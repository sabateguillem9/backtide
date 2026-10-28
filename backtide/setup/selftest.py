"""`backtide comprobar --despues-de-instalar`: does the installed backtide really work?

Design: docs/25, section 4, step 8, with T13-1's additions. A short version of what the battery
proves, on the real installation and through its systemd units (never a service started by
hand), each check one line like the preflight's (``ok``, ``aviso``, ``falla``):

- the four units are active, and the volume is mounted ``nosuid,nodev,noatime``;
- the agent started under the service (``agent_start`` in the black box) and answers its
  profile's health probe as the service expects (OpenClaw's ``/healthz``; Claude Code's
  ``claude --version`` with the pinned version, D27);
- it runs as 61000 in all four ids, with no capability and ``NoNewPrivs``; under SELinux in
  enforcing its process is ``container_t`` (T13-1: Docker without ``selinux-enabled`` runs it as
  ``spc_t`` and says nothing), under AppArmor it has ``docker-default`` in enforce mode;
- from inside, nothing goes out without the proxy: a TEST-NET address (RFC 5737, never routed)
  and the host's own address both fail to connect;
- the black box verifies (chain and checkpoint);
- the process sensor sees a command with a fresh nonce (a warning, not a failure: the agent
  runs without it, decision 7 of docs/23; and D24 on kernels 7.1+);
- the web listens on 127.0.0.1 and its link is in its file, not in the journal;
- ``systemd-analyze security`` of each service is at or under its measured threshold.

Nothing here reaches anything outside the machine.
"""

import json
import os
import re
import secrets
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from backtide.blackbox import BlackBox, BlackBoxError, load_key
from backtide.jail import AgentJail, JailError
from backtide.jail import docker as jail_docker
from backtide.jail.profile import AgentProfile
from backtide.service.config import ServiceConfig
from backtide.setup import layout, networks, preflight, units
from backtide.setup.host import Host, Runner
from backtide.setup.preflight import Check, Status

AGENT_WAIT = 600.0  # the first start makes the proxy's CA and boots OpenClaw
HEALTH_WAIT = 180.0
SENSOR_WAIT = 60.0
WEB_PORT = 8765
TEST_NET = "192.0.2.1"  # RFC 5737 TEST-NET-1: documentation only, never routed
# `systemd-analyze security` of each unit, measured in clean VMs (docs/25, "Resultados de
# T13-3"): 3.1 and 1.2 with systemd 255 (Ubuntu 24.04) and 259 (Fedora 44), plus 0.1 of margin.
# A higher number means a directive was lost.
SECURITY_THRESHOLDS = {layout.SERVICE_UNIT: 3.2, layout.WEB_UNIT: 1.3}
_EXPOSURE = re.compile(r"Overall exposure level for \S+: ([0-9]+(?:\.[0-9]+)?)")
_CONNECT_PROBE = (
    "import errno, socket, sys\n"
    "out = []\n"
    "for host, port in ((sys.argv[1], 443), (sys.argv[2], 22)):\n"
    "    s = socket.socket()\n"
    "    s.settimeout(5)\n"
    "    try:\n"
    "        s.connect((host, port))\n"
    "        out.append('connected')\n"
    "    except OSError as e:\n"
    "        out.append(errno.errorcode.get(e.errno or 0, type(e).__name__))\n"
    "    finally:\n"
    "        s.close()\n"
    "print(' '.join(out))\n"
)


def unit_states(run: Runner) -> Check:
    names = (units.volume_unit_name(), units.channel_unit_name(), layout.SERVICE_UNIT,
             layout.WEB_UNIT)  # fmt: skip
    down = []
    for name in names:
        ran = run(("systemctl", "is-active", name))
        state = ran.stdout.strip() if ran is not None else "?"
        if state != "active":
            down.append(f"{name} ({state or '?'})")
    if down:
        return Check("units", Status.FAIL, f"Unidades paradas: {', '.join(down)}",
                     "Mira `systemctl status <unidad>` y `journalctl -u <unidad>`.")  # fmt: skip
    return Check("units", Status.OK, "Las cuatro unidades de backtide están en marcha")


def mount_options(run: Runner, path: Path) -> Check:
    ran = run(("findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--mountpoint", str(path)))
    parts = ran.stdout.split() if ran is not None and ran.returncode == 0 else []
    options = set(parts[1].split(",")) if len(parts) == 2 else set()
    missing = sorted({"nosuid", "nodev", "noatime"} - options)
    if not parts or parts[0] != "btrfs" or missing:
        what = (
            "no está montado como Btrfs"
            if not parts or parts[0] != "btrfs"
            else (f"le falta {','.join(missing)}")
        )
        return Check("volume", Status.FAIL, f"El volumen {path} {what}",
                     f"Mira `systemctl status {units.volume_unit_name()}`.")  # fmt: skip
    return Check("volume", Status.OK, f"Volumen montado en {path} con nosuid,nodev,noatime")


def identity(status: str, label: str, *, selinux: bool, apparmor: bool, uid: int) -> Check:
    """The agent's process as the kernel sees it: /proc/<pid>/status and its LSM label."""
    fields = {}
    for line in status.splitlines():
        name, _, value = line.partition(":")
        fields[name.strip()] = value.split()
    problems = []
    if fields.get("Uid", []) != [str(uid)] * 4 or fields.get("Gid", []) != [str(uid)] * 4:
        problems.append(f"sus ids son {fields.get('Uid')} / {fields.get('Gid')}")
    if fields.get("CapEff", ["?"])[0].strip("0") != "":
        problems.append(f"tiene capacidades ({fields.get('CapEff')})")
    if fields.get("NoNewPrivs", ["?"])[0] != "1":
        problems.append("puede ganar privilegios (NoNewPrivs no es 1)")
    if selinux and ":container_t:" not in label:
        problems.append(f"no está confinado por SELinux (etiqueta {label or '?'})")
    if problems:
        return Check("agent_identity", Status.FAIL, f"El agente {'; '.join(problems)}",
                     "Vuelve a instalar; si sigue, no lo uses y avisa.")  # fmt: skip
    if apparmor and "(enforce)" not in label:
        return Check("agent_identity", Status.WARN,
                     f"El agente corre sin su perfil de AppArmor en modo estricto ({label or '?'})",
                     "Instala `apparmor` y reinicia Docker.")  # fmt: skip
    where = "container_t" if selinux else (label if apparmor else "sin SELinux ni AppArmor")
    return Check("agent_identity", Status.OK,
                 f"El agente corre como {uid}, sin capacidades ({where})")  # fmt: skip


def egress(result: str) -> Check:
    """What the connect probe printed: one word per address, never ``connected``."""
    words = result.split()
    if len(words) != 2:
        return Check("egress", Status.FAIL, "No se pudo probar la salida directa del agente",
                     f"La prueba dijo: {jail_docker.sanitize(result, 200) or 'nada'}")  # fmt: skip
    if "connected" in words:
        return Check(
            "egress",
            Status.FAIL,
            "El agente sale a la red sin pasar por el proxy (invariante 3)",
            "Para backtide (`systemctl stop backtide`) y avisa: no lo uses así.",
        )
    return Check("egress", Status.OK,
                 f"Sin el proxy, el agente no llega a nada ({words[0]}, {words[1]})")  # fmt: skip


def security_level(text: str) -> float | None:
    match = _EXPOSURE.search(text)
    return float(match[1]) if match else None


def security(run: Runner) -> list[Check]:
    found = []
    for unit, threshold in SECURITY_THRESHOLDS.items():
        ran = run(("systemd-analyze", "security", "--no-pager", unit))
        level = security_level((ran.stdout + ran.stderr) if ran is not None else "")
        if level is None:
            found.append(Check(f"security:{unit}", Status.WARN,
                               f"No se pudo medir el endurecimiento de {unit}"))  # fmt: skip
        elif level > threshold:
            found.append(Check(f"security:{unit}", Status.FAIL,
                               f"{unit} está menos endurecido de lo medido ({level} > {threshold})",
                               f"Compara {layout.UNIT_DIR / unit} con su plantilla."))  # fmt: skip
        else:
            found.append(Check(f"security:{unit}", Status.OK,
                               f"{unit}: exposición {level} (umbral {threshold})"))  # fmt: skip
    return found


def host_address(run: Runner) -> str:
    """The host's first IPv4 that is not loopback nor Docker's: the agent must not reach it."""
    ran = run(networks.ADDRESSES_ARGV)
    try:
        links = json.loads(ran.stdout) if ran is not None and ran.returncode == 0 else []
    except ValueError:
        links = []
    for link in links if isinstance(links, list) else []:
        name = str(link.get("ifname", "")) if isinstance(link, dict) else ""
        if name == "lo" or name.startswith(networks.DOCKER_DEVICES):
            continue
        for address in link.get("addr_info") or []:
            if isinstance(address, dict) and isinstance(address.get("local"), str):
                return address["local"]
    return "127.0.0.1"


def run_selftest(
    config: ServiceConfig,
    host: Host,
    *,
    run: Runner,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> list[Check]:
    """Every check, on the real machine (root)."""
    jail = AgentJail(config.jail_config())
    opened: list[BlackBox] = []

    def started() -> bool:
        if _restarts(run) > MAX_RESTARTS:
            raise _Crashing
        if not opened and (box := _box(config)) is not None:
            opened.append(box)
        return bool(opened) and _agent_started(opened[0]) and jail.is_running()

    try:
        up = _wait(started, AGENT_WAIT, sleep, clock)
    except _Crashing:
        up = False
    found = [unit_states(run), mount_options(run, config.volume)]
    box = opened[0] if opened else None
    if not up:
        found.append(Check("agent", Status.FAIL, "El agente no ha arrancado bajo backtide",
                           f"Mira `journalctl -u {layout.SERVICE_UNIT}`."))  # fmt: skip
        return found + _verify(config) + security(run)
    profile = config.jail_config().profile
    probe = list(profile.ready_probe or ())

    def answers() -> bool:
        return probe_answers(profile, jail.exec(probe, timeout=30))

    healthy = not probe or _wait(answers, HEALTH_WAIT, sleep, clock)
    found.append(
        Check("agent", Status.OK, "El agente arrancó bajo backtide y responde")
        if healthy
        else Check(
            "agent",
            Status.FAIL,
            "El agente arrancó pero no responde a su prueba de salud",
            f"Mira `docker logs {config.jail_config().name}`.",
        )  # fmt: skip
    )
    found.append(_identity(jail, host, config))
    found.append(_egress(jail, run))
    found += _verify(config)
    found.append(_sensor(jail, box, host, sleep, clock))
    found.append(_web(run))
    found += security(run)
    return found


MAX_RESTARTS = 3  # a service systemd keeps restarting will not come up by waiting longer


class _Crashing(Exception):
    pass


def _restarts(run: Runner) -> int:
    ran = run(("systemctl", "show", "-p", "NRestarts", "--value", layout.SERVICE_UNIT))
    text = ran.stdout.strip() if ran is not None and ran.returncode == 0 else ""
    return int(text) if text.isdigit() else 0


def _box(config: ServiceConfig) -> BlackBox | None:
    try:
        return BlackBox(
            config.blackbox_db,
            load_key(config.blackbox_key),
            checkpoint_path=config.blackbox_checkpoint,
            readonly=True,
        )
    except (BlackBoxError, OSError):
        return None


def _agent_started(box: BlackBox | None) -> bool:
    return box is not None and bool(box.events(source="system", action="agent_start", limit=1))


def _identity(jail: AgentJail, host: Host, config: ServiceConfig) -> Check:
    pid = jail_docker.run(
        ["inspect", "--format", "{{.State.Pid}}", config.jail_config().name], check=False
    ).stdout.strip()
    status = (host.read(f"/proc/{pid}/status") or b"").decode(errors="replace")
    label = (host.read(f"/proc/{pid}/attr/current") or b"").decode(errors="replace").strip("\0\n")
    selinux = (host.read("/sys/fs/selinux/enforce") or b"").strip() == b"1"
    apparmor = (host.read("/sys/module/apparmor/parameters/enabled") or b"").strip() == b"Y"
    return identity(status, label, selinux=selinux, apparmor=apparmor and not selinux,
                    uid=config.jail_config().uid)  # fmt: skip


def _egress(jail: AgentJail, run: Runner) -> Check:
    try:
        done = jail.exec(["python3", "-c", _CONNECT_PROBE, TEST_NET, host_address(run)], timeout=60)
    except JailError as error:
        return egress(str(error))
    return egress(done.stdout.strip() or done.stderr.strip())


def _verify(config: ServiceConfig) -> list[Check]:
    box = _box(config)
    if box is None:
        return [
            Check(
                "blackbox",
                Status.FAIL,
                "No se puede abrir la caja negra con su clave",
                f"Mira los permisos de {config.blackbox_db} y {config.blackbox_key}.",
            )
        ]
    try:
        report = box.verify()
    except BlackBoxError as error:
        return [Check("blackbox", Status.FAIL, f"La caja negra no se puede leer: {error}")]
    finally:
        box.close()
    if not report.ok:
        return [Check("blackbox", Status.FAIL, "La caja negra NO está íntegra",
                      "`sudo backtide verificar` dice qué falla.")]  # fmt: skip
    return [Check("blackbox", Status.OK, f"La caja negra está íntegra ({report.checked} eventos)")]


def _sensor(
    jail: AgentJail,
    box: BlackBox | None,
    host: Host,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> Check:
    nonce = "backtide-selftest-" + secrets.token_hex(6)
    try:
        jail.exec(["sh", "-c", f"true {nonce}"], timeout=30)
    except JailError:
        pass

    def seen() -> bool:
        if box is None:
            return False
        events = box.events(source="exec", newest_first=True, limit=500)
        return any(nonce in json.dumps(e.details) + str(e.target) for e in events)

    if _wait(seen, SENSOR_WAIT, sleep, clock):
        return Check("sensor", Status.OK, "El sensor de procesos ve los comandos del agente")
    btf = {c.key: c for c in [preflight._btf(host)]}["btf"]  # noqa: SLF001 - the same check
    why = f" ({btf.summary})" if btf.status is not Status.OK else ""
    return Check(
        "sensor",
        Status.WARN,
        f"El sensor de procesos no vio un comando de prueba{why}: el agente funciona, "
        "pero sus comandos no se graban",
        "Mira `docker logs backtide-sensor`.",
    )


def probe_answers(profile: AgentProfile, done: subprocess.CompletedProcess[str]) -> bool:
    """The agent's health probe answered as its profile expects, as the service checks it."""
    return done.returncode == 0 and profile.ready_answer(done.stdout) is True


def link_in_journal(text: str) -> bool:
    """Does the web's journal hold a one-time link (``?t=`` and a token)?"""
    return "?t=" in text


def _web(run: Runner) -> Check:
    try:
        socket.create_connection(("127.0.0.1", WEB_PORT), timeout=5).close()
    except OSError:
        return Check("web", Status.FAIL, f"La web no escucha en 127.0.0.1:{WEB_PORT}",
                     f"Mira `journalctl -u {layout.WEB_UNIT}`.")  # fmt: skip
    journal = run(("journalctl", "-u", layout.WEB_UNIT, "--no-pager", "-o", "cat"))
    if journal is None or journal.returncode != 0:
        return Check("web", Status.WARN, "No se pudo leer el registro de la web",
                     f"`journalctl -u {layout.WEB_UNIT}`.")  # fmt: skip
    if link_in_journal(journal.stdout):
        return Check("web", Status.FAIL, "El enlace de un solo uso de la web está en el registro",
                     f"Compara {layout.UNIT_DIR / layout.WEB_UNIT} con su plantilla "
                     "(`--enlace-en`).")  # fmt: skip
    if not os.path.isfile(layout.WEB_LINK_FILE):
        return Check("web", Status.WARN, "La web escucha, pero no ha dejado su enlace",
                     f"`sudo systemctl restart {layout.WEB_UNIT}`.")  # fmt: skip
    return Check("web", Status.OK, f"La web escucha en 127.0.0.1:{WEB_PORT}, su enlace no está "
                 "en el registro; `sudo backtide enlace` lo da")  # fmt: skip


def _wait(
    predicate: Callable[[], bool],
    timeout: float,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> bool:
    start = clock()
    while True:
        try:
            if predicate():
                return True
        except (JailError, BlackBoxError, OSError):
            pass
        if clock() - start > timeout:
            return False
        sleep(2.0)
