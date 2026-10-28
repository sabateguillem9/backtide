"""The seven T13 scenarios (invariant 7), against a REAL installation: backtide put there by
install.sh, as root, its systemd units, its volume and its web, in a clean VM (backtide-limpia-*).

They never run in vigia-dev nor on the Mac: there they are skipped, saying so. In a clean VM,
after `install.sh`, as root (docs/25, "Resultados de T13-3"):

    sudo uv run --locked pytest -m ataques -p no:cacheprovider \\
        tests/attacks/test_install_attacks.py

Some of them stop and start the installed service or change a mount for a moment; each one puts
everything back as it was (and checks it) before it ends. Nothing here leaves the VM.
"""

import json
import os
import secrets
import stat
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from attack_kit import Attack, battery_profile, scenario

from backtide.blackbox import BlackBox, load_key
from backtide.jail import AgentJail
from backtide.jail.proxy import _mounts, channel_mount_problem
from backtide.service.config import ServiceConfig
from backtide.setup import layout, selftest, units
from backtide.snapshots import SnapshotStore

pytestmark = pytest.mark.instalada
AGENT_WAIT = 600.0
SERVICE_CAPS = ("CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER")
CAP_NUMBERS = {"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_FOWNER": 3, "CAP_SYS_ADMIN": 21}


@dataclass
class Installed:
    """The installed backtide, seen from the host as root."""

    config: ServiceConfig
    jail: AgentJail
    box: BlackBox
    store: SnapshotStore


def sh(*argv: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        list(argv), capture_output=True, text=True, check=check, timeout=timeout
    )


def wait(predicate: Callable[[], bool], timeout: float, interval: float = 2.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if predicate():
                return True
        except Exception:  # noqa: BLE001, S110 - a check that cannot look yet: look again
            pass
        time.sleep(interval)
    return False


def main_pid(unit: str) -> int:
    return int(sh("systemctl", "show", "-p", "MainPID", "--value", unit).stdout.strip())


def status_fields(pid: int) -> dict[str, str]:
    fields = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, _, value = line.partition(":")
        fields[name] = value.strip()
    return fields


def agent_running(installed: Installed) -> bool:
    return installed.jail.is_running() and bool(
        installed.jail.exec(
            list(installed.config.jail_config().profile.ready_probe or ["true"]), timeout=30
        ).returncode
        == 0  # fmt: skip
    )


def back_to_normal(installed: Installed) -> None:
    """Every unit up and the agent answering again, or the test fails: the next scenario must
    find the installation as install.sh left it."""
    sh("systemctl", "start", units.volume_unit_name(), units.channel_unit_name())
    sh("systemctl", "start", layout.SERVICE_UNIT, layout.WEB_UNIT)
    assert wait(lambda: agent_running(installed), AGENT_WAIT), "the agent did not come back"


@pytest.fixture(scope="module")
def installed() -> Iterator[Installed]:
    yield from open_installed()


def open_installed() -> Iterator[Installed]:
    """The installed backtide, its agent answering (test_mac_vm_attacks.py uses it too)."""
    config = ServiceConfig.from_file(layout.CONFIG_FILE)
    # The battery's agent must be the installed one (D27): a scenario run for Claude Code
    # against an OpenClaw install would prove nothing about Claude Code.
    assert config.agent_profile.name == battery_profile(), (
        f"installed agent {config.agent_profile.name}, battery run for {battery_profile()}"
    )
    box = BlackBox(
        config.blackbox_db,
        load_key(config.blackbox_key),
        checkpoint_path=config.blackbox_checkpoint,
        readonly=True,
    )
    found = Installed(config, AgentJail(config.jail_config()), box, SnapshotStore(config.volume))
    assert wait(lambda: agent_running(found), AGENT_WAIT), "the installed agent is not running"
    try:
        yield found
    finally:
        box.close()


# -- the service and the web ----------------------------------------------------------------------


@scenario("servicio-endurecido")
def test_the_root_service_has_only_what_it_needs(attack: Attack, installed: Installed) -> None:
    pid = main_pid(layout.SERVICE_UNIT)
    fields = status_fields(pid)
    bounding = int(fields["CapBnd"], 16)
    wanted = sum(1 << CAP_NUMBERS[name] for name in SERVICE_CAPS)
    nonce = "backtide-probe-" + secrets.token_hex(4)
    writes = {}
    for folder in ("/etc", "/usr", "/root", "/opt/backtide", "/var/lib/docker"):
        done = sh("nsenter", "-t", str(pid), "-m", "--", "sh", "-c", f"echo x > {folder}/{nonce}",
                  check=False)  # fmt: skip
        writes[folder] = done.returncode != 0 and not Path(folder, nonce).exists()
    tmp = sh("nsenter", "-t", str(pid), "-m", "--", "sh", "-c", f"echo x > /tmp/{nonce}",
             check=False)  # fmt: skip
    private_tmp = tmp.returncode == 0 and not Path("/tmp", nonce).exists()  # noqa: S108
    levels = {c.key: c for c in selftest.security(selftest_runner)}
    level = levels[f"security:{layout.SERVICE_UNIT}"]
    ok = (
        bounding == wanted
        and int(fields["CapEff"], 16) & ~wanted == 0
        and fields["NoNewPrivs"] == "1"
        and fields["Seccomp"] == "2"
        and all(writes.values())
        and private_tmp
        and level.status.value == "ok"
    )
    attack.check(
        "stopped",
        ok,
        f"CapBnd {fields['CapBnd']} (las cuatro de D25: {bounding == wanted}), NoNewPrivs "
        f"{fields['NoNewPrivs']}, Seccomp {fields['Seccomp']}; escribir desde su espacio de "
        f"montaje falla en {sorted(k for k, v in writes.items() if v)}; su /tmp es privado: "
        f"{private_tmp}; {level.summary}",
    )


def selftest_runner(argv):  # noqa: ANN001, ANN201 - the setup module's Runner
    from backtide.setup.host import run

    return run(argv)


WEB_PROBE = """
import errno, json, os, socket, sys
state, host = sys.argv[1], sys.argv[2]
out = {}
def tried(name, fn):
    try:
        fn()
        out[name] = "ok"
    except TimeoutError:
        out[name] = "timeout"
    except OSError as e:
        out[name] = errno.errorcode.get(e.errno, str(e.errno))
tried("read_db", lambda: os.close(os.open(f"{state}/blackbox.db", os.O_RDONLY)))
tried("write_db", lambda: os.close(os.open(f"{state}/blackbox.db", os.O_RDWR)))
tried("read_key", lambda: os.close(os.open(f"{state}/blackbox.key", os.O_RDONLY)))
tried("list_keys", lambda: os.listdir(f"{state}/keys"))
tried("list_state", lambda: os.listdir(state))
tried("read_config", lambda: os.close(os.open("/etc/backtide/backtide.toml", os.O_RDONLY)))
tried("connect_out", lambda: socket.create_connection((host, 22), timeout=5).close())
tried("connect_local", lambda: socket.create_connection(("127.0.0.1", 8765), timeout=5).close())
out["uid"] = os.getuid()
print(json.dumps(out))
"""


@scenario("web-sin-privilegios")
def test_the_web_cannot_write_the_box_nor_send_anything_out(
    attack: Attack, installed: Installed
) -> None:
    """A probe placed where code running in the web would be: its cgroup (so its IP filter
    applies), its mount namespace, its user and group, no capability."""
    pid = main_pid(layout.WEB_UNIT)
    fields = status_fields(pid)
    web_uid = int(sh("id", "-u", layout.WEB_USER).stdout)
    web_gid = int(sh("id", "-g", layout.WEB_USER).stdout)
    cgroup = Path("/proc", str(pid), "cgroup").read_text().strip().split("::", 1)[1]
    host = selftest.host_address(selftest_runner)
    python = str(layout.CURRENT / ".venv" / "bin" / "python")
    enter = (
        f"exec nsenter -t {pid} -m -S {web_uid} -G {web_gid} -- {python} -I -c "
        f'"$0" {layout.STATE_DIR} {host}'
    )

    def probed(script: str) -> dict:
        done = sh("sh", "-c", script, WEB_PROBE, check=False)
        lines = done.stdout.strip().splitlines()
        return json.loads(lines[-1]) if lines else {"error": done.stderr.strip()[-300:]}

    # Control: the same probe outside the web's cgroup reaches the host's sshd; inside it, the
    # unit's IP filter is all that changes.
    control = probed(enter)
    probe = probed(f"echo $$ > /sys/fs/cgroup{cgroup}/cgroup.procs && {enter}")
    ok = (
        fields["Uid"].split()[0] == str(web_uid)
        and int(fields["CapEff"], 16) == 0
        and probe.get("uid") == web_uid
        and probe.get("read_db") == "ok"
        and probe.get("write_db") == "EACCES"
        and probe.get("read_key") == "EACCES"
        and probe.get("list_keys") == "EACCES"
        and probe.get("list_state") == "EACCES"
        and probe.get("read_config") == "EACCES"
        and control.get("connect_out") == "ok"
        and probe.get("connect_out") not in (None, "ok")  # IPAddressDeny=any: the cgroup's
        and probe.get("connect_local") == "ok"
    )
    attack.check(
        "stopped",
        ok,
        f"la web corre como {fields['Uid'].split()[0]} con CapEff {fields['CapEff']}; desde su "
        f"cgroup, su espacio de montaje y su usuario: {probe}; fuera de su cgroup la misma "
        f"prueba sí llega a {host}:22 ({control.get('connect_out')})",
    )


# -- the agent ----------------------------------------------------------------------------------


@scenario("agente-no-ve-la-instalacion")
def test_the_agent_sees_nothing_of_the_installation(attack: Attack, installed: Installed) -> None:
    attack.watch_service(installed)
    paths = [
        "/etc/backtide/backtide.toml", "/etc/systemd/system/backtide.service",
        "/var/lib/backtide/keys/anthropic.key", "/var/lib/backtide/blackbox.db",
        "/var/lib/backtide/volume.img", "/opt/backtide/current",
        "/var/lib/backtide/telegram.toml",
    ]  # fmt: skip
    seen = {}
    for path in paths:
        done = installed.jail.exec(["cat", path], timeout=30)
        seen[path] = done.returncode != 0 and "No such file" in done.stderr
    listing = installed.jail.exec(["ls", "/var/lib/backtide", "/etc/backtide"], timeout=30)
    seen["ls"] = listing.returncode != 0
    # Docker's socket is root on the host: never in the jail, at either of its usual paths.
    sockets = installed.jail.exec(
        ["sh", "-c", "for p in /var/run/docker.sock /run/docker.sock; do "
                     "[ -e $p ] || [ -L $p ] && echo $p; done; true"],
        timeout=30,
    )  # fmt: skip
    seen["docker.sock"] = sockets.returncode == 0 and sockets.stdout.strip() == ""
    info = json.loads(sh("docker", "inspect", installed.config.jail_config().name).stdout)[0]
    mounts = info.get("Mounts", [])
    sources = sorted({m.get("Source", "") for m in mounts})
    allowed = {str(installed.config.jail_config().agent_dir),
               str(installed.config.jail_config().config_dir),
               str(installed.config.jail_config().ca_dir)}  # fmt: skip
    # An allow-list (review of T13-3, G4): every bind is one of the three, and nothing but binds.
    forbidden = sorted(
        f"{m.get('Type')}:{m.get('Source', m.get('Name', '?'))}"
        for m in mounts
        if m.get("Type") != "bind" or m.get("Source") not in allowed
    )
    attack.check(
        "stopped",
        all(seen.values()) and not forbidden,
        f"desde la jaula no existe ninguna de {len(paths)} rutas de la instalación, ni el socket "
        f"de Docker ({seen['docker.sock']}), ni se puede listar /var/lib/backtide ni "
        f"/etc/backtide; el contenedor solo monta {sources}, las tres permitidas "
        f"(otras: {forbidden})",
    )
    events = attack.recorded_exec(argv="/etc/backtide/backtide.toml", binary="*/cat")
    attack.check(
        "recorded",
        bool(events),
        f"el sensor grabó {len(events)} exec de `cat /etc/backtide/backtide.toml`",
    )
    risks = sorted({event.risk for event in events})
    rules = sorted({rule for event in events for rule in event.details.get("risk_rules", [])})
    attack.check("risk", risks == [2], f"nivel {risks}: reglas {rules}")


@scenario("setuid-en-el-volumen")
def test_a_setuid_file_of_the_agent_is_useless_on_the_host(
    attack: Attack, installed: Installed
) -> None:
    config = installed.config
    before = installed.store.snapshots()
    assert before, "the installation always has a first snapshot"
    attack.watch_service(installed)
    name = f"suid-{secrets.token_hex(4)}"
    inside = f"/workspace/work/{name}"
    installed.jail.exec(["mkdir", "-p", "/workspace/work"], check=True)
    installed.jail.exec(["cp", "/usr/bin/id", inside], check=True)
    chmod = installed.jail.exec(["chmod", "u+s", inside], timeout=30)
    host = config.jail_config().agent_dir / "work" / name
    info = os.stat(host)
    made = chmod.returncode == 0 and bool(info.st_mode & stat.S_ISUID) and info.st_uid == 61000
    nosuid = bool(os.statvfs(config.volume).f_flag & os.ST_NOSUID)
    root_closed = stat.S_IMODE(os.stat(config.volume).st_mode) == 0o700
    image_closed = stat.S_IMODE(os.stat(layout.VOLUME_IMAGE).st_mode) == 0o600
    # Run it on the host as nobody, the way root could hand it over (an open file: the 0700
    # root of the volume would stop nobody before nosuid does). nosuid: its euid stays nobody.
    ran = sh("python3", "-I", "-c", (
        "import os, sys\n"
        "fd = os.open(sys.argv[1], os.O_PATH)\n"
        "os.setgroups([]); os.setgid(65534); os.setuid(65534)\n"
        "os.execve(fd, ['id', '-u'], {})\n"
    ), str(host), check=False)  # fmt: skip
    ran_as = ran.stdout.strip()
    attack.check(
        "stopped",
        made and nosuid and root_closed and image_closed and ran_as in ("65534", ""),
        f"el agente dejó {name} setuid (uid {info.st_uid}, modo {stat.S_IMODE(info.st_mode):o}); "
        f"el volumen va con nosuid ({nosuid}), su raíz en 0700 ({root_closed}) y la imagen en 0600 "
        f"({image_closed}); ejecutado por nobody en el anfitrión da uid "
        f"{ran_as or 'ninguno: ' + ran.stderr.strip()[-120:]} (nunca 61000)",
    )
    events = attack.recorded_exec(argv="u+s", binary="*/chmod")
    attack.check("recorded", bool(events), f"el sensor grabó {len(events)} `chmod u+s`")
    risks = sorted({event.risk for event in events})
    attack.check("risk", risks == [2], f"nivel {risks} (regla exec-setuid)")
    last = before[-1]
    kept = installed.store.snapshots_dir / last.id / host.relative_to(installed.store.workspace)
    attack.check(
        "recoverable",
        not kept.exists() and host.exists(),
        f"la instantánea {last.id}, anterior al ataque, no tiene {name}: rebobinar lo quita",
    )
    host.unlink()


# -- the proxy's channel and the volume ---------------------------------------------------------


def channel_table_entry(config: ServiceConfig):  # noqa: ANN201
    target = os.path.realpath(config.proxy_jail_config().channel_dir)
    found = [m for m in _mounts(Path("/proc/self/mountinfo").read_text()) if m.point == target]
    return found[-1] if found else None


@scenario("canal-del-proxy-instalado")
def test_the_channel_is_its_units_tmpfs_and_no_other(attack: Attack, installed: Installed) -> None:
    config = installed.config
    channel = config.proxy_jail_config().channel_dir
    mounted = channel_table_entry(config)
    assert mounted is not None
    as_unit = channel_mount_problem(mounted, config.proxy_jail_config()) is None and (
        mounted.source == "backtide-proxy-channel"
        and {"nosuid", "nodev", "noexec"} <= mounted.options
        and mounted.super_options.get("size") == "1024k"
        and mounted.super_options.get("mode") == "700"
        and mounted.super_options.get("uid") == "61001"
    )
    head = installed.box.head()
    since = head[0] if head else 0
    sh("systemctl", "stop", layout.SERVICE_UNIT, timeout=300)
    sh("systemctl", "stop", units.channel_unit_name())
    try:
        sh("mount", "-t", "tmpfs", "-o", "size=64m,mode=0700,uid=61001,gid=61001", "otra-tmpfs",
           str(channel))  # fmt: skip
        sh("systemctl", "start", layout.SERVICE_UNIT)

        def refused() -> list:
            return [e for e in installed.box.events(source="system", action="proxy_start_failed",
                                                    since_seq=since)]  # fmt: skip

        seen = wait(lambda: bool(refused()), 300)
        agent_up = installed.jail.is_running()
        events = refused()
    finally:
        sh("systemctl", "stop", layout.SERVICE_UNIT, timeout=300)
        sh("umount", str(channel), check=False)
        back_to_normal(installed)
    attack.check(
        "stopped",
        as_unit and seen and not agent_up,
        f"montada por su unidad: {mounted.source} {sorted(mounted.options)} "
        f"{mounted.super_options}; con otra tmpfs encima backtide no arranca el proxy "
        f"({seen}) ni el agente (en marcha: {agent_up})",
    )
    attack.check(
        "recorded",
        bool(events),
        f"system/proxy_start_failed en la caja negra: "
        f"{events[0].details.get('error', '')[:160] if events else 'nada'}",
    )
    attack.check("risk", bool(events) and events[0].risk == 2, f"nivel {[e.risk for e in events]}")


@scenario("volumen-que-no-monta")
def test_without_its_volume_neither_backtide_nor_the_agent_start(
    attack: Attack, installed: Installed
) -> None:
    """The image moved away, and the mount unit gone (a broken install): backtide.service never
    starts on the empty folder underneath, and no agent runs. Then everything comes back."""
    mount_unit = units.volume_unit_name()
    unit_file = layout.UNIT_DIR / mount_unit
    image = layout.VOLUME_IMAGE
    apart = {"sin-imagen": image.with_name("volume.img.apartado"),
             "sin-unidad": Path("/root") / f"{mount_unit}.apartada"}  # fmt: skip
    outcomes = {}
    for case, aside in apart.items():
        sh("systemctl", "stop", layout.SERVICE_UNIT, timeout=300)
        sh("systemctl", "stop", mount_unit)
        sh("systemctl", "reset-failed", layout.SERVICE_UNIT, check=False)
        moved = image if case == "sin-imagen" else unit_file
        head = installed.box.head()
        since = head[0] if head else 0
        try:
            moved.rename(aside)
            sh("systemctl", "daemon-reload")
            start = sh("systemctl", "start", layout.SERVICE_UNIT, check=False, timeout=300)
            time.sleep(10)
            shown = dict(
                line.split("=", 1)
                for line in sh(
                    "systemctl",
                    "show",
                    "-p",
                    "ActiveState,NRestarts,AssertResult",
                    layout.SERVICE_UNIT,
                ).stdout.splitlines()  # fmt: skip
                if "=" in line
            )
            mounted = sh("findmnt", "--mountpoint", str(layout.VOLUME_MOUNT), check=False)
            agent = sh("docker", "ps", "--quiet", "--filter",
                       f"name=^{installed.config.jail_config().name}$").stdout.strip()  # fmt: skip
            new_events = installed.box.events(since_seq=since)
            outcomes[case] = {
                "start_exit": start.returncode,
                "why": " ".join((start.stderr or start.stdout).split())[:160],
                **shown,
                "mounted": mounted.returncode == 0,
                "agent": bool(agent),
                "new_events": [f"{e.source}/{e.action}" for e in new_events],
            }
        finally:
            if aside.exists():
                aside.rename(moved)
            sh("systemctl", "daemon-reload")
            sh("systemctl", "reset-failed", layout.SERVICE_UNIT, mount_unit, check=False)
            back_to_normal(installed)

    def refused(case: str, outcome: dict) -> bool:
        """Refused by systemd before backtide ran (review of T13-3, G2): the start fails at once,
        nothing restarts it, nothing reaches the black box, and for the reason of that case."""
        reason = (
            outcome.get("AssertResult") == "no"
            if case == "sin-unidad"
            else "dependency" in outcome["why"].lower()
        )
        return (
            outcome["start_exit"] != 0
            and outcome.get("NRestarts") == "0"
            and outcome.get("ActiveState") != "active"
            and not outcome["mounted"]
            and not outcome["agent"]
            and outcome["new_events"] == []
            and reason
        )

    attack.check(
        "stopped",
        all(refused(case, outcome) for case, outcome in outcomes.items()),
        f"sin la imagen y sin su unidad de montaje, systemd no deja arrancar backtide.service, "
        f"nada se monta, no corre ningún agente y no hay ningún evento nuevo en la caja negra: "
        f"{outcomes}; después todo vuelve y el agente responde",
    )


# -- installing again --------------------------------------------------------------------------


@scenario("reinstalar-no-pisa-la-historia")
def test_installing_again_keeps_the_agents_history(attack: Attack, installed: Installed) -> None:
    config = installed.config
    image_before = os.stat(layout.VOLUME_IMAGE)
    uuid = sh("blkid", "-p", "-o", "value", "-s", "UUID", str(layout.VOLUME_IMAGE)).stdout.strip()
    marker = f"historia-{secrets.token_hex(4)}"
    installed.jail.exec(["sh", "-c", f"mkdir -p /workspace/work && echo {marker} > "
                         f"/workspace/work/{marker}.txt"], check=True)  # fmt: skip
    head = installed.box.head()
    assert head is not None
    old = installed.box.events(limit=head[0])
    snaps = {s.id for s in installed.store.snapshots()}
    db_before, key_before = os.stat(config.blackbox_db), os.stat(config.blackbox_key)
    key_bytes = Path(config.blackbox_key).read_bytes()
    checkpoint_before = os.path.isfile(config.blackbox_checkpoint)
    done = sh(str(layout.BIN_LINK), "instalar", "--si", "--sin-clave", check=False, timeout=1800)
    image_after = os.stat(layout.VOLUME_IMAGE)
    uuid_after = sh("blkid", "-p", "-o", "value", "-s", "UUID",
                    str(layout.VOLUME_IMAGE)).stdout.strip()  # fmt: skip
    db_after, key_after = os.stat(config.blackbox_db), os.stat(config.blackbox_key)
    # The same files, never made again (review of T13-3, G1): the key byte for byte, the box the
    # same inode and never shorter (it only grows). The checkpoint the service itself rewrites
    # by rename every cycle, so its inode moves on its own: it must be there, and verify signs it.
    files_kept = (
        (key_after.st_ino, key_after.st_size) == (key_before.st_ino, key_before.st_size)
        and Path(config.blackbox_key).read_bytes() == key_bytes
        and db_after.st_ino == db_before.st_ino
        and db_after.st_size >= db_before.st_size
        and checkpoint_before
        and os.path.isfile(config.blackbox_checkpoint)
    )
    # A box opened afresh, with the key read again from its file, as `backtide verificar` would.
    fresh = BlackBox(
        config.blackbox_db,
        load_key(config.blackbox_key),
        checkpoint_path=config.blackbox_checkpoint,
        readonly=True,
    )
    try:
        same = [e.hash for e in fresh.events(limit=head[0])] == [e.hash for e in old]
        report = fresh.verify()
    finally:
        fresh.close()
    host_file = config.jail_config().agent_dir / "work" / f"{marker}.txt"
    attack.check(
        "recorded",
        done.returncode == 0 and files_kept and same and report.ok,
        f"instalar otra vez sale con {done.returncode}; blackbox.db (inodo {db_after.st_ino}) y "
        f"blackbox.key (inodo {key_after.st_ino}, mismos bytes) no se rehacen ({files_kept}); "
        f"abierta de nuevo con su clave, los {head[0]} eventos de antes siguen iguales ({same}) "
        f"y verifica con su punto de control ({report.ok}, {report.checked} eventos)",
    )
    attack.check(
        "recoverable",
        (image_after.st_ino, uuid_after) == (image_before.st_ino, uuid)
        and host_file.read_text().strip() == marker
        and snaps <= {s.id for s in installed.store.snapshots()},
        f"volume.img con el mismo inodo ({image_after.st_ino}) y el mismo Btrfs ({uuid}); el "
        f"archivo del agente sigue ahí y las {len(snaps)} instantáneas de antes también",
    )
    host_file.unlink()


# -- uninstalling (T13-4, the review's battery for invariant 7) --------------------------------
#
# Destructive: each one ends with backtide uninstalled (its data kept). They run only when the
# lab asks for them (BACKTIDE_LAB_DESTRUCTIVO=1), at the end of an installed lab's run or in a
# clean VM of their own; anywhere else they are skipped, saying so.

DESTRUCTIVE = os.environ.get("BACKTIDE_LAB_DESTRUCTIVO") == "1"
destructive = pytest.mark.skipif(
    not DESTRUCTIVE,
    reason="uninstalls backtide: only with BACKTIDE_LAB_DESTRUCTIVO=1, in a clean lab VM",
)
_BEFORE: dict[str, object] = {}  # what the first of them saw while backtide-web still existed

GROUP_PROBE = """
import errno, json, os, sys
def tried(fn):
    try:
        fn()
        return "ok"
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
state, db = sys.argv[1], sys.argv[2]
print(json.dumps({"list_state": tried(lambda: os.listdir(state)),
                  "open_blackbox": tried(lambda: os.close(os.open(db, os.O_RDONLY)))}))
"""


def group_probe(user: str) -> dict[str, str]:
    """As ``user``: list the state folder and open the black box. Only errno names come back."""
    ran = sh("runuser", "-u", user, "--", "python3", "-I", "-c", GROUP_PROBE,
             str(layout.STATE_DIR), str(layout.BLACKBOX_DB), check=False)  # fmt: skip
    return json.loads(ran.stdout.strip().splitlines()[-1]) if ran.stdout.strip() else {}


def web_group_before() -> None:
    """backtide-web's gid, and the control: its own user opens the black box (0640, its group)."""
    if "gid" in _BEFORE:
        return
    import grp

    _BEFORE["gid"] = grp.getgrnam(layout.WEB_USER).gr_gid
    _BEFORE["control"] = group_probe(layout.WEB_USER)


def sha256_of(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


@destructive
@scenario("desinstalar-con-un-montaje-debajo")
def test_uninstall_never_deletes_through_a_mount_under_its_folders(attack: Attack) -> None:
    """The agent's volume bind-mounted under /opt/backtide (a mistake, or someone's trick): an
    rmtree of /opt/backtide would go into it and delete the agent's work and its snapshots."""
    assert layout.BIN_LINK.is_symlink(), "backtide is not installed here"
    web_group_before()
    config = ServiceConfig.from_file(layout.CONFIG_FILE)
    store = SnapshotStore(config.volume)
    witness = config.jail_config().agent_dir / f"eco-{secrets.token_hex(4)}.txt"
    witness.write_text("el trabajo del agente\n")
    os.chown(witness, 61000, 61000)
    digest, snaps = sha256_of(witness), {s.id for s in store.snapshots()}
    eco = layout.OPT_DIR / "eco"
    eco.mkdir()
    sh("mount", "--bind", str(layout.VOLUME_MOUNT), str(eco))
    try:
        first = sh(str(layout.BIN_LINK), "desinstalar", "--si", check=False, timeout=1800)
        kept = (
            sha256_of(witness) == digest
            and snaps <= {s.id for s in store.snapshots()}
            and layout.BIN_LINK.is_symlink()
            and (layout.UNIT_DIR / layout.SERVICE_UNIT).is_file()
        )
        said = " ".join(first.stderr.split())
    finally:
        sh("umount", str(eco))
        eco.rmdir()
    attack.check(
        "stopped",
        first.returncode == 1 and "hay algo montado" in said and kept,
        f"con el volumen montado en {eco}, `backtide desinstalar --si` sale con "
        f"{first.returncode} («hay algo montado»: {'hay algo montado' in said}) antes de tocar "
        f"nada: el archivo del agente con la misma huella, las {len(snaps)} instantáneas, la "
        f"orden y las unidades siguen ({kept})",
    )
    second = sh(str(layout.BIN_LINK), "desinstalar", "--si", check=False, timeout=1800)
    look = Path("/root") / f"eco-ro-{secrets.token_hex(4)}"
    look.mkdir()
    sh("mount", "-o", "loop,ro,nosuid,nodev,noexec", str(layout.VOLUME_IMAGE), str(look))
    try:
        inside = look / witness.relative_to(config.volume)
        survived = inside.is_file() and sha256_of(inside) == digest
        snaps_after = {p.name for p in (look / "snapshots").iterdir()}
    finally:
        sh("umount", str(look))
        look.rmdir()
    attack.check(
        "recoverable",
        second.returncode == 0
        and survived
        and snaps <= snaps_after
        and not layout.OPT_DIR.exists()
        and not layout.BIN_LINK.exists(),
        f"desmontado, otra vez sale con {second.returncode} y quita backtide; en la imagen del "
        f"volumen, que se conserva, siguen el archivo del agente ({survived}) y las "
        f"{len(snaps)} instantáneas de antes ({snaps <= snaps_after})",
    )


@destructive
@scenario("grupo-reciclado-lee-la-caja-negra")
def test_a_recycled_gid_cannot_read_the_kept_black_box(attack: Attack) -> None:
    """After a default uninstall the black box stays, and backtide-web's group goes. A group
    made later that gets the same gid must not read it (the state folder and blackbox.db go to
    root's group first)."""
    if layout.BIN_LINK.is_symlink():
        web_group_before()
        done = sh(str(layout.BIN_LINK), "desinstalar", "--si", check=False, timeout=1800)
        assert done.returncode == 0, done.stderr[-400:]
    assert "gid" in _BEFORE, "backtide must be installed when the first of these scenarios runs"
    gid = int(str(_BEFORE["gid"]))
    group, user = "reciclado", "reciclado"
    sh("groupadd", "--gid", str(gid), group)
    try:
        sh("useradd", "--system", "--no-create-home", "--no-user-group", "--gid", group,
           "--shell", "/usr/sbin/nologin", user)  # fmt: skip
        try:
            seen = group_probe(user)
        finally:
            sh("userdel", user, check=False)
    finally:
        sh("groupdel", group, check=False)
    control = _BEFORE.get("control") or {}
    attack.check(
        "stopped",
        seen == {"list_state": "EACCES", "open_blackbox": "EACCES"}
        and isinstance(control, dict)
        and control.get("open_blackbox") == "ok",
        f"un grupo nuevo con el gid {gid} de backtide-web, y un usuario en él: {seen}; el "
        f"control, antes de desinstalar y como backtide-web: {control}",
    )
