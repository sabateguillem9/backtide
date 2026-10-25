"""The whole stack as an installation lays it out, with the fake internet (T13-1 P1; T13-5 reuses
it for its self-test). Inside a backtide-limpia-* VM only, as root, never on the Mac or vigia-dev.

    python -m tests.install.stack_lab preparar   # config, token, a made-up key, the pinned images
    python -m tests.install.stack_lab servir     # fake internet + `backtide vigilar` (foreground)
    python -m tests.install.stack_lab comprobar  # the checks, as RESULT lines (service running)
    python -m tests.install.stack_lab parar      # SIGTERM to the service, remove the fake internet

The layout is docs/25's: ``/etc/backtide/backtide.toml`` (root, 0600), ``/var/lib/backtide``
(root, 0700) and the volume mounted at ``/var/lib/backtide-agent`` by its systemd unit. backtide
runs as root and the agent with its own ids (61000:61000) WITHOUT ``allow_shared_ids``; the proxy
with its own (61001) and its channel on a tmpfs that backtide mounts; the process sensor on, with
its production settings (its file 0600, read by root).

The one concession is the fake internet (tests/integration/internet_kit.py): the proxy's egress
network is ``--internal`` and the fake internet is its only neighbour, with the fake model
provider among its names. The provider's "real" key is made up here. Nothing reaches a real
service and no real key exists (invariant 8).
"""

import json
import os
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

CONFIG = Path("/etc/backtide/backtide.toml")
STATE = Path("/var/lib/backtide")
VOLUME = Path("/var/lib/backtide-agent")
LAB = Path("/var/lib/backtide-lab")  # the fake internet's files, the service's pid and log
PID_FILE = LAB / "service.pid"
INTERNET_FILE = LAB / "internet.json"
LOG = LAB / "service.log"
REAL_KEY_FILE = LAB / "made-up-real.key"  # the made-up "real" key, to look for it afterwards
WORKSPACE_LIMIT = 1024**3  # 5 % of a 20 GiB volume (docs/25, decision 4)
CYCLE = 5
TURN_TIMEOUT = 300.0
NONCE = "t13-sensor-" + secrets.token_hex(6)
FILE_NAME = f"t13-{secrets.token_hex(4)}.txt"  # unique per run: the box keeps old runs


def result(name: str, value: object) -> None:
    print(f"RESULT {name}={value}", flush=True)


def require_clean_vm_root() -> None:
    if sys.platform != "linux" or not platform.node().startswith("lima-backtide-limpia-"):
        raise SystemExit("stack_lab only runs inside a backtide-limpia-* VM")
    if os.geteuid() != 0:
        raise SystemExit("stack_lab runs as root: that is what it tests")


def render_config() -> str:
    from tests.integration.internet_kit import PLAIN_HOST, provider_toml

    return (
        f'state_dir = "{STATE}"\n'
        f'volume = "{VOLUME}"\n'
        f"workspace_limit = {WORKSPACE_LIMIT}\n"
        f"cycle_interval = {CYCLE}\n"
        "[budget]\n"
        "auto_prices = false\n"
        "daily_usd = 100000\nmonthly_usd = 100000\n"
        "[agent]\n"
        'memory = "3g"\n'
        "[proxy]\n"
        f'allow_hosts = ["{PLAIN_HOST}"]\n' + provider_toml(openai=False)
    )


def write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(text)


def preparar() -> None:
    from backtide.jail import IMAGE, proxy_config
    from backtide.jail import sensor as sensor_jail
    from tests.integration.internet_kit import ANTHROPIC, made_up_key

    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE, 0o700)
    CONFIG.parent.mkdir(mode=0o755, exist_ok=True)
    LAB.mkdir(mode=0o700, exist_ok=True)
    write_private(CONFIG, render_config())
    write_private(STATE / "gateway.token", secrets.token_urlsafe(32) + "\n")
    keys = STATE / "keys"
    keys.mkdir(mode=0o700, exist_ok=True)
    key = made_up_key("anthropic")
    write_private(keys / f"{ANTHROPIC}.key", key + "\n")
    write_private(REAL_KEY_FILE, key)
    # The fake internet's kit copies backtide's package next to the state; under the hardened
    # unit (ProtectSystem=strict) that folder is read-only, so it is made here, once.
    from backtide.service.config import ServiceConfig
    from tests.integration.proxy_kit import package_copy

    package_copy(ServiceConfig.from_file(CONFIG))
    for image in (IMAGE, proxy_config.IMAGE, sensor_jail.IMAGE):
        start = time.monotonic()
        subprocess.run(["docker", "pull", "--quiet", image], check=True, timeout=3600)
        size = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Size}}", image],
            check=True, capture_output=True, text=True,
        ).stdout.strip()  # fmt: skip
        result(
            f"pull_{image.split('@')[0]}", f"{time.monotonic() - start:.0f}s {int(size) >> 20}MiB"
        )


def fresh_folder(path: Path) -> None:
    """Remove a previous run's fake internet: its files are read-only on purpose, and a root
    without CAP_DAC_OVERRIDE (the hardened unit) can neither write over them nor delete them
    from a read-only folder until the folders are writable again."""
    if not path.exists():
        return
    for folder, _, _ in os.walk(path):
        os.chmod(folder, 0o700)
    shutil.rmtree(path)


def servir() -> int:
    import backtide.cli as cli
    from backtide.jail import AgentJail
    from backtide.jail.proxy import ProxyJail
    from backtide.service import runner
    from backtide.service.config import ServiceConfig
    from tests.integration.internet_kit import start_fake_internet_for
    from tests.integration.proxy_kit import read_grants

    config = ServiceConfig.from_file(CONFIG)
    fresh_folder(LAB / "internet")
    # Each fake internet has a new CA, and backtide (rightly) refuses a proxy made for an
    # older one. In production the CA does not change between starts.
    subprocess.run(["docker", "rm", "--force", "backtide-egress"], capture_output=True)
    internet = start_fake_internet_for(config, LAB / "internet", name="backtide-test-agent-t13")
    INTERNET_FILE.write_text(
        json.dumps({"name": internet.name, "ip": internet.ip, "ca": internet.ca_pem})
    )
    grants = read_grants(internet.grants_file)

    def serve(config: ServiceConfig) -> None:
        jail = AgentJail(config.jail_config())  # production: no allow_shared_ids
        proxy = ProxyJail(replace(config.proxy_jail_config(), internal_egress=True, **grants))
        runner.serve(config, jail=jail, proxy=proxy)  # the sensor too, with its defaults

    cli.serve = serve  # type: ignore[attr-defined]
    PID_FILE.write_text(f"{os.getpid()}\n")
    try:
        return cli.main(["vigilar", "--config", str(CONFIG)])
    finally:
        PID_FILE.unlink(missing_ok=True)
        internet.remove()


def wait(predicate, timeout: float, interval: float = 1.0) -> float | None:  # noqa: ANN001
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if predicate():
            return time.monotonic() - start
        time.sleep(interval)
    return None


def comprobar() -> None:  # noqa: PLR0915 - one check after another, as a report
    from backtide.blackbox import BlackBox, load_key
    from backtide.jail import AgentJail
    from backtide.jail import docker as jail_docker
    from backtide.service.config import ServiceConfig
    from backtide.snapshots import SnapshotStore, btrfs
    from tests.integration.internet_kit import (
        ANTHROPIC_HOST,
        PLAIN_HOST,
        REPLY_TEXT,
        FakeInternet,
    )

    config = ServiceConfig.from_file(CONFIG)
    jail = AgentJail(config.jail_config())
    store = SnapshotStore(VOLUME)
    if wait(INTERNET_FILE.exists, 120) is None:
        result("fake_internet", "NO (see the service log)")
        return
    info = json.loads(INTERNET_FILE.read_text())
    internet = FakeInternet(info["name"], info["ip"], info["ca"], LAB / "internet" / "grants.json")
    box = BlackBox(
        config.blackbox_db,
        load_key(config.blackbox_key),
        checkpoint_path=config.blackbox_checkpoint,
        readonly=True,
    )

    def events(source: str | None = None, action: str | None = None) -> list:
        return box.events(source=source, action=action)

    took = wait(lambda: events(action="agent_start") and jail.is_running(), 600)
    result(
        "agent_started", f"yes ({took:.0f}s after the check began)" if took is not None else "NO"
    )
    if took is None:
        print(subprocess.run(["tail", "-40", str(LOG)], capture_output=True, text=True).stdout)
        return
    name = config.jail_config().name
    user = jail_docker.run(["inspect", "--format", "{{.Config.User}}", name]).stdout.strip()
    result("agent_user", user)
    pid = jail_docker.run(["inspect", "--format", "{{.State.Pid}}", name]).stdout.strip()
    status = Path(f"/proc/{pid}/status").read_text()
    uids = next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1:]
    capeff = next(line for line in status.splitlines() if line.startswith("CapEff:")).split()[1]
    result("agent_host_uids", ",".join(uids))
    result("agent_capeff", capeff)
    label = Path(f"/proc/{pid}/attr/current").read_text().strip("\x00\n")
    result("agent_process_label", label)
    for other in (config.proxy_jail_config().name, config.sensor_jail_config().name):
        running = jail_docker.run(["inspect", "--format", "{{.State.Running}} {{.Config.User}}",
                                   other], check=False)  # fmt: skip
        result(f"container_{other}", running.stdout.strip() or running.stderr.strip())
    owner = os.stat(config.jail_config().agent_dir)
    result("agent_dir_owner", f"{owner.st_uid}:{owner.st_gid} {oct(owner.st_mode & 0o7777)}")

    def healthy() -> bool:
        probe = ["curl", "-fsS", "http://127.0.0.1:18789/healthz"]
        return jail.exec(probe, timeout=30).returncode == 0

    took = wait(healthy, 180)
    result("healthz_after", f"{took:.0f}s" if took is not None else "NEVER")
    health = jail.exec(["curl", "-fsS", "http://127.0.0.1:18789/healthz"], timeout=30)
    result("healthz", health.stdout.strip()[:80] or health.stderr.strip()[:200])
    try:
        usage = btrfs.qgroup_usage(store.workspace)
        result("workspace_cap", f"limit={usage.limit} used={usage.referenced}")
    except Exception as error:  # noqa: BLE001 - reported, this is a report
        result("workspace_cap", f"ERROR {error}")

    # A turn with the fake model: the proxy swaps the fake key for the made-up real one.
    real = REAL_KEY_FILE.read_text()
    before = len(internet.requests(ANTHROPIC_HOST))
    start = time.monotonic()
    turn = jail.exec(["node", "openclaw.mjs", "agent", "--agent", "main", "--message",
                      "Say the test phrase.", "--json"], timeout=TURN_TIMEOUT)  # fmt: skip
    result(
        "turn", f"{'ok' if REPLY_TEXT in turn.stdout else 'FAIL'} {time.monotonic() - start:.1f}s"
    )
    if REPLY_TEXT not in turn.stdout:
        print((turn.stdout + turn.stderr)[-2000:])
    calls = internet.requests(ANTHROPIC_HOST)[before:]
    result("provider_got_real_key", bool(calls) and all(
        c["headers"].get("x-api-key") == real for c in calls))  # fmt: skip
    llm = events(source="llm")
    result("llm_events", sorted({e.action for e in llm}))

    # Out without the proxy: nothing.
    connect = (
        "import socket,sys\n"
        "try:\n socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5).close();"
        "print('connected')\n"
        "except OSError as e:\n print(type(e).__name__)\n"
    )
    direct = [jail.exec(["python3", "-c", connect, internet.ip, port]).stdout.strip()
              for port in ("443", "8443")]  # fmt: skip
    result("direct_connect", direct)
    no_proxy = ["env", "-u", "HTTPS_PROXY", "-u", "https_proxy", "-u", "HTTP_PROXY", "-u",
                "http_proxy", "-u", "OPENCLAW_PROXY_URL"]  # fmt: skip
    curl = jail.exec([*no_proxy, "curl", "-sS", "--max-time", "10", f"https://{PLAIN_HOST}/t13"])
    result("direct_curl_fails", curl.returncode != 0)
    through = jail.exec(["curl", "-sS", "--max-time", "20", f"https://{PLAIN_HOST}/t13-proxied"])
    result("proxied_curl", through.returncode == 0)

    # Files: the watcher (root, inotify) sees what the agent (61000) writes.
    snaps_before = {s.id for s in store.snapshots()}
    jail.exec(["sh", "-c", f"mkdir -p /workspace/work && echo v1 > /workspace/work/{FILE_NAME}"],
              check=True)  # fmt: skip
    took = wait(lambda: any(FILE_NAME in str(e.target) for e in events(source="file")), 60)
    result("file_event", f"yes {took:.1f}s" if took is not None else "NO")
    took = wait(lambda: any(s.id not in snaps_before for s in store.snapshots()), 120)
    result("snapshot_after_write", f"yes {took:.1f}s" if took is not None else "NO")
    target = store.snapshots()[-1].id if took is not None else None

    # The sensor: an exec with a nonce.
    jail.exec(["sh", "-c", f"true {NONCE}"])
    took = wait(lambda: any(NONCE in json.dumps(e.details) + str(e.target)
                            for e in events(source="exec")), 60)  # fmt: skip
    result("sensor_exec", f"yes {took:.1f}s" if took is not None else "NO")
    result("sensor_events", len(events(source="exec")))

    # Rewind as root, without user_subvol_rm_allowed: back to v1 after writing v2.
    if target is not None:
        jail.exec(["sh", "-c", f"echo v2 > /workspace/work/{FILE_NAME}"], check=True)
        start = time.monotonic()
        backtide = str(Path(sys.executable).parent / "backtide")
        done = subprocess.run(
            [backtide, "rebobinar", "--config", str(CONFIG), target, "--si"],
            capture_output=True, text=True, timeout=600,
        )  # fmt: skip
        result("rewind_exit", f"{done.returncode} {time.monotonic() - start:.1f}s")
        if done.returncode != 0:
            print((done.stdout + done.stderr)[-2000:])
        back = wait(lambda: jail.is_running(), 300)
        text = (config.jail_config().agent_dir / "work" / FILE_NAME).read_text().strip()
        result("rewind_content", f"{text} (agent running again: {back is not None})")
    # The black box: the chain and the checkpoint; and the made-up key is nowhere in it.
    report = box.verify()
    result("verify", "ok" if report.ok else report.problems)
    leaked = [str(p) for p in (config.blackbox_db, Path(f"{config.blackbox_db}-wal"),
                               config.blackbox_checkpoint, LOG)
              if p.exists() and real.encode() in p.read_bytes()]  # fmt: skip
    result("real_key_leaks", leaked)
    result("events_total", len(events()))


def parar() -> None:
    try:
        pid = int(PID_FILE.read_text())
    except (OSError, ValueError):
        result("service", "not running")
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pid = 0  # a pid file left by a service that died
        PID_FILE.unlink(missing_ok=True)
        took = wait(lambda: not pid or not Path(f"/proc/{pid}").exists(), 180)
        result("service_stop", f"{took:.0f}s" if took is not None else "STILL RUNNING")
    # The next run brings a fake internet with a new CA, and backtide (rightly) refuses a
    # proxy made for another one: remove it with the fake internet.
    for name in ("backtide-test-agent-t13", "backtide-egress"):
        subprocess.run(["docker", "rm", "--force", name], capture_output=True)
    left = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                          capture_output=True, text=True).stdout.split()  # fmt: skip
    result("containers_left", left)


def main() -> int:
    require_clean_vm_root()
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "preparar":
        preparar()
    elif command == "servir":
        return servir()
    elif command == "comprobar":
        comprobar()
    elif command == "parar":
        parar()
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
