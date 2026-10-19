"""The T07-1 spike: what Tetragon really does in the VM, before backtide relies on it (docs/23).

Each test pins one assumption of the design (P1-P14 in docs/23, "Sesiones") and stays as a
regression test for Tetragon and kernel upgrades. The results and figures are in docs/23,
"Resultados en la VM"; the real event lines, in tests/fixtures/tetragon/.

How it runs:
- Tetragon is the pinned v1.7.1 image, started with the argv of docs/23 section 2:
  ``--privileged --pid=host --cgroupns=host --network none``, the BTF read-only, and only its
  own folders mounted (events read-write, tp.d and conf.d read-only). Nothing of backtide, no
  docker.sock. Every sensor container is removed when its test or module ends, also on
  failure, and a killed run's are removed by the next one (the names carry the pytest pid).
- Settings go in conf.d, one file per option, as backtide will write them. One difference with
  production: ``export-file-perm`` is 644 here, so the unprivileged test user can read the
  file (production: 600, root only). The file lives in this run's 0700 tmp directory.
- The processes to watch run in a throwaway "target" container from the OpenClaw image (it
  has sh and python3) with ``--network none``, no capabilities and a fixed user. The at-rest
  test uses the real OpenClaw in its jail (``running_agent``).
- Connections only go to TEST-NET addresses (192.0.2.0/24, 2001:db8::/32) from a container
  without a route, or to a closed port on loopback: nothing leaves the VM.
- Run with ``make it IT="-s tests/integration/test_sensor_assumptions.py"`` to see the
  ``RESULT`` and ``CAPTURE`` lines (figures and raw events) that docs/23 and the fixtures use.
"""

import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from backtide.jail import docker as jail_docker
from tests.integration.conftest import RunningAgent

pytestmark = pytest.mark.integration

TETRAGON_VERSION = "v1.7.1"
TETRAGON_INDEX_DIGEST = "sha256:afc9458ba4bc3f2795da3df6b03d88ce50e175ac3903027de8036e2046b84a02"
TETRAGON_REPO = "quay.io/cilium/tetragon"
TETRAGON_IMAGE = f"{TETRAGON_REPO}:{TETRAGON_VERSION}@{TETRAGON_INDEX_DIGEST}"
IMAGE_PULL_TIMEOUT = 900.0  # about 84 MB compressed
VM_HOSTNAME = "lima-vigia-dev"
BTF = "/sys/kernel/btf/vmlinux"
SOCKET = "unix:///var/run/tetragon/tetragon.sock"
EVENTS_IN_CONTAINER = "/var/log/tetragon"
LOG_NAME = "tetragon.log"
POLICY = Path(__file__).parents[2] / "deploy" / "tetragon" / "backtide-connect.yaml"
# Test containers are named <prefix><pytest pid>-<random>, like the test agents (conftest.py).
SENSOR_PREFIX = "backtide-test-tetragon-"
TARGET_PREFIX = "backtide-test-sensortarget-"
READY_TIMEOUT = 90.0
EVENT_TIMEOUT = 30.0
TARGET_USER = "1000:1000"
REDACTED = "*****"

# The redaction rules of docs/23 section 5, as Python regexes (RE2 syntax); json.dumps writes
# them as Tetragon reads them, one JSON object per line.
REDACTION_RULES: tuple[tuple[str, ...], ...] = (
    (
        r"(?i)(?:authorization|x-api-key|api-key|x-goog-api-key|cookie)[\"']?\s*[:=]\s*"
        r"(?:bearer\s+|basic\s+)?(\S+)",
    ),
    (r"(?:--?(?:password|passwd|secret|token|api-key|apikey))(?:\s+|=)(\S+)",),
    (
        r"\b(sk-[A-Za-z0-9_-]{16,})",
        r"\b(gh[pousr]_[A-Za-z0-9]{20,})",
        r"\b(AKIA[A-Z0-9]{16})\b",
        r"(?://[^/\s:@]+:)([^/\s@]+)(?:@)",
    ),
)


def design_settings(**overrides: str) -> dict[str, str]:
    """The conf.d of docs/23 section 2 (with export-file-perm 644, see the module docstring)."""
    settings = {
        "export-filename": f"{EVENTS_IN_CONTAINER}/{LOG_NAME}",
        "export-file-max-size-mb": "50",
        "export-file-max-backups": "8",
        "export-file-compress": "false",
        "export-file-perm": "644",
        # Plan B of P10: THROTTLE events carry no process (so no container id) and the
        # container_id filter alone dropped them. Filters on separate lines are OR-ed.
        "export-allowlist": "\n".join(
            json.dumps(f) for f in ({"container_id": ["."]}, {"event_set": ["PROCESS_THROTTLE"]})
        ),
        "cgroup-rate": "1000,1s",
        "redaction-filters": "\n".join(json.dumps({"redact": list(r)}) for r in REDACTION_RULES),
        "server-address": SOCKET,
        "health-server-address": "",
        "log-level": "warn",
    }
    settings.update(overrides)
    return settings


PRIVILEGED = ("--privileged", "--pid=host", "--cgroupns=host")


def report(name: str, value: object) -> None:
    """A figure for docs/23 (see ``-s`` in the module docstring)."""
    print(f"\nRESULT {name} {json.dumps(value, sort_keys=True)}", flush=True)


def capture(name: str, line: str) -> None:
    """A raw event line for tests/fixtures/tetragon/."""
    print(f"\nCAPTURE {name} {line}", flush=True)


def docker(
    *args: str, check: bool = True, timeout: float = 120.0, max_output: int = 4 * 1024 * 1024
) -> subprocess.CompletedProcess[str]:
    return jail_docker.run(list(args), check=check, timeout=timeout, max_output=max_output)


# --- events -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Event:
    raw: str
    data: dict[str, Any]

    @property
    def kind(self) -> str:
        return next((k for k in self.data if k.startswith("process_")), "")

    @property
    def body(self) -> dict[str, Any]:
        return self.data.get(self.kind, {})

    @property
    def process(self) -> dict[str, Any]:
        return self.body.get("process", {})

    @property
    def docker_id(self) -> str:
        return self.process.get("docker", "")

    @property
    def arguments(self) -> str:
        return self.process.get("arguments", "")

    def of(self, container_id: str) -> bool:
        """Attribution as docs/23 wants it: by the parsed field, at least 12 characters."""
        prefix = self.docker_id
        return len(prefix) >= 12 and container_id.startswith(prefix)

    def sockaddr(self) -> dict[str, Any] | None:
        for arg in self.body.get("args", []):
            if "sockaddr_arg" in arg:
                return arg["sockaddr_arg"]
        return None

    def sock(self) -> dict[str, Any] | None:
        for arg in self.body.get("args", []):
            for key in ("sock_arg", "socket_arg"):
                if key in arg:
                    return arg[key]
        return None


@dataclass
class Sensor:
    """One running Tetragon container and its export file, read incrementally."""

    name: str
    events_dir: Path
    events: list[Event] = field(default_factory=list)
    bad_lines: int = 0
    _offset: int = 0
    _inode: int | None = None

    @property
    def log(self) -> Path:
        return self.events_dir / LOG_NAME

    def poll(self) -> list[Event]:
        """Read the complete lines added to tetragon.log since the last poll."""
        try:
            with self.log.open("rb") as f:
                inode = os.fstat(f.fileno()).st_ino
                if inode != self._inode:  # first read, or rotated: start the new file
                    self._inode, self._offset = inode, 0
                f.seek(self._offset)
                chunk = f.read()
        except FileNotFoundError:
            return []
        end = chunk.rfind(b"\n") + 1  # a partial last line waits for the next poll
        self._offset += end
        new: list[Event] = []
        for raw in chunk[:end].splitlines():
            text = raw.decode("utf-8", "backslashreplace")
            try:
                new.append(Event(text, json.loads(text)))
            except ValueError:
                self.bad_lines += 1
        self.events.extend(new)
        return new

    def wait_for(
        self, predicate: Callable[[Event], bool], *, timeout: float = EVENT_TIMEOUT, since: int = 0
    ) -> Event:
        deadline = time.monotonic() + timeout
        while True:
            self.poll()
            for event in self.events[since:]:
                if predicate(event):
                    return event
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"no matching event in {timeout} s ({len(self.events)} events read); "
                    f"sensor logs: {self.logs()[-2000:]}"
                )
            time.sleep(0.2)

    def settle(self, seconds: float = 2.0) -> None:
        """Wait a little and read what Tetragon wrote meanwhile (its writes are buffered)."""
        time.sleep(seconds)
        self.poll()

    def logs(self) -> str:
        result = docker("logs", self.name, check=False)
        return result.stdout + result.stderr

    def tetra(self, *args: str) -> subprocess.CompletedProcess[str]:
        return docker("exec", self.name, "tetra", "--server-address", SOCKET, *args, check=False)

    def pid(self) -> int:
        return int(docker("inspect", "--format", "{{.State.Pid}}", self.name).stdout.strip())

    def running(self) -> bool:
        state = docker("inspect", "--format", "{{.State.Running}}", self.name, check=False)
        return state.stdout.strip() == "true"


@dataclass(frozen=True)
class Target:
    """A throwaway container whose processes the sensor should see."""

    name: str
    id: str

    def exec(self, *argv: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        return docker("exec", self.name, *argv, check=False, timeout=timeout)


def exec_with(marker: str, container_id: str) -> Callable[[Event], bool]:
    return lambda e: e.kind == "process_exec" and e.of(container_id) and marker in e.arguments


def connects(events: Sequence[Event], container_id: str | None = None) -> list[Event]:
    return [
        e
        for e in events
        if e.kind == "process_kprobe"
        and e.sockaddr() is not None
        and (container_id is None or e.of(container_id))
    ]


# --- containers ---------------------------------------------------------------------------


def _require_dev_vm() -> None:
    if sys.platform != "linux" or platform.node() != VM_HOSTNAME:
        pytest.fail(f"integration tests run only inside the {VM_HOSTNAME} VM: use `make it`")


def _is_pytest_alive(pid: int) -> bool:
    try:
        return b"pytest" in Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return False


def _remove_stale_containers() -> None:
    """Remove the sensors and targets of killed runs: a privileged container never stays."""
    names = docker("ps", "--all", "--format", "{{.Names}}").stdout.split()
    for name in names:
        for prefix in (SENSOR_PREFIX, TARGET_PREFIX):
            if name.startswith(prefix):
                pid = name.removeprefix(prefix).partition("-")[0]
                if not pid.isdigit() or not _is_pytest_alive(int(pid)):
                    docker("rm", "--force", "--volumes", name)


def _unique(prefix: str) -> str:
    return f"{prefix}{os.getpid()}-{uuid4().hex[:12]}"


@pytest.fixture(scope="module")
def tetragon_image() -> str:
    """The pinned image, pulled by digest the first time (the registry cannot swap it)."""
    _require_dev_vm()
    _remove_stale_containers()
    if docker("image", "inspect", TETRAGON_IMAGE, check=False).returncode != 0:
        docker("pull", "--quiet", TETRAGON_IMAGE, timeout=IMAGE_PULL_TIMEOUT)
    return TETRAGON_IMAGE


@pytest.fixture(scope="module")
def target(agent_image: str) -> Iterator[Target]:
    """The OpenClaw image running a shell loop: a ``sleep 1`` every second from its own init
    tree (for in_init_tree), without network, capabilities or root."""
    _require_dev_vm()
    _remove_stale_containers()
    name = _unique(TARGET_PREFIX)
    try:
        container_id = docker(
            "run", "--detach", "--name", name, "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", TARGET_USER, "--memory", "256m",
            "--pids-limit", "256", "--entrypoint", "sh", agent_image,
            "-c", "while :; do sleep 1; done",
        ).stdout.strip()  # fmt: skip
        yield Target(name, container_id)
    finally:
        docker("rm", "--force", "--volumes", name, check=False)


@contextmanager
def tetragon(
    base: Path,
    image: str,
    settings: dict[str, str],
    *,
    privileges: Sequence[str] = PRIVILEGED,
    policy: bool = True,
    events_mode: int = 0o700,
) -> Iterator[Sensor]:
    """Start a sensor with these conf.d ``settings`` (and the connect policy in tp.d). Yields
    at once: ``wait_ready`` says when it sees. Removed on the way out, whatever happens."""
    events, tp, conf = base / "events", base / "tp.d", base / "conf.d"
    events.mkdir(mode=events_mode)
    events.chmod(events_mode)  # mkdir applies the umask
    tp.mkdir(mode=0o755)
    conf.mkdir(mode=0o755)
    for option, value in settings.items():
        (conf / option).write_text(value)
    if policy:
        (tp / POLICY.name).write_text(POLICY.read_text())
    name = _unique(SENSOR_PREFIX)
    argv = [
        "run", "--detach", "--name", name, *privileges, "--network", "none",
        "--restart", "no", "--memory", "1g", "--cpus", "1",
        "--log-driver", "local", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
        "--volume", f"{BTF}:/var/lib/tetragon/btf:ro",
        "--volume", f"{events}:{EVENTS_IN_CONTAINER}",
        "--volume", f"{tp}:/etc/tetragon/tetragon.tp.d:ro",
        "--volume", f"{conf}:/etc/tetragon/tetragon.conf.d:ro",
        image,
    ]  # fmt: skip
    try:
        docker(*argv)
        yield Sensor(name, events)
    finally:
        # SIGTERM first, so Tetragon unloads its programs itself; then remove it anyway.
        docker("stop", "--time", "10", name, check=False, timeout=60)
        docker("rm", "--force", "--volumes", name, check=False)
        for path in events.iterdir():  # root's files in our directory: we may unlink them
            path.unlink()


@dataclass
class Readiness:
    running: float | None = None
    first_line: float | None = None
    status_ok: float | None = None
    policy_enabled: float | None = None
    marker_seen: float | None = None
    status_output: str = ""
    policy_output: str = ""


def wait_ready(sensor: Sensor, target: Target, timeout: float = READY_TIMEOUT) -> Readiness:
    """Probe like the heartbeat will (an exec with a nonce in the target) until it shows up,
    and time the other candidate signals of readiness on the way (P13). Seconds since
    ``docker run`` returned."""
    start = time.monotonic()
    ready = Readiness()
    nonce = f"backtide-ready-{secrets.token_hex(6)}"

    def elapsed() -> float:
        return round(time.monotonic() - start, 2)

    while time.monotonic() - start < timeout:
        if ready.running is None and sensor.running():
            ready.running = elapsed()
        if ready.status_ok is None:
            status = sensor.tetra("status")
            ready.status_output = (status.stdout + status.stderr).strip()[:300]
            if status.returncode == 0 and "running" in status.stdout.lower():
                ready.status_ok = elapsed()
        if ready.policy_enabled is None:
            policies = sensor.tetra("tracingpolicy", "list")
            if policies.returncode == 0 and "enabled" in policies.stdout:
                ready.policy_enabled, ready.policy_output = elapsed(), policies.stdout.strip()
        if ready.first_line is None and sensor.log.exists() and sensor.log.stat().st_size > 0:
            ready.first_line = elapsed()
        target.exec("/bin/true", nonce)
        sensor.poll()
        if any(exec_with(nonce, target.id)(e) for e in sensor.events):
            ready.marker_seen = elapsed()
            return ready
        if not sensor.running():
            break
        time.sleep(0.2)
    raise AssertionError(f"the sensor did not see the target: {ready}; logs: {sensor.logs()}")


@pytest.fixture(scope="module")
def sensor_and_readiness(
    tetragon_image: str, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[Sensor, Readiness]]:
    """The sensor as docs/23 designs it, started after the target and ready."""
    with tetragon(tmp_path_factory.mktemp("sensor"), tetragon_image, design_settings()) as s:
        ready = wait_ready(s, target)
        yield s, ready


@pytest.fixture
def sensor(sensor_and_readiness: tuple[Sensor, Readiness]) -> Sensor:
    return sensor_and_readiness[0]


# --- P1, P2: it loads, under SELinux Enforcing ----------------------------------------------


def test_p1_the_pinned_image_loads_with_the_design_argv(
    sensor: Sensor, tetragon_image: str
) -> None:
    digests = json.loads(
        docker("image", "inspect", "--format", "{{json .RepoDigests}}", tetragon_image).stdout
    )
    assert f"{TETRAGON_REPO}@{TETRAGON_INDEX_DIGEST}" in digests
    arch = docker("image", "inspect", "--format", "{{.Architecture}}", tetragon_image).stdout
    version = sensor.tetra("version")
    assert TETRAGON_VERSION.removeprefix("v") in version.stdout, version
    kernel = platform.release()
    assert sensor.running()
    # The one error Tetragon logs on this kernel is a feature probe for enforcement
    # (fmod_ret: CONFIG_BPF_KPROBE_OVERRIDE is missing, docs/23 section 8). We only observe.
    errors = [
        line
        for line in sensor.logs().splitlines()
        if "level=error" in line.lower() and "detect modify return syscall" not in line
    ]
    assert not errors, errors
    assert "pre-validation issued a warning" not in sensor.logs()
    report(
        "p1",
        {
            "digests": digests,
            "arch": arch.strip(),
            "version": version.stdout.strip(),
            "kernel": kernel,
            "log_lines": sensor.logs().splitlines()[:20],
        },
    )


def test_p2_selinux_is_enforcing_and_the_sensor_runs_unconfined(sensor: Sensor) -> None:
    assert Path("/sys/fs/selinux/enforce").read_text().strip() == "1"
    label = Path(f"/proc/{sensor.pid()}/attr/current").read_text().strip("\x00\n")
    process_label = docker("inspect", "--format", "{{.ProcessLabel}}", sensor.name).stdout
    report("p2", {"label": label, "docker_process_label": process_label.strip()})
    assert ":spc_t:" in label


# --- P3, P4: attribution and the init tree --------------------------------------------------


def test_p3_the_docker_field_is_a_prefix_of_the_container_id(
    sensor: Sensor, target: Target
) -> None:
    nonce = f"backtide-p3-{secrets.token_hex(6)}"
    target.exec("/bin/true", nonce)
    event = sensor.wait_for(lambda e: e.kind == "process_exec" and nonce in e.arguments)
    docker_id = event.docker_id
    assert docker_id and target.id.startswith(docker_id)
    assert len(docker_id) >= 12
    report("p3", {"docker": docker_id, "length": len(docker_id), "full_id": target.id})
    capture("exec_docker_exec", event.raw)


def test_p4_in_init_tree_tells_docker_exec_from_the_containers_own_tree(
    sensor: Sensor, target: Target
) -> None:
    start = len(sensor.events)
    nonce = f"backtide-p4-{secrets.token_hex(6)}"
    target.exec("/bin/true", nonce)
    injected = sensor.wait_for(exec_with(nonce, target.id), since=start)
    own = sensor.wait_for(
        lambda e: (
            e.kind == "process_exec"
            and e.of(target.id)
            and e.process.get("binary", "").endswith("/sleep")
        ),
        since=start,
    )
    assert injected.process.get("in_init_tree", False) is False
    assert own.process.get("in_init_tree") is True
    preexisting = [
        e for e in sensor.events if e.of(target.id) and "procFS" in e.process.get("flags", "")
    ]
    assert preexisting, "the target's shell existed before the sensor: it comes as procFS"
    exits = [e for e in sensor.events if e.kind == "process_exit" and e.of(target.id)]
    assert exits
    report(
        "p4",
        {
            "injected_keys": sorted(injected.process),
            "injected_parent": injected.body.get("parent", {}).get("binary"),
            "own_parent": own.body.get("parent", {}).get("binary"),
            "preexisting_flags": preexisting[0].process.get("flags"),
            "exit_keys": sorted(exits[-1].body),
        },
    )
    capture("exec_init_tree", own.raw)
    capture("exec_procfs", preexisting[0].raw)
    capture("exit_normal", exits[-1].raw)


def test_p4_a_process_killed_by_a_signal(sensor: Sensor, target: Target) -> None:
    start = len(sensor.events)
    target.exec("sh", "-c", "kill -KILL $$")
    event = sensor.wait_for(
        lambda e: e.kind == "process_exit" and e.of(target.id) and e.body.get("signal"),
        since=start,
    )
    report("p4_signal", {"signal": event.body.get("signal"), "status": event.body.get("status")})
    assert event.body["signal"] == "SIGKILL"
    capture("exit_signal", event.raw)


# --- P5: long arguments -------------------------------------------------------------------


def test_p5_long_arguments_arrive_whole_up_to_320_kib_and_vanish_beyond(
    sensor: Sensor, target: Target
) -> None:
    """Tetragon never cuts the arguments of these sizes (no ``truncArgs``): up to about
    320 KiB in all they arrive whole (``dataArgs`` past ~1 KiB), and beyond that the event
    still comes, with the binary, but with no ``arguments`` at all and no flag saying so."""
    results: dict[str, dict[str, Any]] = {}
    for size in (256, 1024, 100_000):
        nonce = f"backtide-p5-{size}-{secrets.token_hex(4)}"
        script = f"pass  # {nonce} " + "x" * size
        start = len(sensor.events)
        target.exec("python3", "-c", script)
        event = sensor.wait_for(exec_with(nonce, target.id), since=start)
        results[str(size)] = _argument_info(event)
        if size == 100_000:
            capture("exec_long_arguments", event.raw)
    for total in (320_000, 400_000):  # several arguments: one cannot pass 128 KiB
        nonce = f"backtide-p5-many-{total}-{secrets.token_hex(4)}"
        chunks = ["y" * 100_000] * (total // 100_000) + ["z" * (total % 100_000)]
        start = len(sensor.events)
        assert target.exec("/bin/true", nonce, *filter(None, chunks)).returncode == 0
        event = sensor.wait_for(
            lambda e: (
                e.kind == "process_exec"
                and e.of(target.id)
                and e.process.get("binary") == "/bin/true"
            ),
            since=start,
        )
        results[str(total)] = _argument_info(event)
        if total == 400_000:
            capture("exec_arguments_lost", event.raw)
    report("p5", results)
    assert "dataArgs" not in results["256"]["flags"]
    assert "dataArgs" in results["1024"]["flags"]
    assert results["100000"]["arguments"] > 100_000
    assert results["320000"]["arguments"] > 320_000
    assert results["400000"]["arguments"] == 0  # gone: the plan B of docs/23 records that
    assert all("truncArgs" not in r["flags"] for r in results.values())


def _argument_info(event: Event) -> dict[str, Any]:
    return {
        "arguments": len(event.arguments),
        "flags": event.process.get("flags", ""),
        "line_bytes": len(event.raw.encode()),
    }


# --- P6: the allowlist keeps the host out -------------------------------------------------


def test_p6_the_allowlist_drops_host_processes_and_keeps_containers(
    sensor: Sensor, target: Target
) -> None:
    host_nonce = f"backtide-p6-host-{secrets.token_hex(6)}"
    container_nonce = f"backtide-p6-ctr-{secrets.token_hex(6)}"
    subprocess.run(["/bin/true", host_nonce], check=True)
    target.exec("/bin/true", container_nonce)
    sensor.wait_for(exec_with(container_nonce, target.id))
    sensor.settle(3)
    assert not [e for e in sensor.events if host_nonce in e.raw]
    no_container = [e for e in sensor.events if e.kind != "process_throttle" and not e.docker_id]
    kinds = sorted({e.kind for e in sensor.events})
    report(
        "p6", {"events": len(sensor.events), "without_docker": len(no_container), "kinds": kinds}
    )
    assert not no_container, no_container[0].raw


# --- P7, P8: connections ------------------------------------------------------------------

CONNECT_SCRIPT = """
import json, socket, sys
port = int(sys.argv[1])
cases = [
    ("tcp4", socket.AF_INET, socket.SOCK_STREAM, ("192.0.2.1", port)),
    ("tcp6", socket.AF_INET6, socket.SOCK_STREAM, ("2001:db8::1", port)),
    ("udp4", socket.AF_INET, socket.SOCK_DGRAM, ("192.0.2.1", port)),
    ("loop4", socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", port)),
]
out = {}
for name, family, kind, addr in cases:
    try:
        s = socket.socket(family, kind)
    except OSError as e:
        out[name] = "socket:" + str(e.errno)
        continue
    s.settimeout(2)
    try:
        s.connect(addr)
        out[name] = "connected"
    except OSError as e:
        out[name] = e.errno
    finally:
        s.close()
print(json.dumps(out))
"""

SENDTO_SCRIPT = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", ("192.0.2.2", int(sys.argv[1])))
    print("sent")
except OSError as e:
    print(e.errno)
"""


def _policy_loaded(sensor: Sensor) -> str:
    listing = sensor.tetra("tracingpolicy", "list")
    assert listing.returncode == 0, listing
    assert "backtide-connect" in listing.stdout
    assert "enabled" in listing.stdout.lower(), listing.stdout
    return listing.stdout


def test_p7_the_connect_policy_sees_failed_connects_outside_the_host_netns(
    sensor: Sensor, target: Target, agent_image: str
) -> None:
    listing = _policy_loaded(sensor)
    port = 20000 + secrets.randbelow(20000)
    start = len(sensor.events)
    outcome = json.loads(target.exec("python3", "-c", CONNECT_SCRIPT, str(port)).stdout)
    seen = {}
    for name, addr in (("tcp4", "192.0.2.1"), ("tcp6", "2001:db8::1"), ("loop4", "127.0.0.1")):
        event = sensor.wait_for(
            lambda e, addr=addr: (
                e.kind == "process_kprobe"
                and e.of(target.id)
                and (e.sockaddr() or {}).get("addr") == addr
                and (e.sockaddr() or {}).get("port") == port
            ),
            since=start,
        )
        seen[name] = {"sockaddr": event.sockaddr(), "sock": event.sock()}
        capture(f"connect_{name}", event.raw)
    udp = [
        e
        for e in connects(sensor.events[start:], target.id)
        if (e.sock() or {}).get("type") == "SOCK_DGRAM"
    ]
    assert udp, "a UDP connect() goes through security_socket_connect too"
    seen["udp4"] = {"sockaddr": udp[0].sockaddr(), "sock": udp[0].sock()}
    capture("connect_udp4", udp[0].raw)

    # NotIn host_ns: the same connect from a container in the host's network namespace (to a
    # closed loopback port: nothing leaves the VM) is dropped by the policy, not by the reader.
    host_port = 40000 + secrets.randbelow(20000)
    host_start = len(sensor.events)
    host_net = docker(
        "run", "--rm", "--network", "host", "--cap-drop", "ALL", "--user", TARGET_USER,
        "--security-opt", "no-new-privileges", "--entrypoint", "python3", agent_image,
        "-c", CONNECT_SCRIPT.replace("192.0.2.1", "127.0.0.1").replace("2001:db8::1", "::1"),
        str(host_port),
    )  # fmt: skip
    sensor.settle(3)
    in_host_ns = [
        e for e in connects(sensor.events[host_start:]) if e.sockaddr().get("port") == host_port
    ]
    report(
        "p7",
        {
            "policy_list": listing.strip(),
            "errno": outcome,
            "seen": seen,
            "host_netns_outcome": host_net.stdout.strip(),
            "host_netns_seen": len(in_host_ns),
        },
    )
    assert not in_host_ns


def test_p8_udp_sendto_without_connect_is_not_seen(sensor: Sensor, target: Target) -> None:
    port = 20000 + secrets.randbelow(20000)
    start = len(sensor.events)
    outcome = target.exec("python3", "-c", SENDTO_SCRIPT, str(port)).stdout.strip()
    sensor.wait_for(
        lambda e: e.kind == "process_exec" and e.of(target.id) and "192.0.2.2" in e.arguments,
        since=start,
    )
    sensor.settle(3)
    seen = [e for e in connects(sensor.events[start:]) if e.sockaddr().get("addr") == "192.0.2.2"]
    report("p8", {"sendto": outcome, "seen": len(seen)})
    assert not seen


# --- P9: rotation -------------------------------------------------------------------------


def _flood(target: Target, count: int, binary: str = "/bin/true") -> float:
    """Run ``count`` execs of ``binary`` in a shell loop inside the target; seconds taken."""
    started = time.monotonic()
    loop = f'i=0; while [ "$i" -lt {count} ]; do {binary}; i=$((i+1)); done'
    result = target.exec("sh", "-c", loop, timeout=300)
    assert result.returncode == 0, result
    return time.monotonic() - started


def _file_info(path: Path) -> dict[str, Any]:
    info = path.stat()
    return {"inode": info.st_ino, "mode": oct(info.st_mode & 0o777), "size": info.st_size}


def test_p9_rotation(
    tetragon_image: str, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> None:
    settings = design_settings(**{"export-file-max-size-mb": "1", "export-file-max-backups": "2"})
    with tetragon(tmp_path_factory.mktemp("rotation"), tetragon_image, settings) as s:
        wait_ready(s, target)
        first = s.log.stat()
        seconds = _flood(target, 4000)
        time.sleep(3)
        files = sorted(s.events_dir.iterdir())
        listing = {p.name: _file_info(p) for p in files}
        execs, kinds, partial = 0, set(), []
        for path in files:
            data = path.read_bytes()
            if data and not data.endswith(b"\n"):
                partial.append(path.name)
            for raw in data.splitlines():
                event = Event(raw.decode(), json.loads(raw))
                kinds.add(event.kind or ",".join(event.data))
                execs += event.kind == "process_exec" and event.of(target.id)
        report(
            "p9",
            {
                "first_inode": first.st_ino,
                "files": listing,
                "target_execs_left": execs,
                "flood_seconds": round(seconds, 1),
                "kinds": sorted(kinds),
                "partial_files": partial,
            },
        )
    rotated = [name for name in listing if name != LOG_NAME]
    assert listing[LOG_NAME]["inode"] != first.st_ino
    assert 1 <= len(rotated) <= 2
    assert all(name.startswith("tetragon-") and name.endswith(".log") for name in rotated)
    assert all(v["mode"] == "0o644" for v in listing.values())  # export-file-perm applies
    assert not partial  # a line is never split across two files
    # The first file (and the oldest backups) were deleted...
    assert first.st_ino not in {v["inode"] for v in listing.values()}
    assert kinds <= {"process_exec", "process_exit", "process_kprobe", "process_throttle"}
    # ...and nothing in the files says so: the reader has to notice by itself (docs/23 s. 3).


# --- P10: cgroup-rate ---------------------------------------------------------------------


def test_p10_cgroup_rate_throttles_and_says_so(
    tetragon_image: str, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> None:
    settings = design_settings(**{"cgroup-rate": "100,1s"})
    with tetragon(tmp_path_factory.mktemp("throttle"), tetragon_image, settings) as s:
        wait_ready(s, target)
        start = len(s.events)
        seconds = _flood(target, 2000)
        throttles = []
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:  # THROTTLE_STOP comes once the rate falls again
            s.settle(1)
            throttles = [e for e in s.events[start:] if e.kind == "process_throttle"]
            if any(e.body.get("type") == "THROTTLE_STOP" for e in throttles):
                break
        execs = [e for e in s.events[start:] if e.kind == "process_exec" and e.of(target.id)]
        report(
            "p10",
            {
                "flood_seconds": round(seconds, 1),
                "rate": round(2000 / seconds),
                "execs_exported": len(execs),
                "throttle": [e.body for e in throttles],
            },
        )
        for e in throttles[:2]:
            capture(f"throttle_{e.body.get('type', '').lower()}", e.raw)
    types = [e.body.get("type") for e in throttles]
    assert "THROTTLE_START" in types and "THROTTLE_STOP" in types
    assert len(execs) < 2000


# --- P11: redaction and field filters -------------------------------------------------------

FAKE_SECRETS = {
    "bearer": "faketokenP11bearer0123456789",
    "password": "hunter2-fake-P11",
    "token_flag": "fake-token-flag-P11-0123",
    "sk": "sk-fakeP11abcdefghijklmnop0123",
    "ghp": "ghp_fakeP11abcdefghijklmnopqrstuv",
    "akia": "AKIAFAKEP11ABCDE0123",
    "url_password": "fakeurlpassP11",
    "api_key_header": "fakeapikeyheaderP11xyz",
}


def test_p11_redaction_filters_apply_to_the_file(sensor: Sensor, target: Target) -> None:
    nonce = f"backtide-p11-{secrets.token_hex(6)}"
    f = FAKE_SECRETS
    args = [
        nonce,
        "-H", f"Authorization: Bearer {f['bearer']}",
        "--password", f["password"],
        f"--token={f['token_flag']}",
        f["sk"],
        f["ghp"],
        f["akia"],
        f"https://someone:{f['url_password']}@example.invalid/repo.git",
        "-H", f"x-api-key: {f['api_key_header']}",
    ]  # fmt: skip
    start = len(sensor.events)
    target.exec("/bin/true", *args)
    event = sensor.wait_for(exec_with(nonce, target.id), since=start)
    sensor.settle(2)
    text = sensor.log.read_text() + sensor.logs()
    leaked = [name for name, value in f.items() if value in text]
    report("p11", {"arguments": event.arguments, "leaked": leaked})
    capture("exec_redacted", event.raw)
    assert not leaked
    assert REDACTED in event.arguments
    assert "environment_variables" not in sensor.log.read_text()


def test_p11_field_filters_shrink_the_exec_events(
    sensor: Sensor, tetragon_image: str, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> None:
    keep = (
        "process.exec_id,process.pid,process.uid,process.cwd,process.binary,process.arguments,"
        "process.flags,process.start_time,process.docker,process.in_init_tree,"
        "process.parent_exec_id,parent.pid,parent.binary"
    )
    filters = json.dumps({"event_set": ["PROCESS_EXEC"], "fields": keep, "action": "INCLUDE"})
    nonce = f"backtide-p11f-{secrets.token_hex(6)}"
    target.exec("/bin/true", nonce)
    full = sensor.wait_for(exec_with(nonce, target.id))
    settings = design_settings(**{"field-filters": filters})
    with tetragon(tmp_path_factory.mktemp("fields"), tetragon_image, settings) as s:
        wait_ready(s, target)
        target.exec("/bin/true", nonce)
        small = s.wait_for(exec_with(nonce, target.id))
    report(
        "p11_fields",
        {
            "full_bytes": len(full.raw),
            "filtered_bytes": len(small.raw),
            "full_process_keys": sorted(full.process),
            "filtered_process_keys": sorted(small.process),
            "filtered_parent_keys": sorted(small.body.get("parent", {})),
        },
    )
    capture("exec_field_filtered", small.raw)
    assert len(small.raw) < len(full.raw)
    assert small.docker_id == full.docker_id


# --- P12: no network, and without --privileged ---------------------------------------------


def _listening(pid: int) -> list[str]:
    found = []
    for table in ("tcp", "tcp6"):
        for line in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A":  # TCP_LISTEN
                found.append(f"{table}:{fields[1]}")
    return found


def test_p12_the_sensor_has_no_network_and_no_listening_port(sensor: Sensor) -> None:
    pid = sensor.pid()
    interfaces = [
        line.split(":")[0].strip()
        for line in Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:]
    ]
    listening = _listening(pid)
    networks = docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", sensor.name)
    report(
        "p12_network",
        {"interfaces": interfaces, "listening": listening, "docker": networks.stdout.strip()},
    )
    assert interfaces == ["lo"]
    assert not listening


UNPRIVILEGED = (
    "--pid=host", "--cgroupns=host", "--cap-drop", "ALL",
    "--cap-add", "SYS_ADMIN", "--cap-add", "BPF", "--cap-add", "PERFMON",
    "--cap-add", "SYS_RESOURCE", "--cap-add", "SYS_PTRACE", "--cap-add", "NET_ADMIN",
    "--cap-add", "DAC_READ_SEARCH",
    "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
)  # fmt: skip


def _try_unprivileged(
    base: Path, image: str, target: Target, extra: Sequence[str]
) -> dict[str, Any]:
    with tetragon(
        base, image, design_settings(), privileges=(*UNPRIVILEGED, *extra), events_mode=0o777
    ) as s:
        try:
            ready = wait_ready(s, target, timeout=45)
            outcome: dict[str, Any] = {
                "works": True,
                "marker_seen": round(ready.marker_seen or 0, 1),
            }
        except AssertionError:
            outcome = {"works": False}
        outcome["running"] = s.running()
        lines = s.logs().splitlines()
        outcome["log"] = [line[:300] for line in lines if "level=" in line][:8]
        return outcome


def test_p12_without_privileged(
    tetragon_image: str, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> None:
    confined = _try_unprivileged(tmp_path_factory.mktemp("unpriv"), tetragon_image, target, ())
    unlabeled = _try_unprivileged(
        tmp_path_factory.mktemp("unpriv-label"),
        tetragon_image,
        target,
        ("--security-opt", "label=disable"),
    )
    report("p12_unprivileged", {"container_t": confined, "label_disable": unlabeled})
    # Both stop before SELinux matters: without --privileged, /sys is read-only and Tetragon
    # cannot create its bpffs folder (/sys/fs/bpf/tetragon). Mounting the host's bpffs would
    # share its pinned programs with the host, and is left for "Después" (docs/23).
    assert not confined["works"]
    assert not unlabeled["works"]


# --- P13: readiness -----------------------------------------------------------------------


def test_p13_how_to_know_it_is_ready(sensor_and_readiness: tuple[Sensor, Readiness]) -> None:
    sensor, ready = sensor_and_readiness
    report(
        "p13",
        {
            "running": ready.running,
            "first_line": ready.first_line,
            "status_ok": ready.status_ok,
            "policy_enabled": ready.policy_enabled,
            "marker_seen": ready.marker_seen,
            "status": ready.status_output,
        },
    )
    assert ready.marker_seen is not None and ready.marker_seen < 30


# --- P14: resources -----------------------------------------------------------------------


def _cgroup(name: str) -> Path:
    """The sensor's cgroup (systemd driver, cgroup v2): its files are readable by anyone."""
    full_id = docker("inspect", "--format", "{{.Id}}", name).stdout.strip()
    return Path(f"/sys/fs/cgroup/system.slice/docker-{full_id}.scope")


def _cpu_seconds(cgroup: Path) -> float:
    for line in (cgroup / "cpu.stat").read_text().splitlines():
        key, value = line.split()
        if key == "usage_usec":
            return int(value) / 1e6
    raise AssertionError("no usage_usec in cpu.stat")


def _mib(cgroup: Path, name: str) -> float:
    return round(int((cgroup / name).read_text()) / 2**20, 1)


FLOOD_EXECS = 20_000


def test_p14_cpu_and_memory_at_rest_and_under_an_exec_flood(sensor: Sensor, target: Target) -> None:
    cgroup = _cgroup(sensor.name)
    sensor.settle(2)
    cpu0, t0 = _cpu_seconds(cgroup), time.monotonic()
    time.sleep(20)
    rest_cpu = (_cpu_seconds(cgroup) - cpu0) / (time.monotonic() - t0)
    rest_mem = _mib(cgroup, "memory.current")
    start = len(sensor.events)
    cpu1, t1 = _cpu_seconds(cgroup), time.monotonic()
    seconds = _flood(target, FLOOD_EXECS)
    sensor.settle(5)
    flood_cpu = _cpu_seconds(cgroup) - cpu1
    window = sensor.events[start:]
    execs = [e for e in window if e.kind == "process_exec" and e.of(target.id)]
    throttles = [e.body for e in window if e.kind == "process_throttle"]
    report(
        "p14",
        {
            "rest_cpu_fraction": round(rest_cpu, 4),
            "rest_memory_mib": rest_mem,
            "flood_execs": FLOOD_EXECS,
            "flood_seconds": round(seconds, 1),
            "flood_rate": round(FLOOD_EXECS / seconds),
            "flood_cpu_seconds": round(flood_cpu, 2),
            "flood_wall_seconds": round(time.monotonic() - t1, 1),
            "memory_peak_mib": _mib(cgroup, "memory.peak"),
            "memory_after_mib": _mib(cgroup, "memory.current"),
            "execs_exported": len(execs),
            "throttle": throttles,
            "log_bytes": sensor.log.stat().st_size,
            "events_total": len(sensor.events),
        },
    )
    assert sensor.running()
    assert len(execs) < FLOOD_EXECS  # cgroup-rate=1000,1s cut the flood...
    assert "THROTTLE_START" in [t.get("type") for t in throttles]  # ...and said so


# --- OpenClaw at rest ---------------------------------------------------------------------

AT_REST_SECONDS = 200  # longer than the image's HEALTHCHECK interval (3 min)


def _brief(event: Event) -> list[object]:
    return [
        event.data.get("time", "")[11:19],
        event.process.get("binary"),
        event.process.get("in_init_tree", False),
        event.arguments[:80],
    ]


def test_openclaw_at_rest(sensor: Sensor, running_agent: RunningAgent) -> None:
    """What the real agent does at rest, seen by the sensor (docs/23, T07-1)."""
    agent_id = docker("inspect", "--format", "{{.Id}}", running_agent.name).stdout.strip()
    sensor.poll()
    startup = [e for e in sensor.events if e.of(agent_id)]
    start = len(sensor.events)
    time.sleep(AT_REST_SECONDS)
    sensor.settle(3)
    window = [e for e in sensor.events[start:] if e.of(agent_id)]
    execs = [e for e in window if e.kind == "process_exec"]
    conns = connects(window)
    loopback = [c for c in conns if c.sockaddr().get("addr", "").startswith(("127.", "::1"))]
    report(
        "openclaw_at_rest",
        {
            "seconds": AT_REST_SECONDS,
            "docker": startup[0].docker_id if startup else None,
            "startup_execs": sorted(
                {e.process.get("binary", "") for e in startup if e.kind == "process_exec"}
            ),
            "startup_exec_lines": [_brief(e) for e in startup if e.kind == "process_exec"],
            "startup_connects": [c.sockaddr() for c in connects(startup)],
            "execs": [_brief(e) for e in execs],
            "connects": len(conns),
            "loopback": len(loopback),
            "non_loopback": [c.sockaddr() for c in conns if c not in loopback],
        },
    )
    assert startup, "the agent's own start shows up, attributed to its container"
    for e in execs[:1]:
        capture("exec_openclaw_at_rest", e.raw)
    for c in loopback[:1]:
        capture("connect_openclaw_loopback", c.raw)


def test_host_connects_are_not_traced_without_a_container(sensor: Sensor) -> None:
    """Sanity check of P6 for kprobes: a connect from the test process itself (host netns,
    no container) never reaches the file."""
    port = 40000 + secrets.randbelow(20000)
    start = len(sensor.events)
    with socket.socket() as s:
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
        except OSError:
            pass
    sensor.settle(3)
    assert not [e for e in connects(sensor.events[start:]) if e.sockaddr().get("port") == port]
