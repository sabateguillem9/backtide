"""The T07 review in the VM: what the fixes rely on, with the production sensor (docs/23).

- The redaction rules of ``backtide/jail/sensor.py`` (with the forms ported from redact.py)
  strike in Tetragon's own file, not only in the second barrier.
- Tetragon's loss counters (``SensorJail.loss_counters``) are served only on the loopback of
  the sensor's own network namespace (``--network none``) and read by ``docker exec``.
- A parallel UDP connect flood makes Tetragon lose events, real execs among them, and nothing
  in its file or its logs says so: the counters do. A marked exec in the middle of the flood is
  either in the file or accounted for by the counters (``KernelLoss``).

The sensor is the production ``SensorJail`` (one per module, never two at a time: one
privileged Tetragon per VM), with ``file_perm = 644`` so this non-root pytest can read its
file; it is stopped (SIGTERM: Tetragon unloads its programs) and removed whatever happens. The
watched processes run in the throwaway target of test_sensor_assumptions.py (no network, no
capabilities); connections go to TEST-NET addresses only, from a container without a route.
Run with ``make it IT="-s tests/integration/test_sensor_review.py"`` to see the RESULT lines.
"""

import json
import os
import secrets
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

from backtide.jail.sensor import METRICS_ADDRESS, SensorJail, SensorJailConfig
from backtide.service.process_sensor import KernelLoss
from tests.integration import test_sensor_assumptions as assumptions
from tests.integration.sensor_kit import SENSOR_PREFIX, remove_sensor, remove_stale_sensors
from tests.integration.service_kit import wait_until
from tests.integration.test_sensor_assumptions import Target, report

pytestmark = pytest.mark.integration

# test_sensor_assumptions.py's fixtures: the pinned image and the throwaway target.
tetragon_image = assumptions.tetragon_image
target = assumptions.target

SERVE_TIMEOUT = 120.0
EVENT_TIMEOUT = 30.0
# Forks ``procs`` children that each connect() a UDP socket ``per`` times to TEST-NET-1/2/3
# addresses (no route: each fails at once, after the kernel's security_socket_connect).
FLOOD = r"""
import os, socket, sys
procs, per = int(sys.argv[1]), int(sys.argv[2])
kids = []
for p in range(procs):
    pid = os.fork()
    if pid == 0:
        for i in range(per):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("192.0.2.%d" % (1 + p % 200), 1024 + (i % 60000)))
            except OSError:
                pass
            s.close()
        os._exit(0)
    kids.append(pid)
for k in kids:
    os.waitpid(k, 0)
print(procs * per)
"""


class ReviewSensor:
    def __init__(self, state_dir: Path) -> None:
        name = f"{SENSOR_PREFIX}{os.getpid()}-{uuid4().hex[:12]}"
        self.config = SensorJailConfig(state_dir=state_dir, name=name, file_perm="644")
        self.jail = SensorJail(self.config)

    def start(self) -> None:
        remove_stale_sensors()
        self.jail.prepare()
        self.jail.create()
        self.jail.start()
        wait_until(self.jail.serving, SERVE_TIMEOUT, "Tetragon to serve", interval=0.5)

    def text(self) -> str:
        return "".join(
            path.read_text(errors="replace")
            for path in sorted(self.config.events_dir.glob("*.log"))
        )

    def logs(self) -> str:
        result = subprocess.run(
            ["docker", "logs", self.config.name], capture_output=True, text=True, check=False
        )
        return result.stdout + result.stderr

    def wait_for(self, needle: str, timeout: float = EVENT_TIMEOUT) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.text():
                return True
            time.sleep(0.5)
        return False

    def pid(self) -> int:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Pid}}", self.config.name],
            capture_output=True,
            text=True,
            check=True,
        )
        return int(result.stdout.strip())


@pytest.fixture(scope="module")
def sensor(
    tetragon_image: str, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[ReviewSensor]:
    review = ReviewSensor(tmp_path_factory.mktemp("review") / "sensor")
    try:
        review.start()
        marker = f"backtide-review-ready-{secrets.token_hex(6)}"
        target.exec("/bin/true", marker)
        assert review.wait_for(marker, 60), review.logs()[-2000:]
        yield review
    finally:
        remove_sensor(review.config.name)


def _fake(size: int = 18) -> str:
    """A fresh secret-looking value: letters and digits only, so no rule cuts it short."""
    return "".join(c for c in secrets.token_urlsafe(size * 2) if c.isalnum())[:size]


def test_the_ported_redaction_rules_strike_in_tetragons_own_file(
    sensor: ReviewSensor, target: Target
) -> None:
    fakes = {
        "env": _fake(),
        "secret_env": _fake(),
        "user_u": _fake(),
        "user_long": _fake(),
        "telegram": "AA" + _fake(33),
        "jwt": f"eyJ{_fake(12)}.eyJ{_fake(16)}.{_fake(20)}",
        "aiza": "AIza" + _fake(35),
        "xox": "xoxb-" + _fake(20),
        "stripe": "sk_live_" + _fake(20),
        "ghpat": "github_pat_" + _fake(30),
        "glpat": "glpat-" + _fake(24),
        "bearer_plain": _fake(24),
        "xauth": _fake(24),
        "client_secret": _fake(24),
    }
    nonce = f"backtide-review-re2-{secrets.token_hex(6)}"
    args = [
        nonce,
        f"API_KEY={fakes['env']}", f"MY_SECRET={fakes['secret_env']}",
        "-u", f"alice:{fakes['user_u']}", f"--user=bob:{fakes['user_long']}",
        f"123456789:{fakes['telegram']}", fakes["jwt"], fakes["aiza"], fakes["xox"],
        fakes["stripe"], fakes["ghpat"], fakes["glpat"],
        f"Bearer {fakes['bearer_plain']}", f"X-Auth-Token: {fakes['xauth']}",
        f"https://x.invalid/?client_secret={fakes['client_secret']}&keep=visible",
        "plain-word-kept",
    ]  # fmt: skip
    target.exec("/bin/true", *args)
    assert sensor.wait_for(nonce)
    time.sleep(2)
    text = sensor.text() + sensor.logs()
    line = next(raw for raw in sensor.text().splitlines() if nonce in raw)
    arguments = json.loads(line)["process_exec"]["process"]["arguments"]
    leaked = [name for name, value in fakes.items() if value in text]
    report("review_re2", {"arguments": arguments, "leaked": leaked})
    assert leaked == []
    assert "keep=visible" in arguments and arguments.endswith("plain-word-kept")


def test_the_t07_5_rules_strike_glued_passwords_in_tetragons_own_file(
    sensor: ReviewSensor, target: Target
) -> None:
    """T07-5: the per-tool rules (Tetragon's binary_regex), the tools inside scripts, the
    values Tetragon wraps in quotes and a glued -b, in Tetragon's own file: binary_regex is
    accepted by this Tetragon (it would not start otherwise) and applies by the binary."""
    f = {name: _fake() for name in (
        "mysql", "mariadb_1", "mariadb_2", "sshpass", "sshpass_q1", "sshpass_q2", "redis",
        "mongo", "lftp", "smb", "curl", "env_1", "env_2", "qflag_1", "qflag_2", "cookie_1",
        "cookie_2", "sh_mysql", "sh_pwd", "sh_sshpass", "sh_env", "sh_redis", "podman",
        "ldap", "zip", "sqlplus", "curl_s1", "curl_s2", "sql",
    )}  # fmt: skip
    nonce = f"backtide-review-t075-{secrets.token_hex(6)}"
    tools = "/tmp/t075"  # noqa: S108 - inside the throwaway target, not on the host
    names = ("mysql", "mariadb-dump", "sshpass", "redis-cli", "mongosh", "lftp", "smbclient",
             "curl", "env", "podman", "ldapsearch", "zip", "sqlplus")  # fmt: skip
    copies = " && ".join(f"cp /bin/true {tools}/{name}" for name in names)
    done = target.exec("sh", "-c", f"mkdir -p {tools} && {copies}")
    assert done.returncode == 0, done.stderr
    runs = [
        [f"{tools}/mysql", nonce, "-uroot", f"-p{f['mysql']}", "shop"],
        [f"{tools}/mariadb-dump", nonce, f"-p{f['mariadb_1']} {f['mariadb_2']}", "shop"],
        [f"{tools}/sshpass", nonce, "-p", f["sshpass"], "ssh", "h.invalid"],
        [f"{tools}/sshpass", nonce, "-p", f"{f['sshpass_q1']} {f['sshpass_q2']}", "ssh"],
        [f"{tools}/redis-cli", nonce, f"-a{f['redis']}", "ping"],
        [f"{tools}/mongosh", nonce, "-u", "admin", "-p", f["mongo"], "--quiet"],
        [f"{tools}/lftp", nonce, "-u", f"alice,{f['lftp']}", "sftp://h.invalid"],
        [f"{tools}/smbclient", nonce, "//h.invalid/s", "-U", f"alice%{f['smb']}"],
        [f"{tools}/curl", nonce, f"-ualice:{f['curl']}", "https://x.invalid/"],
        [f"{tools}/env", nonce, f"DB_PASSWORD={f['env_1']} {f['env_2']}", "run"],
        ["/bin/true", nonce, f"--password=pass phrase {f['qflag_1']} {f['qflag_2']}", "x"],
        ["/bin/true", nonce, f"-bsessionid={f['cookie_1']};csrftoken={f['cookie_2']}", "y"],
        ["/bin/sh", "-c", f"true {nonce}; mysql -uroot -p{f['sh_mysql']} shop 2>/dev/null; "
         f"MYSQL_PWD={f['sh_pwd']} true"],
        ["/bin/sh", "-c", f"true {nonce}; sshpass -p {f['sh_sshpass']} ssh h 2>/dev/null; "
         f"SSHPASS={f['sh_env']} true; redis-cli -a {f['sh_redis']} ping 2>/dev/null; true"],
        [f"{tools}/podman", "login", "-u", "me", "-p", f["podman"], nonce],
        [f"{tools}/ldapsearch", nonce, "-x", "-w", f["ldap"], "-b", "dc=x"],
        [f"{tools}/zip", nonce, "-P", f["zip"], "out.zip"],
        [f"{tools}/sqlplus", nonce, f"scott/{f['sqlplus']}@orcl"],
        [f"{tools}/curl", nonce, "-u", f"alice:{f['curl_s1']} {f['curl_s2']}", "x"],
        [f"{tools}/mysql", nonce, "-e", f"CREATE USER u IDENTIFIED BY '{f['sql']}'"],
        # Ordinary flags of other binaries keep their values.
        ["/bin/true", nonce, "-p2222", "mkdir -pnew", "keep-this-visible"],
    ]  # fmt: skip
    for argv in runs:
        target.exec(*argv)
    deadline = time.monotonic() + EVENT_TIMEOUT
    while time.monotonic() < deadline and sensor.text().count(nonce) < len(runs):
        time.sleep(0.5)
    time.sleep(2)
    text = sensor.text() + sensor.logs()
    lines = [json.loads(raw) for raw in sensor.text().splitlines() if nonce in raw]
    lines = [line for line in lines if "process_exec" in line]
    arguments = [line["process_exec"]["process"]["arguments"] for line in lines]
    leaked = [name for name, value in f.items() if value in text]
    report("review_t075", {"arguments": arguments, "leaked": leaked})
    assert len(lines) >= len(runs), arguments
    assert leaked == [], arguments
    assert any(a.endswith("keep-this-visible") and "-p2222" in a for a in arguments), arguments


def _listening(pid: int) -> list[str]:
    found = []
    for table in ("tcp", "tcp6"):
        for row in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
            fields = row.split()
            if fields[3] == "0A":  # TCP_LISTEN
                found.append(f"{table}:{fields[1]}")
    return found


def test_the_loss_counters_are_only_on_the_sensors_own_loopback(sensor: ReviewSensor) -> None:
    pid = sensor.pid()
    interfaces = [
        row.split(":")[0].strip()
        for row in Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:]
    ]
    host, port = METRICS_ADDRESS.split(":")
    loopback = "0100007F" if host == "127.0.0.1" else "?"
    counters = sensor.jail.loss_counters()
    report("review_metrics", {"interfaces": interfaces, "listening": _listening(pid), **counters})
    assert interfaces == ["lo"]
    assert _listening(pid) == [f"tcp:{loopback}:{int(port):04X}"]
    assert set(counters) == {"kernel", "ringbuf", "queue", "notify", "export"}
    assert all(isinstance(value, int) and value >= 0 for value in counters.values())


def test_a_connect_flood_loses_nothing_without_a_count(
    sensor: ReviewSensor, target: Target
) -> None:
    """The review's finding 2: 32 processes of UDP connect() in parallel, with a marked exec in
    the middle. Either the marker is in the file, or the counters account for the loss."""
    losses = KernelLoss(sensor.jail.loss_counters)
    losses.baseline()
    marker = f"backtide-review-flood-{secrets.token_hex(6)}"
    flood = subprocess.Popen(
        ["docker", "exec", target.name, "python3", "-c", FLOOD, "32", "20000"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(1.0)
        target.exec("/bin/true", marker)
        made = flood.communicate(timeout=600)[0].strip()
    finally:
        if flood.poll() is None:
            flood.kill()
    seen = sensor.wait_for(marker, 20)
    grew = losses.check()
    report("review_flood", {"made": made, "marker_seen": seen, "lost": grew})
    assert seen or sum(grew.values()) > 0, "an exec vanished and no counter says so"
    assert grew, "a flood of 640,000 connects in parallel overflows Tetragon in this VM"
    # Nothing in Tetragon's file or logs says it lost them: only the counters do.
    assert "lost" not in sensor.logs().lower()
