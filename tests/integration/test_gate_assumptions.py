"""T10-1: what the gate's hold design (docs/32) assumes, checked in the VM.

The gate keeps a held request's connection open while it waits for the owner (up to 90 s) and
then answers "pending, retry". That only works if the proxy can keep a request waiting that
long and the clients the agent really uses wait for it. Each test pins one behaviour, or records
a figure for docs/32 ("Resultados en la VM") through ``report`` (``pytest -rP``):

- Q0: what the pinned OpenClaw image ships (Node, the undici copies, and whether ``gog`` or
  ``himalaya``, its two mail skills' programs, are in it).
- Q1: mitmproxy 12.2.3 keeps a request waiting in an ``async`` request hook for 95 s and still
  answers it (no timeout of its own while a hook awaits).
- Q2: how long each client of the agent waits for headers (Node's own ``fetch`` through the
  proxy, OpenClaw's bundled undici with no timeout given, curl, Python's urllib), and that none
  of them retries a 429 by itself. Node's ``fetch`` is held for 310 s to find its real cap.
- Q3: when a client gives up mid-hold, the hook can see it (``client_conn.timestamp_end``), so a
  held request whose client is gone is never sent later.

The lab is one ``--internal`` network with an isolated gateway: nothing in it reaches the
internet, the VM or the Mac (invariant 8). The proxy answers every request itself from its hook
(429 with ``Retry-After``): no server, no DNS, no real service is ever contacted. Containers and
the network carry conftest.py's test prefixes, so a killed run's leftovers are cleaned up.
"""

import json
import os
import re
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import pytest

from backtide.jail import IMAGE
from backtide.jail import docker as jail_docker

pytestmark = pytest.mark.integration

MITMPROXY_IMAGE = (
    "mitmproxy/mitmproxy:12.2.3"
    "@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
)  # the image pinned in T06-1 (docs/21)
PROXY_UID = 61001
CLIENT_UID = 61000  # the agent's ids
PROXY_ALIAS = "backtide-proxy"
PROXY_URL = f"http://{PROXY_ALIAS}:8080"
CONTAINER_PREFIX = "backtide-test-agent-"  # conftest.TEST_CONTAINER_PREFIX
NETWORK_PREFIX = "backtide-test-net-"  # conftest.TEST_NETWORK_PREFIX
PULL_TIMEOUT = 900.0
HOLD = 95  # seconds: a little over the 90 s the founder chose
LONG_HOLD = 310  # seconds: over undici's documented 300 s headersTimeout
MARK = "T10LAB "

# The proxy's addon: every /hold/<seconds>/<tag> waits that long in the request hook and is then
# answered 429 by the proxy itself; it notes when the client went away while it waited.
HOLD_ADDON = """
import asyncio, json, time
from mitmproxy import http

def log(**fields):
    print("T10LAB " + json.dumps(fields), flush=True)

class Hold:
    def running(self):
        log(event="ready")

    def client_disconnected(self, client):
        log(event="client_disconnected", client=client.id, t=time.time())

    async def request(self, flow):
        parts = flow.request.path.split("/")
        if len(parts) < 4 or parts[1] != "hold":
            flow.response = http.Response.make(404, b"no\\n", {"content-type": "text/plain"})
            return
        seconds, tag = float(parts[2]), parts[3]
        start = time.time()
        log(event="hold_start", tag=tag, client=flow.client_conn.id, t=start)
        gone = None
        while time.time() - start < seconds:
            await asyncio.sleep(0.25)
            if gone is None and flow.client_conn.timestamp_end is not None:
                gone = round(time.time() - start, 2)
        log(event="hold_end", tag=tag, waited=round(time.time() - start, 2), client_gone_after=gone)
        flow.response = http.Response.make(
            429,
            b"backtide: waiting for the owner's approval; ask again later\\n",
            {"content-type": "text/plain", "retry-after": "30"},
        )

addons = [Hold()]
"""

NODE_FETCH = """
const url = process.argv[2];
const start = Date.now();
fetch(url).then(async (r) => {
  await r.text();
  console.log(JSON.stringify({ok: true, status: r.status, retry_after: r.headers.get("retry-after"),
    elapsed: (Date.now() - start) / 1000}));
}).catch((e) => {
  console.log(JSON.stringify({ok: false, name: e.name, code: e.cause && e.cause.code,
    message: String(e.cause || e).slice(0, 200), elapsed: (Date.now() - start) / 1000}));
});
"""

# OpenClaw's own undici, the way its Slack writes use it: EnvHttpProxyAgent with no timeout.
NODE_UNDICI = """
const path = process.argv[3];
const url = process.argv[2];
const undici = require(path);
const agent = new undici.EnvHttpProxyAgent();
const start = Date.now();
undici.request(url, {dispatcher: agent}).then(async (r) => {
  await r.body.text();
  console.log(JSON.stringify({ok: true, status: r.statusCode, elapsed: (Date.now() - start) / 1000,
    version: require(path + "/package.json").version}));
}).catch((e) => {
  console.log(JSON.stringify({ok: false, name: e.name, code: e.code,
    message: String(e).slice(0, 200), elapsed: (Date.now() - start) / 1000}));
});
"""

PYTHON_URLLIB = """
import json, sys, time, urllib.error, urllib.request
start = time.time()
try:
    urllib.request.urlopen(sys.argv[1])
    print(json.dumps({"ok": True, "status": 200, "elapsed": time.time() - start}))
except urllib.error.HTTPError as error:
    print(json.dumps({"ok": True, "status": error.code, "elapsed": time.time() - start}))
except Exception as error:
    print(json.dumps({"ok": False, "name": type(error).__name__, "elapsed": time.time() - start}))
"""

CURL_FORMAT = '{"ok": true, "status": %{http_code}, "elapsed": %{time_total}}'


def report(record_property: Callable[[str, object], None], name: str, outcome: object) -> None:
    """Shown with ``pytest -rP``, and kept in the JUnit XML, for docs/32."""
    print(f"{name}: {outcome}")  # noqa: T201
    record_property(name, str(outcome))


def unique(prefix: str) -> str:
    return f"{prefix}{os.getpid()}-{uuid4().hex[:12]}"


def docker(*args: str, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    return jail_docker.run(list(args), timeout=timeout, check=check)


def require(image: str) -> None:
    if docker("image", "inspect", image, check=False).returncode != 0:
        docker("pull", "--quiet", image, timeout=PULL_TIMEOUT)


def hardened(name: str, uid: int, network: str) -> list[str]:
    return [
        "--name", name,
        "--user", f"{uid}:{uid}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true",
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",  # noqa: S108 - in the container
        "--memory", "512m",
        "--pids-limit", "64",
        "--env", "HOME=/tmp",
        "--network", network,
    ]  # fmt: skip


@dataclass
class Lab:
    network: str
    proxy: str
    scripts: Path
    containers: list[str] = field(default_factory=list)

    def proxy_log(self) -> list[dict]:
        out = docker("logs", self.proxy, check=False)
        return [
            json.loads(line[len(MARK) :])
            for line in (out.stdout + out.stderr).splitlines()
            if line.startswith(MARK)
        ]

    def client(self, *command: str, timeout: float) -> dict:
        """Run ``command`` in a throwaway container of the OpenClaw image, as the agent, with
        the proxy variables of the jail (docs/21, section 2). Its last line is JSON."""
        name = unique(CONTAINER_PREFIX)
        self.containers.append(name)
        argv = ["run", "--rm", *hardened(name, CLIENT_UID, self.network)]
        for item in (
            f"HTTP_PROXY={PROXY_URL}",
            f"http_proxy={PROXY_URL}",
            "NO_PROXY=localhost,127.0.0.1,::1",
            "no_proxy=localhost,127.0.0.1,::1",
            "NODE_USE_ENV_PROXY=1",
        ):
            argv += ["--env", item]
        argv += ["--volume", f"{self.scripts}:/lab:ro,z", "--entrypoint", command[0], IMAGE]
        argv += list(command[1:])
        result = docker(*argv, timeout=timeout, check=False)
        lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
        assert lines, f"no result from {command[0]}: {jail_docker.sanitize(result.stderr)[-800:]}"
        return json.loads(lines[-1])


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    require(MITMPROXY_IMAGE)
    require(IMAGE)
    scripts = tmp_path_factory.mktemp("t10-lab")
    scripts.chmod(0o755)
    for name, text in (
        ("hold_addon.py", HOLD_ADDON),
        ("fetch.js", NODE_FETCH),
        ("undici.js", NODE_UNDICI),
        ("urllib_get.py", PYTHON_URLLIB),
    ):
        (scripts / name).write_text(text)
        (scripts / name).chmod(0o444)
    network = unique(NETWORK_PREFIX)
    docker(
        "network", "create", "--driver", "bridge", "--internal",
        "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "--opt", "com.docker.network.bridge.gateway_mode_ipv6=isolated",
        network,
    )  # fmt: skip
    proxy = unique(CONTAINER_PREFIX)
    lab_ = Lab(network=network, proxy=proxy, scripts=scripts, containers=[proxy])
    try:
        argv = ["create", *hardened(proxy, PROXY_UID, network)]
        argv[argv.index("--network") + 1] = f"name={network},alias={PROXY_ALIAS}"
        argv += ["--env", "PYTHONUNBUFFERED=1", "--volume", f"{scripts}:/lab:ro,z"]
        argv += ["--entrypoint", "mitmdump", MITMPROXY_IMAGE]
        argv += [
            "--listen-port", "8080",
            "--set", "confdir=/tmp/mitm",
            "--set", "connection_strategy=lazy",
            "--set", "termlog_verbosity=warn",
            "-s", "/lab/hold_addon.py",
        ]  # fmt: skip
        docker(*argv)
        docker("start", proxy)
        deadline = time.monotonic() + 60
        while not any(e["event"] == "ready" for e in lab_.proxy_log()):
            assert time.monotonic() < deadline, "the lab proxy did not start"
            time.sleep(0.5)
        yield lab_
    finally:
        for name in lab_.containers:
            docker("rm", "--force", "--volumes", name, check=False)
        docker("network", "rm", network, check=False)


def test_q0_what_the_openclaw_image_ships(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    probe = (
        "import json, os, shutil, subprocess\n"
        "found = []\n"
        "for top in ('/app', '/usr/local/lib/node_modules'):\n"
        "    for root, dirs, files in os.walk(top):\n"
        "        if root.endswith('/node_modules/undici') and 'package.json' in files:\n"
        "            found.append([root, json.load(open(root + '/package.json'))['version']])\n"
        "            dirs[:] = []\n"
        "        if root.count('/') > 9:\n"
        "            dirs[:] = []\n"
        "node = subprocess.run(['node', '--version'], capture_output=True, text=True).stdout\n"
        "print(json.dumps({'node': node.strip(), 'gog': shutil.which('gog'),\n"
        "    'himalaya': shutil.which('himalaya'), 'curl': shutil.which('curl'),\n"
        "    'undici': sorted(found)[:12]}))\n"
    )
    seen = lab.client("python3", "-c", probe, timeout=180)
    report(record_property, "q0_image", seen)
    assert seen["node"].startswith("v24."), seen
    assert seen["gog"] is None and seen["himalaya"] is None, "a mail CLI is in the image"
    assert seen["undici"], "OpenClaw's undici was not found"


def test_q1_q2_clients_wait_for_a_long_hold_and_never_retry_a_429(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    undici_paths = lab.client(
        "sh",
        "-c",
        # OpenClaw's own undici (pnpm layout), not npm's older copy.
        "d=$(find /app/node_modules/.pnpm -maxdepth 3 -type d "
        "-path '*/undici@8*/node_modules/undici' | sort | head -n 1); "
        'printf \'{"path": "%s"}\\n\' "$d"',
        timeout=120,
    )
    undici_path = undici_paths["path"]
    base = "http://hold.fake.test/hold"
    runs = {
        "node_fetch": ("node", "/lab/fetch.js", f"{base}/{HOLD}/node_fetch"),
        "node_fetch_long": ("node", "/lab/fetch.js", f"{base}/{LONG_HOLD}/node_fetch_long"),
        "openclaw_undici": ("node", "/lab/undici.js", f"{base}/{HOLD}/undici", undici_path),
        "curl": ("curl", "-sS", "-o", "/dev/null", "-w", CURL_FORMAT, f"{base}/{HOLD}/curl"),
        "python_urllib": ("python3", "/lab/urllib_get.py", f"{base}/{HOLD}/python"),
    }
    results: dict[str, dict] = {}

    def run(key: str, command: tuple[str, ...]) -> None:
        try:
            results[key] = lab.client(*command, timeout=LONG_HOLD + 120)
        except Exception as error:  # reported below and asserted on, never silenced
            results[key] = {"ok": False, "error": type(error).__name__, "detail": str(error)[:300]}

    threads = [threading.Thread(target=run, args=item) for item in runs.items()]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(LONG_HOLD + 180)
    for key, value in results.items():
        report(record_property, f"q2_{key}", value)
    holds = [e for e in lab.proxy_log() if e["event"] == "hold_start"]
    per_tag = {tag: sum(1 for e in holds if e["tag"] == tag) for tag in {e["tag"] for e in holds}}
    report(record_property, "q2_requests_seen_per_client", per_tag)
    ends = {e["tag"]: e for e in lab.proxy_log() if e["event"] == "hold_end"}
    report(record_property, "q1_hold_ends", ends)
    # Q1: the proxy answered after the whole hold, every time.
    for tag in ("node_fetch", "undici", "curl", "python"):
        assert ends[tag]["waited"] >= HOLD, ends[tag]
        assert ends[tag]["client_gone_after"] is None, ends[tag]
    # Q2: every client waited for it and got the 429, once (no retry of its own).
    for key in ("node_fetch", "openclaw_undici", "curl", "python_urllib"):
        assert results[key].get("status") == 429, results[key]
        assert results[key]["elapsed"] >= HOLD, results[key]
    assert all(count == 1 for count in per_tag.values()), per_tag
    # Node's own fetch gives up on headers at undici's default 300 s (headersTimeout).
    long = results["node_fetch_long"]
    assert long.get("code") == "UND_ERR_HEADERS_TIMEOUT", long
    assert 295 <= long["elapsed"] < LONG_HOLD, long


def test_q3_the_hook_sees_a_client_that_gave_up(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    seen = lab.client(
        "sh",
        "-c",
        "start=$(date +%s); curl -sS --max-time 5 -o /dev/null http://gone.fake.test/hold/20/gone;"
        ' printf \'{"curl_exit": %s, "elapsed": %s}\\n\' "$?" "$(( $(date +%s) - start ))"',
        timeout=120,
    )
    report(record_property, "q3_client", seen)
    deadline = time.monotonic() + 40
    end = None
    while end is None and time.monotonic() < deadline:
        end = next((e for e in lab.proxy_log() if e.get("tag") == "gone" and "waited" in e), None)
        time.sleep(0.5)
    report(record_property, "q3_hold_end", end)
    assert end is not None, "the hold never ended"
    assert end["client_gone_after"] is not None, "the hook never saw the client leave"
    assert end["client_gone_after"] < 10, end
    disconnects = [e for e in lab.proxy_log() if e["event"] == "client_disconnected"]
    assert disconnects, "client_disconnected never fired"
    assert re.fullmatch(r"\d+", str(seen["curl_exit"])), seen
