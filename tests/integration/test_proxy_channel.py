"""T06-4 in the VM: the channel and the recording (docs/21, sections 5 and 9).

Done when: EVERY request of the agent is in the black box BEFORE it reaches the fake server, and
with no channel or no proxy nothing goes out. The added latency is measured here (``-rP``).

The lab: the real proxy (``ProxyJail``, backtide/gate/main.py and its addon) and backtide's real
end of the channel (``Egress``: ``open_channel`` with ``O_PATH``, ``SO_PEERCRED`` and the cgroup,
``ProxyChannel``), recording into a real black box. Both networks are ``--internal``: on the
egress one only the proxy and T06-1's fake internet (HTTPS with a test CA of its own), let
through by the tests' three concessions (``egress_neighbours``, ``test_public_addresses``,
``test_upstream_ca``); on the agent's one only the proxy and a client in the agent's role.
Nothing here can reach the internet, and every key is a fake one made here (invariant 8).
"""

import json
import os
import shutil
import statistics
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox, BlackBoxError, Event, create_key
from backtide.gate.providers import Providers
from backtide.jail import docker as jail_docker
from backtide.jail import proxy_config
from backtide.jail.proxy import ProxyJail
from backtide.service import proxy_channel
from backtide.service.egress import Egress, EgressHooks
from backtide.service.proxy_channel import ChannelError, Policy, open_channel
from tests.integration.conftest import TestEgress
from tests.integration.test_proxy_assumptions import (
    CONTAINER_PREFIX,
    FAKE_HOSTS,
    FAKE_UID,
    FIXTURES,
    INTERNET_READY,
    NETWORK_PREFIX,
    docker,
    hardened,
    internal_network,
    ip_on,
    make_ca,
    make_server_cert,
    unique,
    wait_for_line,
)

pytestmark = pytest.mark.integration

ALLOWED = "plain.fake.test"
NOT_ALLOWED = "p6.fake.test"
CLIENT_UID = 61000
LATENCY_REQUESTS = 30
# Runs in the client container: LATENCY_REQUESTS GETs through the proxy, each on a new tunnel
# (what an agent that opens a connection per call pays), and their durations in ms.
LATENCY = r"""
import json, ssl, sys, time
from http.client import HTTPSConnection
tls = ssl.create_default_context(cafile="/opt/t06/agent-ca.pem")
times = []
for n in range(int(sys.argv[1])):
    start = time.perf_counter()
    conn = HTTPSConnection("backtide-proxy", 8080, timeout=20, context=tls)
    conn.set_tunnel(sys.argv[2], 443)
    conn.request("GET", f"/latency/{n}")
    response = conn.getresponse()
    response.read()
    conn.close()
    times.append((time.perf_counter() - start) * 1000)
    assert response.status == 200, response.status
print(json.dumps(times))
"""


# Runs in the client container: on ONE tunnel, a GET and then a POST whose body is chunked
# ("chunked") or 2 MiB long ("big"), with the given Host header. Prints the two statuses.
STREAM = r"""
import json, ssl, sys
from http.client import HTTPSConnection
mode, host, path, host_header = sys.argv[1:5]
tls = ssl.create_default_context(cafile="/opt/t06/agent-ca.pem")
conn = HTTPSConnection("backtide-proxy", 8080, timeout=60, context=tls)
conn.set_tunnel(host, 443)
conn.request("GET", path + "-get")
first = conn.getresponse()
first.read()
headers = {"Host": host_header, "Content-Type": "application/octet-stream"}
if mode == "chunked":
    chunks = (b"stolen-data-" + bytes([65 + n % 26]) * 1024 for n in range(64))
    conn.request("POST", path, body=chunks, headers=headers, encode_chunked=True)
else:
    conn.request("POST", path, body=b"x" * (2 * 1024 * 1024), headers=headers)
second = conn.getresponse()
second.read()
print(json.dumps([first.status, second.status]))
"""


class GatedBox:
    """The real black box; ``hold`` makes every net append wait until it is released, and
    ``broken`` makes them fail, so the order "recorded, then out" can be watched."""

    def __init__(self, box: BlackBox) -> None:
        self.box = box
        self.hold = threading.Event()
        self.hold.set()
        self.waiting = threading.Event()
        self.broken = False
        self.only_method: str | None = None  # hold only the appends of this method
        self.append_ms: list[float] = []

    def append(self, source: str, action: str, target: str, **kwargs: Any) -> Event:
        method = (kwargs.get("details") or {}).get("method")
        if source in {"net", "llm"} and self.only_method in (None, method):
            self.waiting.set()
            assert self.hold.wait(60)
            if self.broken:
                raise BlackBoxError("the test broke the black box")
        start = time.perf_counter()
        event = self.box.append(source, action, target, **kwargs)
        if action == "request":
            self.append_ms.append((time.perf_counter() - start) * 1000)
        return event

    def events(self, action: str | None = None) -> list[Event]:
        return [e for e in self.box.events() if action in (None, e.action)]


@dataclass
class Gate:
    jail: ProxyJail
    egress: Egress
    box: GatedBox
    client: str
    fake: str
    system: list[tuple[str, dict]] = field(default_factory=list)

    def request(self, host: str, path: str, timeout: float = 60) -> dict:
        result = docker(
            "exec", self.client, "python3", "/opt/t06/client.py", "https",
            "backtide-proxy:8080", host, path, timeout=timeout, check=False,
        )  # fmt: skip
        lines = result.stdout.strip().splitlines()
        assert lines, jail_docker.sanitize(result.stderr)
        return json.loads(lines[-1])

    def fake_requests(self, path: str) -> list[dict]:
        stats = json.loads(
            docker(
                "exec", self.fake, "python3", "-c",
                "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen("
                "'http://127.0.0.1:9000/stats', timeout=10).read().decode())",
            ).stdout
        )  # fmt: skip
        return [r for r in stats["requests"] if r["path"] == path]

    def recorded(self, path: str) -> list[Event]:
        return [e for e in self.box.events() if e.details.get("path") == path]


@pytest.fixture(scope="module")
def gate(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Gate]:
    root = tmp_path_factory.mktemp("t06-4")
    root.chmod(0o755)
    egress_files = TestEgress(root / "egress")
    lab = root / "lab"
    certs, internet, t06 = lab / "certs", lab / "internet", lab / "t06"
    for folder in (lab, certs, internet, t06):
        folder.mkdir()
    internet_key, internet_cert = make_ca(certs, "T06-4 test internet CA", 2048, 30)
    shutil.copyfile(make_server_cert(certs, internet_key, internet_cert), internet / "server.pem")
    shutil.copyfile(FIXTURES / "fake_internet.py", t06 / "fake_internet.py")
    shutil.copyfile(FIXTURES / "client.py", t06 / "client.py")
    (t06 / "latency.py").write_text(LATENCY)
    (t06 / "stream.py").write_text(STREAM)
    shutil.copyfile(egress_files.agent_ca / "ca.pem", t06 / "agent-ca.pem")
    for folder in (t06, internet):
        for path in folder.iterdir():
            path.chmod(0o444)
        folder.chmod(0o555)

    agent_net = unique(NETWORK_PREFIX)
    fake, client = unique(CONTAINER_PREFIX), unique(CONTAINER_PREFIX)
    jail = egress_files.proxy(agent_net)
    containers: list[str] = []
    # On the VM's disk, not in /tmp (a tmpfs on Fedora), so each fsync costs what it costs.
    box_dir = Path(tempfile.mkdtemp(prefix="backtide-t06-4-", dir=Path.home()))
    key = create_key(box_dir / "bb.key")
    box = BlackBox(box_dir / "bb.db", key, checkpoint_path=box_dir / "bb.checkpoint").open()
    egress: Egress | None = None
    try:
        internal_network(agent_net)
        jail.ensure_network()  # the egress network (internal: a concession of the tests)
        argv = hardened(fake, FAKE_UID) + ["--network", jail.config.network]
        for host in FAKE_HOSTS:
            argv += ["--network-alias", host]
        argv += [
            "--volume", f"{t06}:/opt/t06:ro,z",
            "--volume", f"{internet}:/opt/internet:ro,z",
            "--entrypoint", "python3", proxy_config.IMAGE, "/opt/t06/fake_internet.py",
        ]  # fmt: skip
        docker(*argv)
        containers.append(fake)
        docker("start", fake)
        wait_for_line(fake, INTERNET_READY)
        docker(
            *hardened(client, CLIENT_UID), "--network", agent_net,
            "--volume", f"{t06}:/opt/t06:ro,z",
            "--entrypoint", "sleep", proxy_config.IMAGE, "infinity",
        )  # fmt: skip
        containers.append(client)
        docker("start", client)

        jail = ProxyJail(
            replace(
                jail.config,
                egress_neighbours=(fake,),
                test_public_addresses=(ip_on(fake, jail.config.network),),
                test_upstream_ca=internet_cert.read_text(),
            )
        )
        gated = GatedBox(box)
        egress = Egress(
            jail,
            agent_name=client,  # the agent's role: the only other one on its network
            policy=Policy(allow_hosts=(ALLOWED,), providers=Providers([])),
            record=gated.append,
            thread=False,
        )
        lab_gate = Gate(jail, egress, gated, client, fake)

        def record(source: str, action: str, target: str = "", **kwargs: Any) -> Event:
            lab_gate.system.append((action, kwargs.get("details") or {}))
            return box.append(source, action, target, **kwargs)

        hooks = EgressHooks(record=record, alert=lambda *a, **k: None)
        assert egress.start(hooks), (lab_gate.system, jail.log_tail())
        yield lab_gate
    finally:
        if egress is not None:
            egress.stop("test_end")
        for name in containers:
            docker("rm", "--force", name, check=False)
        jail.remove()
        jail.remove_network()
        docker("network", "rm", agent_net, check=False)
        box.close()
        shutil.rmtree(box_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def healthy(gate: Gate) -> Iterator[None]:
    """Every test starts and ends with the gate up and the black box working."""
    gate.box.hold.set()
    gate.box.broken = False
    gate.box.only_method = None
    gate.egress.check()
    assert gate.egress.up, gate.system[-3:]
    yield
    gate.box.hold.set()
    gate.box.broken = False


def ts(event: Event) -> float:
    return datetime.fromisoformat(event.ts.replace("Z", "+00:00")).timestamp()


# --- the channel's own checks ---------------------------------------------------------------


def test_the_peer_is_the_proxy_in_its_container(gate: Gate) -> None:
    channel = gate.egress._channel  # noqa: SLF001 - the one connection under test
    assert channel is not None and not channel.closed
    assert channel.hello is not None and channel.hello["version"] == "0+unknown"
    started = [d for action, d in gate.system if action == "proxy_start"]
    assert started and started[0]["reason"] == "boot"


def test_a_symlink_in_the_proxys_folder_leads_nowhere(gate: Gate, tmp_path: Path) -> None:
    """The folder is the proxy's: backtide never follows what it finds there."""
    os.symlink("/run/docker.sock", tmp_path / "events.sock")
    with pytest.raises(ChannelError):
        open_channel(tmp_path, proxy_uid=gate.jail.config.uid)


def test_the_socket_is_the_proxys_and_private(gate: Gate) -> None:
    info = (gate.jail.config.channel_dir / "events.sock").lstat()
    assert info.st_uid == gate.jail.config.uid
    assert info.st_mode & 0o777 == 0o600


# --- recorded before it goes out -----------------------------------------------------------


def test_every_request_is_in_the_black_box_before_it_reaches_the_server(gate: Gate) -> None:
    path = f"/before/{time.time_ns()}"
    gate.box.waiting.clear()
    gate.box.hold.clear()
    results: list[dict] = []
    asking = threading.Thread(target=lambda: results.append(gate.request(ALLOWED, path)))
    asking.start()
    assert gate.box.waiting.wait(30), "the proxy never asked"
    time.sleep(1.0)  # backtide is "slow": the request waits, and nothing reaches the server
    assert gate.fake_requests(path) == []
    assert gate.recorded(path) == []
    gate.box.hold.set()
    asking.join(60)
    assert results and results[0]["status"] == 200, results
    [arrived] = gate.fake_requests(path)
    [event] = [e for e in gate.recorded(path) if e.action == "request"]
    assert (event.source, event.details["host"], event.details["method"]) == ("net", ALLOWED, "GET")
    assert ts(event) < arrived["at"]  # the same kernel clock: recorded, then out
    response = [e for e in gate.box.events("response") if e.details.get("flow_id") ==
                event.details["flow_id"]]  # fmt: skip
    assert response and response[0].details["status"] == 200


def test_a_host_that_is_not_allowed_is_recorded_and_never_reached(gate: Gate) -> None:
    path = f"/denied/{time.time_ns()}"
    result = gate.request(NOT_ALLOWED, path)
    assert result["status"] == 403
    assert gate.fake_requests(path) == []
    [event] = gate.recorded(path)
    assert (event.action, event.details["reason"]) == ("blocked", "not_allowed")


def test_when_the_black_box_fails_nothing_goes_out(gate: Gate) -> None:
    path = f"/broken/{time.time_ns()}"
    gate.box.broken = True
    result = gate.request(ALLOWED, path)
    assert result["status"] == 503
    assert gate.fake_requests(path) == []


@pytest.mark.parametrize("mode", ["chunked", "big"])
def test_a_streamable_body_on_a_kept_alive_tunnel_waits_for_its_ack(gate: Gate, mode: str) -> None:
    """T06-4's review: mitmproxy streams large or chunked request bodies out BEFORE the request
    hook when ``stream_large_bodies`` is on. Here the GET is let through, and the POST that
    follows on the same tunnel must wait for backtide like any other."""
    path = f"/stream-{mode}/{time.time_ns()}"
    gate.box.only_method = "POST"
    gate.box.waiting.clear()
    gate.box.hold.clear()
    results: list[str] = []
    asking = threading.Thread(
        target=lambda: results.append(
            docker(
                "exec", gate.client, "python3", "/opt/t06/stream.py", mode, ALLOWED, path,
                ALLOWED, timeout=120, check=False,
            ).stdout
        )
    )  # fmt: skip
    asking.start()
    assert gate.box.waiting.wait(60), "the proxy never asked about the POST"
    time.sleep(1.0)
    assert gate.fake_requests(path) == []  # not a byte of the POST reached the server
    gate.box.hold.set()
    asking.join(120)
    assert results and json.loads(results[0].strip().splitlines()[-1]) == [200, 200], results
    [arrived] = gate.fake_requests(path)
    [event] = [e for e in gate.recorded(path) if e.action == "request"]
    assert ts(event) < arrived["at"]
    assert event.details["body"]["size"] > 64 * 1024


def test_domain_fronting_with_a_chunked_body_is_refused(gate: Gate) -> None:
    path = f"/fronting/{time.time_ns()}"
    result = docker(
        "exec", gate.client, "python3", "/opt/t06/stream.py", "chunked", ALLOWED, path,
        NOT_ALLOWED, timeout=120, check=False,
    ).stdout  # fmt: skip
    assert json.loads(result.strip().splitlines()[-1]) == [200, 403]
    assert gate.fake_requests(path) == []
    [event] = gate.recorded(path)
    assert (event.action, event.details["reason"]) == ("blocked", "host_mismatch")


# --- no channel, no proxy: nothing goes out -------------------------------------------------


def test_with_the_channel_cut_nothing_goes_out_and_the_refusal_is_recorded_later(
    gate: Gate,
) -> None:
    path = f"/cut/{time.time_ns()}"
    channel = gate.egress._channel  # noqa: SLF001 - the cut under test
    assert channel is not None
    channel.close("test_cut")
    time.sleep(0.5)  # the proxy sees the end of the connection
    result = gate.request(ALLOWED, path)
    assert result["status"] == 503
    assert "recorded" in result["body"]
    assert gate.fake_requests(path) == []
    gate.egress.check()  # the watch: the channel was lost while the proxy runs
    assert gate.egress.up
    assert [a for a, _ in gate.system][-2:] == ["proxy_down", "proxy_up"]
    deadline = time.monotonic() + 15
    while not gate.recorded(path) and time.monotonic() < deadline:
        time.sleep(0.2)
    [event] = gate.recorded(path)
    assert (event.action, event.details["reason"]) == ("blocked", "not_recorded")
    assert gate.request(ALLOWED, f"/after-cut/{time.time_ns()}")["status"] == 200


def test_with_the_proxy_killed_nothing_goes_out_until_it_is_back(gate: Gate) -> None:
    path = f"/killed/{time.time_ns()}"
    docker("kill", gate.jail.config.name)
    result = gate.request(ALLOWED, path, timeout=90)
    assert result["ok"] is False  # no proxy: no way out at all
    assert gate.fake_requests(path) == []
    gate.egress.check()
    actions = [a for a, _ in gate.system]
    assert "proxy_down" in actions and actions[-3:] == ["proxy_restart", "proxy_start", "proxy_up"]
    down = [d for a, d in gate.system if a == "proxy_down"][-1]
    assert down["problem"] == "not_running"
    assert gate.request(ALLOWED, f"/after-kill/{time.time_ns()}")["status"] == 200


# --- the cost ---------------------------------------------------------------------------------


def test_the_added_latency_is_measured(
    gate: Gate, record_property: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    verdict_ms: list[float] = []
    original = proxy_channel.ProxyChannel._verdict

    def timed(self: proxy_channel.ProxyChannel, message: dict) -> dict:
        start = time.perf_counter()
        try:
            return original(self, message)
        finally:
            verdict_ms.append((time.perf_counter() - start) * 1000)

    monkeypatch.setattr(proxy_channel.ProxyChannel, "_verdict", timed)
    gate.box.append_ms.clear()
    result = docker(
        "exec", gate.client, "python3", "/opt/t06/latency.py", str(LATENCY_REQUESTS), ALLOWED,
        timeout=300,
    )  # fmt: skip
    total_ms = json.loads(result.stdout.strip().splitlines()[-1])

    def summary(values: list[float]) -> str:
        ordered = sorted(values)
        p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
        return f"median {statistics.median(ordered):.1f} ms, p95 {p95:.1f} ms (n={len(ordered)})"

    figures = {
        "black box append of a net/request": summary(gate.box.append_ms),
        "backtide's verdict (checks + append)": summary(verdict_ms),
        "a whole request through the proxy (new tunnel each)": summary(total_ms),
    }
    for name, value in figures.items():
        print(f"{name}: {value}")  # noqa: T201 - for docs/21, with -rP
        record_property(name, value)
    assert len(verdict_ms) >= LATENCY_REQUESTS
    assert statistics.median(verdict_ms) < 200  # milliseconds, while a model call takes seconds
