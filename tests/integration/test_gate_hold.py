"""T10-2 in the VM: the gate holds a write until the person says yes (docs/32, sections 6 and 15).

Done when: a DELETE is held and goes out exactly once, only if it is approved from the terminal
(``backtide aprobar``'s request over the control socket), and a GET goes out without asking.

The lab is test_proxy_channel.py's: the real proxy (``ProxyJail``, backtide/gate/main.py and its
addon) and backtide's real end of the channel (``Egress``, ``ProxyChannel`` and its
``HoldBook``), recording into a real black box, with T06-1's fake internet on an internal egress
network and a client in the agent's role. The gate's times are shortened (a concession of the
tests, like T06's): a held request waits WAIT s with its connection open and a hold lives LIFE s.
The approval goes through a real ``ControlServer`` and ``ask_decide``, the client of `backtide
aprobar`. Nothing here can reach the internet (invariant 8).
"""

import json
import shutil
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox, Event, create_key
from backtide.gate.providers import Providers
from backtide.jail import docker as jail_docker
from backtide.jail import proxy_config
from backtide.jail.proxy import ProxyJail
from backtide.service.control import ControlServer, ask_decide
from backtide.service.egress import Egress, EgressHooks
from backtide.service.holds import HoldOutcome, HoldTimings
from backtide.service.proxy_channel import Policy
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
CLIENT_UID = 61000
WAIT = 6.0  # seconds a held request keeps its connection (90 in production)
LIFE = 15.0  # seconds a hold lives (5 min in production)
TIMINGS = HoldTimings(life=LIFE, wait=WAIT, preapproval=60.0, remember=60.0)

# Runs in the client container: one request through the proxy, with a timeout of its own (a
# client that gives up), and what came back.
ASK = r"""
import json, ssl, sys, time
from http.client import HTTPSConnection
method, host, path, timeout, body = sys.argv[1:6]
timeout = float(timeout)
tls = ssl.create_default_context(cafile="/opt/t06/agent-ca.pem")
start = time.monotonic()
try:
    conn = HTTPSConnection("backtide-proxy", 8080, timeout=timeout, context=tls)
    conn.set_tunnel(host, 443)
    headers = {"content-type": "application/json"} if body else {}
    conn.request(method, path, body=body.encode() or None, headers=headers)
    response = conn.getresponse()
    data = response.read().decode("utf-8", "replace")
    print(json.dumps({"ok": True, "status": response.status, "body": data[:500],
                      "retry_after": response.getheader("retry-after"),
                      "elapsed": time.monotonic() - start}))
except Exception as error:
    print(json.dumps({"ok": False, "error": type(error).__name__,
                      "elapsed": time.monotonic() - start}))
"""


@dataclass
class Lab:
    jail: ProxyJail
    egress: Egress
    box: BlackBox
    client: str
    fake: str
    control: Path
    system: list[tuple[str, dict]] = field(default_factory=list)

    def ask(self, method: str, path: str, *, timeout: float = 60, body: str = "") -> dict:
        result = docker(
            "exec", self.client, "python3", "/opt/t06/ask.py", method, ALLOWED, path,
            str(timeout), body, timeout=timeout + 30, check=False,
        )  # fmt: skip
        lines = result.stdout.strip().splitlines()
        assert lines, jail_docker.sanitize(result.stderr)
        return json.loads(lines[-1])

    def ask_in_background(self, method: str, path: str, **options: Any) -> Callable[[], dict]:
        results: list[dict] = []
        thread = threading.Thread(target=lambda: results.append(self.ask(method, path, **options)))
        thread.start()

        def wait() -> dict:
            thread.join(120)
            assert results, "the client never came back"
            return results[0]

        return wait

    def arrived(self, path: str) -> list[dict]:
        stats = json.loads(
            docker(
                "exec", self.fake, "python3", "-c",
                "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen("
                "'http://127.0.0.1:9000/stats', timeout=10).read().decode())",
            ).stdout
        )  # fmt: skip
        return [r for r in stats["requests"] if r["path"] == path]

    def events(self, path: str, action: str | None = None) -> list[Event]:
        found = [e for e in self.box.events() if e.details.get("path") == path]
        return [e for e in found if action in (None, e.action)]

    def gate(self, action: str, hold_id: str) -> list[Event]:
        return [
            e
            for e in self.box.events(source="gate", action=action)
            if e.details.get("hold_id") == hold_id
        ]

    def held(self, path: str, timeout: float = 30, *, after: int = 0) -> Event:
        """The (newest) gate/held of ``path`` recorded after seq ``after``, once it is there."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = [e for e in self.events(path, "held") if e.source == "gate" and e.seq > after]
            if found:
                return found[-1]
            time.sleep(0.1)
        pytest.fail(f"{path} was never held")

    def decide(self, hold_id: str, verdict: str = "approve") -> dict:
        return ask_decide(self.control, hold_id, verdict)


class Deciding:
    """What the control socket needs of the Guardian, played by the egress itself."""

    def __init__(self, egress: Egress) -> None:
        self.egress = egress

    def decide_hold(
        self, hold_id: str, verdict: str, *, via: str, requested_by: str
    ) -> HoldOutcome:
        return self.egress.decide(hold_id, verdict, by=via, requested_by=requested_by)

    def pending_holds(self) -> list[dict]:
        return self.egress.pending()


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    root = tmp_path_factory.mktemp("t10-2")
    root.chmod(0o755)
    egress_files = TestEgress(root / "egress")
    files = root / "lab"
    certs, internet, t06 = files / "certs", files / "internet", files / "t06"
    for folder in (files, certs, internet, t06):
        folder.mkdir()
    internet_key, internet_cert = make_ca(certs, "T10-2 test internet CA", 2048, 30)
    shutil.copyfile(make_server_cert(certs, internet_key, internet_cert), internet / "server.pem")
    shutil.copyfile(FIXTURES / "fake_internet.py", t06 / "fake_internet.py")
    (t06 / "ask.py").write_text(ASK)
    shutil.copyfile(egress_files.agent_ca / "ca.pem", t06 / "agent-ca.pem")
    for folder in (t06, internet):
        for path in folder.iterdir():
            path.chmod(0o444)
        folder.chmod(0o555)

    agent_net = unique(NETWORK_PREFIX)
    fake, client = unique(CONTAINER_PREFIX), unique(CONTAINER_PREFIX)
    jail = egress_files.proxy(agent_net)
    containers: list[str] = []
    box_dir = Path(tempfile.mkdtemp(prefix="backtide-t10-2-", dir=Path.home()))
    control_dir = Path(tempfile.mkdtemp(prefix="bt"))  # a Unix socket path is ~100 bytes at most
    control_dir.chmod(0o700)
    key = create_key(box_dir / "bb.key")
    box = BlackBox(box_dir / "bb.db", key, checkpoint_path=box_dir / "bb.checkpoint").open()
    egress: Egress | None = None
    server: ControlServer | None = None
    try:
        internal_network(agent_net)
        jail.ensure_network()
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
        egress = Egress(
            jail,
            agent_name=client,
            policy=Policy(allow_hosts=(ALLOWED,), providers=Providers([])),
            record=box.append,
            thread=False,
            timings=TIMINGS,
            history=box.events,
        )
        lab = Lab(jail, egress, box, client, fake, control_dir / "control.sock")

        def record(source: str, action: str, target: str = "", **kwargs: Any) -> Event:
            lab.system.append((action, kwargs.get("details") or {}))
            return box.append(source, action, target, **kwargs)

        assert egress.start(EgressHooks(record=record, alert=lambda *a, **k: None)), (
            lab.system,
            jail.log_tail(),
        )
        server = ControlServer(Deciding(egress), lab.control)  # type: ignore[arg-type]
        server.start()
        yield lab
    finally:
        if server is not None:
            server.close()
        if egress is not None:
            egress.stop("test_end")
        for name in containers:
            docker("rm", "--force", "--volumes", name, check=False)
        jail.remove()
        jail.remove_network()
        docker("network", "rm", agent_net, check=False)
        box.close()
        shutil.rmtree(box_dir, ignore_errors=True)
        shutil.rmtree(control_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def healthy(lab: Lab) -> Iterator[None]:
    lab.egress.check()
    assert lab.egress.up, lab.system[-3:]
    yield


def ts(event: Event) -> float:
    return datetime.fromisoformat(event.ts.replace("Z", "+00:00")).timestamp()


def tag() -> str:
    return f"/t10-2/{time.time_ns()}"


# --- the criterion ----------------------------------------------------------------------------


def test_a_delete_is_held_and_goes_out_once_only_when_approved(lab: Lab) -> None:
    path = tag() + "/buckets/b1"
    done = lab.ask_in_background("DELETE", path)
    held = lab.held(path)
    assert held.risk == 3 and held.details["reason"] == "delete"
    time.sleep(1.0)
    assert lab.arrived(path) == []  # held: the server never saw it
    assert [e for e in lab.events(path) if e.source == "net"] == []
    reply = lab.decide(held.details["hold_id"])
    assert (reply["ok"], reply["outcome"]) == (True, "released"), reply
    result = done()
    assert result["ok"] and result["status"] == 200, result
    [arrived] = lab.arrived(path)
    assert arrived["method"] == "DELETE"
    [approved] = lab.gate("approved", held.details["hold_id"])
    [request] = lab.events(path, "request")
    assert approved.details["by"] == "cli" and "uid" in approved.details["requested_by"]
    assert approved.seq < request.seq and ts(request) < arrived["at"]  # recorded, then out
    assert request.details["gate"]["decision"] == "approved"
    # The yes is spent: the same DELETE again is held again, and rejected it never goes out.
    again = lab.ask_in_background("DELETE", path)
    second = lab.held(path, after=held.seq)
    assert second.details["hold_id"] != held.details["hold_id"]
    assert lab.decide(second.details["hold_id"], "reject")["outcome"] == "rejected"
    refused = again()
    assert refused["status"] == 403 and "rejected" in refused["body"], refused
    assert len(lab.arrived(path)) == 1


def test_a_get_goes_out_without_asking(lab: Lab) -> None:
    path = tag() + "/read"
    result = lab.ask("GET", path)
    assert result["status"] == 200, result
    [request] = lab.events(path, "request")
    assert request.details["gate"] == {"decision": "read"}
    assert [e for e in lab.events(path) if e.source == "gate"] == []
    assert len(lab.arrived(path)) == 1


# --- no answer, a client that leaves --------------------------------------------------------


def test_with_no_answer_it_is_pending_then_expired_and_refused(lab: Lab) -> None:
    path = tag() + "/post"
    pending = lab.ask("POST", path, body='{"send": "everything"}')
    assert pending["status"] == 429 and pending["retry_after"] == "30", pending
    assert WAIT - 1 <= pending["elapsed"] <= WAIT + 5
    assert "not in a loop" in pending["body"]
    held = lab.held(path)
    hold_id = held.details["hold_id"]
    assert held.risk == 2
    # A retry while it is open joins it (no second gate/held) and, as its 5 min end while it
    # waits, hears "expired".
    expired = lab.ask("POST", path, body='{"send": "everything"}')
    assert expired["status"] in (403, 429), expired
    deadline = time.monotonic() + LIFE + 10
    while not lab.gate("expired", hold_id) and time.monotonic() < deadline:
        time.sleep(0.5)
    [gone] = lab.gate("expired", hold_id)
    assert gone.details["why"] == "timeout" and gone.risk == 2
    assert len([e for e in lab.events(path, "held")]) == 1
    refused = lab.ask("POST", path, body='{"send": "everything"}')
    assert refused["status"] == 403, refused  # remembered: not asked again
    assert lab.decide(hold_id)["outcome"] == "unknown"  # a yes after the end does nothing
    assert lab.arrived(path) == []


def test_a_request_whose_client_left_is_not_sent_when_approved(lab: Lab) -> None:
    path = tag() + "/left"
    result = lab.ask("DELETE", path, timeout=2)  # the client gives up before the wait ends
    assert not result["ok"], result
    held = lab.held(path)
    hold_id = held.details["hold_id"]
    deadline = time.monotonic() + 10
    while lab.egress.pending() and lab.egress.pending()[0]["waiting"]:
        assert time.monotonic() < deadline, "the proxy never said the client left"
        time.sleep(0.2)
    assert lab.decide(hold_id)["outcome"] == "preapproved"
    time.sleep(2.0)
    assert lab.arrived(path) == []  # what was abandoned is never sent later
    # The yes waits for the same request, once.
    assert lab.ask("DELETE", path)["status"] == 200
    assert lab.ask("DELETE", path, timeout=2)["ok"] is False  # held again
    assert len(lab.arrived(path)) == 1
    by = [e.details["by"] for e in lab.gate("approved", hold_id)]
    assert by == ["cli", "preapproval"]


# --- something falls while it is held --------------------------------------------------------


def test_with_the_channel_cut_a_held_request_is_refused_and_expired(lab: Lab) -> None:
    path = tag() + "/cut"
    done = lab.ask_in_background("DELETE", path)
    held = lab.held(path)
    channel = lab.egress._channel  # noqa: SLF001 - the cut under test
    assert channel is not None
    channel.close("test_cut")
    result = done()
    assert result["status"] == 503, result
    [expired] = lab.gate("expired", held.details["hold_id"])
    assert expired.details["why"] == "channel_lost"
    lab.egress.check()  # reconnects
    assert lab.decide(held.details["hold_id"])["outcome"] == "unknown"
    time.sleep(1.0)
    assert lab.arrived(path) == []


def test_with_the_proxy_killed_a_held_request_never_goes_out(lab: Lab) -> None:
    path = tag() + "/killed"
    done = lab.ask_in_background("DELETE", path)
    held = lab.held(path)
    docker("kill", lab.jail.config.name)
    result = done()
    assert result.get("status") != 200, result
    deadline = time.monotonic() + 20
    while not lab.gate("expired", held.details["hold_id"]) and time.monotonic() < deadline:
        time.sleep(0.2)
    [expired] = lab.gate("expired", held.details["hold_id"])
    assert expired.details["why"] in ("channel_lost", "proxy_restart")
    lab.egress.check()  # the watch brings the proxy back
    assert lab.egress.up
    assert lab.decide(held.details["hold_id"])["outcome"] == "unknown"
    assert lab.arrived(path) == []
    assert lab.ask("GET", tag() + "/after")["status"] == 200
