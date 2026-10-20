"""T10-2 in the VM: the gate holds a write until the person says yes (docs/32, sections 6 and 15).

Done when: a DELETE is held and goes out exactly once, only if it is approved from the terminal
(``backtide aprobar``'s request over the control socket), and a GET goes out without asking.

T10-3 (the translators): the fake internet answers for ``api.telegram.org`` too (a fake Bot API
inside the internal network). A ``sendMessage`` to the owner's chat (``Policy.trusted``) passes;
one to another chat is held with the translator's sentence, and its client gets Telegram's own
429 ("pending") and 403 ("rejected").

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
from backtide.gate.translate.base import normalize_trusted
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
TELEGRAM = "api.telegram.org"  # an alias of the fake internet, in its certificate (T10-3)
BOT = "bot123456789:" + "AAbbCCddEEffGGhhIIjjKKllMMnnOOppQ"  # made up
OWNER = "424242424"
CLIENT_UID = 61000
WAIT = 6.0  # seconds a held request keeps its connection (90 in production)
LIFE = 15.0  # seconds a hold lives (5 min in production)
TIMINGS = HoldTimings(life=LIFE, wait=WAIT, preapproval=60.0, remember=60.0)

# Runs in the client container: one request through the proxy, with a timeout of its own (a
# client that gives up), and what came back. A sixth argument adds headers (a JSON object).
ASK = r"""
import json, ssl, sys, time
from http.client import HTTPSConnection
method, host, path, timeout, body = sys.argv[1:6]
extra = json.loads(sys.argv[6]) if len(sys.argv) > 6 else {}
timeout = float(timeout)
tls = ssl.create_default_context(cafile="/opt/t06/agent-ca.pem")
start = time.monotonic()
try:
    conn = HTTPSConnection("backtide-proxy", 8080, timeout=timeout, context=tls)
    conn.set_tunnel(host, 443)
    headers = {"content-type": "application/json"} if body else {}
    headers.update(extra)
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

    def ask(
        self,
        method: str,
        path: str,
        *,
        timeout: float = 60,
        body: str = "",
        headers: dict[str, str] | None = None,
        host: str = ALLOWED,
    ) -> dict:
        result = docker(
            "exec", self.client, "python3", "/opt/t06/ask.py", method, host, path,
            str(timeout), body, json.dumps(headers or {}), timeout=timeout + 30, check=False,
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
    server_pem = make_server_cert(certs, internet_key, internet_cert, (TELEGRAM,))
    shutil.copyfile(server_pem, internet / "server.pem")
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
        for host in (*FAKE_HOSTS, TELEGRAM):
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
            policy=Policy(
                allow_hosts=(ALLOWED,),
                providers=Providers([]),
                trusted=(normalize_trusted("telegram", OWNER),),
            ),
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


# --- the security review of T10-2: twins, headers ---------------------------------------------


def connected(lab: Lab, hold_id: str) -> int:
    channel = lab.egress._channel  # noqa: SLF001 - backtide's book, the state under test
    assert channel is not None
    hold = channel._book.get(hold_id)  # noqa: SLF001
    return -1 if hold is None else hold.connected


def until(predicate: Callable[[], bool], what: str, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, what
        time.sleep(0.1)


def test_an_identical_retry_while_one_waits_does_not_take_its_place(lab: Lab) -> None:
    """M1: the twin joins the hold and hears "pending" at once; the first keeps waiting and,
    approved, goes out exactly once. backtide's book ends clean: nothing pending, no leave."""
    path = tag() + "/twin"
    first = lab.ask_in_background("DELETE", path)
    held = lab.held(path)
    hold_id = held.details["hold_id"]
    twin = lab.ask("DELETE", path)
    assert twin["status"] == 429 and twin["elapsed"] < WAIT - 1, twin
    until(lambda: connected(lab, hold_id) == 1, "the twin never said it left")
    reply = lab.decide(hold_id)
    assert (reply["ok"], reply["outcome"]) == (True, "released"), reply
    result = first()
    assert result["ok"] and result["status"] == 200, result
    assert len(lab.arrived(path)) == 1
    [request] = lab.events(path, "request")
    assert request.details["gate"]["decision"] == "approved"
    until(lambda: connected(lab, hold_id) == -1, "the yes was never spent")
    assert [p for p in lab.egress.pending() if p["path"] == path] == []
    # No leave is left over: the same DELETE again is held again.
    assert lab.ask("DELETE", path, timeout=2)["ok"] is False
    again = lab.held(path, after=held.seq)
    assert lab.decide(again.details["hold_id"], "reject")["outcome"] == "rejected"
    assert len(lab.arrived(path)) == 1


def test_a_yes_is_good_only_for_the_same_headers(lab: Lab) -> None:
    """M2: a preapproved POST does not let out the same POST with a method override."""
    path = tag() + "/override"
    body = '{"archive": "b1"}'
    assert lab.ask("POST", path, timeout=2, body=body)["ok"] is False  # held; it gives up
    held = lab.held(path)
    hold_id = held.details["hold_id"]
    until(lambda: connected(lab, hold_id) == 0, "the proxy never said the client left")
    assert lab.decide(hold_id)["outcome"] == "preapproved"
    override = {"X-HTTP-Method-Override": "DELETE"}
    other = lab.ask("POST", path, timeout=2, body=body, headers=override)
    assert other["ok"] is False, other  # another request: held, the leave is not spent
    second = lab.held(path, after=held.seq)
    assert second.details["hold_id"] != hold_id
    assert lab.arrived(path) == []
    assert lab.ask("POST", path, body=body)["status"] == 200  # the exact one, once
    [arrived] = lab.arrived(path)
    assert "x-http-method-override" not in arrived["headers"]
    assert lab.decide(second.details["hold_id"], "reject")["outcome"] == "rejected"


def test_a_get_with_a_method_override_is_held(lab: Lab) -> None:
    path = tag() + "/get-override"
    result = lab.ask("GET", path, timeout=2, headers={"X-HTTP-Method-Override": "DELETE"})
    assert result["ok"] is False, result
    held = lab.held(path)
    assert held.details["reason"] == "write"
    assert lab.decide(held.details["hold_id"], "reject")["outcome"] == "rejected"
    assert lab.arrived(path) == []


def test_a_get_that_carries_a_secret_in_a_header_is_held(lab: Lab) -> None:
    """M3: decision 1's guard on the headers. The secret is never recorded."""
    path = tag() + "/header-secret"
    secret = "AKIA" + "QWERTYUIOPASDFGH"
    result = lab.ask("GET", path, timeout=2, headers={"X-Data": secret})
    assert result["ok"] is False, result
    held = lab.held(path)
    assert (held.risk, held.details["reason"]) == (3, "header_secret")
    assert lab.decide(held.details["hold_id"], "reject")["outcome"] == "rejected"
    assert lab.arrived(path) == []
    assert secret not in json.dumps([e.details for e in lab.box.events()])
    plain = lab.ask("GET", path + "/plain", headers={"X-Data": "nothing to see"})
    assert plain["status"] == 200, plain


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


# --- the translators (T10-3) -----------------------------------------------------------------


def telegram_path(chat: str, text: str) -> str:
    return f"/{BOT}/sendMessage?chat_id={chat}&text={text}"


def recorded_with(lab: Lab, text: str, action: str) -> list[Event]:
    return [e for e in lab.box.events() if text in str(e.details.get("path", ""))
            and e.action == action]  # fmt: skip


def telegram_arrived(lab: Lab, text: str) -> list[dict]:
    stats = json.loads(
        docker(
            "exec", lab.fake, "python3", "-c",
            "import sys, urllib.request; sys.stdout.write(urllib.request.urlopen("
            "'http://127.0.0.1:9000/stats', timeout=10).read().decode())",
        ).stdout
    )  # fmt: skip
    return [r for r in stats["requests"] if text in r["path"]]


def test_a_send_to_the_owners_chat_passes_without_asking(lab: Lab) -> None:
    text = f"owner{time.time_ns()}"
    result = lab.ask("GET", telegram_path(OWNER, text), host=TELEGRAM)
    assert result["ok"] and result["status"] == 200, result
    [arrived] = telegram_arrived(lab, text)
    [request] = recorded_with(lab, text, "request")
    assert request.details["gate"] == {
        "decision": "trusted", "translator": "telegram", "operation": "sendmessage",
        "effect": "send",
    }  # fmt: skip
    assert ts(request) < arrived["at"]
    assert recorded_with(lab, text, "held") == []
    assert BOT.split(":")[1] not in json.dumps(request.details)


def test_a_send_to_another_chat_is_held_with_its_sentence_and_telegrams_429(lab: Lab) -> None:
    text = f"stranger{time.time_ns()}"
    body = json.dumps({"chat_id": 556, "text": text})
    path = f"/{BOT}/sendMessage"
    pending = lab.ask("POST", path, body=body, host=TELEGRAM)
    assert pending["ok"] and pending["status"] == 429, pending
    assert pending["retry_after"] == "30" and pending["elapsed"] >= WAIT - 1
    answer = json.loads(pending["body"])
    assert (answer["ok"], answer["error_code"]) == (False, 429)
    assert answer["parameters"] == {"retry_after": 30}
    [held] = [e for e in lab.box.events(source="gate", action="held")
              if e.details.get("reading", {}).get("first_lines") == text]  # fmt: skip
    assert (held.risk, held.details["reason"]) == (2, "send")
    assert held.details["phrase"] == f"Telegram: enviar un mensaje al chat 556: «{text}»"
    assert held.details["hold_id"] in answer["description"]
    # Nothing reached the fake Bot API at that path (a POST: its text is in the body).
    assert [r for r in telegram_arrived(lab, "/sendMessage") if r["path"] == path] == []
    # Rejected, the same message again is refused at once, in Telegram's shape too.
    assert lab.decide(held.details["hold_id"], "reject")["outcome"] == "rejected"
    refused = lab.ask("POST", path, body=body, host=TELEGRAM)
    assert refused["status"] == 403, refused
    assert json.loads(refused["body"])["error_code"] == 403
    assert refused["elapsed"] < WAIT


def test_the_same_message_written_otherwise_is_the_same_hold(lab: Lab) -> None:
    """Decision 2: the semantic fingerprint. The same message with its fields in another order
    (another JSON, the same send) joins the hold the first one opened: no second gate/held."""
    text = f"twice{time.time_ns()}"
    path = f"/{BOT}/sendMessage"
    first = lab.ask("POST", path, body=json.dumps({"chat_id": 557, "text": text}),
                    host=TELEGRAM, timeout=2)  # fmt: skip
    assert not first["ok"] or first["status"] == 429, first
    again = lab.ask("POST", path, body=json.dumps({"text": text, "chat_id": 557}, indent=1),
                    host=TELEGRAM, timeout=2)  # fmt: skip
    assert not again["ok"] or again["status"] == 429, again
    helds = [e for e in lab.box.events(source="gate", action="held")
             if e.details.get("reading", {}).get("first_lines") == text]  # fmt: skip
    assert len(helds) == 1
    assert lab.decide(helds[0].details["hold_id"], "reject")["outcome"] == "rejected"


def test_a_translated_api_by_its_ip_literal_never_reaches_it(lab: Lab) -> None:
    """Review of T10-3, L11: by its address, the fake Bot API has no translator (the translators
    are picked by name), so its requests fall into rule 6. A Bot API call carries the bot's
    token in its path, which the guard strikes: held with risk 3. And a read that the gate does
    let pass never reaches the API either: the proxy checks the server's certificate, and the
    API's names the certificate has are not its address."""
    address = ip_on(lab.fake, lab.jail.config.network)
    text = f"byip{time.time_ns()}"
    sent = lab.ask("GET", telegram_path("556", text), host=address, timeout=3)
    assert not sent["ok"] or sent["status"] != 200, sent
    [held] = [e for e in lab.box.events(source="gate", action="held")
              if text in str(e.details.get("path", ""))]  # fmt: skip
    assert (held.risk, held.details["reason"]) == (3, "url_secret")
    assert lab.decide(held.details["hold_id"], "reject")["outcome"] == "rejected"
    probe = tag() + "/by-ip"
    read = lab.ask("GET", probe, host=address)
    assert read["ok"] and read["status"] == 502, read  # the gate let it pass; TLS did not
    [request] = lab.events(probe, "request")
    assert request.details["gate"] == {"decision": "read"}
    assert lab.arrived(probe) == [] and telegram_arrived(lab, text) == []
