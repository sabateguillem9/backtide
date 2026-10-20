"""backtide's end of the channel to the proxy (backtide/service/proxy_channel.py).

The proxy is played by hand over a ``socketpair``, and the black box is a real one: so "the ack
comes after the event is on disk" is checked by reading the box when the ack arrives. Who is at
the other end (``SO_PEERCRED`` and the cgroup) is checked with fake readers here; ``open_channel``
(``O_PATH``, Linux only) and the real peer run in the VM (tests/integration/test_proxy_channel.py).
"""

import json
import logging
import os
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox, BlackBoxError, Event
from backtide.gate import protocol, record
from backtide.gate.protocol import MAX_LINE_BYTES, Sender
from backtide.gate.providers import FAKE_KEY_PREFIX, Kind, Provider, Providers, Secret
from backtide.service import proxy_channel
from backtide.service.proxy_channel import (
    Budgets,
    ChannelError,
    Peer,
    Policy,
    ProxyChannel,
    check_peer,
    in_container,
    open_channel,
)

KEY = b"k" * 32
REAL = "sk-ant-api03-TEST" + "Ch4nn3lR3alK3y" * 4
FAKE = FAKE_KEY_PREFIX + "anthropic-" + "C1h2a3n4n5e6l7A8b9C0d1E2f3G4h5I6"
GATEWAY = "GaTeWaY-" + "t0k3nV4lu3" * 4
CONTAINER = "ab" * 32
PROXY_UID = 61001


def providers() -> Providers:
    return Providers(
        [Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL))]
    )


def policy(**changes: Any) -> Policy:
    """The strict mode (T06's allowed list), which most of these tests are about; the default
    since T10-3 is ``unknown_hosts = "hold"``."""
    options = {"allow_hosts": ("example.com", "*.allowed.test"), "providers": providers(),
               "secrets": (GATEWAY,), "unknown_hosts": "deny"} | changes  # fmt: skip
    return Policy(**options)


def facts(fp: str = "e" * 64, **changes: Any) -> dict[str, Any]:
    """The gate facts of a plain GET (T10-2)."""
    base = {"fp": fp, "url_struck": False, "url_bytes": 30, "websocket": False,
            "exact_read": True, "headers_struck": False, "header_bytes": 60}  # fmt: skip
    return protocol.gate(**(base | changes))


def request_event(host: str = "example.com", port: int = 443, **details: Any) -> dict[str, Any]:
    flow = {"flow_id": "f1", "method": "GET", "scheme": "https", "host": host, "port": port,
            "path": "/x", "headers": []} | details  # fmt: skip
    return record.request_event(flow, ())


class Proxy:
    """The proxy's end, by hand."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.sock.settimeout(5)
        self.buffer = b""

    def send(self, message: dict[str, Any]) -> None:
        self.sock.sendall(protocol.encode(message, Sender.PROXY))

    def raw(self, data: bytes) -> None:
        self.sock.sendall(data)

    def receive(self) -> dict[str, Any]:
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buffer += chunk
        line, _, self.buffer = self.buffer.partition(b"\n")
        return json.loads(line)

    def receive_type(self, kind: str) -> dict[str, Any]:
        while True:
            message = self.receive()
            if message["type"] == kind:
                return message

    def closed(self, timeout: float = 3.0) -> bool:
        self.sock.settimeout(timeout)
        try:
            while True:
                if not self.sock.recv(65536):
                    return True
        except TimeoutError:
            return False
        except OSError:
            return True


@pytest.fixture
def box(tmp_path: Path) -> Iterator[BlackBox]:
    with BlackBox(tmp_path / "bb.db", KEY, checkpoint_path=tmp_path / "bb.checkpoint") as opened:
        yield opened


def make_channel(box: BlackBox, **options: Any) -> tuple[ProxyChannel, Proxy]:
    ours, theirs = socket.socketpair()
    channel = ProxyChannel(ours, record=box.append, policy=options.pop("policy", policy()),
                           **options)  # fmt: skip
    return channel, Proxy(theirs)


@pytest.fixture
def connected(box: BlackBox) -> Iterator[tuple[ProxyChannel, Proxy]]:
    channel, proxy = make_channel(box)
    proxy.send(protocol.hello("12.2.3-test", 4242))
    channel.handshake(timeout=2)
    channel.start()
    try:
        yield channel, proxy
    finally:
        channel.close()


# --- who is at the other end ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cgroup", "inside"),
    [
        (f"0::/system.slice/docker-{CONTAINER}.scope\n", True),
        (f"0::/docker/{CONTAINER}\n", True),
        (f"0::/system.slice/docker-{CONTAINER}.scope/init\n", True),
        (f"0::/system.slice/docker-{'cd' * 32}.scope\n", False),
        (f"0::/system.slice/docker-{CONTAINER}.scope-x\n", False),
        (f"1:name=systemd:/system.slice/docker-{CONTAINER}.scope\n0::/user.slice\n", False),
        ("0::/user.slice/user-501.slice/session-3.scope\n", False),
    ],
)
def test_the_cgroup_names_the_proxys_container(cgroup: str, inside: bool) -> None:
    assert in_container(cgroup, CONTAINER) is inside


def test_a_container_id_that_is_not_an_id_matches_nothing() -> None:
    assert not in_container("0::/docker/x\n", "x")


@pytest.mark.parametrize(
    ("peer", "cgroup", "accepted"),
    [
        (Peer(10, PROXY_UID, PROXY_UID), f"0::/system.slice/docker-{CONTAINER}.scope", True),
        (Peer(10, 0, 0), f"0::/system.slice/docker-{CONTAINER}.scope", False),  # root, not it
        (Peer(10, PROXY_UID, PROXY_UID), "0::/user.slice", False),  # its uid, outside
        (Peer(0, PROXY_UID, PROXY_UID), f"0::/docker/{CONTAINER}", False),  # no pid seen
    ],
)
def test_only_the_proxy_in_its_container_is_accepted(
    peer: Peer, cgroup: str, accepted: bool, caplog: pytest.LogCaptureFixture
) -> None:
    ours, _theirs = socket.socketpair()

    def check() -> Peer:
        return check_peer(
            ours, proxy_uid=PROXY_UID, container_id=CONTAINER,
            peer=lambda sock: peer, cgroup=lambda pid: cgroup,
        )  # fmt: skip

    if accepted:
        assert check() == peer
    else:
        with pytest.raises(ChannelError):
            check()
        assert f"pid {peer.pid}" in caplog.text


@pytest.mark.skipif(hasattr(os, "O_PATH"), reason="Linux: see the VM test")
def test_without_o_path_the_channel_is_not_opened(tmp_path: Path) -> None:
    with pytest.raises(ChannelError, match="O_PATH"):
        open_channel(tmp_path, proxy_uid=PROXY_UID)


# --- hello and config ----------------------------------------------------------------------------


def test_the_hello_is_answered_with_the_config_and_the_keys_never_reach_a_log(
    box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    channel, proxy = make_channel(box, limits={"ack_timeout_ms": 1000})
    proxy.send(protocol.hello("12.2.3-test", 4242))
    hello = channel.handshake(timeout=2)
    assert hello["version"] == "12.2.3-test"
    config = proxy.receive()
    assert config["type"] == "config"
    [provider] = config["providers"]
    assert (provider["real_key"], provider["fake_key"]) == (REAL, FAKE)
    assert "example.com" in config["allow_hosts"] and "api.anthropic.com" in config["allow_hosts"]
    assert config["limits"]["ack_timeout_ms"] == 1000
    for secret in (REAL, FAKE, GATEWAY):
        assert secret not in caplog.text
    assert REAL not in repr(policy())
    channel.close()


@pytest.mark.parametrize(
    "first",
    [protocol.encode(protocol.ping(), Sender.PROXY), b'{"type": "config"}\n', b""],
    ids=["ping", "config", "nothing"],
)
def test_without_a_hello_there_is_no_config(box: BlackBox, first: bytes) -> None:
    channel, proxy = make_channel(box)
    if first:
        proxy.raw(first)
    else:
        proxy.sock.shutdown(socket.SHUT_WR)
    with pytest.raises(ChannelError):
        channel.handshake(timeout=1)
    proxy.sock.settimeout(0.2)
    with pytest.raises((TimeoutError, ConnectionError, OSError)):
        assert proxy.receive()["type"] != "config"
    channel.close()


def test_a_silent_proxy_gets_no_config(box: BlackBox) -> None:
    channel, _proxy = make_channel(box)
    started = time.monotonic()
    with pytest.raises(ChannelError):
        channel.handshake(timeout=0.3)
    assert time.monotonic() - started < 2


# --- recorded, then allowed ----------------------------------------------------------------------


def test_an_allowed_request_is_in_the_black_box_before_its_ack(
    connected: tuple[ProxyChannel, Proxy], box: BlackBox
) -> None:
    _, proxy = connected
    proxy.send(protocol.request(1, request_event(), facts()))
    ack = proxy.receive_type("ack")
    assert (ack["id"], ack["verdict"]) == (1, "allow")
    [event] = [e for e in box.events() if e.source == "net"]
    assert (event.action, event.seq) == ("request", ack["seq"])
    assert event.details["host"] == "example.com"


def test_acks_come_back_in_the_order_of_the_requests(
    connected: tuple[ProxyChannel, Proxy], box: BlackBox
) -> None:
    _, proxy = connected
    hosts = ["example.com", "nope.example", "a.allowed.test", "api.anthropic.com"]
    for n, host in enumerate(hosts, start=1):
        proxy.send(protocol.request(n, request_event(host), facts()))
    acks = [proxy.receive_type("ack") for _ in hosts]
    assert [(a["id"], a["verdict"]) for a in acks] == [
        (1, "allow"), (2, "deny"), (3, "allow"), (4, "allow"),
    ]  # fmt: skip
    seqs = [a["seq"] for a in acks]
    assert seqs == sorted(seqs)


@pytest.mark.parametrize(
    ("host", "port"),
    [("nope.example", 443), ("example.com", 22), ("allowed.test", 443), ("10.0.0.1", 443)],
)
def test_what_is_not_allowed_is_recorded_as_blocked_and_denied(
    connected: tuple[ProxyChannel, Proxy], box: BlackBox, host: str, port: int
) -> None:
    _, proxy = connected
    proxy.send(protocol.request(5, request_event(host, port), facts()))
    ack = proxy.receive_type("ack")
    assert (ack["verdict"], ack["reason"]) == ("deny", "not_allowed")
    stored = [e for e in box.events() if e.source == "net"]
    assert [(e.action, e.details["reason"], e.risk, e.seq) for e in stored] == [
        ("blocked", "not_allowed", 1, ack["seq"])
    ]


def test_if_the_black_box_refuses_nothing_is_allowed(box: BlackBox) -> None:
    def broken(*args: Any, **kwargs: Any) -> Event:
        raise BlackBoxError("disk full")

    ours, theirs = socket.socketpair()
    channel = ProxyChannel(ours, record=broken, policy=policy())
    proxy = Proxy(theirs)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    channel.start()
    try:
        proxy.send(protocol.request(1, request_event(), facts()))
        proxy.send(protocol.request(2, request_event("nope.example"), facts()))
        acks = [proxy.receive_type("ack") for _ in range(2)]
        assert [(a["verdict"], a["reason"], a["seq"]) for a in acks] == [
            ("deny", "not_recorded", None), ("deny", "not_recorded", None),
        ]  # fmt: skip
    finally:
        channel.close()


# --- untrusted data ------------------------------------------------------------------------------


def test_backtide_strikes_its_own_secrets_again_also_in_lower_case_and_cut(
    connected: tuple[ProxyChannel, Proxy], box: BlackBox
) -> None:
    _, proxy = connected
    # A proxy that knew nothing of the Gateway token (it never does) let it through, lowered.
    sneaky = request_event(path=f"/x?note={GATEWAY.lower()}")
    sneaky["details"]["headers"] = {GATEWAY.lower(): None}
    proxy.send(protocol.request(1, sneaky, facts()))
    cut = request_event()
    cut["target"] = "https://example.com/" + REAL[:30]  # a cut that left the start of a key
    proxy.send(protocol.request(2, cut, facts()))
    proxy.send(protocol.event(record.dropped_event(1) | {"target": FAKE}))
    [proxy.receive_type("ack") for _ in range(2)]
    time.sleep(0.2)
    text = json.dumps([[e.target, e.details] for e in box.events()])
    for secret in (GATEWAY, GATEWAY.lower(), REAL[:30], FAKE):
        assert secret not in text


@pytest.mark.parametrize(
    "line",
    [
        b'{"type": "event", "event": {"source": "system", "action": "service_stop", '
        b'"target": "", "risk": 0, "details": {}}}\n',
        b'{"type": "event", "event": {"source": "file", "action": "delete", "target": "x", '
        b'"risk": 0, "details": {}}}\n',
        b'{"type": "hello", "version": "again", "pid": 3}\n',
        b'{"type": "config", "allow_hosts": [], "providers": [], "limits": {}}\n',
        b"not json\n",
        b"{" + b" " * MAX_LINE_BYTES + b"}\n",
    ],
    ids=["system", "file", "second-hello", "config", "garbage", "too-long"],
)
def test_a_message_the_proxy_may_not_send_closes_the_channel_and_writes_nothing(
    connected: tuple[ProxyChannel, Proxy], box: BlackBox, line: bytes
) -> None:
    channel, proxy = connected
    before = len(box.events())
    proxy.raw(line)
    assert proxy.closed()
    assert channel.closed and channel.close_reason == "protocol"
    assert [e.source for e in box.events()[before:]] == []


def test_the_proxy_cannot_choose_the_risk(connected: tuple[ProxyChannel, Proxy]) -> None:
    channel, proxy = connected
    event = request_event()
    event["risk"] = 3
    proxy.raw(json.dumps({"type": "request", "id": 1, "event": event}).encode() + b"\n")
    assert proxy.closed() and channel.close_reason == "protocol"


def test_events_are_recorded(connected: tuple[ProxyChannel, Proxy], box: BlackBox) -> None:
    _, proxy = connected
    proxy.send(protocol.event(record.blocked_event("real_key", {"host": "x.example"}, ())))
    proxy.send(protocol.ping())
    assert proxy.receive_type("pong")["type"] == "pong"
    [event] = [e for e in box.events() if e.source == "net"]
    assert (event.action, event.risk, event.details["reason"]) == ("blocked", 3, "real_key")


# --- budgets -------------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_over_the_burst_requests_are_throttled_and_counted(
    box: BlackBox,
) -> None:
    clock = Clock()
    budgets = Budgets(clock(), rate=1.0, burst=2)
    channel, proxy = make_channel(box, budgets=budgets, monotonic=clock)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    verdicts = []
    for n in range(1, 5):
        channel.handle({"type": "request", "id": n, "event": request_event()})
        verdicts.append(proxy.receive_type("ack"))
    assert [v["verdict"] for v in verdicts] == ["allow", "allow", "deny", "deny"]
    assert verdicts[2]["reason"] == "throttled" and verdicts[2]["retry_after"] == 1
    requests = [e for e in box.events() if e.action == "request"]
    assert len(requests) == 2  # a throttled request is not recorded one by one...
    clock.now += 11
    channel.handle({"type": "ping"})
    # ...it is counted: the first one at once, the rest at most every 10 s.
    throttled = [e.details["count"] for e in box.events() if e.action == "throttled"]
    assert throttled == [1, 1]
    channel.close()


def test_over_the_burst_a_request_is_denied_at_once_and_never_waits(box: BlackBox) -> None:
    """The reader never sleeps: the acks of the others never wait behind a throttled one."""
    clock = Clock()
    budgets = Budgets(clock(), rate=10.0, burst=1)
    channel, proxy = make_channel(box, budgets=budgets, monotonic=clock)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    for n in (1, 2):
        channel.handle({"type": "request", "id": n, "event": request_event()})
    clock.now += 0.1  # a token is back
    channel.handle({"type": "request", "id": 3, "event": request_event()})
    verdicts = [proxy.receive_type("ack")["verdict"] for _ in range(3)]
    assert verdicts == ["allow", "deny", "allow"]
    assert clock.now == 1000.1  # nobody slept
    channel.close()


def test_a_flood_of_big_events_is_cut_by_bytes_and_by_day(box: BlackBox) -> None:
    clock = Clock()
    budgets = Budgets(clock(), event_bytes_rate=1.0, event_bytes_burst=2000, daily_events=1000)
    channel, proxy = make_channel(box, budgets=budgets, monotonic=clock)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    big = record.blocked_event(
        "port", {"host": "x.example", "port": 22, "path": "/" + "a" * 900}, ()
    )
    for _ in range(5):
        channel.handle(protocol.event(big))
    kept = [e for e in box.events() if e.action == "blocked"]
    assert 1 <= len(kept) <= 2  # about 2000 bytes' worth, then counted
    dropped = [e.details["count"] for e in box.events() if e.action == "dropped"]
    assert dropped and sum(dropped) >= 1
    channel.close()


def test_the_daily_event_budget_holds(box: BlackBox) -> None:
    clock = Clock()
    budgets = Budgets(clock(), daily_events=3)
    channel, proxy = make_channel(box, budgets=budgets, monotonic=clock)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    for _ in range(5):
        clock.now += 1
        channel.handle(protocol.event(record.blocked_event("port", {"host": "x.example"}, ())))
    assert len([e for e in box.events() if e.action == "blocked"]) == 3
    clock.now += 24 * 3600
    channel.handle(protocol.event(record.blocked_event("port", {"host": "x.example"}, ())))
    assert len([e for e in box.events() if e.action == "blocked"]) == 4  # a new day
    channel.close()


def test_the_daily_budget_refuses_and_says_so_once(
    box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    told: list[str] = []
    budgets = Budgets(clock(), daily=2)
    channel, proxy = make_channel(
        box, budgets=budgets, monotonic=clock,
        on_budget=lambda: told.append("budget"),
    )  # fmt: skip
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    for n in range(1, 6):
        channel.handle({"type": "request", "id": n, "event": request_event()})
    verdicts = [proxy.receive_type("ack")["verdict"] for _ in range(5)]
    assert verdicts == ["allow", "allow", "deny", "deny", "deny"]
    assert told == ["budget"]
    assert caplog.text.count("in a day") == 1
    channel.close()


def test_a_flood_of_events_is_dropped_and_counted(box: BlackBox) -> None:
    clock = Clock()
    budgets = Budgets(clock(), event_rate=1.0, event_burst=3)
    channel, proxy = make_channel(box, budgets=budgets, monotonic=clock)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    for _ in range(10):
        channel.handle(protocol.event(record.dropped_event(1)))
    clock.now += 11
    channel.handle({"type": "ping"})
    kept = [e.details["count"] for e in box.events() if e.action == "dropped"]
    # Three kept, then the count of the dropped: the first at once, the rest 10 s later.
    assert kept == [1, 1, 1, 1, 6]
    channel.close()


# --- liveness ------------------------------------------------------------------------------------


def test_backtide_pings_and_answers_pings(box: BlackBox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxy_channel, "PING_EVERY", 0.05)
    channel, proxy = make_channel(box)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    channel.start()
    try:
        assert proxy.receive_type("ping")["type"] == "ping"
        before = channel.last_seen
        time.sleep(0.05)
        proxy.send(protocol.ping())
        assert proxy.receive_type("pong")["type"] == "pong"
        assert channel.last_seen > before
    finally:
        channel.close()


def test_a_proxy_that_goes_away_closes_the_channel(
    connected: tuple[ProxyChannel, Proxy],
) -> None:
    channel, proxy = connected
    proxy.sock.close()
    for _ in range(100):
        if channel.closed:
            break
        time.sleep(0.02)
    assert channel.closed and channel.close_reason in {"eof", "broken"}


def test_close_ends_the_threads(box: BlackBox) -> None:
    channel, proxy = make_channel(box)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    before = threading.active_count()
    channel.start()
    channel.close()
    assert threading.active_count() <= before


def test_the_config_carries_the_allowed_provider_tools(box: BlackBox) -> None:
    allowed = Policy(allow_hosts=(), providers=providers(), provider_tools=("web_search_20250305",))
    channel, proxy = make_channel(box, policy=allowed)
    proxy.send(protocol.hello("12.2.3-test", 4242))
    channel.handshake(timeout=2)
    assert proxy.receive()["provider_tools"] == ["web_search_20250305"]
    channel.close()
    plain, proxy = make_channel(box)
    proxy.send(protocol.hello("12.2.3-test", 4242))
    plain.handshake(timeout=2)
    assert proxy.receive()["provider_tools"] == []
    plain.close()


# --- the gate (T10-2, docs/32 sections 5 to 7) ---------------------------------------------------

DELETE_FP, OTHER_FP = "d" * 64, "c" * 64


def delete_event(path: str = "/v1/buckets/b1", flow_id: str = "f1") -> dict[str, Any]:
    return request_event(path=path, method="DELETE", flow_id=flow_id)


TOKEN_ID = "c" * 64  # the credential_id the proxy sends (fingerprint.credential_id)


def write_facts(fp: str = DELETE_FP, **changes: Any) -> dict[str, Any]:
    return facts(fp, exact_read=False, **({"credential_id": TOKEN_ID} | changes))


class Gated:
    """A channel with the gate on a fake clock, its proxy by hand and the black box."""

    def __init__(self, box: BlackBox, **options: Any) -> None:
        self.clock = Clock()
        self.box = box
        self.channel, self.proxy = make_channel(box, monotonic=self.clock, **options)
        self.proxy.send(protocol.hello("t", 1))
        self.channel.handshake(timeout=2)
        self.config = self.proxy.receive_type("config")
        self.channel.start()
        self._ids = 0

    def ask(self, event: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any]:
        self._ids += 1
        self.proxy.send(protocol.request(self._ids, event, gate))
        return self.proxy.receive_type("ack")

    def gate_events(self, action: str | None = None) -> list[Event]:
        return [e for e in self.box.events(source="gate") if action in (None, e.action)]

    def requests(self) -> list[Event]:
        return [e for e in self.box.events(source="net") if e.action == "request"]

    def decide(self, hold_id: str, verdict: str = "approve") -> str:
        outcome = self.channel.decide(hold_id, verdict, by="cli", requested_by="cli (uid 1)")
        return str(outcome.status)

    def until(self, predicate: Any) -> None:
        for _ in range(200):
            if predicate():
                return
            time.sleep(0.01)
        raise AssertionError("timed out")


@pytest.fixture
def gated(box: BlackBox) -> Iterator[Gated]:
    made = Gated(box)
    try:
        yield made
    finally:
        made.channel.close()


def test_a_read_passes_recorded_with_its_rule_and_without_any_gate_event(gated: Gated) -> None:
    ack = gated.ask(request_event(), facts())
    assert ack["verdict"] == "allow"
    [event] = gated.requests()
    assert event.seq == ack["seq"] and event.details["gate"] == {"decision": "read"}
    assert gated.gate_events() == []


def test_a_delete_is_held_recorded_as_gate_held_and_not_as_a_request(gated: Gated) -> None:
    ack = gated.ask(delete_event(), write_facts())
    assert ack["verdict"] == "hold" and ack["wait_ms"] == 90_000 and ack["retry_after"] == 30
    [held] = gated.gate_events()
    assert (held.action, held.risk, held.seq) == ("held", 3, ack["seq"])
    assert held.details["hold_id"] == ack["hold_id"]
    assert held.details["fp"] == DELETE_FP[:16]  # never the whole fingerprint
    assert (held.details["reason"], held.details["method"]) == ("delete", "DELETE")
    assert held.details["host"] == "example.com" and held.details["path"] == "/v1/buckets/b1"
    assert held.details["expires_at"].endswith("Z")
    assert gated.requests() == []  # nothing went out, so no net/request


def test_a_write_is_held_with_risk_2(gated: Gated) -> None:
    gated.ask(request_event(method="POST", body=b'{"a": 1}'), write_facts(OTHER_FP))
    [held] = gated.gate_events("held")
    assert (held.risk, held.details["reason"]) == (2, "write")


def test_approved_while_connected_its_request_is_recorded_before_the_proxy_lets_it_go(
    gated: Gated,
) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    assert gated.decide(hold_id) == "released"
    decision = gated.proxy.receive_type("decision")
    [approved] = gated.gate_events("approved")
    [request] = gated.requests()
    assert approved.details | {"requested_by": "x"} == {
        "hold_id": hold_id, "fp": DELETE_FP[:16], "by": "cli", "requested_by": "x"
    }  # fmt: skip
    assert approved.details["requested_by"] == "cli (uid 1)" and approved.risk == 1
    assert decision == {"type": "decision", "hold_id": hold_id, "verdict": "allow",
                        "seq": request.seq}  # fmt: skip
    assert approved.seq < request.seq
    assert request.details["gate"] == {"decision": "approved", "hold_id": hold_id, "by": "cli"}
    gated.proxy.send(protocol.released(hold_id))
    gated.until(lambda: gated.channel.pending() == [])
    # Spent: the same request asks again (a new hold), it does not pass.
    again = gated.ask(delete_event(flow_id="f2"), write_facts())
    assert again["verdict"] == "hold" and again["hold_id"] != hold_id


def test_approved_with_nobody_waiting_the_next_identical_request_passes_once(
    gated: Gated,
) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    gated.proxy.send(protocol.hold_left(hold_id, "waited"))  # 429 "pending" to the agent
    gated.until(lambda: not gated.channel.pending()[0]["waiting"])
    assert gated.decide(hold_id) == "preapproved"
    assert gated.requests() == []  # nothing went out yet
    retry = gated.ask(delete_event(flow_id="f2"), write_facts())
    assert retry["verdict"] == "allow"
    by = [e.details["by"] for e in gated.gate_events("approved")]
    assert by == ["cli", "preapproval"]
    [request] = gated.requests()
    assert request.seq == retry["seq"]
    assert request.details["gate"] == {"decision": "preapproved", "hold_id": hold_id}
    third = gated.ask(delete_event(flow_id="f3"), write_facts())
    assert third["verdict"] == "hold"  # one use


def test_a_yes_that_crosses_a_hold_left_is_a_preapproval_not_lost_nor_spent_twice(
    gated: Gated,
) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    assert gated.decide(hold_id) == "released"
    gated.proxy.receive_type("decision")
    gated.proxy.send(protocol.hold_left(hold_id, "client_left"))  # it had just gone
    time.sleep(0.1)
    assert gated.ask(delete_event(flow_id="f2"), write_facts())["verdict"] == "allow"
    assert gated.ask(delete_event(flow_id="f3"), write_facts())["verdict"] == "hold"


def test_a_retry_joins_the_open_hold_without_a_new_event(gated: Gated) -> None:
    first = gated.ask(delete_event(), write_facts())
    gated.proxy.send(protocol.hold_left(first["hold_id"], "waited"))
    second = gated.ask(delete_event(flow_id="f2"), write_facts())
    assert (second["hold_id"], second["seq"]) == (first["hold_id"], first["seq"])
    assert len(gated.gate_events("held")) == 1
    [pending] = gated.channel.pending()
    assert pending["hold_id"] == first["hold_id"] and pending["waiting"]


def test_another_fingerprint_is_another_hold(gated: Gated) -> None:
    one = gated.ask(delete_event(), write_facts())
    two = gated.ask(delete_event(path="/v1/buckets/b2"), write_facts(OTHER_FP))
    assert one["hold_id"] != two["hold_id"] and len(gated.gate_events("held")) == 2


def test_a_rejection_is_told_and_remembered_for_10_min(gated: Gated) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    assert gated.decide(hold_id, "reject") == "rejected"
    assert gated.proxy.receive_type("decision") == {
        "type": "decision", "hold_id": hold_id, "verdict": "deny", "reason": "rejected"
    }  # fmt: skip
    [rejected] = gated.gate_events("rejected")
    assert (rejected.details["by"], rejected.risk) == ("cli", 1)
    again = gated.ask(delete_event(flow_id="f2"), write_facts())
    assert (again["verdict"], again["reason"]) == ("deny", "gate_rejected")
    [blocked] = [e for e in gated.box.events(source="net") if e.action == "blocked"]
    assert blocked.seq == again["seq"] and blocked.details["fp"] == DELETE_FP[:16]
    assert blocked.risk == 1
    gated.clock.now += 601
    assert gated.ask(delete_event(flow_id="f3"), write_facts())["verdict"] == "hold"


def test_with_no_answer_in_5_min_it_is_expired_and_refused(gated: Gated) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    gated.clock.now += 299
    gated.channel.tick()
    assert gated.gate_events("expired") == []
    gated.clock.now += 2
    gated.channel.tick()
    [expired] = gated.gate_events("expired")
    assert (expired.details["hold_id"], expired.details["why"], expired.risk) == (
        hold_id, "timeout", 2
    )  # fmt: skip
    assert gated.proxy.receive_type("decision")["reason"] == "expired"
    assert gated.decide(hold_id) == "unknown"  # a yes after the end lets nothing out
    again = gated.ask(delete_event(flow_id="f2"), write_facts())
    assert again["reason"] == "gate_rejected"


def test_a_hold_already_decided_is_unknown(gated: Gated) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    assert gated.decide("h-000000000000") == "unknown"
    assert gated.decide(hold_id, "reject") == "rejected"
    assert gated.decide(hold_id) == "unknown" and gated.decide(hold_id, "reject") == "unknown"


def test_bad_decisions_are_errors(gated: Gated) -> None:
    with pytest.raises(ValueError):
        gated.channel.decide("h-000000000000", "maybe", by="cli", requested_by="x")
    with pytest.raises(ValueError):
        gated.channel.decide("h-000000000000", "approve", by="agent", requested_by="x")


def test_past_20_open_holds_requests_are_refused_and_counted_in_a_flood(box: BlackBox) -> None:
    from backtide.service.holds import HoldTimings

    gated = Gated(box, timings=HoldTimings(max_open=2))
    try:
        gated.ask(delete_event(), write_facts("1" * 64))
        gated.ask(delete_event(), write_facts("2" * 64))
        full = gated.ask(delete_event(), write_facts("3" * 64))
        assert (full["verdict"], full["reason"], full["seq"]) == ("deny", "hold_full", None)
        gated.channel.tick()
        [flood] = gated.gate_events("flood")
        assert (flood.details["count"], flood.risk) == (1, 2)
        # A request that joins an open hold is never refused for the cap.
        assert gated.ask(delete_event(), write_facts("1" * 64))["verdict"] == "hold"
    finally:
        gated.channel.close()


@pytest.mark.parametrize(
    ("reason", "why"), [("stop", "restart"), ("restart", "proxy_restart"), ("reconnect",
                                                                             "channel_lost")]
)  # fmt: skip
def test_when_the_channel_ends_every_open_hold_is_expired(
    box: BlackBox, reason: str, why: str
) -> None:
    gated = Gated(box)
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    gated.channel.close(reason)
    [expired] = gated.gate_events("expired")
    assert (expired.details["hold_id"], expired.details["why"]) == (hold_id, why)
    gated.channel.close(reason)  # once
    assert len(gated.gate_events("expired")) == 1
    assert gated.channel.decide(hold_id, "approve", by="cli", requested_by="x").status == "unknown"


def test_a_clean_stop_ends_the_holds_before_the_proxy_goes(box: BlackBox) -> None:
    """backtide stopping: the holds end as a restart while the channel is still open (the
    proxy is stopped next, and its end must not read as a lost channel); from then on nothing
    is held or approved, and the end of the channel adds nothing."""
    gated = Gated(box)
    try:
        hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
        gated.channel.end_holds("stop")
        [expired] = gated.gate_events("expired")
        assert (expired.details["hold_id"], expired.details["why"]) == (hold_id, "restart")
        late = gated.ask(delete_event(path="/v1/buckets/b9"), write_facts(OTHER_FP))
        assert (late["verdict"], late["reason"]) == ("deny", "not_recorded")
        assert gated.channel.decide(hold_id, "approve", by="cli", requested_by="x").status == (
            "unknown"
        )
        gated.proxy.sock.close()  # the proxy goes: nothing more is recorded about the holds
        gated.until(lambda: gated.channel.closed)
        assert len(gated.gate_events("expired")) == 1 and gated.gate_events("held")[1:] == []
    finally:
        gated.channel.close("stop")


def test_a_proxy_that_goes_away_ends_its_holds(box: BlackBox) -> None:
    gated = Gated(box)
    gated.ask(delete_event(), write_facts())
    gated.proxy.sock.close()
    gated.until(lambda: gated.gate_events("expired"))
    assert gated.gate_events("expired")[0].details["why"] == "channel_lost"
    gated.channel.close()


@pytest.mark.parametrize(("by", "reason"), [("pause", "paused"), ("rewind", "rejected")])
def test_a_pause_or_a_rewind_rejects_every_open_hold(gated: Gated, by: str, reason: str) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    assert gated.channel.reject_open(by) == 1
    assert gated.proxy.receive_type("decision")["reason"] == reason
    [rejected] = gated.gate_events("rejected")
    assert (rejected.details["hold_id"], rejected.details["by"]) == (hold_id, by)
    assert gated.channel.pending() == [] and gated.channel.reject_open(by) == 0


def test_the_pending_holds_say_what_the_person_decides_on(gated: Gated) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    gated.clock.now += 60
    [pending] = gated.channel.pending()
    [held] = gated.gate_events("held")
    assert pending == {
        "hold_id": hold_id, "risk": 3, "reason": "delete", "phrase": None, "method": "DELETE",
        "host": "example.com", "path": "/v1/buckets/b1",
        "target": "https://example.com/v1/buckets/b1", "expires_in_s": 240, "waiting": True,
        # T10-5: what the web shows of it (no reading: a plain DELETE)
        "seq": held.seq, "held_at": pending["held_at"], "expires_at": held.details["expires_at"],
        "batches": [], "trustable": False, "view": None,
    }  # fmt: skip
    assert pending["held_at"].endswith("Z") and pending["held_at"] < pending["expires_at"]


def test_a_twin_does_not_change_what_is_recorded_when_the_waiting_one_goes(gated: Gated) -> None:
    """Security review of T10-2, M2: the net/request recorded on approval is the one of the
    request in the proxy's slot (the first), not the twin's that got "pending"."""
    first = gated.ask(delete_event(flow_id="f-first"), write_facts())
    twin = gated.ask(delete_event(flow_id="f-twin"), write_facts())
    assert twin["hold_id"] == first["hold_id"]
    gated.proxy.send(protocol.hold_left(first["hold_id"], "no_slot"))
    gated.until(lambda: gated.channel._book.get(first["hold_id"]).connected == 1)  # noqa: SLF001
    assert gated.decide(first["hold_id"]) == "released"
    [request] = gated.requests()
    assert request.details["flow_id"] == "f-first"


def test_approval_is_refused_while_the_agent_is_paused_or_rewound(gated: Gated) -> None:
    """Security review of T10-2, B2: a request in flight when the agent was paused is held
    after the pause; it cannot be approved until the agent runs again."""
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    outcome = gated.channel.decide(
        hold_id, "approve", by="cli", requested_by="x", frozen=lambda: True
    )
    assert str(outcome.status) == "paused" and "pausado" in outcome.message
    assert gated.gate_events("approved") == [] and gated.requests() == []
    assert [p["hold_id"] for p in gated.channel.pending()] == [hold_id]  # still held
    rejected = gated.channel.decide(
        hold_id, "reject", by="cli", requested_by="x", frozen=lambda: True
    )
    assert str(rejected.status) == "rejected"  # a no is always welcome


def test_a_pause_after_the_yes_leaves_no_preapproval_behind(gated: Gated) -> None:
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    assert gated.decide(hold_id) == "released"
    gated.proxy.receive_type("decision")
    assert gated.channel.reject_open("pause") == 0
    gated.proxy.send(protocol.hold_left(hold_id, "client_left"))  # it never went
    gated.until(lambda: gated.channel._book.get(hold_id) is None)  # noqa: SLF001
    again = gated.ask(delete_event(flow_id="f2"), write_facts())
    assert again["verdict"] == "hold" and again["hold_id"] != hold_id


@pytest.mark.parametrize(
    ("changes", "risk"),
    [
        ({"headers_struck": True}, 3),  # a read whose headers carried a secret
        ({"header_bytes": 4000}, 2),
    ],
)
def test_reads_are_guarded_by_their_headers(
    gated: Gated, changes: dict[str, Any], risk: int
) -> None:
    ack = gated.ask(request_event(), facts(**changes))
    assert ack["verdict"] == "hold"
    assert gated.gate_events("held")[0].risk == risk


def test_a_read_whose_headers_carry_a_secret_only_backtide_knows_is_held(gated: Gated) -> None:
    """The proxy never sees the Gateway token: in a header value the recording keeps (as the
    User-Agent), backtide strikes it, and holds the read."""
    event = request_event(headers=[("User-Agent", f"agent {GATEWAY}")])
    assert gated.ask(event, facts())["verdict"] == "hold"
    [held] = gated.gate_events("held")
    assert (held.risk, held.details["reason"]) == (3, "header_secret")


def test_a_read_with_an_override_header_is_held_even_if_the_proxy_said_read(
    gated: Gated,
) -> None:
    """M2 again, in backtide: the recorded header names are looked at as well."""
    event = request_event(headers=[("X-HTTP-Method-Override", "DELETE")])
    assert gated.ask(event, facts())["verdict"] == "hold"


class Failing:
    """The black box, failing for one gate action."""

    def __init__(self, box: BlackBox, action: str) -> None:
        self.box, self.action = box, action

    def __call__(self, source: str, action: str, target: str, **kwargs: Any) -> Event:
        if (source, action) == ("gate", self.action):
            raise BlackBoxError("disk full")
        return self.box.append(source, action, target, **kwargs)


def test_a_hold_that_cannot_be_recorded_is_refused_and_forgotten(box: BlackBox) -> None:
    ours, theirs = socket.socketpair()
    channel = ProxyChannel(ours, record=Failing(box, "held"), policy=policy())
    proxy = Proxy(theirs)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    channel.start()
    try:
        proxy.send(protocol.request(1, delete_event(), write_facts()))
        ack = proxy.receive_type("ack")
        assert (ack["verdict"], ack["reason"]) == ("deny", "not_recorded")
        assert channel.pending() == []
    finally:
        channel.close()


def test_an_approval_that_cannot_be_recorded_is_not_given(box: BlackBox) -> None:
    ours, theirs = socket.socketpair()
    channel = ProxyChannel(ours, record=Failing(box, "approved"), policy=policy())
    proxy = Proxy(theirs)
    proxy.send(protocol.hello("t", 1))
    channel.handshake(timeout=2)
    channel.start()
    try:
        proxy.send(protocol.request(1, delete_event(), write_facts()))
        hold_id = proxy.receive_type("ack")["hold_id"]
        outcome = channel.decide(hold_id, "approve", by="cli", requested_by="x")
        assert outcome.status == "failed" and "no se aprueba" in outcome.message
        assert [p["hold_id"] for p in channel.pending()] == [hold_id]  # still waiting
        assert [e for e in box.events() if e.action == "request"] == []
    finally:
        channel.close()


@pytest.mark.parametrize(
    ("changes", "verdict", "risk"),
    [
        ({"url_struck": True}, "hold", 3),  # a read whose URL carried a secret
        ({"url_bytes": 4000}, "hold", 2),
        ({"exact_read": False}, "hold", 2),  # `get`, not GET
        ({"websocket": True}, "allow", None),  # to the allowed list
    ],
)
def test_reads_are_guarded(gated: Gated, changes: dict[str, Any], verdict: str, risk: Any) -> None:
    ack = gated.ask(request_event(), facts(**changes))
    assert ack["verdict"] == verdict
    if risk is not None:
        assert gated.gate_events("held")[0].risk == risk


def test_a_get_with_a_body_is_held(gated: Gated) -> None:
    assert gated.ask(request_event(body=b"q=1"), facts())["verdict"] == "hold"


def test_the_strict_mode_refuses_what_is_off_the_list(gated: Gated) -> None:
    """``[gate] unknown_hosts = "deny"``: off the allowed list everything is refused, as in T06.
    Since T10-3 it is optional: the default gates unknown hosts (decision 1)."""
    assert Policy(allow_hosts=(), providers=providers()).unknown_hosts == "hold"
    for gate in (facts(), write_facts(), facts(websocket=True)):
        ack = gated.ask(request_event("nope.example"), gate)
        assert (ack["verdict"], ack["reason"]) == ("deny", "not_allowed")
    assert gated.gate_events() == []


def test_with_unknown_hosts_gated_reads_pass_and_writes_are_held(box: BlackBox) -> None:
    lenient = Policy(allow_hosts=("example.com",), providers=providers(), unknown_hosts="hold")
    gated = Gated(box, policy=lenient)
    try:
        assert gated.ask(request_event("nope.example"), facts())["verdict"] == "allow"
        assert gated.ask(request_event("nope.example", method="POST", body=b"x"),
                         write_facts())["verdict"] == "hold"  # fmt: skip
        socket_ack = gated.ask(request_event("nope.example"), facts(websocket=True))
        assert (socket_ack["verdict"], socket_ack["reason"]) == ("deny", "not_allowed")
    finally:
        gated.channel.close()
    with pytest.raises(ValueError):
        Policy(allow_hosts=(), providers=providers(), unknown_hosts="allow")


def test_the_fingerprint_key_goes_in_the_config_and_nowhere_else(
    gated: Gated, caplog: pytest.LogCaptureFixture
) -> None:
    key = gated.config["fp_key"]
    assert len(bytes.fromhex(key)) == 32
    hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
    gated.decide(hold_id)
    text = json.dumps([[e.target, e.details] for e in gated.box.events()])
    assert key not in text and key not in caplog.text
    other = Gated(gated.box)
    try:
        assert other.config["fp_key"] != key  # one per connection
    finally:
        other.channel.close()


def test_a_read_whose_url_carries_a_secret_only_backtide_knows_is_held(gated: Gated) -> None:
    """The proxy never sees the Gateway token: backtide strikes it, and holds the read."""
    for n, path in enumerate((f"/x/{GATEWAY}/end", f"/x?session={GATEWAY}")):
        ack = gated.ask(request_event(path=path), facts(fp=f"{n:064x}"))
        assert ack["verdict"] == "hold"
    assert [e.risk for e in gated.gate_events("held")] == [3, 3]
    assert GATEWAY not in json.dumps([e.details for e in gated.box.events()])


# --- the translators' readings (T10-3, docs/32 sections 5 and 9) ---------------------------------

BOT = "bot123456789:" + "AAbbCCddEEffGGhhIIjjKKllMMnnOOppQ"
OWNER = "555"


def telegram_send(
    chat: str, text: str = "hola", n: int = 1
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The event and the gate facts of ``GET api.telegram.org/bot…/sendMessage?chat_id=…``,
    read by the real translator."""
    from backtide.gate.translate import Context, RequestView, translate

    path = f"/{BOT}/sendMessage?chat_id={chat}&text={text}"
    view = RequestView(method="GET", host="api.telegram.org", port=443, path=path)
    reading = translate(view, Context(key=bytes(32)))
    assert reading is not None
    event = request_event("api.telegram.org", path=path)
    return event, facts(f"{n:064x}", reading=protocol.fit_reading(reading.summary()))


def a_reading(**fields: Any) -> dict[str, Any]:
    from backtide.gate.translate.base import Effect, Note, Reading, Shape

    base: dict[str, Any] = {"translator": "gmail", "operation": "unknown",
                            "effect": Effect.UNKNOWN, "shape": Shape.GOOGLE, "wait_s": 25,
                            "account": "0123456789abcdef"} | fields  # fmt: skip
    base["effect"] = Effect(base["effect"])
    base["notes"] = tuple(Note(note) for note in base.get("notes", ()))
    return protocol.fit_reading(Reading(**base).summary())


@pytest.fixture
def translated(box: BlackBox) -> Iterator[Gated]:
    from backtide.gate.translate.base import normalize_trusted

    made = Gated(box, policy=policy(unknown_hosts="hold",
                                    trusted=(normalize_trusted("telegram", OWNER),)))  # fmt: skip
    try:
        yield made
    finally:
        made.channel.close()


def test_a_send_to_the_owners_chat_passes_with_its_reading_noted(translated: Gated) -> None:
    event, gate = telegram_send(OWNER)
    assert translated.ask(event, gate)["verdict"] == "allow"
    [request] = translated.requests()
    assert request.details["gate"] == {"decision": "trusted", "translator": "telegram",
                                       "operation": "sendmessage", "effect": "send"}  # fmt: skip
    assert translated.gate_events() == []


def test_a_send_to_another_chat_is_held_with_its_sentence(translated: Gated) -> None:
    event, gate = telegram_send("556")
    ack = translated.ask(event, gate)
    assert ack["verdict"] == "hold" and ack["wait_ms"] == 50_000  # Telegram's client: 50 s
    [held] = translated.gate_events("held")
    assert (held.risk, held.details["reason"]) == (2, "send")
    assert held.details["phrase"] == "Telegram: enviar un mensaje al chat 556: «hola»"
    assert held.details["reading"]["recipients"] == ["556"]
    assert "account" not in held.details["reading"]  # this connection's HMAC: worthless later
    assert BOT.split(":")[1] not in json.dumps(held.details)
    [pending] = translated.channel.pending()
    assert pending["phrase"] == held.details["phrase"]


def test_a_send_to_the_owner_with_a_secret_is_held_with_risk_3(translated: Gated) -> None:
    event, gate = telegram_send(OWNER, text="AKIAIOSFODNN7EXAMPLE")
    assert gate["reading"]["secret_seen"] is True
    assert translated.ask(event, gate)["verdict"] == "hold"
    [held] = translated.gate_events("held")
    assert held.risk == 3 and "AKIAIOSFODNN7EXAMPLE" not in json.dumps(held.details)


def test_a_cut_reading_is_never_trusted(translated: Gated) -> None:
    event, gate = telegram_send(OWNER)
    gate["reading"]["cut"] = True
    assert translated.ask(event, protocol.gate(**gate))["verdict"] == "hold"


def test_a_translated_read_to_an_unknown_host_passes_and_a_secret_in_its_url_is_held(
    translated: Gated,
) -> None:
    read = a_reading(operation="get", effect="read")
    ask = translated.ask
    assert ask(request_event("gmail.googleapis.com"), facts("1" * 64, reading=read))[
        "verdict"
    ] == "allow"  # fmt: skip
    leak = facts("2" * 64, reading=read, url_struck=True)
    assert ask(request_event("gmail.googleapis.com"), leak)["verdict"] == "hold"
    [held] = translated.gate_events("held")
    assert (held.risk, held.details["reason"]) == (3, "url_secret")


def test_a_draft_change_while_its_sending_is_held_is_held(translated: Gated) -> None:
    """Decision 12: the text the person approves must not change before it goes out. (With no
    owner accounts configured every draft change is held anyway; this is the READ case.)"""
    send = a_reading(draft="r-42", target="draft r-42", notes=("content_unseen",))
    event = request_event("gmail.googleapis.com", method="POST", body=b'{"id": "r-42"}')
    assert translated.ask(event, write_facts("3" * 64, reading=send))["verdict"] == "hold"
    change = a_reading(operation="drafts.update", effect="read", draft="r-42")
    update = request_event("gmail.googleapis.com", method="PUT", body=b"{}")
    ack = translated.ask(update, write_facts("4" * 64, reading=change))
    assert ack["verdict"] == "hold"
    assert translated.gate_events("held")[-1].details["reason"] == "draft_open"
    other = a_reading(operation="drafts.update", effect="read", draft="r-43")
    assert translated.ask(update, write_facts("5" * 64, reading=other))["verdict"] == "allow"


def test_the_read_endpoints_go_to_the_proxy_in_its_config(box: BlackBox) -> None:
    made = Gated(box, policy=policy(read_endpoints=("search.fake.test/v1/query",)))
    try:
        assert made.config["read_endpoints"] == ["search.fake.test/v1/query"]
    finally:
        made.channel.close()


def test_a_read_to_a_host_named_with_a_secret_only_backtide_knows_is_held(
    translated: Gated,
) -> None:
    """The proxy never sees the Gateway token: in a host name (lower case, as DNS has it) it
    is struck by backtide, and the read is held before the name is ever resolved."""
    host = f"{GATEWAY.lower()}.exfil.example"
    ack = translated.ask(request_event(host), facts("6" * 64))
    assert ack["verdict"] == "hold"
    [held] = translated.gate_events("held")
    assert (held.risk, held.details["reason"]) == (3, "url_secret")


# --- security review of T10-3 ----------------------------------------------------------------


def test_a_credential_header_to_an_unknown_host_is_held(translated: Gated) -> None:
    """H1: any credential header toward a host off allow_hosts is held (risk 2); one whose
    value the redaction recognises, with risk 3. To a listed host it passes."""
    ack = translated.ask(request_event("nope.example"), facts("7" * 64, credential_bytes=40))
    assert ack["verdict"] == "hold"
    struck = facts("8" * 64, credential_bytes=40, credentials_struck=True)
    assert translated.ask(request_event("nope.example"), struck)["verdict"] == "hold"
    first, second = translated.gate_events("held")
    assert (first.risk, first.details["reason"]) == (2, "credential_unknown_host")
    assert (second.risk, second.details["reason"]) == (3, "credential_secret")
    listed = translated.ask(request_event("example.com"), facts("9" * 64, credential_bytes=40))
    assert listed["verdict"] == "allow"


def test_a_header_name_with_a_secret_only_backtide_knows_is_held(translated: Gated) -> None:
    """H1: the recorded header names go through backtide's guard too (the Gateway token)."""
    event = request_event("example.com", headers=[(f"x-{GATEWAY}", "1")])
    assert translated.ask(event, facts("a" * 64))["verdict"] == "hold"
    [held] = translated.gate_events("held")
    assert (held.risk, held.details["reason"]) == (3, "header_secret")


def test_reads_to_unknown_hosts_spend_a_read_budget(box: BlackBox) -> None:
    """M5: the bytes of URL and headers of the reads that pass to unknown hosts are counted,
    per host and in total, per hour; over either, the read is held (``read_budget``, risk 2).
    The listed hosts are not counted."""
    from backtide.service.read_budget import ReadBudget

    made = Gated(box, policy=policy(unknown_hosts="hold"),
                 read_budget=ReadBudget(host_bytes=200, total_bytes=300))  # fmt: skip
    try:
        one = facts("b" * 64, url_bytes=60, header_bytes=40)  # 100 bytes
        assert made.ask(request_event("a.example"), one)["verdict"] == "allow"
        assert made.ask(request_event("a.example"), facts("c" * 64, url_bytes=100, header_bytes=0))[
            "verdict"
        ] == "allow"  # fmt: skip
        over = made.ask(request_event("a.example"), facts("d" * 64, url_bytes=60, header_bytes=0))
        assert over["verdict"] == "hold"
        [held] = made.gate_events("held")
        assert (held.risk, held.details["reason"]) == (2, "read_budget")
        assert made.ask(request_event("b.example"), facts("e" * 64, url_bytes=40, header_bytes=0))[
            "verdict"
        ] == "allow"  # fmt: skip
        total = made.ask(request_event("c.example"), facts("f" * 64, url_bytes=70, header_bytes=0))
        assert total["verdict"] == "hold"  # the total: 200 + 40 + 70 > 300
        for _ in range(5):  # a listed host is never counted
            assert made.ask(request_event("example.com"), facts("0" * 64, url_bytes=150))[
                "verdict"
            ] == "allow"  # fmt: skip
    finally:
        made.channel.close()


def test_a_send_that_makes_the_platform_fetch_a_url_is_never_trusted(translated: Gated) -> None:
    """M3: a photo by URL to the owner's chat makes Telegram fetch it: held, with the URL."""
    from backtide.gate.translate import Context, RequestView, translate

    path = f"/{BOT}/sendPhoto?chat_id={OWNER}&photo=https://evil.example/x.png"
    view = RequestView(method="GET", host="api.telegram.org", port=443, path=path)
    reading = translate(view, Context(key=bytes(32)))
    assert reading is not None
    gate = facts("1" * 64, reading=protocol.fit_reading(reading.summary()))
    assert translated.ask(request_event("api.telegram.org", path=path), gate)["verdict"] == "hold"
    [held] = translated.gate_events("held")
    assert "https://evil.example/x.png" in held.details["phrase"]


def test_an_inline_message_edit_is_never_trusted(translated: Gated) -> None:
    """H2: ``inline_message_id`` wins over ``chat_id``: the edit may land in any chat."""
    from backtide.gate.translate import Context, RequestView, translate

    path = f"/{BOT}/editMessageText?chat_id={OWNER}&inline_message_id=AAA111&text=hola"
    view = RequestView(method="GET", host="api.telegram.org", port=443, path=path)
    reading = translate(view, Context(key=bytes(32)))
    assert reading is not None
    gate = facts("2" * 64, reading=protocol.fit_reading(reading.summary()))
    assert translated.ask(request_event("api.telegram.org", path=path), gate)["verdict"] == "hold"


# --- batches and the watch (T10-4, docs/32 sections 10 and 11) -----------------------------------

OTHER_BOT = "bot987654321:" + "ZZyyXXwwVVuuTTssRRqqPPooNNmmLLkkJ"


def telegram_call(
    chat: str, text: str = "hola", n: int = 1, *, bot: str = BOT, method: str = "sendMessage",
    extra: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    """Like ``telegram_send``, with another bot (another account) or another method."""
    from backtide.gate.translate import Context, RequestView, translate

    path = f"/{bot}/{method}?chat_id={chat}&text={text}{extra}"
    view = RequestView(method="GET", host="api.telegram.org", port=443, path=path)
    reading = translate(view, Context(key=bytes(32)))
    assert reading is not None
    event = request_event("api.telegram.org", path=path, flow_id=f"f{n}")
    return event, facts(f"{n:064x}", reading=protocol.fit_reading(reading.summary()))


class Watched:
    """A ``HoldWatch`` that takes note."""

    def __init__(self) -> None:
        self.held_notices: list[dict[str, Any]] = []
        self.endings: list[tuple[str, str, str | None]] = []

    def held(self, notice: Any) -> None:
        self.held_notices.append(dict(notice))

    def closed(self, hold_id: str, status: str, by: str | None) -> None:
        self.endings.append((hold_id, status, by))


@pytest.fixture
def batched(box: BlackBox) -> Iterator[tuple[Gated, Watched]]:
    from backtide.gate.translate.base import normalize_trusted

    watch = Watched()
    made = Gated(box, watch=watch, policy=policy(
        unknown_hosts="hold", trusted=(normalize_trusted("telegram", OWNER),)
    ))  # fmt: skip
    try:
        yield made, watch
    finally:
        made.channel.close()


def make_batch(gated: Gated, hold_id: str, kind: str, **options: Any) -> Any:
    return gated.channel.create_batch(
        hold_id, kind, by="telegram", requested_by="telegram (pid 1)", **options
    )


def test_the_watch_hears_of_each_hold_with_what_its_notice_shows(
    batched: tuple[Gated, Watched],
) -> None:
    gated, watch = batched
    ack = gated.ask(*telegram_call("556", "hola ana"))
    [notice] = watch.held_notices
    assert notice["hold_id"] == ack["hold_id"] and notice["risk"] == 2
    assert notice["phrase"] == "Telegram: enviar un mensaje al chat 556: «hola ana»"
    assert notice["reading"]["recipients"] == ["556"]
    assert notice["batches"] == ["recipient", "kind"]
    assert notice["seq"] == gated.gate_events("held")[0].seq
    assert notice["expires_in_s"] == 300 and BOT.split(":")[1] not in json.dumps(notice)
    gated.ask(*telegram_call("556", "hola ana", n=1))  # a retry joins: no new notice
    assert len(watch.held_notices) == 1
    deleted = gated.ask(delete_event(), write_facts())
    assert watch.held_notices[-1]["hold_id"] == deleted["hold_id"]
    assert watch.held_notices[-1]["batches"] == []  # a DELETE never makes a batch


def test_the_watch_hears_how_each_hold_ends(batched: tuple[Gated, Watched]) -> None:
    gated, watch = batched
    first = gated.ask(*telegram_call("556", n=1))["hold_id"]
    second = gated.ask(*telegram_call("557", n=2))["hold_id"]
    third = gated.ask(*telegram_call("558", n=3))["hold_id"]
    fourth = gated.ask(*telegram_call("559", n=4))["hold_id"]
    assert gated.decide(first) == "released"
    gated.proxy.send(protocol.released(first))
    gated.until(lambda: gated.channel._book.get(first) is None)  # noqa: SLF001
    gated.proxy.send(protocol.hold_left(second, "waited"))
    gated.until(lambda: gated.channel._book.get(second).connected == 0)  # noqa: SLF001
    assert gated.decide(second) == "preapproved"
    assert gated.decide(third, "reject") == "rejected"
    gated.channel.reject_open("pause")
    assert watch.endings == [
        (first, "released", "cli"), (second, "preapproved", "cli"), (third, "rejected", "cli"),
        (fourth, "rejected", "pause"),
    ]  # fmt: skip
    fifth = gated.ask(*telegram_call("560", n=5))["hold_id"]
    gated.clock.now += 301
    gated.channel.tick()
    sixth = gated.ask(*telegram_call("561", n=6))["hold_id"]
    gated.channel.close("stop")
    assert watch.endings[-2:] == [(fifth, "expired", "timeout"), (sixth, "expired", "restart")]


def test_a_watch_that_fails_never_breaks_the_gate(box: BlackBox) -> None:
    class Broken:
        def held(self, notice: Any) -> None:
            raise RuntimeError("boom")

        def closed(self, hold_id: str, status: str, by: str | None) -> None:
            raise RuntimeError("boom")

    gated = Gated(box, watch=Broken())
    try:
        hold_id = gated.ask(delete_event(), write_facts())["hold_id"]
        assert gated.decide(hold_id) == "released"
    finally:
        gated.channel.close()


def test_a_recipient_batch_approves_its_hold_and_lets_what_it_covers_pass(
    batched: tuple[Gated, Watched],
) -> None:
    gated, watch = batched
    hold_id = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
    outcome = make_batch(gated, hold_id, "recipient")
    assert str(outcome.status) == "created" and str(outcome.hold) == "released"
    assert outcome.rule_id is not None and "Sale ahora" in outcome.message
    [rule] = gated.gate_events("batch_rule")
    [approved] = gated.gate_events("approved")
    assert rule.risk == 2 and rule.seq < approved.seq
    assert rule.details["rule_id"] == outcome.rule_id and rule.details["scope"] == "recipient"
    assert rule.details["recipients"] == ["556"] and rule.details["translator"] == "telegram"
    assert rule.details["hold_id"] == hold_id and rule.details["by"] == "telegram"
    assert "account" not in rule.details and rule.details["until"]
    assert gated.proxy.receive_type("decision")["verdict"] == "allow"
    assert watch.endings == [(hold_id, "released", "telegram")]
    # Another message to the same chat from the same bot: it rides the batch.
    ack = gated.ask(*telegram_call("556", "dos", n=2))
    assert ack["verdict"] == "allow"
    request = gated.requests()[-1]
    assert request.details["gate"] == {"decision": "batch", "rule": outcome.rule_id,
                                       "translator": "telegram", "operation": "sendmessage",
                                       "effect": "send"}  # fmt: skip
    # Nothing else does: another chat, another bot, a forward, a deletion, a URL to fetch.
    for n, call in enumerate([
        telegram_call("557", "tres"),
        telegram_call("556", "cuatro", bot=OTHER_BOT),
        telegram_call("556", "x", method="forwardMessage", extra="&from_chat_id=1&message_id=2"),
        telegram_call("556", "x", method="deleteMessage", extra="&message_id=2"),
        telegram_call("556", "mira https://other.fake.test/x"),
    ], start=10):  # fmt: skip
        event, gate = call
        gate = facts(f"{n:064x}", reading=gate["reading"])
        assert gated.ask(event, gate)["verdict"] == "hold", call[0]["details"]["path"]
    [summary] = gated.channel.batches()
    assert summary["uses"] == 1 and summary["recipients"] == ["556"]
    assert summary["left_s"] == 12 * 3600


def test_a_batch_never_lets_a_request_whose_own_hold_is_open_go_twice(
    batched: tuple[Gated, Watched],
) -> None:
    gated, _ = batched
    first = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
    waiting = gated.ask(*telegram_call("556", "dos", n=2))["hold_id"]
    make_batch(gated, first, "recipient")
    again = gated.ask(*telegram_call("556", "dos", n=2))  # its retry: it joins its hold
    assert again["verdict"] == "hold" and again["hold_id"] == waiting


def test_a_kind_batch_covers_the_effect_for_an_hour_to_anyone(
    batched: tuple[Gated, Watched],
) -> None:
    gated, _ = batched
    hold_id = gated.ask(*telegram_call("556", n=1))["hold_id"]
    outcome = make_batch(gated, hold_id, "kind")
    assert str(outcome.status) == "created"
    assert gated.ask(*telegram_call("999", "otro", n=2))["verdict"] == "allow"
    gated.clock.now += 3601
    gated.channel.tick()
    [end] = gated.gate_events("batch_rule_end")
    assert end.details == {"rule_id": outcome.rule_id, "why": "expired", "uses": 1}
    assert end.risk == 0
    assert gated.ask(*telegram_call("999", "tres", n=3))["verdict"] == "hold"


def test_a_pause_a_revocation_and_the_end_of_the_channel_end_the_batches(
    batched: tuple[Gated, Watched],
) -> None:
    gated, _ = batched
    first = make_batch(gated, gated.ask(*telegram_call("556", n=1))["hold_id"], "recipient")
    second = make_batch(gated, gated.ask(*telegram_call("557", n=2))["hold_id"], "recipient")
    assert gated.channel.end_batch(first.rule_id, by="telegram") is True
    assert gated.channel.end_batch(first.rule_id, by="telegram") is False
    gated.channel.reject_open("pause")
    third = make_batch(gated, gated.ask(*telegram_call("558", n=3))["hold_id"], "recipient")
    gated.channel.close("restart")
    ends = [(e.details["rule_id"], e.details["why"]) for e in gated.gate_events("batch_rule_end")]
    assert ends == [(first.rule_id, "revoked"), (second.rule_id, "pause"),
                    (third.rule_id, "proxy_restart")]  # fmt: skip


def test_a_hold_of_risk_3_offers_no_batch_even_if_its_reading_would(
    batched: tuple[Gated, Watched],
) -> None:
    """Its URL carried a secret only backtide knows: the hold is risk 3, so no batch buttons."""
    gated, watch = batched
    event, gate = telegram_call("556", n=1)
    gate = facts(f"{1:064x}", reading=gate["reading"], url_struck=True)
    ack = gated.ask(event, gate)
    assert ack["verdict"] == "hold"
    assert watch.held_notices[-1]["risk"] == 3 and watch.held_notices[-1]["batches"] == []
    assert str(make_batch(gated, ack["hold_id"], "recipient").status) == "not_batchable"


def test_no_batch_for_what_may_never_ride_one_nor_while_paused(
    batched: tuple[Gated, Watched],
) -> None:
    gated, _ = batched
    deleted = gated.ask(delete_event(), write_facts())["hold_id"]
    assert str(make_batch(gated, deleted, "kind").status) == "not_batchable"
    sent = gated.ask(*telegram_call("556", n=1))["hold_id"]
    paused = make_batch(gated, sent, "recipient", frozen=lambda: True)
    assert str(paused.status) == "paused" and gated.gate_events("batch_rule") == []
    assert [p["hold_id"] for p in gated.channel.pending()] == [deleted, sent]
    assert str(make_batch(gated, "h-000000000000", "kind").status) == "unknown"
    with pytest.raises(ValueError):
        gated.channel.create_batch(sent, "kind", by="agent", requested_by="x")
    with pytest.raises(ValueError):
        gated.channel.create_batch(sent, "everything", by="cli", requested_by="x")


def test_a_batch_that_cannot_be_recorded_is_not_made(box: BlackBox) -> None:
    records: list[str] = []

    def record(source: str, action: str, target: str, **kw: Any) -> Event:
        records.append(action)
        if action == "batch_rule":
            raise BlackBoxError("disk full")
        return box.append(source, action, target, **kw)

    gated = Gated(box, policy=policy(unknown_hosts="hold"))
    gated.channel._record = record  # noqa: SLF001
    try:
        hold_id = gated.ask(*telegram_call("556", n=1))["hold_id"]
        outcome = make_batch(gated, hold_id, "recipient")
        assert str(outcome.status) == "failed" and gated.channel.batches() == []
        assert [p["hold_id"] for p in gated.channel.pending()] == [hold_id]
    finally:
        gated.channel.close()


def test_a_plain_write_batch_by_method_host_and_route(batched: tuple[Gated, Watched]) -> None:
    gated, _ = batched

    def post(path: str, n: int) -> dict[str, Any]:
        event = request_event(path=path, method="POST", flow_id=f"f{n}")
        return gated.ask(event, write_facts(f"{n:064x}"))

    hold_id = post("/v1/items/12/notes", 1)["hold_id"]
    assert str(make_batch(gated, hold_id, "kind").status) == "created"
    assert post("/v1/items/99/notes", 2)["verdict"] == "allow"
    assert post("/v1/items/99/other", 3)["verdict"] == "hold"
    [rule] = gated.gate_events("batch_rule")
    assert (rule.details["method"], rule.details["host"], rule.details["route"]) == (
        "POST", "example.com", "/v1/items/*/notes"
    )  # fmt: skip


# --- the security review of T10-4 ----------------------------------------------------------------


def plain_batch(gated: Gated, host: str = "example.com") -> str:
    """A "POST a este host y ruta, 1 h" batch, made from a held POST."""
    event = request_event(host, path="/v1/items/12/notes", method="POST", flow_id="f1")
    hold_id = gated.ask(event, write_facts(("1" if host == "example.com" else "2") * 64))["hold_id"]
    outcome = make_batch(gated, hold_id, "kind")
    assert str(outcome.status) == "created"
    return str(outcome.rule_id)


def post(gated: Gated, n: int, *, headers: list[list[str]] | None = None, scheme: str = "https",
         port: int = 443, host: str = "example.com", **gate: Any) -> dict[str, Any]:  # fmt: skip
    event = request_event(host, path=f"/v1/items/{n}/notes", method="POST", flow_id=f"f{n}",
                          headers=headers or [], scheme=scheme, port=port)  # fmt: skip
    return gated.ask(event, write_facts(f"{n + 100:064x}", **gate))


def test_a_disguised_delete_never_rides_a_batch(batched: tuple[Gated, Watched]) -> None:
    """A1: a POST with X-HTTP-Method-Override: DELETE is a deletion (risk 3), never batched;
    an override name the recording keeps but the proxy did not report counts, unread."""
    gated, watch = batched
    plain_batch(gated)
    assert post(gated, 2)["verdict"] == "allow"  # the batch works
    override = [["X-HTTP-Method-Override", "DELETE"]]
    ack = post(gated, 3, headers=override, override="DELETE")
    assert ack["verdict"] == "hold"
    held = gated.gate_events("held")[-1]
    assert (held.risk, held.details["reason"]) == (3, "delete")
    assert watch.held_notices[-1]["batches"] == []
    unreported = post(gated, 4, headers=[["X-Original-URL", "/admin"]])
    assert unreported["verdict"] == "hold" and gated.gate_events("held")[-1].risk == 3
    assert post(gated, 5, override="PUT")["verdict"] == "hold"
    assert gated.gate_events("held")[-1].details["reason"] == "override"
    assert post(gated, 6, trailers=True)["verdict"] == "hold"


def test_a_plain_batch_is_bound_to_its_token_scheme_and_port(
    batched: tuple[Gated, Watched],
) -> None:
    """M1 and B3: another token, a token the redaction recognises, http or another port ask
    again."""
    gated, _ = batched
    plain_batch(gated)
    assert post(gated, 2, credential_id="d" * 64)["verdict"] == "hold"
    assert post(gated, 4, scheme="http", port=80)["verdict"] == "hold"
    assert post(gated, 5)["verdict"] == "allow"
    # A token the redaction recognises (every "Bearer …"): the agent's own toward a listed API,
    # so the batch (bound to it) covers it; toward a host off the list, never.
    assert post(gated, 3, credentials_struck=True)["verdict"] == "allow"
    plain_batch(gated, "unlisted.test")
    assert post(gated, 6, host="unlisted.test")["verdict"] == "allow"
    assert post(gated, 7, host="unlisted.test", credentials_struck=True)["verdict"] == "hold"


def test_no_batch_is_used_while_the_agent_is_frozen(box: BlackBox) -> None:
    """B4: as an approval, a batch lets nothing pass while the person's pause is open or a
    rewind runs, even before reject_open ended it."""
    frozen = {"now": False}
    watch = Watched()
    gated = Gated(box, watch=watch, policy=policy(unknown_hosts="hold"),
                  frozen=lambda: frozen["now"])  # fmt: skip
    try:
        plain_batch(gated)
        frozen["now"] = True
        assert post(gated, 2)["verdict"] == "hold"
        frozen["now"] = False
        assert post(gated, 3)["verdict"] == "allow"
    finally:
        gated.channel.close()


def test_the_batches_end_even_if_rejecting_the_holds_fails(
    batched: tuple[Gated, Watched], monkeypatch: pytest.MonkeyPatch
) -> None:
    """B4: a pause whose rejection breaks half way still ends every batch."""
    gated, _ = batched
    rule_id = plain_batch(gated)

    def broken() -> list[Any]:
        raise RuntimeError("boom")

    monkeypatch.setattr(gated.channel._book, "reject_open", broken)  # noqa: SLF001
    with pytest.raises(RuntimeError):
        gated.channel.reject_open("pause")
    assert gated.channel.batches() == []
    [end] = gated.gate_events("batch_rule_end")
    assert end.details == {"rule_id": rule_id, "why": "pause", "uses": 0}
    assert post(gated, 2)["verdict"] == "hold"
