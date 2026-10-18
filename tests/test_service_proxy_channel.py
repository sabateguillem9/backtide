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


def policy() -> Policy:
    return Policy(allow_hosts=("example.com", "*.allowed.test"), providers=providers(),
                  secrets=(GATEWAY,))  # fmt: skip


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
    proxy.send(protocol.request(1, request_event()))
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
        proxy.send(protocol.request(n, request_event(host)))
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
    proxy.send(protocol.request(5, request_event(host, port)))
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
        proxy.send(protocol.request(1, request_event()))
        proxy.send(protocol.request(2, request_event("nope.example")))
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
    proxy.send(protocol.request(1, sneaky))
    cut = request_event()
    cut["target"] = "https://example.com/" + REAL[:30]  # a cut that left the start of a key
    proxy.send(protocol.request(2, cut))
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
