"""The proxy's side of the channel (backtide/gate/client.py), over a real Unix socket.

backtide's side is played here by a small asyncio client that speaks the protocol by hand, so
every rule of the proxy's end is seen from outside: who may connect, hello then config, the ack
with its timeout, the bounded queue and its dropped count, ping, and a dead channel.
"""

import asyncio
import json
import os
import shutil
import socket
import tempfile
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from backtide.gate import protocol, record
from backtide.gate.client import NOT_RECORDED, SOCKET_NAME, Channel
from backtide.gate.protocol import Sender
from backtide.gate.providers import FAKE_KEY_PREFIX, Kind, Provider, Providers, Secret

ME = os.getuid()
REAL = "sk-ant-api03-TEST" + "cl13ntR3alK3y" * 4
FAKE = FAKE_KEY_PREFIX + "anthropic-" + "C1l2i3e4n5t6A7b8C9d0E1f2G3h4I5j6"
FAST = {"ack_timeout_ms": 300, "ping_interval_ms": 500, "max_queue": 3}


@pytest.fixture
def folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="bt"))  # a Unix socket path is limited to ~100 bytes
    path.chmod(0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def providers() -> Providers:
    return Providers(
        [Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL))]
    )


def a_request(host: str = "example.com") -> dict[str, Any]:
    return record.request_event(
        {"flow_id": "f1", "method": "GET", "scheme": "https", "host": host, "port": 443,
         "path": "/", "headers": []},
        (),
    )  # fmt: skip


def config_line(limits: dict[str, int] | None = None) -> bytes:
    return protocol.encode(protocol.config([], providers(), limits or FAST), Sender.BACKTIDE)


class Backtide:
    """backtide's end, by hand."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def receive(self, timeout: float = 2.0) -> dict[str, Any]:
        line = await asyncio.wait_for(self.reader.readline(), timeout)
        if not line:
            raise ConnectionError("closed")
        return protocol.decode(line, Sender.PROXY)

    async def receive_type(self, kind: str, timeout: float = 2.0) -> dict[str, Any]:
        while True:
            message = await self.receive(timeout)
            if message["type"] == kind:
                return message

    def send(self, data: bytes) -> None:
        self.writer.write(data)

    async def closed(self, timeout: float = 3.0) -> bool:
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout)
                if not line:
                    return True
        except TimeoutError:
            return False


@asynccontextmanager
async def proxy_side(
    folder: Path, *, peer: Callable[[socket.socket], int] = lambda sock: ME
) -> AsyncIterator[Channel]:
    channel = Channel(str(folder), backtide_uid=ME, version="t", pid=7, peer=peer)
    await channel.start()
    try:
        yield channel
    finally:
        await channel.close()


async def connect(folder: Path, *, configure: bool = True) -> Backtide:
    reader, writer = await asyncio.open_unix_connection(str(folder / SOCKET_NAME))
    side = Backtide(reader, writer)
    hello = await side.receive()
    assert hello == {"type": "hello", "version": "t", "pid": 7}
    if configure:
        side.send(config_line())
    return side


async def until(predicate: Callable[[], bool], timeout: float = 2.0) -> None:
    for _ in range(int(timeout / 0.01)):
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("timed out")


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


# --- the socket and who may use it ---------------------------------------------------------------


def test_the_socket_is_private_and_a_stale_one_is_replaced(folder: Path) -> None:
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(folder / SOCKET_NAME))
    stale.close()

    async def go() -> None:
        async with proxy_side(folder):
            mode = (folder / SOCKET_NAME).stat().st_mode & 0o777
            assert mode == 0o600
            await connect(folder)

    run(go())


def test_a_connection_from_another_uid_is_refused_before_anything_is_said(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder, peer=lambda sock: ME + 1) as channel:
            reader, writer = await asyncio.open_unix_connection(str(folder / SOCKET_NAME))
            assert await asyncio.wait_for(reader.read(), 2) == b""  # not even a hello
            assert not channel.ready
            writer.close()

    run(go())


def test_unreadable_credentials_are_refused(folder: Path) -> None:
    def unreadable(sock: socket.socket) -> int:
        raise OSError("no SO_PEERCRED")

    async def go() -> None:
        async with proxy_side(folder, peer=unreadable):
            reader, _ = await asyncio.open_unix_connection(str(folder / SOCKET_NAME))
            assert await asyncio.wait_for(reader.read(), 2) == b""

    run(go())


# --- hello, config and the verdicts --------------------------------------------------------------


def test_nothing_is_asked_before_the_config(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            assert await channel.ask(a_request()) == NOT_RECORDED  # nobody connected
            await connect(folder, configure=False)
            assert await channel.ask(a_request()) == NOT_RECORDED  # hello, but no config yet
            assert channel.config is None

    run(go())


def test_the_config_keeps_the_keys_in_memory_and_never_in_its_repr(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)  # kept: a dropped one closes the connection
            await until(lambda: channel.ready)
            assert side.writer is not None and channel.config is not None
            [provider] = channel.config.providers.items
            assert provider.real_key.reveal() == REAL
            assert REAL not in repr(channel.config) and FAKE not in repr(channel.config)
            assert channel.limits["ack_timeout_ms"] == 300
            assert channel.scrubber.text(f"x {REAL} {FAKE}") == "x [REDACTED] [REDACTED]"

    run(go())


def test_a_first_message_that_is_not_the_config_closes_the_channel(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder, configure=False)
            side.send(protocol.encode(protocol.ping(), Sender.BACKTIDE))
            assert await side.closed()
            assert not channel.ready

    run(go())


def test_allow_and_deny_come_back_to_the_request_that_asked(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            first = asyncio.ensure_future(channel.ask(a_request("one.example")))
            second = asyncio.ensure_future(channel.ask(a_request("two.example")))
            asked = [await side.receive_type("request"), await side.receive_type("request")]
            assert [m["event"]["details"]["host"] for m in asked] == ["one.example", "two.example"]
            one, two = (m["id"] for m in asked)
            side.send(protocol.encode(protocol.ack(two, "deny", reason="not_allowed"), "backtide"))
            side.send(protocol.encode(protocol.ack(one, "allow", seq=41), Sender.BACKTIDE))
            assert (await first).allowed and (await first).seq == 41
            denied = await second
            assert not denied.allowed and denied.reason == "not_allowed"

    run(go())


def test_no_ack_in_time_is_a_denial(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            asked = asyncio.ensure_future(channel.ask(a_request()))
            message = await side.receive_type("request")
            assert await asked == NOT_RECORDED  # 300 ms
            # A late allow changes nothing.
            side.send(protocol.encode(protocol.ack(message["id"], "allow", seq=1), "backtide"))
            await asyncio.sleep(0.05)

    run(go())


def test_a_channel_that_closes_denies_what_was_waiting(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            asked = asyncio.ensure_future(channel.ask(a_request()))
            await side.receive_type("request")
            side.writer.close()
            assert await asked == NOT_RECORDED
            await until(lambda: not channel.ready)
            assert await channel.ask(a_request()) == NOT_RECORDED

    run(go())


def test_a_broken_line_from_backtide_closes_the_channel(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            asked = asyncio.ensure_future(channel.ask(a_request()))
            await side.receive_type("request")
            side.send(b'{"type": "ack", "id": 1, "verdict": "maybe", "seq": 1}\n')
            assert await asked == NOT_RECORDED
            assert await side.closed()

    run(go())


def test_a_newer_connection_replaces_the_older_one(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            old = await connect(folder)
            await until(lambda: channel.ready)
            new = await connect(folder)
            assert await old.closed()
            await until(lambda: channel.ready)
            asked = asyncio.ensure_future(channel.ask(a_request()))
            message = await new.receive_type("request")
            new.send(protocol.encode(protocol.ack(message["id"], "allow", seq=2), "backtide"))
            assert (await asked).allowed

    run(go())


# --- events, the queue and its drops -------------------------------------------------------------


def test_events_wait_for_backtide_and_go_once_it_is_configured(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            for n in range(5):  # the default limit is 1000; the config lowers it to 3 later
                channel.tell(record.dropped_event(n + 1))
            assert channel.queued == 5
            side = await connect(folder)
            got = [await side.receive_type("event") for _ in range(5)]
            assert [m["event"]["details"]["count"] for m in got] == [1, 2, 3, 4, 5]
            assert channel.dropped == 0

    run(go())


def test_drops_are_reported_before_the_rest_once_there_is_room(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            # Fill past max_queue (3) synchronously: nothing is written in between.
            for n in range(6):
                channel.tell(record.throttled_event(n + 1, 10))
            assert channel.queued == 3 and channel.dropped == 3
            first = await side.receive_type("event")
            assert first["event"]["action"] == "dropped"
            assert first["event"]["details"]["count"] == 3
            rest = [await side.receive_type("event") for _ in range(3)]
            assert [m["event"]["details"]["count"] for m in rest] == [1, 2, 3]

    run(go())


def test_events_are_sent_whole_and_never_carry_a_known_key(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            leaked = {"flow_id": "f", "host": "example.com", "port": 443,
                      "path": f"/?q={REAL}", "headers": [("x-note", FAKE)]}  # fmt: skip
            channel.tell(record.blocked_event("port", leaked, channel.scrubber))
            got = await side.receive_type("event")
            text = json.dumps(got)
            assert REAL not in text and FAKE not in text

    run(go())


# --- ping and a dead channel ---------------------------------------------------------------------


def test_the_proxy_pings_and_answers_pings(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            assert (await side.receive_type("ping", timeout=2))["type"] == "ping"
            side.send(protocol.encode(protocol.ping(), Sender.BACKTIDE))
            assert (await side.receive_type("pong"))["type"] == "pong"

    run(go())


def test_a_silent_backtide_is_taken_for_dead(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            side = await connect(folder)
            await until(lambda: channel.ready)
            # ping_interval 500 ms: three silent intervals and the channel closes.
            assert await side.closed(timeout=3.0)
            assert not channel.ready

    run(go())


def test_the_hello_comes_first_even_with_an_eager_task_factory(folder: Path) -> None:
    """mitmproxy's loop runs a task as soon as it is made (seen in the VM): the first ping
    must still come after the hello."""

    async def go() -> None:
        asyncio.get_running_loop().set_task_factory(asyncio.eager_task_factory)
        async with proxy_side(folder):
            await connect(folder)  # asserts the very first line is the hello

    run(go())


def test_the_proxys_own_throttles_are_told_as_one_count(folder: Path) -> None:
    async def go() -> None:
        async with proxy_side(folder) as channel:
            for _ in range(4):
                channel.count_throttled()
            side = await connect(folder)
            got = await side.receive_type("event")
            assert got["event"]["action"] == "throttled"
            assert got["event"]["details"]["count"] == 4

    run(go())
