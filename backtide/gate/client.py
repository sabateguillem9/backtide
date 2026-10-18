"""The proxy's side of the channel to backtide (asyncio, in mitmproxy's own loop).

Design: docs/21-diseno-t06-proxy.md, section 5 (plan B of T06-1, P3): the proxy LISTENS on
``/run/backtide/events.sock`` and backtide connects (SELinux does not let a container connect to
a socket of the host). So here:

- ``start()`` makes the socket (0600, in the proxy's own 0700 folder) and accepts backtide. A
  connection is taken only from ``backtide_uid`` (``SO_PEERCRED``); a newer one replaces the
  older one. The proxy says ``hello`` and waits for the ``config`` (the real keys arrive here,
  and live only in memory).
- ``ask(event)`` sends a ``request`` and waits for its ``ack`` for ``ack_timeout_ms``. With no
  configured connection, a timeout, a broken line or a closed channel the answer is a denial
  (``not_recorded``): nothing goes out unless backtide says it is in the black box.
- ``tell(event)`` puts an event that sends nothing out (a response, a refusal) in a bounded
  queue; when it is full the event is counted and a ``net/dropped {count}`` goes first once
  there is room. The queue outlives a connection: what was refused while backtide was away is
  recorded when it comes back.
- ``ping`` every ``ping_interval_ms``; with nothing from backtide for three intervals the
  connection is taken for dead and closed (every pending request is then denied).

Never logs a message's content: only its type (``protocol.describe``) and error kinds.
Imports the standard library and ``backtide.gate``/``backtide.blackbox.redact`` only.
"""

import asyncio
import contextlib
import logging
import os
import socket
import struct
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from backtide.blackbox.redact import KnownScrubber
from backtide.gate import protocol, record
from backtide.gate.protocol import DEFAULT_LIMITS, LineReader, ProtocolError, Sender
from backtide.gate.providers import Providers

logger = logging.getLogger(__name__)

SOCKET_NAME = "events.sock"
THROTTLED_EVERY = 10.0  # the proxy's own refusals for its limits, counted in one net/throttled
CONFIG_TIMEOUT = 10.0  # seconds backtide has to answer the hello with a config
DEAD_AFTER_PINGS = 3  # silent intervals before a connection is taken for dead
READ_CHUNK = 65536
_CREDENTIALS = struct.Struct("3i")

PeerUid = Callable[[socket.socket], int]


def peer_uid(sock: socket.socket) -> int:
    """The uid of the process at the other end (``SO_PEERCRED``, Linux). OSError where the
    option does not exist: the caller refuses the connection."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise OSError("SO_PEERCRED is not available here")
    _pid, uid, _gid = _CREDENTIALS.unpack(
        sock.getsockopt(socket.SOL_SOCKET, option, _CREDENTIALS.size)
    )
    return uid


@dataclass(frozen=True)
class GateConfig:
    """What backtide sent: the providers (real keys inside ``Secret``), one scrubber built
    for them (reused by every event of this config), the limits, and the provider-side tools
    that may go to a provider anyway (``[proxy] allow_provider_tools``, T06-6)."""

    providers: Providers
    scrubber: KnownScrubber
    limits: Mapping[str, int]
    provider_tools: frozenset[str] = frozenset()

    def __repr__(self) -> str:
        return f"GateConfig({self.providers!r})"


@dataclass(frozen=True)
class Ack:
    verdict: str  # "allow" or "deny"
    seq: int | None = None
    reason: str | None = None
    retry_after: int | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow" and self.seq is not None


NOT_RECORDED = Ack("deny", reason="not_recorded")
_NO_SECRETS = KnownScrubber(())


def gate_config(message: Mapping[str, Any]) -> GateConfig:
    """A GateConfig from a checked ``config`` message (ProtocolError if it is not usable)."""
    providers = protocol.providers_from_config(message)
    return GateConfig(
        providers=providers,
        scrubber=KnownScrubber(providers.known_secrets()),
        limits=dict(message["limits"]),
        provider_tools=frozenset(message.get("provider_tools", [])),
    )


class _Connection:
    """One connection from backtide. ``configured`` once its ``config`` arrived."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.configured = False
        self.closed = False
        self.pending: dict[int, asyncio.Future[Ack]] = {}
        self.writer_task: asyncio.Future[None] | None = None

    def send(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionError("the channel is closed")
        self.writer.write(data)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for future in self.pending.values():
            if not future.done():
                future.set_result(NOT_RECORDED)
        self.pending.clear()
        with contextlib.suppress(Exception):
            self.writer.close()


class Channel:
    """The proxy's end of the channel. Everything runs in one asyncio loop."""

    def __init__(
        self,
        folder: str,
        *,
        backtide_uid: int,
        version: str,
        pid: int,
        peer: PeerUid = peer_uid,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.path = os.path.join(folder, SOCKET_NAME)
        self._backtide_uid = backtide_uid
        self._version = version
        self._pid = pid
        self._peer = peer
        self._clock = clock
        self.config: GateConfig | None = None
        self._conn: _Connection | None = None
        self._queue: deque[dict[str, Any]] = deque()
        self._dropped = 0
        self._throttled = 0
        self._throttled_since = clock()
        self._last_throttled = float("-inf")
        self._next_id = 0
        self._server: asyncio.AbstractServer | None = None
        self._wake: asyncio.Event | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    # Public

    @property
    def limits(self) -> Mapping[str, int]:
        return self.config.limits if self.config is not None else DEFAULT_LIMITS

    @property
    def scrubber(self) -> KnownScrubber:
        """The secrets the proxy knows, for every event it builds (none before a config)."""
        return self.config.scrubber if self.config is not None else _NO_SECRETS

    @property
    def ready(self) -> bool:
        """A configured connection to backtide is open: requests can be asked about."""
        conn = self._conn
        return conn is not None and conn.configured and not conn.closed

    @property
    def queued(self) -> int:
        return len(self._queue)

    @property
    def dropped(self) -> int:
        return self._dropped

    async def start(self) -> None:
        """Listen on the socket (a stale one is removed first; it is 0600 from its birth)."""
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)
        old_mask = os.umask(0o177)
        try:
            self._server = await asyncio.start_unix_server(self._accept, path=self.path)
        finally:
            os.umask(old_mask)
        self._wake = asyncio.Event()

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
        for task in list(self._tasks):
            task.cancel()

    async def ask(self, event: Mapping[str, Any]) -> Ack:
        """Send ``event`` (a ``net/request`` or ``llm/request``) and wait for backtide's
        verdict. Any failure is a denial (NOT_RECORDED): nothing goes out unrecorded."""
        conn = self._conn
        if conn is None or not conn.configured or conn.closed:
            return NOT_RECORDED
        self._next_id += 1
        request_id = self._next_id
        future: asyncio.Future[Ack] = asyncio.get_running_loop().create_future()
        conn.pending[request_id] = future
        timeout = self.limits["ack_timeout_ms"] / 1000
        try:
            conn.send(protocol.encode(protocol.request(request_id, event), Sender.PROXY))
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            logger.warning("no ack from backtide in %.1f s: the request is refused", timeout)
            return NOT_RECORDED
        except (ConnectionError, ProtocolError, OSError) as error:
            logger.warning("cannot ask backtide (%s): the request is refused", type(error).__name__)
            return NOT_RECORDED
        finally:
            conn.pending.pop(request_id, None)

    def count_throttled(self) -> None:
        """One refusal for the proxy's own limits (connections, requests waiting): counted,
        and told in one ``net/throttled`` every THROTTLED_EVERY s at most."""
        self._throttled += 1
        if self._wake is not None:
            self._wake.set()

    def tell(self, event: Mapping[str, Any]) -> None:
        """Queue an event that sends nothing out. Never blocks, never raises for a full queue."""
        if len(self._queue) >= self.limits["max_queue"]:
            self._dropped += 1
            return
        self._queue.append(dict(event))
        if self._wake is not None:
            self._wake.set()

    # Connections

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        try:
            uid = self._peer(sock)
        except OSError as error:
            logger.error("cannot tell who connected to the channel (%s): refused", error)
            writer.close()
            return
        if uid != self._backtide_uid:
            logger.error("a channel connection from uid %d (not backtide's): refused", uid)
            writer.close()
            return
        conn = _Connection(reader, writer)
        old, self._conn = self._conn, conn
        if old is not None:
            logger.warning("backtide connected again: the older channel connection is closed")
            old.close()
        try:
            await self._serve(conn)
        except (ProtocolError, ConnectionError, OSError, TimeoutError) as error:
            logger.warning("the channel to backtide ended (%s)", type(error).__name__)
        except Exception:
            logger.exception("the channel to backtide failed")
        finally:
            conn.close()
            if self._conn is conn:
                self._conn = None
            if conn.writer_task is not None:
                conn.writer_task.cancel()
                self._tasks.discard(conn.writer_task)

    async def _serve(self, conn: _Connection) -> None:
        conn.send(protocol.encode(protocol.hello(self._version, self._pid), Sender.PROXY))
        # Only now: with an eager task factory (mitmproxy's loop) a task runs as soon as it is
        # made, and its first ping must not go before the hello.
        conn.writer_task = asyncio.ensure_future(self._write_loop(conn))
        self._tasks.add(conn.writer_task)
        lines = LineReader()
        pending_lines: deque[bytes] = deque()
        message = await asyncio.wait_for(
            self._next_message(conn, lines, pending_lines), CONFIG_TIMEOUT
        )
        if message["type"] != "config":
            raise ProtocolError(f"{message['type']}: expected the config first")
        self.config = gate_config(message)
        conn.configured = True
        logger.info("channel configured: %s", protocol.describe(message))
        if self._wake is not None:
            self._wake.set()  # what waited in the queue goes now
        while True:
            silence = DEAD_AFTER_PINGS * self.limits["ping_interval_ms"] / 1000
            try:
                message = await asyncio.wait_for(
                    self._next_message(conn, lines, pending_lines), silence
                )
            except TimeoutError:
                logger.warning("nothing from backtide for %.0f s: the channel is closed", silence)
                return
            self._handle(conn, message)

    async def _next_message(
        self, conn: _Connection, lines: LineReader, pending: deque[bytes]
    ) -> dict[str, Any]:
        while not pending:
            chunk = await conn.reader.read(READ_CHUNK)
            if not chunk:
                raise ConnectionError("backtide closed the channel")
            pending.extend(lines.feed(chunk))
        return protocol.decode(pending.popleft(), Sender.BACKTIDE)

    def _handle(self, conn: _Connection, message: dict[str, Any]) -> None:
        kind = message["type"]
        if kind == "ack":
            future = conn.pending.get(message["id"])
            if future is None or future.done():
                return  # late (its request already timed out) or unknown: nothing to do
            future.set_result(
                Ack(
                    message["verdict"],
                    seq=message.get("seq"),
                    reason=message.get("reason"),
                    retry_after=message.get("retry_after"),
                )
            )
        elif kind == "ping":
            conn.send(protocol.encode(protocol.pong(), Sender.PROXY))
        elif kind == "config":
            self.config = gate_config(message)
            logger.info("channel configured again: %s", protocol.describe(message))
        # pong: its arrival already counted as a sign of life

    async def _write_loop(self, conn: _Connection) -> None:
        """Drain the queue (only on a configured connection) and ping now and then."""
        if self._wake is None:
            raise RuntimeError("the channel was not started")
        next_ping = self._clock()
        while not conn.closed:
            if conn.configured:
                self._flush(conn)
                await conn.writer.drain()
            interval = self.limits["ping_interval_ms"] / 1000
            now = self._clock()
            if now >= next_ping:
                conn.send(protocol.encode(protocol.ping(), Sender.PROXY))
                await conn.writer.drain()
                next_ping = now + interval
            self._wake.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), max(0.0, next_ping - self._clock()))

    def _flush(self, conn: _Connection) -> None:
        now = self._clock()
        if self._throttled and now - self._last_throttled >= THROTTLED_EVERY:
            window = max(1, int(now - self._throttled_since))
            count, self._throttled = self._throttled, 0
            self._throttled_since = self._last_throttled = now
            self._send_event(conn, record.throttled_event(count, window))
        while not conn.closed:
            if self._dropped:
                count, self._dropped = self._dropped, 0
                self._send_event(conn, record.dropped_event(count))
                continue
            if not self._queue:
                return
            self._send_event(conn, self._queue.popleft())

    def _send_event(self, conn: _Connection, event: Mapping[str, Any]) -> None:
        try:
            data = protocol.encode(protocol.event(event), Sender.PROXY)
        except ProtocolError as error:
            logger.error("an event could not be encoded (%s): it is counted as dropped", error)
            self._dropped += 1
            return
        conn.send(data)
