"""backtide's end of the channel to the egress proxy: connect, check who is there, configure
it, and record what it says BEFORE it lets anything out.

Design: docs/21-diseno-t06-proxy.md, section 5 (with T06-1's plan B: the proxy listens, backtide
connects) and section 8 (the budgets).

- **Where it connects** (``open_channel``): the folder is the proxy's, so what is in it is not
  to be trusted. ``events.sock`` is opened with ``O_PATH|O_NOFOLLOW`` relative to the folder
  (itself opened with ``O_DIRECTORY|O_NOFOLLOW``), ``fstat`` must say it is a socket of the
  proxy's uid, and the connection goes through ``/proc/self/fd/<fd>``: no symlink can lead it
  to another socket.
- **Who is at the other end** (``check_peer``), before a byte is sent (the config carries the
  real keys): ``SO_PEERCRED`` must give the proxy's uid and a pid whose ``/proc/<pid>/cgroup``
  is the proxy container's (``docker-<id>.scope``). Another process of the host with that uid is
  refused.
- **The proxy is exposed to the agent, so what it says is untrusted data**: every line is
  checked by ``protocol.decode`` (only ``net``/``llm``, known actions and keys, bounded sizes,
  the fixed risk), struck again with ``scrub_known(..., cut_tails=True)`` against every secret
  backtide knows (the real and fake keys and the Gateway token, also in lower case: the proxy
  lowers hosts and header names), and the black box redacts once more.
- **The verdict** (``ack``), in order: the budgets (20 requests/s sustained with a burst of 500,
  and 100,000 a day: over them ``deny throttled`` with ``Retry-After``, counted in a
  ``net/throttled`` at most every 10 s, and never let out unrecorded); then the allowed hosts
  (the user's ``allow_hosts`` and the providers' hosts, ports 80 and 443 only): anything else
  is recorded as ``net/blocked {reason: not_allowed}`` and denied; then the request's own event
  is appended and only then ``allow`` with its ``seq``. If the append fails: ``deny
  not_recorded``. Acks go in the order the requests came.
- Events that send nothing out (responses, the proxy's own refusals) have their own budgets, by
  count and by bytes, per second and per day: a proxy that the agent makes refuse things in a
  loop cannot fill the disk of the black box. Over them they are counted and a ``net/dropped``
  says how many.
- A request over the budgets is denied at once (``throttled``): the reader never sleeps, so the
  acks of the others never wait behind it.
- ``ping`` every 5 s; ``last_seen`` is when the proxy last said anything (the Guardian's watch
  takes it for down after 15 s of silence).

The config is never logged: ``protocol.describe`` names the providers and counts the hosts.
"""

import json
import logging
import os
import re
import socket
import stat
import struct
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import BlackBoxError, Event
from backtide.blackbox.redact import MIN_KNOWN_SECRET, KnownScrubber
from backtide.gate import protocol, record
from backtide.gate.client import SOCKET_NAME
from backtide.gate.policy import ALLOWED_PORTS, AllowList
from backtide.gate.protocol import BLOCK_RISK, LineReader, ProtocolError, Sender
from backtide.gate.providers import Providers
from backtide.sensors.files import DailyBudget, TokenBucket

logger = logging.getLogger(__name__)

HELLO_TIMEOUT = 10.0  # seconds the proxy has to say hello once connected
PING_EVERY = 5.0
READ_TIMEOUT = 0.5  # the reader wakes this often to see whether it should stop
REQUEST_RATE = 20.0  # requests per second, sustained (docs/21, section 8)
REQUEST_BURST = 500
DAILY_REQUESTS = 100_000
THROTTLED_EVERY = 10.0  # at most one net/throttled this often
EVENT_RATE = 100.0  # events that send nothing out, per second
EVENT_BURST = 2000
DAILY_EVENTS = 200_000  # a response and a refusal for every allowed request, and some more
EVENT_BYTES_RATE = 256 * 1024  # bytes of events per second, sustained
EVENT_BYTES_BURST = 8 * 1024 * 1024
DAILY_EVENT_BYTES = 512 * 1024 * 1024
DROPPED_EVERY = 10.0
_CREDENTIALS = struct.Struct("3i")
_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


class ChannelError(Exception):
    """The channel cannot be opened or used, or the peer is not the proxy. The message never
    holds a key."""


class Record(Protocol):
    def __call__(
        self, source: str, action: str, target: str, *, details: Mapping[str, Any], risk: int
    ) -> Event: ...


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def peer_of(sock: socket.socket) -> Peer:
    """``SO_PEERCRED`` (Linux). ChannelError where it cannot be read."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ChannelError("SO_PEERCRED is not available: cannot tell who is the proxy")
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, option, _CREDENTIALS.size)
    except OSError as error:
        raise ChannelError(f"cannot read the channel peer's credentials: {error}") from error
    return Peer(*_CREDENTIALS.unpack(raw))


def read_cgroup(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cgroup").read_text()
    except OSError as error:
        raise ChannelError(f"cannot read the cgroup of pid {pid}: {error}") from error


def in_container(cgroup: str, container_id: str) -> bool:
    """Whether a ``/proc/<pid>/cgroup`` text puts the process in that Docker container: the
    unified line is ``0::/system.slice/docker-<id>.scope`` (systemd driver, as in the VM) or
    ``0::/docker/<id>`` (cgroupfs driver), maybe with a deeper path below it."""
    if not _CONTAINER_ID_RE.fullmatch(container_id):
        return False
    wanted = (f"/system.slice/docker-{container_id}.scope", f"/docker/{container_id}")
    for line in cgroup.splitlines():
        hierarchy, _, path = line.partition("::")
        if hierarchy != "0":
            continue
        if any(path == w or path.startswith(w + "/") for w in wanted):
            return True
    return False


def check_peer(
    sock: socket.socket,
    *,
    proxy_uid: int,
    container_id: str,
    peer: Callable[[socket.socket], Peer] = peer_of,
    cgroup: Callable[[int], str] = read_cgroup,
) -> Peer:
    """The peer must be the proxy's uid inside the proxy's container (ChannelError otherwise,
    logged with uid and pid)."""
    who = peer(sock)
    if who.uid != proxy_uid:
        logger.error(
            "the channel peer is uid %d (pid %d), not the proxy's: refused", who.uid, who.pid
        )
        raise ChannelError(f"the channel peer is uid {who.uid}, not the proxy's {proxy_uid}")
    if who.pid <= 0 or not in_container(cgroup(who.pid), container_id):
        logger.error("the channel peer (pid %d) is not in the proxy's container: refused", who.pid)
        raise ChannelError(f"the channel peer (pid {who.pid}) is not in the proxy's container")
    return who


def open_channel(folder: Path, *, proxy_uid: int, timeout: float = HELLO_TIMEOUT) -> socket.socket:
    """Connect to the proxy's socket without following any symlink (Linux: ``O_PATH`` and
    ``/proc/self/fd``). ChannelError if it is missing, not a socket, not the proxy's, or
    nobody listens."""
    o_path = getattr(os, "O_PATH", None)
    if o_path is None:
        raise ChannelError("O_PATH is not available: the channel needs Linux")
    try:
        dir_fd = os.open(folder, _OPEN_DIR)
    except OSError as error:
        raise ChannelError(f"cannot open the channel folder {folder}: {error}") from error
    try:
        try:
            fd = os.open(SOCKET_NAME, o_path | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        except OSError as error:
            raise ChannelError(f"no channel socket in {folder}: {error}") from error
        try:
            info = os.fstat(fd)
            if not stat.S_ISSOCK(info.st_mode):
                raise ChannelError(f"{folder / SOCKET_NAME} is not a socket")
            if info.st_uid != proxy_uid:
                raise ChannelError(
                    f"{folder / SOCKET_NAME} belongs to uid {info.st_uid}, not the proxy's"
                )
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect(f"/proc/self/fd/{fd}")
            except OSError as error:
                sock.close()
                raise ChannelError(f"cannot connect to the proxy's channel: {error}") from error
            return sock
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


@dataclass(frozen=True)
class Policy:
    """What backtide lets out (docs/21, section 4) and the secrets it knows."""

    allow_hosts: tuple[str, ...]
    providers: Providers
    secrets: tuple[str, ...] = ()  # e.g. the Gateway token: struck from whatever is recorded
    provider_tools: tuple[str, ...] = ()  # [proxy] allow_provider_tools (T06-6)

    def __repr__(self) -> str:
        return f"Policy({len(self.allow_hosts)} hosts, {self.providers!r})"

    def allow_list(self) -> AllowList:
        return AllowList([*self.allow_hosts, *(p.host for p in self.providers.items)])

    def scrubber(self) -> KnownScrubber:
        known = [*self.providers.known_secrets(), *self.secrets]
        lowered = [secret.lower() for secret in known]  # the proxy lowers hosts and names
        return KnownScrubber([*known, *lowered], cut_tails=True)


class Budgets:
    """The request budgets of docs/21, section 8, and the event budget."""

    def __init__(
        self,
        now: float,
        *,
        rate: float = REQUEST_RATE,
        burst: int = REQUEST_BURST,
        daily: int = DAILY_REQUESTS,
        event_rate: float = EVENT_RATE,
        event_burst: int = EVENT_BURST,
        daily_events: int = DAILY_EVENTS,
        event_bytes_rate: float = EVENT_BYTES_RATE,
        event_bytes_burst: int = EVENT_BYTES_BURST,
        daily_event_bytes: int = DAILY_EVENT_BYTES,
    ) -> None:
        self.bucket = TokenBucket(rate, burst, now)
        self.daily = DailyBudget(daily)
        self.events = TokenBucket(event_rate, event_burst, now)
        self.daily_events = DailyBudget(daily_events)
        self.event_bytes = ByteBucket(event_bytes_rate, event_bytes_burst, now)
        self.daily_event_bytes = DailyBudget(daily_event_bytes)

    def take_event(self, size: int, now: float) -> bool:
        """Room for one event of ``size`` bytes in every event budget (spent only if all)."""
        if self.daily_events.exhausted(now) or self.daily_event_bytes.used + size > (
            self.daily_event_bytes.limit
        ):
            self.daily_event_bytes.exhausted(now)  # rolls the window when it has ended
            return False
        if not self.event_bytes.take(size, now) or not self.events.take(now):
            return False
        self.daily_events.try_spend(now)
        if self.daily_event_bytes.window_start is None:
            self.daily_event_bytes.window_start = now
        self.daily_event_bytes.used += size
        return True


class ByteBucket:
    """A TokenBucket that spends ``size`` tokens at a time (bytes)."""

    def __init__(self, rate: float, burst: int, now: float) -> None:
        self._rate = rate
        self._burst = float(burst)
        self._tokens = float(burst)
        self._last = now

    def take(self, size: int, now: float) -> bool:
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        if self._tokens >= size:
            self._tokens -= size
            return True
        return False


class ProxyChannel:
    """One connection to the proxy, after open_channel and check_peer.

    ``handshake()`` reads the ``hello`` and answers with the config (the keys go here, never to a
    log); ``start()`` runs the reader and the pinger threads; ``close()`` ends them. ``record``
    appends to the black box (``BlackBox.append``, or the rated one). ``on_budget`` is told when
    the daily budget runs out (once per window)."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        record: Record,
        policy: Policy,
        limits: Mapping[str, int] | None = None,
        budgets: Budgets | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        on_budget: Callable[[], None] | None = None,
    ) -> None:
        self._sock = sock
        self._record = record
        self._policy = policy
        self._allow = policy.allow_list()
        self._scrub = policy.scrubber()
        self._limits = dict(limits or {})
        self._mono = monotonic
        self._budgets = budgets if budgets is not None else Budgets(monotonic())
        self._on_budget = on_budget
        self._write_lock = threading.Lock()
        self._lines = LineReader()
        self._pending: list[bytes] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.last_seen = monotonic()
        self.closed = False
        self.close_reason: str | None = None
        self.hello: dict[str, Any] | None = None
        self._throttled = 0
        self._throttled_since = monotonic()
        self._last_throttled_event = float("-inf")
        self._dropped = 0
        self._last_dropped_event = float("-inf")
        self._budget_told: float | None = None

    # Handshake and threads

    def handshake(self, timeout: float = HELLO_TIMEOUT) -> dict[str, Any]:
        """Read the proxy's hello, send it the config. ChannelError if the hello does not
        come in ``timeout`` seconds or is not a hello."""
        self._sock.settimeout(timeout)
        try:
            message = self._read_message()
        except (OSError, ProtocolError) as error:
            raise ChannelError(f"no hello from the proxy: {type(error).__name__}") from None
        if message is None:
            raise ChannelError("the proxy closed the channel before its hello")
        if message["type"] != "hello":
            raise ChannelError(f"the proxy started with a {message['type']}, not a hello")
        self.hello = message
        config = protocol.config(
            self._allow.entries,
            self._policy.providers,
            self._limits or protocol.DEFAULT_LIMITS,
            provider_tools=self._policy.provider_tools,
        )
        try:
            self._send(protocol.encode(config, Sender.BACKTIDE))
        finally:
            del config  # the keys in clear live no longer than this
        logger.info(
            "proxy %s configured (%s)",
            message["version"],
            f"{len(self._policy.providers.items)} providers, {len(self._allow.entries)} hosts",
        )
        self.last_seen = self._mono()
        return message

    def start(self) -> None:
        self._sock.settimeout(READ_TIMEOUT)
        for name, target in (("reader", self._read_loop), ("pinger", self._ping_loop)):
            thread = threading.Thread(target=target, name=f"backtide-channel-{name}", daemon=True)
            self._threads.append(thread)
            thread.start()

    def close(self, reason: str = "closed") -> None:
        if not self.closed:
            self.closed = True
            self.close_reason = reason
        self._stop.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(5)

    def silent_for(self) -> float:
        return self._mono() - self.last_seen

    # Reading

    def _read_message(self) -> dict[str, Any] | None:
        """The next message, or None when the proxy closed the connection."""
        while not self._pending:
            chunk = self._sock.recv(65536)
            if not chunk:
                return None
            self._pending.extend(self._lines.feed(chunk))
        return protocol.decode(self._pending.pop(0), Sender.PROXY)

    def _read_loop(self) -> None:
        reason = "eof"
        try:
            while not self._stop.is_set():
                try:
                    message = self._read_message()
                except TimeoutError:
                    continue
                if message is None:
                    break
                self.last_seen = self._mono()
                self.handle(message)
        except ProtocolError as error:
            logger.warning("the proxy sent a message that is not valid (%s): channel closed", error)
            reason = "protocol"
        except OSError as error:
            if not self._stop.is_set():
                logger.warning("the channel to the proxy broke: %s", type(error).__name__)
            reason = "broken"
        except Exception:
            logger.exception("the channel's reader failed: channel closed")
            reason = "crash"
        finally:
            if not self.closed:
                self.closed = True
                self.close_reason = reason
                self._stop.set()
            try:  # the proxy sees the end at once (and denies what waits); close() frees the fd
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _ping_loop(self) -> None:
        while not self._stop.wait(PING_EVERY):
            try:
                self._send(protocol.encode(protocol.ping(), Sender.BACKTIDE))
            except OSError as error:
                if not self._stop.is_set():
                    logger.warning(
                        "cannot ping the proxy (%s): channel closed", type(error).__name__
                    )
                self._broken("broken")
                return

    def _broken(self, reason: str) -> None:
        """A write failed (maybe half a line went out): nothing more is sent on this channel."""
        if not self.closed:
            self.closed = True
            self.close_reason = reason
        self._stop.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _send(self, data: bytes) -> None:
        with self._write_lock:
            self._sock.sendall(data)

    # Messages

    def handle(self, message: dict[str, Any]) -> None:
        """One checked message from the proxy (public for the tests)."""
        kind = message["type"]
        if kind == "request":
            self._send(protocol.encode(self._verdict(message), Sender.BACKTIDE))
        elif kind == "event":
            self._event(message["event"])
        elif kind == "ping":
            self._send(protocol.encode(protocol.pong(), Sender.BACKTIDE))
        elif kind == "hello":
            raise ProtocolError("hello: only once, at the start")
        self._report_counts()

    def _verdict(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id, event = message["id"], message["event"]
        if not self._spend():
            self._throttled += 1
            return protocol.ack(request_id, "deny", reason="throttled", retry_after=1)
        details = event["details"]
        host, port = details.get("host"), details.get("port")
        if not (isinstance(host, str) and port in ALLOWED_PORTS and self._allow.allows(host)):
            blocked = _blocked_from(event, "not_allowed")
            stored = self._append(blocked)
            if stored is None:
                return protocol.ack(request_id, "deny", reason="not_recorded")
            return protocol.ack(request_id, "deny", seq=stored.seq, reason="not_allowed")
        stored = self._append(event)
        if stored is None:
            return protocol.ack(request_id, "deny", reason="not_recorded")
        return protocol.ack(request_id, "allow", seq=stored.seq)

    def _spend(self) -> bool:
        """A token of the bucket and one of the day, or a denial at once (never a wait)."""
        now = self._mono()
        budgets = self._budgets
        if budgets.daily.exhausted(now):
            self._tell_budget(now)
            return False
        if not budgets.bucket.take(now):
            return False
        return budgets.daily.try_spend(now)

    def _tell_budget(self, now: float) -> None:
        window_start = self._budgets.daily.window_start
        if self._budget_told == window_start:
            return
        self._budget_told = window_start
        logger.warning(
            "the agent made %d requests in a day: what it asks now is refused until the day ends",
            self._budgets.daily.limit,
        )
        if self._on_budget is not None:
            try:
                self._on_budget()
            except Exception:
                logger.exception("telling about the daily budget failed")

    def _event(self, event: dict[str, Any]) -> None:
        size = len(json.dumps(event, separators=(",", ":")))
        if not self._budgets.take_event(size, self._mono()):
            self._dropped += 1
            return
        self._append(event)

    def _report_counts(self) -> None:
        now = self._mono()
        if self._throttled and now - self._last_throttled_event >= THROTTLED_EVERY:
            window = max(1, int(now - self._throttled_since))
            count, self._throttled = self._throttled, 0
            self._throttled_since = self._last_throttled_event = now
            self._append(record.throttled_event(count, window))
        if self._dropped and now - self._last_dropped_event >= DROPPED_EVERY:
            count, self._dropped = self._dropped, 0
            self._last_dropped_event = now
            self._append(record.dropped_event(count))

    def _append(self, event: Mapping[str, Any]) -> Event | None:
        """Strike again, then append. None if the black box refused it (logged)."""
        target = self._scrub.text(event["target"])
        details = self._scrub(event["details"])
        try:
            return self._record(
                event["source"], event["action"], target, details=details, risk=event["risk"]
            )
        except (BlackBoxError, ValueError) as error:
            logger.error(
                "cannot record %s/%s from the proxy: %s",
                event["source"],
                event["action"],
                type(error).__name__,
            )
            return None


def _blocked_from(event: Mapping[str, Any], reason: str) -> dict[str, Any]:
    """The ``net/blocked`` of a request backtide refused: what the proxy said of it, without
    its body or model metadata, and the reason."""
    _risk, keys = protocol.EVENT_SCHEMA[("net", "blocked")]
    details = {key: value for key, value in event["details"].items() if key in keys}
    details["reason"] = reason
    return {
        "source": "net",
        "action": "blocked",
        "target": event["target"],
        "risk": BLOCK_RISK[reason],
        "details": details,
    }


def known_secrets(values: Iterable[str | None]) -> tuple[str, ...]:
    """The texts usable as known secrets (long enough for scrub_known), without repeats."""
    return tuple(dict.fromkeys(v for v in values if v and len(v) >= MIN_KNOWN_SECRET))
