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
  not_recorded``. Acks go in the order the requests came. A model call to a provider that waits
  for its key (the owner has not set it, or its file cannot be used) is ``deny no_key``, never
  sent: recorded as ``llm/blocked {reason: no_key}``, the first at once and then at most one
  every ``NO_KEY_EVERY`` s per provider with how many.
- Events that send nothing out (responses, the proxy's own refusals) have their own budgets, by
  count and by bytes, per second and per day: a proxy that the agent makes refuse things in a
  loop cannot fill the disk of the black box. Over them they are counted and a ``net/dropped``
  says how many.
- A request over the budgets is denied at once (``throttled``): the reader never sleeps, so the
  acks of the others never wait behind it.
- ``ping`` every 5 s; ``last_seen`` is when the proxy last said anything (the Guardian's watch
  takes it for down after 15 s of silence).

**The gate** (T10-2, docs/32-diseno-t10-puerta.md, sections 5 to 7). A ``net/request`` comes with
its ``gate`` facts and ``decide.py`` gives its verdict, with what this connection's ``HoldBook``
remembers of its fingerprint. Every ``gate`` event is written here, never by the proxy:

- **pass** (a read, a preapproved fingerprint, a WebSocket to the allowed list): the
  ``net/request`` is appended with ``details.gate = {decision, ...}`` and then ``allow``. A
  preapproval is spent with a ``gate/approved {by: preapproval}`` first.
- **reject**: ``net/blocked`` (``not_allowed``, or ``gate_rejected`` for a fingerprint rejected
  or expired less than 10 min ago) and ``deny``.
- **hold**: ``gate/held`` (risk 2 or 3) and ``ack hold`` with its ``seq``; a request with the same
  fingerprint joins the open hold without a new event. Past 20 open holds: ``deny hold_full``,
  counted in a ``gate/flood``.
- **The person decides** (``decide``, from the control socket): ``gate/approved`` and, with the
  request still connected, its ``net/request`` BEFORE ``decision allow`` (nothing goes out
  without its event); with nobody waiting, a preapproval. ``gate/rejected`` and ``decision
  deny``. ``reject_open`` is the same for a pause or a rewind (``by: pause | rewind``). While
  the agent is paused or rewound (``frozen``, asked under the same lock as ``reject_open``),
  nothing is approved: a request in flight when the pause came is held after it (B2).
- **Time** (a tick every second): ``gate/expired {why: timeout}`` after 5 min, and its deny.
- **The end of the channel** fails closed: every open hold is ``gate/expired`` (``why``:
  ``restart`` when backtide stops, ``proxy_restart`` when the proxy is restarted, else
  ``channel_lost``), and the proxy refuses what it held. Preapprovals and rejections go with this
  connection's fingerprint key (``fp_key``, in the config: never logged, never recorded).
- ``unknown_hosts`` (``Policy``, ``[gate] unknown_hosts``): ``"hold"``, the default since T10-3
  (decision 1), lets reads to any host pass with decision 1's guard and holds the writes;
  ``"deny"``, the optional strict mode, keeps T06's allowed list for whatever is off it.
- **The translators** (T10-3, docs/32 sections 5, 8 and 9): a request a translator read comes
  with its ``reading`` (checked by ``protocol.check_reading``). It decides instead of the method
  (rule 5): a read passes; a send or a change whose recipients are all trusted (``Policy.trusted``,
  ``[gate] trusted``: by default the owner's Telegram chat) passes; the rest is held with its
  reading and the sentence that tells it (``gate/held {reading, phrase}``). A change to a draft
  whose sending is held or preapproved is held (``HoldBook.draft_open``).
- **Batches and the watch** (T10-4, docs/32 sections 10 and 11): a request a batch rule covers
  (``HoldBook.batch_for``; never while a hold of its fingerprint is open, so a yes is never
  spent twice) passes, recorded as its ``net/request`` with ``gate {decision: batch, rule}``.
  ``create_batch`` makes a rule from an open hold (``gate/batch_rule``, risk 2) and approves
  that hold with it; ``end_batch`` revokes one, and time, a pause, a rewind or the end of the
  channel end them (``gate/batch_rule_end {why}``). ``watch`` (the Telegram notice) is told of
  every hold recorded and of every hold that ends, whoever ended it.

**A local provider** (T20, docs/35 sections 6.4 and 6.5): its calls are never held, like any
provider's. Whether a call is local is backtide's own reading (its config says the provider is
local, and the call went to its virtual name), never the proxy's word alone: such a call costs 0
and has its own calls in flight (``Budget.admit(local=True)``).

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import BlackBoxError, Event
from backtide.blackbox.redact import MIN_KNOWN_SECRET, KnownScrubber
from backtide.gate import protocol, record
from backtide.gate.client import SOCKET_NAME
from backtide.gate.decide import UNKNOWN_HOSTS, Facts, ReadingFacts, Verdict, decide
from backtide.gate.fingerprint import new_key, short
from backtide.gate.phrase import describe
from backtide.gate.policy import ALLOWED_PORTS, AllowList
from backtide.gate.protocol import (
    BLOCK_RISK,
    MAX_RECIPIENT_CHARS,
    LineReader,
    ProtocolError,
    Sender,
)
from backtide.gate.provider_tools import FREE_ENDPOINTS, endpoint_of
from backtide.gate.providers import Providers
from backtide.gate.translate.base import (
    OVERRIDE_HEADERS,
    UNKNOWN_OVERRIDE,
    Effect,
    Note,
    Reading,
    Shape,
    Trusted,
    all_trusted,
)
from backtide.sensors.files import DailyBudget, TokenBucket
from backtide.service.holds import (
    BatchKind,
    BatchOutcome,
    BatchRefused,
    BatchRule,
    BatchStatus,
    Hold,
    HoldBook,
    HoldOutcome,
    HoldStatus,
    HoldTimings,
    HoldWatch,
    Scope,
    TrustOutcome,
    TrustStatus,
    plain_scope,
    reading_scope,
    trust_target,
)
from backtide.service.read_budget import DEFAULT_HOST_BYTES, DEFAULT_TOTAL_BYTES, ReadBudget
from backtide.service.spend import Budget
from backtide.service.trust import TrustError, TrustStore

logger = logging.getLogger(__name__)

HELLO_TIMEOUT = 10.0  # seconds the proxy has to say hello once connected
PING_EVERY = 5.0
TICK_EVERY = 1.0  # how often held requests are looked at for their 5 min
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
NO_KEY_EVERY = 10.0  # at most one llm/blocked {reason: no_key} per provider this often
# Why a provider waits when its new key was read but a failed reload could not hand it to the
# proxy (``runner.fail_closed``): not its file's fault, unlike "unusable" (review of 40dfd53).
KEY_NOT_APPLIED = "not_applied"
_CREDENTIALS = struct.Struct("3i")
_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
MAX_REQUESTER_CHARS = 120
DECIDERS = frozenset({"cli", "web", "telegram"})  # who may approve or reject (docs/32, section 7)
# Why the open holds end with the channel: close()'s reason -> gate/expired's why.
_END_WHY = {"stop": "restart", "restart": "proxy_restart"}


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
    # What the gate does with a host off the allowed list ([gate] unknown_hosts): "hold" lets
    # reads pass (with decision 1's guard) and holds writes; "deny" is T06's allowed list, the
    # optional strict mode (decision 1).
    unknown_hosts: str = "hold"
    trusted: tuple[Trusted, ...] = ()  # [gate] trusted (docs/32, section 9), normalized
    read_endpoints: tuple[str, ...] = ()  # [gate] read_endpoints, for the read_post translator
    # [gate] read_budget_host_kib and read_budget_total_kib (review of T10-3, M5), in bytes.
    read_budget_host: int = DEFAULT_HOST_BYTES
    read_budget_total: int = DEFAULT_TOTAL_BYTES
    # Why each provider without its key waits: ("missing", why) for no key file yet,
    # ("unusable", why) for a file that cannot be used, or (KEY_NOT_APPLIED, why) for a key a
    # failed reload could not hand over (``runner.fail_closed``); ``why`` says what the file IS,
    # never what it holds. Only the names ``providers`` has without a key count.
    key_problems: Mapping[str, tuple[str, str]] = field(default_factory=dict)
    # T20 (review of T20-2/3, L2): local providers whose name resolved elsewhere at a reload, and
    # where. Not used (the old address stays until a restart): only recorded and alerted.
    local_moved: Mapping[str, tuple[str, int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.unknown_hosts not in UNKNOWN_HOSTS:
            raise ValueError("unknown_hosts is 'hold' or 'deny'")

    def waiting(self) -> dict[str, str]:
        """The providers that wait for their key, and why ("missing", "unusable" or
        KEY_NOT_APPLIED)."""
        shown = {"unusable", KEY_NOT_APPLIED}
        return {
            name: problem if (problem := self.key_problems.get(name, ("",))[0]) in shown
            else "missing"
            for name in self.providers.waiting()
        }  # fmt: skip

    def key_note(self, name: str) -> str:
        """What is wrong with the key of ``name``, for the log (never a key)."""
        return self.key_problems.get(name, ("", "no key file yet"))[1]

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
        timings: HoldTimings | None = None,
        book: HoldBook | None = None,
        read_budget: ReadBudget | None = None,
        watch: HoldWatch | None = None,
        frozen: Callable[[], bool] | None = None,
        trust: TrustStore | None = None,
        budget: Budget | None = None,
    ) -> None:
        self._sock = sock
        # The spending cap (T11, docs/33): asked before a model call goes out, told what each
        # answer cost. One for the service (the Egress keeps it across channels).
        self._budget = budget
        self._watch = watch
        # The recipients the person trusted from the web (T10-5, decision 9): with [gate]
        # trusted, what a send to trusted recipients only is compared with.
        self._trust = trust
        # Whether the agent is paused or being rewound (the Guardian's): no batch is used then,
        # as no approval is given (security review of T10-4, B4).
        self._frozen: Callable[[], bool] = frozen if frozen is not None else lambda: False
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
        # Model calls refused for want of a key since the last llm/blocked, per provider.
        self._no_key: dict[str, int] = {}
        self._no_key_last: dict[str, float] = {}
        # The gate (T10-2): this connection's fingerprint key and its book of holds. One lock
        # for the book, what is recorded about it and the messages sent for it (the reader,
        # the ticker and the control socket's threads all come here).
        self._fp_key = new_key()
        self._book = book if book is not None else HoldBook(timings, clock=monotonic)
        # What reads to unknown hosts may carry out (M5): the Egress keeps one across channels,
        # so a proxy restart does not refill it.
        self._read_budget = (
            read_budget
            if read_budget is not None
            else ReadBudget(policy.read_budget_host, policy.read_budget_total)
        )
        self._gate_lock = threading.RLock()
        self._holds_ended = False

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
            fp_key=self._fp_key,
            read_endpoints=self._policy.read_endpoints,
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
        self._end_holds(_END_WHY.get(reason, "channel_lost"))
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
        # The refusals for want of a key counted since the last llm/blocked are not lost with
        # the channel (a new key, or a proxy restart, makes a new one).
        for provider in [name for name, count in self._no_key.items() if count]:
            self._record_no_key(provider)

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
            self._end_holds("channel_lost")
            try:  # the proxy sees the end at once (and denies what waits); close() frees the fd
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _ping_loop(self) -> None:
        next_ping = self._mono() + PING_EVERY
        while not self._stop.wait(min(TICK_EVERY, PING_EVERY)):
            try:
                self.tick()
            except Exception:  # the ping goes on: a hold not expired now expires later
                logger.exception("looking at the held requests failed")
            if self._mono() < next_ping:
                continue
            next_ping = self._mono() + PING_EVERY
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
        elif kind == "released":
            with self._gate_lock:
                self._book.released(message["hold_id"])
        elif kind == "hold_left":
            with self._gate_lock:
                self._book.left(message["hold_id"])
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
        if not (isinstance(host, str) and port in ALLOWED_PORTS):
            return self._refuse(request_id, event, "not_allowed")
        allowed = self._allow.allows(host)
        gate = message.get("gate")
        if gate is None:  # a model call (llm/request): never held, only to a provider's host
            if not allowed:
                return self._refuse(request_id, event, "not_allowed")
            waiting = self._waiting_provider(host, details.get("provider"))
            if waiting is not None:
                return self._no_key_refusal(request_id, waiting, details.get("model"))
            return self._model_call(request_id, event)
        with self._gate_lock:
            self._tick_locked()
            return self._gate_verdict(request_id, event, gate, allowed)

    def _gate_verdict(
        self, request_id: int, event: dict[str, Any], gate: dict[str, Any], allowed: bool
    ) -> dict[str, Any]:
        details = event["details"]
        fp = gate["fp"]
        body = details.get("body")
        size = body.get("size") if isinstance(body, dict) else None
        # Decision 1's guard with what backtide knows too: the proxy never sees the Gateway
        # token, so a URL (or a header value the recording keeps) that carried it is only
        # struck here. And a method override header that the recording names makes it a write,
        # whatever the proxy said (security review of T10-2, M2 and M3).
        path, host = details.get("path"), details.get("host")
        struck_here = not isinstance(path, str) or self._scrub.text(path) != path
        struck_here |= isinstance(host, str) and self._scrub.text(host) != host  # a name too
        headers = details.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        overridden = any(str(name).strip().lower() in OVERRIDE_HEADERS for name in headers)
        # What the proxy read of the override headers; a name the recording keeps that the
        # proxy did not report still counts, unread (security review of T10-4, A1).
        override = gate["override"]
        if override is None and overridden:
            override = UNKNOWN_OVERRIDE
        headers_struck_here = any(
            isinstance(value, str) and self._scrub.text(value) != value
            for value in headers.values()
        ) or any(self._scrub.text(str(name)) != str(name) for name in headers)  # a name too
        reading = gate["reading"]
        method = str(details.get("method", ""))
        # A batch is looked up only when no hold of this fingerprint is open (the request then
        # joins it, so the waiting one and this one never both go out: T10-4) and never while
        # the agent is paused or being rewound, as an approval (security review of T10-4, B4).
        scope = self._scope(details, gate, override, risk=2, reason="write", allowed=allowed)
        # The same holds for trust (final review of T10, finding 1): a retry of a request that
        # is held joins its hold even when its recipient was trusted meanwhile, so the hold is
        # decided on its own and the black box never says both "held" and "out".
        joins = self._book.live(fp) is not None
        rule = None
        if scope is not None and not joins and not self._frozen():
            rule = self._book.batch_for(scope)
        facts = Facts(
            method=method,
            exact_read=gate["exact_read"] and not overridden,
            has_body=not (type(size) is int and size == 0),  # unknown: a body (fails closed)
            url_bytes=gate["url_bytes"],
            url_struck=gate["url_struck"] or struck_here,
            headers_struck=gate["headers_struck"] or headers_struck_here,
            header_bytes=gate["header_bytes"],
            websocket=gate["websocket"],
            allowed=allowed,
            preapproved=self._book.preapproved(fp),
            rejected=self._book.rejected(fp),
            credential_bytes=gate["credential_bytes"],
            credentials_struck=gate["credentials_struck"],
            body_struck=gate["body_struck"],
            reading=None if reading is None else self._reading_facts(reading, rule, joins=joins),
            batch=None if reading is not None or rule is None else rule.rule_id,
            override=override,
            trailers=gate["trailers"],
        )
        decision = decide(facts, unknown_hosts=self._policy.unknown_hosts)
        if decision.verdict is Verdict.PASS and decision.reason == "read" and not allowed:
            # M5: what a read to an unknown host carries out (its URL and its headers but the
            # credentials, which are held there anyway) is counted per host and in total.
            spent = gate["url_bytes"] + gate["header_bytes"]
            if not self._read_budget.take(str(host).lower(), spent, self._mono()):
                return self._hold(request_id, event, gate, 2, "read_budget")
        if decision.verdict is Verdict.REJECT:
            return self._refuse(request_id, event, decision.reason, fp=fp)
        if decision.verdict is Verdict.PASS:
            note: dict[str, Any] = {"decision": decision.reason}
            if reading is not None:
                note |= {key: reading[key] for key in ("translator", "operation", "effect")}
            if decision.reason == "batch" and rule is not None and scope is not None:
                self._book.batch_for(scope, use=True)
                note["rule"] = rule.rule_id
            if decision.reason == "preapproved":
                hold = self._book.spend(fp)
                if hold is None:  # cannot be: preapproved() said so under this same lock
                    return protocol.ack(request_id, "deny", reason="not_recorded")
                approved = self._gate_event(
                    "approved", hold, {"by": "preapproval"}, risk=1, target=event["target"]
                )
                if approved is None:
                    return protocol.ack(request_id, "deny", reason="not_recorded")
                note["hold_id"] = hold.hold_id
            return self._let_out(request_id, event, note)
        return self._hold(request_id, event, gate, decision.risk, decision.reason)

    def _reading_facts(
        self, reading: Mapping[str, Any], rule: BatchRule | None = None, *, joins: bool = False
    ) -> ReadingFacts:
        """What decide.py needs of a checked reading: its effect and risk, whether all its
        recipients are trusted (never a cut one: a recipient may be missing; never one that
        ``joins`` an open hold of its fingerprint), whether it changes a draft whose sending is
        held or preapproved, and the batch rule that covers it (``rule``, looked up by the
        caller). No owner account is configured yet (docs/32, approved decision 4), so a
        mail recipient is never trusted here (final review of T10, finding 2)."""
        effect = Effect(reading["effect"])
        trusted = (
            not joins and not reading["cut"] and all_trusted(_as_reading(reading), self._trusted())
        )
        key = _draft_key(reading)
        changes_draft = key is not None and effect in (Effect.READ, Effect.CHANGE)
        return ReadingFacts(
            effect=effect,
            risk=reading["risk"],
            trusted=trusted,
            draft_open=changes_draft and key is not None and self._book.draft_open(key),
            batch=None if rule is None else rule.rule_id,
        )

    def _trusted(self) -> tuple[Trusted, ...]:
        """``[gate] trusted`` and the recipients trusted from the web (T10-5)."""
        extra = () if self._trust is None else self._trust.entries()
        return (*self._policy.trusted, *extra)

    def _scope(
        self,
        details: Mapping[str, Any],
        gate: Mapping[str, Any],
        override: str | None,
        *,
        risk: int,
        reason: str,
        allowed: bool,
    ) -> Scope | None:
        """What the request is, for the batches (``holds.Scope``): from its reading, or from
        its method, host, route and credential headers; with the connection's scheme and port.
        Nothing with an override header or trailers is batchable, nor a plain write whose
        credential headers carry a token the redaction recognises toward a host off the allowed
        list (security review of T10-4, A1 and M1; toward a listed API that token is the
        agent's own, as for the reads of T10-3, H1)."""
        scheme = details.get("scheme") if isinstance(details.get("scheme"), str) else None
        port = details.get("port") if type(details.get("port")) is int else None
        batchable = override is None and not gate["trailers"]
        reading = gate["reading"]
        if reading is not None:
            return reading_scope(reading, risk=risk, scheme=scheme, port=port, batchable=batchable)
        path, host = details.get("path"), details.get("host")
        if not (isinstance(path, str) and isinstance(host, str)):
            return None
        return plain_scope(
            str(details.get("method", "")),
            host,
            path,
            risk=risk,
            reason=reason if batchable else "override",
            scheme=scheme,
            port=port,
            credential=gate["credential_id"],
            credentials_struck=gate["credentials_struck"] and not allowed,
        )

    def _hold(
        self, request_id: int, event: dict[str, Any], gate: dict[str, Any], risk: int, reason: str
    ) -> dict[str, Any]:
        fp = gate["fp"]
        if self._holds_ended:  # backtide is stopping: no hold would ever be closed
            return protocol.ack(request_id, "deny", reason="not_recorded")
        hold = self._book.live(fp)
        reading = gate["reading"]
        if hold is not None:  # the same request again: it joins, without a new event
            self._book.join(hold, event)
        else:
            draft = None if reading is None else _draft_key(reading)
            override = gate["override"]
            headers = event["details"].get("headers")
            if override is None and isinstance(headers, dict):
                if any(str(name).strip().lower() in OVERRIDE_HEADERS for name in headers):
                    override = UNKNOWN_OVERRIDE
            host_ = event["details"].get("host")
            allowed = isinstance(host_, str) and self._allow.allows(host_)
            scope = self._scope(
                event["details"], gate, override, risk=risk, reason=reason, allowed=allowed
            )
            hold = self._book.open(
                fp, risk=risk, reason=reason, event=event, draft=draft, scope=scope
            )
            if hold is None:  # too many open: counted in the next gate/flood
                return protocol.ack(request_id, "deny", reason="hold_full")
            extra: dict[str, Any] = {"reason": reason, "expires_at": hold.expires_at}
            if reading is not None:
                hold.phrase = self._scrub.text(describe(reading))
                extra |= {"reading": _recorded_reading(reading), "phrase": hold.phrase}
            stored = self._gate_event("held", hold, extra, risk=risk, request=event["details"])
            if stored is None:
                self._book.discard(hold)
                return protocol.ack(request_id, "deny", reason="not_recorded")
            self._book.recorded(hold, stored.seq)
            if reading is not None:
                hold.reading = _recorded_reading(reading)
            self._tell_held(hold)
        if hold.seq is None:  # cannot be: a hold is only kept once its gate/held is stored
            return protocol.ack(request_id, "deny", reason="not_recorded")
        return protocol.ack(
            request_id,
            "hold",
            seq=hold.seq,
            hold_id=hold.hold_id,
            wait_ms=self._book.wait_ms(hold, _wait_hint(gate)),
            retry_after=_retry_after(self._book.timings, reading),
        )

    def _let_out(
        self, request_id: int, event: dict[str, Any], note: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Append the request's own event (with ``details.gate``, the rule that let it pass)
        and only then ``allow`` with its seq."""
        stored = self._append(event, None if note is None else {"gate": note})
        if stored is None:
            return protocol.ack(request_id, "deny", reason="not_recorded")
        return protocol.ack(request_id, "allow", seq=stored.seq)

    def _waiting_provider(self, host: str, named: object) -> str | None:
        """The provider without its key this model call goes to, by backtide's own reading of
        the host (and, failing closed, by the name the proxy gives), if any."""
        providers = self._policy.providers
        for provider in (providers.for_host(host), providers.by_name(named)):
            if provider is not None and provider.waiting:
                return provider.name
        return None

    def _no_key_refusal(self, request_id: int, provider: str, model: object) -> dict[str, Any]:
        """``deny no_key``: the call never reaches the provider. Recorded as ``llm/blocked``, the
        first at once and then at most one every NO_KEY_EVERY s with how many."""
        self._no_key[provider] = self._no_key.get(provider, 0) + 1
        if self._mono() - self._no_key_last.get(provider, float("-inf")) >= NO_KEY_EVERY:
            self._record_no_key(provider, model)
        return protocol.ack(request_id, "deny", reason="no_key")

    def _record_no_key(self, provider: str, model: object = None) -> None:
        count = self._no_key.pop(provider, 0)
        self._no_key_last[provider] = self._mono()
        details: dict[str, Any] = {
            "reason": "no_key",
            "provider": provider,
            "problem": self._policy.waiting().get(provider, "missing"),
            "count": count,
        }
        if isinstance(model, str):
            details["model"] = model[:128]
        event = {"source": "llm", "action": "blocked", "target": provider, "risk": 1,
                 "details": details}  # fmt: skip
        self._append(event)  # a refusal: nothing goes out whether or not it is recorded

    def _flush_no_key(self) -> None:
        now = self._mono()
        for provider in [name for name, count in self._no_key.items() if count]:
            if now - self._no_key_last.get(provider, float("-inf")) >= NO_KEY_EVERY:
                self._record_no_key(provider)

    def _model_call(self, request_id: int, event: dict[str, Any]) -> dict[str, Any]:
        """An ``llm/request`` to an allowed provider: the spending cap first (T11). A refusal
        never reaches the provider; ``Budget.admit`` records it (``llm/blocked``)."""
        if self._budget is None:
            return self._let_out(request_id, event)
        details = event["details"]
        flow_id = details.get("flow_id")
        body = details.get("body")
        try:
            why = self._budget.admit(
                flow_id,
                model=details.get("model"),
                request_bytes=body.get("size") if isinstance(body, dict) else None,
                max_tokens=details.get("max_tokens"),
                choices=details.get("choices"),
                context=details.get("context") is True,
                service_tier=details.get("service_tier"),
                free=self._free_call(details),
                local=self._local_call(details),
            )
        except Exception:  # without a count nothing goes out
            logger.exception("the spending cap could not be asked: the model call is refused")
            why = "spend_unavailable"
        if why == "throttled":
            self._throttled += 1
            return protocol.ack(request_id, "deny", reason="throttled", retry_after=2)
        if why is not None:
            return protocol.ack(request_id, "deny", reason=why)
        ack = self._let_out(request_id, event)
        if ack["verdict"] != "allow":
            self._budget.forget(flow_id)  # never sent: it costs nothing
        return ack

    def _kind(self, details: Mapping[str, Any]) -> str:
        provider = self._policy.providers.by_name(details.get("provider"))
        return str(provider.kind) if provider is not None else "anthropic"

    def _local_call(self, details: Mapping[str, Any]) -> bool:
        """T20: whether this model call is to a local provider, by backtide's own config: the
        provider it names is local and, when the event says its host (an ``llm/request``), that
        host is exactly its virtual name."""
        provider = self._policy.providers.by_name(details.get("provider"))
        if provider is None or not provider.local:
            return False
        return "host" not in details or details.get("host") == provider.host

    def _free_call(self, details: Mapping[str, Any]) -> bool:
        """M4: the list of models or Anthropic's token count, which the providers do not bill:
        only when what the proxy says (``endpoint``) is what backtide reads of the recorded
        method and path itself."""
        said = details.get("endpoint")
        if said not in FREE_ENDPOINTS:
            return False
        method, path = details.get("method"), details.get("path")
        if not (isinstance(method, str) and isinstance(path, str)):
            return False
        provider = self._policy.providers.by_name(details.get("provider"))
        exact = provider is not None and provider.exact_paths
        models = provider.models if provider is not None else ()
        found = endpoint_of(self._kind(details), method, path, exact=exact, models=models)
        return found == said

    def _charge(self, event: dict[str, Any]) -> None:
        """An ``llm/response``: priced, recorded with its cost, then added to the spending (also
        when the event cannot be recorded or is over the event budget: the money was spent).
        A call let out that ends without an answer is charged its estimate (M1): a ``net/error``
        unless the proxy says it never reached the provider (``upstream: false``), and the
        proxy's ``net/blocked`` of an answer (``side: response``); a ``net/blocked`` of a request
        the proxy refused before sending frees it."""
        details = event["details"]
        budget = self._budget
        if budget is None:  # cannot be: _event only comes here with a budget
            self._event_plain(event)
            return
        if event["source"] == "llm" and event["action"] == "response":
            try:
                cost = budget.settle(self._kind(details), details, local=self._local_call(details))
            except Exception:  # B2: never fail open, never uncharged
                logger.exception("pricing a model answer failed: it is charged its estimate")
                cost = budget.fallback_cost(details)
            size = len(json.dumps(event, separators=(",", ":")))
            stored = None
            if self._budgets.take_event(size, self._mono()):
                stored = self._append(event, {"cost": cost.details()})
            else:
                self._dropped += 1
            budget.book_cost(cost, stored)
            return
        stored = self._event_plain(event)
        if event["source"] != "net" or event["action"] not in ("error", "blocked"):
            return
        flow_id = details.get("flow_id")
        if event["action"] == "error" and details.get("upstream") is False:
            budget.forget(flow_id)
        elif event["action"] == "error" or details.get("side") == "response":
            budget.charge_unanswered(flow_id, why=str(event["action"]), cause=stored)
        else:
            budget.forget(flow_id)  # the proxy refused the request itself: it never went out

    def _refuse(
        self, request_id: int, event: dict[str, Any], reason: str, *, fp: str | None = None
    ) -> dict[str, Any]:
        blocked = _blocked_from(event, reason)
        if fp is not None and reason == "gate_rejected":
            blocked["details"]["fp"] = short(fp)  # joins it to the hold that was rejected
        stored = self._append(blocked)
        if stored is None:
            return protocol.ack(request_id, "deny", reason="not_recorded")
        return protocol.ack(request_id, "deny", seq=stored.seq, reason=reason)

    # The person's decisions, time and the end (T10-2)

    def decide(
        self,
        hold_id: str,
        verdict: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> HoldOutcome:
        """Approve (``verdict="approve"``) or reject an open hold. ``by`` is who decided
        (``DECIDERS``), ``requested_by`` the kernel's uid and pid of whoever asked. ``frozen``
        says whether the agent is paused or being rewound: then nothing is approved (PAUSED),
        and a no still goes. Never raises for a hold that is not there: the outcome says so."""
        if verdict not in {"approve", "reject"} or by not in DECIDERS:
            raise ValueError("verdict is approve or reject; by is cli, web or telegram")
        who = {"by": by, "requested_by": str(requested_by)[:MAX_REQUESTER_CHARS]}
        with self._gate_lock:
            if self.closed:
                return HoldOutcome(HoldStatus.UNKNOWN, hold_id)
            self._tick_locked()
            if verdict == "reject":
                hold = self._book.reject(hold_id)
                if hold is None:
                    return HoldOutcome(HoldStatus.UNKNOWN, hold_id)
                self._gate_event("rejected", hold, who, risk=1)  # a no is good unrecorded too
                if hold.connected:
                    self._tell_decision(protocol.decision(hold_id, "deny", reason="rejected"))
                self._tell_closed(hold, "rejected", by)
                return HoldOutcome(HoldStatus.REJECTED, hold_id)
            hold = self._book.approve(hold_id)
            if hold is None:
                return HoldOutcome(HoldStatus.UNKNOWN, hold_id)
            # Under the lock reject_open takes too: a pause that came first is seen here.
            if frozen is not None and frozen():
                return HoldOutcome(HoldStatus.PAUSED, hold_id)  # still open, nothing recorded
            return self._approve(hold, who)

    def _approve(self, hold: Hold, who: Mapping[str, Any]) -> HoldOutcome:
        """Approve the open ``hold`` (under the gate lock): ``gate/approved``, then, with the
        request still connected, its net/request BEFORE ``decision allow``; else a
        preapproval."""
        hold_id, by = hold.hold_id, str(who["by"])
        if self._gate_event("approved", hold, who, risk=1) is None:
            return HoldOutcome(HoldStatus.FAILED, hold_id)  # still open: nothing went out
        if hold.connected:
            # Recorded BEFORE it goes out, as every request: its net/request, then allow.
            note = {"decision": "approved", "hold_id": hold_id, "by": by}
            stored = self._append(hold.event, {"gate": note})
            if stored is not None:
                self._book.release(hold)
                self._tell_decision(protocol.decision(hold_id, "allow", seq=stored.seq))
                self._tell_closed(hold, "released", by)
                return HoldOutcome(HoldStatus.RELEASED, hold_id)
        # Nobody waits (or its net/request could not be recorded): the next identical
        # request passes once, recorded then, within 10 min.
        self._book.preapprove(hold)
        self._tell_closed(hold, "preapproved", by)
        return HoldOutcome(HoldStatus.PREAPPROVED, hold_id)

    # Batches (T10-4)

    def create_batch(
        self,
        hold_id: str,
        kind: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> BatchOutcome:
        """Make a batch rule of ``kind`` ("recipient" or "kind") from the open hold
        ``hold_id`` and approve that hold with it: ``gate/batch_rule`` first, then the yes as
        ``decide`` gives it. Nothing while the agent is paused or rewound (``frozen``). Never
        raises for a hold that is not there."""
        if by not in DECIDERS:
            raise ValueError("by is cli, web or telegram")
        batch_kind = BatchKind(kind)
        who = {"by": by, "requested_by": str(requested_by)[:MAX_REQUESTER_CHARS]}
        with self._gate_lock:
            if self.closed:
                return BatchOutcome(BatchStatus.UNKNOWN, hold_id)
            self._tick_locked()
            hold = self._book.approve(hold_id)
            if hold is None:
                return BatchOutcome(BatchStatus.UNKNOWN, hold_id)
            if frozen is not None and frozen():
                return BatchOutcome(BatchStatus.PAUSED, hold_id)
            made = self._book.add_batch(hold, batch_kind)
            if isinstance(made, BatchRefused):
                status = {BatchRefused.FULL: BatchStatus.FULL,
                          BatchRefused.NOT_OPEN: BatchStatus.UNKNOWN}.get(
                              made, BatchStatus.NOT_BATCHABLE)  # fmt: skip
                return BatchOutcome(status, hold_id)
            if made.hold_id == hold_id:  # a new rule (an equal one already there is not recorded)
                own = {"rule_id": made.rule_id, "scope": str(made.kind),
                       "until": made.until_at, **who} | _rule_fields(made)  # fmt: skip
                if self._gate_event("batch_rule", hold, own, risk=2) is None:
                    self._book.drop_batch(made)
                    return BatchOutcome(BatchStatus.FAILED, hold_id)
            outcome = self._approve(hold, who)
            return BatchOutcome(BatchStatus.CREATED, hold_id, made.rule_id, outcome.status)

    def batches(self) -> list[dict[str, Any]]:
        """The active batch rules, oldest first: what ``/lotes`` shows."""
        with self._gate_lock:
            if self.closed:
                return []
            self._tick_locked()
            now = self._mono()
            return [self._scrub(_rule_summary(rule, now)) for rule in self._book.batches()]

    def end_batch(self, rule_id: str, *, by: str) -> bool:
        """Revoke the batch rule ``rule_id`` (``gate/batch_rule_end {why: revoked}``). False
        if there is no such active rule."""
        with self._gate_lock:
            if self.closed:
                return False
            rule = self._book.end_batch(rule_id)
            if rule is None:
                return False
            self._batch_ended(rule, "revoked", by=by)
            return True

    def _batch_ended(self, rule: BatchRule, why: str, *, by: str | None = None) -> None:
        own: dict[str, Any] = {"rule_id": rule.rule_id, "why": why, "uses": rule.uses}
        if by is not None:
            own["by"] = by
        self._record_gate("batch_rule_end", rule.rule_id, own, risk=0)

    def pending(self) -> list[dict[str, Any]]:
        """The holds waiting for the person, oldest first: what the person needs to decide
        (the request as it was recorded, struck), never its body. Since T10-5 also what the
        web shows (``_web_fields``: the gate/held's seq, when, the reading cut short, which
        batches it may make and whether it may make a trusted recipient)."""
        with self._gate_lock:
            if self.closed:
                return []
            self._tick_locked()
            now = self._mono()
            return [
                self._scrub(_summary(hold, now) | self._web_fields(hold))
                for hold in self._book.pending()
            ]

    def _web_fields(self, hold: Hold) -> dict[str, Any]:
        return {
            "seq": hold.seq,
            "held_at": hold.held_at,
            "expires_at": hold.expires_at,
            "batches": [str(kind) for kind in self._book.offers(hold)],
            "trustable": trust_target(hold) is not None,
            "view": _view(hold.reading),
        }

    # "Aprobar y confiar en este destinatario" (T10-5, decision 9)

    def trust(
        self,
        hold_id: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> TrustOutcome:
        """Trust the one recipient of the open hold ``hold_id`` from now on (``gate/trust_added``
        recorded, then saved in the ``TrustStore``) and approve that hold, as ``decide`` does.
        Only for what ``holds.trust_target`` allows; nothing while the agent is paused or
        rewound. Never raises for a hold that is not there."""
        if by not in DECIDERS:
            raise ValueError("by is cli, web or telegram")
        who = {"by": by, "requested_by": str(requested_by)[:MAX_REQUESTER_CHARS]}
        with self._gate_lock:
            if self.closed:
                return TrustOutcome(TrustStatus.UNKNOWN, hold_id)
            self._tick_locked()
            hold = self._book.approve(hold_id)
            if hold is None:
                return TrustOutcome(TrustStatus.UNKNOWN, hold_id)
            if frozen is not None and frozen():
                return TrustOutcome(TrustStatus.PAUSED, hold_id)
            target = trust_target(hold)
            if target is None or self._trust is None:
                return TrustOutcome(TrustStatus.NOT_TRUSTABLE, hold_id)
            translator, recipient = target
            try:
                entry, new = self._trust.prepare(translator, recipient, by=by, hold_id=hold_id)
            except TrustError as error:
                return TrustOutcome(TrustStatus.FAILED, hold_id, detail=str(error))
            except ValueError:
                return TrustOutcome(TrustStatus.NOT_TRUSTABLE, hold_id)
            if new:
                # Two phases (final review of T10, finding 6): recorded first, then saved and
                # used; a trust that could not be saved is recorded as failed and never used.
                own = {"trust_id": entry.trust_id, "translator": translator,
                       "recipient": recipient, **who}  # fmt: skip
                if self._gate_event("trust_added", hold, own, risk=2) is None:
                    return TrustOutcome(TrustStatus.FAILED, hold_id)  # nothing saved nor used
                try:
                    self._trust.commit(entry)
                except TrustError as error:
                    failed = {"trust_id": entry.trust_id, "why": "not_saved", **who}
                    if self._gate_event("trust_failed", hold, failed, risk=2) is None:
                        logger.error("a trust that could not be saved could not be recorded")
                    return TrustOutcome(TrustStatus.FAILED, hold_id, detail=str(error))
            outcome = self._approve(hold, who)
            return TrustOutcome(TrustStatus.TRUSTED, hold_id, entry.trust_id, outcome.status)

    def reject_open(self, by: str) -> int:
        """A pause (``by="pause"``) or a rewind (``"rewind"``): every open hold is rejected
        (decision 7), and a yes being released never becomes a preapproval. Returns how many
        were rejected."""
        with self._gate_lock:
            if self.closed:
                return 0
            try:
                holds = self._book.reject_open()
                reason = "paused" if by == "pause" else "rejected"
                for hold in holds:
                    self._gate_event("rejected", hold, {"by": by}, risk=1)
                    if hold.connected:
                        self._tell_decision(protocol.decision(hold.hold_id, "deny", reason=reason))
                    self._tell_closed(hold, "rejected", by)
            finally:
                # A batch is leave too: a pause or a rewind ends every one (T10-4), even when
                # rejecting the holds failed half way (security review of T10-4, B4).
                self.end_batches(by)
            return len(holds)

    def end_batches(self, why: str) -> int:
        """End every batch rule now (``gate/batch_rule_end {why}``). Never raises for a rule
        whose end cannot be recorded: it is gone all the same."""
        with self._gate_lock:
            ended = self._book.end_batches()
            for rule in ended:
                try:
                    self._batch_ended(rule, why)
                except Exception:
                    logger.exception("recording the end of a batch rule failed")
            return len(ended)

    def tick(self) -> None:
        """The holds whose 5 min are over, and the flood count (every TICK_EVERY s)."""
        with self._gate_lock:
            if not self.closed:
                self._tick_locked()

    def _tick_locked(self) -> None:
        for hold in self._book.due():
            self._gate_event("expired", hold, {"why": "timeout"}, risk=2)
            if hold.connected:
                self._tell_decision(protocol.decision(hold.hold_id, "deny", reason="expired"))
            self._tell_closed(hold, "expired", "timeout")
        for rule in self._book.due_batches():
            self._batch_ended(rule, "expired")
        flood = self._book.flood()
        if flood is not None:
            count, window = flood
            self._record_gate("flood", "", {"count": count, "window_s": window}, risk=2)

    def end_holds(self, reason: str) -> None:
        """End every open hold now, as ``close(reason)`` would, while the channel is still
        open: ``Egress.stop`` calls it before it stops the proxy, so a clean stop is recorded as
        ``restart`` and not as the lost channel the reader would see first. From then on nothing
        is held (``not_recorded``) nor approved; the proxy refuses what it holds when the
        channel ends."""
        self._end_holds(_END_WHY.get(reason, "channel_lost"))

    def _end_holds(self, why: str) -> None:
        """The channel ends: every open hold is expired with ``why`` (the proxy refuses what it
        held), and the leave of this connection is forgotten. Once."""
        with self._gate_lock:
            if self._holds_ended:
                return
            self._holds_ended = True
            for hold in self._book.close_all():
                self._gate_event("expired", hold, {"why": why}, risk=2)
                self._tell_closed(hold, "expired", why)
            for rule in self._book.end_batches():
                self._batch_ended(rule, why)

    def _tell_held(self, hold: Hold) -> None:
        if self._watch is None:
            return
        try:
            self._watch.held(self._scrub(self._notice(hold)))
        except Exception:  # the hold stands; only its notice is missing
            logger.exception("telling about a held request failed")

    def _tell_closed(self, hold: Hold, status: str, by: str | None) -> None:
        if self._watch is None:
            return
        try:
            self._watch.closed(hold.hold_id, status, by)
        except Exception:
            logger.exception("telling about the end of a held request failed")

    def _notice(self, hold: Hold) -> dict[str, Any]:
        """What the notice of ``hold`` shows (T10-4): its summary, the reading as recorded,
        the gate/held's seq ("Ver" reads the excerpt there) and the batches it may make."""
        return _summary(hold, self._mono()) | {
            "seq": hold.seq,
            "reading": hold.reading,
            "batches": [str(kind) for kind in self._book.offers(hold)],
        }

    def _tell_decision(self, message: dict[str, Any]) -> None:
        try:
            self._send(protocol.encode(message, Sender.BACKTIDE))
        except OSError as error:
            # The channel broke: the proxy refuses what it holds, and the reader ends the holds.
            logger.warning("cannot tell the proxy a decision (%s)", type(error).__name__)
            self._broken("broken")

    def _gate_event(
        self,
        action: str,
        hold: Hold,
        extra: Mapping[str, Any],
        *,
        risk: int,
        target: str | None = None,
        request: Mapping[str, Any] | None = None,
    ) -> Event | None:
        own = {**extra, "hold_id": hold.hold_id, "fp": short(hold.fp)}
        where = target if target is not None else hold.event["target"]
        return self._record_gate(action, where, own, risk=risk, request=request)

    def _record_gate(
        self,
        action: str,
        target: str,
        own: Mapping[str, Any],
        *,
        risk: int,
        request: Mapping[str, Any] | None = None,
    ) -> Event | None:
        """A ``gate`` event, written by backtide (never the proxy), struck like the rest:
        ``request`` (what the proxy said of the request) whole, ``own`` (backtide's fields) in
        its values."""
        event = {"source": "gate", "action": action, "target": target, "risk": risk,
                 "details": dict(request or {})}  # fmt: skip
        return self._append(event, own)

    def _spend(self) -> bool:
        """A token of the bucket and one of the day, or a denial at once (never a wait)."""
        now = self._mono()
        budgets = self._budgets
        if budgets.daily.exhausted(now):
            self._tell_budget()
            return False
        if not budgets.bucket.take(now):
            return False
        return budgets.daily.try_spend(now)

    def _tell_budget(self) -> None:
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
        if self._budget is not None:
            self._charge(event)
            return
        self._event_plain(event)

    def _event_plain(self, event: dict[str, Any]) -> Event | None:
        size = len(json.dumps(event, separators=(",", ":")))
        if not self._budgets.take_event(size, self._mono()):
            self._dropped += 1
            return None
        return self._append(event)

    def _report_counts(self) -> None:
        now = self._mono()
        if self._budget is not None:
            self._budget.flush_blocked()
        if self._no_key:
            self._flush_no_key()
        if self._throttled and now - self._last_throttled_event >= THROTTLED_EVERY:
            window = max(1, int(now - self._throttled_since))
            count, self._throttled = self._throttled, 0
            self._throttled_since = self._last_throttled_event = now
            self._append(record.throttled_event(count, window))
        if self._dropped and now - self._last_dropped_event >= DROPPED_EVERY:
            count, self._dropped = self._dropped, 0
            self._last_dropped_event = now
            self._append(record.dropped_event(count))

    def _append(
        self, event: Mapping[str, Any], own: Mapping[str, Any] | None = None
    ) -> Event | None:
        """Strike again, then append. ``own``: details of backtide's own (the gate's), whose
        names are ours and are not struck (a short name can look like the start of a secret to
        ``cut_tails``), only their values. None if the black box refused it (logged)."""
        target = self._scrub.text(event["target"])
        details = self._scrub(event["details"])
        if own:
            details |= {name: self._scrub(value) for name, value in own.items()}
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


def _as_reading(reading: Mapping[str, Any]) -> Reading:
    """A checked ``gate.reading`` as the translators' Reading (for ``all_trusted``)."""
    return Reading(
        translator=reading["translator"],
        operation=reading["operation"],
        effect=Effect(reading["effect"]),
        shape=Shape(reading["shape"]),
        wait_s=reading["wait_s"],
        account=reading["account"],
        recipients=tuple(reading["recipients"]),
        reply_to=tuple(reading["reply_to"]),
        secret_seen=reading["secret_seen"],
        notes=tuple(Note(note) for note in reading["notes"]),
    )


def _wait_hint(gate: Mapping[str, Any]) -> int | None:
    """How long the request's client waits: the least of the proxy's hint and its reading's
    ``wait_s`` (decision 3: Telegram 50 s, Discord 10 s, gog 25 s...)."""
    hints = [gate["wait_hint_s"], None if gate["reading"] is None else gate["reading"]["wait_s"]]
    known = [hint for hint in hints if hint is not None]
    return min(known) if known else None


def _retry_after(timings: HoldTimings, reading: Mapping[str, Any] | None) -> int:
    """The Retry-After of "pending": shorter for Telegram (T10-5, docs/32 section 16), whose
    OpenClaw channel stops the whole bot for that long."""
    if reading is not None and reading.get("translator") == "telegram":
        return min(timings.retry_after, timings.telegram_retry_after)
    return timings.retry_after


def _draft_key(reading: Mapping[str, Any]) -> tuple[str, str] | None:
    """A draft by its translator and its ``draft`` (already a digest of the mailbox and the
    draft's id, ``base.draft_ref``), never by the token that acts: a refreshed token is the same
    draft (review of T10-3, M7)."""
    draft = reading.get("draft")
    return None if draft is None else (reading["translator"], draft)


_RECORDED_READING = (
    "translator", "operation", "effect", "recipients", "sender", "reply_to", "subject",
    "first_lines", "target", "attachments", "secret_seen", "notes", "draft", "cut",
)  # fmt: skip


def _recorded_reading(reading: Mapping[str, Any]) -> dict[str, Any]:
    """What ``gate/held`` keeps of a reading (docs/32, section 7): what it does and to whom,
    the struck texts and the attachments; not the account's HMAC (it is of this connection's
    key, worthless after it) nor the proxy's mechanics (wait, shape)."""
    return {key: reading[key] for key in _RECORDED_READING}


def _rule_fields(rule: BatchRule) -> dict[str, Any]:
    """What a batch rule covers, for the black box and ``/lotes``: never the account's HMAC
    (it is of this connection's key)."""
    scope = rule.scope
    if scope.translator is None:
        return {"method": scope.method, "host": scope.host, "route": scope.route}
    fields: dict[str, Any] = {"translator": scope.translator, "effect": scope.effect}
    if rule.kind is BatchKind.RECIPIENT:
        fields["recipients"] = sorted(scope.recipients)
    return fields


def _rule_summary(rule: BatchRule, now: float) -> dict[str, Any]:
    return {"rule_id": rule.rule_id, "scope": str(rule.kind), "hold_id": rule.hold_id,
            "until": rule.until_at, "left_s": max(0, int(rule.until - now)),
            "uses": rule.uses} | _rule_fields(rule)  # fmt: skip


def _summary(hold: Hold, now: float) -> dict[str, Any]:
    details = hold.event.get("details") or {}
    return {
        "hold_id": hold.hold_id,
        "risk": hold.risk,
        "reason": hold.reason,
        "phrase": hold.phrase,
        "method": details.get("method"),
        "host": details.get("host"),
        "path": details.get("path"),
        "target": hold.event.get("target"),
        "expires_in_s": max(0, int(hold.expires - now)),
        "waiting": hold.connected > 0,
    }


VIEW_RECIPIENTS = 5
VIEW_ATTACHMENTS = 5


def _view(reading: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """What the web shows of a recorded reading, cut short (the control socket's reply has a
    size): the agent's texts stay the agent's (the web marks and escapes them)."""
    if reading is None:
        return None

    def cut(value: object, limit: int) -> str | None:
        return str(value)[:limit] if value else None

    # Whole (a checked recipient is at most MAX_RECIPIENT_CHARS): the web cuts them in the
    # middle, keeping the domain, and marks the cut (final review of T10, finding 4).
    recipients = [str(item)[:MAX_RECIPIENT_CHARS] for item in reading.get("recipients") or []]
    reply_to = [str(item)[:MAX_RECIPIENT_CHARS] for item in reading.get("reply_to") or []]
    attachments = [
        {"name": str(item.get("name") or "")[:100], "size": item.get("size")}
        for item in reading.get("attachments") or []
        if isinstance(item, Mapping)
    ]
    return {
        "translator": reading.get("translator"),
        "effect": reading.get("effect"),
        "notes": list(reading.get("notes") or []),
        "cut": reading.get("cut") is True,
        "recipients": recipients[:VIEW_RECIPIENTS],
        "recipients_total": len(recipients),
        "reply_to": reply_to[:VIEW_RECIPIENTS],
        "subject": cut(reading.get("subject"), 200),
        "first_lines": cut(reading.get("first_lines"), 300),
        "target": cut(reading.get("target"), 200),
        "attachments": attachments[:VIEW_ATTACHMENTS],
        "attachments_total": len(attachments),
    }


def known_secrets(values: Iterable[str | None]) -> tuple[str, ...]:
    """The texts usable as known secrets (long enough for scrub_known), without repeats."""
    return tuple(dict.fromkeys(v for v in values if v and len(v) >= MIN_KNOWN_SECRET))
