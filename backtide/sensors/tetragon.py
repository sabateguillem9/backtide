"""The reader of Tetragon's export file: from ``tetragon.log`` to the black box.

Design: docs/23-diseno-t07-tetragon.md, sections 3, 6 and 7, with T07-1's findings. Tetragon
writes one JSON event per line into a file only root reads; this reader follows it, keeps the
agent's events (backtide/sensors/procs.py decides what each line means) and never waits for
Tetragon, nor Tetragon for it. What it loses it records as lost (``system/sensor_gap``).

- **The cursor** (``cursor.json``, 0600, written atomically): the inode of the file being read,
  the offset after its last complete line, a fingerprint of its first bytes (an inode number
  can be reused by a new file) and the last kernel time. A restart goes on from there.
- **Rotation** (T07-1, P9): Tetragon renames the active file to ``tetragon-<time>.log`` and
  opens a new one; the oldest are deleted without a trace. The reader keeps the file it reads
  open, so a rename or even a deletion does not lose it: when the active file is another inode,
  it finishes its own (Tetragon closes a file before renaming it, so one more read after seeing
  the rename gets everything) and moves to the next one by name. A file it saw waiting and that
  disappeared before it got there, or a cursor whose file is gone, is a ``sensor_gap``.
- **Lines**: a line without its final newline waits (Tetragon may be writing it); a line of
  more than 512 KiB (T07-1, P5: 320 KiB of arguments make a line of 321 KB) is dropped and
  counted, and never held in memory whole; a broken one is counted. No line raises.
- **The cheap prefilter**: a line without the first 12 characters of the agent's id is counted
  as ``other`` without being parsed. What decides is the parsed field (procs.belongs).
- **Rate limits** (section 6): a token bucket and a daily budget per class (``exec``, ``net``).
  What does not fit is folded into one ``exec/summary`` or ``net/summary`` every 10 s at most,
  which lists every distinct binary it folded (up to 50, the least frequent first: a flood of
  one program cannot hide another). Past the bucket, the first ``novel_per_binary`` events of
  each binary in a summary window are still recorded one by one (``novel: true``), from a
  bucket and a daily budget of their own: a flood does not erase who else ran. An exhausted
  daily budget is a ``sensor_gap`` of risk 2 (the process sensor alerts and, when required,
  treats it as the sensor down: ``exhausted_budgets``).
- **Throttles**: Tetragon's THROTTLE start and stop are gaps, at most one every
  ``summary_interval``; the rest are counted into the next one.
- **Probes** (section 7): ``expect(nonce)`` and ``wait_seen``. An expected probe is consumed
  once and never recorded; ``wait_ready`` is "a probe exec was seen", with a 30 s cap (P13).
  With ``stale_probes_before``, an unexpected probe older than that moment (one a killed
  service launched) is only counted.
- **Read twice** (T07-3): the cursor is saved every 5 s, so after a kill -9 of the service the
  lines after it are read again. ``already_recorded(since)`` (the keys of the sensor events in
  the black box newer than the cursor's time, ``procs.event_key``) is asked once, when the
  reader opens its first file; a line whose key is there is skipped once and counted as
  ``duplicates``. If it fails, the reader records everything (it may repeat, never lose).
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import stat
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox.model import Source
from backtide.jail.docker import sanitize
from backtide.sensors import procs
from backtide.sensors.files import DailyBudget, TokenBucket
from backtide.sensors.procs import Context, Record, Skipped, Throttle
from backtide.snapshots.model import utc_now

logger = logging.getLogger(__name__)

EVENTS_FILE = "tetragon.log"
# lumberjack's backups, as T07-1 saw them: tetragon-2026-10-17T09-45-35.139.log. The name sorts
# by time, which is the order the reader follows.
_ROTATED_RE = re.compile(r"tetragon-\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d\.\d{3}\.log", re.ASCII)
_TIME_RE = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
HEAD_BYTES = 256  # the fingerprint of a file: its first bytes
# Bytes kept from each end of a line too big to parse: the binary and the cwd come before the
# arguments, and each may be 4 KiB of controls escaped six times over.
OVERSIZE_KEEP = 64 * 1024
SENSOR_TARGET = "backtide-sensor"
READY_TIMEOUT = 30.0  # docs/23, section 7 (T07-1, P13: 1.2 s in the VM)
_SUMMARY_TOP = 5
_SUMMARY_KEYS = 1000  # distinct binaries or targets kept while folding (then "…")
_SUMMARY_BINARIES = 50  # distinct binaries listed in a summary, the least frequent first
# Folders of the image the agent cannot write to (it runs without root): their programs go
# first among the equally rare, so decoys the agent names cannot push them out of the list.
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/")
_SYSTEM_DIRS = SYSTEM_DIRS
_SEEN_KEPT = 64
_STAT_NAMES = (
    "lines", "other", "parse_errors", "oversize", "preexisting", "exit", "loopback", "unknown",
    "invalid", "recorded", "folded", "probes", "lost", "duplicates", "stale_probes", "novel",
)  # fmt: skip
MAX_REPLAY_KEYS = 50_000  # keys of recorded events kept to spot a line read twice
_ERROR_CHARS = 300
_CURSOR_VERSION = 1
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_CURSOR_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC


class SensorNotReady(Exception):
    """No probe went through the sensor in time."""


class Recorder(Protocol):
    """What the reader needs from the black box (``BlackBox.append``)."""

    def append(
        self,
        source: Source | str,
        action: str,
        target: str,
        *,
        details: Mapping[str, Any] | None = None,
        risk: int = 0,
        snapshot_id: str | None = None,
    ) -> object: ...


@dataclass(frozen=True)
class ReaderConfig:
    """The reader's paths and limits. The defaults are docs/23's; tests lower them."""

    events_dir: Path
    cursor_file: Path
    agent_name: str = "backtide-agente"
    sensor_name: str = SENSOR_TARGET
    # T07-1 measured lines of 321 KB, but JSON escaping can make Tetragon's ~327 KB of
    # arguments six times bigger (a control character is \u0001): a line up to the worst case
    # is parsed, and a bigger one is still attributed from its first and last bytes.
    max_line: int = 2560 * 1024
    read_size: int = 256 * 1024
    max_bytes_per_poll: int = 16 * 1024 * 1024
    # A poll holds the reader's lock, which the heartbeat needs: it returns after this long so
    # the lock is free between batches, and the thread loops to read the rest.
    poll_time_budget: float = 2.0
    poll_interval: float = 0.5
    cursor_interval: float = 5.0
    summary_interval: float = 10.0
    exec_rate: float = 20.0
    exec_burst: int = 500
    exec_daily: int = 100_000
    net_rate: float = 20.0
    net_burst: int = 200
    net_daily: int = 50_000
    # Past the bucket: the first events of each distinct binary in a summary window.
    novel_per_binary: int = 3
    novel_rate: float = 5.0
    novel_burst: int = 100
    # The first event of each binary not recorded yet in the window has a bucket of its own,
    # so repeats (a decoy name, argv variations) cannot use up the room for new programs.
    first_rate: float = 50.0
    first_burst: int = 200
    novel_daily: int = 20_000
    budget_window: float = 24 * 3600.0
    lag_warning: float = 60.0
    lag_interval: float = 600.0
    nonce_ttl: float = 120.0
    max_nonces: int = 64
    retire_after: float = 600.0  # seconds a replaced agent container is still accepted


@dataclass(frozen=True)
class _File:
    name: str
    ino: int
    size: int


@dataclass
class _Open:
    fd: int
    ino: int
    pos: int  # where the next read starts
    committed: int  # right after the last complete line: what the cursor saves


@dataclass(frozen=True)
class _Cursor:
    ino: int
    offset: int
    head_len: int
    head_sha256: str
    size: int
    time: str | None


class _Folded:
    """The records of one class that did not fit, for one summary."""

    def __init__(self, second: str) -> None:
        self._second = second  # "parents" for commands, "targets" for connections
        self._salt = secrets.token_bytes(16)  # the tie-break the agent cannot predict
        self._reset()

    def _rank(self, item: tuple[str, int]) -> tuple[int, int, bytes]:
        binary, count = item
        system = 0 if binary.startswith(_SYSTEM_DIRS) else 1
        mixed = hmac.new(self._salt, binary.encode("utf-8", "replace"), "sha256").digest()
        return count, system, mixed

    def _reset(self) -> None:
        self.folded = 0
        self.snapshot_id: str | None = None
        self._counts: Counter[str] = Counter()
        self._binaries: Counter[str] = Counter()
        self._others: Counter[str] = Counter()
        self._first: str | None = None
        self._last: str | None = None

    def __bool__(self) -> bool:
        return self.folded > 0

    def add(self, record: Record, snapshot_id: str | None) -> None:
        if not self.folded:
            self.snapshot_id = snapshot_id  # the first folded command's (docs/23, section 6)
        self.folded += 1
        self._counts[record.action] += 1
        _bump(self._binaries, record.binary)
        _bump(self._others, record.parent if self._second == "parents" else record.target)
        if record.time:
            self._first = self._first or record.time
            self._last = record.time

    def build(self) -> dict[str, Any]:
        key = "binary" if self._second == "parents" else "target"
        # Every distinct binary, the least frequent first: the one command among a flood of
        # another is at the top of the list, not cut off by it.
        # Ties: the image's own programs first, then an order keyed by a secret salt.
        rarest = sorted(self._binaries.items(), key=self._rank)
        details = {
            "window": {"from": self._first, "to": self._last},
            "counts": dict(self._counts),
            "top_binaries": [
                {"binary": b, "count": c} for b, c in self._binaries.most_common(_SUMMARY_TOP)
            ],
            "binaries": [{"binary": b, "count": c} for b, c in rarest[:_SUMMARY_BINARIES]],
            "distinct_binaries": len(self._binaries),
            f"top_{self._second}": [
                {key: k, "count": c} for k, c in self._others.most_common(_SUMMARY_TOP)
            ],
            "folded": self.folded,
        }
        self._reset()
        return details


class TetragonReader:
    """Follows the sensor's events folder and records the agent's events.

    ``poll()`` does one round (tests call it directly); ``start()`` runs it in a thread every
    ``poll_interval`` seconds and ``stop()`` ends it, writing the last summary and the cursor.
    ``agent_id`` is the agent container's full id (None: nothing is the agent's yet);
    ``set_agent`` changes it when the container is created again. ``snapshot_for`` gets an
    event's kernel time and returns the snapshot to rewind to (docs/23, section 4); ``scrub``
    strikes the exact secrets backtide knows. ``already_recorded`` and ``stale_probes_before``:
    see "Read twice" and "Probes" in the module's docstring. Thread-safe."""

    def __init__(
        self,
        config: ReaderConfig,
        recorder: Recorder,
        *,
        agent_id: str | None = None,
        snapshot_for: Callable[[str | None], str | None] | None = None,
        scrub: Callable[[str], str] | None = None,
        already_recorded: Callable[[str | None], Iterable[str]] | None = None,
        stale_probes_before: datetime | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], datetime] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.clock = clock
        self._recorder = recorder
        self._snapshot_for = snapshot_for
        self._scrub = scrub
        self._already_recorded = already_recorded
        self._stale_before = stale_probes_before
        self._replay: set[str] = set()
        self._wall = wall
        self._sleep = sleep
        self._lock = threading.RLock()
        self._ctx: Context | None = None
        self._prefixes: tuple[bytes, ...] = ()
        self._agent_id: str | None = None
        self._retired: dict[str, float] = {}  # previous container -> until when it is accepted
        self.set_agent(agent_id)
        self._file: _Open | None = None
        self._buf = bytearray()
        self._skipping = False
        # Files waiting after ours and files already read, with their first bytes: an inode
        # number is reused at once on ext4 or XFS, so the number alone does not say which
        # file it is (the open one is safe: an inode held open is never reused).
        self._pending: dict[int, tuple[int, bytes]] = {}  # inode -> (size, head)
        self._done: deque[tuple[int, bytes]] = deque(maxlen=32)
        self._oversize_head = b""
        self._oversize_tail = b""
        self._counts: Counter[str] = Counter()
        now = clock()
        self._buckets = {
            Source.EXEC: TokenBucket(config.exec_rate, config.exec_burst, now),
            Source.NET: TokenBucket(config.net_rate, config.net_burst, now),
        }
        self._budgets = {
            Source.EXEC: DailyBudget(config.exec_daily, config.budget_window),
            Source.NET: DailyBudget(config.net_daily, config.budget_window),
        }
        self._budget_warned: dict[Source, float | None] = {Source.EXEC: None, Source.NET: None}
        self._novel_buckets = {
            kind: TokenBucket(config.novel_rate, config.novel_burst, now)
            for kind in (Source.EXEC, Source.NET)
        }
        self._first_buckets = {
            kind: TokenBucket(config.first_rate, config.first_burst, now)
            for kind in (Source.EXEC, Source.NET)
        }
        self._novel_budgets = {
            kind: DailyBudget(config.novel_daily, config.budget_window)
            for kind in (Source.EXEC, Source.NET)
        }
        # Per summary window, by command (the binary and a digest of its whole command line):
        # how many went past the bucket. A new command line of a binary already seen is new.
        self._novel_seen: dict[Source, Counter[_Command]] = {
            Source.EXEC: Counter(),
            Source.NET: Counter(),
        }
        # Per summary window: the commands and the binaries recorded one by one, and the
        # commands folded without a single event of theirs recorded.
        self._window_kept: dict[Source, set[_Command]] = {Source.EXEC: set(), Source.NET: set()}
        self._window_binaries: dict[Source, set[str]] = {Source.EXEC: set(), Source.NET: set()}
        # Commands still novel that a drained bucket or budget turned away: their identity is
        # lost to a flood, not to a legitimate build's own quota.
        self._window_starved: dict[Source, set[_Command]] = {Source.EXEC: set(), Source.NET: set()}
        # Folds of a command already recorded this window (a build running it many times): no
        # loss, only a note (argv_folded, risk 1).
        self._window_repeats: dict[Source, Counter[_Command]] = {
            Source.EXEC: Counter(),
            Source.NET: Counter(),
        }
        self._window_unseen: dict[Source, Counter[_Command]] = {
            Source.EXEC: Counter(),
            Source.NET: Counter(),
        }
        # Folded commands past _SUMMARY_KEYS distinct ones, by binary (then "…").
        self._window_overflow: dict[Source, Counter[str]] = {
            Source.EXEC: Counter(),
            Source.NET: Counter(),
        }
        # What the process sensor must hear about (alert, and with required stop the agent):
        # throttles of the agent's cgroup, windows with binaries lost whole (novelty_lost) and
        # rotated files lost, since it last asked.
        self._blind = Counter[str]()
        # Binaries whose command lines were folded unseen while they do have events of their
        # own (a build's many distinct commands), by windows: risk 2 and an alert, never a stop.
        self._unseen = Counter[str]()
        # When the current run of windows with unseen command lines began (None: the last
        # window had none). The founder's decision B: a long run is a blind spot (required).
        self._unseen_since: float | None = None
        self._salt = secrets.token_bytes(16)  # the order of names in a gap, unpredictable
        self._folded = {Source.EXEC: _Folded("parents"), Source.NET: _Folded("targets")}
        self._last_summary = now
        self._reported = Counter[str]()
        self._throttle_since: str | None = None
        self._throttle_last: float | None = None  # when the last throttle gap was recorded
        self._throttle_held: Counter[str] = Counter()  # starts and stops not recorded yet
        self._throttle_window: list[str | None] = [None, None]
        self._last_lag: float | None = None
        self._last_time: str | None = None
        self._expected: dict[str, float] = {}
        self._seen: deque[str] = deque(maxlen=_SEEN_KEPT)
        self._failing: set[str] = set()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        # Read lock-free by the process sensor's watchdog to notice a poll that is taking too
        # long (a flood of hostile lines): a stuck poll holds the lock, so nothing under it
        # would answer. Set inside the lock and cleared only by the poll that set it.
        self.polling_since: float | None = None
        self._poll_token: object | None = None

    # The agent

    def set_agent(self, agent_id: str | None, *, timeout: float | None = None) -> bool:
        """Whose events to record: a full container id, or None for nobody. The container it
        replaces is still accepted for ``retire_after`` seconds: its lines the reader has not
        reached yet (it may lag behind a flood) are still the agent's. With ``timeout``, False
        (and nothing changed) if the reader's lock could not be had in time."""
        if agent_id is not None:
            Context(agent_id=agent_id, agent_name=self.config.agent_name)  # validates it
        with self.held(timeout) as got:
            if not got:
                return False
            old = self._agent_id
            if old is not None and old != agent_id:
                self._retired[old] = self.clock() + self.config.retire_after
            self._retired.pop(agent_id or "", None)
            self._agent_id = agent_id
            self._rebuild_context()
            return True

    def _rebuild_context(self) -> None:
        now = self.clock()
        for container in [c for c, until in self._retired.items() if until <= now]:
            del self._retired[container]
        if self._agent_id is None:
            self._ctx, self._prefixes = None, ()
            return
        self._ctx = Context(
            agent_id=self._agent_id,
            agent_name=self.config.agent_name,
            scrub=self._scrub,
            previous=tuple(self._retired),
        )
        self._prefixes = tuple(c[: procs.MIN_PREFIX].encode() for c in self._ctx.ids)

    # Probes

    def expect(self, nonce: str, *, timeout: float | None = None) -> bool:
        """A probe with this nonce is on its way: consume it instead of recording it. With
        ``timeout``, False if the reader's lock could not be had in time."""
        if not procs.is_nonce(nonce):
            raise ValueError(f"not a probe nonce: {nonce!r:.80}")
        with self.held(timeout) as got:
            if not got:
                return False
            self._expire_nonces(self.clock())
            while len(self._expected) >= self.config.max_nonces:
                del self._expected[next(iter(self._expected))]
            self._expected[nonce] = self.clock() + self.config.nonce_ttl
            return True

    def seen(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._seen

    def wait_seen(self, nonces: str | Iterable[str], timeout: float) -> bool:
        """Poll until one of ``nonces`` went through the sensor, for up to ``timeout``
        seconds. Works with or without the reader's thread. Never waits for the lock longer
        than what is left: a stuck poll elsewhere makes it give up, not hang."""
        wanted = {nonces} if isinstance(nonces, str) else set(nonces)
        deadline = self.clock() + timeout
        while True:
            with self.held(deadline - self.clock()) as got:
                if got:
                    self.poll()
                    if any(nonce in self._seen for nonce in wanted):
                        return True
            remaining = deadline - self.clock()
            if remaining <= 0:
                return False
            self._sleep(min(0.1, remaining))

    @contextmanager
    def held(self, timeout: float | None) -> Iterator[bool]:
        """The reader's lock, if it can be had within ``timeout`` seconds (True), or not
        (False): for callers that must not block behind a stuck poll. None waits as long as it
        takes; a timeout already past only tries."""
        if timeout is None:
            got = self._lock.acquire()
        else:
            got = self._lock.acquire(timeout=max(0.0, timeout))
        try:
            yield got
        finally:
            if got:
                self._lock.release()

    # Reading

    def poll(self) -> int:
        """Read what Tetragon added since the last round; returns the number of lines. One poll
        reads for at most ``poll_time_budget`` seconds (the thread loops for the rest), so the
        lock it holds does not keep the heartbeat waiting."""
        with self._lock:
            token = self._poll_token = object()
            self.polling_since = now = self.clock()
            try:
                self._expire_nonces(now)
                if any(until <= now for until in self._retired.values()):
                    self._rebuild_context()
                lines_before = self._counts["lines"]
                try:
                    self._poll_files()
                except OSError as e:
                    self._failed("read", e)
                else:
                    self._failing.discard("read")
                self._flush(now)
                return self._counts["lines"] - lines_before
            finally:
                if self._poll_token is token:
                    self._poll_token = self.polling_since = None

    def blocked(self, seconds: float) -> bool:
        """Whether a poll has been running for at least ``seconds`` (read without the lock): the
        reader is stuck and nothing under its lock would answer."""
        since = self.polling_since
        return since is not None and self.clock() - since >= seconds

    def stats(self) -> dict[str, int]:
        """What the reader counted: lines, other, parse_errors, oversize, preexisting, exit,
        loopback, folded, probes, lost (appends that failed)..."""
        with self._lock:
            return {name: 0 for name in _STAT_NAMES} | dict(self._counts)

    def exhausted_budgets(self) -> list[str]:
        """The classes (``exec``, ``net``) whose daily budget is spent now: events of those
        are only folded, and the summaries cannot say every command that ran."""
        with self._lock:
            now = self.clock()
            spent = [kind.value for kind, budget in self._budgets.items() if budget.exhausted(now)]
            spent += [
                f"{kind.value}_novel"
                for kind, budget in self._novel_budgets.items()
                if budget.exhausted(now)
            ]
            return spent

    def take_blind_spots(self) -> dict[str, int]:
        """What made the reader blind since the last call: ``throttle`` (the kernel dropped the
        agent's exec/exit events, cgroup-rate), ``novelty_lost`` (binaries folded without a
        single event of theirs recorded) and ``rotated`` (a file of events lost before it was
        read). Each was a gap of risk 2 already."""
        with self._lock:
            blind, self._blind = dict(self._blind), Counter()
            return blind

    def unseen_streak(self) -> float:
        """Seconds since the current run of summary windows with command lines folded unseen
        (``novelty_lost {blind: false}``) began, with no window free of them; 0 without one."""
        with self._lock:
            since = self._unseen_since
            return 0.0 if since is None else max(0.0, self.clock() - since)

    def take_unseen(self) -> dict[str, int]:
        """The binaries whose command lines were folded unseen since the last call while they
        did have events of their own (risk 2 gaps, ``blind: false``), with how many windows:
        the process sensor alerts, but never stops the agent for them (a parallel build does
        this)."""
        with self._lock:
            unseen, self._unseen = dict(self._unseen), Counter()
            return unseen

    @property
    def preexisting(self) -> int:
        """Processes that ran before the sensor (procFS): for ``system/sensor_start``."""
        with self._lock:
            return self._counts["preexisting"]

    def save_cursor(self) -> None:
        """Write the cursor (atomically). A failure is recorded once, never raised."""
        with self._lock:
            try:
                self._write_cursor()
            except OSError as e:
                self._failed("cursor", e)
            else:
                self._failing.discard("cursor")

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                os.close(self._file.fd)
                self._file = None

    # The thread

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("the reader is already running")
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="tetragon-reader", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the thread (if any), read what is left, write the last summary and the cursor,
        and close the file."""
        thread, self._thread = self._thread, None
        if thread is not None:
            self._stopping.set()
            thread.join(timeout)
            if thread.is_alive():
                logger.error("the Tetragon reader did not stop within %s s", timeout)
        self.poll()
        with self._lock:
            self._flush(self.clock(), final=True)
        self.save_cursor()
        self.close()

    def _run(self) -> None:
        last_cursor = self.clock()
        while not self._stopping.wait(self.config.poll_interval):
            try:
                self.poll()
                if self.clock() - last_cursor >= self.config.cursor_interval:
                    self.save_cursor()
                    last_cursor = self.clock()
            except Exception as e:  # never let the thread die silently
                logger.exception("the Tetragon reader failed")
                with self._lock:
                    self._failed("reader", e)

    # Files

    def _poll_files(self) -> None:
        listing = self._list()
        if self._file is None:
            self._start(listing)
            if self._file is None:
                return
        self._note_lost(listing)
        budget = self.config.max_bytes_per_poll
        deadline = self.clock() + self.config.poll_time_budget
        while budget > 0:
            got = self._read(budget)
            budget -= got
            if got:
                if self.clock() >= deadline:
                    break  # more to read: the thread polls again, the lock free meanwhile
                continue
            if not self._rotated_away(listing):
                break
            # Tetragon closes a file before renaming it: one more read gets its last lines.
            got = self._read(budget)
            budget -= got
            if got:
                continue
            following = self._next(listing)
            if following is None:
                break  # the new file is not there yet: stay on this one
            self._finish()
            opened = self._open(following, 0)
            # Look again after every switch: under a flood, files come and go quickly.
            listing = self._list()
            self._note_lost(listing)
            if not opened:
                break  # it changed under us: look again next round

    def _list(self) -> list[_File]:
        """The regular files of the events folder that Tetragon writes, oldest first and the
        active one last. Symlinks and anything else are ignored."""
        rotated: list[_File] = []
        active: list[_File] = []
        with os.scandir(self.config.events_dir) as entries:
            for entry in entries:
                is_active = entry.name == EVENTS_FILE
                if not is_active and not _ROTATED_RE.fullmatch(entry.name):
                    continue
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISREG(st.st_mode):
                    (active if is_active else rotated).append(
                        _File(entry.name, st.st_ino, st.st_size)
                    )
        return sorted(rotated, key=lambda f: f.name) + active

    def _head(self, file: _File) -> bytes | None:
        """The first bytes of ``file``, or None if it is not that inode any more."""
        try:
            fd = os.open(self.config.events_dir / file.name, _READ_FLAGS)
        except OSError:
            return None
        try:
            if os.fstat(fd).st_ino != file.ino:
                return None
            return os.pread(fd, HEAD_BYTES, 0)
        finally:
            os.close(fd)

    def _start(self, listing: list[_File]) -> None:
        """Open the cursor's file at its offset, or the oldest file when there is none."""
        cursor = self._load_cursor()
        self._load_replay(cursor.time if cursor is not None else None)
        if cursor is not None:
            self._last_time = self._last_time or cursor.time
            for candidate in listing:
                if candidate.ino == cursor.ino and candidate.size >= cursor.offset:
                    if self._open(candidate, cursor.offset, cursor):
                        return
            # Rotated away unread (or its inode now belongs to another file).
            self._blind["rotated"] += 1
            self._gap(
                "rotated",
                2,
                files=1,
                min_bytes=max(0, cursor.size - cursor.offset),
                reason="the cursor's file is gone",
            )
        if listing:
            self._open(listing[0], 0)

    def _load_replay(self, since: str | None) -> None:
        """The keys of what an earlier run recorded after ``since``: asked once."""
        lookup, self._already_recorded = self._already_recorded, None
        if lookup is None:
            return
        try:
            keys = [key for key in lookup(since) if isinstance(key, str)]
        except Exception as e:  # recorded, never raised: repeating beats losing
            self._failed("dedupe", e)
            return
        self._replay = set(keys[-MAX_REPLAY_KEYS:])

    def _open(self, file: _File, offset: int, cursor: _Cursor | None = None) -> bool:
        try:
            fd = os.open(self.config.events_dir / file.name, _READ_FLAGS)
        except FileNotFoundError:
            return False
        try:
            st = os.fstat(fd)
            ok = stat.S_ISREG(st.st_mode) and st.st_ino == file.ino
            if ok and cursor is not None:
                head = os.pread(fd, cursor.head_len, 0)
                ok = hashlib.sha256(head).hexdigest() == cursor.head_sha256
        except BaseException:
            os.close(fd)
            raise
        if not ok:
            os.close(fd)
            return False
        self._file = _Open(fd=fd, ino=file.ino, pos=offset, committed=offset)
        self._buf.clear()
        self._skipping = False
        self._pending.pop(file.ino, None)
        return True

    def _finish(self) -> None:
        """Close the file that was rotated away; a last line without its newline is broken."""
        assert self._file is not None  # noqa: S101 - only called with a file open
        if self._buf or self._skipping:
            self._counts["parse_errors"] += 1
        self._done.append((self._file.ino, os.pread(self._file.fd, HEAD_BYTES, 0)))
        os.close(self._file.fd)
        self._file = None
        self._buf.clear()
        self._skipping = False

    def _rotated_away(self, listing: list[_File]) -> bool:
        """Whether Tetragon moved on to another file. The inode of the open file cannot be
        reused while it is open, so comparing numbers is enough here."""
        assert self._file is not None  # noqa: S101
        active = next((f for f in listing if f.name == EVENTS_FILE), None)
        return active is None or active.ino != self._file.ino

    def _is_done(self, file: _File) -> bool:
        """Whether ``file`` is one already read: same inode AND same first bytes."""
        for ino, head in self._done:
            if ino == file.ino and head:
                current = self._head(file)
                return current is not None and current[: len(head)] == head
        return False

    def _after(self, listing: list[_File]) -> list[_File]:
        """The files to read after the current one, in order."""
        assert self._file is not None  # noqa: S101
        inos = [f.ino for f in listing]
        # Gone from the folder: everything left is newer (Tetragon deletes the oldest first).
        rest = listing[inos.index(self._file.ino) + 1 :] if self._file.ino in inos else listing
        return [f for f in rest if f.ino != self._file.ino and not self._is_done(f)]

    def _next(self, listing: list[_File]) -> _File | None:
        following = self._after(listing)
        return following[0] if following else None

    def _note_lost(self, listing: list[_File]) -> None:
        """Files that were waiting and disappeared before the reader got to them, also when
        their inode number already belongs to a new file (its first bytes differ)."""
        assert self._file is not None  # noqa: S101
        present = {f.ino: f for f in listing}
        lost: dict[int, int] = {}
        for ino, (size, head) in list(self._pending.items()):
            file = present.get(ino)
            current = None if file is None else self._head(file)
            # Append-only: the first bytes of the same file only ever grow.
            if current is None or current[: len(head)] != head[: len(current)]:
                lost[ino] = size
                del self._pending[ino]
        for f in self._after(listing):
            size, head = self._pending.get(f.ino, (f.size, b""))
            if len(head) < HEAD_BYTES:
                head = self._head(f) or head
            self._pending[f.ino] = (f.size, head)
        if lost:
            self._blind["rotated"] += 1
            self._gap(
                "rotated",
                2,
                files=len(lost),
                min_bytes=sum(lost.values()),
                reason="rotated away before it was read",
            )

    def _read(self, budget: int) -> int:
        assert self._file is not None  # noqa: S101
        f = self._file
        data = os.pread(f.fd, min(self.config.read_size, budget), f.pos)
        if not data:
            if os.fstat(f.fd).st_size < f.pos:
                logger.warning("%s shrank under the reader: reading it again", EVENTS_FILE)
                self._gap("truncated", 1, offset=f.pos)
                f.pos = f.committed = 0
                self._buf.clear()
                self._skipping = False
            return 0
        start_pos = f.pos
        f.pos += len(data)
        self._feed(data, start_pos)
        return len(data)

    def _feed(self, data: bytes, start_pos: int) -> None:
        """Split ``data`` (read at ``start_pos``) into lines, holding at most ``max_line``
        bytes of an unfinished one. Of a bigger line only its first and last OVERSIZE_KEEP
        bytes are kept, to attribute it (procs.classify_oversize)."""
        assert self._file is not None  # noqa: S101
        limit = self.config.max_line
        start = 0
        while start < len(data):
            newline = data.find(b"\n", start)
            end = len(data) if newline < 0 else newline
            if self._skipping:
                self._oversize_tail = (self._oversize_tail + data[start:end])[-OVERSIZE_KEEP:]
            elif len(self._buf) + end - start > limit:
                whole = bytes(self._buf) + data[start:end]
                self._oversize_head = whole[:OVERSIZE_KEEP]
                self._oversize_tail = whole[-OVERSIZE_KEEP:]
                self._buf.clear()
                self._skipping = True
                self._counts["oversize"] += 1
            elif newline < 0:
                self._buf += data[start:]
            else:
                line = bytes(self._buf) + data[start:newline]
                self._buf.clear()
                self._handle(line)
            if newline < 0:
                return
            if self._skipping:
                self._skipping = False
                self._handle_oversize(self._oversize_head, self._oversize_tail)
                self._oversize_head = self._oversize_tail = b""
            start = newline + 1
            self._file.committed = start_pos + start

    # Lines

    def _handle(self, line: bytes) -> None:
        self._counts["lines"] += 1
        if not line.strip():
            return
        ctx = self._ctx
        if ctx is None or not any(prefix in line for prefix in self._prefixes):
            self._counts["other"] += 1
            return
        try:
            data = json.loads(line)
        except (ValueError, RecursionError):
            self._counts["parse_errors"] += 1
            return
        if not isinstance(data, dict):
            self._counts["parse_errors"] += 1
            return
        try:
            parsed = procs.classify(data, ctx)
        except Exception:  # a bug in procs: counted and logged, the reader goes on
            logger.exception("could not classify a Tetragon event")
            self._counts["parse_errors"] += 1
            return
        self._dispatch(parsed)

    def _handle_oversize(self, head: bytes, tail: bytes) -> None:
        """A line too big to parse: attributed from its ends, so it cannot hide a command."""
        self._counts["lines"] += 1
        ctx = self._ctx
        if ctx is None or not any(p in head or p in tail for p in self._prefixes):
            self._counts["other"] += 1
            return
        try:
            parsed = procs.classify_oversize(head, tail, ctx)
        except Exception:
            logger.exception("could not classify a Tetragon event too big to parse")
            return
        self._dispatch(parsed)

    def _dispatch(self, parsed: procs.Parsed) -> None:
        if isinstance(parsed, Skipped):
            self._counts[parsed.reason] += 1
        elif isinstance(parsed, Throttle):
            self._throttle(parsed)
        else:
            self._record(parsed)

    def _record(self, record: Record) -> None:
        if record.nonce is not None and self._consume(record.nonce):
            self._counts["probes"] += 1
            return
        if record.nonce is not None and self._is_stale(record.time):
            self._counts["stale_probes"] += 1
            return
        if record.preexisting:
            # Tetragon found it running when it started. Recorded only when it began after
            # the last event seen (while the sensor was down); else it is only counted.
            self._counts["preexisting"] += 1
            resume = procs.parse_time(self._last_time)
            started = procs.parse_time(record.started)
            if resume is None or started is None or started <= resume:
                return
        else:
            self._check_lag(record.time)
            if record.time:
                self._last_time = record.time
        if record.key is not None and record.key in self._replay:
            self._replay.discard(record.key)
            self._counts["duplicates"] += 1
            return
        snapshot_id = self._snapshot_for(record.time) if self._snapshot_for else None
        kind = Source.NET if record.source is Source.NET else Source.EXEC
        now = self.clock()
        budget = self._budgets[kind]
        if budget.exhausted(now):
            self._warn_budget(kind, budget)
            fits = False
        else:
            fits = self._buckets[kind].take(now) and budget.try_spend(now)
        if not fits and self._novel(kind, record, now):
            record.details["novel"] = True
            self._counts["novel"] += 1
            fits = True
        if fits:
            if self._append(
                record.source,
                record.action,
                record.target,
                details=record.details,
                risk=record.risk,
                snapshot_id=snapshot_id,
            ):
                self._counts["recorded"] += 1
                if len(self._window_kept[kind]) < _SUMMARY_KEYS:
                    self._window_kept[kind].add(_command(record))
                if len(self._window_binaries[kind]) < _SUMMARY_KEYS:
                    self._window_binaries[kind].add(record.binary)
            return
        self._folded[kind].add(record, snapshot_id)
        self._counts["folded"] += 1
        command = _command(record)
        if command in self._window_kept[kind]:
            self._window_repeats[kind][command] += 1  # recorded already: a repeat, no loss
        else:
            unseen = self._window_unseen[kind]
            if command in unseen or len(unseen) < _SUMMARY_KEYS:
                unseen[command] += 1
            else:
                _bump(self._window_overflow[kind], record.binary)

    def _novel(self, kind: Source, record: Record, now: float) -> bool:
        """Whether this event, past the bucket, is still one of the first of its command in
        this summary window (and the novelty buckets and budget have room). The first event of
        a binary not recorded yet in the window takes from its own bucket."""
        seen = self._novel_seen[kind]
        command = _command(record)
        if seen[command] >= self.config.novel_per_binary:
            return False
        if command not in seen and len(seen) >= _SUMMARY_KEYS:
            self._window_starved[kind].add(command)
            return False
        first = record.binary not in self._window_binaries[kind]
        bucket = self._first_buckets[kind] if first else self._novel_buckets[kind]
        if not bucket.take(now):
            self._window_starved[kind].add(command)  # a drained bucket, not the per-command quota
            return False
        if not self._novel_budgets[kind].try_spend(now):
            self._window_starved[kind].add(command)
            return False
        seen[command] += 1
        return True

    def _throttle(self, throttle: Throttle) -> None:
        """At most one throttle gap every ``summary_interval``: the rest are counted into the
        next one (an agent that flaps around the rate cannot flood the black box with them)."""
        now = self.clock()
        since = self._throttle_since
        if throttle.state == "start":
            self._throttle_since = since = throttle.time
        else:
            self._throttle_since = None
        if (
            self._throttle_last is not None
            and now - self._throttle_last < self.config.summary_interval
        ):
            self._throttle_held[throttle.state] += 1
            first, _ = self._throttle_window
            self._throttle_window = [first or since or throttle.time, throttle.time]
            return
        details: dict[str, Any] = {"state": throttle.state, "since": since}
        if throttle.state == "stop":
            details["until"] = throttle.time
        self._record_throttle(now, details)

    def _record_throttle(self, now: float, details: dict[str, Any]) -> None:
        if self._throttle_held:
            held, self._throttle_held = self._throttle_held, Counter()
            first, last = self._throttle_window
            self._throttle_window = [None, None]
            details["held"] = {"starts": held["start"], "stops": held["stop"]}
            details["held_window"] = {"from": first, "to": last}
        self._throttle_last = now
        if details.get("state") == "start" or details.get("held", {}).get("starts"):
            self._blind["throttle"] += 1
        self._gap("throttle", 2, **details)

    def _lost_details(self, kind: Source, lost: "Mapping[_Command, int]") -> dict[str, Any]:
        return _lost_details(kind, lost, self._salt)

    def _consume(self, nonce: str) -> bool:
        if self._expected.pop(nonce, None) is None:
            return False
        self._seen.append(nonce)
        return True

    def _is_stale(self, kernel_time: str | None) -> bool:
        """A probe from before ``stale_probes_before``: launched by an earlier run."""
        moment = procs.parse_time(kernel_time)
        return self._stale_before is not None and moment is not None and moment < self._stale_before

    def _expire_nonces(self, now: float) -> None:
        for nonce in [n for n, until in self._expected.items() if until <= now]:
            del self._expected[nonce]

    def _check_lag(self, kernel_time: str | None) -> None:
        moment = procs.parse_time(kernel_time)
        if moment is None:
            return
        lag = (self._wall() - moment).total_seconds()
        now = self.clock()
        if lag <= self.config.lag_warning:
            return
        if self._last_lag is not None and now - self._last_lag < self.config.lag_interval:
            return
        self._last_lag = now
        self._gap("lag", 1, seconds=int(lag))

    def _warn_budget(self, kind: Source, budget: DailyBudget) -> None:
        """Once per budget window, at risk 2: from here on that class is only folded."""
        if self._budget_warned[kind] == budget.window_start:
            return
        self._budget_warned[kind] = budget.window_start
        self._gap("budget", 2, **{"class": kind.value, "limit": budget.limit})

    def _flush(self, now: float, *, final: bool = False) -> None:
        """At most every ``summary_interval``: the summaries and the parse errors."""
        if self._throttle_held and (
            final
            or self._throttle_last is None
            or now - self._throttle_last >= self.config.summary_interval
        ):
            self._record_throttle(now, {"state": "repeated", "since": self._throttle_since})
        if not final and now - self._last_summary < self.config.summary_interval:
            return
        window_start, self._last_summary = self._last_summary, now
        any_seen = False
        for seen in self._novel_seen.values():
            seen.clear()  # a new summary window: every binary is new again
        for kind, unseen in self._window_unseen.items():
            # Commands recorded later in the window are not lost after all.
            kept = self._window_kept[kind]
            binaries = self._window_binaries[kind]
            # A command line with no event of its own recorded in the window is lost (risk 2).
            # When its binary has none either, a flood erased that a program ran at all: the
            # sensor is blind (take_blind_spots: with required, the agent stops). When the
            # binary does have events of its own (a build running many distinct commands of
            # one compiler), it is an alert only (take_unseen). Exact repeats of a recorded
            # command line are a build's repeats: risk 1.
            lost = {cmd: n for cmd, n in unseen.items() if cmd not in kept}
            for binary, n in self._window_overflow[kind].items():
                lost[(binary, "…")] = lost.get((binary, "…"), 0) + n
            blind = {cmd: n for cmd, n in lost.items() if cmd[0] not in binaries}
            seen = {cmd: n for cmd, n in lost.items() if cmd[0] in binaries}
            repeats = self._window_repeats[kind]
            if blind:
                self._blind["novelty_lost"] += 1
                self._gap("novelty_lost", 2, blind=True, **self._lost_details(kind, blind))
            if seen:
                any_seen = True
                for binary in {binary for binary, _ in seen}:
                    _bump(self._unseen, binary)
                self._gap("novelty_lost", 2, blind=False, **self._lost_details(kind, seen))
            if repeats:
                self._gap("argv_folded", 1, **self._lost_details(kind, repeats))
            unseen.clear()
            kept.clear()
            binaries.clear()
            self._window_overflow[kind].clear()
            self._window_starved[kind].clear()
            repeats.clear()
        if not any_seen:
            self._unseen_since = None
        elif self._unseen_since is None:
            self._unseen_since = window_start
        for kind, folded in self._folded.items():
            if folded:
                snapshot_id = folded.snapshot_id
                details = folded.build()
                self._append(
                    kind, "summary", "agent", details=details, risk=0, snapshot_id=snapshot_id
                )
        new = {
            name: self._counts[name] - self._reported[name] for name in ("parse_errors", "oversize")
        }
        if any(new.values()):
            self._reported.update(new)
            self._gap("parse_errors", 1, count=sum(new.values()), **new)

    # Recording

    def _append(
        self,
        source: Source,
        action: str,
        target: str,
        *,
        details: Mapping[str, Any],
        risk: int,
        snapshot_id: str | None = None,
    ) -> bool:
        try:
            self._recorder.append(
                source, action, target, details=details, risk=risk, snapshot_id=snapshot_id
            )
        except Exception:
            # Counted and logged; the reader goes on (the black box's own failure is the
            # Guardian's to report).
            logger.exception("could not record %s/%s from the sensor", source, action)
            self._counts["lost"] += 1
            return False
        return True

    def _gap(self, kind: str, risk: int, **details: Any) -> None:
        logger.warning("sensor gap: %s %s", kind, details)
        self._append(
            Source.SYSTEM,
            "sensor_gap",
            self.config.sensor_name,
            details={"kind": kind, **details},
            risk=risk,
        )

    def _failed(self, stage: str, error: BaseException) -> None:
        """Record (and log) a failure of ``stage`` once, until that stage works again."""
        if stage in self._failing:
            logger.debug("the Tetragon reader still fails at %s: %s", stage, error)
            return
        logger.error("the Tetragon reader failed at %s: %s", stage, error)
        self._failing.add(stage)
        self._append(
            Source.SYSTEM,
            "sensor_failed",
            self.config.sensor_name,
            details={"stage": stage, "error": sanitize(str(error), _ERROR_CHARS)},
            risk=2,
        )

    # The cursor

    def _write_cursor(self) -> None:
        f = self._file
        if f is None:
            return
        head = os.pread(f.fd, HEAD_BYTES, 0)
        content = {
            "version": _CURSOR_VERSION,
            "inode": f.ino,
            "offset": f.committed,
            "head_len": len(head),
            "head_sha256": hashlib.sha256(head).hexdigest(),
            "size": os.fstat(f.fd).st_size,
            "time": self._last_time,
        }
        path = self.config.cursor_file
        tmp = path.with_name(f".{path.name}.tmp")
        fd = os.open(tmp, _CURSOR_FLAGS, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(content).encode() + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _load_cursor(self) -> _Cursor | None:
        """The saved cursor, or None. A broken one is recorded and ignored (the reader then
        starts from the oldest file: it may repeat events, but it loses none)."""
        path = self.config.cursor_file
        try:
            fd = os.open(path, _READ_FLAGS)
        except FileNotFoundError:
            return None
        except OSError as e:
            self._gap("cursor_invalid", 1, error=sanitize(str(e), _ERROR_CHARS))
            return None
        try:
            text = os.read(fd, 4096)
        finally:
            os.close(fd)
        try:
            data = json.loads(text)
            cursor = _Cursor(
                ino=data["inode"],
                offset=data["offset"],
                head_len=data["head_len"],
                head_sha256=data["head_sha256"],
                size=data["size"],
                time=data.get("time") if isinstance(data.get("time"), str) else None,
            )
            numbers = (cursor.ino, cursor.offset, cursor.head_len, cursor.size)
            if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in numbers):
                raise ValueError("negative or non-integer fields")
            if cursor.head_len > HEAD_BYTES or not isinstance(cursor.head_sha256, str):
                raise ValueError("bad fingerprint")
            if not _SHA256_RE.fullmatch(cursor.head_sha256):
                raise ValueError("bad fingerprint")
        except (ValueError, KeyError, TypeError) as e:
            self._gap("cursor_invalid", 1, error=sanitize(str(e), _ERROR_CHARS))
            return None
        return cursor


def wait_ready(
    reader: TetragonReader,
    launch: Callable[[str], object],
    *,
    timeout: float = READY_TIMEOUT,
    interval: float = 1.0,
) -> float:
    """Wait until the sensor sees a probe: ``launch(nonce)`` runs ``true <nonce>`` in the
    watched container (by docker exec), again every ``interval`` seconds with a new nonce,
    until one of them shows up in the file (T07-1, P13: the only signal that proves the whole
    path). Returns the seconds it took; raises SensorNotReady after ``timeout``."""
    start = reader.clock()
    deadline = start + timeout
    nonces: list[str] = []
    while True:
        nonce = procs.new_nonce("ready")
        # Never blocked behind a stuck poll: a reader that cannot even take the nonce in time
        # is not ready.
        if reader.expect(nonce, timeout=max(0.0, deadline - reader.clock())):
            nonces.append(nonce)
            launch(nonce)
        remaining = deadline - reader.clock()
        if reader.wait_seen(nonces, max(0.0, min(interval, remaining))):
            return reader.clock() - start
        if reader.clock() >= deadline:
            raise SensorNotReady(f"the sensor saw no probe in {timeout} s")


type _Command = tuple[str, str]  # (binary, digest of its whole command line)


def _command(record: Record) -> _Command:
    """What makes a command distinct for novelty: its binary and its WHOLE command line, so
    only an exact repeat is a repeat (a shared head is not: T07-5). The digest is procs'
    ``fingerprint`` (sha256 of the full argv with the known secrets struck, kept in memory
    only); a record without one (a connection) uses its stored argv."""
    if record.fingerprint is not None:
        return record.binary, record.fingerprint
    argv = record.details.get("argv")
    text = argv if isinstance(argv, str) else ""
    return record.binary, hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


_GAP_NAMES = 20  # binaries named in a novelty gap


def _lost_details(kind: Source, lost: Mapping[_Command, int], salt: bytes = b"") -> dict[str, Any]:
    """What a novelty gap says: how many binaries, command lines and events, and which binaries
    (up to _GAP_NAMES, the image's programs first: the agent cannot write those; then an order
    keyed by a secret salt, so its own decoy names cannot be chosen to push a program out of
    the list). The names are the struck and escaped ones the events already carry; a command
    line never is."""
    binaries = {binary for binary, _ in lost}

    def rank(binary: str) -> tuple[bool, bytes]:
        mixed = hmac.new(salt, binary.encode("utf-8", "replace"), "sha256").digest()
        return not binary.startswith(_SYSTEM_DIRS), mixed

    names = sorted(binaries, key=rank)
    return {
        "class": kind.value,
        "binaries": len(binaries),
        "commands": len(lost),
        "events": sum(lost.values()),
        "names": names[:_GAP_NAMES],
    }


def _bump(counter: Counter[str], key: str) -> None:
    if key in counter or len(counter) < _SUMMARY_KEYS:
        counter[key] += 1
    else:
        counter["…"] += 1
