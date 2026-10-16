"""The file watcher: what the agent changed in its folder, condensed, in the black box.

Design and rationale: docs/19-diseno-t04.md, section 1. Two independent mechanisms: Btrfs
decides WHEN to take a snapshot, this watcher only DESCRIBES what changed. If it degrades it
loses detail, never snapshots, and it always records that it lost something (``file/dropped``).

Pure pieces (unit tests on the Mac): ``WatchTree`` (watch descriptor -> path), ``Coalescer``
(raw changes -> one record per path and window), ``TokenBucket``, ``DailyBudget`` and the
summary buffer. ``FileWatcher`` ties them to inotify with four kinds of threads:

- the READER drains the kernel queue and nothing else: it updates the in-memory state and
  never touches the black box (so a slow disk cannot overflow the queue). Each round reads
  only what was queued when it began (FIONREAD), so a flood that never ends cannot keep it
  from answering ``drain()``, expiring moves or stopping;
- the SCANNER walks directories to put watches on them (at start, new directories, and after
  an overflow), in chunks, so the reader keeps going. It opens each directory by name relative
  to its parent's descriptor, and a pending directory is "the entry NAME of the watch WD", not
  a path: neither PATH_MAX nor a rename of an ancestor can make it lose one. Whatever it
  cannot watch goes to the ledger of unwatched directories, never only to the log;
- the DUMPER turns the pending state into records every ``dump_interval`` seconds;
- short-lived helper threads re-arm after an anomaly.

Paths are recorded relative to the agent's folder (``.`` is the folder itself), decoded with
``os.fsdecode``; the black box redacts every target and detail like any other event.
"""

import errno
import logging
import os
import select
import stat
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from vigia.blackbox.model import Source
from vigia.sensors import inotify
from vigia.sensors.inotify import (
    IN_ATTRIB,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_DELETE_SELF,
    IN_EXCL_UNLINK,
    IN_IGNORED,
    IN_ISDIR,
    IN_MODIFY,
    IN_MOVE_SELF,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_ONLYDIR,
    IN_Q_OVERFLOW,
    Inotify,
    OpenBeneath,
    RawEvent,
    parse_events,
)
from vigia.snapshots.model import Snapshot, utc_now

logger = logging.getLogger(__name__)

WATCH_MASK = (
    IN_CREATE
    | IN_DELETE
    | IN_MODIFY
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_ATTRIB
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_ONLYDIR
    | IN_EXCL_UNLINK
)
# The sentinel watch on the workspace subvolume's root: only to learn that it was swapped.
SENTINEL_MASK = IN_MOVE_SELF | IN_DELETE_SELF | IN_ONLYDIR

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PARENT_FLAGS = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_CLOEXEC
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MAX_LINK_CHARS = 256
SUMMARY_SAMPLE = 20
SUMMARY_DIRS = 20
_SUMMARY_DIR_KEYS = 5000  # distinct directory prefixes kept while folding (then "…")
_UNWATCHED_KEPT = 10_000
_UNWATCHED_BYTES = 4 * 1024 * 1024  # of kept paths; beyond it they are only counted
_MAX_QUEUED_DIRS = 10_000  # directory jobs waiting for the scanner; more is left to a rescan
_MAX_READS_PER_BATCH = 64  # when the queue size cannot be asked (FIONREAD)
_ENTRY_OVERHEAD = 256  # bytes counted per pending path besides the path itself
MAX_NAME_CHARS = 255
# Open errors that say "try again later", not "this directory refuses to be watched".
_TRANSIENT = frozenset({errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.EINTR, errno.EAGAIN})
_JOIN_TIMEOUT = 30.0
_ARM_TIMEOUT = 120.0
_DRAIN_TIMEOUT = 5.0
_POLL_MS = 500
_SCAN_POLL = 0.2


# -- rate limits -------------------------------------------------------------------------


class TokenBucket:
    """A counter refilled at a fixed rate; each record spends one token. ``now`` is a
    monotonic reading in seconds. Starts full."""

    def __init__(self, rate: float, burst: int, now: float) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be positive and burst at least 1")
        self._rate = rate
        self._burst = float(burst)
        self._tokens = float(burst)
        self._last = now

    def take(self, now: float) -> bool:
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class DailyBudget:
    """At most ``limit`` records per window of ``window`` seconds. The window starts at the
    first record after the previous one ended."""

    def __init__(self, limit: int, window: float = 24 * 3600.0) -> None:
        if limit < 1 or window <= 0:
            raise ValueError("limit and window must be positive")
        self.limit = limit
        self._window = window
        self.window_start: float | None = None
        self.used = 0

    def _roll(self, now: float) -> None:
        if self.window_start is not None and now - self.window_start >= self._window:
            self.window_start, self.used = None, 0

    def exhausted(self, now: float) -> bool:
        self._roll(now)
        return self.used >= self.limit

    def try_spend(self, now: float) -> bool:
        if self.exhausted(now):
            return False
        if self.window_start is None:
            self.window_start = now
        self.used += 1
        return True


# -- the watch tree ----------------------------------------------------------------------


type Ident = tuple[int, int]  # (st_dev, st_ino): which directory a watch is on


class WatchTree:
    """The model ``wd -> (parent wd, name)``. No descriptor is kept per directory. A watch is
    stamped with the ``generation`` current when it was added or confirmed, so a full rescan
    can tell which entries it did not find again. Each watch also keeps the identity of its
    directory (device and inode), to check that a path rebuilt from the model still leads to
    that same directory before arming anything below it."""

    def __init__(self) -> None:
        self._parent: dict[int, tuple[int | None, bytes]] = {}
        self._kids: dict[int, dict[bytes, int]] = {}
        self._stamp: dict[int, int] = {}
        self._ident: dict[int, Ident] = {}
        self.generation = 0
        self.root: int | None = None

    def __len__(self) -> int:
        return len(self._parent)

    def __contains__(self, wd: object) -> bool:
        return wd in self._parent

    def add(self, wd: int, parent: int | None, name: bytes, ident: Ident | None = None) -> None:
        """Insert ``wd``, or move it if it is already known, and stamp it."""
        old = self._parent.get(wd)
        if old is not None:
            self._unlink(wd, old)
        self._parent[wd] = (parent, name)
        if parent is None:
            self.root = wd
        else:
            self._kids.setdefault(parent, {})[name] = wd
        self._stamp[wd] = self.generation
        if ident is not None:
            self._ident[wd] = ident

    def ident(self, wd: int) -> Ident | None:
        return self._ident.get(wd)

    def wds(self) -> list[int]:
        return list(self._parent)

    def touch(self, wd: int) -> None:
        if wd in self._parent:
            self._stamp[wd] = self.generation

    def _unlink(self, wd: int, entry: tuple[int | None, bytes]) -> None:
        parent, name = entry
        if parent is not None:
            siblings = self._kids.get(parent)
            if siblings is not None and siblings.get(name) == wd:
                del siblings[name]

    def remove(self, wd: int) -> bool:
        """Forget ``wd`` only (its children, if any, stay as orphans). False if unknown."""
        entry = self._parent.pop(wd, None)
        if entry is None:
            return False
        self._unlink(wd, entry)
        self._stamp.pop(wd, None)
        self._ident.pop(wd, None)
        self._kids.pop(wd, None)
        if self.root == wd:
            self.root = None
        return True

    def remove_subtree(self, wd: int) -> list[int]:
        """Forget ``wd`` and everything below it; return the wds forgotten."""
        removed: list[int] = []
        stack = [wd]
        while stack:
            current = stack.pop()
            stack.extend(self._kids.get(current, {}).values())
            if self.remove(current):
                removed.append(current)
        return removed

    def child(self, parent: int, name: bytes) -> int | None:
        return self._kids.get(parent, {}).get(name)

    def path(self, wd: int) -> bytes | None:
        """The path of ``wd`` below the root (``b""`` for the root), or None if unknown or
        orphaned. Iterative: a chain of thousands of directories is fine."""
        parts: list[bytes] = []
        current = wd
        for _ in range(len(self._parent) + 1):
            entry = self._parent.get(current)
            if entry is None:
                return None
            parent, name = entry
            if parent is None:
                return b"/".join(reversed(parts))
            parts.append(name)
            current = parent
        return None  # a cycle: a bug, but never an endless loop

    def depth(self, wd: int) -> int | None:
        """How many levels ``wd`` is below the root (0 for the root), or None if unknown."""
        depth, current = 0, wd
        for _ in range(len(self._parent) + 1):
            entry = self._parent.get(current)
            if entry is None:
                return None
            if entry[0] is None:
                return depth
            depth, current = depth + 1, entry[0]
        return None

    def height(self, wd: int, limit: int | None = None) -> int:
        """How many levels of watched directories hang below ``wd`` (0 if none). With a
        ``limit``, it stops at the first level beyond it (and returns that level): the
        caller only needs to know that it does not fit."""
        best = 0
        stack = [(wd, 0)]
        for _ in range(len(self._parent) + 1):  # never more nodes than the tree has
            if not stack:
                break
            current, level = stack.pop()
            best = max(best, level)
            if limit is not None and best > limit:
                return best
            stack.extend((kid, level + 1) for kid in self._kids.get(current, {}).values())
        return best

    def touch_subtree(self, wd: int) -> None:
        """Stamp ``wd`` and everything below it with the current generation."""
        stack = [wd]
        for _ in range(len(self._parent) + 1):
            if not stack:
                break
            current = stack.pop()
            self.touch(current)
            stack.extend(self._kids.get(current, {}).values())

    def is_below(self, wd: int, ancestor: int) -> bool:
        """Whether ``wd`` is ``ancestor`` or hangs somewhere below it."""
        current: int | None = wd
        for _ in range(len(self._parent) + 1):
            if current is None:
                return False
            if current == ancestor:
                return True
            entry = self._parent.get(current)
            current = entry[0] if entry is not None else None
        return False

    def find(self, rel: bytes) -> int | None:
        """The wd of the directory at ``rel`` (``b""`` or ``b"."`` is the root)."""
        current = self.root
        if current is None:
            return None
        for part in rel.split(b"/"):
            if part in (b"", b"."):
                continue
            current = self.child(current, part)
            if current is None:
                return None
        return current

    def stale(self) -> list[int]:
        """The wds not stamped in the current generation."""
        return [wd for wd, stamp in self._stamp.items() if stamp < self.generation]

    def clear(self) -> None:
        self._parent.clear()
        self._kids.clear()
        self._stamp.clear()
        self._ident.clear()
        self.root = None


class _Unwatched:
    """Directories we could not put a watch on, or not list: ``watch_limit``, ``depth``,
    ``refused`` (the kernel said no), ``raced`` (it changed under the walk: a rescan will
    confirm) and ``unlisted``. Bounded by count and by bytes: ``total`` is exact until the
    kept set is full."""

    def __init__(self) -> None:
        self.paths: dict[str, str] = {}
        self.total = 0
        self._bytes = 0

    def add(self, path: str, reason: str) -> None:
        if path in self.paths:
            return
        self.total += 1
        if len(self.paths) < _UNWATCHED_KEPT and self._bytes + len(path) <= _UNWATCHED_BYTES:
            self.paths[path] = reason
            self._bytes += len(path)

    def discard(self, path: str) -> None:
        if self.paths.pop(path, None) is not None:
            self.total -= 1
            self._bytes -= len(path)

    def reasons(self) -> dict[str, int]:
        return dict(Counter(self.paths.values()))

    def sample(self, size: int = SUMMARY_SAMPLE) -> list[str]:
        return list(self.paths)[:size]


# -- coalescing --------------------------------------------------------------------------


@dataclass(frozen=True)
class FileRecord:
    """The net effect on one path in one window. ``action`` is create, modify, delete or move."""

    action: str
    path: str
    is_dir: bool
    snapshot_id: str | None
    writes: int
    attrib: bool
    first: datetime
    last: datetime
    transient: bool = False  # created and deleted inside the window (recorded as delete)
    scan: bool = False  # found by walking a new directory, not by an event
    recreated: bool = False  # deleted and created again inside the window (recorded as modify)
    origin: str | None = None  # where a moved path came from


@dataclass
class _Pending:
    kind: str
    is_dir: bool
    first: datetime
    last: datetime
    snapshot_id: str | None
    writes: int = 0
    attrib: bool = False
    transient: bool = False
    scan: bool = False
    recreated: bool = False
    origin: str | None = None
    cost: int = 0  # bytes counted for it against the cap


@dataclass
class _Unpaired:
    path: str
    is_dir: bool
    seen: datetime
    snapshot_id: str | None
    pending: _Pending | None
    cost: int = 0


@dataclass(frozen=True)
class OverflowWindow:
    """A window in which changes were not described, since the last time it was taken:
    ``queue_overflow`` (the kernel queue overflowed: how many events were lost is unknown)
    or ``dir_queue_full`` (``overflows`` new directories were not walked when they appeared:
    a rescan walks them later, and what happened inside them meanwhile is lost)."""

    since: datetime
    until: datetime
    overflows: int
    snapshot_id: str | None  # the one current at the first overflow
    reason: str = "queue_overflow"


@dataclass(frozen=True)
class Flush:
    records: list[FileRecord]
    spilled: Counter[str]  # changes beyond the pending cap: only counted, by action


class Coalescer:
    """Turns raw changes into one record per path and window. Pure: the caller passes the time
    of observation and the snapshot id current at that moment; nothing here does I/O.

    Net effects: create+modify stays create; create+delete is a ``transient`` delete;
    delete+create is a ``recreated`` modify; a MOVED_FROM/MOVED_TO pair (same cookie) is ONE
    ``move`` with its origin, also for a directory; an unpaired MOVED_FROM is a delete after
    ``pair_grace`` and an unpaired MOVED_TO is a create.

    Memory is bounded by entries AND by bytes: beyond ``max_paths`` pending paths or
    ``max_bytes`` of them, new ones are only counted (``Flush.spilled``); beyond
    ``max_unpaired`` MOVED_FROM waiting for their pair, the oldest becomes a delete now."""

    def __init__(
        self,
        *,
        max_paths: int = 50_000,
        max_bytes: int = 32 * 1024 * 1024,
        max_unpaired: int = 10_000,
        pair_grace: timedelta = timedelta(seconds=1),
    ) -> None:
        self._max_paths = max_paths
        self._max_bytes = max_bytes
        self._max_unpaired = max(1, max_unpaired)
        self._grace = pair_grace
        self._pending: dict[str, _Pending] = {}
        self._unpaired: dict[int, _Unpaired] = {}
        self._bytes = 0
        self._spilled: Counter[str] = Counter()
        self._windows: dict[str, OverflowWindow] = {}

    def __len__(self) -> int:
        return len(self._pending)

    def unpaired(self) -> int:
        """MOVED_FROM still waiting for their MOVED_TO."""
        return len(self._unpaired)

    # events

    def created(
        self,
        path: str,
        *,
        is_dir: bool,
        now: datetime,
        snapshot_id: str | None,
        scan: bool = False,
    ) -> None:
        cur = self._pending.get(path)
        if cur is None:
            self._add(path, _Pending("create", is_dir, now, now, snapshot_id, scan=scan))
        elif cur.kind == "delete":
            self._resurrect(cur, now, is_dir=is_dir)
        else:
            cur.last = now  # known already: a walk that finds it again adds nothing

    def modified(self, path: str, *, now: datetime, snapshot_id: str | None, write: bool) -> None:
        """A write (IN_MODIFY, ``write=True``) or the close of a writer (``write=False``)."""
        self._touch(path, now, snapshot_id, writes=1 if write else 0, attrib=False)

    def attrib(self, path: str, *, now: datetime, snapshot_id: str | None) -> None:
        self._touch(path, now, snapshot_id, writes=0, attrib=True)

    def deleted(self, path: str, *, is_dir: bool, now: datetime, snapshot_id: str | None) -> None:
        cur = self._pending.get(path)
        if cur is None:
            self._add(path, _Pending("delete", is_dir, now, now, snapshot_id))
        elif cur.kind == "delete":
            cur.last = now
        elif cur.kind == "create":
            cur.kind, cur.transient, cur.last = "delete", True, now
        elif cur.kind == "move":
            origin, cur.origin = cur.origin, None
            cur.kind, cur.last = "delete", now
            if origin is not None and origin not in self._pending:
                self._add(origin, _Pending("delete", cur.is_dir, cur.first, now, cur.snapshot_id))
        else:
            cur.kind, cur.last = "delete", now

    def moved_from(
        self, path: str, cookie: int, *, is_dir: bool, now: datetime, snapshot_id: str | None
    ) -> None:
        while len(self._unpaired) >= self._max_unpaired:  # a storm of renames out: no pair
            self._expire(next(iter(self._unpaired)), now)
        before = self._pending.pop(path, None)
        if before is not None:
            self._bytes -= before.cost
        cost = len(path) + _ENTRY_OVERHEAD
        if self._bytes + cost > self._max_bytes:  # no room to wait for the pair: a delete now
            if before is not None:
                self._keep(path, before)
            self.deleted(path, is_dir=is_dir, now=now, snapshot_id=snapshot_id)
            return
        self._bytes += cost
        self._unpaired[cookie] = _Unpaired(path, is_dir, now, snapshot_id, before, cost)

    def moved_to(
        self, path: str, cookie: int, *, is_dir: bool, now: datetime, snapshot_id: str | None
    ) -> None:
        source = self._unpaired.pop(cookie, None)
        if source is None:  # it came from somewhere we do not watch
            self.created(path, is_dir=is_dir, now=now, snapshot_id=snapshot_id)
            return
        self._bytes -= source.cost
        before = source.pending
        entry = _Pending(
            "move",
            is_dir,
            before.first if before else source.seen,
            now,
            before.snapshot_id if before else source.snapshot_id,
            writes=before.writes if before else 0,
            attrib=before.attrib if before else False,
            origin=source.path,
        )
        if before is not None and before.kind == "create":
            # Born inside this window: at the destination it is a plain create.
            entry.kind, entry.origin, entry.scan = "create", None, before.scan
        elif before is not None and before.kind == "move":
            entry.origin = before.origin
        over = self._pending.get(path)
        if over is not None and over.first < entry.first:  # it replaced something older
            entry.first, entry.snapshot_id = over.first, over.snapshot_id
        if over is not None:
            self._bytes -= over.cost
            self._keep(path, entry)
        else:
            self._add(path, entry)

    def overflowed(
        self, now: datetime, snapshot_id: str | None, reason: str = "queue_overflow"
    ) -> None:
        cur = self._windows.get(reason)
        if cur is None:
            self._windows[reason] = OverflowWindow(now, now, 1, snapshot_id, reason)
        else:
            self._windows[reason] = replace(cur, until=now, overflows=cur.overflows + 1)

    # output

    def take_overflow(self) -> OverflowWindow | None:
        """The ``queue_overflow`` window, if any."""
        return self._windows.pop("queue_overflow", None)

    def take_windows(self) -> list[OverflowWindow]:
        """Every window of loss, oldest first; they start over."""
        windows = sorted(self._windows.values(), key=lambda w: w.since)
        self._windows = {}
        return windows

    def expire_moves(self, now: datetime, *, everything: bool = False) -> None:
        """Turn the MOVED_FROM that found no pair in ``pair_grace`` into deletes."""
        for cookie in [
            c for c, u in self._unpaired.items() if everything or now - u.seen >= self._grace
        ]:
            self._expire(cookie, now)

    def _expire(self, cookie: int, now: datetime) -> None:
        source = self._unpaired.pop(cookie)
        self._bytes -= source.cost
        before = source.pending
        if before is not None and source.path not in self._pending:
            self._keep(source.path, before)
        self.deleted(
            source.path,
            is_dir=source.is_dir,
            now=now,
            snapshot_id=before.snapshot_id if before else source.snapshot_id,
        )

    def flush(self, now: datetime, *, final: bool = False) -> Flush:
        """Everything pending, oldest first, and start a new window."""
        self.expire_moves(now, everything=final)
        records = [
            FileRecord(
                action=p.kind,
                path=path,
                is_dir=p.is_dir,
                snapshot_id=p.snapshot_id,
                writes=p.writes,
                attrib=p.attrib,
                first=p.first,
                last=p.last,
                transient=p.transient,
                scan=p.scan,
                recreated=p.recreated,
                origin=p.origin,
            )
            for path, p in self._pending.items()
        ]
        records.sort(key=lambda r: r.first)
        spilled, self._spilled = self._spilled, Counter()
        self._pending = {}
        self._bytes = sum(u.cost for u in self._unpaired.values())
        return Flush(records, spilled)

    # internals

    def _add(self, path: str, entry: _Pending) -> None:
        cost = _cost(path, entry)
        if len(self._pending) >= self._max_paths or self._bytes + cost > self._max_bytes:
            self._spilled[entry.kind] += 1
            return
        entry.cost = cost
        self._bytes += cost
        self._pending[path] = entry

    def _keep(self, path: str, entry: _Pending) -> None:
        """Put back an entry that was already pending (it held that memory before)."""
        entry.cost = _cost(path, entry)
        self._bytes += entry.cost
        self._pending[path] = entry

    def _touch(
        self, path: str, now: datetime, snapshot_id: str | None, *, writes: int, attrib: bool
    ) -> None:
        cur = self._pending.get(path)
        if cur is None:
            self._add(
                path,
                _Pending("modify", False, now, now, snapshot_id, writes=writes, attrib=attrib),
            )
            return
        if cur.kind == "delete":  # a change after a delete: it was recreated unseen
            self._resurrect(cur, now, is_dir=cur.is_dir)
        cur.writes += writes
        cur.attrib = cur.attrib or attrib
        cur.last = now

    @staticmethod
    def _resurrect(cur: _Pending, now: datetime, *, is_dir: bool) -> None:
        if cur.transient:  # it did not exist before this window: a create again
            cur.kind, cur.transient = "create", False
        else:
            cur.kind, cur.recreated = "modify", True
        cur.is_dir, cur.last = is_dir, now


class SummaryBuffer:
    """Accumulates the records that did not fit the rate limit, to write one ``file/summary``."""

    def __init__(self) -> None:
        self._reset()

    def _reset(self) -> None:
        self._counts: Counter[str] = Counter()
        self._dirs: Counter[str] = Counter()
        self._sample: list[str] = []
        self._folded = 0
        self._first: datetime | None = None
        self._last: datetime | None = None
        self._snapshot: str | None = None
        self._unknown_snapshot = False

    def __bool__(self) -> bool:
        return self._folded > 0

    def add(self, record: FileRecord) -> None:
        self._folded += 1
        self._counts[record.action] += 1
        key = _top_dirs(record.path)
        if key in self._dirs or len(self._dirs) < _SUMMARY_DIR_KEYS:
            self._dirs[key] += 1
        else:
            self._dirs["…"] += 1
        if len(self._sample) < SUMMARY_SAMPLE:
            self._sample.append(record.path)
        self._first = record.first if self._first is None else min(self._first, record.first)
        self._last = record.last if self._last is None else max(self._last, record.last)
        if record.snapshot_id is None:
            self._unknown_snapshot = True
        elif self._snapshot is None or record.snapshot_id < self._snapshot:
            self._snapshot = record.snapshot_id  # ids sort chronologically

    def add_spilled(self, spilled: Mapping[str, int], now: datetime) -> None:
        for action, count in spilled.items():
            self._folded += count
            self._counts[action] += count
            self._first = now if self._first is None else self._first
            self._last = now

    @property
    def snapshot_id(self) -> str | None:
        return None if self._unknown_snapshot else self._snapshot

    def build(self) -> dict[str, Any]:
        """The ``details`` of the summary; the buffer starts over."""
        assert self._first is not None and self._last is not None  # noqa: S101 - never empty
        details = {
            "window": {"from": _iso(self._first), "to": _iso(self._last)},
            "counts": dict(self._counts),
            "dirs": [{"dir": d, "count": c} for d, c in self._dirs.most_common(SUMMARY_DIRS)],
            "sample": list(self._sample),
            "folded": self._folded,
        }
        self._reset()
        return details


def _cost(path: str, entry: _Pending) -> int:
    return len(path) + len(entry.origin or "") + _ENTRY_OVERHEAD


def _top_dirs(path: str) -> str:
    """The directory of ``path`` cut to 2 levels: ``a/b/c/f.txt`` -> ``a/b``; ``f`` -> ``.``."""
    parts = path.split("/")[:-1]
    return "/".join(parts[:2]) or "."


def _iso(moment: datetime) -> str:
    return moment.strftime(_TS_FORMAT)


# -- the watcher -------------------------------------------------------------------------


class Recorder(Protocol):
    """What the watcher needs from the black box (``BlackBox.append``)."""

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


class InotifyBackend(Protocol):
    def fileno(self) -> int: ...
    def queued(self) -> int: ...
    def add_watch(self, dir_fd: int, mask: int) -> int: ...
    def rm_watch(self, wd: int) -> None: ...
    def read(self) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class WatcherConfig:
    """Limits of the watcher. The defaults are the ones in docs/19; tests lower them."""

    max_watches: int | None = None  # None: min(8192, 25 % of the user's max_user_watches)
    max_depth: int = 64
    dump_interval: float | None = 2.0  # None: no dumper thread (tests call flush())
    bucket_rate: float = 5.0  # records per second
    bucket_burst: int = 1000
    summary_interval: float = 10.0
    daily_budget: int = 50_000
    budget_window: float = 24 * 3600.0
    over_budget_summary_interval: float = 60.0
    max_pending_paths: int = 50_000
    max_pending_bytes: int = 32 * 1024 * 1024
    max_unpaired: int = 10_000  # MOVED_FROM waiting for their pair
    rescan_cooldown: float = 30.0
    pair_grace: float = 1.0
    scan_chunk: int = 64  # directories walked before yielding the lock
    settle: float = 0.1  # the wait of the second drain of the snapshot barrier


@dataclass
class WatcherStats:
    events: int = 0
    overflows: int = 0
    rescans: int = 0
    unknown_wd: int = 0
    errors: int = 0
    records: int = 0
    folded: int = 0
    lost: int = 0


@dataclass(frozen=True)
class BlackBoxHealth:
    """For the P7 pause: appends that failed in a row, since when (monotonic), and how many
    records were lost while it failed."""

    consecutive_failures: int
    failing_since: float | None
    lost: int


@dataclass
class _Job:
    """``initial`` and ``rescan`` walk from the root. ``dir`` arms and walks the entry ``name``
    of the watched directory ``parent``: by watch, not by path, so a rename of an ancestor
    while the job waits does not lose it."""

    kind: str  # "initial", "dir" or "rescan"
    parent: int | None = None
    name: bytes = b""
    snapshot_id: str | None = None
    emit: bool = False


@dataclass(frozen=True)
class _Ref:
    """A directory for the walk to arm and list: the entry ``name`` of the watch ``parent``.
    Its depth is not kept: it is taken from the model when it is armed, because an ancestor
    may move while it waits."""

    parent: int
    name: bytes


class _Stale(Exception):  # noqa: N818 - a signal inside the walk, not an error to report
    """A watched directory cannot be reopened as the same directory from the model."""


class _Waker:
    """Wakes the reader out of poll(): an eventfd on Linux, a pipe elsewhere."""

    def __init__(self) -> None:
        self._event = hasattr(os, "eventfd")
        if self._event:
            self._r = self._w = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        else:
            self._r, self._w = os.pipe()
            os.set_blocking(self._r, False)
            os.set_blocking(self._w, False)

    def fileno(self) -> int:
        return self._r

    def set(self) -> None:
        try:
            if self._event:
                os.eventfd_write(self._w, 1)
            else:
                os.write(self._w, b"\0")
        except BlockingIOError:
            pass  # already signalled

    def clear(self) -> None:
        try:
            if self._event:
                os.eventfd_read(self._r)
            else:
                os.read(self._r, 4096)
        except BlockingIOError:
            pass

    def close(self) -> None:
        os.close(self._r)
        if self._w != self._r:
            os.close(self._w)


class FileWatcher:
    """Watches ``agent_dir`` (the agent's ``/workspace``) and records ``file`` events.

    Normal life: ``arm()`` before the agent starts; take every snapshot through
    ``barrier(take)``; call ``rearm_if_moved(workspace_id)`` and, when Btrfs says something
    changed, ``report_unwatched()`` once per cycle; rewind inside ``suspended(target)``;
    ``close()`` at the end. Nothing here raises for an environmental failure: it records
    ``system/watcher_failed`` (or ``watcher_lost``) and logs, because a security tool that dies
    quietly is worse than one that says it is blind.

    ``workspace_id`` is ``SnapshotStore.workspace_id``: it changes exactly when a restore swaps
    the workspace. Threads: see the module docstring."""

    def __init__(
        self,
        agent_dir: Path,
        blackbox: Recorder,
        *,
        workspace_id: Callable[[], int],
        config: WatcherConfig | None = None,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        inotify_factory: Callable[[], InotifyBackend] = Inotify,
        open_beneath: OpenBeneath = inotify.open_beneath,
    ) -> None:
        agent_dir = Path(agent_dir)
        if not agent_dir.is_absolute():
            raise ValueError(f"the agent folder must be an absolute path, got {str(agent_dir)!r}")
        self._agent_dir = agent_dir
        self._ws_dir = agent_dir.parent
        self._agent_name = agent_dir.name
        self._box = blackbox
        self._workspace_id_of = workspace_id
        self._cfg = config or WatcherConfig()
        self._clock = clock
        self._mono = monotonic
        self._sleep = sleep
        self._factory = inotify_factory
        self._open_beneath = open_beneath
        self._max_watches = self._cfg.max_watches or min(8192, inotify.max_user_watches() // 4)

        # State shared by the threads (guarded by _lock; _cond uses the same lock).
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._arm_lock = threading.RLock()  # arm / disarm / suspended transitions
        self._emit_lock = threading.Lock()  # one flush at a time
        self._state = "unarmed"  # unarmed | armed | suspended | closed
        self._want_armed = False
        self._tree = WatchTree()
        self._coalescer = self._new_coalescer()
        self._unwatched = _Unwatched()
        self._current: str | None = None
        self._ws_id: int | None = None
        self._dir_froms: dict[int, tuple[int, datetime]] = {}  # cookie -> (wd, seen)
        self._dir_from_of: dict[int, int] = {}  # wd -> cookie: one pending move per directory
        self._jobs: deque[_Job] = deque()
        self._queued_dirs: set[tuple[int, bytes]] = set()
        self._busy = False
        self._rescan_wanted = False
        self._rescan_emit = False
        self._rescan_sid: str | None = None  # the oldest snapshot current at a request
        self._rescan_sid_unknown = False
        self._rescanning = False
        self._rescan_walk_sid: str | None = None  # the snapshot of the rescan that is running
        self._last_rescan: float | None = None
        self._gen = 0  # one per armed period: a thread of an older one touches nothing
        self._orphans: set[int] = set()  # periods whose reader was left running
        self._refusals: Counter[tuple[str, int | None]] = Counter()
        self._drain_wanted = 0
        self._drain_done = 0
        self._reader_alive = False
        self._disarming = False
        self._anomaly: str | None = None
        self._stats = WatcherStats()

        # Resources of one armed period.
        self._ino: InotifyBackend | None = None
        self._ws_fd: int | None = None
        self._root_fd: int | None = None
        self._sentinel_wd: int | None = None
        self._waker: _Waker | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        # Rate limits and the record of what is lost (guarded by _emit_lock).
        self._bucket = TokenBucket(self._cfg.bucket_rate, self._cfg.bucket_burst, monotonic())
        self._budget = DailyBudget(self._cfg.daily_budget, self._cfg.budget_window)
        self._budget_alerted: float | None = None
        self._summary = SummaryBuffer()
        self._last_summary: float | None = None
        self._lost = 0
        self._lost_snapshot: str | None = None
        self._flush_failed = False
        self._failures = 0
        self._failing_since: float | None = None
        self._arm_error: str | None = None
        self._suspended_ws_id: int | None = None

    def _new_coalescer(self) -> Coalescer:
        return Coalescer(
            max_paths=self._cfg.max_pending_paths,
            max_bytes=self._cfg.max_pending_bytes,
            max_unpaired=self._cfg.max_unpaired,
            pair_grace=timedelta(seconds=self._cfg.pair_grace),
        )

    # -- public API --------------------------------------------------------------------

    @property
    def current(self) -> str | None:
        """The snapshot id the next first-seen change will point to."""
        with self._lock:
            return self._current

    def set_current(self, snapshot_id: str | None) -> None:
        with self._lock:
            self._current = snapshot_id

    @property
    def is_armed(self) -> bool:
        return self._state == "armed"

    @property
    def is_suspended(self) -> bool:
        return self._state == "suspended"

    def stats(self) -> WatcherStats:
        with self._lock:
            return replace(self._stats)

    def watch_count(self) -> int:
        """Directories being watched (without the sentinel)."""
        with self._lock:
            return len(self._tree)

    def unwatched_count(self) -> int:
        with self._lock:
            return self._unwatched.total

    def blackbox_health(self) -> BlackBoxHealth:
        """Read without ``_emit_lock``, which is held while a whole batch is written: the space
        thread asks every second and must never wait for an avalanche of events (a late check
        is P4). Three plain reads; a value one batch old is fine for P7."""
        return BlackBoxHealth(self._failures, self._failing_since, self._lost)

    def arm(self, current: str | None = None) -> bool:
        """Put the watches on the agent's folder, before the agent starts. ``current`` is the
        snapshot id changes point to from now on. Returns whether it is armed: on failure
        (no inotify instances left, no watches left) it records ``system/watcher_failed``
        and the next ``rearm_if_moved`` tries again; the agent can run meanwhile, because
        snapshots do not depend on this."""
        with self._arm_lock:
            if self._state == "closed":
                return False
            if current is not None:
                self.set_current(current)
            if self._state == "armed":
                return True
            if self._state == "suspended":
                return False
            return self._arm_locked()

    def drain(self, settle: float = 0.0) -> bool:
        """Wait for the reader to have read everything that was in the kernel queue when this
        was called (after sleeping ``settle`` seconds, for events still in flight). Returns
        False if it did not finish in time, or nothing is armed."""
        if settle > 0:
            self._sleep(settle)
        with self._cond:
            waker = self._waker
            if self._state != "armed" or not self._reader_alive or waker is None:
                return False
            self._drain_wanted += 1
            ticket = self._drain_wanted
            waker.set()
            done = self._cond.wait_for(
                lambda: self._drain_done >= ticket or not self._reader_alive, _DRAIN_TIMEOUT
            )
            ok = done and self._drain_done >= ticket
        if not ok:
            logger.warning("the file watcher did not drain its queue in %s s", _DRAIN_TIMEOUT)
        return ok

    def barrier(self, take: Callable[[], Snapshot]) -> Snapshot:
        """Run ``take`` (which makes a snapshot) so that no change is pointed at a snapshot
        that already contains it: drain, take (S2), drain again (what arrived meanwhile still
        points to the previous one, which is older), and only then make S2 the current one.
        If ``take`` raises, the current snapshot stays. If the second drain does not finish
        while the reader is running, it stays too: what is still unread may predate S2."""
        self.drain()
        snapshot = take()
        if self.drain(self._cfg.settle) or not self._reading():
            self.set_current(snapshot.id)
        else:
            logger.warning(
                "the file watcher did not drain after a snapshot: changes keep pointing to the "
                "previous one"
            )
        return snapshot

    def _reading(self) -> bool:
        with self._lock:
            return self._state == "armed" and self._reader_alive

    def rearm_if_moved(self, workspace_id: int) -> bool:
        """The safety net of every cycle: if the workspace is not the one we watch, record
        ``system/watcher_lost`` and watch the new one; if the last arming failed, try again.
        Does nothing while suspended (a rewind is swapping it) or closed. Returns whether it
        rearmed."""
        with self._arm_lock:
            if self._state in ("suspended", "closed"):
                return False
            if self._state == "unarmed":
                return self._arm_locked() if self._want_armed else False
            if workspace_id == self._ws_id:
                return False
            self._record_system(
                "watcher_lost",
                {"reason": "workspace_changed", "from": self._ws_id, "to": workspace_id},
                risk=2,
            )
            logger.warning("the workspace changed under the file watcher: arming it again")
            self._disarm_quietly()
            return self._arm_locked()

    def report_unwatched(self) -> bool:
        """Call it in every cycle in which Btrfs says the workspace changed: if some directories
        have no watch, record ``file/dropped {unwatched_dirs}``. Returns whether it recorded."""
        with self._lock:
            total = self._unwatched.total
            sample = self._unwatched.sample()
            reasons = self._unwatched.reasons()
        if total == 0:
            return False
        self.record_dropped("unwatched_dirs", count=total, sample=sample, reasons=reasons)
        return True

    def record_dropped(
        self,
        reason: str,
        *,
        count: int | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        snapshot_id: str | None = None,
        **extra: Any,
    ) -> bool:
        """Write a ``file/dropped`` (risk 1): changes we know we did not describe. Returns
        whether the black box took it."""
        details: dict[str, Any] = {"reason": reason, "count": count, **extra}
        if since is not None:
            details["since"] = _iso(since)
        if until is not None:
            details["until"] = _iso(until)
        with self._emit_lock:
            self._flush_failed = False
            return self._safe_append(
                "dropped", ".", details, risk=1, snapshot_id=snapshot_id or self.current
            )

    def flush(self, *, final: bool = False) -> None:
        """Write what is pending now (the dumper calls it every ``dump_interval`` seconds)."""
        self._flush(final=final, timeout=-1)

    def _flush(self, *, final: bool, timeout: float) -> bool:
        """``flush`` waiting at most ``timeout`` seconds (-1: forever) for another writer.
        The root descriptor is only closed under ``_emit_lock``, so it is valid all along."""
        if not self._emit_lock.acquire(timeout=timeout):
            return False
        try:
            with self._lock:
                now = self._clock()
                batch = self._coalescer.flush(now, final=final)
                ws_id = self._ws_id
                root_fd = self._root_fd
            self._emit(batch, now, ws_id, root_fd, final=final)
        finally:
            self._emit_lock.release()
        return True

    def wait_idle(self, timeout: float = 10.0) -> bool:
        """Wait until the scanner has nothing queued or running."""
        with self._cond:
            return self._cond.wait_for(
                lambda: not self._jobs and not self._busy and not self._rescan_due(), timeout
            )

    @contextmanager
    def suspended(self, new_current: str | None = None) -> Iterator[None]:
        """Around a rewind's swap of the workspace. On entry: drain the queue, write what is
        pending (with the old workspace id) and only then close inotify, so nothing keeps
        watching the old workspace. On exit: if the workspace did change, ``new_current`` (the
        snapshot rewound to) becomes the current one, and the new workspace is armed.

        Never raises, on entry or exit: a failure becomes ``system/watcher_failed``."""
        entered = self._enter_suspended()
        try:
            yield
        finally:
            if entered:
                self._exit_suspended(new_current)

    def close(self) -> None:
        """Stop for good: drain, write what is pending, close everything."""
        with self._arm_lock:
            if self._state == "armed":
                self._disarm_quietly()
            self._state = "closed"

    # -- arming ------------------------------------------------------------------------

    def _arm_locked(self) -> bool:
        self._want_armed = True
        try:
            self._open_and_start()
        except Exception as exc:  # noqa: BLE001 - recorded below, never silent
            self._arm_failed(exc)
            return False
        self._arm_error = None
        return True

    def _open_and_start(self) -> None:
        ws_id = self._workspace_id_of()  # BEFORE opening: a swap in between is seen later
        ino = self._factory()
        ws_fd = root_fd = None
        try:
            ws_fd = os.open(self._ws_dir, _DIR_FLAGS)
            root_fd = os.open(self._agent_name, _DIR_FLAGS, dir_fd=ws_fd)
            root_stat = os.fstat(root_fd)
            sentinel = ino.add_watch(ws_fd, SENTINEL_MASK)
            root_wd = ino.add_watch(root_fd, WATCH_MASK)
            waker = _Waker()
        except BaseException:
            for fd in (root_fd, ws_fd):
                if fd is not None:
                    os.close(fd)
            ino.close()
            raise
        with self._lock:
            self._ino, self._ws_fd, self._root_fd = ino, ws_fd, root_fd
            self._sentinel_wd, self._waker = sentinel, waker
            self._ws_id = ws_id
            self._gen += 1
            gen = self._gen
            self._tree.clear()
            self._tree.add(root_wd, None, b"", (root_stat.st_dev, root_stat.st_ino))
            self._coalescer = self._new_coalescer()
            self._unwatched = _Unwatched()
            self._dir_froms.clear()
            self._dir_from_of.clear()
            self._jobs.clear()
            self._queued_dirs.clear()
            self._rescan_wanted = self._rescan_emit = self._rescan_sid_unknown = False
            self._rescan_sid = None
            self._rescanning = False
            self._rescan_walk_sid = None
            self._refusals.clear()
            self._anomaly = None
            self._disarming = False
            self._drain_wanted = self._drain_done = 0
            self._stop = threading.Event()
            self._state = "armed"
            self._jobs.append(_Job("initial"))
        self._start_threads(gen)
        if not self.wait_idle(_ARM_TIMEOUT):
            logger.warning("the file watcher is still arming after %s s", _ARM_TIMEOUT)
        with self._lock:
            details = {
                "workspace_id": ws_id,
                "dirs": len(self._tree),
                "unwatched": self._unwatched.total,
                "max_watches": self._max_watches,
            }
        self._record_system("watcher_armed", details, risk=0)

    def _arm_failed(self, exc: Exception) -> None:
        message = str(exc)
        logger.error("the file watcher cannot arm: %s", message)
        if message != self._arm_error:  # once per distinct failure, not once per retry
            self._arm_error = message
            self._record_system(
                "watcher_failed",
                {"reason": "arm", "error": message, "errno": getattr(exc, "errno", None)},
                risk=2,
            )

    def _start_threads(self, gen: int) -> None:
        stop = self._stop
        ino, waker = self._ino, self._waker
        assert ino is not None and waker is not None  # noqa: S101 - set just before
        targets: list[tuple[str, Callable[[], None]]] = [
            ("vigia-watch-reader", lambda: self._read_loop(ino, waker, stop, gen)),
            ("vigia-watch-scanner", lambda: self._scan_loop(stop, gen)),
        ]
        if self._cfg.dump_interval is not None:
            targets.append(("vigia-watch-dumper", lambda: self._dump_loop(stop)))
        self._threads = [threading.Thread(target=t, name=n, daemon=True) for n, t in targets]
        self._reader_alive = True
        for thread in self._threads:
            thread.start()

    def _disarm_quietly(self) -> None:
        """Stop, write what is pending and close. A failure is logged and recorded."""
        try:
            self._disarm()
        except Exception as exc:  # noqa: BLE001 - recorded, and the caller goes on
            logger.exception("the file watcher did not stop cleanly")
            self._record_system("watcher_failed", {"reason": "disarm", "error": str(exc)}, risk=2)
            self._state = "unarmed"

    def _disarm(self) -> None:
        """Signal stop, wait for the threads, write what is pending and close. A thread that
        does not stop is never left with descriptors it could reuse: a stuck reader keeps its
        inotify instance (closing it would let another file take the number) but loses every
        watch, and its period is marked so that it touches nothing of the next one."""
        with self._cond:
            self._disarming = True
            self._stop.set()
            if self._waker is not None:
                self._waker.set()
            self._cond.notify_all()
        threads, self._threads = self._threads, []
        for thread in threads:  # scanner first, so the reader drains what it added
            if thread.name == "vigia-watch-scanner":
                self._join(thread)
        for thread in threads:
            if thread.name != "vigia-watch-scanner":
                self._join(thread)
        stuck = sorted(t.name.removeprefix("vigia-watch-") for t in threads if t.is_alive())
        writer_free = "dumper" not in stuck and self._flush(final=True, timeout=_JOIN_TIMEOUT)
        if writer_free:
            self._report_windows()
        with self._lock:
            ino, waker = self._ino, self._waker
            fds = [fd for fd in (self._root_fd, self._ws_fd) if fd is not None]
            reader_stuck = self._reader_alive  # its own exit clears it, under this lock
            if reader_stuck and ino is not None:
                self._orphans.add(self._gen)
                for wd in [*self._tree.wds(), self._sentinel_wd]:
                    if wd is not None:
                        try:
                            ino.rm_watch(wd)
                        except OSError as exc:
                            logger.debug("rm_watch(%d) under a stuck reader: %s", wd, exc)
            self._gen += 1
            self._reader_alive = False
            self._ino = self._waker = self._root_fd = self._ws_fd = None
            self._sentinel_wd = None
            self._tree.clear()
            self._unwatched = _Unwatched()
            self._dir_froms.clear()
            self._dir_from_of.clear()
            self._jobs.clear()
            self._queued_dirs.clear()
            self._state = "unarmed"
        if reader_stuck and "reader" not in stuck:
            stuck.append("reader")
        if stuck:
            logger.error("file watcher threads did not stop: %s", ", ".join(stuck))
            self._record_system(
                "watcher_failed",
                {"reason": "reader_stuck" if reader_stuck else "thread_stuck", "threads": stuck},
                risk=2,
            )
        if not reader_stuck:
            if ino is not None:
                ino.close()
            if waker is not None:
                waker.close()
        if "scanner" in stuck or not self._close_fds(fds):
            logger.error("the file watcher left its folder descriptors open")

    def _close_fds(self, fds: list[int]) -> bool:
        """Close the folder descriptors when no flush can be using them."""
        if not self._emit_lock.acquire(timeout=_JOIN_TIMEOUT):
            return False
        try:
            for fd in fds:
                os.close(fd)
        finally:
            self._emit_lock.release()
        return True

    @staticmethod
    def _join(thread: threading.Thread) -> bool:
        """Join; True if the thread is still alive afterwards."""
        thread.join(_JOIN_TIMEOUT)
        return thread.is_alive()

    def _enter_suspended(self) -> bool:
        try:
            with self._arm_lock:
                if self._state in ("suspended", "closed"):
                    return False
                try:
                    self._suspended_ws_id = self._workspace_id_of()
                except Exception:  # noqa: BLE001 - we only lose the "did it swap?" check
                    logger.exception("cannot read the workspace id before suspending")
                    self._suspended_ws_id = None
                if self._state == "armed":
                    self._disarm_quietly()
                self._state = "suspended"
                return True
        except Exception as exc:  # noqa: BLE001 - suspended() never raises
            logger.exception("the file watcher could not be suspended")
            self._record_system("watcher_failed", {"reason": "suspend", "error": str(exc)}, risk=2)
            return False

    def _exit_suspended(self, new_current: str | None) -> None:
        try:
            with self._arm_lock:
                if self._state != "suspended":
                    return
                if new_current is not None and self._swapped():
                    self.set_current(new_current)
                self._state = "unarmed"
                self._arm_locked()
        except Exception as exc:  # noqa: BLE001 - suspended() never raises
            logger.exception("the file watcher could not be armed after the rewind")
            self._state = "unarmed"
            self._record_system("watcher_failed", {"reason": "rearm", "error": str(exc)}, risk=2)

    def _swapped(self) -> bool:
        """Did the workspace change while suspended? If we cannot tell, assume it did: the
        rewind target is older, so pointing at it is the safe side."""
        try:
            return self._workspace_id_of() != self._suspended_ws_id
        except Exception:  # noqa: BLE001
            logger.exception("cannot read the workspace id after the rewind")
            return True

    # -- the reader --------------------------------------------------------------------

    def _read_loop(
        self, ino: InotifyBackend, waker: _Waker, stop: threading.Event, gen: int
    ) -> None:
        poller = select.poll()
        poller.register(ino.fileno(), select.POLLIN)
        poller.register(waker.fileno(), select.POLLIN)
        try:
            while True:
                poller.poll(_POLL_MS)
                stopping = stop.is_set()
                waker.clear()  # before the snapshot below: a later wake is never lost
                with self._cond:
                    if self._gen != gen:
                        return
                    wanted = self._drain_wanted
                try:
                    # Only what is queued NOW: a queue that never empties cannot keep the
                    # reader from answering drain(), expiring moves or seeing the stop.
                    self._read_batch(ino, gen)
                    self._expire_unpaired(ino, gen)
                except Exception:  # noqa: BLE001 - the reader must not die quietly
                    logger.exception("the file watcher failed reading its queue")
                    time.sleep(0.05)
                with self._cond:
                    if self._gen == gen:
                        self._drain_done = max(self._drain_done, wanted)
                    self._cond.notify_all()
                if stopping:
                    return
        finally:
            with self._cond:
                orphan = gen in self._orphans
                self._orphans.discard(gen)
                if self._gen == gen:
                    self._reader_alive = False
                self._cond.notify_all()
            if orphan:  # its period was closed without it: the instance is only its own
                ino.close()
                waker.close()

    def _read_batch(self, ino: InotifyBackend, gen: int) -> None:
        """Read the bytes that were queued when it started (FIONREAD), and no more."""
        try:
            target: int | None = ino.queued()
        except (OSError, ValueError) as exc:
            logger.debug("cannot ask the inotify queue size: %s", exc)
            target = None
        consumed = reads = 0
        while target is None or consumed < target:
            if target is None and reads >= _MAX_READS_PER_BATCH:
                return
            data = ino.read()
            if not data:
                return
            reads += 1
            consumed += len(data)
            try:
                events = parse_events(data)
            except ValueError:
                logger.exception("the file watcher read a broken inotify buffer")
                self._note_unreadable(gen)
                continue
            now = self._clock()
            with self._lock:
                if self._gen != gen:
                    return
                for event in events:
                    try:
                        self._handle(event, now, ino)
                    except Exception:  # noqa: BLE001 - one bad event never stops the rest
                        self._stats.errors += 1
                        logger.exception("the file watcher failed handling an event")

    def _note_unreadable(self, gen: int) -> None:
        """The reader (which never touches the black box) lost a buffer: count it like an
        overflow, so it ends in a ``dropped`` and a rescan."""
        with self._cond:
            if self._gen != gen:
                return
            self._coalescer.overflowed(self._clock(), self._current)
            self._want_rescan(self._current, emit=True)

    def _want_rescan(self, snapshot_id: str | None, *, emit: bool, unknown: bool = False) -> None:
        """Ask the scanner for a full walk (at most one per ``rescan_cooldown``). What it
        finds points to the OLDEST snapshot current at any request since the last walk, or
        to none (``unknown``) when the loss may be older than any of them. Under _lock."""
        if unknown or snapshot_id is None:
            self._rescan_sid_unknown = True
        elif self._rescan_sid is None or snapshot_id < self._rescan_sid:
            self._rescan_sid = snapshot_id  # ids sort chronologically
        self._rescan_wanted = True
        self._rescan_emit = self._rescan_emit or emit
        self._cond.notify_all()

    def _handle(self, ev: RawEvent, now: datetime, ino: InotifyBackend) -> None:
        self._stats.events += 1
        mask = ev.mask
        if mask & IN_Q_OVERFLOW:
            self._stats.overflows += 1
            self._coalescer.overflowed(now, self._current)
            self._want_rescan(self._current, emit=True)
            return
        if ev.wd == self._sentinel_wd:
            if mask & (IN_MOVE_SELF | IN_DELETE_SELF | IN_IGNORED):
                self._flag_anomaly("the workspace folder was moved or deleted")
            return
        if mask & IN_IGNORED:
            self._on_ignored(ev.wd)
            return
        base = self._tree.path(ev.wd)
        if base is None:
            self._stats.unknown_wd += 1  # a watch we already dropped: its tail of events
            return
        if mask & (IN_MOVE_SELF | IN_DELETE_SELF):
            if ev.wd == self._tree.root:
                self._flag_anomaly("the agent folder was moved or deleted")
            return  # a subdirectory: its parent reports the move or delete
        raw = base + b"/" + ev.name if base and ev.name else (ev.name or base)
        path = os.fsdecode(raw) or "."
        is_dir = bool(mask & IN_ISDIR)
        sid = self._current
        co = self._coalescer
        if mask & IN_CREATE:
            co.created(path, is_dir=is_dir, now=now, snapshot_id=sid)
            if is_dir:
                self._queue_dir(ev.wd, ev.name, sid, now)
        elif mask & IN_DELETE:
            co.deleted(path, is_dir=is_dir, now=now, snapshot_id=sid)
            if is_dir:
                self._unwatched.discard(path)
        elif mask & IN_MODIFY:
            co.modified(path, now=now, snapshot_id=sid, write=True)
        elif mask & IN_CLOSE_WRITE:
            co.modified(path, now=now, snapshot_id=sid, write=False)
        elif mask & IN_ATTRIB:
            co.attrib(path, now=now, snapshot_id=sid)
        elif mask & IN_MOVED_FROM:
            child = self._tree.child(ev.wd, ev.name) if is_dir else None
            if child is not None:
                self._note_dir_from(ev.cookie, child, now)
            co.moved_from(path, ev.cookie, is_dir=is_dir, now=now, snapshot_id=sid)
        elif mask & IN_MOVED_TO:
            moved = self._pop_dir_from(ev.cookie) if is_dir else None
            if moved is not None:
                self._move_dir(moved, ev.wd, ev.name, sid, now, ino)
            elif is_dir:
                self._queue_dir(ev.wd, ev.name, sid, now)  # it came from outside: walk it
            co.moved_to(path, ev.cookie, is_dir=is_dir, now=now, snapshot_id=sid)

    def _note_dir_from(self, cookie: int, wd: int, now: datetime) -> None:
        """One pending move per watched directory: a newer MOVED_FROM replaces the older one
        (so a storm of renames cannot grow this beyond the number of watches)."""
        older = self._dir_from_of.pop(wd, None)
        if older is not None:
            self._dir_froms.pop(older, None)
        self._dir_froms[cookie] = (wd, now)
        self._dir_from_of[wd] = cookie

    def _pop_dir_from(self, cookie: int) -> int | None:
        entry = self._dir_froms.pop(cookie, None)
        if entry is None:
            return None
        if self._dir_from_of.get(entry[0]) == cookie:
            del self._dir_from_of[entry[0]]
        return entry[0]

    def _move_dir(
        self,
        wd: int,
        parent: int,
        name: bytes,
        snapshot_id: str | None,
        now: datetime,
        ino: InotifyBackend,
    ) -> None:
        """The same watch in a new place, if the whole subtree still fits the depth cap.
        If not (an agent moving chains into each other's leaves to build endless paths), the
        subtree loses its watches and is walked again from its new place, which applies the
        cap and records what does not fit.

        During a rescan, the walk may already have listed the old parent and find nothing
        under the old name: the moved subtree is stamped as found (its watches are not
        dropped as vanished at the end) and walked again from its new place."""
        depth = self._tree.depth(parent)
        room = self._cfg.max_depth - depth - 1 if depth is not None else -1
        if (
            room >= 0
            and not self._tree.is_below(parent, wd)
            and self._tree.height(wd, limit=room) <= room
        ):
            self._tree.add(wd, parent, name)
            if self._rescanning:
                self._tree.touch_subtree(wd)
                self._queue_dir(parent, name, self._rescan_walk_sid, now)
            return
        for gone in self._tree.remove_subtree(wd):
            try:
                ino.rm_watch(gone)
            except OSError as exc:
                logger.debug("rm_watch(%d) of a subtree moved too deep: %s", gone, exc)
        self._queue_dir(parent, name, snapshot_id, now, emit=False)  # the move says it all

    def _on_ignored(self, wd: int) -> None:
        if wd == self._tree.root:
            self._flag_anomaly("the agent folder lost its watch")
            return
        if self._tree.remove(wd) and self._unwatched.total:
            # A watch was freed: arm the folders that did not fit. They were blind for an
            # unknown time, so what the walk finds has no snapshot to point to.
            self._want_rescan(None, emit=False, unknown=True)

    def _expire_unpaired(self, ino: InotifyBackend, gen: int) -> None:
        now = self._clock()
        with self._lock:
            if self._gen != gen:
                return
            self._coalescer.expire_moves(now)
            grace = timedelta(seconds=self._cfg.pair_grace)
            for cookie in [c for c, (_, seen) in self._dir_froms.items() if now - seen >= grace]:
                wd = self._pop_dir_from(cookie)
                if wd is None:
                    continue
                for gone in self._tree.remove_subtree(wd):  # moved out of the watched tree
                    try:
                        ino.rm_watch(gone)
                    except OSError as exc:
                        logger.debug("rm_watch(%d) after a move out failed: %s", gone, exc)

    def _flag_anomaly(self, message: str) -> None:
        """A root watch got MOVE_SELF, DELETE_SELF or IGNORED outside a rewind."""
        if self._disarming or self._anomaly is not None:
            return
        self._anomaly = message
        threading.Thread(
            target=self._rearm_after_anomaly, args=(message,), name="vigia-watch-rearm", daemon=True
        ).start()

    def _rearm_after_anomaly(self, message: str) -> None:
        with self._arm_lock:
            if self._state != "armed" or self._anomaly is None:
                return
            self._record_system("watcher_lost", {"reason": "root_watch", "error": message}, risk=2)
            logger.warning("file watcher: %s: arming it again", message)
            self._disarm_quietly()
            self._arm_locked()

    def _queue_dir(
        self,
        parent: int,
        name: bytes,
        snapshot_id: str | None,
        now: datetime,
        *,
        emit: bool = True,
    ) -> None:
        key = (parent, name)
        if key in self._queued_dirs:
            return
        if len(self._jobs) >= _MAX_QUEUED_DIRS:
            # A bomb of directories faster than the scanner: do not queue without bound. The
            # next rescan finds them (and reports them as scanned); until then they are blind,
            # and that window is written as a ``dropped``.
            self._coalescer.overflowed(now, snapshot_id, reason="dir_queue_full")
            self._want_rescan(snapshot_id, emit=True)
            return
        self._queued_dirs.add(key)
        self._jobs.append(_Job("dir", parent, name, snapshot_id, emit=emit))
        self._cond.notify_all()

    # -- the scanner -------------------------------------------------------------------

    def _rescan_due(self) -> bool:
        if not self._rescan_wanted:
            return False
        last = self._last_rescan
        return last is None or self._mono() - last >= self._cfg.rescan_cooldown

    def _scan_loop(self, stop: threading.Event, gen: int) -> None:
        while True:
            with self._cond:
                job: _Job | None = None
                while not stop.is_set() and self._gen == gen:
                    if self._rescan_due():
                        sid = None if self._rescan_sid_unknown else self._rescan_sid
                        job = _Job("rescan", emit=self._rescan_emit, snapshot_id=sid)
                        self._rescan_wanted = self._rescan_emit = False
                        self._rescan_sid, self._rescan_sid_unknown = None, False
                        self._last_rescan = self._mono()
                    elif self._jobs:
                        job = self._jobs.popleft()
                        if job.parent is not None:
                            self._queued_dirs.discard((job.parent, job.name))
                    if job is not None:
                        self._busy = True
                        break
                    self._cond.wait(_SCAN_POLL)
                if job is None:
                    return
            try:
                self._run_job(job, stop, gen)
            except Exception:  # noqa: BLE001 - the scanner must not die quietly
                logger.exception("the file watcher failed scanning")
                with self._cond:
                    if self._gen == gen:  # what that walk did not reach: the rescan will
                        self._stats.errors += 1
                        self._want_rescan(job.snapshot_id, emit=job.emit)
            finally:
                with self._cond:
                    self._busy = False
                    self._cond.notify_all()

    def _run_job(self, job: _Job, stop: threading.Event, gen: int) -> None:
        if job.kind == "dir":
            assert job.parent is not None  # noqa: S101 - dir jobs always have one
            with self._lock:
                watched = self._gen == gen and job.parent in self._tree
            if not watched:
                return  # the parent is no longer watched: its own events said where it went
            start = deque([_Ref(job.parent, job.name)])
            self._walk(start, job.emit, job.snapshot_id, stop, None, gen)
            return
        if job.kind == "rescan":
            self._stats.rescans += 1
            self._report_windows()
        self._rescan(emit_new=job.emit, snapshot_id=job.snapshot_id, stop=stop, gen=gen)

    def _report_windows(self) -> None:
        with self._lock:
            windows = self._coalescer.take_windows()
        for window in windows:
            self._report_window(window)

    def _report_window(self, window: OverflowWindow) -> None:
        if window.reason == "queue_overflow":
            logger.warning(
                "the file watcher's queue overflowed %d time(s): events were lost, scanning again",
                window.overflows,
            )
            count, extra = None, {"overflows": window.overflows}
        else:
            logger.warning(
                "the file watcher could not queue %d new directories: scanning again",
                window.overflows,
            )
            count, extra = window.overflows, {}
        self.record_dropped(
            window.reason,
            count=count,
            since=window.since,
            until=window.until,
            snapshot_id=window.snapshot_id,
            **extra,
        )

    def _rescan(
        self, *, emit_new: bool, snapshot_id: str | None, stop: threading.Event, gen: int
    ) -> None:
        """Walk the whole tree from the root: arm what is missing, re-stamp what is still
        there and drop the watches of what is gone, so the map is rebuilt from the truth."""
        fresh = _Unwatched()
        with self._lock:
            if self._gen != gen:
                return
            self._tree.generation += 1
            root = self._tree.root
            if root is not None:
                self._tree.touch(root)
            self._rescanning, self._rescan_walk_sid = True, snapshot_id
        walked = False
        try:
            if root is not None:
                self._walk_from_root(root, emit_new, snapshot_id, stop, fresh, gen)
            walked = True
        finally:
            with self._lock:
                self._rescanning = False
                # Only a COMPLETE walk may say what is gone: a walk cut short by the stop or by
                # an error leaves the watches as they were (and the request stands).
                if not walked and self._gen == gen:
                    self._want_rescan(snapshot_id, emit=emit_new, unknown=snapshot_id is None)
                if walked and not stop.is_set() and self._gen == gen:
                    ino = self._ino
                    for wd in self._tree.stale():
                        self._tree.remove(wd)
                        if ino is not None:
                            try:
                                ino.rm_watch(wd)
                            except OSError as exc:
                                logger.debug("rm_watch(%d) of a vanished directory: %s", wd, exc)
                    self._unwatched = fresh

    def _walk_from_root(
        self,
        root: int,
        emit: bool,
        snapshot_id: str | None,
        stop: threading.Event,
        ledger: _Unwatched,
        gen: int,
    ) -> None:
        try:
            fd = self._open_watched(root)
        except _Stale:
            logger.warning("the file watcher cannot reopen the agent folder to walk it")
            self._note_unwatched(".", "raced", ledger, snapshot_id, gen)
            return
        try:  # the root is always known: what it holds is not reported as new
            children = self._list(fd, root, b"", False, snapshot_id, ledger, gen)
        finally:
            os.close(fd)
        self._walk(deque(children), emit, snapshot_id, stop, ledger, gen)

    def _walk(
        self,
        queue: deque[_Ref],
        emit: bool,
        snapshot_id: str | None,
        stop: threading.Event,
        ledger: _Unwatched | None,
        gen: int,
    ) -> None:
        """Breadth first, in chunks so the lock is free between them. Every directory is
        opened by NAME relative to a descriptor of its parent (siblings share it), never by a
        path from the root: no path is too long and no rename of an ancestor loses it."""
        parent_wd: int | None = None
        parent_fd: int | None = None
        try:
            while queue and not stop.is_set():
                for _ in range(self._cfg.scan_chunk):
                    if not queue:
                        break
                    ref = queue.popleft()
                    if ref.parent != parent_wd:
                        if parent_fd is not None:
                            os.close(parent_fd)
                        parent_wd, parent_fd = ref.parent, None
                        try:
                            parent_fd = self._open_watched(ref.parent)
                        except _Stale:
                            pass
                    if parent_fd is None:
                        self._parent_lost(ref, snapshot_id, ledger, gen)
                        continue
                    room = max(0, self._max_watches - len(queue))
                    queue.extend(
                        self._scan_child(ref, parent_fd, emit, snapshot_id, ledger, gen, room)
                    )
                time.sleep(0)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)

    def _open_watched(self, wd: int) -> int:
        """A descriptor of the directory of ``wd``, checked to be THAT directory (device and
        inode): the path comes from the model, which may lag behind renames still queued."""
        with self._lock:
            rel = self._tree.path(wd)
            ident = self._tree.ident(wd)
            root_fd = self._root_fd
        if rel is None or root_fd is None:
            raise _Stale
        try:
            fd = self._open_beneath(root_fd, rel or b".", _DIR_FLAGS)
        except (OSError, ValueError) as exc:
            raise _Stale from exc
        info = os.fstat(fd)
        if ident is not None and (info.st_dev, info.st_ino) != ident:
            os.close(fd)
            raise _Stale
        return fd

    def _parent_lost(
        self, ref: _Ref, snapshot_id: str | None, ledger: _Unwatched | None, gen: int
    ) -> None:
        """The parent of ``ref`` cannot be reopened. If it is not watched any more, its own
        events (delete, move out, a deeper move) cover what happened to it. If it still is,
        the model lags behind the disk: the directory is ``raced`` until a rescan."""
        with self._lock:
            base = self._tree.path(ref.parent)
        if base is None:
            return
        rel = base + b"/" + ref.name if base else ref.name
        self._note_unwatched(os.fsdecode(rel), "raced", ledger, snapshot_id, gen)

    def _scan_child(
        self,
        ref: _Ref,
        parent_fd: int,
        emit: bool,
        snapshot_id: str | None,
        ledger: _Unwatched | None,
        gen: int,
        room: int,
    ) -> list[_Ref]:
        """Open, arm and list the directory ``ref``; return its subdirectories."""
        place = self._place(ref, gen)
        if place is None:
            return []  # the parent stopped being watched meanwhile
        rel, depth = place
        path = os.fsdecode(rel)
        if depth > self._cfg.max_depth:  # checked again, under the lock, when arming
            self._note_unwatched(path, "depth", ledger, snapshot_id, gen)
            return []
        opened = self._open_child(parent_fd, ref.name)
        if opened is None:
            return []
        if isinstance(opened, str):
            self._note_unwatched(path, opened, ledger, snapshot_id, gen)
            return []
        try:
            armed = self._arm_dir(ref, opened, parent_fd, ledger, gen)
            if armed is None:
                return []
            wd, known, rel = armed
            new = emit and not known
            if new:  # a directory nobody told us about: it is new too
                self._add_scanned([(os.fsdecode(rel), True)], snapshot_id, gen)
            return self._list(opened, wd, rel, new, snapshot_id, ledger, gen, room)
        finally:
            os.close(opened)

    def _place(self, ref: _Ref, gen: int) -> tuple[bytes, int] | None:
        """Where ``ref`` is NOW (its path and depth, from the model), or None if its parent is
        no longer watched. Under _lock or not: it takes it."""
        with self._lock:
            if self._gen != gen:
                return None
            base = self._tree.path(ref.parent)
            depth = self._tree.depth(ref.parent)
        if base is None or depth is None:
            return None
        return (base + b"/" + ref.name if base else ref.name), depth + 1

    def _open_child(self, parent_fd: int, name: bytes) -> int | str | None:
        """Open the subdirectory ``name`` of ``parent_fd`` (no symlink, no mount crossing).
        Returns the descriptor; None if it is confirmed that there is no directory to watch
        there (gone, or a file or a link now); or the reason to record it as unwatched."""
        for _ in range(2):
            try:
                return self._open_beneath(parent_fd, name, _DIR_FLAGS)
            except OSError as exc:
                code = exc.errno
            if code not in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                self._log_refused("open", code)
                return "raced" if code in _TRANSIENT else "refused"
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None  # gone: the events of its watched parent tell where
            except OSError as exc:
                self._log_refused("look at", exc.errno)
                return "refused"
            if not stat.S_ISDIR(info.st_mode):
                return None  # a file or a symlink now: nothing to watch, never followed
            # a directory again, made between the two calls: try once more
        return "raced"

    def _list(
        self,
        fd: int,
        wd: int,
        rel: bytes,
        report: bool,
        snapshot_id: str | None,
        ledger: _Unwatched | None,
        gen: int,
        room: int | None = None,
    ) -> list[_Ref]:
        """List the directory ``fd`` (watch ``wd``): its subdirectories to walk next and, if
        ``report``, what it holds as scan creates. Subdirectories beyond ``room`` (more than
        could ever get a watch) are recorded as unwatched instead of queued."""
        subdirs: list[_Ref] = []
        found: list[tuple[str, bool]] = []
        limit = self._max_watches if room is None else room
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        is_dir = False
                    name = os.fsencode(entry.name)
                    child = rel + b"/" + name if rel else name
                    if is_dir:
                        if len(subdirs) < limit:
                            subdirs.append(_Ref(wd, name))
                        else:
                            self._note_unwatched(
                                os.fsdecode(child), "watch_limit", ledger, snapshot_id, gen
                            )
                    if report:
                        found.append((os.fsdecode(child), is_dir))
                        if len(found) >= 1000:
                            self._add_scanned(found, snapshot_id, gen)
                            found = []
        except OSError as exc:
            self._log_refused("list", exc.errno)
            self._note_unwatched(os.fsdecode(rel) or ".", "unlisted", ledger, snapshot_id, gen)
        if found:
            self._add_scanned(found, snapshot_id, gen)
        return subdirs

    def _add_scanned(
        self, found: list[tuple[str, bool]], snapshot_id: str | None, gen: int
    ) -> None:
        now = self._clock()
        with self._lock:
            if self._gen != gen:
                return
            for path, is_dir in found:
                self._coalescer.created(
                    path, is_dir=is_dir, now=now, snapshot_id=snapshot_id, scan=True
                )

    def _note_unwatched(
        self,
        path: str,
        reason: str,
        ledger: _Unwatched | None,
        snapshot_id: str | None,
        gen: int,
    ) -> None:
        """Record a directory without a watch. ``raced`` and ``unlisted`` also ask for a
        rescan, which confirms them or arms them."""
        with self._lock:
            if self._gen != gen:
                return
            (ledger if ledger is not None else self._unwatched).add(path, reason)
            if reason in ("raced", "unlisted"):
                self._want_rescan(snapshot_id, emit=True)

    def _log_refused(self, what: str, code: int | None) -> None:
        """A WARNING the first time per kind of failure and arming, never with the path: the
        agent chooses the names (``token=...``), and the log is not redacted."""
        key = (what, code)
        self._refusals[key] += 1
        if self._refusals[key] == 1:
            logger.warning(
                "the file watcher cannot %s a directory (%s): it is recorded as unwatched",
                what,
                errno.errorcode.get(code or 0, code),
            )

    def _arm_dir(
        self, ref: _Ref, fd: int, parent_fd: int, ledger: _Unwatched | None, gen: int
    ) -> tuple[int, bool, bytes] | None:
        """Watch the directory open as ``fd``, the entry ``ref.name`` of the watch
        ``ref.parent``. Returns None if it could not be watched, else its wd, whether it
        already was (so its contents are not reported as new) and its path now.

        Everything is decided under the lock, against the model as it is now: the depth (an
        ancestor may have moved since the walk queued it) and the name (the directory may have
        been moved away between the open and the watch: a watch hung under a name it no
        longer has would log, at the agent's will, its writes under a false path)."""
        info = os.fstat(fd)
        with self._lock:
            ino = self._ino
            if ino is None or self._gen != gen:
                return None
            place = self._place(ref, gen)
            if place is None:
                return None
            rel, depth = place
            path = os.fsdecode(rel)
            book = ledger if ledger is not None else self._unwatched
            if depth > self._cfg.max_depth:
                book.add(path, "depth")
                return None
            new = self._tree.child(ref.parent, ref.name) is None
            if new and len(self._tree) + 1 >= self._max_watches:
                book.add(path, "watch_limit")
                return None
            try:
                wd = ino.add_watch(fd, WATCH_MASK)
            except OSError as exc:
                limit = exc.errno in (errno.ENOSPC, errno.EMFILE)
                if not limit:
                    self._log_refused("watch", exc.errno)
                book.add(path, "watch_limit" if limit else "refused")
                return None
            known = wd in self._tree
            try:
                now = os.stat(ref.name, dir_fd=parent_fd, follow_symlinks=False)
                still_there = (now.st_dev, now.st_ino) == (info.st_dev, info.st_ino)
            except OSError:
                still_there = False
            if not still_there:
                # Moved away (or swapped) since it was opened: the reader saw that event,
                # and where it went is told by the events of its new place, if watched.
                if not known:
                    try:
                        ino.rm_watch(wd)
                    except OSError as exc:
                        logger.debug("rm_watch(%d) of a directory moved away: %s", wd, exc)
                return None
            self._tree.add(wd, ref.parent, ref.name, (info.st_dev, info.st_ino))
            book.discard(path)
            return wd, known, rel

    # -- the dumper and the black box --------------------------------------------------

    def _dump_loop(self, stop: threading.Event) -> None:
        interval = self._cfg.dump_interval or 2.0
        while not stop.wait(interval):
            try:
                self.flush()
            except Exception:  # noqa: BLE001 - the dumper must not die quietly
                logger.exception("the file watcher failed writing its records")

    def _emit(
        self,
        batch: Flush,
        now: datetime,
        ws_id: int | None,
        root_fd: int | None,
        *,
        final: bool,
    ) -> None:
        mono = self._mono()
        self._flush_failed = False
        for record in batch.records:
            if self._budget.exhausted(mono):
                self._announce_budget(mono)
                self._fold(record)
            elif not self._bucket.take(mono):
                self._fold(record)
            else:
                self._budget.try_spend(mono)
                self._stats.records += 1
                self._append_record(record, ws_id, root_fd)
        self._summary.add_spilled(batch.spilled, now)
        self._stats.folded += sum(batch.spilled.values())
        if self._summary:
            self._maybe_summarize(mono, final)
        elif self._lost and not self._flush_failed:
            self._report_lost()  # nothing else to write: tell what was lost when it failed

    def _fold(self, record: FileRecord) -> None:
        self._stats.folded += 1
        self._summary.add(record)

    def _announce_budget(self, mono: float) -> None:
        if self._budget_alerted == self._budget.window_start:
            return
        self._budget_alerted = self._budget.window_start
        logger.warning(
            "the file watcher wrote its daily budget of %d records: only summaries from now on",
            self._budget.limit,
        )
        self._safe_append(
            "record_budget",
            ".",
            {"limit": self._budget.limit, "window_seconds": self._cfg.budget_window},
            risk=1,
            snapshot_id=None,
            source=Source.SYSTEM,
        )

    def _maybe_summarize(self, mono: float, final: bool) -> None:
        interval = (
            self._cfg.over_budget_summary_interval
            if self._budget.exhausted(mono)
            else self._cfg.summary_interval
        )
        last = self._last_summary
        if not final and last is not None and mono - last < interval:
            return
        snapshot_id = self._summary.snapshot_id
        details = self._summary.build()
        self._last_summary = mono
        self._safe_append("summary", ".", details, risk=0, snapshot_id=snapshot_id)

    def _append_record(self, record: FileRecord, ws_id: int | None, root_fd: int | None) -> None:
        details: dict[str, Any] = {
            # The black box cuts texts at 4 KiB keeping the START: the name goes apart, so a
            # long path still says which file it was.
            "name": record.path.rpartition("/")[2][:MAX_NAME_CHARS],
            "writes": record.writes,
            "attrib": record.attrib,
            "first": _iso(record.first),
            "last": _iso(record.last),
        }
        if record.action == "delete":
            details["type"] = "dir" if record.is_dir else "unknown"
        else:
            details.update(self._inspect(record.path, root_fd))
        if record.origin is not None:
            details["from"] = record.origin
        for flag in ("transient", "scan", "recreated"):
            if getattr(record, flag):
                details[flag] = True
        if ws_id is not None:
            details["workspace_id"] = ws_id
        self._safe_append(
            record.action, record.path, details, risk=0, snapshot_id=record.snapshot_id
        )

    def _inspect(self, path: str, root_fd: int | None) -> dict[str, Any]:
        """Type, size, mode, nlink and symlink target of ``path``, read WITHOUT leaving the
        agent's folder: the parent is opened with openat2 (no symlinks, no mount crossing) and
        the entry is looked at with fstatat(AT_SYMLINK_NOFOLLOW) and readlinkat. By path, an
        agent that swaps a directory for a link to /etc would make root read the host."""
        if root_fd is None:
            return {"type": "unknown"}
        rel = os.fsencode(path)
        link: str | None = None
        try:
            if rel == b".":
                info = os.fstat(root_fd)
            else:
                parent, _, name = rel.rpartition(b"/")
                parent_fd = self._open_beneath(root_fd, parent or b".", _PARENT_FLAGS)
                try:
                    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        link = os.fsdecode(os.readlink(name, dir_fd=parent_fd))[:MAX_LINK_CHARS]
                finally:
                    os.close(parent_fd)
        except (OSError, ValueError):
            return {"type": "unknown"}
        mode = info.st_mode
        if stat.S_ISREG(mode):
            kind = "file"
        elif stat.S_ISDIR(mode):
            kind = "dir"
        elif stat.S_ISLNK(mode):
            kind = "symlink"
        else:
            kind = "other"
        details: dict[str, Any] = {"type": kind, "mode": stat.S_IMODE(mode)}
        if kind != "dir":
            details["nlink"] = info.st_nlink
            details["size"] = info.st_size
        if link is not None:
            details["link"] = link
        return details

    def _safe_append(
        self,
        action: str,
        target: str,
        details: Mapping[str, Any],
        *,
        risk: int,
        snapshot_id: str | None,
        source: Source = Source.FILE,
    ) -> bool:
        """Append to the black box; never raises. A failure is logged as an ERROR, counted, and
        the records of this flush that come after it are counted as lost without trying (a
        failing disk would only make the dumper slower). When it works again, the next write is a
        ``file/dropped {blackbox_error}`` with the count."""
        if self._flush_failed:
            self._lost += 1
            self._stats.lost += 1
            return False
        if self._lost and source is Source.FILE and action != "dropped" and not self._report_lost():
            self._lost += 1
            self._stats.lost += 1
            return False
        try:
            self._box.append(
                source, action, target, details=details, risk=risk, snapshot_id=snapshot_id
            )
        except Exception as exc:  # noqa: BLE001 - counted and logged, never silent
            self._append_failed(exc, snapshot_id)
            return False
        self._failures, self._failing_since = 0, None
        return True

    def _append_failed(self, exc: Exception, snapshot_id: str | None) -> None:
        self._lost += 1
        self._stats.lost += 1
        if self._lost_snapshot is None:
            self._lost_snapshot = snapshot_id
        self._note_failure(exc)

    def _note_failure(self, exc: Exception) -> None:
        """One flush in which the black box refused: at most one count per flush."""
        self._flush_failed = True
        self._failures += 1
        if self._failing_since is None:
            self._failing_since = self._mono()
        logger.error("the file watcher cannot write to the black box: %s", exc)

    def _report_lost(self) -> bool:
        """Write the pending ``dropped {blackbox_error}``. True if the black box took it."""
        count = self._lost
        try:
            self._box.append(
                Source.FILE,
                "dropped",
                ".",
                details={"reason": "blackbox_error", "count": count},
                risk=1,
                snapshot_id=self._lost_snapshot,
            )
        except Exception as exc:  # noqa: BLE001 - still failing: stays counted
            self._note_failure(exc)
            return False
        self._lost, self._lost_snapshot = 0, None
        self._failures, self._failing_since = 0, None
        return True

    def _record_system(self, action: str, details: Mapping[str, Any], *, risk: int) -> None:
        """A ``system`` event about the watcher itself. Never raises."""
        try:
            self._box.append(Source.SYSTEM, action, ".", details=details, risk=risk)
        except Exception:  # noqa: BLE001 - there is nowhere else to say it
            logger.exception("the file watcher cannot record system/%s", action)
