"""The file watcher on the Mac: the pure pieces (watch tree, coalescer, token bucket, daily
budget, summary) and the whole FileWatcher on a fake inotify that is fed raw events through a
pipe. The real inotify (queue, overflow, the swap of a rewind) is tested in the VM."""

import errno
import os
import shutil
import struct
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import FakeClock
from vigia.blackbox import BlackBox
from vigia.sensors import files as files_module
from vigia.sensors import inotify
from vigia.sensors.files import (
    SENTINEL_MASK,
    WATCH_MASK,
    Coalescer,
    DailyBudget,
    FileWatcher,
    SummaryBuffer,
    TokenBucket,
    WatcherConfig,
    WatchTree,
)
from vigia.sensors.inotify import (
    IN_ATTRIB,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_DELETE_SELF,
    IN_IGNORED,
    IN_ISDIR,
    IN_MODIFY,
    IN_MOVE_SELF,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_Q_OVERFLOW,
    InotifyError,
    OpenBeneath,
    RawEvent,
)
from vigia.snapshots import Snapshot

T0 = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
S1 = "20261016T085900.000000Z-periodic"
S2 = "20261016T090100.000000Z-periodic"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


# -- the pure pieces -----------------------------------------------------------------------


class TestTokenBucket:
    def test_starts_full_and_then_denies(self) -> None:
        bucket = TokenBucket(rate=5, burst=3, now=0.0)
        assert [bucket.take(0.0) for _ in range(4)] == [True, True, True, False]

    def test_refills_at_the_rate(self) -> None:
        bucket = TokenBucket(rate=5, burst=3, now=0.0)
        for _ in range(3):
            bucket.take(0.0)
        assert not bucket.take(0.1)  # half a token
        assert bucket.take(0.2)  # one full token at 5/s
        assert not bucket.take(0.2)

    def test_never_holds_more_than_the_burst(self) -> None:
        bucket = TokenBucket(rate=5, burst=3, now=0.0)
        assert [bucket.take(1000.0) for _ in range(4)] == [True, True, True, False]

    def test_a_clock_going_backwards_gives_nothing(self) -> None:
        bucket = TokenBucket(rate=5, burst=1, now=100.0)
        assert bucket.take(100.0)
        assert not bucket.take(50.0)

    def test_invalid_parameters(self) -> None:
        with pytest.raises(ValueError):
            TokenBucket(rate=0, burst=1, now=0.0)
        with pytest.raises(ValueError):
            TokenBucket(rate=1, burst=0, now=0.0)


class TestDailyBudget:
    def test_allows_up_to_the_limit(self) -> None:
        budget = DailyBudget(3)
        assert [budget.try_spend(0.0) for _ in range(4)] == [True, True, True, False]
        assert budget.exhausted(1.0)

    def test_the_window_rolls_after_the_period(self) -> None:
        budget = DailyBudget(2, window=100.0)
        budget.try_spend(10.0)
        budget.try_spend(20.0)
        assert budget.exhausted(109.0)  # the window began at 10
        assert not budget.exhausted(110.0)
        assert budget.try_spend(110.0)
        assert budget.window_start == 110.0

    def test_not_exhausted_before_any_spending(self) -> None:
        assert not DailyBudget(1).exhausted(0.0)


class TestWatchTree:
    def tree(self) -> WatchTree:
        tree = WatchTree()
        tree.add(1, None, b"")
        tree.add(2, 1, b"a")
        tree.add(3, 2, b"b")
        tree.add(4, 1, b"c")
        return tree

    def test_paths_and_find(self) -> None:
        tree = self.tree()
        assert tree.path(1) == b""
        assert tree.path(3) == b"a/b"
        assert tree.find(b"a/b") == 3
        assert tree.find(b"") == 1 and tree.find(b".") == 1
        assert tree.find(b"a/x") is None
        assert tree.path(99) is None

    def test_moving_a_directory_moves_its_descendants(self) -> None:
        tree = self.tree()
        tree.add(2, 4, b"renamed")  # the same watch, a new place
        assert tree.path(2) == b"c/renamed"
        assert tree.path(3) == b"c/renamed/b"
        assert tree.find(b"a") is None
        assert tree.child(1, b"a") is None

    def test_ignored_removes_only_that_watch(self) -> None:
        tree = self.tree()
        assert tree.remove(3)
        assert not tree.remove(3)
        assert tree.find(b"a/b") is None and tree.find(b"a") == 2

    def test_a_stale_ignored_does_not_unlink_a_newer_owner_of_the_name(self) -> None:
        tree = self.tree()
        tree.add(5, 1, b"a")  # another directory took the name (rename over an empty one)
        tree.remove(2)
        assert tree.find(b"a") == 5

    def test_remove_subtree_gives_every_wd(self) -> None:
        tree = self.tree()
        assert sorted(tree.remove_subtree(2)) == [2, 3]
        assert len(tree) == 2 and 3 not in tree

    def test_orphans_have_no_path(self) -> None:
        tree = self.tree()
        tree.remove(2)
        assert tree.path(3) is None

    def test_a_chain_of_three_thousand_directories(self) -> None:
        tree = WatchTree()
        tree.add(1, None, b"")
        for wd in range(2, 3002):
            tree.add(wd, wd - 1, b"d")
        path = tree.path(3001)
        assert path is not None and path.count(b"/") == 2999
        assert tree.find(path) == 3001

    def test_names_that_are_not_utf8(self) -> None:
        tree = WatchTree()
        tree.add(1, None, b"")
        tree.add(2, 1, b"bad\xff\xfe")
        assert tree.path(2) == b"bad\xff\xfe"

    def test_generations_find_what_a_rescan_did_not_confirm(self) -> None:
        tree = self.tree()
        tree.generation += 1
        tree.touch(1)
        tree.touch(2)
        tree.add(5, 1, b"new")  # added during the rescan
        assert sorted(tree.stale()) == [3, 4]

    def test_a_cycle_is_not_an_endless_loop(self) -> None:
        tree = WatchTree()
        tree.add(1, 2, b"x")
        tree.add(2, 1, b"y")
        assert tree.path(1) is None

    def test_clear(self) -> None:
        tree = self.tree()
        tree.clear()
        assert len(tree) == 0 and tree.root is None


class TestCoalescer:
    def co(self, **kwargs: Any) -> Coalescer:
        return Coalescer(**kwargs)

    def only(self, co: Coalescer, now: float = 10.0) -> Any:
        records = co.flush(at(now)).records
        assert len(records) == 1, records
        return records[0]

    def test_create_then_writes_is_one_create(self) -> None:
        co = self.co()
        co.created("a.txt", is_dir=False, now=at(0), snapshot_id=S1)
        for i in range(1, 4):
            co.modified("a.txt", now=at(i), snapshot_id=S2, write=True)
        record = self.only(co)
        assert (record.action, record.writes, record.snapshot_id) == ("create", 3, S1)
        assert record.first == at(0) and record.last == at(3)

    def test_many_writes_are_one_modify_with_the_count(self) -> None:
        co = self.co()
        for i in range(500):
            co.modified("big.bin", now=at(i / 100), snapshot_id=S1, write=True)
        record = self.only(co)
        assert (record.action, record.writes) == ("modify", 500)

    def test_close_without_write_is_a_modify_with_no_writes(self) -> None:
        co = self.co()
        co.modified("a", now=at(0), snapshot_id=S1, write=False)
        assert self.only(co).writes == 0

    def test_attrib_alone_is_a_modify_marked_attrib(self) -> None:
        co = self.co()
        co.attrib("a", now=at(0), snapshot_id=S1)
        record = self.only(co)
        assert (record.action, record.attrib, record.writes) == ("modify", True, 0)

    def test_create_and_delete_in_one_window_is_a_transient_delete(self) -> None:
        co = self.co()
        co.created("tmp", is_dir=False, now=at(0), snapshot_id=S1)
        co.deleted("tmp", is_dir=False, now=at(1), snapshot_id=S1)
        record = self.only(co)
        assert (record.action, record.transient) == ("delete", True)

    def test_modify_then_delete_is_a_delete(self) -> None:
        co = self.co()
        co.modified("a", now=at(0), snapshot_id=S1, write=True)
        co.deleted("a", is_dir=False, now=at(1), snapshot_id=S2)
        record = self.only(co)
        assert (record.action, record.transient, record.snapshot_id) == ("delete", False, S1)

    def test_delete_then_create_is_a_recreated_modify(self) -> None:
        co = self.co()
        co.deleted("a", is_dir=False, now=at(0), snapshot_id=S1)
        co.created("a", is_dir=False, now=at(1), snapshot_id=S1)
        record = self.only(co)
        assert (record.action, record.recreated) == ("modify", True)

    def test_create_delete_create_is_a_create(self) -> None:
        co = self.co()
        co.created("a", is_dir=False, now=at(0), snapshot_id=S1)
        co.deleted("a", is_dir=False, now=at(1), snapshot_id=S1)
        co.created("a", is_dir=False, now=at(2), snapshot_id=S1)
        record = self.only(co)
        assert (record.action, record.transient, record.recreated) == ("create", False, False)

    def test_a_move_pair_is_one_move_with_its_origin(self) -> None:
        co = self.co()
        co.moved_from("old.txt", 7, is_dir=False, now=at(0), snapshot_id=S1)
        co.moved_to("new.txt", 7, is_dir=False, now=at(0), snapshot_id=S1)
        record = self.only(co)
        assert (record.action, record.path, record.origin) == ("move", "new.txt", "old.txt")

    def test_moving_a_directory_is_one_record(self) -> None:
        co = self.co()
        co.moved_from("dir", 3, is_dir=True, now=at(0), snapshot_id=S1)
        co.moved_to("dir2", 3, is_dir=True, now=at(0), snapshot_id=S1)
        record = self.only(co)
        assert (record.action, record.is_dir, record.origin) == ("move", True, "dir")

    def test_a_file_born_and_moved_in_one_window_is_a_create_at_the_destination(self) -> None:
        co = self.co()
        co.created("tmp.part", is_dir=False, now=at(0), snapshot_id=S1)
        co.modified("tmp.part", now=at(1), snapshot_id=S1, write=True)
        co.moved_from("tmp.part", 5, is_dir=False, now=at(2), snapshot_id=S2)
        co.moved_to("final.txt", 5, is_dir=False, now=at(2), snapshot_id=S2)
        record = self.only(co)
        assert (record.action, record.path, record.writes, record.origin) == (
            "create",
            "final.txt",
            1,
            None,
        )

    def test_a_move_after_writes_keeps_the_writes_and_the_first_snapshot(self) -> None:
        co = self.co()
        co.modified("a", now=at(0), snapshot_id=S1, write=True)
        co.moved_from("a", 5, is_dir=False, now=at(1), snapshot_id=S2)
        co.moved_to("b", 5, is_dir=False, now=at(1), snapshot_id=S2)
        record = self.only(co)
        assert (record.action, record.writes, record.snapshot_id) == ("move", 1, S1)
        assert record.path == "b" and record.origin == "a"

    def test_two_moves_keep_the_first_origin(self) -> None:
        co = self.co()
        co.moved_from("a", 1, is_dir=False, now=at(0), snapshot_id=S1)
        co.moved_to("b", 1, is_dir=False, now=at(0), snapshot_id=S1)
        co.moved_from("b", 2, is_dir=False, now=at(1), snapshot_id=S1)
        co.moved_to("c", 2, is_dir=False, now=at(1), snapshot_id=S1)
        record = self.only(co)
        assert (record.path, record.origin) == ("c", "a")

    def test_a_moved_file_deleted_leaves_a_delete_at_both_ends(self) -> None:
        co = self.co()
        co.moved_from("a", 1, is_dir=False, now=at(0), snapshot_id=S1)
        co.moved_to("b", 1, is_dir=False, now=at(0), snapshot_id=S1)
        co.deleted("b", is_dir=False, now=at(1), snapshot_id=S1)
        records = {r.path: r.action for r in co.flush(at(5)).records}
        assert records == {"a": "delete", "b": "delete"}

    def test_a_move_over_something_older_keeps_the_older_snapshot(self) -> None:
        co = self.co()
        co.modified("b", now=at(0), snapshot_id=S1, write=True)
        co.moved_from("a", 1, is_dir=False, now=at(5), snapshot_id=S2)
        co.moved_to("b", 1, is_dir=False, now=at(5), snapshot_id=S2)
        record = self.only(co)
        assert (record.action, record.snapshot_id, record.first) == ("move", S1, at(0))

    def test_an_unpaired_moved_from_is_a_delete_only_after_the_grace(self) -> None:
        co = self.co()
        co.moved_from("gone", 9, is_dir=False, now=at(0), snapshot_id=S1)
        assert co.flush(at(0.5)).records == []  # the pair may still arrive
        record = self.only(co, now=1.5)
        assert (record.action, record.path) == ("delete", "gone")

    def test_the_pair_arriving_late_but_within_the_grace_still_pairs(self) -> None:
        co = self.co()
        co.moved_from("a", 9, is_dir=False, now=at(0), snapshot_id=S1)
        assert co.flush(at(0.4)).records == []
        co.moved_to("b", 9, is_dir=False, now=at(0.6), snapshot_id=S1)
        assert self.only(co, now=0.7).action == "move"

    def test_a_final_flush_does_not_wait_for_the_grace(self) -> None:
        co = self.co()
        co.moved_from("gone", 9, is_dir=False, now=at(0), snapshot_id=S1)
        records = co.flush(at(0.1), final=True).records
        assert [r.action for r in records] == ["delete"]

    def test_an_unpaired_moved_from_of_a_new_file_is_a_transient_delete(self) -> None:
        co = self.co()
        co.created("new", is_dir=False, now=at(0), snapshot_id=S1)
        co.moved_from("new", 9, is_dir=False, now=at(1), snapshot_id=S1)
        record = self.only(co, now=5)
        assert (record.action, record.transient) == ("delete", True)

    def test_an_unpaired_moved_to_is_a_create(self) -> None:
        co = self.co()
        co.moved_to("in.txt", 4, is_dir=False, now=at(0), snapshot_id=S1)
        assert self.only(co).action == "create"

    def test_a_scan_does_not_add_a_second_record_for_a_known_path(self) -> None:
        co = self.co()
        co.created("d/f", is_dir=False, now=at(0), snapshot_id=S1)
        co.created("d/f", is_dir=False, now=at(1), snapshot_id=S2, scan=True)
        record = self.only(co)
        assert (record.scan, record.snapshot_id) == (False, S1)

    def test_a_scan_create_is_flagged(self) -> None:
        co = self.co()
        co.created("d/f", is_dir=False, now=at(0), snapshot_id=S1, scan=True)
        assert self.only(co).scan

    def test_records_come_out_oldest_first_and_a_new_window_starts(self) -> None:
        co = self.co()
        co.created("late", is_dir=False, now=at(5), snapshot_id=S1)
        co.created("early", is_dir=False, now=at(1), snapshot_id=S1)
        assert [r.path for r in co.flush(at(9)).records] == ["early", "late"]
        assert co.flush(at(10)).records == []

    def test_beyond_the_cap_new_paths_are_counted_not_kept(self) -> None:
        co = self.co(max_paths=2)
        co.created("a", is_dir=False, now=at(0), snapshot_id=S1)
        co.created("b", is_dir=False, now=at(0), snapshot_id=S1)
        co.created("c", is_dir=False, now=at(0), snapshot_id=S1)
        co.deleted("d", is_dir=False, now=at(0), snapshot_id=S1)
        co.modified("a", now=at(1), snapshot_id=S1, write=True)  # a known path still updates
        flush = co.flush(at(2))
        assert sorted(r.path for r in flush.records) == ["a", "b"]
        assert flush.records[0].writes + flush.records[1].writes == 1
        assert flush.spilled == Counter({"create": 1, "delete": 1})
        assert co.flush(at(3)).spilled == Counter()

    def test_overflows_are_one_window_with_unknown_loss(self) -> None:
        co = self.co()
        assert co.take_overflow() is None
        co.overflowed(at(1), S1)
        co.overflowed(at(2), S2)
        co.overflowed(at(4), S2)
        window = co.take_overflow()
        assert window is not None
        assert (window.since, window.until, window.overflows) == (at(1), at(4), 3)
        assert window.snapshot_id == S1  # the one current at the FIRST overflow
        assert co.take_overflow() is None


class TestSummaryBuffer:
    def record(
        self, co: Coalescer, path: str, action: str = "create", snap: str | None = S1
    ) -> Any:
        co.created(path, is_dir=False, now=at(1), snapshot_id=snap)
        return co.flush(at(2)).records[0]

    def test_counts_dirs_sample_window_and_the_oldest_snapshot(self) -> None:
        co, buf = Coalescer(), SummaryBuffer()
        assert not buf
        for i in range(30):
            buf.add(self.record(co, f"big/sub/deep/f{i}", snap=S2 if i else S1))
        buf.add(self.record(co, "top.txt"))
        buf.add_spilled({"delete": 5}, at(3))
        assert buf
        snapshot_id = buf.snapshot_id
        details = buf.build()
        assert details["folded"] == 36
        assert details["counts"] == {"create": 31, "delete": 5}
        assert details["dirs"][0] == {"dir": "big/sub", "count": 30}
        assert {"dir": ".", "count": 1} in details["dirs"]
        assert len(details["sample"]) == 20 and details["sample"][0] == "big/sub/deep/f0"
        assert details["window"]["from"].startswith("2026-10-16T09:00:01")
        assert snapshot_id == S1
        assert not buf  # it starts over

    def test_one_change_without_a_snapshot_leaves_the_summary_without_one(self) -> None:
        co, buf = Coalescer(), SummaryBuffer()
        buf.add(self.record(co, "a", snap=S1))
        buf.add(self.record(co, "b", snap=None))
        assert buf.snapshot_id is None


# -- the watcher on a fake inotify ---------------------------------------------------------


class FakeInotify:
    """An inotify that is fed by hand: ``push`` queues events and wakes poll() through a pipe.
    Watches are remembered by the inode of the directory they were put on."""

    def __init__(self, log: list[str], *, max_watches: int | None = None) -> None:
        self._r, self._w = os.pipe()
        os.set_blocking(self._r, False)
        os.set_blocking(self._w, False)
        self._queue = bytearray()
        self._lock = threading.Lock()
        self.log = log
        self.watches: dict[int, int] = {}
        self.masks: dict[int, int] = {}
        self.removed: list[int] = []
        self.closed = False
        self._next = 1
        self.max_watches = max_watches

    def fileno(self) -> int:
        return self._r

    def add_watch(self, dir_fd: int, mask: int) -> int:
        inode = os.fstat(dir_fd).st_ino
        with self._lock:
            for wd, known in self.watches.items():
                if known == inode:
                    self.masks[wd] = mask
                    return wd
            if self.max_watches is not None and len(self.watches) >= self.max_watches:
                raise InotifyError(errno.ENOSPC, "no watches left")
            wd, self._next = self._next, self._next + 1
            self.watches[wd] = inode
            self.masks[wd] = mask
            return wd

    def rm_watch(self, wd: int) -> None:
        with self._lock:
            if wd not in self.watches:
                raise InotifyError(errno.EINVAL, "no such watch")
            del self.watches[wd]
            self.removed.append(wd)

    def queued(self) -> int:
        with self._lock:
            return len(self._queue)

    def read(self) -> bytes:
        with self._lock:
            data = bytes(self._queue)
            self._queue.clear()
        try:
            os.read(self._r, 65536)
        except BlockingIOError:
            pass
        return data

    def close(self) -> None:
        self.log.append("inotify.close")
        self.closed = True
        os.close(self._r)
        os.close(self._w)

    def push(self, *events: RawEvent) -> None:
        raw = b""
        for event in events:
            name = event.name + b"\0" if event.name else b""
            raw += struct.pack("=iIII", event.wd, event.mask, event.cookie, len(name)) + name
        with self._lock:
            self._queue += raw
        os.write(self._w, b"x")

    def wd_of(self, directory: Path) -> int:
        inode = directory.stat().st_ino
        return next(wd for wd, known in self.watches.items() if known == inode)

    def is_watching(self, directory: Path) -> bool:
        inode = directory.stat().st_ino
        return inode in self.watches.values()


@dataclass
class Rec:
    source: str
    action: str
    target: str
    details: dict[str, Any]
    risk: int
    snapshot_id: str | None


class FakeBox:
    """The black box as the watcher sees it. ``fail`` makes every append raise."""

    def __init__(self, log: list[str]) -> None:
        self.records: list[Rec] = []
        self.fail = False
        self.log = log

    def append(
        self,
        source: Any,
        action: str,
        target: str,
        *,
        details: Any = None,
        risk: int = 0,
        snapshot_id: str | None = None,
    ) -> None:
        if self.fail:
            raise OSError("disk full (test)")
        self.log.append(f"append {source}/{action}")
        self.records.append(
            Rec(str(source), action, target, dict(details or {}), risk, snapshot_id)
        )

    def of(self, source: str, action: str | None = None) -> list[Rec]:
        return [r for r in self.records if r.source == source and action in (None, r.action)]


class Mono:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def eventually(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail("timed out waiting for the watcher")
        time.sleep(0.01)


@dataclass
class Rig:
    watcher: FileWatcher
    box: FakeBox
    agent_dir: Path
    instances: list[FakeInotify]
    log: list[str]
    mono: Mono
    clock: FakeClock
    ws_id: list[int] = field(default_factory=lambda: [100])
    factory_errors: list[Exception] = field(default_factory=list)

    @property
    def ino(self) -> FakeInotify:
        return self.instances[-1]

    def event(
        self, directory: str, mask: int, name: str | bytes = b"", cookie: int = 0
    ) -> RawEvent:
        folder = self.agent_dir / directory if directory != "." else self.agent_dir
        raw = os.fsencode(name) if isinstance(name, str) else name
        return RawEvent(self.ino.wd_of(folder), mask, cookie, raw)

    def deliver(self, *events: RawEvent) -> None:
        self.ino.push(*events)
        assert self.watcher.drain()

    def settle(self) -> None:
        """Read everything, finish every scan, and write what is pending."""
        assert self.watcher.drain()
        assert self.watcher.wait_idle(5)
        assert self.watcher.drain()
        self.watcher.flush()

    def files(self, action: str | None = None) -> list[Rec]:
        return self.box.of("file", action)

    def system(self, action: str | None = None) -> list[Rec]:
        return self.box.of("system", action)

    def by_target(self, action: str | None = None) -> dict[str, Rec]:
        return {r.target: r for r in self.files(action)}


@pytest.fixture
def make_rig(tmp_path: Path, clock: FakeClock) -> Iterator[Callable[..., Rig]]:
    rigs: list[Rig] = []

    def make(
        config: WatcherConfig | None = None,
        *,
        arm: bool = True,
        opener: OpenBeneath = inotify.open_beneath,
        ino_cls: type[FakeInotify] = FakeInotify,
        **fake: Any,
    ) -> Rig:
        agent_dir = tmp_path / f"ws{len(rigs)}" / "agente"
        agent_dir.mkdir(parents=True)
        (agent_dir / "work").mkdir()
        (agent_dir / "work" / "old.txt").write_text("old")
        (agent_dir / "home").mkdir()
        log: list[str] = []
        box = FakeBox(log)
        instances: list[FakeInotify] = []
        mono = Mono()
        rig = Rig(None, box, agent_dir, instances, log, mono, clock)  # type: ignore[arg-type]

        def factory() -> FakeInotify:
            if rig.factory_errors:
                raise rig.factory_errors.pop(0)
            fake_inotify = ino_cls(log, **fake)
            instances.append(fake_inotify)
            return fake_inotify

        rig.watcher = FileWatcher(
            agent_dir,
            box,
            workspace_id=lambda: rig.ws_id[0],
            config=config or WatcherConfig(dump_interval=None, max_watches=100),
            clock=clock,
            monotonic=mono,
            sleep=lambda _s: None,
            inotify_factory=factory,
            open_beneath=opener,
        )
        rigs.append(rig)
        if arm:
            assert rig.watcher.arm(S1)
        return rig

    yield make
    for rig in rigs:
        rig.watcher.close()


class TestArming:
    def test_watches_every_directory_and_the_sentinel_and_says_so(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        folders = [rig.agent_dir, rig.agent_dir / "work", rig.agent_dir / "home"]
        assert all(rig.ino.is_watching(folder) for folder in folders)
        assert rig.ino.is_watching(rig.agent_dir.parent)  # the sentinel
        assert rig.ino.masks[rig.ino.wd_of(rig.agent_dir)] == WATCH_MASK
        assert rig.ino.masks[rig.ino.wd_of(rig.agent_dir.parent)] == SENTINEL_MASK
        (armed,) = rig.system("watcher_armed")
        assert armed.details["dirs"] == 3 and armed.details["unwatched"] == 0
        assert armed.details["workspace_id"] == 100
        assert rig.watcher.is_armed and rig.watcher.watch_count() == 3

    def test_nothing_that_already_existed_is_reported_as_created(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.settle()
        assert rig.files() == []

    def test_the_agent_folder_must_be_absolute(self, clock: FakeClock) -> None:
        with pytest.raises(ValueError, match="absolute"):
            FileWatcher(Path("rel/agente"), FakeBox([]), workspace_id=lambda: 1, clock=clock)

    def test_arming_twice_is_harmless(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()
        assert rig.watcher.arm()
        assert len(rig.instances) == 1

    def test_a_failure_to_arm_is_recorded_and_never_raised(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(arm=False)
        rig.factory_errors.append(InotifyError(errno.EMFILE, "too many instances"))
        assert not rig.watcher.arm(S1)
        (failed,) = rig.system("watcher_failed")
        assert failed.risk == 2 and failed.details["errno"] == errno.EMFILE
        assert not rig.watcher.is_armed

    def test_the_cycle_retries_and_records_a_repeated_failure_once(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(arm=False)
        for _ in range(3):
            rig.factory_errors.append(InotifyError(errno.EMFILE, "too many instances"))
        assert not rig.watcher.arm(S1)
        assert not rig.watcher.rearm_if_moved(100)
        assert not rig.watcher.rearm_if_moved(100)
        assert len(rig.system("watcher_failed")) == 1
        assert rig.watcher.rearm_if_moved(100)  # the instance is available now
        assert rig.watcher.is_armed and len(rig.system("watcher_armed")) == 1

    def test_a_failing_black_box_does_not_stop_the_arming(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(arm=False)
        rig.box.fail = True
        assert rig.watcher.arm(S1)  # armed; only the system/watcher_armed record is lost
        assert rig.watcher.is_armed

    def test_the_watch_cap_leaves_the_rest_unwatched_and_says_so_every_cycle(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        # root + sentinel + one directory fit; "work" and "home" compete for the last place.
        rig = make_rig(WatcherConfig(dump_interval=None, max_watches=3))
        assert rig.watcher.watch_count() == 2
        assert rig.watcher.unwatched_count() == 1
        (armed,) = rig.system("watcher_armed")
        assert armed.details["dirs"] == 2 and armed.details["unwatched"] == 1
        for expected in (1, 2):
            assert rig.watcher.report_unwatched()
            dropped = rig.files("dropped")
            assert len(dropped) == expected
        last = dropped[-1]
        assert last.risk == 1 and last.details["reason"] == "unwatched_dirs"
        assert last.details["count"] == 1 and last.details["sample"][0] in {"work", "home"}
        assert last.details["reasons"] == {"watch_limit": 1}
        assert last.snapshot_id == S1

    def test_nothing_unwatched_records_nothing(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()
        assert not rig.watcher.report_unwatched()
        assert rig.files("dropped") == []

    def test_too_deep_directories_are_unwatched(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(
            arm=False, config=WatcherConfig(dump_interval=None, max_depth=2, max_watches=100)
        )
        (rig.agent_dir / "work" / "x" / "y" / "z").mkdir(parents=True)
        assert rig.watcher.arm(S1)
        assert rig.watcher.unwatched_count() == 1  # work/x/y/z is at depth 4... and y at 3
        assert not rig.ino.is_watching(rig.agent_dir / "work" / "x" / "y" / "z")
        rig.watcher.report_unwatched()
        assert rig.files("dropped")[0].details["reasons"] == {"depth": 1}

    def test_a_refused_watch_is_unwatched_and_the_walk_goes_on(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(arm=False, max_watches=3)  # the FAKE kernel refuses the third watch
        assert rig.watcher.arm(S1)
        assert rig.watcher.unwatched_count() == 1
        assert rig.watcher.is_armed

    def test_a_directory_is_never_followed_through_a_symlink(
        self, make_rig: Callable[..., Rig], tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        rig = make_rig(arm=False)
        (rig.agent_dir / "link").symlink_to(outside)
        assert rig.watcher.arm(S1)
        assert not rig.ino.is_watching(outside)


class TestRecords:
    def test_create_modify_delete_move_with_relative_paths_and_types(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        work = rig.agent_dir / "work"
        (work / "new.md").write_text("hello")
        (work / "new.md").chmod(0o640)
        (work / "old.txt").write_text("changed")
        (work / "old.txt").rename(work / "renamed.txt")
        (rig.agent_dir / "home" / "gone.txt").write_text("x")
        (rig.agent_dir / "home" / "gone.txt").unlink()
        rig.deliver(
            rig.event("work", IN_CREATE, "new.md"),
            rig.event("work", IN_MODIFY, "new.md"),
            rig.event("work", IN_MODIFY, "new.md"),
            rig.event("work", IN_CLOSE_WRITE, "new.md"),
            rig.event("work", IN_MODIFY, "old.txt"),
            rig.event("work", IN_MOVED_FROM, "old.txt", cookie=5),
            rig.event("work", IN_MOVED_TO, "renamed.txt", cookie=5),
            rig.event("home", IN_CREATE, "gone.txt"),
            rig.event("home", IN_DELETE, "gone.txt"),
        )
        rig.settle()
        records = rig.by_target()
        created = records["work/new.md"]
        assert created.action == "create" and created.snapshot_id == S1 and created.risk == 0
        assert created.details["writes"] == 2 and created.details["type"] == "file"
        assert created.details["size"] == 5 and created.details["mode"] == 0o640
        assert created.details["nlink"] == 1 and created.details["workspace_id"] == 100
        assert created.details["first"].endswith("Z") and "transient" not in created.details
        moved = records["work/renamed.txt"]
        assert moved.action == "move" and moved.details["from"] == "work/old.txt"
        assert moved.details["writes"] == 1
        deleted = records["home/gone.txt"]
        assert deleted.action == "delete" and deleted.details["transient"] is True
        assert deleted.details["type"] == "unknown" and "size" not in deleted.details
        assert "work/old.txt" not in records  # the move is ONE record, not a delete and a create
        assert all(r.target and not r.target.startswith("/") for r in rig.files())

    def test_events_about_the_agent_folder_itself_are_the_dot_path(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.deliver(rig.event(".", IN_ATTRIB))
        rig.settle()
        (record,) = rig.files()
        assert record.target == "." and record.details["attrib"] is True
        assert record.details["type"] == "dir"

    def test_the_snapshot_id_is_the_one_current_at_the_first_event(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.deliver(rig.event("work", IN_MODIFY, "old.txt"))
        rig.watcher.set_current(S2)
        rig.deliver(rig.event("work", IN_MODIFY, "old.txt"), rig.event("home", IN_CREATE, "n"))
        rig.settle()
        by = rig.by_target()
        assert by["work/old.txt"].snapshot_id == S1
        assert by["home/n"].snapshot_id == S2

    def test_a_hard_link_and_a_symlink_are_described_without_following_them(
        self, make_rig: Callable[..., Rig], tmp_path: Path
    ) -> None:
        rig = make_rig()
        work = rig.agent_dir / "work"
        os.link(work / "old.txt", work / "hard")
        long_target = "t" * 400
        (work / "soft").symlink_to(long_target)
        rig.deliver(rig.event("work", IN_CREATE, "hard"), rig.event("work", IN_CREATE, "soft"))
        rig.settle()
        by = rig.by_target()
        assert by["work/hard"].details["nlink"] == 2
        assert by["work/soft"].details["type"] == "symlink"
        assert by["work/soft"].details["link"] == "t" * 256

    def test_a_directory_swapped_for_a_link_to_the_host_is_never_read(
        self, make_rig: Callable[..., Rig], tmp_path: Path
    ) -> None:
        outside = tmp_path / "host"
        outside.mkdir()
        (outside / "secret.txt").write_text("not for the log")
        rig = make_rig()
        (rig.agent_dir / "work" / "sub").mkdir()
        rig.deliver(rig.event("work", IN_CREATE | IN_ISDIR, "sub"))
        rig.watcher.wait_idle(5)
        rig.deliver(rig.event("work/sub", IN_CREATE, "secret.txt"))
        # Between the event and the dump the agent replaces the directory by a link out.
        (rig.agent_dir / "work" / "sub").rmdir()
        (rig.agent_dir / "work" / "sub").symlink_to(outside)
        rig.watcher.flush()
        record = rig.by_target()["work/sub/secret.txt"]
        assert record.details["type"] == "unknown"
        assert "size" not in record.details and "mode" not in record.details

    def test_a_new_directory_is_walked_and_what_it_holds_is_a_scan_create(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        new = rig.agent_dir / "work" / "proj"
        (new / "src").mkdir(parents=True)
        (new / "README").write_text("r")
        (new / "src" / "main.py").write_text("print()")
        rig.deliver(rig.event("work", IN_CREATE | IN_ISDIR, "proj"))
        rig.settle()
        by = rig.by_target()
        assert by["work/proj"].details["type"] == "dir" and "scan" not in by["work/proj"].details
        for path in ("work/proj/README", "work/proj/src", "work/proj/src/main.py"):
            assert by[path].action == "create" and by[path].details["scan"] is True
        assert rig.ino.is_watching(new) and rig.ino.is_watching(new / "src")
        # the new directories really are watched: an event inside gets its path
        rig.deliver(rig.event("work/proj/src", IN_MODIFY, "main.py"))
        rig.settle()
        assert rig.by_target("modify")["work/proj/src/main.py"].action == "modify"

    def test_a_scan_does_not_repeat_what_an_event_already_said(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        new = rig.agent_dir / "work" / "proj"
        new.mkdir()
        (new / "a").write_text("a")
        rig.deliver(
            rig.event("work", IN_CREATE | IN_ISDIR, "proj"),
        )
        rig.settle()
        # the event for "a" arrives after the walk already found it
        rig.deliver(rig.event("work/proj", IN_CREATE, "a"))
        rig.settle()
        assert [r.target for r in rig.files() if r.target == "work/proj/a"] == ["work/proj/a"] * 2
        # ...each window has its own record; within a window there is only one
        assert all(r.action == "create" for r in rig.files())

    def test_a_moved_directory_is_one_record_and_its_children_follow_it(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        (rig.agent_dir / "work" / "old.txt").unlink()
        (rig.agent_dir / "work").rename(rig.agent_dir / "home" / "work2")
        rig.deliver(
            rig.event(".", IN_MOVED_FROM | IN_ISDIR, "work", cookie=11),
            rig.event("home", IN_MOVED_TO | IN_ISDIR, "work2", cookie=11),
        )
        rig.settle()
        (record,) = rig.files()
        assert record.action == "move" and record.target == "home/work2"
        assert record.details["from"] == "work" and record.details["type"] == "dir"
        # the same watch is now under its new name
        rig.deliver(RawEvent(rig.ino.wd_of(rig.agent_dir / "home" / "work2"), IN_CREATE, 0, b"f"))
        rig.settle()
        assert rig.files("create")[-1].target == "home/work2/f"

    def test_a_directory_moved_out_of_the_watched_tree_loses_its_watches(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        wd = rig.ino.wd_of(rig.agent_dir / "work")
        rig.deliver(rig.event(".", IN_MOVED_FROM | IN_ISDIR, "work", cookie=12))
        rig.mono.now += 5
        rig.clock.advance(timedelta(seconds=5))
        eventually(lambda: wd in rig.ino.removed)
        rig.settle()
        assert rig.by_target()["work"].action == "delete"
        assert rig.watcher.watch_count() == 2  # root and home

    def test_a_directory_moved_in_from_outside_is_walked(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        (rig.agent_dir / "work" / "incoming").mkdir()
        (rig.agent_dir / "work" / "incoming" / "x").write_text("x")
        rig.deliver(rig.event("work", IN_MOVED_TO | IN_ISDIR, "incoming", cookie=13))
        rig.settle()
        by = rig.by_target()
        assert by["work/incoming"].action == "create"
        assert by["work/incoming/x"].details["scan"] is True

    def test_a_deleted_directory_loses_its_watch_when_the_kernel_says_so(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        wd = rig.ino.wd_of(rig.agent_dir / "home")
        rig.deliver(
            RawEvent(wd, IN_DELETE_SELF, 0, b""),
            RawEvent(wd, IN_IGNORED, 0, b""),
            rig.event(".", IN_DELETE | IN_ISDIR, "home"),
        )
        assert rig.watcher.watch_count() == 2
        rig.settle()
        assert rig.by_target()["home"].details["type"] == "dir"

    def test_events_of_a_watch_that_is_already_gone_are_counted_not_recorded(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.deliver(RawEvent(9999, IN_CREATE, 0, b"ghost"))
        rig.settle()
        assert rig.files() == []
        assert rig.watcher.stats().unknown_wd == 1

    def test_the_target_goes_through_the_black_box_redaction(
        self, tmp_path: Path, clock: FakeClock
    ) -> None:
        agent_dir = tmp_path / "ws" / "agente"
        (agent_dir / "work").mkdir(parents=True)
        (agent_dir / "work" / "token=SUPERSECRETVALUE123").write_text("x")
        instances: list[FakeInotify] = []

        def factory() -> FakeInotify:
            instances.append(FakeInotify([]))
            return instances[-1]

        with BlackBox(tmp_path / "bb.db", bytes(range(32)), clock=clock) as box:
            watcher = FileWatcher(
                agent_dir,
                box,
                workspace_id=lambda: 1,
                config=WatcherConfig(dump_interval=None, max_watches=50),
                clock=clock,
                inotify_factory=factory,
            )
            try:
                assert watcher.arm(S1)
                wd = instances[0].wd_of(agent_dir / "work")
                instances[0].push(
                    RawEvent(wd, IN_CREATE, 0, b"token=SUPERSECRETVALUE123"),
                    RawEvent(wd, IN_CREATE, 0, b"bad\xffname"),
                )
                assert watcher.drain()
                watcher.flush()
            finally:
                watcher.close()
            events = box.events(source="file")
            assert box.verify().ok
        targets = {e.target for e in events}
        assert "work/token=[REDACTED]" in targets
        assert "work/bad\\udcffname" in targets
        assert all("SUPERSECRETVALUE123" not in e.target for e in events)
        assert all("SUPERSECRETVALUE123" not in str(e.details) for e in events)


class TestBarrier:
    def snapshot(self, snapshot_id: str) -> Snapshot:
        snap = Snapshot.parse(snapshot_id)
        assert snap is not None
        return snap

    def test_a_delete_that_arrives_while_the_snapshot_is_taken_points_to_the_one_before(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        """The agent deletes at t0, Vigía takes S2 at t0+e, the reader sees the event after: the
        record must say S1 (S2 no longer has the file)."""
        rig = make_rig()
        (rig.agent_dir / "work" / "old.txt").unlink()

        def take() -> Snapshot:
            rig.ino.push(rig.event("work", IN_DELETE, "old.txt"))  # in flight during take()
            return self.snapshot(S2)

        assert rig.watcher.barrier(take).id == S2
        assert rig.watcher.current == S2
        rig.deliver(rig.event("home", IN_CREATE, "after"))  # happened after S2
        rig.settle()
        by = rig.by_target()
        assert by["work/old.txt"].snapshot_id == S1
        assert by["home/after"].snapshot_id == S2

    def test_a_change_read_before_the_snapshot_points_to_the_one_before(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.ino.push(rig.event("work", IN_MODIFY, "old.txt"))  # in the queue, not yet read
        rig.watcher.barrier(lambda: self.snapshot(S2))
        rig.settle()
        assert rig.by_target()["work/old.txt"].snapshot_id == S1

    def test_the_second_drain_waits_the_settle_time(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()
        sleeps: list[float] = []
        rig.watcher._sleep = sleeps.append  # type: ignore[method-assign]
        rig.watcher.barrier(lambda: self.snapshot(S2))
        assert sleeps == [WatcherConfig().settle]

    def test_a_failed_take_leaves_the_current_snapshot(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()

        def failing() -> Snapshot:
            raise RuntimeError("no space")

        with pytest.raises(RuntimeError):
            rig.watcher.barrier(failing)
        assert rig.watcher.current == S1

    def test_drain_does_nothing_when_nothing_is_armed(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(arm=False)
        assert not rig.watcher.drain()
        assert rig.watcher.barrier(lambda: self.snapshot(S2)).id == S2  # the barrier still works


class TestRateLimits:
    def config(self, **kwargs: Any) -> WatcherConfig:
        return WatcherConfig(dump_interval=None, max_watches=100, **kwargs)

    def create_files(self, rig: Rig, count: int, prefix: str = "f") -> None:
        for i in range(count):
            (rig.agent_dir / "work" / f"{prefix}{i}").write_text("x")
        rig.deliver(*[rig.event("work", IN_CREATE, f"{prefix}{i}") for i in range(count)])

    def test_what_does_not_fit_the_bucket_is_folded_into_a_summary(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config(bucket_rate=1, bucket_burst=3))
        self.create_files(rig, 10)
        rig.settle()
        assert len(rig.files("create")) == 3
        (summary,) = rig.files("summary")
        assert summary.details["folded"] == 7 and summary.details["counts"] == {"create": 7}
        assert summary.details["dirs"] == [{"dir": "work", "count": 7}]
        assert summary.snapshot_id == S1 and summary.risk == 0
        assert rig.watcher.stats().folded == 7

    def test_at_most_one_summary_per_interval_and_nothing_is_lost(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config(bucket_rate=0.001, bucket_burst=1, summary_interval=10))
        self.create_files(rig, 5, "a")
        rig.settle()  # 1 record + a summary of 4
        self.create_files(rig, 5, "b")
        rig.mono.now += 3
        rig.settle()
        assert len(rig.files("summary")) == 1  # too soon for another one
        rig.mono.now += 8
        rig.settle()
        summaries = rig.files("summary")
        assert len(summaries) == 2 and summaries[1].details["folded"] == 5
        assert sum(s.details["folded"] for s in summaries) + len(rig.files("create")) == 10

    def test_the_daily_budget_stops_the_records_and_says_so_once(
        self, make_rig: Callable[..., Rig], caplog: pytest.LogCaptureFixture
    ) -> None:
        rig = make_rig(
            self.config(bucket_rate=1000, bucket_burst=1000, daily_budget=4, summary_interval=10)
        )
        with caplog.at_level("WARNING", logger="vigia.sensors.files"):
            self.create_files(rig, 10, "a")
            rig.settle()
            self.create_files(rig, 10, "b")
            rig.settle()
        assert len(rig.files("create")) == 4
        (budget,) = rig.system("record_budget")
        assert budget.risk == 1 and budget.details["limit"] == 4
        assert "daily budget" in caplog.text
        # over budget the summaries come once a minute, not every 10 s
        rig.mono.now += 15
        self.create_files(rig, 3, "c")
        rig.settle()
        before = len(rig.files("summary"))
        rig.mono.now += 20
        self.create_files(rig, 3, "d")
        rig.settle()
        assert len(rig.files("summary")) == before
        rig.mono.now += 40
        rig.settle()
        assert len(rig.files("summary")) == before + 1
        total = len(rig.files("create")) + sum(s.details["folded"] for s in rig.files("summary"))
        assert total == 26

    def test_the_budget_comes_back_after_a_day(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(self.config(bucket_rate=1000, bucket_burst=1000, daily_budget=2))
        self.create_files(rig, 5, "a")
        rig.settle()
        assert len(rig.files("create")) == 2
        rig.mono.now += 24 * 3600 + 1
        self.create_files(rig, 5, "b")
        rig.settle()
        assert len(rig.files("create")) == 4
        assert len(rig.system("record_budget")) == 2

    def test_the_pending_map_beyond_its_cap_becomes_counters_in_the_summary(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config(max_pending_paths=5, bucket_burst=1000, bucket_rate=1000))
        self.create_files(rig, 12)
        rig.settle()
        assert len(rig.files("create")) == 5
        (summary,) = rig.files("summary")
        assert summary.details["folded"] == 7 and summary.details["counts"] == {"create": 7}
        assert summary.details["sample"] == []


class TestOverflow:
    def config(self) -> WatcherConfig:
        return WatcherConfig(dump_interval=None, max_watches=100, rescan_cooldown=30)

    def test_an_overflow_is_a_dropped_with_the_window_and_a_rescan(
        self, make_rig: Callable[..., Rig], caplog: pytest.LogCaptureFixture
    ) -> None:
        rig = make_rig(self.config())
        newer = rig.agent_dir / "work" / "made_during_the_overflow"
        newer.mkdir()
        (newer / "inside").write_text("x")
        with caplog.at_level("WARNING", logger="vigia.sensors.files"):
            rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))
            rig.settle()
        (dropped,) = rig.files("dropped")
        assert dropped.risk == 1 and dropped.details["reason"] == "queue_overflow"
        assert dropped.details["count"] is None and dropped.details["overflows"] == 1
        assert dropped.details["since"] and dropped.details["until"]
        assert dropped.snapshot_id == S1
        assert "overflowed" in caplog.text
        # the rescan armed the folder the events never told about, and reported what it holds
        assert rig.ino.is_watching(newer)
        by = rig.by_target("create")
        assert by["work/made_during_the_overflow"].details["scan"] is True
        assert by["work/made_during_the_overflow/inside"].details["scan"] is True
        assert "work" not in by and "work/old.txt" not in by  # known ones are not repeated

    def test_overflows_in_the_cooldown_add_up_to_one_dropped_and_one_rescan(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config())
        rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))
        rig.settle()
        assert rig.watcher.stats().rescans == 1
        for _ in range(5):
            rig.mono.now += 2  # an overflow storm: 5 in 10 s
            rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))
        rig.settle()
        time.sleep(0.5)  # give a wrongly eager scanner the chance to rescan
        rig.settle()
        assert rig.watcher.stats().rescans == 1 and len(rig.files("dropped")) == 1
        rig.mono.now += 30
        eventually(lambda: rig.watcher.stats().rescans == 2)
        rig.settle()
        second = rig.files("dropped")[1]
        assert second.details["overflows"] == 5
        assert rig.watcher.stats().overflows == 6

    def test_the_rescan_rebuilds_the_map_and_drops_watches_of_what_no_longer_exists(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config())
        wd = rig.ino.wd_of(rig.agent_dir / "home")
        (rig.agent_dir / "home").rmdir()  # its events were lost in the overflow
        rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))
        rig.settle()
        assert wd in rig.ino.removed
        assert rig.watcher.watch_count() == 2

    def test_a_renamed_directory_whose_events_were_lost_gets_its_true_name(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config())
        (rig.agent_dir / "home").rename(rig.agent_dir / "house")
        rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))
        rig.settle()
        rig.deliver(RawEvent(rig.ino.wd_of(rig.agent_dir / "house"), IN_CREATE, 0, b"n"))
        rig.settle()
        assert "house/n" in rig.by_target()
        assert rig.watcher.watch_count() == 3

    def test_a_freed_watch_rearms_the_directories_that_did_not_fit(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(WatcherConfig(dump_interval=None, max_watches=3, rescan_cooldown=30))
        (watched,) = [
            d for d in (rig.agent_dir / "work", rig.agent_dir / "home") if rig.ino.is_watching(d)
        ]
        (missing,) = [d for d in (rig.agent_dir / "work", rig.agent_dir / "home") if d != watched]
        assert rig.watcher.unwatched_count() == 1
        wd = rig.ino.wd_of(watched)
        shutil.rmtree(watched)
        rig.deliver(
            RawEvent(wd, IN_DELETE_SELF, 0, b""),
            RawEvent(wd, IN_IGNORED, 0, b""),
        )
        rig.settle()
        assert rig.ino.is_watching(missing)
        assert rig.watcher.unwatched_count() == 0
        assert not rig.watcher.report_unwatched()


class TestBounds:
    def test_directory_jobs_beyond_the_cap_become_a_rescan_not_an_endless_queue(
        self, make_rig: Callable[..., Rig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(files_module, "_MAX_QUEUED_DIRS", 3)
        rig = make_rig(arm=False)  # no scanner thread: the queue only grows
        watcher = rig.watcher
        with watcher._lock:
            for i in range(5):
                watcher._queue_dir(1, f"d{i}".encode(), S1, at(i))
            assert len(watcher._jobs) == 3
            assert watcher._rescan_wanted and watcher._rescan_emit
            (window,) = watcher._coalescer.take_windows()
        assert (window.reason, window.overflows, window.snapshot_id) == ("dir_queue_full", 2, S1)
        assert (window.since, window.until) == (at(3), at(4))

    def test_an_event_that_makes_the_handler_fail_is_logged_counted_and_skipped(
        self,
        make_rig: Callable[..., Rig],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        rig = make_rig()
        real = rig.watcher._coalescer.created

        def flaky(path: str, **kwargs: Any) -> None:
            if path == "work/bad":
                raise RuntimeError("boom")
            real(path, **kwargs)

        monkeypatch.setattr(rig.watcher._coalescer, "created", flaky)
        with caplog.at_level("ERROR", logger="vigia.sensors.files"):
            rig.deliver(rig.event("work", IN_CREATE, "bad"), rig.event("work", IN_CREATE, "good"))
        rig.settle()
        assert "work/good" in rig.by_target()
        assert rig.watcher.stats().errors == 1 and "failed handling an event" in caplog.text


class TestBlackBoxFailures:
    def test_lost_records_are_counted_and_reported_when_the_box_works_again(
        self, make_rig: Callable[..., Rig], caplog: pytest.LogCaptureFixture
    ) -> None:
        rig = make_rig()
        for i in range(4):
            (rig.agent_dir / "work" / f"n{i}").write_text("x")
        rig.box.fail = True
        with caplog.at_level("ERROR", logger="vigia.sensors.files"):
            rig.deliver(*[rig.event("work", IN_CREATE, f"n{i}") for i in range(4)])
            rig.watcher.flush()
        assert rig.files() == []
        assert "cannot write to the black box" in caplog.text
        health = rig.watcher.blackbox_health()
        assert health.consecutive_failures == 1 and health.lost == 4
        assert health.failing_since is not None
        rig.mono.now += 5
        rig.deliver(rig.event("work", IN_MODIFY, "old.txt"))
        rig.watcher.flush()
        assert rig.watcher.blackbox_health().consecutive_failures == 2
        rig.box.fail = False
        rig.deliver(rig.event("work", IN_MODIFY, "old.txt"))
        rig.watcher.flush()
        actions = [r.action for r in rig.files()]
        assert actions == ["dropped", "modify"]  # the loss is told BEFORE the next record
        dropped = rig.files("dropped")[0]
        assert dropped.details == {"reason": "blackbox_error", "count": 5}
        assert dropped.risk == 1 and dropped.snapshot_id == S1
        health = rig.watcher.blackbox_health()
        assert (health.consecutive_failures, health.failing_since, health.lost) == (0, None, 0)

    def test_a_flush_stops_trying_after_the_first_failure(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        attempts: list[str] = []

        class Counting(FakeBox):
            def append(self, *args: Any, **kwargs: Any) -> None:
                attempts.append(args[1])
                raise OSError("down")

        rig.watcher._box = Counting(rig.log)  # type: ignore[assignment]
        rig.deliver(*[rig.event("work", IN_CREATE, f"x{i}") for i in range(50)])
        rig.watcher.flush()
        assert len(attempts) == 1
        assert rig.watcher.blackbox_health().lost == 50

    def test_the_dumper_thread_survives_a_failing_box(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(WatcherConfig(dump_interval=0.02, max_watches=100))
        rig.box.fail = True
        rig.deliver(rig.event("work", IN_CREATE, "a"))
        eventually(lambda: rig.watcher.blackbox_health().consecutive_failures >= 1)
        rig.box.fail = False
        rig.deliver(rig.event("work", IN_CREATE, "b"))
        eventually(lambda: any(r.target == "work/b" for r in rig.files()))
        assert rig.files("dropped")


class TestSuspended:
    def test_it_drains_writes_and_only_then_closes_inotify(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        old = rig.ino
        old.push(rig.event("work", IN_MODIFY, "old.txt"))  # still in the kernel queue
        rig.ws_id[0] = 100
        with rig.watcher.suspended(S2):
            # by now: read, written (with the OLD workspace id) and closed
            assert old.closed
            assert rig.log.index("append file/modify") < rig.log.index("inotify.close")
            assert rig.files("modify")[0].details["workspace_id"] == 100
            assert rig.watcher.is_suspended and not rig.watcher.is_armed
            rig.ws_id[0] = 200  # the swap of the rewind
        assert rig.watcher.is_armed and len(rig.instances) == 2
        assert rig.ino is not old and rig.ino.is_watching(rig.agent_dir / "work")
        assert rig.watcher.current == S2  # the workspace changed: now it points to the target
        armed = rig.system("watcher_armed")[-1]
        assert armed.details["workspace_id"] == 200

    def test_the_old_workspace_has_no_watch_left_and_the_new_one_works(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        with rig.watcher.suspended(S2):
            rig.ws_id[0] = 200
        rig.deliver(rig.event("work", IN_CREATE, "after-rewind"))
        rig.settle()
        record = rig.by_target()["work/after-rewind"]
        assert record.snapshot_id == S2 and record.details["workspace_id"] == 200

    def test_if_the_rewind_failed_before_swapping_the_current_snapshot_stays(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        with pytest.raises(RuntimeError), rig.watcher.suspended(S2):
            raise RuntimeError("restore failed, nothing swapped")
        assert rig.watcher.current == S1 and rig.watcher.is_armed

    def test_it_never_raises_when_the_black_box_fails(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()
        rig.box.fail = True
        rig.ino.push(rig.event("work", IN_MODIFY, "old.txt"))
        with rig.watcher.suspended(S2):
            rig.ws_id[0] = 200
        assert rig.watcher.is_armed  # armed again; only the records were lost
        assert rig.watcher.blackbox_health().lost >= 1

    def test_it_never_raises_when_the_new_workspace_cannot_be_armed(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        with rig.watcher.suspended(S2):
            rig.ws_id[0] = 200
            rig.factory_errors.append(InotifyError(errno.EMFILE, "no instances"))
        assert not rig.watcher.is_armed
        (failed,) = rig.system("watcher_failed")
        assert failed.risk == 2
        assert rig.watcher.current == S2
        assert rig.watcher.rearm_if_moved(200)  # the next cycle tries again, and works
        assert rig.watcher.is_armed

    def test_it_never_raises_when_the_workspace_id_cannot_be_read(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()

        def broken() -> int:
            raise OSError("btrfs gone")

        rig.watcher._workspace_id_of = broken  # type: ignore[method-assign]
        with rig.watcher.suspended(S2):
            pass
        assert not rig.watcher.is_armed
        assert rig.watcher.current == S2  # unknown swap: the older target is the safe side
        assert rig.system("watcher_failed")

    def test_rearm_if_moved_does_nothing_while_suspended(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        with rig.watcher.suspended(S2):
            rig.ws_id[0] = 200
            assert not rig.watcher.rearm_if_moved(200)
            assert len(rig.instances) == 1
        assert len(rig.instances) == 2  # armed once, by the exit of suspended()
        assert not rig.watcher.rearm_if_moved(200)  # and the cycle after it has nothing to do

    def test_a_pending_move_pair_is_written_when_suspending(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.deliver(rig.event("work", IN_MOVED_FROM, "old.txt", cookie=3))
        with rig.watcher.suspended(S2):
            assert [r.action for r in rig.files()] == ["delete"]

    def test_nested_use_is_a_noop_for_the_inner_block(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()
        with rig.watcher.suspended(S2), rig.watcher.suspended(S1):
            pass
        assert len(rig.instances) == 2

    def test_an_unarmed_watcher_is_armed_by_the_exit(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(arm=False)
        with rig.watcher.suspended(S2):
            pass
        assert rig.watcher.is_armed


class TestRearmIfMoved:
    def test_the_same_workspace_is_left_alone(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig()
        assert not rig.watcher.rearm_if_moved(100)
        assert len(rig.instances) == 1

    def test_a_different_workspace_is_a_watcher_lost_and_a_new_arming(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.ino.push(rig.event("work", IN_MODIFY, "old.txt"))
        rig.ws_id[0] = 200
        assert rig.watcher.rearm_if_moved(200)
        (lost,) = rig.system("watcher_lost")
        assert lost.risk == 2 and lost.details["from"] == 100 and lost.details["to"] == 200
        assert len(rig.instances) == 2 and rig.instances[0].closed
        assert rig.files("modify")  # what was pending is not lost
        assert not rig.watcher.rearm_if_moved(200)

    def test_a_watcher_that_never_armed_does_not_arm_by_itself(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(arm=False)
        assert not rig.watcher.rearm_if_moved(100)
        assert rig.instances == []


class TestAnomalies:
    def test_the_sentinel_hearing_the_workspace_move_is_a_watcher_lost(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        sentinel = rig.ino.wd_of(rig.agent_dir.parent)
        rig.ino.push(RawEvent(sentinel, IN_MOVE_SELF, 0, b""))
        eventually(lambda: len(rig.instances) == 2)
        eventually(lambda: rig.watcher.is_armed)
        (lost,) = rig.system("watcher_lost")
        assert lost.risk == 2 and "moved or deleted" in lost.details["error"]

    def test_the_agent_folder_losing_its_watch_is_a_watcher_lost(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.ino.push(RawEvent(rig.ino.wd_of(rig.agent_dir), IN_IGNORED, 0, b""))
        eventually(lambda: len(rig.instances) == 2 and rig.watcher.is_armed)
        assert len(rig.system("watcher_lost")) == 1

    def test_a_subdirectory_moving_itself_is_not_an_anomaly(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.deliver(RawEvent(rig.ino.wd_of(rig.agent_dir / "work"), IN_MOVE_SELF, 0, b""))
        rig.settle()
        assert rig.system("watcher_lost") == [] and len(rig.instances) == 1


class TestLifecycle:
    def test_close_writes_what_is_pending_and_closes_everything(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig()
        rig.ino.push(rig.event("work", IN_CREATE, "last"))
        rig.watcher.close()
        assert rig.ino.closed
        assert [r.target for r in rig.files()] == ["work/last"]
        assert not rig.watcher.arm()  # closed for good

    def test_no_descriptor_is_left_open_after_closing(self, make_rig: Callable[..., Rig]) -> None:
        before = len(os.listdir("/dev/fd"))
        rig = make_rig()
        rig.watcher.close()
        assert len(os.listdir("/dev/fd")) == before

    def test_the_dumper_thread_writes_on_its_own(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(WatcherConfig(dump_interval=0.02, max_watches=100))
        rig.deliver(rig.event("work", IN_CREATE, "auto"))
        eventually(lambda: any(r.target == "work/auto" for r in rig.files()))

    def test_it_does_not_leave_threads_behind(self, make_rig: Callable[..., Rig]) -> None:
        rig = make_rig(WatcherConfig(dump_interval=0.02, max_watches=100))
        rig.watcher.close()
        names = {t.name for t in threading.enumerate()}
        assert not {n for n in names if n.startswith("vigia-watch")}


# -- the security review of T04a: each finding with the test that failed without its fix -----


class TestCoalescerBounds:
    """Finding 3: the memory of the coalescer is bounded by bytes, not only by entries."""

    def test_beyond_the_byte_cap_new_paths_are_counted_not_kept(self) -> None:
        co = Coalescer(max_bytes=3000)
        for i in range(10):
            co.created(f"{i}" + "x" * 500, is_dir=False, now=at(0), snapshot_id=S1)
        flush = co.flush(at(1))
        assert 0 < len(flush.records) < 10
        assert len(flush.records) + sum(flush.spilled.values()) == 10  # counted, never lost
        assert co.flush(at(2)).spilled == Counter()

    def test_the_byte_cap_also_holds_for_moves(self) -> None:
        co = Coalescer(max_bytes=3000)
        for i in range(10):
            co.moved_from(f"a{i}", i + 1, is_dir=False, now=at(0), snapshot_id=S1)
            co.moved_to(f"{i}" + "y" * 500, i + 1, is_dir=False, now=at(0), snapshot_id=S1)
        flush = co.flush(at(5), final=True)
        assert len(flush.records) + sum(flush.spilled.values()) >= 10
        assert sum(len(r.path) for r in flush.records) <= 3000

    def test_unpaired_moves_are_bounded_and_the_oldest_becomes_a_delete(self) -> None:
        co = Coalescer(max_unpaired=2)
        for i in range(5):  # a storm of renames out to folders nobody watches
            co.moved_from(f"f{i}", i + 1, is_dir=False, now=at(0), snapshot_id=S1)
        assert co.unpaired() <= 2
        co.moved_to("g4", 5, is_dir=False, now=at(0), snapshot_id=S1)  # a recent one still pairs
        records = {r.path: r for r in co.flush(at(0.1), final=True).records}
        assert records["g4"].action == "move" and records["g4"].origin == "f4"
        assert {p for p, r in records.items() if r.action == "delete"} == {"f0", "f1", "f2", "f3"}


class TestWalkerRaces:
    """Finding 1: a directory is never left unwatched without saying so."""

    def config(self, **kwargs: Any) -> WatcherConfig:
        return WatcherConfig(dump_interval=None, max_watches=100, rescan_cooldown=30, **kwargs)

    def test_a_pending_job_follows_its_parent_when_an_ancestor_is_renamed(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        """``mkdir work/y && mv work z``: the job for y must not be lost with the old path."""
        rig = make_rig(self.config())
        work = rig.agent_dir / "work"
        wd_work, wd_root = rig.ino.wd_of(work), rig.ino.wd_of(rig.agent_dir)
        (work / "y").mkdir()
        work.rename(rig.agent_dir / "z")
        rig.deliver(
            RawEvent(wd_work, IN_CREATE | IN_ISDIR, 0, b"y"),
            RawEvent(wd_root, IN_MOVED_FROM | IN_ISDIR, 21, b"work"),
            RawEvent(wd_root, IN_MOVED_TO | IN_ISDIR, 21, b"z"),
        )
        rig.settle()
        assert rig.ino.is_watching(rig.agent_dir / "z" / "y")
        rig.deliver(RawEvent(rig.ino.wd_of(rig.agent_dir / "z" / "y"), IN_CREATE, 0, b"f"))
        rig.settle()
        assert "z/y/f" in rig.by_target()
        assert rig.watcher.unwatched_count() == 0

    def test_a_job_whose_parent_moved_unseen_is_raced_and_the_rescan_fixes_it(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(self.config())
        work = rig.agent_dir / "work"
        wd_work, wd_root = rig.ino.wd_of(work), rig.ino.wd_of(rig.agent_dir)
        (work / "y").mkdir()
        work.rename(rig.agent_dir / "z")  # its events are not read yet
        with rig.watcher._cond:
            rig.watcher._last_rescan = rig.mono.now  # in the cooldown: no rescan right away
        rig.deliver(RawEvent(wd_work, IN_CREATE | IN_ISDIR, 0, b"y"))
        assert rig.watcher.wait_idle(5)
        assert rig.watcher.unwatched_count() == 1
        assert rig.watcher.report_unwatched()
        assert rig.files("dropped")[-1].details["reasons"] == {"raced": 1}
        rig.deliver(
            RawEvent(wd_root, IN_MOVED_FROM | IN_ISDIR, 22, b"work"),
            RawEvent(wd_root, IN_MOVED_TO | IN_ISDIR, 22, b"z"),
        )
        rig.mono.now += 31
        eventually(lambda: rig.watcher.stats().rescans == 1)
        rig.settle()
        assert rig.ino.is_watching(rig.agent_dir / "z" / "y")
        assert rig.watcher.unwatched_count() == 0

    def test_a_directory_that_cannot_be_opened_is_unwatched_not_only_logged(
        self, make_rig: Callable[..., Rig], caplog: pytest.LogCaptureFixture
    ) -> None:
        hostile = "token=SUPERSECRETVALUE123"  # a name the log must never show

        def refusing(fd: int, rel: bytes, flags: int) -> int:
            if rel.endswith(hostile.encode()):
                raise PermissionError(errno.EACCES, "denied", rel)
            return inotify.open_beneath(fd, rel, flags)

        rig = make_rig(self.config(), arm=False, opener=refusing)
        (rig.agent_dir / "work" / hostile).mkdir()
        with caplog.at_level("DEBUG", logger="vigia.sensors"):
            assert rig.watcher.arm(S1)
        assert rig.watcher.unwatched_count() == 1
        assert rig.watcher.report_unwatched()
        assert rig.files("dropped")[-1].details["reasons"] == {"refused": 1}
        assert "SUPERSECRETVALUE123" not in caplog.text  # finding 7: no agent path in the log

    def test_a_directory_swapped_for_a_symlink_between_listing_and_open_is_not_followed(
        self, make_rig: Callable[..., Rig], tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        swapped: list[bool] = []

        def swapping(fd: int, rel: bytes, flags: int) -> int:
            if rel.endswith(b"sub") and not swapped:
                swapped.append(True)
                sub = rig.agent_dir / "work" / "sub"
                sub.rmdir()
                sub.symlink_to(outside)
            return inotify.open_beneath(fd, rel, flags)

        rig = make_rig(self.config(), arm=False, opener=swapping)
        (rig.agent_dir / "work" / "sub").mkdir()
        assert rig.watcher.arm(S1)
        assert swapped and not rig.ino.is_watching(outside)
        assert rig.watcher.unwatched_count() == 0  # it is a link now: nothing to watch

    def test_a_directory_job_whose_name_is_now_a_symlink_is_not_followed(
        self, make_rig: Callable[..., Rig], tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        rig = make_rig(self.config())
        (rig.agent_dir / "work" / "d").symlink_to(outside)  # mkdir d; rmdir d; ln -s ... d
        rig.deliver(rig.event("work", IN_CREATE | IN_ISDIR, "d"))
        rig.settle()
        assert not rig.ino.is_watching(outside)
        assert rig.watcher.unwatched_count() == 0

    def test_a_full_directory_queue_is_a_dropped_with_its_window(
        self, make_rig: Callable[..., Rig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(files_module, "_MAX_QUEUED_DIRS", 0)
        rig = make_rig(self.config())
        (rig.agent_dir / "work" / "new").mkdir()
        (rig.agent_dir / "work" / "new" / "inside").write_text("x")
        rig.deliver(rig.event("work", IN_CREATE | IN_ISDIR, "new"))
        rig.watcher.set_current(S2)  # the rescan runs later: the window keeps S1
        rig.settle()
        (dropped,) = rig.files("dropped")
        assert dropped.details["reason"] == "dir_queue_full" and dropped.risk == 1
        assert dropped.details["since"] and dropped.details["until"]
        assert dropped.snapshot_id == S1
        assert rig.ino.is_watching(rig.agent_dir / "work" / "new")
        assert rig.by_target()["work/new/inside"].snapshot_id == S1


class TestDepthOnMoves:
    """Finding 2: moving a subtree under a deep directory cannot pass the depth cap."""

    def test_a_subtree_moved_too_deep_is_cut_at_the_cap_and_said(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(
            arm=False, config=WatcherConfig(dump_interval=None, max_depth=3, max_watches=100)
        )
        (rig.agent_dir / "a" / "b" / "c").mkdir(parents=True)  # c is at depth 3
        (rig.agent_dir / "d" / "e").mkdir(parents=True)  # e is at depth 2
        assert rig.watcher.arm(S1)
        assert rig.watcher.unwatched_count() == 0
        root, e = rig.ino.wd_of(rig.agent_dir), rig.ino.wd_of(rig.agent_dir / "d" / "e")
        (rig.agent_dir / "a").rename(rig.agent_dir / "d" / "e" / "a")
        rig.deliver(
            RawEvent(root, IN_MOVED_FROM | IN_ISDIR, 31, b"a"),
            RawEvent(e, IN_MOVED_TO | IN_ISDIR, 31, b"a"),
        )
        rig.settle()
        moved = rig.agent_dir / "d" / "e" / "a"
        assert rig.ino.is_watching(moved)  # depth 3: fits
        assert not rig.ino.is_watching(moved / "b")  # depth 4
        assert not rig.ino.is_watching(moved / "b" / "c")  # depth 5
        assert rig.watcher.report_unwatched()
        assert rig.files("dropped")[-1].details["reasons"] == {"depth": 1}
        (move,) = rig.files("move")  # still ONE record for the move, not a walk of creates
        assert move.target == "d/e/a" and move.details["from"] == "a"
        assert not rig.files("create")

    def test_a_subtree_that_still_fits_keeps_its_watches(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(
            arm=False, config=WatcherConfig(dump_interval=None, max_depth=4, max_watches=100)
        )
        (rig.agent_dir / "a" / "b").mkdir(parents=True)
        (rig.agent_dir / "d" / "e").mkdir(parents=True)
        assert rig.watcher.arm(S1)
        wd_b = rig.ino.wd_of(rig.agent_dir / "a" / "b")
        root, e = rig.ino.wd_of(rig.agent_dir), rig.ino.wd_of(rig.agent_dir / "d" / "e")
        (rig.agent_dir / "a").rename(rig.agent_dir / "d" / "e" / "a")
        rig.deliver(
            RawEvent(root, IN_MOVED_FROM | IN_ISDIR, 32, b"a"),
            RawEvent(e, IN_MOVED_TO | IN_ISDIR, 32, b"a"),
        )
        rig.settle()
        assert wd_b not in rig.ino.removed and rig.watcher.unwatched_count() == 0


class TestRenameStorms:
    def test_a_directory_moved_out_again_and_again_is_one_pending_move(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        """Finding 3: one entry per watched directory, whatever the number of cookies."""
        rig = make_rig()
        for cookie in range(1, 50):
            rig.deliver(rig.event(".", IN_MOVED_FROM | IN_ISDIR, "work", cookie=cookie))
        assert len(rig.watcher._dir_froms) == 1


class FloodInotify(FakeInotify):
    """A kernel queue that never empties: every read returns the same chunk again."""

    chunk = b""

    def flood(self, *events: RawEvent) -> None:
        raw = b""
        for event in events:
            name = event.name + b"\0" if event.name else b""
            raw += struct.pack("=iIII", event.wd, event.mask, event.cookie, len(name)) + name
        self.chunk = raw
        os.write(self._w, b"x")  # never read back: poll() keeps saying "readable"

    def queued(self) -> int:
        return len(self.chunk) if self.chunk else super().queued()

    def read(self) -> bytes:
        return self.chunk if self.chunk else super().read()


class BlockingInotify(FakeInotify):
    """A read() that hangs until released: a reader that is really stuck."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.block = threading.Event()
        self.inside = threading.Event()
        self.release = threading.Event()

    def read(self) -> bytes:
        if self.block.is_set():
            self.inside.set()
            self.release.wait(30)
        return super().read()


class TestSustainedFlood:
    """Finding 4: a queue that never empties cannot stop drain(), the expiry or the stop."""

    def test_drain_and_close_finish_under_a_flood_that_never_ends(
        self, make_rig: Callable[..., Rig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(files_module, "_DRAIN_TIMEOUT", 1.0)
        monkeypatch.setattr(files_module, "_JOIN_TIMEOUT", 1.0)
        rig = make_rig(ino_cls=FloodInotify)
        flood = rig.ino
        rig.deliver(rig.event("work", IN_MOVED_FROM, "old.txt", cookie=77))
        flood.flood(*[rig.event("work", IN_MODIFY, "old.txt") for _ in range(50)])
        assert rig.watcher.drain()
        rig.mono.now += 5
        rig.clock.advance(timedelta(seconds=5))
        eventually(lambda: rig.watcher._coalescer.unpaired() == 0)  # the expiry still runs
        rig.watcher.close()
        assert flood.closed
        assert rig.system("watcher_failed") == []

    def test_a_stuck_reader_is_recorded_and_never_touches_the_next_arming(
        self, make_rig: Callable[..., Rig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(files_module, "_JOIN_TIMEOUT", 0.5)
        rig = make_rig(ino_cls=BlockingInotify)
        old = rig.ino
        assert isinstance(old, BlockingInotify)
        root_wd = old.wd_of(rig.agent_dir)
        old.block.set()
        old.push(RawEvent(root_wd, IN_CREATE, 0, b"before"))
        assert old.inside.wait(5)
        try:
            rig.ws_id[0] = 200
            assert rig.watcher.rearm_if_moved(200)
            (failed,) = rig.system("watcher_failed")
            assert failed.details["reason"] == "reader_stuck" and failed.risk == 2
            assert old.watches == {}  # every watch removed, the sentinel too: it hears nothing
            assert not old.closed  # never closed under a reader that may still use it
            assert rig.ino is not old and rig.watcher.is_armed
            # the old reader wakes up with an event whose wd number exists in the new arming
            old.push(RawEvent(root_wd, IN_CREATE, 0, b"ghost"))
            old.release.set()
            eventually(lambda: old.closed)  # the orphaned reader closes its own instance
            rig.settle()
            assert "ghost" not in rig.by_target() and "before" not in rig.by_target()
        finally:
            old.release.set()


class TestSnapshotOfRescans:
    """Finding 5: a rescan never points to a snapshot newer than the loss it repairs."""

    def test_a_rescan_after_an_overflow_points_to_the_snapshot_of_the_overflow(
        self, make_rig: Callable[..., Rig]
    ) -> None:
        rig = make_rig(WatcherConfig(dump_interval=None, max_watches=100, rescan_cooldown=30))
        rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))
        rig.settle()  # the first rescan: now the cooldown runs
        made = rig.agent_dir / "work" / "made"
        made.mkdir()
        (made / "inside").write_text("x")
        rig.deliver(RawEvent(-1, IN_Q_OVERFLOW, 0, b""))  # its CREATE was lost, under S1
        rig.watcher.set_current(S2)  # S2 already contains "made"
        rig.mono.now += 31
        eventually(lambda: rig.watcher.stats().rescans == 2)
        rig.settle()
        by = rig.by_target("create")
        assert by["work/made"].snapshot_id == S1
        assert by["work/made/inside"].snapshot_id == S1

    def test_the_barrier_keeps_the_current_snapshot_if_the_second_drain_fails(
        self, make_rig: Callable[..., Rig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rig = make_rig()
        answers = iter([True, False])
        monkeypatch.setattr(rig.watcher, "drain", lambda settle=0.0: next(answers))
        snap = Snapshot.parse(S2)
        assert snap is not None
        assert rig.watcher.barrier(lambda: snap).id == S2
        assert rig.watcher.current == S1  # what is still unread may predate S2


class TestLongPaths:
    def test_the_name_is_kept_apart_so_a_cut_target_still_says_which_file(
        self, tmp_path: Path, clock: FakeClock
    ) -> None:
        """Finding 6: the black box cuts texts at 4 KiB keeping the start."""
        agent_dir = tmp_path / "ws" / "agente"
        agent_dir.mkdir(parents=True)
        fd = os.open(agent_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for i in range(20):  # 20 x 250 bytes: more than 4 KiB of path
                name = f"{i:02d}" + "d" * 248
                os.mkdir(name, dir_fd=fd)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = child
            deepest = os.fstat(fd).st_ino
        finally:
            os.close(fd)
        instances: list[FakeInotify] = []

        def factory() -> FakeInotify:
            instances.append(FakeInotify([]))
            return instances[-1]

        with BlackBox(tmp_path / "bb.db", bytes(range(32)), clock=clock) as box:
            watcher = FileWatcher(
                agent_dir,
                box,
                workspace_id=lambda: 1,
                config=WatcherConfig(dump_interval=None, max_watches=50),
                clock=clock,
                inotify_factory=factory,
            )
            try:
                assert watcher.arm(S1)
                wd = next(w for w, ino in instances[0].watches.items() if ino == deepest)
                instances[0].push(RawEvent(wd, IN_CREATE, 0, b"the-file-that-matters.txt"))
                assert watcher.drain()
                watcher.flush()
            finally:
                watcher.close()
            (event,) = [e for e in box.events(source="file") if e.action == "create"]
        assert "truncated" in event.target
        assert event.details["name"] == "the-file-that-matters.txt"


class TestDisarmOrder:
    def test_the_folder_descriptors_are_closed_only_while_no_flush_can_use_them(
        self, make_rig: Callable[..., Rig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Finding 9: flush() reads the root descriptor; close it under the emit lock."""
        rig = make_rig()
        root_fd = rig.watcher._root_fd
        seen: list[bool] = []
        real_close = os.close

        def spying(fd: int) -> None:
            if fd == root_fd and not seen:
                seen.append(rig.watcher._emit_lock.locked())
            real_close(fd)

        monkeypatch.setattr(files_module.os, "close", spying)
        rig.watcher.close()
        assert seen == [True]
