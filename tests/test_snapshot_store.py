"""Unit tests for SnapshotStore on the Mac: no btrfs.

FakeBtrfs stands in for every btrfs function the store calls. Subvolumes are plain directories
under tmp_path that it tracks (with their read-only flag and subvolume ID), renames really move
directories, and every call is appended to one ordered log, together with os.sync and the
recording quiesce. The lock, the layout checks and the directory listings are real.
"""

import contextlib
import errno
import logging
import os
import re
import shutil
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol

import pytest

import vigia.snapshots.store as store_module
from vigia.snapshots import (
    PruneIncomplete,
    Reason,
    RestoreIncomplete,
    Snapshot,
    SnapshotBusy,
    SnapshotError,
    SnapshotNoSpace,
    SnapshotStore,
    btrfs,
)

FAKED = (
    "create_subvolume",
    "snapshot",
    "is_readonly",
    "set_readonly",
    "delete_subvolume",
    "subvolume_id",
    "is_subvolume",
    "renameat2",
)
FLAG_NAMES = {btrfs.RENAME_EXCHANGE: "EXCHANGE", btrfs.RENAME_NOREPLACE: "NOREPLACE"}
OLD = Snapshot(datetime(2026, 10, 1, 12, 0, tzinfo=UTC), Reason.PERIODIC)
NESTED = "ERROR: Could not destroy subvolume: Directory not empty"
# What every out-of-space error must tell the user (NO_SPACE_HINT).
NO_SPACE = r"out of space: delete snapshots \(oldest first\) or grow the volume, then retry"

type Call = tuple[object, ...]


class Clock(Protocol):
    def __call__(self) -> datetime: ...
    def advance(self, delta: timedelta) -> None: ...


@dataclass
class Fault:
    name: str
    error: BaseException
    match: Callable[..., bool]
    after_effect: bool


class FakeBtrfs:
    """The btrfs functions, on plain directories. Paths in the log are relative to the root;
    renameat2 logs its flag by name. ``fail()`` makes the next matching call raise, either
    before it takes effect or, with ``after_effect``, after (an ambiguous CLI failure)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.log: list[Call] = []
        self.ids: dict[Path, int] = {}  # tracked subvolumes and their subvolume IDs
        self.readonly: set[Path] = set()
        self._faults: list[Fault] = []
        self._next_id = 256

    def fail(
        self,
        name: str,
        error: BaseException,
        *,
        match: Callable[..., bool] = lambda *args: True,
        after_effect: bool = False,
    ) -> None:
        self._faults.append(Fault(name, error, match, after_effect))

    def add_subvolume(self, path: Path, *, readonly: bool = False, marker: str = "") -> Path:
        """A subvolume made by hand, as a crash would leave it. Not logged."""
        path.mkdir()
        if marker:
            write_marker(path, marker)
        self._track(path, readonly)
        return path

    def calls(self, name: str) -> list[Call]:
        return [call for call in self.log if call[0] == name]

    # The faked functions

    def create_subvolume(self, path: Path) -> None:
        fault = self._record("create_subvolume", self._rel(path))
        path.mkdir()
        self._track(path, readonly=False)
        _raise(fault)

    def snapshot(self, src: Path, dst: Path, *, readonly: bool) -> None:
        fault = self._record("snapshot", self._rel(src), self._rel(dst), readonly)
        self._require_subvolume(src)
        if os.path.lexists(dst):
            raise SnapshotError(f"{dst} already exists", errno=errno.EEXIST)
        shutil.copytree(src, dst, symlinks=True)
        self._track(dst, readonly)
        _raise(fault)

    def is_readonly(self, path: Path) -> bool:
        fault = self._record("is_readonly", self._rel(path))
        self._require_subvolume(path)
        _raise(fault)
        return path in self.readonly

    def set_readonly(self, path: Path, value: bool) -> None:
        fault = self._record("set_readonly", self._rel(path), value)
        self._require_subvolume(path)
        if value:
            self.readonly.add(path)
        else:
            self.readonly.discard(path)
        _raise(fault)

    def delete_subvolume(self, path: Path, *, commit: bool = False) -> None:
        fault = self._record("delete_subvolume", self._rel(path), commit)
        self._require_subvolume(path)
        shutil.rmtree(path)
        del self.ids[path]
        self.readonly.discard(path)
        _raise(fault)

    def subvolume_id(self, path: Path) -> int:
        fault = self._record("subvolume_id", self._rel(path))
        self._require_subvolume(path)
        _raise(fault)
        return self.ids[path]

    def is_subvolume(self, path: Path) -> bool:
        fault = self._record("is_subvolume", self._rel(path))
        _raise(fault)
        return path in self.ids and path.is_dir() and not path.is_symlink()

    def renameat2(self, dir_fd: int, old: str, new: str, flags: int) -> None:
        fault = self._record("renameat2", old, new, FLAG_NAMES[flags])
        assert os.path.samestat(os.fstat(dir_fd), os.stat(self.root)), "not the root fd"
        for name in (old, new):
            assert not name.startswith("/") and ".." not in name.split("/"), name
        src, dst = self.root / old, self.root / new
        self._require_movable(src, dst)
        if flags == btrfs.RENAME_EXCHANGE:
            self._require_movable(dst, src)
            parked = self.root / ".fake-exchange"
            os.rename(src, parked)
            os.rename(dst, src)
            os.rename(parked, dst)
            self._retrack({src: dst, dst: src})
        else:
            if os.path.lexists(dst):
                raise SnapshotError(f"renameat2: {new} exists", errno=errno.EEXIST)
            os.rename(src, dst)
            self._retrack({src: dst})
        _raise(fault)

    def sync(self) -> None:
        self.log.append(("sync",))

    # Helpers

    def _record(self, name: str, *args: object) -> Fault | None:
        self.log.append((name, *args))
        for fault in self._faults:
            if fault.name == name and fault.match(*args):
                self._faults.remove(fault)
                if not fault.after_effect:
                    raise fault.error
                return fault
        return None

    def _rel(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    def _track(self, path: Path, readonly: bool) -> None:
        self.ids[path] = self._next_id
        self._next_id += 1
        if readonly:
            self.readonly.add(path)

    def _retrack(self, moves: dict[Path, Path]) -> None:
        ids = {moves[path]: self.ids.pop(path) for path in moves if path in self.ids}
        readonly = {moves[path] for path in moves if path in self.readonly}
        self.readonly -= set(moves)
        self.ids.update(ids)
        self.readonly |= readonly

    def _require_subvolume(self, path: Path) -> None:
        if path not in self.ids:
            raise SnapshotError(f"{path}: not a subvolume")

    def _require_movable(self, src: Path, dst: Path) -> None:
        if not os.path.lexists(src):
            raise SnapshotError(f"renameat2: {src} is missing", errno=errno.ENOENT)
        if src in self.readonly and src.parent != dst.parent:  # what the kernel does
            raise SnapshotError(f"renameat2: {src} is read-only", errno=errno.EROFS)


def _raise(fault: Fault | None) -> None:
    if fault is not None:
        raise fault.error


class Quiesce:
    """A recording quiesce, passed the way T04 will pass its factory: ``quiesce=q``."""

    def __init__(
        self,
        log: list[Call],
        *,
        on_enter: Callable[[], None] | None = None,
        enter_error: BaseException | None = None,
        exit_error: BaseException | None = None,
        swallow: bool = False,
    ) -> None:
        self.log = log
        self.on_enter = on_enter
        self.enter_error = enter_error
        self.exit_error = exit_error
        self.swallow = swallow
        self.exit_saw: BaseException | None = None

    def __call__(self) -> "Quiesce":
        return self

    def __enter__(self) -> None:
        self.log.append(("quiesce", "enter"))
        if self.on_enter is not None:
            self.on_enter()
        if self.enter_error is not None:
            raise self.enter_error

    def __exit__(self, exc_type: object, exc: BaseException | None, tb: object) -> bool:
        self.log.append(("quiesce", "exit"))
        self.exit_saw = exc
        if self.exit_error is not None:
            raise self.exit_error
        return self.swallow


def write_marker(path: Path, text: str) -> None:
    (path / "marker").write_text(text)


def marker(path: Path) -> str:
    return (path / "marker").read_text()


def open_fds() -> int:
    return len(os.listdir("/dev/fd"))


def _no_real_btrfs(*args: object, **kwargs: object) -> str:
    raise AssertionError("the store ran the real btrfs CLI")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "volume"
    root.mkdir()
    root.chmod(0o700)
    return root


@pytest.fixture
def fake(root: Path, monkeypatch: pytest.MonkeyPatch) -> FakeBtrfs:
    fake = FakeBtrfs(root)
    for name in FAKED:
        monkeypatch.setattr(btrfs, name, getattr(fake, name))
    monkeypatch.setattr(btrfs, "run", _no_real_btrfs)
    monkeypatch.setattr(os, "sync", fake.sync)
    return fake


@pytest.fixture
def store(root: Path, fake: FakeBtrfs, clock: Clock) -> SnapshotStore:
    """An initialised store whose workspace holds marker 'v0'. The log starts empty."""
    store = SnapshotStore(root, clock=clock, lock_timeout=1.0)
    store.init()
    write_marker(store.workspace, "v0")
    fake.log.clear()
    return store


def take(store: SnapshotStore, text: str, reason: Reason = Reason.PERIODIC) -> Snapshot:
    """Write ``text`` into the workspace marker, then take a snapshot."""
    write_marker(store.workspace, text)
    return store.take(reason)


def other_store(root: Path, clock: Clock, timeout: float = 0.1) -> SnapshotStore:
    return SnapshotStore(root, clock=clock, lock_timeout=timeout)


# Construction and ids from outside


def test_root_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="absolute"):
        SnapshotStore(Path("relative/volume"))


def test_constructor_touches_nothing(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "missing")

    assert store.root == tmp_path / "missing"
    assert store.workspace == tmp_path / "missing" / "workspace"
    assert store.snapshots_dir == tmp_path / "missing" / "snapshots"
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize(
    "snapshot_id",
    [
        "../workspace",
        "nope",
        "",
        "..",
        f"{OLD.id}/../../x",
        f".incoming-{OLD.id}",
        f".trash-{OLD.id}",
        "workspace.restore",
        f"{OLD.id}\n",
    ],
)
@pytest.mark.parametrize("operation", ["restore", "delete"])
def test_invalid_ids_fail_before_any_io(
    root: Path, fake: FakeBtrfs, snapshot_id: str, operation: str
) -> None:
    store = SnapshotStore(root)

    with pytest.raises(SnapshotError, match="invalid snapshot id"):
        if operation == "restore":
            store.restore(snapshot_id, quiesce=contextlib.nullcontext)
        else:
            store.delete(snapshot_id)

    assert fake.log == []
    assert os.listdir(root) == []  # not even .lock


def test_take_rejects_a_reason_that_is_not_a_reason(root: Path, fake: FakeBtrfs) -> None:
    with pytest.raises(ValueError):
        SnapshotStore(root).take("evidence/../x")  # type: ignore[arg-type]

    assert fake.log == []
    assert os.listdir(root) == []


# Layout


def test_init_creates_a_private_layout_and_is_idempotent(
    root: Path, fake: FakeBtrfs, clock: Clock
) -> None:
    store = SnapshotStore(root, clock=clock)
    store.init()

    assert stat.S_IMODE(os.lstat(store.snapshots_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(root / ".lock").st_mode) == 0o600
    assert store.workspace in fake.ids
    assert store.workspace not in fake.readonly
    assert fake.calls("create_subvolume") == [("create_subvolume", "workspace")]

    store.init()
    assert len(fake.calls("create_subvolume")) == 1


def test_init_refuses_an_empty_workspace_when_snapshots_exist(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    take(store, "v1")
    newest = take(store, "v2")
    fake.delete_subvolume(store.workspace)

    with pytest.raises(SnapshotError, match=rf"restore\('{newest.id}'\)"):
        store.init()
    assert not os.path.lexists(store.workspace)


def test_init_only_warns_about_a_readonly_workspace(
    store: SnapshotStore, fake: FakeBtrfs, caplog: pytest.LogCaptureFixture
) -> None:
    fake.readonly.add(store.workspace)

    with caplog.at_level(logging.WARNING):
        store.init()

    assert "read-only" in caplog.text


def test_init_refuses_a_workspace_that_is_a_plain_directory(root: Path, fake: FakeBtrfs) -> None:
    (root / "workspace").mkdir()

    with pytest.raises(SnapshotError, match="not a subvolume"):
        SnapshotStore(root).init()
    assert fake.calls("create_subvolume") == []


@pytest.mark.parametrize("operation", ["init", "take"])
def test_a_root_open_to_others_is_refused(
    store: SnapshotStore, fake: FakeBtrfs, operation: str
) -> None:
    store.root.chmod(0o755)

    with pytest.raises(SnapshotError, match="mode 0755"):
        getattr(store, operation)(*([Reason.PERIODIC] if operation == "take" else []))
    assert fake.calls("snapshot") == []
    assert fake.calls("create_subvolume") == []


def test_a_snapshots_dir_open_to_others_is_refused(store: SnapshotStore, fake: FakeBtrfs) -> None:
    store.snapshots_dir.chmod(0o750)

    with pytest.raises(SnapshotError, match="mode 0750"):
        store.take(Reason.PERIODIC)
    assert fake.calls("snapshot") == []


def test_a_snapshots_dir_that_is_a_symlink_is_refused(
    store: SnapshotStore, fake: FakeBtrfs, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    store.snapshots_dir.rmdir()
    store.snapshots_dir.symlink_to(elsewhere)

    with pytest.raises(SnapshotError, match="not a directory"):
        store.take(Reason.PERIODIC)
    with pytest.raises(SnapshotError, match="not a directory"):
        store.init()
    assert os.listdir(elsewhere) == []


def test_directories_owned_by_another_user_are_refused(
    store: SnapshotStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)

    with pytest.raises(SnapshotError, match=f"owned by uid {real_euid}"):
        store.take(Reason.PERIODIC)


def test_a_root_that_is_a_symlink_is_refused(root: Path, fake: FakeBtrfs, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(root)

    with pytest.raises(SnapshotError) as excinfo:
        SnapshotStore(link).init()

    # O_NOFOLLOW gives ELOOP on Linux; with O_DIRECTORY, macOS says ENOTDIR first.
    assert excinfo.value.errno in (errno.ELOOP, errno.ENOTDIR)
    assert os.listdir(root) == []


def test_a_lock_file_that_is_a_symlink_is_refused(
    root: Path, fake: FakeBtrfs, tmp_path: Path
) -> None:
    (root / ".lock").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(SnapshotError) as excinfo:
        SnapshotStore(root).init()

    assert excinfo.value.errno == errno.ELOOP
    assert not (tmp_path / "elsewhere").exists()


def test_take_on_an_uninitialised_root_points_at_init(root: Path, fake: FakeBtrfs) -> None:
    with pytest.raises(SnapshotError, match=r"run init\(\) first"):
        SnapshotStore(root).take(Reason.PERIODIC)


def test_take_needs_the_workspace(store: SnapshotStore, fake: FakeBtrfs) -> None:
    fake.delete_subvolume(store.workspace)

    with pytest.raises(SnapshotError, match="workspace is missing"):
        store.take(Reason.PERIODIC)


# Lock


def _operations(snap_id: str) -> dict[str, Callable[[SnapshotStore], object]]:
    return {
        "init": lambda s: s.init(),
        "take": lambda s: s.take(Reason.PERIODIC),
        "restore": lambda s: s.restore(snap_id, quiesce=contextlib.nullcontext),
        "delete": lambda s: s.delete(snap_id),
        "prune": lambda s: s.prune(),
        "recover": lambda s: s.recover(),
    }


@pytest.mark.parametrize("operation", list(_operations(OLD.id)))
def test_a_second_store_gets_busy_while_the_lock_is_held(
    store: SnapshotStore, fake: FakeBtrfs, clock: Clock, operation: str
) -> None:
    snap = take(store, "v1")
    run = _operations(snap.id)[operation]
    other = other_store(store.root, clock)

    with store._lock():
        fake.log.clear()
        with pytest.raises(SnapshotBusy):
            run(other)
        assert fake.log == []

    run(other)  # the lock is free again as soon as the holder releases it


def test_the_lock_is_polled_until_the_timeout(store: SnapshotStore, clock: Clock) -> None:
    other = other_store(store.root, clock, timeout=0.2)

    with store._lock():
        started = time.monotonic()
        with pytest.raises(SnapshotBusy, match="after 0.2 s"):
            other.take(Reason.PERIODIC)

    assert time.monotonic() - started >= 0.2


def test_the_lock_fds_are_closed_when_the_body_raises(store: SnapshotStore, clock: Clock) -> None:
    before = open_fds()

    with pytest.raises(RuntimeError), store._lock():
        raise RuntimeError("boom")

    assert open_fds() == before
    other_store(store.root, clock, timeout=0).take(Reason.PERIODIC)


def test_btrfs_children_inherit_the_lock_fd(
    store: SnapshotStore, fake: FakeBtrfs, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_hold = btrfs.children_hold
    held: list[int] = []

    @contextlib.contextmanager
    def recording_hold(fd: int) -> Iterator[None]:
        assert os.path.samestat(os.fstat(fd), os.stat(store.root / ".lock"))
        held.append(fd)
        fake.log.append(("hold", "enter"))
        with real_hold(fd):
            yield
        fake.log.append(("hold", "exit"))

    monkeypatch.setattr(btrfs, "children_hold", recording_hold)
    snap = store.take(Reason.PERIODIC)

    assert len(held) == 1
    names = [call[0] for call in fake.log]
    assert names[0] == "hold" and names[-1] == "hold"
    assert ("snapshot", "workspace", f"snapshots/{snap.id}", True) in fake.log


# Take and list


def test_take_creates_a_readonly_snapshot_of_the_workspace(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    snap = take(store, "v1", Reason.MANUAL)

    assert snap == Snapshot(datetime(2026, 10, 5, 8, 0, tzinfo=UTC), Reason.MANUAL)
    path = store.snapshots_dir / snap.id
    assert ("snapshot", "workspace", f"snapshots/{snap.id}", True) in fake.log
    assert path in fake.readonly
    assert marker(path) == "v1"
    assert store.snapshots() == [snap]


def test_two_takes_get_distinct_ordered_ids(store: SnapshotStore) -> None:
    first = store.take(Reason.PERIODIC)
    second = store.take(Reason.PERIODIC)

    assert first.id < second.id
    assert store.snapshots() == [first, second]


def test_take_ignores_crash_leftovers(store: SnapshotStore, fake: FakeBtrfs) -> None:
    fake.add_subvolume(store.root / "workspace.restore", marker="staged")
    fake.add_subvolume(store.snapshots_dir / f".incoming-{OLD.id}")
    fake.add_subvolume(store.snapshots_dir / f".trash-{OLD.id}", readonly=True)
    before = sorted(os.listdir(store.root)), sorted(os.listdir(store.snapshots_dir))

    snap = store.take(Reason.PERIODIC)

    assert fake.calls("renameat2") == [] and fake.calls("delete_subvolume") == []
    assert sorted(os.listdir(store.root)) == before[0]
    assert sorted(os.listdir(store.snapshots_dir)) == sorted([*before[1], snap.id])


def test_take_succeeds_when_btrfs_fails_after_creating_the_snapshot(
    store: SnapshotStore, fake: FakeBtrfs, caplog: pytest.LogCaptureFixture
) -> None:
    fake.fail("snapshot", SnapshotError("btrfs subvolume snapshot timed out"), after_effect=True)

    with caplog.at_level(logging.WARNING):
        snap = store.take(Reason.PERIODIC)

    assert store.snapshots() == [snap]
    assert "timed out" in caplog.text


def test_take_reraises_when_the_snapshot_was_not_created(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    error = SnapshotNoSpace("No space left on device", errno=errno.ENOSPC)
    fake.fail("snapshot", error)

    with pytest.raises(SnapshotNoSpace) as excinfo:
        store.take(Reason.PERIODIC)

    assert excinfo.value is error
    assert store.snapshots() == []


def test_take_never_claims_an_existing_snapshot(root: Path, fake: FakeBtrfs) -> None:
    instant = datetime(2026, 10, 5, 8, 0, tzinfo=UTC)
    store = SnapshotStore(root, clock=lambda: instant)
    store.init()
    store.take(Reason.PERIODIC)

    with pytest.raises(SnapshotError) as excinfo:
        store.take(Reason.PERIODIC)

    assert excinfo.value.errno == errno.EEXIST


def test_take_logs_an_error_when_the_clock_is_behind(
    store: SnapshotStore, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    first = store.take(Reason.PERIODIC)
    clock.advance(timedelta(hours=-1))

    with caplog.at_level(logging.ERROR):
        second = store.take(Reason.PERIODIC)

    assert "clock is behind the newest snapshot by 0:59:59" in caplog.text
    assert second.taken_at < first.taken_at  # never clamped
    assert store.snapshots() == [second, first]


def test_take_logs_no_error_when_the_clock_moves_forward(
    store: SnapshotStore, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR):
        store.take(Reason.PERIODIC)
        store.take(Reason.PERIODIC)

    assert caplog.records == []


def test_snapshots_lists_only_published_snapshots(
    store: SnapshotStore, fake: FakeBtrfs, clock: Clock
) -> None:
    first = take(store, "v1")
    second = take(store, "v2", Reason.MANUAL)
    later = Snapshot(datetime(2026, 10, 6, tzinfo=UTC), "evidence")
    fake.add_subvolume(store.snapshots_dir / later.id, readonly=True)  # unknown reason: listed
    (store.snapshots_dir / OLD.id).mkdir()  # a plain directory with a valid name
    (store.snapshots_dir / "junk").write_text("x")
    (store.snapshots_dir / "link").symlink_to(store.workspace)
    fake.add_subvolume(store.snapshots_dir / f".incoming-{OLD.id}")
    fake.add_subvolume(store.snapshots_dir / f".trash-{first.id}")

    with store._lock():  # takes no lock
        assert store.snapshots() == [first, second, later]


# Restore


def test_restore_order_is_exact_and_holds_the_lock_inside_quiesce(
    store: SnapshotStore, fake: FakeBtrfs, clock: Clock
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    busy: list[SnapshotBusy] = []

    def take_from_another_store() -> None:
        with pytest.raises(SnapshotBusy) as excinfo:
            other_store(store.root, clock).take(Reason.PERIODIC)
        busy.append(excinfo.value)

    quiesce = Quiesce(fake.log, on_enter=take_from_another_store)
    fake.log.clear()

    result = store.restore(target.id, quiesce=quiesce)

    undo = result.undo
    assert undo is not None and undo.reason == Reason.PRE_RESTORE
    staging = ("snapshot", f"snapshots/{target.id}", "workspace.restore", False)
    start = fake.log.index(staging)
    assert fake.log[start:] == [
        staging,
        ("quiesce", "enter"),
        ("renameat2", "workspace.restore", "workspace", "EXCHANGE"),
        ("is_readonly", "workspace.restore"),
        ("renameat2", "workspace.restore", f"snapshots/.incoming-{undo.id}", "NOREPLACE"),
        ("set_readonly", f"snapshots/.incoming-{undo.id}", True),
        ("renameat2", f"snapshots/.incoming-{undo.id}", f"snapshots/{undo.id}", "NOREPLACE"),
        ("sync",),
        ("quiesce", "exit"),
    ]
    validation = fake.log[:start]
    assert ("is_subvolume", f"snapshots/{target.id}") in validation
    assert ("is_readonly", f"snapshots/{target.id}") in validation
    assert len(busy) == 1


def test_restore_rewinds_and_keeps_the_old_workspace_as_the_undo_point(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    before = store.workspace_id()

    result = store.restore(target.id, quiesce=contextlib.nullcontext)

    assert result.target == target and result.recovered == ()
    assert result.undo is not None
    assert marker(store.workspace) == "v1"
    assert store.workspace not in fake.readonly
    assert store.workspace_id() != before
    undo_path = store.snapshots_dir / result.undo.id
    assert marker(undo_path) == "v2" and undo_path in fake.readonly
    assert fake.ids[undo_path] == before  # the old workspace itself, not a copy
    assert store.snapshots() == [target, result.undo]
    assert sorted(os.listdir(store.root)) == [".lock", "snapshots", "workspace"]

    store.restore(result.undo.id, quiesce=contextlib.nullcontext)  # undo
    assert marker(store.workspace) == "v2"
    assert [snap.reason for snap in store.snapshots()].count(Reason.PRE_RESTORE) == 2


def test_restore_flips_a_readonly_workspace_before_moving_it(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    fake.readonly.add(store.workspace)  # the agent flipped its own workspace

    result = store.restore(target.id, quiesce=contextlib.nullcontext)

    assert result.undo is not None
    flip = fake.log.index(("set_readonly", "workspace.restore", False))
    move = fake.log.index(
        ("renameat2", "workspace.restore", f"snapshots/.incoming-{result.undo.id}", "NOREPLACE")
    )
    assert flip < move
    assert store.snapshots_dir / result.undo.id in fake.readonly
    assert store.workspace not in fake.readonly


def test_restore_recreates_a_missing_workspace(store: SnapshotStore, fake: FakeBtrfs) -> None:
    target = take(store, "v1")
    fake.delete_subvolume(store.workspace)
    fake.log.clear()

    result = store.restore(target.id, quiesce=contextlib.nullcontext)

    assert result.undo is None
    assert ("renameat2", "workspace.restore", "workspace", "NOREPLACE") in fake.log
    assert fake.log[-1] == ("sync",)
    assert marker(store.workspace) == "v1"
    store.take(Reason.PERIODIC)


def test_restore_of_an_unknown_snapshot_changes_nothing(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    quiesce = Quiesce(fake.log)

    with pytest.raises(SnapshotError, match="no such snapshot"):
        store.restore(OLD.id, quiesce=quiesce)

    assert fake.calls("snapshot") == [] and fake.calls("quiesce") == []


def test_restore_refuses_a_writable_snapshot(store: SnapshotStore, fake: FakeBtrfs) -> None:
    target = take(store, "v1")
    fake.readonly.discard(store.snapshots_dir / target.id)

    with pytest.raises(SnapshotError, match="writable"):
        store.restore(target.id, quiesce=Quiesce(fake.log))

    assert fake.calls("snapshot") == [("snapshot", "workspace", f"snapshots/{target.id}", True)]
    assert fake.calls("quiesce") == []


def test_a_staging_copy_left_by_a_failed_snapshot_command_is_deleted(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    fake.fail(
        "snapshot",
        SnapshotError("btrfs subvolume snapshot failed"),
        match=lambda src, dst, readonly: dst == "workspace.restore",
        after_effect=True,
    )

    with pytest.raises(SnapshotError, match="before the swap; workspace unchanged"):
        store.restore(target.id, quiesce=Quiesce(fake.log))

    assert ("delete_subvolume", "workspace.restore", False) in fake.log
    assert not os.path.lexists(store.root / "workspace.restore")
    assert fake.calls("quiesce") == []
    assert marker(store.workspace) == "v2"


def test_a_staging_snapshot_out_of_space_says_what_to_do(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    fake.fail(
        "snapshot",
        SnapshotNoSpace("No space left on device", errno=errno.ENOSPC),
        match=lambda src, dst, readonly: dst == "workspace.restore",
    )

    with pytest.raises(SnapshotNoSpace, match=NO_SPACE) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log))

    assert excinfo.value.errno == errno.ENOSPC
    assert fake.calls("quiesce") == []


def test_a_failing_quiesce_enter_propagates_unchanged_and_nothing_changes(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    before = store.workspace_id()
    error = RuntimeError("docker stop failed")

    with pytest.raises(RuntimeError) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log, enter_error=error))

    assert excinfo.value is error
    assert ("delete_subvolume", "workspace.restore", False) in fake.log
    assert fake.calls("renameat2") == [] and ("sync",) not in fake.log
    assert ("quiesce", "exit") not in fake.log
    assert store.workspace_id() == before and marker(store.workspace) == "v2"
    assert not os.path.lexists(store.root / "workspace.restore")


def test_a_failed_exchange_deletes_staging_and_exits_quiesce(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    fake.fail("renameat2", SnapshotError("renameat2 failed: I/O error", errno=errno.EIO))
    quiesce = Quiesce(fake.log)

    with pytest.raises(SnapshotError, match="before the swap; workspace unchanged") as excinfo:
        store.restore(target.id, quiesce=quiesce)

    assert not isinstance(excinfo.value, SnapshotNoSpace)
    assert ("delete_subvolume", "workspace.restore", False) in fake.log
    assert fake.log[-1] == ("quiesce", "exit") and quiesce.exit_saw is excinfo.value
    assert ("sync",) not in fake.log
    assert marker(store.workspace) == "v2"
    assert not os.path.lexists(store.root / "workspace.restore")


def test_a_full_metadata_exchange_raises_no_space_with_staging_cleaned(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    fake.fail(
        "renameat2",
        SnapshotNoSpace("renameat2 failed: No space left on device", errno=errno.ENOSPC),
        match=lambda old, new, flags: flags == "EXCHANGE",
    )

    with pytest.raises(SnapshotNoSpace, match=NO_SPACE) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log))

    assert excinfo.value.errno == errno.ENOSPC
    assert "workspace unchanged" in str(excinfo.value)
    assert not os.path.lexists(store.root / "workspace.restore")
    assert marker(store.workspace) == "v2"
    assert fake.log[-1] == ("quiesce", "exit")


@dataclass(frozen=True)
class PublishFailure:
    name: str
    match: Callable[..., bool]
    leftover_is_incoming: bool
    published_reason: Reason


PUBLISH_FAILURES = {
    "move to .incoming": PublishFailure(
        "renameat2",
        lambda old, new, flags: old == "workspace.restore" and ".incoming-" in new,
        leftover_is_incoming=False,
        published_reason=Reason.RECOVERED,  # R3
    ),
    "seal": PublishFailure(
        "set_readonly",
        lambda path, value: ".incoming-" in path,
        leftover_is_incoming=True,
        published_reason=Reason.PRE_RESTORE,  # R2
    ),
    "final rename": PublishFailure(
        "renameat2",
        lambda old, new, flags: ".incoming-" in old,
        leftover_is_incoming=True,
        published_reason=Reason.PRE_RESTORE,  # R2
    ),
}


@pytest.mark.parametrize("no_space", [False, True], ids=["error", "no space"])
@pytest.mark.parametrize("step", list(PUBLISH_FAILURES))
def test_a_publish_failure_after_the_swap_raises_restore_incomplete(
    store: SnapshotStore, fake: FakeBtrfs, step: str, no_space: bool
) -> None:
    failure = PUBLISH_FAILURES[step]
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    cause = (
        SnapshotNoSpace(f"{step}: No space left on device", errno=errno.ENOSPC)
        if no_space
        else SnapshotError(f"{step} failed")
    )
    fake.fail(failure.name, cause, match=failure.match)
    quiesce = Quiesce(fake.log)

    with pytest.raises(RestoreIncomplete) as excinfo:
        store.restore(target.id, quiesce=quiesce)

    error = excinfo.value
    assert not isinstance(error, SnapshotError)
    assert error.target == target
    assert error.__cause__ is cause
    # Every recover() fails the same way until space is freed, so say how to free it.
    hint = "\n".join(getattr(error, "__notes__", ()))
    assert bool(re.search(NO_SPACE, hint)) == no_space, hint
    if failure.leftover_is_incoming:
        assert error.leftover.parent == store.snapshots_dir
        assert error.leftover.name.startswith(".incoming-")
    else:
        assert error.leftover == store.root / "workspace.restore"
    assert marker(error.leftover) == "v2"
    assert marker(store.workspace) == "v1"  # the rewind happened
    assert fake.log[-2:] == [("sync",), ("quiesce", "exit")]
    assert quiesce.exit_saw is error

    recovered = store.recover()

    assert [snap.reason for snap in recovered] == [failure.published_reason]
    published = store.snapshots_dir / recovered[0].id
    assert marker(published) == "v2" and published in fake.readonly
    assert not os.path.lexists(error.leftover)


def test_a_clock_that_breaks_after_the_swap_raises_restore_incomplete(
    root: Path, fake: FakeBtrfs, clock: Clock
) -> None:
    reads = iter([clock(), datetime(2026, 10, 5, 10, 0)])  # the second one is naive
    store = SnapshotStore(root, clock=lambda: next(reads))
    store.init()
    target = store.take(Reason.PERIODIC)

    with pytest.raises(RestoreIncomplete) as excinfo:
        store.restore(target.id, quiesce=contextlib.nullcontext)

    assert excinfo.value.leftover == root / "workspace.restore"
    assert isinstance(excinfo.value.__cause__, ValueError)


def test_an_error_from_quiesce_exit_propagates_after_the_rewind(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    error = RuntimeError("docker start failed")

    with pytest.raises(RuntimeError) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log, exit_error=error))

    assert excinfo.value is error
    assert marker(store.workspace) == "v1"
    assert [snap.reason for snap in store.snapshots()] == [Reason.PERIODIC, Reason.PRE_RESTORE]


def test_a_snapshot_error_from_quiesce_exit_after_the_rewind_says_it_happened(
    store: SnapshotStore, fake: FakeBtrfs, caplog: pytest.LogCaptureFixture
) -> None:
    """A SnapshotError means 'workspace unchanged', so one raised by T04's exit code (say,
    workspace_id() timing out while re-arming the watcher) must say the rewind did happen."""
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    error = SnapshotError("btrfs inspect-internal rootid timed out")

    with caplog.at_level(logging.INFO), pytest.raises(SnapshotError) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log, exit_error=error))

    assert excinfo.value is error  # still the caller's own exception, unchanged
    undo = store.snapshots()[-1]
    assert undo.reason == Reason.PRE_RESTORE
    notes = "\n".join(error.__notes__)
    assert "restore DID happen" in notes
    assert target.id in notes and undo.id in notes
    assert marker(store.workspace) == "v1"
    assert f"workspace restored to {target.id}; undo point {undo.id}" in caplog.text


def test_an_error_from_quiesce_exit_after_a_publish_failure_names_the_leftover(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    fake.fail(
        "set_readonly",
        SnapshotNoSpace("seal: No space left on device", errno=errno.ENOSPC),
        match=lambda path, value: value,
    )
    error = RuntimeError("docker start failed")

    with pytest.raises(RuntimeError) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log, exit_error=error))

    assert excinfo.value is error
    incomplete = error.__context__
    assert isinstance(incomplete, RestoreIncomplete)
    notes = "\n".join(error.__notes__)
    assert "restore DID happen" in notes and str(incomplete.leftover) in notes
    assert "the next recover() publishes it" in notes
    assert re.search(NO_SPACE, notes), notes


def test_an_error_from_quiesce_exit_after_a_failed_swap_says_nothing_changed(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    target = take(store, "v1")
    write_marker(store.workspace, "v2")
    fake.fail("renameat2", SnapshotError("renameat2 failed: I/O error", errno=errno.EIO))
    error = RuntimeError("docker start failed")

    with pytest.raises(RuntimeError) as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log, exit_error=error))

    assert excinfo.value is error
    assert isinstance(error.__context__, SnapshotError)
    assert "did NOT happen, workspace unchanged" in "\n".join(error.__notes__)
    assert marker(store.workspace) == "v2"


def test_a_failure_after_recovery_still_names_what_recovery_published(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    take(store, "v1")
    fake.add_subvolume(store.root / "workspace.restore", marker="leftover")

    with pytest.raises(SnapshotError, match="no such snapshot") as excinfo:
        store.restore(OLD.id, quiesce=Quiesce(fake.log))

    recovered = store.snapshots()[-1]
    assert recovered.reason == Reason.RECOVERED
    assert f"recovery published first: {recovered.id}" in excinfo.value.__notes__


def test_a_quiesce_cannot_swallow_restore_errors(store: SnapshotStore, fake: FakeBtrfs) -> None:
    target = take(store, "v1")
    fake.fail("renameat2", SnapshotError("renameat2 failed", errno=errno.EIO))

    with pytest.raises(SnapshotError, match="before the swap"):
        store.restore(target.id, quiesce=Quiesce(fake.log, swallow=True))


def test_restore_publishes_crash_leftovers_first(store: SnapshotStore, fake: FakeBtrfs) -> None:
    target = take(store, "v1")
    fake.add_subvolume(store.root / "workspace.restore", marker="leftover")

    result = store.restore(target.id, quiesce=contextlib.nullcontext)

    assert [snap.reason for snap in result.recovered] == [Reason.RECOVERED]
    recovered = store.snapshots_dir / result.recovered[0].id
    assert marker(recovered) == "leftover" and recovered in fake.readonly
    assert marker(store.workspace) == "v1"


def test_restore_stops_when_recovery_finds_tampering(store: SnapshotStore, fake: FakeBtrfs) -> None:
    target = take(store, "v1")
    (store.root / "workspace.restore").mkdir()  # a plain directory, not a subvolume

    with pytest.raises(SnapshotError, match="tampering") as excinfo:
        store.restore(target.id, quiesce=Quiesce(fake.log))

    assert "the workspace is unchanged" in "\n".join(excinfo.value.__notes__)
    assert fake.calls("quiesce") == []
    assert len(fake.calls("snapshot")) == 1  # only the take
    assert (store.root / "workspace.restore").is_dir()


# Delete


def test_delete_goes_through_a_tombstone_and_commits(store: SnapshotStore, fake: FakeBtrfs) -> None:
    snap = take(store, "v1", Reason.MANUAL)  # protected, but an explicit delete is allowed
    fake.log.clear()

    store.delete(snap.id)

    trash = f"snapshots/.trash-{snap.id}"
    assert fake.calls("renameat2") == [("renameat2", f"snapshots/{snap.id}", trash, "NOREPLACE")]
    assert fake.calls("delete_subvolume") == [("delete_subvolume", trash, True)]
    assert store.snapshots() == []
    assert os.listdir(store.snapshots_dir) == []


def test_delete_of_an_unknown_snapshot_fails(store: SnapshotStore, fake: FakeBtrfs) -> None:
    with pytest.raises(SnapshotError, match="no such snapshot"):
        store.delete(OLD.id)

    assert fake.calls("renameat2") == []


def test_a_nested_subvolume_blocking_a_delete_gives_a_hint(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    snap = take(store, "v1")
    fake.fail("delete_subvolume", SnapshotError(NESTED))

    with pytest.raises(SnapshotError, match="nested subvolume") as excinfo:
        store.delete(snap.id)

    assert "btrfs subvolume delete -R" in str(excinfo.value)
    assert excinfo.value.errno == errno.ENOTEMPTY
    assert store.snapshots() == [snap]
    assert store.snapshots_dir / snap.id in fake.readonly


def test_delete_works_in_place_when_renames_are_out_of_space(
    store: SnapshotStore, fake: FakeBtrfs, caplog: pytest.LogCaptureFixture
) -> None:
    snap = take(store, "v1")
    fake.fail("renameat2", SnapshotNoSpace("renameat2 failed", errno=errno.ENOSPC))

    with caplog.at_level(logging.WARNING):
        store.delete(snap.id)

    assert fake.calls("delete_subvolume") == [("delete_subvolume", f"snapshots/{snap.id}", True)]
    assert store.snapshots() == []
    assert "in place" in caplog.text


def test_a_failed_in_place_delete_leaves_the_snapshot_read_only(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    """An earlier in-place delete that died after clearing ro left it writable: a failed delete
    must not leave it that way, or restore() refuses it."""
    snap = take(store, "v1")
    fake.readonly.discard(store.snapshots_dir / snap.id)
    fake.fail("renameat2", SnapshotNoSpace("renameat2 failed", errno=errno.ENOSPC))
    fake.fail("delete_subvolume", SnapshotError(NESTED))

    with pytest.raises(SnapshotError, match="nested subvolume"):
        store.delete(snap.id)

    assert store.snapshots() == [snap]
    assert store.snapshots_dir / snap.id in fake.readonly


def test_the_nested_subvolume_hint_keeps_the_notes_of_its_cause(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    snap = take(store, "v1")
    cause = SnapshotError(NESTED)
    cause.add_note("restoring ro=true on the snapshot also failed")
    fake.fail("delete_subvolume", cause)

    with pytest.raises(SnapshotError, match="nested subvolume") as excinfo:
        store.delete(snap.id)

    assert excinfo.value is not cause
    assert "restoring ro=true on the snapshot also failed" in excinfo.value.__notes__


# Prune


@pytest.fixture
def history(store: SnapshotStore, clock: Clock) -> dict[str, Snapshot]:
    """Periodic snapshots at 08:00, 08:05, 08:10 and 08:20, a manual one at 08:15, and the clock
    moved to about 11:20. The 08:10 one anchors the manual; 08:20 is the newest of its hour."""
    taken: dict[str, Snapshot] = {}
    for name, minutes, reason in [
        ("p0800", 0, Reason.PERIODIC),
        ("p0805", 5, Reason.PERIODIC),
        ("p0810", 5, Reason.PERIODIC),
        ("m0815", 5, Reason.MANUAL),
        ("p0820", 5, Reason.PERIODIC),
    ]:
        clock.advance(timedelta(minutes=minutes))
        taken[name] = store.take(reason)
    clock.advance(timedelta(hours=3))
    return taken


def test_prune_deletes_what_retention_expires(
    store: SnapshotStore, fake: FakeBtrfs, history: dict[str, Snapshot]
) -> None:
    fake.log.clear()

    deleted = store.prune()

    assert deleted == [history["p0800"], history["p0805"]]
    assert store.snapshots() == [history["p0810"], history["m0815"], history["p0820"]]
    assert [call[2] for call in fake.calls("delete_subvolume")] == [False, False]


def test_prune_attempts_everything_then_raises(
    store: SnapshotStore,
    fake: FakeBtrfs,
    history: dict[str, Snapshot],
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = history["p0800"]
    fake.fail(
        "delete_subvolume",
        SnapshotError("Permission denied"),
        match=lambda path, commit: first.id in path,
    )

    with caplog.at_level(logging.ERROR), pytest.raises(PruneIncomplete) as excinfo:
        store.prune()

    assert isinstance(excinfo.value, SnapshotError)
    assert excinfo.value.deleted == [history["p0805"]]
    assert excinfo.value.failed == [first]
    assert first in store.snapshots()  # renamed back from its tombstone
    assert first.id in caplog.text


def test_prune_warns_about_many_snapshots_and_low_space(
    store: SnapshotStore,
    history: dict[str, Snapshot],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(store_module, "WARN_SNAPSHOT_COUNT", 2)
    monkeypatch.setattr(
        shutil, "disk_usage", lambda path: SimpleNamespace(total=1000, used=950, free=50)
    )

    with caplog.at_level(logging.WARNING):
        store.prune()

    assert "3 snapshots kept, more than 2 (manual: 1, periodic: 2)" in caplog.text
    assert "low on space: 5.0% free" in caplog.text


def test_prune_does_not_warn_below_the_thresholds(
    store: SnapshotStore,
    history: dict[str, Snapshot],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        shutil, "disk_usage", lambda path: SimpleNamespace(total=1000, used=100, free=900)
    )

    with caplog.at_level(logging.WARNING):
        store.prune()

    assert caplog.records == []


# Recover


def test_recover_with_nothing_to_do(store: SnapshotStore, fake: FakeBtrfs) -> None:
    take(store, "v1")
    fake.log.clear()

    assert store.recover() == []
    assert ("sync",) not in fake.log


def test_recover_finishes_an_interrupted_delete(store: SnapshotStore, fake: FakeBtrfs) -> None:
    fake.add_subvolume(store.snapshots_dir / f".trash-{OLD.id}", readonly=True)

    assert store.recover() == []

    assert ("delete_subvolume", f"snapshots/.trash-{OLD.id}", False) in fake.log
    assert os.listdir(store.snapshots_dir) == []
    assert fake.log[-1] == ("sync",)


def test_recover_lists_again_a_trashed_snapshot_it_cannot_delete(
    store: SnapshotStore, fake: FakeBtrfs, caplog: pytest.LogCaptureFixture
) -> None:
    fake.add_subvolume(store.snapshots_dir / f".trash-{OLD.id}", readonly=True)
    fake.fail("delete_subvolume", SnapshotError(NESTED))

    with caplog.at_level(logging.ERROR), pytest.raises(SnapshotError, match="nested subvolume"):
        store.recover()

    assert store.snapshots() == [OLD]
    assert "recovery could not handle" in caplog.text


def test_recover_lists_a_writable_tombstone_it_cannot_delete_only_read_only(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    """A crash inside btrfs.delete_subvolume, after it cleared ro and before the delete, leaves a
    writable tombstone. R1 must not bring it back to the listing writable."""
    fake.add_subvolume(store.snapshots_dir / f".trash-{OLD.id}", readonly=False)
    fake.fail("delete_subvolume", SnapshotError(NESTED))

    with pytest.raises(SnapshotError, match="nested subvolume"):
        store.recover()

    assert store.snapshots() == [OLD]
    assert store.snapshots_dir / OLD.id in fake.readonly
    seal = ("set_readonly", f"snapshots/.trash-{OLD.id}", True)
    rename = ("renameat2", f"snapshots/.trash-{OLD.id}", f"snapshots/{OLD.id}", "NOREPLACE")
    assert fake.log.index(seal) < fake.log.index(rename)  # sealed before it is listed


def test_recover_still_lists_a_tombstone_it_cannot_seal_and_says_so(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    fake.add_subvolume(store.snapshots_dir / f".trash-{OLD.id}", readonly=False)
    fake.fail("delete_subvolume", SnapshotError(NESTED))
    fake.fail("set_readonly", SnapshotError("property set failed"))

    with pytest.raises(SnapshotError, match="nested subvolume") as excinfo:
        store.recover()

    assert store.snapshots() == [OLD]  # listed, so a human sees it; restore() refuses it
    assert store.snapshots_dir / OLD.id not in fake.readonly
    assert any("read-only again also failed" in note for note in excinfo.value.__notes__)


def test_recover_publishes_an_interrupted_publish(store: SnapshotStore, fake: FakeBtrfs) -> None:
    undo = Snapshot(OLD.taken_at, Reason.PRE_RESTORE)
    fake.add_subvolume(store.snapshots_dir / f".incoming-{undo.id}", marker="old")

    assert store.recover() == [undo]

    assert store.snapshots() == [undo]
    assert store.snapshots_dir / undo.id in fake.readonly
    assert marker(store.snapshots_dir / undo.id) == "old"


def test_recover_leaves_both_when_the_published_name_exists(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    incoming = fake.add_subvolume(store.snapshots_dir / f".incoming-{OLD.id}", marker="a")
    fake.add_subvolume(store.snapshots_dir / OLD.id, readonly=True, marker="b")

    with pytest.raises(SnapshotError, match="leaving both"):
        store.recover()

    assert marker(incoming) == "a" and incoming not in fake.readonly
    assert marker(store.snapshots_dir / OLD.id) == "b"


def test_recover_publishes_the_staging_leftover_as_recovered(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    fake.add_subvolume(store.root / "workspace.restore", readonly=True, marker="staged")

    recovered = store.recover()

    assert [snap.reason for snap in recovered] == [Reason.RECOVERED]
    path = store.snapshots_dir / recovered[0].id
    assert marker(path) == "staged" and path in fake.readonly
    assert not os.path.lexists(store.root / "workspace.restore")


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_recover_refuses_a_staging_leftover_that_is_not_a_subvolume(
    store: SnapshotStore, fake: FakeBtrfs, kind: str
) -> None:
    staging = store.root / "workspace.restore"
    if kind == "directory":
        staging.mkdir()
    elif kind == "file":
        staging.write_text("x")
    else:
        staging.symlink_to(store.workspace)
    fake.log.clear()

    with pytest.raises(SnapshotError, match="tampering"):
        store.recover()

    assert os.path.lexists(staging)
    assert fake.calls("renameat2") == [] and fake.calls("set_readonly") == []


def test_recover_leaves_unknown_entries_alone(
    store: SnapshotStore, fake: FakeBtrfs, caplog: pytest.LogCaptureFixture
) -> None:
    (store.snapshots_dir / "junk").mkdir()
    (store.snapshots_dir / "file").write_text("x")
    (store.snapshots_dir / "link").symlink_to(store.workspace)
    (store.snapshots_dir / OLD.id).mkdir()  # valid name, not a subvolume
    (store.snapshots_dir / f".trash-{OLD.id}x").mkdir()
    fake.add_subvolume(store.snapshots_dir / ".trash-junk")
    before = sorted(os.listdir(store.snapshots_dir))

    with caplog.at_level(logging.WARNING):
        assert store.recover() == []

    assert sorted(os.listdir(store.snapshots_dir)) == before
    assert caplog.text.count("leaving it untouched") == len(before)
    assert fake.calls("renameat2") == [] and fake.calls("delete_subvolume") == []


def test_recover_attempts_every_leftover_before_raising(
    store: SnapshotStore, fake: FakeBtrfs
) -> None:
    fake.add_subvolume(store.snapshots_dir / f".incoming-{OLD.id}")
    fake.add_subvolume(store.snapshots_dir / OLD.id, readonly=True)  # makes R2 fail
    fake.add_subvolume(store.root / "workspace.restore", marker="staged")

    with pytest.raises(SnapshotError, match="1 leftover") as excinfo:
        store.recover()

    assert fake.log[-1] == ("sync",)
    assert any("published first" in note for note in excinfo.value.__notes__)
    assert [snap.reason for snap in store.snapshots()] == [Reason.PERIODIC, Reason.RECOVERED]


def test_recover_out_of_space_says_what_to_do(store: SnapshotStore, fake: FakeBtrfs) -> None:
    fake.add_subvolume(store.root / "workspace.restore", marker="staged")
    fake.fail("renameat2", SnapshotNoSpace("renameat2 failed", errno=errno.ENOSPC))

    with pytest.raises(SnapshotNoSpace, match=NO_SPACE):
        store.recover()

    assert marker(store.root / "workspace.restore") == "staged"


# workspace_id


def test_workspace_id_changes_exactly_when_a_restore_swaps(store: SnapshotStore) -> None:
    first = store.workspace_id()
    target = store.take(Reason.PERIODIC)
    assert store.workspace_id() == first

    store.restore(target.id, quiesce=contextlib.nullcontext)

    assert store.workspace_id() != first
