"""SnapshotStore on a real btrfs: take, rewind, undo, crash leftovers, prune and a full disk.

Everything runs as the unprivileged Lima user on the loop btrfs of conftest.py, through the
public SnapshotStore API (docs/10, "Tests" and "Rebobinar"). T04's quiesce (stop the agent,
then start it again) is played by ``contextlib.nullcontext`` or by the recording ``Quiesce``
below. Every store reads the auto-ticking FakeClock, so two operations never share an id.

The "done" criterion of T01b is test_create_modify_restore (plus undo and crash recovery).
"""

import errno
import logging
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import pytest

import vigia.snapshots.store as store_module
from vigia.snapshots import (
    Reason,
    RestoreIncomplete,
    RestoreResult,
    Snapshot,
    SnapshotBusy,
    SnapshotError,
    SnapshotNoSpace,
    btrfs,
)
from vigia.snapshots.store import SnapshotStore

pytestmark = pytest.mark.integration

LOGGER = "vigia.snapshots"
STAGING = "workspace.restore"
CLEAN_ROOT = [".lock", "snapshots", "workspace"]  # sorted: nothing in progress, nothing stray
NESTED_STUB_INO = 2  # the empty directory a nested subvolume leaves inside a snapshot
MIB = 1024**2
SMALL_FILE = b"x" * 2000  # under max_inline (2048): stored in the metadata tree
# Well-formed ids that name nothing on disk, dated before the fake clock starts.
UNKNOWN = Snapshot(datetime(2026, 1, 1, tzinfo=UTC), Reason.PERIODIC)
LEFTOVER = Snapshot(datetime(2026, 10, 5, 7, 0, tzinfo=UTC), Reason.PRE_RESTORE)


class Clock(Protocol):
    """The FakeClock of tests/conftest.py, as far as these tests use it."""

    def __call__(self) -> datetime: ...

    def advance(self, delta: timedelta) -> None: ...


@dataclass
class Quiesce:
    """Stands in for T04's quiesce: records when the agent would be stopped and started.

    ``probe`` is called right after each event, while restore() still holds the lock."""

    error: Exception | None = None
    probe: Callable[[str], None] | None = None
    events: list[str] = field(default_factory=list)

    @contextmanager
    def __call__(self) -> Iterator[None]:
        self._record("stop")
        if self.error is not None:
            raise self.error
        try:
            yield
        finally:
            self._record("start")

    def _record(self, event: str) -> None:
        self.events.append(event)
        if self.probe is not None:
            self.probe(event)


class AgentDidNotStop(Exception):  # noqa: N818 - named after what T04 would report
    """What T04's quiesce might raise when docker stop fails."""


@pytest.fixture
def root(btrfs_volume: Path) -> Path:
    """An empty 0700 directory on the shared btrfs, for tests that call init() themselves."""
    path = btrfs_volume / uuid4().hex
    path.mkdir(mode=0o700)
    return path


# init


def test_init_creates_the_layout_and_is_idempotent(root: Path, clock: Clock) -> None:
    store = SnapshotStore(root, clock=clock)

    store.init()

    assert sorted(os.listdir(root)) == CLEAN_ROOT
    workspace = root / "workspace"
    assert btrfs.is_subvolume(workspace)
    assert not btrfs.is_readonly(workspace)
    snapshots = os.lstat(root / "snapshots")
    assert stat.S_ISDIR(snapshots.st_mode)
    assert stat.S_IMODE(snapshots.st_mode) == 0o700
    lock = os.lstat(root / ".lock")
    assert stat.S_ISREG(lock.st_mode)
    assert stat.S_IMODE(lock.st_mode) == 0o600
    assert store.snapshots() == []

    (workspace / "a.txt").write_text("kept")
    workspace_id = store.workspace_id()
    store.init()

    assert sorted(os.listdir(root)) == CLEAN_ROOT
    assert (workspace / "a.txt").read_text() == "kept"
    assert store.workspace_id() == workspace_id


def test_init_refuses_a_root_open_to_others(root: Path, clock: Clock) -> None:
    root.chmod(0o755)

    with pytest.raises(SnapshotError):
        SnapshotStore(root, clock=clock).init()

    assert stat.S_IMODE(os.lstat(root).st_mode) == 0o755  # reported, never fixed
    assert not os.path.lexists(root / "workspace")


def test_init_refuses_a_snapshots_directory_open_to_others(root: Path, clock: Clock) -> None:
    snapshots = root / "snapshots"
    snapshots.mkdir()
    snapshots.chmod(0o755)

    with pytest.raises(SnapshotError):
        SnapshotStore(root, clock=clock).init()

    assert stat.S_IMODE(os.lstat(snapshots).st_mode) == 0o755


def test_init_refuses_a_snapshots_directory_that_is_a_symlink(root: Path, clock: Clock) -> None:
    elsewhere = root / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (root / "snapshots").symlink_to("elsewhere")

    with pytest.raises(SnapshotError):
        SnapshotStore(root, clock=clock).init()

    assert os.readlink(root / "snapshots") == "elsewhere"
    assert os.listdir(elsewhere) == []


def test_init_refuses_a_workspace_that_is_a_plain_directory(root: Path, clock: Clock) -> None:
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / "a.txt").write_text("agent data")

    with pytest.raises(SnapshotError):
        SnapshotStore(root, clock=clock).init()

    assert not btrfs.is_subvolume(workspace)
    assert (workspace / "a.txt").read_text() == "agent data"


def test_init_refuses_a_root_that_is_not_on_btrfs(tmp_path: Path, clock: Clock) -> None:
    root = tmp_path / "volume"
    root.mkdir(mode=0o700)
    assert filesystem_type(root) != "btrfs"

    with pytest.raises(SnapshotError):
        SnapshotStore(root, clock=clock).init()


def test_init_only_warns_about_a_read_only_workspace(
    store: SnapshotStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The agent can flip its own workspace; refusing would let it stop the guardian starting."""
    workspace = workspace_of(store)
    (workspace / "a.txt").write_text("v1")
    btrfs.set_readonly(workspace, True)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        store.init()

    assert warnings_logged(caplog)
    assert btrfs.is_readonly(workspace)  # reported, never fixed
    snap = store.take(Reason.PERIODIC)
    assert (snapshot_path(store, snap) / "a.txt").read_text() == "v1"


# take


def test_take_makes_a_read_only_copy_of_the_workspace(store: SnapshotStore) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    expected = tree(workspace)
    workspace_id = store.workspace_id()

    snap = store.take(Reason.MANUAL)
    (workspace / "a.txt").write_text("v2")  # later changes never reach the snapshot

    assert snap.reason == "manual"
    assert store.snapshots() == [snap]
    path = snapshot_path(store, snap)
    assert_read_only_snapshot(path)
    assert tree(path) == expected
    assert store.workspace_id() == workspace_id
    assert not btrfs.is_readonly(workspace)
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT


def test_two_takes_get_distinct_ids_in_time_order(store: SnapshotStore) -> None:
    first = store.take(Reason.PERIODIC)
    second = store.take(Reason.PERIODIC)

    assert first.id < second.id
    assert first.taken_at < second.taken_at
    assert store.snapshots() == [first, second]


# The DONE criterion: create, modify, restore. Then undo.


def test_create_modify_restore(store: SnapshotStore) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    v1 = tree(workspace)
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace)
    v2 = tree(workspace)
    before = os.lstat(workspace)
    workspace_id = store.workspace_id()

    result = store.restore(s1.id, quiesce=nullcontext)

    assert tree(workspace) == v1
    assert (workspace / "a.txt").read_text() == "v1"
    assert (workspace / "sub" / "b.txt").read_text() == "b"
    assert not os.path.lexists(workspace / "c.txt")
    after = os.lstat(workspace)
    assert btrfs.is_subvolume(workspace)
    assert not btrfs.is_readonly(workspace)
    assert (after.st_uid, after.st_gid, after.st_mode) == (
        before.st_uid,
        before.st_gid,
        before.st_mode,
    )
    assert store.workspace_id() != workspace_id
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT

    assert result.target == s1
    assert result.recovered == ()
    undo = result.undo
    assert undo is not None
    assert undo.reason == "pre_restore"
    assert store.snapshots() == [s1, undo]
    assert sorted(os.listdir(snapshots_dir(store))) == [s1.id, undo.id]  # no .incoming-*
    assert_read_only_snapshot(snapshot_path(store, undo))
    assert tree(snapshot_path(store, undo)) == v2
    assert tree(snapshot_path(store, s1)) == v1


def test_undo_is_a_restore_of_the_undo_point(store: SnapshotStore) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    v1 = tree(workspace)
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace)
    v2 = tree(workspace)
    first = store.restore(s1.id, quiesce=nullcontext)
    assert first.undo is not None

    second = store.restore(first.undo.id, quiesce=nullcontext)

    assert tree(workspace) == v2
    assert second.target == first.undo
    assert second.undo is not None
    undo_points = [s for s in store.snapshots() if s.reason == Reason.PRE_RESTORE]
    assert undo_points == [first.undo, second.undo]
    assert tree(snapshot_path(store, second.undo)) == v1
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT


def test_restore_swaps_the_workspace_while_the_agent_is_stopped(
    store: SnapshotStore, clock: Clock
) -> None:
    """The copy is made before the agent stops; the swap and the undo point happen while it is
    stopped and while restore() holds the volume lock, so a periodic take has to wait."""
    workspace = workspace_of(store)
    write_v1(workspace)
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace)
    other = SnapshotStore(store.root, clock=clock, lock_timeout=0.1)
    seen: dict[str, tuple[str, bool, bool]] = {}

    def probe(event: str) -> None:
        seen[event] = (
            (workspace / "a.txt").read_text(),
            os.path.lexists(store.root / STAGING),
            raises_busy(lambda: other.take(Reason.PERIODIC)),
        )

    quiesce = Quiesce(probe=probe)
    result = store.restore(s1.id, quiesce=quiesce)

    assert quiesce.events == ["stop", "start"]
    assert seen["stop"] == ("v2", True, True)  # staging ready, old workspace, lock held
    assert seen["start"] == ("v1", False, True)  # swapped and published, lock still held
    assert store.snapshots() == [s1, result.undo]  # the waiting takes created nothing


# No side effects when a restore is refused or fails before the swap


@pytest.mark.parametrize(
    "snapshot_id",
    [
        "nope",
        "../workspace",
        "workspace",
        STAGING,
        f".trash-{UNKNOWN.id}",
        f"{UNKNOWN.id}/../../workspace",
        UNKNOWN.id,  # well-formed, but there is no such snapshot
    ],
)
def test_restore_of_an_invalid_or_unknown_id_changes_nothing(
    store: SnapshotStore, snapshot_id: str
) -> None:
    write_v1(workspace_of(store))
    store.take(Reason.PERIODIC)
    write_v2(workspace_of(store))
    before = state(store)
    quiesce = Quiesce()

    with pytest.raises(SnapshotError):
        store.restore(snapshot_id, quiesce=quiesce)

    assert state(store) == before
    assert quiesce.events == []  # the agent is never stopped for a refused restore


def test_restore_refuses_a_snapshot_made_writable_by_hand(store: SnapshotStore) -> None:
    """A listed snapshot is read-only, so a writable one means tampering (or an in-place
    delete that died while the volume was full, docs/10 "Borrar"): restore() refuses it."""
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace_of(store))
    btrfs.set_readonly(snapshot_path(store, s1), False)
    before = state(store)

    with pytest.raises(SnapshotError):
        store.restore(s1.id, quiesce=nullcontext)

    assert state(store) == before


def test_restore_changes_nothing_when_stopping_the_agent_fails(store: SnapshotStore) -> None:
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace_of(store))
    before = state(store)
    error = AgentDidNotStop("docker stop timed out")
    quiesce = Quiesce(error=error)

    with pytest.raises(AgentDidNotStop) as excinfo:
        store.restore(s1.id, quiesce=quiesce)

    assert excinfo.value is error  # the caller's own exception, unchanged
    assert quiesce.events == ["stop"]
    assert state(store) == before  # no staging copy left, no undo point


# What the agent can do to its own workspace


def test_restore_works_when_the_agent_made_its_workspace_read_only(store: SnapshotStore) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace)
    v2 = tree(workspace)
    btrfs.set_readonly(workspace, True)

    result = store.restore(s1.id, quiesce=nullcontext)

    assert (workspace / "a.txt").read_text() == "v1"
    assert not btrfs.is_readonly(workspace)
    assert result.undo is not None
    assert result.undo in store.snapshots()
    assert_read_only_snapshot(snapshot_path(store, result.undo))
    assert tree(snapshot_path(store, result.undo)) == v2
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT


def test_nested_subvolume_escapes_snapshots_but_restore_works_and_keeps_the_evidence(
    store: SnapshotStore,
) -> None:
    """Seed of the T05 scenario. A nested subvolume is not part of any snapshot (the escape,
    documented here and closed in T03 with seccomp). Rewinding still works, and the undo point
    keeps the planted subvolume as evidence, which only root can delete."""
    workspace = workspace_of(store)
    (workspace / "a.txt").write_text("v1")
    btrfs.create_subvolume(workspace / "nested")
    (workspace / "nested" / "loot.txt").write_text("planted")

    s1 = store.take(Reason.PERIODIC)

    stub = snapshot_path(store, s1) / "nested"
    assert os.lstat(stub).st_ino == NESTED_STUB_INO
    assert os.listdir(stub) == []  # the escape: the nested data is not in the snapshot

    (workspace / "a.txt").write_text("v2")
    result = store.restore(s1.id, quiesce=nullcontext)

    assert (workspace / "a.txt").read_text() == "v1"
    assert not btrfs.is_subvolume(workspace / "nested")
    assert os.listdir(workspace / "nested") == []
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT
    assert result.undo is not None
    undo_path = snapshot_path(store, result.undo)
    assert_read_only_snapshot(undo_path)
    assert btrfs.is_subvolume(undo_path / "nested")
    assert (undo_path / "nested" / "loot.txt").read_text() == "planted"

    with pytest.raises(SnapshotError) as excinfo:
        store.delete(result.undo.id)

    text = error_text(excinfo.value)
    assert re.search(r"nested subvolume", text, re.IGNORECASE), text
    assert "delete -R" in text, text
    assert store.snapshots() == [s1, result.undo]
    assert sorted(os.listdir(snapshots_dir(store))) == [s1.id, result.undo.id]  # no .trash-*
    assert btrfs.is_readonly(undo_path)
    assert (undo_path / "nested" / "loot.txt").read_text() == "planted"


def test_a_missing_workspace_is_recreated_by_restore(store: SnapshotStore) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    v1 = tree(workspace)
    s1 = store.take(Reason.PERIODIC)
    s2 = store.take(Reason.MANUAL)
    btrfs.delete_subvolume(workspace)

    with pytest.raises(SnapshotError) as excinfo:
        store.init()  # never an empty workspace while snapshots exist
    text = error_text(excinfo.value)
    assert "restore" in text, text
    assert s2.id in text, text  # names the newest snapshot
    assert not os.path.lexists(workspace)
    with pytest.raises(SnapshotError):
        store.take(Reason.PERIODIC)

    result = store.restore(s1.id, quiesce=nullcontext)

    assert result.target == s1
    assert result.undo is None
    assert tree(workspace) == v1
    assert btrfs.is_subvolume(workspace)
    assert not btrfs.is_readonly(workspace)
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT
    s3 = store.take(Reason.PERIODIC)
    assert store.snapshots() == [s1, s2, s3]
    assert tree(snapshot_path(store, s3)) == v1


# Crash leftovers, built by hand


def leave_staging(store: SnapshotStore, s1: Snapshot) -> Path:
    """A restore that died after making its staging copy (or right after the swap)."""
    staging = store.root / STAGING
    btrfs.snapshot(snapshot_path(store, s1), staging, readonly=False)
    (staging / "marker").write_text("crash leftover")
    return staging


def leave_incoming(store: SnapshotStore, s1: Snapshot) -> Path:
    """A restore that died while publishing its undo point, before sealing it."""
    incoming = snapshots_dir(store) / f".incoming-{LEFTOVER.id}"
    btrfs.snapshot(workspace_of(store), incoming, readonly=False)
    return incoming


def leave_trash(store: SnapshotStore, s1: Snapshot) -> Path:
    """A delete that died after its tombstone rename."""
    trash = snapshots_dir(store) / f".trash-{s1.id}"
    os.rename(snapshot_path(store, s1), trash)  # read-only, but in the same directory
    return trash


LEFTOVERS = [leave_staging, leave_incoming, leave_trash]
LEFTOVER_IDS = ["staging", "incoming", "trash"]


def test_restore_first_publishes_a_staging_leftover_as_recovered(store: SnapshotStore) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace)
    v2 = tree(workspace)
    s2 = store.take(Reason.PERIODIC)
    leftover = tree(leave_staging(store, s1))

    result = store.restore(s2.id, quiesce=nullcontext)

    assert tree(workspace) == v2
    assert len(result.recovered) == 1
    recovered = result.recovered[0]
    assert recovered.reason == "recovered"
    assert recovered in store.snapshots()
    assert_read_only_snapshot(snapshot_path(store, recovered))
    assert tree(snapshot_path(store, recovered)) == leftover
    assert (snapshot_path(store, recovered) / "marker").read_text() == "crash leftover"
    assert result.undo is not None
    assert store.snapshots() == [s1, s2, recovered, result.undo]  # recovered before the swap
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT


def test_recover_publishes_a_staging_leftover_as_recovered(store: SnapshotStore) -> None:
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace_of(store))
    v2 = tree(workspace_of(store))
    workspace_id = store.workspace_id()
    leftover = tree(leave_staging(store, s1))

    recovered = store.recover()

    assert [s.reason for s in recovered] == ["recovered"]
    assert store.snapshots() == [s1, recovered[0]]
    assert_read_only_snapshot(snapshot_path(store, recovered[0]))
    assert tree(snapshot_path(store, recovered[0])) == leftover
    assert tree(workspace_of(store)) == v2
    assert store.workspace_id() == workspace_id
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT


@pytest.mark.parametrize("sealed", [False, True], ids=["writable", "sealed"])
def test_recover_publishes_an_incoming_leftover(store: SnapshotStore, sealed: bool) -> None:
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    incoming = leave_incoming(store, s1)
    expected = tree(incoming)
    if sealed:  # died after sealing it, before the final rename
        btrfs.set_readonly(incoming, True)

    recovered = store.recover()

    assert recovered == [LEFTOVER]
    assert store.snapshots() == [LEFTOVER, s1]
    assert_read_only_snapshot(snapshot_path(store, LEFTOVER))
    assert tree(snapshot_path(store, LEFTOVER)) == expected
    assert sorted(os.listdir(snapshots_dir(store))) == sorted([LEFTOVER.id, s1.id])


def test_recover_finishes_an_interrupted_delete(store: SnapshotStore) -> None:
    s1 = store.take(Reason.PERIODIC)
    s2 = store.take(Reason.PERIODIC)
    leave_trash(store, s1)
    assert store.snapshots() == [s2]  # a tombstone is never listed

    assert store.recover() == []  # nothing published: a delete was finished

    assert store.snapshots() == [s2]
    assert os.listdir(snapshots_dir(store)) == [s2.id]


@pytest.mark.parametrize("readonly", [True, False], ids=["sealed", "ro cleared by a crash"])
def test_recover_lists_again_a_tombstone_it_cannot_delete(
    store: SnapshotStore, readonly: bool
) -> None:
    """R1: a tombstone holding a nested subvolume cannot be deleted without root, so it gets
    its name back (listed and read-only again) and recover() reports the error. A crash inside
    btrfs.delete_subvolume, after it cleared ro, leaves the tombstone writable: it must still
    come back read-only."""
    trash = snapshots_dir(store) / f".trash-{LEFTOVER.id}"
    btrfs.create_subvolume(trash)
    btrfs.create_subvolume(trash / "nested")
    (trash / "nested" / "loot.txt").write_text("planted")
    btrfs.set_readonly(trash, readonly)

    with pytest.raises(SnapshotError):
        store.recover()

    assert store.snapshots() == [LEFTOVER]
    assert os.listdir(snapshots_dir(store)) == [LEFTOVER.id]
    assert btrfs.is_readonly(snapshot_path(store, LEFTOVER))
    assert (snapshot_path(store, LEFTOVER) / "nested" / "loot.txt").read_text() == "planted"


def test_recover_leaves_an_incoming_leftover_whose_id_is_taken_for_a_human(
    store: SnapshotStore,
) -> None:
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    incoming = snapshots_dir(store) / f".incoming-{s1.id}"
    btrfs.snapshot(workspace_of(store), incoming, readonly=False)

    with pytest.raises(SnapshotError):
        store.recover()

    assert store.snapshots() == [s1]
    assert btrfs.is_subvolume(incoming)
    assert sorted(os.listdir(snapshots_dir(store))) == sorted([s1.id, incoming.name])
    assert tree(snapshot_path(store, s1)) == tree(incoming)


def test_recover_with_nothing_to_do_changes_nothing(store: SnapshotStore) -> None:
    write_v1(workspace_of(store))
    store.take(Reason.PERIODIC)
    before = state(store)

    assert store.recover() == []

    assert state(store) == before


@pytest.mark.parametrize("leave", LEFTOVERS, ids=LEFTOVER_IDS)
def test_take_works_with_a_leftover_present_and_leaves_it_alone(
    store: SnapshotStore, leave: Callable[[SnapshotStore, Snapshot], Path]
) -> None:
    """take() never runs recovery: it is the last safety net and must work regardless."""
    workspace = workspace_of(store)
    write_v1(workspace)
    s1 = store.take(Reason.PERIODIC)
    leftover = leave(store, s1)
    write_v2(workspace)
    v2 = tree(workspace)
    leftover_before = (btrfs.is_readonly(leftover), tree(leftover))

    taken = store.take(Reason.PERIODIC)

    assert taken in store.snapshots()
    assert tree(snapshot_path(store, taken)) == v2
    assert btrfs.is_subvolume(leftover)
    assert (btrfs.is_readonly(leftover), tree(leftover)) == leftover_before


def plant_directory(path: Path) -> None:
    path.mkdir()
    (path / "a.txt").write_text("planted")


def plant_file(path: Path) -> None:
    path.write_text("planted")


def plant_symlink_to_workspace(path: Path) -> None:
    path.symlink_to("workspace")


@pytest.mark.parametrize(
    "plant",
    [plant_directory, plant_file, plant_symlink_to_workspace],
    ids=["directory", "file", "symlink-to-workspace"],
)
def test_a_staging_entry_that_is_not_a_subvolume_is_refused_and_left_alone(
    store: SnapshotStore, plant: Callable[[Path], None]
) -> None:
    """R3: anything but a subvolume at workspace.restore is tampering. A human decides."""
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace_of(store))
    staging = store.root / STAGING
    plant(staging)
    before = (state(store), describe(staging))

    with pytest.raises(SnapshotError):
        store.recover()
    with pytest.raises(SnapshotError):
        store.restore(s1.id, quiesce=nullcontext)  # recovery runs first, so nothing swaps

    assert (state(store), describe(staging)) == before


# Deleting


def test_deleting_the_snapshot_a_workspace_came_from_leaves_the_workspace_intact(
    store: SnapshotStore,
) -> None:
    """btrfs reference-counts extents: the restored workspace does not depend on its source."""
    workspace = workspace_of(store)
    write_v1(workspace)
    s1 = store.take(Reason.PERIODIC)
    write_v2(workspace)
    store.restore(s1.id, quiesce=nullcontext)
    restored = tree(workspace)

    store.delete(s1.id)

    assert s1 not in store.snapshots()
    assert not os.path.lexists(snapshot_path(store, s1))
    assert tree(workspace) == restored
    (workspace / "a.txt").write_text("still writable")


def test_delete_removes_any_snapshot_when_asked_explicitly(store: SnapshotStore) -> None:
    periodic = store.take(Reason.PERIODIC)
    manual = store.take(Reason.MANUAL)  # protected from prune, not from an explicit delete

    store.delete(periodic.id)
    store.delete(manual.id)

    assert store.snapshots() == []
    assert os.listdir(snapshots_dir(store)) == []  # no tombstones left


@pytest.mark.parametrize(
    "snapshot_id",
    [
        "nope",
        "../workspace",
        "workspace",
        f".trash-{UNKNOWN.id}",
        f"{UNKNOWN.id}/../../workspace",
        UNKNOWN.id,
    ],
)
def test_delete_of_an_invalid_or_unknown_id_changes_nothing(
    store: SnapshotStore, snapshot_id: str
) -> None:
    write_v1(workspace_of(store))
    store.take(Reason.PERIODIC)
    before = state(store)

    with pytest.raises(SnapshotError):
        store.delete(snapshot_id)

    assert state(store) == before


# prune

D5, D6, D7, D8 = 5, 6, 7, 8  # October 2026; the 5th is a Monday, all four share ISO week 41


def at(day: int, hour: int, minute: int) -> datetime:
    return datetime(2026, 10, day, hour, minute, tzinfo=UTC)


# Three days and four hours of history. "r" is a real restore, which publishes a pre_restore.
PRUNE_HISTORY = [
    ("p1", at(D5, 8, 5), Reason.PERIODIC),
    ("p2", at(D5, 8, 30), Reason.PERIODIC),
    ("p3", at(D5, 9, 10), Reason.PERIODIC),
    ("m", at(D5, 9, 20), Reason.MANUAL),
    ("p4", at(D5, 10, 40), Reason.PERIODIC),
    ("p5", at(D5, 23, 50), Reason.PERIODIC),
    ("p6", at(D6, 6, 0), Reason.PERIODIC),
    ("p7", at(D6, 14, 0), Reason.PERIODIC),
    ("r", at(D6, 14, 30), Reason.PRE_RESTORE),
    ("p8", at(D6, 20, 0), Reason.PERIODIC),
    ("p9", at(D7, 9, 0), Reason.PERIODIC),
    ("p10", at(D7, 11, 0), Reason.PERIODIC),
    ("p11", at(D7, 15, 10), Reason.PERIODIC),
    ("p12", at(D7, 15, 40), Reason.PERIODIC),
    ("p13", at(D7, 22, 0), Reason.PERIODIC),
    ("p14", at(D8, 9, 30), Reason.PERIODIC),
    ("p15", at(D8, 9, 55), Reason.PERIODIC),
    ("p16", at(D8, 10, 30), Reason.PERIODIC),
    ("p17", at(D8, 11, 0), Reason.PERIODIC),
]
PRUNE_AT = at(D8, 12, 0)
# Worked out by hand from the policy in docs/10, never recomputed with select_expired:
# - before 7 Oct 12:00 (24 h or older): the newest of each UTC day stays, p5, p8 and p13;
#   p3 stays as the anchor of m, and p7 as the anchor of r;
# - 7 Oct 12:00 to 8 Oct 10:00 (2 to 24 h): the newest of each UTC hour, p12, p13 and p15;
# - after 8 Oct 10:00 (under 2 h): everything, p16 and p17.
PRUNE_EXPIRED = ["p1", "p2", "p4", "p6", "p9", "p10", "p11", "p14"]
PRUNE_SURVIVORS = ["p3", "m", "p5", "p7", "r", "p8", "p12", "p13", "p15", "p16", "p17"]


def test_prune_deletes_exactly_what_the_policy_expires(store: SnapshotStore, clock: Clock) -> None:
    taken: dict[str, Snapshot] = {}
    for label, when, reason in PRUNE_HISTORY:
        move_clock_to(clock, when)
        if reason == Reason.PRE_RESTORE:
            undo = store.restore(taken["p7"].id, quiesce=nullcontext).undo
            assert undo is not None
            taken[label] = undo
        else:
            taken[label] = store.take(reason)
    move_clock_to(clock, PRUNE_AT)

    deleted = store.prune()

    assert sorted(s.id for s in deleted) == [taken[label].id for label in PRUNE_EXPIRED]
    assert store.snapshots() == [taken[label] for label in PRUNE_SURVIVORS]
    assert sorted(os.listdir(snapshots_dir(store))) == [
        taken[label].id for label in PRUNE_SURVIVORS
    ]
    assert store.prune() == []  # stable: a second prune finds nothing more


def test_prune_warns_about_too_many_snapshots_and_low_free_space(
    store: SnapshotStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.take(Reason.PERIODIC)
    store.take(Reason.PERIODIC)
    store.take(Reason.MANUAL)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert store.prune() == []
    assert warnings_logged(caplog) == []
    caplog.clear()

    monkeypatch.setattr(store_module, "WARN_SNAPSHOT_COUNT", 1)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert store.prune() == []
    [count_warning] = warnings_logged(caplog)
    assert "periodic" in count_warning, count_warning  # counts per reason
    assert "manual" in count_warning, count_warning
    caplog.clear()

    monkeypatch.undo()
    monkeypatch.setattr(store_module, "WARN_FREE_FRACTION", 1.0)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert store.prune() == []
    [space_warning] = warnings_logged(caplog)
    assert re.search(r"free|space", space_warning, re.IGNORECASE), space_warning
    assert len(store.snapshots()) == 3


# Strays and symlinks


def test_strays_in_the_snapshots_directory_are_ignored_and_never_touched(
    store: SnapshotStore, clock: Clock
) -> None:
    write_v1(workspace_of(store))
    s1 = store.take(Reason.PERIODIC)
    snapshots = snapshots_dir(store)
    symlinked = Snapshot(datetime(2026, 1, 5, 12, 0, tzinfo=UTC), Reason.PERIODIC)
    plain = Snapshot(datetime(2026, 1, 4, 12, 0, tzinfo=UTC), Reason.PERIODIC)
    plant_directory(snapshots / "junk")
    plant_file(snapshots / "notes.txt")
    (snapshots / "link").symlink_to("../workspace")
    (snapshots / symlinked.id).symlink_to("../workspace")  # parses as an id, is a symlink
    plant_directory(snapshots / plain.id)  # parses as an id, is not a subvolume
    before = (state(store), tree(snapshots))

    assert store.snapshots() == [s1]
    assert store.recover() == []
    clock.advance(timedelta(days=60))  # old enough to prune, if they were ever considered
    assert store.prune() == []
    for stray in (symlinked, plain):
        with pytest.raises(SnapshotError):
            store.restore(stray.id, quiesce=nullcontext)
        with pytest.raises(SnapshotError):
            store.delete(stray.id)

    assert (state(store), tree(snapshots)) == before


@pytest.mark.parametrize("prefix", [".trash-", ".incoming-"])
def test_an_in_progress_name_that_is_a_symlink_never_reaches_the_workspace(
    store: SnapshotStore, prefix: str
) -> None:
    workspace = workspace_of(store)
    write_v1(workspace)
    s1 = store.take(Reason.PERIODIC)
    link = snapshots_dir(store) / f"{prefix}{LEFTOVER.id}"
    link.symlink_to("../workspace")
    before = state(store)

    # Ignoring it as a stray or refusing it as tampering are both fine; following it is not.
    with suppress(SnapshotError):
        store.recover()

    assert state(store) == before
    assert os.readlink(link) == "../workspace"
    assert btrfs.is_subvolume(workspace)
    assert not btrfs.is_readonly(workspace)
    assert store.snapshots() == [s1]


def test_symlinks_in_the_workspace_survive_take_and_restore_as_symlinks(
    store: SnapshotStore, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside the volume")
    links = {
        "to-snapshots": "../snapshots",
        "to-etc": "/etc/passwd",
        "to-outside": str(outside),
        "dangling": "no-such-file",
    }
    workspace = workspace_of(store)
    for name, target in links.items():
        (workspace / name).symlink_to(target)
    watched = [Path("/etc/passwd"), outside]
    fingerprints = {path: fingerprint(path) for path in watched}

    s1 = store.take(Reason.PERIODIC)
    for name in links:
        (workspace / name).unlink()
    result = store.restore(s1.id, quiesce=nullcontext)

    assert result.undo is not None
    for name, target in links.items():
        for directory in (workspace, snapshot_path(store, s1)):
            assert (directory / name).is_symlink()
            assert os.readlink(directory / name) == target
    assert {path: fingerprint(path) for path in watched} == fingerprints
    assert outside.read_text() == "outside the volume"
    assert sorted(os.listdir(snapshots_dir(store))) == sorted([s1.id, result.undo.id])


# A full disk (tiny_btrfs_volume). Both fills keep the tmpfs-backed image sparse: fallocate
# never writes the data, and small files live inline in the metadata tree.


def test_data_full_disk_take_and_restore_succeed_or_report_no_space(
    tiny_btrfs_volume: Path,
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
    record_property: Callable[[str, object], None],
) -> None:
    """Never a generic error. The outcome goes in the devlog (pytest -rP)."""
    store = new_store(tiny_btrfs_volume, clock)
    workspace = workspace_of(store)
    (workspace / "a.txt").write_text("v1")
    s1 = store.take(Reason.PERIODIC)
    (workspace / "a.txt").write_text("v2")
    preallocated = fill_data(workspace)
    workspace_id = store.workspace_id()

    taken = no_space_or(lambda: store.take(Reason.PERIODIC))
    quiesce = Quiesce()
    restored = no_space_or(lambda: store.restore(s1.id, quiesce=quiesce))
    report(
        record_property,
        "store_data_full",
        f"{preallocated // MIB} MiB preallocated; take: {summarize(taken)}; "
        f"restore: {summarize(restored)}",
    )

    periodic = [s for s in store.snapshots() if s.reason == Reason.PERIODIC]
    assert periodic == ([s1] if isinstance(taken, SnapshotNoSpace) else [s1, taken])
    if isinstance(restored, SnapshotNoSpace):
        assert (workspace / "a.txt").read_text() == "v2"
        assert store.workspace_id() == workspace_id
    else:
        assert (workspace / "a.txt").read_text() == "v1"
        assert restored.undo in store.snapshots()
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT
    assert quiesce.events in ([], ["stop", "start"])  # the agent is never left stopped

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert store.prune() == []
    assert any(re.search(r"free|space", m, re.IGNORECASE) for m in warnings_logged(caplog))

    store.delete(s1.id)
    assert s1 not in store.snapshots()


def test_metadata_full_disk_restore_raises_no_space_and_changes_nothing(
    tiny_btrfs_volume: Path,
    clock: Clock,
    record_property: Callable[[str, object], None],
) -> None:
    """With metadata full every rename fails with ENOSPC, so the swap cannot happen."""
    store = new_store(tiny_btrfs_volume, clock)
    workspace = workspace_of(store)
    (workspace / "a.txt").write_text("v1")
    s1 = store.take(Reason.PERIODIC)
    (workspace / "a.txt").write_text("v2")
    fill_data(workspace)
    small_files = fill_metadata(workspace / "small")
    report(record_property, "store_metadata_full", f"{small_files} small files until ENOSPC")
    workspace_id = store.workspace_id()
    quiesce = Quiesce()

    with pytest.raises(SnapshotNoSpace) as excinfo:
        store.restore(s1.id, quiesce=quiesce)

    text = error_text(excinfo.value)
    assert re.search(r"delete", text, re.IGNORECASE), text  # tells the user what to do
    assert (workspace / "a.txt").read_text() == "v2"
    assert store.workspace_id() == workspace_id
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT  # the staging copy was removed
    assert store.snapshots() == [s1]
    assert os.listdir(snapshots_dir(store)) == [s1.id]
    assert quiesce.events in ([], ["stop", "start"])  # the agent is never left stopped


def test_metadata_full_disk_delete_still_works_so_the_hint_can_be_followed(
    tiny_btrfs_volume: Path,
    clock: Clock,
    record_property: Callable[[str, object], None],
) -> None:
    """The no-space error says to delete snapshots and retry (or grow the volume), so delete()
    must work even when every rename fails with ENOSPC, and must leave no tombstone behind.

    Whether the retried restore then works goes in the devlog (pytest -rP). In T01b it did not:
    s2 shares everything with the workspace, and the agent's own files fill the metadata, so
    deleting it frees almost nothing. That is why the hint also says to grow the volume."""
    store = new_store(tiny_btrfs_volume, clock)
    workspace = workspace_of(store)
    (workspace / "a.txt").write_text("v1")
    s1 = store.take(Reason.PERIODIC)
    s2 = store.take(Reason.MANUAL)
    (workspace / "a.txt").write_text("v2")
    fill_data(workspace)
    fill_metadata(workspace / "small")
    with pytest.raises(SnapshotNoSpace) as excinfo:
        store.restore(s1.id, quiesce=Quiesce())
    assert "grow the volume" in error_text(excinfo.value)

    store.delete(s2.id)

    assert store.snapshots() == [s1]
    assert os.listdir(snapshots_dir(store)) == [s1.id]  # no .trash- left for R1
    assert sorted(os.listdir(store.root)) == CLEAN_ROOT
    assert (workspace / "a.txt").read_text() == "v2"
    assert (snapshot_path(store, s1) / "a.txt").read_text() == "v1"

    try:
        retried: RestoreResult | SnapshotNoSpace | RestoreIncomplete = store.restore(
            s1.id, quiesce=Quiesce()
        )
    except (SnapshotNoSpace, RestoreIncomplete) as e:
        retried = e
    outcome = "ok" if isinstance(retried, RestoreResult) else f"{type(retried).__name__}"
    report(record_property, "store_metadata_full_retry", f"restore after delete(): {outcome}")
    rewound = not isinstance(retried, SnapshotNoSpace)
    assert (workspace / "a.txt").read_text() == ("v1" if rewound else "v2")


def test_metadata_full_disk_recover_raises_no_space_and_keeps_the_leftover(
    tiny_btrfs_volume: Path, clock: Clock
) -> None:
    store = new_store(tiny_btrfs_volume, clock)
    workspace = workspace_of(store)
    (workspace / "a.txt").write_text("v1")
    s1 = store.take(Reason.PERIODIC)
    (workspace / "a.txt").write_text("v2")
    staging = leave_staging(store, s1)  # made before the disk fills up
    fill_data(workspace)
    fill_metadata(workspace / "small")
    workspace_id = store.workspace_id()

    with pytest.raises(SnapshotNoSpace) as excinfo:
        store.recover()

    text = error_text(excinfo.value)
    assert re.search(r"delete", text, re.IGNORECASE), text
    assert btrfs.is_subvolume(staging)  # recovery only ever preserves data
    assert (staging / "marker").read_text() == "crash leftover"
    assert (staging / "a.txt").read_text() == "v1"
    assert (workspace / "a.txt").read_text() == "v2"
    assert store.workspace_id() == workspace_id
    assert store.snapshots() == [s1]
    assert os.listdir(snapshots_dir(store)) == [s1.id]


# Helpers


def new_store(volume: Path, clock: Clock) -> SnapshotStore:
    """Like the ``store`` fixture, on another volume."""
    root = volume / uuid4().hex
    root.mkdir(mode=0o700)
    store = SnapshotStore(root, clock=clock)
    store.init()
    return store


def workspace_of(store: SnapshotStore) -> Path:
    return store.root / "workspace"


def snapshots_dir(store: SnapshotStore) -> Path:
    return store.root / "snapshots"


def snapshot_path(store: SnapshotStore, snap: Snapshot) -> Path:
    return snapshots_dir(store) / snap.id


def write_v1(workspace: Path) -> None:
    (workspace / "a.txt").write_text("v1")
    (workspace / "sub").mkdir()
    (workspace / "sub" / "b.txt").write_text("b")


def write_v2(workspace: Path) -> None:
    """Change a file, delete a directory and add a file: what a rewind must all undo."""
    (workspace / "a.txt").write_text("v2")
    shutil.rmtree(workspace / "sub")
    (workspace / "c.txt").write_text("c")


def tree(path: Path) -> dict[str, object]:
    """Everything under ``path``, never following symlinks: files by content, symlinks by
    target and directories as "dir"."""
    entries: dict[str, object] = {}
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            entry = Path(dirpath) / name
            key = str(entry.relative_to(path))
            if entry.is_symlink():
                entries[key] = ("symlink", os.readlink(entry))
            elif entry.is_dir():
                entries[key] = "dir"
            else:
                entries[key] = entry.read_bytes()
    return entries


def describe(path: Path) -> tuple[object, ...]:
    """A file, directory or symlink by type and content, without following symlinks."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return ("symlink", os.readlink(path))
    if stat.S_ISDIR(st.st_mode):
        return ("dir", btrfs.is_subvolume(path), tree(path))
    return ("file", path.read_bytes())


def state(store: SnapshotStore) -> tuple[object, ...]:
    """Everything a refused or failed operation must leave exactly as it was."""
    return (
        tree(workspace_of(store)),
        store.workspace_id(),
        btrfs.is_readonly(workspace_of(store)),
        store.snapshots(),
        sorted(os.listdir(store.root)),
        sorted(os.listdir(snapshots_dir(store))),
    )


def fingerprint(path: Path) -> tuple[int, int, int, int]:
    st = os.stat(path)
    return st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns


def assert_read_only_snapshot(path: Path) -> None:
    assert btrfs.is_subvolume(path)
    assert btrfs.is_readonly(path)
    with pytest.raises(OSError) as excinfo:
        (path / "intruder.txt").write_text("x")
    assert excinfo.value.errno == errno.EROFS


def raises_busy(operation: Callable[[], object]) -> bool:
    try:
        operation()
    except SnapshotBusy:
        return True
    return False


def no_space_or[T](operation: Callable[[], T]) -> T | SnapshotNoSpace:
    """The result, or the SnapshotNoSpace raised. Any other error fails the test."""
    try:
        return operation()
    except SnapshotNoSpace as e:
        return e


def summarize(result: Snapshot | RestoreResult | SnapshotNoSpace) -> str:
    return f"SnapshotNoSpace ({result})" if isinstance(result, SnapshotNoSpace) else "ok"


def error_text(error: BaseException) -> str:
    """The message plus its notes (add_note), where hints may be attached."""
    return "\n".join([str(error), *getattr(error, "__notes__", ())])


def warnings_logged(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and r.name.startswith(LOGGER)
    ]


def move_clock_to(clock: Clock, when: datetime) -> None:
    """Make ``when`` the clock's next reading. Reading the clock moves it 1 µs forward."""
    current = clock()
    assert when > current, "the fake clock only moves forward here"
    clock.advance(when - current - timedelta(microseconds=1))


def filesystem_type(path: Path) -> str:
    result = subprocess.run(
        ["stat", "-f", "-c", "%T", str(path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return result.stdout.strip()


def fill_data(directory: Path) -> int:
    """Preallocate files until ENOSPC, in 64 MiB and then 1 MiB steps. Returns the bytes."""
    preallocated = 0
    for size in (64 * MIB, MIB):
        while preallocate(directory / f"fill-{uuid4().hex}", size):
            preallocated += size
    return preallocated


def preallocate(path: Path, size: int) -> bool:
    """False when the disk is full (the empty file is left behind)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.posix_fallocate(fd, 0, size)
    except OSError as e:
        if e.errno != errno.ENOSPC:
            raise
        return False
    finally:
        os.close(fd)
    return True


def fill_metadata(directory: Path) -> int:
    """Create small files, stored inline in the metadata tree, until ENOSPC. Returns how many."""
    directory.mkdir()
    count = 0
    while write_small_file(directory / f"f{count}"):
        count += 1
    return count


def write_small_file(path: Path) -> bool:
    """False when the disk is full."""
    try:
        path.write_bytes(SMALL_FILE)
    except OSError as e:
        if e.errno != errno.ENOSPC:
            raise
        return False
    return True


def report(record_property: Callable[[str, object], None], name: str, text: str) -> None:
    """Shown with ``pytest -rP``, and kept in the JUnit XML, for the devlog."""
    print(f"{name}: {text}")
    record_property(name, text)
