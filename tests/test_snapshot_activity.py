"""Activity detection: did the workspace change since its reference snapshot? Pure, no btrfs.

The counters come from BTRFS_IOC_GET_SUBVOL_INFO (docs/19, section 2); the parser itself is
tested in test_snapshot_btrfs.py. Here a SubvolumeInfo is built by hand."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from backtide.snapshots import Reason, Snapshot
from backtide.snapshots.activity import SnapshotInfo, changed_since, lineage_reference
from backtide.snapshots.btrfs import SubvolumeInfo

T0 = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
WS_UUID = UUID(int=0xA1)
OLD_WS_UUID = UUID(int=0xA0)
TARGET_UUID = UUID(int=0xB1)


def info(
    *,
    own: UUID,
    parent: UUID | None = None,
    ctransid: int = 100,
    generation: int = 100,
    otransid: int = 90,
    treeid: int = 258,
    flags: int = 0,
) -> SubvolumeInfo:
    return SubvolumeInfo(
        treeid=treeid,
        name="x",
        generation=generation,
        flags=flags,
        uuid=own,
        parent_uuid=parent,
        ctransid=ctransid,
        otransid=otransid,
    )


def snap_of(
    minutes: int, parent: UUID | None, *, own: int, reason: str = Reason.PERIODIC, **counters: int
) -> SnapshotInfo:
    return SnapshotInfo(
        Snapshot(T0 + timedelta(minutes=minutes), reason),
        info(own=UUID(int=own), parent=parent, flags=1, **counters),
    )


# --- changed_since: a snapshot of this very workspace ----------------------------------------


def test_nothing_changed_when_the_counters_match() -> None:
    workspace = info(own=WS_UUID, ctransid=100, generation=95)
    reference = info(own=UUID(int=1), parent=WS_UUID, ctransid=100, otransid=95)
    assert not changed_since(workspace, reference)


def test_a_different_ctransid_means_changed() -> None:
    workspace = info(own=WS_UUID, ctransid=101, generation=95)
    reference = info(own=UUID(int=1), parent=WS_UUID, ctransid=100, otransid=95)
    assert changed_since(workspace, reference)


def test_same_ctransid_but_a_later_generation_means_changed() -> None:
    # The backup signal: ctransid equal (a rewrite in the same tick) but a commit happened.
    workspace = info(own=WS_UUID, ctransid=100, generation=96)
    reference = info(own=UUID(int=1), parent=WS_UUID, ctransid=100, otransid=95)
    assert changed_since(workspace, reference)


# --- changed_since: right after a rewind, the reference is the target ------------------------


def test_after_a_rewind_nothing_changed_while_generation_is_still_otransid() -> None:
    workspace = info(own=WS_UUID, parent=TARGET_UUID, ctransid=80, generation=120, otransid=120)
    target = info(own=TARGET_UUID, ctransid=80, generation=80, otransid=70, flags=1)
    assert not changed_since(workspace, target)


def test_after_a_rewind_a_later_generation_than_its_own_creation_means_changed() -> None:
    workspace = info(own=WS_UUID, parent=TARGET_UUID, ctransid=80, generation=121, otransid=120)
    target = info(own=TARGET_UUID, ctransid=80, generation=80, otransid=70, flags=1)
    assert changed_since(workspace, target)


def test_after_a_rewind_a_different_ctransid_means_changed() -> None:
    workspace = info(own=WS_UUID, parent=TARGET_UUID, ctransid=81, generation=120, otransid=120)
    target = info(own=TARGET_UUID, ctransid=80, generation=80, otransid=70, flags=1)
    assert changed_since(workspace, target)


# --- changed_since: no usable reference -------------------------------------------------------


def test_no_reference_means_changed() -> None:
    assert changed_since(info(own=WS_UUID), None)


def test_a_reference_from_another_lineage_means_changed_even_if_the_counters_match() -> None:
    # Never trust counters of a snapshot that is neither of this workspace nor its target.
    workspace = info(own=WS_UUID, parent=TARGET_UUID, ctransid=100, generation=90, otransid=90)
    stranger = info(own=UUID(int=7), parent=OLD_WS_UUID, ctransid=100, otransid=90)
    assert changed_since(workspace, stranger)


def test_a_fresh_workspace_without_a_parent_matches_nothing_but_its_own_snapshots() -> None:
    workspace = info(own=WS_UUID, parent=None, ctransid=100, generation=95)
    unrelated = info(own=UUID(int=3), parent=None, ctransid=100, otransid=95)
    assert changed_since(workspace, unrelated)


# --- lineage_reference ------------------------------------------------------------------------


def test_the_reference_is_the_newest_snapshot_of_this_workspace() -> None:
    workspace = info(own=WS_UUID)
    older = snap_of(1, WS_UUID, own=1)
    newest = snap_of(5, WS_UUID, own=2)
    assert lineage_reference(workspace, [older, newest]) == newest
    assert lineage_reference(workspace, [newest, older]) == newest  # order does not matter


def test_a_newer_pre_restore_of_the_other_lineage_is_never_chosen() -> None:
    # After a rewind the newest snapshot of all is the pre_restore: the OLD workspace.
    workspace = info(own=WS_UUID, parent=TARGET_UUID)
    target = SnapshotInfo(Snapshot(T0, Reason.PERIODIC), info(own=TARGET_UUID, flags=1))
    pre_restore = snap_of(30, OLD_WS_UUID, own=0xAA, reason=Reason.PRE_RESTORE)
    assert pre_restore.snapshot.taken_at > target.snapshot.taken_at
    assert lineage_reference(workspace, [target, pre_restore]) == target


def test_after_a_rewind_a_new_snapshot_of_the_new_workspace_wins_over_the_target() -> None:
    workspace = info(own=WS_UUID, parent=TARGET_UUID)
    target = SnapshotInfo(Snapshot(T0, Reason.PERIODIC), info(own=TARGET_UUID, flags=1))
    pre_restore = snap_of(30, OLD_WS_UUID, own=0xAA, reason=Reason.PRE_RESTORE)
    own = snap_of(40, WS_UUID, own=0xBB)
    assert lineage_reference(workspace, [target, pre_restore, own]) == own


def test_a_manual_snapshot_of_the_workspace_counts_like_any_other() -> None:
    workspace = info(own=WS_UUID)
    manual = snap_of(2, WS_UUID, own=1, reason=Reason.MANUAL)
    assert lineage_reference(workspace, [manual]) == manual


def test_no_reference_when_nothing_descends_from_the_workspace() -> None:
    workspace = info(own=WS_UUID, parent=None)
    assert lineage_reference(workspace, [snap_of(1, OLD_WS_UUID, own=1)]) is None
    assert lineage_reference(workspace, []) is None


def test_a_workspace_with_a_parent_but_a_deleted_target_has_no_reference() -> None:
    workspace = info(own=WS_UUID, parent=TARGET_UUID)
    assert lineage_reference(workspace, [snap_of(1, OLD_WS_UUID, own=1)]) is None


@pytest.mark.parametrize("count", [0, 1, 300])
def test_lineage_reference_accepts_any_iterable(count: int) -> None:
    workspace = info(own=WS_UUID)
    snapshots = (snap_of(i, WS_UUID, own=i + 1) for i in range(count))
    reference = lineage_reference(workspace, snapshots)
    assert (reference is None) == (count == 0)
    if count:
        assert reference is not None
        assert reference.snapshot.taken_at == T0 + timedelta(minutes=count - 1)
