"""BTRFS_IOC_GET_SUBVOL_INFO on a real btrfs, and the change detection built on it (docs/19,
section 2). Everything runs as the unprivileged Lima user, through the store fixture.

These are the facts activity.py and the Guardian rely on: ``ctransid`` moves at once with any
change and not with a read or a snapshot, a snapshot copies it, ``parent_uuid`` links a
snapshot to its origin and a rewound workspace to its target, and ``generation`` catches up
after ``btrfs filesystem sync`` (so the backup signal does not fire on an idle workspace)."""

import mmap
import os
import subprocess
from contextlib import nullcontext
from pathlib import Path

import pytest

from vigia.service.clock import clock_synced
from vigia.snapshots import Reason, SnapshotError, SnapshotStore, btrfs
from vigia.snapshots.activity import SnapshotInfo, changed_since, lineage_reference

pytestmark = pytest.mark.integration


def workspace_info(store: SnapshotStore) -> btrfs.SubvolumeInfo:
    return btrfs.subvolume_info(store.workspace)


def snapshot_infos(store: SnapshotStore) -> list[SnapshotInfo]:
    return [
        SnapshotInfo(snap, btrfs.subvolume_info(store.snapshots_dir / snap.id))
        for snap in store.snapshots()
    ]


def changed(store: SnapshotStore) -> bool:
    """What the Guardian does: compare; if equal, commit and compare again."""
    reference = lineage_reference(workspace_info(store), snapshot_infos(store))
    ref_info = reference.info if reference else None
    if changed_since(workspace_info(store), ref_info):
        return True
    btrfs.sync_filesystem(store.root)
    return changed_since(workspace_info(store), ref_info)


def test_a_new_workspace_is_a_writable_subvolume_without_a_parent(store: SnapshotStore) -> None:
    info = workspace_info(store)
    assert info.treeid == store.workspace_id()
    assert info.uuid.int != 0
    assert info.parent_uuid is None
    assert not info.readonly
    assert info.otransid > 0
    assert info.ctransid >= info.otransid
    assert info.generation >= info.otransid
    assert info.name == "workspace"


def test_a_snapshot_is_read_only_and_remembers_its_origin(store: SnapshotStore) -> None:
    (store.workspace / "a.txt").write_text("hello")
    snap = store.take(Reason.MANUAL)
    origin = workspace_info(store)
    taken = btrfs.subvolume_info(store.snapshots_dir / snap.id)
    assert taken.readonly
    assert taken.parent_uuid == origin.uuid
    assert taken.uuid != origin.uuid
    assert taken.ctransid == origin.ctransid  # a snapshot copies the origin's ctransid
    assert taken.name == snap.id


def test_ctransid_moves_with_changes_and_not_with_reads_or_snapshots(store: SnapshotStore) -> None:
    # ctransid is the id of the transaction of the last change, so two changes in the same
    # transaction share it: each step is committed first, as the Guardian's snapshots do.
    target = store.workspace / "f.bin"
    target.write_bytes(b"x" * 100)
    btrfs.sync_filesystem(store.root)
    base = workspace_info(store).ctransid

    assert target.read_bytes() == b"x" * 100
    os.stat(target)
    assert workspace_info(store).ctransid == base  # a read is not a change

    store.take(Reason.MANUAL)
    assert workspace_info(store).ctransid == base  # neither is a snapshot of it

    steps = [
        ("write", lambda: target.write_bytes(b"y" * 100)),
        ("rewrite the same bytes", lambda: target.write_bytes(b"y" * 100)),
        ("chmod", lambda: target.chmod(0o600)),
        ("create", lambda: (store.workspace / "g").write_text("new")),
        ("delete", lambda: (store.workspace / "g").unlink()),
        ("mkdir", lambda: (store.workspace / "d").mkdir()),
    ]
    last = base
    for label, act in steps:
        btrfs.sync_filesystem(store.root)
        act()
        now = workspace_info(store).ctransid
        assert now > last, label
        last = now


def test_an_mmap_write_moves_ctransid(store: SnapshotStore) -> None:
    target = store.workspace / "m.bin"
    target.write_bytes(b"\0" * 4096)
    btrfs.sync_filesystem(store.root)
    before = workspace_info(store).ctransid
    with open(target, "r+b") as handle, mmap.mmap(handle.fileno(), 4096) as mapped:
        mapped[0:4] = b"abcd"
        mapped.flush()
    assert workspace_info(store).ctransid > before


def test_change_detection_end_to_end(store: SnapshotStore) -> None:
    target = store.workspace / "f.txt"
    target.write_text("one")
    assert changed(store)  # no snapshot yet
    store.take(Reason.PERIODIC)
    assert not changed(store)  # including the generation backup, after a sync
    assert not changed(store)
    target.read_text()
    assert not changed(store)
    target.write_text("two")
    assert changed(store)
    store.take(Reason.PERIODIC)
    assert not changed(store)
    target.chmod(0o600)
    assert changed(store)


def test_a_snapshot_of_something_else_does_not_make_the_workspace_changed(
    store: SnapshotStore,
) -> None:
    (store.workspace / "f.txt").write_text("one")
    store.take(Reason.PERIODIC)
    assert not changed(store)
    store.take(Reason.MANUAL)
    store.take(Reason.RECOVERED)
    assert not changed(store)
    os.sync()
    assert not changed(store)


def test_after_a_rewind_the_reference_is_the_target_and_not_the_undo_point(
    store: SnapshotStore,
) -> None:
    target_file = store.workspace / "f.txt"
    target_file.write_text("one")
    first = store.take(Reason.PERIODIC)
    target_file.write_text("two")
    store.take(Reason.PERIODIC)
    old = workspace_info(store)

    result = store.restore(first.id, quiesce=nullcontext)
    assert result.undo is not None
    rewound = workspace_info(store)
    first_info = btrfs.subvolume_info(store.snapshots_dir / first.id)
    undo_info = btrfs.subvolume_info(store.snapshots_dir / result.undo.id)

    assert rewound.uuid != old.uuid
    assert rewound.treeid != old.treeid
    assert rewound.parent_uuid == first_info.uuid
    assert undo_info.uuid == old.uuid  # the undo point IS the old workspace, renamed
    assert result.undo.taken_at > first.taken_at  # the newest snapshot of all is the undo point

    reference = lineage_reference(rewound, snapshot_infos(store))
    assert reference is not None
    assert reference.snapshot == first
    assert not changed(store)  # nothing was written since the rewind

    target_file.write_text("three")
    assert changed(store)
    newer = store.take(Reason.PERIODIC)
    reference = lineage_reference(workspace_info(store), snapshot_infos(store))
    assert reference is not None
    assert reference.snapshot == newer
    assert not changed(store)


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: p.mkdir(), id="plain-directory"),
        pytest.param(lambda p: p.write_text("x"), id="file"),
        pytest.param(lambda p: p.symlink_to("/"), id="symlink"),
        pytest.param(lambda p: None, id="missing"),
    ],
)
def test_only_a_subvolume_root_is_accepted(
    store: SnapshotStore,
    make: "callable[[Path], object]",  # type: ignore[valid-type]
) -> None:
    path = store.workspace / "inside"
    make(path)
    with pytest.raises(SnapshotError, match="not a subvolume root"):
        btrfs.subvolume_info(path)


def test_sync_filesystem_works_without_privileges_and_commits(store: SnapshotStore) -> None:
    (store.workspace / "f.txt").write_text("one")
    before = workspace_info(store)
    btrfs.sync_filesystem(store.root)
    after = workspace_info(store)
    assert after.generation >= before.generation
    assert after.ctransid == before.ctransid  # committing is not changing


def test_clock_synced_agrees_with_systemd() -> None:
    """The VM's own opinion: ``timedatectl`` reads the same kernel flag."""
    answer = subprocess.run(
        ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    assert answer in ("yes", "no")
    assert clock_synced() is (answer == "yes")
