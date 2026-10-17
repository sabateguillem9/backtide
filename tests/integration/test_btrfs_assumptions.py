"""The T01a spike: what btrfs really does for an unprivileged user, checked in the VM.

Each test pins one behaviour of the kernel or btrfs-progs that the snapshot store relies on
(docs/10, "Plan B" table). They stay as regression tests for kernel and btrfs-progs upgrades.

Everything runs as the unprivileged Lima user on a loop btrfs mounted with
user_subvol_rm_allowed (see conftest.py), through the same backtide.snapshots.btrfs functions
the store uses.
"""

import errno
import logging
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from backtide.snapshots import SnapshotError, SnapshotNoSpace, btrfs

pytestmark = pytest.mark.integration

MIB = 1024**2
TOP_LEVEL_SUBVOLUME_ID = 5  # BTRFS_FS_TREE_OBJECTID: the subvolume the mount shows
NESTED_STUB_INO = 2  # the empty directory a nested subvolume leaves inside a snapshot
SMALL_FILE = b"x" * 2000  # under max_inline (2048): stored in the metadata tree


@pytest.fixture
def root(btrfs_volume: Path) -> Path:
    """This test's own volume root on the shared btrfs, 0700 like the store's ``<root>``."""
    path = btrfs_volume / uuid4().hex
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def root_fd(root: Path) -> Iterator[int]:
    """A directory fd on ``root``: the store renames everything relative to one."""
    with open_dir(root) as fd:
        yield fd


@contextmanager
def open_dir(path: Path) -> Iterator[int]:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)  # an fd left open would make the teardown's umount fail (busy)


def make_subvolume(path: Path, content: str | None = None) -> Path:
    """A new subvolume, with ``content`` in its marker file when given."""
    btrfs.create_subvolume(path)
    if content is not None:
        (path / "marker").write_text(content)
    return path


def marker(path: Path) -> str:
    return (path / "marker").read_text()


def delete_committed(path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """delete_subvolume(commit=True) as the store calls it, but failing on a swallowed error.

    When btrfs exits non-zero and the path is gone anyway, delete_subvolume only logs a
    WARNING: that is what a failed commit wait after a successful delete looks like."""
    with caplog.at_level(logging.WARNING, logger=btrfs.__name__):
        btrfs.delete_subvolume(path, commit=True)
    assert [r.getMessage() for r in caplog.records if r.name == btrfs.__name__] == []
    assert not os.path.lexists(path)


# 1. Deleting a read-only snapshot without privileges


def test_unprivileged_delete_of_readonly_snapshot_fails_until_ro_is_cleared(root: Path) -> None:
    workspace = make_subvolume(root / "workspace", "v1")
    snap = root / "snap"
    btrfs.snapshot(workspace, snap, readonly=True)

    with pytest.raises(SnapshotError, match="Read-only file system"):
        btrfs.run("subvolume", "delete", snap)
    assert btrfs.is_readonly(snap)
    assert marker(snap) == "v1"

    btrfs.set_readonly(snap, False)
    btrfs.run("subvolume", "delete", snap)
    assert not os.path.lexists(snap)
    assert marker(workspace) == "v1"


# 2. --commit-after without privileges. btrfs-progs deletes first and waits for the commit
# after, exiting 1 if that wait fails, so only a zero exit proves the commit.


def test_cli_delete_with_commit_after_exits_zero_unprivileged(root: Path) -> None:
    workspace = make_subvolume(root / "workspace", "v1")
    snap = root / "snap"
    btrfs.snapshot(workspace, snap, readonly=True)
    btrfs.set_readonly(snap, False)

    btrfs.run("subvolume", "delete", "--commit-after", snap)  # raises on any non-zero exit

    assert not os.path.lexists(snap)
    assert marker(workspace) == "v1"


def test_delete_subvolume_with_commit_works_unprivileged_without_warnings(
    root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    workspace = make_subvolume(root / "workspace", "v1")
    snap = root / "snap"
    btrfs.snapshot(workspace, snap, readonly=True)

    delete_committed(snap, caplog)

    assert marker(workspace) == "v1"


# 3. renameat2 EXCHANGE and NOREPLACE on subvolumes


def test_renameat2_exchange_swaps_two_subvolumes(root: Path, root_fd: int) -> None:
    make_subvolume(root / "workspace", "old")
    make_subvolume(root / "workspace.restore", "new")

    btrfs.renameat2(root_fd, "workspace.restore", "workspace", btrfs.RENAME_EXCHANGE)

    assert marker(root / "workspace") == "new"
    assert marker(root / "workspace.restore") == "old"
    assert btrfs.is_subvolume(root / "workspace")
    assert btrfs.is_subvolume(root / "workspace.restore")


def test_renameat2_exchange_works_when_the_workspace_is_readonly(root: Path, root_fd: int) -> None:
    """The agent may flip its own workspace to read-only; the swap is in one directory."""
    make_subvolume(root / "workspace", "old")
    make_subvolume(root / "workspace.restore", "new")
    btrfs.set_readonly(root / "workspace", True)

    btrfs.renameat2(root_fd, "workspace.restore", "workspace", btrfs.RENAME_EXCHANGE)

    assert marker(root / "workspace") == "new"
    assert not btrfs.is_readonly(root / "workspace")
    assert btrfs.is_readonly(root / "workspace.restore")


def test_renameat2_noreplace_onto_an_existing_subvolume_raises_eexist(
    root: Path, root_fd: int
) -> None:
    make_subvolume(root / "workspace", "old")
    make_subvolume(root / "workspace.restore", "new")

    with pytest.raises(SnapshotError) as excinfo:
        btrfs.renameat2(root_fd, "workspace.restore", "workspace", btrfs.RENAME_NOREPLACE)

    assert excinfo.value.errno == errno.EEXIST
    assert marker(root / "workspace") == "old"
    assert marker(root / "workspace.restore") == "new"


# 4. Moving subvolumes into snapshots/


def test_writable_subvolume_moves_into_another_directory(root: Path, root_fd: int) -> None:
    (root / "snapshots").mkdir(mode=0o700)
    make_subvolume(root / "workspace", "old")

    btrfs.renameat2(root_fd, "workspace", "snapshots/.incoming-x", btrfs.RENAME_NOREPLACE)

    moved = root / "snapshots" / ".incoming-x"
    assert btrfs.is_subvolume(moved)
    assert marker(moved) == "old"
    assert not os.path.lexists(root / "workspace")


def test_readonly_subvolume_cannot_move_to_another_directory(root: Path, root_fd: int) -> None:
    (root / "snapshots").mkdir(mode=0o700)
    make_subvolume(root / "workspace", "old")
    btrfs.set_readonly(root / "workspace", True)

    with pytest.raises(SnapshotError) as excinfo:
        btrfs.renameat2(root_fd, "workspace", "snapshots/x", btrfs.RENAME_NOREPLACE)

    assert excinfo.value.errno == errno.EROFS
    assert marker(root / "workspace") == "old"
    assert not os.path.lexists(root / "snapshots" / "x")


def test_readonly_subvolume_renames_within_its_directory(root: Path, root_fd: int) -> None:
    """How a snapshot is published (.incoming-<id> to <id>) and tombstoned (<id> to .trash-)."""
    (root / "snapshots").mkdir(mode=0o700)
    make_subvolume(root / "snapshots" / ".incoming-x", "old")
    btrfs.set_readonly(root / "snapshots" / ".incoming-x", True)

    btrfs.renameat2(root_fd, "snapshots/.incoming-x", "snapshots/x", btrfs.RENAME_NOREPLACE)
    btrfs.renameat2(root_fd, "snapshots/x", "snapshots/.trash-x", btrfs.RENAME_NOREPLACE)

    trashed = root / "snapshots" / ".trash-x"
    assert btrfs.is_readonly(trashed)
    assert marker(trashed) == "old"
    assert sorted(os.listdir(root / "snapshots")) == [".trash-x"]


# 5. Detecting subvolumes with lstat


def test_subvolume_roots_have_inode_256_and_nested_stubs_inode_2(root: Path) -> None:
    workspace = make_subvolume(root / "workspace")
    (workspace / "plain").mkdir()
    make_subvolume(workspace / "nested", "hidden")
    snap = root / "snap"
    btrfs.snapshot(workspace, snap, readonly=True)

    for subvolume in (workspace, workspace / "nested", snap):
        assert os.lstat(subvolume).st_ino == btrfs.SUBVOLUME_ROOT_INO
        assert btrfs.is_subvolume(subvolume)
    for plain in (root, workspace / "plain", snap / "plain"):
        assert os.lstat(plain).st_ino != btrfs.SUBVOLUME_ROOT_INO
        assert not btrfs.is_subvolume(plain)

    stub = snap / "nested"
    stub_stat = os.lstat(stub)
    assert stat.S_ISDIR(stub_stat.st_mode)
    assert stub_stat.st_ino == NESTED_STUB_INO
    assert not btrfs.is_subvolume(stub)
    assert os.listdir(stub) == []  # the nested subvolume's data escapes the snapshot


# 6. Subvolume IDs without privileges


def test_rootid_is_unprivileged_and_follows_the_exchange(root: Path, root_fd: int) -> None:
    workspace_id = btrfs.subvolume_id(make_subvolume(root / "workspace"))
    staging_id = btrfs.subvolume_id(make_subvolume(root / "workspace.restore"))
    assert btrfs.subvolume_id(root) == TOP_LEVEL_SUBVOLUME_ID
    assert len({workspace_id, staging_id, TOP_LEVEL_SUBVOLUME_ID}) == 3

    btrfs.renameat2(root_fd, "workspace.restore", "workspace", btrfs.RENAME_EXCHANGE)

    assert btrfs.subvolume_id(root / "workspace") == staging_id
    assert btrfs.subvolume_id(root / "workspace.restore") == workspace_id


# 7. Snapshot consistency without fsync


def test_a_write_without_fsync_is_in_the_snapshot(root: Path) -> None:
    workspace = make_subvolume(root / "workspace")
    data = os.urandom(8 * MIB)
    snap = root / "snap"

    with open(workspace / "unsynced.bin", "wb") as file:
        file.write(data)
        file.flush()  # into the page cache only: no fsync, and the file is still open
        btrfs.snapshot(workspace, snap, readonly=True)

    assert (snap / "unsynced.bin").read_bytes() == data


# 8. A workspace with a nested subvolume planted in it


def test_subvolume_with_a_nested_one_moves_and_turns_readonly(root: Path, root_fd: int) -> None:
    """The restore publishes the old workspace like this; the planted data stays as evidence."""
    (root / "snapshots").mkdir(mode=0o700)
    workspace = make_subvolume(root / "workspace", "old")
    make_subvolume(workspace / "nested", "planted")

    btrfs.renameat2(root_fd, "workspace", "snapshots/.incoming-x", btrfs.RENAME_NOREPLACE)
    btrfs.set_readonly(root / "snapshots" / ".incoming-x", True)
    btrfs.renameat2(root_fd, "snapshots/.incoming-x", "snapshots/x", btrfs.RENAME_NOREPLACE)

    published = root / "snapshots" / "x"
    assert btrfs.is_readonly(published)
    assert marker(published) == "old"
    assert btrfs.is_subvolume(published / "nested")
    assert marker(published / "nested") == "planted"


def test_delete_of_a_subvolume_with_a_nested_one_fails_and_stays_readonly(root: Path) -> None:
    """The store matches "Directory not empty" to hint at a root ``delete -R``."""
    workspace = make_subvolume(root / "workspace", "old")
    make_subvolume(workspace / "nested", "planted")
    btrfs.set_readonly(workspace, True)

    with pytest.raises(SnapshotError, match="Directory not empty"):
        btrfs.delete_subvolume(workspace, commit=True)

    assert btrfs.is_readonly(workspace)
    assert marker(workspace) == "old"
    assert marker(workspace / "nested") == "planted"


# 9. A full disk. take needs one read-only snapshot; restore needs one writable snapshot, then
# renames. Both fills keep the tmpfs-backed image sparse: fallocate never writes the data, and
# small files live inline in the metadata tree.


def test_data_full_disk_still_allows_snapshots_renames_and_delete(
    tiny_btrfs_volume: Path,
    record_property: Callable[[str, object], None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Decides the ballast fallback (docs/10, Plan B): it is needed only if a snapshot fails."""
    root = tiny_btrfs_volume
    workspace, target = volume_with_one_snapshot(root)

    preallocated = fill_data(workspace)
    free = free_bytes(root)
    take = try_snapshot(workspace, root / "snapshots" / "taken", readonly=True)
    staging = try_snapshot(target, root / "workspace.restore", readonly=False)
    report(
        record_property,
        "data_full",
        f"{preallocated // MIB} MiB preallocated, {free // MIB} MiB free; "
        f"snapshot -r: {take}; writable snapshot: {staging}",
    )

    assert free < MIB
    assert take == "ok", "take fails on a full disk: T01b needs the .reserve ballast"
    assert staging == "ok", "restore fails on a full disk: T01b needs the .reserve ballast"
    with open_dir(root) as fd:
        btrfs.renameat2(fd, "workspace.restore", "workspace", btrfs.RENAME_EXCHANGE)
        btrfs.renameat2(fd, "workspace.restore", "snapshots/.incoming-x", btrfs.RENAME_NOREPLACE)
    assert marker(root / "workspace") == "v1"
    assert marker(root / "snapshots" / ".incoming-x") == "v2"
    delete_committed(target, caplog)


def test_metadata_full_disk_blocks_renames_but_not_snapshots_or_delete(
    tiny_btrfs_volume: Path,
    record_property: Callable[[str, object], None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With data full, small files fill the metadata too. Snapshots and deletes still work,
    but every rename fails with ENOSPC: a restore stops at the exchange, before any change.

    Not pinned here, seen in the spike: neither unlinking a 64 MiB data file (the planned
    ballast) nor 2,000 of the small files made renames work again; removing all of them did."""
    root = tiny_btrfs_volume
    workspace, target = volume_with_one_snapshot(root)
    fill_data(workspace)
    small_files = fill_metadata(workspace / "small")
    report(record_property, "metadata_full", f"{small_files} small files until ENOSPC")

    btrfs.snapshot(workspace, root / "snapshots" / "taken", readonly=True)
    btrfs.snapshot(target, root / "workspace.restore", readonly=False)
    with open_dir(root) as fd, pytest.raises(SnapshotNoSpace) as excinfo:
        btrfs.renameat2(fd, "workspace.restore", "workspace", btrfs.RENAME_EXCHANGE)

    assert excinfo.value.errno == errno.ENOSPC
    assert marker(root / "workspace") == "v2"
    assert marker(root / "workspace.restore") == "v1"
    delete_committed(root / "workspace.restore", caplog)
    delete_committed(root / "snapshots" / "taken", caplog)
    assert sorted(os.listdir(root)) == ["snapshots", "workspace"]
    assert os.listdir(root / "snapshots") == ["target"]


# 10. Symlinks. The CLI follows a symlink in the last component, so the wrapper refuses one.


def test_cli_acts_on_a_symlink_target_so_the_wrapper_refuses_symlinks(root: Path) -> None:
    """A tombstone that is really a symlink to the workspace must never delete the workspace."""
    workspace = make_subvolume(root / "workspace", "live")
    link = root / ".trash-x"
    link.symlink_to(workspace)

    with pytest.raises(SnapshotError, match="not a subvolume root"):
        btrfs.delete_subvolume(link, commit=True)
    for refused in (lambda: btrfs.set_readonly(link, True), lambda: btrfs.is_readonly(link)):
        with pytest.raises(SnapshotError, match="symlink"):
            refused()
    assert marker(workspace) == "live"
    assert not btrfs.is_readonly(workspace)

    # What the checks prevent: btrfs reads and deletes the TARGET.
    assert btrfs.run("property", "get", "-ts", link, "ro") == "ro=false\n"
    btrfs.run("subvolume", "delete", link)
    assert not os.path.lexists(workspace)
    assert os.path.islink(link)


def volume_with_one_snapshot(root: Path) -> tuple[Path, Path]:
    """The store's layout: a workspace now at "v2", and a read-only snapshot of it at "v1"."""
    (root / "snapshots").mkdir(mode=0o700)
    workspace = make_subvolume(root / "workspace", "v1")
    target = root / "snapshots" / "target"
    btrfs.snapshot(workspace, target, readonly=True)
    (workspace / "marker").write_text("v2")
    return workspace, target


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


def try_snapshot(src: Path, dst: Path, *, readonly: bool) -> str:
    """ "ok", or the SnapshotNoSpace message. Any other error fails the test."""
    try:
        btrfs.snapshot(src, dst, readonly=readonly)
    except SnapshotNoSpace as e:
        return f"SnapshotNoSpace ({e})"
    return "ok"


def free_bytes(path: Path) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def report(record_property: Callable[[str, object], None], name: str, outcome: str) -> None:
    """Shown with ``pytest -rP``, and kept in the JUnit XML, for the devlog."""
    print(f"{name}: {outcome}")
    record_property(name, outcome)
