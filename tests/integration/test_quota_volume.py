"""The guards around the two sudo btrfs commands of conftest.py, checked in the VM.

QuotaVolume.set_limit runs ``sudo -n btrfs qgroup limit <bytes>|none <path>`` through
_sudo_btrfs, which checks the argv, the mount and the path itself, before sudo runs. Each test
caps a real subvolume first (the positive control, a real sudo), then forbids every
subprocess: a guard that let something through fails the test instead of running sudo on it.
Afterwards the cap must be unchanged.

The second one is ``sudo -n btrfs filesystem resize max <mnt>`` (_sudo_btrfs_resize, approved by
the founder on 2026-10-17 for test_grow.py): it refuses, before sudo runs, any path that is not
a mount point this process mounted itself.
"""

import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import pytest

from vigia.snapshots import SnapshotError, btrfs

pytestmark = pytest.mark.integration

MIB = 1024**2
CAP = 32 * MIB

type SudoBtrfs = Callable[[Path, tuple[str, ...]], None]


class QuotaVolume(Protocol):
    """What conftest.py's ``quota_volume`` fixture gives (not imported: two conftest.py)."""

    mnt: Path
    image_file: Path

    def set_limit(self, path: Path, limit: int | None) -> None: ...


@contextmanager
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Any subprocess (sudo among them) fails the test while this is active."""

    def refuse(argv: object, *args: object, **kwargs: object) -> None:
        raise AssertionError(f"the guard let {argv!r} through to a subprocess")

    with monkeypatch.context() as patched:
        patched.setattr(subprocess, "run", refuse)
        patched.setattr(subprocess, "Popen", refuse)
        yield


@pytest.fixture
def workspace(quota_volume: QuotaVolume) -> Path:
    """A subvolume of the quota volume, capped with a real sudo (the positive control)."""
    path = quota_volume.mnt / "workspace"
    btrfs.create_subvolume(path)
    quota_volume.set_limit(path, CAP)
    assert btrfs.qgroup_usage(path).limit == CAP
    return path


# set_limit: only subvolumes of its own mount


PATH_CASES = {
    "the mount itself, 0/5": ("", "not strictly inside the test mount"),
    "a plain directory": ("workspace/plain", "not a subvolume root"),
    "a missing path": ("missing", "not a subvolume root"),
    "a symlink to the capped subvolume": ("link", "not canonical"),
    "a symlink in a parent": ("dirlink/workspace", "not canonical"),
    "a .. that resolves to the capped subvolume": ("workspace/plain/..", "not canonical"),
    "a .. that resolves to the mount": ("workspace/..", "not canonical"),
}


@pytest.mark.parametrize(("relative", "reason"), PATH_CASES.values(), ids=PATH_CASES)
def test_set_limit_refuses_anything_but_a_subvolume_of_its_own_mount(
    quota_volume: QuotaVolume,
    workspace: Path,
    relative: str,
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mnt = quota_volume.mnt
    (workspace / "plain").mkdir()
    (mnt / "link").symlink_to(workspace)
    (mnt / "dirlink").symlink_to(mnt)
    path = Path(f"{mnt}/{relative}") if relative else mnt  # str: pathlib keeps "..", not "/"

    with no_subprocess(monkeypatch):
        for limit in (2 * CAP, None):
            with pytest.raises(SnapshotError, match=f"refusing sudo on .*: {reason}"):
                quota_volume.set_limit(path, limit)

    assert btrfs.qgroup_usage(workspace).limit == CAP


def test_set_limit_refuses_a_subvolume_of_another_btrfs(
    quota_volume: QuotaVolume,
    workspace: Path,
    btrfs_volume: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other = btrfs_volume / f"quota-guard-{uuid4().hex}"
    btrfs.create_subvolume(other)
    try:
        with no_subprocess(monkeypatch):
            with pytest.raises(SnapshotError, match="refusing sudo on .*: not strictly inside"):
                quota_volume.set_limit(other, CAP)
    finally:
        btrfs.delete_subvolume(other)


def test_set_limit_refuses_a_path_on_another_btrfs_inside_its_mount(
    quota_volume: QuotaVolume, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Something mounted inside the test mount would pass the path checks; the fsid stops it.
    Making that mount needs root, so here the fsid of the subvolume is faked."""
    real_fsid = btrfs.fsid

    def fsid(path: Path) -> str:
        return "00000000-0000-0000-0000-000000000000" if path == workspace else real_fsid(path)

    with no_subprocess(monkeypatch), monkeypatch.context() as patched:
        patched.setattr(btrfs, "fsid", fsid)
        with pytest.raises(SnapshotError, match="refusing sudo on .*: not on the btrfs mounted"):
            quota_volume.set_limit(workspace, None)

    assert btrfs.qgroup_usage(workspace).limit == CAP


def test_set_limit_rejects_a_relative_path_before_anything_else(
    quota_volume: QuotaVolume, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with no_subprocess(monkeypatch), pytest.raises(ValueError, match="absolute"):
        quota_volume.set_limit(Path("workspace"), None)
    assert btrfs.qgroup_usage(workspace).limit == CAP


# _sudo_btrfs: only `qgroup limit`, only on a test mount


def argv_cases(workspace: Path, mnt: Path) -> dict[str, object]:
    ws = str(workspace)
    return {
        "qgroup destroy": ("qgroup", "destroy", "0/256", ws),
        "qgroup clear-stale": ("qgroup", "clear-stale", ws),
        "quota disable": ("quota", "disable", str(mnt)),
        "an option": ("qgroup", "limit", "-e", str(CAP), ws),
        "a qgroup id": ("qgroup", "limit", str(CAP), "0/256", ws),
        "a size suffix": ("qgroup", "limit", "32M", ws),
        "a leading zero": ("qgroup", "limit", f"0{CAP}", ws),
        "a zero limit": ("qgroup", "limit", "0", ws),
        "u64 max, which btrfs reads as none": ("qgroup", "limit", str(2**64 - 1), ws),
        "a huge number": ("qgroup", "limit", "9" * 5000, ws),
        "a relative path": ("qgroup", "limit", str(CAP), "workspace"),
        "a trailing slash": ("qgroup", "limit", str(CAP), f"{ws}/"),
        "a double slash": ("qgroup", "limit", str(CAP), ws.replace("/workspace", "//workspace")),
        "a list": ["qgroup", "limit", str(CAP), ws],
        "an int": ("qgroup", "limit", CAP, ws),
        "no path": ("qgroup", "limit", str(CAP)),
    }


ARGV_CASES = list(argv_cases(Path("/w"), Path("/m")))


@pytest.mark.parametrize("case", ARGV_CASES)
def test_sudo_btrfs_runs_nothing_but_qgroup_limit(
    quota_volume: QuotaVolume,
    workspace: Path,
    sudo_btrfs: SudoBtrfs,
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = argv_cases(workspace, quota_volume.mnt)[case]

    with no_subprocess(monkeypatch):
        with pytest.raises(SnapshotError, match="refusing sudo btrfs"):
            sudo_btrfs(quota_volume.mnt, args)  # a wrong shape on purpose

    assert btrfs.qgroup_usage(workspace).limit == CAP


def test_sudo_btrfs_runs_only_on_the_mount_point_of_a_test_btrfs(
    quota_volume: QuotaVolume,
    workspace: Path,
    sudo_btrfs: SudoBtrfs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mnt = quota_volume.mnt
    (mnt.parent / "mntlink").symlink_to(mnt)
    args = btrfs.qgroup_limit_args(workspace, None)

    with no_subprocess(monkeypatch):
        for not_a_test_mount in (Path("/"), mnt.parent, workspace, mnt.parent / "mntlink"):
            with pytest.raises(SnapshotError, match="not the mount point of a test btrfs"):
                sudo_btrfs(not_a_test_mount, args)

    assert btrfs.qgroup_usage(workspace).limit == CAP
    sudo_btrfs(mnt, args)  # the same argv on the right mount runs
    assert btrfs.qgroup_usage(workspace).limit is None


# _sudo_btrfs_resize: only `filesystem resize max`, only on a mount this process mounted


def test_sudo_btrfs_resize_runs_only_on_a_mount_this_test_made(
    quota_volume: QuotaVolume,
    workspace: Path,
    sudo_btrfs_resize: Callable[[Path], None],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mnt = quota_volume.mnt
    (mnt.parent / "mntlink").symlink_to(mnt)
    outside = tmp_path / "not-a-mount"
    outside.mkdir()

    with no_subprocess(monkeypatch):
        for refused in (
            Path("/"),
            outside,
            mnt.parent,
            mnt / "workspace",
            workspace,
            mnt.parent / "mntlink",
            mnt / ".." / mnt.name,
            Path("mnt"),
            str(mnt),
        ):
            with pytest.raises(SnapshotError, match="refusing sudo btrfs resize"):
                sudo_btrfs_resize(refused)  # type: ignore[arg-type]

    sudo_btrfs_resize(mnt)  # the same call on the right mount runs (a no-op: already max)
