"""T04e-1 in the VM: a small volume full of metadata, a rewind that fails for lack of space, the
volume grown once and within its limit, and the retry that works. docs/19, section 6, and the
criterion "Crecimiento de emergencia" of T04 in docs/backlog.md.

Its one new sudo, approved by the founder on 2026-10-17 (docs/19, "Bloqueado por el
founder"), is

    sudo -n btrfs filesystem resize max <mount point of this test's own btrfs>

and it lives in conftest.py (``_sudo_btrfs_resize``, next to ``_sudo_btrfs``): it runs only on
a mount this process mounted itself and only after ``_require_test_mount`` (a canonical path
under pytest-of-*, the btrfs loop mount of the image next to it). ``make it`` runs this file.

Nothing else is privileged: the btrfs is formatted with ``mkfs.btrfs -b 1G`` on a 1.25 GiB
image, so the loop device already sees the whole file and ``losetup --set-capacity`` is never
needed (here it fails the test if it is called), and the
image is the test user's own, so growing it would need no privilege either.

What is real: the store on a real btrfs, the black box, the Guardian's rewind, its retry and
``VolumeGrower`` with the production readings (``SystemProbe``: mountinfo, /sys/block, stat,
BTRFS_IOC_DEV_INFO). What is not: the agent (a fake jail, already stopped: no Docker), the file
watcher (``NullWatcher``) and the host's free space (the VM's /tmp is a small tmpfs in RAM; the
margin rule has its unit tests).
"""

from collections.abc import Callable
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox, create_key
from backtide.service.config import Secret, ServiceConfig
from backtide.service.guardian import Guardian
from backtide.service.offline import NullWatcher
from backtide.service.rewind import RewindStatus
from backtide.snapshots import Reason, SnapshotError, SnapshotStore
from backtide.snapshots.grow import GrowLimits, SystemProbe, VolumeGrower
from backtide.snapshots.space import GIB, MIB, HostSpace
from tests.integration.conftest import VOLUME_IMAGE
from tests.integration.test_snapshots import fill_data, fill_metadata
from tests.test_service_guardian import TOKEN, Alerts, FakeJail

IMAGE_SIZE = GIB + 256 * MIB  # measured: the loop sees 1,280 MiB and btrfs uses 1,024
FS_SIZE = GIB
CEILING = 3 * GIB // 2

pytestmark = pytest.mark.integration


class VmSteps:
    """The privileged steps of this test: the file is the test user's, the loop step must not
    be needed, and the resize is the one sudo above."""

    def __init__(self, mnt: Path, sudo_resize: Callable[[Path], None]) -> None:
        self.mnt = mnt
        self.sudo_resize = sudo_resize
        self.calls: list[str] = []

    def grow_file(self, image: Path, size: int) -> None:
        self.calls.append("grow_file")
        raise AssertionError("the image is already 1.25 GiB: growing it is not needed")

    def set_capacity(self, loop: str) -> None:
        self.calls.append("set_capacity")
        raise AssertionError("the loop already sees the whole image: losetup is not needed")

    def resize(self, mount: Path) -> None:
        self.calls.append("resize")
        if mount != self.mnt:
            raise SnapshotError(f"refusing to resize {mount}: not this test's mount {self.mnt}")
        self.sudo_resize(mount)  # checks the mount itself, then runs the one sudo


class RoomyHost(SystemProbe):
    """The production readings, except the host's free space (the VM's /tmp is a tmpfs)."""

    def host(self, folder: Path) -> HostSpace:
        return HostSpace(total=100 * GIB, free=50 * GIB)


def test_a_rewind_without_space_grows_the_volume_once_and_the_retry_works(
    small_btrfs_volume: Path, tmp_path: Path, sudo_btrfs_resize: Callable[[Path], None]
) -> None:
    mnt = small_btrfs_volume
    image = mnt.parent / VOLUME_IMAGE
    probe = RoomyHost()
    assert probe.fs_bytes(mnt) == FS_SIZE
    assert probe.file_bytes(image) == IMAGE_SIZE

    (mnt / "vol").mkdir(mode=0o700)
    store = SnapshotStore(mnt / "vol")
    store.init()
    (store.workspace / "a.txt").write_text("v1")
    target = store.take(Reason.PERIODIC)
    (store.workspace / "a.txt").write_text("v2")
    fill_data(store.workspace)
    fill_metadata(store.workspace / "small")
    before = store.snapshots()

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    config = ServiceConfig(
        state_dir=state,
        volume=store.root,
        gateway_token=Secret(TOKEN),
        volume_image=image,
        max_volume_bytes=CEILING,
    )
    steps = VmSteps(mnt, sudo_btrfs_resize)
    box = BlackBox(
        config.blackbox_db,
        create_key(config.blackbox_key),
        checkpoint_path=config.blackbox_checkpoint,
    )
    guardian = Guardian(
        config,
        store=store,
        jail=FakeJail([]),  # type: ignore[arg-type] - stopped, no Docker
        blackbox=box,
        watcher=NullWatcher(),
        alerts=Alerts(),
        grow=VolumeGrower(store.root, GrowLimits(image, CEILING), steps=steps, probe=probe),
    )
    guardian.open_for_rewind()
    try:
        outcome = guardian.rewind(target.id, requested_by="test")
    finally:
        guardian.close_after_rewind()

    events = box.events()
    grows = [e.details for e in events if e.action == "volume_grow"]
    failed = [e.details for e in events if e.action == "rewind_failed"]
    assert [g["phase"] for g in grows] == ["requested", "done"], (grows, failed)
    assert steps.calls == ["resize"]
    assert grows[1]["reached_bytes"] == IMAGE_SIZE <= CEILING
    assert probe.fs_bytes(mnt) == IMAGE_SIZE
    assert outcome.status is RewindStatus.DONE, (outcome, failed)
    assert (store.workspace / "a.txt").read_text() == "v1"
    (done,) = [e for e in events if e.action == "rewind_done"]
    assert done.details["retried"] is True and done.details["grow"] == "done"
    # No snapshot was deleted to make room: the same ones, plus the undo point.
    after = store.snapshots()
    assert set(before) < set(after) and len(after) == len(before) + 1
    assert after[-1].reason == Reason.PRE_RESTORE
    assert box.verify().ok
    box.close()
