"""T04e-1 in the VM: a small volume full of metadata, a rewind that fails for lack of space, the
volume grown once and within its limit, and the retry that works. docs/19, section 6, and the
criterion "Crecimiento de emergencia" of T04 in docs/backlog.md.

SKIPPED until the founder approves its one new sudo (docs/19, "Bloqueado por el founder"):

    sudo -n btrfs filesystem resize max <mount point of this test's own btrfs>

run only after ``_require_test_mount`` (the check ``_unmount`` makes before its sudo: a
canonical path under pytest-of-*, the btrfs loop mount of the image next to it). Set
``VIGIA_IT_GROW_SUDO=1`` to run it; ``make it`` does not pass the Mac's environment into the
VM, so from ``make vm-shell``: ``VIGIA_IT_GROW_SUDO=1 UV_PROJECT_ENVIRONMENT=$HOME/.venvs/vigia
uv run --locked pytest -m integration tests/integration/test_grow.py``.

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

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.integration.conftest import (
    COMMAND_TIMEOUT,
    VOLUME_IMAGE,
    _mounted_btrfs,
    _require_test_mount,
)
from tests.integration.test_snapshots import fill_data, fill_metadata
from tests.test_service_guardian import TOKEN, Alerts, FakeJail
from vigia.blackbox import BlackBox, create_key
from vigia.service.config import Secret, ServiceConfig
from vigia.service.guardian import Guardian
from vigia.service.offline import NullWatcher
from vigia.service.rewind import RewindStatus
from vigia.snapshots import Reason, SnapshotError, SnapshotStore
from vigia.snapshots.grow import GrowLimits, SystemProbe, VolumeGrower, resize_argv
from vigia.snapshots.space import GIB, MIB, HostSpace

SUDO_ENV = "VIGIA_IT_GROW_SUDO"
IMAGE_SIZE = GIB + 256 * MIB  # measured: the loop sees 1,280 MiB and btrfs uses 1,024
FS_SIZE = GIB
CEILING = 3 * GIB // 2

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get(SUDO_ENV) != "1",
        reason=(
            "needs one sudo the founder has not approved yet: `sudo -n btrfs filesystem resize "
            f"max <test mount>` (docs/19, 'Bloqueado por el founder'); set {SUDO_ENV}=1 once "
            "it is"
        ),
    ),
]


class VmSteps:
    """The privileged steps of this test: the file is the test user's, the loop step must not
    be needed, and the resize is the one sudo above."""

    def __init__(self, mnt: Path) -> None:
        self.mnt = mnt
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
        _require_test_mount(mount)
        argv = ["sudo", "-n", *resize_argv(mount)]
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False
        )
        if result.returncode != 0:
            raise SnapshotError(f"{argv} failed: {result.stderr.strip()}")


class RoomyHost(SystemProbe):
    """The production readings, except the host's free space (the VM's /tmp is a tmpfs)."""

    def host(self, folder: Path) -> HostSpace:
        return HostSpace(total=100 * GIB, free=50 * GIB)


@pytest.fixture
def small_volume(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    base = tmp_path_factory.mktemp("grow-btrfs").resolve()
    with _mounted_btrfs(base, IMAGE_SIZE, fs_size=FS_SIZE) as mnt:
        yield mnt
    (base / VOLUME_IMAGE).unlink()  # only reached after a checked, successful unmount


def test_a_rewind_without_space_grows_the_volume_once_and_the_retry_works(
    small_volume: Path, tmp_path: Path
) -> None:
    mnt = small_volume
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
    steps = VmSteps(mnt)
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
