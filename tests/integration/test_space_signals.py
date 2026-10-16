"""T04d-1 in the VM: the space signals of vigia.snapshots.space against a real btrfs.

The unit tests (tests/test_snapshot_space.py) feed ``evaluate`` the numbers measured in docs/16.
Here the numbers come from a real 1 GiB volume with simple quotas (``quota_volume``), read
without privileges with the ioctls and /sys, and checked against independent readings:

- DEV_INFO and FS_INFO agree with /sys (the device btrfs uses, what is unallocated);
- the signals move by what the test writes (data and metadata), and with the metadata full
  they say so while the volume still looks usable;
- each condition fires on its real situation: a new volume (P1 depends on the cap, 64 MiB
  passes and 192 MiB does not), data full (P2), a delete after a snapshot (P3, A13), no cap or a
  wrong one (P5) and a signal that cannot be read (P4);
- starting from a volume that passes, the worst the agent can do (A14b: buffered data, a
  delete, then metadata) leaves room for the rewind, which is what P1 is for.

Everything runs as the unprivileged Lima user; the only privileged command is
``quota_volume.set_limit``. The fills reuse the helpers of test_quota_assumptions.py.
"""

import errno
import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from test_quota_assumptions import (
    MIB,
    SMALL_CAP,
    Space,
    capped_subvolume,
    commit,
    create,
    delete_after_snapshot,
    fill_by_preallocating,
    fill_by_writing,
    fill_with_small_files,
    make_subvolume,
    mib,
    preallocate,
    report,
    space,
    try_rewind,
)

from vigia.snapshots import SnapshotError, btrfs
from vigia.snapshots import space as signals
from vigia.snapshots.space import DEFAULT_CONFIG, GIB, HostSpace

pytestmark = pytest.mark.integration

CAP = 64 * MIB  # the cap of the pause tests: P1 is 341 MiB, a new volume has about 494
PLENTY = HostSpace(total=500 * GIB, free=400 * GIB)  # the VM's tmpfs says nothing about P6
REWIND_RESERVE = 13 * MIB  # what the EXCHANGE and the snapshot reserve (docs/16: ~12.75 MiB)
SMALL_FILES = 20_000  # about 45 MiB of metadata
SMALL_FILE = b"x" * 2000  # inline: stored in the metadata tree
FRESH = signals.Health(check_age=0.0)  # a reading taken just now, with the agent running
SMALL_FILE_COST = 3000  # bytes of metadata one 2,000-byte file takes, about


def read(volume, workspace: Path, *, sync: bool = True) -> signals.Sample:
    """One sample of the volume, as the space thread will take it: after a sync, with the
    host disk faked (the VM keeps its tmpfs small and says nothing about P6)."""
    found = signals.sample(volume.mnt, workspace, volume.mnt, sync=sync)
    assert found.errors == (), found.errors
    assert found.space is not None
    return found


def conditions(found: signals.Sample, limit: int = CAP) -> list[str]:
    return [c.code for c in evaluate(found, limit)]


def evaluate(found: signals.Sample, limit: int = CAP) -> list[signals.Condition]:
    """The guardian's entry point on a sample, with the host disk faked and a fresh check."""
    return signals.evaluate_sample(replace(found, host=PLENTY), limit, health=FRESH)


def describe(found: signals.VolumeSpace) -> str:
    return (
        f"unallocated {mib(found.unallocated)}, meta_avail {mib(found.meta_avail)}, "
        f"data_avail {mib(found.data_avail)}"
    )


# The ioctls and /sys agree with each other


def test_dev_info_and_fs_info_agree_with_sysfs(quota_volume) -> None:
    """The size btrfs uses comes from the ioctl; the independent reading is /sys: the size of the
    device file (the whole image on a fresh volume) minus every chunk of every kind."""
    mnt = quota_volume.mnt
    commit(mnt)
    info = signals.fs_info(mnt)
    assert info.fsid == btrfs.fsid(mnt)
    assert (info.num_devices, info.max_id) == (1, 1)
    assert info.nodesize == 16 * 1024
    device = signals.dev_info(mnt, info.max_id)
    independent: Space = space(mnt)
    assert device.total_bytes == independent.device == GIB
    assert device.bytes_used == independent.allocated
    assert device.unallocated == independent.unallocated
    assert signals.volume_space(mnt).unallocated == independent.unallocated


def test_the_ioctls_work_without_privileges_and_refuse_what_is_not_a_btrfs(
    quota_volume, tmp_path: Path
) -> None:
    assert os.geteuid() != 0  # the whole point: no root needed
    signals.fs_info(quota_volume.mnt)
    with pytest.raises(SnapshotError, match="BTRFS_IOC_FS_INFO"):
        signals.fs_info(tmp_path)  # the VM's tmpfs
    with pytest.raises(SnapshotError, match="BTRFS_IOC_DEV_INFO"):
        signals.dev_info(quota_volume.mnt, 99)  # no such device


def test_the_allocation_files_are_what_the_design_reads(quota_volume) -> None:
    """The metadata of the test volume is mirrored (f = 2) and its data is not (f = 1), and
    every file the signals need exists on this kernel."""
    found = signals.volume_space(quota_volume.mnt)
    assert found.metadata.disk_total == 2 * found.metadata.total_bytes
    assert found.data.disk_total == found.data.total_bytes
    assert found.metadata.total_bytes > 0 and found.data.total_bytes > 0
    directory = btrfs.SYSFS_BTRFS / btrfs.fsid(quota_volume.mnt) / "allocation" / "metadata"
    for name in signals._ALLOCATION_FILES:
        assert (directory / name).is_file(), name


# A new volume


def test_a_new_volume_has_room_for_a_64_mib_cap_but_not_for_a_192_mib_one(
    quota_volume, record_property: Callable[[str, object], None]
) -> None:
    """P1 is 341 MiB with a 64 MiB cap and 741 MiB with 192 MiB, and a new 1 GiB volume has
    about 494 MiB of metadata (docs/19): so the pause tests use 64 MiB."""
    small = capped_subvolume(quota_volume, "small", CAP)
    large = capped_subvolume(quota_volume, "large", 192 * MIB)
    found_small, found_large = read(quota_volume, small), read(quota_volume, large)
    assert found_small.space == found_large.space
    now = found_small.space
    assert 300 * MIB < now.meta_avail < 520 * MIB, describe(now)
    minimum_small = signals.metadata_threshold(now, CAP)
    minimum_large = signals.metadata_threshold(now, 192 * MIB)
    report(
        record_property,
        "new_volume_signals",
        f"{describe(now)}; P1 with 64 MiB: {mib(minimum_small)}, with 192 MiB: "
        f"{mib(minimum_large)}",
    )
    assert round(minimum_small / MIB) == 341 and round(minimum_large / MIB) == 741
    assert conditions(found_small, CAP) == []
    assert conditions(found_large, 192 * MIB) == ["P1"]
    # The 1 GiB test volume is under the 1.5 x P1 mark (511 MiB) of the early warning too: it
    # warns, it does not pause.
    assert [w.code for w in signals.early_warnings(now, found_small.usage, CAP)] == ["W1"]


# The signals move by what is written


def test_the_signals_fall_by_what_the_agent_writes(
    quota_volume, record_property: Callable[[str, object], None]
) -> None:
    """32 MiB of preallocated data lowers data_avail by 32 MiB, wherever btrfs puts the chunks;
    thousands of small files lower meta_avail by about the metadata they are charged."""
    workspace = capped_subvolume(quota_volume, "workspace", 512 * MIB)  # never reached
    before = read(quota_volume, workspace)

    preallocate(workspace / "data", 32 * MIB)
    after_data = read(quota_volume, workspace)
    written = after_data.usage.referenced - before.usage.referenced
    fell = before.space.data_avail - after_data.space.data_avail
    assert written >= 32 * MIB
    assert abs(fell - written) < 16 * MIB, (describe(before.space), describe(after_data.space))

    (workspace / "small").mkdir()
    for index in range(SMALL_FILES):
        fd = create(workspace / "small" / f"f{index}")
        try:
            os.write(fd, SMALL_FILE)
        finally:
            os.close(fd)
    after_files = read(quota_volume, workspace)
    charged = after_files.usage.referenced - after_data.usage.referenced
    spent = after_data.space.meta_avail - after_files.space.meta_avail
    report(
        record_property,
        "signals_move_with_writes",
        f"data: wrote {mib(written)}, data_avail fell {mib(fell)}; metadata: {SMALL_FILES} small "
        f"files, charged {mib(charged)}, meta_avail fell {mib(spent)}",
    )
    assert 0.9 * charged < spent < 1.6 * charged


# Data and metadata full


def test_p2_when_the_data_is_used_up(quota_volume) -> None:
    filler = make_subvolume(quota_volume.mnt / "filler")
    workspace = capped_subvolume(quota_volume, "workspace", CAP)
    assert conditions(read(quota_volume, workspace)) == []
    fill_by_preallocating(filler, steps=(64 * MIB,))  # stops with under 64 MiB left to take
    found = read(quota_volume, workspace)
    assert found.space.data_avail < CAP, describe(found.space)
    assert "P2" in conditions(found)


def test_with_metadata_full_the_signals_say_so_while_the_volume_still_looks_usable(
    quota_volume, record_property: Callable[[str, object], None]
) -> None:
    """A10: ENOSPC creating an empty file, and statvfs still reports free space (it counts
    data, not metadata), which is why the signals are read from /sys."""
    workspace = capped_subvolume(quota_volume, "workspace", CAP)
    filler = make_subvolume(quota_volume.mnt / "filler")
    data = fill_by_preallocating(filler)
    small = fill_with_small_files(filler / "small")
    assert (data.errno, small.errno) == (errno.ENOSPC, errno.ENOSPC)
    assert small.call == "create", small  # metadata, not data, ran out
    found = read(quota_volume, workspace)
    statvfs = os.statvfs(quota_volume.mnt)
    report(
        record_property,
        "metadata_full_signals",
        f"{describe(found.space)}; statvfs free {mib(statvfs.f_bavail * statvfs.f_frsize)}",
    )
    assert found.space.meta_avail < 8 * MIB, describe(found.space)
    assert found.space.metadata.free < 8 * MIB and found.space.unallocated < 16 * MIB
    assert conditions(found) == ["P1", "P2"]


# The workspace's own cap: P3 and P5


def test_p3_after_a_delete_following_a_snapshot_and_not_before(quota_volume) -> None:
    """A13: filling to the cap stays under it, a snapshot alone does too, but deleting after a
    snapshot charges more without any check, so referenced ends past the cap."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    fill = fill_with_small_files(workspace / "small")
    assert fill.errno == errno.EDQUOT
    filled = read(quota_volume, workspace)
    assert filled.usage.referenced <= SMALL_CAP
    assert "P3" not in conditions(filled, SMALL_CAP)

    btrfs.snapshot(workspace, mnt / "just-a-snapshot", readonly=True)
    assert "P3" not in conditions(read(quota_volume, workspace), SMALL_CAP)

    pushed = delete_after_snapshot(mnt, workspace, workspace / "small")
    assert pushed.referenced > SMALL_CAP
    found = read(quota_volume, workspace)
    assert "P3" in conditions(found, SMALL_CAP)
    (p3,) = (c for c in evaluate(found, SMALL_CAP) if c.code == "P3")
    assert p3.value > SMALL_CAP == p3.threshold


def test_p5_no_cap_or_another_cap(quota_volume) -> None:
    mnt = quota_volume.mnt
    workspace = make_subvolume(mnt / "workspace")
    assert conditions(read(quota_volume, workspace)) == ["P5"]  # no cap
    quota_volume.set_limit(workspace, 2 * CAP)
    assert conditions(read(quota_volume, workspace)) == ["P5"]  # not the configured one
    quota_volume.set_limit(workspace, CAP)
    assert conditions(read(quota_volume, workspace)) == []
    quota_volume.set_limit(workspace, None)
    assert conditions(read(quota_volume, workspace)) == ["P5"]  # lifted again


def test_a_volume_with_quotas_off_has_no_usage_and_p5(btrfs_volume: Path, tmp_path: Path) -> None:
    """The shared test volume has no quotas: no usage, no error, and the agent would not run."""
    root = btrfs_volume / "no-quotas"
    root.mkdir()
    workspace = make_subvolume(root / "workspace")
    found = signals.sample(root, workspace, tmp_path)
    assert (found.usage, found.errors) == (None, ())
    assert conditions(found) == ["P5"]


# P4: a signal that cannot be read


def test_p4_when_a_signal_cannot_be_read(quota_volume, tmp_path: Path) -> None:
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", CAP)
    # The workspace is gone (not a subvolume root): its quota cannot be read.
    gone = signals.sample(mnt, mnt / "missing", mnt)
    assert gone.usage is None and len(gone.errors) == 1
    assert gone.errors[0].startswith("workspace quota") and "not a subvolume root" in gone.errors[0]
    assert [c.code for c in evaluate(gone)] == ["P4", "P5"]  # no Health to build by hand

    # sysfs is not what the code expects: nothing is read as zero.
    blind = signals.sample(mnt, workspace, mnt, sysfs=tmp_path / "no-sysfs")
    assert blind.space is None and blind.usage is None
    assert [error.split(":")[0] for error in blind.errors] == ["volume space", "workspace quota"]

    # Not a btrfs at all.
    elsewhere = signals.sample(tmp_path, tmp_path / "workspace", tmp_path)
    assert elsewhere.space is None and elsewhere.errors
    assert "P4" in conditions(elsewhere)
    assert "P4" in conditions(blind)


def test_host_space_of_a_real_disk(tmp_path: Path) -> None:
    found = signals.host_space(tmp_path)
    assert 0 < found.free <= found.total
    assert signals.host_threshold(found) >= DEFAULT_CONFIG.host_min_free


# What P1 is for


def spend_the_worst(volume, workspace: Path, cap: int) -> dict:
    """The worst the agent can do to the metadata in the few seconds before it is frozen
    (docs/19, P1): buffered writes up to the cap reserve far more data chunks than the data
    needs (A14b), a delete empties them but they take ~10 s to come back, a round of "snapshot
    and delete" charges more metadata without any check (A13), and the agent spends what is left
    of its cap on metadata. Returns the readings around it and how the rewind went."""
    (workspace / "data").mkdir()
    data = fill_by_writing(workspace / "data")
    assert data.errno == errno.EDQUOT
    held = read(volume, workspace)
    for path in (workspace / "data").iterdir():
        path.unlink()
    window = read(volume, workspace)  # the chunks are empty but still held

    (workspace / "round").mkdir()
    files = max(1000, cap // 4 // SMALL_FILE_COST)  # enough leaves for the round, a quarter cap
    for index in range(files):
        fd = create(workspace / "round" / f"f{index}")
        try:
            os.write(fd, SMALL_FILE)
        finally:
            os.close(fd)
    # A13: a snapshot, then one delete per leaf (each copies a leaf the snapshot shares and is
    # charged without any check).
    btrfs.snapshot(workspace, volume.mnt / "round-snapshot", readonly=True)
    for index in range(0, 7 * 64, 7):
        (workspace / "round" / f"f{index}").unlink()
    after_round = read(volume, workspace)

    metadata = fill_with_small_files(workspace / "small")
    assert metadata.errno == errno.EDQUOT
    worst = read(volume, workspace)
    rewind = try_rewind(volume, workspace, cap)
    return {
        "held": held,
        "window": window,
        "after_round": after_round,
        "worst": worst,
        "rewind": rewind,
        "chunks_held": window.space.unallocated,
        "metadata": metadata,
        "data": data,
    }


def consume_metadata_down_to(volume, workspace: Path, target: int) -> signals.Sample:
    """Fill a sibling subvolume with small files until meta_avail is just above ``target``."""
    filler = make_subvolume(volume.mnt / "filler")
    count = 0
    while True:
        found = read(volume, workspace)
        excess = found.space.meta_avail - target
        if excess < 4 * MIB:
            return found
        for _ in range(min(5000, max(100, (excess - 3 * MIB) // SMALL_FILE_COST))):
            fd = create(filler / f"f{count}")
            count += 1
            try:
                os.write(fd, SMALL_FILE)
            finally:
                os.close(fd)


@pytest.mark.parametrize("tight", [False, True], ids=["new-volume", "just-above-P1"])
@pytest.mark.parametrize("cap", [16 * MIB, CAP], ids=mib)
def test_the_worst_the_agent_does_stays_inside_what_p1_leaves_and_the_rewind_works(
    quota_volume, cap: int, tight: bool, record_property: Callable[[str, object], None]
) -> None:
    """P1 - R is the metadata the agent may spend before it is frozen. Measured here, with caps
    of 16 MiB (a data chunk is 7 times the cap, so what dominates is the number of chunks that
    buffered writes reserve) and 64 MiB: the real spend never exceeds P1 - R, and starting
    just above P1 (the tight case, metadata pre-consumed from a sibling subvolume) the volume
    ends with more than R and the rewind still works."""
    workspace = capped_subvolume(quota_volume, "workspace", cap)
    start = read(quota_volume, workspace)
    minimum = signals.metadata_threshold(start.space, cap)
    if tight:
        start = consume_metadata_down_to(quota_volume, workspace, minimum + 6 * MIB)
        assert start.space.meta_avail - minimum < 10 * MIB, describe(start.space)
    assert conditions(start, cap) == [], describe(start.space)
    budget = minimum - DEFAULT_CONFIG.reserve

    result = spend_the_worst(quota_volume, workspace, cap)
    worst, window = result["worst"], result["window"]
    lowest = min(r.space.meta_avail for r in (window, result["after_round"], worst))
    spend = start.space.meta_avail - lowest
    chunks = (start.space.unallocated - window.space.unallocated) / MIB
    report(
        record_property,
        f"worst_case_{cap // MIB}_{'tight' if tight else 'new'}",
        f"cap {mib(cap)}: P1 {mib(minimum)}, budget P1-R {mib(budget)}; start "
        f"{describe(start.space)}; buffered data {mib(result['data'].amount)} held "
        f"{chunks:.0f} MiB of raw chunks beyond the data; held: {describe(result['held'].space)}"
        f"; window: {describe(window.space)}; after the round: "
        f"{describe(result['after_round'].space)} (referenced "
        f"{mib(result['after_round'].usage.referenced)}); metadata filled "
        f"{result['metadata'].amount} files: {describe(worst.space)}; spend {mib(spend)} of "
        f"{mib(budget)}; rewind: {result['rewind']}",
    )
    assert window.space.unallocated < start.space.unallocated  # the signal sees the held chunks
    assert spend <= budget, f"spent {mib(spend)} of a budget of {mib(budget)}"
    assert worst.space.meta_avail >= DEFAULT_CONFIG.reserve
    assert result["rewind"] == "ok"
    if cap == 16 * MIB:
        # Why the over-reservation is budgeted in chunks: the burst as 3.4 L (R + C + 3.4 L)
        # would have been 110 MiB here, less than the 128 MiB that really went.
        old_budget = 56 * MIB + 16 * MIB * 34 // 10
        assert spend > old_budget, f"spent {mib(spend)}, old budget {mib(old_budget)}"
