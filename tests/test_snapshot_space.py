"""Unit tests for vigia/snapshots/space.py: the space signals and the pause conditions P1-P7.

``evaluate`` is pure, so the table tests feed it the numbers measured in the VM (docs/16 and
docs/19): a new 1 GiB volume, the metadata full, the buffered-write trap of A14b, a workspace
past its cap after "snapshot and delete" (A13). The reading side runs on a fake sysfs tree and
fake ioctl results; the real thing is tests/integration/test_space_signals.py."""

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from vigia.snapshots import btrfs, space
from vigia.snapshots.model import SnapshotError
from vigia.snapshots.space import (
    DEFAULT_CONFIG,
    GIB,
    MIB,
    Allocation,
    Health,
    HostSpace,
    SpaceConfig,
    VolumeSpace,
    chunk_estimate,
    early_warnings,
    evaluate_sample,
    host_threshold,
    metadata_threshold,
)
from vigia.snapshots.space import evaluate as raw_evaluate

FSID = "8c9bd68d-0b2f-4d38-a2e2-6c2d3a5f1b77"
PLENTY = HostSpace(total=500 * GIB, free=400 * GIB)


def metadata(free: int, *, total: int = 64 * MIB, used: int | None = None) -> Allocation:
    """Mirrored (DUP) metadata chunks of ``total`` bytes with ``free`` bytes left inside."""
    return Allocation(total, 2 * total, total - free if used is None else used)


def data(free: int, *, total: int = 8 * MIB) -> Allocation:
    return Allocation(total, total, total - free)  # single profile: disk_total == total_bytes


def volume(
    *, device: int = GIB, unallocated: int, meta_free: int, data_free: int = 0
) -> VolumeSpace:
    return VolumeSpace(
        device_total=device,
        unallocated=unallocated,
        data=data(data_free),
        metadata=metadata(meta_free),
    )


# A new 1 GiB volume: the design's figure is 494 MiB of metadata (docs/19, section 5).
NEW_VOLUME = volume(unallocated=874 * MIB, meta_free=57 * MIB, data_free=6 * MIB)


def capped(referenced: int, limit: int) -> btrfs.QgroupUsage:
    return btrfs.QgroupUsage(
        referenced=referenced,
        exclusive=referenced,
        limit_flags=btrfs.QGROUP_LIMIT_MAX_RFER,
        max_referenced=limit,
        max_exclusive=0,
    )


# A reading the space thread just took: the agent runs and the last check is now. A bare Health()
# has no check yet, which is P4 (see test_p4_the_space_thread_is_late).
FRESH = Health(check_age=0.0)


def evaluate(
    found_volume: VolumeSpace | None,
    usage: btrfs.QgroupUsage | None,
    limit: int,
    host: HostSpace | None,
    cfg: space.SpaceConfig = DEFAULT_CONFIG,
    health: Health = FRESH,
) -> list[space.Condition]:
    return raw_evaluate(found_volume, usage, limit, host, cfg, health)


def codes(found: list[space.Condition]) -> list[str]:
    return [condition.code for condition in found]


def check(
    found_volume: VolumeSpace | None,
    usage: btrfs.QgroupUsage | None,
    limit: int,
    host: HostSpace | None = PLENTY,
    health: Health = FRESH,
) -> list[str]:
    return codes(evaluate(found_volume, usage, limit, host, DEFAULT_CONFIG, health))


# The formulas


def test_free_room_in_the_chunks_subtracts_everything_spoken_for() -> None:
    allocation = Allocation(
        total_bytes=100 * MIB,
        disk_total=200 * MIB,
        bytes_used=10 * MIB,
        bytes_reserved=1 * MIB,
        bytes_pinned=2 * MIB,
        bytes_may_use=3 * MIB,
        bytes_readonly=4 * MIB,
        bytes_zone_unusable=5 * MIB,
    )
    assert allocation.free == 75 * MIB
    assert replace(allocation, bytes_may_use=500 * MIB).free == 0  # never negative


@pytest.mark.parametrize(
    ("allocation", "unallocated", "extra"),
    [
        (metadata(10 * MIB), 100 * MIB, 50 * MIB),  # mirrored: f = 2
        (data(10 * MIB), 100 * MIB, 100 * MIB),  # single: f = 1
        (Allocation(0, 0, 0), 100 * MIB, 50 * MIB),  # no chunk yet: assume mirrored
        (metadata(0), 0, 0),
    ],
)
def test_unallocated_space_counts_divided_by_the_measured_factor(
    allocation: Allocation, unallocated: int, extra: int
) -> None:
    assert allocation.from_unallocated(unallocated) == extra
    assert allocation.available(unallocated) == allocation.free + extra


def test_meta_avail_and_data_avail() -> None:
    found = volume(unallocated=100 * MIB, meta_free=20 * MIB, data_free=7 * MIB)
    assert found.meta_avail == 20 * MIB + 50 * MIB
    assert found.data_avail == 7 * MIB + 100 * MIB


def test_the_new_volume_has_the_designs_494_mib_of_metadata() -> None:
    assert NEW_VOLUME.meta_avail == 494 * MIB


@pytest.mark.parametrize(
    ("device", "expected"),
    [
        (GIB, 112 * MIB),  # measured: 112 MiB chunks on 1 GiB
        (20 * GIB, GIB),  # 10 % would be 2 GiB: capped at 1 GiB
        (10 * GIB, GIB),
        (160 * MIB, 16 * MIB),
        (2 * GIB, 208 * MIB),
    ],
)
def test_chunk_estimate(device: int, expected: int) -> None:
    assert chunk_estimate(device) == expected


def test_p1_for_the_test_volume_with_a_64_mib_cap_is_341_mib() -> None:
    """R + C + max(1.2 L, 2 C) + 2.2 L with C = 56 MiB: at 64 MiB the two over-reserved chunks
    (112 MiB, measured: 64 MiB of buffered data reserved two 112 MiB chunks) beat 1.2 L."""
    minimum = metadata_threshold(NEW_VOLUME, 64 * MIB)
    assert minimum == 32 * MIB + 56 * MIB + 112 * MIB + 64 * MIB * 22 // 10
    assert round(minimum / MIB) == 341


def test_p1_for_the_test_volume_with_a_192_mib_cap_is_741_mib() -> None:
    """Here 1.2 L (230 MiB) beats the two chunks, so it is the old R + C + 3.4 L."""
    minimum = metadata_threshold(NEW_VOLUME, 192 * MIB)
    assert minimum == 32 * MIB + 56 * MIB + 192 * MIB * 34 // 10
    assert round(minimum / MIB) == 741


def test_p1_with_a_small_cap_is_dominated_by_the_chunks_not_by_the_cap() -> None:
    """16 MiB on the 1 GiB volume: the chunk is 7 times the cap, and the over-reservation is a
    number of chunks, so P1 does not shrink with L (docs/19: lowering L needs re-validating P1)."""
    minimum = metadata_threshold(NEW_VOLUME, 16 * MIB)
    assert minimum == 32 * MIB + 56 * MIB + 112 * MIB + 16 * MIB * 22 // 10
    assert round(minimum / MIB) == 235
    old_formula = 32 * MIB + 56 * MIB + 16 * MIB * 34 // 10
    assert minimum > 1.5 * old_formula  # the burst-as-a-multiple-of-L formula missed this


def test_the_over_reservation_term_switches_at_two_chunks_of_cap() -> None:
    chunk = 56 * MIB  # C on the 1 GiB volume
    below = metadata_threshold(NEW_VOLUME, 90 * MIB)  # 1.2 L = 108 < 2 C = 112
    above = metadata_threshold(NEW_VOLUME, 100 * MIB)  # 1.2 L = 120 > 112
    assert below == 32 * MIB + chunk + 2 * chunk + 90 * MIB * 22 // 10
    assert above == 32 * MIB + chunk + 120 * MIB + 100 * MIB * 22 // 10


def test_p1_for_a_production_sized_volume_is_about_a_fifth_of_it() -> None:
    """V = 20 GiB, L = 1 GiB (5 % of V): about 3.9 GiB, 20 % of V (1.2 L beats the two chunks
    of 512 MiB, so as before). Unvalidated until T13; lowering L requires re-validating P1."""
    production = volume(device=20 * GIB, unallocated=19 * GIB, meta_free=0)
    minimum = metadata_threshold(production, GIB)
    assert abs(minimum - (32 * MIB + 512 * MIB + GIB * 34 // 10)) <= 2  # integer rounding
    assert 3.9 * GIB < minimum < 4.0 * GIB
    assert round(100 * minimum / (20 * GIB)) == 20
    # A smaller cap does not make P1 proportionally smaller: the chunks stay.
    smaller = metadata_threshold(production, GIB // 10)
    assert smaller == 32 * MIB + 512 * MIB + 2 * 512 * MIB + (GIB // 10) * 22 // 10
    assert smaller > 0.3 * minimum


def test_the_terms_come_from_the_config() -> None:
    cfg = SpaceConfig(
        reserve=0, cap_tenths=10, overreserve_tenths=10, overreserve_chunks=2, max_chunk=16 * MIB
    )
    # C = 8 MiB (16 MiB chunk, mirrored metadata): 8 + max(100, 16) + 100
    assert metadata_threshold(NEW_VOLUME, 100 * MIB, cfg) == 208 * MIB
    assert (
        metadata_threshold(NEW_VOLUME, MIB, replace(cfg, overreserve_chunks=5))
        == 8 * MIB + 40 * MIB + MIB
    )


def test_host_threshold_is_the_larger_of_1_gib_and_5_percent() -> None:
    assert host_threshold(HostSpace(10 * GIB, 0)) == GIB
    assert host_threshold(HostSpace(100 * GIB, 0)) == 5 * GIB
    assert host_threshold(HostSpace(20 * GIB, 0)) == GIB  # exactly 5 % == 1 GiB


# evaluate: the measured situations


def test_a_new_volume_does_not_pause_with_a_64_mib_cap() -> None:
    assert check(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB) == []


def test_a_new_volume_pauses_with_a_192_mib_cap_so_the_tests_use_64() -> None:
    """P1 (741 MiB) is above the 494 MiB of a new volume: TEST_CAP cannot be used for the pause
    tests (docs/19)."""
    found = evaluate(NEW_VOLUME, capped(0, 192 * MIB), 192 * MIB, PLENTY)
    assert codes(found) == ["P1"]
    assert found[0].value == 494 * MIB
    assert round(found[0].threshold / MIB) == 741
    assert "metadata" in found[0].message and "494.0 MiB" in found[0].message


def test_metadata_full_pauses_p1() -> None:
    """A10: ENOSPC creating an empty file, 1 MiB unallocated, 4.23 MiB left in the chunks."""
    full = volume(unallocated=MIB, meta_free=int(3.73 * MIB), data_free=100 * MIB)
    found = evaluate(full, capped(0, 64 * MIB), 64 * MIB, PLENTY)
    assert codes(found) == ["P1"]
    assert found[0].value == MIB // 2 + int(3.73 * MIB)
    assert found[0].reason == "space"


@pytest.mark.parametrize("cap", [192 * MIB, 64 * MIB])
def test_the_buffered_write_trap_of_a14b_pauses_p1(cap: int) -> None:
    """A14b: after buffered writes and a delete, 13 MiB unallocated and 76 MiB free in the
    metadata chunks, and the agent is about to fill metadata."""
    trap = volume(unallocated=13 * MIB, meta_free=76 * MIB, data_free=200 * MIB)
    assert "P1" in check(trap, capped(0, cap), cap)


def test_a_second_round_of_writes_in_the_same_transaction_cannot_happen() -> None:
    """Two rounds of "snapshot and delete" fit in one transaction (A13: 1.92 L, then 2.81 L)
    only if no check comes between them. Each snapshot is preceded by a sync and P3, so the
    first round already pauses: P1 only has to cover one."""
    limit = 64 * MIB
    after_one_round = capped(int(1.92 * limit), limit)
    assert "P3" in check(NEW_VOLUME, after_one_round, limit)
    after_two = capped(int(2.81 * limit), limit)
    assert "P3" in check(NEW_VOLUME, after_two, limit)


def test_p2_data_below_the_cap() -> None:
    low = volume(unallocated=40 * MIB, meta_free=400 * MIB, data_free=10 * MIB)
    found = evaluate(low, capped(0, 64 * MIB), 64 * MIB, PLENTY)
    assert codes(found) == ["P2"]
    assert (found[0].value, found[0].threshold) == (50 * MIB, 64 * MIB)


def test_p2_is_strict_data_exactly_at_the_cap_passes() -> None:
    edge = volume(unallocated=54 * MIB, meta_free=400 * MIB, data_free=10 * MIB)
    assert edge.data_avail == 64 * MIB
    assert check(edge, capped(0, 64 * MIB), 64 * MIB) == []
    assert "P2" in check(replace(edge, unallocated=54 * MIB - 1), capped(0, 64 * MIB), 64 * MIB)


@pytest.mark.parametrize(
    ("referenced", "paused"),
    [(0, False), (64 * MIB, False), (64 * MIB + 1, True), (int(1.92 * 64 * MIB), True)],
)
def test_p3_referenced_over_the_cap(referenced: int, paused: bool) -> None:
    found = check(NEW_VOLUME, capped(referenced, 64 * MIB), 64 * MIB)
    assert found == (["P3"] if paused else [])


def test_p3_says_how_much_over() -> None:
    (found,) = evaluate(NEW_VOLUME, capped(100 * MIB, 64 * MIB), 64 * MIB, PLENTY)
    assert (found.code, found.kind) == ("P3", "usage")
    assert (found.value, found.threshold) == (100 * MIB, 64 * MIB)
    assert "100.0 MiB" in found.message and "64.0 MiB" in found.message


def test_p5_no_cap_at_all() -> None:
    uncapped = btrfs.QgroupUsage(5 * MIB, 5 * MIB, 0x500000, 8 * MIB, 123)  # mkfs garbage bits
    assert check(NEW_VOLUME, uncapped, 64 * MIB) == ["P5"]


def test_p5_a_cap_that_is_not_the_configured_one() -> None:
    (found,) = evaluate(NEW_VOLUME, capped(0, 192 * MIB), 64 * MIB, PLENTY)
    assert found.code == "P5" and (found.value, found.threshold) == (192 * MIB, 64 * MIB)
    assert "192.0 MiB" in found.message


def test_p5_only_an_exclusive_cap_is_not_the_referenced_cap() -> None:
    exclusive_only = btrfs.QgroupUsage(0, 0, btrfs.QGROUP_LIMIT_MAX_EXCL, 0, 64 * MIB)
    assert check(NEW_VOLUME, exclusive_only, 64 * MIB) == ["P5"]


def test_p5_a_volume_without_quotas() -> None:
    found = evaluate(NEW_VOLUME, None, 64 * MIB, PLENTY)
    assert codes(found) == ["P5"] and "no cap" in found[0].message


def test_p6_the_host_disk() -> None:
    limit = 64 * MIB
    host = HostSpace(100 * GIB, 5 * GIB)
    assert check(NEW_VOLUME, capped(0, limit), limit, host) == []
    low = HostSpace(100 * GIB, 5 * GIB - 1)
    found = evaluate(NEW_VOLUME, capped(0, limit), limit, low)
    assert codes(found) == ["P6"] and found[0].threshold == 5 * GIB
    small = HostSpace(10 * GIB, GIB - 1)  # 5 % of 10 GiB is under the 1 GiB floor
    assert check(NEW_VOLUME, capped(0, limit), limit, small) == ["P6"]


def test_p4_a_signal_that_cannot_be_read() -> None:
    health = replace(
        FRESH, read_errors=("volume space: cannot read /sys/fs/btrfs/x/allocation/data",)
    )
    (found,) = evaluate(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB, PLENTY, health=health)
    assert (found.code, found.kind) == ("P4", "blind")
    assert "allocation/data" in found.message


@pytest.mark.parametrize(
    ("found_volume", "host"), [(None, PLENTY), (NEW_VOLUME, None), (None, None)]
)
def test_p4_missing_signals_without_a_reason_are_still_blind(
    found_volume: VolumeSpace | None, host: HostSpace | None
) -> None:
    found = evaluate(found_volume, capped(0, 64 * MIB), 64 * MIB, host)
    assert codes(found) == ["P4"]


@pytest.mark.parametrize(
    ("age", "running", "paused"),
    [
        (None, True, True),  # no check yet: fail closed
        (-0.1, True, True),  # the clock went backwards
        (-1.0, False, False),
        (None, False, False),
        (0.0, True, False),
        (0.5, True, False),
        (3.0, True, False),  # "more than 3 s"
        (3.01, True, True),
        (60.0, True, True),
        (60.0, False, False),  # a stopped agent cannot run code: a late check is harmless
    ],
)
def test_p4_the_space_thread_is_late(age: float | None, running: bool, paused: bool) -> None:
    health = Health(check_age=age, agent_running=running)
    found = evaluate(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB, PLENTY, health=health)
    assert codes(found) == (["P4"] if paused else [])


def test_p4_says_why_the_check_is_missing_late_or_negative() -> None:
    def message(age: float | None) -> str:
        health = Health(check_age=age)
        (found,) = evaluate(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB, PLENTY, health=health)
        return found.message

    assert "no space check yet" in message(None)
    assert "negative" in message(-2.0)
    assert "9.0 s" in message(9.0)


def test_a_bare_health_is_a_running_agent_nobody_has_checked() -> None:
    """The default fails closed: the caller must say the check is fresh."""
    assert codes(raw_evaluate(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB, PLENTY)) == ["P4"]
    assert (
        codes(raw_evaluate(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB, PLENTY, health=FRESH)) == []
    )


@pytest.mark.parametrize(
    ("failures", "seconds", "paused"),
    [(0, 0.0, False), (2, 60.0, False), (3, 10.0, False), (3, 10.1, True), (50, 600.0, True)],
)
def test_p7_the_black_box_cannot_append(failures: int, seconds: float, paused: bool) -> None:
    health = replace(FRESH, blackbox_failures=failures, blackbox_failing_for=seconds)
    found = evaluate(NEW_VOLUME, capped(0, 64 * MIB), 64 * MIB, PLENTY, health=health)
    assert codes(found) == (["P7"] if paused else [])
    if paused:
        assert found[0].reason == "blackbox" and found[0].value is None


def test_every_condition_is_reported_in_order() -> None:
    bad = volume(unallocated=0, meta_free=0, data_free=0)
    health = Health(
        read_errors=("x",), check_age=9.0, blackbox_failures=3, blackbox_failing_for=11.0
    )
    uncapped = btrfs.QgroupUsage(0, 0, 0, 0, 0)
    host = HostSpace(100 * GIB, 0)
    found = evaluate(bad, uncapped, 64 * MIB, host, health=health)
    assert codes(found) == ["P1", "P2", "P4", "P5", "P6", "P7"]
    over = evaluate(bad, capped(2 * 64 * MIB, 64 * MIB), 64 * MIB, host, health=health)
    assert codes(over) == ["P1", "P2", "P3", "P4", "P6", "P7"]
    assert [c.reason for c in over] == ["space"] * 5 + ["blackbox"]


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, None])
def test_the_limit_must_be_a_positive_number_of_bytes(limit: object) -> None:
    with pytest.raises(ValueError, match="limit"):
        evaluate(NEW_VOLUME, capped(0, 64 * MIB), limit, PLENTY)  # type: ignore[arg-type]


def test_the_cap_and_the_volume_decide_which_cap_the_new_volume_survives() -> None:
    """64 MiB against 192 MiB on the same 1 GiB volume: the thresholds scale with the cap."""
    for cap in (32 * MIB, 64 * MIB, 96 * MIB):  # 88 MiB + 3.4 L stays under the 494 MiB
        assert check(NEW_VOLUME, capped(0, cap), cap) == [], cap
    for cap in (128 * MIB, 160 * MIB, 192 * MIB, 256 * MIB):
        assert check(NEW_VOLUME, capped(0, cap), cap) == ["P1"], cap


# Early warnings


def test_early_warning_on_usage_over_80_percent() -> None:
    limit = 100 * MIB
    roomy = volume(device=20 * GIB, unallocated=19 * GIB, meta_free=57 * MIB)
    assert early_warnings(roomy, capped(80 * MIB, limit), limit) == []
    (found,) = early_warnings(roomy, capped(80 * MIB + 1, limit), limit)
    assert (found.code, found.kind) == ("W3", "usage")


def test_early_warning_on_metadata_under_one_and_a_half_times_p1() -> None:
    limit = 64 * MIB
    minimum = metadata_threshold(NEW_VOLUME, limit)
    just_over = volume(unallocated=2 * (minimum * 3 // 2), meta_free=0)
    assert early_warnings(just_over, capped(0, limit), limit) == []
    near = volume(unallocated=2 * (minimum * 3 // 2) - 2 * MIB, meta_free=0)
    (found,) = early_warnings(near, capped(0, limit), limit)
    assert (found.code, found.kind) == ("W1", "metadata")
    assert evaluate(near, capped(0, limit), limit, PLENTY) == []  # a warning is not a pause


def test_early_warnings_with_nothing_to_read() -> None:
    assert early_warnings(None, None, 64 * MIB) == []


# Reading: ioctl results


def test_parse_fs_info() -> None:
    buffer = bytearray(1024)
    struct.pack_into("<QQ", buffer, 0, 1, 1)
    buffer[16:32] = bytes.fromhex(FSID.replace("-", ""))
    struct.pack_into("<I", buffer, 32, 16384)
    assert space.parse_fs_info(bytes(buffer)) == space.FsInfo(FSID, 1, 1, 16384)
    with pytest.raises(SnapshotError, match="returned 10 bytes"):
        space.parse_fs_info(b"x" * 10)


def test_parse_dev_info() -> None:
    buffer = bytearray(4096)
    struct.pack_into("<Q16sQQ", buffer, 0, 1, b"u" * 16, 150 * MIB, GIB)
    found = space.parse_dev_info(bytes(buffer))
    assert found == space.DevInfo(devid=1, total_bytes=GIB, bytes_used=150 * MIB)
    assert found.unallocated == GIB - 150 * MIB
    assert space.DevInfo(1, 100, 150).unallocated == 0  # never negative
    with pytest.raises(SnapshotError, match="returned 100 bytes"):
        space.parse_dev_info(b"x" * 100)


def test_the_ioctl_numbers_are_the_kernels() -> None:
    assert space.BTRFS_IOC_DEV_INFO == 0xD000941E  # _IOWR(0x94, 30, 4096 bytes)
    assert btrfs.BTRFS_IOC_FS_INFO == 0x8400941F  # _IOR(0x94, 31, 1024 bytes)


# Reading: sysfs


def write_allocation(sysfs: Path, kind: str, values: dict[str, int | str]) -> None:
    directory = sysfs / FSID / "allocation" / kind
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in values.items():
        (directory / name).write_text(f"{value}\n")


def allocation_values(allocation: Allocation) -> dict[str, int | str]:
    return {
        "total_bytes": allocation.total_bytes,
        "disk_total": allocation.disk_total,
        "bytes_used": allocation.bytes_used,
        "bytes_reserved": allocation.bytes_reserved,
        "bytes_pinned": allocation.bytes_pinned,
        "bytes_may_use": allocation.bytes_may_use,
        "bytes_readonly": allocation.bytes_readonly,
        "bytes_zone_unusable": allocation.bytes_zone_unusable,
    }


@pytest.fixture
def sysfs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake /sys/fs/btrfs with the NEW_VOLUME's numbers, and the ioctls answering for it."""
    root = tmp_path / "sys"
    write_allocation(root, "data", allocation_values(NEW_VOLUME.data))
    write_allocation(root, "metadata", allocation_values(NEW_VOLUME.metadata))
    monkeypatch.setattr(space, "fs_info", lambda path: space.FsInfo(FSID, 1, 1, 16384))
    monkeypatch.setattr(
        space,
        "dev_info",
        lambda path, devid: space.DevInfo(devid, GIB, GIB - NEW_VOLUME.unallocated),
    )
    return root


def test_volume_space_reads_the_device_and_the_allocation(sysfs: Path, tmp_path: Path) -> None:
    assert space.volume_space(tmp_path, sysfs=sysfs) == NEW_VOLUME


def test_volume_space_asks_for_the_device_that_fs_info_names(
    sysfs: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = []

    def dev_info(path: Path, devid: int) -> space.DevInfo:
        asked.append((path, devid))
        return space.DevInfo(devid, GIB, 0)

    monkeypatch.setattr(space, "fs_info", lambda path: space.FsInfo(FSID, 1, 7, 16384))
    monkeypatch.setattr(space, "dev_info", dev_info)
    space.volume_space(tmp_path, sysfs=sysfs)
    assert asked == [(tmp_path, 7)]


def test_volume_space_refuses_more_than_one_device(
    sysfs: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(space, "fs_info", lambda path: space.FsInfo(FSID, 2, 2, 16384))
    with pytest.raises(SnapshotError, match="2 devices"):
        space.volume_space(tmp_path, sysfs=sysfs)


@pytest.mark.parametrize("name", space._ALLOCATION_FILES)
def test_a_missing_allocation_file_is_an_error_not_a_zero(
    sysfs: Path, tmp_path: Path, name: str
) -> None:
    (sysfs / FSID / "allocation" / "metadata" / name).unlink()
    with pytest.raises(SnapshotError, match=f"cannot read.*{name}"):
        space.volume_space(tmp_path, sysfs=sysfs)


@pytest.mark.parametrize("content", ["", "\n", "abc\n", "-1\n", "1.5\n", "007\n", f"{2**64}\n"])
def test_garbage_in_an_allocation_file_is_an_error(
    sysfs: Path, tmp_path: Path, content: str
) -> None:
    (sysfs / FSID / "allocation" / "data" / "bytes_pinned").write_text(content)
    with pytest.raises(SnapshotError, match="unexpected content"):
        space.volume_space(tmp_path, sysfs=sysfs)


def test_a_missing_filesystem_directory_is_an_error(sysfs: Path, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere"
    other.mkdir()
    with pytest.raises(SnapshotError, match="cannot read"):
        space.volume_space(tmp_path, sysfs=other)


def test_the_ioctl_helper_refuses_a_symlink_and_reports_failures(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(SnapshotError, match="cannot open"):
        space.fs_info(link)
    with pytest.raises(SnapshotError, match="cannot open"):
        space.dev_info(tmp_path / "missing", 1)
    # Not a btrfs (or not Linux): the ioctl itself fails, as a SnapshotError.
    with pytest.raises(SnapshotError, match="BTRFS_IOC_FS_INFO"):
        space.fs_info(target)


def test_dev_info_checks_the_answer_is_for_the_device_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def answer(path: Path, request: int, buffer: bytearray, name: str) -> None:
        struct.pack_into("<Q16sQQ", buffer, 0, 9, b"u" * 16, 0, GIB)

    monkeypatch.setattr(space, "_ioctl", answer)
    with pytest.raises(SnapshotError, match="answered for device 9"):
        space.dev_info(tmp_path, 1)


def test_host_space_is_what_an_unprivileged_writer_can_use(tmp_path: Path) -> None:
    found = space.host_space(tmp_path)
    assert 0 < found.free <= found.total
    with pytest.raises(SnapshotError, match="cannot read the free space"):
        space.host_space(tmp_path / "missing")


# sample: failures become P4, never exceptions


def fake_world(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> list[str]:
    """volume_space, host_space, quota_mode, qgroup_usage and the sync, all answering with
    healthy values unless ``overrides`` replaces one with an exception or a value."""
    calls: list[str] = []

    def answer(name: str, value: object):
        def fake(*args: object, **kwargs: object) -> object:
            calls.append(name)
            if isinstance(overrides.get(name), Exception):
                raise overrides[name]  # type: ignore[misc]
            return overrides.get(name, value)

        return fake

    monkeypatch.setattr(space, "volume_space", answer("space", NEW_VOLUME))
    monkeypatch.setattr(space, "host_space", answer("host", PLENTY))
    monkeypatch.setattr(btrfs, "quota_mode", answer("mode", "squota"))
    monkeypatch.setattr(btrfs, "qgroup_usage", answer("usage", capped(MIB, 64 * MIB)))
    monkeypatch.setattr(btrfs, "run", answer("sync", ""))
    return calls


def test_a_healthy_sample(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_world(monkeypatch)
    found = space.sample(tmp_path, tmp_path / "workspace", tmp_path)
    assert found == space.Sample(NEW_VOLUME, capped(MIB, 64 * MIB), PLENTY, ())
    assert evaluate_sample(found, 64 * MIB, health=FRESH) == []


def test_sample_syncs_first_only_when_asked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = fake_world(monkeypatch)
    space.sample(tmp_path, tmp_path / "workspace", tmp_path)
    assert "sync" not in calls
    calls.clear()
    space.sample(tmp_path, tmp_path / "workspace", tmp_path, sync=True)
    assert calls[0] == "sync"


def test_a_volume_without_quotas_is_no_usage_and_no_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_world(monkeypatch, mode=None)
    found = space.sample(tmp_path, tmp_path / "workspace", tmp_path)
    assert (found.usage, found.errors) == (None, ())
    assert codes(evaluate_sample(found, 64 * MIB, health=FRESH)) == ["P5"]


@pytest.mark.parametrize(
    ("failing", "field", "message"),
    [
        ("space", "space", "volume space"),
        ("host", "host", "host space"),
        ("usage", "usage", "workspace quota"),
        ("mode", "usage", "workspace quota"),
    ],
)
def test_a_signal_that_fails_is_none_with_its_reason_and_blinds_the_agent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failing: str, field: str, message: str
) -> None:
    fake_world(monkeypatch, **{failing: SnapshotError("boom")})
    found = space.sample(tmp_path, tmp_path / "workspace", tmp_path)
    assert getattr(found, field) is None
    assert len(found.errors) == 1 and found.errors[0].startswith(message)
    assert "boom" in found.errors[0]
    # The guardian's entry point counts the sample's own errors: nothing to pass on by hand.
    assert "P4" in codes(evaluate_sample(found, 64 * MIB, health=FRESH))


def test_oserror_and_failed_sync_are_reported_too(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_world(monkeypatch, host=OSError("disk gone"), sync=SnapshotError("sync timed out"))
    found = space.sample(tmp_path, tmp_path / "workspace", tmp_path, sync=True)
    assert [error.split(":")[0] for error in found.errors] == [
        "btrfs filesystem sync",
        "host space",
    ]


def test_sample_does_not_hide_programming_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_world(monkeypatch, space=KeyError("bug"))
    with pytest.raises(KeyError):
        space.sample(tmp_path, tmp_path / "workspace", tmp_path)


def test_conditions_map_to_pause_reasons() -> None:
    assert space.Condition("P7", "blackbox", "x").reason == "blackbox"
    for kind in ("metadata", "data", "usage", "blind", "uncapped", "host"):
        assert space.Condition("P1", kind, "x").reason == "space"  # type: ignore[arg-type]


# evaluate_sample: the guardian's entry point


def test_evaluate_sample_turns_a_failed_sync_into_p4_when_everything_else_is_healthy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The sync failed, so `referenced` may be 30 s old: blind, even though every number read
    fine and none is bad."""
    fake_world(monkeypatch, sync=SnapshotError("sync timed out"))
    found = space.sample(tmp_path, tmp_path / "workspace", tmp_path, sync=True)
    assert found.space and found.usage and found.host  # everything else was read
    assert raw_evaluate(found.space, found.usage, 64 * MIB, found.host, health=FRESH) == []
    (blind,) = evaluate_sample(found, 64 * MIB, health=FRESH)
    assert blind.code == "P4" and "sync timed out" in blind.message


def test_evaluate_sample_keeps_the_callers_read_errors_and_the_samples() -> None:
    reading = space.Sample(NEW_VOLUME, capped(0, 64 * MIB), PLENTY, ("a: boom",))
    health = replace(FRESH, read_errors=("b: bang",))
    (blind,) = evaluate_sample(reading, 64 * MIB, health=health)
    assert "a: boom" in blind.message and "b: bang" in blind.message
    assert health.read_errors == ("b: bang",)  # the caller's Health is not changed


def test_evaluate_sample_defaults_to_a_health_with_no_check_yet() -> None:
    reading = space.Sample(NEW_VOLUME, capped(0, 64 * MIB), PLENTY)
    assert codes(evaluate_sample(reading, 64 * MIB)) == ["P4"]
    assert evaluate_sample(reading, 64 * MIB, health=FRESH) == []


def test_evaluate_sample_passes_the_config_and_the_limit_through() -> None:
    reading = space.Sample(NEW_VOLUME, capped(0, 192 * MIB), PLENTY)
    assert codes(evaluate_sample(reading, 192 * MIB, health=FRESH)) == ["P1"]
    relaxed = replace(DEFAULT_CONFIG, cap_tenths=0, overreserve_tenths=0, overreserve_chunks=0)
    assert evaluate_sample(reading, 192 * MIB, relaxed, FRESH) == []
    with pytest.raises(ValueError, match="limit"):
        evaluate_sample(reading, 0, health=FRESH)
