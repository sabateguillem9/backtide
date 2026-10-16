"""The pieces of the pause by space that live outside the Guardian (vigia/service/pause.py):
what resuming answers, what the alert says holds the space, the real space gate and the
threads that tick. Pure or with fakes; the Guardian's side is in test_service_space_thread.py.
"""

import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vigia.service.config import Secret, ServiceConfig
from vigia.service.pause import (
    Holder,
    ResumeOutcome,
    ResumeStatus,
    Ticker,
    condition_text,
    holders_text,
    make_space_gate,
)
from vigia.snapshots import btrfs, space
from vigia.snapshots.space import GIB, MIB, Allocation, Condition, HostSpace, Sample, VolumeSpace

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
CAP = 64 * MIB


# --- what resuming answers ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (ResumeStatus.RESUMED, 0),
        (ResumeStatus.NOT_PAUSED, 0),
        (ResumeStatus.STOPPED, 1),
        (ResumeStatus.STILL_RED, 1),
        (ResumeStatus.STILL_PAUSED, 1),
        (ResumeStatus.FAILED, 1),
        (ResumeStatus.PROBLEM, 3),
    ],
)
def test_every_resume_status_has_its_exit_code(status: ResumeStatus, code: int) -> None:
    assert ResumeOutcome(status, "x").exit_code == code


# --- the alert, in Spanish ---------------------------------------------------------------------


def test_conditions_with_figures_are_told_in_spanish() -> None:
    p1 = Condition("P1", "metadata", "metadata: 100 MiB left", 100 * MIB, 341 * MIB)
    p2 = Condition("P2", "data", "data: ...", 10 * MIB, 64 * MIB)
    p3 = Condition("P3", "usage", "workspace uses ...", 80 * MIB, 64 * MIB)
    assert condition_text(p1) == "metadatos: quedan 100.0 MiB, mínimo 341.0 MiB"
    assert condition_text(p2) == "datos: quedan 10.0 MiB, mínimo 64.0 MiB"
    assert "80.0 MiB" in condition_text(p3) and "tope de 64.0 MiB" in condition_text(p3)


def test_a_condition_without_figures_keeps_its_message() -> None:
    p4 = Condition("P4", "blind", "cannot see the space: no check yet")
    assert "cannot see the space" in condition_text(p4)
    assert condition_text(p4).startswith("no se puede comprobar el espacio")


def snap(name: str, size: int, hour: int, reason: str = "pre_restore") -> Holder:
    moment = datetime(2026, 10, 16, hour, 30, tzinfo=UTC)
    return Holder("snapshot", name, size, taken_at=moment, reason=reason)


def test_the_holders_are_the_five_largest_with_the_workspace_against_its_cap() -> None:
    holders = [
        Holder("workspace", "workspace", 50 * MIB),
        snap("a", 300 * MIB, 8),
        snap("b", 1 * MIB, 9, reason="periodic"),
        snap("c", 200 * MIB, 10),
        Holder("other", "0/300", 120 * MIB),
        snap("d", 90 * MIB, 11),
        snap("e", 2 * MIB, 12, reason="periodic"),
    ]
    lines = holders_text(holders, CAP, tz=UTC)
    assert len(lines) == 5
    assert lines[0].startswith("- punto de deshacer a (antes de rebobinar, 2026-10-16 08:30)")
    assert "300.0 MiB" in lines[0]
    assert "0/300" in lines[2] and "borrado" in lines[2]
    assert any(
        line.startswith("- el espacio de trabajo actual: 50.0 MiB de 64.0 MiB") for line in lines
    )
    assert not any(" b " in line or line.endswith(" b") for line in lines)


def test_the_workspace_is_always_listed_even_if_it_is_small() -> None:
    holders = [Holder("workspace", "workspace", 1 * MIB)] + [
        snap(str(index), (index + 2) * MIB, 8) for index in range(6)
    ]
    lines = holders_text(holders, CAP, tz=UTC)
    assert len(lines) == 5
    assert lines[-1].startswith("- el espacio de trabajo actual")


def test_nothing_known_says_so() -> None:
    assert holders_text([], CAP) == []


# --- the real space gate -----------------------------------------------------------------------


def config(tmp_path: Path, limit: int | None = CAP) -> ServiceConfig:
    (tmp_path / "state").mkdir(mode=0o700, exist_ok=True)
    return ServiceConfig(
        state_dir=tmp_path / "state",
        volume=tmp_path / "vol",
        gateway_token=Secret(TOKEN),
        workspace_limit=limit,
    )


class Store:
    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "vol"
        self.workspace = self.root / "workspace"


def volume(meta_free: int) -> VolumeSpace:
    return VolumeSpace(
        device_total=GIB,
        unallocated=0,
        data=Allocation(total_bytes=GIB // 2, disk_total=GIB // 2, bytes_used=0),
        metadata=Allocation(total_bytes=meta_free, disk_total=2 * meta_free, bytes_used=0),
    )


def usage(referenced: int, limit: int = CAP) -> btrfs.QgroupUsage:
    return btrfs.QgroupUsage(referenced, referenced, btrfs.QGROUP_LIMIT_MAX_RFER, limit, 0)


PLENTY = HostSpace(total=500 * GIB, free=400 * GIB)


def test_without_a_cap_there_is_no_gate(tmp_path: Path) -> None:
    assert make_space_gate(config(tmp_path, limit=None), Store(tmp_path)) is None  # type: ignore[arg-type]


def test_the_gate_reads_a_fresh_sample_and_evaluates_it(tmp_path: Path) -> None:
    read: list[tuple[Path, Path, Path]] = []

    def sample(root: Path, workspace: Path, state_dir: Path) -> Sample:
        read.append((root, workspace, state_dir))
        return Sample(volume(600 * MIB), usage(10 * MIB), PLENTY)

    gate = make_space_gate(config(tmp_path), Store(tmp_path), sample=sample)  # type: ignore[arg-type]
    assert gate is not None
    assert list(gate()) == []
    assert read == [(tmp_path / "vol", tmp_path / "vol" / "workspace", tmp_path / "state")]


def test_the_gate_finds_p1_and_fails_closed_on_a_read_error(tmp_path: Path) -> None:
    readings = [
        Sample(volume(100 * MIB), usage(10 * MIB), PLENTY),
        Sample(None, usage(10 * MIB), PLENTY, errors=("volume space: EIO",)),
    ]
    gate = make_space_gate(config(tmp_path), Store(tmp_path), sample=lambda *a: readings.pop(0))  # type: ignore[arg-type]
    assert gate is not None
    assert [c.code for c in gate()] == ["P1"]
    assert [c.code for c in gate()] == ["P4"]


def test_the_gate_gives_early_warnings_only_when_nothing_pauses(tmp_path: Path) -> None:
    readings = [
        Sample(volume(600 * MIB), usage(60 * MIB), PLENTY),  # 94 % of the cap: W3 only
        Sample(volume(600 * MIB), usage(80 * MIB), PLENTY),  # past it: P3, no warning
    ]
    gate = make_space_gate(config(tmp_path), Store(tmp_path), sample=lambda *a: readings.pop(0))  # type: ignore[arg-type]
    assert gate is not None
    assert [c.code for c in gate()] == ["W3"]
    assert [c.code for c in gate()] == ["P3"]


def test_the_gate_never_counts_the_age_of_a_check_it_just_made(tmp_path: Path) -> None:
    """Staleness (P4 "no check for 3 s") is the watchdog's: a fresh reading is never stale."""
    gate = make_space_gate(
        config(tmp_path),
        Store(tmp_path),  # type: ignore[arg-type]
        sample=lambda *a: Sample(volume(600 * MIB), usage(1 * MIB), PLENTY),
    )
    assert gate is not None
    assert list(gate()) == []


def test_space_blackbox_condition_is_p7_past_both_thresholds() -> None:
    assert space.blackbox_condition(2, 60.0) is None
    assert space.blackbox_condition(3, 10.0) is None
    found = space.blackbox_condition(3, 10.5)
    assert found is not None and found.code == "P7" and found.reason == "blackbox"


# --- the threads -------------------------------------------------------------------------------


def test_a_ticker_runs_its_step_at_once_and_then_every_interval_until_closed() -> None:
    ran = threading.Event()
    count = [0]

    def step() -> None:
        count[0] += 1
        if count[0] >= 3:
            ran.set()

    ticker = Ticker("test-ticker", 0.01, step)
    ticker.start()
    assert ran.wait(5)
    ticker.close()
    after = count[0]
    assert not ticker.alive
    assert count[0] == after  # nothing runs once closed


def test_a_step_that_raises_is_logged_and_the_ticker_goes_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ran = threading.Event()
    count = [0]

    def step() -> None:
        count[0] += 1
        if count[0] == 1:
            raise RuntimeError("boom")
        ran.set()

    ticker = Ticker("test-ticker", 0.01, step)
    with caplog.at_level("ERROR", logger="vigia.service.pause"):
        ticker.start()
        assert ran.wait(5)
        ticker.close()
    assert any("test-ticker" in record.getMessage() for record in caplog.records)
