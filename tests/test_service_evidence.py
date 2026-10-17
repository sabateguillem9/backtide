# ruff: noqa: F811 - the fixtures of test_service_guardian.py are imported by name
"""The Guardian's part of risk 3 (T08): ``take_evidence`` and how the responder is opened and
closed with the service. Same fakes as test_service_guardian.py (a fake volume, jail and watcher
around the real black box)."""

from typing import Any

import pytest

from tests.test_service_guardian import (  # noqa: F401 - fixtures, used by name
    Violation,
    World,
    no_leftover_bridge,
    running,
    world,
)
from vigia.service import guardian as guardian_module
from vigia.snapshots import SnapshotError


class FakeRisk:
    """What the Guardian sees of the RiskResponder."""

    def __init__(self, guardian_lock: Any = None) -> None:
        self.calls: list[str] = []
        self.guardian_lock = guardian_lock
        self.lock_was_free_on_close: bool | None = None
        self.close_error: Exception | None = None
        self.flushed = False

    def flush_held(self) -> None:
        self.calls.append("flush_held")
        self.flushed = True

    def open(self) -> None:
        self.calls.append("open")

    def close(self, timeout: float = 10.0) -> bool:
        self.calls.append("close")
        if self.guardian_lock is not None:
            self.lock_was_free_on_close = not self.guardian_lock.locked()
        if self.close_error is not None:
            raise self.close_error
        return True


def takes(world: World) -> list[str]:
    return [entry for entry in world.log if entry.startswith("store.take")]


def test_a_changed_workspace_gets_an_evidence_snapshot_through_the_barrier(running: World) -> None:
    running.volume.write()
    snapshot_id = running.guardian.take_evidence()
    assert snapshot_id is not None and snapshot_id.endswith("-evidence")
    assert running.log[-3:] == ["watcher.barrier>", "store.take(evidence)", "watcher.barrier<"]
    event = running.events("take")[-1]
    assert (event.snapshot_id, event.details["reason"], event.details["trigger"]) == (
        snapshot_id,
        "evidence",
        "risk",
    )
    assert running.watcher.current == snapshot_id


def test_an_unchanged_workspace_still_gets_a_new_evidence_snapshot(running: World) -> None:
    """Not the newest periodic one: retention deletes those, and evidence is kept."""
    newest = running.volume.listed[-1].id
    snapshot_id = running.guardian.take_evidence()
    assert snapshot_id is not None and snapshot_id != newest and snapshot_id.endswith("-evidence")
    assert len(takes(running)) == 1


def test_after_the_evidence_snapshot_the_next_cycle_sees_nothing_to_do(running: World) -> None:
    running.volume.write()
    assert running.guardian.take_evidence() is not None
    assert not running.guardian.cycle().changed


def test_no_evidence_before_the_service_is_up_or_after_it_stopped(world: World) -> None:
    assert world.guardian.take_evidence() is None
    world.guardian.start()
    world.guardian.stop()
    assert world.guardian.take_evidence() is None


def test_a_rewind_or_a_stop_holding_the_lock_makes_it_give_up(
    running: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guardian_module, "EVIDENCE_LOCK_WAIT", 0.05)
    running.volume.write()
    with running.guardian.agent_lock:
        assert running.guardian.take_evidence() is None
    assert takes(running) == []
    assert running.guardian.take_evidence() is not None  # the lock is free again


def test_a_failed_evidence_snapshot_is_recorded_like_any_failed_snapshot(running: World) -> None:
    running.volume.write()
    running.volume.take_error = SnapshotError("workspace is not a subvolume")
    assert running.guardian.take_evidence() is None
    failed = running.only("take_failed")
    assert (failed.details["reason"], failed.details["trigger"]) == ("evidence", "risk")
    assert running.alerts.titled("No se pudo hacer")


def test_a_space_condition_forbids_the_evidence_snapshot_and_freezes(running: World) -> None:
    running.volume.write()
    running.violations.append(Violation("P3", "el uso pasa del tope", "space"))
    assert running.guardian.take_evidence() is None
    assert takes(running) == []
    assert running.jail.paused


def test_an_unreadable_workspace_is_recorded_not_raised(running: World) -> None:
    original = running.guardian._info  # noqa: SLF001

    def broken(path: object) -> object:
        raise SnapshotError("cannot read the workspace")

    running.guardian._info = broken  # type: ignore[assignment]  # noqa: SLF001
    assert running.guardian.take_evidence() is None
    running.guardian._info = original  # noqa: SLF001
    assert running.only("cycle_failed").details["step"] == "evidence"


def test_the_responder_is_opened_on_start_and_closed_before_stop_takes_the_lock(
    world: World,
) -> None:
    risk = FakeRisk(world.guardian.agent_lock)
    world.guardian._risk = risk  # type: ignore[assignment]  # noqa: SLF001
    world.guardian.start()
    assert risk.calls == ["open"]
    world.guardian.stop()
    assert risk.calls == ["open", "close", "flush_held"]  # the flush is the last step
    assert risk.lock_was_free_on_close is True  # its evidence snapshot needs this very lock
    assert world.events("service_stop")


def test_a_responder_that_fails_to_close_does_not_stop_the_stop(world: World) -> None:
    risk = FakeRisk()
    risk.close_error = RuntimeError("thread stuck")
    world.guardian._risk = risk  # type: ignore[assignment]  # noqa: SLF001
    world.guardian.start()
    world.guardian.stop()
    assert world.events("service_stop")
    assert not world.jail.running


def test_without_a_responder_nothing_changes(world: World) -> None:
    world.guardian.start()
    world.guardian.stop()
    assert world.events("service_stop")
