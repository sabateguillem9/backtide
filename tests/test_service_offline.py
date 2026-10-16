"""`vigia rebobinar` without a service (T04c-2): the real Guardian and black box, fake store/jail.

The fakes are those of test_service_guardian.py (a volume with Btrfs counters, a jail that logs
its calls). What these tests pin down: the rewind is the real ``Guardian.rewind`` with its events,
nothing else boots (no snapshot, no watcher, no agent start), the agent is left stopped, and a
black box that cannot be used means nothing is rewound. The VM tests (tests/integration/
test_cli_rewind.py) run it against the real OpenClaw.
"""

import logging
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.test_service_guardian import TOKEN, FakeJail, FakeVolume
from vigia.blackbox import BlackBox, BlackBoxError, Event, load_key
from vigia.jail import JailError
from vigia.notify import Alert
from vigia.service.config import Secret, ServiceConfig
from vigia.service.guardian import Guardian
from vigia.service.offline import NullWatcher, rewind_without_service
from vigia.service.rewind import RewindStatus
from vigia.snapshots import Reason, Snapshot, SnapshotError


class Collector:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def send(self, alert: Alert) -> None:
        self.alerts.append(alert)


class Rig:
    def __init__(self, tmp_path: Path, clock: Callable[[], datetime]) -> None:
        self.log: list[str] = []
        self.volume = FakeVolume(tmp_path, clock, self.log)
        self.jail = FakeJail(self.log)
        (tmp_path / "state").mkdir(mode=0o700)
        self.config = ServiceConfig(
            state_dir=tmp_path / "state", volume=tmp_path / "vol", gateway_token=Secret(TOKEN)
        )
        self.notifier = Collector()
        self.target: Snapshot = self.volume.snapshot_quietly(Reason.PERIODIC)
        self.volume.write()  # the workspace moved on after the snapshot

    def rewind(self, snapshot_id: str | None = None) -> object:
        return rewind_without_service(
            self.config,
            snapshot_id if snapshot_id is not None else self.target.id,
            jail=self.jail,  # type: ignore[arg-type]
            store=self.volume,  # type: ignore[arg-type]
            notifier=self.notifier,
            guardian_options={"info": self.volume.info, "sync": self.volume.sync},
        )

    def events(self) -> list[Event]:
        with BlackBox(
            self.config.blackbox_db,
            load_key(self.config.blackbox_key),
            checkpoint_path=self.config.blackbox_checkpoint,
            readonly=True,
        ) as box:
            return box.events()

    def actions(self) -> list[str]:
        return [f"{event.source}/{event.action}" for event in self.events()]

    def verify_ok(self) -> bool:
        with BlackBox(
            self.config.blackbox_db,
            load_key(self.config.blackbox_key),
            checkpoint_path=self.config.blackbox_checkpoint,
            readonly=True,
        ) as box:
            return box.verify().ok


@pytest.fixture
def rig(tmp_path: Path, clock: Callable[[], datetime]) -> Iterator[Rig]:
    yield Rig(tmp_path, clock)
    vigia_logger = logging.getLogger("vigia")
    for handler in list(vigia_logger.handlers):
        if type(handler).__name__ == "LogBridge":
            vigia_logger.removeHandler(handler)


def test_the_rewind_is_done_in_this_process_and_recorded(rig: Rig) -> None:
    before = rig.volume.workspace_id()
    outcome = rig.rewind()
    assert outcome.status is RewindStatus.DONE and outcome.exit_code == 0  # type: ignore[attr-defined]
    assert rig.volume.workspace_id() != before
    assert outcome.undo is not None  # type: ignore[attr-defined]
    assert rig.actions() == [
        "system/cli_start",
        "snapshot/rewind_requested",
        "snapshot/rewind_done",
        "system/cli_stop",
    ]
    done = rig.events()[2]
    assert done.snapshot_id == rig.target.id
    assert done.details["undo"] == outcome.undo  # type: ignore[attr-defined]
    assert done.details["agent_started"] is False
    assert "problems" not in done.details
    assert not rig.config.pending_file.exists()
    assert rig.verify_ok()


def test_nothing_else_boots_no_snapshot_no_watcher_no_agent(rig: Rig) -> None:
    rig.rewind()
    assert "jail.start" not in rig.log
    assert "jail.wait_ready" not in rig.log
    assert "store.take(periodic)" not in rig.log
    assert not any(entry.startswith("jail.create") for entry in rig.log)
    assert not rig.jail.running
    assert [event.action for event in rig.events() if event.action.startswith("agent_")] == []


def test_an_agent_found_running_is_stopped_by_the_rewind_and_left_stopped(rig: Rig) -> None:
    rig.jail.running = True  # a killed service left it running, unwatched
    outcome = rig.rewind()
    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert not rig.jail.running
    assert "jail.stop" in rig.log and "jail.start" not in rig.log
    (stop,) = [e for e in rig.events() if e.action == "agent_stop"]
    assert stop.details["reason"] == "rewind"
    done = next(e for e in rig.events() if e.action == "rewind_done")
    assert done.details["agent_started"] is False
    assert "problems" not in done.details  # not starting it is not a problem here


def test_a_frozen_agent_is_killed_and_left_stopped(rig: Rig) -> None:
    rig.jail.running = rig.jail.paused = True
    outcome = rig.rewind()
    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert "jail.kill" in rig.log
    assert not rig.jail.running and "jail.start" not in rig.log


def test_a_black_box_that_cannot_be_used_means_nothing_is_rewound_and_an_unrecorded_agent_stops(
    rig: Rig,
) -> None:
    rig.config.blackbox_db.write_bytes(b"")  # a database without its key
    rig.jail.running = True  # a killed service left it running
    with pytest.raises(BlackBoxError) as raised:
        rig.rewind()
    assert "store.restore" not in rig.log
    assert not rig.jail.running  # as the service does: with nothing to record it, it must not run
    assert any("parado" in note for note in raised.value.__notes__)


def test_a_black_box_that_cannot_be_used_touches_a_stopped_agent_not_at_all(rig: Rig) -> None:
    rig.config.blackbox_db.write_bytes(b"")
    with pytest.raises(BlackBoxError):
        rig.rewind()
    assert rig.log == []


def test_an_agent_that_cannot_be_stopped_without_a_black_box_is_said_loudly(rig: Rig) -> None:
    rig.config.blackbox_db.write_bytes(b"")
    rig.jail.running = True
    rig.jail.cannot_stop()
    with pytest.raises(JailError, match="SIGUE EN MARCHA"):
        rig.rewind()
    assert "store.restore" not in rig.log


def test_an_unexpected_exception_is_logged_into_the_black_box_before_it_goes_up(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Guardian, snapshot_id: str, *, requested_by: str) -> None:
        raise ZeroDivisionError("guardian bug")

    monkeypatch.setattr(Guardian, "rewind", boom)
    with pytest.raises(ZeroDivisionError):
        rig.rewind()
    logs = [e for e in rig.events() if e.source == "system" and e.action == "log"]
    assert any("failed unexpectedly" in str(e.details) for e in logs)  # nothing is swallowed
    assert rig.actions()[-1] == "system/cli_stop"


def test_a_checkpoint_that_shows_tampering_means_nothing_is_rewound(rig: Rig) -> None:
    rig.rewind()  # makes the black box
    rig.log.clear()
    rig.config.blackbox_db.unlink()  # the evidence is gone, the checkpoint says it was there
    for extra in ("-wal", "-shm"):
        Path(str(rig.config.blackbox_db) + extra).unlink(missing_ok=True)
    with pytest.raises(BlackBoxError):
        rig.rewind(rig.volume.snapshots()[0].id)
    assert "store.restore" not in rig.log


def test_a_failed_rewind_leaves_the_workspace_and_says_so(rig: Rig) -> None:
    rig.volume.restore_error_before = SnapshotError("staging failed: /tmp/x is not writable")
    before = rig.volume.workspace_id()
    outcome = rig.rewind()
    assert outcome.status is RewindStatus.FAILED and outcome.exit_code == 1  # type: ignore[attr-defined]
    assert rig.volume.workspace_id() == before
    assert rig.actions() == [
        "system/cli_start",
        "snapshot/rewind_requested",
        "snapshot/rewind_failed",
        "system/cli_stop",
    ]
    assert [a.title for a in rig.notifier.alerts] == ["No se ha rebobinado"]


def test_an_invalid_id_does_nothing(rig: Rig) -> None:
    outcome = rig.rewind("latest")
    assert outcome.status is RewindStatus.INVALID and outcome.exit_code == 2  # type: ignore[attr-defined]
    assert "store.restore" not in rig.log
    assert rig.actions() == ["system/cli_start", "system/cli_stop"]


def test_the_log_is_bridged_into_the_black_box_during_the_rewind_and_then_detached(
    rig: Rig,
) -> None:
    rig.volume.during_swap = lambda: logging.getLogger("vigia.snapshots.fake").warning(
        "the swap took a while"
    )
    rig.rewind()
    logs = [e for e in rig.events() if e.source == "system" and e.action == "log"]
    assert any("swap took a while" in str(e.details) for e in logs)
    assert not [h for h in logging.getLogger("vigia").handlers if type(h).__name__ == "LogBridge"]


def test_the_requester_is_recorded(rig: Rig) -> None:
    rig.rewind()
    requested = next(e for e in rig.events() if e.action == "rewind_requested")
    assert requested.details["requested_by"] == "cli"


def test_the_null_watcher_does_nothing_and_says_it_is_not_armed() -> None:
    watcher = NullWatcher()
    assert watcher.arm("x") is False
    assert watcher.rearm_if_moved(3) is False
    assert watcher.report_unwatched() is False
    with watcher.suspended("y"):
        pass
    watcher.close()
    sentinel = Snapshot(datetime(2026, 10, 16, tzinfo=UTC), "periodic")
    assert watcher.barrier(lambda: sentinel) is sentinel
