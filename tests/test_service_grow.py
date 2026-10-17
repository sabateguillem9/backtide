"""The Guardian's emergency growth (T04e-1, docs/19 sections 4 and 6), with fake pieces.

A rewind that fails for lack of space kills the agent and opens the pause ``rewind_no_space``
(T04c-1); then the volume grows once, within its limits, and the rewind is retried once with
the same request id and intent. Here the store, the jail and the watcher are the fakes of
test_service_guardian.py, and the grower is the real ``VolumeGrower`` with the fake disk of
test_snapshot_grow.py: its ``resize`` is what "frees" the space the fake store lacked.
"""

# ruff: noqa: F811 - the fixtures of test_service_guardian.py are imported and used by name

from collections.abc import Callable
from pathlib import Path

import pytest

from tests.test_service_guardian import (  # noqa: F401 - fixtures, used by name
    Violation,
    World,
    no_leftover_bridge,
    pending_intent,
    rewinding,
    running,
    world,
)
from tests.test_snapshot_grow import IMAGE, VOLUME
from tests.test_snapshot_grow import World as Disk
from vigia.jail import JailError
from vigia.notify import AlertLevel
from vigia.service.guardian import AgentState
from vigia.service.rewind import RewindStatus, read_pending
from vigia.snapshots import Reason, SnapshotError, SnapshotNoSpace
from vigia.snapshots.grow import NOT_CONFIGURED, GrowLimits, VolumeGrower
from vigia.snapshots.space import GIB, MIB

CEILING = 3 * GIB // 2


class Crash(BaseException):
    """The process dies here (SIGKILL): nothing below it runs, nothing catches it."""


class GrowingDisk(Disk):
    """The fake disk; ``on_resize`` runs when btrfs takes the new size (the space is there)."""

    def __init__(self) -> None:
        super().__init__()
        self.on_resize: Callable[[], None] | None = None

    def resize(self, mount: Path) -> None:
        super().resize(mount)
        if self.on_resize is not None:
            self.on_resize()


@pytest.fixture
def disk() -> GrowingDisk:
    return GrowingDisk()


def give_grower(world: World, disk: GrowingDisk, *, ceiling: int = CEILING) -> None:
    grower = VolumeGrower(VOLUME, GrowLimits(IMAGE, ceiling), steps=disk, probe=disk)
    world.guardian._grow = grower  # noqa: SLF001 - the one collaborator the fixture lacks


@pytest.fixture
def full(rewinding: World, disk: GrowingDisk) -> World:
    """A running service whose next rewind fails for lack of space before the swap (the
    staging copy), until the volume grows."""
    give_grower(rewinding, disk)
    rewinding.volume.restore_error_before = SnapshotNoSpace("no space for the staging copy")

    def room() -> None:
        rewinding.volume.restore_error_before = None
        rewinding.volume.swap_error = None

    disk.on_resize = room
    return rewinding


def restores(world: World) -> int:
    return world.log.count("store.restore")


def phases(world: World) -> list[str]:
    return [event.details["phase"] for event in world.events("volume_grow")]


def rewind(world: World) -> tuple[object, str]:
    target = world.volume.listed[0].id
    return world.guardian.rewind(target, requested_by="cli"), target


# --- grow once, retry once ---------------------------------------------------------------------


def test_no_space_grows_once_and_the_retry_rewinds(full: World, disk: GrowingDisk) -> None:
    before = full.volume.snapshots()
    outcome, target = rewind(full)

    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert outcome.agent_started  # type: ignore[attr-defined]
    assert "ha crecido" in outcome.message  # type: ignore[attr-defined]
    assert restores(full) == 2
    assert disk.log == [
        f"grow_file({IMAGE}, {GIB + 256 * MIB})",
        "set_capacity(loop3)",
        f"resize({VOLUME.parent})",
    ]
    assert full.guardian.agent_state is AgentState.RUNNING
    assert full.guardian.pause_reasons == frozenset()
    assert full.actions()[-8:] == [
        "snapshot/rewind_requested",
        "system/space_pause",
        "system/agent_stop",  # killed for rewind_no_space
        "snapshot/volume_grow",
        "snapshot/volume_grow",
        "system/space_resume",  # the retry ended green: the pause is closed
        "system/agent_start",
        "snapshot/rewind_done",
    ]
    request_id = full.only("rewind_requested").details["request_id"]
    grow_events = full.events("volume_grow")
    assert [e.details["phase"] for e in grow_events] == ["requested", "done"]
    assert {e.details["request_id"] for e in grow_events} == {request_id}
    assert [e.risk for e in grow_events] == [2, 2]
    assert grow_events[0].details["from_bytes"] == GIB
    assert grow_events[1].details["reached_bytes"] == GIB + 256 * MIB
    done = full.only("rewind_done")
    assert done.details["request_id"] == request_id
    assert (done.details["grow"], done.details["retried"]) == ("done", True)
    assert done.risk == 1 and "problems" not in done.details
    assert full.only("space_resume").details["reasons"] == ["rewind_no_space"]
    # No snapshot was deleted: all of them are still there, plus the undo point.
    after = full.volume.snapshots()
    assert set(before) < set(after) and len(after) == len(before) + 1
    assert after[-1].reason == Reason.PRE_RESTORE
    assert not full.config.pending_file.exists()
    (grew,) = full.alerts.titled("El volumen ha crecido")
    assert grew.level is AlertLevel.WARNING
    assert grew.event_seq == grow_events[1].seq
    assert "1024 MiB a 1280 MiB" in grew.body
    (space,) = full.alerts.titled("No hay espacio para rebobinar")
    assert "agrandar el volumen una sola vez" in space.body
    assert full.alerts.titled("No se ha rebobinado") == []
    assert target == done.snapshot_id


def test_the_intent_is_kept_through_the_growth(full: World, disk: GrowingDisk) -> None:
    """The retry is the same rewind: rewind.pending says where it starts the whole time."""
    seen: list[object] = []
    room = disk.on_resize
    assert room is not None

    def look_and_room() -> None:
        seen.append(pending_intent(full))
        room()

    disk.on_resize = look_and_room
    rewind(full)
    (intent,) = seen
    requested = full.only("rewind_requested").details
    assert intent.request_id == requested["request_id"]  # type: ignore[attr-defined]
    assert intent.from_workspace_id == 258  # type: ignore[attr-defined]
    assert len(full.events("rewind_requested")) == 1


def test_no_space_in_the_swap_grows_and_retries_too(rewinding: World, disk: GrowingDisk) -> None:
    give_grower(rewinding, disk)
    rewinding.volume.swap_error = SnapshotNoSpace("the EXCHANGE ran out of metadata")
    disk.on_resize = lambda: setattr(rewinding.volume, "swap_error", None)
    outcome, _ = rewind(rewinding)
    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert restores(rewinding) == 2
    assert rewinding.jail.running
    # The first attempt's quiesce stopped it; the kill had nothing left to kill.
    assert rewinding.only("space_pause").details["killed"] is False


def test_the_retry_happens_only_once(full: World, disk: GrowingDisk) -> None:
    disk.on_resize = None  # the growth works, but the space is still not enough
    outcome, _ = rewind(full)

    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    assert restores(full) == 2  # the first one and the one retry, never a third
    assert phases(full) == ["requested", "done"]  # one growth
    assert len(disk.log) == 3
    failed = full.only("rewind_failed")
    assert failed.risk == 3  # the last resort failed
    assert failed.details["no_space"] is True
    assert (failed.details["grow"], failed.details["retried"]) == ("done", True)
    assert not full.jail.running
    assert full.guardian.agent_state is AgentState.STOPPED
    assert full.guardian.pause_reasons == {"rewind_no_space"}
    assert len(full.events("space_pause")) == 1  # the pause opened once
    (alert,) = full.alerts.titled("No se ha rebobinado")
    assert "ha crecido una vez y sigue sin haber espacio" in alert.body
    assert not full.config.pending_file.exists()


def test_a_retry_that_fails_for_another_reason_is_still_risk_3(
    full: World, disk: GrowingDisk
) -> None:
    def other_failure() -> None:
        full.volume.restore_error_before = SnapshotError("EIO on the staging copy")

    disk.on_resize = other_failure
    outcome, _ = rewind(full)
    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    failed = full.only("rewind_failed")
    assert failed.risk == 3 and failed.details["no_space"] is False
    assert "el reintento ha fallado" in full.alerts.titled("No se ha rebobinado")[0].body


# --- no growth, no retry -----------------------------------------------------------------------


def test_without_growth_configured_it_is_recorded_and_nothing_is_retried(
    rewinding: World,
) -> None:
    rewinding.volume.restore_error_before = SnapshotNoSpace("full")
    outcome, _ = rewind(rewinding)
    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    assert restores(rewinding) == 1
    (refused,) = rewinding.events("volume_grow")
    assert refused.details == {
        "phase": "refused",
        "request_id": rewinding.only("rewind_requested").details["request_id"],
        "reason": "not_configured",
    }
    failed = rewinding.only("rewind_failed")
    assert failed.risk == 2
    assert (failed.details["grow"], failed.details["grow_reason"]) == ("refused", "not_configured")
    assert failed.details["retried"] is False
    # One alert says what to do; the growth that was never configured adds none.
    (space,) = rewinding.alerts.titled("No hay espacio para rebobinar")
    assert "Libera espacio" in space.body
    assert not rewinding.alerts.titled("volumen")


def test_production_steps_fail_closed_with_not_configured(rewinding: World, disk: Disk) -> None:
    rewinding.guardian._grow = VolumeGrower(  # noqa: SLF001
        VOLUME, GrowLimits(IMAGE, CEILING), steps=NOT_CONFIGURED, probe=disk
    )
    rewinding.volume.restore_error_before = SnapshotNoSpace("full")
    outcome, _ = rewind(rewinding)
    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    assert restores(rewinding) == 1
    assert (disk.file, disk.loop, disk.fs) == (GIB, GIB, GIB)
    assert phases(rewinding) == ["requested", "failed"]
    failed_grow = rewinding.events("volume_grow")[-1]
    assert failed_grow.risk == 3
    assert failed_grow.details["not_configured"] is True
    (alert,) = rewinding.alerts.titled("No se ha podido agrandar el volumen")
    assert "todavía no tiene permiso" in alert.body
    assert alert.event_seq == failed_grow.seq


@pytest.mark.parametrize(
    ("step", "half"),
    [("grow_file", False), ("set_capacity", True), ("resize", True)],
)
def test_a_failing_step_is_recorded_alerted_and_not_retried(
    full: World, disk: GrowingDisk, step: str, half: bool
) -> None:
    disk.fail[step] = OSError(1, "Operation not permitted")
    outcome, _ = rewind(full)
    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    assert restores(full) == 1
    failed_grow = full.events("volume_grow")[-1]
    assert (failed_grow.details["phase"], failed_grow.details["step"]) == ("failed", step)
    assert failed_grow.risk == 3
    rewind_failed = full.only("rewind_failed")
    assert rewind_failed.details["grow_step"] == step
    assert rewind_failed.details["retried"] is False and rewind_failed.risk == 2
    (alert,) = full.alerts.titled("No se ha podido agrandar el volumen")
    assert alert.level is AlertLevel.ERROR
    assert ("a medias" in alert.body) is half
    assert "Operation not permitted" not in alert.body  # the step's text stays in the event
    assert not full.jail.running
    assert full.guardian.pause_reasons == {"rewind_no_space"}


def test_a_refused_growth_is_alerted_with_its_reason(full: World, disk: GrowingDisk) -> None:
    disk.fs = disk.file = disk.loop = CEILING - 64 * MIB  # one more step would pass the ceiling
    outcome, _ = rewind(full)
    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    assert restores(full) == 1
    assert disk.log == []
    assert full.only("volume_grow").details["reason"] == "ceiling"
    (alert,) = full.alerts.titled("No se ha agrandado el volumen")
    assert "max_volume_bytes" in alert.body


def test_an_agent_that_could_not_be_killed_is_never_grown_under(
    full: World, disk: GrowingDisk
) -> None:
    full.jail.cannot_stop()
    outcome, _ = rewind(full)
    assert outcome.status is RewindStatus.FAILED  # type: ignore[attr-defined]
    assert disk.log == []
    assert full.only("volume_grow").details["reason"] == "agent_running"
    assert restores(full) == 1
    (space,) = full.alerts.titled("No hay espacio para rebobinar")
    assert "Libera espacio" in space.body  # no promise of a growth that cannot happen


def test_an_agent_whose_docker_state_cannot_be_read_is_never_grown_under(
    full: World, disk: GrowingDisk
) -> None:
    def broken() -> bool:
        raise JailError("docker inspect failed")

    full.jail.is_running = broken  # type: ignore[method-assign]
    rewind(full)
    assert disk.log == []
    # Whether the kill could be confirmed or not, nothing proves it stopped: refused.
    (refused,) = full.events("volume_grow")
    assert refused.details["reason"] in {"agent_running", "agent_state_unknown"}
    assert restores(full) == 1


# --- the undo point that could not be published ------------------------------------------------


def test_a_rewind_without_room_for_its_undo_point_grows_and_recovers_it(
    rewinding: World, disk: GrowingDisk
) -> None:
    """Swapped, but the old workspace could not be published: the growth is followed by
    recover() (never a second rewind), and the agent then starts."""
    give_grower(rewinding, disk)
    rewinding.volume.incomplete_cause = SnapshotNoSpace("no space to publish the undo point")
    disk.on_resize = lambda: setattr(rewinding.volume, "incomplete_cause", None)
    outcome, _ = rewind(rewinding)

    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert restores(rewinding) == 1
    assert rewinding.log.index("store.recover") > rewinding.log.index("store.restore")
    undo = rewinding.volume.snapshots()[-1]
    assert undo.reason == Reason.RECOVERED
    assert outcome.undo == undo.id  # type: ignore[attr-defined]
    done = rewinding.only("rewind_done")
    assert done.details["undo"] == undo.id
    assert done.details["recovered"] == [undo.id]
    assert "incomplete" not in done.details and "problems" not in done.details
    assert done.details["retried"] is True
    assert rewinding.jail.running
    assert rewinding.guardian.agent_state is AgentState.RUNNING
    assert rewinding.guardian.pause_reasons == frozenset()
    starts = [e.details for e in rewinding.events("agent_start")]
    assert starts[-1]["reason"] == "rewind"


def test_a_user_pause_during_the_start_after_recovery_is_caught_up(
    rewinding: World, disk: GrowingDisk
) -> None:
    """`/pausar` while the agent starts after the recovered undo point: nothing was there to
    freeze yet, so the start catches it up and freezes the agent."""
    give_grower(rewinding, disk)
    rewinding.volume.incomplete_cause = SnapshotNoSpace("no space to publish the undo point")
    disk.on_resize = lambda: setattr(rewinding.volume, "incomplete_cause", None)
    pauses: list[object] = []

    def pause_now() -> None:
        if not pauses and "store.recover" in rewinding.log:
            pauses.append(rewinding.guardian.pause_by_user(requested_by="telegram"))

    rewinding.jail.on_wait_ready = pause_now
    rewind(rewinding)
    assert pauses
    # Frozen, or killed when it could not get ready frozen: never left running.
    assert not (rewinding.jail.running and not rewinding.jail.paused)
    assert rewinding.guardian.agent_state in (AgentState.FROZEN, AgentState.STOPPED)
    assert "user" in rewinding.guardian.pause_reasons


def test_an_undo_point_that_still_cannot_be_published_stays_incomplete(
    rewinding: World, disk: GrowingDisk
) -> None:
    give_grower(rewinding, disk)
    rewinding.volume.incomplete_cause = SnapshotNoSpace("no space to publish the undo point")
    rewinding.volume.recover_error = SnapshotNoSpace("still no space")
    outcome, _ = rewind(rewinding)
    assert outcome.status is RewindStatus.PROBLEM  # type: ignore[attr-defined]
    done = rewinding.only("rewind_done")
    assert done.details["incomplete"] is True and done.details["retried"] is True
    assert not rewinding.jail.running
    assert rewinding.guardian.pause_reasons == {"rewind_no_space"}


def test_a_restore_incomplete_for_another_reason_is_not_grown(
    rewinding: World, disk: GrowingDisk
) -> None:
    give_grower(rewinding, disk)
    rewinding.volume.incomplete_cause = SnapshotError("EIO")
    rewind(rewinding)
    assert disk.log == []
    assert not rewinding.events("volume_grow")


# --- with the pause by space -------------------------------------------------------------------


def test_a_frozen_agent_paused_for_space_starts_after_the_grown_retry(
    running: World, disk: GrowingDisk
) -> None:
    running.violations.append(Violation("P1", "faltan metadatos", "space"))
    running.volume.write()
    running.guardian.cycle()
    assert running.guardian.agent_state is AgentState.FROZEN
    give_grower(running, disk)
    running.volume.restore_error_before = SnapshotNoSpace("full")

    def room() -> None:
        running.volume.restore_error_before = None
        running.violations.clear()  # the growth freed the metadata

    disk.on_resize = room
    outcome, _ = rewind(running)
    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert running.jail.running and not running.jail.paused
    assert running.guardian.pause_reasons == frozenset()
    assert running.events("space_resume")[-1].details["reasons"] == ["rewind_no_space", "space"]


def test_still_red_after_the_grown_retry_leaves_the_agent_stopped_and_paused(
    full: World, disk: GrowingDisk
) -> None:
    room = disk.on_resize
    assert room is not None

    def room_but_still_red() -> None:
        room()
        full.violations.append(Violation("P1", "faltan metadatos", "space"))

    disk.on_resize = room_but_still_red
    outcome, _ = rewind(full)
    assert outcome.status is RewindStatus.PROBLEM  # type: ignore[attr-defined]
    assert outcome.rewound and not outcome.agent_started  # type: ignore[attr-defined]
    assert not full.jail.running
    assert {"rewind_no_space", "space"} <= full.guardian.pause_reasons
    assert full.only("rewind_done").details["problems"] == ["agent"]


def test_a_stopped_agent_is_grown_for_and_stays_stopped(full: World, disk: GrowingDisk) -> None:
    full.jail.stop()  # stopped on purpose: the rewind never starts it
    full.guardian._set_state(AgentState.STOPPED)  # noqa: SLF001
    outcome, _ = rewind(full)
    assert outcome.status is RewindStatus.DONE  # type: ignore[attr-defined]
    assert not outcome.agent_started  # type: ignore[attr-defined]
    assert phases(full) == ["requested", "done"]
    assert not full.jail.running
    assert full.only("space_pause").details["killed"] is False


def test_a_second_failed_rewind_may_grow_again_within_the_ceiling(
    full: World, disk: GrowingDisk
) -> None:
    disk.on_resize = None
    rewind(full)
    rewind(full)
    assert phases(full) == ["requested", "done", "requested", "done"]
    assert disk.fs == GIB + 512 * MIB == CEILING
    rewind(full)  # a third would pass the ceiling
    assert full.events("volume_grow")[-1].details["reason"] == "ceiling"
    assert disk.fs == CEILING


# --- the intent and the reconciliation ---------------------------------------------------------


def test_killed_during_the_growth_is_reconciled_as_failed(full: World, disk: GrowingDisk) -> None:
    def die() -> None:
        raise Crash

    disk.on_resize = die
    with pytest.raises(Crash):
        rewind(full)
    intent = read_pending(full.config.pending_file)
    assert intent is not None and intent.from_workspace_id == 258
    assert phases(full) == ["requested"]  # cut half way: no done, no failed

    full.guardian.stop()
    full.guardian.start()
    failed = full.only("rewind_failed")
    assert failed.details["reconciled"] is True
    assert failed.details["request_id"] == intent.request_id
    assert not full.config.pending_file.exists()


def test_killed_after_the_retrys_swap_is_reconciled_as_done(full: World, disk: GrowingDisk) -> None:
    room = disk.on_resize
    assert room is not None

    def room_and_die_when_ready() -> None:
        room()

        def die() -> None:
            raise Crash

        full.jail.on_wait_ready = die

    disk.on_resize = room_and_die_when_ready
    with pytest.raises(Crash):
        rewind(full)
    assert full.config.pending_file.exists()
    full.jail.on_wait_ready = None
    full.guardian.stop()
    full.guardian.start()
    done = full.only("rewind_done")
    assert done.details["reconciled"] is True
    assert done.details["undo"] == full.volume.snapshots()[-1].id
    assert not full.events("rewind_failed")


def test_the_next_rewind_settles_an_interrupted_growth_first(
    full: World, disk: GrowingDisk
) -> None:
    def die() -> None:
        raise Crash

    disk.on_resize = die
    with pytest.raises(Crash):
        rewind(full)
    first = full.only("rewind_requested").details["request_id"]
    disk.on_resize = lambda: setattr(full.volume, "restore_error_before", None)
    full.guardian.rewind(full.volume.listed[0].id, requested_by="cli")
    failed = full.only("rewind_failed")
    assert failed.details["request_id"] == first and failed.details["reconciled"] is True
    assert len(full.events("rewind_done")) == 1
