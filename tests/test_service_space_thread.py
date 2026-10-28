"""The pause by space in the Guardian (T04d-2, docs/19 section 5), with the fakes of
test_service_guardian.py: the space thread (``check_space``), its watchdog (``check_watchdog``),
P7, the early warnings, ``resume`` (`backtide seguir`) and a pause that survives the service.

The threads themselves are not run here (except one test of ``run``): each pass is called by
the test, with the monotonic clock in its hands. The real `docker pause` is in the VM test
tests/integration/test_space_pause.py.
"""

# The fixtures of test_service_guardian.py are imported and then named as parameters.
# ruff: noqa: F811

import threading
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

import pytest
from test_service_guardian import (  # noqa: F401 - fixtures, used by name
    Alerts,
    FakeWatcher,
    FlakyBox,
    Violation,
    World,
    no_leftover_bridge,
    rewinding,
    running,
    world,
)

from backtide.blackbox import BlackBoxError
from backtide.jail import JailError
from backtide.notify import AlertLevel
from backtide.service.guardian import AgentState, Guardian
from backtide.service.pause import Holder, ResumeStatus
from backtide.service.rewind import RewindStatus
from backtide.snapshots import SnapshotError

P1 = Violation("P1", "metadatos: quedan 100 MiB, mínimo 341 MiB")
P3 = Violation("P3", "el uso pasa del tope")


class Readings:
    """A gate that answers from a script: each call pops the next reading (the last repeats)."""

    def __init__(self, world: World, *readings: Sequence[Violation]) -> None:
        self.world = world
        self.readings = [list(reading) for reading in readings]
        self.calls = 0

    def __call__(self) -> list[Violation]:
        self.calls += 1
        self.world.log.append("space.evaluate")
        if len(self.readings) > 1:
            return self.readings.pop(0)
        return list(self.readings[0])


@pytest.fixture
def live(running: World) -> World:
    """A running service whose space thread has just checked."""
    running.guardian._sleep = lambda seconds: running.log.append(f"sleep({seconds})")  # noqa: SLF001
    running.guardian.check_space()
    running.log.clear()
    return running


def script(world: World, *readings: Sequence[Violation]) -> Readings:
    gate = Readings(world, *readings)
    world.guardian._space = gate  # noqa: SLF001 - the gate the test scripts
    return gate


# --- the space thread --------------------------------------------------------------------------


def test_a_green_check_does_nothing_but_count_as_a_check(live: World) -> None:
    before = live.actions()
    live.advance(10)
    live.guardian.check_space()
    assert "jail.pause" not in live.log
    assert live.actions() == before
    live.advance(2)
    live.guardian.check_watchdog()  # checked 2 s ago: not late
    assert "jail.pause" not in live.log


def test_a_condition_freezes_first_and_then_confirms_after_a_sync(live: World) -> None:
    gate = script(live, [P1])
    live.guardian.check_space()
    assert gate.calls == 2
    first = live.log.index("space.evaluate")
    pause = live.log.index("jail.pause")
    sync = live.log.index("btrfs.sync", pause)
    assert first < pause < sync < live.log.index("space.evaluate", sync)
    assert live.jail.paused
    assert live.guardian.agent_state is AgentState.FROZEN
    assert live.guardian.pause_reasons == {"space"}
    event = live.only("space_pause")
    assert (event.risk, event.details["conditions"], event.details["frozen"]) == (2, ["P1"], True)
    (alert,) = live.alerts.titled("pausado")
    assert alert.event_seq == event.seq
    assert "backtide seguir" in alert.body
    assert "no libera nada" in alert.body


def test_a_false_alarm_thaws_the_agent_and_is_counted_once_an_hour(live: World) -> None:
    script(live, [P1], [])
    live.guardian.check_space()
    assert live.log.count("jail.pause") == 1 and live.log.count("jail.unpause") == 1
    assert live.guardian.agent_state is AgentState.RUNNING
    assert live.guardian.pause_reasons == frozenset()
    assert not live.events("space_pause")
    assert live.alerts.sent == []
    live.advance(3601)
    live.guardian.check_space()
    report = live.only("space_check")
    assert report.details == {"transient_freezes": 1}
    live.advance(3601)
    live.guardian.check_space()
    assert len(live.events("space_check")) == 1  # nothing new to report


def test_a_false_alarm_does_not_thaw_if_a_pause_opened_meanwhile(live: World) -> None:
    def confirm_with_a_pause_opened() -> list[Violation]:
        live.guardian._pause([P3], freeze=True)  # noqa: SLF001 - the cycle, at that moment
        return []

    calls = [0]

    def scripted() -> list[Violation]:
        calls[0] += 1
        return [P1] if calls[0] == 1 else confirm_with_a_pause_opened()

    live.guardian._space = scripted  # noqa: SLF001
    live.guardian.check_space()
    assert "jail.unpause" not in live.log
    assert live.jail.paused
    assert live.guardian.pause_reasons == {"space"}


def test_many_false_alarms_alert_and_then_confirm_over_three_readings(live: World) -> None:
    for _ in range(7):
        script(live, [P1], [])
        live.guardian.check_space()
        live.advance(1)
    assert live.alerts.titled("falsas alarmas")
    gate = script(live, [P1], [P1], [P1], [P1])
    live.log.clear()
    live.guardian.check_space()
    assert gate.calls == 4  # the reading that fired, and three to confirm
    assert live.log.count("sleep(1.0)") == 2
    assert live.guardian.agent_state is AgentState.FROZEN


def test_a_standing_condition_with_the_agent_frozen_is_not_recorded_every_second(
    live: World,
) -> None:
    script(live, [P1])
    live.guardian.check_space()
    events = len(live.events())
    for _ in range(5):
        live.advance(1)
        live.guardian.check_space()
    assert live.log.count("jail.pause") == 1
    assert len(live.events()) == events


def test_a_stopped_agent_is_not_frozen(live: World) -> None:
    live.guardian.stop()
    live.guardian._serving = True  # noqa: SLF001 - only the state of the agent matters here
    live.log.clear()
    script(live, [P1])
    live.guardian.check_space()
    assert "jail.pause" not in live.log


def test_a_freeze_that_fails_kills_the_agent(live: World) -> None:
    live.jail.pause_error = JailError("docker pause failed")
    script(live, [P1])
    live.guardian.check_space()
    assert not live.jail.running
    assert live.guardian.agent_state is AgentState.STOPPED
    pause = live.only("space_pause")
    assert pause.risk == 3 and pause.details["killed"] is True
    assert live.only("agent_stop").details == {"reason": "freeze_failed"}


def test_a_gate_that_raises_freezes_the_agent(live: World) -> None:
    def broken() -> list[Violation]:
        raise OSError("sysfs went away")

    live.guardian._space = broken  # noqa: SLF001
    live.guardian.check_space()
    assert live.guardian.agent_state is AgentState.FROZEN
    assert live.only("space_pause").details["conditions"] == ["P4"]


def test_the_transaction_is_committed_every_5_s_only_if_the_workspace_changed(live: World) -> None:
    live.advance(6)
    live.guardian.check_space()
    assert "btrfs.sync" not in live.log  # nothing changed since the last commit
    live.volume.write()
    live.advance(2)
    live.guardian.check_space()
    assert "btrfs.sync" not in live.log  # not due yet
    live.advance(4)
    live.guardian.check_space()
    assert live.log.count("btrfs.sync") == 1


def test_a_failed_periodic_sync_is_p4(live: World) -> None:
    live.volume.write()
    live.advance(6)
    live.volume.sync_error = SnapshotError("btrfs filesystem sync failed")
    live.guardian.check_space()
    assert live.guardian.agent_state is AgentState.FROZEN
    assert "P4" in live.only("space_pause").details["conditions"]


def test_early_warnings_are_recorded_and_alerted_once_an_hour(live: World) -> None:
    w3 = Violation("W3", "workspace uses 60 MiB of its cap of 64 MiB")
    script(live, [w3])
    live.guardian.check_space()
    live.advance(10)
    live.guardian.check_space()
    low = live.only("space_low")
    assert (low.risk, low.details["condition"]) == (1, "W3")
    (alert,) = live.alerts.titled("poco espacio")
    assert alert.level is AlertLevel.WARNING
    assert "jail.pause" not in live.log
    live.advance(3601)
    live.guardian.check_space()
    assert len(live.events("space_low")) == 2


def test_the_alert_names_what_holds_the_space_and_the_snapshot_p3_passed_after(
    live: World, clock: Callable[[], datetime]
) -> None:
    undo = live.volume.listed[0]
    live.guardian._holders = lambda: [  # noqa: SLF001
        Holder("workspace", "workspace", 80 * 1024**2),
        Holder("snapshot", undo.id, 300 * 1024**2, taken_at=undo.taken_at, reason="pre_restore"),
        Holder("other", "0/300", 120 * 1024**2),
    ]
    script(live, [P3])
    live.guardian.check_space()
    (alert,) = live.alerts.titled("pausado")
    assert f"después de la instantánea {undo.id}" in alert.body
    assert f"punto de deshacer {undo.id}" in alert.body
    assert "0/300" in alert.body
    assert alert.body.index(undo.id + " (") < alert.body.index("0/300")


def test_holders_that_cannot_be_read_still_send_the_alert(live: World) -> None:
    def broken() -> list[Holder]:
        raise OSError("no sysfs")

    live.guardian._holders = broken  # noqa: SLF001
    script(live, [P1])
    live.guardian.check_space()
    (alert,) = live.alerts.titled("pausado")
    assert "No se ha podido leer qué ocupa el espacio" in alert.body


# --- the watchdog ------------------------------------------------------------------------------


def test_the_watchdog_freezes_the_agent_when_the_space_thread_is_late(live: World) -> None:
    live.advance(3.5)
    live.guardian.check_watchdog()
    assert live.guardian.agent_state is AgentState.FROZEN
    assert live.only("space_pause").details["conditions"] == ["P4"]
    # Its own reason: the space thread lifts it once it checks again (test_service_space_late.py).
    assert live.guardian.pause_reasons == {"late"}


def test_the_watchdog_leaves_a_stopped_agent_alone(live: World) -> None:
    live.guardian.stop()
    live.guardian._serving = True  # noqa: SLF001
    live.log.clear()
    live.advance(60)
    live.guardian.check_watchdog()
    assert "jail.pause" not in live.log


def test_the_watchdog_freezes_an_agent_that_never_had_a_check(running: World) -> None:
    running.guardian._last_check = None  # noqa: SLF001
    running.guardian.check_watchdog()
    assert running.guardian.agent_state is AgentState.RUNNING  # counted from the start
    running.advance(3.5)
    running.guardian.check_watchdog()
    assert running.guardian.agent_state is AgentState.FROZEN


def test_the_watchdog_counts_a_clock_that_went_backwards_as_late(live: World) -> None:
    live.advance(-5)
    live.guardian.check_watchdog()
    assert live.guardian.agent_state is AgentState.FROZEN


# --- P7: the black box -------------------------------------------------------------------------


def test_a_black_box_that_keeps_failing_pauses_with_its_own_reason(live: World) -> None:
    live.box.append_error = BlackBoxError("disk I/O error")
    for _ in range(3):
        live.guardian._record("system", "x")  # noqa: SLF001 - three failed appends
    live.advance(5)
    live.guardian.check_space()
    assert "jail.pause" not in live.log  # 3 failures, but for 5 s only
    live.advance(6)
    live.guardian.check_space()
    assert live.guardian.agent_state is AgentState.FROZEN
    assert live.guardian.pause_reasons == {"blackbox"}
    live.box.append_error = None
    outcome = live.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED  # the request's own append reset P7
    assert live.guardian.agent_state is AgentState.RUNNING


def test_a_successful_append_resets_the_streak(live: World) -> None:
    live.box.append_error = BlackBoxError("disk I/O error")
    for _ in range(3):
        live.guardian._record("system", "x")  # noqa: SLF001
    live.box.append_error = None
    live.guardian._record("system", "y")  # noqa: SLF001
    live.advance(20)
    live.guardian.check_space()
    assert "jail.pause" not in live.log


# --- resume (backtide seguir) ---------------------------------------------------------------------


@pytest.fixture
def frozen(live: World) -> World:
    script(live, [P1])
    live.guardian.check_space()
    assert live.guardian.agent_state is AgentState.FROZEN
    live.log.clear()
    return live


def test_resume_refuses_while_a_condition_stands(frozen: World) -> None:
    outcome = frozen.guardian.resume(requested_by="cli (uid 1, pid 2)")
    assert outcome.status is ResumeStatus.STILL_RED and outcome.exit_code == 1
    assert "metadatos" in outcome.message
    assert frozen.jail.paused and frozen.guardian.agent_state is AgentState.FROZEN
    assert frozen.guardian.pause_reasons == {"space"}
    refused = frozen.only("resume_refused")
    assert refused.details["conditions"] == ["P1"]
    assert refused.details["requested_by"] == "cli (uid 1, pid 2)"
    assert frozen.log.index("btrfs.sync") < frozen.log.index("space.evaluate")


def test_resume_thaws_the_agent_once_it_is_green(frozen: World) -> None:
    script(frozen, [])
    outcome = frozen.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED and outcome.exit_code == 0
    assert "jail.unpause" in frozen.log and "jail.start" not in frozen.log
    assert not frozen.jail.paused
    assert frozen.guardian.agent_state is AgentState.RUNNING
    assert frozen.guardian.pause_reasons == frozenset()
    resumed = frozen.only("space_resume")
    assert resumed.details == {
        "by": "user",
        "reasons": ["space"],
        "requested_by": "cli",
        "agent": "thawed",
    }
    assert frozen.actions().index("system/resume_requested") < frozen.actions().index(
        "system/space_resume"
    )


def test_resume_without_a_pause_does_nothing(live: World) -> None:
    outcome = live.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.NOT_PAUSED
    assert "jail.unpause" not in live.log and "space.evaluate" not in live.log
    assert not live.events("space_resume")


def test_resume_keeps_the_agent_paused_for_another_reason(frozen: World) -> None:
    # `seguir` closes the space pause and the person's own (T09, test_service_user_pause.py);
    # a reason it does not know stays.
    with frozen.guardian.freeze_lock:
        frozen.guardian._pause_reasons.add("other")  # noqa: SLF001
    script(frozen, [])
    outcome = frozen.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.STILL_PAUSED
    assert frozen.jail.paused
    assert frozen.guardian.pause_reasons == {"other"}
    assert frozen.only("space_resume").details["agent"] == "still_paused"


def test_resume_without_a_service_does_nothing(world: World) -> None:
    outcome = world.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.FAILED
    assert world.log == []


def test_a_frozen_agent_that_cannot_be_thawed_is_killed_and_started_again(frozen: World) -> None:
    frozen.jail.unpause_error = JailError("docker unpause failed")
    script(frozen, [])
    outcome = frozen.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED
    assert frozen.log.index("jail.kill") < frozen.log.index("jail.start")
    assert "jail.stop" not in frozen.log  # never woken by docker stop
    assert frozen.only("space_resume").details["agent"] == "restarted"
    assert frozen.guardian.agent_state is AgentState.RUNNING


def test_a_resumed_agent_that_does_not_start_is_a_problem(frozen: World) -> None:
    frozen.jail.unpause_error = JailError("docker unpause failed")
    frozen.jail.start_error = JailError("disk quota exceeded")
    script(frozen, [])
    outcome = frozen.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.PROBLEM and outcome.exit_code == 3
    assert frozen.only("agent_start_failed")
    assert frozen.guardian.pause_reasons == frozenset()  # the pause itself is closed


# --- a pause survives the service --------------------------------------------------------------


def second_guardian(world: World, tmp_path: Path, clock: Callable[[], datetime]) -> World:
    """A new Guardian on the same volume, jail and black box: the service started again."""
    log = world.log
    log.clear()
    world.box.close()
    box = FlakyBox(world.box._box)  # noqa: SLF001 - the same black box, reopened by start()
    alerts = Alerts()
    watcher = FakeWatcher(log)
    guardian = Guardian(
        world.config,
        store=world.volume,  # type: ignore[arg-type]
        jail=world.jail,  # type: ignore[arg-type]
        blackbox=box,  # type: ignore[arg-type]
        watcher=watcher,
        alerts=alerts,
        space=world.guardian._space,  # noqa: SLF001
        clock=clock,
        monotonic=lambda: world.mono[0],
        info=world.volume.info,
        sync=world.volume.sync,
        clock_synced=lambda: True,
    )
    return World(world.config, world.volume, world.jail, watcher, box, alerts, log, guardian)


def test_an_open_pause_keeps_the_agent_stopped_after_a_restart_until_seguir(
    frozen: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    script(frozen, [])  # green from now on: only the open pause keeps it paused
    frozen.guardian.stop()
    assert not frozen.jail.running
    again = second_guardian(frozen, tmp_path, clock)
    again.guardian.start()
    assert "jail.start" not in again.log
    assert again.guardian.agent_state is AgentState.STOPPED
    assert again.guardian.pause_reasons == {"space"}
    carried = again.events("space_pause")[-1]
    assert carried.details["carried_over"] is True
    (alert,) = again.alerts.titled("sigue pausado")
    assert "backtide seguir" in alert.body
    again.log.clear()
    outcome = again.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED
    arm = next(entry for entry in again.log if entry.startswith("watcher.arm("))
    assert again.log.index(arm) < again.log.index("jail.start")  # watched before it runs
    assert again.events("agent_start")[-1].details == {"reason": "resume"}
    assert again.guardian.agent_state is AgentState.RUNNING


def test_a_service_killed_with_the_agent_frozen_kills_it_at_boot_and_keeps_it_paused(
    frozen: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    """SIGKILL with the agent frozen: Docker still has it paused. The next boot kills it (never
    wakes it with docker stop) and the pause in the black box keeps it stopped."""
    script(frozen, [])
    assert frozen.jail.paused  # the service "dies" here: nothing is stopped
    again = second_guardian(frozen, tmp_path, clock)
    again.guardian.start()
    assert again.log[0] == "jail.kill"
    assert "jail.stop" not in again.log and "jail.start" not in again.log
    assert again.only("agent_stop").details == {"reason": "unsupervised"}
    assert again.guardian.pause_reasons == {"space"}
    assert not again.jail.running and not again.jail.paused


def test_a_rewind_that_ends_green_closes_the_pause_for_the_next_boot_too(
    frozen: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    script(frozen, [])
    outcome = frozen.guardian.rewind(frozen.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.DONE and outcome.agent_started
    frozen.guardian.stop()
    again = second_guardian(frozen, tmp_path, clock)
    again.guardian.start()
    assert "jail.start" in again.log
    assert again.guardian.pause_reasons == frozenset()


def test_a_rewind_of_a_frozen_agent_never_leaves_a_frozen_container(frozen: World) -> None:
    """restore() needs the agent stopped, not frozen: quiesce kills it, and if the space is
    still red afterwards it stays stopped (not paused), with the pause open."""
    outcome = frozen.guardian.rewind(frozen.volume.listed[0].id, requested_by="cli")
    assert outcome.rewound and not outcome.agent_started
    assert frozen.log.index("store.restore") < frozen.log.index("jail.kill")
    assert "jail.stop" not in frozen.log
    assert not frozen.jail.running and not frozen.jail.paused
    assert frozen.guardian.agent_state is AgentState.STOPPED
    assert frozen.guardian.pause_reasons == {"space"}
    script(frozen, [])
    assert frozen.guardian.resume(requested_by="cli").status is ResumeStatus.RESUMED
    assert frozen.jail.running and not frozen.jail.paused


def test_a_rewind_during_a_freeze_to_confirm_starts_the_agent_again(live: World) -> None:
    """The space thread froze the agent to confirm a condition (no reason is open yet) and a
    rewind comes in: the agent was running, so it runs after the rewind. It is not left stopped
    with nothing written down, where `backtide seguir` would say there is nothing to resume."""
    epoch = live.guardian._freeze_to_confirm()  # noqa: SLF001 - the space thread, mid-confirmation
    assert isinstance(epoch, int) and live.guardian.pause_reasons == frozenset()
    script(live, [])
    outcome = live.guardian.rewind(live.volume.listed[0].id, requested_by="cli")
    assert outcome.rewound and outcome.agent_started
    assert live.jail.running and not live.jail.paused
    assert live.guardian.agent_state is AgentState.RUNNING
    live.log.clear()
    live.guardian._thaw_after_false_alarm(epoch)  # noqa: SLF001 - the freeze is no longer ours
    assert "jail.unpause" not in live.log
    assert live.guardian.agent_state is AgentState.RUNNING


def test_a_rewind_during_a_freeze_to_confirm_with_red_space_leaves_a_pause_to_close(
    live: World,
) -> None:
    live.guardian._freeze_to_confirm()  # noqa: SLF001
    script(live, [P1])
    outcome = live.guardian.rewind(live.volume.listed[0].id, requested_by="cli")
    assert outcome.rewound and not outcome.agent_started
    assert not live.jail.running
    assert live.guardian.pause_reasons == {"space"}  # the reason is written down
    script(live, [])
    assert live.guardian.resume(requested_by="cli").status is ResumeStatus.RESUMED
    assert live.jail.running


def test_a_rewind_of_a_freeze_that_was_not_a_confirmation_is_unchanged(live: World) -> None:
    """A frozen agent that is not mid-confirmation (a stopped agent, here) is not started."""
    live.guardian._set_state(AgentState.STOPPED)  # noqa: SLF001
    live.jail.running = False
    outcome = live.guardian.rewind(live.volume.listed[0].id, requested_by="cli")
    assert outcome.rewound and not outcome.agent_started
    assert not live.jail.running


def test_resume_of_an_agent_stopped_with_no_pause_says_what_to_do(live: World) -> None:
    """Nothing is paused by space and the agent is stopped: `backtide seguir` does not say "nothing
    to resume" as if all were well; it says the agent is stopped and how to get it back."""
    live.guardian._set_state(AgentState.STOPPED)  # noqa: SLF001
    live.jail.running = False
    outcome = live.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.STOPPED
    assert outcome.exit_code == 1
    assert "parado" in outcome.message and "backtide vigilar" in outcome.message
    assert "jail.start" not in live.log  # it is not started behind anybody's back


def test_resume_of_a_running_agent_with_no_pause_still_has_nothing_to_resume(live: World) -> None:
    outcome = live.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.NOT_PAUSED and outcome.exit_code == 0


# --- the threads in run() ----------------------------------------------------------------------


def test_run_ticks_the_space_threads_and_ends_them_before_stopping_the_agent(
    world: World,
) -> None:
    world.guardian._tick = 0.01  # noqa: SLF001
    checked = threading.Event()
    original = world.guardian.check_space

    def counting() -> None:
        original()
        if world.guardian._serving:  # noqa: SLF001
            checked.set()

    world.guardian.check_space = counting  # type: ignore[method-assign]
    stop = threading.Event()
    runner = threading.Thread(target=world.guardian.run, args=(stop,))
    runner.start()
    assert checked.wait(5)
    stop.set()
    runner.join(10)
    assert not runner.is_alive()
    names = {thread.name for thread in threading.enumerate()}
    assert "backtide-space" not in names and "backtide-space-guard" not in names
    assert world.guardian.agent_state is AgentState.STOPPED


def test_no_gate_no_threads(world: World) -> None:
    world.guardian._space = None  # noqa: SLF001
    assert world.guardian._space_threads() == []  # noqa: SLF001


# --- review of T04d-2 --------------------------------------------------------------------------


def test_a_frozen_agent_being_rewound_is_not_frozen_again_nor_killed_twice(frozen: World) -> None:
    """Rewinding a frozen agent must not turn it into "stopping" (an agent that runs code): the
    space thread would try to freeze it again, fail, and kill it in parallel with the rewind."""
    seen: list[AgentState] = []

    def tick_during_the_rewind() -> None:
        seen.append(frozen.guardian.agent_state)
        script(frozen, [P1])
        frozen.guardian.check_space()

    frozen.volume.during_swap = tick_during_the_rewind
    frozen.jail.on_stop = tick_during_the_rewind
    frozen.guardian.rewind(frozen.volume.listed[0].id, requested_by="cli")
    assert frozen.log.count("jail.kill") == 1
    assert "jail.pause" not in frozen.log and "jail.remove" not in frozen.log
    assert not [e for e in frozen.events("space_pause") if e.details.get("killed")]


def test_a_pause_that_fails_because_it_is_paused_already_counts_as_frozen(live: World) -> None:
    def already() -> None:
        live.jail.paused = True
        raise JailError("container is already paused")

    live.jail.pause = already  # type: ignore[method-assign]
    script(live, [P1])
    live.guardian.check_space()
    assert live.jail.running and "jail.kill" not in live.log
    assert live.guardian.agent_state is AgentState.FROZEN
    assert live.only("space_pause").risk == 2


def test_a_failed_freeze_is_alerted_even_right_after_a_pause_alert(frozen: World) -> None:
    script(frozen, [])
    frozen.guardian.resume(requested_by="cli")
    frozen.jail.pause_error = JailError("docker pause failed")
    frozen.jail.cannot_stop()
    script(frozen, [P1])
    frozen.guardian.check_space()
    assert frozen.alerts.titled("No se pudo congelar ni parar")


def test_a_new_pause_after_seguir_is_alerted_at_once(frozen: World) -> None:
    script(frozen, [])
    frozen.guardian.resume(requested_by="cli")
    before = len(frozen.alerts.titled("pausado"))
    script(frozen, [P1])
    frozen.guardian.check_space()
    assert len(frozen.alerts.titled("pausado")) == before + 1


def test_an_agent_found_running_while_stopped_is_restarted_watched_on_resume(
    live: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    with live.guardian.freeze_lock:
        live.guardian._pause_reasons.add("space")  # noqa: SLF001
    live.guardian._set_state(AgentState.STOPPED)  # noqa: SLF001 - ours says stopped...
    live.jail.running = True  # ...and somebody started it behind our back
    script(live, [])
    outcome = live.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED
    assert live.log.index("jail.kill") < live.log.index("jail.start")
    assert "jail.stop" not in live.log  # unwatched: no 30 s of SIGTERM grace
    assert live.only("space_resume").details["agent"] == "started"


def test_without_a_gate_the_boot_records_that_space_is_not_watched(world: World) -> None:
    world.guardian._space = None  # noqa: SLF001 - no workspace_limit configured
    world.guardian.start()
    unwatched = world.only("space_unwatched")
    assert unwatched.risk == 2 and unwatched.details == {"reason": "no_workspace_limit"}
    assert world.alerts.titled("no se vigila")
    assert "jail.start" in world.log  # it still runs, as before T04d-2


def test_with_a_gate_nothing_says_it_is_unwatched(running: World) -> None:
    assert not running.events("space_unwatched")
