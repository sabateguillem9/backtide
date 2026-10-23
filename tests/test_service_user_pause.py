"""The person's pause in the Guardian (T09, Telegram's `/pausar`), with the fakes of
test_service_guardian.py: it freezes at once without waiting for anyone, it holds through the
space thread, a rewind and a restart, and `seguir` closes it.

The real `docker pause` from Telegram is in the VM battery (tests/attacks)."""

# The fixtures of test_service_guardian.py are imported and then named as parameters.
# ruff: noqa: F811

import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest
from test_service_guardian import (  # noqa: F401 - fixtures, used by name
    FakeWatcher,
    Violation,
    World,
    no_leftover_bridge,
    rewinding,
    running,
    world,
)
from test_service_space_thread import second_guardian

from backtide.jail import JailError
from backtide.service.guardian import AgentState
from backtide.service.pause import PauseStatus, ResumeStatus
from backtide.service.rewind import RewindStatus

P1 = Violation("P1", "metadatos: quedan 100 MiB, mínimo 341 MiB")


def pause(world: World) -> object:
    return world.guardian.pause_by_user(requested_by="telegram")


def test_pausar_freezes_a_running_agent_and_records_it(running: World) -> None:
    outcome = pause(running)
    assert outcome.status is PauseStatus.FROZEN and outcome.held and not outcome.already
    assert running.log == ["jail.pause"]  # nothing before the freeze: no sync, no lock
    assert running.jail.paused
    assert running.guardian.agent_state is AgentState.FROZEN
    assert running.guardian.pause_reasons == {"user"}
    event = running.only("user_pause")
    assert event.risk == 1
    assert event.details == {
        "requested_by": "telegram",
        "agent_before": "running",
        "agent": "frozen",
        "already": False,
    }
    assert running.alerts.sent == []  # the person asked: the answer goes back to them


def test_pausar_never_waits_for_the_agent_lock(running: World) -> None:
    done = threading.Event()
    with running.guardian.agent_lock:  # a rewind or a long `docker stop` holds it
        worker = threading.Thread(target=lambda: (pause(running), done.set()))
        worker.start()
        assert done.wait(2.0), "the pause waited for agent_lock"
    worker.join()
    assert running.jail.paused


def test_pausar_twice_freezes_once(running: World) -> None:
    pause(running)
    again = running.guardian.pause_by_user(requested_by="telegram")
    assert again.status is PauseStatus.FROZEN and again.already
    assert running.log.count("jail.pause") == 1
    assert "ya estaba congelado" in again.message


def test_the_space_thread_never_thaws_the_persons_pause(running: World) -> None:
    pause(running)
    running.guardian.check_space()  # green
    running.guardian.check_watchdog()
    running.violations[:] = [P1]
    running.guardian.check_space()  # red: an agent already frozen is not touched
    assert "jail.unpause" not in running.log
    assert running.jail.paused and running.guardian.pause_reasons == {"user"}


def test_seguir_closes_the_persons_pause_and_thaws(running: World) -> None:
    pause(running)
    running.log.clear()
    outcome = running.guardian.resume(requested_by="telegram")
    assert outcome.status is ResumeStatus.RESUMED
    assert "jail.unpause" in running.log and not running.jail.paused
    assert running.guardian.agent_state is AgentState.RUNNING
    assert running.guardian.pause_reasons == frozenset()
    paused = running.only("user_pause")
    assert running.only("user_resume").details == {
        "requested_by": "telegram",
        "agent": "thawed",
        "closes": paused.seq,
    }
    assert not running.events("space_resume")  # the space pause was never open


def test_seguir_refuses_while_space_is_red_and_keeps_the_pause(running: World) -> None:
    pause(running)
    running.violations[:] = [P1]
    outcome = running.guardian.resume(requested_by="telegram")
    assert outcome.status is ResumeStatus.STILL_RED
    assert running.jail.paused and running.guardian.pause_reasons == {"user"}
    assert not running.events("user_resume")


def test_seguir_closes_both_pauses_when_green(running: World) -> None:
    running.violations[:] = [P1]
    running.guardian.check_space()  # the space pause opens and freezes
    pause(running)
    running.violations.clear()
    outcome = running.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED
    assert running.only("space_resume").details["reasons"] == ["space"]
    assert running.only("user_resume").details["requested_by"] == "cli"


def test_a_stopped_agent_stays_stopped_and_seguir_starts_it(world: World) -> None:
    world.violations[:] = [P1]
    world.guardian.start()  # red at boot: the agent never starts
    outcome = pause(world)
    assert outcome.status is PauseStatus.STOPPED
    assert "jail.pause" not in world.log
    world.violations.clear()
    world.log.clear()
    assert world.guardian.resume(requested_by="telegram").status is ResumeStatus.RESUMED
    assert "jail.start" in world.log


def test_an_agent_that_cannot_be_frozen_is_killed(running: World) -> None:
    running.jail.pause_error = JailError("docker pause failed")
    outcome = pause(running)
    assert outcome.status is PauseStatus.KILLED and outcome.held
    assert not running.jail.running
    assert running.guardian.agent_state is AgentState.STOPPED
    assert running.only("user_pause").details["killed"] is True
    stop = running.only("agent_stop")
    assert stop.details == {"reason": "user_pause_freeze_failed"}


def test_an_agent_that_can_be_neither_frozen_nor_stopped_is_the_worst_case(
    running: World,
) -> None:
    running.jail.pause_error = JailError("docker pause failed")
    running.jail.kill_error = JailError("docker kill failed")
    running.jail.stop_error = JailError("docker stop failed")
    running.jail.remove_error = JailError("docker rm failed")
    outcome = pause(running)
    assert outcome.status is PauseStatus.STILL_RUNNING and not outcome.held
    assert "SIGUE EN MARCHA" in outcome.message
    assert running.only("user_pause").risk == 3
    assert running.only("agent_stop_failed").risk == 3
    (alert,) = running.alerts.titled("No se pudo congelar ni parar")
    assert alert.event_seq is not None


def test_without_a_service_nothing_is_paused(world: World) -> None:
    outcome = pause(world)
    assert outcome.status is PauseStatus.FAILED
    assert world.log == []


def test_a_rewind_during_the_pause_leaves_the_agent_stopped(rewinding: World) -> None:
    first = rewinding.volume.snapshots()[0].id
    pause(rewinding)
    outcome = rewinding.guardian.rewind(first, requested_by="telegram")
    assert outcome.status is RewindStatus.DONE
    assert "jail.kill" in rewinding.log  # frozen: killed, never woken by a stop
    assert "jail.start" not in rewinding.log
    assert rewinding.guardian.agent_state is AgentState.STOPPED
    assert rewinding.guardian.pause_reasons == {"user"}
    assert rewinding.guardian.resume(requested_by="telegram").status is ResumeStatus.RESUMED
    assert rewinding.jail.running


def test_a_pause_while_the_agent_starts_is_caught_up_after_the_start(world: World) -> None:
    """`/pausar` while `docker start` runs: there is nothing to freeze yet. Once it is up,
    the Guardian freezes it."""

    def pause_in_the_middle() -> None:
        with world.guardian.freeze_lock:
            world.guardian._pause_reasons.add("user")  # noqa: SLF001 - as if it raced the start

    world.jail.on_wait_ready = pause_in_the_middle
    world.guardian.start()
    assert world.jail.paused
    assert world.guardian.agent_state is AgentState.FROZEN
    late = world.events("user_pause")[-1]
    assert late.details["late"] is True and late.details["requested_by"] == "catch_up"


def test_no_start_while_the_persons_pause_is_open(running: World) -> None:
    pause(running)
    running.jail.running = False  # say the agent died meanwhile
    with running.guardian.freeze_lock:
        running.guardian._agent_state = AgentState.STOPPED  # noqa: SLF001
    running.log.clear()
    running.guardian._start_agent(reason="resume")  # noqa: SLF001 - e.g. a resume that raced
    assert "jail.start" not in running.log
    assert running.only("agent_start_skipped").details == {"reason": "user_pause"}


def test_the_pause_survives_a_restart_until_seguir(
    running: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    pause(running)
    running.guardian.stop()
    again = second_guardian(running, tmp_path, clock)
    again.guardian.start()
    assert "jail.start" not in again.log
    assert again.guardian.pause_reasons == {"user"}
    carried = again.events("user_pause")[-1]
    assert carried.details["carried_over"] is True
    assert not again.events("space_pause")  # a user pause is not a space pause
    (alert,) = again.alerts.titled("sigue pausado")
    assert "lo pediste tú" in alert.body
    assert again.guardian.resume(requested_by="telegram").status is ResumeStatus.RESUMED
    assert "jail.start" in again.log
    third = second_guardian(again, tmp_path, clock)
    again.guardian.stop()
    third.guardian.start()
    assert third.guardian.pause_reasons == frozenset()  # closed for good


@pytest.mark.parametrize("state", [AgentState.STOPPING])
def test_an_agent_being_stopped_is_killed_not_frozen(running: World, state: AgentState) -> None:
    with running.guardian.freeze_lock:
        running.guardian._agent_state = state  # noqa: SLF001 - `docker stop` in flight
    outcome = pause(running)
    assert outcome.status is PauseStatus.KILLED
    assert "jail.pause" not in running.log
    assert running.only("agent_stop").details == {"reason": "user_pause_while_stopping"}


def test_the_watcher_fake_is_untouched_by_a_pause(running: World) -> None:
    pause(running)
    assert isinstance(running.watcher, FakeWatcher)
    assert not any(entry.startswith("watcher.") for entry in running.log)


def test_a_pausar_after_a_seguir_wins_even_if_the_seguir_runs_later(running: World) -> None:
    """`/seguir`, then `/pausar` while the seguir waits for agent_lock (a cycle, a rewind):
    the late seguir must not undo the later pause."""
    pause(running)
    mark = running.guardian.user_pause_mark()  # when the person sent /seguir
    pause(running)  # ...and then /pausar, while the seguir is still waiting
    outcome = running.guardian.resume(requested_by="telegram", pause_mark=mark)
    assert outcome.status is ResumeStatus.STILL_PAUSED
    assert running.jail.paused and running.guardian.pause_reasons == {"user"}
    assert not running.events("user_resume")
    assert running.events("resume_refused")[-1].details["reason"] == "paused_after"


def test_a_cli_seguir_that_waited_for_the_lock_does_not_undo_a_later_pausar(
    running: World,
) -> None:
    pause(running)
    marked = threading.Event()
    real_mark = running.guardian.user_pause_mark

    def mark_and_tell() -> int:
        try:
            return real_mark()
        finally:
            marked.set()  # the seguir has its mark: a /pausar from now on is a later one

    running.guardian.user_pause_mark = mark_and_tell  # type: ignore[method-assign]
    finished = threading.Event()
    with running.guardian.agent_lock:  # the CLI's seguir waits here
        worker = threading.Thread(
            target=lambda: (running.guardian.resume(requested_by="cli"), finished.set())
        )
        worker.start()
        # Not a sleep: a seguir that had not taken its mark yet would see this /pausar as an
        # earlier one, and rightly undo it (a slow machine did not give it the time).
        assert marked.wait(5)
        pause(running)  # /pausar meanwhile
    assert finished.wait(5)
    worker.join()
    assert running.jail.paused and running.guardian.pause_reasons == {"user"}


def test_a_pause_reopened_during_a_resume_survives_a_restart(
    running: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    pause(running)
    real_unpause = running.jail.unpause
    real_resumed = running.guardian._record_resumed  # noqa: SLF001
    pausing: list[threading.Thread] = []

    def unpause_then_pausar() -> None:
        real_unpause()
        # /pausar right after the thaw: a new user_pause after the one the resume closes
        pausing.append(threading.Thread(target=lambda: pause(running)))
        pausing[0].start()

    def resumed_after_the_pausar(*args: object, **kwargs: object) -> object:
        # The /pausar is in the box before the user_resume that closes the older pause: the
        # order a restart must not be fooled by, every time (a sleep made it only likely, and
        # on a slow machine the /pausar was not even recorded when this test looked).
        pausing[0].join(5)
        return real_resumed(*args, **kwargs)

    running.jail.unpause = unpause_then_pausar  # type: ignore[method-assign]
    running.guardian._record_resumed = resumed_after_the_pausar  # type: ignore[method-assign]  # noqa: SLF001
    running.guardian.resume(requested_by="telegram")
    assert pausing and not pausing[0].is_alive()
    closed = running.only("user_resume").details["closes"]
    assert max(e.seq for e in running.events("user_pause")) > closed
    running.guardian.stop()
    again = second_guardian(running, tmp_path, clock)
    again.guardian.start()
    assert again.guardian.pause_reasons == {"user"}
    assert "jail.start" not in again.log
