"""A late space check (docs/19, section 5, "El retraso"): the watchdog freezes the agent when the
space thread has not checked for 3 s, as before. What changed (from the founder's first real
Ollama test, 2026-10-23): when lateness is the only cause, the pause (reason ``late``) is lifted
by the space thread itself as soon as it checks again, after a sync, and every condition is
clear; the freeze and the thaw are both in the black box. Everything else stays manual:

- a real space condition seen while the late pause is open turns it into a manual one;
- other blind causes (a gate that raises, a failed sync) were never ``late``;
- the third late check within 10 minutes is a manual pause from the start;
- the person's own pause, a freeze that failed, or anything that changed the agent's state since
  the freeze keep it as it is;
- nothing thaws the agent while the thread is not checking.

With the fakes and the monotonic clock of test_service_guardian.py, as
test_service_space_thread.py does.
"""

# The fixtures of test_service_guardian.py are imported and then named as parameters.
# ruff: noqa: F811

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest
from test_service_guardian import (  # noqa: F401 - fixtures, used by name
    Violation,
    World,
    no_leftover_bridge,
    running,
    world,
)
from test_service_space_thread import P1, live, script, second_guardian  # noqa: F401

from backtide.jail import JailError
from backtide.notify import AlertLevel
from backtide.service.guardian import (
    LATE_HOUR,
    LATE_HOUR_MAX,
    LATE_MANUAL_AFTER,
    LATE_STUCK_AFTER,
    LATE_WINDOW,
    AgentState,
)
from backtide.service.pause import ResumeStatus


def late(world: World, seconds: float = 4.1) -> None:
    """The space thread does not check for ``seconds``: the watchdog sees it."""
    world.advance(seconds)
    world.guardian.check_watchdog()


@pytest.fixture
def lagged(live: World) -> World:
    """A running agent frozen once by a late space check."""
    late(live)
    assert live.guardian.agent_state is AgentState.FROZEN
    return live


def test_a_late_check_freezes_the_agent_with_a_pause_of_its_own(lagged: World) -> None:
    assert lagged.jail.paused
    assert lagged.guardian.pause_reasons == {"late"}
    pause = lagged.only("space_pause")
    assert pause.risk == 2
    assert pause.details["conditions"] == ["P4"] and pause.details["reasons"] == ["late"]
    assert pause.details["late"] is True and pause.details["auto_resume"] is True
    assert pause.details["frozen"] is True
    (alert,) = lagged.alerts.titled("congelado")
    assert alert.level is AlertLevel.WARNING and alert.event_seq == pause.seq
    assert "4.1 s" in alert.body and "sigue solo" in alert.body
    assert "borra puntos de deshacer" not in alert.body  # it is not about space
    assert pause.details["age_s"] == 4.1
    assert lagged.guardian.late_pause_lifts


def test_the_next_green_check_thaws_it_after_a_sync_and_says_so(lagged: World) -> None:
    lagged.log.clear()
    lagged.guardian.check_space()
    assert not lagged.jail.paused
    assert lagged.guardian.agent_state is AgentState.RUNNING
    assert lagged.guardian.pause_reasons == frozenset()
    # A fresh reading after a sync, as `backtide seguir` does, before the agent runs again.
    sync = lagged.log.index("btrfs.sync")
    assert sync < lagged.log.index("space.evaluate", sync) < lagged.log.index("jail.unpause")
    resumed = lagged.only("space_resume")
    assert resumed.details == {
        "by": "space_thread",
        "reasons": ["late"],
        "agent": "thawed",
        "pause": lagged.only("space_pause").seq,
    }
    assert lagged.actions().index("system/space_pause") < lagged.actions().index(
        "system/space_resume"
    )
    lagged.advance(2)
    lagged.guardian.check_watchdog()  # the thaw's own check counts: not late again
    assert lagged.guardian.agent_state is AgentState.RUNNING


def test_nothing_thaws_it_while_the_thread_does_not_check(lagged: World) -> None:
    for _ in range(30):
        late(lagged, 1.0)
    assert lagged.jail.paused and lagged.guardian.pause_reasons == {"late"}
    assert not lagged.events("space_resume")


def test_a_red_reading_after_the_sync_does_not_thaw(lagged: World) -> None:
    script(lagged, [], [P1], [])  # green, then red after the sync: not this time
    lagged.guardian.check_space()
    assert lagged.jail.paused and lagged.guardian.pause_reasons == {"late"}
    assert not lagged.events("space_resume")


def test_a_real_condition_during_the_late_pause_makes_it_manual(lagged: World) -> None:
    script(lagged, [P1])
    lagged.guardian.check_space()
    assert lagged.guardian.pause_reasons == {"late", "space"}
    assert lagged.jail.paused
    confirmed = lagged.events("space_pause")[-1]
    assert confirmed.details["conditions"] == ["P1"] and confirmed.details["frozen"] is True
    script(lagged, [])  # the space comes back: still paused, `seguir` is needed
    lagged.guardian.check_space()
    lagged.guardian.check_space()
    assert lagged.jail.paused and not lagged.events("space_resume")
    outcome = lagged.guardian.resume(requested_by="cli")
    assert outcome.status is ResumeStatus.RESUMED
    assert lagged.only("space_resume").details["reasons"] == ["late", "space"]
    assert lagged.guardian.agent_state is AgentState.RUNNING


def test_an_unconfirmed_red_reading_during_the_late_pause_leaves_it_as_it_was(
    lagged: World,
) -> None:
    script(lagged, [P1], [])  # red, then green after the sync: a false alarm
    lagged.guardian.check_space()
    assert lagged.guardian.pause_reasons == {"late"}
    lagged.guardian.check_space()
    assert lagged.guardian.agent_state is AgentState.RUNNING


def test_the_third_late_check_in_ten_minutes_is_a_manual_pause(live: World) -> None:
    for _ in range(LATE_MANUAL_AFTER - 1):
        late(live)
        live.guardian.check_space()
        assert live.guardian.agent_state is AgentState.RUNNING
    late(live)
    assert live.guardian.pause_reasons == {"space"}
    pause = live.events("space_pause")[-1]
    assert pause.details["late"] is True and pause.details["auto_resume"] is False
    assert pause.details["lates"] == LATE_MANUAL_AFTER
    alert = live.alerts.sent[-1]
    assert alert.level is AlertLevel.ERROR and "backtide seguir" in alert.body
    live.guardian.check_space()
    assert live.jail.paused  # green, but manual
    assert live.guardian.resume(requested_by="cli").status is ResumeStatus.RESUMED


def test_late_checks_ten_minutes_apart_are_not_counted_together(live: World) -> None:
    assert LATE_WINDOW == 600.0 and LATE_MANUAL_AFTER == 3
    for _ in range(5):
        late(live)
        assert live.guardian.pause_reasons == {"late"}
        live.guardian.check_space()
        assert live.guardian.agent_state is AgentState.RUNNING
        live.advance(LATE_WINDOW / 2 + 1)
        live.guardian.check_space()
    assert len(live.events("space_resume")) == 5


def test_the_persons_pause_during_the_late_pause_keeps_it(lagged: World) -> None:
    lagged.guardian.pause_by_user(requested_by="telegram")
    assert lagged.guardian.pause_reasons == {"late", "user"}
    lagged.guardian.check_space()
    assert lagged.jail.paused and not lagged.events("space_resume")


def test_a_late_freeze_that_failed_never_starts_the_agent_on_its_own(live: World) -> None:
    live.jail.pause_error = JailError("docker pause failed")
    late(live)
    assert live.guardian.agent_state is AgentState.STOPPED  # killed instead
    live.log.clear()
    live.guardian.check_space()
    assert "jail.start" not in live.log and "jail.unpause" not in live.log
    assert live.guardian.agent_state is AgentState.STOPPED
    assert live.guardian.pause_reasons  # `seguir` decides


def test_a_change_of_state_since_the_freeze_keeps_it(lagged: World) -> None:
    lagged.guardian._set_state(AgentState.FROZEN)  # noqa: SLF001 - someone else's freeze
    lagged.guardian.check_space()
    assert lagged.jail.paused and not lagged.events("space_resume")


def test_a_thaw_that_fails_is_a_manual_pause_and_said(lagged: World) -> None:
    lagged.jail.unpause_error = JailError("docker unpause failed")
    lagged.guardian.check_space()
    assert lagged.guardian.pause_reasons == {"late", "space"}  # not only late: manual
    pause = lagged.events("space_pause")[-1]
    assert pause.details["conditions"] == ["P4"] and "late" not in pause.details
    assert not lagged.events("space_resume")
    assert lagged.alerts.titled("pausado")


def test_other_blind_causes_stay_manual(live: World) -> None:
    def broken() -> list[Violation]:
        raise OSError("cannot read /sys")

    live.guardian._space = broken  # noqa: SLF001
    live.guardian.check_space()
    assert live.guardian.pause_reasons == {"space"}
    script(live, [])
    live.guardian.check_space()
    assert live.jail.paused and not live.events("space_resume")


def test_a_late_pause_carried_over_a_restart_waits_for_seguir(
    lagged: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    lagged.guardian.stop()
    again = second_guardian(lagged, tmp_path, clock)
    again.guardian.start()
    assert "jail.start" not in again.log
    assert again.guardian.pause_reasons == {"late"}
    again.guardian.check_space()
    assert again.guardian.agent_state is AgentState.STOPPED
    assert again.guardian.resume(requested_by="cli").status is ResumeStatus.RESUMED


def test_a_late_pause_lifted_is_closed_for_the_next_boot_too(
    lagged: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    lagged.guardian.check_space()
    assert lagged.guardian.agent_state is AgentState.RUNNING
    lagged.guardian.stop()
    again = second_guardian(lagged, tmp_path, clock)
    again.guardian.start()
    assert again.guardian.pause_reasons == frozenset()
    assert again.guardian.agent_state is AgentState.RUNNING


def test_the_space_threads_resume_closes_only_the_late_pause_it_names(
    live: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    """Read back at boot: a space_resume of the space thread never closes another pause, nor a
    late one it does not name (the boot fails closed)."""
    box = live.guardian._record  # noqa: SLF001 - the events as the Guardian writes them
    manual = box("system", "space_pause", details={"conditions": ["P1"], "reasons": ["space"]})
    box("system", "space_resume", details={"by": "space_thread", "pause": manual.seq})
    other = box("system", "space_pause", details={"conditions": ["P4"], "reasons": ["late"]})
    box("system", "space_resume", details={"by": "space_thread", "pause": other.seq + 1000})
    live.guardian.stop()
    again = second_guardian(live, tmp_path, clock)
    again.guardian.start()
    assert again.guardian.pause_reasons == {"space", "late"}
    assert "jail.start" not in again.log


# --- after the security review --------------------------------------------------------------------


def test_lateness_spaced_out_on_purpose_hits_the_hourly_budget(live: World) -> None:
    """Late checks about 5 minutes apart never make 3 in 10 minutes; more than LATE_HOUR_MAX in
    an hour is a manual pause too."""
    assert (LATE_HOUR, LATE_HOUR_MAX) == (3600.0, 6)
    for _ in range(LATE_HOUR_MAX):
        late(live)
        assert live.guardian.pause_reasons == {"late"}
        live.guardian.check_space()
        assert live.guardian.agent_state is AgentState.RUNNING
        live.advance(LATE_WINDOW / 2 + 1)  # 301 s: never 3 within 10 minutes
        live.guardian.check_space()
    late(live)  # the 7th within the hour
    assert live.guardian.pause_reasons == {"space"}
    pause = live.events("space_pause")[-1]
    assert pause.details["auto_resume"] is False and pause.details["lates_hour"] == 7
    live.guardian.check_space()
    assert live.jail.paused and not live.guardian.late_pause_lifts
    assert "en una hora" in live.alerts.sent[-1].body


def test_a_late_freeze_that_meets_a_freeze_to_confirm_is_said_to_be_manual(live: World) -> None:
    """The race: between the watchdog's look and its freeze, the space thread froze the agent to
    confirm a reading. The late reason is added to an agent this call did not freeze, so the
    pause cannot lift by itself, and nothing may say it will."""
    guardian = live.guardian
    original = guardian._freeze  # noqa: SLF001

    def racing(*args: object, **kwargs: object) -> object:
        assert guardian._freeze_to_confirm()  # noqa: SLF001 - the space thread, a moment before
        return original(*args, **kwargs)  # type: ignore[arg-type]

    guardian._freeze = racing  # type: ignore[method-assign]  # noqa: SLF001
    late(live)
    guardian._freeze = original  # type: ignore[method-assign]  # noqa: SLF001
    assert guardian.pause_reasons == {"late"} and not guardian.late_pause_lifts
    pause = live.events("space_pause")[-1]
    assert pause.details["auto_resume"] is False and pause.details["frozen"] is True
    alert = live.alerts.sent[-1]
    assert alert.level is AlertLevel.ERROR
    assert "sigue solo" not in alert.body and "backtide seguir" in alert.body
    live.guardian.check_space()
    assert live.jail.paused and not live.events("space_resume")


def test_a_late_pause_that_lasts_a_minute_is_escalated(lagged: World) -> None:
    """The space thread never comes back (a hung sync): the watchdog, which has no I/O of its
    own, says so after LATE_STUCK_AFTER s and the pause stops lifting by itself."""
    assert LATE_STUCK_AFTER == 60.0
    late(lagged, 30)
    assert lagged.guardian.late_pause_lifts and not lagged.alerts.titled("no vuelve")
    late(lagged, 31)
    assert not lagged.guardian.late_pause_lifts
    assert lagged.guardian.pause_reasons == {"late", "space"}
    (alert,) = lagged.alerts.titled("no vuelve")
    assert alert.level is AlertLevel.ERROR and "backtide seguir" in alert.body
    stuck = lagged.events("space_pause")[-1]
    assert stuck.details["stuck"] is True and stuck.details["frozen"] is True
    late(lagged, 10)
    assert len(lagged.alerts.titled("no vuelve")) == 1  # once
    lagged.guardian.check_space()  # the thread comes back: still `seguir`
    assert lagged.jail.paused and not lagged.events("space_resume")


def test_a_thaw_that_cannot_be_recorded_is_said(lagged: World) -> None:
    guardian = lagged.guardian
    original = guardian._record  # noqa: SLF001

    def no_resume(source: str, action: str, *args: object, **kwargs: object) -> object:
        if action == "space_resume":
            return None  # the black box did not take it
        return original(source, action, *args, **kwargs)  # type: ignore[arg-type]

    guardian._record = no_resume  # type: ignore[method-assign]  # noqa: SLF001
    guardian.check_space()
    assert guardian.agent_state is AgentState.RUNNING  # it was thawed before the record
    (alert,) = lagged.alerts.titled("no se ha grabado")
    assert alert.level is AlertLevel.ERROR and "en marcha" in alert.body


def test_a_thaw_whose_record_raises_is_said_too(lagged: World) -> None:
    guardian = lagged.guardian
    original = guardian._record  # noqa: SLF001

    def broken(source: str, action: str, *args: object, **kwargs: object) -> object:
        if action == "space_resume":
            raise RuntimeError("boom")
        return original(source, action, *args, **kwargs)  # type: ignore[arg-type]

    guardian._record = broken  # type: ignore[method-assign]  # noqa: SLF001
    guardian.check_space()
    assert guardian.agent_state is AgentState.RUNNING
    assert lagged.alerts.titled("no se ha grabado")


def test_a_carried_late_pause_is_named_as_a_delay(
    lagged: World, tmp_path: Path, clock: Callable[[], datetime]
) -> None:
    lagged.guardian.stop()
    again = second_guardian(lagged, tmp_path, clock)
    again.guardian.start()
    (alert,) = again.alerts.titled("sigue pausado")
    assert "llegó tarde" in alert.body and "falta de espacio" not in alert.body
