# ruff: noqa: F811 - the fixtures of test_service_guardian.py are imported by name
"""A start that meets the space thread's freeze-to-confirm (found by `pausar-por-espacio`: right
after a rewind, metadata read 4 MiB under P1 for a moment, the space thread froze the agent to
confirm, ``wait_ready`` saw it frozen, and the agent was left stopped for a condition that was
never confirmed).

A freeze that ends in a pause is another matter and stays as it was: the agent is not started
(tests/test_service_guardian.py, ``test_the_space_thread_can_freeze_an_agent_that_is_starting``).
Same fakes as test_service_guardian.py."""

import pytest
from test_service_guardian import (  # noqa: F401 - fixtures, used by name
    Violation,
    World,
    no_leftover_bridge,
    rewinding,
    running,
    world,
)

from backtide.service.guardian import AgentState
from backtide.service.rewind import RewindStatus

P1 = Violation("P1", "metadatos: quedan 100 MiB, mínimo 341 MiB", "space")


def freeze_once_to_confirm(world: World, *, thaw: bool = True) -> list[int]:
    """The first ``wait_ready`` finds the agent frozen by a freeze-to-confirm; the verdict comes
    (a false alarm: thawed) on the first poll of the Guardian, if ``thaw``. Returns the epochs."""
    guardian = world.guardian
    epochs: list[int] = []
    clock = world.mono

    def freeze_now() -> None:
        if not epochs:
            freeze = guardian._freeze_to_confirm()  # noqa: SLF001
            assert isinstance(freeze, int) and not isinstance(freeze, bool)
            epochs.append(freeze)

    def verdict(seconds: float) -> None:
        clock[0] += seconds
        if thaw and epochs and guardian.agent_state is AgentState.FROZEN:
            guardian._thaw_after_false_alarm(epochs[0])  # noqa: SLF001

    world.jail.on_wait_ready = freeze_now
    guardian._sleep = verdict  # noqa: SLF001
    return epochs


def test_a_rewind_whose_start_meets_a_false_alarm_still_starts_the_agent(rewinding: World) -> None:
    epochs = freeze_once_to_confirm(rewinding)
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert epochs, "the freeze never happened: the test proves nothing"
    assert outcome.status is RewindStatus.DONE and outcome.agent_started
    assert rewinding.log.count("jail.wait_ready") == 2
    assert rewinding.guardian.agent_state is AgentState.RUNNING
    assert rewinding.jail.running and not rewinding.jail.paused
    assert rewinding.events("agent_start") and not rewinding.events("agent_start_failed")


def test_a_boot_whose_start_meets_a_false_alarm_still_starts_the_agent(world: World) -> None:
    epochs = freeze_once_to_confirm(world)
    world.guardian.start()
    assert epochs, "the freeze never happened: the test proves nothing"
    assert world.log.count("jail.wait_ready") == 2
    assert world.guardian.agent_state is AgentState.RUNNING
    assert world.events("agent_start") and not world.events("agent_start_failed")


def test_a_freeze_to_confirm_that_never_ends_is_a_failed_start_after_a_wait(
    rewinding: World,
) -> None:
    """Nobody thaws it (the space thread died): the start does not wait for ever."""
    freeze_once_to_confirm(rewinding, thaw=False)
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM and not outcome.agent_started
    assert rewinding.log.count("jail.wait_ready") == 1
    assert rewinding.events("agent_start_failed")
    assert rewinding.mono[0] < 1000.0 + 60  # it gave up after seconds, not minutes


def test_a_freeze_that_ends_in_a_pause_is_not_waited_for(rewinding: World) -> None:
    def pause_now() -> None:
        rewinding.guardian._pause([P1], freeze=True)  # noqa: SLF001

    rewinding.jail.on_wait_ready = pause_now
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM and not outcome.agent_started
    assert rewinding.log.count("jail.wait_ready") == 1
    assert rewinding.guardian.pause_reasons == {"space"}


def test_a_start_that_fails_for_another_reason_is_not_retried(rewinding: World) -> None:
    from backtide.jail import JailError  # noqa: PLC0415

    rewinding.jail.ready_error = JailError("not ready after 120 s")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM
    assert rewinding.log.count("jail.wait_ready") == 1


@pytest.mark.parametrize("thaw", [True, False])
def test_the_same_freeze_is_not_waited_for_twice(rewinding: World, thaw: bool) -> None:
    """A second ``wait_ready`` failure with no new freeze in between is final."""
    epochs = freeze_once_to_confirm(rewinding, thaw=thaw)
    original = rewinding.jail.on_wait_ready

    def then_fail_for_good() -> None:
        original()  # type: ignore[misc]
        if len(epochs) == 1 and rewinding.log.count("jail.wait_ready") > 1:
            from backtide.jail import JailError  # noqa: PLC0415

            rewinding.jail.ready_error = JailError("not ready after 120 s")

    rewinding.jail.on_wait_ready = then_fail_for_good
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert not outcome.agent_started
    assert rewinding.log.count("jail.wait_ready") == (2 if thaw else 1)


def test_a_freeze_to_confirm_that_is_confirmed_meanwhile_is_a_pause_not_a_wait(
    rewinding: World,
) -> None:
    """The verdict comes while the start waits: red again, so the pause opens (the agent is
    killed, as for any pause during a start) and ``wait_ready`` is not asked again."""
    guardian = rewinding.guardian
    frozen: list[int] = []

    def freeze_now() -> None:
        if not frozen:
            frozen.append(guardian._freeze_to_confirm())  # type: ignore[arg-type]  # noqa: SLF001

    def confirmed(seconds: float) -> None:
        rewinding.mono[0] += seconds
        if guardian.agent_state is AgentState.FROZEN and not guardian.pause_reasons:
            guardian._pause([P1], freeze=True, frozen_already=True)  # noqa: SLF001

    rewinding.jail.on_wait_ready = freeze_now
    guardian._sleep = confirmed  # noqa: SLF001
    outcome = guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert frozen and not outcome.agent_started
    assert rewinding.log.count("jail.wait_ready") == 1
    assert guardian.pause_reasons == {"space"}
    assert not rewinding.jail.running


def test_a_user_pause_during_the_wait_wins(rewinding: World) -> None:
    guardian = rewinding.guardian
    epochs = freeze_once_to_confirm(rewinding, thaw=False)
    plain_sleep = guardian._sleep  # noqa: SLF001

    def user_pauses(seconds: float) -> None:
        plain_sleep(seconds)
        if "user" not in guardian.pause_reasons:
            guardian.pause_by_user(requested_by="telegram")

    guardian._sleep = user_pauses  # noqa: SLF001
    outcome = guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert epochs and not outcome.agent_started
    assert rewinding.log.count("jail.wait_ready") == 1
    assert "user" in guardian.pause_reasons
    assert not rewinding.jail.running or rewinding.jail.paused
