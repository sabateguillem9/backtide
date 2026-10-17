"""T04b-2 in the VM: the service owns the agent. Parar backtide para al agente.

docs/19-diseno-t04.md, "Los procesos" and "Parar". `backtide vigilar` runs as a process against the
real OpenClaw in its jail:

- stopping the service (SIGTERM, Ctrl-C) stops the agent, and the black box says so;
- a service killed with SIGKILL leaves the agent running (the limit T13's `Restart=always`
  closes); the next service stops that agent, records it as unsupervised, and starts it again
  watched;
- a second service cannot take the agent away from the first.
"""

import signal
from collections.abc import Callable

import pytest

from backtide.service.runner import ServiceLocked, take_lock
from tests.integration.service_kit import Service

pytestmark = pytest.mark.integration


def actions(service: Service) -> list[str]:
    return [f"{e.source}/{e.action}" for e in service.events()]


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
def test_stopping_the_service_stops_the_agent(
    make_real_service: Callable[..., Service], number: signal.Signals
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()
    assert service.jail.is_running()

    assert service.stop(number) == 0

    assert not service.jail.is_running()  # and not merely paused: it is stopped
    assert "backtide parado" in service.log_text()
    stops = service.events("agent_stop")
    assert [e.details["reason"] for e in stops] == ["service_stop"]  # no "unsupervised": first run
    assert service.events("service_stop")[0].details == {"agent_stopped": True}
    assert actions(service)[-1] == "system/service_stop"  # the last thing on record
    report = service.box.verify()
    assert report.ok, report.problems
    take_lock(service.config.lock_file).close()  # and the lock is free


def test_a_frozen_agent_is_stopped_too_when_the_service_stops(
    make_real_service: Callable[..., Service],
) -> None:
    """`docker stop` on a frozen container would wake it to run its SIGTERM handler: it is
    killed instead (docs/19, "Cómo se para al agente")."""
    service = make_real_service()
    service.start()
    service.wait_ready()
    service.freeze()
    assert service.stop() == 0
    assert not service.jail.is_running()
    assert not service.jail.is_paused()


def test_a_killed_service_leaves_the_agent_and_the_next_one_stops_it_and_says_so(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()

    # A second service cannot take the agent away from the first one.
    intruder = service.launch()
    assert intruder.wait(60) == 1
    assert "Ya hay un `backtide vigilar` en marcha" in service.log_text()
    assert service.jail.is_running()
    with pytest.raises(ServiceLocked):
        take_lock(service.config.lock_file)

    # SIGKILL: nothing is stopped, and that is the documented limit.
    service.kill()
    assert service.jail.is_running(), "the agent keeps running without a service (T13's job)"
    take_lock(service.config.lock_file).close()  # the kernel dropped the lock with the process
    killed_at = len(service.events())

    # The next service finds it, stops it, records the gap, and starts it again, watched.
    service.start()
    service.wait_ready()
    later = service.events()[killed_at:]
    later_actions = [f"{e.source}/{e.action}" for e in later]
    assert later_actions[0] == "system/service_start"
    unsupervised = [e for e in later if e.action == "agent_stop"]
    assert [e.details["reason"] for e in unsupervised] == ["unsupervised"]
    assert unsupervised[0].risk == 2
    assert later_actions.index("system/agent_stop") < later_actions.index("system/agent_start")
    assert service.jail.is_running()

    assert service.stop() == 0
    assert not service.jail.is_running()
    report = service.box.verify()
    assert report.ok, report.problems


def test_a_killed_service_and_an_unusable_key_still_leave_the_agent_stopped(
    make_real_service: Callable[..., Service],
) -> None:
    """The agent keeps running after a SIGKILL. If the next start cannot even open the black
    box (here the key is open to others), nothing can be recorded, but an agent running
    unrecorded must not be left running: "sin grabar no hay vigilancia"."""
    service = make_real_service()
    service.start()
    service.wait_ready()
    service.kill()
    assert service.jail.is_running()
    events_before = len(service.events())
    service.config.blackbox_key.chmod(0o644)

    service.start()
    assert service.wait_exit() == 1
    assert not service.jail.is_running()
    assert "Se ha parado al agente que estaba en marcha" in service.log_text()
    assert len(service.events()) == events_before  # and nothing could be written, as said

    service.config.blackbox_key.chmod(0o600)  # fixed by hand: the chain is intact and goes on
    service.start()
    service.wait_ready()
    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems


def test_the_service_refuses_to_start_when_the_config_is_not_there(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.config_path.unlink()
    process = service.launch()
    assert process.wait(60) == 2
    assert "configuración no válida" in service.log_text()
    assert not service.jail.exists()
