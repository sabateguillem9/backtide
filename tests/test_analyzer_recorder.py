"""The black box with the rules in front of it, and the answer to risk 3 (T08): a real black
box in a temporary folder, a fake alert sink and a fake snapshot function. Threads are waited
for with events and a timeout, never with sleeps."""

import logging
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from backtide.analyzer import AssessedBlackBox, RiskResponder, parse_rules
from backtide.analyzer.respond import EXCERPT_CHARS
from backtide.blackbox import BlackBox, Event, Source
from backtide.notify import Alert, AlertLevel
from tests.conftest import FakeClock

KEY = bytes(range(32))
WAIT = 5.0
RULES = parse_rules(
    """
[[rule]]
id = "mass-delete"
description = "Ha borrado muchos archivos"
risk = 3
source = "file"
action = "delete"
burst = { count = 3, window = 60 }

[[rule]]
id = "pem"
description = "Toca una clave"
risk = 2
source = ["file", "exec"]
target = "*.pem"

[[rule]]
id = "env"
description = "Toca un .env"
risk = 1
source = "file"
target = "*.env"

[[rule]]
id = "struck"
description = "Un nombre con un secreto"
risk = 1
source = "file"
target = "*[[]REDACTED]*"

[[rule]]
id = "wipe"
description = "Borra el disco"
risk = 3
source = "exec"
target = "wipe*"
"""
)


class Sink:
    """An AlertSink that remembers what it got and says when."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []
        self.arrived = threading.Condition()

    def submit(self, alert: Alert) -> bool:
        with self.arrived:
            self.alerts.append(alert)
            self.arrived.notify_all()
        return True

    def wait_for(self, count: int) -> list[Alert]:
        with self.arrived:
            assert self.arrived.wait_for(lambda: len(self.alerts) >= count, WAIT), self.alerts
            return list(self.alerts)


class Clock:
    """A clock the test moves."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def raw(tmp_path: Path) -> Iterator[BlackBox]:
    clock = FakeClock(datetime(2026, 10, 5, 8, 0, tzinfo=UTC))
    with BlackBox(
        tmp_path / "bb.db", KEY, checkpoint_path=tmp_path / "bb.checkpoint", clock=clock
    ) as box:
        yield box


class Rig:
    """Everything wired the way ``build_guardian`` does it, with fakes for the Guardian."""

    def __init__(self, raw: BlackBox, **limits: Any) -> None:
        self.raw = raw
        self.clock = Clock()
        self.sink = Sink()
        self.snapshots: list[str] = []
        self.snapshot_calls = 0
        self.snapshot_result: Callable[[], str | None] = self._next_snapshot
        self.responder = RiskResponder(self.sink, clock=self.clock, **limits)
        self.box = AssessedBlackBox(raw, RULES, self.responder, clock=self.clock)
        self.responder.bind(snapshot=self._snapshot, record=self.box.append)

    def _snapshot(self) -> str | None:
        self.snapshot_calls += 1
        return self.snapshot_result()

    def _next_snapshot(self) -> str | None:
        snapshot_id = f"20261005T08{len(self.snapshots):02d}00.000000Z-evidence"
        self.snapshots.append(snapshot_id)
        return snapshot_id

    def settle(self) -> None:
        """Wait until the responder answered everything it was told."""
        assert self.responder.close(WAIT)
        self.responder.open()

    def events(self, **kwargs: Any) -> list[Event]:
        return self.raw.events(**kwargs)


@pytest.fixture
def rig(raw: BlackBox) -> Iterator[Rig]:
    rig = Rig(raw)
    yield rig
    rig.responder.close(WAIT)


# -- the risk of what is recorded ------------------------------------------------------------


def test_an_event_no_rule_touches_is_recorded_as_asked(rig: Rig) -> None:
    event = rig.box.append(Source.FILE, "modify", "work/a.txt", details={"size": 3}, risk=0)
    assert (event.risk, event.details) == (0, {"size": 3})


def test_the_rules_raise_the_risk_and_say_which_rules_did(rig: Rig) -> None:
    event = rig.box.append(Source.FILE, "create", "keys/server.pem", details={"size": 3})
    assert event.risk == 2
    assert event.details == {"size": 3, "risk_rules": ["pem"]}
    assert rig.events()[-1] == event  # it is what was recorded, not only what was returned


def test_the_rules_never_lower_what_the_caller_asked_for(rig: Rig) -> None:
    event = rig.box.append(Source.FILE, "create", "x.env", risk=2)
    assert event.risk == 2
    assert event.details["risk_rules"] == ["env"]
    quiet = rig.box.append(Source.FILE, "create", "work/a", risk=3)
    assert quiet.risk == 3 and "risk_rules" not in quiet.details


def test_the_callers_details_are_not_changed(rig: Rig) -> None:
    details = {"size": 3}
    rig.box.append(Source.FILE, "create", "keys/server.pem", details=details)
    assert details == {"size": 3}


def test_a_burst_builds_up_across_events(rig: Rig) -> None:
    risks = [rig.box.append(Source.FILE, "delete", f"work/{n}").risk for n in range(5)]
    assert risks == [0, 0, 3, 3, 3]
    rig.clock.now += 120  # the window is over
    assert rig.box.append(Source.FILE, "delete", "work/late").risk == 0


def test_the_rules_see_what_is_stored_not_what_was_given(rig: Rig) -> None:
    secret_name = "token=abcdefghijklmnopqrstuvwxyz0123456789.pem"  # noqa: S105
    event = rig.box.append(Source.FILE, "create", secret_name)
    assert "abcdefghijkl" not in event.target
    # The struck name no longer ends in ".pem" (the whole value went), and says it was struck.
    assert (event.risk, event.details["risk_rules"]) == (1, ["struck"])


def test_wrong_arguments_still_get_the_black_boxs_own_error(rig: Rig) -> None:
    with pytest.raises(ValueError, match="unknown source"):
        rig.box.append("disk", "x", "y")
    with pytest.raises(ValueError, match="risk"):
        rig.box.append(Source.FILE, "x", "y", risk=9)
    with pytest.raises(ValueError, match="details"):
        rig.box.append(Source.FILE, "x", "y", details=[1])  # type: ignore[arg-type]
    assert rig.events() == []


def test_if_the_rules_break_the_event_is_recorded_anyway_with_risk_2(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def explode(*_: object) -> None:
        raise RuntimeError("bug in a rule")

    monkeypatch.setattr("backtide.analyzer.recorder.assess", explode)
    with caplog.at_level(logging.ERROR, logger="backtide.analyzer"):
        event = rig.box.append(Source.FILE, "modify", "work/a.txt")
        calm = rig.box.append(Source.FILE, "modify", "work/b.txt", risk=3)
    assert (event.risk, calm.risk) == (2, 3)
    assert any("risk rules failed" in r.message for r in caplog.records)
    assert rig.raw.verify().ok


def test_the_rest_of_the_black_box_is_reachable(rig: Rig) -> None:
    assert rig.box.head() is None
    rig.box.append(Source.SYSTEM, "service_start", "")
    assert rig.box.head() is not None
    assert [e.action for e in rig.box.events(source="system")] == ["service_start"]
    assert rig.box.open() is rig.box
    assert rig.box.rules is RULES


# -- risk 3: the snapshot and the alert -----------------------------------------------------


def delete_burst(rig: Rig, count: int, start: int = 0) -> list[Event]:
    return [rig.box.append(Source.FILE, "delete", f"work/{n}") for n in range(start, start + count)]


def test_risk_3_takes_a_snapshot_then_alerts_citing_the_event(rig: Rig) -> None:
    events = delete_burst(rig, 3)
    (alert,) = rig.sink.wait_for(1)
    rig.settle()
    assert rig.snapshot_calls == 1
    assert alert.level is AlertLevel.ERROR
    assert "Ha borrado muchos archivos" in alert.title
    assert alert.event_seq == events[2].seq  # the first event of risk 3, recorded before the alert
    assert rig.snapshots[0] in alert.body
    assert "work/2" in alert.body


def test_the_snapshot_is_linked_to_the_event_in_the_black_box(rig: Rig) -> None:
    events = delete_burst(rig, 3)
    rig.sink.wait_for(1)
    rig.settle()
    (linked,) = rig.events(source="snapshot", action="evidence")
    assert linked.snapshot_id == rig.snapshots[0]
    assert linked.details["event_seq"] == events[2].seq
    assert linked.details["rules"] == ["mass-delete"]
    assert linked.seq > events[2].seq


def test_the_event_is_recorded_before_the_snapshot_is_asked_for(rig: Rig) -> None:
    seen_when_asked: list[int] = []

    def snapshot() -> str:
        seen_when_asked.append(len(rig.events(source="file")))
        return "20261005T080000.000000Z-evidence"

    rig.snapshot_result = snapshot
    delete_burst(rig, 3)
    rig.sink.wait_for(1)
    rig.settle()
    assert seen_when_asked == [3]


def test_a_flood_of_risk_3_is_one_snapshot_and_one_alert(rig: Rig) -> None:
    delete_burst(rig, 2000)
    rig.sink.wait_for(1)
    rig.settle()
    assert rig.snapshot_calls == 1
    # The first answer, and at most one more that says how many events were held back.
    assert 1 <= len(rig.sink.alerts) <= 2
    assert len(rig.events(source="snapshot", action="evidence")) == 1
    assert rig.raw.verify().ok


def test_after_two_minutes_the_next_flood_gets_its_own_snapshot(rig: Rig) -> None:
    delete_burst(rig, 10)
    rig.sink.wait_for(1)
    rig.settle()
    rig.clock.now += 61  # the burst window has passed, the alert throttle too, evidence not yet
    delete_burst(rig, 10, 100)
    rig.settle()
    assert rig.snapshot_calls == 1
    rig.clock.now += 120
    delete_burst(rig, 10, 200)
    rig.sink.wait_for(2)
    rig.settle()
    assert rig.snapshot_calls == 2
    assert len(rig.events(source="snapshot", action="evidence")) == 2


def test_alerts_for_one_rule_are_throttled_and_say_how_many_they_stand_for(rig: Rig) -> None:
    delete_burst(rig, 5)
    rig.sink.wait_for(1)
    delete_burst(rig, 7, 100)  # within the minute: held back, not lost
    time.sleep(0.2)
    assert len(rig.sink.alerts) == 1
    rig.clock.now += 61  # the minute is over; the next event (or the stop) sends what was held
    rig.settle()
    (_, second) = rig.sink.wait_for(2)
    assert "Son 9 eventos" in second.body and "el último, el" in second.body


def held_back(responder: RiskResponder) -> int:
    """How many events the responder holds back, waiting for their minute to be over."""
    with responder._tell_lock:  # noqa: SLF001
        return sum(pending.count for pending in responder._held.values())  # noqa: SLF001


def wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + WAIT
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.005)


def test_a_decoy_cannot_use_up_the_minute_to_hide_the_damage(raw: BlackBox) -> None:
    """Some junk files deleted to make the rule alert, then the real files half a minute later:
    the second alert must come, and in time, not only if the agent keeps going.

    The clock is the test's, so the whole damage falls inside the minute however slow the
    machine is. The minute is short (0.4 s) because the thread waits for it in real time: it
    sleeps what the clock says is left, wakes, and finds the minute over once the test moves
    the clock, with no event to wake it."""
    rig = Rig(raw, alert_every=0.4)  # the responder reads the test's clock too
    try:
        delete_burst(rig, 3)  # the decoy
        rig.sink.wait_for(1)
        rig.clock.now += 0.2  # half the minute later
        delete_burst(rig, 500, 100)  # the damage
        wait_until(lambda: held_back(rig.responder) == 500)  # all of it answered: held back
        assert len(rig.sink.alerts) == 1
        rig.clock.now += 0.3  # the minute is over, and no more events come
        alerts = rig.sink.wait_for(2)  # the thread sends it when due, by itself
        assert len(alerts) == 2
        assert "Son 500 eventos" in alerts[1].body
        assert "work/599" in alerts[1].body  # the latest one is cited
    finally:
        rig.responder.close(WAIT)


def test_alerts_held_during_the_stop_itself_go_out_with_flush_held(rig: Rig) -> None:
    """The agent's grace period and the watcher's last dump come after close(): their events of
    risk 3 are alerted inline, throttled, and held; flush_held() is the last step of the stop."""
    delete_burst(rig, 3)
    rig.sink.wait_for(1)
    assert rig.responder.close(WAIT)
    rig.clock.now += 5  # inside the minute of the first alert
    delete_burst(rig, 4, 100)  # inline now: held back, not sent
    assert len(rig.sink.alerts) == 1
    rig.responder.flush_held()
    assert len(rig.sink.alerts) == 2
    assert "Son 4 eventos" in rig.sink.alerts[1].body


def test_reopening_restarts_the_answer_to_what_a_retired_thread_left(rig: Rig) -> None:
    gate = threading.Event()
    entered = threading.Event()

    def stuck() -> str:
        entered.set()
        gate.wait(WAIT)
        return "20261005T080000.000000Z-evidence"

    rig.snapshot_result = stuck
    delete_burst(rig, 3)
    assert entered.wait(WAIT)
    rig.box.append(Source.EXEC, "exec", "wipe /")  # waits in the table behind the stuck snapshot
    assert not rig.responder.close(0.05)
    rig.responder.open()  # retires the stuck thread; what it left must still be answered
    gate.set()
    rig.snapshot_result = rig._next_snapshot  # noqa: SLF001
    assert len(rig.sink.wait_for(2)) >= 2


def test_stopping_sends_what_was_held(rig: Rig) -> None:
    delete_burst(rig, 3)
    rig.sink.wait_for(1)
    delete_burst(rig, 9, 100)
    assert rig.responder.close(WAIT)
    assert len(rig.sink.alerts) == 2
    assert "Son 9 eventos" in rig.sink.alerts[1].body


def test_the_evidence_snapshots_of_a_day_are_limited(
    raw: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    rig = Rig(raw, evidence_per_day=2)
    try:
        for round_ in range(3):
            rig.clock.now += 200  # past the two minutes between snapshots, and the burst window
            delete_burst(rig, 3, round_ * 10)
            rig.sink.wait_for(round_ + 1)
            rig.settle()
        assert rig.snapshot_calls == 2
        assert "ya se han hecho 2 en las últimas 24 horas" in rig.sink.alerts[-1].body
        rig.clock.now += 24 * 3600
        delete_burst(rig, 3, 100)
        rig.sink.wait_for(4)
        assert rig.snapshot_calls == 3
    finally:
        rig.responder.close(WAIT)


def test_reopening_retires_a_thread_that_did_not_finish(rig: Rig) -> None:
    gate = threading.Event()
    entered = threading.Event()

    def stuck() -> str:
        entered.set()
        gate.wait(WAIT)
        return "20261005T080000.000000Z-evidence"

    rig.snapshot_result = stuck
    delete_burst(rig, 3)
    assert entered.wait(WAIT)
    assert not rig.responder.close(0.05)  # the thread is stuck in the snapshot
    rig.responder.open()  # the service starts again: a new thread, the old one retired
    gate.set()
    rig.sink.wait_for(1)  # the retired thread still finishes the answer it was giving
    rig.snapshot_result = rig._next_snapshot  # noqa: SLF001
    rig.clock.now += 200
    delete_burst(rig, 3, 100)
    rig.sink.wait_for(2)
    assert rig.snapshots  # the new thread answered


def test_two_rules_get_two_alerts_and_one_snapshot(rig: Rig) -> None:
    delete_burst(rig, 3)
    rig.box.append(Source.EXEC, "exec", "wipe /")
    rig.sink.wait_for(2)
    rig.settle()
    assert len(rig.sink.alerts) == 2
    assert rig.snapshot_calls == 1


def test_a_risk_2_event_gets_neither_a_snapshot_nor_an_alert(rig: Rig) -> None:
    rig.box.append(Source.FILE, "create", "keys/server.pem")
    rig.settle()
    assert (rig.snapshot_calls, rig.sink.alerts) == (0, [])


def test_the_services_own_events_alert_for_themselves(rig: Rig) -> None:
    rig.box.append(Source.SYSTEM, "agent_stop_failed", "", risk=3)
    rig.box.append(Source.SNAPSHOT, "rewind_failed", "", risk=3)
    rig.settle()
    assert (rig.snapshot_calls, rig.sink.alerts) == (0, [])


def test_an_agent_event_whose_risk_comes_from_the_caller_is_answered_too(rig: Rig) -> None:
    event = rig.box.append(Source.NET, "blocked", "https://x", risk=3)
    (alert,) = rig.sink.wait_for(1)
    assert alert.event_seq == event.seq
    assert "net/blocked" in alert.title or "net/blocked" in alert.body


def test_a_failed_snapshot_is_said_in_the_alert_and_retried_later(rig: Rig) -> None:
    rig.snapshot_result = lambda: None
    delete_burst(rig, 3)
    (alert,) = rig.sink.wait_for(1)
    assert "No se ha podido hacer la instantánea" in alert.body
    rig.settle()
    assert rig.events(source="snapshot", action="evidence") == []
    rig.clock.now += 11
    rig.snapshot_result = rig._next_snapshot  # noqa: SLF001
    rig.clock.now += 61
    delete_burst(rig, 3, 100)
    rig.sink.wait_for(2)
    rig.settle()
    assert rig.snapshots


def test_a_snapshot_that_raises_does_not_stop_the_alert(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    def boom() -> str:
        raise RuntimeError("btrfs said no")

    rig.snapshot_result = boom
    with caplog.at_level(logging.ERROR, logger="backtide.analyzer"):
        delete_burst(rig, 3)
        (alert,) = rig.sink.wait_for(1)
    assert "No se ha podido hacer la instantánea" in alert.body
    assert any("evidence snapshot" in r.message for r in caplog.records)


def test_a_failing_record_of_the_evidence_does_not_stop_the_alert(rig: Rig) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise RuntimeError("black box full")

    rig.responder.bind(snapshot=rig._snapshot, record=refuse)  # noqa: SLF001
    delete_burst(rig, 3)
    rig.sink.wait_for(1)


def test_events_after_the_first_reuse_the_evidence_snapshot_but_file_events_do_not(
    rig: Rig,
) -> None:
    delete_burst(rig, 3)
    rig.sink.wait_for(1)
    rig.settle()
    wipe = rig.box.append(Source.EXEC, "exec", "wipe /")
    assert wipe.snapshot_id == rig.snapshots[0]
    later_file = rig.box.append(Source.FILE, "delete", "work/zzz")  # risk 3 too
    assert later_file.snapshot_id is None  # the watcher's own pointer is the only honest one
    given = rig.box.append(
        Source.EXEC, "exec", "wipe /x", snapshot_id="20261005T070000.000000Z-periodic"
    )
    assert given.snapshot_id == "20261005T070000.000000Z-periodic"
    calm = rig.box.append(Source.EXEC, "exec", "ls")
    assert calm.snapshot_id is None
    rig.clock.now += 121
    assert rig.box.append(Source.EXEC, "exec", "wipe /y").snapshot_id is None


def test_the_alert_quotes_the_path_cut_and_escaped_and_with_no_secret(rig: Rig) -> None:
    name = "work/\x1b[2JOK" + "x" * 300
    for _ in range(3):
        rig.box.append(Source.FILE, "delete", name)
    (alert,) = rig.sink.wait_for(1)
    assert "\x1b" not in alert.body
    assert "\\x1b" in alert.body
    assert alert.body.count("x") < EXCERPT_CHARS + 20


def test_alerts_are_redacted(rig: Rig) -> None:
    rig.responder.note(
        _fake_event(target="k"), (), "Clave sk-abcdefghijklmnopqrstuvwxyz0123456789 filtrada"
    )
    (alert,) = rig.sink.wait_for(1)
    assert "sk-abcdefghijkl" not in alert.title + alert.body


def test_before_close_notes_wait_for_the_thread_and_after_it_they_alert_straight_away(
    rig: Rig,
) -> None:
    assert rig.responder.close(WAIT)
    delete_burst(rig, 3)  # closed: no thread, no snapshot, but still told
    (alert,) = rig.sink.alerts
    assert "se estaba parando" in alert.body
    assert rig.snapshot_calls == 0
    rig.responder.open()
    rig.clock.now += 61
    delete_burst(rig, 3, 100)
    rig.sink.wait_for(2)
    assert rig.snapshot_calls == 1


def test_close_answers_what_was_waiting(rig: Rig) -> None:
    gate = threading.Event()
    entered = threading.Event()

    def slow() -> str:
        entered.set()
        assert gate.wait(WAIT)
        return "20261005T080000.000000Z-evidence"

    rig.snapshot_result = slow
    delete_burst(rig, 3)
    assert entered.wait(WAIT)  # the thread is inside the snapshot...
    rig.box.append(Source.EXEC, "exec", "wipe /")  # ...and this one waits for it
    closer = threading.Thread(target=rig.responder.close, args=(WAIT,))
    closer.start()
    gate.set()
    closer.join(WAIT)
    assert not closer.is_alive()
    assert len(rig.sink.wait_for(2)) == 2


def test_note_never_blocks_on_a_slow_snapshot(rig: Rig) -> None:
    gate = threading.Event()
    rig.snapshot_result = lambda: gate.wait(WAIT) and "20261005T080000.000000Z-evidence" or None
    finished = threading.Event()

    def append_a_lot() -> None:
        delete_burst(rig, 500)
        finished.set()

    thread = threading.Thread(target=append_a_lot)
    thread.start()
    assert finished.wait(WAIT)  # the appends did not wait for the snapshot
    gate.set()
    thread.join(WAIT)


def _fake_event(target: str) -> Event:
    return Event(
        seq=1, ts="2026-10-05T08:00:00.000001Z", source=Source.FILE, action="delete",
        target=target, details={}, risk=3, snapshot_id=None, prev_hash="0" * 64, hash="1" * 64,
    )  # fmt: skip
