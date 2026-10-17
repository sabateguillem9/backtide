"""Alerts: the queue that delivers them off the caller's thread and the log bridge.

Design: docs/19-diseno-t04.md, section 3 ("Avisos"). Threads are waited for with events and a
timeout, never with sleeps."""

import logging
import threading
from collections.abc import Callable

import pytest

from backtide.notify import (
    Alert,
    AlertLevel,
    AlertQueue,
    LogBridge,
    LoggedProblem,
    LogNotifier,
)

WAIT = 5.0  # seconds a test waits for a thread before failing


class Recorder:
    """A Notifier that remembers what it was sent, and can block or fail on demand."""

    def __init__(self) -> None:
        self.sent: list[Alert] = []
        self.delivered = threading.Event()
        self.entered = threading.Event()  # set when send() is called, before it waits
        self.gate: threading.Event | None = None  # when set, send() waits for it
        self.fail_first = 0
        self.threads: set[str] = set()

    def send(self, alert: Alert) -> None:
        self.threads.add(threading.current_thread().name)
        self.entered.set()
        if self.gate is not None:
            assert self.gate.wait(WAIT)
        if self.fail_first > 0:
            self.fail_first -= 1
            raise RuntimeError("delivery broke")
        self.sent.append(alert)
        self.delivered.set()


def alert(
    title: str = "t", level: AlertLevel = AlertLevel.WARNING, seq: int | None = None
) -> Alert:
    return Alert(level, title, "body", seq)


# --- LogNotifier -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "log_level"),
    [
        (AlertLevel.INFO, logging.INFO),
        (AlertLevel.WARNING, logging.WARNING),
        (AlertLevel.ERROR, logging.ERROR),
    ],
)
def test_log_notifier_logs_at_the_matching_level(
    caplog: pytest.LogCaptureFixture, level: AlertLevel, log_level: int
) -> None:
    with caplog.at_level(logging.DEBUG):
        LogNotifier().send(Alert(level, "Titulo", "Cuerpo", event_seq=42))
    (record,) = [r for r in caplog.records if r.name.startswith("backtide.notify")]
    assert record.levelno == log_level
    assert "Titulo" in record.message
    assert "Cuerpo" in record.message
    assert "42" in record.message


def test_log_notifier_escapes_control_characters_chosen_by_the_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        LogNotifier().send(Alert(AlertLevel.WARNING, "t", "file \x1b[2J\nOK: all fine"))
    (record,) = [r for r in caplog.records if r.name.startswith("backtide.notify")]
    assert "\x1b" not in record.message
    assert "\n" not in record.message
    assert "\\x1b" in record.message


# --- AlertQueue --------------------------------------------------------------------------------


def test_the_queue_delivers_in_order_on_its_own_thread() -> None:
    notifier = Recorder()
    queue = AlertQueue(notifier)
    queue.start()
    for i in range(5):
        assert queue.submit(alert(str(i)))
    assert queue.close(WAIT)
    assert [a.title for a in notifier.sent] == ["0", "1", "2", "3", "4"]
    assert notifier.threads == {"backtide-alerts"}
    assert queue.dropped == 0


def test_submit_never_blocks_when_the_notifier_is_stuck() -> None:
    notifier = Recorder()
    notifier.gate = threading.Event()
    queue = AlertQueue(notifier, maxsize=2)
    queue.start()
    accepted = [queue.submit(alert(str(i))) for i in range(10)]  # returns at once
    assert accepted.count(False) >= 7  # at most 1 in delivery + 2 queued
    assert queue.dropped == accepted.count(False)
    notifier.gate.set()
    assert queue.close(WAIT)


def test_lost_alerts_are_reported_once_the_queue_drains() -> None:
    notifier = Recorder()
    notifier.gate = threading.Event()
    queue = AlertQueue(notifier, maxsize=1)
    queue.start()
    results = [queue.submit(alert(str(i))) for i in range(6)]
    lost = results.count(False)
    assert lost >= 3
    notifier.gate.set()
    assert queue.close(WAIT)
    (summary,) = [a for a in notifier.sent if a.title == "Avisos perdidos"]
    assert summary.level is AlertLevel.WARNING
    assert str(lost) in summary.body
    assert "caja negra" not in summary.body  # it may be the black box that is failing


def test_a_failing_notifier_does_not_kill_the_queue(caplog: pytest.LogCaptureFixture) -> None:
    notifier = Recorder()
    notifier.fail_first = 1
    queue = AlertQueue(notifier)
    queue.start()
    with caplog.at_level(logging.ERROR):
        queue.submit(alert("lost"))
        queue.submit(alert("kept"))
        assert queue.close(WAIT)
    assert [a.title for a in notifier.sent] == ["kept"]
    failure = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert failure
    assert all(r.name.startswith("backtide.notify") for r in failure)  # the bridge ignores them


def test_alerts_submitted_before_start_are_delivered_after_it() -> None:
    notifier = Recorder()
    queue = AlertQueue(notifier)
    queue.submit(alert("early"))
    assert notifier.sent == []
    queue.start()
    assert queue.close(WAIT)
    assert [a.title for a in notifier.sent] == ["early"]


def test_submit_after_close_is_refused_and_counted() -> None:
    queue = AlertQueue(Recorder())
    queue.start()
    assert queue.close(WAIT)
    assert not queue.submit(alert())
    assert queue.dropped == 1


def test_close_without_start_and_twice_is_fine() -> None:
    queue = AlertQueue(Recorder())
    assert queue.close(WAIT)
    assert queue.close(WAIT)


def stuck_queue(maxsize: int) -> tuple[AlertQueue, Recorder]:
    """A queue whose notifier is busy with one alert, so the next ones really wait."""
    notifier = Recorder()
    notifier.gate = threading.Event()
    queue = AlertQueue(notifier, maxsize=maxsize)
    queue.start()
    assert queue.submit(alert("in-delivery"))
    assert notifier.entered.wait(WAIT)
    return queue, notifier


def test_an_error_alert_pushes_out_the_oldest_warning_when_the_queue_is_full() -> None:
    queue, notifier = stuck_queue(2)
    assert queue.submit(alert("w1"))
    assert queue.submit(alert("w2"))
    assert not queue.submit(alert("w3"))  # a warning meets a full queue: it is the one lost
    assert queue.submit(alert("E1", AlertLevel.ERROR))  # an error makes room instead
    assert queue.submit(alert("E2", AlertLevel.ERROR))
    notifier.gate.set()  # type: ignore[union-attr]
    assert queue.close(WAIT)
    delivered = [a.title for a in notifier.sent if a.title != "Avisos perdidos"]
    assert delivered == ["in-delivery", "E1", "E2"]
    assert queue.dropped == 3  # w3 refused, w1 and w2 pushed out; the summary says so
    assert any("3" in a.body for a in notifier.sent if a.title == "Avisos perdidos")


def test_errors_are_only_lost_when_the_queue_holds_nothing_but_errors() -> None:
    queue, notifier = stuck_queue(2)
    assert queue.submit(alert("E1", AlertLevel.ERROR))
    assert queue.submit(alert("E2", AlertLevel.ERROR))
    assert not queue.submit(alert("E3", AlertLevel.ERROR))
    assert queue.dropped == 1
    notifier.gate.set()  # type: ignore[union-attr]
    assert queue.close(WAIT)
    delivered = [a.title for a in notifier.sent if a.title != "Avisos perdidos"]
    assert delivered == ["in-delivery", "E1", "E2"]


def test_close_logs_the_drops_nobody_was_told_about(caplog: pytest.LogCaptureFixture) -> None:
    queue = AlertQueue(Recorder())
    queue.start()
    assert queue.close(WAIT)
    assert not queue.submit(alert("late 1"))
    assert not queue.submit(alert("late 2"))
    with caplog.at_level(logging.ERROR):
        assert queue.close(WAIT)
    (record,) = [r for r in caplog.records if "dropped" in r.getMessage()]
    assert record.name.startswith("backtide.notify")  # the bridge ignores it
    assert "2" in record.getMessage()
    caplog.clear()
    with caplog.at_level(logging.ERROR):
        queue.close(WAIT)
    assert not [r for r in caplog.records if "dropped" in r.getMessage()]  # said once


# --- LogBridge ---------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


def make_bridge(
    clock: Clock, sink: Callable[[LoggedProblem], None] | None = None, **options: object
) -> tuple[LogBridge, list[LoggedProblem], logging.Logger]:
    """A started bridge attached to a private logger, so tests do not see each other. Call
    ``bridge.close()`` to wait for what it has queued."""
    seen: list[LoggedProblem] = []
    bridge = LogBridge(sink or seen.append, clock=clock, **options)  # type: ignore[arg-type]
    bridge.start()
    logger = logging.getLogger(f"backtide.test_bridge.{id(bridge)}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(bridge)
    return bridge, seen, logger


def test_warnings_and_errors_are_bridged_and_lower_levels_are_not(clock: Clock) -> None:
    bridge, seen, logger = make_bridge(clock)
    logger.debug("d")
    logger.info("i")
    logger.warning("w %s", 1)
    logger.error("e %s", 2)
    assert bridge.close(WAIT)
    assert [(p.level, p.message) for p in seen] == [
        (AlertLevel.WARNING, "w 1"),
        (AlertLevel.ERROR, "e 2"),
    ]
    assert seen[0].logger == logger.name
    assert seen[0].template == "w %s"


def test_the_sink_runs_on_the_bridges_own_thread_never_on_the_loggers(clock: Clock) -> None:
    # The sink writes the black box (fsync) and the logging call may hold the volume lock.
    threads: list[str] = []
    bridge, _, logger = make_bridge(
        clock, lambda p: threads.append(threading.current_thread().name)
    )
    logger.warning("anything")
    assert bridge.close(WAIT)
    assert threads == ["backtide-logbridge"]


def test_logging_does_not_wait_for_a_slow_sink(clock: Clock) -> None:
    release = threading.Event()
    entered = threading.Event()

    def slow(problem: LoggedProblem) -> None:
        entered.set()
        assert release.wait(WAIT)

    bridge, _, logger = make_bridge(clock, slow)
    logger.warning("first")
    assert entered.wait(WAIT)
    for i in range(20):
        logger.warning(f"distinct {i}")  # noqa: G004 - returns at once, sink still stuck
    release.set()
    assert bridge.close(WAIT)


def test_a_full_bridge_drops_and_says_how_many(clock: Clock) -> None:
    release = threading.Event()
    entered = threading.Event()
    seen: list[LoggedProblem] = []

    def sink(problem: LoggedProblem) -> None:
        entered.set()
        assert release.wait(WAIT)
        seen.append(problem)

    bridge, _, logger = make_bridge(clock, sink, maxsize=2)
    logger.warning("stuck one")
    assert entered.wait(WAIT)
    for i in range(6):
        logger.warning(f"flood {i}")  # noqa: G004
    assert bridge.dropped == 4  # two fit in the queue
    release.set()
    assert bridge.close(WAIT)
    (report,) = [p for p in seen if p.logger == "backtide.notify.bridge"]
    assert "4" in report.message


def test_the_same_template_is_limited_to_one_per_minute_whatever_its_arguments(
    clock: Clock,
) -> None:
    # An agent that picks file names must not turn each one into a new message.
    bridge, seen, logger = make_bridge(clock)
    for name in ("a", "b", "c"):
        logger.warning("cannot read %s", name)
    clock.now += 59
    logger.warning("cannot read %s", "d")
    clock.now += 2
    logger.warning("cannot read %s", "e")
    assert bridge.close(WAIT)
    assert [p.message for p in seen] == ["cannot read a", "cannot read e"]
    assert [p.suppressed for p in seen] == [0, 3]  # b, c and d were held back


def test_different_templates_and_levels_are_limited_separately(clock: Clock) -> None:
    bridge, seen, logger = make_bridge(clock)
    logger.warning("same text")
    logger.error("same text")
    logger.warning("other text")
    assert bridge.close(WAIT)
    assert len(seen) == 3


def test_a_sink_that_logs_does_not_loop(clock: Clock) -> None:
    calls: list[str] = []
    holder: dict[str, logging.Logger] = {}

    def sink(problem: LoggedProblem) -> None:
        calls.append(problem.message)
        holder["logger"].error("the black box failed while recording %s", problem.message)

    bridge, _, logger = make_bridge(clock, sink)
    holder["logger"] = logger
    logger.warning("first")
    assert bridge.close(WAIT)
    assert calls == ["first"]


def test_a_failing_sink_reports_through_logging_and_the_thread_survives(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def sink(problem: LoggedProblem) -> None:
        if problem.message == "boom":
            raise RuntimeError("sink broke")
        seen.append(problem.message)

    bridge, _, logger = make_bridge(clock, sink)
    handled: list[logging.LogRecord] = []
    monkeypatch.setattr(bridge, "handleError", handled.append)
    logger.warning("boom")
    logger.warning("fine")
    assert bridge.close(WAIT)
    assert len(handled) == 1
    assert seen == ["fine"]


@pytest.mark.parametrize(
    "name", ["backtide.notify", "backtide.notify.log", "backtide.notify.queue"]
)
def test_records_of_the_notifier_itself_are_ignored(clock: Clock, name: str) -> None:
    seen: list[LoggedProblem] = []
    bridge = LogBridge(seen.append, clock=clock)
    bridge.start()
    logger = logging.getLogger(name)
    logger.addHandler(bridge)
    try:
        logger.error("delivery failed")
    finally:
        logger.removeHandler(bridge)
    assert bridge.close(WAIT)
    assert seen == []


def test_the_table_of_templates_stays_bounded(clock: Clock) -> None:
    bridge, seen, logger = make_bridge(clock, maxsize=20_000)
    for i in range(10_000):
        logger.warning(f"unique template {i}")  # noqa: G004 - the point of the test
        clock.now += 0.001
    assert bridge.close(WAIT)
    assert len(seen) == 10_000
    assert bridge.tracked <= 4096


def test_a_message_that_cannot_be_formatted_goes_to_handle_error(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, seen, logger = make_bridge(clock)
    handled: list[logging.LogRecord] = []
    monkeypatch.setattr(bridge, "handleError", handled.append)
    logger.warning("needs %s and %s", "one")
    assert bridge.close(WAIT)
    assert seen == []
    assert len(handled) == 1


def test_flush_waits_until_everything_queued_has_reached_the_sink(clock: Clock) -> None:
    release = threading.Event()
    seen: list[str] = []

    def sink(problem: LoggedProblem) -> None:
        assert release.wait(WAIT)
        seen.append(problem.message)

    bridge, _, logger = make_bridge(clock, sink)
    logger.warning("one")
    logger.warning("two")
    assert not bridge.flush(0.05)  # the sink is stuck: it says so instead of waiting forever
    release.set()
    assert bridge.flush(WAIT)
    assert seen == ["one", "two"]
    assert bridge.close(WAIT)
