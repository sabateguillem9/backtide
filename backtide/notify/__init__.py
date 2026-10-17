"""Alerts for the user, and the bridge that turns log warnings into them.

Design: docs/19-diseno-t04.md, section 3 ("Avisos").

- An ``Alert`` cites the black-box event that explains it (``event_seq``): the event is always
  recorded first.
- Whoever alerts never does network I/O, and least of all while holding the volume lock: alerts
  go into an ``AlertQueue`` and one thread of its own hands them to a ``Notifier``. Telegram (T09)
  is one more Notifier (``backtide.notify.telegram``): with it, ``FanOut`` hands every alert to the
  log and then to Telegram.
- A queue that is full refuses a new WARNING, or pushes out the oldest non-ERROR to make room for
  an ERROR; it never blocks, counts what it loses and reports it later.
- ``LogBridge`` is a ``logging.Handler``: every WARNING or ERROR of the ``backtide.*`` loggers (the
  store's, for one) reaches the sink, on the bridge's own thread (``emit`` only enqueues, so a
  slow black box never blocks a logging call), once per minute per message TEMPLATE, taken
  before the arguments are formatted, since the arguments are often file names the agent chose. It
  ignores ``backtide.notify.*`` (that is where delivery problems are logged, and a bridged
  delivery problem would alert about alerting) and has a guard against re-entry (a black box
  that fails while recording a log must not log a log of itself).
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

logger = logging.getLogger(__name__)

QUEUE_SIZE = 256
BRIDGE_QUEUE_SIZE = 256
BRIDGE_INTERVAL = 60.0  # seconds between two bridged messages with the same template
BRIDGE_MAX_TEMPLATES = 4096
BRIDGE_IGNORED = ("backtide.notify",)
MAX_TEMPLATE_CHARS = 200
MAX_MESSAGE_CHARS = 2000


class AlertLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class Alert:
    """What the user is told. ``title`` and ``body`` are in Spanish; ``event_seq`` is the
    black-box event that explains it."""

    level: AlertLevel
    title: str
    body: str
    event_seq: int | None = None


class Notifier(Protocol):
    """Delivers one alert. May block (the queue's thread calls it) and may raise."""

    def send(self, alert: Alert) -> None: ...


class AlertSink(Protocol):
    """Where the Guardian puts alerts. Never blocks and never raises."""

    def submit(self, alert: Alert) -> bool: ...


class LogNotifier:
    """Writes alerts to the log. Always available, and what runs before T09 brings Telegram."""

    def __init__(self) -> None:
        self._logger = logging.getLogger("backtide.notify.log")

    def send(self, alert: Alert) -> None:
        level = {
            AlertLevel.INFO: logging.INFO,
            AlertLevel.WARNING: logging.WARNING,
            AlertLevel.ERROR: logging.ERROR,
        }[alert.level]
        cited = f" (evento {alert.event_seq})" if alert.event_seq is not None else ""
        self._logger.log(level, "%s: %s%s", _printable(alert.title), _printable(alert.body), cited)


class FanOut:
    """Hands each alert to every notifier in turn (the log, then Telegram): one that fails
    does not stop the others, and the first failure is raised after all were tried."""

    def __init__(self, *notifiers: Notifier) -> None:
        self._notifiers = notifiers

    def send(self, alert: Alert) -> None:
        failure: Exception | None = None
        for notifier in self._notifiers:
            try:
                notifier.send(alert)
            except Exception as error:
                failure = failure or error
        if failure is not None:
            raise failure


class AlertQueue:
    """A bounded queue and the thread that empties it into a Notifier.

    When it is full a new WARNING or INFO is refused, but a new ERROR pushes out the oldest
    queued alert that is not an ERROR: the alerts that matter keep their room. Everything
    refused or pushed out is counted and reported after the queue drains, and once more in the
    log by ``close()`` if nobody could be told."""

    def __init__(self, notifier: Notifier, *, maxsize: int = QUEUE_SIZE) -> None:
        self._notifier = notifier
        self._maxsize = maxsize
        self._items: deque[Alert] = deque()
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._dropped = 0
        self._reported = 0

    @property
    def dropped(self) -> int:
        """Alerts refused, pushed out of a full queue or submitted after close."""
        with self._cond:
            return self._dropped

    def start(self) -> None:
        """Start delivering. Idempotent; alerts submitted before it wait in the queue."""
        with self._cond:
            if self._thread is not None or self._closed:
                return
            self._thread = threading.Thread(target=self._run, name="backtide-alerts", daemon=True)
            self._thread.start()

    def submit(self, alert: Alert) -> bool:
        """Queue ``alert`` without ever blocking. False (and counted) if it was dropped."""
        with self._cond:
            if self._closed:
                self._dropped += 1
                return False
            if len(self._items) >= self._maxsize and not self._make_room_for(alert):
                self._dropped += 1
                return False
            self._items.append(alert)
            self._cond.notify()
            return True

    def _make_room_for(self, alert: Alert) -> bool:
        """The queue is full: only an ERROR gets in, by pushing out the oldest non-ERROR."""
        if alert.level is not AlertLevel.ERROR:
            return False
        for queued in self._items:
            if queued.level is not AlertLevel.ERROR:
                self._items.remove(queued)
                self._dropped += 1
                return True
        return False

    def close(self, timeout: float = 5.0) -> bool:
        """Deliver what is queued, then stop the thread. True if it all went out in time."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()
            thread = self._thread
        done = True
        if thread is not None:
            thread.join(timeout)
            done = not thread.is_alive()
        if done:
            self._log_unreported()
        return done

    def _log_unreported(self) -> None:
        """Drops that no alert reported (made after the thread ended): say it in the log."""
        with self._cond:
            lost = self._dropped - self._reported
            self._reported = self._dropped
        if lost:
            logger.error("%d alerts were dropped and the user was not told", lost)

    def _run(self) -> None:
        while True:
            with self._cond:
                self._cond.wait_for(lambda: self._items or self._closed)
                if not self._items:
                    break
                alert = self._items.popleft()
            self._deliver(alert)
            self._report_losses()
        self._report_losses()

    def _report_losses(self) -> None:
        with self._cond:
            lost = self._dropped - self._reported
            self._reported = self._dropped
        if lost:
            self._deliver(
                Alert(
                    AlertLevel.WARNING,
                    "Avisos perdidos",
                    f"Se perdieron {lost} avisos porque la cola de avisos estaba llena. "
                    "No se vuelven a enviar: revisa el registro del servicio.",
                )
            )

    def _deliver(self, alert: Alert) -> None:
        try:
            self._notifier.send(alert)
        except Exception:
            logger.exception("could not deliver the alert %r", _printable(alert.title))


@dataclass(frozen=True)
class LoggedProblem:
    """A WARNING or ERROR the bridge lets through. ``suppressed`` counts the ones with the same
    template held back since the last one."""

    level: AlertLevel
    logger: str
    template: str
    message: str
    suppressed: int


class LogBridge(logging.Handler):
    """Hands WARNING and ERROR records to ``sink``, at most one per template per minute.

    ``emit`` only decides and enqueues (it runs inside the logging call, under the handler lock,
    maybe with the volume lock held): the sink, which writes the black box, runs on the bridge's
    own thread. A full queue drops and counts; the drops are reported to the sink once it
    catches up. Call ``start()`` before logging and ``close()`` to drain it."""

    def __init__(
        self,
        sink: Callable[[LoggedProblem], None],
        *,
        interval: float = BRIDGE_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        maxsize: int = BRIDGE_QUEUE_SIZE,
    ) -> None:
        super().__init__(level=logging.WARNING)
        self._sink = sink
        self._interval = interval
        self._clock = clock
        self._seen: dict[tuple[str, int, str], tuple[float, int]] = {}
        self._table_lock = threading.Lock()
        self._busy = threading.local()
        self._maxsize = maxsize
        self._items: deque[tuple[logging.LogRecord, LoggedProblem]] = deque()
        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._dropped = 0
        self._reported = 0
        self._pending = 0  # queued or being recorded

    @property
    def tracked(self) -> int:
        """How many templates are remembered."""
        with self._table_lock:
            return len(self._seen)

    @property
    def dropped(self) -> int:
        """Records that passed the rate limit but found the queue full."""
        with self._cond:
            return self._dropped

    def start(self) -> None:
        with self._cond:
            if self._thread is not None or self._closed:
                return
            self._thread = threading.Thread(
                target=self._run, name="backtide-logbridge", daemon=True
            )
            self._thread.start()

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until everything queued so far has reached the sink. True if it did in time."""
        with self._cond:
            return self._cond.wait_for(lambda: self._pending == 0, timeout)

    def close(self, timeout: float = 5.0) -> bool:  # type: ignore[override]
        """Record what is queued, then stop the thread. True if it finished in time."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.WARNING or record.name.startswith(BRIDGE_IGNORED):
            return
        if getattr(self._busy, "active", False):
            return  # the sink itself logged: never answer a log with a log
        try:
            template = str(record.msg)[:MAX_TEMPLATE_CHARS]
            suppressed = self._admit((record.name, record.levelno, template))
            if suppressed is None:
                return
            problem = LoggedProblem(
                level=AlertLevel.ERROR if record.levelno >= logging.ERROR else AlertLevel.WARNING,
                logger=record.name,
                template=template,
                message=record.getMessage()[:MAX_MESSAGE_CHARS],
                suppressed=suppressed,
            )
        except Exception:
            self.handleError(record)
            return
        with self._cond:
            if self._closed or len(self._items) >= self._maxsize:
                self._dropped += 1
                return
            self._items.append((record, problem))
            self._pending += 1
            self._cond.notify_all()

    def _run(self) -> None:
        self._busy.active = True
        while True:
            with self._cond:
                self._cond.wait_for(lambda: self._items or self._closed)
                if not self._items:
                    break
                record, problem = self._items.popleft()
            self._record(record, problem)
            self._report_drops()
            with self._cond:
                self._pending -= 1
                self._cond.notify_all()
        self._report_drops()

    def _report_drops(self) -> None:
        with self._cond:
            lost = self._dropped - self._reported
            self._reported = self._dropped
        if lost:
            message = f"{lost} log messages were dropped because the bridge's queue was full"
            problem = LoggedProblem(
                AlertLevel.WARNING, "backtide.notify.bridge", "bridge dropped", message, 0
            )
            self._record(None, problem)

    def _record(self, record: logging.LogRecord | None, problem: LoggedProblem) -> None:
        try:
            self._sink(problem)
        except Exception:
            if record is not None:
                self.handleError(record)
            else:
                logger.exception("the log bridge sink failed")

    def _admit(self, key: tuple[str, int, str]) -> int | None:
        """How many records with this key were held back if this one goes through, else None."""
        now = self._clock()
        with self._table_lock:
            last, held = self._seen.get(key, (None, 0))
            if last is not None and now - last < self._interval:
                self._seen[key] = (last, held + 1)
                return None
            if key not in self._seen and len(self._seen) >= BRIDGE_MAX_TEMPLATES:
                self._forget_old(now)
            self._seen[key] = (now, 0)
            return held

    def _forget_old(self, now: float) -> None:
        self._seen = {k: v for k, v in self._seen.items() if now - v[0] < self._interval}
        if len(self._seen) >= BRIDGE_MAX_TEMPLATES:
            self._seen.clear()  # a flood of new templates: better to repeat than to grow


def _printable(text: str) -> str:
    """``text`` with control characters escaped: alerts quote names the agent chose, and an
    escape sequence in one could rewrite what a terminal shows."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)
