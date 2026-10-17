"""What happens after an event of risk 3: an evidence snapshot, then an alert.

Design: docs/27-diseno-t08-reglas.md, section "Qué pasa con el riesgo 3".

- The event is recorded FIRST (``AssessedBlackBox`` calls ``note`` after the append) and the alert
  cites it. ``note`` never blocks and never raises: it only writes a line in a small table under
  a lock, and a thread of its own does the snapshot, the recording and the alerting. So the
  watcher's dumper or the Guardian (which may hold the volume lock) never wait on a snapshot,
  and a snapshot needing the watcher's barrier cannot deadlock with the watcher's own thread.
- **A flood is one response.** The table is keyed by rule (``pending``), so thousands of events
  of risk 3 are a handful of lines whatever their number; the thread takes the whole table at
  once. Evidence snapshots are at most one per ``EVIDENCE_EVERY`` (2 min, docs/10) and at most
  ``EVIDENCE_PER_DAY`` in 24 h: the ones in between reuse the last snapshot. Alerts are at most
  one per rule per ``ALERT_EVERY``.
- **Nothing held back is lost.** An alert held back by that limit is kept (how many events, and
  the latest one), and the thread sends it as soon as the minute is over, or at once when the
  service stops (``close()``, and ``flush_held()`` after the last events of the stop).
  Otherwise an agent could burn the minute with a decoy and then do the damage unannounced.
- Evidence snapshots are never pruned (retention only deletes ``periodic`` ones), so the daily
  budget is also the most they can pin: 30 a day, plus the periodic snapshot each one anchors.
- After ``close()`` (the service is stopping) or before the thread exists, a note is alerted
  straight away without a snapshot: the agent is already stopped or the service is not up.
- Alerts carry no secrets (``redact``) and quote a path the agent chose only escaped and cut.
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from backtide.blackbox import Event, redact
from backtide.notify import Alert, AlertLevel, AlertSink

logger = logging.getLogger(__name__)

EVIDENCE_EVERY = 120.0  # seconds between two evidence snapshots
EVIDENCE_PER_DAY = 30  # most new evidence snapshots in 24 h
DAY = 24 * 3600.0
ALERT_EVERY = 60.0  # seconds between two alerts for the same rule
RETRY_AFTER = 10.0  # after a snapshot that failed, before trying another
MAX_KEYS = 512  # rules (or source/action pairs) remembered for the alert throttle
EXCERPT_CHARS = 100


@dataclass
class _Pending:
    """Events of risk 3 of one rule that nobody has answered yet. ``first`` and ``last`` are the
    oldest and the newest of them."""

    first: Event
    description: str
    rules: tuple[str, ...]
    count: int = 1
    last: Event | None = None

    @property
    def newest(self) -> Event:
        return self.last if self.last is not None else self.first


class RiskResponder:
    def __init__(
        self,
        alerts: AlertSink,
        *,
        clock: Callable[[], float] = time.monotonic,
        evidence_every: float = EVIDENCE_EVERY,
        evidence_per_day: int = EVIDENCE_PER_DAY,
        alert_every: float = ALERT_EVERY,
        retry_after: float = RETRY_AFTER,
    ) -> None:
        self._alerts = alerts
        self._clock = clock
        self._evidence_every = evidence_every
        self._evidence_per_day = evidence_per_day
        self._alert_every = alert_every
        self._retry_after = retry_after
        self._snapshot: Callable[[], str | None] | None = None
        self._record: Callable[..., object] | None = None

        self._cond = threading.Condition()
        self._pending: dict[str, _Pending] = {}
        self._thread: threading.Thread | None = None
        self._generation = 0  # a new ``open()`` retires the thread of the old one
        self._closing = False
        # What the thread alone touches after the start (``recent_snapshot`` reads the pair
        # under the lock too).
        self._evidence_id: str | None = None
        self._evidence_at = float("-inf")
        self._evidence_times: deque[float] = deque()
        self._retry_at = float("-inf")
        self._tell_lock = threading.Lock()  # the throttle below: the thread and inline notes
        self._last_alert: dict[str, float] = {}
        self._held: dict[str, _Pending] = {}  # alerts held back, to be sent when due

    def bind(self, *, snapshot: Callable[[], str | None], record: Callable[..., object]) -> None:
        """``snapshot()`` takes (or finds) the evidence snapshot and returns its id, or None;
        it may block and may raise. ``record`` is ``AssessedBlackBox.append``."""
        self._snapshot = snapshot
        self._record = record

    def open(self) -> None:
        """Ready for notes again after a ``close()`` (the Guardian starts again). A thread that
        is still winding down from before is retired, not waited for."""
        with self._cond:
            if self._closing or self._thread is None or not self._thread.is_alive():
                self._generation += 1
                self._closing = False
                self._thread = None
                self._cond.notify_all()
                if self._pending or self._held:  # left behind by a thread that was retired
                    self._start_thread()

    def close(self, timeout: float = 10.0) -> bool:
        """Answer what is pending and held (alerts only: no snapshots from here on) and stop the
        thread. True if it ended in time."""
        with self._cond:
            self._closing = True
            self._cond.notify_all()
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def flush_held(self) -> None:
        """Send every alert still held back, now. For the end of the stop, once the last events
        of the agent's grace period are in: the thread is gone by then."""
        try:
            self._send_held(force=True)
        except Exception:
            logger.exception("could not send the alerts held back")

    def recent_snapshot(self) -> str | None:
        """The evidence snapshot of the last ``evidence_every`` seconds, if there is one."""
        with self._cond:
            if self._evidence_id is not None and self._clock() - self._evidence_at < (
                self._evidence_every
            ):
                return self._evidence_id
        return None

    def note(self, event: Event, rules: tuple[str, ...], description: str) -> None:
        """An event of risk 3 was recorded. Never blocks, never raises."""
        key = rules[0] if rules else f"{event.source}/{event.action}"
        try:
            with self._cond:
                if self._closing:
                    inline = True
                else:
                    inline = False
                    waiting = self._pending.get(key)
                    if waiting is None and len(self._pending) >= MAX_KEYS:
                        key = "other"  # so many different rules: fold into one line, still told
                        waiting = self._pending.get(key)
                    if waiting is not None:
                        waiting.count += 1
                        waiting.last = event
                    else:
                        self._pending[key] = _Pending(event, description, rules)
                    self._start_thread()
                    self._cond.notify()
            if inline:
                self._tell(key, _Pending(event, description, rules), None, "stopping")
        except Exception:
            logger.exception("could not queue the response to a dangerous event")

    # -- the thread -------------------------------------------------------------------------

    def _start_thread(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, args=(self._generation,), name="backtide-risk", daemon=True
            )
            self._thread.start()

    def _run(self, generation: int) -> None:
        while True:
            with self._cond:
                while True:
                    if generation != self._generation:
                        return
                    if self._pending or self._closing:
                        break
                    wait = self._next_held_in()
                    if wait is not None and wait <= 0:
                        break
                    self._cond.wait(wait)
                batch, self._pending = self._pending, {}
                closing = self._closing
            try:
                if batch:
                    self._respond(batch, snapshots_allowed=not closing)
                self._send_held(force=closing)
            except Exception:
                logger.exception("the response to dangerous events failed")
            if closing:
                with self._cond:
                    if not self._pending:
                        return

    def _next_held_in(self) -> float | None:
        """Seconds until the earliest held alert may go out (None if none is held)."""
        with self._tell_lock:
            if not self._held:
                return None
            now = self._clock()
            return min(
                self._alert_every - (now - self._last_alert.get(key, now)) for key in self._held
            )

    def _respond(self, batch: dict[str, _Pending], snapshots_allowed: bool) -> None:
        oldest = min(batch.values(), key=lambda pending: pending.first.seq)
        snapshot_id, fresh, why = self._evidence(snapshots_allowed)
        if fresh and snapshot_id is not None:
            self._record_evidence(oldest, snapshot_id, batch)
        for key, pending in batch.items():
            self._tell(key, pending, snapshot_id, why)

    def _evidence(self, allowed: bool) -> tuple[str | None, bool, str | None]:
        """(the evidence snapshot to cite, whether this call made it, why there is none)."""
        recent = self.recent_snapshot()
        if recent is not None:
            return recent, False, None
        now = self._clock()
        if not allowed:
            return None, False, "stopping"
        if self._snapshot is None or now < self._retry_at:
            return None, False, "failed"
        while self._evidence_times and now - self._evidence_times[0] >= DAY:
            self._evidence_times.popleft()
        if len(self._evidence_times) >= self._evidence_per_day:
            logger.warning(
                "the evidence snapshots of the last 24 h are used up: dangerous events are "
                "still alerted, but no more are snapshotted until some are a day old"
            )
            return None, False, "budget"
        try:
            snapshot_id = self._snapshot()
        except Exception:
            logger.exception("could not take the evidence snapshot")
            snapshot_id = None
        if snapshot_id is None:
            self._retry_at = self._clock() + self._retry_after
            return None, False, "failed"
        now = self._clock()
        self._evidence_times.append(now)
        with self._cond:
            self._evidence_id, self._evidence_at = snapshot_id, now
        return snapshot_id, True, None

    def _record_evidence(
        self, oldest: _Pending, snapshot_id: str, batch: dict[str, _Pending]
    ) -> None:
        if self._record is None:
            return
        details: dict[str, Any] = {
            "event_seq": oldest.first.seq,
            "rules": sorted(batch)[:8],
            "events": sum(pending.count for pending in batch.values()),
        }
        try:
            self._record(
                "snapshot", "evidence", snapshot_id, details=details, snapshot_id=snapshot_id
            )
        except Exception:
            logger.exception("could not record the evidence snapshot")

    # -- alerts -----------------------------------------------------------------------------

    def _tell(self, key: str, pending: _Pending, snapshot_id: str | None, why: str | None) -> None:
        """Alert now, or hold the alert back if this rule alerted less than a minute ago."""
        now = self._clock()
        with self._tell_lock:
            last = self._last_alert.get(key)
            if last is not None and now - last < self._alert_every:
                held = self._held.get(key)
                if held is None:
                    self._held[key] = _Pending(
                        pending.first, pending.description, pending.rules, pending.count,
                        pending.newest,
                    )  # fmt: skip
                else:
                    held.count += pending.count
                    held.last = pending.newest
                return
            held = self._held.pop(key, None)
            if len(self._last_alert) >= MAX_KEYS:  # forget the throttle, never what is held
                self._last_alert = {k: v for k, v in self._last_alert.items() if k in self._held}
            self._last_alert[key] = now
        if held is not None:
            pending = _Pending(
                held.first, pending.description, pending.rules,
                held.count + pending.count, pending.newest,
            )  # fmt: skip
        self._submit(pending, snapshot_id, why)

    def _send_held(self, *, force: bool) -> None:
        """Send the alerts held back whose minute is over (all of them if ``force``)."""
        now = self._clock()
        with self._tell_lock:
            due = [
                key
                for key in self._held
                if force or now - self._last_alert.get(key, float("-inf")) >= self._alert_every
            ]
            sending = [(key, self._held.pop(key)) for key in due]
            for key, _ in sending:
                self._last_alert[key] = now
        if not sending:
            return
        recent = self.recent_snapshot()
        for _, pending in sending:
            self._submit(pending, recent, None if recent else "held")

    def _submit(self, pending: _Pending, snapshot_id: str | None, why: str | None) -> None:
        first, newest = pending.first, pending.newest
        lines = [f"{pending.description}."]
        lines.append(f"Evento {first.seq}: {first.source}/{first.action} {_excerpt(first.target)}")
        if pending.count > 1:
            lines.append(
                f"Son {pending.count} eventos así desde el último aviso; el último, el "
                f"{newest.seq}: {_excerpt(newest.target)}"
            )
        if snapshot_id is not None:
            lines.append(f"Instantánea de evidencia: {snapshot_id}.")
        elif why == "stopping":
            lines.append("No se hizo instantánea de evidencia: el servicio se estaba parando.")
        elif why == "budget":
            lines.append(
                "No se hace instantánea de evidencia: ya se han hecho "
                f"{self._evidence_per_day} en las últimas 24 horas."
            )
        elif why == "held":
            lines.append("Aviso retenido hasta pasado el minuto; mira la caja negra.")
        else:
            lines.append("No se ha podido hacer la instantánea de evidencia; mira la caja negra.")
        if first.snapshot_id is not None:
            lines.append(f"Para volver a antes: rebobinar a {first.snapshot_id}.")
        self._alerts.submit(
            Alert(
                AlertLevel.ERROR,
                redact(f"Riesgo máximo: {pending.description}"),
                redact(" ".join(lines)),
                first.seq,
            )
        )


def _excerpt(text: str) -> str:
    """A path or command the agent chose, cut and with its control characters escaped."""
    cut = text[:EXCERPT_CHARS] + ("…" if len(text) > EXCERPT_CHARS else "")
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in cut)
