"""The black box with the rules in front of it: every event gets its risk before it is recorded.

``AssessedBlackBox`` has the ``append`` of ``BlackBox`` (and the few other calls the Guardian
makes), so the Guardian and the file watcher record through it without knowing. Design:
docs/27-diseno-t08-reglas.md.

- **The rules can only raise.** The risk recorded is the higher of what the caller asked for
  (the Guardian knows that a failed space check is 2, the watcher that an overflow is 1) and
  what the rules say. A rule matched is listed in ``details.risk_rules``, which is part of the
  hashed event: the chain says why.
- **The rules see what will be stored**: the same redacted target and details, so a rule can
  never be written against a secret and a rule run again over the black box gives the same risk.
- **If the rules break, the event still gets recorded**, with at least risk 2, and the failure
  is logged at ERROR (the log bridge turns it into an alert). A rule problem must never lose an
  event, and never makes it look calm.
- **Arguments that are wrong go straight to the black box**, which refuses them as ever.
- After the append, an event of risk 3 from the agent's side (``file``, ``exec``, ``net``,
  ``llm``, ``gate``) is handed to the ``RiskResponder``. The service's own events (``system``,
  ``snapshot``) alert for themselves where they are recorded.
"""

import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from backtide.analyzer.assess import History, assess
from backtide.analyzer.model import Assessment, Observation, RuleSet
from backtide.analyzer.respond import RiskResponder
from backtide.blackbox import BlackBox, Event, Source, redact

logger = logging.getLogger(__name__)

# What the agent does (as opposed to what backtide does): these are answered with evidence.
AGENT_SOURCES = frozenset({Source.FILE, Source.EXEC, Source.NET, Source.LLM, Source.GATE})
# Events that carry no snapshot of their own and are recorded when they happen, so a recent
# evidence snapshot is a point before them. A file event never gets one here: it comes from the
# watcher with the snapshot from before the change, or with none if there is none.
_REUSES_EVIDENCE = frozenset({Source.EXEC, Source.NET, Source.LLM, Source.GATE})
FAILED_RULES_RISK = 2
RULES_KEY = "risk_rules"


@dataclass(frozen=True)
class _Judged:
    risk: int
    details: Mapping[str, Any] | None
    assessment: Assessment | None  # None: the rules did not run (or failed)


class AssessedBlackBox:
    def __init__(
        self,
        inner: BlackBox,
        rules: RuleSet,
        responder: RiskResponder | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._inner = inner
        self._rules = rules
        self._responder = responder
        self._clock = clock
        self._history = History()
        self._lock = threading.Lock()

    @property
    def rules(self) -> RuleSet:
        return self._rules

    # What the Guardian and the watcher use of the black box

    def open(self) -> "AssessedBlackBox":
        self._inner.open()
        return self

    def close(self) -> None:
        self._inner.close()

    def head(self) -> tuple[int, str] | None:
        return self._inner.head()

    def events(self, *args: Any, **kwargs: Any) -> list[Event]:
        return self._inner.events(*args, **kwargs)

    def append(
        self,
        source: Source | str,
        action: str,
        target: str,
        *,
        details: Mapping[str, Any] | None = None,
        risk: int = 0,
        snapshot_id: str | None = None,
    ) -> Event:
        """``BlackBox.append`` with the risk the rules give, if higher."""
        judged = self._judge(source, action, target, details, risk)
        if snapshot_id is None and self._reuses_evidence(source, judged.risk):
            snapshot_id = self._responder.recent_snapshot() if self._responder else None
        event = self._inner.append(
            source,
            action,
            target,
            details=judged.details,
            risk=judged.risk,
            snapshot_id=snapshot_id,
        )
        self._respond(event, judged)
        return event

    # -- inside -----------------------------------------------------------------------------

    def _judge(
        self,
        source: Source | str,
        action: str,
        target: str,
        details: Mapping[str, Any] | None,
        risk: int,
    ) -> _Judged:
        if not _well_formed(source, action, target, details, risk):
            return _Judged(risk, details, None)  # the black box says what is wrong
        try:
            seen = Observation(
                self._clock(),
                str(source),
                action,
                redact(target),
                redact(details) if details else {},
            )
            with self._lock:
                assessment = assess(seen, self._history, self._rules.rules)
                self._history.add(assessment.contributions, seen.ts)
        except Exception:
            logger.exception("the risk rules failed on a %s event: recording it as risk 2", source)
            return _Judged(max(risk, FAILED_RULES_RISK), details, None)
        if not assessment.rules:
            return _Judged(risk, details, assessment)
        noted = {**(details or {}), RULES_KEY: list(assessment.rules)}
        return _Judged(max(risk, assessment.risk), noted, assessment)

    def _reuses_evidence(self, source: Source | str, risk: int) -> bool:
        try:
            return risk == 3 and Source(source) in _REUSES_EVIDENCE
        except ValueError:
            return False

    def _respond(self, event: Event, judged: _Judged) -> None:
        if self._responder is None or event.risk != 3 or event.source not in AGENT_SOURCES:
            return
        assessment = judged.assessment
        rules = assessment.rules if assessment is not None else ()
        if assessment is not None and assessment.risk == 3 and assessment.top_description:
            description = assessment.top_description
        else:
            description = f"Evento de riesgo máximo ({event.source}/{event.action})"
        self._responder.note(event, rules, description)


def _well_formed(
    source: object, action: object, target: object, details: object, risk: object
) -> bool:
    return (
        isinstance(source, str)
        and isinstance(action, str)
        and isinstance(target, str)
        and (details is None or isinstance(details, Mapping))
        and type(risk) is int
        and 0 <= risk <= 3
    )
