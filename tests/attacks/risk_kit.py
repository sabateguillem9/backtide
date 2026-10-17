"""What the scenarios share to check the ``risk`` dimension (T08): the level of a group of events
and the rules that gave it. Host side only; it reads events the way a person would.

A scenario's risk is the highest risk among the events its attack caused, not among every event
of the run: the service's own start-up and shutdown events have a risk of their own.
"""

from collections import Counter
from collections.abc import Iterable

from backtide.blackbox import Event

RULES_KEY = "risk_rules"  # in ``details``: the rules that touched the event (backtide.analyzer)


def peak(events: Iterable[Event]) -> int:
    """The highest risk among ``events`` (0 if there are none)."""
    return max((event.risk for event in events), default=0)


def rules_of(events: Iterable[Event]) -> set[str]:
    """Every rule id that touched any of ``events``."""
    return {rule for event in events for rule in event.details.get(RULES_KEY, [])}


def at_risk(events: Iterable[Event], risk: int) -> list[Event]:
    return [event for event in events if event.risk == risk]


def summary(events: Iterable[Event]) -> str:
    """For the report: how many events at each risk, and which rules gave them."""
    events = list(events)
    counts = Counter(event.risk for event in events)
    levels = ", ".join(f"{counts[level]} de riesgo {level}" for level in sorted(counts))
    rules = ", ".join(sorted(rules_of(events))) or "ninguna regla"
    return f"{len(events)} eventos ({levels or 'ninguno'}); reglas: {rules}"
