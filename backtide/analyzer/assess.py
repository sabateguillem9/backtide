"""The risk of one event: ``assess(event, history, rules)``. No I/O, no clock, no threads.

- Every rule that matches gives its ``risk``; the event gets the highest one (0 if none).
- A rule with a ``burst`` also needs enough earlier events in the window. Those are counted in
  ``History``, which keeps one little queue of per-second totals for each burst rule, so its
  size depends on the window (at most 3600 numbers) and never on how many events came.
- ``assess`` only reads ``History`` (it forgets what fell out of the window, which nobody can
  tell). The caller adds what this event contributes with ``History.add`` once it has decided
  to keep the event: that is the one write, and it is separate on purpose.
"""

import math
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

from backtide.analyzer.model import (
    MAX_RULES_REPORTED,
    Assessment,
    Condition,
    Observation,
    Rule,
)

_MISSING = object()
NOTHING = Assessment(0)
MAX_VIEW = 1024  # characters of a target that the globs read
MAX_WEIGHT = 1e9  # one event never weighs more: sums stay finite whatever a field says


class History:
    """What earlier events add to each burst rule's window. Not thread-safe: the caller locks."""

    def __init__(self) -> None:
        # rule id -> [(second, weight)] oldest first, and the running total of the weights.
        self._buckets: dict[str, deque[tuple[int, float]]] = {}
        self._totals: dict[str, float] = {}

    def total(self, rule_id: str, window: int, now: float) -> float:
        """Weight added in the last ``window`` seconds before ``now`` (``now`` included)."""
        buckets = self._buckets.get(rule_id)
        if not buckets:
            return 0.0
        oldest = math.floor(now) - window  # a second at or before this is out of the window
        total = self._totals[rule_id]
        while buckets and buckets[0][0] <= oldest:
            total -= buckets.popleft()[1]
        self._totals[rule_id] = max(total, 0.0)
        if not buckets:
            del self._buckets[rule_id], self._totals[rule_id]
            return 0.0
        return self._totals[rule_id]

    def add(self, contributions: Mapping[str, float], now: float) -> None:
        second = math.floor(now)
        for rule_id, weight in contributions.items():
            buckets = self._buckets.setdefault(rule_id, deque())
            if buckets and buckets[-1][0] >= second:
                last_second, last_weight = buckets[-1]
                buckets[-1] = (last_second, last_weight + weight)  # same second, or a clock step
            else:
                buckets.append((second, weight))
            self._totals[rule_id] = self._totals.get(rule_id, 0.0) + weight

    @property
    def rules_tracked(self) -> int:
        return len(self._buckets)


def assess(event: Observation, history: History, rules: Sequence[Rule]) -> Assessment:
    """The risk ``rules`` give ``event`` given what ``history`` has seen."""
    matched: list[Rule] = []
    contributions: dict[str, float] = {}
    view = _view(event.target)
    for rule in rules:
        if not _selects(rule, event, view):
            continue
        if rule.burst is not None:
            weight = _weight(rule, event)
            contributions[rule.id] = weight
            if weight <= 0:
                continue  # it adds nothing (a summary without deletes): not part of the burst
            seen = history.total(rule.id, rule.burst.window, event.ts) + weight
            if seen < rule.burst.count:
                continue
        matched.append(rule)
    if not matched:
        return Assessment(0, (), contributions)
    matched.sort(key=lambda rule: -rule.risk)  # stable: the file's order breaks ties
    return Assessment(
        matched[0].risk,
        tuple(rule.id for rule in matched[:MAX_RULES_REPORTED]),
        contributions,
        matched[0].description,
    )


def _view(target: str) -> str:
    """What the globs read of a target: all of it up to ``MAX_VIEW`` characters, else the start
    and the end (where the folder and the file name are). A path the agent made thousands of
    characters long costs no more than one of 1 KiB."""
    if len(target) <= MAX_VIEW:
        return target
    half = MAX_VIEW // 2
    return target[:half] + target[-half:]


def _selects(rule: Rule, event: Observation, view: str) -> bool:
    """Does the event fit the rule's source, action, target and details (not the burst)?"""
    if rule.sources and event.source not in rule.sources:
        return False
    if rule.actions and event.action not in rule.actions:
        return False
    if rule.targets and not any(glob.match(view) for glob in rule.targets):
        return False
    if rule.unless and any(glob.match(view) for glob in rule.unless):
        return False
    return all(_holds(condition, event.details) for condition in rule.where)


def _weight(rule: Rule, event: Observation) -> float:
    burst = rule.burst
    assert burst is not None  # noqa: S101 - only called for burst rules
    if burst.sum_path is None:
        return 1.0
    value = _lookup(event.details, burst.sum_path)
    if value is _MISSING:
        return burst.default
    return min(float(value), MAX_WEIGHT) if _is_number(value) and value > 0 else 0.0


def _lookup(details: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = details
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return _MISSING
        current = current[key]
    return current


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _holds(condition: Condition, details: Mapping[str, Any]) -> bool:
    value = _lookup(details, condition.path)
    op = condition.op
    if op == "exists":
        return (value is not _MISSING) is condition.value
    if value is _MISSING:
        return False
    wanted = condition.value
    if op == "eq":
        return _equal(value, wanted)
    if op == "ne":
        return not _equal(value, wanted)
    if op == "in":
        return any(_equal(value, item) for item in wanted)
    if op == "glob":
        if not isinstance(value, str):
            return False
        text = _view(value)
        return any(glob.match(text) for glob in condition.globs)
    if not _is_number(value):
        return False
    if op == "gt":
        return value > wanted
    if op == "ge":
        return value >= wanted
    if op == "lt":
        return value < wanted
    return value <= wanted  # "le"


def _equal(value: object, wanted: object) -> bool:
    """Equality that does not take True for 1: a bool only equals a bool."""
    if isinstance(value, bool) or isinstance(wanted, bool):
        return isinstance(value, bool) and isinstance(wanted, bool) and value is wanted
    if _is_number(value) and _is_number(wanted):
        return value == wanted
    return isinstance(value, str) and isinstance(wanted, str) and value == wanted
