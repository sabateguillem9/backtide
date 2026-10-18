"""What a rule is and what the analyzer says about an event. Pure: no I/O.

Design: docs/27-diseno-t08-reglas.md.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from backtide.analyzer.glob import Glob

MAX_RULES = 200
MAX_RULES_REPORTED = 8  # ids kept in an event's details

# What a condition on ``details`` can ask. Each one is a plain comparison: nothing here can run
# code or take long.
OPERATORS = frozenset({"eq", "ne", "gt", "ge", "lt", "le", "in", "glob", "exists"})


class RulesError(ValueError):
    """The rules cannot be used. The message is in Spanish and says which rule and which key;
    it never repeats a value from the file beyond a short, escaped excerpt."""


@dataclass(frozen=True)
class Observation:
    """What a rule sees of an event that is about to be recorded. ``target`` and ``details`` are
    the redacted ones (what the black box will store). ``ts`` is in seconds on any clock that
    does not go back: only the differences count (burst windows)."""

    ts: float
    source: str
    action: str
    target: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Condition:
    """One test on a field of ``details``. ``path`` is the key, or the keys inside keys
    (``("counts", "delete")``). A field that is not there fails every test but ``exists``."""

    path: tuple[str, ...]
    op: str
    value: Any = None
    globs: tuple[Glob, ...] = ()  # compiled from ``value`` for op == "glob": one match is enough


@dataclass(frozen=True)
class Burst:
    """The rule only matches once ``count`` is reached within the last ``window`` seconds,
    counting this event and the earlier ones that match the rule's other conditions. With
    ``sum_path`` each event weighs what that number in ``details`` says (a summary that folded
    300 deletes weighs 300), and an event without that number weighs ``default`` (so one rule
    can count loose deletes as 1 each and add a summary's folded ones); without it, 1."""

    count: int
    window: int
    sum_path: tuple[str, ...] | None = None
    default: float = 0.0


@dataclass(frozen=True)
class Rule:
    """``sources``, ``actions`` and ``targets`` are empty for "any". ``targets`` are alternatives:
    one match is enough. ``unless`` takes events out of the rule (they are not counted in its
    burst either). ``where`` are all required."""

    id: str
    description: str  # in Spanish: it is what the alert says
    risk: int  # 1-3
    sources: frozenset[str] = frozenset()
    actions: frozenset[str] = frozenset()
    targets: tuple[Glob, ...] = ()
    unless: tuple[Glob, ...] = ()  # an event whose target matches one of these is not the rule's
    where: tuple[Condition, ...] = ()
    burst: Burst | None = None


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]
    origin: str = "reglas por defecto"  # for messages: the file, or the built-in ones


@dataclass(frozen=True)
class Assessment:
    """What the analyzer says about one event. ``risk`` is 0 when no rule matched. ``rules`` are
    the ids that matched, the strongest first (at most ``MAX_RULES_REPORTED``);
    ``contributions`` is how much this event adds to each burst rule's window (the caller hands
    it to ``History.add`` once the event is recorded)."""

    risk: int
    rules: tuple[str, ...] = ()
    contributions: Mapping[str, float] = field(default_factory=dict)
    top_description: str = ""
