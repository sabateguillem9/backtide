"""The analyzer: rules that give each event a risk level (0-3), and what risk 3 sets off.

Design and rationale: docs/27-diseno-t08-reglas.md.

- ``rules.py``: the TOML format, strict and clear; ``default_rules.toml`` ships with Vigía.
- ``glob.py``: the one pattern language of the rules. No regex: it cannot be made to take long.
- ``assess.py``: ``assess(event, history, rules)``, pure, and the ``History`` of burst windows.
- ``recorder.py``: ``AssessedBlackBox``, the black box with the rules in front of it.
- ``respond.py``: ``RiskResponder``, the evidence snapshot and the alert for risk 3.
"""

from vigia.analyzer.assess import History, assess
from vigia.analyzer.glob import Glob
from vigia.analyzer.model import (
    Assessment,
    Burst,
    Condition,
    Observation,
    Rule,
    RulesError,
    RuleSet,
)
from vigia.analyzer.recorder import AssessedBlackBox
from vigia.analyzer.respond import RiskResponder
from vigia.analyzer.rules import default_rules, parse_rules

__all__ = [
    "AssessedBlackBox",
    "Assessment",
    "Burst",
    "Condition",
    "Glob",
    "History",
    "Observation",
    "RiskResponder",
    "Rule",
    "RuleSet",
    "RulesError",
    "assess",
    "default_rules",
    "parse_rules",
]
