"""The report that ``make ataques`` prints at the end. Pure: text in, text out.

Per scenario: what the attacker tried, whether it was stopped, what is recorded, what can be
recovered. What is not built yet is printed as "pendiente (Txx)": the report only says "sí"
about what a test checked in this run.
"""

import textwrap
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from attack_manifest import DIMENSIONS, Expectation, Scenario

WIDTH = 100
INDENT = " " * 7
LABEL_WIDTH = 13
LABELS: Mapping[str, str] = {
    "stopped": "Frenado",
    "recorded": "Grabado",
    "risk": "Riesgo",
    "recoverable": "Recuperable",
    "held": "Retenido",
}
OUTCOMES: Mapping[str, str] = {
    "passed": "OK",
    "failed": "FALLO",
    "skipped": "SALTADO",
    "not_run": "NO EJECUTADO",
}
_EXPECTED_WORDS: Mapping[str, Mapping[str, str]] = {
    "stopped": {
        "yes": "sí",
        "contained": "contenido por un tope",
        "no": "no (no se puede impedir)",
    },
    "recorded": {"yes": "sí", "no": "no"},
    "recoverable": {"yes": "sí", "no": "no"},
    "held": {"yes": "sí", "no": "no"},
}


@dataclass
class Result:
    """What one run of a ready scenario produced."""

    outcome: str = "not_run"  # passed | failed | skipped | not_run
    evidence: dict[str, str] = field(default_factory=dict)  # dimension -> what the test saw
    failure: str | None = None


def describe(expectation: Expectation, dimension: str) -> str:
    """A dimension without a measurement: pending, not applicable, or what was expected."""
    if expectation.pending_task is not None:
        return f"pendiente ({expectation.pending_task})"
    if expectation.value == "n/a":
        return "no aplica"
    if dimension == "risk":
        return f"nivel {expectation.value}"
    return _EXPECTED_WORDS[dimension][expectation.value]


def format_scenario(scenario: Scenario, result: Result) -> list[str]:
    """The block of one ready scenario."""
    title = OUTCOMES[result.outcome]
    invariants = ", ".join(str(n) for n in scenario.invariants)
    lines = [f"[{title}] {scenario.id}: {scenario.name}  (invariante {invariants})"]
    lines += _wrap("Intentó", scenario.story)
    for dimension, label in LABELS.items():
        lines += _wrap(label, _dimension_text(scenario, dimension, result))
    if result.failure:
        lines += _wrap("FALLO", result.failure)
    return lines


def format_table(scenarios: Iterable[Scenario], results: Mapping[str, Result]) -> list[str]:
    """One row per ready scenario, the columns of the `probar-ataques` skill."""
    header = ("Escenario", "Frenado", "Grabado", "Riesgo", "Recuperable", "Retenido", "Resultado")
    rows = [header]
    for scenario in scenarios:
        result = results.get(scenario.id, Result())
        cells = [_cell(scenario, dimension, result) for dimension in DIMENSIONS]
        rows.append((scenario.id, *cells, OUTCOMES[result.outcome]))
    widths = [max(len(row[column]) for row in rows) for column in range(len(header))]

    def line(cells: Iterable[str]) -> str:
        return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))

    lines = [line(header), line("-" * width for width in widths)]
    lines += [line(row) for row in rows[1:]]
    return [text.rstrip() for text in lines]


def format_pending(scenarios: Iterable[Scenario]) -> list[str]:
    """The scenarios that wait for a task, grouped by task. They have no test: nothing here
    passed."""
    by_task: dict[str, list[Scenario]] = {}
    for scenario in scenarios:
        by_task.setdefault(scenario.task or "?", []).append(scenario)
    lines: list[str] = []
    for task in sorted(by_task):
        for scenario in by_task[task]:
            lines.append(f"PENDIENTE ({task})  {scenario.id}: {scenario.name}")
    return lines


def format_report(scenarios: list[Scenario], results: Mapping[str, Result]) -> list[str]:
    """The whole report, in lines: a block per ready scenario, the table, the pending ones and
    the totals."""
    ready = [s for s in scenarios if s.is_ready]
    waiting = [s for s in scenarios if not s.is_ready]
    lines = ["", "BATERÍA DEL AGENTE MALVADO (T05)", ""]
    ran = [s for s in ready if results.get(s.id, Result()).outcome != "not_run"]
    for scenario in ran or ready:  # a partial run (-k) shows only what ran
        lines += format_scenario(scenario, results.get(scenario.id, Result())) + [""]
    lines += format_table(ready, results) + [""]
    if waiting:
        lines += [f"Escenarios pendientes de otras tareas ({len(waiting)}), sin comprobar:"]
        lines += [f"  {line}" for line in format_pending(waiting)] + [""]
    lines += [_totals(ready, waiting, results)]
    return lines


def _wrap(label: str, text: str) -> list[str]:
    first = f"{INDENT}{label + ':':<{LABEL_WIDTH}}"
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first,
        subsequent_indent=" " * len(first),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [first.rstrip()]


def _dimension_text(scenario: Scenario, dimension: str, result: Result) -> str:
    expectation = scenario.expect[dimension]
    if not expectation.must_be_checked:
        return describe(expectation, dimension)
    seen = result.evidence.get(dimension)
    if seen is None:
        return "sin comprobar"
    return f"{describe(expectation, dimension)}: {seen}"


def _cell(scenario: Scenario, dimension: str, result: Result) -> str:
    expectation = scenario.expect[dimension]
    if result.outcome == "not_run":
        return "-"
    if expectation.must_be_checked and dimension not in result.evidence:
        return "sin comprobar"
    return describe(expectation, dimension)


def _totals(ready: list[Scenario], waiting: list[Scenario], results: Mapping[str, Result]) -> str:
    outcomes = [results.get(s.id, Result()).outcome for s in ready]
    pending_cells = sum(
        1 for s in ready for d in DIMENSIONS if s.expect[d].pending_task is not None
    )
    parts = [
        f"{len(ready)} escenarios activos: {outcomes.count('passed')} superados, "
        f"{outcomes.count('failed')} fallidos, "
        f"{len(outcomes) - outcomes.count('passed') - outcomes.count('failed')} sin resultado",
        f"{pending_cells} comprobaciones pendientes dentro de ellos",
        f"{len(waiting)} escenarios pendientes",
    ]
    return "Resumen: " + "; ".join(parts) + "."
