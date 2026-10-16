"""The battery's own tests: they run on the Mac with `make test`, with no VM and no attack.

They keep the manifest honest: every ready scenario has its test, every pending one has none
(so nobody forgets to flip it when its task lands), every script is used, and the report never
prints "sí" for what a test did not check.
"""

import ast
import platform
import sys
import tomllib
from pathlib import Path

import pytest
from attack_kit import Attack, AttackError
from attack_manifest import (
    DIMENSIONS,
    SCRIPTS_DIR,
    Expectation,
    ManifestError,
    Scenario,
    load_manifest,
)
from attack_report import Result, describe, format_pending, format_report, format_scenario

HERE = Path(__file__).parent
ROOT = HERE.parents[1]
MANIFEST = load_manifest()
READY = [s for s in MANIFEST if s.is_ready]
PENDING = [s for s in MANIFEST if not s.is_ready]


def decorated_scenarios() -> dict[str, list[str]]:
    """Scenario id -> the test functions marked @scenario("id"), read from the source."""
    found: dict[str, list[str]] = {}
    for path in sorted(HERE.glob("test_*_attacks.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Name)
                    and decorator.func.id == "scenario"
                ):
                    found.setdefault(ast.literal_eval(decorator.args[0]), []).append(
                        f"{path.name}::{node.name}"
                    )
    return found


# The manifest and its tests


def test_the_manifest_lists_both_kinds_of_scenario() -> None:
    assert READY, "no scenario runs today"
    assert PENDING, "nothing is waiting for a later task: T06-T10 have scenarios to list"
    assert {s.task for s in PENDING} >= {"T04a", "T06", "T10"}


def test_every_ready_scenario_has_exactly_one_test() -> None:
    tests = decorated_scenarios()
    assert sorted(tests) == sorted(s.id for s in READY)
    assert all(len(names) == 1 for names in tests.values()), tests


def test_a_pending_scenario_has_no_test_yet() -> None:
    """When its task lands, the scenario changes to ready AND gets its test, in one change."""
    assert not set(decorated_scenarios()) & {s.id for s in PENDING}


def test_every_script_belongs_to_a_ready_scenario_and_is_used() -> None:
    sources = "".join(path.read_text() for path in HERE.glob("test_*_attacks.py"))
    ready_scripts = {s.script for s in READY}
    for script in sorted(SCRIPTS_DIR.glob("*.py")):
        assert script.stem in ready_scripts, f"{script.name} has no ready scenario"
        assert f'"{script.stem}"' in sources, f"no test runs {script.name}"
        compile(script.read_text(), str(script), "exec")  # at least it is valid Python


def test_every_ready_scenario_has_something_to_check() -> None:
    for scenario in READY:
        assert any(e.must_be_checked for e in scenario.expect.values()), scenario.id


def test_attack_tests_are_left_out_of_make_test_and_make_it() -> None:
    options = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert "not ataques" in options["addopts"]
    assert "ataques" in "".join(options["markers"])


@pytest.mark.skipif(platform.node() == "lima-vigia-dev", reason="this is the VM itself")
def test_the_vm_guard_refuses_to_run_an_attack_anywhere_else() -> None:
    """Invariant 8, on the Mac: the check every attack makes first fails here."""
    guard = sys.modules["vigia_vm_fixtures"]._require_dev_vm_user_with_sudo
    with pytest.raises(pytest.fail.Exception, match="only inside"):
        guard()


# The loader


def write_manifest(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "manifest.toml"
    path.write_text(text)
    return path


GOOD = """
[[scenario]]
id = "{id}"
name = "A name"
story = "What it tries"
inspired_by = "Somewhere"
invariants = [2]
status = "{status}"
{extra}
[scenario.expect]
stopped = "{stopped}"
recorded = "pending:T04a"
risk = "n/a"
recoverable = "yes"
held = "n/a"
"""


def good(**changes: str) -> str:
    values = {"id": "one", "status": "ready", "extra": "", "stopped": "yes"} | changes
    return GOOD.format(**values)


def test_a_good_manifest_loads(tmp_path: Path) -> None:
    (scenario,) = load_manifest(write_manifest(tmp_path, good()))
    assert scenario.id == "one" and scenario.is_ready
    assert scenario.pending_tasks == ("T04a",)
    assert scenario.expect["recorded"].pending_task == "T04a"
    assert [d for d, e in scenario.expect.items() if e.must_be_checked] == [
        "stopped",
        "recoverable",
    ]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"stopped": "maybe"}, "stopped must be one of"),
        ({"stopped": "pending:soon"}, "not 'pending:Txx'"),
        ({"status": "pending"}, "needs a task"),
        ({"status": "ready", "extra": 'task = "T04a"'}, "no 'task'"),
        ({"id": "Bad_Id"}, "lowercase words"),
        ({"status": "done"}, "status must be one of"),
        ({"extra": "invariants = [9]"}, "|".join(["invariants", "duplicate", "9"])),
    ],
)
def test_a_bad_manifest_is_refused(tmp_path: Path, changes: dict[str, str], message: str) -> None:
    with pytest.raises((ManifestError, tomllib.TOMLDecodeError), match=message):
        load_manifest(write_manifest(tmp_path, good(**changes)))


def test_duplicate_ids_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="duplicate"):
        load_manifest(write_manifest(tmp_path, good() + good()))


# The Attack handle


def attack_for(**expect: str) -> Attack:
    base = {"stopped": "yes", "recorded": "pending:T04a", "risk": "n/a", "recoverable": "yes"}
    base |= {"held": "n/a"} | expect
    scenario = Scenario(
        "x",
        "X",
        "story",
        "inspiration",
        (2,),
        "ready",
        None,
        {d: Expectation(v) for d, v in base.items()},
    )
    return Attack(scenario, Result())


def test_a_pending_dimension_cannot_be_checked() -> None:
    attack = attack_for()
    with pytest.raises(AttackError, match="pending"):
        attack.check("recorded", True, "it was recorded")
    assert "recorded" not in attack.result.evidence


def test_a_dimension_that_is_not_applicable_cannot_be_checked() -> None:
    with pytest.raises(AttackError, match="n/a"):
        attack_for().check("risk", True, "level 3")


def test_a_failed_check_fails_the_test_and_keeps_the_evidence() -> None:
    attack = attack_for()
    with pytest.raises(pytest.fail.Exception, match="the attack got through"):
        attack.check("stopped", False, "the attack got through")
    assert attack.result.evidence == {"stopped": "the attack got through"}


def test_what_the_test_forgot_to_check_is_reported() -> None:
    attack = attack_for()
    assert attack.missing_checks() == ["stopped", "recoverable"]
    attack.check("stopped", True, "blocked")
    assert attack.missing_checks() == ["recoverable"]


# The report


def test_the_report_says_pending_and_never_yes_for_what_was_not_checked() -> None:
    scenario = READY[0]
    lines = format_scenario(scenario, Result(outcome="passed", evidence={}))
    text = "\n".join(lines)
    assert "sin comprobar" in text  # nothing was checked
    assert "pendiente (T07)" in text and "pendiente (T08)" in text
    assert text.splitlines()[0].startswith("[OK]")


def test_the_report_prints_the_evidence_next_to_what_was_expected() -> None:
    scenario = next(s for s in READY if s.id == "subvolumen-anidado")
    result = Result(
        outcome="passed",
        evidence={"stopped": "EOPNOTSUPP in 5 ioctl", "recoverable": "in the snapshot"},
    )
    text = "\n".join(format_scenario(scenario, result))
    assert "Frenado:" in text and "sí: EOPNOTSUPP in 5 ioctl" in text
    assert "Recuperable:" in text and "sí: in the snapshot" in text
    assert "Retenido:" in text and "no aplica" in text


def test_a_failure_is_printed_with_its_reason() -> None:
    scenario = READY[0]
    text = "\n".join(format_scenario(scenario, Result(outcome="failed", failure="it escaped")))
    assert text.splitlines()[0].startswith("[FALLO]") and "FALLO:" in text and "it escaped" in text


def test_the_full_report_lists_every_scenario_and_the_pending_ones_apart() -> None:
    results = {s.id: Result(outcome="passed") for s in READY}
    text = "\n".join(format_report(MANIFEST, results))
    assert all(s.id in text for s in MANIFEST)
    assert text.count("PENDIENTE (") == len(PENDING)
    assert f"{len(READY)} escenarios activos: {len(READY)} superados, 0 fallidos" in text
    assert f"{len(PENDING)} escenarios pendientes" in text
    header = next(line for line in text.splitlines() if line.startswith("Escenario"))
    assert header.split() == [
        "Escenario",
        "Frenado",
        "Grabado",
        "Riesgo",
        "Recuperable",
        "Retenido",
        "Resultado",
    ]


def test_a_scenario_that_did_not_run_is_not_a_pass() -> None:
    text = "\n".join(format_report(MANIFEST, {}))
    assert "NO EJECUTADO" in text and "0 superados" in text


def test_describe_words() -> None:
    assert describe(Expectation("pending:T10"), "held") == "pendiente (T10)"
    assert describe(Expectation("n/a"), "held") == "no aplica"
    assert describe(Expectation("contained"), "stopped") == "contenido por un tope"
    assert describe(Expectation("3"), "risk") == "nivel 3"


def test_pending_scenarios_are_grouped_by_task() -> None:
    lines = format_pending(PENDING)
    tasks = [line.split(")")[0] for line in lines]
    assert tasks == sorted(tasks)
    assert len(lines) == len(PENDING)


def test_every_dimension_has_a_label() -> None:
    from attack_report import LABELS  # noqa: PLC0415

    assert list(LABELS) == list(DIMENSIONS)
