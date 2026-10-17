"""The plumbing of the evil-agent battery (T05).

- Reuses the VM fixtures of tests/integration/conftest.py (the real OpenClaw in its jail, the
  Btrfs volumes with and without quotas) instead of copying them: that file is loaded here by
  path, under another module name, because two conftest.py files cannot import each other.
- Every test marked ``ataques`` refuses to run anywhere but the vigia-dev VM (invariant 8).
- Puts fake secrets ("canaries") in the environment of the test process before the agent
  starts: if the jail ever forwarded the host's environment, the scenarios would find them.
- Collects the result of each scenario and prints the report at the end (attack_report.py).
"""

import importlib.util
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from attack_kit import CANARY_PREFIX, CANARY_VARIABLES, RESULTS, Attack, scenarios
from attack_manifest import Scenario
from attack_report import Result, format_report

_INTEGRATION = Path(__file__).resolve().parent.parent / "integration"


def _load_vm_fixtures() -> ModuleType:
    """tests/integration/conftest.py, imported once under a name of its own. The helpers of its
    sibling test modules (test_quota.py...) are imported by name, so its folder joins the path
    after the other folders (it only adds names that nothing else uses)."""
    name = "backtide_vm_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _INTEGRATION / "conftest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if str(_INTEGRATION) not in sys.path:
        sys.path.append(str(_INTEGRATION))
    return module


_vm = _load_vm_fixtures()
# Re-exported so pytest finds them here. Their scopes are the originals' (docs in that file).
btrfs_volume = _vm.btrfs_volume
quota_volume = _vm.quota_volume
running_agent = _vm.running_agent
real_service = _vm.real_service
make_real_service = _vm.make_real_service
start_quota_agent = _vm.start_quota_agent


# The report

_REPORTS: pytest.StashKey[dict[str, pytest.TestReport]] = pytest.StashKey()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "scenario(id): the manifest scenario this test runs")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Make each scenario selectable by its manifest id, which is Spanish while the test names
    are English: `make ataques ATK="-k rebobinado-matado"` (or any part of an id, such as
    `-k rebobin`) runs the tests of the scenarios whose id contains it."""
    for item in items:
        marker = item.get_closest_marker("scenario")
        if marker is not None:
            item.extra_keyword_matches.add(marker.args[0])


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Iterator[None]:
    """Remember how each scenario ended (setup, call and teardown) for the report."""
    report = yield
    marker = item.get_closest_marker("scenario")
    if marker is None:
        return report
    result = RESULTS.setdefault(marker.args[0], Result())
    if report.failed:
        result.outcome = "failed"
        result.failure = _first_line(report)
    elif report.skipped and result.outcome != "failed":
        result.outcome = "skipped"
        result.failure = _first_line(report)
    elif report.when == "call" and result.outcome in ("not_run", "skipped"):
        result.outcome = "passed"
    item.stash.setdefault(_REPORTS, {})[report.when] = report
    return report


def _first_line(report: pytest.TestReport) -> str:
    """What failed, in a few lines: the crash message, or the text of pytest.fail."""
    crash = getattr(report.longrepr, "reprcrash", None)
    text = crash.message if crash is not None else str(report.longrepr or report.outcome)
    return " ".join(text.split())[:600]


def pytest_terminal_summary(terminalreporter: Any, exitstatus: int, config: pytest.Config) -> None:
    if not RESULTS:
        return
    terminalreporter.section("agente malvado: resumen")
    for line in format_report(list(scenarios().values()), RESULTS):
        terminalreporter.write_line(line)


# Fixtures


@pytest.fixture(autouse=True)
def _only_in_the_vm(request: pytest.FixtureRequest) -> None:
    """Invariant 8: an attack never runs on the Mac, on a laptop or in CI. The same check the
    VM fixtures make (hostname, not root, passwordless sudo), before anything else starts."""
    if request.node.get_closest_marker("ataques") is not None:
        _vm._require_dev_vm_user_with_sudo()


@pytest.fixture(scope="module")
def canary_environment() -> Iterator[dict[str, str]]:
    """Fake keys in this process's environment for the whole module, set BEFORE the agent
    starts (list this fixture first). Nothing real: each value is its own name."""
    canaries = {name: f"{CANARY_PREFIX}{name}" for name in CANARY_VARIABLES}
    with pytest.MonkeyPatch.context() as patch:
        for name, value in canaries.items():
            patch.setenv(name, value)
        yield canaries


@pytest.fixture(scope="module")
def agent(canary_environment: dict[str, str], running_agent: Any) -> Any:
    """The real OpenClaw in its jail on a shared Btrfs (one per test module)."""
    return running_agent


@pytest.fixture
def quota_agent(
    canary_environment: dict[str, str], start_quota_agent: Callable[[int | None], Any]
) -> Callable[[int | None], Any]:
    """A factory for the real OpenClaw on its own volume with simple quotas and a capped
    workspace (``quota_agent(cap_in_bytes)``): see ``start_quota_agent``."""
    return start_quota_agent


@pytest.fixture
def attack(request: pytest.FixtureRequest) -> Iterator[Attack]:
    """The handle of the scenario this test runs (marked with ``@scenario``). When the test
    passed, every dimension the manifest expects must have been checked."""
    marker = request.node.get_closest_marker("scenario")
    assert marker is not None, "tests that use `attack` carry @scenario(...)"
    scenario_entry: Scenario = scenarios()[marker.args[0]]
    result = RESULTS.setdefault(scenario_entry.id, Result())
    result.evidence.clear()  # a rerun starts clean
    result.outcome, result.failure = "not_run", None
    handle = Attack(scenario_entry, result)
    yield handle
    call = request.node.stash.get(_REPORTS, {}).get("call")
    if call is not None and call.passed and handle.missing_checks():
        pytest.fail(
            f"{scenario_entry.id}: the manifest expects {handle.missing_checks()} but the test "
            "never checked them (check them, or mark them pending/n/a in manifest.toml)",
            pytrace=False,
        )
