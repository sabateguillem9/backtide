"""What the scenario tests share: the ``@scenario`` decorator, the ``Attack`` handle that checks
each dimension of the manifest, the runner of the in-container scripts and a few host helpers.

A scenario test looks like this::

    @scenario("subvolumen-anidado")
    def test_nested_subvolume(attack, agent):
        outcome = attack.run_script(agent, "workspace_probe", "/workspace/work")
        attack.check("stopped", outcome["created"] == [], "no subvolume was created")
        attack.check("recoverable", ..., "the snapshot holds the file")

Run one scenario by its manifest id (or part of it): `make ataques ATK="-k rebobinado-matado"`
(conftest.py adds the id to the test's keywords; the function names are English).

``check`` ties a test to a dimension of its manifest entry: a dimension that is final and not
"n/a" must be checked (else the battery fails), and one that is ``pending:Txx`` must not (it
is reported as pending). So a task that builds a pending piece has to flip the manifest and
add the check in the same change.
"""

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any, Protocol

import pytest
from attack_manifest import DIMENSIONS, SCRIPTS_DIR, Scenario, load_manifest
from attack_report import Result

# What the agent sees inside its container (docs/13): its folder of the snapshotted volume.
CONTAINER_WORK = "/workspace/work"
SCRIPT_TIMEOUT = 180.0
# Fake secrets (see conftest.canary_environment): each value is "<prefix><its own name>".
CANARY_PREFIX = "backtide-canary-"
CANARY_VARIABLES = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "TELEGRAM_BOT_TOKEN",
)

# The report reads these at the end of the session (one process: a module-level dict is enough).
RESULTS: dict[str, Result] = {}
_SCENARIOS: dict[str, Scenario] | None = None


class AttackError(Exception):
    """The scenario test is wrong (not backtide): it checked a dimension the manifest forbids."""


class Agent(Protocol):
    """The part of conftest's ``RunningAgent`` that the scripts need."""

    def exec(
        self, argv: list[str], *, check: bool = False, timeout: float = 60
    ) -> CompletedProcess[str]: ...


def scenarios() -> dict[str, Scenario]:
    """The manifest by id (read once)."""
    global _SCENARIOS  # noqa: PLW0603 - a read-once cache of an immutable file
    if _SCENARIOS is None:
        _SCENARIOS = {s.id: s for s in load_manifest()}
    return _SCENARIOS


def scenario(scenario_id: str) -> Callable[[Any], Any]:
    """Mark a test as the run of manifest scenario ``scenario_id``. It also marks it
    ``ataques``: `make ataques` selects those, and `make test` and `make it` never do."""
    if scenario_id not in scenarios():
        raise AttackError(f"unknown scenario {scenario_id!r}: add it to manifest.toml")
    if not scenarios()[scenario_id].is_ready:
        raise AttackError(f"{scenario_id!r} is pending in manifest.toml: set status = 'ready'")
    mark = pytest.mark.scenario(scenario_id)

    def decorate(function: Any) -> Any:
        return pytest.mark.ataques(mark(function))

    return decorate


class Attack:
    """The handle of one running scenario test (the ``attack`` fixture)."""

    def __init__(self, scenario: Scenario, result: Result) -> None:
        self.scenario = scenario
        self.result = result

    def check(self, dimension: str, ok: bool, evidence: str) -> None:
        """Check one dimension of the manifest. ``evidence`` is what the report prints next to
        it: what the test saw. It fails the test, with that evidence, when ``ok`` is false."""
        if dimension not in DIMENSIONS:
            raise AttackError(f"{dimension!r} is not a dimension: {sorted(DIMENSIONS)}")
        expected = self.scenario.expect[dimension]
        if expected.pending_task is not None:
            raise AttackError(
                f"{self.scenario.id}: {dimension} is pending ({expected.pending_task}) in the "
                "manifest, so it cannot be checked yet: flip it when that task is built"
            )
        if expected.value == "n/a":
            raise AttackError(f"{self.scenario.id}: {dimension} is n/a in the manifest")
        self.result.evidence[dimension] = evidence
        if not ok:
            pytest.fail(f"{dimension} (expected {expected.value}): {evidence}", pytrace=False)

    def missing_checks(self) -> list[str]:
        """Dimensions the manifest expects but this test never checked."""
        return [
            dimension
            for dimension, expected in self.scenario.expect.items()
            if expected.must_be_checked and dimension not in self.result.evidence
        ]

    def run_script(
        self, agent: Agent, name: str, *args: str, timeout: float = SCRIPT_TIMEOUT
    ) -> Any:
        """Run ``scripts/<name>.py`` inside the agent's container (python3 -c, as the agent's
        user) and return the JSON object it prints on its last line."""
        return run_script(agent, name, *args, timeout=timeout)


def run_script(agent: Agent, name: str, *args: str, timeout: float = SCRIPT_TIMEOUT) -> Any:
    source = (SCRIPTS_DIR / f"{name}.py").read_text(encoding="utf-8")
    done = agent.exec(["python3", "-c", source, *args], timeout=timeout)
    lines = (done.stdout or "").strip().splitlines()
    if done.returncode != 0 or not lines:
        pytest.fail(
            f"{name}.py exited {done.returncode} in the container:\n{done.stdout}\n{done.stderr}",
            pytrace=False,
        )
    try:
        return json.loads(lines[-1])
    except ValueError:
        pytest.fail(f"{name}.py did not print JSON on its last line:\n{done.stdout}", pytrace=False)


# Host-side helpers (the test process runs on the VM, outside the jail)


def tree_digest(root: Path) -> str:
    """A hash of everything under ``root``: names, kinds, modes, file contents and the targets of
    symlinks (never followed). Two trees with the same digest are the same."""
    digest = hashlib.sha256()
    for directory, names, files in os.walk(root):
        names.sort()
        for name in sorted(files) + names:
            path = Path(directory, name)
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            digest.update(
                f"{relative}\0{stat.S_IFMT(info.st_mode):o}{info.st_mode & 0o7777:o}\0".encode()
            )
            if stat.S_ISLNK(info.st_mode):
                digest.update(os.readlink(path).encode())
            elif stat.S_ISREG(info.st_mode):
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def files_under(root: Path) -> int:
    """How many entries (files, links and directories) are under ``root``."""
    return sum(len(names) + len(files) for _, names, files in os.walk(root))


def ensure_running(agent: Any) -> None:
    """After a rewind: start the agent if it ended up stopped (quiesce leaves a stopped agent
    stopped, and a wrecked OpenClaw may have crashed) and wait until it answers."""
    if not agent.jail.is_running():
        agent.jail.start()
    agent.jail.wait_ready()


def is_healthy(agent: Any) -> bool:
    """True if OpenClaw's Gateway answers ok on /healthz inside the container."""
    from backtide.jail.config import HEALTH_URL  # noqa: PLC0415 - only the VM scenarios need it

    try:
        answer = agent.exec(["curl", "--fail", "--silent", "--max-time", "5", HEALTH_URL])
        return answer.returncode == 0 and json.loads(answer.stdout)["ok"] is True
    except (ValueError, KeyError, TypeError, OSError):
        return False


def nested_subvolumes(root: Path) -> list[str]:
    """Directories under ``root`` that are Btrfs subvolume roots (inode 256), ``root`` itself
    left out: what a nested subvolume looks like from the host."""
    found = []
    for directory, names, _ in os.walk(root):
        for name in names:
            path = Path(directory, name)
            if not path.is_symlink() and path.lstat().st_ino == 256:
                found.append(path.relative_to(root).as_posix())
    return found
