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

import fnmatch
import hashlib
import json
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from subprocess import CompletedProcess
from typing import TYPE_CHECKING, Any, Protocol

import pytest
from attack_manifest import DIMENSIONS, PROFILES, SCRIPTS_DIR, Scenario, load_manifest
from attack_report import Result

if TYPE_CHECKING:
    from sensor_battery import BatterySensor

    from backtide.blackbox import Event

# What the agent sees inside its container (docs/13): its folder of the snapshotted volume.
CONTAINER_WORK = "/workspace/work"
SCRIPT_TIMEOUT = 180.0
# How long to wait for an attack's exec/connect to reach the black box: the command, Tetragon's
# buffered write, the reader's 0.5 s poll (docs/23, sections 3 and 6).
RECORDED_TIMEOUT = 60.0
_RECORDED_POLL = 0.5
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

# The agent the battery runs with: `make ataques PERFIL=claude-code` sets it (T17a-5). A
# scenario whose manifest entry does not list it is skipped, saying so (conftest.py).
PROFILE_ENV = "BACKTIDE_ATK_PERFIL"

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


class _BoxSensor:
    """A ``BatterySensor``-shaped view over a service's black box, for ``Attack.watch_service``:
    the service's own process sensor already watches its agent, so the events are already in the
    box (``recorded_exec``/``recorded_connect`` only need ``events(source, action, since)``)."""

    def __init__(self, box: Any) -> None:
        self._box = box

    def events(self, source: str, *, action: str | None = None, since: int = 0) -> list["Event"]:
        found = self._box.events(source=source, since_seq=since)
        return [e for e in found if action in (None, e.action)]


def scenarios() -> dict[str, Scenario]:
    """The manifest by id (read once)."""
    global _SCENARIOS  # noqa: PLW0603 - a read-once cache of an immutable file
    if _SCENARIOS is None:
        _SCENARIOS = {s.id: s for s in load_manifest()}
    return _SCENARIOS


def battery_profile() -> str:
    """The profile this run of the battery is for (``openclaw`` when nothing says otherwise)."""
    profile = os.environ.get(PROFILE_ENV, "") or PROFILES[0]
    if profile not in PROFILES:
        raise AttackError(f"{PROFILE_ENV}={profile!r}: the battery's profiles are {PROFILES}")
    return profile


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
        self._sensor: BatterySensor | None = None
        self._container: str | None = None
        self._since = 0

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

    # The ``recorded`` dimension (docs/23, section 9): the process sensor.

    def watch(self, sensor: "BatterySensor", jail: Any) -> int:
        """Point the shared sensor at this agent's container and prove the whole path, so from
        now on ``recorded_exec`` and ``recorded_connect`` see this agent's events. Returns the
        black box's seq right before the attack: call it just before running the attack, so a
        scenario only looks at what its own attack adds. ``jail`` is the agent's ``AgentJail``
        (``.container_id()`` and ``.exec``)."""
        container = jail.container_id()
        assert container is not None, "the agent's container must exist to be watched"
        self._sensor = sensor
        self._container = container
        self._since = sensor.watch(container, jail.exec)
        return self._since

    def watch_service(self, service: Any) -> int:
        """Like ``watch``, but over a real service's own process sensor (its reader already
        watches its agent, so there is no probe to run): the T17a-5 claude-code labs. Makes
        ``recorded_exec`` and ``recorded_connect`` read the service's black box. Returns the seq
        just before the attack. Call it right before running the attack."""
        container = service.jail.container_id()
        assert container is not None, "the service's agent container must exist to be watched"
        head = service.box.head()
        self._sensor = _BoxSensor(service.box)
        self._container = container
        self._since = head[0] if head is not None else 0
        return self._since

    @property
    def container_short(self) -> str:
        """The watched container's short id, as the events carry it (``details.container``)."""
        assert self._container is not None, "call attack.watch(...) first"
        return self._container[:12]

    @property
    def since(self) -> int:
        """The black box seq just before the attack (set by ``watch``): read only what the
        attack added."""
        return self._since

    def recorded_exec(
        self,
        *,
        argv: str | None = None,
        binary: str | None = None,
        at_least: int = 1,
        timeout: float = RECORDED_TIMEOUT,
    ) -> list["Event"]:
        """Wait for and return the watched agent's ``exec`` events whose ``argv`` contains
        ``argv`` and whose binary matches the glob ``binary``. docs/23, decision 6: ``recorded``
        here means the process that made the attempt, with its arguments struck and cut."""

        def matches(event: "Event") -> bool:
            details = event.details
            if details.get("container") != self.container_short:
                return False
            if argv is not None and argv not in str(details.get("argv", "")):
                return False
            return binary is None or fnmatch.fnmatch(event.target, binary)

        return self._wait_records("exec", "exec", matches, at_least, timeout)

    def recorded_connect(
        self,
        *,
        target: str | None = None,
        addr: str | None = None,
        port: int | None = None,
        at_least: int = 1,
        timeout: float = RECORDED_TIMEOUT,
    ) -> list["Event"]:
        """Wait for and return the watched agent's ``net/connect`` events to ``target``
        (``ip:port``), or to ``addr`` and/or ``port``. The attempt is recorded even when it
        fails (docs/23, section 4)."""

        def matches(event: "Event") -> bool:
            details = event.details
            if details.get("container") != self.container_short:
                return False
            if target is not None and event.target != target:
                return False
            if addr is not None and details.get("addr") != addr:
                return False
            return port is None or details.get("port") == port

        return self._wait_records("net", "connect", matches, at_least, timeout)

    def _wait_records(
        self,
        source: str,
        action: str,
        matches: Callable[["Event"], bool],
        at_least: int,
        timeout: float,
    ) -> list["Event"]:
        assert self._sensor is not None, "call attack.watch(sensor, jail) before recorded_*"
        deadline = time.monotonic() + timeout
        found: list[Event] = []
        while True:
            events = self._sensor.events(source, action=action, since=self._since)
            found = [event for event in events if matches(event)]
            if len(found) >= at_least or time.monotonic() >= deadline:
                return found
            time.sleep(_RECORDED_POLL)


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
