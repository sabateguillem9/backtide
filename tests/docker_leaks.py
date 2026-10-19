"""The leak guard of the VM test sessions: a test that leaves a container, a network or a volume
behind fails the session, loudly, and the leftovers are removed.

Why it exists: on 2026-10-19 the dev VM was found at 200% CPU long after the tests had ended,
because something was still running. A test that leaks must not be able to hide.

How it works, with no names to maintain:

- When the session starts (after collection, and only if it will run an ``integration`` or
  ``ataques`` test), the guard takes an inventory of Docker: every container, every network and
  every volume that exists.
- When the session ends (``trylast``: after the session fixtures have been torn down), it takes
  another and anything new is a leak. It removes it (``docker rm -f -v`` for containers, so their
  anonymous volumes go too; then networks; then volumes) and sets the exit status to failure.
  ``pytest_terminal_summary`` names every leaked object, and what could not be removed.

Left alone on purpose: Docker's own networks (bridge, host, none); the demo's objects (a person
may run ``make demo`` while the tests run); and test objects whose name carries the pid of
ANOTHER live pytest (a second ``make it`` at the same time).

The conftest.py of tests/integration and tests/attacks import the three hooks from here. They
are idempotent: with both conftests loaded in one session, the guard still runs once.
"""

import os
import re
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from backtide.jail import docker as jail_docker

DockerRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]

BUILTIN_NETWORKS = frozenset({"bridge", "host", "none"})
# What a person runs by hand, not a test: never removed.
DEMO_PREFIXES = ("backtide-demo-", "vigia-demo-")
# backtide-test-agent-<pid>-<hex>, backtide-test-net-<pid>-..., backtide-test-sensor-<pid>-...
_PID_NAME = re.compile(r"backtide-test-[a-z]+-(\d+)(?:-|$)")
_MARKERS = ("integration", "ataques")
_CHECK_TIMEOUT = 120.0


def _docker(args: list[str]) -> subprocess.CompletedProcess[str]:
    return jail_docker.run(args, check=False, timeout=_CHECK_TIMEOUT)


@dataclass(frozen=True)
class Item:
    """One Docker object: its id, its name and, for a container, its status."""

    id: str
    name: str
    status: str = ""

    def describe(self) -> str:
        return f"{self.name} ({self.status})" if self.status else self.name


@dataclass(frozen=True)
class Inventory:
    containers: tuple[Item, ...] = ()
    networks: tuple[Item, ...] = ()
    volumes: tuple[str, ...] = ()


@dataclass
class Leaks:
    containers: list[Item] = field(default_factory=list)
    networks: list[Item] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)  # orphans: not attached to a leaked container
    errors: list[str] = field(default_factory=list)

    def any(self) -> bool:
        return bool(self.containers or self.networks or self.volumes or self.errors)


def take_inventory(docker: DockerRunner | None = None) -> Inventory:
    """Every container (stopped ones too), every network and every volume of the daemon.
    Raises RuntimeError if Docker does not answer: a guard that cannot look must say so."""
    docker = docker or _docker
    containers = _lines(
        docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}"]),
        "docker ps",
    )
    networks = _lines(
        docker(["network", "ls", "--no-trunc", "--format", "{{.ID}}\t{{.Name}}"]),
        "docker network ls",
    )
    volumes = _lines(docker(["volume", "ls", "--quiet"]), "docker volume ls")
    return Inventory(
        containers=tuple(_item(line) for line in containers),
        networks=tuple(_item(line) for line in networks),
        volumes=tuple(line.strip() for line in volumes),
    )


def _lines(result: subprocess.CompletedProcess[str], command: str) -> list[str]:
    if result.returncode != 0:
        raise RuntimeError(f"{command} failed ({result.returncode}): {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def _item(line: str) -> Item:
    fields = line.split("\t")
    return Item(
        fields[0], fields[1] if len(fields) > 1 else "", fields[2] if len(fields) > 2 else ""
    )


def is_another_run(name: str, *, alive: Callable[[int], bool] | None = None) -> bool:
    """True if ``name`` is a test object of a DIFFERENT, live pytest process."""
    found = _PID_NAME.match(name)
    if found is None:
        return False
    pid = int(found.group(1))
    return pid != os.getpid() and (alive or _is_pytest_alive)(pid)


def _is_pytest_alive(pid: int) -> bool:
    try:
        return b"pytest" in Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False


def _ours(item: Item, alive: Callable[[int], bool] | None) -> bool:
    if item.name in BUILTIN_NETWORKS or item.name.startswith(DEMO_PREFIXES):
        return False
    return not is_another_run(item.name, alive=alive)


def find_leaks(
    before: Inventory, after: Inventory, *, alive: Callable[[int], bool] | None = None
) -> Leaks:
    """What ``after`` has that ``before`` did not, minus what is not a test's to clean up."""
    known_containers = {item.id for item in before.containers}
    known_networks = {item.id for item in before.networks}
    return Leaks(
        containers=[
            item
            for item in after.containers
            if item.id not in known_containers and _ours(item, alive)
        ],
        networks=[
            item for item in after.networks if item.id not in known_networks and _ours(item, alive)
        ],
        volumes=[volume for volume in after.volumes if volume not in set(before.volumes)],
    )


def remove_leaks(leaks: Leaks, docker: DockerRunner | None = None) -> Leaks:
    """Remove what leaked: containers (with their anonymous volumes), then the networks they
    were on, then the volumes that are still there. Returns the volumes that were still there
    after the containers went (the ones a ``rm`` without ``-v`` orphaned) and fills in
    ``errors`` with whatever could not be removed."""
    docker = docker or _docker
    if leaks.containers:
        result = docker(["rm", "--force", "--volumes", *[c.id for c in leaks.containers]])
        if result.returncode != 0:
            leaks.errors.append(f"docker rm -f -v failed: {result.stderr.strip()}")
    for network in leaks.networks:
        result = docker(["network", "rm", network.id])
        if result.returncode != 0 and "not found" not in result.stderr:
            leaks.errors.append(f"docker network rm {network.name}: {result.stderr.strip()}")
    for volume in list(leaks.volumes):
        result = docker(["volume", "rm", volume])
        if result.returncode == 0:
            continue
        if "no such volume" in result.stderr.lower():
            leaks.volumes.remove(volume)  # it went with its container: not an orphan
        elif "in use" in result.stderr.lower():
            leaks.volumes.remove(volume)  # somebody else's live container holds it
        else:
            leaks.errors.append(f"docker volume rm {volume}: {result.stderr.strip()}")
    return leaks


def collect(
    before: Inventory,
    docker: DockerRunner | None = None,
    *,
    alive: Callable[[int], bool] | None = None,
) -> Leaks:
    """Find the leaks since ``before`` and remove them. The leaks it returns are what was
    there (and is now gone, unless ``errors`` says otherwise)."""
    leaks = find_leaks(before, take_inventory(docker), alive=alive)
    if not leaks.any():
        return leaks
    return remove_leaks(leaks, docker)


def report_lines(leaks: Leaks) -> list[str]:
    lines = ["", "DOCKER LEAK: the session left Docker objects behind (now removed):"]
    for container in leaks.containers:
        lines.append(f"  container {container.describe()}")
    for network in leaks.networks:
        lines.append(f"  network   {network.name}")
    for volume in leaks.volumes:
        lines.append(f"  volume    {volume[:20]}{'...' if len(volume) > 20 else ''} (orphaned)")
    for error in leaks.errors:
        lines.append(f"  COULD NOT REMOVE: {error}")
    lines.append(
        "Fix the test that left them: its fixture must remove them, also when setup fails "
        "(`docker rm -f -v`, never without -v), instead of relying on this guard."
    )
    return lines


# The pytest hooks. A conftest.py gets them with
# `from docker_leaks import pytest_collection_finish, pytest_sessionfinish, ...`.

_BEFORE: pytest.StashKey[Inventory] = pytest.StashKey()
_RESULT: pytest.StashKey[Leaks | str] = pytest.StashKey()
_SHOWN: pytest.StashKey[bool] = pytest.StashKey()


def _will_use_docker(items: Iterable[pytest.Item]) -> bool:
    return any(item.get_closest_marker(name) for item in items for name in _MARKERS)


def pytest_collection_finish(session: pytest.Session) -> None:
    """The inventory, before the first test: only if this session runs a VM test (a unit test
    session on the Mac never touches Docker)."""
    config = session.config
    if _BEFORE in config.stash or not _will_use_docker(session.items):
        return
    try:
        config.stash[_BEFORE] = take_inventory()
    except RuntimeError as error:
        config.stash[_RESULT] = f"the leak guard could not take its inventory: {error}"


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """After every fixture is torn down: remove what is left and fail the session."""
    config = session.config
    if _RESULT not in config.stash:  # not yet decided (the inventory failed, or already done)
        if _BEFORE not in config.stash:
            return  # a session with no VM test
        try:
            config.stash[_RESULT] = collect(config.stash[_BEFORE])
        except RuntimeError as error:
            config.stash[_RESULT] = f"the leak guard could not look for leaks: {error}"
    result = config.stash[_RESULT]
    if (isinstance(result, str) or result.any()) and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED  # tests failed or Ctrl-C: already not 0


def pytest_terminal_summary(
    terminalreporter: object, exitstatus: int, config: pytest.Config
) -> None:
    write = getattr(terminalreporter, "write_line")  # noqa: B009 - a TerminalReporter
    result = config.stash.get(_RESULT, None)
    if result is None or _SHOWN in config.stash:
        return
    config.stash[_SHOWN] = True
    if isinstance(result, str):
        write("")
        write(f"DOCKER LEAK GUARD: {result}", red=True, bold=True)
        return
    if result.any():
        for line in report_lines(result):
            write(line, red=True, bold=True)
