"""The manifest of the evil-agent battery (manifest.toml), loaded and validated. Pure: no VM.

Every scenario says what backtide is expected to do in five dimensions (``DIMENSIONS``). A
dimension is either a final value or ``pending:Txx``: it will exist when that task is built,
and until then it is reported as pending, never as passed.
"""

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

MANIFEST_PATH = Path(__file__).with_name("manifest.toml")
SCRIPTS_DIR = Path(__file__).with_name("scripts")

# What each dimension can say (besides "pending:Txx").
DIMENSIONS: Mapping[str, tuple[str, ...]] = {
    "stopped": ("yes", "contained", "no", "n/a"),
    "recorded": ("yes", "no", "n/a"),
    "risk": ("0", "1", "2", "3", "n/a"),
    "recoverable": ("yes", "no", "n/a"),
    "held": ("yes", "no", "n/a"),
}
STATUSES = ("ready", "pending")
INVARIANTS = range(1, 9)  # CLAUDE.md, "Invariantes de seguridad"
_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
_TASK_RE = re.compile(r"T[0-9]{2}(?:[a-e](?:-[1-9])?)?", re.ASCII)
_PENDING_PREFIX = "pending:"
_REQUIRED_TEXT = ("id", "name", "story", "inspired_by", "status")


class ManifestError(Exception):
    """manifest.toml is malformed."""


@dataclass(frozen=True)
class Expectation:
    """One dimension of one scenario: a final value, or ``pending:Txx``."""

    value: str

    @property
    def pending_task(self) -> str | None:
        """The task that makes this dimension checkable, or None if it is final."""
        return self.value.removeprefix(_PENDING_PREFIX) if self.is_pending else None

    @property
    def is_pending(self) -> bool:
        return self.value.startswith(_PENDING_PREFIX)

    @property
    def must_be_checked(self) -> bool:
        """True when a ready scenario has to check it: final, and not "n/a"."""
        return not self.is_pending and self.value != "n/a"


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    story: str  # what the attacker tries
    inspired_by: str
    invariants: tuple[int, ...]
    status: str  # "ready" (a test runs it today) or "pending" (waits for ``task``)
    task: str | None  # for pending scenarios: the task that makes them possible
    expect: Mapping[str, Expectation]

    @property
    def is_ready(self) -> bool:
        return self.status == "ready"

    @property
    def pending_tasks(self) -> tuple[str, ...]:
        """Tasks the pending dimensions of a ready scenario wait for, in order, without
        repeats."""
        found: list[str] = []
        for dimension in DIMENSIONS:
            task = self.expect[dimension].pending_task
            if task is not None and task not in found:
                found.append(task)
        return tuple(found)

    @property
    def script(self) -> str:
        """The in-container script's file name stem (the id with underscores)."""
        return self.id.replace("-", "_")


def load_manifest(path: Path = MANIFEST_PATH) -> list[Scenario]:
    """Read and validate the manifest; ManifestError says what is wrong and where."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ManifestError(f"cannot read {path}: {error}") from error
    entries = data.get("scenario")
    if not isinstance(entries, list) or not entries:
        raise ManifestError("the manifest has no [[scenario]]")
    scenarios = [_parse(entry, index) for index, entry in enumerate(entries, start=1)]
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario.id in seen:
            raise ManifestError(f"duplicate scenario id {scenario.id!r}")
        seen.add(scenario.id)
    return scenarios


def _parse(entry: object, index: int) -> Scenario:
    where = f"scenario #{index}"
    if not isinstance(entry, dict):
        raise ManifestError(f"{where}: not a table")
    for key in _REQUIRED_TEXT:
        if not isinstance(entry.get(key), str) or not entry[key].strip():
            raise ManifestError(f"{where}: {key!r} must be a non-empty string")
    scenario_id = entry["id"]
    where = f"scenario {scenario_id!r}"
    if not _ID_RE.fullmatch(scenario_id):
        raise ManifestError(f"{where}: the id must be lowercase words joined by hyphens")
    status = entry["status"]
    if status not in STATUSES:
        raise ManifestError(f"{where}: status must be one of {STATUSES}, got {status!r}")
    task = entry.get("task")
    if status == "pending":
        if not isinstance(task, str) or not _TASK_RE.fullmatch(task):
            raise ManifestError(f"{where}: a pending scenario needs a task such as 'T04a'")
    elif task is not None:
        raise ManifestError(f"{where}: a ready scenario has no 'task' (use pending:Txx)")
    invariants = entry.get("invariants")
    if (
        not isinstance(invariants, list)
        or not invariants
        or not all(type(n) is int and n in INVARIANTS for n in invariants)
    ):
        raise ManifestError(f"{where}: invariants must be a list of numbers 1 to 8")
    return Scenario(
        id=scenario_id,
        name=entry["name"],
        story=" ".join(entry["story"].split()),
        inspired_by=entry["inspired_by"],
        invariants=tuple(invariants),
        status=status,
        task=task,
        expect=_parse_expect(entry.get("expect"), where),
    )


def _parse_expect(table: object, where: str) -> dict[str, Expectation]:
    if not isinstance(table, dict) or set(table) != set(DIMENSIONS):
        raise ManifestError(f"{where}: [scenario.expect] needs exactly {sorted(DIMENSIONS)}")
    expect: dict[str, Expectation] = {}
    for dimension, allowed in DIMENSIONS.items():
        value = table[dimension]
        if not isinstance(value, str):
            raise ManifestError(f"{where}: {dimension} must be a string")
        pending = value.removeprefix(_PENDING_PREFIX)
        if value.startswith(_PENDING_PREFIX):
            if not _TASK_RE.fullmatch(pending):
                raise ManifestError(f"{where}: {dimension} = {value!r}: not 'pending:Txx'")
        elif value not in allowed:
            raise ManifestError(f"{where}: {dimension} must be one of {allowed}, got {value!r}")
        expect[dimension] = Expectation(value)
    return expect
