"""The pause by space outside the Guardian: what resuming answers, what holds the space, the
real space gate and the threads that tick. Design: docs/19-diseno-t04.md, section 5.

- ``ResumeOutcome`` is what ``Guardian.resume`` (``vigia seguir``) returns, with the CLI's
  exit code.
- ``read_holders`` lists what holds room on the volume, from the level-0 qgroups in /sys: the
  workspace (against its cap), every undo point and the subvolumes that are gone but still hold
  space through snapshots (simple quotas keep their qgroup). ``holders_text`` is the part of the
  alert that names them, in Spanish: rewinding gives a whole new cap, but frees nothing.
- ``make_space_gate`` is the real ``space`` of the Guardian: a fresh ``space.sample`` evaluated
  with ``space.evaluate_sample`` (P1-P6; P7 and staleness are the Guardian's own), and the early
  warnings when nothing pauses.
- ``Ticker`` runs one step every interval in a thread of its own, logging (never swallowing)
  what a step raises: the space thread and its watchdog.
"""

import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, tzinfo
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from vigia.service.config import ServiceConfig
from vigia.snapshots import Snapshot, btrfs, space
from vigia.snapshots.space import MIB

logger = logging.getLogger(__name__)

TOP_HOLDERS = 5
_TOP_LEVEL_TREE = 5  # the btrfs's own top-level subvolume: never the agent's
REASON_NAMES = {
    "periodic": "periódica",
    "manual": "manual",
    "pre_restore": "antes de rebobinar",
    "recovered": "recuperada",
}


class ResumeStatus(StrEnum):
    RESUMED = "resumed"  # the pause by space is closed and the agent runs again
    NOT_PAUSED = "not_paused"  # there was no pause by space to close
    STOPPED = "stopped"  # no pause to close, but the agent is stopped: nothing here starts it
    STILL_RED = "still_red"  # a condition still stands: nothing changed
    STILL_PAUSED = "still_paused"  # the space pause is closed, another reason keeps it paused
    FAILED = "failed"  # no service to resume anything
    PROBLEM = "problem"  # the pause is closed, but the agent could not be thawed or started


RESUME_EXIT_CODES = {
    ResumeStatus.RESUMED: 0,
    ResumeStatus.NOT_PAUSED: 0,
    ResumeStatus.STOPPED: 1,
    ResumeStatus.STILL_RED: 1,
    ResumeStatus.STILL_PAUSED: 1,
    ResumeStatus.FAILED: 1,
    ResumeStatus.PROBLEM: 3,
}


@dataclass(frozen=True)
class ResumeOutcome:
    """What ``Guardian.resume`` did. ``message`` is for the person, in Spanish, and carries
    nothing of the agent's."""

    status: ResumeStatus
    message: str
    agent_state: str = ""

    @property
    def exit_code(self) -> int:
        return RESUME_EXIT_CODES[self.status]


# What holds the space


@dataclass(frozen=True)
class Holder:
    """One generation that holds room on the volume. ``size`` is its qgroup's ``exclusive``
    (under simple quotas, what it wrote and is still on disk)."""

    kind: Literal["workspace", "snapshot", "other"]
    name: str  # "workspace", a snapshot id, or "0/<id>"
    size: int
    taken_at: datetime | None = None
    reason: str | None = None


class _Store(Protocol):
    @property
    def root(self) -> Path: ...

    @property
    def workspace(self) -> Path: ...

    @property
    def snapshots_dir(self) -> Path: ...

    def snapshots(self) -> list[Snapshot]: ...


def read_holders(store: _Store, *, sysfs: Path = btrfs.SYSFS_BTRFS) -> list[Holder]:
    """Every generation of the volume of ``store`` with its qgroup: the workspace, each
    snapshot, and each other level-0 qgroup (a deleted workspace that snapshots still share,
    or a subvolume that is not Vigía's). Unprivileged. Raises SnapshotError if /sys or a
    subvolume cannot be read; the caller says it could not tell."""
    qgroups = btrfs.level0_qgroups(store.root, sysfs=sysfs)
    workspace_id = btrfs.subvolume_id(store.workspace)
    live = {workspace_id, _TOP_LEVEL_TREE}
    holders: list[Holder] = []
    if workspace_id in qgroups:
        holders.append(Holder("workspace", "workspace", qgroups[workspace_id].exclusive))
    for snap in store.snapshots():
        snapshot_id = btrfs.subvolume_id(store.snapshots_dir / snap.id)
        live.add(snapshot_id)
        if snapshot_id in qgroups:
            holders.append(
                Holder(
                    "snapshot",
                    snap.id,
                    qgroups[snapshot_id].exclusive,
                    taken_at=snap.taken_at,
                    reason=snap.reason,
                )
            )
    for qgroup_id, usage in sorted(qgroups.items()):
        if qgroup_id not in live and usage.exclusive > 0:
            holders.append(Holder("other", f"0/{qgroup_id}", usage.exclusive))
    return holders


def holders_text(
    holders: Sequence[Holder],
    limit: int | None,
    *,
    top: int = TOP_HOLDERS,
    tz: tzinfo | None = None,
) -> list[str]:
    """The ``top`` generations that hold the most, largest first, one line each, in Spanish.
    The workspace is always among them (against its cap ``limit``): it is the one the agent
    fills. Pure."""
    ranked = sorted(holders, key=lambda holder: holder.size, reverse=True)
    chosen = ranked[:top]
    workspace = next((h for h in ranked if h.kind == "workspace"), None)
    if workspace is not None and workspace not in chosen:
        chosen = [*ranked[: top - 1], workspace]
    return [f"- {_holder_line(holder, limit, tz)}" for holder in chosen]


def _holder_line(holder: Holder, limit: int | None, tz: tzinfo | None) -> str:
    size = _mib(holder.size)
    if holder.kind == "workspace":
        cap = f" de {_mib(limit)}" if limit is not None else ""
        return f"el espacio de trabajo actual: {size}{cap}"
    if holder.kind == "snapshot":
        when = holder.taken_at.astimezone(tz).strftime("%Y-%m-%d %H:%M") if holder.taken_at else ""
        why = REASON_NAMES.get(holder.reason or "", holder.reason or "")
        return f"punto de deshacer {holder.name} ({why}, {when}): {size}"
    return f"espacio de trabajo borrado u otro subvolumen {holder.name}: {size}"


_CONDITION_TEXT = {
    "P1": "metadatos: quedan {value}, mínimo {threshold}",
    "P2": "datos: quedan {value}, mínimo {threshold}",
    "P3": "el espacio de trabajo usa {value}, más que su tope de {threshold}",
    "P6": "disco de Vigía: quedan {value} libres, mínimo {threshold}",
}
_PLAIN_TEXT = {
    "P4": "no se puede comprobar el espacio",
    "P5": "el espacio de trabajo no tiene su tope",
    "P7": "la caja negra no graba",
}


class _Described(Protocol):
    code: str
    message: str


def condition_text(condition: _Described) -> str:
    """One condition for the person, in Spanish, with its figures when it has them. Pure."""
    value = getattr(condition, "value", None)
    threshold = getattr(condition, "threshold", None)
    template = _CONDITION_TEXT.get(condition.code)
    if template is not None and isinstance(value, int) and isinstance(threshold, int):
        return template.format(value=_mib(value), threshold=_mib(threshold))
    prefix = _PLAIN_TEXT.get(condition.code)
    if prefix is None or condition.message.startswith(prefix):
        return condition.message
    return f"{prefix} ({condition.message})"


# The real gate

type Gate = Callable[[], Sequence[space.Condition]]
type Sampler = Callable[[Path, Path, Path], space.Sample]


class _Paths(Protocol):
    @property
    def root(self) -> Path: ...

    @property
    def workspace(self) -> Path: ...


def make_space_gate(
    config: ServiceConfig,
    store: _Paths,
    *,
    sample: Sampler = space.sample,
    cfg: space.SpaceConfig = space.DEFAULT_CONFIG,
) -> Gate | None:
    """The ``space`` of the Guardian: read every signal now and return the conditions that
    hold (P1-P6, in order), or, when none does, the early warnings (``W1``, ``W3``). None
    without a configured cap: without L there is nothing to measure against (the Guardian then
    checks only P4 and P5 after a rewind, as before T04d-2).

    The reading is fresh, so its age is 0 and a stale check is never its business (the
    watchdog's); P7 comes from the Guardian's own counters. A signal that cannot be read is P4
    (``evaluate_sample``)."""
    limit = config.workspace_limit
    if limit is None:
        return None
    fresh = space.Health(check_age=0.0, agent_running=False)

    def gate() -> list[space.Condition]:
        reading = sample(store.root, store.workspace, config.state_dir)
        found = space.evaluate_sample(reading, limit, cfg, health=fresh)
        if found:
            return found
        return space.early_warnings(reading.space, reading.usage, limit, cfg)

    return gate


# The threads


class Ticker:
    """``step()`` at once and then every ``every`` seconds (counted from the end of the last
    one), in a daemon thread called ``name``, until ``close()``. An exception of a step is
    logged with its trace (it reaches the black box through the log bridge) and the next tick
    tries again: a broken step never ends the thread."""

    def __init__(self, name: str, every: float, step: Callable[[], None]) -> None:
        self._name = name
        self._every = every
        self._step = step
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        self._thread.start()

    def close(self, timeout: float = 30.0) -> None:
        self._stop.set()
        if self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout)
            if self._thread.is_alive():
                logger.error("the %s thread did not stop in %.0f s", self._name, timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._step()
            except Exception:
                logger.exception("a step of the %s thread failed", self._name)
            self._stop.wait(self._every)


def _mib(size: int | None) -> str:
    return f"{(size or 0) / MIB:.1f} MiB"


__all__ = [
    "Holder",
    "RESUME_EXIT_CODES",
    "ResumeOutcome",
    "ResumeStatus",
    "Ticker",
    "condition_text",
    "holders_text",
    "make_space_gate",
    "read_holders",
]
