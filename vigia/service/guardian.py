"""Guardian: the service that owns the agent. It starts it, snapshots its workspace when Btrfs
says something changed, and stops it. Design: docs/19-diseno-t04.md, section 3.

- **The agent only runs while Vigía watches it.** ``start()`` stops an agent it finds running (the
  service died and came back) and says so; ``stop()`` stops the agent. Without a black box the
  service does not start, and an agent found running is stopped.
- **Btrfs decides when to snapshot, the file watcher only describes** (``activity.py``): every
  cycle compares the workspace's ``ctransid`` with its lineage reference, whatever the watcher
  saw or lost.
- **Every snapshot goes through the watcher's barrier** (``watcher.barrier(take)``): drain, take,
  drain, and only then is the new snapshot the one changes point to. So a change is never
  pointed at a snapshot that already contains it.
- **Alerts go after the event.** Every notable thing is recorded first and the alert cites it.
  ``logging`` WARNING and ERROR of ``vigia.*`` (the store's, for one) reach the black box and
  the alerts through the bridge in ``vigia.notify``.
- **Nothing on the security path is swallowed.** A failure is recorded and alerted; if even the
  black box fails, it is logged at ERROR and alerted. "No recording, no watching": if the black
  box opens but the first event cannot be written, the service does not start.
- **Alerts carry no secrets and no agent output.** Every title and body goes through
  ``redact`` in ``_alert``; a Docker error (which may quote the agent's logs) is never put in a
  body, the alert points at the event instead.
- **Stopping the agent is decided by Docker's state, not by memory**: a frozen container still
  reports "running" and ``docker stop`` would wake it up, so ``_halt`` kills a paused one, and
  falls back to kill and ``rm --force`` when a stop fails. The space seam fails closed: an
  exception from ``space()``, or a failed ``btrfs filesystem sync``, counts as a condition.

- **One way to rewind** (T04c-1, docs/19 section 4): ``rewind()``. It writes its intent
  (``rewind.pending``) before anything changes, decides what happened by comparing workspace ids
  (never by the type of an exception), and starts the agent afterwards only if it should run and
  the space is green. A rewind killed half way is reconciled at the next start.

Not here yet: the space thread, ``vigia seguir`` and the pause thresholds (T04d), growth (T04e),
the control socket (T04c-2). ``space`` is the seam T04d plugs into: a function that returns
the conditions that forbid the agent to run, evaluated after a ``btrfs filesystem sync`` before
every snapshot and every agent start. The Guardian only reacts to what it says by not
snapshotting and by freezing (``jail.pause()``, added in T04d; if it fails, the agent is killed).

Synchronous and thread-hostile in the places that matter: ``start()``, ``cycle()`` and
``stop()`` are called by one thread (``run()``); ``rewind()`` may come from another one.
``agent_lock`` serialises what starts or stops the agent, and the cycle, which skips itself
while a rewind holds it; ``freeze_lock`` guards only ``agent_state`` and ``pause_reasons`` for a
few milliseconds, so freezing never waits for a long ``docker stop``.
"""

import logging
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol
from uuid import uuid4

import vigia
from vigia.blackbox import BlackBox, BlackBoxError, Event, redact
from vigia.jail import AgentJail, JailError
from vigia.jail.openclaw import UnrewindableConfig
from vigia.notify import Alert, AlertLevel, AlertSink, LogBridge, LoggedProblem
from vigia.service.clock import clock_synced as kernel_clock_synced
from vigia.service.config import ServiceConfig
from vigia.service.rewind import (
    PendingError,
    PendingRewind,
    RewindOutcome,
    RewindStatus,
    is_space_error,
    read_pending,
    remove_pending,
    write_pending,
)
from vigia.snapshots import (
    PruneIncomplete,
    Reason,
    RestoreIncomplete,
    RestoreResult,
    Snapshot,
    SnapshotBusy,
    SnapshotError,
    SnapshotNoSpace,
    SnapshotStore,
    btrfs,
    space,
    utc_now,
)
from vigia.snapshots.activity import SnapshotInfo, changed_since, lineage_reference

logger = logging.getLogger(__name__)

BUSY_ALERT_AFTER = 3  # SnapshotBusy cycles in a row before the user hears about it
CLOCK_ALERT_EVERY = 24 * 3600.0  # prune blocked by the clock: one alert a day
REPEAT_ALERT_EVERY = 3600.0  # the same failure, over and over: one alert an hour
MAX_LISTED_SNAPSHOTS = 20  # ids kept in the details of a prune event
MAX_ERROR_CHARS = 500
ALERT_EXCERPT_CHARS = 300
MAX_REQUESTER_CHARS = 64
# The pause reasons that are about space or the black box: a rewind that ends green clears them
# and starts the agent (docs/19, section 4). Any other reason ("user", T09) keeps it stopped.
SPACE_REASONS = frozenset({"space", "rewind_no_space", "blackbox"})
# Until the space thread exists (T04d-2) and plugs ``space`` in, the start after a rewind checks
# only that the workspace has its cap (P5), and that the signals could be read at all (P4).
_CHECKED_WITHOUT_SPACE_GATE = frozenset({"P4", "P5"})

_BRIDGED_LOGGERS = "vigia"


class AgentState(StrEnum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FROZEN = "frozen"


# The states in which the agent may run code, so a space condition must freeze it: also while
# `docker stop` waits for its SIGTERM handler and while `wait_ready` waits for it (a rewind).
_CAN_RUN_CODE = frozenset({AgentState.RUNNING, AgentState.STARTING, AgentState.STOPPING})


class FileWatcher(Protocol):
    """What the Guardian needs from the file watcher (``vigia.sensors.files.FileWatcher``).

    Nothing here raises for an environmental failure: the watcher records ``system/watcher_failed``
    itself. The Guardian still defends itself against an exception, because a broken watcher
    must never stop the snapshots."""

    def arm(self, current: str | None = None) -> bool:
        """Watch the agent's folder; ``current`` is the snapshot changes point to. False if
        it could not (the agent can run anyway; ``rearm_if_moved`` tries again)."""
        ...

    def barrier(self, take: Callable[[], Snapshot]) -> Snapshot:
        """drain, ``take()``, drain, and then the new snapshot becomes the current one. An
        exception of ``take`` propagates and the current snapshot stays."""
        ...

    def rearm_if_moved(self, workspace_id: int) -> bool:
        """Every cycle: watch the workspace again if it is no longer the one being watched, or
        if the last arming failed."""
        ...

    def report_unwatched(self) -> bool:
        """Every cycle in which Btrfs says the workspace changed: record
        ``file/dropped {unwatched_dirs}`` if some folders have no watch."""
        ...

    def suspended(self, new_current: str | None = None) -> AbstractContextManager[object]:
        """Around a rewind's swap: drain, write and close on entry; on exit, if the workspace
        changed, ``new_current`` becomes the current snapshot and the new workspace is armed
        (``system/watcher_armed``). Never raises."""
        ...

    def close(self) -> None:
        """Stop for good: drain, write what is pending, close everything."""
        ...


class Violation(Protocol):
    """One space or black-box condition that forbids the agent to run (T04d's ``Condition``)."""

    code: str
    message: str
    reason: str  # the ``pause_reasons`` entry: "space" or "blackbox"


type SpaceGate = Callable[[], Sequence[Violation]]


@dataclass(frozen=True)
class _Blind:
    """P4 made by the Guardian itself: it could not find out, which counts against the agent."""

    message: str
    code: str = "P4"
    reason: str = "space"


@dataclass(frozen=True)
class CycleResult:
    """What one cycle did. ``snapshot`` is None when nothing changed or the snapshot failed or
    was refused; ``pruned`` is None when pruning was not due, did not run or failed. ``skipped``:
    a rewind (or another change of the agent) held ``agent_lock``, so the cycle did nothing."""

    changed: bool
    snapshot: Snapshot | None = None
    pruned: tuple[Snapshot, ...] | None = None
    skipped: bool = False


@dataclass
class _RewindAttempt:
    """What one rewind decided and what happened to the agent along the way."""

    request_id: str
    target: Snapshot
    want_running: bool
    from_workspace: int | None = None
    stopped: bool = False  # quiesce stopped the agent (the swap may follow)
    final_recorded: bool = False  # rewind_done / rewind_failed is in the black box
    start_requested: bool = False
    agent_started: bool = False
    start_error: Exception | None = None
    problems: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Assessment:
    workspace: btrfs.SubvolumeInfo
    reference: SnapshotInfo | None
    changed: bool


class Guardian:
    def __init__(
        self,
        config: ServiceConfig,
        *,
        store: SnapshotStore,
        jail: AgentJail,
        blackbox: BlackBox,
        watcher: FileWatcher,
        alerts: AlertSink,
        space: SpaceGate | None = None,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        info: Callable[[Path], btrfs.SubvolumeInfo] = btrfs.subvolume_info,
        sync: Callable[[Path], None] = btrfs.sync_filesystem,
        clock_synced: Callable[[], bool] = kernel_clock_synced,
        sample: Callable[[Path, Path, Path], space.Sample] = space.sample,
    ) -> None:
        """Every collaborator is injected, so the tests use fakes. ``alerts`` is where alerts
        go (an ``AlertQueue`` in production); the caller starts and closes it. ``sample``
        reads the space signals (``space.sample(root, workspace, state_dir)``) for the start
        after a rewind while ``space`` is not plugged in (T04d-2)."""
        self._config = config
        self._store = store
        self._jail = jail
        self._box = blackbox
        self._watcher = watcher
        self._alerts = alerts
        self._space = space
        self._clock = clock
        self._mono = monotonic
        self._info = info
        self._sync = sync
        self._clock_synced = clock_synced
        self._sample = sample

        self.agent_lock = threading.Lock()
        self.freeze_lock = threading.Lock()
        self._agent_state = AgentState.STOPPED
        self._pause_reasons: set[str] = set()

        self._bridge = LogBridge(self._on_log)
        self._stopped = False  # the agent really stopped
        self._wound_down = False  # watcher closed, service_stop recorded, bridge removed
        self._serving = False  # booted (black box open, service_start recorded), not wound down
        self._previous_run = False  # the black box had events before this start
        self._busy_cycles = 0
        self._next_prune = 0.0
        self._last_prune_ok = 0.0
        self._last_alerted: dict[str, float] = {}
        self._record_failures = 0  # appends that failed: a rewind reports them (exit code 3)
        self._record_failures_lock = threading.Lock()

    # State

    @property
    def agent_state(self) -> AgentState:
        with self.freeze_lock:
            return self._agent_state

    @property
    def pause_reasons(self) -> frozenset[str]:
        with self.freeze_lock:
            return frozenset(self._pause_reasons)

    def _set_state(self, state: AgentState) -> None:
        with self.freeze_lock:
            self._agent_state = state

    # Start

    def start(self) -> None:
        """The boot sequence (docs/19, section 3). Raises if the service cannot run: no black
        box, a jail that cannot be set up, a store that is broken. An agent that merely fails
        to start is recorded and alerted, and the service stays up with the agent stopped."""
        with self.agent_lock:
            self._stopped = False
            self._wound_down = False
            try:
                self._open_black_box()
            except BaseException:
                self._wound_down = True  # nothing was recorded or armed: only the agent is left
                raise
            self._serving = True
            self._bridge = LogBridge(self._on_log)
            self._bridge.start()
            logging.getLogger(_BRIDGED_LOGGERS).addHandler(self._bridge)
            try:
                self._boot()
            except BaseException as error:
                self._boot_failed(error)
                self._abort_boot(error)
                raise

    def _boot_failed(self, error: BaseException) -> None:
        """Record why the boot failed and, for a config a rewind would break, say so in the
        user's language: the alert carries the error's own Spanish notice (paths of the config,
        never values), and the caller prints it again when it exits."""
        details: dict[str, Any] = {"error": _short(error)}
        if isinstance(error, UnrewindableConfig):
            details["reason"] = "unrewindable_config"
            details["problems"] = [problem.path for problem in error.problems]
        event = self._record("system", "service_start_failed", details=details, risk=2)
        if isinstance(error, UnrewindableConfig):
            self._alert(
                AlertLevel.ERROR,
                "La configuración del agente no se puede rebobinar",
                error.notice,
                event,
            )

    def _open_black_box(self) -> None:
        """Open the black box AND write ``service_start``: no recording, no watching. If either
        fails the service does not start, and an agent found running is stopped."""
        try:
            self._box.open()
            self._previous_run = self._box.head() is not None
            self._box.append("system", "service_start", "", details={"version": vigia.__version__})
        except BlackBoxError as error:
            logger.error("cannot use the black box, so the service does not start: %s", error)
            self._alert(
                AlertLevel.ERROR,
                "La caja negra no se puede usar",
                "Vigía no arranca: sin grabar no hay vigilancia. "
                f"Si el agente estaba en marcha, se para. Causa: {_excerpt(error)}",
            )
            self._stop_unrecorded(error)
            raise

    def _stop_unrecorded(self, error: BaseException) -> None:
        """The black box is not usable: stop an agent that is running, with nothing to record."""
        try:
            running = self._jail.is_running()
        except JailError:
            running = True  # cannot tell: try to stop it
        if not running:
            return
        stop_error = self._halt()
        if stop_error is not None:
            error.add_note(f"stopping the running agent also failed: {stop_error}")
            logger.error("cannot stop the agent while the black box is down: %s", stop_error)

    def _boot(self) -> None:
        now = self._mono()
        self._last_prune_ok = now
        self._next_prune = now + self._config.prune_interval
        self._stop_unsupervised_agent()
        self._store.init()
        self._recover_store()
        self._reconcile_rewinds()
        self._note_downtime()
        self._prepare_jail()
        if self._space_forbids_start():
            return
        current = self._startup_snapshot()
        self._arm_watcher(current)
        self._start_agent()

    def _abort_boot(self, error: BaseException) -> None:
        """The boot failed halfway: leave nothing running that nobody watches. The caller
        raises ``error``; whatever cleanup also fails is added to it as a note."""
        self._serving = False
        self._wound_down = True
        try:
            running = self._jail.is_running()
        except JailError:
            running = True
        if running:
            stop_error = self._halt()
            if stop_error is None:
                self._set_state(AgentState.STOPPED)
                self._record("system", "agent_stop", details={"reason": "boot_failed"}, risk=1)
            else:
                self._stopped = False  # stop() may try again
                self._wound_down = False
                error.add_note(
                    f"stopping the agent after the failed boot also failed: {stop_error}"
                )
                logger.error("cannot stop the agent after a failed boot: %s", stop_error)
                return
        self._stopped = True
        self._watcher_step("close", self._watcher.close)
        logging.getLogger(_BRIDGED_LOGGERS).removeHandler(self._bridge)
        self._bridge.close()

    def _stop_unsupervised_agent(self) -> None:
        """Step 3: an agent already running means the service died and came back."""
        if not self._jail.is_running():
            return
        self._set_state(AgentState.STOPPING)
        error = self._halt()
        if error is not None:
            self._set_state(AgentState.RUNNING)
            event = self._record(
                "system",
                "agent_stop_failed",
                details={"reason": "unsupervised", "error": _short(error)},
                risk=3,
            )
            self._alert(
                AlertLevel.ERROR,
                "No se pudo parar un agente sin vigilancia",
                "El agente estaba en marcha sin que Vigía lo vigilase y no se ha podido parar: "
                "sigue en marcha. Detalles en el evento.",
                event,
            )
            raise error
        self._set_state(AgentState.STOPPED)
        event = self._record("system", "agent_stop", details={"reason": "unsupervised"}, risk=2)
        self._alert(
            AlertLevel.ERROR,
            "El agente corría sin vigilancia",
            "Vigía se había parado y el agente seguía en marcha sin que nadie lo grabase. "
            "Se ha parado y volverá a arrancar vigilado.",
            event,
        )

    def _recover_store(self) -> None:
        try:
            published = self._store.recover()
        except SnapshotError as error:
            event = self._record(
                "snapshot",
                "recover_failed",
                details={"error": _short(error), "no_space": isinstance(error, SnapshotNoSpace)},
                risk=2,
            )
            self._alert(
                AlertLevel.ERROR,
                "No se pudo terminar una operación interrumpida",
                "Quedan restos de una operación a medias que no se han podido resolver: "
                f"{_excerpt(error)}",
                event,
            )
            return
        for snap in published:
            self._record(
                "snapshot",
                "recovered",
                snap.id,
                details={"reason": snap.reason},
                risk=1,
                snapshot_id=snap.id,
            )

    def _note_downtime(self) -> None:
        """Step 6: if the workspace changed since its reference while nobody was watching, the
        file events of that window do not exist. Say so."""
        assessment = self._assess()
        reference = assessment.reference
        if reference is None and not self._previous_run:
            return  # the very first start: there was nobody to miss
        if reference is not None and not assessment.changed:
            return
        # With no reference but an earlier run on record, there is nothing to compare with: say
        # that we cannot tell (no ``since``, no snapshot to rewind to).
        self._record(
            "file",
            "dropped",
            ".",
            details={
                "reason": "watcher_down",
                "count": None,
                "since": _iso(reference.snapshot.taken_at) if reference else None,
                "until": _iso(self._clock()),
                "workspace_id": assessment.workspace.treeid,
            },
            risk=1,
            snapshot_id=reference.snapshot.id if reference else None,
        )

    def _prepare_jail(self) -> None:
        self._jail.ensure_network()
        self._jail.prepare_workspace()
        self._jail.write_config()
        if not self._jail.exists():
            self._jail.create()

    def _space_forbids_start(self) -> bool:
        """Step 8 (T04d plugs in): the agent does not start with a condition standing."""
        violations = self._space_verdict()
        if not violations:
            return False
        self._pause(violations, freeze=False)
        return True

    def _startup_snapshot(self) -> str | None:
        """Step 9: with the agent stopped, snapshot the workspace if it changed or has no
        reference, through the barrier. Returns the snapshot id changes point to."""
        assessment = self._assess()
        reference = assessment.reference
        if reference is not None and not assessment.changed:
            return reference.snapshot.id
        snapshot = self._take(Reason.PERIODIC, "startup", assessment.workspace)
        if snapshot is not None:
            return snapshot.id
        return reference.snapshot.id if reference is not None else None

    def _arm_watcher(self, current: str | None) -> None:
        """Step 10: before the agent starts, so it never runs unwatched."""
        armed = self._watcher_step("arm", lambda: self._watcher.arm(current=current))
        if armed is True:
            return
        self._alert(
            AlertLevel.ERROR,
            "El vigilante de archivos no está armado",
            "No se han podido poner los avisos de archivos. El agente arranca igualmente, "
            "porque las instantáneas no dependen de ellos, pero los cambios de archivos "
            "no se describirán hasta que se rearme (se reintenta en cada ciclo).",
        )

    def _start_agent(self) -> None:
        """Step 11."""
        self._set_state(AgentState.STARTING)
        try:
            self._jail.start()
            self._jail.wait_ready()
        except JailError as error:
            self._agent_did_not_start(error)
            return
        self._set_state(AgentState.RUNNING)
        self._record("system", "agent_start")

    def _agent_did_not_start(self, error: JailError) -> None:
        """``start`` or ``wait_ready`` failed. Docker's error may quote the agent's own logs,
        so it goes into the event (redacted by the black box) and never into the alert."""
        quota = "disk quota exceeded" in str(error).lower()
        try:
            running = self._jail.is_running()
        except JailError:
            running = True  # cannot tell
        halt_error = self._halt() if running else None
        still_running = halt_error is not None
        self._set_state(AgentState.RUNNING if still_running else AgentState.STOPPED)
        event = self._record(
            "system",
            "agent_start_failed",
            details={"error": _short(error), "quota": quota, "still_running": still_running},
            risk=3 if still_running else 2,
        )
        if still_running:
            stop_event = self._record(
                "system",
                "agent_stop_failed",
                details={"reason": "start_failed", "error": _short(halt_error)},
                risk=3,
            )
            self._alert(
                AlertLevel.ERROR,
                "El agente sigue en marcha sin estar listo",
                "El agente no ha terminado de arrancar y no se ha podido parar: sigue en "
                "marcha. Detalles en el evento.",
                stop_event or event,
            )
            return
        if quota:
            body = (
                "El agente no ha podido arrancar porque su carpeta ha llegado al tope de "
                "espacio: borra archivos del agente o sube el tope, y reinicia Vigía."
            )
        else:
            body = "El agente no ha podido arrancar. Detalles en el evento."
        self._alert(AlertLevel.ERROR, "El agente no ha arrancado", body, event)

    # Cycle

    def cycle(self) -> CycleResult:
        """One pass of the 120 s loop: rearm the watcher if needed, snapshot if Btrfs says the
        workspace changed, prune now and then. Failures are recorded and alerted, never raised:
        the next cycle tries again.

        Holds ``agent_lock`` (without waiting for it): while a rewind holds it, the cycle is
        skipped. So the cycle never reads the workspace id before a swap and rearms the watcher
        after it (the rewind rearms it itself), and never waits on the volume lock that the
        rewind holds for its whole length."""
        if not self.agent_lock.acquire(blocking=False):
            logger.info("a rewind is in progress: this cycle is skipped")
            return CycleResult(changed=False, skipped=True)
        try:
            return self._cycle_locked()
        finally:
            self.agent_lock.release()

    def _cycle_locked(self) -> CycleResult:
        try:
            workspace_id = self._store.workspace_id()
        except SnapshotError as error:
            self._cycle_problem("workspace_id", error)
            return CycleResult(changed=False)
        self._watcher_step("rearm", lambda: self._watcher.rearm_if_moved(workspace_id))
        try:
            assessment = self._assess()
        except SnapshotError as error:
            self._cycle_problem("assess", error)
            return CycleResult(changed=False)
        snapshot = None
        if assessment.changed:
            self._watcher_step("report_unwatched", self._watcher.report_unwatched)
            snapshot = self._take(Reason.PERIODIC, "cycle", assessment.workspace, check_space=True)
        return CycleResult(
            changed=assessment.changed, snapshot=snapshot, pruned=self._maybe_prune()
        )

    def _assess(self) -> _Assessment:
        """Did the workspace change since its lineage reference? If the counters match, commit
        the transaction and read again: ``generation`` only moves on commit."""
        workspace = self._info(self._store.workspace)
        reference = lineage_reference(workspace, self._snapshot_infos())
        if changed_since(workspace, reference.info if reference else None):
            return _Assessment(workspace, reference, changed=True)
        if not self._sync_quietly():
            return _Assessment(workspace, reference, changed=True)  # cannot tell: be safe
        workspace = self._info(self._store.workspace)
        changed = changed_since(workspace, reference.info if reference else None)
        return _Assessment(workspace, reference, changed=changed)

    def _snapshot_infos(self) -> list[SnapshotInfo]:
        found = []
        for snap in self._store.snapshots():
            try:
                found.append(SnapshotInfo(snap, self._info(self._store.snapshots_dir / snap.id)))
            except SnapshotError as error:
                logger.warning("cannot read the lineage of snapshot %s: %s", snap.id, error)
        return found

    def _sync_quietly(self) -> bool:
        try:
            self._sync(self._store.root)
        except SnapshotError as error:
            logger.warning(
                "btrfs filesystem sync failed, so the workspace is assumed changed: %s", error
            )
            return False
        return True

    def _take(
        self,
        reason: Reason,
        trigger: str,
        workspace: btrfs.SubvolumeInfo,
        *,
        check_space: bool = False,
    ) -> Snapshot | None:
        """Snapshot through the watcher's barrier and record it. None if it was refused (a
        space condition), could not be made (recorded, alerted, retried next cycle), or the
        volume was busy."""
        if check_space:
            violations = self._space_verdict()
            if violations:
                self._pause(violations, freeze=True)
                return None
        try:
            snapshot = self._barrier_take(reason)
        except SnapshotBusy:
            self._busy_cycles += 1
            if self._busy_cycles >= BUSY_ALERT_AFTER and self._due("busy", REPEAT_ALERT_EVERY):
                event = self._record(
                    "snapshot",
                    "busy",
                    details={"consecutive": self._busy_cycles, "reason": str(reason)},
                    risk=1,
                )
                self._alert(
                    AlertLevel.WARNING,
                    "Las instantáneas no se pueden hacer",
                    f"Otra operación tiene el volumen ocupado desde hace {self._busy_cycles} "
                    "ciclos seguidos. Se reintenta en cada ciclo.",
                    event,
                )
            return None
        except SnapshotError as error:
            self._take_failed(reason, trigger, error)
            return None
        self._busy_cycles = 0
        self._last_alerted.pop("busy", None)  # the next streak is told about at once
        self._record(
            "snapshot",
            "take",
            snapshot.id,
            details={
                "reason": str(reason),
                "trigger": trigger,
                "workspace_id": workspace.treeid,
            },
            snapshot_id=snapshot.id,
        )
        return snapshot

    def _barrier_take(self, reason: Reason) -> Snapshot:
        """``store.take`` inside ``watcher.barrier``. A watcher that breaks must not stop the
        snapshots: if it raises, the snapshot is taken (or kept, if the barrier broke after
        it) and the failure is recorded."""
        taken: list[Snapshot] = []
        failed: list[BaseException] = []

        def take() -> Snapshot:
            try:
                snapshot = self._store.take(reason)
            except BaseException as error:
                failed.append(error)
                raise
            taken.append(snapshot)
            return snapshot

        try:
            result = self._watcher.barrier(take)
        except Exception as error:
            if failed:
                raise failed[0] from None  # the store's own error, not the watcher's
            self._watcher_failed("barrier", error)
            return taken[0] if taken else self._store.take(reason)
        if taken and result == taken[0]:
            return result
        # The barrier must hand back the snapshot ``take`` made: anything else would make the
        # watcher point changes at the wrong snapshot.
        self._watcher_failed(
            "barrier", RuntimeError("the barrier returned a snapshot take() did not make")
        )
        return taken[0] if taken else self._store.take(reason)

    def _take_failed(self, reason: Reason, trigger: str, error: SnapshotError) -> None:
        no_space = isinstance(error, SnapshotNoSpace)
        event = self._record(
            "snapshot",
            "take_failed",
            details={
                "reason": str(reason),
                "trigger": trigger,
                "error": _short(error),
                "no_space": no_space,
            },
            risk=2,
        )
        if no_space:
            title = "No hay espacio para hacer una instantánea"
            body = (
                "El volumen está lleno y no se ha podido guardar el estado del agente: "
                f"{_excerpt(error)}"
            )
        else:
            title = "No se pudo hacer una instantánea"
            body = f"El estado del agente no se ha guardado en este ciclo: {_excerpt(error)}"
        self._alert_throttled(f"take_failed:{no_space}", AlertLevel.ERROR, title, body, event)

    # Space (the seam T04d plugs into)

    def _violations(self) -> list[Violation]:
        """What the seam says. An exception from it is a P4: if we cannot find out, the agent
        does not get the benefit of the doubt."""
        if self._space is None:
            return []
        try:
            return list(self._space())
        except Exception as error:
            logger.error("the space check failed: %s", error)
            return [_Blind(f"no se puede comprobar el espacio: {_excerpt(error)}")]

    def _space_verdict(self) -> list[Violation]:
        """Sync, then evaluate (P3 reads qgroup usage, which only moves on commit). A failed
        sync leaves that usage stale, so it counts as a condition too."""
        if self._space is None:
            return []
        synced = self._sync_quietly()
        found = self._violations()
        if not synced:
            found.append(_Blind("btrfs filesystem sync ha fallado: el uso de espacio no es fiable"))
        return found

    def _pause(self, violations: Sequence[Violation], *, freeze: bool) -> None:
        """A condition forbids the agent to run: freeze it if it is running, remember why, say
        so. If it cannot be frozen it is killed: an agent that should be paused and is not is
        the one failure that cannot be left. Resuming is manual (T04d)."""
        reasons = {violation.reason for violation in violations}
        frozen = False
        pause_error: Exception | None = None
        with self.freeze_lock:
            self._pause_reasons |= reasons
            if freeze and self._agent_state in _CAN_RUN_CODE:
                try:
                    self._jail.pause()  # milliseconds; never waits for agent_lock
                except Exception as error:
                    pause_error = error
                else:
                    self._agent_state = AgentState.FROZEN
                    frozen = True
        killed = False
        kill_error: JailError | None = None
        if pause_error is not None:
            kill_error = self._halt(kill_first=True)
            killed = kill_error is None
            if killed:
                self._set_state(AgentState.STOPPED)
        details: dict[str, Any] = {
            "conditions": [violation.code for violation in violations],
            "reasons": sorted(reasons),
            "frozen": frozen,
        }
        if pause_error is not None:
            details["pause_error"] = _short(pause_error)
            details["killed"] = killed
        event = self._record("system", "space_pause", details=details, risk=3 if pause_error else 2)
        if killed:
            self._record("system", "agent_stop", details={"reason": "freeze_failed"}, risk=3)
        elif pause_error is not None:
            self._record(
                "system",
                "agent_stop_failed",
                details={"reason": "freeze_failed", "error": _short(kill_error)},
                risk=3,
            )
        what = "; ".join(violation.message for violation in violations)
        key = "pause:" + ",".join(sorted(violation.code for violation in violations))
        if pause_error is None:
            paused = frozen or self.agent_state is AgentState.FROZEN
            title = "El agente está pausado" if paused else "El agente no arranca"
            self._alert_throttled(key, AlertLevel.ERROR, title, what, event)
        elif killed:
            self._alert_throttled(
                key,
                AlertLevel.ERROR,
                "El agente se ha parado: no se pudo congelar",
                f"{what}. No se pudo congelar al agente, así que se ha parado a la fuerza.",
                event,
            )
        else:
            self._alert_throttled(
                key,
                AlertLevel.ERROR,
                "No se pudo congelar ni parar al agente",
                f"{what}. El agente debería estar pausado y sigue en marcha. "
                "Detalles en el evento.",
                event,
            )

    # Prune

    def _maybe_prune(self) -> tuple[Snapshot, ...] | None:
        now = self._mono()
        if now < self._next_prune:
            return None
        if not self._prune_clock_ok(now):
            return None
        try:
            deleted = self._store.prune()
        except SnapshotBusy:
            return None  # still due: tried again next cycle
        except PruneIncomplete as error:
            self._prune_done(now)
            event = self._record(
                "snapshot",
                "prune",
                details=_prune_details(error.deleted, error.failed),
                risk=2,
            )
            self._alert_throttled(
                "prune_incomplete",
                AlertLevel.ERROR,
                "No se pudieron borrar instantáneas antiguas",
                f"Han fallado {len(error.failed)} borrados de instantáneas caducadas.",
                event,
            )
            return tuple(error.deleted)
        except SnapshotError as error:
            self._prune_done(now, ok=False)
            event = self._record(
                "snapshot", "prune_failed", details={"error": _short(error)}, risk=2
            )
            self._alert_throttled(
                "prune_failed",
                AlertLevel.ERROR,
                "No se pudo podar",
                f"No se han podido borrar instantáneas caducadas: {_excerpt(error)}",
                event,
            )
            return None
        self._prune_done(now)
        if deleted:
            self._record("snapshot", "prune", details=_prune_details(deleted, []))
        return tuple(deleted)

    def _prune_done(self, now: float, *, ok: bool = True) -> None:
        self._next_prune = now + self._config.prune_interval
        if ok:
            self._last_prune_ok = now

    def _prune_clock_ok(self, now: float) -> bool:
        """Pruning compares snapshot ages: only with a clock the kernel trusts."""
        try:
            synced = self._clock_synced()
        except OSError as error:
            logger.warning(
                "cannot read the state of the clock, so snapshots are not pruned: %s", error
            )
            synced = False
        if synced:
            return True
        hours = (now - self._last_prune_ok) / 3600
        if now - self._last_prune_ok >= CLOCK_ALERT_EVERY and self._due(
            "prune_clock", CLOCK_ALERT_EVERY
        ):
            event = self._record(
                "snapshot",
                "prune_skipped",
                details={"reason": "clock_unsynced", "hours": round(hours, 1)},
                risk=1,
            )
            self._alert(
                AlertLevel.WARNING,
                "No se poda por el reloj",
                f"Hace {hours:.0f} h que no se borran instantáneas antiguas porque el reloj "
                "del sistema no está sincronizado. Revisa la sincronización de la hora (NTP).",
                event,
            )
        return False

    # Rewind (docs/19, section 4)

    def rewind(self, snapshot_id: str, *, requested_by: str) -> RewindOutcome:
        """THE way to rewind the workspace: the CLI (T04c-2), Telegram (T09) and the web (T12)
        all call this. Never raises for a failed rewind: the outcome says what happened, and
        the black box has it (``snapshot/rewind_requested`` and then ``rewind_done`` or
        ``rewind_failed``, joined by ``request_id``).

        1. An id that is not a snapshot id does nothing: no lock, no event.
        2. Under ``agent_lock``, decide first whether the agent should run afterwards.
        3. Write ``rewind.pending`` (fsynced) and record ``rewind_requested``.
        4. ``store.restore`` with the composed quiesce: stop the agent (kill it if frozen),
           suspend the file watcher; on the way out, rearm the watcher and start the agent
           only if ``_start_after_rewind`` says so.
        5. What happened is decided by comparing ``workspace_id()`` with the one before, never
           by the type of an exception: a failure after the swap is still a rewind.
        6. A space error (even before the agent was stopped) kills the agent and opens the
           pause ``rewind_no_space``.
        7. Remove ``rewind.pending``.

        If the black box fails at 3 or 5 the rewind goes on (it is the person's safety action),
        with an ERROR and an alert; ``rewind.pending`` is enough to reconcile it later."""
        target = Snapshot.parse(snapshot_id) if isinstance(snapshot_id, str) else None
        if target is None:
            return RewindOutcome(
                RewindStatus.INVALID,
                target="",
                message="Eso no es el identificador de una instantánea: no se ha hecho nada.",
            )
        requester = str(requested_by)[:MAX_REQUESTER_CHARS] or "unknown"
        with self.agent_lock:
            if not self._serving:
                # Not booted: no black box to record in. Wound down: no watcher to rearm, and
                # the agent must stay stopped. Nothing is touched (T04c-2's CLI without a
                # service will open the black box first).
                return RewindOutcome(
                    RewindStatus.FAILED,
                    target=target.id,
                    message="Vigía no está en marcha: no se ha rebobinado nada.",
                )
            return self._rewind_locked(target, requester)

    def _rewind_locked(self, target: Snapshot, requested_by: str) -> RewindOutcome:
        self._settle_earlier_rewind()
        attempt = _RewindAttempt(uuid4().hex, target, want_running=self._want_running())
        with self._record_failures_lock:
            failures_before = self._record_failures
        try:
            from_workspace = self._store.workspace_id()
        except SnapshotError as error:
            return self._rewind_not_started(attempt, requested_by, error)

        attempt.from_workspace = from_workspace
        intent = PendingRewind(attempt.request_id, target.id, from_workspace, requested_by)
        self._write_intent(intent)
        self._record(
            "snapshot",
            "rewind_requested",
            target.id,
            details={
                "request_id": attempt.request_id,
                "target": target.id,
                "requested_by": requested_by,
                "from_workspace_id": from_workspace,
                "want_running": attempt.want_running,
            },
            risk=1,
            snapshot_id=target.id,
        )

        result: RestoreResult | None = None
        error: Exception | None = None
        try:
            result = self._store.restore(target.id, quiesce=lambda: self._rewind_quiesce(attempt))
        except Exception as caught:  # decided below by the workspace id, never by the type
            error = caught

        if is_space_error(error):
            self._pause_for_rewind_space(attempt, error)
        try:
            after = self._store.workspace_id()
        except SnapshotError as read_error:
            return self._rewind_unknown(attempt, error, read_error)
        with self._record_failures_lock:
            if self._record_failures > failures_before:
                attempt.problems.append("blackbox")
        if after != from_workspace:
            outcome = self._rewind_happened(attempt, intent, after, result, error)
        else:
            outcome = self._rewind_did_not_happen(attempt, error)
        if attempt.final_recorded:
            self._clear_intent()
        else:
            # Without its rewind_done / rewind_failed, the intent is what reconciles this rewind
            # (before the next one, or at the next start): never today's workspace id alone.
            logger.error(
                "the outcome of the rewind %s could not be recorded; its intent is kept so it is "
                "reconciled later",
                attempt.request_id,
            )
        return outcome

    def _want_running(self) -> bool:
        """Should the agent run after the rewind? Yes if it was running, or if only a space
        reason keeps it paused (the rewind may be what frees the space). No if it was stopped
        on purpose, or paused for any other reason (``user``, T09)."""
        if self._stopped or self._wound_down:
            return False
        with self.freeze_lock:
            state, reasons = self._agent_state, set(self._pause_reasons)
        if reasons:
            return reasons <= SPACE_REASONS
        return state is AgentState.RUNNING

    @contextmanager
    def _rewind_quiesce(self, attempt: _RewindAttempt) -> Iterator[None]:
        """What ``store.restore`` holds around the swap. Entered in this order, left in the
        reverse one: the agent stops first (what it writes while stopping is still described,
        because the watcher is armed), then the watcher drains, writes and closes; afterwards
        the watcher is armed on the new workspace and only then may the agent start."""
        with ExitStack() as stack:
            stack.enter_context(self._agent_quiesced(attempt))
            stack.enter_context(self._watcher_suspended(attempt.target.id, attempt))
            yield

    @contextmanager
    def _agent_quiesced(self, attempt: _RewindAttempt) -> Iterator[None]:
        """``jail.quiesce`` with the Guardian's state and records around it. A failure to start
        the agent afterwards is recorded (``agent_start_failed``, alert) and not raised: the
        swap already happened, and ``rewind_done`` says the agent did not start."""
        try:
            was_running = self._jail.is_running()
        except JailError:
            was_running = True  # cannot tell: quiesce asks again
        quiesced = self._jail.quiesce(
            start_if=lambda error: self._start_after_rewind(attempt, error)
        )
        if was_running:
            self._set_state(AgentState.STOPPING)
        try:
            quiesced.__enter__()
        except JailError as error:
            self._rewind_stop_failed(attempt, error)
            raise
        attempt.stopped = True
        self._set_state(AgentState.STOPPED)
        if was_running:
            self._record(
                "system",
                "agent_stop",
                details={"reason": "rewind", "request_id": attempt.request_id},
            )
        body_error: BaseException | None = None
        try:
            yield
        except BaseException as error:
            body_error = error
            raise
        finally:
            self._leave_agent_quiesce(quiesced, body_error, attempt)

    def _leave_agent_quiesce(
        self,
        quiesced: AbstractContextManager[None],
        body_error: BaseException | None,
        attempt: _RewindAttempt,
    ) -> None:
        exc_info: tuple[type[BaseException] | None, BaseException | None, TracebackType | None]
        if body_error is None:
            exc_info = (None, None, None)
        else:
            exc_info = (type(body_error), body_error, body_error.__traceback__)
        try:
            quiesced.__exit__(*exc_info)
        except JailError as error:
            if not attempt.start_requested:
                raise
            attempt.start_error = error
            attempt.problems.append("agent")
            self._agent_did_not_start(error)
            return
        if attempt.start_requested:
            self._set_state(AgentState.RUNNING)
            attempt.agent_started = True
            self._record(
                "system",
                "agent_start",
                details={"reason": "rewind", "request_id": attempt.request_id},
            )

    def _rewind_stop_failed(self, attempt: _RewindAttempt, error: JailError) -> None:
        """quiesce could not stop the agent, so ``restore`` raises with the workspace unchanged.
        Docker says whether it still runs and whether it is frozen (a frozen agent whose kill
        failed is still frozen, never "running"), and quiesce may have started it again."""
        try:
            running = self._jail.is_running()
            frozen = running and self._jail.is_paused()
        except JailError:
            running, frozen = True, False
        if frozen:
            self._set_state(AgentState.FROZEN)
        else:
            self._set_state(AgentState.RUNNING if running else AgentState.STOPPED)
        restarted = attempt.start_requested and running and not frozen
        self._record(
            "system",
            "agent_stop_failed",
            details={
                "reason": "rewind",
                "request_id": attempt.request_id,
                "error": _short(error),
                "still_running": running,
                "restarted": restarted,
            },
            risk=2,
        )
        if restarted:
            attempt.agent_started = True
            self._record(
                "system",
                "agent_start",
                details={"reason": "rewind", "request_id": attempt.request_id},
            )

    @contextmanager
    def _watcher_suspended(self, target_id: str, attempt: _RewindAttempt) -> Iterator[None]:
        """``watcher.suspended(target)``, which never raises. If it does anyway, the rewind goes
        on: the failure is recorded, and the cycle's ``rearm_if_moved`` catches up."""
        suspended: AbstractContextManager[object] | None = None
        try:
            suspended = self._watcher.suspended(new_current=target_id)
            suspended.__enter__()
        except Exception as error:
            suspended = None
            attempt.problems.append("watcher")
            self._watcher_failed("suspend", error)
        try:
            yield
        finally:
            if suspended is not None:
                try:
                    suspended.__exit__(None, None, None)
                except Exception as error:
                    attempt.problems.append("watcher")
                    self._watcher_failed("rearm", error)

    def _start_after_rewind(self, attempt: _RewindAttempt, error: BaseException | None) -> bool:
        """The ``start_if`` of the rewind's quiesce: start the agent only if it should run, the
        rewind did not fail for lack of space, the space is green after a sync (``_start_
        verdict``), and nothing but space reasons keeps it paused; those are then cleared and
        the pause closed (``space_resume {by: rewind}``: the person acted). Anything red
        leaves it stopped with the pause open (``vigia seguir``, T04d-2, starts it later).
        Fails closed: if deciding breaks, the agent stays stopped and that is logged."""
        try:
            if not attempt.want_running or is_space_error(error):
                return False
            with self.freeze_lock:
                reasons = set(self._pause_reasons)
            if not attempt.stopped:
                # The stop failed but the agent stopped anyway (quiesce asks before raising):
                # only an agent that ran with no pause goes back to running. A pause is never
                # closed here: nothing was rewound, nothing was freed.
                if reasons:
                    return False
                attempt.start_requested = True
                self._set_state(AgentState.STARTING)
                return True
            if reasons - SPACE_REASONS:
                return False
            if reasons and not self._workspace_changed(attempt):
                return False  # the swap failed: nothing was freed, the pause stays open
            violations = self._start_verdict()
            if violations:
                self._pause(violations, freeze=False)
                return False
            with self.freeze_lock:
                cleared = self._pause_reasons & SPACE_REASONS
                self._pause_reasons -= SPACE_REASONS
            if cleared:
                self._record(
                    "system",
                    "space_resume",
                    details={
                        "by": "rewind",
                        "reasons": sorted(cleared),
                        "request_id": attempt.request_id,
                    },
                )
            attempt.start_requested = True
            self._set_state(AgentState.STARTING)
            return True
        except Exception as failure:
            attempt.problems.append("start_check")
            logger.error(
                "cannot decide whether to start the agent after the rewind, so it stays "
                "stopped: %s",
                failure,
            )
            return False

    def _workspace_changed(self, attempt: _RewindAttempt) -> bool:
        try:
            return self._store.workspace_id() != attempt.from_workspace
        except SnapshotError as error:
            logger.warning("cannot tell whether the rewind swapped the workspace: %s", error)
            return False

    def _start_verdict(self) -> list[Violation]:
        """The space conditions that forbid starting the agent after a rewind, read after a
        ``btrfs filesystem sync``. With ``space`` plugged in (T04d-2), all of P1-P7. Until
        then, with a cap configured, ``evaluate_sample`` keeps only P5 (the new workspace has
        its cap) and P4 (the signals could be read): the rest has no thread watching it yet."""
        if self._space is not None:
            return self._space_verdict()
        limit = self._config.workspace_limit
        if limit is None:
            return []  # no cap configured: the boot does not check one either
        if not self._sync_quietly():
            return [_Blind("btrfs filesystem sync ha fallado: el uso de espacio no es fiable")]
        reading = self._sample(self._store.root, self._store.workspace, self._config.state_dir)
        found = space.evaluate_sample(
            reading, limit, health=space.Health(check_age=0.0, agent_running=False)
        )
        return [c for c in found if c.code in _CHECKED_WITHOUT_SPACE_GATE]

    def _pause_for_rewind_space(self, attempt: _RewindAttempt, error: BaseException) -> None:
        """The rewind failed for lack of space, maybe before the agent was stopped (the
        recovery at the start of restore, the staging copy): kill the agent, open the pause
        ``rewind_no_space`` and say so. Freeing space and rewinding again (or, in T04e-1,
        growing the volume) is what comes next."""
        with self.freeze_lock:
            self._pause_reasons.add("rewind_no_space")
            reasons = sorted(self._pause_reasons)
        try:
            was_running = self._jail.is_running()
        except JailError:
            was_running = True  # cannot tell: kill it to be sure
        kill_error = self._halt(kill_first=True) if was_running else None
        killed = was_running and kill_error is None
        if kill_error is None:
            self._set_state(AgentState.STOPPED)
        else:
            attempt.problems.append("agent")
        event = self._record(
            "system",
            "space_pause",
            details={
                "reason": "rewind_no_space",
                "conditions": [],
                "reasons": reasons,
                "frozen": False,
                "killed": killed,
                "request_id": attempt.request_id,
                "error": _short(error),
            },
            risk=2 if kill_error is None else 3,
        )
        if killed:
            self._record(
                "system",
                "agent_stop",
                details={"reason": "rewind_no_space", "request_id": attempt.request_id},
            )
        if kill_error is not None:
            self._record(
                "system",
                "agent_stop_failed",
                details={"reason": "rewind_no_space", "error": _short(kill_error)},
                risk=3,
            )
        if kill_error is not None:
            agent = "No se ha podido parar al agente: sigue en marcha. "
        elif killed:
            agent = "El agente se ha parado. "
        else:
            agent = "El agente ya estaba parado y sigue así. "
        body = (
            "El rebobinado no ha podido terminar por falta de espacio en el volumen. "
            + agent
            + "Libera espacio (borra instantáneas que no necesites) y vuelve a rebobinar."
        )
        self._alert(AlertLevel.ERROR, "No hay espacio para rebobinar", body, event)

    def _rewind_happened(
        self,
        attempt: _RewindAttempt,
        intent: PendingRewind,
        after: int,
        result: RestoreResult | None,
        error: Exception | None,
    ) -> RewindOutcome:
        """The workspace changed: whatever failed on the way, this is a rewind."""
        undo = result.undo.id if result is not None and result.undo is not None else None
        incomplete = isinstance(error, RestoreIncomplete)
        if undo is None and not incomplete:
            undo = self._find_undo(intent.from_workspace_id)
        details: dict[str, Any] = {
            "request_id": attempt.request_id,
            "target": attempt.target.id,
            "undo": undo,
            "workspace_id": after,
            "workspace_uuid": self._workspace_uuid(),
            "from_workspace_id": intent.from_workspace_id,
            "recovered": [snap.id for snap in result.recovered] if result is not None else [],
            "agent_started": attempt.agent_started,
            "agent_state": str(self.agent_state),
        }
        problems = list(attempt.problems)
        shown_error = error if error is not None else attempt.start_error
        if error is not None:
            details["error"] = _short(error)
            problems.append("incomplete" if incomplete else "error")
        elif attempt.start_error is not None:
            details["error"] = _short(attempt.start_error)
        if isinstance(error, RestoreIncomplete):
            details["incomplete"] = True
            details["leftover"] = error.leftover.name
        if attempt.want_running and not attempt.agent_started and "agent" not in problems:
            problems.append("agent")
        if problems:
            details["problems"] = sorted(set(problems))
        event = self._record(
            "snapshot",
            "rewind_done",
            attempt.target.id,
            details=details,
            risk=2 if problems else 1,
            snapshot_id=attempt.target.id,
        )
        attempt.final_recorded = event is not None
        if event is None and "blackbox" not in problems:
            problems.append("blackbox")
        if problems:
            self._alert(
                AlertLevel.ERROR,
                "Rebobinado con problemas",
                f"Se ha vuelto a {attempt.target.id}, pero {_rewind_problems(problems)}. "
                "Detalles en el evento.",
                event,
            )
        message = f"Rebobinado a {attempt.target.id}."
        if problems:
            message += f" Pero {_rewind_problems(problems)}."
        return RewindOutcome(
            RewindStatus.PROBLEM if problems else RewindStatus.DONE,
            target=attempt.target.id,
            message=message,
            request_id=attempt.request_id,
            undo=undo,
            agent_started=attempt.agent_started,
            error=_outcome_error(shown_error, event),
        )

    def _rewind_did_not_happen(
        self, attempt: _RewindAttempt, error: Exception | None
    ) -> RewindOutcome:
        no_space = is_space_error(error)
        details: dict[str, Any] = {
            "request_id": attempt.request_id,
            "target": attempt.target.id,
            "error": _short(error) if error is not None else None,
            "no_space": no_space,
            "agent_started": attempt.agent_started,
            "agent_state": str(self.agent_state),
        }
        event = self._record(
            "snapshot", "rewind_failed", attempt.target.id, details=details, risk=2
        )
        attempt.final_recorded = event is not None
        if no_space:
            body = "No hay espacio en el volumen: el espacio de trabajo no ha cambiado."
        elif isinstance(error, JailError):
            body = "No se ha podido parar al agente: el espacio de trabajo no ha cambiado."
        else:
            body = "El espacio de trabajo no ha cambiado. Detalles en el evento."
        self._alert(AlertLevel.ERROR, "No se ha rebobinado", body, event)
        return RewindOutcome(
            RewindStatus.FAILED,
            target=attempt.target.id,
            message=f"No se ha rebobinado: {body}",
            request_id=attempt.request_id,
            agent_started=attempt.agent_started,
            error=_outcome_error(error, event),
        )

    def _rewind_not_started(
        self, attempt: _RewindAttempt, requested_by: str, error: SnapshotError
    ) -> RewindOutcome:
        """The workspace id cannot be read, so the outcome could never be told: do nothing."""
        event = self._record(
            "snapshot",
            "rewind_failed",
            attempt.target.id,
            details={
                "request_id": attempt.request_id,
                "target": attempt.target.id,
                "requested_by": requested_by,
                "error": _short(error),
                "no_space": False,
                "stage": "workspace_id",
            },
            risk=2,
        )
        body = f"No se puede leer el espacio de trabajo: {_excerpt(error)}"
        self._alert(AlertLevel.ERROR, "No se ha rebobinado", body, event)
        return RewindOutcome(
            RewindStatus.FAILED,
            target=attempt.target.id,
            message=f"No se ha rebobinado. {body}",
            request_id=attempt.request_id,
            error=_outcome_error(error, event),
        )

    def _rewind_unknown(
        self, attempt: _RewindAttempt, error: Exception | None, read_error: SnapshotError
    ) -> RewindOutcome:
        """The workspace id cannot be read after the rewind: nobody can tell whether it
        happened. ``rewind.pending`` stays, so the next start reconciles it."""
        logger.error(
            "cannot read the workspace id after the rewind %s, so its outcome is unknown until "
            "the next start reconciles it: %s",
            attempt.request_id,
            read_error,
        )
        self._alert(
            AlertLevel.ERROR,
            "No se sabe si se ha rebobinado",
            "No se puede leer el espacio de trabajo tras el rebobinado. Vigía lo comprobará al "
            "volver a arrancar.",
        )
        return RewindOutcome(
            RewindStatus.UNKNOWN,
            target=attempt.target.id,
            message="No se sabe si se ha rebobinado: se comprobará al volver a arrancar Vigía.",
            request_id=attempt.request_id,
            agent_started=attempt.agent_started,
            error=_outcome_error(error or read_error, None),
        )

    def _find_undo(self, workspace_id: int) -> str | None:
        """The undo point of a rewind is the old workspace itself, published as a snapshot:
        the snapshot whose subvolume id is the workspace id from before. None if not found."""
        try:
            listed = self._store.snapshots()
        except SnapshotError as error:
            logger.warning("cannot list the snapshots to find the undo point: %s", error)
            return None
        for snap in reversed(listed):
            try:
                if self._info(self._store.snapshots_dir / snap.id).treeid == workspace_id:
                    return snap.id
            except SnapshotError:
                continue
        return None

    def _workspace_uuid(self) -> str | None:
        """The new generation's uuid, so a later alert can name what holds space (T04d-2)."""
        try:
            return str(self._info(self._store.workspace).uuid)
        except SnapshotError as error:
            logger.warning("cannot read the uuid of the rewound workspace: %s", error)
            return None

    def _write_intent(self, intent: PendingRewind) -> None:
        try:
            write_pending(self._config.pending_file, intent)
        except OSError as error:
            # The event is the other way to reconcile; the rewind is the person's safety
            # action, so it goes on.
            logger.error("cannot write the rewind intent %s: %s", self._config.pending_file, error)

    def _clear_intent(self) -> None:
        try:
            remove_pending(self._config.pending_file)
        except OSError as error:
            logger.error(
                "cannot remove the rewind intent %s; the next start finds it settled: %s",
                self._config.pending_file,
                error,
            )

    # Reconcile (docs/19, section 4, "Conciliar al arrancar")

    def _settle_earlier_rewind(self) -> None:
        """Before a new rewind: an intent or an unanswered request left by an earlier one is
        reconciled first, so two rewinds never share one ``rewind.pending``."""
        try:
            self._reconcile_rewinds()
        except (SnapshotError, BlackBoxError) as error:
            logger.error("cannot reconcile an earlier rewind before this one: %s", error)

    def _reconcile_rewinds(self) -> None:
        """Boot step 5: a rewind that a crash (or SIGKILL) left half way. Its intent
        (``rewind.pending``) or its ``rewind_requested`` without a ``rewind_done`` or
        ``rewind_failed`` is settled by comparing the workspace id with the one it started
        from: different means the swap happened. Only the newest request is looked at: every
        rewind ends with one of the two, or is reconciled at the next start."""
        path = self._config.pending_file
        unreadable = False
        try:
            intent = read_pending(path)
        except PendingError as error:
            unreadable = True
            intent = None
            logger.error(
                "the intent of an interrupted rewind cannot be read, so it is reconciled from "
                "the black box only: %s",
                error,
            )
        candidates: dict[str, tuple[str, int, int | None, str]] = {}
        newest = self._box.events(
            source="snapshot", action="rewind_requested", newest_first=True, limit=1
        )
        newest_seq = newest[0].seq if newest else None
        if intent is not None:
            since = newest_seq if newest and _request_of(newest[0]) == intent.request_id else None
            candidates[intent.request_id] = (
                intent.target,
                intent.from_workspace_id,
                since,
                "pending",
            )
        if newest:
            event = newest[0]
            request_id, from_workspace = _request_of(event), event.details.get("from_workspace_id")
            target = event.details.get("target")
            if (
                request_id
                and request_id not in candidates
                and type(from_workspace) is int
                and isinstance(target, str)
            ):
                candidates[request_id] = (target, from_workspace, event.seq, "blackbox")
        settled = True
        for request_id, (target, from_workspace, since, basis) in candidates.items():
            if not self._rewind_settled(request_id, since):
                settled = self._reconcile_one(request_id, target, from_workspace, basis) and settled
        if unreadable or (intent is not None and settled):
            self._clear_intent()

    def _rewind_settled(self, request_id: str, since_seq: int | None) -> bool:
        for action in ("rewind_done", "rewind_failed"):
            for event in self._box.events(source="snapshot", action=action, since_seq=since_seq):
                if _request_of(event) == request_id:
                    return True
        return False

    def _reconcile_one(self, request_id: str, target: str, from_workspace: int, basis: str) -> bool:
        """Record what an interrupted rewind did. ``basis`` says what it is judged on: its
        intent ("pending") or only its request in the black box ("blackbox"). Returns whether
        the black box took it (if not, the intent stays for the next try)."""
        workspace = self._store.workspace_id()
        if workspace != from_workspace:
            undo = self._find_undo(from_workspace)
            event = self._record(
                "snapshot",
                "rewind_done",
                target,
                details={
                    "request_id": request_id,
                    "target": target,
                    "reconciled": True,
                    "basis": basis,
                    "undo": undo,
                    "workspace_id": workspace,
                    "workspace_uuid": self._workspace_uuid(),
                    "from_workspace_id": from_workspace,
                    "agent_started": False,
                },
                risk=2,
                snapshot_id=target if Snapshot.parse(target) else None,
            )
            body = (
                f"Vigía se paró a mitad de un rebobinado a {target}. Al volver ha comprobado que "
                "el rebobinado sí se hizo" + (f"; para deshacerlo: {undo}." if undo else ".")
            )
        else:
            event = self._record(
                "snapshot",
                "rewind_failed",
                target,
                details={
                    "request_id": request_id,
                    "target": target,
                    "reconciled": True,
                    "basis": basis,
                    "error": "interrupted before the swap: the workspace is unchanged",
                    "no_space": False,
                },
                risk=2,
            )
            body = (
                f"Vigía se paró a mitad de un rebobinado a {target}. Al volver ha comprobado que "
                "no llegó a hacerse: el espacio de trabajo no ha cambiado."
            )
        self._alert(AlertLevel.WARNING, "Un rebobinado se interrumpió", body, event)
        return event is not None

    # Stop and run

    def stop(self) -> None:
        """Stop for good: the agent, then the watcher (which writes what it holds), then the
        service. Parar Vigía para al agente. If Docker's stop fails, the agent is killed and
        removed before giving up; if it still runs, ``stop()`` records that, finishes closing
        the watcher and the log, and raises, and calling it again tries the agent once more."""
        with self.agent_lock:
            if self._stopped:
                return
            error = self._stop_agent("service_stop")
            if not self._wound_down:
                self._wound_down = True
                self._serving = False
                self._watcher_step("close", self._watcher.close)
                self._record("system", "service_stop", details={"agent_stopped": error is None})
                logging.getLogger(_BRIDGED_LOGGERS).removeHandler(self._bridge)
                self._bridge.close()
            if error is None:
                self._stopped = True
        if error is not None:
            raise error

    def _stop_agent(self, reason: str) -> JailError | None:
        try:
            running = self._jail.is_running()
        except JailError:
            running = True  # cannot tell: _halt confirms
        if not running:
            self._set_state(AgentState.STOPPED)
            return None
        self._set_state(AgentState.STOPPING)
        error = self._halt()
        if error is not None:
            self._set_state(AgentState.RUNNING)
            event = self._record(
                "system",
                "agent_stop_failed",
                details={"reason": reason, "error": _short(error)},
                risk=3,
            )
            self._alert(
                AlertLevel.ERROR,
                "No se pudo parar el agente",
                "Vigía se para y el agente no se ha podido parar: sigue en marcha. "
                "Detalles en el evento.",
                event,
            )
            return error
        self._set_state(AgentState.STOPPED)
        self._record("system", "agent_stop", details={"reason": reason})
        return None

    def _halt(self, *, kill_first: bool = False) -> JailError | None:
        """Make sure the agent is not running (see ``halt_agent``)."""
        return halt_agent(self._jail, kill_first=kill_first)

    def flush_logs(self, timeout: float = 5.0) -> bool:
        """Wait until the log messages bridged so far are in the black box (for tests, and for
        a caller that wants to read the box right after something was logged)."""
        return self._bridge.flush(timeout)

    def run(self, stop: threading.Event) -> None:
        """Start, run a cycle every ``cycle_interval`` seconds until ``stop`` is set, and stop.
        The caller sets ``stop`` from its signal handlers."""
        try:
            self.start()
            while not stop.wait(self._config.cycle_interval):
                try:
                    self.cycle()
                except Exception as error:  # a bug must not end the watch
                    logger.exception("the cycle crashed")
                    self._cycle_problem("crash", error)
        finally:
            self.stop()

    # Records, alerts and watcher guards

    def _record(
        self,
        source: str,
        action: str,
        target: str = "",
        *,
        details: dict[str, Any] | None = None,
        risk: int = 0,
        snapshot_id: str | None = None,
        log_failure: bool = True,
    ) -> Event | None:
        """Append to the black box. If that fails, say so (ERROR, alert) and return None: the
        service goes on, because stopping the world for a full disk would be its own attack."""
        try:
            return self._box.append(
                source, action, target, details=details, risk=risk, snapshot_id=snapshot_id
            )
        except BlackBoxError as error:
            with self._record_failures_lock:
                self._record_failures += 1
            if log_failure:
                logger.error("cannot write %s/%s to the black box: %s", source, action, error)
                self._alert_throttled(
                    "blackbox_write",
                    AlertLevel.ERROR,
                    "No se puede escribir en la caja negra",
                    f"Se ha perdido el registro de {source}/{action}: {_excerpt(error)}",
                    every=600.0,
                )
            return None

    def _alert(self, level: AlertLevel, title: str, body: str, event: Event | None = None) -> None:
        """The one door alerts go through: title and body are redacted here, whatever put the
        text together (invariant 5), and the event is cited."""
        self._alerts.submit(Alert(level, redact(title), redact(body), event.seq if event else None))

    def _due(self, key: str, every: float) -> bool:
        """True at most once per ``every`` seconds for ``key``; calling it counts as using it."""
        now = self._mono()
        last = self._last_alerted.get(key)
        if last is not None and now - last < every:
            return False
        self._last_alerted[key] = now
        return True

    def _alert_throttled(
        self,
        key: str,
        level: AlertLevel,
        title: str,
        body: str,
        event: Event | None = None,
        *,
        every: float = REPEAT_ALERT_EVERY,
    ) -> None:
        if self._due(key, every):
            self._alert(level, title, body, event)

    def _cycle_problem(self, step: str, error: Exception) -> None:
        event = self._record(
            "system", "cycle_failed", details={"step": step, "error": _short(error)}, risk=2
        )
        self._alert_throttled(
            f"cycle:{step}",
            AlertLevel.ERROR,
            "Falló un ciclo de vigilancia",
            f"No se ha podido comprobar el espacio de trabajo del agente ({step}): "
            f"{_excerpt(error)}",
            event,
        )

    def _watcher_step(self, step: str, call: Callable[[], Any]) -> Any:
        try:
            return call()
        except Exception as error:
            self._watcher_failed(step, error)
            return None

    def _watcher_failed(self, step: str, error: Exception) -> None:
        event = self._record(
            "system", "watcher_failed", details={"step": step, "error": _short(error)}, risk=2
        )
        self._alert_throttled(
            f"watcher:{step}",
            AlertLevel.ERROR,
            "Falló el vigilante de archivos",
            f"El vigilante de archivos falló ({step}): {_excerpt(error)}. Las instantáneas siguen.",
            event,
        )

    def _on_log(self, problem: LoggedProblem) -> None:
        """The bridge: a WARNING or ERROR of a ``vigia.*`` logger becomes an event and an alert."""
        error = problem.level is AlertLevel.ERROR
        event = self._record(
            "system",
            "log",
            problem.logger,
            details={
                "level": problem.level.value,
                "template": problem.template,
                "message": problem.message,
                "suppressed": problem.suppressed,
            },
            risk=2 if error else 1,
            log_failure=False,  # logging that the log failed would only come back here
        )
        self._alert(
            problem.level,
            f"Aviso de {problem.logger}",
            problem.message,
            event,
        )


def halt_agent(jail: AgentJail, *, kill_first: bool = False) -> JailError | None:
    """Make sure the agent is not running; None once Docker confirms it, else the first
    error. Decided by Docker's own state, never by ours: a frozen container still reports
    Running, and ``docker stop`` would wake it to run its SIGTERM handler, so a paused one
    is killed. If the attempt fails (or does not take), kill and then ``rm --force``.

    Also used by the runner when the service cannot even open its black box."""
    try:
        kill = kill_first or jail.is_paused()
    except JailError:
        kill = True  # cannot tell: assume the worst
    attempts = [jail.kill if kill else jail.stop, jail.kill, jail.remove]
    first_error: JailError | None = None
    tried: list[Callable[[], None]] = []
    for attempt in attempts:
        if attempt in tried:
            continue
        tried.append(attempt)
        try:
            attempt()
        except JailError as error:
            first_error = first_error or error
            continue
        try:
            if not jail.is_running():
                return None
        except JailError as error:
            first_error = first_error or error
    return first_error or JailError("the agent is still running after stop, kill and remove")


def _prune_details(deleted: Sequence[Snapshot], failed: Sequence[Snapshot]) -> dict[str, Any]:
    return {
        "deleted_count": len(deleted),
        "deleted": [snap.id for snap in deleted[:MAX_LISTED_SNAPSHOTS]],
        "failed_count": len(failed),
        "failed": [snap.id for snap in failed[:MAX_LISTED_SNAPSHOTS]],
    }


def _outcome_error(error: BaseException | None, event: Event | None) -> str | None:
    """What a RewindOutcome may say about an error: it reaches the CLI, Telegram and the web.
    A JailError can quote the agent's own logs, so only its type and the event that holds the
    (redacted) text; anything else is redacted here."""
    if error is None:
        return None
    if isinstance(error, JailError):
        where = f"detalles en el evento #{event.seq}" if event is not None else "detalles en el log"
        return f"{type(error).__name__} ({where})"
    return str(redact(_short(error)))


def _request_of(event: Event) -> str | None:
    request_id = event.details.get("request_id")
    return request_id if isinstance(request_id, str) and request_id else None


_PROBLEM_TEXT = {
    "agent": "el agente no ha arrancado",
    "blackbox": "la caja negra ha fallado",
    "error": "algo falló después del intercambio",
    "incomplete": "el punto para deshacer no se ha podido guardar todavía",
    "start_check": "no se pudo comprobar si el agente podía arrancar",
    "watcher": "el vigilante de archivos ha fallado",
}


def _rewind_problems(problems: Sequence[str]) -> str:
    return ", ".join(_PROBLEM_TEXT.get(problem, problem) for problem in sorted(set(problems)))


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _short(error: BaseException | None) -> str:
    return f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]


def _excerpt(error: BaseException) -> str:
    """A short, redacted piece of an error for an alert. Never for a JailError: Docker's
    errors can quote the agent's own logs, and those do not go into alerts at all."""
    return str(redact(str(error)))[:ALERT_EXCERPT_CHARS]


__all__ = [
    "AgentState",
    "CycleResult",
    "FileWatcher",
    "RewindOutcome",
    "RewindStatus",
    "Guardian",
    "SpaceGate",
    "Violation",
    "halt_agent",
]
