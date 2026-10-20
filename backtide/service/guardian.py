"""Guardian: the service that owns the agent. It starts it, snapshots its workspace when Btrfs
says something changed, and stops it. Design: docs/19-diseno-t04.md, section 3.

- **The agent only runs while backtide watches it.** ``start()`` stops an agent it finds running
  (the service died and came back) and says so; ``stop()`` stops the agent. Without a black box the
  service does not start, and an agent found running is stopped.
- **Btrfs decides when to snapshot, the file watcher only describes** (``activity.py``): every
  cycle compares the workspace's ``ctransid`` with its lineage reference, whatever the watcher
  saw or lost.
- **Every snapshot goes through the watcher's barrier** (``watcher.barrier(take)``): drain, take,
  drain, and only then is the new snapshot the one changes point to. So a change is never
  pointed at a snapshot that already contains it.
- **Alerts go after the event.** Every notable thing is recorded first and the alert cites it.
  ``logging`` WARNING and ERROR of ``backtide.*`` (the store's, for one) reach the black box and
  the alerts through the bridge in ``backtide.notify``.
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

- **The control socket** (T04c-2, ``control.py``): ``run()`` starts it once the service is up and
  closes it before stopping, so a rewind in flight finishes and is answered. Without a service,
  ``backtide rebobinar`` opens the Guardian just to rewind (``open_for_rewind``, with a
  ``NullWatcher``): the agent is never started.

- **The pause by space** (T04d-2, docs/19 section 5): ``space`` returns the conditions that
  forbid the agent to run (``pause.make_space_gate``: P1-P6 of ``space.py``, or the early
  warnings W1/W3); the Guardian adds P7 from its own failed appends. It is evaluated after a
  ``btrfs filesystem sync`` before every snapshot and every agent start, and by the space
  thread every second (``check_space``): freeze first (``docker pause``), then sync and read
  again; confirmed, the pause opens (``system/space_pause``, an alert that names what holds the
  space); not confirmed, the agent is thawed if nothing else keeps it paused. A watchdog
  (``check_watchdog``, no I/O) freezes the agent if the space thread has not checked for 3 s.
  Resuming is manual: ``resume()`` (``backtide seguir``) refuses while a condition stands. A pause
  survives the service: at boot the open ones are read back from the black box and the agent
  stays stopped until ``backtide seguir``. If freezing fails, the agent is killed.

- **The emergency growth** (T04e-1, docs/19 section 6, ``backtide.snapshots.grow``): a rewind that
  fails for lack of space kills the agent and opens the pause ``rewind_no_space`` (as before);
  then the volume grows once, within its limits (``snapshot/volume_grow``), and the rewind is
  retried once with the same request id and intent. If it was swapped but its undo point could
  not be published (``RestoreIncomplete``), the growth is followed by ``store.recover()``
  instead of a second rewind. Never deletes a snapshot to make room. Until T13 gives backtide the
  privilege, the production steps say "not configured" and nothing grows.

- **The process sensor** (T07-3, docs/23 section 7, ``process_sensor.py``): started after the
  black box opens and before the agent's jail is prepared, told about the agent's container
  right before every start, asked to prove it sees the agent right after, and stopped after
  the agent. Without it the agent runs anyway (decision 7); with ``[sensor] required`` the
  agent only runs while the sensor is up, and the sensor's hooks stop it and start it again.
  Those hooks come from the sensor's thread and never wait for ``agent_lock`` once the service
  stops (``_sensor_closing``), because ``stop()`` joins that thread while holding the lock.

- **The egress proxy** (T06-4, docs/21 section 9, ``egress.py``): started after the agent's jail
  is prepared (its network, the CA) and before the agent; **without the proxy's hello the agent
  does not start** (``agent_start_skipped {reason: proxy_down}``). If it falls, the agent keeps
  running with no way out, and ``egress.py`` records it, alerts and retries; once it is back its
  ``back`` hook starts an agent it kept stopped. Stopped after the agent, whatever the agent's
  stop did: a proxy without its service lets nothing out anyway. Its hook, like the sensor's,
  never waits for ``agent_lock`` once the service stops (``_egress_closing``).

Synchronous and thread-hostile in the places that matter: ``start()``, ``cycle()`` and
``stop()`` are called by one thread (``run()``); ``rewind()`` may come from another one.
``agent_lock`` serialises what starts or stops the agent, and the cycle, which skips itself
while a rewind holds it; ``freeze_lock`` guards only ``agent_state`` and ``pause_reasons`` for a
few milliseconds, so freezing never waits for a long ``docker stop``.
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol
from uuid import uuid4

import backtide
from backtide.blackbox import BlackBox, BlackBoxError, Event, redact
from backtide.jail import AgentJail, JailError
from backtide.jail.openclaw import UnrewindableConfig
from backtide.notify import Alert, AlertLevel, AlertSink, LogBridge, LoggedProblem
from backtide.service.clock import clock_synced as kernel_clock_synced
from backtide.service.config import ServiceConfig
from backtide.service.egress import EgressHooks
from backtide.service.holds import BatchOutcome, BatchStatus, HoldOutcome, HoldStatus
from backtide.service.pause import (
    Holder,
    PauseOutcome,
    PauseStatus,
    ResumeOutcome,
    ResumeStatus,
    Ticker,
    condition_text,
    holders_text,
)
from backtide.service.process_sensor import SensorHooks
from backtide.service.rewind import (
    PendingError,
    PendingRewind,
    RewindOutcome,
    RewindStatus,
    is_space_error,
    read_pending,
    remove_pending,
    write_pending,
)
from backtide.snapshots import (
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
from backtide.snapshots.activity import SnapshotInfo, changed_since, lineage_reference
from backtide.snapshots.grow import GrowResult, GrowStatus, VolumeGrower

logger = logging.getLogger(__name__)

BUSY_ALERT_AFTER = 3  # SnapshotBusy cycles in a row before the user hears about it
EVIDENCE_LOCK_WAIT = 10.0  # seconds an evidence snapshot waits for a rewind or a stop to end
CLOCK_ALERT_EVERY = 24 * 3600.0  # prune blocked by the clock: one alert a day
REPEAT_ALERT_EVERY = 3600.0  # the same failure, over and over: one alert an hour
MAX_LISTED_SNAPSHOTS = 20  # ids kept in the details of a prune event
MAX_ERROR_CHARS = 500
ALERT_EXCERPT_CHARS = 300
MAX_REQUESTER_CHARS = 64
# The pause reasons that are about space or the black box: a rewind that ends green clears them
# and starts the agent (docs/19, section 4). Any other reason ("user", T09) keeps it stopped.
SPACE_REASONS = frozenset({"space", "rewind_no_space", "blackbox"})
# Without a space gate (no cap configured), the start after a rewind checks only that the
# workspace has its cap (P5) and that the signals could be read at all (P4), as before T04d-2.
_CHECKED_WITHOUT_SPACE_GATE = frozenset({"P4", "P5"})
SPACE_TICK = 1.0  # tau: the space thread checks every second
SYNC_EVERY = 5.0  # ... and commits the transaction this often if the workspace changed
TRANSIENT_WINDOW = 3600.0  # unconfirmed freezes are counted per hour
JUMPY_AFTER = 6  # more unconfirmed freezes than this in an hour: confirm over 3 readings
JUMPY_READINGS = 3
CONFIRM_WAIT = 15.0  # seconds a start waits for a freeze-to-confirm to end (3 readings, ticks)

_BRIDGED_LOGGERS = "backtide"


class AgentState(StrEnum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FROZEN = "frozen"


# The states in which the agent may run code, so a space condition must freeze it: also while
# `docker stop` waits for its SIGTERM handler and while `wait_ready` waits for it (a rewind).
_CAN_RUN_CODE = frozenset({AgentState.RUNNING, AgentState.STARTING, AgentState.STOPPING})


class ControlHook(Protocol):
    """The control socket as ``run()`` sees it (``backtide.service.control.ControlServer``)."""

    def start(self) -> None:
        """Start answering. Raises if it cannot (the service then stops)."""
        ...

    def close(self) -> None:
        """Stop accepting and wait for the requests in flight."""
        ...


class RiskResponses(Protocol):
    """The answers to events of risk 3 as the Guardian sees them
    (``backtide.analyzer.RiskResponder``, T08): it takes the evidence snapshot by calling
    ``take_evidence`` and alerts."""

    def open(self) -> None:
        """Ready for events again (the Guardian starts)."""
        ...

    def close(self, timeout: float = ...) -> bool:
        """Answer what is pending and stop. Called before the stop takes ``agent_lock``."""
        ...

    def flush_held(self) -> None:
        """Send the alerts that were held back (the last step of the stop)."""
        ...


class FileWatcher(Protocol):
    """What the Guardian needs from the file watcher (``backtide.sensors.files.FileWatcher``).

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


# Why a required sensor stops the agent (``agent_stop {reason}``).
_SENSOR_REASONS = frozenset(
    {
        "sensor_down",
        "sensor_unproven",
        "sensor_lost_events",
        "sensor_budget",
        "sensor_novelty_streak",
    }
)


class Sensor(Protocol):
    """The process sensor as the Guardian sees it (``backtide.service.process_sensor``). None
    of its methods raises: it records and alerts its own failures."""

    @property
    def required(self) -> bool: ...

    def start(self, hooks: SensorHooks) -> bool:
        """Bring the sensor up (False if it is not) and start its heartbeat."""
        ...

    def follow_agent(self) -> None:
        """Attribute events to the agent's container as it is now."""
        ...

    def agent_started(self) -> bool:
        """The agent is ready: whether the sensor sees it (a probe went through)."""
        ...

    def allows_agent(self) -> bool:
        """False only if the sensor is required and not up."""
        ...

    def stop(self, reason: str = ...) -> None: ...


class EgressProxy(Protocol):
    """The egress proxy as the Guardian sees it (``backtide.service.egress.Egress``). None of
    its methods raises: it records and alerts its own failures."""

    def start(self, hooks: EgressHooks) -> bool:
        """Bring the proxy up, configured over its channel (False if it is not), and start its
        watch."""
        ...

    def allows_agent(self) -> bool:
        """True only while the proxy is up and configured."""
        ...

    def stop(self, reason: str = ...) -> None: ...

    def decide(
        self,
        hold_id: str,
        verdict: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> HoldOutcome:
        """Approve or reject a held request (T10-2); ``frozen``: nothing is approved while it
        says True."""
        ...

    def pending(self) -> list[dict[str, Any]]:
        """The held requests waiting for the person."""
        ...

    def reject_holds(self, by: str) -> int:
        """Reject every open hold (a pause or a rewind, decision 7 of docs/32)."""
        ...

    def create_batch(
        self,
        hold_id: str,
        kind: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> BatchOutcome:
        """Make a batch rule from an open hold and approve it (T10-4)."""
        ...

    def batches(self) -> list[dict[str, Any]]:
        """The active batch rules."""
        ...

    def end_batch(self, rule_id: str, *, by: str) -> bool:
        """Revoke a batch rule."""
        ...


class Violation(Protocol):
    """One space or black-box condition that forbids the agent to run (T04d's ``Condition``)."""

    code: str
    message: str
    reason: str  # the ``pause_reasons`` entry: "space" or "blackbox"


type SpaceGate = Callable[[], Sequence[Violation]]


class _BeingStopped(Exception):
    """A space condition while the agent was being stopped: it is killed, not frozen."""


@dataclass(frozen=True)
class _Blind:
    """P4 made by the Guardian itself: it could not find out, which counts against the agent."""

    message: str
    code: str = "P4"
    reason: str = "space"


@dataclass(frozen=True)
class _Held:
    """What ``_freeze`` did to the agent."""

    frozen: bool
    pause_error: Exception | None
    killed: bool
    kill_error: JailError | None


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
    grow: GrowResult | None = None  # the emergency growth after a space error (T04e-1)
    retried: bool = False  # grown, then rewound again (or its undo point published)


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
        holders: Callable[[], Sequence[Holder]] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        space_interval: float = SPACE_TICK,
        space_config: space.SpaceConfig = space.DEFAULT_CONFIG,
        grow: VolumeGrower | None = None,
        risk: RiskResponses | None = None,
        prepare_egress: Callable[[], None] | None = None,
        sensor: Sensor | None = None,
        egress: EgressProxy | None = None,
    ) -> None:
        """Every collaborator is injected, so the tests use fakes. ``alerts`` is where alerts
        go (an ``AlertQueue`` in production); the caller starts and closes it. ``sample``
        reads the space signals (``space.sample(root, workspace, state_dir)``) for the start
        after a rewind when ``space`` is not plugged in (no cap configured). ``holders`` lists
        what holds the space (``pause.read_holders``) for the pause alert; ``space_interval``
        is the space thread's tick and ``space_config`` its thresholds (staleness, P7).
        ``grow`` grows the volume after a rewind runs out of space (T04e-1); without it the
        volume is never grown (recorded as ``volume_grow {phase: refused, reason:
        not_configured}``). ``risk`` (T08) is closed when the service stops, before ``stop()``
        takes ``agent_lock``: its evidence snapshot (``take_evidence``) needs that lock.
        ``prepare_egress`` (T06-2) makes what the agent's way out needs before its container is
        made (the proxy's CA); if it raises, the service does not start and no agent is made.
        ``sensor`` (T07-3) is the process sensor; without it nothing watches the agent's
        commands and connections. ``egress`` (T06-4) is the proxy, the agent's only way out;
        without it the Guardian neither starts nor watches one (the unit tests that do not
        test it)."""
        self._config = config
        self._sensor = sensor
        self._sensor_closing = threading.Event()  # set by the stop: the hooks stop waiting
        self._sensor_held = False  # the sensor (required) stopped the agent or kept it stopped
        self._egress = egress
        self._egress_closing = threading.Event()  # set by the stop: its hook stops waiting
        self._egress_held = False  # the agent was kept stopped for want of a proxy
        self._egress_stopped = True  # nothing to stop until _start_egress
        self._risk = risk
        self._prepare_egress = prepare_egress
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
        self._holders = holders
        self._sleep = sleep
        self._tick = space_interval
        self._space_config = space_config
        self._grow = grow if grow is not None else VolumeGrower(None, None)

        self.agent_lock = threading.Lock()
        self.freeze_lock = threading.Lock()
        self._agent_state = AgentState.STOPPED
        self._state_epoch = 0  # bumped by every change of state: a stale thaw never applies
        self._thaw_to = AgentState.RUNNING  # what a freeze to confirm a condition goes back to
        self._confirm_freezes = 0  # freezes to confirm made so far (a start that meets one waits)
        self._pause_reasons: set[str] = set()
        self._rewinding = False  # a rewind() runs: no held request is approved meanwhile
        # T09: bumped (under freeze_lock) by every freeze the person asks for, also when the
        # pause was open already, so a `seguir` decided before a later `/pausar` never undoes it.
        self._user_pause_epoch = 0
        self._last_user_pause_seq: int | None = None  # the user_pause a user_resume closes
        # The space thread (T04d-2). All monotonic seconds.
        self._last_check: float | None = None  # the last finished space evaluation
        self._serving_since: float | None = None  # before any check, the watchdog counts from here
        self._last_sync = float("-inf")
        self._synced_ctransid: int | None = None
        self._transients: deque[float] = deque()  # unconfirmed freezes in the last hour
        self._transients_unreported = 0
        self._next_space_report = 0.0
        self._bb_streak = 0  # appends that failed in a row (P7)
        self._bb_failing_since: float | None = None

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
            self._state_epoch += 1

    def _advance(self, expected: AgentState, state: AgentState) -> None:
        """``expected`` -> ``state``, unless something changed it meanwhile: the space thread
        may have frozen an agent that was just getting ready, and FROZEN must not be
        overwritten by RUNNING (a thaw after a false alarm then goes back to ``state``)."""
        with self.freeze_lock:
            if self._agent_state is expected:
                self._agent_state = state
                self._state_epoch += 1
            elif self._agent_state is AgentState.FROZEN and self._thaw_to is expected:
                self._thaw_to = state

    def _mark_stopping(self) -> None:
        """The agent is about to be stopped. A frozen one (Docker's word, or ours) stays FROZEN:
        it runs no code, so the space thread must not try to freeze it again (and fail, and
        kill it in parallel with the stop)."""
        try:
            paused = self._jail.is_paused()
        except JailError:
            paused = False
        with self.freeze_lock:
            if paused or self._agent_state is AgentState.FROZEN:
                self._agent_state = AgentState.FROZEN
            else:
                self._agent_state = AgentState.STOPPING
            self._state_epoch += 1

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
            if self._risk is not None:
                self._risk.open()
            self._serving = True
            with self.freeze_lock:
                self._serving_since = self._mono()
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
            self._box.append(
                "system", "service_start", "", details={"version": backtide.__version__}
            )
        except BlackBoxError as error:
            logger.error("cannot use the black box, so the service does not start: %s", error)
            self._alert(
                AlertLevel.ERROR,
                "La caja negra no se puede usar",
                "backtide no arranca: sin grabar no hay vigilancia. "
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
        stop_error = self._halt(kill_first=True)  # unwatched and unrecorded: no grace period
        if stop_error is not None:
            error.add_note(f"stopping the running agent also failed: {stop_error}")
            logger.error("cannot stop the agent while the black box is down: %s", stop_error)

    def _boot(self) -> None:
        now = self._mono()
        self._last_prune_ok = now
        self._next_prune = now + self._config.prune_interval
        self._next_space_report = now + TRANSIENT_WINDOW
        self._stop_unsupervised_agent()
        if self._space is None:
            self._say_space_unwatched()
        self._store.init()
        self._recover_store()
        self._reconcile_rewinds()
        self._note_downtime()
        self._start_sensor()
        self._prepare_jail()
        self._start_egress()
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
        self._stop_sensor("boot_failed")
        self._stop_egress("boot_failed")
        self._stopped = True
        self._watcher_step("close", self._watcher.close)
        logging.getLogger(_BRIDGED_LOGGERS).removeHandler(self._bridge)
        self._bridge.close()

    def _stop_unsupervised_agent(self) -> None:
        """Step 3: an agent already running means the service died and came back."""
        if not self._jail.is_running():
            return
        self._mark_stopping()
        # Killed, not stopped: nobody has watched it, and `docker stop` would give it up to
        # `stop_timeout` more seconds of running without a watcher.
        error = self._halt(kill_first=True)
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
                "El agente estaba en marcha sin que backtide lo vigilase y no se ha podido parar: "
                "sigue en marcha. Detalles en el evento.",
                event,
            )
            raise error
        self._set_state(AgentState.STOPPED)
        event = self._record("system", "agent_stop", details={"reason": "unsupervised"}, risk=2)
        self._alert(
            AlertLevel.ERROR,
            "El agente corría sin vigilancia",
            "backtide se había parado y el agente seguía en marcha sin que nadie lo grabase. "
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
        if self._prepare_egress is not None:
            self._prepare_egress()
        if not self._jail.exists():
            self._jail.create()

    def _space_forbids_start(self) -> bool:
        """Step 8: the agent does not start with a condition standing, nor with a pause left
        open by an earlier run (read back from the black box: resuming is manual, so a restart
        of the service is not a way around ``backtide seguir``). The service stays up, with the
        space thread and the socket, waiting for ``backtide seguir``."""
        carried = self._open_pause_reasons()
        violations = self._space_verdict()
        if not violations and not carried:
            return False
        if carried:
            with self.freeze_lock:
                self._pause_reasons |= carried
        if violations:
            self._pause(violations, freeze=False)
        else:
            self._carried_pause(carried)
        return True

    def _say_space_unwatched(self) -> None:
        """No space gate (no cap configured): nothing pauses the agent for lack of space or
        for a black box that stops recording. Recorded and told at every start."""
        event = self._record(
            "system", "space_unwatched", details={"reason": "no_workspace_limit"}, risk=2
        )
        self._alert(
            AlertLevel.WARNING,
            "El espacio no se vigila",
            "No hay `workspace_limit` en la configuración: el espacio de trabajo del agente no "
            "tiene tope y nada lo pausa si falta espacio o si la caja negra deja de grabar.",
            event,
        )

    def _open_pause_reasons(self) -> set[str]:
        """The reasons of the pauses no ``space_resume`` closed: every ``system/space_pause``
        after the newest ``system/space_resume``. Fails closed: a black box that cannot be read
        here counts as an open pause."""
        try:
            resumed = self._box.events(
                source="system", action="space_resume", newest_first=True, limit=1
            )
            since = resumed[0].seq if resumed else None
            pauses = self._box.events(source="system", action="space_pause", since_seq=since)
        except BlackBoxError as error:
            logger.error(
                "cannot read the open pauses from the black box, so the agent stays paused: %s",
                error,
            )
            return {"space"}
        reasons: set[str] = set()
        for event in pauses:
            listed = event.details.get("reasons")
            if isinstance(listed, list):
                reasons |= {reason for reason in listed if reason in SPACE_REASONS}
        if pauses and not reasons:
            reasons.add("space")
        if self._user_pause_open():
            reasons.add("user")
        return reasons

    def _user_pause_open(self) -> bool:
        """The person's pause (T09) is open unless a ``system/user_resume`` says it closed the
        newest ``system/user_pause`` (``closes``: that event's seq). A resume that raced a
        later `/pausar` closes only the older one. Fails closed, like the space pauses."""
        try:
            paused = self._box.events(
                source="system", action="user_pause", newest_first=True, limit=1
            )
            if not paused:
                return False
            newest = paused[0].seq
            resumed = self._box.events(source="system", action="user_resume", since_seq=newest)
        except BlackBoxError as error:
            logger.error(
                "cannot read the person's pause from the black box, so the agent stays paused: %s",
                error,
            )
            return True
        with self.freeze_lock:
            self._last_user_pause_seq = newest
        return not any(
            type(event.details.get("closes")) is int and event.details["closes"] >= newest
            for event in resumed
        )

    def _record_user_pause(self, details: dict[str, Any], *, risk: int) -> Event | None:
        """``system/user_pause``, remembering its seq: the ``user_resume`` that closes it says
        so, and that is what the next boot reads."""
        event = self._record("system", "user_pause", details=details, risk=risk)
        if event is not None:
            with self.freeze_lock:
                self._last_user_pause_seq = max(event.seq, self._last_user_pause_seq or 0)
        return event

    def _carried_pause(self, reasons: set[str]) -> None:
        """Nothing is red now, but an earlier run left the agent paused: it stays so, and the
        person hears why and how to resume. The space reasons go back into ``space_pause``,
        the person's own into ``user_pause`` (each event only carries its own kind)."""
        space_reasons = reasons & SPACE_REASONS
        event: Event | None = None
        if space_reasons:
            event = self._record(
                "system",
                "space_pause",
                details={
                    "conditions": [],
                    "reasons": sorted(space_reasons),
                    "frozen": False,
                    "carried_over": True,
                },
                risk=2,
            )
        if "user" in reasons:
            user_event = self._record_user_pause(
                {"requested_by": "boot", "agent": "stopped", "carried_over": True}, risk=1
            )
            event = event or user_event
        why = "por falta de espacio" if space_reasons else ""
        if "user" in reasons:
            why = (why + " y " if why else "") + "porque lo pediste tú (/pausar)"
        self._alert(
            AlertLevel.ERROR,
            "El agente sigue pausado",
            f"backtide se paró con el agente pausado {why}, y la pausa sigue abierta: el agente no "
            "arranca. Ahora no falta espacio; para reanudarlo, ejecuta `backtide seguir` (o "
            "/seguir en Telegram).",
            event,
        )

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

    def _start_agent(self, reason: str | None = None) -> None:
        """Step 11 (and ``resume()`` with ``reason="resume"``). Never while the person's pause
        is open (T09): a `/pausar` that came in after the decision to start wins."""
        if not self._sensor_allows_start():
            return
        if not self._egress_allows_start():
            return
        with self.freeze_lock:
            held = "user" in self._pause_reasons
            if not held:
                self._agent_state = AgentState.STARTING
                self._state_epoch += 1
        if held:
            self._record("system", "agent_start_skipped", details={"reason": "user_pause"})
            return
        freezes = self._confirm_freezes_so_far()
        try:
            if not self._jail.exists():  # a pause that had to kill it may have removed it too
                self._jail.create()
            self._sensor_follow_agent()
            self._jail.start()
            try:
                self._jail.wait_ready()
            except JailError:
                if not self._ready_after_confirm_freeze(freezes):
                    raise
        except JailError as error:
            self._agent_did_not_start(error)
            return
        self._advance(AgentState.STARTING, AgentState.RUNNING)
        self._record("system", "agent_start", details={"reason": reason} if reason else None)
        if not self._sensor_saw_start():
            return
        self._catch_up_user_pause()

    def _confirm_freezes_so_far(self) -> int:
        with self.freeze_lock:
            return self._confirm_freezes

    def _ready_after_confirm_freeze(self, freezes: int) -> bool:
        """``wait_ready`` failed during a start. If the space thread froze the agent to confirm a
        condition meanwhile (``freezes`` is how many it had made when the start began) the
        failure may be that freeze, which ``wait_ready`` cannot tell from a pause: wait up to
        ``CONFIRM_WAIT`` s for its verdict. A false alarm thaws the agent and ``wait_ready`` is
        asked once more (True if it is ready); a confirmed condition (a pause reason) or a
        verdict that does not come leaves the failure as it was. Never waits for a failure with
        no freeze behind it. Called with ``agent_lock`` held, like ``wait_ready`` itself, and
        never waits for ``freeze_lock`` for long."""
        deadline = self._mono() + CONFIRM_WAIT
        while True:
            with self.freeze_lock:
                if self._confirm_freezes == freezes or self._pause_reasons:
                    return False
                settled = self._agent_state is not AgentState.FROZEN
            if settled:
                break
            if self._mono() >= deadline:
                logger.error(
                    "a freeze to confirm a space condition did not end in %.0f s", CONFIRM_WAIT
                )
                return False
            self._sleep(0.1)
        logger.warning("the agent was frozen by a space check that was a false alarm: asking again")
        try:
            self._jail.wait_ready()
        except JailError:
            return False
        return True

    def _catch_up_user_pause(self) -> None:
        """Right after a start: a `/pausar` that came in while `docker start` ran found nothing
        to freeze yet (or killed what was there) and the start went on. Docker says whether
        the agent runs; if it does, it is frozen now (killed if that fails)."""
        with self.freeze_lock:
            if "user" not in self._pause_reasons or self._agent_state is AgentState.FROZEN:
                return
        try:
            running = self._jail.is_running() and not self._jail.is_paused()
        except JailError:
            running = True  # cannot tell: freezing (or killing) is the safe side
        if not running:
            return
        with self.freeze_lock:
            if self._agent_state is not AgentState.FROZEN:
                self._agent_state = AgentState.RUNNING
                self._state_epoch += 1
        held = self._freeze(set(), freeze=True, frozen_already=False)
        still_running = held.pause_error is not None and not held.killed
        self._record_user_pause(
            {
                "requested_by": "catch_up",
                "agent": str(self.agent_state),
                "late": True,
                "killed": held.killed,
            },
            risk=3 if still_running else 1,
        )
        if still_running:
            logger.error("the agent was started during a pause and cannot be frozen nor stopped")

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
                "espacio: borra archivos del agente o sube el tope, y reinicia backtide."
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

    # Space (docs/19, section 5)

    def _read_gate(self) -> tuple[list[Violation], list[Violation]]:
        """Read the gate now: the conditions that forbid the agent to run, with P7 from the
        black box's failures, and the early warnings (W1, W3) apart. An exception from the gate
        is a P4: if we cannot find out, the agent does not get the benefit of the doubt. Every
        reading counts as a check for the watchdog, also one that found P4."""
        if self._space is None:
            return [], []
        try:
            found = list(self._space())
        except Exception as error:
            logger.error("the space check failed: %s", error)
            found = [_Blind(f"no se puede comprobar el espacio: {_excerpt(error)}")]
        violations = [item for item in found if not _is_warning(item)]
        warnings = [item for item in found if _is_warning(item)]
        blackbox = self._blackbox_condition()
        if blackbox is not None:
            violations.append(blackbox)
        with self.freeze_lock:
            self._last_check = self._mono()
        return violations, warnings

    def _violations(self) -> list[Violation]:
        return self._read_gate()[0]

    def _blackbox_condition(self) -> space.Condition | None:
        """P7: appends failed in a row for too long, ours or the file watcher's."""
        with self._record_failures_lock:
            failures, since = self._bb_streak, self._bb_failing_since
        health = getattr(self._watcher, "blackbox_health", None)
        if callable(health):
            try:
                theirs = health()
                if theirs.consecutive_failures > failures:
                    failures = theirs.consecutive_failures
                if theirs.failing_since is not None and (
                    since is None or theirs.failing_since < since
                ):
                    since = theirs.failing_since
            except Exception as error:
                logger.error("cannot read the file watcher's black box health: %s", error)
        failing_for = self._mono() - since if since is not None else 0.0
        return space.blackbox_condition(failures, failing_for, self._space_config)

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

    def _pause(
        self, violations: Sequence[Violation], *, freeze: bool, frozen_already: bool = False
    ) -> None:
        """A condition forbids the agent to run: freeze it if it is running, remember why, say
        so. If it cannot be frozen it is killed: an agent that should be paused and is not is
        the one failure that cannot be left. Resuming is manual (``resume``). ``frozen_already``:
        the space thread froze it to confirm the condition."""
        reasons = {violation.reason for violation in violations}
        held = self._freeze(reasons, freeze=freeze, frozen_already=frozen_already)
        frozen, pause_error = held.frozen, held.pause_error
        killed, kill_error = held.killed, held.kill_error
        details: dict[str, Any] = {
            "conditions": [violation.code for violation in violations],
            "reasons": sorted(reasons),
            "frozen": frozen,
        }
        if pause_error is not None:
            details["pause_error"] = _short(pause_error)
            details["killed"] = killed
        failed_freeze = pause_error is not None and not isinstance(pause_error, _BeingStopped)
        event = self._record(
            "system", "space_pause", details=details, risk=3 if failed_freeze else 2
        )
        if killed:
            self._record(
                "system",
                "agent_stop",
                details={"reason": "freeze_failed" if failed_freeze else "space_while_stopping"},
                risk=3 if failed_freeze else 2,
            )
        elif pause_error is not None:
            self._record(
                "system",
                "agent_stop_failed",
                details={"reason": "freeze_failed", "error": _short(kill_error)},
                risk=3,
            )
        if pause_error is None:
            outcome = "paused"
        else:
            outcome = "killed" if killed else "still_running"
        key = "pause:" + ",".join(sorted(v.code for v in violations)) + ":" + outcome
        if outcome != "still_running" and not self._due(key, REPEAT_ALERT_EVERY):
            return  # every pause is recorded; the alert, once an hour per set and outcome
        body = self._pause_body(violations)
        if pause_error is None:
            paused = frozen or self.agent_state is AgentState.FROZEN
            title = "El agente está pausado" if paused else "El agente no arranca"
            self._alert(AlertLevel.ERROR, title, body, event)
        elif killed and isinstance(pause_error, _BeingStopped):
            self._alert(
                AlertLevel.ERROR,
                "El agente se ha parado",
                "El agente se estaba parando y falta espacio: se ha parado a la fuerza.\n" + body,
                event,
            )
        elif killed:
            self._alert(
                AlertLevel.ERROR,
                "El agente se ha parado: no se pudo congelar",
                "No se pudo congelar al agente, así que se ha parado a la fuerza.\n" + body,
                event,
            )
        else:
            self._alert(
                AlertLevel.ERROR,
                "No se pudo congelar ni parar al agente",
                "El agente debería estar pausado y sigue en marcha. Detalles en el evento.\n"
                + body,
                event,
            )

    def _freeze(self, reasons: set[str], *, freeze: bool, frozen_already: bool) -> "_Held":
        """Open ``reasons`` and, with ``freeze``, freeze an agent that can run code, in one
        hold of ``freeze_lock`` (so the space thread never thaws in between). Being stopped,
        or impossible to freeze, it is killed instead: a `docker stop` would wake a frozen
        one, and an agent that should be paused and is not is the one failure that cannot be
        left. Never waits for ``agent_lock``. ``frozen_already``: the space thread froze it to
        confirm a condition."""
        frozen = False
        pause_error: Exception | None = None
        stopping = False
        with self.freeze_lock:
            self._pause_reasons |= reasons
            if "user" in reasons:
                self._user_pause_epoch += 1
            if frozen_already and self._agent_state is AgentState.FROZEN:
                frozen = True
            elif freeze and self._agent_state is AgentState.STOPPING:
                stopping = True  # being stopped: killed below, never frozen (stop would wake it)
            elif freeze and self._agent_state in _CAN_RUN_CODE:
                try:
                    self._jail.pause()  # milliseconds; never waits for agent_lock
                except Exception as error:
                    pause_error = error
                else:
                    self._agent_state = AgentState.FROZEN
                    self._state_epoch += 1
                    frozen = True
        if pause_error is not None and self._already_paused():
            pause_error, frozen = None, True
            self._set_state(AgentState.FROZEN)
        if stopping:
            pause_error = _BeingStopped("the agent was being stopped: killed instead of frozen")
        killed = False
        kill_error: JailError | None = None
        if pause_error is not None:
            kill_error = self._halt(kill_first=True)
            killed = kill_error is None
            if killed:
                self._set_state(AgentState.STOPPED)
        return _Held(frozen, pause_error, killed, kill_error)

    def _already_paused(self) -> bool:
        """``docker pause`` failed: maybe because the agent is frozen already (that counts)."""
        try:
            return self._jail.is_paused()
        except JailError:
            return False

    def _pause_body(self, violations: Sequence[Violation]) -> str:
        """What the pause alert says (docs/19, section 5): which condition, with figures; for
        P3, after which snapshot the cap was passed; the generations that hold the most; that a
        rewind gives a new cap but frees nothing; and what to do."""
        lines = ["; ".join(condition_text(violation) for violation in violations) + "."]
        if any(violation.code == "P3" for violation in violations):
            passed = self._passed_cap_after()
            if passed is not None:
                lines.append(
                    f"El espacio de trabajo pasó de su tope después de la instantánea {passed}."
                )
        if self._holders is not None:
            try:
                holders = holders_text(self._holders(), self._config.workspace_limit)
            except Exception as error:  # the alert still goes out, saying it could not tell
                logger.warning("cannot read what holds the space: %s", error)
                holders = []
            if holders:
                lines.append("Lo que más ocupa:")
                lines += holders
            else:
                lines.append("No se ha podido leer qué ocupa el espacio.")
        lines.append("Rebobinar da un tope nuevo al espacio de trabajo, pero no libera nada.")
        lines.append(
            "Para liberar espacio, borra puntos de deshacer que ya no necesites o archivos del "
            "agente, y después ejecuta `backtide seguir`."
        )
        return "\n".join(lines)

    def _passed_cap_after(self) -> str | None:
        """The snapshot the workspace comes from (its lineage reference): the cap was passed
        after it."""
        try:
            workspace = self._info(self._store.workspace)
            reference = lineage_reference(workspace, self._snapshot_infos())
        except SnapshotError as error:
            logger.warning("cannot tell after which snapshot the cap was passed: %s", error)
            return None
        return reference.snapshot.id if reference is not None else None

    # The space thread and its watchdog

    def check_space(self) -> None:
        """One pass of the space thread (every second). Read the signals; if something is red
        and the agent can run code, freeze it FIRST, then sync and read again (reservations
        make ``meta_avail`` jump down and back within a second): confirmed, the pause opens;
        not, the agent is thawed unless something else paused it meanwhile, and the false
        alarm is counted (``system/space_check`` once an hour; more than 6 in an hour and the
        confirmation takes 3 readings). Green: the early warnings. Never waits for
        ``agent_lock``. Every 5 s it commits the transaction if the workspace changed, so P3
        sees what was deleted after a snapshot."""
        if self._space is None or not self._serving:
            return
        blind = self._sync_if_due()
        violations, warnings = self._read_gate()
        if blind is not None:
            violations.append(blind)
        if not violations:
            self._warn_low(warnings)
            self._report_transients()
            return
        epoch = self._freeze_to_confirm()
        if epoch is None:
            return  # stopped or already frozen: nothing runs, an open pause stays open
        if epoch is False:
            self._pause(violations, freeze=True)  # could not freeze: tries again, then kills
            return
        confirmed = self._confirm()
        if confirmed:
            self._pause(confirmed, freeze=True, frozen_already=True)
            return
        self._thaw_after_false_alarm(epoch)
        self._report_transients()

    def check_watchdog(self) -> None:
        """One pass of the watchdog (every second, no I/O but the freeze): if the space thread
        has not finished a check for more than 3 s while the agent can run code, that is P4,
        and the agent is frozen. A stopped or frozen agent runs nothing, so a late check is
        harmless then."""
        if self._space is None or not self._serving:
            return
        with self.freeze_lock:
            can_run = self._agent_state in _CAN_RUN_CODE
            last = self._last_check if self._last_check is not None else self._serving_since
        if not can_run:
            return
        age = None if last is None else self._mono() - last
        if age is not None and 0 <= age <= self._space_config.stale_after:
            return
        late = "ninguna comprobación todavía" if age is None else f"{age:.1f} s sin comprobar"
        logger.error("the space thread is late (%s): the agent is frozen", late)
        self._pause([_Blind(f"el hilo de espacio va con retraso ({late})")], freeze=True)

    def _sync_if_due(self) -> Violation | None:
        """Every ``SYNC_EVERY`` seconds, if the workspace changed since the last commit, commit:
        ``referenced`` (P3) only moves then. A failure is a P4."""
        now = self._mono()
        if now - self._last_sync < SYNC_EVERY:
            return None
        self._last_sync = now
        try:
            ctransid = self._info(self._store.workspace).ctransid
        except SnapshotError as error:
            return _Blind(f"no se puede leer el espacio de trabajo: {_excerpt(error)}")
        if ctransid == self._synced_ctransid:
            return None
        if not self._sync_quietly():
            return _Blind("btrfs filesystem sync ha fallado: el uso de espacio no es fiable")
        self._synced_ctransid = ctransid
        return None

    def _freeze_to_confirm(self) -> int | None | bool:
        """Freeze the agent before confirming a condition. Returns the state epoch of the
        freeze, None if there is nothing to freeze (stopped, or frozen already), False if the
        freeze failed."""
        with self.freeze_lock:
            if self._agent_state not in _CAN_RUN_CODE:
                return None
            if self._agent_state is AgentState.STOPPING:
                return False  # being stopped: `_pause` kills it (a freeze would be woken)
            try:
                self._jail.pause()
            except Exception as error:
                logger.error("cannot freeze the agent to confirm a space condition: %s", error)
                return False
            self._thaw_to = self._agent_state
            self._agent_state = AgentState.FROZEN
            self._state_epoch += 1
            self._confirm_freezes += 1
            return self._state_epoch

    def _confirm(self) -> list[Violation]:
        """With the agent frozen: commit and read again, once (three times, a tick apart, when
        false alarms are frequent). The conditions of the last reading if every one is red,
        else nothing."""
        readings = JUMPY_READINGS if len(self._transients) > JUMPY_AFTER else 1
        found: list[Violation] = []
        for index in range(readings):
            if index:
                self._sleep(self._tick)
            found = self._space_verdict()
            if not found:
                return []
        return found

    def _thaw_after_false_alarm(self, epoch: int) -> None:
        """The condition was not confirmed: thaw the agent, but only if the freeze is still
        ours (nothing changed the state since) and no pause was opened meanwhile."""
        now = self._mono()
        self._transients.append(now)
        self._transients_unreported += 1
        thaw_error: Exception | None = None
        with self.freeze_lock:
            if (
                self._agent_state is not AgentState.FROZEN
                or self._state_epoch != epoch
                or self._pause_reasons
            ):
                return
            try:
                self._jail.unpause()
            except Exception as error:
                thaw_error = error
            else:
                self._agent_state = self._thaw_to
                self._state_epoch += 1
                return
        logger.error("cannot thaw the agent after a false alarm: %s", thaw_error)
        self._pause(
            [_Blind("no se ha podido descongelar al agente tras una falsa alarma")], freeze=False
        )

    def _report_transients(self) -> None:
        """Unconfirmed freezes: ``system/space_check {transient_freezes}`` once an hour if
        there were any, and a warning when they pass 6 in an hour (confirmation then takes
        three readings)."""
        now = self._mono()
        while self._transients and now - self._transients[0] > TRANSIENT_WINDOW:
            self._transients.popleft()
        if len(self._transients) > JUMPY_AFTER and self._due("transient", TRANSIENT_WINDOW):
            self._alert(
                AlertLevel.WARNING,
                "Muchas falsas alarmas de espacio",
                f"El agente se ha congelado {len(self._transients)} veces en una hora por una "
                "lectura de espacio que no se confirmó. Ahora se confirma con tres lecturas.",
            )
        if now < self._next_space_report:
            return
        self._next_space_report = now + TRANSIENT_WINDOW
        if self._transients_unreported:
            self._record(
                "system",
                "space_check",
                details={"transient_freezes": self._transients_unreported},
                risk=1,
            )
            self._transients_unreported = 0

    def _warn_low(self, warnings: Sequence[Violation]) -> None:
        """The early warnings: ``system/space_low`` and an alert, once an hour per condition."""
        for warning in warnings:
            if not self._due(f"space_low:{warning.code}", REPEAT_ALERT_EVERY):
                continue
            event = self._record(
                "system",
                "space_low",
                details={
                    "condition": warning.code,
                    "message": warning.message,
                    "value": getattr(warning, "value", None),
                    "threshold": getattr(warning, "threshold", None),
                },
                risk=1,
            )
            self._alert(
                AlertLevel.WARNING,
                "Queda poco espacio",
                f"{condition_text(warning)}. Aún no se pausa al agente; si sigue así, se pausará.",
                event,
            )

    # The person's pause (Telegram's `/pausar`, T09)

    def pause_by_user(self, *, requested_by: str) -> PauseOutcome:
        """Freeze the agent now, from outside (``docker pause``), and keep it so until
        ``resume`` (`/seguir`, `backtide seguir`): the pause reason ``user``. Never waits for
        ``agent_lock``, so it is immediate also while a rewind or a long `docker stop` runs; an
        agent being stopped is killed instead (a stop would wake it), and so is one that cannot
        be frozen. A stopped agent stays stopped: nothing starts it while the pause is open,
        not a rewind and not a restart of the service (the pause is read back at boot).
        Recorded: ``system/user_pause`` (and ``agent_stop`` or ``agent_stop_failed`` if it had
        to be killed). Never raises."""
        requester = str(requested_by)[:MAX_REQUESTER_CHARS] or "unknown"
        if not self._serving:
            return PauseOutcome(
                PauseStatus.FAILED, "backtide no está en marcha: no hay ningún agente que pausar."
            )
        try:
            return self._pause_by_user(requester)
        except Exception as error:  # nothing on this path is swallowed
            logger.exception("pausing the agent failed")
            return PauseOutcome(
                PauseStatus.STILL_RUNNING,
                f"Ha fallado algo al pausar: {_excerpt(error)}. Puede que el agente siga en "
                "marcha: mira /estado.",
                str(self.agent_state),
            )

    def _pause_by_user(self, requester: str) -> PauseOutcome:
        with self.freeze_lock:
            already = "user" in self._pause_reasons
            before = self._agent_state
        held = self._freeze({"user"}, freeze=True, frozen_already=False)
        # After the freeze (the urgent part): what the agent asked and waits for is rejected,
        # so nothing is approved for a frozen agent (docs/32, decision 7).
        self._reject_holds("pause")
        after = self.agent_state
        failed_freeze = held.pause_error is not None and not isinstance(
            held.pause_error, _BeingStopped
        )
        still_running = held.pause_error is not None and not held.killed
        details: dict[str, Any] = {
            "requested_by": requester,
            "agent_before": str(before),
            "agent": str(after),
            "already": already,
        }
        if held.pause_error is not None:
            details["pause_error"] = _short(held.pause_error)
            details["killed"] = held.killed
        event = self._record_user_pause(details, risk=3 if still_running else 1)
        reason = "user_pause_freeze_failed" if failed_freeze else "user_pause_while_stopping"
        if held.killed:
            self._record("system", "agent_stop", details={"reason": reason}, risk=2)
            return PauseOutcome(
                PauseStatus.KILLED,
                "No se ha podido congelar al agente, así que se ha parado a la fuerza. No "
                "arranca hasta /seguir.",
                str(after),
                already,
            )
        if still_running:
            stop_failed = self._record(
                "system",
                "agent_stop_failed",
                details={"reason": reason, "error": _short(held.kill_error)},
                risk=3,
            )
            self._alert(
                AlertLevel.ERROR,
                "No se pudo congelar ni parar al agente",
                "Has pedido pausar al agente y sigue en marcha: no se ha podido congelar ni "
                "parar. Detalles en el evento.",
                stop_failed or event,
            )
            return PauseOutcome(
                PauseStatus.STILL_RUNNING,
                "No se ha podido congelar ni parar al agente: SIGUE EN MARCHA. Detalles en la "
                "caja negra.",
                str(after),
                already,
            )
        if after is AgentState.FROZEN:
            text = "El agente ya estaba congelado" if not held.frozen else "Agente congelado"
            return PauseOutcome(
                PauseStatus.FROZEN,
                f"{text}: no hace nada hasta /seguir.",
                str(after),
                already,
            )
        return PauseOutcome(
            PauseStatus.STOPPED,
            "El agente no estaba en marcha: queda parado y no arranca hasta /seguir.",
            str(after),
            already,
        )

    # Resume (`backtide seguir`)

    def user_pause_mark(self) -> int:
        """How many times the person has asked to pause so far (T09): a ``resume`` given this
        mark refuses if another `/pausar` came after it."""
        with self.freeze_lock:
            return self._user_pause_epoch

    def resume(self, *, requested_by: str, pause_mark: int | None = None) -> ResumeOutcome:
        """Close a pause by space and let the agent run again (``backtide seguir``; T09's
        ``/seguir``). Refuses while any condition stands (read after a sync, as at every
        start). Otherwise the space reasons are removed and, only if no other reason is left,
        the agent is thawed (or started, if it was stopped: as at boot, after a snapshot and
        with the watcher armed). Recorded: ``system/resume_requested``, then ``resume_refused``
        or ``space_resume {by: user}``. Never raises.

        It also closes the person's pause (``user``, T09; ``user_resume``), but never one asked
        for after the request: ``pause_mark`` is ``user_pause_mark()`` when the person sent it
        (taken here, before waiting for ``agent_lock``, if not given). A `/pausar` after that,
        even while this waits or syncs, wins: STILL_PAUSED and nothing closed."""
        requester = str(requested_by)[:MAX_REQUESTER_CHARS] or "unknown"
        mark = self.user_pause_mark() if pause_mark is None else pause_mark
        with self.agent_lock:
            if not self._serving:
                return ResumeOutcome(
                    ResumeStatus.FAILED, "backtide no está en marcha: no se ha reanudado nada."
                )
            try:
                return self._resume_locked(requester, mark)
            except Exception as error:  # nothing on this path is swallowed
                logger.exception("resuming the agent failed")
                return ResumeOutcome(
                    ResumeStatus.PROBLEM,
                    f"Ha fallado algo al reanudar: {_excerpt(error)}. Detalles en el log.",
                    str(self.agent_state),
                )

    def _resume_locked(self, requester: str, mark: int) -> ResumeOutcome:
        # Recorded first: a black box that works again resets P7 with this very append.
        self._record("system", "resume_requested", details={"requested_by": requester})
        with self.freeze_lock:
            reasons = set(self._pause_reasons)
        if not reasons & (SPACE_REASONS | {"user"}):
            if not reasons and self._stopped_with_no_pause():
                return ResumeOutcome(
                    ResumeStatus.STOPPED,
                    "El agente está parado, pero no por falta de espacio: no hay ninguna pausa "
                    "que cerrar y `backtide seguir` no lo arranca. Mira por qué se paró en la "
                    "caja negra (eventos `agent_stop` y `agent_start_failed`) y reinicia "
                    "`backtide vigilar`: al arrancar, el servicio lo pone en marcha vigilado.",
                    str(self.agent_state),
                )
            return ResumeOutcome(
                ResumeStatus.NOT_PAUSED,
                "El agente no está pausado: no hay nada que reanudar.",
                str(self.agent_state),
            )
        # Also when only the person paused it: nothing runs with a condition standing (the
        # space thread does not look at a frozen agent, so a pause could hide one).
        violations = self._space_verdict()
        if violations:
            event = self._record(
                "system",
                "resume_refused",
                details={
                    "requested_by": requester,
                    "conditions": [violation.code for violation in violations],
                },
                risk=1,
            )
            texts = "; ".join(condition_text(violation) for violation in violations)
            self._alert(
                AlertLevel.WARNING,
                "No se reanuda: sigue faltando espacio",
                f"{texts}. Libera espacio y vuelve a ejecutar `backtide seguir`.",
                event,
            )
            return ResumeOutcome(
                ResumeStatus.STILL_RED,
                f"No se reanuda: {texts}. Libera espacio y vuelve a probar.",
                str(self.agent_state),
            )
        with self.freeze_lock:
            paused_after = self._user_pause_epoch != mark
            if not paused_after:
                cleared = self._pause_reasons & SPACE_REASONS
                self._pause_reasons -= SPACE_REASONS
                cleared_user = "user" in self._pause_reasons
                self._pause_reasons.discard("user")
                remaining = set(self._pause_reasons)
                closes = self._last_user_pause_seq
        if paused_after:
            self._record(
                "system",
                "resume_refused",
                details={"requested_by": requester, "reason": "paused_after"},
                risk=1,
            )
            return ResumeOutcome(
                ResumeStatus.STILL_PAUSED,
                "Se ha pedido pausar después de esta orden de seguir: el agente sigue pausado.",
                str(self.agent_state),
            )
        for key in [key for key in self._last_alerted if key.startswith("pause:")]:
            self._last_alerted.pop(key, None)  # the next pause is told about at once
        if remaining:
            self._record_resumed(
                cleared, cleared_user, requester, "still_paused", remaining, closes
            )
            return ResumeOutcome(
                ResumeStatus.STILL_PAUSED,
                "La pausa se ha cerrado, pero el agente sigue pausado por otra razón.",
                str(self.agent_state),
            )
        agent = self._wake_agent()
        self._record_resumed(cleared, cleared_user, requester, agent, set(), closes)
        if self.agent_state is AgentState.RUNNING:
            message = (
                "El agente sigue donde estaba." if agent == "thawed" else "El agente ha arrancado."
            )
            return ResumeOutcome(ResumeStatus.RESUMED, message, str(self.agent_state))
        if agent == "paused_again":
            return ResumeOutcome(
                ResumeStatus.STILL_PAUSED,
                "Se ha vuelto a pausar al agente mientras se reanudaba: sigue pausado.",
                str(self.agent_state),
            )
        return ResumeOutcome(
            ResumeStatus.PROBLEM,
            "La pausa se ha cerrado, pero el agente no ha arrancado. Detalles en la caja negra.",
            str(self.agent_state),
        )

    def _record_resumed(
        self,
        cleared: set[str],
        cleared_user: bool,
        requester: str,
        agent: str,
        remaining: set[str],
        closes: int | None,
    ) -> None:
        """``space_resume {by: user}`` closes the space reasons (what the boot reads back) and
        ``user_resume`` the person's pause (T09): each only if it was open."""
        extra: dict[str, Any] = {"remaining": sorted(remaining)} if remaining else {}
        if cleared:
            self._record(
                "system",
                "space_resume",
                details={
                    "by": "user",
                    "reasons": sorted(cleared),
                    "requested_by": requester,
                    "agent": agent,
                    **extra,
                },
            )
        if cleared_user:
            self._record(
                "system",
                "user_resume",
                details={"requested_by": requester, "agent": agent, "closes": closes, **extra},
            )

    def _stopped_with_no_pause(self) -> bool:
        """Docker says the agent is not running while no pause is open (Docker's word, as in
        ``_wake_agent``; if it cannot be read, "nothing to resume" stands)."""
        try:
            return not self._jail.is_running()
        except JailError as error:
            logger.warning("cannot tell whether the agent runs to answer `seguir`: %s", error)
            return False

    def _wake_agent(self) -> str:
        """Thaw a frozen agent, or start a stopped one. Docker's state decides, never ours.
        A frozen agent that cannot be thawed is killed and started again. Returns what was
        done: "thawed", "started", "restarted" or "running"."""
        try:
            running = self._jail.is_running()
            frozen = running and self._jail.is_paused()
        except JailError as error:
            logger.error("cannot tell the state of the agent to resume it: %s", error)
            running, frozen = True, True  # assume the worst: try to thaw, else kill
        if frozen:
            # Under freeze_lock: a `/pausar` that came in meanwhile (it never waits for
            # agent_lock) either wins and keeps it frozen, or freezes it right after.
            with self.freeze_lock:
                if self._pause_reasons:
                    return "paused_again"
                try:
                    self._jail.unpause()
                except Exception as error:
                    thaw_error: Exception | None = error
                else:
                    self._agent_state = AgentState.RUNNING
                    self._state_epoch += 1
                    return "thawed"
            logger.error("cannot thaw the agent, so it is restarted: %s", thaw_error)
            self._mark_stopping()
            halt_error = self._halt(kill_first=True)
            if halt_error is not None:
                self._set_state(AgentState.FROZEN)
                self._record(
                    "system",
                    "agent_stop_failed",
                    details={"reason": "thaw_failed", "error": _short(halt_error)},
                    risk=3,
                )
                return "frozen"
            self._set_state(AgentState.STOPPED)
            self._record("system", "agent_stop", details={"reason": "thaw_failed"}, risk=2)
            self._start_from_pause()
            return "restarted"
        if running and self.agent_state is not AgentState.STOPPED:
            with self.freeze_lock:  # a `/pausar` meanwhile froze it: FROZEN stays
                if self._pause_reasons or self._agent_state is AgentState.FROZEN:
                    return "paused_again"
                self._agent_state = AgentState.RUNNING
                self._state_epoch += 1
            return "running"
        if running:
            # Running while we had it stopped: nobody armed the watcher for it. Stop it and
            # start it the watched way.
            self._mark_stopping()
            if self._halt(kill_first=True) is not None:  # unwatched: no `docker stop` grace
                self._set_state(AgentState.RUNNING)
                return "running"
            self._set_state(AgentState.STOPPED)
            self._record("system", "agent_stop", details={"reason": "unsupervised"}, risk=2)
        self._set_state(AgentState.STOPPED)
        self._start_from_pause()
        return "started"

    def _start_from_pause(self) -> None:
        """Start an agent that a pause kept stopped, as the boot does from step 9: a snapshot
        with the agent stopped if the workspace changed, the watcher armed, then the agent."""
        current = self._startup_snapshot()
        self._arm_watcher(current)
        self._start_agent(reason="resume")

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

    # Rewind without a service (T04c-2: `backtide rebobinar` when no `backtide vigilar` runs)

    def open_for_rewind(self) -> None:
        """Make ``rewind()`` usable without a service: open the black box (so the rewind has
        somewhere to record), write ``system/cli_start`` and bridge the log into it. Nothing
        else boots: no snapshot, no watcher armed, no agent started. ``want_running`` is
        "no" for the state of a fresh Guardian (stopped, no pause), so the agent is never started
        by this rewind, and one found running unsupervised is stopped by the rewind itself.

        The caller holds ``backtide.lock`` (there is no service) and uses a ``NullWatcher``. Raises
        BlackBoxError, with nothing touched, if the black box cannot be used: no recording, no
        rewinding. Call ``close_after_rewind`` when done."""
        with self.agent_lock:
            self._stopped = False
            self._wound_down = False
            try:
                self._box.open()
                self._box.append(
                    "system", "cli_start", "", details={"version": backtide.__version__}
                )
            except BlackBoxError as error:
                self._wound_down = True
                logger.error("cannot use the black box, so nothing is rewound: %s", error)
                raise
            self._serving = True
            self._bridge = LogBridge(self._on_log)
            self._bridge.start()
            logging.getLogger(_BRIDGED_LOGGERS).addHandler(self._bridge)

    def close_after_rewind(self) -> None:
        """The end of ``open_for_rewind``: record ``system/cli_stop``, detach the bridge (which
        drains the bridged log into the black box). Never touches the agent. Idempotent."""
        with self.agent_lock:
            if not self._serving:
                return
            self._serving = False
            self._wound_down = True
            self._stopped = True
            self._record("system", "cli_stop", details={"agent_state": str(self.agent_state)})
            logging.getLogger(_BRIDGED_LOGGERS).removeHandler(self._bridge)
            self._bridge.close()

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
           pause ``rewind_no_space``. Then the volume grows once (T04e-1) and, if it grew, the
           rewind is retried once (or, if it was swapped without its undo point, the undo point
           is published with ``recover()``), under the same lock, request id and intent.
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
                    message="backtide no está en marcha: no se ha rebobinado nada.",
                )
            self._rewinding = True  # no approval until it ends (B2)
            try:
                return self._rewind_locked(target, requester)
            finally:
                self._rewinding = False

    def _rewind_locked(self, target: Snapshot, requested_by: str) -> RewindOutcome:
        self._settle_earlier_rewind()
        self._reject_holds("rewind")  # docs/32, decision 7
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

        result, error = self._restore(attempt)
        if is_space_error(error):
            self._pause_for_rewind_space(attempt, error)
            result, error = self._grow_and_retry(attempt, result, error)
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

    def _restore(self, attempt: _RewindAttempt) -> tuple[RestoreResult | None, Exception | None]:
        try:
            result = self._store.restore(
                attempt.target.id, quiesce=lambda: self._rewind_quiesce(attempt)
            )
        except Exception as caught:  # decided by the workspace id afterwards, never by the type
            return None, caught
        return result, None

    # The emergency growth (T04e-1, docs/19 section 6)

    def _grow_and_retry(
        self, attempt: _RewindAttempt, result: RestoreResult | None, error: Exception | None
    ) -> tuple[RestoreResult | None, Exception | None]:
        """The rewind failed for lack of space and the agent is stopped (or could not be: then
        the grower refuses). Grow the volume once and, if it grew, try once more: the rewind
        again if the workspace was not swapped, or ``recover()`` (which publishes the undo
        point) if it was. Never deletes a snapshot. Returns the new result and error; whether
        the rewind happened is still decided by the workspace id, by the caller."""
        try:
            swapped = self._store.workspace_id() != attempt.from_workspace
        except SnapshotError as read_error:
            logger.error(
                "cannot tell whether the rewind %s swapped the workspace, so the volume is not "
                "grown: %s",
                attempt.request_id,
                read_error,
            )
            return result, error
        if swapped and not isinstance(error, RestoreIncomplete):
            logger.error(
                "the rewind %s swapped the workspace and then ran out of space: nothing to retry, "
                "so the volume is not grown",
                attempt.request_id,
            )
            return result, error
        events: list[Event] = []

        def record(details: dict[str, Any], risk: int) -> bool:
            event = self._record(
                "snapshot", "volume_grow", str(self._store.root), details=details, risk=risk
            )
            if event is not None:
                events.append(event)
            return event is not None

        grown = self._grow.grow(
            attempt.request_id, agent_stopped=self._agent_is_stopped, record=record
        )
        attempt.grow = grown
        self._growth_alert(grown, events[-1] if events else None)
        if not grown.grown:
            return result, error
        attempt.retried = True
        if swapped:
            return self._recover_after_growth(attempt, result, error)
        # Once, with the same request id and intent: rewind.pending still says where it starts.
        attempt.stopped = attempt.start_requested = attempt.agent_started = False
        attempt.start_error = None
        return self._restore(attempt)

    def _agent_is_stopped(self) -> bool:
        """For the grower: stopped in our state AND in Docker's. A JailError propagates (the
        grower refuses: it cannot tell)."""
        return self.agent_state is AgentState.STOPPED and not self._jail.is_running()

    def _recover_after_growth(
        self, attempt: _RewindAttempt, result: RestoreResult | None, error: Exception | None
    ) -> tuple[RestoreResult | None, Exception | None]:
        """The rewind happened but its undo point was left unpublished for lack of space: with
        room now, ``recover()`` publishes it (as ``recovered``), and the agent may start."""
        try:
            recovered = self._store.recover()
        except SnapshotError as recover_error:
            logger.error(
                "the volume grew, but the undo point of the rewind %s still cannot be "
                "published: %s",
                attempt.request_id,
                recover_error,
            )
            return result, error
        self._start_after_recovery(attempt)
        return RestoreResult(target=attempt.target, undo=None, recovered=tuple(recovered)), None

    def _start_after_recovery(self, attempt: _RewindAttempt) -> None:
        """What the quiesce's exit does after a swap, for the rewind whose quiesce is long gone:
        start the agent only if ``_start_after_rewind`` allows it (it should run, the space is
        green, only space reasons keep it paused, and those are closed)."""
        if not self._start_after_rewind(attempt, None):
            return
        try:
            self._jail.start()
            self._jail.wait_ready()
        except JailError as start_error:
            attempt.start_error = start_error
            attempt.problems.append("agent")
            self._agent_did_not_start(start_error)
            return
        self._advance(AgentState.STARTING, AgentState.RUNNING)
        attempt.agent_started = True
        self._record(
            "system", "agent_start", details={"reason": "rewind", "request_id": attempt.request_id}
        )
        if not self._sensor_saw_start():
            attempt.agent_started = False  # a required sensor did not see it: stopped
            return
        self._catch_up_user_pause()  # a `/pausar` during the start found nothing to freeze

    def _growth_alert(self, grown: GrowResult, event: Event | None) -> None:
        """One alert per growth, citing its last ``volume_grow``. Never the step's own text (it
        is in the event): only what it means for the person. Nothing is said for a Guardian
        without growth configured: the space alert already says what to do."""
        if grown.status is GrowStatus.REFUSED and grown.reason == "not_configured":
            return
        if grown.grown:
            self._alert(
                AlertLevel.WARNING,
                "El volumen ha crecido",
                f"Un rebobinado se ha quedado sin espacio y backtide ha agrandado el volumen de "
                f"{_mib(grown.from_bytes)} a {_mib(grown.reached_bytes)}, una sola vez y sin "
                "borrar ninguna instantánea. Ahora lo reintenta.",
                event,
            )
            return
        if grown.status is GrowStatus.REFUSED:
            why = _GROW_REFUSED_TEXT.get(grown.reason or "", "no se cumplían sus condiciones")
            self._alert(
                AlertLevel.ERROR,
                "No se ha agrandado el volumen",
                f"El rebobinado se ha quedado sin espacio y backtide no ha agrandado el volumen: "
                f"{why}. Libera espacio y vuelve a rebobinar.",
                event,
            )
            return
        if grown.reason == "not_configured":
            how = (
                "backtide todavía no tiene permiso para agrandarlo (lo prepara el instalador). "
                "No ha cambiado nada."
            )
        elif grown.done_steps:
            how = (
                f"Ha fallado el paso {grown.step} después de {', '.join(grown.done_steps)}: "
                "el volumen puede haber quedado a medias, revísalo."
            )
        else:
            how = f"Ha fallado el primer paso ({grown.step}): no ha cambiado nada."
        self._alert(
            AlertLevel.ERROR,
            "No se ha podido agrandar el volumen",
            f"El rebobinado se ha quedado sin espacio. {how} Libera espacio y vuelve a "
            "rebobinar. Detalles en el evento.",
            event,
        )

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
        if state is AgentState.FROZEN:
            # No reason is open: the space thread froze it to confirm a condition (nothing is
            # confirmed yet), and it goes back to what it was if the alarm is false. A rewind
            # that left it stopped here would leave it stopped with nothing written down.
            return self._thaw_to is AgentState.RUNNING
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
            self._mark_stopping()
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
        freezes = self._confirm_freezes_so_far()
        try:
            quiesced.__exit__(*exc_info)
        except JailError as error:
            if not attempt.start_requested:
                raise
            # The agent was started and ``wait_ready`` failed. If that was a freeze to confirm
            # that turned out a false alarm, the agent is ready now and the start succeeded.
            if body_error is not None or not self._ready_after_confirm_freeze(freezes):
                attempt.start_error = error
                attempt.problems.append("agent")
                self._agent_did_not_start(error)
                return
        if attempt.start_requested:
            self._advance(AgentState.STARTING, AgentState.RUNNING)
            attempt.agent_started = True
            self._record(
                "system",
                "agent_start",
                details={"reason": "rewind", "request_id": attempt.request_id},
            )
            if not self._sensor_saw_start():
                attempt.agent_started = False  # a required sensor did not see it: stopped
                return
            self._catch_up_user_pause()

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
            if not self._sensor_saw_start():
                attempt.agent_started = False

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
        leaves it stopped with the pause open (``backtide seguir``, T04d-2, starts it later).
        Fails closed: if deciding breaks, the agent stays stopped and that is logged."""
        try:
            if not attempt.want_running or is_space_error(error):
                return False
            if not self._egress_allows_start():
                return False  # held for the proxy: its ``back`` hook starts it
            if not self._sensor_allows_start():
                return False  # held for a required sensor: its ``back`` hook starts it
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
            with self.freeze_lock:  # a `/pausar` meanwhile (it never waits for agent_lock) wins
                if "user" in self._pause_reasons:
                    return False
                self._agent_state = AgentState.STARTING
                self._state_epoch += 1
            attempt.start_requested = True
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
        ``rewind_no_space`` and say so. Growing the volume once (T04e-1, ``_grow_and_retry``)
        or, failing that, freeing space and rewinding again is what comes next."""
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
        if self._grow.can_grow and kill_error is None:
            then = "backtide va a agrandar el volumen una sola vez y a reintentarlo."
        else:
            then = "Libera espacio (borra instantáneas que no necesites) y vuelve a rebobinar."
        body = (
            "El rebobinado no ha podido terminar por falta de espacio en el volumen. "
            + agent
            + then
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
        details.update(_growth_details(attempt))
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
        if attempt.retried:
            message += " Antes, el volumen ha crecido una vez porque faltaba espacio."
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
            **_growth_details(attempt),
        }
        # Grown and retried, and still not rewound: the last resort failed (docs/19, section 6).
        risk = 3 if attempt.retried else 2
        event = self._record(
            "snapshot", "rewind_failed", attempt.target.id, details=details, risk=risk
        )
        attempt.final_recorded = event is not None
        if attempt.retried and no_space:
            body = (
                "El volumen ha crecido una vez y sigue sin haber espacio: el espacio de trabajo "
                "no ha cambiado y el agente sigue parado. Libera espacio y vuelve a rebobinar."
            )
        elif attempt.retried:
            body = (
                "El volumen ha crecido, pero el reintento ha fallado: el espacio de trabajo no "
                "ha cambiado. Detalles en el evento."
            )
        elif no_space:
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
            "No se puede leer el espacio de trabajo tras el rebobinado. backtide lo comprobará al "
            "volver a arrancar.",
        )
        return RewindOutcome(
            RewindStatus.UNKNOWN,
            target=attempt.target.id,
            message="No se sabe si se ha rebobinado: se comprobará al volver a arrancar backtide.",
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
                f"backtide se paró a mitad de un rebobinado a {target}. Al volver ha comprobado "
                "que el rebobinado sí se hizo" + (f"; para deshacerlo: {undo}." if undo else ".")
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
                f"backtide se paró a mitad de un rebobinado a {target}. Al volver ha comprobado "
                "que no llegó a hacerse: el espacio de trabajo no ha cambiado."
            )
        self._alert(AlertLevel.WARNING, "Un rebobinado se interrumpió", body, event)
        return event is not None

    # The process sensor (T07-3, docs/23 section 7)

    def _start_sensor(self) -> None:
        """Boot, after the black box and before the agent's jail: the sensor never raises,
        and without it the agent starts anyway unless it is required (``_start_agent``)."""
        if self._sensor is None:
            return
        self._sensor_closing.clear()
        self._sensor_held = False
        self._sensor.start(
            SensorHooks(
                record=self._record,
                alert=self._alert,
                agent_running=lambda: self.agent_state is AgentState.RUNNING,
                lost=self._sensor_lost,
                back=self._sensor_back,
            )
        )

    def _stop_sensor(self, reason: str) -> None:
        """After the agent: its last commands are in Tetragon's file, read before the stop."""
        if self._sensor is None:
            return
        self._sensor_closing.set()
        self._sensor.stop(reason)

    def _sensor_follow_agent(self) -> None:
        """Right before the agent starts: its container may be a new one."""
        if self._sensor is not None:
            self._sensor.follow_agent()

    def _sensor_allows_start(self) -> bool:
        """A required sensor that is not up keeps the agent stopped (decision 7)."""
        if self._sensor is None or self._sensor.allows_agent():
            return True
        self._sensor_held = True
        event = self._record("system", "agent_start_skipped", details={"reason": "sensor_required"})
        self._alert(
            AlertLevel.ERROR,
            "El agente no arranca sin el sensor de procesos",
            "El sensor de procesos es obligatorio en esta configuración ([sensor] required) y no "
            "funciona: el agente no arranca. Arrancará en cuanto el sensor vuelva.",
            event,
        )
        return False

    def _sensor_saw_start(self) -> bool:
        """Right after the agent got ready: the sensor proves it sees it. A required sensor
        that does not stops the agent again (False)."""
        if self._sensor is None:
            return True
        if self._sensor.agent_started() or not self._sensor.required:
            return True
        self._sensor_held = True
        stopped = self._stop_agent("sensor_required") is None
        self._alert(
            AlertLevel.ERROR,
            "El agente se ha parado: el sensor no lo ve",
            "El sensor de procesos es obligatorio y no ha visto al agente al arrancar"
            + (", así que se ha parado." if stopped else ", y el agente no se ha podido parar.")
            + " Arrancará en cuanto el sensor vuelva.",
        )
        return False

    def _sensor_lock(self) -> bool:
        """``agent_lock`` for a hook of the sensor's thread, unless the service stops first."""
        while not self.agent_lock.acquire(timeout=0.2):
            if self._sensor_closing.is_set():
                return False
        if self._sensor_closing.is_set():
            self.agent_lock.release()
            return False
        return True

    def _sensor_lost(self, reason: str = "sensor_down") -> bool:
        """A required sensor fell, or cannot vouch for what the agent runs (``reason``: the
        sensor's, recorded in ``agent_stop``): the agent stops until it is back (the sensor
        alerted). Returns whether the agent is stopped now: the sensor does not restart
        Tetragon while it may still run unseen (False: it could not be stopped, or the service
        is closing and its stop will do it)."""
        if not self._sensor_lock():
            return False
        try:
            try:
                running = self._jail.is_running()
            except JailError:
                running = True  # cannot tell: _stop_agent confirms
            if not running:
                return True
            if not self._serving:
                return False
            self._sensor_held = True
            return self._stop_agent(reason if reason in _SENSOR_REASONS else "sensor_down") is None
        finally:
            self.agent_lock.release()

    def _sensor_back(self) -> None:
        """A required sensor is back: start the agent it stopped, if nothing else holds it
        (a pause of the person or of space decides on its own; so does a stopped service)."""
        if not self._sensor_lock():
            return
        try:
            if not self._serving or not self._sensor_held or self.pause_reasons:
                return
            try:
                running = self._jail.is_running()
            except JailError:
                return
            if running:
                self._sensor_held = False
                return
            if [item for item in self._start_verdict() if not _is_warning(item)]:
                return  # the space thread pauses it; `backtide seguir` starts it later
            self._sensor_held = False
            self._start_agent(reason="sensor_back")
        finally:
            self.agent_lock.release()

    # The egress proxy (T06-4, docs/21 section 9)

    def _start_egress(self) -> None:
        """Boot, after the agent's jail is prepared and before the agent. Never raises: a proxy
        that does not come up is recorded and alerted by ``egress.py``, and the agent waits."""
        if self._egress is None:
            return
        self._egress_closing.clear()
        self._egress_held = False
        self._egress_stopped = False
        self._egress.start(
            EgressHooks(
                record=self._record,
                alert=self._alert,
                back=self._egress_back,
                frozen=self._approvals_frozen,
            )
        )

    def _stop_egress(self, reason: str) -> None:
        """After the agent: the proxy, then its channel. Once per start."""
        if self._egress is None or self._egress_stopped:
            return
        self._egress_stopped = True
        self._egress_closing.set()
        self._egress.stop(reason)

    def decide_hold(
        self, hold_id: str, verdict: str, *, via: str, requested_by: str
    ) -> HoldOutcome:
        """Approve (``verdict="approve"``) or reject a held request: `backtide aprobar` and
        `backtide rechazar` (T10-2), later Telegram and the web. ``via`` is who decides (cli,
        web, telegram), ``requested_by`` the kernel's uid and pid. Never raises."""
        if self._egress is None or not self._serving:
            return HoldOutcome(HoldStatus.UNKNOWN, hold_id)
        try:
            return self._egress.decide(
                hold_id,
                verdict,
                by=via,
                requested_by=str(requested_by)[:MAX_REQUESTER_CHARS],
                frozen=self._approvals_frozen,
            )
        except Exception:
            logger.exception("deciding on a held request failed")
            return HoldOutcome(HoldStatus.FAILED, hold_id)

    def create_batch(self, hold_id: str, kind: str, *, via: str, requested_by: str) -> BatchOutcome:
        """A batch rule made from the open hold ``hold_id`` (T10-4: "todo a este destinatario,
        esta sesión" or "este tipo de acción, 1 h"), which it approves. Like ``decide_hold``:
        nothing while the person's pause is open or a rewind runs. Never raises."""
        if self._egress is None or not self._serving:
            return BatchOutcome(BatchStatus.UNKNOWN, hold_id)
        try:
            return self._egress.create_batch(
                hold_id,
                kind,
                by=via,
                requested_by=str(requested_by)[:MAX_REQUESTER_CHARS],
                frozen=self._approvals_frozen,
            )
        except Exception:
            logger.exception("making a batch rule failed")
            return BatchOutcome(BatchStatus.FAILED, hold_id)

    def batches(self) -> list[dict[str, Any]]:
        """The active batch rules (``/lotes``). Never raises."""
        if self._egress is None or not self._serving:
            return []
        try:
            return self._egress.batches()
        except Exception:
            logger.exception("listing the batch rules failed")
            return []

    def end_batch(self, rule_id: str, *, via: str) -> bool:
        """Revoke a batch rule (``/lotes``). Never raises."""
        if self._egress is None or not self._serving:
            return False
        try:
            return self._egress.end_batch(rule_id, by=via)
        except Exception:
            logger.exception("revoking a batch rule failed")
            return False

    def _approvals_frozen(self) -> bool:
        """Nothing is approved while the person's pause is open or a rewind runs (security
        review of T10-2, B2): a request in flight when they began is held after their
        ``reject_holds``, and a yes would let it out for a frozen agent. Called under the
        channel's gate lock, so it reads without taking ``freeze_lock`` (a set's membership and
        a bool are read whole); the pause opens its reason before it rejects the holds."""
        return "user" in self._pause_reasons or self._rewinding

    def pending_holds(self) -> list[dict[str, Any]]:
        """The held requests waiting for the person (`backtide retenidas`). Never raises."""
        if self._egress is None or not self._serving:
            return []
        try:
            return self._egress.pending()
        except Exception:
            logger.exception("listing the held requests failed")
            return []

    def _reject_holds(self, by: str) -> None:
        if self._egress is None:
            return
        try:
            rejected = self._egress.reject_holds(by)
        except Exception:  # a pause or a rewind never fails for this; the hold expires anyway
            logger.exception("rejecting the held requests failed (%s)", by)
            self._egress.end_batches(by)  # the batches end all the same (review of T10-4, B4)
            return
        if rejected:
            logger.info("%d held requests rejected (%s)", rejected, by)

    def _egress_allows_start(self) -> bool:
        """Without the proxy's hello the agent does not start (docs/21, section 9)."""
        if self._egress is None or self._egress.allows_agent():
            return True
        self._egress_held = True
        event = self._record(
            "system", "agent_start_skipped", details={"reason": "proxy_down"}, risk=1
        )
        self._alert(
            AlertLevel.ERROR,
            "El agente no arranca sin el proxy de salida",
            "Sin el proxy no se puede grabar lo que el agente manda a internet, así que no "
            "arranca. Arrancará en cuanto el proxy vuelva.",
            event,
        )
        return False

    def _egress_lock(self) -> bool:
        """``agent_lock`` for the proxy's hook, unless the service stops first."""
        while not self.agent_lock.acquire(timeout=0.2):
            if self._egress_closing.is_set():
                return False
        if self._egress_closing.is_set():
            self.agent_lock.release()
            return False
        return True

    def _egress_back(self) -> None:
        """The proxy is up again: start the agent it kept stopped, if nothing else holds it
        (a pause decides on its own; so does a stopped service)."""
        if not self._egress_held or not self._egress_lock():
            return
        try:
            if not self._serving or not self._egress_held or self.pause_reasons:
                return
            try:
                running = self._jail.is_running()
            except JailError:
                return
            if running:
                self._egress_held = False
                return
            if [item for item in self._start_verdict() if not _is_warning(item)]:
                return  # the space thread pauses it; `backtide seguir` starts it later
            self._egress_held = False
            self._start_agent(reason="proxy_back")
        finally:
            self.agent_lock.release()

    # Stop and run

    def stop(self) -> None:
        """Stop for good: the agent, then the watcher (which writes what it holds), then the
        service. Parar backtide para al agente. If Docker's stop fails, the agent is killed and
        removed before giving up; if it still runs, ``stop()`` records that, finishes closing
        the watcher and the log, and raises, and calling it again tries the agent once more."""
        self._settle_risk()
        self._sensor_closing.set()  # the sensor's hooks stop waiting for agent_lock
        self._egress_closing.set()  # and so does the proxy's
        with self.agent_lock:
            if self._stopped:
                return
            error = self._stop_agent("service_stop")
            self._stop_egress("service_stop")  # after the agent, whatever its stop did
            if error is None:
                self._stop_sensor("service_stop")  # last: docs/23, agent, proxy, sensor
            if not self._wound_down:
                self._wound_down = True
                self._serving = False
                self._watcher_step("close", self._watcher.close)
                self._record("system", "service_stop", details={"agent_stopped": error is None})
                logging.getLogger(_BRIDGED_LOGGERS).removeHandler(self._bridge)
                self._bridge.close()
                self._flush_risk()
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
                "backtide se para y el agente no se ha podido parar: sigue en marcha. "
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

    def _settle_risk(self) -> None:
        """Answer the events of risk 3 still waiting (alerts only), before the stop."""
        if self._risk is None:
            return
        try:
            self._risk.close()
        except Exception:
            logger.exception("could not settle the answers to dangerous events")

    def _flush_risk(self) -> None:
        """The agent's grace period and the watcher's last dump may have added events of risk 3
        after the responder closed: send what its alert throttle held back."""
        if self._risk is None:
            return
        try:
            self._risk.flush_held()
        except Exception:
            logger.exception("could not flush the alerts held back")

    def take_evidence(self) -> str | None:
        """The id of a new snapshot (reason ``evidence``) that holds the workspace as it is now:
        the evidence of a dangerous event (T08). Always a new one, even if nothing changed: the
        newest periodic snapshot would do as a picture, but retention deletes it in time and
        evidence is kept (a snapshot of an unchanged workspace costs next to nothing). None if it
        cannot be had: the service is not up, a rewind or a stop kept ``agent_lock`` for
        ``EVIDENCE_LOCK_WAIT`` s, or the snapshot failed (recorded and alerted as any failed
        snapshot). Called from the risk thread; never from one that holds ``agent_lock``."""
        if not self.agent_lock.acquire(timeout=EVIDENCE_LOCK_WAIT):
            logger.warning("no evidence snapshot: the agent lock was busy for too long")
            return None
        try:
            if not self._serving:
                return None
            try:
                assessment = self._assess()
            except SnapshotError as error:
                self._cycle_problem("evidence", error)
                return None
            snapshot = self._take(Reason.EVIDENCE, "risk", assessment.workspace, check_space=True)
            return snapshot.id if snapshot is not None else None
        finally:
            self.agent_lock.release()

    def flush_logs(self, timeout: float = 5.0) -> bool:
        """Wait until the log messages bridged so far are in the black box (for tests, and for
        a caller that wants to read the box right after something was logged)."""
        return self._bridge.flush(timeout)

    def run(self, stop: threading.Event, *, control: ControlHook | None = None) -> None:
        """Start, run a cycle every ``cycle_interval`` seconds until ``stop`` is set, and stop.
        The caller sets ``stop`` from its signal handlers.

        ``control`` (the socket of ``backtide rebobinar``) starts once the service is up and is
        closed BEFORE the stop: no new request after that, and a rewind in flight finishes and
        is answered. If it cannot start, the service stops (and so does the agent): without it
        a `backtide rebobinar` would find the lock taken and nobody to ask.

        The space thread and its watchdog (``check_space``, ``check_watchdog``) tick from
        before the boot (they do nothing until the black box is open) until the control socket
        is closed, so a rewind in flight is still watched; they end before the agent is stopped,
        because a freeze in the middle of a `docker stop` would only be undone by it."""
        threads = self._space_threads()
        try:
            for thread in threads:
                thread.start()
            self.start()
            if control is not None:
                control.start()
            while not stop.wait(self._config.cycle_interval):
                try:
                    self.cycle()
                except Exception as error:  # a bug must not end the watch
                    logger.exception("the cycle crashed")
                    self._cycle_problem("crash", error)
        finally:
            try:
                if control is not None:
                    control.close()
            finally:
                try:
                    for thread in threads:
                        thread.close()
                finally:
                    self.stop()

    def _space_threads(self) -> list[Ticker]:
        if self._space is None:
            return []
        return [
            Ticker("backtide-space", self._tick, self.check_space),
            Ticker("backtide-space-guard", self._tick, self.check_watchdog),
        ]

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
            event = self._box.append(
                source, action, target, details=details, risk=risk, snapshot_id=snapshot_id
            )
        except BlackBoxError as error:
            with self._record_failures_lock:
                self._record_failures += 1
                self._bb_streak += 1
                if self._bb_failing_since is None:
                    self._bb_failing_since = self._mono()
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
        with self._record_failures_lock:
            self._bb_streak = 0
            self._bb_failing_since = None
        return event

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
        """The bridge: a WARNING or ERROR of a ``backtide.*`` logger becomes an event and an
        alert."""
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
            if not _still_running(jail, settle=attempt == jail.kill):
                return None
        except JailError as error:
            first_error = first_error or error
    return first_error or JailError("the agent is still running after stop, kill and remove")


HALT_SETTLE = 2.0  # seconds a SIGKILL may take to show in Docker's state
HALT_POLL = 0.1


def _still_running(jail: AgentJail, *, settle: bool) -> bool:
    """Docker's word on whether the agent runs. After a kill, ask for a moment: the state may
    lag the signal, and falling through to ``rm --force`` would delete the container."""
    deadline = time.monotonic() + (HALT_SETTLE if settle else 0.0)
    while jail.is_running():
        if time.monotonic() >= deadline:
            return True
        time.sleep(HALT_POLL)
    return False


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


def _is_warning(item: Violation) -> bool:
    """An early warning (W1, W3) from the gate: told about, never a reason to pause."""
    return item.code.startswith("W")


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


_GROW_REFUSED_TEXT = {
    "agent_running": "el agente no está parado",
    "agent_state_unknown": "no se sabe si el agente está parado",
    "not_a_loop": "el volumen no está montado desde un archivo (un dispositivo loop)",
    "not_the_image": "el dispositivo del volumen no es el archivo configurado",
    "unreadable": "no se han podido leer los tamaños del volumen",
    "ceiling": "superaría el tamaño máximo configurado (max_volume_bytes)",
    "host_space": "al disco del ordenador no le quedaría margen suficiente",
    "already_grown": "ya ha crecido una vez para este rebobinado",
    "blackbox": "no se ha podido grabar en la caja negra, y sin registro no se agranda",
}


def _growth_details(attempt: _RewindAttempt) -> dict[str, Any]:
    """What a rewind_done / rewind_failed says about the growth, if there was one."""
    if attempt.grow is None:
        return {}
    grown = attempt.grow
    details: dict[str, Any] = {"grow": str(grown.status), "retried": attempt.retried}
    if grown.reason is not None:
        details["grow_reason"] = grown.reason
    if grown.step is not None:
        details["grow_step"] = grown.step
    return details


def _mib(size: int | None) -> str:
    return "?" if size is None else f"{size / 1024**2:.0f} MiB"


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
    "EgressProxy",
    "Sensor",
    "SpaceGate",
    "Violation",
    "halt_agent",
]
