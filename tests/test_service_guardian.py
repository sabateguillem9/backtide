"""Guardian with fake pieces: the boot, the stop and the 120 s cycle (docs/19, sections 2 and 3).

Nothing here touches Docker, btrfs or inotify. One ``FakeVolume`` plays the store AND the
Btrfs counters (``ctransid``, ``generation``, lineage) so change detection is tested for real;
the jail and the watcher append to the same call log, so the ORDER of the boot is asserted. The
black box is the real one. A VM test (test_subvolume_info.py) checks that the counters behave
like the fake's.
"""

import logging
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from uuid import UUID

import pytest

from vigia.blackbox import BlackBox, BlackBoxError, Event, create_key
from vigia.jail import JailError
from vigia.jail.openclaw import RewindProblem, UnrewindableConfig
from vigia.notify import Alert, AlertLevel
from vigia.service.config import Secret, ServiceConfig
from vigia.service.guardian import AgentState, CycleResult, FileWatcher, Guardian
from vigia.service.rewind import RewindStatus
from vigia.snapshots import (
    PruneIncomplete,
    Reason,
    RestoreIncomplete,
    RestoreResult,
    Snapshot,
    SnapshotBusy,
    SnapshotError,
    SnapshotNoSpace,
)
from vigia.snapshots.btrfs import SubvolumeInfo

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2


# --- the fakes ---------------------------------------------------------------------------------


class FakeVolume:
    """The store and the Btrfs counters of one workspace, with its snapshots.

    Counters behave like Btrfs's: a write moves ``ctransid`` at once and ``generation`` only on
    a commit (``sync`` or a snapshot); a snapshot copies the ``ctransid`` of its origin and has
    the origin's ``uuid`` as ``parent_uuid``."""

    def __init__(self, tmp_path: Path, clock: Callable[[], datetime], log: list[str]) -> None:
        self.root = tmp_path / "vol"
        self.workspace = self.root / "workspace"
        self.snapshots_dir = self.root / "snapshots"
        self._clock = clock
        self.log = log
        self._next_uuid = 1
        self.txn = 100
        self.dirty = False
        self.workspace_info = SubvolumeInfo(
            treeid=258,
            name="workspace",
            generation=100,
            flags=0,
            uuid=self._uuid(),
            parent_uuid=None,
            ctransid=100,
            otransid=90,
        )
        self.infos: dict[str, SubvolumeInfo] = {}
        self.listed: list[Snapshot] = []
        self.take_error: Exception | None = None
        self.recover_error: Exception | None = None
        self.recovered: list[Snapshot] = []
        self.leftover: SubvolumeInfo | None = None  # an old workspace no snapshot was made of
        self.prune_error: Exception | None = None
        self.pruned: list[Snapshot] = []
        self.workspace_id_error: Exception | None = None
        self.sync_error: Exception | None = None
        self.hide_info_of: set[str] = set()
        # restore(): what goes wrong, and where
        self.restore_error_before: Exception | None = None  # before quiesce (staging, recovery)
        self.swap_error: Exception | None = None  # the swap itself, inside quiesce
        self.incomplete_cause: Exception | None = None  # swapped, undo point not published
        self.during_swap: Callable[[], None] | None = None  # runs inside quiesce, before the swap
        self.workspace_id_error_after_restore: Exception | None = None

    def _uuid(self) -> UUID:
        self._next_uuid += 1
        return UUID(int=self._next_uuid)

    # What the agent does to the workspace

    def write(self) -> None:
        self.workspace_info = _with(self.workspace_info, ctransid=self.workspace_info.ctransid + 1)
        self.dirty = True

    def rewind_to(self, target: Snapshot, *, publish: bool = True) -> Snapshot:
        """What a restore leaves: the old workspace published as pre_restore (a renamed
        subvolume keeps its id, so the undo point has the old workspace's id), a new workspace
        copied from the target (so it has the target's ctransid)."""
        undo = Snapshot(self._clock(), Reason.PRE_RESTORE)
        if publish:
            self._publish(undo, self.workspace_info, treeid=self.workspace_info.treeid)
        else:
            self.leftover = self.workspace_info  # recover() publishes it later
        self.txn += 1
        self.workspace_info = SubvolumeInfo(
            treeid=self.workspace_info.treeid + 1,
            name="workspace",
            generation=self.txn,
            flags=0,
            uuid=self._uuid(),
            parent_uuid=self.infos[target.id].uuid,
            ctransid=self.infos[target.id].ctransid,
            otransid=self.txn,
        )
        self.dirty = False
        return undo

    def snapshot_quietly(self, reason: Reason = Reason.PERIODIC) -> Snapshot:
        """A snapshot that already existed before the test's service started."""
        return self._make_snapshot(reason)

    def _make_snapshot(self, reason: Reason) -> Snapshot:
        snapshot = Snapshot(self._clock(), reason)
        self.txn += 1  # a snapshot commits the transaction
        self.dirty = False
        self.workspace_info = _with(self.workspace_info, generation=self.txn)
        self._publish(snapshot, self.workspace_info, otransid=self.txn)
        return snapshot

    def _publish(
        self,
        snapshot: Snapshot,
        origin: SubvolumeInfo,
        otransid: int = 0,
        treeid: int | None = None,
    ) -> None:
        self.listed.append(snapshot)
        self.infos[snapshot.id] = SubvolumeInfo(
            treeid=treeid if treeid is not None else 1000 + len(self.listed),
            name=snapshot.id,
            generation=origin.generation if not otransid else otransid,
            flags=1,
            uuid=self._uuid(),
            parent_uuid=origin.uuid,
            ctransid=origin.ctransid,
            otransid=otransid or origin.otransid,
        )

    # The SnapshotStore interface

    def init(self) -> None:
        self.log.append("store.init")

    def recover(self) -> list[Snapshot]:
        self.log.append("store.recover")
        if self.recover_error is not None:
            raise self.recover_error
        if self.leftover is not None:  # R3: the old workspace left at the staging name
            origin, self.leftover = self.leftover, None
            snapshot = Snapshot(self._clock(), Reason.RECOVERED)
            self._publish(snapshot, origin, treeid=origin.treeid)
            self.recovered = [*self.recovered, snapshot]
        return self.recovered

    def snapshots(self) -> list[Snapshot]:
        return sorted(self.listed, key=lambda snap: (snap.taken_at, snap.id))

    def take(self, reason: Reason) -> Snapshot:
        self.log.append(f"store.take({reason})")
        if self.take_error is not None:
            raise self.take_error
        return self._make_snapshot(reason)

    def prune(self) -> list[Snapshot]:
        self.log.append("store.prune")
        if self.prune_error is not None:
            raise self.prune_error
        return self.pruned

    def workspace_id(self) -> int:
        if self.workspace_id_error is not None:
            raise self.workspace_id_error
        return self.workspace_info.treeid

    def restore(self, snapshot_id: str, *, quiesce: Callable[[], object]) -> RestoreResult:
        """SnapshotStore.restore's contract: errors before quiesce leave everything as it was;
        quiesce is entered around the swap and always exited, with restore's own error."""
        self.log.append("store.restore")
        target = Snapshot.parse(snapshot_id)
        if target is None or target not in self.listed:
            raise SnapshotError(f"no such snapshot: {snapshot_id}")
        if self.restore_error_before is not None:
            raise self.restore_error_before
        quiesced = quiesce()
        quiesced.__enter__()  # type: ignore[attr-defined]
        try:
            if self.during_swap is not None:
                self.during_swap()
            if self.swap_error is not None:
                raise self.swap_error
            undo = self.rewind_to(target, publish=self.incomplete_cause is None)
            self.log.append(f"store.swap({target.id})")
            if self.incomplete_cause is not None:
                raise RestoreIncomplete(target, self.root / "workspace.restore") from (
                    self.incomplete_cause
                )
            if self.workspace_id_error_after_restore is not None:
                self.workspace_id_error = self.workspace_id_error_after_restore
        except BaseException as error:
            quiesced.__exit__(type(error), error, error.__traceback__)  # type: ignore[attr-defined]
            raise
        quiesced.__exit__(None, None, None)  # type: ignore[attr-defined]
        return RestoreResult(target=target, undo=undo)

    # The btrfs functions the Guardian is given

    def info(self, path: Path) -> SubvolumeInfo:
        if path == self.workspace:
            return self.workspace_info
        if path.parent == self.snapshots_dir and path.name not in self.hide_info_of:
            if path.name in self.infos:
                return self.infos[path.name]
        raise SnapshotError(f"{path} is not a subvolume root")

    def sync(self, path: Path) -> None:
        self.log.append("btrfs.sync")
        if self.sync_error is not None:
            raise self.sync_error
        if self.dirty:
            self.txn += 1
            self.dirty = False
            self.workspace_info = _with(self.workspace_info, generation=self.txn)


def _with(info: SubvolumeInfo, **changes: int) -> SubvolumeInfo:
    values = {**info.__dict__, **changes}
    return SubvolumeInfo(**values)


class FakeJail:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.running = False
        self.created = False
        self.paused = False
        self.start_error: JailError | None = None
        self.ready_error: JailError | None = None
        self.stop_error: JailError | None = None
        self.setup_error: JailError | None = None
        self.config_error: Exception | None = None
        self.pause_error: Exception | None = None
        self.unpause_error: Exception | None = None
        self.kill_error: JailError | None = None
        self.remove_error: JailError | None = None
        self.stops_anyway = False  # a stop or kill that fails (a timeout) but did stop it
        self.on_stop: Callable[[], None] | None = None  # runs in the middle of `docker stop`
        self.on_wait_ready: Callable[[], None] | None = None  # ... and of `wait_ready`

    def ensure_network(self) -> None:
        self.log.append("jail.ensure_network")
        if self.setup_error is not None:
            raise self.setup_error

    def prepare_workspace(self) -> None:
        self.log.append("jail.prepare_workspace")

    def write_config(self) -> None:
        self.log.append("jail.write_config")
        if self.config_error is not None:
            raise self.config_error

    def create(self) -> None:
        self.log.append("jail.create")
        self.created = True

    def exists(self) -> bool:
        return self.created or self.running

    def is_running(self) -> bool:
        return self.running

    def start(self) -> None:
        self.log.append("jail.start")
        if self.start_error is not None:
            raise self.start_error
        self.running = True

    def wait_ready(self) -> None:
        self.log.append("jail.wait_ready")
        if self.on_wait_ready is not None:
            self.on_wait_ready()
        if self.ready_error is not None:
            raise self.ready_error
        if self.paused:
            raise JailError("the agent is frozen: it cannot get ready")

    def stop(self) -> None:
        self.log.append("jail.stop")
        if self.on_stop is not None:
            self.on_stop()
        if self.stop_error is not None:
            if self.stops_anyway:
                self.running = False
                self.paused = False
            raise self.stop_error
        self.running = False
        self.paused = False

    def pause(self) -> None:
        self.log.append("jail.pause")
        if self.pause_error is not None:
            raise self.pause_error
        self.paused = True

    def unpause(self) -> None:
        self.log.append("jail.unpause")
        if self.unpause_error is not None:
            raise self.unpause_error
        self.paused = False

    def is_paused(self) -> bool:
        return self.running and self.paused

    def kill(self) -> None:
        self.log.append("jail.kill")
        if self.kill_error is not None:
            if self.stops_anyway:
                self.running = False
                self.paused = False
            raise self.kill_error
        self.running = False
        self.paused = False

    @contextmanager
    def quiesce(
        self, start_if: Callable[[BaseException | None], bool] | None = None
    ) -> Iterator[None]:
        """AgentJail.quiesce's contract: a frozen agent is killed, a running one stopped; on
        the way out ``start_if`` (given the body's exception) decides whether it starts."""
        was_running, was_paused = self.running, self.paused
        if was_running:
            try:
                self.kill() if was_paused else self.stop()
                if self.running:
                    raise JailError("still running after being stopped")
            except JailError as error:
                if not self.running and start_if is not None and start_if(error):
                    self.start()
                    self.wait_ready()
                raise
        body_error: BaseException | None = None
        try:
            yield
        except BaseException as error:
            body_error = error
            raise
        finally:
            start = (was_running and not was_paused) if start_if is None else start_if(body_error)
            if start:
                self.start()
                self.wait_ready()

    def remove(self) -> None:
        self.log.append("jail.remove")
        if self.remove_error is not None:
            raise self.remove_error
        self.running = False
        self.paused = False
        self.created = False

    def cannot_stop(self) -> None:
        """Stop, kill and rm --force all fail."""
        self.stop_error = JailError("docker stop failed")
        self.kill_error = JailError("docker kill failed")
        self.remove_error = JailError("docker rm failed")

    def can_stop_again(self) -> None:
        self.stop_error = self.kill_error = self.remove_error = None


class FakeWatcher:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.current: str | None = None
        self.arm_result = True
        self.arm_error: Exception | None = None
        self.barrier_error_before: Exception | None = None  # the watcher breaks before take()
        self.barrier_error_after: Exception | None = None  # ... or after it
        self.step_error: Exception | None = None  # rearm / report_unwatched / close
        self.suspend_error: Exception | None = None  # suspended() never raises, but if it did
        self.resume_error: Exception | None = None

    def arm(self, current: str | None = None) -> bool:
        self.log.append(f"watcher.arm({current})")
        if self.arm_error is not None:
            raise self.arm_error
        self.current = current
        return self.arm_result

    def barrier(self, take: Callable[[], Snapshot]) -> Snapshot:
        self.log.append("watcher.barrier>")
        if self.barrier_error_before is not None:
            raise self.barrier_error_before
        snapshot = take()
        if self.barrier_error_after is not None:
            raise self.barrier_error_after
        self.log.append("watcher.barrier<")
        self.current = snapshot.id
        return snapshot

    def rearm_if_moved(self, workspace_id: int) -> bool:
        self.log.append(f"watcher.rearm_if_moved({workspace_id})")
        if self.step_error is not None:
            raise self.step_error
        return False

    def report_unwatched(self) -> bool:
        self.log.append("watcher.report_unwatched")
        if self.step_error is not None:
            raise self.step_error
        return False

    def close(self) -> None:
        self.log.append("watcher.close")
        if self.step_error is not None:
            raise self.step_error

    @contextmanager
    def suspended(self, new_current: str | None = None) -> Iterator[None]:
        self.log.append("watcher.suspend")
        if self.suspend_error is not None:
            raise self.suspend_error
        try:
            yield
        finally:
            self.log.append(f"watcher.rearm({new_current})")
            self.current = new_current
            if self.resume_error is not None:
                raise self.resume_error


class Alerts:
    def __init__(self) -> None:
        self.sent: list[Alert] = []

    def submit(self, alert: Alert) -> bool:
        self.sent.append(alert)
        return True

    def titled(self, text: str) -> list[Alert]:
        return [alert for alert in self.sent if text in alert.title]


class FlakyBox:
    """The real black box, with switches to make it fail."""

    def __init__(self, box: BlackBox) -> None:
        self._box = box
        self.open_error: BlackBoxError | None = None
        self.append_error: BlackBoxError | None = None

    def open(self) -> BlackBox:
        if self.open_error is not None:
            raise self.open_error
        return self._box.open()

    def append(self, *args: object, **kwargs: object) -> Event:
        if self.append_error is not None:
            raise self.append_error
        return self._box.append(*args, **kwargs)  # type: ignore[arg-type]

    def head(self) -> tuple[int, str] | None:
        return self._box.head()

    def events(self, **filters: object) -> list[Event]:
        return self._box.events(**filters)  # type: ignore[arg-type]

    def close(self) -> None:
        self._box.close()


@dataclass
class Violation:
    code: str
    message: str
    reason: str = "space"


@dataclass
class World:
    config: ServiceConfig
    volume: FakeVolume
    jail: FakeJail
    watcher: FakeWatcher
    box: FlakyBox
    alerts: Alerts
    log: list[str]
    guardian: Guardian
    mono: list[float] = field(default_factory=lambda: [1000.0])
    violations: list[Violation] = field(default_factory=list)
    synced: list[bool] = field(default_factory=lambda: [True])

    def advance(self, seconds: float) -> None:
        self.mono[0] += seconds

    def events(self, action: str | None = None) -> list[Event]:
        found = self.box.events()
        return [event for event in found if action is None or event.action == action]

    def only(self, action: str) -> Event:
        (event,) = self.events(action)
        return event

    def actions(self) -> list[str]:
        return [f"{event.source}/{event.action}" for event in self.box.events()]


@pytest.fixture(autouse=True)
def no_leftover_bridge() -> Iterator[None]:
    yield
    vigia_logger = logging.getLogger("vigia")
    for handler in list(vigia_logger.handlers):
        if type(handler).__name__ == "LogBridge":
            vigia_logger.removeHandler(handler)


@pytest.fixture
def world(tmp_path: Path, clock: Callable[[], datetime]) -> Iterator[World]:
    log: list[str] = []
    volume = FakeVolume(tmp_path, clock, log)
    jail = FakeJail(log)
    watcher = FakeWatcher(log)
    alerts = Alerts()
    key = create_key(tmp_path / "bb.key")
    box = FlakyBox(BlackBox(tmp_path / "bb.db", key, checkpoint_path=tmp_path / "bb.checkpoint"))
    (tmp_path / "state").mkdir(mode=0o700)
    config = ServiceConfig(
        state_dir=tmp_path / "state",
        volume=tmp_path / "vol",
        gateway_token=Secret(TOKEN),
        prune_interval=600.0,
    )
    world: World

    def gate() -> list[Violation]:
        log.append("space.evaluate")
        return list(world.violations)

    guardian = Guardian(
        config,
        store=volume,  # type: ignore[arg-type]
        jail=jail,  # type: ignore[arg-type]
        blackbox=box,  # type: ignore[arg-type]
        watcher=watcher,
        alerts=alerts,
        space=gate,
        clock=clock,
        monotonic=lambda: world.mono[0],
        info=volume.info,
        sync=volume.sync,
        clock_synced=lambda: world.synced[0],
    )
    world = World(config, volume, jail, watcher, box, alerts, log, guardian)
    yield world
    box.close()


def index(log: list[str], entry: str) -> int:
    return log.index(entry)


# --- the watcher interface the Guardian assumes ------------------------------------------------


def test_the_fake_watcher_satisfies_the_protocol() -> None:
    watcher: FileWatcher = FakeWatcher([])
    assert watcher.arm("x") is True


# --- boot --------------------------------------------------------------------------------------


def test_a_first_boot_does_everything_in_the_documented_order(world: World) -> None:
    world.guardian.start()
    (first,) = world.volume.listed
    assert world.log == [
        "store.init",
        "store.recover",
        "jail.ensure_network",
        "jail.prepare_workspace",
        "jail.write_config",
        "jail.create",
        "btrfs.sync",  # the space check always reads a committed volume
        "space.evaluate",
        "watcher.barrier>",
        "store.take(periodic)",
        "watcher.barrier<",
        f"watcher.arm({first.id})",
        "jail.start",
        "jail.wait_ready",
    ]
    assert world.guardian.agent_state is AgentState.RUNNING
    assert world.actions() == ["system/service_start", "snapshot/take", "system/agent_start"]


def test_the_startup_snapshot_is_taken_with_the_agent_stopped_and_before_arming(
    world: World,
) -> None:
    world.guardian.start()
    arm = index(world.log, f"watcher.arm({world.volume.listed[0].id})")
    assert index(world.log, "store.take(periodic)") < arm < index(world.log, "jail.start")
    event = world.only("take")
    assert event.snapshot_id == world.volume.listed[0].id
    assert event.details["trigger"] == "startup"
    assert event.details["workspace_id"] == 258
    assert event.details["reason"] == "periodic"


def test_the_service_start_event_carries_the_version(world: World) -> None:
    world.guardian.start()
    assert world.only("service_start").details["version"]


def test_an_agent_found_running_is_stopped_first_and_the_gap_is_recorded(world: World) -> None:
    world.jail.running = True
    world.guardian.start()
    # Killed, not stopped: `docker stop` would give it up to 30 s more of unwatched running.
    assert world.log[0] == "jail.kill"
    assert "jail.stop" not in world.log
    assert index(world.log, "jail.kill") < index(world.log, "store.init")
    unsupervised = world.only("agent_stop")
    assert unsupervised.details == {"reason": "unsupervised"}
    assert unsupervised.risk == 2
    (alert,) = world.alerts.titled("sin vigilancia")
    assert alert.level is AlertLevel.ERROR
    assert alert.event_seq == unsupervised.seq
    assert world.jail.running  # and it is started again, watched
    assert world.actions().index("system/agent_stop") < world.actions().index("system/agent_start")


def test_an_agent_that_cannot_be_stopped_stops_the_boot(world: World) -> None:
    world.jail.running = True
    world.jail.cannot_stop()
    with pytest.raises(JailError):
        world.guardian.start()
    assert "store.init" not in world.log
    failed = world.only("agent_stop_failed")
    assert failed.risk == 3
    assert world.alerts.titled("No se pudo parar")
    assert world.only("service_start_failed")


def test_without_a_black_box_nothing_starts(world: World) -> None:
    world.box.open_error = BlackBoxError("disk full")
    with pytest.raises(BlackBoxError, match="disk full"):
        world.guardian.start()
    assert world.log == []
    assert world.alerts.titled("caja negra")


def test_without_a_black_box_a_running_agent_is_stopped(world: World) -> None:
    world.jail.running = True
    world.box.open_error = BlackBoxError("disk full")
    with pytest.raises(BlackBoxError):
        world.guardian.start()
    assert world.log == ["jail.kill"]  # nobody watches it: no SIGTERM grace period
    assert not world.jail.running


def test_without_a_black_box_and_an_agent_that_will_not_stop_the_error_says_both(
    world: World,
) -> None:
    world.jail.running = True
    world.jail.cannot_stop()
    world.box.open_error = BlackBoxError("disk full")
    with pytest.raises(BlackBoxError) as raised:
        world.guardian.start()
    assert any("docker kill failed" in note for note in raised.value.__notes__)


def test_a_failing_boot_step_is_recorded_and_raised(world: World) -> None:
    world.jail.setup_error = JailError("network is unsafe")
    with pytest.raises(JailError, match="unsafe"):
        world.guardian.start()
    failed = world.only("service_start_failed")
    assert "network is unsafe" in failed.details["error"]
    assert "jail.start" not in world.log
    assert world.guardian.agent_state is AgentState.STOPPED


def unrewindable() -> UnrewindableConfig:
    return UnrewindableConfig(
        [
            RewindProblem("channels.whatsapp", "its session cannot be rewound"),
            RewindProblem("channels.telegram.dmPolicy", "open to anyone after a rewind"),
        ]
    )


def test_an_unrewindable_config_stops_the_boot_with_its_notice(world: World) -> None:
    error = unrewindable()
    world.jail.config_error = error
    with pytest.raises(UnrewindableConfig) as raised:
        world.guardian.start()
    assert raised.value is error  # the caller prints error.notice
    assert "jail.create" not in world.log
    assert "jail.start" not in world.log
    assert world.guardian.agent_state is AgentState.STOPPED
    failed = world.only("service_start_failed")
    assert failed.risk == 2
    assert failed.details["reason"] == "unrewindable_config"
    assert failed.details["problems"] == ["channels.whatsapp", "channels.telegram.dmPolicy"]


def test_an_unrewindable_config_alerts_with_the_spanish_notice_after_recording(
    world: World,
) -> None:
    error = unrewindable()
    world.jail.config_error = error
    with pytest.raises(UnrewindableConfig):
        world.guardian.start()
    (alert,) = world.alerts.titled("configuración")
    assert alert.level is AlertLevel.ERROR
    assert alert.body == error.notice
    assert alert.event_seq == world.only("service_start_failed").seq
    assert not world.jail.running


def test_an_unrewindable_config_with_an_agent_found_running_leaves_nothing_running(
    world: World,
) -> None:
    world.jail.running = True  # the service died before: the agent is stopped first anyway
    world.jail.config_error = unrewindable()
    with pytest.raises(UnrewindableConfig):
        world.guardian.start()
    assert not world.jail.running
    assert world.only("agent_stop").details == {"reason": "unsupervised"}


def test_stopping_after_an_unrewindable_config_is_quiet(world: World) -> None:
    world.jail.config_error = unrewindable()
    with pytest.raises(UnrewindableConfig):
        world.guardian.start()
    before = world.actions()
    world.guardian.stop()  # what Guardian.run does in its finally
    assert world.actions() == before


def test_recovered_leftovers_are_recorded(world: World) -> None:
    leftover = world.volume.snapshot_quietly(Reason.RECOVERED)
    world.volume.recovered = [leftover]
    world.guardian.start()
    event = world.only("recovered")
    assert (event.source, event.risk, event.snapshot_id) == ("snapshot", 1, leftover.id)
    assert event.target == leftover.id


def test_a_failed_recovery_is_recorded_and_alerted_and_the_boot_goes_on(world: World) -> None:
    world.volume.recover_error = SnapshotNoSpace("no room to publish")
    world.guardian.start()
    failed = world.only("recover_failed")
    assert failed.risk == 2
    assert failed.details["no_space"] is True
    assert world.alerts.titled("interrumpida")
    assert world.guardian.agent_state is AgentState.RUNNING


def test_no_startup_snapshot_when_nothing_changed_since_the_reference(world: World) -> None:
    reference = world.volume.snapshot_quietly()
    world.guardian.start()
    assert "store.take(periodic)" not in world.log
    assert f"watcher.arm({reference.id})" in world.log  # changes point to the reference
    assert world.guardian.agent_state is AgentState.RUNNING


def test_a_workspace_that_changed_while_the_service_was_down_is_recorded_and_snapshotted(
    world: World,
) -> None:
    reference = world.volume.snapshot_quietly()
    world.volume.write()
    world.guardian.start()
    dropped = world.only("dropped")
    assert (dropped.source, dropped.risk) == ("file", 1)
    assert dropped.details["reason"] == "watcher_down"
    assert dropped.details["since"] < dropped.details["until"]
    assert dropped.snapshot_id == reference.id  # the point that undoes it
    assert "store.take(periodic)" in world.log
    assert world.actions().index("file/dropped") < world.actions().index("snapshot/take")


def test_a_fresh_workspace_without_any_reference_records_no_downtime(world: World) -> None:
    world.guardian.start()
    assert world.events("dropped") == []


def test_a_watcher_that_could_not_arm_does_not_stop_the_agent(world: World) -> None:
    world.watcher.arm_result = False
    world.guardian.start()
    assert world.guardian.agent_state is AgentState.RUNNING
    (alert,) = world.alerts.titled("vigilante de archivos")
    assert alert.level is AlertLevel.ERROR


def test_a_watcher_that_raises_when_arming_is_recorded_and_the_agent_still_starts(
    world: World,
) -> None:
    world.watcher.arm_error = RuntimeError("inotify exploded")
    world.guardian.start()
    failed = world.only("watcher_failed")
    assert failed.risk == 2
    assert "inotify exploded" in failed.details["error"]
    assert world.guardian.agent_state is AgentState.RUNNING
    assert world.alerts.titled("vigilante de archivos")


def test_a_standing_space_condition_keeps_the_agent_from_starting(world: World) -> None:
    world.violations.append(Violation("P5", "el workspace no tiene tope"))
    world.guardian.start()
    assert "jail.start" not in world.log
    assert "jail.pause" not in world.log  # nothing running to freeze
    assert world.guardian.agent_state is AgentState.STOPPED
    assert world.guardian.pause_reasons == {"space"}
    pause = world.only("space_pause")
    assert pause.details["conditions"] == ["P5"]
    assert pause.details["frozen"] is False
    (alert,) = world.alerts.titled("no arranca")
    assert "no tiene tope" in alert.body
    assert world.only("service_start")  # the service itself is up


@pytest.mark.parametrize(
    ("error", "quota"),
    [
        pytest.param(JailError("docker start failed: Disk quota exceeded"), True, id="quota"),
        pytest.param(JailError("docker start failed: no such file"), False, id="other"),
    ],
)
def test_an_agent_that_fails_to_start_is_recorded_and_the_service_stays_up(
    world: World, error: JailError, quota: bool
) -> None:
    world.jail.start_error = error
    world.guardian.start()  # does not raise
    failed = world.only("agent_start_failed")
    assert failed.risk == 2
    assert failed.details["quota"] is quota
    assert world.guardian.agent_state is AgentState.STOPPED
    (alert,) = world.alerts.titled("no ha arrancado")
    assert ("tope de espacio" in alert.body) is quota
    assert alert.event_seq == failed.seq
    assert "agent_start" not in [event.action for event in world.events()]


def test_an_agent_that_never_gets_ready_is_stopped_and_recorded(world: World) -> None:
    world.jail.ready_error = JailError("not ready after 120 s")
    world.guardian.start()
    assert world.only("agent_start_failed")
    assert world.log[-1] == "jail.stop"  # it was running but not ready: do not leave it
    assert not world.jail.running


# --- stop --------------------------------------------------------------------------------------


def test_stopping_the_service_stops_the_agent_then_flushes_the_watcher(world: World) -> None:
    world.guardian.start()
    world.log.clear()
    world.guardian.stop()
    assert world.log == ["jail.stop", "watcher.close"]
    assert not world.jail.running
    assert world.guardian.agent_state is AgentState.STOPPED
    assert world.actions()[-2:] == ["system/agent_stop", "system/service_stop"]
    assert world.only("agent_stop").details == {"reason": "service_stop"}
    assert world.only("agent_stop").risk == 0


def test_stop_is_idempotent(world: World) -> None:
    world.guardian.start()
    world.guardian.stop()
    world.log.clear()
    world.guardian.stop()
    assert world.log == []
    assert len(world.events("service_stop")) == 1


def test_stop_with_the_agent_already_stopped_still_closes_the_watcher(world: World) -> None:
    world.jail.start_error = JailError("quota")
    world.guardian.start()
    world.log.clear()
    world.guardian.stop()
    assert world.log == ["watcher.close"]
    assert world.events("agent_stop") == []
    assert world.events("service_stop")


def test_stop_falls_back_to_kill_when_docker_stop_fails(world: World) -> None:
    world.guardian.start()
    world.jail.stop_error = JailError("docker stop timed out")
    world.log.clear()
    world.guardian.stop()  # does not raise: the kill worked
    assert world.log == ["jail.stop", "jail.kill", "watcher.close"]
    assert not world.jail.running
    assert world.guardian.agent_state is AgentState.STOPPED
    assert world.only("agent_stop").details == {"reason": "service_stop"}


def test_stop_falls_back_to_removing_the_container(world: World) -> None:
    world.guardian.start()
    world.jail.stop_error = JailError("docker stop timed out")
    world.jail.kill_error = JailError("docker kill failed")
    world.guardian.stop()
    assert world.log[-3:] == ["jail.kill", "jail.remove", "watcher.close"]
    assert not world.jail.running


def test_an_agent_that_will_not_die_is_recorded_and_stop_can_be_retried(world: World) -> None:
    world.guardian.start()
    world.jail.cannot_stop()
    with pytest.raises(JailError, match="docker stop failed"):
        world.guardian.stop()
    failed = world.only("agent_stop_failed")
    assert failed.risk == 3
    assert world.guardian.agent_state is AgentState.RUNNING  # it is: do not claim otherwise
    (alert,) = world.alerts.titled("No se pudo parar")
    assert "sigue en marcha" in alert.body
    assert alert.event_seq == failed.seq
    # The watcher is closed and the service is wound down, but honestly: agent_stopped = False.
    assert world.only("service_stop").details == {"agent_stopped": False}
    assert "watcher.close" in world.log

    world.jail.can_stop_again()
    world.log.clear()
    world.guardian.stop()  # the second try works...
    assert not world.jail.running
    assert world.log == ["jail.stop"]  # ...without closing everything again
    assert len(world.events("service_stop")) == 1
    world.guardian.stop()  # and now it is a no-op
    assert world.log == ["jail.stop"]


def test_a_watcher_that_fails_to_close_does_not_hide_the_service_stop(world: World) -> None:
    world.guardian.start()
    world.watcher.step_error = RuntimeError("close broke")
    world.guardian.stop()
    assert world.only("watcher_failed").details["step"] == "close"
    assert world.events("service_stop")


# --- the cycle ---------------------------------------------------------------------------------


@pytest.fixture
def running(world: World) -> World:
    world.guardian.start()
    world.log.clear()
    return world


def test_no_change_means_no_snapshot(running: World) -> None:
    result = running.guardian.cycle()
    assert not result.changed
    assert result.snapshot is None
    assert not any(entry.startswith("store.take") for entry in running.log)
    assert "btrfs.sync" in running.log  # it committed and looked again before saying "no change"
    assert running.watcher.current == running.volume.listed[0].id


def test_a_change_makes_a_snapshot_through_the_barrier(running: World) -> None:
    previous = running.volume.listed[-1]
    running.volume.write()
    result = running.guardian.cycle()
    assert result.changed
    assert result.snapshot is not None
    assert result.snapshot != previous
    assert running.log[-3:] == ["watcher.barrier>", "store.take(periodic)", "watcher.barrier<"]
    assert running.watcher.current == result.snapshot.id
    event = running.events("take")[-1]
    assert event.snapshot_id == result.snapshot.id
    assert event.details["trigger"] == "cycle"


def test_a_cycle_after_a_snapshot_with_no_writes_in_between_sees_nothing(running: World) -> None:
    running.volume.write()
    assert running.guardian.cycle().snapshot is not None
    assert not running.guardian.cycle().changed


def test_unwatched_folders_are_reported_before_the_snapshot_in_every_cycle_with_changes(
    running: World,
) -> None:
    running.volume.write()
    running.guardian.cycle()
    entries = [e for e in running.log if e.startswith(("watcher.report", "store.take"))]
    assert entries == ["watcher.report_unwatched", "store.take(periodic)"]
    running.log.clear()
    running.guardian.cycle()  # nothing changed
    assert "watcher.report_unwatched" not in running.log


def test_every_cycle_asks_the_watcher_to_rearm_if_the_workspace_moved(running: World) -> None:
    running.guardian.cycle()
    assert running.log[0] == "watcher.rearm_if_moved(258)"


def test_the_reference_follows_the_lineage_not_the_newest_snapshot(running: World) -> None:
    # After a rewind the newest snapshot is the pre_restore of the OLD workspace: comparing with
    # it would see a change that is not there (or hide one that is).
    target = running.volume.listed[0]
    running.volume.write()
    running.guardian.cycle()
    running.volume.rewind_to(target)
    assert running.volume.snapshots()[-1].reason == Reason.PRE_RESTORE
    result = running.guardian.cycle()
    assert not result.changed
    running.volume.write()
    assert running.guardian.cycle().changed


def test_a_space_condition_stops_the_snapshot_and_freezes_the_agent(running: World) -> None:
    running.volume.write()
    running.violations.append(Violation("P3", "el uso pasa del tope", "space"))
    result = running.guardian.cycle()
    assert result.changed
    assert result.snapshot is None
    assert not any(entry.startswith("store.take") for entry in running.log)
    assert running.jail.paused
    assert running.guardian.agent_state is AgentState.FROZEN
    assert running.guardian.pause_reasons == {"space"}
    pause = running.only("space_pause")
    assert (pause.risk, pause.details["conditions"], pause.details["frozen"]) == (2, ["P3"], True)
    (alert,) = running.alerts.titled("pausado")
    assert alert.event_seq == pause.seq


def test_the_space_check_comes_after_a_sync(running: World) -> None:
    running.volume.write()
    running.guardian.cycle()
    sync = index(running.log, "btrfs.sync")
    assert sync < index(running.log, "space.evaluate") < index(running.log, "watcher.barrier>")


def test_a_black_box_condition_freezes_with_its_own_reason(running: World) -> None:
    running.volume.write()
    running.violations.append(Violation("P7", "no se puede grabar", "blackbox"))
    running.guardian.cycle()
    assert running.guardian.pause_reasons == {"blackbox"}


def test_a_standing_condition_does_not_freeze_twice(running: World) -> None:
    running.volume.write()
    running.violations.append(Violation("P1", "metadatos bajos"))
    running.guardian.cycle()
    running.guardian.cycle()
    assert running.log.count("jail.pause") == 1


def test_snapshot_busy_is_retried_and_alerted_only_after_three_in_a_row(running: World) -> None:
    running.volume.write()
    running.volume.take_error = SnapshotBusy("lock held")
    for _ in range(2):
        assert running.guardian.cycle().snapshot is None
    assert running.alerts.sent == []
    running.guardian.cycle()
    (alert,) = running.alerts.titled("instantáneas")
    assert alert.level is AlertLevel.WARNING
    assert running.only("busy").details["consecutive"] == 3
    running.guardian.cycle()
    assert len(running.alerts.sent) == 1  # not again on the 4th

    running.volume.take_error = None
    assert running.guardian.cycle().snapshot is not None  # the next cycle succeeds


def test_a_busy_streak_is_reset_by_a_success(running: World) -> None:
    running.volume.write()
    running.volume.take_error = SnapshotBusy("lock held")
    running.guardian.cycle()
    running.guardian.cycle()
    running.volume.take_error = None
    running.guardian.cycle()  # success: streak over
    running.volume.write()
    running.volume.take_error = SnapshotBusy("lock held")
    running.guardian.cycle()
    running.guardian.cycle()
    assert running.alerts.sent == []


def test_no_space_for_a_snapshot_is_recorded_alerted_and_retried(running: World) -> None:
    running.volume.write()
    running.volume.take_error = SnapshotNoSpace("ENOSPC")
    result = running.guardian.cycle()
    assert result.snapshot is None
    failed = running.only("take_failed")
    assert (failed.risk, failed.details["no_space"]) == (2, True)
    (alert,) = running.alerts.titled("No hay espacio")
    assert alert.level is AlertLevel.ERROR
    running.guardian.cycle()
    assert len(running.alerts.titled("No hay espacio")) == 1  # throttled
    assert len(running.events("take_failed")) == 2  # but every failure is on record
    running.volume.take_error = None
    assert running.guardian.cycle().snapshot is not None


def test_another_snapshot_error_is_recorded_and_alerted(running: World) -> None:
    running.volume.write()
    running.volume.take_error = SnapshotError("workspace is not a subvolume")
    running.guardian.cycle()
    assert running.only("take_failed").details["no_space"] is False
    assert running.alerts.titled("No se pudo hacer")


def test_a_failing_sync_counts_as_a_change(running: World) -> None:
    running.guardian._space = None  # noqa: SLF001 - no space gate in this test
    running.volume.sync_error = SnapshotError("sync failed")
    result = running.guardian.cycle()
    assert result.changed  # cannot tell: a false positive only costs a snapshot
    assert result.snapshot is not None


def test_an_unreadable_snapshot_is_skipped_when_looking_for_the_reference(
    running: World, caplog: pytest.LogCaptureFixture
) -> None:
    other = running.volume.snapshot_quietly()
    running.volume.hide_info_of.add(other.id)  # pruned meanwhile, say
    with caplog.at_level(logging.WARNING):
        result = running.guardian.cycle()
    assert result.changed is True  # the reference is gone, so be safe
    assert any(other.id in record.getMessage() for record in caplog.records)


def test_a_workspace_that_cannot_be_read_is_recorded_not_raised(running: World) -> None:
    running.volume.workspace_id_error = SnapshotError("workspace is missing")
    result = running.guardian.cycle()
    assert not result.changed
    assert running.only("cycle_failed").details["step"] == "workspace_id"
    assert running.alerts.titled("ciclo")


def test_a_watcher_that_breaks_before_the_snapshot_does_not_stop_the_snapshots(
    running: World,
) -> None:
    running.volume.write()
    running.watcher.barrier_error_before = RuntimeError("drain failed")
    result = running.guardian.cycle()
    assert result.snapshot is not None  # taken without the barrier
    assert running.only("watcher_failed").details["step"] == "barrier"
    assert running.events("take")[-1].snapshot_id == result.snapshot.id


def test_a_watcher_that_breaks_after_the_snapshot_keeps_that_snapshot(running: World) -> None:
    running.volume.write()
    running.watcher.barrier_error_after = RuntimeError("settle failed")
    taken_before = len(running.volume.listed)
    result = running.guardian.cycle()
    assert result.snapshot is not None
    assert len(running.volume.listed) == taken_before + 1  # exactly one, not two
    assert running.only("watcher_failed")


def test_a_watcher_that_raises_in_every_step_never_stops_the_cycle(running: World) -> None:
    running.volume.write()
    running.watcher.step_error = RuntimeError("everything broke")
    assert running.guardian.cycle().snapshot is not None
    steps = {event.details["step"] for event in running.events("watcher_failed")}
    assert steps == {"rearm", "report_unwatched"}
    assert len(running.alerts.titled("vigilante")) == 2  # one per step, not per event


# --- pruning -----------------------------------------------------------------------------------


def test_prune_is_not_run_before_it_is_due(running: World) -> None:
    running.guardian.cycle()
    assert "store.prune" not in running.log
    running.advance(599)
    running.guardian.cycle()
    assert "store.prune" not in running.log


def test_prune_runs_every_ten_minutes_with_a_synchronised_clock(running: World) -> None:
    old = running.volume.listed[0]
    running.volume.pruned = [old]
    running.advance(600)
    result = running.guardian.cycle()
    assert result.pruned == (old,)
    event = running.only("prune")
    assert event.details["deleted"] == [old.id]
    assert (event.details["deleted_count"], event.risk) == (1, 0)
    running.log.clear()
    running.advance(300)
    running.guardian.cycle()
    assert "store.prune" not in running.log
    running.advance(300)
    running.guardian.cycle()
    assert "store.prune" in running.log


def test_a_prune_that_deletes_nothing_leaves_no_event(running: World) -> None:
    running.advance(600)
    assert running.guardian.cycle().pruned == ()
    assert running.events("prune") == []


def test_no_prune_without_a_synchronised_clock(running: World) -> None:
    running.synced[0] = False
    running.advance(600)
    result = running.guardian.cycle()
    assert result.pruned is None
    assert "store.prune" not in running.log
    assert running.alerts.sent == []  # not yet 24 h
    running.advance(600)
    running.guardian.cycle()
    assert "store.prune" not in running.log


def test_a_clock_that_stays_unsynchronised_for_a_day_alerts_once_a_day(running: World) -> None:
    running.synced[0] = False
    running.advance(24 * 3600)
    running.guardian.cycle()
    (alert,) = running.alerts.titled("reloj")
    assert alert.level is AlertLevel.WARNING
    skipped = running.only("prune_skipped")
    assert (skipped.details["reason"], skipped.risk) == ("clock_unsynced", 1)
    running.advance(3600)
    running.guardian.cycle()
    assert len(running.alerts.titled("reloj")) == 1  # not every cycle
    running.advance(24 * 3600)
    running.guardian.cycle()
    assert len(running.alerts.titled("reloj")) == 2


def test_pruning_resumes_when_the_clock_syncs(running: World) -> None:
    running.synced[0] = False
    running.advance(600)
    running.guardian.cycle()
    running.synced[0] = True
    running.advance(120)
    running.guardian.cycle()
    assert "store.prune" in running.log


def test_a_clock_that_cannot_be_read_counts_as_unsynchronised(running: World) -> None:
    def broken() -> bool:
        raise OSError("no adjtimex")

    running.guardian._clock_synced = broken  # noqa: SLF001
    running.advance(600)
    assert running.guardian.cycle().pruned is None
    assert "store.prune" not in running.log


def test_an_incomplete_prune_is_recorded_with_what_failed(running: World) -> None:
    old = running.volume.listed[0]
    stuck = Snapshot(old.taken_at.replace(year=2025), Reason.PERIODIC)
    running.volume.prune_error = PruneIncomplete([old], [stuck])
    running.advance(600)
    result = running.guardian.cycle()
    assert result.pruned == (old,)
    event = running.only("prune")
    assert event.risk == 2
    assert event.details["failed"] == [stuck.id]
    assert running.alerts.titled("borrar instantáneas")


def test_a_prune_that_finds_the_volume_busy_is_retried_next_cycle(running: World) -> None:
    running.volume.prune_error = SnapshotBusy("lock held")
    running.advance(600)
    assert running.guardian.cycle().pruned is None
    running.volume.prune_error = None
    running.guardian.cycle()  # still due, no need to wait another ten minutes
    assert running.log.count("store.prune") == 2


def test_a_prune_error_is_recorded_not_raised(running: World) -> None:
    running.volume.prune_error = SnapshotError("cannot list snapshots")
    running.advance(600)
    running.guardian.cycle()
    assert running.only("prune_failed").risk == 2


# --- the black box failing ---------------------------------------------------------------------


def test_a_black_box_that_fails_mid_cycle_is_logged_alerted_and_does_not_stop_the_cycle(
    running: World, caplog: pytest.LogCaptureFixture
) -> None:
    running.volume.write()
    running.box.append_error = BlackBoxError("disk full")
    with caplog.at_level(logging.ERROR):
        result = running.guardian.cycle()
    assert result.snapshot is not None  # the snapshot is what matters
    assert any("black box" in record.getMessage() for record in caplog.records)
    (alert,) = running.alerts.titled("caja negra")
    assert alert.event_seq is None  # there is no event to cite
    running.guardian.cycle()
    assert len(running.alerts.titled("caja negra")) == 1  # throttled


# --- the log bridge ----------------------------------------------------------------------------


def test_a_store_warning_becomes_an_event_and_an_alert(running: World) -> None:
    logging.getLogger("vigia.snapshots.store").warning("%s is low on space: %d%% free", "/vol", 4)
    assert running.guardian.flush_logs()
    event = running.only("log")
    assert (event.source, event.risk, event.target) == ("system", 1, "vigia.snapshots.store")
    assert event.details["template"] == "%s is low on space: %d%% free"
    assert event.details["message"] == "/vol is low on space: 4% free"
    (alert,) = running.alerts.titled("vigia.snapshots.store")
    assert alert.event_seq == event.seq
    assert alert.level is AlertLevel.WARNING


def test_an_error_has_risk_two_and_error_level(running: World) -> None:
    logging.getLogger("vigia.snapshots.store").error("the clock is behind")
    assert running.guardian.flush_logs()
    assert running.only("log").risk == 2
    assert running.alerts.sent[-1].level is AlertLevel.ERROR


def test_a_flood_of_one_template_is_one_event_a_minute(running: World) -> None:
    store_logger = logging.getLogger("vigia.snapshots.store")
    for name in ("a", "b", "c"):
        store_logger.warning("unexpected entry %s: leaving it untouched", name)
    assert running.guardian.flush_logs()
    assert len(running.events("log")) == 1


def test_a_failing_black_box_does_not_make_the_bridge_loop(running: World) -> None:
    running.box.append_error = BlackBoxError("disk full")
    logging.getLogger("vigia.snapshots.store").warning("something")  # must return
    assert running.guardian.flush_logs()
    assert running.alerts.titled("vigia.snapshots.store")  # the user still hears about it


def test_the_bridge_is_removed_when_the_service_stops(running: World) -> None:
    running.guardian.stop()
    logging.getLogger("vigia.snapshots.store").warning("after the stop")
    assert [e.details["message"] for e in running.events("log")] == []


def test_the_bridge_is_not_installed_when_the_boot_fails(world: World) -> None:
    world.jail.setup_error = JailError("boom")
    with pytest.raises(JailError):
        world.guardian.start()
    logging.getLogger("vigia.snapshots.store").warning("after a failed boot")
    assert world.events("log") == []


# --- run ---------------------------------------------------------------------------------------


def test_run_starts_cycles_until_told_to_stop_and_then_stops(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = threading.Event()
    cycles = 0
    real_cycle = world.guardian.cycle

    def counting_cycle() -> object:
        nonlocal cycles
        cycles += 1
        result = real_cycle()
        if cycles == 3:
            stop.set()
        return result

    monkeypatch.setattr(world.guardian, "cycle", counting_cycle)
    object.__setattr__(world.config, "cycle_interval", 0.001)
    world.guardian.run(stop)
    assert cycles == 3
    assert world.actions()[0] == "system/service_start"
    assert world.actions()[-1] == "system/service_stop"
    assert not world.jail.running


def test_a_cycle_that_crashes_is_recorded_and_the_loop_goes_on(
    world: World, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    stop = threading.Event()
    calls = 0

    def crashing_cycle() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("bug in a cycle")
        stop.set()

    monkeypatch.setattr(world.guardian, "cycle", crashing_cycle)
    object.__setattr__(world.config, "cycle_interval", 0.001)
    with caplog.at_level(logging.ERROR):
        world.guardian.run(stop)
    assert calls == 2
    assert "bug in a cycle" in world.only("cycle_failed").details["error"]
    assert world.events("service_stop")


def test_run_stops_the_agent_if_the_boot_succeeded_and_a_signal_comes_at_once(
    world: World,
) -> None:
    stop = threading.Event()
    stop.set()
    world.guardian.run(stop)
    assert not world.jail.running
    assert world.actions()[-1] == "system/service_stop"


def test_run_does_not_leave_the_agent_running_if_the_boot_fails_halfway(world: World) -> None:
    world.watcher.arm_error = None
    world.jail.setup_error = JailError("boom")
    with pytest.raises(JailError):
        world.guardian.run(threading.Event())
    assert not world.jail.running


# --- a boot that fails halfway, and frozen agents ------------------------------------------------


def test_a_boot_that_fails_after_the_agent_started_does_not_leave_it_running(
    world: World,
) -> None:
    def explode() -> None:
        raise RuntimeError("wait_ready blew up")

    world.jail.wait_ready = explode  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="blew up"):
        world.guardian.start()
    assert not world.jail.running
    assert world.log[-2:] == ["jail.stop", "watcher.close"]
    assert world.only("agent_stop").details == {"reason": "boot_failed"}
    assert world.only("service_start_failed")
    logging.getLogger("vigia.snapshots.store").warning("after the failed boot")
    assert world.events("log") == []  # the bridge is gone
    world.log.clear()
    world.guardian.stop()  # nothing left to do
    assert world.log == []


def test_a_boot_that_fails_and_cannot_stop_the_agent_says_so(world: World) -> None:
    def explode() -> None:
        raise RuntimeError("wait_ready blew up")

    world.jail.wait_ready = explode  # type: ignore[method-assign]
    world.jail.cannot_stop()
    with pytest.raises(RuntimeError) as raised:
        world.guardian.start()
    assert any("docker stop failed" in note for note in raised.value.__notes__)


def test_a_freeze_that_fails_falls_back_to_killing_the_agent(running: World) -> None:
    running.volume.write()
    running.violations.append(Violation("P3", "el uso pasa del tope"))
    running.jail.pause_error = JailError("docker pause failed")
    result = running.guardian.cycle()
    assert result.snapshot is None  # still refused
    assert "jail.kill" in running.log
    assert not running.jail.running
    assert running.guardian.agent_state is AgentState.STOPPED
    assert running.guardian.pause_reasons == {"space"}
    pause = running.only("space_pause")
    assert (pause.risk, pause.details["frozen"], pause.details["killed"]) == (3, False, True)
    assert "docker pause failed" in pause.details["pause_error"]
    stop = running.only("agent_stop")
    assert (stop.details, stop.risk) == ({"reason": "freeze_failed"}, 3)
    (alert,) = running.alerts.titled("no se pudo congelar")
    assert alert.event_seq == pause.seq


@pytest.mark.parametrize("error", [RuntimeError("docker exploded"), OSError("no socket")])
def test_any_exception_from_pause_triggers_the_fallback(running: World, error: Exception) -> None:
    running.volume.write()
    running.violations.append(Violation("P2", "pocos datos"))
    running.jail.pause_error = error  # type: ignore[assignment]
    running.guardian.cycle()
    assert not running.jail.running  # killed, whatever kind of failure it was


def test_an_agent_that_can_be_neither_frozen_nor_killed_is_reported_as_running(
    running: World,
) -> None:
    running.volume.write()
    running.violations.append(Violation("P3", "el uso pasa del tope"))
    running.jail.pause_error = JailError("docker pause failed")
    running.jail.kill_error = JailError("docker kill failed")
    running.jail.remove_error = JailError("docker rm failed")
    running.guardian.cycle()
    assert running.jail.running
    assert running.guardian.agent_state is not AgentState.STOPPED
    failed = running.only("agent_stop_failed")
    assert (failed.details["reason"], failed.risk) == ("freeze_failed", 3)
    (alert,) = running.alerts.titled("ni parar")
    assert "sigue en marcha" in alert.body


def test_a_frozen_agent_is_killed_not_stopped(running: World) -> None:
    # docker stop would wake a frozen container to deliver SIGTERM, and it would run code again.
    running.volume.write()
    running.violations.append(Violation("P2", "pocos datos"))
    running.guardian.cycle()
    assert running.guardian.agent_state is AgentState.FROZEN
    running.log.clear()
    running.guardian.stop()
    assert running.log == ["jail.kill", "watcher.close"]
    assert running.only("agent_stop").details == {"reason": "service_stop"}


def test_the_prune_clock_starts_at_boot_even_if_the_agent_does_not(world: World) -> None:
    world.mono[0] = 10 * 24 * 3600.0  # a machine that has been up for ten days
    world.synced[0] = False
    world.violations.append(Violation("P5", "sin tope"))
    world.guardian.start()
    world.guardian.cycle()
    assert world.events("prune_skipped") == []  # the 24 h count from the boot, not from zero


# --- review round: no recording no watching, fail-closed space, secrets, paused agents -----------

SECRET = "token=abcdef0123456789abcdef0123456789"  # noqa: S105


def test_a_black_box_that_opens_but_cannot_be_written_stops_the_boot(world: World) -> None:
    world.box.append_error = BlackBoxError("disk full")
    with pytest.raises(BlackBoxError, match="disk full"):
        world.guardian.start()
    assert world.log == []  # no store, no jail setup, nothing started
    assert world.alerts.titled("caja negra")


def test_a_black_box_that_cannot_be_written_stops_an_agent_found_running(world: World) -> None:
    world.jail.running = True
    world.box.append_error = BlackBoxError("disk full")
    with pytest.raises(BlackBoxError):
        world.guardian.start()
    assert world.log == ["jail.kill"]
    assert not world.jail.running


def test_a_frozen_agent_found_at_boot_is_killed_not_stopped(world: World) -> None:
    world.jail.running = True
    world.jail.paused = True
    world.guardian.start()
    assert "jail.kill" in world.log
    assert world.log.index("jail.kill") < world.log.index("store.init")
    assert "jail.stop" not in world.log[: world.log.index("jail.start")]  # docker stop wakes it


def test_a_frozen_agent_found_at_boot_by_a_failing_black_box_is_killed(world: World) -> None:
    world.jail.running = True
    world.jail.paused = True
    world.box.open_error = BlackBoxError("disk full")
    with pytest.raises(BlackBoxError):
        world.guardian.start()
    assert world.log == ["jail.kill"]


def test_a_paused_agent_is_killed_when_the_boot_is_aborted(world: World) -> None:
    def explode() -> None:
        world.jail.paused = True  # frozen by something else meanwhile
        raise RuntimeError("wait_ready blew up")

    world.jail.wait_ready = explode  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        world.guardian.start()
    assert world.log[-2:] == ["jail.kill", "watcher.close"]


def test_a_not_ready_agent_that_cannot_be_stopped_is_still_reported_as_running(
    world: World,
) -> None:
    world.jail.ready_error = JailError("not ready after 120 s")
    original_wait = world.jail.wait_ready

    def wait_then_break_the_stop() -> None:
        world.jail.cannot_stop()
        original_wait()

    world.jail.wait_ready = wait_then_break_the_stop  # type: ignore[method-assign]
    world.guardian.start()  # the service stays up
    assert world.jail.running
    assert world.guardian.agent_state is AgentState.RUNNING  # not "stopped": it is not
    failed = world.only("agent_stop_failed")
    assert (failed.details["reason"], failed.risk) == ("start_failed", 3)
    (alert,) = world.alerts.titled("sigue en marcha")
    assert alert.event_seq == failed.seq


def test_a_not_ready_agent_is_killed_if_stop_fails(world: World) -> None:
    world.jail.ready_error = JailError("not ready after 120 s")
    original_wait = world.jail.wait_ready

    def wait_then_break_docker_stop() -> None:
        world.jail.stop_error = JailError("docker stop failed")
        original_wait()

    world.jail.wait_ready = wait_then_break_docker_stop  # type: ignore[method-assign]
    world.guardian.start()
    assert not world.jail.running
    assert world.guardian.agent_state is AgentState.STOPPED
    assert world.log[-2:] == ["jail.stop", "jail.kill"]


# the space seam fails closed


def test_an_exception_from_the_space_check_freezes_the_agent(running: World) -> None:
    running.volume.write()

    def broken() -> list[Violation]:
        raise OSError("cannot read /sys/fs/btrfs")

    running.guardian._space = broken  # noqa: SLF001
    result = running.guardian.cycle()
    assert result.snapshot is None
    assert running.guardian.agent_state is AgentState.FROZEN
    pause = running.only("space_pause")
    assert pause.details["conditions"] == ["P4"]
    assert "cannot read" in running.alerts.titled("pausado")[0].body


def test_a_failed_sync_with_a_space_check_freezes_the_agent(running: World) -> None:
    running.volume.write()
    running.volume.sync_error = SnapshotError("sync failed")
    running.guardian.cycle()
    assert running.guardian.agent_state is AgentState.FROZEN
    assert running.only("space_pause").details["conditions"] == ["P4"]
    assert not any(entry.startswith("store.take") for entry in running.log)


def test_the_space_check_at_boot_comes_after_a_sync(world: World) -> None:
    world.guardian.start()
    boot = world.log[: world.log.index("jail.start")]
    assert boot.index("btrfs.sync") < boot.index("space.evaluate")


def test_an_exception_from_the_space_check_at_boot_keeps_the_agent_from_starting(
    world: World,
) -> None:
    def broken() -> list[Violation]:
        raise OSError("cannot read /sys/fs/btrfs")

    world.guardian._space = broken  # noqa: SLF001
    world.guardian.start()
    assert "jail.start" not in world.log
    assert world.only("space_pause").details["conditions"] == ["P4"]
    assert world.guardian.agent_state is AgentState.STOPPED


def test_a_failed_sync_at_boot_keeps_the_agent_from_starting(world: World) -> None:
    world.volume.sync_error = SnapshotError("sync failed")
    world.guardian.start()
    assert "jail.start" not in world.log
    assert world.only("space_pause").details["conditions"] == ["P4"]


def test_a_standing_condition_alerts_once_an_hour_not_every_cycle(running: World) -> None:
    running.volume.write()
    running.violations.append(Violation("P1", "metadatos bajos"))
    for _ in range(4):
        running.guardian.cycle()
    assert len(running.alerts.titled("pausado")) == 1
    assert len(running.events("space_pause")) == 4  # but every cycle is on record
    running.advance(3600)
    running.guardian.cycle()
    assert len(running.alerts.titled("pausado")) == 2


# alerts carry no secrets and no agent output


def test_the_agents_log_tail_in_a_jail_error_never_reaches_an_alert(world: World) -> None:
    world.jail.ready_error = JailError(f"the agent was not ready after 120 s: {SECRET} from logs")
    world.guardian.start()
    assert world.alerts.sent  # the user was told...
    for alert in world.alerts.sent:
        assert SECRET not in alert.body
        assert SECRET not in alert.title
        assert "from logs" not in alert.body  # ...without any of the agent's own words
    failed = world.only("agent_start_failed")
    assert SECRET not in str(failed.details)  # and the black box struck it too


def test_every_alert_goes_through_redact(running: World) -> None:
    running.volume.take_error = SnapshotError(f"btrfs said: {SECRET}")
    running.volume.write()
    running.guardian.cycle()
    (alert,) = running.alerts.titled("No se pudo hacer")
    assert SECRET not in alert.body
    assert "[REDACTED]" in alert.body


def test_a_secret_in_a_logged_warning_is_redacted_in_the_alert_and_the_event(
    running: World,
) -> None:
    logging.getLogger("vigia.snapshots.store").warning("unexpected entry %s", SECRET)
    assert running.guardian.flush_logs()
    assert all(SECRET not in alert.body for alert in running.alerts.sent)
    assert SECRET not in str(running.only("log").details)


def test_an_alert_about_a_failed_boot_step_does_not_carry_the_secret(world: World) -> None:
    world.volume.recover_error = SnapshotError(f"cannot publish: {SECRET}")
    world.guardian.start()
    assert all(SECRET not in alert.body for alert in world.alerts.sent)


# throttles


def test_prune_skipped_is_recorded_once_a_day_not_every_cycle(running: World) -> None:
    running.synced[0] = False
    running.advance(24 * 3600)
    for _ in range(5):
        running.guardian.cycle()
        running.advance(120)
    assert len(running.events("prune_skipped")) == 1
    running.advance(24 * 3600)
    running.guardian.cycle()
    assert len(running.events("prune_skipped")) == 2


def test_a_volume_that_stays_busy_is_reported_every_hour(running: World) -> None:
    running.volume.write()
    running.volume.take_error = SnapshotBusy("lock held")
    for _ in range(6):
        running.guardian.cycle()
    assert len(running.events("busy")) == 1  # three in a row, then quiet
    running.advance(3600)
    running.guardian.cycle()
    assert len(running.events("busy")) == 2
    assert running.events("busy")[-1].details["consecutive"] == 7
    assert len(running.alerts.titled("instantáneas")) == 2


# the watcher and the boot, more precisely


def test_an_earlier_run_without_any_reference_is_recorded_as_a_gap(world: World) -> None:
    world.box._box.append("system", "service_start", "")  # noqa: SLF001 - a run that came before
    world.guardian.start()
    (dropped,) = world.events("dropped")
    assert dropped.details["reason"] == "watcher_down"
    assert dropped.details["since"] is None
    assert dropped.snapshot_id is None


def test_the_barrier_must_return_the_snapshot_take_made(running: World) -> None:
    running.volume.write()
    stranger = running.volume.listed[0]

    def lying_barrier(take: Callable[[], Snapshot]) -> Snapshot:
        take()
        return stranger

    running.watcher.barrier = lying_barrier  # type: ignore[method-assign]
    result = running.guardian.cycle()
    assert result.snapshot is not None
    assert result.snapshot != stranger  # the snapshot that was really made
    assert "did not make" in running.only("watcher_failed").details["error"]


def test_a_barrier_that_never_calls_take_still_gets_its_snapshot(running: World) -> None:
    running.volume.write()
    running.watcher.barrier = lambda take: running.volume.listed[0]  # type: ignore[method-assign,assignment]
    result = running.guardian.cycle()
    assert result.snapshot is not None
    assert result.snapshot != running.volume.listed[0]
    assert running.only("watcher_failed")


# --- rewind (T04c-1, docs/19 section 4) -------------------------------------------------------


def pending_intent(world: World) -> object:
    from vigia.service.rewind import read_pending  # noqa: PLC0415 - only the rewind tests

    return read_pending(world.config.pending_file)


@pytest.fixture
def rewinding(running: World) -> World:
    """A running service with a change snapshotted after the startup snapshot: rewinding to the
    startup one undoes it."""
    running.volume.write()
    running.guardian.cycle()
    running.log.clear()
    return running


def test_an_invalid_id_does_nothing_at_all(running: World) -> None:
    before = running.actions()
    with running.guardian.agent_lock:  # not even the lock is asked for
        outcome = running.guardian.rewind("../../etc", requested_by="cli")
    assert outcome.status is RewindStatus.INVALID
    assert outcome.exit_code == 2
    assert running.actions() == before
    assert running.log == []
    assert not running.config.pending_file.exists()


def test_a_rewind_of_a_running_agent_in_the_documented_order(rewinding: World) -> None:
    target = rewinding.volume.listed[0]
    seen_intent: list[object] = []
    rewinding.volume.during_swap = lambda: seen_intent.append(pending_intent(rewinding))

    outcome = rewinding.guardian.rewind(target.id, requested_by="cli")

    assert rewinding.log == [
        "store.restore",
        "jail.stop",  # the agent stops first, while the watcher still describes what it writes
        "watcher.suspend",
        f"store.swap({target.id})",
        f"watcher.rearm({target.id})",  # the watcher is armed again before the agent starts
        "btrfs.sync",
        "space.evaluate",  # and the agent only starts with the space green
        "jail.start",
        "jail.wait_ready",
    ]
    assert outcome.status is RewindStatus.DONE and outcome.exit_code == 0
    assert outcome.agent_started
    assert rewinding.guardian.agent_state is AgentState.RUNNING
    assert rewinding.actions()[-4:] == [
        "snapshot/rewind_requested",
        "system/agent_stop",
        "system/agent_start",
        "snapshot/rewind_done",
    ]
    requested = rewinding.only("rewind_requested")
    assert requested.details["from_workspace_id"] == 258
    assert requested.details["requested_by"] == "cli"
    assert requested.snapshot_id == target.id
    # The intent was on disk, with what reconciling needs, before anything changed.
    (intent,) = seen_intent
    assert intent.request_id == requested.details["request_id"]  # type: ignore[attr-defined]
    assert intent.from_workspace_id == 258  # type: ignore[attr-defined]
    assert intent.target == target.id  # type: ignore[attr-defined]
    assert not rewinding.config.pending_file.exists()  # and is gone afterwards

    done = rewinding.only("rewind_done")
    undo = rewinding.volume.snapshots()[-1]
    assert undo.reason == Reason.PRE_RESTORE
    assert done.snapshot_id == target.id
    assert done.details["request_id"] == requested.details["request_id"]
    assert done.details["undo"] == undo.id == outcome.undo
    assert done.details["workspace_id"] == 259
    assert done.details["from_workspace_id"] == 258
    assert done.details["workspace_uuid"] == str(rewinding.volume.workspace_info.uuid)
    assert done.details["agent_started"] is True
    assert "error" not in done.details and "problems" not in done.details
    assert [e.details["reason"] for e in rewinding.events("agent_stop")][-1] == "rewind"
    assert rewinding.alerts.titled("ebobina") == []  # nothing went wrong: nothing to alert


def test_a_stopped_agent_stays_stopped_after_a_rewind(rewinding: World) -> None:
    rewinding.jail.stop()  # stopped on purpose (no pause reason): not the rewind's to start
    rewinding.guardian._set_state(AgentState.STOPPED)  # noqa: SLF001
    rewinding.log.clear()
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.DONE
    assert not outcome.agent_started
    assert "jail.start" not in rewinding.log and "space.evaluate" not in rewinding.log
    assert not rewinding.jail.running
    assert rewinding.only("rewind_done").details["agent_started"] is False


def test_the_outcome_is_decided_by_the_workspace_id_not_by_the_exception(rewinding: World) -> None:
    """A watcher that raises while rearming and an agent that cannot start, both AFTER the
    swap: still a rewind (rewind_done, exit code 3), never a failed one."""
    rewinding.watcher.resume_error = RuntimeError("rearm broke")
    rewinding.jail.ready_error = JailError("not ready: the agent log says token=abc")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")

    assert outcome.status is RewindStatus.PROBLEM and outcome.exit_code == 3
    assert outcome.rewound and not outcome.agent_started
    assert not rewinding.events("rewind_failed")
    done = rewinding.only("rewind_done")
    assert done.details["agent_started"] is False
    assert set(done.details["problems"]) == {"agent", "watcher"}
    assert "not ready" in done.details["error"]
    assert done.risk == 2
    failed_start = rewinding.events("agent_start_failed")[-1]
    assert failed_start.seq < done.seq
    assert rewinding.only("watcher_failed").details["step"] == "rearm"
    assert not rewinding.jail.running  # the half-started agent was stopped again
    assert rewinding.guardian.agent_state is AgentState.STOPPED
    (alert,) = rewinding.alerts.titled("Rebobinado con problemas")
    assert alert.event_seq == done.seq
    assert "token=abc" not in alert.body  # Docker's text never reaches an alert


def test_a_failure_before_the_swap_leaves_everything_as_it_was(rewinding: World) -> None:
    rewinding.volume.restore_error_before = SnapshotError("staging failed")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED and outcome.exit_code == 1
    assert rewinding.log == ["store.restore"]  # the agent was never touched
    assert rewinding.jail.running
    failed = rewinding.only("rewind_failed")
    assert failed.details["no_space"] is False
    assert failed.details["request_id"] == rewinding.only("rewind_requested").details["request_id"]
    assert failed.risk == 2
    assert rewinding.alerts.titled("No se ha rebobinado")
    assert not rewinding.config.pending_file.exists()


def test_a_failed_swap_starts_the_agent_again_on_the_old_workspace(rewinding: World) -> None:
    rewinding.volume.swap_error = SnapshotError("rename failed")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED
    assert outcome.agent_started
    assert rewinding.jail.running
    assert rewinding.guardian.agent_state is AgentState.RUNNING
    assert rewinding.log.index("jail.stop") < rewinding.log.index("jail.start")
    assert rewinding.only("rewind_failed")


@pytest.mark.parametrize("where", ["before_quiesce", "in_the_swap"])
def test_no_space_kills_the_agent_and_opens_the_pause(rewinding: World, where: str) -> None:
    """Before quiesce (the recovery or the staging copy), the agent is still running: it is
    killed, and that is recorded. In the swap, it is already stopped and start_if refuses to
    start it: nothing is killed, and nothing says it was. Either way the pause stays open."""
    error = SnapshotNoSpace("restore stopped before the swap: no space")
    if where == "before_quiesce":
        rewinding.volume.restore_error_before = error
    else:
        rewinding.volume.swap_error = error
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")

    assert outcome.status is RewindStatus.FAILED
    assert "jail.start" not in rewinding.log and "space.evaluate" not in rewinding.log
    assert not rewinding.jail.running
    assert rewinding.guardian.agent_state is AgentState.STOPPED
    assert rewinding.guardian.pause_reasons == {"rewind_no_space"}
    pause = rewinding.only("space_pause")
    assert pause.details["reason"] == "rewind_no_space"
    request_id = rewinding.only("rewind_requested").details["request_id"]
    stops = [
        e.details for e in rewinding.events("agent_stop") if e.details["reason"] != "service_stop"
    ]
    (alert,) = rewinding.alerts.titled("No hay espacio para rebobinar")
    if where == "before_quiesce":
        assert "jail.kill" in rewinding.log
        assert pause.details["killed"] is True
        assert stops == [{"reason": "rewind_no_space", "request_id": request_id}]
        assert "se ha parado" in alert.body
    else:
        assert pause.details["killed"] is False
        assert stops == [{"reason": "rewind", "request_id": request_id}]  # quiesce stopped it
        assert "ya estaba parado" in alert.body
    assert rewinding.only("rewind_failed").details["no_space"] is True


def test_a_rewind_without_space_for_the_undo_point_is_done_but_incomplete(
    rewinding: World,
) -> None:
    rewinding.volume.incomplete_cause = SnapshotNoSpace("no space to publish")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM and outcome.exit_code == 3
    assert outcome.undo is None
    done = rewinding.only("rewind_done")
    assert done.details["incomplete"] is True
    assert done.details["leftover"] == "workspace.restore"
    assert "jail.start" not in rewinding.log  # start_if refused: a space error
    assert rewinding.guardian.pause_reasons == {"rewind_no_space"}


def freeze_for_space(world: World) -> None:
    world.violations.append(Violation("P3", "el uso pasa del tope", "space"))
    world.volume.write()
    world.guardian.cycle()
    assert world.guardian.agent_state is AgentState.FROZEN
    world.log.clear()


def test_rewinding_an_agent_frozen_for_space_starts_it_when_all_is_green(running: World) -> None:
    freeze_for_space(running)
    running.violations.clear()  # the rewind gives a new cap: green again
    outcome = running.guardian.rewind(running.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.DONE and outcome.agent_started
    assert running.log[1] == "jail.kill"  # frozen: killed, never woken by docker stop
    assert "jail.stop" not in running.log
    assert running.guardian.pause_reasons == frozenset()
    resume = running.only("space_resume")
    assert resume.details["by"] == "rewind"
    assert resume.details["reasons"] == ["space"]
    assert running.guardian.agent_state is AgentState.RUNNING


def test_rewinding_an_agent_frozen_for_space_leaves_it_stopped_if_still_red(
    running: World,
) -> None:
    freeze_for_space(running)
    outcome = running.guardian.rewind(running.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM and not outcome.agent_started
    assert "jail.start" not in running.log
    assert not running.jail.running
    assert running.guardian.agent_state is AgentState.STOPPED
    assert running.guardian.pause_reasons == {"space"}  # the pause stays open
    assert not running.events("space_resume")
    assert len(running.events("space_pause")) == 2  # the cycle's and the rewind's
    assert running.only("rewind_done").details["problems"] == ["agent"]


def test_an_agent_paused_for_another_reason_stays_stopped(running: World) -> None:
    freeze_for_space(running)
    with running.guardian.freeze_lock:
        running.guardian._pause_reasons.add("user")  # noqa: SLF001 - T09's pause does not exist yet
    running.violations.clear()
    outcome = running.guardian.rewind(running.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.DONE  # it was not supposed to run
    assert not outcome.agent_started
    assert "space.evaluate" not in running.log
    assert running.guardian.pause_reasons == {"space", "user"}


def test_start_if_fails_closed_when_deciding_breaks(rewinding: World) -> None:
    """A bug while deciding whether to start (here the space reading blows up): the agent
    stays stopped, the rewind says why, and the error is logged, never swallowed."""
    world = capped_world(rewinding, usage_limit=64 * 1024**2)

    def broken(root: Path, workspace: Path, state_dir: Path) -> object:
        raise KeyError("a bug in the space reading")

    world.guardian._sample = broken  # type: ignore[assignment]  # noqa: SLF001
    outcome = world.guardian.rewind(world.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM
    assert not outcome.agent_started and not world.jail.running
    assert set(world.only("rewind_done").details["problems"]) == {"agent", "start_check"}
    world.guardian.flush_logs()
    assert any(
        "cannot decide whether to start" in e.details["message"] for e in world.events("log")
    )


def test_a_failing_black_box_does_not_stop_the_rewind(rewinding: World) -> None:
    from vigia.blackbox import BlackBoxError  # noqa: PLC0415

    rewinding.box.append_error = BlackBoxError("disk full")
    seen_intent: list[object] = []
    rewinding.volume.during_swap = lambda: seen_intent.append(pending_intent(rewinding))
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.rewound and outcome.status is RewindStatus.PROBLEM  # exit code 3
    assert outcome.agent_started
    assert seen_intent and seen_intent[0] is not None  # the intent is what reconciles it
    assert rewinding.alerts.titled("caja negra")
    # rewind_done could not be written: the intent stays, so the rewind is reconciled later
    # (and an older request can never be judged by today's workspace id).
    assert rewinding.config.pending_file.exists()

    rewinding.box.append_error = None
    rewinding.guardian.stop()
    rewinding.guardian.start()
    (done,) = rewinding.events("rewind_done")
    assert done.details["reconciled"] is True
    assert done.details["basis"] == "pending"
    assert not rewinding.config.pending_file.exists()


def test_the_watcher_cannot_stop_a_rewind_on_entry_either(rewinding: World) -> None:
    rewinding.watcher.suspend_error = RuntimeError("suspend broke")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.PROBLEM
    assert outcome.agent_started
    assert rewinding.only("watcher_failed").details["step"] == "suspend"


def test_a_workspace_that_cannot_be_read_first_is_not_rewound(rewinding: World) -> None:
    rewinding.volume.workspace_id_error = SnapshotError("workspace is missing")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED
    assert rewinding.log == []
    assert rewinding.only("rewind_failed").details["stage"] == "workspace_id"
    assert not rewinding.config.pending_file.exists()


def test_a_workspace_that_cannot_be_read_afterwards_keeps_the_intent(rewinding: World) -> None:
    rewinding.volume.workspace_id_error_after_restore = SnapshotError("cannot read")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.UNKNOWN and outcome.exit_code == 3
    assert rewinding.config.pending_file.exists()  # the next start reconciles it
    assert not rewinding.events("rewind_done") and not rewinding.events("rewind_failed")
    assert rewinding.alerts.titled("No se sabe si se ha rebobinado")


def test_the_cycle_is_skipped_while_a_rewind_holds_the_agent(rewinding: World) -> None:
    """Interleaved with a rewind whose workspace id changes half way, the cycle must not read
    the old id and rearm the watcher a second time (nor wait on the volume lock)."""
    results: list[CycleResult] = []

    def cycle_meanwhile() -> None:
        thread = threading.Thread(target=lambda: results.append(rewinding.guardian.cycle()))
        thread.start()
        thread.join(5)

    rewinding.volume.during_swap = cycle_meanwhile
    rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    (result,) = results
    assert result.skipped and not result.changed
    assert not any(entry.startswith("watcher.rearm_if_moved") for entry in rewinding.log)
    assert rewinding.log.count(f"watcher.rearm({rewinding.volume.listed[0].id})") == 1


def test_a_rewind_waits_for_a_cycle_and_a_cycle_does_not_wait_for_a_rewind(
    rewinding: World,
) -> None:
    with rewinding.guardian.agent_lock:
        assert rewinding.guardian.cycle().skipped
    assert not rewinding.guardian.cycle().skipped


def test_an_undo_point_can_be_rewound_to_in_turn(rewinding: World) -> None:
    first = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert first.undo is not None
    second = rewinding.guardian.rewind(first.undo, requested_by="cli")
    assert second.status is RewindStatus.DONE
    assert len(rewinding.events("rewind_done")) == 2


# --- reconcile at startup ----------------------------------------------------------------------


def interrupted_rewind(
    world: World, *, swapped: bool, with_event: bool = True, request_id: str = "a" * 32
) -> str:
    """What a rewind killed half way leaves: its intent on disk, its request in the black box
    (unless ``with_event`` is False) and, if ``swapped``, a rewound workspace."""
    from vigia.service.rewind import PendingRewind, write_pending  # noqa: PLC0415

    target = world.volume.snapshot_quietly()
    world.volume.write()
    from_workspace = world.volume.workspace_info.treeid
    write_pending(
        world.config.pending_file, PendingRewind(request_id, target.id, from_workspace, "cli")
    )
    if with_event:
        world.box._box.open()  # noqa: SLF001 - the service that died wrote it
        world.box._box.append(  # noqa: SLF001
            "snapshot",
            "rewind_requested",
            target.id,
            details={
                "request_id": request_id,
                "target": target.id,
                "requested_by": "cli",
                "from_workspace_id": from_workspace,
            },
            snapshot_id=target.id,
        )
    if swapped:
        world.volume.rewind_to(target)
    return target.id


@pytest.mark.parametrize("with_event", [True, False])
def test_a_rewind_killed_after_the_swap_is_reconciled_as_done(
    world: World, with_event: bool
) -> None:
    target = interrupted_rewind(world, swapped=True, with_event=with_event)
    undo = world.volume.snapshots()[-1]
    world.guardian.start()
    done = world.only("rewind_done")
    assert done.details["reconciled"] is True
    assert done.details["request_id"] == "a" * 32
    assert done.details["undo"] == undo.id
    assert done.details["from_workspace_id"] == 258
    assert done.snapshot_id == target
    assert not world.events("rewind_failed")
    assert not world.config.pending_file.exists()
    assert world.alerts.titled("Un rebobinado se interrumpió")
    # Reconciled before anything starts.
    assert world.actions().index("snapshot/rewind_done") < world.actions().index(
        "system/agent_start"
    )


def test_a_rewind_killed_before_the_swap_is_reconciled_as_failed(world: World) -> None:
    interrupted_rewind(world, swapped=False)
    world.guardian.start()
    failed = world.only("rewind_failed")
    assert failed.details["reconciled"] is True
    assert failed.details["request_id"] == "a" * 32
    assert not world.events("rewind_done")
    assert not world.config.pending_file.exists()


def test_a_request_without_its_intent_is_reconciled_from_the_black_box(world: World) -> None:
    interrupted_rewind(world, swapped=True)
    world.config.pending_file.unlink()
    world.guardian.start()
    assert world.only("rewind_done").details["reconciled"] is True


def test_nothing_pending_records_nothing(world: World) -> None:
    world.guardian.start()
    assert not world.events("rewind_done") and not world.events("rewind_failed")


def test_a_settled_rewind_is_not_reconciled_twice(rewinding: World) -> None:
    rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    rewinding.guardian.stop()
    rewinding.guardian.start()
    assert len(rewinding.events("rewind_done")) == 1


def test_an_intent_whose_rewind_was_settled_is_only_removed(rewinding: World) -> None:
    """The rewind ended, but removing its intent failed: the next start finds it settled."""
    from vigia.service.rewind import PendingRewind, write_pending  # noqa: PLC0415

    rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    done = rewinding.only("rewind_done")
    write_pending(
        rewinding.config.pending_file,
        PendingRewind(done.details["request_id"], done.details["target"], 258, "cli"),
    )
    rewinding.guardian.stop()
    rewinding.guardian.start()
    assert len(rewinding.events("rewind_done")) == 1
    assert not rewinding.events("rewind_failed")
    assert not rewinding.config.pending_file.exists()


def test_an_unreadable_intent_is_logged_and_removed(world: World) -> None:
    world.config.pending_file.write_text("garbage")
    world.guardian.start()
    world.guardian.flush_logs()
    assert any("cannot be read" in e.details["message"] for e in world.events("log"))
    assert not world.config.pending_file.exists()
    assert world.guardian.agent_state is AgentState.RUNNING


def test_an_earlier_interrupted_rewind_is_settled_before_a_new_one(world: World) -> None:
    world.guardian.start()
    interrupted_rewind(world, swapped=False)
    world.guardian.rewind(world.volume.listed[0].id, requested_by="cli")
    failed = world.only("rewind_failed")
    assert failed.details["reconciled"] is True
    assert failed.seq < world.events("rewind_requested")[-1].seq
    assert world.events("rewind_done")


# --- the start after a rewind, before the space thread exists (T04d-2) -------------------------


def capped_world(world: World, usage_limit: int | None, errors: tuple[str, ...] = ()) -> World:
    from dataclasses import replace  # noqa: PLC0415

    from vigia.snapshots import space  # noqa: PLC0415
    from vigia.snapshots.btrfs import QGROUP_LIMIT_MAX_RFER, QgroupUsage  # noqa: PLC0415

    limit = 64 * 1024**2
    usage = None
    if usage_limit is not None or not errors:
        usage = QgroupUsage(
            referenced=1024**2,
            exclusive=1024**2,
            limit_flags=QGROUP_LIMIT_MAX_RFER if usage_limit is not None else 0,
            max_referenced=usage_limit or 0,
            max_exclusive=0,
        )
    gib = 1024**3
    volume = space.VolumeSpace(
        device_total=100 * gib,
        unallocated=90 * gib,
        data=space.Allocation(4 * gib, 4 * gib, gib),
        metadata=space.Allocation(gib, 2 * gib, 0),
    )
    host = space.HostSpace(total=500 * gib, free=400 * gib)
    reading = space.Sample(space=volume, usage=usage, host=host, errors=errors)
    reads: list[tuple[Path, Path, Path]] = []

    def sample(root: Path, workspace: Path, state_dir: Path) -> space.Sample:
        reads.append((root, workspace, state_dir))
        return reading

    world.guardian._config = replace(world.config, workspace_limit=limit)  # noqa: SLF001
    world.guardian._space = None  # noqa: SLF001
    world.guardian._sample = sample  # noqa: SLF001
    world.reads = reads  # type: ignore[attr-defined]
    return world


def test_without_the_space_thread_only_the_cap_decides_the_start(rewinding: World) -> None:
    world = capped_world(rewinding, usage_limit=64 * 1024**2)
    outcome = world.guardian.rewind(world.volume.listed[0].id, requested_by="cli")
    assert outcome.agent_started
    assert world.reads == [(world.volume.root, world.volume.workspace, world.config.state_dir)]  # type: ignore[attr-defined]
    assert world.log.index("btrfs.sync") < world.log.index("jail.start")


@pytest.mark.parametrize("usage_limit", [None, 32 * 1024**2])
def test_without_the_space_thread_a_workspace_without_its_cap_does_not_start(
    rewinding: World, usage_limit: int | None
) -> None:
    world = capped_world(rewinding, usage_limit=usage_limit)
    outcome = world.guardian.rewind(world.volume.listed[0].id, requested_by="cli")
    assert not outcome.agent_started
    assert world.events("space_pause")[-1].details["conditions"] == ["P5"]
    assert world.guardian.pause_reasons == {"space"}


def test_without_the_space_thread_unreadable_signals_do_not_start(rewinding: World) -> None:
    world = capped_world(rewinding, usage_limit=None, errors=("workspace quota: EIO",))
    outcome = world.guardian.rewind(world.volume.listed[0].id, requested_by="cli")
    assert not outcome.agent_started
    assert set(world.events("space_pause")[-1].details["conditions"]) == {"P4", "P5"}


# --- review of T04c-1: freezing during a rewind, what the outcome may say, failed stops -------


P1 = Violation("P1", "metadatos: quedan 100 MiB, mínimo 341 MiB", "space")


def test_the_space_thread_kills_an_agent_that_is_being_stopped(rewinding: World) -> None:
    """During `docker stop` the agent runs its SIGTERM handler: a condition must stop it then
    too (state STOPPING). Frozen, `docker stop` would wake it again, so it is killed (T04d-2,
    review: a freeze in the middle of a stop is undone by the stop)."""
    guardian = rewinding.guardian
    states: list[AgentState] = []

    def condition_now() -> None:
        states.append(guardian.agent_state)
        rewinding.violations.append(P1)
        guardian._pause([P1], freeze=True)  # noqa: SLF001 - what the space thread calls

    rewinding.jail.on_stop = condition_now
    outcome = guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert states == [AgentState.STOPPING]
    assert "jail.pause" not in rewinding.log
    assert rewinding.log.index("jail.kill") < rewinding.log.index(
        f"store.swap({rewinding.volume.listed[0].id})"
    )
    pause = rewinding.events("space_pause")[0]
    assert pause.details["killed"] is True and pause.risk == 2
    assert not outcome.agent_started  # still red afterwards: it stays stopped, pause open
    assert guardian.pause_reasons == {"space"}
    assert not rewinding.jail.running


def test_the_space_thread_can_freeze_an_agent_that_is_starting(rewinding: World) -> None:
    """During wait_ready the agent runs code too (state STARTING): it is frozen, wait_ready
    fails at once, and the frozen agent is killed, never woken."""
    guardian = rewinding.guardian
    states: list[AgentState] = []

    def freeze_now() -> None:
        states.append(guardian.agent_state)
        guardian._pause([P1], freeze=True)  # noqa: SLF001

    rewinding.jail.on_wait_ready = freeze_now
    outcome = guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert states == [AgentState.STARTING]
    assert outcome.status is RewindStatus.PROBLEM and not outcome.agent_started
    pause, kill = rewinding.log.index("jail.pause"), len(rewinding.log) - 1
    assert (
        rewinding.log[pause:].count("jail.kill") == 1 and "jail.stop" not in rewinding.log[pause:]
    )
    assert kill >= pause
    assert not rewinding.jail.running
    assert guardian.agent_state is AgentState.STOPPED
    assert guardian.pause_reasons == {"space"}


def test_the_outcome_never_carries_the_agents_text(rewinding: World) -> None:
    """outcome.error and outcome.message go to the CLI, Telegram and the web: Docker's errors
    (which quote the agent's logs) never go there, only their type and the event to read;
    anything else is redacted."""
    rewinding.jail.ready_error = JailError("not ready; the agent printed token=abc")
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    done = rewinding.only("rewind_done")
    assert "token=abc" not in (outcome.error or "") + outcome.message
    assert outcome.error is not None
    assert "JailError" in outcome.error and f"#{done.seq}" in outcome.error

    rewinding.jail.ready_error = None
    rewinding.volume.swap_error = SnapshotError("rename failed for token=abc")
    failed = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert failed.status is RewindStatus.FAILED
    assert "token=abc" not in (failed.error or "") + failed.message
    assert "rename failed" in (failed.error or "")


@pytest.mark.parametrize("when", ["never_started", "stopped"])
def test_a_rewind_needs_a_running_service(world: World, when: str) -> None:
    """Without a booted service there is no black box to record in (never started) or no
    watcher to rearm (stopped): the rewind is refused and nothing is touched."""
    if when == "stopped":
        world.guardian.start()
        world.guardian.stop()
    world.log.clear()
    before = world.actions() if when == "stopped" else []
    target = world.volume.snapshot_quietly()
    outcome = world.guardian.rewind(target.id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED and outcome.exit_code == 1
    assert "Vigía" in outcome.message
    assert world.log == []
    if when == "stopped":
        assert world.actions() == before
    assert not world.config.pending_file.exists()


def test_a_failed_stop_that_did_stop_restarts_the_agent_as_it_was_and_says_so(
    rewinding: World,
) -> None:
    """`docker stop` timed out, but the daemon stopped it: restore does not run, the agent is
    started again as it was, and the black box says it was started."""
    rewinding.jail.stop_error = JailError("docker stop timed out after 90 s")
    rewinding.jail.stops_anyway = True
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED
    assert outcome.agent_started
    assert rewinding.jail.running
    assert rewinding.guardian.agent_state is AgentState.RUNNING
    starts = [e.details for e in rewinding.events("agent_start") if e.details.get("request_id")]
    assert [d["reason"] for d in starts] == ["rewind"]
    assert not rewinding.events("space_resume")
    assert rewinding.only("rewind_failed").details["agent_started"] is True


def test_a_failed_stop_never_closes_a_pause(running: World) -> None:
    """A frozen agent whose kill failed but which stopped anyway: its pause stays open, it is
    not started, and nothing says the pause was closed."""
    freeze_for_space(running)
    running.violations.clear()
    running.jail.kill_error = JailError("docker kill failed")
    running.jail.stops_anyway = True
    outcome = running.guardian.rewind(running.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED and not outcome.agent_started
    assert "jail.start" not in running.log
    assert running.guardian.pause_reasons == {"space"}
    assert not running.events("space_resume")
    assert running.guardian.agent_state is AgentState.STOPPED


def test_a_frozen_agent_whose_kill_failed_is_still_frozen(running: World) -> None:
    freeze_for_space(running)
    running.jail.kill_error = JailError("docker kill failed")
    outcome = running.guardian.rewind(running.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED
    assert running.jail.running and running.jail.paused
    assert running.guardian.agent_state is AgentState.FROZEN  # never "running"
    assert running.only("agent_stop_failed").details["still_running"] is True


def test_a_failed_swap_never_closes_a_pause_for_lack_of_space(rewinding: World) -> None:
    """An earlier rewind failed for lack of space (pause rewind_no_space). This one fails too,
    for another reason (EIO): the workspace did not change, so nothing was freed, the pause
    stays and the agent is not started on the old workspace."""
    rewinding.volume.restore_error_before = SnapshotNoSpace("no space")
    rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert rewinding.guardian.pause_reasons == {"rewind_no_space"}
    rewinding.volume.restore_error_before = None
    rewinding.volume.swap_error = SnapshotError("EIO")
    rewinding.log.clear()
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED and not outcome.agent_started
    assert "jail.start" not in rewinding.log
    assert rewinding.guardian.pause_reasons == {"rewind_no_space"}
    assert not rewinding.events("space_resume")


def test_a_rewind_after_one_without_space_closes_its_pause_when_it_works(rewinding: World) -> None:
    rewinding.volume.restore_error_before = SnapshotNoSpace("no space")
    rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    rewinding.volume.restore_error_before = None  # the person freed some space
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.DONE and outcome.agent_started
    assert rewinding.guardian.pause_reasons == frozenset()
    assert rewinding.only("space_resume").details["reasons"] == ["rewind_no_space"]


def test_a_reconciliation_that_cannot_be_recorded_keeps_the_intent(world: World) -> None:
    from vigia.blackbox import BlackBoxError  # noqa: PLC0415

    interrupted_rewind(world, swapped=True)
    world.guardian.start()
    assert world.only("rewind_done").details["basis"] == "pending"
    world.guardian.stop()

    interrupted_rewind(world, swapped=False, request_id="c" * 32)
    world.box._box.open()  # noqa: SLF001
    original = world.box.append

    def failing_for_rewinds(source: str, action: str, *args: object, **kwargs: object) -> Event:
        if action.startswith("rewind_"):
            raise BlackBoxError("disk full")
        return original(source, action, *args, **kwargs)

    world.box.append = failing_for_rewinds  # type: ignore[method-assign]
    world.guardian.start()
    assert world.config.pending_file.exists()  # not recorded: not settled
    world.guardian.stop()


def test_a_reconciliation_from_the_black_box_alone_says_so(world: World) -> None:
    interrupted_rewind(world, swapped=False)
    world.config.pending_file.unlink()
    world.guardian.start()
    assert world.only("rewind_failed").details["basis"] == "blackbox"


def test_a_rewind_killed_between_the_swap_and_the_undo_point_is_reconciled(
    world: World,
) -> None:
    """Killed after the swap but before the old workspace was published: the next start's
    recover() publishes it (as "recovered"), and the reconciliation finds it as the undo point
    by its subvolume id."""
    from vigia.service.rewind import PendingRewind, write_pending  # noqa: PLC0415

    target = world.volume.snapshot_quietly()
    world.volume.write()
    write_pending(world.config.pending_file, PendingRewind("b" * 32, target.id, 258, "cli"))
    world.volume.rewind_to(target, publish=False)
    world.guardian.start()
    (recovered,) = world.events("recovered")
    done = world.only("rewind_done")
    assert done.details["undo"] == recovered.snapshot_id
    assert done.details["reconciled"] is True
    assert world.actions().index("snapshot/recovered") < world.actions().index(
        "snapshot/rewind_done"
    )


def test_a_real_jail_whose_stop_fails_in_the_middle_of_a_rewind(
    rewinding: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The real AgentJail.quiesce (Docker faked): `docker stop` times out and the container is
    still running. restore never swaps, the agent was never stopped, and the black box says
    the stop failed with the agent still running."""
    from vigia.jail import agent as agent_module  # noqa: PLC0415
    from vigia.jail import docker  # noqa: PLC0415
    from vigia.jail.agent import AgentJail  # noqa: PLC0415
    from vigia.jail.config import AgentJailConfig  # noqa: PLC0415

    replies = iter([{"Running": True, "Paused": False}] * 50)
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> object:
        import json  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        calls.append(list(args))
        if args[0] == "stop":
            raise JailError("docker stop timed out after 90 s")
        if args[:2] == ["container", "inspect"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(next(replies)), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(docker, "run", fake_run)
    monkeypatch.setattr(agent_module, "container_problems", lambda *a, **k: [])
    workspace = tmp_path / "jail-root" / "workspace"
    workspace.mkdir(parents=True)
    jail = AgentJail(
        AgentJailConfig(
            workspace=workspace,
            config_dir=tmp_path / "jail-config",
            gateway_token="u" * 43,
            name="agent-under-test",
            network="net-under-test",
            uid=os.getuid(),
            gid=os.getgid(),
            allow_shared_ids=True,
        )
    )
    rewinding.guardian._jail = jail  # type: ignore[assignment]  # noqa: SLF001
    outcome = rewinding.guardian.rewind(rewinding.volume.listed[0].id, requested_by="cli")
    assert outcome.status is RewindStatus.FAILED
    assert "token" not in (outcome.error or "")
    assert not any(entry.startswith("store.swap") for entry in rewinding.log)
    assert [c[0] for c in calls if c[0] in {"stop", "kill", "start"}] == ["stop"]
    failed = rewinding.only("agent_stop_failed")
    assert failed.details["reason"] == "rewind" and failed.details["still_running"] is True
    assert rewinding.guardian.agent_state is AgentState.RUNNING


# --- the control socket as ``run()`` drives it (T04c-2) ----------------------------------------


class FakeControl:
    """The control socket as the Guardian sees it: start and close, on the shared call log."""

    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.start_error: Exception | None = None

    def start(self) -> None:
        self.log.append("control.start")
        if self.start_error is not None:
            raise self.start_error

    def close(self) -> None:
        self.log.append("control.close")


def test_run_opens_the_control_socket_after_the_agent_is_up_and_closes_it_before_stopping(
    world: World,
) -> None:
    stop = threading.Event()
    stop.set()  # one start, no cycle, one stop
    world.guardian.run(stop, control=FakeControl(world.log))  # type: ignore[arg-type]
    assert index(world.log, "jail.wait_ready") < index(world.log, "control.start")
    assert index(world.log, "control.start") < index(world.log, "control.close")
    assert index(world.log, "control.close") < index(world.log, "jail.stop")
    assert not world.jail.running


def test_a_control_socket_that_cannot_start_stops_the_service_and_the_agent(
    world: World,
) -> None:
    """Without the socket, `vigia rebobinar` would find the lock taken and nobody to ask."""
    control = FakeControl(world.log)
    control.start_error = RuntimeError("cannot bind")
    with pytest.raises(RuntimeError, match="cannot bind"):
        world.guardian.run(threading.Event(), control=control)  # type: ignore[arg-type]
    assert "control.close" in world.log
    assert not world.jail.running
    assert world.actions()[-1] == "system/service_stop"


def test_a_control_socket_that_fails_to_close_still_stops_the_agent(world: World) -> None:
    class BrokenClose(FakeControl):
        def close(self) -> None:
            raise RuntimeError("cannot close")

    stop = threading.Event()
    stop.set()
    with pytest.raises(RuntimeError, match="cannot close"):
        world.guardian.run(stop, control=BrokenClose(world.log))  # type: ignore[arg-type]
    assert not world.jail.running
    assert world.actions()[-1] == "system/service_stop"


def test_run_without_a_control_socket_is_what_it_was(world: World) -> None:
    stop = threading.Event()
    stop.set()
    world.guardian.run(stop)
    assert "control.start" not in world.log
    assert not world.jail.running
