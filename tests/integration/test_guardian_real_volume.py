"""The Guardian's boot and cycle on a real btrfs: real store, real counters, real black box.

Only the agent (a stub jail) and the file watcher (a stub that just runs ``take``) are fake: this
is T04b-1's check that the pieces that were tested apart with fakes work together. The real
agent and watcher come in T04b-2 and T04a."""

from collections.abc import Callable
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox, create_key
from backtide.notify import Alert
from backtide.service.config import Secret, ServiceConfig
from backtide.service.guardian import AgentState, Guardian
from backtide.snapshots import Reason, Snapshot, SnapshotStore

pytestmark = pytest.mark.integration

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2


class StubJail:
    def __init__(self) -> None:
        self.running = False

    def is_running(self) -> bool:
        return self.running

    def running_exposure(self) -> list[str]:
        return []

    def ensure_network(self) -> None: ...

    def prepare_workspace(self) -> None: ...

    def write_config(self) -> None: ...

    def exists(self) -> bool:
        return True

    def start(self) -> None:
        self.running = True

    def wait_ready(self) -> None: ...

    def stop(self) -> None:
        self.running = False

    def is_paused(self) -> bool:
        return False

    def kill(self) -> None:
        self.running = False

    def remove(self) -> None:
        self.running = False


class StubWatcher:
    def __init__(self) -> None:
        self.current: str | None = None

    def arm(self, current: str | None = None) -> bool:
        self.current = current
        return True

    def barrier(self, take: Callable[[], Snapshot]) -> Snapshot:
        snapshot = take()
        self.current = snapshot.id
        return snapshot

    def rearm_if_moved(self, workspace_id: int) -> bool:
        return False

    def report_unwatched(self) -> bool:
        return False

    def close(self) -> None: ...


class Alerts:
    def __init__(self) -> None:
        self.sent: list[Alert] = []

    def submit(self, alert: Alert) -> bool:
        self.sent.append(alert)
        return True


@pytest.fixture
def guardian_setup(
    store: SnapshotStore, tmp_path: Path, clock: Callable[[], datetime]
) -> tuple[Guardian, BlackBox, StubWatcher, StubJail, Alerts]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    box = BlackBox(
        state / "blackbox.db",
        create_key(state / "blackbox.key"),
        checkpoint_path=state / "blackbox.checkpoint",
    )
    config = ServiceConfig(state_dir=state, volume=store.root, gateway_token=Secret(TOKEN))
    watcher, jail, alerts = StubWatcher(), StubJail(), Alerts()
    guardian = Guardian(
        config,
        store=store,
        jail=jail,  # type: ignore[arg-type]
        blackbox=box,
        watcher=watcher,
        alerts=alerts,
        clock=clock,
    )
    return guardian, box, watcher, jail, alerts


def test_boot_and_cycles_on_a_real_volume(
    store: SnapshotStore,
    guardian_setup: tuple[Guardian, BlackBox, StubWatcher, StubJail, Alerts],
) -> None:
    guardian, box, watcher, jail, alerts = guardian_setup
    try:
        guardian.start()
        (first,) = store.snapshots()  # the startup snapshot of a fresh workspace
        assert watcher.current == first.id
        assert jail.running
        assert guardian.agent_state is AgentState.RUNNING

        for _ in range(3):
            assert not guardian.cycle().changed  # idle: Btrfs says nothing changed

        (store.workspace / "f.txt").write_text("one")
        taken = guardian.cycle().snapshot
        assert taken is not None
        assert watcher.current == taken.id
        assert not guardian.cycle().changed

        # A rewind: the newest snapshot of all becomes the undo point, of the OTHER lineage.
        result = store.restore(first.id, quiesce=nullcontext)
        assert result.undo is not None
        assert store.snapshots()[-1] == result.undo
        assert not guardian.cycle().changed
        (store.workspace / "g.txt").write_text("two")
        after = guardian.cycle().snapshot
        assert after is not None
        assert not guardian.cycle().changed

        (store.workspace / "g.txt").chmod(0o600)
        assert guardian.cycle().changed

        takes = [e for e in box.events() if e.action == "take"]
        assert [e.details["trigger"] for e in takes] == ["startup", "cycle", "cycle", "cycle"]
        assert all(e.snapshot_id for e in takes)
    finally:
        guardian.stop()
    assert not jail.running
    report = box.verify()
    assert report.ok, report.problems
    # This volume has no workspace_limit, so the only alert is that the space is not watched
    # (T04d-2); anything else would be a real problem.
    assert [a.title for a in alerts.sent] == ["El espacio no se vigila"]
    box.close()


def test_a_workspace_changed_between_runs_is_noticed_at_the_next_boot(
    store: SnapshotStore,
    guardian_setup: tuple[Guardian, BlackBox, StubWatcher, StubJail, Alerts],
) -> None:
    guardian, box, _, _, _ = guardian_setup
    reference = store.take(Reason.PERIODIC)
    (store.workspace / "while-down.txt").write_text("nobody was watching")
    try:
        guardian.start()
        (dropped,) = [e for e in box.events() if e.action == "dropped"]
        assert dropped.details["reason"] == "watcher_down"
        assert dropped.snapshot_id == reference.id
        assert len(store.snapshots()) == 2  # and a startup snapshot caught the change
    finally:
        guardian.stop()
        box.close()
