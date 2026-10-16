"""T04b-2 in the VM: snapshots by activity, with the real service and the real OpenClaw.

docs/19-diseno-t04.md, sections 2 and 3. `vigia vigilar` runs as a process with a 3 s cycle;
the agent is the real OpenClaw in its jail. What is proven:

- With nothing changing there is no snapshot, and with a change there is one within a cycle.
- `chmod` and an `mmap` write, which inotify cannot see well, count: Btrfs decides, not inotify.
- The file watcher describes the change with the snapshot BEFORE it (the barrier), end to end.

A running OpenClaw is never "quiet": idle, it writes its SQLite about every 10 s (measured in
test_idle.py), so while it runs every cycle finds a change. Where a test needs "nothing
changed" the agent is frozen with ``docker pause``, which stops every one of its processes.
Where it needs "only this changed" the change is made from the host on the agent's folder (the
agent's own uid, in the VM) with the agent frozen the whole time, so nothing of OpenClaw's can
land in the window; the two tests that make the change inside the agent wait for a snapshot
that HOLDS the change, so a snapshot of OpenClaw's own noise cannot satisfy them.
"""

import mmap
import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.integration.service_kit import CYCLE, Service, wait_until
from vigia.snapshots import Snapshot

pytestmark = pytest.mark.integration

REPEATS = 3
WITHIN_ONE_CYCLE = CYCLE + 12  # a cycle, plus the sync, the snapshot and a loaded VM


@pytest.fixture(autouse=True)
def thawed_after(real_service: Service) -> Iterator[None]:
    """Every test starts and ends with the agent running, so the module's service stays usable."""
    if real_service.jail.is_paused():
        real_service.thaw()
    yield
    if real_service.jail.is_running() and real_service.jail.is_paused():
        real_service.thaw()


def exec_in_agent(service: Service, *argv: str) -> None:
    result = service.jail.exec(list(argv), timeout=60)
    assert result.returncode == 0, (argv, result.stdout, result.stderr)


def quiet(service: Service) -> list[Snapshot]:
    """Freeze the agent and wait until its last writes are snapshotted. Returns the snapshots."""
    service.freeze()
    service.wait_quiet()
    return service.snapshots()


def change_while_thawed(service: Service, *argv: str) -> None:
    """Thaw, make one change inside the agent, freeze again: about a second in which the agent
    can run."""
    service.thaw()
    try:
        exec_in_agent(service, *argv)
    finally:
        service.freeze()


def new_snapshot_within_a_cycle(service: Service, before: list[Snapshot]) -> Snapshot:
    started = time.monotonic()
    after = service.wait_snapshot_after(len(before), WITHIN_ONE_CYCLE)
    assert time.monotonic() - started <= WITHIN_ONE_CYCLE
    return after[-1]


def test_the_test_volume_is_mounted_noatime(btrfs_volume: Path) -> None:
    """With relatime, reading an old file writes its access time, which costs metadata shared
    with the snapshots and could look like activity (docs/19, "Disposición")."""
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    ours = [line.split(" ") for line in mounts if f" {btrfs_volume} " in line]
    assert ours, f"{btrfs_volume} is not a mount point"
    assert "noatime" in ours[-1][5].split(",")


def test_the_service_runs_the_agent_and_records_the_start(real_service: Service) -> None:
    assert real_service.jail.is_running()
    actions = [f"{e.source}/{e.action}" for e in real_service.events()]
    assert actions[0] == "system/service_start"
    assert "snapshot/take" in actions
    assert actions.index("snapshot/take") < actions.index("system/agent_start")
    first = real_service.takes()[0]
    assert first.details["trigger"] == "startup"  # taken with the agent still stopped


def agent_folder(service: Service) -> Path:
    return service.store.workspace / "agente"


def snapshot_has(service: Service, snapshot: Snapshot, relative: str) -> Path | None:
    """The copy of ``relative`` (inside the agent's folder) in ``snapshot``, if it has one."""
    copy = service.store.snapshots_dir / snapshot.id / "agente" / relative
    return copy if copy.exists() else None


def test_without_changes_there_is_no_snapshot(real_service: Service) -> None:
    before = quiet(real_service)
    ctransid = real_service.workspace_ctransid()
    takes = len(real_service.takes())
    time.sleep(5 * CYCLE)  # five cycles, with the service really cycling
    assert real_service.snapshots() == before
    assert len(real_service.takes()) == takes
    assert real_service.workspace_ctransid() == ctransid  # and Btrfs agrees: nothing changed
    # "No snapshot" must not mean "the service died": it is alive and still sees changes.
    assert real_service.process is not None and real_service.process.poll() is None
    name = f"work/control-{int(time.time())}.txt"
    (agent_folder(real_service) / name).write_text("a change after the quiet window")
    after = new_snapshot_within_a_cycle(real_service, before)
    assert snapshot_has(real_service, after, name) is not None


def test_a_change_makes_a_snapshot_within_a_cycle(real_service: Service) -> None:
    before = quiet(real_service)
    name = f"work/created-{int(time.time())}.txt"
    change_while_thawed(real_service, "sh", "-c", f"echo hello > /workspace/{name}")
    new_snapshot_within_a_cycle(real_service, before)
    # The snapshot of the cycle that saw the change HAS the change (not one of OpenClaw's own).
    wait_until(
        lambda: snapshot_has(real_service, real_service.snapshots()[-1], name) is not None,
        WITHIN_ONE_CYCLE,
        "a snapshot with the new file in it",
        context=real_service.diagnosis,
    )
    newest = real_service.snapshots()[-1]
    assert newest.reason == "periodic"
    assert (snapshot_has(real_service, newest, name) or Path()).read_text() == "hello\n"

    def recorded() -> bool:  # the event is written right after the snapshot exists
        return any(e.snapshot_id == newest.id for e in real_service.takes())

    wait_until(recorded, 10, "the take event", context=real_service.diagnosis)
    take = next(e for e in real_service.takes() if e.snapshot_id == newest.id)
    assert take.details["trigger"] == "cycle"


def test_the_watcher_describes_the_change_with_the_snapshot_before_it(
    real_service: Service,
) -> None:
    """inotify only describes, and points at a snapshot that does not contain the change yet:
    rewinding to it undoes the change (docs/19, "La barrera del snapshot_id")."""
    before = quiet(real_service)
    name = f"described-{int(time.time())}.txt"
    change_while_thawed(real_service, "sh", "-c", f"echo hi > /workspace/work/{name}")
    new_snapshot_within_a_cycle(real_service, before)
    wait_until(
        lambda: snapshot_has(real_service, real_service.snapshots()[-1], f"work/{name}"),
        WITHIN_ONE_CYCLE,
        "a snapshot with the new file in it",
        context=real_service.diagnosis,
    )
    after = real_service.snapshots()[-1]

    def described() -> bool:
        return any(e.target == f"work/{name}" for e in real_service.events(source="file"))

    wait_until(described, 20, "the file event", context=real_service.diagnosis)
    event = next(e for e in real_service.events(source="file") if e.target == f"work/{name}")
    assert event.action == "create"
    assert event.snapshot_id is not None
    assert event.snapshot_id != after.id  # not the snapshot that already has the file
    assert event.snapshot_id in {snap.id for snap in real_service.snapshots()}
    assert event.snapshot_id < after.id  # ids sort by time: it is an older one
    assert not (
        real_service.store.snapshots_dir / event.snapshot_id / "agente/work" / name
    ).exists()
    assert (real_service.store.snapshots_dir / after.id / "agente/work" / name).exists()


def snapshot_holds(service: Service, snapshot: Snapshot, kind: str, expected: str) -> bool:
    copy = snapshot_has(service, snapshot, f"work/{kind}-target.bin")
    if copy is None:
        return False
    if kind == "chmod":
        return copy.stat().st_mode & 0o777 == int(expected, 8)
    return copy.read_bytes()[:4] == expected.encode()


def change_from_the_host(target: Path, kind: str, attempt: int) -> str:
    """One chmod or one mmap write on the agent's file, done by us with the agent frozen. The
    mmap write is flushed but the file is closed only afterwards, like any program."""
    if kind == "chmod":
        expected = "600" if attempt % 2 == 0 else "640"
        target.chmod(int(expected, 8))
        return expected
    expected = f"ab{attempt}x"
    with open(target, "r+b") as handle, mmap.mmap(handle.fileno(), 4096) as mapped:
        mapped[0:4] = expected.encode()
        mapped.flush()
    return expected


@pytest.mark.parametrize("kind", ["chmod", "mmap"])
def test_chmod_and_mmap_writes_count(real_service: Service, kind: str) -> None:
    """Neither is a normal write, and inotify misses an mmap write until the file closes (or
    forever). Btrfs's counters see both, and they are what decides. The agent is frozen the
    whole time, so the only change in each round is ours."""
    target = agent_folder(real_service) / "work" / f"{kind}-target.bin"
    real_service.freeze()
    target.write_bytes(b"\0" * 4096)
    for attempt in range(REPEATS):
        before = quiet(real_service)
        expected = change_from_the_host(target, kind, attempt)
        newest = new_snapshot_within_a_cycle(real_service, before)
        assert snapshot_holds(real_service, newest, kind, expected)  # it holds the change


def test_the_agent_runs_and_changes_make_a_snapshot_every_cycle_without_any_help(
    real_service: Service,
) -> None:
    """The other side of the same fact: a running OpenClaw changes its own workspace all the
    time, so with the agent thawed there is a snapshot per cycle (docs/19: no noise rule)."""
    assert not real_service.jail.is_paused()
    count = len(real_service.snapshots())
    real_service.wait_snapshot_after(count, 60)
    assert re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z-periodic", real_service.snapshots()[-1].id)
