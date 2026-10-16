"""T04a in the VM: the file watcher on the real inotify and the real OpenClaw.

docs/19-diseno-t04.md, section 1 and "Tests". Three kinds of tests:
- through the real agent's bind mount (``running_agent.exec``): create, modify, delete and move,
  and the rewind, which is the last test of the module because it restarts the agent;
- the hostile cases (a flood that overflows the kernel queue, a bomb of directories, links to
  ``/`` and to the snapshots, a directory swapped for a link) on a plain folder of the shared
  btrfs, where the host plays the agent;
- the kernel's own account of what is watched (``/proc/self/fdinfo``), the proof that nothing
  outside the agent's folder, and nothing in a workspace that was rewound, is watched.

``fdinfo`` prints, for each watch, the filesystem's file handle. On btrfs it is the inode (8
bytes), the subvolume id (8 bytes) and the generation (4): that is how a watch is told apart
from the same inode number in another subvolume.
"""

import errno
import os
import re
import shutil
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.test_sensors_inotify import TestOpenBeneath as _UnitOpenBeneath
from tests.test_sensors_inotify import TestOpenBeneathHardening as _UnitHardening
from tests.test_sensors_inotify import root  # noqa: F401 - the fixture of those cases
from vigia.blackbox import BlackBox, Event
from vigia.sensors import inotify
from vigia.sensors.files import FileWatcher, WatcherConfig
from vigia.sensors.inotify import IN_CREATE, IN_ONLYDIR, Inotify
from vigia.snapshots import Reason
from vigia.snapshots.store import SnapshotStore

pytestmark = pytest.mark.integration

KEY = bytes(range(32))
FDINFO_RE = re.compile(
    r"inotify wd:(?P<wd>[0-9a-f]+) ino:(?P<ino>[0-9a-f]+) sdev:(?P<sdev>[0-9a-f]+) "
    r"mask:\S+ ignored_mask:\S+ fhandle-bytes:\S+ fhandle-type:\S+ f_handle:(?P<handle>[0-9a-f]+)"
)
FAST = {"dump_interval": 0.1}


@dataclass(frozen=True)
class Watch:
    """A watch as the kernel reports it: filesystem, subvolume and inode."""

    sdev: int
    subvolume: int
    ino: int


def my_watches() -> list[Watch]:
    """Every watch of every inotify instance of this process, read from /proc/self/fdinfo."""
    found: list[Watch] = []
    for name in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{name}") != "anon_inode:inotify":
                continue
            text = Path(f"/proc/self/fdinfo/{name}").read_text()
        except OSError:
            continue  # the descriptor closed meanwhile
        lines = [line for line in text.splitlines() if line.startswith("inotify wd:")]
        matched = list(FDINFO_RE.finditer(text))
        assert len(lines) == len(matched), [ln for ln in lines if not FDINFO_RE.match(ln)][:3]
        for match in matched:
            handle = bytes.fromhex(match["handle"])
            assert len(handle) == 20, f"unexpected btrfs file handle: {match['handle']}"
            found.append(
                Watch(
                    sdev=int(match["sdev"], 16),
                    subvolume=int.from_bytes(handle[8:16], "little"),
                    ino=int.from_bytes(handle[:8], "little"),
                )
            )
    return found


def watch_of(path: Path | str) -> Watch:
    """The identity of a directory, as fdinfo will show it, from a probe instance."""
    probe = Inotify()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            probe.add_watch(fd, IN_CREATE | IN_ONLYDIR)
        finally:
            os.close(fd)
        text = Path(f"/proc/self/fdinfo/{probe.fileno()}").read_text()
    finally:
        probe.close()
    (match,) = FDINFO_RE.finditer(text)
    handle = bytes.fromhex(match["handle"])
    return Watch(
        int(match["sdev"], 16),
        int.from_bytes(handle[8:16], "little"),
        int.from_bytes(handle[:8], "little"),
    )


def eventually(predicate: Callable[[], object], timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail("timed out")
        time.sleep(0.05)


def settle(watcher: FileWatcher) -> None:
    """Read everything queued, finish every scan, and write what is pending."""
    assert watcher.drain()
    assert watcher.wait_idle(30)
    assert watcher.drain()
    watcher.flush()


def records(box: BlackBox, source: str = "file", action: str | None = None) -> list[Event]:
    return [e for e in box.events(source=source) if action in (None, e.action)]


def by_target(box: BlackBox, action: str | None = None) -> dict[str, Event]:
    return {e.target: e for e in records(box, action=action)}


@pytest.fixture
def box(tmp_path: Path) -> Iterator[BlackBox]:
    with BlackBox(
        tmp_path / "blackbox.db", KEY, checkpoint_path=tmp_path / "blackbox.checkpoint"
    ) as black_box:
        yield black_box
        assert black_box.verify().ok  # whatever the watcher wrote is a valid chain


@contextmanager
def watching(
    folder: Path, box: BlackBox, store: SnapshotStore, **config: object
) -> Iterator[FileWatcher]:
    watcher = FileWatcher(
        folder,
        box,
        workspace_id=store.workspace_id,
        config=WatcherConfig(**{"dump_interval": 0.1, **config}),  # type: ignore[arg-type]
    )
    try:
        assert watcher.arm(store.take(Reason.MANUAL).id)
        yield watcher
    finally:
        watcher.close()


@pytest.fixture
def plain_agent_dir(store: SnapshotStore) -> Path:
    """A folder `agente` in this test's own workspace: the host plays the agent."""
    folder = store.workspace / "agente"
    folder.mkdir()
    return folder


# -- through the real agent -----------------------------------------------------------------


@pytest.fixture
def agent_watcher(running_agent, box: BlackBox) -> Iterator[FileWatcher]:  # noqa: ANN001
    snapshot = running_agent.store.take(Reason.MANUAL)
    watcher = FileWatcher(
        running_agent.workspace,
        box,
        workspace_id=running_agent.store.workspace_id,
        config=WatcherConfig(dump_interval=None),  # one window per settle(): deterministic
    )
    try:
        assert watcher.arm(snapshot.id)
        yield watcher
    finally:
        watcher.close()


def test_the_real_agent_creates_modifies_moves_and_deletes(running_agent, agent_watcher, box):  # noqa: ANN001
    running_agent.exec(
        ["sh", "-c", "mkdir -p /workspace/work/pre && echo old > /workspace/work/pre/existing.txt"],
        check=True,
    )
    settle(agent_watcher)
    before = len(records(box))
    script = (
        "cd /workspace/work && "
        "echo hello > notes.md && echo more >> notes.md && "
        "echo old2 >> pre/existing.txt && "
        "mkdir sub && mv notes.md sub/renamed.md && "
        "echo tmp > scratch.tmp && rm scratch.tmp && "
        "echo bye > doomed.txt && sleep 0.3 && rm pre/existing.txt"
    )
    running_agent.exec(["sh", "-c", script], check=True)
    settle(agent_watcher)

    found = {k: v for k, v in by_target(box).items() if k.startswith("work/")}
    assert len(records(box)) > before
    assert found["work/sub"].action == "create" and found["work/sub"].details["type"] == "dir"
    moved = found["work/sub/renamed.md"]
    assert moved.action == "create"  # born and moved inside one window: a create at the end
    assert moved.details["type"] == "file" and moved.details["size"] == 11  # "hello\nmore\n"
    assert moved.details["writes"] >= 2 and moved.details["nlink"] == 1
    assert "work/notes.md" not in found  # the move is not a delete plus a create
    scratch = found["work/scratch.tmp"]
    assert scratch.action == "delete" and scratch.details["transient"] is True
    assert found["work/pre/existing.txt"].action in {"modify", "delete"}
    assert found["work/doomed.txt"].action == "create"
    assert all(not t.startswith("/") for t in by_target(box))  # relative to the agent's folder
    assert all(e.details.get("workspace_id") for e in records(box) if e.action != "dropped")
    assert all(e.snapshot_id for e in records(box))


def test_a_move_of_something_that_existed_is_one_move_with_its_origin(
    running_agent,  # noqa: ANN001
    agent_watcher,
    box,
):
    running_agent.exec(["sh", "-c", "echo keep > /workspace/work/before-move.txt"], check=True)
    settle(agent_watcher)
    agent_watcher.set_current(running_agent.store.take(Reason.MANUAL).id)
    head = box.head()[0]
    running_agent.exec(
        ["mv", "/workspace/work/before-move.txt", "/workspace/work/after-move.txt"], check=True
    )
    settle(agent_watcher)
    window = {e.target: e for e in box.events(since_seq=head, source="file")}
    moved = window["work/after-move.txt"]
    assert moved.action == "move" and moved.details["from"] == "work/before-move.txt"
    assert "work/before-move.txt" not in window  # one record, not a delete plus a create


def test_the_agent_in_idle_does_not_flood_the_black_box(running_agent, agent_watcher, box):  # noqa: ANN001
    settle(agent_watcher)
    time.sleep(3)
    settle(agent_watcher)
    assert len(records(box)) < 50  # OpenClaw's own bookkeeping in state/ is a trickle


# -- the barrier on the real kernel ---------------------------------------------------------


def test_a_change_before_a_snapshot_points_to_the_snapshot_before_it(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    (plain_agent_dir / "doomed.txt").write_text("precious")
    with watching(plain_agent_dir, box, store) as watcher:
        first = watcher.current
        (plain_agent_dir / "doomed.txt").unlink()  # at t0
        second = watcher.barrier(lambda: store.take(Reason.PERIODIC))  # S2 at t0 + e
        (plain_agent_dir / "later.txt").write_text("x")  # after S2
        settle(watcher)
    found = by_target(box)
    assert found["doomed.txt"].snapshot_id == first  # S2 no longer has the file
    assert found["later.txt"].snapshot_id == second.id
    assert first != second.id


# -- hostile cases ---------------------------------------------------------------------------


class GatedInotify(Inotify):
    """An inotify whose read() waits for a gate: the reader falls behind on purpose."""

    gate = threading.Event()

    def read(self) -> bytes:
        self.gate.wait(60)
        return super().read()


def test_a_flood_overflows_the_kernel_queue_and_is_recorded_not_lost_silently(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    work = plain_agent_dir / "work"
    work.mkdir()
    gate = threading.Event()
    factory = type("Gated", (GatedInotify,), {"gate": gate})
    watcher = FileWatcher(
        plain_agent_dir,
        box,
        workspace_id=store.workspace_id,
        config=WatcherConfig(**FAST, max_watches=500, bucket_burst=200, bucket_rate=500),
        inotify_factory=factory,
    )
    try:
        gate.set()  # armed with a reader that works...
        assert watcher.arm(store.take(Reason.MANUAL).id)
        gate.clear()  # ...which now stops reading while the agent floods
        for i in range(30_000):
            os.close(os.open(work / f"f{i}", os.O_CREAT | os.O_WRONLY))  # CREATE + CLOSE_WRITE
        gate.set()
        settle(watcher)
        assert watcher.is_armed
        stats = watcher.stats()
        assert stats.overflows >= 1 and stats.rescans >= 1
        (dropped,) = [
            e for e in records(box, action="dropped") if e.details["reason"] == "queue_overflow"
        ]
        assert dropped.risk == 1 and dropped.details["count"] is None
        assert dropped.details["since"] <= dropped.details["until"]
        assert dropped.snapshot_id  # the point to rewind to for whatever the overflow hid
        # the rate limit held: a bounded number of records, and the rest folded in summaries
        assert len(records(box, action="create")) <= 200 + 100
        assert records(box, action="summary")
        # and the watcher still sees: a NEW directory is watched and described (the bucket
        # has refilled meanwhile)
        time.sleep(1.5)
        (work / "after").mkdir()
        (work / "after" / "x").write_text("x")
        settle(watcher)
        assert "work/after/x" in by_target(box)
        assert watch_of(work / "after") in my_watches()
    finally:
        gate.set()
        watcher.close()


def test_a_bomb_of_directories_is_capped_and_recorded_every_cycle(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    bomb = plain_agent_dir / "bomb"
    for i in range(120):
        (bomb / f"d{i}").mkdir(parents=True)
    cap = 40
    with watching(plain_agent_dir, box, store, max_watches=cap, rescan_cooldown=1.0) as watcher:
        filesystem = watch_of(plain_agent_dir).sdev
        mine = [w for w in my_watches() if w.sdev == filesystem]
        assert len(mine) <= cap
        assert watcher.unwatched_count() > 80
        assert watcher.report_unwatched() and watcher.report_unwatched()
        dropped = [
            e for e in records(box, action="dropped") if e.details["reason"] == "unwatched_dirs"
        ]
        assert len(dropped) == 2  # EVERY cycle with changes, not only the first
        assert dropped[0].details["reasons"].keys() == {"watch_limit"}
        # the watcher is alive and describes what it can see
        watched_dir = next(p for p in sorted(bomb.iterdir()) if watch_of(p) in mine)
        (watched_dir / "ping").write_text("x")
        settle(watcher)
        assert f"bomb/{watched_dir.name}/ping" in by_target(box)
        # a hundred more directories, created now: still capped, still alive
        for i in range(100):
            (plain_agent_dir / "more" / f"m{i}").mkdir(parents=True)
        settle(watcher)
        assert len([w for w in my_watches() if w.sdev == filesystem]) <= cap
        # the agent deletes its decoy folders: the watches are freed and others are armed
        assert watcher.watch_count() == cap - 1  # full
        for victim in list(bomb.iterdir()):
            if watch_of(victim) in my_watches():
                shutil.rmtree(victim)
        assert watcher.drain()
        eventually(lambda: watcher.stats().rescans >= 1)
        time.sleep(
            3
        )  # a rescan in the middle of the deletes saw a full tree: the next one fixes it
        settle(watcher)
        assert watcher.watch_count() == cap - 1  # the freed places are in use again
        assert len([w for w in my_watches() if w.sdev == filesystem]) <= cap


LONG = "n" * 255  # the longest name there is: 16 levels of it already pass PATH_MAX


def make_chain(top: Path, levels: int, *, keep: int | None = None) -> int | None:
    """``levels`` nested directories named LONG below ``top``, made through descriptors (the
    path cannot be written as a string). Returns an open descriptor of level ``keep``."""
    fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY)
    kept = None
    try:
        for level in range(1, levels + 1):
            os.mkdir(LONG, dir_fd=fd)
            child = os.open(LONG, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            if level == keep:
                kept = os.dup(child)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)
    return kept


def test_a_chain_of_three_thousand_directories_is_capped_by_depth_not_by_path_length(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    max_depth = WatcherConfig().max_depth
    deepest = make_chain(plain_agent_dir, 3000, keep=max_depth)  # 765 KB of path
    assert deepest is not None
    try:
        with watching(plain_agent_dir, box, store) as watcher:
            filesystem = watch_of(plain_agent_dir).sdev
            mine = [w for w in my_watches() if w.sdev == filesystem]
            assert len(mine) == max_depth + 2  # the 64 levels, the agent's folder, the sentinel
            assert watcher.unwatched_count() == 1
            assert watcher.report_unwatched()
            (dropped,) = records(box, action="dropped")
            assert dropped.details["reasons"] == {"depth": 1}
            # a file in the deepest watched level: 16 KiB of path, described all the same
            os.close(os.open("deep.txt", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=deepest))
            settle(watcher)
    finally:
        os.close(deepest)
    (created,) = records(box, action="create")
    assert created.details["name"] == "deep.txt" and "truncated" in created.target
    assert created.details["type"] == "file"  # looked at below the agent's folder, in pieces


def test_moving_chains_into_each_others_leaves_never_passes_the_depth_cap(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    """The agent builds two chains of 40 levels and moves one into the leaf of the other:
    80 levels would be watched (and paths of 20 KB built for every event) without the cap."""
    (plain_agent_dir / "a").mkdir()
    (plain_agent_dir / "b").mkdir()
    make_chain(plain_agent_dir / "a", 39)
    leaf = make_chain(plain_agent_dir / "b", 39, keep=39)
    assert leaf is not None
    max_depth = WatcherConfig().max_depth
    try:
        with watching(plain_agent_dir, box, store) as watcher:
            filesystem = watch_of(plain_agent_dir).sdev
            assert len([w for w in my_watches() if w.sdev == filesystem]) == 82
            top = os.open(plain_agent_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.rename("a", "a", src_dir_fd=top, dst_dir_fd=leaf)
            finally:
                os.close(top)
            settle(watcher)
            mine = [w for w in my_watches() if w.sdev == filesystem]
            assert len(mine) == max_depth + 2  # b's 40 levels, a's first 24, root, sentinel
            assert watcher.report_unwatched()
            dropped = records(box, action="dropped")[-1]
            assert dropped.details["reasons"] == {"depth": 1}
    finally:
        os.close(leaf)
    (moved,) = records(box, action="move")
    assert moved.details["from"] == "a" and moved.details["name"] == "a"


def gated_watcher(folder: Path, box: BlackBox, store: SnapshotStore) -> tuple[FileWatcher, Any]:
    gate = threading.Event()
    factory = type("Gated", (GatedInotify,), {"gate": gate})
    watcher = FileWatcher(
        folder,
        box,
        workspace_id=store.workspace_id,
        config=WatcherConfig(**FAST),
        inotify_factory=factory,
    )
    gate.set()
    assert watcher.arm(store.take(Reason.MANUAL).id)
    return watcher, gate


def test_a_directory_made_just_before_its_parent_is_renamed_is_watched_where_it_ended(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    """``mkdir work/y && mv work z`` while the reader is behind: the walk of y must follow
    its parent (it waits by watch, not by path)."""
    (plain_agent_dir / "work").mkdir()
    watcher, gate = gated_watcher(plain_agent_dir, box, store)
    try:
        gate.clear()
        (plain_agent_dir / "work" / "y").mkdir()
        (plain_agent_dir / "work").rename(plain_agent_dir / "z")
        gate.set()
        settle(watcher)
        assert watch_of(plain_agent_dir / "z" / "y") in my_watches()
        assert watcher.unwatched_count() == 0
        (plain_agent_dir / "z" / "y" / "f").write_text("x")
        settle(watcher)
        assert "z/y/f" in by_target(box)
    finally:
        gate.set()
        watcher.close()


def test_a_directory_swapped_for_a_link_to_the_root_before_its_walk_is_not_followed(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    watcher, gate = gated_watcher(plain_agent_dir, box, store)
    try:
        gate.clear()
        for name in ("d1", "d2", "d3"):
            (plain_agent_dir / name).mkdir()
            (plain_agent_dir / name).rmdir()
            (plain_agent_dir / name).symlink_to("/")
        gate.set()
        settle(watcher)
        assert watch_of("/") not in my_watches()
        assert watcher.unwatched_count() == 0  # links, not directories: nothing to watch
    finally:
        gate.set()
        watcher.close()


class TestOpenBeneathWithOpenat2(_UnitOpenBeneath):
    """The cases that run with the walking fallback on the Mac, against the real openat2."""

    def test_openat2_is_the_one_in_use(self) -> None:
        assert inotify._openat2_usable()

    def test_a_mount_crossing_is_refused(self) -> None:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for rel in (b"proc", b"proc/self"):
                with pytest.raises(OSError) as raised:
                    inotify.open_beneath(fd, rel, os.O_RDONLY | os.O_DIRECTORY)
                assert raised.value.errno == errno.EXDEV
        finally:
            os.close(fd)

    def test_a_path_longer_than_path_max_is_opened_in_pieces(self, tmp_path: Path) -> None:
        make_chain(tmp_path, 40)
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            rel = b"/".join([LONG.encode()] * 40)  # 10 KB
            os.close(inotify.open_beneath(fd, rel, os.O_RDONLY | os.O_DIRECTORY))
        finally:
            os.close(fd)


class TestOpenBeneathWithTheLinuxFallback(_UnitOpenBeneath):
    """The same cases with the fallback forced, as under a seccomp filter without openat2."""

    @pytest.fixture(autouse=True)
    def _without_openat2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(inotify, "_openat2_usable", lambda: False)


class TestOpenBeneathHardeningInTheVM(_UnitHardening):
    """The hardening cases on Linux: /proc is the mount the fallback must not cross."""


def test_links_to_the_root_and_to_the_snapshots_are_never_watched(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    control = plain_agent_dir / "control"
    control.mkdir()
    (control / "to_root").symlink_to("/")
    (control / "to_snapshots").symlink_to(store.snapshots_dir)
    (control / "up").symlink_to("../../snapshots")
    (control / "self").symlink_to(".")
    with watching(plain_agent_dir, box, store) as watcher:
        # one created after arming, so the scanner of new directories walks it too
        late = plain_agent_dir / "late"
        late.mkdir()
        (late / "to_root").symlink_to("/")
        (late / "to_snapshots").symlink_to(store.snapshots_dir)
        settle(watcher)
        watched = set(my_watches())
        assert watch_of("/") not in watched
        assert watch_of(store.snapshots_dir) not in watched
        assert watch_of(control) in watched and watch_of(late) in watched
        assert watch_of(store.workspace) in watched  # the sentinel


def test_a_directory_swapped_for_a_link_to_the_host_is_never_read(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    (plain_agent_dir / "swap").mkdir()
    with watching(plain_agent_dir, box, store, dump_interval=None) as watcher:
        (plain_agent_dir / "swap" / "passwd").write_text("agent file")
        assert watcher.drain()
        # between the event and the write to the black box the agent swaps the directory
        (plain_agent_dir / "swap" / "passwd").unlink()
        (plain_agent_dir / "swap").rmdir()
        (plain_agent_dir / "swap").symlink_to("/etc")
        watcher.flush()
    record = by_target(box)["swap/passwd"]
    assert record.details["type"] == "unknown"
    assert "size" not in record.details and "mode" not in record.details


def test_special_files_and_hostile_names_are_described_without_being_opened(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    with watching(plain_agent_dir, box, store) as watcher:
        os.mkfifo(plain_agent_dir / "fifo")  # opening it for reading would block forever
        (plain_agent_dir / "esc\x1b[2Jape\nname").write_text("x")
        (plain_agent_dir / "token=SUPERSECRETVALUE0123").write_text("x")
        os.close(os.open(os.fsencode(plain_agent_dir) + b"/bad\xff\xfename", os.O_CREAT))
        os.link(plain_agent_dir / "token=SUPERSECRETVALUE0123", plain_agent_dir / "hard")
        settle(watcher)
    found = by_target(box)
    assert found["fifo"].details["type"] == "other"
    assert "esc\x1b[2Jape\nname" in found  # stored as data (JSON escapes it), never executed
    assert "token=[REDACTED]" in found
    assert any(t.startswith("bad\\udcff") for t in found)
    assert found["hard"].details["nlink"] == 2
    assert not any("SUPERSECRETVALUE0123" in t for t in found)


def test_a_workspace_swapped_without_a_rewind_is_noticed_and_rearmed(
    store: SnapshotStore, plain_agent_dir: Path, box: BlackBox
):
    from contextlib import nullcontext

    (plain_agent_dir / "work").mkdir()
    with watching(plain_agent_dir, box, store) as watcher:
        old = store.workspace_id()
        snapshot = store.take(Reason.MANUAL)
        store.restore(snapshot.id, quiesce=nullcontext)  # a swap the watcher was NOT told about
        new = store.workspace_id()
        assert new != old
        # Two things notice it: the sentinel (MOVE_SELF on the swapped subvolume, asynchronous)
        # and the cycle's safety net. Whichever is first re-arms; the other finds nothing to do.
        watcher.rearm_if_moved(new)
        eventually(
            lambda: records(box, "system", "watcher_armed")[-1].details["workspace_id"] == new
        )
        (store.workspace / "agente" / "work" / "new.txt").write_text("x")
        settle(watcher)
        assert "work/new.txt" in by_target(box)
        (lost,) = records(box, "system", "watcher_lost")
        assert lost.risk == 2
        filesystem = watch_of(store.root).sdev
        assert not any(w.subvolume == old for w in my_watches() if w.sdev == filesystem)
        assert not watcher.rearm_if_moved(new)


# -- the rewind, with the real agent (last: it restarts it) ---------------------------------


def test_after_a_rewind_nothing_watches_the_old_workspace_and_the_new_one_is_watched(
    running_agent,  # noqa: ANN001
    agent_watcher,
    box,
):
    store = running_agent.store
    agent = running_agent
    agent.exec(
        ["sh", "-c", "mkdir -p /workspace/work/keep && echo precious > /workspace/work/keep/a.txt"],
        check=True,
    )
    settle(agent_watcher)
    agent_watcher.barrier(lambda: store.take(Reason.PERIODIC))  # the point to come back to
    agent.exec(["rm", "-rf", "/workspace/work/keep"], check=True)
    settle(agent_watcher)
    deleted = by_target(box, "delete")["work/keep/a.txt"]
    target = deleted.snapshot_id
    assert target  # the snapshot BEFORE the delete: the one that still has the file
    old_id = store.workspace_id()
    filesystem = watch_of(store.root).sdev

    @contextmanager
    def quiesce() -> Iterator[None]:
        with ExitStack() as stack:
            stack.enter_context(agent.quiesce())  # the agent stops first (its last writes count)
            stack.enter_context(agent_watcher.suspended(target))
            yield

    started = time.monotonic()
    result = store.restore(target, quiesce=quiesce)
    assert time.monotonic() - started < 120
    new_id = store.workspace_id()
    assert new_id != old_id and result.undo is not None

    # the files are back
    assert (agent.workspace / "work" / "keep" / "a.txt").read_text() == "precious\n"
    # nothing watches the old workspace (now the undo point in snapshots/)
    watches = [w for w in my_watches() if w.sdev == filesystem]
    assert watches and not any(w.subvolume == old_id for w in watches)

    # the new one is watched directory by directory: the kernel's list equals the real folders
    def real_directories() -> set[int]:
        found = {watch_of(agent.workspace).ino}
        for folder, names, _ in os.walk(agent.workspace):
            found |= {watch_of(Path(folder) / n).ino for n in names}
        return found

    sentinel = watch_of(store.workspace).ino

    def watched_inodes() -> set[int]:
        return {w.ino for w in my_watches() if w.sdev == filesystem}

    def same() -> bool:
        got, want = watched_inodes(), real_directories() | {sentinel}
        same.diff = (len(got), len(want), sorted(got - want)[:5], sorted(want - got)[:5])  # type: ignore[attr-defined]
        return got == want

    try:
        eventually(same)
    except BaseException:
        got = watched_inodes()
        missing = [
            os.path.relpath(Path(folder) / n, agent.workspace)
            for folder, names, _ in os.walk(agent.workspace)
            for n in names
            if watch_of(Path(folder) / n).ino not in got
        ]
        pytest.fail(
            f"watched vs real directories: {same.diff} missing={missing[:12]} "
            f"unwatched={agent_watcher.unwatched_count()} stats={agent_watcher.stats()} "
            f"tree={agent_watcher.watch_count()}"
        )
    assert {w.subvolume for w in my_watches() if w.sdev == filesystem} == {new_id}
    assert not agent_watcher.rearm_if_moved(new_id)  # the cycle's safety net has nothing to do
    # and a write after the rewind gives its event, pointing to the snapshot rewound to
    agent.exec(["sh", "-c", "echo back > /workspace/work/after-rewind.txt"], check=True)
    settle(agent_watcher)
    after = by_target(box)["work/after-rewind.txt"]
    assert after.snapshot_id == target and after.details["workspace_id"] == new_id
    armed = records(box, "system", "watcher_armed")
    assert armed[-1].details["workspace_id"] == new_id
    assert box.verify().ok
