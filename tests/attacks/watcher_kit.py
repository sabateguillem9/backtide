"""What the file-watcher scenarios share (test_watcher_flood_attacks.py and the like): reading
the kernel's own account of what the service watches, the black box's raw bytes and the file
events by kind. Host side only; the attacks themselves are in scripts/.
"""

import os
import re
import signal
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from tests.integration.service_kit import CYCLE, Service, wait_until
from vigia.blackbox import Event

# `fdinfo` prints one line per watch; on btrfs its file handle is the inode (8 bytes), the
# subvolume id (8 bytes) and the generation (4): that tells a watch apart from the same inode
# number in another subvolume (docs/19, "Tests en la VM").
FDINFO_RE = re.compile(
    r"inotify wd:(?P<wd>[0-9a-f]+) ino:(?P<ino>[0-9a-f]+) sdev:(?P<sdev>[0-9a-f]+) "
    r"mask:\S+ ignored_mask:\S+ fhandle-bytes:\S+ fhandle-type:\S+ f_handle:(?P<handle>[0-9a-f]+)"
)


WITHIN = CYCLE + 60  # a cycle, the sync, the snapshot, a summary every 10 s and a loaded VM


def started(make_real_service: Callable[..., Service]) -> Service:
    """A fresh service with its agent running and the first snapshot made. Each scenario gets
    its own: what one leaves unwatched or flooded must not change what the next one sees."""
    service = make_real_service()
    service.start()
    service.wait_ready()
    wait_until(service.snapshots, WITHIN, "the first snapshot", context=service.diagnosis)
    return service


def calm(service: Service, seconds: float = 20.0) -> None:
    """Wait until the agent's own start-up noise is over: OpenClaw writes hundreds of files when
    it starts and that empties the watcher's token bucket (5 records a second after a burst of
    1.000), so what a test does right then would be folded into a summary instead of getting a
    record of its own. Quiet means no create, delete, move or summary for ``seconds``."""
    seen = {"seq": last_seq(service), "at": time.monotonic()}

    def quiet() -> bool:
        noisy = [
            e
            for e in service.box.events(since_seq=seen["seq"])
            if e.source == "file" and e.action in ("create", "delete", "move", "summary")
        ]
        seen["seq"] = last_seq(service)
        if noisy:
            seen["at"] = time.monotonic()
        return time.monotonic() - seen["at"] >= seconds

    wait_until(quiet, 240, "the agent's start-up noise to end", interval=1.0)


@dataclass(frozen=True)
class Watch:
    """A watch as the kernel reports it: filesystem, subvolume and inode."""

    sdev: int
    subvolume: int
    ino: int


def watches_of(pid: int) -> list[Watch]:
    """Every watch of every inotify instance of process ``pid`` (same user), from fdinfo."""
    found: list[Watch] = []
    for name in os.listdir(f"/proc/{pid}/fd"):
        try:
            if os.readlink(f"/proc/{pid}/fd/{name}") != "anon_inode:inotify":
                continue
            text = Path(f"/proc/{pid}/fdinfo/{name}").read_text()
        except OSError:
            continue  # the descriptor closed meanwhile
        lines = [line for line in text.splitlines() if line.startswith("inotify wd:")]
        matched = list(FDINFO_RE.finditer(text))
        assert len(lines) == len(matched), [ln for ln in lines if not FDINFO_RE.match(ln)][:3]
        for match in matched:
            handle = bytes.fromhex(match["handle"])
            if len(handle) == 20:
                subvolume, ino = (
                    int.from_bytes(handle[8:16], "little"),
                    int.from_bytes(handle[:8], "little"),
                )
            else:  # not btrfs: certainly not the agent's workspace
                subvolume, ino = -1, int(match["ino"], 16)
            found.append(Watch(int(match["sdev"], 16), subvolume, ino))
    return found


def service_watches(service: Service) -> list[Watch]:
    """The watches of the running `vigia vigilar` process of ``service``."""
    return watches_of(service.require_process().pid)


def watches_outside(service: Service, watches: list[Watch]) -> list[Watch]:
    """The watches that are not in the agent's workspace subvolume of the service's volume:
    there must be none, whatever the agent does with links. A watch on any other filesystem
    has a different file handle (not btrfs's 20 bytes) and counts as outside."""
    mine = service.store.workspace_id()
    return [w for w in watches if w.subvolume != mine]


def raw_blackbox_bytes(service: Service) -> bytes:
    """Everything the black box wrote beside its key: database, WAL, shared memory and
    checkpoint (the state folder also has the gateway token, which is not ours to read)."""
    database = service.config.blackbox_db
    parts = [
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
        service.config.blackbox_checkpoint,
    ]
    return b"".join(path.read_bytes() for path in parts if path.exists())


def file_events(service: Service, *actions: str, since_seq: int = 0) -> list[Event]:
    """The ``file`` events of the black box after ``since_seq``, of those actions (all if none)."""
    return [
        event
        for event in service.box.events(source="file", since_seq=since_seq)
        if not actions or event.action in actions
    ]


def last_seq(service: Service) -> int:
    """The sequence number of the newest event (0 if none)."""
    found = service.box.events(newest_first=True, limit=1)
    return found[0].seq if found else 0


def dropped(service: Service, reason: str, since_seq: int = 0) -> list[Event]:
    return [
        e
        for e in file_events(service, "dropped", since_seq=since_seq)
        if e.details["reason"] == reason
    ]


def wait_for_a_record(service: Service, name: str, since_seq: int = 0) -> Event:
    """Prove the watcher is alive: make a new empty file in the agent's work folder every few
    seconds (``<name>-1``, ``<name>-2``...) until one gets a ``create`` record of its own. One
    file is not enough after a flood: the token bucket may still be empty, and then it is
    folded into a summary; it refills at 5 a second."""
    made = 0
    found: list[Event] = []

    def context() -> str:
        recent = [(e.action, e.target) for e in file_events(service, since_seq=since_seq)][-12:]
        return (
            f"made {made} files; watches: {len(service_watches(service))}; "
            f"last file events: {recent}\n{service.diagnosis()}"
        )

    def attempt() -> bool:
        nonlocal made
        made += 1
        service.jail.exec(["sh", "-c", f"echo x > /workspace/work/{name}-{made}"], check=True)
        time.sleep(3)
        found[:] = [
            e
            for e in file_events(service, "create", since_seq=since_seq)
            if e.target.startswith(f"work/{name}-")
        ]
        return bool(found)

    wait_until(attempt, 3 * WITHIN, f"a record of a new file ({name})", context=context)
    return found[0]


def make_watched_folder(service: Service, relative: str) -> None:
    """Make ``relative`` (inside the agent's /workspace) and wait until the service watches it.

    Why it existed: a name made in the instant between the watcher opening a NEW folder and
    putting its watch on it was lost, with no record and no ``dropped`` (btrfs fixes what a
    listing returns when the folder is opened, and that was before the watch). That bug is
    fixed: the watcher now lists through a descriptor opened after the watch, and
    tests/integration/test_watcher_listing_race.py guards it. The wait is no longer needed for
    correctness; it only keeps these scenarios about something else deterministic."""
    service.jail.exec(["mkdir", "-p", f"/workspace/{relative}"], check=True)
    folder = service.store.workspace / "agente" / relative
    wait_until(
        lambda: folder.stat().st_ino in {w.ino for w in service_watches(service)},
        WITHIN,
        f"the new folder {relative} to be watched",
        context=service.diagnosis,
    )


def in_snapshot(service: Service, snapshot_id: str, relative: str) -> Path:
    """``relative`` (a path inside the agent's folder, like a record's target) as the snapshot
    ``snapshot_id`` holds it."""
    return service.store.snapshots_dir / snapshot_id / "agente" / relative


@contextmanager
def service_stopped(service: Service) -> Iterator[None]:
    """SIGSTOP the service (its reader thread included) and SIGCONT it afterwards, whatever
    happens. The kernel keeps queueing the agent's events meanwhile, up to its limit: that is
    how a test makes an overflow certain instead of racing the reader."""
    process = service.require_process()
    process.send_signal(signal.SIGSTOP)
    try:
        yield
    finally:
        process.send_signal(signal.SIGCONT)
