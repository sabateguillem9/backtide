"""The file watcher lists a folder through a descriptor opened AFTER its watch, on real btrfs.

Btrfs fixes the end of a directory listing when the directory is opened. The watcher used to
open a new folder, put its watch and list it through that same descriptor: a name made in the
instant between the open and the watch was in neither the listing nor the events, and it was
lost with no ``dropped`` (docs/19: nothing is lost in silence). Each case runs with openat2 and
with the walking fallback (a seccomp filter without openat2), which used to answer ``.`` with a
dup of the old descriptor and so had the same window on the agent's folder itself.

- the agent's real timing: a process makes a folder and files in it as fast as it can, many
  times (before the fix, about three runs in four lost one to four names);
- the window hit on purpose: an inotify that does what the agent would just before the watch.
"""

import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox
from backtide.sensors import inotify
from backtide.sensors.files import FileWatcher, WatcherConfig
from backtide.sensors.inotify import Inotify
from backtide.snapshots import Reason
from backtide.snapshots.store import SnapshotStore
from tests.integration.test_file_watcher import (  # noqa: F401 - box and plain_agent_dir are fixtures
    box,
    by_target,
    my_watches,
    plain_agent_dir,
    settle,
    watch_of,
)

pytestmark = pytest.mark.integration

ROUNDS = 25
FILES = 40
AGENT = r"""
import os, sys
base = sys.argv[1].encode()
os.mkdir(base)
for i in range(int(sys.argv[2])):
    with open(os.path.join(base, b"f%02d" % i), "wb"):
        pass
"""


@pytest.fixture(params=["openat2", "fallback"])
def resolver(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    if request.param == "fallback":
        monkeypatch.setattr(inotify, "_openat2_usable", lambda: False)
    else:
        assert inotify._openat2_usable()
    return str(request.param)


class HookedInotify(Inotify):
    """Runs ``before_watch[inode]`` once, just before the first watch on that directory."""

    def __init__(self, before_watch: dict[int, Callable[[], object]]) -> None:
        super().__init__()
        self.before_watch = before_watch

    def add_watch(self, dir_fd: int, mask: int) -> int:
        hook = self.before_watch.pop(os.fstat(dir_fd).st_ino, None)
        if hook is not None:
            hook()
        return super().add_watch(dir_fd, mask)


def hooked_watcher(
    folder: Path,
    black_box: BlackBox,
    store: SnapshotStore,
    hooks: dict[int, Callable[[], object]],
) -> FileWatcher:
    return FileWatcher(
        folder,
        black_box,
        workspace_id=store.workspace_id,
        config=WatcherConfig(dump_interval=0.1),
        inotify_factory=lambda: HookedInotify(hooks),
    )


@pytest.fixture
def hooks() -> Iterator[dict[int, Callable[[], object]]]:
    pending: dict[int, Callable[[], object]] = {}
    yield pending
    assert not pending, "a hook never ran: the window was not hit"


def test_files_made_as_fast_as_possible_in_new_folders_are_all_recorded(
    store: SnapshotStore,
    plain_agent_dir: Path,  # noqa: F811
    box: BlackBox,  # noqa: F811
    resolver: str,
) -> None:
    watcher = FileWatcher(
        plain_agent_dir,
        box,
        workspace_id=store.workspace_id,
        config=WatcherConfig(dump_interval=0.1, bucket_burst=10_000),  # every record, no summary
    )
    try:
        assert watcher.arm(store.take(Reason.MANUAL).id)
        for round_ in range(ROUNDS):
            folder = plain_agent_dir / f"new{round_:02d}"
            subprocess.run([sys.executable, "-c", AGENT, str(folder), str(FILES)], check=True)
        settle(watcher)
        found = set(by_target(box))
        wanted = {f"new{r:02d}/f{i:02d}" for r in range(ROUNDS) for i in range(FILES)}
        assert sorted(wanted - found) == []
        assert watcher.stats().unknown_wd == 0
        assert watcher.unwatched_count() == 0
        assert not [e for e in box.events(source="file") if e.action == "dropped"]
    finally:
        watcher.close()


def test_names_made_between_the_open_and_the_watch_of_a_new_folder_are_recorded(
    store: SnapshotStore,
    plain_agent_dir: Path,  # noqa: F811
    box: BlackBox,  # noqa: F811
    resolver: str,
    hooks: dict[int, Callable[[], object]],
) -> None:
    watcher = hooked_watcher(plain_agent_dir, box, store, hooks)
    try:
        assert watcher.arm(store.take(Reason.MANUAL).id)
        staging = store.workspace / "staging"  # same subvolume, not watched
        staging.mkdir()

        new = plain_agent_dir / "new"

        def agent() -> None:  # by then the folder is already in its new place
            (new / "early.txt").write_text("x")
            (new / "sub").mkdir()

        hooks[staging.stat().st_ino] = agent
        staging.rename(new)  # a folder from outside: the watcher walks it
        settle(watcher)
        records = by_target(box)
        assert records["new/early.txt"].action == "create"
        assert records["new/early.txt"].details["scan"] is True
        assert "new/sub" in records
        assert watch_of(new / "sub") in my_watches()
        assert watcher.unwatched_count() == 0
    finally:
        watcher.close()


def test_a_folder_made_between_the_open_and_the_watch_of_the_root_is_watched_after_a_rewind(
    store: SnapshotStore,
    plain_agent_dir: Path,  # noqa: F811
    box: BlackBox,  # noqa: F811
    resolver: str,
    hooks: dict[int, Callable[[], object]],
) -> None:
    """Arming again (after a rewind, here without a swap) opens the agent's folder, watches it
    and walks it while the agent may be running: what it makes in between must be armed."""
    watcher = hooked_watcher(plain_agent_dir, box, store, hooks)
    try:
        assert watcher.arm(store.take(Reason.MANUAL).id)
        hooks[plain_agent_dir.stat().st_ino] = lambda: (plain_agent_dir / "late").mkdir()
        with watcher.suspended():
            pass
        assert watcher.is_armed
        settle(watcher)
        assert watch_of(plain_agent_dir / "late") in my_watches()
        assert watcher.unwatched_count() == 0
    finally:
        watcher.close()
