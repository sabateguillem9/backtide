"""Demo data for `backtide web` (T12): a throwaway state with a believable black box, no VM.

Usage: python scripts/web-demo/seed.py <folder> [--live]

Writes into <folder>: ``backtide.toml``, ``state/`` (a black box written by the real BlackBox),
``volume/snapshots/`` (one empty folder per snapshot, which serve.py lists: no btrfs on a Mac)
and a ``.ready`` file when the first story is in. Before the last hour there is a day of work
with quiet stretches, so the tide has a shape. The last hour: an agent creates notes, a report
and a spreadsheet, backtide takes snapshots, the agent deletes a whole project (a
burst of 120 files), the person rewinds, and the agent carries on. With ``--live`` it then keeps
adding events like an agent at work (some edits, now and then a burst of deletions, a snapshot
every half minute) until it is stopped, so the "Ahora" page has something to show.

The data is made up, calm and harmless on purpose (hostile names are the attack battery's job:
tests/attacks/test_web_attacks.py). Nothing here touches Docker, Btrfs or the network.
"""

import random
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from backtide.blackbox import BlackBox, create_key, load_key

LIVE_EVERY = 2.0  # seconds between live events
SNAPSHOT_EVERY = 15  # live events between two snapshots


class Story:
    """Appends events with a clock that starts an hour ago and catches up with now."""

    def __init__(self, box: BlackBox, clock: "Clock", volume: Path | None = None) -> None:
        self.box = box
        self.clock = clock
        self.last_snapshot: str | None = None
        self.volume = volume  # where serve.py finds the snapshot list (one empty folder each)

    def keep(self, snapshot_id: str) -> None:
        """Leave the snapshot where serve.py lists it (a plain folder: no btrfs on a Mac)."""
        if self.volume is not None:
            (self.volume / "snapshots" / snapshot_id).mkdir(parents=True, exist_ok=True)

    def at(self, seconds: float) -> None:
        self.clock.advance(seconds)

    def file(self, action: str, path: str, *, risk: int = 0, **details: object) -> None:
        details = {"type": "file", "name": path.rsplit("/", 1)[-1], **details}
        self.box.append(
            "file", action, path, details=details, risk=risk, snapshot_id=self.last_snapshot
        )

    def snapshot(self) -> str:
        snapshot_id = f"{self.clock.now():%Y%m%dT%H%M%S.%f}Z-periodic"
        self.box.append(
            "snapshot",
            "take",
            snapshot_id,
            details={"reason": "periodic", "trigger": "cycle"},
            snapshot_id=snapshot_id,
        )
        self.last_snapshot = snapshot_id
        self.keep(snapshot_id)
        return snapshot_id

    def system(self, action: str, **details: object) -> None:
        self.box.append("system", action, "", details=details)


class Clock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def __call__(self) -> datetime:
        self._now += timedelta(microseconds=1)
        return self._now

    def now(self) -> datetime:
        return self._now

    def jump_to(self, moment: datetime) -> None:
        """Forward to ``moment`` (never backwards)."""
        self._now = max(self._now, moment)

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)

    def sync(self) -> None:
        """Follow the real time (never backwards: the black box wants non-decreasing times)."""
        self._now = max(self._now, datetime.now(UTC))


def earlier_day(story: Story) -> None:
    """The day before the last hour, so the tide has a shape: three work sessions with quiet
    stretches between them, and snapshots every half hour while the agent works."""
    rng = random.Random(3)  # noqa: S311 - demo data, not a secret
    story.system("service_start", version="0.1.0")
    story.at(2)
    story.system("agent_start")
    sessions = ((1.5, 4.0, 6), (8.0, 9.5, 12), (13.5, 18.5, 4))  # (from h, to h, events per step)
    files = ("notas.md", "plan.md", "datos-ventas.csv", "informe-trimestral.md", "ideas.txt")
    step = 300.0  # five minutes
    begin = story.clock.now()
    for i in range(int(22 * 3600 / step)):
        hour = i * step / 3600
        busy = next((n for start, end, n in sessions if start <= hour < end), 0)
        if i % (6 if busy else 24) == 0:
            story.snapshot()
        for _ in range(rng.randint(0, busy * 2) if busy else 0):
            story.at(rng.uniform(1, step / (busy * 2 + 1)))
            story.file("modify", f"work/{rng.choice(files)}", writes=rng.randint(1, 4))
        story.clock.jump_to(begin + timedelta(seconds=step * (i + 1)))


def first_story(story: Story) -> str:
    """The last hour. Returns the id of the snapshot the person rewinds to."""
    story.system("service_start", version="0.1.0")
    story.at(2)
    story.system("agent_start")
    story.at(1)
    story.box.append("system", "watcher_armed", ".", details={"dirs": 14, "unwatched": 0})
    story.at(120)
    story.snapshot()
    for name, size in (
        ("notas.md", 1200),
        ("informe-trimestral.md", 5400),
        ("datos-ventas.csv", 88000),
    ):
        story.at(40)
        story.file("create", f"work/{name}", size=size)
    story.at(30)
    story.snapshot()
    for _ in range(14):
        story.at(55)
        story.file("modify", "work/informe-trimestral.md", writes=3)
    story.at(60)
    good = story.snapshot()
    story.at(120)
    story.file("create", "work/proyecto", type="dir")
    for i in range(40):
        story.at(0.4)
        story.file("create", f"work/proyecto/modulo_{i:02d}.py", size=900 + 31 * i)
    story.at(70)
    story.snapshot()
    story.at(300)
    for i in range(120):  # the mistake: the whole project goes
        story.at(0.05)
        story.file(
            "delete",
            f"work/proyecto/modulo_{i % 40:02d}.py"
            if i < 40
            else f"work/proyecto/datos/fila_{i:03d}.txt",
            risk=1,
        )
    story.at(20)
    story.snapshot()
    story.at(60)
    story.box.append(
        "snapshot",
        "rewind_requested",
        good,
        details={"target": good, "requested_by": "cli"},
        risk=1,
        snapshot_id=good,
    )
    story.at(1)
    story.system("agent_stop", reason="rewind")
    story.at(2)
    # the rewind keeps the workspace it replaces, so it can be undone ("antes de rebobinar")
    story.keep(f"{story.clock.now():%Y%m%dT%H%M%S.%f}Z-pre_restore")
    story.at(2)
    story.box.append(
        "snapshot",
        "rewind_done",
        good,
        details={"target": good, "agent_started": True},
        risk=1,
        snapshot_id=good,
    )
    story.system("agent_start", reason="rewind")
    story.at(30)
    story.snapshot()
    story.at(40)
    story.file("modify", "work/notas.md", writes=1)
    return good


def live(story: Story) -> None:
    """Add events at the pace of an agent at work, until stopped. Real time from here on."""
    rng = random.Random(7)  # noqa: S311 - demo data, not a secret
    count = 0
    while True:
        time.sleep(LIVE_EVERY)
        story.clock.sync()
        count += 1
        if count % SNAPSHOT_EVERY == 0:
            story.snapshot()
        elif count % 9 == 0:
            story.file("create", f"work/borrador_{count}", type="dir")
            for i in range(rng.randint(6, 14)):
                story.file("create", f"work/borrador_{count}/parte_{i}.md", size=400 + i)
        elif count % 11 == 0:
            for i in range(rng.randint(10, 30)):
                story.file("delete", f"work/borrador_{count - 2}/parte_{i}.md", risk=1)
        else:
            story.file(
                "modify", rng.choice(["work/notas.md", "work/informe-trimestral.md"]), writes=2
            )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    folder = Path(argv[1])
    state = folder / "state"
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o700)
    (state / "gateway.token").write_text("demo-token-not-a-secret\n")
    (state / "gateway.token").chmod(0o600)
    config = folder / "backtide.toml"
    config.write_text(f'state_dir = "{state}"\nvolume = "{folder / "volume"}"\n')
    config.chmod(0o600)
    if not (state / "blackbox.key").exists():
        create_key(state / "blackbox.key")
    clock = Clock(datetime.now(UTC) - timedelta(hours=23, minutes=30))
    box = BlackBox(
        state / "blackbox.db",
        load_key(state / "blackbox.key"),
        checkpoint_path=state / "blackbox.checkpoint",
        clock=clock,
    )
    story = Story(box, clock, folder / "volume")
    if box.head() is None:
        earlier_day(story)
        clock.jump_to(datetime.now(UTC) - timedelta(minutes=58))
        first_story(story)
        # The story ran on a fast-forwarded clock: from here on, wait until it is "now" again.
        wait = (clock.now() - datetime.now(UTC)).total_seconds()
        if wait > 0:
            time.sleep(wait + 0.1)
    (folder / ".ready").write_text("ready\n")
    print(f"python -m backtide.cli web --config {config}", flush=True)
    if "--live" in argv:
        clock.sync()
        live(story)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
