"""Demo data for `vigia web` (T12): a throwaway state with a believable black box, no VM.

Usage: python scripts/web-demo/seed.py <folder> [--live]

Writes into <folder>: ``vigia.toml``, ``state/`` (a black box written by the real BlackBox) and a
``.ready`` file when the first story is in. The story is about the last hour: an agent creates
notes, a report and a spreadsheet, Vigía takes snapshots, the agent deletes a whole project (a
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

from vigia.blackbox import BlackBox, create_key, load_key

LIVE_EVERY = 2.0  # seconds between live events
SNAPSHOT_EVERY = 15  # live events between two snapshots


class Story:
    """Appends events with a clock that starts an hour ago and catches up with now."""

    def __init__(self, box: BlackBox, clock: "Clock") -> None:
        self.box = box
        self.clock = clock
        self.last_snapshot: str | None = None

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

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)

    def sync(self) -> None:
        """Follow the real time (never backwards: the black box wants non-decreasing times)."""
        self._now = max(self._now, datetime.now(UTC))


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
    story.at(4)
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
    config = folder / "vigia.toml"
    config.write_text(f'state_dir = "{state}"\nvolume = "{folder / "volume"}"\n')
    config.chmod(0o600)
    if not (state / "blackbox.key").exists():
        create_key(state / "blackbox.key")
    story_start = datetime.now(UTC) - timedelta(minutes=58)
    clock = Clock(story_start)
    box = BlackBox(
        state / "blackbox.db",
        load_key(state / "blackbox.key"),
        checkpoint_path=state / "blackbox.checkpoint",
        clock=clock,
    )
    story = Story(box, clock)
    if box.head() is None:
        first_story(story)
        # The story ran on a fast-forwarded clock: from here on, wait until it is "now" again.
        wait = (clock.now() - datetime.now(UTC)).total_seconds()
        if wait > 0:
            time.sleep(wait + 0.1)
    (folder / ".ready").write_text("ready\n")
    print(f"python -m vigia.cli web --config {config}", flush=True)
    if "--live" in argv:
        clock.sync()
        live(story)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
