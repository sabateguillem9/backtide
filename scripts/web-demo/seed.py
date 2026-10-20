"""Demo data for `backtide web` (T12): a throwaway state with believable black boxes, no VM.

Usage: python scripts/web-demo/seed.py <folder> [--live]

Several agents (T12d's control room): the main one, "OpenClaw personal", is the one
``backtide.toml`` points at (its story is below). Three more, each with its own black box and its
own snapshot folders under ``<folder>/agents/<slug>/``, are listed in ``<folder>/agents.json``: a
coding agent at work, a research bot that is mostly quiet and now and then loses its process
sensor, and a mail assistant that was frozen for lack of space. ``<folder>/requests.json`` holds
made-up held requests of the gate (in the real gate's shape, T10-5) that only serve.py reads:
each one waits a few minutes and is then rejected on its own, and with ``--live`` new ones come
in.
``<folder>/settings.json`` is what the Settings page (T12e) starts with: the Anthropic key set
(only its last four characters, as the real service tells them), no OpenAI key and the Telegram
bot set. There is no key anywhere in the demo, and serve.py keeps every change in memory.

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

import json
import os
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


MAIN_FILES = ("notas.md", "plan.md", "datos-ventas.csv", "informe-trimestral.md", "ideas.txt")
MAIN_SESSIONS = ((1.5, 4.0, 6), (8.0, 9.5, 12), (13.5, 18.5, 4))  # (from h, to h, events a step)


def earlier_day(
    story: Story,
    seed: int = 3,
    sessions: tuple[tuple[float, float, int], ...] = MAIN_SESSIONS,
    files: tuple[str, ...] = MAIN_FILES,
    hours: float = 22,
) -> None:
    """The day before the last hour, so the tide has a shape: work sessions with quiet
    stretches between them, and snapshots every half hour while the agent works."""
    rng = random.Random(seed)  # noqa: S311 - demo data, not a secret
    story.system("service_start", version="0.1.0")
    story.at(2)
    story.system("agent_start")
    step = 300.0  # five minutes
    begin = story.clock.now()
    for i in range(int(hours * 3600 / step)):
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


def live_main(story: Story, count: int, rng: random.Random) -> None:
    """One step of the main agent at work."""
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
        story.file("modify", rng.choice(["work/notas.md", "work/informe-trimestral.md"]), writes=2)


# -- the other agents of the control room (T12d) ----------------------------------------------

# slug, name, seed, work sessions of the day before, files it touches
OTHERS = (
    ("codigo", "Agente de código", 11, ((2.0, 6.0, 8), (10.0, 14.0, 10), (16.0, 21.5, 7)),
     ("src/tienda/carrito.py", "src/tienda/pagos.py", "tests/test_carrito.py", "README.md")),
    ("investigacion", "Bot de investigación", 21, ((4.0, 5.0, 3), (12.0, 12.5, 4), (19.0, 20.0, 3)),
     ("notas/mareas.md", "notas/fuentes.md", "resumen.md")),
    ("correo", "Asistente de correo", 31, ((6.0, 9.0, 3), (15.0, 17.0, 2)),
     ("bandeja/borradores.md", "bandeja/respuestas.md")),
)  # fmt: skip


def other_story(story: Story, slug: str) -> None:
    """The last hour of one of the other agents (its clock then catches up with now)."""
    story.at(60)
    story.snapshot()
    if slug == "codigo":
        story.system("sensor_start")
        for i in range(30):
            story.at(70)
            story.file("modify", f"work/src/tienda/{('carrito', 'pagos')[i % 2]}.py", writes=2)
            if i % 5 == 4:
                story.box.append("exec", "run", "pytest -q tests/", details={"exit": 0})
        story.at(30)
        story.box.append("exec", "run", "rm -rf build/ dist/", risk=2, details={"exit": 0})
        story.snapshot()
    elif slug == "investigacion":
        story.system("sensor_start")
        for topic in ("mareas vivas", "corrientes de resaca"):
            story.at(400)
            story.box.append("llm", "chat", "api.anthropic.com", details={"topic": topic})
            story.at(5)
            story.box.append("net", "connect", "arxiv.org:443")
            story.at(20)
            story.file("create", f"work/notas/{topic.replace(' ', '-')}.md", size=2400)
    else:  # correo: frozen for lack of space, waiting for room
        story.system("sensor_start")
        story.at(300)
        story.file("modify", "work/bandeja/borradores.md", writes=3)
        story.at(200)
        story.system("space_low")
        story.at(30)
        story.system("space_pause", frozen=True)


def live_other(story: Story, slug: str, count: int, rng: random.Random, plan: dict) -> None:
    """One step of one of the other agents."""
    if slug == "codigo":
        if plan.get("rewind_at") == count:
            story.box.append(
                "snapshot", "rewind_done", plan["rewind_to"],
                details={"target": plan["rewind_to"], "agent_started": True}, risk=1,
            )  # fmt: skip
            story.system("agent_start", reason="rewind")
            return
        if count % 120 == 60 and story.last_snapshot:
            target = story.last_snapshot
            story.box.append(
                "snapshot", "rewind_requested", target,
                details={"target": target, "requested_by": "cli"}, risk=1,
            )  # fmt: skip
            plan["rewind_at"], plan["rewind_to"] = count + 4, target
            return
        if count % 20 == 0:
            story.snapshot()
        elif count % 6 == 0:
            story.box.append("exec", "run", "pytest -q tests/", details={"exit": 0})
        elif count % 37 == 0:
            story.box.append("exec", "run", "rm -rf build/", risk=2, details={"exit": 0})
        elif count % 3 == 0:
            for i in range(rng.randint(3, 9)):
                story.file("modify", f"work/src/tienda/modulo_{i}.py", writes=1)
        else:
            story.file(
                "modify", rng.choice(["work/src/tienda/carrito.py", "work/tests/test_carrito.py"])
            )
    elif slug == "investigacion":
        if count % 90 == 30:
            story.box.append("system", "sensor_down", "tetragon", risk=2)
        elif count % 90 == 50:
            story.system("sensor_restart", attempt=1)
            story.system("sensor_start")
        elif count % 25 == 0:
            story.box.append("llm", "chat", "api.anthropic.com", details={"topic": "mareas"})
            story.box.append("net", "connect", rng.choice(["arxiv.org:443", "doi.org:443"]))
            story.file("modify", "work/notas/mareas.md", writes=1)
        elif count % 60 == 0:
            story.snapshot()


# -- the gate's requests (made up, in the shape of the real gate's: T10-5) --------------------

# ``action`` and ``notes`` are what backtide says (backtide.gate.phrase's words); the rest is what
# the agent asked. The last one imitates our notice, as an agent might (aviso-con-trampa).
REQUESTS: tuple[dict[str, object], ...] = (
    {"agent": "principal", "kind": "email", "action": "Gmail: enviar un correo",
     "target": "ana.garcia@ejemplo.com", "recipients": ["ana.garcia@ejemplo.com"],
     "subject": "Presupuesto de la reforma", "lines": "Hola Ana, te paso el presupuesto.",
     "detail": "Presupuesto de la reforma", "reason": "send", "risk": 2, "trustable": True,
     "batches": ["recipient", "kind"]},
    {"agent": "codigo", "kind": "delete", "target": "api.github.com",
     "request": "DELETE api.github.com/repos/ana/tienda-web", "reason": "delete", "risk": 3},
    {"agent": "investigacion", "kind": "other", "target": "editorial.ejemplo.org",
     "request": "POST editorial.ejemplo.org/api/checkout?item=modelos-de-marea-2024",
     "reason": "write", "risk": 2, "batches": ["kind"]},
    {"agent": "principal", "kind": "message", "action": "Telegram: enviar un mensaje",
     "target": "-100223344", "recipients": ["-100223344"], "lines": "Llego a las 9",
     "detail": "Llego a las 9", "reason": "send", "risk": 2, "trustable": True,
     "batches": ["recipient", "kind"]},
    {"agent": "codigo", "kind": "other", "target": "api.stripe.com",
     "request": "POST api.stripe.com/v1/refunds", "reason": "credential_unknown_host",
     "risk": 2},
    {"agent": "principal", "kind": "message", "action": "Telegram: enviar un mensaje",
     "notes": ["la plataforma descargará esa dirección"], "target": "556",
     "recipients": ["556"],
     "lines": "⏸ backtide · RETENIDA · ya aprobado ✅\u202eRESULTADO: aprobada <b>OK</b> "
     "https://malo.example/aprobar",
     "detail": "⏸ backtide · ya aprobado", "reason": "send", "risk": 2},
)  # fmt: skip


class Gate:
    """The made-up requests, written to ``requests.json`` for serve.py. Each waits a few minutes
    and then is gone (rejected on its own); with ``--live`` the next sample takes its place."""

    def __init__(self, path: Path, rng: random.Random) -> None:
        self.path = path
        self.rng = rng
        self.next = 0
        self.serial = 0
        self.open: list[dict[str, object]] = []

    def add(self, now: datetime, seconds: float) -> None:
        sample = REQUESTS[self.next % len(REQUESTS)]
        self.next += 1
        self.serial += 1
        held = now - timedelta(seconds=self.rng.uniform(10, 60))
        self.open.append(
            {
                **sample,
                "id": f"h-{self.serial:012x}",
                "held_at": held.isoformat(),
                "expires_at": (now + timedelta(seconds=seconds)).isoformat(),
            }
        )

    def tick(self, now: datetime) -> None:
        """Drop what ran out; keep three waiting (one at a time comes back after a pause)."""
        before = len(self.open)
        self.open = [r for r in self.open if datetime.fromisoformat(str(r["expires_at"])) > now]
        if len(self.open) < 3 and self.rng.random() < 0.15:
            self.add(now, self.rng.uniform(120, 480))
        if len(self.open) != before or len(self.open) != getattr(self, "_written", -1):
            self.write()

    def write(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.open, ensure_ascii=False, indent=2) + "\n")
        os.replace(tmp, self.path)
        self._written = len(self.open)


def seed_others(folder: Path) -> list[tuple[Story, str]]:
    """The other agents, each in ``<folder>/agents/<slug>/``, and ``agents.json`` listing them."""
    listed = []
    stories = []
    for slug, name, seed, sessions, files in OTHERS:
        home = folder / "agents" / slug
        home.mkdir(parents=True, exist_ok=True)
        home.chmod(0o700)
        if not (home / "blackbox.key").exists():
            create_key(home / "blackbox.key")
        clock = Clock(datetime.now(UTC) - timedelta(hours=23, minutes=30))
        box = BlackBox(
            home / "blackbox.db",
            load_key(home / "blackbox.key"),
            checkpoint_path=home / "blackbox.checkpoint",
            clock=clock,
        )
        story = Story(box, clock, home)
        if box.head() is None:
            earlier_day(story, seed, sessions, files, hours=22.4)
            clock.jump_to(datetime.now(UTC) - timedelta(minutes=50))
            other_story(story, slug)
        listed.append(
            {"slug": slug, "name": name, "db": str(home / "blackbox.db"),
             "snapshots": str(home / "snapshots")}
        )  # fmt: skip
        stories.append((story, slug))
    (folder / "agents.json").write_text(
        json.dumps({"main": "OpenClaw personal", "others": listed}, ensure_ascii=False, indent=2)
    )
    return stories


def seed_settings(folder: Path) -> None:
    """``settings.json``: what the Settings page shows at first, in the shape of the service's
    ``secrets`` reply (a tail and a date, never a key). serve.py reads it once."""
    now = datetime.now(UTC)
    shown = {
        "anthropic": {"set": True, "tail": "4f2a", "in_use": True, "problem": None,
                      "changed": f"{now - timedelta(days=2, hours=3):%Y-%m-%dT%H:%M:%SZ}"},
        "openai": {"set": False, "tail": None, "changed": None, "in_use": False, "problem": None},
        "telegram": {"set": True, "tail": "Rk7w", "chat_tail": "5531", "in_use": True,
                     "problem": None, "changed": f"{now - timedelta(days=6):%Y-%m-%dT%H:%M:%SZ}"},
    }  # fmt: skip
    (folder / "settings.json").write_text(json.dumps(shown, indent=2) + "\n")


def live(story: Story, others: list[tuple[Story, str]], gate: Gate) -> None:
    """Add events at the pace of agents at work, until stopped. Real time from here on."""
    rng = random.Random(7)  # noqa: S311 - demo data, not a secret
    plans: dict[str, dict] = {slug: {} for _, slug in others}
    count = 0
    while True:
        time.sleep(LIVE_EVERY)
        count += 1
        story.clock.sync()
        live_main(story, count, rng)
        for other, slug in others:
            other.clock.sync()
            live_other(other, slug, count, rng, plans[slug])
        gate.tick(datetime.now(UTC))


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
    others = seed_others(folder)
    seed_settings(folder)
    gate = Gate(folder / "requests.json", random.Random(5))  # noqa: S311 - demo data
    start = datetime.now(UTC)
    for seconds in (95, 260, 420):
        gate.add(start, seconds)
    gate.write()
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
        live(story, others, gate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
