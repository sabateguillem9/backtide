"""The Mac's web demo: `backtide web` over the made-up state of seed.py, with its snapshot list.

Usage: python scripts/web-demo/serve.py <folder>/backtide.toml [port]

The real web lists the snapshots of the btrfs volume (``SnapshotStore``), which a Mac does not
have: there the page would fall back to the black box. seed.py also leaves one empty folder per
snapshot in ``<volume>/snapshots/``; this lists those by name, so the snapshots page looks like
the real one.

The control room (T12d) shows several agents and the gate's requests. Neither exists for real
yet (T17 and T10), so seed.py writes ``agents.json`` (the other agents' black boxes, each read
with its own keyless, read-only ``BoxReader``, like the main one) and ``requests.json`` (made-up
requests), next to ``backtide.toml``. Only this script reads them. Demo only: ``backtide web``
itself never takes this path.

The held requests (T10-5): ``DemoApprover`` stands in for the service's control socket, so the
buttons of "Esperan tu sí" work for real (their confirmation pages, the CSRF token and the
one-time tickets are the web's own) but only change what the demo remembers: nothing goes out and
nothing is written.

The Settings page (T12e) asks the service through its control socket, which the demo does not
have. ``DemoSettings`` stands in for it: it starts from ``settings.json`` (a tail and a date per
kind, never a key), checks a value with the service's own rules and keeps only what the page may
show (the last four characters and when). It writes no file, holds no key and forgets everything
when the demo stops. The page, its confirmations, the CSRF token and the one-time tickets are the
real ones.

The chat (T26-5b): ``DemoTasks`` stands in for the service's tasks. A task "runs" for a few seconds
and answers with a made-up text; one that asks for ``hostil`` answers what a hostile agent would, to
look at how the page shows it (docs/47 section 7.3). Nothing runs and nothing is written.
"""

import copy
import json
import logging
import secrets
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from backtide.service.settings import KINDS, PROVIDERS, check_chat_id, check_value, tail_of
from backtide.snapshots import Snapshot
from backtide.web.agents import AgentSource, PendingRequest, RosterError, request_from
from backtide.web.paths import WebPaths
from backtide.web.reader import BoxReader
from backtide.web.rewind import Availability
from backtide.web.server import DEFAULT_PORT, run_web

logger = logging.getLogger("web-demo")


def folder_snapshots(folder: Path) -> Callable[[], list[Snapshot]]:
    """The snapshots seed.py left in ``folder`` (one empty folder each, named like the real)."""

    def listing() -> list[Snapshot]:
        if not folder.is_dir():
            return []
        found = [
            s for name in sorted(p.name for p in folder.iterdir()) if (s := Snapshot.parse(name))
        ]
        return sorted(found, key=lambda s: (s.taken_at, s.id))

    return listing


def demo_english(home: Path) -> bool:
    """Whether seed.py made the data in English (``--english``: the demo video)."""
    path = home / "agents.json"
    return path.is_file() and json.loads(path.read_text()).get("english") is True


def demo_agents(home: Path) -> tuple[str | None, list[AgentSource]]:
    """The main agent's name and the other agents of ``agents.json`` (none if it is missing)."""
    path = home / "agents.json"
    if not path.is_file():
        return None, []
    data = json.loads(path.read_text())
    others = [
        AgentSource(
            slug=item["slug"],
            name=item["name"],
            reader=BoxReader(Path(item["db"])),
            snapshots=folder_snapshots(Path(item["snapshots"])),
        )
        for item in data.get("others", [])
    ]
    return data.get("main"), others


def demo_requests(
    path: Path, approver: "DemoApprover | None" = None
) -> Callable[[], list[PendingRequest]]:
    """The made-up requests in ``path``, read again on every call (seed.py rewrites it), but
    those the demo's buttons already decided (``approver``)."""

    def listing() -> list[PendingRequest]:
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return []
        decided = approver.decided() if approver is not None else set()
        requests = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict) or item.get("id") in decided:
                continue
            try:
                requests.append(request_from(item))
            except RosterError as error:
                logger.warning("a made-up request was skipped: %s", error)
        return requests

    return listing


DEMO_DECIDED = "Esto es la demo: no ha salido nada ni se ha escrito nada."
DEMO_DECIDED_EN = "This is the demo: nothing went out and nothing was written."


class DemoApprover:
    """The held requests' service, in memory (T10-5): the buttons, their confirmations, the
    CSRF token and the one-time tickets are the real ones; what they "do" is remembered here
    until the demo stops. Nothing goes out and nothing is written. Thread-safe."""

    enabled = True

    def __init__(self, requests: Path, said: str = DEMO_DECIDED) -> None:
        self._requests = requests
        self._said = said
        self._lock = threading.Lock()
        self._decided: set[str] = set()
        self._trusted: list[dict[str, Any]] = [
            {"trust_id": "t-0a1b2c3d", "translator": "telegram", "recipient": "556677",
             "added_at": _now(), "by": "web"},
        ]  # fmt: skip
        self._batches: list[dict[str, Any]] = [
            {"rule_id": "b-5e6f7a8b", "scope": "recipient", "translator": "telegram",
             "effect": "send", "recipients": ["424242424"], "until": _later(12 * 3600),
             "uses": 3},
            {"rule_id": "b-9c0d1e2f", "scope": "kind", "translator": None, "method": "POST",
             "host": "api.ejemplo.dev", "route": "/v1/notas/*", "until": _later(3600),
             "uses": 1},
        ]  # fmt: skip

    def decided(self) -> set[str]:
        with self._lock:
            return set(self._decided)

    def availability(self) -> Availability:
        return Availability.READY

    def holds(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        return []  # the page lists the made-up ones through ``demo_requests``

    def _open(self, hold_id: str) -> dict[str, Any] | None:
        try:
            raw = json.loads(self._requests.read_text())
        except (OSError, ValueError):
            return None
        return next(
            (r for r in raw if isinstance(r, dict) and r.get("id") == hold_id), None
        ) if isinstance(raw, list) else None  # fmt: skip

    def decide(self, hold_id: str, verdict: str, *, agent: str | None = None) -> dict[str, Any]:
        with self._lock:
            if hold_id in self._decided or self._open(hold_id) is None:
                return {"ok": False, "outcome": "unknown", "message": self._said}
            self._decided.add(hold_id)
        outcome = "released" if verdict == "approve" else "rejected"
        return {"ok": True, "outcome": outcome, "message": self._said}

    def trust(self, hold_id: str, *, agent: str | None = None) -> dict[str, Any]:
        with self._lock:
            found = self._open(hold_id)
            if hold_id in self._decided or found is None:
                return {"ok": False, "outcome": "unknown", "message": self._said, "hold": None}
            if not found.get("trustable"):
                return {"ok": False, "outcome": "not_trustable", "message": self._said,
                        "hold": None}  # fmt: skip
            self._decided.add(hold_id)
            translator = str(found.get("translator") or "telegram")
            self._trusted.append(
                {
                    "trust_id": f"t-{len(self._trusted):08x}",
                    "translator": translator,
                    "recipient": str((found.get("recipients") or ["?"])[0]),
                    "added_at": _now(),
                    "by": "web",
                }  # fmt: skip
            )
        return {"ok": True, "outcome": "trusted", "message": self._said, "hold": "released"}

    def trusted(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        if agent is not None:  # the made-up lists are the main agent's
            return []
        with self._lock:
            return copy.deepcopy(self._trusted)

    def untrust(self, trust_id: str, *, agent: str | None = None) -> dict[str, Any]:
        with self._lock:
            kept = [t for t in self._trusted if t["trust_id"] != trust_id]
            gone = len(kept) != len(self._trusted)
            self._trusted = kept
        outcome = "removed" if gone else "unknown"
        return {"ok": gone, "outcome": outcome, "message": self._said}

    def batches(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        if agent is not None:
            return []
        with self._lock:
            return copy.deepcopy(self._batches)

    def end_batch(self, rule_id: str, *, agent: str | None = None) -> dict[str, Any]:
        with self._lock:
            kept = [b for b in self._batches if b["rule_id"] != rule_id]
            gone = len(kept) != len(self._batches)
            self._batches = kept
        outcome = "ended" if gone else "unknown"
        return {"ok": gone, "outcome": outcome, "message": self._said}


DEMO_SAID = "Esto es la demo: no se ha escrito nada y el cambio dura hasta que la pares."
DEMO_SHAPE = "Eso no tiene la forma de {what}: no se ha cambiado nada."
DEMO_WHAT = {
    "anthropic": "una clave de Anthropic (sk-ant-…)",
    "openai": "una clave de OpenAI (sk-…)",
    "telegram": "un token de bot (cifras, dos puntos y unos 35 caracteres)",
}


class DemoSettings:
    """The Settings page's service, in memory (see the module's docstring). Thread-safe."""

    enabled = True

    def __init__(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            raw = {}
        self._shown: dict[str, dict[str, Any]] = {
            kind: dict(raw[kind]) if isinstance(raw.get(kind), dict) else {"set": False}
            for kind in KINDS
        }
        self._lock = threading.Lock()

    def availability(self) -> Availability:
        return Availability.READY

    def status(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._shown)

    def set_secret(self, kind: str, value: str, chat_id: str | None) -> dict[str, Any]:
        with self._lock:
            entry = self._shown[kind]
            if kind in PROVIDERS:
                if not check_value(kind, value):
                    return _refused(DEMO_SHAPE.format(what=DEMO_WHAT[kind]))
                applied = "now" if entry.get("in_use") else "unused"
            else:
                chat = chat_id or ""
                if (value and not check_value(kind, value)) or (chat and not check_chat_id(chat)):
                    return _refused(DEMO_SHAPE.format(what=DEMO_WHAT[kind]))
                if not value and not chat:
                    return _refused("No has puesto nada: no se ha cambiado nada.")
                if not entry.get("set") and not (value and chat):
                    return _refused("La primera vez hacen falta el token y el chat a la vez.")
                if chat:
                    entry["chat_tail"] = chat[-4:] if len(chat) > 4 else None
                applied = "restart"
            if value:
                entry["tail"] = tail_of(value)
            entry.update(set=True, problem=None, changed=_now())
            return {"ok": True, "outcome": "saved", "message": DEMO_SAID, "applied": applied}

    def clear_secret(self, kind: str) -> dict[str, Any]:
        with self._lock:
            entry = self._shown[kind]
            if not entry.get("set"):
                return {"ok": False, "outcome": "not_set", "message": "", "applied": "none"}
            entry.update(set=False, tail=None, chat_tail=None, changed=None, problem=None)
            applied = (
                "restart" if kind not in PROVIDERS else ("now" if entry.get("in_use") else "unused")
            )
            return {"ok": True, "outcome": "cleared", "message": DEMO_SAID, "applied": applied}


DEMO_TASK_SECONDS = 4.0
DEMO_ANSWER = (
    "He mirado la carpeta de trabajo: hay un proyecto en Python con sus tests.\n\n"
    "\tmake test   # pasa\n\tmake lint   # pasa\n\nNo he cambiado nada."
)
# What a hostile agent would answer: markup, a way out of the frame, a link and an image that would
# ask for something, a fake line of the page, the marks that turn text around, escape sequences.
DEMO_HOSTILE = (
    "<script>alert(1)</script></pre></li><h1>backtide: todo en orden</h1>\n"
    '<img src="https://evil.example/x.png" onerror="alert(2)">\n'
    '<a href="javascript:alert(3)">Aprobar</a> [Aprobar](https://evil.example/ok)\n'
    '<button hx-post="/salir" hx-trigger="load">Salir</button>\n'
    '<div hx-swap-oob="true" id="tasks">fuera</div>\n'
    "https://evil.example/entra\n"
    "evil\u202etxt.exe \u2066dentro\u2069 cero\u200dancho\n"
    "\x1b]52;c;c2VjcmV0bw==\x07\x1b[2Jborrado\r\n"
    "</textarea>{{7*7}}\n"
)


class DemoTasks:
    """The chat without a service: in this process's memory, and gone when the demo stops."""

    enabled = True

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._of: dict[str | None, list[dict[str, Any]]] = {}

    def availability(self) -> Availability:
        return Availability.READY

    def tasks(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "task": one["task"],
                    "asked": one["asked"],
                    "asked_at": one["asked_at"],
                    "via": "web",
                    "outcome": self._outcome_of(one),
                    "seconds": None,
                    "answer_chars": 0,
                }
                for one in self._of.get(agent, [])
            ]

    def status(self, task_id: str, *, agent: str | None = None) -> dict[str, Any]:
        with self._lock:
            one = next((o for o in self._of.get(agent, []) if o["task"] == task_id), None)
            if one is None:
                return {"ok": False, "outcome": "unknown", "message": "", "answer": None}
            outcome = self._outcome_of(one)
            answer = one["answer"] if outcome == "ok" else None
            return {
                "ok": True,
                "outcome": outcome,
                "message": "",
                "answer": answer,
                "answer_chars": len(answer or ""),
                "code": 0,
                "seconds": DEMO_TASK_SECONDS,
            }

    def start(
        self, prompt: str, *, resume: bool = False, agent: str | None = None
    ) -> dict[str, Any]:
        task_id = secrets.token_hex(16)
        answer = DEMO_HOSTILE if "hostil" in prompt else DEMO_ANSWER
        now = time.time()
        one = {"task": task_id, "asked": prompt, "asked_at": now, "answer": answer}
        with self._lock:
            self._of.setdefault(agent, []).append(one)
            del self._of[agent][:-20]
        return {"ok": True, "outcome": "started", "message": "", "task": task_id}

    def stop(self, task_id: str, *, agent: str | None = None) -> bool:
        with self._lock:
            for one in self._of.get(agent, []):
                if self._outcome_of(one) == "running":
                    one["stopped"] = True
        return True

    @staticmethod
    def _outcome_of(one: dict[str, Any]) -> str:
        if one.get("stopped"):
            return "stopped"
        return "ok" if time.time() - one["asked_at"] >= DEMO_TASK_SECONDS else "running"


def _refused(message: str) -> dict[str, Any]:
    return {"ok": False, "outcome": "invalid", "message": message, "applied": "none"}


def _now() -> str:
    return f"{datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ}"


def _later(seconds: float) -> str:
    return f"{datetime.now(UTC) + timedelta(seconds=seconds):%Y-%m-%dT%H:%M:%SZ}"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    config = Path(argv[1])
    paths = WebPaths.from_file(config)
    port = int(argv[2]) if len(argv) > 2 else DEFAULT_PORT
    name, others = demo_agents(config.parent)

    def announce(url: str, run_name: str) -> None:
        print(
            f"Puesto de vigilancia listo (demo), solo en este ordenador:\n\n  {url}\n", flush=True
        )
        print(f"Nombre de esta ejecución: {run_name}\nCtrl-C la para.", flush=True)

    said = DEMO_DECIDED_EN if demo_english(config.parent) else DEMO_DECIDED
    approver = DemoApprover(config.parent / "requests.json", said)
    run_web(
        paths,
        port,
        announce,
        snapshots=folder_snapshots(paths.volume / "snapshots"),
        agent_name=name,
        others=others,
        pending=demo_requests(config.parent / "requests.json", approver),
        settings=DemoSettings(config.parent / "settings.json"),
        approver=approver,
        tasks=DemoTasks(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
