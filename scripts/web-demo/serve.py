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

The Settings page (T12e) asks the service through its control socket, which the demo does not
have. ``DemoSettings`` stands in for it: it starts from ``settings.json`` (a tail and a date per
kind, never a key), checks a value with the service's own rules and keeps only what the page may
show (the last four characters and when). It writes no file, holds no key and forgets everything
when the demo stops. The page, its confirmations, the CSRF token and the one-time tickets are the
real ones.
"""

import copy
import json
import logging
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime
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


def demo_requests(path: Path) -> Callable[[], list[PendingRequest]]:
    """The made-up requests in ``path``, read again on every call (seed.py rewrites it)."""

    def listing() -> list[PendingRequest]:
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return []
        requests = []
        for item in raw if isinstance(raw, list) else []:
            try:
                requests.append(request_from(item))
            except RosterError as error:
                logger.warning("a made-up request was skipped: %s", error)
        return requests

    return listing


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


def _refused(message: str) -> dict[str, Any]:
    return {"ok": False, "outcome": "invalid", "message": message, "applied": "none"}


def _now() -> str:
    return f"{datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ}"


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

    run_web(
        paths,
        port,
        announce,
        snapshots=folder_snapshots(paths.volume / "snapshots"),
        agent_name=name,
        others=others,
        pending=demo_requests(config.parent / "requests.json"),
        settings=DemoSettings(config.parent / "settings.json"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
