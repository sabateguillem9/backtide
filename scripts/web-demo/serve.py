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
"""

import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path

from backtide.snapshots import Snapshot
from backtide.web.agents import AgentSource, PendingRequest, RosterError, request_from
from backtide.web.paths import WebPaths
from backtide.web.reader import BoxReader
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
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
