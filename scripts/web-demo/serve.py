"""The Mac's web demo: `vigia web` over the made-up state of seed.py, with its snapshot list.

Usage: python scripts/web-demo/serve.py <folder>/vigia.toml [port]

The real web lists the snapshots of the btrfs volume (``SnapshotStore``), which a Mac does not
have: there the page would fall back to the black box. seed.py also leaves one empty folder per
snapshot in ``<volume>/snapshots/``; this lists those by name, so the snapshots page looks like
the real one. Demo only: ``vigia web`` itself never takes this path.
"""

import sys
from pathlib import Path

from vigia.snapshots import Snapshot
from vigia.web.paths import WebPaths
from vigia.web.server import DEFAULT_PORT, run_web


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    paths = WebPaths.from_file(Path(argv[1]))
    port = int(argv[2]) if len(argv) > 2 else DEFAULT_PORT
    folder = paths.volume / "snapshots"

    def snapshots() -> list[Snapshot]:
        found = [
            s for name in sorted(p.name for p in folder.iterdir()) if (s := Snapshot.parse(name))
        ]
        return sorted(found, key=lambda s: (s.taken_at, s.id))

    def announce(url: str, run_name: str) -> None:
        print(
            f"Puesto de vigilancia listo (demo), solo en este ordenador:\n\n  {url}\n", flush=True
        )
        print(f"Nombre de esta ejecución: {run_name}\nCtrl-C la para.", flush=True)

    run_web(paths, port, announce, snapshots=snapshots)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
