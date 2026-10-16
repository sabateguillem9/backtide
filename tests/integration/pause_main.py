"""`vigia vigilar` on a capped workspace, for the VM tests of the pause by space (T04d-2).

    python -m tests.integration.pause_main <config.toml> <quota volume mount point>

The real command (argument parsing, signals, messages, exit codes) with the concessions the VM
tests need, all in the parts handed to ``runner.serve``:

- the jail with ``allow_shared_ids`` (the tests run without root), as service_main.py does;
- a store whose cap is set through the one privileged command of the tests
  (``QuotaVolume.set_limit``: ``sudo -n btrfs qgroup limit``, checked before it runs), because
  setting a qgroup limit needs CAP_SYS_ADMIN;
- the real gate, but with the host disk read as plenty: the VM keeps its /tmp small, and P6
  would pause on it before anything the test does (P6 has its own unit tests).
"""

import sys
from dataclasses import replace
from pathlib import Path

import vigia.cli as cli
import vigia.service.runner as runner
from tests.integration.conftest import VOLUME_IMAGE, QuotaVolume
from vigia.jail import AgentJail
from vigia.service.config import ServiceConfig
from vigia.service.pause import make_space_gate
from vigia.snapshots import SnapshotStore, space
from vigia.snapshots.space import GIB, HostSpace

PLENTY = HostSpace(total=500 * GIB, free=400 * GIB)


def sample_with_plenty_of_host(root: Path, workspace: Path, state_dir: Path) -> space.Sample:
    found = space.sample(root, workspace, state_dir)
    errors = tuple(error for error in found.errors if not error.startswith("host space"))
    return replace(found, host=PLENTY, errors=errors)


def serve_on(mnt: Path) -> None:
    volume = QuotaVolume(mnt, mnt.parent / VOLUME_IMAGE)

    def serve(config: ServiceConfig) -> None:
        jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
        store = SnapshotStore(
            config.volume, workspace_limit=config.workspace_limit, set_limit=volume.set_limit
        )
        gate = make_space_gate(config, store, sample=sample_with_plenty_of_host)
        runner.serve(config, jail=jail, store=store, space=gate)

    cli.serve = serve  # type: ignore[attr-defined]


if __name__ == "__main__":
    serve_on(Path(sys.argv[2]))
    raise SystemExit(cli.main(["vigilar", "--config", str(Path(sys.argv[1]))]))
