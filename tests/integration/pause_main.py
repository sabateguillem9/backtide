"""`backtide vigilar` on a capped workspace, for the VM tests of the pause by space (T04d-2).

    python -m tests.integration.pause_main <config.toml> <quota volume mount point>

The real command (argument parsing, signals, messages, exit codes) with the concessions the VM
tests need, all in the parts handed to ``runner.serve``:

- the jail with ``allow_shared_ids`` (the tests run without root), as service_main.py does;
- a store whose cap is set through the one privileged command of the tests
  (``QuotaVolume.set_limit``: ``sudo -n btrfs qgroup limit``, checked before it runs), because
  setting a qgroup limit needs CAP_SYS_ADMIN;
- the real gate, but with the host disk read as plenty: the VM keeps its /tmp small, and P6
  would pause on it before anything the test does (P6 has its own unit tests);
- a late space check on demand (``retraso-del-hilo-de-espacio``, tests/attacks/
  test_space_late_attacks.py): when ``<state_dir>/SPACE_DELAY_FILE`` holds a number of seconds,
  the space thread's next reading waits that long first, once (the file is removed). The state
  directory is backtide's, which the agent never sees (invariant 1).
"""

import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

import backtide.cli as cli
import backtide.service.runner as runner
from backtide.jail import AgentJail
from backtide.service.config import ServiceConfig
from backtide.service.pause import make_space_gate
from backtide.snapshots import SnapshotStore, space
from backtide.snapshots.space import GIB, HostSpace
from tests.integration.conftest import VOLUME_IMAGE, QuotaVolume
from tests.integration.proxy_kit import test_proxy

PLENTY = HostSpace(total=500 * GIB, free=400 * GIB)
SPACE_DELAY_FILE = "test-space-delay"
SPACE_THREAD = "backtide-space"  # the Ticker of Guardian.check_space


def delayed_on_demand(gate: Callable[[], Sequence[object]], state_dir: Path) -> Callable[[], list]:
    """``gate``, but the space thread's next call waits the seconds written in the delay file
    first (read once, then removed). Only the space thread: a snapshot's own check is not it."""
    flag = state_dir / SPACE_DELAY_FILE

    def gate_with_delay() -> list:
        if threading.current_thread().name == SPACE_THREAD:
            try:
                seconds = float(flag.read_text())
                flag.unlink()
            except (OSError, ValueError):
                seconds = 0.0
            if 0 < seconds <= 120:
                time.sleep(seconds)
        return list(gate())

    return gate_with_delay


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
        if gate is not None:
            gate = delayed_on_demand(gate, config.state_dir)
        # No process sensor: one privileged Tetragon per VM, and it is not what this tests.
        runner.serve(
            config, jail=jail, store=store, space=gate, sensor=False, proxy=test_proxy(config)
        )

    cli.serve = serve  # type: ignore[attr-defined]


if __name__ == "__main__":
    serve_on(Path(sys.argv[2]))
    raise SystemExit(cli.main(["vigilar", "--config", str(Path(sys.argv[1]))]))
