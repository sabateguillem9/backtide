"""A rewind that dies half way, for the VM tests: the real service, killed with SIGKILL from
inside its own rewind.

    python -m tests.integration.rewind_main <config.toml> <snapshot id> before|after

It takes the service lock, builds the real parts (``build_guardian``, with the one concession
of the VM tests: ``allow_shared_ids``), starts them (the agent boots, watched) and calls
``Guardian.rewind``. The file watcher's ``suspended`` is wrapped so that the process kills
itself:

- ``before``: on entering it. The agent was just stopped by the rewind's quiesce; the staging
  copy exists, ``rewind.pending`` and ``rewind_requested`` are written, the swap has NOT
  happened.
- ``after``: on leaving it. The swap happened and the undo point is published; the watcher is
  not rearmed and the agent is not started.

Nothing else is changed: what a fresh service finds afterwards is what a crash would leave.
"""

import os
import signal
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from vigia.jail import AgentJail
from vigia.service.config import ServiceConfig
from vigia.service.runner import build_guardian, take_lock


def main(config_path: Path, target: str, when: str) -> None:
    if when not in ("before", "after"):
        raise SystemExit(f"when must be 'before' or 'after', not {when!r}")
    config = ServiceConfig.from_file(config_path)
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    with take_lock(config.lock_file):
        guardian, alerts, _box = build_guardian(config, jail=jail)
        alerts.start()
        guardian.start()
        watcher = guardian._watcher  # noqa: SLF001 - the one seam this test needs
        suspended = watcher.suspended

        @contextmanager
        def dying(new_current: str | None = None) -> Iterator[None]:
            if when == "before":
                os.kill(os.getpid(), signal.SIGKILL)
            with suspended(new_current):
                yield
                if when == "after":
                    os.kill(os.getpid(), signal.SIGKILL)

        watcher.suspended = dying  # type: ignore[method-assign]
        print("rewinding", flush=True)
        outcome = guardian.rewind(target, requested_by="test")
        print(f"the rewind was not killed: {outcome}", flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
