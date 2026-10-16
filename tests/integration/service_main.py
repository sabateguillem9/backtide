"""`vigia vigilar` for the VM tests: the real command, with the one concession they need.

The VM tests run without root, so the agent's ids are the test user's, and AgentJail refuses
that unless ``allow_shared_ids`` says so. A config file cannot set it (it is not an ``[agent]``
option, on purpose), so this launcher hands the real service a jail with it set and then runs
``vigia vigilar`` as it is: the argument parsing, the signal handlers, the messages and the exit
codes are the production ones.

    python -m tests.integration.service_main <config.toml>
"""

import sys
from dataclasses import replace
from pathlib import Path

import vigia.cli as cli
import vigia.service.runner as runner
from vigia.jail import AgentJail
from vigia.service.config import ServiceConfig


def serve_without_root(config: ServiceConfig) -> None:
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    runner.serve(config, jail=jail)


if __name__ == "__main__":
    cli.serve = serve_without_root  # type: ignore[attr-defined]
    raise SystemExit(cli.main(["vigilar", "--config", str(Path(sys.argv[1]))]))
