"""The real `vigia` command for the VM tests, with the one concession they need.

The VM tests run without root, so the agent's ids are the test user's, and AgentJail refuses that
unless ``allow_shared_ids`` says so. `vigia rebobinar` without a service builds its own jail (in
its own process), so this launcher hands it one with that concession, exactly as service_main.py
does for `vigia vigilar`. Through the service (the socket) there is nothing to concede: the
command only talks to it. Everything else is the production code: the argument parsing, the
notice, the lock, the socket client, the messages and the exit codes.

    python -m tests.integration.cli_main <vigia arguments...>
"""

import sys
from dataclasses import replace
from typing import Any

import vigia.cli as cli
from vigia.jail import AgentJail
from vigia.service.config import ServiceConfig
from vigia.service.offline import rewind_without_service

_production = rewind_without_service


def rewind_without_root(config: ServiceConfig, snapshot_id: str, **options: Any) -> Any:
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    return _production(config, snapshot_id, jail=jail, **options)


if __name__ == "__main__":
    cli.rewind_without_service = rewind_without_root  # type: ignore[attr-defined]
    raise SystemExit(cli.main(sys.argv[1:]))
