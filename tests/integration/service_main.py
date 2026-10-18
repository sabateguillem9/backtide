"""`backtide vigilar` for the VM tests: the real command, with the concessions they need.

The VM tests run without root, so the agent's ids are the test user's, and AgentJail refuses
that unless ``allow_shared_ids`` says so. A config file cannot set it (it is not an ``[agent]``
option, on purpose), so this launcher hands the real service a jail with it set and then runs
``backtide vigilar`` as it is: the argument parsing, the signal handlers, the messages and the exit
codes are the production ones.

The process sensor (T07-3) is left out unless ``--with-sensor`` is given: it is a privileged
Tetragon, one per VM, and only test_sensor_exec.py tests it. With it, Tetragon's file is made
readable by the test user (``file_perm`` 644, inside the state's 0700 folder), the one
concession the reader needs without root.

    python -m tests.integration.service_main <config.toml> [--with-sensor]
"""

import sys
from dataclasses import replace
from pathlib import Path

import backtide.cli as cli
import backtide.service.runner as runner
from backtide.jail import AgentJail
from backtide.service.config import ServiceConfig
from tests.integration.proxy_kit import test_proxy

WITH_SENSOR = "--with-sensor"


def serve_without_root(config: ServiceConfig, *, with_sensor: bool = False) -> None:
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    if with_sensor:
        sensor_jail = replace(config.sensor_jail_config(), file_perm="644")
        runner.serve(config, jail=jail, sensor_jail=sensor_jail, proxy=test_proxy(config))
    else:
        runner.serve(config, jail=jail, sensor=False, proxy=test_proxy(config))


if __name__ == "__main__":
    sensor = WITH_SENSOR in sys.argv[2:]
    cli.serve = lambda config: serve_without_root(config, with_sensor=sensor)  # type: ignore[attr-defined]
    raise SystemExit(cli.main(["vigilar", "--config", str(Path(sys.argv[1]))]))
