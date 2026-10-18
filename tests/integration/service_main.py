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

With ``--egress-grants <file.json>`` (T06-5, tests/integration/internet_kit.py) the proxy gets the
grants that let it use the test's fake internet on its egress network.

    python -m tests.integration.service_main <config.toml> [--with-sensor]
        [--egress-grants <file.json>]
"""

import sys
from dataclasses import replace
from pathlib import Path

import backtide.cli as cli
import backtide.service.runner as runner
from backtide.jail import AgentJail
from backtide.service.config import ServiceConfig
from tests.integration.proxy_kit import read_grants, test_proxy

WITH_SENSOR = "--with-sensor"
EGRESS_GRANTS = "--egress-grants"


def serve_without_root(
    config: ServiceConfig, *, with_sensor: bool = False, grants: dict[str, object] | None = None
) -> None:
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    proxy = test_proxy(config, **(grants or {}))
    if with_sensor:
        sensor_jail = replace(config.sensor_jail_config(), file_perm="644")
        runner.serve(config, jail=jail, sensor_jail=sensor_jail, proxy=proxy)
    else:
        runner.serve(config, jail=jail, sensor=False, proxy=proxy)


if __name__ == "__main__":
    options = sys.argv[2:]
    sensor = WITH_SENSOR in options
    grants = None
    if EGRESS_GRANTS in options:
        grants = read_grants(Path(options[options.index(EGRESS_GRANTS) + 1]))
    cli.serve = lambda config: serve_without_root(config, with_sensor=sensor, grants=grants)  # type: ignore[attr-defined]
    raise SystemExit(cli.main(["vigilar", "--config", str(Path(sys.argv[1]))]))
