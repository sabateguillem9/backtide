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

With ``--hold-timings <life>,<wait>,<preapproval>,<remember>[,<telegram_retry_after>]`` (T10-2)
the gate's times are shortened, in seconds (5 min, 90 s, 10 min and 10 min in production): no
config file can set them, so a scenario does not wait 5 minutes for a hold to expire. The fifth
(T10-5) is the Retry-After of Telegram's "pending".

With ``--reload-fails-when <file>`` (review of 40dfd53, finding 7) the service's reload of the
providers' keys (``runner.providers_now``, what the Settings page triggers) raises while
``<file>`` exists, so a scenario sees the real service fail closed. Nothing else changes.

    python -m tests.integration.service_main <config.toml> [--with-sensor]
        [--egress-grants <file.json>] [--hold-timings <life>,<wait>,<preapproval>,<remember>]
        [--reload-fails-when <file>]
"""

import sys
from dataclasses import replace
from pathlib import Path

import backtide.cli as cli
import backtide.service.runner as runner
from backtide.jail import AgentJail
from backtide.service.config import ServiceConfig
from backtide.service.holds import HoldTimings
from tests.integration.proxy_kit import read_grants, test_proxy

WITH_SENSOR = "--with-sensor"
EGRESS_GRANTS = "--egress-grants"
HOLD_TIMINGS = "--hold-timings"
RELOAD_FAILS_WHEN = "--reload-fails-when"


def hold_timings(text: str) -> HoldTimings:
    """``life,wait,preapproval,remember`` and, optionally, Telegram's ``retry_after`` (T10-5:
    test_openclaw_telegram.py measures OpenClaw with the long one and the short one)."""
    parts = text.split(",")
    life, wait, preapproval, remember = (float(part) for part in parts[:4])
    timings = HoldTimings(life=life, wait=wait, preapproval=preapproval, remember=remember)
    if len(parts) == 5:
        timings = replace(timings, telegram_retry_after=int(parts[4]))
    return timings


def fail_reloads_when(marker: Path) -> None:
    """The keys' reload raises while ``marker`` exists (the test makes and removes it)."""
    production = runner.providers_now

    def providers_now(config: ServiceConfig) -> object:
        if marker.exists():
            raise RuntimeError("the test makes the keys' reload fail")
        return production(config)

    runner.providers_now = providers_now  # type: ignore[assignment]


def serve_without_root(
    config: ServiceConfig,
    *,
    with_sensor: bool = False,
    grants: dict[str, object] | None = None,
    timings: HoldTimings | None = None,
) -> None:
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    proxy = test_proxy(config, **(grants or {}))
    if with_sensor:
        sensor_jail = replace(config.sensor_jail_config(), file_perm="644")
        runner.serve(config, jail=jail, sensor_jail=sensor_jail, proxy=proxy, hold_timings=timings)
    else:
        runner.serve(config, jail=jail, sensor=False, proxy=proxy, hold_timings=timings)


if __name__ == "__main__":
    options = sys.argv[2:]
    sensor = WITH_SENSOR in options
    grants = None
    if EGRESS_GRANTS in options:
        grants = read_grants(Path(options[options.index(EGRESS_GRANTS) + 1]))
    timings = None
    if HOLD_TIMINGS in options:
        timings = hold_timings(options[options.index(HOLD_TIMINGS) + 1])
    if RELOAD_FAILS_WHEN in options:
        fail_reloads_when(Path(options[options.index(RELOAD_FAILS_WHEN) + 1]))
    cli.serve = lambda config: serve_without_root(  # type: ignore[attr-defined]
        config, with_sensor=sensor, grants=grants, timings=timings
    )
    raise SystemExit(cli.main(["vigilar", "--config", str(Path(sys.argv[1]))]))
