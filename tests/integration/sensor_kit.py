"""The real service with its process sensor in the VM (T07-3): test_sensor_exec.py and
test_sensor_connect.py.

The service is `backtide vigilar` (tests/integration/service_main.py ``--with-sensor``) watching
the real OpenClaw, with the real Tetragon beside it: privileged, ``--pid=host``, no network,
started and stopped by the service itself. Two concessions, both because the tests run without
root: Tetragon's file is 644 (inside the state's 0700 folder) so the reader can open it, and the
sensor's container carries this pytest's pid in its name (``[sensor] name``), so a killed run's
is removed by the next one, like the test agents.

Whatever happens, the sensor's container is stopped (SIGTERM: Tetragon unloads its programs)
and removed when the test ends: a privileged container is never left running.
"""

import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from uuid import uuid4

from backtide.blackbox import Event
from backtide.jail import docker as jail_docker
from backtide.service.config import ServiceConfig
from tests.integration.conftest import _is_stale_test_name
from tests.integration.service_kit import Service, wait_until

SENSOR_PREFIX = "backtide-test-sensor-"
EVENT_TIMEOUT = 60.0  # a command, Tetragon's buffered write, the reader's 0.5 s and the rules
DOWN_WITHIN = 90.0  # docs/23, matar-el-sensor
SENSOR_START_TIMEOUT = 120.0  # the image is there (T07-1): Tetragon loads in ~1.2 s
STOP_TIMEOUT = 60


def remove_stale_sensors() -> None:
    """The sensors of runs killed with kill -9 (their pytest is gone)."""
    names = jail_docker.run(["ps", "--all", "--format", "{{.Names}}"]).stdout.split()
    for name in names:
        if _is_stale_test_name(name, SENSOR_PREFIX):
            remove_sensor(name)


def remove_sensor(name: str) -> None:
    jail_docker.run(["stop", "--time", "10", name], check=False, timeout=STOP_TIMEOUT)
    jail_docker.run(["rm", "--force", "--volumes", name], check=False)


@contextmanager
def sensed_service(
    make_real_service: Callable[..., Service], *, required: bool = False
) -> Iterator[Service]:
    """A service (not started) whose config has a ``[sensor]`` and whose launcher runs it."""
    remove_stale_sensors()
    service = make_real_service()
    name = f"{SENSOR_PREFIX}{os.getpid()}-{uuid4().hex[:12]}"
    with service.config_path.open("a") as config:
        config.write(f'[sensor]\nname = "{name}"\n')
        if required:
            config.write("required = true\n")
    service.config = ServiceConfig.from_file(service.config_path)
    service.main_args = ("--with-sensor",)
    try:
        yield service
    finally:
        try:
            service.shutdown()
        finally:
            remove_sensor(name)


def sensor_name(service: Service) -> str:
    return service.config.sensor_jail_config().name


def wait_event(
    service: Service,
    predicate: Callable[[Event], bool],
    what: str,
    timeout: float = EVENT_TIMEOUT,
    *,
    since: int = 0,
) -> Event:
    """The first event after seq ``since`` that ``predicate`` likes, waiting for it."""
    found: list[Event] = []

    def seen() -> bool:
        found[:] = [e for e in service.box.events(since_seq=since) if predicate(e)]
        return bool(found)

    wait_until(seen, timeout, what, interval=0.5, context=service.diagnosis)
    return found[0]


def sensor_started(service: Service, *, since: int = 0) -> Event:
    return wait_event(
        service,
        lambda e: e.action == "sensor_start",
        "the sensor to start",
        SENSOR_START_TIMEOUT,
        since=since,
    )


def execs_with(service: Service, text: str) -> list[Event]:
    return [
        e
        for e in service.box.events(source="exec", action="exec")
        if text in str(e.details.get("argv", ""))
    ]


def head_seq(service: Service) -> int:
    head = service.box.head()
    return head[0] if head is not None else 0


def sensor_inspect(service: Service) -> dict[str, Any] | None:
    result = jail_docker.run(
        ["container", "inspect", "--format", "{{json .}}", sensor_name(service)], check=False
    )
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def events_text(service: Service) -> str:
    """Everything Tetragon wrote (644 here: see the module's docstring)."""
    folder = service.config.sensor_jail_config().events_dir
    return "".join(path.read_text(errors="replace") for path in sorted(folder.glob("*.log")))
