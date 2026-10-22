"""Shared Claude Code lab for the evil-agent battery (T17a-5).

The battery's Claude Code scenarios (`make ataques PERFIL=claude-code`) need the real
`backtide vigilar` with ``[agent] profile = "claude-code"``, its process sensor and T06's fake
internet. Several scenarios that were OpenClaw's (``salida-directa``, ``dns-tunel``,
``socket-de-control``, ``leer-secretos``) run on both agents now, so this lab lives apart and the
fixtures (``cc_lab`` deny mode, ``cc_lab_hold`` hold mode) are defined in conftest.py, visible to
every test module. Only fake and made-up keys: nothing reaches anything real (invariant 8).
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from backtide.blackbox import Event
from backtide.jail.profiles.claude_code import PROVIDER as CC_PROVIDER
from backtide.service.config import ServiceConfig
from tests.integration import sensor_kit
from tests.integration.conftest import _new_service, _remove_stale_test_agents
from tests.integration.internet_kit import (
    OTHER_HOST as NOT_ALLOWED_HOST,
)
from tests.integration.internet_kit import (
    PLAIN_HOST as ECHO_HOST,
)
from tests.integration.internet_kit import (
    FakeInternet,
    made_up_key,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import Service

# Claude Code calls api.anthropic.com itself (no base URL), so that is the provider's host.
PROVIDER_HOST = "api.anthropic.com"
PLAIN_HOST = ECHO_HOST  # the ordinary allowed host that echoes what reached it
DNS_CANARY_DOMAIN = "dns-canary.test"
AGENT_TOML = 'profile = "claude-code"\n'
# A write a held lab waits 3 s for before it answers "pending" (the production wait is 90 s).
HOLD_TIMINGS = ("--hold-timings", "60,3,60,60")


def proxy_toml(*, unknown_hosts: str, allow_hosts: list[str]) -> str:
    """``[proxy]``/``[gate]`` for a Claude Code lab: the anthropic provider, an allow list and
    the gate's mode (``deny`` for the allow-list scenarios, ``hold`` for dns-tunel)."""
    return (
        f"allow_hosts = {json.dumps(allow_hosts)}\n"
        f'[[proxy.providers]]\nname = "{CC_PROVIDER}"\nkind = "anthropic"\n'
        f'\n[gate]\nunknown_hosts = "{unknown_hosts}"\n'
    )


@dataclass
class CcAgent:
    """The part of conftest's ``RunningAgent`` that the shared scenarios touch, over a service's
    jail: ``run_script`` (``exec``), and the helpers of test_workspace_attacks (``name``,
    ``jail``, ``proxy.config``)."""

    service: Service

    @property
    def jail(self) -> Any:
        return self.service.jail

    @property
    def name(self) -> str:
        return self.service.jail.config.name

    @property
    def workspace(self) -> Path:
        return self.service.jail.config.agent_dir

    @property
    def proxy(self) -> SimpleNamespace:
        return SimpleNamespace(config=self.service.config.proxy_jail_config())

    def exec(self, argv: list[str], *, check: bool = False, timeout: float = 60) -> Any:
        return self.service.jail.exec(argv, check=check, timeout=timeout)


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    real: str  # the made-up real key of the anthropic provider

    @property
    def agent(self) -> CcAgent:
        return CcAgent(self.service)

    @property
    def work(self) -> Path:
        return self.service.store.workspace / "agente" / "work"

    @property
    def fake(self) -> str:
        return self.service.config.provider_keys[CC_PROVIDER].fake

    def head(self) -> int:
        events = self.service.events()
        return events[-1].seq if events else 0

    def since(self, seq: int, action: str | None = None) -> list[Event]:
        return [e for e in self.service.events(action) if e.seq > seq]

    def tagged(self, tag: str, action: str | None = None) -> list[Event]:
        prefix = f"/{tag}/"
        return [
            e
            for e in self.service.events(action)
            if str(e.details.get("path", "")).startswith(prefix)
        ]


def build_cc_lab(
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
    *,
    unknown_hosts: str,
    allow_hosts: list[str],
) -> tuple[Lab, str]:
    """Start a Claude Code service with its process sensor and fake internet. Returns the lab and
    the sensor's container name (the caller removes it on teardown)."""
    sensor_kit.remove_stale_sensors()
    _remove_stale_test_agents()
    real = made_up_key("anthropic")
    service = _new_service(
        btrfs_volume,
        tmp_path_factory,
        agent_toml=AGENT_TOML,
        proxy_toml=proxy_toml(unknown_hosts=unknown_hosts, allow_hosts=allow_hosts),
        real_keys={CC_PROVIDER: real},
    )
    sensor = f"{sensor_kit.SENSOR_PREFIX}{os.getpid()}-{uuid4().hex[:12]}"
    with service.config_path.open("a") as config:
        config.write(f'[sensor]\nname = "{sensor}"\n')
    service.config = ServiceConfig.from_file(service.config_path)
    internet: FakeInternet | None = None
    try:
        internet = start_fake_internet(service, tmp_path_factory.mktemp("t17a5-internet"))
        service.main_args = ("--with-sensor", *internet.service_args(), *HOLD_TIMINGS)
        service.start()
        service.wait_ready()
        sensor_kit.sensor_started(service)
    except BaseException:
        stop_with_internet(service, internet)
        sensor_kit.remove_sensor(sensor)
        raise
    return Lab(service, internet, real), sensor


def stop_cc_lab(lab: Lab, sensor: str) -> None:
    try:
        stop_with_internet(lab.service, lab.internet)
    finally:
        sensor_kit.remove_sensor(sensor)


# What the shared allow-list labs permit (deny mode): the echo/plain host and the DNS canary.
DENY_ALLOW_HOSTS = [ECHO_HOST, f"*.{DNS_CANARY_DOMAIN}"]
HOLD_ALLOW_HOSTS = [ECHO_HOST, f"*.{DNS_CANARY_DOMAIN}"]

__all__ = [
    "AGENT_TOML",
    "DENY_ALLOW_HOSTS",
    "DNS_CANARY_DOMAIN",
    "ECHO_HOST",
    "HOLD_ALLOW_HOSTS",
    "NOT_ALLOWED_HOST",
    "PLAIN_HOST",
    "PROVIDER_HOST",
    "CcAgent",
    "Lab",
    "build_cc_lab",
    "stop_cc_lab",
]
