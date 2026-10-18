"""The egress proxy in the service (backtide/service/egress.py): start, watch and stop, with a
fake ProxyJail and a fake channel. The real ones run in the VM (test_proxy_channel.py)."""

from collections.abc import Callable
from typing import Any

import pytest

from backtide.gate.providers import Providers
from backtide.jail.docker import JailError
from backtide.jail.proxy_config import ProxyJailConfig
from backtide.notify import AlertLevel
from backtide.service.egress import (
    RESTARTS_PER_HOUR,
    SILENCE_LIMIT,
    Egress,
    EgressHooks,
)
from backtide.service.proxy_channel import ChannelError, Policy


class FakeProxyJail:
    def __init__(self, log: list[str], tmp: Any) -> None:
        self.log = log
        self.config = ProxyJailConfig(ca_dir=tmp / "ca", channel_dir=tmp / "ch")
        self.running = False
        self.created = False
        self.fail: dict[str, Exception] = {}

    def _step(self, name: str) -> None:
        self.log.append(f"proxy.{name}")
        if name in self.fail:
            raise self.fail[name]

    def ensure_network(self) -> None:
        self._step("ensure_network")

    def prepare_channel(self) -> None:
        self._step("prepare_channel")

    def exists(self) -> bool:
        return self.created

    def create(self) -> None:
        self._step("create")
        self.created = True

    def is_running(self) -> bool:
        if "is_running" in self.fail:
            raise self.fail["is_running"]
        return self.running

    def kill(self) -> None:
        self._step("kill")
        self.running = False

    def check_agent_network(self, agent_name: str) -> None:
        self._step(f"check_agent_network({agent_name})")

    def start(self) -> None:
        self._step("start")
        self.running = True

    def wait_ready(self) -> None:
        self._step("wait_ready")

    def stop(self) -> None:
        self._step("stop")
        self.running = False


class FakeChannel:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.hello = {"type": "hello", "version": "0.1.0", "pid": 9}
        self.closed = False
        self.close_reason: str | None = None
        self.silence = 0.0

    def silent_for(self) -> float:
        return self.silence

    def close(self, reason: str = "closed") -> None:
        if not self.closed:
            self.log.append(f"channel.close({reason})")
        self.closed = True
        self.close_reason = self.close_reason or reason


class World:
    def __init__(self, tmp: Any) -> None:
        self.log: list[str] = []
        self.records: list[tuple[str, dict[str, Any], int]] = []
        self.alerts: list[tuple[AlertLevel, str]] = []
        self.backs = 0
        self.now = [0.0]
        self.jail = FakeProxyJail(self.log, tmp)
        self.channels: list[FakeChannel] = []
        self.connect_error: Exception | None = None
        self.egress = Egress(
            self.jail,  # type: ignore[arg-type]
            agent_name="the-agent",
            policy=Policy(allow_hosts=("example.com",), providers=Providers([])),
            record=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
            thread=False,
            connect=self.connect,
            monotonic=lambda: self.now[0],
            sleep=lambda s: None,
        )
        self.hooks = EgressHooks(record=self.record, alert=self.alert, back=self.back)

    def connect(self, jail: Any, timeout: float) -> FakeChannel:
        self.log.append(f"connect({timeout})")
        if self.connect_error is not None:
            raise self.connect_error
        channel = FakeChannel(self.log)
        self.channels.append(channel)
        return channel  # type: ignore[return-value]

    def record(self, source: str, action: str, target: str = "", *, details: Any = None,
               risk: int = 0) -> None:  # fmt: skip
        assert source == "system"
        self.records.append((action, details or {}, risk))

    def alert(self, level: AlertLevel, title: str, body: str, event: Any = None) -> None:
        self.alerts.append((level, title))

    def back(self) -> None:
        self.backs += 1

    def actions(self) -> list[str]:
        return [action for action, _, _ in self.records]

    def only(self, action: str) -> tuple[dict[str, Any], int]:
        [(details, risk)] = [(d, r) for a, d, r in self.records if a == action]
        return details, risk


@pytest.fixture
def world(tmp_path: Any) -> World:
    return World(tmp_path)


def started(world: World) -> World:
    assert world.egress.start(world.hooks)
    world.log.clear()
    world.records.clear()
    world.alerts.clear()
    return world


# --- start ---------------------------------------------------------------------------------------


def test_start_brings_up_the_proxy_and_its_channel_in_order(world: World) -> None:
    assert world.egress.start(world.hooks) is True
    assert world.log == [
        "proxy.ensure_network",
        "proxy.prepare_channel",
        "proxy.create",
        "proxy.check_agent_network(the-agent)",
        "proxy.start",
        "proxy.wait_ready",
        "connect(30.0)",
    ]
    details, risk = world.only("proxy_start")
    assert (details["reason"], details["version"], risk) == ("boot", "0.1.0", 0)
    assert details["allow_hosts"] == 1 and details["providers"] == []
    assert world.egress.allows_agent()


def test_a_proxy_left_running_is_killed_and_started_fresh(world: World) -> None:
    world.jail.created = world.jail.running = True
    assert world.egress.start(world.hooks)
    assert "proxy.create" not in world.log
    assert world.log.index("proxy.kill") < world.log.index("proxy.start")


@pytest.mark.parametrize(
    ("step", "error"),
    [
        ("ensure_network", JailError("unsafe network")),
        ("check_agent_network", JailError("intruder")),
        ("wait_ready", JailError("never ready")),
        ("connect", ChannelError("no hello")),
    ],
)
def test_without_the_hello_the_proxy_is_not_up(world: World, step: str, error: Exception) -> None:
    if step == "connect":
        world.connect_error = error
    elif step == "check_agent_network":
        world.jail.fail["check_agent_network(the-agent)"] = error
    else:
        world.jail.fail[step] = error
    assert world.egress.start(world.hooks) is False
    assert not world.egress.allows_agent()
    details, risk = world.only("proxy_start_failed")
    assert risk == 2 and details["reason"] == "boot"
    assert world.alerts[0][0] is AlertLevel.ERROR
    assert "proxy_start" not in world.actions()


def test_after_a_failed_start_the_watch_retries_without_a_second_down(world: World) -> None:
    world.connect_error = ChannelError("no hello")
    world.egress.start(world.hooks)
    world.connect_error = None
    world.egress.check()
    assert "proxy_down" not in world.actions()
    # The container runs (only the hello was missing): its channel is simply tried again.
    assert world.actions() == ["proxy_start_failed", "proxy_up"]
    assert world.egress.allows_agent() and world.backs == 1
    # A proxy that never started at all is restarted instead.
    world.jail.running = False
    world.egress.check()
    assert world.actions()[-4:] == ["proxy_down", "proxy_restart", "proxy_start", "proxy_up"]


# --- the watch -----------------------------------------------------------------------------------


def test_a_healthy_proxy_is_left_alone(world: World) -> None:
    started(world)
    world.egress.check()
    assert world.records == [] and world.log == []


def test_a_proxy_that_stopped_is_down_then_restarted(world: World) -> None:
    started(world)
    world.jail.running = False
    world.egress.check()
    assert world.actions() == ["proxy_down", "proxy_restart", "proxy_start", "proxy_up"]
    assert world.only("proxy_down") == ({"problem": "not_running"}, 2)
    assert world.only("proxy_start")[0]["reason"] == "restart"
    assert [level for level, _ in world.alerts] == [AlertLevel.ERROR, AlertLevel.INFO]
    assert world.backs == 1 and world.egress.allows_agent()


def test_a_lost_channel_is_reconnected_without_restarting(world: World) -> None:
    started(world)
    world.channels[-1].closed = True
    world.channels[-1].close_reason = "eof"
    world.egress.check()
    assert world.actions() == ["proxy_down", "proxy_up"]
    assert world.only("proxy_down")[0] == {"problem": "channel_eof"}
    assert world.only("proxy_up")[0]["how"] == "reconnect"
    assert "proxy.start" not in world.log
    assert world.backs == 1


def test_a_proxy_that_broke_the_protocol_is_restarted_not_reconnected(world: World) -> None:
    started(world)
    world.channels[-1].closed = True
    world.channels[-1].close_reason = "protocol"
    world.egress.check()
    assert world.only("proxy_down") == ({"problem": "channel_protocol"}, 2)
    assert world.log.index("proxy.kill") < world.log.index("proxy.start")
    assert world.actions()[-3:] == ["proxy_restart", "proxy_start", "proxy_up"]


def test_a_silent_proxy_is_restarted(world: World) -> None:
    started(world)
    world.channels[-1].silence = SILENCE_LIMIT + 1
    world.egress.check()
    assert world.only("proxy_down")[0] == {"problem": "silent"}
    assert world.log.index("proxy.kill") < world.log.index("proxy.start")


def test_while_down_the_agent_is_not_let_start_and_down_is_said_once(world: World) -> None:
    started(world)
    world.jail.running = False
    world.jail.fail["start"] = JailError("still broken")
    world.egress.check()
    assert not world.egress.allows_agent()
    world.now[0] += 60
    world.egress.check()
    assert world.actions().count("proxy_down") == 1
    assert world.actions().count("proxy_start_failed") == 2


def test_restarts_are_capped_per_hour(world: World) -> None:
    started(world)
    world.jail.running = False
    world.jail.fail["start"] = JailError("still broken")
    for _ in range(RESTARTS_PER_HOUR + 3):
        world.now[0] += 60
        world.egress.check()
    assert world.actions().count("proxy_restart") == RESTARTS_PER_HOUR
    assert world.actions().count("proxy_restart_skipped") == 1
    world.now[0] += 3600
    world.egress.check()
    assert world.actions().count("proxy_restart") == RESTARTS_PER_HOUR + 1


def test_a_failing_back_hook_does_not_break_the_watch(world: World) -> None:
    def broken() -> None:
        raise RuntimeError("guardian bug")

    world.hooks = EgressHooks(record=world.record, alert=world.alert, back=broken)
    started(world)
    world.jail.running = False
    world.egress.check()
    assert world.egress.allows_agent()


def test_a_watch_that_breaks_is_recorded(world: World) -> None:
    started(world)
    world.jail.fail["is_running"] = RuntimeError("docker is gone")
    world.egress.check()
    assert world.only("proxy_watch_failed")[1] == 2


# --- stop ----------------------------------------------------------------------------------------


def test_stop_stops_the_proxy_then_closes_the_channel(world: World) -> None:
    started(world)
    world.egress.stop("service_stop")
    assert world.log == ["proxy.stop", "channel.close(stop)"]
    assert world.only("proxy_stop") == ({"reason": "service_stop", "stopped": True}, 0)
    assert not world.egress.allows_agent()


def test_a_proxy_that_will_not_stop_is_killed(world: World) -> None:
    started(world)
    world.jail.fail["stop"] = JailError("timeout")
    world.egress.stop()
    assert world.log[:2] == ["proxy.stop", "proxy.kill"]
    assert world.only("proxy_stop")[0]["stopped"] is True


def test_a_proxy_that_cannot_even_be_killed_is_said(world: World) -> None:
    started(world)
    world.jail.fail["stop"] = JailError("timeout")
    world.jail.fail["kill"] = JailError("daemon down")
    world.egress.stop()
    details, risk = world.only("proxy_stop")
    assert details["stopped"] is False and risk == 2


def test_the_watch_runs_on_its_own_thread(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import backtide.service.egress as egress

    ticks: list[str] = []

    class FakeTicker:
        def __init__(self, name: str, every: float, step: Callable[[], None]) -> None:
            ticks.append(f"{name}/{every}")

        def start(self) -> None:
            ticks.append("start")

        def close(self) -> None:
            ticks.append("close")

    monkeypatch.setattr(egress, "Ticker", FakeTicker)
    world = World(tmp_path)
    world.egress._thread = True
    world.egress.start(world.hooks)
    world.egress.stop()
    assert ticks == [f"backtide-egress/{egress.WATCH_EVERY}", "start", "close"]
