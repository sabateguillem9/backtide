"""Unit tests for backtide/service/process_sensor.py: the process sensor in the service (T07-3).

Docker is faked by a ``FakeSensorJail`` (the container) and a ``FakeAgent`` (``docker exec`` in
the agent); the reader is the real one, on a real folder, and the fake sensor plays Tetragon:
while it "sees", a probe launched in the agent shows up in tetragon.log as the real line would
(T07-1's fixture with the probe's arguments). Time is a fake clock: nothing here sleeps."""

import copy
import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from backtide.jail.docker import JailError
from backtide.jail.sensor import IMAGE, TETRAGON_VERSION, SensorJailConfig
from backtide.notify import AlertLevel
from backtide.sensors import procs
from backtide.sensors.tetragon import ReaderConfig, TetragonReader
from backtide.service.process_sensor import (
    ProcessSensor,
    SensorHooks,
    SensorState,
    SnapshotBefore,
    recorded_keys,
)
from backtide.snapshots import Snapshot


@pytest.fixture(autouse=True)
def readers_stop_with_their_test(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A sensor a test starts and never stops keeps its reader's thread polling the test's
    folder every 0.5 s for the rest of the suite: 48 of them did, and another test's descriptor
    check took one of their cursor files for a leak of its own. Each reader still running at the
    end of its test is stopped, and none may be left alive."""
    running: list[TetragonReader] = []
    start, stop = TetragonReader.start, TetragonReader.stop

    def noted_start(reader: TetragonReader) -> None:
        start(reader)
        running.append(reader)

    def noted_stop(reader: TetragonReader, timeout: float = 10.0) -> None:
        if reader in running:
            running.remove(reader)
        stop(reader, timeout)

    monkeypatch.setattr(TetragonReader, "start", noted_start)
    monkeypatch.setattr(TetragonReader, "stop", noted_stop)
    before = set(threading.enumerate())
    yield
    for reader in list(running):
        reader.stop()
    left = [t for t in set(threading.enumerate()) - before if t.name == "tetragon-reader"]
    assert [t for t in left if t.is_alive()] == []


FIXTURES = Path(__file__).parent / "fixtures" / "tetragon"
AGENT_ID = "4978b4ee592382f24921acfc5822f6f33f7e95e6c89887f80dac399102aa2eff"
NEW_AGENT_ID = "cf2e46aad38cd5637c8432bb0b97390b53971cd56bf006c35f92998e26d29188"
WALL = datetime(2026, 10, 17, 9, 46, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Recorded:
    source: str
    action: str
    target: str
    details: dict[str, Any]
    risk: int


@dataclass
class Box:
    """Stands in for the Guardian's ``_record`` and for the black box the reader appends to."""

    events: list[Recorded] = field(default_factory=list)

    def record(
        self,
        source: Any,
        action: str,
        target: str = "",
        *,
        details: Any = None,
        risk: int = 0,
        snapshot_id: str | None = None,
    ) -> Recorded:
        event = Recorded(str(source), action, target, dict(details or {}), risk)
        self.events.append(event)
        return event

    append = record

    def actions(self) -> list[str]:
        return [f"{e.source}/{e.action}" for e in self.events]

    def of(self, action: str) -> list[Recorded]:
        return [e for e in self.events if e.action == action]


class FakeSensorJail:
    """The sensor's container. ``sees``: Tetragon writes what happens in the agent."""

    def __init__(self, config: SensorJailConfig, log: list[str]) -> None:
        self.config = config
        self.log = log
        self.created = False
        self.running = False
        self.sees = True
        self.serves = True
        self.create_error: JailError | None = None
        self.start_error: JailError | None = None
        self.stop_error: JailError | None = None
        self.prepare_error: Exception | None = None
        self.losses = {"kernel": 0, "ringbuf": 0, "queue": 0, "notify": 0, "export": 0}
        self.losses_error: JailError | None = None

    def prepare(self) -> None:
        self.log.append("sensor.prepare")
        if self.prepare_error is not None:
            raise self.prepare_error
        self.config.events_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def exists(self) -> bool:
        return self.created

    def is_running(self) -> bool:
        return self.running

    def create(self) -> None:
        self.log.append("sensor.create")
        if self.create_error is not None:
            raise self.create_error
        self.created = True

    def start(self) -> None:
        self.log.append("sensor.start")
        if self.start_error is not None:
            raise self.start_error
        if not self.created:
            raise JailError("no such container")
        self.running = True

    def stop(self) -> None:
        self.log.append("sensor.stop")
        if self.stop_error is not None:
            raise self.stop_error
        self.running = False

    def remove(self) -> None:
        self.log.append("sensor.remove")
        self.created = self.running = False

    def serving(self) -> bool:
        return self.running and self.serves

    def die(self) -> None:
        self.running = False

    def loss_counters(self) -> dict[str, int]:
        if self.losses_error is not None:
            raise self.losses_error
        return dict(self.losses)

    def lose(self, kind: str, count: int) -> None:
        self.losses[kind] += count

    def write_exec(
        self, arguments: str, *, docker: str = AGENT_ID, binary: str = "/bin/true"
    ) -> None:
        data = copy.deepcopy(json.loads((FIXTURES / "exec_docker_exec.json").read_text()))
        process = data["process_exec"]["process"]
        process.update(arguments=arguments, binary=binary, docker=docker[:31])
        with (self.config.events_dir / "tetragon.log").open("a") as f:
            f.write(json.dumps(data) + "\n")


class FakeAgent:
    """``container_id()`` and ``docker exec`` in the agent's container."""

    def __init__(self, sensor: FakeSensorJail, log: list[str]) -> None:
        self.sensor = sensor
        self.log = log
        self.id: str | None = AGENT_ID
        self.runs = True
        self.exec_code = 0  # what docker exec exits with while the agent runs
        self.execs: list[list[str]] = []

    def is_running(self) -> bool:
        return self.runs

    def is_paused(self) -> bool:
        return False

    def container_id(self) -> str | None:
        return self.id

    def exec(self, argv: list[str], **_: object) -> Any:
        self.execs.append(list(argv))
        if not self.runs:
            raise JailError("container is not running")
        code = self.exec_code
        if code == 0 and self.sensor.running and self.sensor.sees and self.id is not None:
            self.sensor.write_exec(argv[1], docker=self.id, binary=argv[0])

        class Done:
            returncode = code

        return Done()


@dataclass
class World:
    sensor: ProcessSensor
    jail: FakeSensorJail
    agent: FakeAgent
    reader: TetragonReader
    box: Box
    clock: Clock
    log: list[str]
    alerts: list[tuple[AlertLevel, str, str]]
    agent_running: list[bool]
    lost: list[str]
    back: list[str]
    lost_result: list[bool] = field(default_factory=lambda: [True])
    reasons: list[str] = field(default_factory=list)

    def start(self) -> bool:
        return self.sensor.start(
            SensorHooks(
                record=self.box.record,
                alert=lambda level, title, body, event=None: self.alerts.append(
                    (level, title, body)
                ),
                agent_running=lambda: self.agent_running[0],
                lost=self._lost,
                back=lambda: (self.back.append("back"), self.log.append("guardian.back")),
            )
        )

    def _lost(self, reason: str = "sensor_down") -> bool:
        self.lost.append("lost")
        self.reasons.append(reason)
        self.log.append("guardian.lost")
        return self.lost_result[0]

    def beat(self, times: int = 1) -> None:
        for _ in range(times):
            self.clock.sleep(30.0)
            self.sensor.tick()


def make_world(tmp_path: Path, *, required: bool = False, **sensor: Any) -> World:
    log: list[str] = []
    clock = Clock()
    jail_config = SensorJailConfig(state_dir=tmp_path / "sensor")
    jail = FakeSensorJail(jail_config, log)
    agent = FakeAgent(jail, log)
    box = Box()
    reader = TetragonReader(
        ReaderConfig(events_dir=jail_config.events_dir, cursor_file=jail_config.cursor_file),
        box,
        clock=clock,
        wall=lambda: WALL,
        sleep=clock.sleep,
    )
    sensor = ProcessSensor(
        jail,  # type: ignore[arg-type]
        reader,
        agent,  # type: ignore[arg-type]
        required=required,
        clock=clock,
        sleep=clock.sleep,
        **({"thread": False} | sensor),
    )
    return World(sensor, jail, agent, reader, box, clock, log, [], [True], [], [])


@pytest.fixture
def world(tmp_path: Path) -> World:
    return make_world(tmp_path)


# --- start ----------------------------------------------------------------------------------


def test_start_prepares_creates_and_waits_until_tetragon_serves(world: World) -> None:
    assert world.start() is True
    assert world.log == ["sensor.prepare", "sensor.create", "sensor.start"]
    assert world.sensor.state is SensorState.UP
    (start,) = world.box.of("sensor_start")
    assert (start.source, start.target, start.risk) == ("system", "backtide-sensor", 0)
    assert start.details["image"] == IMAGE
    assert start.details["version"] == TETRAGON_VERSION
    assert start.details["reused"] is False and start.details["restart"] is False
    assert start.details["preexisting"] == 0


def test_a_sensor_a_killed_service_left_running_is_reused(world: World) -> None:
    """Tetragon kept writing while backtide was dead: the reader catches up from its cursor."""
    world.jail.created = world.jail.running = True
    assert world.start() is True
    assert "sensor.create" not in world.log
    assert world.box.of("sensor_start")[0].details["reused"] is True


def test_a_running_sensor_that_is_not_ours_is_replaced(world: World) -> None:
    world.jail.created = world.jail.running = True
    world.jail.start_error = JailError("container backtide-sensor is not the sensor")

    def fixed_start() -> None:
        world.jail.start_error = None

    original_create = world.jail.create

    def create() -> None:
        fixed_start()
        original_create()

    world.jail.create = create  # type: ignore[method-assign]
    assert world.start() is True
    assert world.log[:4] == ["sensor.prepare", "sensor.start", "sensor.stop", "sensor.remove"]
    assert world.box.of("sensor_start")[0].details["reused"] is False


def test_a_sensor_that_cannot_start_is_recorded_and_the_service_goes_on(world: World) -> None:
    """Decision 7: without required, the agent runs anyway, with a warning."""
    world.jail.create_error = JailError("pull access denied")
    assert world.start() is False
    assert world.sensor.state is SensorState.DOWN
    (failed,) = world.box.of("sensor_failed")
    assert failed.details["stage"] == "start" and failed.risk == 2
    assert "pull access denied" in failed.details["error"]
    ((level, title, body),) = world.alerts
    assert level is AlertLevel.WARNING
    assert "sin sensor" in body.lower() or "arranca igual" in body.lower()
    assert world.sensor.allows_agent() is True


def test_a_sensor_that_never_serves_is_removed(world: World) -> None:
    world.jail.serves = False
    assert world.start() is False
    assert world.box.of("sensor_failed")[0].details["stage"] == "ready"
    assert world.log[-2:] == ["sensor.stop", "sensor.remove"]  # no privileged leftover
    assert world.jail.running is False


def test_a_required_sensor_that_cannot_start_holds_the_agent(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    world.jail.prepare_error = JailError("cannot create /var/lib/backtide/sensor")
    assert world.start() is False
    assert world.sensor.allows_agent() is False
    ((level, _, body),) = world.alerts
    assert level is AlertLevel.ERROR and "no arranca" in body


# --- the agent's container and the first probe ----------------------------------------------


def test_the_reader_follows_the_agents_container(world: World) -> None:
    world.start()
    world.sensor.follow_agent()
    world.jail.write_exec("cmd-1")
    world.agent.id = NEW_AGENT_ID  # created again
    world.sensor.follow_agent()
    world.jail.write_exec("cmd-2", docker=NEW_AGENT_ID)
    world.reader.poll()
    assert [e.details["argv"] for e in world.box.of("exec")] == ["cmd-1", "cmd-2"]


def test_the_first_probe_proves_the_whole_path_and_is_not_recorded(world: World) -> None:
    world.start()
    world.sensor.follow_agent()
    assert world.sensor.agent_started() is True
    (probe,) = world.agent.execs
    assert probe[0] == "/bin/true" and procs.is_nonce(probe[1])  # the full path: T07-2's review
    assert world.box.of("exec") == []
    assert world.reader.stats()["probes"] == 1


def test_a_sensor_blind_to_the_agent_fails_the_probe(world: World) -> None:
    world.start()
    world.sensor.follow_agent()
    world.jail.sees = False
    assert world.sensor.agent_started() is False
    failed = world.box.of("sensor_failed")[-1]
    assert failed.details["stage"] == "probe"
    assert world.sensor.state is SensorState.DOWN


def test_an_agent_that_went_away_is_not_the_sensors_fault(world: World) -> None:
    world.start()
    world.sensor.follow_agent()
    world.agent.runs = False
    assert world.sensor.agent_started() is False
    assert world.box.of("sensor_failed") == []
    assert world.sensor.state is SensorState.UP


# --- the heartbeat --------------------------------------------------------------------------


def _running(world: World) -> None:
    world.start()
    world.sensor.follow_agent()
    assert world.sensor.agent_started()
    world.agent.execs.clear()


def test_a_heartbeat_every_30_s_is_consumed(world: World) -> None:
    _running(world)
    world.beat(3)
    assert len(world.agent.execs) == 3
    assert all(
        argv[0] == "/bin/true" and argv[1].startswith("backtide-hb-") for argv in world.agent.execs
    )
    assert world.box.of("exec") == [] and world.box.of("sensor_down") == []


def test_no_heartbeat_while_the_agent_does_not_run(world: World) -> None:
    _running(world)
    world.agent_running[0] = False
    world.beat(5)
    assert world.agent.execs == [] and world.box.of("sensor_down") == []


def test_three_missed_heartbeats_are_sensor_down_and_a_restart(world: World) -> None:
    _running(world)
    world.jail.sees = False  # alive but mute: only the heartbeat can tell
    world.beat(2)
    assert world.box.of("sensor_down") == []
    world.beat(1)
    (down,) = world.box.of("sensor_down")
    assert (down.details["reason"], down.risk) == ("heartbeat", 2)
    assert any(level is AlertLevel.ERROR for level, _, _ in world.alerts)
    (restart,) = world.box.of("sensor_restart")
    assert restart.details["attempt"] == 1
    assert world.box.of("sensor_start")[-1].details["restart"] is True
    assert world.sensor.state is SensorState.UP
    assert world.lost == []  # not required: the agent goes on


def test_a_stopped_container_is_down_at_once(world: World) -> None:
    """matar-el-sensor: well under 90 s, without waiting for three heartbeats."""
    _running(world)
    world.jail.die()
    world.beat(1)
    (down,) = world.box.of("sensor_down")
    assert down.details["reason"] == "container_stopped"
    assert world.sensor.state is SensorState.UP  # restarted in the same tick


def test_at_most_three_restarts_an_hour(world: World) -> None:
    _running(world)
    world.jail.serves = False  # every restart fails
    world.jail.die()
    world.beat(6)
    assert len(world.box.of("sensor_restart")) == 3
    gave_up = [e for e in world.box.of("sensor_failed") if e.details["stage"] == "restart"]
    assert len(gave_up) == 1  # said once, not every tick
    world.clock.sleep(3600)
    world.jail.serves = True
    world.sensor.tick()
    assert len(world.box.of("sensor_restart")) == 4
    assert world.sensor.state is SensorState.UP


def test_a_required_sensor_down_stops_the_agent_and_back_starts_it(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.jail.serves = False
    world.jail.die()
    world.beat(1)
    assert world.lost == ["lost"] and world.back == []
    assert world.sensor.allows_agent() is False
    world.jail.serves = True
    world.beat(1)
    assert world.back == ["back"]
    assert world.sensor.allows_agent() is True


def test_the_reader_keeps_recording_the_agents_commands(world: World) -> None:
    _running(world)
    world.jail.write_exec("rm -rf /app/data")
    world.beat(1)
    world.reader.poll()
    (command,) = world.box.of("exec")
    assert command.details["argv"] == "rm -rf /app/data"
    assert command.details["container"] == AGENT_ID[:12]


# --- stop -----------------------------------------------------------------------------------


def test_stop_halts_the_container_saves_the_cursor_and_removes_it(world: World) -> None:
    _running(world)
    world.jail.write_exec("last-command")
    world.sensor.stop()
    assert world.log[-2:] == ["sensor.stop", "sensor.remove"]
    assert [e.details["argv"] for e in world.box.of("exec")] == ["last-command"]
    assert world.jail.config.cursor_file.exists()
    (stop,) = world.box.of("sensor_stop")
    assert stop.details["reason"] == "service_stop"
    assert world.sensor.state is SensorState.OFF


def test_stop_still_removes_a_sensor_that_does_not_stop(world: World) -> None:
    _running(world)
    world.jail.stop_error = JailError("timeout")
    world.sensor.stop()
    assert world.log[-1] == "sensor.remove"
    assert world.box.of("sensor_failed")[-1].details["stage"] == "stop"


def test_stop_without_start_does_nothing(world: World) -> None:
    world.sensor.stop()
    assert world.log == [] and world.box.events == []


def test_the_thread_runs_the_heartbeat(tmp_path: Path) -> None:
    """With ``thread=True`` the ticks come by themselves; stop ends them."""
    world = make_world(tmp_path)
    sensor = ProcessSensor(
        world.jail,  # type: ignore[arg-type]
        world.reader,
        world.agent,  # type: ignore[arg-type]
        heartbeat_interval=0.01,
        heartbeat_timeout=0.5,
    )
    world.sensor = sensor
    world.start()
    sensor.follow_agent()
    deadline = time.monotonic() + 10
    while len(world.agent.execs) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    sensor.stop()
    assert len(world.agent.execs) >= 2


# --- helpers for the service --------------------------------------------------------------


def _snapshot(seconds: float) -> Snapshot:
    return Snapshot(taken_at=WALL + timedelta(seconds=seconds), reason="periodic")


def test_snapshot_before_is_the_last_one_a_second_before_the_command() -> None:
    snaps = [_snapshot(-60), _snapshot(-10), _snapshot(-0.5), _snapshot(30)]
    before = SnapshotBefore(lambda: snaps, clock=Clock())
    assert before("2026-10-17T09:46:00.000000000Z") == snaps[1].id
    assert before("2026-10-17T09:45:00.000000000Z") is None
    assert before(None) is None
    assert before("not a time") is None


def test_snapshot_before_never_raises_and_caches(tmp_path: Path) -> None:
    calls: list[int] = []
    clock = Clock()

    def listing() -> list[Snapshot]:
        calls.append(1)
        if len(calls) > 1:
            raise OSError("the store is busy")
        return [_snapshot(-10)]

    before = SnapshotBefore(listing, clock=clock)
    first = before("2026-10-17T09:46:00Z")
    assert before("2026-10-17T09:46:00Z") == first and len(calls) == 1  # cached
    clock.sleep(10)
    assert before("2026-10-17T09:46:00Z") == first  # the old list, when the new one fails


@dataclass
class Event:
    action: str
    details: dict[str, Any]


class EventBox:
    def __init__(self, events: dict[str, list[Event]]) -> None:
        self._events = events
        self.asked: list[dict[str, Any]] = []

    def events(self, **filters: Any) -> list[Event]:
        self.asked.append(filters)
        return self._events.get(filters["source"], [])


def test_recorded_keys_are_the_sensor_events_newer_than_the_cursor() -> None:
    old = Event("exec", {"exec_id": "b2xkLWV4ZWM=", "t": "2026-10-17T09:40:00Z"})
    new = Event("exec", {"exec_id": "bmV3LWV4ZWM=", "t": "2026-10-17T09:45:59Z"})
    connect = Event("connect", {"exec_id": "bmV3LWV4ZWM=", "t": "2026-10-17T09:45:59.5Z"})
    summary = Event("summary", {"folded": 3})
    box = EventBox({"exec": [new, old, summary], "net": [connect]})
    keys = recorded_keys(box)  # type: ignore[arg-type]
    assert set(keys("2026-10-17T09:45:58Z")) == {
        "exec:bmV3LWV4ZWM=",
        "connect:bmV3LWV4ZWM=:2026-10-17T09:45:59.5Z",
    }
    assert set(keys(None)) == {
        "exec:b2xkLWV4ZWM=",
        "exec:bmV3LWV4ZWM=",
        "connect:bmV3LWV4ZWM=:2026-10-17T09:45:59.5Z",
    }
    assert all(ask["newest_first"] is True and ask["limit"] > 0 for ask in box.asked)


def test_what_tetragon_wrote_while_backtide_was_dead_is_the_agents(world: World) -> None:
    """After a kill -9 the reader catches up at once, before the Guardian starts the agent:
    it must already know the agent's container (it still exists, stopped or not)."""
    world.jail.created = world.jail.running = True
    world.jail.config.events_dir.mkdir(parents=True)
    world.jail.write_exec("while-nobody-recorded")
    world.start()
    world.reader.poll()
    assert [e.details["argv"] for e in world.box.of("exec")] == ["while-nobody-recorded"]


# --- review of T07-3 -------------------------------------------------------------------------


def test_a_required_sensor_stops_the_agent_before_it_restarts_tetragon(tmp_path: Path) -> None:
    """Finding 2: a restart leaves the agent unseen for up to 40 s, so with ``required`` the
    agent is stopped first."""
    world = make_world(tmp_path, required=True)
    _running(world)
    world.log.clear()
    world.jail.die()
    world.beat(1)
    assert world.log.index("guardian.lost") < world.log.index("sensor.create")
    assert world.sensor.state is SensorState.UP and world.back == ["back"]


def test_a_heartbeat_the_agent_keeps_from_launching_is_sensor_unproven(world: World) -> None:
    """Finding 3: an agent that fills its process limit makes `docker exec` fail. While it
    still runs, that is not "nobody's fault": three in a row are recorded and alerted."""
    _running(world)
    world.agent.exec_code = 126
    world.beat(2)
    assert world.box.of("sensor_unproven") == []
    world.beat(1)
    (unproven,) = world.box.of("sensor_unproven")
    assert unproven.risk == 2 and unproven.details["reason"] == "probe_launch"
    assert any(level is AlertLevel.ERROR for level, _, _ in world.alerts)
    world.beat(3)
    assert len(world.box.of("sensor_unproven")) == 1  # said once, until a beat goes through
    assert world.box.of("sensor_restart") == []  # Tetragon is fine: it is not restarted
    assert world.lost == []  # not required: the agent goes on
    world.agent.exec_code = 0
    world.beat(1)
    world.agent.exec_code = 126
    world.beat(3)
    assert len(world.box.of("sensor_unproven")) == 2


def test_an_unproven_required_sensor_stops_the_agent_and_tries_again(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.agent.exec_code = 126
    world.beat(3)
    assert world.lost == ["lost"]
    world.agent_running[0] = False  # the Guardian stopped it
    world.beat(1)
    assert world.back == ["back"]  # finding 5: it is asked to start it again


def test_a_required_sensor_whose_first_probe_could_not_launch_asks_again(tmp_path: Path) -> None:
    """Finding 5: the Guardian stops the agent (agent_started is False) and the sensor, still
    up, asks it to start it again on the next tick; at most 3 times an hour."""
    world = make_world(tmp_path, required=True)
    world.start()
    world.sensor.follow_agent()
    world.agent.exec_code = 126
    assert world.sensor.agent_started() is False
    world.agent_running[0] = False
    for _ in range(5):
        world.beat(1)
        world.sensor.agent_started()  # the Guardian's start, failing again
    assert world.back == ["back"] * 3


# --- review of T07: required keeps failing closed, Tetragon's own losses, the budget --------


def test_a_required_sensor_stops_the_agent_on_every_unproven_streak(tmp_path: Path) -> None:
    """Finding 4: after the first alert, a second streak of 3 must stop the agent again."""
    world = make_world(tmp_path, required=True)
    _running(world)
    world.agent.exec_code = 126
    world.beat(3)
    assert world.lost == ["lost"]
    world.beat(3)  # the agent still runs (it came back, or could not be stopped)
    assert world.lost == ["lost", "lost"]
    assert len(world.box.of("sensor_unproven")) == 1  # recorded and alerted once
    # The next start must prove the path again: no stale confirmation.
    world.agent.exec_code = 0
    world.agent.execs.clear()
    assert world.sensor.agent_started() is True
    assert world.agent.execs and world.agent.execs[0][1].startswith("backtide-ready-")


def test_a_new_agent_container_is_proven_again(world: World) -> None:
    _running(world)
    world.agent.id = NEW_AGENT_ID
    world.sensor.follow_agent()
    world.agent.execs.clear()
    assert world.sensor.agent_started() is True
    assert world.agent.execs  # probed again, not trusted from the old container


def test_a_failed_attribution_is_not_proven(world: World) -> None:
    _running(world)

    def broken() -> str:
        raise JailError("docker is gone")

    world.agent.container_id = broken  # type: ignore[method-assign]
    world.sensor.follow_agent()
    world.agent.container_id = lambda: AGENT_ID  # type: ignore[method-assign]
    world.agent.execs.clear()
    world.sensor.agent_started()
    assert world.agent.execs


def test_tetragons_own_losses_are_a_gap_and_an_alert(world: World) -> None:
    """Finding 2: a connect flood fills Tetragon's ring buffer and queues; nothing in its file
    or its logs says so, only its counters."""
    _running(world)
    world.beat(1)
    assert world.box.of("sensor_gap") == []
    world.jail.lose("kernel", 3000)
    world.jail.lose("notify", 12)
    world.beat(1)
    (gap,) = world.box.of("sensor_gap")
    assert gap.risk == 2
    assert gap.details == {
        "kind": "kernel_lost",
        "count": 3012,
        "counters": {"kernel": 3000, "notify": 12},
    }
    alerts = [title for _, title, _ in world.alerts]
    assert alerts.count("El sensor de procesos ha perdido eventos") == 1
    world.jail.lose("queue", 5)
    world.beat(1)
    assert len(world.box.of("sensor_gap")) == 2
    assert alerts.count("El sensor de procesos ha perdido eventos") == 1  # once per spell
    assert world.lost == []  # not required: the agent goes on


def test_with_required_tetragons_losses_stop_the_agent_and_ask_it_back(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.jail.lose("kernel", 10)
    world.beat(1)
    assert world.lost == ["lost"]
    world.agent_running[0] = False
    world.beat(1)
    assert world.back == ["back"]


def test_unreadable_loss_counters_are_a_failure_and_unproven_when_required(
    tmp_path: Path,
) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.jail.losses_error = JailError("wget: connection refused")
    world.beat(2)
    failed = [e for e in world.box.of("sensor_failed") if e.details["stage"] == "losses"]
    assert len(failed) == 1
    assert world.lost == ["lost", "lost"]


def test_losses_of_a_reused_tetragon_are_a_gap(world: World) -> None:
    world.jail.created = world.jail.running = True
    world.jail.config.events_dir.mkdir(parents=True)
    world.jail.lose("queue", 7)
    world.start()
    (gap,) = world.box.of("sensor_gap")
    assert gap.details["count"] == 7 and gap.details["while_down"] is True


def test_a_spent_budget_alerts_and_with_required_holds_the_agent(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    spent = ["exec"]
    world.reader.exhausted_budgets = lambda: list(spent)  # type: ignore[method-assign]
    world.beat(1)
    assert world.lost == ["lost"]
    assert world.sensor.allows_agent() is False
    world.agent_running[0] = False
    world.beat(3)
    assert world.back == []  # never while the budget is spent
    spent.clear()
    assert world.sensor.allows_agent() is True
    world.beat(1)
    assert world.back == ["back"]
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos ha agotado su cupo diario") == 1


def test_a_spent_budget_without_required_only_alerts(world: World) -> None:
    _running(world)
    world.reader.exhausted_budgets = lambda: ["net"]  # type: ignore[method-assign]
    world.beat(2)
    assert world.lost == [] and world.sensor.allows_agent() is True
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos ha agotado su cupo diario") == 1


def test_tetragon_is_not_restarted_while_a_required_agent_still_runs(tmp_path: Path) -> None:
    """Finding 13: `lost` says whether it stopped the agent; until it did, no restart."""
    world = make_world(tmp_path, required=True)
    _running(world)
    world.lost_result[0] = False
    world.log.clear()
    world.jail.die()
    world.beat(2)
    assert world.box.of("sensor_down") and world.box.of("sensor_restart") == []
    assert "sensor.create" not in world.log
    world.lost_result[0] = True
    world.beat(1)
    assert len(world.box.of("sensor_restart")) == 1
    assert world.sensor.state is SensorState.UP


# --- T07 re-review: blind spots of the reader, the reason to stop, no baseline -----------


def test_a_throttle_or_lost_novelty_alerts_and_with_required_stops_the_agent(
    tmp_path: Path,
) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.reader.take_blind_spots = lambda: {"throttle": 1}  # type: ignore[method-assign]
    world.beat(1)
    assert world.lost == ["lost"] and world.reasons == ["sensor_lost_events"]
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos ha dejado de ver comandos") == 1


def test_blind_spots_without_required_only_alert(world: World) -> None:
    _running(world)
    world.reader.take_blind_spots = lambda: {"novelty_lost": 2}  # type: ignore[method-assign]
    world.beat(2)
    assert world.lost == []
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos ha dejado de ver comandos") == 1


def test_the_unproven_streak_records_its_misses(world: World) -> None:
    _running(world)
    world.agent.exec_code = 126
    world.beat(3)
    (unproven,) = world.box.of("sensor_unproven")
    assert unproven.details["misses"] == 3


def test_without_a_baseline_every_loss_counts() -> None:
    from backtide.service.process_sensor import KernelLoss  # noqa: PLC0415

    losses = KernelLoss(lambda: {"kernel": 5, "queue": 0})
    assert losses.check() == {"kernel": 5}
    assert losses.check() == {}


def test_a_failure_to_read_the_losses_is_said_again_every_hour(world: World) -> None:
    _running(world)
    world.jail.losses_error = JailError("wget: bad address")
    world.beat(3)
    stage = [e for e in world.box.of("sensor_failed") if e.details["stage"] == "losses"]
    assert len(stage) == 1
    world.clock.sleep(3600)
    world.beat(1)
    stage = [e for e in world.box.of("sensor_failed") if e.details["stage"] == "losses"]
    assert len(stage) == 2


# --- T07 third pass: a stuck reader poll is a blind spot ------------------------------------


def test_a_stalled_reader_is_blind_and_with_required_stops_the_agent(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.reader.polling_since = world.clock() - 120  # a poll has been running for 2 minutes
    world.beat(1)
    (gap,) = [e for e in world.box.of("sensor_gap") if e.details["kind"] == "reader_stalled"]
    assert gap.risk == 2 and world.lost == ["lost"] and world.reasons == ["sensor_lost_events"]
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos va muy por detrás") == 1
    # No probe is launched while the reader is stuck.
    assert world.agent.execs == []


def test_a_stalled_reader_without_required_only_alerts(world: World) -> None:
    _running(world)
    world.reader.polling_since = world.clock() - 120
    world.beat(2)
    assert world.lost == []
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos va muy por detrás") == 1


# --- T07-5: the stall watchdog, unseen command lines, a lost rotated file ------------------


class BlockingRecorder:
    """The reader's black box, whose append waits on an Event: a poll stuck for real."""

    def __init__(self, box: Box) -> None:
        self.box = box
        self.entered = threading.Event()
        self.release = threading.Event()

    def append(self, *args: Any, **kwargs: Any) -> object:
        self.entered.set()
        assert self.release.wait(20)
        return self.box.append(*args, **kwargs)


def _stick(world: World) -> tuple[BlockingRecorder, threading.Thread]:
    """Make the next poll hang in append, holding the reader's lock."""
    blocking = BlockingRecorder(world.box)
    world.reader._recorder = blocking
    world.jail.write_exec("stuck-command")
    poller = threading.Thread(target=world.reader.poll, daemon=True)
    poller.start()
    assert blocking.entered.wait(5)
    return blocking, poller


def test_a_heartbeat_never_hangs_behind_a_stuck_poll(tmp_path: Path) -> None:
    """T07-5: the heartbeat used to block in set_agent() on the reader's lock, before it
    looked at blocked() again, so the stall could never be said."""
    world = make_world(tmp_path, required=True, heartbeat_timeout=0.2)
    _running(world)
    blocking, poller = _stick(world)
    try:
        beat = threading.Thread(target=world.beat, daemon=True)
        beat.start()
        beat.join(5)
        assert not beat.is_alive(), "the heartbeat hung behind the reader's lock"
        assert world.sensor.state is SensorState.UP  # a busy reader is not a dead sensor
        world.clock.sleep(61)  # the poll is now older than reader_stall
        world.sensor.watch()
        (gap,) = [e for e in world.box.of("sensor_gap") if e.details["kind"] == "reader_stalled"]
        assert gap.risk == 2 and world.reasons == ["sensor_lost_events"]
        world.sensor.watch()  # once per stall
        assert (
            len([e for e in world.box.of("sensor_gap") if e.details["kind"] == "reader_stalled"])
            == 1
        )
        assert world.reasons == ["sensor_lost_events"]
    finally:
        blocking.release.set()
        poller.join(5)


def test_the_watchdog_thread_says_a_stall_with_no_heartbeat(tmp_path: Path) -> None:
    """The watchdog has its own thread and takes neither the reader's lock nor the sensor's."""
    world = make_world(tmp_path, required=True, thread=True, watch_interval=0.05)
    _running(world)
    blocking, poller = _stick(world)
    try:
        world.clock.sleep(61)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and world.reasons != ["sensor_lost_events"]:
            time.sleep(0.05)
        assert world.reasons == ["sensor_lost_events"]
        assert [e for e in world.box.of("sensor_gap") if e.details["kind"] == "reader_stalled"]
    finally:
        blocking.release.set()
        poller.join(5)
        world.sensor.stop()


def test_follow_agent_and_allows_agent_do_not_hang_behind_a_stuck_poll(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True, heartbeat_timeout=0.2)
    _running(world)
    blocking, poller = _stick(world)
    try:
        calls = threading.Thread(
            target=lambda: (world.sensor.follow_agent(), world.sensor.allows_agent()), daemon=True
        )
        calls.start()
        calls.join(5)
        assert not calls.is_alive()
        assert world.sensor.allows_agent() is False  # required, and the reader cannot answer
    finally:
        blocking.release.set()
        poller.join(5)
    assert world.sensor.allows_agent() is True


def test_unseen_command_lines_alert_per_streak_and_never_stop(tmp_path: Path) -> None:
    """T07-5: a parallel build (distinct commands of a binary that has events of its own) is
    risk 2 and an alert naming the programs, never a stop, also under required. A streak is
    alerted when it starts and again every 10 minutes while it lasts."""
    world = make_world(tmp_path, required=True)
    _running(world)
    decoy = "/workspace/compilacion-normal-ignorar"
    unseen = [{"/usr/bin/cc": 1}, {"/usr/bin/cc": 1}, {}, {"/bin/sh": 1, decoy: 1}]
    world.reader.take_unseen = lambda: unseen.pop(0) if unseen else {"/bin/sh": 1}  # type: ignore[method-assign]
    world.beat(4)
    assert world.lost == []
    bodies = [
        b
        for _, t, b in world.alerts
        if t == "El sensor de procesos ha resumido comandos sin verlos"
    ]
    assert len(bodies) == 2 and "/usr/bin/cc" in bodies[0] and "/bin/sh" in bodies[1]
    # The agent's own binary is only counted: its chosen name never reaches the alert.
    assert decoy not in bodies[1] and "1 programa(s) del propio agente" in bodies[1]
    world.beat(19)  # 9.5 more minutes of the same streak: no new alert yet
    world.beat(1)  # 10 minutes after the last one: said again, with how long it lasts
    bodies = [
        b
        for _, t, b in world.alerts
        if t == "El sensor de procesos ha resumido comandos sin verlos"
    ]
    assert len(bodies) == 3 and "Dura ya" in bodies[2]
    assert world.lost == [] and world.sensor.allows_agent() is True


def test_a_rotated_file_lost_is_blind_and_with_required_stops_the_agent(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.reader.take_blind_spots = lambda: {"rotated": 1}  # type: ignore[method-assign]
    world.beat(1)
    assert world.reasons == ["sensor_lost_events"]
    (body,) = [
        b for _, t, b in world.alerts if t == "El sensor de procesos ha dejado de ver comandos"
    ]
    assert "archivo" in body


def test_an_agent_the_watchdog_stopped_is_asked_back_once_the_reader_reads(tmp_path: Path) -> None:
    """T07-5 review: the debt is marked after `lost` stopped the agent, so a beat that still
    saw it running cannot clear it."""
    world = make_world(tmp_path, required=True, heartbeat_timeout=0.2)
    _running(world)
    blocking, poller = _stick(world)
    try:
        world.clock.sleep(61)
        world.sensor.watch()
        assert world.reasons == ["sensor_lost_events"]
    finally:
        blocking.release.set()
        poller.join(5)
    world.agent_running[0] = False  # the Guardian stopped it
    world.beat(1)
    assert world.back == ["back"]


def test_a_required_agent_refused_for_a_busy_reader_is_asked_back(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True, heartbeat_timeout=0.2)
    _running(world)
    blocking, poller = _stick(world)
    try:
        assert world.sensor.allows_agent() is False
    finally:
        blocking.release.set()
        poller.join(5)
    world.agent_running[0] = False
    world.beat(1)
    assert world.back == ["back"]


def test_losses_read_on_a_skipped_heartbeat_are_carried_to_the_next(tmp_path: Path) -> None:
    """T07-5 second review, A: the counters' baseline moves before the reader's lock is
    taken; a beat skipped for a busy reader must not drop what it read."""
    world = make_world(tmp_path, heartbeat_timeout=0.2)
    _running(world)
    world.jail.lose("queue", 7)
    held = world.reader.held
    tries: list[int] = []

    class Busy:
        def __enter__(self) -> bool:
            return False

        def __exit__(self, *_: object) -> None:
            return None

    def busy_once(timeout: float | None) -> Any:
        tries.append(1)
        return Busy() if len(tries) == 2 else held(timeout)  # 1: follow_agent; 2: the beat

    world.reader.held = busy_once  # type: ignore[method-assign]
    world.beat(1)  # skipped: the reader is busy, but the counters were read
    assert not [e for e in world.box.of("sensor_gap") if e.details["kind"] == "kernel_lost"]
    world.beat(1)
    (gap,) = [e for e in world.box.of("sensor_gap") if e.details["kind"] == "kernel_lost"]
    assert gap.details["count"] == 7 and gap.risk == 2


def test_heartbeats_skipped_in_a_row_are_a_busy_reader(tmp_path: Path) -> None:
    """A poll slow enough to make every beat give up (10 to 59 s) is never reader_stalled:
    three skipped beats in a row are sensor_gap reader_busy, risk 2, and with required the
    agent stops."""
    world = make_world(tmp_path, required=True, heartbeat_timeout=0.2)
    _running(world)

    class Busy:
        def __enter__(self) -> bool:
            return False

        def __exit__(self, *_: object) -> None:
            return None

    world.reader.held = lambda timeout: Busy()  # type: ignore[method-assign]
    world.beat(2)
    assert not [e for e in world.box.of("sensor_gap") if e.details["kind"] == "reader_busy"]
    world.beat(1)
    (gap,) = [e for e in world.box.of("sensor_gap") if e.details["kind"] == "reader_busy"]
    assert gap.risk == 2 and gap.details["skipped"] == 3
    assert world.reasons == ["sensor_lost_events"]
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos no da abasto") == 1


# --- The founder's decision B (2026-10-19): a long streak of unseen command lines -----------


def test_an_unseen_streak_shorter_than_the_limit_does_not_stop(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    world.reader.unseen_streak = lambda: 9 * 60.0  # type: ignore[method-assign]
    world.beat(2)
    assert world.lost == []
    assert not [e for e in world.box.of("sensor_gap") if e.details["kind"] == "novelty_streak"]


def test_an_unseen_streak_of_ten_minutes_stops_a_required_agent(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True)
    _running(world)
    streak = [600.0]
    world.reader.unseen_streak = lambda: streak[0]  # type: ignore[method-assign]
    world.beat(2)
    (gap,) = [e for e in world.box.of("sensor_gap") if e.details["kind"] == "novelty_streak"]
    assert gap.risk == 2 and gap.details["seconds"] >= 600
    assert world.reasons[0] == "sensor_novelty_streak"
    titles = [title for _, title, _ in world.alerts]
    assert titles.count("El sensor de procesos lleva demasiado tiempo sin ver comandos") == 1
    # A window without unseen command lines resets it; a new streak is said again.
    streak[0] = 0.0
    world.beat(1)
    streak[0] = 600.0
    world.beat(1)
    gaps = [e for e in world.box.of("sensor_gap") if e.details["kind"] == "novelty_streak"]
    assert len(gaps) == 2


def test_an_unseen_streak_without_required_never_stops(tmp_path: Path) -> None:
    world = make_world(tmp_path)
    _running(world)
    world.reader.unseen_streak = lambda: 3600.0  # type: ignore[method-assign]
    world.beat(2)
    assert world.lost == []
    assert not [e for e in world.box.of("sensor_gap") if e.details["kind"] == "novelty_streak"]


def test_the_streak_limit_is_a_setting(tmp_path: Path) -> None:
    world = make_world(tmp_path, required=True, novelty_streak=120.0)
    _running(world)
    world.reader.unseen_streak = lambda: 120.0  # type: ignore[method-assign]
    world.beat(1)
    assert world.reasons == ["sensor_novelty_streak"]
