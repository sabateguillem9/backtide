"""The process sensor in the service (T07-3): Tetragon's container, its reader and its heartbeat.

Design: docs/23-diseno-t07-tetragon.md, section 7. The Guardian owns one ``ProcessSensor`` and
calls it at a few points of its life; everything else happens here, on the sensor's own thread.

- **Start** (``start``), after the black box opens and before the proxy and the agent: write
  its settings, create the container (or reuse the one a killed service left running, so what
  Tetragon wrote meanwhile is read), start it and wait until it serves (``tetra status`` and the
  policy, T07-1 P13), then ``system/sensor_start``. The reader starts reading at once.
- **The whole path** is only proven by a probe: ``/bin/true backtide-ready-<nonce>`` (the full
  path: T07-2's review) by ``docker exec`` in the agent's container, seen by the reader and
  attributed to that container. ``agent_started`` does it once after every (re)start of the
  sensor, and the heartbeat every 30 s while the agent runs. Probes are never recorded.
- **Down**: the container stopped, or three heartbeats in a row unseen, is
  ``system/sensor_down`` (risk 2) and an alert; then a restart, at most 3 an hour, each one
  recorded (``system/sensor_restart``). Failures are ``system/sensor_failed {stage, error}``.
  With ``required`` the agent is stopped (``lost``) BEFORE Tetragon is restarted: a restart
  leaves the agent unseen for up to 40 s.
- **Unproven**: three heartbeats in a row that ``docker exec`` could not even launch while the
  agent runs (an agent that fills its process limit can do that) are ``system/sensor_unproven``
  (risk 2) and an alert, once until a heartbeat goes through. Tetragon is not restarted (it is
  fine); with ``required`` the agent is stopped, and asked back on the next tick.
- **Required** (``[sensor] required``, decision 7): without it the agent runs anyway, with a
  warning. With it, ``allows_agent()`` is False while the sensor is not up, and the hooks tell
  the Guardian to stop the agent (``lost``) and to start it again once the sensor is back
  (``back``). The hooks run without this module's lock held: the Guardian takes ``agent_lock``
  in them, and calls this module while holding it.
- **Stop** (``stop``), after the agent: SIGTERM to Tetragon (it writes what it holds and unloads
  its programs), the reader reads to the end and saves its cursor, the container is removed
  (``system/sensor_stop``). A privileged container is never left behind by a stop.
- Nothing raises out of here into the Guardian: the sensor is observation, not a barrier.
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any, Protocol

from backtide.blackbox import Event
from backtide.jail import docker
from backtide.jail.docker import JailError
from backtide.jail.sensor import IMAGE, TETRAGON_VERSION, SensorJailConfig
from backtide.notify import AlertLevel
from backtide.sensors import procs
from backtide.sensors.tetragon import SensorNotReady, TetragonReader, wait_ready
from backtide.snapshots import Snapshot

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = 30.0  # docs/23, decision 10
HEARTBEAT_TIMEOUT = 10.0
MISSES_FOR_DOWN = 3
RESTARTS_PER_HOUR = 3
RESTART_WINDOW = 3600.0
BACKS_PER_HOUR = 3  # a required sensor, up, asking the Guardian to start the agent again
SERVING_POLL = 0.5
PROBE_BINARY = "/bin/true"  # the full path: procs only takes /bin/true or /usr/bin/true
PROBE_TIMEOUT = 15.0  # seconds one `docker exec` of a probe may take
PROBE_OUTPUT = 4096
STOP_JOIN = 120.0  # a heartbeat thread blocked in `lost` waits for the agent's stop
RECORDED_LOOKUP = 5000  # sensor events per source read back to spot a line read twice
REPLAY_MARGIN = timedelta(seconds=2)
SNAPSHOT_SLACK = timedelta(seconds=1)  # docs/23, section 4: "con una holgura de 1 s"
SNAPSHOT_CACHE = 5.0
_ERROR_CHARS = 300


class SensorState(StrEnum):
    OFF = "off"  # not started, or stopped
    UP = "up"  # serving; the reader reads
    DOWN = "down"  # failed or fallen: the heartbeat thread tries to restart it


class SensorContainer(Protocol):
    """What this module needs from ``backtide.jail.sensor.SensorJail``."""

    config: SensorJailConfig

    def prepare(self) -> None: ...
    def exists(self) -> bool: ...
    def is_running(self) -> bool: ...
    def create(self) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def remove(self) -> None: ...
    def serving(self) -> bool: ...


class AgentContainer(Protocol):
    """What this module needs from ``backtide.jail.AgentJail``."""

    def container_id(self) -> str | None: ...
    def is_running(self) -> bool: ...
    def is_paused(self) -> bool: ...
    def exec(self, argv: Sequence[str], *, check: bool = ..., timeout: float = ...,
             max_output: int = ...) -> Any: ...  # fmt: skip


@dataclass(frozen=True)
class SensorHooks:
    """The Guardian's side. ``record`` and ``alert`` are its own (``_record``, ``_alert``), so
    a sensor event goes through the same door as every other. ``agent_running`` says whether
    the agent runs code now (no heartbeat otherwise). ``lost`` and ``back`` only matter with
    ``required``."""

    record: Callable[..., Event | object | None]
    alert: Callable[..., None]
    agent_running: Callable[[], bool]
    lost: Callable[[], None] = lambda: None
    back: Callable[[], None] = lambda: None


class _NotServing(Exception):
    """The container started but Tetragon did not serve in time."""


class _AgentGone(Exception):
    """A probe could not even be launched: the agent does not run (not the sensor's fault)."""


class ProcessSensor:
    """The sensor's container, its reader and its heartbeat, for the Guardian.

    ``thread=False`` (tests) leaves the heartbeat to whoever calls ``tick()``."""

    def __init__(
        self,
        jail: SensorContainer,
        reader: TetragonReader,
        agent: AgentContainer,
        *,
        required: bool = False,
        heartbeat_interval: float = HEARTBEAT_INTERVAL,
        heartbeat_timeout: float = HEARTBEAT_TIMEOUT,
        misses_for_down: int = MISSES_FOR_DOWN,
        restarts_per_hour: int = RESTARTS_PER_HOUR,
        ready_timeout: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        thread: bool = True,
    ) -> None:
        self._jail = jail
        self._reader = reader
        self._agent = agent
        self._required = required
        self._interval = heartbeat_interval
        self._timeout = heartbeat_timeout
        self._misses_for_down = misses_for_down
        self._max_restarts = restarts_per_hour
        self._ready_timeout = (
            ready_timeout if ready_timeout is not None else jail.config.ready_timeout
        )
        self._clock = clock
        self._sleep = sleep
        self._use_thread = thread
        self._lock = threading.RLock()
        self._closing = threading.Event()
        self._thread: threading.Thread | None = None
        self._hooks: SensorHooks | None = None
        self._state = SensorState.OFF
        self._reading = False
        self._confirmed = False  # a probe went through since the last (re)start
        self._misses = 0
        self._restarts: deque[float] = deque()
        self._gave_up = False
        self._unlaunched = 0  # heartbeats in a row docker exec could not launch, agent running
        self._unproven_said = False
        self._owes_back = False  # required and up: the Guardian stopped the agent for us
        self._backs: deque[float] = deque()

    @property
    def required(self) -> bool:
        return self._required

    @property
    def state(self) -> SensorState:
        return self._state

    @property
    def name(self) -> str:
        return self._jail.config.name

    def allows_agent(self) -> bool:
        """Whether the agent may run now: always, unless the sensor is required and not up."""
        return not self._required or self._state is SensorState.UP

    # The Guardian's calls

    def start(self, hooks: SensorHooks) -> bool:
        """Bring the sensor up and start watching it. True if it serves. Never raises."""
        with self._lock:
            self._hooks = hooks
            self._closing.clear()
            self._state = SensorState.DOWN
            self._restarts.clear()
            self._gave_up = False
            up = self._bring_up(restart=False)
        if self._use_thread and self._thread is None:
            self._thread = threading.Thread(target=self._run, name="backtide-sensor", daemon=True)
            self._thread.start()
        return up

    def follow_agent(self) -> None:
        """Attribute events to the agent's container as it is now (called right before the
        agent starts: the container may have been created again). Never raises."""
        try:
            agent_id = self._agent.container_id()
            if agent_id is not None:
                self._reader.set_agent(agent_id)
        except (JailError, ValueError) as error:
            self._failed("attribution", error, alert=False)

    def agent_started(self) -> bool:
        """The agent just got ready: prove the whole path once per (re)start of the sensor.
        True if the sensor is up and sees the agent; False if not (``sensor_failed {stage:
        probe}`` when the sensor, not the agent, is at fault). Never raises."""
        with self._lock:
            if self._state is not SensorState.UP:
                return False
            if self._confirmed:
                return True
            seen = self._probe_ready()
            if seen is None:
                # The agent went away (nobody's fault here) or would not run the probe. With
                # required the Guardian stops it: ask for it again on the next tick.
                self._owes_back = self._required
                return False
            if seen:
                self._confirmed, self._misses = True, 0
                return True
            self._failed(
                "probe",
                SensorNotReady(
                    f"the sensor saw no probe from the agent in {self._ready_timeout} s"
                ),
            )
            self._state = SensorState.DOWN
            return False

    def stop(self, reason: str = "service_stop") -> None:
        """Stop for good (after the agent). Never raises; a container that does not stop is
        removed anyway."""
        self._closing.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(STOP_JOIN)
            if thread.is_alive():
                logger.error("the sensor's heartbeat did not stop within %s s", STOP_JOIN)
        with self._lock:
            if self._state is SensorState.OFF:
                return
            try:
                if self._jail.is_running():
                    self._jail.stop()  # SIGTERM: Tetragon writes what it holds, unloads programs
            except JailError as error:
                self._failed("stop", error, alert=False)
            if self._reading:
                self._reading = False
                self._reader.stop()  # reads to the end, the last summary and the cursor
            try:
                self._jail.remove()
            except JailError as error:
                self._failed("remove", error)
            self._state = SensorState.OFF
            self._record("system", "sensor_stop", self.name, details={"reason": reason})

    # The heartbeat

    def tick(self) -> None:
        """One heartbeat: check an up sensor, or try to restart a fallen one. The thread calls
        it every ``heartbeat_interval`` seconds. Never raises."""
        after: list[Callable[[], None]] = []
        with self._lock:
            if self._closing.is_set() or self._hooks is None:
                return
            if self._state is SensorState.UP:
                self._check(after)
        # Without our lock (the Guardian takes agent_lock in these), and before any restart:
        # with required, `lost` stops the agent before Tetragon goes away for a restart.
        self._answer(after)
        with self._lock:
            if self._closing.is_set():
                return
            if self._state is SensorState.DOWN:
                self._retry(after)
        self._answer(after)

    @staticmethod
    def _answer(calls: list[Callable[[], None]]) -> None:
        while calls:
            call = calls.pop(0)
            try:
                call()
            except Exception:
                logger.exception("the Guardian's answer to the sensor failed")

    def _run(self) -> None:
        while not self._closing.wait(self._interval):
            try:
                self.tick()
            except Exception as error:  # never let the heartbeat die silently
                logger.exception("the sensor's heartbeat failed")
                try:
                    self._failed("watch", error)
                except Exception:
                    logger.exception("cannot record that the sensor's heartbeat failed")

    def _check(self, after: list[Callable[[], None]]) -> None:
        try:
            running = self._jail.is_running()
        except JailError as error:
            logger.info("cannot tell whether the sensor runs: %s", error)
            running = None
        if running is False:
            self._down("container_stopped", after)
            return
        hooks = self._hooks
        if hooks is None or not hooks.agent_running():
            if self._owes_back:
                self._ask_back(after)
            return  # a frozen or stopped agent runs nothing to see
        self._owes_back = False
        if running is True:
            self.follow_agent()
            nonce = procs.new_nonce("hb")
            self._reader.expect(nonce)
            try:
                self._launch(nonce)
            except _AgentGone as gone:
                self._not_launched(gone, after)
                return
            self._unlaunched, self._unproven_said = 0, False
            if self._reader.wait_seen(nonce, self._timeout):
                self._misses, self._confirmed = 0, True
                return
        self._misses += 1
        logger.info("the sensor missed heartbeat %d of %d", self._misses, self._misses_for_down)
        if self._misses >= self._misses_for_down:
            self._down("heartbeat", after)

    def _not_launched(self, gone: _AgentGone, after: list[Callable[[], None]]) -> None:
        """A heartbeat docker exec did not launch. Nobody's fault if the agent is not running
        (or frozen) any more; if it runs, the agent may be keeping the probe out."""
        try:
            running = self._agent.is_running() and not self._agent.is_paused()
        except JailError:
            running = True  # cannot tell: count it
        if not running:
            return
        self._unlaunched += 1
        if self._unlaunched < self._misses_for_down or self._unproven_said:
            return
        self._unproven_said = True
        event = self._record(
            "system",
            "sensor_unproven",
            self.name,
            details={
                "reason": "probe_launch",
                "misses": self._unlaunched,
                "error": docker.sanitize(str(gone), _ERROR_CHARS),
            },
            risk=2,
        )
        tail = (
            " Es obligatorio en esta configuración, así que el agente se para."
            if self._required
            else " El agente sigue."
        )
        self._alert(
            AlertLevel.ERROR,
            "No se puede comprobar el sensor de procesos",
            "El agente está en marcha pero no deja lanzar la prueba del sensor (puede haber "
            "llenado su límite de procesos o de memoria): no se sabe si sus comandos se graban."
            + tail,
            event,
        )
        if self._required and self._hooks is not None:
            self._owes_back = True
            after.append(self._hooks.lost)

    def _ask_back(self, after: list[Callable[[], None]]) -> None:
        """Required and up, and the Guardian stopped the agent for us: ask it to start the
        agent again, at most ``BACKS_PER_HOUR`` times an hour."""
        now = self._clock()
        while self._backs and now - self._backs[0] >= RESTART_WINDOW:
            self._backs.popleft()
        if len(self._backs) >= BACKS_PER_HOUR or self._hooks is None:
            return
        self._backs.append(now)
        self._owes_back = False
        after.append(self._hooks.back)

    def _down(self, reason: str, after: list[Callable[[], None]]) -> None:
        misses, self._misses = self._misses, 0
        self._state = SensorState.DOWN
        self._confirmed = False
        event = self._record(
            "system", "sensor_down", self.name, details={"reason": reason, "misses": misses}, risk=2
        )
        if self._required:
            body = (
                "El sensor de procesos ha dejado de ver al agente. Es obligatorio en esta "
                "configuración, así que el agente se para hasta que vuelva. Se reintenta."
            )
        else:
            body = (
                "El sensor de procesos ha dejado de ver al agente: sus comandos y conexiones no "
                "se graban hasta que vuelva. El agente sigue. Se reintenta."
            )
        self._alert(AlertLevel.ERROR, "El sensor de procesos no responde", body, event)
        if self._required and self._hooks is not None:
            after.append(self._hooks.lost)

    def _retry(self, after: list[Callable[[], None]]) -> None:
        now = self._clock()
        while self._restarts and now - self._restarts[0] >= RESTART_WINDOW:
            self._restarts.popleft()
        if len(self._restarts) >= self._max_restarts:
            if not self._gave_up:
                self._gave_up = True
                self._failed(
                    "restart",
                    RuntimeError(f"{self._max_restarts} restarts in the last hour: waiting"),
                )
            return
        self._gave_up = False
        self._restarts.append(now)
        self._record(
            "system", "sensor_restart", self.name, details={"attempt": len(self._restarts)}, risk=1
        )
        try:
            self._halt_container()
        except JailError as error:
            self._failed("restart", error)
            return
        if self._bring_up(restart=True) and self._required and self._hooks is not None:
            after.append(self._hooks.back)

    # Bringing it up

    def _bring_up(self, *, restart: bool) -> bool:
        stage = "prepare"
        started = self._clock()
        try:
            self._jail.prepare()
            if not self._reading:
                # Before the first read: what Tetragon wrote while backtide was down (a kill -9
                # leaves the agent's container, with its id) is the agent's.
                self.follow_agent()
                self._reader.start()
                self._reading = True
            stage = "start"
            reused = self._start_container()
            stage = "ready"
            self._wait_serving()
        except Exception as error:  # recorded and alerted: the agent may run without it
            self._failed(stage, error, starting=True)
            self._state = SensorState.DOWN
            if stage == "ready":
                self._halt_quietly()  # never leave a privileged container that does not serve
            return False
        self._state = SensorState.UP
        self._misses, self._confirmed = 0, False
        self._reader.poll()
        self._record(
            "system",
            "sensor_start",
            self.name,
            details={
                "image": IMAGE,
                "version": TETRAGON_VERSION,
                "preexisting": self._reader.preexisting,
                "reused": reused,
                "restart": restart,
                "seconds": round(self._clock() - started, 2),
            },
        )
        return True

    def _start_container(self) -> bool:
        """Start the sensor; True if it reused one already running (a killed service's)."""
        if self._jail.is_running():
            try:
                self._jail.start()  # checks it is exactly our sensor; a no-op otherwise
                return True
            except JailError as error:
                logger.info("replacing the running sensor, which is not this one: %s", error)
                self._halt_container()
        elif self._jail.exists():
            self._jail.remove()  # a stopped leftover: made again from this code
        self._jail.create()
        self._jail.start()
        return False

    def _wait_serving(self) -> None:
        deadline = self._clock() + self._ready_timeout
        while not self._jail.serving():
            if not self._jail.is_running():
                raise _NotServing("the sensor's container stopped while starting")
            if self._clock() >= deadline:
                raise _NotServing(f"Tetragon did not serve in {self._ready_timeout} s")
            self._sleep(SERVING_POLL)

    def _halt_container(self) -> None:
        """SIGTERM, then remove. Raises JailError only if it cannot be removed."""
        try:
            if self._jail.is_running():
                self._jail.stop()
        except JailError as error:
            logger.info("the sensor did not stop, removing it: %s", error)
        self._jail.remove()

    def _halt_quietly(self) -> None:
        try:
            self._halt_container()
        except JailError as error:
            self._failed("remove", error)

    # Probes

    def _launch(self, nonce: str) -> None:
        """``docker exec <agent> /bin/true <nonce>``. Raises _AgentGone if it did not run."""
        try:
            result = self._agent.exec(
                [PROBE_BINARY, nonce], check=False, timeout=PROBE_TIMEOUT, max_output=PROBE_OUTPUT
            )
        except JailError as error:
            raise _AgentGone(str(error)) from error
        if result.returncode != 0:
            raise _AgentGone(f"docker exec exited with {result.returncode}")

    def _probe_ready(self) -> bool | None:
        """Probes until one is seen (True), ``ready_timeout`` passes (False) or the agent is
        gone (None)."""
        try:
            wait_ready(self._reader, self._launch, timeout=self._ready_timeout)
        except _AgentGone:
            return None
        except SensorNotReady:
            return False
        return True

    # Records and alerts

    def _record(self, *args: Any, **kwargs: Any) -> Event | object | None:
        if self._hooks is None:
            return None
        return self._hooks.record(*args, **kwargs)

    def _alert(self, level: AlertLevel, title: str, body: str, event: object = None) -> None:
        if self._hooks is not None:
            self._hooks.alert(level, title, body, event)

    def _failed(
        self, stage: str, error: BaseException, *, alert: bool = True, starting: bool = False
    ) -> None:
        """``system/sensor_failed {stage, error}`` (risk 2) and, unless told, an alert. The
        error is cut and sanitized; Docker's own text never goes into the alert."""
        text = docker.sanitize(f"{type(error).__name__}: {error}", _ERROR_CHARS)
        logger.info("the process sensor failed at %s: %s", stage, text)
        event = self._record(
            "system", "sensor_failed", self.name, details={"stage": stage, "error": text}, risk=2
        )
        if not alert:
            return
        if starting and not self._required:
            level, body = (
                AlertLevel.WARNING,
                "El sensor de procesos no ha arrancado: el agente arranca igual, pero sin sensor "
                "sus comandos y conexiones no se graban. Se reintenta. Detalles en el evento.",
            )
        elif starting:
            level, body = (
                AlertLevel.ERROR,
                "El sensor de procesos no ha arrancado y es obligatorio: el agente no arranca "
                "hasta que funcione. Se reintenta. Detalles en el evento.",
            )
        else:
            level, body = (
                AlertLevel.ERROR,
                f"El sensor de procesos ha fallado ({stage}). Detalles en el evento.",
            )
        self._alert(level, "Fallo del sensor de procesos", body, event)


class SnapshotBefore:
    """``snapshot_for`` of the reader: the newest snapshot taken at least 1 s before an event's
    kernel time (docs/23, section 4), never a later one. The list is read at most every
    ``SNAPSHOT_CACHE`` seconds and a failure keeps the last one: never raises."""

    def __init__(
        self,
        snapshots: Callable[[], Iterable[Snapshot]],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._list = snapshots
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: list[Snapshot] = []
        self._read_at: float | None = None

    def __call__(self, kernel_time: str | None) -> str | None:
        moment = procs.parse_time(kernel_time)
        if moment is None:
            return None
        limit = moment - SNAPSHOT_SLACK
        older = [snap for snap in self._snapshots() if snap.taken_at <= limit]
        return max(older, key=lambda snap: snap.taken_at).id if older else None

    def _snapshots(self) -> list[Snapshot]:
        with self._lock:
            now = self._clock()
            if self._read_at is None or now - self._read_at >= SNAPSHOT_CACHE:
                self._read_at = now
                try:
                    self._cached = list(self._list())
                except Exception as error:  # the old list beats none
                    logger.info("cannot list the snapshots for the sensor's events: %s", error)
            return self._cached


class _Events(Protocol):
    def events(self, **filters: Any) -> Sequence[Any]: ...


def recorded_keys(box: _Events) -> Callable[[str | None], list[str]]:
    """``already_recorded`` of the reader: the keys (``procs.event_key``) of the sensor events
    in the black box newer than ``since`` (the cursor's time, minus a margin), or of the last
    ones when there is no cursor."""

    def keys(since: str | None) -> list[str]:
        moment = procs.parse_time(since)
        threshold = moment - REPLAY_MARGIN if moment is not None else None
        found: list[str] = []
        for source in ("exec", "net"):
            for event in box.events(source=source, newest_first=True, limit=RECORDED_LOOKUP):
                details = event.details if isinstance(event.details, dict) else {}
                if threshold is not None:
                    t = procs.parse_time(
                        details.get("t") if isinstance(details.get("t"), str) else None
                    )
                    if t is not None and t < threshold:
                        continue
                key = procs.event_key(event.action, details)
                if key is not None:
                    found.append(key)
        return found

    return keys
