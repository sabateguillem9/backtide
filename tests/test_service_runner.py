"""The real service's assembly: the lock, the black box's key, the real parts and the run loop.

Nothing here touches Docker, btrfs or inotify: the parts are only constructed (their
constructors do no I/O), and the run loop is driven with a fake guardian. The VM tests
(tests/integration/test_service.py) run the real thing.
"""

import fcntl
import os
import signal
import stat
import threading
from pathlib import Path

import pytest

from vigia.blackbox import BlackBox, BlackBoxError
from vigia.jail import AgentJail, JailError
from vigia.notify import AlertQueue, LogNotifier
from vigia.sensors.files import FileWatcher
from vigia.service.config import Secret, ServiceConfig
from vigia.service.guardian import Guardian
from vigia.service.runner import (
    ServiceLocked,
    build_guardian,
    open_black_box,
    run_guardian,
    serve,
    take_lock,
)
from vigia.snapshots import SnapshotStore

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return ServiceConfig(state_dir=state, volume=tmp_path / "vol", gateway_token=Secret(TOKEN))


# --- the lock: one owner of the agent at a time ------------------------------------------------


def test_the_lock_is_taken_and_a_second_owner_is_refused(config: ServiceConfig) -> None:
    with take_lock(config.lock_file):
        with pytest.raises(ServiceLocked, match="vigilar"):
            take_lock(config.lock_file)
    with take_lock(config.lock_file):  # released when the first owner is done
        pass


def test_the_lock_file_is_private(config: ServiceConfig) -> None:
    with take_lock(config.lock_file):
        assert stat.S_IMODE(config.lock_file.stat().st_mode) == 0o600


def test_the_lock_dies_with_its_owner_process(config: ServiceConfig) -> None:
    """flock belongs to the open file, not to the file name: a service killed with SIGKILL
    leaves a lock file behind, and the next service can take it."""
    config.lock_file.write_text("left by a killed service")
    config.lock_file.chmod(0o600)
    with take_lock(config.lock_file):
        pass


def test_the_lock_is_not_inherited_by_child_processes(config: ServiceConfig) -> None:
    """docker CLI children would otherwise keep the lock after the service died."""
    with take_lock(config.lock_file) as lock:
        assert not os.get_inheritable(lock.fileno())


def test_a_symlinked_lock_file_is_refused(config: ServiceConfig, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("")
    config.lock_file.symlink_to(target)
    with pytest.raises(ServiceLocked, match="enlace simbólico"):
        take_lock(config.lock_file)


def test_the_lock_is_the_flock_the_cli_will_probe(config: ServiceConfig) -> None:
    """T04c-2's `vigia rebobinar` decides between "no service" and "send it over the
    socket" with a non-blocking flock on this same file."""
    with take_lock(config.lock_file):
        fd = os.open(config.lock_file, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


# --- the black box -----------------------------------------------------------------------------


def test_the_first_start_creates_the_key_and_the_next_one_reuses_it(config: ServiceConfig) -> None:
    box = open_black_box(config)
    assert stat.S_IMODE(config.blackbox_key.stat().st_mode) == 0o600
    first_key = config.blackbox_key.read_bytes()
    box.open()
    box.append("system", "service_start", "")
    box.close()
    again = open_black_box(config)
    again.open()
    assert config.blackbox_key.read_bytes() == first_key
    assert again.verify().ok
    again.close()


def test_a_database_without_its_key_is_refused_and_no_new_key_is_made(
    config: ServiceConfig,
) -> None:
    config.blackbox_db.write_bytes(b"")  # there is a black box, but its key is gone
    with pytest.raises(BlackBoxError, match="clave"):
        open_black_box(config)
    assert not config.blackbox_key.exists()


def test_a_key_open_to_others_is_refused(config: ServiceConfig) -> None:
    open_black_box(config)
    config.blackbox_key.chmod(0o644)
    with pytest.raises(BlackBoxError):
        open_black_box(config)


# --- the real parts ----------------------------------------------------------------------------


def test_build_guardian_wires_the_real_parts(config: ServiceConfig) -> None:
    guardian, alerts, box = build_guardian(config)
    assert isinstance(guardian, Guardian)
    assert isinstance(alerts, AlertQueue)
    assert isinstance(box, BlackBox)
    assert isinstance(guardian._store, SnapshotStore)  # noqa: SLF001
    assert guardian._store.root == config.volume  # noqa: SLF001
    assert isinstance(guardian._jail, AgentJail)  # noqa: SLF001
    assert isinstance(guardian._watcher, FileWatcher)  # noqa: SLF001
    assert guardian._space is None  # noqa: SLF001 - the pause comes with T04d-2


def test_the_watcher_watches_the_agents_own_folder_and_nothing_else(config: ServiceConfig) -> None:
    guardian, _, _ = build_guardian(config)
    watched = guardian._watcher._agent_dir  # noqa: SLF001
    assert watched == config.workspace / "agente"
    assert watched == guardian._jail.config.agent_dir  # noqa: SLF001


def test_the_store_gets_the_workspace_limit_of_the_config(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    limited = ServiceConfig(
        state_dir=state,
        volume=tmp_path / "vol",
        gateway_token=Secret(TOKEN),
        workspace_limit=123456,
    )
    guardian, _, _ = build_guardian(limited)
    assert guardian._store._workspace_limit == 123456  # noqa: SLF001


def test_build_guardian_takes_a_jail_the_tests_can_adjust(config: ServiceConfig) -> None:
    """The VM tests run without root, so the agent's ids are the user's: they hand in a jail
    with that one concession instead of the config file growing a switch for it."""
    jail = AgentJail(config.jail_config())
    guardian, _, _ = build_guardian(config, jail=jail)
    assert guardian._jail is jail  # noqa: SLF001
    assert guardian._watcher._agent_dir == jail.config.agent_dir  # noqa: SLF001


def test_the_alerts_go_to_the_log_by_default(config: ServiceConfig) -> None:
    _, alerts, _ = build_guardian(config)
    assert isinstance(alerts._notifier, LogNotifier)  # noqa: SLF001


# --- the run loop ------------------------------------------------------------------------------


class FakeGuardian:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.error: Exception | None = None
        self.on_run: object = None

    def run(self, stop: threading.Event) -> None:
        self.calls.append("guardian.run")
        if callable(self.on_run):
            self.on_run(stop)
        else:
            stop.wait(5)
        self.calls.append("guardian.stopped")
        if self.error is not None:
            raise self.error


class FakeAlerts:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def start(self) -> None:
        self.calls.append("alerts.start")

    def close(self) -> bool:
        self.calls.append("alerts.close")
        return True


class FakeBox:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def close(self) -> None:
        self.calls.append("box.close")


def run(calls: list[str], guardian: FakeGuardian, **kwargs: object) -> None:
    run_guardian(guardian, FakeAlerts(calls), FakeBox(calls), **kwargs)  # type: ignore[arg-type]


def test_the_alerts_are_running_before_the_guardian_and_everything_is_closed_after() -> None:
    calls: list[str] = []
    guardian = FakeGuardian(calls)
    guardian.on_run = lambda stop: None
    run(calls, guardian, handle_signals=False)
    assert calls == [
        "alerts.start",
        "guardian.run",
        "guardian.stopped",
        "alerts.close",
        "box.close",
    ]


def test_a_guardian_that_fails_still_closes_the_alerts_and_the_box() -> None:
    calls: list[str] = []
    guardian = FakeGuardian(calls)
    guardian.on_run = lambda stop: None
    guardian.error = JailError("the agent is still running")
    with pytest.raises(JailError, match="still running"):
        run(calls, guardian, handle_signals=False)
    assert calls[-2:] == ["alerts.close", "box.close"]


@pytest.mark.parametrize("name", ["SIGTERM", "SIGINT", "SIGHUP"])
def test_a_signal_stops_the_guardian_instead_of_killing_the_process(name: str) -> None:
    calls: list[str] = []
    guardian = FakeGuardian(calls)
    number = getattr(signal, name)
    timer = threading.Timer(0.3, os.kill, args=(os.getpid(), number))
    before = signal.getsignal(number)
    timer.start()
    try:
        run(calls, guardian)  # waits on `stop` for up to 5 s: the signal must end it
    finally:
        timer.cancel()
    assert calls == [
        "alerts.start",
        "guardian.run",
        "guardian.stopped",
        "alerts.close",
        "box.close",
    ]
    assert signal.getsignal(number) is before  # the handlers are put back


def test_the_stop_event_can_also_be_given() -> None:
    calls: list[str] = []
    stop = threading.Event()
    stop.set()
    run(calls, FakeGuardian(calls), stop=stop, handle_signals=False)
    assert "guardian.stopped" in calls


def test_a_second_signal_while_stopping_does_not_interrupt_the_stop() -> None:
    """SIGTERM twice (systemd, then an impatient Ctrl-C): the stop of the agent, which takes
    up to 30 s, must run to its end."""
    calls: list[str] = []
    guardian = FakeGuardian(calls)

    def slow_stop(stop: threading.Event) -> None:
        stop.wait(5)
        os.kill(os.getpid(), signal.SIGTERM)  # the impatient one, while "stopping"
        calls.append("still stopping")

    guardian.on_run = slow_stop
    timer = threading.Timer(0.2, os.kill, args=(os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        run(calls, guardian)
    finally:
        timer.cancel()
    assert "still stopping" in calls
    assert calls[-1] == "box.close"


def test_a_signal_handler_touches_no_lock_it_only_writes_to_a_pipe() -> None:
    """Event.set() takes a lock: from a signal handler that interrupted the very thread that
    holds it, that is a deadlock. The handler writes a byte; another thread sets the event."""

    class RecordingEvent(threading.Event):
        setters: list[str] = []  # noqa: RUF012 - one test, one list

        def set(self) -> None:
            RecordingEvent.setters.append(threading.current_thread().name)
            super().set()

    RecordingEvent.setters = []
    calls: list[str] = []
    stop = RecordingEvent()
    timer = threading.Timer(0.2, os.kill, args=(os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        run(calls, FakeGuardian(calls), stop=stop)
    finally:
        timer.cancel()
    assert RecordingEvent.setters
    assert threading.main_thread().name not in RecordingEvent.setters


def test_no_thread_or_pipe_is_left_behind_by_the_signal_plumbing() -> None:
    before = threading.active_count()
    fds = len(os.listdir("/dev/fd"))
    calls: list[str] = []
    stop = threading.Event()
    stop.set()
    for _ in range(3):
        run(calls, FakeGuardian(calls), stop=stop)
    assert threading.active_count() == before
    assert len(os.listdir("/dev/fd")) == fds


# --- an unusable black-box key must not leave an unrecorded agent running ----------------------


class StubJail:
    """The part of AgentJail the cleanup uses."""

    def __init__(self, *, running: bool) -> None:
        self.running = running
        self.calls: list[str] = []
        self.fail_to_stop = False

    def is_running(self) -> bool:
        return self.running

    def is_paused(self) -> bool:
        return False

    def stop(self) -> None:
        self.calls.append("stop")
        if self.fail_to_stop:
            raise JailError("docker stop failed")
        self.running = False

    def kill(self) -> None:
        self.calls.append("kill")
        if self.fail_to_stop:
            raise JailError("docker kill failed")
        self.running = False

    def remove(self) -> None:
        self.calls.append("remove")
        if self.fail_to_stop:
            raise JailError("docker rm failed")
        self.running = False


def bad_key(config: ServiceConfig) -> None:
    config.blackbox_key.write_bytes(os.urandom(32))
    config.blackbox_key.chmod(0o644)  # open to others: load_key refuses it


@pytest.mark.parametrize(
    "damage",
    ["mode_0644", "wrong_size", "db_without_key", "checkpoint_without_key"],
)
def test_an_unusable_key_stops_the_agent_a_killed_service_left_running(
    config: ServiceConfig, damage: str
) -> None:
    if damage == "mode_0644":
        bad_key(config)
    elif damage == "wrong_size":
        config.blackbox_key.write_bytes(b"short")
        config.blackbox_key.chmod(0o600)
    elif damage == "db_without_key":
        config.blackbox_db.write_bytes(b"")
    else:
        config.blackbox_checkpoint.write_bytes(b"{}")
    jail = StubJail(running=True)
    with pytest.raises(BlackBoxError) as raised:
        build_guardian(config, jail=jail)  # type: ignore[arg-type]
    assert not jail.running
    assert jail.calls == ["stop"]
    assert any("parado" in note for note in raised.value.__notes__)


def test_an_unusable_key_with_no_agent_running_touches_nothing(config: ServiceConfig) -> None:
    bad_key(config)
    jail = StubJail(running=False)
    with pytest.raises(BlackBoxError) as raised:
        build_guardian(config, jail=jail)  # type: ignore[arg-type]
    assert jail.calls == []
    assert not getattr(raised.value, "__notes__", [])


def test_an_unusable_key_and_an_agent_that_will_not_stop_says_the_agent_keeps_running(
    config: ServiceConfig,
) -> None:
    bad_key(config)
    jail = StubJail(running=True)
    jail.fail_to_stop = True
    with pytest.raises(JailError, match="SIGUE EN MARCHA") as raised:
        build_guardian(config, jail=jail)  # type: ignore[arg-type]
    assert isinstance(raised.value.__cause__, BlackBoxError)  # and the key's problem with it
    assert jail.calls == ["stop", "kill", "remove"]


def test_an_unusable_key_in_serve_releases_the_lock_after_stopping_the_agent(
    config: ServiceConfig,
) -> None:
    bad_key(config)
    jail = StubJail(running=True)
    with pytest.raises(BlackBoxError):
        serve(config, jail=jail, handle_signals=False)  # type: ignore[arg-type]
    assert not jail.running
    take_lock(config.lock_file).close()


# --- the lock file is checked like the other files of the state --------------------------------


def test_a_lock_file_open_to_others_is_made_private(config: ServiceConfig) -> None:
    config.lock_file.write_text("")
    config.lock_file.chmod(0o666)
    with take_lock(config.lock_file):
        assert stat.S_IMODE(config.lock_file.stat().st_mode) == 0o600


def test_a_lock_file_with_another_name_for_it_is_refused(
    config: ServiceConfig, tmp_path: Path
) -> None:
    """A hard link: someone else could hold the same lock under a name of their own."""
    config.lock_file.write_text("")
    os.link(config.lock_file, tmp_path / "other-name")
    with pytest.raises(ServiceLocked, match="enlaces"):
        take_lock(config.lock_file)


def test_a_lock_file_that_is_not_a_regular_file_is_refused(config: ServiceConfig) -> None:
    os.mkfifo(config.lock_file)
    with pytest.raises(ServiceLocked, match="archivo normal"):
        take_lock(config.lock_file)


def test_a_lock_file_of_another_user_is_refused(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.lock_file.write_text("")
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(ServiceLocked, match="es del usuario"):
        take_lock(config.lock_file)


def test_a_lock_file_replaced_between_open_and_flock_is_retried(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock would be held on an inode nobody else will ever open by name: a second service
    would take the new file and both would own the agent."""
    config.lock_file.write_text("")
    real_flock = fcntl.flock
    swapped: list[bool] = []

    def swapping(fd: int, operation: int) -> None:
        if not swapped:
            swapped.append(True)
            config.lock_file.unlink()
            config.lock_file.write_text("")
            config.lock_file.chmod(0o600)
        real_flock(fd, operation)

    monkeypatch.setattr(fcntl, "flock", swapping)
    with take_lock(config.lock_file) as lock:
        held, named = os.fstat(lock.fileno()), os.stat(config.lock_file)
        assert (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
    assert swapped


def test_a_lock_file_that_keeps_being_replaced_gives_up(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.lock_file.write_text("")
    real_flock = fcntl.flock

    def always_swapping(fd: int, operation: int) -> None:
        config.lock_file.unlink()
        config.lock_file.write_text("")
        config.lock_file.chmod(0o600)
        real_flock(fd, operation)

    monkeypatch.setattr(fcntl, "flock", always_swapping)
    with pytest.raises(ServiceLocked, match="cambia|reemplaz"):
        take_lock(config.lock_file)


# --- the key must exist before any other part of the black box is trusted ---------------------


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_a_wal_or_shm_without_the_key_is_refused_and_creates_nothing(
    config: ServiceConfig, suffix: str
) -> None:
    config.blackbox_db.with_name(config.blackbox_db.name + suffix).write_bytes(b"")
    with pytest.raises(BlackBoxError, match="clave"):
        open_black_box(config)
    assert not config.blackbox_key.exists()


def test_a_checkpoint_without_the_key_is_refused_and_creates_nothing(
    config: ServiceConfig,
) -> None:
    config.blackbox_checkpoint.write_bytes(b"{}")
    with pytest.raises(BlackBoxError, match="clave"):
        open_black_box(config)
    assert not config.blackbox_key.exists()
