"""The real service: the lock, the real parts and the loop that `backtide vigilar` runs.

Design: docs/19-diseno-t04.md, sections "Los procesos" and 3.

- ``take_lock``: one owner of the agent at a time. ``backtide.lock`` is held with ``flock`` for the
  whole life of the service, so ``backtide rebobinar`` can tell "no service" (it takes the lock and
  rewinds in its own process) from "a service" (``ServiceRunning``: it asks over the control
  socket, ``control.py``) by trying the same lock without blocking. The kernel drops it when
  the process dies, also with SIGKILL, so a killed service never leaves a lock behind.
- ``open_black_box``: the key is made on the very first start and never again. A database (or
  its checkpoint, -wal or -shm) without its key is an error, not a reason to start a new chain.
  If the black box cannot be used, an agent left running by a killed service is stopped before
  the error goes up: no recording, no watching.
- ``build_guardian``: the real store, jail, file watcher and black box in one ``Guardian``. Every
  part can be handed in, which is how the VM tests run the real thing without root. The process
  sensor (T07-3, ``build_sensor``) too: the VM tests that do not test it leave it out.
- ``run_guardian``: SIGTERM, SIGINT and SIGHUP stop the service (and so the agent), never kill
  it half way, and a second signal while it stops is ignored: a stop of the agent takes up to
  ``stop_timeout`` s. The handler only writes a byte to a pipe: ``Event.set`` takes a lock, and
  a handler runs on the very thread that may be holding it.
"""

import errno
import fcntl
import logging
import os
import signal
import stat
import threading
from collections.abc import Callable
from pathlib import Path
from types import FrameType, TracebackType
from typing import Protocol

from backtide.analyzer import (
    AssessedBlackBox,
    RiskResponder,
    RulesError,
    RuleSet,
    default_rules,
    parse_rules,
)
from backtide.blackbox import BlackBox, BlackBoxError, create_key, load_key
from backtide.blackbox.redact import KnownScrubber
from backtide.jail import AgentJail, JailError, ca
from backtide.jail.proxy import ProxyJail
from backtide.jail.sensor import SensorJail, SensorJailConfig
from backtide.notify import AlertQueue, FanOut, LogNotifier, Notifier
from backtide.sensors.files import FileWatcher, WatcherConfig
from backtide.sensors.tetragon import TetragonReader
from backtide.service.bot import Hooks, telegram_parts
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.control import ControlServer
from backtide.service.egress import Egress
from backtide.service.guardian import ControlHook, Guardian, SpaceGate, halt_agent
from backtide.service.pause import Holder, make_space_gate, read_holders
from backtide.service.process_sensor import ProcessSensor, SnapshotBefore, recorded_keys
from backtide.service.proxy_channel import Policy, known_secrets
from backtide.service.telegram_config import load_telegram
from backtide.snapshots import SnapshotStore, utc_now
from backtide.snapshots.grow import NOT_CONFIGURED, GrowLimits, VolumeGrower

logger = logging.getLogger(__name__)

_STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
LOCK_ATTEMPTS = 5
_HANDLER = Callable[[int, FrameType | None], None]


class ServiceLocked(RuntimeError):  # noqa: N818 - reads better than ServiceLockedError
    """The lock is taken (another service owns the agent) or cannot be used. The message is
    for the user, in Spanish."""


class ServiceRunning(ServiceLocked):
    """The lock is held by a live process: there is a service (or a rewind without one) that
    owns the agent. ``backtide rebobinar`` asks it over the control socket instead of rewinding
    in its own process."""


class ServiceLock:
    """``backtide.lock`` held with ``flock``. Close it (or leave the ``with``) to release it."""

    def __init__(self, fd: int) -> None:
        self._fd: int | None = fd

    def fileno(self) -> int:
        if self._fd is None:
            raise ValueError("the lock is released")
        return self._fd

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)  # closing drops the flock

    def __enter__(self) -> "ServiceLock":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def take_lock(path: Path) -> ServiceLock:
    """Take the service lock at ``path`` or raise ServiceLocked. Does not block.

    The file is checked like the rest of the state: a regular file of ours with no other name
    (a hard link would let someone hold the same lock from elsewhere), made private if it was
    not. After the ``flock``, the file we hold must still be the one the path names: if someone
    replaced it in between, the lock is on an inode nobody else will ever open by name and a
    second service would own the agent too. Then we try again."""
    for _ in range(LOCK_ATTEMPTS):
        fd = _open_lock_file(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise ServiceRunning(
                "Ya hay un `backtide vigilar` en marcha: solo uno puede vigilar al agente "
                f"(cerrojo {path})."
            ) from None
        except OSError as error:
            os.close(fd)
            raise ServiceLocked(
                f"No se puede tomar el cerrojo {path}: {os.strerror(error.errno or 0)}"
            ) from None
        if _still_the_file_at(fd, path):
            return ServiceLock(fd)
        os.close(fd)  # replaced while we took it: take the new one
    raise ServiceLocked(f"El cerrojo {path} cambia mientras se toma: alguien lo está reemplazando.")


def _open_lock_file(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        if error.errno == errno.ELOOP:  # the last component is a symlink
            raise ServiceLocked(f"El cerrojo {path} es un enlace simbólico: no se usa.") from None
        raise ServiceLocked(
            f"No se puede abrir el cerrojo {path}: {os.strerror(error.errno or 0)}"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ServiceLocked(f"El cerrojo {path} no es un archivo normal: no se usa.")
        if info.st_uid != os.geteuid():
            raise ServiceLocked(
                f"El cerrojo {path} es del usuario {info.st_uid} y no del que ejecuta backtide: "
                "no se usa."
            )
        if info.st_nlink != 1:
            raise ServiceLocked(
                f"El cerrojo {path} tiene {info.st_nlink} nombres (enlaces duros): no se usa."
            )
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _still_the_file_at(fd: int, path: Path) -> bool:
    held = os.fstat(fd)
    try:
        named = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


def open_black_box(config: ServiceConfig) -> BlackBox:
    """The black box of ``config``, not yet opened (the Guardian opens it and writes
    ``service_start``). Creates the key on the very first start; raises BlackBoxError if any
    part of a black box (database, checkpoint, -wal, -shm) exists without it, or the key file
    is not private. Nothing is created in those cases."""
    key_path = config.blackbox_key
    if os.path.lexists(key_path):
        key = load_key(key_path)
    else:
        db = config.blackbox_db
        parts = [
            db,
            config.blackbox_checkpoint,
            db.with_name(db.name + "-wal"),
            db.with_name(db.name + "-shm"),
        ]
        found = [part for part in parts if os.path.lexists(part)]
        if found:
            raise BlackBoxError(
                f"Existe la caja negra ({', '.join(part.name for part in found)}) pero falta su "
                f"clave {key_path}: no se crea una clave nueva para una cadena que ya existe."
            )
        key = create_key(key_path)
    return BlackBox(config.blackbox_db, key, checkpoint_path=config.blackbox_checkpoint)


def load_rules(config: ServiceConfig) -> RuleSet:
    """The risk rules: ``<state_dir>/rules.toml`` if it exists (it REPLACES the default ones),
    else the ones that ship with backtide. A file that is wrong is a ConfigError that says which
    rule and which key: the service does not start with rules nobody can read."""
    text = config.read_rules()
    try:
        if text is None:
            return default_rules()
        return parse_rules(text, origin=str(config.rules_file))
    except RulesError as error:
        raise ConfigError(f"{config.rules_file}: {error}") from None
    except Exception as error:  # the packaged file missing or broken: the same refusal
        raise ConfigError(f"las reglas de riesgo no se pueden leer: {error}") from error


def build_guardian(
    config: ServiceConfig,
    *,
    jail: AgentJail | None = None,
    notifier: Notifier | None = None,
    watcher_config: WatcherConfig | None = None,
    store: SnapshotStore | None = None,
    space: SpaceGate | None = None,
    grow: VolumeGrower | None = None,
    sensor: bool = True,
    sensor_jail: SensorJailConfig | None = None,
    proxy: ProxyJail | None = None,
) -> tuple[Guardian, AlertQueue, BlackBox]:
    """The Guardian with the real store, jail, file watcher and black box, the alert queue it
    reports to (not started) and the black box (not opened).

    With a ``workspace_limit``, the pause by space is on (T04d-2): the real gate
    (``make_space_gate``) and the reader of what holds the space. Without one there is no cap
    to measure against and the pause is off, which is logged. ``store`` and ``space`` replace
    the real ones (the VM tests: a cap set through their one sudo command, and a gate that does
    not count the VM's tmpfs against P6).

    The emergency growth (T04e-1) gets the configured image and ceiling, if any, and the
    privileged steps ``NOT_CONFIGURED``: until T13 decides how backtide gets that privilege, a
    growth is recorded as failed at its first step and nothing changes. ``grow`` replaces it.

    The process sensor (T07-3) is built from ``[sensor]``; ``sensor=False`` leaves it out and
    ``sensor_jail`` replaces its container's settings (the VM tests: one Tetragon per VM, and
    a file the test user can read).

    The egress proxy (T06-4, ``build_egress``) is always there: it is the agent's only way out.
    ``proxy`` replaces its container (the VM tests: their concessions, docs/21 "En la VM")."""
    jail = jail if jail is not None else AgentJail(config.jail_config())
    try:
        rules = load_rules(config)  # a broken file is an error, not a guess
    except ConfigError as error:
        _stop_unrecorded_agent(jail, error, what="las reglas de riesgo no se pueden usar")
        raise
    try:
        box = open_black_box(config)
    except BlackBoxError as error:
        _stop_unrecorded_agent(jail, error)
        raise
    if store is None:
        store = SnapshotStore(config.volume, workspace_limit=config.workspace_limit)
    if space is None:
        space = make_space_gate(config, store)
    if space is None:
        logger.warning(
            "no workspace_limit is configured: the agent is not paused for lack of space"
        )
    alerts = AlertQueue(notifier if notifier is not None else LogNotifier())
    # The rules sit in front of the black box (T08): the Guardian and the watcher record through
    # it, and an event of risk 3 gets an evidence snapshot and an alert.
    responder = RiskResponder(alerts)
    rated_box = AssessedBlackBox(box, rules, responder)
    watcher = FileWatcher(
        jail.config.agent_dir, rated_box, workspace_id=store.workspace_id, config=watcher_config
    )
    holders_of = store

    def holders() -> list[Holder]:
        return read_holders(holders_of)

    if grow is None:
        grow = make_grower(config)
    process_sensor = (
        build_sensor(config, jail, rated_box, store, jail_config=sensor_jail) if sensor else None
    )
    egress = build_egress(config, jail, rated_box, proxy=proxy)
    guardian = Guardian(
        config,
        store=store,
        jail=jail,
        blackbox=rated_box,
        watcher=watcher,
        alerts=alerts,
        space=space,
        holders=holders,
        grow=grow,
        risk=responder,
        prepare_egress=lambda: prepare_egress(config),
        sensor=process_sensor,
        egress=egress,
    )
    responder.bind(snapshot=guardian.take_evidence, record=rated_box.append)
    return guardian, alerts, box


def build_sensor(
    config: ServiceConfig,
    agent: AgentJail,
    box: AssessedBlackBox,
    store: SnapshotStore,
    *,
    jail_config: SensorJailConfig | None = None,
) -> ProcessSensor:
    """The process sensor of ``config`` (docs/23): Tetragon's container, and the reader that
    records the agent's commands and connections through the rules (``box``), each with the
    snapshot to rewind to, the Gateway token struck and what an earlier run already recorded
    skipped. Constructed only: the Guardian starts it."""
    jail_config = jail_config if jail_config is not None else config.sensor_jail_config()
    # The Gateway token and the providers' keys (the agent may type its fake one in a command;
    # the real one it never has, but nothing it could show is recorded either). known_secrets
    # leaves out what is too short to search for (redact() still runs), so nothing here fails
    # quietly: a config whose providers cannot be built raises.
    known = known_secrets(
        [config.gateway_token.reveal(), *config.model_providers().known_secrets()]
    )
    # cut_tails: Tetragon cuts long arguments (~327 KiB), maybe in the middle of a secret.
    scrub = KnownScrubber(list(known), cut_tails=True).text if known else None
    reader = TetragonReader(
        config.sensor_reader_config(),
        box,
        snapshot_for=SnapshotBefore(lambda: store.snapshots()),
        scrub=scrub,
        already_recorded=recorded_keys(box),
        stale_probes_before=utc_now(),
    )
    return ProcessSensor(
        SensorJail(jail_config),
        reader,
        agent,
        required=config.sensor_required,
        novelty_streak=config.sensor_novelty_streak,
    )


def build_egress(
    config: ServiceConfig,
    agent: AgentJail,
    box: AssessedBlackBox,
    *,
    proxy: ProxyJail | None = None,
) -> Egress:
    """The egress proxy of ``config`` (docs/21, section 9): its container, and what backtide lets
    out through it, the allowed hosts of ``[proxy]`` and the model providers' hosts. The channel
    hands the proxy each provider's real and fake key (in memory only: the ``config`` message,
    T06-5), records through the rules (``box``) and strikes the Gateway token too. Constructed
    only: the Guardian starts it. ConfigError for an allowed host the gate cannot use."""
    proxy = proxy if proxy is not None else ProxyJail(config.proxy_jail_config())
    settings = config.proxy_settings()
    policy = Policy(
        allow_hosts=settings.allow_hosts,
        providers=config.model_providers(),
        secrets=known_secrets([config.gateway_token.reveal()]),
        provider_tools=settings.allow_provider_tools,
    )
    try:
        policy.allow_list()
    except ValueError as error:
        raise ConfigError(f"[proxy] allow_hosts: {error}") from None
    return Egress(proxy, agent_name=agent.config.name, policy=policy, record=box.append)


def prepare_egress(config: ServiceConfig) -> None:
    """What the agent's way out needs before its container is made (T06-2): the proxy's CA,
    made once, and the agent's copy of its certificate. Starting the proxy itself, and watching
    it, is T06-4's (docs/21, section 9)."""
    if ca.ensure_ca(config.ca_paths()):
        logger.info("made the egress proxy's CA in %s", config.proxy_ca_dir)


def make_grower(config: ServiceConfig) -> VolumeGrower:
    """The emergency growth of the volume (T04e-1) as configured: the image and the ceiling,
    if both are set, and the privileged steps ``NOT_CONFIGURED`` until T13 decides how backtide
    gets that privilege (a growth then fails at its first step and changes nothing)."""
    limits = None
    if config.volume_image is not None and config.max_volume_bytes is not None:
        limits = GrowLimits(config.volume_image, config.max_volume_bytes)
    return VolumeGrower(config.volume, limits, steps=NOT_CONFIGURED)


def _stop_unrecorded_agent(
    jail: AgentJail, error: Exception, *, what: str = "la caja negra no se puede usar"
) -> None:
    """The black box (or the rules) cannot be used, so the Guardian (which would do this) does
    not exist yet. An agent that a killed service left running is running unrecorded: stop it.
    Raises a JailError, caused by ``error``, if it cannot be stopped; else adds a note to
    ``error``. ``what`` says why, in Spanish, for the JailError."""
    try:
        running = jail.is_running()
    except JailError:
        running = True  # cannot tell: halt_agent confirms
    if not running:
        return
    logger.error("the service cannot start, so the agent that was running is stopped: %s", error)
    stop_error = halt_agent(jail, kill_first=True)  # unwatched: no `docker stop` grace period
    if stop_error is not None:
        raise JailError(
            f"EL AGENTE SIGUE EN MARCHA sin vigilancia: {what} ({error}) "
            f"y no se ha podido parar: {stop_error}"
        ) from error
    error.add_note("Se ha parado al agente que estaba en marcha: sin grabar no hay vigilancia.")


class _Runnable(Protocol):
    def run(self, stop: threading.Event, **options: ControlHook) -> None: ...


class _Closable(Protocol):
    def close(self) -> object: ...


class _Startable(_Closable, Protocol):
    def start(self) -> None: ...


def run_guardian(
    guardian: _Runnable,
    alerts: _Startable,
    box: _Closable,
    *,
    stop: threading.Event | None = None,
    handle_signals: bool = True,
    control: ControlHook | None = None,
) -> None:
    """Run ``guardian`` until ``stop`` is set, SIGTERM, SIGINT or SIGHUP arrives, or it fails.

    The alerts are delivering before the guardian starts and are flushed after it ends, so the
    alert about a failed start is not lost. The guardian's own ``run`` stops the agent and
    records ``service_stop``; the black box is closed last. Raises what the guardian raises.
    ``control`` is the control socket (``ControlServer``): the guardian starts it once the
    service is up and closes it before stopping. Signal handlers only work in the main thread."""
    stop = stop if stop is not None else threading.Event()
    wake = _StopPipe(stop) if handle_signals else None
    previous: dict[int, object] = {}
    if wake is not None:
        for number in _STOP_SIGNALS:
            previous[number] = signal.signal(number, wake.on_signal)
    alerts.start()
    try:
        if control is None:
            guardian.run(stop)
        else:
            guardian.run(stop, control=control)
    finally:
        try:
            alerts.close()
            box.close()
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)  # type: ignore[arg-type]
            if wake is not None:
                wake.close()


class _StopPipe:
    """Turns a signal into ``stop.set()`` without the handler touching a lock: the handler
    writes one byte to a pipe and a thread of ours reads it and sets the event. Again while
    stopping: the event is already set, so another byte changes nothing."""

    def __init__(self, stop: threading.Event) -> None:
        self._stop = stop
        self._read, self._write = os.pipe()
        os.set_blocking(self._write, False)  # a handler must never block
        self._thread = threading.Thread(target=self._run, name="backtide-signals", daemon=True)
        self._thread.start()

    def on_signal(self, number: int, frame: FrameType | None) -> None:
        try:
            os.write(self._write, b"x")
        except BlockingIOError:
            pass  # the pipe is full of earlier signals: the stop is already on its way

    def _run(self) -> None:
        while os.read(self._read, 64):
            self._stop.set()

    def close(self) -> None:
        """After the handlers are gone: closing the write end ends the thread."""
        os.close(self._write)
        self._thread.join(5)
        os.close(self._read)


def serve(
    config: ServiceConfig,
    *,
    jail: AgentJail | None = None,
    notifier: Notifier | None = None,
    watcher_config: WatcherConfig | None = None,
    stop: threading.Event | None = None,
    handle_signals: bool = True,
    store: SnapshotStore | None = None,
    space: SpaceGate | None = None,
    sensor: bool = True,
    sensor_jail: SensorJailConfig | None = None,
    proxy: ProxyJail | None = None,
) -> None:
    """What `backtide vigilar` does: take the lock, build the real service and run it until it is
    told to stop, with the control socket of ``backtide rebobinar`` and ``backtide seguir`` open
    while it runs (``store`` and ``space``: see ``build_guardian``). Raises
    ServiceLocked, ControlError (the socket cannot be opened; the agent is stopped then),
    BlackBoxError, ConfigError-like errors from the parts, ``UnrewindableConfig`` (the caller
    shows its ``notice``) or, if the agent could not be stopped, the JailError that says it
    keeps running.

    With ``<state_dir>/telegram.toml`` (T09) the alerts also go to Telegram and the bot runs
    inside the service, started after the control socket and closed before it; an unusable
    file is a ConfigError, before anything starts."""
    settings = load_telegram(config.state_dir)
    with take_lock(config.lock_file):
        telegram = telegram_parts(config, settings) if settings is not None else None
        if telegram is not None:
            notifier = FanOut(notifier or LogNotifier(), telegram.notifier)
        guardian, alerts, box = build_guardian(
            config,
            jail=jail,
            notifier=notifier,
            watcher_config=watcher_config,
            store=store,
            space=space,
            sensor=sensor,
            sensor_jail=sensor_jail,
            proxy=proxy,
        )
        control: ControlHook = ControlServer(guardian, config.control_socket)
        if telegram is not None:
            snapshots = store if store is not None else SnapshotStore(config.volume)
            telegram.actions.bind(guardian, box, snapshots)
            control = Hooks(control, telegram.bot)
        run_guardian(
            guardian, alerts, box, stop=stop, handle_signals=handle_signals, control=control
        )
