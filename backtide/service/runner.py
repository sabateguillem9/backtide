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
- ``serve`` with ``others`` (T26-2b; docs/47, section 6.1): one ``Guardian`` per agent in one
  process. The main one runs on the main thread, as it always did: the sockets, the bot and the
  lock are its and, if it ends, so does everything (fail closed, and systemd starts it again).
  Every other one runs on a thread of its own (``_Neighbours``): one that cannot start or fails is
  told, in the installation's black box and to the owner, and the others go on. With no others,
  no thread and nothing of this.
- With ``others`` too (T26-2c): an order on the sockets says which agent it is about
  (``backtide.service.roster``), each agent is published there once its ``Guardian`` is up and taken
  out before it stops, and ``InstallationSpend`` adds up what all of them spend.
- ``backtide.service.fleet`` (T26-6a) creates, starts and stops the others while the service runs:
  each has a stop of its own, its volume and channel are mounted before it is built
  (``agent_disk``), and one the owner stopped stays stopped across a restart.
- It deletes them too (T26-6c): a deleted agent is nobody here, its box and its volume wait in its
  folder (``backtide.service.trash``), and its spending still counts. Deleting the last one does
  not take the installation back to one agent's budget (``spend_total_for``).
"""

import dataclasses
import errno
import fcntl
import logging
import os
import signal
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import FrameType, TracebackType
from typing import Any, Protocol

from backtide.analyzer import (
    AssessedBlackBox,
    RiskResponder,
    RulesError,
    RuleSet,
    default_rules,
    parse_rules,
)
from backtide.blackbox import BlackBox, BlackBoxError, create_key, load_key
from backtide.blackbox.redact import MIN_KNOWN_SECRET, redact
from backtide.gate import protocol
from backtide.gate.providers import Providers
from backtide.gate.translate.base import MAIL_TRANSLATORS
from backtide.jail import AgentJail, JailError, ca
from backtide.jail.config import Protected
from backtide.jail.proxy import ProxyJail
from backtide.jail.sensor import SensorJail, SensorJailConfig
from backtide.notify import (
    ALREADY_TOLD,
    Alert,
    AlertLevel,
    AlertQueue,
    AlertSink,
    FanOut,
    Labelled,
    LogNotifier,
    Notifier,
)
from backtide.sensors.files import FileWatcher, WatcherConfig
from backtide.sensors.scrub import LiveScrub
from backtide.sensors.tetragon import TetragonReader
from backtide.service import scope
from backtide.service.agent_disk import SYSTEMD_RUN_MARK, ensure_on_disk, is_stopped
from backtide.service.bot import Hooks, TelegramNeighbours, telegram_parts
from backtide.service.config import (
    KEY_UNUSABLE,
    ConfigError,
    ProviderKey,
    ServiceConfig,
    ensure_state_folder,
    holds_fake,
    read_real_keys,
    read_strike_only,
)
from backtide.service.control import ControlServer
from backtide.service.egress import Egress
from backtide.service.fleet import Fleet, TrashWatch
from backtide.service.guardian import ControlHook, Guardian, SpaceGate, halt_agent
from backtide.service.holds import HoldTimings, HoldWatch
from backtide.service.local_models import (
    ContextNeed,
    LocalModelError,
    Lookup,
    ollama_contexts,
    ollama_version,
    resolve_all,
)
from backtide.service.passkeys import WEB_PORT, Passkeys, origin_for
from backtide.service.password import Checker
from backtide.service.pause import Holder, make_space_gate, read_holders
from backtide.service.price_update import PriceUpdater
from backtide.service.process_sensor import (
    ProcessSensor,
    SensorShare,
    SnapshotBefore,
    recorded_keys,
)
from backtide.service.proxy_channel import KEY_NOT_APPLIED, Policy, known_secrets
from backtide.service.roster import Desk, Roster
from backtide.service.settings import Applied, ReloadFailedClosed, Settings
from backtide.service.spend import MAX_CAP_USD, STATE_BUDGET, Budget, SharedSpend
from backtide.service.spend_total import InstallationSpend
from backtide.service.telegram_config import load_telegram
from backtide.service.trash import retired_agents
from backtide.service.trust import TrustStore
from backtide.service.web_control import WebControlServer
from backtide.snapshots import SnapshotStore, utc_now
from backtide.snapshots.grow import NOT_CONFIGURED, GrowLimits, VolumeGrower

logger = logging.getLogger(__name__)

NEIGHBOURS_STOP = 110.0  # under the unit's TimeoutStopSec, which ends it all at 120
_FAILED_AGENT_CHARS = 300
# What the web's group has of another agent's black box (T26-2d), as of the main one's (D25).
WEB_FOLDER_MODE, WEB_BOX_MODE = 0o710, 0o640
_INSTALLATION_BOX = (
    threading.Lock()
)  # one writer: agents may fail at once, and its key is made once
_STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
LOCK_ATTEMPTS = 5


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
    return _box_at(config.blackbox_db, config.blackbox_key, config.blackbox_checkpoint)


def open_installation_box(config: ServiceConfig) -> BlackBox:
    """The installation's own black box (T26-2a, docs/47 section 6.2), not yet opened, with the
    same rules as an agent's: its key is made once and a box without it is refused. Its folder
    is made here. Raises BlackBoxError or ConfigError."""
    ensure_state_folder(config.installation_dir, "the installation's black box folder")
    return _box_at(config.installation_db, config.installation_key, config.installation_checkpoint)


def record_installation_start(
    config: ServiceConfig, alerts: AlertSink, others: Sequence[ServiceConfig] = ()
) -> None:
    """Write in the installation's box that the service starts, and with which agents. Opened
    and closed each time: what goes there is rare, and it holds nothing open.

    A box that cannot be used never stops the service: it records no agent, whose own black box
    is untouched and is what the service depends on. It is told out loud instead, and a chain
    that does not verify is not extended."""
    details = {"agents": [config.slug, *(other.slug for other in others)]}
    _record_in_installation(config, alerts, "service_start", "", details)


def record_agent_failed(
    config: ServiceConfig, alerts: AlertSink, slug: str, error: BaseException
) -> None:
    """An agent other than the main one could not start or stopped being watched: it is told
    in the installation's box, whose business it is, and to the owner. The others go on."""
    text = str(redact(f"{type(error).__name__}: {error}"))[:_FAILED_AGENT_CHARS]
    _record_in_installation(config, alerts, "agent_failed", slug, {"error": text}, risk=2)
    alerts.submit(
        Alert(
            AlertLevel.ERROR,
            f"El agente {slug} no se está vigilando",
            f"No ha arrancado o ha dejado de vigilarse, y los demás siguen. Causa: {text}",
            agent=slug,
        )
    )


def _record_in_installation(
    config: ServiceConfig,
    alerts: AlertSink,
    action: str,
    target: str,
    details: dict[str, object],
    *,
    risk: int = 0,
    source: str = "system",
) -> bool:
    """True once it is written. If it cannot be, False: logged, alerted, and who asked decides."""
    try:
        with _INSTALLATION_BOX, open_installation_box(config) as box:
            problems = box.verify().problems
            if problems:
                raise BlackBoxError(f"its chain does not verify ({len(problems)} problems)")
            box.append(source, action, target, details=details, risk=risk)
        return True
    except (BlackBoxError, ConfigError, OSError) as error:
        logger.error("the installation's black box cannot be used: %s", error, extra=ALREADY_TOLD)
        alerts.submit(
            Alert(
                AlertLevel.ERROR,
                "La caja de la instalación no se puede usar",
                "Cada agente sigue grabándose en su propia caja negra. Mira "
                f"{config.installation_dir}: {error}",
                installation=True,
            )
        )
        return False


def _box_at(db: Path, key_path: Path, checkpoint: Path) -> BlackBox:
    if os.path.lexists(key_path):
        key = load_key(key_path)
    else:
        parts = [
            db,
            checkpoint,
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
    return BlackBox(db, key, checkpoint_path=checkpoint)


def share_box_with_web(config: ServiceConfig, group: int) -> None:
    """Let the web's group read the black box of an agent other than the main one (T26-2d; D25, as
    the installer does for the main one): its database and SQLite's -wal and -shm, which copy their
    owner and mode, root's 0640 with that group, and its folders 0710, to go through and not to
    list. Done each time it starts: the service owns these folders, and nothing else tends them.

    The agent's folder has been 0700, so something in it may be open and nobody knew (an image made
    by hand with umask 022 is 0644). All of that is closed first (``_close_to_the_web``). Only then
    does the group get to go through. What cannot be closed leaves the folder 0700.

    Whatever fails is said, and nothing is opened: the web cannot read that box, and says so. Never
    a reason for this to stop what comes next, which decides what to do with a box that cannot be
    used (``build_guardian`` stops an agent it cannot record)."""
    try:
        _close_to_the_web(config, group)
        for folder in (config.agents_dir, config.agent_dir):
            _open_to_group(folder, group, WEB_FOLDER_MODE, stat.S_ISDIR)
        open_black_box(config)  # the key comes before the box, or the box would be refused
        db = config.blackbox_db
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            os.close(os.open(db, flags, 0o600))
        except FileExistsError:
            pass
        for path in _box_files(db):
            try:
                _open_to_group(path, group, WEB_BOX_MODE, stat.S_ISREG)
            except FileNotFoundError:
                continue
    except (OSError, BlackBoxError) as error:
        logger.error(
            "the web cannot be given the black box of the agent %s: %s", config.slug, error
        )
        _close_folder(config.agent_dir)


def _box_files(db: Path) -> tuple[Path, Path, Path]:
    return db, db.with_name(f"{db.name}-wal"), db.with_name(f"{db.name}-shm")


def bits_for_the_web(mode: int, gid: int, group: int) -> int:
    """The bits of ``mode`` that let the web's group in. A folder of the agent's or the proxy's
    group (0750) lets it in by nothing: that group is theirs, and they need it."""
    return mode & (0o077 if gid == group else 0o007)


def _close_to_the_web(config: ServiceConfig, group: int) -> None:
    """What is directly in the agent's folder and open to the web's group stops being, but for the
    box and the agent's CA (0755: the certificate alone, as on the main agent's, which the agent
    reads). Never followed. OSError for what it cannot judge or close: a link, or not a file or a
    folder. Below these it does not go: nobody gets past a folder that lets them in by nothing."""
    allowed = {path.name for path in _box_files(config.blackbox_db)} | {config.agent_ca_dir.name}
    folder = os.open(config.agent_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.scandir(folder) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            if name not in allowed:
                _close_one(name, folder, group)
    finally:
        os.close(folder)


def _close_one(name: str, folder: int, group: int) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=folder)
    try:
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise OSError(errno.EPERM, f"{name} is neither a file nor a folder")
        mode = stat.S_IMODE(info.st_mode)
        extra = bits_for_the_web(mode, info.st_gid, group)
        if extra:
            os.fchmod(fd, mode & ~extra)
            logger.warning(
                "%s, in the folder of an agent, was open to the web's group: it is %04o now",
                name,
                mode & ~extra,
            )
    finally:
        os.close(fd)


def _close_folder(path: Path) -> None:
    """Back to 0700, if it is still a folder of ours: it was shared at an earlier start."""
    try:
        _open_to_group(path, -1, 0o700, stat.S_ISDIR)
    except OSError as error:
        logger.error("the folder %s could not be closed to the web: %s", path, error)


def _open_to_group(path: Path, group: int, mode: int, is_right_kind: Callable[[int], bool]) -> None:
    """``path`` with this group (-1: the one it has) and this mode, if it is what it should be and
    ours. Never followed. OSError otherwise."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not is_right_kind(info.st_mode) or info.st_uid != os.geteuid():
            raise OSError(errno.EPERM, f"{path} is not what it should be, or not ours")
        os.fchown(fd, -1, group)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


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
    hold_timings: HoldTimings | None = None,
    on_egress: Callable[[Egress], None] | None = None,
    scrub: LiveScrub | None = None,
    hold_watch: HoldWatch | None = None,
    sensor_share: SensorShare | None = None,
    log_filter: Callable[[logging.LogRecord], bool] | None = None,
    log_nobodys: Callable[[], bool] | None = None,
    spend_total: SharedSpend | None = None,
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
    ``proxy`` replaces its container (the VM tests: their concessions, docs/21 "En la VM"), and
    ``hold_timings`` the gate's times (the VM tests shorten its 5 min and 90 s, T10-2).
    ``on_egress`` is handed the egress once it is built (``serve``: the Settings page hands it
    the providers' new keys, T12e), and ``hold_watch`` is told about its held requests (the
    Telegram notice, T10-4). ``scrub`` is the process sensor's list of secrets to strike,
    filled here and kept by ``serve`` to refresh it when a key changes. With several agents
    (T26-2b), ``sensor_share`` is the one Tetragon they have in common, ``log_filter`` says
    which log records are this one's and ``spend_total`` is what they spend together (T26-2c)."""
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
    # With the Telegram hold desk, a held request's own notice is its alert (T10-4 and its
    # review, M4); without it, the generic alert says so.
    responder = RiskResponder(alerts, quiet_holds=hold_watch is not None)
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
        build_sensor(
            config, jail, rated_box, store, jail_config=sensor_jail, scrub=scrub, share=sensor_share
        )
        if sensor
        else None
    )
    egress = build_egress(
        config,
        jail,
        rated_box,
        proxy=proxy,
        timings=hold_timings,
        watch=hold_watch,
        alerts=alerts,
        spend_total=spend_total,
    )
    if on_egress is not None:
        on_egress(egress)
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
        log_filter=log_filter,
        log_nobodys=log_nobodys,
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
    scrub: LiveScrub | None = None,
    share: SensorShare | None = None,
) -> ProcessSensor:
    """The process sensor of ``config`` (docs/23): Tetragon's container, and the reader that
    records the agent's commands and connections through the rules (``box``), each with the
    snapshot to rewind to, the Gateway token struck and what an earlier run already recorded
    skipped. Constructed only: the Guardian starts it. ``scrub`` is the list of secrets to strike
    (``serve`` keeps it to refresh it when Settings changes a key, T12e): it is filled here."""
    jail_config = jail_config if jail_config is not None else config.sensor_jail_config()
    # The Gateway token and the providers' keys (the agent may type its fake one in a command;
    # the real one it never has, but nothing it could show is recorded either). known_secrets
    # leaves out what is too short to search for (redact() still runs), so nothing here fails
    # quietly: a config whose providers cannot be built raises.
    known = known_secrets([*config.gateway_secrets(), *config.model_providers().known_secrets()])
    # cut_tails: Tetragon cuts long arguments (~327 KiB), maybe in the middle of a secret.
    live = scrub if scrub is not None else LiveScrub()
    live.replace(known)
    reader = TetragonReader(
        config.sensor_reader_config(),
        box,
        snapshot_for=SnapshotBefore(lambda: store.snapshots()),
        scrub=live.text,
        already_recorded=recorded_keys(box),
        stale_probes_before=utc_now(),
    )
    return ProcessSensor(
        SensorJail(jail_config),
        reader,
        agent,
        required=config.sensor_required,
        novelty_streak=config.sensor_novelty_streak,
        share=share,
    )


def build_egress(
    config: ServiceConfig,
    agent: AgentJail,
    box: AssessedBlackBox,
    *,
    proxy: ProxyJail | None = None,
    timings: HoldTimings | None = None,
    watch: HoldWatch | None = None,
    alerts: AlertQueue | None = None,
    spend_total: SharedSpend | None = None,
) -> Egress:
    """The egress proxy of ``config`` (docs/21, section 9): its container, and what backtide lets
    out through it, the allowed hosts of ``[proxy]`` and the model providers' hosts. The channel
    hands the proxy each provider's real and fake key (in memory only: the ``config`` message,
    T06-5), records through the rules (``box``) and strikes the Gateway token too. Constructed
    only: the Guardian starts it. ConfigError for an allowed host the gate cannot use."""
    proxy = proxy if proxy is not None else _proxy_jail(config)
    providers, problems = config.model_providers_and_problems(local_upstreams(config))
    policy = egress_policy(config, providers, problems)
    if timings is None:
        timings = config.gate_settings().timings  # [gate] wait_s, hold_s, preapproval_s
    # The recipients trusted from the web (T10-5, decision 9): trusted.json in the agent's folder
    # (the main one's is <state_dir>), read once here; a file that cannot be used gives no trust
    # (logged). What is trusted for one agent never lets out another's.
    trust = TrustStore(config.agent_dir)
    trust.load()
    budget, prices = build_budget(config, box, alerts, spend_total)
    # The gate (T10-2) reads the black box once, at the first start: the holds a backtide that
    # died left open there are closed.
    return Egress(
        proxy,
        agent_name=agent.config.name,
        policy=policy,
        record=box.append,
        timings=timings,
        history=box.events,
        watch=watch,
        trust=trust,
        budget=budget,
        prices=prices,
        ask_version=ollama_version,  # T20-4: from the VM, never through the proxy
        # How much context the Ollama gives its models (GET /api/ps), against the agent's need.
        ask_context=ollama_contexts,
        context_need=ContextNeed.for_profile(agent.config.profile.name),
    )


def _proxy_jail(config: ServiceConfig) -> ProxyJail:
    """The proxy's container. What a service under its systemd unit mounts stays in its own mount
    namespace and Docker never sees it (docs/25, section 1), so another agent's channel has to be
    mounted before the service starts, as the main one's is by its unit (docs/47, section 6.3)."""
    if not config.is_main and SYSTEMD_RUN_MARK in os.environ:
        return ProxyJail(config.proxy_jail_config(), mount=_channel_not_mounted)
    return ProxyJail(config.proxy_jail_config())


def stop_unwatched(config: ServiceConfig) -> bool:
    """What Docker says runs of this agent, with no Guardian: it is stopped. True if there was
    something to stop. Raises JailError if it keeps running."""
    jail = AgentJail(config.jail_config())
    proxy = ProxyJail(config.proxy_jail_config(), mount=_channel_not_mounted)
    try:
        found = jail.is_running()
    except JailError:
        found = True  # cannot tell: halt_agent confirms
    if found:
        error = halt_agent(jail, kill_first=True)  # unwatched: no grace period
        if error is not None:
            raise error
    if proxy.is_running():  # with no channel it lets nothing out, and it is not left behind
        found = True
        proxy.kill()
    return found


def _channel_not_mounted(argv: list[str]) -> None:
    raise JailError(
        f"the channel's tmpfs has to be mounted before the service starts: {' '.join(argv)}"
    )


def build_budget(
    config: ServiceConfig,
    box: AssessedBlackBox,
    alerts: AlertQueue | None,
    spend_total: SharedSpend | None = None,
) -> tuple[Budget, PriceUpdater]:
    """The spending cap of ``[budget]`` (T11, docs/33) and, unless ``auto_prices = false``, the
    updater of its prices (Anthropic's page, from the service: never through the agent's proxy).
    Constructed only: the Egress opens the budget and starts the updater at its first start.
    What it keeps goes in the agent's folder: <state_dir> for the main one, and for another its
    own, so two ledgers never write one file. With ``spend_total`` (several agents, T26-2c)
    ``[budget]`` is the whole installation's cap, so the agent's own are only those of its file."""
    settings = config.budget_settings()
    own = settings
    if spend_total is not None:
        none_of_its_own = {
            key: MAX_CAP_USD for key in ("daily_usd", "monthly_usd") if key not in config.own_caps
        }
        own = dataclasses.replace(settings, **none_of_its_own)
    budget = Budget(
        own,
        state_dir=config.agent_dir,
        record=box.append,
        alert=None if alerts is None else alerts.submit,
        history=box.events,
        shared=spend_total,
        slug=config.slug,
    )
    # With auto_prices = false it only loads the last good table fetched before (no thread).
    prices = PriceUpdater(
        budget,
        state_dir=config.agent_dir,
        record=box.append,
        url=settings.prices_url,
        auto=settings.auto_prices,
    )
    return budget, prices


def egress_policy(
    config: ServiceConfig,
    providers: Providers,
    problems: Mapping[str, tuple[str, str]] | None = None,
) -> Policy:
    """What backtide lets out through the proxy: the allowed hosts of ``[proxy]``, ``providers``
    (their hosts, fake and real keys; ``problems`` says why those without a real key wait), the
    Gateway token to strike, and the gate of ``[gate]`` (T10-3): the mode for unknown hosts,
    the trusted recipients (with the owner's Telegram chat of ``telegram.toml``, read now) and
    the extra read endpoints. ConfigError for an allowed host the gate cannot use, or an
    unusable ``telegram.toml``."""
    settings = config.proxy_settings()
    telegram = load_telegram(config.state_dir)
    gate = config.gate_settings(owner_chat=None if telegram is None else telegram.chat_id)
    mail = sum(1 for item in gate.trusted if item.translator in MAIL_TRANSLATORS)
    if mail:
        # Final review of T10, finding 2: a trusted mail address needs the owner's own account
        # (approved decision 4, still to do); until then it trusts nothing. Said, not refused.
        logger.warning(
            "[gate] trusted: %d mail recipient(s) are not used until the owner's mail accounts "
            "are configured (docs/32, section 9): those mails are held",
            mail,
        )
    policy = Policy(
        allow_hosts=settings.allow_hosts,
        profile_hosts=settings.profile_hosts,
        providers=providers,
        secrets=known_secrets(config.gateway_secrets()),
        provider_tools=settings.allow_provider_tools,
        unknown_hosts=gate.unknown_hosts,
        trusted=gate.trusted,
        read_endpoints=gate.read_endpoints,
        read_budget_host=gate.read_budget_host,
        read_budget_total=gate.read_budget_total,
        key_problems=dict(problems or {}),
    )
    try:
        policy.allow_list()
    except ValueError as error:
        raise ConfigError(f"[proxy] allow_hosts: {error}") from None
    unresolved = [p.name for p in providers.items if p.local and p.upstream is None]
    if unresolved:  # never handed to the proxy so (protocol.config refuses it too)
        raise ConfigError(f"[proxy] providers: {', '.join(unresolved)} have no address yet")
    return policy


def local_upstreams(
    config: ServiceConfig,
    previous: Mapping[str, tuple[str, int]] | None = None,
    *,
    lookup: Lookup | None = None,
    moved: dict[str, tuple[str, int]] | None = None,
) -> dict[str, tuple[str, int]]:
    """Where each local provider of ``[proxy]`` is (T20, local_models.py): resolved here, on the
    trusted side. At the start (``previous`` None) a provider that cannot be placed is a
    ConfigError, so the service does not start; at a reload it keeps the address it had, also
    when it now resolves elsewhere (that new place goes into ``moved``: the owner confirms it
    by restarting). A key file of a local provider is never used (it is struck): said in the
    log."""
    providers = config.proxy_settings().providers
    for provider in providers:
        key = config.provider_keys.get(provider.name)
        if provider.local is not None and key is not None and (key.real or key.strike):
            logger.warning(
                "local provider %s has a key file in keys/: it is never sent (a local model "
                "gets no credential, and over http it would travel in clear), only struck",
                provider.name,
            )
    try:
        if lookup is None:
            found, now = resolve_all(providers, previous)
        else:
            found, now = resolve_all(providers, previous, lookup=lookup)
    except LocalModelError as error:
        raise ConfigError(f"[proxy] providers: {error}") from None
    if moved is not None:
        moved.update(now)
    return found


def providers_now(
    config: ServiceConfig,
    current: Providers | None = None,
    moved: dict[str, tuple[str, int]] | None = None,
) -> tuple[Providers, dict[str, tuple[str, str]]]:
    """The providers of ``[proxy]`` with the real keys ``<state_dir>/keys/`` holds NOW (T12e: the
    Settings page set, changed or removed one), and why those without one wait. A provider
    whose key was removed, or whose file cannot be used, waits for its key again: the proxy
    refuses its calls (``no_key``). The fake keys are the ones the service started with (the
    agent's, never changed). ConfigError only for a ``[proxy]`` the gate cannot use. The local
    providers are resolved again (T20); one that cannot be keeps its address in ``current``."""
    names = [p.name for p in config.proxy_settings().providers]
    reals = read_real_keys(config.keys_dir, names)
    keys = {
        name: ProviderKey(
            real=real,
            fake=config.provider_keys[name].fake,
            problem=problem,
            why=why,
            strike=read_strike_only(config.keys_dir, name) if problem == KEY_UNUSABLE else None,
        )
        for name, (real, problem, why) in reals.items()
        if name in config.provider_keys
    }
    now = dataclasses.replace(config, provider_keys=keys)
    previous = {
        p.name: p.upstream
        for p in (current.items if current is not None else ())
        if p.local and p.upstream is not None
    }
    return now.model_providers_and_problems(local_upstreams(config, previous, moved=moved))


class _Reloadable(Protocol):
    """What ``key_reloader`` needs of the Egress."""

    @property
    def policy(self) -> Policy: ...

    def reload(self, policy: Policy) -> bool: ...


def key_reloader(
    config: ServiceConfig, egress: _Reloadable, scrub: LiveScrub | None = None
) -> Callable[[], Applied]:
    """What the Settings page calls after it writes or removes a provider's key: the providers
    read again and handed to the running proxy (``Egress.reload``), no restart. A provider left
    without a usable key waits for it (``no_key``), never crashes the service. With ``scrub``
    (the process sensor's list of secrets) the new key is added to it and the removed one is
    dropped, before the proxy can use the new key.

    Only the providers change: the rest of the policy is the one the proxy has (nothing else is
    read again, not telegram.toml nor ``[gate]``: review of T09b, finding 1). If even that fails,
    or the sensor's list cannot take the new keys, it fails closed (``fail_closed``): every
    provider whose key is no longer the one in keys/ waits, the proxy's connection is replaced
    (first: nothing else may skip it) so it refuses until it has that config, and
    ReloadFailedClosed says so."""

    def reload() -> Applied:
        current = egress.policy
        try:
            moved: dict[str, tuple[str, int]] = {}
            providers, problems = providers_now(config, current.providers, moved)
            policy = dataclasses.replace(
                current, providers=providers, key_problems=problems, local_moved=moved
            )
            # The sensor strikes the new keys before the proxy can use them; if it cannot, the
            # proxy never gets them (review of 40dfd53, finding 2).
            _refresh(scrub, config, providers)
        except Exception as error:
            logger.error(
                "the providers' keys cannot be read again or struck (%s): the keys that "
                "changed are not used until the next reload", type(error).__name__,
            )  # fmt: skip
            policy = fail_closed(config, current)
            # The cut first: nothing here may skip it (review of 40dfd53, finding 2).
            applied = Applied.NOW if egress.reload(policy) else Applied.WHEN_UP
            try:
                _refresh(scrub, config, policy.providers)
            except Exception as refresh_error:  # the proxy has the cut already
                logger.error(
                    "the process sensor's list of secrets cannot be refreshed (%s): it keeps "
                    "the keys it had", type(refresh_error).__name__,
                )  # fmt: skip
            raise ReloadFailedClosed(applied) from error
        return Applied.NOW if egress.reload(policy) else Applied.WHEN_UP

    return reload


def _refresh(scrub: LiveScrub | None, config: ServiceConfig, providers: Providers) -> None:
    """The process sensor's list of secrets: the Gateway token and ``providers``' keys."""
    if scrub is not None:
        scrub.replace(known_secrets([*config.gateway_secrets(), *providers.known_secrets()]))


def fail_closed(config: ServiceConfig, current: Policy) -> Policy:
    """``current`` with every provider whose real key is not exactly the one in keys/ now (it was
    removed, replaced or cannot be read) waiting for its key: a failed reload never keeps a key
    the owner took away. The keys it stops using, and the new ones it does not take, are struck
    only from now on; a new key that reads well waits as ``KEY_NOT_APPLIED`` (not its file's
    fault). If keys/ cannot even be read, every provider waits. The keys struck only are capped
    (``_capped_strikes``). Never raises."""
    items = current.providers.items
    try:
        on_disk = read_real_keys(config.keys_dir, [p.name for p in items])
    except Exception:  # read_real_keys never raises; if it did, nothing is trusted
        logger.exception("keys/ cannot be read: every provider waits for its key")
        on_disk = {}
    problems = dict(current.key_problems)
    struck = list(current.providers.strike_only)
    kept = []
    for provider in items:
        real, problem, why = on_disk.get(provider.name, (None, KEY_NOT_APPLIED, "keys/ unread"))
        used = None if provider.real_key is None else provider.real_key.reveal()
        if real is not None and real.reveal() == used:
            kept.append(provider)  # unchanged: it keeps its key
            continue
        if used is None and real is None:
            kept.append(provider)  # it waited already, and there is nothing new to take
            continue
        if used is not None:
            struck.append(used)
        if real is not None:
            struck.append(real.reveal())  # the new key, never swapped in by this policy
        kept.append(dataclasses.replace(provider, real_key=None))
        problems[provider.name] = (
            problem or KEY_NOT_APPLIED,
            why
            or "its key changed and the new one could not be handed over: it is read "
            "again at the next reload",
        )
    fakes = [p.fake_key for p in items]
    reals = {p.real_key.reveal() for p in kept if p.real_key is not None}
    struck = [
        k
        for k in struck
        if len(k) >= MIN_KNOWN_SECRET and not holds_fake(k, fakes) and k not in reals
    ]
    try:
        providers = Providers(kept, strike_only=_capped_strikes(struck))
    except ValueError:  # cannot happen (fewer keys than before): then nothing is struck anew
        logger.exception("the keys that stopped being used cannot be struck")
        providers = Providers(kept, strike_only=current.providers.strike_only)
    return dataclasses.replace(current, providers=providers, key_problems=problems)


def _capped_strikes(struck: list[str]) -> list[str]:
    """``struck`` without repeats, cut to the most recent (its end) that fit in
    ``protocol.MAX_STRIKE_ONLY`` keys and ``protocol.STRIKE_ONLY_CHARS`` characters, so the
    proxy's config always fits in one line (review of 40dfd53, finding 4). What is dropped is
    logged by count, never by value."""
    newest_first = list(dict.fromkeys(reversed(struck)))
    kept: list[str] = []
    chars = 0
    for key in newest_first:
        if len(kept) == protocol.MAX_STRIKE_ONLY or chars + len(key) > protocol.STRIKE_ONLY_CHARS:
            break
        kept.append(key)
        chars += len(key)
    if len(kept) < len(newest_first):
        logger.error(
            "%d keys that stopped being used are no longer struck: only the %d most recent are "
            "kept (at most %d keys and %d characters)", len(newest_first) - len(kept), len(kept),
            protocol.MAX_STRIKE_ONLY, protocol.STRIKE_ONLY_CHARS,
        )  # fmt: skip
    return list(reversed(kept))


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


def spend_total_for(
    main: ServiceConfig, others: Sequence[ServiceConfig]
) -> InstallationSpend | None:
    """The total, if this installation has one: with other agents, and also if it had them and they
    were deleted (T26-6c). Going back to one agent's way would drop the caps set for the whole
    installation, and the main agent's ``budget.json`` says ``MAX_CAP_USD`` for what had no cap of
    its own: with no total above it, that is 100000 $. An installation that never had another agent
    has neither that file nor a deleted agent, and nothing changes for it."""
    if (
        others
        or os.path.lexists(main.installation_dir / STATE_BUDGET)
        or retired_agents(main.agents_dir)
    ):
        return build_spend_total(main, others)
    return None


def build_spend_total(main: ServiceConfig, others: Sequence[ServiceConfig]) -> InstallationSpend:
    """What every agent spends together (T26-2c): ``[budget]`` of ``backtide.toml`` is its cap, and
    the caps the main agent had set, the first time. A deleted agent is a member too: what it spent
    this month was spent (T26-6c). Not bound yet: its alerts are the main agent's, which needs this
    to be built."""
    try:
        ensure_state_folder(main.installation_dir, "the installation's black box folder")
    except ConfigError as error:  # as with its box, this stops no agent: its caps cannot change
        logger.error("the installation's folder cannot be used: %s", error)
    return InstallationSpend(
        main.budget_settings(),
        members={
            **{slug: main.agents_dir / slug for slug in retired_agents(main.agents_dir)},
            **{config.slug: config.agent_dir for config in (main, *others)},
        },
        folder=main.installation_dir,
        inherit_from=main.agent_dir,
    )


def reload_everyones_keys(
    main: Callable[[], Applied], others: Callable[[], Sequence[Callable[[], Applied]]]
) -> Callable[[], Applied]:
    """What the Settings page calls with several agents: the keys are the machine's, so each
    agent's proxy gets them. All are tried: one that fails closed never leaves another with a key
    the owner took away. ``NOW`` only if every proxy has it; a failure, whichever, is told."""

    def reload() -> Applied:
        applied: list[Applied] = []
        failed = False
        for each in (main, *others()):
            try:
                applied.append(each())
            except ReloadFailedClosed as error:
                failed = True
                applied.append(error.applied)
            except Exception:  # key_reloader handles its own: this is a bug, and it is told
                logger.exception("an agent's proxy could not be handed the keys")
                failed = True
                applied.append(Applied.WHEN_UP)
        result = Applied.NOW if all(a is Applied.NOW for a in applied) else Applied.WHEN_UP
        if failed:
            raise ReloadFailedClosed(result)
        return result

    return reload


class _OnTheRoster:
    """Orders about a neighbour reach it while its ``Guardian`` is up: as the main agent's socket,
    this is what ``Guardian.run`` starts once it is up and closes before it stops (T26-2c)."""

    def __init__(self, roster: Roster, desk: Desk, up: Callable[[], None] = lambda: None) -> None:
        self._roster, self._desk, self._up = roster, desk, up

    def start(self) -> None:
        self._roster.publish(self._desk)
        self._up()

    def close(self) -> None:
        self._roster.retire(self._desk.slug)


class _Neighbours:
    """The agents other than the main one, each with its Guardian on a thread of its own."""

    def __init__(
        self,
        main: ServiceConfig,
        others: Sequence[ServiceConfig],
        *,
        notifier_for: Callable[[str], Notifier],
        stop: threading.Event,
        share: SensorShare | None,
        told: AlertSink,
        build: Callable[..., tuple[Guardian, AlertQueue, BlackBox]] | None = None,
        run: Callable[..., None] | None = None,
        roster: Roster | None = None,
        spend_total: SharedSpend | None = None,
        telegram: TelegramNeighbours | None = None,
        web_group: int | None = None,
        prepare: Callable[[ServiceConfig], None] | None = None,
        stop_alive: Callable[[ServiceConfig], bool] | None = None,
    ) -> None:
        self._stop_alive = stop_alive if stop_alive is not None else stop_unwatched
        self._roster = roster
        self._telegram = telegram
        self._spend_total = spend_total
        self._web_group = web_group
        self._main = main
        self._others = {config.slug: config for config in others}
        self._notifier_for = notifier_for
        self._stop = stop
        self._share = share
        self._told = told
        self._build = build if build is not None else build_guardian
        self._run_guardian = run if run is not None else run_guardian
        self._prepare = prepare if prepare is not None else ensure_on_disk
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._stops: dict[str, threading.Event] = {}
        self._settled: dict[str, threading.Event] = {}
        self._failures: dict[str, str] = {}
        self._reloads: dict[str, list[Callable[[], Applied]]] = {}
        self._guardians: dict[str, Guardian] = {}
        self._newcomers: list[tuple[str, tuple[Protected, ...]]] = []

    def reloads(self) -> list[Callable[[], Applied]]:
        """Who to hand new keys to: the proxies of the agents up so far."""
        with self._lock:
            return [reload for each in self._reloads.values() for reload in each]

    def start(self) -> None:
        threading.Thread(
            target=self._pass_on_the_stop, name="backtide-agents-stop", daemon=True
        ).start()
        for config in self._others.values():
            if is_stopped(config):
                logger.info("the agent %s stays stopped, as its owner left it", config.slug)
                self.halt(config)  # the mark is what was asked: Docker says whether it holds
            else:
                self.start_one(config)

    def _pass_on_the_stop(self) -> None:
        """The service stops: so does each of them, at once with the others."""
        self._stop.wait()
        with self._lock:
            stops = list(self._stops.values())
        for stop in stops:
            stop.set()

    def add(self, config: ServiceConfig) -> None:
        """It exists now, running or not: also for the bot."""
        with self._lock:
            self._others[config.slug] = config
        if self._telegram is not None:
            self._telegram.add(config)

    def config_of(self, slug: str) -> ServiceConfig | None:
        with self._lock:
            return self._others.get(slug)

    def start_one(self, config: ServiceConfig) -> None:
        """A thread for this agent, with a stop of its own. ``wait_settled`` tells its start."""
        thread = threading.Thread(
            target=self._watch, args=(config,), name=f"backtide-agent-{config.slug}"
        )
        self.add(config)
        with self._lock:
            self._failures.pop(config.slug, None)
            self._stops[config.slug] = threading.Event()
            self._settled[config.slug] = threading.Event()
            self._threads[config.slug] = thread
            if self._stop.is_set():  # the service is already going: this one goes too
                self._stops[config.slug].set()
        thread.start()

    def halt(self, config: ServiceConfig) -> bool:
        """Nothing of this agent runs with no Guardian: what does is stopped and told. True once
        Docker says so. Only for an agent whose thread is not running. Never raises."""
        slug = config.slug
        try:
            found = self._stop_alive(config)
        except Exception as error:  # the worst case: it runs, unrecorded, and it is said
            logger.exception("the agent %s runs with nobody watching it", slug, extra=ALREADY_TOLD)
            text = str(redact(f"{type(error).__name__}: {error}"))[:_FAILED_AGENT_CHARS]
            _record_in_installation(
                self._main, self._told, "agent_stop_failed", slug,
                {"reason": "unsupervised", "error": text}, risk=3,
            )  # fmt: skip
            self._told.submit(
                Alert(
                    AlertLevel.ERROR,
                    f"El agente {slug} sigue en marcha sin vigilancia",
                    f"No se ha podido parar: {text}. Para intentarlo otra vez: "
                    f"`sudo backtide agentes parar {slug}`.",
                    agent=slug,
                )
            )
            return False
        if found:
            logger.error(
                "the agent %s was running with nobody watching it: stopped",
                slug,
                extra=ALREADY_TOLD,
            )
            _record_in_installation(
                self._main, self._told, "agent_stop", slug, {"reason": "unsupervised"}, risk=2
            )
            self._told.submit(
                Alert(
                    AlertLevel.ERROR,
                    f"El agente {slug} corría sin vigilancia",
                    "Lo que corría sin grabarse se ha parado. Mira su caja negra antes de "
                    "arrancarlo.",
                    agent=slug,
                )
            )
        return True

    def forget(self, slug: str) -> None:
        """This agent was deleted (T26-6c) and its thread has ended: nothing of it stays here for
        whoever comes back with that name."""
        with self._lock:
            self._others.pop(slug, None)
            self._threads.pop(slug, None)
            self._stops.pop(slug, None)
            self._settled.pop(slug, None)
            self._failures.pop(slug, None)
            self._reloads.pop(slug, None)
            self._guardians.pop(slug, None)
            self._newcomers = [item for item in self._newcomers if item[0] != slug]
        if self._telegram is not None:  # also what an alert about it issued since its thread ended
            self._telegram.forget(slug)

    def wait_settled(self, slug: str, timeout: float) -> None:
        """Until the agent is up, or its thread ended. See ``failure_of`` and the roster."""
        with self._lock:
            settled = self._settled.get(slug)
        if settled is not None:
            settled.wait(timeout)

    def is_running(self, slug: str) -> bool:
        """Whether its thread is alive: whatever it is doing, its Guardian answers for it."""
        with self._lock:
            thread = self._threads.get(slug)
        return thread is not None and thread.is_alive()

    def failure_of(self, slug: str) -> str | None:
        with self._lock:
            return self._failures.get(slug)

    def stop_one(self, slug: str, requested_by: str = "") -> None:
        """This agent alone stops, as the service would stop it: what it holds ends, its proxy
        goes, and Tetragon stays while others use it. Waits for it."""
        with self._lock:
            stop, thread, guardian = (
                self._stops.get(slug), self._threads.get(slug), self._guardians.get(slug)
            )  # fmt: skip
        try:
            if guardian is not None:
                with scope.working_for(slug):
                    guardian.owner_order("agent_stop_asked", {"requested_by": requested_by})
        except Exception:  # noting it never gets in the way of stopping
            logger.exception("the stop of the agent %s could not be noted in its box", slug)
        finally:
            if stop is not None:
                stop.set()
        if thread is not None:
            thread.join(NEIGHBOURS_STOP)
            if thread.is_alive():
                logger.error("%s did not stop in %s s", thread.name, NEIGHBOURS_STOP)

    def protect_also(self, slug: str, items: tuple[Protected, ...]) -> None:
        """The agent ``slug`` is new: no jail here may show what is its. Also those that are still
        being built, which read the installation before it existed."""
        with self._lock:
            self._newcomers.append((slug, items))
            guardians = dict(self._guardians)
        for guardian in guardians.values():
            guardian.protect_also(items)

    def join(self, timeout: float = NEIGHBOURS_STOP) -> None:
        """They were told to stop (``stop``): each stops its own agent, at once with the others."""
        deadline = time.monotonic() + timeout
        with self._lock:
            threads = list(self._threads.values())
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                logger.error("%s did not stop in %s s", thread.name, timeout)

    def _watch(self, config: ServiceConfig) -> None:
        """One agent's whole watch. What goes wrong in it stays in it."""
        scope.enter(config.slug)
        with self._lock:
            stop, settled = self._stops[config.slug], self._settled[config.slug]
        try:
            self._serve_one(config, stop, settled)
        except Exception as error:  # the Guardian already stopped its agent, or said it could not
            logger.exception("the agent %s is not being watched", config.slug, extra=ALREADY_TOLD)
            with self._lock:
                self._failures[config.slug] = str(redact(f"{error}"))[:_FAILED_AGENT_CHARS]
            record_agent_failed(self._main, self._told, config.slug, error)
        finally:
            with self._lock:
                self._reloads.pop(config.slug, None)
                self._guardians.pop(config.slug, None)
            side = None if self._telegram is None else self._telegram.get(config.slug)
            if side is not None:  # what its last alerts issued as they went out, after its watch
                side.ended()
            settled.set()

    def _serve_one(
        self, config: ServiceConfig, stop: threading.Event, settled: threading.Event
    ) -> None:
        try:
            self._prepare(config)  # its volume and its channel: also after a reboot
        except Exception:
            self.halt(config)  # no Guardian is coming to stop what a killed service left
            raise
        if self._web_group is not None:
            share_box_with_web(config, self._web_group)
        built: list[Egress] = []
        secrets = LiveScrub()
        telegram = None if self._telegram is None else self._telegram.get(config.slug)
        guardian, alerts, box = self._build(
            config,
            notifier=self._notifier_for(config.slug),
            hold_watch=None if telegram is None else telegram.desk,
            on_egress=built.append,
            scrub=secrets,
            sensor=self._share is not None,
            sensor_share=self._share,
            log_filter=scope.belongs_to(config.slug),
            spend_total=self._spend_total,
        )
        with self._lock:
            self._reloads[config.slug] = [key_reloader(config, egress, secrets) for egress in built]
            self._guardians[config.slug] = guardian
            newcomers = [items for slug, items in self._newcomers if slug != config.slug]
        for items in newcomers:  # read before it existed; one read after it says the same
            missing = tuple(item for item in items if item not in config.agent_protected())
            if missing:
                guardian.protect_also(missing)
        control: ControlHook | None = None
        if self._roster is not None:
            desk = _desk_of(config, guardian, built)
            control = _OnTheRoster(self._roster, desk, up=settled.set)
            if telegram is not None:
                # Off the bot before it goes off the roster, which waits for what is in flight.
                watch = telegram.watch(
                    guardian,
                    box,
                    SnapshotStore(config.volume),
                    budget=desk.budget,
                    waiting=desk.waiting,
                )
                control = Hooks(control, watch)
        self._run_guardian(guardian, alerts, box, stop=stop, handle_signals=False, control=control)


class _OfNobody:
    """Hooks that are the machine's, not the main agent's, though ``Guardian.run`` starts them on
    its thread: the sockets, the bot, the trash. What they start and log is nobody's (``scope``)."""

    def __init__(self, hook: ControlHook) -> None:
        self._hook = hook

    def start(self) -> None:
        with scope.working_for(None):
            self._hook.start()

    def close(self) -> None:
        with scope.working_for(None):
            self._hook.close()


class _Runnable(Protocol):
    def run(self, stop: threading.Event, **options: ControlHook) -> None: ...


class _Closable(Protocol):
    def close(self) -> object: ...


class _Startable(_Closable, Protocol):
    def start(self) -> None: ...


def _desk_of(
    config: ServiceConfig,
    guardian: Guardian,
    built: Sequence[Egress],
    store: SnapshotStore | None = None,
) -> Desk:
    """What the sockets act on for this agent."""
    egress = built[0] if built else None
    listing = store if store is not None else SnapshotStore(config.volume)
    return Desk(
        config.slug,
        guardian,
        budget=None if egress is None else egress.budget,
        waiting=None if egress is None else egress.waiting,
        snapshots=lambda: listing.snapshots(),
        name=config.display_name,
        notice=config.agent_profile.rewind_notice_lines,
    )


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


def web_passkeys_of(config: ServiceConfig) -> Passkeys:
    """The web's passkeys: for its domain if it is behind one (T26-4a), else for the tunnel's
    name, ``backtide.localhost``."""
    origin = config.web_public_origin()
    if origin is None:
        return Passkeys(config.state_dir, origins=[origin_for(WEB_PORT)])
    return Passkeys(config.state_dir, origins=[origin.url], rp_id=origin.name)


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
    hold_timings: HoldTimings | None = None,
    web_group: int | None = None,
    web_user: int | None = None,
    others: Sequence[ServiceConfig] = (),
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
    file is a ConfigError, before anything starts.

    With ``web_group`` (`--grupo-web`, T12c) the web's narrow socket (``config.web_socket``)
    opens too, right after the control socket, for that group only (and, with ``web_user``,
    that user only).

    With ``others`` (T26-2b) those agents run too, each on its own thread, and this one holds
    the sockets and the bot. An order on a socket says which agent it is about (T26-2c), and what
    they spend together has a cap of its own. Each one's alerts say whose."""
    settings = load_telegram(config.state_dir)
    with take_lock(config.lock_file):
        telegram = telegram_parts(config, settings, others) if settings is not None else None
        if telegram is not None:
            notifier = FanOut(notifier or LogNotifier(), telegram.notifier)
        stop = stop if stop is not None else threading.Event()
        share: SensorShare | None = None
        log_filter = None
        log_nobodys = None
        neighbours: _Neighbours | None = None
        spend_total = spend_total_for(config, others)
        if others:
            scope.hand_down()  # before any thread of an agent starts
            log_filter = scope.belongs_to(config.slug, and_nobodys=True)
            log_nobodys = scope.is_nobodys
            share = SensorShare() if sensor else None
            machine_notifier = notifier if notifier is not None else LogNotifier()
            one_at_a_time = threading.Lock()

            def notifier_for(slug: str) -> Notifier:
                return Labelled(machine_notifier, slug, one_at_a_time)

            notifier = notifier_for(config.slug)
        built: list[Egress] = []
        sensor_secrets = LiveScrub()
        # With others this thread is nobody's but for the main agent's Guardian and what it starts:
        # what forgets to say whose it is gets no button (``scope``).
        main_scope = config.slug if others else None
        with scope.working_for(main_scope):
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
                hold_timings=hold_timings,
                on_egress=built.append,
                scrub=sensor_secrets,
                hold_watch=None if telegram is None else telegram.desk,
                sensor_share=share,
                log_filter=log_filter,
                log_nobodys=log_nobodys,
                spend_total=spend_total,
            )
        # The Settings page (T12e): `backtide web --ajustes` asks through this same socket.
        (egress,) = built
        reload_keys = key_reloader(config, egress, sensor_secrets)
        # Which agent an order is about: this one, unless it says another (T26-2c).
        roster = Roster(
            _desk_of(config, guardian, built, store),
            [(other.slug, other.display_name) for other in others],
            [other.slug for other in others if is_stopped(other)],
        )

        def record_total(
            action: str, target: str, details: dict[str, object], **options: Any
        ) -> bool:
            return _record_in_installation(config, alerts, action, target, details, **options)

        if spend_total is not None:
            spend_total.bind(record=record_total, alert=alerts.submit)
        if others:
            neighbours = _Neighbours(
                config,
                others,
                notifier_for=notifier_for,
                stop=stop,
                share=share,
                told=alerts,
                roster=roster,
                spend_total=spend_total,
                telegram=None if telegram is None else telegram.neighbours,
                web_group=web_group,
            )
            reload_keys = reload_everyones_keys(reload_keys, neighbours.reloads)
        # Creating, starting and stopping the others (T26-6a): on root's socket only.
        fleet = None
        if config.config_file is not None:

            def first_event(new: ServiceConfig, details: dict[str, Any]) -> None:
                with open_black_box(new) as new_box:
                    new_box.append("system", "agent_created", new.slug, details=details, risk=1)

            fleet = Fleet(
                config,
                config.config_file,
                roster=roster,
                neighbours=neighbours,
                stop=stop,
                told=alerts,
                record=record_total,
                first_event=first_event,
                protect_main=guardian.protect_also,
                open_box=open_black_box,
                stop_alive=stop_unwatched,
                add_to_total=None if spend_total is None else spend_total.add_member,
                whole_caps=None if spend_total is None else spend_total.caps,
            )
        settings_service = Settings(
            config.state_dir,
            record=box.append,
            reload_keys=reload_keys,
            in_use=[p.name for p in config.proxy_settings().providers],
            waiting=egress.waiting,
        )
        # The spending cap (T11): `backtide web` reads it and changes it through the socket too,
        # and, next to it, which providers wait for their key (the panel).
        # The web's sign-in (T26-3a): only with an installed web; root's socket gives the
        # one-time link (`sudo backtide enlace`) and the web's narrow socket opens and checks
        # the sessions, in this process's memory alone.
        web_sessions = config.web_sessions() if web_group is not None else None
        # The web's password (T26-3b-1): checked by the narrow socket, set by root's.
        web_password = Checker(config.state_dir) if web_group is not None else None
        # Its passkeys (T26-3b-2): registered from a session, for the web's own origin.
        web_passkeys = web_passkeys_of(config) if web_group is not None else None
        # Behind a domain the password stops at the service too (D40, T26-4a): the narrow socket
        # does not check any, so a web taken over cannot try them. Root can still set it.
        web_checks = None if config.web_public_origin() is not None else web_password
        control: ControlHook = ControlServer(
            guardian,
            config.control_socket,
            settings=settings_service,
            budget=egress.budget,
            waiting=egress.waiting,
            sessions=web_sessions,
            on_entry=guardian.web_access,
            password=web_password,
            passkeys=web_passkeys,
            roster=roster,
            whole_budget=spend_total,
            fleet=fleet,
        )
        if web_group is not None:
            listing = store if store is not None else SnapshotStore(config.volume)
            control = Hooks(
                control,
                WebControlServer(
                    guardian,
                    config.web_socket,
                    group=web_group,
                    user=web_user,
                    snapshots=listing.snapshots,
                    settings=settings_service,
                    budget=egress.budget,
                    waiting=egress.waiting,
                    sessions=web_sessions,
                    on_entry=guardian.web_access,
                    password=web_checks,
                    passkeys=web_passkeys,
                    roster=roster,
                    whole_budget=spend_total,
                ),
            )
        if telegram is not None:
            snapshots = store if store is not None else SnapshotStore(config.volume)
            telegram.actions.bind(
                guardian, box, snapshots, budget=egress.budget, waiting=egress.waiting
            )
            control = Hooks(control, telegram.bot)
        if fleet is not None:
            control = Hooks(control, TrashWatch(fleet))
        if others:
            control = _OfNobody(control)
        record_installation_start(config, alerts, others)
        if fleet is not None:
            fleet.finish_interrupted()
        if neighbours is not None:
            neighbours.start()
        try:
            with scope.working_for(main_scope):
                run_guardian(
                    guardian, alerts, box, stop=stop, handle_signals=handle_signals, control=control
                )
        finally:
            if neighbours is not None:
                stop.set()  # the main agent is gone, and with it the way to ask for anything
                neighbours.join()
