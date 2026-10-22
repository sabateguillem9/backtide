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

import dataclasses
import errno
import fcntl
import logging
import os
import signal
import stat
import threading
from collections.abc import Callable, Mapping
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
from backtide.blackbox.redact import MIN_KNOWN_SECRET
from backtide.gate import protocol
from backtide.gate.providers import Providers
from backtide.gate.translate.base import MAIL_TRANSLATORS
from backtide.jail import AgentJail, JailError, ca
from backtide.jail.proxy import ProxyJail
from backtide.jail.sensor import SensorJail, SensorJailConfig
from backtide.notify import AlertQueue, FanOut, LogNotifier, Notifier
from backtide.sensors.files import FileWatcher, WatcherConfig
from backtide.sensors.scrub import LiveScrub
from backtide.sensors.tetragon import TetragonReader
from backtide.service.bot import Hooks, telegram_parts
from backtide.service.config import (
    KEY_UNUSABLE,
    ConfigError,
    ProviderKey,
    ServiceConfig,
    holds_fake,
    read_real_keys,
    read_strike_only,
)
from backtide.service.control import ControlServer
from backtide.service.egress import Egress
from backtide.service.guardian import ControlHook, Guardian, SpaceGate, halt_agent
from backtide.service.holds import HoldTimings, HoldWatch
from backtide.service.local_models import LocalModelError, Lookup, ollama_version, resolve_all
from backtide.service.pause import Holder, make_space_gate, read_holders
from backtide.service.price_update import PriceUpdater
from backtide.service.process_sensor import ProcessSensor, SnapshotBefore, recorded_keys
from backtide.service.proxy_channel import KEY_NOT_APPLIED, Policy, known_secrets
from backtide.service.settings import Applied, ReloadFailedClosed, Settings
from backtide.service.spend import Budget
from backtide.service.telegram_config import load_telegram
from backtide.service.trust import TrustStore
from backtide.snapshots import SnapshotStore, utc_now
from backtide.snapshots.grow import NOT_CONFIGURED, GrowLimits, VolumeGrower

logger = logging.getLogger(__name__)

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
    hold_timings: HoldTimings | None = None,
    on_egress: Callable[[Egress], None] | None = None,
    scrub: LiveScrub | None = None,
    hold_watch: HoldWatch | None = None,
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
    filled here and kept by ``serve`` to refresh it when a key changes."""
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
        build_sensor(config, jail, rated_box, store, jail_config=sensor_jail, scrub=scrub)
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
) -> Egress:
    """The egress proxy of ``config`` (docs/21, section 9): its container, and what backtide lets
    out through it, the allowed hosts of ``[proxy]`` and the model providers' hosts. The channel
    hands the proxy each provider's real and fake key (in memory only: the ``config`` message,
    T06-5), records through the rules (``box``) and strikes the Gateway token too. Constructed
    only: the Guardian starts it. ConfigError for an allowed host the gate cannot use."""
    proxy = proxy if proxy is not None else ProxyJail(config.proxy_jail_config())
    providers, problems = config.model_providers_and_problems(local_upstreams(config))
    policy = egress_policy(config, providers, problems)
    if timings is None:
        timings = config.gate_settings().timings  # [gate] wait_s, hold_s, preapproval_s
    # The recipients trusted from the web (T10-5, decision 9): <state_dir>/trusted.json, read
    # once here; a file that cannot be used gives no trust (logged).
    trust = TrustStore(config.state_dir)
    trust.load()
    budget, prices = build_budget(config, box, alerts)
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
    )


def build_budget(
    config: ServiceConfig, box: AssessedBlackBox, alerts: AlertQueue | None
) -> tuple[Budget, PriceUpdater]:
    """The spending cap of ``[budget]`` (T11, docs/33) and, unless ``auto_prices = false``, the
    updater of its prices (Anthropic's page, from the service: never through the agent's proxy).
    Constructed only: the Egress opens the budget and starts the updater at its first start."""
    settings = config.budget_settings()
    budget = Budget(
        settings,
        state_dir=config.state_dir,
        record=box.append,
        alert=None if alerts is None else alerts.submit,
        history=box.events,
    )
    # With auto_prices = false it only loads the last good table fetched before (no thread).
    prices = PriceUpdater(
        budget,
        state_dir=config.state_dir,
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
    hold_timings: HoldTimings | None = None,
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
        built: list[Egress] = []
        sensor_secrets = LiveScrub()
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
        )
        # The Settings page (T12e): `backtide web --ajustes` asks through this same socket.
        (egress,) = built
        settings_service = Settings(
            config.state_dir,
            record=box.append,
            reload_keys=key_reloader(config, egress, sensor_secrets),
            in_use=[p.name for p in config.proxy_settings().providers],
            waiting=egress.waiting,
        )
        # The spending cap (T11): `backtide web` reads it and changes it through the socket too,
        # and, next to it, which providers wait for their key (the panel).
        control: ControlHook = ControlServer(
            guardian,
            config.control_socket,
            settings=settings_service,
            budget=egress.budget,
            waiting=egress.waiting,
        )
        if telegram is not None:
            snapshots = store if store is not None else SnapshotStore(config.volume)
            telegram.actions.bind(
                guardian, box, snapshots, budget=egress.budget, waiting=egress.waiting
            )
            control = Hooks(control, telegram.bot)
        run_guardian(
            guardian, alerts, box, stop=stop, handle_signals=handle_signals, control=control
        )
