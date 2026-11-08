"""What the Telegram bot can make the service do (T09): the ``BotActions`` of
``backtide.notify.telegram`` over the Guardian, the black box, the snapshot store and the control
socket. Built in ``runner.serve`` when ``<state_dir>/telegram.toml`` exists.

- ``pause`` calls ``Guardian.pause_by_user`` directly: it must freeze at once, and it never
  waits for ``agent_lock``. ``resume`` calls ``Guardian.resume`` (the same as `backtide seguir`).
- ``rewind`` goes through the control socket, ``via: "telegram"``, like `backtide rebobinar` and
  the web: one door for every rewind, which records who asked (with the kernel's uid and pid).
- ``target_for`` offers, for the alert about an event, the newest snapshot taken before that
  event: rewinding to it undoes what the event is about.
- ``record`` writes ``system/<action>`` to the black box (it redacts); if that fails it is
  logged at ERROR, which the log bridge turns into an alert.
- The held requests (T10-4, ``backtide.notify.hold_notice``): ``decide`` goes through the
  control socket, ``via: "telegram"``, like `backtide aprobar` (the socket checks that only the
  service itself claims ``telegram``); a batch, ``batches`` and ``end_batch`` go to the Guardian,
  which refuses them while the agent is paused or rewound; ``held_details`` reads the
  ``gate/held`` of a hold back from the black box ("Ver").
- Every text goes out redacted; none quotes the agent.
- With several agents (T26-2e; docs/47, section 6.10) each one has its ``GuardianActions`` and its
  ``HoldDesk``, so a button can only reach the agent whose desk it came from. What goes through the
  control socket carries its ``agent`` (the main one's is byte for byte as always), and the socket
  is the machine's, the main config's. A neighbour's side is bound while its ``Guardian`` is up
  (``NeighbourWatch``); before and after, it says it is not being watched. It goes on the table when
  it is created or recovered and off it when it is deleted (``TelegramNeighbours``), with the
  service running.
"""

import logging
import os
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import BlackBox, BlackBoxError, redact
from backtide.jail.profiles import DEFAULT_PROFILE
from backtide.notify.buttons import ButtonBook
from backtide.notify.hold_notice import HoldDesk
from backtide.notify.telegram import AgentSide, AgentTable, TelegramBot, TelegramNotifier
from backtide.notify.telegram_api import BotApi
from backtide.service import scope
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_decide,
    ask_rewind,
)
from backtide.service.holds import BatchOutcome
from backtide.service.notice import ago, rewind_notice
from backtide.service.pause import PauseOutcome, ResumeOutcome
from backtide.service.telegram_config import TelegramSettings
from backtide.snapshots import Snapshot, SnapshotError

logger = logging.getLogger(__name__)

REQUESTER = "telegram"
STATE_NAMES = {
    "running": "en marcha",
    "starting": "arrancando",
    "stopping": "parándose",
    "stopped": "parado",
    "frozen": "congelado",
}
REASON_NAMES = {
    "user": "la has pedido tú (/pausar)",
    "space": "falta espacio",
    "rewind_no_space": "un rebobinado se quedó sin espacio",
    "blackbox": "la caja negra no graba",
    "late": "el hilo de espacio llegó tarde (no se quita sola)",
}
# A late pause the space thread will still lift by itself (``Guardian.late_pause_lifts``).
LATE_LIFTS = "el hilo de espacio llegó tarde (sigue solo en cuanto vuelva a comprobar)"
REWIND_WAIT = 10.0  # seconds to wait for the control socket (the service is up: it is ours)
STARTING = "backtide está arrancando: prueba otra vez en unos segundos."
NOT_WATCHED = (
    "El agente {slug} no se está vigilando ahora mismo (no ha arrancado, ha fallado o se está "
    "parando): no se ha hecho nada."
)


class _Guardian(Protocol):
    @property
    def agent_state(self) -> Any: ...

    @property
    def pause_reasons(self) -> frozenset[str]: ...

    @property
    def late_pause_lifts(self) -> bool: ...

    def pause_by_user(self, *, requested_by: str) -> PauseOutcome: ...

    def user_pause_mark(self) -> int: ...

    def resume(self, *, requested_by: str, pause_mark: int | None = None) -> ResumeOutcome: ...

    def pending_holds(self) -> list[dict[str, Any]]: ...

    def create_batch(
        self, hold_id: str, kind: str, *, via: str, requested_by: str
    ) -> BatchOutcome: ...

    def batches(self) -> list[dict[str, Any]]: ...

    def end_batch(self, rule_id: str, *, via: str) -> bool: ...


class _Snapshots(Protocol):
    def snapshots(self) -> list[Snapshot]: ...


AskRewind = Callable[..., dict[str, Any]]
AskDecide = Callable[..., dict[str, Any]]


class GuardianActions:
    """``BotActions`` for a running service. ``bind`` hands it the Guardian once it exists
    (the alert queue, and so the notifier, is built before it); until then every action says
    that backtide is starting. ``agent``: the neighbour this one acts on (T26-2e), whose name the
    control socket gets, and who may stop being watched (``unbind``); None is the main agent."""

    def __init__(
        self,
        control_socket: Path,
        *,
        ask: AskRewind = ask_rewind,
        ask_decision: AskDecide = ask_decide,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        tz: tzinfo | None = None,
        agent_lines: Sequence[str] = DEFAULT_PROFILE.rewind_notice_lines,
        agent: str | None = None,
    ) -> None:
        self._socket = control_socket
        self._agent = agent
        self._about = {} if agent is None else {"agent": agent}
        self._agent_lines = tuple(agent_lines)  # the profile's lines of the rewind notice
        self._ask = ask
        self._ask_decision = ask_decision
        self._now = now
        self._tz = tz if tz is not None else (datetime.now().astimezone().tzinfo or UTC)
        self._guardian: _Guardian | None = None
        self._box: BlackBox | None = None
        self._store: _Snapshots | None = None
        self._budget: Any = None
        self._waiting: Callable[[], Mapping[str, str]] | None = None

    def bind(
        self,
        guardian: _Guardian,
        box: BlackBox,
        store: _Snapshots,
        *,
        budget: Any = None,
        waiting: Callable[[], Mapping[str, str]] | None = None,
    ) -> None:
        """``budget``: the spending cap (T11, ``spend.Budget``), for ``/estado``; ``waiting``: the
        providers that wait for their key (``Egress.waiting``)."""
        self._guardian, self._box, self._store = guardian, box, store
        self._budget = budget
        self._waiting = waiting

    def unbind(self) -> None:
        """Its Guardian is about to stop, and its black box to close."""
        self._guardian, self._box, self._store = None, None, None
        self._budget, self._waiting = None, None

    def _not_up(self, starting: str = STARTING) -> str:
        return starting if self._agent is None else redact(NOT_WATCHED.format(slug=self._agent))

    # BotActions

    def pause(self) -> str:
        guardian = self._guardian
        if guardian is None:
            return self._not_up()
        return redact(guardian.pause_by_user(requested_by=REQUESTER).message)

    def pause_mark(self) -> int | None:
        guardian = self._guardian
        return None if guardian is None else guardian.user_pause_mark()

    def resume(self, pause_mark: int | None) -> str:
        guardian = self._guardian
        if guardian is None:
            return self._not_up()
        outcome = guardian.resume(requested_by=REQUESTER, pause_mark=pause_mark)
        return redact(outcome.message)

    def status(self) -> str:
        guardian = self._guardian
        if guardian is None:
            return self._not_up("backtide está arrancando.")
        state = str(guardian.agent_state)
        lines = [f"Agente: {STATE_NAMES.get(state, state)}."]
        reasons = sorted(guardian.pause_reasons)
        if reasons:
            lifts = guardian.late_pause_lifts
            names = ", ".join(
                LATE_LIFTS if reason == "late" and lifts else REASON_NAMES.get(reason, reason)
                for reason in reasons
            )
            lines.append(f"En pausa: {names}. /seguir lo reanuda.")
        snapshots = self._snapshots()
        if snapshots:
            newest = snapshots[-1]
            when = newest.taken_at.astimezone(self._tz).strftime("%H:%M:%S del %Y-%m-%d")
            lines.append(
                f"Última instantánea: {when} ({ago(self._now() - newest.taken_at)}); "
                f"hay {len(snapshots)}."
            )
        else:
            lines.append("No hay instantáneas (o no se pueden leer).")
        holds, batches = len(guardian.pending_holds()), len(guardian.batches())
        lines.append(f"Peticiones retenidas: {holds} (/retenidas). Lotes activos: {batches} "
                     "(/lotes).")  # fmt: skip
        budget, waiting_for = self._budget, self._waiting
        if budget is not None:
            try:
                lines.extend(budget.lines())
            except Exception:
                logger.exception("the spending could not be read for /estado")
                lines.append("Gasto: no se ha podido leer.")
        if waiting_for is not None:
            try:
                waiting = sorted(waiting_for())
            except Exception:
                logger.exception("the providers waiting for their key could not be read")
                waiting = []
            if waiting:
                lines.append(
                    f"Sin clave: {', '.join(waiting)}. El agente no puede usar el modelo hasta "
                    "que la pongas en Ajustes."
                )
        return "\n".join(lines)

    def rewind(self, snapshot_id: str) -> str:
        try:
            reply = self._ask(
                self._socket, snapshot_id, via=REQUESTER, wait=REWIND_WAIT, **self._about
            )
        except ControlUnavailable:
            return "El servicio no contesta en su socket de control: no se ha rebobinado nada."
        except ControlOutcomeUnknown as error:
            return redact(str(error))
        except ControlError as error:
            return redact(f"No se ha podido pedir el rebobinado: {error}")
        text = reply["message"]
        if reply.get("undo"):
            text += f"\nPunto para deshacer el rebobinado: {reply['undo']}"
        return redact(text)

    def notice(self, snapshot_id: str) -> str | None:
        target = Snapshot.parse(snapshot_id) if isinstance(snapshot_id, str) else None
        if target is None or not any(snap.id == target.id for snap in self._snapshots()):
            return None
        paragraphs = rewind_notice(
            target.taken_at, now=self._now(), tz=self._tz, agent_lines=self._agent_lines
        )
        return "\n\n".join(paragraphs)

    def target_for(self, event_seq: int) -> str | None:
        box = self._box
        if box is None:
            return None
        try:
            found = box.events(since_seq=event_seq - 1, limit=1) if event_seq >= 1 else []
        except BlackBoxError as error:
            logger.warning("cannot read the event of an alert to offer a rewind: %s", error)
            return None
        if not found or found[0].seq != event_seq:
            return None
        moment = _parse_ts(found[0].ts)
        if moment is None:
            return None
        before = [snap for snap in self._snapshots() if snap.taken_at <= moment]
        return before[-1].id if before else None

    # HoldActions (T10-4)

    def decide(self, hold_id: str, verdict: str) -> tuple[str, str]:
        try:
            reply = self._ask_decision(
                self._socket, hold_id, verdict, via=REQUESTER, wait=REWIND_WAIT, **self._about
            )
        except ControlUnavailable:
            return "failed", "El servicio no contesta en su socket de control: no se ha decidido."
        except ControlOutcomeUnknown as error:
            return "failed", redact(str(error))
        except (ControlError, ValueError) as error:
            return "failed", redact(f"No se ha podido pedir la decisión: {error}")
        return str(reply["outcome"]), redact(str(reply["message"]))

    def create_batch(self, hold_id: str, kind: str) -> tuple[str, str]:
        guardian = self._guardian
        if guardian is None:
            return "failed", self._not_up()
        requested_by = f"{REQUESTER} (el bot, pid {os.getpid()})"
        try:
            outcome = guardian.create_batch(hold_id, kind, via=REQUESTER, requested_by=requested_by)
        except ValueError:
            return "failed", "Ese lote no existe."
        return str(outcome.status), redact(outcome.message)

    def end_batch(self, rule_id: str) -> str:
        guardian = self._guardian
        if guardian is None:
            return self._not_up()
        if guardian.end_batch(rule_id, via=REQUESTER):
            return "Lote revocado: lo que cubría vuelve a preguntar."
        return "Ese lote ya no está activo (caducó, se revocó o backtide se reinició)."

    def batches(self) -> list[dict[str, Any]]:
        guardian = self._guardian
        return [] if guardian is None else guardian.batches()

    def pending_holds(self) -> list[dict[str, Any]]:
        guardian = self._guardian
        return [] if guardian is None else guardian.pending_holds()

    def held_details(self, seq: int) -> dict[str, Any] | None:
        box = self._box
        if box is None or seq < 1:
            return None
        try:
            found = box.events(since_seq=seq - 1, limit=1)
        except BlackBoxError as error:
            logger.warning("cannot read a held request back from the black box: %s", error)
            return None
        if not found or found[0].seq != seq or (found[0].source, found[0].action) != (
            "gate", "held"
        ):  # fmt: skip
            return None
        return dict(found[0].details)

    def record(self, action: str, details: dict[str, Any], risk: int) -> None:
        box = self._box
        if box is None:
            return
        try:
            box.append("system", action, "", details=details, risk=risk)
        except BlackBoxError as error:
            logger.error("cannot write system/%s to the black box: %s", action, error)

    def _snapshots(self) -> list[Snapshot]:
        store = self._store
        if store is None:
            return []
        try:
            return sorted(store.snapshots(), key=lambda snap: snap.taken_at)
        except SnapshotError as error:
            logger.warning("cannot list the snapshots for Telegram: %s", error)
            return []


def _parse_ts(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


# Putting it together (runner.serve)


class _Hook(Protocol):
    def start(self) -> None: ...

    def close(self) -> None: ...


class Hooks:
    """Several ``ControlHook`` as one, for ``Guardian.run``: started in order once the service
    is up (the control socket, then the bot, which rewinds through it), closed in the reverse
    order before the service stops. ``close`` closes only what started, and every one of them
    even if another fails (the first failure is raised afterwards)."""

    def __init__(self, *hooks: _Hook) -> None:
        self._hooks = hooks
        self._started: list[_Hook] = []

    def start(self) -> None:
        for hook in self._hooks:
            hook.start()
            self._started.append(hook)

    def close(self) -> None:
        failure: Exception | None = None
        while self._started:
            hook = self._started.pop()
            try:
                hook.close()
            except Exception as error:
                failure = failure or error
        if failure is not None:
            raise failure


class _WorkingFor:
    """``target`` with each call on this thread working for the agent ``slug``: the bot's threads
    are nobody's, and what one logs about an agent is that agent's (T26-2c)."""

    def __init__(self, target: Any, slug: str) -> None:
        self._target, self._slug = target, slug

    def __getattr__(self, name: str) -> Any:
        found = getattr(self._target, name)

        def call(*args: Any, **kwargs: Any) -> Any:
            with scope.working_for(self._slug):
                return found(*args, **kwargs)

        return call


@dataclass(frozen=True)
class TelegramNeighbour:
    """The Telegram side of an agent other than the main one (T26-2e). ``desk`` is its gate's
    HoldWatch, built with it; ``watch`` gives what runs while its ``Guardian`` is up."""

    slug: str
    actions: GuardianActions
    desk: HoldDesk
    book: ButtonBook

    def watch(
        self, guardian: Any, box: BlackBox, store: Any, *, budget: Any = None, waiting: Any = None
    ) -> "NeighbourWatch":
        return NeighbourWatch(self, guardian, box, store, budget, waiting)

    def ended(self) -> None:
        """Its thread ended, and with it this life of the agent: what its last alerts issued goes,
        and what its gate told as it stopped is not told in the next one."""
        self.desk.clear()
        self.book.forget_agent(self.slug)


class TelegramNeighbours(Mapping[str, TelegramNeighbour]):
    """The Telegram side of each agent other than the main one, while the service runs. ``add``
    gives one its own actions and its own desk and puts it on the bot's table; ``forget`` takes it
    off, and none of its buttons acts again. As ``AgentTable``: each change makes a new dict."""

    def __init__(
        self, control_socket: Path, api: BotApi, chat_id: int, book: ButtonBook, table: AgentTable
    ) -> None:
        self._socket = control_socket  # the machine's: it is one, and says which agent by name
        self._api = api
        self._chat_id = chat_id
        self._book = book
        self._table = table
        self._lock = threading.Lock()
        self._theirs: dict[str, TelegramNeighbour] = {}

    def add(self, config: ServiceConfig) -> None:
        """It exists now, running or not. Twice is once: a desk stays the same for all its lives."""
        slug = config.slug
        with self._lock:
            if slug in self._theirs:
                return
            actions = GuardianActions(
                self._socket, agent_lines=config.agent_profile.rewind_notice_lines, agent=slug
            )
            scoped = _WorkingFor(actions, slug)
            desk = HoldDesk(self._api, self._chat_id, self._book, scoped, agent=slug)  # type: ignore[arg-type]
            self._book.admit_agent(slug)
            self._theirs = {
                **self._theirs,
                slug: TelegramNeighbour(slug, actions, desk, self._book),
            }
            self._table.put(slug, AgentSide(scoped, _WorkingFor(desk, slug)))  # type: ignore[arg-type]

    def forget(self, slug: str) -> None:
        """It was deleted, and its thread has ended. Off the table first: nothing new reaches it."""
        with self._lock:
            side = self._theirs.get(slug)
            self._theirs = {key: each for key, each in self._theirs.items() if key != slug}
            self._table.drop(slug)
        if side is not None:
            side.actions.unbind()
            side.desk.close()
        self._book.retire_agent(slug)

    def __getitem__(self, slug: str) -> TelegramNeighbour:
        return self._theirs[slug]

    def __iter__(self) -> Iterator[str]:
        return iter(self._theirs)

    def __len__(self) -> int:
        return len(self._theirs)


class NeighbourWatch:
    """A ``ControlHook``: what the bot can do for a neighbour starts once its ``Guardian`` is up and
    ends before it stops. Its desk's thread starts here, on the neighbour's own thread, so what the
    desk logs reaches the neighbour's black box. Its old buttons go with it."""

    def __init__(
        self,
        side: TelegramNeighbour,
        guardian: Any,
        box: BlackBox,
        store: Any,
        budget: Any,
        waiting: Any,
    ) -> None:
        self._side = side
        self._parts = (guardian, box, store)
        self._budget, self._waiting = budget, waiting

    def start(self) -> None:
        self._side.actions.bind(*self._parts, budget=self._budget, waiting=self._waiting)
        self._side.desk.start()

    def close(self) -> None:
        self._side.actions.unbind()
        self._side.desk.close()  # first: it issues buttons until it is closed (review of T26-2e)
        self._side.book.forget_agent(self._side.slug)


@dataclass(frozen=True)
class TelegramParts:
    """The notifier the alert queue delivers to, the actions to ``bind`` once the Guardian
    exists, the bot to run as a hook next to the control socket (it runs the desk too), and the
    desk the egress tells about its held requests. ``neighbours``: the same for each other agent,
    those there are now."""

    notifier: TelegramNotifier
    actions: GuardianActions
    bot: TelegramBot
    desk: HoldDesk  # the gate's HoldWatch: the notices of the held requests (T10-4)
    neighbours: TelegramNeighbours


def telegram_parts(
    config: ServiceConfig, settings: TelegramSettings, others: Sequence[ServiceConfig] = ()
) -> TelegramParts:
    """The Telegram side of the service, with ``others`` the other agents it runs (T26-2e). One bot
    and one book for all of them. Touches no network: the bot connects when started. With others,
    what the bot does for the main agent, on its threads of nobody, is the main agent's too."""
    api = BotApi(settings.token.reveal(), base=settings.api_base)
    book = ButtonBook()
    actions = GuardianActions(
        config.control_socket, agent_lines=config.agent_profile.rewind_notice_lines
    )
    chat = settings.chat_id
    table = AgentTable()
    neighbours = TelegramNeighbours(config.control_socket, api, chat, book, table)
    if others:
        scoped = _WorkingFor(actions, config.slug)
        desk = HoldDesk(api, chat, book, scoped, agent=config.slug)  # type: ignore[arg-type]
        its_desk: Any = _WorkingFor(desk, config.slug)
        table.put(config.slug, AgentSide(scoped, its_desk))  # type: ignore[arg-type]
        for other in others:
            neighbours.add(other)
    else:
        desk = HoldDesk(api, chat, book, actions)
        its_desk = desk
    notifier = TelegramNotifier(api, chat, book, actions, agents=table)
    bot = TelegramBot(api, chat, book, actions, desk=its_desk, agents=table)
    return TelegramParts(notifier, actions, bot, desk, neighbours)
