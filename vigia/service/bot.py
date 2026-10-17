"""What the Telegram bot can make the service do (T09): the ``BotActions`` of
``vigia.notify.telegram`` over the Guardian, the black box, the snapshot store and the control
socket. Built in ``runner.serve`` when ``<state_dir>/telegram.toml`` exists.

- ``pause`` calls ``Guardian.pause_by_user`` directly: it must freeze at once, and it never
  waits for ``agent_lock``. ``resume`` calls ``Guardian.resume`` (the same as `vigia seguir`).
- ``rewind`` goes through the control socket, ``via: "telegram"``, like `vigia rebobinar` and
  the web: one door for every rewind, which records who asked (with the kernel's uid and pid).
- ``target_for`` offers, for the alert about an event, the newest snapshot taken before that
  event: rewinding to it undoes what the event is about.
- ``record`` writes ``system/<action>`` to the black box (it redacts); if that fails it is
  logged at ERROR, which the log bridge turns into an alert.
- Every text goes out redacted; none quotes the agent.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any, Protocol

from vigia.blackbox import BlackBox, BlackBoxError, redact
from vigia.notify.buttons import ButtonBook
from vigia.notify.telegram import TelegramBot, TelegramNotifier
from vigia.notify.telegram_api import BotApi
from vigia.service.config import ServiceConfig
from vigia.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_rewind,
)
from vigia.service.notice import ago, rewind_notice
from vigia.service.pause import PauseOutcome, ResumeOutcome
from vigia.service.telegram_config import TelegramSettings
from vigia.snapshots import Snapshot, SnapshotError

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
}
REWIND_WAIT = 10.0  # seconds to wait for the control socket (the service is up: it is ours)


class _Guardian(Protocol):
    @property
    def agent_state(self) -> Any: ...

    @property
    def pause_reasons(self) -> frozenset[str]: ...

    def pause_by_user(self, *, requested_by: str) -> PauseOutcome: ...

    def user_pause_mark(self) -> int: ...

    def resume(self, *, requested_by: str, pause_mark: int | None = None) -> ResumeOutcome: ...


class _Snapshots(Protocol):
    def snapshots(self) -> list[Snapshot]: ...


AskRewind = Callable[..., dict[str, Any]]


class GuardianActions:
    """``BotActions`` for a running service. ``bind`` hands it the Guardian once it exists
    (the alert queue, and so the notifier, is built before it); until then every action says
    that Vigía is starting."""

    def __init__(
        self,
        control_socket: Path,
        *,
        ask: AskRewind = ask_rewind,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        tz: tzinfo | None = None,
    ) -> None:
        self._socket = control_socket
        self._ask = ask
        self._now = now
        self._tz = tz if tz is not None else (datetime.now().astimezone().tzinfo or UTC)
        self._guardian: _Guardian | None = None
        self._box: BlackBox | None = None
        self._store: _Snapshots | None = None

    def bind(self, guardian: _Guardian, box: BlackBox, store: _Snapshots) -> None:
        self._guardian, self._box, self._store = guardian, box, store

    # BotActions

    def pause(self) -> str:
        if self._guardian is None:
            return "Vigía está arrancando: prueba otra vez en unos segundos."
        return redact(self._guardian.pause_by_user(requested_by=REQUESTER).message)

    def pause_mark(self) -> int | None:
        return None if self._guardian is None else self._guardian.user_pause_mark()

    def resume(self, pause_mark: int | None) -> str:
        if self._guardian is None:
            return "Vigía está arrancando: prueba otra vez en unos segundos."
        outcome = self._guardian.resume(requested_by=REQUESTER, pause_mark=pause_mark)
        return redact(outcome.message)

    def status(self) -> str:
        if self._guardian is None:
            return "Vigía está arrancando."
        state = str(self._guardian.agent_state)
        lines = [f"Agente: {STATE_NAMES.get(state, state)}."]
        reasons = sorted(self._guardian.pause_reasons)
        if reasons:
            names = ", ".join(REASON_NAMES.get(reason, reason) for reason in reasons)
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
        return "\n".join(lines)

    def rewind(self, snapshot_id: str) -> str:
        try:
            reply = self._ask(self._socket, snapshot_id, via=REQUESTER, wait=REWIND_WAIT)
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
        paragraphs = rewind_notice(target.taken_at, now=self._now(), tz=self._tz)
        return "\n\n".join(paragraphs)

    def target_for(self, event_seq: int) -> str | None:
        if self._box is None:
            return None
        try:
            found = self._box.events(since_seq=event_seq - 1, limit=1) if event_seq >= 1 else []
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

    def record(self, action: str, details: dict[str, Any], risk: int) -> None:
        if self._box is None:
            return
        try:
            self._box.append("system", action, "", details=details, risk=risk)
        except BlackBoxError as error:
            logger.error("cannot write system/%s to the black box: %s", action, error)

    def _snapshots(self) -> list[Snapshot]:
        if self._store is None:
            return []
        try:
            return sorted(self._store.snapshots(), key=lambda snap: snap.taken_at)
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


@dataclass(frozen=True)
class TelegramParts:
    """The notifier the alert queue delivers to, the actions to ``bind`` once the Guardian
    exists, and the bot to run as a hook next to the control socket."""

    notifier: TelegramNotifier
    actions: GuardianActions
    bot: TelegramBot


def telegram_parts(config: ServiceConfig, settings: TelegramSettings) -> TelegramParts:
    """The Telegram side of the service. Touches no network: the bot connects when started."""
    api = BotApi(settings.token.reveal(), base=settings.api_base)
    book = ButtonBook()
    actions = GuardianActions(config.control_socket)
    notifier = TelegramNotifier(api, settings.chat_id, book, actions)
    bot = TelegramBot(api, settings.chat_id, book, actions)
    return TelegramParts(notifier, actions, bot)
