"""Telegram (T09): the alerts go to the founder's chat, and from it come `/pausar`, `/seguir`,
`/estado` and the "Pausar" and "Rebobinar" buttons of each alert.

The bot runs inside the backtide service (never in the agent's container) and only talks out:
**long polling** (``getUpdates``), no webhook, so there is no port to reach it.

Who may command:
- Only the founder's chat: a private chat whose id is ``chat_id`` and a sender with that same
  id (in a private chat they are equal). Groups, channels, other people, other bots, forwarded
  messages and messages "via" a bot are ignored without an answer (a stranger does not even
  learn that the bot is alive) and recorded in the black box as ``system/telegram_ignored``
  (the reason and the ids, never the text), at most ``IGNORED_PER_MINUTE`` a minute plus a
  count of the rest. Once an hour a warning says so (the log bridge makes it an alert).
- A button only acts through the server-side book (``buttons.py``): random tokens with an
  expiry, bound to the message they were sent on, and single use for the confirmation of a
  rewind. A forwarded, replayed or forged button does nothing, and is recorded.
- Commands are rate limited (``COMMAND_BURST`` at once, then one every ``COMMAND_EVERY`` s),
  except `/pausar` and the Pausar button: freezing is the safety action, cheap and idempotent.
- A command that arrives late (``MAX_COMMAND_AGE``: say, sent while the service was down) is
  not run, except `/pausar` (late or not, freezing is the safe side).

Speed: `/pausar` is handled on the polling thread itself, before anything else (the reply goes
out afterwards, on the sending thread), so it freezes the agent within a moment of Telegram
handing over the update. What takes long (a rewind, `/seguir`, `/estado`) runs on a worker
thread, one at a time, so polling never waits for it. A rewind always shows the fixed notice
(``backtide.service.notice``) first and asks for a confirmation.

What the bot can do is a ``BotActions`` (``backtide.service.bot`` puts the Guardian and the control
socket behind it). Texts are in Spanish and plain text (no ``parse_mode``): what an alert quotes
from the agent (a file name) cannot become markup, and control characters are escaped.
"""

import logging
import queue
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from backtide.notify import Alert, AlertLevel
from backtide.notify.buttons import (
    CONFIRM_TTL,
    HOLD_ACTIONS,
    Action,
    Button,
    ButtonBook,
    RateLimit,
    Refused,
)
from backtide.notify.hold_notice import HoldDesk
from backtide.notify.telegram_api import BotApi, TelegramError
from backtide.notify.text import inert, printable

# Bridged into the black box (``backtide.*``): polling problems are worth recording.
logger = logging.getLogger("backtide.telegram")
# Not bridged (``backtide.notify.*``): a failed delivery must never become an alert about alerting.
delivery_logger = logging.getLogger("backtide.notify.telegram")

POLL_TIMEOUT = 25  # seconds Telegram holds a getUpdates open
MAX_TEXT = 4000  # Telegram's limit is 4096 characters
MAX_COMMAND_AGE = 120.0  # seconds; older commands (but /pausar) are not run
COMMAND_BURST = 5
COMMAND_EVERY = 3.0
IGNORED_PER_MINUTE = 20
STRANGER_WARNING_EVERY = 3600.0
BACKOFF_MAX = 60.0
WORK_QUEUE = 4
SEND_QUEUE = 64
ALLOWED_UPDATES = ["message", "callback_query"]

HELP = (
    "Órdenes:\n"
    "/pausar: congela al agente al momento, desde fuera.\n"
    "/seguir: lo reanuda.\n"
    "/estado: cómo está el agente.\n"
    "/retenidas: las peticiones que esperan tu sí, con sus botones.\n"
    "/lotes: los lotes de aprobación activos, para revocarlos.\n\n"
    "En cada aviso, «Pausar» congela al agente y «Rebobinar» devuelve su carpeta a la "
    "instantánea de antes del aviso (antes te enseña qué se deshace y qué no, y te pide "
    "confirmación). En cada petición retenida, «Aprobar» la deja salir una vez, «Rechazar» la "
    "para y «Ver» te enseña lo que guarda la caja negra; si no respondes, se rechaza sola."
)
HOLD_ANSWERS = {
    Action.APPROVE: "Aprobando…",
    Action.REJECT: "Rechazando…",
    Action.BATCH_CONFIRM: "Creando el lote…",
    Action.BATCH_END: "Revocando el lote…",
}
REFUSED_TEXT = {
    Refused.UNKNOWN: "Este botón ya no vale (es de antes de reiniciar backtide, o no es nuestro).",
    Refused.EXPIRED: "Este botón ha caducado.",
    Refused.USED: "Este botón ya se usó.",
    Refused.WRONG_MESSAGE: "Este botón no es de este mensaje: no se hace nada.",
}
LEVEL_MARK = {
    AlertLevel.INFO: "backtide",
    AlertLevel.WARNING: "backtide, aviso",
    AlertLevel.ERROR: "backtide, ALERTA",
}


class BotActions(Protocol):
    """What the bot can make backtide do. Every method returns the text for the person (Spanish,
    with nothing of the agent's) and never raises; ``target_for`` and ``notice`` return None
    when there is nothing to offer."""

    def pause(self) -> str: ...

    def pause_mark(self) -> int | None:
        """How many pauses the person has asked for so far (``Guardian.user_pause_mark``)."""
        ...

    def resume(self, pause_mark: int | None) -> str:
        """Resume, unless the person asked to pause again after ``pause_mark``."""
        ...

    def status(self) -> str: ...

    def rewind(self, snapshot_id: str) -> str: ...

    def notice(self, snapshot_id: str) -> str | None:
        """The fixed notice of a rewind to ``snapshot_id``, or None if it no longer exists."""
        ...

    def target_for(self, event_seq: int) -> str | None:
        """The snapshot to offer for the alert about event ``event_seq``: the newest one taken
        before it."""
        ...

    def record(self, action: str, details: dict[str, Any], risk: int) -> None: ...


def alert_text(alert: Alert) -> str:
    """The message of an alert: plain text, redacted again (whoever made the alert), control
    characters escaped line by line, and nothing Telegram would turn into something to tap."""
    cited = (
        f"\n\n(evento {alert.event_seq} de la caja negra)" if alert.event_seq is not None else ""
    )
    head = f"{LEVEL_MARK[alert.level]}: {inert(alert.title)}\n\n"
    body = inert(alert.body)
    room = MAX_TEXT - len(head) - len(cited)
    if len(body) > room:
        body = body[: max(room - 1, 0)] + "…"
    return head + body + cited


def _keyboard(rows: list[list[tuple[str, str]]]) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": label, "callback_data": token} for label, token in row] for row in rows
        ]
    }


def _message_id(result: Any) -> int | None:
    if isinstance(result, dict):
        found = result.get("message_id")
        if type(found) is int:
            return found
    return None


class TelegramNotifier:
    """A ``Notifier``: each alert is one message to the founder's chat, with "Pausar" and,
    when there is a snapshot from before its event, "Rebobinar". Raises on failure (the alert
    queue logs it)."""

    def __init__(self, api: BotApi, chat_id: int, book: ButtonBook, actions: BotActions) -> None:
        self._api = api
        self._chat_id = chat_id
        self._book = book
        self._actions = actions

    def send(self, alert: Alert) -> None:
        tokens = [self._book.issue(Action.PAUSE)]
        row = [("Pausar", tokens[0])]
        target = self._target(alert)
        if target is not None:
            tokens.append(self._book.issue(Action.NOTICE, snapshot_id=target))
            row.append(("Rebobinar", tokens[-1]))
        params = {
            "chat_id": self._chat_id,
            "text": alert_text(alert),
            "reply_markup": _keyboard([row]),
            "link_preview_options": {"is_disabled": True},
        }
        try:
            result = self._call_with_retry(params)
        except Exception:
            self._book.forget(tokens)
            raise
        message_id = _message_id(result)
        if message_id is None:
            self._book.forget(tokens)
            raise TelegramError("sendMessage: the reply has no message_id")
        self._book.bind(tokens, message_id)

    def _target(self, alert: Alert) -> str | None:
        if alert.event_seq is None:
            return None
        try:
            return self._actions.target_for(alert.event_seq)
        except Exception as error:  # the alert still goes out, without the button
            delivery_logger.warning("cannot find the snapshot to offer for an alert: %s", error)
            return None

    def _call_with_retry(self, params: dict[str, Any]) -> Any:
        """One retry: after Telegram's ``retry_after`` (at most 10 s) for a 429, or a second
        for a network error or a 5xx. A refused token or a bad request is not retried."""
        try:
            return self._api.call("sendMessage", params)
        except TelegramError as error:
            if error.status == 429:
                time.sleep(min(error.retry_after or 1.0, 10.0))
            elif error.status == 0 or error.status >= 500:
                time.sleep(1.0)
            else:
                raise
        return self._api.call("sendMessage", params)


class TelegramBot:
    """The long-polling loop and the threads around it. ``start()`` never raises for a
    network problem (it retries with backoff, logging); ``close()`` stops everything and runs
    no command after it returns."""

    def __init__(
        self,
        api: BotApi,
        chat_id: int,
        book: ButtonBook,
        actions: BotActions,
        *,
        poll_timeout: int = POLL_TIMEOUT,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        max_command_age: float = MAX_COMMAND_AGE,
        limit: RateLimit | None = None,
        desk: HoldDesk | None = None,
    ) -> None:
        if type(chat_id) is not int:
            raise TypeError("chat_id must be an int")
        self._desk = desk
        self._api = api
        self._chat_id = chat_id
        self._book = book
        self._actions = actions
        self._poll_timeout = poll_timeout
        self._clock = clock
        self._mono = monotonic
        self._max_age = max_command_age
        self._limit = limit if limit is not None else RateLimit(COMMAND_BURST, COMMAND_EVERY)
        self._stop = threading.Event()
        self._work: queue.Queue[Callable[[], None] | None] = queue.Queue(WORK_QUEUE)
        self._outbox: queue.Queue[tuple[str, dict[str, Any]] | None] = queue.Queue(SEND_QUEUE)
        self._threads: list[threading.Thread] = []
        self._offset: int | None = None
        self._ignored_lock = threading.Lock()
        self._ignored_window = float("-inf")
        self._ignored_in_window = 0
        self._ignored_suppressed = 0
        self._next_stranger_warning = float("-inf")
        self._next_limit_reply = float("-inf")
        self._next_conflict_error = float("-inf")
        self.polls = 0  # finished getUpdates calls (for tests and diagnosis)

    # Life

    def start(self) -> None:
        if self._threads:
            return
        if self._desk is not None:
            self._desk.start()
        for name, target in (
            ("backtide-telegram", self._poll_loop),
            ("backtide-telegram-work", self._work_loop),
            ("backtide-telegram-send", self._send_loop),
        ):
            thread = threading.Thread(target=target, name=name, daemon=True)
            self._threads.append(thread)
            thread.start()

    def close(self, timeout: float = 2.0) -> None:
        """Stop. A getUpdates in flight is abandoned (its daemon thread ends with it; the
        updates it brings are not confirmed, so Telegram hands them over again next time)."""
        self._stop.set()
        for box in (self._work, self._outbox):
            try:
                box.put_nowait(None)
            except queue.Full:
                pass
        deadline = self._mono() + timeout
        poll, *others = self._threads or [None]
        for thread in others:
            thread.join(max(0.0, deadline - self._mono()))
        if poll is not None:
            poll.join(min(0.2, max(0.0, deadline - self._mono())))  # it acts on nothing now
        if self._desk is not None:
            self._desk.close(max(0.1, deadline - self._mono()))
        self._confirm_handled()

    def _confirm_handled(self) -> None:
        """Tell Telegram that what was handled is done (a getUpdates with the next offset), or
        it would hand the last batch over again at the next start and run it twice."""
        if self._offset is None:
            return
        try:
            self._api.call(
                "getUpdates", {"offset": self._offset, "timeout": 0, "limit": 1}, timeout=3.0
            )
        except TelegramError as error:
            logger.warning("telegram: cannot confirm the last updates: %s", error)

    # Polling

    def _poll_loop(self) -> None:
        backoff = 1.0
        webhook_cleared = False
        while not self._stop.is_set():
            try:
                if not webhook_cleared:
                    # A webhook would make getUpdates fail (409): this bot only polls.
                    self._api.call("deleteWebhook", {"drop_pending_updates": False})
                    webhook_cleared = True
                params: dict[str, Any] = {
                    "timeout": self._poll_timeout,
                    "allowed_updates": ALLOWED_UPDATES,
                }
                if self._offset is not None:
                    params["offset"] = self._offset
                updates = self._api.call("getUpdates", params, timeout=self._poll_timeout + 15.0)
            except TelegramError as error:
                if error.conflict:
                    webhook_cleared = False
                    if self._mono() >= self._next_conflict_error:
                        self._next_conflict_error = self._mono() + STRANGER_WARNING_EVERY
                        logger.error(
                            "telegram: another program is reading this bot's updates (409): "
                            "it may be taking the /pausar meant for backtide (%s)",
                            error,
                        )
                elif error.unauthorized:
                    logger.error("telegram refused the bot token: check telegram.toml (%s)", error)
                    backoff = BACKOFF_MAX
                else:
                    logger.warning("telegram: cannot fetch updates: %s", error)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, BACKOFF_MAX)
                continue
            backoff = 1.0
            self.polls += 1
            if self._stop.is_set():
                return  # not confirmed: handed over again at the next start
            if not isinstance(updates, list):
                logger.warning("telegram: getUpdates did not return a list")
                self._stop.wait(1.0)
                continue
            for update in updates:
                if self._stop.is_set():
                    return  # the rest is not confirmed either
                self._take(update)

    def _take(self, update: Any) -> None:
        if not isinstance(update, dict):
            return
        update_id = update.get("update_id")
        if type(update_id) is int and (self._offset is None or update_id >= self._offset):
            self._offset = update_id + 1
        try:
            self._handle(update)
        except Exception:  # one bad update must not stop the bot
            logger.exception("telegram: an update could not be handled")

    def _handle(self, update: dict[str, Any]) -> None:
        if isinstance(update.get("message"), dict):
            self._on_message(update["message"])
        elif isinstance(update.get("callback_query"), dict):
            self._on_button(update["callback_query"])
        else:
            kinds = sorted(key for key in update if key != "update_id")[:3]
            self._ignore("unexpected_update", ",".join(kinds) or "empty", None, None)

    def _is_owner(self, value: Any) -> bool:
        return type(value) is int and value == self._chat_id

    # Messages

    def _on_message(self, message: dict[str, Any]) -> None:
        chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
        sender = message.get("from") if isinstance(message.get("from"), dict) else {}
        chat_id, from_id = chat.get("id"), sender.get("id")
        if (
            not self._is_owner(chat_id)
            or not self._is_owner(from_id)
            or chat.get("type") != "private"
        ):
            self._ignore("not_owner", "message", chat_id, from_id)
            return
        if sender.get("is_bot") is not False or any(
            key in message for key in ("forward_origin", "forward_from", "forward_date", "via_bot")
        ):
            self._ignore("forwarded_or_bot", "message", chat_id, from_id)
            return
        command = _command(message.get("text"))
        if command == "pausar":  # first, and late or not: freezing is the safe side
            self._reply(self._actions.pause())
            return
        date = message.get("date")
        age = self._clock() - date if isinstance(date, int | float) else None
        if age is None or age > self._max_age or age < -self._max_age:
            self._ignore("stale", "message", chat_id, from_id)
            self._reply(
                "Esta orden ha llegado tarde (¿estaba backtide parado?) y no se ejecuta. Si "
                "todavía la quieres, mándala otra vez."
            )
            return
        if command == "estado":
            if self._allowed(chat_id, from_id):
                self._submit(lambda: self._reply(self._actions.status()))
            return
        if command == "seguir":
            if self._allowed(chat_id, from_id):
                # Taken now, on the thread that also runs /pausar: a /pausar sent after this
                # /seguir wins, however long the seguir waits for the worker or for the lock.
                mark = self._actions.pause_mark()
                self._submit(lambda: self._resume(mark, date))
            return
        if command in ("retenidas", "lotes"):
            desk = self._desk
            if desk is None:
                self._reply("Sin el bot completo no hay peticiones retenidas que enseñar aquí.")
            elif self._allowed(chat_id, from_id):
                listing = desk.list_holds if command == "retenidas" else desk.list_batches
                self._submit(lambda: self._reply_if(listing()))
            return
        self._reply(HELP)

    # Buttons

    def _on_button(self, query: dict[str, Any]) -> None:
        sender = query.get("from") if isinstance(query.get("from"), dict) else {}
        message = query.get("message") if isinstance(query.get("message"), dict) else {}
        chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
        from_id, chat_id = sender.get("id"), chat.get("id")
        if not self._is_owner(from_id) or not self._is_owner(chat_id):
            self._ignore("not_owner", "callback_query", chat_id, from_id)
            return  # not even answered
        query_id = query.get("id")
        button = self._book.take(query.get("data"), message.get("message_id"))
        if isinstance(button, Refused):
            self._ignore(str(button), "callback_query", chat_id, from_id)
            self._answer(query_id, self._refused_text(button, query.get("data")))
            return
        if button.action in HOLD_ACTIONS:
            self._on_hold_button(button, query_id, chat_id, from_id)
            return
        if button.action is Action.PAUSE:
            text = self._actions.pause()
            self._answer(query_id, "")
            self._reply(text)
            return
        if button.action is Action.NOTICE:
            if not self._allowed(chat_id, from_id, query_id):
                return
            self._answer(query_id, "")
            self._submit(lambda: self._ask_to_confirm(button))
            return
        if button.action is Action.CONFIRM:
            self._answer(query_id, "Rebobinando…")
            self._reply("Rebobinando: tarda unos segundos.")
            snapshot_id = button.snapshot_id or ""
            self._submit(lambda: self._reply(self._actions.rewind(snapshot_id)))
            return
        self._answer(query_id, "Cancelado.")
        self._reply("No se ha rebobinado nada.")

    def _refused_text(self, refused: Refused, data: Any) -> str:
        """Why a press did nothing; for a held request's button, how its hold ended."""
        found = self._book.peek(data) if refused in (Refused.USED, Refused.EXPIRED) else None
        if found is not None and found.hold_id is not None:
            if found.note is not None:
                return f"Esa retención ya está cerrada: {found.note}."
            if refused is Refused.EXPIRED:
                return "Esa retención ha caducado: se rechazó."
        return REFUSED_TEXT[refused]

    def _on_hold_button(self, button: Button, query_id: Any, chat_id: Any, from_id: Any) -> None:
        """A held request's button (T10-4). Saying no (Rechazar, Cancelar, Revocar) is never
        rate limited; saying yes or asking for more is, like a command."""
        desk = self._desk
        if desk is None:
            self._answer(query_id, REFUSED_TEXT[Refused.UNKNOWN])
            return
        cheap = button.action in (Action.REJECT, Action.BATCH_CANCEL, Action.BATCH_END)
        if not cheap and not self._allowed(chat_id, from_id, query_id):
            return
        self._answer(query_id, HOLD_ANSWERS.get(button.action, ""))
        self._submit(lambda: self._reply_if(desk.press(button)))

    def _reply_if(self, text: str | None) -> None:
        if text:
            self._reply(text)

    def _resume(self, mark: int | None, date: float) -> None:
        if self._clock() - date > self._max_age:
            self._reply("Esta orden de seguir ha esperado demasiado y no se ejecuta.")
            return
        self._reply(self._actions.resume(mark))

    def _ask_to_confirm(self, button: Button) -> None:
        snapshot_id = button.snapshot_id or ""
        notice = self._actions.notice(snapshot_id)
        if notice is None:
            self._reply("Esa instantánea ya no existe: no se puede rebobinar a ella.")
            return
        group = self._book.issue(Action.CANCEL, ttl=CONFIRM_TTL, single_use=True)
        confirm = self._book.issue(
            Action.CONFIRM,
            snapshot_id=snapshot_id,
            ttl=CONFIRM_TTL,
            single_use=True,
            group=group,
        )
        tokens = [confirm, group]
        text = printable(notice) + "\n\n¿Rebobinar? (Este botón caduca en 2 minutos.)"
        try:
            result = self._api.call(
                "sendMessage",
                {
                    "chat_id": self._chat_id,
                    "text": text[:MAX_TEXT],
                    "reply_markup": _keyboard([[("Sí, rebobinar", confirm), ("Cancelar", group)]]),
                },
            )
        except TelegramError as error:
            self._book.forget(tokens)
            delivery_logger.warning("telegram: cannot send the rewind notice: %s", error)
            return
        message_id = _message_id(result)
        if message_id is None:
            self._book.forget(tokens)
            return
        self._book.bind(tokens, message_id)

    # Shared steps

    def _allowed(self, chat_id: Any, from_id: Any, query_id: Any = None) -> bool:
        if self._limit.allow():
            return True
        self._ignore("rate_limited", "callback_query" if query_id else "message", chat_id, from_id)
        text = "Demasiadas órdenes seguidas: espera unos segundos."
        if query_id is not None:
            self._answer(query_id, text)
        elif self._mono() >= self._next_limit_reply:
            self._next_limit_reply = self._mono() + 60.0
            self._reply(text)
        return False

    def _submit(self, job: Callable[[], None]) -> None:
        try:
            self._work.put_nowait(job)
        except queue.Full:
            self._reply("Estoy con otra orden: espera a que termine y vuelve a probar.")

    def _work_loop(self) -> None:
        while True:
            job = self._work.get()
            if job is None or self._stop.is_set():
                return
            try:
                job()
            except Exception:
                logger.exception("telegram: an order failed")
                self._reply("Ha fallado algo al hacer la orden. Detalles en la caja negra.")

    def _reply(self, text: str) -> None:
        self._send("sendMessage", {"chat_id": self._chat_id, "text": printable(text)[:MAX_TEXT]})

    def _answer(self, query_id: Any, text: str) -> None:
        if isinstance(query_id, str):
            self._send("answerCallbackQuery", {"callback_query_id": query_id, "text": text[:190]})

    def _send(self, method: str, params: dict[str, Any]) -> None:
        try:
            self._outbox.put_nowait((method, params))
        except queue.Full:
            delivery_logger.warning("telegram: the outbox is full, a %s was dropped", method)

    def _send_loop(self) -> None:
        while True:
            item = self._outbox.get()
            if item is None:
                return
            method, params = item
            try:
                self._api.call(method, params)
            except TelegramError as error:
                delivery_logger.warning("telegram: %s", error)
            except Exception:
                delivery_logger.exception("telegram: %s failed", method)

    def _ignore(self, reason: str, kind: str, chat_id: Any, from_id: Any) -> None:
        """Record an ignored update, at most ``IGNORED_PER_MINUTE`` a minute; the rest are
        counted and the count goes with the next one recorded."""
        now = self._mono()
        with self._ignored_lock:
            if now - self._ignored_window >= 60.0:
                self._ignored_window, self._ignored_in_window = now, 0
            if self._ignored_in_window >= IGNORED_PER_MINUTE:
                self._ignored_suppressed += 1
                return
            self._ignored_in_window += 1
            suppressed, self._ignored_suppressed = self._ignored_suppressed, 0
            warn = reason == "not_owner" and now >= self._next_stranger_warning
            if warn:
                self._next_stranger_warning = now + STRANGER_WARNING_EVERY
        details: dict[str, Any] = {
            "reason": reason,
            "kind": kind,
            "chat_id": chat_id if type(chat_id) is int else None,
            "from_id": from_id if type(from_id) is int else None,
        }
        if suppressed:
            details["suppressed"] = suppressed
        self._actions.record("telegram_ignored", details, 2 if reason == "not_owner" else 1)
        if warn:
            logger.warning(
                "telegram: a chat that is not the owner's wrote to the bot; it is ignored "
                "(system/telegram_ignored in the black box)"
            )


def _command(text: Any) -> str | None:
    """``/pausar@MiBot extra`` -> ``pausar``; anything that is not a command -> None."""
    if not isinstance(text, str) or not text.startswith("/"):
        return None
    word = text[1:].split(maxsplit=1)[0] if len(text) > 1 else ""
    return word.split("@", 1)[0].lower() or None
