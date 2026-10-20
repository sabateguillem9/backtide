"""The notice of a held request in Telegram, its buttons, the batches and the notice budget
(T10-4, docs/32-diseno-t10-puerta.md, sections 10 and 11).

**The notice** (``hold_text``) is plain text (no ``parse_mode``: nothing the agent writes can be
markup) in two parts that cannot be mixed up:

- Ours, first: a fixed header line (``⏸ backtide · RETENIDA · riesgo N · h-…``), what it does in
  our words (``phrase.action``: "Telegram: enviar un mensaje"), our notes ("Ojo: …") and the
  countdown ("Si no respondes en 5 min, se rechaza.").
- The agent's, after "Lo que pide el agente (texto suyo, no de backtide):": the recipients, the
  subject, the first lines, the attachments, or the request itself without a translator. EVERY
  line of it starts with ``│ `` and the block ends with ``└ fin del texto del agente``, so a line
  the agent writes can never look like one of ours ("✅ Aprobada", "(ya aprobado)", a fake
  header). Each piece goes through ``inert`` (struck again, control and invisible characters such
  as RLO or a zero-width space escaped, ``/orden`` and ``://`` made untappable) and is cut:
  200 characters of subject, 3 lines and 300 characters of text, 5 recipients and "y N más".
- The buttons: "Aprobar", "Rechazar", "Ver" and, when the hold may make one, the batches
  (docs/32 section 10: never for a deletion, a forward, risk 3...). Labels are ours.

**The buttons** live in the server-side ``ButtonBook``, bound to the message and to the hold, and
living as long as it. "Aprobar" and "Rechazar" go through the same door as `backtide aprobar`
(the control socket, ``via: telegram``); the ``HoldBook`` lets a hold be decided once, so a
second press answers "ya no está abierta". When the hold ends, however it ended (Telegram, the
terminal, the web, a pause, the 5 min), ``closed`` uses its buttons up and the message is edited
to say how, without buttons. "Ver" is never used up: it sends what the black box keeps (the
2 KiB excerpt, every recipient and attachment). A batch takes two taps: its button asks, with
the exact scope, and only "Sí, crear el lote" makes it.

**The budget** (fatigue as an attack): at most ``NOTICES_PER_MINUTE`` notices a minute. Past it
a single summary message ("N retenidas más; míralas con /retenidas"), edited as the count grows
(at most every ``SUMMARY_EVERY`` s) and with "Pausar". `/retenidas` sends the open ones again
with their buttons, and `/lotes` lists the batches with a "Revocar" for each.

``held`` and ``closed`` are the ``HoldWatch`` of the proxy's channel: called under its gate lock,
they only queue (never block, never raise); the desk's own thread talks to Telegram.
"""

import logging
import math
import queue
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from backtide.gate.phrase import action, api_name, note_texts
from backtide.notify.buttons import CONFIRM_TTL, Action, Button, ButtonBook
from backtide.notify.telegram_api import BotApi, TelegramError
from backtide.notify.text import inert

delivery_logger = logging.getLogger("backtide.notify.telegram")

NOTICES_PER_MINUTE = 6  # docs/32, section 11 and decision 9
SUMMARY_EVERY = 5.0  # seconds between two edits of the summary
MAX_TEXT = 4000
MAX_LISTED = 10  # /retenidas sends at most this many notices
MAX_TRACKED = 64  # holds remembered (20 open at most, plus some just closed)
QUEUE_SIZE = 256
SUBJECT_CHARS = 200
LINES = 3
LINES_CHARS = 300
SHOWN_RECIPIENTS = 5
SHOWN_ATTACHMENTS = 5
LINE_CHARS = 300  # any other line of the agent's
VIEW_RECIPIENTS = 64
AGENT = "│ "
AGENT_HEAD = "Lo que pide el agente (texto suyo, no de backtide):"
AGENT_END = "└ fin del texto del agente"
REASONS = {
    "delete": "un borrado (DELETE) que backtide no sabe leer",
    "write": "una escritura que backtide no sabe leer",
    "url_secret": "una petición cuya dirección llevaba un secreto (tachado)",
    "header_secret": "una petición con un secreto en una cabecera (tachado)",
    "credential_secret": "una lectura con una credencial reconocible, a un host fuera de la lista",
    "credential_unknown_host": "una lectura con credenciales, a un host fuera de la lista",
    "url_long": "una lectura con una dirección demasiado larga",
    "headers_long": "una lectura con cabeceras demasiado largas",
    "credentials_long": "una lectura con credenciales demasiado largas",
    "read_budget": "una lectura que pasa del presupuesto de lecturas a hosts desconocidos",
    "draft_open": "un cambio en un borrador cuyo envío está retenido",
}
BY = {"telegram": "desde Telegram", "cli": "desde la terminal", "web": "desde la web"}
EXPIRED = {
    "timeout": "Caducada: nadie respondió en 5 minutos, así que se rechazó. No salió.",
}
EXPIRED_OTHER = "Caducada: backtide o el proxy se reiniciaron. No salió."


class HoldActions(Protocol):
    """What the desk can make backtide do (``backtide.service.bot.GuardianActions``). Every
    method returns texts for the person (Spanish, nothing of the agent's) and never raises."""

    def decide(self, hold_id: str, verdict: str) -> tuple[str, str]:
        """(outcome, message) of approving or rejecting through the control socket."""
        ...

    def create_batch(self, hold_id: str, kind: str) -> tuple[str, str]:
        """(status, message) of making a batch from the hold, which approves it."""
        ...

    def end_batch(self, rule_id: str) -> str: ...

    def batches(self) -> list[dict[str, Any]]: ...

    def pending_holds(self) -> list[dict[str, Any]]: ...

    def held_details(self, seq: int) -> dict[str, Any] | None:
        """The details of the gate/held with that seq, as the black box keeps them."""
        ...


# --- texts ---------------------------------------------------------------------------------------


def _inert(text: object) -> str:
    return inert(str(text))  # the alerts' own rule (T09): one for every message


def _one_line(text: object, limit: int = LINE_CHARS) -> str:
    """The agent's text on one line: struck, inert and cut."""
    flat = " / ".join(piece.strip() for piece in str(text).splitlines() if piece.strip())
    return _cut(_inert(flat), limit)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(limit - 1, 0)] + "…"


def _lines(text: object, lines: int = LINES, limit: int = LINES_CHARS) -> list[str]:
    """The agent's text on at most ``lines`` lines and ``limit`` characters, inert."""
    shown = _inert(_cut(str(text), limit)).split("\n")
    out = [line for line in shown if line.strip()][:lines]
    if len(shown) > lines:
        out[-1] += " …"
    return out


def _block(lines: Sequence[str]) -> str:
    """The agent's part: every line marked, so none can pass for ours."""
    body = []
    for line in lines:
        for piece in str(line).split("\n"):
            body.append(AGENT + piece)
    return "\n".join([AGENT_HEAD, *body, AGENT_END])


def _size(size: object) -> str:
    if type(size) is not int or size <= 0:
        return "?"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _recipients(recipients: Sequence[Any], shown: int = SHOWN_RECIPIENTS) -> str:
    names = [_one_line(item, 120) for item in recipients[:shown]]
    more = len(recipients) - shown
    return ", ".join(names) + (f" y {more} más" if more > 0 else "")


def _countdown(seconds: object) -> str:
    left = seconds if type(seconds) is int and seconds > 0 else 0
    if left >= 60:
        return f"Si no respondes en {math.ceil(left / 60)} min, se rechaza."
    return f"Si no respondes en {left} s, se rechaza."


def _what(notice: Mapping[str, Any]) -> tuple[str, list[str]]:
    """(what it does, our notes), in our words."""
    reading = notice.get("reading")
    if isinstance(reading, Mapping):
        return action(reading), note_texts(reading)
    reason = str(notice.get("reason", ""))
    return "Sin traductor: " + REASONS.get(reason, "una petición retenida"), []


def _agent_lines(notice: Mapping[str, Any]) -> list[str]:
    """What the agent asked, piece by piece (each inert and cut)."""
    reading = notice.get("reading")
    lines: list[str] = []
    if isinstance(reading, Mapping):
        recipients = reading.get("recipients") or []
        if recipients:
            lines.append("Para: " + _recipients(recipients))
        if reading.get("reply_to"):
            lines.append("Responder a: " + _recipients(reading["reply_to"]))
        if reading.get("subject"):
            lines.append("Asunto: " + _one_line(reading["subject"], SUBJECT_CHARS))
        if reading.get("first_lines"):
            lines += _lines(reading["first_lines"])
        if reading.get("target"):
            lines.append("Sobre: " + _one_line(reading["target"]))
        attachments = reading.get("attachments") or []
        if attachments:
            names = [
                f"{_one_line(item.get('name') or '(sin nombre)', 100)} ({_size(item.get('size'))})"
                for item in attachments[:SHOWN_ATTACHMENTS]
                if isinstance(item, Mapping)
            ]
            more = len(attachments) - SHOWN_ATTACHMENTS
            lines.append("Adjuntos: " + ", ".join(names) + (f" y {more} más" if more > 0 else ""))
        if not lines and notice.get("phrase"):
            lines.append(_one_line(notice["phrase"]))
    else:
        request = (
            f"{notice.get('method') or '?'} {notice.get('host') or ''}{notice.get('path') or ''}"
        )
        lines.append(_one_line(request))
    return lines or ["(nada que enseñar)"]


def hold_text(notice: Mapping[str, Any]) -> str:
    """The notice of a held request: ours first, the agent's apart and marked."""
    risk = notice.get("risk")
    what, notes = _what(notice)
    ours = [
        f"⏸ backtide · RETENIDA · riesgo {risk if risk in (2, 3) else '?'} · "
        f"{notice.get('hold_id')}",
        what,
    ]
    if notes:
        ours.append("Ojo: " + "; ".join(notes) + ".")
    ours.append(_countdown(notice.get("expires_in_s")))
    text = "\n".join(ours) + "\n\n" + _block(_agent_lines(notice))
    return _fit(text)


def _fit(text: str) -> str:
    """Cut to Telegram's size, keeping the end of the agent's block in sight."""
    if len(text) <= MAX_TEXT:
        return text
    return text[: MAX_TEXT - len(AGENT_END) - 3] + "…\n" + AGENT_END


def view_text(notice: Mapping[str, Any], details: Mapping[str, Any] | None) -> str:
    """ "Ver": what the black box keeps of the hold (the 2 KiB excerpt, every recipient and
    attachment), with the same two parts."""
    what, notes = _what(notice)
    ours = [f"backtide · detalle de la retención {notice.get('hold_id')}", what]
    if notes:
        ours.append("Ojo: " + "; ".join(notes) + ".")
    details = details or {}
    lines = [
        _one_line(
            f"Petición: {details.get('method') or notice.get('method') or '?'} "
            f"{details.get('host') or notice.get('host') or ''}"
            f"{details.get('path') or notice.get('path') or ''}"
        )
    ]
    reading = details.get("reading") if isinstance(details.get("reading"), Mapping) else None
    reading = reading or (
        notice.get("reading") if isinstance(notice.get("reading"), Mapping) else None
    )
    if reading:
        if reading.get("recipients"):
            lines.append("Para: " + _recipients(reading["recipients"], VIEW_RECIPIENTS))
        if reading.get("reply_to"):
            lines.append("Responder a: " + _recipients(reading["reply_to"], VIEW_RECIPIENTS))
        if reading.get("sender"):
            lines.append("De: " + _one_line(reading["sender"], 200))
        if reading.get("subject"):
            lines.append("Asunto: " + _one_line(reading["subject"], SUBJECT_CHARS))
        for item in reading.get("attachments") or []:
            if isinstance(item, Mapping):
                lines.append(
                    f"Adjunto: {_one_line(item.get('name') or '(sin nombre)', 100)} · "
                    f"{_one_line(item.get('type') or '?', 80)} · "
                    f"{_size(item.get('size'))}"
                )
    body = details.get("body") if isinstance(details.get("body"), Mapping) else {}
    excerpt = body.get("excerpt") if isinstance(body, Mapping) else None
    if isinstance(excerpt, str) and excerpt:
        lines.append("Extracto del cuerpo (2 KiB como mucho, con los secretos tachados):")
        lines += _inert(_cut(excerpt, 2048)).split("\n")
        if body.get("excerpt_truncated"):
            lines.append("(sigue: la caja negra solo guarda los primeros 2 KiB)")
    elif isinstance(body, Mapping) and body.get("size"):
        lines.append(f"Cuerpo de {_size(body.get('size'))}: la caja negra no guarda extracto.")
    return _fit("\n".join(ours) + "\n\n" + _block(lines))


def result_line(status: str, by: str | None) -> str:
    """How a hold ended, in our words."""
    who = BY.get(str(by), "")
    if status == "released":
        return f"Resultado: aprobada {who}: salió una sola vez.".replace("  ", " ")
    if status == "preapproved":
        return (
            f"Resultado: aprobada {who}. El agente ya no esperaba: si la repite igual en "
            "10 minutos, sale una vez."
        ).replace("  ", " ")
    if status == "rejected":
        if by == "pause":
            return "Resultado: rechazada al pausar el agente. No salió."
        if by == "rewind":
            return "Resultado: rechazada al rebobinar el agente. No salió."
        return f"Resultado: rechazada {who}. No salió.".replace("  ", " ")
    if status == "expired":
        return "Resultado: " + EXPIRED.get(str(by), EXPIRED_OTHER)
    return "Resultado: ya no está abierta."


def retired_note(status: str) -> str:
    return {
        "released": "aprobada",
        "preapproved": "aprobada",
        "rejected": "rechazada",
        "expired": "caducada",
    }.get(status, "cerrada")


def batch_label(notice: Mapping[str, Any], kind: str) -> str:
    reading = notice.get("reading")
    if kind == "recipient":
        many = isinstance(reading, Mapping) and len(reading.get("recipients") or []) > 1
        return (
            "Todo a estos destinatarios (sesión)" if many else "Todo a este destinatario (sesión)"
        )
    if isinstance(reading, Mapping):
        noun = "Envíos" if reading.get("effect") == "send" else "Cambios"
        return f"{noun} de {api_name(str(reading.get('translator')))}, 1 h"
    return f"{notice.get('method')} a este host y ruta, 1 h"


NEVER = (
    "Nunca entra un borrado, un reenvío, algo de riesgo 3, algo con un secreto ni algo que "
    "haga descargar una dirección. Se ve y se revoca con /lotes."
)


def batch_question(notice: Mapping[str, Any], kind: str) -> str:
    """The confirmation of a batch: its exact scope."""
    reading = notice.get("reading")
    if isinstance(reading, Mapping):
        api = api_name(str(reading.get("translator")))
        if kind == "recipient":
            ours = (
                f"¿Crear un lote? Se aprueba esta petición y, sin volver a preguntar, todo "
                f"envío o cambio de {api} desde esta misma cuenta a estos destinatarios, "
                "hasta que pauses o rebobines el agente, reinicies backtide o el proxy, o "
                "pasen 12 horas (lo primero que llegue). Otro destinatario o una copia de "
                f"más vuelven a preguntar. {NEVER}"
            )
            agent = ["Destinatarios: " + _recipients(reading.get("recipients") or [])]
        else:
            what = "envío" if reading.get("effect") == "send" else "cambio"
            ours = (
                f"¿Crear un lote? Se aprueba esta petición y, durante 1 hora, sin volver a "
                f"preguntar, todo {what} de {api} desde esta misma cuenta, a cualquier "
                f"destinatario. {NEVER}"
            )
            agent = ["Ahora va a: " + _recipients(reading.get("recipients") or [])]
    else:
        method = notice.get("method")
        ours = (
            f"¿Crear un lote? Se aprueba esta petición y, durante 1 hora, sin volver a "
            f"preguntar, todo {method} a este host y a esta ruta (con otros números o "
            "identificadores en ella, y con cualquier cuerpo). Otro host, otra ruta u otros "
            f"parámetros vuelven a preguntar. {NEVER}"
        )
        agent = [_one_line(f"Host y ruta: {notice.get('host') or ''}{notice.get('path') or ''}")]
    head = f"backtide · lote para la retención {notice.get('hold_id')}"
    tail = "(Estos botones caducan en 2 minutos.)"
    return _fit(f"{head}\n{ours}\n{tail}\n\n{_block(agent)}")


def _left(seconds: object) -> str:
    left = seconds if type(seconds) is int and seconds > 0 else 0
    hours, minutes = divmod(math.ceil(left / 60), 60)
    return f"{hours} h {minutes} min" if hours else f"{minutes} min"


def batches_text(rules: Sequence[Mapping[str, Any]]) -> str:
    if not rules:
        return "No hay lotes activos."
    lines = [f"Lotes activos ({len(rules)}). «Revocar N» lo termina ya:"]
    agent: list[str] = []
    for n, rule in enumerate(rules, start=1):
        uses = rule.get("uses") if type(rule.get("uses")) is int else 0
        if rule.get("translator") is None:
            what = f"{rule.get('method')} a un host y ruta, 1 h"
            agent.append(_one_line(f"{n}. {rule.get('host') or ''}{rule.get('route') or ''}"))
        elif rule.get("scope") == "recipient":
            what = f"{api_name(str(rule.get('translator')))}, todo a unos destinatarios, sesión"
            agent.append(f"{n}. " + _recipients(rule.get("recipients") or []))
        else:
            noun = "envíos" if rule.get("effect") == "send" else "cambios"
            what = f"{api_name(str(rule.get('translator')))}, todos los {noun}, 1 h"
        lines.append(f"{n}. {what}: quedan {_left(rule.get('left_s'))}; usado {uses} veces.")
    text = "\n".join(lines)
    if agent:
        text += "\n\n" + _block(agent)
    return _fit(text)


def summary_text(count: int) -> str:
    return (
        f"backtide · {count} retenidas más sin aviso propio: el agente pide demasiadas cosas "
        "seguidas (como mucho mando 6 avisos por minuto). Míralas con /retenidas. Si no "
        "esperabas tantas, pausa al agente."
    )


def keyboard(rows: list[list[tuple[str, str]]]) -> dict[str, Any]:
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


# --- the desk ------------------------------------------------------------------------------------


class HoldDesk:
    """The ``HoldWatch`` that tells the founder's chat about each held request, and what its
    buttons and `/retenidas` and `/lotes` do. ``start()`` runs its thread; ``close()`` ends it."""

    def __init__(
        self,
        api: BotApi,
        chat_id: int,
        book: ButtonBook,
        actions: HoldActions,
        *,
        clock: Callable[[], float] = time.monotonic,
        per_minute: int = NOTICES_PER_MINUTE,
        summary_every: float = SUMMARY_EVERY,
    ) -> None:
        self._api = api
        self._chat_id = chat_id
        self._book = book
        self._actions = actions
        self._clock = clock
        self._per_minute = per_minute
        self._summary_every = summary_every
        self._queue: queue.Queue[tuple[Any, ...] | None] = queue.Queue(QUEUE_SIZE)
        self._lock = threading.Lock()
        self._notices: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._messages: dict[str, list[tuple[int, str]]] = {}
        # hold id -> how it ended and who ended it
        self._closed: OrderedDict[str, tuple[str, str | None]] = OrderedDict()
        self._sent: deque[float] = deque()
        self._unannounced = 0  # holds without a notice since the summary began
        self._summary_id: int | None = None
        self._summary_token: str | None = None  # its "Pausar"
        self._summary_since = float("-inf")
        self._summary_shown = 0
        self._summary_edited = float("-inf")
        self._lost = 0
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # The HoldWatch: never blocks, never raises

    def held(self, notice: Mapping[str, Any]) -> None:
        self._put(("held", dict(notice)))

    def closed(self, hold_id: str, status: str, by: str | None) -> None:
        try:
            # At once: a press after this answers how it ended, before the edit goes out.
            self._book.retire_hold(hold_id, retired_note(status))
        except Exception:
            delivery_logger.exception("cannot retire the buttons of a held request")
        self._put(("closed", hold_id, status, by))

    def _put(self, item: tuple[Any, ...]) -> None:
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._lock:
                self._lost += 1  # told in the summary; the holds are in /retenidas anyway

    # Life

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="backtide-holds", daemon=True)
        self._thread.start()

    def close(self, timeout: float = 2.0) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                item = ()
            if item is None:
                return
            try:
                if item and item[0] == "held":
                    self._on_held(item[1])
                elif item and item[0] == "closed":
                    self._on_closed(item[1], item[2], item[3])
                self._tell_summary()
            except Exception:  # one bad notice must not stop the next
                delivery_logger.exception("telegram: a hold notice failed")

    # What the thread does

    def _on_held(self, notice: dict[str, Any]) -> None:
        hold_id = str(notice.get("hold_id"))
        with self._lock:
            self._notices[hold_id] = notice
            while len(self._notices) > MAX_TRACKED:
                self._notices.popitem(last=False)
            now = self._clock()
            while self._sent and now - self._sent[0] >= 60.0:
                self._sent.popleft()
            if len(self._sent) >= self._per_minute:
                self._unannounced += 1
                return
            self._sent.append(now)
        self.send_notice(notice)

    def _on_closed(self, hold_id: str, status: str, by: str | None) -> None:
        with self._lock:
            self._closed[hold_id] = (status, by)
            while len(self._closed) > MAX_TRACKED * 4:
                self._closed.popitem(last=False)
            self._notices.pop(hold_id, None)
            messages = self._messages.pop(hold_id, [])
        self._book.retire_hold(hold_id, retired_note(status))  # buttons issued meanwhile too
        line = result_line(status, by)
        for message_id, text in messages:
            self._edit(message_id, _fit(text + "\n\n" + line))

    def _tell_summary(self) -> None:
        """One summary for the holds past the budget: a new message when there is none from
        the last minute, else that one edited with the new count (at most every
        ``summary_every`` s)."""
        with self._lock:
            lost, self._lost = self._lost, 0
            self._unannounced += lost
            now = self._clock()
            if self._unannounced <= self._summary_shown:
                return
            if now - self._summary_edited < self._summary_every:
                return
            fresh = self._summary_id is not None and now - self._summary_since < 60.0
            if not fresh:  # a new summary counts only what the last one did not show
                self._unannounced -= self._summary_shown
                self._summary_id, self._summary_token, self._summary_since = None, None, now
            count = self._unannounced
            message_id, token = self._summary_id, self._summary_token
            self._summary_edited = now
            self._summary_shown = count
        if message_id is not None and token is not None:
            self._edit(message_id, summary_text(count), keyboard([[("Pausar", token)]]))
            return
        token = self._book.issue(Action.PAUSE)
        markup = keyboard([[("Pausar", token)]])
        sent = self._call(
            "sendMessage",
            {"chat_id": self._chat_id, "text": summary_text(count), "reply_markup": markup},
        )
        found = _message_id(sent)
        if found is None:
            self._book.forget([token])
            return
        self._book.bind([token], found)
        with self._lock:
            self._summary_id, self._summary_token = found, token

    # Sending (the desk's thread, or the bot's worker for /retenidas)

    def send_notice(self, notice: Mapping[str, Any]) -> None:
        """One notice of ``notice``'s hold, with fresh buttons bound to it."""
        hold_id = str(notice.get("hold_id"))
        with self._lock:
            if hold_id in self._closed:
                return
        ttl = float(max(1, notice.get("expires_in_s") or 0))
        approve = self._book.issue(Action.APPROVE, ttl=ttl, hold_id=hold_id)
        reject = self._book.issue(Action.REJECT, ttl=ttl, hold_id=hold_id)
        view = self._book.issue(Action.VIEW, ttl=ttl, hold_id=hold_id)
        rows = [[("Aprobar", approve), ("Rechazar", reject), ("Ver", view)]]
        tokens = [approve, reject, view]
        batch_row = []
        for kind in notice.get("batches") or []:
            if kind not in ("recipient", "kind"):
                continue
            token = self._book.issue(Action.BATCH, ttl=ttl, hold_id=hold_id, kind=kind)
            tokens.append(token)
            batch_row.append((batch_label(notice, kind), token))
        if batch_row:
            rows.append(batch_row)
        text = hold_text(notice)
        sent = self._call(
            "sendMessage",
            {
                "chat_id": self._chat_id,
                "text": text,
                "reply_markup": keyboard(rows),
                "link_preview_options": {"is_disabled": True},
            },
        )
        message_id = _message_id(sent)
        if message_id is None:
            self._book.forget(tokens)
            return
        self._book.bind(tokens, message_id)
        with self._lock:
            ended = self._closed.get(hold_id)
            if ended is None:
                self._messages.setdefault(hold_id, []).append((message_id, text))
        if ended is not None:  # it ended while this went out
            self._book.retire_hold(hold_id, retired_note(ended[0]))
            self._edit(message_id, _fit(text + "\n\n" + result_line(*ended)))

    def _edit(self, message_id: int, text: str, markup: dict[str, Any] | None = None) -> None:
        self._call(
            "editMessageText",
            {
                "chat_id": self._chat_id,
                "message_id": message_id,
                "text": text,
                "reply_markup": markup if markup is not None else {"inline_keyboard": []},
                "link_preview_options": {"is_disabled": True},
            },
        )

    def _call(self, method: str, params: dict[str, Any]) -> Any:
        try:
            return self._api.call(method, params)
        except TelegramError as error:
            delivery_logger.warning("telegram: %s of a hold notice failed: %s", method, error)
            return None

    def _send(self, text: str, rows: list[list[tuple[str, str]]] | None = None) -> int | None:
        params: dict[str, Any] = {
            "chat_id": self._chat_id,
            "text": _fit(text),
            "link_preview_options": {"is_disabled": True},
        }
        if rows:
            params["reply_markup"] = keyboard(rows)
        return _message_id(self._call("sendMessage", params))

    # The bot's side (its worker thread): buttons and commands

    def press(self, button: Button) -> str | None:
        """Do what a hold's button says. Returns a reply for the chat, or None."""
        hold_id = button.hold_id or ""
        if button.action is Action.APPROVE:
            return self._decide(hold_id, "approve")
        if button.action is Action.REJECT:
            return self._decide(hold_id, "reject")
        if button.action is Action.VIEW:
            return self._view(hold_id)
        if button.action is Action.BATCH:
            return self._ask_batch(hold_id, button.kind or "")
        if button.action is Action.BATCH_CONFIRM:
            status, message = self._actions.create_batch(hold_id, button.kind or "")
            return message
        if button.action is Action.BATCH_CANCEL:
            return "No se ha creado ningún lote. La petición sigue retenida."
        if button.action is Action.BATCH_END:
            return self._actions.end_batch(button.rule_id or "")
        return None

    def _decide(self, hold_id: str, verdict: str) -> str:
        outcome, message = self._actions.decide(hold_id, verdict)
        if outcome == "unknown":
            with self._lock:
                ended = self._closed.get(hold_id)
            if ended is not None:
                return f"Esa retención ya está cerrada: {retired_note(ended[0])}."
        return message

    def _notice_of(self, hold_id: str) -> dict[str, Any] | None:
        with self._lock:
            found = self._notices.get(hold_id)
            return dict(found) if found is not None else None

    def _view(self, hold_id: str) -> str | None:
        notice = self._notice_of(hold_id)
        if notice is None:
            return "Esa retención ya no está abierta."
        seq = notice.get("seq")
        details = self._actions.held_details(seq) if type(seq) is int else None
        self._send(view_text(notice, details))
        return None

    def _ask_batch(self, hold_id: str, kind: str) -> str | None:
        notice = self._notice_of(hold_id)
        if notice is None:
            return "Esa retención ya no está abierta."
        if kind not in (notice.get("batches") or []):
            return "Esta petición no puede abrir ese lote."
        left = notice.get("expires_in_s")
        ttl = min(CONFIRM_TTL, float(left)) if type(left) is int and left > 0 else CONFIRM_TTL
        cancel = self._book.issue(Action.BATCH_CANCEL, ttl=ttl, single_use=True, hold_id=hold_id)
        confirm = self._book.issue(
            Action.BATCH_CONFIRM, ttl=ttl, single_use=True, group=cancel, hold_id=hold_id, kind=kind
        )
        message_id = self._send(
            batch_question(notice, kind), [[("Sí, crear el lote", confirm), ("Cancelar", cancel)]]
        )
        if message_id is None:
            self._book.forget([confirm, cancel])
            return None
        self._book.bind([confirm, cancel], message_id)
        return None

    def list_holds(self) -> str | None:
        """`/retenidas`: the open holds, each sent again with its buttons (MAX_LISTED)."""
        pending = self._actions.pending_holds()
        if not pending:
            return "No hay ninguna petición retenida."
        shown = pending[:MAX_LISTED]
        more = len(pending) - len(shown)
        head = f"Hay {len(pending)} retenidas abiertas; te las mando con sus botones."
        if more > 0:
            head += f" Van las {len(shown)} más antiguas; el resto, con `backtide retenidas`."
        self._send(head)
        for summary in shown:
            hold_id = str(summary.get("hold_id"))
            notice = self._notice_of(hold_id) or dict(summary)
            notice["expires_in_s"] = summary.get("expires_in_s")
            self.send_notice(notice)
        return None

    def list_batches(self) -> str | None:
        """`/lotes`: the active batches, with a "Revocar N" for each."""
        rules = self._actions.batches()
        if not rules:
            return "No hay lotes activos."
        tokens: list[str] = []
        row: list[tuple[str, str]] = []
        rows: list[list[tuple[str, str]]] = []
        for n, rule in enumerate(rules, start=1):
            ttl = float(max(1, rule.get("left_s") or 0))
            token = self._book.issue(
                Action.BATCH_END, ttl=ttl, single_use=True, rule_id=str(rule.get("rule_id"))
            )
            tokens.append(token)
            row.append((f"Revocar {n}", token))
            if len(row) == 3:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        message_id = self._send(batches_text(rules), rows)
        if message_id is None:
            self._book.forget(tokens)
            return None
        self._book.bind(tokens, message_id)
        return None
