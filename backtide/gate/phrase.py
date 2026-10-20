"""The sentence a held request is told with (docs/32, sections 4 and 11): what a translator's
reading says it does, in Spanish, in one line that reads well on a phone. Pure: no I/O.

``describe(reading)`` takes a checked ``gate.reading`` (``protocol.check_reading``). Its words are
ours; the agent's texts (recipients, subject, first lines, target, attachment names) are only
quoted, already struck and cut by the translator (and struck again by backtide when recorded),
on one line and without control characters. T10-4's alert and the web (T10-5) escape them for
their medium: here they are data, never markup.
"""

from collections.abc import Mapping, Sequence
from typing import Any

MAX_CHARS = 400
_SHOWN_RECIPIENTS = 3
_API = {
    "telegram": "Telegram",
    "gmail": "Gmail",
    "graph_mail": "Outlook",
    "slack": "Slack",
    "discord": "Discord",
    "github_graphql": "GitHub",
    "read_post": "Un buscador",
}
_MAIL = frozenset({"gmail", "graph_mail"})
_VERBS = {
    "send": "enviar",
    "forward": "reenviar",
    "change": "cambiar",
    "delete": "borrar",
    "admin": "cambiar la administración",
    "read": "leer",
}
_NOTES = {
    "content_unseen": "no se ve qué lleva",
    "batch": "un lote de la API con otras peticiones",
    "too_large": "demasiado grande para leerla",
    "secret_seen": "llevaba un secreto (tachado)",
    "deletes_message": "borra un mensaje",
    "to_trash": "a la papelera",
    "webhook": "por un webhook",
    "alternative_differs": "su HTML dice otra cosa que su texto",
    "idn_domain": "un dominio con caracteres no latinos",
    "method_override": "una cabecera cambia su método",
    "duplicate": "un campo repetido",
    "bad_address": "un destinatario que no se entiende",
    "translator_failed": "el traductor falló",
}


def describe(reading: Mapping[str, Any]) -> str:
    """One line: "<API>: <qué hace> <a quién>: «<asunto o primeras líneas>» (<notas>)"."""
    translator = str(reading.get("translator", ""))
    effect = str(reading.get("effect", "unknown"))
    api = _API.get(translator, translator or "Una API")
    mail = translator in _MAIL
    operation = reading.get("target")
    if effect == "unknown":
        action = "una petición que backtide no entiende"
    else:
        what = ("un correo" if mail else "un mensaje") if effect in ("send", "forward") else ""
        action = " ".join(part for part in (_VERBS.get(effect, effect), what) if part)
    parts = [f"{api}: {action}"]
    recipients = _recipients(translator, reading.get("recipients") or [])
    if recipients:
        parts.append(recipients)
    sentence = " ".join(parts)
    quoted = reading.get("subject") or reading.get("first_lines")
    if quoted:
        sentence += f": «{_line(str(quoted))}»"
    extra = []
    if operation:
        extra.append(_line(str(operation)))
    attachments = reading.get("attachments") or []
    if attachments:
        extra.append("1 adjunto" if len(attachments) == 1 else f"{len(attachments)} adjuntos")
    extra += [_NOTES[note] for note in reading.get("notes") or [] if note in _NOTES]
    if reading.get("cut"):
        extra.append("resumida: era demasiado larga")
    if extra:
        sentence += f" ({'; '.join(dict.fromkeys(extra))})"
    return sentence[:MAX_CHARS]


def _recipients(translator: str, recipients: Sequence[Any]) -> str:
    if not recipients:
        return ""
    shown = ", ".join(_line(str(item)) for item in recipients[:_SHOWN_RECIPIENTS])
    more = len(recipients) - _SHOWN_RECIPIENTS
    if more > 0:
        shown += f" y {more} más"
    if translator == "telegram":
        return f"al chat {shown}" if len(recipients) == 1 else f"a los chats {shown}"
    if translator in ("slack", "discord"):
        return f"al canal {shown}" if len(recipients) == 1 else f"a los canales {shown}"
    return f"a {shown}"


def _line(text: str) -> str:
    """One line, without control or invisible characters (a newline reads as " / ")."""
    flat = " / ".join(piece.strip() for piece in text.splitlines() if piece.strip())
    return "".join(char for char in flat if char.isprintable())
