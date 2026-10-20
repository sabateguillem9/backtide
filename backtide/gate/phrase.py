"""The sentence a held request is told with (docs/32, sections 4 and 11): what a translator's
reading says it does, in Spanish, in one line that reads well on a phone. Pure: no I/O.

``describe(reading)`` takes a checked ``gate.reading`` (``protocol.check_reading``). Its words are
ours; the agent's texts (recipients, subject, first lines, target, attachment names) are only
quoted, already struck and cut by the translator (and struck again by backtide when recorded),
on one line and without control characters. Inside «…» the agent's own quote marks become plain
ones, and inside our brackets its brackets become square ones: it can never close our quote and
write something that reads as ours, such as "(ya aprobado)" (review of T10-3, L8). T10-4's
alert and the web (T10-5) escape them for their medium: here they are data, never markup.
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
    "fetches_url": "la plataforma descargará esa dirección",
    "inline_message": "un mensaje en línea: puede estar en cualquier chat",
}
# Quote marks the agent could use to close our «…» and write after it as if it were ours
# (review of T10-3, L8): inside a quote they become plain ones.
_QUOTES = str.maketrans(
    {"«": '"', "»": '"', "‹": "'", "›": "'", "“": '"', "”": '"', "„": '"', "‟": '"',
     "〝": '"', "〞": '"', "＂": '"'}
)  # fmt: skip
# And inside our brackets, the brackets.
_BRACKETS = str.maketrans({"(": "[", ")": "]", "（": "[", "）": "]"})


def api_name(translator: str) -> str:
    """The API's name in our words ("Telegram", "Gmail"...), never the agent's."""
    return _API.get(translator, "Una API")


def action(reading: Mapping[str, Any]) -> str:
    """ "<API>: <qué hace>", only our words (T10-4's notice puts the agent's apart)."""
    translator = str(reading.get("translator", ""))
    effect = str(reading.get("effect", "unknown"))
    if effect == "unknown":
        what = "una petición que backtide no entiende"
    else:
        noun = ("un correo" if translator in _MAIL else "un mensaje") if effect in (
            "send", "forward"
        ) else ""  # fmt: skip
        what = " ".join(part for part in (_VERBS.get(effect, "cambiar"), noun) if part)
    return f"{api_name(translator)}: {what}"


def note_texts(reading: Mapping[str, Any]) -> list[str]:
    """The reading's notes in our words (our fixed texts, never the agent's)."""
    texts = [_NOTES[note] for note in reading.get("notes") or [] if note in _NOTES]
    if reading.get("cut"):
        texts.append("resumida: era demasiado larga")
    return list(dict.fromkeys(texts))


def describe(reading: Mapping[str, Any]) -> str:
    """One line: "<API>: <qué hace> <a quién>: «<asunto o primeras líneas>» (<notas>)"."""
    translator = str(reading.get("translator", ""))
    operation = reading.get("target")
    parts = [action(reading)]
    recipients = _recipients(translator, reading.get("recipients") or [])
    if recipients:
        parts.append(recipients)
    sentence = " ".join(parts)
    quoted = reading.get("subject") or reading.get("first_lines")
    if quoted:
        sentence += f": «{_line(str(quoted)).translate(_QUOTES)}»"
    extra = []
    if operation:
        extra.append(_line(str(operation)).translate(_QUOTES).translate(_BRACKETS))
    attachments = reading.get("attachments") or []
    if attachments:
        extra.append("1 adjunto" if len(attachments) == 1 else f"{len(attachments)} adjuntos")
    extra += note_texts(reading)
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
