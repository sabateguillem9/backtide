"""The sentence a held request is told with (docs/32, sections 4 and 11): what a translator's
reading says it does, in one line that reads well on a phone. Pure: no I/O.

Spanish is the language of the black box, the Telegram notice and the terminal, and the default
of every function here. ``action``, ``note_texts`` and ``api_name`` also speak English
(``lang="en"``) for the English web: the same words, from the tables below, never the agent's.

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
RECIPIENT_CHARS = 120  # a recipient longer than this is shown cut in the middle (cut_middle)
_SHOWN_RECIPIENTS = 3
_API = {
    "telegram": "Telegram",
    "gmail": "Gmail",
    "graph_mail": "Outlook",
    "slack": "Slack",
    "discord": "Discord",
    "github_graphql": "GitHub",
    "git": "git",
    "read_post": "Un buscador",
}
_API_EN = {**_API, "read_post": "A search engine"}
_NO_API = {"es": "Una API", "en": "An API"}
# A push (translate/git.py): what it does, and what backtide cannot know of it (a note).
_GIT = {"change": "push a un repositorio", "delete": "push que borra ramas o etiquetas"}
_GIT_UNSEEN = "backtide no ve el código que lleva"
_GIT_EN = {"change": "push to a repository", "delete": "push that deletes branches or tags"}
_GIT_UNSEEN_EN = "backtide does not see the code it carries"
_MAIL = frozenset({"gmail", "graph_mail"})
_VERBS = {
    "send": "enviar",
    "forward": "reenviar",
    "change": "cambiar",
    "delete": "borrar",
    "admin": "cambiar la administración",
    "read": "leer",
}
_VERBS_EN = {
    "send": "send",
    "forward": "forward",
    "change": "change",
    "delete": "delete",
    "admin": "change account settings",
    "read": "read",
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
    "moves_ref": (
        "mueve una rama o etiqueta que ya existe: backtide no puede saber si es un push forzado"
    ),
}
_NOTES_EN = {
    "content_unseen": "what it carries cannot be seen",
    "batch": "an API batch with other requests",
    "too_large": "too large to read",
    "secret_seen": "it carried a secret (struck out)",
    "deletes_message": "it deletes a message",
    "to_trash": "to the trash",
    "webhook": "through a webhook",
    "alternative_differs": "its HTML says something other than its text",
    "idn_domain": "a domain with non-Latin characters",
    "method_override": "a header changes its method",
    "duplicate": "a repeated field",
    "bad_address": "a recipient that cannot be understood",
    "translator_failed": "the translator failed",
    "fetches_url": "the platform will download that address",
    "inline_message": "an inline message: it may be in any chat",
    "moves_ref": (
        "it moves a branch or tag that already exists: backtide cannot know if it is a forced push"
    ),
}
# Everything else our phrase says, by language. A language we do not speak reads as Spanish.
_WORDS: dict[str, dict[str, Any]] = {
    "es": {
        "api": _API,
        "git": _GIT,
        "git_unseen": _GIT_UNSEEN,
        "verbs": _VERBS,
        "notes": _NOTES,
        "unknown": "una petición que backtide no entiende",
        "mail": "un correo",
        "message": "un mensaje",
        "cut": "resumida: era demasiado larga",
    },
    "en": {
        "api": _API_EN,
        "git": _GIT_EN,
        "git_unseen": _GIT_UNSEEN_EN,
        "verbs": _VERBS_EN,
        "notes": _NOTES_EN,
        "unknown": "a request backtide does not understand",
        "mail": "an email",
        "message": "a message",
        "cut": "cut short: it was too long",
    },
}
LANGUAGES = tuple(_WORDS)
# Quote marks the agent could use to close our «…» and write after it as if it were ours
# (review of T10-3, L8): inside a quote they become plain ones.
_QUOTES = str.maketrans(
    {"«": '"', "»": '"', "‹": "'", "›": "'", "“": '"', "”": '"', "„": '"', "‟": '"',
     "〝": '"', "〞": '"', "＂": '"'}
)  # fmt: skip
# And inside our brackets, the brackets.
_BRACKETS = str.maketrans({"(": "[", ")": "]", "（": "[", "）": "]"})


def _words(lang: str) -> dict[str, Any]:
    return _WORDS.get(lang, _WORDS["es"])


def api_name(translator: str, lang: str = "es") -> str:
    """The API's name in our words ("Telegram", "Gmail"...), never the agent's."""
    return _words(lang)["api"].get(translator, _NO_API.get(lang, _NO_API["es"]))


def action(reading: Mapping[str, Any], lang: str = "es") -> str:
    """ "<API>: <qué hace>", only our words (T10-4's notice puts the agent's apart)."""
    words = _words(lang)
    translator = str(reading.get("translator", ""))
    effect = str(reading.get("effect", "unknown"))
    if effect == "unknown":
        what = words["unknown"]
    elif translator == "git" and effect in words["git"]:
        what = words["git"][effect]
    else:
        noun = (words["mail"] if translator in _MAIL else words["message"]) if effect in (
            "send", "forward"
        ) else ""  # fmt: skip
        what = " ".join(
            part for part in (words["verbs"].get(effect, words["verbs"]["change"]), noun) if part
        )
    return f"{api_name(translator, lang)}: {what}"


def note_texts(reading: Mapping[str, Any], lang: str = "es") -> list[str]:
    """The reading's notes in our words (our fixed texts, never the agent's)."""
    words = _words(lang)
    notes = words["notes"]
    texts = [notes[note] for note in reading.get("notes") or [] if note in notes]
    if reading.get("translator") == "git" and reading.get("effect") in words["git"]:
        texts.append(words["git_unseen"])
    if reading.get("cut"):
        texts.append(words["cut"])
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


def cut_middle(text: str, limit: int = RECIPIENT_CHARS) -> str:
    """``text`` cut in the middle when it is longer than ``limit``, saying how many characters
    were left out: ``ana@ejemplo.com.…(190)….malo.io``. Two thirds of it are the end, which is
    what tells an address apart (its domain): cutting only the end would show the start of
    ``ana@ejemplo.com.<190 characters>.malo.io`` as if it were ``ana@ejemplo.com`` (final
    review of T10, finding 4). A normalized address never has "…" nor parentheses."""
    if len(text) <= limit:
        return text
    head = limit // 3
    tail = limit - head
    return f"{text[:head]}…({len(text) - head - tail})…{text[-tail:]}"


def _recipients(translator: str, recipients: Sequence[Any]) -> str:
    if not recipients or translator == "git":
        return ""  # a push's refs are in its target, with what happens to each one
    shown = ", ".join(cut_middle(_line(str(item))) for item in recipients[:_SHOWN_RECIPIENTS])
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
