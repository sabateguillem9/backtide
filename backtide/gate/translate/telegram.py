"""The Telegram Bot API (``api.telegram.org``), as grammy in OpenClaw uses it. Pure.

Every call is ``/bot<token>/<method>``, by ``GET`` or ``POST``, with its parameters in the
query, a JSON body, a urlencoded form or a multipart form; method names are case-insensitive
(docs/32, section 3). So the HTTP method never decides here: ``GET .../sendMessage?chat_id=..``
is a send. Long polling (``getUpdates``) and the rest of ``get*`` are reads.

- SEND: the ``send*`` methods of the table (recipient: ``chat_id``).
- FORWARD: ``forwardMessage(s)`` and ``copyMessage(s)``: existing content, never batched.
- CHANGE: ``editMessage*``, reactions, pins, stopping a poll or a live location, and an
  ``answerCallbackQuery`` with a ``text`` or a ``url`` (it shows them to whoever pressed).
  An edit by ``inline_message_id`` (which Telegram reads before ``chat_id``) may be in any chat:
  its recipient is ``inline:<id>``, never trusted (review of T10-3, H2).
- A send or a change that makes Telegram fetch a URL (a file given by URL, a link preview of
  a URL in the text, ``link_preview_options.url``) is never trusted (``FETCHES_URL``), and the
  person reads the URL (review of T10-3, M3).
- DELETE (risk 3, never trusted or batched): ``deleteMessage(s)``.
- ADMIN (risk 3): ``setWebhook``, ``logOut``, ``close``, the administration of chats, and the
  bot's public texts: ``setMyCommands``, ``setMyName``, ``setMyDescription``...
- READ (passes): ``get*``, ``sendChatAction``, a bare ``answerCallbackQuery``, ``deleteWebhook``,
  ``deleteMyCommands`` and file downloads (``GET /file/bot<token>/...``).
- Anything else: UNKNOWN.
"""

import hashlib
import re
from typing import Any

from backtide.gate.translate.base import (
    MAX_ATTACHMENTS,
    READ_METHODS,
    TARGET_CHARS,
    WAIT_TELEGRAM,
    WAIT_TELEGRAM_FILES,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    attachment,
    data_has_secret,
    fetch_target,
    find_url,
    first_lines,
    has_secret,
    has_secret_in,
    is_http_url,
    opt_clean,
    rpc_params,
    semantic_canonical,
    split_path,
    strict_json,
    unknown,
    walk_fields,
)

NAME = "telegram"
HOSTS = frozenset({"api.telegram.org"})

_BOT_RE = re.compile(r"bot([0-9]{1,20}:[A-Za-z0-9_-]{20,128})", re.ASCII)
_CHAT_NUMBER_RE = re.compile(r"[+-]?[0-9]{1,20}", re.ASCII)
_CHAT_NAME_RE = re.compile(r"@[A-Za-z0-9_]{1,64}", re.ASCII)

_SEND_TEXT = frozenset({"sendmessage"})
_SEND_FILES = frozenset(
    {"sendphoto", "senddocument", "sendvideo", "sendaudio", "sendvoice", "sendanimation",
     "sendvideonote", "sendmediagroup", "sendsticker", "sendpaidmedia"}
)  # fmt: skip
_SEND_OTHER = frozenset(
    {"sendlocation", "sendvenue", "sendcontact", "sendpoll", "senddice", "sendinvoice",
     "sendgame", "sendchecklist"}
)  # fmt: skip
_SEND = _SEND_TEXT | _SEND_FILES | _SEND_OTHER
_FORWARD = frozenset({"forwardmessage", "forwardmessages", "copymessage", "copymessages"})
_CHANGE = frozenset(
    {"editmessagetext", "editmessagecaption", "editmessagemedia", "editmessagereplymarkup",
     "editmessagelivelocation", "stopmessagelivelocation", "stoppoll", "setmessagereaction",
     "pinchatmessage", "unpinchatmessage", "unpinallchatmessages", "editmessagechecklist",
     "answercallbackquery"}
)  # fmt: skip
_DELETES = frozenset({"deletemessage", "deletemessages"})
_ADMIN = frozenset(
    {"setwebhook", "logout", "close", "banchatmember", "unbanchatmember", "restrictchatmember",
     "promotechatmember", "setchatadministratorcustomtitle", "banchatsenderchat",
     "unbanchatsenderchat", "setchatpermissions", "exportchatinvitelink",
     "createchatinvitelink", "editchatinvitelink", "revokechatinvitelink",
     "createchatsubscriptioninvitelink", "editchatsubscriptioninvitelink",
     "approvechatjoinrequest", "declinechatjoinrequest", "setchatphoto", "deletechatphoto",
     "setchattitle", "setchatdescription", "leavechat", "setchatstickerset",
     "deletechatstickerset", "createforumtopic", "editforumtopic", "closeforumtopic",
     "reopenforumtopic", "deleteforumtopic", "setmyname", "setmydescription",
     "setmyshortdescription", "setmydefaultadministratorrights", "setchatmenubutton",
     "setmycommands"}
)  # fmt: skip
_PASS = {
    "sendchataction": Note.TYPING,
    "answercallbackquery": Note.BOT_SETUP,  # only without text or url (see read)
    "deletewebhook": Note.BOT_SETUP,
    "deletemycommands": Note.BOT_SETUP,
}
_CALLBACK_SHOWS = ("text", "url")
_TEXT_PARAMS = ("text", "caption", "question")
# Parameters that take a file, which Telegram downloads when given an HTTP URL (Bot API, "Sending
# files"), at any depth (``media`` of an album or of editMessageMedia), and an invoice's photo.
_FILE_PARAMS = frozenset(
    {"photo", "document", "video", "animation", "audio", "voice", "sticker", "video_note",
     "thumbnail", "thumb", "media", "cover", "photo_url", "png_sticker", "tgs_sticker",
     "webm_sticker"}
)  # fmt: skip
# The methods whose text gets a link preview (unless it is turned off).
_PREVIEWED = frozenset({"sendmessage", "editmessagetext"})
_INLINE_RE = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host in HOSTS


def credential_segments(segments: tuple[str, ...]) -> frozenset[int]:
    """Which segments of a path (split on "/", the query apart) are the bot's token: the gate
    leaves them out when it looks for a secret in the URL (the token is the API's own way to
    authenticate, and the black box strikes it anyway)."""
    return frozenset(i for i, segment in enumerate(segments) if _BOT_RE.fullmatch(segment))


def chat_id(value: object) -> str | None:
    """A chat as Telegram reads ``chat_id``: an integer (canonical form) or ``@username``
    (case-insensitive). None for anything else (a bool, a float, a list...)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if abs(value) < 10**20 else None
    if not isinstance(value, str):
        return None
    if _CHAT_NUMBER_RE.fullmatch(value):
        return str(int(value))
    if _CHAT_NAME_RE.fullmatch(value):
        return value.lower()
    return None


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
    except Unreadable as error:
        return unknown(NAME, Shape.TELEGRAM, WAIT_TELEGRAM, error.note)
    if len(segments) >= 3 and segments[0] == "file" and _BOT_RE.fullmatch(segments[1]):
        token = segments[1][3:]
        account = account_id(context, NAME, token)
        if view.method in READ_METHODS and not view.body:
            return Reading(
                NAME,
                "file_download",
                Effect.READ,
                Shape.TELEGRAM,
                WAIT_TELEGRAM,
                account=account,
                path_credential=True,
                notes=(Note.DOWNLOAD,),
            )
        return _unknown(account, Note.NOT_IN_TABLE)
    match = _BOT_RE.fullmatch(segments[0]) if len(segments) == 2 else None
    if match is None:
        return unknown(NAME, Shape.TELEGRAM, WAIT_TELEGRAM, Note.NOT_IN_TABLE)
    account = account_id(context, NAME, match.group(1))
    method = segments[1].lower()
    if view.method not in ("GET", "POST"):
        return _unknown(account, Note.NOT_IN_TABLE)
    if method == "answercallbackquery":
        try:
            params, files = rpc_params(view, query)
            if any(name in params for name in _CALLBACK_SHOWS) or files:
                return _reading(view, context, method, Effect.CHANGE, account, params, files)
        except Unreadable as error:
            return _unknown(account, error.note)
    if method.startswith("get") or method in _PASS:
        if view.method == "GET" and view.body:
            return _unknown(account, Note.UNPARSED)
        note = _PASS.get(method)
        return Reading(
            NAME,
            method if note else "get",
            Effect.READ,
            Shape.TELEGRAM,
            WAIT_TELEGRAM,
            account=account,
            path_credential=True,
            notes=(note,) if note else (),
        )
    effect = _effect(method)
    if effect is None:
        return _unknown(account, Note.NOT_IN_TABLE, target=opt_clean(method, context.scrub, 64))
    try:
        params, files = rpc_params(view, query)
        return _reading(view, context, method, effect, account, params, files)
    except Unreadable as error:
        return _unknown(account, error.note)


def _unknown(account: str | None, note: Note, *, target: str | None = None) -> Reading:
    return unknown(
        NAME,
        Shape.TELEGRAM,
        WAIT_TELEGRAM,
        note,
        account=account,
        target=target,
        path_credential=True,
    )


def _effect(method: str) -> Effect | None:
    if method in _SEND:
        return Effect.SEND
    if method in _FORWARD:
        return Effect.FORWARD
    if method in _DELETES:
        return Effect.DELETE
    if method in _CHANGE:
        return Effect.CHANGE
    if method in _ADMIN:
        return Effect.ADMIN
    return None


def _reading(
    view: RequestView,
    context: Context,
    method: str,
    effect: Effect,
    account: str | None,
    params: dict[str, Any],
    files: list[Any],
) -> Reading:
    scrub = context.scrub
    notes: list[Note] = []
    recipients: tuple[str, ...] = ()
    if "inline_message_id" in params and effect is Effect.CHANGE:
        # Telegram reads it before chat_id: the message may be in any chat (H2).
        recipients = (_inline(params["inline_message_id"]),)
        notes.append(Note.INLINE_MESSAGE)
    elif "inline_message_id" in params:
        raise Unreadable(Note.NOT_IN_TABLE)
    elif "chat_id" in params:
        chat = chat_id(params["chat_id"])
        if chat is None:
            raise Unreadable(Note.BAD_ADDRESS)
        recipients = (chat,)
    elif effect is Effect.SEND or effect is Effect.FORWARD:
        raise Unreadable(Note.BAD_ADDRESS)  # a send to no one Telegram would accept?
    target = None
    if effect is Effect.FORWARD:
        source = chat_id(params.get("from_chat_id"))
        if source is None:
            raise Unreadable(Note.BAD_ADDRESS)
        target = f"from chat {source}"[:TARGET_CHARS]
    if method in _DELETES:
        notes.append(Note.DELETES_MESSAGE)
    if method == "answercallbackquery" and isinstance(params.get("url"), str):
        target = opt_clean(f"opens {params['url']}", scrub, TARGET_CHARS)
    fetched = _fetched_url(method, params) if effect in (Effect.SEND, Effect.CHANGE) else None
    if fetched is not None:
        notes.append(Note.FETCHES_URL)
        target = target or fetch_target(fetched, scrub)
    text = _text(params, method)
    if text is not None and not isinstance(text, str):
        raise Unreadable
    if len(files) > MAX_ATTACHMENTS:
        raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    shown = []
    entries = []
    # Every parameter at any depth: the text, but also a keyboard's buttons and their URLs
    # (``reply_markup``), a poll's options, a media group's captions.
    secret = has_secret_in(params, scrub)
    for part in files:
        item, entry = attachment(part.filename or part.name, part.type, part.data, scrub)
        shown.append(item)
        entries.append(entry)
        if part.filename and has_secret(part.filename, scrub):
            secret = True
        if data_has_secret(part.data, scrub):
            secret = True
    if secret:
        notes.append(Note.SECRET_SEEN)
    canonical = semantic_canonical(
        translator=NAME,
        host=view.host,
        port=view.port,
        operation=method,
        account=account,
        recipients=recipients,
        fields=params,
        files=entries,
    )
    wait = WAIT_TELEGRAM_FILES if method in _SEND_FILES or files else WAIT_TELEGRAM
    if method == "editmessagemedia":
        wait = WAIT_TELEGRAM_FILES
    return Reading(
        translator=NAME,
        operation=method,
        effect=effect,
        shape=Shape.TELEGRAM,
        wait_s=wait,
        account=account,
        recipients=recipients,
        first_lines=first_lines(text, scrub),
        target=target,
        attachments=tuple(shown),
        secret_seen=secret,
        path_credential=True,
        notes=tuple(notes),
        canonical=canonical,
    )


def _inline(value: object) -> str:
    """``inline:<id>``: the id when plain, else a short digest of it (it is only shown)."""
    text = str(value) if isinstance(value, int | str) and not isinstance(value, bool) else ""
    if _INLINE_RE.fullmatch(text):
        return f"inline:{text}"
    return "inline:#" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _fetched_url(method: str, params: dict[str, Any]) -> str | None:
    """The first URL that this call makes Telegram's servers fetch, or None: a file given by
    URL (at any depth), ``link_preview_options.url``, or a link in a previewed text or its
    entities (``text_link``) unless the preview is off (``link_preview_options.is_disabled``,
    ``disable_web_page_preview``). A button's URL is only opened by whoever presses it."""
    for key, value in walk_fields({k: v for k, v in params.items() if k != "reply_markup"}):
        if key in _FILE_PARAMS and is_http_url(value):
            return str(value).strip()
    if method not in _PREVIEWED:
        return None
    options = _parsed(params.get("link_preview_options"))
    options = options if isinstance(options, dict) else {}
    if options.get("is_disabled") in (True, "true") or params.get("disable_web_page_preview") in (
        True,
        "true",
    ):
        return None
    if isinstance(options.get("url"), str) and options["url"].strip():
        return options["url"].strip()
    texts: list[object] = [params.get("text")]
    entities = _parsed(params.get("entities"))
    if isinstance(entities, list):
        texts += [item.get("url") for item in entities if isinstance(item, dict)]
    for text in texts:
        if isinstance(text, str):
            found = find_url(text)
            if found is not None:
                return found
    return None


def _parsed(value: object) -> object:
    """A form's JSON text as JSON (Telegram takes objects as JSON in a form); else as is."""
    if isinstance(value, str) and value.lstrip()[:1] in ("{", "["):
        try:
            return strict_json(value)
        except Unreadable:
            return value
    return value


def _text(params: dict[str, Any], method: str) -> object:
    for name in _TEXT_PARAMS:
        if name in params:
            return params[name]
    if method == "sendmediagroup":
        media = params.get("media")
        if isinstance(media, str):
            return None  # a JSON text in a form: its captions are not read, only shown whole
        if isinstance(media, list):
            for item in media:
                if isinstance(item, dict) and isinstance(item.get("caption"), str):
                    return item["caption"]
    return None
