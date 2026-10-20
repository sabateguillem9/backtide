"""The Telegram Bot API (``api.telegram.org``), as grammy in OpenClaw uses it. Pure.

Every call is ``/bot<token>/<method>``, by ``GET`` or ``POST``, with its parameters in the
query, a JSON body, a urlencoded form or a multipart form; method names are case-insensitive
(docs/32, section 3). So the HTTP method never decides here: ``GET .../sendMessage?chat_id=..``
is a send. Long polling (``getUpdates``) and the rest of ``get*`` are reads.

- SEND: the ``send*`` methods of the table (recipient: ``chat_id``).
- FORWARD: ``forwardMessage(s)`` and ``copyMessage(s)``: existing content, never batched.
- CHANGE: ``editMessage*``, ``deleteMessage(s)`` (docs/32, section 8: held outside the trusted
  chats), reactions, pins, stopping a poll or a live location.
- ADMIN (risk 3): ``setWebhook``, ``logOut``, ``close`` and the administration of chats.
- READ (passes): ``get*``, ``sendChatAction``, ``answerCallbackQuery``, ``deleteWebhook``,
  ``setMyCommands``, ``deleteMyCommands`` and file downloads (``GET /file/bot<token>/...``).
- Anything else: UNKNOWN.
"""

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
    first_lines,
    has_secret,
    opt_clean,
    rpc_params,
    semantic_canonical,
    split_path,
    unknown,
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
     "editmessagelivelocation", "stopmessagelivelocation", "stoppoll", "deletemessage",
     "deletemessages", "setmessagereaction", "pinchatmessage", "unpinchatmessage",
     "unpinallchatmessages", "editmessagechecklist"}
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
     "setmyshortdescription", "setmydefaultadministratorrights", "setchatmenubutton"}
)  # fmt: skip
_PASS = {
    "sendchataction": Note.TYPING,
    "answercallbackquery": Note.BOT_SETUP,
    "deletewebhook": Note.BOT_SETUP,
    "setmycommands": Note.BOT_SETUP,
    "deletemycommands": Note.BOT_SETUP,
}
_TEXT_PARAMS = ("text", "caption", "question")


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host in HOSTS


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
    if "chat_id" in params:
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
    text = _text(params, method)
    if text is not None and not isinstance(text, str):
        raise Unreadable
    if len(files) > MAX_ATTACHMENTS:
        raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    shown = []
    entries = []
    secret = text is not None and has_secret(text, scrub)
    for part in files:
        item, entry = attachment(part.filename or part.name, part.type, part.data, scrub)
        shown.append(item)
        entries.append(entry)
        if part.filename and has_secret(part.filename, scrub):
            secret = True
        if _texty(part.data) and has_secret(part.data.decode("utf-8"), scrub):
            secret = True
    for name, value in params.items():
        if name not in _TEXT_PARAMS and isinstance(value, str) and has_secret(value, scrub):
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


def _texty(data: bytes) -> bool:
    """A small file that is UTF-8 text: searched for secrets (a key sent as a document)."""
    if len(data) > 1024 * 1024:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True
