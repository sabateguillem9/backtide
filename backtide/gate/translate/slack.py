"""Slack: the Web API (``slack.com/api/<method>``, also on a workspace's own subdomain), incoming
webhooks (``hooks.slack.com``) and file uploads (``files.slack.com``), as ``@slack/web-api``
in OpenClaw uses them (docs/32, section 3). Pure.

The Web API is RPC-style: every method takes ``GET`` or ``POST``, with its parameters in the
query, a JSON body or a urlencoded form, so the method name decides, never the HTTP method.

- SEND: ``chat.postMessage``, ``chat.postEphemeral``, ``chat.scheduleMessage``,
  ``chat.meMessage``, ``files.completeUploadExternal`` (recipients: ``channel``,
  ``channel_id`` or ``channels``), the legacy ``files.upload``, and a POST to an incoming
  webhook (recipient: ``webhook:T…/B…``, never its secret).
- CHANGE: ``chat.update``, ``chat.delete`` (held outside the trusted channels), reactions,
  pins, bookmarks, topics, joining a channel.
- DELETE: ``files.delete``. ADMIN (risk 3): inviting, kicking, creating, archiving or renaming
  channels, ``admin.*``, making a file public.
- READ (passes): ``auth.test``, ``conversations.list/history/info/replies/members/open``, the
  ``users.*`` reads, ``team.info``, ``files.info/list``, Socket Mode's ``apps.connections.open``,
  ``files.getUploadURLExternal`` and the upload to ``files.slack.com`` (it reaches no one until
  ``files.completeUploadExternal``). Web pages on ``slack.com`` (outside ``/api``) by ``GET``.
- Anything else: UNKNOWN.
"""

import hashlib
import re
from typing import Any

from backtide.gate.translate.base import (
    MAX_ATTACHMENTS,
    MAX_RECIPIENTS,
    READ_METHODS,
    WAIT_DEFAULT,
    Attachment,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    credential,
    decode_utf8,
    first_lines,
    has_secret,
    json_object,
    media_type,
    opt_clean,
    parse_pairs,
    rpc_params,
    semantic_canonical,
    split_path,
    strict_json,
    unknown,
)

NAME = "slack"
WEBHOOK_HOST = "hooks.slack.com"
FILES_HOST = "files.slack.com"

_CHANNEL_RE = re.compile(r"[A-Za-z0-9_.#@-]{1,80}", re.ASCII)
_HOOK_ID_RE = re.compile(r"[A-Z0-9]{2,32}", re.ASCII)

_SEND = frozenset(
    {"chat.postmessage", "chat.postephemeral", "chat.schedulemessage", "chat.memessage",
     "files.completeuploadexternal", "files.upload"}
)  # fmt: skip
_CHANGE = frozenset(
    {"chat.update", "chat.delete", "chat.deletescheduledmessage", "chat.unfurl",
     "reactions.add", "reactions.remove", "pins.add", "pins.remove", "bookmarks.add",
     "bookmarks.edit", "bookmarks.remove", "conversations.settopic",
     "conversations.setpurpose", "conversations.join", "conversations.mark",
     "files.revokepublicurl"}
)  # fmt: skip
_DELETE = frozenset({"files.delete", "files.comments.delete"})
_ADMIN = frozenset(
    {"conversations.invite", "conversations.kick", "conversations.create",
     "conversations.archive", "conversations.unarchive", "conversations.rename",
     "conversations.leave", "conversations.close", "conversations.inviteshared",
     "conversations.acceptsharedinvite", "files.sharedpublicurl", "usergroups.create",
     "usergroups.update", "usergroups.disable", "usergroups.enable", "usergroups.users.update",
     "apps.uninstall", "auth.revoke"}
)  # fmt: skip
_READ = frozenset(
    {"api.test", "auth.test", "conversations.list", "conversations.history",
     "conversations.info", "conversations.replies", "conversations.members",
     "users.info", "users.list", "users.lookupbyemail", "users.conversations",
     "users.getpresence", "users.profile.get", "users.identity", "team.info", "files.info",
     "files.list", "emoji.list", "bots.info", "reactions.get", "reactions.list", "pins.list",
     "bookmarks.list", "chat.getpermalink", "search.messages", "search.files", "search.all",
     "apps.connections.open", "rtm.connect", "usergroups.list", "usergroups.users.list",
     "dnd.info", "team.profile.get"}
)  # fmt: skip
_PASS = {
    "conversations.open": Note.OPEN_DM,
    "files.getuploadurlexternal": Note.UPLOAD_STEP,
}
_DELETES = frozenset({"chat.delete", "chat.deletescheduledmessage"})


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host == "slack.com" or view.host.endswith(".slack.com")


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
    except Unreadable as error:
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT, error.note)
    if view.host == WEBHOOK_HOST:
        return _webhook(view, context, segments, query)
    if view.host == FILES_HOST:
        return _files_host(view, segments)
    if not segments or segments[0].lower() != "api":
        if view.method in READ_METHODS and not view.body:
            return Reading(NAME, "web_page", Effect.READ, Shape.SLACK, WAIT_DEFAULT)
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT)
    if len(segments) != 2 or view.method not in ("GET", "POST"):
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT)
    try:
        params, files = rpc_params(view, query)
        return _web_api(view, context, segments[1].lower(), params, files)
    except Unreadable as error:
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT, error.note)


def _account(view: RequestView, context: Context, params: dict[str, Any]) -> str | None:
    header = credential(view.headers)
    body_token = params.get("token")
    if header is not None and body_token is not None:
        raise Unreadable(Note.DUPLICATE)  # which one would Slack use?
    token = header if header is not None else body_token
    if token is not None and not isinstance(token, str):
        raise Unreadable
    if isinstance(token, str) and token.lower().startswith("bearer "):
        token = token[7:].strip()
    return account_id(context, NAME, token)


def _web_api(
    view: RequestView, context: Context, method: str, params: dict[str, Any], files: list[Any]
) -> Reading:
    account = _account(view, context, params)
    if method in _READ or method in _PASS:
        note = _PASS.get(method)
        return Reading(
            NAME,
            method,
            Effect.READ,
            Shape.SLACK,
            WAIT_DEFAULT,
            account=account,
            notes=(note,) if note else (),
        )
    if method in _SEND:
        effect = Effect.SEND
    elif method in _CHANGE:
        effect = Effect.CHANGE
    elif method in _DELETE:
        effect = Effect.DELETE
    elif method in _ADMIN or method.startswith("admin."):
        effect = Effect.ADMIN
    else:
        target = opt_clean(method, context.scrub, 64)
        return unknown(
            NAME, Shape.SLACK, WAIT_DEFAULT, Note.NOT_IN_TABLE, account=account, target=target
        )
    recipients = _channels(params)
    if effect is Effect.SEND and not recipients and method != "files.completeuploadexternal":
        raise Unreadable(Note.BAD_ADDRESS)
    scrub = context.scrub
    text = params.get("text")
    if text is None:
        text = params.get("initial_comment")
    if text is not None and not isinstance(text, str):
        raise Unreadable
    if text is None and params.get("blocks") is not None:
        text = "[blocks]"
    attachments = _files(params, files, context)
    notes = [Note.DELETES_MESSAGE] if method in _DELETES else []
    secret = any(
        isinstance(value, str) and name != "token" and has_secret(value, scrub)
        for name, value in params.items()
    )
    if secret:
        notes.append(Note.SECRET_SEEN)
    fields = {name: value for name, value in params.items() if name != "token"}
    entries = [[item.name, item.type, item.size, None] for item in attachments]
    for part in files:
        entries.append([part.filename, part.type, len(part.data), _digest(part.data)])
    return Reading(
        translator=NAME,
        operation=method,
        effect=effect,
        shape=Shape.SLACK,
        wait_s=WAIT_DEFAULT,
        account=account,
        recipients=recipients,
        first_lines=first_lines(text, scrub),
        target=_target(params, context),
        attachments=attachments,
        secret_seen=secret,
        notes=tuple(notes),
        canonical=semantic_canonical(
            translator=NAME,
            host=view.host,
            port=view.port,
            operation=method,
            account=account,
            recipients=recipients,
            fields=fields,
            files=entries,
        ),  # fmt: skip
    )


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _channels(params: dict[str, Any]) -> tuple[str, ...]:
    """The channels a call acts on, from ``channel``, ``channel_id`` or ``channels`` (a list
    with commas). More than one of those fields, or an odd value, is Unreadable."""
    given = [name for name in ("channel", "channel_id", "channels") if params.get(name) is not None]
    if len(given) > 1:
        raise Unreadable(Note.DUPLICATE)
    if not given:
        return ()
    value = params[given[0]]
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = value.split(",") if given[0] == "channels" else [value]
    else:
        raise Unreadable(Note.BAD_ADDRESS)
    found: list[str] = []
    for item in items:
        if not isinstance(item, str) or not _CHANNEL_RE.fullmatch(item.strip()):
            raise Unreadable(Note.BAD_ADDRESS)
        found.append(item.strip())
    if len(found) > MAX_RECIPIENTS:
        raise Unreadable(Note.TOO_MANY_RECIPIENTS)
    return tuple(dict.fromkeys(found))


def _files(params: dict[str, Any], parts: list[Any], context: Context) -> tuple[Attachment, ...]:
    """The files a call shares: ``files.completeUploadExternal``'s ``files`` (id and title) and
    the parts of a legacy ``files.upload``."""
    shown: list[Attachment] = []
    listed = params.get("files")
    if isinstance(listed, str):
        listed = strict_json(listed) if listed.strip() else []
    if isinstance(listed, list):
        for item in listed:
            if not isinstance(item, dict):
                raise Unreadable
            title = item.get("title") if isinstance(item.get("title"), str) else item.get("id")
            name = opt_clean(title if isinstance(title, str) else None, context.scrub, 100)
            shown.append(Attachment(name or "(no name)", None, 0))
    elif listed is not None:
        raise Unreadable
    for part in parts:
        name = opt_clean(part.filename or part.name, context.scrub, 100)
        shown.append(Attachment(name or "(no name)", None, len(part.data)))
    if len(shown) > MAX_ATTACHMENTS:
        raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    return tuple(shown)


def _target(params: dict[str, Any], context: Context) -> str | None:
    ts = params.get("ts")
    if isinstance(ts, str):
        return opt_clean(f"message {ts}", context.scrub, 80)
    return None


def _webhook(view: RequestView, context: Context, segments: tuple[str, ...], query: str) -> Reading:
    """``POST hooks.slack.com/services/T…/B…/<secret>``: a send to that webhook."""
    if (
        len(segments) != 4
        or segments[0] != "services"
        or not _HOOK_ID_RE.fullmatch(segments[1])
        or not _HOOK_ID_RE.fullmatch(segments[2])
    ):
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT, path_credential=True)
    account = account_id(context, NAME, "webhook", segments[3])
    if view.method != "POST" or query:
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT, account=account, path_credential=True)
    try:
        kind = media_type(view.headers)
        if kind == "application/x-www-form-urlencoded":
            form = parse_pairs(decode_utf8(view.body))
            if set(form) != {"payload"}:
                raise Unreadable
            payload = json_object(form["payload"])
        elif kind == "application/json" or kind is None:
            payload = json_object(view.body)
        else:
            raise Unreadable
        text = payload.get("text")
        if text is not None and not isinstance(text, str):
            raise Unreadable
        if text is None and payload.get("blocks") is not None:
            text = "[blocks]"
    except Unreadable as error:
        return unknown(
            NAME, Shape.SLACK, WAIT_DEFAULT, error.note, account=account, path_credential=True
        )
    recipient = f"webhook:{segments[1]}/{segments[2]}"
    secret = any(isinstance(v, str) and has_secret(v, context.scrub) for v in payload.values())
    return Reading(
        translator=NAME,
        operation="webhook",
        effect=Effect.SEND,
        shape=Shape.SLACK,
        wait_s=WAIT_DEFAULT,
        account=account,
        recipients=(recipient,),
        first_lines=first_lines(text, context.scrub),
        secret_seen=secret,
        path_credential=True,
        notes=(Note.WEBHOOK, Note.SECRET_SEEN) if secret else (Note.WEBHOOK,),
        canonical=semantic_canonical(
            translator=NAME,
            host=view.host,
            port=view.port,
            operation="webhook",
            account=account,
            recipients=(recipient,),
            fields=payload,
        ),  # fmt: skip
    )


def _files_host(view: RequestView, segments: tuple[str, ...]) -> Reading:
    """``files.slack.com``: the upload step of ``files.getUploadURLExternal`` (it reaches no one
    until ``files.completeUploadExternal``), and downloads."""
    if view.method in READ_METHODS and not view.body:
        return Reading(
            NAME, "file_download", Effect.READ, Shape.SLACK, WAIT_DEFAULT, notes=(Note.DOWNLOAD,)
        )
    if view.method == "POST" and segments[:2] == ("upload", "v1"):
        return Reading(
            NAME,
            "file_upload_step",
            Effect.READ,
            Shape.SLACK,
            WAIT_DEFAULT,
            notes=(Note.UPLOAD_STEP,),
        )
    return unknown(NAME, Shape.SLACK, WAIT_DEFAULT)
