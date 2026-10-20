"""Slack: the Web API (``slack.com/api/<method>``, also on a workspace's own subdomain), incoming
webhooks (``hooks.slack.com``) and file uploads (``files.slack.com``), as ``@slack/web-api``
in OpenClaw uses them (docs/32, section 3). Pure.

The Web API is RPC-style: every method takes ``GET`` or ``POST``, with its parameters in the
query, a JSON body or a urlencoded form, so the method name decides, never the HTTP method.

- SEND: ``chat.postMessage``, ``chat.postEphemeral``, ``chat.scheduleMessage``,
  ``chat.meMessage``, ``files.completeUploadExternal`` (recipients: ``channel``,
  ``channel_id`` or ``channels``), the legacy ``files.upload``, a POST to an incoming
  webhook (recipient: ``webhook:T…/B…``, never its secret), and the upload of a file's bytes to
  ``files.slack.com/upload/v1/...`` (no recipient yet, so never trusted: an injected prompt
  could hand the agent an upload URL of an attacker's workspace).
- CHANGE: ``chat.update``, ``chat.delete`` (held outside the trusted channels), reactions,
  pins, bookmarks, topics, joining a channel.
- DELETE: ``files.delete``. ADMIN (risk 3): inviting, kicking, creating, archiving or renaming
  channels, ``admin.*``, making a file public.
- READ (passes): ``auth.test``, ``conversations.list/history/info/replies/members/open``, the
  ``users.*`` reads, ``team.info``, ``files.info/list``, Socket Mode's ``apps.connections.open``
  and ``files.getUploadURLExternal`` (the upload itself is held). Web pages on ``slack.com``
  (outside ``/api``) and file downloads by ``GET``.
- Anything else: UNKNOWN.

A send or a change that makes Slack fetch a URL (an ``icon_url``, an image in its blocks or
attachments, or a link it unfurls: unless both ``unfurl_links`` and ``unfurl_media`` are
false) is never trusted (``FETCHES_URL``), and the person reads the URL (review of T10-3, M3).
A channel is trusted by its id only (M4).

What is shown of a message is what Slack shows: its ``blocks`` (``text`` is then only the
notification's fallback), else its ``text``, and its legacy ``attachments``. Every parameter but
the token is searched for secrets at any depth.
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
    FormPart,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    attachment,
    content_type,
    credential,
    data_has_secret,
    decode_utf8,
    fetch_target,
    find_url,
    first_lines,
    has_secret,
    has_secret_in,
    json_object,
    media_type,
    nested_text,
    opt_clean,
    parse_multipart,
    parse_pairs,
    rpc_params,
    semantic_canonical,
    split_path,
    strict_json,
    unknown,
    walk_fields,
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
_SHOWN_KEYS = frozenset({"title", "pretext", "text", "value"})  # in blocks and attachments
# What Slack's servers download to show a message (at any depth: blocks, attachments).
_IMAGE_KEYS = frozenset(
    {"icon_url", "image_url", "thumb_url", "author_icon", "footer_icon", "video_url",
     "thumbnail_url", "provider_icon_url"}
)  # fmt: skip
# Where a link that Slack unfurls is: the message's text and initial comment, and the texts of
# its blocks and attachments (a file's title is not unfurled).
_LINK_KEYS = frozenset({"text", "initial_comment", "pretext"})


def credential_segments(segments: tuple[str, ...]) -> frozenset[int]:
    """Which segments of a path (split on "/", the query apart) are an incoming webhook's
    secret: ``/services/T…/B…/<secret>`` (only on hooks.slack.com: the caller asks for it)."""
    if len(segments) == 5 and segments[0] == "" and segments[1] == "services":
        return frozenset({4})
    return frozenset()


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
        return _files_host(view, context, segments)
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
    """The HMAC of the token that acts. ``@slack/web-api`` 8.1.1 (OpenClaw 2026.9.8) sends it
    in ``Authorization`` and, for many calls (``conversations.info``, ``users.info``,
    ``chat.update``...), ALSO as the form's ``token`` with the same value: that is one token.
    Two different ones are DUPLICATE: which one would Slack use?"""
    header = credential(view.headers)
    if header is not None and header.lower().startswith("bearer "):
        header = header[7:].strip()
    body_token = params.get("token")
    if body_token is not None and not isinstance(body_token, str):
        raise Unreadable
    if header is not None and body_token is not None and body_token.strip() != header:
        raise Unreadable(Note.DUPLICATE)
    token = header if header is not None else body_token
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
    attachments = _files(params, files, context)
    notes = [Note.DELETES_MESSAGE] if method in _DELETES else []
    fields = {name: value for name, value in params.items() if name != "token"}
    fetched = _fetched_url(fields)
    target = _target(params, context)
    if fetched is not None:
        notes.append(Note.FETCHES_URL)
        target = target or fetch_target(fetched, scrub)
    secret = has_secret_in(fields, scrub) or any(
        data_has_secret(part.data, scrub) for part in files
    )
    if secret:
        notes.append(Note.SECRET_SEEN)
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
        first_lines=first_lines(shown_text(text, params), scrub),
        target=target,
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


def _fetched_url(fields: dict[str, Any]) -> str | None:
    """The first URL this call makes Slack fetch: an image or icon at any depth, or a link it
    would unfurl (``unfurl_links`` and ``unfurl_media`` both false turn that off)."""
    walked = walk_fields(fields)
    for key, value in walked:
        if key in _IMAGE_KEYS and isinstance(value, str) and value.strip():
            return value.strip()
    if all(fields.get(name) in (False, "false") for name in ("unfurl_links", "unfurl_media")):
        return None
    for key, value in walked:
        if key in _LINK_KEYS and isinstance(value, str):
            found = find_url(value)
            if found is not None:
                return found
    return None


def shown_text(text: str | None, message: dict[str, Any]) -> str | None:
    """What the recipient reads of a message: its blocks (else its text), then its legacy
    attachments' texts."""
    blocks = message.get("blocks")
    shown = []
    if blocks is not None:
        shown.append(nested_text(blocks, _SHOWN_KEYS) or "[blocks]")
    elif text is not None:
        shown.append(text)
    if message.get("attachments") is not None:
        shown.append(nested_text(message["attachments"], _SHOWN_KEYS) or "[attachments]")
    return "\n".join(shown) or None


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
        shown = shown_text(text, payload)
    except Unreadable as error:
        return unknown(
            NAME, Shape.SLACK, WAIT_DEFAULT, error.note, account=account, path_credential=True
        )
    recipient = f"webhook:{segments[1]}/{segments[2]}"
    secret = has_secret_in(payload, context.scrub)
    return Reading(
        translator=NAME,
        operation="webhook",
        effect=Effect.SEND,
        shape=Shape.SLACK,
        wait_s=WAIT_DEFAULT,
        account=account,
        recipients=(recipient,),
        first_lines=first_lines(shown, context.scrub),
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


def _files_host(view: RequestView, context: Context, segments: tuple[str, ...]) -> Reading:
    """``files.slack.com``: downloads, and the upload of a file's bytes to the URL that
    ``files.getUploadURLExternal`` gave. The upload is a SEND: that URL may be of a workspace
    that is not the owner's, and the bytes are already out. Its recipient is not known yet
    (``files.completeUploadExternal`` names it), so it is never trusted."""
    if view.method in READ_METHODS and not view.body:
        return Reading(
            NAME, "file_download", Effect.READ, Shape.SLACK, WAIT_DEFAULT, notes=(Note.DOWNLOAD,)
        )
    if view.method != "POST" or segments[:2] != ("upload", "v1"):
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT)
    try:
        account = _account(view, context, {})
        return _upload(view, context, segments, account)
    except Unreadable as error:
        return unknown(NAME, Shape.SLACK, WAIT_DEFAULT, error.note)


def _upload(
    view: RequestView, context: Context, segments: tuple[str, ...], account: str | None
) -> Reading:
    scrub = context.scrub
    if media_type(view.headers) == "multipart/form-data":
        parts = parse_multipart(content_type(view.headers) or "", view.body)
    else:  # the bytes as they are (what @slack/web-api sends)
        parts = [FormPart("file", None, media_type(view.headers), view.body)]
    if len(parts) > MAX_ATTACHMENTS:
        raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    shown = []
    entries = []
    secret = False
    for part in parts:
        item, entry = attachment(part.filename, part.type, part.data, scrub)
        shown.append(item)
        entries.append(entry)
        secret |= bool(part.filename and has_secret(part.filename, scrub))
        secret |= data_has_secret(part.data, scrub)
    return Reading(
        translator=NAME,
        operation="file_upload",
        effect=Effect.SEND,
        shape=Shape.SLACK,
        wait_s=WAIT_DEFAULT,
        account=account,
        target="a file upload (its channel is named later)",
        attachments=tuple(shown),
        secret_seen=secret,
        notes=(Note.SECRET_SEEN,) if secret else (),
        canonical=semantic_canonical(
            translator=NAME,
            host=view.host,
            port=view.port,
            operation="file_upload",
            account=account,
            recipients=(),
            fields={"path": "/".join(segments)},
            files=entries,
        ),  # fmt: skip
    )
