"""Discord's REST API (``discord.com`` and ``discordapp.com``, ``/api`` and ``/api/v{n}``), as
OpenClaw's own REST client uses it (docs/32, section 3). Pure.

- SEND: ``POST /channels/{id}/messages`` (JSON, or multipart with ``payload_json`` and
  ``files[n]``), ``POST /webhooks/{id}/{token}`` (recipient ``webhook:{id}``, never the token),
  ``POST /interactions/{id}/{token}/callback`` (answers whoever used a command), and starting a
  thread (``POST /channels/{id}/threads``, a forum post with its first ``message``, or
  ``.../messages/{id}/threads``): its name and message are read by the whole channel.
- FORWARD: ``crosspost`` (publishes a message to the channels that follow it), and a message
  whose ``message_reference.type`` is 1 (a forward of an existing message).
- CHANGE: ``PATCH`` of a message (held outside the trusted channels), reactions, pins, and a
  webhook's own messages.
- DELETE (risk 3, never trusted or batched): ``DELETE`` of a message (also a webhook's),
  ``bulk-delete``, deleting a channel or a webhook. ADMIN (risk 3): webhooks, invites,
  permissions, channel settings and anything that changes a guild.
- READ (passes): ``GET`` and ``HEAD``, ``POST /channels/{id}/typing`` and
  ``POST /users/@me/channels`` (opening a direct message sends nothing).
- Anything else: UNKNOWN.

What is shown of a message is its ``content``, its embeds' texts and its poll; the whole message
(components, poll, embeds...) is searched for secrets at any depth.
"""

import re
from typing import Any

from backtide.gate.translate.base import (
    MAX_ATTACHMENTS,
    READ_METHODS,
    WAIT_DISCORD,
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
    first_lines,
    has_secret,
    has_secret_in,
    json_object,
    media_type,
    nested_text,
    parse_multipart,
    parse_pairs,
    semantic_canonical,
    split_path,
    unknown,
)

NAME = "discord"
HOSTS = frozenset(
    {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com",
     "canary.discordapp.com", "ptb.discordapp.com"}
)  # fmt: skip

_ID_RE = re.compile(r"[0-9]{1,20}", re.ASCII)
_VERSION_RE = re.compile(r"v[0-9]{1,2}", re.ASCII)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{1,512}", re.ASCII)
_FILE_FIELD_RE = re.compile(r"files\[[0-9]{1,2}\]|file", re.ASCII)
_VOLATILE = frozenset({"nonce", "enforce_nonce"})  # random per message; a retry keeps it
_MESSAGE_FIELDS = frozenset(
    {"content", "nonce", "enforce_nonce", "tts", "embeds", "allowed_mentions",
     "message_reference", "components", "sticker_ids", "attachments", "flags", "poll",
     "username", "avatar_url", "thread_name", "applied_tags"}
)  # fmt: skip
_THREAD_FIELDS = frozenset(
    {"name", "auto_archive_duration", "rate_limit_per_user", "message", "applied_tags", "type",
     "invitable"}
)  # fmt: skip
_SHOWN_KEYS = frozenset({"title", "description", "name", "value", "text"})  # embeds and polls


def credential_segments(segments: tuple[str, ...]) -> frozenset[int]:
    """Which segments of a path (split on "/", the query apart) are a webhook's or an
    interaction's token: ``/api[/vN]/webhooks/{id}/{token}`` and ``/interactions/{id}/{token}``."""
    lowered = [segment.lower() for segment in segments]
    for index, segment in enumerate(lowered[:4]):
        if segment in ("webhooks", "interactions") and index + 2 < len(segments):
            if _ID_RE.fullmatch(segments[index + 1]):
                return frozenset({index + 2})
    return frozenset()


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host in HOSTS


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
    except Unreadable as error:
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, error.note)
    if not segments or segments[0].lower() != "api":
        if view.method in READ_METHODS and not view.body:
            return Reading(NAME, "web_page", Effect.READ, Shape.DISCORD, WAIT_DISCORD)
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD)
    rest = segments[1:]
    if rest and _VERSION_RE.fullmatch(rest[0]):
        rest = rest[1:]
    try:
        account = account_id(context, NAME, credential(view.headers))
        parse_pairs(query)  # read strictly here; _message keeps it in the canonical form
    except Unreadable as error:
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, error.note)
    if view.method in READ_METHODS:
        if view.body:
            return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, Note.UNPARSED, account=account)
        return Reading(NAME, "get", Effect.READ, Shape.DISCORD, WAIT_DISCORD, account=account)
    lowered = tuple(segment.lower() for segment in rest)
    try:
        if lowered[:1] in (("webhooks",), ("interactions",)):
            return _token_path(view, context, rest, lowered)
        return _bot_path(view, context, rest, lowered, account)
    except Unreadable as error:
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, error.note, account=account)


def _bot_path(
    view: RequestView,
    context: Context,
    rest: tuple[str, ...],
    lowered: tuple[str, ...],
    account: str | None,
) -> Reading:
    method = view.method
    if lowered == ("users", "@me", "channels") and method == "POST":
        return Reading(
            NAME,
            "open_dm",
            Effect.READ,
            Shape.DISCORD,
            WAIT_DISCORD,
            account=account,
            notes=(Note.OPEN_DM,),
        )
    if lowered[:1] == ("guilds",) and method in ("POST", "PUT", "PATCH", "DELETE"):
        return _plain(Effect.ADMIN, "guild_change", account)
    if lowered[:1] != ("channels",) or len(rest) < 2 or not _ID_RE.fullmatch(rest[1]):
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, account=account)
    channel = rest[1]
    tail = lowered[2:]
    if tail == ("typing",) and method == "POST":
        return Reading(
            NAME,
            "typing",
            Effect.READ,
            Shape.DISCORD,
            WAIT_DISCORD,
            account=account,
            notes=(Note.TYPING,),
        )
    if tail == ("messages",) and method == "POST":
        return _message(view, context, "create_message", Effect.SEND, account, (channel,), None)
    if tail == ("messages", "bulk-delete") and method == "POST":
        return _plain(Effect.DELETE, "bulk_delete", account, (channel,))
    if len(tail) >= 2 and tail[0] == "messages" and _ID_RE.fullmatch(tail[1]):
        target = f"message {tail[1]}"
        if len(tail) == 2 and method == "PATCH":
            return _message(
                view, context, "edit_message", Effect.CHANGE, account, (channel,), target
            )
        if len(tail) == 2 and method == "DELETE" and not view.body:
            return _plain(
                Effect.DELETE,
                "delete_message",
                account,
                (channel,),
                target,
                notes=(Note.DELETES_MESSAGE,),
            )
        if tail[2:] == ("crosspost",) and method == "POST":
            return _plain(Effect.FORWARD, "crosspost", account, (channel,), target)
        if tail[2:3] == ("reactions",) and method in ("PUT", "DELETE") and not view.body:
            return _plain(Effect.CHANGE, "reaction", account, (channel,), target)
        if tail[2:] == ("threads",) and method == "POST":
            return _message(view, context, "start_thread", Effect.SEND, account, (channel,), target)
    if tail[:1] == ("pins",) and method in ("PUT", "DELETE") and not view.body:
        return _plain(Effect.CHANGE, "pin", account, (channel,))
    if tail == ("threads",) and method == "POST":
        return _message(view, context, "start_thread", Effect.SEND, account, (channel,), None)
    if tail == () and method == "DELETE":
        return _plain(Effect.DELETE, "delete_channel", account, (channel,))
    if (
        tail in (("webhooks",), ("invites",), ("followers",))
        or tail[:1] == ("permissions",)
        or tail == ()
    ) and method in ("POST", "PUT", "PATCH", "DELETE"):
        return _plain(Effect.ADMIN, "channel_admin", account, (channel,))
    return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, account=account)


def _token_path(
    view: RequestView,
    context: Context,
    rest: tuple[str, ...],
    lowered: tuple[str, ...],
) -> Reading:
    """``/webhooks/{id}/{token}...`` and ``/interactions/{id}/{token}/callback``: the token in
    the path is the credential, so the account is its HMAC."""
    if len(rest) < 3 or not _ID_RE.fullmatch(rest[1]) or not _TOKEN_RE.fullmatch(rest[2]):
        if lowered[:1] == ("webhooks",) and len(rest) == 2 and _ID_RE.fullmatch(rest[1]):
            account = account_id(context, NAME, credential(view.headers))
            if view.method in ("PATCH", "DELETE"):  # the webhook itself, with the bot's token
                effect = Effect.DELETE if view.method == "DELETE" else Effect.ADMIN
                return _plain(effect, "webhook_admin", account)
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, path_credential=True)
    account = account_id(context, NAME, "path", rest[2])
    tail = lowered[3:]
    if lowered[0] == "interactions":
        if tail == ("callback",) and view.method == "POST":
            return _message(
                view,
                context,
                "interaction_callback",
                Effect.SEND,
                account,
                (f"interaction:{rest[1]}",),
                None,
                path_credential=True,
                notes=(Note.INTERACTION,),
            )
        return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, account=account, path_credential=True)
    recipient = (f"webhook:{rest[1]}",)
    if tail == () and view.method == "POST":
        return _message(
            view,
            context,
            "execute_webhook",
            Effect.SEND,
            account,
            recipient,
            None,
            path_credential=True,
            notes=(Note.WEBHOOK,),
        )
    if tail == () and view.method in ("PATCH", "DELETE"):
        effect = Effect.DELETE if view.method == "DELETE" else Effect.ADMIN
        return _plain(effect, "webhook_admin", account, recipient, path_credential=True)
    if len(tail) == 2 and tail[0] == "messages" and view.method in ("PATCH", "DELETE"):
        target = f"message {tail[1]}" if _ID_RE.fullmatch(tail[1]) else None
        if view.method == "PATCH":
            return _message(
                view,
                context,
                "edit_webhook_message",
                Effect.CHANGE,
                account,
                recipient,
                target,
                path_credential=True,
            )
        if not view.body:
            return _plain(
                Effect.DELETE,
                "delete_webhook_message",
                account,
                recipient,
                target,
                notes=(Note.DELETES_MESSAGE,),
                path_credential=True,
            )
    return unknown(NAME, Shape.DISCORD, WAIT_DISCORD, account=account, path_credential=True)


def _plain(
    effect: Effect,
    operation: str,
    account: str | None,
    recipients: tuple[str, ...] = (),
    target: str | None = None,
    *,
    notes: tuple[Note, ...] = (),
    path_credential: bool = False,
) -> Reading:
    return Reading(
        NAME,
        operation,
        effect,
        Shape.DISCORD,
        WAIT_DISCORD,
        account=account,
        recipients=recipients,
        target=target,
        notes=notes,
        path_credential=path_credential,
    )


def _message(
    view: RequestView,
    context: Context,
    operation: str,
    effect: Effect,
    account: str | None,
    recipients: tuple[str, ...],
    target: str | None,
    *,
    path_credential: bool = False,
    notes: tuple[Note, ...] = (),
) -> Reading:
    payload, files = _payload(view)
    query = parse_pairs(view.path.partition("?")[2])  # wait, thread_id: part of what it does
    heading: object = None
    if operation == "interaction_callback":
        message = payload.get("data")
        if not isinstance(message, dict):
            message = {}
    elif operation == "start_thread":
        if not set(payload) <= _THREAD_FIELDS:
            raise Unreadable(Note.NOT_IN_TABLE)
        heading = payload.get("name")
        message = payload.get("message") or {}
        if not isinstance(message, dict) or not set(message) <= _MESSAGE_FIELDS:
            raise Unreadable(Note.NOT_IN_TABLE)
    else:
        if not set(payload) <= _MESSAGE_FIELDS:
            raise Unreadable(Note.NOT_IN_TABLE)
        message = payload
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        raise Unreadable
    if heading is not None and not isinstance(heading, str):
        raise Unreadable
    if operation == "create_message":
        effect, target = _forward(message, effect, target)
    scrub = context.scrub
    shown = []
    entries = []
    secret = has_secret_in(payload, scrub)  # everything: embeds, components, poll, names...
    for part in files:
        item, entry = attachment(part.filename or part.name, part.type, part.data, scrub)
        shown.append(item)
        entries.append(entry)
        if part.filename and has_secret(part.filename, scrub):
            secret = True
        if data_has_secret(part.data, scrub):
            secret = True
    fields = {name: value for name, value in payload.items() if name not in _VOLATILE}
    fields["?query"] = query
    return Reading(
        translator=NAME,
        operation=operation,
        effect=effect,
        shape=Shape.DISCORD,
        wait_s=WAIT_DISCORD,
        account=account,
        recipients=recipients,
        first_lines=first_lines(_shown(heading, content, message), scrub),
        target=target,
        attachments=tuple(shown),
        secret_seen=secret,
        path_credential=path_credential,
        notes=notes + ((Note.SECRET_SEEN,) if secret else ()),
        canonical=semantic_canonical(
            translator=NAME,
            host=view.host,
            port=view.port,
            operation=operation,
            account=account,
            recipients=recipients,
            fields=fields,
            files=entries,
        ),  # fmt: skip
    )


def _shown(heading: str | None, content: str | None, message: dict[str, Any]) -> str | None:
    """What the channel reads: a thread's name, the content, the embeds' texts and the poll."""
    shown = [heading, content]
    for name in ("embeds", "poll"):
        if message.get(name):
            shown.append(nested_text(message[name], _SHOWN_KEYS) or f"[{name}]")
    return "\n".join(text for text in shown if text) or None


def _forward(
    message: dict[str, Any], effect: Effect, target: str | None
) -> tuple[Effect, str | None]:
    """A message whose ``message_reference`` has ``type`` 1 forwards an existing message (0, or
    none, is a reply). Any other type is Unreadable."""
    reference = message.get("message_reference")
    if reference is None:
        return effect, target
    if not isinstance(reference, dict):
        raise Unreadable
    kind = reference.get("type", 0)
    if type(kind) is not int or kind not in (0, 1):
        raise Unreadable(Note.NOT_IN_TABLE)
    if kind == 0:
        return effect, target
    item = reference.get("message_id")
    source = reference.get("channel_id")
    item_id = item if isinstance(item, str) and _ID_RE.fullmatch(item) else None
    source_id = source if isinstance(source, str) and _ID_RE.fullmatch(source) else None
    shown = f"message {item_id or '?'}" + (f" from channel {source_id}" if source_id else "")
    return Effect.FORWARD, shown


def _payload(view: RequestView) -> tuple[dict[str, Any], list[FormPart]]:
    """The message: a JSON body, or a multipart one with ``payload_json`` and ``files[n]``."""
    kind = media_type(view.headers)
    if kind == "application/json":
        return json_object(view.body), []
    if kind != "multipart/form-data":
        raise Unreadable
    payload: dict[str, Any] | None = None
    files: list[FormPart] = []
    for part in parse_multipart(content_type(view.headers) or "", view.body):
        if part.name == "payload_json" and part.filename is None:
            payload = json_object(part.data)
        elif _FILE_FIELD_RE.fullmatch(part.name):
            files.append(part)
        else:
            raise Unreadable(Note.NOT_IN_TABLE)  # loose form fields: read by no one here
    if len(files) > MAX_ATTACHMENTS:
        raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    return payload or {}, files
