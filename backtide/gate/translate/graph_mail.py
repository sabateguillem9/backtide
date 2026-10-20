"""Outlook mail through Microsoft Graph (``graph.microsoft.com``, ``/v1.0`` and ``/beta``). Pure.

``{u}`` is ``me`` or ``users/{id}``; the account is the HMAC of the token and the mailbox. The
mail paths are those under ``sendMail``, ``messages``, ``mailFolders`` and ``mailboxSettings``.

- SEND: ``POST /{u}/sendMail`` (``message.subject``, ``body.content``, ``toRecipients``,
  ``ccRecipients``, ``bccRecipients``, ``replyTo``, ``attachments[].name``).
- FORWARD: ``.../messages/{id}/forward`` (its recipients are in the request; the content is the
  existing message).
- UNKNOWN: ``.../messages/{id}/send``, ``reply`` and ``replyAll`` (the recipients or the content
  are not in the request), ``$batch``, and anything not in the table.
- DELETE (risk 3): ``DELETE`` of a message, an attachment or a folder, ``permanentDelete``, and
  a ``move`` to ``deleteditems``. CHANGE: other moves, copies and folders.
- ADMIN (risk 3): ``messageRules`` and ``mailboxSettings``.
- READ (passes): ``GET`` and ``HEAD``. Other Graph APIs (files, Teams...) by ``GET``.
- Drafts (``POST messages``, ``createReply``, ``createReplyAll``, ``createForward``, ``PATCH`` of
  a message, ``POST`` of an attachment): READ only in the owner's own accounts
  (``Context.owner_accounts``), CHANGE (held) in any other: a draft in an attacker's mailbox is
  data out (docs/32, decision 12).
"""

import json
import re
from dataclasses import replace
from typing import Any

from backtide.gate.translate.base import (
    MAX_ATTACHMENTS,
    MAX_RECIPIENTS,
    READ_METHODS,
    SUBJECT_CHARS,
    WAIT_DEFAULT,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    attachment,
    b64_decode,
    credential,
    data_has_secret,
    draft_ref,
    first_lines,
    has_secret,
    has_secret_in,
    html_text,
    json_object,
    media_type,
    normalize_email,
    opt_clean,
    parse_pairs,
    safe_id,
    semantic_canonical,
    split_path,
    unknown,
)

NAME = "graph_mail"
HOSTS = frozenset({"graph.microsoft.com"})

_VERSIONS = frozenset({"v1.0", "beta"})
_MAIL_ROOTS = frozenset({"sendmail", "messages", "mailfolders", "mailboxsettings"})
_MESSAGE_FIELDS = frozenset(
    {"subject", "body", "torecipients", "ccrecipients", "bccrecipients", "replyto",
     "attachments", "importance", "isdeliveryreceiptrequested", "isreadreceiptrequested",
     "flag", "categories", "internetmessageheaders", "@odata.type"}
)  # fmt: skip
_SEND_FIELDS = frozenset({"message", "savetosentitems"})
_FORWARD_FIELDS = frozenset({"comment", "torecipients", "message"})
_RECIPIENT_FIELDS = ("torecipients", "ccrecipients", "bccrecipients")
_DRAFT_ACTIONS = frozenset({"createreply", "createreplyall", "createforward"})
_UNSEEN_ACTIONS = frozenset({"send", "reply", "replyall"})
_TRASH = frozenset({"deleteditems", "recoverableitemsdeletions"})
_FOLDER_RE = re.compile(r"[A-Za-z0-9=_-]{1,256}", re.ASCII)


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host in HOSTS


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
        parse_pairs(query)
    except Unreadable as error:
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, error.note)
    lowered = tuple(segment.lower() for segment in segments)
    if not lowered or lowered[0] not in _VERSIONS:
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT)
    if lowered[1:] == ("$batch",):
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, Note.BATCH)
    if lowered[1:2] == ("me",):
        mailbox, rest, raw = "me", lowered[2:], segments[2:]
    elif lowered[1:2] == ("users",) and len(lowered) >= 3:
        mailbox, rest, raw = lowered[2], lowered[3:], segments[3:]
    else:
        mailbox, rest, raw = "", (), ()
    if not rest or rest[0] not in _MAIL_ROOTS:
        # Another Graph API (files, Teams, calendars): its GETs are reads; the rest is held.
        if view.method in READ_METHODS and not view.body:
            return Reading(NAME, "graph_get", Effect.READ, Shape.GRAPH, WAIT_DEFAULT)
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT)
    try:
        account = account_id(context, NAME, credential(view.headers), mailbox)
    except Unreadable as error:
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, error.note)
    try:
        return _classify(view, context, account, rest, raw, mailbox)
    except Unreadable as error:
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, error.note, account=account)


def _plain(
    effect: Effect, operation: str, account: str | None, *notes: Note, target: str | None = None
) -> Reading:
    return Reading(
        NAME, operation, effect, Shape.GRAPH, WAIT_DEFAULT, account=account, target=target,
        notes=notes,
    )  # fmt: skip


def _message_tail(rest: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(the folders before ``messages``, what follows it), for ``messages/...`` and
    ``mailFolders/{id}/(childFolders/{id}/)*messages/...``."""
    if rest[:1] == ("messages",):
        return (), rest[1:]
    if "messages" in rest:
        index = rest.index("messages")
        return rest[:index], rest[index + 1 :]
    return rest, ()


def _classify(
    view: RequestView,
    context: Context,
    account: str | None,
    rest: tuple[str, ...],
    raw: tuple[str, ...],
    mailbox: str = "me",
) -> Reading:
    method = view.method
    if method in READ_METHODS:
        if view.body:
            raise Unreadable
        return _plain(Effect.READ, "get", account)
    if rest == ("sendmail",) and method == "POST":
        return _send_mail(view, context, account)
    if rest[0] == "mailboxsettings":
        return _plain(Effect.ADMIN, "mailboxSettings", account)
    if "messagerules" in rest:
        return _plain(Effect.ADMIN, "messageRules", account)
    _folders, tail = _message_tail(rest)
    if rest[0] == "sendmail":
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, account=account)
    if "messages" not in rest:
        # mailFolders/...: creating, renaming or deleting folders (deleting one deletes its mail).
        if method == "DELETE" and not view.body:
            return _plain(Effect.DELETE, "mailFolders.delete", account)
        if method in ("POST", "PATCH"):
            return _plain(Effect.CHANGE, "mailFolders", account)
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, account=account)
    draft = Effect.READ if account in context.owner_accounts else Effect.CHANGE
    if tail == () and method == "POST":
        return _plain(draft, "messages.create", account, Note.DRAFT)
    index = len(raw) - len(tail)
    given = raw[index] if tail and index < len(raw) else None
    item = safe_id(given)
    # Graph's ids are long and end in "=": the draft is named by a digest of the mailbox and the
    # id, never dropped (review of T10-3, M7).
    ref = draft_ref(mailbox, given)
    target = f"message {item}" if item else None
    if len(tail) == 1 and method == "PATCH":
        changed = _plain(draft, "messages.update", account, Note.DRAFT, target=target)
        return replace(changed, draft=ref)
    if len(tail) == 1 and method == "DELETE" and not view.body:
        return _plain(Effect.DELETE, "messages.delete", account, target=target)
    if tail[1:] == ("attachments",) and method == "POST":
        # It cannot tell a draft from a sent message: an attachment is a draft's only there.
        added = _plain(draft, "messages.attachments.add", account, Note.DRAFT, target=target)
        return replace(added, draft=ref)
    if len(tail) == 3 and tail[1] == "attachments" and method == "DELETE" and not view.body:
        removed = _plain(Effect.DELETE, "messages.attachments.delete", account, target=target)
        return replace(removed, draft=ref)
    if len(tail) != 2 or method != "POST":
        return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, account=account, target=target)
    action = tail[1]
    if action in _DRAFT_ACTIONS:
        return _plain(draft, f"messages.{action}", account, Note.DRAFT, target=target)
    if action in _UNSEEN_ACTIONS:
        unseen = unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, Note.CONTENT_UNSEEN, account=account,
                         target=target or "a saved message")  # fmt: skip
        return replace(unseen, draft=ref if action == "send" else None)
    if action == "permanentdelete":
        return _plain(Effect.DELETE, "messages.permanentDelete", account, target=target)
    if action in ("move", "copy"):
        destination = _destination(view)
        if action == "move" and destination in _TRASH:
            return _plain(Effect.DELETE, "messages.move", account, Note.TO_TRASH, target=target)
        return _plain(Effect.CHANGE, f"messages.{action}", account, target=target)
    if action == "forward":
        return _forward(view, context, account, target)
    return unknown(NAME, Shape.GRAPH, WAIT_DEFAULT, account=account, target=target)


def _body(view: RequestView) -> dict[str, Any]:
    if media_type(view.headers) not in (None, "application/json"):
        raise Unreadable
    return json_object(view.body)


def _destination(view: RequestView) -> str:
    body = _body(view)
    if set(body) != {"destinationid"} or not isinstance(body["destinationid"], str):
        raise Unreadable
    destination = body["destinationid"]
    if not _FOLDER_RE.fullmatch(destination):
        raise Unreadable
    return destination.lower()


def _recipients(value: object) -> list[str]:
    """``[{"emailAddress": {"address": ..., "name": ...}}]``: the addresses only."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise Unreadable(Note.BAD_ADDRESS)
    found: list[str] = []
    for item in value:
        email = item.get("emailaddress") if isinstance(item, dict) else None
        address = email.get("address") if isinstance(email, dict) else None
        if not isinstance(item, dict) or set(item) != {"emailaddress"}:
            raise Unreadable(Note.BAD_ADDRESS)
        if not isinstance(email, dict) or not set(email) <= {"address", "name"}:
            raise Unreadable(Note.BAD_ADDRESS)
        normalized = normalize_email(address) if isinstance(address, str) else None
        if normalized is None:
            raise Unreadable(Note.BAD_ADDRESS)
        found.append(normalized[0])
        if len(found) > MAX_RECIPIENTS:
            raise Unreadable(Note.TOO_MANY_RECIPIENTS)
    return found


def _international(addresses: list[str]) -> bool:
    return any("xn--" in address.rpartition("@")[2] for address in addresses)


def _send_mail(view: RequestView, context: Context, account: str | None) -> Reading:
    body = _body(view)
    if not set(body) <= _SEND_FIELDS or not isinstance(body.get("message"), dict):
        raise Unreadable(Note.NOT_IN_TABLE)
    message = body["message"]
    return _mail(view, context, account, "sendMail", Effect.SEND, message, None,
                 {"saveToSentItems": body.get("savetosentitems")})  # fmt: skip


def _forward(
    view: RequestView, context: Context, account: str | None, target: str | None
) -> Reading:
    body = _body(view)
    if not set(body) <= _FORWARD_FIELDS:
        raise Unreadable(Note.NOT_IN_TABLE)
    message = body.get("message") or {}
    if not isinstance(message, dict):
        raise Unreadable
    if "torecipients" in body:
        if "torecipients" in message:
            raise Unreadable(Note.DUPLICATE)
        message = {**message, "torecipients": body["torecipients"]}
    comment = body.get("comment")
    if comment is not None and not isinstance(comment, str):
        raise Unreadable
    return _mail(view, context, account, "messages.forward", Effect.FORWARD, message, target,
                 {"comment": comment})  # fmt: skip


def _mail(
    view: RequestView,
    context: Context,
    account: str | None,
    operation: str,
    effect: Effect,
    message: dict[str, Any],
    target: str | None,
    extra: dict[str, Any],
) -> Reading:
    if not set(message) <= _MESSAGE_FIELDS:
        raise Unreadable(Note.NOT_IN_TABLE)
    recipients: list[str] = []
    for name in _RECIPIENT_FIELDS:
        recipients.extend(_recipients(message.get(name)))
        if len(recipients) > MAX_RECIPIENTS:
            raise Unreadable(Note.TOO_MANY_RECIPIENTS)
    if not recipients:
        raise Unreadable(Note.BAD_ADDRESS)
    reply_to = _recipients(message.get("replyto"))
    subject = message.get("subject")
    if subject is not None and not isinstance(subject, str):
        raise Unreadable
    text = _text(message.get("body"))
    if text is None and isinstance(extra.get("comment"), str):
        text = extra["comment"]
    scrub = context.scrub
    # Everything but the files' bytes, at any depth (the whole HTML too, not only what is shown).
    unfiled = {key: value for key, value in message.items() if key != "attachments"}
    secret = has_secret_in(unfiled, scrub) or has_secret_in(extra, scrub)
    shown = []
    entries = []
    attachments = message.get("attachments") or []
    if not isinstance(attachments, list):
        raise Unreadable
    if len(attachments) > MAX_ATTACHMENTS:
        raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    for item in attachments:
        name, kind, data = _attachment(item)
        shown_item, entry = attachment(name, kind, data, scrub)
        shown.append(shown_item)
        entries.append(entry)
        if name and has_secret(name, scrub):
            secret = True
        if isinstance(item, dict):
            secret |= has_secret_in({k: v for k, v in item.items() if k != "contentbytes"}, scrub)
        if data is not None:
            secret |= data_has_secret(data, scrub)
    fields = {key: value for key, value in message.items() if key != "attachments"}
    fields.update(extra)
    notes = []
    if _international(recipients + reply_to):
        notes.append(Note.IDN_DOMAIN)
    if secret:
        notes.append(Note.SECRET_SEEN)
    unique = tuple(dict.fromkeys(recipients))
    return Reading(
        translator=NAME,
        operation=operation,
        effect=effect,
        shape=Shape.GRAPH,
        wait_s=WAIT_DEFAULT,
        account=account,
        recipients=unique,
        reply_to=tuple(dict.fromkeys(reply_to)),
        subject=opt_clean(subject, scrub, SUBJECT_CHARS),
        first_lines=first_lines(text, scrub),
        target=target,
        attachments=tuple(shown),
        secret_seen=secret,
        notes=tuple(notes),
        canonical=semantic_canonical(
            translator=NAME,
            host=view.host,
            port=view.port,
            operation=operation,
            account=account,
            recipients=unique,
            fields=fields,
            files=entries,
        ),  # fmt: skip
    )


def _text(body: object) -> str | None:
    if body is None:
        return None
    if not isinstance(body, dict) or not set(body) <= {"contenttype", "content"}:
        raise Unreadable
    content = body.get("content")
    if content is None:
        return None
    if not isinstance(content, str):
        raise Unreadable
    kind = body.get("contenttype")
    if isinstance(kind, str) and kind.lower() == "html":
        return html_text(content)
    return content


_FILE = "#microsoft.graph.fileattachment"
_ITEM = "#microsoft.graph.itemattachment"
_REFERENCE = "#microsoft.graph.referenceattachment"


def _attachment(item: object) -> tuple[str | None, str | None, bytes | None]:
    """(name, type, content) of an attachment. A file's ``contentBytes`` is decoded; an item
    (an embedded mail or event) is hashed as its JSON; a reference has no content here."""
    if not isinstance(item, dict):
        raise Unreadable
    kind = item.get("@odata.type")
    name = item.get("name")
    if name is not None and not isinstance(name, str):
        raise Unreadable
    media = item.get("contenttype") if isinstance(item.get("contenttype"), str) else None
    if not isinstance(kind, str):
        raise Unreadable
    lowered = kind.lower()
    if lowered == _FILE:
        return name, media, b64_decode(item.get("contentbytes"))
    if lowered == _ITEM:
        inner = item.get("item")
        if not isinstance(inner, dict):
            raise Unreadable
        return name, "message/rfc822", json.dumps(inner, sort_keys=True).encode()
    if lowered == _REFERENCE:
        return name, media, None
    raise Unreadable(Note.NOT_IN_TABLE)
