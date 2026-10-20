"""The Gmail API (``gmail.googleapis.com``, and ``www.googleapis.com`` where Google serves it
too), as ``gog gmail send`` uses it: ``POST /gmail/v1/users/me/messages/send`` with
``{"raw": <the MIME mail in base64url>, "threadId"?}`` (docs/32, section 3). Pure.

``{u}`` is ``me`` or an address; the account is the HMAC of the token and the mailbox.

- SEND: ``messages/send``, and its upload path with ``uploadType=media`` or ``multipart``. The
  MIME mail gives From, To, Cc, Bcc, Reply-To, Subject, the text and the attachments' names.
- DELETE (risk 3): ``trash`` and ``DELETE`` of messages, threads and drafts, ``batchDelete``,
  and a label change that adds ``TRASH`` or ``SPAM``.
- CHANGE: ``batchModify``, ``untrash``, ``import``, ``insert`` and labels.
- ADMIN (risk 3): ``settings/*`` (filters, forwarding, auto-forwarding, sendAs, vacation...),
  ``watch`` and ``stop``.
- UNKNOWN: ``drafts/send`` (the content is a saved draft) and resumable uploads, which cannot
  be seen; ``/batch``; anything not in the table.
- READ (passes): ``GET`` and ``HEAD``; one message's or thread's labels (``modify``); and
  creating and changing drafts, but only in the owner's own accounts (``Context.owner_accounts``).
  In any other account a draft is a CHANGE (held): an injected prompt could hand the agent an
  attacker's token, and a draft in the attacker's mailbox is data out (docs/32, decision 12).
"""

from dataclasses import replace
from email import message_from_bytes
from email.policy import compat32
from typing import Any

from backtide.gate.translate.base import (
    MAX_MIME,
    READ_METHODS,
    SUBJECT_CHARS,
    WAIT_GOG,
    Context,
    Effect,
    Mail,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    attachment,
    b64url_decode,
    content_type,
    credential,
    data_has_secret,
    first_lines,
    has_secret,
    json_object,
    media_type,
    opt_clean,
    parse_mail,
    parse_pairs,
    safe_id,
    semantic_canonical,
    split_path,
    unknown,
)

NAME = "gmail"
HOSTS = frozenset({"gmail.googleapis.com", "www.googleapis.com"})

_SEND_FIELDS = frozenset({"raw", "threadid"})
_DELETING_LABELS = frozenset({"TRASH", "SPAM"})
_LABEL_FIELDS = frozenset({"addlabelids", "removelabelids"})


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host in HOSTS


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
        params = parse_pairs(query)
    except Unreadable as error:
        return unknown(NAME, Shape.GOOGLE, WAIT_GOG, error.note)
    lowered = tuple(segment.lower() for segment in segments)
    if lowered[:1] == ("batch",):
        return unknown(NAME, Shape.GOOGLE, WAIT_GOG, Note.BATCH)
    upload = lowered[:1] == ("upload",)
    start = 1 if upload else 0
    if lowered[start : start + 3] != ("gmail", "v1", "users") or len(lowered) < start + 4:
        # Another Google API on the shared host (Calendar, Drive...): its GETs are reads.
        if view.method in READ_METHODS and not view.body:
            return Reading(NAME, "google_get", Effect.READ, Shape.GOOGLE, WAIT_GOG)
        return unknown(NAME, Shape.GOOGLE, WAIT_GOG)
    try:
        account = account_id(context, NAME, credential(view.headers), lowered[start + 3])
    except Unreadable as error:
        return unknown(NAME, Shape.GOOGLE, WAIT_GOG, error.note)
    tail = lowered[start + 4 :]
    try:
        return _classify(view, context, account, tail, segments[start + 4 :], upload, params)
    except Unreadable as error:
        return unknown(NAME, Shape.GOOGLE, WAIT_GOG, error.note, account=account)


def _plain(
    effect: Effect, operation: str, account: str | None, *notes: Note, target: str | None = None
) -> Reading:
    return Reading(
        NAME, operation, effect, Shape.GOOGLE, WAIT_GOG, account=account, target=target, notes=notes
    )


def _classify(
    view: RequestView,
    context: Context,
    account: str | None,
    tail: tuple[str, ...],
    raw_tail: tuple[str, ...],
    upload: bool,
    params: dict[str, str],
) -> Reading:
    method = view.method
    if method in READ_METHODS:
        if view.body:
            raise Unreadable
        return _plain(Effect.READ, "get", account)
    item = safe_id(raw_tail[1]) if len(raw_tail) >= 2 else None
    target = f"{tail[0][:-1]} {item}" if item and tail[0] in ("messages", "threads") else None
    if tail == ("messages", "send") and method == "POST":
        return _send(view, context, account, upload, params)
    if tail == ("drafts", "send") and method == "POST":
        draft = _draft_id(view)
        return unknown(
            NAME,
            Shape.GOOGLE,
            WAIT_GOG,
            Note.CONTENT_UNSEEN,
            account=account,
            target=f"draft {draft}" if draft else "a saved draft",
        )
    draft = Effect.READ if account in context.owner_accounts else Effect.CHANGE
    if tail == ("drafts",) and method == "POST":
        return _plain(draft, "drafts.create", account, Note.DRAFT)
    if len(tail) == 2 and tail[0] == "drafts":
        if method == "PUT":
            return _plain(draft, "drafts.update", account, Note.DRAFT)
        if method == "DELETE" and not view.body:
            return _plain(Effect.DELETE, "drafts.delete", account, target=f"draft {item}")
    if upload:
        return unknown(NAME, Shape.GOOGLE, WAIT_GOG, account=account)
    if len(tail) == 3 and tail[0] in ("messages", "threads") and method == "POST":
        if tail[2] == "trash":
            return _plain(Effect.DELETE, f"{tail[0]}.trash", account, Note.TO_TRASH, target=target)
        if tail[2] == "untrash":
            return _plain(Effect.CHANGE, f"{tail[0]}.untrash", account, target=target)
        if tail[2] == "modify":
            if _labels_delete(view):
                return _plain(
                    Effect.DELETE, f"{tail[0]}.modify", account, Note.TO_TRASH, target=target
                )
            return _plain(
                Effect.READ, f"{tail[0]}.modify", account, Note.LABEL_CHANGE, target=target
            )
    if len(tail) == 2 and tail[0] in ("messages", "threads") and method == "DELETE":
        return _plain(Effect.DELETE, f"{tail[0]}.delete", account, target=target)
    if tail == ("messages", "batchdelete") and method == "POST":
        return _plain(Effect.DELETE, "messages.batchDelete", account)
    if tail == ("messages", "batchmodify") and method == "POST":
        effect = Effect.DELETE if _labels_delete(view) else Effect.CHANGE
        return _plain(effect, "messages.batchModify", account)
    if tail in (("messages",), ("messages", "import")) and method == "POST":
        return _plain(Effect.CHANGE, "messages.insert", account)
    if tail[:1] == ("labels",) and method in ("POST", "PUT", "PATCH", "DELETE"):
        return _plain(Effect.CHANGE, "labels", account)
    if tail[:1] == ("settings",) or tail in (("watch",), ("stop",)):
        return _plain(Effect.ADMIN, tail[0] if tail[0] != "settings" else "settings", account)
    return unknown(NAME, Shape.GOOGLE, WAIT_GOG, account=account)


def _draft_id(view: RequestView) -> str | None:
    try:
        return safe_id(json_object(view.body).get("id"))
    except Unreadable:
        return None


def _labels_delete(view: RequestView) -> bool:
    """Whether a label change sends messages to the trash or to spam. Read strictly."""
    if media_type(view.headers) not in (None, "application/json"):
        raise Unreadable
    body = json_object(view.body or b"{}")
    if not set(body) <= _LABEL_FIELDS | {"ids"}:
        raise Unreadable(Note.NOT_IN_TABLE)
    added = body.get("addlabelids") or []
    if not isinstance(added, list) or not all(isinstance(label, str) for label in added):
        raise Unreadable
    return any(label.upper() in _DELETING_LABELS for label in added)


def _send(
    view: RequestView, context: Context, account: str | None, upload: bool, params: dict[str, str]
) -> Reading:
    extra: dict[str, Any] = {}
    if not upload:
        if media_type(view.headers) not in (None, "application/json"):
            raise Unreadable
        body = json_object(view.body)
        if not set(body) <= _SEND_FIELDS or "raw" not in body:
            raise Unreadable(Note.NOT_IN_TABLE)
        raw = b64url_decode(body["raw"])
        extra["threadId"] = body.get("threadid")
        return mail_reading(
            NAME,
            Shape.GOOGLE,
            WAIT_GOG,
            view,
            context,
            account,
            "messages.send",
            parse_mail(raw),
            extra,
        )
    kind = params.get("uploadtype")
    if kind == "media":
        if media_type(view.headers) != "message/rfc822":
            raise Unreadable
        return mail_reading(
            NAME,
            Shape.GOOGLE,
            WAIT_GOG,
            view,
            context,
            account,
            "messages.send",
            parse_mail(view.body),
            {"upload": "media"},
        )
    if kind == "multipart":
        metadata, mail = _related(view)
        if not set(metadata) <= _SEND_FIELDS - {"raw"}:
            raise Unreadable(Note.NOT_IN_TABLE)
        extra = {"upload": "multipart", "threadId": metadata.get("threadid")}
        return mail_reading(
            NAME,
            Shape.GOOGLE,
            WAIT_GOG,
            view,
            context,
            account,
            "messages.send",
            parse_mail(mail),
            extra,
        )
    if kind == "resumable":
        return unknown(
            NAME,
            Shape.GOOGLE,
            WAIT_GOG,
            Note.CONTENT_UNSEEN,
            account=account,
            target="a resumable upload",
        )
    raise Unreadable(Note.NOT_IN_TABLE)


def _related(view: RequestView) -> tuple[dict[str, Any], bytes]:
    """A ``multipart/related`` upload: the JSON metadata, then the ``message/rfc822`` mail."""
    if len(view.body) > MAX_MIME:
        raise Unreadable(Note.TOO_LARGE)
    header = content_type(view.headers) or ""
    if media_type(view.headers) != "multipart/related" or header.lower().count("boundary") != 1:
        raise Unreadable
    if "\r" in header or "\n" in header:
        raise Unreadable
    message = message_from_bytes(
        b"Content-Type: " + header.encode("utf-8", "surrogateescape") + b"\r\n\r\n" + view.body,
        policy=compat32,
    )
    parts = message.get_payload()
    if message.defects or not isinstance(parts, list) or len(parts) != 2:
        raise Unreadable
    first, second = parts
    if first.defects or second.defects or first.get_content_type() != "application/json":
        raise Unreadable
    if second.get_content_type() != "message/rfc822":
        raise Unreadable
    data = first.get_payload(decode=True)
    inner = second.get_payload()
    if not isinstance(data, bytes) or not isinstance(inner, list) or len(inner) != 1:
        raise Unreadable
    return json_object(data), inner[0].as_bytes()


def mail_reading(
    translator: str,
    shape: Shape,
    wait_s: int,
    view: RequestView,
    context: Context,
    account: str | None,
    operation: str,
    mail: Mail,
    extra: dict[str, Any],
) -> Reading:
    """The reading of a mail to send (Gmail's MIME, shared by any MIME translator)."""
    if not mail.recipients:
        raise Unreadable(Note.BAD_ADDRESS)
    scrub = context.scrub
    shown = []
    entries = []
    secret = any(has_secret(text, scrub) for text in (mail.subject, *mail.texts) if text)
    for name, kind, data, inline in mail.attachments:
        item, entry = attachment(name, kind, data, scrub)
        if inline:
            item = replace(item, name=f"(inline {item.type or 'part'})")
        shown.append(item)
        entries.append(entry)
        if name and has_secret(name, scrub):
            secret = True
        if data_has_secret(data, scrub):
            secret = True
    notes = []
    if mail.international:
        notes.append(Note.IDN_DOMAIN)
    if secret:
        notes.append(Note.SECRET_SEEN)
    recipients = tuple(dict.fromkeys(mail.recipients))
    return Reading(
        translator=translator,
        operation=operation,
        effect=Effect.SEND,
        shape=shape,
        wait_s=wait_s,
        account=account,
        recipients=recipients,
        sender=mail.sender,
        reply_to=tuple(dict.fromkeys(mail.reply_to)),
        subject=opt_clean(mail.subject, scrub, SUBJECT_CHARS),
        first_lines=first_lines(mail.text, scrub),
        attachments=tuple(shown),
        secret_seen=secret,
        notes=tuple(notes),
        canonical=semantic_canonical(
            translator=translator,
            host=view.host,
            port=view.port,
            operation=operation,
            account=account,
            recipients=recipients,
            fields={"mail": mail.canonical, **extra},
            files=entries,
        ),  # fmt: skip
    )
