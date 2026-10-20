"""What every translator shares: the request it reads, the ``Reading`` it gives, and the strict,
bounded readers of paths, queries, forms, JSON, multipart bodies and mail addresses. Pure: no I/O.

A translator turns a request to an API it knows (Gmail, Telegram...) into a ``Reading``: what the
request does (its ``Effect``), from which account, to whom, and a short struck view of its text,
so the gate can decide on it and ask the person in one clear sentence (docs/32, section 8).

Rules for all of them (docs/32, section 8):
- A translator is picked by the CONNECTION's host only (never the ``Host`` header), and reads the
  canonical path: no ``.``, ``..``, ``%``, ``;``, ``\\`` or ``//``.
- What it does not understand it never lets through: an odd path, a repeated parameter, the same
  parameter in the query and the body, a method not in its table, or anything past the cost caps
  gives ``Effect.UNKNOWN``, which the gate holds.
- Text from the agent is data: subjects, bodies, file names and display names are struck
  (``scrub_known`` then the patterns), cut, and never decide anything. Decisions come from the
  connection's host, the canonical path and the named recipient fields.
- ``Effect.READ`` means "passes without asking": reads, and the few harmless writes the founder
  listed (docs/32, decision 12: single label changes, "typing...", deleteWebhook, and drafts in
  the owner's own accounts only). A READ that a body carries is held when the body is over
  MAX_READ_BODY or carries a secret (``guard_read``).
- Secrets are searched in everything a request carries, whole and at any depth (nested blocks,
  embeds, keyboards, every MIME part, every file): a scan is never cut short.

``Reading.canonical`` holds what the semantic fingerprint hashes (docs/32, decision 2): account,
all recipients, the whole text (long values as their SHA-256) and each attachment's name, type
and hash, never ``Date``, ``Message-ID`` or MIME boundaries. It exists only in the proxy's memory
to be HMAC'd with the channel's key: it is never recorded, logged or sent (``summary()`` leaves it
out, and so does ``repr``).
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.policy import compat32
from email.utils import getaddresses
from enum import StrEnum
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, unquote_plus

from backtide.blackbox.redact import KnownScrubber, strike_text
from backtide.gate.policy import is_ip, normalize_host

# --- cost caps -----------------------------------------------------------------------------------

MAX_BODY = 6 * 1024 * 1024  # what a translator parses at all (a 4 MiB mail in base64url fits)
MAX_MIME = 4 * 1024 * 1024  # a MIME message or a multipart body
MAX_NODES = 1_000_000  # JSON: objects, lists and values (counted before parsing)
MAX_PARAMS = 256
MAX_PARTS = 64  # MIME parts walked, and multipart form fields
MAX_BOUNDARIES = 32  # nested multiparts in a mail (counted before parsing)
MAX_RECIPIENTS = 64
MAX_ATTACHMENTS = 32
# A text is searched for secrets whole (about 0.2 s per MiB); one longer than this is taken as
# carrying one (fail closed). Every text a translator reads is within MAX_BODY.
SECRET_SCAN_CHARS = MAX_BODY
MAX_HTML_COMPARE = 1024 * 1024  # a mail's HTML compared with its plain text (see parse_mail)
MAX_READ_BODY = 64 * 1024  # a read by POST (or another write method) carries at most this
URL_CHARS = 2048  # a URL in a read's body longer than this is held (docs/32, decision 1)

# What is shown, in characters, after striking.
SUBJECT_CHARS = 200
LINES = 3
LINES_CHARS = 300
NAME_CHARS = 100
TARGET_CHARS = 200
_MARGIN = 1024  # as record.py: strike past the cut, then drop the piece a cut could split
_LONG_VALUE = 1024  # canonical: longer strings go as their SHA-256

# How long the gate keeps a held request connected, per client (docs/32, decision 3): below
# each client's own timeout, at most 90 s.
WAIT_DEFAULT = 90  # Slack (undici, 300 s), curl, Python, unknown clients
WAIT_TELEGRAM = 50  # grammy in OpenClaw: sendMessage 60 s
WAIT_TELEGRAM_FILES = 25  # sendPhoto, sendDocument and the other sends with a file: 30 s
WAIT_DISCORD = 10  # OpenClaw's REST client: 15 s
WAIT_GOG = 25  # gog: responseHeaderTimeout 30 s

READ_METHODS = frozenset({"GET", "HEAD"})
# Headers some servers and gateways read as another method or another path (provider_tools.py).
OVERRIDE_HEADERS = frozenset(
    {"x-http-method-override", "x-method-override", "x-http-method", "x-original-method",
     "x-original-url", "x-rewrite-url", "x-forwarded-prefix"}
)  # fmt: skip

_SEGMENT_RE = re.compile(r"[A-Za-z0-9_~:@+$=!-][A-Za-z0-9._~:@+$=!-]*", re.ASCII)
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}")
_LOCAL_PART_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}", re.ASCII)
_HOLD_SAFE_RE = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*={0,2}", re.ASCII)
_B64_RE = re.compile(r"[A-Za-z0-9+/\r\n]*={0,2}[\r\n]*", re.ASCII)
_TAG_RE = re.compile(r"<[^<>]{0,2048}>")
_ACCOUNT_RE = re.compile(r"[0-9a-f]{16}", re.ASCII)


class Effect(StrEnum):
    READ = "read"  # passes without asking (see the module's docstring)
    SEND = "send"  # new content to recipients
    FORWARD = "forward"  # existing content to recipients: never in a batch of sends
    CHANGE = "change"  # edits what is already there
    DELETE = "delete"  # risk 3, never batched
    ADMIN = "admin"  # webhooks, filters, forwarding, permissions: risk 3, never batched
    UNKNOWN = "unknown"  # not understood: held, never trusted or batched


class Shape(StrEnum):
    """How "pending" and "rejected" are written for the request's API (shapes.py)."""

    TELEGRAM = "telegram"
    DISCORD = "discord"
    SLACK = "slack"
    GOOGLE = "google"
    GRAPH = "graph"
    PLAIN = "plain"


class Note(StrEnum):
    """Fixed texts of ours that explain a reading. Never the agent's words."""

    TOO_LARGE = "too_large"  # past a cost cap: not read
    UNPARSED = "unparsed"  # a body, path or field that could not be read strictly
    DUPLICATE = "duplicate"  # a parameter or header given twice, or in the query and the body
    NOT_IN_TABLE = "not_in_table"  # a method or path the translator does not know
    METHOD_OVERRIDE = "method_override"  # a header that could turn it into another method
    TOO_MANY_RECIPIENTS = "too_many_recipients"
    TOO_MANY_ATTACHMENTS = "too_many_attachments"
    BAD_ADDRESS = "bad_address"  # a recipient that is not a plain address or id
    IDN_DOMAIN = "idn_domain"  # a recipient domain with non-Latin characters (shown in punycode)
    CONTENT_UNSEEN = "content_unseen"  # a saved draft, a resumable upload, a reply: not visible
    BATCH = "batch"  # an API batch of other requests
    TRANSLATOR_FAILED = "translator_failed"  # an exception inside the translator
    LABEL_CHANGE = "label_change"  # one message's labels (passes)
    DRAFT = "draft"  # creates or edits a draft (passes)
    TYPING = "typing"  # "typing..." (passes)
    BOT_SETUP = "bot_setup"  # harmless bot administration: commands, deleteWebhook (passes)
    OPEN_DM = "open_dm"  # opens a direct message channel, sends nothing (passes)
    UPLOAD_STEP = "upload_step"  # a file upload step that reaches no one yet (passes)
    DOWNLOAD = "download"  # reads a file
    DELETES_MESSAGE = "deletes_message"  # removes a message from a chat or channel
    TO_TRASH = "to_trash"
    WEBHOOK = "webhook"  # the recipient is a webhook
    INTERACTION = "interaction"  # answers whoever used a command
    REMOTE_ACTIONS = "remote_actions"  # a read API asked to act on pages or call a webhook
    GRAPHQL_QUERY = "graphql_query"
    GRAPHQL_MUTATION = "graphql_mutation"
    ALTERNATIVE_DIFFERS = "alternative_differs"  # a mail's HTML says other than its plain text
    LONG_URL = "long_url"  # a read whose body carries a URL over URL_CHARS
    # The platform itself fetches a URL the agent gave (a file by URL, a link preview, an
    # unfurl, an icon): a way out to any host, so never trusted (review of T10-3, M3).
    FETCHES_URL = "fetches_url"
    # A Telegram inline message (``inline_message_id``): it may be in any chat, so never
    # trusted, whatever ``chat_id`` says (review of T10-3, H2).
    INLINE_MESSAGE = "inline_message"
    SECRET_SEEN = "secret_seen"  # noqa: S105 (a note, not a secret): striking removed a secret from what it carries


@dataclass(frozen=True)
class Attachment:
    name: str  # struck, at most NAME_CHARS
    type: str | None  # a plain media type, or None
    size: int  # bytes; 0 when only referenced (a file uploaded before)


@dataclass(frozen=True)
class Reading:
    translator: str
    operation: str  # the API operation as our table names it: fixed text, never the agent's
    effect: Effect
    shape: Shape
    wait_s: int
    account: str | None = None  # 16 hex: HMAC of the credential that acts (and the mailbox)
    recipients: tuple[str, ...] = ()  # normalized: lower-case IDNA email, chat id, channel id
    sender: str | None = None  # From, normalized
    reply_to: tuple[str, ...] = ()
    subject: str | None = None  # struck, at most SUBJECT_CHARS
    first_lines: str | None = None  # struck: LINES lines, at most LINES_CHARS
    target: str | None = None  # what it acts on ("message 123", "from chat 5"): struck, cut
    attachments: tuple[Attachment, ...] = ()
    secret_seen: bool = False  # striking removed something from the text it carries
    path_credential: bool = False  # the path carries the credential (bot token, webhook token)
    # The saved draft it sends or changes (a Gmail draft id, a Graph message id): while a send of
    # that draft is held or preapproved, a change to it is held too (docs/32, decision 12).
    draft: str | None = None
    notes: tuple[Note, ...] = ()
    canonical: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.wait_s < 1 or self.wait_s > WAIT_DEFAULT:
            raise ValueError("wait_s out of range")
        if len(self.recipients) > MAX_RECIPIENTS or len(self.reply_to) > MAX_RECIPIENTS:
            raise ValueError("too many recipients")
        if len(self.attachments) > MAX_ATTACHMENTS:
            raise ValueError("too many attachments")
        if self.draft is not None and safe_id(self.draft) != self.draft:
            raise ValueError("a draft is a plain id")
        for text, limit in (
            (self.subject, SUBJECT_CHARS),
            (self.first_lines, LINES_CHARS),
            (self.target, TARGET_CHARS),
        ):
            if text is not None and len(text) > limit:
                raise ValueError("a shown text is over its limit")

    @property
    def risk(self) -> int:
        """The gate's risk if held (docs/32, section 5); the rules of T08 may raise it."""
        if self.effect is Effect.READ:
            return 0
        if self.effect in (Effect.DELETE, Effect.ADMIN) or self.secret_seen:
            return 3
        return 2

    def summary(self) -> dict[str, Any]:
        """JSON-safe and bounded, for the channel's ``gate.reading``: never ``canonical``."""
        return {
            "translator": self.translator,
            "operation": self.operation,
            "effect": str(self.effect),
            "account": self.account,
            "recipients": list(self.recipients),
            "sender": self.sender,
            "reply_to": list(self.reply_to),
            "subject": self.subject,
            "first_lines": self.first_lines,
            "target": self.target,
            "attachments": [
                {"name": item.name, "type": item.type, "size": item.size}
                for item in self.attachments
            ],
            "secret_seen": self.secret_seen,
            "path_credential": self.path_credential,
            "draft": self.draft,
            "notes": [str(note) for note in self.notes],
            "risk": self.risk,
            "wait_s": self.wait_s,
            "shape": str(self.shape),
        }


@dataclass(frozen=True)
class RequestView:
    """The request as the proxy holds it. A local type until T10-2's own lands: the addon's
    ``fields`` (record.py) map onto it with ``from_fields``."""

    method: str  # as sent: methods are case-sensitive, so "get" is not a read
    host: str  # the CONNECTION's host, normalized (policy.normalize_host)
    port: int
    path: str  # with its query, as sent
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""  # decoded (mitmproxy's ``get_content``)
    scheme: str = "https"
    trailers: bool = False

    @classmethod
    def from_fields(cls, fields: Mapping[str, Any], *, trailers: bool = False) -> "RequestView":
        headers = tuple(
            (str(pair[0]), str(pair[1]))
            for pair in fields.get("headers") or ()
            if isinstance(pair, list | tuple) and len(pair) == 2
        )
        body = fields.get("body")
        port = fields.get("port")
        return cls(
            method=str(fields.get("method", "")),
            host=normalize_host(fields.get("host")) or "",
            port=port if type(port) is int else 0,
            path=str(fields.get("path", "")),
            headers=headers,
            body=bytes(body) if isinstance(body, bytes | bytearray) else b"",
            scheme=str(fields.get("scheme", "https")),
            trailers=trailers,
        )


@dataclass(frozen=True)
class Context:
    """What a translator needs besides the request. ``key``: the channel's per-connection key
    (32 random bytes, never recorded), for the account's HMAC. ``read_endpoints``: the extra
    ``[gate] read_endpoints`` as ``host/path`` (see ``read_post.check_read_endpoint``).
    ``owner_accounts``: the ``account`` ids (``account_id`` with this ``key``) of the owner's own
    mailboxes: only there do drafts pass without asking (docs/32, decision 12)."""

    key: bytes
    scrub: KnownScrubber = field(default_factory=lambda: KnownScrubber(()))
    read_endpoints: frozenset[str] = frozenset()
    owner_accounts: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) < 16:
            raise ValueError("the gate's key must be 16+ bytes")
        if not all(
            isinstance(item, str) and _ACCOUNT_RE.fullmatch(item) for item in self.owner_accounts
        ):
            raise ValueError("an owner account is the 16 hex of its account id")

    def __repr__(self) -> str:
        return (
            f"Context({len(self.read_endpoints)} read endpoints, "
            f"{len(self.owner_accounts)} owner accounts)"
        )


class Unreadable(Exception):
    """A part of the request that cannot be read strictly. ``note`` says why (fixed text)."""

    def __init__(self, note: Note = Note.UNPARSED) -> None:
        super().__init__(str(note))
        self.note = note


# --- readings ------------------------------------------------------------------------------------


def unknown(
    translator: str,
    shape: Shape,
    wait_s: int,
    *notes: Note,
    account: str | None = None,
    target: str | None = None,
    path_credential: bool = False,
) -> Reading:
    """Not understood: the gate holds it with a technical description."""
    return Reading(
        translator=translator,
        operation="unknown",
        effect=Effect.UNKNOWN,
        shape=shape,
        wait_s=wait_s,
        account=account,
        target=target,
        path_credential=path_credential,
        notes=tuple(dict.fromkeys(notes or (Note.NOT_IN_TABLE,))),
    )


def common_refusal(view: RequestView) -> Note | None:
    """What makes any request unreadable for every translator."""
    if view.trailers:
        return Note.UNPARSED
    if len(view.body) > MAX_BODY:
        return Note.TOO_LARGE
    types = 0
    for name, value in view.headers:
        lowered = name.strip().lower()
        if lowered in OVERRIDE_HEADERS:
            return Note.METHOD_OVERRIDE
        if lowered == "content-encoding" and value.strip().lower() not in ("", "identity"):
            return Note.UNPARSED
        if lowered == "content-type":
            types += 1
    if types > 1:
        return Note.DUPLICATE
    return None


# --- paths, queries and forms --------------------------------------------------------------------


def split_path(path: str) -> tuple[tuple[str, ...], str]:
    """(segments, query) of a canonical path. Unreadable for "", ".", "..", escapes, ";", "\\",
    "//", a fragment or anything odd: a server could read those otherwise than the gate. One
    trailing slash is dropped (a read or a write either way: no table has both forms)."""
    raw, _mark, query = path.partition("?")
    if not raw.startswith("/") or "#" in path:
        raise Unreadable
    if raw.endswith("/"):
        raw = raw[:-1]  # one trailing slash: "/intl/en/" is ("intl", "en"), "/" is ()
    segments = tuple(raw[1:].split("/")) if raw else ()
    if not all(_SEGMENT_RE.fullmatch(segment) for segment in segments):
        raise Unreadable
    return segments, query


def parse_pairs(text: str) -> dict[str, str]:
    """A query or a urlencoded form, names case-folded: each name once (Unreadable otherwise),
    ``&`` only."""
    if not text:
        return {}
    if ";" in text:
        raise Unreadable  # some servers split on ";" too
    try:
        pairs = parse_qsl(text, keep_blank_values=True, errors="strict", max_num_fields=MAX_PARAMS)
    except (ValueError, UnicodeDecodeError):
        raise Unreadable(
            Note.TOO_LARGE if text.count("&") >= MAX_PARAMS else Note.UNPARSED
        ) from None
    result: dict[str, str] = {}
    for name, value in pairs:
        folded = name.casefold()  # as strict_json: two names that fold the same are refused
        if folded in result:
            raise Unreadable(Note.DUPLICATE)
        result[folded] = value
    return result


def decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unreadable from None


def media_type(headers: Sequence[tuple[str, str]]) -> str | None:
    """The body's media type, lower case, without parameters; None when absent."""
    raw = content_type(headers)
    return None if raw is None else raw.split(";", 1)[0].strip().lower()


def content_type(headers: Sequence[tuple[str, str]]) -> str | None:
    values = header_values(headers, "content-type")
    if len(values) > 1:
        raise Unreadable(Note.DUPLICATE)
    return values[0] if values else None


def header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.strip().lower() == name]


def credential(headers: Sequence[tuple[str, str]]) -> str | None:
    """The ``Authorization`` header, whole (it may be ``Bearer x`` or ``Bot x``)."""
    values = header_values(headers, "authorization")
    if len(values) > 1:
        raise Unreadable(Note.DUPLICATE)
    return values[0].strip() if values else None


def account_id(context: Context, translator: str, *parts: str | None) -> str | None:
    """16 hex of an HMAC of the credential (and the mailbox it acts on), or None without any."""
    if not any(parts):
        return None
    message = b"\0".join(
        [b"backtide-account-v1", translator.encode()]
        + [(part or "").encode("utf-8", "surrogatepass") for part in parts]
    )
    return hmac.new(context.key, message, hashlib.sha256).hexdigest()[:16]


# --- JSON ----------------------------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Keys case-folded, two that fold the same refused: some servers' readers match keys
    without case (Go), so two readers could each keep a different one (provider_tools.py)."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        folded = key.casefold()
        if folded in result:
            raise Unreadable(Note.DUPLICATE)
        result[folded] = value
    return result


def _no_constant(name: str) -> Any:
    raise Unreadable  # NaN and Infinity are not JSON


def strict_json(data: bytes | str) -> Any:
    """UTF-8 JSON, read strictly: no duplicate keys (case-folded: every object's keys come back
    case-folded), no NaN, no BOM, at most MAX_NODES values and Python's nesting limit."""
    raw = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else data
    if raw.count(b"{") + raw.count(b"[") + raw.count(b",") > MAX_NODES:
        raise Unreadable(Note.TOO_LARGE)
    try:
        text = raw.decode("utf-8") if isinstance(data, bytes) else data
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Unreadable from None


def json_object(data: bytes | str) -> dict[str, Any]:
    value = strict_json(data)
    if not isinstance(value, dict):
        raise Unreadable
    return value


# --- multipart/form-data -------------------------------------------------------------------------


@dataclass(frozen=True)
class FormPart:
    name: str
    filename: str | None
    type: str | None
    data: bytes


def parse_multipart(header: str, body: bytes) -> list[FormPart]:
    """A ``multipart/form-data`` body: flat, each field named once, no defects, bounded."""
    if len(body) > MAX_MIME:
        raise Unreadable(Note.TOO_LARGE)
    if header.lower().count("boundary") != 1 or "\r" in header or "\n" in header:
        raise Unreadable
    message = message_from_bytes(
        b"Content-Type: " + header.encode("utf-8", "surrogateescape") + b"\r\n\r\n" + body,
        policy=compat32,
    )
    if not message.is_multipart() or message.get_content_type() != "multipart/form-data":
        raise Unreadable
    payload = message.get_payload()
    if message.defects or not isinstance(payload, list) or not payload:
        raise Unreadable
    if len(payload) > MAX_PARTS:
        raise Unreadable(Note.TOO_LARGE)
    parts: list[FormPart] = []
    names: set[str] = set()
    for part in payload:
        if not isinstance(part, Message) or part.defects or part.is_multipart():
            raise Unreadable
        if len(part.get_all("content-disposition") or []) != 1:
            raise Unreadable
        if part.get_content_disposition() != "form-data":
            raise Unreadable
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            raise Unreadable
        if name in names:
            raise Unreadable(Note.DUPLICATE)
        names.add(name)
        data = part.get_payload(decode=True)
        if not isinstance(data, bytes):
            raise Unreadable
        filename = part.get_filename()
        kind = part.get_content_type() if part.get("content-type") else None
        parts.append(FormPart(name, filename if isinstance(filename, str) else None, kind, data))
    return parts


# --- the parameters of an RPC-style API (Telegram, Slack) ----------------------------------------


def rpc_params(view: RequestView, query: str) -> tuple[dict[str, Any], list[FormPart]]:
    """The parameters (names case-folded) from the query and the body (JSON, urlencoded form or
    multipart), and the files of a multipart body. A name in both places, or twice, is
    Unreadable: two readers could each keep a different one. A body of any other type is
    Unreadable."""
    params: dict[str, Any] = dict(parse_pairs(query))
    files: list[FormPart] = []
    if not view.body:
        return params, files
    if view.method in READ_METHODS:
        raise Unreadable  # a GET with a body: who reads which?
    kind = media_type(view.headers)
    body: dict[str, Any]
    if kind == "application/json":
        body = json_object(view.body)
    elif kind == "application/x-www-form-urlencoded":
        body = dict(parse_pairs(decode_utf8(view.body)))
    elif kind == "multipart/form-data":
        body = {}
        for part in parse_multipart(content_type(view.headers) or "", view.body):
            if part.filename is None:
                try:
                    body[part.name] = part.data.decode("utf-8")
                    continue
                except UnicodeDecodeError:
                    pass
            files.append(part)
            body[part.name] = {"file": part.filename or part.name}
    else:
        raise Unreadable
    if len(body) > MAX_PARAMS:
        raise Unreadable(Note.TOO_LARGE)
    for name, value in body.items():
        folded = name.casefold()
        if folded in params:
            raise Unreadable(Note.DUPLICATE)
        params[folded] = value
    if len(params) > MAX_PARAMS:
        raise Unreadable(Note.TOO_LARGE)
    return params, files


# --- texts shown ---------------------------------------------------------------------------------


def clean(text: str, scrub: KnownScrubber, limit: int) -> tuple[str, bool]:
    """(struck and cut to ``limit`` characters, whether striking removed anything). Striking
    goes past the cut, as in record.py, so a secret that crosses it is struck whole."""
    window = text[: limit + _MARGIN]
    struck = strike_text(scrub.text(window))
    changed = struck != window
    if len(text) > len(window):
        struck = struck[:-_MARGIN]
    return struck[:limit], changed


def opt_clean(text: str | None, scrub: KnownScrubber, limit: int) -> str | None:
    if text is None:
        return None
    value = clean(text, scrub, limit)[0].strip()
    return value or None


def has_secret(text: str, scrub: KnownScrubber) -> bool:
    """Whether striking would remove anything from ``text``, searched whole. A text over
    SECRET_SCAN_CHARS is taken as carrying a secret: a scan is never cut short."""
    if len(text) > SECRET_SCAN_CHARS:
        return True
    return scrub.text(text) != text or strike_text(text) != text


def data_has_secret(data: bytes, scrub: KnownScrubber) -> bool:
    """Whether a file's content carries a secret: its UTF-8 text (undecodable bytes dropped,
    so a key appended to an image is still found), searched whole."""
    return has_secret(data.decode("utf-8", "ignore"), scrub)


def has_secret_in(value: Any, scrub: KnownScrubber) -> bool:
    """Whether a parsed JSON value carries a secret at any depth: its texts (keys and values, one
    per line, so a secret alone in a field is found) and its JSON (where a secret NAME next to
    its value shows: ``{"password": "..."}`` nested in a message). Bounded by MAX_NODES."""
    texts: list[str] = []
    stack: list[Any] = [value]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            return True  # too large to search: taken as carrying one
        if isinstance(item, str):
            texts.append(item)
        elif isinstance(item, dict):
            for key, inner in item.items():
                texts.append(str(key))
                stack.append(inner)
        elif isinstance(item, list | tuple):
            stack.extend(item)
    if has_secret("\n".join(texts), scrub):
        return True
    try:
        dumped = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        return True
    return has_secret(dumped, scrub)


def body_has_secret(body: bytes, scrub: KnownScrubber) -> bool:
    """Whether a request body carries a secret: as it came, %-decoded (a form) and, when it is
    JSON, with its escapes read (``\\u0073k-...``)."""
    text = body.decode("utf-8", "replace")
    if has_secret(text, scrub) or has_secret(unquote_plus(text), scrub):
        return True
    try:
        parsed = strict_json(body)
    except Unreadable:
        return False
    return has_secret_in(parsed, scrub)


def nested_text(value: object, keys: frozenset[str]) -> str | None:
    """The texts under ``keys`` at any depth of a message's nested parts (Slack blocks, Discord
    embeds), in order, one per line: what the recipient reads there. A JSON text (a form field)
    is read first; one that is not JSON is shown as it is. Bounded by MAX_NODES."""
    if isinstance(value, str):
        try:
            value = strict_json(value)
        except Unreadable:
            return value or None
    found: list[str] = []
    stack: list[tuple[bool, object]] = [(False, value)]  # (a text to show, the item)
    nodes = 0
    while stack:
        shown_text, item = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise Unreadable(Note.TOO_LARGE)
        if shown_text:
            found.append(str(item))
        elif isinstance(item, dict):
            for key, inner in reversed(list(item.items())):
                stack.append((key in keys and isinstance(inner, str), inner))
        elif isinstance(item, list):
            stack.extend((False, inner) for inner in reversed(item))
    shown = "\n".join(text for text in found if text.strip())
    return shown or None


def guard_read(view: RequestView, reading: Reading, scrub: KnownScrubber) -> Reading:
    """A read carried by a body (a POST to a read API, a "harmless" write) passes only when its
    body is small and carries no secret: an agent told to "search" with a key in the query, or
    to label a message with one, would otherwise hand it out without asking. Over MAX_READ_BODY
    it is UNKNOWN (held); with a secret, UNKNOWN with risk 3."""
    if reading.effect is not Effect.READ or (view.method in READ_METHODS and not view.body):
        return reading
    held = (reading.translator, reading.shape, reading.wait_s)
    options: dict[str, Any] = {
        "account": reading.account,
        "path_credential": reading.path_credential,
    }
    if len(view.body) > MAX_READ_BODY:
        return unknown(*held, Note.TOO_LARGE, **options)
    body = _without_own_token(view) if reading.translator == "slack" else view.body
    if reading.secret_seen or body_has_secret(body, scrub):
        return replace(unknown(*held, Note.SECRET_SEEN, **options), secret_seen=True)
    return reading


def _without_own_token(view: RequestView) -> bytes:
    """Slack's body without its ``token`` field when that field is exactly the request's own
    ``Authorization`` token (``@slack/web-api`` repeats it there, see slack.py): it goes to the
    same API that it authenticates with, so it is not a secret leaving. Only that field, only a
    urlencoded form or a JSON object: the same token anywhere else in the body, or any other
    secret, still counts (review of T10-3, M6). Anything that cannot be read is left whole."""
    try:
        value = credential(view.headers)
        if value is None:
            return view.body
        token = value[7:].strip() if value.lower().startswith("bearer ") else value
        kind = media_type(view.headers)
        if kind == "application/x-www-form-urlencoded":
            pairs = parse_qsl(decode_utf8(view.body), keep_blank_values=True, strict_parsing=True)
            kept = [(name, item) for name, item in pairs if not (name == "token" and item == token)]
            if len(kept) == len(pairs):
                return view.body
            return "&".join(f"{name}={item}" for name, item in kept).encode()
        if kind == "application/json":
            data = json_object(view.body)
            if data.get("token") != token:
                return view.body
            return json.dumps({k: v for k, v in data.items() if k != "token"}).encode()
    except (Unreadable, ValueError):
        return view.body
    return view.body


# --- what a platform fetches (review of T10-3, M3) -----------------------------------------------

# A link as Telegram, Slack and Discord find one in a text: with a scheme, from "www.", or a bare
# domain name (Telegram previews "evil.example/x" too). A file name such as "plan.pdf" reads as
# one as well: such a text is held, never let out unseen.
_URL_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s<>\"']+"
    r"|\bwww\.[^\s<>\"']+"
    r"|(?<![\w@.-])(?:[^\W_][\w-]{0,62}\.)+(?:[^\W\d_]{2,63}|xn--[a-z0-9-]{1,59})(?![\w@-])"
    r"(?:[/?#:][^\s<>\"']*)?"
)
_HTTP_RE = re.compile(r"(?i)\s*https?://")


def find_url(text: str) -> str | None:
    """The first link in ``text`` that a platform would fetch a preview of, or None."""
    match = _URL_RE.search(text)
    return None if match is None else match.group(0)


def is_http_url(value: object) -> bool:
    """Whether a file parameter is a URL the platform downloads (not a file id or an upload)."""
    return isinstance(value, str) and _HTTP_RE.match(value) is not None


def walk_fields(value: object) -> list[tuple[str | None, Any]]:
    """Every (key, value) at any depth of parsed parameters, reading a string that holds a JSON
    object or list (a form's ``media``, ``blocks``, ``link_preview_options``) as JSON too.
    Bounded by MAX_NODES (Unreadable past it)."""
    found: list[tuple[str | None, Any]] = []
    stack: list[tuple[str | None, Any, int]] = [(None, value, 0)]
    nodes = 0
    while stack:
        key, item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise Unreadable(Note.TOO_LARGE)
        if isinstance(item, str) and depth < 4 and item.lstrip()[:1] in ("{", "["):
            try:
                item = strict_json(item)
                depth += 1
            except Unreadable:
                pass
        found.append((key, item))
        if isinstance(item, dict):
            stack.extend((str(name), inner, depth) for name, inner in item.items())
        elif isinstance(item, list):
            stack.extend((key, inner, depth) for inner in item)
    return found


def fetch_target(url: str, scrub: KnownScrubber) -> str | None:
    """What the person reads of a fetched URL (struck and cut, as every target)."""
    return opt_clean(f"opens {url}", scrub, TARGET_CHARS)


def first_lines(text: str | None, scrub: KnownScrubber) -> str | None:
    """The first LINES non-blank lines, struck, at most LINES_CHARS characters."""
    if not text:
        return None
    struck, _ = clean(text.lstrip(), scrub, LINES_CHARS * 2)
    lines = [line.strip() for line in re.split(r"\r\n|\r|\n", struck)]
    shown = "\n".join([line for line in lines if line.strip()][:LINES])[:LINES_CHARS]
    return shown or None


def html_text(html: str) -> str:
    """A rough plain text of an HTML body, for its first lines only (bounded)."""
    head = html[: LINES_CHARS * 64]
    head = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", head)
    head = re.sub(r"(?i)<br\s*/?>|</p\s*>|</div\s*>", "\n", head)
    return unescape(_TAG_RE.sub(" ", head))


def plain_media_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.split(";", 1)[0].strip().lower()
    return lowered if _MEDIA_TYPE_RE.fullmatch(lowered) else None


def attachment(
    name: str | None, kind: object, data: bytes | None, scrub: KnownScrubber
) -> tuple[Attachment, list[str | int | None]]:
    """The attachment shown, and its entry in the canonical form (name, type, size, SHA-256)."""
    shown = opt_clean(name, scrub, NAME_CHARS) or "(no name)"
    media = plain_media_type(kind)
    size = len(data) if data is not None else 0
    digest = hashlib.sha256(data).hexdigest() if data is not None else None
    return Attachment(shown, media, size), [name, media, size, digest]


def safe_id(value: object, limit: int = 64) -> str | None:
    """An id the API gave (draft, message, webhook) when it is plain; None otherwise."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if isinstance(value, str) and _HOLD_SAFE_RE.fullmatch(value) and len(value) <= limit:
        return value
    return None


def draft_ref(mailbox: str, value: object) -> str | None:
    """How a saved draft is named in a reading: 32 hex of the SHA-256 of its mailbox and its id,
    for any id the API gave, plain or not (Graph's are long and end in "="). Never of the token:
    a refreshed token acts on the same draft (review of T10-3, M7). None without an id."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    message = b"\0".join(
        [b"backtide-draft-v1"]
        + [part.encode("utf-8", "surrogatepass") for part in (mailbox.lower(), value)]
    )
    return hashlib.sha256(message).hexdigest()[:32]


# --- mail addresses ------------------------------------------------------------------------------


def normalize_email(address: str) -> tuple[str, bool] | None:
    """(lower-case address with its domain in IDNA, whether the domain is international), or
    None when it is not a plain ``local@domain`` (quoted local parts and IP literals refused)."""
    local, at, domain = address.strip().rpartition("@")
    if not at or not _LOCAL_PART_RE.fullmatch(local):
        return None
    if local.startswith(".") or local.endswith(".") or ".." in local or "=?" in local:
        return None  # "=?": an encoded word, which a server might decode into another name
    host = normalize_host(domain, idna=True)
    if host is None or is_ip(host) or "." not in host:
        return None
    international = not domain.isascii() or any(
        label.startswith("xn--") for label in host.split(".")
    )
    return f"{local.lower()}@{host}", international


def _utf8_header(value: str) -> str:
    """A raw header from the bytes parser: its non-ASCII bytes (surrogate-escaped) read as UTF-8,
    strictly. Control characters are Unreadable."""
    try:
        text = value.encode("ascii", "surrogateescape").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        raise Unreadable(Note.BAD_ADDRESS) from None
    if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
        raise Unreadable(Note.BAD_ADDRESS)
    return text


_FOLD_RE = re.compile(r"\r?\n[ \t]")
# One entry of an address list, as plainly as it can be written: an address, or a display name
# (a quoted string without escapes, or a phrase without specials) and an address in angles.
_ADDRESS = r"[^\s\"<>(),;:\\\[\]@]+@[^\s\"<>(),;:\\\[\]@]+"
_NAME = r"\"[^\"\\]*\"|[^\"<>(),;:\\\[\]@]*?"  # quoted without escapes, or a plain phrase
_ENTRY_RE = re.compile(
    rf"\s*(?:(?P<bare>{_ADDRESS})|(?P<name>{_NAME})\s*<(?P<angle>{_ADDRESS})>)\s*"
)
_ENCODED_SPECIALS = frozenset('@<>,;:"\\()[]')


def _plain_entries(text: str) -> list[str]:
    """The addresses of an address header read with the plainest grammar, or Unreadable: no
    comments, groups, escapes, nested quotes or route addresses, and no encoded word that
    decodes into a special character. The standard library has read such headers otherwise in
    some versions (CVE-2023-27043): ``parse_addresses`` keeps a header only when both agree."""
    entries: list[str] = []
    current: list[str] = []
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
        if char == "," and not quoted:
            entries.append("".join(current))
            current = []
        else:
            current.append(char)
    if quoted:
        raise Unreadable(Note.BAD_ADDRESS)
    entries.append("".join(current))
    found: list[str] = []
    for entry in entries:
        match = _ENTRY_RE.fullmatch(entry)
        if match is None:
            raise Unreadable(Note.BAD_ADDRESS)
        name = match.group("name")
        if name and "=?" in name and _encoded_special(name):
            raise Unreadable(Note.BAD_ADDRESS)
        found.append(match.group("bare") or match.group("angle"))
    return found


def _encoded_special(name: str) -> bool:
    """Whether an encoded word in a display name decodes into a special character (an ``@``,
    a comma, a quote...), which a reader that decodes it would take for part of an address."""
    try:
        chunks = decode_header(name.strip('"'))
    except (ValueError, LookupError, binascii.Error):
        return True
    for chunk, charset in chunks:
        if isinstance(chunk, bytes):
            if charset is None:
                continue  # plain text between encoded words, already checked
            try:
                chunk = chunk.decode(charset, "replace")
            except LookupError:
                return True
        if any(char in _ENCODED_SPECIALS for char in chunk):
            return True
    return False


def parse_addresses(values: Iterable[str]) -> tuple[list[str], bool]:
    """(the addresses of address headers, normalized; whether any is international). Only the
    address counts, never the display name: ``"ana@x.com" <evil@y.com>`` is ``evil@y.com``.
    Unreadable when the standard library cannot read them strictly, or when it and the plainest
    grammar (``_plain_entries``) do not find the same addresses."""
    found: list[str] = []
    international = False
    for value in values:
        text = _FOLD_RE.sub(" ", _utf8_header(value))
        if not text.strip():
            continue
        if "\r" in text or "\n" in text:
            raise Unreadable(Note.BAD_ADDRESS)
        plain = _plain_entries(text)
        parsed = [address for _name, address in getaddresses([text])]
        if parsed != plain:
            raise Unreadable(Note.BAD_ADDRESS)
        for address in parsed:
            normalized = normalize_email(address) if address else None
            if normalized is None:
                raise Unreadable(Note.BAD_ADDRESS)
            found.append(normalized[0])
            international |= normalized[1]
            if len(found) > MAX_RECIPIENTS:
                raise Unreadable(Note.TOO_MANY_RECIPIENTS)
    return found, international


# --- MIME mail -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Mail:
    sender: str | None
    recipients: tuple[str, ...]  # To, Cc and Bcc
    reply_to: tuple[str, ...]
    subject: str | None  # decoded, NOT struck yet
    text: str | None  # the first text part (or HTML made text), decoded, NOT struck yet
    texts: tuple[str, ...]  # the text and HTML parts shown, whole: what is searched for secrets
    attachments: tuple[tuple[str | None, str | None, bytes, bool], ...]  # name, type, data, inline
    international: bool
    canonical: dict[str, Any]  # headers and parts, without Date, Message-ID or boundaries


_SINGLE_MAIL_HEADERS = ("from", "to", "cc", "bcc", "reply-to", "subject", "sender")
_RESENT_HEADERS = ("resent-to", "resent-cc", "resent-bcc", "resent-from", "resent-sender")
_VOLATILE_HEADERS = frozenset({"date", "message-id"})


def parse_mail(data: bytes) -> Mail:
    """An RFC 822 message (what gog builds), with the standard library, strictly and bounded:
    each address header at most once, no ``Resent-*`` (which a server might send to), no
    defects, at most MAX_PARTS parts and MAX_ATTACHMENTS attachments.

    What the person sees must be what the recipient gets: the first ``text/plain`` part is the
    text, and the first ``text/html`` part its alternative. Any other part (a second text, an
    inline image) is an attachment, named "(inline <type>)" when it has no name. When both a
    plain text and an HTML exist and the HTML says something else (other words, or a link or an
    image the text does not carry), the mail is Unreadable with ``ALTERNATIVE_DIFFERS``: most
    clients show the HTML, so the first lines would not be what the recipient reads."""
    if len(data) > MAX_MIME:
        raise Unreadable(Note.TOO_LARGE)
    if data.lower().count(b"boundary") > MAX_BOUNDARIES:
        raise Unreadable(Note.TOO_LARGE)
    message = message_from_bytes(data, policy=compat32)
    if message.defects:
        raise Unreadable
    raw = _raw_headers(message)
    for name in _SINGLE_MAIL_HEADERS:
        if len(raw.get(name, [])) > 1:
            raise Unreadable(Note.DUPLICATE)
    if any(name in raw for name in _RESENT_HEADERS):
        raise Unreadable(Note.NOT_IN_TABLE)
    recipients, international = parse_addresses(
        [value for name in ("to", "cc", "bcc") for value in raw.get(name, [])]
    )
    reply_to, reply_international = parse_addresses(raw.get("reply-to", []))
    senders, sender_international = parse_addresses(raw.get("from", []))
    if len(senders) > 1:
        raise Unreadable(Note.BAD_ADDRESS)
    text: str | None = None
    html: str | None = None
    attachments: list[tuple[str | None, str | None, bytes, bool]] = []
    parts_canonical: list[list[Any]] = []
    walked = 0
    for part in message.walk():
        walked += 1
        if walked > MAX_PARTS:
            raise Unreadable(Note.TOO_LARGE)
        if part.defects:
            raise Unreadable
        headers = _canonical_headers(part)
        if part.is_multipart():
            parts_canonical.append([headers, None])
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise Unreadable
        parts_canonical.append([headers, hashlib.sha256(payload).hexdigest()])
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        kind = part.get_content_type()
        if filename is None and disposition != "attachment":
            if kind == "text/plain" and text is None:
                text = _decode_part(part, payload)
                continue
            if kind == "text/html" and html is None:
                html = _decode_part(part, payload)
                continue
        attachments.append((filename, kind, payload, filename is None))
        if len(attachments) > MAX_ATTACHMENTS:
            raise Unreadable(Note.TOO_MANY_ATTACHMENTS)
    texts = tuple(item for item in (text, html) if item is not None)
    if text is not None and html is not None and _alternative_differs(text, html):
        raise Unreadable(Note.ALTERNATIVE_DIFFERS)
    if text is None and html is not None:
        text = html_text(html)
    return Mail(
        sender=senders[0] if senders else None,
        recipients=tuple(recipients),
        reply_to=tuple(reply_to),
        subject=_subject(raw.get("subject", [None])[0]),
        text=text,
        texts=texts,
        attachments=tuple(attachments),
        international=international or reply_international or sender_international,
        canonical={"parts": parts_canonical},
    )


_URL_ATTRIBUTES = frozenset(
    {"href", "src", "srcset", "action", "formaction", "background", "poster", "data", "cite"}
)
_WORD_RE = re.compile(r"\w+")


class _HtmlWords(HTMLParser):
    """What an HTML part puts before the recipient: its text (comments too: Outlook shows
    conditional ones) and the URLs of its links and images. Scripts and styles are not shown."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.texts: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._hidden += 1
        self.texts.extend(value for name, value in attrs if name in _URL_ATTRIBUTES and value)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.texts.extend(value for name, value in attrs if name in _URL_ATTRIBUTES and value)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.texts.append(data)

    def handle_comment(self, data: str) -> None:
        self.texts.append(data)


def _alternative_differs(text: str, html: str) -> bool:
    """Whether an HTML alternative says something its plain text does not: the words of the
    HTML (its text and its links' and images' URLs) against the plain text's, as multisets,
    ignoring case, spacing and punctuation. Bounded: an HTML over MAX_HTML_COMPARE is not read."""
    if len(html) > MAX_HTML_COMPARE:
        raise Unreadable(Note.TOO_LARGE)
    parser = _HtmlWords()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # what HTMLParser raises on input it cannot take
        raise Unreadable from None
    words = Counter(_WORD_RE.findall(" ".join(parser.texts).casefold()))
    return words != Counter(_WORD_RE.findall(text.casefold()))


def _raw_headers(part: Message) -> dict[str, list[str]]:
    """The headers as they came (non-ASCII bytes surrogate-escaped), by lower-case name.
    ``get()`` would give ``Header`` objects for non-ASCII ones under compat32."""
    found: dict[str, list[str]] = {}
    for name, value in part.raw_items():
        found.setdefault(name.lower(), []).append(str(value))
    return found


def _canonical_headers(part: Message) -> list[list[str]]:
    """Every header but Date and Message-ID, in order; Content-Type without its boundary."""
    headers: list[list[str]] = []
    for name, value in part.raw_items():
        lowered = name.lower()
        if lowered in _VOLATILE_HEADERS:
            continue
        if lowered == "content-type":
            params = [
                f"{key.lower()}={val}"
                for key, val in (part.get_params() or [])[1:]
                if key.lower() != "boundary"
            ]
            value = ";".join([part.get_content_type(), *sorted(params)])
        else:
            value = " ".join(value.split())  # unfolded
        headers.append([lowered, value])
    return headers


def _decode_part(part: Message, payload: bytes) -> str:
    charset = part.get_content_charset() or "us-ascii"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        raise Unreadable from None  # an encoding Python does not know


def _subject(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.encode("ascii", "surrogateescape").decode("utf-8", "replace")
    try:
        return str(make_header(decode_header(value)))
    except (UnicodeError, LookupError, ValueError, binascii.Error):
        return value  # only shown, struck: an odd encoding is shown as it came


def b64url_decode(text: object) -> bytes:
    """Base64url as Gmail reads ``raw``: the URL-safe alphabet only, padding optional."""
    if not isinstance(text, str) or not _B64URL_RE.fullmatch(text):
        raise Unreadable
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text.rstrip("=")) % 4))
    except (binascii.Error, ValueError):
        raise Unreadable from None


def b64_decode(text: object) -> bytes:
    """Standard base64 (Graph's ``contentBytes``), validated."""
    if not isinstance(text, str) or not _B64_RE.fullmatch(text):
        raise Unreadable
    try:
        return base64.b64decode(re.sub(r"[\r\n]", "", text), validate=True)
    except (binascii.Error, ValueError):
        raise Unreadable from None


# --- the semantic fingerprint's input (docs/32, decision 2) ---------------------------------------


def _bounded(value: Any) -> Any:
    """Top-level values for the canonical form: long strings and bytes as their SHA-256, nested
    values as their sorted JSON (hashed when long), so the canonical form stays small."""
    if isinstance(value, bytes):
        return "sha256:" + hashlib.sha256(value).hexdigest()
    if isinstance(value, dict | list | tuple):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if isinstance(value, str) and len(value) > _LONG_VALUE:
        return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return value


def semantic_canonical(
    *,
    translator: str,
    host: str,
    port: int,
    operation: str,
    account: str | None,
    recipients: Sequence[str],
    fields: Mapping[str, Any],
    files: Sequence[Sequence[Any]] = (),
) -> bytes:
    """The bytes the semantic fingerprint HMACs: what the request does, from which account,
    to whom, with all its fields (the caller leaves out only what changes on every build of
    the same message: Date, Message-ID, MIME boundaries, Discord's nonce) and each file's
    name, type, size and hash. Deterministic: sorted keys, ASCII, no spaces. Never recorded."""
    document = {
        "translator": translator,
        "host": host,
        "port": port,
        "operation": operation,
        "account": account,
        "recipients": list(recipients),
        "fields": {str(key): _bounded(value) for key, value in fields.items()},
        "files": [_bounded(list(entry)) for entry in files],
    }
    text = json.dumps(
        document, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    )
    return b"backtide-semantic-v1\n" + text.encode("ascii")


# --- trusted recipients (docs/32, section 9) -----------------------------------------------------


_SLACK_ID_RE = re.compile(r"[CGD][A-Z0-9]{8,}", re.ASCII)
_UNTRUSTABLE = frozenset({Note.FETCHES_URL, Note.INLINE_MESSAGE})


@dataclass(frozen=True)
class Trusted:
    """A ``[gate] trusted`` entry: a translator and one normalized recipient."""

    translator: str
    recipient: str


def normalize_trusted(translator: str, recipient: str) -> Trusted:
    """A trusted entry as the translators normalize recipients. ValueError, with a message
    that is safe to show, for one that could never match."""
    value = recipient.strip()
    if translator in ("gmail", "graph_mail"):
        normalized = normalize_email(value)
        if normalized is None:
            raise ValueError("a trusted mail recipient is a plain address: name@domain")
        return Trusted(translator, normalized[0])
    if translator == "telegram":
        from backtide.gate.translate.telegram import chat_id

        chat = chat_id(value)
        if chat is None:
            raise ValueError("a trusted Telegram chat is a number or @username")
        return Trusted(translator, chat)
    if translator == "slack":
        if not _SLACK_ID_RE.fullmatch(value):
            raise ValueError("a trusted Slack channel is its id (C…, G… or D…), never its name")
        return Trusted(translator, value)
    if translator == "discord":
        if not value or not value.isprintable() or len(value) > 128:
            raise ValueError("a trusted channel is its id")
        return Trusted(translator, value)
    raise ValueError("trusted recipients are for gmail, graph_mail, telegram, slack or discord")


def all_trusted(reading: Reading, trusted: Iterable[Trusted]) -> bool:
    """Whether a reading goes to trusted recipients only (docs/32, section 9): a send or a
    change, with at least one recipient, every one of them trusted for its translator, and
    no secret struck from it. Never a forward, a deletion, an administration or the unknown;
    never one that makes the platform fetch a URL or edits an inline message (review of T10-3,
    M3 and H2); and a Slack channel only by its id (M4)."""
    if reading.effect not in (Effect.SEND, Effect.CHANGE) or not reading.recipients:
        return False
    if reading.secret_seen or _UNTRUSTABLE & set(reading.notes):
        return False
    allowed = {item.recipient for item in trusted if item.translator == reading.translator}
    if reading.translator == "slack" and not all(
        _SLACK_ID_RE.fullmatch(recipient) for recipient in reading.recipients
    ):
        return False
    return all(recipient in allowed for recipient in reading.recipients)
