"""git's smart HTTP protocol on GitHub (docs/34, decision 6; T17b-1): ``clone``, ``fetch``,
``pull`` and ``ls-remote`` pass, and a push is held saying which repository and which refs it
creates, updates or deletes. Pure, bounded.

Only ``github.com``, and only the three smart HTTP routes of a repository (with or without
``.git``); every other path of ``github.com`` follows the gate's plain rules:

    GET|HEAD /<owner>/<repo>/info/refs[?service=git-upload-pack|git-receive-pack]
    POST     /<owner>/<repo>/git-upload-pack    (application/x-git-upload-pack-request)
    POST     /<owner>/<repo>/git-receive-pack   (application/x-git-receive-pack-request)

The account is the HMAC of the credential and the repository (``github.com/owner/repo``, lower
case, without ``.git``), as Gmail's is of the token and the mailbox. So a batch keeps to one
repository: "este tipo de acción, 1 h" is every push to this repository that deletes nothing,
for an hour, and "todo a este destinatario, esta sesión" every push to these refs of it.

- READ: the discovery (``info/refs``), and ``git-upload-pack``, whose server only sends: its
  body must be well-formed pkt-lines (and, as every read a body carries, small and without a
  secret: ``base.guard_read``). And the probe git sends before a push over ``http.postBuffer``
  (``remote-curl.c``, ``probe_rpc``): a ``git-receive-pack`` whose body is a lone flush-pkt,
  an empty command list the server does nothing with.
- CHANGE (risk 2): a push that creates or updates refs. Its commands (``old new ref``) are read
  from the pkt-lines at the start of the body: the recipients are the refs, in full
  (``refs/heads/main``), and the target says the repository and what happens to each one.
- DELETE (risk 3): a push with at least one deletion (its new id is all zeros).
- UNKNOWN (held): anything not read strictly: a pkt-line that is truncated, whose length is not
  four hex digits or is over 65520, or that is a control packet among the commands; no command
  (but the probe), more than MAX_COMMANDS, the same ref twice, an id that is not one, a ref
  name git itself refuses or that has any character outside the plain ones (the target shows
  it escaped), a signed push (``push-cert``), push options (the server may act on them: GitLab
  opens merge requests with them), or anything after the commands that is not a pack.

What the body says and what it cannot: the commands say exactly which refs move, from which id
to which id, and whether the push is atomic. Whether an update is a fast-forward or rewrites
history (a forced push) cannot be known from it: git sends the same command for both (the
``+`` of a refspec stays in the client) and only the server's history says whether the old id
is an ancestor of the new one. Nor can what the commits carry be read: the pack is compressed,
and a thin pack is deltas against objects only the server has. So a push is never READ, never
trusted to carry no secret, and its notice says both (``phrase``). A secret in what can be read
(a ref name, a capability) makes it UNKNOWN with risk 3.

The semantic fingerprint (``Reading.canonical``, decision 2 of docs/32) is the repository, the
account, the commands, the shallow lines, the capabilities but ``agent`` and ``session-id``
(which change with each git and each run) and the SHA-256 of the pack.
"""

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, replace

from backtide.blackbox.redact import KnownScrubber
from backtide.gate.phrase import cut_middle
from backtide.gate.providers import CREDENTIAL_HEADERS
from backtide.gate.translate.base import (
    MAX_READ_BODY,
    MAX_RECIPIENTS,
    READ_METHODS,
    TARGET_CHARS,
    WAIT_DEFAULT,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    clean,
    credential,
    has_secret,
    media_type,
    parse_pairs,
    semantic_canonical,
    unknown,
)

NAME = "git"
HOSTS = frozenset({"github.com"})
UPLOAD = "git-upload-pack"
RECEIVE = "git-receive-pack"
SERVICES = frozenset({UPLOAD, RECEIVE})
MAX_PKT = 65520  # LARGE_PACKET_MAX: the longest pkt-line git writes or reads, with its header
MAX_LINES = 1024  # pkt-lines read before the pack (shallow lines and commands)
MAX_COMMANDS = MAX_RECIPIENTS  # refs in one push: each is a recipient
MAX_REF = 255  # bytes of a ref name
MAX_CAPABILITIES = 64
PROBE = b"0000"
FLUSH, DELIM, RESPONSE_END = 0, 1, 2

_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", re.ASCII)
_REPO_RE = re.compile(r"[A-Za-z0-9._-]{1,100}", re.ASCII)
_HEX_RE = re.compile(rb"[0-9a-fA-F]{4}", re.ASCII)
_OID_RE = {40: re.compile(rb"[0-9a-f]{40}", re.ASCII), 64: re.compile(rb"[0-9a-f]{64}", re.ASCII)}
# A ref name we show and batch on: ASCII letters, digits and ``._/+-`` only, under ``refs/``.
# Git allows more (any byte but controls, space and ``~^:?*[\``); a ref with any of it is held as
# unknown and shown escaped: a comma or a semicolon would let it write in our list of refs.
_REF_RE = re.compile(rb"refs/[A-Za-z0-9._/+-]{1,250}", re.ASCII)
_CAPABILITY_RE = re.compile(rb"[!-~]{1,1024}", re.ASCII)
# What git's send-pack asks for (security review of T17b-1, L1): anything else is held, so an
# option the server would act on (``push-options``, with or without a value) never slips by.
_PUSH_CAPABILITIES = frozenset(
    {b"report-status", b"report-status-v2", b"side-band-64k", b"quiet", b"atomic", b"ofs-delta"}
)
_VALUED_CAPABILITIES = (b"agent=", b"object-format=", b"session-id=")
# A fetch's grammar (gitprotocol-pack and gitprotocol-v2; review of T17b-1, L2): its lines are
# read word by word, so a fetch is never a free-text channel. ``server-option`` is not in it.
_FETCH_CAPABILITIES = frozenset(
    {b"multi_ack", b"multi_ack_detailed", b"no-done", b"thin-pack", b"side-band",
     b"side-band-64k", b"ofs-delta", b"shallow", b"deepen-since", b"deepen-not",
     b"deepen-relative", b"no-progress", b"include-tag", b"allow-tip-sha1-in-want",
     b"allow-reachable-sha1-in-want", b"filter"}
)  # fmt: skip
_OID_ANY_RE = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}", re.ASCII)
_NUMBER_RE = re.compile(rb"[0-9]{1,12}", re.ASCII)
_REF_WORD_RE = re.compile(rb"[A-Za-z0-9._/+-]{1,250}", re.ASCII)
_FILTER_RE = re.compile(rb"[A-Za-z0-9:=+%._/-]{1,256}", re.ASCII)
_VALUE_RE = re.compile(rb"[!-~]{1,256}", re.ASCII)
_PROTOCOLS_RE = re.compile(rb"[a-z]{1,16}(?:,[a-z]{1,16}){0,7}", re.ASCII)
# The words of a v0 fetch and of each v2 command: a flag alone, or a word and its value.
_V0_WORDS = {b"want": _OID_ANY_RE, b"have": _OID_ANY_RE, b"shallow": _OID_ANY_RE,
             b"deepen": _NUMBER_RE, b"deepen-since": _NUMBER_RE, b"deepen-not": _REF_WORD_RE,
             b"filter": _FILTER_RE}  # fmt: skip
_V2_COMMANDS: dict[bytes, tuple[frozenset[bytes], dict[bytes, re.Pattern[bytes]]]] = {
    b"ls-refs": (frozenset({b"peel", b"symrefs", b"unborn"}), {b"ref-prefix": _REF_WORD_RE}),
    b"fetch": (
        frozenset({b"thin-pack", b"no-progress", b"include-tag", b"ofs-delta", b"done",
                   b"deepen-relative", b"sideband-all", b"wait-for-done"}),
        {b"want": _OID_ANY_RE, b"have": _OID_ANY_RE, b"shallow": _OID_ANY_RE,
         b"want-ref": _REF_WORD_RE, b"deepen": _NUMBER_RE, b"deepen-since": _NUMBER_RE,
         b"deepen-not": _REF_WORD_RE, b"filter": _FILTER_RE, b"packfile-uris": _PROTOCOLS_RE},
    ),
    b"object-info": (frozenset({b"size"}), {b"oid": _OID_ANY_RE}),
}  # fmt: skip
# GitHub's own tokens: the credential a git request to github.com is meant to carry.
_GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")
NAME_WIDTH = 60  # a ref name in the target, at most (cut in the middle)
_MORE = 12  # room kept for " y NN más"
_VOLATILE_CAPABILITIES = (b"agent=", b"session-id=")
_TYPES = {UPLOAD: "application/x-git-upload-pack-request",
          RECEIVE: "application/x-git-receive-pack-request"}  # fmt: skip


@dataclass(frozen=True)
class Command:
    old: bytes
    new: bytes
    ref: bytes  # as sent: checked by ``_plain_ref`` before it is trusted

    @property
    def verb(self) -> str:
        if set(self.old) == {ord("0")}:
            return "create"
        if set(self.new) == {ord("0")}:
            return "delete"
        return "update"


@dataclass(frozen=True)
class Push:
    commands: tuple[Command, ...]
    capabilities: tuple[bytes, ...]
    shallow: tuple[bytes, ...]
    pack: bytes  # whatever follows the command list: empty, or a pack


def claims(view: RequestView, context: Context) -> bool:
    """Only the smart HTTP routes, by the number of segments: ``/o/r/info/refs``,
    ``/o/r/git-upload-pack`` and ``/o/r/git-receive-pack``. A web page of a repository such as
    ``/o/r/blob/main/info/refs`` has more segments, and stays with the plain rules."""
    del context  # the same for every configuration
    if view.host not in HOSTS:
        return False
    parts = re.split(r"[?#]", view.path, maxsplit=1)[0].split("/")
    return (len(parts) == 5 and parts[3:] == ["info", "refs"]) or (
        len(parts) == 4 and parts[3] in SERVICES
    )


def read(view: RequestView, context: Context) -> Reading:
    raw, _mark, query = view.path.partition("?")
    parts = raw.split("/")
    repository = _repository(view.host, parts)
    try:
        if repository is None or "#" in view.path:
            raise Unreadable
        params = parse_pairs(query)
        account = account_id(context, NAME, credential(view.headers), repository)
    except Unreadable as error:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note)
    target = clean(repository, context.scrub, TARGET_CHARS)[0]
    if _foreign_credential(view.headers, context.scrub):
        foreign = unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.SECRET_SEEN, account=account,
                          target=target)  # fmt: skip
        return replace(foreign, secret_seen=True)
    service = parts[3] if len(parts) == 4 else "info/refs"
    if service == "info/refs":
        good = view.method in READ_METHODS and not view.body
        if good and (not params or (set(params) == {"service"} and params["service"] in SERVICES)):
            return _reading("info-refs", Effect.READ, account, target)
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, account=account, target=target)
    if view.method != "POST" or query:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, account=account, target=target)
    try:
        if media_type(view.headers) != _TYPES[service]:
            raise Unreadable
        if service == UPLOAD:
            if len(view.body) > MAX_READ_BODY:
                raise Unreadable(Note.TOO_LARGE)
            _well_formed(view.body)
            return _reading("upload-pack", Effect.READ, account, target)
        if view.body == PROBE:
            return _reading("receive-pack.probe", Effect.READ, account, target)
        push = parse_push(view.body)
    except Unreadable as error:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note, account=account, target=target)
    return _push_reading(view, context.scrub, repository, account, push)


def _repository(host: str, parts: list[str]) -> str | None:
    """``github.com/owner/repo`` (lower case, without ``.git``), or None for a path that is not
    plainly one: an odd owner or repository name, ``.``, ``..``, escapes, empty segments."""
    if len(parts) not in (4, 5) or parts[0] != "":
        return None
    owner, repo = parts[1], parts[2]
    if not _OWNER_RE.fullmatch(owner) or not _REPO_RE.fullmatch(repo) or repo in (".", ".."):
        return None
    name = repo[:-4] if repo.lower().endswith(".git") else repo
    if not name or name in (".", ".."):
        return None
    return f"{host}/{owner.lower()}/{name.lower()}"


def _reading(operation: str, effect: Effect, account: str | None, target: str) -> Reading:
    return Reading(NAME, operation, effect, Shape.PLAIN, WAIT_DEFAULT, account=account,
                   target=target)  # fmt: skip


# --- pkt-lines -----------------------------------------------------------------------------------


def pkt_line(data: bytes, index: int) -> tuple[int | bytes, int]:
    """(the pkt-line at ``index``: its payload, or FLUSH, DELIM or RESPONSE_END; the index after
    it). Unreadable when it is truncated, its length is not four hex digits, or it is ``0003``,
    an empty ``0004`` or longer than MAX_PKT."""
    head = data[index : index + 4]
    if len(head) < 4 or not _HEX_RE.fullmatch(head):
        raise Unreadable
    length = int(head, 16)
    if length in (FLUSH, DELIM, RESPONSE_END):
        return length, index + 4
    if length <= 4:
        raise Unreadable  # 0003 does not exist, and git never sends an empty 0004
    if length > MAX_PKT:
        raise Unreadable(Note.TOO_LARGE)
    end = index + length
    if end > len(data):
        raise Unreadable  # truncated
    return data[index + 4 : end], end


def _well_formed(body: bytes) -> None:
    """A fetch's body, whole: pkt-lines in the grammar of protocol v2 (one command) or v0
    (wants, shallow and deepen lines, haves, ``done``). Unreadable for anything else."""
    if not body:
        raise Unreadable
    packets: list[int | bytes] = []
    index = 0
    while index < len(body):
        packet, index = pkt_line(body, index)
        packets.append(packet.removesuffix(b"\n") if isinstance(packet, bytes) else packet)
    first = packets[0]
    if isinstance(first, bytes) and first.startswith(b"command="):
        _fetch_v2(packets)
    else:
        _fetch_v0(packets)


def _fetch_v2(packets: list[int | bytes]) -> None:
    """``command=<c>``, capability lines, then (after a delim) its arguments, and a flush that
    ends the body."""
    command = packets[0][len(b"command=") :]  # type: ignore[index]
    if command not in _V2_COMMANDS:
        raise Unreadable(Note.NOT_IN_TABLE)
    if packets[-1] != FLUSH:
        raise Unreadable
    flags, valued = _V2_COMMANDS[command]  # type: ignore[index]
    in_arguments = False
    for packet in packets[1:-1]:
        if packet == DELIM and not in_arguments:
            in_arguments = True
            continue
        if not isinstance(packet, bytes):
            raise Unreadable
        if in_arguments:
            _word(packet, flags, valued)
        elif not _valued_capability(packet):
            raise Unreadable(Note.NOT_IN_TABLE)  # server-option, or one we do not know


def _fetch_v0(packets: list[int | bytes]) -> None:
    """``want <id> <capabilities>`` first, then wants, shallow and deepen lines, flushes, haves
    and ``done``."""
    first = packets[0]
    if not isinstance(first, bytes) or not first.startswith(b"want "):
        raise Unreadable
    words = first.split(b" ")
    if not all(item in _FETCH_CAPABILITIES or _valued_capability(item) for item in words[2:]):
        raise Unreadable(Note.NOT_IN_TABLE)
    _word(b" ".join(words[:2]), frozenset({b"done"}), _V0_WORDS)
    for packet in packets[1:]:
        if packet == FLUSH:
            continue
        if not isinstance(packet, bytes):
            raise Unreadable
        _word(packet, frozenset({b"done"}), _V0_WORDS)


def _word(line: bytes, flags: frozenset[bytes], valued: dict[bytes, re.Pattern[bytes]]) -> None:
    if line in flags:
        return
    word, space, value = line.partition(b" ")
    pattern = valued.get(word)
    if not space or pattern is None or not pattern.fullmatch(value):
        raise Unreadable


def _valued_capability(item: bytes) -> bool:
    if item.startswith(b"object-format="):
        return item in (b"object-format=sha1", b"object-format=sha256")
    return item.startswith(_VALUED_CAPABILITIES) and _VALUE_RE.fullmatch(item) is not None


def _foreign_credential(headers: tuple[tuple[str, str], ...], scrub: KnownScrubber) -> bool:
    """Whether a credential header carries a key the redaction knows that is not GitHub's (an
    Anthropic key in a ``Basic`` password, say). The gate lets a translated read pass whatever
    its credential says, since it is the API's own; toward github.com only GitHub's tokens are
    (security review of T17b-1, L2)."""
    for name, value in headers:
        if name.strip().lower() not in CREDENTIAL_HEADERS:
            continue
        for text in _credential_texts(value):
            if has_secret(_GITHUB_TOKEN_RE.sub("", text), scrub):
                return True
    return False


def _credential_texts(value: str) -> list[str]:
    """The secret parts of a credential header: the value after its scheme, and a ``Basic``
    one's user and password, decoded (when it does not decode, it is searched as it came)."""
    text = value.strip()
    scheme, space, rest = text.partition(" ")
    if not space:
        return [text]
    if scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(rest.strip(), validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return [rest]
        return decoded.split(":", 1)
    return [rest.strip()]


def parse_push(body: bytes) -> Push:
    """The update requests of a push (``gitprotocol-pack``): shallow lines, then the commands
    (the first with its capabilities after a NUL) up to a flush-pkt, then the pack. Unreadable
    for anything else, a signed push or push options."""
    index = 0
    shallow: list[bytes] = []
    lines: list[bytes] = []
    while True:
        if len(shallow) + len(lines) >= MAX_LINES:
            raise Unreadable(Note.TOO_LARGE)
        packet, index = pkt_line(body, index)
        if packet == FLUSH:
            break
        if not isinstance(packet, bytes):
            raise Unreadable  # a delim or a response-end in a command list
        packet = packet.removesuffix(b"\n")
        if packet.startswith(b"shallow ") and not lines:
            shallow.append(packet[8:])
            continue
        if packet.startswith(b"push-cert"):
            raise Unreadable(Note.NOT_IN_TABLE)  # a signed push: its commands are in the cert
        lines.append(packet)
    if not lines:
        raise Unreadable  # a pack and no command (the lone flush, the probe, is read before)
    if len(lines) > MAX_COMMANDS:
        raise Unreadable(Note.TOO_MANY_RECIPIENTS)
    first, nul, caps = lines[0].partition(b"\0")
    capabilities = tuple(caps.split()) if nul else ()
    if len(capabilities) > MAX_CAPABILITIES or not all(
        _CAPABILITY_RE.fullmatch(item) for item in capabilities
    ):
        raise Unreadable
    if not all(item in _PUSH_CAPABILITIES or _valued_capability(item) for item in capabilities):
        raise Unreadable(Note.NOT_IN_TABLE)  # push-options, or one we do not know
    size = _oid_size(capabilities)
    commands = tuple(_command(line, size) for line in (first, *lines[1:]))
    if not all(_OID_RE[size].fullmatch(item) for item in shallow):
        raise Unreadable
    pack = body[index:]
    if pack and not pack.startswith(b"PACK"):
        raise Unreadable
    if pack and all(command.verb == "delete" for command in commands):
        raise Unreadable  # git sends no pack when it only deletes
    return Push(commands, capabilities, tuple(shallow), pack)


def _oid_size(capabilities: tuple[bytes, ...]) -> int:
    formats = [item[len(b"object-format=") :] for item in capabilities
               if item.startswith(b"object-format=")]  # fmt: skip
    if len(formats) > 1:
        raise Unreadable(Note.DUPLICATE)
    if not formats or formats[0] == b"sha1":
        return 40
    if formats[0] == b"sha256":
        return 64
    raise Unreadable


def _command(line: bytes, size: int) -> Command:
    if b"\0" in line:
        raise Unreadable  # capabilities only after the first command
    old, space, rest = line.partition(b" ")
    new, space2, ref = rest.partition(b" ")
    if not (space and space2 and ref):
        raise Unreadable
    pattern = _OID_RE[size]
    if not pattern.fullmatch(old) or not pattern.fullmatch(new):
        raise Unreadable
    zero = b"0" * size
    if old == zero and new == zero:
        raise Unreadable
    if len(ref) > MAX_REF:
        raise Unreadable(Note.TOO_LARGE)
    return Command(old, new, ref)


def _plain_ref(ref: bytes) -> bool:
    """A ref name git accepts (``check-ref-format``) made only of plain characters
    (``_REF_RE``): no ``..``, ``//`` or ``@{``, no part that starts with ``.`` or ends with
    ``.lock``, and no ``/`` or ``.`` at the end."""
    if not _REF_RE.fullmatch(ref) or b".." in ref or b"//" in ref or b"@{" in ref:
        return False
    if ref.endswith((b"/", b".")):
        return False
    return all(part and not part.startswith(b".") and not part.endswith(b".lock")
               for part in ref.split(b"/"))  # fmt: skip


# --- the push's reading --------------------------------------------------------------------------

_VERBS = {"create": "crea", "update": "actualiza", "delete": "borra"}


def escape_ref(ref: bytes) -> str:
    """A ref name as the person may read it: printable ASCII as it is (a backslash doubled), any
    other byte as ``\\xNN``. Control characters, a right-to-left override or a zero-width space
    can never hide or reorder what it says."""
    out: list[str] = []
    for byte in ref:
        if byte == 0x5C:
            out.append("\\\\")
        elif 0x20 < byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def short_ref(ref: str) -> str:
    """How a ref is named in the target: a branch by its name, a tag as ``etiqueta v1``."""
    for prefix, shown in (("refs/heads/", ""), ("refs/tags/", "etiqueta ")):
        rest = ref[len(prefix) :]
        if ref.startswith(prefix) and not rest.startswith("refs/"):
            return shown + rest
    return ref  # refs/heads/refs/tags/v1 stays whole: it must not read as a tag


def _cut(name: str, width: int) -> str:
    """``name`` at most ``width`` characters, cut in the middle (``…(N)…`` is 7 at most)."""
    return name if len(name) <= width else cut_middle(name, max(width - 7, 3))


def push_target(repository: str, commands: tuple[Command, ...]) -> str:
    """``github.com/o/r: actualiza main; crea feature/x; borra etiqueta v1``: the verbs are
    ours, the names the agent's (escaped, each cut in the middle). The first name of every verb
    is shown first, so a long name can never hide that the push also deletes or creates one
    (security review of T17b-1, L3); the rest go while they fit, then "y N más"."""
    by_verb: dict[str, list[str]] = {}
    for command in commands:
        by_verb.setdefault(command.verb, []).append(short_ref(escape_ref(command.ref)))
    groups = [(verb, by_verb[verb]) for verb in ("update", "create", "delete") if verb in by_verb]
    room = TARGET_CHARS - len(repository) - 2 - _MORE
    overhead = sum(len(_VERBS[verb]) + 1 for verb, _ in groups) + 2 * (len(groups) - 1)
    first = max(12, min(NAME_WIDTH, (room - overhead) // max(len(groups), 1)))
    kept = {verb: [_cut(names[0], first)] for verb, names in groups}

    def text() -> str:
        return "; ".join(f"{_VERBS[verb]} {', '.join(kept[verb])}" for verb, _ in groups)

    full = True
    for verb, names in groups:
        for name in names[1:]:
            kept[verb].append(_cut(name, NAME_WIDTH))
            if len(text()) > room:
                kept[verb].pop()
                full = False
                break
        if not full:
            break
    shown = sum(len(names) for names in kept.values())
    total = sum(len(names) for _verb, names in groups)
    result = f"{repository}: {text()}" if groups else repository
    if shown < total:
        result += f" y {total - shown} más"
    return result


def _push_reading(
    view: RequestView, scrub: KnownScrubber, repository: str, account: str | None, push: Push
) -> Reading:
    commands = push.commands
    target, struck = clean(push_target(repository, commands), scrub, TARGET_CHARS)
    held = (NAME, Shape.PLAIN, WAIT_DEFAULT)
    readable = b"\n".join([*(command.ref for command in commands), *push.capabilities])
    if struck or has_secret(readable.decode("utf-8", "replace"), scrub):
        secret = unknown(*held, Note.SECRET_SEEN, account=account, target=target)
        return replace(secret, secret_seen=True)
    refs = [command.ref for command in commands]
    if len(set(refs)) != len(refs):
        return unknown(*held, Note.DUPLICATE, account=account, target=target)
    if not all(_plain_ref(ref) for ref in refs):
        return unknown(*held, Note.UNPARSED, account=account, target=target)
    recipients = tuple(ref.decode("ascii") for ref in refs)
    deletes = any(command.verb == "delete" for command in commands)
    effect = Effect.DELETE if deletes else Effect.CHANGE
    # An update may be a forced push, which the body cannot tell: it never rides a batch
    # (security review of T17b-1, M1). Only creating new refs may.
    moves = any(command.verb == "update" for command in commands)
    notes = (Note.MOVES_REF,) if moves else ()
    operation = "receive-pack"
    fields = {
        "commands": [[c.old.decode(), c.new.decode(), c.ref.decode()] for c in commands],
        "shallow": [item.decode() for item in push.shallow],
        "capabilities": sorted(
            item.decode()
            for item in push.capabilities
            if not item.startswith(_VOLATILE_CAPABILITIES)
        ),  # fmt: skip
        "pack": "sha256:" + hashlib.sha256(push.pack).hexdigest(),
    }
    return Reading(
        translator=NAME,
        operation=operation,
        effect=effect,
        shape=Shape.PLAIN,
        wait_s=WAIT_DEFAULT,
        account=account,
        recipients=recipients,
        target=target,
        notes=notes,
        canonical=semantic_canonical(
            translator=NAME,
            host=view.host,
            port=view.port,
            operation=operation,
            account=account,
            recipients=recipients,
            fields={"repository": repository, **fields},
        ),
    )
