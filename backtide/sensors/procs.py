"""One Tetragon event (a parsed JSON line) to one black-box event. Pure: no I/O.

Design: docs/23-diseno-t07-tetragon.md, sections 3 to 5. T07 only records (risk 0): the risk
rules are T08's.

- Attribution is by the parsed ``process.docker`` field (a prefix of the container id, 31
  characters in the VM, at least 12 here), never by searching the line: the agent writes
  whatever it likes in its own arguments. The context also knows the agent's previous
  containers for a while, so lines still unread when the container is created again are
  not lost.
- Everything inside ``process`` (the binary, its arguments, its directory) is the agent's, so
  hostile: struck (``redact`` plus a few command-line forms of our own), escaped visibly
  (controls and newlines as ``\\x1b``, a backslash as ``\\\\`` and ``…`` as ``\\u2026``, so
  nothing the agent writes looks like an escape or a marker of ours), runs of one character
  folded and cut to 1 KiB keeping the head AND the tail (padding cannot push the end of a
  command out of sight). Never interpreted.
- The environment never reaches an event: nothing here reads it (and Tetragon never sends it:
  backtide/jail/sensor.py never turns it on).
- ``classify`` never raises on an odd shape: what it cannot use is ``Skipped("invalid")``.
  ``classify_oversize`` makes the most of a line too big to parse (see the reader).
- Every record carries Tetragon's ``exec_id`` (written by Tetragon, not by the agent) and a
  ``key`` made from it (``event_key``): after a kill -9 the reader reads again the lines after
  its last saved cursor, and the key in the black box is how it knows which it recorded.
"""

import ipaddress
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from backtide.blackbox.model import Source
from backtide.blackbox.redact import REDACTED, strike_text

ARGV_LIMIT = 1024  # bytes of argv, binary or cwd kept (docs/23, decision 8)
# Hostile text longer than two windows is struck window by window (its head and its tail):
# it bounds the work of the patterns (an exec may carry 320 KiB of arguments), and nothing
# between the windows is ever kept. Each window is struck with _MARGIN more characters past its
# cut, so a secret that straddles the cut is seen whole (the bounded patterns reach 512), and
# the run of token characters touching a cut is dropped: no head or tail of a secret is left.
_WINDOW = 2048
_MARGIN = 512
_TOKEN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/=.-"  # noqa: S105 - characters, not a secret
# The tail window starts back at the last line break or quote before it (at most this far),
# with a little more before it, so an unbounded pattern (a header line, a PEM block, a cookie)
# sees the name or the flag that starts it.
_TAIL_REACH = 64 * 1024
_TAIL_LEAD = 64
_TERMINATORS = "\r\n\"'"
# The lines of a key body right before its END (whose BEGIN may be out of the window). Only
# those lines: a fake END line cannot wipe the commands before it.
_PEM_BODY_RE = re.compile(
    r"(?:[A-Za-z0-9+/=]{1,76}\r?\n)+(?=-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)"
)
_SHORT_LIMIT = 64  # a signal name, a timestamp, a protocol
MIN_PREFIX = 12  # characters of a container id that make an attribution

# Tetragon writes the id in lowercase hex; anything else is not an id.
_FULL_ID_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_PREFIX_RE = re.compile(rf"[0-9a-f]{{{MIN_PREFIX},64}}", re.ASCII)
# A THROTTLE's cgroup (after the NUL padding is stripped): docker-<id>.scope with Docker's
# systemd driver (the VM's), the bare id with the cgroupfs one.
_SCOPE_RE = re.compile(r"(?:.*/)?(?:docker-)?([0-9a-f]{64})(?:\.scope)?", re.ASCII)

# The probes backtide runs in the agent's container (readiness and heartbeat): `true <nonce>`
# through docker exec, so never from the agent's own tree.
_PROBE_BINARIES = frozenset({"/bin/true", "/usr/bin/true"})
_NONCE_RE = re.compile(r"backtide-(?:hb|ready)-[0-9a-f]{32}", re.ASCII)
# runc's own init, which starts every docker exec. Recorded like anything else (the agent can
# imitate the name); only flagged, so a reader can tell it apart.
_RUNC_INIT_RE = re.compile(r"/proc/self/fd/[0-9]+", re.ASCII)
_SHIM_SUFFIX = "/containerd-shim-runc-v2"

_CONNECT_FUNCTION = "security_socket_connect"
_FAMILIES = {"AF_INET": 4, "AF_INET6": 6}
_PROTOCOLS = {
    "IPPROTO_TCP": "tcp",
    "IPPROTO_UDP": "udp",
    "IPPROTO_SCTP": "sctp",
    "IPPROTO_ICMP": "icmp",
    "IPPROTO_ICMPV6": "icmpv6",
}
# Docker's embedded DNS: how the agent's name lookups look. Not treated as loopback (T07-1).
_DOCKER_DNS = (ipaddress.ip_address("127.0.0.11"), 53)
_THROTTLE_STATES = {"THROTTLE_START": "start", "THROTTLE_STOP": "stop"}
_TIME_RE = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z", re.ASCII)
# Tetragon's exec_id: base64 of node, start time and pid. Anything else is no id at all.
_EXEC_ID_RE = re.compile(r"[A-Za-z0-9+/=_-]{8,128}", re.ASCII)
_KEYED_ACTIONS = frozenset({"exec", "exit", "connect"})

# Command-line forms ``redact`` does not strike on its own: a value after a flag whose name ends
# with one of these words (``--pass x``, ``--password "two words"``) and an assignment inside a
# script (``password = 'x'``). Each quantifier is bounded and each name starts after a
# non-word character, so the scans stay linear on hostile text.
_SECRET_WORDS = r"(?:password|passwd|pass|pwd|secret|token|api[-_]?key|apikey|auth|cookie)"  # noqa: S105
_FLAG = rf"(?i)(?<!\S)--?[\w-]*?{_SECRET_WORDS}(?:[ \t]+|=)"
# redact.py's sensitive names, for JSON and Python values a cut window leaves unclosed.
_VALUE_WORDS = (
    r"(?:token|secret|passw(?:or)?d|api[-_]?key|private[-_]?key|access[-_]?key"
    r"|authorization|cookie)"
)
# A value that crosses spaces is only taken between quotes: without an opening quote a pattern
# strikes ONE token, so an ordinary flag (`git checkout -b x`, `sort -b`) never swallows the
# rest of a command. The closing quote may be missing at the end of the text or of a window
# (``\Z``): a cut must not leave the inside of a quoted secret.
_ARGV_PATTERNS = (
    *(
        re.compile(pattern)
        for quote in ('"', "'")
        for pattern in (
            # A quoted value is struck whole, with no cap (AWS session tokens are ~1,300
            # chars; cookies, kilobytes): anchored at the name, so the scan stays linear. An
            # unclosed quote (the end of the text or of a cut window) strikes to that end.
            rf"{_FLAG}{quote}(?P<secret>[^{quote}\r\n]+)(?:{quote}|\Z)",
            rf"(?i)(?<![\w.-])[\w.-]*?{_SECRET_WORDS}[\"']?[ \t]*[:=][ \t]*{quote}"
            rf"(?P<secret>[^{quote}\r\n]+)(?:{quote}|\Z)",
            # curl -b / --cookie "a=b; c=d".
            rf"(?<!\S)(?:-b|--cookie)(?:[ \t]+|=){quote}(?P<secret>[^{quote}\r\n]+)(?:{quote}|\Z)",
            # "api_key": "… or 'api_key': '…, closed or cut by the end.
            rf"(?i){quote}[\w.-]*?{_VALUE_WORDS}{quote}\s*:\s*{quote}"
            rf"(?P<secret>[^{quote}\r\n]+)(?:{quote}|\Z)",
        )
    ),
    re.compile(rf"{_FLAG}(?P<secret>[^\s\"']+)"),
    re.compile(r"(?<!\S)(?:-b|--cookie)(?:[ \t]+|=)(?P<secret>[^\s\"']+)"),
    # Three or more lines of 64 base64 characters: the body of a key, even without its BEGIN.
    re.compile(r"(?<![A-Za-z0-9+/])(?P<secret>(?:[A-Za-z0-9+/]{64}\r?\n){3,}[A-Za-z0-9+/=]{0,64})"),
)
# A unit of 1 to 4 characters repeated 16 times or more (padding): folded to one copy and a
# count. After escaping, so a run of escaped controls (\x01\x01...) folds too.
_RUN_RE = re.compile(r"(.{1,4}?)\1{15,}", re.DOTALL)

# What can still be read from a line too big to parse (the reader keeps its first and last
# bytes). An unescaped quote only exists in JSON's own syntax (Tetragon escapes the agent's),
# so these keys cannot be forged from inside an argument.
# protojson may put a space after a colon, so every pattern allows whitespace around it.
_KIND_B = re.compile(rb'\A\{\s*"(process_exec|process_exit|process_kprobe)"\s*:')
_DOCKER_B = re.compile(rb'"docker"\s*:\s*"([0-9a-f]{12,64})"')
# A path of 4096 control characters is 24 KiB once escaped (\u0001): the bound covers it.
_STRING_B = r'"{}"\s*:\s*"((?:[^"\\]|\\.){{0,32768}})"'
_BINARY_B = re.compile(_STRING_B.format("binary").encode())
_CWD_B = re.compile(_STRING_B.format("cwd").encode())
_FLAGS_B = re.compile(_STRING_B.format("flags").encode())
_FUNCTION_B = re.compile(_STRING_B.format("function_name").encode())
_SIGNAL_B = re.compile(_STRING_B.format("signal").encode())
_PID_B = re.compile(rb'"pid"\s*:\s*([0-9]{1,10})\s*[,}]')
_EXEC_ID_B = re.compile(rb'"exec_id"\s*:\s*"([A-Za-z0-9+/=_-]{8,128})"')
_INIT_TREE_B = re.compile(rb'"in_init_tree"\s*:\s*(true|false)')
_TIME_B = re.compile(rb'"time"\s*:\s*"([0-9T:.Z-]{1,40})"')
_OBJECT_B = r'"{}"\s*:\s*(\{{[^{{}}]{{0,512}}\}})'
_SOCKADDR_B = re.compile(_OBJECT_B.format("sockaddr_arg").encode())
_SOCK_B = re.compile(_OBJECT_B.format("sock_arg").encode())


@dataclass(frozen=True)
class Context:
    """Whose events these are. ``agent_id`` is the agent container's full id (64 hex
    characters, from ``docker inspect``); ``previous`` are the full ids of the containers it
    replaced, still accepted for a while; ``agent_name`` is AgentJail's name for it.
    ``scrub``, when given, strikes the exact secrets backtide knows (``scrub_known``)."""

    agent_id: str
    agent_name: str
    scrub: Callable[[str], str] | None = field(default=None, compare=False)
    previous: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for container in (self.agent_id, *self.previous):
            if not isinstance(container, str) or not _FULL_ID_RE.fullmatch(container):
                raise ValueError("container ids must be full (64 lowercase hex characters)")

    @property
    def ids(self) -> tuple[str, ...]:
        return (self.agent_id, *self.previous)

    @property
    def short_id(self) -> str:
        return self.agent_id[:MIN_PREFIX]

    def match(self, prefix: object) -> str | None:
        """The full id that ``prefix`` (a Tetragon ``docker`` field) is a prefix of, or None."""
        if not isinstance(prefix, str) or _PREFIX_RE.fullmatch(prefix) is None:
            return None
        return next((full for full in self.ids if full.startswith(prefix)), None)


@dataclass(frozen=True)
class Record:
    """One event to append. ``binary`` and ``parent`` (already safe) are for the summaries;
    ``time`` is the kernel's (``t``); ``nonce`` is set when this exec looks like one of
    backtide's probes (the reader decides whether it expected it). ``preexisting`` marks a
    process Tetragon found already running when it started (procFS); ``started`` is its start
    time, so the reader can tell the ones that began while the sensor was down."""

    source: Source
    action: str
    target: str
    details: dict[str, Any]
    risk: int = 0
    binary: str = ""
    parent: str = ""
    time: str | None = None
    nonce: str | None = None
    preexisting: bool = False
    started: str | None = None
    key: str | None = None  # event_key(action, details): spots a line read twice


@dataclass(frozen=True)
class Skipped:
    """A line that is not recorded on its own, and why: ``other`` (another container or none),
    ``exit`` (a normal exit), ``loopback``, ``unknown`` (a kind of event this reader does not
    record) or ``invalid``."""

    reason: str


@dataclass(frozen=True)
class Throttle:
    """Tetragon started (``start``) or stopped (``stop``) dropping the agent's exec/exit events
    in the kernel (``cgroup-rate``)."""

    state: str
    time: str | None


type Parsed = Record | Skipped | Throttle


def new_nonce(kind: str) -> str:
    """A probe's marker: ``backtide-hb-<32 hex>`` (heartbeat) or ``backtide-ready-<32 hex>``."""
    if kind not in ("hb", "ready"):
        raise ValueError(f"unknown probe kind {kind!r}")
    return f"backtide-{kind}-{secrets.token_hex(16)}"


def is_nonce(text: object) -> bool:
    return isinstance(text, str) and _NONCE_RE.fullmatch(text) is not None


def event_key(action: str, details: object) -> str | None:
    """The key of a sensor event, from its action and its details (a Record's, or a recorded
    event's read back from the black box): ``exec:<exec_id>``, ``exit:<exec_id>`` or
    ``connect:<exec_id>:<t>`` (a process may connect many times). None without a usable
    ``exec_id``: such a line is never taken for one already recorded."""
    if action not in _KEYED_ACTIONS or not isinstance(details, Mapping):
        return None
    exec_id = details.get("exec_id")
    if not isinstance(exec_id, str) or not _EXEC_ID_RE.fullmatch(exec_id):
        return None
    if action != "connect":
        return f"{action}:{exec_id}"
    t = details.get("t")
    return f"connect:{exec_id}:{t}" if isinstance(t, str) and t else None


def classify(data: Mapping[str, Any], ctx: Context) -> Parsed:
    """What this Tetragon event means for the agent of ``ctx``."""
    t = _time(data.get("time"))
    if "process_exec" in data:
        return _exec(_dict(data["process_exec"]), t, ctx)
    if "process_exit" in data:
        return _exit(_dict(data["process_exit"]), t, ctx)
    if "process_kprobe" in data:
        return _connect(_dict(data["process_kprobe"]), t, ctx)
    if "process_throttle" in data:
        return _throttle(_dict(data["process_throttle"]), t, ctx)
    return Skipped("unknown")


def classify_oversize(head: bytes, tail: bytes, ctx: Context) -> Parsed:
    """A line too big to parse, from its first and last bytes: still recorded when it is the
    agent's (an exec marked ``oversize`` and ``arguments_lost``, a connect or a killed exit),
    so making a line huge does not hide a command. The process's fields come before its
    arguments (in ``head``) and its ``docker`` field after them (in ``tail``)."""
    kind = _KIND_B.match(head)
    if kind is None:
        return Skipped("invalid")
    docker = next(
        (
            (part, m)
            for part in (head, tail)
            for m in _DOCKER_B.finditer(part)
            if ctx.match(m.group(1).decode()) is not None
        ),
        None,
    )
    if docker is None:
        return Skipped("other")
    part, found = docker
    init_tree = _INIT_TREE_B.search(part, found.end())
    process: dict[str, Any] = {
        "docker": found.group(1).decode(),
        "binary": _json_string(_BINARY_B.search(head)),
        "cwd": _json_string(_CWD_B.search(head)),
        "flags": _json_string(_FLAGS_B.search(head)) + " dataArgs",
        "pid": _int_match(_PID_B.search(head)),
        "in_init_tree": init_tree is not None and init_tree.group(1) == b"true",
    }
    exec_id = _EXEC_ID_B.search(head)
    if exec_id is not None:
        process["exec_id"] = exec_id.group(1).decode()
    times = list(_TIME_B.finditer(tail))
    data: dict[str, Any] = {"time": times[-1].group(1).decode() if times else None}
    name = kind.group(1).decode()
    if name == "process_kprobe":
        args = [{"sockaddr_arg": _json_object(_SOCKADDR_B.search(tail))}]
        args.append({"sock_arg": _json_object(_SOCK_B.search(tail))})
        data[name] = {
            "process": process,
            "function_name": _json_string(_FUNCTION_B.search(tail)),
            "args": args,
        }
    elif name == "process_exit":
        data[name] = {"process": process, "signal": _json_string(_SIGNAL_B.search(tail))}
    else:
        data[name] = {"process": process}
    parsed = classify(data, ctx)
    if isinstance(parsed, Record):
        parsed.details["oversize"] = True
        if not process["binary"]:
            parsed.details["binary_lost"] = True  # not in the bytes kept: an unknown program
    return parsed


def belongs(process: Mapping[str, Any], ctx: Context) -> bool:
    """Whether a Tetragon ``process`` runs in the agent's container: by its parsed field."""
    return ctx.match(process.get("docker")) is not None


def safe_text(
    text: str, ctx: Context | None = None, limit: int = ARGV_LIMIT, *, scrubbed: str | None = None
) -> str:
    """Hostile ``text`` made safe to keep: struck, escaped, its runs folded and cut to
    ``limit`` bytes, keeping its head and its tail.

    The order matters: strike first (the patterns need the real newlines, and a cut must
    never leave the head of a key), then escape, then fold and cut. The exact secrets backtide
    knows are struck over the whole text, before any window: a cut cannot split them
    (``scrubbed``: that already done by the caller, so it is not done twice)."""
    total = len(text.encode("utf-8", "surrogatepass"))
    if scrubbed is not None:
        text = scrubbed
    elif ctx is not None and ctx.scrub is not None:
        text = ctx.scrub(text)
    if len(text) > 2 * _WINDOW:
        head = _cut_head(_strike_patterns(text[: _WINDOW + _MARGIN]), _WINDOW)
        tail = _cut_tail(_strike_patterns(_tail_window(text)), _WINDOW)
        return _join(_shown(head), _shown(tail), limit, total)
    clean = _shown(_strike_patterns(text))
    if len(clean.encode("utf-8")) <= limit:
        return clean
    return _join(clean, clean, limit, total)


def parse_time(text: str | None) -> datetime | None:
    """Tetragon's RFC 3339 time with nanoseconds, to the microsecond (UTC)."""
    match = _TIME_RE.fullmatch(text or "")
    if match is None:
        return None
    fraction = (match.group(2) or "0")[:6].ljust(6, "0")
    try:
        moment = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return moment.replace(microsecond=int(fraction), tzinfo=UTC)


# --- the kinds ------------------------------------------------------------------------------


def _exec(body: dict[str, Any], t: str | None, ctx: Context) -> Parsed:
    process = _dict(body.get("process"))
    container = ctx.match(process.get("docker"))
    if container is None:
        return Skipped("other")
    flags = _str(process.get("flags")).split()
    preexisting = "procFS" in flags
    raw_binary = _str(process.get("binary"))
    raw_args = _str(process.get("arguments"))
    parent = _dict(body.get("parent"))
    raw_parent = _str(parent.get("binary"))
    injected = process.get("in_init_tree") is not True
    binary = safe_text(raw_binary, ctx)
    parent_binary = safe_text(raw_parent, ctx)
    # A known secret written so that only its decodings show it (twice %-encoded, say) makes
    # the scrubber strike the whole text: visible, so it cannot be a quiet way to hide a command.
    scrubbed_args = ctx.scrub(raw_args) if ctx.scrub is not None else raw_args
    struck_whole = scrubbed_args == REDACTED and raw_args.strip() not in ("", REDACTED)
    details: dict[str, Any] = {
        "argv": safe_text(raw_args, ctx, scrubbed=scrubbed_args),
        "cwd": safe_text(_str(process.get("cwd")), ctx),
        "pid": _int(process.get("pid")),
        "uid": _int(process.get("uid")),
        "parent": {"pid": _int(parent.get("pid")), "binary": parent_binary},
        "container": container[:MIN_PREFIX],
        "container_name": ctx.agent_name,
        "injected": injected,
        "truncated": any(flag.startswith("trunc") for flag in flags),
        "argv_bytes": len(raw_args.encode("utf-8", "surrogatepass")),
        "t": t,
        "exec_id": _exec_id(process),
    }
    if struck_whole:
        details["argv_struck_whole"] = True
    if "dataArgs" in flags and not raw_args:
        # T07-1, P5: past ~320 KiB Tetragon drops the arguments without any flag saying so.
        details["arguments_lost"] = True
    if (
        injected
        and raw_args == "init"
        and _RUNC_INIT_RE.fullmatch(raw_binary)
        and raw_parent.endswith(_SHIM_SUFFIX)
    ):
        details["runc_init"] = True
    started = _time(process.get("start_time"))
    if preexisting:
        details["preexisting"] = True
        details["started"] = started
    nonce = raw_args if injected and raw_binary in _PROBE_BINARIES and is_nonce(raw_args) else None
    return Record(
        Source.EXEC,
        "exec",
        binary,
        details,
        risk=1 if struck_whole else 0,
        binary=binary,
        parent=parent_binary,
        time=t,
        nonce=nonce,
        preexisting=preexisting,
        started=started,
        key=event_key("exec", details),
    )


def _exit(body: dict[str, Any], t: str | None, ctx: Context) -> Parsed:
    process = _dict(body.get("process"))
    container = ctx.match(process.get("docker"))
    if container is None:
        return Skipped("other")
    signal = _str(body.get("signal"))
    if not signal:
        return Skipped("exit")  # a normal exit: not recorded (docs/23, decision 5)
    binary = safe_text(_str(process.get("binary")), ctx)
    details = {
        "pid": _int(process.get("pid")),
        "signal": safe_text(signal, ctx, _SHORT_LIMIT),
        "status": _int(body.get("status")) or 0,  # Tetragon leaves out a status of 0
        "container": container[:MIN_PREFIX],
        "t": t,
        "exec_id": _exec_id(process),
    }
    key = event_key("exit", details)
    return Record(Source.EXEC, "exit", binary, details, binary=binary, time=t, key=key)


def _connect(body: dict[str, Any], t: str | None, ctx: Context) -> Parsed:
    if body.get("function_name") != _CONNECT_FUNCTION:
        return Skipped("unknown")
    process = _dict(body.get("process"))
    container = ctx.match(process.get("docker"))
    if container is None:
        return Skipped("other")
    args = body.get("args")
    items = [_dict(arg) for arg in args] if isinstance(args, list) else []
    sockaddr = next((a["sockaddr_arg"] for a in items if "sockaddr_arg" in a), None)
    sock = next((a[k] for a in items for k in ("sock_arg", "socket_arg") if k in a), None)
    sockaddr, sock = _dict(sockaddr), _dict(sock)
    family = _str(sockaddr.get("family"))
    # protojson leaves out a field whose value is 0: a missing port is port 0.
    port = _int(sockaddr.get("port")) if "port" in sockaddr else 0
    try:
        addr = ipaddress.ip_address(_str(sockaddr.get("addr")))
    except ValueError:
        return Skipped("invalid")
    if _FAMILIES.get(family) != addr.version or port is None or not 0 <= port <= 65535:
        return Skipped("invalid")
    if _is_loopback(addr, port):
        return Skipped("loopback")
    binary = safe_text(_str(process.get("binary")), ctx)
    protocol = _str(sock.get("protocol"))
    target = f"[{addr.compressed}]:{port}" if addr.version == 6 else f"{addr.compressed}:{port}"
    details = {
        "family": family,
        "addr": addr.compressed,
        "port": port,
        "proto": _PROTOCOLS.get(protocol) or safe_text(protocol, ctx, _SHORT_LIMIT) or "unknown",
        "pid": _int(process.get("pid")),
        "binary": binary,
        "container": container[:MIN_PREFIX],
        "t": t,
        "exec_id": _exec_id(process),
    }
    key = event_key("connect", details)
    return Record(Source.NET, "connect", target, details, binary=binary, time=t, key=key)


def _throttle(body: dict[str, Any], t: str | None, ctx: Context) -> Parsed:
    state = _THROTTLE_STATES.get(_str(body.get("type")))
    if state is None:
        return Skipped("unknown")
    scope = _SCOPE_RE.fullmatch(_str(body.get("cgroup")).replace("\0", ""))
    if scope is None or scope.group(1) not in ctx.ids:
        return Skipped("other")
    return Throttle(state, t)


# --- text -----------------------------------------------------------------------------------


def _strike_patterns(text: str) -> str:
    """Our command-line forms and redact()'s patterns struck (not cut, not escaped)."""
    for pattern in _ARGV_PATTERNS:
        text = pattern.sub(_strike, text)
    return strike_text(text)


def _shown(text: str) -> str:
    """Escaped and folded: what is kept of an already struck text."""
    return _fold(_escape(text))


def _tail_window(text: str) -> str:
    """The end of ``text`` to strike: the last _WINDOW + _MARGIN characters, reaching back to
    the last line break or quote before them (and _TAIL_LEAD more), so a secret whose name or
    flag is far before the cut (a 3 KB cookie, a PEM block) is still matched whole. Without
    one within _TAIL_REACH, the plain window. The key lines right before a PEM block's END are
    struck even without its BEGIN."""
    start = len(text) - (_WINDOW + _MARGIN)
    reach = max(0, start - _TAIL_REACH)
    stop = max(text.rfind(char, reach, start) for char in _TERMINATORS)
    # Without one within reach, the plain window: dropping it would hide the end of the
    # command, which padding must never do (the cut's token run is still dropped).
    window = text[max(0, stop - _TAIL_LEAD) :] if stop >= 0 else text[start:]
    return _PEM_BODY_RE.sub(REDACTED + "\n", window)


def _cut_head(text: str, size: int) -> str:
    """The first ``size`` characters of a struck window, never ending inside a REDACTED
    marker, without the run of token characters the cut touches (the head of a secret)."""
    return text[: _redacted_end(text, size)].rstrip(_TOKEN_CHARS)


def _cut_tail(text: str, size: int) -> str:
    """The last ``size`` characters, the same way at the other end."""
    start = max(0, len(text) - size)
    for found in re.finditer(re.escape(REDACTED), text):
        if found.start() < start < found.end():
            start = found.start()
            break
    return text[start:].lstrip(_TOKEN_CHARS)


def _redacted_end(text: str, size: int) -> int:
    for found in re.finditer(re.escape(REDACTED), text):
        if found.start() < size < found.end():
            return found.end()
    return size


def _strike(match: re.Match[str]) -> str:
    start, end = match.span("secret")
    offset = match.start()
    whole = match.group(0)
    return whole[: start - offset] + REDACTED + whole[end - offset :]


def _escape(text: str) -> str:
    """Every non-printable character (controls, newlines, tabs, bidi overrides) becomes a
    visible escape such as ``\\x1b`` or ``\\u202e``; a backslash becomes ``\\\\`` and ``…``
    becomes ``\\u2026``, so the agent cannot write an escape or a marker of ours."""
    return "".join(_escape_char(char) if _needs_escape(char) else char for char in text)


def _needs_escape(char: str) -> bool:
    return not char.isprintable() or char in "\\…"


def _escape_char(char: str) -> str:
    code = ord(char)
    if char == "\\":
        return "\\\\"
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _fold(text: str) -> str:
    return _RUN_RE.sub(lambda m: f"{m.group(1)}…[×{len(m.group(0)) // len(m.group(1))}]", text)


def _join(head: str, tail: str, limit: int, total: int) -> str:
    """The first three quarters and the last quarter of ``limit`` bytes, with a marker of
    how big the original was in between."""
    marker = f"…[{total} bytes in all]…"
    room = max(0, limit - len(marker.encode("utf-8")))
    head_room = room * 3 // 4
    tail_room = room - head_room
    kept_head = head.encode("utf-8")[:head_room].decode("utf-8", errors="ignore")
    tail_bytes = tail.encode("utf-8")
    kept_tail = tail_bytes[len(tail_bytes) - tail_room :].decode("utf-8", errors="ignore")
    return kept_head + marker + (kept_tail if tail_room else "")


# --- helpers --------------------------------------------------------------------------------


def _is_loopback(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback and (addr, port) != _DOCKER_DNS


def _json_string(match: re.Match[bytes] | None) -> str:
    if match is None:
        return ""
    try:
        value = json.loads(b'"' + match.group(1) + b'"')
    except ValueError:
        return ""
    return value if isinstance(value, str) else ""


def _json_object(match: re.Match[bytes] | None) -> dict[str, Any]:
    if match is None:
        return {}
    try:
        value = json.loads(match.group(1))
    except ValueError:
        return {}
    return _dict(value)


def _int_match(match: re.Match[bytes] | None) -> int | None:
    return int(match.group(1)) if match is not None else None


def _exec_id(process: Mapping[str, Any]) -> str | None:
    exec_id = process.get("exec_id")
    return exec_id if isinstance(exec_id, str) and _EXEC_ID_RE.fullmatch(exec_id) else None


def _time(value: object) -> str | None:
    return safe_text(value, None, _SHORT_LIMIT) if isinstance(value, str) and value else None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
