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

import hashlib
import ipaddress
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from backtide.blackbox.model import Source
from backtide.blackbox.redact import REDACTED, strike_structured, strike_text
from backtide.blackbox.secret_words import (
    CONFIG_BASE,
    CONFIG_WORDS,
    ENV_WORDS,
    FLAG_BASE,
    FLAG_WORDS,
    SENSITIVE_BASE,
    SENSITIVE_WORDS,
)

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
# Walked back from each END line, line by line (never a regex over the window: that was
# quadratic): three or more lines of 40+ base64 characters, the last one maybe shorter. A fake
# END after a few one-word lines (cd, ls, reboot) strikes nothing.
_KEY_END_RE = re.compile(r"-----END [A-Z0-9 ]{0,64}PRIVATE KEY(?: BLOCK)?-----")
_KEY_LINE_RE = re.compile(r"[A-Za-z0-9+/=]{1,76}\r?")
_KEY_LINE_MIN = 40
_KEY_LINES = 3
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
# with one of the flag words (``--pass x``, ``--password "two words"``) and an assignment inside
# a script (``password = 'x'``). The words are secret_words': the forms below keep the *_BASE
# words they were checked with at their place in the order, and _LATE_PATTERNS, after redact's,
# have the whole lists (secret_words' docstring says why). Each quantifier is bounded or
# possessive and each name starts after a non-word character, so the scans stay linear on
# hostile text.
_SECRET_WORDS = FLAG_BASE
_VALUE_WORDS = SENSITIVE_BASE


def _flag(words: str) -> str:
    """A flag named like a secret, to its separator. It starts an element: after a space, at
    the start, or after a quote (a shell's, or the one Tetragon puts around an element with a
    space in it)."""
    return rf"(?i)(?<![^\s\"'])--?[\w-]*?{words}(?:[ \t]+|=)"


_FLAG = _flag(_SECRET_WORDS)
# A scheme word before a value (--auth Bearer x, MYSQL_PWD=Basic x): skipped, so the value is
# struck and not the word.
_SCHEME = r"(?:(?i:bearer|basic)[ \t]++)?+"
# A run of secret-named flags (--pass --pass x), skipped whole so the value after the last one
# is struck. One dash then [\w-]: each step has one way to split and ends at a separator, so a
# run that fails is not retried two ways per step (exponential).
_FLAG_STEP = rf"-[\w-]*?{FLAG_WORDS}(?:[ \t]+|=)"
_FLAG_RUN = rf"(?i)(?<![^\s\"']){_FLAG_STEP}(?:{_FLAG_STEP})*"


def _quoted(quote: str, open_end: bool) -> str:
    """A quoted value to its closing quote or a line break; ``\\Z`` closes it only at an
    artificial cut (``open_end``: the end of the head window, or arguments Tetragon cut). A
    backslash escapes the next character (``\\"`` inside JSON or a shell string)."""
    end = rf"(?:{quote}|(?=[\r\n]){'|\\Z' if open_end else ''})"
    return rf"(?P<secret>(?:[^{quote}\\\r\n]|\\[^\r\n]?)++){end}"


def _wrapped(open_end: bool) -> str:
    """The value of an element Tetragon wrapped in double quotes (it has a space): up to the
    next double quote. Tetragon escapes nothing inside, so a backslash escapes nothing here."""
    return rf'(?P<secret>[^"\r\n]++)(?:"|(?=[\r\n]){"|\\Z" if open_end else ""})'


def _unclosed(quote: str) -> str:
    """The fallback for a quote that never closes before the real end: up to the next shell
    separator or line break, so the rest of a short command stays in sight."""
    return rf"(?P<secret>[^{quote};|&\r\n]+)"


def _argv_patterns(open_end: bool) -> tuple[re.Pattern[str], ...]:
    patterns: list[str] = []
    for quote in ('"', "'"):
        for value in (_quoted(quote, open_end), _unclosed(quote)):
            patterns += [
                # A quoted value is struck whole, with no cap (AWS session tokens are ~1,300
                # chars; cookies, kilobytes): anchored at the name, so the scan stays linear.
                rf"{_FLAG}{quote}{value}",
                rf"(?i)(?<![\w.-])[\w.-]*?{_SECRET_WORDS}[\"']?[ \t]*[:=][ \t]*{quote}{value}",
                # curl -b / --cookie "a=b; c=d", and -b"a=b" glued.
                rf"(?<![^\s\"'])(?:-b(?:[ \t]+|=)?|--cookie(?:[ \t]+|=)){quote}{value}",
                # "api_key": "… or 'api_key': '…, closed or cut by the end.
                rf"(?i){quote}[\w.-]*?{_VALUE_WORDS}{quote}\s*:\s*{quote}{value}",
                # SQL: CREATE USER u IDENTIFIED BY 'x', ALTER USER u WITH PASSWORD 'x'.
                rf"(?i)\bidentified[ \t]+(?:with[ \t]+\S+[ \t]+)?by[ \t]+(?:password[ \t]+)?"
                rf"{quote}{value}",
                rf"(?i)\bpassword[ \t]+{quote}{value}",
            ]
    wrapped = _wrapped(open_end)
    patterns += [
        # An element Tetragon wrapped in quotes because it has a space: the value runs to the
        # closing quote ("--password=pass phrase", "--token abc def"). Not a bare NAME=a b:
        # a script "PGPASSWORD=x psql …" looks the same, and its command must stay in sight
        # (env "DB_PASSWORD=a b" is the env tool's, below).
        rf'(?i)(?<!\S)"--?[\w-]*?{_SECRET_WORDS}(?:=|[ \t]+){wrapped}',
        rf'(?<!\S)"-b(?=[^\s"=;]+=){wrapped}',
        # Unquoted: one token. A leading quote that never closes is skipped.
        rf"{_FLAG}[\"']*(?P<secret>[^\s\"']+)",
        r"(?<![^\s\"'])(?:-b|--cookie)(?:[ \t]+|=)(?P<secret>[^\s\"']+)",
        # -bsessionid=…: glued, and shaped like a cookie (a name, then =).
        r"(?<![^\s\"'])-b(?P<secret>[^\s\"'=;]+=[^\s\"']*)",
        rf"(?i)(?<![\w.-])[\w.-]*?{ENV_WORDS}=(?P<secret>[^\s&#;,'\"]+)",
        # openssl's -pass pass:secret, -passin pass:secret.
        r"(?<![^\s\"'])pass:(?P<secret>[^\s\"']+)",
        # aws configure set aws_secret_access_key x, npm config set //r/:_authToken x: the
        # key's name is checked by a lookahead and taken possessively (linear).
        r"(?i)\bconfig(?:ure)?[ \t]+set[ \t]+(?:-\S*+[ \t]+)*+"
        rf"(?=\S*?{CONFIG_BASE})\S++[ \t]+(?P<secret>[^\s\"']+)",
        # Three or more lines of 64 base64 characters: the body of a key, even without BEGIN.
        r"(?<![A-Za-z0-9+/])(?P<secret>(?:[A-Za-z0-9+/]{64}\r?\n){3,}[A-Za-z0-9+/=]{0,64})",
    ]
    return tuple(re.compile(pattern) for pattern in patterns)


# Both sets: [0] for a text whose end is its real end, [1] for one cut short (the head window,
# or arguments Tetragon cut: truncArgs), where an unclosed quote closes at the cut.
_ARGV_PATTERNS = (_argv_patterns(False), _argv_patterns(True))


def _late_patterns(open_end: bool) -> tuple[re.Pattern[str], ...]:
    """The forms above that depend on a word list, with the whole lists, a run of flags and a
    scheme word skipped, and nothing left for later: they run last, after redact's patterns, so
    whatever they strike no other pattern needed. In the order of _argv_patterns."""
    flag = _flag(FLAG_WORDS)
    patterns: list[str] = []
    for quote in ('"', "'"):
        for value in (_quoted(quote, open_end), _unclosed(quote)):
            patterns += [
                rf"{flag}{quote}{value}",
                rf"(?i)(?<![\w.-])[\w.-]*?{FLAG_WORDS}[\"']?[ \t]*[:=][ \t]*{quote}{value}",
                rf"(?i){quote}[\w.-]*?{SENSITIVE_WORDS}{quote}\s*:\s*{quote}{value}",
            ]
    patterns += [
        rf'(?i)(?<!\S)"--?[\w-]*?{FLAG_WORDS}(?:=|[ \t]+){_wrapped(open_end)}',
        rf"{_FLAG_RUN}{_SCHEME}[\"']*(?P<secret>[^\s\"']+)",
        rf"(?i)(?<![\w.-])[\w.-]*?{ENV_WORDS}={_SCHEME}(?P<secret>[^\s&#;,'\"]+)",
        r"(?i)\bconfig(?:ure)?[ \t]+set[ \t]+(?:-\S*+[ \t]+)*+"
        rf"(?=\S*?{CONFIG_WORDS})\S++[ \t]+{_SCHEME}(?P<secret>[^\s\"']+)",
    ]
    return tuple(re.compile(pattern) for pattern in patterns)


_LATE_PATTERNS = (_late_patterns(False), _late_patterns(True))

# --- T07-5: tools that take a password glued to a short flag (``mysql -pS3cr3t``), after a flag
# only they give that meaning (``sshpass -p``, ``ldapsearch -w``, ``zip -P``) or in a place of
# their own (``sqlplus user/pass@db``, ``vault login TOKEN``). By the basename of the binary
# Tetragon reports; inside a script (and behind a wrapper such as sudo), anchored at the tool's
# name and bounded to its own command (to the next ``;``, ``|``, ``&``, ``)``, backquote or line
# break outside quotes, at most _SEGMENT characters), so the -p of another command is never
# taken for a password. A CLOSED list: a tool not here with a password flag of its own that
# does not name a secret word is a residual (docs/23, T07-5). Mirrored in RE2 by
# backtide/jail/sensor.py (_TOOLS).
_SEGMENT = 512
_SCRIPT_VALUE = r"""(?P<secret>(?:'[^'\r\n]*+'?|"[^"\r\n]*+"?|[^\s"';|&<>()`]++)++)"""
# How a flag meets its value: glued (-pX), glued or after spaces (-p X), = or spaces; "assign"
# is glued too, for a NAME= of a secret name (env's late spec): its value may open a quote and
# a scheme word first, and takes the next word along when it looks like a flag.
_SEPS = {"glued": "", "assign": "", "opt": "[ \t]*", "eq": "(?:=|[ \t]+)"}
_GLUED = frozenset({"glued", "assign"})
# (flag, separator, what comes before the secret: user, or user and a separator)
type _FlagSpec = tuple[str, str, str]
# What comes before a secret is bounded and possessive: an unbounded run that fails at its end
# would be scanned again from every flag (quadratic on hostile text).
_USER_COLON = r"[^\s:\"']{1,256}+:"
# (basename, the subcommand the flags belong to or None, the flags)
_TOOL_FLAGS: tuple[tuple[str, str | None, tuple[_FlagSpec, ...]], ...] = (
    (r"(?:mysql|mariadb)[\w-]*+", None, (("-p", "glued", ""),)),
    (r"sshpass", None, (("-p", "opt", ""),)),
    (r"(?:redis|valkey|keydb)-cli", None, (("-a", "opt", ""),)),
    (r"mongo(?:sh|dump|restore|export|import|stat|top|files)?", None, (("-p", "opt", ""),)),
    (r"lftp", None, (("-u", "opt", r"[^\s,]{0,256}+,"),)),
    # env "DB_PASSWORD=two words" cmd: here an element wrapped by Tetragon is an assignment.
    (r"env", None, ((rf"(?i:[\w.-]*?(?:{_SECRET_WORDS}|{_VALUE_WORDS}))=", "glued", ""),)),
    (
        r"smbclient|rpcclient|smbget|smbcacls|smbtree",
        None,
        (("-U", "opt", r"[^\s%]{0,256}+%"), ("--user", "eq", r"[^\s%]{0,256}+%")),
    ),
    (
        r"curl",
        None,
        (
            ("-u", "opt", _USER_COLON),  # -ualice:pw, -u "alice:pw x"
            ("--user", "eq", _USER_COLON),
            ("-U", "opt", _USER_COLON),
            ("--proxy-user", "eq", _USER_COLON),
            ("--oauth2-bearer", "eq", ""),
            ("-E", "opt", _USER_COLON),  # a client certificate's passphrase: cert.pem:pw
            ("--cert", "eq", _USER_COLON),
        ),
    ),
    # docker login -p: only in the login subcommand (in docker run, -p publishes a port).
    (r"docker|podman|nerdctl|buildah|skopeo|oras", r"login", (("-p", "opt", ""),)),
    (r"helm", r"registry[ \t]+login", (("-p", "opt", ""),)),
    (
        r"ldap(?:search|add|modify|delete|passwd|whoami|compare|modrdn|exop)",
        None,
        (("-w", "opt", ""),),
    ),  # fmt: skip
    (r"sqlcmd|bcp|ipmitool|mosquitto_(?:pub|sub|rr)", None, (("-P", "opt", ""),)),
    (r"zip|unzip|zipcloak", None, (("-P", "opt", ""),)),
    (r"7z|7za|7zr|7zz", None, (("-p", "glued", ""),)),
    (r"openssl", None, (("-k", "opt", ""), ("-K", "opt", ""))),
    (r"ssh-keygen", None, (("-N", "opt", ""), ("-P", "opt", ""))),
    (
        r"sqlplus|sqlldr|expdp|impdp|rman",
        None,
        (("", "glued", r"[\w$#]{1,128}+/"),),
    ),  # user/pass@db
    (r"gh", r"secret[ \t]+set", (("--body", "eq", ""), ("-b", "opt", ""))),
    (r"vault", None, (("login[ \t]+(?!-)", "glued", ""),)),  # vault login TOKEN
    # htpasswd -b[c] file user PASS, htpasswd -nb user PASS: the last of them.
    (r"htpasswd", None, ((r"-[A-Za-z]*b[A-Za-z]*(?:[ \t]+[^\s-]\S*+){1,2}", "opt", ""),)),
    (r"nmcli", None, ((r"(?:[\w-]+\.)?(?:password|psk|wep-key[0-3])", "opt", ""),)),
    (
        r"x?freerdp\d*|wlfreerdp|sdl-freerdp",
        None,
        (("/p:", "glued", ""), ("/password:", "glued", "")),
    ),
)


@dataclass(frozen=True)
class _Tool:
    """The patterns of one tool: ``argv`` for its own command line (closed, open), ``script``
    for its command inside a script. ``subcommand``: the flags only count after it (``docker
    login``); ``in_script`` matches the tool's name (and subcommand) inside a script."""

    name: re.Pattern[str]
    subcommand: re.Pattern[str] | None
    in_script: re.Pattern[str]
    argv: tuple[tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...]]
    script: tuple[re.Pattern[str], ...]


def _tool_argv(specs: tuple[_FlagSpec, ...], open_end: bool) -> tuple[re.Pattern[str], ...]:
    wrapped = _wrapped(open_end)
    patterns: list[str] = []
    for flag, how, before in specs:
        sep = _SEPS[how]
        # An element Tetragon wrapped in quotes ("-pa b"): the value runs to its close.
        patterns.append(rf'(?<!\S)"{flag}{sep}{before}{wrapped}')
        if how not in _GLUED or before:
            # The value is an element of its own, wrapped: -p "a b", -u "alice:pw x".
            spaced = "[ \t]+" if how in _GLUED else sep
            patterns.append(rf'(?<!\S){flag}{spaced}"{before}{wrapped}')
        lead, spill = (rf"[\"']?{_SCHEME}", r"(?:-\S*+[ \t]++)*") if how == "assign" else ("", "")
        patterns.append(rf"(?<!\S){flag}{sep}{before}{lead}(?!\[REDACTED\])(?P<secret>{spill}\S+)")
    return tuple(re.compile(pattern) for pattern in patterns)


def _tool_script(specs: tuple[_FlagSpec, ...]) -> tuple[re.Pattern[str], ...]:
    patterns: list[str] = []
    for flag, how, before in specs:
        sep = _SEPS[how]
        # Behind a wrapper (sudo mysql "-ppw x"): an element Tetragon wrapped.
        patterns.append(rf'(?<!\S)"{flag}{sep}{before}(?P<secret>[^"\r\n]++)')
        if before:  # curl -u 'alice:pw x': the quote opens before the user
            spaced = "[ \t]*" if how in _GLUED else sep
            patterns += [
                rf"""(?<![^\s"']){flag}{spaced}{q}{before}(?P<secret>[^{q}\r\n]++)"""
                for q in ("'", '"')
            ]
        # Never again over a strike already made (its closing quote would open a value).
        patterns.append(rf"""(?<![^\s"']){flag}{sep}{before}(?!\[REDACTED\]){_SCRIPT_VALUE}""")
    return tuple(re.compile(pattern) for pattern in patterns)


def _make_tool(name: str, subcommand: str | None, specs: tuple[_FlagSpec, ...]) -> _Tool:
    script_name = rf"(?:{name})" + (rf"[ \t]+(?:{subcommand})" if subcommand else "")
    return _Tool(
        re.compile(name),
        re.compile(rf"[ \t]*(?:{subcommand})(?![\w.-])") if subcommand else None,
        re.compile(script_name),
        (_tool_argv(specs, False), _tool_argv(specs, True)),
        _tool_script(specs),
    )


_TOOLS = tuple(_make_tool(*entry) for entry in _TOOL_FLAGS)
# env's own assignments with the whole flag words, after redact's patterns (as _LATE_PATTERNS):
# env "SIGNING_KEY=a b" run, env MASTER_KEY="Bearer x".
_ENV_TOOL = next(tool for tool in _TOOLS if tool.name.pattern == "env")
_ENV_LATE = tuple(
    _tool_argv(((rf"(?i:[\w.-]*?{FLAG_WORDS})=", "assign", ""),), open_end)
    for open_end in (False, True)
)
_SCRIPT_TOOL_RE = re.compile(
    r"(?<![\w.-])(?:" + "|".join(tool.in_script.pattern for tool in _TOOLS) + r")(?![\w.-])"
)
# A tool's command inside a script: quoted strings are skipped whole (a ; inside them does not
# end it). Matched with an end position, so it never reads more than _SEGMENT characters.
_SEGMENT_RE = re.compile(r"""(?:[^;|&\r\n)`'"]++|'[^'\r\n]*+'?|"[^"\r\n]*+"?)*+""")
# A strike that may hide a command (argv_struck_long, risk 1): it holds a shell separator,
# substitution or redirection, a quote followed by a space (it crossed an element), or it
# crosses a space and is long or reaches the end of the text. A value of token characters
# alone, however long (an AWS session token), cannot carry a command, except when it is quoted
# in an interpreter's script: there it can be code between two strings (_note_code).
_LONG_STRIKE = 64
_SCRIPT_CHARS = frozenset(";|&$(`\n<>")
_CROSSED_RE = re.compile(r"[\"'][ \t]|\\\"")


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
    # A digest of the whole command line, for the reader's novelty. Kept in memory only: it is
    # never part of ``details``, so it never reaches the black box.
    fingerprint: str | None = field(default=None, repr=False)


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
    text: str,
    ctx: Context | None = None,
    limit: int = ARGV_LIMIT,
    *,
    scrubbed: str | None = None,
    tool: str | None = None,
    cut: bool = False,
    notes: set[str] | None = None,
) -> str:
    """Hostile ``text`` made safe to keep: struck, escaped, its runs folded and cut to
    ``limit`` bytes, keeping its head and its tail.

    The order matters: strike first (the patterns need the real newlines, and a cut must
    never leave the head of a key), then escape, then fold and cut. The exact secrets backtide
    knows are struck over the whole text, before any window: a cut cannot split them
    (``scrubbed``: that already done by the caller, so it is not done twice).

    ``tool``: the binary whose command line this is (its own password flags, ``_TOOLS``).
    ``cut``: Tetragon cut the text short (truncArgs), so its end is not its real end and an
    unclosed quote closes there. ``notes`` collects ``"long"`` when a strike may have hidden
    part of a command (``argv_struck_long``)."""
    total = len(text.encode("utf-8", "surrogatepass"))
    if scrubbed is not None:
        text = scrubbed
    elif ctx is not None and ctx.scrub is not None:
        text = ctx.scrub(text)
    found = _tool_of(tool) if tool else None
    code = notes is not None and _runs_code(tool, text)
    if len(text) > 2 * _WINDOW:
        # The head window always ends at an artificial cut; the tail ends where the text does.
        head = _strike_patterns(
            text[: _WINDOW + _MARGIN], tool=found, open_end=True, notes=notes, code=code
        )
        tail = _strike_patterns(
            _tail_window(text), tool=found, open_end=cut, notes=notes, code=code
        )
        return _join(
            _shown(_cut_head(head, _WINDOW)), _shown(_cut_tail(tail, _WINDOW)), limit, total
        )
    clean = _shown(_strike_patterns(text, tool=found, open_end=cut, notes=notes, code=code))
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
    notes: set[str] = set()
    argv = safe_text(
        raw_args,
        ctx,
        scrubbed=scrubbed_args,
        tool=raw_binary,
        cut="truncArgs" in flags,
        notes=notes,
    )
    details: dict[str, Any] = {
        "argv": argv,
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
    if "long" in notes:
        details["argv_struck_long"] = True  # a strike may hide part of the command
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
        risk=1 if struck_whole or "long" in notes else 0,
        binary=binary,
        parent=parent_binary,
        time=t,
        nonce=nonce,
        preexisting=preexisting,
        started=started,
        key=event_key("exec", details),
        # The whole command, for the reader's novelty (an exact repeat, not a shared head):
        # a digest of the full command line with the known secrets struck, where it ran and
        # as whom. Never stored.
        fingerprint=_fingerprint(
            scrubbed_args, _str(process.get("cwd")), str(_int(process.get("uid")))
        ),
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
    # For novelty, a connection to a new target is a new command (only an exact repeat is a
    # repeat).
    fingerprint = _fingerprint(family, addr.compressed, str(port), details["proto"])
    return Record(
        Source.NET,
        "connect",
        target,
        details,
        binary=binary,
        time=t,
        key=key,
        fingerprint=fingerprint,
    )


def _throttle(body: dict[str, Any], t: str | None, ctx: Context) -> Parsed:
    state = _THROTTLE_STATES.get(_str(body.get("type")))
    if state is None:
        return Skipped("unknown")
    scope = _SCOPE_RE.fullmatch(_str(body.get("cgroup")).replace("\0", ""))
    if scope is None or scope.group(1) not in ctx.ids:
        return Skipped("other")
    return Throttle(state, t)


# --- text -----------------------------------------------------------------------------------


def _fingerprint(*parts: str) -> str:
    """A sha256 of ``parts``, each one delimited (no two lists of parts give the same text)."""
    digest = hashlib.sha256()
    for part in parts:
        data = part.encode("utf-8", "surrogatepass")
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def _strike_patterns(
    text: str,
    *,
    tool: _Tool | None = None,
    open_end: bool = False,
    notes: set[str] | None = None,
    code: bool = False,
) -> str:
    """Our command-line forms and redact()'s patterns struck (not cut, not escaped): first the
    tool's own flags (when the binary is one of _TOOLS), then the tools inside scripts, then
    the generic forms. ``open_end``: the text ends at an artificial cut. ``code``: an
    interpreter may run it (_runs_code), for the notes."""
    strike = _striker(notes, code)
    # A subcommand (docker login) is looked for at the start: a window that does not start
    # the command (the tail of a long one) gets the tool's flags only through the scripts.
    if tool is not None and (tool.subcommand is None or tool.subcommand.match(text)):
        for pattern in tool.argv[open_end]:
            text = pattern.sub(strike, text)
    text = _strike_scripts(text, strike)
    for pattern in _ARGV_PATTERNS[open_end]:
        text = pattern.sub(strike, text)
    text = strike_text(
        text,
        on_strike=None if notes is None else lambda m: _note(m, notes, code),
        structured=False,
    )
    late = _LATE_PATTERNS[open_end] + (_ENV_LATE[open_end] if tool is _ENV_TOOL else ())
    for pattern in late:
        text = pattern.sub(strike, text)
    # Last (T27-9, docs/46): a clean literal holds no whitespace, shell character or bracket,
    # but between two strings of a Ruby or Perl script ('+exit!+') it can still be code: noted
    # as _note_code says.
    return strike_structured(
        text,
        FLAG_WORDS,
        on_strike=None if notes is None else lambda s: _note_code(s, notes, code),
        open_end=open_end,
    )


def _tool_of(binary: str | None) -> _Tool | None:
    """The tool whose password flags apply, by the basename of ``binary``."""
    name = (binary or "").rsplit("/", 1)[-1]
    return next((tool for tool in _TOOLS if tool.name.fullmatch(name)), None)


def _script_tool_of(found: str) -> _Tool | None:
    """The tool whose name (and subcommand) a script names, as _SCRIPT_TOOL_RE found it."""
    return next((tool for tool in _TOOLS if tool.in_script.fullmatch(found)), None)


def _strike_scripts(text: str, strike: Callable[[re.Match[str]], str]) -> str:
    """Each tool's password flags inside a script: from the tool's name to the end of its own
    command (_SEGMENT_RE, at most _SEGMENT characters). Every character belongs to at most one
    segment, so the work stays linear."""
    out: list[str] = []
    done = 0
    for found in _SCRIPT_TOOL_RE.finditer(text):
        if found.start() < done:
            continue
        tool = _script_tool_of(found.group(0))
        if tool is None:
            continue
        start = found.end()
        segment = _SEGMENT_RE.match(text, start, min(len(text), start + _SEGMENT))
        stop = segment.end() if segment is not None else start
        part = text[start:stop]
        for pattern in tool.script:
            part = pattern.sub(strike, part)
        out += [text[done:start], part]
        done = stop
    if not out:
        return text
    out.append(text[done:])
    return "".join(out)


def _striker(notes: set[str] | None, code: bool = False) -> Callable[[re.Match[str]], str]:
    if notes is None:
        return _strike

    def strike(match: re.Match[str]) -> str:
        _note(match, notes, code)
        return _strike(match)

    return strike


_WORD_RE = re.compile(r"\w*", re.ASCII)
_TOKEN_SET = frozenset(_TOKEN_CHARS)
# A program that runs code written in its arguments, with or without its version in the name
# (perl5.36.0, ruby3.1, python3.12). Between two strings of its script a quoted "value" can be
# code ('+exit!+', '.unlink"f".'); for any other program (mysql --password='a-1', export
# TOKEN="ab+c=") it is one word of the command.
_INTERPRETER_RE = re.compile(
    r"(?<![\w.-])(?:ruby|irb|jruby|truffleruby|perl|raku|rakudo|python|pypy|node|nodejs|deno"
    r"|bun|php|lua|luajit|tclsh|wish|[gm]?awk|osascript|pwsh|julia|Rscript)[\d.]*(?![\w-])"
)
# The image's own programs. The agent's root is read-only, so a program anywhere else (its
# workspace, /tmp, /dev/shm, a relative path) is one the agent put there: a link to perl, say.
_IMAGE_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/")


def _runs_code(binary: str | None, text: str) -> bool:
    """Whether an interpreter may run ``text``: ``binary`` is one, or the agent's own program
    (outside the image), or the text names one (sh -c "ruby -e …")."""
    binary = binary or ""
    if not binary.startswith(_IMAGE_DIRS):
        return True
    name = binary.rsplit("/", 1)[-1]
    return _INTERPRETER_RE.fullmatch(name) is not None or _INTERPRETER_RE.search(text) is not None


def _note_code(value: str, notes: set[str], code: bool) -> None:
    """Note a quoted strike that may be code between two strings of a script: any value with a
    character no token has ('+exit!+'), whatever the program; one of token characters only
    ('.exit.') when an interpreter may run the text (``code``). An image program with an
    interpreter's power under a name not in _INTERPRETER_RE, with token characters alone (no
    space, quote, bracket or "!"), is the accepted rest."""
    if _WORD_RE.fullmatch(value) is not None:
        return
    if code or not set(value) <= _TOKEN_SET:
        notes.add("long")


def _note(match: re.Match[str], notes: set[str], code: bool = False) -> None:
    """Note a strike that may hide part of a command (see _LONG_STRIKE)."""
    secret = match.group("secret")
    if secret == REDACTED or not secret:
        return
    spaced = any(char.isspace() for char in secret)
    reaches_end = match.end("secret") == len(match.string)
    if (
        not _SCRIPT_CHARS.isdisjoint(secret)
        or _CROSSED_RE.search(secret) is not None
        or (spaced and len(secret) > _LONG_STRIKE)
        or (spaced and reaches_end)
    ):
        notes.add("long")
        return
    # A quoted value can be the code between two strings of a Ruby or Perl script, as in
    # print('x_token='.unlink"/w/f".'') (T27-9a review).
    start = match.start("secret")
    if start > 0 and match.string[start - 1] in "'\"":
        _note_code(secret, notes, code)


def every_pattern() -> list[re.Pattern[str]]:
    """Every pattern of this module that runs on hostile text: for the cost tests."""
    patterns = [*_ARGV_PATTERNS[0], *_ARGV_PATTERNS[1], _KEY_END_RE, _SCRIPT_TOOL_RE]
    patterns += [*_LATE_PATTERNS[0], *_LATE_PATTERNS[1], *_ENV_LATE[0], *_ENV_LATE[1]]
    for tool in _TOOLS:
        patterns += [*tool.argv[0], *tool.argv[1], *tool.script]
    return patterns


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
    return _strike_key_bodies(window)


def _strike_key_bodies(text: str) -> str:
    """The lines of a key body right before each ``-----END … PRIVATE KEY-----`` (whose BEGIN
    may be out of the window), struck. Each END walks back at most over the lines since the
    previous one, so the work stays linear."""
    out: list[str] = []
    done = 0
    for end in _KEY_END_RE.finditer(text):
        pos = first = end.start()
        sizes: list[int] = []
        while pos > done and text[pos - 1] == "\n":
            low = max(done, pos - 2 - 80)
            prev = text.rfind("\n", low, pos - 1)
            if prev < 0 and low > done:
                break  # longer than any key line
            line_start = prev + 1 if prev >= 0 else done
            line = text[line_start : pos - 1]
            if not _KEY_LINE_RE.fullmatch(line):
                break
            size = len(line.rstrip("\r"))
            if sizes and size < _KEY_LINE_MIN:
                break  # only the last line of a body may be short
            sizes.append(size)
            pos = line_start
        long_lines = sum(size >= _KEY_LINE_MIN for size in sizes)
        if long_lines >= _KEY_LINES:
            out += [text[done:pos], REDACTED + "\n"]
            done = first
    if not out:
        return text
    out.append(text[done:])
    return "".join(out)


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
