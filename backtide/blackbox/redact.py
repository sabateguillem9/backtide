"""Strike secrets out of what gets recorded, and cut long texts. Pure: no I/O.

This is the second barrier (invariant 5); the first one is the proxy (T06). Redaction
errs on the side of striking too much: a lost word is better than a stored key.
"""

import html
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any, NoReturn
from urllib.parse import quote, quote_plus, unquote, unquote_plus

REDACTED = "[REDACTED]"
MAX_TEXT_BYTES = 4096
# Room kept for the "…[truncated N bytes]" suffix, so a cut text stays within MAX_TEXT_BYTES.
_SUFFIX_RESERVE = 64

# A name is secret when it ENDS with one of these words, so "access_token", "X-Api-Key"
# or "client_secret" are secret but "input_tokens" or "token_count" are not.
_SENSITIVE_WORDS = (
    r"(?:token|secret|passw(?:or)?d|api[-_]?key|private[-_]?key|access[-_]?key"
    r"|(?:secret|signing|encryption|master)[-_]?key|authorization|cookie)"
)
_SECRET_NAME_RE = re.compile(rf"[\w.-]*?{_SENSITIVE_WORDS}")
# Headers stored as {"name": "Authorization", "value": "..."} (HAR) or similar pairs.
_PAIR_NAME_KEYS = frozenset({"name", "key", "header"})
_PAIR_VALUE_KEYS = frozenset({"value", "values"})

# Each pattern marks the part to strike with the group "secret". Order matters: whole
# blocks first, then header lines, then single tokens, then name/value pairs. A name is
# matched from its first character (the lookbehinds), which also keeps the scans linear.
_TEXT_PATTERNS = (
    # PEM private keys. A block without its END line is struck to the end of the text.
    re.compile(
        r"(?P<secret>-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
        r"(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|.*))",
        re.DOTALL,
    ),
    # JSON Web Tokens: base64url('{"...') . base64url('{"...') . signature
    re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)"),
    # Header lines with a secret name: "Authorization: Basic ...", "X-Auth-Token: ..."
    re.compile(rf"(?i)(?<![\w-])[\w-]*?{_SENSITIVE_WORDS}[ \t]*:[ \t]*(?P<secret>[^\r\n\"']+)"),
    re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/-]{8,}=*)"),
    # Basic credentials: base64 (with a digit, +, /, = or a case change, unlike a word).
    re.compile(
        r"(?i:\bbasic)\s+"
        r"(?P<secret>(?=[A-Za-z0-9+/]*(?:[0-9+/=]|[a-z][A-Z]))[A-Za-z0-9+/]{8,}={0,2})"
    ),
    re.compile(r"\b(?P<secret>sk-[A-Za-z0-9_-]{20,})"),  # OpenAI, Anthropic
    re.compile(r"\b(?P<secret>[rs]k_(?:live|test)_[A-Za-z0-9]{16,})"),  # Stripe
    re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})"),  # Google API keys (Gemini)
    re.compile(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{20,})"),  # GitHub
    re.compile(r"\b(?P<secret>github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,})"),  # GitLab
    re.compile(r"\b(?P<secret>xox[abprs]-[A-Za-z0-9-]{10,})"),  # Slack
    re.compile(r"\b(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})\b"),  # AWS access key id
    re.compile(r"(?<![0-9])(?P<secret>[0-9]{5,16}:[A-Za-z0-9_-]{30,})"),  # Telegram bot
    # Credentials inside a URL: scheme://user:password@host
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:(?P<secret>[^/\s@]+)@"),
    # curl -u user:password, --user user:password
    re.compile(r"(?<!\S)(?:-u|--user)(?:[ \t]+|=)[^\s:]+:(?P<secret>\S+)"),
    # A flag with a secret name and its value after a space: --password hunter2
    re.compile(rf"(?i)(?<!\S)--?[\w-]*?{_SENSITIVE_WORDS}[ \t]+(?P<secret>[^\s'\"]+)"),
    # URL parameters that carry a key or a signature: ?key=AIza..., &sig=...
    re.compile(r"(?i)[?&](?:key|sig|signature)=(?P<secret>[^&#\s]+)"),
    # name=value with a secret name: URL parameters, --flags, environment variables.
    re.compile(rf"(?i)(?<![\w.-])[\w.-]*?{_SENSITIVE_WORDS}=(?P<secret>[^\s&#;,'\"]+)"),
    # "name": "value" with a secret name: JSON and Python reprs inside a text.
    re.compile(rf"(?i)\"[\w.-]*?{_SENSITIVE_WORDS}\"\s*:\s*\"(?P<secret>(?:[^\"\\]|\\.)*)\""),
    re.compile(rf"(?i)'[\w.-]*?{_SENSITIVE_WORDS}'\s*:\s*'(?P<secret>(?:[^'\\]|\\.)*)'"),
)


def redact(value: Any) -> Any:
    """Return a copy of ``value`` with secrets struck out and every text cut to 4 KiB.

    - Mappings: the value of a secret name becomes REDACTED, whatever its type, and so
      does the "value" of a {"name": <secret name>, "value": ...} pair. Two keys that
      become equal once redacted or cut are both kept: the later one gets "#2", "#3"...
    - Pairs: in a 2-item list or tuple whose first item is a secret name, the second
      becomes REDACTED (headers as [("Cookie", "..."), ...], argv ["--password", "..."]).
    - Texts (values and keys): secret patterns are struck, lone surrogates are escaped
      so the text is valid UTF-8, and texts over MAX_TEXT_BYTES are cut.
    - Lists and tuples become lists. Other values are returned unchanged.
    """
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return _redact_mapping(value)
    if isinstance(value, list | tuple):
        if len(value) == 2 and _is_secret_name(value[0]):
            return [redact(value[0]), REDACTED]
        return [redact(item) for item in value]
    return value


def _redact_mapping(mapping: Mapping[Any, Any]) -> dict[Any, Any]:
    names_a_secret = any(
        _lower(key) in _PAIR_NAME_KEYS and _is_secret_name(item) for key, item in mapping.items()
    )
    result: dict[Any, Any] = {}
    for key, item in mapping.items():
        hidden = _is_secret_name(key) or (names_a_secret and _lower(key) in _PAIR_VALUE_KEYS)
        result[_unused_key(result, _redact_key(key))] = REDACTED if hidden else redact(item)
    return result


def _unused_key(taken: Mapping[Any, Any], key: Any) -> Any:
    """``key``, or ``key#2``, ``key#3``... if taken: never overwrite another entry."""
    if key not in taken:
        return key
    number = 2
    while f"{key}#{number}" in taken:
        number += 1
    return f"{key}#{number}"


def _lower(key: object) -> str | None:
    return key.strip().lower() if isinstance(key, str) else None


def _is_secret_name(key: object) -> bool:
    return isinstance(key, str) and _SECRET_NAME_RE.fullmatch(key.strip().lower()) is not None


def _redact_key(key: object) -> object:
    return _redact_text(key) if isinstance(key, str) else key


def _redact_text(text: str) -> str:
    text = _to_valid_utf8(text)
    for pattern in _TEXT_PATTERNS:
        text = pattern.sub(_strike_secret, text)
    return _truncate(text)


def _strike_secret(match: re.Match[str]) -> str:
    start, end = match.span("secret")
    offset = match.start()
    whole = match.group(0)
    return whole[: start - offset] + REDACTED + whole[end - offset :]


def _to_valid_utf8(text: str) -> str:
    """Escape lone surrogates (undecodable file names) so the text encodes as UTF-8."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _truncate(text: str) -> str:
    data = text.encode("utf-8")
    if len(data) <= MAX_TEXT_BYTES:
        return text
    # Cut on a byte budget; "ignore" only drops a character split by the cut.
    head = data[: MAX_TEXT_BYTES - _SUFFIX_RESERVE].decode("utf-8", errors="ignore")
    dropped = len(data) - len(head.encode("utf-8"))
    return f"{head}…[truncated {dropped} bytes]"


# --- scrub_known: the secrets backtide knows (T06) ----------------------------------------------

# Shorter secrets would strike ordinary words; the configuration never holds one this short.
MIN_KNOWN_SECRET = 8
_JSON_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_PERCENT_RE = re.compile(r"%([0-9A-F])([0-9A-F])")


# A text cut by someone who did not know a secret may end with its first characters.
MIN_CUT_TAIL = 4


def scrub_known(value: Any, secrets: Iterable[str], *, cut_tails: bool = False) -> Any:
    """Return a copy of ``value`` with each exact appearance of the given secrets (the real
    and fake keys, the Gateway token) replaced by REDACTED, in texts and in keys.

    - Also URL-encoded: ``%xx`` in any letter case, ``+`` for spaces.
    - A text in which a secret still shows once decoded some other way (partly or twice
      URL-encoded, ``\\uXXXX`` JSON escapes, HTML entities) becomes REDACTED as a whole:
      the place cannot be pinned down, so the whole text goes.
    - With ``cut_tails``, a text that ENDS with the first MIN_CUT_TAIL+ characters of a
      secret loses that end too: for texts already cut by someone who did not know the
      secret (backtide re-striking what the proxy sends, docs/21 section 5).
    - Mappings, lists and tuples are walked as in redact(); colliding keys are all kept.

    Run it BEFORE redact() or any cut: a secret split by a cut can no longer be found.
    Raises ValueError for a secret that is not a str or is shorter than MIN_KNOWN_SECRET.
    For many values with the same secrets, build one KnownScrubber and reuse it.
    """
    return KnownScrubber(secrets, cut_tails=cut_tails)(value)


class KnownScrubber:
    """scrub_known() with its secrets prepared once (the pattern is built here)."""

    __slots__ = ("_cut_tails", "_pattern", "_plain")

    def __init__(self, secrets: Iterable[str], *, cut_tails: bool = False) -> None:
        plain: list[str] = []
        for secret in secrets:
            if not isinstance(secret, str) or len(secret) < MIN_KNOWN_SECRET:
                raise ValueError(f"a known secret must be a text of {MIN_KNOWN_SECRET}+ characters")
            plain.append(secret)
        self._plain = tuple(dict.fromkeys(plain))
        self._pattern = _known_pattern(self._plain) if self._plain else None
        self._cut_tails = cut_tails

    def __repr__(self) -> str:
        return f"KnownScrubber({len(self._plain)} secrets)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a KnownScrubber cannot be pickled or copied")

    def __call__(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Mapping):
            result: dict[Any, Any] = {}
            for key, item in value.items():
                new_key = self.text(key) if isinstance(key, str) else key
                result[_unused_key(result, new_key)] = self(item)
            return result
        if isinstance(value, list | tuple):
            return [self(item) for item in value]
        return value

    def text(self, text: str) -> str:
        if self._pattern is None:
            return text
        text = self._pattern.sub(REDACTED, text)
        if any(secret in decoded for decoded in _decodings(text) for secret in self._plain):
            return REDACTED
        if self._cut_tails:
            text = _strike_cut_tail(text, self._plain)
        return text


def _strike_cut_tail(text: str, plain: tuple[str, ...]) -> str:
    longest = 0
    for secret in plain:
        for size in range(min(len(secret) - 1, len(text)), MIN_CUT_TAIL - 1, -1):
            if size <= longest:
                break
            if text.endswith(secret[:size]):
                longest = size
                break
    return text[: len(text) - longest] + REDACTED if longest else text


def _known_pattern(plain: tuple[str, ...]) -> re.Pattern[str]:
    forms = {
        encoded
        for secret in plain
        for encoded in (
            secret,
            quote(secret, safe=""),
            quote(secret),
            quote_plus(secret, safe=""),
            json.dumps(secret)[1:-1],
        )
    }
    # Longest first, so a secret that contains another is struck whole.
    ordered = sorted(forms, key=len, reverse=True)
    return re.compile("|".join(_PERCENT_RE.sub(_any_case_escape, re.escape(f)) for f in ordered))


def _any_case_escape(match: re.Match[str]) -> str:
    """``%2F`` (already through re.escape) matches ``%2f`` too."""
    high, low = match.group(1), match.group(2)
    return "%" + "".join(f"[{c.upper()}{c.lower()}]" if c.isalpha() else c for c in high + low)


def _decodings(text: str) -> tuple[str, ...]:
    """Ways a server or a program could read ``text`` back."""
    once = unquote(text)
    return (
        once,
        unquote(once),
        unquote_plus(text),
        _JSON_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text).replace("\\/", "/"),
        html.unescape(text),
    )
