"""Strike secrets out of what gets recorded, and cut long texts. Pure: no I/O.

This is the second barrier (invariant 5); the first one is the proxy (T06). Redaction
errs on the side of striking too much: a lost word is better than a stored key.
"""

import re
from collections.abc import Mapping
from typing import Any

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
    re.compile(r"(?<![0-9])(?P<secret>[0-9]{6,12}:[A-Za-z0-9_-]{30,})"),  # Telegram bot
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
