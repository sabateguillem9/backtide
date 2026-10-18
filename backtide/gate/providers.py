"""The model providers, their credential headers, the fake-key swap and the search for a
real key. Pure: no I/O (the fake key's randomness comes from ``secrets``).

The agent only ever holds a fake key, ``backtide-fake-<provider>-<32 random characters>``.
On the way out to its provider's host, the proxy drops every credential header and puts the
real key in the provider's header. A request that carries the real key, anywhere and to any
host, is refused. Design and rationale: docs/21-diseno-t06-proxy.md, section 6.
"""

import re
import secrets
import string
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from hmac import compare_digest
from typing import NoReturn

from backtide.blackbox.redact import MIN_KNOWN_SECRET, scrub_known
from backtide.gate.policy import is_ip, normalize_host

FAKE_KEY_PREFIX = "backtide-fake-"
_FAKE_KEY_RANDOM = 32
_ALPHABET = string.ascii_letters + string.digits
_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", re.ASCII)
_FAKE_KEY_RE = re.compile(
    rf"{re.escape(FAKE_KEY_PREFIX)}(?P<name>{_NAME_RE.pattern})-[A-Za-z0-9]{{{_FAKE_KEY_RANDOM}}}",
    re.ASCII,
)
# OpenClaw takes a key that contains this for an OAuth token (T06-1, docs/21 section 6).
_OAUTH_MARK = "sk-ant-oat"
# Printable ASCII without spaces: anything else could break or inject a header line.
_REAL_KEY_RE = re.compile(r"[\x21-\x7e]+", re.ASCII)
MIN_REAL_KEY = 20
MAX_MODELS = 32
MAX_MODEL_ID = 128

# Dropped from every request to a provider host, whatever the provider (docs/21, section 6).
CREDENTIAL_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie", "proxy-authorization"}
)
# A header name as RFC 9110 defines it ("token"): no spaces, no colons, nothing odd.
_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
_BEARER_RE = re.compile(r"(?i:bearer) +(?P<token>\S+)", re.ASCII)


class Kind(StrEnum):
    """How a provider takes its key. Gemini and Azure come later (docs/21, section 6)."""

    ANTHROPIC = "anthropic"  # x-api-key: <key>
    OPENAI = "openai"  # Authorization: Bearer <key> (OpenAI and compatible APIs)


DEFAULT_HOSTS = {Kind.ANTHROPIC: "api.anthropic.com", Kind.OPENAI: "api.openai.com"}
_HEADER = {Kind.ANTHROPIC: "x-api-key", Kind.OPENAI: "authorization"}


class Secret:
    """A string that must not reach a log, an error or the black box: it prints as
    ``[REDACTED]`` and ``reveal()`` is the only way to read it.

    The same contract as ``backtide.service.config.Secret``, kept here because the proxy
    must not import the service (docs/21, section 1)."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("a Secret holds a str")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED]"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return "[REDACTED]"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a Secret cannot be pickled or copied")


def new_fake_key(name: str) -> str:
    """A new fake key for the provider ``name`` (lower case, digits and dashes)."""
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ValueError("a provider name is 1-32 lower-case letters, digits or dashes")
    while True:
        random = "".join(secrets.choice(_ALPHABET) for _ in range(_FAKE_KEY_RANDOM))
        key = f"{FAKE_KEY_PREFIX}{name}-{random}"
        if is_fake_key(key):  # never draws "sk-ant-oat" by chance
            return key


def is_fake_key(value: object, name: str | None = None) -> bool:
    """Whether ``value`` has the shape of a fake key (for provider ``name``, if given)."""
    if not isinstance(value, str):
        return False
    match = _FAKE_KEY_RE.fullmatch(value)
    if match is None or _OAUTH_MARK in value.lower():
        return False
    return name is None or match.group("name") == name


@dataclass(frozen=True)
class Provider:
    """A model provider as backtide configures it. ``host`` is compared exactly with the
    connection's host (never with the ``Host`` header). Raises ValueError, with messages
    that never contain a key."""

    name: str
    kind: Kind
    host: str
    fake_key: str = field(repr=False)
    real_key: Secret = field(repr=False)
    # The model ids of [[proxy.providers]] models: when there are any, a request to this
    # provider may only ask for one of them (T06-6). Empty: any model.
    models: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME_RE.fullmatch(self.name):
            raise ValueError("a provider name is 1-32 lower-case letters, digits or dashes")
        try:
            object.__setattr__(self, "kind", Kind(self.kind))
        except ValueError:
            raise ValueError(f"provider {self.name}: unknown kind") from None
        host = normalize_host(self.host)
        if host is None or is_ip(host):
            raise ValueError(f"provider {self.name}: the host must be a host name")
        object.__setattr__(self, "host", host)
        if not is_fake_key(self.fake_key, self.name):
            raise ValueError(f"provider {self.name}: the fake key does not have the right shape")
        if not isinstance(self.real_key, Secret):
            raise ValueError(f"provider {self.name}: the real key must be a Secret")
        real = self.real_key.reveal()
        if len(real) < MIN_REAL_KEY or not _REAL_KEY_RE.fullmatch(real):
            raise ValueError(
                f"provider {self.name}: the real key must be {MIN_REAL_KEY}+ printable "
                "ASCII characters without spaces"
            )
        if real.startswith(FAKE_KEY_PREFIX) or real in self.fake_key or self.fake_key in real:
            raise ValueError(f"provider {self.name}: the real key cannot be a fake key")
        models = tuple(self.models) if isinstance(self.models, list | tuple) else None
        if (
            models is None
            or len(models) > MAX_MODELS
            or not all(isinstance(m, str) and 0 < len(m) <= MAX_MODEL_ID and m.isprintable()
                       for m in models)
        ):  # fmt: skip
            raise ValueError(f"provider {self.name}: models must be up to {MAX_MODELS} model ids")
        object.__setattr__(self, "models", models)

    @property
    def header(self) -> str:
        """The header that carries the key, in lower case."""
        return _HEADER[self.kind]

    def _carries_fake_key(self, value: str) -> bool:
        value = value.strip(" \t")
        if self.kind is Kind.OPENAI:
            match = _BEARER_RE.fullmatch(value)
            if match is None:
                return False
            value = match.group("token")
        return compare_digest(value.encode(), self.fake_key.encode())

    def _real_header_value(self) -> str:
        real = self.real_key.reveal()
        return f"Bearer {real}" if self.kind is Kind.OPENAI else real


def swap_key(
    provider: Provider, headers: Sequence[tuple[str, str]], *, scheme: str, port: int
) -> list[tuple[str, str]] | None:
    """The headers to send to ``provider``: every credential header dropped and the real
    key put in the provider's header (appended, in lower case).

    None (``foreign_credential``) unless the request goes over HTTPS to port 443 (the real
    key never travels in clear), every header name is a plain HTTP token, and there is
    EXACTLY ONE credential header, the provider's, holding exactly its fake key: not
    another key, an OAuth token, a cookie, the fake key in another header, twice, or nothing.
    """
    if scheme != "https" or type(port) is not int or port != 443:
        return None
    if not all(isinstance(name, str) and _TOKEN_RE.fullmatch(name) for name, _ in headers):
        return None
    credentials = [(name, value) for name, value in headers if name.lower() in CREDENTIAL_HEADERS]
    if len(credentials) != 1:
        return None
    [(name, value)] = credentials
    if name.lower() != provider.header or not provider._carries_fake_key(value):
        return None
    kept = [(name, value) for name, value in headers if name.lower() not in CREDENTIAL_HEADERS]
    return [*kept, (provider.header, provider._real_header_value())]


def contains_secret(part: str | bytes | None, known: Iterable[str]) -> bool:
    """Whether any of the ``known`` secrets shows in ``part``, as is, URL-encoded (in any
    way), with JSON escapes or HTML entities. Bytes are read as Latin-1, so a key (ASCII)
    is found whatever the rest of the bytes are.

    Known limit (docs/21, section 6): a key encoded otherwise (base64, split in two,
    compressed) is not seen. The real defence is that the agent never has it. Raises
    ValueError for a secret shorter than MIN_KNOWN_SECRET.
    """
    secrets_list = list(known)
    if any(not isinstance(s, str) or len(s) < MIN_KNOWN_SECRET for s in secrets_list):
        raise ValueError(f"a known secret must be a text of {MIN_KNOWN_SECRET}+ characters")
    if part is None or not secrets_list:
        return False
    text = part.decode("latin-1") if isinstance(part, bytes) else part
    return scrub_known(text, secrets_list) != text


class Providers:
    """The configured providers: no two share a name, a host or a key."""

    def __init__(self, items: Iterable[Provider]) -> None:
        self.items: tuple[Provider, ...] = tuple(items)
        names = [p.name for p in self.items]
        hosts = [p.host for p in self.items]
        keys = [p.real_key.reveal() for p in self.items] + [p.fake_key for p in self.items]
        if len(set(names)) != len(names):
            raise ValueError("two providers have the same name")
        if len(set(hosts)) != len(hosts):
            raise ValueError("two providers have the same host")
        if len(set(keys)) != len(keys):
            raise ValueError("two providers share a key")
        self._by_host = {p.host: p for p in self.items}

    def __repr__(self) -> str:
        return f"Providers({', '.join(p.name for p in self.items)})"

    def for_host(self, host: str) -> Provider | None:
        """The provider whose host is exactly ``host`` (the connection's), if any."""
        name = normalize_host(host)
        return self._by_host.get(name) if name else None

    def real_key_in(self, *parts: str | bytes | None) -> bool:
        """Whether any real key shows in any of ``parts`` (the URL, each header name and
        value, the body, a WebSocket message). Checked for every request, to any host."""
        real = [p.real_key.reveal() for p in self.items]
        return any(contains_secret(part, real) for part in parts)

    def known_secrets(self) -> tuple[str, ...]:
        """Every real and fake key, for ``scrub_known`` before anything is recorded."""
        return tuple(p.real_key.reveal() for p in self.items) + tuple(
            p.fake_key for p in self.items
        )
