"""The model providers, their credential headers, the fake-key swap and the search for a
real key. Pure: no I/O (the fake key's randomness comes from ``secrets``).

The agent only ever holds a fake key, ``backtide-fake-<provider>-<32 random characters>``.
On the way out to its provider's host, the proxy drops every credential header and puts the
real key in the provider's header. A request that carries the real key, anywhere and to any
host, is refused. A provider whose real key the owner has not set yet (or whose key file cannot
be used) is "waiting": it has no real key at all, and nothing goes to its host (``no_key``).
Design and rationale: docs/21-diseno-t06-proxy.md, section 6.

A **local** provider (T20, docs/35 section 6) is a model on the owner's own machine (Ollama on the
Mac or on a computer of the LAN). The agent calls it by a virtual name,
``<provider>.backtide.internal``, that no DNS knows; backtide resolved its real place once, on
the trusted side, to a fixed private IPv4 and port (``upstream``), and the proxy goes there and
nowhere else. It has no real key: the agent still holds a fake one, which the proxy demands and
drops, and no credential ever reaches the owner's machine. Its models are listed (never one that
runs in Ollama's cloud) and only its model routes pass, compared exactly
(``provider_tools.exact_endpoint``).
"""

import json
import re
import secrets
import string
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from hmac import compare_digest
from ipaddress import IPv4Address, IPv4Network
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

# The headers that carry a credential: dropped from every request to a provider host, whatever
# the provider (docs/21, section 6), and left out of decision 1's guard on the other headers of a
# read (their bytes are capped apart: decide.MAX_READ_CREDENTIALS). Besides the usual ones, the
# token headers of common APIs (T10-3), so a read with its own token is not held as a leak:
# GitLab (``PRIVATE-TOKEN``, ``JOB-TOKEN``), OpenStack and many others (``X-Auth-Token``), the
# ``X-Access-Token`` some APIs use, and an AWS session token (``X-Amz-Security-Token``).
CREDENTIAL_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie", "proxy-authorization",
     "private-token", "job-token", "x-auth-token", "x-access-token", "x-amz-security-token"}
)  # fmt: skip
# A header name as RFC 9110 defines it ("token"): no spaces, no colons, nothing odd.
_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
_BEARER_RE = re.compile(r"(?i:bearer) +(?P<token>\S+)", re.ASCII)


class Kind(StrEnum):
    """How a provider takes its key. Gemini and Azure come later (docs/21, section 6)."""

    ANTHROPIC = "anthropic"  # x-api-key: <key>
    OPENAI = "openai"  # Authorization: Bearer <key> (OpenAI and compatible APIs)


_HEADER = {Kind.ANTHROPIC: "x-api-key", Kind.OPENAI: "authorization"}

# T20 (docs/35, section 6.1): a local provider's virtual name, and where it may really be.
LOCAL_SUFFIX = ".backtide.internal"  # ".internal" is reserved (ICANN, 2024): never on internet
MAX_LOCAL = 4
# Only private IPv4 (decision 5): the LAN's ranges and Tailscale's (100.64/10). Never loopback
# (inside the proxy that is the proxy itself), "this network", link-local (cloud metadata),
# multicast, broadcast, a public address (a public provider goes by https like any other) nor
# IPv6. The agent's own network is refused by the service, which knows its subnet.
LOCAL_NETWORKS = tuple(
    IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)
# Inside 100.64/10 but never a model (review of T20-2/3, L3): Alibaba Cloud's metadata service
# (100.100.100.200) and Tailscale's own resolver (100.100.100.100).
LOCAL_REFUSED = IPv4Network("100.100.100.0/24")
# Ollama's cloud API (T20, the founder's addition): a public provider like any other, with a
# real key; only its model routes pass, compared exactly as for a local one (the same server
# has its account and web-search routes). ``ollama.com`` and any name under it.
OLLAMA_CLOUD_HOST = "ollama.com"
# A model that runs in Ollama's cloud (decision 6): ``:cloud``, ``-cloud`` or a tag that says so.
_CLOUD_MODEL_RE = re.compile(r"(?:^|[:_.-])cloud(?:[:_.-]|$)", re.ASCII)


def virtual_host(name: str) -> str:
    """The virtual name of the local provider ``name``: ``<name>.backtide.internal``."""
    return f"{name}{LOCAL_SUFFIX}"


def is_cloud_model(model: object) -> bool:
    """Whether a model id names one of Ollama's cloud models (``qwen3:480b-cloud``,
    ``gpt-oss:cloud``): a "local" call to it would leave home through the owner's Ollama."""
    return isinstance(model, str) and _CLOUD_MODEL_RE.search(model.lower()) is not None


def is_ollama_cloud(host: object) -> bool:
    """Whether ``host`` is Ollama's cloud: ``ollama.com`` or a name under it."""
    name = normalize_host(host, idna=True)
    return name is not None and (
        name == OLLAMA_CLOUD_HOST or name.endswith("." + OLLAMA_CLOUD_HOST)
    )


def local_address_ok(address: object) -> bool:
    """Whether a local provider may be at ``address``: a plain IPv4 text in its canonical form
    (``192.168.5.2``; never ``0xc0a80502``, ``3232236802`` or IPv6), inside LOCAL_NETWORKS and
    not the network's own first or last address, and never in LOCAL_REFUSED."""
    if not isinstance(address, str):
        return False
    try:
        parsed = IPv4Address(address)
    except ValueError:
        return False
    if str(parsed) != address or parsed in LOCAL_REFUSED:
        return False
    for net in LOCAL_NETWORKS:
        if parsed in net:
            return parsed not in (net.network_address, net.broadcast_address)
    return False


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
    # None: waiting for its key (the owner has not set it, or its file cannot be used). The
    # proxy then refuses every call to this provider (``no_key``) and never contacts it.
    real_key: Secret | None = field(repr=False)
    # The model ids of [[proxy.providers]] models: when there are any, a request to this
    # provider may only ask for one of them (T06-6). Empty: any model.
    models: tuple[str, ...] = ()
    # T20: a local provider (``host`` is its virtual name) and where backtide found it, as
    # (IPv4, port). ``upstream`` None for a local one: not resolved yet, and refused (the proxy
    # never gets one so: the channel demands it).
    local: bool = False
    upstream: tuple[str, int] | None = None
    # T11 (docs/33, "include_usage"): whether the proxy may ask this provider for the usage of a
    # streamed Chat Completions call (``[[proxy.providers]] stream_usage``; on by default). Off
    # for a compatible API that refuses fields it does not know.
    stream_usage: bool = True

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
        if self.real_key is not None:
            self._check_real_key()
        models = tuple(self.models) if isinstance(self.models, list | tuple) else None
        if (
            models is None
            or len(models) > MAX_MODELS
            or not all(isinstance(m, str) and 0 < len(m) <= MAX_MODEL_ID and m.isprintable()
                       for m in models)
        ):  # fmt: skip
            raise ValueError(f"provider {self.name}: models must be up to {MAX_MODELS} model ids")
        object.__setattr__(self, "models", models)
        if self.local is not True and self.local is not False:
            raise ValueError(f"provider {self.name}: local is true or false")
        if self.stream_usage is not True and self.stream_usage is not False:
            raise ValueError(f"provider {self.name}: stream_usage is true or false")
        if self.local:
            self._check_local()
        elif self.host.endswith(LOCAL_SUFFIX) or self.upstream is not None:
            raise ValueError(
                f"provider {self.name}: only a local provider has a virtual name or an upstream"
            )

    def _check_local(self) -> None:
        if self.host != virtual_host(self.name):
            raise ValueError(f"provider {self.name}: a local provider's host is its virtual name")
        if self.real_key is not None:
            raise ValueError(f"provider {self.name}: a local provider has no real key")
        if not self.models or any(is_cloud_model(model) for model in self.models):
            raise ValueError(
                f"provider {self.name}: a local provider lists its models, none of the cloud"
            )
        upstream = self.upstream
        if upstream is None:
            return
        if (
            not isinstance(upstream, tuple)
            or len(upstream) != 2
            or not local_address_ok(upstream[0])
            or type(upstream[1]) is not int
            or not 0 < upstream[1] < 65536
        ):
            raise ValueError(
                f"provider {self.name}: a local provider is at a private IPv4 and a port"
            )

    def _check_real_key(self) -> None:
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

    @property
    def waiting(self) -> bool:
        """Whether it waits for its real key: then nothing is sent to it. A local provider never
        has one, and never waits for it."""
        return self.real_key is None and not self.local

    @property
    def exact_paths(self) -> bool:
        """Whether only its model routes pass, compared exactly (``exact_endpoint``): a local
        provider (an Ollama on the owner's machine) and Ollama's cloud API."""
        return self.local or is_ollama_cloud(self.host)

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
        if self.real_key is None:
            raise ValueError(f"provider {self.name}: it has no real key yet")
        real = self.real_key.reveal()
        return f"Bearer {real}" if self.kind is Kind.OPENAI else real


def only_fake_key(
    provider: Provider, headers: Sequence[tuple[str, str]], *, scheme: str, port: int
) -> list[tuple[str, str]] | None:
    """The headers without any credential header, if the request carries exactly the fake key
    of ``provider`` as its only credential (``swap_key``'s rules); None otherwise
    (``foreign_credential``). For a provider that waits for its key, too: what the agent sends
    it is checked the same, though nothing goes out."""
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
    return [(name, value) for name, value in headers if name.lower() not in CREDENTIAL_HEADERS]


def swap_key(
    provider: Provider, headers: Sequence[tuple[str, str]], *, scheme: str, port: int
) -> list[tuple[str, str]] | None:
    """The headers to send to ``provider``: every credential header dropped and the real
    key put in the provider's header (appended, in lower case).

    None (``foreign_credential``) unless the request goes over HTTPS to port 443 (the real
    key never travels in clear), every header name is a plain HTTP token, and there is
    EXACTLY ONE credential header, the provider's, holding exactly its fake key: not
    another key, an OAuth token, a cookie, the fake key in another header, twice, or nothing.
    None too for a provider that waits for its key (fail closed: there is nothing to send).
    """
    if provider.real_key is None:
        return None
    kept = only_fake_key(provider, headers, scheme=scheme, port=port)
    if kept is None:
        return None
    return [*kept, (provider.header, provider._real_header_value())]


# T11 (docs/33): a model call refused by backtide's spending cap. Fixed texts (backtide never
# sends the proxy a text to show: a broken proxy must not become a way to inject one), in English
# and Spanish, without figures, windows or a ``retry-after``: the agent learns nothing of the
# owner's money, and a 429 without a hint is retried little (the provider's own spend limit
# answers the same way). OpenClaw shows the message to the person in its channel.
SPEND_MESSAGES = {
    "spend_cap": "backtide spending cap reached / tope de gasto de backtide alcanzado. "
    "Do not retry; ask the owner to raise it. / No reintentes; pide al dueño que lo suba.",
    "spend_unavailable": "backtide cannot count the spending right now, so model calls are "
    "refused / backtide no puede contar el gasto ahora, así que rechaza las llamadas al modelo.",
}
# A provider that waits for its key (docs/21, section 6): a 400 ``invalid_request_error``, which
# OpenClaw 2026.9.8 neither retries nor counts against its key (a 401 or 403 would put the
# agent's fake key on a cooldown of 30 s and up, so the first call after the owner sets the key
# would fail). OpenClaw also matches words of the message before the status: none of "api key",
# "authentication", "credentials", "unauthorized", "forbidden", "expired", "permission",
# "rate limit", "quota", "billing" or "credit" may appear in it.
NO_KEY_MESSAGE = (
    "backtide: no key set yet for {name}; the owner sets it in the Settings page of backtide. / "
    "backtide: aún no hay clave para {name}; el dueño la pone en la página Ajustes de backtide."
)
NO_KEY = "no_key"


def blocked_response(
    kind: str, reason: str, provider: str = "this model provider"
) -> tuple[int, bytes, dict[str, str]]:
    """(status, body, headers) of a refused model call, in the error shape of ``kind``'s API:
    Anthropic's ``rate_limit_error``, OpenAI's ``insufficient_quota``; for ``no_key`` (the
    provider ``provider`` waits for its key), a 400 ``invalid_request_error`` of either.
    ValueError otherwise."""
    message = SPEND_MESSAGES.get(reason)
    if reason == NO_KEY:
        if not isinstance(provider, str) or not provider.isprintable() or len(provider) > 64:
            raise ValueError("a provider name is a short text")
        message = NO_KEY_MESSAGE.format(name=provider)
    if message is None:
        raise ValueError("unknown model call refusal")
    if kind == Kind.ANTHROPIC:
        error_type = {"spend_cap": "rate_limit_error", NO_KEY: "invalid_request_error"}.get(
            reason, "api_error"
        )
        payload: dict[str, object] = {
            "type": "error",
            "error": {"type": error_type, "message": message},
        }
    elif kind == Kind.OPENAI:
        code = {"spend_cap": "insufficient_quota", NO_KEY: "backtide_no_key"}.get(
            reason, "service_unavailable"
        )
        error_type = "invalid_request_error" if reason == NO_KEY else code
        payload = {"error": {"message": message, "type": error_type, "code": code, "param": None}}
    else:
        raise ValueError("unknown provider kind")
    status = {"spend_cap": 429, NO_KEY: 400}.get(reason, 503)
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return status, body, {"content-type": "application/json", "x-backtide": reason}


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
    """The configured providers: no two share a name, a host or a key. Those waiting for their
    key (``real_key`` None) are here too: their host is a provider's host, and nothing goes
    there.

    ``strike_only``: real keys that are never swapped in (a key file that cannot be used, a key
    two providers share, a key just removed when the reload failed: review of T09b, finding 2).
    They are struck and searched for like the real keys (``known_secrets``, ``real_key_in``,
    ``keys_to_find``), and nothing else. ValueError for one too short to search for or that is
    (or holds, or is held in) a fake key."""

    def __init__(self, items: Iterable[Provider], strike_only: Iterable[str] = ()) -> None:
        self.items: tuple[Provider, ...] = tuple(items)
        names = [p.name for p in self.items]
        hosts = [p.host for p in self.items]
        keys = [*self._real_keys(), *(p.fake_key for p in self.items)]
        if len(set(names)) != len(names):
            raise ValueError("two providers have the same name")
        if len(set(hosts)) != len(hosts):
            raise ValueError("two providers have the same host")
        if len(set(keys)) != len(keys):
            raise ValueError("two providers share a key")
        if sum(1 for p in self.items if p.local) > MAX_LOCAL:
            raise ValueError(f"more than {MAX_LOCAL} local providers")
        struck = list(strike_only)
        if any(not isinstance(key, str) or len(key) < MIN_KNOWN_SECRET for key in struck):
            raise ValueError(f"a key to strike is a text of {MIN_KNOWN_SECRET}+ characters")
        fakes = [p.fake_key for p in self.items]
        if any(key in fake or fake in key for key in struck for fake in fakes):
            raise ValueError("a key to strike cannot be a fake key")
        real = set(self._real_keys())
        self.strike_only: tuple[str, ...] = tuple(
            key for key in dict.fromkeys(struck) if key not in real
        )
        self._by_host = {p.host: p for p in self.items}

    def __repr__(self) -> str:
        return f"Providers({', '.join(p.name for p in self.items)})"

    def _real_keys(self) -> list[str]:
        return [p.real_key.reveal() for p in self.items if p.real_key is not None]

    def waiting(self) -> tuple[str, ...]:
        """The names of the providers that wait for their key (never a local one)."""
        return tuple(p.name for p in self.items if p.waiting)

    def local_at(self, address: str, port: int) -> Provider | None:
        """The local provider whose upstream is exactly (``address``, ``port``), if any."""
        return next((p for p in self.items if p.local and p.upstream == (address, port)), None)

    def by_name(self, name: object) -> Provider | None:
        """The provider called ``name``, if any."""
        return next((p for p in self.items if p.name == name), None)

    def for_host(self, host: str) -> Provider | None:
        """The provider whose host is exactly ``host`` (the connection's), if any."""
        name = normalize_host(host)
        return self._by_host.get(name) if name else None

    def keys_to_find(self) -> tuple[str, ...]:
        """The real keys and those to strike only: what must never leave, nor come back in an
        answer (``real_key``)."""
        return (*self._real_keys(), *self.strike_only)

    def real_key_in(self, *parts: str | bytes | None) -> bool:
        """Whether any real key (or one to strike only) shows in any of ``parts`` (the URL,
        each header name and value, the body, a WebSocket message). Checked for every request,
        to any host."""
        real = self.keys_to_find()
        return any(contains_secret(part, real) for part in parts)

    def known_secrets(self) -> tuple[str, ...]:
        """Every real key, key to strike only and fake key, for ``scrub_known`` before
        anything is recorded."""
        return (*self.keys_to_find(), *(p.fake_key for p in self.items))
