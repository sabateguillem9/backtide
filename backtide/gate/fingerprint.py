"""The exact fingerprint of a request: what one "yes" is good for. Pure: no I/O.

Design: docs/32-diseno-t10-puerta.md, section 7 (and "Resultados de T10-2": the headers count).

    fp = HMAC-SHA256(key, "backtide-fp-v2" | method | host:port | path with its query |
                          SHA-256(headers) | SHA-256(trailers) | SHA-256(decoded body))

- **Every field is length-prefixed** (8 bytes, big-endian), so no field can be shifted into the
  next one to make two different requests collide; inside the headers, every name and every
  value is too.
- The method and the path (with its query) are taken exactly as they were sent. The host is the
  connection's (never the ``Host`` header), normalized as the gate compares hosts.
- **Every header counts but VOLATILE ones** (security review of T10-2, M2): a header can change
  what the server does (``X-HTTP-Method-Override: DELETE``, WebDAV's ``Destination``, Dropbox's
  ``Dropbox-API-Arg``) or whose account it is done as (``Authorization``, ``Cookie``, but also
  ``PRIVATE-TOKEN`` or ``X-Auth-Token``), so a yes for one request must not ride on another that
  only differs there. Names are compared in lower case and in any order; the values of a name
  that is repeated keep their order (``a`` then ``b`` is not ``b`` then ``a``, nor ``a, b``).
  The trailers are hashed the same way, apart.
- **The key** is 32 random bytes per channel connection (backtide makes it and sends it in the
  ``config`` message). It lives only in memory, so a stored fingerprint cannot be used to guess
  what was behind it, and a restart makes every old fingerprint worthless. The black box keeps
  only ``short(fp)``, to join events.
- **The semantic hook** (decision 2, T10-3): a translator that understands a request hands its
  canonical bytes (``Reading.canonical``: account, every recipient, subject, the whole text, each
  attachment's name and hash) and they replace the raw body, under another tag. Then a repeated
  e-mail whose MIME has a new ``Date`` and ``Message-ID`` is still the same request, and a
  semantic fingerprint is never equal to an exact one. The headers still count.

Imports only the standard library and backtide.gate (it runs in the proxy).
"""

import hashlib
import hmac
import secrets
from collections.abc import Iterable

from backtide.gate.policy import normalize_host

KEY_BYTES = 32
SHORT = 16  # characters of a fingerprint kept in the black box
_EXACT = b"backtide-fp-v2"
_SEMANTIC = b"backtide-fp-v2-semantic"
# Headers that do not count: each one either says nothing to the server about what to do or as
# whom (it changes with every attempt or every client version, and the same request sent again
# must stay the same request), or it only frames the message, whose bytes count already.
VOLATILE_HEADERS = frozenset(
    {
        # Hop by hop (RFC 9110, section 7.6.1): the connection, never the request. The body is
        # hashed decoded, so how it was framed (Content-Length or chunked) does not count.
        "connection", "keep-alive", "proxy-connection", "te", "transfer-encoding",
        "content-length",
        # The body is hashed as the server reads it once decoded (the gate only lets out a
        # Content-Encoding it decoded itself: identity, gzip or deflate).
        "content-encoding",
        # What the answer may look like; nothing about what is done.
        "accept-encoding",
        # Who the client is and when it asked: another version or another second, the same
        # request. A retry counter (Stainless' SDKs) too.
        "user-agent", "date", "x-stainless-retry-count",
        # Tracing ids: new for every attempt (W3C Trace Context, B3, AWS, Sentry).
        "traceparent", "tracestate", "baggage", "x-request-id", "x-correlation-id",
        "x-amzn-trace-id", "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled",
        "b3", "sentry-trace",
    }
)  # fmt: skip


def new_key() -> bytes:
    """A fresh fingerprint key (one per channel connection)."""
    return secrets.token_bytes(KEY_BYTES)


def _field(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def _text(value: str) -> bytes:
    return value.encode("utf-8", "surrogateescape")


def fingerprint(
    key: bytes,
    *,
    method: str,
    host: str,
    port: int,
    path: str,
    headers: Iterable[tuple[str, str]],
    body: bytes | None,
    trailers: Iterable[tuple[str, str]] = (),
    canonical: bytes | None = None,
) -> str:
    """The fingerprint of a request, 64 hex characters. ``headers`` and ``trailers`` are the
    request's own (every one counts but VOLATILE_HEADERS); ``body`` the decoded one.
    ``canonical``: a translator's canonical bytes, in place of the body (T10-3). ValueError for
    a key that is not KEY_BYTES long."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("a fingerprint key is 32 bytes")
    if canonical is not None:
        tag, content = _SEMANTIC, canonical
    else:
        tag, content = _EXACT, body or b""
    name = normalize_host(host) or str(host)
    message = b"".join(
        _field(part)
        for part in (
            tag,
            _text(method),
            _text(f"{name}:{port}"),
            _text(path),
            _headers_digest(headers),
            _headers_digest(trailers),
            hashlib.sha256(content).digest(),
        )
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _headers_digest(pairs: Iterable[tuple[str, str]]) -> bytes:
    """SHA-256 of the headers that count: by lower-case name, names sorted, each name's values
    in the order they came."""
    values: dict[str, list[str]] = {}
    for name, value in pairs:
        lowered = str(name).strip().lower()
        if lowered not in VOLATILE_HEADERS:
            values.setdefault(lowered, []).append(str(value))
    digest = hashlib.sha256()
    for lowered in sorted(values):
        digest.update(_field(_text(lowered)) + _field(len(values[lowered]).to_bytes(8, "big")))
        for value in values[lowered]:
            digest.update(_field(_text(value)))
    return digest.digest()


def short(fp: str) -> str:
    """What the black box keeps of a fingerprint (ValueError if it is not one)."""
    if not is_fingerprint(fp):
        raise ValueError("not a fingerprint")
    return fp[:SHORT]


def is_fingerprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )
