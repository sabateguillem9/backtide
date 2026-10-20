"""The exact fingerprint of a request: what one "yes" is good for. Pure: no I/O.

Design: docs/32-diseno-t10-puerta.md, section 7.

    fp = HMAC-SHA256(key, "backtide-fp-v1" | method | host:port | path with its query |
                          Content-Type | SHA-256(credential headers) | SHA-256(decoded body))

- **Every field is length-prefixed** (8 bytes, big-endian), so no field can be shifted into the
  next one to make two different requests collide.
- The method and the path (with its query) are taken exactly as they were sent. The host is the
  connection's (never the ``Host`` header), normalized as the gate compares hosts.
- ``Content-Type`` counts: the same bytes as JSON or as a form are another request. So do the
  credential headers (``providers.CREDENTIAL_HEADERS``): the same message with another token
  leaves from another account (Slack's token is in ``Authorization``, not in the path).
- **The key** is 32 random bytes per channel connection (backtide makes it and sends it in the
  ``config`` message). It lives only in memory, so a stored fingerprint cannot be used to guess
  what was behind it, and a restart makes every old fingerprint worthless. The black box keeps
  only ``short(fp)``, to join events.
- **The semantic hook** (decision 2, T10-3): a translator that understands a request hands its
  canonical bytes (``Reading.canonical``: account, every recipient, subject, the whole text, each
  attachment's name and hash) and they replace the raw body, under another tag. Then a repeated
  e-mail whose MIME has a new ``Date`` and ``Message-ID`` is still the same request, and a
  semantic fingerprint is never equal to an exact one.

Imports only the standard library and backtide.gate (it runs in the proxy).
"""

import hashlib
import hmac
import secrets
from collections.abc import Iterable

from backtide.gate.policy import normalize_host
from backtide.gate.providers import CREDENTIAL_HEADERS

KEY_BYTES = 32
SHORT = 16  # characters of a fingerprint kept in the black box
_EXACT = b"backtide-fp-v1"
_SEMANTIC = b"backtide-fp-v1-semantic"


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
    canonical: bytes | None = None,
) -> str:
    """The fingerprint of a request, 64 hex characters. ``headers`` are the request's own, in
    order (only ``Content-Type`` and the credential headers are read); ``body`` the decoded one.
    ``canonical``: a translator's canonical bytes, in place of the body (T10-3). ValueError for
    a key that is not KEY_BYTES long."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("a fingerprint key is 32 bytes")
    pairs = [(str(name), str(value)) for name, value in headers]
    content_type = b"\x00".join(_text(v) for n, v in pairs if n.strip().lower() == "content-type")
    credentials = hashlib.sha256()
    for name, value in pairs:
        lowered = name.strip().lower()
        if lowered in CREDENTIAL_HEADERS:
            credentials.update(_field(_text(lowered)) + _field(_text(value)))
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
            content_type,
            credentials.digest(),
            hashlib.sha256(content).digest(),
        )
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


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
