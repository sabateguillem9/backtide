"""A small client of the Telegram Bot API over HTTPS, with the standard library only (T09).

- One method: ``call(method, params)`` POSTs JSON to ``<base>/bot<token>/<method>`` and returns
  the ``result`` of a reply whose ``ok`` is true. Everything else raises ``TelegramError``.
- **The token never leaves this object in the clear.** It goes in the URL path (that is how the
  Bot API works), so no error, log or exception text here carries the URL: every message is
  built by us, and whatever comes from outside (the API's ``description``, a socket error) has
  the token replaced and is redacted before it is kept. Exceptions are raised ``from None``, so
  a traceback never shows urllib's own (whose ``HTTPError`` holds the URL).
- No redirects (a 3xx is an error: a redirect to another host would carry the token there) and
  no proxy from the environment (``HTTPS_PROXY`` would see the token too). TLS is verified with
  the system's certificates.
- The base URL must be ``https://``, or ``http://`` on this machine's loopback, which is what the
  tests' fake Bot API uses (``api_base`` in ``telegram.toml``). It is checked when the settings
  are read (``backtide.service.telegram_config``) and again here.
- Replies are read up to 1 MiB: a server that sends more is not believed.
"""

import http.client
import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from backtide.blackbox import redact

DEFAULT_API_BASE = "https://api.telegram.org"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
MAX_REPLY_BYTES = 1 << 20
REQUEST_TIMEOUT = 15.0  # seconds; getUpdates adds its own long-poll time to this
MAX_DESCRIPTION_CHARS = 200


class TelegramError(Exception):
    """A call failed. The message is ours and never holds the token. ``status`` is the HTTP
    status (0 for a network error), ``retry_after`` the seconds Telegram asked to wait (429),
    and ``unauthorized`` says the token was refused (401 or 404, which is what a wrong token
    gets)."""

    def __init__(self, message: str, *, status: int = 0, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after

    @property
    def unauthorized(self) -> bool:
        return self.status in (401, 404)

    @property
    def conflict(self) -> bool:
        """409: another poller or a webhook is set for this bot."""
        return self.status == 409


def check_api_base(base: str) -> str:
    """``base`` without a trailing slash, if it is ``https://host[:port]`` or loopback
    ``http://``. Raises ValueError (with ``base`` in it: a base URL holds no secret) otherwise."""
    if not isinstance(base, str) or not base:
        raise ValueError("api_base must be a URL")
    parts = urlsplit(base)
    host = parts.hostname or ""
    if parts.scheme == "http" and host not in LOOPBACK_HOSTS:
        raise ValueError(f"api_base {base!r}: plain http only on this machine (127.0.0.1)")
    if parts.scheme not in ("https", "http"):
        raise ValueError(f"api_base {base!r} must be https://")
    if not host or parts.username or parts.password:
        raise ValueError(f"api_base {base!r} must be scheme://host[:port], without a user")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(f"api_base {base!r} must not have a path, a query or a fragment")
    try:
        parts.port  # noqa: B018 - raises ValueError for a port that is not a number
    except ValueError:
        raise ValueError(f"api_base {base!r} has an invalid port") from None
    return base.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a 3xx reaches the caller as an HTTPError


class BotApi:
    """The Bot API of one bot. Thread-safe: every call opens its own connection."""

    def __init__(self, token: str, *, base: str = DEFAULT_API_BASE) -> None:
        if (
            not isinstance(token, str)
            or not token
            or "/" in token
            or any(c.isspace() for c in token)
        ):
            raise ValueError("the bot token is empty or has characters a token never has")
        self._token = token
        self._base = check_api_base(base)
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        ]
        if self._base.startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        return f"BotApi(base={self._base!r}, token=[REDACTED])"

    def scrub(self, text: str) -> str:
        """``text`` with this bot's token (and any other secret ``redact`` knows) taken out."""
        return redact(str(text).replace(self._token, "[REDACTED]"))

    def call(
        self, method: str, params: dict[str, Any] | None = None, *, timeout: float = REQUEST_TIMEOUT
    ) -> Any:
        """POST ``params`` as JSON to ``method`` and return the reply's ``result``."""
        if not method.isalnum():
            raise ValueError(f"not a Bot API method: {method!r}")
        body = json.dumps(params or {}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked in __init__
            f"{self._base}/bot{self._token}/{method}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = response.status
                raw = response.read(MAX_REPLY_BYTES + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            try:
                raw = error.read(MAX_REPLY_BYTES + 1)
            except (OSError, http.client.HTTPException):
                raw = b""
            finally:
                error.close()
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as error:
            raise TelegramError(f"{method}: {self._network_reason(error)}") from None
        return self._result(method, status, raw)

    def _network_reason(self, error: Exception) -> str:
        if isinstance(error, TimeoutError | socket.timeout):
            return "no answer in time"
        reason = getattr(error, "reason", None)
        text = f"{type(error).__name__}: {reason if reason is not None else error}"
        return self.scrub(text)[:MAX_DESCRIPTION_CHARS]

    def _result(self, method: str, status: int, raw: bytes) -> Any:
        if len(raw) > MAX_REPLY_BYTES:
            raise TelegramError(f"{method}: the reply is too big", status=status)
        try:
            reply = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            reply = None
        if not isinstance(reply, dict):
            raise TelegramError(f"{method}: HTTP {status}, not a Bot API reply", status=status)
        if reply.get("ok") is True and status == 200:
            return reply.get("result")
        description = reply.get("description")
        text = (
            self.scrub(description)[:MAX_DESCRIPTION_CHARS] if isinstance(description, str) else ""
        )
        parameters = reply.get("parameters")
        retry_after = None
        if isinstance(parameters, dict) and isinstance(parameters.get("retry_after"), int | float):
            retry_after = float(parameters["retry_after"])
        code = reply.get("error_code")
        status = code if isinstance(code, int) and not isinstance(code, bool) else status
        raise TelegramError(
            f"{method}: HTTP {status}" + (f" ({text})" if text else ""),
            status=status,
            retry_after=retry_after,
        )
