"""What keeps a local web page from being a door.

A page on 127.0.0.1 is still reachable by every web page the browser has open, and by every other
program on this machine that listens on a port of its own (cookies ignore ports), so:

- ``Guard`` (an ASGI middleware, OUTSIDE everything, so even a 500 carries the headers):
  * the ``Host`` header must be exactly ``127.0.0.1:<port>`` (not ``localhost``: that name can
    also resolve to ``::1``, where another program may be listening): a page on ``evil.example``
    that re-points its name at 127.0.0.1 (DNS rebinding) arrives with ITS name in ``Host``;
  * only GET, except ONE path: ``POST /instantaneas/rebobinar`` (T12b), the only request that
    changes anything. A POST anywhere else, and any other method, is a 405;
  * that POST must come from our own page: exactly one ``Origin``, ours (every browser sends it
    on a POST), ``Sec-Fetch-Site: same-origin`` when the browser sends it (anything else, even
    ``none``, is refused), a plain form body (``application/x-www-form-urlencoded``: no
    ``text/plain`` or multipart tricks) with a ``Content-Length`` of at most ``MAX_FORM_BYTES``
    (no chunked bodies). Behind that the app still wants the session cookie (never the link
    token), the session's CSRF token from the form, and a one-time confirmation ticket for that
    very snapshot (``backtide.web.rewind.Tickets``);
  * a browser ``Origin`` that is not ours is refused, and so is any request the browser says is
    ``same-site`` or ``cross-site`` unless it is a top-level navigation (``Sec-Fetch-Mode:
    navigate``): the stream and the fragments are only ever fetched from our own pages;
  * the whole app lives under a random per-run prefix, ``/s/<random>/``: anything else is a
    bare 404, so a squatter or a page that guesses ``/ahora`` finds nothing;
  * every response, errors included, carries the headers below.
- ``Access``: the link carries a one-time token. The first request that uses it gets a session
  secret (a different random value) in an HttpOnly, SameSite=Strict cookie whose Path is the
  prefix, and the token stops working. A copy of the link in the shell history or the terminal
  scrollback is then worth nothing. The session also has a CSRF token (another random value),
  which only our pages carry, in the rewind's confirmation form. Since T12b a web that runs as
  the service's user can rewind, so a stolen, unspent link is worth a rewind too, not only a
  look: it is printed once, and nothing else may read the terminal it is printed in.
- What this does NOT stop: another program on this machine can set cookies for 127.0.0.1 (cookies
  ignore ports) with ``Path=/``, enough of them to make every request too big to be served.
  That is a denial of service of the web, not a way in: the session check reads every
  ``backtide_web`` cookie and needs ours, which that program does not know. The CLI still works.
- ``Referrer-Policy: same-origin`` (not ``no-referrer``): with ``no-referrer`` a browser sends
  ``Origin: null`` on the confirmation's plain form POST (no JavaScript), which the POST check
  refuses, as it refuses ``null`` everywhere. The pages link to no other site, so a ``Referer``
  only ever travels back to us.
- ``CSP``: scripts, styles, fonts and images only from this origin, no inline anything, no
  frames, no form posts elsewhere. HTMX is vendored for this reason.
"""

import hmac
import secrets
import threading
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

TOKEN_BYTES = 32
COOKIE_NAME = "backtide_web"
LANG_COOKIE = "backtide_lang"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CSP.encode()),
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    (b"cache-control", b"no-store"),
)
ALLOWED_METHODS = frozenset({"GET"})
# The one path that takes a POST (under the prefix), and how big its form may be.
POST_PATH = "/instantaneas/rebobinar"
MAX_FORM_BYTES = 2048
FORM_TYPE = "application/x-www-form-urlencoded"


RUN_WORDS = (
    "marea", "faro", "nube", "ola", "roca", "bruma", "cala", "isla", "vela", "sal", "arena",
    "gaviota", "ancla", "boya", "puerto", "brisa", "coral", "delta", "duna", "estrella",
    "bahia", "ceniza", "lluvia", "norte", "pino", "rio", "sol", "trigo", "viento", "luna",
    "musgo", "nieve",
)  # fmt: skip


def make_token() -> str:
    """A new random link token (256 bits): good for one request, then dead."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def make_prefix() -> str:
    """The random path segment the whole app lives under (128 bits)."""
    return secrets.token_urlsafe(16)


def make_run_name() -> str:
    """Three random words naming this run, shown on the page and printed in the terminal. It is
    NOT derived from the token or the prefix: a program that squats the port cannot know it,
    so the founder can tell the real page from an impostor by comparing the two."""
    return "-".join(secrets.choice(RUN_WORDS) for _ in range(3))


def token_matches(given: str | None, expected: str) -> bool:
    """Constant-time comparison; a missing value never matches."""
    if not given:
        return False
    return hmac.compare_digest(given.encode(), expected.encode())


class Access:
    """The link token (single use) and the session secret it is exchanged for. The secret
    exists from the start but nobody knows it until the link is used: it is only ever sent as
    the ``Set-Cookie`` of the response to the one request that presented the token."""

    def __init__(self, token: str, session: str | None = None) -> None:
        self._token: str | None = token
        self._session = session or secrets.token_urlsafe(TOKEN_BYTES)
        # The form token of the session (T12b): in the pages, never in a cookie or a link.
        self.csrf = secrets.token_urlsafe(TOKEN_BYTES)
        self._lock = threading.Lock()

    def use_link(self, given: str) -> str | None:
        """The session secret if ``given`` is the link token and it was not used yet; the link
        is then dead, whoever asks next (two requests with it at once: only one wins)."""
        with self._lock:
            if self._token is None or not token_matches(given, self._token):
                return None
            self._token = None
            return self._session

    def session_is(self, given: str | None) -> bool:
        return token_matches(given, self._session)

    def csrf_is(self, given: str | None) -> bool:
        return token_matches(given, self.csrf)

    def session_in(self, cookie_header: str | None) -> bool:
        """Is our session among the cookies of this ``Cookie`` header? Cookies ignore ports, so
        a stale ``backtide_web`` of another run (or version) on 127.0.0.1 can travel with ours,
        and a parser that keeps only one of two equal names would pick the wrong one."""
        for part in (cookie_header or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME and self.session_is(value.strip('"')):
                return True
        return False


def allowed_hosts(port: int) -> frozenset[str]:
    return frozenset({f"127.0.0.1:{port}"})


def allowed_origins(port: int) -> frozenset[str]:
    return frozenset({f"http://127.0.0.1:{port}"})


class Guard:
    """Pure ASGI middleware, outside the app: the Host, method, Origin and Sec-Fetch checks, the
    prefix, and the security headers on every response. It does not touch the body, so streaming
    (SSE) passes through untouched. ``inner`` is the app it guards, ``base`` the prefix path."""

    def __init__(self, app: App, *, port: int, prefix: str) -> None:
        self.inner = app
        self.base = f"/s/{prefix}"
        self._hosts = allowed_hosts(port)
        self._origins = allowed_origins(port)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.inner(scope, receive, send)
            return
        if scope["type"] != "http":  # no websockets here
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        refusal = self._refusal(scope)
        if refusal is not None:
            status, text, extra = refusal
            await self._respond(send, status, text, extra)
            return
        # The app sees its own paths, without the prefix; it learns the prefix from the scope.
        path = scope["path"]
        inside = path[len(self.base) :] or "/"
        scope = {**scope, "path": inside, "backtide.base": self.base}
        if "raw_path" in scope and scope["raw_path"] is not None:
            scope["raw_path"] = inside.encode()

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                names = {name for name, _ in message.get("headers", [])}
                extra = [(n, v) for n, v in SECURITY_HEADERS if n not in names]
                message = {**message, "headers": [*message.get("headers", []), *extra]}
            await send(message)

        await self.inner(scope, receive, with_headers)

    def _refusal(self, scope: Scope) -> tuple[int, str, list[tuple[bytes, bytes]]] | None:
        headers = scope["headers"]
        hosts = [v for k, v in headers if k == b"host"]
        if len(hosts) != 1 or hosts[0].decode("latin-1").lower() not in self._hosts:
            return 400, "Host not allowed", []
        if scope["method"] == "POST" and token_matches(scope["path"], self.base + POST_PATH):
            refusal = self._post_refusal(headers)
            if refusal is not None:
                return refusal
        elif scope["method"] not in ALLOWED_METHODS:
            return 405, "Read-only", [(b"allow", b"GET")]
        origins = [v for k, v in headers if k == b"origin"]
        if origins and (len(origins) != 1 or origins[0].decode("latin-1") not in self._origins):
            return 403, "Origin not allowed", []
        site = next((v for k, v in headers if k == b"sec-fetch-site"), b"").decode("latin-1")
        mode = next((v for k, v in headers if k == b"sec-fetch-mode"), b"").decode("latin-1")
        if site.lower() in {"same-site", "cross-site"} and mode.lower() != "navigate":
            return 403, "Cross-site request", []
        if not self._under_prefix(scope["path"]):
            return 404, "Not found", []
        return None

    def _post_refusal(
        self, headers: list[tuple[bytes, bytes]]
    ) -> tuple[int, str, list[tuple[bytes, bytes]]] | None:
        """The rewind's POST: from our own page, a small plain form, or nothing."""

        def values(name: bytes) -> list[str]:
            return [v.decode("latin-1") for k, v in headers if k == name]

        origins = values(b"origin")
        if len(origins) != 1 or origins[0] not in self._origins:
            return 403, "A change needs our own Origin", []
        sites = values(b"sec-fetch-site")
        if len(sites) > 1 or (sites and sites[0].lower() != "same-origin"):
            return 403, "Cross-site request", []
        types = values(b"content-type")
        if len(types) != 1 or types[0].split(";")[0].strip().lower() != FORM_TYPE:
            return 415, "Only a plain form", []
        if values(b"transfer-encoding"):
            return 411, "Length required", []
        lengths = values(b"content-length")
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            return 411, "Length required", []
        if len(lengths[0]) > 6 or int(lengths[0]) > MAX_FORM_BYTES:
            return 413, "Too large", []
        return None

    def _under_prefix(self, path: str) -> bool:
        """Is ``path`` the prefix itself or something below it? Compared in constant time."""
        head = path[: len(self.base)]
        if not token_matches(head, self.base) or len(head) != len(self.base):
            return False
        return len(path) == len(self.base) or path[len(self.base)] == "/"

    @staticmethod
    async def _respond(
        send: Send, status: int, text: str, extra: list[tuple[bytes, bytes]]
    ) -> None:
        body = text.encode()
        headers = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
            *extra,
            *SECURITY_HEADERS,
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
