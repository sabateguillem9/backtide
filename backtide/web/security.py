"""What keeps a local web page from being a door.

A page on 127.0.0.1 is still reachable by every web page the browser has open, and by every other
program on this machine that listens on a port of its own (cookies ignore ports), so:

- ``Guard`` (an ASGI middleware, OUTSIDE everything, so even a 500 carries the headers):
  * the ``Host`` header must be exactly ``127.0.0.1:<port>`` (not ``localhost``: that name can
    also resolve to ``::1``, where another program may be listening), or ``backtide.localhost:
    <port>`` (T26-3b-2: a passkey cannot belong to an address; Chrome, Edge and Firefox keep
    ``*.localhost`` on this machine, but try ``[::1]`` first, so the web holds ``[::1]:<port>``
    too, ``backtide.web.server.bind_both``): a page on ``evil.example`` that re-points its name
    at 127.0.0.1 (DNS rebinding) arrives with ITS name in ``Host``. Each name's pages send their
    own ``Origin``, and only that one is taken with it;
  * only GET, except the paths that change something: ``POST /instantaneas/rebobinar`` (T12b);
    only when `backtide web --ajustes` turned the Settings page on, ``POST /ajustes/guardar``
    (T12e: a key set or removed); and only with `backtide web --aprobar`, ``POST
    /peticiones/decidir`` (T10-5: approve, reject, "aprobar y confiar", revoke a batch, take a
    trusted recipient out); and always ``POST /salir`` and ``POST /ajustes/cerrar-sesiones``
    (T26-3a-2: sign out, close every session), which only end sessions. A POST anywhere else,
    and any other method, is a 405, so without ``--ajustes`` or ``--aprobar`` there is no door
    that changes anything;
  * every such POST must come from our own page: exactly one ``Origin``, ours (every browser
    sends it on a POST), ``Sec-Fetch-Site: same-origin`` when the browser sends it (anything
    else, even ``none``, is refused), a plain form body (``application/x-www-form-urlencoded``: no
    ``text/plain`` or multipart tricks) with a ``Content-Length`` of at most ``MAX_FORM_BYTES``
    (no chunked bodies). Behind that the app still wants the session cookie (never the link
    token), the session's CSRF token from the form, and a one-time confirmation ticket for that
    very snapshot (``backtide.web.rewind.Tickets``), that very change of that very key
    (``backtide.web.settings.SettingTickets``) or that very decision on that very hold, batch or
    recipient (``backtide.web.approve.DecisionTickets``);
  * a browser ``Origin`` that is not ours is refused, and so is any request the browser says is
    ``same-site`` or ``cross-site`` unless it is a top-level navigation (``Sec-Fetch-Mode:
    navigate``): the stream and the fragments are only ever fetched from our own pages;
  * the whole app lives under a random per-run prefix, ``/s/<random>/``: anything else is a
    bare 404, so a squatter or a page that guesses ``/ahora`` finds nothing;
  * every response, errors included, carries the headers below.
- ``Access``: the link carries a one-time token. The first request that uses it gets a NEW
  session id (another random value, never one that existed before) in an HttpOnly,
  SameSite=Strict cookie whose Path is the prefix, and the token stops working. A copy of the
  link in the shell history or the terminal scrollback is then worth nothing. Each session has
  its own CSRF token (another random value), which only our pages carry, in the forms. A
  session dies after an hour unused or twelve in all (``backtide.service.sessions``, T26-3a).
  Who keeps them: the installed web asks the service (``ServiceAccess``, over its narrow
  socket), which also wants the session on every change (``ACTING_SESSION``), so a web taken
  over can change nothing on its own; ``backtide web`` without that socket and the Mac's demo
  keep their own (``LocalAccess``), with the same rules. A stolen, unspent link is worth a
  rewind, not only a look: it is printed once (or given by `sudo backtide enlace`), and
  nothing else may read where it is printed.
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
import logging
import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Protocol

from backtide.service.control import ControlError, PeerCredentials, peer_credentials
from backtide.service.sessions import Session, Sessions
from backtide.service.web_control import (
    ask_auth,
    ask_passkey,
    ask_session_check,
    ask_session_end,
    ask_session_open,
    ask_session_password,
)

logger = logging.getLogger(__name__)

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
# The paths that take a POST (under the prefix), and how big their form may be. The Settings
# page's is only taken when it is on (``Guard(post_paths=...)``).
POST_PATH = "/instantaneas/rebobinar"
SETTINGS_PATH = "/ajustes"
SETTINGS_POST_PATH = "/ajustes/guardar"
# The held requests (T10-5): their page, and the POST that decides, only with --aprobar.
HOLDS_PATH = "/peticiones"
DECIDE_PATH = "/peticiones/decidir"
# Signing out and closing every session (T26-3a-2): always there, each with the session's CSRF.
KEYS_PATH = "/llaves"  # the passkeys (T26-3b-2): the page, then its two POSTs
KEYS_BEGIN_PATH = "/llaves/empezar"
KEYS_FINISH_PATH = "/llaves/registrar"  # the one path that takes a large form (the answer)
SIGN_IN_PATH = "/entrar"  # the web's password (T26-3b-1): no session yet, our own Origin
SIGN_IN_KEY_BEGIN_PATH = "/entrar/llave/empezar"  # with a passkey (T26-3c): the same, two POSTs
SIGN_IN_KEY_FINISH_PATH = "/entrar/llave/responder"
TOUCH_PATH = "/tocar"  # touching the key again (T26-3c): the page, then its two POSTs
TOUCH_BEGIN_PATH = "/tocar/empezar"
TOUCH_FINISH_PATH = "/tocar/responder"
SIGN_OUT_PATH = "/salir"
CLOSE_SESSIONS_PATH = "/ajustes/cerrar-sesiones"
CLOSE_SESSIONS_WORD = "cerrar-todas"  # typed in the form: the confirmation
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


MAX_COOKIES = 4  # how many of our cookies a request may carry that are looked at

# The session of the person whose request is being served, for the change it asks (T26-3a): the
# app sets it from the cookie before it calls a client, and the clients of the narrow socket send
# it. Unset, nothing is sent and the service refuses the change: it fails closed.
ACTING_SESSION: ContextVar[str | None] = ContextVar("backtide_acting_session", default=None)


def acting_session(server_uid: int | None) -> str | None:
    """The session to send with a change: only to the narrow socket (``server_uid`` set), whose
    every change wants it; the control socket takes no such field."""
    return ACTING_SESSION.get() if server_uid is not None else None


def cookie_values(cookie_header: str | None) -> list[str]:
    """Our cookie's values in this ``Cookie`` header, at most ``MAX_COOKIES``. Cookies ignore
    ports, so a stale ``backtide_web`` of another run (or version) on 127.0.0.1 can travel with
    ours, and a parser that keeps only one of two equal names would pick the wrong one."""
    found = []
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE_NAME and value.strip('"'):
            found.append(value.strip('"'))
    return found[:MAX_COOKIES]


class Access(Protocol):
    """Who is signed in: the link traded for a session, and the session of a cookie."""

    def open(self, token: str) -> Session | None:
        """A new session for the link's token, or None (wrong, spent or too old)."""

    def sign_in(self, password: str) -> tuple[Session | None, str]:
        """A new session for the web's password (T26-3b-1), and why not: "opened", "wrong",
        "slow_down", "locked", "unset" or "refused"."""

    def auth(self, command: str, **fields: str) -> dict[str, Any]:
        """Signing in with a passkey (T26-3c): the service's reply."""

    def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
        """The live session among this header's cookies, or None; with ``use`` it counts as
        used (a page's own stream checks without it)."""

    def end(self, session_id: str, *, every: bool = False) -> bool | None:
        """End this session, or every one (asked from this live one): True if ended, False if
        it was not a live one, None if the service could not be asked or would not say (then
        nobody may assume it ended)."""


class LocalAccess:
    """The sessions in this process: ``backtide web`` without the narrow socket, and the demo."""

    passwords = False  # only its link

    def __init__(self, sessions: Sessions) -> None:
        self.sessions = sessions

    def open(self, token: str) -> Session | None:
        return self.sessions.open(token)

    def sign_in(self, password: str) -> tuple[Session | None, str]:
        return None, "unset"  # a web of its own has no password: only its link

    def auth(self, command: str, **fields: str) -> dict[str, Any]:
        return {"ok": False, "outcome": "refused", "message": "Solo en la web instalada."}

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        return {"ok": False, "outcome": "refused", "message": "Solo en la web instalada."}

    def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
        for value in cookie_values(cookie_header):
            session = self.sessions.check(value, use=use)
            if session is not None:
                return session
        return None

    def end(self, session_id: str, *, every: bool = False) -> bool:
        if every:
            if self.sessions.check(session_id) is None:
                return False
            self.sessions.end_all()
            return True
        return self.sessions.end(session_id)


class ServiceAccess:
    """The sessions the service keeps (the installed web, T26-3a): asked over the narrow socket
    at ``path``, whose server must be ``server_uid``. If the service cannot be asked, nobody is
    signed in: it fails closed, and says so in the log."""

    passwords = True  # the web's password (T26-3b-1), checked by the service

    def __init__(
        self,
        path: Path,
        *,
        server_uid: int,
        wait: float = 2.0,
        peer: PeerCredentials = peer_credentials,
    ) -> None:
        self._path = Path(path)
        self._server_uid = server_uid
        self._wait = wait
        self._peer = peer

    def _ask(self) -> dict[str, Any]:
        return {"server_uid": self._server_uid, "wait": self._wait, "peer": self._peer}

    def open(self, token: str) -> Session | None:
        try:
            return ask_session_open(self._path, token, **self._ask())
        except ControlError as error:
            logger.error("the service could not open a session: %s", error)
            return None

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        """A passkey command for this session (T26-3b-2): the service's reply, or a refusal of
        our own if it cannot be asked."""
        try:
            return ask_passkey(self._path, command, session_id, **fields, **self._ask())
        except ControlError as error:
            logger.error("the service could not be asked about the passkeys: %s", error)
            return {
                "ok": False,
                "outcome": "refused",
                "message": "Ahora no se puede: prueba otra vez.",
            }

    def auth(self, command: str, **fields: str) -> dict[str, Any]:
        """Signing in with a passkey (T26-3c): the service's reply, or a refusal of our own if
        it cannot be asked."""
        try:
            return ask_auth(self._path, command, **fields, **self._ask())
        except ControlError as error:
            logger.error("the service could not be asked about a sign-in: %s", error)
            return {
                "ok": False,
                "outcome": "refused",
                "message": "Ahora no se puede: prueba otra vez.",
            }

    def sign_in(self, password: str) -> tuple[Session | None, str]:
        try:
            return ask_session_password(self._path, password, **self._ask())
        except ControlError as error:
            logger.error("the service could not check the password: %s", error)
            return None, "refused"

    def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
        for value in cookie_values(cookie_header):
            try:
                session = ask_session_check(self._path, value, use=use, **self._ask())
            except ControlError as error:
                logger.error("the service could not check a session: %s", error)
                return None
            if session is not None:
                return session
        return None

    def end(self, session_id: str, *, every: bool = False) -> bool | None:
        try:
            outcome = ask_session_end(self._path, session_id, every=every, **self._ask())
        except ControlError as error:
            logger.error("the service could not end a session: %s", error)
            return None
        return {"ended": True, "expired": False}.get(outcome)


PASSKEY_HOST = "backtide.localhost"  # the passkeys' relying party (backtide.service.passkeys)
MAX_LARGE_FORM_BYTES = 8192  # a passkey's answer, on its own path only


def allowed_hosts(port: int) -> frozenset[str]:
    return frozenset({f"127.0.0.1:{port}", f"{PASSKEY_HOST}:{port}"})


class Guard:
    """Pure ASGI middleware, outside the app: the Host, method, Origin and Sec-Fetch checks, the
    prefix, and the security headers on every response. It does not touch the body, so streaming
    (SSE) passes through untouched. ``inner`` is the app it guards, ``base`` the prefix path.
    ``post_paths`` are the paths that take a POST: the rewind's, and the Settings page's only
    when it is on."""

    def __init__(
        self,
        app: App,
        *,
        port: int,
        prefix: str,
        post_paths: tuple[str, ...] = (POST_PATH,),
        large_post_paths: tuple[str, ...] = (),
    ) -> None:
        self.inner = app
        self.base = f"/s/{prefix}"
        self._post_paths = tuple(self.base + path for path in (*post_paths, *large_post_paths))
        # A passkey's answer is bigger than any other form: only its path takes up to 8 KiB.
        self._large_paths = tuple(self.base + path for path in large_post_paths)
        self._hosts = allowed_hosts(port)

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
        # The one Origin a page of ours sends is the name it was opened by: 127.0.0.1's or
        # backtide.localhost's, never the other one (review of T26-3b-2).
        own = "http://" + hosts[0].decode("latin-1").lower()
        if scope["method"] == "POST" and any(
            token_matches(scope["path"], path) for path in self._post_paths
        ):
            large = any(token_matches(scope["path"], path) for path in self._large_paths)
            limit = MAX_LARGE_FORM_BYTES if large else MAX_FORM_BYTES
            refusal = self._post_refusal(headers, own, limit)
            if refusal is not None:
                return refusal
        elif scope["method"] not in ALLOWED_METHODS:
            return 405, "Read-only", [(b"allow", b"GET")]
        origins = [v for k, v in headers if k == b"origin"]
        if origins and (len(origins) != 1 or origins[0].decode("latin-1") != own):
            return 403, "Origin not allowed", []
        site = next((v for k, v in headers if k == b"sec-fetch-site"), b"").decode("latin-1")
        mode = next((v for k, v in headers if k == b"sec-fetch-mode"), b"").decode("latin-1")
        if site.lower() in {"same-site", "cross-site"} and mode.lower() != "navigate":
            return 403, "Cross-site request", []
        if not self._under_prefix(scope["path"]):
            return 404, "Not found", []
        return None

    def _post_refusal(
        self, headers: list[tuple[bytes, bytes]], own: str, limit: int = MAX_FORM_BYTES
    ) -> tuple[int, str, list[tuple[bytes, bytes]]] | None:
        """A POST that changes something: from our own page, a small plain form, or nothing."""

        def values(name: bytes) -> list[str]:
            return [v.decode("latin-1") for k, v in headers if k == name]

        origins = values(b"origin")
        if len(origins) != 1 or origins[0] != own:
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
        if len(lengths[0]) > 6 or int(lengths[0]) > limit:
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
