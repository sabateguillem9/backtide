"""The web of backtide: a lookout post on 127.0.0.1.

The control room ("Panel", T12d): every agent's card, a live feed of all of them and the gate's
requests waiting for your yes. Then, for each agent (``backtide.web.agents``), four pages:
"Ahora" (a live conversation of what the agent does, over Server-Sent Events), "Historia" (the
filtered timeline), "Instantáneas" (the list, and the rewind button) and "Preguntar" (the
question box on a page of its own). The main agent's pages keep their old addresses; the others
live under ``/agentes/<slug>/``. The security reasoning is in ``backtide.web.security``; the
rewind's in ``backtide.web.rewind``.

Which agent (T26-2d): the service says which there are (``backtide.web.live``), and a slug from a
browser is only ever looked up in that list, so one that is nobody's is the page of "nothing here".
The rewind and the decisions have one POST path each: their form says which agent (``agente``, none
for the main one), the page and its confirmation name it when there are several, and the one-time
ticket is bound to it, so a form for one agent acts on no other. Then it goes to the service as
``agent``, and the service decides again.

Everything here reads black boxes through ``BoxReader`` (read-only, without the key). The one
thing it can change is the agent's workspace, and only by asking the service (T12b): a
confirmation page (GET, the fixed notice and a one-time ticket) and then a POST from it. The
other thing it can change, only with `backtide web --ajustes` (T12e), is a key of the Settings
page ("Ajustes"), again by asking the service: a confirmation page per change and a POST from it
(``backtide.web.settings``). The third, only with `backtide web --aprobar` (T10-5), is a decision
on a held request of the gate (approve, reject, "aprobar y confiar", revoke a batch, take a
trusted recipient out), again by asking the service: a confirmation page per decision and a POST
from it (``backtide.web.approve``). The fourth, only with `backtide web --tareas` (T26-5b), is
giving the agent a task, on the chat's page: a POST with the session and its form token, and no
ticket, as a task is an everyday thing (``backtide.web.talk``). Every other route answers GET only.
"""

import asyncio
import contextvars
import hashlib
import itertools
import json
import logging
import math
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

import jinja2
from fastapi import Depends, FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from markupsafe import Markup
from starlette.exceptions import HTTPException as StarletteHTTPException

from backtide.blackbox import Event, Source
from backtide.gate.phrase import api_name
from backtide.jail.identity import SLUG, SlugError, check_slug
from backtide.jail.profile import MAX_PROMPT
from backtide.jail.profiles import DEFAULT_PROFILE, NAMED
from backtide.service.control import ControlError, ControlOutcomeUnknown, ControlUnavailable
from backtide.service.fleet import PROFILES, VOLUME_SIZES_GIB
from backtide.service.notice import rewind_notice
from backtide.service.origin import PublicOrigin
from backtide.service.passkeys import MAX_ANSWER_CHARS
from backtide.service.sessions import Sessions
from backtide.snapshots import Snapshot, SnapshotError
from backtide.web import format as fmt
from backtide.web.agents import (
    MAIN_SLUG,
    Agent,
    AgentFacts,
    AgentSource,
    Card,
    Listing,
    PendingRequest,
    Roster,
    Summary,
    Watch,
    card,
    countdown,
    empty_summary,
    live_requests,
    merged_feed,
    started,
    summarise,
)
from backtide.web.approve import (
    APPROVE,
    BOX_ROWS,
    REJECT,
    REVOKE,
    TRUST,
    Approver,
    BatchView,
    DecisionTickets,
    TrustView,
    batch_views,
    box_holds,
    box_partial,
    detail_of,
    held_event,
    held_request,
    id_fits,
    same_recipient,
    trust_note,
    trust_views,
)
from backtide.web.ask import MAX_QUESTION, answer
from backtide.web.i18n import LANGUAGES, Translator, negotiate
from backtide.web.manage import (
    CREATE,
    LONG_AFTER,
    ORDER_COMMAND,
    QUICK,
    TYPED_VERB,
    VERBS,
    AgentOrders,
    Order,
    OrderBook,
    Row,
    restart_command,
    rows_of,
)
from backtide.web.narrate import Line, Name, Narrator, line_for, safe_sentence, sentence
from backtide.web.reader import BoxReader, BoxUnavailable
from backtide.web.rewind import Availability, Redeemed, Rewinder, Tickets
from backtide.web.security import (
    ACTING_SESSION,
    AGENT_CREATE_PATH,
    AGENT_NEW_PATH,
    AGENT_ORDER_PATH,
    AGENT_RUNNING_PATH,
    AGENTS_PATH,
    AGENTS_STREAM_PATH,
    CLOSE_SESSIONS_PATH,
    CLOSE_SESSIONS_WORD,
    DECIDE_PATH,
    HOLDS_PATH,
    KEY_REMOVE_PATH,
    KEY_RENAME_PATH,
    KEYS_BEGIN_PATH,
    KEYS_FINISH_PATH,
    KEYS_PATH,
    LANG_COOKIE,
    MAX_FORM_BYTES,
    MAX_LARGE_FORM_BYTES,
    MAX_PROMPT_FORM_BYTES,
    PASSKEY_HOST,
    POST_PATH,
    SETTINGS_PATH,
    SETTINGS_POST_PATH,
    SIGN_IN_KEY_BEGIN_PATH,
    SIGN_IN_KEY_FINISH_PATH,
    SIGN_IN_PATH,
    SIGN_OUT_PATH,
    TALK_PATH,
    TALK_SEND_PATH,
    TALK_STOP_PATH,
    TOUCH_BEGIN_PATH,
    TOUCH_FINISH_PATH,
    TOUCH_PATH,
    Access,
    Guard,
    LocalAccess,
    SessionsBusy,
    make_prefix,
    make_run_name,
    make_token,
    session_cookie_name,
    token_matches,
)
from backtide.web.settings import (
    ACTIONS,
    BUDGET,
    KINDS,
    PRICES,
    TELEGRAM,
    SecretView,
    SettingsClient,
    SettingTickets,
    SpendClient,
    SpendView,
    cap_ok,
    digest_ok,
    spend_view,
    views,
)
from backtide.web.state import STATE_ACTIONS, AgentStatus, read_status
from backtide.web.talk import (
    QUICK_STOP,
    RUNNING,
    UNKNOWN,
    TaskClient,
    TaskView,
    is_task_id,
    known_id,
    known_of,
    view_of,
)
from backtide.web.text import visible, visible_middle
from backtide.web.tide import WINDOW, build_tide

logger = logging.getLogger(__name__)

HERE = Path(__file__).parent
PRIME_EVENTS = 3000  # how far back the conversation is rebuilt (to fold a burst correctly)
SHOWN_LINES = 60
PAGE_SIZE = 50
STREAM_BATCH = 500
TIDE_REFRESH = 60.0
ACTIVITY_EVENTS = 5000  # how many of the day's events shape the tide (and are counted)
KEEPALIVE = 15.0
LISTED_SNAPSHOTS = 30
SNAPSHOT_FALLBACK = 200
MAX_ACTION_CHARS = 64
RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
FORM_FIELDS = ("csrf", "id", "ticket")  # the rewind's form: these, once each, and nothing else
AGENT_FIELD = ("agente",)  # ...and which agent, when it is not the main one (T26-2d)
# The decisions' form (T10-5): these always; ``confirmo`` ticked for "aprobar y confiar".
DECIDE_FIELDS = ("csrf", "id", "v", "ticket")
DECIDE_OPTIONAL = ("confirmo",)
MAX_FIELD_CHARS = 128
# The Settings page's form (T12e): these always; ``valor`` (and ``chat`` for Telegram) to set a key;
# ``confirmo`` when it replaces one that is set. A pasted key may bring spaces around it.
SETTINGS_FIELDS = ("csrf", "ticket", "tipo", "accion")
SETTINGS_OPTIONAL = ("valor", "chat", "confirmo", "diario", "mensual", "huella")
SETTINGS_LIMITS = {"valor": 320, "chat": 32, "diario": 16, "mensual": 16, "huella": 32}
FROM_THE_BOX = "list"  # the rewind state when the list did not come from the volume
NOT_WATCHED = "unwatched"  # the rewind state of an agent the service is not watching now
SUMMARY_TTL = 3.0  # an agent's card is read again at most this often...
SUMMARY_MAX = 20.0  # ...and at least this often, even when its box has not moved
PANEL_FEED = 40  # lines in the control room's feed when it loads
REQUESTS_EVERY = 5.0  # how often the stream looks at the requests
MAX_PASSWORD_CHARS = 256
ROSTER_MARK_CHARS = 12  # enough to tell two lists apart: nothing is secret in it
# The agents' forms (T26-6b): a slug, a word of a list and a number of a list, and nothing else.
CREATE_FIELDS = ("csrf", "ticket", "slug", "perfil", "tamano")
ORDER_FIELDS = ("csrf", "ticket", "v", "agente")
ORDER_OPTIONAL = ("escrito",)
ORDER_REFRESH = 2  # seconds: how often a page with an order running looks again
# Where the touch page goes back to: a word, never a path from the query.
TOUCH_BACK = {
    "agentes": AGENTS_PATH,
    "agentes-nuevo": AGENT_NEW_PATH,
    "ajustes": SETTINGS_PATH,
    "peticiones": HOLDS_PATH,
    "llaves": KEYS_PATH,
    "llaves-alta": f"{KEYS_PATH}?nueva=1",
}
MAX_KEY_ID_CHARS = 1400  # 1023 bytes, the most a credential id can be, in base64url
KEY_REMOVE_ACTION, KEY_RENAME_ACTION = "remove", "rename"  # what a confirmation's ticket is for
SIGN_IN_ERRORS = frozenset({"wrong", "slow_down", "locked", "unset", "refused", "form"})
SESSION_RECHECK = 60.0  # how often an open stream asks whether its session still lives
BUSY_RETRY_SECONDS = 5  # a 503 past the service's cap: its bucket comes back in moments


class Unauthorized(Exception):  # noqa: N818 - an HTTP outcome, not an error
    def __init__(self, *, bad_link: bool = False) -> None:
        self.bad_link = bad_link


class StartSession(Exception):  # noqa: N818 - an HTTP outcome, not an error
    """The link carried the right token: set the cookie and go to the same page without it."""

    def __init__(self, session: str, target: str | None = None) -> None:
        self.session = session
        self.target = target  # where to go; None: the same page, without the link


def create_app(
    *,
    reader: BoxReader,
    port: int,
    token: str | None = None,
    session: str | None = None,
    access: Access | None = None,
    prefix: str | None = None,
    run_name: str | None = None,
    snapshots: Callable[[], Sequence[Snapshot]] | None = None,
    rewinder: Rewinder | None = None,
    agent_name: str | None = None,
    others: Sequence[AgentSource] = (),
    pending: Callable[[], Sequence[PendingRequest]] | None = None,
    settings: SettingsClient | None = None,
    approver: Approver | None = None,
    tasks: TaskClient | None = None,
    spend: SpendClient | None = None,
    agents_from: Callable[[], Sequence[AgentSource] | None] | None = None,
    agent_orders: AgentOrders | None = None,
    poll_interval: float = 1.0,
    stream_seconds: float = 600.0,
    session_recheck: float = SESSION_RECHECK,
    keepalive: float = KEEPALIVE,
    tz: tzinfo | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    agent_lines: Sequence[str] = DEFAULT_PROFILE.rewind_notice_lines,
    origin: PublicOrigin | None = None,
) -> Guard:
    """The ASGI app for one run, wrapped in its ``Guard``. ``token`` is the link's one-time
    token, ``session`` the secret of the cookie it is exchanged for, ``prefix`` the random path
    the whole app lives under, ``run_name`` the name shown to compare with the terminal (see
    ``backtide.web.security``; all random unless given, which the tests do). ``port`` is the one the
    server listens on (the ``Host`` check needs it). A stream lasts ``stream_seconds`` and the
    browser reconnects by itself, so no connection lives forever. ``rewinder`` asks the service
    to rewind (``backtide.web.rewind``); without one the rewind buttons are disabled.

    ``reader`` and ``snapshots`` are the main agent's, called ``agent_name``; ``others`` are more
    agents, read the same way (the demo's), and ``agents_from`` says which others there are now
    (``backtide.web.live``; None: it cannot say, the list stays). ``agent_orders`` manages them
    (T26-6b, ``backtide.web.manage``): its POST paths exist only when it is enabled (`--gestionar`).
    ``pending`` lists the gate's
    requests waiting for a yes, in the demo: the page shows them. ``settings``
    asks the service about the keys (T12e, ``backtide.web.settings``); its POST path exists
    only when it is enabled (`backtide web --ajustes`). ``approver`` asks the service about the
    held requests (T10-5, ``backtide.web.approve``): without ``pending`` the page lists the real
    ones (from the service with `backtide web --aprobar`, else from the black box), and the
    POST that decides exists only when it is enabled. ``spend`` reads the spending (T11) for the
    panel and Settings; changing the caps goes through ``settings`` (`--ajustes`). ``tasks``
    asks the service about the agent's tasks (T26-5b, ``backtide.web.talk``): the POST that gives
    one exists only when it is enabled (`--tareas`).
    ``agent_lines`` are the agent profile's lines of the rewind notice (T17a-3). ``origin`` is the
    domain it is behind, if any (T26-4a, ``backtide.web.security``): the app lives at its root,
    the cookie is the ``__Host-`` one, and there is no way in with the password (D40)."""
    cookie_name = session_cookie_name(origin)
    if access is None:
        sessions = Sessions()
        sessions.new_link(token or make_token())
        if session is not None:
            sessions.preset(session)  # the demo and the tests set the cookie themselves
        access = LocalAccess(sessions, cookie_name=cookie_name)
    prefix = prefix or make_prefix()
    base = "" if origin is not None else f"/s/{prefix}"
    cookie_path = base or "/"
    passkey_origin = origin.url if origin is not None else f"http://{PASSKEY_HOST}:{port}"
    roster = Roster(AgentSource(MAIN_SLUG, agent_name, reader, snapshots), others, base)
    run_name = run_name or make_run_name()
    zone = tz if tz is not None else fmt.local_tz()
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(HERE / "templates"),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    app = FastAPI(
        # "/ahora/" must not answer "307 to /ahora?t=...": the redirect drops the prefix and copies
        # an unspent token into another address. A path with a trailing slash is simply a 404.
        redirect_slashes=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        # FastAPI can emit OpenTelemetry traces, metrics and logs: this app sends nothing anywhere.
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    # -- access ----------------------------------------------------------------------------

    def _refresh_roster() -> None:
        """The list as the service says it now (at most every few seconds: ``LiveAgents``). What
        cannot be said leaves it as it is: never a page's problem."""
        if agents_from is None:
            return
        try:
            listed = agents_from()
            if listed is not None:
                roster.update(listed)
        except Exception:  # a list that makes no sense must not take the pages down
            logger.exception("the list of agents cannot be used")

    async def _roster_now() -> None:
        if agents_from is not None:
            await asyncio.to_thread(_refresh_roster)

    async def _signed_in(request: Request, *, use: bool = True) -> bool:
        """Is the cookie's session live? Then it is this request's (``request.state.session``)
        and the one every change it asks is sent with (``ACTING_SESSION``). Async on purpose: a
        context variable set here reaches the handler and the threads it starts. Cleared first,
        so nothing of an earlier request on the same connection is ever sent."""
        ACTING_SESSION.set(None)
        cookie = request.headers.get("cookie")
        session = await asyncio.to_thread(access.session_of, cookie, use=use)
        if session is None:
            return False
        request.state.session = session
        ACTING_SESSION.set(session.id)
        return True

    async def _signed_in_if_known(request: Request) -> bool:
        """For a new way in: an old cookie the service would not look at right now (T26-4a) must
        not stand in the way of the link, the password or the key. It dies at its own hour."""
        try:
            return await _signed_in(request)
        except SessionsBusy:
            return False

    async def _first_key_page(session_id: str) -> str | None:
        """Where to go after entering with no key yet: to register one (D40). None with keys."""
        keys = await asyncio.to_thread(access.passkey, "passkey_list", session_id)
        return (
            f"{base}{KEYS_PATH}?nueva=1"
            if keys.get("ok") is True and not keys.get("keys")
            else None
        )

    async def require_access(request: Request) -> None:
        given = request.query_params.get("t")
        if given is None:
            if not await _signed_in(request):
                raise Unauthorized
            return
        inside = await _signed_in_if_known(request)
        # One use, even in a browser that is already in (review of T26-3a): a link meant for
        # the phone, opened here, is spent here and does not stay alive in the history.
        opened = await asyncio.to_thread(access.open, given)
        if opened is not None:
            if inside:
                await asyncio.to_thread(access.end, request.state.session.id)
            # Behind a domain the link is there for the first key: straight to it.
            first = None if origin is None else await _first_key_page(opened.id)
            raise StartSession(opened.id, target=first)
        if not inside:
            raise Unauthorized(bad_link=True)

    async def require_watching(request: Request) -> None:
        """A page's own stream: the cookie, checked without counting as a use, because the
        browser reconnects it by itself (a tab left open must not keep a session alive)."""
        if not await _signed_in(request, use=False):
            raise Unauthorized

    protected = [Depends(require_access), Depends(_roster_now)]
    watching = [Depends(require_watching), Depends(_roster_now)]

    async def require_session(request: Request) -> None:
        """The cookie and nothing else: a change never starts from the link's token."""
        if not await _signed_in(request):
            raise Unauthorized
        await _roster_now()

    def _csrf(request: Request) -> str:
        return request.state.session.csrf

    def _csrf_is(request: Request, given: str | None) -> bool:
        return token_matches(given, request.state.session.csrf)

    # -- the cookie, and signing out (T26-3a-2) --------------------------------------------

    def _with_cookie(response: Response, session_id: str) -> Response:
        response.set_cookie(
            cookie_name,
            session_id,
            httponly=True,
            samesite="strict",
            path=cookie_path,
            secure=origin is not None,
        )
        return response

    def _signed_out() -> Response:
        """Back to the start, without the cookie: the next page asks for a link."""
        response = Response(status_code=303, headers={"location": base + "/"})
        response.delete_cookie(
            cookie_name,
            path=cookie_path,
            httponly=True,
            samesite="strict",
            secure=origin is not None,
        )
        return response

    @app.post(SIGN_OUT_PATH, dependencies=[Depends(require_session)])
    async def sign_out(request: Request) -> Response:
        """ "Salir": this session ends in the service, whatever the browser does next."""
        form = await _read_form(request, ("csrf",))
        if form is None:
            return Response("Formulario no válido", status_code=400)
        if not _csrf_is(request, form["csrf"]):
            return Response("Formulario de otra sesión", status_code=403)
        if await asyncio.to_thread(access.end, request.state.session.id) is None:
            # The service could not say it ended: the cookie stays, or the owner would think
            # they left while the session lives on (review of T26-3a-2).
            return Response(
                "No se ha podido cerrar la sesión: prueba otra vez, o `sudo backtide enlace "
                "--cerrar-todas`.",
                status_code=503,
            )
        return _signed_out()

    @app.post(CLOSE_SESSIONS_PATH, dependencies=[Depends(require_session)])
    async def close_sessions(request: Request) -> Response:
        """ "Cerrar todas": every session and the unspent link, asked from a live one, with the
        word typed as the confirmation. The service records it and alerts."""
        form = await _read_form(request, ("csrf", "confirmo"))
        if form is None:
            return Response("Formulario no válido", status_code=400)
        if not _csrf_is(request, form["csrf"]):
            return Response("Formulario de otra sesión", status_code=403)
        if not token_matches(form["confirmo"], CLOSE_SESSIONS_WORD):
            return Response(f"Escribe {CLOSE_SESSIONS_WORD} para confirmar", status_code=400)
        if await _touch_needed(request):
            return _go_touch("ajustes")
        if await asyncio.to_thread(access.end, request.state.session.id, every=True) is not True:
            return Response("El servicio no ha cerrado las sesiones", status_code=503)
        return _signed_out()

    tickets = Tickets(clock)
    rewinding: dict[str, threading.Lock] = {}  # one rewind in flight per agent, whoever asks
    stopping: dict[str, threading.Lock] = {}  # one task stop in flight per agent, whoever asks

    @app.exception_handler(StartSession)
    async def _start_session(request: Request, started: StartSession) -> Response:
        rest = [(k, v) for k, v in request.query_params.multi_items() if k != "t"]
        # The path hangs from our own prefix: "//host/x" can never become a link to another site.
        target = started.target or _here(request) + (f"?{urlencode(rest)}" if rest else "")
        # A 200 page, not a 303: when the link is opened from another site (a chat, a mail, the
        # browser pane of another app) the browser keeps that origin for the whole redirect
        # chain, and SameSite=Strict then withholds the cookie that this very response sets. Our
        # own page starts the next navigation (a meta refresh, or the link), and that one sends it.
        response = _page("enter.html", request, active="", t=None, target=target)
        # The cookie belongs to our prefix: other services on 127.0.0.1 (cookies ignore ports)
        # see it only if they are asked for a path under it, which they cannot guess.
        return _with_cookie(response, started.session)

    @app.exception_handler(Unauthorized)
    async def _unauthorized(request: Request, error: Unauthorized) -> Response:
        t = Translator(_language(request)[0])
        return _denied(request, t, 401, bad_link=error.bad_link)

    @app.exception_handler(SessionsBusy)
    async def _busy(request: Request, error: SessionsBusy) -> Response:
        """Not "you are out": nobody knows yet (T26-4a). With the way in, for whoever holds an old
        cookie while somebody floods the web with made-up ones."""
        response = _denied(request, Translator(_language(request)[0]), 503, why="busy")
        response.headers["retry-after"] = str(BUSY_RETRY_SECONDS)
        return response

    def _denied(
        request: Request, t: Translator, status: int, *, bad_link: bool = False, why: str = ""
    ) -> HTMLResponse:
        """The way in: the link, and on the installed web the password form (T26-3b-1)."""
        return _page(
            "denied.html",
            request,
            status=status,
            active="",
            t=t,
            bad_link=bad_link,
            key_only=origin is not None,
            sign_in=base + SIGN_IN_PATH
            if origin is None and getattr(access, "passwords", False)
            else None,
            sign_in_error=why,
            here=_at_the_keys_name(request),
            origin=passkey_origin,
            key_begin=base + SIGN_IN_KEY_BEGIN_PATH,
            key_finish=base + SIGN_IN_KEY_FINISH_PATH,
        )

    def _at_the_keys_name(request: Request) -> bool:
        """Was this page opened by the name its passkeys belong to? Behind a domain there is no
        other (the Guard); through the tunnel, 127.0.0.1 is one too and cannot have them."""
        host = request.headers.get("host", "").lower()
        return origin is not None or host.split(":")[0] == PASSKEY_HOST

    async def sign_in(request: Request) -> Response:
        """The web's password: the service checks it and gives a new session. Never logged,
        never kept here; only our own page may send it (the Guard's Origin checks)."""
        t = Translator(_language(request)[0])
        if not getattr(access, "passwords", False):
            return _denied(request, t, 404, why="unset")
        form = await _read_form(request, ("password",), limits={"password": MAX_PASSWORD_CHARS})
        if form is None:
            return _denied(request, t, 400, why="form")
        inside = await _signed_in_if_known(request)
        session, why = await asyncio.to_thread(access.sign_in, form.pop("password"))
        del form
        if session is None:
            status = 429 if why in ("slow_down", "locked") else 401
            return _denied(request, t, status, why=why if why in SIGN_IN_ERRORS else "refused")
        if inside:  # as the link does: the session this browser had ends, the new one begins
            await asyncio.to_thread(access.end, request.state.session.id)
        # D40: after the first entry, the web asks for a passkey (T26-3b-2).
        raise StartSession(session.id, target=await _first_key_page(session.id) or base + "/")

    if origin is None:  # behind a domain it takes a passkey: this path does not exist (D40)
        app.post(SIGN_IN_PATH)(sign_in)

    # -- signing in with a passkey and touching it again (T26-3c) -----------------------------

    @app.post(SIGN_IN_KEY_BEGIN_PATH)
    async def sign_in_key_begin(request: Request) -> Response:
        """The challenge to sign. No session yet: only our own page may ask (the Guard's Origin
        checks), and the service has its own limits."""
        if not getattr(access, "passwords", False):
            return JSONResponse({"ok": False, "message": "Solo en la web instalada."}, 404)
        if await _read_form(request, ()) is None:
            return JSONResponse({"ok": False, "message": "Formulario no válido."}, status_code=400)
        return _keys_reply(await asyncio.to_thread(access.auth, "auth_begin"))

    @app.post(SIGN_IN_KEY_FINISH_PATH)
    async def sign_in_key_finish(request: Request) -> Response:
        """The signature: the service checks it and gives a new session, whose cookie goes out
        with this answer (a fetch of our own page, so SameSite=Strict lets it in on the next
        navigation)."""
        if not getattr(access, "passwords", False):
            return JSONResponse({"ok": False, "message": "Solo en la web instalada."}, 404)
        form = await _read_form(
            request,
            ("answer",),
            limits={"answer": MAX_ANSWER_CHARS},
            max_bytes=MAX_LARGE_FORM_BYTES,
        )
        if form is None:
            return JSONResponse({"ok": False, "message": "Formulario no válido."}, status_code=400)
        inside = await _signed_in_if_known(request)
        reply = await asyncio.to_thread(access.auth, "auth_finish", answer=form["answer"])
        session = reply.get("session")
        if reply.get("ok") is not True or not isinstance(session, str):
            return JSONResponse({"ok": False, "message": str(reply.get("message", ""))}, 400)
        if inside:  # as the link and the password do
            await asyncio.to_thread(access.end, request.state.session.id)
        return _with_cookie(JSONResponse({"ok": True, "target": base + "/"}), session)

    async def _touch_needed(request: Request) -> bool:
        """Does this session have to touch its key first? Only to send the person there before
        they fill in a form: the service decides anyway, and says no if it was not done."""
        if not getattr(access, "passwords", False):
            return False
        reply = await asyncio.to_thread(access.passkey, "touch_status", request.state.session.id)
        return reply.get("needs") is True

    def _go_touch(back: str) -> Response:
        return RedirectResponse(f"{base}{TOUCH_PATH}?volver={back}", status_code=303)

    @app.get(TOUCH_PATH, dependencies=protected)
    async def touch_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        back = TOUCH_BACK.get(request.query_params.get("volver", ""), "/")
        return _page(
            "touch.html",
            request,
            active="settings",
            t=t,
            here=_at_the_keys_name(request),
            origin=passkey_origin,
            csrf=request.state.session.csrf,
            begin=base + TOUCH_BEGIN_PATH,
            finish=base + TOUCH_FINISH_PATH,
            target=base + back,
        )

    @app.post(TOUCH_BEGIN_PATH, dependencies=[Depends(require_session)])
    async def touch_begin(request: Request) -> Response:
        form = await _read_form(request, ("csrf",))
        if form is None or not _csrf_is(request, form["csrf"]):
            return JSONResponse({"ok": False, "message": "Formulario no válido."}, status_code=403)
        if not getattr(access, "passwords", False):
            return JSONResponse({"ok": False, "message": "Solo en la web instalada."}, 404)
        reply = await asyncio.to_thread(access.passkey, "touch_begin", request.state.session.id)
        return _keys_reply(reply)

    @app.post(TOUCH_FINISH_PATH, dependencies=[Depends(require_session)])
    async def touch_finish(request: Request) -> Response:
        form = await _read_form(
            request,
            ("csrf", "answer"),
            limits={"answer": MAX_ANSWER_CHARS},
            max_bytes=MAX_LARGE_FORM_BYTES,
        )
        if form is None or not _csrf_is(request, form["csrf"]):
            return JSONResponse({"ok": False, "message": "Formulario no válido."}, status_code=403)
        if not getattr(access, "passwords", False):
            return JSONResponse({"ok": False, "message": "Solo en la web instalada."}, 404)
        reply = await asyncio.to_thread(
            access.passkey, "touch_finish", request.state.session.id, answer=form["answer"]
        )
        return _keys_reply(reply)

    # -- the passkeys (T26-3b-2) -------------------------------------------------------------

    @app.get(KEYS_PATH, dependencies=protected)
    async def keys_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        session = request.state.session
        listed: dict[str, Any] = {"ok": False, "keys": []}
        if getattr(access, "passwords", False):  # only the installed web's service keeps keys
            listed = await asyncio.to_thread(access.passkey, "passkey_list", session.id)
        add = "ok"
        if getattr(access, "passwords", False):
            status = await asyncio.to_thread(access.passkey, "touch_status", session.id)
            add = status["add"] if status.get("add") in ("ok", "touch", "again") else "ok"
        # A passkey belongs to backtide.localhost: on 127.0.0.1 the page says where to go instead
        # of offering a form that cannot work there.
        first = request.query_params.get("nueva") == "1"
        return _page(
            "keys.html",
            request,
            active="settings",
            t=t,
            installed=getattr(access, "passwords", False),
            key_only=origin is not None,
            here=_at_the_keys_name(request),
            origin=passkey_origin,
            keys=listed.get("keys") if listed.get("ok") is True else [],
            first=first,
            add=add,
            touch=f"{base}{TOUCH_PATH}?volver={'llaves-alta' if first else 'llaves'}",
            remove=base + KEY_REMOVE_PATH,
            rename=base + KEY_RENAME_PATH,
            csrf=session.csrf,
            begin=base + KEYS_BEGIN_PATH,
            finish=base + KEYS_FINISH_PATH,
        )

    # -- taking a key out and naming it (T26-3d): the service decides ---------------------------

    key_tickets = SettingTickets(clock)

    def _key_step(
        request: Request, t: Translator, status: int, view: str, **values: Any
    ) -> HTMLResponse:
        for name in ("key", "error", "reason", "ticket", "action", "typed"):
            values.setdefault(name, None)
        return _page(
            "keys_step.html",
            request,
            status=status,
            active="settings",
            t=t,
            view=view,
            back=base + KEYS_PATH,
            **values,
        )

    async def _listed_keys(request: Request) -> list[dict[str, Any]] | None:
        """The keys the service lists now, or None if it cannot say."""
        reply = await asyncio.to_thread(access.passkey, "passkey_list", request.state.session.id)
        keys = reply.get("keys")
        return keys if reply.get("ok") is True and isinstance(keys, list) else None

    async def _key_confirm(request: Request, action: str) -> Response:
        """The confirmation of a change to a key: a one-time ticket for this action on this key.
        After a touch, or the page sends you to touch one and back to the list."""
        t = Translator(_language(request)[0])
        if not getattr(access, "passwords", False):
            return _key_step(request, t, 404, "refused", reason="keys.local")
        if await _touch_needed(request):
            return _go_touch("llaves")
        given = request.query_params.get("llave", "")
        keys = await _listed_keys(request)
        if keys is None:
            return _key_step(request, t, 503, "refused", reason="keys.err.refused")
        key = next((k for k in keys if k.get("id") == given), None)
        if key is None:
            return _key_step(request, t, 404, "refused", reason="keys.err.missing")
        if action == KEY_REMOVE_ACTION and len(keys) == 1:
            return _key_step(request, t, 200, "refused", reason="keys.err.last")
        view = "confirm_remove" if action == KEY_REMOVE_ACTION else "confirm_rename"
        return _key_step(
            request, t, 200, view, key=key, typed=key.get("name"),
            ticket=key_tickets.issue(action, given), csrf=request.state.session.csrf,
            action=base + (KEY_REMOVE_PATH if action == KEY_REMOVE_ACTION else KEY_RENAME_PATH),
        )  # fmt: skip

    @app.get(KEY_REMOVE_PATH, dependencies=protected)
    async def key_remove_page(request: Request) -> Response:
        return await _key_confirm(request, KEY_REMOVE_ACTION)

    @app.get(KEY_RENAME_PATH, dependencies=protected)
    async def key_rename_page(request: Request) -> Response:
        return await _key_confirm(request, KEY_RENAME_ACTION)

    async def _key_form(
        request: Request, t: Translator, action: str, fields: tuple[str, ...]
    ) -> dict[str, str] | Response:
        """The form of a change to a key, its CSRF and its ticket: the form, or the refusal."""
        form = await _read_form(
            request,
            fields,
            limits={"llave": MAX_KEY_ID_CHARS, "nombre": 48},
            max_bytes=MAX_LARGE_FORM_BYTES,
        )
        if form is None:
            return _key_step(request, t, 400, "refused", reason="keys.err.form")
        if not _csrf_is(request, form["csrf"]):
            return Response("Formulario de otra sesión", status_code=403)
        if not getattr(access, "passwords", False):
            return _key_step(request, t, 404, "refused", reason="keys.local")
        redeemed, _ = key_tickets.redeem(form["ticket"], action, form["llave"])
        if redeemed is not Redeemed.OK:
            return _key_step(request, t, 400, "refused", reason="keys.err.ticket")
        return form

    def _key_refused(request: Request, t: Translator, reply: dict[str, Any]) -> Response:
        """The service said no: to touch a key first, or why not, in the page's language."""
        outcome = reply.get("outcome")
        if outcome == "touch":
            return _go_touch("llaves")
        if outcome == "missing":
            return _key_step(request, t, 404, "refused", reason="keys.err.missing")
        if outcome == "last":
            return _key_step(request, t, 400, "refused", reason="keys.err.last")
        return _key_step(request, t, 400, "refused", reason="keys.err.refused")

    @app.post(KEY_REMOVE_PATH, dependencies=[Depends(require_session)])
    async def key_remove(request: Request) -> Response:
        """Take a key out. The service records it first, and ends every session, this one too."""
        t = Translator(_language(request)[0])
        form = await _key_form(request, t, KEY_REMOVE_ACTION, ("csrf", "ticket", "llave"))
        if isinstance(form, Response):
            return form
        reply = await asyncio.to_thread(
            access.passkey, "key_remove", request.state.session.id, key=form["llave"]
        )
        if reply.get("ok") is not True:
            return _key_refused(request, t, reply)
        request.state.session = None  # it has just ended: the page offers no "Salir"
        response = _key_step(
            request, t, 200, "removed",
            key={"name": str(reply.get("name", "")), "tail": str(reply.get("tail", ""))},
        )  # fmt: skip
        response.delete_cookie(
            cookie_name,
            path=cookie_path,
            httponly=True,
            samesite="strict",
            secure=origin is not None,
        )
        return response

    @app.post(KEY_RENAME_PATH, dependencies=[Depends(require_session)])
    async def key_rename(request: Request) -> Response:
        """A key's new name. A bad one comes back to its form, with its reason and a new ticket."""
        t = Translator(_language(request)[0])
        form = await _key_form(request, t, KEY_RENAME_ACTION, ("csrf", "ticket", "llave", "nombre"))
        if isinstance(form, Response):
            return form
        session = request.state.session
        name = form["nombre"].strip()
        reply = await asyncio.to_thread(
            access.passkey, "key_rename", session.id, key=form["llave"], name=name
        )
        if reply.get("ok") is True:
            return RedirectResponse(base + KEYS_PATH, status_code=303)
        if reply.get("outcome") != "name":
            return _key_refused(request, t, reply)
        keys = await _listed_keys(request)
        key = next((k for k in keys or [] if k.get("id") == form["llave"]), None)
        if key is None:
            return _key_step(request, t, 404, "refused", reason="keys.err.missing")
        return _key_step(
            request, t, 400, "confirm_rename", key=key, typed=name, error="keys.err.name",
            ticket=key_tickets.issue(KEY_RENAME_ACTION, form["llave"]), csrf=session.csrf,
            action=base + KEY_RENAME_PATH,
        )  # fmt: skip

    def _keys_reply(reply: dict[str, Any]) -> JSONResponse:
        shown = {"ok": reply.get("ok") is True, "message": str(reply.get("message", ""))}
        if isinstance(reply.get("options"), str):
            shown["options"] = reply["options"]
        if isinstance(reply.get("key"), dict):
            shown["key"] = reply["key"]
        return JSONResponse(shown, status_code=200 if shown["ok"] else 400)

    @app.post(KEYS_BEGIN_PATH, dependencies=[Depends(require_session)])
    async def keys_begin(request: Request) -> Response:
        form = await _read_form(request, ("csrf",))
        if form is None or not _csrf_is(request, form["csrf"]):
            return JSONResponse({"ok": False, "message": "Formulario no válido."}, status_code=403)
        if not getattr(access, "passwords", False):
            return JSONResponse({"ok": False, "message": "Solo en la web instalada."}, 404)
        reply = await asyncio.to_thread(access.passkey, "passkey_begin", request.state.session.id)
        return _keys_reply(reply)

    @app.post(KEYS_FINISH_PATH, dependencies=[Depends(require_session)])
    async def keys_finish(request: Request) -> Response:
        form = await _read_form(
            request,
            ("csrf", "name", "answer"),
            limits={"name": 48, "answer": MAX_ANSWER_CHARS},
            max_bytes=MAX_LARGE_FORM_BYTES,
        )
        if form is None or not _csrf_is(request, form["csrf"]):
            return JSONResponse({"ok": False, "message": "Formulario no válido."}, status_code=403)
        if not getattr(access, "passwords", False):
            return JSONResponse({"ok": False, "message": "Solo en la web instalada."}, 404)
        reply = await asyncio.to_thread(
            access.passkey,
            "passkey_finish",
            request.state.session.id,
            answer=form["answer"],
            name=form["name"],
        )
        return _keys_reply(reply)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, error: StarletteHTTPException) -> Response:
        if error.status_code == 404:
            return _page("missing.html", request, status=404, active="", t=None)
        return Response(status_code=error.status_code, headers=dict(error.headers or {}))

    # -- shared pieces ---------------------------------------------------------------------

    def _here(request: Request) -> str:
        """This request's path under our prefix, with a single leading slash."""
        return base + "/" + request.url.path.lstrip("/\\")

    def _language(request: Request) -> tuple[str, bool]:
        """(language, whether the URL asked for it: then it is remembered in a cookie)."""
        asked = request.query_params.get("lang")
        if asked in LANGUAGES:
            return asked, True
        saved = request.cookies.get(LANG_COOKIE)
        if saved in LANGUAGES:
            return saved, False
        return negotiate(request.headers.get("accept-language")), False

    def _helpers(t: Translator, now: datetime, agent: Agent | None = None) -> dict[str, Any]:
        """What every template (page or stream fragment) may call. ``agent``: the agent the
        page is about (None: the control room and the pages of no agent)."""
        abase = agent.base if agent is not None else roster.main.base

        def tell(event_or_line: Event | Line) -> Markup:
            line = event_or_line if isinstance(event_or_line, Line) else line_for(event_or_line)
            return safe_sentence(t, line, zone)

        def stamp(when: str | datetime) -> str:
            moment = fmt.parse_ts(when) if isinstance(when, str) else when
            return fmt.stamp(moment, zone)

        def burst(line: Line) -> dict[str, str] | None:
            """A folded line's span and the history of its events, or None for a single one."""
            if line.count < 2 or line.mark or not line.first_ts or "/" not in line.what:
                return None
            first, last = fmt.parse_ts(line.first_ts), fmt.parse_ts(line.ts)
            source = line.what.partition("/")[0]
            # By seq, not by action or by time: a burst may have absorbed file/summary rows
            # (another action), and local minutes are ambiguous when the clock changes (DST).
            # Nothing else happens inside the range: any other event closes a burst.
            query = urlencode(
                [("origen", source), ("tras", str(line.id - 1)), ("antes", str(line.last_seq + 1))]
            )
            return {
                "from_": fmt.clock(first, zone),
                "to": fmt.clock(last, zone),
                "href": f"{abase}/historia?{query}",
            }

        def agent_name(who: Agent) -> str:
            return who.name if who.name is not None else t("agent.default")

        def kind_label(who: AgentFacts | Row | None) -> str:
            """Which agent it is (D42), from the service's word: "Claude Code 2.1.306"."""
            if who is None or who.kind is None:
                return ""
            key = f"agents.kind.{who.kind}"
            kind = t(key) if t.has(key) else who.kind
            return f"{kind} {who.version}" if who.version else kind

        return {
            "t": t,
            "tell": tell,
            "burst": burst,
            "vis": visible,
            "clock": lambda ts: fmt.clock(fmt.parse_ts(ts), zone),
            "stamp": stamp,
            "parse_ts": fmt.parse_ts,
            "age": lambda moment: fmt.age(t, now - moment),
            "day_time": lambda moment: fmt.day_time(t, moment, now, zone),
            "details_json": _details_json,
            "say": lambda key, **params: sentence(t, key, params, zone),
            "name": Name,
            "base": base,
            "abase": abase,
            "agent": agent,
            "roster": roster,
            "agent_name": agent_name,
            "kind_label": kind_label,
            "facts_of": _facts_of,
            "countdown": countdown,
            "run_name": run_name,
            # Whether the holds' buttons work (T10-5): "ready", or why not. Asked when drawn.
            "approvals_state": lambda: str(_approvals()),
            # The list read from the black box may miss older holds (finding 7).
            "holds_partial": lambda: box_cache.get("partial") is True,
            "vis_mid": visible_middle,
            "api": lambda translator: api_name(translator, t.language),
        }

    def _page(
        template: str,
        request: Request,
        *,
        status: int = 200,
        active: str,
        t: Translator | None,
        agent: Agent | None = None,
        **values: Any,
    ) -> HTMLResponse:
        language, remember = _language(request)
        t = t or Translator(language)
        now = clock()
        values.setdefault("wide", False)

        def switch(code: str) -> str:
            rest = [(k, v) for k, v in request.query_params.multi_items() if k not in {"lang", "t"}]
            return f"{_here(request)}?{urlencode([*rest, ('lang', code)])}"

        session = getattr(request.state, "session", None)
        context = {
            **_helpers(t, now, agent),
            "active": active,
            "public_host": origin.host if origin is not None else None,
            "lang": t.language,
            "switch": switch,
            "languages": LANGUAGES,
            # For the "Salir" and "Cerrar todas" forms (T26-3a-2): None outside a session.
            "signed_in": None
            if session is None
            else {
                "csrf": session.csrf,
                "sign_out": base + SIGN_OUT_PATH,
                "close_all": base + CLOSE_SESSIONS_PATH,
                "close_word": CLOSE_SESSIONS_WORD,
            },
            **values,
        }
        response = HTMLResponse(env.get_template(template).render(**context), status_code=status)
        if remember:
            response.set_cookie(
                LANG_COOKIE,
                t.language,
                httponly=True,
                samesite="strict",
                path=cookie_path,
                secure=origin is not None,
            )
        return response

    def _status_view(agent: Agent) -> dict[str, Any]:
        try:
            status = read_status(agent.reader)
        except BoxUnavailable:
            status = AgentStatus("unknown", None)
        when = fmt.clock(status.since, zone) if status.since else None
        return {"state": status.state, "state_time": when}

    def _snapshot_source(agent: Agent) -> Callable[[], Sequence[Snapshot]] | None:
        return agent.source.snapshots

    def _tide_view(
        agent: Agent,
        now: datetime,
        window: timedelta = WINDOW,
        marked: Sequence[Snapshot] | None = None,
    ) -> Any:
        """The tide of ``window`` before ``now``. One read, by primary key only (the newest
        ``ACTIVITY_EVENTS`` + 1 events, whatever the box's size: ``ts`` has no index, so asking
        for "since" would walk the whole table in a quiet window, under the reader's lock).
        The marks are ``marked`` if given, else the volume's snapshots, else the ``take``
        events among the rows read."""
        try:
            rows = agent.reader.events(newest_first=True, limit=ACTIVITY_EVENTS + 1)
        except BoxUnavailable:
            rows = []
        start = now - window
        inside = [e for e in rows[:ACTIVITY_EVENTS] if fmt.parse_ts(e.ts) >= start]
        more = len(rows) > ACTIVITY_EVENTS and fmt.parse_ts(rows[ACTIVITY_EVENTS].ts) >= start
        activity = [fmt.parse_ts(e.ts) for e in inside]
        listing = _snapshot_source(agent)
        if marked is None and listing is not None:
            try:
                marked = [s for s in listing() if s.taken_at >= start]
            except (SnapshotError, OSError):
                marked = None  # the page about snapshots says so; here the box's word will do
        takes = [e for e in inside if e.source is Source.SNAPSHOT and e.action == "take"]
        return build_tide(
            list(reversed(takes)), now, activity, more=more, window=window, snapshots=marked
        )

    tide_cache: dict[str, tuple[float, Any]] = {}
    tide_lock = threading.Lock()

    def _day_tide(agent: Agent, *, fresh: bool = False) -> Any:
        """The day's tide of an agent's "Ahora", built at most once per ``TIDE_REFRESH`` for
        every page and stream (``fresh`` after a new snapshot: its mark must not wait a
        minute)."""
        moment = time.monotonic()
        with tide_lock:
            cached = tide_cache.get(agent.slug)
            if not fresh and cached is not None and moment - cached[0] < TIDE_REFRESH:
                return cached[1]
        tide = _tide_view(agent, clock())
        with tide_lock:
            tide_cache[agent.slug] = (moment, tide)
        return tide

    # -- the control room's view of each agent --------------------------------------------

    summaries: dict[str, tuple[float, Summary]] = {}
    summary_lock = threading.Lock()  # guards ``summaries`` only, held for a moment
    agent_locks: dict[str, threading.Lock] = {}  # one read of an agent at a time
    watches: dict[str, Watch] = {}
    versions = itertools.count(1)

    def _summary(agent: Agent) -> Summary:
        """What an agent's card says: one read of its newest events, shared by every page and
        stream, read again when its box has moved (at most every ``SUMMARY_TTL`` seconds) or
        every ``SUMMARY_MAX`` seconds (its "working" turns into "idle" with time). One reader
        at a time per agent: whoever comes while it is read waits and takes the result."""

        def fresh_enough(cached: tuple[float, Summary] | None, moment: float) -> bool:
            return cached is not None and moment - cached[0] < SUMMARY_TTL

        with summary_lock:
            cached = summaries.get(agent.slug)
        if fresh_enough(cached, time.monotonic()):
            return cached[1]  # type: ignore[index]
        with agent_locks.setdefault(agent.slug, threading.Lock()):
            moment = time.monotonic()
            with summary_lock:
                cached = summaries.get(agent.slug)
            if fresh_enough(cached, moment):
                return cached[1]  # type: ignore[index]
            now = clock()
            try:
                if cached is not None and moment - cached[0] < SUMMARY_MAX:
                    if agent.reader.head_seq() == cached[1].head:
                        with summary_lock:
                            summaries[agent.slug] = (moment, cached[1])
                        return cached[1]
                rows = agent.reader.events(newest_first=True, limit=ACTIVITY_EVENTS + 1)
                marks = None
                listing = _snapshot_source(agent)
                if listing is not None:
                    try:
                        marks = list(listing())
                    except (SnapshotError, OSError):
                        marks = None
                summary = summarise(
                    rows[:ACTIVITY_EVENTS],
                    now,
                    zone,
                    cut=len(rows) > ACTIVITY_EVENTS,
                    watch=watches.setdefault(agent.slug, Watch(agent.reader)),
                    snapshots=marks,
                )
            except BoxUnavailable:
                summary = empty_summary(now, unreadable=True)
            summary = replace(summary, version=next(versions))
            with summary_lock:
                summaries[agent.slug] = (moment, summary)
            return summary

    def _requests() -> tuple[list[PendingRequest] | None, datetime, bool]:
        """The gate's requests still waiting, when, and whether the list could NOT be read
        (then it is empty here, and the page says so instead of "nothing waits"). The demo's
        come from ``pending``; the real ones from the service or the black box (T10-5)."""
        now = clock()
        try:
            if pending is not None:
                return live_requests(list(pending()), roster, now), now, False
            listed, failed = _held(now)
            return live_requests(listed, roster, now), now, failed
        except Exception:  # a page, not a 500: the log says why, the page says it is unknown
            logger.exception("the pending requests cannot be listed")
            return [], now, True

    # -- the held requests (T10-5) --------------------------------------------------------

    decision_tickets = DecisionTickets(clock)
    box_cache: dict[str, Any] = {}  # "partial": what the page says of the list
    box_rows: dict[str, tuple[int, Sequence[Event]]] = {}  # by agent: a slug may be any word
    box_lock = threading.Lock()

    def _approvals() -> Availability:
        if approver is None:
            return Availability.DISABLED  # as `backtide web` without --aprobar
        try:
            return approver.availability()
        except Exception:  # never a 500 for a disabled button; the log says why
            logger.exception("cannot tell whether the service can be asked about the holds")
            return Availability.OFF

    def _held(now: datetime) -> tuple[list[PendingRequest], bool]:
        """Every agent's holds, and whether some could not be read: from the service when this web
        may decide (``--aprobar``), else rebuilt from each black box (read again only when it
        moved). One agent that cannot say never hides what the others hold. One that is not being
        watched holds nothing: its proxy is not up, and nobody could answer."""
        ready = _approvals() is Availability.READY and approver is not None
        found: list[PendingRequest] = []
        failed = partial = False
        for who in roster:
            if ready and not who.source.watched:
                continue
            try:
                if ready:
                    raw = approver.holds(**who.order)
                else:
                    rows = _box_rows(who)
                    raw = box_holds(rows, now)
                    partial = partial or box_partial(rows, now)
            except Exception:  # the page says the list may be old; the log says why
                logger.exception("the holds of the agent %s cannot be listed", who.slug)
                failed = True
                continue
            shown = (held_request(item, now=now, agent=who.slug) for item in raw)
            found += [request for request in shown if request is not None]
        box_cache["partial"] = partial
        return found, failed

    def _box_rows(who: Agent) -> Sequence[Event]:
        """The newest rows of an agent's box, read again only when it moved."""
        head = who.reader.head_seq()
        with box_lock:
            cached = box_rows.get(who.slug)
            if cached is None or cached[0] != head:
                cached = (head, who.reader.events(newest_first=True, limit=BOX_ROWS))
                box_rows[who.slug] = cached
        return cached[1]

    def _find_hold(who: Agent, hold_id: str) -> PendingRequest | None:
        requests, _now, _failed = _requests()
        return next((r for r in requests or () if (r.agent, r.id) == (who.slug, hold_id)), None)

    def _shown(who: Agent) -> Agent | None:
        """The agent a confirmation names: with only one there is nobody to mix it up with, and
        the page stays what it always was."""
        return who if len(roster) > 1 else None

    def _bound(who: Agent, subject: str) -> str:
        """What a one-time ticket is for: this agent's this. A slug has no colon."""
        return f"{who.slug}:{subject}"

    def _agent_in(form: dict[str, str]) -> Agent:
        """The agent a form says (none: the main one). One that is nobody's is "nothing here". The
        ticket, which is bound to one, and the service, which has its own list, come after."""
        slug = form.get("agente")
        return roster.main if slug is None else _agent(slug)

    def _cards(requests: Sequence[PendingRequest] | None, now: datetime) -> list[Card]:
        listing = _listing()
        return [
            card(
                a, _summary(a), requests or (), now, None if listing is None else listing.of(a.slug)
            )
            for a in roster
        ]

    def _listing() -> Listing | None:
        """What the service says of the agents now: asked at most every few seconds. Not knowing
        leaves the pages saying less, never a page's problem."""
        if agent_orders is None:
            return None
        try:
            return agent_orders.listing()
        except Exception:  # as ``_refresh_roster``: a list that makes no sense takes no page down
            logger.exception("what the service says of the agents cannot be used")
            return None

    def _facts_of(who: Agent) -> AgentFacts | None:
        listing = _listing()
        return None if listing is None else listing.of(who.slug)

    def _agent(slug: str) -> Agent:
        found = roster.get(slug)
        if found is None:
            raise StarletteHTTPException(404)
        return found

    # -- pages -----------------------------------------------------------------------------

    @app.get("/", dependencies=protected)
    def home() -> Response:
        return RedirectResponse(f"{base}/panel", status_code=303)

    @app.get("/panel", dependencies=protected)
    def panel_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        requests, now, failed = _requests()
        cards = _cards(requests, now)
        return _page(
            "panel.html",
            request,
            active="panel",
            t=t,
            wide=True,
            cards=cards,
            requests=requests,
            stale=failed,
            feed=_panel_feed(cards),
            heads=_heads_id(_roster_mark(roster), [c.summary.head for c in cards]),
            now=now,
            spend=_spend(),
        )

    @app.get("/panel/stream", dependencies=watching)
    def panel_stream(request: Request, after: str = "") -> Response:
        given = request.headers.get("last-event-id", "") or after
        mark = _roster_mark(roster)
        starts = _heads(given, mark)
        t = Translator(_language(request)[0])
        return StreamingResponse(
            _panel_stream(request, t, starts, stale=bool(given) and not starts),
            media_type="text/event-stream",
            headers={"x-accel-buffering": "no"},
        )

    @app.get("/ahora", dependencies=protected)
    def now_page(request: Request) -> Response:
        return _now_page(request, roster.main)

    @app.get("/agentes/{slug}/ahora", dependencies=protected)
    def agent_now_page(request: Request, slug: str) -> Response:
        return _now_page(request, _agent(slug))

    def _now_page(request: Request, agent: Agent) -> Response:
        t = Translator(_language(request)[0])
        unreadable = False
        lines: list[Line] = []
        head = 0
        last_ts = None
        try:
            recent = list(reversed(_recent(agent.reader, PRIME_EVENTS)))
            lines = Narrator().feed(recent)[-SHOWN_LINES:]
            head = recent[-1].seq if recent else 0
            last_ts = recent[-1].ts if recent else None
        except BoxUnavailable:
            unreadable = True
        return _page(
            "now.html",
            request,
            active="now",
            t=t,
            agent=agent,
            lines=lines,
            head=head,
            last_ts=last_ts,
            unreadable=unreadable,
            tide=_day_tide(agent),
            **_status_view(agent),
        )

    @app.get("/ahora/preguntar", dependencies=protected)
    def ask(request: Request, q: str = "") -> Response:
        return _ask(request, roster.main, q)

    @app.get("/agentes/{slug}/ahora/preguntar", dependencies=protected)
    def agent_ask(request: Request, slug: str, q: str = "") -> Response:
        return _ask(request, _agent(slug), q)

    def _ask(request: Request, agent: Agent, q: str) -> Response:
        t = Translator(_language(request)[0])
        try:
            reply = answer(q, reader=agent.reader, now=clock(), tz=zone, t=t)
            unreadable = False
        except BoxUnavailable:
            reply, unreadable = None, True
        partial = request.headers.get("hx-request") == "true"
        return _page(
            "ask.html" if partial else "ask_page.html",
            request,
            active="ask",
            t=t,
            agent=agent,
            question=q[:MAX_QUESTION],
            reply=reply,
            unreadable=unreadable,
        )

    @app.get("/ahora/stream", dependencies=watching)
    def stream(request: Request, after: str = "0") -> Response:
        return _open_stream(request, roster.main, after)

    @app.get("/agentes/{slug}/ahora/stream", dependencies=watching)
    def agent_stream(request: Request, slug: str, after: str = "0") -> Response:
        return _open_stream(request, _agent(slug), after)

    def _open_stream(request: Request, agent: Agent, after: str) -> Response:
        resume = request.headers.get("last-event-id", "")
        start = _seq(resume) or _seq(after)
        t = Translator(_language(request)[0])
        events = _stream(request, t, start, agent)
        return StreamingResponse(
            events,
            media_type="text/event-stream",
            headers={"x-accel-buffering": "no"},
        )

    @app.get("/historia", dependencies=protected)
    def history_page(request: Request) -> Response:
        return _history_page(request, roster.main)

    @app.get("/agentes/{slug}/historia", dependencies=protected)
    def agent_history_page(request: Request, slug: str) -> Response:
        return _history_page(request, _agent(slug))

    def _history_page(request: Request, agent: Agent) -> Response:
        t = Translator(_language(request)[0])
        now = clock()
        filters = parse_filters(request.query_params, now, zone)
        unreadable = False
        events: list[Event] = []
        try:
            events = agent.reader.events(**filters.query(), newest_first=True, limit=PAGE_SIZE + 1)
        except BoxUnavailable:
            unreadable = True
        more = len(events) > PAGE_SIZE
        events = events[:PAGE_SIZE]
        older = None
        if more:
            older = f"{agent.base}/historia?" + urlencode(
                [*filters.pairs(), ("antes", str(events[-1].seq))]
            )
        partial = request.headers.get("hx-request") == "true"
        template = (
            "history_rows.html"
            if "antes" in request.query_params and partial
            else ("history_results.html" if partial else "history.html")
        )
        page = _page(
            template,
            request,
            active="history",
            t=t,
            agent=agent,
            filters=filters,
            events=events,
            older=older,
            unreadable=unreadable,
            sources=[s.value for s in Source],
            ranges=list(RANGES),
        )
        if partial and "antes" not in request.query_params:
            # the address of the filtered page, without the form's empty fields
            query = urlencode(filters.pairs())
            page.headers["HX-Push-Url"] = f"{agent.base}/historia" + (f"?{query}" if query else "")
        return page

    @app.get("/instantaneas", dependencies=protected)
    def snapshots_page(request: Request) -> Response:
        return _snapshots_page(request, roster.main)

    @app.get("/agentes/{slug}/instantaneas", dependencies=protected)
    def agent_snapshots_page(request: Request, slug: str) -> Response:
        return _snapshots_page(request, _agent(slug))

    def _snapshots_page(request: Request, agent: Agent) -> Response:
        t = Translator(_language(request)[0])
        now = clock()
        show_all = request.query_params.get("todas") == "1"
        rows: list[Snapshot] = []
        error: str | None = None
        from_box = False
        listing = _snapshot_source(agent)
        if listing is not None:
            try:
                rows = list(listing())
            except (SnapshotError, OSError) as failure:
                logger.warning("the snapshot list cannot be read: %s", failure)
                error = str(failure)
        else:
            error = "no volume configured"
        box_unreadable = False
        if error is not None:
            from_box = True
            try:
                takes = agent.reader.events(
                    source=Source.SNAPSHOT,
                    action="take",
                    newest_first=True,
                    limit=SNAPSHOT_FALLBACK,
                )
            except BoxUnavailable:
                takes, box_unreadable = [], True
            rows = [s for e in takes if e.snapshot_id and (s := Snapshot.parse(e.snapshot_id))][
                ::-1
            ]
        newest_first = list(reversed(rows))
        shown = newest_first if show_all else newest_first[:LISTED_SNAPSHOTS]
        if not agent.source.watched:
            rewind_state = NOT_WATCHED  # the service would refuse, and this says why first
        else:
            rewind_state = FROM_THE_BOX if from_box else str(_availability())
        return _page(
            "snapshots.html",
            request,
            active="snapshots",
            t=t,
            agent=agent,
            rows=shown,
            rewind_state=rewind_state,
            hidden=len(newest_first) - len(shown),
            error=error,
            from_box=from_box,
            box_unreadable=box_unreadable,
            now=now,
            tide=_tide_view(agent, now, _snapshot_window(shown, now), shown),
        )

    # -- the rewind (T12b) -----------------------------------------------------------------

    def _availability() -> Availability:
        if rewinder is None:
            return Availability.OFF
        try:
            return rewinder.availability()
        except Exception:  # never a 500 for a disabled button; the log says why
            logger.exception("cannot tell whether the service can be asked to rewind")
            return Availability.OFF

    def _listed(who: Agent) -> list[Snapshot] | None:
        """That agent's volume's own list, or None: a rewind is only ever to a snapshot in it."""
        listing = _snapshot_source(who)
        if listing is None:
            return None
        try:
            return list(listing())
        except (SnapshotError, OSError) as failure:
            logger.warning("the snapshot list cannot be read: %s", failure)
            return None

    def _rewind_view(
        request: Request, t: Translator, status: int, view: str, **values: Any
    ) -> Response:
        """The rewind's step: a fragment for HTMX (always 200, or it would not be shown), the
        whole page otherwise (with the real status)."""
        for name in ("snap", "message", "undo"):
            values.setdefault(name, None)
        values.setdefault("agent_started", False)
        if request.headers.get("hx-request") == "true":
            return _page("rewind.html", request, active="snapshots", t=t, view=view, **values)
        return _page(
            "rewind_page.html",
            request,
            status=status,
            active="snapshots",
            t=t,
            view=view,
            **values,
        )

    def _not_now(
        request: Request, t: Translator, status: int, reason: str, **values: Any
    ) -> Response:
        return _rewind_view(request, t, status, "refused", reason=reason, **values)

    def _target(who: Agent, snapshot_id: str) -> tuple[Snapshot | None, str | None]:
        """The snapshot ``snapshot_id`` names if it is in that agent's list now; else why not."""
        listed = _listed(who)
        if listed is None:
            return None, "rewind.off.list"
        target = Snapshot.parse(snapshot_id) if len(snapshot_id) <= MAX_FIELD_CHARS else None
        if target is None or target not in listed:
            return None, "rewind.err.not_listed"
        return target, None

    @app.get(POST_PATH, dependencies=protected)
    def rewind_confirm(request: Request) -> Response:
        return _rewind_confirm(request, roster.main)

    @app.get("/agentes/{slug}" + POST_PATH, dependencies=protected)
    def agent_rewind_confirm(request: Request, slug: str) -> Response:
        return _rewind_confirm(request, _agent(slug))

    def _rewind_confirm(request: Request, who: Agent) -> Response:
        """The confirmation: the fixed notice, and a form with a ticket for this snapshot of this
        agent. It changes nothing, and it is the only way to get a ticket."""
        t = Translator(_language(request)[0])
        named = _shown(who)
        target, why = _target(who, request.query_params.get("id", ""))
        if target is None:
            return _not_now(request, t, 200, why or "rewind.err.not_listed", agent=named)
        if not who.source.watched:
            reason = f"rewind.off.{NOT_WATCHED}"
            return _not_now(request, t, 200, reason, snap=target, agent=named)
        state = _availability()
        if state is not Availability.READY:
            return _not_now(request, t, 200, f"rewind.off.{state}", snap=target, agent=named)
        lines = agent_lines if who.main else who.source.notice_lines
        return _rewind_view(
            request,
            t,
            200,
            "confirm",
            snap=target,
            agent=named,
            notice=rewind_notice(target.taken_at, now=clock(), tz=zone, agent_lines=lines),
            csrf=_csrf(request),
            ticket=tickets.issue(_bound(who, target.id)),
        )

    @app.post(POST_PATH, dependencies=[Depends(require_session)])
    async def rewind(request: Request) -> Response:
        """The rewind. The Guard already checked where it comes from and its size."""
        t = Translator(_language(request)[0])
        form = await _read_form(request, FORM_FIELDS, AGENT_FIELD)
        if form is None:
            return _not_now(request, t, 400, "rewind.err.form")
        if not _csrf_is(request, form["csrf"]):
            logger.warning("a rewind from the web was refused: wrong form token")
            return _not_now(request, t, 403, "rewind.err.form")
        who = _agent_in(form)
        named = _shown(who)
        lock = rewinding.setdefault(who.slug, threading.Lock())
        redeemed = tickets.redeem(form["ticket"], _bound(who, form["id"]))
        if redeemed is Redeemed.SPENT:  # a second click on the same form
            return _not_now(request, t, 400, "rewind.err.used", agent=named)
        if redeemed is not Redeemed.OK:
            if lock.locked():
                return _not_now(request, t, 409, "rewind.err.busy", agent=named)
            return _not_now(request, t, 400, "rewind.err.expired", agent=named)
        target, why = await asyncio.to_thread(_target, who, form["id"])
        if target is None:
            status = 503 if why == "rewind.off.list" else 400
            return _not_now(request, t, status, why or "", agent=named)
        state = await asyncio.to_thread(_availability)
        if state is not Availability.READY or rewinder is None:
            return _not_now(request, t, 503, f"rewind.off.{state}", snap=target, agent=named)
        ask = rewinder.rewind

        def run() -> tuple[str, dict[str, Any] | None]:
            # Taken and released in this thread, which runs the rewind to its end whatever the
            # browser does (a closed tab does not stop it), so the lock is held exactly as long
            # as the rewind and the next one waits for it.
            if not lock.acquire(blocking=False):
                return "busy", None
            try:
                return "asked", ask(target.id, **who.order)
            except ControlUnavailable:
                return "no_service", None
            except ControlOutcomeUnknown as error:
                logger.warning("a rewind from the web has no known outcome: %s", error)
                return "unknown", None
            except ControlError as error:
                logger.error("a rewind from the web was not sent: %s", error)
                return "untrusted", None
            finally:
                lock.release()

        what, reply = await asyncio.to_thread(run)
        if what == "busy":
            return _not_now(request, t, 409, "rewind.err.busy", snap=target, agent=named)
        if reply is None:
            status = 503 if what == "no_service" else 200
            return _rewind_view(
                request, t, status, "result", snap=target, outcome=what, agent=named
            )
        undo = Snapshot.parse(reply["undo"]) if isinstance(reply.get("undo"), str) else None
        return _rewind_view(
            request,
            t,
            200,
            "result",
            snap=target,
            agent=named,
            outcome=reply["outcome"],
            message=reply["message"],
            undo=undo,
            agent_started=reply.get("agent_started") is True,
        )

    # -- the Settings page (T12e) ----------------------------------------------------------

    setting_tickets = SettingTickets(clock)

    def _settings_state() -> Availability:
        if settings is None:
            return Availability.OFF
        try:
            return settings.availability()
        except Exception:  # never a 500 for a page that only says it cannot ask
            logger.exception("cannot tell whether the service can be asked about the settings")
            return Availability.OFF

    def _settings_rows() -> tuple[str, list[SecretView]]:
        """(state, the rows): the state says whether the rows come from the service."""
        state = _settings_state()
        if state is not Availability.READY or settings is None:
            return str(state), views(None)
        try:
            return str(state), views(settings.status())
        except ControlUnavailable:
            return str(Availability.NO_SERVICE), views(None)
        except ControlError as error:
            logger.warning("the settings cannot be read from the service: %s", error)
            return "unreadable", views(None)

    def _settings_view(
        request: Request, t: Translator, status: int, view: str, **values: Any
    ) -> Response:
        for name in ("row", "message", "outcome", "applied", "reason", "spend"):
            values.setdefault(name, None)
        return _page(
            "settings_step.html",
            request,
            status=status,
            active="settings",
            t=t,
            view=view,
            **values,
        )

    def _settings_refused(
        request: Request, t: Translator, status: int, reason: str, **values: Any
    ) -> Response:
        return _settings_view(request, t, status, "refused", reason=reason, **values)

    def _spend() -> SpendView | None:
        """The spending (T11), or None when the service cannot be asked or says nonsense."""
        if spend is None:
            return None
        try:
            if spend.availability() is not Availability.READY:
                return None
            return spend_view(spend.spend())
        except ControlError as error:
            logger.warning("the spending cannot be read from the service: %s", type(error).__name__)
            return None
        except Exception:  # never a 500 for a line of the panel
            logger.exception("reading the spending failed")
            return None

    @app.get(SETTINGS_PATH, dependencies=protected)
    def settings_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        state, rows = _settings_rows()
        return _page(
            "settings.html",
            request,
            active="settings",
            t=t,
            state=state,
            rows=rows,
            spend=_spend(),
        )

    def _settings_confirm(request: Request, action: str) -> Response:
        """The confirmation of one change: a form with a ticket for it. It changes nothing."""
        t = Translator(_language(request)[0])
        kind = request.query_params.get("tipo", "")
        if kind == BUDGET and action == "set":
            return _budget_confirm(request, t)
        if kind == PRICES and action == "set":
            return _prices_confirm(request, t)
        if kind not in KINDS:
            return _settings_refused(request, t, 200, "settings.err.kind")
        state, rows = _settings_rows()
        if state != str(Availability.READY):
            return _settings_refused(request, t, 200, f"settings.off.{state}")
        row = next(r for r in rows if r.kind == kind)
        if action == "clear" and not row.set:
            return _settings_refused(request, t, 200, "settings.err.not_set", row=row)
        replacing = action == "set" and row.set
        return _settings_view(
            request,
            t,
            200,
            f"confirm_{action}",
            row=row,
            replacing=replacing,
            csrf=_csrf(request),
            ticket=setting_tickets.issue(action, kind, replacing=replacing),
        )

    def _budget_confirm(request: Request, t: Translator) -> Response:
        """The spending caps' form (T11), with a one-time ticket bound to it. Changes nothing."""
        state = str(_settings_state())
        if state != str(Availability.READY):
            return _settings_refused(request, t, 200, f"settings.off.{state}")
        shown = _spend()
        if shown is None or not shown.available:
            return _settings_refused(request, t, 200, "settings.err.spend")
        return _settings_view(
            request,
            t,
            200,
            "confirm_budget",
            spend=shown,
            csrf=_csrf(request),
            ticket=setting_tickets.issue("set", BUDGET),
        )

    def _prices_confirm(request: Request, t: Translator) -> Response:
        """The new prices waiting for the owner (T11, security review B3), with a one-time
        ticket and the digest of what is shown: only those are accepted. Changes nothing."""
        state = str(_settings_state())
        if state != str(Availability.READY):
            return _settings_refused(request, t, 200, f"settings.off.{state}")
        shown = _spend()
        if shown is None or not shown.available or not shown.pending:
            return _settings_refused(request, t, 200, "settings.err.no_prices")
        return _settings_view(
            request,
            t,
            200,
            "confirm_prices",
            spend=shown,
            csrf=_csrf(request),
            ticket=setting_tickets.issue("set", PRICES),
        )

    async def _prices_save(request: Request, t: Translator, digest: str) -> Response:
        """The owner's yes. The Guard, the form's shape, CSRF and the ticket were checked by
        ``settings_save``; the service checks the digest against what waits now."""
        state = await asyncio.to_thread(_settings_state)
        if state is not Availability.READY or settings is None:
            return _settings_refused(request, t, 503, f"settings.off.{state}")
        client = settings

        def run() -> tuple[str, dict[str, Any] | None]:
            try:
                return "asked", client.accept_prices(digest)
            except ControlUnavailable:
                return "no_service", None
            except ControlOutcomeUnknown:
                logger.warning("accepting the new prices from the web has no known outcome")
                return "unknown", None
            except ControlError as error:
                logger.error("accepting the new prices was not sent: %s", type(error).__name__)
                return "untrusted", None

        what, reply = await asyncio.to_thread(run)
        row = SecretView(PRICES)
        if reply is None:
            status = 503 if what == "no_service" else 200
            return _settings_view(request, t, status, "result", row=row, outcome=what)
        return _settings_view(
            request,
            t,
            200 if reply["ok"] or reply["outcome"] != "invalid" else 409,
            "result",
            row=row,
            outcome=reply["outcome"],
            message=reply["message"],
        )

    async def _budget_save(request: Request, t: Translator, form: dict[str, str]) -> Response:
        """New caps from the form. The Guard, the form's shape, CSRF and the ticket were checked
        by ``settings_save``; the service checks the amounts again and records the change."""
        daily = form.get("diario", "").strip()
        monthly = form.get("mensual", "").strip()
        form.clear()
        if not cap_ok(daily) or not cap_ok(monthly) or not (daily or monthly):
            return _settings_refused(request, t, 400, "settings.err.cap")
        state = await asyncio.to_thread(_settings_state)
        if state is not Availability.READY or settings is None:
            return _settings_refused(request, t, 503, f"settings.off.{state}")
        client = settings

        def run() -> tuple[str, dict[str, Any] | None]:
            try:
                return "asked", client.set_budget(daily or None, monthly or None)
            except ControlUnavailable:
                return "no_service", None
            except ControlOutcomeUnknown:
                logger.warning("a change of the spending caps from the web has no known outcome")
                return "unknown", None
            except ControlError as error:
                logger.error("a change of the spending caps was not sent: %s", type(error).__name__)
                return "untrusted", None

        what, reply = await asyncio.to_thread(run)
        row = SecretView(BUDGET)
        if reply is None:
            status = 503 if what == "no_service" else 200
            return _settings_view(request, t, status, "result", row=row, outcome=what)
        return _settings_view(
            request,
            t,
            200 if reply["ok"] or reply["outcome"] != "invalid" else 400,
            "result",
            row=row,
            outcome=reply["outcome"],
            message=reply["message"],
        )

    @app.get(SETTINGS_PATH + "/cambiar", dependencies=protected)
    def settings_change(request: Request) -> Response:
        return _settings_confirm(request, "set")

    @app.get(SETTINGS_PATH + "/quitar", dependencies=protected)
    def settings_clear(request: Request) -> Response:
        return _settings_confirm(request, "clear")

    async def settings_save(request: Request) -> Response:
        """A change. The Guard already checked where it comes from and its size (and that the
        page is on at all). The value goes to the service and nowhere else: not to a log, not
        back to the page."""
        t = Translator(_language(request)[0])
        form = await _read_form(request, SETTINGS_FIELDS, SETTINGS_OPTIONAL, SETTINGS_LIMITS)
        if form is not None and form["tipo"] == BUDGET:
            # T11: the spending caps, with the same checks as a key (the Guard, CSRF, the ticket).
            if form["accion"] != "set" or set(form) != {*SETTINGS_FIELDS, "diario", "mensual"}:
                form.clear()
                return _settings_refused(request, t, 400, "settings.err.form")
            if not _csrf_is(request, form["csrf"]):
                form.clear()
                logger.warning("a change of the spending caps was refused: wrong form token")
                return _settings_refused(request, t, 403, "settings.err.form")
            redeemed, _ = setting_tickets.redeem(form["ticket"], "set", BUDGET)
            if redeemed is not Redeemed.OK:
                form.clear()
                spent = redeemed is Redeemed.SPENT
                reason = "settings.err.used" if spent else "settings.err.expired"
                return _settings_refused(request, t, 400, reason)
            return await _budget_save(request, t, form)
        if form is not None and form["tipo"] == PRICES:
            # T11 (B3): accepting the new prices, with the same checks as a key.
            digest = form.get("huella", "")
            shape = set(form) == {*SETTINGS_FIELDS, "huella"}
            if form["accion"] != "set" or not shape or not digest_ok(digest):
                form.clear()
                return _settings_refused(request, t, 400, "settings.err.form")
            if not _csrf_is(request, form["csrf"]):
                form.clear()
                logger.warning("accepting the new prices was refused: wrong form token")
                return _settings_refused(request, t, 403, "settings.err.form")
            redeemed, _ = setting_tickets.redeem(form["ticket"], "set", PRICES)
            form.clear()
            if redeemed is not Redeemed.OK:
                spent = redeemed is Redeemed.SPENT
                reason = "settings.err.used" if spent else "settings.err.expired"
                return _settings_refused(request, t, 400, reason)
            return await _prices_save(request, t, digest)
        if form is None or form["accion"] not in ACTIONS or form["tipo"] not in KINDS:
            return _settings_refused(request, t, 400, "settings.err.form")
        action, kind = form["accion"], form["tipo"]
        shape = {"valor", "chat"} if kind == TELEGRAM else {"valor"}
        given = set(form) - set(SETTINGS_FIELDS) - {"confirmo"}
        if (action == "set" and given != shape) or (
            action == "clear" and set(form) != set(SETTINGS_FIELDS)
        ):
            form.clear()
            return _settings_refused(request, t, 400, "settings.err.form")
        if not _csrf_is(request, form["csrf"]):
            form.clear()
            logger.warning("a change of the settings from the web was refused: wrong form token")
            return _settings_refused(request, t, 403, "settings.err.form")
        redeemed, replacing = setting_tickets.redeem(form["ticket"], action, kind)
        if redeemed is not Redeemed.OK:
            form.clear()
            reason = "settings.err.used" if redeemed is Redeemed.SPENT else "settings.err.expired"
            return _settings_refused(request, t, 400, reason)
        if replacing and form.get("confirmo") != "si":
            form.clear()
            return _settings_refused(request, t, 400, "settings.err.confirm")
        state = await asyncio.to_thread(_settings_state)
        if state is not Availability.READY or settings is None:
            form.clear()
            return _settings_refused(request, t, 503, f"settings.off.{state}")
        if await _touch_needed(request):
            form.clear()
            return _go_touch("ajustes")
        client = settings
        value = form.pop("valor", "").strip()
        chat = form.pop("chat", None)
        form.clear()

        def run() -> tuple[str, dict[str, Any] | None]:
            nonlocal value
            try:
                if action == "clear":
                    return "asked", client.clear_secret(kind)
                return "asked", client.set_secret(
                    kind, value, chat.strip() if chat is not None else None
                )
            except ControlUnavailable:
                return "no_service", None
            except ControlOutcomeUnknown:
                logger.warning("a change of the %s setting from the web has no known outcome", kind)
                return "unknown", None
            except ControlError as error:
                logger.error("a change of the %s setting from the web was not sent: %s", kind,
                             type(error).__name__)  # fmt: skip
                return "untrusted", None
            finally:
                value = ""

        what, reply = await asyncio.to_thread(run)
        value = chat = None  # nothing here keeps the key once it is sent
        row = SecretView(kind)
        if reply is None:
            status = 503 if what == "no_service" else 200
            return _settings_view(request, t, status, "result", row=row, outcome=what)
        status = 200 if reply["ok"] or reply["outcome"] != "refused" else 400
        return _settings_view(
            request,
            t,
            status,
            "result",
            row=row,
            outcome=reply["outcome"],
            applied=reply["applied"],
            message=reply["message"],
        )

    # The POST exists only when the page is on (`backtide web --ajustes`): without it, neither
    # the Guard nor the app has a door for it.
    settings_on = settings is not None and getattr(settings, "enabled", True) is True
    if settings_on:
        app.post(SETTINGS_POST_PATH, dependencies=[Depends(require_session)])(settings_save)

    # -- managing the agents (T26-6b, backtide.web.manage) ----------------------------------

    order_tickets = Tickets(clock)
    orders_on = agent_orders is not None and agent_orders.enabled is True
    order_book = OrderBook(agent_orders.ask) if orders_on and agent_orders is not None else None

    def _orders_state() -> Availability:
        return Availability.DISABLED if agent_orders is None else agent_orders.availability()

    def _agents_view() -> tuple[list[Row], tuple[Any, ...], str]:
        listing = _listing()
        running = {} if order_book is None else order_book.running()
        retired = () if listing is None else listing.retired
        return rows_of(list(roster), listing, running), retired, str(_orders_state())

    def _manage_step(
        request: Request, t: Translator, status: int, view: str, **values: Any
    ) -> Response:
        values.setdefault("outcome", "")
        return _page("manage_step.html", request, status=status, active="agents", t=t, view=view,
                     back=base + AGENTS_PATH, **values)  # fmt: skip

    def _manage_refused(request: Request, t: Translator, status: int, reason: str) -> Response:
        return _manage_step(request, t, status, "refused", reason=reason)

    def _new_form(
        request: Request, t: Translator, status: int, *, error: str = "", **typed: str
    ) -> Response:
        """The form: a slug, and two lists. Its ticket is what a POST has to come from."""
        return _manage_step(
            request, t, status, "new",
            csrf=_csrf(request),
            ticket=order_tickets.issue(CREATE),
            action=base + AGENT_CREATE_PATH,
            profiles=[(name, NAMED[name].version) for name in PROFILES],
            sizes=VOLUME_SIZES_GIB,
            pattern=SLUG.pattern,
            error=error,
            typed_slug=typed.get("slug", ""),
            typed_profile=typed.get("profile", ""),
            typed_size=typed.get("size", ""),
        )  # fmt: skip

    def _order_started(request: Request, t: Translator, order: Order | None, slug: str) -> Response:
        if order is None:
            running = order_book is not None and slug in order_book.running()
            reason = "manage.err.running" if running else "manage.err.busy"
            return _manage_refused(request, t, 409, reason)
        return RedirectResponse(
            f"{base}{AGENT_RUNNING_PATH}?{urlencode([('id', order.id)])}", status_code=303
        )

    @app.get(AGENTS_PATH, dependencies=protected)
    def agents_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        rows, retired, state = _agents_view()
        return _page("manage.html", request, active="agents", t=t, rows=rows, retired=retired,
                     state=state, stream=base + AGENTS_STREAM_PATH)  # fmt: skip

    @app.get(AGENTS_STREAM_PATH, dependencies=watching)
    def agents_stream(request: Request) -> Response:
        return StreamingResponse(
            _agents_stream(request, Translator(_language(request)[0])),
            media_type="text/event-stream",
            headers={"x-accel-buffering": "no"},
        )

    async def _agents_stream(request: Request, t: Translator) -> AsyncIterator[bytes]:
        """The list when it changes (D42: "Tarea en marcha" while it runs). It does not count as a
        use of the session: a tab left open must not keep it alive."""
        loop = asyncio.get_running_loop()
        signed_in = _session_watch(request)
        deadline = loop.time() + stream_seconds
        sent: tuple[Any, ...] | None = None
        last_sent = loop.time()
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            if not await signed_in(loop.time()):
                yield _sse("session", "expired", None)
                return
            await _roster_now()
            rows, retired, state = await asyncio.to_thread(_agents_view)
            key = (rows, retired, state)
            if key != sent:
                sent = key
                last_sent = loop.time()
                html = env.get_template("manage_list.html").render(
                    **_helpers(t, clock()), rows=rows, retired=retired, state=state
                )
                yield _sse("list", html, None)
            elif loop.time() - last_sent >= keepalive:
                last_sent = loop.time()
                yield b": keepalive\n\n"
            await asyncio.sleep(poll_interval)

    @app.get(AGENT_NEW_PATH, dependencies=protected)
    async def agent_new(request: Request) -> Response:
        t = Translator(_language(request)[0])
        state = await asyncio.to_thread(_orders_state)
        if state is not Availability.READY:
            return _manage_refused(request, t, 200, f"manage.off.{state}")
        if await _touch_needed(request):
            return _go_touch("agentes-nuevo")
        return _new_form(request, t, 200)

    @app.get(AGENT_ORDER_PATH, dependencies=protected)
    async def agent_order_confirm(request: Request) -> Response:
        """The confirmation of one order about one agent, and the only way to its ticket."""
        t = Translator(_language(request)[0])
        verb = request.query_params.get("v", "")
        who = roster.get(request.query_params.get("agente", ""))
        if verb not in VERBS or who is None:
            return _manage_refused(request, t, 404, "manage.err.nobody")
        if who.main:
            return _manage_refused(request, t, 200, "manage.err.main")
        state = await asyncio.to_thread(_orders_state)
        if state is not Availability.READY:
            return _manage_refused(request, t, 200, f"manage.off.{state}")
        if verb == TYPED_VERB and await _touch_needed(request):
            return _go_touch("agentes")
        return _order_confirm(request, t, 200, verb, who)

    def _order_confirm(
        request: Request, t: Translator, status: int, verb: str, who: Agent, *, error: str = ""
    ) -> Response:
        return _manage_step(
            request, t, status, "confirm",
            verb=verb,
            whose=who,
            csrf=_csrf(request),
            ticket=order_tickets.issue(f"{verb}:{who.slug}"),
            action=base + AGENT_ORDER_PATH,
            typed_verb=TYPED_VERB,
            error=error,
        )  # fmt: skip

    async def agent_create(request: Request) -> Response:
        """Create one. A slug, and a word and a number of their lists: the service checks them
        again, with the session and the key, and writes the agent's file from its own template."""
        t = Translator(_language(request)[0])
        form = await _read_form(request, CREATE_FIELDS)
        if form is None:
            return _manage_refused(request, t, 400, "manage.err.form")
        if not _csrf_is(request, form["csrf"]):
            logger.warning("creating an agent from the web was refused: wrong form token")
            return _manage_refused(request, t, 403, "manage.err.form")
        typed = {"slug": form["slug"], "profile": form["perfil"], "size": form["tamano"]}
        size = int(form["tamano"]) if form["tamano"] in map(str, VOLUME_SIZES_GIB) else None
        try:
            check_slug(form["slug"])
        except SlugError:
            return _new_form(request, t, 400, error="manage.err.slug", **typed)
        if form["perfil"] not in PROFILES or size is None:
            return _new_form(request, t, 400, error="manage.err.list", **typed)
        if await _touch_needed(request):
            return _go_touch("agentes-nuevo")
        redeemed = order_tickets.redeem(form["ticket"], CREATE)
        if redeemed is not Redeemed.OK:
            return _manage_refused(
                request, t, 400,
                "manage.err.used" if redeemed is Redeemed.SPENT else "manage.err.expired",
            )  # fmt: skip
        state = await asyncio.to_thread(_orders_state)
        if state is not Availability.READY or order_book is None:
            return _manage_refused(request, t, 503, f"manage.off.{state}")
        asked = {"cmd": ORDER_COMMAND, "slug": form["slug"], "profile": form["perfil"],
                 "volume_gib": size}  # fmt: skip
        order = order_book.start(CREATE, form["slug"], asked, request.state.session.id)
        if order is not None:
            await asyncio.to_thread(order.done.wait, QUICK)
        return _order_started(request, t, order, form["slug"])

    async def agent_order(request: Request) -> Response:
        """Start, stop, freeze, thaw or delete one, past its confirmation. It answers at once and
        the order goes on: a stop can take minutes, and a page must not hang on it."""
        t = Translator(_language(request)[0])
        form = await _read_form(request, ORDER_FIELDS, ORDER_OPTIONAL)
        if form is None:
            return _manage_refused(request, t, 400, "manage.err.form")
        if not _csrf_is(request, form["csrf"]):
            logger.warning("an order from the web was refused: wrong form token")
            return _manage_refused(request, t, 403, "manage.err.form")
        verb, who = form["v"], roster.get(form["agente"])
        if verb not in VERBS or who is None:
            return _manage_refused(request, t, 404, "manage.err.nobody")
        if who.main:
            return _manage_refused(request, t, 400, "manage.err.main")
        if verb == TYPED_VERB:
            if await _touch_needed(request):
                return _go_touch("agentes")
            if not token_matches(form.get("escrito"), who.slug):
                return _order_confirm(request, t, 400, verb, who, error="manage.err.typed")
        redeemed = order_tickets.redeem(form["ticket"], f"{verb}:{who.slug}")
        if redeemed is not Redeemed.OK:
            return _manage_refused(
                request, t, 400,
                "manage.err.used" if redeemed is Redeemed.SPENT else "manage.err.expired",
            )  # fmt: skip
        state = await asyncio.to_thread(_orders_state)
        if state is not Availability.READY or order_book is None:
            return _manage_refused(request, t, 503, f"manage.off.{state}")
        asked: dict[str, Any] = {"cmd": VERBS[verb], "agent": who.slug}
        if verb == TYPED_VERB:
            asked["typed"] = form.get("escrito", "")
        order = order_book.start(verb, who.slug, asked, request.state.session.id)
        if order is not None:
            await asyncio.to_thread(order.done.wait, QUICK)
        return _order_started(request, t, order, who.slug)

    if orders_on:
        app.post(AGENT_CREATE_PATH, dependencies=[Depends(require_session)])(agent_create)
        app.post(AGENT_ORDER_PATH, dependencies=[Depends(require_session)])(agent_order)

    @app.get(AGENT_RUNNING_PATH, dependencies=protected)
    def agent_order_running(request: Request) -> Response:
        """How an order goes: what the service answered, or that it is not over. A web that
        restarted has forgotten it, and says so: the list is what the service says now."""
        t = Translator(_language(request)[0])
        given = request.query_params.get("id", "")
        order = (
            None if order_book is None or len(given) > MAX_FIELD_CHARS else order_book.find(given)
        )
        if order is None:
            return _manage_step(request, t, 200, "lost")
        slug = order.slug
        whose = roster.get(slug)
        if not order.done.is_set():
            return _manage_step(
                request, t, 200, "running", verb=order.verb, slug=slug, whose=whose,
                refresh=ORDER_REFRESH,
                long=time.monotonic() - order.started >= LONG_AFTER,
            )  # fmt: skip
        reply = order.reply or {}
        outcome = reply.get("outcome")
        return _manage_step(
            request, t, 200, "result", verb=order.verb, slug=slug, whose=whose,
            what=order.what,
            ok=reply.get("ok") is True,
            outcome=outcome if isinstance(outcome, str) else "",
            message=reply.get("message"),
            command=restart_command(order.fields) if outcome == "needs_restart" else "",
        )  # fmt: skip

    # -- the held requests (T10-5) ---------------------------------------------------------

    def _hold_view(
        request: Request, t: Translator, status: int, view: str, **values: Any
    ) -> Response:
        for name in ("hold", "batch", "trust", "outcome", "message", "reason", "verb", "hold_out",
                     "trust_note", "others"):  # fmt: skip
            values.setdefault(name, None)
        return _page(
            "hold_step.html", request, status=status, active="holds", t=t, view=view, **values
        )

    def _hold_refused(
        request: Request, t: Translator, status: int, reason: str, agent: Agent | None = None
    ) -> Response:
        return _hold_view(request, t, status, "refused", reason=reason, agent=agent)

    def _lists_of(who: Agent) -> tuple[list[BatchView] | None, list[TrustView] | None]:
        """That agent's active batches and the recipients trusted from here, from the service
        (None: not asked, or it could not say)."""
        if _approvals() is not Availability.READY or approver is None:
            return None, None
        try:
            batches = batch_views(approver.batches(**who.order), who.slug)
        except ControlError as error:
            logger.warning("the batches cannot be listed: %s", error)
            batches = None
        try:
            trusted = trust_views(approver.trusted(**who.order), who.slug)
        except ControlError as error:
            logger.warning("the trusted recipients cannot be listed: %s", error)
            trusted = None
        return batches, trusted

    def _lists() -> tuple[list[BatchView] | None, list[TrustView] | None]:
        """Those of every agent the service is watching, each saying whose. None only if nothing
        could be read: one agent that cannot say does not hide what the others have."""
        read = [_lists_of(who) for who in roster if who.source.watched]
        kept = [batches for batches, _ in read if batches is not None]
        trust = [trusted for _, trusted in read if trusted is not None]
        return (
            [view for views in kept for view in views] if kept else None,
            [view for views in trust for view in views] if trust else None,
        )

    @app.get(HOLDS_PATH, dependencies=protected)
    def holds_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        requests, now, failed = _requests()
        batches, trusted = _lists()
        return _page(
            "holds.html",
            request,
            active="holds",
            t=t,
            requests=requests,
            stale=failed,
            now=now,
            batches=batches,
            trusted=trusted,
        )

    @app.get(HOLDS_PATH + "/ver", dependencies=protected)
    def hold_detail(request: Request) -> Response:
        return _hold_detail(request, roster.main)

    @app.get("/agentes/{slug}" + HOLDS_PATH + "/ver", dependencies=protected)
    def agent_hold_detail(request: Request, slug: str) -> Response:
        return _hold_detail(request, _agent(slug))

    def _hold_detail(request: Request, who: Agent) -> Response:
        """ "Ver": the hold as that agent's black box keeps it (the 2 KiB excerpt, every recipient
        and attachment). Reads only; the agent's text is shown as the agent's."""
        t = Translator(_language(request)[0])
        named = _shown(who)
        hold_id = request.query_params.get("id", "")
        if not id_fits(APPROVE, hold_id):
            return _hold_refused(request, t, 404, "hold.err.unknown", agent=named)
        listed = _find_hold(who, hold_id)
        event = None
        try:
            if listed is not None and listed.seq is not None:
                rows = who.reader.events(since_seq=listed.seq - 1, limit=1)
                event = held_event(rows, hold_id)
            if event is None:
                rows = who.reader.events(newest_first=True, limit=BOX_ROWS)
                event = held_event(rows, hold_id)
        except BoxUnavailable:
            event = None
        if event is None and listed is None:
            return _hold_refused(request, t, 404, "hold.err.unknown", agent=named)
        return _page(
            "hold_view.html",
            request,
            active="holds",
            t=t,
            agent=named,
            hold=listed,
            detail=None if event is None else detail_of(event),
            risk=listed.risk if listed is not None else (event.risk if event else 0),
            hold_id=hold_id,
            now=clock(),
        )

    @app.get(DECIDE_PATH, dependencies=protected)
    def decide_confirm(request: Request) -> Response:
        return _decide_confirm(request, roster.main)

    @app.get("/agentes/{slug}" + DECIDE_PATH, dependencies=protected)
    def agent_decide_confirm(request: Request, slug: str) -> Response:
        return _decide_confirm(request, _agent(slug))

    def _decide_confirm(request: Request, who: Agent) -> Response:
        """The confirmation of one decision: what it is, on which agent, and a form with a ticket
        bound to that verb, that agent and that id. It changes nothing, and it is the only way to
        get a ticket."""
        t = Translator(_language(request)[0])
        named = _shown(who)
        verb, subject = request.query_params.get("v", ""), request.query_params.get("id", "")
        if not id_fits(verb, subject):
            return _hold_refused(request, t, 200, "hold.err.form", agent=named)
        state = _approvals()
        if state is not Availability.READY:
            return _hold_refused(request, t, 200, f"hold.off.{state}", agent=named)
        values: dict[str, Any] = {"verb": verb, "csrf": _csrf(request), "agent": named}
        if verb in (APPROVE, REJECT, TRUST):
            listed, _now, _failed = _requests()
            found = [r for r in listed or () if r.agent == who.slug]
            hold = next((r for r in found if r.id == subject), None)
            if hold is None:
                return _hold_refused(request, t, 200, "hold.err.unknown", agent=named)
            if verb == TRUST and not hold.trustable:
                return _hold_refused(request, t, 200, "hold.err.not_trustable", agent=named)
            values["hold"] = hold
            if verb == TRUST:  # our notes: who reads it, and what is still held (final review)
                values["trust_note"] = trust_note(hold)
                values["others"] = same_recipient(hold, found)
            values["now"] = clock()
            ticket = decision_tickets.issue(verb, _bound(who, subject), until=hold.expires_at)
        else:
            batches, trusted = _lists_of(who)
            if verb == REVOKE:
                found = next((b for b in batches or [] if b.rule_id == subject), None)
                values["batch"] = found
            else:
                found = next((x for x in trusted or [] if x.trust_id == subject), None)
                values["trust"] = found
            if found is None:
                return _hold_refused(request, t, 200, "hold.err.unknown", agent=named)
            ticket = decision_tickets.issue(verb, _bound(who, subject))
        return _hold_view(request, t, 200, "confirm", ticket=ticket, subject=subject, **values)

    async def decide(request: Request) -> Response:
        """A decision. The Guard already checked where it comes from and its size (and that
        this web may decide at all)."""
        t = Translator(_language(request)[0])
        form = await _read_form(request, DECIDE_FIELDS, (*DECIDE_OPTIONAL, *AGENT_FIELD))
        if form is None or not id_fits(form["v"], form["id"]):
            return _hold_refused(request, t, 400, "hold.err.form")
        verb, subject = form["v"], form["id"]
        if not _csrf_is(request, form["csrf"]):
            logger.warning("a decision from the web was refused: wrong form token")
            return _hold_refused(request, t, 403, "hold.err.form")
        who = _agent_in(form)
        named = _shown(who)
        redeemed = decision_tickets.redeem(form["ticket"], verb, _bound(who, subject))
        if redeemed is Redeemed.SPENT:
            return _hold_refused(request, t, 400, "hold.err.used", agent=named)
        if redeemed is not Redeemed.OK:
            return _hold_refused(request, t, 400, "hold.err.expired", agent=named)
        if verb == TRUST and form.get("confirmo") != "si":
            return _hold_refused(request, t, 400, "hold.err.confirm", agent=named)
        if verb != TRUST and "confirmo" in form:
            return _hold_refused(request, t, 400, "hold.err.form", agent=named)
        state = await asyncio.to_thread(_approvals)
        if state is not Availability.READY or approver is None:
            return _hold_refused(request, t, 503, f"hold.off.{state}", agent=named)
        if verb == TRUST and await _touch_needed(request):
            return _go_touch("peticiones")
        client = approver

        def run() -> tuple[str, dict[str, Any] | None]:
            try:
                if verb in (APPROVE, REJECT):
                    verdict = "approve" if verb == APPROVE else "reject"
                    return "asked", client.decide(subject, verdict, **who.order)
                if verb == TRUST:
                    return "asked", client.trust(subject, **who.order)
                if verb == REVOKE:
                    return "asked", client.end_batch(subject, **who.order)
                return "asked", client.untrust(subject, **who.order)
            except ControlUnavailable:
                return "no_service", None
            except ControlOutcomeUnknown as error:
                logger.warning("a decision from the web has no known outcome: %s", error)
                return "unknown_outcome", None
            except ControlError as error:
                logger.error("a decision from the web was not sent: %s", error)
                return "untrusted", None

        what, reply = await asyncio.to_thread(run)
        if reply is None:
            status = 503 if what == "no_service" else 200
            return _hold_view(request, t, status, "result", verb=verb, outcome=what, agent=named)
        status = 400 if reply["outcome"] == "refused" else 200
        return _hold_view(
            request,
            t,
            status,
            "result",
            verb=verb,
            agent=named,
            outcome=str(reply["outcome"]),
            message=str(reply["message"]),
            hold_out=reply.get("hold"),
        )

    # The POST exists only with `backtide web --aprobar` (decision 10): without it, neither the
    # Guard nor the app has a door for it.
    approvals_on = approver is not None and getattr(approver, "enabled", False) is True
    if approvals_on:
        app.post(DECIDE_PATH, dependencies=[Depends(require_session)])(decide)

    # -- the chat (T26-5b) -----------------------------------------------------------------

    talk_on = tasks is not None and getattr(tasks, "enabled", False) is True

    def _talk_state(who: Agent) -> str:
        """Whether this agent can be asked now: "ready", or why not. Asked when drawn."""
        if tasks is None:
            return str(Availability.OFF)
        try:
            state = tasks.availability()
        except Exception:  # never a 500 for a page that only says it cannot ask
            logger.exception("cannot tell whether the service can be asked about the tasks")
            return str(Availability.OFF)
        if state is Availability.READY and not who.source.watched:
            return NOT_WATCHED
        return str(state)

    def _task_view(who: Agent, entry: dict[str, Any]) -> TaskView:
        """A line of the list, with its answer once it ended. What cannot be read is said so, and
        the stream asks again; a reply about a task only says "unknown" if the service forgot it.
        Only ever an error's type in the log: what was asked or answered is never there."""
        if entry["outcome"] == RUNNING or tasks is None:
            return view_of(entry)
        try:
            status = tasks.status(entry["task"], **who.order)
        except ControlError as error:
            logger.warning("the chat cannot read a task's end: %s", type(error).__name__)
            return view_of(entry)
        if status["ok"] is not True and status["outcome"] != UNKNOWN:
            logger.warning("the service refused the chat a task's end")
            return view_of(entry)
        return view_of(entry, status)

    def _task_views(who: Agent) -> tuple[list[TaskView], bool]:
        """This agent's tasks, the newest first, and whether the list could not be read."""
        if tasks is None:
            return [], False
        try:
            entries = tasks.tasks(**who.order)
        except ControlError as error:
            logger.warning("the chat cannot list the tasks: %s", type(error).__name__)
            return [], True
        return [_task_view(who, entry) for entry in reversed(entries)], False

    def _talk_page(
        request: Request,
        who: Agent,
        *,
        status: int = 200,
        asked: str = "",
        error: str | None = None,
        said: str = "",
    ) -> Response:
        """The page. A POST that did not give its task comes back here with what was typed."""
        t = Translator(_language(request)[0])
        state = _talk_state(who)
        views, failed = _task_views(who) if state == Availability.READY else ([], False)
        return _page(
            "talk.html",
            request,
            status=status,
            active="talk",
            t=t,
            agent=who,
            tasks=views,
            talk_state=state,
            failed=failed,
            running=sum(1 for one in views if not one.ended),
            known=known_id({one.id: one.ended and not one.unread for one in reversed(views)}),
            send=base + TALK_SEND_PATH,
            stop=base + TALK_STOP_PATH,
            csrf=_csrf(request),
            max_prompt=MAX_PROMPT,
            asked=asked,
            error=error,
            said=said,
        )

    @app.get(TALK_PATH, dependencies=protected)
    def talk_page(request: Request) -> Response:
        return _talk_page(request, roster.main)

    @app.get("/agentes/{slug}" + TALK_PATH, dependencies=protected)
    def agent_talk_page(request: Request, slug: str) -> Response:
        return _talk_page(request, _agent(slug))

    async def talk_send(request: Request) -> Response:
        """Give the agent a task. The Guard already checked where it comes from and its size."""
        form = await _read_form(
            request,
            ("csrf", "pedido"),
            (*AGENT_FIELD, "seguir"),
            limits={"pedido": 2 * MAX_PROMPT},  # each line break comes as two: see below
            max_bytes=MAX_PROMPT_FORM_BYTES,
            free=("pedido",),
        )
        if form is None:
            return await asyncio.to_thread(
                _talk_page, request, roster.main, status=400, error="talk.err.form"
            )
        if not _csrf_is(request, form["csrf"]):
            logger.warning("a task from the web was refused: wrong form token")
            return await asyncio.to_thread(
                _talk_page, request, roster.main, status=403, error="talk.err.form"
            )
        who = _agent_in(form)
        asked = form["pedido"].replace("\r\n", "\n")

        def again(status: int, error: str, said: str = "") -> Any:
            return asyncio.to_thread(
                _talk_page, request, who, status=status, asked=asked, error=error, said=said
            )

        if not asked.strip():
            return await again(400, "talk.err.empty")
        if len(asked) > MAX_PROMPT:
            return await again(400, "talk.err.long")
        if await asyncio.to_thread(_talk_state, who) != Availability.READY or tasks is None:
            return await again(503, "talk.err.not_now")
        ask = tasks.start
        order = who.order

        def run() -> dict[str, Any] | str:
            try:
                return ask(asked, resume="seguir" in form, **order)
            except ControlOutcomeUnknown as error:
                logger.warning("a task from the web has no known outcome: %s", type(error).__name__)
                return "talk.err.unknown"
            except ControlError as error:
                logger.warning("a task from the web was not sent: %s", type(error).__name__)
                return "talk.err.not_now"

        reply = await asyncio.to_thread(run)
        if isinstance(reply, str):
            return await again(503, reply)
        if reply["ok"] is not True:
            return await again(409, "talk.err.refused", said=reply["message"])
        return RedirectResponse(f"{who.base}{TALK_PATH}", status_code=303)

    async def talk_stop(request: Request) -> Response:
        """Stop a task inside the agent (a decision that can be undone: docs/47 section 7.1). The
        service stops every one that runs in that agent, as Ctrl-C does: the page says so."""
        form = await _read_form(request, ("csrf", "tarea"), AGENT_FIELD)
        if form is None or not is_task_id(form["tarea"]):
            return await asyncio.to_thread(
                _talk_page, request, roster.main, status=400, error="talk.err.form"
            )
        if not _csrf_is(request, form["csrf"]):
            logger.warning("a task's stop from the web was refused: wrong form token")
            return await asyncio.to_thread(
                _talk_page, request, roster.main, status=403, error="talk.err.form"
            )
        who = _agent_in(form)
        if await asyncio.to_thread(_talk_state, who) != Availability.READY or tasks is None:
            return await asyncio.to_thread(
                _talk_page, request, who, status=503, error="talk.err.not_now"
            )
        ask = tasks.stop
        order = who.order
        lock = stopping.setdefault(who.slug, threading.Lock())
        if not lock.acquire(blocking=False):  # the service stops them all: one ask is enough
            return await asyncio.to_thread(
                _talk_page, request, who, status=409, error="talk.err.stopping"
            )
        done = threading.Event()
        failed: list[bool] = []

        def run() -> None:
            # Taken above and released here, in the thread that waits for the service to its end
            # (up to two minutes), whatever the browser does: the next stop waits for this one.
            try:
                failed.append(not ask(form["tarea"], **order))
            except ControlError as error:
                logger.warning("a task's stop from the web failed: %s", type(error).__name__)
                failed.append(True)
            except Exception:  # said, with its trace: nobody knows how far it got
                logger.exception("a task's stop from the web failed")
                failed.append(True)
            finally:
                lock.release()
                done.set()

        # With this request's context: it carries the session the service wants with the stop.
        context = contextvars.copy_context()
        thread = threading.Thread(
            target=context.run, args=(run,), name=f"backtide-web-stop-{who.slug}", daemon=True
        )
        try:
            thread.start()
        except RuntimeError as error:  # no more threads: it never was a stop
            lock.release()
            logger.error("a task's stop from the web could not start its thread: %s", error)
            return await asyncio.to_thread(
                _talk_page, request, who, status=503, error="talk.err.stop"
            )
        # A moment, so that a refusal reaches the page that asked; past it, the page goes on and
        # the stream shows how the task ends, which is the service's word and not ours.
        await asyncio.to_thread(done.wait, QUICK_STOP)
        if done.is_set() and failed == [True]:
            return await asyncio.to_thread(
                _talk_page, request, who, status=503, error="talk.err.stop"
            )
        return RedirectResponse(f"{who.base}{TALK_PATH}", status_code=303)

    if talk_on:
        app.post(TALK_SEND_PATH, dependencies=[Depends(require_session)])(talk_send)
        app.post(TALK_STOP_PATH, dependencies=[Depends(require_session)])(talk_stop)

    def _render_task(t: Translator, who: Agent, view: TaskView, csrf: str, *, oob: bool) -> str:
        return env.get_template("talk_item.html").render(
            **_helpers(t, clock(), who),
            task=view,
            oob=oob,
            csrf=csrf,
            stop=base + TALK_STOP_PATH,
        )

    def _render_talk_state(t: Translator, who: Agent, running: int, failed: bool) -> str:
        return env.get_template("talk_state.html").render(
            **_helpers(t, clock(), who), running=running, failed=failed
        )

    def _task_lost(t: Translator, task_id: str) -> str:
        """A line that was running and that the service no longer knows (it restarted): what was
        asked stays on the page, with the word for it."""
        return env.get_template("talk_lost.html").render(t=t, task_id=task_id)

    async def _talk_stream(
        request: Request, t: Translator, who: Agent, known: dict[str, bool]
    ) -> AsyncIterator[bytes]:
        """The chat as it changes: a new line, the end of one (each read once, ``known``) and how
        many are running. Every question goes with the session of the page that asks."""
        ACTING_SESSION.set(request.state.session.id)  # for the threads it asks the service from
        csrf = _csrf(request)
        loop = asyncio.get_running_loop()
        # Before every read, not once a minute: a read with a dead session is a WARNING, recorded
        # and alerted as what a web taken over would do, and a tab left open would say it every
        # second.
        signed_in = _session_watch(request, every=0.0)
        deadline = loop.time() + stream_seconds
        last_sent = loop.time()
        sent_state: tuple[int, bool] | None = None
        order = who.order
        if tasks is None:
            return
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            if not await signed_in(loop.time()):
                yield _sse("session", "expired", None)
                return
            pieces: list[str] = []
            try:
                entries = await asyncio.to_thread(tasks.tasks, **order)
                failed = False
            except ControlError as error:
                logger.warning("the chat cannot list the tasks: %s", type(error).__name__)
                entries, failed = [], True
            # The newest first: "afterbegin" puts a message's lines at the top, in its order.
            for entry in reversed(entries):
                task_id, ended = entry["task"], entry["outcome"] != RUNNING
                had = known.get(task_id)
                if had is True or (had is False and not ended):
                    continue
                view = await asyncio.to_thread(_task_view, who, entry)
                known[task_id] = view.ended and not view.unread
                if view.unread and had is not None:  # the page has this already: look again
                    continue
                pieces.append(
                    await asyncio.to_thread(_render_task, t, who, view, csrf, oob=had is not None)
                )
            if not failed:
                listed = {entry["task"] for entry in entries}
                for task_id, had in list(known.items()):
                    if not had and task_id not in listed:
                        pieces.append(_task_lost(t, task_id))
                        known[task_id] = True
            now_t = loop.time()
            if pieces:
                yield _sse("tasks", "\n".join(pieces), known_id(known))
                last_sent = now_t
            running = sum(1 for ended in known.values() if not ended)
            if (running, failed) != sent_state:
                sent_state = (running, failed)
                yield _sse("talk-state", _render_talk_state(t, who, running, failed), None)
                last_sent = now_t
            if now_t - last_sent >= keepalive:
                last_sent = now_t
                yield b": keepalive\n\n"
            await asyncio.sleep(poll_interval)

    def _open_talk_stream(request: Request, who: Agent, seen: str) -> Response:
        resume = request.headers.get("last-event-id", "")
        known = known_of(resume or seen)
        t = Translator(_language(request)[0])
        return StreamingResponse(
            _talk_stream(request, t, who, known),
            media_type="text/event-stream",
            headers={"x-accel-buffering": "no"},
        )

    @app.get(TALK_PATH + "/stream", dependencies=watching)
    def talk_stream(request: Request, visto: str = "") -> Response:
        return _open_talk_stream(request, roster.main, visto)

    @app.get("/agentes/{slug}" + TALK_PATH + "/stream", dependencies=watching)
    def agent_talk_stream(request: Request, slug: str, visto: str = "") -> Response:
        return _open_talk_stream(request, _agent(slug), visto)

    # -- the stream ------------------------------------------------------------------------

    def _session_watch(
        request: Request, every: float | None = None
    ) -> Callable[[float], Awaitable[bool]]:
        """For an open stream: does its session still live? Asked of the service at most every
        ``session_recheck`` seconds (or ``every``), without counting as a use, so "Salir", "Cerrar
        todas" or the end of the session stop a tab that is open (T26-3a-2)."""
        last = [asyncio.get_running_loop().time()]
        wait = session_recheck if every is None else every

        async def alive(now: float) -> bool:
            if now - last[0] < wait:
                return True
            last[0] = now
            cookie = request.headers.get("cookie")
            try:
                return await asyncio.to_thread(access.session_of, cookie, use=False) is not None
            except SessionsBusy:  # not known now: it ends here, and the browser asks again
                return False

        return alive

    async def _stream(
        request: Request, t: Translator, start: int, agent: Agent
    ) -> AsyncIterator[bytes]:
        loop = asyncio.get_running_loop()
        signed_in = _session_watch(request)
        deadline = loop.time() + stream_seconds
        narrator = Narrator()
        seen: set[int] = set()
        seq = start
        failing = False
        last_sent = last_tide = loop.time()
        fresh_tide = False
        reader_ = agent.reader
        # The page saw nothing: begin near the end, not at the beginning, also when the box
        # can only be read later (code review of 2026-10-29, W3: it replayed the whole history).
        unanchored = start == 0
        try:
            if unanchored:
                seq = max(0, await asyncio.to_thread(reader_.head_seq) - SHOWN_LINES)
                unanchored = False
            else:  # rebuild the open burst the page ended on, so it keeps growing in place
                primed = await asyncio.to_thread(_recent, reader_, PRIME_EVENTS, start)
                seen = {line.id for line in narrator.feed(reversed(primed))}
        except BoxUnavailable:
            failing = True
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            if not await signed_in(loop.time()):
                yield _sse("session", "expired", None)
                return
            try:
                if unanchored:
                    seq = max(0, await asyncio.to_thread(reader_.head_seq) - SHOWN_LINES)
                    unanchored = False
                batch = await asyncio.to_thread(reader_.events, since_seq=seq, limit=STREAM_BATCH)
                if failing:
                    logger.info("the black box can be read again")
                failing = False
            except BoxUnavailable as problem:
                if not failing:
                    logger.warning("the web cannot read the black box: %s", problem)
                failing = True
                batch = []
            now_t = loop.time()
            if batch:
                seq = batch[-1].seq
                changed = narrator.feed(batch)
                html = "\n".join(
                    env.get_template("line.html").render(
                        **_helpers(t, clock(), agent), line=line, oob=line.id in seen
                    )
                    for line in changed
                )
                seen.update(line.id for line in changed)
                yield _sse("lines", html, seq)
                if any(e.source is Source.SYSTEM and e.action in STATE_ACTIONS for e in batch):
                    yield _sse("state", await asyncio.to_thread(_render_state, t, agent), None)
                if any(e.source is Source.SNAPSHOT and e.action == "take" for e in batch):
                    last_tide, fresh_tide = float("-inf"), True
                last_sent = now_t
            if now_t - last_tide >= TIDE_REFRESH:
                last_tide = now_t
                yield _sse(
                    "tide", await asyncio.to_thread(_render_tide, t, agent, fresh_tide), None
                )
                fresh_tide = False
                last_sent = now_t
            if now_t - last_sent >= keepalive:
                last_sent = now_t
                yield b": keepalive\n\n"
            await asyncio.sleep(poll_interval)

    def _render_state(t: Translator, agent: Agent) -> str:
        return env.get_template("state.html").render(t=t, **_status_view(agent))

    def _render_tide(t: Translator, agent: Agent, fresh: bool = False) -> str:
        return env.get_template("tide.html").render(t=t, tide=_day_tide(agent, fresh=fresh))

    # -- the control room's stream ---------------------------------------------------------

    def _panel_feed(cards: Sequence[Card]) -> list[tuple[Agent, Line]]:
        """The newest lines of every agent, newest first: what the feed shows on load."""
        return merged_feed(cards, PANEL_FEED)

    def _render_card(t: Translator, one: Card) -> str:
        return env.get_template("card.html").render(**_helpers(t, clock()), c=one)

    def _render_requests(
        t: Translator, requests: Sequence[PendingRequest] | None, now: datetime, stale: bool
    ) -> str:
        return env.get_template("requests.html").render(
            **_helpers(t, now), requests=requests, now=now, stale=stale
        )

    def _render_feed(t: Translator, changed: Sequence[tuple[Agent, Line, bool]]) -> str:
        """The lines of one poll, every agent's, newest first (they go on top, in the order
        they started); a line already shown (``True``: a growing burst) replaces itself."""
        helpers = _helpers(t, clock())
        ordered = sorted(changed, key=lambda item: _started(item[0], item[1]), reverse=True)
        return "\n".join(
            env.get_template("panel_line.html").render(**helpers, who=who, line=line, oob=oob)
            for who, line, oob in ordered
        )

    async def _panel_stream(
        request: Request, t: Translator, starts: list[int], *, stale: bool = False
    ) -> AsyncIterator[bytes]:
        """Every agent's new lines (one feed), its card when it changes, and the requests.
        ``stale``: the position it was given is of another list of agents (or not one at all), so
        its numbers are nobody's here and that page's cards are not these: it loads again."""
        if stale:
            yield b"retry: 2000\n\n"
            yield _sse("roster", "changed", None)
            return
        loop = asyncio.get_running_loop()
        signed_in = _session_watch(request)
        deadline = loop.time() + stream_seconds
        agents = list(roster)
        if len(starts) != len(agents):
            starts = [0] * len(agents)
        narrators = [Narrator() for _ in agents]
        seen: list[set[int]] = [set() for _ in agents]
        seqs = list(starts)
        # Nothing counts as already shown: the first round sends the requests and every card
        # (code review of 2026-10-29, W1: a hold that came between the page and its stream, or
        # during a reconnect, never reached the panel and could time out unseen).
        sent_cards: dict[str, Any] = {}
        sent_requests: tuple[Any, ...] | None = None
        last_good: list[Any] | None = None
        last_sent = loop.time()
        last_requests = float("-inf")
        unanchored = [seq == 0 for seq in seqs]  # W3: begin at the end once it can be read
        for i, agent in enumerate(agents):
            try:
                if unanchored[i]:
                    seqs[i] = await asyncio.to_thread(agent.reader.head_seq)
                    unanchored[i] = False
                else:
                    primed = await asyncio.to_thread(_recent, agent.reader, PRIME_EVENTS, seqs[i])
                    seen[i] = {line.id for line in narrators[i].feed(reversed(primed))}
            except BoxUnavailable:
                pass
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            if not await signed_in(loop.time()):
                yield _sse("session", "expired", None)
                return
            now_t = loop.time()
            changed: list[tuple[Agent, Line, bool]] = []
            for i, agent in enumerate(agents):
                try:
                    if unanchored[i]:
                        seqs[i] = await asyncio.to_thread(agent.reader.head_seq)
                        unanchored[i] = False
                    batch = await asyncio.to_thread(
                        agent.reader.events, since_seq=seqs[i], limit=STREAM_BATCH
                    )
                except BoxUnavailable:
                    batch = []
                if not batch:
                    continue
                seqs[i] = batch[-1].seq
                for line in narrators[i].feed(batch):
                    changed.append((agent, line, line.id in seen[i]))
                    seen[i].add(line.id)
            moved = bool(changed)
            if moved:
                yield _sse("feed", _render_feed(t, changed), None)
            if moved or now_t - last_requests >= REQUESTS_EVERY:
                last_requests = now_t
                await _roster_now()
                if [a.slug for a in roster] != [a.slug for a in agents]:
                    # Other agents, so other cards: the page itself has to change (web.js).
                    yield _sse("roster", "changed", None)
                    return
                requests, now, failed = await asyncio.to_thread(_requests)
                if failed:
                    # Not "nothing waits": what could be read, and the rest of the last list
                    # read, said to be maybe old.
                    known = {(r.agent, r.id) for r in requests or ()}
                    older = [r for r in last_good or () if (r.agent, r.id) not in known]
                    requests = live_requests([*(requests or ()), *older], roster, now)
                else:
                    last_good = requests
                key = (_requests_key(requests), failed)
                if key != sent_requests:
                    sent_requests = key
                    yield _sse("requests", _render_requests(t, requests, now, failed), None)
                for one in await asyncio.to_thread(_cards, requests, now):
                    if sent_cards.get(one.agent.slug) != one.key:
                        sent_cards[one.agent.slug] = one.key
                        yield _sse(f"card-{one.agent.slug}", _render_card(t, one), None)
                last_sent = now_t
            if moved:
                # where each agent's feed is, so a reconnect goes on from here
                yield _sse("at", "", _heads_id(_roster_mark(agents), seqs))
                last_sent = now_t
            if now_t - last_sent >= keepalive:
                last_sent = now_t
                yield b": keepalive\n\n"
            await asyncio.sleep(poll_interval)

    post_paths = (
        POST_PATH,
        *(() if origin is not None else (SIGN_IN_PATH,)),
        SIGN_IN_KEY_BEGIN_PATH,
        SIGN_OUT_PATH,
        CLOSE_SESSIONS_PATH,
        KEYS_BEGIN_PATH,
        TOUCH_BEGIN_PATH,
    )
    large_post_paths = (
        KEYS_FINISH_PATH,
        SIGN_IN_KEY_FINISH_PATH,
        TOUCH_FINISH_PATH,
        KEY_REMOVE_PATH,
        KEY_RENAME_PATH,
    )
    if orders_on:
        post_paths += (AGENT_CREATE_PATH, AGENT_ORDER_PATH)
    if settings_on:
        post_paths += (SETTINGS_POST_PATH,)
    if approvals_on:
        post_paths += (DECIDE_PATH,)
    if talk_on:
        post_paths += (TALK_STOP_PATH,)
    return Guard(
        app,
        port=port,
        prefix=prefix,
        post_paths=post_paths,
        large_post_paths=large_post_paths,
        prompt_post_paths=(TALK_SEND_PATH,) if talk_on else (),
        origin=origin,
    )


# -- helpers ---------------------------------------------------------------------------------


def _recent(reader: BoxReader, count: int, up_to: int | None = None) -> list[Event]:
    """The newest ``count`` events (newest first), those up to seq ``up_to`` if given."""
    if up_to is not None:
        return reader.events(before_seq=up_to + 1, newest_first=True, limit=count)
    return reader.events(newest_first=True, limit=count)


async def _read_form(
    request: Request,
    fields: Sequence[str] = FORM_FIELDS,
    optional: Sequence[str] = (),
    limits: dict[str, int] | None = None,
    max_bytes: int = MAX_FORM_BYTES,
    free: Sequence[str] = (),
) -> dict[str, str] | None:
    """A form of ``fields`` (each once) and maybe some of ``optional`` (each once at most), every
    value short (``MAX_FIELD_CHARS``, or its own of ``limits``) and printable, but for those of
    ``free`` (what the owner writes to an agent has lines, and the service has its own rules for
    it); None for anything else. Read up to ``max_bytes`` whatever the request says its length is.
    Never logs."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_bytes:
            return None
    try:
        pairs = parse_qsl(
            body.decode("ascii"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=len(fields) + len(optional),
            errors="strict",
        )
    except ValueError:  # also UnicodeDecodeError, and more fields than allowed
        return None
    finally:
        del body
    form = dict(pairs)
    names = [name for name, _ in pairs]
    del pairs
    if len(names) != len(form) or not set(fields) <= set(form) <= {*fields, *optional}:
        return None
    sizes = limits or {}
    if any(
        len(value) > sizes.get(name, MAX_FIELD_CHARS) or not (name in free or value.isprintable())
        for name, value in form.items()
    ):
        return None
    return form


def _snapshot_window(shown: Sequence[Snapshot], now: datetime) -> timedelta:
    """The snapshots page draws the tide back to its oldest listed snapshot (whole hours, from
    one hour to thirty days), so every row has its mark and a preview shows how far it goes."""
    if not shown:
        return WINDOW
    oldest = now - min(s.taken_at for s in shown)
    hours = math.ceil(max(oldest, timedelta(0)) / timedelta(hours=1) + 0.25)
    return timedelta(hours=min(max(hours, 1), 30 * 24))


def _started(agent: Agent, line: Line) -> tuple[str, str, int]:
    """The order of the control room's feed: when a line began, then whose it is."""
    return (started(line), agent.slug, line.id)


def _requests_key(requests: Sequence[PendingRequest] | None) -> tuple[Any, ...] | None:
    return None if requests is None else tuple((r.agent, r.id, r.expires_at) for r in requests)


MAX_AGENTS_IN_ID = 64


def _roster_mark(agents: Iterable[Agent]) -> str:
    """Which list of agents a position is about (T26-6b): a number means nothing in another's box,
    and now the list changes from this very web."""
    slugs = "\n".join(agent.slug for agent in agents)
    return hashlib.sha256(slugs.encode()).hexdigest()[:ROSTER_MARK_CHARS]


def _heads(text: str, mark: str) -> list[int]:
    """The control room's position in every agent's box (``<mark>.12.0.345``, in roster order); an
    empty list for anything else, and for another list of agents."""
    given, _, rest = text.partition(".")
    if given != mark or not rest or len(rest) > 20 * MAX_AGENTS_IN_ID or not rest.isascii():
        return []
    parts = rest.split(".")
    if len(parts) > MAX_AGENTS_IN_ID or not all(p.isdigit() and len(p) < 19 for p in parts):
        return []
    return [int(p) for p in parts]


def _heads_id(mark: str, seqs: Sequence[int]) -> str:
    return ".".join((mark, *(str(s) for s in seqs)))


def _details_json(event: Event) -> str:
    return json.dumps(event.details, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def _seq(text: str) -> int:
    """A seq from a query string or header; anything else is 0 (start near the end)."""
    return int(text) if text.isascii() and text.isdigit() and len(text) < 19 else 0


def _sse(event: str, data: str, event_id: int | None) -> bytes:
    """One Server-Sent Event. Every line of ``data`` gets its own ``data:`` field."""
    out = [f"event: {event}"]
    if event_id is not None:
        out.append(f"id: {event_id}")
    out += [f"data: {line}" for line in data.replace("\r", "").split("\n")]
    return ("\n".join(out) + "\n\n").encode()


@dataclass
class Filters:
    source: str | None = None
    action: str | None = None
    min_risk: int | None = None
    since: datetime | None = None
    until: datetime | None = None
    before: int | None = None
    after: int | None = None
    rng: str | None = None
    since_text: str = ""
    until_text: str = ""
    bad_time: bool = False

    def query(self) -> dict[str, Any]:
        """The keyword arguments of ``BoxReader.events``."""
        wanted: dict[str, Any] = {
            "source": self.source,
            "action": self.action,
            "min_risk": self.min_risk,
            "since_ts": self.since,
            "until_ts": self.until,
            "before_seq": self.before,
            "since_seq": self.after,
        }
        return {k: v for k, v in wanted.items() if v is not None}

    def pairs(self) -> list[tuple[str, str]]:
        """The filters as a query string (without the page position)."""
        pairs = [
            ("origen", self.source or ""),
            ("accion", self.action or ""),
            ("riesgo", str(self.min_risk) if self.min_risk else ""),
            ("rango", self.rng or ""),
            ("desde", self.since_text),
            ("hasta", self.until_text),
            ("tras", str(self.after) if self.after is not None else ""),
        ]
        return [(k, v) for k, v in pairs if v]


def parse_filters(params: Any, now: datetime, tz: tzinfo) -> Filters:
    """The filters of the history page from its query string. Anything invalid is ignored
    (never an error page); a bad date sets ``bad_time`` so the page can say so."""
    filters = Filters()
    source = params.get("origen")
    if source in {s.value for s in Source}:
        filters.source = source
    action = params.get("accion", "").strip()
    if _valid_action(action):
        filters.action = action
    risk = params.get("riesgo", "")
    if risk in {"1", "2", "3"}:
        filters.min_risk = int(risk)
    before = params.get("antes", "")
    if before.isascii() and before.isdigit() and 1 <= int(before) < 2**62:
        filters.before = int(before)
    after = params.get("tras", "")
    if after.isascii() and after.isdigit() and int(after) < 2**62:
        filters.after = int(after)  # only events after this seq (a burst's link from "Ahora")
    rng = params.get("rango", "")
    if rng in RANGES:
        filters.rng = rng
        filters.since = now - RANGES[rng]
    for name in ("desde", "hasta"):
        raw = params.get(name, "")
        if not raw:
            continue
        moment = _local_moment(raw, tz)
        if moment is None:
            filters.bad_time = True
        elif name == "desde":
            filters.since_text = moment.astimezone(tz).strftime("%Y-%m-%dT%H:%M")
            if filters.since is None:
                filters.since = moment
        else:
            filters.until_text = moment.astimezone(tz).strftime("%Y-%m-%dT%H:%M")
            filters.until = moment
    return filters


def _valid_action(text: str) -> bool:
    """An action the black box accepts as a filter (it raises on any other): not blank, at most
    64 characters, printable and encodable. Anything else is an ignored filter, never a 500."""
    if not text or len(text) > MAX_ACTION_CHARS or not text.isprintable():
        return False
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


MIN_YEAR, MAX_YEAR = 1970, 9000  # the black box began after the first and ends before the second


def _local_moment(text: str, tz: tzinfo) -> datetime | None:
    """``text`` (a date typed in the form, local time unless it carries an offset) as UTC, with
    the year clamped to 1970-9000 so no date can overflow a conversion. None if it is no date."""
    if len(text) > 32:
        return None
    try:
        moment = datetime.fromisoformat(text)
        clamped = moment.replace(year=min(max(moment.year, MIN_YEAR), MAX_YEAR))
        return (clamped if clamped.tzinfo else clamped.replace(tzinfo=tz)).astimezone(UTC)
    except (ValueError, OverflowError):  # also 29 February of a year that is not a leap year
        return None


__all__ = ["Filters", "create_app", "parse_filters"]
