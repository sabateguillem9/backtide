"""The web of backtide: a lookout post on 127.0.0.1.

The control room ("Panel", T12d): every agent's card, a live feed of all of them and the gate's
requests waiting for your yes. Then, for each agent (``backtide.web.agents``), four pages:
"Ahora" (a live conversation of what the agent does, over Server-Sent Events), "Historia" (the
filtered timeline), "Instantáneas" (the list, and the rewind button) and "Preguntar" (the
question box on a page of its own). The main agent's pages keep their old addresses; the others
live under ``/agentes/<slug>/``. The security reasoning is in ``backtide.web.security``; the
rewind's in ``backtide.web.rewind``.

Everything here reads black boxes through ``BoxReader`` (read-only, without the key). The one
thing it can change is the agent's workspace, and only by asking the service (T12b): a
confirmation page (GET, the fixed notice and a one-time ticket) and then a POST from it. The
other thing it can change, only with `backtide web --ajustes` (T12e), is a key of the Settings
page ("Ajustes"), again by asking the service: a confirmation page per change and a POST from it
(``backtide.web.settings``). The third, only with `backtide web --aprobar` (T10-5), is a decision
on a held request of the gate (approve, reject, "aprobar y confiar", revoke a batch, take a
trusted recipient out), again by asking the service: a confirmation page per decision and a POST
from it (``backtide.web.approve``). Every other route answers GET only.
"""

import asyncio
import itertools
import json
import logging
import math
import threading
import time
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

import jinja2
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from markupsafe import Markup
from starlette.exceptions import HTTPException as StarletteHTTPException

from backtide.blackbox import Event, Source
from backtide.gate.phrase import api_name
from backtide.jail.profiles import DEFAULT_PROFILE
from backtide.service.control import ControlError, ControlOutcomeUnknown, ControlUnavailable
from backtide.service.notice import rewind_notice
from backtide.snapshots import Snapshot, SnapshotError
from backtide.web import format as fmt
from backtide.web.agents import (
    MAIN_SLUG,
    Agent,
    AgentSource,
    Card,
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
from backtide.web.narrate import Line, Name, Narrator, line_for, safe_sentence, sentence
from backtide.web.reader import BoxReader, BoxUnavailable
from backtide.web.rewind import Availability, Redeemed, Rewinder, Tickets
from backtide.web.security import (
    COOKIE_NAME,
    DECIDE_PATH,
    HOLDS_PATH,
    LANG_COOKIE,
    MAX_FORM_BYTES,
    POST_PATH,
    SETTINGS_PATH,
    SETTINGS_POST_PATH,
    Access,
    Guard,
    make_prefix,
    make_run_name,
    make_token,
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
NOT_MAIN = "agent"  # the rewind state of an agent the service does not run (until T17)
SUMMARY_TTL = 3.0  # an agent's card is read again at most this often...
SUMMARY_MAX = 20.0  # ...and at least this often, even when its box has not moved
PANEL_FEED = 40  # lines in the control room's feed when it loads
REQUESTS_EVERY = 5.0  # how often the stream looks at the requests


class Unauthorized(Exception):  # noqa: N818 - an HTTP outcome, not an error
    def __init__(self, *, bad_link: bool = False) -> None:
        self.bad_link = bad_link


class StartSession(Exception):  # noqa: N818 - an HTTP outcome, not an error
    """The link carried the right token: set the cookie and go to the same page without it."""

    def __init__(self, session: str) -> None:
        self.session = session


def create_app(
    *,
    reader: BoxReader,
    port: int,
    token: str | None = None,
    session: str | None = None,
    prefix: str | None = None,
    run_name: str | None = None,
    snapshots: Callable[[], Sequence[Snapshot]] | None = None,
    rewinder: Rewinder | None = None,
    agent_name: str | None = None,
    others: Sequence[AgentSource] = (),
    pending: Callable[[], Sequence[PendingRequest]] | None = None,
    settings: SettingsClient | None = None,
    approver: Approver | None = None,
    spend: SpendClient | None = None,
    poll_interval: float = 1.0,
    stream_seconds: float = 600.0,
    keepalive: float = KEEPALIVE,
    tz: tzinfo | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    agent_lines: Sequence[str] = DEFAULT_PROFILE.rewind_notice_lines,
) -> Guard:
    """The ASGI app for one run, wrapped in its ``Guard``. ``token`` is the link's one-time
    token, ``session`` the secret of the cookie it is exchanged for, ``prefix`` the random path
    the whole app lives under, ``run_name`` the name shown to compare with the terminal (see
    ``backtide.web.security``; all random unless given, which the tests do). ``port`` is the one the
    server listens on (the ``Host`` check needs it). A stream lasts ``stream_seconds`` and the
    browser reconnects by itself, so no connection lives forever. ``rewinder`` asks the service
    to rewind (``backtide.web.rewind``); without one the rewind buttons are disabled.

    ``reader`` and ``snapshots`` are the main agent's (the one the service runs), called
    ``agent_name``; ``others`` are more agents, read the same way and never rewound from here
    (the demo's today, T17's later). ``pending`` lists the gate's requests waiting for a yes
    (the demo's today, T10's later): the page shows them, and cannot answer them. ``settings``
    asks the service about the keys (T12e, ``backtide.web.settings``); its POST path exists
    only when it is enabled (`backtide web --ajustes`). ``approver`` asks the service about the
    held requests (T10-5, ``backtide.web.approve``): without ``pending`` the page lists the real
    ones (from the service with `backtide web --aprobar`, else from the black box), and the
    POST that decides exists only when it is enabled. ``spend`` reads the spending (T11) for the
    panel and Settings; changing the caps goes through ``settings`` (`--ajustes`).
    ``agent_lines`` are the agent profile's lines of the rewind notice (T17a-3)."""
    access = Access(token or make_token(), session)
    prefix = prefix or make_prefix()
    base = f"/s/{prefix}"
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

    async def require_access(request: Request) -> None:
        if access.session_in(request.headers.get("cookie")):
            return  # already in: an old link in the address is simply ignored
        given = request.query_params.get("t")
        if given is not None:
            minted = access.use_link(given)  # one use: the link dies here
            if minted is not None:
                raise StartSession(minted)
            raise Unauthorized(bad_link=True)
        raise Unauthorized

    protected = [Depends(require_access)]

    def require_session(request: Request) -> None:
        """The cookie and nothing else: a change never starts from the link's token."""
        if not access.session_in(request.headers.get("cookie")):
            raise Unauthorized

    tickets = Tickets(clock)
    rewinding = threading.Lock()  # one rewind in flight at a time, whoever asks

    @app.exception_handler(StartSession)
    async def _start_session(request: Request, started: StartSession) -> Response:
        rest = [(k, v) for k, v in request.query_params.multi_items() if k != "t"]
        # The path hangs from our own prefix: "//host/x" can never become a link to another site.
        target = _here(request) + (f"?{urlencode(rest)}" if rest else "")
        # A 200 page, not a 303: when the link is opened from another site (a chat, a mail, the
        # browser pane of another app) the browser keeps that origin for the whole redirect
        # chain, and SameSite=Strict then withholds the cookie that this very response sets. Our
        # own page starts the next navigation (a meta refresh, or the link), and that one sends it.
        response = _page("enter.html", request, active="", t=None, target=target)
        # The cookie belongs to our prefix: other services on 127.0.0.1 (cookies ignore ports)
        # see it only if they are asked for a path under it, which they cannot guess.
        response.set_cookie(
            COOKIE_NAME, started.session, httponly=True, samesite="strict", path=base
        )
        return response

    @app.exception_handler(Unauthorized)
    async def _unauthorized(request: Request, error: Unauthorized) -> Response:
        t = Translator(_language(request)[0])
        return _page("denied.html", request, status=401, active="", t=t, bad_link=error.bad_link)

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
            "countdown": countdown,
            "run_name": run_name,
            # Whether the holds' buttons work (T10-5): "ready", or why not. Asked when drawn.
            "approvals_state": lambda: str(_approvals()),
            # The list read from the black box may miss older holds (finding 7).
            "holds_partial": lambda: box_cache.get("partial") is True,
            "vis_mid": visible_middle,
            "api": api_name,
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

        context = {
            **_helpers(t, now, agent),
            "active": active,
            "lang": t.language,
            "switch": switch,
            "languages": LANGUAGES,
            **values,
        }
        response = HTMLResponse(env.get_template(template).render(**context), status_code=status)
        if remember:
            response.set_cookie(
                LANG_COOKIE, t.language, httponly=True, samesite="strict", path=base
            )
        return response

    def _status_view(t: Translator, agent: Agent) -> dict[str, Any]:
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
    agent_locks = {a.slug: threading.Lock() for a in roster}  # one read of an agent at a time
    watches = {a.slug: Watch(a.reader) for a in roster}
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
        with agent_locks[agent.slug]:
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
                    watch=watches[agent.slug],
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
            listed = list(pending()) if pending is not None else _held(now)
            return live_requests(listed, roster, now), now, False
        except Exception:  # a page, not a 500: the log says why, the page says it is unknown
            logger.exception("the pending requests cannot be listed")
            return [], now, True

    # -- the held requests (T10-5) --------------------------------------------------------

    decision_tickets = DecisionTickets(clock)
    box_cache: dict[str, Any] = {}
    box_lock = threading.Lock()

    def _approvals() -> Availability:
        if approver is None:
            return Availability.DISABLED  # as `backtide web` without --aprobar
        try:
            return approver.availability()
        except Exception:  # never a 500 for a disabled button; the log says why
            logger.exception("cannot tell whether the service can be asked about the holds")
            return Availability.OFF

    def _held(now: datetime) -> list[PendingRequest]:
        """The main agent's holds: from the service when this web may decide (``--aprobar``),
        else rebuilt from its black box (read again only when it moved). Raises when neither
        can be read."""
        if _approvals() is Availability.READY and approver is not None:
            raw = approver.holds()
            box_cache["partial"] = False
        else:
            reader = roster.main.reader
            head = reader.head_seq()
            with box_lock:
                cached = box_cache.get("rows")
                if cached is None or cached[0] != head:
                    rows = reader.events(newest_first=True, limit=BOX_ROWS)
                    cached = (head, rows)
                    box_cache["rows"] = cached
            raw = box_holds(cached[1], now)
            box_cache["partial"] = box_partial(cached[1], now)
        found = [held_request(item, now=now) for item in raw if isinstance(item, dict)]
        return [request for request in found if request is not None]

    def _find_hold(hold_id: str) -> PendingRequest | None:
        requests, _now, failed = _requests()
        if failed or not requests:
            return None
        return next((r for r in requests if r.id == hold_id), None)

    def _cards(requests: Sequence[PendingRequest] | None, now: datetime) -> list[Card]:
        return [card(a, _summary(a), requests or (), now) for a in roster]

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
            heads=".".join(str(c.summary.head) for c in cards),
            now=now,
            spend=_spend(),
        )

    @app.get("/panel/stream", dependencies=protected)
    def panel_stream(request: Request, after: str = "") -> Response:
        resume = request.headers.get("last-event-id", "")
        starts = _heads(resume) or _heads(after)
        t = Translator(_language(request)[0])
        return StreamingResponse(
            _panel_stream(request, t, starts),
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
            **_status_view(t, agent),
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

    @app.get("/ahora/stream", dependencies=protected)
    def stream(request: Request, after: str = "0") -> Response:
        return _open_stream(request, roster.main, after)

    @app.get("/agentes/{slug}/ahora/stream", dependencies=protected)
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
        if not agent.main:
            rewind_state = NOT_MAIN  # the service rewinds the agent it runs, and only that one
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

    def _listed() -> list[Snapshot] | None:
        """The volume's own list, or None: a rewind is only ever to a snapshot in it."""
        if snapshots is None:
            return None
        try:
            return list(snapshots())
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

    def _target(snapshot_id: str) -> tuple[Snapshot | None, str | None]:
        """The snapshot ``snapshot_id`` names if it is in the volume's list now; else why not."""
        listed = _listed()
        if listed is None:
            return None, "rewind.off.list"
        target = Snapshot.parse(snapshot_id) if len(snapshot_id) <= MAX_FIELD_CHARS else None
        if target is None or target not in listed:
            return None, "rewind.err.not_listed"
        return target, None

    @app.get(POST_PATH, dependencies=protected)
    def rewind_confirm(request: Request) -> Response:
        """The confirmation: the fixed notice, and a form with a ticket for this snapshot. It
        changes nothing, and it is the only way to get a ticket."""
        t = Translator(_language(request)[0])
        target, why = _target(request.query_params.get("id", ""))
        if target is None:
            return _not_now(request, t, 200, why or "rewind.err.not_listed")
        state = _availability()
        if state is not Availability.READY:
            return _not_now(request, t, 200, f"rewind.off.{state}", snap=target)
        return _rewind_view(
            request,
            t,
            200,
            "confirm",
            snap=target,
            notice=rewind_notice(target.taken_at, now=clock(), tz=zone, agent_lines=agent_lines),
            csrf=access.csrf,
            ticket=tickets.issue(target.id),
        )

    @app.post(POST_PATH, dependencies=[Depends(require_session)])
    async def rewind(request: Request) -> Response:
        """The rewind. The Guard already checked where it comes from and its size."""
        t = Translator(_language(request)[0])
        form = await _read_form(request)
        if form is None:
            return _not_now(request, t, 400, "rewind.err.form")
        if not access.csrf_is(form["csrf"]):
            logger.warning("a rewind from the web was refused: wrong form token")
            return _not_now(request, t, 403, "rewind.err.form")
        redeemed = tickets.redeem(form["ticket"], form["id"])
        if redeemed is Redeemed.SPENT:  # a second click on the same form
            return _not_now(request, t, 400, "rewind.err.used")
        if redeemed is not Redeemed.OK:
            if rewinding.locked():
                return _not_now(request, t, 409, "rewind.err.busy")
            return _not_now(request, t, 400, "rewind.err.expired")
        target, why = await asyncio.to_thread(_target, form["id"])
        if target is None:
            return _not_now(request, t, 503 if why == "rewind.off.list" else 400, why or "")
        state = await asyncio.to_thread(_availability)
        if state is not Availability.READY or rewinder is None:
            return _not_now(request, t, 503, f"rewind.off.{state}", snap=target)
        ask = rewinder.rewind

        def run() -> tuple[str, dict[str, Any] | None]:
            # Taken and released in this thread, which runs the rewind to its end whatever the
            # browser does (a closed tab does not stop it), so the lock is held exactly as long
            # as the rewind and the next one waits for it.
            if not rewinding.acquire(blocking=False):
                return "busy", None
            try:
                return "asked", ask(target.id)
            except ControlUnavailable:
                return "no_service", None
            except ControlOutcomeUnknown as error:
                logger.warning("a rewind from the web has no known outcome: %s", error)
                return "unknown", None
            except ControlError as error:
                logger.error("a rewind from the web was not sent: %s", error)
                return "untrusted", None
            finally:
                rewinding.release()

        what, reply = await asyncio.to_thread(run)
        if what == "busy":
            return _not_now(request, t, 409, "rewind.err.busy", snap=target)
        if reply is None:
            status = 503 if what == "no_service" else 200
            return _rewind_view(request, t, status, "result", snap=target, outcome=what)
        undo = Snapshot.parse(reply["undo"]) if isinstance(reply.get("undo"), str) else None
        return _rewind_view(
            request,
            t,
            200,
            "result",
            snap=target,
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
            csrf=access.csrf,
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
            csrf=access.csrf,
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
            csrf=access.csrf,
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
            if not access.csrf_is(form["csrf"]):
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
            if not access.csrf_is(form["csrf"]):
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
        if not access.csrf_is(form["csrf"]):
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

    def _hold_refused(request: Request, t: Translator, status: int, reason: str) -> Response:
        return _hold_view(request, t, status, "refused", reason=reason)

    def _lists() -> tuple[list[BatchView] | None, list[TrustView] | None]:
        """The active batches and the recipients trusted from here, from the service (None:
        not asked, or it could not say)."""
        if _approvals() is not Availability.READY or approver is None:
            return None, None
        try:
            batches = batch_views(approver.batches())
        except ControlError as error:
            logger.warning("the batches cannot be listed: %s", error)
            batches = None
        try:
            trusted = trust_views(approver.trusted())
        except ControlError as error:
            logger.warning("the trusted recipients cannot be listed: %s", error)
            trusted = None
        return batches, trusted

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
        """ "Ver": the hold as the black box keeps it (the 2 KiB excerpt, every recipient and
        attachment). Reads only; the agent's text is shown as the agent's."""
        t = Translator(_language(request)[0])
        hold_id = request.query_params.get("id", "")
        if not id_fits(APPROVE, hold_id):
            return _hold_refused(request, t, 404, "hold.err.unknown")
        listed = _find_hold(hold_id)
        event = None
        try:
            if listed is not None and listed.seq is not None:
                rows = roster.main.reader.events(since_seq=listed.seq - 1, limit=1)
                event = held_event(rows, hold_id)
            if event is None:
                rows = roster.main.reader.events(newest_first=True, limit=BOX_ROWS)
                event = held_event(rows, hold_id)
        except BoxUnavailable:
            event = None
        if event is None and listed is None:
            return _hold_refused(request, t, 404, "hold.err.unknown")
        return _page(
            "hold_view.html",
            request,
            active="holds",
            t=t,
            hold=listed,
            detail=None if event is None else detail_of(event),
            risk=listed.risk if listed is not None else (event.risk if event else 0),
            hold_id=hold_id,
            now=clock(),
        )

    @app.get(DECIDE_PATH, dependencies=protected)
    def decide_confirm(request: Request) -> Response:
        """The confirmation of one decision: what it is, and a form with a ticket bound to that
        verb and that id. It changes nothing, and it is the only way to get a ticket."""
        t = Translator(_language(request)[0])
        verb, subject = request.query_params.get("v", ""), request.query_params.get("id", "")
        if not id_fits(verb, subject):
            return _hold_refused(request, t, 200, "hold.err.form")
        state = _approvals()
        if state is not Availability.READY:
            return _hold_refused(request, t, 200, f"hold.off.{state}")
        values: dict[str, Any] = {"verb": verb, "csrf": access.csrf}
        if verb in (APPROVE, REJECT, TRUST):
            listed, _now, failed = _requests()
            found = [] if failed or not listed else listed
            hold = next((r for r in found if r.id == subject), None)
            if hold is None:
                return _hold_refused(request, t, 200, "hold.err.unknown")
            if verb == TRUST and not hold.trustable:
                return _hold_refused(request, t, 200, "hold.err.not_trustable")
            values["hold"] = hold
            if verb == TRUST:  # our notes: who reads it, and what is still held (final review)
                values["trust_note"] = trust_note(hold)
                values["others"] = same_recipient(hold, found)
            values["now"] = clock()
            ticket = decision_tickets.issue(verb, subject, until=hold.expires_at)
        else:
            batches, trusted = _lists()
            if verb == REVOKE:
                found = next((b for b in batches or [] if b.rule_id == subject), None)
                values["batch"] = found
            else:
                found = next((x for x in trusted or [] if x.trust_id == subject), None)
                values["trust"] = found
            if found is None:
                return _hold_refused(request, t, 200, "hold.err.unknown")
            ticket = decision_tickets.issue(verb, subject)
        return _hold_view(request, t, 200, "confirm", ticket=ticket, subject=subject, **values)

    async def decide(request: Request) -> Response:
        """A decision. The Guard already checked where it comes from and its size (and that
        this web may decide at all)."""
        t = Translator(_language(request)[0])
        form = await _read_form(request, DECIDE_FIELDS, DECIDE_OPTIONAL)
        if form is None or not id_fits(form["v"], form["id"]):
            return _hold_refused(request, t, 400, "hold.err.form")
        verb, subject = form["v"], form["id"]
        if not access.csrf_is(form["csrf"]):
            logger.warning("a decision from the web was refused: wrong form token")
            return _hold_refused(request, t, 403, "hold.err.form")
        redeemed = decision_tickets.redeem(form["ticket"], verb, subject)
        if redeemed is Redeemed.SPENT:
            return _hold_refused(request, t, 400, "hold.err.used")
        if redeemed is not Redeemed.OK:
            return _hold_refused(request, t, 400, "hold.err.expired")
        if verb == TRUST and form.get("confirmo") != "si":
            return _hold_refused(request, t, 400, "hold.err.confirm")
        if verb != TRUST and "confirmo" in form:
            return _hold_refused(request, t, 400, "hold.err.form")
        state = await asyncio.to_thread(_approvals)
        if state is not Availability.READY or approver is None:
            return _hold_refused(request, t, 503, f"hold.off.{state}")
        client = approver

        def run() -> tuple[str, dict[str, Any] | None]:
            try:
                if verb in (APPROVE, REJECT):
                    verdict = "approve" if verb == APPROVE else "reject"
                    return "asked", client.decide(subject, verdict)
                if verb == TRUST:
                    return "asked", client.trust(subject)
                if verb == REVOKE:
                    return "asked", client.end_batch(subject)
                return "asked", client.untrust(subject)
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
            return _hold_view(request, t, status, "result", verb=verb, outcome=what)
        status = 400 if reply["outcome"] == "refused" else 200
        return _hold_view(
            request,
            t,
            status,
            "result",
            verb=verb,
            outcome=str(reply["outcome"]),
            message=str(reply["message"]),
            hold_out=reply.get("hold"),
        )

    # The POST exists only with `backtide web --aprobar` (decision 10): without it, neither the
    # Guard nor the app has a door for it.
    approvals_on = approver is not None and getattr(approver, "enabled", False) is True
    if approvals_on:
        app.post(DECIDE_PATH, dependencies=[Depends(require_session)])(decide)

    # -- the stream ------------------------------------------------------------------------

    async def _stream(
        request: Request, t: Translator, start: int, agent: Agent
    ) -> AsyncIterator[bytes]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + stream_seconds
        narrator = Narrator()
        seen: set[int] = set()
        seq = start
        failing = False
        last_sent = last_tide = loop.time()
        fresh_tide = False
        reader_ = agent.reader
        try:
            if start == 0:  # the page saw nothing: begin near the end, not at the beginning
                seq = max(0, await asyncio.to_thread(reader_.head_seq) - SHOWN_LINES)
            else:  # rebuild the open burst the page ended on, so it keeps growing in place
                primed = await asyncio.to_thread(_recent, reader_, PRIME_EVENTS, start)
                seen = {line.id for line in narrator.feed(reversed(primed))}
        except BoxUnavailable:
            failing = True
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            try:
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
        return env.get_template("state.html").render(t=t, **_status_view(t, agent))

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
        request: Request, t: Translator, starts: list[int]
    ) -> AsyncIterator[bytes]:
        """Every agent's new lines (one feed), its card when it changes, and the requests."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + stream_seconds
        agents = list(roster)
        if len(starts) != len(agents):
            starts = [0] * len(agents)
        narrators = [Narrator() for _ in agents]
        seen: list[set[int]] = [set() for _ in agents]
        seqs = list(starts)
        sent_cards: dict[str, Any] = {}
        sent_requests: tuple[Any, ...] | None = None
        last_sent = loop.time()
        last_requests = float("-inf")
        for i, agent in enumerate(agents):
            try:
                if seqs[i] == 0:
                    seqs[i] = await asyncio.to_thread(agent.reader.head_seq)
                else:
                    primed = await asyncio.to_thread(_recent, agent.reader, PRIME_EVENTS, seqs[i])
                    seen[i] = {line.id for line in narrators[i].feed(reversed(primed))}
            except BoxUnavailable:
                pass
        # Cards the page drew: send again only what changes from here.
        requests, now, failed = await asyncio.to_thread(_requests)
        for one in await asyncio.to_thread(_cards, requests, now):
            sent_cards[one.agent.slug] = one.key
        sent_requests = (_requests_key(requests), failed)
        last_good = None if failed else requests
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            now_t = loop.time()
            changed: list[tuple[Agent, Line, bool]] = []
            for i, agent in enumerate(agents):
                try:
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
                requests, now, failed = await asyncio.to_thread(_requests)
                if failed:
                    # Not "nothing waits": the last list read stays, said to be maybe old.
                    requests = live_requests(last_good, roster, now) if last_good else []
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
                yield _sse("at", "", _heads_id(seqs))
                last_sent = now_t
            if now_t - last_sent >= keepalive:
                last_sent = now_t
                yield b": keepalive\n\n"
            await asyncio.sleep(poll_interval)

    post_paths = (POST_PATH,)
    if settings_on:
        post_paths += (SETTINGS_POST_PATH,)
    if approvals_on:
        post_paths += (DECIDE_PATH,)
    return Guard(app, port=port, prefix=prefix, post_paths=post_paths)


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
) -> dict[str, str] | None:
    """A form of ``fields`` (each once) and maybe some of ``optional`` (each once at most), every
    value short (``MAX_FIELD_CHARS``, or its own of ``limits``) and printable; None for anything
    else. Read up to ``MAX_FORM_BYTES`` whatever the request says its length is. Never logs."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_FORM_BYTES:
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
        len(value) > sizes.get(name, MAX_FIELD_CHARS) or not value.isprintable()
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
    return None if requests is None else tuple((r.id, r.expires_at) for r in requests)


MAX_AGENTS_IN_ID = 64


def _heads(text: str) -> list[int]:
    """The control room's position in every agent's box (``12.0.345``, in roster order); an
    empty list for anything else (the stream then starts at each box's end)."""
    if not text or len(text) > 20 * MAX_AGENTS_IN_ID or not text.isascii():
        return []
    parts = text.split(".")
    if len(parts) > MAX_AGENTS_IN_ID or not all(p.isdigit() and len(p) < 19 for p in parts):
        return []
    return [int(p) for p in parts]


def _heads_id(seqs: Sequence[int]) -> str:
    return ".".join(str(s) for s in seqs)


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
