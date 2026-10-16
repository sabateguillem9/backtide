"""The web of Vigía: a lookout post on 127.0.0.1, read-only.

Three pages: "Ahora" (a live conversation of what the agent does, over Server-Sent Events),
"Historia" (the filtered timeline) and "Instantáneas" (the list; the rewind button is disabled
until the web gets the control socket). The security reasoning is in ``vigia.web.security``.

Everything here reads the black box through ``BoxReader`` (read-only, without its key); nothing
writes, and the only method the app answers is GET.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import jinja2
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from markupsafe import Markup
from starlette.exceptions import HTTPException as StarletteHTTPException

from vigia.blackbox import Event, Source
from vigia.snapshots import Snapshot, SnapshotError
from vigia.web import format as fmt
from vigia.web.ask import MAX_QUESTION, answer
from vigia.web.i18n import LANGUAGES, Translator, negotiate
from vigia.web.narrate import Line, Name, Narrator, line_for, safe_sentence, sentence
from vigia.web.reader import BoxReader, BoxUnavailable
from vigia.web.security import (
    COOKIE_NAME,
    LANG_COOKIE,
    Access,
    Guard,
    make_prefix,
    make_run_name,
    make_token,
)
from vigia.web.state import STATE_ACTIONS, AgentStatus, read_status
from vigia.web.text import visible
from vigia.web.tide import WINDOW, build_tide

logger = logging.getLogger(__name__)

HERE = Path(__file__).parent
PRIME_EVENTS = 3000  # how far back the conversation is rebuilt (to fold a burst correctly)
SHOWN_LINES = 60
PAGE_SIZE = 50
STREAM_BATCH = 500
TIDE_REFRESH = 60.0
KEEPALIVE = 15.0
LISTED_SNAPSHOTS = 30
SNAPSHOT_FALLBACK = 200
MAX_ACTION_CHARS = 64
RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}


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
    poll_interval: float = 1.0,
    stream_seconds: float = 600.0,
    keepalive: float = KEEPALIVE,
    tz: tzinfo | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Guard:
    """The ASGI app for one run, wrapped in its ``Guard``. ``token`` is the link's one-time
    token, ``session`` the secret of the cookie it is exchanged for, ``prefix`` the random path
    the whole app lives under, ``run_name`` the name shown to compare with the terminal (see
    ``vigia.web.security``; all random unless given, which the tests do). ``port`` is the one the
    server listens on (the ``Host`` check needs it). A stream lasts ``stream_seconds`` and the
    browser reconnects by itself, so no connection lives forever."""
    access = Access(token or make_token(), session)
    prefix = prefix or make_prefix()
    base = f"/s/{prefix}"
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

    def _helpers(t: Translator, now: datetime) -> dict[str, Any]:
        """What every template (page or stream fragment) may call."""

        def tell(event_or_line: Event | Line) -> Markup:
            line = event_or_line if isinstance(event_or_line, Line) else line_for(event_or_line)
            return safe_sentence(t, line, zone)

        def stamp(when: str | datetime) -> str:
            moment = fmt.parse_ts(when) if isinstance(when, str) else when
            return fmt.stamp(moment, zone)

        return {
            "t": t,
            "tell": tell,
            "vis": visible,
            "clock": lambda ts: fmt.clock(fmt.parse_ts(ts), zone),
            "stamp": stamp,
            "age": lambda moment: fmt.age(t, now - moment),
            "details_json": _details_json,
            "say": lambda key, **params: sentence(t, key, params, zone),
            "name": Name,
            "base": base,
            "run_name": run_name,
        }

    def _page(
        template: str,
        request: Request,
        *,
        status: int = 200,
        active: str,
        t: Translator | None,
        **values: Any,
    ) -> HTMLResponse:
        language, remember = _language(request)
        t = t or Translator(language)
        now = clock()

        def switch(code: str) -> str:
            rest = [(k, v) for k, v in request.query_params.multi_items() if k not in {"lang", "t"}]
            return f"{_here(request)}?{urlencode([*rest, ('lang', code)])}"

        context = {
            **_helpers(t, now),
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

    def _status_view(t: Translator) -> dict[str, Any]:
        try:
            status = read_status(reader)
        except BoxUnavailable:
            status = AgentStatus("unknown", None)
        when = fmt.clock(status.since, zone) if status.since else None
        return {"state": status.state, "state_time": when}

    def _tide_view(now: datetime) -> Any:
        try:
            takes = reader.events(
                source=Source.SNAPSHOT,
                action="take",
                since_ts=now - WINDOW,
                newest_first=True,
                limit=300,
            )
        except BoxUnavailable:
            takes = []
        return build_tide(list(reversed(takes)), now)

    # -- pages -----------------------------------------------------------------------------

    @app.get("/", dependencies=protected)
    def home() -> Response:
        return RedirectResponse(f"{base}/ahora", status_code=303)

    @app.get("/ahora", dependencies=protected)
    def now_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        now = clock()
        unreadable = False
        lines: list[Line] = []
        head = 0
        try:
            recent = list(reversed(_recent(reader, PRIME_EVENTS)))
            lines = Narrator().feed(recent)[-SHOWN_LINES:]
            head = recent[-1].seq if recent else 0
        except BoxUnavailable:
            unreadable = True
        return _page(
            "now.html",
            request,
            active="now",
            t=t,
            lines=lines,
            head=head,
            unreadable=unreadable,
            tide=_tide_view(now),
            **_status_view(t),
        )

    @app.get("/ahora/preguntar", dependencies=protected)
    def ask(request: Request, q: str = "") -> Response:
        t = Translator(_language(request)[0])
        try:
            reply = answer(q, reader=reader, now=clock(), tz=zone, t=t)
            unreadable = False
        except BoxUnavailable:
            reply, unreadable = None, True
        return _page(
            "ask.html" if request.headers.get("hx-request") == "true" else "ask_page.html",
            request,
            active="",
            t=t,
            question=q[:MAX_QUESTION],
            reply=reply,
            unreadable=unreadable,
        )

    @app.get("/ahora/stream", dependencies=protected)
    def stream(request: Request, after: str = "0") -> Response:
        resume = request.headers.get("last-event-id", "")
        start = _seq(resume) or _seq(after)
        t = Translator(_language(request)[0])
        events = _stream(request, t, start)
        return StreamingResponse(
            events,
            media_type="text/event-stream",
            headers={"x-accel-buffering": "no"},
        )

    @app.get("/historia", dependencies=protected)
    def history_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        now = clock()
        filters = parse_filters(request.query_params, now, zone)
        unreadable = False
        events: list[Event] = []
        try:
            events = reader.events(**filters.query(), newest_first=True, limit=PAGE_SIZE + 1)
        except BoxUnavailable:
            unreadable = True
        more = len(events) > PAGE_SIZE
        events = events[:PAGE_SIZE]
        older = None
        if more:
            older = f"{base}/historia?" + urlencode(
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
            page.headers["HX-Push-Url"] = f"{base}/historia" + (f"?{query}" if query else "")
        return page

    @app.get("/instantaneas", dependencies=protected)
    def snapshots_page(request: Request) -> Response:
        t = Translator(_language(request)[0])
        now = clock()
        show_all = request.query_params.get("todas") == "1"
        rows: list[Snapshot] = []
        error: str | None = None
        from_box = False
        if snapshots is not None:
            try:
                rows = list(snapshots())
            except (SnapshotError, OSError) as failure:
                logger.warning("the snapshot list cannot be read: %s", failure)
                error = str(failure)
        else:
            error = "no volume configured"
        if error is not None:
            from_box = True
            try:
                takes = reader.events(
                    source=Source.SNAPSHOT,
                    action="take",
                    newest_first=True,
                    limit=SNAPSHOT_FALLBACK,
                )
            except BoxUnavailable:
                takes = []
            rows = [s for e in takes if e.snapshot_id and (s := Snapshot.parse(e.snapshot_id))][
                ::-1
            ]
        newest_first = list(reversed(rows))
        shown = newest_first if show_all else newest_first[:LISTED_SNAPSHOTS]
        return _page(
            "snapshots.html",
            request,
            active="snapshots",
            t=t,
            rows=shown,
            hidden=len(newest_first) - len(shown),
            error=error,
            from_box=from_box,
            now=now,
        )

    # -- the stream ------------------------------------------------------------------------

    async def _stream(request: Request, t: Translator, start: int) -> AsyncIterator[bytes]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + stream_seconds
        narrator = Narrator()
        seen: set[int] = set()
        seq = start
        failing = False
        last_sent = last_tide = loop.time()
        try:
            if start == 0:  # the page saw nothing: begin near the end, not at the beginning
                seq = max(0, await asyncio.to_thread(reader.head_seq) - SHOWN_LINES)
            else:  # rebuild the open burst the page ended on, so it keeps growing in place
                primed = await asyncio.to_thread(_recent, reader, PRIME_EVENTS, start)
                seen = {line.id for line in narrator.feed(reversed(primed))}
        except BoxUnavailable:
            failing = True
        yield b"retry: 2000\n\n"
        while loop.time() < deadline:
            if await request.is_disconnected():
                return
            try:
                batch = await asyncio.to_thread(reader.events, since_seq=seq, limit=STREAM_BATCH)
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
                        **_helpers(t, clock()), line=line, oob=line.id in seen
                    )
                    for line in changed
                )
                seen.update(line.id for line in changed)
                yield _sse("lines", html, seq)
                if any(e.source is Source.SYSTEM and e.action in STATE_ACTIONS for e in batch):
                    yield _sse("state", await asyncio.to_thread(_render_state, t), None)
                if any(e.source is Source.SNAPSHOT and e.action == "take" for e in batch):
                    last_tide = float("-inf")
                last_sent = now_t
            if now_t - last_tide >= TIDE_REFRESH:
                last_tide = now_t
                yield _sse("tide", await asyncio.to_thread(_render_tide, t), None)
                last_sent = now_t
            if now_t - last_sent >= keepalive:
                last_sent = now_t
                yield b": keepalive\n\n"
            await asyncio.sleep(poll_interval)

    def _render_state(t: Translator) -> str:
        return env.get_template("state.html").render(t=t, **_status_view(t))

    def _render_tide(t: Translator) -> str:
        return env.get_template("tide.html").render(t=t, tide=_tide_view(clock()))

    return Guard(app, port=port, prefix=prefix)


# -- helpers ---------------------------------------------------------------------------------


def _recent(reader: BoxReader, count: int, up_to: int | None = None) -> list[Event]:
    """The newest ``count`` events (newest first), those up to seq ``up_to`` if given."""
    if up_to is not None:
        return reader.events(before_seq=up_to + 1, newest_first=True, limit=count)
    return reader.events(newest_first=True, limit=count)


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
        ]
        return [(k, v) for k, v in pairs if v]


def parse_filters(params: Any, now: datetime, tz: tzinfo) -> Filters:
    """The filters of the history page from its query string. Anything invalid is ignored
    (never an error page); a bad date sets ``bad_time`` so the page can say so."""
    filters = Filters()
    source = params.get("origen")
    if source in {s.value for s in Source}:
        filters.source = source
    action = params.get("accion", "")
    if action and len(action) <= MAX_ACTION_CHARS and action.isprintable():
        filters.action = action
    risk = params.get("riesgo", "")
    if risk in {"1", "2", "3"}:
        filters.min_risk = int(risk)
    before = params.get("antes", "")
    if before.isdigit() and 1 <= int(before) < 2**62:
        filters.before = int(before)
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
