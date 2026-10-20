"""T12a-2: the design and motion pass of the lookout post.

What moves must stay inside the rules of the review (no inline anything, nothing the agent wrote
ever becomes HTML in the browser, only transform and opacity, nothing with reduced motion) and the
drawings must keep saying something true (the tide's height is the agent's activity)."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backtide.snapshots import Reason, Snapshot
from backtide.web.security import CSP
from backtide.web.tide import BASE, PAD, WIDTH, build_tide
from tests.conftest import FakeClock
from tests.webkit import PREFIX_PATH, START, new_box, new_client

STATIC = Path(__file__).resolve().parent.parent / "backtide" / "web" / "static"
TEMPLATES = STATIC.parent / "templates"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


@pytest.fixture
def web(tmp_path: Path) -> TestClient:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "service_start", "")
    box.append("system", "agent_start", "")
    take = "20261016T100000.000000Z-periodic"
    box.append("snapshot", "take", take, snapshot_id=take)
    clock.advance(timedelta(minutes=1))
    for i in range(12):
        box.append("file", "delete", f"work/f{i}.txt", details={"type": "file"}, risk=1)
        clock.advance(timedelta(seconds=2))
    return new_client(tmp_path, clock=lambda: START + timedelta(minutes=5))


# -- the policy did not move ------------------------------------------------------------------


def test_the_csp_is_exactly_the_reviewed_one() -> None:
    assert CSP == (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )


@pytest.mark.parametrize("template", sorted(p.name for p in TEMPLATES.glob("*.html")))
def test_no_template_has_inline_script_style_or_handlers(template: str) -> None:
    source = (TEMPLATES / template).read_text()
    assert "<script" not in source or re.search(r"<script src=", source), template
    assert not re.search(r"<script(?![^>]*\bsrc=)", source), template
    assert "<style" not in source, template
    assert not re.search(r"\sstyle\s*=", source), template
    assert not re.search(r"\son[a-z]+\s*=", source, re.I), template
    assert "hx-on" not in source and "javascript:" not in source.lower(), template


@pytest.mark.parametrize(
    "path",
    [
        "/panel",
        "/ahora",
        "/historia",
        "/instantaneas",
        "/ahora/preguntar",
        "/agentes/principal/ahora",
    ],
)
def test_the_new_pages_obey_the_policy(web: TestClient, path: str) -> None:
    html = web.get(path).text
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"<style|\sstyle\s*=|\son[a-z]+\s*=", html, re.I)
    assert not re.search(r"(?:src|href|action|hx-get)=[\"']?(?:https?:)?//", html)


def test_the_script_never_turns_text_into_html() -> None:
    js = (STATIC / "web.js").read_text()
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "createContextualFragment",
        "DOMParser",
        'setAttribute("style"',
        'setTimeout("',
    ):
        assert sink not in js, sink


def test_the_script_rests_when_the_tab_is_hidden_and_respects_reduced_motion() -> None:
    js = (STATIC / "web.js").read_text()
    assert "visibilitychange" in js and "document.hidden" in js
    assert "prefers-reduced-motion: reduce" in js


def _blocks(css: str, at_rule: str) -> list[tuple[int, str]]:
    """(start, body) of every ``@<at_rule> ... { ... }`` block, braces balanced."""
    found = []
    for match in re.finditer(rf"@{at_rule}\b[^{{]*{{", css):
        depth, i = 1, match.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(css[i], 0)
            i += 1
        found.append((match.start(), css[match.end() : i - 1]))
    return found


def test_keyframes_and_transitions_move_only_transform_and_opacity() -> None:
    css = (STATIC / "web.css").read_text()
    for _, body in _blocks(css, "keyframes"):
        props = set(re.findall(r"([a-z-]+)\s*:", body))
        assert props <= {"transform", "opacity"}, props
    for value in re.findall(r"transition\s*:\s*([^;}]+)", css):
        for part in re.split(r",(?![^(]*\))", value):  # commas outside cubic-bezier(...)
            assert part.split()[0] in {"transform", "opacity"}, value


def test_every_animation_and_transition_waits_for_no_preference() -> None:
    css = (STATIC / "web.css").read_text()
    allowed = [
        (start, start + len(body) + 200)
        for start, body in _blocks(css, "media")
        if "prefers-reduced-motion: no-preference" in css[start : start + 60]
    ]
    for match in re.finditer(r"\b(animation|transition)\s*:", css):
        inside = any(lo <= match.start() <= hi for lo, hi in allowed)
        in_keyframes = any(
            s <= match.start() <= s + len(b) + 20 for s, b in _blocks(css, "keyframes")
        )
        # the dot button's hover nudge is the brand component's own (bundle.css)
        brand_button = css.rfind(".dot-button {", 0, match.start()) > css.rfind(
            "}", 0, match.start()
        )
        assert inside or in_keyframes or brand_button, css[match.start() - 80 : match.start() + 40]


def test_only_token_colours_still() -> None:
    """Every colour of the page is a token of the brand (the base or the app's palette, T12d),
    and there are still no shadows and no gradients in the CSS."""
    import json

    tokens = json.loads(
        (STATIC.parents[2] / "brand" / "design-system" / "project" / "tokens.json").read_text()
    )
    allowed = set()
    for group in (tokens["color"]["tokens"], tokens["app"]["color"]["tokens"]):
        for token in group:
            value = token["value"]
            allowed |= set(value.values()) if isinstance(value, dict) else {value}
    css = (STATIC / "web.css").read_text()
    used = set(re.findall(r"#[0-9a-fA-F]{3,8}\b", css))
    assert used <= {c for c in allowed if c.startswith("#")}, used - allowed
    assert not re.search(r"rgba?\(|hsla?\(|gradient|box-shadow", css)


# -- the tide ---------------------------------------------------------------------------------


def _points(path: str) -> list[tuple[float, float]]:
    return [(float(x), float(y)) for x, y in re.findall(r"[ML](-?[\d.]+),(-?[\d.]+)", path)]


def test_a_quiet_day_is_a_still_line_and_the_dot_rests_on_it() -> None:
    tide = build_tide([], NOW)
    points = _points(tide.path) + _points(tide.swell)
    assert {y for _, y in points} == {BASE}
    assert points[0][0] == PAD and points[-1] == (WIDTH - PAD, BASE)
    assert len(points) < 10, "a flat line is a few points, not hundreds"


def test_the_tide_swells_where_the_agent_was_busy_and_is_calm_elsewhere() -> None:
    busy = [NOW - timedelta(hours=6, seconds=i) for i in range(300)]
    tide = build_tide([], NOW, busy)
    points = _points(tide.path)
    x_busy = PAD + (WIDTH - 2 * PAD) * 0.75
    near = [abs(y - BASE) for x, y in points if abs(x - x_busy) < 30]
    far = [abs(y - BASE) for x, y in points if x < PAD + 100]
    assert max(near) > 4
    assert max(far, default=0) < 0.1
    assert tide.events == 300


def test_the_swell_joins_the_line_on_the_baseline_and_ends_at_the_head() -> None:
    recent = [NOW - timedelta(minutes=5, seconds=i) for i in range(200)]
    tide = build_tide([], NOW, recent)
    path, swell = _points(tide.path), _points(tide.swell)
    assert path[-1] == swell[0] and path[-1][1] == BASE
    assert swell[-1] == (WIDTH - PAD, BASE)
    assert any(abs(y - BASE) > 1 for _, y in swell), "recent activity shows next to the dot"


def test_marks_sit_on_the_wave_and_carry_when_they_were_taken() -> None:
    snaps = [Snapshot(NOW - timedelta(hours=h), str(Reason.PERIODIC)) for h in (1, 3)]
    busy = [NOW - timedelta(hours=1, seconds=i) for i in range(200)]
    tide = build_tide([], NOW, busy, snapshots=snaps)
    assert [m.at for m in tide.marks] == [s.taken_at.isoformat() for s in reversed(snaps)]
    for mark in tide.marks:
        assert 0 < mark.y < tide.height


def test_a_cut_list_of_events_is_drawn_busy_not_calm() -> None:
    newest = [NOW - timedelta(minutes=1, seconds=i) for i in range(50)]
    calm = build_tide([], NOW, newest)
    cut = build_tide([], NOW, newest, more=True)
    early = [abs(y - BASE) for x, y in _points(cut.path) if x < 200]
    assert max(early) > 4 and max(abs(y - BASE) for x, y in _points(calm.path) if x < 200) < 0.1


def test_a_shorter_window_spreads_the_marks_out() -> None:
    snaps = [Snapshot(NOW - timedelta(hours=2), str(Reason.PERIODIC))]
    day = build_tide([], NOW, snapshots=snaps)
    three_hours = build_tide([], NOW, snapshots=snaps, window=timedelta(hours=3))
    assert three_hours.marks[0].x < day.marks[0].x - 100
    assert three_hours.hours == 3 and day.hours == 24


# -- the pages --------------------------------------------------------------------------------


def test_the_dot_lives_outside_what_the_stream_replaces(web: TestClient) -> None:
    html = web.get("/ahora").text
    swapped = re.search(
        r'<div class="tide-wrap" id="tide" sse-swap="tide">(.*?)</div>\s*<svg', html, re.S
    )
    assert swapped and "tide-head" not in swapped.group(1)
    assert 'class="tide-head"' in html and 'class="tide-frame is-intro" data-tide' in html
    assert 'stroke="url(#tide-fade)"' in html, "the tide's fade-in, drawn by the SVG itself"


def test_counters_and_the_last_move_are_there_without_javascript(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert re.search(r'data-count="events">15</span> eventos', html)
    assert re.search(r'data-count="snaps">1</span> instantánea<', html)
    assert "Último movimiento" in html
    assert re.search(r'<time class="ago" datetime="[^"]+" data-ago', html)
    english = web.get("/ahora?lang=en").text
    assert "15</span> events" in english and "Last move" in english


def test_the_page_carries_its_words_for_live_times(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert 'data-age-sec="hace {n} s"' in html
    assert 'data-age-sec="{n} s ago"' in web.get("/ahora?lang=en").text


def test_a_folded_burst_opens_to_its_span_and_its_history(web: TestClient) -> None:
    html = web.get("/ahora").text
    burst = re.search(r'<details class="burst"><summary>(.*?)</summary>(.*?)</details>', html, re.S)
    assert burst
    assert "Ha borrado 12 archivos" in text_of(burst.group(1))
    assert "De 10:01:00 a 10:01:22." in text_of(burst.group(2))
    link = re.search(r'href="([^"]+)">Verlos en Historia', burst.group(2))
    assert link and link.group(1).startswith(f"{PREFIX_PATH}/historia?")
    assert link.group(1).endswith("?origen=file&amp;tras=3&amp;antes=16"), "by seq, not by time"
    rows = web.get(link.group(1).replace("&amp;", "&").removeprefix(PREFIX_PATH)).text
    assert re.findall(r'id="e-(\d+)"', rows) == [str(n) for n in range(15, 3, -1)]
    assert "Solo los eventos de una ráfaga" in rows


def test_a_burst_link_keeps_the_rows_a_summary_folded_in(tmp_path: Path) -> None:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "agent_start", "")
    for i in range(5):
        box.append("file", "delete", f"work/f{i}.txt", details={"type": "file"}, risk=1)
        clock.advance(timedelta(seconds=1))
    box.append("file", "summary", ".", details={"counts": {"delete": 100}}, risk=1)
    clock.advance(timedelta(minutes=2))
    box.append("system", "agent_stop", "")
    web = new_client(tmp_path, clock=lambda: START + timedelta(minutes=5))
    html = web.get("/ahora").text
    assert "Ha borrado 105 archivos" in text_of(html)
    link = re.search(r'href="([^"]+)">Verlos en Historia', html)
    assert link
    rows = web.get(link.group(1).replace("&amp;", "&").removeprefix(PREFIX_PATH)).text
    shown = re.findall(r'id="e-(\d+)"', rows)
    assert shown == ["7", "6", "5", "4", "3", "2"], "the 5 deletions and the summary of 100"
    assert "accion=" not in link.group(1)


@pytest.mark.parametrize("after", ["%C2%B2", "-1", "x", "9" * 30])
def test_a_bad_lower_bound_is_ignored(web: TestClient, after: str) -> None:
    response = web.get(f"/historia?tras={after}")
    assert response.status_code == 200
    assert "Solo los eventos de una ráfaga" not in response.text


def test_the_tide_reads_a_bounded_number_of_rows_whatever_the_box_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide.web import app as web_app
    from backtide.web.reader import BoxReader

    monkeypatch.setattr(web_app, "ACTIVITY_EVENTS", 40)
    clock = FakeClock(START - timedelta(days=3))
    box = new_box(tmp_path, clock)
    for i in range(400):  # most of them older than a day: a "since" query would walk them all
        box.append("file", "modify", f"f{i}")
        clock.advance(timedelta(minutes=12))
    calls: list[tuple[dict, int]] = []

    class Counting(BoxReader):
        def events(self, **filters):  # noqa: ANN003, ANN202 - a spy
            found = super().events(**filters)
            calls.append((filters, len(found)))
            return found

    now = START + timedelta(days=2)
    snaps = [Snapshot(now - timedelta(hours=2), str(Reason.PERIODIC))]
    app = web_app.create_app(
        reader=Counting(tmp_path / "blackbox.db"),
        port=8765,
        token="t",  # noqa: S106 - a test value
        session="s",
        prefix="pref0123456789abcdefghijkl",
        snapshots=lambda: snaps,
        clock=lambda: now,
        tz=UTC,
    )
    from fastapi.testclient import TestClient as Client

    client = Client(app, base_url="http://127.0.0.1:8765/s/pref0123456789abcdefghijkl")
    client.cookies.set(
        "backtide_web", "s", domain="127.0.0.1", path="/s/pref0123456789abcdefghijkl"
    )
    for path in ("/instantaneas", "/ahora", "/ahora"):
        calls.clear()
        assert client.get(path).status_code == 200
        tide_reads = [c for c in calls if "since_ts" not in c[0] and c[0].get("limit") == 41]
        assert all("since_ts" not in f for f, _ in calls), "no query by time: ts has no index"
        assert all(rows <= 41 for f, rows in tide_reads)
        if path == "/instantaneas":
            assert len(tide_reads) == 1, "one read for the tide, marks from the list"
    # the second "Ahora" reused the day's tide instead of reading again
    assert not [c for c in calls if c[0].get("limit") == 41]


def test_a_single_event_is_a_plain_line_not_a_burst(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "solo.md")
    html = new_client(tmp_path).get("/ahora").text
    assert "<details" not in html.split('id="feed"')[1].split("</main>")[0]


def test_an_empty_watch_says_what_will_appear(tmp_path: Path) -> None:
    new_box(tmp_path).open()
    html = new_client(tmp_path).get("/ahora").text
    assert "Todavía no ha pasado nada." in html
    assert "aparecerá aquí, línea a línea" in html


def test_asking_has_its_own_page_in_the_navigation(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert f'href="{PREFIX_PATH}/ahora/preguntar">Preguntar</a>' in html
    page = web.get("/ahora/preguntar").text
    assert re.search(r'aria-current="page">Preguntar<span class="nav-line"', page)
    assert 'class="line you"' not in page, "no question yet: only the help"
    assert "Puedes preguntar" in page
    assert page.count(f'hx-get="{PREFIX_PATH}/ahora/preguntar?q=') == 3, "three suggestions"
    assert 'id="feed"' in page and 'class="ask"' in page


def test_the_current_page_carries_the_gliding_underline(web: TestClient) -> None:
    for path, label in (("/historia", "Historia"), ("/instantaneas", "Instantáneas")):
        html = web.get(path).text
        assert html.count('class="nav-line"') == 1
        assert re.search(rf'aria-current="page">{label}<span class="nav-line"', html)


def test_the_snapshots_page_draws_its_list_on_a_tide(tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    snaps = [Snapshot(now - timedelta(hours=h), str(Reason.PERIODIC)) for h in (5, 2, 1)]
    web = new_client(tmp_path, snapshots=lambda: snaps, clock=lambda: now)
    html = web.get("/instantaneas").text
    rows = re.findall(r'class="snaprow" data-rewind-to="([^"]+)"', html)
    marks = re.findall(r'class="tide-mark"[^>]*data-at="([^"]+)"', html)
    assert rows and set(rows) == set(marks), "every row has its mark to go back to"
    assert "sse-swap" not in html.split("data-tide")[1].split("</svg>")[0], "nothing live here"
    assert "hace 6 h" in text_of(html), "the line goes back to the oldest listed snapshot"
    assert re.search(r'<time class="ago" datetime="[^"]+" data-ago>', html)
    assert "Señala o toca una instantánea" in html
    assert "<form" not in html, "still nothing here can rewind"


def test_snapshots_have_human_titles_and_a_small_id(tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    snaps = [
        Snapshot(datetime(2025, 3, 3, 8, 5, tzinfo=UTC), str(Reason.PERIODIC)),
        Snapshot(datetime(2026, 10, 14, 9, 10, tzinfo=UTC), str(Reason.MANUAL)),
        Snapshot(datetime(2026, 10, 15, 12, 53, tzinfo=UTC), str(Reason.PRE_RESTORE)),
        Snapshot(datetime(2026, 10, 16, 9, 24, tzinfo=UTC), str(Reason.PERIODIC)),
    ]
    web = new_client(tmp_path, snapshots=lambda: snaps, clock=lambda: now)
    html = web.get("/instantaneas").text
    titles = re.findall(r'<time class="snaptitle"[^>]*>([^<]+)</time>', html)
    assert titles == ["Hoy, 09:24", "Ayer, 12:53", "14 oct, 09:10", "3 mar 2025, 08:05"]
    assert "antes de rebobinar" in html and "manual" in html
    assert re.findall(r'<span class="sid">([^<]+)</span>', html) == [s.id for s in snaps[::-1]]
    english = web.get("/instantaneas?lang=en").text
    titles = re.findall(r'<time class="snaptitle"[^>]*>([^<]+)</time>', english)
    assert titles == ["Today, 09:24", "Yesterday, 12:53", "14 Oct, 09:10", "3 Mar 2025, 08:05"]
    assert "before a rewind" in english


def test_days_follow_the_persons_time_zone() -> None:
    from zoneinfo import ZoneInfo

    from backtide.web import format as fmt
    from backtide.web.i18n import Translator

    madrid = ZoneInfo("Europe/Madrid")
    now = datetime(2026, 10, 16, 22, 30, tzinfo=UTC)  # already the 17th in Madrid
    moment = datetime(2026, 10, 16, 21, 0, tzinfo=UTC)  # 23:00 on the 16th in Madrid
    assert fmt.day_time(Translator("es"), moment, now, madrid) == "Ayer, 23:00"


def test_a_preview_never_draws_a_rewind_to_a_point_that_is_not_there() -> None:
    js = (STATIC / "web.js").read_text()
    retract = js[js.index("function retractTo") : js.index("function restore")]
    assert "if (!mark) return false;" in retract
    assert "lineParts()" in retract, "the line is looked up on every call (the stream redraws it)"
    assert "reapply();" in js
