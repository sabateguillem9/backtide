"""The three pages and the question box, over a black box written by the real BlackBox."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeClock
from tests.webkit import PREFIX_PATH, ROOT, START, new_box, new_client
from vigia.snapshots import Reason, Snapshot, SnapshotError

HOSTILE = '"><img src=x onerror=alert(1)>‮txt.exe'


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def assert_no_hostile_markup(html: str) -> None:
    assert "<img" not in html
    assert "onerror=alert(1)>" not in html
    assert "‮" not in html


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(START)


@pytest.fixture
def web(tmp_path: Path, clock: FakeClock) -> TestClient:
    box = new_box(tmp_path, clock)
    box.append("system", "service_start", "", details={"version": "0.1.0"})
    box.append("system", "agent_start", "")
    box.append("file", "create", "notas.md", details={"type": "file", "name": "notas.md"})
    take = "20261016T100000.000000Z-periodic"
    box.append("snapshot", "take", take, snapshot_id=take)
    clock.advance(timedelta(minutes=5))
    for i in range(30):
        box.append("file", "delete", f"work/f{i}.txt", risk=1)
    box.append("file", "create", f"work/{HOSTILE}", risk=2)
    return new_client(tmp_path, clock=lambda: START + timedelta(minutes=10))


# -- Ahora ---------------------------------------------------------------------------------------


def test_now_tells_what_happened_as_a_conversation(web: TestClient) -> None:
    html = web.get("/ahora").text
    text = text_of(html)
    assert "Vigía ha empezado a vigilar" in text
    assert "El agente ha arrancado" in text
    assert "Ha creado notas.md" in text
    assert "Ha borrado 30 archivos, entre ellos work/f0.txt" in text
    assert "Instantánea guardada" in text
    assert html.index("Vigía ha empezado") < html.index("Ha borrado 30")  # oldest first


def test_the_agent_state_is_at_the_top(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert "El agente" in text_of(html) and "vigilado" in text_of(html)
    assert 'class="status-dot st-watched"' in html
    assert html.index("st-watched") < html.index('id="feed"')


def test_risk_is_a_dot_never_a_colour(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert 'class="dot dot-2"' in html and 'aria-label="riesgo importante"' in html
    assert 'class="dot dot-1"' in html
    css = web.get("/static/web.css").text
    allowed = {"#ffffff", "#0b0b0b", "#2e2e2e", "#6b6b6b", "#767676"}
    assert set(re.findall(r"#[0-9a-fA-F]{6}\b", css)) <= allowed, "only the brand tokens"
    assert not re.search(r"rgba?\(|hsla?\(|gradient|box-shadow", css)


def test_the_tide_marks_every_snapshot_of_the_day(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert 'class="tide-mark"' in html and 'class="tide-head"' in html
    assert "Instantáneas de las últimas 24 horas: 1." in html


def test_the_stream_starts_after_the_last_event_the_page_showed(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert f'sse-connect="{PREFIX_PATH}/ahora/stream?after=35"' in html  # 4 + 30 + 1 events
    assert 'hx-ext="sse"' in html


def test_hostile_names_are_inert_on_the_conversation(web: TestClient) -> None:
    html = web.get("/ahora").text
    assert_no_hostile_markup(html)
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert ">U+202E</span>" in html


def test_an_empty_box_is_a_calm_page(tmp_path: Path) -> None:
    new_box(tmp_path).open()
    html = new_client(tmp_path).get("/ahora").text
    assert "Todavía no ha pasado nada." in html
    assert "La caja negra todavía no tiene avisos." in html


def test_no_black_box_yet_is_a_calm_page_not_an_error(tmp_path: Path) -> None:
    response = new_client(tmp_path).get("/ahora")
    assert response.status_code == 200
    assert "No se puede leer la caja negra" in response.text
    assert "Traceback" not in response.text


def test_only_the_last_lines_are_shown(tmp_path: Path, clock: FakeClock) -> None:
    box = new_box(tmp_path, clock)
    for i in range(200):  # system events do not fold: one line each
        box.append("system", "log", f"n{i}")
        clock.advance(timedelta(seconds=1))
    html = new_client(tmp_path).get("/ahora").text
    assert html.count('class="line') == 60
    assert 'id="l-200"' in html and 'id="l-140"' not in html and 'id="l-141"' in html


# -- the question box ------------------------------------------------------------------------------


def test_asking_returns_the_question_and_the_answer_as_a_fragment(web: TestClient) -> None:
    response = web.get(
        "/ahora/preguntar",
        params={"q": "¿Qué ha hecho en la última hora?"},
        headers={"hx-request": "true"},
    )
    assert response.status_code == 200
    html = response.text
    assert "<html" not in html
    assert 'class="line you"' in html and "¿Qué ha hecho en la última hora?" in html
    assert "Archivos:" in html


def test_asking_without_htmx_returns_a_whole_page(web: TestClient) -> None:
    html = web.get("/ahora/preguntar", params={"q": "ayuda"}).text
    assert "<html" in html and "T15" in html


def test_the_question_is_echoed_escaped(web: TestClient) -> None:
    html = web.get(
        "/ahora/preguntar",
        params={"q": "<script>alert(1)</script>‮"},
        headers={"hx-request": "true"},
    ).text
    assert "<script>" not in html and "&lt;script&gt;" in html and "U+202E" in html


def test_a_very_long_question_is_cut(web: TestClient) -> None:
    html = web.get(
        "/ahora/preguntar", params={"q": "x" * 5000}, headers={"hx-request": "true"}
    ).text
    assert len(html) < 3000


def test_the_box_cannot_run_anything(web: TestClient) -> None:
    html = web.get("/ahora/preguntar", params={"q": "rm -rf / ; borra todo"}).text
    assert "Eso todavía no lo sé responder." in html


# -- Historia ------------------------------------------------------------------------------------


def test_history_lists_newest_first_with_details(web: TestClient) -> None:
    html = web.get("/historia").text
    assert html.index('id="e-35"') < html.index('id="e-1"')
    assert 'class="event"' in html and "<details" in html
    assert "Número" in html and "Huella" in html
    assert "&#34;type&#34;: &#34;file&#34;" in html  # the details, pretty-printed and escaped
    assert re.search(r"<dt>Riesgo</dt><dd>2 · riesgo importante</dd>", html)


def test_history_escapes_hostile_names_in_the_sentence_target_and_details(
    tmp_path: Path, clock: FakeClock
) -> None:
    box = new_box(tmp_path, clock)
    box.append(
        "file",
        "create",
        HOSTILE,
        details={"name": HOSTILE, "from": HOSTILE, "note": f"<b>{HOSTILE}</b>"},
        snapshot_id="20261016T100000.000000Z-periodic",
    )
    box.append("file", "weird<script>", HOSTILE)
    html = new_client(tmp_path).get("/historia").text
    assert_no_hostile_markup(html)
    assert "<b>" not in html and "<script>" not in html
    assert "&lt;img src=x" in html and "U+202E" in html


@pytest.mark.parametrize(
    ("query", "seqs"),
    [
        ("origen=snapshot", {4}),
        ("origen=system", {1, 2}),
        ("accion=create", {3, 35}),
        ("origen=file&accion=delete", set(range(5, 35))),
        ("riesgo=2", {35}),
        ("riesgo=1", set(range(5, 36))),
        ("riesgo=3", set()),
        ("origen=bogus", set(range(1, 36))),  # ignored, not an error
        ("riesgo=9", set(range(1, 36))),
        ("accion=" + "x" * 500, set(range(1, 36))),
    ],
)
def test_history_filters(web: TestClient, query: str, seqs: set[int]) -> None:
    html = web.get(f"/historia?{query}").text
    shown = {int(n) for n in re.findall(r'<details class="event[^"]*" id="e-(\d+)"', html)}
    assert shown == seqs


def test_history_time_filters(web: TestClient) -> None:
    # events 1-4 at 10:00, the rest at 10:05 (local time = UTC in these tests)
    html = web.get("/historia?desde=2026-10-16T10:03&hasta=2026-10-16T11:00").text
    shown = {int(n) for n in re.findall(r'id="e-(\d+)"', html)}
    assert shown == set(range(5, 36))
    html = web.get("/historia?hasta=2026-10-16T10:03").text
    assert {int(n) for n in re.findall(r'id="e-(\d+)"', html)} == {1, 2, 3, 4}
    assert 'value="2026-10-16T10:03"' in html  # the form remembers it


def test_history_range_presets(tmp_path: Path, clock: FakeClock) -> None:
    box = new_box(tmp_path, clock)
    box.append("system", "log", "old")  # 10:00
    clock.advance(timedelta(hours=30))
    box.append("system", "log", "recent")  # the next day 16:00
    clock.advance(timedelta(minutes=30))
    box.append("system", "log", "latest")  # 16:30
    now = START + timedelta(hours=30, minutes=40)
    web = new_client(tmp_path, clock=lambda: now)

    def shown(query: str) -> set[int]:
        return {int(n) for n in re.findall(r'id="e-(\d+)"', web.get(f"/historia?{query}").text)}

    assert shown("rango=1h") == {2, 3}
    assert shown("rango=24h") == {2, 3}
    assert shown("rango=7d") == {1, 2, 3}
    assert shown("rango=all") == {1, 2, 3}
    assert shown("rango=forever") == {1, 2, 3}


def test_a_bad_date_is_ignored_and_said(web: TestClient) -> None:
    html = web.get("/historia?desde=not-a-date&hasta=2026-13-45T99:99").text
    assert "no es válida" in html
    assert len(re.findall(r'id="e-\d+"', html)) == 35


def test_history_pages_and_the_more_link(tmp_path: Path, clock: FakeClock) -> None:
    box = new_box(tmp_path, clock)
    for i in range(120):
        box.append("system", "log", f"n{i}")
    web = new_client(tmp_path)
    first = web.get("/historia").text
    assert len(re.findall(r'id="e-\d+"', first)) == 50
    assert 'id="e-120"' in first and 'id="e-71"' in first and 'id="e-70"' not in first
    link = re.search(r'class="more" href="([^"]+)"', first)
    assert link and link.group(1) == f"{PREFIX_PATH}/historia?antes=71"
    second = web.get(ROOT + link.group(1)).text
    assert {int(n) for n in re.findall(r'id="e-(\d+)"', second)} == set(range(21, 71))
    third = web.get("/historia?antes=21").text
    assert len(re.findall(r'id="e-\d+"', third)) == 20 and 'class="more"' not in third


def test_the_more_link_keeps_the_filters(tmp_path: Path, clock: FakeClock) -> None:
    box = new_box(tmp_path, clock)
    for i in range(60):
        box.append("system", "log", f"n{i}", risk=1)
    html = new_client(tmp_path).get("/historia?origen=system&riesgo=1").text
    assert f'href="{PREFIX_PATH}/historia?origen=system&amp;riesgo=1&amp;antes=11"' in html


def test_htmx_gets_only_the_fragment(web: TestClient) -> None:
    hx = {"hx-request": "true"}
    results = web.get("/historia?riesgo=2", headers=hx).text
    assert "<html" not in results and 'id="e-35"' in results and "<form" not in results
    rows = web.get("/historia?antes=10", headers=hx).text
    assert "<html" not in rows and 'class="events"' not in rows and 'id="e-9"' in rows


def test_htmx_filters_push_a_clean_address_without_the_empty_fields(web: TestClient) -> None:
    hx = {"hx-request": "true"}
    response = web.get("/historia?origen=&accion=&riesgo=2&rango=&desde=&hasta=", headers=hx)
    assert response.headers["hx-push-url"] == f"{PREFIX_PATH}/historia?riesgo=2"
    assert web.get("/historia", headers=hx).headers["hx-push-url"] == f"{PREFIX_PATH}/historia"
    assert "hx-push-url" not in web.get("/historia?antes=10", headers=hx).headers
    assert "hx-push-url" not in web.get("/historia").headers


def test_what_the_address_carries_is_escaped_where_it_is_echoed(web: TestClient) -> None:
    attack = '"><script>alert(1)</script>'
    for url in (
        f"/historia?accion={attack}&desde={attack}",
        f"/historia?origen={attack}&riesgo={attack}&antes={attack}",
        f"/ahora?lang={attack}",
        f"/instantaneas?todas={attack}",
        "/%22%3E%3Cscript%3Ealert(1)%3C/script%3E",  # a path that does not exist
        "/ahora?x=%22%3E%3Cscript%3E&lang=en",
    ):
        html = web.get(url).text
        assert "<script>alert" not in html, url
        assert "<script>" not in html.replace("<script src=", ""), url


def test_the_filter_form_works_without_javascript(web: TestClient) -> None:
    html = web.get("/historia").text
    form = re.search(r"<form class=\"filters\"[^>]*>", html)
    assert (
        form
        and 'method="get"' in form.group(0)
        and f'action="{PREFIX_PATH}/historia"' in form.group(0)
    )
    assert 'hx-push-url="true"' in form.group(0)


def test_snapshot_marks_in_the_timeline(web: TestClient) -> None:
    html = web.get("/historia?origen=snapshot").text
    assert 'class="event mark"' in html and "Instantánea guardada" in html


def test_an_unreadable_box_is_a_sentence(tmp_path: Path) -> None:
    html = new_client(tmp_path).get("/historia").text
    assert "No se puede leer la caja negra" in html


# -- Instantáneas --------------------------------------------------------------------------------


def snapshots(count: int, now: datetime) -> list[Snapshot]:
    return [
        Snapshot(now - timedelta(minutes=2 * (count - i)), str(Reason.PERIODIC))
        for i in range(count)
    ]


def test_snapshots_list_newest_first_with_a_disabled_rewind(tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    snaps = [*snapshots(3, now), Snapshot(now - timedelta(hours=1), "manual")]
    web = new_client(tmp_path, snapshots=lambda: sorted(snaps, key=lambda s: s.taken_at))
    html = web.get("/instantaneas").text
    ids = re.findall(r'<span class="sid">([^<]+)</span>', html)
    assert ids == sorted((s.id for s in snaps), reverse=True)
    assert html.count('<button class="dot-button" type="button" disabled') == 4
    assert html.count("llega con T04c-2") >= 4
    assert "periódica" in html and "manual" in html
    assert "hace 2 min" in text_of(html)
    assert "<form" not in html, "nothing here can rewind yet"
    assert not re.search(r"<a [^>]*rebobinar|hx-(post|put|delete|get)=\"[^\"]*rebob", html, re.I)


def test_snapshots_show_the_30_newest_and_all_on_request(tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    web = new_client(tmp_path, snapshots=lambda: snapshots(45, now))
    html = web.get("/instantaneas").text
    assert html.count('class="snaprow"') == 30
    assert "+15" in html
    assert web.get("/instantaneas?todas=1").text.count('class="snaprow"') == 45


def test_snapshots_in_english(tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    web = new_client(tmp_path, snapshots=lambda: snapshots(1, now))
    text = text_of(web.get("/instantaneas", headers={"accept-language": "en"}).text)
    assert "arrives with T04c-2" in text and "periodic" in text and "2 min ago" in text


def test_an_unreadable_volume_falls_back_to_what_the_black_box_says(
    tmp_path: Path, clock: FakeClock
) -> None:
    box = new_box(tmp_path, clock)
    ids = ["20261016T095800.000000Z-periodic", "20261016T100000.000000Z-periodic"]
    for snapshot_id in ids:
        box.append("snapshot", "take", snapshot_id, snapshot_id=snapshot_id)

    def failing() -> list[Snapshot]:
        raise SnapshotError("no btrfs here <b>")

    html = new_client(tmp_path, snapshots=failing).get("/instantaneas").text
    assert "No se puede leer el volumen de instantáneas desde aquí" in html
    assert "no btrfs here" not in html, "the cause goes to the log, not onto the page"
    assert "Esto es lo que dice la caja negra." in html
    assert re.findall(r'<span class="sid">([^<]+)</span>', html) == ids[::-1]


def test_no_volume_and_no_box_is_an_empty_list_not_an_error(tmp_path: Path) -> None:
    response = new_client(tmp_path).get("/instantaneas")
    assert response.status_code == 200 and "No hay instantáneas todavía." in response.text


def test_a_reason_this_version_does_not_know_is_shown_escaped(tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
    web = new_client(tmp_path, snapshots=lambda: [Snapshot(now, "from_the_future")])
    assert "from_the_future" in web.get("/instantaneas").text


# -- language ------------------------------------------------------------------------------------


def test_the_language_follows_the_browser_and_the_switch_remembers_it(web: TestClient) -> None:
    english = web.get("/ahora", headers={"accept-language": "en-GB,en;q=0.9"}).text
    assert '<html lang="en">' in english and "The agent started" in english
    assert "History" in english and "Only on this computer" in english
    switched = web.get("/ahora?lang=en")
    assert '<html lang="en">' in switched.text
    cookie = switched.headers["set-cookie"]
    assert "vigia_lang=en" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert '<html lang="en">' in web.get("/historia").text  # remembered
    assert '<html lang="es">' in web.get("/historia?lang=es").text


def test_a_made_up_language_is_ignored(web: TestClient) -> None:
    response = web.get("/ahora?lang=xx<script>")
    assert '<html lang="es">' in response.text and "set-cookie" not in response.headers


def test_the_switch_links_keep_the_filters(web: TestClient) -> None:
    html = web.get("/historia?origen=file&riesgo=2").text
    assert f'href="{PREFIX_PATH}/historia?origen=file&amp;riesgo=2&amp;lang=en"' in html


def test_an_unknown_page_is_a_calm_404(web: TestClient) -> None:
    response = web.get("/nada")
    assert response.status_code == 404 and "Aquí no hay nada" in response.text
    assert web.get("/ahora/../etc/passwd").status_code == 404


# -- the review's findings ------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "desde=9999-12-31T23:59&hasta=9999-12-31T23:59",
        "desde=0001-01-01T00:00",
        "hasta=0001-01-01T00:00",
        "desde=0001-01-01T00:00%2B14:00",  # an offset that pushes it before year 1
        "hasta=9999-12-31T23:59-12:00",  # and after year 9999
        "desde=2026-02-30T10:00",  # a day that does not exist
        "desde=1969-12-31T23:59&hasta=9000-01-01T00:00",
        "desde=%00&hasta=%F0%9F%98%80",
    ],
)
def test_extreme_dates_are_never_a_500(web: TestClient, query: str) -> None:
    response = web.get(f"/historia?{query}")
    assert response.status_code == 200, query
    assert "Traceback" not in response.text


def test_extreme_dates_are_clamped_to_1970_9000(web: TestClient) -> None:
    html = web.get("/historia?desde=0001-01-01T00:00&hasta=9999-12-31T23:59").text
    assert 'name="desde" type="datetime-local" value="1970-01-01T00:00"' in html
    assert 'name="hasta" type="datetime-local" value="9000-12-31T23:59"' in html
    assert len(re.findall(r'id="e-\d+"', html)) == 35  # everything is in that range


def test_a_hostile_dropped_reason_does_not_take_the_page_down(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    for reason in ("{0.__class__}", "{reason}", "}{", "x" * 5000):
        box.append("file", "dropped", ".", details={"reason": reason}, risk=1)
    web = new_client(tmp_path)
    for path in ("/ahora", "/historia", "/ahora/preguntar?q=en+la+ultima+hora"):
        response = web.get(path)
        assert response.status_code == 200, path
        said = "".join(re.findall(r'class="said">(.*?)</span>\s*(?:<span|</)', response.text, re.S))
        assert "__class__" not in said  # (the details of History show the raw text, escaped)
        assert "otro motivo" in response.text or path.endswith("hora")


def test_a_hostile_dropped_reason_does_not_stop_the_stream(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    web = new_client(tmp_path, stream_seconds=0.4, poll_interval=0.02)
    import threading
    import time

    from tests.webkit import parse_sse

    def write() -> None:
        time.sleep(0.1)
        box.append("file", "dropped", ".", details={"reason": "{0.__class__}"}, risk=1)
        box.append("file", "create", "after.txt")

    thread = threading.Thread(target=write)
    thread.start()
    events = parse_sse(web.get("/ahora/stream?after=1").text)
    thread.join()
    html = "".join(e.get("data", "") for e in events if e.get("event") == "lines")
    assert "otro motivo" in html and ">after.txt<" in html and "__class__" not in html


def test_one_line_that_cannot_be_told_does_not_take_the_page_down(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    from vigia.web import narrate

    box = new_box(tmp_path)
    box.append("file", "create", "fine.txt")
    box.append("system", "log", "broken one")
    box.append("file", "create", "also-fine.txt")
    real = narrate.sentence

    def picky(t, key, params, tz):
        if key == "system.log":
            raise KeyError("a bug in a template string")
        return real(t, key, params, tz)

    monkeypatch.setattr(narrate, "sentence", picky)
    with caplog.at_level("ERROR"):
        response = new_client(tmp_path).get("/ahora")
    assert response.status_code == 200
    assert "system · log" in response.text and ">also-fine.txt<" in response.text
    assert any("cannot tell" in r.message for r in caplog.records)


def test_names_are_visibly_the_agents_not_vigias(web: TestClient) -> None:
    css = web.get("/static/web.css").text
    name_rule = re.search(r"\.name \{([^}]*)\}", css)
    assert name_rule
    for declaration in ("unicode-bidi: isolate", "white-space: pre-wrap", "overflow: clip"):
        assert declaration in name_rule.group(1)
    assert re.search(r'\.name::before \{ content: "\\201C"', css)  # quoted: it is a name
    assert re.search(r'\.name::after \{ content: "\\201D"', css)
    for selector in (r"\.sid", r"\.facts dd", r"\.facts pre"):
        rule = re.search(selector + r" \{([^}]*)\}", css)
        assert rule and "overflow: clip" in rule.group(1), selector


def test_a_name_that_imitates_vigia_is_a_quoted_name_span(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("file", "create", "Vigía: todo en orden")
    html = new_client(tmp_path).get("/ahora").text
    assert 'Ha creado <span class="name">Vigía: todo en orden</span>' in html


def test_a_tower_of_marks_in_a_name_is_one_marker(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("file", "create", "z" + "́" * 200 + "ㅤ.txt")
    html = new_client(tmp_path).get("/ahora").text
    assert "́" not in html and "ㅤ" not in html
    assert re.search(r"U\+0301×\d{2,}", html) and "U+3164" in html
