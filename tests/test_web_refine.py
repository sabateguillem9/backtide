"""T12f-1, T12f-1b, T12f-2a and T12f-2b: the header, the control room, the requests, the cards,
the feed, the agent's pages and its history, told in a person's words.

The agent's text is drawn as it is (no ligatures), a request is titled by what it wants to do
(the verb from what the gate read, never from what the agent wrote), the control room opens
with one sentence on what waits, "trust" sits a level below approve and reject, each card
tells its day in one line with one call to action, and the feed says an agent's name once per
run and can put the routine aside.
"""

import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeClock
from tests.test_web_decide import NOW as HOLD_NOW
from tests.test_web_decide import FakeApprover, hold
from tests.test_web_panel import (
    NOW,
    STATIC,
    other_box,
    request,
    source,
    text_of,
)
from tests.webkit import PREFIX_PATH, START, new_box, new_client

DELETE = {
    "reason": "delete", "method": "DELETE", "host": "api.github.com",
    "path": "/repos/ana/tienda-web", "target": "https://api.github.com/repos/ana/tienda-web",
    "view": None, "trustable": False,
}  # fmt: skip


def web_with(tmp_path: Path, *holds: dict[str, Any]) -> TestClient:
    fake = FakeApprover()
    fake.listed = list(holds)
    new_box(tmp_path).append("file", "create", "work/notas.md")
    return new_client(tmp_path, approver=fake, clock=lambda: HOLD_NOW)


def waiting_of(html: str) -> str:
    return html[html.index('id="waiting"') : html.index('class="room"')]


def titles(html: str) -> list[str]:
    return [text_of(m) for m in re.findall(r'<h3 class="req-what"[^>]*>(.*?)</h3>', html, re.S)]


# -- the agent's text, as it is -----------------------------------------------------------------


def test_the_agents_text_is_drawn_without_ligatures() -> None:
    """Jost joins "--" into a dash: `git reset --hard` must not read as `git reset –hard`."""
    css = (STATIC / "web.css").read_text()
    rule = re.search(r"\n\.name \{([^}]*)\}", css)
    assert rule, "the .name rule"
    assert "font-variant-ligatures: none" in rule.group(1)
    assert '"liga" 0' in rule.group(1) and '"calt" 0' in rule.group(1)


# -- a request, by what it wants to do -----------------------------------------------------------


def test_a_message_and_an_email_are_titled_by_what_they_do(tmp_path: Path) -> None:
    mail = hold()["view"] | {"translator": "gmail", "recipients": ["ana@ejemplo.com"]}
    html = web_with(tmp_path, hold(), hold("h-ba9876543210", view=mail)).get("/panel").text
    assert titles(html) == [
        "Quiere enviar un mensaje por Telegram",
        "Quiere enviar un correo por Gmail",
    ]
    assert "Una petición que la puerta no sabe leer" not in html
    assert "no se puede retirar" in text_of(waiting_of(html)), "what happens if it goes out"


def test_a_request_backtide_cannot_read_says_what_and_where(tmp_path: Path) -> None:
    """Without a reading, the verb comes from the gate's rule (it read a DELETE) and the host
    is the agent's, quoted as such."""
    html = web_with(tmp_path, hold(**DELETE)).get("/panel").text
    assert titles(html) == ["Quiere borrar algo en api.github.com"]
    assert re.search(
        r'<h3 class="req-what"[^>]*>[^<]*<span class="name">api\.github\.com</span>', html
    )
    text = text_of(waiting_of(html))
    assert "DELETE api.github.com/repos/ana/tienda-web" in text, "what it asks, as it wrote it"
    assert "Una petición que la puerta no sabe leer" not in text


def test_the_verb_never_comes_from_the_agents_words(tmp_path: Path) -> None:
    """A POST to /delete-everything is not a delete, and a host that sounds like us is a name."""
    sneaky = DELETE | {
        "reason": "write", "method": "POST", "host": "aprobado-por-backtide.com",
        "path": "/delete-everything",
    }  # fmt: skip
    odd = DELETE | {"reason": "unknown", "method": "GET", "host": "borrar.ejemplo.org"}
    html = web_with(tmp_path, hold(**sneaky), hold("h-ba9876543210", **odd)).get("/panel").text
    assert titles(html) == [
        "Quiere mandar algo a aprobado-por-backtide.com",
        "Quiere hacer una petición a borrar.ejemplo.org",
    ]
    assert '<span class="name">aprobado-por-backtide.com</span>' in html
    assert '<span class="name">borrar.ejemplo.org</span>' in html


def test_an_api_backtide_does_not_name_keeps_our_phrase(tmp_path: Path) -> None:
    unknown = hold()["view"] | {"translator": "made-up"}
    html = web_with(tmp_path, hold(view=unknown)).get("/panel").text
    assert titles(html) == ["Una API: enviar un mensaje"], "our words, never its name"
    assert "made-up" not in html


def test_a_hostile_host_in_a_title_is_inert(tmp_path: Path) -> None:
    html = (
        web_with(tmp_path, hold(**DELETE | {"host": '"><img src=x onerror=alert(1)>'}))
        .get("/panel")
        .text
    )
    assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html


def test_the_titles_in_english(tmp_path: Path) -> None:
    web = web_with(tmp_path, hold(), hold("h-ba9876543210", **DELETE))
    html = web.get("/panel", headers={"accept-language": "en"}).text
    assert titles(html) == [
        "Wants to send a message by Telegram",
        "Wants to delete something on api.github.com",
    ]


# -- approve, reject and, a level below, trust ---------------------------------------------------


def test_trust_and_the_full_request_sit_under_more(tmp_path: Path) -> None:
    html = web_with(tmp_path, hold()).get("/panel").text
    req = html[html.index('id="req-h-0123456789ab"') :]
    req = req[: req.index("\n  </li>")]
    actions = req[req.index('class="req-actions"') :]
    first = actions[: actions.index("</div>")]
    assert "v=aprobar" in first and "v=rechazar" in first and "v=confiar" not in first
    more = re.search(r'<details class="req-more">(.*?)</details>', req, re.S)
    assert more, "a 'More' fold"
    assert "v=confiar" in more.group(1) and "/peticiones/ver?" in more.group(1)
    assert "Aprobar y no volver a preguntar" in text_of(more.group(1))


# -- the header ---------------------------------------------------------------------------------


def test_the_header_is_one_width_and_counts_what_waits(tmp_path: Path) -> None:
    web = web_with(tmp_path, hold(), hold("h-ba9876543210", trustable=False))
    panel = web.get("/panel").text
    assert re.search(r'<span class="badge"[^>]*>.*?data-waiting-n[^>]*>2<', panel, re.S)
    assert "esperan tu sí" in text_of(panel[panel.index('class="badge"') :][:400])
    now = web.get("/ahora").text
    for page in (panel, now):
        assert '<div class="topbar">' in page, "the header lives outside the page's measure"
        assert page.index('<div class="topbar">') < page.index('<div class="page')


def test_the_badge_hides_when_nothing_waits(tmp_path: Path) -> None:
    """Hidden, not missing: the stream may bring a request and web.js shows it."""
    panel = web_with(tmp_path).get("/panel").text
    assert re.search(r'<span class="badge" data-waiting-badge hidden>', panel)


# -- the control room's sentence ---------------------------------------------------------------


def test_the_room_opens_with_what_waits_and_the_most_urgent(tmp_path: Path) -> None:
    pending = [
        request(id="r1", agent="principal"),
        request(id="r2", agent="principal", expires_at=NOW + timedelta(minutes=2, seconds=42)),
    ]
    new_box(tmp_path).append("file", "create", "a")
    html = new_client(tmp_path, clock=lambda: NOW, pending=lambda: pending).get("/panel").text
    head = html[html.index('class="panel-head') : html.index('id="waiting"')]
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", head, re.S)
    assert h1 and text_of(h1.group(1)) == "2 peticiones esperan tu sí."
    text = text_of(head)
    assert "La más urgente se rechaza sola en 2:42" in text
    assert 'data-deadline="' in head, "the clock ticks in the browser"
    assert "data-one=" in head and "data-other=" in head and "data-none=" in head


def test_the_room_says_when_nothing_waits(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "a")
    html = new_client(tmp_path, clock=lambda: NOW, pending=lambda: []).get("/panel").text
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S)
    assert h1 and text_of(h1.group(1)) == "Nada espera tu sí."


def test_the_room_lists_your_other_matters(tmp_path: Path) -> None:
    clock = FakeClock(START)
    new_box(tmp_path, clock).append("system", "agent_start", "")
    mail = other_box(tmp_path, "correo", clock)
    mail.append("system", "agent_start", "")
    mail.append("system", "space_pause", "", details={"frozen": True})
    html = (
        new_client(
            tmp_path,
            clock=lambda: START + timedelta(minutes=1),
            others=[source(tmp_path, "correo", "Asistente de correo")],
            pending=lambda: [],
        )
        .get("/panel")
        .text
    )
    attention = re.search(r'<ul class="attention"[^>]*>(.*?)</ul>', html, re.S)
    assert attention, "the other matters"
    assert "Asistente de correo está congelado" in text_of(attention.group(1))
    assert "OpenClaw" not in text_of(attention.group(1)), "an agent at work is no matter"


@pytest.mark.parametrize("page", ["/panel", "/peticiones"])
def test_the_new_pages_stay_free_of_inline_code(tmp_path: Path, page: str) -> None:
    html = web_with(tmp_path, hold(), hold("h-ba9876543210", **DELETE)).get(page).text
    assert " style=" not in html and "<style" not in html
    assert not re.search(r"<script(?![^>]*\ssrc=)", html)
    assert not re.search(r"\son[a-z]+=", html)


# -- the review of T12f-1 -----------------------------------------------------------------------


def test_a_host_that_is_not_a_host_stays_out_of_the_title(tmp_path: Path) -> None:
    """Quote marks and spaces in a "host" could read as our words: the title goes without it,
    and the host stays in the agent's own block (L1)."""
    trick = DELETE | {
        "reason": "write",
        "method": "POST",
        "host": "a” · aprobado por backtide · “b",
    }
    html = web_with(tmp_path, hold(**trick)).get("/panel").text
    assert titles(html) == ["Quiere mandar algo fuera de tu ordenador"]
    agent = html[html.index('class="req-agent"') :]
    assert "aprobado por backtide" in text_of(agent[: agent.index("</div>")])


def test_a_forward_and_a_push_keep_our_own_phrase(tmp_path: Path) -> None:
    """Our phrase says more than a title for a forward or a push (L2)."""
    forward = hold()["view"] | {"translator": "gmail", "effect": "forward"}
    push = hold()["view"] | {"translator": "git", "effect": "delete"}
    html = (
        web_with(tmp_path, hold(view=forward), hold("h-ba9876543210", view=push)).get("/panel").text
    )
    assert titles(html) == ["Gmail: reenviar un correo", "git: push que borra ramas o etiquetas"]


def test_a_list_that_may_be_incomplete_says_at_least(tmp_path: Path) -> None:
    """A list read again from the last one known is not "N wait" but "at least N" (L3)."""
    pending = [request(id="r1", agent="principal")]
    new_box(tmp_path).append("file", "create", "a")
    web = new_client(tmp_path, clock=lambda: NOW, pending=lambda: pending)
    html = web.get("/panel").text
    assert "data-least=" in html
    head = re.search(r'<div class="waiting-head"[^>]*>', html)
    assert head and "data-unsure" not in head.group(0), "a full list is sure"


# -- T12f-1b: the cards ------------------------------------------------------------------------


def card_of(html: str, slug: str) -> str:
    start = html.index(f'id="card-{slug}"')
    return html[start : html.index("</article>", start)]


def room_with(tmp_path: Path, script, *, pending=None, now=START + timedelta(minutes=1)):
    clock = FakeClock(START)
    main = new_box(tmp_path, clock)
    main.append("system", "agent_start", "")
    mail = other_box(tmp_path, "correo", clock)
    mail.append("system", "agent_start", "")
    script(main, mail, clock)
    return new_client(
        tmp_path,
        clock=lambda: now,
        others=[source(tmp_path, "correo", "Asistente de correo")],
        pending=lambda: pending or [],
    )


def test_a_card_tells_its_day_in_one_line(tmp_path: Path) -> None:
    def script(main, mail, clock):
        main.append("file", "modify", "work/a.md")
        main.append("snapshot", "take", "s", snapshot_id="20261016T100000.000000Z-periodic")
        mail.append("exec", "run", "rm -rf /", risk=3)

    html = room_with(tmp_path, script).get("/panel").text
    main = card_of(html, "principal")
    assert "Hoy 3 acciones · 1 punto para volver · nada grave" in text_of(main)
    assert "<dl" not in main, "no more three big numbers"
    mail = card_of(html, "correo")
    assert "Hoy 2 acciones · 0 puntos para volver · 1 cosa grave" in text_of(mail)
    assert 'class="is-risky"' in mail and 'class="is-risky"' not in main


def test_a_card_says_when_the_day_is_cut_or_the_serious_count_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backtide.web.agents as agents

    monkeypatch.setattr(agents, "RISK_CAP", 2)

    def script(main, mail, clock):
        for _ in range(4):
            main.append("exec", "run", "rm -rf /", risk=3)
        for i in range(5001):
            main.append("file", "modify", f"work/f{i % 50}.txt")

    text = text_of(card_of(room_with(tmp_path, script).get("/panel").text, "principal"))
    assert "5000+ acciones" in text, "events there were more of than were read"
    assert "≥2 cosas graves" in text, "at least what was counted, and it says so"


def test_a_card_in_english(tmp_path: Path) -> None:
    def script(main, mail, clock):
        mail.append("exec", "run", "rm -rf /", risk=3)

    html = room_with(tmp_path, script).get("/panel", headers={"accept-language": "en"}).text
    assert "Today 2 actions · 0 points to go back to · 1 serious thing" in text_of(
        card_of(html, "correo")
    )


def test_a_card_has_one_call_to_action_a_waiting_request(tmp_path: Path) -> None:
    pending = [request(id="r1", agent="correo"), request(id="r2", agent="correo")]
    html = room_with(tmp_path, lambda main, mail, clock: None, pending=pending).get("/panel").text
    mail = card_of(html, "correo")
    assert mail.count('class="card-cta"') == 1
    assert re.search(
        r'<a class="card-cta" href="#req-r1">.*?2 peticiones esperan tu sí', mail, re.S
    )
    assert 'class="card-cta"' not in card_of(html, "principal"), "a calm agent asks for nothing"


@pytest.mark.parametrize(
    ("script", "state"),
    [
        (lambda b: b.append("system", "space_pause", "", details={"frozen": True}), "frozen"),
        (lambda b: b.append("system", "sensor_down", "tetragon", risk=2), "sensor_down"),
    ],
)
def test_a_frozen_or_blind_agent_points_to_its_page(tmp_path: Path, script, state: str) -> None:
    def run(main, mail, clock):
        mail.append("system", "sensor_start", "")
        script(mail)

    html = room_with(tmp_path, run).get("/panel").text
    mail = card_of(html, "correo")
    assert f'class="card-in st-{state}"' in mail
    assert re.search(
        r'<a class="card-cta" href="[^"]*/agentes/correo/ahora">.*?Ver qué pasa', mail, re.S
    )


def test_a_card_keeps_its_three_links(tmp_path: Path) -> None:
    html = room_with(tmp_path, lambda main, mail, clock: None).get("/panel").text
    links = re.search(r'<p class="card-links">(.*?)</p>', card_of(html, "correo"), re.S)
    assert links and text_of(links.group(1)) == "Ahora Historia Instantáneas"


# -- T12f-1b: the feed -------------------------------------------------------------------------


def feed_lines(html: str) -> list[tuple[list[str], str]]:
    feed = html[html.index('id="pfeed"') :]
    feed = feed[: feed.index("</ol>")]
    return [
        (cls.split(), text_of(body))
        for cls, body in re.findall(r'<li class="(pline[^"]*)"[^>]*>(.*?)</li>', feed, re.S)
    ]


def test_the_feed_says_an_agents_name_once_per_run(tmp_path: Path) -> None:
    def script(main, mail, clock):
        for who, what in (
            (main, "a1"),
            (main, "a2"),
            (mail, "b1"),
            (main, "a3"),
            (main, "a4"),
        ):
            clock.advance(timedelta(seconds=1))
            who.append("exec", "run", what)

    html = room_with(tmp_path, script, now=START + timedelta(minutes=2)).get("/panel").text
    same = {text.split()[-1]: "same" in cls for cls, text in feed_lines(html)}
    assert same["a4"] is False, "the newest of its run says its name"
    assert same["a3"] is True and same["b1"] is False
    assert same["a2"] is False and same["a1"] is True
    assert html.count('<a class="who"') == html.count('<li class="pline'), "the name stays"


def test_the_routine_is_marked_and_the_filter_is_offered(tmp_path: Path) -> None:
    def script(main, mail, clock):
        clock.advance(timedelta(seconds=1))
        main.append("exec", "run", "git status")
        clock.advance(timedelta(seconds=1))
        main.append("exec", "run", "rm -rf /", risk=3)

    html = room_with(tmp_path, script, now=START + timedelta(minutes=2)).get("/panel").text
    by_text = {text: cls for cls, text in feed_lines(html)}
    risky = next(c for text, c in by_text.items() if "rm -rf /" in text)
    calm = next(c for text, c in by_text.items() if "git status" in text)
    assert "routine" in calm and "routine" not in risky
    buttons = re.findall(r'<button[^>]*aria-pressed="(\w+)"[^>]*data-feed-filter="(\w+)"', html)
    assert buttons == [("true", "all"), ("false", "important")]
    assert 'data-hidden-one="' in html and 'data-hidden-other="' in html
    assert re.search(r"<p[^>]*data-hidden-count[^>]*hidden", html), "hidden until it is used"


def test_the_feed_logic_stays_free_of_markup() -> None:
    js = (STATIC / "web.js").read_text()
    assert "regroupFeed" in js and "data-feed-filter" in js
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js


def test_a_delete_and_anything_above_risk_0_are_never_routine(tmp_path: Path) -> None:
    """The filter hides risk 0 and nothing else; a delete is never put aside, even at risk 0
    (review of T12f-1b, L1), and a folded burst that grows past risk 0 is no longer routine (L3)."""

    def script(main, mail, clock):
        for what, risk in (("exec a-calm", 0), ("exec b-one", 1), ("exec c-two", 2)):
            clock.advance(timedelta(seconds=1))
            main.append("exec", "run", what, risk=risk)
        clock.advance(timedelta(seconds=1))
        main.append("file", "delete", "work/.env", risk=0)
        clock.advance(timedelta(minutes=2))
        main.append("file", "modify", "work/x1", risk=0)
        main.append("file", "modify", "work/x2", risk=2)

    html = room_with(tmp_path, script, now=START + timedelta(minutes=5)).get("/panel").text
    routine = {text: "routine" in cls for cls, text in feed_lines(html)}
    by = lambda needle: next(v for text, v in routine.items() if needle in text)  # noqa: E731
    assert by("a-calm") is True
    assert by("b-one") is False and by("c-two") is False
    assert by(".env") is False, "a delete says so, even when it looks calm"
    assert by("x1") is False, "a folded burst takes the highest risk of its events"


def test_a_hidden_name_shows_when_it_has_the_keyboard() -> None:
    css = (STATIC / "web.css").read_text()
    assert ".pline.same .who:focus-visible" in css


# -- T12f-2a: Now, the agent's bar and the still tide ----------------------------------------


def agent_pages(tmp_path: Path, script=None) -> TestClient:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "agent_start", "")
    if script is not None:
        script(box, clock)
    return new_client(tmp_path, clock=lambda: START + timedelta(minutes=1))


def test_the_tide_is_drawn_still(tmp_path: Path) -> None:
    """No entrance: it draws where it is (the entrance left Snapshots blank when the browser did
    not run the animation), and it can already move the dot to a point it is shown."""
    html = agent_pages(tmp_path).get("/ahora").text
    assert 'class="tide-frame can-rewind" data-tide' in html and "is-intro" not in html
    css = (STATIC / "web.css").read_text()
    assert "is-intro" not in css and "tide-window-in" not in css
    js = (STATIC / "web.js").read_text()
    assert "is-intro" not in js and "function intro" not in js


def header_links(html: str) -> list[str]:
    nav = re.search(r'<header class="top">.*?<nav[^>]*>(.*?)</nav>', html, re.S)
    assert nav, "the header's navigation"
    return [text_of(a) for a in re.findall(r"<a [^>]*>.*?</a>", nav.group(1), re.S)]


@pytest.mark.parametrize(
    ("path", "current"),
    [
        ("/ahora", "Ahora"),
        ("/historia", "Historia"),
        ("/instantaneas", "Instantáneas"),
        ("/ahora/preguntar", "Preguntar"),
    ],
)
def test_the_agent_has_a_bar_with_its_tabs_and_the_header_is_only_global(
    tmp_path: Path, path: str, current: str
) -> None:
    html = agent_pages(tmp_path).get(path).text
    assert header_links(html) == ["Panel", "Peticiones", "Ajustes"]
    assert '<div class="agentbar a-' in html, "the agent's bar"
    tabs = re.search(r'<nav class="agentbar-tabs"[^>]*>(.*?)</nav>', html, re.S)
    assert tabs
    assert [text_of(a) for a in re.findall(r"<a [^>]*>.*?</a>", tabs.group(1), re.S)] == [
        "Ahora",
        "Historia",
        "Instantáneas",
        "Preguntar",
    ]
    assert re.findall(r'<a [^>]*aria-current="page"[^>]*>(.*?)</a>', tabs.group(1), re.S) == [
        current
    ]


def test_the_panel_and_the_other_pages_have_no_agent_bar(tmp_path: Path) -> None:
    web = agent_pages(tmp_path)
    for path in ("/panel", "/peticiones", "/ajustes"):
        assert "agentbar-tabs" not in web.get(path).text, path


def test_the_tabs_of_another_agent_stay_under_its_address(tmp_path: Path) -> None:
    clock = FakeClock(START)
    new_box(tmp_path, clock).append("system", "agent_start", "")
    other_box(tmp_path, "correo", clock).append("system", "agent_start", "")
    web = new_client(
        tmp_path,
        clock=lambda: START,
        others=[source(tmp_path, "correo", "Asistente de correo")],
    )
    html = web.get("/agentes/correo/historia").text
    tabs = re.search(r'<nav class="agentbar-tabs"[^>]*>(.*?)</nav>', html, re.S)
    assert tabs and re.findall(r'href="([^"]*)"', tabs.group(1)) == [
        f"{PREFIX_PATH}/agentes/correo/ahora",
        f"{PREFIX_PATH}/agentes/correo/historia",
        f"{PREFIX_PATH}/agentes/correo/instantaneas",
        f"{PREFIX_PATH}/agentes/correo/ahora/preguntar",
    ]
    assert "Asistente de correo" in text_of(html[html.index("agentbar") :][:600])
    assert "OpenClaw" not in text_of(tabs.group(1)) and "Tu agente" in text_of(
        html[html.index("agentbar-others") :][:400]
    ), "the other agents stay one click away"


@pytest.mark.parametrize(
    ("script", "sentence"),
    [
        (None, "Vigilado: todo lo que haga queda grabado."),
        (
            lambda box, clock: box.append("system", "space_pause", "", details={"frozen": True}),
            "Congelado: no hace nada hasta que liberes espacio.",
        ),
        (lambda box, clock: box.append("system", "agent_stop", ""), "Parado."),
    ],
)
def test_now_opens_with_the_state_in_one_sentence(tmp_path: Path, script, sentence: str) -> None:
    html = agent_pages(tmp_path, script).get("/ahora").text
    state = re.search(r'<div class="state" id="state"[^>]*>(.*?)</div>', html, re.S)
    assert state
    h1 = re.search(r'<h1 class="statement">(.*?)</h1>', state.group(1), re.S)
    assert h1 and text_of(h1.group(1)) == sentence
    assert html.count("<h1") == 1, "the sentence is the page's one heading"
    assert "El agente" not in text_of(state.group(1)), "no more 'El agente: vigilado'"


def test_the_state_sentence_in_english(tmp_path: Path) -> None:
    html = agent_pages(tmp_path).get("/ahora", headers={"accept-language": "en"}).text
    assert "Watched: everything it does is recorded." in text_of(html)


def test_a_state_keeps_the_dot_the_heartbeat_looks_for(tmp_path: Path) -> None:
    html = agent_pages(tmp_path).get("/ahora").text
    assert re.search(r'<div class="state" id="state".*?class="status-dot st-watched"', html, re.S)


def test_now_does_not_scroll_by_itself() -> None:
    """The sentence on top is the first thing seen; the "new lines" button says what arrives."""
    js = (STATIC / "web.js").read_text()
    assert "var stick = atBottom();" in js, "a long page is not dragged down by a new line"
    assert 'addEventListener("load", function () { toBottom(false); })' not in js
    assert not re.search(r"observe\(feed, \{ childList: true \}\);\s*toBottom\(false\)", js)


def test_calm_lines_are_quiet_and_a_delete_is_not(tmp_path: Path) -> None:
    def script(box, clock):
        clock.advance(timedelta(seconds=1))
        box.append("exec", "run", "git status")
        clock.advance(timedelta(seconds=1))
        box.append("exec", "run", "rm -rf build", risk=2)
        clock.advance(timedelta(seconds=1))
        box.append("file", "delete", "work/.env", risk=0)

    html = agent_pages(tmp_path, script).get("/ahora").text
    lines = {
        text_of(body): cls
        for cls, body in re.findall(
            r'<div class="(line[^"]*)" id="l-\d+"[^>]*>(.*?)</div>\s*(?=<div class="line|</div>)',
            html,
            re.S,
        )
    }
    by = lambda needle: next(c for text, c in lines.items() if needle in text)  # noqa: E731
    assert "routine" in by("git status")
    assert "routine" not in by("rm -rf build") and "routine" not in by(".env")


def test_the_chat_offers_questions_it_can_answer(tmp_path: Path) -> None:
    html = agent_pages(tmp_path).get("/ahora").text
    examples = re.search(r'<ul class="ask-examples"[^>]*>(.*?)</ul>', html, re.S)
    assert examples
    links = re.findall(r'<a [^>]*href="([^"]*)"[^>]*>(.*?)</a>', examples.group(1), re.S)
    assert len(links) == 3
    for href, label in links:
        assert href.startswith(f"{PREFIX_PATH}/ahora/preguntar?q="), href
        assert "hx-get=" in examples.group(1) and 'hx-target="#feed"' in examples.group(1)
        # each one is a question the rules answer (ask.py): not a "not yet"
        answer = new_client(tmp_path, clock=lambda: START).get(href).text
        assert "todavía no lo sé responder" not in answer, label


def test_the_questions_are_not_offered_twice_on_the_chat_page(tmp_path: Path) -> None:
    """Its own page already lists what it can answer; the examples are for Now."""
    html = agent_pages(tmp_path).get("/ahora/preguntar").text
    assert "ask-examples" not in html
    assert html.count(f'hx-get="{PREFIX_PATH}/ahora/preguntar?q=') == 3


def test_the_chat_field_is_not_pinned_on_a_phone() -> None:
    css = (STATIC / "web.css").read_text()
    assert re.search(r"@media \(max-width: 480px\) \{[^}]*\.ask \{ position: relative; \}", css)
    assert re.search(r"\.jump \{ position: fixed;", css), (
        "the 'new lines' button follows the screen"
    )


def test_a_name_with_hidden_characters_cannot_break_the_bars_markup(tmp_path: Path) -> None:
    """The tabs are named by the agent's own name element, never by a copy of it in an attribute:
    the marker `vis` writes for a bidi character carries quotes of its own (review of T12f-2a)."""
    clock = FakeClock(START)
    new_box(tmp_path, clock).append("system", "agent_start", "")
    other_box(tmp_path, "correo", clock).append("system", "agent_start", "")
    web = new_client(
        tmp_path,
        clock=lambda: START,
        others=[source(tmp_path, "correo", "Asistente\u202ede correo")],
    )
    html = web.get("/agentes/correo/ahora").text
    nav = re.search(r'<nav class="agentbar-tabs"[^>]*>', html)
    assert nav and nav.group(0) == '<nav class="agentbar-tabs" aria-labelledby="agentbar-name">'
    assert html.count('id="agentbar-name"') == 1 and "\u202e" not in html


# -- T12f-2b: History ------------------------------------------------------------

CHIPS = [
    ("Todo", ""),
    ("Lo importante", "riesgo=1"),
    ("Archivos", "origen=file"),
    ("Comandos", "origen=exec"),
    ("Internet", "origen=net"),
    ("Modelos", "origen=llm"),
    ("Lo que frenó backtide", "origen=gate"),
    ("Puntos para volver", "origen=snapshot"),
]


def history_web(tmp_path: Path) -> TestClient:
    """One agent with a day of events of every kind, over four days (the last is "today")."""
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("file", "create", "work/a.md", details={"type": "file"})
    box.append("exec", "run", "git status")
    clock.advance(timedelta(days=1))
    box.append("net", "connect", "api.example.com:443")
    box.append("llm", "call", "api.anthropic.com")
    clock.advance(timedelta(days=1))
    box.append(
        "gate", "held", "https://example.com/x", risk=2, details={"hold_id": "h-0123456789ab"}
    )
    box.append("file", "delete", "work/old.md", risk=1)
    clock.advance(timedelta(days=1))
    box.append("snapshot", "take", "s", snapshot_id="20261019T100000.000000Z-periodic")
    box.append("system", "log", "hello")
    return new_client(tmp_path, clock=lambda: START + timedelta(days=3, hours=1))


def chips_of(html: str) -> list[tuple[str, str, bool]]:
    nav = re.search(r'<nav class="chips"[^>]*>(.*?)</nav>', html, re.S)
    assert nav, "the filter chips"
    return [
        (text_of(label), href, current == ' aria-current="true"')
        for href, current, label in re.findall(
            r'<a href="([^"]*)"( aria-current="true")?[^>]*>(.*?)</a>', nav.group(1), re.S
        )
    ]


def test_history_filters_are_words_that_are_links(tmp_path: Path) -> None:
    html = history_web(tmp_path).get("/historia").text
    chips = chips_of(html)
    assert [label for label, _, _ in chips] == [label for label, _ in CHIPS]
    for (_, query), (_, href, _) in zip(CHIPS, chips, strict=True):
        assert href == f"{PREFIX_PATH}/historia" + (f"?{query}" if query else "")
    assert [c for c in chips if c[2]] == [("Todo", f"{PREFIX_PATH}/historia", True)]


@pytest.mark.parametrize(
    ("query", "current", "open_filters"),
    [
        ("origen=file", "Archivos", False),
        ("riesgo=1", "Lo importante", False),
        ("origen=snapshot", "Puntos para volver", False),
        ("origen=file&riesgo=1", None, True),
        ("accion=delete", None, True),
        ("rango=1h", None, True),
        ("desde=2026-10-18T00:00", None, True),
    ],
)
def test_the_chip_that_matches_the_filters_is_the_current_one(
    tmp_path: Path, query: str, current: str | None, open_filters: bool
) -> None:
    html = history_web(tmp_path).get(f"/historia?{query}").text
    assert [label for label, _, on in chips_of(html) if on] == ([current] if current else [])
    assert ('<details class="more-filters" open>' in html) is open_filters


def test_every_chip_leads_to_what_it_says(tmp_path: Path) -> None:
    web = history_web(tmp_path)
    shown = {
        "Todo": 8,
        "Lo importante": 2,  # risk 1 or more: the delete and the held request
        "Archivos": 2,
        "Comandos": 1,
        "Internet": 1,
        "Modelos": 1,
        "Lo que frenó backtide": 1,
        "Puntos para volver": 1,
    }
    for label, href, _ in chips_of(web.get("/historia").text):
        page = web.get(href.removeprefix(PREFIX_PATH)).text
        assert len(re.findall(r'<details class="event[^"]*" id="e-\d+"', page)) == shown[label], (
            label
        )


def test_the_other_filters_wait_behind_more_filters_in_words(tmp_path: Path) -> None:
    html = history_web(tmp_path).get("/historia").text
    form = re.search(
        r'<details class="more-filters">.*?(<form class="filters".*?</form>)', html, re.S
    )
    assert form, "the form sits inside 'More filters'"
    assert "hx-" not in form.group(1), "plain navigation: the chips and the form never disagree"
    assert "Más filtros" in text_of(html)
    options = re.findall(r"<option[^>]*>(.*?)</option>", form.group(1), re.S)
    assert "Archivos" in options and "Lo que frenó backtide" in options
    assert not {"file", "exec", "net", "llm", "gate", "snapshot"} & set(options), "no raw names"
    assert "Desde qué gravedad" in text_of(form.group(1))


def test_history_groups_the_rows_by_day_and_each_row_has_only_its_time(tmp_path: Path) -> None:
    html = history_web(tmp_path).get("/historia").text
    days = re.findall(r'<h2 class="day" data-day="([\d-]+)">(.*?)</h2>', html)
    assert [(key, text_of(label)) for key, label in days] == [
        ("2026-10-19", "Hoy"),
        ("2026-10-18", "Ayer"),
        ("2026-10-17", "17 oct"),
        ("2026-10-16", "16 oct"),
    ]
    first = html[html.index('class="day"') :]
    assert re.search(
        r'<time class="when" datetime="[^"]+" title="2026-10-19 10:00:00">10:00:00</time>', first
    )
    assert 'class="tag">' not in html[html.index('id="results"') :], "no machine tag on the row"
    assert html.count("Detalles</span>") == 8, "every row says it opens details"


def test_a_page_of_older_rows_carries_its_days_and_the_browser_joins_them(tmp_path: Path) -> None:
    fragment = history_web(tmp_path).get("/historia?antes=4", headers={"hx-request": "true"}).text
    assert '<h2 class="day"' in fragment and "<html" not in fragment
    js = (STATIC / "web.js").read_text()
    assert "function joinDays" in js and "data-day" in js


def test_the_details_are_told_in_words(tmp_path: Path) -> None:
    html = history_web(tmp_path).get("/historia?origen=snapshot").text
    labels = [text_of(dt) for dt in re.findall(r"<dt>(.*?)</dt>", html, re.S)]
    assert labels == [
        "Evento número",
        "Hora exacta (UTC)",
        "Para buscarlo",
        "Sobre qué",
        "Gravedad",
        "Punto para volver",
        "Huella",
        "Datos en bruto",
    ]
    assert "snapshot / take" in text_of(html), "the machine's name is still there, in the details"


def test_history_in_english(tmp_path: Path) -> None:
    html = history_web(tmp_path).get("/historia", headers={"accept-language": "en"}).text
    assert [label for label, _, _ in chips_of(html)] == [
        "All",
        "What matters",
        "Files",
        "Commands",
        "Internet",
        "Models",
        "What backtide stopped",
        "Points to go back to",
    ]
    assert re.search(r'<h2 class="day"[^>]*>Today</h2>', html) and "Yesterday</h2>" in html
    assert "More filters" in text_of(html) and "Details</span>" in html


def test_the_chips_scroll_sideways_on_a_phone() -> None:
    css = (STATIC / "web.css").read_text()
    assert re.search(r"@media \(max-width: 480px\) \{[^}]*\.chips \{[^}]*overflow-x: auto", css)


def test_a_hostile_event_stays_inside_its_details_and_a_day_heading_says_only_the_day(
    tmp_path: Path,
) -> None:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("file", 'a"b', '"><img src=x onerror=1>‮txt', details={"x": "<script>1</script>"})
    html = new_client(tmp_path, clock=lambda: START).get("/historia").text
    assert "<img" not in html and "<script>1" not in html and "‮" not in html
    heading = re.search(r'<h2 class="day"[^>]*>(.*?)</h2>', html, re.S)
    assert heading and text_of(heading.group(1)) == "Hoy"
    summary = re.search(r"<summary class=\"line\">(.*?)</summary>", html, re.S)
    assert summary and "<img" not in summary.group(1)


def test_a_burst_or_an_older_page_is_not_the_whole_of_a_chip(tmp_path: Path) -> None:
    """Only part of what a chip says is shown then, so no chip claims to be the page (L2)."""
    web = history_web(tmp_path)
    for query in ("origen=file&tras=1&antes=9", "antes=5"):
        assert not [c for c in chips_of(web.get(f"/historia?{query}").text) if c[2]], query
