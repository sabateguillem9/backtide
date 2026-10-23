"""T12f-1: the header, the control room and the requests, told in a person's words.

The agent's text is drawn as it is (no ligatures), a request is titled by what it wants to do
(the verb from what the gate read, never from what the agent wrote), the control room opens
with one sentence on what waits, and "trust" sits a level below approve and reject.
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
from tests.webkit import START, new_box, new_client

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
