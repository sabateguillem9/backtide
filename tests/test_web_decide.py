"""T10-5: deciding on held requests from the web (docs/32 section 11, decisions 9 and 10).

Most of this file is about what must NOT happen: a decision from a forged request (another
origin, no cookie, the link instead of the cookie, no CSRF, a reused ticket, the ticket of another
hold or of another verdict), a page that decides without ``--aprobar``, the agent's text read as
ours. The service is a fake (``FakeApprover``) except at the bottom, where the web goes through a
real control socket to a fake Guardian."""

import html as html_lib
import re
import shutil
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from backtide.blackbox import BlackBox
from backtide.service.control import ControlServer, ControlUnavailable
from backtide.web.approve import (
    ControlApprover,
    DecisionTickets,
    box_holds,
    held_request,
)
from backtide.web.rewind import Availability, Redeemed
from tests.test_service_control import FakeGuardian, me
from tests.webkit import PREFIX_PATH, ROOT, START, TOKEN, new_box, new_client

NOW = START + timedelta(minutes=1)
POST_HEADERS = {"origin": ROOT, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate"}
DECIDE = "/peticiones/decidir"
HOLD = "h-0123456789ab"
OTHER = "h-ba9876543210"
RLO = "‮"


def hold(hold_id: str = HOLD, **changes: Any) -> dict[str, Any]:
    """A hold as the service lists it (ProxyChannel.pending)."""
    base = {
        "hold_id": hold_id, "risk": 2, "reason": "send", "phrase": "Telegram: …",
        "method": "POST", "host": "api.telegram.org", "path": "/bot[REDACTED]/sendMessage",
        "target": "https://api.telegram.org/bot[REDACTED]/sendMessage", "expires_in_s": 240,
        "waiting": True, "seq": 1, "held_at": "2026-10-16T10:00:30Z",
        "expires_at": "2026-10-16T10:05:30Z", "batches": ["recipient", "kind"],
        "trustable": True,
        "view": {"translator": "telegram", "effect": "send", "notes": [], "cut": False,
                 "recipients": ["556"], "recipients_total": 1, "reply_to": [],
                 "subject": None, "first_lines": "hola", "target": None, "attachments": [],
                 "attachments_total": 0},
    }  # fmt: skip
    return base | changes


class FakeApprover:
    enabled = True

    def __init__(self, state: Availability = Availability.READY) -> None:
        self.state = state
        self.listed: list[dict[str, Any]] = [hold(), hold(OTHER, trustable=False)]
        self.calls: list[tuple[str, str]] = []
        self.outcome = "released"
        self.error: Exception | None = None

    def availability(self) -> Availability:
        return self.state

    def holds(self) -> list[dict[str, Any]]:
        if self.error is not None:
            raise self.error
        return self.listed

    def decide(self, hold_id: str, verdict: str) -> dict[str, Any]:
        self.calls.append((verdict, hold_id))
        if self.error is not None:
            raise self.error
        outcome = self.outcome if verdict == "approve" else "rejected"
        return {"ok": True, "outcome": outcome, "message": "Aprobada."}

    def trust(self, hold_id: str) -> dict[str, Any]:
        self.calls.append(("trust", hold_id))
        return {"ok": True, "outcome": "trusted", "message": "Añadido.", "hold": "released"}

    def trusted(self) -> list[dict[str, Any]]:
        return [{"trust_id": "t-0a1b2c3d", "translator": "telegram", "recipient": "557",
                 "added_at": "2026-10-16T09:00:00Z", "by": "web"}]  # fmt: skip

    def untrust(self, trust_id: str) -> dict[str, Any]:
        self.calls.append(("untrust", trust_id))
        return {"ok": True, "outcome": "removed", "message": "Quitado."}

    def batches(self) -> list[dict[str, Any]]:
        return [{"rule_id": "b-01234567", "scope": "kind", "translator": None, "method": "POST",
                 "host": "api.ejemplo.dev", "route": "/v1/*", "until": "2026-10-16T11:00:00Z",
                 "uses": 1}]  # fmt: skip

    def end_batch(self, rule_id: str) -> dict[str, Any]:
        self.calls.append(("end_batch", rule_id))
        return {"ok": True, "outcome": "ended", "message": "Revocado."}


@pytest.fixture
def fake() -> FakeApprover:
    return FakeApprover()


@pytest.fixture
def web(tmp_path: Path, fake: FakeApprover) -> TestClient:
    new_box(tmp_path).append("file", "create", "work/notas.md")
    return new_client(tmp_path, approver=fake, clock=lambda: NOW)


def text_of(page: str) -> str:
    return html_lib.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))).strip()


def hidden(page: str) -> dict[str, str]:
    return {
        name: html_lib.unescape(value)
        for name, value in re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page)
    }


def confirm(web: TestClient, verb: str, subject: str = HOLD) -> dict[str, str]:
    page = web.get(f"{DECIDE}?{urlencode({'id': subject, 'v': verb})}")
    assert page.status_code == 200, page.text[:300]
    fields = hidden(page.text)
    assert set(fields) == {"csrf", "ticket", "id", "v"}, text_of(page.text)[:500]
    return fields


def post(web: TestClient, fields: dict[str, str], **headers: str) -> Any:
    return web.post(DECIDE, data=fields, headers={**POST_HEADERS, **headers})


# -- the panel and the page --------------------------------------------------------------------


def test_with_aprobar_the_buttons_lead_to_a_confirmation(web: TestClient) -> None:
    page = web.get("/panel").text
    assert f'href="{PREFIX_PATH}/peticiones/decidir?id={HOLD}&amp;v=aprobar"' in page
    assert f'href="{PREFIX_PATH}/peticiones/decidir?id={HOLD}&amp;v=rechazar"' in page
    assert f'href="{PREFIX_PATH}/peticiones/decidir?id={HOLD}&amp;v=confiar"' in page
    assert f"id={OTHER}&amp;v=confiar" not in page, "only what may be trusted offers it"
    assert f'href="{PREFIX_PATH}/peticiones/ver?id={HOLD}"' in page
    assert "<form" not in page, "the panel itself changes nothing"
    said = text_of(page)
    assert "Quiere enviar un mensaje por Telegram" in said, "our words, from the closed tables"
    assert "Lo que pide el agente (texto suyo, no de backtide):" in said and "556" in said


def test_without_aprobar_nothing_decides_and_the_post_does_not_exist(tmp_path: Path) -> None:
    new_box(tmp_path).append(
        "gate", "held", "https://example.com/y", risk=3,
        details={"hold_id": HOLD, "reason": "delete", "expires_at": "2026-10-16T10:05:00Z"},
    )  # fmt: skip
    off = FakeApprover(Availability.DISABLED)
    off.enabled = False
    web = new_client(tmp_path, approver=off, clock=lambda: NOW)
    page = web.get("/panel").text
    assert "/peticiones/decidir" not in page and HOLD in page, "listed from the black box"
    assert "backtide web --aprobar" in text_of(page)
    assert off.calls == [] and re.findall(r"<button[^>]*disabled", page)
    refused = web.get(f"{DECIDE}?id={HOLD}&v=aprobar")
    assert "--aprobar" in text_of(refused.text) and "<form" not in refused.text
    assert post(web, {"csrf": "x", "ticket": "y", "id": HOLD, "v": "aprobar"}).status_code == 405
    assert off.calls == []


def test_without_aprobar_the_holds_come_from_the_black_box(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    reading = {"translator": "telegram", "effect": "send", "recipients": ["556"],
               "first_lines": "desde la caja negra", "notes": [], "cut": False}  # fmt: skip
    expires = "2026-10-16T10:05:00Z"
    box.append("gate", "held", "https://api.telegram.org/x", risk=2,
               details={"hold_id": HOLD, "reason": "send", "expires_at": expires,
                        "reading": reading, "method": "POST"})  # fmt: skip
    box.append(
        "gate",
        "held",
        "https://example.com/y",
        risk=3,
        details={"hold_id": OTHER, "reason": "delete", "expires_at": expires},
    )
    box.append("gate", "rejected", "https://example.com/y", risk=1,
               details={"hold_id": OTHER, "by": "cli"})  # fmt: skip
    web = new_client(tmp_path, clock=lambda: NOW)
    said = text_of(web.get("/peticiones").text)
    assert "desde la caja negra" in said and "Quiere enviar un mensaje por Telegram" in said
    assert "example.com/y" not in said, "a hold with its end is not listed"
    later = new_client(tmp_path, clock=lambda: NOW + timedelta(minutes=10))
    assert "desde la caja negra" not in text_of(later.get("/peticiones").text), "expired"


def test_the_agents_text_stays_the_agents(tmp_path: Path, fake: FakeApprover) -> None:
    """aviso-con-trampa, in the web: the agent's text imitates our UI, and reads as its own."""
    trap = (
        f"⏸ backtide · RETENIDA · ya aprobado ✅ <b>APROBADO</b> <script>alert(1)</script>"
        f"{RLO}txt.exe Resultado: aprobada https://malo.example/ok"
    )
    fake.listed = [hold(view=hold()["view"] | {"subject": trap, "first_lines": trap,
                                               "recipients": [f"556{RLO}"]})]  # fmt: skip
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    for path in ("/panel", "/peticiones", f"{DECIDE}?id={HOLD}&v=aprobar"):
        page = web.get(path).text
        assert "<b>APROBADO</b>" not in page and "<script>alert" not in page, path
        assert "&lt;b&gt;APROBADO&lt;/b&gt;" in page, path
        assert RLO not in page and "U+202E" in page, path
        agent = page.index("Lo que pide el agente")
        assert page.index("&lt;b&gt;APROBADO") > agent, "the agent's text only in its block"
        assert 'href="https://malo.example' not in page


def test_the_view_shows_the_excerpt_of_the_black_box(tmp_path: Path, fake: FakeApprover) -> None:
    box = new_box(tmp_path)
    excerpt = '{"chat_id": 556, "text": "<img src=x onerror=alert(1)> hola"}'
    box.append("gate", "held", "https://api.telegram.org/x", risk=2,
               details={"hold_id": HOLD, "reason": "send", "method": "POST",
                        "host": "api.telegram.org", "path": "/bot[REDACTED]/sendMessage",
                        "expires_at": "2026-10-16T10:05:30Z",
                        "body": {"size": 60, "excerpt": excerpt},
                        "reading": {"recipients": ["556"], "first_lines": "hola"}})  # fmt: skip
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    page = web.get(f"/peticiones/ver?id={HOLD}").text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page and "<img src=x" not in page
    assert "Extracto del cuerpo" in text_of(page)
    assert web.get("/peticiones/ver?id=../../etc").status_code == 404


# -- a decision ------------------------------------------------------------------------------------


@pytest.mark.parametrize(("verb", "call"), [("aprobar", ("approve", HOLD)),
                                             ("rechazar", ("reject", HOLD))])  # fmt: skip
def test_a_decision_goes_to_the_service_once(
    web: TestClient, fake: FakeApprover, verb: str, call: tuple[str, str]
) -> None:
    fields = confirm(web, verb)
    done = post(web, fields)
    assert done.status_code == 200, done.text[:300]
    assert fake.calls == [call]
    again = post(web, fields)
    assert "ya se usó" in text_of(again.text) and fake.calls == [call], "a ticket works once"


def test_a_ticket_is_bound_to_its_verb_and_its_hold(web: TestClient, fake: FakeApprover) -> None:
    reject = confirm(web, "rechazar")
    assert "caducó o no es de esta decisión" in text_of(
        post(web, reject | {"v": "aprobar"}).text
    ), "a ticket to reject never approves"
    other = confirm(web, "aprobar", OTHER)
    post(web, other | {"id": HOLD})
    assert fake.calls == [], "nor one of another hold"


@pytest.mark.parametrize(
    "headers",
    [
        {"origin": "http://evil.example"},
        {"origin": "null"},
        {"origin": ROOT, "sec-fetch-site": "cross-site"},
        {"origin": ROOT, "sec-fetch-site": "same-site"},
        {"origin": ROOT, "sec-fetch-site": "none"},
    ],
)
def test_a_decision_from_another_page_is_refused(
    web: TestClient, fake: FakeApprover, headers: dict[str, str]
) -> None:
    fields = confirm(web, "aprobar")
    reply = web.post(DECIDE, data=fields, headers={**POST_HEADERS, **headers})
    assert reply.status_code == 403 and fake.calls == []


def test_a_decision_without_the_origin_cookie_or_csrf_is_refused(
    tmp_path: Path, web: TestClient, fake: FakeApprover
) -> None:
    fields = confirm(web, "aprobar")
    assert web.post(DECIDE, data=fields, headers={"sec-fetch-site": "same-origin"}).status_code \
        == 403  # fmt: skip
    assert post(web, {k: v for k, v in fields.items() if k != "csrf"}).status_code == 400
    assert post(web, fields | {"csrf": "x" * 43}).status_code == 403
    stranger = new_client(tmp_path, logged_in=False, approver=fake, clock=lambda: NOW)
    assert stranger.post(DECIDE, data=fields, headers=POST_HEADERS).status_code == 401
    with_link = stranger.post(f"{DECIDE}?t={TOKEN}", data=fields, headers=POST_HEADERS)
    assert with_link.status_code == 401, "the link's token never decides"
    big = fields | {"v": "aprobar" + "x" * 3000}
    assert post(web, big).status_code == 413
    assert fake.calls == []
    assert post(web, fields).status_code == 200 and fake.calls == [("approve", HOLD)]


def test_aprobar_y_confiar_needs_its_box(web: TestClient, fake: FakeApprover) -> None:
    page = web.get(f"{DECIDE}?id={HOLD}&v=confiar")
    assert 'name="confirmo"' in page.text and "solo a este destinatario" in text_of(page.text)
    fields = hidden(page.text)
    assert "marcar la casilla" in text_of(post(web, fields).text) and fake.calls == []
    fields = confirm_trust(web)
    done = post(web, fields | {"confirmo": "si"})
    assert done.status_code == 200 and fake.calls == [("trust", HOLD)]
    assert "Destinatario de confianza añadido" in text_of(done.text)


def confirm_trust(web: TestClient) -> dict[str, str]:
    return hidden(web.get(f"{DECIDE}?id={HOLD}&v=confiar").text)


def test_what_may_not_be_trusted_is_not_offered(web: TestClient, fake: FakeApprover) -> None:
    page = web.get(f"{DECIDE}?id={OTHER}&v=confiar")
    assert "<form" not in page.text and "una a una" in text_of(page.text)
    approve = confirm(web, "aprobar")
    assert post(web, approve | {"confirmo": "si"}).status_code == 400, "no box on another verb"
    assert fake.calls == []


# -- the final review of T10 -------------------------------------------------------------------

LONG = "ana@ejemplo.com." + "x" * 190 + ".malo.io"


def test_a_long_address_is_cut_in_the_middle_with_our_mark_and_its_domain_apart(
    tmp_path: Path, fake: FakeApprover
) -> None:
    """Finding 4: the start of a long address would read as another one. The end (its domain)
    stays, the cut is marked by us, and the confirmation names each domain in our words."""
    mail = hold()["view"] | {"translator": "gmail", "recipients": [LONG],
                             "reply_to": ["ana@ejemplo.com"]}  # fmt: skip
    fake.listed = [hold(view=mail, trustable=False)]
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    for path in ("/peticiones", f"{DECIDE}?id={HOLD}&v=aprobar"):
        page = web.get(path).text
        assert re.search(r'<span class="cut">…\(\d+\)…</span>[^<]*\.malo\.io', page), path
        assert "ana@ejemplo.com.xxxx" in page and "x" * 150 not in page, path
    said = text_of(web.get(f"{DECIDE}?id={HOLD}&v=aprobar").text)
    domains = said[said.index("Dominio de cada dirección") : said.index("Lo que pide el agente")]
    assert "malo.io" in domains and "ejemplo.com" in domains


def test_the_confirmation_shows_reply_to_and_attachments_as_the_list_does(
    tmp_path: Path, fake: FakeApprover
) -> None:
    """Finding 8: the page where the person says yes shows what the list shows."""
    view = hold()["view"] | {"translator": "gmail", "recipients": ["ana@ejemplo.com"],
                             "reply_to": ["otro@malo.example"],
                             "attachments": [{"name": "factura.pdf", "size": 10}]}  # fmt: skip
    fake.listed = [hold(view=view, trustable=False)]
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    said = text_of(web.get(f"{DECIDE}?id={HOLD}&v=aprobar").text)
    agent = said[said.index("Lo que pide el agente") :]
    assert "Responder a: otro@malo.example" in agent and "Adjuntos: factura.pdf" in agent


def test_mail_and_an_at_name_say_why_they_cannot_be_trusted(
    tmp_path: Path, fake: FakeApprover
) -> None:
    """Findings 2 and 9: no "aprobar y confiar" for mail (until the owner's accounts exist)
    nor for a Telegram @name; the list says why in a few words."""
    mail = hold()["view"] | {"translator": "gmail", "recipients": ["ana@ejemplo.com"]}
    name = hold()["view"] | {"recipients": ["@canal_publico"]}
    fake.listed = [hold(view=mail, trustable=False), hold(OTHER, view=name, trustable=False)]
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    page = web.get("/peticiones").text
    assert "v=confiar" not in page
    assert 'data-trust-off="mail"' in page and 'data-trust-off="name"' in page
    assert "aún no con correo" in text_of(page) and "no con un @nombre" in text_of(page)


@pytest.mark.parametrize(
    ("chat", "note"), [("-1001234567890", "channel"), ("-4242", "group"), ("556", None)]
)
def test_trusting_a_group_or_a_channel_says_who_reads_it(
    tmp_path: Path, fake: FakeApprover, chat: str, note: str | None
) -> None:
    """Finding 9: a negative id is a group, -100... a supergroup or a channel."""
    fake.listed = [hold(view=hold()["view"] | {"recipients": [chat]})]
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    page = web.get(f"{DECIDE}?id={HOLD}&v=confiar").text
    if note is None:
        assert "data-trust-note" not in page
    else:
        assert f'data-trust-note="{note}"' in page and "lo leen todos" in text_of(page)


def test_trusting_says_how_many_other_holds_to_that_recipient_are_decided_apart(
    tmp_path: Path, fake: FakeApprover
) -> None:
    """Finding 1, option (a): the other holds to the newly trusted recipient stay open and are
    decided one by one; the confirmation says how many there are."""
    third = "h-00000000000c"
    fake.listed = [hold(), hold(OTHER, trustable=False), hold(third)]
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=fake, clock=lambda: NOW)
    page = web.get(f"{DECIDE}?id={HOLD}&v=confiar").text
    assert 'data-others="2"' in page and "Hay 2 retenida(s) más" in text_of(page)
    fake.listed = [hold()]
    assert "data-others" not in web.get(f"{DECIDE}?id={HOLD}&v=confiar").text


def test_a_list_from_the_black_box_that_may_miss_holds_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 7: without --aprobar the list reads the newest BOX_ROWS rows of the black box;
    when even the oldest of them is within the 15 minutes a hold may wait, older holds may be
    missing, and the page says "puede que haya más"."""
    monkeypatch.setattr("backtide.web.approve.BOX_ROWS", 5)
    monkeypatch.setattr("backtide.web.app.BOX_ROWS", 5)
    box = new_box(tmp_path)
    box.append("gate", "held", "https://example.com/y", risk=2,
               details={"hold_id": HOLD, "reason": "write", "expires_at": "2026-10-16T10:05:00Z",
                        "method": "POST", "host": "example.com", "path": "/y"})  # fmt: skip
    for n in range(3):
        box.append("file", "create", f"work/{n}.md")
    web = new_client(tmp_path, clock=lambda: NOW)
    assert "data-partial" not in web.get("/peticiones").text, "every row was read"
    for n in range(3):
        box.append("file", "create", f"work/mas-{n}.md")
    page = web.get("/peticiones").text
    assert "data-partial" in page and "Puede que haya más" in text_of(page)
    assert "example.com/y" not in text_of(page), "the hold is past what was read"
    panel = web.get("/panel").text
    h1 = panel[panel.index("<h1") : panel.index("</h1>")]
    assert "No se sabe si algo espera tu sí." in h1, "not 'nothing waits' (T12f-1, L3)"


def test_box_partial_needs_a_full_read_whose_oldest_row_is_recent() -> None:
    from backtide.blackbox import Event, Source
    from backtide.web.approve import BOX_ROWS, box_partial

    def rows(ts: str, count: int) -> list[Event]:
        return [Event(seq=i + 1, ts=ts, source=Source.FILE, action="create", target="x",
                      details={}, risk=0, snapshot_id=None, prev_hash="", hash="")
                for i in range(count)]  # fmt: skip

    recent, old = "2026-10-16T10:00:00.000000Z", "2026-10-16T09:00:00.000000Z"
    assert box_partial(rows(recent, BOX_ROWS), NOW)
    assert not box_partial(rows(recent, BOX_ROWS - 1), NOW)
    assert not box_partial(rows(old, BOX_ROWS), NOW)


def test_batches_and_trusted_recipients_are_listed_and_ended(
    web: TestClient, fake: FakeApprover
) -> None:
    page = web.get("/peticiones").text
    assert "api.ejemplo.dev/v1/*" in text_of(page) and "557" in text_of(page)
    revoke = confirm(web, "revocar", "b-01234567")
    assert post(web, revoke).status_code == 200
    forget = confirm(web, "olvidar", "t-0a1b2c3d")
    assert post(web, forget).status_code == 200
    assert fake.calls == [("end_batch", "b-01234567"), ("untrust", "t-0a1b2c3d")]
    assert web.get(f"{DECIDE}?id=b-ffffffff&v=revocar").text.count("<form") == 0


@pytest.mark.parametrize(
    ("verb", "subject"),
    [("aprobar", "b-01234567"), ("revocar", HOLD), ("olvidar", HOLD), ("borrar", HOLD),
     ("aprobar", "h-XYZ")],
)  # fmt: skip
def test_an_id_of_the_wrong_shape_is_refused(
    web: TestClient, fake: FakeApprover, verb: str, subject: str
) -> None:
    page = web.get(f"{DECIDE}?{urlencode({'id': subject, 'v': verb})}")
    assert "<form" not in page.text
    reply = post(web, {"csrf": "c", "ticket": "t", "id": subject, "v": verb})
    assert reply.status_code == 400 and fake.calls == []


def test_the_outcome_is_shown_paused_too(web: TestClient, fake: FakeApprover) -> None:
    fake.outcome = "paused"
    done = post(web, confirm(web, "aprobar"))
    assert "pausado" in text_of(done.text)


def test_a_service_that_goes_away_decides_nothing(web: TestClient, fake: FakeApprover) -> None:
    fields = confirm(web, "aprobar")
    fake.error = ControlUnavailable("no")
    done = post(web, fields)
    assert done.status_code == 503 and "no contesta" in text_of(done.text)


# -- the pieces --------------------------------------------------------------------------------


def test_tickets_expire_with_their_hold() -> None:
    now = [datetime(2026, 10, 16, 10, 0, tzinfo=UTC)]
    tickets = DecisionTickets(lambda: now[0])
    ticket = tickets.issue("aprobar", HOLD, until=now[0] + timedelta(seconds=30))
    now[0] += timedelta(seconds=31)
    assert tickets.redeem(ticket, "aprobar", HOLD) is Redeemed.INVALID
    assert tickets.redeem(ticket, "aprobar", HOLD) is Redeemed.SPENT


@pytest.mark.parametrize(
    "raw",
    [hold(hold_id="nope"), hold(risk=7), hold(risk=True), hold(expires_at="x", expires_in_s=-1)],
)
def test_a_hold_that_does_not_fit_is_dropped(raw: dict[str, Any]) -> None:
    assert held_request(raw, now=NOW) is None


def test_box_holds_skip_what_ended_or_expired(tmp_path: Path) -> None:
    box: BlackBox = new_box(tmp_path)
    for hold_id in (HOLD, OTHER):
        box.append("gate", "held", "x", risk=2,
                   details={"hold_id": hold_id, "expires_at": "2026-10-16T10:05:00Z"})  # fmt: skip
    box.append("gate", "approved", "x", risk=1, details={"hold_id": OTHER, "by": "web"})
    found = box_holds(list(reversed(box.events())), NOW)
    assert [h["hold_id"] for h in found] == [HOLD]


# -- through a real control socket -----------------------------------------------------------------


@pytest.fixture
def socket_folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vg"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def test_the_web_decides_through_the_control_socket_as_web(
    tmp_path: Path, socket_folder: Path
) -> None:
    guardian = FakeGuardian()
    guardian.holds = [hold()]
    server = ControlServer(guardian, socket_folder / "control.sock", peer=me)
    server.start()
    try:
        approver = ControlApprover(server.path, enabled=True, wait=0, peer=me)
        new_box(tmp_path).append("file", "create", "work/notas.md")
        web = new_client(tmp_path, approver=approver, clock=lambda: NOW)
        assert "556" in text_of(web.get("/panel").text)
        done = post(web, confirm(web, "aprobar"))
        assert done.status_code == 200, text_of(done.text)
        assert [d[:3] for d in guardian.decisions] == [(HOLD, "approve", "web")]
        trusted = post(web, confirm_trust(web) | {"confirmo": "si"})
        assert trusted.status_code == 200
        assert [d[:3] for d in guardian.decisions][-1] == (HOLD, "trust", "web")
    finally:
        server.close()
    assert ControlApprover(server.path, enabled=False).availability() is Availability.DISABLED
