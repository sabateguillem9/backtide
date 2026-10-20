"""T12e: the Settings page of the web ("Ajustes"). Keys are write-only: most of this file is about
what must NOT happen. A page, a reply, a stream, a log line or a black-box event with a key or a
piece of it; a change from a forged request, a replayed or stale confirmation, the link instead
of the cookie, another origin; a page that writes without ``--ajustes``.

The service is a fake (``FakeSettings``) in most tests. The end-to-end test at the bottom goes
through a real control socket to the real ``Settings`` on a real black box, and greps everything
it produced for the test key and every 8-character piece of it."""

import html as html_lib
import json
import logging
import re
import secrets
import shutil
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from backtide.blackbox import BlackBox
from backtide.service.control import ControlServer, ControlUnavailable
from backtide.service.settings import Applied, Settings
from backtide.web.rewind import Availability, Redeemed
from backtide.web.settings import ControlSettings, SettingTickets, views
from tests.test_service_control import FakeGuardian, me
from tests.webkit import KEY, PREFIX_PATH, ROOT, SESSION, TOKEN, new_box, new_client, parse_sse

NOW = datetime(2026, 10, 20, 10, 0, tzinfo=UTC)
POST_HEADERS = {"origin": ROOT, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate"}
SAVE = "/ajustes/guardar"


def anthropic_key() -> str:
    return "sk-ant-api03-TEST" + secrets.token_urlsafe(48).replace("=", "")


def bot_token() -> str:
    """A made-up token with a random bot id (a fixed one could match the test prefix's digits)."""
    return f"{secrets.randbelow(9 * 10**9) + 10**9}:AA" + secrets.token_urlsafe(30)[:33]


def pieces(value: str) -> set[str]:
    return {value[i : i + 8] for i in range(len(value) - 7)} | {value}


class FakeSettings:
    enabled = True

    def __init__(self, state: Availability = Availability.READY) -> None:
        self.state = state
        self.shown: dict[str, dict[str, Any]] = {
            "anthropic": {"set": True, "tail": "WXyz", "changed": "2026-10-19T08:00:00Z",
                          "in_use": True, "problem": None},
            "openai": {"set": False, "tail": None, "changed": None, "in_use": False,
                       "problem": None},
            "telegram": {"set": False, "tail": None, "chat_tail": None, "changed": None,
                         "in_use": True, "problem": None},
        }  # fmt: skip
        self.sets: list[tuple[str, str, str | None]] = []
        self.clears: list[str] = []
        self.error: Exception | None = None

    def availability(self) -> Availability:
        return self.state

    def status(self) -> dict[str, dict[str, Any]]:
        if self.error is not None:
            raise self.error
        return self.shown

    def set_secret(self, kind: str, value: str, chat_id: str | None) -> dict[str, Any]:
        self.sets.append((kind, value, chat_id))
        if self.error is not None:
            raise self.error
        return {"ok": True, "outcome": "saved", "message": "Guardada.", "applied": "now"}

    def clear_secret(self, kind: str) -> dict[str, Any]:
        self.clears.append(kind)
        return {"ok": True, "outcome": "cleared", "message": "Quitada.", "applied": "now"}


@pytest.fixture
def fake() -> FakeSettings:
    return FakeSettings()


@pytest.fixture
def web(tmp_path: Path, fake: FakeSettings) -> TestClient:
    new_box(tmp_path).append("file", "create", "work/notas.md")
    return new_client(tmp_path, settings=fake, clock=lambda: NOW)


def text_of(page: str) -> str:
    return html_lib.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))).strip()


def hidden(page: str) -> dict[str, str]:
    return {
        name: html_lib.unescape(value)
        for name, value in re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page)
    }


def confirm(web: TestClient, action: str, kind: str) -> dict[str, str]:
    path = "/ajustes/cambiar" if action == "set" else "/ajustes/quitar"
    page = web.get(f"{path}?{urlencode({'tipo': kind})}")
    assert page.status_code == 200, page.text[:300]
    fields = hidden(page.text)
    assert set(fields) == {"csrf", "ticket", "tipo", "accion"}, page.text[:500]
    return fields


def post(web: TestClient, fields: dict[str, str], **headers: str) -> Any:
    return web.post(SAVE, data=fields, headers={**POST_HEADERS, **headers})


# -- the page -------------------------------------------------------------------------------------


def test_the_page_says_what_is_set_and_never_more(web: TestClient) -> None:
    page = web.get("/ajustes")
    assert page.status_code == 200
    said = text_of(page.text)
    assert "Clave de Anthropic configurada, termina en …WXyz, cambiada el" in said
    assert "Clave de OpenAI sin configurar" in said
    assert "Ningún proveedor de [proxy] se llama así" in said
    assert "Bot de Telegram sin configurar" in said
    assert "Tope de gasto" in said and "Llega con T11" in said
    assert re.search(r'<input id="setting-cap"[^>]* disabled', page.text)
    assert "<form" not in page.text, "the list itself changes nothing"
    assert f'href="{PREFIX_PATH}/ajustes/quitar?tipo=anthropic"' in page.text
    assert f'href="{PREFIX_PATH}/ajustes/quitar?tipo=openai"' not in page.text
    assert f'href="{PREFIX_PATH}/ajustes"' in page.text, "the menu has it"


def test_a_tail_that_is_not_four_plain_characters_is_never_shown(
    web: TestClient, fake: FakeSettings
) -> None:
    fake.shown["anthropic"]["tail"] = "sk-ant-api03-WHOLEKEY"
    fake.shown["telegram"] = {"set": True, "tail": "<b>x", "chat_tail": "12345678"}
    said = text_of(web.get("/ajustes").text)
    assert "WHOLEKEY" not in said and "<b>x" not in said and "12345678" not in said
    assert [v.tail for v in views(fake.shown)] == [None, None, None]


@pytest.mark.parametrize(
    "state", [Availability.DISABLED, Availability.NO_SERVICE, Availability.OTHER_USER]
)
def test_without_the_service_the_page_says_why_and_offers_nothing(
    tmp_path: Path, state: Availability
) -> None:
    fake = FakeSettings(state)
    web = new_client(tmp_path, settings=fake)
    page = web.get("/ajustes").text
    assert "/ajustes/cambiar" not in page and "/ajustes/quitar" not in page
    assert "WXyz" not in page, "the service is not even asked"
    if state is Availability.DISABLED:
        assert "backtide web --ajustes" in text_of(page)
    confirmation = web.get("/ajustes/cambiar?tipo=anthropic")
    assert "<form" not in confirmation.text


def test_without_ajustes_there_is_no_post_at_all(tmp_path: Path) -> None:
    web = new_client(tmp_path, settings=ControlSettings(tmp_path / "control.sock"))
    assert "backtide web --ajustes" in text_of(web.get("/ajustes").text)
    reply = web.post(SAVE, data={"csrf": "x"}, headers=POST_HEADERS)
    assert reply.status_code == 405, "the Guard has no door for it"
    plain = new_client(tmp_path)  # no settings client at all
    assert plain.post(SAVE, data={"csrf": "x"}, headers=POST_HEADERS).status_code == 405


def test_a_service_gone_while_reading_says_so(web: TestClient, fake: FakeSettings) -> None:
    fake.error = ControlUnavailable("gone")
    page = text_of(web.get("/ajustes").text)
    assert "tiene que estar en marcha" in page


# -- setting a key --------------------------------------------------------------------------------


def test_a_key_is_set_with_its_confirmation_and_nothing_comes_back(
    web: TestClient, fake: FakeSettings
) -> None:
    page = web.get("/ajustes/cambiar?tipo=openai").text
    assert 'type="password" name="valor"' in page
    assert 'name="confirmo"' not in page, "nothing to replace"
    fields = confirm(web, "set", "openai")
    key = "sk-proj-TEST" + secrets.token_urlsafe(40)
    reply = post(web, {**fields, "valor": f"  {key}  "})
    assert reply.status_code == 200
    assert fake.sets == [("openai", key, None)], "the paste's spaces are dropped"
    assert 'data-outcome="saved"' in reply.text
    assert "El proxy ya usa lo nuevo." in text_of(reply.text)
    assert not any(piece in reply.text for piece in pieces(key))
    again = post(web, {**fields, "valor": key})
    assert again.status_code == 400 and "ya se ha usado" in text_of(again.text)
    assert len(fake.sets) == 1


def test_replacing_a_key_needs_the_box_ticked(web: TestClient, fake: FakeSettings) -> None:
    page = web.get("/ajustes/cambiar?tipo=anthropic").text
    assert re.search(r'<input type="checkbox" name="confirmo" value="si" required>', page)
    assert "…WXyz" in text_of(page)
    fields = confirm(web, "set", "anthropic")
    refused = post(web, {**fields, "valor": anthropic_key()})
    assert refused.status_code == 400 and "marcar la casilla" in text_of(refused.text)
    assert fake.sets == []
    fields = confirm(web, "set", "anthropic")
    key = anthropic_key()
    assert post(web, {**fields, "valor": key, "confirmo": "si"}).status_code == 200
    assert fake.sets == [("anthropic", key, None)]


def test_telegram_sends_the_token_and_the_chat(web: TestClient, fake: FakeSettings) -> None:
    page = web.get("/ajustes/cambiar?tipo=telegram").text
    assert 'name="chat"' in page and "Se aplica al reiniciar" in text_of(page)
    fields = confirm(web, "set", "telegram")
    token = bot_token()
    assert post(web, {**fields, "valor": token, "chat": " 42424242 "}).status_code == 200
    assert fake.sets == [("telegram", token, "42424242")]
    fields = confirm(web, "set", "telegram")
    assert post(web, {**fields, "valor": token}).status_code == 400, "Telegram's form has a chat"


def test_a_key_is_removed_with_its_own_confirmation(web: TestClient, fake: FakeSettings) -> None:
    page = text_of(web.get("/ajustes/quitar?tipo=anthropic").text)
    assert "no arranca con un proveedor de [proxy] sin clave" in page
    refused = web.get("/ajustes/quitar?tipo=openai")
    assert "<form" not in refused.text and "No hay nada que quitar" in text_of(refused.text)
    fields = confirm(web, "clear", "anthropic")
    assert post(web, fields).status_code == 200
    assert fake.clears == ["anthropic"]
    fields = confirm(web, "clear", "anthropic")
    assert post(web, {**fields, "valor": anthropic_key()}).status_code == 400
    assert fake.clears == ["anthropic"], "a removal carries no key"


def test_a_ticket_is_for_its_own_action_and_kind(web: TestClient, fake: FakeSettings) -> None:
    fields = confirm(web, "clear", "anthropic")
    assert post(web, {**fields, "tipo": "openai"}).status_code == 400
    fields = confirm(web, "set", "openai")
    assert post(web, {**fields, "accion": "clear"}).status_code == 400
    assert fake.sets == [] and fake.clears == []


def test_a_confirmation_expires() -> None:
    now = [NOW]
    tickets = SettingTickets(lambda: now[0])
    ticket = tickets.issue("set", "anthropic")
    now[0] = NOW.replace(minute=11)
    assert tickets.redeem(ticket, "set", "anthropic")[0].value == "invalid"
    fresh = tickets.issue("set", "anthropic", replacing=True)
    assert tickets.redeem(fresh, "set", "anthropic") == (Redeemed.OK, True)
    assert tickets.redeem(fresh, "set", "anthropic") == (Redeemed.SPENT, False)


# -- forged requests ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"origin": "http://evil.example"},
        {"origin": "null"},
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
        {"sec-fetch-site": "none"},
    ],
)
def test_a_post_from_anywhere_else_is_refused_before_the_app(
    web: TestClient, fake: FakeSettings, headers: dict[str, str]
) -> None:
    fields = confirm(web, "set", "openai")
    reply = post(web, {**fields, "valor": anthropic_key()}, **headers)
    assert reply.status_code == 403
    assert fake.sets == []


def test_a_post_without_the_origin_is_refused(web: TestClient, fake: FakeSettings) -> None:
    fields = confirm(web, "set", "openai")
    reply = web.post(SAVE, data={**fields, "valor": "x"}, headers={"sec-fetch-site": "same-origin"})
    assert reply.status_code == 403 and fake.sets == []


def test_the_csrf_token_is_needed(web: TestClient, fake: FakeSettings) -> None:
    fields = confirm(web, "set", "openai")
    assert post(web, {**fields, "csrf": "wrong", "valor": "x"}).status_code == 403
    assert fake.sets == []
    # the ticket was not spent by a POST that failed the form check
    assert post(web, {**fields, "valor": "sk-" + "a" * 30}).status_code == 200


def test_the_link_alone_cannot_change_anything(tmp_path: Path, fake: FakeSettings) -> None:
    web = new_client(tmp_path, settings=fake)
    fields = confirm(web, "set", "openai")
    stranger = new_client(tmp_path, settings=fake, logged_in=False)
    reply = stranger.post(f"{SAVE}?t={TOKEN}", data={**fields, "valor": "x"}, headers=POST_HEADERS)
    assert reply.status_code == 401 and fake.sets == []


@pytest.mark.parametrize(
    "body",
    [
        "csrf=a&ticket=b&tipo=openai&accion=set&valor=x&valor=y",
        "csrf=a&ticket=b&tipo=openai&accion=set&valor=x&other=1",
        "csrf=a&ticket=b&tipo=gemini&accion=set&valor=x",
        "csrf=a&ticket=b&tipo=openai&accion=drop",
        "csrf=a&ticket=b&tipo=openai&accion=set&valor=" + "x" * 400,
        "csrf=a&ticket=b&tipo=openai&accion=set&valor=%0A",
        "csrf=a&ticket=b&tipo=openai&accion=set&valor=%C3%B1",
    ],
)
def test_a_form_that_is_not_ours_is_refused(web: TestClient, fake: FakeSettings, body: str) -> None:
    reply = web.post(
        SAVE,
        content=body,
        headers={**POST_HEADERS, "content-type": "application/x-www-form-urlencoded"},
    )
    assert reply.status_code in (400, 403)  # a bad form, or (a printable "ñ") the wrong CSRF
    assert fake.sets == [] and fake.clears == []


def test_a_form_too_big_is_refused(web: TestClient, fake: FakeSettings) -> None:
    reply = web.post(
        SAVE,
        content="valor=" + "x" * 3000,
        headers={**POST_HEADERS, "content-type": "application/x-www-form-urlencoded"},
    )
    assert reply.status_code == 413 and fake.sets == []


# -- the whole way, and nothing leaks -------------------------------------------------------------


@pytest.fixture
def short_folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vw"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def test_end_to_end_no_key_nor_a_piece_of_it_shows_anywhere(
    tmp_path: Path, short_folder: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Through a real control socket to the real Settings on the real black box the web reads:
    every kind set, changed and removed, a bad one, a replayed one, a forged one. Then every
    response body and header, the live stream, every log record and every black-box event (and
    the database's own bytes) are searched for each key and each 8-character piece of it."""
    caplog.set_level(logging.DEBUG)
    box = BlackBox(tmp_path / "blackbox.db", KEY, checkpoint_path=tmp_path / "blackbox.checkpoint")
    box.append("file", "create", "work/notas.md")
    state = short_folder / "state"
    state.mkdir(mode=0o700)
    reloads: list[int] = []
    settings = Settings(
        state,
        record=box.append,
        reload_keys=lambda: reloads.append(1) or Applied.NOW,
        in_use=["anthropic", "openai"],
    )
    server = ControlServer(FakeGuardian(), short_folder / "control.sock", peer=me,
                           settings=settings)  # fmt: skip
    server.start()
    client = ControlSettings(server.path, enabled=True, peer=me)
    web = new_client(tmp_path, settings=client)
    seen: list[str] = []

    def keep(response: Any) -> Any:
        seen.append(response.text)
        seen.append(json.dumps(dict(response.headers)))
        return response

    keys = {"anthropic": anthropic_key(), "openai": "sk-proj-TEST" + secrets.token_urlsafe(40)}
    replaced = anthropic_key()
    token = bot_token()
    bad = anthropic_key() + "!"
    try:
        keep(web.get("/ajustes"))
        for kind, key in keys.items():
            fields = confirm(web, "set", kind)
            assert keep(post(web, {**fields, "valor": key})).status_code == 200
            keep(post(web, {**fields, "valor": key}))  # replayed: refused, nothing sent
        fields = confirm(web, "set", "anthropic")
        keep(post(web, {**fields, "valor": replaced, "confirmo": "si"}))
        fields = confirm(web, "set", "openai")
        invalid = keep(post(web, {**fields, "valor": bad, "confirmo": "si"}))
        assert 'data-outcome="invalid"' in invalid.text
        fields = confirm(web, "set", "telegram")
        keep(post(web, {**fields, "valor": token, "chat": "42424242"}))
        fields = confirm(web, "set", "openai")
        keep(post(web, {**fields, "valor": anthropic_key()}, origin="http://evil.example"))
        page = keep(web.get("/ajustes"))
        said = text_of(page.text)
        assert f"termina en …{replaced[-4:]}" in said
        assert f"termina en …{keys['openai'][-4:]}" in said
        assert f"termina en …{token[-4:]}" in said and "Tu chat termina en …4242" in said
        for kind in ("openai", "telegram"):
            keep(web.get(f"/ajustes/quitar?tipo={kind}"))
            keep(post(web, confirm(web, "clear", kind)))
        keep(web.get("/ajustes"))
        keep(web.get("/ahora"))
        keep(web.get("/historia"))
        keep(web.get("/historia?origen=settings"))
        live = new_client(tmp_path, settings=client, stream_seconds=0.5, poll_interval=0.05)
        body = keep(live.get("/ahora/stream?after=0")).text
        streamed = " ".join(e.get("data", "") for e in parse_sse(body))
        assert "Has puesto la clave de Anthropic" in text_of(streamed)
    finally:
        server.close()
    assert (state / "keys" / "anthropic.key").read_text() == replaced + "\n"
    assert not (state / "keys" / "openai.key").exists()
    assert not (state / "telegram.toml").exists()
    events = [e for e in box.events() if e.source == "settings"]
    assert [(e.action, e.details["kind"]) for e in events] == [
        ("secret_set", "anthropic"), ("secret_set", "openai"), ("secret_set", "anthropic"),
        ("secret_set", "telegram"), ("secret_cleared", "openai"), ("secret_cleared", "telegram"),
    ]  # fmt: skip
    for event in events:
        assert set(event.details) == {"kind", "requested_by"}
        assert str(event.details["requested_by"]).startswith("web (uid ")
    assert len(reloads) == 4  # anthropic twice, openai set and removed: Telegram waits a restart
    logs = [r.getMessage() + " " + (r.exc_text or "") for r in caplog.records]
    recorded = [json.dumps([e.source, e.action, e.target, e.details]) for e in box.events()]
    raw = b"".join(p.read_bytes() for p in tmp_path.glob("blackbox.*") if p.is_file()).decode(
        "latin-1"
    )
    for secret in (*keys.values(), replaced, token, bad):
        found = [
            where
            for where, texts in (
                ("responses", seen),
                ("logs", logs),
                ("events", recorded),
                ("database", [raw]),
            )  # fmt: skip
            if any(piece in text for text in texts for piece in pieces(secret))
        ]
        hits = sorted(
            {
                piece
                for texts in (seen, logs)
                for text in texts
                for piece in pieces(secret)
                if piece in text
            }
        )
        assert found == [], f"a piece of a test key in {found}: {hits}"
    assert SESSION not in " ".join(logs)
