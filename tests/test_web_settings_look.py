"""T12e: how the Settings page looks and reads (the frontend's polish), and the Mac demo's stand-in
for the service. What may never happen (a key in a reply, a forged change) is in
test_web_settings.py; here: every step obeys the CSP and has nothing inline, the key fields ask
the browser not to fill them in, removing looks like removing, the words fit each kind, and the
demo keeps nothing but what the page may show."""

import importlib.util
import json
import re
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient

from backtide.web.i18n import Translator
from backtide.web.rewind import Availability
from backtide.web.security import CSP
from tests.test_web_settings import NOW, POST_HEADERS, SAVE, FakeSettings, confirm, text_of
from tests.webkit import new_box, new_client

ROOT = Path(__file__).resolve().parent.parent
# The policy as T12e found it: the polish adds no exception to it.
PINNED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


@pytest.fixture
def fake() -> FakeSettings:
    fake = FakeSettings()
    fake.shown["telegram"] = {
        "set": True, "tail": "Rk7w", "chat_tail": "5531", "changed": "2026-10-14T08:00:00Z",
        "in_use": True, "problem": None,
    }  # fmt: skip
    return fake


@pytest.fixture
def web(tmp_path: Path, fake: FakeSettings) -> TestClient:
    new_box(tmp_path).append("file", "create", "work/notas.md")
    return new_client(tmp_path, settings=fake, clock=lambda: NOW)


def every_step(web: TestClient) -> dict[str, object]:
    """One response of each view of the page."""
    used = confirm(web, "set", "openai")
    web.post(SAVE, data={**used, "valor": "sk-proj-TEST" + secrets.token_urlsafe(30)},
             headers=POST_HEADERS)  # fmt: skip
    return {
        "list": web.get("/ajustes"),
        "set-provider": web.get("/ajustes/cambiar?tipo=openai"),
        "replace-telegram": web.get("/ajustes/cambiar?tipo=telegram"),
        "clear": web.get("/ajustes/quitar?tipo=anthropic"),
        "result": web.post(SAVE, data={**confirm(web, "clear", "anthropic")}, headers=POST_HEADERS),
        "refused": web.post(SAVE, data={**used, "valor": "x"}, headers=POST_HEADERS),
        "unknown-kind": web.get("/ajustes/cambiar?tipo=nada"),
    }


def test_the_policy_is_the_one_it_was() -> None:
    assert CSP == PINNED_CSP


def test_every_step_obeys_the_policy_and_has_nothing_inline(web: TestClient) -> None:
    for name, response in every_step(web).items():
        html = response.text
        assert response.headers["content-security-policy"] == PINNED_CSP, name
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), f"{name}: inline script"
        assert not re.search(r"<style", html), f"{name}: style element"
        assert not re.search(r"\sstyle\s*=", html), f"{name}: style attribute"
        assert not re.search(r"\son[a-z]+\s*=", html, re.I), f"{name}: event handler"
        assert "javascript:" not in html.lower() and "hx-on" not in html, name
        assert not re.search(r"(?:src|href|action)=[\"']?(?:https?:)?//", html), name


def test_the_disabled_page_obeys_it_too(tmp_path: Path) -> None:
    page = new_client(tmp_path, settings=FakeSettings(Availability.DISABLED)).get("/ajustes")
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert not re.search(r"\sstyle\s*=|<style|<script(?![^>]*\bsrc=)", page.text)


def test_the_key_field_is_never_filled_in_nor_remembered(web: TestClient) -> None:
    for kind in ("anthropic", "openai", "telegram"):
        page = web.get(f"/ajustes/cambiar?tipo={kind}").text
        field = re.search(r'<input id="setting-value"[^>]*>', page)
        assert field, kind
        tag = field.group(0)
        assert 'type="password" name="valor"' in tag
        assert 'autocomplete="new-password"' in tag, "no saved password offered or filled in"
        assert 'spellcheck="false"' in tag and 'autocapitalize="off"' in tag
        assert "value=" not in tag, "nothing typed ever comes back"
        assert re.search(r'<form class="settings-form"[^>]* autocomplete="off"', page)
    chat = re.search(
        r'<input id="setting-chat"[^>]*>', web.get("/ajustes/cambiar?tipo=telegram").text
    )
    assert chat and 'autocomplete="off"' in chat.group(0) and "value=" not in chat.group(0)


def test_removing_looks_like_removing(web: TestClient) -> None:
    page = web.get("/ajustes").text
    assert re.search(
        r'<a class="setting-remove" href="[^"]+/ajustes/quitar\?tipo=anthropic">', page
    )
    step = web.get("/ajustes/quitar?tipo=anthropic").text
    assert '<button class="settings-yes is-remove" type="submit">' in step
    said = text_of(step)
    assert (
        "Sí, quitarla" in said
        and "el agente no puede usar ese modelo hasta que pongas otra" in said
    )
    assert '<p class="settings-warning">' in step, "the consequence is not a muted note"
    telegram = text_of(web.get("/ajustes/quitar?tipo=telegram").text)
    assert "Sí, quitarlo" in telegram, "el bot: masculine"


def test_every_link_and_button_says_what_it_acts_on(web: TestClient) -> None:
    said = text_of(web.get("/ajustes").text)
    assert "Cambiar la clave de Anthropic" in said and "Quitar la clave de Anthropic" in said
    assert "Poner la clave de OpenAI" in said and "Quitar el bot de Telegram" in said


def test_the_words_fit_each_kind_and_each_day(tmp_path: Path, fake: FakeSettings) -> None:
    new_box(tmp_path).append("file", "create", "a")
    now = datetime(2026, 10, 20, 15, 0, tzinfo=UTC)
    fake.shown["anthropic"]["changed"] = (now - timedelta(hours=2)).isoformat()
    fake.shown["openai"] = {"set": True, "tail": "9c1e", "in_use": True, "problem": None,
                            "changed": (now - timedelta(days=1)).isoformat()}  # fmt: skip
    web = new_client(tmp_path, settings=fake, clock=lambda: now)
    said = text_of(web.get("/ajustes").text)
    assert "termina en …WXyz, cambiada hoy a las 13:00" in said
    assert "termina en …9c1e, cambiada ayer a las 15:00" in said
    assert "Bot de Telegram configurado, termina en …Rk7w, cambiado el 14 oct, 08:00" in said
    assert "Hoy," not in said and "el Hoy" not in said
    step = text_of(web.get("/ajustes/cambiar?tipo=telegram").text)
    assert (
        "El token que hay ahora termina en …Rk7w." in step and "Tu chat termina en …5531." in step
    )
    assert "Sí, sustituye lo que hay ahora (el token termina en …Rk7w)" in step
    english = text_of(web.get("/ajustes?lang=en").text)
    assert "Telegram bot set, ends in …Rk7w, changed on 14 Oct, 08:00" in english
    assert "changed today at 13:00" in english and "changed yesterday at 15:00" in english


def test_commands_are_set_apart_and_escaped(tmp_path: Path) -> None:
    page = new_client(tmp_path, settings=FakeSettings(Availability.DISABLED)).get("/ajustes").text
    assert "<code>backtide web --ajustes</code>" in page
    assert "`" not in text_of(page), "no stray backticks on the page"
    t = Translator("es")
    assert str(t.code("settings.off.disabled")).count("<code>") == 1
    # a key the page does not know is shown as it is, escaped, never as markup
    assert str(t.code("x.<b>`<i>`")) == "x.&lt;b&gt;<code>&lt;i&gt;</code>"


def test_the_spending_cap_row_says_it_does_not_know_without_the_service(web: TestClient) -> None:
    page = web.get("/ajustes").text
    assert '<span class="setting-name">Tope de gasto</span>' in page
    assert 'id="setting-cap-note"' in page and "no se sabe" in page
    assert '<span class="setting-go is-off" aria-disabled="true">Cambiar</span>' in page


# -- the Mac demo's stand-in for the service ------------------------------------------------------


def demo_serve() -> ModuleType:
    path = ROOT / "scripts/web-demo/serve.py"
    spec = importlib.util.spec_from_file_location("web_demo_serve", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("web_demo_serve", module)
    spec.loader.exec_module(module)
    return module


def seeded(folder: Path) -> Path:
    path = ROOT / "scripts/web-demo/seed.py"
    spec = importlib.util.spec_from_file_location("web_demo_seed", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.seed_settings(folder)
    return folder / "settings.json"


def test_the_demo_starts_as_the_brief_says(tmp_path: Path) -> None:
    shown = json.loads(seeded(tmp_path).read_text())
    assert shown["anthropic"]["set"] and shown["anthropic"]["tail"] == "4f2a"
    assert not shown["openai"]["set"]
    assert shown["telegram"]["set"] and shown["telegram"]["chat_tail"]


def test_the_demo_writes_nothing_and_keeps_only_the_tail(tmp_path: Path) -> None:
    demo = demo_serve().DemoSettings(seeded(tmp_path))
    before = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    key = "sk-proj-TEST" + secrets.token_urlsafe(40)
    reply = demo.set_secret("openai", key, None)
    assert reply["ok"] and reply["outcome"] == "saved" and reply["applied"] == "unused"
    assert key[:12] not in reply["message"]
    shown = json.dumps(demo.status())
    assert not any(key[i : i + 8] in shown for i in range(len(key) - 7)), "only the last four"
    assert demo.status()["openai"]["tail"] == key[-4:]
    assert not demo.set_secret("anthropic", "not-a-key", None)["ok"]
    assert demo.status()["anthropic"]["tail"] == "4f2a", "a refused value changes nothing"
    assert demo.clear_secret("anthropic")["outcome"] == "cleared"
    assert demo.clear_secret("anthropic")["outcome"] == "not_set"
    token = f"{10**9 + 7}:AA" + secrets.token_urlsafe(30)[:33]
    assert demo.set_secret("telegram", "", "4242424242")["applied"] == "restart", "chat only"
    assert demo.status()["telegram"]["chat_tail"] == "4242"
    assert demo.set_secret("telegram", token, "")["ok"]
    assert {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")} == before, "no file written"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json"]


def test_the_demo_page_goes_all_the_way_through_the_real_checks(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "a")
    demo = demo_serve().DemoSettings(seeded(tmp_path))
    web = new_client(tmp_path, settings=demo)
    fields = confirm(web, "set", "openai")
    reply = web.post(
        SAVE, data={**fields, "valor": "sk-" + "a" * 30 + "Zz9q"}, headers=POST_HEADERS
    )
    assert reply.status_code == 200 and 'data-outcome="saved"' in reply.text
    assert "Esto es la demo" in text_of(reply.text)
    assert "termina en …Zz9q" in text_of(web.get("/ajustes").text)
    forged = web.post(SAVE, data={**fields, "valor": "sk-" + "b" * 30}, headers=POST_HEADERS)
    assert forged.status_code == 400, "the ticket is spent, as in the real one"
