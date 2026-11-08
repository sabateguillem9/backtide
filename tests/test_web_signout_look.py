"""T26-3a-2, the frontend's half: the core already has ``POST /salir`` and ``POST
/ajustes/cerrar-sesiones`` (test_web_security.py says what they refuse); here, the pages that offer
them. "Salir" is in the header of every page with a session and nowhere without one, "Cerrar todas"
is in Ajustes with its typed word, the sign-in page says when a session ends, and a page whose
stream says the session is over stops listening and goes back to the sign-in page. Every form is
plain HTML, so nothing is inline and the policy is the one it was."""

import re
from pathlib import Path

import pytest

from backtide.web.i18n import STRINGS
from backtide.web.security import CLOSE_SESSIONS_WORD, CSP
from tests.test_web_rewind import POST_HEADERS
from tests.test_web_security import signed_in_web
from tests.test_web_signin_look import PINNED_CSP, assert_nothing_inline
from tests.test_web_signin_look import web as signin_web
from tests.webkit import PREFIX_PATH, SESSION, new_box, new_client

PAGES = ["/panel", "/ahora", "/historia", "/instantaneas", "/peticiones", "/ajustes", "/llaves"]
STATIC = Path(__file__).resolve().parents[1] / "backtide" / "web" / "static"
TEMPLATES = STATIC.parent / "templates"


def forms(html: str, css_class: str) -> list[str]:
    return re.findall(rf'<form class="[^"]*\b{css_class}\b[^"]*".*?</form>', html, re.S)


def action_and_csrf(form: str) -> tuple[str, str]:
    action = re.search(r'action="([^"]+)"', form)
    csrf = re.search(r'<input type="hidden" name="csrf" value="([^"]+)">', form)
    assert action and csrf, form
    return action.group(1), csrf.group(1)


def test_the_policy_is_the_one_it_was() -> None:
    assert CSP == PINNED_CSP


@pytest.mark.parametrize("path", PAGES)
def test_every_page_with_a_session_offers_salir_in_its_header(tmp_path: Path, path: str) -> None:
    web, (_, session) = signed_in_web(tmp_path)
    page = web.get(path)
    assert page.status_code == 200
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)
    header = page.text.split("</header>")[0]
    (form,) = forms(header, "sign-out")  # once, in the header
    assert 'method="post"' in form
    assert action_and_csrf(form) == (f"{PREFIX_PATH}/salir", session.csrf)
    assert '<button class="sign-out-go" type="submit">' in form
    assert len(forms(page.text, "sign-out")) == 1


@pytest.mark.parametrize("path", ["/", "/panel", "/ajustes"])
def test_without_a_session_there_is_no_salir(tmp_path: Path, path: str) -> None:
    new_box(tmp_path)
    page = new_client(tmp_path, logged_in=False).get(path)
    assert page.status_code == 401
    assert "sign-out" not in page.text and "/salir" not in page.text
    assert "close-all" not in page.text and "cerrar-sesiones" not in page.text
    assert 'name="csrf"' not in page.text


def test_the_salir_form_as_rendered_ends_the_session(tmp_path: Path) -> None:
    web, (sessions, _) = signed_in_web(tmp_path)
    (form,) = forms(web.get("/panel").text, "sign-out")
    action, csrf = action_and_csrf(form)
    reply = web.post(
        action.removeprefix(PREFIX_PATH),
        data={"csrf": csrf},
        headers=POST_HEADERS,
        follow_redirects=False,
    )
    assert reply.status_code == 303 and reply.headers["location"] == f"{PREFIX_PATH}/"
    assert sessions.check(SESSION) is None
    web.cookies.set("backtide_web", SESSION, domain="127.0.0.1", path=PREFIX_PATH)
    assert web.get("/panel").status_code == 401


def test_ajustes_offers_closing_every_session_with_the_word(tmp_path: Path) -> None:
    web, (_, session) = signed_in_web(tmp_path)
    page = web.get("/ajustes").text
    (form,) = forms(page, "close-all")
    assert 'method="post"' in form
    assert action_and_csrf(form) == (f"{PREFIX_PATH}/ajustes/cerrar-sesiones", session.csrf)
    field = re.search(r"<input [^>]*name=\"confirmo\"[^>]*>", form)
    assert field is not None
    field_html = field.group(0)
    for attribute in ('type="text"', "required", 'autocomplete="off"', 'spellcheck="false"'):
        assert attribute in field_html
    assert f'pattern="{CLOSE_SESSIONS_WORD}"' in field_html  # a typo never leaves the browser
    assert f'title="Escribe exactamente {CLOSE_SESSIONS_WORD}, en minúsculas."' in field_html
    assert 'id="close-all-word"' in field_html and 'for="close-all-word"' in form
    assert f"<code>{CLOSE_SESSIONS_WORD}</code>" in form  # the word to type, set apart
    assert 'class="settings-yes is-remove"' in form  # it removes: the danger button
    # What it closes, and the way back in.
    section = page.split('id="settings-sessions"')[1].split("</section>")[0]
    assert "portátil" in section and "móvil" in section and "enlace" in section
    assert "<code>sudo backtide enlace</code>" in section


def test_closing_every_session_from_the_rendered_form_closes_them(tmp_path: Path) -> None:
    web, (sessions, _) = signed_in_web(tmp_path)
    phone = sessions.open(sessions.new_link())
    unspent = sessions.new_link()
    assert phone is not None
    (form,) = forms(web.get("/ajustes").text, "close-all")
    action, csrf = action_and_csrf(form)
    reply = web.post(
        action.removeprefix(PREFIX_PATH),
        data={"csrf": csrf, "confirmo": CLOSE_SESSIONS_WORD},
        headers=POST_HEADERS,
        follow_redirects=False,
    )
    assert reply.status_code == 303
    assert len(sessions) == 0 and sessions.open(unspent) is None


def test_ajustes_says_it_in_english_too(tmp_path: Path) -> None:
    web, _ = signed_in_web(tmp_path)
    page = web.get("/ajustes?lang=en").text
    section = page.split('id="settings-sessions"')[1].split("</section>")[0]
    assert (
        "laptop" in section
        and "phone" in section
        and "<code>sudo backtide enlace</code>" in section
    )
    header = page.split("</header>")[0]
    assert ">Sign out<" in header


@pytest.mark.parametrize("lang", ["es", "en"])
@pytest.mark.parametrize("installed", [False, True])
def test_the_sign_in_page_says_when_a_session_ends(
    tmp_path: Path, lang: str, installed: bool
) -> None:
    """The installed web (its password, its key) points at `sudo backtide enlace`; `backtide web`
    on its own, at starting it again: that is where each one's next link comes from."""
    page = (signin_web(tmp_path) if installed else new_client(tmp_path, logged_in=False)).get(
        f"/panel?lang={lang}"
    )
    assert page.status_code == 401
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)
    key = "auth.expiry" if installed else "auth.expiry.local"
    said = STRINGS[lang][key]
    assert "12" in said and ("hora" in said if lang == "es" else "hour" in said)
    command = "sudo backtide enlace" if installed else "backtide web"
    assert (
        f"<code>{command}</code>"
        in page.text.split('class="note auth-expiry">')[1].split("</p>")[0]
    )
    assert ("12 horas" if lang == "es" else "12 hours") in page.text


def test_every_live_page_stops_listening_when_its_session_ends() -> None:
    """The stream sends ``event: session`` and ends; htmx's SSE closes on it (sse-close) instead
    of reconnecting forever, and web.js reloads, so the server answers with the sign-in page."""
    live = [
        path.name
        for path in TEMPLATES.glob("*.html")
        if "sse-connect=" in path.read_text(encoding="utf-8")
    ]
    assert sorted(live) == ["manage.html", "now.html", "panel.html", "talk.html"]
    for name in live:
        html = (TEMPLATES / name).read_text(encoding="utf-8")
        assert html.count("sse-connect=") == html.count('sse-close="session"'), name
    script = (STATIC / "web.js").read_text(encoding="utf-8")
    assert 'addEventListener("htmx:sseClose"' in script
    assert 'detail.type === "message"' in script and "window.location.reload()" in script


def test_a_live_page_carries_the_close_word(tmp_path: Path) -> None:
    web, _ = signed_in_web(tmp_path)
    for path in ("/panel", "/ahora"):
        html = web.get(path).text
        tag = re.search(r"<main [^>]*sse-connect=[^>]*>", html)
        assert tag is not None and 'sse-close="session"' in tag.group(0), path


def test_the_new_words_exist_in_both_languages() -> None:
    keys = [
        k for k in STRINGS["es"] if k.startswith(("signout.", "sessions.")) or k == "auth.expiry"
    ]
    assert len(keys) >= 6
    for key in keys:
        assert key in STRINGS["en"], key
