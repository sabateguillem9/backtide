"""T26-3c: how signing in with a key and touching it again look (the frontend's polish). That the
service checks the signature, and that a session must touch before it adds a key, is in
test_web_narrow_socket.py and test_passkeys.py; here: every view obeys the CSP and has nothing
inline, the view has one primary button (the password's, on the sign-in page), an error reads as the
Field's error, both languages say it, and at the numeric address no key is offered."""

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backtide.web.i18n import STRINGS
from backtide.web.security import CSP
from tests.test_web_keys_look import KEYS, InstalledWeb
from tests.test_web_signin_look import PINNED_CSP, SaysNo, assert_nothing_inline
from tests.webkit import new_box, new_client

HERE = "backtide.localhost:8765"
NUMERIC = "127.0.0.1:8765"
STATIC = Path(__file__).parent.parent / "backtide" / "web" / "static"
SAID = (
    '<div class="webauthn-said">'
    '<svg class="ic ic-warning" viewBox="0 0 48 48" aria-hidden="true" focusable="false">'
)


class AddsThisWay(InstalledWeb):
    """A live session whose next key waits on ``add``: ok, touch or again."""

    def __init__(self, add: str) -> None:
        super().__init__(KEYS)
        self.add = add

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        if command == "touch_status":
            return {"ok": True, "needs": False, "add": self.add}
        return super().passkey(command, session_id, **fields)


def signed_out(tmp_path: Path, host: str = HERE) -> TestClient:
    new_box(tmp_path)
    client = new_client(tmp_path, logged_in=False, access=SaysNo("wrong"))
    client.headers["host"] = host
    return client


def signed_in(tmp_path: Path, host: str = HERE, add: str = "ok") -> TestClient:
    new_box(tmp_path)
    client = new_client(tmp_path, access=AddsThisWay(add))
    client.headers["host"] = host
    return client


def main_of(html: str) -> str:
    return html.split("<main", 1)[1].split("</main>", 1)[0]


def test_the_policy_is_the_one_it_was() -> None:
    assert CSP == PINNED_CSP


@pytest.mark.parametrize("host", [HERE, NUMERIC])
@pytest.mark.parametrize("lang", ["es", "en"])
def test_the_sign_in_page_obeys_the_policy_and_has_nothing_inline(
    tmp_path: Path, host: str, lang: str
) -> None:
    page = signed_out(tmp_path, host).get(f"/ahora?lang={lang}")
    assert page.status_code == 401
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)


@pytest.mark.parametrize("host", [HERE, NUMERIC])
@pytest.mark.parametrize("back", ["ajustes", "peticiones", "llaves", "otra-cosa"])
@pytest.mark.parametrize("lang", ["es", "en"])
def test_the_touch_page_obeys_the_policy_and_has_nothing_inline(
    tmp_path: Path, host: str, back: str, lang: str
) -> None:
    page = signed_in(tmp_path, host).get(f"/tocar?volver={back}&lang={lang}")
    assert page.status_code == 200
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)


@pytest.mark.parametrize("add", ["ok", "touch", "again"])
@pytest.mark.parametrize("lang", ["es", "en"])
def test_each_state_of_the_keys_page_obeys_the_policy_and_has_nothing_inline(
    tmp_path: Path, add: str, lang: str
) -> None:
    page = signed_in(tmp_path, add=add).get(f"/llaves?lang={lang}")
    assert page.status_code == 200
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)


def test_the_password_is_the_primary_and_the_key_its_secondary(tmp_path: Path) -> None:
    html = main_of(signed_out(tmp_path).get("/ahora").text)
    assert html.count('class="settings-yes"') == 1
    assert '<button class="settings-yes" type="submit">' in html
    assert '<div class="settings-actions signin-key">' in html
    assert '<button class="setting-go" type="button" id="webauthn-go"' in html
    assert html.index('id="signin-password"') < html.index('id="webauthn-go"')  # under the form


def test_a_key_error_is_the_fields_error_from_the_first_paint(tmp_path: Path) -> None:
    """The script only writes the words (textContent): the drawing waits next to them, in the
    markup, and web.css shows both in crimson once the status has .is-error."""
    client = signed_out(tmp_path)
    for html in (client.get("/ahora").text, signed_in(tmp_path).get("/tocar").text):
        said = main_of(html)
        assert SAID in said
        assert (
            '<p class="setting-hint" id="webauthn-status" role="status" aria-live="polite"></p>'
            in said
        )
    css = (STATIC / "web.css").read_text(encoding="utf-8")
    error = re.search(r":is\(#passkey-status, #webauthn-status\)\.is-error \{([^}]*)\}", css)
    assert error and "color: var(--danger)" in error.group(1)
    assert ".webauthn-said > .ic { display: none; }" in css
    assert ".webauthn-said:has(.is-error) > .ic { display: block; }" in css


def test_the_script_puts_text_in_as_text_and_never_shows_a_parsers_sentence() -> None:
    script = (STATIC / "webauthn-get.js").read_text(encoding="utf-8")
    assert "status.textContent = text" in script
    assert "innerHTML" not in script and "insertAdjacentHTML" not in script
    assert 'response.json().catch(function () { return { ok: false, message: "" }; })' in script


def test_touching_has_one_primary_and_a_quiet_way_back(tmp_path: Path) -> None:
    html = main_of(signed_in(tmp_path).get("/tocar?volver=llaves").text)
    actions = html.split('<div class="settings-actions">')[1].split("</div>")[0]
    assert actions.count('class="settings-yes"') == 1 and 'id="webauthn-go"' in actions
    assert 'class="settings-cancel"' in actions and "Volver" in actions
    assert "<code>sudo backtide llaves</code>" in html and "`" not in html


def test_the_keys_page_asks_for_a_touch_with_a_link_that_is_the_same_button(tmp_path: Path) -> None:
    html = main_of(signed_in(tmp_path, add="touch").get("/llaves").text)
    assert 'id="passkey-form"' not in html
    assert STRINGS["es"]["keys.touch"] in html
    actions = html.split('<div class="settings-actions">')[1].split("</div>")[0]
    assert '<a class="settings-yes" href="' in actions and "/tocar?volver=llaves" in actions
    assert "Tocar la llave" in actions


def test_the_keys_page_says_when_the_first_key_must_wait(tmp_path: Path) -> None:
    html = main_of(signed_in(tmp_path, add="again").get("/llaves").text)
    assert 'id="passkey-form"' not in html and "settings-actions" not in html
    assert "regístrala" in html


@pytest.mark.parametrize(
    "key",
    [
        "auth.key",
        "auth.key.elsewhere",
        "touch.title",
        "touch.body",
        "touch.go",
        "touch.cancel",
        "touch.lost",
        "keys.touch",
        "keys.again",
        "webauthn.cancelled",
        "webauthn.failed",
        "webauthn.unsupported",
    ],
)
def test_both_languages_say_it(key: str) -> None:
    spanish, english = STRINGS["es"].get(key), STRINGS["en"].get(key)
    assert spanish and english and spanish != english


def test_each_page_says_it_in_its_language(tmp_path: Path) -> None:
    client = signed_out(tmp_path)
    spanish, english = client.get("/ahora?lang=es").text, client.get("/ahora?lang=en").text
    assert 'lang="es"' in spanish and "Entrar con tu llave" in spanish
    assert 'lang="en"' in english and "Sign in with your key" in english
    assert "It did not work." in english and "No ha funcionado." in spanish

    client = signed_in(tmp_path)
    spanish, english = client.get("/tocar?lang=es").text, client.get("/tocar?lang=en").text
    assert "Toca tu llave" in spanish and "Tocar la llave" in spanish
    assert "Touch your key" in english and "Touch the key" in english

    client = signed_in(tmp_path, add="touch")
    assert STRINGS["en"]["keys.touch"] in client.get("/llaves?lang=en").text
    client = signed_in(tmp_path, add="again")
    assert "right after signing in" in client.get("/llaves?lang=en").text


def test_at_the_numeric_address_no_key_is_offered_and_it_says_where(tmp_path: Path) -> None:
    html = signed_out(tmp_path, NUMERIC).get("/ahora").text
    assert 'id="webauthn-go"' not in html and "webauthn-get.js" not in html
    assert "signin-key" not in html and "webauthn-status" not in html
    assert "Entrar con tu llave" not in html
    assert "<code>http://backtide.localhost:8765</code>" in html
    assert '<button class="settings-yes" type="submit">' in html  # the password still works


def test_at_the_numeric_address_the_touch_page_says_where_too(tmp_path: Path) -> None:
    html = signed_in(tmp_path, NUMERIC).get("/tocar").text
    assert 'id="webauthn-go"' not in html and "webauthn-get.js" not in html
    assert "<code>http://backtide.localhost:8765</code>" in html
