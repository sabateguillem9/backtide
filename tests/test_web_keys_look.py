"""T26-3b-2: how the installed web's keys page looks (the frontend's polish). That a key is made
only from a live session, with its CSRF and our origin, is in test_web_narrow_socket.py and
test_passkeys.py; here: the page obeys the CSP and has nothing inline, the keys are Ajustes' rows
(the person's name escaped, never markup), "Más tarde" is the form's quiet way out, and both
languages say it."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backtide.service.sessions import Session
from backtide.web.i18n import STRINGS
from backtide.web.security import CSP
from tests.test_web_signin_look import PINNED_CSP, assert_nothing_inline
from tests.webkit import new_box, new_client

KEYS = [
    {"name": "portátil", "tail": "DNMg", "added": "2026-10-31T09:12:00+00:00", "id": "aaaaDNMg"},
    {"name": "llave-USB-del-cajón", "tail": "T-XQ", "added": "2026-10-30T18:00:00+00:00",
     "id": "bbbbT-XQ"},
]  # fmt: skip
HOSTILE = {"name": '<img src=x onerror="alert(1)">', "tail": "AbCd", "added": "2026-10-29",
           "id": "ccccAbCd"}  # fmt: skip


class InstalledWeb:
    """The service as the installed web asks it: one live session, and ``keys`` kept."""

    passwords = True

    def __init__(self, keys: list[dict[str, str]]) -> None:
        self.keys = keys

    def open(self, token: str) -> Session | None:
        return None

    def sign_in(self, password: str) -> tuple[Session | None, str]:
        return None, "wrong"

    def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
        return Session("s" * 43, "c" * 43)

    def end(self, session_id: str, *, every: bool = False) -> bool | None:
        return None

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        if command == "touch_status":
            return {"ok": True, "needs": False, "add": "ok"}
        assert command == "passkey_list"
        return {"ok": True, "keys": self.keys}


def web(tmp_path: Path, keys: list[dict[str, str]]) -> TestClient:
    new_box(tmp_path)
    client = new_client(tmp_path, access=InstalledWeb(keys))
    # Opened as the owner would, at backtide.localhost: there the page offers its form.
    client.headers["host"] = "backtide.localhost:8765"
    return client


def test_the_policy_is_the_one_it_was() -> None:
    assert CSP == PINNED_CSP


@pytest.mark.parametrize("path", ["/llaves", "/llaves?nueva=1", "/llaves?lang=en"])
@pytest.mark.parametrize("keys", [[], KEYS], ids=["none", "two"])
def test_every_view_obeys_the_policy_and_has_nothing_inline(
    tmp_path: Path, path: str, keys: list[dict[str, str]]
) -> None:
    page = web(tmp_path, keys).get(path)
    assert page.status_code == 200
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)


def test_the_keys_are_ajustes_rows_and_a_name_is_only_text(tmp_path: Path) -> None:
    html = web(tmp_path, [*KEYS, HOSTILE]).get("/llaves").text
    assert '<ul class="settings-list keys-list">' in html
    assert html.count('<li class="setting">') == 3
    assert '<span class="setting-name">portátil</span>' in html
    assert "termina en …DNMg" in html
    assert '<time datetime="2026-10-31T09:12:00+00:00">2026-10-31</time>' in html
    assert "<img" not in html and "&lt;img src=x" in html  # the person's name, escaped


def test_no_list_without_keys(tmp_path: Path) -> None:
    html = web(tmp_path, []).get("/llaves").text
    assert "keys-list" not in html and 'id="passkey-form"' in html


def test_later_is_the_forms_quiet_way_out_only_the_first_time(tmp_path: Path) -> None:
    client = web(tmp_path, [])
    first = client.get("/llaves?nueva=1").text
    actions = first.split('<div class="settings-actions">')[1].split("</div>")[0]
    assert 'class="settings-yes"' in actions and 'class="settings-cancel"' in actions
    assert "Más tarde" in actions
    assert "settings-cancel" not in client.get("/llaves").text


def test_english_says_it_in_english(tmp_path: Path) -> None:
    html = web(tmp_path, [KEYS[0]]).get("/llaves?lang=en&nueva=1").text
    assert 'lang="en"' in html and "ends in …DNMg" in html
    assert "Register this key" in html and "Later" in html


def test_at_the_numeric_address_the_page_lists_and_says_where_to_go(tmp_path: Path) -> None:
    new_box(tmp_path)
    html = new_client(tmp_path, access=InstalledWeb(KEYS)).get("/llaves").text
    assert 'id="passkey-form"' not in html and "http://backtide.localhost:8765" in html
    assert "keys-list" in html  # the keys are still listed


# -- T26-3d: managing the keys ------------------------------------------------------------------


class ManagedWeb(InstalledWeb):
    """A live session that has touched a key, and whose service says ``replies[command]``."""

    def __init__(self, keys: list[dict[str, str]], **replies: dict[str, Any]) -> None:
        super().__init__(keys)
        self.replies = replies
        self.asked: list[tuple[str, dict[str, str]]] = []

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        if command in ("key_remove", "key_rename"):
            self.asked.append((command, fields))
            return self.replies.get(command, {"ok": True, "outcome": "done", "name": "x"})
        return super().passkey(command, session_id, **fields)


def managed(tmp_path: Path, keys: list[dict[str, str]], **replies: dict[str, Any]) -> Any:
    new_box(tmp_path)
    access = ManagedWeb(keys, **replies)
    client = new_client(tmp_path, access=access)
    client.headers["host"] = "backtide.localhost:8765"
    client.access = access
    return client


def post_headers() -> dict[str, str]:
    return {"origin": "http://backtide.localhost:8765", "sec-fetch-site": "same-origin"}


def test_each_key_has_its_two_actions_in_ajustes_own_style(tmp_path: Path) -> None:
    html = web(tmp_path, KEYS).get("/llaves").text
    assert html.count('class="setting-actions"') == 2
    assert html.count('class="setting-go"') == 2 and html.count('class="setting-remove"') == 2
    assert f"/llaves/nombre?llave={KEYS[0]['id']}" in html
    assert f"/llaves/quitar?llave={KEYS[1]['id']}" in html
    # Each link says which key, for whoever does not see the row around it.
    assert '<span class="visually-hidden"> portátil</span>' in html


def test_an_id_goes_into_a_link_escaped(tmp_path: Path) -> None:
    hostile = {**HOSTILE, "id": 'a"b&c<d'}
    html = web(tmp_path, [KEYS[0], hostile]).get("/llaves").text
    assert 'a"b' not in html and "a%22b%26c%3Cd" in html


def test_the_only_key_has_no_way_out_here_and_says_why(tmp_path: Path) -> None:
    html = web(tmp_path, [KEYS[0]]).get("/llaves").text
    assert 'class="setting-remove"' not in html and 'class="setting-go"' in html
    assert "<code>sudo backtide llaves --quitar</code>" in html
    assert STRINGS["es"]["keys.second"] in html


def test_with_two_keys_it_does_not_ask_for_another(tmp_path: Path) -> None:
    html = web(tmp_path, KEYS).get("/llaves").text
    assert STRINGS["es"]["keys.second"] not in html
    assert "sudo backtide llaves --quitar" not in html


@pytest.mark.parametrize("lang", ["es", "en"])
@pytest.mark.parametrize(
    "path",
    [f"/llaves/quitar?llave={KEYS[0]['id']}", f"/llaves/nombre?llave={KEYS[0]['id']}",
     "/llaves/quitar?llave=nada", "/llaves/nombre?llave=nada", "/llaves/quitar"],
    ids=["remove", "rename", "remove-none", "rename-none", "no-key"],
)  # fmt: skip
def test_every_step_obeys_the_policy_and_has_nothing_inline(
    tmp_path: Path, path: str, lang: str
) -> None:
    page = web(tmp_path, KEYS).get(f"{path}&lang={lang}" if "?" in path else f"{path}?lang={lang}")
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)
    assert 'lang="' + lang + '"' in page.text


def test_removing_is_said_plainly_with_one_red_button_and_a_quiet_way_back(tmp_path: Path) -> None:
    html = web(tmp_path, KEYS).get(f"/llaves/quitar?llave={KEYS[0]['id']}").text
    assert "portátil" in html and "…DNMg" in html
    assert STRINGS["es"]["keys.remove.note"] in html
    actions = html.split('<div class="settings-actions">')[1].split("</div>")[0]
    assert actions.count('class="settings-yes is-remove"') == 1
    assert 'class="settings-cancel"' in actions and "/llaves" in actions


def test_naming_is_a_field_with_the_name_there_was(tmp_path: Path) -> None:
    html = web(tmp_path, [HOSTILE, KEYS[0]]).get(f"/llaves/nombre?llave={HOSTILE['id']}").text
    assert "<img" not in html and "&lt;img src=x" in html
    assert 'maxlength="48"' in html and 'name="nombre"' in html and "required" in html


def test_a_removed_key_says_so_and_offers_the_way_back_in(tmp_path: Path) -> None:
    said = {"ok": True, "outcome": "removed", "name": "portátil", "tail": "DNMg", "ended": 2}
    client = managed(tmp_path, KEYS, key_remove=said)
    ticket = _ticket(client.get(f"/llaves/quitar?llave={KEYS[0]['id']}").text)
    page = client.post(
        "/llaves/quitar",
        data={"csrf": "c" * 43, "ticket": ticket, "llave": KEYS[0]["id"]},
        headers=post_headers(),
    )
    assert page.status_code == 200
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)
    assert "portátil" in page.text and "…DNMg" in page.text
    assert client.access.asked == [("key_remove", {"key": KEYS[0]["id"]})]
    assert 'class="settings-yes"' in page.text
    assert "Max-Age=0" in page.headers["set-cookie"] or "expires" in page.headers["set-cookie"]
    assert "sign-out" not in page.text and "/salir" not in page.text  # no session left to end


@pytest.mark.parametrize(
    ("outcome", "status", "said"),
    [("last", 400, "keys.err.last"), ("missing", 404, "keys.err.missing"),
     ("refused", 400, "keys.err.refused")],
)  # fmt: skip
def test_a_refusal_says_why_in_the_pages_language(
    tmp_path: Path, outcome: str, status: int, said: str
) -> None:
    client = managed(tmp_path, KEYS, key_remove={"ok": False, "outcome": outcome, "message": "x"})
    ticket = _ticket(client.get(f"/llaves/quitar?llave={KEYS[0]['id']}&lang=en").text)
    page = client.post(
        "/llaves/quitar",
        data={"csrf": "c" * 43, "ticket": ticket, "llave": KEYS[0]["id"]},
        headers=post_headers(),
    )
    assert page.status_code == status and "set-cookie" not in page.headers  # still signed in
    assert_nothing_inline(page.text)
    assert STRINGS["en"][said].split("`")[0] in page.text


def test_outside_the_installed_web_there_is_nothing_to_manage(tmp_path: Path) -> None:
    new_box(tmp_path)
    client = new_client(tmp_path)
    assert client.get("/llaves/quitar?llave=abc").status_code == 404
    assert client.get("/llaves/nombre?llave=abc").status_code == 404


@pytest.mark.parametrize(
    "key",
    ["keys.second", "keys.both", "keys.go_on", "keys.last", "keys.rename", "keys.remove",
     "keys.remove.title", "keys.remove.note", "keys.remove.yes", "keys.removed.title",
     "keys.removed.body", "keys.removed.enter", "keys.name.title", "keys.name.save",
     "keys.name.hint", "keys.back", "keys.err.last", "keys.err.missing", "keys.err.refused",
     "keys.err.name", "keys.err.ticket", "keys.err.form"],
)  # fmt: skip
def test_both_languages_say_the_new_words(key: str) -> None:
    spanish, english = STRINGS["es"].get(key), STRINGS["en"].get(key)
    assert spanish and english and spanish != english


def _ticket(html: str) -> str:
    import re

    found = re.search(r'name="ticket" value="([^"]+)"', html)
    assert found is not None
    return found.group(1)
