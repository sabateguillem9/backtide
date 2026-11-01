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
from backtide.web.security import CSP
from tests.test_web_signin_look import PINNED_CSP, assert_nothing_inline
from tests.webkit import new_box, new_client

KEYS = [
    {"name": "portátil", "tail": "DNMg", "added": "2026-10-31T09:12:00+00:00"},
    {"name": "llave-USB-del-cajón", "tail": "T-XQ", "added": "2026-10-30T18:00:00+00:00"},
]
HOSTILE = {"name": '<img src=x onerror="alert(1)">', "tail": "AbCd", "added": "2026-10-29"}


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
    html = web(tmp_path, KEYS).get("/llaves?lang=en&nueva=1").text
    assert 'lang="en"' in html and "ends in …DNMg" in html
    assert "Register this key" in html and "Later" in html


def test_at_the_numeric_address_the_page_lists_and_says_where_to_go(tmp_path: Path) -> None:
    new_box(tmp_path)
    html = new_client(tmp_path, access=InstalledWeb(KEYS)).get("/llaves").text
    assert 'id="passkey-form"' not in html and "http://backtide.localhost:8765" in html
    assert "keys-list" in html  # the keys are still listed
