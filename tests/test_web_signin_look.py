"""T26-3b-1: how the installed web's way in looks and reads (the frontend's polish). What may never
happen (a password in a reply or a log, a session for a wrong one, a form from another site) is in
test_web_narrow_socket.py; here: every view of the page obeys the CSP and has nothing inline, the
error is the system's Field error (crimson, with its drawing, tied to the field), the commands are
code to copy, and both languages say every error."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backtide.service.sessions import Session
from backtide.web.app import SIGN_IN_ERRORS
from backtide.web.i18n import STRINGS
from backtide.web.security import CSP
from tests.test_web_rewind import POST_HEADERS
from tests.webkit import new_box, new_client

PINNED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


class SaysNo:
    """The service's sessions as the installed web asks them, always refusing with ``why``."""

    passwords = True

    def __init__(self, why: str) -> None:
        self.why = why

    def open(self, token: str) -> Session | None:
        return None

    def sign_in(self, password: str) -> tuple[Session | None, str]:
        return None, self.why

    def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
        return None

    def end(self, session_id: str, *, every: bool = False) -> bool | None:
        return None


def web(tmp_path: Path, why: str = "wrong") -> TestClient:
    new_box(tmp_path)
    return new_client(tmp_path, logged_in=False, access=SaysNo(why))


def refused(tmp_path: Path, why: str, lang: str = "es") -> str:
    client = web(tmp_path, why)
    data = {"password": "x" * 300} if why == "form" else {"password": "a made-up one, long"}
    return client.post(f"/entrar?lang={lang}", data=data, headers=POST_HEADERS).text


def assert_nothing_inline(html: str) -> None:
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline script"
    assert not re.search(r"<style", html), "style element"
    assert not re.search(r"\sstyle\s*=", html), "style attribute"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "event handler"
    assert "javascript:" not in html.lower() and "hx-on" not in html
    assert not re.search(r"(?:src|href|action)=[\"']?(?:https?:)?//", html), "foreign address"


def test_the_policy_is_the_one_it_was() -> None:
    assert CSP == PINNED_CSP


def test_the_form_obeys_the_policy_and_has_nothing_inline(tmp_path: Path) -> None:
    page = web(tmp_path).get("/ahora")
    assert page.status_code == 401
    assert page.headers["content-security-policy"] == PINNED_CSP
    assert_nothing_inline(page.text)
    # One field, with its label, in the settings' field; no error until there is one.
    assert '<div class="setting-field">' in page.text
    assert '<label class="setting-label" for="signin-password">' in page.text
    assert "aria-invalid" not in page.text and "signin-error" not in page.text


@pytest.mark.parametrize("why", sorted(SIGN_IN_ERRORS))
def test_each_error_is_the_fields_error_tied_to_the_field(tmp_path: Path, why: str) -> None:
    html = refused(tmp_path, why)
    assert_nothing_inline(html)
    assert 'aria-invalid="true" aria-describedby="signin-error"' in html
    error = re.search(
        r'<p class="signin-error" id="signin-error" role="alert">(.*?)</p>', html, re.S
    )
    assert error, why
    assert 'class="ic ic-warning"' in error.group(1)  # never colour alone: a drawing too
    assert "`" not in error.group(1)  # a command is code to copy, not backticks


def test_the_commands_are_code_to_copy(tmp_path: Path) -> None:
    html = web(tmp_path).get("/ahora").text
    assert "<code>sudo backtide enlace</code>" in html and "`" not in html.split("<main")[1]
    assert "<code>sudo backtide contraseña</code>" in refused(tmp_path, "unset")


@pytest.mark.parametrize("why", sorted(SIGN_IN_ERRORS))
def test_both_languages_say_every_error(why: str) -> None:
    for lang in ("es", "en"):
        assert STRINGS[lang].get(f"auth.err.{why}"), (lang, why)


def test_english_says_it_in_english(tmp_path: Path) -> None:
    html = refused(tmp_path, "wrong", lang="en")
    assert 'lang="en"' in html and "That is not the password." in html
