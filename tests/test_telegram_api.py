"""The Bot API client (T09) against the fake Bot API: results, errors without the token, no
redirects, and which base URLs are accepted."""

import socket
from collections.abc import Iterator

import pytest
from telegram_fake import TOKEN, FakeBotApi

from backtide.notify.telegram_api import BotApi, TelegramError, check_api_base


@pytest.fixture
def fake() -> Iterator[FakeBotApi]:
    with FakeBotApi() as server:
        yield server


def test_a_call_posts_json_and_returns_the_result(fake: FakeBotApi) -> None:
    api = BotApi(TOKEN, base=fake.base)
    result = api.call("sendMessage", {"chat_id": 1, "text": "hola ñ"})
    assert result["message_id"] == 1
    (call,) = fake.sent("sendMessage")
    assert call.params == {"chat_id": 1, "text": "hola ñ"}
    assert call.path == f"/bot{TOKEN}/sendMessage"


def test_a_refused_token_says_so_without_the_token(fake: FakeBotApi) -> None:
    api = BotApi("999999999:" + "B" * 35, base=fake.base)
    with pytest.raises(TelegramError) as caught:
        api.call("getMe")
    assert caught.value.unauthorized
    assert "B" * 35 not in str(caught.value)
    # No urllib exception behind it, whose HTTPError holds the URL (and so the token).
    error = caught.value
    assert error.__cause__ is None and (error.__context__ is None or error.__suppress_context__)


def test_the_api_description_is_scrubbed_of_the_token(fake: FakeBotApi) -> None:
    fake.fail_with = 400
    with pytest.raises(TelegramError) as caught:
        BotApi(TOKEN, base=fake.base).call("sendMessage", {})
    assert TOKEN not in str(caught.value)
    assert TOKEN.split(":")[1] not in str(caught.value)
    assert "failing on purpose" in str(caught.value)
    assert caught.value.status == 400


def test_a_redirect_is_never_followed(fake: FakeBotApi) -> None:
    with FakeBotApi() as elsewhere:
        fake.redirect_to = f"{elsewhere.base}/bot{TOKEN}/sendMessage"
        with pytest.raises(TelegramError) as caught:
            BotApi(TOKEN, base=fake.base).call("sendMessage", {"text": "x"})
        assert caught.value.status == 302
        assert elsewhere.calls == []  # the token never went there


def test_a_network_error_carries_no_url_or_token() -> None:
    with socket.socket() as probe:  # a port nobody listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    api = BotApi(TOKEN, base=f"http://127.0.0.1:{port}")
    with pytest.raises(TelegramError) as caught:
        api.call("getMe", timeout=2)
    text = str(caught.value)
    assert TOKEN not in text and "bot" + TOKEN[:5] not in text
    assert caught.value.status == 0


def test_the_repr_hides_the_token(fake: FakeBotApi) -> None:
    assert TOKEN not in repr(BotApi(TOKEN, base=fake.base))


@pytest.mark.parametrize(
    "base",
    [
        "https://api.telegram.org",
        "https://api.telegram.org/",
        "http://127.0.0.1:8081",
        "http://[::1]:9000",
        "http://localhost:1234",
    ],
)
def test_accepted_bases(base: str) -> None:
    assert check_api_base(base) == base.rstrip("/")


@pytest.mark.parametrize(
    "base",
    [
        "http://api.telegram.org",  # plain http off this machine would show the token
        "http://192.168.1.10:8081",
        "ftp://api.telegram.org",
        "https://user:pw@api.telegram.org",
        "https://api.telegram.org/bot",
        "https://api.telegram.org?x=1",
        "https://",
        "",
        "https://api.telegram.org:notaport",
    ],
)
def test_refused_bases(base: str) -> None:
    with pytest.raises(ValueError):
        check_api_base(base)


@pytest.mark.parametrize("token", ["", "a/b", "has space", "tab\there"])
def test_a_token_that_cannot_be_one_is_refused(token: str) -> None:
    with pytest.raises(ValueError) as caught:
        BotApi(token)
    assert token == "" or token not in str(caught.value)


def test_a_method_name_is_checked() -> None:
    with pytest.raises(ValueError):
        BotApi(TOKEN, base="http://127.0.0.1:1").call("../getMe")
