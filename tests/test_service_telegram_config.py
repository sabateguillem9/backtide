"""``<state_dir>/telegram.toml`` (T09): read like the gateway token (0600, ours, not a link),
and no error, repr or log ever shows the bot token."""

import os
from pathlib import Path

import pytest

from vigia.service.config import ConfigError
from vigia.service.telegram_config import TelegramSettings, load_telegram, telegram_file

TOKEN = "123456789:" + "Zx9_-" * 7  # the shape of a BotFather token; not a real one
SECRET_PART = TOKEN.split(":")[1]


@pytest.fixture
def state(tmp_path: Path) -> Path:
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    return folder


def write(state: Path, text: str, mode: int = 0o600) -> Path:
    path = telegram_file(state)
    path.write_text(text)
    path.chmod(mode)
    return path


def good(extra: str = "") -> str:
    return f'token = "{TOKEN}"\nchat_id = 424242424\n{extra}'


def test_no_file_no_bot(state: Path) -> None:
    assert load_telegram(state) is None


def test_a_good_file(state: Path) -> None:
    write(state, good())
    settings = load_telegram(state)
    assert isinstance(settings, TelegramSettings)
    assert settings.token.reveal() == TOKEN
    assert settings.chat_id == 424242424
    assert settings.api_base == "https://api.telegram.org"
    assert SECRET_PART not in repr(settings) and SECRET_PART not in str(settings)


def test_the_fake_api_on_loopback_is_allowed(state: Path) -> None:
    write(state, good('api_base = "http://127.0.0.1:8081"\n'))
    settings = load_telegram(state)
    assert settings is not None and settings.api_base == "http://127.0.0.1:8081"


def assert_refused(state: Path, text: str, mode: int = 0o600, *, says: str = "") -> None:
    write(state, text, mode)
    with pytest.raises(ConfigError) as caught:
        load_telegram(state)
    message = str(caught.value)
    assert SECRET_PART not in message and TOKEN not in message
    assert says in message


def test_a_file_others_can_read_is_refused(state: Path) -> None:
    assert_refused(state, good(), 0o644, says="chmod 600")


def test_a_symlink_is_refused(state: Path, tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.toml"
    real.write_text(good())
    real.chmod(0o600)
    os.symlink(real, telegram_file(state))
    with pytest.raises(ConfigError, match="symlink"):
        load_telegram(state)


@pytest.mark.parametrize(
    ("text", "says"),
    [
        (good('api_base = "http://api.telegram.org"\n'), "plain http"),
        (good('api_base = "https://evil.example/bot"\n'), "path"),
        (good("webhook = true\n"), "unknown"),
        (f'token = "{TOKEN}"\n', "chat_id"),
        ("chat_id = 1\n", "token"),
        (f'token = "{TOKEN}"\nchat_id = -100123\n', "positive"),
        (f'token = "{TOKEN}"\nchat_id = "424242424"\n', "positive"),
        (f'token = "{TOKEN}"\nchat_id = true\n', "positive"),
        ('token = "not a token"\nchat_id = 1\n', "BotFather"),
        (f'token = "{TOKEN} {TOKEN}"\nchat_id = 1\n', "BotFather"),
        (f"token = {TOKEN}\nchat_id = 1\n", "not valid TOML"),
        (f'token = "{TOKEN}"\nchat_id = 1\n[[', "not valid TOML"),
    ],
)
def test_bad_files_are_refused_without_quoting_the_token(state: Path, text: str, says: str) -> None:
    assert_refused(state, text, says=says)


def test_a_huge_file_is_refused(state: Path) -> None:
    assert_refused(state, good("# " + "x" * 10_000 + "\n"), says="too big")
