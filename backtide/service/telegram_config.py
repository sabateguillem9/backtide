"""The settings of the Telegram bot (T09): ``<state_dir>/telegram.toml``.

    token = "123456789:AA..."     # from BotFather
    chat_id = 123456789           # the founder's chat: the only one that may command
    api_base = "https://api.telegram.org"   # optional; the tests point it at a fake

- The file lives in backtide's private state folder, never in ``backtide.toml`` (which holds no
  secret) and never in the agent's world: the state folder is not mounted into the agent and
  cannot be inside its config folder (``ServiceConfig`` checks that), so invariant 1 holds.
- It must be a regular file of ours, 0600, not a symlink: the same reading as the gateway
  token's (``config._read_file``). Its errors say the size and the mode, never the content,
  and a TOML error says only the line.
- No file, no bot: the alerts then go to the log, as before T09.
- The token is kept in a ``Secret`` (it prints as ``[REDACTED]``); ``api_base`` must be
  ``https://``, or ``http://`` on this machine's loopback (the tests' fake Bot API).
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from backtide.notify.telegram_api import DEFAULT_API_BASE, check_api_base
from backtide.service.config import ConfigError, Secret, _decode, _read_file

STATE_TELEGRAM = "telegram.toml"
MAX_TELEGRAM_BYTES = 4096
_KEYS = frozenset({"token", "chat_id", "api_base"})
# "<bot id>:<secret>", as BotFather hands it out.
_TOKEN_RE = re.compile(r"[0-9]{5,16}:[A-Za-z0-9_-]{30,64}")


@dataclass(frozen=True)
class TelegramSettings:
    token: Secret
    chat_id: int
    api_base: str = DEFAULT_API_BASE

    def __post_init__(self) -> None:
        if not isinstance(self.token, Secret):
            raise ConfigError("the Telegram token must be a Secret")
        if not _TOKEN_RE.fullmatch(self.token.reveal()):
            length = len(self.token.reveal())
            raise ConfigError(
                f"the Telegram token in {STATE_TELEGRAM} does not look like one from BotFather "
                f"({length} characters; expected <digits>:<letters>)"
            )
        if type(self.chat_id) is not int or self.chat_id <= 0:
            raise ConfigError(
                f"chat_id in {STATE_TELEGRAM} must be your own chat's id, a positive number "
                "(groups and channels are negative: only a private chat may command)"
            )
        try:
            object.__setattr__(self, "api_base", check_api_base(self.api_base))
        except ValueError as error:
            raise ConfigError(f"{STATE_TELEGRAM}: {error}") from None


def telegram_file(state_dir: Path) -> Path:
    return state_dir / STATE_TELEGRAM


def load_telegram(state_dir: Path) -> TelegramSettings | None:
    """The bot's settings, or None if ``telegram.toml`` does not exist. Raises ConfigError
    for a file that exists and is unusable (better to refuse to start than to watch without
    the alerts the founder asked for)."""
    path = telegram_file(state_dir)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ConfigError(f"cannot look at {path}: {error.strerror}") from None
    text = _decode(_read_file(path, "Telegram settings file", MAX_TELEGRAM_BYTES, private=True))
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        line = getattr(error, "lineno", None)
        where = f" (line {line})" if line else ""
        raise ConfigError(f"{path} is not valid TOML{where}") from None
    unknown = sorted(set(data) - _KEYS)
    if unknown:
        raise ConfigError(f"unknown settings in {path}: {', '.join(map(repr, unknown))}")
    for key in ("token", "chat_id"):
        if key not in data:
            raise ConfigError(f"{path} needs {key!r}")
    token = data["token"]
    if not isinstance(token, str):
        raise ConfigError(f"token in {path} must be a string (in quotes)")
    api_base = data.get("api_base", DEFAULT_API_BASE)
    if not isinstance(api_base, str):
        raise ConfigError(f"api_base in {path} must be a string")
    return TelegramSettings(Secret(token.strip()), data["chat_id"], api_base)
