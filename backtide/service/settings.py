"""The person's keys, set from the web's Settings page (T12e): what ``set_secret``,
``clear_secret`` and ``secrets`` of the control socket do inside the service.

Where each one lives (the same files a person would write by hand):

- ``anthropic`` and ``openai``: ``<state_dir>/keys/<kind>.key`` (0600, in a 0700 folder), the real
  key of the ``[proxy]`` provider with that name (docs/21, section 6). Its fake key (``.fake``) is
  never touched: the agent keeps seeing the same fake one.
- ``telegram``: ``<state_dir>/telegram.toml`` (0600), the bot's token and the owner's chat id
  together (the file needs both: ``backtide.service.telegram_config``).

The rules:

- **Write-only.** No reply, message, log line, exception text or black-box event carries a key or
  any part of it. ``status`` gives, per kind, whether it is set, when it changed and its LAST FOUR
  characters (only for a value of ``MIN_SHOWN`` characters or more): that is all the page shows.
  The black box gets ``settings/secret_set`` or ``settings/secret_cleared`` with the kind and who
  asked, nothing else (no length, no hash, no tail).
- **Checked here**, not in the web: an Anthropic key looks like ``sk-ant-…``, an OpenAI one like
  ``sk-…``, a Telegram token like ``<digits>:<30-64 characters>`` and a chat id is a positive
  number. A value that does not fit is refused with a fixed text (never quoting it). A fake key
  of backtide's is refused too: it would hand the agent's own key to the proxy as the real one.
- **Written atomically**: a new 0600 file of ours (``O_EXCL``, ``O_NOFOLLOW``) next to the old
  one, ``fsync``, ``rename`` over it, ``fsync`` of the folder, all through the folder's own file
  descriptor (a folder swapped for a link half way is not followed). The folder must be ours and
  closed to others. No sudo anywhere: the service writes as itself.
- **Recorded first**: the event goes to the black box before the file changes, and if it cannot be
  recorded nothing changes. If the write then fails, ``settings/secret_failed`` says so.
- **Applied**: a provider's key is handed to the egress proxy at once (``reload_keys``: a new
  connection to the proxy with the new config, no restart). A provider of ``[proxy]`` without a
  usable key waits for it (``waiting``): the service runs, the proxy refuses its model calls,
  and ``status`` says so (``waiting``) until the key is set; removing it makes it wait again.
  If the keys cannot be handed over, the reload fails closed (``ReloadFailedClosed``): a
  removed key is no longer used already, a new one is used from the next start.
  The Telegram bot reads its file when the service starts, so a change there applies at the
  next start, and the reply says so.
- One change at a time (a lock), and the value is dropped as soon as it is written. Python cannot
  wipe an immutable string, so "dropped" means no reference is kept.
"""

import json
import logging
import os
import re
import secrets
import stat
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from backtide.blackbox import Source
from backtide.gate.providers import FAKE_KEY_PREFIX
from backtide.notify.telegram_api import DEFAULT_API_BASE
from backtide.service.config import STATE_KEYS, ConfigError, _decode, _read_file
from backtide.service.telegram_config import (
    MAX_TELEGRAM_BYTES,
    STATE_TELEGRAM,
    load_telegram,
)

logger = logging.getLogger(__name__)

PROVIDERS = ("anthropic", "openai")
TELEGRAM = "telegram"
KINDS = (*PROVIDERS, TELEGRAM)
MAX_VALUE_CHARS = 256
MAX_KEY_FILE_BYTES = 4096
SHOWN_TAIL = 4  # the page shows the last four characters of a key...
MIN_SHOWN = 16  # ...only when it has at least this many (fewer: four would be too much of it)
# An Anthropic API key (``sk-ant-api03-…``); not an OAuth token (``sk-ant-oat…``), which OpenClaw
# treats differently (docs/21, section 6).
_ANTHROPIC_RE = re.compile(r"sk-ant-(?!oat)[A-Za-z0-9_-]{20,240}", re.ASCII)
# An OpenAI key: ``sk-…``, ``sk-proj-…``, ``sk-svcacct-…``. Not an Anthropic one.
_OPENAI_RE = re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{20,240}", re.ASCII)
# "<bot id>:<secret>", as BotFather hands it out (the same shape telegram_config accepts).
_TELEGRAM_TOKEN_RE = re.compile(r"[0-9]{5,16}:[A-Za-z0-9_-]{30,64}", re.ASCII)
# A private chat's id: positive (groups and channels are negative and may never command).
_CHAT_RE = re.compile(r"[1-9][0-9]{0,15}", re.ASCII)
_TAIL_RE = re.compile(r"[A-Za-z0-9_-]{4}", re.ASCII)
RISK = 1  # a change to backtide's own settings: worth seeing, not a danger


class Outcome(StrEnum):
    SAVED = "saved"
    CLEARED = "cleared"
    NOT_SET = "not_set"  # nothing to remove
    INVALID = "invalid"  # the value does not look like one of its kind: nothing changed
    FAILED = "failed"  # it could not be recorded or written: nothing changed (or see the box)


class Applied(StrEnum):
    NOW = "now"  # the proxy uses it already
    WHEN_UP = "when_up"  # the proxy is down right now: it gets it when the watch brings it back
    UNUSED = "unused"  # no [proxy] provider has that name: saved, used by nobody yet
    RESTART = "restart"  # read when the service starts (the Telegram bot)
    NONE = "none"  # nothing changed


@dataclass(frozen=True)
class SettingsOutcome:
    """The answer to a change. ``message`` is a fixed Spanish text: it never holds the value."""

    status: Outcome
    message: str
    applied: Applied = Applied.NONE

    @property
    def ok(self) -> bool:
        return self.status in (Outcome.SAVED, Outcome.CLEARED)


Record = Callable[..., object]  # BlackBox.append (or the rated one)
Reload = Callable[[], Applied]  # hand the keys of keys/ to the proxy again
Waiting = Callable[[], Mapping[str, str]]  # the providers that wait for their key, and why


class SettingsError(Exception):
    """A file or folder of the settings cannot be used. The message never holds a value."""


class ReloadFailedClosed(Exception):
    """The keys could not be handed to the proxy as they are now, so it failed closed: the
    providers whose key changed wait for it (review of T09b, finding 1). ``applied`` says
    whether the proxy took that at once (``NOW``) or takes it when it is back (``WHEN_UP``)."""

    def __init__(self, applied: Applied) -> None:
        super().__init__(f"the reload failed closed ({applied})")
        self.applied = applied


def check_value(kind: str, value: str) -> bool:
    """Does ``value`` look like a key (or token) of ``kind``? Never raises, never logs."""
    if not isinstance(value, str) or not value or len(value) > MAX_VALUE_CHARS:
        return False
    if FAKE_KEY_PREFIX in value:
        return False
    if kind == "anthropic":
        return _ANTHROPIC_RE.fullmatch(value) is not None
    if kind == "openai":
        return _OPENAI_RE.fullmatch(value) is not None
    if kind == TELEGRAM:
        return _TELEGRAM_TOKEN_RE.fullmatch(value) is not None
    return False


def check_chat_id(value: str) -> bool:
    return isinstance(value, str) and _CHAT_RE.fullmatch(value) is not None


def tail_of(value: str) -> str | None:
    """The last four characters of ``value``, if it is long enough and they are plain."""
    if len(value) < MIN_SHOWN:
        return None
    tail = value[-SHOWN_TAIL:]
    return tail if _TAIL_RE.fullmatch(tail) else None


class Settings:
    """The keys of ``state_dir``. ``record`` appends to the black box; ``reload_keys`` hands the
    providers' keys to the proxy again (None: nothing to tell, which only tests do); ``in_use``
    names the providers of ``[proxy]`` (a key for another name is saved and used by nobody);
    ``waiting`` says which of them the proxy holds without a usable key now (``Egress.waiting``;
    None: it is read from the files)."""

    def __init__(
        self,
        state_dir: Path,
        *,
        record: Record,
        reload_keys: Reload | None = None,
        in_use: Iterable[str] = (),
        waiting: Waiting | None = None,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._record = record
        self._reload = reload_keys
        self._in_use = frozenset(in_use)
        self._waiting = waiting
        self._lock = threading.Lock()

    @property
    def keys_dir(self) -> Path:
        return self._state_dir / STATE_KEYS

    # -- what the page shows ---------------------------------------------------------------

    def status(self) -> dict[str, dict[str, Any]]:
        """Per kind: ``set``, ``tail`` (last four or None), ``changed`` (ISO 8601 UTC or None),
        ``in_use`` (a provider of [proxy] by that name), ``problem`` (None, or "unreadable":
        there is a file and it cannot be used) and ``waiting`` (a provider of [proxy] the agent
        cannot use until its key is set). Telegram adds ``chat_tail``. Never raises for a
        broken file: it says so."""
        waiting = self._waiting_now()
        shown: dict[str, dict[str, Any]] = {}
        for kind in PROVIDERS:
            entry = self._provider_status(kind)
            if entry["in_use"]:
                # The proxy's own view first: a file that reads well but holds no key the gate
                # can use (too short, two providers with one key) waits too.
                problem = waiting.get(kind)
                if problem == "unusable" and entry["set"]:
                    entry["problem"] = "unreadable"
                entry["waiting"] = (
                    problem is not None or not entry["set"] or entry["problem"] is not None
                )
            else:
                entry["waiting"] = False
            shown[kind] = entry
        shown[TELEGRAM] = self._telegram_status()
        return shown

    def _waiting_now(self) -> Mapping[str, str]:
        if self._waiting is None:
            return {}
        try:
            return dict(self._waiting())
        except Exception as error:  # the files still say what they can
            logger.error("settings: which providers wait cannot be read: %s", _what(error))
            return {}

    def _provider_status(self, kind: str) -> dict[str, Any]:
        path = self.keys_dir / f"{kind}.key"
        entry: dict[str, Any] = {
            "set": False, "tail": None, "changed": None, "in_use": kind in self._in_use,
            "problem": None,
        }  # fmt: skip
        if not os.path.lexists(path):
            return entry
        entry["set"] = True
        try:
            value = _decode(_read_file(path, "key file", MAX_KEY_FILE_BYTES, private=True)).strip()
            entry["tail"] = tail_of(value)
            del value
            entry["changed"] = _changed(path)
        except (ConfigError, OSError) as error:
            logger.warning("settings: the %s key file cannot be used: %s", kind, _what(error))
            entry["problem"] = "unreadable"
        return entry

    def _telegram_status(self) -> dict[str, Any]:
        path = self._state_dir / STATE_TELEGRAM
        entry: dict[str, Any] = {
            "set": False, "tail": None, "chat_tail": None, "changed": None, "in_use": True,
            "problem": None,
        }  # fmt: skip
        if not os.path.lexists(path):
            return entry
        entry["set"] = True
        try:
            settings = load_telegram(self._state_dir)
        except (ConfigError, OSError) as error:
            logger.warning("settings: telegram.toml cannot be used: %s", _what(error))
            entry["problem"] = "unreadable"
            return entry
        if settings is not None:
            entry["tail"] = tail_of(settings.token.reveal())
            chat = str(settings.chat_id)
            entry["chat_tail"] = chat[-SHOWN_TAIL:] if len(chat) > SHOWN_TAIL else None
            entry["changed"] = _changed(path)
        return entry

    # -- changes ---------------------------------------------------------------------------

    def set_secret(
        self, kind: str, value: str, *, chat_id: str = "", requested_by: str
    ) -> SettingsOutcome:
        """Put ``value`` as the key of ``kind``. For Telegram, ``value`` is the token and
        ``chat_id`` the owner's chat; an empty one keeps what the file has (the first time,
        both are needed)."""
        if kind not in KINDS:
            return SettingsOutcome(Outcome.INVALID, "Ese tipo de clave no existe aquí.")
        if kind == TELEGRAM:
            return self._set_telegram(value, chat_id, requested_by)
        if not check_value(kind, value):
            return SettingsOutcome(Outcome.INVALID, _SHAPES[kind])
        data = (value + "\n").encode()
        del value
        with self._lock:
            refusal = self._record_change("secret_set", kind, requested_by)
            if refusal is not None:
                return refusal
            try:
                folder = self._keys_folder()
                write_private(folder, f"{kind}.key", data)
            except (SettingsError, OSError) as error:
                return self._failed(kind, requested_by, "write", error)
            finally:
                del data
            applied = self._apply(kind)
        return SettingsOutcome(Outcome.SAVED, _SAVED[applied], applied)

    def clear_secret(self, kind: str, *, requested_by: str) -> SettingsOutcome:
        if kind not in KINDS:
            return SettingsOutcome(Outcome.INVALID, "Ese tipo de clave no existe aquí.")
        folder = self._state_dir if kind == TELEGRAM else self.keys_dir
        name = STATE_TELEGRAM if kind == TELEGRAM else f"{kind}.key"
        with self._lock:
            if not os.path.lexists(folder / name):
                return SettingsOutcome(Outcome.NOT_SET, "No había nada que quitar.")
            refusal = self._record_change("secret_cleared", kind, requested_by)
            if refusal is not None:
                return refusal
            try:
                remove_private(folder, name, private_dir=kind != TELEGRAM)
            except (SettingsError, OSError) as error:
                return self._failed(kind, requested_by, "remove", error)
            applied = Applied.RESTART if kind == TELEGRAM else self._apply(kind, removed=True)
        return SettingsOutcome(Outcome.CLEARED, _CLEARED[applied], applied)

    def _set_telegram(self, token: str, chat_id: str, requested_by: str) -> SettingsOutcome:
        if token and not check_value(TELEGRAM, token):
            return SettingsOutcome(Outcome.INVALID, _SHAPES[TELEGRAM])
        if chat_id and not check_chat_id(chat_id):
            return SettingsOutcome(
                Outcome.INVALID,
                "El chat tiene que ser el número de tu chat privado con el bot (positivo, solo "
                "cifras): no se ha cambiado nada.",
            )
        if not token and not chat_id:
            return SettingsOutcome(Outcome.INVALID, "No has puesto nada: no se ha cambiado nada.")
        with self._lock:
            api_base = DEFAULT_API_BASE
            path = self._state_dir / STATE_TELEGRAM
            if not token or not chat_id:
                try:
                    current = load_telegram(self._state_dir) if os.path.lexists(path) else None
                except (ConfigError, OSError):
                    current = None
                if current is None:
                    return SettingsOutcome(
                        Outcome.INVALID,
                        "La primera vez hacen falta el token y el chat a la vez: no se ha "
                        "cambiado nada.",
                    )
                token = token or current.token.reveal()
                chat_id = chat_id or str(current.chat_id)
                api_base = current.api_base
                del current
            elif os.path.lexists(path):
                try:  # keep the tests' api_base, if the file has one
                    current = load_telegram(self._state_dir)
                    api_base = current.api_base if current is not None else api_base
                    del current
                except (ConfigError, OSError):
                    pass  # unusable: replaced whole, with the real Bot API
            lines = [f'token = "{token}"', f"chat_id = {int(chat_id)}"]
            del token
            if api_base != DEFAULT_API_BASE:
                lines.append(f"api_base = {json.dumps(api_base)}")
            data = ("\n".join(lines) + "\n").encode()
            del lines
            if len(data) > MAX_TELEGRAM_BYTES:  # cannot happen with checked values
                return SettingsOutcome(Outcome.INVALID, _SHAPES[TELEGRAM])
            refusal = self._record_change("secret_set", TELEGRAM, requested_by)
            if refusal is not None:
                return refusal
            try:
                write_private(self._state_dir, STATE_TELEGRAM, data, private_dir=False)
            except (SettingsError, OSError) as error:
                return self._failed(TELEGRAM, requested_by, "write", error)
            finally:
                del data
        return SettingsOutcome(Outcome.SAVED, _SAVED[Applied.RESTART], Applied.RESTART)

    # -- pieces ----------------------------------------------------------------------------

    def _keys_folder(self) -> Path:
        """``<state_dir>/keys``, made 0700 if there is none yet."""
        folder = self.keys_dir
        try:
            os.mkdir(folder, 0o700)  # the umask can only take bits away; _open_folder checks
        except FileExistsError:
            pass  # whatever is there (a link, a folder open to others) _open_folder refuses
        return folder

    def _record_change(self, action: str, kind: str, requested_by: str) -> SettingsOutcome | None:
        """The event, before anything changes. A refusal (nothing changed) if it cannot be
        recorded."""
        try:
            self._record(
                Source.SETTINGS,
                action,
                kind,
                details={"kind": kind, "requested_by": requested_by},
                risk=RISK,
            )
        except Exception as error:  # the black box said no: nothing changes without its record
            logger.error("settings: %s of %s not recorded, so not done: %s", action, kind,
                         _what(error))  # fmt: skip
            return SettingsOutcome(
                Outcome.FAILED,
                "No se ha podido apuntar en la caja negra, así que no se ha cambiado nada.",
            )
        return None

    def _failed(
        self, kind: str, requested_by: str, step: str, error: BaseException
    ) -> SettingsOutcome:
        logger.error("settings: the %s of %s failed: %s", step, kind, _what(error))
        try:
            self._record(
                Source.SETTINGS,
                "secret_failed",
                kind,
                details={"kind": kind, "requested_by": requested_by, "step": step},
                risk=2,
            )
        except Exception as record_error:
            logger.error("settings: the failure of %s is not recorded either: %s", kind,
                         _what(record_error))  # fmt: skip
        return SettingsOutcome(
            Outcome.FAILED,
            "No se ha podido escribir el archivo: la clave anterior sigue como estaba. Mira el "
            "registro del servicio.",
        )

    def _apply(self, kind: str, *, removed: bool = False) -> Applied:
        """Hand the providers' keys to the proxy again, if this one is a provider of [proxy].
        If that fails closed, a removed key is no longer used already (its provider waits);
        a new one is used from the next start."""
        if kind not in self._in_use:
            return Applied.UNUSED
        if self._reload is None:
            return Applied.RESTART
        try:
            return self._reload()
        except ReloadFailedClosed as error:
            logger.error("settings: the proxy could not take the new keys, so the ones that "
                         "changed wait: %s", _what(error.__cause__ or error))  # fmt: skip
            return error.applied if removed else Applied.RESTART
        except Exception as error:  # the file is written: it applies at the next start
            logger.error("settings: the proxy could not take the new keys: %s", _what(error))
            return Applied.RESTART


# -- files ---------------------------------------------------------------------------------------


def write_private(folder: Path, name: str, data: bytes, *, private_dir: bool = True) -> None:
    """Replace ``folder/name`` with ``data``, atomically, as a 0600 file of ours. ``folder`` must
    be ours, not a link and not writable by others (and, if ``private_dir``, closed to them)."""
    dir_fd = _open_folder(folder, private_dir=private_dir)
    temp = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(temp, flags, 0o600, dir_fd=dir_fd)
        try:
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise SettingsError("the new file is not 0600 and ours")
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp = ""
        os.fsync(dir_fd)
    finally:
        if temp:
            try:
                os.unlink(temp, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)


def remove_private(folder: Path, name: str, *, private_dir: bool = True) -> None:
    """Remove ``folder/name`` (a regular file or a link, never followed)."""
    dir_fd = _open_folder(folder, private_dir=private_dir)
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            raise SettingsError(f"{name} is a folder")
        os.unlink(name, dir_fd=dir_fd)
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _open_folder(folder: Path, *, private_dir: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(folder, flags)
    except OSError as error:
        raise SettingsError(f"cannot open {folder}: {os.strerror(error.errno or 0)}") from None
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    closed = mode & (0o077 if private_dir else 0o022)
    if info.st_uid != os.geteuid() or closed:
        os.close(fd)
        raise SettingsError(f"{folder} is not ours and closed to others ({mode:04o})")
    return fd


def _changed(path: Path) -> str | None:
    try:
        moment = os.lstat(path).st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(moment, UTC).isoformat().replace("+00:00", "Z")


def _what(error: BaseException) -> str:
    """An error, for a log line: our own errors say what a file IS, never what it holds; an
    OSError gives its strerror only; anything else gives its type only."""
    if isinstance(error, SettingsError | ConfigError):
        return str(error)
    if isinstance(error, OSError):
        return error.strerror or type(error).__name__
    return type(error).__name__


_SHAPES = {
    "anthropic": "Eso no parece una clave de Anthropic (empieza por sk-ant-, solo letras, cifras, "
    "guiones y guiones bajos): no se ha cambiado nada.",
    "openai": "Eso no parece una clave de OpenAI (empieza por sk-, solo letras, cifras, guiones y "
    "guiones bajos): no se ha cambiado nada.",
    TELEGRAM: "Eso no parece el token de un bot (cifras, dos puntos y unos 35 caracteres, tal "
    "como lo da @BotFather): no se ha cambiado nada.",
}
_SAVED = {
    Applied.NOW: "Guardada. El proxy ya la usa: el agente sigue con su clave falsa.",
    Applied.WHEN_UP: "Guardada. El proxy está caído ahora mismo: la usará en cuanto vuelva.",
    Applied.UNUSED: "Guardada, pero ningún proveedor de [proxy] se llama así: nadie la usa "
    "todavía.",
    Applied.RESTART: "Guardada. Se aplica al reiniciar el servicio.",
    Applied.NONE: "Guardada.",
}
_CLEARED = {
    Applied.NOW: "Quitada. El proxy ya no la usa: el agente no puede usar ese modelo hasta que "
    "pongas otra.",
    Applied.WHEN_UP: "Quitada. El proxy está caído ahora mismo y vuelve sin ella.",
    Applied.UNUSED: "Quitada.",
    Applied.RESTART: "Quitada. Se aplica al reiniciar el servicio.",
    Applied.NONE: "Quitada.",
}
