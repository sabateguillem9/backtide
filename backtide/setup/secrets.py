"""The installer's keys: asked without echo, or read from a file or stdin; written 0600.

Design: docs/25, section 3 ("Entrada de secretos"), T13-3. The rules:
- a key never goes through an argument or an environment variable (``ps`` and
  ``/proc/<pid>/environ`` show both): ``--clave-archivo <ruta>`` names a FILE, ``--clave-stdin``
  reads it from standard input, and with a terminal it is asked for with ``getpass`` (no echo,
  read from ``/dev/tty``, so it also works under ``curl ... | sudo sh``);
- it is checked with the Settings page's own rule (``settings.check_value``): what does not look
  like a key of that provider is refused, saying so and never quoting it;
- it is written as the Settings page writes it (``settings.write_private``): a new 0600 file of
  root in the 0700 keys folder, renamed into place, so the service never reads half a key;
- no message, exception or log line carries it: errors say what the input IS (a path, a size,
  that it is empty), never what it holds. A second install with the same key changes nothing.
"""

import getpass
import os
import secrets
import stat
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from backtide.service.settings import SettingsError, check_value, write_private

MAX_SECRET_BYTES = 4096
TOKEN_BYTES = 32  # the gateway token: 43 characters of urlsafe base64


class SecretError(Exception):
    """A key could not be read or written. The message never holds the key (in Spanish)."""


class Written(StrEnum):
    CREATED = "creada"
    REPLACED = "cambiada"
    UNCHANGED = "igual"


def from_file(path: Path) -> str:
    """The key in ``path``: one line, surrounding spaces and the final newline taken off. The
    file is opened without following a link and must be a regular, small file."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise SecretError(f"no se puede abrir {path}: {os.strerror(error.errno or 0)}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SecretError(f"{path} no es un archivo normal")
        if info.st_size > MAX_SECRET_BYTES:
            raise SecretError(f"{path} es demasiado grande para ser una clave ({info.st_size} B)")
        data = os.read(fd, MAX_SECRET_BYTES + 1)
    except OSError as error:
        raise SecretError(f"no se puede leer {path}: {os.strerror(error.errno or 0)}") from None
    finally:
        os.close(fd)
    return _one_line(data, f"el archivo {path}")


def from_stream(stream: BinaryIO) -> str:
    """The key from standard input (``--clave-stdin``)."""
    data = stream.read(MAX_SECRET_BYTES + 1)
    return _one_line(data or b"", "la entrada estándar")


def ask(prompt: str, *, reader: Callable[[str], str] = getpass.getpass) -> str:
    """Ask for the key at the terminal, without echo. ``reader`` is getpass (the tests')."""
    try:
        value = reader(prompt)
    except (EOFError, KeyboardInterrupt):
        raise SecretError("no se ha escrito ninguna clave") from None
    return _one_line(value.encode("utf-8", errors="replace"), "lo escrito")


def check(kind: str, value: str) -> None:
    """Refuse what does not look like a key of ``kind`` (the Settings page's rule)."""
    if not check_value(kind, value):
        raise SecretError(
            f"eso no parece una clave de {kind} ({len(value)} caracteres): no se ha guardado. "
            "Cópiala otra vez de la consola del proveedor."
        )


def write(folder: Path, name: str, value: str, *, private_dir: bool = True) -> Written:
    """Write ``value`` to ``folder/name`` (0600, atomically). The same value there already is
    left alone: a second install changes nothing. ``folder`` must be root's and closed to
    others (``private_dir``: to its group too; the state folder is 0710 for the web, D25)."""
    path = folder / name
    current = _current(path)
    if current == value:
        return Written.UNCHANGED
    try:
        write_private(folder, name, (value + "\n").encode("utf-8"), private_dir=private_dir)
    except (SettingsError, OSError) as error:
        what = error.strerror if isinstance(error, OSError) else str(error)
        raise SecretError(f"no se puede escribir {path}: {what}") from None
    return Written.CREATED if current is None else Written.REPLACED


def new_token() -> str:
    """A fresh random token (the Gateway's): nobody types it."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def _current(path: Path) -> str | None:
    """What ``path`` holds now, or None if there is nothing there. A link, a folder or a file
    that is not 0600 and ours is never read: it is an error."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SecretError(f"no se puede mirar {path}: {os.strerror(error.errno or 0)}") from None
    if not stat.S_ISREG(info.st_mode):
        raise SecretError(f"{path} existe y no es un archivo normal: revísalo a mano")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise SecretError(
            f"{path} existe pero no es 0600 de root ({stat.S_IMODE(info.st_mode):04o}, dueño "
            f"{info.st_uid}): revísalo a mano"
        )
    try:
        return from_file(path)
    except SecretError:
        return ""  # unreadable or empty: different from any key, so it is replaced


def _one_line(data: bytes, where: str) -> str:
    if len(data) > MAX_SECRET_BYTES:
        raise SecretError(f"{where} es demasiado grande para ser una clave")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SecretError(f"{where} no es texto UTF-8") from None
    lines = [line.strip() for line in text.strip().splitlines()]
    if not lines or not lines[0]:
        raise SecretError(f"{where} está vacío")
    if len(lines) > 1:
        raise SecretError(f"{where} tiene {len(lines)} líneas: una clave es una sola línea")
    return lines[0]
