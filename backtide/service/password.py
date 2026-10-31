"""The web's password (T26-3b-1, D40): the first way in, set at install.

`install.sh` (or `sudo backtide contraseña`) sets it; the service checks it, never the web, and
gives a session for it (``backtide.service.sessions``). After the first entry the web asks to
register a passkey (T26-3b-2); through the tunnel or a private network the password is enough
and is also the way back if the passkey is lost.

- Only a hash is kept: scrypt (standard library, n=2^15, r=8, p=1, a 16-byte salt), in
  ``<state_dir>/web-auth/password``, root's and 0600 in a 0700 folder, one line
  ``scrypt$<n>$<r>$<p>$<salt>$<hash>``. Nothing in it opens the web without guessing.
- A password is 12 to 256 characters (NIST SP 800-63B asks at least 8, and 15 when it is the
  only factor; the passkey comes next), and not only spaces.
- Guessing is slow and then stops: a bucket for the whole web (5 at once, then one every 12 s),
  whatever the address, and after ``LOCK_AFTER`` failures in a row every try is refused for
  ``LOCK_SECONDS``, the right password too. Whoever reaches the port can thus lock the owner out
  for a while: the way in then is `sudo backtide enlace` (an accepted limit, docs/47).
"""

import base64
import hashlib
import hmac
import os
import secrets
import stat
import threading
import time
import unicodedata
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

from backtide.service.settings import SettingsError, write_private

FOLDER = "web-auth"
FILE = "password"
MIN_CHARS, MAX_CHARS = 12, 256
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
SALT_BYTES, HASH_BYTES = 16, 32
MAX_FILE_BYTES = 512
TRIES_BURST, TRIES_PER_SECOND = 5, 1 / 12
LOCK_AFTER = 20
LOCK_SECONDS = 15 * 60


class PasswordError(Exception):
    """A password that cannot be set, or a file that is not ours. The message never holds it."""


class Verdict(StrEnum):
    RIGHT = "right"
    WRONG = "wrong"
    SLOW_DOWN = "slow_down"  # too many tries now: nothing was checked
    LOCKED = "locked"  # too many failures in a row: nothing is checked for a while
    LOCKING = "locking"  # this failure was the one too many: locked from now (alerted once)
    UNSET = "unset"  # no password yet


# The most common long passwords: refused outright (no list of leaks, no dependency).
COMMON = frozenset(
    {
        "password1234", "passwordpassword", "contraseña123", "contrasena1234", "qwertyuiop12",
        "qwertyuiopasdf", "iloveyou1234", "administrator", "letmein12345", "welcome12345",
        "backtide1234", "backtidebacktide", "123456789012", "1234567890123", "abcdefghijkl",
        "asdfghjklñ12", "zxcvbnm12345", "000000000000", "111111111111", "trustno1trustno1",
    }
)  # fmt: skip
SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm")
MAX_FORM_VALUE_BYTES = 2048 - len("password=")  # the web's form: every byte may be %XX


def _normal(password: str) -> str:
    """One way to write each character (NFC): a Mac and a phone compose accents differently."""
    return unicodedata.normalize("NFC", password)


def _trivial(password: str) -> bool:
    """One character or one block repeated, a simple run (forwards or backwards), or common."""
    low = password.lower()
    if low in COMMON:
        return True
    for size in range(1, len(low) // 2 + 1):
        if len(low) % size == 0 and low[:size] * (len(low) // size) == low:
            return True
    return any(low in run or low in run[::-1] for run in (s * 3 for s in SEQUENCES))


def problem(password: object) -> str | None:
    """Why ``password`` cannot be the web's password, or None. Never quotes it. Whatever passes
    can be typed in the web's form as it is (no spaces at the ends, nothing unprintable, short
    enough once encoded)."""
    if not isinstance(password, str):
        return "la contraseña tiene que ser texto"
    password = _normal(password)
    if not MIN_CHARS <= len(password) <= MAX_CHARS:
        return f"la contraseña tiene que tener entre {MIN_CHARS} y {MAX_CHARS} caracteres"
    if password != password.strip():
        return "la contraseña no puede empezar ni acabar con espacios"
    if not password.isprintable():
        return "la contraseña no puede llevar caracteres de control ni invisibles"
    if len(password.encode("utf-8")) * 3 > MAX_FORM_VALUE_BYTES:
        return "la contraseña es demasiado larga para el formulario de la web"
    if _trivial(password):
        return "esa contraseña es demasiado fácil de adivinar"
    return None


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        _normal(password).encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024,
        dklen=HASH_BYTES,
    )  # fmt: skip


def hash_password(password: str) -> str:
    """The line kept for ``password`` (PasswordError if it cannot be one)."""
    why = problem(password)
    if why is not None:
        raise PasswordError(why)
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    b64 = base64.b64encode
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt).decode()}${b64(digest).decode()}"


def matches(password: object, line: str) -> bool:
    """Does ``password`` match the kept ``line``? Constant time; False for anything odd. Only
    the shape that keeps scrypt cheap is checked here, never the rules for a new password: a
    rule added later must not lock out a password kept before it (review of T26-3b-1)."""
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_CHARS:
        return False
    parts = line.strip().split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n, r, p = (int(v) for v in parts[1:4])
        salt = base64.b64decode(parts[4], validate=True)
        digest = base64.b64decode(parts[5], validate=True)
    except ValueError:
        return False
    if (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P) or len(digest) != HASH_BYTES:
        return False  # only our own parameters: a file cannot make a check cheap or huge
    return hmac.compare_digest(_scrypt(password, salt, n, r, p), digest)


def path_of(state_dir: Path) -> Path:
    return Path(state_dir) / FOLDER / FILE


def write(state_dir: Path, password: str) -> None:
    """Keep the hash of ``password`` (0600, atomically, in a 0700 folder of ours)."""
    line = hash_password(password)
    folder = Path(state_dir) / FOLDER
    try:
        folder.mkdir(mode=0o700, exist_ok=True)
        info = os.lstat(folder)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise PasswordError(f"{folder} no es una carpeta nuestra")
        os.chmod(folder, 0o700)
        write_private(folder, FILE, (line + "\n").encode(), private_dir=True)
    except OSError as error:
        raise PasswordError(f"no se puede guardar en {folder}: {error.strerror}") from None
    except SettingsError as error:
        raise PasswordError(f"no se puede guardar en {folder}: {error}") from None


def read(state_dir: Path) -> str | None:
    """The kept line, or None if there is no password yet. PasswordError for a file that is not
    ours (a link, another owner, open to others, too big)."""
    path = path_of(state_dir)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise PasswordError(f"no se puede abrir {path}: {error.strerror}") from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > MAX_FILE_BYTES
        ):
            raise PasswordError(f"{path} no es el archivo de la contraseña: no se usa")
        return os.read(fd, MAX_FILE_BYTES).decode("ascii", errors="replace").strip()
    finally:
        os.close(fd)


class Checker:
    """The service's side: one per service, thread-safe. ``clock`` is monotonic seconds."""

    def __init__(self, state_dir: Path, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._state_dir = Path(state_dir)
        self._clock = clock
        self._tokens = float(TRIES_BURST)
        self._at = clock()
        self._failures = 0
        self._locked_until: float | None = None
        self._lock = threading.Lock()

    def check(self, password: object) -> Verdict:
        """Is it the web's password? One try of the bucket; the lock first."""
        with self._lock:
            now = self._clock()
            if self._locked_until is not None:
                if now < self._locked_until:
                    return Verdict.LOCKED
                self._locked_until, self._failures = None, 0
            self._tokens = min(
                float(TRIES_BURST), self._tokens + (now - self._at) * TRIES_PER_SECOND
            )
            self._at = now
            if self._tokens < 1:
                return Verdict.SLOW_DOWN
            self._tokens -= 1
        line = read(self._state_dir)  # outside the lock: scrypt takes a while
        if line is None:
            return Verdict.UNSET
        right = matches(password, line)
        with self._lock:
            # Another try may have locked it while this one was hashing: the lock wins, the
            # right one too, and only the try that locks says so (review of T26-3b-1).
            if self._locked_until is not None and self._clock() < self._locked_until:
                return Verdict.LOCKED
            if right:
                self._failures = 0
                return Verdict.RIGHT
            self._failures += 1
            if self._failures >= LOCK_AFTER:
                self._locked_until = self._clock() + LOCK_SECONDS
                return Verdict.LOCKING
            return Verdict.WRONG

    def set(self, password: str) -> None:
        """A new password (`sudo backtide contraseña`): PasswordError if it cannot be one. The
        count of failures starts again, and a lock ends."""
        write(self._state_dir, password)
        with self._lock:
            self._failures, self._locked_until = 0, None

    @property
    def failures(self) -> int:
        with self._lock:
            return self._failures


__all__ = [
    "LOCK_AFTER",
    "LOCK_SECONDS",
    "MAX_CHARS",
    "MIN_CHARS",
    "Checker",
    "PasswordError",
    "Verdict",
    "hash_password",
    "matches",
    "path_of",
    "problem",
    "read",
    "write",
]
