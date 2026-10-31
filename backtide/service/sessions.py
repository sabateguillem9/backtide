"""Who is signed in to the web (T26-3a, docs/47 section 5.2).

The service keeps the web's sessions, not the web: a web taken over cannot change anything
without a live session, and it cannot mint one, because a session is only ever given for a
one-time link that root asks for (`sudo backtide enlace`, on the control socket).

- A link: a random token (256 bits), good for one use and ``LINK_SECONDS``. There is at most
  one: a new one kills the unspent one.
- A session: a new random id (256 bits) at every entry, never one that existed before (session
  fixation), with its own CSRF token for the forms. It dies after ``IDLE_SECONDS`` unused and
  ``LIFETIME_SECONDS`` after it was opened, however much it is used (NIST SP 800-63B, AAL2).
  Several at once (the laptop and the phone), at most ``MAX_SESSIONS``: past that, the least
  recently used goes. One can be ended ("Salir") or all ("Cerrar todas", which kills the
  unspent link too).
- Only a SHA-256 digest of each token and id is kept, in memory: a restart of the service signs
  everyone out, and nothing on disk or in a dump of these structures opens a session.
- The limits can be shortened (a test of expiry), never made longer than the design's.

The web of the Mac's demo and `backtide web` without the service's narrow socket keep a
``Sessions`` of their own, in their process, with the same rules (``backtide.web.security``).
"""

import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeGuard

IDLE_SECONDS = 60 * 60
LIFETIME_SECONDS = 12 * 60 * 60
LINK_SECONDS = 15 * 60
MAX_SESSIONS = 16
MIN_SECONDS = 60  # the shortest a test may make a session's life
SECRET_BYTES = 32
MAX_SECRET_CHARS = 128  # anything longer is not one of ours: not even hashed


@dataclass(frozen=True)
class Session:
    """A live session: its id (the cookie) and its CSRF token (the forms)."""

    id: str
    csrf: str


@dataclass
class _Entry:
    csrf: str
    opened: float
    used: float


def _digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()


def _usable(given: object) -> TypeGuard[str]:
    return isinstance(given, str) and 0 < len(given) <= MAX_SECRET_CHARS and given.isascii()


class Sessions:
    """The link and the sessions, thread-safe. ``clock`` is monotonic seconds."""

    def __init__(
        self,
        *,
        idle: float = IDLE_SECONDS,
        lifetime: float = LIFETIME_SECONDS,
        link_seconds: float = LINK_SECONDS,
        max_sessions: int = MAX_SESSIONS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not MIN_SECONDS <= idle <= IDLE_SECONDS:
            raise ValueError(f"idle must be {MIN_SECONDS}..{IDLE_SECONDS} seconds")
        if not idle <= lifetime <= LIFETIME_SECONDS:
            raise ValueError(f"lifetime must be idle..{LIFETIME_SECONDS} seconds")
        if not 0 < link_seconds <= LINK_SECONDS:
            raise ValueError(f"link_seconds must be 1..{LINK_SECONDS} seconds")
        if not 0 < max_sessions <= MAX_SESSIONS:
            raise ValueError(f"max_sessions must be 1..{MAX_SESSIONS}")
        self._idle, self._lifetime, self._link_seconds = idle, lifetime, link_seconds
        self._max = max_sessions
        self._clock = clock
        self._link: tuple[bytes, float] | None = None  # (digest, dies at)
        self._sessions: dict[bytes, _Entry] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def new_link(self, token: str | None = None) -> str:
        """A new one-time link token; the unspent one, if any, dies. ``token`` is given only by
        a web that keeps its own sessions and prints its link (``backtide web``, the demo,
        the tests); the service always makes its own."""
        if token is None:
            token = secrets.token_urlsafe(SECRET_BYTES)
        elif not _usable(token):
            raise ValueError("a link token is 1..128 ASCII characters")
        with self._lock:
            self._link = (_digest(token), self._clock() + self._link_seconds)
        return token

    def open(self, token: object) -> Session | None:
        """A new session for the link's ``token``, or None (wrong, spent or too old: then the
        link is left as it was, so a guess cannot spend it)."""
        if not _usable(token):
            return None
        with self._lock:
            now = self._clock()
            link = self._link
            if (
                link is None
                or now >= link[1]
                or not secrets.compare_digest(_digest(token), link[0])
            ):
                return None
            self._link = None
            return self._start(secrets.token_urlsafe(SECRET_BYTES), now)

    def start(self) -> Session:
        """A new session for an entry the service checked itself (the password; later the
        passkey): a new random id, as for a link."""
        with self._lock:
            return self._start(secrets.token_urlsafe(SECRET_BYTES), self._clock())

    def preset(self, session_id: str) -> Session:
        """A session that is already open with this id: for the Mac's demo and the tests, which
        set the cookie themselves. The service never calls it."""
        with self._lock:
            return self._start(session_id, self._clock())

    def check(self, session_id: object, *, use: bool = True) -> Session | None:
        """The live session with this id, or None. With ``use`` it counts as used (its idle hour
        starts again); a page's own stream, which reconnects by itself, checks without it, so a
        tab left open does not keep a session alive (review of T26-3a)."""
        if not _usable(session_id):
            return None
        with self._lock:
            now = self._clock()
            self._forget_the_dead(now)
            entry = self._sessions.get(_digest(session_id))
            if entry is None:
                return None
            if use:
                entry.used = max(entry.used, now)
            return Session(session_id, entry.csrf)

    def end(self, session_id: object) -> bool:
        """End this session ("Salir"); False if it was not a live one."""
        if not _usable(session_id):
            return False
        with self._lock:
            self._forget_the_dead(self._clock())
            return self._sessions.pop(_digest(session_id), None) is not None

    def end_all(self) -> int:
        """End every session and the unspent link ("Cerrar todas"); how many sessions ended."""
        with self._lock:
            self._forget_the_dead(self._clock())
            ended = len(self._sessions)
            self._sessions.clear()
            self._link = None
            return ended

    def _start(self, session_id: str, now: float) -> Session:
        self._forget_the_dead(now)
        while len(self._sessions) >= self._max:
            oldest = min(self._sessions, key=lambda key: self._sessions[key].used)
            del self._sessions[oldest]
        csrf = secrets.token_urlsafe(SECRET_BYTES)
        self._sessions[_digest(session_id)] = _Entry(csrf, opened=now, used=now)
        return Session(session_id, csrf)

    def _forget_the_dead(self, now: float) -> None:
        dead = [
            key
            for key, entry in self._sessions.items()
            if now >= entry.used + self._idle
            or now >= entry.opened + self._lifetime
            or now < entry.opened  # the clock went back past the start: not to be trusted
        ]
        for key in dead:
            del self._sessions[key]


__all__ = [
    "IDLE_SECONDS",
    "LIFETIME_SECONDS",
    "LINK_SECONDS",
    "MAX_SESSIONS",
    "MIN_SECONDS",
    "Session",
    "Sessions",
]
