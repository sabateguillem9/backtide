"""The rewind button of the web (T12b): who it asks, whether it can, and the confirmations.

The web never rewinds on its own. It asks the running service through its control socket, the
same way `vigia rebobinar` does when the service holds the lock (``ask_rewind``, with
``via="web"`` so the black box says where the request came from). If there is no service, the
web says so and does nothing: there is no in-process fallback here, on purpose (the CLI has one
because the person is at the terminal and sees the agent stay stopped).

Writes are explicit: `vigia web` rewinds only when started with ``--rebobinar``. Without it the
web only watches, whoever runs it (``Availability.DISABLED``; it does not even look at the
socket), and as root it refuses to start (``vigia.cli``).

Who can: the socket is 0600 (connecting to a Unix socket needs write permission on it) and the
service answers only its own uid (``SO_PEERCRED``). The state folder may be ``g+rx`` for a
reader (the recipe in ``vigia.web.server``): that lets the reader see the socket, not use it.
So, with ``--rebobinar``, the button works only when `vigia web` runs as the service's user; a
web run as a lower-privileged reader cannot ask and says so.
``ControlRewinder.availability`` tells which case this is, without connecting.

Confirmations (``Tickets``): the confirmation page hands out a one-time ticket bound to one
snapshot id, and only a POST that carries it (plus the session's CSRF token) rewinds. So no
single request can rewind blindly: the notice has to have been fetched for that very snapshot
first. A ticket lives ``CONFIRM_SECONDS``. It is spent by the first POST that shows it AND gets
past the form and CSRF checks (a POST that fails those spends nothing), whatever happens after
that (another id, a list without it, no service, a rewind already running). A spent ticket is
remembered until it would have expired, so a second click on the same form (a double submit
without JavaScript) is told "already used", not "expired".
"""

import os
import secrets
import stat
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from vigia.service.control import ControlError, PeerCredentials, ask_rewind, peer_credentials
from vigia.web.security import TOKEN_BYTES, token_matches

CONFIRM_SECONDS = 600  # how long a confirmation stays valid
MAX_TICKETS = 16  # confirmations open at once; the oldest is dropped first
WAIT_FOR_SERVICE = 2.0  # a starting service gets this long; the CLI waits 10 s


class Availability(StrEnum):
    READY = "ready"  # the service's socket is there, and it is ours: the button works
    NO_SERVICE = "no_service"  # no socket: the service is not running (or starting)
    OTHER_USER = "other_user"  # the socket (or its folder) belongs to another user
    OFF = "off"  # not configured, or something odd is where the socket should be
    DISABLED = "disabled"  # `vigia web` without --rebobinar: it only watches


class Redeemed(StrEnum):
    OK = "ok"  # open, for this snapshot, in time: now spent
    SPENT = "spent"  # it was good, and a POST already used it
    INVALID = "invalid"  # unknown, expired, or (now spent) for another snapshot


class Rewinder(Protocol):
    """What the app needs to rewind. ``rewind`` returns ``ask_rewind``'s checked reply and
    raises its errors (ControlUnavailable, ControlOutcomeUnknown, ControlError)."""

    def availability(self) -> Availability: ...

    def rewind(self, snapshot_id: str) -> dict[str, Any]: ...


class ControlRewinder:
    """The real one: the control socket at ``path`` (``<state_dir>/control.sock``)."""

    def __init__(
        self,
        path: Path,
        *,
        enabled: bool = False,
        wait: float = WAIT_FOR_SERVICE,
        peer: PeerCredentials = peer_credentials,
        euid: Callable[[], int] = os.geteuid,
    ) -> None:
        self._path = Path(path)
        self._enabled = enabled
        self._wait = wait
        self._peer = peer
        self._euid = euid

    def availability(self) -> Availability:
        """Can this process ask the service? Looked at, never connected to, and never
        followed (a symbolic link is OFF: ``ask_rewind`` would refuse it too). Without
        ``enabled`` (``--rebobinar``) it is DISABLED, whatever is there."""
        if not self._enabled:
            return Availability.DISABLED
        try:
            info = os.lstat(self._path)
        except FileNotFoundError:
            return self._without_socket()
        except PermissionError:  # the state folder is not ours to look into
            return Availability.OTHER_USER
        except OSError:
            return Availability.OFF
        if not stat.S_ISSOCK(info.st_mode):
            return Availability.OFF
        if info.st_uid != self._euid():
            return Availability.OTHER_USER
        return Availability.READY

    def _without_socket(self) -> Availability:
        try:
            folder = os.stat(self._path.parent)
        except PermissionError:
            return Availability.OTHER_USER
        except OSError:
            return Availability.OFF
        return Availability.NO_SERVICE if folder.st_uid == self._euid() else Availability.OTHER_USER

    def rewind(self, snapshot_id: str) -> dict[str, Any]:
        if not self._enabled:  # the app never gets here without READY; still, never by accident
            raise ControlError("esta web no se lanzó con --rebobinar")
        return ask_rewind(self._path, snapshot_id, via="web", wait=self._wait, peer=self._peer)


class Tickets:
    """One-time confirmations, each bound to one snapshot id. Thread-safe."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        *,
        lifetime: timedelta = timedelta(seconds=CONFIRM_SECONDS),
        limit: int = MAX_TICKETS,
    ) -> None:
        self._clock = clock
        self._lifetime = lifetime
        self._limit = limit
        self._open: list[tuple[str, str, datetime]] = []  # (ticket, snapshot id, expires)
        self._spent: list[tuple[str, datetime]] = []  # (ticket, when it would have expired)
        self._lock = threading.Lock()

    def issue(self, snapshot_id: str) -> str:
        ticket = secrets.token_urlsafe(TOKEN_BYTES)
        with self._lock:
            self._open.append((ticket, snapshot_id, self._clock() + self._lifetime))
            del self._open[: max(0, len(self._open) - self._limit)]
        return ticket

    def redeem(self, given: str, snapshot_id: str) -> Redeemed:
        """OK if ``given`` is an open ticket for ``snapshot_id`` that has not expired. A ticket
        that matches an open one is spent here, also when it is for another id or too old (then
        INVALID). SPENT for one already spent that has not expired yet."""
        now = self._clock()
        with self._lock:
            self._spent = [(t, until) for t, until in self._spent if now < until]
            for index, (ticket, bound_to, expires) in enumerate(self._open):
                if token_matches(given, ticket):
                    del self._open[index]
                    self._spent.append((ticket, expires))
                    del self._spent[: max(0, len(self._spent) - self._limit)]
                    good = bound_to == snapshot_id and now < expires
                    return Redeemed.OK if good else Redeemed.INVALID
            if any(token_matches(given, ticket) for ticket, _ in self._spent):
                return Redeemed.SPENT
        return Redeemed.INVALID


__all__ = ["Availability", "ControlRewinder", "Redeemed", "Rewinder", "Tickets"]
