"""The Settings page of the web (T12e): who it asks, whether it can, and its confirmations.

The web never opens a key file (``WebPaths`` does not even know where they are). It asks the
running service through its control socket, like the rewind (``backtide.web.rewind``):
``secrets`` for what is set (the last four characters at most), ``set_secret`` and
``clear_secret`` to change it, with ``via="web"`` so the black box says where it came from. The
service checks the value and writes the file (``backtide.service.settings``).

Writes are explicit: only with ``backtide web --ajustes``. Without it the page says how to turn it
on and asks the service nothing (``Availability.DISABLED``), and the Guard does not even take its
POST. Who can: the same as the rewind, the service's own user (the socket is 0600 and the service
answers only its uid).

What comes back is checked before it reaches a page (``SecretView``): a tail is shown only if it
is exactly four plain characters, so a broken or hostile reply cannot put more of a key there.

Confirmations (``SettingTickets``): each change has a page of its own (GET, changes nothing) that
hands out a one-time ticket bound to that action and that kind; only a POST that carries it (and
the session's CSRF token) changes anything. Replacing a key that is set also needs the box "replace
the key that ends in …" ticked. A ticket lives ``CONFIRM_SECONDS`` and is spent by the first POST
that shows it and gets past the form and CSRF checks, whatever happens after.
"""

import os
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from backtide.service.control import (
    ControlError,
    PeerCredentials,
    ask_clear_secret,
    ask_secrets,
    ask_set_secret,
    peer_credentials,
)
from backtide.service.settings import KINDS, PROVIDERS, TELEGRAM, check_chat_id
from backtide.web.rewind import (
    CONFIRM_SECONDS,
    MAX_TICKETS,
    WAIT_FOR_SERVICE,
    Availability,
    Redeemed,
    socket_availability,
)
from backtide.web.security import TOKEN_BYTES, token_matches

ACTIONS = ("set", "clear")
_TAIL_RE = re.compile(r"[A-Za-z0-9_-]{4}", re.ASCII)
_CHAT_TAIL_RE = re.compile(r"[0-9]{4}", re.ASCII)


class SettingsClient(Protocol):
    """What the app needs. ``status``, ``set_secret`` and ``clear_secret`` raise the control
    socket's errors (ControlUnavailable, ControlOutcomeUnknown, ControlError)."""

    def availability(self) -> Availability: ...

    def status(self) -> dict[str, dict[str, Any]]: ...

    def set_secret(self, kind: str, value: str, chat_id: str | None) -> dict[str, Any]: ...

    def clear_secret(self, kind: str) -> dict[str, Any]: ...


class ControlSettings:
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
        self.enabled = enabled
        self._wait = wait
        self._peer = peer
        self._euid = euid

    def availability(self) -> Availability:
        return socket_availability(self._path, enabled=self.enabled, euid=self._euid)

    def _require(self) -> None:
        if not self.enabled:  # the app never gets here without READY; still, never by accident
            raise ControlError("esta web no se lanzó con --ajustes")

    def status(self) -> dict[str, dict[str, Any]]:
        self._require()
        return ask_secrets(self._path, wait=self._wait, peer=self._peer)

    def set_secret(self, kind: str, value: str, chat_id: str | None) -> dict[str, Any]:
        self._require()
        return ask_set_secret(
            self._path, kind, value, chat_id=chat_id, via="web", wait=self._wait, peer=self._peer
        )

    def clear_secret(self, kind: str) -> dict[str, Any]:
        self._require()
        return ask_clear_secret(self._path, kind, via="web", wait=self._wait, peer=self._peer)


@dataclass(frozen=True)
class SecretView:
    """One row of the page, from the service's reply, checked field by field."""

    kind: str
    set: bool = False
    tail: str | None = None
    chat_tail: str | None = None
    changed: datetime | None = None
    in_use: bool = False
    problem: bool = False

    @property
    def provider(self) -> bool:
        return self.kind in PROVIDERS


def views(raw: dict[str, Any] | None) -> list[SecretView]:
    """One ``SecretView`` per kind, in the page's order. ``raw`` is ``SettingsClient.status``'s
    reply (None: unknown, every row says nothing)."""
    rows = []
    for kind in KINDS:
        entry = raw.get(kind) if isinstance(raw, dict) else None
        if not isinstance(entry, dict):
            rows.append(SecretView(kind))
            continue
        tail = entry.get("tail")
        chat = entry.get("chat_tail")
        rows.append(
            SecretView(
                kind,
                set=entry.get("set") is True,
                tail=tail if isinstance(tail, str) and _TAIL_RE.fullmatch(tail) else None,
                chat_tail=chat if isinstance(chat, str) and _CHAT_TAIL_RE.fullmatch(chat) else None,
                changed=_moment(entry.get("changed")),
                in_use=entry.get("in_use") is True,
                problem=entry.get("problem") is not None,
            )
        )
    return rows


def _moment(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def chat_ok(value: str) -> bool:
    return value == "" or check_chat_id(value)


class SettingTickets:
    """One-time confirmations, each bound to an action ("set" or "clear"), a kind and whether it
    replaces a key that is set. Thread-safe. The same rules as ``backtide.web.rewind.Tickets``."""

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
        self._open: list[tuple[str, str, str, bool, datetime]] = []
        self._spent: list[tuple[str, datetime]] = []
        self._lock = threading.Lock()

    def issue(self, action: str, kind: str, *, replacing: bool = False) -> str:
        ticket = secrets.token_urlsafe(TOKEN_BYTES)
        with self._lock:
            self._open.append((ticket, action, kind, replacing, self._clock() + self._lifetime))
            del self._open[: max(0, len(self._open) - self._limit)]
        return ticket

    def redeem(self, given: str, action: str, kind: str) -> tuple[Redeemed, bool]:
        """(OK, replacing) for an open ticket of ``action`` on ``kind`` in time; it is spent
        here whenever it matches an open one, also when it is for something else or too old
        (then INVALID). SPENT for one already spent that would not have expired yet."""
        now = self._clock()
        with self._lock:
            self._spent = [(t, until) for t, until in self._spent if now < until]
            for index, (ticket, bound, bound_kind, replacing, expires) in enumerate(self._open):
                if token_matches(given, ticket):
                    del self._open[index]
                    self._spent.append((ticket, expires))
                    del self._spent[: max(0, len(self._spent) - self._limit)]
                    good = bound == action and bound_kind == kind and now < expires
                    return (Redeemed.OK if good else Redeemed.INVALID), replacing
            if any(token_matches(given, ticket) for ticket, _ in self._spent):
                return Redeemed.SPENT, False
        return Redeemed.INVALID, False


__all__ = [
    "ACTIONS",
    "TELEGRAM",
    "ControlSettings",
    "SecretView",
    "SettingTickets",
    "SettingsClient",
    "chat_ok",
    "views",
]
