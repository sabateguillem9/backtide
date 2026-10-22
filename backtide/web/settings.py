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
    ask_accept_prices,
    ask_budget,
    ask_clear_secret,
    ask_secrets,
    ask_set_budget,
    ask_set_secret,
    peer_credentials,
)
from backtide.service.prices import usd
from backtide.service.settings import KINDS, PROVIDERS, TELEGRAM, check_chat_id
from backtide.service.spend import check_cap
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
_DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
BUDGET = "tope"  # the Settings page's "kind" for the spending caps (T11)
PRICES = "precios"  # ... and for accepting the new prices that wait for the owner (T11, B3)
_PROVIDER_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", re.ASCII)
_MODEL_RE = re.compile(r"claude-[a-z]+-[0-9]{1,2}(?:-[0-9]{1,2})?", re.ASCII)
_PRICE_RE = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,8})?", re.ASCII)
_DIGEST_RE = re.compile(r"[0-9a-f]{16}", re.ASCII)


class SettingsClient(Protocol):
    """What the app needs. ``status``, ``set_secret`` and ``clear_secret`` raise the control
    socket's errors (ControlUnavailable, ControlOutcomeUnknown, ControlError)."""

    def availability(self) -> Availability: ...

    def status(self) -> dict[str, dict[str, Any]]: ...

    def set_secret(self, kind: str, value: str, chat_id: str | None) -> dict[str, Any]: ...

    def clear_secret(self, kind: str) -> dict[str, Any]: ...

    def set_budget(self, daily: str | None, monthly: str | None) -> dict[str, Any]: ...

    def accept_prices(self, digest: str) -> dict[str, Any]: ...


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

    def set_budget(self, daily: str | None, monthly: str | None) -> dict[str, Any]:
        """New spending caps (T11), as typed: the service checks them and records the change."""
        self._require()
        return ask_set_budget(
            self._path,
            daily_usd=daily,
            monthly_usd=monthly,
            via="web",
            wait=self._wait,
            peer=self._peer,
        )

    def accept_prices(self, digest: str) -> dict[str, Any]:
        """Accept the new prices waiting that the page showed (``digest``, T11 B3)."""
        self._require()
        return ask_accept_prices(
            self._path, digest=digest, via="web", wait=self._wait, peer=self._peer
        )


class SpendClient(Protocol):
    """What the panel and Settings read of the spending (T11). Raises the control socket's
    errors."""

    def availability(self) -> Availability: ...

    def spend(self) -> dict[str, Any]: ...


class ControlSpend:
    """The real one: the spending is read-only and holds no secret, so it is asked whenever the
    socket is the service's (``--ajustes`` is only needed to CHANGE the caps)."""

    def __init__(
        self,
        path: Path,
        *,
        wait: float = 2.0,
        peer: PeerCredentials = peer_credentials,
        euid: Callable[[], int] = os.geteuid,
    ) -> None:
        self._path = Path(path)
        self._wait = wait
        self._peer = peer
        self._euid = euid

    def availability(self) -> Availability:
        return socket_availability(self._path, enabled=True, euid=self._euid)

    def spend(self) -> dict[str, Any]:
        return ask_budget(self._path, wait=self._wait, peer=self._peer)


@dataclass(frozen=True)
class PendingPrice:
    """One new price waiting for the owner (B3), checked field by field."""

    model: str
    why: str  # "new_model" | "drop"
    input: str
    output: str
    old_input: str | None = None
    old_output: str | None = None


@dataclass(frozen=True)
class SpendView:
    """The spending as a page shows it, checked field by field (dollars with a comma)."""

    available: bool
    day_spent: str = ""
    day_cap: str = ""
    month_spent: str = ""
    month_cap: str = ""
    day_cap_plain: str = ""  # "5.00", to fill the form in
    month_cap_plain: str = ""
    blocked: str | None = None  # "day" | "month"
    prices_on: str | None = None  # the date of the last good table from Anthropic
    defaults_on: str | None = None
    pending: tuple[PendingPrice, ...] = ()  # B3: what waits for "Aceptar los precios nuevos"
    pending_digest: str | None = None
    # The providers of [proxy] that wait for their key: the agent cannot use them yet.
    waiting: tuple[str, ...] = ()


def spend_view(raw: object) -> SpendView | None:
    """``SpendClient.spend``'s reply, checked; None if it makes no sense."""
    if not isinstance(raw, dict):
        return None
    waiting = _waiting(raw.get("models_waiting"))
    if raw.get("available") is not True:
        return SpendView(False, waiting=waiting)
    try:
        day, month = raw["day"], raw["month"]
        amounts = [day["spent_micro"], day["cap_micro"], month["spent_micro"], month["cap_micro"]]
    except (KeyError, TypeError):
        return None
    if not all(type(a) is int and 0 <= a <= 10**15 for a in amounts):
        return None
    prices = raw.get("prices") if isinstance(raw.get("prices"), dict) else {}
    blocked = raw.get("blocked")
    return SpendView(
        True,
        day_spent=_money(amounts[0]),
        day_cap=_money(amounts[1]),
        month_spent=_money(amounts[2]),
        month_cap=_money(amounts[3]),
        day_cap_plain=usd(amounts[1]),
        month_cap_plain=usd(amounts[3]),
        blocked=blocked if blocked in ("day", "month") else None,
        prices_on=_day(prices.get("updated_on")),
        defaults_on=_day(prices.get("defaults_on")),
        waiting=waiting,
        **_pending(prices),
    )


def _waiting(raw: object) -> tuple[str, ...]:
    """The names of the providers that wait for their key, or none when any makes no sense."""
    if not isinstance(raw, list) or len(raw) > 32:
        return ()
    if not all(isinstance(name, str) and _PROVIDER_RE.fullmatch(name) for name in raw):
        return ()
    return tuple(dict.fromkeys(raw))


def _pending(prices: dict[str, Any]) -> dict[str, Any]:
    """The new prices waiting, or none at all when any of them does not make sense."""
    digest, rows = prices.get("pending_digest"), prices.get("pending")
    if not isinstance(rows, list) or not rows or not isinstance(digest, str):
        return {}
    if not _DIGEST_RE.fullmatch(digest) or len(rows) > 64:
        return {}
    found = []
    for row in rows:
        if not isinstance(row, dict) or row.get("why") not in ("new_model", "drop"):
            return {}
        model = row.get("model")
        values = [row.get(name) for name in ("input", "output", "old_input", "old_output")]
        if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
            return {}
        if not all(isinstance(v, str) and _PRICE_RE.fullmatch(v) for v in values[:2]):
            return {}
        if not all(
            v is None or (isinstance(v, str) and _PRICE_RE.fullmatch(v)) for v in values[2:]
        ):
            return {}
        found.append(PendingPrice(model, row["why"], *values))  # type: ignore[arg-type]
    return {"pending": tuple(found), "pending_digest": digest}


def digest_ok(value: str) -> bool:
    return bool(_DIGEST_RE.fullmatch(value))


def _money(micro: int) -> str:
    return usd(micro).replace(".", ",")


def _day(value: object) -> str | None:
    return value if isinstance(value, str) and _DAY_RE.fullmatch(value) else None


def cap_ok(value: str) -> bool:
    """Empty (keep it) or a cap ``check_cap`` takes. The service checks it again."""
    return value == "" or check_cap(value) is not None


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
    # A provider of [proxy] the agent cannot use until its key is set (none, or unusable).
    waiting: bool = False

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
                waiting=entry.get("waiting") is True,
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
    "BUDGET",
    "PRICES",
    "PendingPrice",
    "digest_ok",
    "ControlSpend",
    "SpendClient",
    "SpendView",
    "cap_ok",
    "spend_view",
    "TELEGRAM",
    "ControlSettings",
    "SecretView",
    "SettingTickets",
    "SettingsClient",
    "chat_ok",
    "views",
]
