"""The book of held requests, in backtide's memory (T10-2). No I/O; the clock is injected.

Design: docs/32-diseno-t10-puerta.md, sections 6 and 7. ``ProxyChannel`` owns one book per
channel connection (the fingerprint key is per connection too) and records what happens in the
black box; the book only keeps the state:

- **A hold** is born with its ``gate/held`` (``open``, then ``recorded``) and lives 5 min from
  then (``life``); a retry with the same fingerprint joins it (``join``: no new event, no new
  alert) and never extends that life. Its ``event`` is the ``net/request`` recorded if the yes
  lets it out: the one of the request in the proxy's slot. A retry that joins while one waits
  is a twin with no slot, so it never replaces it (security review of T10-2, M2).
  ``connected`` counts the attempts the proxy holds with their connection open: each hold ack
  is answered by the proxy with exactly one ``released`` or ``hold_left`` (unless a deny
  came), so the count is exact.
- **A yes is spent once.** With a request connected, the hold is ``releasing`` (backtide sent
  ``decision allow``) until the proxy says ``released`` (spent: gone). If it says ``hold_left``
  instead and nothing else waits, the yes becomes a **preapproval**: the next identical request
  passes, once, within 10 min. With nobody connected the yes is a preapproval at once.
- **A no is remembered** 10 min (``rejected``), and so is an expiry: the same request is refused
  without asking again.
- **A pause or a rewind** (``reject_open``) rejects what is open, drops the preapprovals, and
  marks the yes being released (``frozen``): if the proxy says ``hold_left`` for it afterwards,
  it is dropped, never kept as a preapproval for the agent's next request (review, B2).
- **Caps:** at most ``max_open`` holds open (``open`` and ``releasing``); past it a request is
  refused (``hold_full``) and counted for a ``gate/flood`` at most every ``flood_every`` s.
- **What a restart loses only gave leave** (holds, preapprovals, rejections): ``close_all`` ends
  it all, failing closed. What must last (what was held, who approved, what expired) is in the
  black box; ``stale_holds`` finds the holds a killed backtide left open there.
"""

import re
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from backtide.snapshots import utc_now

HOLD_ID_RE = re.compile(r"h-[0-9a-f]{12}", re.ASCII)
STALE_WINDOW = timedelta(minutes=15)  # what a restart looks back at (docs/32, section 6)
CLOSING = frozenset({"approved", "rejected", "expired"})
EXPIRY_MARGIN = 2.0  # seconds: backtide looks at the holds every second (proxy_channel's tick)


@dataclass(frozen=True)
class HoldTimings:
    """docs/32, decision 1 and the caps of section 6 (the VM tests shorten them)."""

    life: float = 300.0  # an open hold, from its gate/held
    wait: float = 90.0  # a held request keeps its connection open this long at most
    preapproval: float = 600.0  # a yes with nobody waiting
    remember: float = 600.0  # a rejection or an expiry
    retry_after: int = 30  # the Retry-After of "pending"
    max_open: int = 20
    flood_every: float = 10.0


class State(StrEnum):
    OPEN = "open"  # waiting for the person
    RELEASING = "releasing"  # approved, the proxy is letting the connected request go
    PREAPPROVED = "preapproved"  # approved: the next identical request passes, once


class HoldStatus(StrEnum):
    """What a decision did (the control socket's ``outcome``)."""

    RELEASED = "released"  # approved: the waiting request goes out now, once
    PREAPPROVED = "preapproved"  # approved: nobody waited; the next identical request passes
    REJECTED = "rejected"
    UNKNOWN = "unknown"  # no open hold with that id (decided, expired, or a restart)
    FAILED = "failed"  # the approval could not be recorded, so it was not given
    PAUSED = "paused"  # the agent is paused or being rewound: nothing is approved meanwhile


HOLD_MESSAGES = {
    HoldStatus.RELEASED: "Aprobada: la petición retenida sale ahora, una sola vez.",
    HoldStatus.PREAPPROVED: (
        "Aprobada: el agente ya no estaba esperando. Si repite exactamente esa petición en los "
        "próximos 10 minutos, sale una vez."
    ),
    HoldStatus.REJECTED: (
        "Rechazada: la petición no sale. Si el agente la repite en los próximos 10 minutos, se "
        "rechaza sin volver a preguntar."
    ),
    HoldStatus.UNKNOWN: (
        "No hay ninguna petición retenida abierta con ese identificador: puede que ya se "
        "decidiera, que caducara (5 minutos sin respuesta) o que backtide o el proxy se "
        "reiniciaran. Mira `backtide retenidas`."
    ),
    HoldStatus.FAILED: (
        "No se ha podido grabar la aprobación en la caja negra, así que no se aprueba: la "
        "petición sigue retenida."
    ),
    HoldStatus.PAUSED: (
        "El agente está pausado o se está rebobinando, así que no se aprueba nada: la petición "
        "sigue retenida. Usa /seguir (o `backtide seguir`) y vuelve a aprobarla, o recházala."
    ),
}


@dataclass(frozen=True)
class HoldOutcome:
    status: HoldStatus
    hold_id: str

    @property
    def message(self) -> str:
        return HOLD_MESSAGES[self.status]


@dataclass(eq=False)
class Hold:
    hold_id: str
    fp: str
    risk: int
    reason: str
    event: dict[str, Any]  # the struck net/request of the attempt in the proxy's slot
    created: float
    expires: float
    expires_at: str  # the same moment on the wall clock, for the black box
    seq: int | None = None  # its gate/held
    connected: int = 0
    state: State = State.OPEN
    until: float | None = None  # a preapproval's end
    frozen: bool = False  # a pause or a rewind came while it was releasing: no preapproval

    @property
    def live(self) -> bool:
        return self.state is not State.PREAPPROVED


def _new_id() -> str:
    return f"h-{secrets.token_hex(6)}"


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class HoldBook:
    def __init__(
        self,
        timings: HoldTimings | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], datetime] = utc_now,
        new_id: Callable[[], str] = _new_id,
    ) -> None:
        self.timings = timings if timings is not None else HoldTimings()
        self._clock = clock
        self._wall = wall
        self._new_id = new_id
        self._holds: dict[str, Hold] = {}  # by hold id, in the order they were made
        self._by_fp: dict[str, Hold] = {}  # the open, releasing or preapproved hold of each fp
        self._rejected: dict[str, float] = {}  # fp -> until when it is refused without asking
        self._full = 0
        self._full_since: float | None = None
        self._last_flood = float("-inf")

    # Lookups

    def get(self, hold_id: str) -> Hold | None:
        return self._holds.get(hold_id)

    def live(self, fp: str) -> Hold | None:
        """The open (or releasing) hold of ``fp``: a request with it joins."""
        hold = self._by_fp.get(fp)
        return hold if hold is not None and hold.live else None

    def preapproved(self, fp: str) -> bool:
        hold = self._by_fp.get(fp)
        if hold is None or hold.state is not State.PREAPPROVED:
            return False
        if hold.until is not None and self._clock() >= hold.until:
            self._drop(hold)
            return False
        return True

    def rejected(self, fp: str) -> bool:
        until = self._rejected.get(fp)
        if until is None:
            return False
        if self._clock() >= until:
            del self._rejected[fp]
            return False
        return True

    def pending(self) -> list[Hold]:
        """The holds waiting for the person, oldest first."""
        return [hold for hold in self._holds.values() if hold.state is State.OPEN]

    def wait_ms(self, hold: Hold, hint_s: int | None = None) -> int:
        """How long the proxy keeps a request of ``hold`` connected: the least of the wait, its
        client's own (``hint_s``, a translator's) and what is left of the hold's life plus
        EXPIRY_MARGIN (so a request that waits when the hold expires hears "expired", 403,
        rather than a last "pending")."""
        seconds = min(self.timings.wait, hint_s if hint_s is not None else self.timings.wait)
        seconds = min(seconds, max(0.0, hold.expires - self._clock()) + EXPIRY_MARGIN)
        return int(seconds * 1000)

    # A hold's life

    def open(self, fp: str, *, risk: int, reason: str, event: dict[str, Any]) -> Hold | None:
        """A new hold for ``fp`` (not yet recorded: ``recorded`` or ``discard``), or None when
        ``max_open`` are open already (counted for the next ``gate/flood``)."""
        if sum(1 for hold in self._holds.values() if hold.live) >= self.timings.max_open:
            self._full += 1
            if self._full_since is None:
                self._full_since = self._clock()
            return None
        hold_id = self._new_id()
        while hold_id in self._holds:
            hold_id = self._new_id()
        now = self._clock()
        hold = Hold(
            hold_id=hold_id,
            fp=fp,
            risk=risk,
            reason=reason,
            event=event,
            created=now,
            expires=now + self.timings.life,
            expires_at=_iso(self._wall() + timedelta(seconds=self.timings.life)),
        )
        self._holds[hold_id] = hold
        self._by_fp[fp] = hold
        return hold

    def recorded(self, hold: Hold, seq: int) -> None:
        """Its gate/held is in the black box: the request that made it waits on it."""
        hold.seq = seq
        hold.connected += 1

    def discard(self, hold: Hold) -> None:
        """Its gate/held could not be recorded: it never was."""
        self._drop(hold)

    def join(self, hold: Hold, event: dict[str, Any]) -> None:
        """Another request with the same fingerprint waits on ``hold``. Its event is kept only
        when no other request is connected: then it is the one that takes the proxy's slot (a
        twin of a request that waits gets none, and lets go at once)."""
        if hold.connected == 0:
            hold.event = event
        hold.connected += 1

    def spend(self, fp: str) -> Hold | None:
        """Use the preapproval of ``fp`` (once): the hold, gone, or None."""
        if not self.preapproved(fp):
            return None
        hold = self._by_fp[fp]
        self._drop(hold)
        return hold

    def approve(self, hold_id: str) -> Hold | None:
        """The open hold ``hold_id``, to approve (then ``release`` or ``preapprove``)."""
        hold = self._holds.get(hold_id)
        if hold is None or hold.state is not State.OPEN or self._clock() >= hold.expires:
            return None
        return hold

    def release(self, hold: Hold) -> None:
        """backtide sent ``decision allow``: until ``released`` or ``hold_left``."""
        hold.state = State.RELEASING

    def preapprove(self, hold: Hold) -> None:
        hold.state = State.PREAPPROVED
        hold.until = self._clock() + self.timings.preapproval

    def reject(self, hold_id: str) -> Hold | None:
        """An open hold or an unused preapproval, ended and remembered. None if there is none
        (or it is being released: too late)."""
        hold = self._holds.get(hold_id)
        if hold is None or hold.state is State.RELEASING:
            return None
        self._end(hold)
        return hold

    def released(self, hold_id: str) -> Hold | None:
        """The proxy let the approved request go: the yes is spent."""
        hold = self._holds.get(hold_id)
        if hold is None or hold.state is not State.RELEASING:
            return None
        self._drop(hold)
        return hold

    def left(self, hold_id: str) -> Hold | None:
        """The proxy no longer holds one request of ``hold_id`` (its client left, it waited, or
        there was no slot). A yes that found nobody becomes a preapproval."""
        hold = self._holds.get(hold_id)
        if hold is None or hold.state is State.PREAPPROVED:
            return None
        hold.connected = max(0, hold.connected - 1)
        if hold.state is State.RELEASING and hold.connected == 0:
            if hold.frozen:
                self._drop(hold)  # paused after the yes: it does not wait for the agent
            else:
                self.preapprove(hold)
        return hold

    def due(self) -> list[Hold]:
        """The open holds whose 5 min are over (ended and remembered: the caller records
        ``gate/expired`` and denies them), after dropping lapsed leave of every kind."""
        now = self._clock()
        expired = []
        for hold in list(self._holds.values()):
            if hold.state is State.OPEN and now >= hold.expires:
                self._end(hold)
                expired.append(hold)
            elif hold.state is State.PREAPPROVED and hold.until is not None and now >= hold.until:
                self._drop(hold)
            elif hold.state is State.RELEASING and now >= hold.expires + self.timings.wait:
                # The proxy never said released nor hold_left (it cannot be: the channel ends
                # first). It is not kept forever, and it gives no more leave.
                self._drop(hold)
        for fp, until in list(self._rejected.items()):
            if now >= until:
                del self._rejected[fp]
        return expired

    def close_all(self) -> list[Hold]:
        """Everything ends (the channel is gone, or backtide stops): the open and releasing
        holds are returned for their ``gate/expired``; preapprovals and rejections are
        forgotten (they were tied to this connection's fingerprint key)."""
        ended = [hold for hold in self._holds.values() if hold.live]
        self._holds.clear()
        self._by_fp.clear()
        self._rejected.clear()
        return ended

    def reject_open(self) -> list[Hold]:
        """A pause or a rewind: every open hold rejected (and remembered), the unused
        preapprovals dropped (a leave given before it does not survive it), and the yes being
        released marked so that it never becomes one."""
        rejected = []
        for hold in list(self._holds.values()):
            if hold.state is State.OPEN:
                self._end(hold)
                rejected.append(hold)
            elif hold.state is State.PREAPPROVED:
                self._drop(hold)
            elif hold.state is State.RELEASING:
                hold.frozen = True
        return rejected

    def flood(self) -> tuple[int, int] | None:
        """``(count, window_s)`` of the requests refused for the cap, when a ``gate/flood`` is
        due (one every ``flood_every`` s at most), else None."""
        now = self._clock()
        if not self._full or now - self._last_flood < self.timings.flood_every:
            return None
        since = self._full_since if self._full_since is not None else now
        count, window = self._full, max(1, int(now - since))
        self._full, self._full_since, self._last_flood = 0, None, now
        return count, window

    # Helpers

    def _drop(self, hold: Hold) -> None:
        self._holds.pop(hold.hold_id, None)
        if self._by_fp.get(hold.fp) is hold:
            del self._by_fp[hold.fp]

    def _end(self, hold: Hold) -> None:
        self._drop(hold)
        self._rejected[hold.fp] = self._clock() + self.timings.remember


def stale_holds(events: Iterable[tuple[str, str, datetime]], *, now: datetime) -> list[str]:
    """The holds a backtide that died left open: ``gate/held`` of the last 15 min with no
    ``gate/approved``, ``gate/rejected`` nor ``gate/expired`` after them. ``events`` are
    ``(action, hold_id, ts)`` of the ``gate`` events, in the black box's order; the result is
    in the order they were held."""
    since = now - STALE_WINDOW
    held: dict[str, datetime] = {}
    closed: set[str] = set()
    for action, hold_id, ts in events:
        if not isinstance(hold_id, str) or not HOLD_ID_RE.fullmatch(hold_id):
            continue
        if action == "held" and ts >= since:
            held.setdefault(hold_id, ts)
        elif action in CLOSING:
            closed.add(hold_id)
    return [hold_id for hold_id, _ in sorted(held.items(), key=lambda item: item[1])
            if hold_id not in closed]  # fmt: skip
