"""Approving held requests from the web (T10-5, docs/32 section 11, decisions 9 and 10).

The web never decides on its own. It asks the running service through its control socket, as
`backtide aprobar` does, with ``via: web`` so the black box says where the yes came from:
``holds`` (what waits), ``decide`` (approve or reject), ``trust`` ("aprobar y confiar en este
destinatario", decision 9: only from here), ``trusted`` / ``untrust`` (the list of recipients
trusted from here, and taking one out), and ``batches`` / ``end_batch`` (the active batch rules,
and revoking one; making a batch stays in Telegram, with its two taps).

Writes are explicit (decision 10): only with ``backtide web --aprobar``. Without it the page lists
what waits from the black box (the ``gate/held`` with no end, ``box_holds``), the buttons are
disabled with a note on how to turn them on, nothing asks the service and the POST does not exist.
Who can: the service's own user, like the rewind (the socket is 0600 and answers only its uid),
or the web's group through the service's narrow socket (``--socket-web``, T12c).

What comes back is checked field by field (``held_request``) before it reaches a page: ids by
their shape, risks in 0..3, times parsed, texts cut. The agent's texts (recipients, subject, the
first lines, the request) stay the agent's: the templates mark them as such and show them with
``visible`` (escaped, invisible characters made visible), never as markup. Our words (what it
does, the notes) come from ``backtide.gate.phrase``, built from closed tables.

Confirmations (``DecisionTickets``): every change has a page of its own (GET, changes nothing)
with a one-time ticket bound to that verb and that id: a ticket to reject never approves, one for
this hold never decides another, and one for a hold lives no longer than the hold. Only a POST
that carries it, with the session's CSRF token, changes anything; "confiar" also needs its box
ticked ("confirmo"). Same rules as ``backtide.web.rewind.Tickets``.
"""

import os
import re
import secrets
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import Event, Source
from backtide.gate.phrase import action, note_texts
from backtide.gate.protocol import MAX_RECIPIENT_CHARS
from backtide.service.control import (
    ControlError,
    PeerCredentials,
    ask_decide,
    ask_end_batch,
    ask_holds,
    ask_list,
    ask_trust,
    ask_untrust,
    peer_credentials,
)
from backtide.service.holds import BATCH_ID_RE, CLOSING, HOLD_ID_RE, STALE_WINDOW
from backtide.service.trust import TRUST_ID_RE
from backtide.web.agents import MAIN_SLUG, PendingRequest
from backtide.web.rewind import (
    CONFIRM_SECONDS,
    MAX_TICKETS,
    WAIT_FOR_SERVICE,
    Availability,
    Redeemed,
    availability_of,
)
from backtide.web.security import TOKEN_BYTES, token_matches

# The verbs of the form, each with the shape of the id it acts on.
APPROVE, REJECT, TRUST, REVOKE, FORGET = "aprobar", "rechazar", "confiar", "revocar", "olvidar"
VERBS: dict[str, re.Pattern[str]] = {
    APPROVE: HOLD_ID_RE,
    REJECT: HOLD_ID_RE,
    TRUST: HOLD_ID_RE,
    REVOKE: BATCH_ID_RE,
    FORGET: TRUST_ID_RE,
}
SHOWN_RECIPIENTS = 5
MAX_TEXT = 300
BOX_ROWS = 5000  # how far back the black box is read for what waits (by primary key only)
_MAIL = frozenset({"gmail", "graph_mail"})
_MESSAGING = frozenset({"telegram", "slack", "discord"})


def id_fits(verb: str, subject: str) -> bool:
    pattern = VERBS.get(verb)
    return pattern is not None and isinstance(subject, str) and bool(pattern.fullmatch(subject))


class Approver(Protocol):
    """What the app needs. Every call but ``availability`` raises the control socket's errors
    (ControlUnavailable, ControlOutcomeUnknown, ControlError)."""

    enabled: bool

    def availability(self) -> Availability: ...

    def holds(self) -> list[dict[str, Any]]: ...

    def decide(self, hold_id: str, verdict: str) -> dict[str, Any]: ...

    def trust(self, hold_id: str) -> dict[str, Any]: ...

    def trusted(self) -> list[dict[str, Any]]: ...

    def untrust(self, trust_id: str) -> dict[str, Any]: ...

    def batches(self) -> list[dict[str, Any]]: ...

    def end_batch(self, rule_id: str) -> dict[str, Any]: ...


class ControlApprover:
    """The real one: the control socket at ``path`` (``<state_dir>/control.sock``)."""

    def __init__(
        self,
        path: Path,
        *,
        enabled: bool = False,
        wait: float = WAIT_FOR_SERVICE,
        peer: PeerCredentials = peer_credentials,
        euid: Callable[[], int] = os.geteuid,
        server_uid: int | None = None,
        egid: Callable[[], int] = os.getegid,
    ) -> None:
        self._path = Path(path)
        self.enabled = enabled
        self._wait = wait
        self._peer = peer
        self._euid = euid
        self._server_uid = server_uid  # the narrow socket's (T12c), else the control socket
        self._egid = egid

    def availability(self) -> Availability:
        return availability_of(
            self._path,
            enabled=self.enabled,
            euid=self._euid,
            server_uid=self._server_uid,
            egid=self._egid,
        )

    def _require(self) -> dict[str, Any]:
        if not self.enabled:  # the app never gets here without READY; still, never by accident
            raise ControlError("esta web no se lanzó con --aprobar")
        return {"wait": self._wait, "peer": self._peer, "server_uid": self._server_uid}

    def holds(self) -> list[dict[str, Any]]:
        return ask_holds(self._path, **self._require())

    def decide(self, hold_id: str, verdict: str) -> dict[str, Any]:
        return ask_decide(self._path, hold_id, verdict, via="web", **self._require())

    def trust(self, hold_id: str) -> dict[str, Any]:
        return ask_trust(self._path, hold_id, **self._require())

    def trusted(self) -> list[dict[str, Any]]:
        return ask_list(self._path, "trusted", **self._require())

    def untrust(self, trust_id: str) -> dict[str, Any]:
        return ask_untrust(self._path, trust_id, via="web", **self._require())

    def batches(self) -> list[dict[str, Any]]:
        return ask_list(self._path, "batches", **self._require())

    def end_batch(self, rule_id: str) -> dict[str, Any]:
        return ask_end_batch(self._path, rule_id, via="web", **self._require())


# -- what the page shows of a hold -----------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _texts(values: object, limit: int = 200, count: int = SHOWN_RECIPIENTS) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    return tuple(_text(item, limit) for item in values[:count] if isinstance(item, str))


def _moment(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def _kind(translator: object, effect: object, reason: object) -> str:
    if effect == "delete" or reason == "delete":
        return "delete"
    if effect in ("send", "forward"):
        if translator in _MAIL:
            return "email"
        if translator in _MESSAGING:
            return "message"
    return "other"


def held_request(
    raw: Mapping[str, Any], *, now: datetime, agent: str = MAIN_SLUG, life: float = 300.0
) -> PendingRequest | None:
    """A hold as the service lists it (``ProxyChannel.pending``: summary and ``_web_fields``)
    or as ``box_holds`` rebuilds it, checked; None for anything that does not fit."""
    hold_id = raw.get("hold_id")
    risk = raw.get("risk")
    if not isinstance(hold_id, str) or not HOLD_ID_RE.fullmatch(hold_id):
        return None
    if type(risk) is not int or risk not in (0, 1, 2, 3):
        return None
    expires = _moment(raw.get("expires_at"))
    if expires is None:
        left = raw.get("expires_in_s")
        if type(left) is not int or left < 0:
            return None
        expires = now + timedelta(seconds=left)
    held = _moment(raw.get("held_at")) or expires - timedelta(seconds=life)
    if held >= expires:
        held = expires - timedelta(seconds=1)
    view = raw.get("view") if isinstance(raw.get("view"), Mapping) else None
    reason = _text(raw.get("reason"), 40)
    if view is not None:
        reading = {
            "translator": view.get("translator"),
            "effect": view.get("effect"),
            "notes": [n for n in view.get("notes") or [] if isinstance(n, str)],
            "cut": view.get("cut") is True,
        }
        ours = action(reading)
        notes = tuple(note_texts(reading))
        ours_en = action(reading, "en")
        notes_en = tuple(note_texts(reading, "en"))
        recipients = _texts(view.get("recipients"), MAX_RECIPIENT_CHARS)
        total = view.get("recipients_total")
        more = max(0, total - len(recipients)) if type(total) is int else 0
        subject = _text(view.get("subject"), 200)
        lines = _text(view.get("first_lines"), MAX_TEXT)
        target = ", ".join(recipients) or _text(view.get("target"), 200)
        request = ""
        kind = _kind(view.get("translator"), view.get("effect"), reason)
        attachments = tuple(
            _text(item.get("name"), 100) or "?"
            for item in (view.get("attachments") or [])[:SHOWN_RECIPIENTS]
            if isinstance(item, Mapping)
        )
        reply_to = _texts(view.get("reply_to"), MAX_RECIPIENT_CHARS)
        translator = view.get("translator") if isinstance(view.get("translator"), str) else ""
        trust_off = _trust_off(translator, view.get("effect"), recipients)
    else:
        ours, notes, recipients, more = "", (), (), 0
        ours_en, notes_en = "", ()
        subject = lines = translator = trust_off = ""
        attachments, reply_to = (), ()
        request = " ".join(
            part
            for part in (
                _text(raw.get("method"), 16),
                _text(raw.get("host"), 200) + _text(raw.get("path"), 400),
            )
            if part
        )
        target = _text(raw.get("host"), 200) or "?"
        kind = _kind(None, None, reason)
    seq = raw.get("seq")
    batches = tuple(b for b in raw.get("batches") or [] if b in ("recipient", "kind"))
    return PendingRequest(
        id=hold_id,
        agent=agent,
        kind=kind,
        target=target,
        reason=reason or "unknown",
        risk=risk,
        held_at=held,
        expires_at=expires,
        detail=subject or lines,
        action=ours,
        notes=notes,
        action_en=ours_en,
        notes_en=notes_en,
        recipients=recipients,
        more_recipients=more,
        reply_to=reply_to,
        subject=subject,
        lines=lines,
        attachments=attachments,
        request=request,
        seq=seq if type(seq) is int and seq > 0 else None,
        waiting=raw.get("waiting") is True,
        batches=batches,
        trustable=raw.get("trustable") is True,
        translator=translator[:20],
        trust_off=trust_off,
    )


def _trust_off(translator: str, effect: object, recipients: Sequence[str]) -> str:
    """Why "aprobar y confiar" is not offered, when it is worth a word (final review of T10):
    "mail" (finding 2: not until the owner's accounts exist) or "name" (finding 9: a Telegram
    chat by its @name is a public channel or group, and a name can pass to another chat)."""
    if effect not in ("send", "change"):
        return ""
    if translator in _MAIL:
        return "mail"
    if translator == "telegram" and len(recipients) == 1 and recipients[0].startswith("@"):
        return "name"
    return ""


def trust_note(hold: PendingRequest) -> str:
    """Our note on who reads a Telegram chat the person is about to trust (finding 9): "group"
    for a group (a negative id), "channel" for a supergroup or a channel (-100...); "" for a
    person's chat or another API."""
    if hold.translator != "telegram" or len(hold.recipients) != 1:
        return ""
    chat = hold.recipients[0]
    if chat.startswith("-100"):
        return "channel"
    return "group" if chat.startswith("-") else ""


def same_recipient(hold: PendingRequest, others: Sequence[PendingRequest]) -> int:
    """How many other open holds name the recipient that trusting ``hold`` would trust: they
    are decided apart (final review of T10, finding 1)."""
    if len(hold.recipients) != 1:
        return 0
    return sum(
        1
        for other in others
        if other.id != hold.id
        and other.translator == hold.translator
        and hold.recipients[0] in other.recipients
    )


def box_holds(events: Sequence[Event], now: datetime) -> list[dict[str, Any]]:
    """The holds that still wait, rebuilt from the black box (``events``: its newest rows, newest
    first): a ``gate/held`` of the last 15 minutes with no ``gate/approved``, ``rejected`` nor
    ``expired`` after it, and not past its ``expires_at``. What the web shows without
    ``--aprobar``: the service is not asked, and nothing here can be decided."""
    since = now - STALE_WINDOW
    closed: set[str] = set()
    found: list[dict[str, Any]] = []
    for event in events:  # newest first: an end is seen before its hold
        if event.source is not Source.GATE:
            continue
        hold_id = event.details.get("hold_id")
        if not isinstance(hold_id, str):
            continue
        if event.action in CLOSING:
            closed.add(hold_id)
            continue
        if event.action != "held" or hold_id in closed:
            continue
        held = _moment(event.ts) or now
        expires = _moment(event.details.get("expires_at"))
        if held < since or expires is None or expires <= now:
            continue
        found.append(
            {
                "hold_id": hold_id,
                "risk": event.risk,
                "reason": event.details.get("reason"),
                "method": event.details.get("method"),
                "host": event.details.get("host"),
                "path": event.details.get("path"),
                "held_at": event.ts,
                "expires_at": event.details.get("expires_at"),
                "seq": event.seq,
                "view": _box_view(event.details.get("reading")),
            }
        )
    return list(reversed(found))


def box_partial(events: Sequence[Event], now: datetime) -> bool:
    """Whether ``box_holds`` may have missed holds (final review of T10, finding 7): it read
    ``BOX_ROWS`` rows (by primary key: the box has no index by source) and the oldest of them is
    newer than the 15 minutes a hold may still wait. The page then says "puede que haya más"."""
    if len(events) < BOX_ROWS:
        return False
    oldest = _moment(events[-1].ts)
    return oldest is None or oldest > now - STALE_WINDOW


def _box_view(reading: object) -> dict[str, Any] | None:
    """The recorded reading of a gate/held in the shape of ``ProxyChannel._view``."""
    if not isinstance(reading, Mapping):
        return None
    recipients = [r for r in reading.get("recipients") or [] if isinstance(r, str)]
    attachments = [a for a in reading.get("attachments") or [] if isinstance(a, Mapping)]
    return {
        "translator": reading.get("translator"),
        "effect": reading.get("effect"),
        "notes": list(reading.get("notes") or []),
        "cut": reading.get("cut") is True,
        "recipients": recipients[:SHOWN_RECIPIENTS],
        "recipients_total": len(recipients),
        "reply_to": list(reading.get("reply_to") or [])[:SHOWN_RECIPIENTS],
        "subject": reading.get("subject"),
        "first_lines": reading.get("first_lines"),
        "target": reading.get("target"),
        "attachments": attachments[:SHOWN_RECIPIENTS],
        "attachments_total": len(attachments),
    }


def held_event(events: Sequence[Event], hold_id: str) -> Event | None:
    """The ``gate/held`` of ``hold_id`` among ``events`` ("Ver" reads its details)."""
    for event in events:
        if (event.source, event.action) == (Source.GATE, "held") and event.details.get(
            "hold_id"
        ) == hold_id:
            return event
    return None


@dataclass(frozen=True)
class Detail:
    """ "Ver": what the black box keeps of a hold (the 2 KiB excerpt, every recipient and
    attachment), checked. Everything but ``request`` (method, host and path) is the agent's."""

    request: str
    recipients: tuple[str, ...]
    reply_to: tuple[str, ...]
    sender: str
    subject: str
    lines: str
    target: str
    attachments: tuple[tuple[str, str, object], ...]  # name, type, size
    excerpt: str
    excerpt_cut: bool
    body_size: object


def detail_of(event: Event) -> Detail:
    details = event.details
    reading = details.get("reading") if isinstance(details.get("reading"), Mapping) else {}
    body = details.get("body") if isinstance(details.get("body"), Mapping) else {}
    excerpt = body.get("excerpt") if isinstance(body, Mapping) else None
    attachments = tuple(
        (_text(a.get("name"), 100) or "?", _text(a.get("type"), 80) or "?", a.get("size"))
        for a in (reading.get("attachments") or [])[:32]
        if isinstance(a, Mapping)
    )
    return Detail(
        request=" ".join(
            p
            for p in (
                _text(details.get("method"), 16),
                _text(details.get("host"), 200) + _text(details.get("path"), 2048),
            )
            if p
        ),
        recipients=_texts(reading.get("recipients"), MAX_RECIPIENT_CHARS, 64),
        reply_to=_texts(reading.get("reply_to"), MAX_RECIPIENT_CHARS, 64),
        sender=_text(reading.get("sender"), 200),
        subject=_text(reading.get("subject"), 200),
        lines=_text(reading.get("first_lines"), MAX_TEXT),
        target=_text(reading.get("target"), 200),
        attachments=attachments,
        excerpt=excerpt[:2048] if isinstance(excerpt, str) else "",
        excerpt_cut=isinstance(body, Mapping) and body.get("excerpt_truncated") is True,
        body_size=body.get("size") if isinstance(body, Mapping) else None,
    )


# -- the lists: batches and trusted recipients ------------------------------------------------


@dataclass(frozen=True)
class BatchView:
    rule_id: str
    scope: str  # "recipient" or "kind"
    translator: str | None
    effect: str | None
    recipients: tuple[str, ...]  # the agent's
    request: str  # method host route, without a translator (the agent's)
    until: datetime | None
    uses: int


def batch_views(raw: Sequence[Mapping[str, Any]]) -> list[BatchView]:
    views = []
    for item in raw:
        rule_id = item.get("rule_id")
        if not isinstance(rule_id, str) or not BATCH_ID_RE.fullmatch(rule_id):
            continue
        uses = item.get("uses")
        translator = item.get("translator")
        views.append(
            BatchView(
                rule_id=rule_id,
                scope="recipient" if item.get("scope") == "recipient" else "kind",
                translator=translator if isinstance(translator, str) else None,
                effect=_text(item.get("effect"), 16) or None,
                recipients=_texts(item.get("recipients"), MAX_RECIPIENT_CHARS),
                request=" ".join(
                    p
                    for p in (
                        _text(item.get("method"), 16),
                        _text(item.get("host"), 200) + _text(item.get("route"), 400),
                    )
                    if p
                ),
                until=_moment(item.get("until")),
                uses=uses if type(uses) is int and uses >= 0 else 0,
            )
        )
    return views


@dataclass(frozen=True)
class TrustView:
    trust_id: str
    translator: str
    recipient: str  # the agent's text once: shown as such
    added_at: datetime | None
    by: str


def trust_views(raw: Sequence[Mapping[str, Any]]) -> list[TrustView]:
    views = []
    for item in raw:
        trust_id, translator = item.get("trust_id"), item.get("translator")
        recipient = item.get("recipient")
        if not isinstance(trust_id, str) or not TRUST_ID_RE.fullmatch(trust_id):
            continue
        if not isinstance(translator, str) or not isinstance(recipient, str):
            continue
        views.append(
            TrustView(
                trust_id=trust_id,
                translator=_text(translator, 20),
                recipient=_text(recipient, MAX_RECIPIENT_CHARS),
                added_at=_moment(item.get("added_at")),
                by=_text(item.get("by"), 16),
            )
        )
    return views


# -- the confirmations -----------------------------------------------------------------------


class DecisionTickets:
    """One-time confirmations, each bound to a verb and an id, living ``CONFIRM_SECONDS`` or
    until ``until`` (the hold's end), whichever comes first. Thread-safe."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        *,
        lifetime: timedelta = timedelta(seconds=CONFIRM_SECONDS),
        limit: int = MAX_TICKETS * 2,
    ) -> None:
        self._clock = clock
        self._lifetime = lifetime
        self._limit = limit
        self._open: list[tuple[str, str, str, datetime]] = []
        self._spent: list[tuple[str, datetime]] = []
        self._lock = threading.Lock()

    def issue(self, verb: str, subject: str, *, until: datetime | None = None) -> str:
        ticket = secrets.token_urlsafe(TOKEN_BYTES)
        expires = self._clock() + self._lifetime
        if until is not None:
            expires = min(expires, until)
        with self._lock:
            self._open.append((ticket, verb, subject, expires))
            del self._open[: max(0, len(self._open) - self._limit)]
        return ticket

    def redeem(self, given: str, verb: str, subject: str) -> Redeemed:
        """OK for an open ticket of ``verb`` on ``subject`` in time; a ticket that matches an
        open one is spent here whatever it was bound to (then INVALID). SPENT for one already
        spent that would not have expired yet."""
        now = self._clock()
        with self._lock:
            self._spent = [(t, until) for t, until in self._spent if now < until]
            for index, (ticket, bound, bound_to, expires) in enumerate(self._open):
                if token_matches(given, ticket):
                    del self._open[index]
                    self._spent.append((ticket, max(expires, now + timedelta(minutes=1))))
                    del self._spent[: max(0, len(self._spent) - self._limit)]
                    good = bound == verb and bound_to == subject and now < expires
                    return Redeemed.OK if good else Redeemed.INVALID
            if any(token_matches(given, ticket) for ticket, _ in self._spent):
                return Redeemed.SPENT
        return Redeemed.INVALID


__all__ = [
    "APPROVE",
    "FORGET",
    "REJECT",
    "REVOKE",
    "TRUST",
    "VERBS",
    "Approver",
    "BatchView",
    "ControlApprover",
    "DecisionTickets",
    "Detail",
    "TrustView",
    "batch_views",
    "box_holds",
    "detail_of",
    "held_event",
    "held_request",
    "box_partial",
    "id_fits",
    "same_recipient",
    "trust_note",
    "trust_views",
]
