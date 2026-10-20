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
- **Drafts** (T10-3): a hold may name the saved draft it sends or changes (``draft``:
  translator and draft reference, never the token). While one is open, releasing or preapproved,
  ``draft_open`` says so, and the gate holds any change to that draft: the text the person
  approves must not change before it goes out (docs/32, decision 12).
- **Batches** (T10-4, docs/32 section 10): a rule that lets more than one request pass, made
  from an open hold the person approves with it: "todo a este destinatario, esta sesión"
  (``RECIPIENT``: translator, account and recipients; 12 h at most) or "este tipo de acción, 1 h"
  (``KIND``: translator, account and effect; without a translator, method, host and route).
  Each hold carries its ``Scope`` (fields the proxy reads strictly, never the agent's texts);
  ``offers`` says which batches it may make, and ``batch_for`` which rule covers a request.
  Never a deletion, an administration, a forward, the unknown, risk 3, a secret seen, a cut or
  doubtful reading, a platform that fetches a URL or an inline message (decision 8 and the
  review of T10-3), nor a request of another account. Since the security review of T10-4: never
  an override header nor trailers (A1); a write without a translator is bound to the HMAC of
  its credential headers (M1); a recipient batch covers a Reply-To only among its recipients
  (M2); and every batch keeps its scheme and port (B3). At most ``max_batches`` at a time.
- **What a restart loses only gave leave** (holds, preapprovals, rejections, batches):
  ``close_all`` and ``end_batches`` end it all, failing closed. What must last (what was held,
  who approved, what expired) is in the black box; ``stale_holds`` finds the holds a killed
  backtide left open there.
"""

import re
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from backtide.gate.translate.base import normalize_trusted
from backtide.snapshots import utc_now

# translator and draft (``base.draft_ref``: a digest of the mailbox and the draft's id, so a
# refreshed token is the same draft; review of T10-3, M7)
DraftKey = tuple[str, str]

HOLD_ID_RE = re.compile(r"h-[0-9a-f]{12}", re.ASCII)
BATCH_ID_RE = re.compile(r"b-[0-9a-f]{8}", re.ASCII)
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
    # The retry_after of Telegram's "pending" (T10-5, docs/32 section 16): OpenClaw's Telegram
    # channel stops EVERY call of the bot for retry_after s after a 429 (its flood gate), the
    # owner's replies too; a short one keeps that stall short, and the held send still waits.
    telegram_retry_after: int = 2
    max_open: int = 20
    flood_every: float = 10.0
    batch_session: float = 12 * 3600.0  # "esta sesión": 12 h at most (decision 9)
    batch_hour: float = 3600.0  # "este tipo de acción, 1 h"
    max_batches: int = 10


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


class TrustStatus(StrEnum):
    """What "aprobar y confiar en este destinatario" did (T10-5, decision 9)."""

    TRUSTED = "trusted"  # the recipient is trusted now (or was), and the hold approved with it
    NOT_TRUSTABLE = "not_trustable"  # that hold may not make a trusted recipient
    UNKNOWN = "unknown"  # no open hold with that id
    PAUSED = "paused"  # the agent is paused or being rewound: nothing is approved meanwhile
    FAILED = "failed"  # the list could not be saved, or the change not recorded: nothing changed


TRUST_MESSAGES = {
    TrustStatus.TRUSTED: "Destinatario de confianza añadido: desde ahora, lo que vaya solo a él "
    "pasa sin preguntar. Se quita desde la web.",
    TrustStatus.NOT_TRUSTABLE: (
        "Esta petición no puede añadir un destinatario de confianza (un borrado, un reenvío, "
        "algo de riesgo 3, varios destinatarios, algo que no se ve entero o que hace descargar "
        "una dirección): se decide una a una. No ha cambiado nada."
    ),
    TrustStatus.UNKNOWN: HOLD_MESSAGES[HoldStatus.UNKNOWN],
    TrustStatus.PAUSED: HOLD_MESSAGES[HoldStatus.PAUSED],
    TrustStatus.FAILED: (
        "No se ha podido guardar o grabar el destinatario de confianza, así que no se añade ni "
        "se aprueba: la petición sigue retenida."
    ),
}


@dataclass(frozen=True)
class TrustOutcome:
    status: TrustStatus
    hold_id: str
    trust_id: str | None = None
    hold: HoldStatus | None = None  # what approving the hold did, once it is trusted
    detail: str | None = None  # why the list refused it (Spanish; never a recipient)

    @property
    def message(self) -> str:
        text = self.detail or TRUST_MESSAGES[self.status]
        if self.hold is not None:
            text += " " + HOLD_MESSAGES[self.hold]
        return text


class HoldWatch(Protocol):
    """Who is told about the holds as they come and go (T10-4: the Telegram notice). Called
    with the channel's gate lock held, so it only takes note and never blocks nor raises."""

    def held(self, notice: Mapping[str, Any]) -> None:
        """A new hold, recorded: ``ProxyChannel._notice`` (struck)."""
        ...

    def closed(self, hold_id: str, status: str, by: str | None) -> None:
        """A hold ended: ``status`` is "released", "preapproved", "rejected" or "expired";
        ``by`` who or what ended it (cli, web, telegram, pause, rewind, timeout, restart...)."""
        ...


# Batches (T10-4, docs/32 section 10)


class BatchKind(StrEnum):
    RECIPIENT = "recipient"  # "todo a este destinatario, esta sesión"
    KIND = "kind"  # "este tipo de acción, 1 h"


class BatchRefused(StrEnum):
    NOT_OPEN = "not_open"  # no open hold with that id (decided, expired, being released)
    NOT_BATCHABLE = "not_batchable"  # that hold may not make that batch (decision 8)
    FULL = "full"  # max_batches are active


class BatchStatus(StrEnum):
    """What asking for a batch did."""

    CREATED = "created"  # recorded; the hold it came from is approved with it
    NOT_BATCHABLE = "not_batchable"
    FULL = "full"
    UNKNOWN = "unknown"  # no open hold with that id
    PAUSED = "paused"  # the agent is paused or being rewound: nothing is approved meanwhile
    FAILED = "failed"  # it could not be recorded, so it was not made


BATCH_MESSAGES = {
    BatchStatus.CREATED: "Lote creado. Esta petición queda aprobada.",
    BatchStatus.NOT_BATCHABLE: (
        "Esta petición no puede abrir un lote (un borrado, un reenvío, algo de riesgo 3, algo "
        "que no se ve entero o que hace descargar una dirección): se decide una a una."
    ),
    BatchStatus.FULL: (
        "Ya hay 10 lotes activos: revoca alguno con /lotes antes de crear otro. La petición "
        "sigue retenida."
    ),
    BatchStatus.UNKNOWN: (
        "Esa retención ya no está abierta (decidida, caducada o tras un reinicio): no se crea "
        "ningún lote."
    ),
    BatchStatus.PAUSED: (
        "El agente está pausado o se está rebobinando, así que no se aprueba nada ni se crea "
        "ningún lote. La petición sigue retenida."
    ),
    BatchStatus.FAILED: (
        "No se ha podido grabar el lote en la caja negra, así que no se crea: la petición sigue "
        "retenida."
    ),
}


@dataclass(frozen=True)
class BatchOutcome:
    status: BatchStatus
    hold_id: str
    rule_id: str | None = None
    hold: HoldStatus | None = None  # what approving the hold did, once the batch is made

    @property
    def message(self) -> str:
        text = BATCH_MESSAGES[self.status]
        if self.hold is HoldStatus.RELEASED:
            text += " Sale ahora, una sola vez."
        elif self.hold is HoldStatus.PREAPPROVED:
            text += " El agente ya no esperaba: si la repite en 10 minutos, sale una vez."
        return text


BATCH_EFFECTS = frozenset({"send", "change"})
# The notes a batchable reading may carry: our fixed texts that say nothing doubtful. Anything
# else (a deletion, a URL the platform fetches, an inline message, a secret, content unseen, a
# duplicate, an IDN domain, a size cap...) keeps it out of every batch.
BATCH_NOTES = frozenset({"webhook", "interaction"})
BATCH_METHODS = frozenset({"POST", "PUT", "PATCH"})  # a write without a translator
MAX_BATCH_RECIPIENTS = 5  # the most a "todo a este destinatario" names (the alert shows 5)
_STAR_RE = re.compile(
    r"\d+|[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}",
    re.ASCII,
)


@dataclass(frozen=True)
class Scope:
    """What a request is, for the batches: fields the proxy reads strictly (the translator the
    path chose, the account's HMAC, the effect from its table, the recipients and the Reply-To
    from named fields; or the method, the connection's host, the route and the HMAC of its
    credential headers), and the connection's scheme and port. ``batchable``: it may make or
    ride a batch at all."""

    translator: str | None = None
    account: str | None = None
    effect: str | None = None
    recipients: frozenset[str] = frozenset()
    reply_to: frozenset[str] = frozenset()  # where the answers go (review of T10-4, M2)
    method: str | None = None
    host: str | None = None
    route: str | None = None
    credential: str | None = None  # fingerprint.credential_id: whose token (review, M1)
    scheme: str | None = None  # an https batch never covers http (review, B3)
    port: int | None = None
    batchable: bool = False


def reading_scope(
    reading: Mapping[str, Any],
    *,
    risk: int = 2,
    scheme: str | None = None,
    port: int | None = None,
    batchable: bool = True,
) -> Scope:
    """The scope of a checked reading (``protocol.check_reading``). ``risk``: the hold's own,
    when it is one (a URL that carried a secret makes it 3 whatever the reading says).
    ``batchable`` False: the request has an override header or trailers (review of T10-4,
    A1)."""
    recipients = reading.get("recipients") or []
    reply_to = reading.get("reply_to") or []
    account = reading.get("account")
    notes = set(reading.get("notes") or [])
    batchable = (
        batchable
        and reading.get("effect") in BATCH_EFFECTS
        and reading.get("risk") == 2
        and risk == 2
        and reading.get("secret_seen") is False
        and reading.get("cut") is False
        and reading.get("draft") is None
        and isinstance(account, str)
        and bool(recipients)
        and notes <= BATCH_NOTES
    )
    return Scope(
        translator=str(reading.get("translator")),
        account=account if isinstance(account, str) else None,
        effect=str(reading.get("effect")),
        recipients=frozenset(str(item) for item in recipients),
        reply_to=frozenset(str(item) for item in reply_to),
        scheme=scheme,
        port=port,
        batchable=batchable,
    )


def plain_scope(
    method: str,
    host: str,
    path: str,
    *,
    risk: int,
    reason: str,
    scheme: str | None = None,
    port: int | None = None,
    credential: str | None = None,
    credentials_struck: bool = False,
) -> Scope:
    """The scope of a request no translator read: only a plain write (``reason`` "write", risk
    2: no secret seen, no override header nor trailers) by POST, PUT or PATCH, whose credential
    headers are known (``credential``) and, toward a host off the allowed list, carry nothing
    the redaction recognises (``credentials_struck``, which the caller only sets then: review
    of T10-4, M1), may make or ride a batch."""
    return Scope(
        method=method,
        host=host.lower(),
        route=route_of(path),
        credential=credential,
        scheme=scheme,
        port=port,
        batchable=reason == "write"
        and risk == 2
        and method in BATCH_METHODS
        and credential is not None
        and not credentials_struck,
    )


def route_of(path: str) -> str:
    """A path with its numeric, long hexadecimal and UUID segments as ``*``, and the sorted
    names of its query's parameters (docs/32, section 10)."""
    route, _, query = path.partition("?")
    segments = ["*" if _STAR_RE.fullmatch(segment) else segment for segment in route.split("/")]
    names = sorted({part.partition("=")[0] for part in query.split("&") if part})
    return "/".join(segments) + ("?" + "&".join(names) if names else "")


@dataclass(eq=False)
class BatchRule:
    rule_id: str
    kind: BatchKind
    scope: Scope
    hold_id: str  # the hold it was made from
    created: float
    until: float
    until_at: str  # the same moment on the wall clock, for the black box
    uses: int = 0

    def covers(self, scope: Scope) -> bool:
        """Whether ``scope`` rides this rule: the same scheme and port, the same translator and
        account (or method, host, route and credential headers), and, for a recipient batch,
        every recipient and every Reply-To in it."""
        mine = self.scope
        if not scope.batchable or (scope.scheme, scope.port) != (mine.scheme, mine.port):
            return False
        if mine.translator is None:  # a write without a translator, with the same token
            return (scope.translator, scope.method, scope.host, scope.route, scope.credential) == (
                None, mine.method, mine.host, mine.route, mine.credential,
            )  # fmt: skip
        if (scope.translator, scope.account) != (mine.translator, mine.account):
            return False
        if self.kind is BatchKind.KIND:
            return scope.effect == mine.effect
        # Every recipient, and every address the answers go to, is one the person named.
        return (
            scope.effect in BATCH_EFFECTS
            and scope.recipients <= mine.recipients
            and scope.reply_to <= mine.recipients
        )


def _new_batch_id() -> str:
    return f"b-{secrets.token_hex(4)}"


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
    held_at: str = ""  # when it was held, on the wall clock (the web's countdown, T10-5)
    seq: int | None = None  # its gate/held
    connected: int = 0
    state: State = State.OPEN
    until: float | None = None  # a preapproval's end
    frozen: bool = False  # a pause or a rewind came while it was releasing: no preapproval
    draft: DraftKey | None = None  # the saved draft it sends or changes (T10-3)
    phrase: str | None = None  # what its translator says it does (backtide.gate.phrase)
    scope: Scope | None = None  # what it is, for the batches (T10-4)
    reading: dict[str, Any] | None = None  # its reading as gate/held recorded it, for the notice

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
        new_batch_id: Callable[[], str] = _new_batch_id,
    ) -> None:
        self.timings = timings if timings is not None else HoldTimings()
        self._clock = clock
        self._wall = wall
        self._new_id = new_id
        self._new_batch_id = new_batch_id
        self._batches: dict[str, BatchRule] = {}  # by rule id, in the order they were made
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

    def draft_open(self, key: DraftKey) -> bool:
        """Whether a hold of the draft ``key`` is open, releasing or preapproved (a lapsed
        preapproval no longer counts)."""
        now = self._clock()
        for hold in self._holds.values():
            if hold.draft != key:
                continue
            if hold.state is not State.PREAPPROVED or hold.until is None or now < hold.until:
                return True
        return False

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

    def open(
        self,
        fp: str,
        *,
        risk: int,
        reason: str,
        event: dict[str, Any],
        draft: DraftKey | None = None,
        scope: Scope | None = None,
    ) -> Hold | None:
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
            held_at=_iso(self._wall()),
            draft=draft,
            scope=scope,
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

    # Batches (T10-4)

    def offers(self, hold: Hold) -> tuple[BatchKind, ...]:
        """The batches ``hold`` may make: none for what may never ride one (decision 8); the
        recipient batch only for a translated request to 1 to 5 recipients whose answers go
        to them too (a Reply-To elsewhere: review of T10-4, M2)."""
        scope = hold.scope
        if scope is None or not scope.batchable:
            return ()
        if scope.translator is None:
            return (BatchKind.KIND,)
        to_them = scope.reply_to <= scope.recipients
        if 1 <= len(scope.recipients) <= MAX_BATCH_RECIPIENTS and to_them:
            return (BatchKind.RECIPIENT, BatchKind.KIND)
        return (BatchKind.KIND,)

    def add_batch(self, hold: Hold, kind: BatchKind) -> BatchRule | BatchRefused:
        """A new rule of ``kind`` made from the open ``hold`` (not yet recorded:
        ``drop_batch`` if its gate/batch_rule cannot be). The same rule again is the one there
        is."""
        if self._holds.get(hold.hold_id) is not hold or hold.state is not State.OPEN:
            return BatchRefused.NOT_OPEN
        if kind not in self.offers(hold) or hold.scope is None:
            return BatchRefused.NOT_BATCHABLE
        now = self._clock()
        self._lapse(now)
        scope = hold.scope
        if kind is BatchKind.KIND and scope.translator is not None:
            scope = Scope(translator=scope.translator, account=scope.account,
                          effect=scope.effect, scheme=scope.scheme, port=scope.port,
                          batchable=True)  # fmt: skip
        for rule in self._batches.values():
            if rule.kind is kind and rule.scope == scope:
                return rule
        if len(self._batches) >= self.timings.max_batches:
            return BatchRefused.FULL
        timings = self.timings
        life = timings.batch_session if kind is BatchKind.RECIPIENT else timings.batch_hour
        rule_id = self._new_batch_id()
        while rule_id in self._batches:
            rule_id = self._new_batch_id()
        rule = BatchRule(
            rule_id=rule_id,
            kind=kind,
            scope=scope,
            hold_id=hold.hold_id,
            created=now,
            until=now + life,
            until_at=_iso(self._wall() + timedelta(seconds=life)),
        )
        self._batches[rule_id] = rule
        return rule

    def drop_batch(self, rule: BatchRule) -> None:
        """Its gate/batch_rule could not be recorded: it never was."""
        if self._batches.get(rule.rule_id) is rule:
            del self._batches[rule.rule_id]

    def batch_for(self, scope: Scope, *, use: bool = False) -> BatchRule | None:
        """The active rule that covers ``scope``, if any (``use``: count one more use)."""
        if not scope.batchable:
            return None
        now = self._clock()
        for rule in self._batches.values():
            if now < rule.until and rule.covers(scope):
                if use:
                    rule.uses += 1
                return rule
        return None

    def batches(self) -> list[BatchRule]:
        """The active rules, oldest first."""
        now = self._clock()
        return [rule for rule in self._batches.values() if now < rule.until]

    def end_batch(self, rule_id: str) -> BatchRule | None:
        """Revoke a rule (``/lotes``). None if there is no such active rule."""
        rule = self._batches.get(rule_id)
        if rule is None or self._clock() >= rule.until:
            return None
        del self._batches[rule_id]
        return rule

    def due_batches(self) -> list[BatchRule]:
        """The rules whose time is over, removed (the caller records gate/batch_rule_end)."""
        return self._lapse(self._clock())

    def end_batches(self) -> list[BatchRule]:
        """Every rule ends: a pause, a rewind, or the end of the channel (they were tied to
        this connection's key, and so is the account's HMAC)."""
        ended = list(self._batches.values())
        self._batches.clear()
        return ended

    def _lapse(self, now: float) -> list[BatchRule]:
        lapsed = [rule for rule in self._batches.values() if now >= rule.until]
        for rule in lapsed:
            del self._batches[rule.rule_id]
        return lapsed

    # Helpers

    def _drop(self, hold: Hold) -> None:
        self._holds.pop(hold.hold_id, None)
        if self._by_fp.get(hold.fp) is hold:
            del self._by_fp[hold.fp]

    def _end(self, hold: Hold) -> None:
        self._drop(hold)
        self._rejected[hold.fp] = self._clock() + self.timings.remember


# "Aprobar y confiar en este destinatario" (T10-5, decision 9): a send or a change, of risk 2,
# to exactly one recipient (and its answers to it), that may ride a batch (no override header nor
# trailers, no secret, no cut, no draft, an account), with none of the reading's notes: so never
# an inline message, a URL the platform fetches, a webhook, a deletion, IDN, a duplicate...
# Final review of T10: never a mail recipient (finding 2: until the owner's accounts exist,
# approved decision 4, a trusted address would pass from any account), never a recipient over
# TRUST_RECIPIENT_CHARS (finding 4: one the person cannot read whole), and never a Telegram
# chat by its @name (finding 9: a public channel or group, and a name can pass to another chat).
TRUST_EFFECTS = frozenset({"send", "change"})
TRUST_TRANSLATORS = frozenset({"telegram", "slack", "discord"})
TRUST_RECIPIENT_CHARS = 100


def trust_target(hold: Hold) -> tuple[str, str] | None:
    """``(translator, recipient)`` that "aprobar y confiar" would trust from ``hold``, from its
    strict fields (never the agent's text), or None when it may not: docs/32, decision 9."""
    reading, scope = hold.reading, hold.scope
    if reading is None or scope is None or not scope.batchable or hold.risk != 2:
        return None
    translator = reading.get("translator")
    recipients = list(reading.get("recipients") or [])
    reply_to = {str(item) for item in reading.get("reply_to") or []}
    if (
        translator not in TRUST_TRANSLATORS
        or reading.get("effect") not in TRUST_EFFECTS
        or reading.get("secret_seen") is not False
        or reading.get("cut") is not False
        or reading.get("draft") is not None
        or reading.get("notes")
        or len(recipients) != 1
        or not isinstance(recipients[0], str)
        or len(recipients[0]) > TRUST_RECIPIENT_CHARS
        or not reply_to <= {recipients[0]}
        or (translator == "telegram" and recipients[0].startswith("@"))
    ):
        return None
    try:
        normalized = normalize_trusted(str(translator), recipients[0])
    except ValueError:
        return None
    if normalized.recipient != recipients[0]:
        return None  # the translator normalizes the same way: anything else is doubtful
    return normalized.translator, normalized.recipient


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
