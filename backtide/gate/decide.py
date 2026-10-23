"""What the gate does with a request: the table of docs/32, section 5. Pure and stateless.

backtide calls ``decide`` with the facts of one request (what the proxy measured, the allowed
list, and what the ``HoldBook`` remembers of its fingerprint) and gets one of three verdicts:
``pass`` (recorded, then out), ``hold`` (wait for the person, with a risk) or ``reject``.

The order, after the proxy's fixed rules of T06 (ports, private addresses, the real key,
``host_mismatch``, OAuth, the providers' hosts, sizes), which do not change:

| # | Case | Verdict |
|---|---|---|
| 1 | A model provider's host | ``pass``: never held (its provider-side tools stay refused, T06-6) |
| 2 | A WebSocket opening (``Upgrade``) | ``pass`` only to the allowed list, else ``reject not_allowed``: an open WebSocket is a blank cheque |
| - | Strict mode (``unknown_hosts = "deny"``) and a host off the list | ``reject not_allowed``: T06's behaviour |
| 3 | Its fingerprint is preapproved (one use, 10 min) | ``pass`` |
| 4 | Its fingerprint was rejected or expired less than 10 min ago | ``reject gate_rejected``, without asking again |
| 5 | A translator read it (``reading``; rule 6 never applies then) | see below |
| 6 | No translator: exactly ``GET``, ``HEAD`` or ``OPTIONS`` with no body, no method override header and no trailers | ``pass``, with decision 1's guard: a URL, or a header that is not a credential (its name or its value), whose redaction struck a secret is held with risk 3; to a host off the allowed list, a credential header whose redaction struck a secret with risk 3 and any credential header at all with risk 2 (review of T10-3, H1); a URL, or those headers together, over 2 KiB with risk 2; the credential headers together over 4 KiB with risk 2 (T10-3: with reads to any host they would be a free channel out). backtide then charges what passes to an unknown host to its read budget (``read_budget``, docs/32 section 13) |
| 7 | Anything else (``POST``, ``PUT``, ``PATCH``, ``DELETE``, WebDAV, an unknown method, a ``GET`` with a body, an override header or trailers) | ``hold``: ``DELETE`` with risk 3, any other write with risk 2, or 3 when its URL or its body carried a secret; an override header that says ``DELETE`` (``delete``), a path, another method or something unreadable (``override``) with risk 3, one that says ``GET``, ``HEAD``, ``OPTIONS``, ``POST``, ``PUT`` or ``PATCH`` (``override``) with risk 2; a write a batch rule covers (``batch``, T10-4) passes, never a ``DELETE``, one with a secret (also a recognisable token in a credential header toward a host off the allowed list), an override header nor trailers (security review of T10-4, A1 and M1) |

Rule 5, a translator's reading (T10-3, docs/32 sections 5 and 9):

- A URL or a header (but the credentials) whose redaction struck a secret makes it risk 3 and
  it never passes: the proxy already left the API's own credential in the path out
  (``path_credential``: Telegram's bot token, a webhook's secret), so that alone never does.
- A change to a draft whose sending is held or preapproved (``draft_open``) is held: else the
  text the person approves could change before it goes out (decision 12).
- ``READ`` passes, within the guard's lengths (URL and headers, 2 KiB each; the credential
  headers, 4 KiB together: review of T10-3, L9).
- ``SEND`` or ``CHANGE`` to trusted recipients only (``trusted``: ``all_trusted``, never with a
  secret seen nor a cut reading) passes.
- A send or a change a batch rule covers (``batch``: the rule's id, from the ``HoldBook``;
  T10-4, docs/32 section 10) passes, never with a secret seen nor with risk 3, nor with an
  override header or trailers (review of T10-4, A1); an override header that says ``DELETE``
  or cannot be read makes any reading risk 3.
- ``FORWARD``, ``DELETE``, ``ADMIN`` and ``UNKNOWN`` are always held, with the reading's risk.
- The rest (a send or a change to someone not trusted) is held, with the reading's risk: the
  translator's phrase is what backtide records and shows (``backtide.gate.phrase``).

The method of rule 6 is the one the agent sent, exactly: ``get`` is not ``GET`` (decision 11:
an unknown method is a write). ``exact_read`` is False too for a request with a method override
header or trailers (the proxy sees them; security review of T10-2, M2). The header guard (M3)
leaves the credential headers out: the agent's own token to an API is not a leak. But only to
an API the person listed (``allowed``): to any other host, a credential header is held, with risk
3 when the redaction recognises its value (``credentials_struck``; review of T10-3, H1).
"""  # noqa: E501

from dataclasses import dataclass
from enum import StrEnum

from backtide.gate.translate.base import Effect

MAX_READ_URL = 2048  # bytes: a read whose URL is longer is held (decision 1's guard)
MAX_READ_HEADERS = 2048  # bytes of a read's headers but the credentials: the same guard
# Bytes of a plain read's credential headers (Authorization, Cookie, PRIVATE-TOKEN...): their
# values are not searched (the agent's own token is no leak), so their size is capped instead.
# 4 KiB, not 2: a Microsoft or Azure JWT is often over 2 KiB, and a cookie jar can be too.
MAX_READ_CREDENTIALS = 4096
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# What an override header may say and still be a plain write (risk 2); anything else (DELETE,
# a path, an unknown verb) is held with risk 3 (security review of T10-4, A1).
PLAIN_OVERRIDES = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"})
UNKNOWN_HOSTS = frozenset({"hold", "deny"})  # [gate] unknown_hosts: "deny" is the strict mode


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict, not a password
    HOLD = "hold"
    REJECT = "reject"


@dataclass(frozen=True)
class ReadingFacts:
    """What backtide makes of a translator's reading. ``risk``: the reading's own (2, or 3 for
    a deletion, an administration or a secret seen). ``trusted``: every recipient is trusted
    (``all_trusted``; never for a cut reading). ``draft_open``: it changes a draft whose sending
    a hold or a preapproval covers. ``batch``: the batch rule that covers it (T10-4), if any."""

    effect: Effect
    risk: int
    trusted: bool = False
    draft_open: bool = False
    batch: str | None = None


@dataclass(frozen=True)
class Facts:
    """One request, as backtide knows it. ``method`` is the recorded one (upper case);
    ``exact_read`` says the method was sent as exactly GET, HEAD or OPTIONS."""

    method: str
    exact_read: bool
    has_body: bool
    url_bytes: int
    url_struck: bool
    headers_struck: bool = False  # a header that is not a credential carried a secret
    header_bytes: int = 0  # the bytes of those headers, names and values
    provider: bool = False
    websocket: bool = False
    allowed: bool = False  # the connection's host is on the allowed list
    # ... only because the agent's profile adds it (a package registry, T17b-1): enough to read
    # unasked, not to open a WebSocket (security review of T17b-1).
    profile_host: bool = False
    preapproved: bool = False
    rejected: bool = False  # rejected or expired less than 10 min ago
    credential_bytes: int = 0  # the bytes of its credential headers, names and values
    credentials_struck: bool = False  # the redaction struck something of a credential header
    body_struck: bool = False  # its body carried a secret (only without a translator)
    reading: ReadingFacts | None = None  # a translator read it (rule 5)
    batch: str | None = None  # the batch rule that covers a write no translator read (T10-4)
    # What its override headers say (None: it has none; a method; "?": a path or unreadable)
    # and whether it has trailers: never under a batch (security review of T10-4, A1).
    override: str | None = None
    trailers: bool = False

    @property
    def batchable(self) -> bool:
        """Whether a batch may cover it at all: no override header, no trailers."""
        return self.override is None and not self.trailers


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    risk: int = 0

    @property
    def held(self) -> bool:
        return self.verdict is Verdict.HOLD


def decide(facts: Facts, *, unknown_hosts: str = "hold") -> Decision:
    """The verdict for ``facts``. ValueError for an ``unknown_hosts`` that is not a mode."""
    if unknown_hosts not in UNKNOWN_HOSTS:
        raise ValueError("unknown_hosts is 'hold' or 'deny'")
    if facts.provider:
        return Decision(Verdict.PASS, "provider")
    if facts.websocket:
        # Only a GET with no body opens one: the proxy refuses any other request that names
        # Upgrade, and this checks it again (security review of T17b-1).
        opening = facts.method == "GET" and facts.exact_read and not facts.has_body
        if opening and facts.allowed and not facts.profile_host:
            return Decision(Verdict.PASS, "websocket")
        return Decision(Verdict.REJECT, "not_allowed")
    if unknown_hosts == "deny" and not facts.allowed:
        return Decision(Verdict.REJECT, "not_allowed")
    if facts.preapproved:
        return Decision(Verdict.PASS, "preapproved")
    if facts.rejected:
        return Decision(Verdict.REJECT, "gate_rejected")
    if facts.reading is not None:
        return _translated(facts, facts.reading)
    if facts.exact_read and facts.method in READ_METHODS and not facts.has_body:
        if facts.url_struck:
            return Decision(Verdict.HOLD, "url_secret", 3)
        if facts.headers_struck:
            return Decision(Verdict.HOLD, "header_secret", 3)
        if not facts.allowed and facts.credentials_struck:
            return Decision(Verdict.HOLD, "credential_secret", 3)
        if not facts.allowed and facts.credential_bytes > 0:
            return Decision(Verdict.HOLD, "credential_unknown_host", 2)
        if facts.url_bytes > MAX_READ_URL:
            return Decision(Verdict.HOLD, "url_long", 2)
        if facts.header_bytes > MAX_READ_HEADERS:
            return Decision(Verdict.HOLD, "headers_long", 2)
        if facts.credential_bytes > MAX_READ_CREDENTIALS:
            return Decision(Verdict.HOLD, "credentials_long", 2)
        return Decision(Verdict.PASS, "read")
    secret = facts.url_struck or facts.body_struck
    if facts.method == "DELETE" or facts.override == "DELETE":
        return Decision(Verdict.HOLD, "delete", 3)
    if facts.override is not None:
        risk = 3 if secret or facts.override not in PLAIN_OVERRIDES else 2
        return Decision(Verdict.HOLD, "override", risk)
    # A token the redaction recognises in a credential header is the agent's own only toward a
    # listed API (T10-3, H1): toward any other host no batch carries it (review of T10-4, M1).
    stray_token = facts.credentials_struck and not facts.allowed
    clean = not secret and not facts.headers_struck and not stray_token
    if facts.batch is not None and clean and facts.batchable:
        return Decision(Verdict.PASS, "batch")
    return Decision(Verdict.HOLD, "write", 3 if secret else 2)


def _translated(facts: Facts, reading: ReadingFacts) -> Decision:
    """Rule 5: what a translator read decides, not the HTTP method (docs/32, section 5)."""
    struck = "url_secret" if facts.url_struck else "header_secret" if facts.headers_struck else None
    risk = 3 if struck is not None else reading.risk
    if facts.override is not None and facts.override not in PLAIN_OVERRIDES:
        risk = 3  # an override that says DELETE, or cannot be read (review of T10-4, A1)
    effect = reading.effect
    if reading.draft_open:
        return Decision(Verdict.HOLD, "draft_open", max(risk, 2))
    if not facts.batchable:
        # The translators read an override header or trailers as UNKNOWN; whatever a reading
        # says, nothing with them passes here (review of T10-4, A1).
        return Decision(Verdict.HOLD, str(effect) if struck is None else struck, max(risk, 2))
    if struck is None:
        if effect is Effect.READ:
            if facts.url_bytes > MAX_READ_URL:
                return Decision(Verdict.HOLD, "url_long", 2)
            if facts.header_bytes > MAX_READ_HEADERS:
                return Decision(Verdict.HOLD, "headers_long", 2)
            if facts.credential_bytes > MAX_READ_CREDENTIALS:
                return Decision(Verdict.HOLD, "credentials_long", 2)
            return Decision(Verdict.PASS, "translator_read")
        if effect in (Effect.SEND, Effect.CHANGE) and reading.trusted:
            return Decision(Verdict.PASS, "trusted")
        # A batch rule lets a send or a change of its scope pass; never a forward, a deletion,
        # an administration, the unknown nor anything of risk 3 (decision 8): the book never
        # offers one for them, and this says no again.
        if effect in (Effect.SEND, Effect.CHANGE) and reading.batch and risk < 3:
            return Decision(Verdict.PASS, "batch")
    elif effect is Effect.READ:
        return Decision(Verdict.HOLD, struck, 3)
    # FORWARD, DELETE, ADMIN and UNKNOWN never get this far without being held (nothing above
    # lets them pass), and neither does a send or a change to someone not trusted.
    return Decision(Verdict.HOLD, str(effect), max(risk, 2))
