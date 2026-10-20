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
| 6 | No translator: exactly ``GET``, ``HEAD`` or ``OPTIONS`` with no body, no method override header and no trailers | ``pass``, with decision 1's guard: a URL, or a header that is not a credential, whose redaction struck a secret is held with risk 3; a URL, or those headers together, over 2 KiB with risk 2; the credential headers together over 4 KiB with risk 2 (T10-3: with reads to any host they would be a free channel out) |
| 7 | Anything else (``POST``, ``PUT``, ``PATCH``, ``DELETE``, WebDAV, an unknown method, a ``GET`` with a body, an override header or trailers) | ``hold``: ``DELETE`` with risk 3, any other write with risk 2, or 3 when its URL or its body carried a secret |

Rule 5, a translator's reading (T10-3, docs/32 sections 5 and 9):

- A URL or a header (but the credentials) whose redaction struck a secret makes it risk 3 and
  it never passes: the proxy already left the API's own credential in the path out
  (``path_credential``: Telegram's bot token, a webhook's secret), so that alone never does.
- A change to a draft whose sending is held or preapproved (``draft_open``) is held: else the
  text the person approves could change before it goes out (decision 12).
- ``READ`` passes, within the guard's lengths (URL and headers, 2 KiB each).
- ``SEND`` or ``CHANGE`` to trusted recipients only (``trusted``: ``all_trusted``, never with a
  secret seen nor a cut reading) passes.
- T10-4 (batches): a reading a batch rule covers will pass here; the hook is ``batch``.
- ``FORWARD``, ``DELETE``, ``ADMIN`` and ``UNKNOWN`` are always held, with the reading's risk.
- The rest (a send or a change to someone not trusted) is held, with the reading's risk: the
  translator's phrase is what backtide records and shows (``backtide.gate.phrase``).

The method of rule 6 is the one the agent sent, exactly: ``get`` is not ``GET`` (decision 11:
an unknown method is a write). ``exact_read`` is False too for a request with a method override
header or trailers (the proxy sees them; security review of T10-2, M2). The header guard (M3)
leaves the credential headers out: the agent's own token to an API is not a leak.
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
    a hold or a preapproval covers. ``batch``: the batch rule that covers it (T10-4; None)."""

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
    preapproved: bool = False
    rejected: bool = False  # rejected or expired less than 10 min ago
    credential_bytes: int = 0  # the bytes of its credential headers, names and values
    body_struck: bool = False  # its body carried a secret (only without a translator)
    reading: ReadingFacts | None = None  # a translator read it (rule 5)


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
        if facts.allowed:
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
        if facts.url_bytes > MAX_READ_URL:
            return Decision(Verdict.HOLD, "url_long", 2)
        if facts.header_bytes > MAX_READ_HEADERS:
            return Decision(Verdict.HOLD, "headers_long", 2)
        if facts.credential_bytes > MAX_READ_CREDENTIALS:
            return Decision(Verdict.HOLD, "credentials_long", 2)
        return Decision(Verdict.PASS, "read")
    secret = facts.url_struck or facts.body_struck
    if facts.method == "DELETE":
        return Decision(Verdict.HOLD, "delete", 3)
    return Decision(Verdict.HOLD, "write", 3 if secret else 2)


def _translated(facts: Facts, reading: ReadingFacts) -> Decision:
    """Rule 5: what a translator read decides, not the HTTP method (docs/32, section 5)."""
    struck = "url_secret" if facts.url_struck else "header_secret" if facts.headers_struck else None
    risk = 3 if struck is not None else reading.risk
    effect = reading.effect
    if reading.draft_open:
        return Decision(Verdict.HOLD, "draft_open", max(risk, 2))
    if struck is None:
        if effect is Effect.READ:
            if facts.url_bytes > MAX_READ_URL:
                return Decision(Verdict.HOLD, "url_long", 2)
            if facts.header_bytes > MAX_READ_HEADERS:
                return Decision(Verdict.HOLD, "headers_long", 2)
            return Decision(Verdict.PASS, "translator_read")
        if effect in (Effect.SEND, Effect.CHANGE) and reading.trusted:
            return Decision(Verdict.PASS, "trusted")
        # T10-4: a batch rule (``reading.batch``) lets a send or a change of its scope pass
        # here; never a forward, a deletion, an administration or the unknown (decision 8).
    elif effect is Effect.READ:
        return Decision(Verdict.HOLD, struck, 3)
    # FORWARD, DELETE, ADMIN and UNKNOWN never get this far without being held (nothing above
    # lets them pass), and neither does a send or a change to someone not trusted.
    return Decision(Verdict.HOLD, str(effect), max(risk, 2))
