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
| 5 | A translator understands it | T10-3: read, trusted recipient or batch pass; the rest is held with its reading |
| 6 | No translator: exactly ``GET``, ``HEAD`` or ``OPTIONS`` with no body, no method override header and no trailers | ``pass``, with decision 1's guard: a URL, or a header that is not a credential, whose redaction struck a secret is held with risk 3; a URL, or those headers together, over 2 KiB with risk 2 |
| 7 | Anything else (``POST``, ``PUT``, ``PATCH``, ``DELETE``, WebDAV, an unknown method, a ``GET`` with a body, an override header or trailers) | ``hold``: ``DELETE`` with risk 3, any other write with risk 2 |

The method of rule 6 is the one the agent sent, exactly: ``get`` is not ``GET`` (decision 11:
an unknown method is a write). ``exact_read`` is False too for a request with a method override
header or trailers (the proxy sees them; security review of T10-2, M2). The header guard (M3)
leaves the credential headers out: the agent's own token to an API is not a leak.
"""  # noqa: E501

from dataclasses import dataclass
from enum import StrEnum

MAX_READ_URL = 2048  # bytes: a read whose URL is longer is held (decision 1's guard)
MAX_READ_HEADERS = 2048  # bytes of a read's headers but the credentials: the same guard
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
UNKNOWN_HOSTS = frozenset({"hold", "deny"})  # [gate] unknown_hosts: "deny" is the strict mode


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict, not a password
    HOLD = "hold"
    REJECT = "reject"


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
    # Rule 5 (the translators, T10-3) goes here: a reading decides before the method does.
    # TODO(T10-3): a draft change passes (decision 12) only while no hold or preapproval of that
    # draft is open: else the text approved could be changed before it is sent.
    # TODO(T10-3): a translated path that carries its own credential (``path_credential``:
    # Telegram's bot token, a Discord webhook) is struck by design; it must not raise the risk to
    # 3 the way ``url_struck`` does here.
    if facts.exact_read and facts.method in READ_METHODS and not facts.has_body:
        if facts.url_struck:
            return Decision(Verdict.HOLD, "url_secret", 3)
        if facts.headers_struck:
            return Decision(Verdict.HOLD, "header_secret", 3)
        if facts.url_bytes > MAX_READ_URL:
            return Decision(Verdict.HOLD, "url_long", 2)
        if facts.header_bytes > MAX_READ_HEADERS:
            return Decision(Verdict.HOLD, "headers_long", 2)
        return Decision(Verdict.PASS, "read")
    if facts.method == "DELETE":
        return Decision(Verdict.HOLD, "delete", 3)
    return Decision(Verdict.HOLD, "write", 2)
