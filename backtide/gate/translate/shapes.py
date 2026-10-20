"""How "pending" and "rejected" are written for each API (docs/32, sections 6 and 8). Pure.

"Pending" is an HTTP 429 with ``Retry-After: 30`` in the shape the API's own client already
reads as "wait and try again", so OpenClaw's channels and gog retry a few times on their own
(docs/32, P6). "Rejected" (also "expired", "the person paused backtide", "too many held") is an
HTTP 403, which no client repeats. The texts are ours and fixed; the only variable is the hold's
id, which must be a plain id.
"""

import json
import re
from dataclasses import dataclass

from backtide.gate.translate.base import Shape

RETRY_AFTER_S = 30
_HOLD_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)

_REFUSALS = {
    "rejected": "the person rejected this request",
    "expired": "no one answered in 5 minutes, so it is rejected",
    "paused": "backtide was paused, so held requests are rejected",
    "hold_full": "too many requests are waiting for approval; this one is rejected",
}
REFUSAL_REASONS = frozenset(_REFUSALS)


@dataclass(frozen=True)
class Answer:
    """What the proxy answers the agent with, instead of the server."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def _hold(hold_id: str | None) -> str:
    if hold_id is None:
        return ""
    if not isinstance(hold_id, str) or not _HOLD_ID_RE.fullmatch(hold_id):
        raise ValueError("a hold id is 1-64 letters, digits, _ or -")
    return f" (hold {hold_id})"


def _json(status: int, value: object, extra: tuple[tuple[str, str], ...] = ()) -> Answer:
    body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    headers = (("content-type", "application/json; charset=utf-8"), *extra)
    return Answer(status, headers, body)


def _text(status: int, text: str, extra: tuple[tuple[str, str], ...] = ()) -> Answer:
    headers = (("content-type", "text/plain; charset=utf-8"), *extra)
    return Answer(status, headers, (text + "\n").encode("ascii"))


def pending(shape: Shape, hold_id: str | None) -> Answer:
    """HTTP 429, ``Retry-After: 30``: held, waiting for the person; try again in a while."""
    message = (
        f"backtide: waiting for the person to approve this request{_hold(hold_id)}; "
        f"try again in {RETRY_AFTER_S} s, not in a loop"
    )
    retry = (("retry-after", str(RETRY_AFTER_S)),)
    if shape is Shape.TELEGRAM:
        return _json(429, {
            "ok": False,
            "error_code": 429,
            "description": f"Too Many Requests: retry after {RETRY_AFTER_S} ({message})",
            "parameters": {"retry_after": RETRY_AFTER_S},
        }, retry)  # fmt: skip
    if shape is Shape.DISCORD:
        # The headers of Discord's own 429 (its docs, "Rate Limits"): unconfirmed whether
        # OpenClaw's REST client needs them besides Retry-After (docs/32, section 8).
        limits = (
            ("x-ratelimit-limit", "1"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset-after", f"{RETRY_AFTER_S:.3f}"),
            ("x-ratelimit-scope", "user"),
        )
        return _json(
            429, {"message": message, "retry_after": RETRY_AFTER_S, "global": False},
            retry + limits,
        )  # fmt: skip
    if shape is Shape.SLACK:
        return _json(429, {"ok": False, "error": "ratelimited", "warning": message}, retry)
    if shape is Shape.GOOGLE:
        return _json(429, {
            "error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": message}
        }, retry)  # fmt: skip
    if shape is Shape.GRAPH:
        return _json(429, {"error": {"code": "TooManyRequests", "message": message}}, retry)
    return _text(429, message, retry)


def refused(shape: Shape, hold_id: str | None, reason: str) -> Answer:
    """HTTP 403: rejected, expired, paused or ``hold_full``. ValueError for another reason."""
    if reason not in _REFUSALS:
        raise ValueError("unknown refusal reason")
    message = f"backtide: {_REFUSALS[reason]}{_hold(hold_id)}"
    if shape is Shape.TELEGRAM:
        return _json(403, {"ok": False, "error_code": 403, "description": f"Forbidden: {message}"})
    if shape is Shape.DISCORD:
        return _json(403, {"message": message, "code": 50013})
    if shape is Shape.SLACK:
        return _json(403, {"ok": False, "error": "backtide_" + reason, "warning": message})
    if shape is Shape.GOOGLE:
        return _json(403, {
            "error": {"code": 403, "status": "PERMISSION_DENIED", "message": message}
        })  # fmt: skip
    if shape is Shape.GRAPH:
        return _json(403, {"error": {"code": "ErrorAccessDenied", "message": message}})
    return _text(403, message)
