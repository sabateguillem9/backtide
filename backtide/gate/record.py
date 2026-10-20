"""From a flow, as a plain dict, to the event the proxy sends to backtide, with the proxy's
redaction: the first barrier of invariant 5. Pure: no I/O.

A request flow is a mapping with ``flow_id``, ``method``, ``scheme``, ``host`` (the
connection's), ``port``, ``path`` (with its query), ``http_version``, ``server_ip``,
``headers`` (a list of ``(name, value)`` pairs, in order, repeated names allowed) and
``body`` (the decoded content as bytes, or None). A missing key is simply not recorded.
A response is a mapping with ``status``, ``headers``, ``size``, ``duration_ms`` and
``streamed``; its body is never read here.

What is kept (docs/21, section 7):
- headers: the value only of a short list of harmless ones, the name of the others;
  cookies only counted;
- the path, with each query value struck when it is a secret by name or by pattern;
- of what is SENT (not GET, text, JSON or a form), a 2 KiB redacted excerpt; of what is
  received, never the body; of the model calls, never the text, only metadata;
- every text goes first through ``scrub_known`` (the secrets the proxy knows), then
  ``redact``, then is cut. In that order: a cut first could leave a piece of a secret.

Every builder returns an event checked by ``protocol.validate_event``.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import unquote, unquote_plus

from backtide.blackbox.redact import REDACTED, KnownScrubber, redact, strike_text
from backtide.gate.policy import normalize_host
from backtide.gate.protocol import BLOCK_RISK, event_risk, validate_event

__all__ = [
    "BLOCK_RISK",
    "EXCERPT_BYTES",
    "MAX_HEADERS",
    "SAFE_HEADERS",
    "blocked_event",
    "dropped_event",
    "error_event",
    "llm_request_event",
    "llm_response_event",
    "headers_struck",
    "path_struck",
    "request_event",
    "response_event",
    "throttled_event",
    "tls_failed_event",
    "websocket_event",
]

EXCERPT_BYTES = 2048
# Read past each limit, so a secret that crosses it is still whole when it is struck; then
# this much is dropped from the end of what was read, if the text went on (_strike).
_MARGIN = 1024
_MAX_PARAMS = 256
MAX_HEADERS = 48
SAFE_HEADERS = frozenset(
    {"content-type", "content-length", "content-encoding", "accept", "user-agent",
     "anthropic-version"}
)  # fmt: skip
_TEXT_TYPES = frozenset({"application/json", "application/x-www-form-urlencoded"})
_NO_EXCERPT_METHODS = frozenset({"GET", "HEAD"})
_DEFAULT_PORTS = {"https": 443, "http": 80, "wss": 443, "ws": 80}
_WEBSOCKET_ACTIONS = frozenset({"websocket_start", "websocket_summary", "websocket_end"})
_WEBSOCKET_STATS = frozenset(
    {"to_server_messages", "to_server_bytes", "to_client_messages", "to_client_bytes",
     "close_code"}
)  # fmt: skip

# Byte limits of the texts kept (after striking).
_LIMIT_SHORT = 64
_LIMIT_NAME = 128
_LIMIT_HEADER_VALUE = 256
_LIMIT_PATH = 2048
_LIMIT_HOST = 253  # the DNS limit: a valid name is never cut


Secrets = Sequence[str] | KnownScrubber
_NO_SECRETS = KnownScrubber(())


def _scrubber(secrets: Secrets) -> KnownScrubber:
    """One scrubber per event (or the caller's, reused): the pattern is built once."""
    return secrets if isinstance(secrets, KnownScrubber) else KnownScrubber(secrets)


def _strike(text: str, scrub: KnownScrubber, limit: int) -> str:
    """Known secrets, then patterns, over the first ``limit`` + _MARGIN characters only
    (bounded work). When the text went on, the last _MARGIN characters of the struck
    window are dropped: a secret crossing the window's end could not be found whole, and
    striking keeps the order of the text, so its piece is always among them."""
    window = text[: limit + _MARGIN]
    struck = redact(scrub.text(window))
    if len(text) > len(window):
        struck = struck[:-_MARGIN]
    return struck


def _clean(value: object, scrub: KnownScrubber, limit: int, *, lower: bool = False) -> str:
    """Struck (known secrets, then patterns), maybe lower-cased, and cut to ``limit``."""
    text = _strike(value if isinstance(value, str) else str(value), scrub, limit)
    if lower:
        text = text.lower()
    return _cut(text, limit)


def _cut(text: str, limit: int) -> str:
    data = text.encode("utf-8")
    if len(data) <= limit:
        return text
    return data[:limit].decode("utf-8", errors="ignore")


def _opt_text(value: object, scrub: KnownScrubber, limit: int) -> str | None:
    return None if value is None else _clean(value, scrub, limit)


def _opt_int(value: object) -> int | None:
    return value if type(value) is int else None


# --- pieces of a request -------------------------------------------------------------------------


def _headers(pairs: object, scrub: KnownScrubber) -> tuple[dict[str, str | None], int, int]:
    """(name -> value or None, cookies, headers dropped). Values only for SAFE_HEADERS."""
    values: dict[str, str | None] = {}
    cookies = 0
    dropped = 0
    for pair in pairs if isinstance(pairs, list | tuple) else []:
        if not isinstance(pair, list | tuple) or len(pair) != 2:
            dropped += 1
            continue
        raw_name, raw_value = (str(item) for item in pair)
        lowered = raw_name.strip().lower()
        if lowered == "cookie":
            cookies += sum(1 for part in raw_value.split(";") if part.strip())
        # Struck before lower-casing: a known secret is only found in its own case.
        name = _clean(raw_name.strip(), scrub, _LIMIT_SHORT, lower=True)
        safe = lowered in SAFE_HEADERS
        value = _clean(raw_value, scrub, _LIMIT_HEADER_VALUE) if safe else None
        if name in values:
            if safe and values[name] is not None and value is not None:
                values[name] = _cut(f"{values[name]}, {value}", _LIMIT_HEADER_VALUE)
            continue
        if len(values) >= MAX_HEADERS:
            dropped += 1
            continue
        values[name] = value
    return values, cookies, dropped


def _header(pairs: object, wanted: str) -> str | None:
    for pair in pairs if isinstance(pairs, list | tuple) else []:
        if isinstance(pair, list | tuple) and len(pair) == 2 and str(pair[0]).lower() == wanted:
            return str(pair[1])
    return None


def _media_type(pairs: object, scrub: KnownScrubber) -> str | None:
    raw = _header(pairs, "content-type")
    if raw is None:
        return None
    return _clean(raw.split(";", 1)[0].strip(), scrub, _LIMIT_NAME, lower=True)


def _path(path: object, scrub: KnownScrubber, *, strike: bool = True) -> str:
    """The path with each query value struck when it is a secret by its name or by a
    pattern (also once decoded), then the whole text struck and cut. Only the first
    _MAX_PARAMS parameters are looked at; the rest are dropped, never kept unchecked.
    ``strike=False``: the same window, parameters and cut, with nothing struck (to compare)."""
    text = path if isinstance(path, str) else str(path)
    window = text[: _LIMIT_PATH + _MARGIN]
    base, mark, query = window.partition("?")
    if mark:
        parts = query.split("&")
        kept = []
        for part in parts[:_MAX_PARAMS]:
            name, equals, value = part.partition("=")
            decoded = {unquote_plus(name): unquote_plus(value)}
            if strike and equals and (redact(decoded) != decoded or scrub(decoded) != decoded):
                value = REDACTED
            kept.append(f"{name}{equals}{value}")
        if len(parts) > _MAX_PARAMS:
            kept.append(f"[{len(parts) - _MAX_PARAMS} params dropped]")
        window = f"{base}?{'&'.join(kept)}"
    struck = redact(scrub.text(window)) if strike else window
    if strike:
        head, mark, tail = struck.partition("?")
        if _shows_once_decoded(head):
            struck = f"/{REDACTED}{mark}{tail}"
    if len(text) > _LIMIT_PATH + _MARGIN:
        struck = struck[:-_MARGIN]  # as in _strike
    return _cut(struck, _LIMIT_PATH)


def _shows_once_decoded(head: str) -> bool:
    """Whether a secret pattern shows in the (struck) path once read as a server may read it:
    %xx decoded once or twice, a backslash as a slash ("/bot123%3AAA…", "/%77ebhooks/…"). Its
    place in the raw text cannot be pinned down, so the caller strikes the whole path (as
    scrub_known does)."""
    once = unquote(head)
    for decoded in {once, unquote(once), once.replace("\\", "/")} - {head}:
        if redact(decoded) != decoded:
            return True
    return False


def headers_struck(pairs: Iterable[tuple[str, str]], secrets: Secrets) -> bool:
    """Whether the redaction strikes something of these header values (by pattern, or a secret
    it knows): the gate holds a read whose headers carried one, as one whose URL did (decision
    1's guard; security review of T10-2, M3). The caller leaves the credential headers out and
    bounds how much is read. Nothing is cut here: a long value is struck or not, never "struck"
    for its length."""
    scrub = _scrubber(secrets)
    for _name, value in pairs:
        text = str(value)
        if strike_text(scrub.text(text)) != text:
            return True
    return False


def path_struck(path: object, secrets: Secrets) -> bool:
    """Whether recording ``path`` (with its query) strikes something of it: a secret by name, by
    pattern or known. The gate holds a read whose URL carried one (decision 1's guard, T10-2).
    Parameters past the first _MAX_PARAMS are never looked at, so they count as struck: what
    cannot be checked is not let out as a plain read. (Past _LIMIT_PATH the URL is held anyway
    for its length.)"""
    scrub = _scrubber(secrets)
    text = path if isinstance(path, str) else str(path)
    _, mark, query = text[: _LIMIT_PATH + _MARGIN].partition("?")
    if mark and query.count("&") >= _MAX_PARAMS:
        return True
    return _path(text, scrub) != _path(text, scrub, strike=False)


def _host(host: object, scrub: KnownScrubber) -> str:
    # Struck before normalizing: lower-casing first would hide a known secret from the strike.
    struck = _clean(host, scrub, _LIMIT_HOST)
    name = normalize_host(struck)
    return name if name is not None else struck


def _target(flow: Mapping[str, Any], scrub: KnownScrubber) -> str:
    host = _host(flow.get("host", ""), scrub)
    if normalize_host(host) is None:
        # Not a host name or IP (so maybe cut): nothing goes after a text that may have been
        # cut, or the piece of a secret it ends with would sit in the middle (cut_tails).
        return host
    if ":" in host:
        host = f"[{host}]"
    port = flow.get("port")
    scheme = flow.get("scheme")
    if "path" not in flow or not isinstance(scheme, str) or scheme not in _DEFAULT_PORTS:
        return host if type(port) is not int else f"{host}:{port}"
    port_text = "" if port is None or _DEFAULT_PORTS.get(scheme) == port else f":{port}"
    return _cut(f"{scheme}://{host}{port_text}{_path(flow['path'], scrub)}", _LIMIT_PATH)


def _excerpt(body: bytes, scrub: KnownScrubber) -> tuple[str, bool]:
    """(excerpt, cut): the first EXCERPT_BYTES of the struck text."""
    window = body[: EXCERPT_BYTES + _MARGIN]
    struck = redact(scrub.text(window.decode("utf-8", errors="replace")))
    cut = len(body) > len(window)
    if cut:
        struck = struck[:-_MARGIN]  # as in _strike: the body went on past the window
    excerpt = _cut(struck, EXCERPT_BYTES)
    return excerpt, cut or excerpt != struck


def _is_text(media_type: str | None) -> bool:
    if media_type is None:
        return False
    return (
        media_type.startswith("text/") or media_type in _TEXT_TYPES or media_type.endswith("+json")
    )


def _body(flow: Mapping[str, Any], scrub: KnownScrubber, *, excerpt: bool) -> dict[str, Any]:
    body = flow.get("body")
    data = body if isinstance(body, bytes | bytearray) else b""
    media_type = _media_type(flow.get("headers"), scrub)
    info: dict[str, Any] = {"size": len(data), "type": media_type}
    method = str(flow.get("method", "")).upper()
    if excerpt and data and method not in _NO_EXCERPT_METHODS and _is_text(media_type):
        info["excerpt"], truncated = _excerpt(bytes(data), scrub)
        if truncated:
            info["excerpt_truncated"] = True
    return info


def _request_details(flow: Mapping[str, Any], scrub: KnownScrubber) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if "flow_id" in flow:
        details["flow_id"] = _opt_text(flow["flow_id"], scrub, _LIMIT_SHORT)
    if "method" in flow:
        details["method"] = _clean(flow["method"], scrub, _LIMIT_SHORT).upper()  # struck first
    if "scheme" in flow:
        details["scheme"] = _clean(flow["scheme"], scrub, _LIMIT_SHORT, lower=True)
    if "host" in flow:
        details["host"] = _host(flow["host"], scrub)
    if "port" in flow:
        details["port"] = _opt_int(flow["port"])
    if "path" in flow:
        details["path"] = _path(flow["path"], scrub)
    if "http_version" in flow:
        details["http_version"] = _opt_text(flow["http_version"], scrub, _LIMIT_SHORT)
    if "server_ip" in flow:
        details["server_ip"] = _opt_text(flow["server_ip"], scrub, _LIMIT_SHORT)
    if "headers" in flow:
        headers, cookies, dropped = _headers(flow["headers"], scrub)
        details["headers"] = headers
        if cookies:
            details["cookies"] = cookies
        if dropped:
            details["headers_dropped"] = dropped
    return details


def _finish(
    source: str, action: str, target: str, details: dict[str, Any], scrub: KnownScrubber
) -> dict[str, Any]:
    """The event, after a last pass of both strikes over everything (idempotent). The
    target is struck again whole: joining host and path could form a secret."""
    details = redact(scrub(details))
    target = _cut(redact(scrub.text(target)), _LIMIT_PATH)
    event = {
        "source": source,
        "action": action,
        "target": target,
        "risk": event_risk(source, action, details),
        "details": details,
    }
    return validate_event(event)


# --- the events ----------------------------------------------------------------------------------


def request_event(flow: Mapping[str, Any], secrets: Secrets) -> dict[str, Any]:
    """``net/request``: before the request goes out (it waits for its ``ack``)."""
    scrub = _scrubber(secrets)
    details = _request_details(flow, scrub)
    details["body"] = _body(flow, scrub, excerpt=True)
    return _finish("net", "request", _target(flow, scrub), details, scrub)


def llm_request_event(
    flow: Mapping[str, Any],
    provider: str,
    secrets: Secrets,
    *,
    provider_tools: Sequence[str] = (),
) -> dict[str, Any]:
    """``llm/request``: a request to a provider's host. Of its body, only metadata, and the
    provider-side tools that ``allow_provider_tools`` let through (T06-6), by name."""
    scrub = _scrubber(secrets)
    details = _request_details(flow, scrub)
    details["body"] = _body(flow, scrub, excerpt=False)
    details["provider"] = _clean(provider, scrub, _LIMIT_SHORT)
    details |= _llm_metadata(flow.get("body"), scrub)
    details["key"] = "swapped"
    if provider_tools:
        details["provider_tools"] = _names(provider_tools, scrub)
    return _finish("llm", "request", _target(flow, scrub), details, scrub)


def _llm_metadata(body: object, scrub: KnownScrubber) -> dict[str, Any]:
    meta: dict[str, Any] = {"model": None, "stream": None, "max_tokens": None,
                            "messages": None, "tools": None}  # fmt: skip
    try:
        data = json.loads(body) if isinstance(body, bytes | bytearray | str) else None
    except (ValueError, RecursionError):  # RecursionError: nested too deep
        return meta
    if not isinstance(data, dict):
        return meta
    if isinstance(data.get("model"), str):
        meta["model"] = _clean(data["model"], scrub, _LIMIT_NAME)
    if isinstance(data.get("stream"), bool):
        meta["stream"] = data["stream"]
    for name in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
        value = data.get(name)
        if type(value) is int and value >= 0:
            meta["max_tokens"] = value
            break
    messages = data.get("messages", data.get("input"))
    if isinstance(messages, list):
        meta["messages"] = len(messages)
    elif isinstance(messages, str):
        meta["messages"] = 1
    if isinstance(data.get("tools"), list):
        meta["tools"] = len(data["tools"])
    return meta


def _response_details(response: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": _opt_int(response.get("status")),
        "size": _opt_int(response.get("size")),
        "duration_ms": _opt_int(response.get("duration_ms")),
        "streamed": response.get("streamed") is True,
    }


def response_event(
    flow: Mapping[str, Any], response: Mapping[str, Any], secrets: Secrets
) -> dict[str, Any]:
    """``net/response``: when it ends. Size and type, never the body."""
    scrub = _scrubber(secrets)
    details: dict[str, Any] = {"flow_id": _opt_text(flow.get("flow_id"), scrub, _LIMIT_SHORT)}
    details |= _response_details(response)
    details["type"] = _media_type(response.get("headers"), scrub)
    return _finish("net", "response", _target(flow, scrub), details, scrub)


def llm_response_event(
    flow: Mapping[str, Any],
    provider: str,
    response: Mapping[str, Any],
    summary: Any,
    secrets: Secrets,
) -> dict[str, Any]:
    """``llm/response``: the summary of the answer (``sse.LlmSummary``), never its text."""
    scrub = _scrubber(secrets)
    details: dict[str, Any] = {
        "flow_id": _opt_text(flow.get("flow_id"), scrub, _LIMIT_SHORT),
        "provider": _clean(provider, scrub, _LIMIT_SHORT),
    }
    details |= _response_details(response)
    answer = summary.details()
    answer["model"] = _opt_text(answer.get("model"), scrub, _LIMIT_NAME)
    answer["stop_reason"] = _opt_text(answer.get("stop_reason"), scrub, _LIMIT_SHORT)
    answer["tool_calls"] = [_clean(name, scrub, _LIMIT_SHORT) for name in answer["tool_calls"]]
    details |= answer
    if summary.dropped:
        details["dropped"] = summary.dropped
    return _finish("llm", "response", _target(flow, scrub), details, scrub)


_SIDES = frozenset({"response"})
_MAX_NAMES = 16


def _names(names: Sequence[str], scrub: KnownScrubber) -> list[str]:
    """Tool names (the agent wrote them): struck, cut, at most _MAX_NAMES."""
    return [_clean(name, scrub, _LIMIT_SHORT) for name in list(names)[:_MAX_NAMES]]


def blocked_event(
    reason: str,
    flow: Mapping[str, Any],
    secrets: Secrets,
    *,
    tools: Sequence[str] = (),
    side: str | None = None,
) -> dict[str, Any]:
    """``net/blocked``: a refused request, with what is known of it (a ``CONNECT`` only
    knows its host and port). Never its body. ``tools``: the provider-side tools refused;
    ``side="response"``: what was refused is the provider's answer (T06-6). ValueError for an
    unknown reason or side."""
    scrub = _scrubber(secrets)
    if reason not in BLOCK_RISK:
        raise ValueError("unknown block reason")
    if side is not None and side not in _SIDES:
        raise ValueError("unknown side")
    details = {"reason": reason} | _request_details(flow, scrub)
    if tools:
        details["tools"] = _names(tools, scrub)
    if side is not None:
        details["side"] = side
    return _finish("net", "blocked", _target(flow, scrub), details, scrub)


def error_event(
    stage: str,
    *,
    error: str | None = None,
    sni: str | None = None,
    flow_id: str | None = None,
    host: str | None = None,
    port: int | None = None,
    secrets: Secrets,
) -> dict[str, Any]:
    """``net/error``: a transport failure, or a hook that failed (the flow was killed).
    ``error`` is the kind of error (its class name), never its message."""
    scrub = _scrubber(secrets)
    details = {
        "stage": _clean(stage, scrub, _LIMIT_SHORT),
        "error": _opt_text(error, scrub, _LIMIT_SHORT),
        "sni": _opt_text(sni, scrub, _LIMIT_NAME),
        "flow_id": _opt_text(flow_id, scrub, _LIMIT_SHORT),
        "host": None if host is None else _host(host, scrub),
        "port": _opt_int(port),
    }
    target = details["host"] or details["sni"] or ""
    return _finish("net", "error", target, details, scrub)


def tls_failed_event(
    sni: str | None, *, host: str | None, port: int | None, secrets: Secrets
) -> dict[str, Any]:
    """``net/tls_failed``: the agent did not accept our certificate (pinning, or a
    program that does not read our CA)."""
    scrub = _scrubber(secrets)
    details = {
        "sni": _opt_text(sni, scrub, _LIMIT_NAME),
        "host": None if host is None else _host(host, scrub),
        "port": _opt_int(port),
    }
    return _finish("net", "tls_failed", details["sni"] or details["host"] or "", details, scrub)


def websocket_event(
    action: str, flow: Mapping[str, Any], stats: Mapping[str, int | None], secrets: Secrets
) -> dict[str, Any]:
    """``net/websocket_start``, ``_summary`` or ``_end``: counts per direction and the
    close code. Never the content. ValueError for an unknown action or statistic."""
    scrub = _scrubber(secrets)
    if action not in _WEBSOCKET_ACTIONS:
        raise ValueError("unknown websocket action")
    if not set(stats) <= _WEBSOCKET_STATS:
        raise ValueError("unknown websocket statistic")
    details: dict[str, Any] = {
        "flow_id": _opt_text(flow.get("flow_id"), scrub, _LIMIT_SHORT),
        "host": _host(flow.get("host", ""), scrub),
        "path": _path(flow.get("path", ""), scrub),
    }
    details |= {name: _opt_int(value) for name, value in stats.items()}
    return _finish("net", action, _target(flow, scrub), details, scrub)


def throttled_event(count: int, window_s: int) -> dict[str, Any]:
    """``net/throttled``: requests refused by the budgets in the last ``window_s``."""
    return _finish("net", "throttled", "", {"count": count, "window_s": window_s}, _NO_SECRETS)


def dropped_event(count: int) -> dict[str, Any]:
    """``net/dropped``: events lost because the queue to backtide was full."""
    return _finish("net", "dropped", "", {"count": count}, _NO_SECRETS)
