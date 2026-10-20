"""The channel between the proxy and backtide: its messages, built and validated the same
way on both sides. Pure: no I/O.

One JSON object per line, MAX_LINE_BYTES at most (with its "\\n"). The proxy is exposed to
the agent, so backtide treats what it says as untrusted data: an event may only be ``net`` or
``llm``, with a known action, known detail keys, bounded sizes and the risk the table below
fixes (the proxy cannot choose it). Errors never quote the offending value.

| Message | Sent by | What |
|---|---|---|
| ``hello {version, pid}`` | proxy | When it starts |
| ``config {allow_hosts, providers, limits, provider_tools, fp_key}`` | backtide | The answer to ``hello``; holds the keys |
| ``request {id, event, gate?}`` / ``ack {id, verdict, seq, reason?, retry_after?, hold_id?, wait_ms?}`` | proxy / backtide | Before a request goes out |
| ``decision {hold_id, verdict, seq?, reason?}`` | backtide | The person's answer to a held request (T10) |
| ``released {hold_id}`` / ``hold_left {hold_id, why}`` | proxy | "I let it go" / "I no longer hold it" |
| ``event {event}`` | proxy | Anything that does not send a request out |
| ``ping`` / ``pong`` | both | Every few seconds |

The hold (T10-2, docs/32-diseno-t10-puerta.md, section 6): a ``net/request`` carries ``gate``,
the facts backtide decides on (its fingerprint, whether the redaction struck something of its
URL or of a header that is not a credential, how long that URL and those headers are, whether
it opens a WebSocket, whether its method is exactly a read with no override header and no
trailers, and how long its client waits). The ack may say ``hold``: its ``seq`` is the ``gate/held``
already recorded, ``hold_id`` names the hold and ``wait_ms`` is how long the proxy keeps the
request with its connection open. backtide's ``decision`` comes later: ``allow`` with the
``seq`` of the ``net/request`` already recorded, or ``deny``. The proxy answers each hold ack
with exactly one ``released`` (it let the request go) or ``hold_left`` (``client_left``,
``waited`` or ``no_slot``), unless a ``deny`` came, so an approval is spent exactly once.
``config`` carries ``fp_key``, the fingerprint key of this connection: like the real keys, it
lives in memory only and is never logged.

Design and rationale: docs/21-diseno-t06-proxy.md, section 5.
"""  # noqa: E501

import json
import re
import secrets
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

from backtide.gate.policy import normalize_pattern
from backtide.gate.provider_tools import check_allow_entry
from backtide.gate.providers import Kind, Provider, Providers, Secret

MAX_LINE_BYTES = 64 * 1024
MAX_TEXT = 4096  # bytes of any text inside a message
_MAX_ITEMS = 64  # entries of any list or mapping inside an event's details
_MAX_DEPTH = 3  # details -> headers -> value
_MAX_ID = 2**53 - 1  # exact in any JSON reader
_MAX_SEQ = 2**63 - 1
_MAX_ALLOW_HOSTS = 1000
_MAX_PROVIDERS = 32
MAX_PROVIDER_TOOLS = 64
MAX_WAIT_MS = 90_000  # a held request keeps its connection 90 s at most (decision 1)
MAX_WAIT_HINT_S = 90
_MAX_URL_BYTES = 2**31
HOLD_ID_RE = re.compile(r"h-[0-9a-f]{12}", re.ASCII)
_FP_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


class ProtocolError(ValueError):
    """A message that cannot be used. The text names the field, never its value."""


class Sender(StrEnum):
    PROXY = "proxy"
    BACKTIDE = "backtide"


_SENT_BY = {
    Sender.PROXY: frozenset({"hello", "request", "event", "released", "hold_left", "ping", "pong"}),
    Sender.BACKTIDE: frozenset({"config", "ack", "decision", "ping", "pong"}),
}

# --- events --------------------------------------------------------------------------------------

# Why a request was refused, and its fixed risk (docs/21, section 4).
BLOCK_RISK = {
    "port": 1,
    "private_address": 2,
    "host_mismatch": 2,
    "oauth_login": 2,
    "real_key": 3,
    "foreign_credential": 2,
    "too_large": 1,
    "throttled": 1,
    "not_recorded": 2,
    "not_allowed": 1,
    "undecodable": 2,  # a Content-Encoding the proxy cannot undo: its content cannot be checked
    # HTTP/1 trailers: mitmproxy 12.2.3 cannot read them, so the request can be neither checked
    # nor held (review of T10-2).
    "trailers": 2,
    # T06-6: what goes to a provider's host leaves with the real key (provider_tools.py).
    "provider_endpoint": 2,  # not one of the provider's model endpoints
    "provider_body": 2,  # a body that is not the provider's JSON: its tools cannot be checked
    "provider_side_tool": 2,  # a tool or connector that runs on the provider's side
    # T10-2: the same fingerprint was rejected (or expired) a moment ago: refused without asking.
    "gate_rejected": 1,
}
DENY_REASONS = frozenset({"not_allowed", "throttled", "not_recorded", "gate_rejected", "hold_full"})
# Why backtide denies a held request (``decision``), and why the proxy no longer holds one.
DECISION_REASONS = frozenset({"rejected", "expired", "paused", "hold_full"})
HOLD_LEFT_WHY = frozenset({"client_left", "waited", "no_slot"})
_GATE_KEYS = frozenset(
    {"fp", "url_struck", "url_bytes", "websocket", "exact_read", "wait_hint_s", "headers_struck",
     "header_bytes"}
)  # fmt: skip

_REQUEST_KEYS = frozenset(
    {"flow_id", "method", "scheme", "host", "port", "path", "http_version", "server_ip",
     "headers", "headers_dropped", "cookies"}
)  # fmt: skip
_LLM_RESPONSE_KEYS = frozenset(
    {"flow_id", "provider", "status", "model", "usage", "usage_missing", "stop_reason",
     "tool_calls", "tool_call_count", "complete", "duration_ms", "size", "streamed", "dropped"}
)  # fmt: skip
_WEBSOCKET_KEYS = frozenset(
    {"flow_id", "host", "path", "to_server_messages", "to_server_bytes", "to_client_messages",
     "to_client_bytes", "close_code"}
)  # fmt: skip

# (source, action) -> (fixed risk, or None when it depends on the reason; allowed detail keys)
EVENT_SCHEMA: dict[tuple[str, str], tuple[int | None, frozenset[str]]] = {
    ("net", "request"): (0, _REQUEST_KEYS | {"body"}),
    ("net", "response"): (
        0,
        frozenset({"flow_id", "status", "size", "type", "duration_ms", "streamed"}),
    ),
    # tools: the provider-side ones refused (provider_side_tool); side: "response" when what
    # was refused is the provider's answer (a real key in it: real_key, T06-6).
    ("net", "blocked"): (None, _REQUEST_KEYS | {"reason", "tools", "side"}),
    ("net", "error"): (1, frozenset({"stage", "error", "sni", "flow_id", "host", "port"})),
    ("net", "tls_failed"): (1, frozenset({"sni", "host", "port"})),
    ("net", "websocket_start"): (0, _WEBSOCKET_KEYS),
    ("net", "websocket_summary"): (0, _WEBSOCKET_KEYS),
    ("net", "websocket_end"): (0, _WEBSOCKET_KEYS),
    ("net", "throttled"): (1, frozenset({"count", "window_s"})),
    ("net", "dropped"): (1, frozenset({"count"})),
    ("llm", "request"): (
        0,
        _REQUEST_KEYS
        | {
            "provider",
            "model",
            "stream",
            "max_tokens",
            "messages",
            "tools",
            "key",
            "body",
            "provider_tools",
        },
    ),
    ("llm", "response"): (0, _LLM_RESPONSE_KEYS),
}
_EVENT_KEYS = frozenset({"source", "action", "target", "risk", "details"})


def event_risk(source: str, action: str, details: Mapping[str, Any]) -> int:
    """The fixed risk of an event (ProtocolError if the event is not in the schema)."""
    schema = EVENT_SCHEMA.get((source, action))
    if schema is None:
        raise ProtocolError("event: unknown source or action")
    risk, _ = schema
    if risk is not None:
        return risk
    reason = details.get("reason")
    if not isinstance(reason, str) or reason not in BLOCK_RISK:
        raise ProtocolError("event: unknown block reason")
    return BLOCK_RISK[reason]


def validate_event(value: object) -> dict[str, Any]:
    """A checked copy of an event the proxy sent (ProtocolError if it is not valid)."""
    if not isinstance(value, dict) or set(value) != _EVENT_KEYS:
        raise ProtocolError("event: wrong fields")
    source, action, target = value["source"], value["action"], value["target"]
    if not isinstance(source, str) or not isinstance(action, str):
        raise ProtocolError("event: unknown source or action")
    if source not in {"net", "llm"}:
        raise ProtocolError("event: the proxy only writes net and llm events")
    _text(target, "event.target", allow_empty=True)
    details = value["details"]
    if not isinstance(details, dict):
        raise ProtocolError("event.details: not an object")
    schema = EVENT_SCHEMA.get((source, action))
    if schema is None:
        raise ProtocolError("event: unknown source or action")
    if not set(details) <= schema[1]:
        raise ProtocolError(f"event.details: unknown keys for {source}/{action}")
    _json_tree(details, "event.details", depth=0)
    risk = value["risk"]
    if type(risk) is not int or risk != event_risk(source, action, details):
        raise ProtocolError(f"event.risk: not the fixed risk of {source}/{action}")
    return {"source": source, "action": action, "target": target, "risk": risk,
            "details": json.loads(json.dumps(details))}  # fmt: skip


def _json_tree(value: object, where: str, depth: int) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SEQ:
            raise ProtocolError(f"{where}: number out of range")
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ProtocolError(f"{where}: not a finite number")
        return
    if isinstance(value, str):
        _text(value, where, allow_empty=True)
        return
    if depth >= _MAX_DEPTH:
        raise ProtocolError(f"{where}: nested too deep")
    if isinstance(value, list):
        if len(value) > _MAX_ITEMS:
            raise ProtocolError(f"{where}: too many items")
        for item in value:
            _json_tree(item, where, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > _MAX_ITEMS:
            raise ProtocolError(f"{where}: too many items")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError(f"{where}: a key is not a text")
            _text(key, where, allow_empty=True)
            _json_tree(item, where, depth + 1)
        return
    raise ProtocolError(f"{where}: not a JSON value")


def _text(value: object, where: str, *, allow_empty: bool = False, line: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ProtocolError(f"{where}: not a text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ProtocolError(f"{where}: not valid UTF-8") from None
    if size > MAX_TEXT:
        raise ProtocolError(f"{where}: too long")
    if line and not value.isprintable():
        raise ProtocolError(f"{where}: not a single printable line")
    return value


def _int(value: object, where: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ProtocolError(f"{where}: not an integer in range")
    return value


# --- builders ------------------------------------------------------------------------------------


def hello(version: str, pid: int) -> dict[str, Any]:
    return _check({"type": "hello", "version": version, "pid": pid})


def config(
    allow_hosts: Iterable[str],
    providers: Providers,
    limits: Mapping[str, int],
    *,
    provider_tools: Iterable[str] = (),
    fp_key: bytes | None = None,
) -> dict[str, Any]:
    """The configuration for the proxy. It holds the real keys in clear: never log it (use
    describe()), and drop it as soon as it is encoded. ``provider_tools``: the provider-side
    tools that may go to a provider anyway (``[proxy] allow_provider_tools``, T06-6).
    ``fp_key``: this connection's fingerprint key (T10-2; a fresh one if None)."""
    key = fp_key if fp_key is not None else secrets.token_bytes(32)
    message = {
        "type": "config",
        "allow_hosts": list(allow_hosts),
        "providers": [
            {
                "name": p.name,
                "kind": str(p.kind),
                "host": p.host,
                "fake_key": p.fake_key,
                "real_key": p.real_key.reveal(),
                "models": list(p.models),
            }
            for p in providers.items
        ],
        "limits": dict(limits),
        "provider_tools": list(provider_tools),
        "fp_key": key.hex(),
    }
    return _check(message)


def request(
    request_id: int, event_: Mapping[str, Any], gate_: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """A request before it goes out. A ``net/request`` carries its ``gate`` facts (``gate()``);
    an ``llm/request`` (a provider's host: never held) carries none."""
    message: dict[str, Any] = {"type": "request", "id": request_id, "event": dict(event_)}
    if gate_ is not None:
        message["gate"] = dict(gate_)
    return _check(message)


def gate(
    *,
    fp: str,
    url_struck: bool,
    url_bytes: int,
    websocket: bool,
    exact_read: bool,
    headers_struck: bool,
    header_bytes: int,
    wait_hint_s: int | None = None,
) -> dict[str, Any]:
    """The facts of a ``net/request`` that backtide decides on (docs/32, section 6): its exact
    fingerprint (64 hex), whether the redaction struck something of its URL, the URL's length in
    bytes, whether it opens a WebSocket, whether its method is exactly GET, HEAD or OPTIONS (and
    it has no method override header and no trailers), whether the redaction struck something
    of a header that is not a credential and how many bytes those headers have (decision 1's
    guard on the headers), and how long its client waits (a translator's hint, T10-3; None:
    90 s)."""
    facts = {"fp": fp, "url_struck": url_struck, "url_bytes": url_bytes, "websocket": websocket,
             "exact_read": exact_read, "wait_hint_s": wait_hint_s,
             "headers_struck": headers_struck, "header_bytes": header_bytes}  # fmt: skip
    return _check_gate(facts)


def ack(
    request_id: int,
    verdict: str,
    *,
    seq: int | None = None,
    reason: str | None = None,
    retry_after: int | None = None,
    hold_id: str | None = None,
    wait_ms: int | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {"type": "ack", "id": request_id, "verdict": verdict, "seq": seq}
    if reason is not None:
        message["reason"] = reason
    if retry_after is not None:
        message["retry_after"] = retry_after
    if hold_id is not None:
        message["hold_id"] = hold_id
    if wait_ms is not None:
        message["wait_ms"] = wait_ms
    return _check(message)


def decision(
    hold_id: str, verdict: str, *, seq: int | None = None, reason: str | None = None
) -> dict[str, Any]:
    """backtide's answer to a held request: ``allow`` with the ``seq`` of its ``net/request``
    (recorded already), or ``deny`` with one of DECISION_REASONS."""
    message: dict[str, Any] = {"type": "decision", "hold_id": hold_id, "verdict": verdict}
    if seq is not None:
        message["seq"] = seq
    if reason is not None:
        message["reason"] = reason
    return _check(message)


def released(hold_id: str) -> dict[str, Any]:
    return _check({"type": "released", "hold_id": hold_id})


def hold_left(hold_id: str, why: str) -> dict[str, Any]:
    return _check({"type": "hold_left", "hold_id": hold_id, "why": why})


def event(event_: Mapping[str, Any]) -> dict[str, Any]:
    return _check({"type": "event", "event": dict(event_)})


def ping() -> dict[str, Any]:
    return {"type": "ping"}


def pong() -> dict[str, Any]:
    return {"type": "pong"}


# --- limits and providers ------------------------------------------------------------------------

DEFAULT_LIMITS = {
    "max_connections": 256,
    "max_pending": 32,
    "max_queue": 1000,
    "ack_timeout_ms": 5000,
    "ping_interval_ms": 5000,
    "max_holds": 8,  # held requests with their connection open at once (docs/32, section 6)
}
_LIMIT_RANGES = {
    "max_connections": (1, 4096),
    "max_pending": (1, 256),
    "max_queue": (1, 100_000),
    "ack_timeout_ms": (100, 60_000),
    "ping_interval_ms": (500, 60_000),
    "max_holds": (1, 64),
}
_PROVIDER_KEYS = frozenset({"name", "kind", "host", "fake_key", "real_key"})


def providers_from_config(message: Mapping[str, Any]) -> Providers:
    """The providers of a ``config`` message, with each real key inside a Secret."""
    items = message.get("providers")
    if not isinstance(items, list) or len(items) > _MAX_PROVIDERS:
        raise ProtocolError("config.providers: not a list of providers")
    built = []
    for entry in items:
        if not isinstance(entry, dict) or not _PROVIDER_KEYS <= set(entry) <= _PROVIDER_KEYS | {
            "models"
        }:
            raise ProtocolError("config.providers: wrong fields")
        if not all(isinstance(entry[key], str) for key in _PROVIDER_KEYS):
            raise ProtocolError("config.providers: a field is not a text")
        models = entry.get("models", [])
        if not isinstance(models, list):
            raise ProtocolError("config.providers: models is not a list")
        try:
            built.append(
                Provider(
                    name=entry["name"],
                    kind=Kind(entry["kind"]) if entry["kind"] in set(Kind) else entry["kind"],
                    host=entry["host"],
                    fake_key=entry["fake_key"],
                    real_key=Secret(entry["real_key"]),
                    models=tuple(models),
                )
            )
        except ValueError:
            # Provider's own messages never hold a key, but only the field is named here.
            raise ProtocolError("config.providers: a provider is not valid") from None
    try:
        return Providers(built)
    except ValueError:
        raise ProtocolError("config.providers: two providers clash") from None


def describe(message: Mapping[str, Any]) -> str:
    """A line for the log: the type and, for a config, names and counts. Never a key."""
    kind = message.get("type")
    if kind == "config":
        names = [p.get("name") for p in message.get("providers", []) if isinstance(p, dict)]
        hosts = message.get("allow_hosts", [])
        return (
            f"config: providers {', '.join(str(n) for n in names) or '-'}; "
            f"{len(hosts) if isinstance(hosts, list) else '?'} allowed hosts"
        )
    if kind in {"request", "ack"}:
        return f"{kind} {message.get('id')}"
    if kind in {"decision", "released", "hold_left"}:
        hold_id = message.get("hold_id")
        valid = isinstance(hold_id, str) and HOLD_ID_RE.fullmatch(hold_id)
        return f"{kind} {hold_id if valid else '?'}"
    return str(kind) if kind in _SENT_BY[Sender.PROXY] | _SENT_BY[Sender.BACKTIDE] else "?"


# --- validation ----------------------------------------------------------------------------------


def _check(message: dict[str, Any]) -> dict[str, Any]:
    """A checked, normalized copy of ``message`` (ProtocolError if it is not valid)."""
    kind = message.get("type")
    if not isinstance(kind, str) or kind not in _CHECKERS:
        raise ProtocolError("message: unknown type")
    return _CHECKERS[kind](message)


def _fields(message: Mapping[str, Any], required: set[str], optional: set[str] = set()) -> None:  # noqa: B006
    keys = set(message) - {"type"}
    if not required <= keys or not keys <= required | optional:
        raise ProtocolError(f"{message['type']}: wrong fields")


def _check_hello(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"version", "pid"})
    version = _text(message["version"], "hello.version", line=True)
    if len(version) > 64:
        raise ProtocolError("hello.version: too long")
    return {"type": "hello", "version": version, "pid": _int(message["pid"], "hello.pid", 1, 2**31)}


def _check_config(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"allow_hosts", "providers", "limits", "fp_key"}, {"provider_tools"})
    fp_key = message["fp_key"]
    if not isinstance(fp_key, str) or not _FP_RE.fullmatch(fp_key):
        raise ProtocolError("config.fp_key: not 32 bytes in hex")
    hosts = message["allow_hosts"]
    if not isinstance(hosts, list) or len(hosts) > _MAX_ALLOW_HOSTS:
        raise ProtocolError("config.allow_hosts: not a list of hosts")
    try:
        allow = list(dict.fromkeys(normalize_pattern(host) for host in hosts))
    except ValueError:
        raise ProtocolError("config.allow_hosts: a host is not valid") from None
    providers = providers_from_config(message)
    tools = message.get("provider_tools", [])
    if not isinstance(tools, list) or len(tools) > MAX_PROVIDER_TOOLS:
        raise ProtocolError("config.provider_tools: not a list of tool names")
    try:
        allowed_tools = list(dict.fromkeys(check_allow_entry(tool) for tool in tools))
    except ValueError:
        raise ProtocolError("config.provider_tools: a tool name is not valid") from None
    limits = message["limits"]
    if not isinstance(limits, dict) or not set(limits) <= set(DEFAULT_LIMITS):
        raise ProtocolError("config.limits: unknown limits")
    checked = dict(DEFAULT_LIMITS)
    for name, value in limits.items():
        checked[name] = _int(value, f"config.limits.{name}", *_LIMIT_RANGES[name])
    return {
        "type": "config",
        "allow_hosts": allow,
        "providers": [
            {
                "name": p.name,
                "kind": str(p.kind),
                "host": p.host,
                "fake_key": p.fake_key,
                "real_key": p.real_key.reveal(),
                "models": list(p.models),
            }
            for p in providers.items
        ],
        "limits": checked,
        "provider_tools": allowed_tools,
        "fp_key": fp_key,
    }


def _check_request(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"id", "event"}, {"gate"})
    checked = validate_event(message["event"])
    if checked["action"] != "request":
        raise ProtocolError("request.event: not a request")
    result = {"type": "request", "id": _int(message["id"], "request.id", 1, _MAX_ID),
              "event": checked}  # fmt: skip
    # Every net/request is decided on its gate facts; a provider's (llm) is never held.
    if checked["source"] == "net":
        if "gate" not in message:
            raise ProtocolError("request.gate: a net request needs its gate facts")
        result["gate"] = _check_gate(message["gate"])
    elif "gate" in message:
        raise ProtocolError("request.gate: only for a net request")
    return result


def _check_gate(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _GATE_KEYS:
        raise ProtocolError("request.gate: wrong fields")
    fp = value["fp"]
    if not isinstance(fp, str) or not _FP_RE.fullmatch(fp):
        raise ProtocolError("request.gate.fp: not a fingerprint")
    for name in ("url_struck", "websocket", "exact_read", "headers_struck"):
        if type(value[name]) is not bool:
            raise ProtocolError(f"request.gate.{name}: not a boolean")
    hint = value["wait_hint_s"]
    return {
        "fp": fp,
        "url_struck": value["url_struck"],
        "url_bytes": _int(value["url_bytes"], "request.gate.url_bytes", 0, _MAX_URL_BYTES),
        "websocket": value["websocket"],
        "exact_read": value["exact_read"],
        "headers_struck": value["headers_struck"],
        "header_bytes": _int(value["header_bytes"], "request.gate.header_bytes", 0, _MAX_URL_BYTES),
        "wait_hint_s": None
        if hint is None
        else _int(hint, "request.gate.wait_hint_s", 1, MAX_WAIT_HINT_S),
    }


def _hold_id(value: object, where: str) -> str:
    if not isinstance(value, str) or not HOLD_ID_RE.fullmatch(value):
        raise ProtocolError(f"{where}: not a hold id")
    return value


def _check_event(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"event"})
    checked = validate_event(message["event"])
    if checked["action"] == "request":
        raise ProtocolError("event: a request goes through request and ack")
    return {"type": "event", "event": checked}


def _check_ack(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"id", "verdict", "seq"}, {"reason", "retry_after", "hold_id", "wait_ms"})
    checked: dict[str, Any] = {"type": "ack", "id": _int(message["id"], "ack.id", 1, _MAX_ID)}
    verdict, seq = message["verdict"], message["seq"]
    reason, retry_after = message.get("reason"), message.get("retry_after")
    if verdict == "hold":
        if reason is not None or "hold_id" not in message or "wait_ms" not in message:
            raise ProtocolError("ack: a hold has a hold_id and a wait, and no reason")
        checked |= {
            "verdict": "hold",
            "seq": _int(seq, "ack.seq", 1, _MAX_SEQ),
            "hold_id": _hold_id(message["hold_id"], "ack.hold_id"),
            "wait_ms": _int(message["wait_ms"], "ack.wait_ms", 0, MAX_WAIT_MS),
            "retry_after": _int(retry_after, "ack.retry_after", 1, 3600),
        }
        return checked
    if "hold_id" in message or "wait_ms" in message:
        raise ProtocolError("ack: only a hold has a hold_id")
    if verdict == "allow":
        if reason is not None or retry_after is not None:
            raise ProtocolError("ack: an allow has no reason")
        checked |= {"verdict": "allow", "seq": _int(seq, "ack.seq", 1, _MAX_SEQ)}
        return checked
    if verdict != "deny":
        raise ProtocolError("ack.verdict: not allow, deny or hold")
    if not isinstance(reason, str) or reason not in DENY_REASONS:
        raise ProtocolError("ack.reason: not a known reason")
    checked["verdict"] = "deny"
    checked["seq"] = None if seq is None else _int(seq, "ack.seq", 1, _MAX_SEQ)
    checked["reason"] = reason
    if retry_after is not None:
        if reason != "throttled":
            raise ProtocolError("ack.retry_after: only when throttled")
        checked["retry_after"] = _int(retry_after, "ack.retry_after", 1, 3600)
    return checked


def _check_decision(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"hold_id", "verdict"}, {"seq", "reason"})
    checked: dict[str, Any] = {
        "type": "decision",
        "hold_id": _hold_id(message["hold_id"], "decision.hold_id"),
    }
    verdict = message["verdict"]
    if verdict == "allow":
        if "reason" in message:
            raise ProtocolError("decision: an allow has no reason")
        checked |= {
            "verdict": "allow",
            "seq": _int(message.get("seq"), "decision.seq", 1, _MAX_SEQ),
        }
        return checked
    if verdict != "deny":
        raise ProtocolError("decision.verdict: not allow or deny")
    if "seq" in message:
        raise ProtocolError("decision: a deny has no seq")
    reason = message.get("reason")
    if not isinstance(reason, str) or reason not in DECISION_REASONS:
        raise ProtocolError("decision.reason: not a known reason")
    checked |= {"verdict": "deny", "reason": reason}
    return checked


def _check_released(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"hold_id"})
    return {"type": "released", "hold_id": _hold_id(message["hold_id"], "released.hold_id")}


def _check_hold_left(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, {"hold_id", "why"})
    why = message["why"]
    if not isinstance(why, str) or why not in HOLD_LEFT_WHY:
        raise ProtocolError("hold_left.why: not a known reason")
    return {"type": "hold_left", "hold_id": _hold_id(message["hold_id"], "hold_left.hold_id"),
            "why": why}  # fmt: skip


def _check_bare(message: dict[str, Any]) -> dict[str, Any]:
    _fields(message, set())
    return {"type": message["type"]}


_CHECKERS = {
    "hello": _check_hello,
    "config": _check_config,
    "request": _check_request,
    "ack": _check_ack,
    "event": _check_event,
    "decision": _check_decision,
    "released": _check_released,
    "hold_left": _check_hold_left,
    "ping": _check_bare,
    "pong": _check_bare,
}


# --- lines ---------------------------------------------------------------------------------------


def encode(message: Mapping[str, Any], sender: Sender) -> bytes:
    """One checked line, with its "\\n". ProtocolError if ``sender`` does not send this
    type, the message is not valid or the line is over MAX_LINE_BYTES."""
    checked = _check(dict(message))
    if checked["type"] not in _SENT_BY[Sender(sender)]:
        raise ProtocolError(f"{checked['type']}: not sent by the {sender}")
    line = json.dumps(checked, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    data = line.encode("ascii") + b"\n"
    if len(data) > MAX_LINE_BYTES:
        raise ProtocolError(f"{checked['type']}: over {MAX_LINE_BYTES} bytes")
    return data


def decode(line: bytes, sender: Sender) -> dict[str, Any]:
    """The checked message in ``line`` (with or without its "\\n"), sent by ``sender``."""
    if len(line) > MAX_LINE_BYTES:
        raise ProtocolError(f"line: over {MAX_LINE_BYTES} bytes")
    body = line[:-1] if line.endswith(b"\n") else line
    if b"\n" in body:
        raise ProtocolError("line: more than one line")
    try:
        message = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):  # Recursion: nested too deep
        raise ProtocolError("line: not a JSON object") from None
    if not isinstance(message, dict):
        raise ProtocolError("line: not a JSON object")
    kind = message.get("type")
    if not isinstance(kind, str) or kind not in _CHECKERS:
        raise ProtocolError("message: unknown type")
    # Who may send it is checked first: a config from the proxy is not even read.
    if kind not in _SENT_BY[Sender(sender)]:
        raise ProtocolError(f"{kind}: not sent by the {sender}")
    return _check(message)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    raise ValueError("NaN and Infinity are not JSON")


class LineReader:
    """Splits a byte stream into lines of at most MAX_LINE_BYTES (with their "\\n").
    ProtocolError as soon as a line passes the limit, even before its end arrives: the
    connection is then closed, never read further."""

    def __init__(self, limit: int = MAX_LINE_BYTES) -> None:
        self._limit = limit
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer += chunk
        lines: list[bytes] = []
        while True:
            end = self._buffer.find(b"\n")
            if end == -1:
                break
            if end + 1 > self._limit:
                raise ProtocolError(f"line: over {self._limit} bytes")
            lines.append(bytes(self._buffer[: end + 1]))
            del self._buffer[: end + 1]
        if len(self._buffer) >= self._limit:
            raise ProtocolError(f"line: over {self._limit} bytes")
        return lines
