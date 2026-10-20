"""Search and read APIs used only by ``POST``: Tavily, Exa and Firecrawl (docs/32, section 8 and
decision 13). Their search and read endpoints are reads, so a web search is not a notice. Pure.

- READ: the endpoints of the table, with a strict JSON object for a body; ``GET`` and ``HEAD``
  without a body; and the extra ``[gate] read_endpoints`` (``host/path``, exact).
- UNKNOWN (held): a body that asks the service to act for the agent (``webhook``, ``callback``,
  Firecrawl's page ``actions``: click, type, run JavaScript), a body that carries a secret the
  strike found (risk 3, the guard of docs/32 decision 1), and any other path or method.
"""

from dataclasses import replace
from typing import Any

from backtide.gate.policy import normalize_host
from backtide.gate.translate.base import (
    MAX_NODES,
    READ_METHODS,
    WAIT_DEFAULT,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    has_secret,
    json_object,
    media_type,
    parse_pairs,
    split_path,
    unknown,
)

NAME = "read_post"
_VERSIONED = frozenset({"api.firecrawl.dev"})
_VERSIONS = frozenset({"v0", "v1", "v2"})
_ENDPOINTS: dict[str, frozenset[tuple[str, ...]]] = {
    "api.tavily.com": frozenset({("search",), ("extract",), ("crawl",), ("map",)}),
    "api.exa.ai": frozenset({("search",), ("contents",), ("findsimilar",), ("answer",)}),
    "api.firecrawl.dev": frozenset(
        {("scrape",), ("crawl",), ("map",), ("search",), ("extract",), ("batch", "scrape")}
    ),
}
HOSTS = frozenset(_ENDPOINTS)
# Keys that make a read service act or call out for the agent: never a plain read.
_REMOTE_KEYS = frozenset(
    {"webhook", "webhooks", "webhookurl", "webhook_url", "callback", "callbackurl",
     "callback_url", "notify_url", "actions"}
)  # fmt: skip


def check_read_endpoint(entry: object) -> str:
    """A ``[gate] read_endpoints`` entry, ``host/path`` (no scheme, no query), normalized as
    ``read`` compares it. Raises ValueError, with a message that is safe to show."""
    if not isinstance(entry, str) or "/" not in entry or "?" in entry or "://" in entry:
        raise ValueError("a read endpoint is host/path, without scheme or query")
    host, _, path = entry.partition("/")
    name = normalize_host(host, idna=True)
    try:
        segments, _query = split_path("/" + path)
    except Unreadable:
        raise ValueError("a read endpoint's path must be plain: no dots, escapes or //") from None
    if name is None:
        raise ValueError("a read endpoint needs a valid host")
    return name + "/" + "/".join(segment.lower() for segment in segments)


def claims(view: RequestView, context: Context) -> bool:
    return view.host in HOSTS or any(
        entry.partition("/")[0] == view.host for entry in context.read_endpoints
    )


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
        parse_pairs(query)
    except Unreadable as error:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note)
    lowered = tuple(segment.lower() for segment in segments)
    if view.method in READ_METHODS:
        if view.body:
            return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.UNPARSED)
        return Reading(NAME, "get", Effect.READ, Shape.PLAIN, WAIT_DEFAULT)
    if view.method != "POST":
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT)
    if view.host + "/" + "/".join(lowered) in context.read_endpoints:
        return _checked(view, context, "configured", strict=False)
    path = lowered
    if view.host in _VERSIONED and path[:1] and path[0] in _VERSIONS:
        path = path[1:]
    if path in _ENDPOINTS.get(view.host, frozenset()):
        return _checked(view, context, "/".join(path), strict=True)
    return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT)


def _checked(view: RequestView, context: Context, operation: str, *, strict: bool) -> Reading:
    """A read, unless the body asks the service to act for the agent or carries a secret.
    ``strict``: the body must be a JSON object (the built-in table); a configured endpoint may
    take other bodies, which are still searched for secrets."""
    try:
        kind = media_type(view.headers)
        if kind in (None, "application/json"):
            if _remote(json_object(view.body or b"{}")):
                return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.REMOTE_ACTIONS)
        elif strict:
            raise Unreadable
    except Unreadable as error:
        if strict:
            return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note)
    if has_secret(view.body.decode("utf-8", "replace"), context.scrub):
        reading = unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.SECRET_SEEN)
        return replace(reading, secret_seen=True)
    return Reading(NAME, operation, Effect.READ, Shape.PLAIN, WAIT_DEFAULT)


def _remote(body: dict[str, Any]) -> bool:
    """Whether any key, at any depth, is one of _REMOTE_KEYS. Bounded by MAX_NODES."""
    stack: list[object] = [body]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise Unreadable(Note.TOO_LARGE)
        if isinstance(item, dict):
            if any(key in _REMOTE_KEYS for key in item):
                return True
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False
