"""Search and read APIs used only by ``POST``: Tavily, Exa and Firecrawl (docs/32, section 8 and
decision 13). Their search and read endpoints are reads, so a web search is not a notice. Pure.

- READ: the endpoints of the table, with a strict JSON object for a body; ``GET`` and ``HEAD``
  without a body; and the extra ``[gate] read_endpoints`` (``host/path``, exact).
- UNKNOWN (held): a body that asks the service to act for the agent (``webhook``, ``callback``,
  Firecrawl's page ``actions``: click, type, run JavaScript), a body over 64 KiB, a body that
  carries a secret the strike found (risk 3), a body with a URL over 2 KiB (the guard of
  docs/32 decision 1 on the URLs a read service is asked to fetch: risk 2, as for a long URL),
  and any other path or method.
"""

import re
from dataclasses import replace
from typing import Any

from backtide.gate.policy import normalize_host
from backtide.gate.translate.base import (
    MAX_NODES,
    MAX_READ_BODY,
    READ_METHODS,
    URL_CHARS,
    WAIT_DEFAULT,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    body_has_secret,
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
_URL_RE = re.compile(r"(?i)[a-z][a-z0-9+.-]{0,31}://[^\s\"'<>\\]*+")


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
    take other bodies, which are still searched for secrets. The whole body is searched, at
    most MAX_READ_BODY of it, and so is each URL in it."""
    if len(view.body) > MAX_READ_BODY:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.TOO_LARGE)
    texts = [view.body.decode("utf-8", "replace")]
    try:
        kind = media_type(view.headers)
        if kind in (None, "application/json"):
            body = json_object(view.body or b"{}")
            if _remote(body):
                return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.REMOTE_ACTIONS)
            texts.extend(_strings(body))
        elif strict:
            raise Unreadable
    except Unreadable as error:
        if strict:
            return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note)
    urls = [url for text in texts for url in _URL_RE.findall(text)]
    if body_has_secret(view.body, context.scrub) or any(
        has_secret(url, context.scrub) for url in urls
    ):
        reading = unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.SECRET_SEEN)
        return replace(reading, secret_seen=True)
    if any(len(url) > URL_CHARS for url in urls):
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, Note.LONG_URL)
    return Reading(NAME, operation, Effect.READ, Shape.PLAIN, WAIT_DEFAULT)


def _strings(body: dict[str, Any]) -> list[str]:
    """Every text in a JSON body, at any depth (its URLs are found as the service reads them,
    with JSON's escapes undone). Bounded by MAX_NODES."""
    found: list[str] = []
    stack: list[object] = [body]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise Unreadable(Note.TOO_LARGE)
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


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
