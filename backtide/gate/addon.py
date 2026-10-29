"""The gate: mitmproxy's hooks, thin, over the pure pieces of backtide/gate.

Design: docs/21-diseno-t06-proxy.md, sections 4 to 8. What each hook does:

- ``client_connected``: only clients that came in through the proxy's address on the agent's
  network, and at most ``max_connections`` at once; any other is cut.
- ``http_connect``: a ``CONNECT`` to a port other than 80 or 443 is refused (``port``).
- ``requestheaders``: no channel, no request (503, ``not_recorded``); at most ``max_pending``
  requests that may have a body, reading it or waiting for their ack, and ``max_pending_reads``
  without one (T17b-1: npm 9 sends a whole install at once), waiting for their ack (429,
  ``throttled``; one with a body over its places is cut instead); a body over the
  limit is refused before it is read (413, ``too_large``); an HTTP/1 request that announces
  trailers is cut (``trailers``: mitmproxy 12.2.3 cannot read them, so it could be neither
  checked nor held). One whose body never reached the ``request`` hook (mitmproxy's reader
  failed: an HTTP/1 trailer that was not announced) is recorded when its client goes
  (``net/error {stage: request_unread}``), and its place is given back.
- ``request`` (async): the fixed rules, in this order: port, the real key anywhere (URL, every
  header, the trailers, the raw and the decoded body: ``real_key``, on any host), a
  ``Content-Encoding`` that cannot be undone (``undecodable``), ``Host`` against the
  connection and the SNI (``host_mismatch``), OAuth logins, and on a provider's host the fake
  key swapped for the real one (``foreign_credential`` otherwise) and only a model call with the
  client's own tools (``provider_endpoint``, ``provider_body`` or ``provider_side_tool``
  otherwise: provider_tools.py, T06-6). A provider that waits for its key (the owner has not
  set it) is checked the same, and then always refused in its own API's error shape
  (``no_key``, recorded by backtide as ``llm/blocked``): nothing goes to it. An IP literal
  that is not public, also written as numbers (``127.1``, ``0x7f.1``), is ``private_address``
  before backtide is asked. Then backtide is asked (``request`` -> ``ack``): only with
  ``allow`` and a ``seq`` (the event is in the black box) does the request go on.
  ``connection_strategy=lazy`` means no server was contacted so far.
- ``server_connect`` (async): only for a host and port that an ack let through on this client
  connection; the name is resolved here, EVERY address must be public, and the connection is
  pinned to the address that was checked (the SNI keeps the name).
- ``responseheaders``/``response``: every response streams through a tap that counts it and,
  for a provider, reads the usage (SSE or JSON, bounded); then ``net/response`` or
  ``llm/response``. Never the body. A provider's answer is checked for the real key before it
  reaches the agent (echo.py, T06-6): a plain SSE stream event by event, anything else whole
  (mitmproxy holds it until the ``response`` hook). On a hit the flow is killed, or the stream
  cut at once, and ``net/blocked {reason: real_key, side: response}`` (risk 3) is queued.
- ``error``, ``tls_failed_client`` and the WebSocket hooks: ``net/error``, ``net/tls_failed``
  and the WebSocket summaries; a client message with a real key kills the WebSocket.

**A local provider** (T20, docs/35 section 6.2): the agent calls it by its virtual name
(``<provider>.backtide.internal``, https, port 443). It must carry exactly its fake key, which is
dropped (no credential goes on), and only its routes pass, compared exactly
(``provider_tools.exact_endpoint``), with the same check of the body and its listed models. Once
backtide has recorded it (``llm/request {local: true, upstream, key: "none"}``), the request is
rewritten to ``http://<IPv4>:<port>`` (and its ``Host``), the fixed address backtide resolved on
its side; ``server_connect`` opens exactly that pair for exactly that client without resolving
anything. Any other private address stays ``private_address``, that same IP on another port too.
A redirection (3xx) or a protocol switch (101) of a local provider never reaches the agent: a 502
and ``net/blocked {reason: local_redirect, side: response}``. Every refusal toward it says
``local: true`` (risk 3 on one of Ollama's administration routes).

**OpenAI's streamed usage** (T11, docs/33 "include_usage", stream_usage.py): a streamed Chat
Completions call to a public ``openai`` provider whose body has no ``stream_options`` gets
``"stream_options":{"include_usage":true}`` inserted after its opening brace, once the rewritten
body passed the same provider check; backtide records it as sent (``include_usage: "added"``,
the body's size as sent) and the rewrite is applied only after the ack. The extra usage chunk is
read by the tap and dropped before it reaches the agent (``drop_usage_events``). Never toward a
local provider, never on a compressed body or one the rewrite would take past BODY_LIMIT.

**Any exception in a hook kills the flow** (mitmproxy carries on after a hook raises, T06-1
P7): before the request has gone out the agent gets a 502, after it the flow is killed, and a
``net/error {stage}`` is queued. If even that fails the process exits: a dead proxy lets
nothing out. The log never gets a request's data, only error kinds and counts.

mitmproxy is never imported here (``respond`` builds the responses; main.py hands in
mitmproxy's), so the Mac tests run the hooks on small fakes of mitmproxy's objects.
"""

import asyncio
import dataclasses
import functools
import logging
import os
import re
import socket
import time
import zlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from backtide.gate import protocol, record
from backtide.gate.client import Ack, Channel, GateConfig, Slot
from backtide.gate.decide import READ_METHODS
from backtide.gate.echo import KeyEcho, KeyScanner, SseGuard
from backtide.gate.fingerprint import credential_id, fingerprint
from backtide.gate.policy import (
    host_mismatch,
    is_ip,
    is_oauth_login,
    is_public,
    normalize_host,
    numeric_ipv4,
    port_allowed,
)
from backtide.gate.provider_tools import check_request, endpoint_of
from backtide.gate.providers import (
    CREDENTIAL_HEADERS,
    LOCAL_SUFFIX,
    NO_KEY,
    Provider,
    blocked_response,
    only_fake_key,
    swap_key,
)
from backtide.gate.sse import UsageStream, summarize_json
from backtide.gate.stream_usage import drop_usage_events, usage_insert_at, with_include_usage
from backtide.gate.translate import credential_free_path, shapes, translate
from backtide.gate.translate.base import (
    OVERRIDE_HEADERS,
    Context,
    Note,
    Reading,
    RequestView,
    Shape,
    body_has_secret,
    override_of,
    unknown,
)

logger = logging.getLogger(__name__)

BODY_LIMIT = 16 * 1024 * 1024  # body_size_limit of main.py (docs/21, section 8)
JSON_SUMMARY_LIMIT = 1 << 20  # a provider's non-streamed answer is summarized up to 1 MiB
# Bytes of providers' answers held whole at once (each is BODY_LIMIT at most; one without a
# length counts as that much). Past it, the answer is not let through: the proxy keeps to its
# memory (1 GiB) whatever the agent asks for at the same time.
HELD_BUDGET = 128 * 1024 * 1024
WEBSOCKET_SUMMARY_EVERY = 2.0  # seconds
HOLD_POLL = 0.25  # seconds: how often a held request looks whether its client is still there
# Bytes of a read's headers (but the credentials) the redaction reads for decision 1's guard.
# Past 2 KiB the read is held anyway (risk 2); past this much it is not read at all, and counts
# as struck (risk 3): what cannot be checked is not let out as a plain read.
HEADER_SCAN_LIMIT = 64 * 1024
EXIT_CODE = 70

REFUSALS = {
    "not_recorded": (503, "backtide: nothing goes out until it can be recorded\n"),
    "not_allowed": (403, "backtide: this host is not on the allowed list\n"),
    "throttled": (429, "backtide: too many requests, try again later\n"),
    "port": (403, "backtide: only ports 80 and 443 go out\n"),
    "private_address": (403, "backtide: only public addresses go out\n"),
    "host_mismatch": (403, "backtide: the Host header must name the connection's host\n"),
    "oauth_login": (403, "backtide: OAuth logins are not allowed from the agent\n"),
    "real_key": (403, "backtide: a real key never leaves through the agent\n"),
    "foreign_credential": (403, "backtide: only the fake key works with this provider\n"),
    "too_large": (413, "backtide: the body is over the limit\n"),
    "undecodable": (400, "backtide: this Content-Encoding cannot be checked\n"),
    "trailers": (400, "backtide: HTTP/1 trailers cannot be checked, so this request is refused\n"),
    "malformed_header": (400, "backtide: a header or its framing is malformed\n"),
    "provider_endpoint": (403, "backtide: only the provider's model endpoints are allowed\n"),
    "provider_body": (400, "backtide: a model request must be the provider's JSON\n"),
    "provider_side_tool": (
        403,
        "backtide: tools that run on the provider's side are not allowed (allow_provider_tools)\n",
    ),
    # The gate (T10-2, docs/32 section 6): plain text until the translators give each API its
    # own shape (T10-3). No client repeats a 403.
    "rejected": (403, "backtide: the person rejected this request\n"),
    "expired": (403, "backtide: nobody answered in 5 min, so this request is rejected\n"),
    "paused": (403, "backtide: the agent was paused, so this request is rejected\n"),
    "hold_full": (
        403,
        "backtide: too many requests are waiting for approval; this one is refused\n",
    ),
    "gate_rejected": (
        403,
        "backtide: this same request was rejected a moment ago; it is not asked again\n",
    ),
    # T11: a provider's call gets its own API's error shape (providers.blocked_response); this
    # plain text is only for a request that is not a provider's (it never happens).
    "spend_cap": (429, "backtide: spending cap reached; ask the owner\n"),
    "spend_unavailable": (503, "backtide: the spending cannot be counted right now\n"),
    NO_KEY: (400, "backtide: no key set yet for this model provider\n"),
    # T20: never sent to the agent; the 502 that replaces it is LOCAL_REDIRECT.
    "local_redirect": (502, "backtide: a local model's redirection never reaches the agent\n"),
}
SPEND_REASONS = frozenset({"spend_cap", "spend_unavailable"})
# The refusals of a model call that the proxy answers in the provider's own error shape.
PROVIDER_REASONS = SPEND_REASONS | {NO_KEY}
FAILED = (502, "backtide: the gate failed, so nothing went out\n")

Respond = Callable[[int, bytes, Mapping[str, str]], Any]
Resolve = Callable[[str, int], Any]  # an awaitable of addresses


def _die() -> None:
    os._exit(EXIT_CODE)


async def resolve(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to (A and AAAA), as the proxy's own resolver says."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _guard_request_phase(stage: str) -> Callable[..., Any]:
    """Wrap a hook that runs before the request went out: any error answers 502."""

    def wrap(hook: Callable[..., Any]) -> Callable[..., Any]:
        if asyncio.iscoroutinefunction(hook):

            @functools.wraps(hook)
            async def run_async(self: "Gate", flow: Any) -> None:
                try:
                    await hook(self, flow)
                except Exception as error:
                    self._failed(stage, flow, error, before=True)

            return run_async

        @functools.wraps(hook)
        def run(self: "Gate", flow: Any) -> None:
            try:
                hook(self, flow)
            except Exception as error:
                self._failed(stage, flow, error, before=True)

        return run

    return wrap


def _guard_after(stage: str) -> Callable[..., Any]:
    """Wrap a hook that runs once the request went out: any error kills the flow."""

    def wrap(hook: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(hook)
        def run(self: "Gate", flow: Any) -> None:
            try:
                hook(self, flow)
            except Exception as error:
                self._failed(stage, flow, error, before=False)

        return run

    return wrap


class _Tap:
    """``flow.response.stream``: every chunk is counted and, for a provider, read for its usage
    and held back by ``guard`` until it is checked for the real key (whole SSE events only).
    Anything else passes at once. A failure, or a key, stops the stream for good: from then on
    not one byte more goes to the agent (it never raises)."""

    def __init__(
        self,
        gate: "Gate",
        flow: Any,
        provider: Provider | None,
        media: str,
        guard: SseGuard | None = None,
        *,
        drop_usage: bool = False,
    ) -> None:
        self._gate = gate
        self._flow = flow
        self._guard = guard
        # T11: the usage chunk the proxy asked for is read (count) and then not passed on.
        self._drop_usage = drop_usage and guard is not None
        self.size = 0
        self.kind = None if provider is None else str(provider.kind)
        self._sse = UsageStream(self.kind) if self.kind and media == "text/event-stream" else None
        self._json: bytearray | None = bytearray() if self.kind and self._sse is None else None
        self.stopped = False

    def __call__(self, chunk: bytes) -> bytes:
        if self.stopped:
            return b""
        try:
            self.count(chunk)
            if self._guard is None:
                return chunk
            ready = self._guard.feed(chunk) if chunk else self._guard.finish()
            return drop_usage_events(ready) if self._drop_usage and ready else ready
        except KeyEcho:
            self.stopped = True
            self._gate._key_in_answer(self._flow)
            return b""
        except Exception as error:
            self.stopped = True
            self._gate._failed("response_stream", self._flow, error, before=False)
            return b""

    def count(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self._sse is not None:
            self._sse.feed(chunk)
        elif self._json is not None:
            if len(self._json) + len(chunk) <= JSON_SUMMARY_LIMIT:
                self._json += chunk
            else:
                self._json = None  # too big to summarize: usage_missing

    def summary(self) -> Any:
        if self._sse is not None:
            return self._sse.finish()
        if self.kind is None:
            raise RuntimeError("a summary of an answer that is not a provider's")
        return summarize_json(self.kind, bytes(self._json or b""))


class Gate:
    """The addon. ``agent_side`` is the proxy's own addresses on the agent's network (only
    clients that came in through them are served); ``public`` are addresses the VM tests let
    through as if they were public (their fake internet: never set in production)."""

    def __init__(
        self,
        channel: Channel,
        *,
        respond: Respond,
        agent_side: Callable[[], frozenset[str]],
        resolve: Resolve = resolve,
        public: frozenset[str] = frozenset(),
        clock: Callable[[], float] = time.monotonic,
        die: Callable[[], None] = _die,
    ) -> None:
        self._channel = channel
        self._respond = respond
        self._agent_side_of = agent_side
        self._resolve = resolve
        self._public = public
        self._clock = clock
        self._die = die
        self.agent_side: frozenset[str] = frozenset()
        self._clients: set[str] = set()
        self._waiting: set[str] = set()  # flows reading their body or waiting for their ack
        self._bodies: set[str] = set()  # those of them that may have a body (max_pending)
        # Flows whose request hook has not come yet: flow id -> (client id, what is known).
        self._reading: dict[str, tuple[str, dict[str, Any]]] = {}
        self._acked: dict[str, set[tuple[str, int]]] = {}  # client id -> targets let through
        # T20: client id -> the local providers' (IPv4, port) an ack let through for it.
        self._local_acked: dict[str, set[tuple[str, int]]] = {}
        self._scanner_of: tuple[GateConfig, KeyScanner] | None = None
        self.held_bytes = 0  # reserved by the providers' answers held whole right now

    # Clients

    def running(self) -> None:
        try:
            self.agent_side = self._agent_side_of()
        except Exception:
            logger.exception("cannot learn the proxy's agent-side address: nobody is let in")
            self.agent_side = frozenset()
        if not self.agent_side:
            logger.error("no agent-side address: no client will be let in")

    def client_connected(self, client: Any) -> None:
        try:
            local = _plain_ip(str(client.sockname[0]))
            if local not in self.agent_side:
                client.error = "backtide: only the agent's side may use the proxy"
                return
            if len(self._clients) >= self._channel.limits["max_connections"]:
                client.error = "backtide: too many connections"
                self._channel.count_throttled()
                return
            self._clients.add(client.id)
        except Exception:
            logger.exception("checking a client failed: stopping the proxy")
            self._die()

    def client_disconnected(self, client: Any) -> None:
        try:
            self._clients.discard(client.id)
            self._acked.pop(client.id, None)
            self._local_acked.pop(client.id, None)
            self._forget_unread(client.id)
        except Exception:
            logger.exception("forgetting a client failed: stopping the proxy")
            self._die()

    def _stop_waiting(self, flow_id: str) -> None:
        """A request no longer waits for its ack (answered, held, failed or gone): its place,
        among those with a body or those without, is free."""
        self._waiting.discard(flow_id)
        self._bodies.discard(flow_id)

    def _forget_unread(self, client_id: str) -> None:
        """The requests of a client that is gone whose body never reached the request hook nor
        the error hook (mitmproxy's reader failed on them): recorded, and their place given
        back. Nothing of them went out."""
        for flow_id, (owner, fields) in list(self._reading.items()):
            if owner != client_id:
                continue
            del self._reading[flow_id]
            self._stop_waiting(flow_id)
            self._tell_error(
                "request_unread", None, flow_id=flow_id, host=fields["host"], port=fields["port"]
            )

    # Requests

    @_guard_request_phase("http_connect")
    def http_connect(self, flow: Any) -> None:
        if not port_allowed(flow.request.port):
            self._block("port", flow, {"host": flow.request.host, "port": flow.request.port})
        elif self._private_literal(flow.request.host) or self._unknown_virtual(flow.request.host):
            self._block(
                "private_address", flow, {"host": flow.request.host, "port": flow.request.port}
            )

    @_guard_request_phase("requestheaders")
    def requestheaders(self, flow: Any) -> None:
        # Never a streamed request: mitmproxy would send its headers and body to the server
        # BEFORE the request hook, that is, before backtide has recorded it. The body is read
        # whole (16 MiB at most, ``body_size_limit``), then checked, recorded and only then sent.
        flow.request.stream = False
        if _announces_http1_trailers(flow.request):
            # mitmproxy 12.2.3 raises on an HTTP/1 request's trailers before the request hook:
            # it could be neither checked nor held. Cut now (an answer would have mitmproxy read
            # the body, and fail on them anyway), and recorded.
            self._channel.tell(
                record.blocked_event("trailers", self._flow_fields(flow), self._channel.scrubber)
            )
            flow.kill()
            return
        body = _may_have_body(flow.request)
        limits = self._channel.limits
        if (
            len(self._bodies) >= limits["max_pending"]
            if body
            else len(self._waiting) - len(self._bodies) >= limits["max_pending_reads"]
        ):
            self._channel.count_throttled()
            if body:
                # mitmproxy reads (and keeps) the body of a request that already has its answer,
                # so a 429 would not save the memory: the request is cut instead (T06-7).
                flow.kill()
            else:
                self._answer(flow, "throttled", retry_after=1)
            return
        length = flow.request.headers.get("content-length")
        if length is not None and (not length.strip().isdigit() or int(length) > BODY_LIMIT):
            # mitmproxy refuses it too (body_size_limit) and never reads its body.
            self._block("too_large", flow, self._flow_fields(flow))
            return
        if not self._channel.ready:
            self._refuse_unrecorded(flow)
            if not body:
                return
        # Every request whose body mitmproxy reads holds a place until its request (or error)
        # hook, the refused ones too: at most max_pending bodies of 16 MiB in memory.
        self._waiting.add(flow.id)
        if body:
            self._bodies.add(flow.id)
        fields = self._flow_fields(flow)
        self._reading[flow.id] = (flow.client_conn.id, {k: fields[k] for k in ("host", "port")})

    @_guard_request_phase("request")
    async def request(self, flow: Any) -> None:
        self._reading.pop(flow.id, None)
        try:
            await self._request(flow)
        finally:
            self._stop_waiting(flow.id)

    async def _request(self, flow: Any) -> None:
        if flow.response is not None:
            return  # already refused by an earlier hook: it never goes out
        config = self._channel.config
        if config is None or not self._channel.ready:
            self._refuse_unrecorded(flow)
            return
        request = flow.request
        _frame_h2_body(request)
        fields = self._flow_fields(flow)
        trailers_present = request.trailers is not None and len(_header_pairs(request.trailers)) > 0
        reason = _malformed_framing(request, trailers_present)
        if reason is not None:
            # Request smuggling (docs/incidentes.md, 2026-10-22): a header the proxy would write
            # as is to an HTTP/1.1 upstream could reframe the request. Refused before anything
            # else, for every version, and recorded. HTTP/2 trailers (none on h1 reach here:
            # _announces_http1_trailers cut them) are refused like h1's (B5).
            self._block(reason, flow, fields)
            return
        if not port_allowed(request.port):
            self._block("port", flow, fields)
            return
        headers = _header_pairs(request.headers)
        trailers = _header_pairs(request.trailers) if request.trailers is not None else []
        refusal = None
        try:
            body: bytes | None = decode_body(
                request.raw_content, request.headers.get("content-encoding"), sent=True
            )
        except Undecodable as error:
            body, refusal = None, error.reason
        parts = [request.url, request.host, request.raw_content, body, flow.client_conn.sni]
        parts += [text for pair in headers + trailers for text in pair]
        if config.providers.real_key_in(*parts):
            self._block("real_key", flow, fields)
            logger.error("a request carried a real key: refused")
            return
        if refusal is not None:
            self._block(refusal, flow, fields)
            return
        encoded = _encoded(request)
        if self._private_literal(request.host):
            # A fixed rule, before the allowed list (which never allows an IP): risk 2, not 1.
            # After the real key's search, so a real key towards one is still real_key (risk 3).
            self._block("private_address", flow, fields)
            return
        if host_mismatch(
            request.host,
            request.host_header,
            connect_port=request.port,
            sni=flow.client_conn.sni,
        ):
            self._block("host_mismatch", flow, fields)
            return
        if is_oauth_login(request.host, request.path):
            self._block("oauth_login", flow, fields)
            return
        fields["body"] = body
        provider = config.providers.for_host(request.host)
        if encoded is not None and provider is None:
            # What leaves is what was read (security review of the G1 fix): a deflate stream has
            # room of its own (empty stored blocks, free Huffman tables) that decodes to nothing,
            # so the owner would approve "ok" and megabytes would leave. The body goes out
            # decoded, as backtide checked and recorded it; its raw bytes still count in the
            # fingerprint. A chunked body mitmproxy frames again; a length is made true. (To a
            # provider, check_request refuses an encoded body: no model client sends one.)
            request.raw_content = body
            del request.headers["content-encoding"]
            if _has_header(request, "content-length"):
                request.headers["content-length"] = str(len(body or b""))
            headers = _header_pairs(request.headers)
        if provider is None and self._unknown_virtual(request.host):
            # T20: a virtual name of backtide's that no local provider has. It stands for a
            # private place and is never resolved: refused before backtide is asked.
            del fields["body"]
            self._block("private_address", flow, fields)
            return
        swapped = None
        usage_at: int | None = None  # T11: where include_usage goes in the body, if it does
        if provider is not None:
            local = provider.local
            if local and provider.upstream is None:
                # The channel never hands one so: fail closed (the guard answers 502).
                raise RuntimeError("a local provider without its address")
            if local:  # T20: the fake key and nothing else, and then no credential at all
                swapped = ok = only_fake_key(
                    provider, headers, scheme=request.scheme, port=request.port
                )
            elif provider.waiting:  # checked as if it had its key; refused after backtide's say
                ok = only_fake_key(provider, headers, scheme=request.scheme, port=request.port)
            else:
                swapped = ok = swap_key(provider, headers, scheme=request.scheme, port=request.port)
            if ok is None:
                self._block("foreign_credential", flow, fields, local=local)
                return
            # What goes there leaves with the real key: only a model call with the client's own
            # tools, never one that has the provider reach other hosts for the agent (T06-6).
            # A local provider (and Ollama's cloud): only its routes, compared exactly (T20).
            verdict = check_request(
                str(provider.kind),
                request.method,
                request.path,
                headers,
                body,
                allowed=config.provider_tools,
                models=provider.models,
                trailers=trailers,
                exact=provider.exact_paths,
                local=local,
            )
            if verdict.reason is not None:
                self._block(verdict.reason, flow, fields, tools=verdict.tools, local=local)
                if verdict.reason == "provider_side_tool":
                    logger.warning("a model request with provider-side tools: refused")
                return
            endpoint = endpoint_of(
                str(provider.kind),
                request.method,
                request.path,
                headers,
                exact=provider.exact_paths,
                models=provider.models,
            )
            if not local and not provider.waiting and provider.stream_usage:
                usage_at = self._plan_usage(
                    provider, endpoint, request, headers, body, verdict, trailers
                )
                if usage_at is not None:
                    # Recorded as it will be sent (applied in _let_through, after the ack): the
                    # body and its Content-Length.
                    fields["body"] = with_include_usage(body or b"", usage_at)
                    fields["headers"] = _with_length(fields["headers"], len(fields["body"]))
            event = record.llm_request_event(
                fields,
                provider.name,
                config.scrubber,
                provider_tools=verdict.tools,
                endpoint=endpoint,
                upstream=provider.upstream if local else None,
                include_usage=usage_at is not None,
            )
            gate = None  # a provider's host is never held (docs/32, section 5, rule 1)
            shape = None
        else:
            event = record.request_event(fields, config.scrubber)
            reading = self._read(request, headers, body, config, trailers)
            gate = self._gate_facts(request, headers, body, config, trailers, reading, encoded)
            shape = None if reading is None else reading.shape
            reading = None  # its canonical text lives no longer than the fingerprint needs
        # Up to max_pending requests wait for their ack at once: each keeps only mitmproxy's raw
        # body, never a decoded copy of up to 16 MiB as well (T06-7).
        del fields["body"]
        body = parts = None
        ack = await self._channel.ask(event, gate)
        if ack.held:
            await self._hold(flow, ack, fields, shape)
            return
        if provider is not None and ack.allowed and (flow.response is not None or _gone(flow)):
            # T11 (security review, M1): a model call backtide let out whose client went (or that
            # was answered) while it waited: it never goes out, and backtide frees its place and
            # charges nothing only because it is told so.
            if flow.response is None:
                flow.kill()
            self._tell_error(
                "not_sent",
                None,
                flow_id=fields["flow_id"],
                host=fields["host"],
                port=fields["port"],
                upstream=False,
            )
            return
        if flow.response is not None:
            return  # killed or answered meanwhile
        if provider is not None and provider.waiting and ack.allowed:
            # Backtide says no_key for a provider without its key: an allow here is a bug of
            # its, and there is no real key to send. Never sent (fail closed): its place in the
            # spending cap is given back and the agent gets the no_key answer.
            logger.error("backtide let a call to a provider without its key through: refused")
            self._tell_error(
                "not_sent",
                None,
                flow_id=fields["flow_id"],
                host=fields["host"],
                port=fields["port"],
                upstream=False,
            )
            self._provider_refusal(flow, provider, NO_KEY)
            return
        if not ack.allowed:
            if provider is not None and ack.reason in PROVIDER_REASONS:
                # T11 and no_key: in the provider's own error shape (backtide recorded it).
                self._provider_refusal(flow, provider, str(ack.reason))
                return
            self._denied(flow, ack, fields, shape)
            return
        self._let_through(flow, fields, provider, swapped, usage_at)

    def _plan_usage(
        self,
        provider: Provider,
        endpoint: str | None,
        request: Any,
        headers: list[tuple[str, str]],
        body: bytes | None,
        verdict: Any,
        trailers: list[tuple[str, str]],
    ) -> int | None:
        """T11 (stream_usage.py): where ``stream_options.include_usage`` goes in this call's
        body, or None. The rewritten body must pass the same provider check with the same tools,
        or the call goes as the agent wrote it (it passed already) and the error is logged."""
        at = usage_insert_at(str(provider.kind), endpoint, headers, body, limit=BODY_LIMIT)
        if at is None or body is None:
            return None
        config = self._channel.config
        if config is None:
            return None
        again = check_request(
            str(provider.kind),
            request.method,
            request.path,
            headers,
            with_include_usage(body, at),
            allowed=config.provider_tools,
            models=provider.models,
            trailers=trailers,
            exact=provider.exact_paths,
            local=provider.local,
        )
        if again.reason is not None or again.tools != verdict.tools:
            logger.error("the include_usage rewrite would change the provider check: not added")
            return None
        return at

    def _provider_refusal(self, flow: Any, provider: Provider, reason: str) -> None:
        """A model call refused in ``provider``'s own API's error shape."""
        status, text, extra = blocked_response(str(provider.kind), reason, provider.name)
        flow.response = self._respond(status, text, extra)

    def _read(
        self,
        request: Any,
        headers: list[tuple[str, str]],
        body: bytes | None,
        config: GateConfig,
        trailers: list[tuple[str, str]],
    ) -> Reading | None:
        """What a translator reads of the request (docs/32, section 8), or None when none
        knows its host. The body is the decoded one, so its Content-Encoding (identity, gzip or
        deflate, undone above) is left out of what the translator sees."""
        view = RequestView.from_fields(
            {
                "method": request.method,
                "scheme": request.scheme,
                "host": request.host,
                "port": request.port,
                "path": request.path,
                "headers": [p for p in headers if p[0].strip().lower() != "content-encoding"],
                "body": body or b"",
            },
            trailers=bool(trailers),
        )
        return translate(view, self._context(config))

    def _context(self, config: GateConfig) -> Context:
        return Context(
            key=config.fp_key, scrub=config.scrubber, read_endpoints=config.read_endpoints
        )

    def _gate_facts(
        self,
        request: Any,
        headers: list[tuple[str, str]],
        body: bytes | None,
        config: GateConfig,
        trailers: list[tuple[str, str]],
        reading: Reading | None = None,
        encoded: bytes | None = None,
    ) -> dict[str, Any]:
        """What backtide decides a request on (docs/32, section 6): its fingerprint (every header
        but the volatile ones, and the trailers, count: security review of T10-2, M2; with a
        translator's reading, its canonical text in place of the body, decision 2), the
        redaction's verdict on its URL (the API's own credential in the path left out) and on
        its headers that are not credentials (names and values), their lengths, the credentials'
        and whether the redaction struck something of them (T10-3 and its review, H1), a
        WebSocket opening, whether its method is exactly a read with no method override header
        and no trailers (M2: either makes it a write), whether the body of a request no
        translator read carries a secret, and the reading itself, checked and fitted."""
        fp = fingerprint(
            config.fp_key,
            method=str(request.method),
            host=normalize_host(request.host) or str(request.host),
            port=request.port,
            path=str(request.path),
            headers=headers,
            body=body,
            trailers=trailers,
            canonical=None if reading is None else reading.canonical,
            encoded=encoded,
        )
        overridden = any(name.strip().lower() in OVERRIDE_HEADERS for name, _ in headers)
        plain = [pair for pair in headers if pair[0].strip().lower() not in CREDENTIAL_HEADERS]
        credentials = [pair for pair in headers if pair[0].strip().lower() in CREDENTIAL_HEADERS]
        header_bytes = sum(len(_utf8(name)) + len(_utf8(value)) for name, value in plain)
        credential_bytes = sum(len(_utf8(name)) + len(_utf8(value)) for name, value in credentials)
        path = str(request.path)
        if reading is not None:
            path = credential_free_path(self._view_of(request), self._context(config), reading)
        return protocol.gate(
            fp=fp,
            url_struck=record.path_struck(path, config.scrubber)
            or record.host_struck(request.host, config.scrubber),
            url_bytes=len(_utf8(str(request.url))),
            websocket=any(name.strip().lower() == "upgrade" for name, _ in headers),
            exact_read=request.method in READ_METHODS and not overridden and not trailers,
            # M3: a GET can carry a secret in a header as well as in its URL.
            headers_struck=header_bytes > HEADER_SCAN_LIMIT
            or record.headers_struck(plain, config.scrubber),
            header_bytes=header_bytes,
            credential_bytes=credential_bytes,
            # Review of T10-3, H1: a recognisable token in a credential header is the agent's
            # own only toward the API it belongs to; backtide holds it toward any other host.
            credentials_struck=credential_bytes > HEADER_SCAN_LIMIT
            or record.headers_struck(credentials, config.scrubber, names=False),
            # A translated request's body is the translator's to search (secret_seen).
            body_struck=reading is None and bool(body) and body_has_secret(body, config.scrubber),
            wait_hint_s=None if reading is None else reading.wait_s,
            reading=None if reading is None else _wire_reading(reading),
            # Security review of T10-4: what a batch must not cover (A1) and whose token it is
            # (M1, never recorded: only backtide's memory compares it).
            override=override_of(headers),
            trailers=bool(trailers),
            credential_id=credential_id(config.fp_key, credentials),
        )

    @staticmethod
    def _view_of(request: Any) -> RequestView:
        """The request's method, connection host and path: what ``credential_free_path``
        picks the translator by."""
        return RequestView.from_fields(
            {"method": request.method, "host": request.host, "port": request.port,
             "path": request.path}
        )  # fmt: skip

    async def _hold(
        self, flow: Any, ack: Ack, fields: dict[str, Any], shape: Shape | None = None
    ) -> None:
        """A held request: kept with its connection open until backtide decides, its client
        leaves or ``wait_ms`` passes. Every hold ack is answered with exactly one ``released``
        or ``hold_left`` (none after a deny), so a yes is spent exactly once. ``shape``: how its
        API writes "pending" and "rejected" (a translator's, T10-3); None: plain text."""
        hold_id = str(ack.hold_id)
        self._stop_waiting(flow.id)  # a held request no longer waits for its ack
        if flow.response is not None or self._client_gone(flow):
            if flow.response is None:
                flow.kill()
            self._channel.let_go(hold_id, why="client_left", slot=False)
            return
        # HTTP/2 and 3: mitmproxy 12.2.3 queues a client's RST_STREAM behind this hook (the
        # stream's layer is paused until it returns), so nothing here could tell that the client
        # cancelled it: released later, it would go out with nobody waiting, and with its retry,
        # twice (security review of T10-2, B1). Such a request is never kept: "pending" at once,
        # and a yes becomes a preapproval that its retry spends, once.
        multiplexed = str(flow.request.http_version).upper().startswith(("HTTP/2", "HTTP/3"))
        if multiplexed or self._channel.hold(hold_id) is not Slot.TAKEN:
            # No slot (max_holds, an identical request waits already, or HTTP/2): "pending" at
            # once, and the hold lives on in backtide. A twin must not give back the slot of the
            # request that waits (M1): it never had one.
            self._channel.let_go(hold_id, why="no_slot", slot=False)
            self._pending(flow, hold_id, ack.retry_after, shape)
            return
        told = False
        try:
            deadline = self._clock() + (ack.wait_ms or 0) / 1000
            decision = None
            while decision is None:
                if self._client_gone(flow):
                    break
                remaining = deadline - self._clock()
                if remaining <= 0:
                    break
                decision = await self._channel.decision(hold_id, min(HOLD_POLL, remaining))
            if decision is None or (decision.verdict == "allow" and self._client_gone(flow)):
                if self._client_gone(flow):
                    # Never sent later: its client gave up, and a retry may come (docs/32, Q3).
                    flow.kill()
                    self._channel.let_go(hold_id, why="client_left")
                else:
                    self._channel.let_go(hold_id, why="waited")
                    self._pending(flow, hold_id, ack.retry_after, shape)
                told = True
                return
            if decision.verdict == "allow" and decision.seq is not None:
                self._channel.let_go(hold_id, released=True)
                told = True
                self._let_through(flow, fields, None, None)
                return
            self._channel.let_go(hold_id)  # a deny, or the channel is gone: nothing to say
            told = True
            if decision.verdict == "deny" and decision.reason in REFUSALS:
                self._answer(flow, decision.reason, shape=shape, hold_id=hold_id)
            else:
                self._refuse_unrecorded(flow, fields)
        finally:
            if not told:  # this hook failed: the guard answers 502, and backtide must know
                self._channel.let_go(hold_id, why="client_left")

    def _client_gone(self, flow: Any) -> bool:
        """Its connection ended, or mitmproxy marked the flow failed (``flow.error``: a reset
        stream once its queued events run, a kill)."""
        conn = flow.client_conn
        if getattr(flow, "error", None) is not None:
            return True
        return getattr(conn, "timestamp_end", None) is not None or conn.id not in self._clients

    def _pending(
        self, flow: Any, hold_id: str, retry_after: int | None, shape: Shape | None = None
    ) -> None:
        """429: still waiting for the person, ask again in a while (never in a loop). In the
        shape of its API when a translator read it, so its client retries on its own."""
        seconds = retry_after if retry_after is not None else 30
        if shape is not None:
            answer = shapes.pending(shape, hold_id, seconds)
            flow.response = self._respond(answer.status, answer.body, dict(answer.headers))
            return
        text = (
            f"backtide: waiting for the person's approval (hold {hold_id}); "
            f"try again in {seconds} s or so, not in a loop\n"
        )
        headers = {"content-type": "text/plain", "retry-after": str(seconds)}
        flow.response = self._respond(429, text.encode(), headers)

    def _let_through(
        self,
        flow: Any,
        fields: dict[str, Any],
        provider: Provider | None,
        swapped: list[tuple[str, str]] | None,
        usage_at: int | None = None,
    ) -> None:
        """The request is recorded and may go out: the connection it needs is let open."""
        request = flow.request
        if provider is not None and swapped is None:
            # Never to a provider without the real key in its place (the guard answers 502).
            raise RuntimeError("a call to a provider without its key swapped")
        if usage_at is not None and swapped is not None:
            # T11: the body as backtide recorded it (with_include_usage raises, so the guard
            # answers 502, if it is not the one the rewrite was planned on).
            request.raw_content = with_include_usage(request.raw_content or b"", usage_at)
            swapped = _with_length(swapped, len(request.raw_content))
        if request.raw_content:
            # Belt (request smuggling, docs/incidentes.md 2026-10-22): the request leaves framed,
            # for every version and after the include_usage rewrite. A chunked body mitmproxy
            # frames itself; otherwise exactly one Content-Length, equal to the body's length (so
            # _frame_h2_body and the rewrite both land). Else UnframedBody: the guard answers 502
            # and records net/error. Checked on the headers that go out (``swapped`` for a
            # provider, else the request's own, which _frame_h2_body already fixed).
            outgoing = swapped if swapped is not None else _header_pairs(request.headers)
            lengths = [
                int(v.strip()) if v.strip().isdigit() else -1
                for n, v in outgoing
                if n.strip().lower() == "content-length"
            ]
            chunked = any(
                n.strip().lower() == "transfer-encoding" and "chunked" in v.lower()
                for n, v in outgoing
            )
            if not (chunked or (len(lengths) == 1 and lengths[0] == len(request.raw_content))):
                raise UnframedBody("a request body leaves without a single matching length")
        upstream = provider.upstream if provider is not None and provider.local else None
        if provider is not None and provider.local and upstream is None:
            raise RuntimeError("a local provider without its address")
        if swapped is not None:
            # An answer the tap can read: compressed, its usage would be lost (usage_missing).
            swapped = [pair for pair in swapped if pair[0].lower() != "accept-encoding"]
            swapped.append(("accept-encoding", "identity"))
            if upstream is not None:  # T20: the Host header names where it really goes
                swapped = [pair for pair in swapped if pair[0].lower() != "host"]
                swapped.append(("host", f"{upstream[0]}:{upstream[1]}"))
            request.headers.fields = tuple(
                (name.encode("utf-8", "surrogateescape"), value.encode("utf-8", "surrogateescape"))
                for name, value in swapped
            )
        if upstream is not None:
            # T20 (docs/35, section 6.2, step 7): to the fixed address backtide resolved, in clear
            # (Ollama has no TLS). The scheme first: mitmproxy rebuilds Host from the three.
            request.scheme = "http"
            request.host = upstream[0]
            request.port = upstream[1]
            self._local_acked.setdefault(flow.client_conn.id, set()).add(upstream)
        else:
            host = normalize_host(request.host) or request.host
            self._acked.setdefault(flow.client_conn.id, set()).add((host, request.port))
        flow.metadata["backtide"] = {
            "provider": provider,
            # The answer is checked for the keys of the config this request went out with.
            "scanner": self._scanner() if provider is not None else None,
            "start": self._clock(),
            "fields": {key: fields[key] for key in ("flow_id", "scheme", "host", "port", "path")},
        }
        if usage_at is not None:
            flow.metadata["backtide"]["drop_usage"] = True

    def _denied(
        self, flow: Any, ack: Ack, fields: dict[str, Any], shape: Shape | None = None
    ) -> None:
        reason = ack.reason or "not_recorded"
        if reason == "not_recorded":
            self._refuse_unrecorded(flow, fields)
            return
        # not_allowed and throttled are backtide's: it recorded or counted them already.
        self._answer(flow, reason, retry_after=ack.retry_after, shape=shape)

    async def server_connect(self, data: Any) -> None:
        try:
            await self._server_connect(data)
        except Exception as error:
            logger.error("server_connect failed (%s): no connection", type(error).__name__)
            try:
                data.server.error = "backtide: the gate failed"
            except Exception:
                logger.exception("cannot refuse a server connection: stopping the proxy")
                self._die()
                return
            self._tell_error("server_connect", error)

    async def _server_connect(self, data: Any) -> None:
        raw_host, port = data.server.address
        host = normalize_host(raw_host) or str(raw_host)
        if self._local_target(data.client.id, host, port):
            # T20 (docs/35, section 6.2, step 8): exactly the pair of a local provider, for a
            # client an ack let through to it. Nothing is resolved.
            data.server.address = (host, port)
            return
        if (host, port) not in self._acked.get(data.client.id, set()):
            data.server.error = "backtide: no recorded request asked for this connection"
            self._tell_error("server_connect_unacked", None, host=host, port=port)
            return
        addresses = [host] if is_ip(host) else await self._resolve(host, port)
        chosen = self._pick(addresses)
        if chosen is None:
            data.server.error = "backtide: only public addresses go out"
            self._channel.tell(
                record.blocked_event(
                    "private_address", {"host": host, "port": port}, self._channel.scrubber
                )
            )
            return
        data.server.address = (chosen, port)

    def _local_target(self, client_id: str, host: str, port: object) -> bool:
        """Whether (``host``, ``port``) is exactly a local provider's upstream in the current
        config, acked for this client, and never one of the proxy's own addresses."""
        if (host, port) not in self._local_acked.get(client_id, set()):
            return False
        config = self._channel.config
        if config is None or type(port) is not int or host in self.agent_side:
            return False
        return config.providers.local_at(host, port) is not None

    def _unknown_virtual(self, raw_host: object) -> bool:
        """Whether the host is under ``.backtide.internal`` and no local provider of the current
        config has it (T20): such a name is never resolved, so it is refused."""
        host = normalize_host(raw_host)
        if host is None or not (host.endswith(LOCAL_SUFFIX) or host == LOCAL_SUFFIX[1:]):
            return False
        config = self._channel.config
        provider = None if config is None else config.providers.for_host(host)
        return provider is None or not provider.local

    def _private_literal(self, raw_host: object) -> bool:
        """Whether the host is an IP literal that may not be reached (server_connect would
        refuse it too, but only once backtide had been asked)."""
        host = normalize_host(raw_host)
        if host is None:
            return False
        if not is_ip(host):
            # 127.1, 0x7f.1, 2130706433: the resolver reads them as addresses (inet_aton).
            host = numeric_ipv4(host)
            if host is None:
                return False
        return self._pick([host]) is None

    def _pick(self, addresses: Iterable[str]) -> str | None:
        """policy.pick_address, where the VM tests' fake internet counts as public."""
        candidates = list(addresses)
        if not candidates or not all(a in self._public or is_public(a) for a in candidates):
            return None
        for address in candidates:
            if ":" not in address:
                return address
        return candidates[0]

    # Responses

    @_guard_after("responseheaders")
    def responseheaders(self, flow: Any) -> None:
        meta = flow.metadata.get("backtide")
        provider = meta["provider"] if meta else None
        if (
            provider is None
            and flow.response.status_code == 101
            and not _has_header(flow.request, "upgrade")
        ):
            # mitmproxy opens a WebSocket on the answer (a 101 to a request with
            # Sec-WebSocket-*), not on the request's Upgrade: a GET without Upgrade passed as a
            # read, even to an unknown host, would open one that no rule decided (security
            # review of T17b-1). Every request that names Upgrade is a WebSocket opening the
            # gate decided on (``_upgrade_refused``). A local model's 101 is held below.
            if meta is None:
                flow.kill()
            else:
                self._stop_answer(flow, "unrequested_upgrade")
            return
        headers = flow.response.headers
        media = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if provider is not None:
            if not self._provider_headers(flow, meta):
                return
            status = flow.response.status_code
            if provider.local and (status == 101 or 300 <= status < 400):
                # T20: a local model's redirection or protocol switch never reaches the agent:
                # held here (no byte of it goes on, within HELD_BUDGET), and replaced by a 502
                # in ``response``.
                flow.metadata["backtide_redirect"] = True
                self._hold_whole(flow, provider, media)
                return
            encoding = (headers.get("content-encoding") or "").strip().lower()
            if media != "text/event-stream" or encoding not in ("", "identity"):
                self._hold_whole(flow, provider, media)
                return
        guard = SseGuard(meta["scanner"]) if provider is not None else None
        tap = _Tap(
            self, flow, provider, media, guard, drop_usage=bool(meta and meta.get("drop_usage"))
        )
        flow.metadata["backtide_tap"] = tap
        flow.response.stream = tap

    def _provider_headers(self, flow: Any, meta: Mapping[str, Any]) -> bool:
        """A provider's status line and headers, checked before mitmproxy sends them on.
        False (and the flow stopped) when they may not go to the agent."""
        response = flow.response
        pairs = _header_pairs(response.headers)
        if meta["scanner"].found_in(str(response.reason or ""), *[t for p in pairs for t in p]):
            self._key_in_answer(flow)
            return False
        codings = [v.strip().lower() for n, v in pairs if n.lower() == "transfer-encoding"]
        if any(coding not in ("", "chunked") for coding in codings):
            # Another transfer coding (gzip, chunked): the body would be checked as compressed
            # while the agent could read it decompressed.
            self._stop_answer(flow, "response_transfer_encoding")
            return False
        return True

    def _hold_whole(self, flow: Any, provider: Provider, media: str) -> None:
        """mitmproxy holds the answer whole (BODY_LIMIT at most, body_size_limit) and
        ``response`` checks it before any byte of it goes to the agent, within HELD_BUDGET."""
        length = flow.response.headers.get("content-length")
        size = int(length) if length is not None and length.strip().isdigit() else BODY_LIMIT
        size = min(size, BODY_LIMIT)
        if self.held_bytes + size > HELD_BUDGET:
            self._stop_answer(flow, "response_budget")
            return
        self.held_bytes += size
        flow.metadata["backtide_held"] = size
        flow.metadata["backtide_tap"] = _Tap(self, flow, provider, media)
        flow.metadata["backtide_whole"] = True
        flow.response.stream = False

    def _release(self, flow: Any) -> None:
        self.held_bytes -= flow.metadata.pop("backtide_held", 0)

    @_guard_after("response")
    def response(self, flow: Any) -> None:
        self._release(flow)
        meta = flow.metadata.get("backtide")
        if meta and meta["provider"] is not None:
            if flow.metadata.get("backtide_told"):
                return  # stopped already (a key in its stream, or a failure)
            if flow.metadata.get("backtide_redirect"):
                self._local_redirect(flow, meta)
                return
            trailers = flow.response.trailers
            pairs = _header_pairs(trailers) if trailers is not None else []
            if pairs and meta["scanner"].found_in(*[t for p in pairs for t in p]):
                self._key_in_answer(flow)
                return
            if flow.metadata.get("backtide_whole") and not self._check_whole(flow, meta):
                return
        self._tell_response(flow)

    def _check_whole(self, flow: Any, meta: Mapping[str, Any]) -> bool:
        """A provider's answer held whole: False (and the flow killed) when it may not go on."""
        raw = flow.response.raw_content or b""
        try:
            decoded = decode_body(raw, flow.response.headers.get("content-encoding")) or b""
        except Undecodable as error:
            self._stop_answer(flow, f"response_{error.reason}")  # it cannot be checked
            return False
        parts = (raw,) if decoded is raw else (raw, decoded)  # once when it was not compressed
        if meta["scanner"].found_in(*parts):
            self._key_in_answer(flow)
            return False
        tap = flow.metadata["backtide_tap"]
        tap.count(decoded)
        tap.size = len(raw)
        return True

    def _local_redirect(self, flow: Any, meta: Mapping[str, Any]) -> None:
        """A local provider's 3xx or 101 (T20): the agent gets a 502 instead, and
        ``net/blocked {reason: local_redirect, side: response, local: true}`` is queued."""
        flow.metadata["backtide_told"] = True
        self._channel.tell(
            record.blocked_event(
                "local_redirect", meta["fields"], self._channel.scrubber, side="response",
                local=True,
            )
        )  # fmt: skip
        status, text = REFUSALS["local_redirect"]
        flow.response = self._respond(status, text.encode(), {"content-type": "text/plain"})

    def _stop_answer(self, flow: Any, stage: str) -> None:
        """An answer that may not go to the agent, for a reason that is not a key: killed, and
        ``net/error {stage}`` queued. No ``llm/response``."""
        flow.metadata["backtide_told"] = True
        flow.kill()
        fields = flow.metadata["backtide"]["fields"]
        self._tell_error(
            stage,
            None,
            flow_id=fields["flow_id"],
            host=fields["host"],
            port=fields["port"],
            upstream=True,  # the provider answered: it bills what it generated (T11)
        )

    def _key_in_answer(self, flow: Any) -> None:
        """A provider's answer carried a real key: ``net/blocked {real_key, side: response}`` is
        queued and the flow dies (what was not sent yet never is). No ``llm/response``. If
        either fails, the proxy stops: a dead proxy lets nothing through."""
        flow.metadata["backtide_told"] = True
        logger.error("a provider's answer carried a real key: the flow is killed")
        try:
            meta = flow.metadata.get("backtide") or {}
            fields = meta.get("fields") or {"flow_id": flow.id}
            self._channel.tell(
                record.blocked_event("real_key", fields, self._channel.scrubber, side="response")
            )
        except Exception:
            logger.exception("cannot record a key in an answer: stopping the proxy")
            self._die()
        try:
            flow.kill()
        except Exception:
            logger.exception("cannot stop an answer that carries a key: stopping the proxy")
            self._die()

    def _scanner(self) -> KeyScanner:
        """The real keys' forms of the current config, built once per config."""
        config = self._channel.config
        if config is None:
            raise RuntimeError("no config to check an answer against")
        if self._scanner_of is None or self._scanner_of[0] is not config:
            # The real keys and those to strike only (review of T09b, finding 2).
            self._scanner_of = (config, KeyScanner(config.providers.keys_to_find()))
        return self._scanner_of[1]

    def _tell_response(self, flow: Any) -> None:
        """The ``net/response`` or ``llm/response`` of what the tap saw, once per flow."""
        meta = flow.metadata.get("backtide")
        tap = flow.metadata.get("backtide_tap")
        if not meta or tap is None or flow.metadata.get("backtide_told"):
            return  # an answer of the proxy itself (its refusal is recorded), or told already
        flow.metadata["backtide_told"] = True
        response = {
            "status": flow.response.status_code,
            "headers": _header_pairs(flow.response.headers),
            "size": tap.size,
            "duration_ms": int((self._clock() - meta["start"]) * 1000),
            "streamed": True,
        }
        provider = meta["provider"]
        scrubber = self._channel.scrubber
        if provider is not None:
            event = record.llm_response_event(
                meta["fields"], provider.name, response, tap.summary(), scrubber,
                local=provider.local,
            )  # fmt: skip
        else:
            event = record.response_event(meta["fields"], response, scrubber)
        self._channel.tell(event)

    @_guard_after("error")
    def error(self, flow: Any) -> None:
        was_waiting = flow.id in self._waiting
        self._stop_waiting(flow.id)
        self._reading.pop(flow.id, None)
        self._release(flow)
        meta = flow.metadata.get("backtide")
        if not meta:
            if was_waiting and flow.response is None and _over_body_limit(flow):
                # A streamed (chunked) body past body_size_limit: mitmproxy answered 413 and
                # never called request. Nothing went out; the attempt is recorded (T06-7).
                self._channel.tell(
                    record.blocked_event(
                        "too_large", self._flow_fields(flow), self._channel.scrubber
                    )
                )
            return
        if flow.response is not None:
            # The answer had started (a client that hangs up once it has it, as OpenAI's do
            # after [DONE]): what went by is recorded first, then the error.
            self._tell_response(flow)
        fields = meta["fields"]
        self._channel.tell(
            record.error_event(
                "flow",
                flow_id=fields["flow_id"],
                host=fields["host"],
                port=fields["port"],
                secrets=self._channel.scrubber,
                # T11 (M1): a model call that ends without an answer is charged its estimate
                # unless it provably never reached the provider.
                upstream=None if meta["provider"] is None else _upstream(flow),
            )
        )

    def tls_failed_client(self, data: Any) -> None:
        try:
            address = getattr(getattr(data.context, "server", None), "address", None) or (None,) * 2
            self._channel.tell(
                record.tls_failed_event(
                    data.conn.sni,
                    host=None if address[0] is None else str(address[0]),
                    port=address[1] if isinstance(address[1], int) else None,
                    secrets=self._channel.scrubber,
                )
            )
        except Exception:
            logger.exception("recording a TLS failure failed: stopping the proxy")
            self._die()

    # WebSocket

    @_guard_after("websocket_start")
    def websocket_start(self, flow: Any) -> None:
        stats = {"to_server_messages": 0, "to_server_bytes": 0,
                 "to_client_messages": 0, "to_client_bytes": 0}  # fmt: skip
        flow.metadata["backtide_ws"] = {"stats": stats, "last": self._clock()}
        self._channel.tell(self._ws_event("websocket_start", flow, stats))

    @_guard_after("websocket_message")
    def websocket_message(self, flow: Any) -> None:
        state = flow.metadata.get("backtide_ws")
        if state is None:
            raise RuntimeError("a WebSocket message before its start")
        message = flow.websocket.messages[-1]
        # mitmproxy keeps every message in the flow while the WebSocket is open; it forwards
        # this one from its own reference, so the list can go: a long WebSocket stays small.
        flow.websocket.messages.clear()
        if message.from_client and not self._channel.ready:
            # No channel, nothing goes out: not even on a WebSocket that was let through.
            self._channel.tell(
                record.blocked_event(
                    "not_recorded", self._flow_fields(flow), self._channel.scrubber
                )
            )
            flow.kill()
            return
        config = self._channel.config
        if message.from_client and (
            config is None or config.providers.real_key_in(message.content)
        ):
            # No config: nothing can be checked, so nothing goes on either.
            if config is not None:
                self._channel.tell(
                    record.blocked_event("real_key", self._flow_fields(flow), config.scrubber)
                )
                logger.error("a WebSocket message carried a real key: the WebSocket is killed")
            flow.kill()
            return
        side = "to_server" if message.from_client else "to_client"
        stats = state["stats"]
        stats[f"{side}_messages"] += 1
        stats[f"{side}_bytes"] += len(message.content)
        now = self._clock()
        if now - state["last"] >= WEBSOCKET_SUMMARY_EVERY:
            state["last"] = now
            self._channel.tell(self._ws_event("websocket_summary", flow, stats))

    @_guard_after("websocket_end")
    def websocket_end(self, flow: Any) -> None:
        state = flow.metadata.get("backtide_ws")
        stats = dict(state["stats"]) if state else {}
        code = getattr(flow.websocket, "close_code", None)
        stats["close_code"] = code if isinstance(code, int) else None
        self._channel.tell(self._ws_event("websocket_end", flow, stats))

    def _ws_event(self, action: str, flow: Any, stats: Mapping[str, int | None]) -> dict[str, Any]:
        fields = self._flow_fields(flow)
        return record.websocket_event(action, fields, stats, self._channel.scrubber)

    # Helpers

    def _flow_fields(self, flow: Any) -> dict[str, Any]:
        request = flow.request
        return {
            "flow_id": flow.id,
            "method": request.method,
            "scheme": request.scheme,
            "host": request.host,
            "port": request.port,
            "path": request.path,
            "http_version": request.http_version,
            "headers": _header_pairs(request.headers),
        }

    def _block(
        self,
        reason: str,
        flow: Any,
        fields: Mapping[str, Any],
        *,
        tools: Iterable[str] = (),
        local: bool = False,
    ) -> None:
        """Refuse with the reason's status, and queue its ``net/blocked`` (never the body).
        ``local``: toward a local provider (T20)."""
        known = {key: value for key, value in fields.items() if key != "body"}
        self._channel.tell(
            record.blocked_event(
                reason, known, self._channel.scrubber, tools=tuple(tools), local=local
            )
        )
        self._answer(flow, reason)

    def _refuse_unrecorded(self, flow: Any, fields: Mapping[str, Any] | None = None) -> None:
        """503: no channel or no ack. The refusal is queued and reaches backtide later."""
        self._block("not_recorded", flow, fields if fields is not None else self._flow_fields(flow))

    def _answer(
        self,
        flow: Any,
        reason: str,
        *,
        retry_after: int | None = None,
        shape: Shape | None = None,
        hold_id: str | None = None,
    ) -> None:
        """The refusal of ``reason``. The gate's own (rejected, expired, paused, hold_full and
        gate_rejected) in the shape of its API when a translator read the request (T10-3): a
        403 its client takes for "forbidden" and does not repeat."""
        gated = "rejected" if reason == "gate_rejected" else reason
        if shape is not None and gated in shapes.REFUSAL_REASONS:
            answer = shapes.refused(shape, hold_id, gated)
            flow.response = self._respond(answer.status, answer.body, dict(answer.headers))
            return
        status, text = REFUSALS[reason]
        headers = {"content-type": "text/plain"}
        if retry_after is not None:
            headers["retry-after"] = str(retry_after)
        flow.response = self._respond(status, text.encode(), headers)

    def _tell_error(
        self, stage: str, error: BaseException | None, *, host: str | None = None,
        port: int | None = None, flow_id: str | None = None, upstream: bool | None = None,
    ) -> None:  # fmt: skip
        try:
            self._channel.tell(
                record.error_event(
                    stage,
                    error=None if error is None else type(error).__name__,
                    flow_id=flow_id,
                    host=host,
                    port=port if isinstance(port, int) else None,
                    secrets=self._channel.scrubber,
                    upstream=upstream,
                )
            )
        except Exception:
            logger.exception("cannot queue a net/error: stopping the proxy")
            self._die()

    def _failed(self, stage: str, flow: Any, error: BaseException, *, before: bool) -> None:
        """A hook raised. Before the request went out: 502 (or kill); after: kill."""
        logger.error("the %s hook failed (%s): the flow is stopped", stage, type(error).__name__)
        try:
            if before:
                status, text = FAILED
                flow.response = self._respond(status, text.encode(), {"content-type": "text/plain"})
            else:
                flow.kill()
        except Exception:
            try:
                flow.kill()
            except Exception:
                logger.exception("cannot stop a flow after a failed hook: stopping the proxy")
                self._die()
                return
        flow_id = getattr(flow, "id", None)
        meta = getattr(flow, "metadata", None)
        provider_flow = isinstance(meta, dict) and bool(meta.get("backtide", {}).get("provider"))
        self._tell_error(
            stage,
            error,
            flow_id=flow_id if isinstance(flow_id, str) else None,
            # T11: a model call stopped by a failed hook after it went out is charged; before,
            # it never left (the request phase answers 502 itself).
            upstream=(not before) if provider_flow or before else None,
        )


def _wire_reading(reading: Reading) -> dict[str, Any]:
    """The reading as ``gate.reading`` carries it (``protocol.fit_reading``). One the channel
    would refuse (cannot be: the translators bound their texts) goes as a technical UNKNOWN
    of the same translator, which is held; its secret, if any, still counts."""
    try:
        return protocol.fit_reading(reading.summary())
    except protocol.ProtocolError:
        logger.error("a %s reading could not be sent: held as unknown", reading.translator)
        held = unknown(
            reading.translator,
            reading.shape,
            reading.wait_s,
            Note.UNPARSED,
            account=reading.account,
            path_credential=reading.path_credential,
        )
        if reading.secret_seen:
            held = dataclasses.replace(held, secret_seen=True)
        return protocol.fit_reading(held.summary())


class UnframedBody(RuntimeError):
    """A request body that would leave without a single length that matches it: never sent (the
    guard answers 502 and records ``net/error {stage: UnframedBody}``). Request smuggling belt."""


class Undecodable(Exception):
    """A request body the gate cannot check: ``reason`` is ``undecodable`` or ``too_large``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_ZLIB_WBITS = {"gzip": 16 + zlib.MAX_WBITS, "x-gzip": 16 + zlib.MAX_WBITS}
# FEXTRA, FNAME and FCOMMENT of a gzip header (RFC 1952, 2.3.1): free bytes zlib skips.
_GZIP_FREE_FIELDS = 0x04 | 0x08 | 0x10


def decode_body(
    raw: bytes | None, encoding: str | None, limit: int = BODY_LIMIT, *, sent: bool = False
) -> bytes | None:
    """The body as the server will read it, decoded with a cap (a 16 MiB gzip can hold
    gigabytes: never decompressed without one). Only identity, gzip and deflate, once;
    anything else (br, zstd, two encodings in a row, a stream that does not end) cannot be
    checked and so does not go out.

    ``sent``: a body the agent sends. Bytes the decoding skips would leave unseen (code review of
    2026-10-29, G1), so a gzip header with a name, a comment or extra fields, and an encoded
    body that decodes to nothing, are refused. The rest of the free room in an encoding (the
    deflate stream's own) never leaves: the gate forwards the decoded body (``request``)."""
    if raw is None or not raw:
        return raw
    name = (encoding or "").strip().lower()
    if name in ("", "identity"):
        return raw
    if name in _ZLIB_WBITS:
        if sent and len(raw) >= 4 and raw[3] & _GZIP_FREE_FIELDS:
            raise Undecodable("undecodable")
        candidates = [_ZLIB_WBITS[name]]
    elif name == "deflate":
        candidates = [zlib.MAX_WBITS, -zlib.MAX_WBITS]  # zlib-wrapped, or raw as some send it
    else:
        raise Undecodable("undecodable")
    for wbits in candidates:
        decompressor = zlib.decompressobj(wbits)
        try:
            data = decompressor.decompress(raw, limit + 1)
        except zlib.error:
            continue
        if len(data) > limit or decompressor.unconsumed_tail:
            raise Undecodable("too_large")
        if not decompressor.eof or decompressor.unused_data or (sent and not data):
            raise Undecodable("undecodable")
        return data
    raise Undecodable("undecodable")


def _encoded(request: Any) -> bytes | None:
    """The raw bytes of a body sent with a Content-Encoding, or None. They count in the
    fingerprint as they go out: the same decoded body can be encoded many ways, and an
    approval is for the bytes that leave (code review of 2026-10-29, G1)."""
    name = (request.headers.get("content-encoding") or "").strip().lower()
    if name in ("", "identity") or not request.raw_content:
        return None
    return bytes(request.raw_content)


def _has_header(request: Any, name: str) -> bool:
    return request.headers.get(name) is not None


# A header (field) name as RFC 9110 §5.1 defines it ("token"): no spaces, controls or separators.
_TOKEN_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)


def _malformed_framing(request: Any, trailers_present: bool) -> str | None:
    """Request smuggling (docs/incidentes.md, 2026-10-22): the reason to refuse a request whose
    headers could reframe it for an HTTP/1.1 upstream, or None. ``trailers`` for trailers (h2
    reach the request hook; h1 were cut at requestheaders), else ``malformed_header`` for a
    header or trailer name that is not a token, a value with CR, LF or NUL, Transfer-Encoding
    together with Content-Length, a Transfer-Encoding that is not exactly ``chunked``, or an
    ``Upgrade`` that is not a WebSocket opening (``_upgrade_refused``)."""
    version = str(request.http_version).upper()
    if trailers_present and version.startswith(("HTTP/2", "HTTP/3")):
        # HTTP/2 and 3 trailers reach the request hook; mitmproxy would forward them to the
        # HTTP/1.1 upstream, which frames them after a chunked body only. Refused like h1's
        # announced trailers (B5). (An h1 request's trailers reaching here are left to the usual
        # write path, as before: in production _announces_http1_trailers already cut them.)
        return "trailers"
    pairs = _header_pairs(request.headers)
    for name, value in pairs:
        if not _TOKEN_NAME_RE.fullmatch(name):
            return "malformed_header"
        if any(ch in value for ch in ("\r", "\n", "\0")) or "\0" in name:
            return "malformed_header"
    tes = [v.strip().lower() for n, v in pairs if n.strip().lower() == "transfer-encoding"]
    has_cl = any(n.strip().lower() == "content-length" for n, _ in pairs)
    if tes:
        if has_cl or len(tes) > 1 or tes[0] != "chunked":
            return "malformed_header"
    if _upgrade_refused(request, pairs):
        return "malformed_header"
    return None


def _upgrade_refused(request: Any, pairs: list[tuple[str, str]]) -> bool:
    """Whether the request names ``Upgrade`` without being exactly a WebSocket opening: a GET
    with no body and one ``Upgrade: websocket``. The gate passes a WebSocket to the allowed list
    unasked, so a POST that only named ``Upgrade`` went out without its hold, and any other
    protocol would leave the connection as a tunnel no hook reads (security review of T17b-1)."""
    upgrades = [value.strip().lower() for name, value in pairs if name.strip().lower() == "upgrade"]
    if not upgrades:
        return False
    lengths = [v.strip() for n, v in pairs if n.strip().lower() == "content-length"]
    return (
        str(request.method) != "GET"
        or upgrades != ["websocket"]
        or bool(request.raw_content)
        or any(n.strip().lower() == "transfer-encoding" for n, _ in pairs)
        or any(length != "0" for length in lengths)
    )


def _frame_h2_body(request: Any) -> None:
    """Request smuggling fix (security review of T11, docs/incidentes.md 2026-10-22). An HTTP/2
    or HTTP/3 request carries no ``Content-Length`` and no ``Transfer-Encoding``: its body is
    framed by DATA frames. mitmproxy 12.2.3 forwards it to an HTTP/1.1 upstream without adding
    either, so the server reads a zero-length body (RFC 9112 §6.3 rule 6) and the body bytes stay
    on the connection, read as a second request the gate never saw. So the gate adds the
    ``Content-Length`` of the body it read: here, before ``_flow_fields``, so it is recorded and
    counts in the fingerprint; a request with no body gets ``Content-Length: 0``. A chunked body
    (which mitmproxy does re-frame) and one that already has a length are left alone. The
    include_usage rewrite (if any) corrects the length again when it changes the body."""
    version = str(request.http_version).upper()
    if not version.startswith(("HTTP/2", "HTTP/3")):
        return
    if _has_header(request, "content-length") or _has_header(request, "transfer-encoding"):
        return
    request.headers["content-length"] = str(len(request.raw_content or b""))


def _announces_http1_trailers(request: Any) -> bool:
    """An HTTP/1 request with a ``Trailer`` header (RFC 9110, section 6.6.2): trailers follow
    its chunked body. (HTTP/2's reach the request hook, and make it a write.)"""
    if str(request.http_version).upper().startswith(("HTTP/2", "HTTP/3")):
        return False
    return request.headers.get("trailer") is not None


def _may_have_body(request: Any) -> bool:
    """Whether a body may follow the headers. In HTTP/1 only with ``Content-Length`` above 0 or
    a ``Transfer-Encoding``; in HTTP/2 and 3 a body needs neither, so any request may have one
    unless its ``Content-Length`` is 0."""
    length = request.headers.get("content-length")
    if length is not None and length.strip() == "0":
        return False
    if str(request.http_version).upper().startswith(("HTTP/2", "HTTP/3")):
        return True
    return length is not None or request.headers.get("transfer-encoding") is not None


_BODY_LIMIT_ERROR = "body_size_limit"  # in mitmproxy 12.2.3's message for a body over it


def _over_body_limit(flow: Any) -> bool:
    error = getattr(flow, "error", None)
    return _BODY_LIMIT_ERROR in str(getattr(error, "msg", "") or "")


def _gone(flow: Any) -> bool:
    """Whether a flow's client went or mitmproxy marked it failed (a kill, a reset)."""
    return (
        getattr(flow, "error", None) is not None
        or getattr(flow.client_conn, "timestamp_end", None) is not None
    )


def _upstream(flow: Any) -> bool:
    """Whether a request may have reached its server: False only when the flow's server
    connection never even started (mitmproxy's ``timestamp_start`` and ``timestamp_tcp_setup``
    both unset). Anything that cannot be told counts as reached (T11: charged, never free)."""
    conn = getattr(flow, "server_conn", None)
    if conn is None or not hasattr(conn, "timestamp_tcp_setup"):
        return True
    started = getattr(conn, "timestamp_start", None)
    return conn.timestamp_tcp_setup is not None or started is not None


def _with_length(headers: list[tuple[str, str]], size: int) -> list[tuple[str, str]]:
    """``headers`` with every ``Content-Length`` saying ``size`` (none is added)."""
    return [(n, str(size) if n.lower() == "content-length" else v) for n, v in headers]


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    return [(str(name), str(value)) for name, value in headers.items(multi=True)]


def _plain_ip(address: str) -> str:
    """``::ffff:172.18.0.2`` (a dual-stack listener) is ``172.18.0.2``."""
    return address.removeprefix("::ffff:")
