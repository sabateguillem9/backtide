"""The gate: mitmproxy's hooks, thin, over the pure pieces of backtide/gate.

Design: docs/21-diseno-t06-proxy.md, sections 4 to 8. What each hook does:

- ``client_connected``: only clients that came in through the proxy's address on the agent's
  network, and at most ``max_connections`` at once; any other is cut.
- ``http_connect``: a ``CONNECT`` to a port other than 80 or 443 is refused (``port``).
- ``requestheaders``: no channel, no request (503, ``not_recorded``); at most ``max_pending``
  requests reading their body or waiting for their ack (429, ``throttled``); a body over the
  limit is refused before it is read (413, ``too_large``).
- ``request`` (async): the fixed rules, in this order: port, the real key anywhere (URL, every
  header, the trailers, the raw and the decoded body: ``real_key``, on any host), a
  ``Content-Encoding`` that cannot be undone (``undecodable``), ``Host`` against the
  connection and the SNI (``host_mismatch``), OAuth logins, and on a provider's host the fake
  key swapped for the real one (``foreign_credential`` otherwise) and only a model call with the
  client's own tools (``provider_endpoint``, ``provider_body`` or ``provider_side_tool``
  otherwise: provider_tools.py, T06-6). An IP literal that is not public, also written as numbers
  (``127.1``, ``0x7f.1``), is ``private_address`` before backtide is asked. Then backtide is asked
  (``request`` -> ``ack``): only with ``allow`` and a ``seq`` (the event is in the black box)
  does the request go on. ``connection_strategy=lazy`` means no server was contacted so far.
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

**Any exception in a hook kills the flow** (mitmproxy carries on after a hook raises, T06-1
P7): before the request has gone out the agent gets a 502, after it the flow is killed, and a
``net/error {stage}`` is queued. If even that fails the process exits: a dead proxy lets
nothing out. The log never gets a request's data, only error kinds and counts.

mitmproxy is never imported here (``respond`` builds the responses; main.py hands in
mitmproxy's), so the Mac tests run the hooks on small fakes of mitmproxy's objects.
"""

import asyncio
import functools
import logging
import os
import socket
import time
import zlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from backtide.gate import record
from backtide.gate.client import Ack, Channel, GateConfig
from backtide.gate.echo import KeyEcho, KeyScanner, SseGuard
from backtide.gate.policy import (
    host_mismatch,
    is_ip,
    is_oauth_login,
    is_public,
    normalize_host,
    numeric_ipv4,
    port_allowed,
)
from backtide.gate.provider_tools import check_request
from backtide.gate.providers import Provider, swap_key
from backtide.gate.sse import UsageStream, summarize_json

logger = logging.getLogger(__name__)

BODY_LIMIT = 16 * 1024 * 1024  # body_size_limit of main.py (docs/21, section 8)
JSON_SUMMARY_LIMIT = 1 << 20  # a provider's non-streamed answer is summarized up to 1 MiB
# Bytes of providers' answers held whole at once (each is BODY_LIMIT at most; one without a
# length counts as that much). Past it, the answer is not let through: the proxy keeps to its
# memory (1 GiB) whatever the agent asks for at the same time.
HELD_BUDGET = 128 * 1024 * 1024
WEBSOCKET_SUMMARY_EVERY = 2.0  # seconds
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
    "provider_endpoint": (403, "backtide: only the provider's model endpoints are allowed\n"),
    "provider_body": (400, "backtide: a model request must be the provider's JSON\n"),
    "provider_side_tool": (
        403,
        "backtide: tools that run on the provider's side are not allowed (allow_provider_tools)\n",
    ),
}
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
    ) -> None:
        self._gate = gate
        self._flow = flow
        self._guard = guard
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
            return self._guard.feed(chunk) if chunk else self._guard.finish()
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
        self._acked: dict[str, set[tuple[str, int]]] = {}  # client id -> targets let through
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
        except Exception:
            logger.exception("forgetting a client failed: stopping the proxy")
            self._die()

    # Requests

    @_guard_request_phase("http_connect")
    def http_connect(self, flow: Any) -> None:
        if not port_allowed(flow.request.port):
            self._block("port", flow, {"host": flow.request.host, "port": flow.request.port})
        elif self._private_literal(flow.request.host):
            self._block(
                "private_address", flow, {"host": flow.request.host, "port": flow.request.port}
            )

    @_guard_request_phase("requestheaders")
    def requestheaders(self, flow: Any) -> None:
        # Never a streamed request: mitmproxy would send its headers and body to the server
        # BEFORE the request hook, that is, before backtide has recorded it. The body is read
        # whole (16 MiB at most, ``body_size_limit``), then checked, recorded and only then sent.
        flow.request.stream = False
        body = _may_have_body(flow.request)
        if len(self._waiting) >= self._channel.limits["max_pending"]:
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

    @_guard_request_phase("request")
    async def request(self, flow: Any) -> None:
        try:
            await self._request(flow)
        finally:
            self._waiting.discard(flow.id)

    async def _request(self, flow: Any) -> None:
        if flow.response is not None:
            return  # already refused by an earlier hook: it never goes out
        config = self._channel.config
        if config is None or not self._channel.ready:
            self._refuse_unrecorded(flow)
            return
        request = flow.request
        fields = self._flow_fields(flow)
        if not port_allowed(request.port):
            self._block("port", flow, fields)
            return
        headers = _header_pairs(request.headers)
        trailers = _header_pairs(request.trailers) if request.trailers is not None else []
        refusal = None
        try:
            body: bytes | None = decode_body(
                request.raw_content, request.headers.get("content-encoding")
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
        swapped = None
        if provider is not None:
            swapped = swap_key(provider, headers, scheme=request.scheme, port=request.port)
            if swapped is None:
                self._block("foreign_credential", flow, fields)
                return
            # What goes there leaves with the real key: only a model call with the client's own
            # tools, never one that has the provider reach other hosts for the agent (T06-6).
            verdict = check_request(
                str(provider.kind),
                request.method,
                request.path,
                headers,
                body,
                allowed=config.provider_tools,
                models=provider.models,
                trailers=trailers,
            )
            if verdict.reason is not None:
                self._block(verdict.reason, flow, fields, tools=verdict.tools)
                if verdict.reason == "provider_side_tool":
                    logger.warning("a model request with provider-side tools: refused")
                return
            event = record.llm_request_event(
                fields, provider.name, config.scrubber, provider_tools=verdict.tools
            )
        else:
            event = record.request_event(fields, config.scrubber)
        # Up to max_pending requests wait for their ack at once: each keeps only mitmproxy's raw
        # body, never a decoded copy of up to 16 MiB as well (T06-7).
        del fields["body"]
        body = parts = None
        ack = await self._channel.ask(event)
        if flow.response is not None:
            return  # killed or answered meanwhile
        if not ack.allowed:
            self._denied(flow, ack, fields)
            return
        if swapped is not None:
            # An answer the tap can read: compressed, its usage would be lost (usage_missing).
            swapped = [pair for pair in swapped if pair[0].lower() != "accept-encoding"]
            swapped.append(("accept-encoding", "identity"))
            request.headers.fields = tuple(
                (name.encode("utf-8", "surrogateescape"), value.encode("utf-8", "surrogateescape"))
                for name, value in swapped
            )
        host = normalize_host(request.host) or request.host
        self._acked.setdefault(flow.client_conn.id, set()).add((host, request.port))
        flow.metadata["backtide"] = {
            "provider": provider,
            # The answer is checked for the keys of the config this request went out with.
            "scanner": self._scanner() if provider is not None else None,
            "start": self._clock(),
            "fields": {key: fields[key] for key in ("flow_id", "scheme", "host", "port", "path")},
        }

    def _denied(self, flow: Any, ack: Ack, fields: dict[str, Any]) -> None:
        reason = ack.reason or "not_recorded"
        if reason == "not_recorded":
            self._refuse_unrecorded(flow, fields)
            return
        # not_allowed and throttled are backtide's: it recorded or counted them already.
        self._answer(flow, reason, retry_after=ack.retry_after)

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
        headers = flow.response.headers
        media = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if provider is not None:
            if not self._provider_headers(flow, meta):
                return
            encoding = (headers.get("content-encoding") or "").strip().lower()
            if media != "text/event-stream" or encoding not in ("", "identity"):
                self._hold_whole(flow, provider, media)
                return
        guard = SseGuard(meta["scanner"]) if provider is not None else None
        tap = _Tap(self, flow, provider, media, guard)
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

    def _stop_answer(self, flow: Any, stage: str) -> None:
        """An answer that may not go to the agent, for a reason that is not a key: killed, and
        ``net/error {stage}`` queued. No ``llm/response``."""
        flow.metadata["backtide_told"] = True
        flow.kill()
        fields = flow.metadata["backtide"]["fields"]
        self._tell_error(
            stage, None, flow_id=fields["flow_id"], host=fields["host"], port=fields["port"]
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
            keys = [provider.real_key.reveal() for provider in config.providers.items]
            self._scanner_of = (config, KeyScanner(keys))
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
                meta["fields"], provider.name, response, tap.summary(), scrubber
            )
        else:
            event = record.response_event(meta["fields"], response, scrubber)
        self._channel.tell(event)

    @_guard_after("error")
    def error(self, flow: Any) -> None:
        was_waiting = flow.id in self._waiting
        self._waiting.discard(flow.id)
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
        self, reason: str, flow: Any, fields: Mapping[str, Any], *, tools: Iterable[str] = ()
    ) -> None:
        """Refuse with the reason's status, and queue its ``net/blocked`` (never the body)."""
        known = {key: value for key, value in fields.items() if key != "body"}
        self._channel.tell(
            record.blocked_event(reason, known, self._channel.scrubber, tools=tuple(tools))
        )
        self._answer(flow, reason)

    def _refuse_unrecorded(self, flow: Any, fields: Mapping[str, Any] | None = None) -> None:
        """503: no channel or no ack. The refusal is queued and reaches backtide later."""
        self._block("not_recorded", flow, fields if fields is not None else self._flow_fields(flow))

    def _answer(self, flow: Any, reason: str, *, retry_after: int | None = None) -> None:
        status, text = REFUSALS[reason]
        headers = {"content-type": "text/plain"}
        if retry_after is not None:
            headers["retry-after"] = str(retry_after)
        flow.response = self._respond(status, text.encode(), headers)

    def _tell_error(
        self, stage: str, error: BaseException | None, *, host: str | None = None,
        port: int | None = None, flow_id: str | None = None,
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
        self._tell_error(stage, error, flow_id=flow_id if isinstance(flow_id, str) else None)


class Undecodable(Exception):
    """A request body the gate cannot check: ``reason`` is ``undecodable`` or ``too_large``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_ZLIB_WBITS = {"gzip": 16 + zlib.MAX_WBITS, "x-gzip": 16 + zlib.MAX_WBITS}


def decode_body(raw: bytes | None, encoding: str | None, limit: int = BODY_LIMIT) -> bytes | None:
    """The body as the server will read it, decoded with a cap (a 16 MiB gzip can hold
    gigabytes: never decompressed without one). Only identity, gzip and deflate, once;
    anything else (br, zstd, two encodings in a row, a stream that does not end) cannot be
    checked and so does not go out."""
    if raw is None or not raw:
        return raw
    name = (encoding or "").strip().lower()
    if name in ("", "identity"):
        return raw
    if name in _ZLIB_WBITS:
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
        if not decompressor.eof or decompressor.unused_data:
            raise Undecodable("undecodable")
        return data
    raise Undecodable("undecodable")


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


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    return [(str(name), str(value)) for name, value in headers.items(multi=True)]


def _plain_ip(address: str) -> str:
    """``::ffff:172.18.0.2`` (a dual-stack listener) is ``172.18.0.2``."""
    return address.removeprefix("::ffff:")
