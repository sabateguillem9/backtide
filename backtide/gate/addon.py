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
  key swapped for the real one (``foreign_credential`` otherwise). Then backtide is asked
  (``request`` -> ``ack``): only with ``allow`` and a ``seq`` (the event is in the black box)
  does the request go on. ``connection_strategy=lazy`` means no server was contacted so far.
- ``server_connect`` (async): only for a host and port that an ack let through on this client
  connection; the name is resolved here, EVERY address must be public, and the connection is
  pinned to the address that was checked (the SNI keeps the name).
- ``responseheaders``/``response``: every response streams through a tap that counts it and,
  for a provider, reads the usage (SSE or JSON, bounded); then ``net/response`` or
  ``llm/response``. Never the body.
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
from backtide.gate.client import Ack, Channel
from backtide.gate.policy import (
    host_mismatch,
    is_ip,
    is_oauth_login,
    is_public,
    normalize_host,
    port_allowed,
)
from backtide.gate.providers import Provider, swap_key
from backtide.gate.sse import UsageStream, summarize_json

logger = logging.getLogger(__name__)

BODY_LIMIT = 16 * 1024 * 1024  # body_size_limit of main.py (docs/21, section 8)
JSON_SUMMARY_LIMIT = 1 << 20  # a provider's non-streamed answer is summarized up to 1 MiB
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
    """``flow.response.stream``: every chunk passes at once; a copy is counted and, for a
    provider, read for its usage. A failure inside kills the flow (it never raises)."""

    def __init__(self, gate: "Gate", flow: Any, provider: Provider | None, media: str) -> None:
        self._gate = gate
        self._flow = flow
        self.size = 0
        self.kind = None if provider is None else str(provider.kind)
        self._sse = UsageStream(self.kind) if self.kind and media == "text/event-stream" else None
        self._json: bytearray | None = bytearray() if self.kind and self._sse is None else None
        self.failed = False

    def __call__(self, chunk: bytes) -> bytes:
        try:
            self.size += len(chunk)
            if self._sse is not None:
                self._sse.feed(chunk)
            elif self._json is not None:
                if len(self._json) + len(chunk) <= JSON_SUMMARY_LIMIT:
                    self._json += chunk
                else:
                    self._json = None  # too big to summarize: usage_missing
            return chunk
        except Exception as error:
            self.failed = True
            self._gate._failed("response_stream", self._flow, error, before=False)
            return b""

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

    @_guard_request_phase("requestheaders")
    def requestheaders(self, flow: Any) -> None:
        # Never a streamed request: mitmproxy would send its headers and body to the server
        # BEFORE the request hook, that is, before backtide has recorded it. The body is read
        # whole (16 MiB at most, ``body_size_limit``), then checked, recorded and only then sent.
        flow.request.stream = False
        if not self._channel.ready:
            self._refuse_unrecorded(flow)
            return
        if len(self._waiting) >= self._channel.limits["max_pending"]:
            self._channel.count_throttled()
            self._answer(flow, "throttled", retry_after=1)
            return
        length = flow.request.headers.get("content-length")
        if length is not None and (not length.strip().isdigit() or int(length) > BODY_LIMIT):
            self._block("too_large", flow, self._flow_fields(flow))
            return
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
            event = record.llm_request_event(fields, provider.name, config.scrubber)
        else:
            event = record.request_event(fields, config.scrubber)
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
        media = (flow.response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        tap = _Tap(self, flow, provider, media)
        flow.metadata["backtide_tap"] = tap
        flow.response.stream = tap

    @_guard_after("response")
    def response(self, flow: Any) -> None:
        meta = flow.metadata.get("backtide")
        tap = flow.metadata.get("backtide_tap")
        if not meta or tap is None:
            return  # an answer of the proxy itself: its refusal is already recorded
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
        self._waiting.discard(flow.id)
        meta = flow.metadata.get("backtide")
        if not meta:
            return
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

    def _block(self, reason: str, flow: Any, fields: Mapping[str, Any]) -> None:
        """Refuse with the reason's status, and queue its ``net/blocked`` (never the body)."""
        known = {key: value for key, value in fields.items() if key != "body"}
        self._channel.tell(record.blocked_event(reason, known, self._channel.scrubber))
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


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    return [(str(name), str(value)) for name, value in headers.items(multi=True)]


def _plain_ip(address: str) -> str:
    """``::ffff:172.18.0.2`` (a dual-stack listener) is ``172.18.0.2``."""
    return address.removeprefix("::ffff:")
