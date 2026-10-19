"""The gate's mitmproxy hooks (backtide/gate/addon.py), on small fakes of mitmproxy's objects.

mitmproxy is not a dependency on the Mac: the hooks are driven here with objects that have the
attributes the gate reads (the same names as mitmproxy 12.2.3's), and the VM runs the real thing
(tests/integration/test_proxy_channel.py). What is checked: nothing goes out before backtide's
ack, every refusal is answered and recorded, a hook that fails stops the flow, the connection is
only opened for what an ack let through and only to a public address, and no real key shows in
any event.
"""

import asyncio
import gzip
import json
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from backtide.blackbox.redact import KnownScrubber
from backtide.gate import addon
from backtide.gate.addon import FAILED, REFUSALS, Gate
from backtide.gate.client import NOT_RECORDED, Ack, GateConfig
from backtide.gate.protocol import DEFAULT_LIMITS
from backtide.gate.providers import FAKE_KEY_PREFIX, Kind, Provider, Providers, Secret

REAL = "sk-ant-api03-TEST" + "4dd0nR3alK3y" * 5
FAKE = FAKE_KEY_PREFIX + "anthropic-" + "A1d2d3o4n5A6b7C8d9E0f1G2h3I4j5K6"
AGENT_SIDE = "172.18.0.2"
PUBLIC = "93.184.215.14"


# --- fakes of mitmproxy's objects ----------------------------------------------------------------


class Headers:
    def __init__(self, pairs: list[tuple[str, str]] | None = None) -> None:
        self.fields = tuple((k.encode(), v.encode()) for k, v in (pairs or []))

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        return [(k.decode(), v.decode()) for k, v in self.fields]

    def get(self, name: str, default: str | None = None) -> str | None:
        for key, value in self.items():
            if key.lower() == name.lower():
                return value
        return default


@dataclass
class Request:
    host: str = "example.com"
    port: int = 443
    method: str = "POST"
    scheme: str = "https"
    path: str = "/api"
    http_version: str = "HTTP/1.1"
    headers: Headers = field(default_factory=lambda: Headers([("Host", "example.com")]))
    trailers: Headers | None = None
    raw_content: bytes | None = b""
    stream: bool = False

    @property
    def host_header(self) -> str | None:
        return self.headers.get("host")

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}{self.path}"


@dataclass
class Response:
    status_code: int
    content: bytes = b""
    headers: Headers = field(default_factory=Headers)
    stream: Any = None
    reason: str = "OK"
    trailers: Headers | None = None

    @property
    def raw_content(self) -> bytes:
        return self.content


def respond(status: int, content: bytes, headers: Any) -> Response:
    return Response(status, content, Headers(list(headers.items())))


@dataclass
class Client:
    id: str = "client-1"
    sockname: tuple[str, int] = (AGENT_SIDE, 8080)
    sni: str | None = "example.com"
    error: str | None = None


@dataclass
class Server:
    address: tuple[str, int]
    error: str | None = None


@dataclass
class ConnectData:
    server: Server
    client: Client


@dataclass
class WsMessage:
    from_client: bool
    content: bytes


@dataclass
class WebSocket:
    messages: list[WsMessage] = field(default_factory=list)
    close_code: int | None = None


@dataclass
class Flow:
    request: Request = field(default_factory=Request)
    id: str = "flow-1"
    response: Response | None = None
    client_conn: Client = field(default_factory=Client)
    metadata: dict[str, Any] = field(default_factory=dict)
    killed: bool = False
    websocket: WebSocket | None = None
    error: Any = None

    def kill(self) -> None:
        self.killed = True


@dataclass
class FlowError:
    msg: str


# --- a fake channel ------------------------------------------------------------------------------


def providers() -> Providers:
    return Providers(
        [Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL))]
    )


class FakeChannel:
    def __init__(
        self,
        *,
        configured: bool = True,
        limits: dict[str, int] | None = None,
        provider_tools: frozenset[str] = frozenset(),
    ) -> None:
        self.config = (
            GateConfig(
                providers(),
                KnownScrubber(providers().known_secrets()),
                DEFAULT_LIMITS,
                provider_tools=provider_tools,
            )
            if configured
            else None
        )
        self.ready = configured
        self._limits = dict(DEFAULT_LIMITS) | (limits or {})
        self.asked: list[dict[str, Any]] = []
        self.told: list[dict[str, Any]] = []
        self.throttled = 0
        self.answer: Ack | Exception = Ack("allow", seq=7)
        self.gate: asyncio.Event | None = None

    @property
    def limits(self) -> dict[str, int]:
        return self._limits

    @property
    def scrubber(self) -> KnownScrubber:
        return self.config.scrubber if self.config else KnownScrubber(())

    async def ask(self, event: dict[str, Any]) -> Ack:
        self.asked.append(event)
        if self.gate is not None:
            await self.gate.wait()
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def tell(self, event: dict[str, Any]) -> None:
        self.told.append(event)

    def count_throttled(self) -> None:
        self.throttled += 1

    def actions(self) -> list[str]:
        return [f"{e['action']}:{e['details'].get('reason', '')}" for e in self.told]


def make_gate(
    channel: FakeChannel,
    *,
    addresses: list[str] | None = None,
    public: frozenset[str] = frozenset(),
    clock: Callable[[], float] = lambda: 100.0,
) -> tuple[Gate, list[str]]:
    died: list[str] = []
    resolved = [PUBLIC] if addresses is None else addresses

    async def resolve(host: str, port: int) -> list[str]:
        return resolved

    gate = Gate(
        channel,  # type: ignore[arg-type]
        respond=respond,
        agent_side=lambda: frozenset({AGENT_SIDE}),
        resolve=resolve,
        public=public,
        clock=clock,
        die=lambda: died.append("died"),
    )
    gate.running()
    return gate, died


def send(gate: Gate, flow: Flow) -> None:
    """requestheaders, then request, as mitmproxy calls them."""
    gate.requestheaders(flow)
    if flow.response is None:
        asyncio.run(gate.request(flow))


def connect(gate: Gate, flow: Flow, address: tuple[str, int] | None = None) -> Server:
    server = Server(address or (flow.request.host, flow.request.port))
    asyncio.run(gate.server_connect(ConnectData(server, flow.client_conn)))
    return server


def status(flow: Flow) -> int | None:
    return None if flow.response is None else flow.response.status_code


# --- record, then go out -------------------------------------------------------------------------


def test_a_request_goes_on_only_after_backtide_allows_it() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    assert flow.response is None  # it goes on
    [event] = channel.asked
    assert (event["source"], event["action"]) == ("net", "request")
    assert event["details"]["host"] == "example.com"
    server = connect(gate, flow)
    assert server.error is None and server.address == (PUBLIC, 443)  # pinned to what was checked


def test_while_backtide_has_not_answered_no_connection_is_let_through() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()

    async def go() -> None:
        channel.gate = asyncio.Event()
        gate.requestheaders(flow)
        asking = asyncio.ensure_future(gate.request(flow))
        await asyncio.sleep(0.01)
        early = Server(("example.com", 443))
        await gate.server_connect(ConnectData(early, flow.client_conn))
        assert early.error is not None  # no ack yet: no connection
        channel.gate.set()
        await asking
        later = Server(("example.com", 443))
        await gate.server_connect(ConnectData(later, flow.client_conn))
        assert later.error is None

    asyncio.run(go())
    assert "error:" in channel.actions()


@pytest.mark.parametrize(
    ("answer", "code", "reason"),
    [
        (Ack("deny", reason="not_allowed"), 403, "not_allowed"),
        (Ack("deny", reason="throttled", retry_after=3), 429, "throttled"),
        (NOT_RECORDED, 503, "not_recorded"),
        (Ack("allow"), 503, "not_recorded"),  # an allow without a seq is not a recording
    ],
)
def test_a_denial_is_answered_and_nothing_goes_out(answer: Ack, code: int, reason: str) -> None:
    channel = FakeChannel()
    channel.answer = answer
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    assert status(flow) == code
    if code == 429:
        assert flow.response is not None and flow.response.headers.get("retry-after") == "3"
    if reason == "not_recorded":  # backtide does not know: the proxy tells it later
        assert channel.actions() == ["blocked:not_recorded"]
    else:  # backtide decided, and recorded or counted it itself
        assert channel.told == []
    assert connect(gate, flow).error is not None  # and no connection for it either
    assert channel.told[-1]["details"]["stage"] == "server_connect_unacked"


def test_without_a_channel_nothing_is_asked_and_everything_is_refused() -> None:
    channel = FakeChannel(configured=False)
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    assert status(flow) == 503
    assert REFUSALS["not_recorded"][1].encode() == flow.response.content  # type: ignore[union-attr]
    assert channel.asked == [] and channel.actions() == ["blocked:not_recorded"]


def test_a_request_answered_by_an_earlier_hook_is_never_asked_about() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(response=Response(204))
    asyncio.run(gate.request(flow))
    assert channel.asked == [] and status(flow) == 204


# --- the fixed rules -----------------------------------------------------------------------------


def blocked(flow: Flow, **gate_options: Any) -> tuple[int | None, list[str], FakeChannel]:
    channel = FakeChannel()
    gate, _ = make_gate(channel, **gate_options)
    send(gate, flow)
    return status(flow), channel.actions(), channel


def test_a_connect_to_another_port_is_refused() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(Request(port=22))
    gate.http_connect(flow)
    assert status(flow) == 403 and channel.actions() == ["blocked:port"]


@pytest.mark.parametrize(
    "request_",
    [
        Request(path=f"/x?key={REAL}"),
        Request(headers=Headers([("Host", "example.com"), ("X-Note", REAL)])),
        Request(raw_content=json.dumps({"k": REAL}).encode()),
        Request(
            headers=Headers([("Host", "example.com"), ("Content-Encoding", "gzip")]),
            raw_content=gzip.compress(REAL.encode()),
        ),
        Request(trailers=Headers([("x-trailer", REAL)])),
        Request(path="/x?key=" + REAL.replace("-", "%2D")),
    ],
    ids=["query", "header", "body", "gzip-body", "trailer", "url-encoded"],
)
def test_a_real_key_is_refused_on_any_host(request_: Request) -> None:
    code, actions, channel = blocked(Flow(request_))
    assert (code, actions) == (403, ["blocked:real_key"])
    assert channel.asked == []
    assert REAL not in json.dumps(channel.told)


@pytest.mark.parametrize(
    ("encoding", "body", "code", "reason"),
    [
        ("br", b"\x00garbage", 400, "undecodable"),
        ("gzip", b"not gzip at all", 400, "undecodable"),
        ("gzip, gzip", gzip.compress(gzip.compress(b"x")), 400, "undecodable"),
        ("gzip", gzip.compress(b"x")[:-6], 400, "undecodable"),  # a stream that does not end
        ("gzip", gzip.compress(b"\0" * (17 * 1024 * 1024)), 413, "too_large"),  # a small bomb
    ],
    ids=["br", "garbage", "twice", "truncated", "bomb"],
)
def test_a_body_that_cannot_be_checked_is_refused(
    encoding: str, body: bytes, code: int, reason: str
) -> None:
    request = Request(
        headers=Headers([("Host", "example.com"), ("Content-Encoding", encoding)]),
        raw_content=body,
    )
    assert blocked(Flow(request))[:2] == (code, [f"blocked:{reason}"])


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "identity"])
def test_a_body_the_gate_can_decode_is_recorded_decoded(encoding: str) -> None:
    text = b'{"note": "hello from the agent"}'
    raw = {"gzip": gzip.compress, "deflate": zlib.compress, "identity": bytes}[encoding](text)
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    headers = [("Host", "example.com"), ("Content-Encoding", encoding),
               ("Content-Type", "application/json")]  # fmt: skip
    send(gate, Flow(Request(headers=Headers(headers), raw_content=raw)))
    assert "hello from the agent" in channel.asked[0]["details"]["body"]["excerpt"]


def test_a_request_never_streams_to_the_server_before_its_ack() -> None:
    """mitmproxy would send a streamed body out before the request hook (T06-4's review)."""
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(Request(stream=True))
    gate.requestheaders(flow)
    assert flow.request.stream is False


@pytest.mark.parametrize(
    ("request_", "sni"),
    [
        (Request(headers=Headers([("Host", "other.example")])), "example.com"),
        (Request(headers=Headers([])), "example.com"),
        (Request(), "other.example"),
    ],
    ids=["host-header", "no-host", "sni"],
)
def test_domain_fronting_is_refused(request_: Request, sni: str) -> None:
    flow = Flow(request_, client_conn=Client(sni=sni))
    assert blocked(flow)[:2] == (403, ["blocked:host_mismatch"])


def test_an_oauth_login_is_refused() -> None:
    flow = Flow(
        Request(host="auth.openai.com", headers=Headers([("Host", "auth.openai.com")])),
        client_conn=Client(sni="auth.openai.com"),
    )
    assert blocked(flow)[:2] == (403, ["blocked:oauth_login"])


def test_a_body_over_the_limit_is_refused_before_it_is_read() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(Request(headers=Headers([("Host", "example.com"), ("Content-Length", "1e9")])))
    gate.requestheaders(flow)
    assert status(flow) == 413 and channel.actions() == ["blocked:too_large"]
    huge = Flow(Request(headers=Headers([("Host", "example.com"), ("content-length", "99999999")])))
    gate.requestheaders(huge)
    assert status(huge) == 413


# --- the provider and its fake key ---------------------------------------------------------------


def provider_flow(*headers: tuple[str, str]) -> Flow:
    return Flow(
        Request(
            host="api.anthropic.com",
            path="/v1/messages",
            headers=Headers([("Host", "api.anthropic.com"), *headers]),
            raw_content=json.dumps(
                {"model": "m", "messages": [{"content": "secret text"}]}
            ).encode(),
        ),
        client_conn=Client(sni="api.anthropic.com"),
    )


def test_the_fake_key_is_swapped_for_the_real_one_only_after_the_ack() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE), ("Accept-Encoding", "gzip"))
    send(gate, flow)
    assert flow.response is None
    sent = dict(flow.request.headers.items())
    assert sent["x-api-key"] == REAL
    assert sent["accept-encoding"] == "identity"
    assert FAKE not in json.dumps(sent)
    [event] = channel.asked
    assert (event["source"], event["action"]) == ("llm", "request")
    assert event["details"]["key"] == "swapped"
    text = json.dumps(event)
    assert REAL not in text and FAKE not in text and "secret text" not in text


def test_a_denied_provider_request_keeps_the_fake_key() -> None:
    channel = FakeChannel()
    channel.answer = Ack("deny", reason="not_allowed")
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    assert dict(flow.request.headers.items())["x-api-key"] == FAKE


@pytest.mark.parametrize(
    "headers",
    [(), (("x-api-key", "sk-ant-api03-someone-elses-key-0123456789"),), (("authorization", FAKE),)],
    ids=["none", "another", "wrong-header"],
)
def test_anything_but_the_fake_key_is_a_foreign_credential(headers: tuple) -> None:
    code, actions, channel = blocked(provider_flow(*headers))
    assert (code, actions) == (403, ["blocked:foreign_credential"])
    assert channel.asked == []


# --- the connection ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addresses",
    [["10.0.0.5"], ["169.254.169.254"], [PUBLIC, "127.0.0.1"], []],
    ids=["private", "metadata", "rebinding", "none"],
)
def test_only_public_addresses_are_connected(addresses: list[str]) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel, addresses=addresses)
    flow = Flow()
    send(gate, flow)
    server = connect(gate, flow)
    assert server.error is not None and server.address == ("example.com", 443)
    assert channel.actions() == ["blocked:private_address"]


def test_a_public_ip_literal_is_checked_without_resolving() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel, addresses=["127.0.0.1"])  # what a name would resolve to
    flow = Flow(Request(host=PUBLIC, headers=Headers([("Host", PUBLIC)])),
                client_conn=Client(sni=None))  # fmt: skip
    send(gate, flow)
    assert flow.response is None
    server = connect(gate, flow)
    assert server.error is None and server.address == (PUBLIC, 443)


PRIVATE_LITERALS = ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.5.2", "::1",
                    "::ffff:127.0.0.1", "fe80::1", "100.64.0.1", "0.0.0.0"]  # noqa: S104  # fmt: skip


def bracketed(host: str) -> str:
    return f"[{host}]" if ":" in host else host


@pytest.mark.parametrize("host", PRIVATE_LITERALS)
def test_a_private_ip_literal_is_refused_before_backtide_is_asked(host: str) -> None:
    """T06-5: the fixed rule comes first. An IP literal that is not public never reaches the
    allowed list (which would say not_allowed): it is private_address, risk 2, at once."""
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(Request(host=host, port=80, scheme="http",
                        headers=Headers([("Host", bracketed(host))])),
                client_conn=Client(sni=None))  # fmt: skip
    send(gate, flow)
    assert status(flow) == REFUSALS["private_address"][0]
    assert channel.asked == []
    assert channel.actions() == ["blocked:private_address"]
    assert channel.told[0]["risk"] == 2


@pytest.mark.parametrize("host", PRIVATE_LITERALS)
def test_a_connect_to_a_private_ip_literal_is_refused(host: str) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(Request(host=host, port=443, method="CONNECT",
                        headers=Headers([("Host", f"{bracketed(host)}:443")])),
                client_conn=Client(sni=None))  # fmt: skip
    gate.http_connect(flow)
    assert status(flow) == REFUSALS["private_address"][0]
    assert channel.actions() == ["blocked:private_address"]


def test_a_real_key_towards_a_private_ip_literal_is_still_a_real_key() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(Request(host="10.0.0.1", port=80, scheme="http", raw_content=REAL.encode(),
                        headers=Headers([("Host", "10.0.0.1")])),
                client_conn=Client(sni=None))  # fmt: skip
    send(gate, flow)
    assert channel.actions() == ["blocked:real_key"]


def test_a_granted_ip_literal_is_not_refused_early() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel, public=frozenset({"172.30.0.9"}))
    flow = Flow(Request(host="172.30.0.9", headers=Headers([("Host", "172.30.0.9")])),
                client_conn=Client(sni=None))  # fmt: skip
    send(gate, flow)
    assert flow.response is None and len(channel.asked) == 1


def test_the_tests_fake_internet_can_be_granted_as_public() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel, addresses=["172.30.0.9"], public=frozenset({"172.30.0.9"}))
    flow = Flow()
    send(gate, flow)
    assert connect(gate, flow).address == ("172.30.0.9", 443)


def test_a_connection_to_another_target_than_the_acked_one_is_refused() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    assert connect(gate, flow, ("evil.example", 443)).error is not None
    other_client = Flow(client_conn=Client(id="client-2"))
    assert connect(gate, other_client).error is not None


# --- limits --------------------------------------------------------------------------------------


def test_only_the_agent_side_may_connect_and_only_so_many_at_once() -> None:
    channel = FakeChannel(limits={"max_connections": 2})
    gate, _ = make_gate(channel)
    outsider = Client(id="x", sockname=("172.19.0.3", 8080))
    gate.client_connected(outsider)
    assert outsider.error is not None
    clients = [Client(id=f"c{n}") for n in range(3)]
    for client in clients:
        gate.client_connected(client)
    assert [c.error is None for c in clients] == [True, True, False]
    gate.client_disconnected(clients[0])
    again = Client(id="c9", sockname=(f"::ffff:{AGENT_SIDE}", 8080))
    gate.client_connected(again)
    assert again.error is None


def test_only_so_many_requests_wait_at_once() -> None:
    channel = FakeChannel(limits={"max_pending": 2})
    gate, _ = make_gate(channel)
    flows = [Flow(id=f"f{n}") for n in range(3)]
    for flow in flows:
        gate.requestheaders(flow)
    assert [status(f) for f in flows] == [None, None, 429]
    assert channel.throttled == 1 and channel.told == []  # counted, not one event each
    asyncio.run(gate.request(flows[0]))  # done: its place is free again
    late = Flow(id="f9")
    gate.requestheaders(late)
    assert status(late) is None


def with_body(flow_id: str, size: int = 100) -> Flow:
    headers = Headers([("Host", "example.com"), ("Content-Length", str(size))])
    return Flow(id=flow_id, request=Request(headers=headers, raw_content=b"x" * size))


def chunked(flow_id: str) -> Flow:
    headers = Headers([("Host", "example.com"), ("Transfer-Encoding", "chunked")])
    return Flow(id=flow_id, request=Request(headers=headers))


def bodyless(flow_id: str) -> Flow:
    headers = Headers([("Host", "example.com")])
    return Flow(id=flow_id, request=Request(method="GET", headers=headers, raw_content=b""))


def test_a_request_refused_at_its_headers_still_holds_a_place_while_its_body_is_read() -> None:
    # mitmproxy reads (and keeps, up to 16 MiB) the body of a request that already has its
    # answer (T06-7): so a refusal with a body counts among the requests waiting, or 256 of them
    # would hold 4 GiB in a proxy of 1 GiB.
    channel = FakeChannel(limits={"max_pending": 2})
    channel.ready = False  # no channel: every request is a 503
    gate, _ = make_gate(channel)
    first, second = with_body("f1"), chunked("f2")
    gate.requestheaders(first)
    gate.requestheaders(second)
    assert [status(first), status(second)] == [503, 503]
    third = with_body("f3")
    gate.requestheaders(third)
    assert third.killed and third.response is None  # cut: answering it would read its body
    asyncio.run(gate.request(first))  # mitmproxy read the body and calls request: place freed
    fourth = with_body("f4")
    gate.requestheaders(fourth)
    assert not fourth.killed and status(fourth) == 503


def test_over_the_pending_limit_a_body_is_cut_and_a_bodyless_request_gets_429() -> None:
    channel = FakeChannel(limits={"max_pending": 1})
    gate, _ = make_gate(channel)
    waiting = with_body("f0")
    gate.requestheaders(waiting)
    assert status(waiting) is None
    cut, plain = with_body("f1"), bodyless("f2")
    gate.requestheaders(cut)
    gate.requestheaders(plain)
    assert cut.killed and cut.response is None
    assert status(plain) == 429 and not plain.killed
    assert channel.throttled == 2 and channel.told == []  # counted together, as before
    gate.error(cut)  # mitmproxy reports the killed flow: nothing to free, nothing recorded
    assert channel.told == []


def test_a_streamed_body_over_the_limit_is_recorded_as_too_large() -> None:
    # A chunked body has no length to check at its headers: mitmproxy cuts it at
    # body_size_limit and calls only the error hook (T06-7: it went unrecorded).
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = chunked("big")
    gate.requestheaders(flow)
    assert status(flow) is None
    flow.error = FlowError("Request body exceeds mitmproxy.options.body_size_limit.")
    gate.error(flow)
    assert channel.actions() == ["blocked:too_large"]
    assert channel.told[0]["details"]["host"] == "example.com"
    assert channel.told[0]["risk"] == 1
    again = with_body("next")  # its place is free
    gate.requestheaders(again)
    assert status(again) is None


def test_a_client_that_hangs_up_mid_body_is_not_recorded_as_too_large() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = chunked("gone")
    gate.requestheaders(flow)
    flow.error = FlowError("Client disconnected.")
    gate.error(flow)
    assert channel.told == []


def test_the_decoded_body_is_let_go_before_waiting_for_the_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 32 requests wait for their ack at once: each must hold its raw body only (mitmproxy's),
    # not a second, decoded copy of up to 16 MiB too (T06-7).
    freed: list[str] = []

    class Tracked(bytes):
        def __del__(self) -> None:
            freed.append("decoded")

    monkeypatch.setattr(addon, "decode_body", lambda raw, encoding: Tracked(raw or b""))
    seen: list[list[str]] = []

    class Watching(FakeChannel):
        async def ask(self, event: dict[str, Any]) -> Ack:
            import gc

            gc.collect()
            seen.append(list(freed))
            return await super().ask(event)

    channel = Watching()
    gate, _ = make_gate(channel)
    flow = with_body("f1", 4096)
    send(gate, flow)
    assert status(flow) is None
    assert seen == [["decoded"]]


# --- a hook that fails ---------------------------------------------------------------------------


def test_a_failing_request_hook_answers_502_and_records_the_error() -> None:
    channel = FakeChannel()
    channel.answer = RuntimeError("boom")
    gate, died = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    assert status(flow) == FAILED[0]
    assert channel.actions() == ["error:"]
    assert channel.told[0]["details"]["stage"] == "request"
    assert connect(gate, flow).error is not None
    assert died == []


def test_a_request_that_breaks_the_gate_never_goes_out() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    flow.request.headers = None  # type: ignore[assignment] - anything that makes a hook raise
    send(gate, flow)
    assert status(flow) == 502 and channel.asked == []


def test_a_failing_server_connect_opens_nothing() -> None:
    channel = FakeChannel()
    gate, died = make_gate(channel)
    flow = Flow()
    send(gate, flow)

    async def broken(host: str, port: int) -> list[str]:
        raise OSError("resolver down")

    gate._resolve = broken  # type: ignore[assignment]
    assert connect(gate, flow).error is not None
    assert channel.actions() == ["error:"] and died == []


def test_a_failing_response_hook_kills_the_flow() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    flow.response = Response(200, headers=None)  # type: ignore[arg-type]
    gate.responseheaders(flow)
    assert flow.killed and channel.actions() == ["error:"]


def test_when_even_stopping_the_flow_fails_the_proxy_dies() -> None:
    channel = FakeChannel()
    channel.answer = RuntimeError("boom")
    gate, died = make_gate(channel)

    class Unstoppable(Flow):
        def __setattr__(self, name: str, value: Any) -> None:
            if name == "response" and value is not None:
                raise RuntimeError("cannot answer")
            super().__setattr__(name, value)

        def kill(self) -> None:
            raise RuntimeError("cannot kill")

    flow = Unstoppable()
    send(gate, flow)
    assert died == ["died"]


# --- responses -----------------------------------------------------------------------------------


SSE = (
    b'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-x",'
    b'"usage":{"input_tokens":11,"output_tokens":1}}}\n\n'
    b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"HELLO"}}\n\n'
    b'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
    b'"usage":{"output_tokens":5}}\n\n'
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)


def stream_through(
    gate: Gate, flow: Flow, body: bytes, content_type: str, *headers: tuple[str, str]
) -> bytes:
    """What the agent gets, as mitmproxy would send it: a stream chunk by chunk (and an empty
    chunk at its end), or, when the gate holds the answer whole, all of it after the response
    hook, unless that hook killed the flow."""
    flow.response = Response(200, headers=Headers([("content-type", content_type), *headers]))
    gate.responseheaders(flow)
    if callable(flow.response.stream):
        chunks = [body[i : i + 7] for i in range(0, len(body), 7)] + [b""]
        out = b""
        for chunk in chunks:
            out += flow.response.stream(chunk)
        gate.response(flow)
        return out
    assert flow.response.stream is False
    flow.response.content = body
    gate.response(flow)
    return b"" if flow.killed else body


def test_a_provider_stream_passes_untouched_and_only_its_usage_is_recorded() -> None:
    times = iter([10.0, 10.25])
    channel = FakeChannel()
    gate, _ = make_gate(channel, clock=lambda: next(times))
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    assert stream_through(gate, flow, SSE, "text/event-stream") == SSE
    [event] = channel.told
    assert (event["source"], event["action"]) == ("llm", "response")
    details = event["details"]
    assert details["usage"] == {"input": 11, "output": 5}
    assert details["model"] == "claude-x" and details["stop_reason"] == "end_turn"
    assert details["size"] == len(SSE) and details["duration_ms"] == 250
    assert "HELLO" not in json.dumps(event)


def test_a_provider_json_answer_is_summarized() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = json.dumps({"model": "claude-x", "usage": {"input_tokens": 3, "output_tokens": 4},
                       "content": [{"type": "text", "text": "HELLO"}]}).encode()  # fmt: skip
    stream_through(gate, flow, body, "application/json")
    assert channel.told[0]["details"]["usage"] == {"input": 3, "output": 4}


def test_any_other_answer_is_recorded_by_size_and_type_only() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    stream_through(gate, flow, b"<html>private page</html>", "text/html; charset=utf-8")
    [event] = channel.told
    assert (event["action"], event["details"]["size"], event["details"]["type"]) == (
        "response", 25, "text/html",
    )  # fmt: skip
    assert "private page" not in json.dumps(event)


def test_the_proxys_own_refusals_are_not_recorded_twice() -> None:
    channel = FakeChannel()
    channel.answer = Ack("deny", reason="not_allowed")
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    gate.response(flow)
    assert channel.told == []


def test_a_transport_error_after_the_ack_is_recorded() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    gate.error(flow)
    assert channel.told[0]["details"]["stage"] == "flow"


def test_a_provider_stream_cut_after_its_answer_still_records_its_summary() -> None:
    """Seen in the VM (T06-5): a client that closes the stream as soon as it has the answer
    (OpenAI's ``[DONE]``) makes mitmproxy end the flow with an error, not ``response``. What
    the tap saw is still recorded (``llm/response``), then the error."""
    times = iter([10.0, 10.5])
    channel = FakeChannel()
    gate, _ = make_gate(channel, clock=lambda: next(times))
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    flow.response = Response(200, headers=Headers([("content-type", "text/event-stream")]))
    gate.responseheaders(flow)
    flow.response.stream(SSE)
    gate.error(flow)
    assert [(e["source"], e["action"]) for e in channel.told] == [
        ("llm", "response"),
        ("net", "error"),
    ]
    assert channel.told[0]["details"]["usage"] == {"input": 11, "output": 5}
    assert channel.told[0]["details"]["size"] == len(SSE)


def test_an_error_before_any_answer_records_only_the_error() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    gate.error(flow)
    assert [e["action"] for e in channel.told] == ["error"]


def test_a_tls_failure_is_recorded() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)

    @dataclass
    class TlsData:
        conn: Client
        context: Any = None

    gate.tls_failed_client(TlsData(Client(sni="pinned.example")))
    assert channel.told[0]["action"] == "tls_failed"
    assert channel.told[0]["details"]["sni"] == "pinned.example"


# --- WebSocket -----------------------------------------------------------------------------------


def test_websocket_messages_are_summarized_and_a_real_key_kills_it() -> None:
    now = [0.0]
    channel = FakeChannel()
    gate, _ = make_gate(channel, clock=lambda: now[0])
    flow = Flow(websocket=WebSocket())
    send(gate, flow)
    gate.websocket_start(flow)
    for text, from_client in ((b"hi", True), (b"hello there", False)):
        flow.websocket.messages.append(WsMessage(from_client, text))  # type: ignore[union-attr]
        gate.websocket_message(flow)
    now[0] = 2.5
    flow.websocket.messages.append(WsMessage(True, b"more"))  # type: ignore[union-attr]
    gate.websocket_message(flow)
    summary = channel.told[-1]
    assert summary["action"] == "websocket_summary"
    assert summary["details"]["to_server_messages"] == 2
    assert summary["details"]["to_client_bytes"] == 11
    flow.websocket.messages.append(WsMessage(True, REAL.encode()))  # type: ignore[union-attr]
    gate.websocket_message(flow)
    assert flow.killed
    assert channel.actions()[-1] == "blocked:real_key"
    flow.killed = False
    channel.ready = False  # the channel is gone: nothing more goes out, not even here
    flow.websocket.messages.append(WsMessage(True, b"still talking"))  # type: ignore[union-attr]
    gate.websocket_message(flow)
    assert flow.killed and channel.actions()[-1] == "blocked:not_recorded"
    flow.websocket.close_code = 1006  # type: ignore[union-attr]
    gate.websocket_end(flow)
    assert channel.told[-1]["details"]["close_code"] == 1006
    assert REAL not in json.dumps(channel.told) and "hello there" not in json.dumps(channel.told)


def test_websocket_messages_are_not_kept_once_checked() -> None:
    # mitmproxy keeps every message of a WebSocket in the flow, for as long as it is open: a
    # long one would fill the proxy's memory (T06-7). The gate forgets each once checked.
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(websocket=WebSocket())
    send(gate, flow)
    gate.websocket_start(flow)
    for n in range(5):
        flow.websocket.messages.append(WsMessage(n % 2 == 0, b"x" * 1000))  # type: ignore[union-attr]
        gate.websocket_message(flow)
        assert flow.websocket.messages == []  # type: ignore[union-attr]
    gate.websocket_end(flow)
    assert channel.told[-1]["details"]["to_server_bytes"] == 3000
    assert channel.told[-1]["details"]["to_client_messages"] == 2


# --- provider-side tools (T06-6) -----------------------------------------------------------------


def model_flow(body: bytes, path: str = "/v1/messages", method: str = "POST") -> Flow:
    flow = provider_flow(("x-api-key", FAKE), ("content-type", "application/json"))
    flow.request.raw_content = body
    flow.request.path = path
    flow.request.method = method
    return flow


def tool_body(*tools: dict[str, Any], **extra: Any) -> bytes:
    request = {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
    return json.dumps(request | {"tools": list(tools)} | extra).encode()


def test_a_provider_side_tool_is_refused_before_backtide_is_asked() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body({"type": "web_fetch_20250910", "name": "web_fetch"}))
    send(gate, flow)
    assert status(flow) == 403
    assert channel.asked == []
    [event] = channel.told
    assert event["details"]["reason"] == "provider_side_tool"
    assert event["details"]["tools"] == ["web_fetch_20250910"]
    assert event["risk"] == 2
    assert dict(flow.request.headers.items())["x-api-key"] == FAKE  # never swapped
    assert REAL not in json.dumps(event)


def test_mcp_servers_are_refused_and_named() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    servers = [{"type": "url", "url": "https://mcp.example/", "name": "x"}]
    send(gate, model_flow(tool_body(mcp_servers=servers)))
    assert channel.told[0]["details"]["tools"] == ["mcp_servers"]
    assert "mcp.example" not in json.dumps(channel.told)


def test_an_allowed_provider_tool_goes_on_and_is_recorded() -> None:
    channel = FakeChannel(provider_tools=frozenset({"web_search_20250305"}))
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body({"type": "web_search_20250305", "name": "web_search"}))
    send(gate, flow)
    assert flow.response is None
    [event] = channel.asked
    assert event["details"]["provider_tools"] == ["web_search_20250305"]


@pytest.mark.parametrize(
    ("flow_", "code", "reason"),
    [
        (lambda: model_flow(b"not json"), 400, "provider_body"),
        (lambda: model_flow(b'{"tools": [], "tools": [{"type": "x"}]}'), 400, "provider_body"),
        (lambda: model_flow(tool_body(), path="/v1/messages/batches"), 403, "provider_endpoint"),
        (lambda: model_flow(tool_body(), path="/v1/files"), 403, "provider_endpoint"),
        (lambda: model_flow(b"", path="/v1/files/f/content", method="GET"), 403,
         "provider_endpoint"),
    ],
)  # fmt: skip
def test_what_is_not_a_model_call_is_refused(
    flow_: Callable[[], Flow], code: int, reason: str
) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = flow_()
    send(gate, flow)
    assert (status(flow), channel.actions(), channel.asked) == (code, [f"blocked:{reason}"], [])


def test_a_plain_model_call_still_goes_on() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body({"name": "exec", "input_schema": {"type": "object"}}))
    send(gate, flow)
    assert flow.response is None
    assert dict(flow.request.headers.items())["x-api-key"] == REAL
    assert "provider_tools" not in channel.asked[0]["details"]


def test_the_same_body_to_an_ordinary_host_is_left_to_the_allowed_list() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    flow.request.raw_content = tool_body({"type": "web_search"})
    send(gate, flow)
    assert flow.response is None and len(channel.asked) == 1


# --- IPv4 written as numbers (T06-6) -------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.1", "0x7f.1", "2130706433", "0177.0.0.1", "169.254.43518"])
def test_a_private_ip_written_as_numbers_is_refused_before_backtide_is_asked(host: str) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow(
        Request(host=host, port=80, scheme="http", headers=Headers([("Host", host)])),
        client_conn=Client(sni=None),
    )
    send(gate, flow)
    assert (status(flow), channel.actions(), channel.asked) == (
        403,
        ["blocked:private_address"],
        [],
    )
    tunnel = Flow(Request(host=host, port=443, method="CONNECT"))
    gate.http_connect(tunnel)
    assert status(tunnel) == 403


def test_a_public_ip_written_as_numbers_is_left_to_the_allowed_list() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    host = "134744072"  # 8.8.8.8
    flow = Flow(
        Request(host=host, port=80, scheme="http", headers=Headers([("Host", host)])),
        client_conn=Client(sni=None),
    )
    send(gate, flow)
    assert len(channel.asked) == 1


# --- the provider's answer, checked for the real key (T06-6) --------------------------------------


def echo_events(*texts: str) -> bytes:
    out = SSE.split(b"\n\n", 1)[0] + b"\n\n"
    for text in texts:
        data = {"type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": text}}  # fmt: skip
        out += b"event: content_block_delta\ndata: " + json.dumps(data).encode() + b"\n\n"
    return out


def test_a_whole_answer_from_a_provider_is_held_and_checked_before_it_goes_on() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = json.dumps({"type": "error", "error": {"message": f"invalid x-api-key {REAL}"}})
    got = stream_through(gate, flow, body.encode(), "application/json")
    assert got == b"" and flow.killed
    [event] = channel.told
    assert (event["details"]["reason"], event["details"]["side"], event["risk"]) == (
        "real_key", "response", 3,
    )  # fmt: skip
    assert REAL not in json.dumps(event)


def test_a_clean_whole_answer_goes_on_and_is_summarized() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = json.dumps({"model": "claude-x", "usage": {"input_tokens": 3, "output_tokens": 4}})
    assert stream_through(gate, flow, body.encode(), "application/json") == body.encode()
    assert not flow.killed
    assert channel.told[0]["details"]["usage"] == {"input": 3, "output": 4}
    assert channel.told[0]["details"]["size"] == len(body)


def test_a_key_in_a_compressed_answer_is_found() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = gzip.compress(echo_events(REAL))
    got = stream_through(gate, flow, body, "text/event-stream", ("content-encoding", "gzip"))
    assert got == b"" and flow.killed
    assert channel.actions() == ["blocked:real_key"]


def test_an_answer_that_cannot_be_decoded_is_not_let_through() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    got = stream_through(gate, flow, b"\x00garbage", "application/json", ("content-encoding", "br"))
    assert got == b"" and flow.killed
    assert [e["action"] for e in channel.told] == ["error"]


@pytest.mark.parametrize("cut", [10, 40, 77])
def test_a_streamed_answer_is_cut_before_the_key_is_whole(cut: int) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = echo_events("Your key: ", REAL[:cut], REAL[cut:], " bye")
    got = stream_through(gate, flow, body, "text/event-stream")
    assert REAL not in got.decode() and flow.killed
    assert b" bye" not in got
    blocked_ = [e for e in channel.told if e["action"] == "blocked"]
    assert [(e["details"]["reason"], e["details"]["side"]) for e in blocked_] == [
        ("real_key", "response")
    ]


def test_a_clean_stream_still_passes_untouched() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = echo_events("sk-ant-api03-", "TEST is how keys start")
    assert stream_through(gate, flow, body, "text/event-stream") == body
    assert not flow.killed


def test_after_a_failure_the_tap_lets_nothing_more_through() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = Flow()
    send(gate, flow)
    flow.response = Response(200, headers=Headers([("content-type", "text/plain")]))
    gate.responseheaders(flow)
    tap = flow.response.stream
    tap._json = None
    tap.size = "broken"  # the next chunk makes the tap fail
    assert tap(b"one") == b""
    tap.size = 0
    assert tap(b"two") == b""
    assert flow.killed


# --- after the review of T06-6 --------------------------------------------------------------------


def answered(gate: Gate, flow: Flow, **response: Any) -> None:
    send(gate, flow)
    flow.response = Response(200, **response)
    gate.responseheaders(flow)


@pytest.mark.parametrize(
    "response",
    [
        {"headers": Headers([("content-type", "application/json"), ("x-debug", f"k={REAL}")])},
        {"headers": Headers([("content-type", "text/event-stream"), ("x-debug", REAL.lower())])},
        {"headers": Headers([("content-type", "text/event-stream")]), "reason": f"bad {REAL}"},
    ],
)
def test_a_key_in_the_answers_headers_or_status_is_stopped_before_they_go(
    response: dict[str, Any],
) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    answered(gate, flow, **response)
    assert flow.killed and flow.response.stream is None
    assert channel.actions() == ["blocked:real_key"]


@pytest.mark.parametrize("content_type", ["application/json", "text/event-stream"])
def test_a_key_in_the_answers_trailers_is_stopped(content_type: str) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    flow.response = Response(200, headers=Headers([("content-type", content_type)]))
    gate.responseheaders(flow)
    flow.response.trailers = Headers([("x-trailer", REAL)])
    if callable(flow.response.stream):
        flow.response.stream(b"")
    gate.response(flow)
    assert flow.killed
    assert [e["action"] for e in channel.told] == ["blocked"]


def test_an_answer_with_another_transfer_encoding_is_not_let_through() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    headers = Headers(
        [("content-type", "text/event-stream"), ("transfer-encoding", "gzip, chunked")]
    )
    answered(gate, flow, headers=headers)
    assert flow.killed
    assert [e["details"]["stage"] for e in channel.told] == ["response_transfer_encoding"]


def test_answers_held_whole_share_a_memory_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(addon, "HELD_BUDGET", 1000)
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    json_headers = [("content-type", "application/json")]
    first = provider_flow(("x-api-key", FAKE))
    answered(gate, first, headers=Headers([*json_headers, ("content-length", "800")]))
    assert not first.killed
    second = provider_flow(("x-api-key", FAKE))
    second.id = "flow-2"
    answered(gate, second, headers=Headers([*json_headers, ("content-length", "800")]))
    assert second.killed
    assert channel.told[-1]["details"]["stage"] == "response_budget"
    unknown = provider_flow(("x-api-key", FAKE))
    unknown.id = "flow-3"
    answered(gate, unknown, headers=Headers(json_headers))  # no length: the worst is reserved
    assert unknown.killed
    first.response.content = b'{"model": "m"}'
    gate.response(first)  # done: its part of the budget is free again
    third = provider_flow(("x-api-key", FAKE))
    third.id = "flow-4"
    answered(gate, third, headers=Headers([*json_headers, ("content-length", "800")]))
    assert not third.killed
    gate.error(third)  # an error frees it too
    assert gate.held_bytes == 0


def test_the_answer_is_checked_against_the_key_its_request_carried() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    other = "sk-ant-api03-TEST" + "r0tat3dK3y" * 5
    rotated = Providers(
        [Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(other))]
    )
    channel.config = GateConfig(rotated, KnownScrubber(rotated.known_secrets()), DEFAULT_LIMITS)
    got = stream_through(gate, flow, json.dumps({"echo": REAL}).encode(), "application/json")
    assert got == b"" and flow.killed


def test_a_key_in_the_answer_is_recorded_even_when_the_flow_cannot_be_killed() -> None:
    channel = FakeChannel()
    gate, died = make_gate(channel)

    class Unkillable(Flow):
        def kill(self) -> None:
            raise RuntimeError("cannot kill")

    flow = Unkillable(provider_flow(("x-api-key", FAKE)).request,
                      client_conn=Client(sni="api.anthropic.com"))  # fmt: skip
    send(gate, flow)
    flow.response = Response(200, headers=Headers([("content-type", "text/event-stream")]))
    gate.responseheaders(flow)
    assert flow.response.stream(echo_events(REAL)) == b""
    assert channel.actions()[-1] == "blocked:real_key"
    assert died == ["died"]
