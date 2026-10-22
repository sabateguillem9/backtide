"""T20-2 and T20-3 (docs/35, sections 6.1 to 6.4): a local model provider in the gate. Its pure
rules (backtide/gate/providers.py, provider_tools.py, protocol.py) and the proxy's hooks on the
fakes of mitmproxy's objects of test_gate_addon.py: the virtual name, the fake key that is
dropped, the closed list of routes, the rewrite to the fixed address, the one exception in
``server_connect``, the cut of a redirection and the events with ``local: true``. Also Ollama's
cloud API, a public provider whose routes are compared exactly too."""

import asyncio
import json
from typing import Any

import pytest

from backtide.blackbox.redact import KnownScrubber
from backtide.gate import protocol, record
from backtide.gate.client import Ack, GateConfig
from backtide.gate.protocol import DEFAULT_LIMITS, ProtocolError, Sender, validate_event
from backtide.gate.provider_tools import check_request, endpoint_of, exact_endpoint, ollama_admin
from backtide.gate.providers import (
    FAKE_KEY_PREFIX,
    MAX_LOCAL,
    Kind,
    Provider,
    Providers,
    Secret,
    is_cloud_model,
    is_ollama_cloud,
    local_address_ok,
    new_fake_key,
    only_fake_key,
    swap_key,
    virtual_host,
)
from tests.test_gate_addon import (
    FAKE,
    REAL,
    Client,
    ConnectData,
    FakeChannel,
    Flow,
    Headers,
    Request,
    Response,
    Server,
    make_gate,
    send,
    status,
)

LOCAL_FAKE = FAKE_KEY_PREFIX + "ollama-" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6"
CLAUDE_FAKE = FAKE_KEY_PREFIX + "ollama-claude-" + "Z1x2C3v4B5n6M7a8S9d0F1g2H3j4K5l6"
CLOUD_FAKE = FAKE_KEY_PREFIX + "ollama-cloud-" + "P1o2I3u4Y5t6R7e8W9q0L1k2J3h4G5f6"
CLOUD_REAL = "c0ffee" * 6 + ".ollamacloudtestkey"
MAC = "192.168.5.2"
PORT = 11434
MODEL = "qwen3-coder:30b"
VIRTUAL = "ollama.backtide.internal"


def local(name: str = "ollama", fake: str = LOCAL_FAKE, **changes: Any) -> Provider:
    options: dict[str, Any] = {
        "name": name,
        "kind": Kind.OPENAI,
        "host": virtual_host(name),
        "fake_key": fake,
        "real_key": None,
        "models": (MODEL,),
        "local": True,
        "upstream": (MAC, PORT),
    } | changes
    return Provider(**options)


def all_providers() -> Providers:
    return Providers(
        [
            Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL)),
            local(),
            local("ollama-claude", CLAUDE_FAKE, kind=Kind.ANTHROPIC),
            Provider(
                "ollama-cloud",
                Kind.OPENAI,
                "ollama.com",
                CLOUD_FAKE,
                Secret(CLOUD_REAL),
                models=("gpt-oss:120b",),
            ),
        ]
    )


def local_channel() -> FakeChannel:
    channel = FakeChannel()
    providers = all_providers()
    channel.config = GateConfig(providers, KnownScrubber(providers.known_secrets()), DEFAULT_LIMITS)
    return channel


def chat(model: str = MODEL, **extra: Any) -> bytes:
    return json.dumps(
        {"model": model, "messages": [{"role": "user", "content": "hi"}]} | extra
    ).encode()


def local_flow(
    path: str = "/v1/chat/completions",
    *headers: tuple[str, str],
    method: str = "POST",
    body: bytes | None = None,
    host: str = VIRTUAL,
    client: str = "client-1",
    flow_id: str = "flow-1",
) -> Flow:
    if not headers:
        headers = (("Authorization", f"Bearer {LOCAL_FAKE}"),)
    return Flow(
        Request(
            host=host,
            path=path,
            method=method,
            headers=Headers([("Host", host), ("Content-Type", "application/json"), *headers]),
            raw_content=chat() if body is None and method == "POST" else (body or b""),
        ),
        id=flow_id,
        client_conn=Client(id=client, sni=host),
    )


# --- the provider (6.1) ---------------------------------------------------------------------------


@pytest.mark.parametrize("address", ["192.168.5.2", "10.0.0.7", "172.20.0.3", "100.101.102.103"])
def test_a_local_provider_may_be_at_a_private_ipv4(address: str) -> None:
    assert local_address_ok(address)
    assert local(upstream=(address, PORT)).upstream == (address, PORT)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # inside the proxy, the proxy itself
        "0.0.0.0",  # noqa: S104 - "this network"
        "169.254.169.254",  # a cloud's metadata
        "224.0.0.1",  # multicast
        "255.255.255.255",  # broadcast
        "8.8.8.8",  # public: it goes by https like any provider
        "192.168.0.0",  # a network's own address
        "10.255.255.255",  # and its last one
        "::1",
        "fd00::1",
        "::ffff:192.168.5.2",
        "0xc0a80502",
        "3232236802",
        "192.168.5.02",
        " 192.168.5.2",
    ],
)
def test_a_local_provider_is_never_anywhere_else(address: str) -> None:
    assert not local_address_ok(address)
    with pytest.raises(ValueError, match="private IPv4"):
        local(upstream=(address, PORT))


@pytest.mark.parametrize("port", [0, 65536, -1, True, "11434"])
def test_a_local_provider_has_a_real_port(port: object) -> None:
    with pytest.raises(ValueError):
        local(upstream=(MAC, port))


def test_a_local_providers_host_is_its_virtual_name() -> None:
    assert virtual_host("ollama") == VIRTUAL
    with pytest.raises(ValueError, match="virtual name"):
        local(host="ollama.lan")
    with pytest.raises(ValueError, match="virtual name or an upstream"):
        Provider("other", Kind.OPENAI, "x.backtide.internal", new_fake_key("other"), Secret(REAL))
    with pytest.raises(ValueError, match="virtual name or an upstream"):
        Provider("p", Kind.OPENAI, "api.p.test", new_fake_key("p"), None, upstream=(MAC, PORT))


def test_a_local_provider_has_no_real_key_and_never_waits_for_one() -> None:
    with pytest.raises(ValueError, match="no real key"):
        local(real_key=Secret(REAL))
    provider = local()
    assert not provider.waiting and provider.exact_paths
    assert Providers([provider]).waiting() == ()
    assert (
        swap_key(provider, [("authorization", f"Bearer {LOCAL_FAKE}")], scheme="https", port=443)
        is None
    )


@pytest.mark.parametrize(
    "models", [(), ("qwen3:480b-cloud",), (MODEL, "gpt-oss:cloud"), ("deepseek-v3.1:671b-cloud",)]
)
def test_a_local_provider_lists_its_models_and_none_of_the_cloud(models: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="lists its models"):
        local(models=models)


@pytest.mark.parametrize(
    ("model", "cloud"),
    [
        ("qwen3:480b-cloud", True),
        ("gpt-oss:cloud", True),
        ("cloud", True),
        ("x:cloud-latest", True),
        (MODEL, False),
        ("soundcloud-7b", False),
        ("cloudy:3b", False),
        (3, False),
    ],
)
def test_which_models_run_in_ollamas_cloud(model: object, cloud: bool) -> None:
    assert is_cloud_model(model) is cloud


def test_at_most_four_local_providers() -> None:
    names = [f"local-{n}" for n in range(MAX_LOCAL + 1)]
    items = [local(name, new_fake_key(name)) for name in names]
    assert len(Providers(items[:MAX_LOCAL]).items) == MAX_LOCAL
    with pytest.raises(ValueError, match="local providers"):
        Providers(items)


def test_the_upstream_is_found_by_its_exact_pair() -> None:
    providers = all_providers()
    found = providers.local_at(MAC, PORT)
    assert found is not None and found.name == "ollama"  # the first of the two at that place
    assert providers.local_at(MAC, 22) is None and providers.local_at("192.168.5.3", PORT) is None


# --- the routes, compared exactly (6.2, step 4) ---------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "method", "path", "endpoint"),
    [
        ("openai", "POST", "/v1/chat/completions", "chat"),
        ("openai", "POST", "/v1/chat/completions?x=1", "chat"),
        ("openai", "POST", "/v1/completions", "completions"),
        ("openai", "POST", "/v1/embeddings", "embeddings"),
        ("openai", "POST", "/v1/responses", "responses"),
        ("openai", "GET", "/v1/models", "models"),
        ("openai", "GET", f"/v1/models/{MODEL}", "models"),
        ("anthropic", "POST", "/v1/messages", "messages"),
        ("anthropic", "POST", "/v1/messages?beta=true", "messages"),
        ("anthropic", "POST", "/v1/messages/count_tokens", "count_tokens"),
    ],
)
def test_only_the_model_routes_pass(kind: str, method: str, path: str, endpoint: str) -> None:
    assert exact_endpoint(kind, method, path, models=(MODEL,)) == endpoint


@pytest.mark.parametrize(
    ("kind", "method", "path"),
    [
        ("openai", "POST", "/api/pull"),
        ("openai", "POST", "/api/chat"),
        ("openai", "POST", "/api/generate"),
        ("openai", "GET", "/api/tags"),
        ("openai", "GET", "/api/version"),
        ("openai", "DELETE", "/api/delete"),
        ("openai", "POST", "/v1/responses/compact"),
        ("openai", "POST", "/v1/audio/transcriptions"),
        ("openai", "GET", "/"),
        ("openai", "POST", "/v1/../api/pull"),
        ("openai", "POST", "/v1/chat/completions/../../api/pull"),
        ("openai", "POST", "/v1/%2e%2e/api/pull"),
        ("openai", "POST", "//api/pull"),
        ("openai", "POST", "//v1/chat/completions"),
        ("openai", "POST", "\\api\\pull"),
        ("openai", "POST", "/v1/chat/completions;x"),
        ("openai", "POST", "/v1/chat/completions/"),
        ("openai", "POST", "/V1/Chat/Completions"),
        ("openai", "POST", "/x/v1/chat/completions"),
        ("openai", "post", "/v1/chat/completions"),
        ("openai", "GET", "/v1/chat/completions"),
        ("openai", "GET", "/v1/models/other-model"),
        ("openai", "GET", "/v1/models/"),
        ("openai", "POST", "/v1/messages"),  # another kind's route
        ("anthropic", "POST", "/v1/chat/completions"),
        ("anthropic", "GET", "/v1/models"),
        ("gemini", "POST", "/v1/chat/completions"),
    ],
)
def test_anything_else_is_not_a_model_route(kind: str, method: str, path: str) -> None:
    assert exact_endpoint(kind, method, path, models=(MODEL,)) is None


@pytest.mark.parametrize(
    "header",
    [
        ("X-HTTP-Method-Override", "DELETE"),
        ("Upgrade", "websocket"),
        ("X-Original-URL", "/api/pull"),
    ],
)
def test_a_header_that_names_another_method_or_route_is_refused(header: tuple[str, str]) -> None:
    assert exact_endpoint("openai", "POST", "/v1/chat/completions", [header]) is None


@pytest.mark.parametrize(
    ("path", "admin"),
    [
        ("/api/pull", True),
        ("/api/push", True),
        ("/api/create", True),
        ("/api/copy", True),
        ("/api/delete", True),
        ("/api/blobs/sha256:abc", True),
        ("/api/experimental/web_search", True),
        ("/api/me", True),
        ("/api/signout", True),
        ("/api/user/keys/x", True),
        ("/v1/../api/pull", True),
        ("//API/Pull;x", True),
        ("/v1/%2e%2e/api/%70ull", True),
        ("\\api\\pull", True),
        ("/api/pull?insecure=true", True),
        ("/api/tags", False),
        ("/api/chat", False),
        ("/v1/chat/completions", False),
        ("/api/pulling", False),
        (None, False),
    ],
)
def test_ollamas_administration_routes_are_named(path: object, admin: bool) -> None:
    assert ollama_admin(path) is admin


def test_the_body_is_checked_as_any_providers() -> None:
    def verdict(body: bytes, path: str = "/v1/chat/completions") -> tuple[str | None, tuple]:
        result = check_request("openai", "POST", path, [], body, models=(MODEL,), exact=True)
        return result.reason, result.tools

    assert verdict(chat()) == (None, ())
    assert verdict(chat("llama3.2:3b")) == ("provider_side_tool", ("model_not_listed",))
    assert verdict(chat("qwen3:480b-cloud")) == ("provider_side_tool", ("model_not_listed",))
    assert verdict(chat(options={"num_ctx": 10_000_000})) == (
        "provider_side_tool",
        ("param:options",),
    )
    assert verdict(chat(keep_alive=-1)) == ("provider_side_tool", ("param:keep_alive",))
    assert verdict(chat(tools=[{"type": "web_search"}])) == ("provider_side_tool", ("web_search",))
    assert verdict(b"not json") == ("provider_body", ())
    assert verdict(chat(), "/api/chat") == ("provider_endpoint", ())
    assert endpoint_of("openai", "POST", "/v1/chat/completions", exact=True) == "chat"
    assert endpoint_of("openai", "POST", "/x/v1/chat/completions", exact=True) is None
    assert endpoint_of("openai", "POST", "/x/v1/chat/completions") == "chat"  # the public rule


# --- the channel and the events -------------------------------------------------------------------


def test_the_config_carries_where_a_local_provider_is() -> None:
    message = protocol.config([], all_providers(), DEFAULT_LIMITS, fp_key=b"k" * 32)
    line = protocol.encode(message, Sender.BACKTIDE)
    assert LOCAL_FAKE.encode() in line  # the fake key goes, as for any provider
    decoded = protocol.decode(line, Sender.BACKTIDE)
    entry = next(p for p in decoded["providers"] if p["name"] == "ollama")
    assert entry["local"] is True and entry["upstream"] == [MAC, PORT]
    assert entry["real_key"] is None and entry["host"] == VIRTUAL
    rebuilt = protocol.providers_from_config(decoded)
    assert rebuilt.by_name("ollama") == local()
    assert "ollama (local)" in protocol.describe(decoded)


@pytest.mark.parametrize(
    "change",
    [
        {"upstream": None},
        {"upstream": [MAC]},
        {"upstream": [MAC, "11434"]},
        {"upstream": ["127.0.0.1", PORT]},
        {"local": False},
        {"local": "yes"},
        {"real_key": REAL},
        {"host": "evil.example"},
        {"models": []},
    ],
)
def test_a_local_provider_the_proxy_cannot_use_is_refused_by_the_channel(change: dict) -> None:
    message = protocol.config([], Providers([local()]), DEFAULT_LIMITS, fp_key=b"k" * 32)
    message["providers"][0] |= change
    with pytest.raises(ProtocolError):
        protocol.decode(json.dumps(message).encode(), Sender.BACKTIDE)


def test_an_unresolved_local_provider_is_never_handed_to_the_proxy() -> None:
    with pytest.raises(ProtocolError, match="without its address"):
        protocol.config([], Providers([local(upstream=None)]), DEFAULT_LIMITS)


def test_an_upstream_is_only_for_a_local_provider() -> None:
    other = Provider("p", Kind.OPENAI, "api.p.test", new_fake_key("p"), Secret(REAL))
    message = protocol.config([], Providers([other]), DEFAULT_LIMITS, fp_key=b"k" * 32)
    message["providers"][0]["upstream"] = [MAC, PORT]
    with pytest.raises(ProtocolError, match="only for a local"):
        protocol.decode(json.dumps(message).encode(), Sender.BACKTIDE)


def blocked(path: str, *, is_local: bool = True, reason: str = "provider_endpoint") -> dict:
    flow = {
        "flow_id": "f",
        "method": "POST",
        "scheme": "https",
        "host": VIRTUAL,
        "port": 443,
        "path": path,
    }
    return record.blocked_event(reason, flow, (), local=is_local)


@pytest.mark.parametrize(
    ("path", "is_local", "reason", "risk"),
    [
        ("/api/pull", True, "provider_endpoint", 3),
        ("/v1/../api/delete", True, "provider_endpoint", 3),
        ("/api/pull", True, "foreign_credential", 3),
        ("/api/tags", True, "provider_endpoint", 2),
        ("/v1/chat/completions", True, "provider_side_tool", 2),
        ("/api/pull", False, "provider_endpoint", 2),  # not toward a local provider: as before
    ],
)
def test_a_refusal_on_ollamas_administration_routes_is_risk_3(
    path: str, is_local: bool, reason: str, risk: int
) -> None:
    event = blocked(path, is_local=is_local, reason=reason)
    assert event["risk"] == risk
    assert validate_event(event) == event
    for wrong in {0, 1, 2, 3} - {risk}:
        with pytest.raises(ProtocolError):
            validate_event(event | {"risk": wrong})


def test_a_local_call_is_recorded_as_local_with_no_key() -> None:
    flow = {
        "flow_id": "f",
        "method": "POST",
        "scheme": "https",
        "host": VIRTUAL,
        "port": 443,
        "path": "/v1/chat/completions",
        "headers": [],
        "body": chat(),
    }
    event = record.llm_request_event(flow, "ollama", (), endpoint="chat", upstream=(MAC, PORT))
    details = event["details"]
    assert details["local"] is True and details["upstream"] == f"{MAC}:{PORT}"
    assert details["key"] == "none" and details["model"] == MODEL
    assert validate_event(event) == event
    plain = record.llm_request_event(flow, "anthropic", (), endpoint="chat")
    assert "local" not in plain["details"] and plain["details"]["key"] == "swapped"


# --- the proxy (6.2, steps 2, 3, 7 and 8) ---------------------------------------------------------


def run_local(flow: Flow, **gate_options: Any) -> tuple[Any, FakeChannel, list[tuple[str, int]]]:
    channel = local_channel()
    looked_up: list[tuple[str, int]] = []
    gate, _ = make_gate(channel, **gate_options)

    async def resolve(host: str, port: int) -> list[str]:
        looked_up.append((host, port))
        # By default, a resolver that would say the Mac: never asked for a local provider.
        return list(gate_options.get("addresses", [MAC]))

    gate._resolve = resolve
    send(gate, flow)
    return gate, channel, looked_up


def connect_to(gate: Any, flow: Flow, address: tuple[str, int]) -> Server:
    server = Server(address)
    asyncio.run(gate.server_connect(ConnectData(server, flow.client_conn)))
    return server


def test_a_good_call_goes_to_the_fixed_address_without_any_credential() -> None:
    flow = local_flow(
        "/v1/chat/completions?stream=1",
        ("Authorization", f"Bearer {LOCAL_FAKE}"),
        ("Accept-Encoding", "gzip"),
    )
    gate, channel, looked_up = run_local(flow)
    assert flow.response is None  # it goes on
    request = flow.request
    assert (request.scheme, request.host, request.port) == ("http", MAC, PORT)
    sent = dict(request.headers.items())
    assert sent["host"] == f"{MAC}:{PORT}"
    assert sent["accept-encoding"] == "identity"
    assert not {"authorization", "x-api-key", "Authorization"} & set(sent)
    assert LOCAL_FAKE not in json.dumps(sent)
    [event] = channel.asked
    assert (event["source"], event["action"]) == ("llm", "request")
    details = event["details"]
    assert details["local"] is True and details["key"] == "none"
    assert details["upstream"] == f"{MAC}:{PORT}" and details["host"] == VIRTUAL
    assert details["endpoint"] == "chat" and details["provider"] == "ollama"
    server = connect_to(gate, flow, (MAC, PORT))
    assert server.error is None and server.address == (MAC, PORT)
    assert looked_up == []  # nothing is resolved, neither the virtual name nor the address


def test_the_anthropic_shape_drops_its_fake_key_too() -> None:
    flow = local_flow(
        "/v1/messages",
        ("x-api-key", CLAUDE_FAKE),
        host="ollama-claude.backtide.internal",
        body=json.dumps({"model": MODEL, "max_tokens": 5, "messages": []}).encode(),
    )
    run_local(flow)
    assert flow.response is None and flow.request.host == MAC
    assert "x-api-key" not in dict(flow.request.headers.items())


@pytest.mark.parametrize(
    "address",
    [(MAC, 22), (MAC, 8080), ("192.168.5.3", PORT), ("127.0.0.1", PORT), (VIRTUAL, 443)],
    ids=["same-ip-port-22", "same-ip-port-8080", "another-ip", "loopback", "virtual-name"],
)
def test_only_that_exact_pair_is_opened(address: tuple[str, int]) -> None:
    flow = local_flow()
    gate, channel, looked_up = run_local(flow)
    server = connect_to(gate, flow, address)
    assert server.error is not None
    assert looked_up == []


def test_the_pair_is_opened_only_for_the_client_that_was_acked() -> None:
    flow = local_flow()
    gate, _, _ = run_local(flow)
    other = Flow(client_conn=Client(id="client-2"))
    assert connect_to(gate, other, (MAC, PORT)).error is not None
    gate.client_disconnected(flow.client_conn)
    assert connect_to(gate, flow, (MAC, PORT)).error is not None  # gone with its client


def test_the_pair_is_not_opened_once_the_config_no_longer_has_it() -> None:
    flow = local_flow()
    gate, channel, _ = run_local(flow)
    moved = Providers([local(upstream=("192.168.5.9", PORT))])
    channel.config = GateConfig(moved, KnownScrubber(moved.known_secrets()), DEFAULT_LIMITS)
    assert connect_to(gate, flow, (MAC, PORT)).error is not None


def test_a_denied_local_call_is_not_rewritten_nor_opened() -> None:
    channel = local_channel()
    channel.answer = Ack("deny", reason="throttled", retry_after=2)
    gate, _ = make_gate(channel)
    flow = local_flow()
    send(gate, flow)
    assert status(flow) == 429 and flow.request.host == VIRTUAL
    assert connect_to(gate, flow, (MAC, PORT)).error is not None


@pytest.mark.parametrize(
    "headers",
    [
        (),
        (("Authorization", "Bearer sk-someone-elses-key-0123456789abcdef"),),
        (("x-api-key", LOCAL_FAKE),),  # the fake key in another kind's header
        (("Authorization", f"Bearer {LOCAL_FAKE}"), ("Cookie", "a=b")),
        (("Authorization", f"Bearer {CLAUDE_FAKE}"),),  # another local provider's fake key
    ],
    ids=["none", "another-key", "wrong-header", "two-credentials", "another-fake"],
)
def test_anything_but_its_fake_key_is_a_foreign_credential(headers: tuple) -> None:
    flow = (
        local_flow("/v1/chat/completions", *headers)
        if headers
        else local_flow("/v1/chat/completions", ("X-Nothing", "1"))
    )
    _, channel, _ = run_local(flow)
    assert status(flow) == 403 and channel.asked == []
    [told] = channel.told
    assert told["details"]["reason"] == "foreign_credential" and told["details"]["local"] is True
    assert flow.request.host == VIRTUAL


def test_a_real_key_toward_a_local_provider_is_a_real_key() -> None:
    flow = local_flow("/v1/chat/completions", ("Authorization", f"Bearer {REAL}"))
    _, channel, _ = run_local(flow)
    assert status(flow) == 403 and channel.actions() == ["blocked:real_key"]


def test_in_clear_or_on_another_port_it_is_a_foreign_credential() -> None:
    plain = local_flow()
    plain.request.scheme, plain.request.port = "http", 80
    plain.request.headers = Headers(
        [("Host", f"{VIRTUAL}:80"), ("Authorization", f"Bearer {LOCAL_FAKE}")]
    )
    _, channel, _ = run_local(plain)
    assert status(plain) == 403 and channel.actions() == ["blocked:foreign_credential"]


@pytest.mark.parametrize(
    ("path", "method", "risk"),
    [
        ("/api/pull", "POST", 3),
        ("/v1/../api/pull", "POST", 3),
        ("/api/delete", "DELETE", 3),
        ("/api/experimental/web_fetch", "POST", 3),
        ("/api/tags", "GET", 2),
        ("/", "GET", 2),
    ],
)
def test_a_route_off_the_list_never_goes_out(path: str, method: str, risk: int) -> None:
    flow = local_flow(path, method=method)
    gate, channel, _ = run_local(flow)
    assert status(flow) == 403 and channel.asked == []
    [told] = channel.told
    assert told["details"]["reason"] == "provider_endpoint" and told["risk"] == risk
    assert flow.request.host == VIRTUAL
    assert connect_to(gate, flow, (MAC, PORT)).error is not None


def test_a_body_with_ollamas_own_options_never_goes_out() -> None:
    flow = local_flow(body=chat(options={"num_ctx": 10_000_000}, keep_alive=-1))
    _, channel, _ = run_local(flow)
    assert status(flow) == 403 and channel.asked == []
    assert channel.told[0]["details"]["tools"] == ["param:keep_alive", "param:options"]


def test_a_local_provider_without_its_address_fails_closed() -> None:
    channel = FakeChannel()
    providers = Providers([local(upstream=None)])
    channel.config = GateConfig(providers, KnownScrubber(providers.known_secrets()), DEFAULT_LIMITS)
    gate, _ = make_gate(channel)
    flow = local_flow()
    send(gate, flow)
    assert status(flow) == 502 and channel.asked == []


def test_the_private_address_rule_stays_whole_for_what_the_agent_writes() -> None:
    for host in (MAC, "3232236802", "0xc0a80502", "host.lima.internal"):
        flow = local_flow(host=host)
        gate, channel, looked_up = run_local(flow, addresses=[MAC])
        if host == "host.lima.internal":  # a name: no provider's, so the agent's own request
            assert channel.asked and channel.asked[0]["action"] == "request"
            assert connect_to(gate, flow, (host, 443)).error is not None  # resolves to the Mac
            assert channel.told[-1]["details"]["reason"] == "private_address"
        else:
            assert status(flow) == 403 and channel.actions() == ["blocked:private_address"]


# --- the answer (6.2, step 9) ---------------------------------------------------------------------


def answer(
    gate: Any, flow: Flow, code: int, content_type: str = "application/json", body: bytes = b"{}"
) -> None:
    flow.response = Response(
        code,
        headers=Headers([("content-type", content_type), ("location", "http://192.168.5.2:22/")]),
    )
    gate.responseheaders(flow)
    assert flow.response.stream is not None and not callable(flow.response.stream)
    flow.response.content = body
    gate.response(flow)


@pytest.mark.parametrize("code", [301, 302, 307, 308, 101])
@pytest.mark.parametrize("content_type", ["application/json", "text/event-stream"])
def test_a_redirection_or_a_switch_never_reaches_the_agent(code: int, content_type: str) -> None:
    flow = local_flow()
    gate, channel, _ = run_local(flow)
    answer(gate, flow, code, content_type)
    assert flow.response.status_code == 502
    assert b"192.168.5.2:22" not in flow.response.content
    assert flow.response.headers.get("location") is None
    [told] = channel.told
    details = told["details"]
    assert told["action"] == "blocked" and details["reason"] == "local_redirect"
    assert details["side"] == "response" and details["local"] is True and told["risk"] == 2


def test_a_local_answer_is_recorded_as_local() -> None:
    flow = local_flow()
    gate, channel, _ = run_local(flow)
    body = json.dumps(
        {
            "model": MODEL,
            "usage": {"prompt_tokens": 3, "completion_tokens": 4},
            "choices": [{"message": {"content": "PONG"}}],
        }
    ).encode()
    answer(gate, flow, 200, body=body)
    assert flow.response.status_code == 200 and flow.response.content == body
    [told] = channel.told
    assert (told["action"], told["details"]["local"]) == ("response", True)
    assert told["details"]["usage"] == {"input": 3, "output": 4}
    assert told["target"].startswith(f"https://{VIRTUAL}/")  # the virtual name, as asked


# --- Ollama's cloud API: a public provider, its routes compared exactly -------------------------


def cloud_flow(path: str, body: bytes | None = None) -> Flow:
    return local_flow(
        path,
        ("Authorization", f"Bearer {CLOUD_FAKE}"),
        host="ollama.com",
        body=body if body is not None else chat("gpt-oss:120b"),
    )


def test_ollamas_cloud_gets_its_real_key_on_its_model_routes() -> None:
    flow = cloud_flow("/v1/chat/completions")
    gate, channel, _ = run_local(flow, addresses=["93.184.215.14"])
    assert flow.response is None
    sent = dict(flow.request.headers.items())
    assert sent["authorization"] == f"Bearer {CLOUD_REAL}"
    assert (flow.request.scheme, flow.request.host) == ("https", "ollama.com")  # not rewritten
    assert channel.asked[0]["details"]["key"] == "swapped"
    assert "local" not in channel.asked[0]["details"]
    assert connect_to(gate, flow, ("ollama.com", 443)).address == ("93.184.215.14", 443)


@pytest.mark.parametrize(
    "path", ["/api/web_search", "/api/me", "/x/v1/chat/completions", "/api/chat", "/api/pull"]
)
def test_ollamas_cloud_routes_off_the_list_never_go_out(path: str) -> None:
    flow = cloud_flow(path)
    _, channel, _ = run_local(flow)
    assert status(flow) == 403 and channel.asked == []
    assert channel.actions() == ["blocked:provider_endpoint"]
    assert "local" not in channel.told[0]["details"]
    assert (
        only_fake_key(all_providers().by_name("ollama-cloud"), [], scheme="https", port=443) is None
    )


@pytest.mark.parametrize(
    "host", ["other.backtide.internal", "backtide.internal.", "X.BACKTIDE.INTERNAL"]
)
def test_a_virtual_name_no_local_provider_has_is_never_resolved(host: str) -> None:
    flow = local_flow(host=host)
    _, channel, looked_up = run_local(flow)
    assert status(flow) == 403 and channel.asked == [] and looked_up == []
    assert channel.actions() == ["blocked:private_address"]
    channel = local_channel()
    gate, _ = make_gate(channel)
    connect = Flow(Request(host=host, port=443))
    gate.http_connect(connect)
    assert status(connect) == 403 and channel.actions() == ["blocked:private_address"]


def test_a_connect_to_a_configured_virtual_name_is_let_in() -> None:
    channel = local_channel()
    gate, _ = make_gate(channel)
    connect = Flow(Request(host=VIRTUAL, port=443))
    gate.http_connect(connect)
    assert connect.response is None and channel.told == []


# --- after the security review of T20-2/3 ---------------------------------------------------------


def local_verdict(body: bytes, allowed: tuple[str, ...]) -> tuple[str | None, tuple]:
    result = check_request(
        "openai",
        "POST",
        "/v1/chat/completions",
        [],
        body,
        allowed=allowed,
        models=(MODEL,),
        exact=True,
        local=True,
    )
    return result.reason, result.tools


@pytest.mark.parametrize(
    ("body", "refused"),
    [
        (chat("qwen3-coder:480b-cloud"), ("cloud_model", "model_not_listed")),
        (chat("llama3.2:3b"), ("model_not_listed",)),
        (chat("sonar-online"), ("model_not_listed", "search_model")),
        (chat(options={"num_ctx": 10_000_000}), ("param:options",)),
        (chat(keep_alive=-1), ("param:keep_alive",)),
        (chat(think=True), ("param:think",)),
        (chat(format="json"), ("param:format",)),
        (
            chat(
                messages=[
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": "http://x/y.png"}}],
                    }
                ]
            ),
            ("url_source",),
        ),
        (chat(web_search=True), ("param:web_search",)),
    ],
)
def test_the_owners_allowed_list_never_opens_a_local_provider(
    body: bytes, refused: tuple[str, ...]
) -> None:
    """M1 of the review: ``allow_provider_tools`` is one list for every provider. An owner who
    allows ``model_not_listed`` (for a new Claude model) or an Ollama field must not open a local
    provider to Ollama's cloud, a model off its list, or Ollama's own options."""
    owner = (
        "model_not_listed",
        "search_model",
        "url_source",
        "param:options",
        "param:keep_alive",
        "param:think",
        "param:format",
        "param:web_search",
        "cloud_model",
    )
    assert local_verdict(body, owner) == ("provider_side_tool", refused)


def test_a_cloud_model_is_refused_toward_a_local_provider_even_when_listed() -> None:
    result = check_request(
        "openai",
        "POST",
        "/v1/chat/completions",
        [],
        chat("gpt-oss:cloud"),
        models=("gpt-oss:cloud",),
        exact=True,
        local=True,
    )
    assert (result.reason, result.tools) == ("provider_side_tool", ("cloud_model",))


def test_a_harmless_field_a_profile_declares_still_passes_toward_a_local_provider() -> None:
    assert local_verdict(chat(reasoning_effort="low"), ()) == (None, ())
    assert local_verdict(chat(mirostat=1), ("param:mirostat",)) == (None, ("param:mirostat",))


def test_the_owners_allowed_list_still_works_for_a_public_provider() -> None:
    result = check_request(
        "openai",
        "POST",
        "/v1/chat/completions",
        [],
        chat("new-model"),
        allowed=("model_not_listed",),
        models=(MODEL,),
    )
    assert (result.reason, result.tools) == (None, ("model_not_listed",))


def test_the_proxy_never_lets_the_owners_list_open_a_local_provider() -> None:
    providers = all_providers()
    channel = FakeChannel()
    channel.config = GateConfig(
        providers,
        KnownScrubber(providers.known_secrets()),
        DEFAULT_LIMITS,
        provider_tools=frozenset({"model_not_listed", "param:options"}),
    )
    gate, _ = make_gate(channel)
    flow = local_flow(body=chat("qwen3-coder:480b-cloud", options={"num_ctx": 1}))
    send(gate, flow)
    assert status(flow) == 403 and channel.asked == []
    assert channel.told[0]["details"]["tools"] == [
        "cloud_model",
        "model_not_listed",
        "param:options",
    ]


@pytest.mark.parametrize("address", ["100.100.100.200", "100.100.100.100", "100.100.100.1"])
def test_the_metadata_and_quad_100_block_is_never_local(address: str) -> None:
    assert not local_address_ok(address)
    assert local_address_ok("100.100.101.1") and local_address_ok("100.64.0.7")


@pytest.mark.parametrize(
    ("host", "cloud"),
    [
        ("ollama.com", True),
        ("api.ollama.com", True),
        ("OLLAMA.com", True),
        ("notollama.com", False),
        ("ollama.com.evil.test", False),
        ("api.openai.com", False),
    ],
)
def test_ollamas_cloud_is_ollama_com_and_its_subdomains(host: str, cloud: bool) -> None:
    assert is_ollama_cloud(host) is cloud
    if host == host.lower():
        provider = Provider("c", Kind.OPENAI, host, new_fake_key("c"), Secret(CLOUD_REAL))
        assert provider.exact_paths is cloud
