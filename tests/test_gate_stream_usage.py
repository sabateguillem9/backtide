"""T11's leftover (docs/33, "include_usage"): the proxy asks a public OpenAI-shaped provider for the
usage of a streamed Chat Completions call the agent did not ask it for, and drops the extra
chunk before it reaches the agent. The pure pieces (backtide/gate/stream_usage.py), the proxy's
hooks on the fakes of test_gate_addon.py, and the price of such a call (backtide/service/spend.py).
"""

import gzip
import json
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.blackbox.redact import KnownScrubber
from backtide.gate import addon, protocol, record
from backtide.gate.addon import BODY_LIMIT
from backtide.gate.client import Ack, GateConfig
from backtide.gate.protocol import DEFAULT_LIMITS
from backtide.gate.provider_tools import check_request
from backtide.gate.providers import FAKE_KEY_PREFIX, Kind, Provider, Providers, Secret
from backtide.gate.sse import LlmSummary, UsageStream
from backtide.gate.stream_usage import (
    INSERTED,
    drop_usage_events,
    usage_insert_at,
    with_include_usage,
)
from tests.test_gate_addon import (
    FAKE,
    REAL,
    Client,
    FakeChannel,
    Flow,
    Headers,
    Request,
    Response,
    make_gate,
    send,
    status,
)
from tests.test_gate_local import CLOUD_FAKE, CLOUD_REAL, LOCAL_FAKE, MODEL, VIRTUAL, local
from tests.test_service_proxy_channel import make_channel
from tests.test_spend_gate import budget_for, costs

OPENAI_FAKE = FAKE_KEY_PREFIX + "openai-" + "O1p2E3n4A5i6F7a8K9e0K1e2Y3t4E5s6"
OPENAI_REAL = "sk-proj-" + "T3stOnlyN0tR3al" * 3
OPENAI_HOST = "api.openai.com"
CHAT = "/v1/chat/completions"
KEY = b"k" * 32  # the test black box's
JSON_HEADERS = [("content-type", "application/json")]


def chat_body(*, stream: object = True, **extra: Any) -> bytes:
    request: dict[str, Any] = {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}
    if stream is not None:
        request["stream"] = stream
    return json.dumps(request | extra).encode()


# --- the rewrite, pure ----------------------------------------------------------------------------


def test_a_streamed_chat_call_gets_include_usage_right_after_its_brace() -> None:
    body = b'  \n{"model": "gpt-x", "temperature": 0.10000000000000000555, "stream": true}'
    at = usage_insert_at("openai", "chat", JSON_HEADERS, body, limit=BODY_LIMIT)
    assert at == 3
    rewritten = with_include_usage(body, at)
    assert rewritten == body[:4] + INSERTED + body[4:]  # nothing the agent wrote is rewritten
    assert b"0.10000000000000000555" in rewritten
    assert json.loads(rewritten)["stream_options"] == {"include_usage": True}
    verdict = check_request("openai", "POST", CHAT, JSON_HEADERS, rewritten)
    assert verdict.reason is None


@pytest.mark.parametrize(
    "own",
    [
        {"stream_options": {"include_usage": False}},
        {"stream_options": {"include_usage": True}},
        {"stream_options": {}},
        {"stream_options": None},
        {"stream_options": {"include_obfuscation": False}},
        {"Stream_Options": {"include_usage": False}},
        {"ſtream_options": {"include_usage": False}},  # folds to stream_options too
    ],
)
def test_the_agents_own_stream_options_are_left_alone(own: dict[str, Any]) -> None:
    body = chat_body(**own)
    assert usage_insert_at("openai", "chat", JSON_HEADERS, body, limit=BODY_LIMIT) is None


@pytest.mark.parametrize("stream", [None, False, "true", 1, {"on": True}])
def test_only_a_streamed_call_is_rewritten(stream: object) -> None:
    body = chat_body(stream=stream)
    assert usage_insert_at("openai", "chat", JSON_HEADERS, body, limit=BODY_LIMIT) is None


@pytest.mark.parametrize(
    ("kind", "endpoint"),
    [
        ("anthropic", "messages"),
        ("anthropic", "chat"),
        ("openai", "responses"),  # Responses streams its usage in response.completed anyway
        ("openai", "completions"),
        ("openai", "embeddings"),
        ("openai", "models"),
        ("openai", None),
    ],
)
def test_only_openais_chat_completions_are_rewritten(kind: str, endpoint: str | None) -> None:
    assert usage_insert_at(kind, endpoint, JSON_HEADERS, chat_body(), limit=BODY_LIMIT) is None


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[1, 2]",
        b'{"stream": true',  # malformed
        b'\xef\xbb\xbf{"stream": true}',  # a BOM
        '{"stream": true}'.encode("utf-16-le"),
        b'{"stream": true, "x": "\xff"}',  # not UTF-8
        b"   ",
    ],
)
def test_a_body_that_is_not_plain_json_is_left_alone(body: bytes) -> None:
    assert usage_insert_at("openai", "chat", JSON_HEADERS, body, limit=BODY_LIMIT) is None


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "identity, gzip"])
def test_a_compressed_body_is_left_alone(encoding: str) -> None:
    headers = [*JSON_HEADERS, ("Content-Encoding", encoding)]
    assert usage_insert_at("openai", "chat", headers, chat_body(), limit=BODY_LIMIT) is None
    identity = [*JSON_HEADERS, ("Content-Encoding", "identity")]
    assert usage_insert_at("openai", "chat", identity, chat_body(), limit=BODY_LIMIT) == 0


def test_the_rewrite_never_takes_a_body_past_the_limit() -> None:
    body = chat_body()
    fits = len(body) + len(INSERTED)
    assert usage_insert_at("openai", "chat", JSON_HEADERS, body, limit=fits) == 0
    assert usage_insert_at("openai", "chat", JSON_HEADERS, body, limit=fits - 1) is None


def test_the_rewrite_refuses_a_body_it_was_not_planned_on() -> None:
    with pytest.raises(ValueError):
        with_include_usage(b'x{"stream": true}', 1)
    with pytest.raises(ValueError):
        with_include_usage(b'{"stream": true}', 1)


# --- the extra chunk, pure ------------------------------------------------------------------------


def chunk(choices: list[Any], usage: object = None, **extra: Any) -> dict[str, Any]:
    return {"id": "c1", "object": "chat.completion.chunk", "model": "gpt-x", "choices": choices,
            "usage": usage} | extra  # fmt: skip


def sse(*events: object, end: str = "\n") -> bytes:
    out = ""
    for event in events:
        text = event if isinstance(event, str) else json.dumps(event)
        out += f"data: {text}{end}{end}"
    return out.encode()


USAGE = {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}
DELTA = chunk([{"index": 0, "delta": {"content": "HELLO"}, "finish_reason": None}])
STOP = chunk([{"index": 0, "delta": {}, "finish_reason": "stop"}])
USAGE_CHUNK = chunk([], USAGE)


@pytest.mark.parametrize("end", ["\n", "\r\n", "\r"])
def test_the_usage_chunk_is_dropped_and_nothing_else(end: str) -> None:
    stream = sse(DELTA, STOP, USAGE_CHUNK, "[DONE]", end=end)
    assert drop_usage_events(stream) == sse(DELTA, STOP, "[DONE]", end=end)


@pytest.mark.parametrize(
    "event",
    [
        chunk([], None, prompt_filter_results=[]),  # Azure's first chunk: no usage
        chunk([{"index": 0, "delta": {}, "finish_reason": "stop"}], USAGE),  # it has a choice
        {"usage": USAGE},  # no choices at all
        chunk([], "12"),
        "[DONE]",
        "not json",
    ],
)
def test_any_other_event_goes_on_byte_for_byte(event: object) -> None:
    stream = sse(event)
    assert drop_usage_events(stream) == stream


def test_a_named_event_or_a_split_data_line_is_read_like_an_sse_client() -> None:
    named = b"event: usage\ndata: " + json.dumps(USAGE_CHUNK).encode() + b"\n\n"
    assert drop_usage_events(named) == named
    text = json.dumps(USAGE_CHUNK)
    cut = text.index(", ") + 1  # between two members: the joining newline is JSON's space
    split = f": a comment\ndata:{text[:cut]}\ndata: {text[cut:]}\nid: 9\n\n".encode()
    assert drop_usage_events(split) == b""  # "data:" without its space, and two lines joined
    assert drop_usage_events(b"event: message\n" + split) == b""


def test_an_unfinished_event_is_kept() -> None:
    tail = b"data: " + json.dumps(USAGE_CHUNK).encode() + b"\n"
    assert drop_usage_events(sse(DELTA) + tail) == sse(DELTA) + tail


def test_the_tap_reads_the_usage_chunk() -> None:
    usage = UsageStream("openai")
    usage.feed(sse(DELTA, STOP, USAGE_CHUNK, "[DONE]"))
    summary = usage.finish()
    assert summary.usage == {"input": 12, "output": 7}
    assert summary.complete and summary.stop_reason == "stop"


# --- the proxy ------------------------------------------------------------------------------------


def openai(**changes: Any) -> Provider:
    options: dict[str, Any] = {
        "name": "openai",
        "kind": Kind.OPENAI,
        "host": OPENAI_HOST,
        "fake_key": OPENAI_FAKE,
        "real_key": Secret(OPENAI_REAL),
    } | changes
    return Provider(**options)


def channel_with(*providers: Provider) -> FakeChannel:
    channel = FakeChannel()
    every = Providers(
        [Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL)),
         *providers]
    )  # fmt: skip
    channel.config = GateConfig(every, KnownScrubber(every.known_secrets()), DEFAULT_LIMITS)
    return channel


def openai_flow(
    body: bytes,
    *extra: tuple[str, str],
    host: str = OPENAI_HOST,
    key: str = OPENAI_FAKE,
    path: str = CHAT,
    length: bool = True,
) -> Flow:
    headers = [("Host", host), ("Content-Type", "application/json"),
               ("Authorization", f"Bearer {key}"), *extra]  # fmt: skip
    if length:
        headers.append(("Content-Length", str(len(body))))
    return Flow(
        Request(host=host, path=path, headers=Headers(headers), raw_content=body),
        client_conn=Client(sni=host),
    )


def sent_headers(flow: Flow) -> dict[str, str]:
    return {name.lower(): value for name, value in flow.request.headers.items()}


def test_the_proxy_adds_include_usage_and_records_it() -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    body = chat_body()
    flow = openai_flow(body)
    send(gate, flow)
    assert flow.response is None  # it goes out
    sent = flow.request.raw_content
    assert sent == body[:1] + INSERTED + body[1:]
    headers = sent_headers(flow)
    assert headers["content-length"] == str(len(sent))
    assert headers["authorization"] == f"Bearer {OPENAI_REAL}"
    assert flow.metadata["backtide"]["drop_usage"] is True
    [event] = channel.asked
    details = event["details"]
    assert details["include_usage"] == "added" and details["key"] == "swapped"
    assert details["body"]["size"] == len(sent)  # what went upstream
    assert details["headers"]["content-length"] == str(len(sent))  # recorded as sent too
    assert details["stream"] is True and details["endpoint"] == "chat"
    assert protocol.validate_event(event)["details"]["include_usage"] == "added"


@pytest.mark.parametrize(
    "own",
    [{"stream_options": {"include_usage": False}}, {"stream_options": {"include_usage": True}}],
)
def test_the_proxy_leaves_the_agents_own_choice_alone(own: dict[str, Any]) -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    body = chat_body(**own)
    flow = openai_flow(body)
    send(gate, flow)
    assert flow.response is None and flow.request.raw_content == body
    assert sent_headers(flow)["content-length"] == str(len(body))
    assert "include_usage" not in channel.asked[0]["details"]
    assert "drop_usage" not in flow.metadata["backtide"]


def test_a_denied_call_is_never_rewritten() -> None:
    channel = channel_with(openai())
    channel.answer = Ack("deny", reason="spend_cap")
    gate, _ = make_gate(channel)
    body = chat_body()
    flow = openai_flow(body)
    send(gate, flow)
    assert status(flow) == 429 and flow.request.raw_content == body
    assert "backtide" not in flow.metadata


def test_a_call_without_content_length_gets_none() -> None:
    """Chunked in HTTP/1.1, mitmproxy chunks it again; HTTP/2 to HTTP/2, the protocol frames it.
    (HTTP/2 without Content-Length toward an HTTP/1.1 server was a smuggling bug older than this
    rewrite, fixed separately: test_gate_smuggling.py and the contrabando-h2 scenario.)"""
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    flow = openai_flow(chat_body(), ("Transfer-Encoding", "chunked"), length=False)
    send(gate, flow)
    assert flow.request.raw_content.startswith(b"{" + INSERTED)
    assert "content-length" not in sent_headers(flow)
    assert sent_headers(flow)["transfer-encoding"] == "chunked"


def test_an_owner_who_turned_it_off_gets_no_rewrite() -> None:
    """``[[proxy.providers]] stream_usage = false``: for a compatible API that refuses fields it
    does not know. The call goes as the agent wrote it, and is estimated as before."""
    channel = channel_with(openai(stream_usage=False))
    gate, _ = make_gate(channel)
    body = chat_body()
    flow = openai_flow(body)
    send(gate, flow)
    assert flow.response is None and flow.request.raw_content == body
    assert "include_usage" not in channel.asked[0]["details"]
    assert "drop_usage" not in flow.metadata["backtide"]


def test_the_rewritten_body_is_checked_with_the_same_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return check_request(*args, **kwargs)

    monkeypatch.setattr(addon, "check_request", spy)
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    send(gate, openai_flow(chat_body()))
    first, again = calls  # the agent's body, then the rewritten one
    assert first == again  # trailers, local, exact, models and the owner's list alike


def test_a_local_provider_is_never_rewritten() -> None:
    """It costs nothing (T20): the call to the owner's machine goes as the agent wrote it, and
    the exact route and the body rule are the same as before."""
    channel = channel_with(local())
    gate, _ = make_gate(channel)
    body = json.dumps({"model": MODEL, "stream": True, "messages": []}).encode()
    flow = openai_flow(body, host=VIRTUAL, key=LOCAL_FAKE)
    send(gate, flow)
    assert flow.response is None and flow.request.raw_content == body
    assert "include_usage" not in channel.asked[0]["details"]
    assert channel.asked[0]["details"]["local"] is True


def test_ollamas_cloud_is_rewritten_and_its_exact_routes_still_hold() -> None:
    cloud = Provider("ollama-cloud", Kind.OPENAI, "ollama.com", CLOUD_FAKE, Secret(CLOUD_REAL),
                     models=("gpt-oss:120b",))  # fmt: skip
    channel = channel_with(cloud)
    gate, _ = make_gate(channel)
    body = json.dumps({"model": "gpt-oss:120b", "stream": True, "messages": []}).encode()
    flow = openai_flow(body, host="ollama.com", key=CLOUD_FAKE)
    send(gate, flow)
    assert flow.response is None and flow.request.raw_content.startswith(b"{" + INSERTED)
    # The same call on a route off its list is refused as before, and nothing is asked.
    other = openai_flow(body, host="ollama.com", key=CLOUD_FAKE, path="/api/chat")
    send(gate, other)
    assert status(other) == 403 and len(channel.asked) == 1
    assert channel.told[-1]["details"]["reason"] == "provider_endpoint"


def test_an_anthropic_call_is_never_rewritten() -> None:
    channel = channel_with()
    gate, _ = make_gate(channel)
    body = json.dumps({"model": "m", "max_tokens": 8, "stream": True, "messages": []}).encode()
    flow = Flow(
        Request(host="api.anthropic.com", path="/v1/messages",
                headers=Headers([("Host", "api.anthropic.com"), ("x-api-key", FAKE),
                                 ("Content-Type", "application/json")]),
                raw_content=body),
        client_conn=Client(sni="api.anthropic.com"),
    )  # fmt: skip
    send(gate, flow)
    assert flow.response is None and flow.request.raw_content == body
    assert "include_usage" not in channel.asked[0]["details"]


@pytest.mark.parametrize(
    ("body", "extra", "code", "reason"),
    [
        (gzip.compress(chat_body()), ("Content-Encoding", "gzip"), 400, "provider_body"),
        (b'{"model": "gpt-x", "stream": true', None, 400, "provider_body"),
        (chat_body(stream_options="x" * 10), None, None, None),  # a string: the agent's, left
        (chat_body(Stream=True), None, 400, "provider_body"),  # "stream" twice once folded
    ],
)
def test_what_failed_before_fails_the_same(
    body: bytes, extra: tuple[str, str] | None, code: int | None, reason: str | None
) -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    flow = openai_flow(body, *([extra] if extra else []))
    send(gate, flow)
    assert status(flow) == code
    assert flow.request.raw_content == body  # never rewritten
    if reason is not None:
        assert channel.asked == [] and channel.told[-1]["details"]["reason"] == reason


def test_a_body_at_the_limit_goes_as_it_came() -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    head = chat_body()[:-1] + b', "user": "'
    body = head + b"u" * (BODY_LIMIT - len(head) - 2) + b'"}'
    assert len(body) == BODY_LIMIT
    flow = openai_flow(body)
    send(gate, flow)
    assert flow.response is None and flow.request.raw_content is body
    assert "include_usage" not in channel.asked[0]["details"]


def through(gate: Any, flow: Flow, body: bytes) -> bytes:
    """What the agent gets of a streamed answer, cut in chunks of 5 bytes."""
    flow.response = Response(200, headers=Headers([("content-type", "text/event-stream")]))
    gate.responseheaders(flow)
    out = b""
    for start in range(0, len(body), 5):
        out += flow.response.stream(body[start : start + 5])
    return out


def test_the_agent_never_sees_the_chunk_it_did_not_ask_for() -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    flow = openai_flow(chat_body())
    send(gate, flow)
    answer = sse(DELTA, STOP, USAGE_CHUNK, "[DONE]")
    out = through(gate, flow, answer) + flow.response.stream(b"")
    gate.response(flow)
    assert out == sse(DELTA, STOP, "[DONE]")
    [event] = channel.told
    details = event["details"]
    assert details["usage"] == {"input": 12, "output": 7} and details["complete"] is True
    assert details["size"] == len(answer)  # what the provider sent


def test_an_agent_that_asked_gets_the_chunk() -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    flow = openai_flow(chat_body(stream_options={"include_usage": True}))
    send(gate, flow)
    answer = sse(DELTA, STOP, USAGE_CHUNK, "[DONE]")
    out = through(gate, flow, answer) + flow.response.stream(b"")
    assert out == answer


def test_a_stream_cut_after_the_usage_says_it_did_not_end() -> None:
    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    flow = openai_flow(chat_body())
    send(gate, flow)
    out = through(gate, flow, sse(DELTA, USAGE_CHUNK))
    gate.error(flow)
    assert out == sse(DELTA)
    response = channel.told[0]["details"]
    assert response["usage"] == {"input": 12, "output": 7} and response["complete"] is False


# --- the switch -----------------------------------------------------------------------------------


def test_the_switch_travels_to_the_proxy_and_is_checked() -> None:
    on, off = openai(), openai(name="groq", host="api.groq.test", stream_usage=False,
                              fake_key=FAKE_KEY_PREFIX + "groq-" + "G" * 32,
                              real_key=Secret("gsk_" + "R3alT3st" * 4))  # fmt: skip
    entries = [protocol._provider_entry(p) for p in (on, off)]
    assert "stream_usage" not in entries[0] and entries[1]["stream_usage"] is False
    back = protocol.providers_from_config({"providers": entries})
    assert [p.stream_usage for p in back.items] == [True, False]
    for wrong in ("false", 0, None):
        with pytest.raises(protocol.ProtocolError, match="stream_usage"):
            protocol.providers_from_config({"providers": [entries[0] | {"stream_usage": wrong}]})
    with pytest.raises(ValueError, match="stream_usage"):
        openai(stream_usage="no")


# --- the price ------------------------------------------------------------------------------------


def openai_request(flow_id: str, *, added: bool, max_tokens: int = 10) -> dict[str, Any]:
    body = json.dumps({"model": "m", "max_completion_tokens": max_tokens, "stream": True,
                       "messages": []}).encode()  # fmt: skip
    # The budget prices any kind alike: the test channel's provider is Anthropic's.
    flow = {"flow_id": flow_id, "method": "POST", "scheme": "https", "host": "api.anthropic.com",
            "port": 443, "path": "/v1/messages", "headers": [], "body": body}  # fmt: skip
    return record.llm_request_event(flow, "anthropic", (), endpoint="messages", include_usage=added)


def openai_response(flow_id: str, usage: dict[str, int] | None, complete: bool) -> dict[str, Any]:
    summary = LlmSummary(model="m", usage=dict(usage or {}), complete=complete)
    flow = {"flow_id": flow_id, "scheme": "https", "host": "api.anthropic.com", "port": 443,
            "path": "/v1/messages"}  # fmt: skip
    return record.llm_response_event(
        flow, "anthropic", {"status": 200, "size": 10, "duration_ms": 5}, summary, ()
    )


@pytest.fixture
def box(tmp_path: Path) -> Iterator[BlackBox]:
    with BlackBox(tmp_path / "bb.db", KEY, checkpoint_path=tmp_path / "bb.checkpoint") as opened:
        yield opened


def price_of(
    tmp_path: Path, box: BlackBox, *, added: bool, usage: dict[str, int] | None, complete: bool
) -> dict[str, Any]:
    budget = budget_for(tmp_path, box, daily="100")
    channel, proxy = make_channel(box, budget=budget)
    request = openai_request("s1", added=added)
    channel.handle({"type": "request", "id": 1, "event": request})
    assert proxy.receive_type("ack")["verdict"] == "allow"
    channel.handle({"type": "event", "event": openai_response("s1", usage, complete)})
    [(_, cost)] = costs(box)
    return cost


def estimate_today(tmp_path: Path) -> int:
    """What the same call cost before the rewrite: no usage, so estimated by excess."""
    with BlackBox(tmp_path / "e.db", KEY, checkpoint_path=tmp_path / "e.cp") as other:
        state = tmp_path / "e"
        state.mkdir()
        return price_of(state, other, added=False, usage=None, complete=True)["usd_micro"]


def test_with_its_usage_a_streamed_call_is_priced_exactly(tmp_path: Path, box: BlackBox) -> None:
    cost = price_of(tmp_path, box, added=True, usage={"input": 12, "output": 7}, complete=True)
    assert cost == {"usd_micro": 12 * 100 + 7 * 100, "estimated": False, "unknown_model": False,
                    "priced_by": "owner"}  # fmt: skip
    assert cost["usd_micro"] < estimate_today(tmp_path)


def test_a_rewritten_call_cut_short_costs_at_least_what_it_did_before(
    tmp_path: Path, box: BlackBox
) -> None:
    """The usage chunk came but [DONE] did not (the agent hung up): never less than the estimate
    the call had before the proxy asked for its usage, and never nearly free."""
    cost = price_of(tmp_path, box, added=True, usage={"input": 12, "output": 7}, complete=False)
    assert cost["estimated"] is True
    assert cost["usd_micro"] >= estimate_today(tmp_path)


def test_a_rewritten_call_cut_before_its_usage_is_estimated_as_before(
    tmp_path: Path, box: BlackBox
) -> None:
    cost = price_of(tmp_path, box, added=True, usage=None, complete=False)
    assert cost["estimated"] is True and cost["priced_by"] == "estimate"
    assert cost["usd_micro"] >= estimate_today(tmp_path)


def test_the_budget_reads_the_flag_only_as_more_caution(tmp_path: Path, box: BlackBox) -> None:
    """Without the flag (the agent asked itself, as OpenClaw does), A1 as before: the usage it
    reported and its whole max_tokens of output."""
    cost = price_of(tmp_path, box, added=False, usage={"input": 12, "output": 7}, complete=False)
    assert cost["usd_micro"] == 12 * 100 + 10 * 100
    assert Decimal(cost["usd_micro"]) < Decimal(estimate_today(tmp_path))
