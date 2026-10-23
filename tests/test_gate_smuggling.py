"""Request smuggling from HTTP/2 to an HTTP/1.1 upstream (security review of T11,
docs/incidentes.md 2026-10-22). An HTTP/2 or HTTP/3 request carries its body in DATA frames,
with no Content-Length and no Transfer-Encoding. mitmproxy 12.2.3 forwards it to an HTTP/1.1
server without adding either, so the server reads a zero-length body and the body bytes are read
as a second request the gate never checked. The gate adds the Content-Length of the body it
read, before it records the request, and never lets a request with a body leave unframed.

These run the hooks on the fakes of test_gate_addon.py; the VM proves the mechanism end to end
(tests/integration/test_smuggling.py)."""

import json

import pytest

import backtide.gate.addon as addon
from tests.test_gate_addon import (
    FAKE,
    Client,
    FakeChannel,
    Flow,
    Headers,
    Request,
    make_gate,
    send,
    status,
)

SMUGGLED = b"GET /T-H2-SMUGGLED HTTP/1.1\r\nHost: other.example\r\nContent-Length: 0\r\n\r\n"


def h2_flow(
    body: bytes,
    *extra: tuple[str, str],
    host: str = "example.com",
    version: str = "HTTP/2.0",
) -> Flow:
    headers = [("Host", host), *extra]
    # http_version in the constructor, so the fake's __post_init__ sees the real version and does
    # not add a Content-Length an HTTP/2 client would not have sent.
    request = Request(host=host, headers=Headers(headers), raw_content=body, http_version=version)
    return Flow(request, client_conn=Client(sni=host))


def sent_length(flow: Flow) -> str | None:
    return flow.request.headers.get("content-length")


def test_an_h2_body_without_a_length_gets_one_before_it_is_recorded() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = h2_flow(SMUGGLED)
    send(gate, flow)
    assert flow.response is None  # it goes out
    assert sent_length(flow) == str(len(SMUGGLED))
    [event] = channel.asked
    # The smuggled bytes are the body of request 1 (a POST), recorded as such with their full
    # length: no second request is hidden past a zero-length body.
    assert event["details"]["method"] == "POST"
    assert event["details"]["body"]["size"] == len(SMUGGLED)


@pytest.mark.parametrize("version", ["HTTP/3.0", "HTTP/2"])
def test_http3_and_http2_are_both_framed(version: str) -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = h2_flow(SMUGGLED, version=version)
    send(gate, flow)
    assert sent_length(flow) == str(len(SMUGGLED))


def test_an_h2_request_with_no_body_gets_content_length_zero() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = h2_flow(b"", ("content-type", "application/json"))
    send(gate, flow)
    assert sent_length(flow) == "0"


def test_an_h2_body_that_already_has_a_length_is_left_alone() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = h2_flow(SMUGGLED, ("Content-Length", str(len(SMUGGLED))))
    send(gate, flow)
    assert sent_length(flow) == str(len(SMUGGLED))


def test_a_chunked_h2_body_is_left_to_mitmproxy() -> None:
    """mitmproxy does re-chunk a Transfer-Encoding: chunked body: no Content-Length is added,
    so no request carries both (a smuggling signal an upstream would reject)."""
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = h2_flow(SMUGGLED, ("Transfer-Encoding", "chunked"))
    send(gate, flow)
    assert sent_length(flow) is None


def test_an_http1_request_is_not_touched() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = h2_flow(b"", version="HTTP/1.1")
    send(gate, flow)
    assert sent_length(flow) is None  # HTTP/1.1 with no body: no length, and none is added


def test_a_provider_h2_call_is_framed_too() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    body = json.dumps({"model": "m", "max_tokens": 8, "messages": []}).encode()
    flow = h2_flow(
        body,
        ("x-api-key", FAKE),
        ("content-type", "application/json"),
        host="api.anthropic.com",
    )
    flow.request.path = "/v1/messages"
    send(gate, flow)
    assert flow.response is None
    assert sent_length(flow) == str(len(body))


def test_the_belt_refuses_a_body_that_would_leave_unframed(monkeypatch: pytest.MonkeyPatch) -> None:
    """If _frame_h2_body somehow did not run, _let_through must not send an unframed body: the
    guard answers 502 and records net/error with the class name and upstream False (B3)."""
    monkeypatch.setattr(addon, "_frame_h2_body", lambda request: None)
    channel = FakeChannel()
    gate, died = make_gate(channel)
    flow = h2_flow(SMUGGLED)
    send(gate, flow)
    assert status(flow) == 502  # the guard answered; nothing went out
    assert "backtide" not in flow.metadata
    [error] = [e for e in channel.told if e["action"] == "error"]
    assert error["details"]["error"] == "UnframedBody"
    assert error["details"]["upstream"] is False  # it never left


# --- malformed framing refused before anything (M1), h1 and h2 -----------------------------------


def blocked_reason(flow: Flow) -> str | None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    send(gate, flow)
    if flow.response is None:
        return None
    [event] = [e for e in channel.told if e["action"] == "blocked"] or [None]
    return event["details"]["reason"] if event else "answered"


def test_a_header_value_with_cr_lf_or_nul_is_refused() -> None:
    for bad in ("b\r\nTransfer-Encoding: chunked", "b\nx", "b\x00x"):
        flow = h2_flow(SMUGGLED, ("X-A", bad))
        assert blocked_reason(flow) == "malformed_header", bad
        assert "backtide" not in flow.metadata


def test_a_header_name_that_is_not_a_token_is_refused() -> None:
    for name in ("X A", "X:A", "X\tA"):
        flow = h2_flow(SMUGGLED, (name, "b"))
        assert blocked_reason(flow) == "malformed_header", name


def test_transfer_encoding_with_content_length_is_refused() -> None:
    flow = h2_flow(SMUGGLED, ("Transfer-Encoding", "chunked"), ("Content-Length", "5"))
    assert blocked_reason(flow) == "malformed_header"


def test_a_transfer_encoding_that_is_not_chunked_is_refused() -> None:
    for te in ("gzip", "chunked, gzip", "identity"):
        flow = h2_flow(SMUGGLED, ("Transfer-Encoding", te))
        assert blocked_reason(flow) == "malformed_header", te


def test_the_malformed_check_covers_http1_too() -> None:
    flow = h2_flow(SMUGGLED, ("X-A", "b\r\nX: y"), version="HTTP/1.1")
    assert blocked_reason(flow) == "malformed_header"


def test_a_plain_chunked_request_is_allowed() -> None:
    flow = h2_flow(SMUGGLED, ("Transfer-Encoding", "chunked"))
    assert blocked_reason(flow) is None  # mitmproxy re-chunks it; no Content-Length added


# --- HTTP/2 trailers refused like h1's (B5) ------------------------------------------------------


def test_http2_trailers_are_refused() -> None:
    flow = h2_flow(SMUGGLED)
    flow.request.trailers = Headers([("X-Checksum", "abc")])
    assert blocked_reason(flow) == "trailers"
    assert "backtide" not in flow.metadata


# --- the include_usage rewrite and the belt agree over h2 (B4) -----------------------------------


def test_an_openai_streaming_chat_over_h2_without_length_is_framed_and_counted() -> None:
    from tests.test_gate_stream_usage import INSERTED, channel_with, openai, sent_headers

    channel = channel_with(openai())
    gate, _ = make_gate(channel)
    body = json.dumps({"model": "gpt-x", "stream": True, "messages": []}).encode()
    flow = Flow(
        Request(
            host="api.openai.com",
            path="/v1/chat/completions",
            headers=Headers(
                [("Host", "api.openai.com"), ("Content-Type", "application/json"),
                 ("Authorization", f"Bearer {openai().fake_key}")]
            ),
            raw_content=body,
            http_version="HTTP/2.0",
        ),
        client_conn=Client(sni="api.openai.com"),
    )  # fmt: skip
    send(gate, flow)
    assert flow.response is None  # it goes out
    sent = flow.request.raw_content
    assert sent == body[:1] + INSERTED + body[1:]  # include_usage added
    # Both the sent Content-Length and the recorded one are the new body's length.
    assert sent_headers(flow)["content-length"] == str(len(sent))
    assert channel.asked[0]["details"]["body"]["size"] == len(sent)
    assert channel.asked[0]["details"]["include_usage"] == "added"


def test_a_local_provider_over_h2_leaves_with_a_length_toward_its_ip() -> None:
    from tests.test_gate_local import LOCAL_FAKE, MAC, MODEL, PORT, VIRTUAL, local_channel

    channel = local_channel()
    gate, _ = make_gate(channel)
    body = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}).encode()
    flow = Flow(
        Request(
            host=VIRTUAL,
            path="/v1/chat/completions",
            headers=Headers(
                [("Host", VIRTUAL), ("Content-Type", "application/json"),
                 ("Authorization", f"Bearer {LOCAL_FAKE}")]
            ),
            raw_content=body,
            http_version="HTTP/2.0",
        ),
        client_conn=Client(sni=VIRTUAL),
    )  # fmt: skip
    send(gate, flow)
    assert flow.response is None
    assert flow.request.scheme == "http" and (flow.request.host, flow.request.port) == (MAC, PORT)
    sent = {name.lower(): value for name, value in flow.request.headers.items()}
    assert sent["content-length"] == str(len(body))  # framed toward http://IP:port
