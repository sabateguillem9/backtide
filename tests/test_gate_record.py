import base64
import json
import secrets
import time
from typing import Any
from urllib.parse import quote

import pytest

from backtide.blackbox import REDACTED
from backtide.blackbox.redact import KnownScrubber, scrub_known
from backtide.gate import record
from backtide.gate.protocol import validate_event
from backtide.gate.providers import FAKE_KEY_PREFIX
from backtide.gate.record import (
    EXCERPT_BYTES,
    blocked_event,
    dropped_event,
    error_event,
    llm_request_event,
    llm_response_event,
    request_event,
    response_event,
    throttled_event,
    tls_failed_event,
    websocket_event,
)
from backtide.gate.sse import LlmSummary


def _random(length: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# Test values, new on every run: never a real key.
REAL = "sk-ant-api03-" + _random(80)
REAL_OPENAI = "sk-proj-" + _random(60)
FAKE = FAKE_KEY_PREFIX + "anthropic-" + _random(32)
GATEWAY = _random(48)  # the Gateway token: known to backtide, no pattern of its own
KNOWN = [REAL, REAL_OPENAI, FAKE, GATEWAY]
# Keys backtide does not know but that look like keys (a user's, found in a file).
STRANGER_ANTHROPIC = "sk-ant-api03-" + _random(80)
STRANGER_GITHUB = "ghp_" + _random(36)
STRANGER_JWT = (
    "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b'{"sub":"x"}').decode().rstrip("=")
    + "." + _random(43)
)  # fmt: skip
TEST_KEYS = [*KNOWN, STRANGER_ANTHROPIC, STRANGER_GITHUB, STRANGER_JWT]


def flow(**change: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "flow_id": "3f2a-flow",
        "method": "POST",
        "scheme": "https",
        "host": "api.example.com",
        "port": 443,
        "path": "/v1/items?page=2",
        "http_version": "HTTP/1.1",
        "server_ip": "93.184.215.14",
        "headers": [
            ("Host", "api.example.com"),
            ("Content-Type", "application/json; charset=utf-8"),
            ("User-Agent", "curl/8.9"),
            ("Accept", "*/*"),
            ("X-Request-Id", "abc"),
        ],
        "body": b'{"name": "report", "size": 3}',
    }
    base.update(change)
    return base


def no_key_in(value: object) -> None:
    """Neither a test key nor any 12-character piece of its random part shows, in any
    letter case (an upper-cased key is still the key)."""
    text = json.dumps(value, ensure_ascii=False).lower()
    for key in TEST_KEYS:
        assert key.lower() not in text
        assert quote(key, safe="").lower() not in text
        tail = key[-32:].lower()
        for start in range(len(tail) - 11):
            assert tail[start : start + 12] not in text, (key[:12], start)


# --- net/request -------------------------------------------------------------------------------


def test_a_request_event_has_the_design_fields() -> None:
    event = request_event(flow(), KNOWN)
    assert event["source"] == "net" and event["action"] == "request" and event["risk"] == 0
    assert event["target"] == "https://api.example.com/v1/items?page=2"
    details = event["details"]
    assert details["flow_id"] == "3f2a-flow"
    assert details["method"] == "POST"
    assert details["scheme"] == "https"
    assert details["host"] == "api.example.com"
    assert details["port"] == 443
    assert details["path"] == "/v1/items?page=2"
    assert details["http_version"] == "HTTP/1.1"
    assert details["server_ip"] == "93.184.215.14"
    assert details["body"]["size"] == 29
    assert details["body"]["type"] == "application/json"
    assert details["body"]["excerpt"] == '{"name": "report", "size": 3}'
    assert validate_event(event) == event


def test_only_harmless_headers_keep_their_value() -> None:
    headers = [
        ("Content-Type", "application/json"),
        ("Content-Length", "29"),
        ("Content-Encoding", "gzip"),
        ("Accept", "*/*"),
        ("User-Agent", "openclaw/2026.9.8"),
        ("anthropic-version", "2023-06-01"),
        ("X-Custom", "some value"),
        ("Authorization", "Bearer abcdefghijklmnop"),
        ("Proxy-Authorization", "Basic eDp5"),
        ("Cookie", "a=1; b=2"),
        ("Cookie", "c=3"),
        ("Referer", "https://x.example/?q=private"),
    ]
    details = request_event(flow(headers=headers), KNOWN)["details"]
    assert details["headers"] == {
        "content-type": "application/json",
        "content-length": "29",
        "content-encoding": "gzip",
        "accept": "*/*",
        "user-agent": "openclaw/2026.9.8",
        "anthropic-version": "2023-06-01",
        "x-custom": None,
        "authorization": REDACTED,
        "proxy-authorization": REDACTED,
        "cookie": REDACTED,
        "referer": None,
    }
    assert details["cookies"] == 3


def test_too_many_headers_are_counted_not_kept() -> None:
    headers = [(f"X-H{i}", "v") for i in range(200)]
    details = request_event(flow(headers=headers), KNOWN)["details"]
    assert len(details["headers"]) == record.MAX_HEADERS
    assert details["headers_dropped"] == 200 - record.MAX_HEADERS


def test_long_header_values_and_names_are_cut() -> None:
    headers = [("User-Agent", "u" * 5000), ("X-" + "n" * 500, "v")]
    details = request_event(flow(headers=headers), KNOWN)["details"]
    assert len(details["headers"]["user-agent"]) <= 256
    assert all(len(name) <= 64 for name in details["headers"])


@pytest.mark.parametrize(
    ("path", "kept"),
    [
        ("/v1/items?page=2&q=cats", "/v1/items?page=2&q=cats"),
        ("/cb?c=1&access_token=abcdefghijk&s=2", f"/cb?c=1&access_token={REDACTED}&s=2"),
        ("/x?key=AIzaSomething&page=1", f"/x?key={REDACTED}&page=1"),
        ("/x?Api%2DKey=abcdefgh", f"/x?Api%2DKey={REDACTED}"),
        ("/x?sig=abc&b=", f"/x?sig={REDACTED}&b="),
        ("/a/b", "/a/b"),
    ],
)  # fmt: skip
def test_the_query_is_struck_value_by_value(path: str, kept: str) -> None:
    assert request_event(flow(path=path), KNOWN)["details"]["path"] == kept


def test_a_get_has_no_excerpt_and_neither_has_a_binary_body() -> None:
    get = request_event(flow(method="GET", body=b"q=1"), KNOWN)["details"]["body"]
    assert get == {"size": 3, "type": "application/json"}
    binary = flow(headers=[("Content-Type", "application/octet-stream")], body=b"\x00\x01text")
    assert "excerpt" not in request_event(binary, KNOWN)["details"]["body"]
    multipart = flow(headers=[("Content-Type", "multipart/form-data; boundary=x")], body=b"--x")
    assert "excerpt" not in request_event(multipart, KNOWN)["details"]["body"]
    empty = request_event(flow(body=b""), KNOWN)["details"]["body"]
    assert empty == {"size": 0, "type": "application/json"}
    none = request_event(flow(body=None, headers=[]), KNOWN)["details"]["body"]
    assert none == {"size": 0, "type": None}


@pytest.mark.parametrize(
    "content_type",
    ["text/plain", "text/csv; charset=utf-8", "application/json", "application/ld+json",
     "application/x-www-form-urlencoded"],
)  # fmt: skip
def test_text_json_and_forms_get_an_excerpt(content_type: str) -> None:
    body = request_event(flow(headers=[("Content-Type", content_type)], body=b"hello=1"), KNOWN)
    assert body["details"]["body"]["excerpt"] == "hello=1"


def test_the_excerpt_is_2_kib_at_most() -> None:
    body = ("ñ" * 3000).encode()
    details = request_event(flow(headers=[("Content-Type", "text/plain")], body=body), KNOWN)
    info = details["details"]["body"]
    assert len(info["excerpt"].encode()) <= EXCERPT_BYTES
    assert set(info["excerpt"]) == {"ñ"}
    assert info["excerpt_truncated"] is True
    assert info["size"] == 6000


@pytest.mark.parametrize("secret", [REAL, FAKE, GATEWAY, STRANGER_ANTHROPIC, STRANGER_GITHUB])
@pytest.mark.parametrize("offset", range(EXCERPT_BYTES - 120, EXCERPT_BYTES + 1100, 37))
def test_no_piece_of_a_key_survives_at_any_cut_of_the_body(secret: str, offset: int) -> None:
    body = ("a" * offset + " " + secret + " " + "b" * 3000).encode()
    event = request_event(flow(headers=[("Content-Type", "text/plain")], body=body), KNOWN)
    no_key_in(event)


def test_many_struck_keys_do_not_pull_a_piece_of_a_key_into_the_excerpt() -> None:
    # Striking shrinks the text: what was past the cut must not slide into view.
    body = (f"{GATEWAY} " * 60 + REAL + "x" * 5000).encode()
    no_key_in(request_event(flow(headers=[("Content-Type", "text/plain")], body=body), KNOWN))


# --- llm/request -------------------------------------------------------------------------------

LLM_BODY = json.dumps(
    {
        "model": "claude-opus-5-5",
        "max_tokens": 4096,
        "stream": True,
        "system": "SYSTEM-PROMPT-TEXT",
        "messages": [
            {"role": "user", "content": "PROMPT-TEXT"},
            {"role": "assistant", "content": "ANSWER-TEXT"},
            {"role": "user", "content": "MORE-TEXT"},
        ],
        "tools": [{"name": "exec", "description": "TOOL-TEXT", "input_schema": {}}],
    }
).encode()


def llm_flow(**change: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "host": "api.anthropic.com",
        "path": "/v1/messages",
        "headers": [("Content-Type", "application/json"), ("X-Api-Key", FAKE)],
        "body": LLM_BODY,
    }
    return flow(**(base | change))


def test_an_llm_request_keeps_metadata_and_never_the_text() -> None:
    event = llm_request_event(llm_flow(), "anthropic", KNOWN)
    assert event["source"] == "llm" and event["action"] == "request" and event["risk"] == 0
    details = event["details"]
    assert details["provider"] == "anthropic"
    assert details["model"] == "claude-opus-5-5"
    assert details["max_tokens"] == 4096
    assert details["stream"] is True
    assert details["messages"] == 3
    assert details["tools"] == 1
    assert details["key"] == "swapped"
    assert details["body"] == {"size": len(LLM_BODY), "type": "application/json"}
    assert details["headers"]["x-api-key"] == REDACTED
    text = json.dumps(event)
    for word in ("SYSTEM-PROMPT", "PROMPT-TEXT", "ANSWER-TEXT", "MORE-TEXT", "TOOL-TEXT"):
        assert word not in text
    assert validate_event(event) == event


def test_an_openai_request_reads_its_own_fields() -> None:
    body = json.dumps(
        {"model": "gpt-5.5", "input": "PROMPT", "max_output_tokens": 50, "tools": []}
    ).encode()
    details = llm_request_event(llm_flow(body=body), "openai", KNOWN)["details"]
    assert details["model"] == "gpt-5.5"
    assert details["max_tokens"] == 50
    assert details["messages"] == 1
    assert details["tools"] == 0
    assert details["stream"] is None
    chat = json.dumps({"model": "m", "max_completion_tokens": 9, "messages": [{}]}).encode()
    details = llm_request_event(llm_flow(body=chat), "openai", KNOWN)["details"]
    assert details["max_tokens"] == 9 and details["messages"] == 1


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"model": 5, "max_tokens": -1}', None])
def test_an_llm_request_that_does_not_parse_keeps_nothing_of_it(body: bytes | None) -> None:
    details = llm_request_event(llm_flow(body=body), "anthropic", KNOWN)["details"]
    assert details["model"] is None
    assert details["max_tokens"] is None
    assert details["messages"] is None


# --- responses ---------------------------------------------------------------------------------

RESPONSE = {
    "status": 200,
    "headers": [("Content-Type", "text/event-stream; charset=utf-8"), ("Set-Cookie", "s=1")],
    "size": 1234,
    "duration_ms": 850,
    "streamed": True,
}


def test_a_response_keeps_size_and_type_never_the_body() -> None:
    event = response_event(flow(), RESPONSE | {"body": b"BODY-TEXT"}, KNOWN)
    assert event["action"] == "response" and event["risk"] == 0
    assert event["details"] == {
        "flow_id": "3f2a-flow",
        "status": 200,
        "size": 1234,
        "type": "text/event-stream",
        "duration_ms": 850,
        "streamed": True,
    }
    assert validate_event(event) == event


def test_an_llm_response_carries_the_summary() -> None:
    summary = LlmSummary(
        model="claude-opus-5-5",
        usage={"input": 1, "output": 2},
        stop_reason="end_turn",
        tool_calls=["exec"],
        tool_call_count=1,
        complete=True,
    )
    event = llm_response_event(llm_flow(), "anthropic", RESPONSE, summary, KNOWN)
    assert event["source"] == "llm" and event["action"] == "response"
    details = event["details"]
    assert details["provider"] == "anthropic"
    assert details["status"] == 200
    assert details["usage"] == {"input": 1, "output": 2}
    assert details["tool_calls"] == ["exec"]
    assert details["duration_ms"] == 850
    assert details["streamed"] is True
    assert validate_event(event) == event
    missing = llm_response_event(llm_flow(), "anthropic", RESPONSE, LlmSummary(), KNOWN)
    assert missing["details"]["usage_missing"] is True


# --- the other events --------------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["port", "private_address", "real_key", "not_allowed"])
def test_a_blocked_event_has_its_reason_and_fixed_risk(reason: str) -> None:
    event = blocked_event(reason, flow(), KNOWN)
    assert event["action"] == "blocked"
    assert event["details"]["reason"] == reason
    assert event["risk"] == record.BLOCK_RISK[reason]
    assert "body" not in event["details"]
    assert validate_event(event) == event


def test_a_blocked_connect_only_knows_its_host_and_port() -> None:
    event = blocked_event("port", {"host": "example.com", "port": 22}, KNOWN)
    assert event["target"] == "example.com:22"
    assert event["details"] == {"reason": "port", "host": "example.com", "port": 22}


def test_an_unknown_reason_is_a_bug() -> None:
    with pytest.raises(ValueError):
        blocked_event("because", flow(), KNOWN)


def test_error_tls_websocket_throttled_and_dropped_events() -> None:
    events = [
        error_event("server_connect", error="ConnectionRefusedError", sni="example.com",
                    flow_id="f", host="example.com", port=443, secrets=KNOWN),
        tls_failed_event("pinned.example", host="pinned.example", port=443, secrets=KNOWN),
        websocket_event("websocket_start", flow(), {}, KNOWN),
        websocket_event("websocket_summary", flow(), {"to_server_messages": 3,
                        "to_server_bytes": 100, "to_client_messages": 1, "to_client_bytes": 9},
                        KNOWN),
        websocket_event("websocket_end", flow(), {"close_code": 1000}, KNOWN),
        throttled_event(12, 10),
        dropped_event(5),
    ]  # fmt: skip
    for event in events:
        assert validate_event(event) == event
    assert events[0]["risk"] == 1 and events[1]["risk"] == 1
    assert events[1]["target"] == "pinned.example"
    assert events[3]["details"]["to_server_messages"] == 3
    assert events[4]["details"]["close_code"] == 1000
    assert events[5]["details"] == {"count": 12, "window_s": 10}
    with pytest.raises(ValueError):
        websocket_event("websocket_party", flow(), {}, KNOWN)
    with pytest.raises(ValueError):
        websocket_event("websocket_summary", flow(), {"content": "MESSAGE"}, KNOWN)


def test_an_ipv6_server_and_odd_ports_show_in_the_target() -> None:
    event = request_event(flow(host="2606:4700::1", scheme="http", port=8080, path="/"), KNOWN)
    assert event["target"] == "http://[2606:4700::1]:8080/"
    plain = request_event(flow(scheme="http", port=80, path="/"), KNOWN)
    assert plain["target"] == "http://api.example.com/"


# --- the catalog: no test key ever shows in what is recorded -----------------------------------


FORM = ("Content-Type", "application/x-www-form-urlencoded")
TEXT = ("Content-Type", "text/plain")


def _catalog() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    for key in TEST_KEYS:
        short = key[:10]
        escaped = "".join(f"\\u{ord(c):04x}" for c in key)
        cases += [
            (f"{short}: authorization", flow(headers=[("Authorization", f"Bearer {key}")])),
            (f"{short}: x-api-key", flow(headers=[("X-Api-Key", key)])),
            (f"{short}: odd header", flow(headers=[("X-Weird", key)])),
            (f"{short}: header name", flow(headers=[(f"X-{key}", "1")])),
            (f"{short}: user-agent", flow(headers=[("User-Agent", f"tool/1 ({key})")])),
            (f"{short}: content-type", flow(headers=[("Content-Type", f"text/plain; x={key}")])),
            (f"{short}: cookie", flow(headers=[("Cookie", f"session={key}")])),
            (f"{short}: path", flow(path=f"/v1/{key}/x")),
            (f"{short}: query", flow(path=f"/x?q={key}&page=1")),
            (f"{short}: query name", flow(path=f"/x?{key}=1")),
            (f"{short}: encoded query", flow(path=f"/x?q={quote(key, safe='')}")),
            (f"{short}: all encoded", flow(path="/x?q=" + "".join(f"%{ord(c):02x}" for c in key))),
            (f"{short}: json body", flow(body=json.dumps({"note": f"key is {key}"}).encode())),
            (f"{short}: json escapes", flow(body=f'{{"n": "{escaped}"}}'.encode())),
            (f"{short}: form body", flow(headers=[FORM], body=f"user=ana&k={quote(key)}".encode())),
            (f"{short}: text body", flow(headers=[TEXT], body=f"line 1\n{key}\nline 3".encode())),
            (f"{short}: method", flow(method=key)),
            (f"{short}: host", flow(host=f"{key}.evil.test")),
            (f"{short}: flow id", flow(flow_id=key)),
            (f"{short}: http version", flow(http_version=key)),
        ]  # fmt: skip
    for key in KNOWN:
        # Glued to other text, only an exact search finds a key: the patterns need a boundary.
        cases.append((f"{key[:10]}: glued path", flow(path=f"/bot{key}/sendMessage")))
    return cases


CATALOG = _catalog()


@pytest.mark.parametrize(("name", "case"), CATALOG, ids=[name for name, _ in CATALOG])
def test_no_test_key_shows_in_any_event(name: str, case: dict[str, Any]) -> None:
    llm_case = case | {"body": (case.get("body") or b"")}
    events = [
        request_event(case, KNOWN),
        llm_request_event(llm_case, "anthropic", KNOWN),
        blocked_event("real_key", case, KNOWN),
        response_event(case, RESPONSE, KNOWN),
        websocket_event("websocket_end", case, {"close_code": 1000}, KNOWN),
    ]
    for event in events:
        no_key_in(event)
        assert validate_event(event) == event


def test_no_test_key_shows_in_llm_metadata() -> None:
    for key in TEST_KEYS:
        body = json.dumps({"model": key, "messages": [{"content": key}], "tools": [{"name": key}]})
        no_key_in(llm_request_event(llm_flow(body=body.encode()), "anthropic", KNOWN))
        summary = LlmSummary(model=key, stop_reason=key, tool_calls=[key, f"x {key}"])
        no_key_in(llm_response_event(llm_flow(), "anthropic", RESPONSE, summary, KNOWN))


def test_no_test_key_shows_in_error_and_tls_events() -> None:
    for key in TEST_KEYS:
        no_key_in(error_event("request", error=key, sni=key, flow_id=key, host="evil.test",
                              port=443, secrets=KNOWN))  # fmt: skip
        no_key_in(tls_failed_event(key, host="evil.test", port=443, secrets=KNOWN))


# --- found in the security review (T06-3) ------------------------------------------------------

UNKNOWN_TO_PROXY = _random(48)  # e.g. the Gateway token: the agent may have it, the proxy not


@pytest.mark.parametrize("pad", [record._LIMIT_HEADER_VALUE - 10, record._LIMIT_HEADER_VALUE - 47])
def test_backtide_strikes_what_a_proxy_cut_left_of_a_secret_it_did_not_know(pad: int) -> None:
    headers = [("User-Agent", "u" * pad + UNKNOWN_TO_PROXY)]
    body = ("b" * (EXCERPT_BYTES - 20) + UNKNOWN_TO_PROXY).encode()
    path = "/" + "p" * (record._LIMIT_PATH - 30) + UNKNOWN_TO_PROXY
    event = request_event(flow(headers=headers, body=body, path=path), KNOWN)
    # The proxy did not know it, so a piece is left at each cut ...
    assert UNKNOWN_TO_PROXY[:8] in json.dumps(event)
    # ... and backtide, which knows it, strikes those ends again (docs/21, section 5).
    again = scrub_known(event, [UNKNOWN_TO_PROXY], cut_tails=True)
    text = json.dumps(again)
    for start in range(len(UNKNOWN_TO_PROXY) - 5):
        assert UNKNOWN_TO_PROXY[start : start + 6] not in text.replace("[REDACTED]", "")


def test_a_path_with_thousands_of_parameters_is_cheap_and_capped() -> None:
    path = "/x?" + "&".join(f"p{i}=v{i}" for i in range(8000))
    started = time.perf_counter()
    details = request_event(flow(path=path), KNOWN)["details"]
    assert time.perf_counter() - started < 0.5
    assert len(details["path"].encode()) <= record._LIMIT_PATH


def test_many_parameters_past_the_cap_are_dropped_not_kept_unchecked() -> None:
    params = [f"p{i}=1" for i in range(record._MAX_PARAMS)] + [f"k={GATEWAY}"]
    details = request_event(flow(path="/?" + "&".join(params)), KNOWN)["details"]
    no_key_in(details)


def test_the_target_is_struck_again_once_host_and_path_are_joined() -> None:
    joined = "abcdefghij/klmnopqrstuvwx"
    event = request_event(flow(host="q.abcdefghij", path="/klmnopqrstuvwx"), [joined])
    assert joined not in event["target"]


def test_a_deeply_nested_llm_body_keeps_nothing_and_does_not_raise() -> None:
    details = llm_request_event(flow(body=b"[" * 200_000), "anthropic", KNOWN)["details"]
    assert details["model"] is None and details["messages"] is None


def test_a_scrubber_built_once_can_be_reused_for_many_events() -> None:
    scrubber = KnownScrubber(KNOWN)
    for key in KNOWN:
        no_key_in(request_event(flow(path=f"/x/{key}"), scrubber))
