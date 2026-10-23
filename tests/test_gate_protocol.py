import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from backtide.gate.protocol import (
    BLOCK_RISK,
    DEFAULT_LIMITS,
    MAX_LINE_BYTES,
    LineReader,
    ProtocolError,
    Sender,
    ack,
    config,
    decision,
    decode,
    describe,
    encode,
    event,
    gate,
    hello,
    hold_left,
    ping,
    pong,
    providers_from_config,
    released,
    request,
    validate_event,
)
from backtide.gate.providers import FAKE_KEY_PREFIX, Kind, Provider, Providers, Secret

REAL = "sk-ant-api03-TEST" + "pr0t0c0lR3alK3y" * 4
FAKE = FAKE_KEY_PREFIX + "anthropic-" + "P1q2R3s4T5u6V7w8X9y0Z1a2B3c4D5e6"


def providers() -> Providers:
    return Providers(
        [
            Provider(
                name="anthropic",
                kind=Kind.ANTHROPIC,
                host="api.anthropic.com",
                fake_key=FAKE,
                real_key=Secret(REAL),
            )
        ]
    )


def net_request() -> dict[str, Any]:
    return {
        "source": "net",
        "action": "request",
        "target": "https://example.com/x",
        "risk": 0,
        "details": {"flow_id": "f1", "method": "POST", "host": "example.com", "port": 443},
    }


FP = "ab" * 32
HOLD = "h-0123456789ab"


def facts(**changes: Any) -> dict[str, Any]:
    return gate(fp=FP, url_struck=False, url_bytes=40, websocket=False, exact_read=False,
                headers_struck=False, header_bytes=120) | changes  # fmt: skip


def blocked(reason: str = "port", risk: int | None = None) -> dict[str, Any]:
    return {
        "source": "net",
        "action": "blocked",
        "target": "example.com:22",
        "risk": BLOCK_RISK[reason] if risk is None else risk,
        "details": {"reason": reason, "host": "example.com", "port": 22},
    }


def roundtrip(message: dict[str, Any], sender: Sender) -> dict[str, Any]:
    line = encode(message, sender)
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert len(line) <= MAX_LINE_BYTES
    return decode(line, sender)


# --- the messages ------------------------------------------------------------------------------


def test_the_proxy_messages_go_there_and_back() -> None:
    for message in (
        hello("0.1.0", 7),
        request(1, net_request(), facts()),
        request(2, net_request(), facts(wait_hint_s=50, url_struck=True, exact_read=True)),
        request(3, net_request(), facts(headers_struck=True, header_bytes=70_000)),
        released(HOLD),
        hold_left(HOLD, "client_left"),
        hold_left(HOLD, "waited"),
        hold_left(HOLD, "no_slot"),
        event(blocked()),
        ping(),
        pong(),
    ):
        assert roundtrip(message, Sender.PROXY) == message


def test_the_backtide_messages_go_there_and_back() -> None:
    allow = ack(1, "allow", seq=42)
    deny = ack(2, "deny", seq=43, reason="not_allowed")
    slow = ack(3, "deny", reason="throttled", retry_after=5)
    held = ack(4, "hold", seq=44, hold_id=HOLD, wait_ms=90_000, retry_after=30)
    again = ack(5, "deny", seq=45, reason="gate_rejected")
    full = ack(6, "deny", reason="hold_full")
    let_go = decision(HOLD, "allow", seq=46)
    no = [decision(HOLD, "deny", reason=r) for r in ("rejected", "expired", "paused", "hold_full")]
    for message in (allow, deny, slow, held, again, full, let_go, *no, ping(), pong()):
        assert roundtrip(message, Sender.BACKTIDE) == message


def test_a_config_carries_the_keys_and_becomes_providers_again() -> None:
    message = config(["Example.COM", "*.cdn.example.net"], providers(), {"max_pending": 8})
    back = roundtrip(message, Sender.BACKTIDE)
    assert back["allow_hosts"] == ["example.com", "*.cdn.example.net"]
    assert back["limits"] == {**DEFAULT_LIMITS, "max_pending": 8}
    rebuilt = providers_from_config(back)
    [provider] = rebuilt.items
    assert provider.name == "anthropic" and provider.host == "api.anthropic.com"
    assert provider.fake_key == FAKE and provider.real_key.reveal() == REAL


@pytest.mark.parametrize(
    ("message", "sender"),
    [
        (lambda: config([], providers(), {}), Sender.PROXY),  # only backtide configures
        (lambda: ack(1, "allow", seq=1), Sender.PROXY),
        (lambda: hello("1", 1), Sender.BACKTIDE),
        (lambda: request(1, net_request(), facts()), Sender.BACKTIDE),
        (lambda: event(blocked()), Sender.BACKTIDE),
        (lambda: decision(HOLD, "allow", seq=1), Sender.PROXY),  # only backtide decides
        (lambda: released(HOLD), Sender.BACKTIDE),
        (lambda: hold_left(HOLD, "waited"), Sender.BACKTIDE),
    ],
)
def test_each_side_only_sends_its_own_messages(message: Any, sender: Sender) -> None:
    built = message()
    with pytest.raises(ProtocolError):
        encode(built, sender)
    other = Sender.BACKTIDE if sender is Sender.PROXY else Sender.PROXY
    line = encode(built, other)
    with pytest.raises(ProtocolError):
        decode(line, sender)


# --- lines -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"\n",
        b"not json\n",
        b"[1, 2]\n",
        b'"ping"\n',
        b'{"type": "ping"',
        b'{"type": "ping"}\n{"type": "ping"}\n',  # two messages in one line
        b'{"type": "ping", "type": "pong"}\n',  # duplicate keys
        b'{"type": "nope"}\n',
        b"{}\n",
        b'{"type": "ping", "extra": 1}\n',
        b'{"type": "hello", "version": "1", "pid": NaN}\n',
        b'{"type": "hello", "version": "1", "pid": 1.0}\n',
        b'{"type": "hello", "version": "1", "pid": true}\n',
        b'{"type": "hello", "version": "1", "pid": 0}\n',
        b'{"type": "hello", "version": "1\\n2", "pid": 1}\n',
        b'{"type": "hello", "version": "", "pid": 1}\n',
        b'{"type": "hello", "version": "1"}\n',
        b'{"type": "p\xffing"}\n',  # not UTF-8
    ],
)
def test_broken_lines_are_refused(line: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode(line, Sender.PROXY)


@pytest.mark.parametrize(
    "line",
    [b"[" * 60_000, b'{"type": "event", "event": ' + b"[" * 60_000, b'{"a":' * 12_000 + b"1"],
)
def test_deeply_nested_json_is_a_protocol_error(line: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode(line, Sender.PROXY)


def test_a_line_over_64_kib_is_refused_both_ways() -> None:
    big = net_request()
    big["details"]["path"] = "/" + "a" * 4000
    big["details"]["headers"] = {f"x-h{i}": "v" * 1000 for i in range(64)}
    with pytest.raises(ProtocolError):
        encode(request(1, big, facts()), Sender.PROXY)
    raw = json.dumps({"type": "ping", "pad": "x" * MAX_LINE_BYTES}).encode() + b"\n"
    with pytest.raises(ProtocolError):
        decode(raw, Sender.PROXY)


def test_the_line_reader_splits_and_joins_chunks() -> None:
    reader = LineReader()
    assert reader.feed(b'{"type": "pi') == []
    assert reader.feed(b'ng"}\n{"type": "pong"}\n{"ty') == [
        b'{"type": "ping"}\n',
        b'{"type": "pong"}\n',
    ]
    assert reader.feed(b'pe": "ping"}\n') == [b'{"type": "ping"}\n']


def test_the_line_reader_refuses_a_line_over_the_limit_even_without_its_end() -> None:
    reader = LineReader()
    reader.feed(b"x" * (MAX_LINE_BYTES - 1))
    with pytest.raises(ProtocolError):
        reader.feed(b"xx")
    exact = LineReader()
    assert exact.feed(b"y" * (MAX_LINE_BYTES - 1) + b"\n") == [b"y" * (MAX_LINE_BYTES - 1) + b"\n"]


# --- events (what the proxy says is data that cannot be trusted) -------------------------------


@pytest.mark.parametrize("source", ["system", "file", "snapshot", "exec", "gate", "NET", "", None])
def test_the_proxy_only_writes_net_and_llm_events(source: object) -> None:
    bad = net_request() | {"source": source}
    with pytest.raises(ProtocolError):
        validate_event(bad)


@pytest.mark.parametrize(
    "change",
    [
        {"action": "delete_everything"},
        {"action": "response", "source": "file"},
        {"target": 42},
        {"target": "x" * 5000},
        {"risk": 4},
        {"risk": -1},
        {"risk": True},
        {"risk": 1},  # a request is risk 0: the proxy cannot choose its own risk
        {"details": []},
        {"details": {"unknown_key": 1}},
        {"details": {"method": "POST", "flow_id": {"a": {"b": {"c": {"d": 1}}}}}},
        {"details": {"method": "x" * 5000}},
        {"details": {"method": float("nan")}},
        {"details": {"headers": {f"h{i}": "v" for i in range(200)}}},
        {"details": {"flow_id": [1] * 200}},
        {"extra": 1},
    ],
)
def test_bad_events_are_refused(change: dict[str, Any]) -> None:
    bad = net_request() | change
    with pytest.raises(ProtocolError):
        validate_event(bad)


def test_a_missing_event_field_is_refused() -> None:
    for key in ("source", "action", "target", "risk", "details"):
        bad = net_request()
        del bad[key]
        with pytest.raises(ProtocolError):
            validate_event(bad)


@pytest.mark.parametrize("reason", sorted(BLOCK_RISK))
def test_each_block_reason_has_its_fixed_risk(reason: str) -> None:
    assert validate_event(blocked(reason)) == blocked(reason)
    for wrong in {0, 1, 2, 3} - {BLOCK_RISK[reason]}:
        with pytest.raises(ProtocolError):
            validate_event(blocked(reason, risk=wrong))


def test_the_block_risks_are_the_design_ones() -> None:
    assert BLOCK_RISK == {
        "port": 1,
        "private_address": 2,
        "host_mismatch": 2,
        "oauth_login": 2,
        "real_key": 3,
        "foreign_credential": 2,
        "too_large": 1,
        "throttled": 1,
        "not_recorded": 2,
        "not_allowed": 1,
        "undecodable": 2,
        "trailers": 2,  # HTTP/1 trailers, which mitmproxy cannot read (review of T10-2)
        "malformed_header": 2,  # a header or framing that could reframe the request (T11 review)
        "provider_endpoint": 2,
        "provider_body": 2,
        "provider_side_tool": 2,
        "gate_rejected": 1,
        "local_redirect": 2,  # T20
    }


def test_an_unknown_block_reason_is_refused() -> None:
    bad = blocked()
    bad["details"]["reason"] = "because"
    with pytest.raises(ProtocolError):
        validate_event(bad)


def test_a_request_must_go_through_its_ack_and_an_ack_is_only_for_requests() -> None:
    with pytest.raises(ProtocolError):
        event(net_request())  # a request is never a plain event
    with pytest.raises(ProtocolError):
        request(1, blocked())


@pytest.mark.parametrize(
    "build",
    [
        lambda: ack(1, "allow"),  # an allow without its seq
        lambda: ack(1, "allow", seq=1, reason="not_allowed"),
        lambda: ack(1, "hold", seq=1),  # a hold without its id and wait
        lambda: ack(1, "hold", seq=1, hold_id=HOLD, wait_ms=1000),  # nor its Retry-After
        lambda: ack(1, "hold", hold_id=HOLD, wait_ms=1000, retry_after=30),  # nor its gate/held
        lambda: ack(1, "hold", seq=1, hold_id="h-XYZ", wait_ms=1000, retry_after=30),
        lambda: ack(1, "hold", seq=1, hold_id=HOLD, wait_ms=90_001, retry_after=30),
        lambda: ack(1, "hold", seq=1, hold_id=HOLD, wait_ms=-1, retry_after=30),
        lambda: ack(1, "hold", seq=1, hold_id=HOLD, wait_ms=10, retry_after=30, reason="write"),
        lambda: ack(1, "allow", seq=1, hold_id=HOLD),  # only a hold has a hold id
        lambda: ack(1, "deny", reason="not_allowed", wait_ms=5),
        lambda: ack(1, "deny", reason="rejected"),  # a decision's reason, not an ack's
        lambda: ack(1, "deny"),  # a deny without its reason
        lambda: ack(1, "deny", reason="because"),
        lambda: ack(1, "deny", reason="not_allowed", retry_after=5),
        lambda: ack(1, "deny", reason="throttled", retry_after=0),
        lambda: ack(0, "allow", seq=1),
        lambda: ack(2**53, "allow", seq=1),
        lambda: ack(1, "allow", seq=0),
        lambda: ack(True, "allow", seq=1),
        lambda: request(0, net_request(), facts()),
        lambda: hello("1", -5),
    ],
)
def test_bad_acks_and_ids_are_refused(build: Any) -> None:
    with pytest.raises(ProtocolError):
        build()


# --- the hold (T10-2) --------------------------------------------------------------------------


def llm_request() -> dict[str, Any]:
    return net_request() | {"source": "llm", "details": {"provider": "anthropic", "port": 443}}


def test_a_net_request_carries_its_gate_facts_and_a_model_call_none() -> None:
    with pytest.raises(ProtocolError):
        request(1, net_request())  # what would backtide decide on?
    assert "gate" not in request(1, llm_request())
    with pytest.raises(ProtocolError):
        request(1, llm_request(), facts())  # a provider's host is never held


@pytest.mark.parametrize(
    "change",
    [
        {"fp": "AB" * 32},  # lower-case hex only
        {"fp": "ab" * 31},
        {"fp": 7},
        {"url_struck": 1},
        {"websocket": "yes"},
        {"exact_read": None},
        {"url_bytes": -1},
        {"url_bytes": 2**31 + 1},
        {"url_bytes": True},
        {"headers_struck": 0},  # the header guard (security review of T10-2, M3)
        {"headers_struck": "false"},
        {"header_bytes": -1},
        {"header_bytes": 2**31 + 1},
        {"header_bytes": False},
        {"header_bytes": 1.5},
        {"wait_hint_s": 0},
        {"wait_hint_s": 91},
        {"wait_hint_s": 1.5},
        {"reading": {"effect": "read"}},  # the translators' field comes with T10-3
    ],
)
def test_bad_gate_facts_are_refused(change: dict[str, Any]) -> None:
    message = {"type": "request", "id": 1, "event": net_request(), "gate": facts() | change}
    with pytest.raises(ProtocolError):
        decode(json.dumps(message).encode(), Sender.PROXY)


def test_missing_gate_facts_are_refused() -> None:
    for key in facts():
        broken = facts()
        del broken[key]
        message = {"type": "request", "id": 1, "event": net_request(), "gate": broken}
        with pytest.raises(ProtocolError):
            decode(json.dumps(message).encode(), Sender.PROXY)


@pytest.mark.parametrize(
    "build",
    [
        lambda: decision(HOLD, "allow"),  # an allow names its net/request
        lambda: decision(HOLD, "allow", seq=1, reason="rejected"),
        lambda: decision(HOLD, "deny"),
        lambda: decision(HOLD, "deny", reason="because"),
        lambda: decision(HOLD, "deny", seq=3, reason="rejected"),
        lambda: decision(HOLD, "hold", seq=3),
        lambda: decision("h-0123456789aB", "allow", seq=1),
        lambda: decision("h-0123456789ab0", "allow", seq=1),
        lambda: released("x"),
        lambda: hold_left(HOLD, "bored"),
        lambda: hold_left(HOLD, ""),
    ],
)
def test_bad_decisions_and_hold_messages_are_refused(build: Any) -> None:
    with pytest.raises(ProtocolError):
        build()


def test_hold_messages_have_exactly_their_fields() -> None:
    for message in (
        {"type": "released", "hold_id": HOLD, "seq": 1},
        {"type": "hold_left", "hold_id": HOLD, "why": "waited", "extra": 1},
        {"type": "hold_left", "hold_id": HOLD},
    ):
        with pytest.raises(ProtocolError):
            decode(json.dumps(message).encode(), Sender.PROXY)
    with pytest.raises(ProtocolError):
        decode(json.dumps(decision(HOLD, "allow", seq=1) | {"x": 1}).encode(), Sender.BACKTIDE)


def test_the_hold_messages_are_described_without_their_content() -> None:
    assert describe(decision(HOLD, "allow", seq=1)) == f"decision {HOLD}"
    assert describe({"type": "hold_left", "hold_id": "secret-ish"}) == "hold_left ?"


# --- the config --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"allow_hosts": ["*"]},
        {"allow_hosts": ["8.8.8.8"]},
        {"allow_hosts": "example.com"},
        {"limits": {"max_pending": 0}},
        {"limits": {"max_pending": 10**9}},
        {"limits": {"unknown": 1}},
        {"limits": {"max_pending": True}},
        {"limits": {"max_pending_reads": 0}},
        {"limits": {"max_pending_reads": 5000}},
        {"providers": [{"name": "anthropic"}]},
        {"providers": "x"},
        {"limits": {"max_holds": 0}},
        {"limits": {"max_holds": 65}},
        {"fp_key": "ab" * 16},
        {"fp_key": "AB" * 32},
        {"fp_key": None},
    ],
)
def test_a_bad_config_is_refused(change: dict[str, Any]) -> None:
    message = config([], providers(), {}) | change
    with pytest.raises(ProtocolError):
        encode(message, Sender.BACKTIDE)


def test_a_config_with_a_bad_provider_is_refused_without_showing_the_key() -> None:
    message = config([], providers(), {})
    message["providers"][0]["fake_key"] = "not-a-fake-" + REAL
    line = json.dumps(message).encode() + b"\n"
    with pytest.raises(ProtocolError) as error:
        decode(line, Sender.BACKTIDE)
    assert REAL not in str(error.value)
    with pytest.raises(ProtocolError) as error:
        providers_from_config(message)
    assert REAL not in str(error.value)


def test_describe_never_shows_a_key() -> None:
    message = config(["example.com"], providers(), {})
    text = describe(message)
    assert REAL not in text and FAKE not in text
    assert "config" in text and "anthropic" in text
    assert describe(ping()) == "ping"


def test_errors_never_show_the_offending_value() -> None:
    bad = net_request()
    bad["details"]["unknown_" + REAL[:30]] = REAL
    with pytest.raises(ProtocolError) as error:
        validate_event(bad)
    assert REAL not in str(error.value)
    assert REAL[:30] not in str(error.value)
    with pytest.raises(ProtocolError) as error:
        decode(json.dumps({"type": REAL}).encode(), Sender.PROXY)
    assert REAL not in str(error.value)


def test_the_gate_modules_are_pure() -> None:
    # The proxy loads these: no mitmproxy, no service, no web, no jail (docs/21, section 1).
    code = (
        "import sys\n"
        "import backtide.gate.policy, backtide.gate.providers, backtide.gate.record\n"
        "import backtide.gate.sse, backtide.gate.protocol\n"
        "bad = ('mitmproxy', 'fastapi', 'backtide.service', 'backtide.web', 'backtide.jail')\n"
        "print([m for m in sys.modules if m.startswith(bad)])\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.stdout.strip() == "[]"


# --- provider-side tools (T06-6) -----------------------------------------------------------------


def test_a_config_carries_the_allowed_provider_tools() -> None:
    message = config([], providers(), {}, provider_tools=["web_search_20250305", "mcp"])
    back = roundtrip(message, Sender.BACKTIDE)
    assert back["provider_tools"] == ["web_search_20250305", "mcp"]


def test_a_config_without_provider_tools_allows_none() -> None:
    message = config([], providers(), {})
    assert message["provider_tools"] == []
    del message["provider_tools"]
    assert roundtrip(message, Sender.BACKTIDE)["provider_tools"] == []


@pytest.mark.parametrize(
    "tools", [["Web Search"], "mcp", [7], ["x" * 65], [f"t{n}" for n in range(100)]]
)
def test_bad_provider_tools_are_refused(tools: object) -> None:
    message = config([], providers(), {}) | {"provider_tools": tools}
    with pytest.raises(ProtocolError):
        encode(message, Sender.BACKTIDE)


def test_a_refusal_names_the_provider_tools_and_its_side() -> None:
    event_ = blocked("provider_side_tool", risk=2)
    event_["details"]["tools"] = ["web_fetch_20250910", "mcp_servers"]
    assert validate_event(event_) == event_
    echo = blocked("real_key", risk=3)
    echo["details"]["side"] = "response"
    assert validate_event(echo) == echo


def test_an_llm_request_may_name_the_allowed_provider_tools() -> None:
    event_ = {
        "source": "llm",
        "action": "request",
        "target": "https://api.anthropic.com/v1/messages",
        "risk": 0,
        "details": {"provider": "anthropic", "provider_tools": ["web_search_20250305"]},
    }
    assert validate_event(event_) == event_


def test_a_config_carries_each_providers_models() -> None:
    listed = Providers(
        [Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL),
                  models=("claude-x", "claude-y"))]
    )  # fmt: skip
    back = roundtrip(config([], listed, {}), Sender.BACKTIDE)
    assert back["providers"][0]["models"] == ["claude-x", "claude-y"]
    assert providers_from_config(back).items[0].models == ("claude-x", "claude-y")


@pytest.mark.parametrize("models", ["claude-x", [7], [""], ["x" * 200], ["m"] * 40])
def test_bad_provider_models_are_refused(models: object) -> None:
    message = config([], providers(), {})
    message["providers"][0]["models"] = models
    with pytest.raises(ProtocolError):
        encode(message, Sender.BACKTIDE)


def test_a_config_carries_this_connections_fingerprint_key_and_never_shows_it() -> None:
    key = bytes(range(32))
    message = config([], providers(), {}, fp_key=key)
    assert roundtrip(message, Sender.BACKTIDE)["fp_key"] == key.hex()
    assert key.hex() not in describe(message)
    assert config([], providers(), {})["fp_key"] != config([], providers(), {})["fp_key"]
    del message["fp_key"]
    with pytest.raises(ProtocolError):
        encode(message, Sender.BACKTIDE)


# --- a translator's reading in gate.reading (T10-3) ---------------------------------------------


def a_summary(**changes: Any) -> dict[str, Any]:
    from backtide.gate.translate.base import Attachment, Effect, Reading, Shape

    reading = Reading(
        translator="gmail", operation="messages.send", effect=Effect.SEND, shape=Shape.GOOGLE,
        wait_s=25, account="0123456789abcdef", recipients=("ana@example.com",),
        subject="Hola", first_lines="Qué tal", attachments=(Attachment("plan.pdf", None, 10),),
    )  # fmt: skip
    return reading.summary() | changes


def test_a_reading_goes_there_and_back() -> None:
    from backtide.gate.protocol import fit_reading

    reading = fit_reading(a_summary())
    assert reading["cut"] is False and reading["risk"] == 2
    back = roundtrip(request(1, net_request(), facts(reading=reading)), Sender.PROXY)
    assert back["gate"]["reading"] == reading


@pytest.mark.parametrize(
    "change",
    [
        {"translator": "smtp"},
        {"operation": "send mail"},
        {"effect": "exfiltrate"},
        {"shape": "html"},
        {"notes": ["please_approve"]},
        {"risk": 0},  # a send is risk 2: the proxy cannot choose it
        {"secret_seen": True},  # ... and with a secret, 3
        {"account": "AKIA0123456789AB"},
        {"draft": "../r-1"},
        {"recipients": ["x" * 400]},
        {"recipients": ["a@b.c"] * 65},
        {"subject": "s" * 201},
        {"first_lines": "l" * 301},
        {"attachments": [{"name": "a", "type": "text/html; x", "size": 1}]},
        {"attachments": [{"name": "a", "type": None, "size": -1}]},
        {"wait_s": 91},
        {"extra": 1},
    ],
)
def test_a_reading_is_checked_field_by_field(change: dict[str, Any]) -> None:
    from backtide.gate.protocol import fit_reading

    with pytest.raises(ProtocolError):
        fit_reading(a_summary(**change))


def test_a_reading_too_large_for_the_line_is_cut_and_says_so() -> None:
    """64 long recipients, as many Reply-To and 32 attachments with long non-Latin names do not
    fit in a line: the reading is sent cut (``cut: true``), which backtide never trusts."""
    from backtide.gate.protocol import MAX_READING_BYTES, fit_reading

    long = [f"{'a' * 60}{n}@{'b' * 60}.example.com" for n in range(64)]
    names = [{"name": "ñ" * 100, "type": None, "size": 1} for _ in range(32)]
    reading = fit_reading(a_summary(recipients=long, reply_to=long, attachments=names))
    assert reading["cut"] is True
    assert len(json.dumps(reading)) <= MAX_READING_BYTES
    assert reading["effect"] == "send" and reading["risk"] == 2
    line = encode(request(1, net_request(), facts(reading=reading)), Sender.PROXY)
    assert len(line) <= MAX_LINE_BYTES


def test_the_config_carries_the_read_endpoints() -> None:
    message = config([], providers(), {}, read_endpoints=["Search.Fake.Test/v1/Query"])
    assert roundtrip(message, Sender.BACKTIDE)["read_endpoints"] == ["search.fake.test/v1/query"]
    for bad in (["https://x.test/a"], ["x.test/a?q=1"], ["x.test/../a"], ["x.test"] * 1):
        with pytest.raises(ProtocolError):
            encode(config([], providers(), {}, read_endpoints=bad), Sender.BACKTIDE)


def test_the_gate_carries_the_credential_bytes_and_the_body_secret() -> None:
    back = roundtrip(request(1, net_request(), facts(credential_bytes=5000, body_struck=True)),
                     Sender.PROXY)  # fmt: skip
    assert back["gate"]["credential_bytes"] == 5000 and back["gate"]["body_struck"] is True
    assert back["gate"]["credentials_struck"] is False
    struck = roundtrip(request(1, net_request(), facts(credentials_struck=True)), Sender.PROXY)
    assert struck["gate"]["credentials_struck"] is True
    for bad in (
        {"credential_bytes": -1},
        {"body_struck": "yes"},
        {"reading": "send"},
        {"credentials_struck": 1},
    ):
        with pytest.raises(ProtocolError):
            encode(request(1, net_request(), facts() | bad), Sender.PROXY)


def test_the_gate_carries_the_override_the_trailers_and_the_credential_id() -> None:
    """Security review of T10-4, A1 and M1: what a batch must not cover, and whose token."""
    sent = facts(override="DELETE", trailers=True, credential_id="c" * 64)
    back = roundtrip(request(1, net_request(), sent), Sender.PROXY)
    assert (back["gate"]["override"], back["gate"]["trailers"]) == ("DELETE", True)
    assert back["gate"]["credential_id"] == "c" * 64
    assert (
        roundtrip(request(1, net_request(), facts(override="?")), Sender.PROXY)["gate"]["override"]
        == "?"
    )
    for bad in (
        {"override": "delete"},  # upper case only, as base.override_of gives it
        {"override": "DEL ETE"},
        {"override": ""},
        {"override": 1},
        {"trailers": 1},
        {"credential_id": "C" * 64},
        {"credential_id": "c" * 63},
        {"credential_id": 7},
    ):
        with pytest.raises(ProtocolError):
            encode(request(1, net_request(), facts() | bad), Sender.PROXY)
