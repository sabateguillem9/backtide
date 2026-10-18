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
    decode,
    describe,
    encode,
    event,
    hello,
    ping,
    pong,
    providers_from_config,
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
        request(1, net_request()),
        event(blocked()),
        ping(),
        pong(),
    ):
        assert roundtrip(message, Sender.PROXY) == message


def test_the_backtide_messages_go_there_and_back() -> None:
    allow = ack(1, "allow", seq=42)
    deny = ack(2, "deny", seq=43, reason="not_allowed")
    slow = ack(3, "deny", reason="throttled", retry_after=5)
    for message in (allow, deny, slow, ping(), pong()):
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
        (lambda: request(1, net_request()), Sender.BACKTIDE),
        (lambda: event(blocked()), Sender.BACKTIDE),
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
        encode(request(1, big), Sender.PROXY)
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
        "provider_endpoint": 2,
        "provider_body": 2,
        "provider_side_tool": 2,
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
        lambda: ack(1, "hold", seq=1),  # T10
        lambda: ack(1, "deny"),  # a deny without its reason
        lambda: ack(1, "deny", reason="because"),
        lambda: ack(1, "deny", reason="not_allowed", retry_after=5),
        lambda: ack(1, "deny", reason="throttled", retry_after=0),
        lambda: ack(0, "allow", seq=1),
        lambda: ack(2**53, "allow", seq=1),
        lambda: ack(1, "allow", seq=0),
        lambda: ack(True, "allow", seq=1),
        lambda: request(0, net_request()),
        lambda: hello("1", -5),
    ],
)
def test_bad_acks_and_ids_are_refused(build: Any) -> None:
    with pytest.raises(ProtocolError):
        build()


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
        {"providers": [{"name": "anthropic"}]},
        {"providers": "x"},
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
