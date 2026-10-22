# ruff: noqa: F811 - pytest fixtures imported from the tests they come from
"""A provider of ``[proxy]`` whose key the owner has not set yet (or whose file cannot be used)
"waits for its key" (docs/21, section 6): backtide starts, the proxy refuses every call to it in
the provider's own error shape without contacting it (``no_key``), backtide records the refusals
as ``llm/blocked`` (rate-limited), and Settings, /estado and the panel say so. Setting the key
makes it usable at once; removing it makes it wait again. Every key here is made up."""

import json
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.blackbox.redact import KnownScrubber
from backtide.gate import protocol
from backtide.gate.client import Ack
from backtide.gate.providers import (
    FAKE_KEY_PREFIX,
    NO_KEY_MESSAGE,
    Kind,
    Provider,
    Providers,
    Secret,
    blocked_response,
    only_fake_key,
    swap_key,
)
from backtide.service import proxy_channel as channel_module
from backtide.service.bot import GuardianActions
from backtide.service.control import ControlServer, ask_budget
from backtide.service.egress import Egress, EgressHooks
from backtide.service.proxy_channel import Policy
from tests.test_gate_addon import FakeChannel, make_gate, model_flow, send, tool_body
from tests.test_service_bot import FakeGuardian as BotGuardian
from tests.test_service_bot import FakeStore
from tests.test_service_control import FakeGuardian, me
from tests.test_service_control_settings import box, folder  # noqa: F401 - fixtures
from tests.test_service_proxy_channel import make_channel
from tests.test_service_proxy_channel import policy as strict_policy
from tests.test_spend_gate import llm_request

REAL = "sk-ant-api03-TEST" + "W4it1ngK3y" * 5
FAKE = FAKE_KEY_PREFIX + "anthropic-" + "Z1y2x3w4v5U6t7S8r9Q0p1O2n3M4l5K6"
OPENAI_FAKE = FAKE_KEY_PREFIX + "openai-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
# OpenClaw 2026.9.8 reads these words of a provider's error before its status, and would take
# the no_key answer for an auth or billing error (and put the agent's key on a cooldown).
TRIGGERS = ("api key", "api_key", "authentication", "credential", "unauthorized", "forbidden",
            "expired", "permission", "rate limit", "quota", "billing", "credit", "revoked",
            "deactivated", "disabled")  # fmt: skip


def waiting_anthropic() -> Provider:
    return Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, None)


# --- the providers ------------------------------------------------------------------------------


def test_a_provider_without_its_key_never_gets_one_swapped_in() -> None:
    provider = waiting_anthropic()
    headers = [("x-api-key", FAKE), ("content-type", "application/json")]
    assert provider.waiting
    assert swap_key(provider, headers, scheme="https", port=443) is None  # fail closed
    assert only_fake_key(provider, headers, scheme="https", port=443) == [
        ("content-type", "application/json")
    ]
    assert only_fake_key(provider, [("x-api-key", REAL)], scheme="https", port=443) is None
    with pytest.raises(ValueError):
        provider._real_header_value()  # noqa: SLF001


def test_providers_without_a_key_have_no_secret_but_their_fake_one() -> None:
    ready = Provider("openai", Kind.OPENAI, "api.openai.com", OPENAI_FAKE, Secret(REAL))
    providers = Providers([waiting_anthropic(), ready])
    assert providers.waiting() == ("anthropic",)
    assert providers.known_secrets() == (REAL, FAKE, OPENAI_FAKE)
    assert providers.real_key_in(f"x {REAL}") and not providers.real_key_in(FAKE)
    assert providers.for_host("api.anthropic.com") is not None  # still a provider's host
    assert REAL not in repr(providers) and FAKE not in repr(waiting_anthropic())


@pytest.mark.parametrize("kind", ["anthropic", "openai"])
def test_the_no_key_answer_has_the_providers_shape(kind: str) -> None:
    status, body, headers = blocked_response(kind, "no_key", "anthropic")
    data = json.loads(body)
    assert status == 400  # neither retried nor a cooldown of the agent's key in OpenClaw
    assert headers == {"content-type": "application/json", "x-backtide": "no_key"}
    message = NO_KEY_MESSAGE.format(name="anthropic")
    if kind == "anthropic":
        assert data == {
            "type": "error",
            "error": {"type": "invalid_request_error", "message": message},
        }
    else:
        assert data == {
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "code": "backtide_no_key",
                "param": None,
            }
        }
    assert "Settings" in message and "Ajustes" in message and "anthropic" in message
    assert not [word for word in TRIGGERS if word in message.lower()]
    with pytest.raises(ValueError):
        blocked_response(kind, "no_key", "x\ny")


def test_the_proxys_config_carries_a_provider_without_its_key() -> None:
    providers = Providers([waiting_anthropic()])
    message = protocol.config(["example.com"], providers, {})
    assert message["providers"][0]["real_key"] is None
    line = protocol.encode(message, protocol.Sender.BACKTIDE)
    decoded = protocol.decode(line, protocol.Sender.BACKTIDE)
    back = protocol.providers_from_config(decoded)
    (provider,) = back.items
    assert provider.waiting and provider.fake_key == FAKE
    assert "anthropic (no key yet)" in protocol.describe(decoded)
    assert REAL not in protocol.describe(decoded)
    for bad in (5, ["x"], {"k": 1}):
        broken = json.loads(line)
        broken["providers"][0]["real_key"] = bad
        with pytest.raises(protocol.ProtocolError):
            protocol.decode(json.dumps(broken).encode() + b"\n", protocol.Sender.BACKTIDE)
    assert protocol.ack(1, "deny", reason="no_key")["reason"] == "no_key"


# --- a key that is never swapped in is still struck (review of T09b, finding 2) ------------------

STRUCK = "sk-ant-api03-TEST" + "Unus4bleButR3al" * 3  # a key whose file cannot be used


def test_a_strike_only_key_is_struck_and_searched_for_but_never_swapped_in() -> None:
    providers = Providers([waiting_anthropic()], strike_only=[STRUCK, STRUCK])
    assert providers.strike_only == (STRUCK,)
    assert providers.known_secrets() == (STRUCK, FAKE)
    assert providers.real_key_in(f"curl -d {STRUCK}") and not providers.real_key_in(FAKE)
    assert providers.keys_to_find() == (STRUCK,)
    headers = [("x-api-key", FAKE)]
    assert swap_key(providers.items[0], headers, scheme="https", port=443) is None
    assert STRUCK not in repr(providers)
    for bad in (["short"], [5], [FAKE]):  # too short to search for, not a text, a fake key
        with pytest.raises(ValueError):
            Providers([waiting_anthropic()], strike_only=bad)  # type: ignore[list-item]


def test_the_proxys_config_carries_the_keys_to_strike_only() -> None:
    providers = Providers([waiting_anthropic()], strike_only=[STRUCK])
    message = protocol.config(["example.com"], providers, {})
    line = protocol.encode(message, protocol.Sender.BACKTIDE)
    decoded = protocol.decode(line, protocol.Sender.BACKTIDE)
    back = protocol.providers_from_config(decoded)
    assert back.strike_only == (STRUCK,) and back.waiting() == ("anthropic",)
    assert STRUCK not in protocol.describe(decoded)
    plain = protocol.config(["example.com"], Providers([waiting_anthropic()]), {})
    assert "strike_only" not in plain  # nothing to strike: the field is left out
    for bad in (5, ["short"], [5], [STRUCK] * 100):
        broken = json.loads(line)
        broken["strike_only"] = bad
        with pytest.raises(protocol.ProtocolError):
            protocol.decode(json.dumps(broken).encode() + b"\n", protocol.Sender.BACKTIDE)


def test_the_keys_to_strike_only_have_their_own_cap() -> None:
    """Review of 40dfd53, finding 4: strike_only is not capped by the number of providers but by
    MAX_STRIKE_ONLY (failed reloads add to it), and that many still fit in one line."""
    keys = [f"sk-ant-api03-TEST{i:03d}" + "Unus4bleButR3al" * 3 for i in range(70)]
    fits = Providers([waiting_anthropic()], strike_only=keys[: protocol.MAX_STRIKE_ONLY])
    line = protocol.encode(protocol.config(["example.com"], fits, {}), protocol.Sender.BACKTIDE)
    decoded = protocol.decode(line, protocol.Sender.BACKTIDE)
    assert len(protocol.providers_from_config(decoded).strike_only) == protocol.MAX_STRIKE_ONLY
    assert protocol.MAX_STRIKE_ONLY > 32  # more than _MAX_PROVIDERS
    assert protocol.STRIKE_ONLY_CHARS < protocol.MAX_LINE_BYTES // 2
    too_many = Providers([waiting_anthropic()], strike_only=keys[: protocol.MAX_STRIKE_ONLY + 1])
    with pytest.raises(protocol.ProtocolError):
        protocol.encode(protocol.config(["example.com"], too_many, {}), protocol.Sender.BACKTIDE)


def test_backtide_strikes_a_key_it_never_swaps_in() -> None:
    policy = strict_policy(providers=Providers([waiting_anthropic()], strike_only=[STRUCK]))
    assert STRUCK not in policy.scrubber().text(f"echo {STRUCK}")


def strike_only_channel() -> FakeChannel:
    channel = FakeChannel()
    assert channel.config is not None
    ready = Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL))
    providers = Providers([ready], strike_only=[STRUCK])
    channel.config = channel.config.__class__(
        providers, KnownScrubber(providers.known_secrets()), channel.config.limits
    )
    return channel


def test_the_proxy_refuses_a_request_and_an_answer_with_a_key_it_never_swaps_in() -> None:
    from tests.test_gate_addon import provider_flow, stream_through

    channel = strike_only_channel()
    gate, _ = make_gate(channel)
    flow = model_flow(json.dumps({"model": "m", "messages": [STRUCK]}).encode())
    send(gate, flow)
    assert flow.response is not None and flow.response.status_code == 403
    assert channel.told[0]["details"]["reason"] == "real_key" and channel.asked == []
    assert STRUCK not in json.dumps(channel.told)

    channel = strike_only_channel()
    gate, _ = make_gate(channel)
    flow = provider_flow(("x-api-key", FAKE))
    send(gate, flow)
    body = json.dumps({"type": "error", "error": {"message": f"echo {STRUCK}"}}).encode()
    assert stream_through(gate, flow, body, "application/json") == b"" and flow.killed
    assert channel.actions() == ["blocked:real_key"]


# --- the proxy ----------------------------------------------------------------------------------


def waiting_channel() -> FakeChannel:
    channel = FakeChannel()
    assert channel.config is not None
    providers = Providers([waiting_anthropic()])
    channel.config = channel.config.__class__(
        providers, channel.config.scrubber, channel.config.limits
    )
    return channel


def test_the_proxy_answers_no_key_in_the_providers_shape_and_sends_nothing() -> None:
    channel = waiting_channel()
    channel.answer = Ack("deny", reason="no_key")
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body())
    flow.request.headers.fields = (
        (b"Host", b"api.anthropic.com"),
        (b"x-api-key", FAKE.encode()),
        (b"content-type", b"application/json"),
    )
    send(gate, flow)
    assert flow.response is not None
    status, body, _ = blocked_response("anthropic", "no_key", "anthropic")
    assert (flow.response.status_code, flow.response.content) == (status, body)
    assert [event["details"]["provider"] for event in channel.asked] == ["anthropic"]
    assert channel.told == []  # backtide records it (llm/blocked), not the proxy
    assert "backtide" not in flow.metadata  # no connection to the provider is let open


def test_an_allow_for_a_provider_without_its_key_still_sends_nothing() -> None:
    channel = waiting_channel()
    channel.answer = Ack("allow", seq=9)  # a bug of backtide's: the proxy fails closed
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body())
    flow.request.headers.fields = ((b"Host", b"api.anthropic.com"), (b"x-api-key", FAKE.encode()))
    send(gate, flow)
    assert flow.response is not None and flow.response.status_code == 400
    assert "backtide" not in flow.metadata
    [told] = channel.told
    assert (told["details"]["stage"], told["details"]["upstream"]) == ("not_sent", False)


def test_another_key_to_a_provider_without_its_key_is_still_a_foreign_credential() -> None:
    channel = waiting_channel()
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body())
    flow.request.headers.fields = ((b"Host", b"api.anthropic.com"), (b"x-api-key", b"sk-ant-x" * 4))
    send(gate, flow)
    assert flow.response is not None and flow.response.status_code == 403
    assert channel.asked == []
    assert channel.told[0]["details"]["reason"] == "foreign_credential"


# --- backtide's side of the channel ------------------------------------------------------------


@pytest.fixture
def opened(box: BlackBox) -> BlackBox:
    box.open()
    return box


def waiting_policy() -> Policy:
    return strict_policy(
        providers=Providers([waiting_anthropic()]),
        key_problems={"anthropic": ("missing", "no file yet")},
    )


def blocked(box: BlackBox) -> list[Any]:
    return [e for e in box.events() if (e.source, e.action) == ("llm", "blocked")]


def test_backtide_denies_no_key_and_records_it_rate_limited(
    opened: BlackBox, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1000.0]
    channel, proxy = make_channel(opened, policy=waiting_policy(), monotonic=lambda: now[0])
    for n in range(1, 6):
        channel.handle({"type": "request", "id": n, "event": llm_request(f"f{n}")})
        ack = proxy.receive_type("ack")
        assert (ack["verdict"], ack["reason"]) == ("deny", "no_key")
    [first] = blocked(opened)
    assert first.details == {"reason": "no_key", "provider": "anthropic", "problem": "missing",
                             "count": 1, "model": "m"}  # fmt: skip
    assert first.risk == 1 and first.target == "anthropic"
    assert [e for e in opened.events() if e.action == "request"] == []  # never let out
    now[0] += channel_module.NO_KEY_EVERY
    channel.handle({"type": "ping"})
    proxy.receive_type("pong")
    later = blocked(opened)
    assert len(later) == 2 and later[1].details["count"] == 4  # the four since the first
    channel.handle({"type": "request", "id": 9, "event": llm_request("f9")})
    proxy.receive_type("ack")
    channel.close("restart")  # a new key: a new channel; what was counted is recorded
    assert [e.details["count"] for e in blocked(opened)] == [1, 4, 1]


def test_a_provider_with_its_key_is_not_refused_for_want_of_one(opened: BlackBox) -> None:
    channel, proxy = make_channel(opened)  # the usual policy: anthropic has its key
    channel.handle({"type": "request", "id": 1, "event": llm_request("ok")})
    assert proxy.receive_type("ack")["verdict"] == "allow"
    assert blocked(opened) == []


def test_policy_says_which_wait_and_why() -> None:
    policy = strict_policy(
        providers=Providers([waiting_anthropic()]),
        key_problems={"anthropic": ("unusable", "mode 0644"), "gone": ("missing", "x")},
    )
    assert policy.waiting() == {"anthropic": "unusable"}  # only providers without a key
    assert policy.key_note("anthropic") == "mode 0644"
    assert strict_policy().waiting() == {}


# --- the transitions, as the Egress sees them --------------------------------------------------


class _Jail:
    config = type("C", (), {"uid": 1, "image": "x", "channel_dir": Path("/nowhere")})()


def egress_with(policy: Policy) -> tuple[Egress, list[tuple[str, dict[str, Any], int]], list[str]]:
    records: list[tuple[str, dict[str, Any], int]] = []
    alerts: list[str] = []

    def record(source: str, action: str, target: str = "", *, details: Any = None,
               risk: int = 0) -> None:  # fmt: skip
        records.append((action, details or {}, risk))

    egress = Egress(
        _Jail(),  # type: ignore[arg-type]
        agent_name="agent",
        policy=policy,
        record=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
        thread=False,
        connect=lambda *a: None,  # type: ignore[arg-type,return-value]
    )
    egress._hooks = EgressHooks(  # noqa: SLF001 - as start() does, without a container
        record=record,  # type: ignore[arg-type]
        alert=lambda level, title, body, event: alerts.append(title),
    )
    return egress, records, alerts


def ready_policy() -> Policy:
    ready = Provider("anthropic", Kind.ANTHROPIC, "api.anthropic.com", FAKE, Secret(REAL))
    return strict_policy(providers=Providers([ready]))


def test_waiting_ready_and_waiting_again_are_recorded_once_each(
    caplog: pytest.LogCaptureFixture,
) -> None:
    egress, records, alerts = egress_with(waiting_policy())
    egress._note_keys()  # noqa: SLF001 - what start() does first
    egress._note_keys()  # noqa: SLF001 - nothing changed: nothing more
    assert [(a, d) for a, d, _ in records] == [
        ("provider_waiting", {"provider": "anthropic", "problem": "missing"})
    ]
    assert egress.waiting() == {"anthropic": "missing"}
    assert egress.reload(ready_policy()) is False  # the proxy is down in this test
    assert ("provider_ready", {"provider": "anthropic"}, 0) in records
    assert egress.waiting() == {}
    unusable = strict_policy(
        providers=Providers([waiting_anthropic()]),
        key_problems={"anthropic": ("unusable", "real key file ... is open to others")},
    )
    egress.reload(unusable)
    egress.reload(unusable)
    waits = [(d, r) for a, d, r in records if a == "provider_waiting"]
    assert waits[-1] == ({"provider": "anthropic", "problem": "unusable"}, 2)
    assert len(waits) == 2  # missing at the start, unusable now: once each
    assert alerts == ["La clave de anthropic no se puede usar"]
    warned = [r.getMessage() for r in caplog.records if "cannot be used" in r.getMessage()]
    assert len(warned) == 1 and "open to others" in warned[0]
    assert all(REAL not in r.getMessage() for r in caplog.records)


def test_before_start_nothing_is_recorded_and_start_says_it() -> None:
    egress, records, _ = egress_with(waiting_policy())
    egress._hooks = None  # noqa: SLF001
    egress._note_keys()  # noqa: SLF001
    assert records == [] and egress.waiting() == {"anthropic": "missing"}


# --- what the owner sees: /estado and the panel ------------------------------------------------


def test_status_in_telegram_says_which_models_have_no_key(opened: BlackBox) -> None:
    actions = GuardianActions(Path("/state/control.sock"))
    actions.bind(
        BotGuardian(),  # type: ignore[arg-type]
        opened,
        FakeStore([]),  # type: ignore[arg-type]
        waiting=lambda: {"anthropic": "missing"},
    )
    assert (
        "Sin clave: anthropic. El agente no puede usar el modelo hasta que la pongas en Ajustes."
        in actions.status()
    )
    actions.bind(BotGuardian(), opened, FakeStore([]), waiting=dict)  # type: ignore[arg-type]
    assert "Sin clave" not in actions.status()


class _Budget:
    def status(self) -> dict[str, Any]:
        return {"available": True}


def test_the_control_socket_tells_the_panel_which_wait(folder: Path) -> None:
    server = ControlServer(
        FakeGuardian(),
        folder / "control.sock",
        peer=me,
        budget=_Budget(),  # type: ignore[arg-type]
        waiting=lambda: {"openai": "missing", "anthropic": "unusable"},
    )
    server.start()
    try:
        status = ask_budget(server.path, peer=me)
    finally:
        server.close()
    assert status["models_waiting"] == ["anthropic", "openai"]
