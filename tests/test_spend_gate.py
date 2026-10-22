"""T11: the spending cap at the door. backtide's channel asks the budget before a model call goes
out and charges each answer (backtide/service/proxy_channel.py); the proxy answers a refused call
in the provider's own error shape (backtide/gate/providers.py, addon.py)."""

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.gate import protocol, record
from backtide.gate.client import Ack
from backtide.gate.providers import SPEND_MESSAGES, blocked_response
from backtide.gate.sse import LlmSummary
from backtide.service.prices import price
from backtide.service.proxy_channel import ProxyChannel
from backtide.service.spend import Budget, BudgetSettings
from tests.test_gate_addon import FakeChannel, make_gate, model_flow, send, tool_body
from tests.test_service_proxy_channel import Proxy, make_channel

KEY = b"k" * 32


@pytest.mark.parametrize("kind", ["anthropic", "openai"])
def test_the_refusal_is_the_providers_own_error(kind: str) -> None:
    status, body, headers = blocked_response(kind, "spend_cap")
    data = json.loads(body)
    assert status == 429
    assert "retry-after" not in {name.lower() for name in headers}
    if kind == "anthropic":
        assert data == {
            "type": "error",
            "error": {"type": "rate_limit_error", "message": SPEND_MESSAGES["spend_cap"]},
        }
    else:
        assert data["error"]["type"] == data["error"]["code"] == "insufficient_quota"
    assert not any(ch.isdigit() for ch in data["error"]["message"])  # no figures for the agent
    unavailable = blocked_response(kind, "spend_unavailable")
    assert unavailable[0] == 503
    with pytest.raises(ValueError):
        blocked_response(kind, "not_allowed")


@pytest.mark.parametrize("reason", ["spend_cap", "spend_unavailable"])
def test_the_proxy_answers_a_refused_model_call_without_sending_it(reason: str) -> None:
    channel = FakeChannel()
    channel.answer = Ack("deny", reason=reason)
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body())
    send(gate, flow)
    assert flow.response is not None
    status, body, _ = blocked_response("anthropic", reason)
    assert (flow.response.status_code, flow.response.content) == (status, body)
    assert channel.told == []  # backtide records it, not the proxy
    assert "backtide" not in flow.metadata  # no connection is let through


def test_the_ack_carries_the_spend_reasons() -> None:
    for reason in ("spend_cap", "spend_unavailable"):
        message = protocol.ack(3, "deny", reason=reason)
        assert (
            protocol.decode(
                protocol.encode(message, protocol.Sender.BACKTIDE), protocol.Sender.BACKTIDE
            )["reason"]
            == reason
        )


# --- backtide's side ---------------------------------------------------------------------------


@pytest.fixture
def box(tmp_path: Path) -> BlackBox:
    with BlackBox(tmp_path / "bb.db", KEY, checkpoint_path=tmp_path / "bb.checkpoint") as opened:
        yield opened


def budget_for(tmp_path: Path, box: BlackBox, daily: str = "0.01", **kw: Any) -> Budget:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    settings = BudgetSettings(
        daily_usd=Decimal(daily),
        monthly_usd=Decimal("100"),
        owner_prices={"m": price("100", "100", "10")},
        **kw,
    )
    budget = Budget(
        settings,
        state_dir=state,
        record=box.append,
        history=box.events,
        now=lambda: datetime(2026, 10, 21, 12, tzinfo=UTC),
    )
    budget.open()
    return budget


def llm_request(flow_id: str) -> dict[str, Any]:
    flow = {
        "flow_id": flow_id,
        "method": "POST",
        "scheme": "https",
        "host": "api.anthropic.com",
        "port": 443,
        "path": "/v1/messages",
        "headers": [],
        "body": json.dumps({"model": "m", "max_tokens": 10, "messages": []}).encode(),
    }
    return record.llm_request_event(flow, "anthropic", ())


def llm_response(flow_id: str, usage: dict[str, int] | None) -> dict[str, Any]:
    summary = LlmSummary(model="m", usage=dict(usage or {}), complete=True)
    flow = {
        "flow_id": flow_id,
        "scheme": "https",
        "host": "api.anthropic.com",
        "port": 443,
        "path": "/v1/messages",
    }
    return record.llm_response_event(
        flow, "anthropic", {"status": 200, "size": 10, "duration_ms": 5}, summary, ()
    )


def ask(channel: ProxyChannel, proxy: Proxy, request_id: int, flow_id: str) -> dict[str, Any]:
    channel.handle({"type": "request", "id": request_id, "event": llm_request(flow_id)})
    return proxy.receive_type("ack")


def test_over_the_cap_nothing_more_goes_out(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box)  # 0.01 $ = 10,000 µ$; a call costs 19 tokens x 100
    channel, proxy = make_channel(box, budget=budget)
    allowed = 0
    for n in range(1, 20):
        ack = ask(channel, proxy, n, f"f{n}")
        if ack["verdict"] != "allow":
            assert ack["reason"] == "spend_cap" and "retry_after" not in ack
            break
        allowed += 1
        channel.handle(
            {"type": "event", "event": llm_response(f"f{n}", {"input": 12, "output": 7})}
        )
    assert allowed == 6  # 6 x 1900 = 11,400 µ$: the sixth crossed it, the seventh is refused
    responses = [e for e in box.events() if e.action == "response"]
    assert [e.details["cost"]["usd_micro"] for e in responses] == [1900] * 6
    assert budget.status()["day"]["spent_micro"] == 11_400
    assert "llm/blocked" in [f"{e.source}/{e.action}" for e in box.events()]
    assert len([e for e in box.events() if e.action == "request"]) == 6  # the refused one: none


def test_a_burst_overshoots_by_the_calls_in_flight_only(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box, max_inflight=3)
    channel, proxy = make_channel(box, budget=budget)
    acks = [ask(channel, proxy, n, f"b{n}") for n in range(1, 6)]
    assert [a["verdict"] for a in acks] == ["allow"] * 3 + ["deny"] * 2
    assert {a.get("reason") for a in acks[3:]} == {"throttled"}
    for n in range(1, 4):  # the three in flight finish and are all charged
        channel.handle(
            {"type": "event", "event": llm_response(f"b{n}", {"input": 40, "output": 40})}
        )
    assert budget.status()["day"]["spent_micro"] == 3 * 8000  # past 10,000 by what was in flight
    assert ask(channel, proxy, 9, "late")["reason"] == "spend_cap"


def test_an_answer_without_usage_is_charged_by_excess(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box, daily="100")
    channel, proxy = make_channel(box, budget=budget)
    assert ask(channel, proxy, 1, "u1")["verdict"] == "allow"
    channel.handle({"type": "event", "event": llm_response("u1", None)})
    [response] = [e for e in box.events() if e.action == "response"]
    cost = response.details["cost"]
    assert cost["estimated"] is True and cost["priced_by"] == "estimate"
    size = len(json.dumps({"model": "m", "max_tokens": 10, "messages": []}))
    assert cost["usd_micro"] >= size * 100 + 10 * 100  # request size and max_tokens, dearest


def test_an_error_frees_the_place_in_flight(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box, daily="100", max_inflight=1)
    channel, proxy = make_channel(box, budget=budget)
    assert ask(channel, proxy, 1, "e1")["verdict"] == "allow"
    assert ask(channel, proxy, 2, "e2")["reason"] == "throttled"
    error = record.error_event("flow", flow_id="e1", host="api.anthropic.com", port=443, secrets=())
    channel.handle({"type": "event", "event": error})
    assert ask(channel, proxy, 3, "e3")["verdict"] == "allow"


def test_without_a_count_model_calls_are_refused(tmp_path: Path, box: BlackBox) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)

    def broken(**_: Any) -> list[Any]:
        raise OSError("disk")

    budget = Budget(BudgetSettings(), state_dir=state, record=box.append, history=broken)
    budget.open()
    channel, proxy = make_channel(box, budget=budget)
    assert ask(channel, proxy, 1, "x")["reason"] == "spend_unavailable"
