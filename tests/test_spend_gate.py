"""T11: the spending cap at the door. backtide's channel asks the budget before a model call goes
out and charges each answer (backtide/service/proxy_channel.py); the proxy answers a refused call
in the provider's own error shape (backtide/gate/providers.py, addon.py)."""

import json
from dataclasses import dataclass
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
from tests.test_gate_addon import (
    FakeChannel,
    FlowError,
    make_gate,
    model_flow,
    send,
    tool_body,
)
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


def llm_request(
    flow_id: str,
    *,
    path: str = "/v1/messages",
    method: str = "POST",
    endpoint: str | None = "messages",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    flow = {
        "flow_id": flow_id,
        "method": method,
        "scheme": "https",
        "host": "api.anthropic.com",
        "port": 443,
        "path": path,
        "headers": [],
        "body": json.dumps(body or {"model": "m", "max_tokens": 10, "messages": []}).encode(),
    }
    return record.llm_request_event(flow, "anthropic", (), endpoint=endpoint)


def llm_response(
    flow_id: str, usage: dict[str, int] | None, *, complete: bool = True
) -> dict[str, Any]:
    summary = LlmSummary(model="m", usage=dict(usage or {}), complete=complete)
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


def ask(
    channel: ProxyChannel, proxy: Proxy, request_id: int, flow_id: str, **request: Any
) -> dict[str, Any]:
    channel.handle({"type": "request", "id": request_id, "event": llm_request(flow_id, **request)})
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


def test_a_burst_overshoots_by_one_call_at_most(tmp_path: Path, box: BlackBox) -> None:
    """M5: each call in flight reserves its estimate, so a burst cannot all go out under the
    cap and land far past it: the second waits while the first may reach the cap alone."""
    budget = budget_for(tmp_path, box, max_inflight=3)
    channel, proxy = make_channel(box, budget=budget)
    acks = [ask(channel, proxy, n, f"b{n}") for n in range(1, 4)]
    assert [a["verdict"] for a in acks] == ["allow", "deny", "deny"]
    assert {a.get("reason") for a in acks[1:]} == {"throttled"}
    assert budget.status()["reserved_micro"] > 10_000  # one call may cost more than the cap
    channel.handle({"type": "event", "event": llm_response("b1", {"input": 40, "output": 40})})
    assert ask(channel, proxy, 4, "b4")["verdict"] == "allow"  # 8,000 spent, nothing reserved
    channel.handle({"type": "event", "event": llm_response("b4", {"input": 40, "output": 40})})
    assert budget.status()["day"]["spent_micro"] == 2 * 8000  # past 10,000 by one call
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


# --- after the security review of T11 (docs/33, "Tras la revisión de seguridad") ---------------


def costs(box: BlackBox) -> list[tuple[str, dict[str, Any]]]:
    return [
        (f"{e.source}/{e.action}", e.details["cost"])
        for e in box.events()
        if isinstance(e.details.get("cost"), dict)
    ]


def test_a1_an_answer_the_client_cut_short_is_charged_its_max_tokens(
    tmp_path: Path, box: BlackBox
) -> None:
    budget = budget_for(tmp_path, box, daily="100")
    channel, proxy = make_channel(box, budget=budget)
    assert ask(channel, proxy, 1, "cut")["verdict"] == "allow"
    # message_start's usage only: the client closed before message_delta.
    channel.handle(
        {"type": "event", "event": llm_response("cut", {"input": 12, "output": 1}, complete=False)}
    )
    [(name, cost)] = costs(box)
    assert name == "llm/response" and cost["estimated"] is True
    assert cost["usd_micro"] == 12 * 100 + 10 * 100  # max_tokens 10, not the 1 reported


@pytest.mark.parametrize(
    ("error", "charged"),
    [
        ({"stage": "flow", "upstream": True}, True),
        ({"stage": "flow"}, True),  # nothing said: it may have gone out
        ({"stage": "response_transfer_encoding", "upstream": True}, True),
        ({"stage": "not_sent", "upstream": False}, False),
        ({"stage": "flow", "upstream": False}, False),
    ],
)
def test_m1_a_call_that_ends_without_an_answer(
    tmp_path: Path, box: BlackBox, error: dict[str, Any], charged: bool
) -> None:
    budget = budget_for(tmp_path, box, daily="100", max_inflight=1)
    channel, proxy = make_channel(box, budget=budget)
    assert ask(channel, proxy, 1, "gone")["verdict"] == "allow"
    event = record.error_event(
        error["stage"],
        flow_id="gone",
        host="api.anthropic.com",
        port=443,
        secrets=(),
        upstream=error.get("upstream"),
    )
    channel.handle({"type": "event", "event": event})
    found = costs(box)
    if charged:
        [(name, cost)] = found
        size = len(json.dumps({"model": "m", "max_tokens": 10, "messages": []}))
        assert name == "system/budget_charged" and cost["estimated"] is True
        assert cost["usd_micro"] == size * 200 + 10 * 100  # bytes at the 1 h write, max_tokens
        [charge] = [e for e in box.events() if e.action == "budget_charged"]
        assert charge.details["seq"] == [e for e in box.events() if e.action == "error"][0].seq
    else:
        assert found == []
    assert budget.status()["day"]["spent_micro"] == (found[0][1]["usd_micro"] if charged else 0)
    assert ask(channel, proxy, 2, "next")["verdict"] == "allow"  # its place is free again


def test_m1_an_answer_the_proxy_stopped_is_charged_a_refused_request_is_not(
    tmp_path: Path, box: BlackBox
) -> None:
    budget = budget_for(tmp_path, box, daily="100")
    channel, proxy = make_channel(box, budget=budget)
    fields = {"flow_id": "k", "host": "api.anthropic.com", "port": 443}
    assert ask(channel, proxy, 1, "k")["verdict"] == "allow"
    key = record.blocked_event("real_key", fields, (), side="response")
    channel.handle({"type": "event", "event": key})
    assert [name for name, _ in costs(box)] == ["system/budget_charged"]
    assert ask(channel, proxy, 2, "r")["verdict"] == "allow"
    refused = record.blocked_event("not_recorded", fields | {"flow_id": "r"}, ())
    channel.handle({"type": "event", "event": refused})
    assert len(costs(box)) == 1 and budget.status()["inflight"] == 0


def test_m4_the_free_endpoints_cost_nothing(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box, daily="100", max_inflight=1)
    channel, proxy = make_channel(box, budget=budget)
    listing = {"path": "/v1/models", "method": "GET", "endpoint": "models", "body": {}}
    assert ask(channel, proxy, 1, "list", **listing)["verdict"] == "allow"
    assert ask(channel, proxy, 2, "busy")["reason"] == "throttled"  # it holds a place
    channel.handle({"type": "event", "event": llm_response("list", None)})
    counting = {"path": "/v1/messages/count_tokens", "endpoint": "count_tokens"}
    assert ask(channel, proxy, 3, "count", **counting)["verdict"] == "allow"
    channel.handle({"type": "event", "event": llm_response("count", None)})
    assert [cost["usd_micro"] for _, cost in costs(box)] == [0, 0]
    assert {cost["priced_by"] for _, cost in costs(box)} == {"free"}
    # The proxy's word alone is not enough: a model call said to be free is charged.
    lying = {"path": "/v1/messages", "endpoint": "count_tokens"}
    assert ask(channel, proxy, 4, "lie", **lying)["verdict"] == "allow"
    channel.handle({"type": "event", "event": llm_response("lie", None)})
    assert costs(box)[-1][1]["usd_micro"] > 0


def test_m3_the_request_says_what_the_cap_needs() -> None:
    body = {"model": "gpt-6-sol", "input": "hi", "max_output_tokens": 50, "n": 3,
            "previous_response_id": "resp_1", "service_tier": "priority"}  # fmt: skip
    event = llm_request("x", path="/v1/responses", endpoint="responses", body=body)
    details = event["details"]
    assert (details["endpoint"], details["choices"], details["context"]) == ("responses", 3, True)
    assert details["service_tier"] == "priority" and details["max_tokens"] == 50
    plain = llm_request("y")["details"]
    assert (plain["choices"], plain["context"], plain["service_tier"]) == (None, False, None)
    assert protocol.validate_event(event) == event


def test_b2_an_answer_that_cannot_be_priced_is_still_charged(
    tmp_path: Path, box: BlackBox, monkeypatch: pytest.MonkeyPatch
) -> None:
    budget = budget_for(tmp_path, box, daily="100")
    channel, proxy = make_channel(box, budget=budget)
    assert ask(channel, proxy, 1, "p")["verdict"] == "allow"

    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(budget, "settle", broken)
    channel.handle({"type": "event", "event": llm_response("p", {"input": 1, "output": 1})})
    [(name, cost)] = costs(box)
    assert name == "llm/response" and cost["estimated"] is True and cost["usd_micro"] > 0
    assert budget.status()["day"]["spent_micro"] == cost["usd_micro"]


# --- the proxy's side: what it says of a call that ends without an answer ----------------------


@dataclass
class _ServerConn:
    timestamp_start: float | None = None
    timestamp_tcp_setup: float | None = None


def test_m1_the_proxy_says_whether_a_call_reached_the_provider() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body())
    send(gate, flow)
    assert "backtide" in flow.metadata  # let through
    flow.server_conn = _ServerConn()  # type: ignore[attr-defined]
    gate.error(flow)
    assert channel.told[-1]["details"]["upstream"] is False
    connected = model_flow(tool_body())
    connected.id = "flow-2"
    send(gate, connected)
    connected.server_conn = _ServerConn(1.0, 1.1)  # type: ignore[attr-defined]
    gate.error(connected)
    assert channel.told[-1]["details"]["upstream"] is True
    unknown = model_flow(tool_body())
    unknown.id = "flow-3"
    send(gate, unknown)  # the fakes have no server_conn: it may have gone out
    gate.error(unknown)
    assert channel.told[-1]["details"]["upstream"] is True
    request = channel.asked[-1]["details"]
    assert request["endpoint"] == "messages"


def test_m1_a_call_whose_client_left_while_backtide_answered_never_goes_out() -> None:
    channel = FakeChannel()
    gate, _ = make_gate(channel)
    flow = model_flow(tool_body())
    flow.error = FlowError("Client disconnected.")
    send(gate, flow)
    assert flow.killed and "backtide" not in flow.metadata
    [told] = channel.told
    assert (told["action"], told["details"]["stage"], told["details"]["upstream"]) == (
        "error",
        "not_sent",
        False,
    )
    assert told["details"]["flow_id"] == flow.id
