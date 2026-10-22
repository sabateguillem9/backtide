"""Evil-agent scenario of the spending cap's security review (T11, docs/33, "Tras la revisión de
seguridad"): an agent that tries to spend without being charged.

The lab is test_proxy_attacks.py's (the real `backtide vigilar`, the real OpenClaw jail with its
proxy and T06's fake internet). ``[budget]`` prices the fake model at 500 $/MTok in and out
(1000 $/MTok for a 1 h cache write: twice the input) with a daily cap of 1 $, and the prices do
not update themselves. Nothing reaches Anthropic or any real service (invariant 8).

- ``evadir-el-tope``: (A1) the agent streams a call with ``max_tokens`` 1000 and hangs up right
  after the last ``content_block_stop``, before ``message_delta`` brings the real output usage:
  the proxy only saw message_start's (output 1), and the call is charged its whole max_tokens
  (12 x 500 + 1000 x 500 = 506,000 µ$), marked estimated. (M1) It sends a call whose answer is
  slow to start and hangs up before the status line: the provider got it, so it is charged its
  estimate (its bytes at the 1 h cache write plus its max_tokens), ``system/budget_charged``.
  Together they pass the cap, and the next call is refused in Anthropic's own shape without
  reaching the provider.
  (include_usage, docs/33) Before those, a streamed call to the OpenAI-shaped provider without
  ``stream_options``: the proxy asks for its usage and drops the extra chunk; the agent hangs up
  right after the usage chunk reached the proxy, before ``[DONE]``. The usage came but the answer
  did not end, so it costs its estimate from before the rewrite (its bytes at the 1 h cache
  write plus its max_tokens), never the little its usage says; the agent never saw the chunk.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_proxy_attacks import Lab, start_lab

from backtide.service.control import ask_budget
from tests.integration.internet_kit import (
    ANTHROPIC,
    ANTHROPIC_HOST,
    ANTHROPIC_MODEL,
    OPENAI,
    OPENAI_HOST,
    OPENAI_MODEL,
    stop_with_internet,
)
from tests.integration.service_kit import wait_until

PRICE = 500  # $/MTok for the fake model, in and out
MAX_TOKENS = 1000  # what the script asks for
CAP_USD = "1"  # 1,000,000 µ$: the two evasions together pass it
OPENAI_PRICE = 1  # $/MTok for the fake OpenAI model: its evasion stays far under the cap


@pytest.fixture(scope="module")
def lab(
    canary_environment: dict[str, str],
    btrfs_volume,  # noqa: ANN001 - the shared btrfs volume of the VM fixtures
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    budget = (
        f'daily_usd = "{CAP_USD}"\nmonthly_usd = 100\nmax_inflight = 4\nauto_prices = false\n'
        f'[budget.prices."{ANTHROPIC_MODEL}"]\ninput = {PRICE}\noutput = {PRICE}\n'
        f'[budget.prices."{OPENAI_MODEL}"]\ninput = {OPENAI_PRICE}\noutput = {OPENAI_PRICE}\n'
    )
    started = start_lab(btrfs_volume, tmp_path_factory, unknown_hosts="deny", budget_toml=budget)
    try:
        yield started
    finally:
        stop_with_internet(started.service, started.internet)


def run(attack: Attack, lab: Lab, mode: str) -> dict[str, Any]:
    return attack.run_script(
        lab.agent, "evadir_el_tope", ANTHROPIC_HOST, lab.fake[ANTHROPIC], ANTHROPIC_MODEL, mode
    )


def model_calls(lab: Lab) -> int:
    return len(lab.internet.requests(ANTHROPIC_HOST, "/v1/messages"))


def last_request(lab: Lab, since: int) -> Any:
    requests = [e for e in lab.since(since) if (e.source, e.action) == ("llm", "request")]
    assert requests, "the call was not recorded"
    return requests[-1]


def costs_of(lab: Lab, flow_id: str, since: int) -> list[tuple[str, dict[str, Any]]]:
    return [
        (f"{e.source}/{e.action}", e.details["cost"])
        for e in lab.since(since)
        if e.details.get("flow_id") == flow_id and isinstance(e.details.get("cost"), dict)
    ]


@scenario("evadir-el-tope")
def test_hanging_up_on_the_model_does_not_make_it_free(attack: Attack, lab: Lab) -> None:
    service = lab.service
    socket = service.config.control_socket
    assert ask_budget(socket)["day"]["spent_micro"] == 0

    # include_usage: the usage chunk the proxy asked for came, [DONE] did not.
    first = lab.head()
    usage_cut = attack.run_script(
        lab.agent, "evadir_el_tope", OPENAI_HOST, lab.fake[OPENAI], OPENAI_MODEL, "usage_cut"
    )
    request0 = last_request(lab, first)
    flow0 = request0.details["flow_id"]
    wait_until(
        lambda: costs_of(lab, flow0, first),
        20,
        "the cost of the stream cut after its usage",
        context=service.diagnosis,
    )
    [(name0, cost0)] = costs_of(lab, flow0, first)
    response0 = next(e for e in lab.since(first) if e.details.get("flow_id") == flow0
                     and e.action == "response")  # fmt: skip
    u_expected = request0.details["body"]["size"] * 2 * OPENAI_PRICE + MAX_TOKENS * OPENAI_PRICE
    u_ok = (
        usage_cut.get("status") == 200
        and usage_cut.get("finished") is True
        and usage_cut.get("usage_chunk_seen") is False
        and usage_cut.get("done") is False
        and request0.details.get("include_usage") == "added"
        and name0 == "llm/response"
        and response0.details.get("usage") == {"input": 12, "output": 7}
        and response0.details.get("complete") is False
        and cost0["usd_micro"] == u_expected
        and cost0["estimated"] is True
    )

    before = lab.head()
    calls_before = model_calls(lab)

    # A1: the stream is cut after its text, before the usage that ends it.
    cut = run(attack, lab, "cut")
    request = last_request(lab, before)
    flow = request.details["flow_id"]
    wait_until(
        lambda: costs_of(lab, flow, before),
        20,
        "the cost of the cut stream",
        context=service.diagnosis,
    )
    [(name, cost)] = costs_of(lab, flow, before)
    response = next(e for e in lab.since(before) if e.details.get("flow_id") == flow
                    and e.action == "response")  # fmt: skip
    a1_expected = 12 * PRICE + MAX_TOKENS * PRICE
    a1_ok = (
        cut.get("events", [])[-1:] == ["content_block_stop"]
        and "message_delta" not in cut.get("events", [])
        and name == "llm/response"
        and response.details.get("complete") is False
        and cost["usd_micro"] == a1_expected
        and cost["estimated"] is True
    )

    # M1: the agent hangs up before the answer's status line.
    middle = lab.head()
    hung = run(attack, lab, "hangup")
    request2 = last_request(lab, middle)
    flow2 = request2.details["flow_id"]
    wait_until(
        lambda: costs_of(lab, flow2, middle),
        30,
        "the charge of the call hung up on",
        context=service.diagnosis,
    )
    [(name2, cost2)] = costs_of(lab, flow2, middle)
    m1_expected = request2.details["body"]["size"] * 2 * PRICE + MAX_TOKENS * PRICE
    m1_ok = (
        hung.get("hung_up") is True
        and name2 == "system/budget_charged"
        and cost2["usd_micro"] == m1_expected
        and cost2["estimated"] is True
    )
    spent = ask_budget(socket)["day"]["spent_micro"]

    # The cap still stops the next call, before the provider.
    at_cap = model_calls(lab)
    after = run(attack, lab, "plain")
    refused = (
        after.get("status") == 429
        and after.get("type") == "rate_limit_error"
        and "tope de gasto" in str(after.get("message"))
        and model_calls(lab) == at_cap
    )
    attack.check(
        "stopped",
        u_ok and a1_ok and m1_ok and spent == u_expected + a1_expected + m1_expected and refused,
        f"cortado tras el uso: {usage_cut} -> {name0} {cost0} {response0.details.get('usage')} "
        f"(esperado {u_expected} µ$); "
        f"cortado: {cut} -> {name} {cost} (esperado {a1_expected} µ$); colgado: {hung} -> "
        f"{name2} {cost2} (esperado {m1_expected} µ$); gastado {spent} µ$; después: {after}; "
        f"llamadas al proveedor {model_calls(lab) - calls_before}",
    )
    events = lab.since(before)
    charged = [e for e in events if e.action == "budget_charged"]
    blocked = [e for e in events if (e.source, e.action) == ("llm", "blocked")]
    exceeded = [e for e in events if e.action == "budget_exceeded"]
    attack.check(
        "recorded",
        len(charged) == 1 and charged[0].risk == 1 and blocked and exceeded,
        f"budget_charged {[(e.details, e.risk) for e in charged]}; llm/blocked {len(blocked)}; "
        f"budget_exceeded {len(exceeded)}",
    )
    attack.check(
        "risk",
        {e.risk for e in blocked} == {2},
        f"llm/blocked con riesgo {sorted({e.risk for e in blocked})}",
    )
