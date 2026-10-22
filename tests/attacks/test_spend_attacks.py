"""Evil-agent scenario of the spending cap (T11, docs/33-diseno-t11-tope-de-gasto.md).

The lab is test_proxy_attacks.py's: the real `backtide vigilar`, the real OpenClaw with its proxy
and T06's fake internet, where ``anthropic.fake.test`` answers every model call with a small usage
(12 tokens in, 7 out). ``[budget]`` gives the fake model a price (500 $/MTok: 0.0095 $ a call), a
daily cap of 5 cents, and points the price update at a fake pricing page that this test serves on
the VM's 127.0.0.1. Nothing reaches Anthropic, its pricing page or Telegram (invariant 8).

- ``tope-de-gasto``: the agent calls the model in a loop (streamed and not). The calls go out
  until the cap is crossed (the sixth, already in flight, finishes), then every one is refused in
  Anthropic's own error shape, without figures, and none of them reaches the provider; the 50, 80
  and 100 % warnings are recorded once each and alerted; the refusals are recorded
  (``llm/blocked``, risk 2). Raising the cap through the control socket (as the web's Settings
  page does) lets calls through again at once. The price table took the fake page's change.
"""

import http.server
import threading
from collections.abc import Iterator
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_proxy_attacks import Lab, start_lab

from backtide.service.control import ask_budget, ask_set_budget
from tests.integration.internet_kit import (
    ANTHROPIC,
    ANTHROPIC_HOST,
    ANTHROPIC_MODEL,
    stop_with_internet,
)
from tests.integration.service_kit import wait_until

PRICE = 500  # $/MTok for the fake model, in and out: 19 tokens = 9,500 µ$ a call
CAP_USD = "0.05"  # 50,000 µ$: five calls stay under, the sixth crosses it
PAGE = """# Pricing

| Model | Base Input Tokens | 5m Cache Writes | 1h Cache Writes | Cache Hits & Refreshes | Output Tokens |
|---|---|---|---|---|---|
| Claude Opus 5.5 | $3 / MTok | $3.75 / MTok | $6 / MTok | $0.20 / MTok | $20 / MTok |
| Claude Sonnet 5.5 | $2 / MTok | $2.50 / MTok | $4 / MTok | $0.20 / MTok | $10 / MTok |
"""  # noqa: E501


class _Page(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        type(self).hits += 1
        body = PAGE.encode()
        self.send_response(200 if self.path == "/pricing.md" else 404)
        self.send_header("content-type", "text/markdown")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def page() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Page)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/pricing.md"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def lab(
    canary_environment: dict[str, str],
    btrfs_volume,  # noqa: ANN001 - the shared btrfs volume of the VM fixtures
    tmp_path_factory: pytest.TempPathFactory,
    page: str,
) -> Iterator[Lab]:
    budget = (
        f'daily_usd = "{CAP_USD}"\nmonthly_usd = 100\nmax_inflight = 2\nauto_prices = true\n'
        f'prices_url = "{page}"\n'
        f'[budget.prices."{ANTHROPIC_MODEL}"]\ninput = {PRICE}\noutput = {PRICE}\n'
    )
    started = start_lab(btrfs_volume, tmp_path_factory, unknown_hosts="deny", budget_toml=budget)
    try:
        yield started
    finally:
        stop_with_internet(started.service, started.internet)


def loop(attack: Attack, lab: Lab, calls: int) -> list[dict[str, Any]]:
    fake = lab.fake[ANTHROPIC]
    outcome = attack.run_script(
        lab.agent, "tope_de_gasto", ANTHROPIC_HOST, fake, ANTHROPIC_MODEL, str(calls)
    )
    return outcome["calls"]


def model_calls(lab: Lab) -> int:
    return len(lab.internet.requests(ANTHROPIC_HOST, "/v1/messages"))


@scenario("tope-de-gasto")
def test_a_loop_that_spends_is_cut_at_the_cap(attack: Attack, lab: Lab) -> None:
    service = lab.service
    socket = service.config.control_socket
    # The price page was read at start (the fake one): Opus 5.5 at 3 $ instead of 4.
    wait_until(
        lambda: service.events("prices_updated"),
        30,
        "the price update from the fake page",
        context=service.diagnosis,
    )
    status = ask_budget(socket)
    assert status["prices"]["updated_on"] and status["day"]["spent_micro"] == 0
    before_calls, before = model_calls(lab), lab.head()

    calls = loop(attack, lab, 12)
    statuses = [c["status"] for c in calls]
    went_out = model_calls(lab) - before_calls
    refused = calls[6:]
    shapes_ok = all(
        c["status"] == 429
        and c["type"] == "rate_limit_error"
        and "tope de gasto" in c["message"]
        and not any(ch.isdigit() for ch in c["message"])
        and c["retry_after"] is None
        for c in refused
    )
    spent = ask_budget(socket)["day"]["spent_micro"]
    attack.check(
        "stopped",
        statuses[:6] == [200] * 6 and shapes_ok and went_out == 6 and spent == 6 * 9500,
        f"estados {statuses}; al proveedor llegaron {went_out}; gastado {spent} µ$ "
        f"(tope {CAP_USD} $)",
    )

    events = lab.since(before)
    warnings = sorted(
        (e.details["window"], e.details["pct"], e.risk)
        for e in events
        if e.action in ("budget_warning", "budget_exceeded")
    )
    blocked = [e for e in events if (e.source, e.action) == ("llm", "blocked")]
    costs = [e.details.get("cost", {}).get("usd_micro") for e in events if e.action == "response"]
    log = service.log_text()
    alerted = "Tope de gasto de hoy alcanzado" in log and "El agente lleva el 80 %" in log
    attack.check(
        "recorded",
        warnings == [("day", 50, 0), ("day", 80, 1), ("day", 100, 2)]
        and blocked
        and costs == [9500] * 6
        and alerted,
        f"avisos {warnings}; llm/blocked {len(blocked)}; costes {costs}; avisos en el registro "
        f"{alerted}",
    )
    attack.check(
        "risk",
        {e.risk for e in blocked} == {2},
        f"llm/blocked con riesgo {sorted({e.risk for e in blocked})}",
    )

    # Raising the cap (the web's Settings page asks the same) lets calls through at once.
    reply = ask_set_budget(socket, daily_usd="1", monthly_usd=None)
    assert reply["ok"], reply
    again = loop(attack, lab, 2)
    assert [c["status"] for c in again] == [200, 200], again
    assert model_calls(lab) - before_calls == 8
    wait_until(lambda: service.events("budget_unblocked"), 10, "budget_unblocked")
    assert [e for e in service.events("budget_set") if e.source == "settings"]
