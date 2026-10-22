# ruff: noqa: F811 - pytest fixtures imported from the tests they come from
"""T11: the spending cap on the control socket (``budget``, ``set_budget``) and in ``/estado``.

A real server over a real Unix socket, with ``SO_PEERCRED`` played by a fake ``peer`` (as in
tests/test_service_control_settings.py), on a real budget and a real black box."""

from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.service.bot import GuardianActions
from backtide.service.control import ControlServer, ask_budget, ask_set_budget
from backtide.service.spend import Budget, BudgetSettings
from tests.test_service_bot import FakeGuardian as BotGuardian
from tests.test_service_bot import FakeStore
from tests.test_service_control import FakeGuardian, me
from tests.test_service_control_settings import box, folder, talk  # noqa: F401 - fixtures


@pytest.fixture
def budget(folder: Path, box: BlackBox) -> Budget:
    box.open()
    made = Budget(
        BudgetSettings(daily_usd=Decimal("1")),
        state_dir=folder,
        record=box.append,
        history=box.events,
        now=lambda: datetime(2026, 10, 21, 12, tzinfo=UTC),
    )
    made.open()
    return made


@pytest.fixture
def server(folder: Path, budget: Budget) -> Iterator[ControlServer]:
    made = ControlServer(FakeGuardian(), folder / "control.sock", peer=me, budget=budget)
    made.start()
    yield made
    made.close()


def test_the_spending_can_be_read(server: ControlServer) -> None:
    status = ask_budget(server.path, peer=me)
    assert status["day"]["cap_micro"] == 1_000_000 and status["available"] is True
    assert status["prices"]["source"] == "defaults"


def test_a_new_cap_is_recorded_and_used(
    server: ControlServer, budget: Budget, box: BlackBox
) -> None:
    reply = ask_set_budget(server.path, daily_usd="2,50", monthly_usd=None, via="web", peer=me)
    assert reply == {
        "ok": True,
        "outcome": "saved",
        "message": "Guardado. Se aplica a la siguiente llamada al modelo.",
    }
    assert budget.status()["day"]["cap_micro"] == 2_500_000
    [event] = [e for e in box.events() if e.action == "budget_set"]
    assert event.source == "settings" and event.details["requested_by"].startswith("web (uid ")


@pytest.mark.parametrize("value", ["0", "-3", "1e9", "lots", "1.999"])
def test_a_cap_that_does_not_fit_changes_nothing(
    server: ControlServer, budget: Budget, value: str
) -> None:
    reply = ask_set_budget(server.path, daily_usd=value, monthly_usd=None, peer=me)
    assert (reply["ok"], reply["outcome"]) == (False, "invalid")
    assert budget.status()["day"]["cap_micro"] == 1_000_000


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "budget", "extra": 1},
        {"cmd": "set_budget", "daily_usd": "3", "via": "telegram"},
        {"cmd": "set_budget", "daily_usd": "3", "whatever": "x"},
        {"cmd": "set_budget", "daily_usd": 3},
    ],
)
def test_odd_requests_are_refused(
    server: ControlServer, budget: Budget, request_: dict[str, Any]
) -> None:
    _, reply = talk(server, request_)
    assert reply["ok"] is False
    assert budget.status()["day"]["cap_micro"] == 1_000_000


def test_without_a_budget_the_commands_are_refused(folder: Path) -> None:
    made = ControlServer(FakeGuardian(), folder / "c2.sock", peer=me)
    made.start()
    try:
        _, reply = talk(made, {"cmd": "budget"})
        assert reply["outcome"] == "refused"
    finally:
        made.close()


def test_status_in_telegram_says_the_spending(budget: Budget, box: BlackBox) -> None:
    actions = GuardianActions(Path("/state/control.sock"), tz=UTC)
    actions.bind(BotGuardian(), box, FakeStore([]), budget=budget)  # type: ignore[arg-type]
    text = actions.status()
    assert "Gasto hoy: 0,00 $ de 1,00 $." in text
    assert "Gasto este mes: 0,00 $ de 50,00 $." in text
    assert "Precios de fábrica del 2026-10-06." in text


def test_b3_new_prices_are_accepted_through_the_socket(
    folder: Path, budget: Budget, box: BlackBox, server: ControlServer
) -> None:
    from backtide.service.control import ask_accept_prices
    from backtide.service.price_update import PriceUpdater
    from tests.test_spend_price_update import PAGE

    updater = PriceUpdater(
        budget, state_dir=folder, record=box.append, fetch=lambda _: PAGE,
        url="http://127.0.0.1:1/pricing.md", now=lambda: datetime(2026, 10, 21, tzinfo=UTC),
    )  # fmt: skip
    assert updater.run_once()
    status = ask_budget(server.path, peer=me)
    digest = status["prices"]["pending_digest"]
    assert {row["model"] for row in status["prices"]["pending"]} == {
        "claude-opus-4-1",
        "claude-haiku-3",
    }
    stale = ask_accept_prices(server.path, digest="f" * 16, via="web", peer=me)
    assert stale["ok"] is False and stale["outcome"] == "invalid"
    done = ask_accept_prices(server.path, digest=digest, via="web", peer=me)
    assert done["ok"] is True and done["outcome"] == "saved"
    assert budget.book.lookup("claude-opus-4-1")[1] == "anthropic"
    [accepted] = [e for e in box.events() if e.action == "prices_accepted"]
    assert accepted.details["requested_by"].startswith("web (uid")
    with pytest.raises(ValueError):
        ask_accept_prices(server.path, digest=digest, via="telegram", peer=me)
