"""T11: the spending cap's book (backtide/service/spend.py): the gate before a model call, the
totals by day and month with an injected clock, the warnings, raising the cap, the restart (from
its file or rebuilt from the black box) and many threads at once."""

import json
import os
import stat
import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from backtide.blackbox import BlackBox
from backtide.notify import Alert, AlertLevel
from backtide.service.prices import Cost, price
from backtide.service.spend import (
    STATE_BUDGET,
    Budget,
    BudgetSettings,
    check_cap,
    status_lines,
)

KEY = bytes(range(32))
MADRID = ZoneInfo("Europe/Madrid")


class Clock:
    def __init__(self, moment: datetime) -> None:
        self.moment = moment
        self.mono = 1000.0

    def now(self) -> datetime:
        return self.moment

    def monotonic(self) -> float:
        return self.mono


@pytest.fixture
def box(tmp_path: Path) -> BlackBox:
    folder = tmp_path / "box"
    folder.mkdir()
    db = BlackBox(folder / "blackbox.db", KEY)
    db.open()
    yield db
    db.close()


def make(
    tmp_path: Path,
    box: BlackBox,
    clock: Clock,
    *,
    daily: str = "1",
    monthly: str = "10",
    inflight: int = 4,
    alerts: list[Alert] | None = None,
) -> Budget:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    settings = BudgetSettings(
        daily_usd=Decimal(daily),
        monthly_usd=Decimal(monthly),
        timezone=MADRID,
        timezone_name="Europe/Madrid",
        max_inflight=inflight,
        owner_prices={"fake-claude": price("100", "100", "10")},
    )
    budget = Budget(
        settings,
        state_dir=state,
        record=box.append,
        alert=(alerts.append if alerts is not None else None),
        history=box.events,
        now=clock.now,
        monotonic=clock.monotonic,
    )
    budget.open()
    return budget


def spend(budget: Budget, box: BlackBox, micro: int, flow: str = "f") -> None:
    """One call: admitted, answered, priced (here: a fixed cost), recorded, booked."""
    assert budget.admit(flow) is None
    budget.settle("anthropic", {"flow_id": flow})
    cost = Cost(micro, priced_by="owner")
    event = box.append("llm", "response", "", details={"flow_id": flow, "cost": cost.details()})
    budget.book_cost(cost, event)


def actions(box: BlackBox, source: str | None = None) -> list[str]:
    return [f"{e.source}/{e.action}" for e in box.events() if source in (None, e.source)]


def test_cap_check_is_before_the_call(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 21, 10, tzinfo=UTC))
    alerts: list[Alert] = []
    budget = make(tmp_path, box, clock, alerts=alerts)
    spend(budget, box, 600_000)  # 0.60 of 1.00
    assert budget.admit("a") is None
    budget.forget("a")
    spend(budget, box, 500_000)  # 1.10: over
    assert budget.blocked_window() == "day"
    assert budget.admit("b") == "spend_cap"
    assert budget.admit("c") == "spend_cap"
    names = actions(box, "system")
    assert names.count("system/budget_warning") == 2  # 50 and 80
    assert names.count("system/budget_exceeded") == 1
    assert actions(box, "llm").count("llm/blocked") == 1  # the second refusal waits its 10 s
    clock.mono += 11
    budget.flush_blocked()
    blocked = [e for e in box.events() if e.action == "blocked"]
    assert [e.details["count"] for e in blocked] == [1, 1]
    assert [a.level for a in alerts] == [AlertLevel.INFO, AlertLevel.ERROR]  # one alert a jump
    assert "hasta mañana" in alerts[-1].body


def test_warnings_once_per_window(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 21, 10, tzinfo=UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="1")
    for _ in range(10):
        spend(budget, box, 100_000)
    exceeded = [e for e in box.events() if e.action == "budget_exceeded"]
    assert [e.details["window"] for e in exceeded] == ["month"]
    assert budget.blocked_window() == "month"


def test_new_day_unblocks_and_only_forwards(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 21, 21, 30, tzinfo=UTC))  # 23:30 in Madrid
    budget = make(tmp_path, box, clock)
    spend(budget, box, 1_000_000)
    assert budget.admit("x") == "spend_cap"
    clock.moment = datetime(2026, 10, 21, 22, 1, tzinfo=UTC)  # 00:01 in Madrid: a new day
    assert budget.admit("y") is None
    assert "system/budget_unblocked" in actions(box)
    assert budget.status()["day"]["spent_micro"] == 0
    assert budget.status()["month"]["spent_micro"] == 1_000_000
    clock.moment = datetime(2026, 10, 21, 20, tzinfo=UTC)  # the clock goes back
    budget.forget("y")
    spend(budget, box, 100_000, "z")
    assert budget.status()["day"] == {
        "spent_micro": 100_000,
        "cap_micro": 1_000_000,
        "key": "2026-10-22",
    }


def test_new_month(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 31, 12, tzinfo=UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="1")
    spend(budget, box, 1_000_000)
    assert budget.admit("a") == "spend_cap"
    clock.moment = datetime(2026, 10, 31, 23, 30, tzinfo=UTC)  # November in Madrid
    assert budget.admit("b") is None
    assert budget.status()["month"]["key"] == "2026-11"


def test_raising_the_cap_lets_calls_through(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 21, 10, tzinfo=UTC))
    alerts: list[Alert] = []
    budget = make(tmp_path, box, clock, alerts=alerts)
    spend(budget, box, 1_000_000)
    assert budget.admit("a") == "spend_cap"
    low = budget.set_caps(Decimal("0.50"), None, requested_by="web (uid 1, pid 2)")
    assert low.ok and "siguen bloqueadas" in low.message
    out = budget.set_caps(Decimal("3"), None, requested_by="web (uid 1, pid 2)")
    assert out.ok
    assert budget.admit("b") is None
    events = box.events()
    names = [f"{e.source}/{e.action}" for e in events]
    assert names.index("settings/budget_set") < names.index("system/budget_unblocked")
    changed = [e for e in events if e.action == "budget_set"][-1]
    assert changed.details["daily_usd"] == "3.00" and changed.details["daily_was_usd"] == "0.50"
    assert alerts[-1].level is AlertLevel.INFO
    # The thresholds of the new cap can be crossed again: 50 % of 3 $ is 1.50 $.
    spend(budget, box, 600_000, "c")
    warnings = [e for e in box.events() if e.action == "budget_warning"]
    assert warnings[-1].details["cap_usd"] == "3.00"


def test_caps_set_from_the_web_survive_a_restart(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 21, 10, tzinfo=UTC))
    budget = make(tmp_path, box, clock)
    budget.set_caps(Decimal("7.5"), Decimal("70"), requested_by="web")
    spend(budget, box, 2_000_000)
    again = make(tmp_path, box, clock)
    status = again.status()
    assert status["day"]["cap_micro"] == 7_500_000 and status["month"]["cap_micro"] == 70_000_000
    assert status["day"]["spent_micro"] == 2_000_000
    assert status["caps_from"] == "web"
    path = tmp_path / "state" / STATE_BUDGET
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_restart_rebuilds_from_the_black_box(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="1000")
    spend(budget, box, 300_000, "a")
    spend(budget, box, 200_000, "b")
    (tmp_path / "state" / STATE_BUDGET).unlink()
    rebuilt = make(tmp_path, box, clock, daily="100", monthly="1000")
    assert rebuilt.status()["day"]["spent_micro"] == 500_000
    assert rebuilt.status()["month"]["spent_micro"] == 500_000
    assert "system/budget_rebuilt" in actions(box)


def test_broken_file_is_rebuilt_and_said(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock)
    spend(budget, box, 300_000)
    path = tmp_path / "state" / STATE_BUDGET
    path.write_text(json.dumps({"version": 1, "day": "x"}))
    again = make(tmp_path, box, clock)
    assert again.status()["day"]["spent_micro"] == 300_000
    rebuilt = [e for e in box.events() if e.action == "budget_rebuilt"]
    assert rebuilt[-1].details["why"] == "unreadable" and rebuilt[-1].risk == 1


def test_no_count_no_calls(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    alerts: list[Alert] = []

    def broken(**_: Any) -> list[Any]:
        raise OSError("disk")

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    budget = Budget(
        BudgetSettings(),
        state_dir=state,
        record=box.append,
        alert=alerts.append,
        history=broken,
        now=clock.now,
    )
    budget.open()
    assert budget.admit("a") == "spend_unavailable"
    assert alerts and alerts[0].level is AlertLevel.ERROR
    assert "system/budget_unavailable" in actions(box)
    assert status_lines(budget.status())[0].startswith("Gasto: no se puede contar")


def test_calls_in_flight_are_limited(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, inflight=2, daily="100", monthly="100")
    assert budget.admit("a") is None and budget.admit("b") is None
    assert budget.admit("c") == "throttled"
    budget.forget("a")
    assert budget.admit("c") is None
    clock.mono += 31 * 60  # a call never answered stops holding its place
    assert budget.admit("d") is None


def test_settle_uses_what_the_request_said(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100")
    assert budget.admit("f", model="nobody-knows", request_bytes=300, max_tokens=10) is None
    cost = budget.settle(
        "anthropic", {"flow_id": "f", "model": "nobody-knows", "usage_missing": True}
    )
    assert cost.estimated and cost.unknown_model
    assert cost.micro == 300 * 100 + 10 * 100  # the dearest is the owner's 100/100
    assert budget.status()["inflight"] == 0
    priced = budget.settle(
        "anthropic", {"flow_id": "g", "model": "fake-claude", "usage": {"input": 12, "output": 7}}
    )
    assert priced.micro == 1900 and priced.priced_by == "owner"


def test_many_threads_lose_nothing(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100000", monthly="100000", inflight=64)
    per_thread, threads = 50, 8

    def work(n: int) -> None:
        for i in range(per_thread):
            flow = f"t{n}-{i}"
            while budget.admit(flow) is not None:
                pass
            cost = budget.settle(
                "anthropic",
                {"flow_id": flow, "model": "fake-claude", "usage": {"input": 1, "output": 1}},
            )
            budget.book_cost(cost, None)

    workers = [threading.Thread(target=work, args=(n,)) for n in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert budget.status()["day"]["spent_micro"] == per_thread * threads * 200
    reread = make(tmp_path, box, clock, daily="100000", monthly="100000")
    assert reread.status()["month"]["spent_micro"] == per_thread * threads * 200


def test_cap_shapes() -> None:
    assert check_cap("5") == Decimal("5")
    assert check_cap("7,50") == Decimal("7.50")
    for bad in ("0", "-1", "1e3", "abc", "1.234", "", "100001", " ", "1.2.3", "nan"):
        assert check_cap(bad) is None, bad


def test_status_lines_say_the_prices_date(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime(2026, 10, 21, 10, tzinfo=UTC))
    budget = make(tmp_path, box, clock)
    spend(budget, box, 250_000)
    lines = budget.lines()
    assert lines[0] == "Gasto hoy: 0,25 $ de 1,00 $."
    assert lines[1] == "Gasto este mes: 0,25 $ de 10,00 $."
    assert "de fábrica del 2026-10-06" in lines[-1]
    budget.use_fetched({}, (clock.moment + timedelta(days=0)).date())
    assert budget.lines()[-1] == "Precios actualizados el 2026-10-21 (fuente: Anthropic)."


def test_an_error_without_usage_costs_nothing(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100")
    assert budget.admit("e", request_bytes=200_000, max_tokens=64_000) is None
    cost = budget.settle(
        "anthropic", {"flow_id": "e", "model": "fake-claude", "status": 529, "usage_missing": True}
    )
    assert (cost.micro, cost.estimated, cost.priced_by) == (0, False, "error")
    assert budget.status()["inflight"] == 0
    ok_but_missing = budget.settle(
        "anthropic", {"flow_id": "x", "model": "fake-claude", "status": 200, "usage_missing": True}
    )
    assert ok_but_missing.estimated and ok_but_missing.micro > 0
    with_usage = budget.settle(
        "anthropic",
        {
            "flow_id": "y",
            "model": "fake-claude",
            "status": 400,
            "usage": {"input": 10, "output": 0},
        },
    )
    assert with_usage.micro == 1000
