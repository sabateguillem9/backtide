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
    budget.forget("b")  # its reservation (M5) would hold the next one back
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
    clock.mono += 31 * 60  # B5: a call in flight keeps its place until it closes...
    assert budget.admit("d") == "throttled"
    clock.mono += 2 * 3600  # ...or its long safety TTL fires, which charges it
    assert budget.admit("d") is None
    charged = [e for e in box.events() if e.action == "budget_charged"]
    assert sorted(e.details["why"] for e in charged) == ["timeout", "timeout"]
    assert all(e.details["cost"]["estimated"] for e in charged)
    assert budget.status()["day"]["spent_micro"] == sum(
        e.details["cost"]["usd_micro"] for e in charged
    )


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
        "anthropic",
        {
            "flow_id": "g",
            "model": "fake-claude",
            "status": 200,
            "complete": True,
            "usage": {"input": 12, "output": 7},
        },
    )
    assert priced.micro == 1900 and priced.priced_by == "owner" and not priced.estimated


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
                {
                    "flow_id": flow,
                    "model": "fake-claude",
                    "complete": True,
                    "usage": {"input": 1, "output": 1},
                },
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


# --- after the security review of T11 (docs/33, "Tras la revisión de seguridad") ---------------


def answer(flow: str, **extra: Any) -> dict[str, Any]:
    return {"flow_id": flow, "model": "fake-claude", "status": 200} | extra


def test_a1_a_2xx_that_did_not_end_is_charged_its_max_tokens(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100")
    for flow, complete in (("a", False), ("b", None)):
        assert budget.admit(flow, model="fake-claude", request_bytes=50, max_tokens=1000) is None
        extra = {} if complete is None else {"complete": complete}
        cut = budget.settle("anthropic", answer(flow, usage={"input": 12, "output": 1}, **extra))
        assert cut.estimated and cut.micro == 12 * 100 + 1000 * 100, flow
    assert budget.admit("c", model="fake-claude", max_tokens=1000) is None
    whole = budget.settle("anthropic", answer("c", complete=True, usage={"input": 12, "output": 1}))
    assert not whole.estimated and whole.micro == 1300
    # No flight (an unknown flow): the whole default max_tokens.
    stray = budget.settle("anthropic", answer("zz", complete=False, usage={"input": 1}))
    assert stray.micro == 100 + 128_000 * 100


def test_m1_a_call_without_an_answer_is_charged_its_estimate(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100")
    assert budget.admit("a", model="fake-claude", request_bytes=300, max_tokens=10) is None
    cost = budget.charge_unanswered("a", why="error")
    assert cost is not None and cost.estimated
    assert cost.micro == 300 * 200 + 10 * 100  # bytes at the 1 h cache write, max_tokens
    [charged] = [e for e in box.events() if e.action == "budget_charged"]
    assert charged.details == {"flow_id": "a", "why": "error", "cost": cost.details()}
    assert charged.risk == 1
    assert budget.status()["day"]["spent_micro"] == cost.micro
    assert budget.status()["inflight"] == 0
    assert budget.charge_unanswered("a", why="error") is None  # once
    assert budget.admit("b") is None
    budget.forget("b")  # never sent: free
    assert budget.status()["day"]["spent_micro"] == cost.micro


def test_m1_a_new_proxy_charges_what_the_old_one_had_in_flight(
    tmp_path: Path, box: BlackBox
) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100")
    assert budget.admit("a", model="fake-claude", request_bytes=10, max_tokens=10) is None
    assert budget.admit("free", model="fake-claude", free=True) is None
    budget.forget_all()
    charged = [e for e in box.events() if e.action == "budget_charged"]
    assert [(e.details["flow_id"], e.details["why"]) for e in charged] == [("a", "proxy_restart")]
    assert budget.status()["inflight"] == 0


def test_m4_free_endpoints_cost_nothing_but_hold_a_place(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100", inflight=1)
    assert budget.admit("m", free=True) is None
    assert budget.admit("x") == "throttled"
    cost = budget.settle("anthropic", {"flow_id": "m", "status": 200, "usage_missing": True})
    assert (cost.micro, cost.priced_by, cost.estimated) == (0, "free", False)


def test_m5_calls_in_flight_reserve_their_estimate(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="1", monthly="100", inflight=8)
    big = {"model": "fake-claude", "request_bytes": 1000, "max_tokens": 4000}
    assert budget.admit("a", **big) is None  # reserves 1000*200 + 4000*100 = 600,000
    assert budget.admit("b", **big) is None  # 600,000 in flight < 1,000,000
    assert budget.admit("c", **big) == "throttled"  # 1,200,000 in flight >= the cap
    assert budget.admit("free", free=True) is None  # reserves nothing
    budget.settle("anthropic", answer("a", complete=True, usage={"input": 1, "output": 1}))
    assert budget.admit("c", **big) is None
    # The overshoot is bounded by one call: what is spent plus what is reserved.
    assert budget.status()["reserved_micro"] == 1_200_000


def test_b1_a_file_behind_the_black_box_is_caught_up(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="1000")
    spend(budget, box, 300_000, "a")
    path = tmp_path / "state" / STATE_BUDGET
    old = path.read_bytes()
    spend(budget, box, 200_000, "b")
    assert budget.charge_unanswered("nobody", why="error") is None
    assert budget.admit("c", model="fake-claude", request_bytes=1, max_tokens=1) is None
    charged = budget.charge_unanswered("c", why="error")
    path.write_bytes(old)  # an older budget.json (a crash before it was written, a restore)
    os.chmod(path, 0o600)
    again = make(tmp_path, box, clock, daily="100", monthly="1000")
    expected = 500_000 + charged.micro
    assert again.status()["day"]["spent_micro"] == expected
    assert again.status()["month"]["spent_micro"] == expected
    behind = [e for e in box.events() if e.action == "budget_rebuilt"]
    assert behind[-1].details["why"] == "behind"
    third = make(tmp_path, box, clock, daily="100", monthly="1000")  # caught up: nothing more
    assert third.status()["month"]["spent_micro"] == expected


def test_b1_an_old_file_without_a_seq_takes_the_larger_count(tmp_path: Path, box: BlackBox) -> None:
    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="1000")
    spend(budget, box, 300_000, "a")
    path = tmp_path / "state" / STATE_BUDGET
    state = json.loads(path.read_text())
    state.pop("last_seq")
    state["day_micro"] = state["month_micro"] = 100_000
    path.write_text(json.dumps(state))
    os.chmod(path, 0o600)
    again = make(tmp_path, box, clock, daily="100", monthly="1000")
    assert again.status()["month"]["spent_micro"] == 300_000


def test_b2_a_price_that_cannot_be_worked_out_is_estimated(
    tmp_path: Path, box: BlackBox, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backtide.service.spend as spend_module

    clock = Clock(datetime.now(UTC))
    budget = make(tmp_path, box, clock, daily="100", monthly="100")
    assert budget.admit("a", model="fake-claude", request_bytes=10, max_tokens=10) is None

    def broken(*_: Any, **__: Any) -> Any:
        raise ArithmeticError("boom")

    monkeypatch.setattr(spend_module, "cost_of", broken)
    cost = budget.settle("anthropic", answer("a", complete=True, usage={"input": 1}))
    assert cost.estimated and cost.micro == 10 * 200 + 10 * 100
    assert budget.status()["inflight"] == 0
    fallback = budget.fallback_cost({"flow_id": "gone"})
    assert fallback.estimated and fallback.micro > 0


def test_b4_local_time_follows_the_system_zone(tmp_path: Path) -> None:
    from backtide.service.spend import local_zone

    zones = tmp_path / "usr" / "share" / "zoneinfo" / "Europe"
    zones.mkdir(parents=True)
    madrid = zones / "Madrid"
    madrid.write_bytes(b"not read")
    link = tmp_path / "localtime"
    link.symlink_to(madrid)
    zone = local_zone(localtime=link, env={})
    assert isinstance(zone, ZoneInfo) and zone.key == "Europe/Madrid"
    assert local_zone(localtime=link, env={"TZ": "America/New_York"}).key == "America/New_York"
    summer = datetime(2026, 7, 1, 12, tzinfo=UTC).astimezone(zone)
    winter = datetime(2026, 12, 1, 12, tzinfo=UTC).astimezone(zone)
    assert summer.utcoffset() != winter.utcoffset()  # it follows the change of time
    nothing = local_zone(localtime=tmp_path / "missing", env={"TZ": "Not/AZone"})
    assert nothing is not None  # a fixed offset, with a warning
