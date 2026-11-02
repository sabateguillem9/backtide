"""T26-2c: the spending cap of the whole installation (backtide/service/spend_total.py), with real
``Budget``s and a real black box per agent. A's cap is A's; the total stops them all; adding an
agent does not multiply what is spent; and a count that cannot be made lets nothing out."""

import json
import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from backtide.blackbox import BlackBox
from backtide.notify import Alert
from backtide.service.prices import Cost
from backtide.service.spend import (
    MAX_CAP_USD,
    STATE_BUDGET,
    UNCOUNTED,
    Budget,
    BudgetSettings,
    status_lines,
)
from backtide.service.spend_total import InstallationSpend

KEY = bytes(range(32))
MADRID = ZoneInfo("Europe/Madrid")
START = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
MICRO = 1_000_000


class Clock:
    def __init__(self) -> None:
        self.moment = START

    def now(self) -> datetime:
        return self.moment


class Machine:
    """Two agents with their books and boxes, and the one total."""

    def __init__(self, root: Path, *, daily: str = "10", monthly: str = "100") -> None:
        self.root = root
        self.clock = Clock()
        self.settings = BudgetSettings(
            daily_usd=Decimal(daily),
            monthly_usd=Decimal(monthly),
            timezone=MADRID,
            timezone_name="Europe/Madrid",
        )
        self.folders = {slug: self._folder(slug) for slug in ("principal", "revisor")}
        self.installation = self._folder("installation")
        self.boxes: dict[str, BlackBox] = {}
        self.alerts: list[Alert] = []
        self.recorded: list[tuple[str, str, dict[str, Any], int, str]] = []
        self.record_works = True
        self.total = self.make_total()
        self.books: dict[str, Budget] = {}

    def _folder(self, name: str) -> Path:
        folder = self.root / name
        folder.mkdir(mode=0o700, exist_ok=True)
        return folder

    def make_total(self) -> InstallationSpend:
        total = InstallationSpend(
            self.settings,
            members=self.folders,
            folder=self.installation,
            inherit_from=self.folders["principal"],
            now=self.clock.now,
        )
        total.bind(record=self._record, alert=self.alerts.append)
        return total

    def _record(
        self, action: str, target: str, details: dict[str, Any], *, risk: int = 0,
        source: str = "system",
    ) -> bool:  # fmt: skip
        if self.record_works:
            self.recorded.append((action, target, details, risk, source))
        return self.record_works

    def book(self, slug: str, *, daily: str | None = None, monthly: str | None = None) -> Budget:
        box = BlackBox(self.folders[slug] / "blackbox.db", KEY)
        box.open()
        self.boxes[slug] = box
        settings = BudgetSettings(
            # What build_budget gives one with no cap of its own: only the total stops it.
            daily_usd=Decimal(daily) if daily else MAX_CAP_USD,
            monthly_usd=Decimal(monthly) if monthly else MAX_CAP_USD,
            timezone=MADRID,
            timezone_name="Europe/Madrid",
        )
        budget = Budget(
            settings,
            state_dir=self.folders[slug],
            record=box.append,
            history=box.events,
            now=self.clock.now,
            shared=self.total,
            slug=slug,
        )
        budget.open()
        self.books[slug] = budget
        return budget

    def spend(self, slug: str, dollars: float) -> None:
        self.books[slug].book_cost(Cost(int(dollars * MICRO), priced_by="test"), None)

    def close(self) -> None:
        for box in self.boxes.values():
            box.close()


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    found = Machine(tmp_path)
    yield found
    found.close()


def blocked_events(machine: Machine, slug: str) -> list[Any]:
    return machine.boxes[slug].events(source="llm", action="blocked")


def test_each_agent_has_its_own_cap_and_the_other_goes_on(machine: Machine) -> None:
    """`vecino-sin-gasto` on the Mac: A spends all it may, and B still calls."""
    a = machine.book("principal", daily="1")
    b = machine.book("revisor")
    machine.spend("principal", 1.0)
    assert a.admit("f1", model="m", max_tokens=1) == "spend_cap"
    assert b.admit("f2", model="m", max_tokens=1) is None
    assert blocked_events(machine, "principal")[0].details.get("scope") is None
    assert blocked_events(machine, "revisor") == []


def test_the_total_stops_every_agent_though_each_is_under_its_own(machine: Machine) -> None:
    """Adding an agent does not multiply the spending: 6 + 4 reach the 10 of the machine."""
    a, b = machine.book("principal"), machine.book("revisor")
    machine.spend("principal", 6.0)
    assert b.admit("f1", model="m", max_tokens=1) is None
    b.forget("f1")
    machine.spend("revisor", 4.0)
    assert a.admit("f2", model="m", max_tokens=1) == "spend_cap"
    assert b.admit("f3", model="m", max_tokens=1) == "spend_cap"
    for slug in ("principal", "revisor"):
        (event,) = blocked_events(machine, slug)
        assert event.details["scope"] == "installation"
        assert event.details["window"] == "day"


def test_one_agent_alone_counts_like_two_together_and_no_more(machine: Machine) -> None:
    a = machine.book("principal")
    machine.book("revisor")
    machine.spend("principal", 9.99)
    assert a.admit("f1", model="m", max_tokens=1) is None


def test_what_a_stopped_agent_spent_still_counts(machine: Machine) -> None:
    """It never started this time, so nobody reports for it: its file says it. Forgetting it
    would give the others its share again after every restart."""
    (machine.folders["revisor"] / STATE_BUDGET).write_text(
        json.dumps(
            {
                "version": 1, "day": "2026-11-02", "month": "2026-11", "day_micro": 7 * MICRO,
                "month_micro": 7 * MICRO, "warned": {"day": [], "month": []}, "estimated_calls": 0,
            }
        )
    )  # fmt: skip
    (machine.folders["revisor"] / STATE_BUDGET).chmod(0o600)
    a = machine.book("principal")
    machine.spend("principal", 3.0)
    assert a.admit("f1", model="m", max_tokens=1) == "spend_cap"
    status = machine.total.status()
    assert status["day"]["spent_micro"] == 10 * MICRO
    assert status["agents"]["revisor"]["day_micro"] == 7 * MICRO


def test_a_count_of_yesterday_is_not_todays(machine: Machine) -> None:
    (machine.folders["revisor"] / STATE_BUDGET).write_text(
        json.dumps(
            {
                "version": 1, "day": "2026-11-01", "month": "2026-11", "day_micro": 9 * MICRO,
                "month_micro": 9 * MICRO, "warned": {"day": [], "month": []}, "estimated_calls": 0,
            }
        )
    )  # fmt: skip
    (machine.folders["revisor"] / STATE_BUDGET).chmod(0o600)
    status = machine.total.status()
    assert status["day"]["spent_micro"] == 0
    assert status["month"]["spent_micro"] == 9 * MICRO


def test_an_idle_agents_day_ends_with_the_day(machine: Machine) -> None:
    machine.book("principal")
    b = machine.book("revisor")
    machine.spend("principal", 10.0)
    assert b.admit("f1", model="m", max_tokens=1) == "spend_cap"
    machine.clock.moment = START + timedelta(days=1)
    # The agent that spent is idle and its book still says yesterday: nobody is held for that.
    assert machine.total.blocked() is None
    assert b.admit("f2", model="m", max_tokens=1) is None
    assert ("budget_unblocked", "") == machine.recorded[-1][:2]


def test_a_count_that_cannot_be_made_lets_nothing_out_and_is_said_once(machine: Machine) -> None:
    (machine.folders["revisor"] / STATE_BUDGET).write_text("not json")
    (machine.folders["revisor"] / STATE_BUDGET).chmod(0o600)
    a = machine.book("principal")
    assert machine.total.blocked() == UNCOUNTED
    assert a.admit("f1", model="m", max_tokens=1) == "spend_unavailable"
    assert a.admit("f2", model="m", max_tokens=1) == "spend_unavailable"
    said = [r for r in machine.recorded if r[0] == "budget_unavailable"]
    assert len(said) == 1 and said[0][2] == {"agents": ["revisor"]}
    assert [a.title for a in machine.alerts] == [
        "No se puede contar el gasto de toda la instalación"
    ]
    assert machine.alerts[0].installation and machine.alerts[0].agent is None
    # It ends by itself when the count comes back.
    (machine.folders["revisor"] / STATE_BUDGET).unlink()
    assert a.admit("f3", model="m", max_tokens=1) is None


def test_a_budget_that_could_not_count_leaves_the_total_unknown(machine: Machine) -> None:
    a = machine.book("principal")
    machine.book("revisor")
    machine.books["revisor"]._unavailable = True  # noqa: SLF001
    machine.books["revisor"]._report()  # noqa: SLF001
    assert a.admit("f1", model="m", max_tokens=1) == "spend_unavailable"
    assert machine.total.status()["uncounted"] == ["revisor"]
    assert machine.total.status()["blocked"] is None
    # Whoever reads an agent's status does not hear that all is well.
    assert a.status()["available"] is False
    assert status_lines(a.status())[0].startswith("Gasto: no se puede contar")


def test_each_agent_passes_the_total_by_one_call_at_most(machine: Machine) -> None:
    """M5 of T11, for several books: one call of each, and then each waits for its own."""
    a, b = machine.book("principal"), machine.book("revisor")
    machine.spend("principal", 9.99)
    assert a.admit("f1", model="claude-opus-5-5", max_tokens=4_000_000) is None
    assert machine.total.status()["reserved_micro"] > 0
    assert a.admit("f2", model="claude-opus-5-5", max_tokens=1) == "throttled"
    assert b.admit("f3", model="claude-opus-5-5", max_tokens=4_000_000) is None
    assert b.admit("f4", model="claude-opus-5-5", max_tokens=1) == "throttled"
    a.forget("f1")
    assert a.admit("f5", model="claude-opus-5-5", max_tokens=1) is None


def test_a_huge_call_of_one_leaves_the_others_their_model(machine: Machine) -> None:
    """Review of T26-2c: a provider refuses a `max_tokens` of a billion for free, again and again,
    and what it reserved meanwhile must not throttle anybody else."""
    a, b = machine.book("principal"), machine.book("revisor")
    for flow in range(3):
        assert a.admit(f"a{flow}", model="desconocido", max_tokens=10**9) is None
        assert b.admit(f"b{flow}", model="claude-opus-5-5", max_tokens=64) is None
        b.forget(f"b{flow}")
        a.forget(f"a{flow}")


def test_many_threads_never_book_more_than_each_agents_own_reports(machine: Machine) -> None:
    machine.book("principal")
    machine.book("revisor")

    def burn(slug: str) -> None:
        for _ in range(50):
            machine.spend(slug, 0.01)

    threads = [threading.Thread(target=burn, args=(s,)) for s in ("principal", "revisor")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert machine.total.status()["day"]["spent_micro"] == 100 * 10_000


def test_the_warnings_of_the_total_go_to_its_box_once_each(machine: Machine) -> None:
    machine.book("principal")
    machine.book("revisor")
    machine.spend("principal", 5.0)
    machine.spend("revisor", 3.0)
    machine.spend("revisor", 0.5)
    machine.spend("principal", 2.0)
    actions = [(r[0], r[2]["pct"], r[3]) for r in machine.recorded if "pct" in r[2]]
    assert actions == [
        ("budget_warning", 50, 0),
        ("budget_warning", 80, 1),
        ("budget_exceeded", 100, 2),
    ]
    assert all(r[2]["scope"] == "installation" for r in machine.recorded if "pct" in r[2])
    assert any("Tope de gasto de hoy de toda la instalación" in a.title for a in machine.alerts)
    assert all(a.installation and a.agent is None for a in machine.alerts)
    # Saved, so a restart does not announce them again.
    again = machine.make_total()
    again.booked()
    assert len([r for r in machine.recorded if "pct" in r[2]]) == 3


def test_a_cap_is_recorded_before_it_changes_and_a_restart_keeps_it(machine: Machine) -> None:
    machine.book("principal")
    done = machine.total.set_caps(Decimal("2"), None, requested_by="cli (uid 0, pid 1)")
    assert done.ok and "toda la instalación" in done.message
    (action, target, details, risk, source) = machine.recorded[-1]
    assert (action, target, risk, source) == ("budget_set", "budget", 1, "settings")
    assert details["scope"] == "installation" and details["daily_usd"] == "2.00"
    assert details["requested_by"] == "cli (uid 0, pid 1)"
    assert machine.make_total().status()["day"]["cap_micro"] == 2 * MICRO


def test_a_cap_that_cannot_be_recorded_is_not_changed(machine: Machine) -> None:
    machine.record_works = False
    done = machine.total.set_caps(Decimal("2"), None, requested_by="cli")
    assert not done.ok and done.outcome == "failed"
    assert machine.total.status()["day"]["cap_micro"] == 10 * MICRO


def test_raising_the_cap_unblocks_at_once_and_it_is_said(machine: Machine) -> None:
    a = machine.book("principal")
    machine.spend("principal", 10.0)
    assert a.admit("f1", model="m", max_tokens=1) == "spend_cap"
    assert machine.total.set_caps(Decimal("20"), None, requested_by="cli").ok
    assert a.admit("f2", model="m", max_tokens=1) is None
    assert machine.recorded[-1][0] == "budget_unblocked"


def test_the_caps_the_main_agent_had_become_the_totals_the_first_time(machine: Machine) -> None:
    """Until now the owner's cap was the installation's: a new agent must not drop it to 5 $ and
    block the main one."""
    (machine.installation / STATE_BUDGET).unlink()
    main_caps(machine, 20 * MICRO, 200 * MICRO)
    status = machine.make_total().status()
    assert status["day"]["cap_micro"] == 20 * MICRO
    assert status["month"]["cap_micro"] == 200 * MICRO


def test_a_broken_total_file_falls_back_to_the_machines_caps_and_says_so(
    machine: Machine,
) -> None:
    """Even with caps of the main agent to inherit: they were only for the first time."""
    main_caps(machine, 20 * MICRO, 200 * MICRO)
    (machine.installation / STATE_BUDGET).write_text('{"version": 1, "extra": true}')
    (machine.installation / STATE_BUDGET).chmod(0o600)
    assert machine.make_total().status()["day"]["cap_micro"] == 10 * MICRO
    assert machine.recorded[-1][0] == "budget_file_unusable"
    assert machine.alerts[-1].title == "No se ha podido leer el tope de toda la instalación"


def main_caps(machine: Machine, daily: int, monthly: int) -> None:
    """What the main agent's budget.json says it has been set."""
    (machine.folders["principal"] / STATE_BUDGET).write_text(
        json.dumps(
            {
                "version": 1, "day": "2026-11-02", "month": "2026-11", "day_micro": 0,
                "month_micro": 0, "warned": {"day": [], "month": []}, "estimated_calls": 0,
                "caps": {"daily_micro": daily, "monthly_micro": monthly},
            }
        )
    )  # fmt: skip
    (machine.folders["principal"] / STATE_BUDGET).chmod(0o600)


def test_no_own_cap_never_becomes_the_total(machine: Machine) -> None:
    """Review of T26-2c: `tope --agente principal --mes 10` leaves 100000 $ a day in its file,
    meaning it has none. A restart before the total was ever saved must not make that the total's,
    with no event, for a whole installation."""
    (machine.installation / STATE_BUDGET).unlink()
    a = machine.book("principal")
    assert a.set_caps(None, Decimal("10"), requested_by="cli").ok
    total = machine.make_total()
    status = total.status()
    assert status["day"]["cap_micro"] == 10 * MICRO  # [budget]
    assert status["month"]["cap_micro"] == 10 * MICRO  # the one that was really set


def test_what_is_inherited_is_inherited_once(machine: Machine) -> None:
    (machine.installation / STATE_BUDGET).unlink()
    main_caps(machine, 20 * MICRO, 200 * MICRO)
    assert machine.make_total().status()["day"]["cap_micro"] == 20 * MICRO
    main_caps(machine, 30 * MICRO, 300 * MICRO)  # later it is the main agent's own, not the total
    assert machine.make_total().status()["day"]["cap_micro"] == 20 * MICRO


def test_status_says_both_and_whoever_reads_blocked_learns_the_truth(machine: Machine) -> None:
    a = machine.book("principal", daily="9")
    machine.book("revisor")
    machine.spend("revisor", 10.0)
    status = a.status()
    assert status["blocked"] == "day" and status["blocked_by"] == "installation"
    assert status["day"]["cap_micro"] == 9 * MICRO  # the one that binds
    assert status["own_caps"] == {"day": 9 * MICRO, "month": None}
    assert status["installation"]["day"]["cap_micro"] == 10 * MICRO
    assert status["month"]["cap_micro"] == 100 * MICRO  # the total's: it has none of its own
    lines = status_lines(status)
    assert "Total de la instalación hoy: 10,00 $ de 10,00 $." in lines
    assert "  revisor: 10,00 $ hoy, 10,00 $ este mes." in lines
    assert any("de toda la instalación alcanzado" in line for line in lines)


def test_without_a_total_nothing_of_this_shows(tmp_path: Path) -> None:
    box = BlackBox(tmp_path / "blackbox.db", KEY)
    box.open()
    budget = Budget(BudgetSettings(), state_dir=tmp_path, record=box.append, history=box.events)
    budget.open()
    status = budget.status()
    assert not {"installation", "blocked_by", "own_caps"} & set(status)
    box.close()
