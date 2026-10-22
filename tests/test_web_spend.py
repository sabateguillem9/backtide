"""T11: the spending in the web. The panel and Settings show today's and this month's spending and
the prices' date; Settings changes the caps with the same protections as a key (the Guard, CSRF,
a one-time ticket, `--ajustes`). The end-to-end test goes through a real control socket to a real
budget on a real black box."""

import shutil
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backtide.blackbox import BlackBox
from backtide.service.control import ControlServer
from backtide.service.spend import Budget, BudgetSettings
from backtide.web.rewind import Availability
from backtide.web.settings import ControlSettings, ControlSpend, spend_view
from tests.test_service_control import FakeGuardian, me
from tests.test_web_settings import NOW, FakeSettings, confirm, hidden, post, text_of
from tests.webkit import KEY, new_box, new_client

STATUS = {
    "available": True,
    "day": {"spent_micro": 250_000, "cap_micro": 5_000_000, "key": "2026-10-20"},
    "month": {"spent_micro": 1_100_000, "cap_micro": 50_000_000, "key": "2026-10"},
    "blocked": None,
    "prices": {"updated_on": "2026-10-20", "source": "anthropic", "defaults_on": "2026-10-06"},
}


class FakeSpend:
    def __init__(self, status: dict[str, Any] | None = None) -> None:
        self.status = dict(STATUS if status is None else status)

    def availability(self) -> Availability:
        return Availability.READY

    def spend(self) -> dict[str, Any]:
        return self.status


class BudgetFake(FakeSettings):
    def __init__(self, state: Availability = Availability.READY) -> None:
        super().__init__(state)
        self.caps: list[tuple[str | None, str | None]] = []

    def set_budget(self, daily: str | None, monthly: str | None) -> dict[str, Any]:
        self.caps.append((daily, monthly))
        return {"ok": True, "outcome": "saved", "message": "Guardado."}


@pytest.fixture
def fake() -> BudgetFake:
    return BudgetFake()


@pytest.fixture
def web(tmp_path: Path, fake: BudgetFake) -> TestClient:
    new_box(tmp_path).append("file", "create", "work/notas.md")
    return new_client(tmp_path, settings=fake, spend=FakeSpend(), clock=lambda: NOW)


def budget_confirm(web: TestClient) -> dict[str, str]:
    page = web.get("/ajustes/cambiar?tipo=tope")
    assert page.status_code == 200, page.text[:300]
    fields = hidden(page.text)
    assert set(fields) == {"csrf", "ticket", "tipo", "accion"}
    return fields


def test_settings_and_panel_show_the_spending(web: TestClient) -> None:
    said = text_of(web.get("/ajustes").text)
    assert "Hoy: 0,25 $ de 5,00 $ · Este mes: 1,10 $ de 50,00 $" in said
    assert "Precios actualizados el 2026-10-20 (fuente: Anthropic)." in said
    assert "/ajustes/cambiar?tipo=tope" in web.get("/ajustes").text
    panel = text_of(web.get("/panel").text)
    assert "Gasto de los modelos: Hoy: 0,25 $ de 5,00 $ · Este mes: 1,10 $ de 50,00 $" in panel


def test_a_reached_cap_is_said(tmp_path: Path) -> None:
    status = dict(STATUS, blocked="day", prices={"defaults_on": "2026-10-06"})
    web = new_client(tmp_path, settings=BudgetFake(), spend=FakeSpend(status))
    said = text_of(web.get("/ajustes").text)
    assert "Tope de hoy alcanzado" in said and "Precios de fábrica del 2026-10-06." in said
    assert "Tope de hoy alcanzado" in text_of(web.get("/panel").text)


def test_nonsense_from_the_service_is_not_shown() -> None:
    assert spend_view({"available": True, "day": {"spent_micro": -1}}) is None
    assert spend_view([]) is None
    odd = dict(STATUS, blocked="<b>", prices={"updated_on": "<script>"})
    view = spend_view(odd)
    assert view is not None and view.blocked is None and view.prices_on is None


def test_new_caps_go_with_their_confirmation(web: TestClient, fake: BudgetFake) -> None:
    page = web.get("/ajustes/cambiar?tipo=tope").text
    assert 'name="diario"' in page and 'name="mensual"' in page and 'placeholder="5.00"' in page
    fields = budget_confirm(web)
    reply = post(web, {**fields, "diario": "7,50", "mensual": ""})
    assert reply.status_code == 200 and "Guardado" in text_of(reply.text)
    assert fake.caps == [("7,50", None)]
    again = post(web, {**fields, "diario": "9", "mensual": ""})  # the ticket is spent
    assert again.status_code == 400 and fake.caps == [("7,50", None)]


@pytest.mark.parametrize(
    "change",
    [
        {"diario": "0", "mensual": ""},
        {"diario": "", "mensual": ""},
        {"diario": "1.999", "mensual": "3"},
        {"diario": "abc", "mensual": ""},
    ],
)
def test_caps_that_do_not_fit_are_refused_here(
    web: TestClient, fake: BudgetFake, change: dict[str, str]
) -> None:
    fields = budget_confirm(web)
    assert post(web, {**fields, **change}).status_code == 400
    assert fake.caps == []


def test_the_same_protections_as_a_key(web: TestClient, fake: BudgetFake) -> None:
    fields = budget_confirm(web)
    forged = post(web, {**fields, "csrf": "nope", "diario": "9", "mensual": ""})
    assert forged.status_code == 403
    other = budget_confirm(web)
    assert post(web, {**other, "diario": "9"}).status_code == 400  # the form is not the page's
    key_ticket = confirm(web, "set", "openai")  # a ticket for another thing does not do
    assert (
        post(web, {**key_ticket, "tipo": "tope", "diario": "9", "mensual": ""}).status_code == 400
    )
    assert (
        web.post(
            "/ajustes/guardar",
            data={**other, "diario": "9", "mensual": ""},
            headers={"origin": "https://evil.test"},
        ).status_code
        == 403
    )
    assert fake.caps == []


def test_without_ajustes_the_caps_are_shown_but_not_changed(tmp_path: Path) -> None:
    settings = BudgetFake(Availability.DISABLED)
    web = new_client(tmp_path, settings=settings, spend=FakeSpend())
    page = web.get("/ajustes").text
    assert "Hoy: 0,25 $ de 5,00 $" in text_of(page)
    assert "/ajustes/cambiar?tipo=tope" not in page
    assert "<form" not in web.get("/ajustes/cambiar?tipo=tope").text


@pytest.fixture
def short_folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vt"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def test_end_to_end_through_the_control_socket(tmp_path: Path, short_folder: Path) -> None:
    box = BlackBox(short_folder / "blackbox.db", KEY)
    box.open()
    budget = Budget(
        BudgetSettings(daily_usd=Decimal("1")),
        state_dir=short_folder,
        record=box.append,
        history=box.events,
        now=lambda: datetime(2026, 10, 21, 12, tzinfo=UTC),
    )
    budget.open()
    server = ControlServer(FakeGuardian(), short_folder / "control.sock", peer=me, budget=budget)
    server.start()
    try:
        web = new_client(
            tmp_path,
            settings=ControlSettings(server.path, enabled=True, peer=me),
            spend=ControlSpend(server.path, peer=me),
        )
        assert "Hoy: 0,00 $ de 1,00 $" in text_of(web.get("/ajustes").text)
        fields = budget_confirm(web)
        reply = post(web, {**fields, "diario": "2,5", "mensual": "40"})
        assert reply.status_code == 200, reply.text[:400]
        assert budget.status()["day"]["cap_micro"] == 2_500_000
        assert budget.status()["month"]["cap_micro"] == 40_000_000
        [event] = [e for e in box.events() if e.action == "budget_set"]
        assert event.details["requested_by"].startswith("web (uid ")
        assert "Hoy: 0,00 $ de 2,50 $" in text_of(web.get("/ajustes").text)
    finally:
        server.close()
        box.close()
