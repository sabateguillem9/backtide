# ruff: noqa: F811 - pytest fixtures imported from the tests they come from
"""`backtide gasto` and `backtide tope` (T11 leftovers): what the commands say and return, with the
lock and the socket played by fakes; plus one run against a real control server, real budget and
real black box to show the change is recorded like the web's. The CLI only reads the config."""

import io
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import backtide.service.gasto as gasto
from backtide.blackbox import BlackBox
from backtide.cli import DEFAULT_CONFIG, build_parser, main
from backtide.service.config import Secret, ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlServer,
    ControlUnavailable,
    ask_budget,
    ask_set_budget,
)
from backtide.service.runner import ServiceLocked, ServiceRunning
from backtide.service.spend import Budget, BudgetSettings
from tests.test_service_control import FakeGuardian, me
from tests.test_service_control_settings import box, folder  # noqa: F401 - fixtures

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2


def status(
    *, day: int = 250_000, month: int = 12_345_678, blocked: str | None = None
) -> dict[str, Any]:
    return {
        "available": True,
        "day": {"spent_micro": day, "cap_micro": 5_000_000, "key": "2026-10-22"},
        "month": {"spent_micro": month, "cap_micro": 50_000_000, "key": "2026-10"},
        "blocked": blocked,
        "prices": {"updated_on": None, "source": "defaults", "defaults_on": "2026-10-06"},
    }


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    (tmp_path / "state").mkdir(mode=0o700)
    return ServiceConfig(
        state_dir=tmp_path / "state", volume=tmp_path / "vol", gateway_token=Secret(TOKEN)
    )


class Lock:
    closed = False

    def close(self) -> None:
        self.closed = True


def patch(
    monkeypatch: pytest.MonkeyPatch, *, lock: object, reply: Any = None
) -> list[tuple[Any, ...]]:
    """The lock and the socket as fakes; ``asked`` records what was sent."""
    asked: list[tuple[Any, ...]] = []

    def take_lock(path: Path) -> Lock:
        if isinstance(lock, Exception):
            raise lock
        assert isinstance(lock, Lock)
        return lock

    def ask_budget(path: Path) -> Any:
        asked.append(("read", path))
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def ask_set_budget(
        path: Path, *, daily_usd: str | None, monthly_usd: str | None, via: str
    ) -> Any:
        asked.append(("set", path, daily_usd, monthly_usd, via))
        if isinstance(reply, BaseException):
            raise reply
        return reply

    monkeypatch.setattr(gasto, "take_lock", take_lock)
    monkeypatch.setattr(gasto, "ask_budget", ask_budget)
    monkeypatch.setattr(gasto, "ask_set_budget", ask_set_budget)
    return asked


def run(call: Callable[..., int], *args: Any, **kwargs: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = call(*args, **kwargs, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


# --- backtide gasto -------------------------------------------------------------------------


def test_gasto_says_today_and_this_month_against_the_cap(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    asked = patch(monkeypatch, lock=ServiceRunning("busy"), reply=status())
    code, out, err = run(gasto.spending, config)
    assert (code, err) == (0, "")
    assert asked == [("read", config.control_socket)]
    assert "Gasto hoy: 0,25 $ de 5,00 $." in out
    assert "Gasto este mes: 12,35 $ de 50,00 $." in out  # rounded up, like the web
    assert "Precios de fábrica del 2026-10-06." in out


def test_gasto_says_when_a_cap_is_reached(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=status(day=5_000_000, blocked="day"))
    code, out, _ = run(gasto.spending, config)
    assert code == 0
    assert "Tope de hoy alcanzado: las llamadas al modelo se rechazan." in out
    assert "backtide tope" in out  # and how to raise it


def test_gasto_when_the_service_cannot_count_is_a_failure(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply={"available": False})
    code, out, err = run(gasto.spending, config)
    assert code == 1 and out == "" and "no se puede contar" in err


@pytest.mark.parametrize(
    "reply",
    [
        {},
        {"available": True},
        {"available": True, "day": {"spent_micro": "5"}, "month": {}},
        {"available": True, "day": {"spent_micro": -1, "cap_micro": 5}, "month": {}},
        {"available": True, **{w: {"spent_micro": True, "cap_micro": 1} for w in ("day", "month")}},
    ],
)
def test_a_reply_that_makes_no_sense_is_never_shown(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, reply: Any
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=reply)
    code, out, err = run(gasto.spending, config)
    assert code == 2 and out == "" and "no es la esperada" in err


def test_without_a_service_there_is_no_spending_to_read(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    lock = Lock()
    asked = patch(monkeypatch, lock=lock)
    code, _, err = run(gasto.spending, config)
    assert code == 1 and "no hay un `backtide vigilar`" in err and lock.closed and asked == []


@pytest.mark.parametrize(
    ("error", "reading", "changing"),
    [
        (ControlUnavailable("x"), 1, 1),
        (ControlOutcomeUnknown("maybe"), 2, 3),  # reading changes nothing: not knowing is moot
        (ControlError("no"), 2, 2),
    ],
)
def test_socket_problems_have_their_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    config: ServiceConfig,
    error: Exception,
    reading: int,
    changing: int,
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=error)
    assert run(gasto.spending, config)[0] == reading
    assert run(gasto.caps, config, None, None)[0] == reading
    assert run(gasto.caps, config, "3", None)[0] == changing


def test_an_unusable_lock_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    patch(monkeypatch, lock=ServiceLocked("symlink"))
    assert run(gasto.spending, config)[0] == 2
    assert run(gasto.caps, config, None, None)[0] == 2


# --- backtide tope --------------------------------------------------------------------------


def test_tope_without_options_shows_both_caps_and_how_to_change_them(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    asked = patch(monkeypatch, lock=ServiceRunning("busy"), reply=status())
    code, out, err = run(gasto.caps, config, None, None)
    assert (code, err) == (0, "")
    assert asked == [("read", config.control_socket)]  # nothing is changed
    assert "Tope diario: 5,00 $" in out and "Tope mensual: 50,00 $" in out
    assert "--dia" in out and "--mes" in out


def test_tope_with_options_asks_the_service_as_the_cli(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    reply = {"ok": True, "outcome": "saved", "message": "Guardado. \x1b[31mSe aplica."}
    asked = patch(monkeypatch, lock=ServiceRunning("busy"), reply=reply)
    code, out, err = run(gasto.caps, config, "7,50", "80")
    assert (code, err) == (0, "")
    assert asked == [("set", config.control_socket, "7,50", "80", "cli")]
    assert "Guardado." in out and "\x1b" not in out  # escaped, never sent to the terminal


def test_tope_with_only_one_option_leaves_the_other_alone(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    reply = {"ok": True, "outcome": "saved", "message": "Guardado."}
    asked = patch(monkeypatch, lock=ServiceRunning("busy"), reply=reply)
    assert run(gasto.caps, config, None, "20")[0] == 0
    assert asked == [("set", config.control_socket, None, "20", "cli")]


@pytest.mark.parametrize("value", ["0", "-3", "1e9", "lots", "1.999", "", "100001"])
def test_a_cap_that_does_not_fit_is_refused_before_asking(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, value: str
) -> None:
    asked = patch(monkeypatch, lock=ServiceRunning("busy"))
    code, out, err = run(gasto.caps, config, value, None)
    assert code == 2 and out == "" and "mayor que cero" in err
    code, _, err = run(gasto.caps, config, "5", value)
    assert code == 2 and "mayor que cero" in err
    assert asked == []


@pytest.mark.parametrize(
    ("outcome", "ok", "code"), [("saved", True, 0), ("invalid", False, 2), ("failed", False, 1),
                                ("refused", False, 2)],
)  # fmt: skip
def test_the_services_answer_decides_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, outcome: str, ok: bool, code: int
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply={"ok": ok, "outcome": outcome,
                                                          "message": "Dicho."})  # fmt: skip
    got, out, err = run(gasto.caps, config, "3", None)
    assert got == code
    assert "Dicho." in (out if code == 0 else err)


def test_without_a_service_a_cap_cannot_be_changed(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    lock = Lock()
    asked = patch(monkeypatch, lock=lock)
    code, _, err = run(gasto.caps, config, "3", None)
    assert code == 1 and "no hay un `backtide vigilar`" in err and lock.closed and asked == []


def test_an_interrupted_change_says_it_does_not_know(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=KeyboardInterrupt())
    code, _, err = run(gasto.caps, config, "3", None)
    assert code == 3 and "no se sabe" in err


# --- the cli --------------------------------------------------------------------------------


def test_the_cli_has_both_commands_with_the_config_option() -> None:
    parser = build_parser()
    spending = parser.parse_args(["gasto"])
    assert spending.handler.__name__ == "_spending" and spending.config == DEFAULT_CONFIG
    caps = parser.parse_args(["tope", "--dia", "3", "--mes", "40", "--config", "/x/b.toml"])
    assert (caps.day, caps.month, caps.config) == ("3", "40", Path("/x/b.toml"))
    assert caps.handler.__name__ == "_caps"
    bare = parser.parse_args(["tope"])
    assert (bare.day, bare.month) == (None, None)


def test_the_commands_read_the_config_they_are_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "gateway.token").write_text(TOKEN + "\n")
    (state / "gateway.token").chmod(0o600)
    path = tmp_path / "backtide.toml"
    path.write_text(f'state_dir = "{state}"\nvolume = "{tmp_path / "vol"}"\n')
    path.chmod(0o600)
    asked = patch(monkeypatch, lock=ServiceRunning("busy"), reply=status())
    assert main(["gasto", "--config", str(path)]) == 0
    assert "Gasto hoy" in capsys.readouterr().out
    assert main(["tope", "--config", str(path)]) == 0
    assert [call[1] for call in asked] == [state / "control.sock"] * 2


def test_a_broken_config_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for command in (["gasto"], ["tope"], ["tope", "--dia", "3"]):
        assert main([*command, "--config", str(tmp_path / "missing.toml")]) == 2
        assert "configuración no válida" in capsys.readouterr().err


# --- against the real thing -----------------------------------------------------------------


def test_a_cap_changed_from_the_terminal_is_recorded_like_the_webs(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, folder: Path, box: BlackBox
) -> None:
    box.open()
    budget = Budget(
        BudgetSettings(daily_usd=Decimal("1")),
        state_dir=folder,
        record=box.append,
        history=box.events,
        now=lambda: datetime(2026, 10, 22, 12, tzinfo=UTC),
    )
    budget.open()
    server = ControlServer(FakeGuardian(), folder / "control.sock", peer=me, budget=budget)
    server.start()
    try:
        monkeypatch.setattr(gasto, "take_lock", _running)
        monkeypatch.setattr(gasto, "ask_budget", lambda path: ask_budget(server.path, peer=me))
        monkeypatch.setattr(
            gasto,
            "ask_set_budget",
            lambda path, **kw: ask_set_budget(server.path, peer=me, **kw),
        )
        code, out, _ = run(gasto.spending, config)
        assert code == 0 and "Gasto hoy: 0,00 $ de 1,00 $." in out
        code, out, err = run(gasto.caps, config, "2,50", "30")
        assert (code, err) == (0, "")
        assert "Guardado." in out
        code, out, _ = run(gasto.caps, config, None, None)
        assert "Tope diario: 2,50 $" in out and "Tope mensual: 30,00 $" in out
        code, out, err = run(gasto.caps, config, "0", None)  # refused before the socket
        assert code == 2
    finally:
        server.close()
    [event] = [e for e in box.events() if e.action == "budget_set"]
    assert event.source == "settings" and event.risk == 1
    assert event.details["daily_usd"] == "2.50" and event.details["monthly_usd"] == "30.00"
    assert event.details["requested_by"].startswith("cli (uid ")


def _running(path: Path) -> Lock:
    raise ServiceRunning("busy")
