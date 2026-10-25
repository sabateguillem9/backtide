"""`backtide comprobar` (T13-2): the preflight, for anyone, at any time."""

from collections.abc import Callable

import pytest

import backtide.cli as cli
from backtide.cli import main
from backtide.setup import preflight
from backtide.setup.preflight import Check, Status

GOOD = [
    Check("root", Status.OK, "Se ejecuta como root"),
    Check("kernel", Status.WARN, "Kernel 7.0.0: sirve, pero sin los arreglos", "Actualiza."),
]
BAD = [*GOOD, Check("loop", Status.FAIL, "No hay dispositivos de bucle", "Carga `loop`.")]


def fake_checks(result: list[Check]) -> tuple[list[bool], Callable[..., list[Check]]]:
    """A run_checks that answers ``result`` and records whether it was asked to install."""
    seen: list[bool] = []

    def run_checks(host: object, *, installing: bool) -> list[Check]:
        seen.append(installing)
        return result

    return seen, run_checks


def test_help_lists_comprobar(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "comprobar" in capsys.readouterr().out


def test_warnings_alone_exit_0(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen, run_checks = fake_checks(GOOD)
    monkeypatch.setattr(cli.preflight, "run_checks", run_checks)
    assert main(["comprobar"]) == 0
    out = capsys.readouterr().out
    assert seen == [False]  # checking, not installing: no root needed
    assert "[ok]" in out and "[aviso]" in out and "Actualiza." in out
    assert "Ningún fallo" in out


def test_a_failure_exits_1_and_says_how_to_fix_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli.preflight, "run_checks", fake_checks(BAD)[1])
    assert main(["comprobar"]) == 1
    out = capsys.readouterr().out
    assert "[falla] No hay dispositivos de bucle" in out
    assert "Carga `loop`." in out
    assert "1 fallo" in out


def test_report_wraps_long_fixes_under_their_check() -> None:
    long_fix = "palabra " * 40
    text = preflight.report([Check("x", Status.WARN, "Algo", long_fix.strip())])
    lines = text.splitlines()
    assert all(len(line) <= 100 for line in lines)
    assert sum("palabra" in line for line in lines) > 1
