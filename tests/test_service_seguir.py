"""`backtide seguir` (T04d-2): what the command says and returns, with the lock and the socket
played by fakes. The CLI wiring (`backtide/cli.py`) only reads the config and calls ``seguir``."""

import io
from pathlib import Path
from typing import Any

import pytest

import backtide.service.seguir as seguir_module
from backtide.service.config import Secret, ServiceConfig
from backtide.service.control import ControlError, ControlOutcomeUnknown, ControlUnavailable
from backtide.service.runner import ServiceLocked, ServiceRunning
from backtide.service.seguir import seguir

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2


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

    def __enter__(self) -> "Lock":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def run(
    monkeypatch: pytest.MonkeyPatch,
    config: ServiceConfig,
    *,
    lock: object = None,
    reply: dict[str, Any] | BaseException | None = None,
) -> tuple[int, str, str, list[Path]]:
    asked: list[Path] = []

    def take_lock(path: Path) -> Lock:
        if isinstance(lock, Exception):
            raise lock
        assert isinstance(lock, Lock)
        return lock

    def ask_resume(path: Path) -> dict[str, Any]:
        asked.append(path)
        if isinstance(reply, BaseException):
            raise reply
        assert reply is not None
        return reply

    monkeypatch.setattr(seguir_module, "take_lock", take_lock)
    monkeypatch.setattr(seguir_module, "ask_resume", ask_resume)
    out, err = io.StringIO(), io.StringIO()
    code = seguir(config, out=out, err=err)
    return code, out.getvalue(), err.getvalue(), asked


def test_with_a_service_it_asks_over_the_socket_and_says_what_happened(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    reply = {
        "ok": True,
        "outcome": "resumed",
        "message": "El agente ha arrancado.",
        "agent_state": "running",
    }
    code, out, err, asked = run(monkeypatch, config, lock=ServiceRunning("busy"), reply=reply)
    assert code == 0
    assert asked == [config.control_socket]
    assert "El agente ha arrancado." in out
    assert err == ""


@pytest.mark.parametrize(
    ("outcome", "code"),
    [
        ("not_paused", 0),
        ("still_red", 1),
        ("still_paused", 1),
        ("failed", 1),
        ("problem", 3),
        ("refused", 2),
    ],
)
def test_the_exit_code_follows_the_outcome(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, outcome: str, code: int
) -> None:
    reply = {"ok": outcome == "not_paused", "outcome": outcome, "message": "m", "agent_state": ""}
    assert run(monkeypatch, config, lock=ServiceRunning("busy"), reply=reply)[0] == code


def test_what_comes_back_is_printed_without_control_characters_or_secrets(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    reply = {
        "ok": False,
        "outcome": "still_red",
        "message": "\x1b[2Jfalta espacio sk-ant-api03-" + "z" * 40,
        "agent_state": "frozen",
    }
    code, out, err, _ = run(monkeypatch, config, lock=ServiceRunning("busy"), reply=reply)
    assert code == 1
    assert "\x1b" not in out + err
    assert "zzzz" not in out + err


def test_without_a_service_nothing_is_resumed_and_it_says_how(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    lock = Lock()
    code, out, err, asked = run(monkeypatch, config, lock=lock)
    assert code == 1
    assert asked == []
    assert lock.closed  # the lock is let go at once: a `backtide vigilar` may start
    assert "backtide vigilar" in err and "backtide seguir" in err


@pytest.mark.parametrize(
    ("error", "code", "says"),
    [
        (ControlUnavailable("nobody"), 1, "arrancando"),
        (ControlOutcomeUnknown("No se sabe si"), 3, "No se sabe si"),
        (ControlError("not ours"), 2, "not ours"),
        (KeyboardInterrupt(), 3, "interrumpido"),
    ],
)
def test_socket_failures_say_what_is_known(
    monkeypatch: pytest.MonkeyPatch,
    config: ServiceConfig,
    error: BaseException,
    code: int,
    says: str,
) -> None:
    result, _, err, _ = run(monkeypatch, config, lock=ServiceRunning("busy"), reply=error)  # type: ignore[arg-type]
    assert result == code
    assert says in err


def test_an_unusable_lock_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    code, _, err, asked = run(monkeypatch, config, lock=ServiceLocked("El cerrojo es un enlace"))
    assert code == 2
    assert "enlace" in err
    assert asked == []
