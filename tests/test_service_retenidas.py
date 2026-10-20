"""`backtide aprobar`, `rechazar` and `retenidas` (T10-2): what the commands say and return, with
the lock and the socket played by fakes. The CLI only reads the config and calls these."""

import io
from pathlib import Path
from typing import Any

import pytest

import backtide.service.retenidas as retenidas
from backtide.cli import build_parser
from backtide.service.config import Secret, ServiceConfig
from backtide.service.control import ControlError, ControlOutcomeUnknown, ControlUnavailable
from backtide.service.runner import ServiceLocked, ServiceRunning

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
HOLD = "h-0123456789ab"


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
    asked: list[tuple[Any, ...]] = []

    def take_lock(path: Path) -> Lock:
        if isinstance(lock, Exception):
            raise lock
        assert isinstance(lock, Lock)
        return lock

    def ask_decide(path: Path, hold_id: str, verdict: str) -> dict[str, Any]:
        asked.append((path, hold_id, verdict))
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def ask_holds(path: Path) -> list[dict[str, Any]]:
        asked.append((path,))
        if isinstance(reply, BaseException):
            raise reply
        return reply

    monkeypatch.setattr(retenidas, "take_lock", take_lock)
    monkeypatch.setattr(retenidas, "ask_decide", ask_decide)
    monkeypatch.setattr(retenidas, "ask_holds", ask_holds)
    return asked


def decide(
    config: ServiceConfig, hold_id: str = HOLD, verdict: str = "approve"
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = retenidas.decide(config, hold_id, verdict, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize(
    ("outcome", "code"),
    [("released", 0), ("preapproved", 0), ("rejected", 0), ("unknown", 1), ("failed", 1),
     ("refused", 2), ("something-else", 3)],
)  # fmt: skip
def test_a_decision_goes_to_the_service_and_says_what_happened(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, outcome: str, code: int
) -> None:
    reply = {"ok": code == 0, "outcome": outcome, "message": "Aprobada \x1b[31m."}
    asked = patch(monkeypatch, lock=ServiceRunning("busy"), reply=reply)
    got, out, err = decide(config)
    assert got == code
    assert asked == [(config.control_socket, HOLD, "approve")]
    text = out if code == 0 else err
    assert "Aprobada" in text and "\x1b" not in text  # escaped, never sent to the terminal


def test_an_id_that_is_not_one_is_refused_before_anything(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    asked = patch(monkeypatch, lock=ServiceRunning("busy"))
    for bad in ("h-XYZ", "rm -rf", "", "h-0123456789abc"):
        code, _, err = decide(config, bad)
        assert code == 2 and "identificador" in err
    assert asked == []


def test_without_a_service_nothing_is_held(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    lock = Lock()
    asked = patch(monkeypatch, lock=lock)
    code, _, err = decide(config)
    assert code == 1 and "no hay" in err and lock.closed and asked == []


@pytest.mark.parametrize(
    ("error", "code"),
    [(ControlUnavailable("x"), 1), (ControlOutcomeUnknown("maybe"), 3), (ControlError("no"), 2)],
)
def test_socket_problems_have_their_exit_codes(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig, error: Exception, code: int
) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=error)
    assert decide(config)[0] == code


def test_an_unusable_lock_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    patch(monkeypatch, lock=ServiceLocked("symlink"))
    assert decide(config)[0] == 2


def test_the_listing_shows_each_hold_escaped(
    monkeypatch: pytest.MonkeyPatch, config: ServiceConfig
) -> None:
    holds = [
        {"hold_id": HOLD, "risk": 3, "method": "DELETE", "target": "https://api.fake.test/b\x1b]0;x",
         "expires_in_s": 125, "waiting": True},
        {"hold_id": "h-00000000000b", "risk": 2, "method": "POST", "host": "x.test"},
    ]  # fmt: skip
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=holds)
    out, err = io.StringIO(), io.StringIO()
    assert retenidas.listing(config, out=out, err=err) == 0
    lines = out.getvalue().splitlines()
    assert lines[0].startswith(f"{HOLD}  riesgo 3  DELETE https://api.fake.test/b")
    assert "caduca en 2 min 05 s" in lines[0] and "esperando conectada" in lines[0]
    assert "\x1b" not in out.getvalue()
    assert lines[1].startswith("h-00000000000b  riesgo 2  POST x.test")
    assert "backtide aprobar" in out.getvalue()


def test_an_empty_listing_says_so(monkeypatch: pytest.MonkeyPatch, config: ServiceConfig) -> None:
    patch(monkeypatch, lock=ServiceRunning("busy"), reply=[])
    out = io.StringIO()
    assert retenidas.listing(config, out=out, err=io.StringIO()) == 0
    assert out.getvalue().strip() == retenidas.NONE_HELD


def test_the_cli_has_the_three_commands() -> None:
    parser = build_parser()
    approve = parser.parse_args(["aprobar", HOLD])
    reject = parser.parse_args(["rechazar", HOLD])
    listing = parser.parse_args(["retenidas"])
    assert (approve.hold, approve.verdict) == (HOLD, "approve")
    assert (reject.hold, reject.verdict) == (HOLD, "reject")
    assert listing.handler.__name__ == "_list_holds"
