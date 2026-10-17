import logging
import signal
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import backtide.cli as cli
from backtide import __version__
from backtide.blackbox import BlackBoxError
from backtide.cli import main
from backtide.jail import JailError
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
)
from backtide.service.notice import rewind_notice
from backtide.service.rewind import RewindOutcome, RewindStatus
from backtide.service.runner import ServiceLocked, ServiceRunning, take_lock
from backtide.snapshots import Snapshot, SnapshotError


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert f"backtide {__version__}" in capsys.readouterr().out


def test_without_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: backtide" in capsys.readouterr().out


def test_help_lists_the_verificar_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "verificar" in capsys.readouterr().out


# --- rebobinar (T04c-2) ------------------------------------------------------------------------
#
# The command is driven with a fake store (the snapshots that exist), a fake `ask_rewind` (the
# service over its socket) and a fake `rewind_without_service` (this process). The real lock is
# used: whether a service "exists" is decided by who holds `backtide.lock`. The socket itself is
# tested in test_service_control.py and the whole thing in the VM (test_cli_rewind.py).


TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
TARGET = Snapshot(NOW - timedelta(minutes=10), "periodic")
UNDO = Snapshot(NOW, "pre_restore")


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "gateway.token").write_text(TOKEN + "\n")
    (state / "gateway.token").chmod(0o600)
    path = tmp_path / "backtide.toml"
    path.write_text(f'state_dir = "{state}"\nvolume = "{tmp_path / "vol"}"\n')
    path.chmod(0o600)
    return path


class FakeStore:
    listed: list[Snapshot] = []
    error: Exception | None = None

    def __init__(self, root: Path, **kwargs: object) -> None:
        pass

    def snapshots(self) -> list[Snapshot]:
        if FakeStore.error is not None:
            raise FakeStore.error
        return list(FakeStore.listed)


class FakeOffline:
    """``rewind_without_service``: records the call and whether the lock was held during it."""

    def __init__(self, config_file: Path) -> None:
        self.calls: list[tuple[str, bool]] = []
        self.config_file = config_file
        self.outcome = RewindOutcome(
            RewindStatus.DONE,
            target=TARGET.id,
            message=f"Rebobinado a {TARGET.id}.",
            undo=UNDO.id,
        )
        self.error: Exception | None = None

    def __call__(self, config: Any, snapshot_id: str, **options: object) -> RewindOutcome:
        try:
            take_lock(config.lock_file).close()
            held = False
        except ServiceRunning:
            held = True
        self.calls.append((snapshot_id, held))
        if self.error is not None:
            raise self.error
        return self.outcome


class FakeService:
    """``ask_rewind``: the service at the other end of the socket."""

    def __init__(self) -> None:
        self.calls: list[tuple[Path, str]] = []
        self.reply: dict[str, Any] = {
            "ok": True,
            "outcome": "done",
            "undo": UNDO.id,
            "message": f"Rebobinado a {TARGET.id}.",
            "agent_started": True,
        }
        self.error: BaseException | None = None

    def __call__(self, path: Path, snapshot_id: str, **options: object) -> dict[str, Any]:
        self.calls.append((path, snapshot_id))
        if self.error is not None:
            raise self.error
        return self.reply


@pytest.fixture
def rebob(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[FakeOffline, FakeService]:
    FakeStore.listed = [Snapshot(NOW - timedelta(minutes=90), "periodic"), TARGET]
    FakeStore.error = None
    offline, service = FakeOffline(config_file), FakeService()
    monkeypatch.setattr(cli, "SnapshotStore", FakeStore)
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    monkeypatch.setattr(cli, "_local_tz", lambda: timezone(timedelta(hours=2)))
    monkeypatch.setattr(cli, "rewind_without_service", offline)
    monkeypatch.setattr(cli, "ask_rewind", service)
    return offline, service


def rebobinar(
    capsys: pytest.CaptureFixture[str], config_file: Path, *args: str
) -> tuple[int, str, str]:
    code = main(["rebobinar", "--config", str(config_file), *args])
    out, err = capsys.readouterr()
    return code, out, err


def test_help_lists_rebobinar(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "rebobinar" in capsys.readouterr().out


def test_the_help_of_rebobinar_says_where_the_id_comes_from_and_the_exit_codes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(["rebobinar", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "backtide instantaneas" in text
    assert "--si" in text
    assert "3 si se rebobinó pero con un problema" in text


# the notice and the question


def test_the_notice_says_what_is_undone_what_is_not_and_when(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = rebobinar(capsys, config_file, "--si", TARGET.id)
    text = " ".join(out.split())
    assert code == 0
    assert "Vas a volver a las 13:50:00 del 2026-10-16 (hace 10 min)" in text  # local time, UTC+2
    assert "Se deshace: los archivos de trabajo del agente y lo que recuerda" in text
    assert "No se deshace: lo que el agente ya ha enviado fuera" in text
    assert "lo que ya salió de la máquina no vuelve" in text
    assert "no recordará nada posterior a esa hora aunque tus chats sí lo muestren" in text
    assert "puede reenviar algún mensaje que estuviera en cola" in text
    assert "Se guarda un punto para deshacer el rebobinado" in text
    assert "el agente se queda parado" in text  # what happens when there is no service
    # The same text as Telegram and the web (backtide/service/notice.py), channels included.
    for paragraph in rewind_notice(TARGET.taken_at, now=NOW, tz=timezone(timedelta(hours=2))):
        assert " ".join(paragraph.split()) in text
    assert "WhatsApp y Signal no se pueden usar en esta versión" in text


def test_nothing_is_asked_with_si_and_the_question_comes_before_anything_is_done(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    offline, _ = rebob
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked despite --si"))
    assert rebobinar(capsys, config_file, "--si", TARGET.id)[0] == 0
    assert len(offline.calls) == 1


class Stdin:
    def __init__(self, tty: bool) -> None:
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@pytest.mark.parametrize("answer", ["s", "S", "sí", "Sí", "si", " SI "])
def test_yes_answers_go_ahead(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    answer: str,
) -> None:
    offline, _ = rebob
    monkeypatch.setattr("sys.stdin", Stdin(True))
    asked: list[str] = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or answer)
    code, _, _ = rebobinar(capsys, config_file, TARGET.id)
    assert code == 0 and len(offline.calls) == 1
    assert asked == ["¿Rebobinar? [s/N] "]


@pytest.mark.parametrize("answer", ["", "n", "N", "no", "y", "yes", "claro", "ss"])
def test_anything_but_yes_does_nothing_and_exits_with_1(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    answer: str,
) -> None:
    offline, service = rebob
    monkeypatch.setattr("sys.stdin", Stdin(True))
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    code, out, _ = rebobinar(capsys, config_file, TARGET.id)
    assert code == 1
    assert "No se ha hecho nada." in out
    assert offline.calls == [] and service.calls == []
    assert not (config_file.parent / "state" / "backtide.lock").exists()  # no lock even taken


def test_end_of_input_at_the_question_is_a_no(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def eof(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("sys.stdin", Stdin(True))
    monkeypatch.setattr("builtins.input", eof)
    offline, _ = rebob
    assert rebobinar(capsys, config_file, TARGET.id)[0] == 1
    assert offline.calls == []


def test_without_a_terminal_it_refuses_to_guess_and_asks_for_si(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    offline, service = rebob
    monkeypatch.setattr("sys.stdin", Stdin(False))
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked without a terminal"))
    code, _, err = rebobinar(capsys, config_file, TARGET.id)
    assert code == 2
    assert "--si" in err
    assert offline.calls == [] and service.calls == []


# what it checks before anything


@pytest.mark.parametrize("bad", ["latest", "../../etc/passwd", "", TARGET.id + "x", "2026"])
def test_an_id_that_is_not_a_snapshot_id_is_a_usage_error_and_touches_nothing(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    bad: str,
) -> None:
    offline, service = rebob
    code, out, err = rebobinar(capsys, config_file, "--si", bad)
    assert code == 2
    assert "backtide instantaneas" in err
    assert "Vas a volver" not in out
    assert offline.calls == [] and service.calls == []
    assert not (config_file.parent / "state" / "backtide.lock").exists()


def test_a_snapshot_that_does_not_exist_is_a_usage_error_before_the_question(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    unknown = Snapshot(NOW - timedelta(days=3), "periodic")
    code, out, err = rebobinar(capsys, config_file, "--si", unknown.id)
    assert code == 2
    assert unknown.id in err and "no existe" in err
    assert "Vas a volver" not in out
    assert offline.calls == [] and service.calls == []


def test_a_store_that_cannot_be_read_is_a_usage_error(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeStore.error = SnapshotError("cannot list /x/snapshots: Permission denied")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 2 and "Permission denied" in err


def test_a_broken_config_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = rebobinar(capsys, tmp_path / "nope.toml", "--si", TARGET.id)
    assert code == 2 and "ERROR" in err


def test_the_default_config_path_is_the_one_of_vigilar(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["rebobinar", "--si", TARGET.id])  # /etc/backtide/backtide.toml is not here
    assert code == 2
    assert "/etc/backtide/backtide.toml" in capsys.readouterr().err


# no service: in this process, with the lock, the agent left stopped


def test_without_a_service_it_rewinds_in_this_process_holding_the_lock(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    code, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 0, err
    assert offline.calls == [(TARGET.id, True)]  # the lock was held while it rewound
    assert service.calls == []
    assert f"Rebobinado a {TARGET.id}." in out
    assert f"Para deshacer: backtide rebobinar {UNDO.id}" in out
    assert "No hay un servicio en marcha" in out
    assert "El agente queda parado" in out and "backtide vigilar" in out
    take_lock(config_file.parent / "state" / "backtide.lock").close()  # and it was released


def test_the_lock_is_released_even_if_the_rewind_blows_up(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    offline.error = RuntimeError("bug")
    rebobinar(capsys, config_file, "--si", TARGET.id)
    take_lock(config_file.parent / "state" / "backtide.lock").close()


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (RewindStatus.DONE, 0),
        (RewindStatus.FAILED, 1),
        (RewindStatus.INVALID, 2),
        (RewindStatus.PROBLEM, 3),
        (RewindStatus.UNKNOWN, 3),
    ],
)
def test_the_exit_code_follows_the_outcome_without_a_service(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    status: RewindStatus,
    code: int,
) -> None:
    offline, _ = rebob
    offline.outcome = RewindOutcome(status, target=TARGET.id, message="lo que pasó", undo=UNDO.id)
    got, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert got == code
    assert "lo que pasó" in (out if code == 0 else err)
    if status in (RewindStatus.DONE, RewindStatus.PROBLEM):
        assert f"Para deshacer: backtide rebobinar {UNDO.id}" in out
    else:
        assert "Para deshacer" not in out


def test_a_rewound_workspace_without_an_undo_point_says_so(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    offline.outcome = RewindOutcome(RewindStatus.DONE, target=TARGET.id, message="ok", undo=None)
    code, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 0
    assert "Para deshacer" not in out
    assert "No se ha podido guardar un punto para deshacer" in err


def test_a_black_box_that_cannot_be_used_is_exit_1_and_nothing_was_rewound(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    offline.error = BlackBoxError("key file is open to group or others")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 1
    assert "caja negra" in err and "no se rebobina" in err
    assert "Traceback" not in err


def test_a_black_box_error_that_stopped_the_agent_says_so(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    error = BlackBoxError("key file is open to group or others")
    error.add_note("Se ha parado al agente que estaba en marcha: sin grabar no hay vigilancia.")
    offline.error = error
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 1 and "Se ha parado al agente que estaba en marcha" in err


def test_an_agent_that_keeps_running_without_a_black_box_is_said_loudly(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    offline.error = JailError("the agent is still running after stop, kill and remove")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 1 and "SIGUE EN MARCHA" in err


def test_an_unexpected_failure_is_exit_3_logged_with_its_trace(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    offline, _ = rebob
    offline.error = ZeroDivisionError("a bug")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 3  # nobody knows how far it got
    assert "no se sabe si se rebobinó" in err
    assert "backtide instantaneas" in err
    assert any(record.exc_info for record in caplog.records)  # nothing is swallowed


def test_ctrl_c_is_ignored_while_this_process_rewinds_and_put_back_after(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    seen: dict[str, object] = {}
    before = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

    def during(config: Any, snapshot_id: str, **options: object) -> RewindOutcome:
        seen.update({n.name: signal.getsignal(n) for n in before})
        return offline.outcome

    cli.rewind_without_service = during  # type: ignore[assignment]  # restored by the fixture
    code, out, _ = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 0
    assert seen == {"SIGINT": signal.SIG_IGN, "SIGTERM": signal.SIG_IGN, "SIGHUP": signal.SIG_IGN}
    assert {n: signal.getsignal(n) for n in before} == before
    assert "Ctrl-C se ignora" in out


def test_ctrl_c_at_the_question_is_a_no_not_a_traceback(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt(prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("sys.stdin", Stdin(True))
    monkeypatch.setattr("builtins.input", interrupt)
    offline, service = rebob
    code, out, _ = rebobinar(capsys, config_file, TARGET.id)
    assert code == 1 and "No se ha hecho nada." in out
    assert offline.calls == [] and service.calls == []


def test_the_log_of_the_package_is_shown_safely_during_the_rewind_and_then_put_back(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, _ = rebob
    package = logging.getLogger("backtide")
    handlers, level = list(package.handlers), package.level
    key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"

    def noisy(config: Any, snapshot_id: str, **options: object) -> RewindOutcome:
        logging.getLogger("backtide.snapshots.store").warning("agent wrote %s\x1b[2J", key)
        return offline.outcome

    cli.rewind_without_service = noisy  # type: ignore[assignment]  # restored by the fixture
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 0
    assert "agent wrote" in err
    assert key not in err and "\x1b" not in err  # struck out and escaped
    assert package.handlers == handlers and package.level == level


# a service: over the socket, never in this process


@pytest.fixture
def held_lock(config_file: Path) -> Any:
    lock = take_lock(config_file.parent / "state" / "backtide.lock")
    yield lock
    lock.close()


def test_with_a_service_it_asks_over_the_socket_and_does_not_rewind_itself(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    code, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 0, err
    assert service.calls == [(config_file.parent / "state" / "control.sock", TARGET.id)]
    assert offline.calls == []  # never in this process with the lock taken
    assert "socket de control" in out
    assert f"Para deshacer: backtide rebobinar {UNDO.id}" in out
    assert "El agente está en marcha otra vez." in out


def test_with_a_service_an_agent_that_was_not_started_is_said(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, service = rebob
    service.reply = {**service.reply, "agent_started": False}
    _, out, _ = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert "El agente no se ha arrancado." in out
    assert "otra vez" not in out


@pytest.mark.parametrize(
    ("outcome", "ok", "code"),
    [
        ("done", True, 0),
        ("failed", False, 1),
        ("invalid", False, 2),
        ("refused", False, 2),
        ("problem", True, 3),
        ("unknown", False, 3),
    ],
)
def test_the_exit_code_follows_the_services_outcome(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
    outcome: str,
    ok: bool,
    code: int,
) -> None:
    offline, service = rebob
    service.reply = {**service.reply, "outcome": outcome, "ok": ok, "message": "dicho por backtide"}
    got, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert got == code
    assert "dicho por backtide" in (out if code == 0 else err)
    assert offline.calls == []


def test_a_service_that_has_the_lock_but_no_socket_yet_is_exit_1_and_never_a_fallback(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    service.error = ControlUnavailable("Nadie contesta")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 1
    assert "está arrancando" in err and "No se ha tocado nada" in err
    assert offline.calls == []  # the lock is taken: this process never touches the agent


def test_a_socket_that_cannot_be_trusted_is_a_usage_error_and_nothing_is_rewound(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    service.error = ControlError("control.sock no es un socket (¿un enlace simbólico?)")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 2 and "no es un socket" in err
    assert offline.calls == []


def test_a_request_that_went_out_without_a_usable_answer_is_exit_3(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    service.error = ControlOutcomeUnknown("Se ha perdido la conexión. No se sabe si se hizo")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 3 and "No se sabe si" in err
    assert offline.calls == []


def test_ctrl_c_while_the_service_rewinds_says_it_goes_on_and_exits_3(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, service = rebob
    service.error = KeyboardInterrupt()
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 3
    assert "sigue con el rebobinado" in err and "backtide instantaneas" in err
    assert "Traceback" not in err


def test_a_lock_file_that_cannot_be_used_is_not_a_service(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    offline, service = rebob
    (config_file.parent / "state" / "backtide.lock").symlink_to(config_file.parent / "elsewhere")
    code, _, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 2 and "enlace simbólico" in err
    assert offline.calls == [] and service.calls == []


def test_a_lock_taken_while_the_question_was_open_is_still_not_a_fallback(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mode is decided when the person says yes, not before the question: a service that
    started in the meantime gets the request, and this process leaves the agent alone."""
    offline, service = rebob
    lock = take_lock(config_file.parent / "state" / "backtide.lock")
    try:
        monkeypatch.setattr("sys.stdin", Stdin(True))
        monkeypatch.setattr("builtins.input", lambda prompt: "s")
        code, _, _ = rebobinar(capsys, config_file, TARGET.id)
    finally:
        lock.close()
    assert code == 0 and offline.calls == [] and len(service.calls) == 1


# what comes back is not trusted


def test_what_the_service_says_cannot_rewrite_the_terminal_or_leak_a_key(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, service = rebob
    key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"
    service.reply = {
        **service.reply,
        "outcome": "failed",
        "ok": False,
        "message": f"\x1b[2J\x1b[31mOK, todo bien {key}\nsegunda línea",
    }
    code, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 1
    assert "\x1b" not in err + out and key not in err + out
    assert err.count("\n") == 1  # the newline in the message is shown escaped, not obeyed


def test_an_undo_point_that_is_not_a_snapshot_id_is_not_offered_as_a_command(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    held_lock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, service = rebob
    service.reply = {**service.reply, "undo": "x; rm -rf ~"}
    code, out, err = rebobinar(capsys, config_file, "--si", TARGET.id)
    assert code == 0
    assert "rm -rf" not in out + err
    assert "punto para deshacer que no es válido" in err


# backtide instantaneas and backtide rebobinar, together


def test_the_id_that_instantaneas_shows_is_the_one_rebobinar_takes(
    rebob: tuple[FakeOffline, FakeService],
    config_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The demo: list, copy the first column of a row, rewind to it."""
    offline, _ = rebob
    assert main(["instantaneas", "--config", str(config_file)]) == 0
    rows = capsys.readouterr().out.strip().splitlines()[1:]
    shown = [row.split()[0] for row in rows]
    assert shown == [TARGET.id, FakeStore.listed[0].id]  # newest first, whole ids
    assert all(Snapshot.parse(identifier) is not None for identifier in shown)
    for identifier in shown:
        assert rebobinar(capsys, config_file, "--si", identifier)[0] == 0
    assert [call[0] for call in offline.calls] == shown


def test_vigilar_exits_1_and_says_so_when_the_control_socket_cannot_be_opened(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise ControlError("/x/control.sock existe y no es un socket (¿un enlace simbólico?)")

    monkeypatch.setattr(cli, "serve", serve)
    code = main(["vigilar", "--config", str(config_file)])
    err = capsys.readouterr().err
    assert code == 1
    assert "socket de control" in err and "no es un socket" in err
    assert "Traceback" not in err


def test_the_service_lock_error_types_are_what_the_command_distinguishes() -> None:
    assert issubclass(ServiceRunning, ServiceLocked)
