"""`vigia vigilar` and `vigia instantaneas`: arguments, messages in Spanish and exit codes.

`vigilar` is driven with a fake ``serve`` (the real one is tested in tests/test_service_runner.py
and in the VM); `instantaneas` with a fake store that lists snapshots.
"""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

import vigia.cli as cli
from vigia.blackbox import BlackBoxError
from vigia.cli import main
from vigia.jail import JailError
from vigia.jail.openclaw import RewindProblem, UnrewindableConfig
from vigia.service.config import ConfigError
from vigia.service.runner import ServiceLocked
from vigia.snapshots import Reason, Snapshot, SnapshotError

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "gateway.token").write_text(TOKEN + "\n")
    (state / "gateway.token").chmod(0o600)
    path = tmp_path / "vigia.toml"
    path.write_text(f'state_dir = "{state}"\nvolume = "{tmp_path / "vol"}"\n')
    path.chmod(0o600)
    return path


def run(capsys: pytest.CaptureFixture[str], *args: str | Path) -> tuple[int, str, str]:
    code = main([str(arg) for arg in args])
    out, err = capsys.readouterr()
    return code, out, err


# --- vigilar -----------------------------------------------------------------------------------


def test_vigilar_is_in_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys)
    assert code == 0
    assert "vigilar" in out
    assert "instantaneas" in out


def test_vigilar_serves_the_config_it_is_given(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    served = []
    monkeypatch.setattr(cli, "serve", lambda config: served.append(config))
    code, out, _ = run(capsys, "vigilar", "--config", config_file)
    assert code == 0
    (config,) = served
    assert config.state_dir == config_file.parent / "state"
    assert "Vigía parado" in out


def test_vigilar_reads_the_default_config_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "serve", lambda config: None)
    code, _, err = run(capsys, "vigilar")  # /etc/vigia/vigia.toml does not exist here
    assert code == 2
    assert "/etc/vigia/vigia.toml" in err


def test_vigilar_with_a_broken_config_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = tmp_path / "vigia.toml"
    broken.write_text("this is = = not toml")
    broken.chmod(0o600)
    code, _, err = run(capsys, "vigilar", "--config", broken)
    assert code == 2
    assert err.startswith("ERROR: ")


def test_a_config_the_rewind_would_break_prints_its_notice_and_exits_cleanly(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    error = UnrewindableConfig([RewindProblem("channels.whatsapp", "cannot be rewound")])

    def serve(config: object) -> None:
        raise error

    monkeypatch.setattr(cli, "serve", serve)
    code, out, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 2
    assert error.notice in err
    assert "Traceback" not in err + out
    assert "Vigía parado" not in out  # it never ran


def test_a_second_service_is_refused_with_the_reason(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise ServiceLocked("Ya hay un `vigia vigilar` en marcha")

    monkeypatch.setattr(cli, "serve", serve)
    code, _, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 1
    assert "Ya hay un `vigia vigilar` en marcha" in err


def test_an_unusable_telegram_file_is_a_config_error(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise ConfigError("Telegram settings file x is open to group or others: chmod 600 it")

    monkeypatch.setattr(cli, "serve", serve)
    code, out, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 2
    assert "configuración no válida" in err and "chmod 600" in err
    assert "error inesperado" not in err and "Traceback" not in err + out


def test_a_black_box_that_cannot_be_used_is_an_error_not_a_traceback(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise BlackBoxError("disk full")

    monkeypatch.setattr(cli, "serve", serve)
    code, _, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 1
    assert "caja negra" in err
    assert "disk full" in err
    assert "Traceback" not in err


def test_a_black_box_error_that_stopped_the_agent_says_so(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        error = BlackBoxError("key file is open to group or others")
        error.add_note("Se ha parado al agente que estaba en marcha.")
        raise error

    monkeypatch.setattr(cli, "serve", serve)
    code, _, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 1
    assert "Se ha parado al agente que estaba en marcha." in err


def test_an_unexpected_failure_says_it_is_unknown_if_the_agent_runs_and_how_to_check(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise ZeroDivisionError("a bug")

    monkeypatch.setattr(cli, "serve", serve)
    code, _, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 1
    assert "no se sabe si el agente sigue en marcha" in err.lower()
    assert "docker ps" in err
    assert "vigia-agente" in err  # the container name of this config


def test_an_agent_that_keeps_running_is_said_loudly(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise JailError("the agent is still running after stop, kill and remove")

    monkeypatch.setattr(cli, "serve", serve)
    code, out, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 1
    assert "SIGUE EN MARCHA" in err
    assert "Vigía parado" not in out


def test_an_unexpected_failure_is_logged_with_its_traceback_and_exits_with_1(
    config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    def serve(config: object) -> None:
        raise ZeroDivisionError("a bug")

    monkeypatch.setattr(cli, "serve", serve)
    code, _, err = run(capsys, "vigilar", "--config", config_file)
    assert code == 1
    assert "error inesperado" in err.lower()
    assert any(record.exc_info for record in caplog.records)  # nothing is swallowed


def test_control_characters_in_an_error_cannot_rewrite_the_terminal(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def serve(config: object) -> None:
        raise BlackBoxError("\x1b[2J fake")

    monkeypatch.setattr(cli, "serve", serve)
    _, _, err = run(capsys, "vigilar", "--config", config_file)
    assert "\x1b" not in err


# --- instantaneas ------------------------------------------------------------------------------


def snap(minutes_ago: float, reason: str = "periodic") -> Snapshot:
    return Snapshot(NOW - timedelta(minutes=minutes_ago), reason)


class FakeStore:
    listed: list[Snapshot] = []
    error: Exception | None = None
    roots: list[Path] = []

    def __init__(self, root: Path, **kwargs: object) -> None:
        FakeStore.roots.append(root)

    def snapshots(self) -> list[Snapshot]:
        if FakeStore.error is not None:
            raise FakeStore.error
        return list(FakeStore.listed)  # oldest first, like the real store


@pytest.fixture
def fake_store(monkeypatch: pytest.MonkeyPatch) -> type[FakeStore]:
    FakeStore.listed = []
    FakeStore.error = None
    FakeStore.roots = []
    monkeypatch.setattr(cli, "SnapshotStore", FakeStore)
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    monkeypatch.setattr(cli, "_local_tz", lambda: timezone(timedelta(hours=2)))
    return FakeStore


def test_instantaneas_lists_the_newest_first_with_local_time_reason_and_age(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_store.listed = [snap(90), snap(10), snap(0.5, "pre_restore")]
    code, out, _ = run(capsys, "instantaneas", "--config", config_file)
    assert code == 0
    lines = out.strip().splitlines()
    assert lines[0].split() == ["INSTANTÁNEA", "HORA", "MOTIVO", "HACE"]
    assert [line.split()[0] for line in lines[1:]] == [
        snap(0.5, "pre_restore").id,
        snap(10).id,
        snap(90).id,
    ]
    assert "antes de rebobinar" in lines[1]
    assert "hace unos segundos" in lines[1]
    assert "periódica" in lines[2]
    assert "hace 10 min" in lines[2]
    assert "hace 1 h" in lines[3]
    # 2026-10-16 12:00 UTC minus 10 min, in UTC+2:
    assert "2026-10-16 13:50:00" in lines[2]
    assert fake_store.roots == [config_file.parent / "vol"]


def test_instantaneas_shows_the_30_newest_and_says_how_many_more(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_store.listed = [snap(minutes) for minutes in range(40, 0, -1)]  # 40 of them
    code, out, _ = run(capsys, "instantaneas", "--config", config_file)
    assert code == 0
    lines = out.strip().splitlines()
    assert len(lines) == 1 + 30 + 1
    assert lines[1].split()[0] == snap(1).id
    assert "10 más" in lines[-1]
    assert "--todas" in lines[-1]


def test_instantaneas_todas_shows_every_one(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_store.listed = [snap(minutes) for minutes in range(40, 0, -1)]
    code, out, _ = run(capsys, "instantaneas", "--config", config_file, "--todas")
    assert code == 0
    assert len(out.strip().splitlines()) == 1 + 40
    assert "más" not in out


def test_instantaneas_with_none_says_so(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, "instantaneas", "--config", config_file)
    assert code == 0
    assert "No hay instantáneas" in out


def test_an_unknown_reason_is_shown_as_it_is_and_escaped(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_store.listed = [snap(5, "from_the_future")]
    _, out, _ = run(capsys, "instantaneas", "--config", config_file)
    assert "from_the_future" in out


def test_a_snapshot_dated_in_the_future_is_flagged_not_hidden(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_store.listed = [snap(-30)]
    _, out, _ = run(capsys, "instantaneas", "--config", config_file)
    assert "en el futuro" in out


def test_instantaneas_that_cannot_read_the_store_exits_with_2(
    config_file: Path, fake_store: type[FakeStore], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_store.error = SnapshotError("cannot list /x/snapshots: Permission denied")
    code, out, err = run(capsys, "instantaneas", "--config", config_file)
    assert code == 2
    assert "Permission denied" in err
    assert out == ""


def test_instantaneas_with_a_broken_config_exits_with_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(capsys, "instantaneas", "--config", tmp_path / "nope.toml")
    assert code == 2
    assert "ERROR" in err


def test_instantaneas_does_not_need_the_service(
    config_file: Path, fake_store: type[FakeStore], monkeypatch: pytest.MonkeyPatch
) -> None:
    """It reads the store directly: it never takes the service lock or opens the black box."""
    monkeypatch.setattr(
        cli, "serve", lambda config: pytest.fail("instantaneas started the service")
    )
    assert main(["instantaneas", "--config", str(config_file)]) == 0
    assert not (config_file.parent / "state" / "vigia.lock").exists()


def test_a_snapshot_reason_has_a_spanish_name_for_every_known_reason() -> None:
    for reason in Reason:
        assert cli.REASON_NAMES[str(reason)]


# --- seguir (T04d-2) ---------------------------------------------------------------------------


def test_seguir_is_in_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert "seguir" in run(capsys)[1]


def test_seguir_hands_the_config_to_the_command_and_returns_its_code(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = []

    def fake(config: object) -> int:
        seen.append(config)
        return 3

    monkeypatch.setattr(cli, "seguir", fake)
    code, _, _ = run(capsys, "seguir", "--config", config_file)
    assert code == 3
    (config,) = seen
    assert config.state_dir == config_file.parent / "state"  # type: ignore[attr-defined]


def test_seguir_with_a_bad_config_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(capsys, "seguir", "--config", tmp_path / "missing.toml")
    assert code == 2
    assert "configuración no válida" in err


def test_seguir_without_a_service_says_so(
    config_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(capsys, "seguir", "--config", config_file)
    assert code == 1
    assert "vigia vigilar" in err
