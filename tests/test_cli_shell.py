"""`backtide entrar`, `tarea`, `importar` and `exportar` (T17a-4, backtide/shell_cli.py): the
docker commands they run, what they ask the service first, and every refusal. The service is a
fake ``ask_shell``/``ask_export``, and docker a fake ``docker.run`` (the VM test runs them for
real: tests/integration/test_claude_code.py)."""

import io
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from backtide import shell_cli
from backtide.cli import main
from backtide.jail import docker
from backtide.jail.profiles.claude_code import CLAUDE, SEED
from backtide.service.config import ServiceConfig
from backtide.service.control import ControlUnavailable

PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
READY = {
    "ok": True,
    "outcome": "ready",
    "message": "",
    "container": "backtide-agente",
    "user": "61000:61000",
    "workdir": "/workspace/work",
}
SETTINGS = ["--dangerously-skip-permissions", "--settings", "/config/claude.json"]


def write_config(tmp_path: Path, profile: str = "claude-code") -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    (state / "gateway.token").write_text("T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2 + "\n")
    (state / "gateway.token").chmod(0o600)
    path = tmp_path / "backtide.toml"
    path.write_text(
        f'state_dir = "{state}"\nvolume = "{tmp_path / "vol"}"\n'
        f'[agent]\nprofile = "{profile}"\n[proxy]\n{PROVIDER}'
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    return ServiceConfig.from_file(write_config(tmp_path))


class Calls:
    def __init__(self) -> None:
        self.asked: list[tuple[str, dict[str, Any]]] = []
        self.runs: list[tuple[list[str], dict[str, Any]]] = []
        self.reply: dict[str, Any] = dict(READY)
        self.results: list[subprocess.CompletedProcess[str]] = []

    def ask_shell(self, path: Path, kind: str, **options: Any) -> dict[str, Any]:
        self.asked.append((kind, options))
        return self.reply

    def run(self, args: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        self.runs.append((list(args), options))
        if self.results:
            return self.results.pop(0)
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    made = Calls()
    monkeypatch.setattr(shell_cli, "ask_shell", made.ask_shell)
    monkeypatch.setattr(docker, "run", made.run)
    return made


PREFIX = ["exec", "--user", "61000:61000", "--workdir", "/workspace/work", "backtide-agente"]


# --- refusals common to the four ----------------------------------------------------------------


@pytest.mark.parametrize(
    "argv", [["entrar"], ["tarea", "hola"], ["importar", "/srv"], ["exportar", "/srv/x"]]
)
def test_a_service_mode_agent_is_refused_with_a_clear_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], calls: Calls, argv: list[str]
) -> None:
    path = write_config(tmp_path, "openclaw")
    code = main([*argv, "--config", str(path)])
    err = capsys.readouterr().err
    assert code == 2 and "no es de modo shell" in err and "claude-code" in err
    assert calls.asked == [] and calls.runs == []


@pytest.mark.parametrize("argv", [["entrar"], ["tarea", "hola"]])
def test_without_a_service_nothing_runs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    calls: Calls,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:
    def unavailable(*args: object, **options: object) -> dict[str, Any]:
        raise ControlUnavailable("nobody")

    monkeypatch.setattr(shell_cli, "ask_shell", unavailable)
    code = main([*argv, "--config", str(write_config(tmp_path))])
    assert code == 1 and "backtide vigilar" in capsys.readouterr().err
    assert calls.runs == []


def test_a_refusal_of_the_service_is_said_and_nothing_runs(
    config: ServiceConfig, calls: Calls, capsys: pytest.CaptureFixture[str]
) -> None:
    calls.reply = {"ok": False, "outcome": "not_running", "message": "El agente está en pausa."}
    assert shell_cli.tarea(config, "hola") == 1
    assert "El agente está en pausa." in capsys.readouterr().err
    assert calls.runs == []


def test_a_bad_config_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["entrar", "--config", str(tmp_path / "missing.toml")])
    assert code == 2 and "configuración no válida" in capsys.readouterr().err


# --- entrar -------------------------------------------------------------------------------------


def test_entrar_seeds_then_opens_the_interactive_session(
    config: ServiceConfig, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[list[str]] = []
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(shell_cli.sys.stdin, "isatty", lambda: False)
    code = shell_cli.entrar(config, resume=True, run=lambda argv: opened.append(argv) or 0)
    assert code == 0
    assert calls.asked == [("session", {"resume": True})]
    ((seed, options),) = calls.runs
    assert seed == [*PREFIX[:1], "--interactive", *PREFIX[1:], "python3", "-I", "-"]
    assert options["input"] == SEED and options["check"] is False
    assert opened == [
        [*PREFIX[:1], "--interactive", "--env", "TERM=xterm-256color", *PREFIX[1:], CLAUDE,
         *SETTINGS, "--continue"]
    ]  # fmt: skip


def test_entrar_takes_a_tty_only_with_a_terminal_and_a_safe_term(
    config: ServiceConfig, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[list[str]] = []
    monkeypatch.setenv("TERM", "x\x1b]0;evil\x07")
    monkeypatch.setattr(shell_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(shell_cli.sys.stdout, "isatty", lambda: True)
    shell_cli.entrar(config, run=lambda argv: opened.append(argv) or 0)
    assert "--tty" in opened[0]
    assert not any(arg.startswith("TERM=") for arg in opened[0])
    assert opened[0][-1] == "/config/claude.json"  # no --continue


def test_a_failed_seed_opens_nothing(
    config: ServiceConfig, calls: Calls, capsys: pytest.CaptureFixture[str]
) -> None:
    calls.results = [subprocess.CompletedProcess([], 1, "", "backtide: ~/.claude.json is not\x1b")]
    opened: list[list[str]] = []
    assert shell_cli.entrar(config, run=lambda argv: opened.append(argv) or 0) == 1
    err = capsys.readouterr().err
    assert "primeros pasos" in err and "\x1b" not in err
    assert opened == []


def test_a_session_cut_by_a_rewind_says_how_to_go_back(
    config: ServiceConfig, calls: Calls, capsys: pytest.CaptureFixture[str]
) -> None:
    assert shell_cli.entrar(config, run=lambda argv: 137) == 1
    assert "--continue" in capsys.readouterr().err


# --- tarea --------------------------------------------------------------------------------------


def answer(result: str, *, error: bool = False, code: int = 0) -> subprocess.CompletedProcess[str]:
    import json

    body = json.dumps({"type": "result", "is_error": error, "result": result})
    return subprocess.CompletedProcess([], code, body, "")


def test_tarea_runs_claude_p_with_the_prompt_after_dashes(
    config: ServiceConfig, calls: Calls, capsys: pytest.CaptureFixture[str]
) -> None:
    calls.results = [answer("listo\nhecho \x1b[2J")]
    assert shell_cli.tarea(config, "-rf todo", resume=True) == 0
    assert calls.asked == [("task", {"resume": True})]
    ((argv, options),) = calls.runs
    assert argv == [*PREFIX, CLAUDE, "-p", "--output-format", "json", *SETTINGS, "--continue",
                    "--", "-rf todo"]  # fmt: skip
    assert options["timeout"] == 3600 and options["max_output"] == shell_cli.TASK_MAX_OUTPUT
    out = capsys.readouterr().out
    assert "listo\nhecho" in out and "\x1b" not in out


def test_tarea_through_the_cli(tmp_path: Path, calls: Calls) -> None:
    calls.results = [answer("ok")]
    code = main(["tarea", "--config", str(write_config(tmp_path)), "--minutos", "2", "haz x"])
    assert code == 0 and calls.runs[0][1]["timeout"] == 120
    assert calls.runs[0][0][-2:] == ["--", "haz x"]


@pytest.mark.parametrize(
    "result",
    [
        answer("falló", error=True),
        answer("ok", code=1),
        subprocess.CompletedProcess([], 1, "not json", "boom"),
        subprocess.CompletedProcess([], 0, "[]", ""),
    ],
)
def test_a_task_that_went_wrong_exits_with_1(
    config: ServiceConfig, calls: Calls, result: subprocess.CompletedProcess[str]
) -> None:
    calls.results = [result]
    assert shell_cli.tarea(config, "hola") == 1


def test_a_task_that_timed_out_is_unknown(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch, calls: Calls
) -> None:
    def timing_out(*args: object, **options: object) -> None:
        raise docker.JailError("timed out")

    monkeypatch.setattr(docker, "run", timing_out)
    assert shell_cli.tarea(config, "hola") == 3


@pytest.mark.parametrize("prompt", ["", "  ", "a\0b"])
def test_an_empty_or_odd_task_is_refused_before_asking(
    config: ServiceConfig, calls: Calls, prompt: str
) -> None:
    assert shell_cli.tarea(config, prompt) == 2
    assert calls.asked == []


def test_minutes_out_of_range_are_refused(config: ServiceConfig, calls: Calls) -> None:
    assert shell_cli.tarea(config, "hola", minutes=0) == 2
    assert shell_cli.tarea(config, "hola", minutes=10_000) == 2
    assert calls.asked == []


# --- importar -----------------------------------------------------------------------------------


class FakePopen:
    """``docker exec -i ... tar -x``: keeps the stream it got."""

    made: list["FakePopen"] = []

    def __init__(self, argv: list[str], **options: Any) -> None:
        self.argv = argv
        self.stdin = io.BytesIO()
        self.stdin.close = lambda: None  # type: ignore[method-assign]
        self.returncode = 0
        FakePopen.made.append(self)

        self.stderr = io.BytesIO(self.error_text())

    def error_text(self) -> bytes:
        return b""

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def members(self) -> dict[str, tarfile.TarInfo]:
        self.stdin.seek(0)
        with tarfile.open(fileobj=self.stdin, mode="r|") as tar:
            found = {}
            for member in tar:
                found[member.name] = member
            return found


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    folder = tmp_path / "repo"
    (folder / "src").mkdir(parents=True)
    (folder / "README.md").write_text("hola\n")
    (folder / "src" / "main.py").write_text("print(1)\n")
    secret = tmp_path / "secret"
    secret.write_text("no")
    (folder / "src" / "fuera").symlink_to(secret)
    (folder / "todo").symlink_to(tmp_path)
    os.mkfifo(folder / "pipe")
    return folder


def run_import(config: ServiceConfig, source: Path, **options: Any) -> int:
    FakePopen.made = []
    return shell_cli.importar(config, str(source), popen=FakePopen, **options)


def test_importar_streams_files_and_folders_and_names_what_it_skipped(
    config: ServiceConfig, calls: Calls, repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_import(config, repo) == 0
    ((kind, options),) = calls.asked
    assert kind == "import"
    assert options["import_details"] == {
        "name": "repo", "source": str(repo), "files": 2, "bytes": 14, "replace": False,
    }  # fmt: skip
    ((mkdir, _),) = calls.runs
    assert mkdir == [*PREFIX, "mkdir", "--", "/workspace/work/repo"]
    (process,) = FakePopen.made
    assert process.argv == [
        docker.PROGRAM, "exec", "--interactive", *PREFIX[1:], "tar", "-x", "--keep-old-files",
        "-f", "-", "--no-same-owner", "-C", "/workspace/work/repo",
    ]  # fmt: skip
    members = process.members()
    assert set(members) == {"src", "README.md", "src/main.py"}
    assert all(member.isfile() or member.isdir() for member in members.values())
    out = capsys.readouterr().out
    assert "2 archivos" in out
    assert "pipe" in out and "src/fuera" in out and "todo" in out  # what it skipped, by name


def test_importar_with_reemplazar_and_another_name(
    config: ServiceConfig, calls: Calls, repo: Path
) -> None:
    assert run_import(config, repo, name="proyecto", replace=True) == 0
    assert calls.runs[0][0][-3:] == ["-p", "--", "/workspace/work/proyecto"]
    assert "--keep-old-files" not in FakePopen.made[0].argv


def test_an_existing_folder_is_not_written_over(
    config: ServiceConfig, calls: Calls, repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls.results = [subprocess.CompletedProcess([], 1, "", "mkdir: cannot create: File exists")]
    assert run_import(config, repo) == 1
    assert "--reemplazar" in capsys.readouterr().err
    assert FakePopen.made == []


def test_a_source_that_is_a_link_is_refused(
    config: ServiceConfig, calls: Calls, repo: Path, tmp_path: Path
) -> None:
    link = tmp_path / "link"
    link.symlink_to(repo)
    assert run_import(config, link) == 2
    assert calls.asked == []


def test_too_big_is_refused_before_asking(
    config: ServiceConfig, calls: Calls, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shell_cli, "MAX_IMPORT_BYTES", 5)
    assert run_import(config, repo) == 2
    assert calls.asked == []


@pytest.mark.parametrize("name", ["..", ".hidden", "a/b", "", "x" * 101])
def test_an_odd_name_in_the_agent_is_refused(
    config: ServiceConfig, calls: Calls, repo: Path, name: str
) -> None:
    assert run_import(config, repo, name=name) == 2
    assert calls.asked == []


def test_a_tar_that_fails_is_half_done(
    config: ServiceConfig, calls: Calls, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Failing(FakePopen):
        def error_text(self) -> bytes:
            return b"tar: Cannot open: File exists"

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = 2
            return 2

    assert shell_cli.importar(config, str(repo), popen=Failing) == 3


# --- exportar -----------------------------------------------------------------------------------


def test_exportar_asks_the_service_with_an_absolute_path(
    config: ServiceConfig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asked: list[str] = []

    def ask_export(path: Path, destination: str) -> dict[str, Any]:
        asked.append(destination)
        return {
            "ok": True, "outcome": "done", "message": "", "destination": destination,
            "snapshot": "s", "details": {"files": 3, "folders": 1, "bytes": 10,
                                         "skipped_links": 2, "skipped_other": 0},
        }  # fmt: skip

    monkeypatch.setattr(shell_cli, "ask_export", ask_export)
    monkeypatch.chdir(tmp_path)
    assert shell_cli.exportar(config, "salida") == 0
    assert asked == [str(tmp_path.resolve() / "salida")] or asked == [str(tmp_path / "salida")]
    out = capsys.readouterr().out
    assert "3 archivos" in out and "2 enlaces simbólicos" in out


def test_a_refused_export_is_a_usage_error(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refused(path: Path, destination: str) -> dict[str, Any]:
        return {"ok": False, "outcome": "invalid", "message": "ya existe", "details": {}}

    monkeypatch.setattr(shell_cli, "ask_export", refused)
    assert shell_cli.exportar(config, "/tmp/x") == 2  # noqa: S108
    assert "ya existe" in capsys.readouterr().err
