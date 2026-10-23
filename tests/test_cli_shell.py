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
    "container_id": "ab12" * 16,
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


# By the id of the container the service checked, never by its name (B4).
PREFIX = ["exec", "--user", "61000:61000", "--workdir", "/workspace/work", "ab12" * 16]
TIMEOUT = ["/usr/bin/timeout", "-k", "30"]


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


def test_entrar_puts_the_terminal_back_and_says_where_you_are(
    config: ServiceConfig,
    calls: Calls,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """M1: whatever the session ends with (a cut too), the terminal is restored before our
    fixed line is printed."""
    order: list[str] = []
    monkeypatch.setattr(
        shell_cli, "terminal_guard", lambda fd, out: lambda: order.append("restored")
    )

    def session(argv: list[str]) -> int:
        order.append("session")
        return 137

    assert shell_cli.entrar(config, run=session) == 1
    assert order == ["session", "restored"]
    assert shell_cli.SESSION_CLOSED in capsys.readouterr().out


def test_the_terminal_guard_flushes_pending_input_restores_and_resets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import termios
    import tty

    monkeypatch.setattr(shell_cli, "SETTLE", 0)
    leader, follower = os.openpty()
    try:
        before = termios.tcgetattr(follower)

        class Out(io.StringIO):
            def isatty(self) -> bool:
                return True

        out = Out()
        restore = shell_cli.terminal_guard(follower, out)
        tty.setraw(follower)  # what docker -it leaves if it dies
        os.write(leader, b"\x1b]52;c;ZXZpbA==\x07")  # an answer queued for the owner's shell
        restore()
        after = termios.tcgetattr(follower)
        pendin = getattr(termios, "PENDIN", 0)  # BSD sets it when canonical mode comes back
        assert after[:3] == before[:3] and after[3] & ~pendin == before[3] & ~pendin
        assert after[4:] == before[4:]
        os.set_blocking(follower, False)
        with pytest.raises(BlockingIOError):
            os.read(follower, 100)  # nothing left to type into the owner's shell
        assert out.getvalue() == shell_cli.TERMINAL_RESET
        assert "\x1b[!p" in out.getvalue() and "\x1b[?1049l" in out.getvalue()
        assert "\x1b[?2004l" in out.getvalue() and "\x1b[?1000l" in out.getvalue()
    finally:
        os.close(leader)
        os.close(follower)


def test_without_a_terminal_the_guard_does_nothing() -> None:
    read, write = os.pipe()
    out = io.StringIO()
    try:
        shell_cli.terminal_guard(read, out)()
    finally:
        os.close(read)
        os.close(write)
    assert out.getvalue() == ""


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
    calls.results = [subprocess.CompletedProcess([], 1, "", ""), answer("listo\nhecho \x1b[2J")]
    assert shell_cli.tarea(config, "-rf todo", resume=True) == 0
    probe, _ = calls.runs.pop(0)  # --continue: no other task runs (pgrep finds none)
    assert probe[: len(PREFIX)] == PREFIX and probe[len(PREFIX) : -1] == [
        "pgrep", "-u", "61000", "-f",
    ]  # fmt: skip
    assert calls.asked == [("task", {"resume": True})]
    ((argv, options),) = calls.runs
    assert argv == [*PREFIX, *TIMEOUT, "3600", CLAUDE, "-p", "--output-format", "json",
                    *SETTINGS, "--continue", "--", "-rf todo"]  # fmt: skip
    assert options["timeout"] > 3600 + 30 and options["max_output"] == shell_cli.TASK_MAX_OUTPUT
    out = capsys.readouterr().out
    assert "listo\nhecho" in out and "\x1b" not in out


def test_tarea_through_the_cli(tmp_path: Path, calls: Calls) -> None:
    calls.results = [answer("ok")]
    code = main(["tarea", "--config", str(write_config(tmp_path)), "--minutos", "2", "haz x"])
    assert code == 0 and calls.runs[0][0][len(PREFIX) : len(PREFIX) + 4] == [*TIMEOUT, "120"]
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


def test_a_task_this_side_gave_up_on_is_stopped_inside(
    config: ServiceConfig,
    monkeypatch: pytest.MonkeyPatch,
    calls: Calls,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """M4: the docker CLI timed out (or broke), so the task may run on: a TERM to its timeout,
    as the agent, by the pattern of the task, and the outcome is unknown (3)."""
    real = calls.run

    def timing_out(args: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        if "claude" in " ".join(args) and "pkill" not in args:
            calls.runs.append((list(args), options))
            raise docker.JailError("timed out")
        return real(args, **options)

    monkeypatch.setattr(docker, "run", timing_out)
    assert shell_cli.tarea(config, "hola") == 3
    (_, _), (kill, _) = calls.runs
    assert kill[: len(PREFIX)] == PREFIX
    assert kill[len(PREFIX) :] == [
        "pkill", "-TERM", "-u", "61000", "-f", shell_cli._task_pattern(config.agent_profile.shell),  # noqa: SLF001
    ]  # fmt: skip
    assert "Se ha parado dentro del agente" in capsys.readouterr().err


def test_the_task_pattern_finds_the_task_and_only_it() -> None:
    import re

    from backtide.jail.profiles import CLAUDE_CODE

    pattern = re.compile(shell_cli._task_pattern(CLAUDE_CODE.shell))  # noqa: SLF001
    task = " ".join(["/usr/bin/timeout", "-k", "30", "3600", CLAUDE, "-p", "--", "hola"])
    assert pattern.search(task)
    assert not pattern.search(task.replace(".local", "xlocal"))  # the dots are literal
    assert not pattern.search(f"sh -c {task}") and not pattern.search(f"{CLAUDE} -p hola")


@pytest.mark.parametrize(("code", "said"), [(124, "pasó de 60 minutos"), (137, "se ha cortado")])
def test_a_task_cut_by_its_timeout_says_so(
    config: ServiceConfig,
    calls: Calls,
    capsys: pytest.CaptureFixture[str],
    code: int,
    said: str,
) -> None:
    calls.results = [subprocess.CompletedProcess([], code, "", "")]
    assert shell_cli.tarea(config, "hola") == 1
    assert said in capsys.readouterr().err


@pytest.mark.parametrize("pgrep", [0, 2])
def test_a_second_continue_waits_for_the_first(
    config: ServiceConfig, calls: Calls, capsys: pytest.CaptureFixture[str], pgrep: int
) -> None:
    """M4: with a task running (pgrep finds it), or when that cannot be said, --continue does
    not start a second run of the same conversation."""
    calls.results = [subprocess.CompletedProcess([], pgrep, "", "")]
    assert shell_cli.tarea(config, "sigue", resume=True) == 1
    assert len(calls.runs) == 1 and calls.runs[0][0][len(PREFIX)] == "pgrep"
    assert "tarea en marcha" in capsys.readouterr().err


def test_a_new_conversation_does_not_wait(config: ServiceConfig, calls: Calls) -> None:
    calls.results = [answer("ok")]
    assert shell_cli.tarea(config, "otra") == 0
    assert len(calls.runs) == 1  # no pgrep: only --continue shares a conversation


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
        self.killed = False
        FakePopen.made.append(self)
        options["stderr"].write(self.error_text())  # a file: nothing has to read it meanwhile

    def error_text(self) -> bytes:
        return b""

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

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
        "secrets_left_out": 0, "include_secrets": False,
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


def test_a_tar_that_stalls_is_killed_at_the_deadline(
    config: ServiceConfig,
    calls: Calls,
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B3: the whole import has one deadline, the writing included (a tar that stops reading
    would block the write for ever): past it the docker CLI is killed and the write fails."""
    import threading

    monkeypatch.setattr(shell_cli, "IMPORT_TIMEOUT", 0.2)

    class Stalling(FakePopen):
        def __init__(self, argv: list[str], **options: Any) -> None:
            super().__init__(argv, **options)
            self.gone = threading.Event()
            stalling = self

            class Pipe(io.BytesIO):
                def write(self, data: Any) -> int:
                    if not stalling.gone.wait(5):
                        raise AssertionError("never killed")
                    raise BrokenPipeError(32, "Broken pipe")

            self.stdin = Pipe()
            self.stdin.close = lambda: None  # type: ignore[method-assign]

        def kill(self) -> None:
            super().kill()
            self.gone.set()

    assert shell_cli.importar(config, str(repo), popen=Stalling) == 3
    assert FakePopen.made[-1].killed
    assert "se ha pasado el tiempo" in capsys.readouterr().err


# --- importar and secrets (M2) ------------------------------------------------------------------


@pytest.fixture
def secrets_repo(tmp_path: Path) -> Path:
    """A project with what a person's folder often holds: made-up values only."""
    folder = tmp_path / "proyecto"
    (folder / "src").mkdir(parents=True)
    (folder / "src" / "main.py").write_text("print(1)\n")
    (folder / "src" / "id_utils.py").write_text("x = 1\n")  # not a key
    for name in (".env", ".env.local", ".npmrc", ".pypirc", ".netrc", "id_ed25519", "cert.PEM",
                 "server.key", "store.p12", ".git-credentials", "credentials.json"):  # fmt: skip
        (folder / name).write_text("made-up\n")
    for folder_name in (".aws", ".ssh", ".gnupg"):
        (folder / folder_name).mkdir()
        (folder / folder_name / "inside").write_text("made-up\n")
    git = folder / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "config").write_text(
        '[remote "origin"]\n\turl = https://bob:hunter2@example.invalid/r.git\n'
    )
    return folder


def test_what_looks_like_a_secret_is_left_out_and_named(
    config: ServiceConfig, calls: Calls, secrets_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_import(config, secrets_repo) == 0
    members = set(FakePopen.made[0].members())
    assert members == {"src", "src/main.py", "src/id_utils.py", ".git", ".git/HEAD"}
    details = calls.asked[0][1]["import_details"]
    assert details["secrets_left_out"] == 15 and details["include_secrets"] is False
    out = capsys.readouterr().out
    assert "parecen secretos" in out and "--incluir-secretos" in out
    assert ".git/config" in out and ".env" in out and ".aws" in out
    assert "hunter2" not in out


def test_incluir_secretos_takes_them(
    config: ServiceConfig, calls: Calls, secrets_repo: Path
) -> None:
    assert run_import(config, secrets_repo, include_secrets=True) == 0
    members = set(FakePopen.made[0].members())
    assert {".env", ".aws/inside", ".git/config", "id_ed25519"} <= members
    assert calls.asked[0][1]["import_details"]["include_secrets"] is True


@pytest.mark.parametrize(
    ("config_text", "secret"),
    [
        ('[remote "o"]\n\turl = git@github.com:me/r.git\n', False),
        ('[remote "o"]\n\turl = ssh://git@example.invalid/r.git\n', False),
        ('[remote "o"]\n\turl = https://example.invalid/r.git\n', False),
        ('[remote "o"]\n\turl = https://x-access-token:abc@example.invalid/r\n', True),
        ('[remote "o"]\n\turl = https://ghp_' + "A" * 36 + "@example.invalid/r\n", True),
        ('[http "https://example.invalid/"]\n\textraheader = AUTHORIZATION: basic eA==\n', True),
    ],
)
def test_a_git_config_is_left_out_only_with_credentials(
    tmp_path: Path, config_text: str, secret: bool
) -> None:
    folder = tmp_path / "r"
    (folder / ".git").mkdir(parents=True)
    (folder / ".git" / "config").write_text(config_text)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        plan = shell_cli.plan_import(fd)
    finally:
        os.close(fd)
    assert (plan.secrets == [".git/config"]) is secret


GHP = "ghp_" + "A" * 36  # made up
GH_ENV = '{"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "' + GHP + '"}}}}'
NPX = '{"x": {"command": "npx", "args": ["-y", "@scope/server", "--port", "3"]}}'
CODEX_GH = '[mcp_servers.gh]\ncommand = "npx"\nenv = { GITHUB_TOKEN = "' + GHP + '" }\n'


@pytest.mark.parametrize(
    ("path", "text", "secret"),
    [
        (".mcp.json", GH_ENV, True),
        (".mcp.json", '{"mcpServers": {"gh": {"env": {"GH_TOKEN": "${GITHUB_TOKEN}"}}}}', False),
        (".mcp.json", '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg"]}}}', False),
        (".mcp.json", '{"x": {"headers": {"Authorization": "Bearer abcdefgh12345"}}}', True),
        (".mcp.json", '{"x": {"env": {"OPENAI_API_KEY": "plain"}}}', True),
        (".mcp.json", '{"x": {"env": {"SLACK": "xoxb-1234567890-abc"}}}', True),
        (".mcp.json", '{"x": {"env": {"DB_PASSWORD": 1234}}}', True),
        (".mcp.json", '{"x": {"env": {"API_TOKEN": ""}}}', False),
        (".mcp.json", '{"x": {"url": "https://bob:hunter2@example.invalid/mcp"}}', True),
        (".mcp.json", "not json {", True),
        ("sub/.MCP.json", GH_ENV, True),
        (".claude.json", '{"primaryApiKey": "sk-ant-' + "a" * 30 + '"}', True),
        (".claude.json", '{"numStartups": 3, "projects": {"/w": {"allowedTools": []}}}', False),
        (".claude.json.backup", GH_ENV, True),
        (".claude/settings.local.json", '{"env": {"ANTHROPIC_AUTH_TOKEN": "abc"}}', True),
        (".claude/settings.local.json", '{"apiKeyHelper": "~/bin/key.sh"}', True),  # fail closed
        (".claude/settings.local.json", '{"apiKeyHelper": "echo sk-ant-' + "b" * 30 + '"}', True),
        ("sub/.Claude/Settings.Local.JSON", '{"env": {"GH_TOKEN": "' + GHP + '"}}', True),
        (".claude/settings.json", '{"permissions": {"allow": ["Bash(ls)"]}}', False),
        (".claude/settings.json", '{"env": {"GITHUB_PAT": "github_pat_' + "c" * 30 + '"}}', True),
        (".cursor/mcp.json", GH_ENV, True),
        (".VSCode/mcp.json", GH_ENV, True),
        # M2 of the review: the shapes MCP configs take
        (".mcp.json", '{"x": {"args": ["-y", "--api-key", "abcd1234efgh5678"]}}', True),
        (".mcp.json", '{"x": {"args": ["--token=abcd1234"]}}', True),
        (".mcp.json", '{"x": {"DB_PASS": "p"}}', True),
        (".mcp.json", '{"x": {"OPENAI_KEY": "k"}}', True),
        (".mcp.json", '{"x": {"TOKEN_GITHUB": "t"}}', True),
        (".mcp.json", '{"x": {"GH_CREDENTIALS": "c"}}', True),
        (".mcp.json", '{"x": {"X_AUTH": "a"}}', True),
        (".mcp.json", '{"x": {"env": {"LOG_LEVEL": "debug"}}}', True),  # all of env
        (".mcp.json", '{"x": {"env": {"PORT": 8080}}}', True),
        (".mcp.json", '{"x": {"Env": {"A": "${A}", "B": "${B}"}}}', False),
        (".mcp.json", '{"x": {"env": {"A": "${A}x"}}}', True),
        (".mcp.json", '{"x": {"headers": ["X-Thing: y"]}}', True),
        (".mcp.json", '{"x": {"Headers": {"X-Custom": "abc"}}}', True),
        (".mcp.json", '{"x": [{"Name": "Authorization", "Value": "abc"}]}', True),
        (".mcp.json", '{"x": [["X-Api-Key", "abc"]]}', True),
        (".mcp.json", '{"apiKey": ["abc"]}', True),
        (".mcp.json", '{"apiKey": {"value": "abc"}}', True),
        (".mcp.json", NPX, False),
        # B2: only ${VAR} is a reference
        (".mcp.json", '{"x": {"env": {"A": "$A"}}}', True),
        (".mcp.json", '{"x": {"GH_TOKEN": "$ecretPassw0rd"}}', True),
        # B1: a repeated key, the first one with the secret
        (".mcp.json", '{"API_TOKEN": "plain", "API_TOKEN": "${X}"}', True),
        (".mcp.json", '{"x": {"env": {"A": "lit"}}, "x": {"command": "npx"}}', True),
        # M3: other agents' configs
        (".gemini/settings.json", GH_ENV, True),
        (".gemini/settings.json", '{"theme": "Default"}', False),
        ("claude_desktop_config.json", GH_ENV, True),
        ("sub/Claude_Desktop_Config.json", '{"mcpServers": {}}', False),
        ("mcp_config.json", GH_ENV, True),
        (".codex/config.toml", CODEX_GH, True),
        (".codex/config.toml", '[mcp_servers.gh]\nenv = { LOG = "debug" }\n', True),
        (".codex/config.toml", 'model = "o3"\n[mcp_servers.gh]\ncommand = "npx"\n', False),
        (".codex/config.toml", "not = = toml", True),
        (".Codex/Config.TOML", 'token = "abc"\n', True),
    ],
)  # fmt: skip
def test_an_agent_config_is_left_out_only_with_a_secret_inside(
    tmp_path: Path, path: str, text: str, secret: bool
) -> None:
    """Finding 6 of the final review: `.mcp.json` (an MCP server's `env`), `.claude.json` and
    `.claude/settings*.json` often hold a real token. Read like a `.git/config`: left out with
    a secret-shaped value (backtide's redact shapes, or a secret name with a literal value),
    imported without one (an env reference such as `${GITHUB_TOKEN}` is not a secret)."""
    folder = tmp_path / "r"
    (folder / path).parent.mkdir(parents=True, exist_ok=True)
    (folder / path).write_text(text)
    (folder / "main.py").write_text("print(1)\n")
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        plan = shell_cli.plan_import(fd)
        assert (plan.secrets == [path]) is secret
        assert ("main.py", 9) in plan.files
        everything = shell_cli.plan_import(fd, include_secrets=True)
        assert everything.secrets == [] and path in {rel for rel, _ in everything.files}
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "path", [".credentials.json", ".claude/.credentials.json", "a/.Credentials.JSON"]
)
def test_a_credentials_file_is_left_out_by_its_name(tmp_path: Path, path: str) -> None:
    folder = tmp_path / "r"
    (folder / path).parent.mkdir(parents=True, exist_ok=True)
    (folder / path).write_text("{}")
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert shell_cli.plan_import(fd).secrets == [path]
    finally:
        os.close(fd)


@pytest.mark.parametrize("same_size", [False, True])
def test_a_scanned_config_that_changes_before_the_copy_is_refused(
    tmp_path: Path, same_size: bool
) -> None:
    """B3 of the review: what is copied is what was read. A ``.mcp.json`` that was clean when
    it was planned and changed before the tar (even to the same size and time) fails."""
    folder = tmp_path / "r"
    folder.mkdir()
    config_file = folder / ".mcp.json"
    config_file.write_text('{"mcpServers": {"a": {"command": "npx"}}}')
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        plan = shell_cli.plan_import(fd)
        assert plan.secrets == [] and ".mcp.json" in plan.scanned
        before = config_file.stat()
        changed = '{"mcpServers": {"a": {"command": "npm"}}}' if same_size else GH_ENV
        config_file.write_text(changed)
        if same_size:
            os.utime(config_file, ns=(before.st_atime_ns, before.st_mtime_ns))
        with pytest.raises(shell_cli.ImportRefused, match="ha cambiado"):
            shell_cli.write_tar(fd, plan, io.BytesIO())
    finally:
        os.close(fd)


def test_a_scanned_config_that_did_not_change_is_copied(tmp_path: Path) -> None:
    folder = tmp_path / "r"
    folder.mkdir()
    (folder / ".mcp.json").write_text('{"mcpServers": {}}')
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        plan = shell_cli.plan_import(fd)
        out = io.BytesIO()
        shell_cli.write_tar(fd, plan, out)
    finally:
        os.close(fd)
    out.seek(0)
    with tarfile.open(fileobj=out) as tar:
        assert tar.getnames() == [".mcp.json"]


def test_a_scanned_git_config_whose_times_moved_is_copied_as_it_was_read(tmp_path: Path) -> None:
    """On the folder Lima shares with the Mac, reading a file moves its ctime: the check is by
    content, so a git config read again (or touched) with the same bytes still goes in, and
    what goes in is exactly what was reviewed (2026-10-23, the founder's first import)."""
    folder = tmp_path / "r"
    (folder / ".git").mkdir(parents=True)
    config_file = folder / ".git" / "config"
    text = '[remote "origin"]\n\turl = https://github.com/o/r.git\n'
    config_file.write_text(text)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        plan = shell_cli.plan_import(fd)
        assert plan.secrets == [] and ".git/config" in plan.scanned
        config_file.chmod(0o600)  # moves the ctime
        os.utime(config_file)  # and the mtime
        out = io.BytesIO()
        shell_cli.write_tar(fd, plan, out)
    finally:
        os.close(fd)
    out.seek(0)
    with tarfile.open(fileobj=out) as tar:
        member = tar.extractfile(".git/config")
        assert member is not None and member.read() == text.encode()


def test_an_agent_config_too_big_to_read_is_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "r"
    folder.mkdir()
    (folder / ".mcp.json").write_text('{"mcpServers": {}, "pad": "' + "x" * 100 + '"}')
    monkeypatch.setattr(shell_cli, "MAX_AGENT_CONFIG", 50)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert shell_cli.plan_import(fd).secrets == [".mcp.json"]
    finally:
        os.close(fd)


def test_an_agent_config_with_a_token_is_named_and_never_printed(
    config: ServiceConfig, calls: Calls, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "proyecto"
    folder.mkdir()
    (folder / ".mcp.json").write_text(GH_ENV)
    (folder / "main.py").write_text("print(1)\n")
    assert run_import(config, folder) == 0
    assert set(FakePopen.made[0].members()) == {"main.py"}
    out = capsys.readouterr().out
    assert ".mcp.json" in out and "--incluir-secretos" in out and GHP not in out


def test_bytes_are_counted_as_files_are_added(repo: Path) -> None:
    fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY)
    try:
        plan = shell_cli.plan_import(fd)
    finally:
        os.close(fd)
    assert plan.bytes == sum(size for _, size in plan.files) == 14


@pytest.mark.parametrize(
    "where", ["home", "above", ".ssh", ".ssh/keys", ".aws", ".claude", ".Claude/x"]
)
def test_the_owners_home_and_key_folders_are_never_a_source(
    config: ServiceConfig,
    calls: Calls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    where: str,
) -> None:
    home = tmp_path / "casa"
    (home / ".ssh" / "keys").mkdir(parents=True)
    (home / ".aws").mkdir()
    (home / ".claude" / "x").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    source = {"home": home, "above": tmp_path}.get(where, home / where)
    assert run_import(config, source, include_secrets=True) == 2
    assert calls.asked == [] and FakePopen.made == []
    err = capsys.readouterr().err
    assert "carpeta personal" in err or "no se importa nunca" in err


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
    assert shell_cli.EXPORTED_WARNING in out  # A1: what left was written by the agent


def test_exportar_names_what_it_left_out_and_how_commits_leave(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def ask_export(path: Path, destination: str) -> dict[str, Any]:
        return {
            "ok": True, "outcome": "done", "message": "", "destination": destination,
            "snapshot": "s",
            "details": {"files": 1, "skipped_git": 2, "skipped_names": 1, "skipped_collisions": 1},
            "skipped": [["git", "proyecto/.git"], ["git", "vendor/x"], ["name", "a\\x1b"],
                        ["case", "README"]],
        }  # fmt: skip

    monkeypatch.setattr(shell_cli, "ask_export", ask_export)
    assert shell_cli.exportar(config, "/srv/out") == 0
    out = capsys.readouterr().out
    assert "2 repositorios de git" in out and "proyecto/.git, vendor/x" in out
    assert "--git" in out and "a\\x1b" in out and "mayúsculas" in out and "README" in out


def test_exportar_names_what_the_owners_tools_would_run_and_says_why(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding 5 of the final review: `.claude/`, `.mcp.json`, `.vscode/`... stay in the jail,
    and the owner is told which and how to take them."""

    def ask_export(path: Path, destination: str) -> dict[str, Any]:
        return {
            "ok": True, "outcome": "done", "message": "", "destination": destination,
            "snapshot": "s", "details": {"files": 1, "skipped_config": 3},
            "skipped": [["config", ".claude"], ["config", "sub/.mcp.json"]],
        }  # fmt: skip

    monkeypatch.setattr(shell_cli, "ask_export", ask_export)
    assert shell_cli.exportar(config, "/srv/out") == 0
    out = capsys.readouterr().out
    assert "Sin copiar: 3 archivos o carpetas que tus herramientas pueden ejecutar" in out
    assert ".claude, sub/.mcp.json y 1 más" in out and "--incluir-config" in out
    assert shell_cli.EXPORTED_WARNING in out and ".mcp.json" in shell_cli.EXPORTED_WARNING


def test_exportar_incluir_config_asks_for_it_and_warns(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    asked: list[dict[str, Any]] = []

    def ask_export(path: Path, destination: str, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return {
            "ok": True, "outcome": "done", "message": "", "destination": destination,
            "snapshot": "s", "details": {"files": 4}, "skipped": [],
        }  # fmt: skip

    monkeypatch.setattr(shell_cli, "ask_export", ask_export)
    assert shell_cli.exportar(config, "/srv/out", include_config=True) == 0
    assert asked == [{"include_config": True}]
    assert shell_cli.INCLUDED_CONFIG_WARNING in capsys.readouterr().out


def test_incluir_config_is_not_for_a_bundle(
    config: ServiceConfig, calls: Calls, capsys: pytest.CaptureFixture[str]
) -> None:
    assert shell_cli.exportar(config, "/srv/p.bundle", git="p", include_config=True) == 2
    assert calls.asked == [] and calls.runs == []
    assert "--incluir-config" in capsys.readouterr().err


def test_exportar_incluir_config_through_the_cli(
    tmp_path: Path, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(
        shell_cli, "exportar", lambda *args, **options: seen.append((args, options)) or 0
    )
    path = str(write_config(tmp_path))
    assert main(["exportar", "--config", path, "--incluir-config", "/srv/out"]) == 0
    assert main(["exportar", "--config", path, "/srv/out2"]) == 0
    assert seen[0][1] == {"git": None, "include_config": True}
    assert seen[1][1] == {"git": None, "include_config": False}


# --- exportar --git (A1) ------------------------------------------------------------------------


def test_exportar_git_has_the_agent_make_a_bundle_inside_and_exports_only_it(
    config: ServiceConfig,
    calls: Calls,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asked: list[tuple[str, dict[str, Any]]] = []

    def ask_export(path: Path, destination: str, **options: Any) -> dict[str, Any]:
        asked.append((destination, options))
        return {
            "ok": True, "outcome": "done", "message": "", "destination": destination,
            "snapshot": "s", "details": {"files": 1, "bytes": 99}, "skipped": [],
        }  # fmt: skip

    monkeypatch.setattr(shell_cli, "ask_export", ask_export)
    assert shell_cli.exportar(config, "/srv/p.bundle", git="proyecto") == 0
    assert calls.asked == [("bundle", {})]
    (mkdir, _), (made, options), (remove, _) = calls.runs
    assert mkdir == [*PREFIX, "mkdir", "-p", "--", "/workspace/home/.backtide-export"]
    assert made[: len(PREFIX)] == PREFIX  # as the agent, inside its container: never on the host
    git = made[len(PREFIX) :]
    assert git[:5] == ["git", "-C", "/workspace/work/proyecto", "bundle", "create"]
    bundle = git[5]
    assert git[6:] == ["--all"] and options["check"] is False
    name = bundle.rsplit("/", 1)[1]
    assert bundle == f"/workspace/home/.backtide-export/{name}"
    assert asked == [("/srv/p.bundle", {"bundle": name, "repo": "proyecto"})]
    assert remove == [*PREFIX, "rm", "-f", "--", bundle]  # tidied up; the snapshot keeps it
    out = capsys.readouterr().out
    assert "git clone --no-checkout /srv/p.bundle" in out
    # M1 of the review: nothing in a bundle is filtered, so it never says it was
    assert shell_cli.BUNDLE_WARNING in out and shell_cli.EXPORTED_WARNING not in out
    assert "git ls-tree -r --name-only HEAD" in out and "--incluir-config" not in out


def test_exportar_git_of_the_whole_work_folder(
    config: ServiceConfig, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        shell_cli,
        "ask_export",
        lambda *a, **o: {
            "ok": True,
            "outcome": "done",
            "message": "",
            "destination": "/srv/b",
            "snapshot": "s",
            "details": {},
            "skipped": [],
        },  # fmt: skip
    )
    assert shell_cli.exportar(config, "/srv/b", git=".") == 0
    assert calls.runs[1][0][len(PREFIX) : len(PREFIX) + 3] == ["git", "-C", "/workspace/work"]


def test_a_bundle_git_could_not_make_exports_nothing(
    config: ServiceConfig,
    calls: Calls,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(shell_cli, "ask_export", lambda *a, **o: pytest.fail("asked"))
    calls.results = [
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 128, "", "fatal: Refusing to create empty bundle.\x1b[2J"),
    ]
    assert shell_cli.exportar(config, "/srv/p.bundle", git="vacio") == 1
    err = capsys.readouterr().err
    assert "empty bundle" in err and "\x1b" not in err
    assert calls.runs[-1][0][len(PREFIX) :][:3] == ["rm", "-f", "--"]


@pytest.mark.parametrize("repo", ["..", "../x", "/etc", "a//b", "", "a b", "x/../y"])
def test_an_odd_repository_folder_is_refused_before_asking(
    config: ServiceConfig, calls: Calls, repo: str
) -> None:
    assert shell_cli.exportar(config, "/srv/p.bundle", git=repo) == 2
    assert calls.asked == [] and calls.runs == []


def test_exportar_git_through_the_cli(
    tmp_path: Path, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(shell_cli, "_export_bundle", lambda *args: seen.append(args) or 0)
    code = main(["exportar", "--config", str(write_config(tmp_path)), "--git", "p", "/srv/p.b"])
    assert code == 0 and seen[0][1:] == (Path("/srv/p.b"), "p")


def test_a_refused_export_is_a_usage_error(
    config: ServiceConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refused(path: Path, destination: str) -> dict[str, Any]:
        return {"ok": False, "outcome": "invalid", "message": "ya existe", "details": {}}

    monkeypatch.setattr(shell_cli, "ask_export", refused)
    assert shell_cli.exportar(config, "/tmp/x") == 2  # noqa: S108
    assert "ya existe" in capsys.readouterr().err
