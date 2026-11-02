"""The control socket's shell commands (T17a-4): ``shell``, ``import`` and ``export``, what the
server refuses without calling the Guardian, and what the clients trust in a reply."""

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.jail.profile import MAX_PROMPT
from backtide.service import control
from backtide.service.control import (
    MAX_REQUEST_BYTES,
    REPLY_TIMEOUT,
    ControlError,
    ControlOutcomeUnknown,
    ControlServer,
    ask_export,
    ask_shell,
    ask_task_list,
    ask_task_start,
    ask_task_status,
    ask_task_stop,
)
from backtide.service.shell import ExportOutcome, ExportStatus, ShellOutcome, ShellStatus
from backtide.service.tasks import (
    ASKED_CHARS,
    MAX_KEPT,
    MAX_RUNNING,
    TaskEntry,
    TaskOutcome,
    TaskStart,
    TaskStatus,
)
from tests.test_service_control import FakeGuardian, me, talk

CONTAINER_ID = "ab12" * 16
TASK_ID = "c0de" * 8
READY = ShellOutcome(
    ShellStatus.READY, "", "backtide-agente", "61000:61000", "/workspace/work", CONTAINER_ID
)
SNAP = "20261022T120000.000000Z-manual"
IMPORT = {
    "cmd": "import", "name": "r", "source": "/s", "files": 1, "bytes": 1, "replace": False,
    "secrets_left_out": 0, "include_secrets": False,
}  # fmt: skip


class ShellGuardian(FakeGuardian):
    def __init__(self) -> None:
        super().__init__()
        self.shells: list[tuple[str, bool, str, Any]] = []
        self.exports: list[tuple[str, str, dict[str, Any]]] = []
        self.shell_outcome = READY
        self.tasks: list[tuple[str, bool, int | None, str]] = []
        self.task_started = TaskStart(TASK_ID)
        self.task_seen: TaskStatus | None = TaskStatus(TASK_ID, TaskOutcome.RUNNING)
        self.task_stopped: bool | None = True
        self.task_lines: list[TaskEntry] = []
        self.stop_requested_by: list[str | None] = []
        self.export_outcome = ExportOutcome(
            ExportStatus.DONE, "", "/home/me/out", SNAP, {"files": 2, "bytes": 9}
        )

    def open_shell(
        self, kind: str, *, resume: bool = False, requested_by: str, details: Any = None
    ) -> ShellOutcome:
        self.shells.append((kind, resume, requested_by, details))
        if self.error is not None:
            raise self.error
        return self.shell_outcome

    def task_start(
        self, prompt: str, *, resume: bool = False, seconds: int | None = None, requested_by: str
    ) -> TaskStart:
        self.tasks.append((prompt, resume, seconds, requested_by))
        if self.error is not None:
            raise self.error
        return self.task_started

    def task_status(self, task_id: str) -> TaskStatus | None:
        if self.error is not None:
            raise self.error
        return self.task_seen

    def task_stop(self, task_id: str, *, requested_by: str | None = None) -> bool | None:
        self.stop_requested_by.append(requested_by)
        if self.error is not None:
            raise self.error
        return self.task_stopped

    def task_list(self) -> list[TaskEntry]:
        if self.error is not None:
            raise self.error
        return self.task_lines

    def export(self, destination: str, *, requested_by: str, **bundle: Any) -> ExportOutcome:
        self.exports.append((destination, requested_by, bundle))
        return self.export_outcome


@pytest.fixture
def guardian() -> ShellGuardian:
    return ShellGuardian()


@pytest.fixture
def server(guardian: ShellGuardian) -> Iterator[ControlServer]:
    folder = Path(tempfile.mkdtemp(prefix="vg"))
    folder.chmod(0o700)
    made = ControlServer(guardian, folder / "control.sock", peer=me)
    made.start()
    yield made
    made.close()
    shutil.rmtree(folder, ignore_errors=True)


def send(server: ControlServer, request: dict[str, Any]) -> dict[str, Any]:
    return talk(server, json.dumps(request).encode() + b"\n")


def test_a_shell_request_reaches_the_guardian(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    reply = ask_shell(server.path, "session", resume=True, peer=me)
    assert reply == {
        "ok": True,
        "outcome": "ready",
        "message": "",
        "container": "backtide-agente",
        "container_id": CONTAINER_ID,
        "user": "61000:61000",
        "workdir": "/workspace/work",
    }
    (kind, resume, by, details) = guardian.shells[0]
    assert (kind, resume, details) == ("session", True, None) and by.startswith("cli (uid ")


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "shell", "kind": "session"},
        {"cmd": "shell", "kind": "import", "continue": False},
        {"cmd": "shell", "kind": "root", "continue": False},
        {"cmd": "shell", "kind": "task", "continue": False},
        {"cmd": "shell", "kind": "task", "continue": False, "prompt": "hola"},
        {"cmd": "shell", "kind": "session", "continue": "yes"},
        {"cmd": "shell", "kind": "session", "continue": False, "argv": ["sh"]},
        {"cmd": "shell", "kind": "session", "continue": False, "prompt": "hola"},
        {"cmd": "import", "name": "r", "source": "/s", "files": 1, "bytes": 1},
        {"cmd": "import", "name": "r", "source": "/s", "files": -1, "bytes": 1, "replace": False},
        {"cmd": "import", "name": "r", "source": "/s", "files": True, "bytes": 1, "replace": False},
        {"cmd": "import", "name": "", "source": "/s", "files": 1, "bytes": 1, "replace": False},
        {"cmd": "import", "name": "r", "source": "/s", "files": 1, "bytes": 1, "replace": 1},
        {"cmd": "export"},
        {"cmd": "export", "dest": 3},
        {"cmd": "export", "dest": "/x", "force": True},
        {"cmd": "export", "dest": "/x", "bundle": "b"},
        {"cmd": "export", "dest": "/x", "bundle": 3, "repo": "."},
        {"cmd": "export", "dest": "/x", "bundle": "b", "repo": "../etc"},
        {"cmd": "export", "dest": "/x", "bundle": "b", "repo": "/etc"},
        {"cmd": "export", "dest": "/x", "include_config": False},
        {"cmd": "export", "dest": "/x", "include_config": 1},
        {"cmd": "export", "dest": "/x", "include_config": "yes"},
        {"cmd": "export", "dest": "/x", "bundle": "b", "repo": ".", "include_config": True},
        {"cmd": "import", "name": "r", "source": "/s", "files": 1, "bytes": 1, "replace": False},
        {**IMPORT, "secrets_left_out": -1},
        {**IMPORT, "include_secrets": "yes"},
    ],
)
def test_malformed_requests_never_reach_the_guardian(
    server: ControlServer, guardian: ShellGuardian, request_: dict[str, Any]
) -> None:
    reply = send(server, request_)
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert guardian.shells == [] and guardian.exports == []


def test_a_bundle_is_a_shell_request_too(server: ControlServer, guardian: ShellGuardian) -> None:
    assert ask_shell(server.path, "bundle", peer=me)["ok"] is True
    assert guardian.shells[0][:2] == ("bundle", False)


def test_an_import_carries_its_counts(server: ControlServer, guardian: ShellGuardian) -> None:
    details = {
        "name": "repo", "source": "/home/me/repo", "files": 2, "bytes": 7, "replace": True,
        "secrets_left_out": 3, "include_secrets": False,
    }  # fmt: skip
    reply = ask_shell(server.path, "import", import_details=details, peer=me)
    assert reply["ok"] is True
    assert guardian.shells[0][0] == "import" and guardian.shells[0][3] == details


def test_a_refusal_comes_back_without_names(server: ControlServer, guardian: ShellGuardian) -> None:
    guardian.shell_outcome = ShellOutcome(ShellStatus.NOT_RUNNING, "El agente está en pausa.")
    reply = ask_shell(server.path, "session", peer=me)
    assert reply == {"ok": False, "outcome": "not_running", "message": "El agente está en pausa."}


def test_a_guardian_that_raises_is_a_failure(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    guardian.error = RuntimeError("boom")
    reply = ask_shell(server.path, "session", peer=me)
    assert reply["outcome"] == "failed" and "boom" not in reply["message"]


@pytest.mark.parametrize(
    "bad",
    [
        {"container": "--privileged"},
        {"container_id": "backtide-agente"},
        {"container_id": ""},
        {"container_id": "AB12" * 16},
        {"user": "0"},
        {"user": "root"},
        {"workdir": "/etc"},
        {"workdir": "/workspace/../etc"},
    ],
)
def test_the_client_never_trusts_odd_names_for_docker_exec(
    server: ControlServer, guardian: ShellGuardian, bad: dict[str, str]
) -> None:
    fields = {
        "container": READY.container,
        "container_id": READY.container_id,
        "user": READY.user,
        "workdir": READY.workdir,
        **bad,
    }
    guardian.shell_outcome = ShellOutcome(ShellStatus.READY, "", **fields)
    with pytest.raises(ControlOutcomeUnknown):
        ask_shell(server.path, "session", peer=me)


def test_an_export_request_and_its_reply(server: ControlServer, guardian: ShellGuardian) -> None:
    reply = ask_export(server.path, "/home/me/out", peer=me)
    assert reply == {
        "ok": True,
        "outcome": "done",
        "message": "",
        "destination": "/home/me/out",
        "snapshot": SNAP,
        "details": {"files": 2, "bytes": 9},
        "skipped": [],
    }
    assert guardian.exports[0][0] == "/home/me/out" and guardian.exports[0][2] == {}


def test_a_bundle_export_names_the_bundle_and_its_repo(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    reply = ask_export(
        server.path, "/home/me/p.bundle", bundle="export-x.bundle", repo="p", peer=me
    )
    assert reply["ok"] is True
    assert guardian.exports[0][2] == {"bundle": "export-x.bundle", "repo": "p"}


def test_include_config_reaches_the_guardian_only_when_asked(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    assert ask_export(server.path, "/home/me/out", include_config=True, peer=me)["ok"] is True
    assert guardian.exports[0][2] == {"include_config": True}
    with pytest.raises(ValueError):
        ask_export(server.path, "/home/me/b", bundle="export-x.bundle", include_config=True)


def test_what_an_export_skipped_comes_back_by_name_checked(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    skipped = [["git", "proyecto/.git"], ["name", "a\\x1b"], ["evil", "x"], ["git", "\x1b[2J"],
               ["config", "sub/.claude"]]  # fmt: skip
    guardian.export_outcome = ExportOutcome(
        ExportStatus.DONE, "", "/home/me/out", SNAP, {"skipped_git": 2, "skipped": skipped}
    )
    reply = ask_export(server.path, "/home/me/out", peer=me)
    assert reply["details"] == {"skipped_git": 2}
    assert reply["skipped"] == [
        ["git", "proyecto/.git"], ["name", "a\\x1b"], ["config", "sub/.claude"],
    ]  # fmt: skip


def test_an_unknown_kind_is_a_programming_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ask_shell(tmp_path / "x.sock", "root")


def test_the_outcomes_a_client_accepts() -> None:
    from backtide.service.control import EXPORT_OUTCOMES, SHELL_OUTCOMES

    assert SHELL_OUTCOMES == {"ready", "not_shell", "not_running", "failed", "refused"}
    assert EXPORT_OUTCOMES == {"done", "invalid", "not_shell", "failed", "refused"}


# --- the tasks (T26-5a): the service runs them, this is who may ask ---------------------------


def test_a_task_reaches_the_guardian_with_who_asked(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    reply = ask_task_start(server.path, "-rf todo", resume=True, seconds=120, peer=me)
    assert reply == {"ok": True, "outcome": "started", "message": "", "task": TASK_ID}
    ((prompt, resume, seconds, by),) = guardian.tasks
    assert (prompt, resume, seconds) == ("-rf todo", True, 120)
    assert by.startswith("cli (uid ")


def test_a_task_without_a_deadline_takes_the_profiles(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    assert ask_task_start(server.path, "hola", peer=me)["ok"]
    assert guardian.tasks[0][1:3] == (False, None)


@pytest.mark.parametrize(
    "prompt",
    ["x" * MAX_PROMPT, "ñ" * MAX_PROMPT, "\x1b" * MAX_PROMPT, "\U0001f600" * MAX_PROMPT],
)
def test_the_longest_prompt_fits_however_json_writes_it(
    server: ControlServer, guardian: ShellGuardian, prompt: str
) -> None:
    assert ask_task_start(server.path, prompt, peer=me)["ok"]
    assert guardian.tasks[0][0] == prompt


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "task_start"},
        {"cmd": "task_start", "prompt": ""},
        {"cmd": "task_start", "prompt": "   "},
        {"cmd": "task_start", "prompt": 3},
        {"cmd": "task_start", "prompt": "a\0b"},
        {"cmd": "task_start", "prompt": "\ud800"},
        {"cmd": "task_start", "prompt": "x" * (MAX_PROMPT + 1)},
        {"cmd": "task_start", "prompt": "x", "continue": "yes"},
        {"cmd": "task_start", "prompt": "x", "seconds": 0},
        {"cmd": "task_start", "prompt": "x", "seconds": 86401},
        {"cmd": "task_start", "prompt": "x", "seconds": 1.5},
        {"cmd": "task_start", "prompt": "x", "seconds": True},
        {"cmd": "task_start", "prompt": "x", "seconds": "60"},
        {"cmd": "task_start", "prompt": "x", "via": "telegram"},
        {"cmd": "task_start", "prompt": "x", "via": 3},
        {"cmd": "task_start", "prompt": "x", "argv": ["sh"]},
        {"cmd": "task_start", "prompt": "x", "container": "otro"},
        {"cmd": "task_start", "prompt": "x", "image": "evil"},
    ],
)
def test_a_malformed_task_never_reaches_the_guardian(
    server: ControlServer, guardian: ShellGuardian, request_: dict[str, Any]
) -> None:
    reply = send(server, request_)
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert guardian.tasks == []


def test_a_refusal_says_why_without_an_id(server: ControlServer, guardian: ShellGuardian) -> None:
    guardian.task_started = TaskStart(None, "Ya tiene 8 tareas.")
    reply = ask_task_start(server.path, "hola", peer=me)
    assert reply == {"ok": False, "outcome": "refused", "message": "Ya tiene 8 tareas."}


def test_a_guardian_that_raises_says_nothing_of_the_prompt(
    server: ControlServer, guardian: ShellGuardian, caplog: pytest.LogCaptureFixture
) -> None:
    guardian.error = RuntimeError("MARCA-DEL-PROMPT")
    assert ask_task_start(server.path, "hola", peer=me)["outcome"] == "refused"
    assert ask_task_status(server.path, TASK_ID, peer=me)["outcome"] == "refused"
    assert ask_task_stop(server.path, TASK_ID, peer=me) is False
    assert "MARCA-DEL-PROMPT" not in caplog.text and "RuntimeError" in caplog.text


def test_only_a_task_may_pass_the_size_of_any_other_request(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    """The longer limit is for the prompt: nothing else gets it, whether it starts like something
    else or says ``task_start`` first and something else after."""
    pad = "x" * (MAX_REQUEST_BYTES + 100)
    for raw in (
        json.dumps({"cmd": "holds", "pad": pad}),
        json.dumps({"cmd": "task_start", "pad": pad}).replace('"pad"', '"cmd": "holds", "pad"'),
    ):
        reply = talk(server, raw.encode() + b"\n")
        assert reply["outcome"] == "refused" and "bytes" in reply["message"]
    assert guardian.tasks == []


def test_a_task_longer_than_its_own_limit_is_refused(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    reply = talk(server, b'{"cmd": "task_start", ' + b"x" * (13 * MAX_PROMPT) + b"\n")
    assert reply["outcome"] == "refused" and "bytes" in reply["message"]
    assert guardian.tasks == []


def test_the_status_of_a_task_that_ended(server: ControlServer, guardian: ShellGuardian) -> None:
    guardian.task_seen = TaskStatus(TASK_ID, TaskOutcome.OK, "", "listo \x1b[2J", 0, 1.5)
    assert ask_task_status(server.path, TASK_ID, peer=me) == {
        "ok": True, "outcome": "ok", "message": "", "answer": "listo \x1b[2J", "answer_chars": 10,
        "code": 0, "seconds": 1.5,
    }  # fmt: skip


def test_the_status_can_come_cut_and_says_how_long_it_was(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    """T26-5b: what the chat's page shows, without 48 MiB through the socket for each load."""
    guardian.task_seen = TaskStatus(TASK_ID, TaskOutcome.OK, "", "x" * 1000, 0, 1.5)
    reply = ask_task_status(server.path, TASK_ID, cut=10, peer=me)
    assert reply["answer"] == "x" * 10 and reply["answer_chars"] == 1000


def test_a_cut_of_a_task_without_an_answer_is_no_answer(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    reply = ask_task_status(server.path, TASK_ID, cut=10, peer=me)
    assert reply["answer"] is None and reply["answer_chars"] == 0


@pytest.mark.parametrize("cut", [0, -1, 1.5, True, "10", [1]])
def test_a_cut_that_is_not_a_number_of_characters_is_refused(
    server: ControlServer, guardian: ShellGuardian, cut: object
) -> None:
    reply = talk(
        server, json.dumps({"cmd": "task_status", "task": TASK_ID, "cut": cut}).encode() + b"\n"
    )
    assert reply["outcome"] == "refused"


def test_the_list_of_the_tasks(server: ControlServer, guardian: ShellGuardian) -> None:
    guardian.task_lines = [
        TaskEntry(TASK_ID, "di hola", 123.5, "web", TaskOutcome.OK, 1.5, 9),
        TaskEntry("b" * 32, "\x1b[2J<b>", 124.0, "cli", TaskOutcome.RUNNING),
    ]
    assert ask_task_list(server.path, peer=me) == [
        {"task": TASK_ID, "asked": "di hola", "asked_at": 123.5, "via": "web", "outcome": "ok",
         "seconds": 1.5, "answer_chars": 9},
        {"task": "b" * 32, "asked": "\x1b[2J<b>", "asked_at": 124.0, "via": "cli",
         "outcome": "running", "seconds": None, "answer_chars": 0},
    ]  # fmt: skip


def test_the_longest_list_fits_its_reply(server: ControlServer, guardian: ShellGuardian) -> None:
    """What JSON makes longest, at the most the service keeps."""
    asked = "😀" * ASKED_CHARS
    guardian.task_lines = [
        TaskEntry(TASK_ID, asked, 1.0, "web", TaskOutcome.OK, 1.0, 1)
        for _ in range(MAX_KEPT + MAX_RUNNING)
    ]
    assert len(ask_task_list(server.path, peer=me)) == MAX_KEPT + MAX_RUNNING


def test_a_list_with_a_broken_line_is_no_list(
    monkeypatch: pytest.MonkeyPatch, server: ControlServer
) -> None:
    from backtide.service import control

    for broken in ({"task": "x"}, {"task": TASK_ID}, "nada"):
        raw = json.dumps({"ok": True, "outcome": "listed", "message": "", "tasks": [broken]})
        monkeypatch.setattr(control, "_ask", lambda *a, raw=raw, **k: raw.encode())
        with pytest.raises(ControlOutcomeUnknown):
            ask_task_list(server.path, peer=me)


def test_a_guardian_that_raises_on_the_list_is_a_refusal(
    server: ControlServer, guardian: ShellGuardian, caplog: pytest.LogCaptureFixture
) -> None:
    guardian.error = RuntimeError("MARCA-DEL-PROMPT")
    with pytest.raises(ControlError, match="inesperado"):
        ask_task_list(server.path, peer=me)
    assert "MARCA-DEL-PROMPT" not in caplog.text


@pytest.mark.parametrize("extra", [{"task": TASK_ID}, {"cut": 1}, {"all": True}])
def test_the_list_takes_nothing_else(
    server: ControlServer, guardian: ShellGuardian, extra: dict[str, Any]
) -> None:
    assert talk(server, json.dumps({"cmd": "task_list", **extra}).encode() + b"\n")["ok"] is False


class Slow:
    """A client socket's other end, for what ``_reply`` gives it."""

    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, seconds: float) -> None:
        self.timeouts.append(seconds)

    def sendall(self, data: bytes) -> None:
        pass

    def shutdown(self, how: int) -> None:
        pass

    def recv(self, size: int) -> bytes:
        return b""


def test_a_long_reply_has_time_to_go(server: ControlServer) -> None:
    """T26-5b: 48 MiB in 5 seconds, all of it (the timeout of sendall is for the whole call), lost
    an answer as soon as the machine was busy. The time goes with the length, and a short reply
    still has the 5 seconds it always had."""
    short, long = Slow(), Slow()
    server._reply(short, {"ok": True})  # type: ignore[arg-type]  # noqa: SLF001
    assert short.timeouts[0] == pytest.approx(REPLY_TIMEOUT, abs=0.01)
    answer = "x" * (48 * 1024 * 1024)
    server._reply(long, {"ok": True, "answer": answer})  # type: ignore[arg-type]  # noqa: SLF001
    assert long.timeouts[0] == pytest.approx(REPLY_TIMEOUT + 48, abs=0.01)


def test_the_status_of_a_task_that_runs(server: ControlServer, guardian: ShellGuardian) -> None:
    reply = ask_task_status(server.path, TASK_ID, peer=me)
    assert reply["ok"] and reply["outcome"] == "running" and reply["answer"] is None


def test_a_big_answer_comes_back_whole(server: ControlServer, guardian: ShellGuardian) -> None:
    """Over the 64 KiB of any other reply, and with what JSON makes longest."""
    answer = "\x1b" * (1024 * 1024)
    guardian.task_seen = TaskStatus(TASK_ID, TaskOutcome.OK, "", answer, 0, 1.0)
    assert ask_task_status(server.path, TASK_ID, peer=me)["answer"] == answer


def test_a_task_it_does_not_know(server: ControlServer, guardian: ShellGuardian) -> None:
    guardian.task_seen = None
    guardian.task_stopped = None
    reply = ask_task_status(server.path, TASK_ID, peer=me)
    assert reply["ok"] is False and reply["outcome"] == "unknown" and reply["answer"] is None
    assert ask_task_stop(server.path, TASK_ID, peer=me) is False


def test_ctrl_c_says_nothing_of_the_web(server: ControlServer, guardian: ShellGuardian) -> None:
    assert ask_task_stop(server.path, TASK_ID, peer=me) is True
    assert guardian.stop_requested_by == [None]


@pytest.mark.parametrize("via", ["telegram", 3, ["web"]])
def test_a_stop_from_nobody_we_know_is_refused(
    server: ControlServer, guardian: ShellGuardian, via: object
) -> None:
    raw = json.dumps({"cmd": "task_stop", "task": TASK_ID, "via": via}).encode() + b"\n"
    assert talk(server, raw)["outcome"] == "refused"
    assert guardian.stop_requested_by == []


@pytest.mark.parametrize("stopped", [True, False])
def test_stopping_says_what_the_guardian_says(
    server: ControlServer, guardian: ShellGuardian, stopped: bool
) -> None:
    guardian.task_stopped = stopped
    assert ask_task_stop(server.path, TASK_ID, peer=me) is stopped


@pytest.mark.parametrize("command", ["task_status", "task_stop"])
@pytest.mark.parametrize(
    "more",
    [{}, {"task": 3}, {"task": "x"}, {"task": "../../etc"}, {"task": TASK_ID, "extra": 1},
     {"task": TASK_ID.upper()}, {"task": TASK_ID + "\n"}],
)  # fmt: skip
def test_a_bad_id_is_refused(server: ControlServer, command: str, more: dict[str, Any]) -> None:
    reply = send(server, {"cmd": command, **more})
    assert reply["outcome"] == "refused" and reply["ok"] is False


def _service_says(monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any]) -> None:
    monkeypatch.setattr(control, "_ask", lambda *args, **options: json.dumps(reply).encode())


@pytest.mark.parametrize(
    "bad",
    [
        {"task": "x"},
        {"task": None},
        {"message": 3},
        {"outcome": "made-up"},
    ],
)
def test_the_client_does_not_trust_an_odd_start_reply(
    monkeypatch: pytest.MonkeyPatch, bad: dict[str, Any]
) -> None:
    _service_says(
        monkeypatch, {"ok": True, "outcome": "started", "message": "", "task": TASK_ID, **bad}
    )
    with pytest.raises(ControlOutcomeUnknown):
        ask_task_start(Path("/nowhere"), "hola", peer=me)


@pytest.mark.parametrize(
    "bad",
    [
        {"outcome": "made-up"},
        {"message": None},
        {"answer": 3},
        {"code": "0"},
        {"code": True},
        {"seconds": "1"},
        {"ok": "yes"},
    ],
)
def test_the_client_does_not_trust_an_odd_status_reply(
    monkeypatch: pytest.MonkeyPatch, bad: dict[str, Any]
) -> None:
    _service_says(monkeypatch, {"ok": True, "outcome": "ok", "message": "", **bad})
    with pytest.raises(ControlOutcomeUnknown):
        ask_task_status(Path("/nowhere"), TASK_ID, peer=me)


def test_the_client_does_not_trust_an_odd_stop_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    _service_says(monkeypatch, {"ok": True, "outcome": "made-up"})
    with pytest.raises(ControlOutcomeUnknown):
        ask_task_stop(Path("/nowhere"), TASK_ID, peer=me)
