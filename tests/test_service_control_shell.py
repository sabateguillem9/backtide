"""The control socket's shell commands (T17a-4): ``shell``, ``import`` and ``export``, what the
server refuses without calling the Guardian, and what the clients trust in a reply."""

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.service.control import (
    ControlOutcomeUnknown,
    ControlServer,
    ask_export,
    ask_shell,
)
from backtide.service.shell import ExportOutcome, ExportStatus, ShellOutcome, ShellStatus
from tests.test_service_control import FakeGuardian, me, talk

READY = ShellOutcome(ShellStatus.READY, "", "backtide-agente", "61000:61000", "/workspace/work")
SNAP = "20261022T120000.000000Z-manual"


class ShellGuardian(FakeGuardian):
    def __init__(self) -> None:
        super().__init__()
        self.shells: list[tuple[str, bool, str, Any]] = []
        self.exports: list[tuple[str, str]] = []
        self.shell_outcome = READY
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

    def export(self, destination: str, *, requested_by: str) -> ExportOutcome:
        self.exports.append((destination, requested_by))
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
        {"cmd": "shell", "kind": "task", "continue": "yes"},
        {"cmd": "shell", "kind": "task", "continue": False, "argv": ["sh"]},
        {"cmd": "import", "name": "r", "source": "/s", "files": 1, "bytes": 1},
        {"cmd": "import", "name": "r", "source": "/s", "files": -1, "bytes": 1, "replace": False},
        {"cmd": "import", "name": "r", "source": "/s", "files": True, "bytes": 1, "replace": False},
        {"cmd": "import", "name": "", "source": "/s", "files": 1, "bytes": 1, "replace": False},
        {"cmd": "import", "name": "r", "source": "/s", "files": 1, "bytes": 1, "replace": 1},
        {"cmd": "export"},
        {"cmd": "export", "dest": 3},
        {"cmd": "export", "dest": "/x", "force": True},
    ],
)
def test_malformed_requests_never_reach_the_guardian(
    server: ControlServer, guardian: ShellGuardian, request_: dict[str, Any]
) -> None:
    reply = send(server, request_)
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert guardian.shells == [] and guardian.exports == []


def test_an_import_carries_its_counts(server: ControlServer, guardian: ShellGuardian) -> None:
    details = {"name": "repo", "source": "/home/me/repo", "files": 2, "bytes": 7, "replace": True}
    reply = ask_shell(server.path, "import", import_details=details, peer=me)
    assert reply["ok"] is True
    assert guardian.shells[0][0] == "import" and guardian.shells[0][3] == details


def test_a_refusal_comes_back_without_names(server: ControlServer, guardian: ShellGuardian) -> None:
    guardian.shell_outcome = ShellOutcome(ShellStatus.NOT_RUNNING, "El agente está en pausa.")
    reply = ask_shell(server.path, "task", peer=me)
    assert reply == {"ok": False, "outcome": "not_running", "message": "El agente está en pausa."}


def test_a_guardian_that_raises_is_a_failure(
    server: ControlServer, guardian: ShellGuardian
) -> None:
    guardian.error = RuntimeError("boom")
    reply = ask_shell(server.path, "task", peer=me)
    assert reply["outcome"] == "failed" and "boom" not in reply["message"]


@pytest.mark.parametrize(
    "bad",
    [
        {"container": "--privileged"},
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
    }
    assert guardian.exports[0][0] == "/home/me/out"


def test_an_unknown_kind_is_a_programming_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ask_shell(tmp_path / "x.sock", "root")


def test_the_outcomes_a_client_accepts() -> None:
    from backtide.service.control import EXPORT_OUTCOMES, SHELL_OUTCOMES

    assert SHELL_OUTCOMES == {"ready", "not_shell", "not_running", "failed", "refused"}
    assert EXPORT_OUTCOMES == {"done", "invalid", "not_shell", "failed", "refused"}
