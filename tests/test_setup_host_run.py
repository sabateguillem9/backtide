"""backtide.setup.host: how the installer runs commands (T13-2)."""

import os
import stat
from pathlib import Path

import pytest

from backtide.setup import host


def test_commands_get_a_fixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://user:secret@elsewhere:2376")
    monkeypatch.setenv("HOME", "/home/someone")
    monkeypatch.setenv("SOMETHING_ELSE", "x")
    ran = host.run(["env"])
    assert ran is not None and ran.returncode == 0
    env = dict(line.split("=", 1) for line in ran.stdout.splitlines())
    assert env == {
        "PATH": host.SAFE_PATH,
        "LC_ALL": "C",
        "DOCKER_HOST": "unix:///var/run/docker.sock",  # the daemon backtide.service uses
    }


def test_a_missing_program_is_none() -> None:
    assert host.run(["backtide-no-such-program-here"]) is None


def test_a_program_that_cannot_run_is_126_not_a_crash(tmp_path: Path) -> None:
    program = tmp_path / "not-executable"
    program.write_text("#!/bin/sh\necho hi\n")
    os.chmod(program, stat.S_IRUSR | stat.S_IWUSR)
    ran = host.run([str(program)])
    assert ran is not None
    assert ran.returncode == 126
    assert "not-executable" in ran.stderr


def test_arguments_must_be_strings() -> None:
    with pytest.raises(TypeError):
        host.run(["echo", Path("/x")])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        host.run([])
