"""Unit tests for the docker CLI wrapper. No docker needed: ``PROGRAM`` points at a fake CLI,
a small Python script, so the real process handling (pipes, timeout, output bound) runs."""

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from backtide.jail import docker
from backtide.jail.docker import JailError

FAKE_SECRET = "fake-value-for-the-test"  # noqa: S105 - not a real secret
OSC52 = "\x1b]52;c;ZWNobyBoYWNrZWQ=\x07"  # "write this to the clipboard", in a terminal

# The fake CLI: records its argv, environment and stdin next to itself, then does what
# behaviour.json says: print, flood stdout or stderr without end, sleep, exit with a code.
FAKE_CLI = """
import json, os, sys, time
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "record.json"), "w") as record:
    json.dump({"argv": sys.argv[1:], "env": dict(os.environ), "stdin": sys.stdin.read(),
               "pgid": os.getpgrp(), "sid": os.getsid(0)}, record)
with open(os.path.join(here, "behaviour.json")) as f:
    behaviour = json.load(f)
time.sleep(behaviour.get("sleep", 0))
for stream in ("stdout", "stderr"):
    getattr(sys, stream).buffer.write(behaviour.get(stream, "").encode())
    getattr(sys, stream).flush()
flood = behaviour.get("flood")
if flood:
    out = getattr(sys, flood).buffer
    while True:
        out.write(b"0" * 65536)
sys.exit(behaviour.get("exit", 0))
"""


class FakeCli:
    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.path = folder / "docker"
        self.path.write_text(f"#!{sys.executable}\n{FAKE_CLI}")
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)
        self.behave()

    def behave(self, **behaviour: object) -> None:
        (self.folder / "behaviour.json").write_text(json.dumps(behaviour))

    def record(self) -> dict:
        return json.loads((self.folder / "record.json").read_text())


@pytest.fixture
def fake_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeCli:
    fake = FakeCli(tmp_path)
    monkeypatch.setattr(docker, "PROGRAM", str(fake.path))
    return fake


def test_runs_docker_with_a_fixed_argv(fake_cli: FakeCli) -> None:
    fake_cli.behave(stdout="out\n")
    result = docker.run(["container", "inspect", "agent; rm -rf /", "$(id)"], timeout=7)
    record = fake_cli.record()
    assert record["argv"] == ["container", "inspect", "agent; rm -rf /", "$(id)"]  # no shell
    assert record["env"]["LC_ALL"] == "C"
    assert record["stdin"] == ""  # closed
    assert result.stdout == "out\n" and result.returncode == 0


def test_the_cli_runs_in_a_process_group_of_its_own(fake_cli: FakeCli) -> None:
    """Ctrl-C in the terminal goes to the foreground process group: it must reach backtide, which
    stops the agent in an orderly way, and not kill the `docker stop` it is waiting for."""
    docker.run(["stop", "agent"])
    record = fake_cli.record()
    assert record["pgid"] != os.getpgrp()
    assert record["sid"] != os.getsid(0)


def test_the_real_program_is_docker() -> None:
    assert docker.PROGRAM == "docker"


def test_extra_env_reaches_the_cli_but_not_the_message(fake_cli: FakeCli) -> None:
    fake_cli.behave(stderr="boom\n", exit=1)
    with pytest.raises(JailError) as error:
        docker.run(["create", "--env", "TOKEN_NAME"], env={"TOKEN_NAME": FAKE_SECRET})
    assert fake_cli.record()["env"]["TOKEN_NAME"] == FAKE_SECRET
    assert FAKE_SECRET not in str(error.value)


def test_failure_raises_with_the_command_exit_code_and_stderr(fake_cli: FakeCli) -> None:
    fake_cli.behave(stderr="Error: name in use\n", exit=125)
    with pytest.raises(JailError) as error:
        docker.run(["create", "--name", "my agent"])
    assert error.value.returncode == 125
    assert error.value.stderr == "Error: name in use"
    assert f"{fake_cli.path} create --name 'my agent'" in str(error.value)
    assert "exit code 125" in str(error.value)


def test_failure_is_returned_without_check(fake_cli: FakeCli) -> None:
    fake_cli.behave(stderr="No such container: x\n", exit=1)
    result = docker.run(["container", "inspect", "x"], check=False)
    assert result.returncode == 1
    assert result.stderr == "No such container: x\n"


def test_timeout_raises_jail_error(fake_cli: FakeCli) -> None:
    fake_cli.behave(sleep=30)
    started = time.monotonic()
    with pytest.raises(JailError, match="timed out after 0.5 s"):
        docker.run(["stop", "agent"], timeout=0.5)
    assert time.monotonic() - started < 10


def test_missing_cli_raises_jail_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(docker, "PROGRAM", str(tmp_path / "no-docker-here"))
    with pytest.raises(JailError, match="cannot run .*no-docker-here version"):
        docker.run(["version"])


def test_arguments_must_be_strings(fake_cli: FakeCli) -> None:
    with pytest.raises(TypeError):
        docker.run(["start", Path("/agent")])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        docker.run(["stop", "--time", 30])  # type: ignore[list-item]
    assert not (fake_cli.folder / "record.json").exists()


# The output is bounded: docker exec and docker logs print whatever the agent wants


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_endless_output_is_cut_at_the_limit(fake_cli: FakeCli, stream: str) -> None:
    fake_cli.behave(flood=stream)
    started = time.monotonic()
    with pytest.raises(JailError, match="printed more than 100000 bytes"):
        docker.run(["exec", "agent", "cat", "/dev/zero"], max_output=100_000, check=False)
    assert time.monotonic() - started < 10  # killed, not read to the end


def test_output_within_the_limit_is_returned_whole(fake_cli: FakeCli) -> None:
    text = "é" * 100_000  # 200 000 bytes: several reads, characters split between them
    fake_cli.behave(stdout=text, stderr="warning\n")
    result = docker.run(["logs", "agent"], max_output=200_008)
    assert result.stdout == text and result.stderr == "warning\n"
    with pytest.raises(JailError, match="printed more than 200007 bytes"):
        docker.run(["logs", "agent"], max_output=200_007)


def test_the_default_limit_is_a_mebibyte(fake_cli: FakeCli) -> None:
    fake_cli.behave(flood="stdout")
    with pytest.raises(JailError, match=f"more than {1024 * 1024} bytes"):
        docker.run(["logs", "agent"])


# Text the agent controls is sanitized before it reaches a message


def test_stderr_in_a_failure_is_sanitized(fake_cli: FakeCli) -> None:
    fake_cli.behave(stderr=f"{OSC52}\x1b[2J\x1b[1A hidden‮evil\n", exit=1)
    with pytest.raises(JailError) as error:
        docker.run(["exec", "agent", "false"])
    for text in (str(error.value), error.value.stderr):
        assert "\x1b" not in text and "\x07" not in text and "‮" not in text
    assert "\\x1b]52;c;ZWNobyBoYWNrZWQ=\\x07" in error.value.stderr
    assert "\\u202eevil" in error.value.stderr


def test_sanitize_keeps_newlines_and_tabs_and_cuts_long_text() -> None:
    assert docker.sanitize("a\tb\nc\r\x00") == "a\tb\nc\\x0d\\x00"
    assert docker.sanitize("ñandú ✓") == "ñandú ✓"
    long = docker.sanitize("x" * 5000, limit=4000)
    assert long.startswith("x" * 4000) and long.endswith("(1000 more characters)")
    assert len(docker.sanitize("\x1b" * 5000)) < 4100


def test_no_process_is_left_behind(fake_cli: FakeCli) -> None:
    fake_cli.behave(flood="stdout")
    with pytest.raises(JailError):
        docker.run(["exec", "agent"], max_output=1000)
    assert fake_cli.record()["argv"] == ["exec", "agent"]
    survivors = subprocess.run(["pgrep", "-f", str(fake_cli.path)], capture_output=True, text=True)
    assert survivors.stdout.split() == []


def test_input_reaches_stdin_and_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T17a-4: the seed of `backtide entrar` goes on stdin (``docker exec -i``), never in the
    argv; without ``input`` stdin stays closed."""
    cat = tmp_path / "cat-docker"
    cat.write_text("#!/bin/sh\nexec cat\n")
    cat.chmod(0o755)
    monkeypatch.setattr(docker, "PROGRAM", str(cat))
    assert docker.run(["exec"], input="línea\n").stdout == "línea\n"
    assert docker.run(["exec"]).stdout == ""
    with pytest.raises(ValueError):
        docker.run(["exec"], input="x" * (docker.MAX_INPUT + 1))
