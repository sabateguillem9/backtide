"""Thin, stateless wrapper over the ``docker`` CLI, in the style of backtide/snapshots/btrfs.py.

- Fixed argv, never through a shell, with ``LC_ALL=C`` (stable error messages), stdin closed
  and a timeout. A failure raises JailError with the command, its exit code and its stderr.
- The output is bounded (``max_output``): ``docker exec`` and ``docker logs`` print whatever
  the agent wants, as fast as it wants (about 1 GB/s in the VM), and backtide must never run out
  of memory reading it. Past the limit the CLI is killed and JailError raised.
- The command line goes into error messages, so it must never carry a secret: secrets travel
  in ``env`` (the CLI copies ``-e NAME`` from its own environment), which is never logged.
- Text the agent controls (stderr of ``docker exec``, its logs) goes through sanitize() before
  it reaches a message: no terminal escape sequences, bounded length.
- A timeout kills the CLI, not the daemon's operation: it may or may not have happened, and
  callers check the state they need.
- agent.py calls these as ``docker.<fn>``, so unit tests can monkeypatch them; tests of this
  module point ``PROGRAM`` at a fake CLI.
"""

import contextlib
import os
import selectors
import shlex
import subprocess
import time
from collections.abc import Mapping, Sequence

PROGRAM = "docker"
DEFAULT_TIMEOUT = 120.0
DEFAULT_MAX_OUTPUT = 1024 * 1024  # bytes of stdout and stderr together
MAX_INPUT = 16 * 1024  # bytes of run()'s input: under any pipe's buffer
MESSAGE_LIMIT = 4000  # characters of agent-controlled text in one message
_READ_SIZE = 64 * 1024


class JailError(Exception):
    """A jail operation failed. ``returncode`` and ``stderr`` come from the docker CLI."""

    def __init__(self, message: str, *, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class _OutputTooLarge(Exception):
    """The CLI printed more than max_output bytes."""


def run(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    max_output: int = DEFAULT_MAX_OUTPUT,
    input: str | None = None,  # noqa: A002 - subprocess's own name for it
) -> subprocess.CompletedProcess[str]:
    """Run ``docker *args`` and return the finished process.

    ``input`` (at most MAX_INPUT bytes, so it fits in a pipe before anything is read back) is
    written to its stdin, which is then closed; without it stdin is closed from the start.

    ``env`` is added to this process's environment (for secrets: see the module docstring).
    With ``check`` (the default) a non-zero exit raises JailError; without it the caller
    reads ``returncode``. More than ``max_output`` bytes of output, or a timeout, always
    raise JailError. Every argument must be a str: a Path or a number is a bug here."""
    bad = [arg for arg in args if not isinstance(arg, str)]
    if bad:
        raise TypeError(f"docker arguments must be str, got {bad!r}")
    data = None if input is None else input.encode()
    if data is not None and len(data) > MAX_INPUT:
        raise ValueError(f"input must be at most {MAX_INPUT} bytes")
    argv = [PROGRAM, *args]
    command = shlex.join(argv)
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL if data is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # LC_ALL last: nothing in ``env`` changes the messages backtide reads back.
            env={**os.environ, **(env or {}), "LC_ALL": "C"},
            # Its own session: a Ctrl-C in the terminal goes to the foreground process group and
            # must reach backtide (which stops the agent in an orderly way), not the `docker stop`
            # it is waiting for. A timeout still kills the child: process.kill() is by pid.
            start_new_session=True,
        )
    except OSError as e:  # FileNotFoundError when the docker CLI is not installed
        raise JailError(f"cannot run {command}: {e}") from e
    with process:  # on the way out: pipes closed and the process reaped
        if data is not None and process.stdin is not None:
            # A child that does not read it closes the pipe: its exit code says so.
            with contextlib.suppress(BrokenPipeError):
                process.stdin.write(data)
            with contextlib.suppress(BrokenPipeError):
                process.stdin.close()
        try:
            stdout, stderr = _read_bounded(process, timeout, max_output)
        except subprocess.TimeoutExpired:
            process.kill()
            raise JailError(f"{command} timed out after {timeout} s") from None
        except _OutputTooLarge:
            process.kill()
            raise JailError(f"{command} printed more than {max_output} bytes: stopped it") from None
    result = subprocess.CompletedProcess(argv, process.returncode, _text(stdout), _text(stderr))
    if check and result.returncode != 0:
        stderr_text = sanitize(result.stderr.strip())
        raise JailError(
            f"{command} failed with exit code {result.returncode}: {stderr_text}",
            returncode=result.returncode,
            stderr=stderr_text,
        )
    return result


def sanitize(text: str, limit: int = MESSAGE_LIMIT) -> str:
    """``text`` made safe to print: every non-printable character except newline and tab
    (ESC, other controls, bidi overrides) becomes a visible escape such as ``\\x1b``, and the
    result is cut to ``limit`` characters. For anything the agent controls."""
    safe = "".join(char if char.isprintable() or char in "\n\t" else _escape(char) for char in text)
    if len(safe) > limit:
        return safe[:limit] + f"... ({len(safe) - limit} more characters)"
    return safe


def _escape(char: str) -> str:
    code = ord(char)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def _read_bounded(
    process: subprocess.Popen[bytes], timeout: float, max_output: int
) -> tuple[bytes, bytes]:
    """Read stdout and stderr until both close and the process exits, like communicate(),
    but raise _OutputTooLarge past ``max_output`` bytes and TimeoutExpired past ``timeout``."""
    if process.stdout is None or process.stderr is None:  # never: run() asks for both pipes
        raise JailError(f"no output pipes for {process.args!r}")
    deadline = time.monotonic() + timeout
    out_fd, err_fd = process.stdout.fileno(), process.stderr.fileno()
    chunks: dict[int, list[bytes]] = {out_fd: [], err_fd: []}
    total = 0
    with selectors.DefaultSelector() as selector:
        for fd in chunks:
            selector.register(fd, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            for key, _ in selector.select(remaining):
                data = os.read(key.fd, _READ_SIZE)
                if not data:
                    selector.unregister(key.fd)
                    continue
                total += len(data)
                if total > max_output:
                    raise _OutputTooLarge
                chunks[key.fd].append(data)
    process.wait(timeout=max(deadline - time.monotonic(), 0))
    return b"".join(chunks[out_fd]), b"".join(chunks[err_fd])


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")
