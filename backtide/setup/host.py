"""What the installer asks of the machine, behind one small interface.

The preflight and the volume steps only talk to a ``Host``, so the Mac tests hand them a fake
one (docs/25, section 8: "con un Runner inyectable"). ``SystemHost`` is the real machine:
- commands run with a fixed argv, never through a shell, with ``LC_ALL=C`` (stable messages),
  stdin closed and a timeout; a program that is not installed is ``None``, not an exception;
- reads are bounded and never follow anything the caller did not name;
- nothing here changes the machine: the only writes are the volume steps' own commands.
"""

import grp
import os
import pwd
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from backtide.service import clock

DEFAULT_TIMEOUT = 60.0
DEFAULT_READ_LIMIT = 64 * 1024
OUTPUT_LIMIT = 256 * 1024  # characters kept of a command's stdout and of its stderr
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# The daemon backtide.service talks to: under systemd it has no DOCKER_HOST and no usable HOME
# (ProtectHome), so it always uses this socket. Fixing it here makes the preflight ask that same
# daemon, never a rootless one or another context from ~/.docker or an inherited DOCKER_HOST.
DOCKER_HOST = "unix:///var/run/docker.sock"


@dataclass(frozen=True)
class Ran:
    """A finished command: its exit code and what it printed."""

    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str]], Ran | None]


class Host(Protocol):
    def euid(self) -> int: ...
    def machine(self) -> str: ...
    def release(self) -> str: ...
    def read(self, path: str, limit: int = DEFAULT_READ_LIMIT) -> bytes | None: ...
    def exists(self, path: str) -> bool: ...
    def run(self, argv: Sequence[str]) -> Ran | None: ...
    def free_bytes(self, path: str) -> int | None: ...
    def uid_taken(self, uid: int) -> bool: ...
    def gid_taken(self, gid: int) -> bool: ...
    def clock_synced(self) -> bool | None: ...


def run(argv: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT) -> Ran | None:
    """Run ``argv`` and return how it ended; ``None`` if the program is not installed.

    A timeout is exit code -1, and a program that cannot be run 126, each with a message in
    stderr: the caller decides what it means."""
    bad = [arg for arg in argv if not isinstance(arg, str)]
    if bad or not argv:
        raise TypeError(f"arguments must be a non-empty list of str, got {list(argv)!r}")
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "DOCKER_HOST": DOCKER_HOST}
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None
    except OSError as e:  # there but not runnable (no execute permission, a broken binary)
        return Ran(126, "", f"{argv[0]}: {e.strerror}")
    except subprocess.TimeoutExpired:
        return Ran(-1, "", f"{argv[0]} did not finish in {timeout:.0f} s")
    return Ran(done.returncode, done.stdout[:OUTPUT_LIMIT], done.stderr[:OUTPUT_LIMIT])


class SystemHost:
    """This machine."""

    def euid(self) -> int:
        return os.geteuid()

    def machine(self) -> str:
        return os.uname().machine

    def release(self) -> str:
        return os.uname().release

    def read(self, path: str, limit: int = DEFAULT_READ_LIMIT) -> bytes | None:
        """Up to ``limit`` bytes of a file, or ``None`` if it cannot be read."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            chunks: list[bytes] = []
            left = limit
            while left > 0:
                chunk = os.read(fd, left)
                if not chunk:
                    break
                chunks.append(chunk)
                left -= len(chunk)
            return b"".join(chunks)
        except OSError:
            return None
        finally:
            os.close(fd)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def run(self, argv: Sequence[str]) -> Ran | None:
        return run(argv)

    def free_bytes(self, path: str) -> int | None:
        try:
            stats = os.statvfs(path)
        except OSError:
            return None
        return stats.f_bavail * stats.f_frsize

    def uid_taken(self, uid: int) -> bool:
        try:
            pwd.getpwuid(uid)
        except KeyError:
            return False
        return True

    def gid_taken(self, gid: int) -> bool:
        try:
            grp.getgrgid(gid)
        except KeyError:
            return False
        return True

    def clock_synced(self) -> bool | None:
        try:
            return clock.clock_synced()
        except OSError:
            return None
