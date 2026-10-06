"""Thin, stateless wrapper over the btrfs CLI, plus the syscalls the CLI does not offer.

- Every command runs with a fixed argv, never through a shell, with ``LC_ALL=C`` (so error
  messages are stable) and a timeout. Nothing here calls sudo: commands run with whatever
  privileges the process has.
- Paths must be absolute (otherwise ValueError), so a path can never be read as an option.
- The CLI follows a symlink in the last component (``property`` opens the path, ``subvolume
  delete`` calls realpath and deletes the target). So the functions that read or change a
  subvolume refuse a symlink there, and delete_subvolume refuses anything but a subvolume root.
  The check and the command are two steps: this stops bugs and tampering done beforehand, not
  someone renaming entries concurrently in a directory they can write to.
- Never parses ``subvolume list`` or ``subvolume show``: they need root and have no JSON
  output in btrfs-progs 6.19.
- When a command fails or times out, the operation may or may not have happened. Callers
  check the postcondition they need (the store does).
- The store calls these as ``btrfs.<fn>``, so unit tests can monkeypatch them or
  ``subprocess.run``.
- libc's ``renameat2`` is loaded on first use, so importing this module works on macOS.
"""

import ctypes
import errno
import functools
import logging
import os
import re
import shlex
import stat
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import NoReturn

from vigia.snapshots.model import SnapshotError, SnapshotNoSpace

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
SUBVOLUME_ROOT_INO = 256  # the root directory of every btrfs subvolume has this inode number
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2

_NO_SPACE_STDERR = {"No space left on device": errno.ENOSPC, "Disk quota exceeded": errno.EDQUOT}
_NO_SPACE_ERRNOS = frozenset(_NO_SPACE_STDERR.values())
_ROOT_ID_RE = re.compile(r"([1-9][0-9]*)\n", re.ASCII)
_READONLY_OUTPUT = {"ro=true\n": True, "ro=false\n": False}

# File descriptors every btrfs child inherits (see children_hold).
_held_fds: ContextVar[tuple[int, ...]] = ContextVar("_held_fds", default=())


@contextmanager
def children_hold(fd: int) -> Iterator[None]:
    """Make every btrfs child started inside this block inherit ``fd`` (the volume lock).

    The flock is then released only when the guardian AND any orphaned child are gone, so a
    crash leftover always comes from a dead process."""
    token = _held_fds.set((*_held_fds.get(), fd))
    try:
        yield
    finally:
        _held_fds.reset(token)


def run(*args: str | Path, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Run ``btrfs *args`` and return its stdout. Path arguments must be absolute."""
    argv = ["btrfs", *(str(_absolute(a)) if isinstance(a, Path) else a for a in args)]
    command = shlex.join(argv)
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
            pass_fds=_held_fds.get(),
        )
    except subprocess.TimeoutExpired as e:
        raise SnapshotError(f"{command} timed out after {timeout} s") from e
    except OSError as e:  # FileNotFoundError when btrfs-progs is not installed
        raise SnapshotError(f"cannot run {command}: {e}", errno=e.errno) from e
    if result.returncode != 0:
        _raise_failure(command, result.returncode, result.stderr.strip())
    return result.stdout


def _raise_failure(command: str, returncode: int, stderr: str) -> NoReturn:
    message = f"{command} failed with exit code {returncode}: {stderr}"
    for text, code in _NO_SPACE_STDERR.items():
        if text in stderr:
            raise SnapshotNoSpace(message, errno=code)
    raise SnapshotError(message)


def create_subvolume(path: Path) -> None:
    run("subvolume", "create", _absolute(path))


def snapshot(src: Path, dst: Path, *, readonly: bool) -> None:
    """Snapshot ``src`` as ``dst``. Never overwrites: if ``dst`` exists, raises (EEXIST)."""
    src, dst = _absolute(src), _absolute(dst)
    _require_absent(dst)
    readonly_flag = ("-r",) if readonly else ()
    run("subvolume", "snapshot", *readonly_flag, src, dst)


def is_readonly(path: Path) -> bool:
    """Unprivileged. Refuses a symlink; btrfs fails unless ``path`` is a subvolume on Btrfs.

    Only the last component is checked: the rest of the path resolves as usual."""
    path = _absolute(path)
    _refuse_symlink(path)
    output = run("property", "get", "-ts", path, "ro")
    if output not in _READONLY_OUTPUT:
        raise SnapshotError(f"unexpected output from btrfs property get on {path}: {output!r}")
    return _READONLY_OUTPUT[output]


def set_readonly(path: Path, value: bool) -> None:
    """Refuses a symlink in the last component, like is_readonly."""
    path = _absolute(path)
    _refuse_symlink(path)
    run("property", "set", "-ts", path, "ro", "true" if value else "false")


def delete_subvolume(path: Path, *, commit: bool = False) -> None:
    """Delete the subvolume at ``path``, read-only or not, privileged or not.

    First refuses anything that is not a subvolume root (lstat): a missing path, a plain
    directory, a file, or a symlink, whose TARGET btrfs would delete. Then always: read ro,
    clear it if set (an unprivileged owner cannot delete a read-only subvolume), delete. If the
    delete fails and ``path`` still exists, ro is put back and the ORIGINAL error is re-raised.

    ``commit`` waits for the transaction commit, so the deletion cannot reappear after a crash.
    btrfs-progs exits 1 when the delete worked but that wait failed; ``path`` is then gone, and
    os.sync() commits instead."""
    path = _absolute(path)
    if not is_subvolume(path):
        raise SnapshotError(
            f"refusing to delete {path}: not a subvolume root "
            "(missing, a plain directory, a file or a symlink)"
        )
    was_readonly = is_readonly(path)
    if was_readonly:
        set_readonly(path, False)
    commit_flag = ("--commit-after",) if commit else ()
    try:
        run("subvolume", "delete", *commit_flag, path)
    except SnapshotError as error:
        if _is_gone(path, error):
            logger.warning(
                "btrfs reported a failure but %s is gone, so it was deleted: %s", path, error
            )
            if commit:
                os.sync()  # the failure may have been the commit wait itself
            return
        if was_readonly:
            _put_readonly_back(path, error)
        raise


def _is_gone(path: Path, error: SnapshotError) -> bool:
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return True
    except OSError as e:
        error.add_note(f"could not check whether {path} still exists: {e}")
    return False


def _put_readonly_back(path: Path, error: SnapshotError) -> None:
    try:
        set_readonly(path, True)
    except SnapshotError as e:
        error.add_note(f"restoring ro=true on {path} also failed: {e}")


def subvolume_id(path: Path) -> int:
    """The btrfs subvolume ID of ``path``. Unprivileged."""
    output = run("inspect-internal", "rootid", _absolute(path))
    match = _ROOT_ID_RE.fullmatch(output)
    if match is None:
        raise SnapshotError(f"unexpected output from btrfs inspect-internal rootid: {output!r}")
    return int(match.group(1))


def is_subvolume(path: Path) -> bool:
    """True if ``path`` is the root of a subvolume. False if it is missing; a symlink never is.

    Only meaningful on Btrfs (which the store's init() proves): elsewhere any directory can
    happen to have inode 256."""
    path = _absolute(path)
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as e:
        raise SnapshotError(f"cannot stat {path}: {e}", errno=e.errno) from e
    return stat.S_ISDIR(st.st_mode) and st.st_ino == SUBVOLUME_ROOT_INO


def renameat2(dir_fd: int, old: str, new: str, flags: int) -> None:
    """libc renameat2(2), with both names relative to ``dir_fd``.

    Each name must stay below ``dir_fd``: an absolute name (the kernel would ignore
    ``dir_fd``), an empty one, or a ``.``, ``..`` or empty component raises ValueError.
    A plain syscall: if it raises SnapshotError, the rename did NOT happen."""
    old_name, new_name = _relative_name(old), _relative_name(new)
    rename = _libc_renameat2()
    if rename(dir_fd, old_name, dir_fd, new_name, flags) == 0:
        return
    code = ctypes.get_errno()
    message = f"renameat2({old!r}, {new!r}, flags={flags}) failed: {os.strerror(code)}"
    if code in _NO_SPACE_ERRNOS:
        raise SnapshotNoSpace(message, errno=code)
    raise SnapshotError(message, errno=code)


@functools.cache
def _libc_renameat2() -> Callable[..., int]:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        function = libc.renameat2
    except AttributeError as e:  # macOS, or a libc without the wrapper
        raise SnapshotError("renameat2 unavailable") from e
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    return function


def _relative_name(name: str) -> bytes:
    """``name`` as C bytes, only if it names an entry below the directory fd."""
    encoded = os.fsencode(name)
    if b"\0" in encoded:  # C would silently stop at the NUL and rename something else
        raise ValueError(f"embedded null byte in {name!r}")
    # A leading "/" gives an empty first part: absolute names are refused here too.
    if any(part in (b"", b".", b"..") for part in encoded.split(b"/")):
        raise ValueError(
            f"rename names must stay below the directory fd (relative, with no empty, "
            f"'.' or '..' parts), got {name!r}"
        )
    return encoded


def _refuse_symlink(path: Path) -> None:
    """The btrfs CLI would act on the symlink's target, so refuse it. A missing path passes:
    btrfs then reports it."""
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return
    except OSError as e:
        raise SnapshotError(f"cannot stat {path}: {e}", errno=e.errno) from e
    if stat.S_ISLNK(st.st_mode):
        raise SnapshotError(f"refusing {path}: it is a symlink", errno=errno.ELOOP)


def _require_absent(path: Path) -> None:
    """btrfs puts the snapshot INSIDE an existing directory instead of failing, so refuse here."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as e:
        raise SnapshotError(f"cannot check {path}: {e}", errno=e.errno) from e
    raise SnapshotError(f"{path} already exists", errno=errno.EEXIST)


def _absolute(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError(f"btrfs paths must be absolute, got {str(path)!r}")
    return path
