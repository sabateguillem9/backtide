"""The black box's secret key: 32 random bytes in a 0600 file.

The key never lives in the snapshot volume and the agent's container never sees it
(invariant 1). Without it nobody can recompute a valid chain or forge the checkpoint.
"""

import errno
import os
import secrets
import stat
from pathlib import Path

from vigia.blackbox.model import BlackBoxError

KEY_SIZE = 32


def create_key(path: str | os.PathLike[str]) -> bytes:
    """Create a new key file at ``path`` (mode 0600) and return the key.

    Never overwrites: raises BlackBoxError if anything already exists at ``path``."""
    path = Path(path)
    key = secrets.token_bytes(KEY_SIZE)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise BlackBoxError(f"key file already exists, refusing to overwrite it: {path}") from exc
    except OSError as exc:
        raise BlackBoxError(f"cannot create key file {path}: {exc}") from exc
    try:
        os.fchmod(fd, 0o600)  # the umask may only remove bits; make the mode exact anyway
        _write_all(fd, key)
        os.fsync(fd)
    except OSError as exc:
        os.close(fd)
        path.unlink(missing_ok=True)  # we created it with O_EXCL: it is ours to remove
        raise BlackBoxError(f"cannot write key file {path}: {exc}") from exc
    os.close(fd)
    try:
        _fsync_directory(path.parent)
    except OSError as exc:
        raise BlackBoxError(f"key file {path} written but its folder not synced: {exc}") from exc
    return key


def load_key(path: str | os.PathLike[str]) -> bytes:
    """Read the key at ``path``. Raises BlackBoxError unless it is a regular file (not a
    symlink, never blocking on a FIFO) owned by this process's user, not readable or
    writable by group or others, and exactly KEY_SIZE bytes."""
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise BlackBoxError(f"key file is a symlink: {path}") from exc
        raise BlackBoxError(f"cannot open key file {path}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BlackBoxError(f"key file is not a regular file: {path}")
        if info.st_uid != os.geteuid():
            # Another user could read the key, or swap it, and then forge the whole chain.
            raise BlackBoxError(f"key file {path} is not owned by this user (uid {info.st_uid})")
        if info.st_mode & 0o077:
            mode = stat.S_IMODE(info.st_mode)
            raise BlackBoxError(f"key file {path} is open to group or others (mode {mode:04o})")
        data = os.read(fd, KEY_SIZE + 1)
    except OSError as exc:
        raise BlackBoxError(f"cannot read key file {path}: {exc}") from exc
    finally:
        os.close(fd)
    if len(data) != KEY_SIZE:
        raise BlackBoxError(f"key file {path} must hold exactly {KEY_SIZE} bytes")
    return data


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
