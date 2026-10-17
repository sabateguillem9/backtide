"""Thin, stateless wrapper over the btrfs CLI, plus the syscalls the CLI does not offer.

- Every command runs with a fixed argv, never through a shell, with ``LC_ALL=C`` (so error
  messages are stable) and a timeout. Nothing here calls sudo: commands run with whatever
  privileges the process has.
- Privileges: only set_qgroup_limit needs CAP_SYS_ADMIN (the kernel refuses
  BTRFS_IOC_QGROUP_LIMIT otherwise, and btrfs reports "Operation not permitted"). Everything
  else works for the unprivileged owner of the subvolumes on a volume mounted with
  ``user_subvol_rm_allowed``. Code that runs unprivileged, like the VM tests, does not call
  set_qgroup_limit: it gets a setter built on qgroup_limit_args injected instead.
- Quotas are simple quotas (squota), enabled when the volume is formatted. Usage and limits
  are read from /sys/fs/btrfs without privileges (``btrfs qgroup show`` needs root), and the
  filesystem's UUID comes from the unprivileged BTRFS_IOC_FS_INFO ioctl.
- Never runs ``btrfs qgroup destroy`` or ``clear-stale``: on kernels before 7.1, freeing an
  extent whose owner qgroup is gone aborts the transaction and the volume turns read-only.
- Paths must be absolute (otherwise ValueError), so a path can never be read as an option.
- The CLI follows a symlink in the last component (``property`` opens the path, ``subvolume
  delete`` calls realpath and deletes the target). So the functions that read or change a
  subvolume refuse a symlink there, and delete_subvolume refuses anything but a subvolume root.
  The check and the command are two steps: this stops bugs and tampering done beforehand, not
  someone renaming entries concurrently in a directory they can write to.
- Never parses ``subvolume list``, ``subvolume show`` or ``qgroup show``: they need root and
  have no JSON output in btrfs-progs 6.19 (``qgroup show`` has, but still needs root).
- When a command fails or times out, the operation may or may not have happened. Callers
  check the postcondition they need (the store does).
- The store calls these as ``btrfs.<fn>``, so unit tests can monkeypatch them or
  ``subprocess.run``.
- libc's ``renameat2`` is loaded on first use, so importing this module works on macOS.
- ``subvolume_info`` (BTRFS_IOC_GET_SUBVOL_INFO) and ``sync_filesystem`` need no privileges: the
  service reads the workspace's change counters every cycle without being root (docs/19).
"""

import ctypes
import errno
import fcntl
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
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NoReturn
from uuid import UUID

from backtide.snapshots.model import SnapshotError, SnapshotNoSpace

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
SUBVOLUME_ROOT_INO = 256  # the root directory of every btrfs subvolume has this inode number
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2

SYSFS_BTRFS = Path("/sys/fs/btrfs")
# _IOR(0x94, 31, struct btrfs_ioctl_fs_info_args): 1024 bytes, the fsid at bytes 16..32.
BTRFS_IOC_FS_INFO = 0x8400941F
_FS_INFO_SIZE = 1024
_FS_INFO_FSID = slice(16, 32)
# limit_flags bits (BTRFS_QGROUP_LIMIT_MAX_*): which of max_referenced/max_exclusive apply.
QGROUP_LIMIT_MAX_RFER = 1
QGROUP_LIMIT_MAX_EXCL = 2
_U64_MAX = 2**64 - 1  # `qgroup limit none` sends this value, so it is never a valid limit
# _IOR(0x94, 60, struct btrfs_ioctl_get_subvol_info_args): 504 bytes. Offsets of the fields read.
BTRFS_IOC_GET_SUBVOL_INFO = 0x81F8943C
_SUBVOL_INFO_SIZE = 504
_SUBVOL_NAME = slice(8, 8 + 256)  # BTRFS_VOL_NAME_MAX + 1
_SUBVOL_UUID = slice(296, 312)
_SUBVOL_PARENT_UUID = slice(312, 328)
_ROOT_SUBVOL_RDONLY = 1  # bit 0 of the flags

type QuotaMode = Literal["squota", "qgroup"]

_NO_SPACE_STDERR = {"No space left on device": errno.ENOSPC, "Disk quota exceeded": errno.EDQUOT}
_NO_SPACE_ERRNOS = frozenset(_NO_SPACE_STDERR.values())
_ROOT_ID_RE = re.compile(r"([1-9][0-9]*)\n", re.ASCII)
_U64_RE = re.compile(r"(0|[1-9][0-9]*)\n", re.ASCII)
_LEVEL0_QGROUP_RE = re.compile(r"0_([1-9][0-9]*)", re.ASCII)  # a subvolume's qgroup in /sys
_READONLY_OUTPUT = {"ro=true\n": True, "ro=false\n": False}
_QUOTA_MODES: dict[str, QuotaMode] = {"squota\n": "squota", "qgroup\n": "qgroup"}

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
            # Its own session: a Ctrl-C in the terminal reaches backtide only, never a btrfs in the
            # middle of a snapshot or a swap. A timeout still kills the child (by pid).
            start_new_session=True,
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


@dataclass(frozen=True)
class QgroupUsage:
    """A subvolume's level-0 qgroup, as /sys/fs/btrfs shows it. Bytes, except limit_flags.

    Under simple quotas ``referenced == exclusive``: data and fs-tree blocks the subvolume
    allocated and that are still on disk. Each value is read separately, so they may come
    from slightly different moments."""

    referenced: int
    exclusive: int
    limit_flags: int
    max_referenced: int
    max_exclusive: int

    @property
    def limit(self) -> int | None:
        """The referenced limit (the one qgroup_limit_args sets), or None if there is none."""
        return self.max_referenced if self.limit_flags & QGROUP_LIMIT_MAX_RFER else None

    @property
    def exclusive_limit(self) -> int | None:
        """The exclusive limit (``qgroup limit -e``), or None. backtide never sets one, but it
        caps writes just the same, so "no cap" means both limits are None."""
        return self.max_exclusive if self.limit_flags & QGROUP_LIMIT_MAX_EXCL else None


def qgroup_limit_args(path: Path, limit: int | None) -> tuple[str, ...]:
    """The argv after ``btrfs`` that sets (or, with None, lifts) the referenced limit of the
    subvolume at ``path``. Pure: no I/O, so a caller with other privileges can run it.

    The two-argument form, ``qgroup limit <bytes>|none <path>``: btrfs-progs checks that
    ``path`` is a subvolume root and limits that subvolume's own qgroup (0/<its id>)."""
    path = _absolute(path)
    token = "none" if limit is None else str(_valid_limit(limit))
    return ("qgroup", "limit", token, str(path))


def set_qgroup_limit(path: Path, limit: int | None) -> None:
    """Set (or, with None, lift) the referenced limit of the subvolume at ``path``.

    Needs CAP_SYS_ADMIN. Refuses a symlink, whose target btrfs would limit, and anything that
    is not a subvolume root, before running anything."""
    args = qgroup_limit_args(path, limit)  # validates first: no I/O on bad input
    path = _absolute(path)
    _refuse_symlink(path)
    if not is_subvolume(path):
        raise SnapshotError(
            f"refusing to limit {path}: not a subvolume root (missing, a plain directory or a file)"
        )
    run(*args)


def fsid(path: Path) -> str:
    """The UUID of the btrfs that holds the directory ``path``: the name of its directory in
    /sys/fs/btrfs. Unprivileged (BTRFS_IOC_FS_INFO has no capability check). Refuses a
    symlink."""
    path = _absolute(path)
    _refuse_symlink(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise SnapshotError(f"cannot open {path}: {e}", errno=e.errno) from e
    info = bytearray(_FS_INFO_SIZE)
    try:
        fcntl.ioctl(fd, BTRFS_IOC_FS_INFO, info)
    except OSError as e:
        raise SnapshotError(f"BTRFS_IOC_FS_INFO on {path} failed: {e}", errno=e.errno) from e
    finally:
        os.close(fd)
    return str(UUID(bytes=bytes(info[_FS_INFO_FSID])))


@dataclass(frozen=True)
class SubvolumeInfo:
    """What BTRFS_IOC_GET_SUBVOL_INFO says about a subvolume (the fields backtide uses).

    ``ctransid`` moves at once with any change to the subvolume (create, write, chmod, mmap,
    delete) and not with a read; ``generation`` only moves when the transaction commits. A
    snapshot copies the ``ctransid`` of its origin, and its ``parent_uuid`` is the origin's
    ``uuid`` (None for a subvolume that is not a snapshot). ``otransid`` is the transaction
    that created the subvolume."""

    treeid: int  # the subvolume ID, the same number as subvolume_id()
    name: str
    generation: int
    flags: int
    uuid: UUID
    parent_uuid: UUID | None
    ctransid: int
    otransid: int

    @property
    def readonly(self) -> bool:
        return bool(self.flags & _ROOT_SUBVOL_RDONLY)


def parse_subvolume_info(buffer: bytes) -> SubvolumeInfo:
    """Decode the ioctl's 504-byte answer (little endian, as on every Linux backtide runs on)."""
    if len(buffer) != _SUBVOL_INFO_SIZE:
        raise SnapshotError(
            f"BTRFS_IOC_GET_SUBVOL_INFO answered {len(buffer)} bytes, expected {_SUBVOL_INFO_SIZE}"
        )

    def u64(offset: int) -> int:
        return int.from_bytes(buffer[offset : offset + 8], "little")

    parent = UUID(bytes=bytes(buffer[_SUBVOL_PARENT_UUID]))
    return SubvolumeInfo(
        treeid=u64(0),
        name=bytes(buffer[_SUBVOL_NAME]).split(b"\0", 1)[0].decode("utf-8", errors="replace"),
        generation=u64(280),
        flags=u64(288),
        uuid=UUID(bytes=bytes(buffer[_SUBVOL_UUID])),
        parent_uuid=parent if parent.int else None,
        ctransid=u64(344),
        otransid=u64(352),
    )


def subvolume_info(path: Path) -> SubvolumeInfo:
    """The change counters and lineage of the subvolume at ``path``. Unprivileged, and cheap
    (about 6 µs): the service calls it for the workspace and every snapshot each cycle.

    Refuses anything that is not a subvolume root (the ioctl would answer for the subvolume
    that CONTAINS a plain directory) and a symlink."""
    path = _absolute(path)
    if not is_subvolume(path):
        raise SnapshotError(
            f"cannot read the subvolume info of {path}: not a subvolume root "
            "(missing, a plain directory, a file or a symlink)"
        )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise SnapshotError(f"cannot open {path}: {e}", errno=e.errno) from e
    info = bytearray(_SUBVOL_INFO_SIZE)
    try:
        fcntl.ioctl(fd, BTRFS_IOC_GET_SUBVOL_INFO, info)
    except OSError as e:
        raise SnapshotError(
            f"BTRFS_IOC_GET_SUBVOL_INFO on {path} failed: {e}", errno=e.errno
        ) from e
    finally:
        os.close(fd)
    return parse_subvolume_info(bytes(info))


def sync_filesystem(path: Path) -> None:
    """``btrfs filesystem sync``: commit the transaction of the btrfs that holds ``path``, so
    ``generation`` and qgroup usage catch up. Unprivileged."""
    run("filesystem", "sync", _absolute(path))


def quota_mode(path: Path, *, sysfs: Path = SYSFS_BTRFS) -> QuotaMode | None:
    """``"squota"`` (simple quotas), ``"qgroup"`` (full qgroups) or None (quotas off) for the
    btrfs that holds ``path``. Unprivileged."""
    path = _absolute(path)
    qgroups = _fs_dir(path, sysfs) / "qgroups"
    if not _exists(qgroups):  # the kernel removes qgroups/ when quotas are disabled
        return None
    text = _read_sysfs(qgroups / "mode")
    if text not in _QUOTA_MODES:
        raise SnapshotError(f"unexpected content in {qgroups / 'mode'}: {text!r}")
    return _QUOTA_MODES[text]


def qgroup_usage(path: Path, *, sysfs: Path = SYSFS_BTRFS) -> QgroupUsage:
    """Usage and limits of the qgroup of the subvolume at ``path``. Unprivileged.

    Refuses anything that is not a subvolume root: a plain directory would report the qgroup of
    the subvolume that contains it. SnapshotError if quotas are off (no qgroup directory) or a
    value is not a decimal u64."""
    path = _absolute(path)
    if not is_subvolume(path):
        raise SnapshotError(
            f"cannot read the qgroup of {path}: not a subvolume root "
            "(missing, a plain directory, a file or a symlink)"
        )
    qgroup = _fs_dir(path, sysfs) / "qgroups" / f"0_{subvolume_id(path)}"
    if not _exists(qgroup):
        raise SnapshotError(f"{qgroup} is missing: are quotas enabled on {path}?")
    return QgroupUsage(
        referenced=_read_u64(qgroup / "referenced"),
        exclusive=_read_u64(qgroup / "exclusive"),
        limit_flags=_read_u64(qgroup / "limit_flags"),
        max_referenced=_read_u64(qgroup / "max_referenced"),
        max_exclusive=_read_u64(qgroup / "max_exclusive"),
    )


def level0_qgroups(path: Path, *, sysfs: Path = SYSFS_BTRFS) -> dict[int, QgroupUsage]:
    """Every level-0 qgroup (one per subvolume, ``0/<id>``) of the btrfs that holds ``path``,
    by subvolume id. Unprivileged. Empty when quotas are off. Under simple quotas a deleted
    subvolume keeps its qgroup while snapshots still share what it wrote: that is how the
    pause by space names the old workspaces that still hold room (T04d-2)."""
    qgroups = _fs_dir(_absolute(path), sysfs) / "qgroups"
    if not _exists(qgroups):
        return {}
    try:
        names = os.listdir(qgroups)
    except OSError as e:
        raise SnapshotError(f"cannot list {qgroups}: {e}", errno=e.errno) from e
    found: dict[int, QgroupUsage] = {}
    for name in names:
        match = _LEVEL0_QGROUP_RE.fullmatch(name)
        if match is None:
            continue
        qgroup = qgroups / name
        found[int(match.group(1))] = QgroupUsage(
            referenced=_read_u64(qgroup / "referenced"),
            exclusive=_read_u64(qgroup / "exclusive"),
            limit_flags=_read_u64(qgroup / "limit_flags"),
            max_referenced=_read_u64(qgroup / "max_referenced"),
            max_exclusive=_read_u64(qgroup / "max_exclusive"),
        )
    return found


def _valid_limit(limit: object) -> int:
    # bool is an int subclass: True would silently become a 1-byte cap.
    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit < _U64_MAX:
        raise ValueError(f"a qgroup limit must be an int of bytes in [1, 2**64 - 2], got {limit!r}")
    return limit


def _fs_dir(path: Path, sysfs: Path) -> Path:
    """/sys/fs/btrfs/<fsid> of the btrfs that holds ``path``. It always exists for a mounted
    btrfs, so a missing one means sysfs is not what this code expects."""
    directory = sysfs / fsid(path)
    if not _exists(directory):
        raise SnapshotError(f"{directory} is missing: is sysfs mounted?")
    return directory


def _exists(path: Path) -> bool:
    try:
        os.stat(path)
    except FileNotFoundError:
        return False
    except OSError as e:
        raise SnapshotError(f"cannot stat {path}: {e}", errno=e.errno) from e
    return True


def _read_sysfs(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError as e:
        raise SnapshotError(f"cannot read {path}: {e}", errno=e.errno) from e


def _read_u64(path: Path) -> int:
    text = _read_sysfs(path)
    match = _U64_RE.fullmatch(text)
    if match is None or int(match.group(1)) > _U64_MAX:
        raise SnapshotError(f"unexpected content in {path}: {text!r}")
    return int(match.group(1))


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
