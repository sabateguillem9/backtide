"""Linux inotify and openat2 through ctypes, with no dependency.

Design and rationale: docs/19-diseno-t04.md, section 1.

- libc is loaded on first use, so importing this module works on macOS; using inotify
  there raises InotifyUnavailable with a clear message.
- ``parse_events`` is pure: it turns what read(2) returned into ``RawEvent`` tuples.
- Watches are added through a directory DESCRIPTOR (``/proc/self/fd/N``), never through a
  path the agent could swap for a symlink while we resolve it.
- ``open_beneath`` opens a path relative to a directory descriptor without ever leaving it:
  openat2 with RESOLVE_BENEATH | NO_SYMLINKS | NO_XDEV | NO_MAGICLINKS, in pieces of less than
  PATH_MAX, so a path of any length works. Where openat2 does not work (an old kernel, a
  seccomp filter that answers EPERM, or macOS for the unit tests) it walks the components one
  by one with O_NOFOLLOW and refuses any component on another device (st_dev).
"""

import ctypes
import errno
import fcntl
import functools
import logging
import os
import struct
import sys
import termios
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# inotify event bits (linux/inotify.h)
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
# flags for inotify_add_watch
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_EXCL_UNLINK = 0x04000000
IN_ISDIR = 0x40000000  # set by the kernel in an event about a directory
# flags for inotify_init1 (the same values as O_CLOEXEC and O_NONBLOCK on Linux)
IN_CLOEXEC = 0o2000000
IN_NONBLOCK = 0o4000

# openat2 resolve flags (linux/openat2.h)
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RESOLVE_STRICT = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS
_SYS_OPENAT2 = 437  # the same number on x86_64 and aarch64

READ_SIZE = 64 * 1024
# openat2 refuses a path of PATH_MAX (4096) bytes or more: longer ones go in pieces.
CHUNK_BYTES = 3072
DEFAULT_MAX_USER_WATCHES = 8192
_MAX_USER_WATCHES_FILE = "/proc/sys/fs/inotify/max_user_watches"
_EVENT_HEADER = struct.Struct("=iIII")  # wd, mask, cookie, len (native order, as the kernel)


class InotifyError(OSError):
    """An inotify or openat2 call failed. ``errno`` says why (EMFILE: no instances left,
    ENOSPC: no watches left, ...)."""


class InotifyUnavailable(InotifyError):
    """inotify is not available here (not Linux, or libc without the functions)."""


@dataclass(frozen=True)
class RawEvent:
    """One ``struct inotify_event``. ``name`` is the entry's name inside the watched
    directory (empty for events about the watched directory itself). ``wd`` is -1 for
    IN_Q_OVERFLOW: the kernel queue was full and events were lost, how many is unknown."""

    wd: int
    mask: int
    cookie: int
    name: bytes


def parse_events(buf: bytes) -> list[RawEvent]:
    """Split what read(2) returned on an inotify descriptor into events.

    The kernel never returns half an event, so a buffer that ends in the middle of one is a
    bug somewhere: ValueError, never a silent truncation."""
    events: list[RawEvent] = []
    offset, end = 0, len(buf)
    while offset < end:
        if end - offset < _EVENT_HEADER.size:
            raise ValueError(f"truncated inotify buffer: {end - offset} bytes of a header")
        wd, mask, cookie, length = _EVENT_HEADER.unpack_from(buf, offset)
        offset += _EVENT_HEADER.size
        if length > end - offset:
            raise ValueError(f"truncated inotify buffer: a name of {length} bytes is cut")
        # The name is padded with NULs up to ``length``; a real name never holds one.
        name = bytes(buf[offset : offset + length]).split(b"\0", 1)[0]
        offset += length
        events.append(RawEvent(wd, mask, cookie, name))
    return events


@functools.cache
def _libc() -> ctypes.CDLL:
    if sys.platform != "linux":
        raise InotifyUnavailable(f"inotify needs Linux (this is {sys.platform})")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        libc.inotify_init1.argtypes = (ctypes.c_int,)
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_rm_watch.argtypes = (ctypes.c_int, ctypes.c_int)
        libc.inotify_rm_watch.restype = ctypes.c_int
        libc.syscall.restype = ctypes.c_long
    except AttributeError as exc:
        raise InotifyUnavailable("this libc has no inotify functions") from exc
    return libc


class _OpenHow(ctypes.Structure):
    _fields_ = (
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    )


class Inotify:
    """One inotify instance (a non-blocking descriptor). Not thread-safe by itself: the
    watcher calls ``read`` from one thread and the others under its lock.

    The limits are per user (uid) and they also count for root: ``__init__`` raises
    InotifyError with errno EMFILE when the user has no instances left."""

    def __init__(self) -> None:
        libc = _libc()
        fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if fd < 0:
            code = ctypes.get_errno()
            raise InotifyError(code, f"inotify_init1 failed: {os.strerror(code)}")
        self._fd: int | None = fd

    def fileno(self) -> int:
        if self._fd is None:
            raise ValueError("the inotify instance is closed")
        return self._fd

    def add_watch(self, dir_fd: int, mask: int) -> int:
        """Watch the directory ``dir_fd`` points to and return its watch descriptor. The same
        directory (inode) added twice gives the same wd, with the mask replaced."""
        path = f"/proc/self/fd/{dir_fd}".encode()
        wd = _libc().inotify_add_watch(self.fileno(), path, mask)
        if wd < 0:
            code = ctypes.get_errno()
            raise InotifyError(code, f"inotify_add_watch failed: {os.strerror(code)}")
        return int(wd)

    def rm_watch(self, wd: int) -> None:
        if _libc().inotify_rm_watch(self.fileno(), wd) < 0:
            code = ctypes.get_errno()
            raise InotifyError(code, f"inotify_rm_watch({wd}) failed: {os.strerror(code)}")

    def queued(self) -> int:
        """How many bytes of events are waiting in the kernel queue now (FIONREAD)."""
        buf = fcntl.ioctl(self.fileno(), termios.FIONREAD, b"\0\0\0\0")
        return int(struct.unpack("i", buf)[0])

    def read(self) -> bytes:
        """Whatever is queued, up to 64 KiB, or b"" if nothing is."""
        try:
            return os.read(self.fileno(), READ_SIZE)
        except BlockingIOError:
            return b""

    def close(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)


def max_user_watches() -> int:
    """The per-user limit of watches (a sysctl). The default of old kernels if unreadable."""
    try:
        with open(_MAX_USER_WATCHES_FILE, encoding="ascii") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError) as exc:
        logger.warning(
            "cannot read %s (%s): assuming %d",
            _MAX_USER_WATCHES_FILE,
            exc,
            DEFAULT_MAX_USER_WATCHES,
        )
        return DEFAULT_MAX_USER_WATCHES


type OpenBeneath = Callable[[int, bytes, int], int]


def open_beneath(root_fd: int, rel: bytes, flags: int) -> int:
    """Open ``rel`` (a relative path of bytes) below the directory ``root_fd`` and return the
    descriptor, never following a symlink or leaving the directory: an absolute path, any
    ``..``, a symlink in ANY component and a mount crossing are refused (OSError).

    ``.`` (or empty) is the directory itself, opened again: a new open file description,
    never a dup of ``root_fd``. Raises ValueError for a path with a NUL. The length of ``rel``
    does not matter: it is opened in pieces below PATH_MAX."""
    rel = _check_relative(rel)
    flags |= os.O_CLOEXEC
    if sys.platform == "linux" and _openat2_usable():
        return _openat2_chunked(root_fd, rel, flags)
    return _open_walking(root_fd, rel, flags)


def _check_relative(rel: bytes) -> bytes:
    if b"\0" in rel:
        raise ValueError("a path with a NUL byte")
    if rel.startswith(b"/"):
        raise OSError(errno.EXDEV, "absolute path refused", rel)
    if b".." in rel.split(b"/"):
        raise OSError(errno.EXDEV, "'..' refused", rel)
    return rel or b"."


@functools.cache
def _openat2_usable() -> bool:
    """Whether openat2 works in this process, asked once. ENOSYS (an old kernel) and EPERM (a
    seccomp filter that blocks it) mean no: the walking fallback is used, with one warning.
    After a working probe, an EPERM is a real refusal and reaches the caller."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        probe = _openat2(fd, b".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        logger.warning(
            "openat2 does not work here (%s): walking paths component by component",
            errno.errorcode.get(exc.errno or 0, exc.errno),
        )
        return False
    finally:
        os.close(fd)
    os.close(probe)
    return True


def _chunks(rel: bytes) -> list[bytes]:
    """``rel`` cut at slashes into pieces of at most CHUNK_BYTES (a name is at most 255)."""
    pieces: list[bytes] = []
    current: list[bytes] = []
    size = 0
    for part in rel.split(b"/"):
        if current and size + 1 + len(part) > CHUNK_BYTES:
            pieces.append(b"/".join(current))
            current, size = [], 0
        size += len(part) + (1 if current else 0)
        current.append(part)
    pieces.append(b"/".join(current))
    return pieces


def _openat2_chunked(root_fd: int, rel: bytes, flags: int) -> int:
    """openat2 piece by piece: each piece is resolved beneath the directory the previous one
    opened, which is beneath ``root_fd``, so the whole path never leaves it either."""
    pieces = _chunks(rel)
    current = root_fd
    try:
        for piece in pieces[:-1]:
            next_fd = _openat2(current, piece, _DIR_PATH_FLAGS)
            if current != root_fd:
                os.close(current)
            current = next_fd
        return _openat2(current, pieces[-1], flags)
    finally:
        if current != root_fd:
            os.close(current)


_DIR_PATH_FLAGS = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_CLOEXEC


def _openat2(root_fd: int, rel: bytes, flags: int) -> int:
    how = _OpenHow(flags, 0, RESOLVE_STRICT)
    libc = _libc()
    fd = libc.syscall(
        ctypes.c_long(_SYS_OPENAT2),
        ctypes.c_int(root_fd),
        ctypes.c_char_p(rel),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if fd < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), rel)
    return int(fd)


def _open_walking(root_fd: int, rel: bytes, flags: int) -> int:
    """Fallback: one openat per component, each with O_NOFOLLOW and O_DIRECTORY (the last
    one with the caller's flags). Refuses ``..``; a symlink anywhere fails with ELOOP/ENOTDIR;
    a component on another device than ``root_fd`` (a mount, or a nested Btrfs subvolume,
    which openat2 would let through) fails with EXDEV."""
    parts = [part for part in rel.split(b"/") if part not in (b"", b".")]
    if b".." in parts:
        raise OSError(errno.EXDEV, "'..' refused", rel)
    if not parts:
        # A NEW open of the directory itself, never a dup: a dup shares the old open file
        # description, and btrfs fixes a directory's listing when it is opened (the watcher
        # reopens ``.`` after its watch to list what came since).
        return os.open(".", flags | os.O_NOFOLLOW, dir_fd=root_fd)
    device = os.fstat(root_fd).st_dev
    current = root_fd
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            next_fd = os.open(
                part,
                (flags if last else os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) | os.O_NOFOLLOW,
                dir_fd=current,
            )
            if os.fstat(next_fd).st_dev != device:
                os.close(next_fd)
                raise OSError(errno.EXDEV, "a mount crossing refused", rel)
            if current != root_fd:
                os.close(current)
            current = next_fd
        result, current = current, root_fd  # the caller owns it now
        return result
    finally:
        if current != root_fd:
            os.close(current)
