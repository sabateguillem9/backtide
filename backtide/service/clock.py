"""Is the system clock synchronised? The kernel's own answer, through ``adjtimex`` (no root).

Pruning snapshots by age with a clock that jumps would delete the wrong ones (docs/10, note of
T04), so the service prunes only when this says yes. Linux only; elsewhere it raises OSError."""

import ctypes
import errno
import functools
import sys

TIME_ERROR = 5  # adjtimex's return value: the clock is not synchronised
STA_UNSYNC = 0x0040  # in timex.status: the clock is not synchronised
_TIMEX_SIZE = 512  # struct timex is 208 bytes on 64-bit Linux; room to spare
_STATUS = slice(40, 44)  # the int `status`, after modes (4+4 padding) and four longs


def is_synchronized(state: int, status: int) -> bool:
    """adjtimex's return value and ``status``: synchronised if neither says otherwise."""
    return state != TIME_ERROR and not status & STA_UNSYNC


def clock_synced() -> bool:
    """Ask the kernel with ``modes = 0``, which only reads. Raises OSError if it cannot."""
    adjtimex = _adjtimex()
    timex = ctypes.create_string_buffer(_TIMEX_SIZE)  # zeroed: modes = 0
    state = adjtimex(timex)
    if state == -1:
        code = ctypes.get_errno()
        raise OSError(code, f"adjtimex failed: {errno.errorcode.get(code, code)}")
    status = int.from_bytes(timex.raw[_STATUS], sys.byteorder, signed=True)
    return is_synchronized(state, status)


@functools.cache
def _adjtimex():  # type: ignore[no-untyped-def]
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        function = libc.adjtimex
    except AttributeError as error:  # macOS
        raise OSError(errno.ENOSYS, "adjtimex is unavailable on this system") from error
    function.argtypes = (ctypes.c_char_p,)
    function.restype = ctypes.c_int
    return function
