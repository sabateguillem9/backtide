"""The clock check: the decision is pure; reading the kernel is tested in the VM."""

import sys

import pytest

from vigia.service import clock


@pytest.mark.parametrize(
    ("state", "status", "expected"),
    [
        pytest.param(0, 0x2001, True, id="time-ok"),
        pytest.param(1, 0, True, id="leap-second-pending"),
        pytest.param(5, 0, False, id="time-error"),
        pytest.param(0, 0x0040, False, id="unsync-bit"),
        pytest.param(0, 0x2001 | 0x0040, False, id="unsync-bit-among-others"),
        pytest.param(5, 0x0040, False, id="both"),
    ],
)
def test_is_synchronized(state: int, status: int, expected: bool) -> None:
    assert clock.is_synchronized(state, status) is expected


@pytest.mark.skipif(sys.platform == "linux", reason="Linux has adjtimex")
def test_without_adjtimex_it_raises_os_error() -> None:
    with pytest.raises(OSError, match="adjtimex"):
        clock.clock_synced()
