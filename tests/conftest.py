"""Fixtures shared by the Mac unit tests and the VM integration tests. No sudo, no btrfs."""

import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--idle-seconds",
        type=int,
        default=250,
        help="how long tests/integration/test_idle.py leaves the real OpenClaw idle "
        "(250 s by default; the 10-minute measurement of docs/19 uses 600)",
    )


class FakeClock:
    """A controllable clock. Each read returns the current instant and then moves
    1 µs forward, so two takes or restores never get the same snapshot id."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def __call__(self) -> datetime:
        now = self._now
        self._now += timedelta(microseconds=1)
        return now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 10, 5, 8, 0, tzinfo=UTC))


def call_unblocking_fifo(
    function: Callable[[], object], fifo: Path, timeout: float = 5.0
) -> object:
    """Call ``function`` in a thread and return what it returned or raised. If it is still
    blocked (opening ``fifo``, waiting for a writer) after ``timeout`` seconds, open the
    other end so the thread can finish, and fail the test."""
    outcome: list[object] = []

    def run() -> None:
        try:
            outcome.append(function())
        except BaseException as exc:  # noqa: BLE001 - handed back to the test
            outcome.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))  # wakes the blocked reader
        thread.join(timeout)
        pytest.fail(f"blocked on the FIFO {fifo}")
    return outcome[0]
