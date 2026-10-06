"""Fixtures shared by the Mac unit tests and the VM integration tests. No sudo, no btrfs."""

from datetime import UTC, datetime, timedelta

import pytest


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
