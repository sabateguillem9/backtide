"""The read budget of unknown hosts (backtide/service/read_budget.py; review of T10-3, M5)."""

import pytest

from backtide.service.read_budget import (
    DEFAULT_HOST_BYTES,
    DEFAULT_TOTAL_BYTES,
    WINDOW_S,
    ReadBudget,
)


def test_the_defaults_are_256_kib_per_host_and_2_mib_in_total() -> None:
    budget = ReadBudget()
    assert (budget.host_bytes, budget.total_bytes) == (256 * 1024, 2 * 1024 * 1024)
    assert (DEFAULT_HOST_BYTES, DEFAULT_TOTAL_BYTES) == (262_144, 2_097_152)


def test_a_host_gets_its_bytes_per_hour_and_no_more() -> None:
    budget = ReadBudget(host_bytes=1000, total_bytes=10_000)
    assert budget.take("a.test", 600, 0.0)
    assert budget.take("a.test", 400, 1.0)
    assert not budget.take("a.test", 1, 2.0)  # over: nothing is spent
    assert budget.used("a.test") == 1000
    assert budget.take("b.test", 1000, 3.0)  # another host has its own
    assert budget.take("a.test", 1000, WINDOW_S)  # a new hour
    assert budget.used("a.test") == 1000


def test_every_host_together_meets_the_total() -> None:
    budget = ReadBudget(host_bytes=1000, total_bytes=2500)
    assert budget.take("a.test", 1000, 0.0) and budget.take("b.test", 1000, 0.0)
    assert not budget.take("c.test", 600, 0.0)  # the total, not c's own
    assert budget.used("c.test") == 0
    assert budget.take("c.test", 500, 0.0)
    assert budget.take("d.test", 1000, WINDOW_S)  # the total's hour ended too


def test_a_refused_read_spends_nothing() -> None:
    budget = ReadBudget(host_bytes=100, total_bytes=150)
    assert not budget.take("a.test", 101, 0.0)
    assert budget.take("a.test", 100, 0.0) and budget.take("b.test", 50, 0.0)


def test_too_many_hosts_fail_closed_until_their_hours_end() -> None:
    budget = ReadBudget(host_bytes=100, total_bytes=10_000, max_hosts=2)
    assert budget.take("a.test", 1, 0.0) and budget.take("b.test", 1, 10.0)
    assert not budget.take("c.test", 1, 20.0)  # no room to remember c: held
    assert budget.take("a.test", 1, 30.0)  # a known host still has its window
    assert budget.take("c.test", 1, WINDOW_S + 1)  # a's hour ended: forgotten, room for c


def test_a_zero_budget_holds_every_read_that_carries_anything() -> None:
    budget = ReadBudget(host_bytes=0, total_bytes=0)
    assert not budget.take("a.test", 1, 0.0)
    assert budget.take("a.test", 0, 0.0)


def test_a_clock_that_goes_back_starts_a_new_window() -> None:
    budget = ReadBudget(host_bytes=100, total_bytes=100)
    assert budget.take("a.test", 100, 50.0)
    assert budget.take("a.test", 100, 10.0)


def test_a_negative_budget_is_refused() -> None:
    with pytest.raises(ValueError):
        ReadBudget(host_bytes=-1)
