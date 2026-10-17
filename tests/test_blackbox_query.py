"""The extra filters of BlackBox.events() that the web's history page needs: older than a
seq, at least some risk, and a time range. Reading only: nothing here writes."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox
from tests.conftest import FakeClock

KEY = bytes(range(32))


@pytest.fixture
def box(tmp_path: Path, clock: FakeClock) -> BlackBox:
    box = BlackBox(tmp_path / "bb.db", KEY, checkpoint_path=tmp_path / "bb.cp", clock=clock)
    # seq 1..5, one hour apart; risks 0, 2, 1, 3, 0
    for risk in (0, 2, 1, 3, 0):
        box.append("file", "modify", f"f{risk}", risk=risk)
        clock.advance(timedelta(hours=1))
    return box


@pytest.mark.parametrize(
    ("kwargs", "seqs"),
    [
        ({"before_seq": 4, "newest_first": True}, [3, 2, 1]),
        ({"before_seq": 4, "newest_first": True, "limit": 2}, [3, 2]),
        ({"before_seq": 1}, []),
        ({"min_risk": 1}, [2, 3, 4]),
        ({"min_risk": 3}, [4]),
        ({"min_risk": 0}, [1, 2, 3, 4, 5]),
        ({"min_risk": 2, "before_seq": 4}, [2]),
    ],
)
def test_before_seq_and_min_risk(box: BlackBox, kwargs: dict, seqs: list[int]) -> None:
    assert [event.seq for event in box.events(**kwargs)] == seqs


def test_time_range_is_since_inclusive_until_exclusive(box: BlackBox) -> None:
    third = datetime.fromisoformat(box.events()[2].ts)
    assert [e.seq for e in box.events(since_ts=third)] == [3, 4, 5]
    assert [e.seq for e in box.events(until_ts=third)] == [1, 2]
    assert [e.seq for e in box.events(since_ts=third, until_ts=third + timedelta(hours=2))] == [
        3,
        4,
    ]


def test_time_range_accepts_any_timezone(box: BlackBox) -> None:
    third = datetime.fromisoformat(box.events()[2].ts)
    madrid = third.astimezone(timezone(timedelta(hours=2)))
    assert [e.seq for e in box.events(since_ts=madrid)] == [3, 4, 5]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"before_seq": 0},
        {"before_seq": "3"},
        {"before_seq": True},
        {"min_risk": -1},
        {"min_risk": 4},
        {"min_risk": True},
        {"min_risk": "1"},
        {"since_ts": "2026-10-05"},
        {"since_ts": datetime(2026, 10, 5)},  # naive: ambiguous, refused
        {"until_ts": 5},
    ],
)
def test_invalid_new_filters_are_refused(box: BlackBox, kwargs: dict) -> None:
    with pytest.raises(ValueError):
        box.events(**kwargs)


def test_they_work_on_a_readonly_box(box: BlackBox, tmp_path: Path) -> None:
    with BlackBox(tmp_path / "bb.db", KEY, readonly=True) as readonly:
        assert [e.seq for e in readonly.events(min_risk=2, newest_first=True)] == [4, 2]


def test_a_time_filter_does_not_depend_on_the_system_timezone(box: BlackBox) -> None:
    first = datetime.fromisoformat(box.events()[0].ts)
    assert first.tzinfo == UTC
