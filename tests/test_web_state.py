"""The agent's state and the tide, told from the black box alone."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.conftest import FakeClock
from tests.test_web_narrate import START, ev
from tests.webkit import new_box
from vigia.web.reader import BoxReader, BoxUnavailable
from vigia.web.state import FROZEN, STOPPED, UNKNOWN, WATCHED, read_status, status_from
from vigia.web.tide import MAX_MARKS, WIDTH, build_tide


def system(seq: int, action: str, **details) -> object:
    return ev(seq, "system", action, details=details, at=seq)


@pytest.mark.parametrize(
    ("events", "state"),
    [
        ([], UNKNOWN),
        ([ev(1, "file", "create", "a")], UNKNOWN),  # nothing says anything about the agent
        ([system(1, "service_start"), system(2, "agent_start")], WATCHED),
        ([system(1, "agent_start"), system(2, "agent_stop", reason="rewind")], STOPPED),
        ([system(1, "agent_start"), system(2, "space_pause", frozen=True)], FROZEN),
        ([system(1, "agent_start"), system(2, "space_pause", frozen=False)], STOPPED),
        ([system(1, "agent_start"), system(2, "space_pause", killed=True)], STOPPED),
        ([system(1, "space_pause", frozen=True), system(2, "space_resume")], WATCHED),
        ([system(1, "agent_start"), system(2, "service_stop")], STOPPED),
        ([system(1, "agent_start"), system(2, "agent_stop_failed")], UNKNOWN),
        ([system(1, "agent_start_failed")], STOPPED),
        ([system(1, "agent_stop"), system(2, "service_start")], STOPPED),  # starting up
        ([system(1, "agent_start"), system(2, "log")], WATCHED),  # other events do not move it
    ],
)
def test_the_newest_moving_event_decides(events: list, state: str) -> None:
    assert status_from(events).state == state


def test_order_of_the_list_does_not_matter_only_seq() -> None:
    newest_first = [system(2, "agent_stop", reason="rewind"), system(1, "agent_start")]
    assert status_from(newest_first).state == STOPPED


def test_status_says_when_the_signal_was() -> None:
    status = status_from([system(7, "agent_start")])
    assert status.since == START + timedelta(seconds=7)


def test_read_status_from_a_real_box(tmp_path: Path) -> None:
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "agent_start", "")
    for i in range(300):  # a lot of noise after: the state still comes from the right event
        box.append("system", "log", f"n{i}")
    reader = BoxReader(tmp_path / "blackbox.db")
    assert read_status(reader).state == WATCHED
    box.append("system", "space_pause", "", details={"frozen": True}, risk=2)
    assert read_status(reader).state == FROZEN
    box.append(
        "snapshot",
        "take",
        "20261016T100000.000000Z-periodic",
        snapshot_id="20261016T100000.000000Z-periodic",
    )
    assert read_status(reader).state == FROZEN


def test_reader_reports_a_missing_box_as_unavailable_and_recovers(tmp_path: Path) -> None:
    reader = BoxReader(tmp_path / "blackbox.db")
    with pytest.raises(BoxUnavailable):
        reader.events()
    assert not (tmp_path / "blackbox.db").exists(), "reading never creates the box"
    new_box(tmp_path).append("system", "agent_start", "")
    assert reader.head_seq() == 1  # the same reader, no restart


def test_reader_is_read_only(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    reader = BoxReader(tmp_path / "blackbox.db")
    reader.events()
    assert reader._box is not None  # noqa: SLF001 - the point of the test
    from vigia.blackbox import BlackBoxError

    with pytest.raises(BlackBoxError):
        reader._box.append("file", "create", "x")  # noqa: SLF001
    assert box.head()[0] == 1


# -- the tide ------------------------------------------------------------------------------------

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def take(seq: int, ago: timedelta):
    return replace(
        ev(seq, "snapshot", "take", "s"), ts=(NOW - ago).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )


def test_a_snapshot_now_sits_at_the_head_and_one_a_day_ago_at_the_start() -> None:
    tide = build_tide(
        [take(1, timedelta(hours=24)), take(2, timedelta(hours=12)), take(3, timedelta())], NOW
    )
    xs = [mark.x for mark in tide.marks]
    assert xs[0] == tide.left and xs[2] == tide.right
    assert xs[1] == pytest.approx((tide.left + tide.right) / 2, abs=0.1)
    assert tide.total == 3 and tide.width == WIDTH


def test_older_than_a_day_is_left_out_and_a_slow_clock_is_clamped() -> None:
    tide = build_tide([take(1, timedelta(hours=25)), take(2, -timedelta(seconds=3))], NOW)
    assert [mark.x for mark in tide.marks] == [tide.right]


def test_the_tide_caps_its_marks() -> None:
    many = [take(i, timedelta(minutes=i)) for i in range(1, MAX_MARKS + 50)]
    assert len(build_tide(many, NOW).marks) == MAX_MARKS


def test_marks_sit_where_the_snapshot_was_taken_not_where_it_was_recorded() -> None:
    """The black box may record a take later than the snapshot it names (a service that was
    down): the point to go back to is the snapshot's own time."""
    old = replace(
        ev(1, "snapshot", "take", "20261016T060000.000000Z-periodic"),
        ts=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        snapshot_id="20261016T060000.000000Z-periodic",
    )
    tide = build_tide([old], NOW)  # six hours before NOW
    assert len(tide.marks) == 1
    assert tide.marks[0].x == pytest.approx(tide.left + (tide.right - tide.left) * 0.75, abs=0.1)


def test_a_mark_is_not_hidden_under_the_head_dot_at_a_different_time() -> None:
    old = replace(
        ev(1, "snapshot", "take", "s"),
        ts=NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        snapshot_id="20261016T080000.000000Z-periodic",
    )
    tide = build_tide([old], NOW)
    assert tide.marks[0].x < tide.right - 10
