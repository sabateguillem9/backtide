"""The web's and the CLI's clock follow the machine's zone with its changes of time (code review
of 2026-10-29, W2: today's fixed offset put every time an hour off across a change)."""

from datetime import UTC, datetime

import pytest

from backtide.web import format as fmt


def test_times_follow_the_change_of_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Europe/Madrid")
    zone = fmt.local_tz()
    summer = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    winter = datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
    assert fmt.stamp(summer, zone) == "2026-08-01 14:00:00"
    assert fmt.stamp(winter, zone) == "2026-12-01 13:00:00"


def test_the_cli_reads_the_same_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    from backtide import cli

    monkeypatch.setenv("TZ", "America/New_York")
    zone = cli._local_tz()  # noqa: SLF001
    assert (
        datetime(2026, 7, 1, tzinfo=UTC).astimezone(zone).utcoffset().total_seconds() == -4 * 3600
    )
    assert (
        datetime(2026, 1, 1, tzinfo=UTC).astimezone(zone).utcoffset().total_seconds() == -5 * 3600
    )
