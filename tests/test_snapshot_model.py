import random
from datetime import UTC, datetime, timedelta, timezone

import pytest

from vigia.snapshots import (
    PruneIncomplete,
    Reason,
    RestoreIncomplete,
    Snapshot,
    SnapshotBusy,
    SnapshotError,
    SnapshotNoSpace,
)

T = datetime(2026, 10, 5, 20, 15, 30, 123456, tzinfo=UTC)
VALID_ID = "20261005T201530.123456Z-periodic"


def test_id_format() -> None:
    assert Snapshot(T, Reason.PERIODIC).id == VALID_ID


def test_reason_is_stored_as_plain_str() -> None:
    assert type(Snapshot(T, Reason.MANUAL).reason) is str


@pytest.mark.parametrize(
    "taken_at",
    [
        datetime(2026, 10, 5, 20, 15, 30),  # naive
        datetime(2026, 10, 5, 22, 15, 30, tzinfo=timezone(timedelta(hours=2))),  # CEST
    ],
)
def test_taken_at_must_be_utc(taken_at: datetime) -> None:
    with pytest.raises(ValueError):
        Snapshot(taken_at, Reason.PERIODIC)


@pytest.mark.parametrize("reason", ["Periodic", "pre-restore", "a" * 33, "", "1abc", "evi dence"])
def test_invalid_reasons_are_rejected(reason: str) -> None:
    with pytest.raises(ValueError):
        Snapshot(T, reason)


@pytest.mark.parametrize("reason", list(Reason))
def test_parse_round_trips_every_reason(reason: Reason) -> None:
    snapshot = Snapshot(T, reason)
    assert Snapshot.parse(snapshot.id) == snapshot


def test_parse_accepts_unknown_but_well_formed_reason() -> None:
    parsed = Snapshot.parse("20261005T201530.123456Z-evidence")
    assert parsed is not None
    assert parsed.reason == "evidence"


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../workspace",
        "x/../y",
        VALID_ID + "/",
        VALID_ID + "\n",
        "20261005T201530Z-periodic",  # no microseconds
        "20261305T201530.123456Z-periodic",  # month 13
        "20260230T201530.123456Z-periodic",  # Feb 30
        "20261005T241530.123456Z-periodic",  # hour 24
        "２０２６1005T201530.123456Z-periodic",  # fullwidth digits
        "-" + VALID_ID,
        ".incoming-" + VALID_ID,
        ".trash-" + VALID_ID,
        "workspace.restore",
        "20261005T201530.123456Z-Periodic",
    ],
)
def test_parse_rejects_without_raising(name: str) -> None:
    assert Snapshot.parse(name) is None


def test_string_order_is_chronological_order() -> None:
    rng = random.Random(42)  # noqa: S311 - deterministic test data
    start = datetime(2020, 1, 1, tzinfo=UTC)
    snapshots = [
        Snapshot(start + timedelta(microseconds=rng.randrange(10**15)), Reason.PERIODIC)
        for _ in range(1000)
    ]
    by_id = sorted(snapshots, key=lambda s: s.id)
    by_time = sorted(snapshots, key=lambda s: s.taken_at)
    assert by_id == by_time


def test_longest_id_fits_telegram_callback_data() -> None:
    longest = Snapshot(T, "a" + "b" * 31)
    assert len(longest.id.encode()) <= 64


def test_exception_hierarchy() -> None:
    for error in (SnapshotBusy, SnapshotNoSpace, PruneIncomplete):
        assert issubclass(error, SnapshotError)
    assert not issubclass(RestoreIncomplete, SnapshotError)


def test_snapshot_error_carries_errno() -> None:
    assert SnapshotError("boom", errno=28).errno == 28
    assert SnapshotError("boom").errno is None
