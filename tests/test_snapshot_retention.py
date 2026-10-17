"""Retention policy: unit cases plus the 60-day simulation (the T01a DONE test)."""

import random
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from itertools import pairwise

import pytest

from backtide.snapshots.model import Reason, Snapshot
from backtide.snapshots.retention import (
    DAILY_FOR,
    HOURLY_FOR,
    KEEP_ALL_FOR,
    PRUNABLE_REASONS,
    select_expired,
)

PERIODIC = Reason.PERIODIC
NOW = datetime(2026, 10, 5, 20, 0, tzinfo=UTC)  # a Monday
D = datetime(2026, 10, 5, tzinfo=UTC)  # day D of the anchor examples, 00:00 UTC
US = timedelta(microseconds=1)
PROTECTED_REASONS = [
    Reason.MANUAL,
    Reason.PRE_RESTORE,
    Reason.RECOVERED,
    "evidence",
    "future_reason",
]


def snap(age: timedelta, reason: str = PERIODIC) -> Snapshot:
    """A snapshot ``age`` before NOW."""
    return Snapshot(NOW - age, reason)


def at(text: str, reason: str = PERIODIC) -> Snapshot:
    """A snapshot at an ISO time written without zone, read as UTC."""
    return Snapshot(datetime.fromisoformat(text).replace(tzinfo=UTC), reason)


def on_d(hhmm: str, reason: str = PERIODIC) -> Snapshot:
    """A snapshot at HH:MM[:SS] UTC on day D."""
    clock = datetime.strptime(hhmm, "%H:%M:%S" if hhmm.count(":") == 2 else "%H:%M")
    return Snapshot(
        D + timedelta(hours=clock.hour, minutes=clock.minute, seconds=clock.second), reason
    )


def every(start: datetime, end: datetime, step: timedelta) -> list[Snapshot]:
    """Periodic snapshots from ``start`` to ``end`` inclusive."""
    result = []
    while start <= end:
        result.append(Snapshot(start, PERIODIC))
        start += step
    return result


def kept(snapshots: Iterable[Snapshot], now: datetime) -> list[Snapshot]:
    """The survivors of a prune at ``now``, oldest first."""
    everything = list(snapshots)
    expired = set(select_expired(everything, now))
    return sorted((s for s in everything if s not in expired), key=lambda s: s.id)


# --- Basics ---------------------------------------------------------------------------------


def test_empty_input_expires_nothing() -> None:
    assert select_expired([], NOW) == []


def test_only_protected_snapshots_expire_nothing() -> None:
    ages = [timedelta(minutes=1), timedelta(hours=5), timedelta(days=3), timedelta(days=400)]
    snapshots = [snap(age, reason) for age in ages for reason in PROTECTED_REASONS]
    assert select_expired(snapshots, NOW) == []


def test_naive_now_raises() -> None:
    with pytest.raises(ValueError):
        select_expired([snap(timedelta(hours=3))], NOW.replace(tzinfo=None))


def test_aware_non_utc_now_is_normalised() -> None:
    snapshots = every(NOW - timedelta(days=40), NOW, timedelta(hours=5))
    cest = NOW.astimezone(timezone(timedelta(hours=2)))
    assert select_expired(snapshots, cest) == select_expired(snapshots, NOW)
    assert select_expired(snapshots, NOW) != []


def test_constants_are_the_agreed_policy() -> None:
    assert (KEEP_ALL_FOR, HOURLY_FOR, DAILY_FOR) == (
        timedelta(hours=2),
        timedelta(hours=24),
        timedelta(days=30),
    )
    assert PRUNABLE_REASONS == {"periodic"}


def test_each_threshold_is_at_least_as_long_as_its_bucket() -> None:
    # Property (b): a snapshot is thinned only after its whole bucket (hour, day, ISO week) has
    # ended, so a snapshot dated in the future can never share a bucket with one being thinned.
    # Lowering a threshold below its bucket length would break that, and with it stability.
    assert KEEP_ALL_FOR >= timedelta(hours=1)
    assert HOURLY_FOR >= timedelta(days=1)
    assert DAILY_FOR >= timedelta(weeks=1)
    assert KEEP_ALL_FOR < HOURLY_FOR < DAILY_FOR


# --- Tiers ----------------------------------------------------------------------------------


def test_keeps_everything_younger_than_two_hours() -> None:
    snapshots = [snap(timedelta(minutes=2 * i)) for i in range(60)]
    assert select_expired(snapshots, NOW) == []


def test_hourly_tier_keeps_newest_per_utc_hour() -> None:
    expired = ["12:10", "12:30", "13:05", "17:00"]
    survivors = ["12:50", "13:55", "17:59:59.999999"]
    snapshots = [at(f"2026-10-05T{t}") for t in expired + survivors]
    assert select_expired(snapshots, NOW) == [at(f"2026-10-05T{t}") for t in expired]


def test_daily_tier_keeps_newest_per_utc_day() -> None:
    now = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    expired = [at("2026-10-10T01:00"), at("2026-10-10T13:00"), at("2026-10-11T00:00")]
    survivors = [at("2026-10-10T23:59:59.999999"), at("2026-10-11T06:00")]
    assert kept(expired + survivors, now) == survivors


def test_weekly_tier_keeps_newest_per_iso_week_across_new_year() -> None:
    # 2026-12-28 (Monday) to 2027-01-03 (Sunday) is ISO week 2026-W53.
    assert datetime(2026, 12, 28).isocalendar()[:2] == (2026, 53)
    assert datetime(2027, 1, 3).isocalendar()[:2] == (2026, 53)
    now = datetime(2027, 3, 1, 12, 0, tzinfo=UTC)
    w53 = [at("2026-12-28T10:00"), at("2026-12-31T10:00"), at("2027-01-01T10:00")]
    w53_newest = at("2027-01-03T23:59:59.999999")
    w01 = [at("2027-01-04T00:00"), at("2027-01-06T10:00")]
    assert kept([*w53, w53_newest, *w01], now) == [w53_newest, w01[-1]]


def test_same_iso_week_number_in_different_years_are_separate_buckets() -> None:
    # Weeks are kept forever, so the key must include the ISO year: week 41 of 2025 must not
    # thin week 41 of 2024.
    w41_2024, w41_2025 = at("2024-10-07T10:00"), at("2025-10-06T10:00")
    assert w41_2024.taken_at.isocalendar()[:2] == (2024, 41)
    assert w41_2025.taken_at.isocalendar()[:2] == (2025, 41)
    assert select_expired([w41_2024, w41_2025], NOW) == []


def test_bucket_straddling_the_keep_all_edge_thins_its_older_members() -> None:
    hour = every(on_d("08:00").taken_at, on_d("08:58").taken_at, timedelta(minutes=2))
    now = D + timedelta(hours=10, minutes=31)
    # 08:30 is 2 h 01 min old: hourly tier, and 08:58 (still in keep-all) is its hour's newest.
    assert select_expired(hour, now) == [s for s in hour if s.taken_at <= on_d("08:30").taken_at]


C = datetime(2026, 10, 5, 8, 0, tzinfo=UTC)  # a Monday: the start of an hour, a day and a week


@pytest.mark.parametrize(
    ("threshold", "sibling_at"),
    [
        # sibling: newer, in the bucket C moves into at the threshold, but not in C's finer one
        (KEEP_ALL_FOR, C + timedelta(minutes=30)),  # same hour
        (HOURLY_FOR, C + timedelta(hours=1, minutes=30)),  # same day, next hour
        (DAILY_FOR, C + timedelta(days=1)),  # same ISO week, next day
    ],
)
@pytest.mark.parametrize("delta", [-US, timedelta(0), US])
def test_tier_boundaries_are_half_open(
    threshold: timedelta, sibling_at: datetime, delta: timedelta
) -> None:
    c = Snapshot(C, PERIODIC)
    sibling = Snapshot(sibling_at, PERIODIC)
    expired = select_expired([c, sibling], C + threshold + delta)
    assert expired == ([c] if delta >= timedelta(0) else [])


def test_newest_periodic_is_kept_at_90_days() -> None:
    snapshots = every(
        datetime(2026, 7, 1, tzinfo=UTC),
        datetime(2026, 7, 3, 23, 0, tzinfo=UTC),
        timedelta(hours=1),
    )
    newest = snapshots[-1]
    assert kept(snapshots, newest.taken_at + timedelta(days=90)) == [newest]


def test_regression_incremental_equals_batch_for_two_snapshots() -> None:
    # An earlier critic's counterexample: periodic S at 08:20 and T at 08:40, nothing else.
    s, t = on_d("08:20"), on_d("08:40")
    assert select_expired([s, t], D + timedelta(hours=10, minutes=50)) == [s]
    later = D + timedelta(days=1, hours=8, minutes=30)
    assert select_expired([s, t], later) == [s]  # batch
    assert select_expired([t], later) == []  # incremental: same survivors


def test_duplicates_in_the_input_are_ignored() -> None:
    s, t = on_d("08:20"), on_d("08:40")
    assert select_expired([s, t, s, t], D + timedelta(days=1)) == [s]


# --- Anchors and protected snapshots --------------------------------------------------------


@pytest.mark.parametrize(
    "now",
    [D + timedelta(hours=12), D + timedelta(days=3), D + timedelta(days=60)],
    ids=["hourly", "daily", "weekly"],
)
def test_anchor_keeps_the_snapshot_just_before_a_protected_one(now: datetime) -> None:
    periodic = every(on_d("08:00").taken_at, on_d("08:58").taken_at, timedelta(minutes=2))
    evidence = on_d("08:15:30", "evidence")
    assert kept([*periodic, evidence], now) == [on_d("08:14"), evidence, on_d("08:58")]
    # Without the anchor rule, 08:14 would be gone as soon as it is 2 h old.
    assert kept(periodic, now) == [on_d("08:58")]


@pytest.mark.parametrize("reason", PROTECTED_REASONS)
def test_every_non_prunable_reason_anchors(reason: str) -> None:
    periodic = [on_d("08:00"), on_d("08:20"), on_d("08:40")]
    protected = on_d("08:25", reason)
    now = D + timedelta(days=3)
    assert select_expired([*periodic, protected], now) == [on_d("08:00")]


def test_protected_without_earlier_periodic_anchors_nothing() -> None:
    periodic = [on_d("08:00"), on_d("08:20"), on_d("08:40")]
    now = D + timedelta(days=3)
    with_protected = select_expired([on_d("07:59", Reason.MANUAL), *periodic], now)
    assert with_protected == select_expired(periodic, now) == periodic[:2]


@pytest.mark.parametrize(
    ("reason", "anchor"),
    [
        (Reason.MANUAL, "08:00"),  # '...Z-manual' sorts before '...Z-periodic': 08:20 is after it
        (Reason.RECOVERED, "08:20"),  # '...Z-recovered' sorts after: 08:20 is its predecessor
    ],
)
def test_anchor_ties_on_taken_at_are_broken_by_id(reason: str, anchor: str) -> None:
    periodic = [on_d("08:00"), on_d("08:20"), on_d("08:40")]
    protected = on_d("08:20", reason)
    survivors = kept([*periodic, protected], D + timedelta(days=3))
    assert survivors == sorted([on_d(anchor), protected, on_d("08:40")], key=lambda s: s.id)


def test_consecutive_protected_snapshots_share_their_anchor() -> None:
    periodic = [on_d("08:00"), on_d("08:20"), on_d("08:40")]
    protected = [on_d("08:21", Reason.MANUAL), on_d("08:22", "evidence")]
    assert select_expired([*periodic, *protected], D + timedelta(days=3)) == [on_d("08:00")]


@pytest.mark.parametrize("reason", PROTECTED_REASONS)
@pytest.mark.parametrize(
    "age",
    [timedelta(minutes=1), timedelta(hours=3), timedelta(days=2), timedelta(days=45)]
    + [timedelta(days=3 * 365)],
)
def test_protected_reasons_never_expire_at_any_age(reason: str, age: timedelta) -> None:
    protected = snap(age, reason)
    around = [snap(age + timedelta(minutes=m)) for m in (-30, -1, 1, 30)]
    expired = select_expired([protected, *around], NOW)
    assert protected not in expired
    assert all(s.reason == PERIODIC for s in expired)


def test_protected_snapshot_does_not_thin_the_periodic_ones_in_its_bucket() -> None:
    # The manual snapshot is the newest of hour 08, but periodic snapshots are judged among
    # themselves: 08:30 stays as the newest periodic of the hour. (It is also the manual's
    # anchor, so with the anchor rule this outcome would be the same even if protected
    # snapshots were bucket representatives; the module keeps them out of the buckets anyway.)
    periodic = [on_d("08:10"), on_d("08:20"), on_d("08:30")]
    manual = on_d("08:40", Reason.MANUAL)
    assert select_expired([*periodic, manual], D + timedelta(hours=12)) == periodic[:2]


# --- Clock trouble --------------------------------------------------------------------------


def _past_history() -> list[Snapshot]:
    """Snapshots before NOW in every tier, several in NOW's own day and ISO week."""
    return [
        *every(NOW - timedelta(days=50), NOW - timedelta(days=2), timedelta(hours=7)),
        *every(NOW - timedelta(hours=20), NOW - timedelta(minutes=10), timedelta(minutes=10)),
        snap(timedelta(hours=5), Reason.MANUAL),
    ]


@pytest.mark.parametrize("reason", [PERIODIC, "evidence"])
@pytest.mark.parametrize("ahead", [timedelta(minutes=1), timedelta(hours=3), timedelta(days=3)])
def test_future_dated_snapshots_cause_no_extra_deletions(ahead: timedelta, reason: str) -> None:
    history = _past_history()
    future = Snapshot(NOW + ahead, reason)
    expired = select_expired(history, NOW)
    assert expired != []
    assert select_expired([*history, future], NOW) == expired


def test_future_dated_snapshots_sharing_buckets_are_all_kept() -> None:
    # A negative age (clock skew) means keep-all, even for future snapshots that share an hour,
    # day or week: a clock that stepped back must not thin the most recent real states. A lone
    # future snapshot is always its bucket's newest, so only siblings can catch a regression.
    future = [
        *every(
            NOW + timedelta(hours=3), NOW + timedelta(hours=3, minutes=50), timedelta(minutes=10)
        ),
        *every(NOW + timedelta(days=3), NOW + timedelta(days=3, hours=5), timedelta(hours=1)),
    ]
    assert select_expired(future, NOW) == []
    history = _past_history()
    assert select_expired([*history, *future], NOW) == select_expired(history, NOW)


def _stepped_back_history() -> tuple[list[Snapshot], list[Snapshot]]:
    """Snapshots every 2 min from 09:00 to 10:28 on day D; at real 10:30 the clock steps back
    1 h, so the agent's work until real 10:50 is stamped 09:30-09:50 (plus a second, to keep
    the ids apart). Returns (before the step, after the step)."""
    before_step = every(on_d("09:00").taken_at, on_d("10:28").taken_at, timedelta(minutes=2))
    after_step = every(on_d("09:30:01").taken_at, on_d("09:50:01").taken_at, timedelta(minutes=2))
    return before_step, after_step


def test_clock_step_back_follows_timestamps_not_real_order() -> None:
    # Pinned, documented behaviour. Hour 09's newest by timestamp is 09:58, so the real final
    # state (stamped 09:50:01) is thinned once it is 2 h old.
    before_step, after_step = _stepped_back_history()
    real_final_state = after_step[-1]
    now = D + timedelta(hours=12, minutes=30)
    survivors = kept([*before_step, *after_step], now)
    assert survivors == [on_d("09:58"), on_d("10:28")]
    assert real_final_state not in survivors


def test_clock_step_back_can_move_an_anchor() -> None:
    # Pinned, documented behaviour (property (e)). A manual snapshot taken at real 09:45, before
    # the step, has the clean 09:44 as its real predecessor. After the step, the agent's
    # 09:44:01 sorts between them by timestamp and becomes the anchor, so 09:44 is thinned.
    before_step, after_step = _stepped_back_history()
    manual = on_d("09:45", Reason.MANUAL)
    survivors = kept([*before_step, manual, *after_step], D + timedelta(hours=12, minutes=30))
    assert survivors == [on_d("09:44:01"), manual, on_d("09:58"), on_d("10:28")]
    assert on_d("09:44") not in survivors


def test_two_sessions_on_the_same_utc_day() -> None:
    # Pinned, documented behaviour: once the day is older than 24 h it keeps only its newest
    # snapshot, so the end of the morning session is gone; within 24 h both ends survive.
    morning = every(on_d("08:00").taken_at, on_d("08:58").taken_at, timedelta(minutes=2))
    afternoon = every(on_d("15:00").taken_at, on_d("15:58").taken_at, timedelta(minutes=2))
    assert kept([*morning, *afternoon], D + timedelta(hours=20)) == [morning[-1], afternoon[-1]]
    assert kept([*morning, *afternoon], D + timedelta(days=2)) == [afternoon[-1]]


# --- Determinism ----------------------------------------------------------------------------


def _mixed_history() -> list[Snapshot]:
    return [
        *every(NOW - timedelta(days=70), NOW, timedelta(minutes=37)),
        snap(timedelta(days=40, minutes=3), Reason.PRE_RESTORE),
        snap(timedelta(days=3, minutes=5), "evidence"),
        snap(timedelta(hours=6, minutes=1), Reason.MANUAL),
    ]


def test_select_expired_is_idempotent() -> None:
    history = _mixed_history()
    expired = set(select_expired(history, NOW))
    assert len(expired) > 100
    survivors = [s for s in history if s not in expired]
    assert select_expired(survivors, NOW) == []


def test_input_order_does_not_matter() -> None:
    history = _mixed_history()
    shuffled = history[:]
    random.Random(7).shuffle(shuffled)  # noqa: S311 - deterministic test data
    assert select_expired(iter(shuffled), NOW) == select_expired(history, NOW)


def test_output_is_oldest_first() -> None:
    history = _mixed_history()
    expired = select_expired(reversed(history), NOW)
    assert expired == sorted(expired, key=lambda s: s.id)


# --- Window helpers for the simulation ------------------------------------------------------


@dataclass(frozen=True)
class Window:
    """The ages of one tier: [min_age, max_age); ``max_age=None`` means forever."""

    min_age: timedelta
    max_age: timedelta | None

    def contains_age(self, age: timedelta) -> bool:
        return age >= self.min_age and (self.max_age is None or age < self.max_age)

    def contains_bucket(self, start: datetime, end: datetime, now: datetime) -> bool:
        """True if EVERY instant of [start, end), at datetime's 1 µs resolution, is in the tier."""
        return self.contains_age(now - (end - US)) and self.contains_age(now - start)


TIERS = {
    "hour": Window(KEEP_ALL_FOR, HOURLY_FOR),
    "day": Window(HOURLY_FOR, DAILY_FOR),
    "week": Window(DAILY_FOR, None),
}


def bucket_bounds(tier: str, t: datetime) -> tuple[datetime, datetime]:
    """[start, end) of the UTC hour, UTC day or ISO week (Monday 00:00 UTC) holding ``t``."""
    if tier == "hour":
        start = t.replace(minute=0, second=0, microsecond=0)
        return start, start + timedelta(hours=1)
    day = t.replace(hour=0, minute=0, second=0, microsecond=0)
    if tier == "day":
        return day, day + timedelta(days=1)
    start = day - timedelta(days=t.weekday())
    return start, start + timedelta(weeks=1)


def test_window_ages_are_half_open() -> None:
    hourly, weekly = TIERS["hour"], TIERS["week"]
    assert not hourly.contains_age(KEEP_ALL_FOR - US)
    assert hourly.contains_age(KEEP_ALL_FOR)
    assert hourly.contains_age(HOURLY_FOR - US)
    assert not hourly.contains_age(HOURLY_FOR)
    assert not weekly.contains_age(DAILY_FOR - US)
    assert weekly.contains_age(DAILY_FOR)
    assert weekly.contains_age(timedelta(days=10_000))


def test_window_contains_bucket_only_when_fully_inside() -> None:
    hourly = TIERS["hour"]
    start, end = D + timedelta(hours=10), D + timedelta(hours=11)
    # Its last instant (10:59:59.999999) must be at least 2 h old...
    assert not hourly.contains_bucket(start, end, D + timedelta(hours=13) - 2 * US)
    assert hourly.contains_bucket(start, end, D + timedelta(hours=13) - US)
    # ...and its first instant (10:00) younger than 24 h.
    assert hourly.contains_bucket(start, end, D + timedelta(days=1, hours=10) - US)
    assert not hourly.contains_bucket(start, end, D + timedelta(days=1, hours=10))
    weekly = TIERS["week"]
    week_start, week_end = bucket_bounds("week", D)
    assert not weekly.contains_bucket(week_start, week_end, week_end - US + DAILY_FOR - US)
    assert weekly.contains_bucket(week_start, week_end, week_end - US + DAILY_FOR)


def test_bucket_bounds() -> None:
    t = datetime(2027, 1, 1, 10, 20, 30, 5, tzinfo=UTC)
    assert bucket_bounds("hour", t) == (
        datetime(2027, 1, 1, 10, tzinfo=UTC),
        datetime(2027, 1, 1, 11, tzinfo=UTC),
    )
    assert bucket_bounds("day", t) == (
        datetime(2027, 1, 1, tzinfo=UTC),
        datetime(2027, 1, 2, tzinfo=UTC),
    )
    assert bucket_bounds("week", t) == (  # ISO week 2026-W53
        datetime(2026, 12, 28, tzinfo=UTC),
        datetime(2027, 1, 4, tzinfo=UTC),
    )
    assert bucket_bounds("week", datetime(2027, 1, 4, tzinfo=UTC))[0] == datetime(
        2027, 1, 4, tzinfo=UTC
    )


# --- The 60-day simulation (DONE criterion) -------------------------------------------------

SIM_START = datetime(2026, 8, 3, tzinfo=UTC)  # a Monday
SIM_END = SIM_START + timedelta(days=60)
TICK = timedelta(minutes=2)
PRUNE_EVERY = timedelta(minutes=30)
SIM_PROTECTED = (Reason.MANUAL, Reason.PRE_RESTORE, "evidence")
# A last long session, so that at the end every tier has buckets fully inside it.
FINAL_SESSION = (SIM_END - timedelta(hours=28), SIM_END - timedelta(minutes=5))


def _simulated_history(rng: random.Random) -> list[Snapshot]:
    """Random active sessions separated by idle gaps from 5 min to 2 days, then FINAL_SESSION."""
    history: list[Snapshot] = []
    t = SIM_START
    while True:
        short_gap = rng.random() < 0.5
        t += timedelta(minutes=rng.randint(5, 120) if short_gap else rng.randint(120, 2 * 24 * 60))
        session_end = t + timedelta(minutes=rng.randint(10, 8 * 60))
        if session_end > FINAL_SESSION[0]:
            return history + _session(rng, *FINAL_SESSION)
        history += _session(rng, t, session_end)
        t = session_end


def _session(rng: random.Random, start: datetime, end: datetime) -> list[Snapshot]:
    """A periodic snapshot every 2 min (plus jitter), and now and then a protected one."""
    snapshots: list[Snapshot] = []
    t = start
    while t < end:
        snapshots.append(Snapshot(t, PERIODIC))
        if rng.random() < 0.01:
            protected_at = t + timedelta(seconds=rng.randint(1, 119))
            snapshots.append(Snapshot(protected_at, rng.choice(SIM_PROTECTED)))
        t += TICK + timedelta(microseconds=rng.randrange(1_000_000))
    return snapshots


def _anchors_of(ordered: list[Snapshot]) -> set[Snapshot]:
    """Periodic snapshots immediately followed (in id order) by a protected one: exactly the
    periodic predecessors of the protected snapshots. Independent of the implementation."""
    return {a for a, b in pairwise(ordered) if a.reason == PERIODIC and b.reason != PERIODIC}


def _check_prune_step(existing: list[Snapshot], expired: list[Snapshot], max_periodic: int) -> None:
    """Invariant 2: a prune never expires a protected snapshot, the newest periodic one, or the
    periodic predecessor of a protected one. Invariant 4 at every step: the count is bounded."""
    assert all(s.reason == PERIODIC for s in expired)
    gone = set(expired)
    periodic = [s for s in existing if s.reason == PERIODIC]
    if periodic:
        assert periodic[-1] not in gone
    assert gone.isdisjoint(_anchors_of(existing))
    assert len(periodic) - len(gone) <= max_periodic


def _check_windows(history: list[Snapshot], survivors: set[Snapshot], now: datetime) -> None:
    """Invariant 3: every bucket FULLY inside its tier keeps its newest periodic snapshot, and
    every other survivor in it is an anchor. A bucket straddling a tier edge is checked only
    when its newest member is inside the tier: then that member survives."""
    periodic = [s for s in history if s.reason == PERIODIC]
    anchors = _anchors_of(history)
    assert all(s in survivors for s in periodic if now - s.taken_at < KEEP_ALL_FOR)
    for tier, window in TIERS.items():
        buckets: dict[tuple[datetime, datetime], list[Snapshot]] = {}
        for s in periodic:
            buckets.setdefault(bucket_bounds(tier, s.taken_at), []).append(s)
        fully_inside = 0
        for (start, end), members in buckets.items():
            if window.contains_age(now - members[-1].taken_at):
                assert members[-1] in survivors
            if window.contains_bucket(start, end, now):
                fully_inside += 1
                assert all(s in anchors for s in members[:-1] if s in survivors)
        assert fully_inside > 0, f"no {tier} bucket fully inside its tier: the check is vacuous"


def test_sixty_day_simulation() -> None:
    rng = random.Random(20261006)  # noqa: S311 - deterministic test data
    history = sorted(_simulated_history(rng), key=lambda s: s.id)
    weeks = len({s.taken_at.isocalendar()[:2] for s in history})
    protected = sum(s.reason != PERIODIC for s in history)
    # 60 in keep-all, at most 23 hours and 31 days touching their tiers, one per week, one
    # anchor per protected snapshot, and a little slack.
    max_periodic = 60 + 23 + 31 + weeks + protected + 2
    assert len(history) > 5_000
    assert protected > 10

    survivors: list[Snapshot] = []
    next_index = 0
    now = SIM_START
    while now <= SIM_END:
        while next_index < len(history) and history[next_index].taken_at <= now:
            survivors.append(history[next_index])
            next_index += 1
        expired = select_expired(survivors, now)
        _check_prune_step(survivors, expired, max_periodic)
        gone = set(expired)
        survivors = [s for s in survivors if s not in gone]
        now += PRUNE_EVERY
    final_now = now - PRUNE_EVERY
    assert next_index == len(history)

    # Invariant 1: pruning every 30 min leaves exactly what one batch prune would.
    batch = set(history) - set(select_expired(history, final_now))
    assert set(survivors) == batch
    assert _anchors_of(history) <= batch
    _check_windows(history, set(survivors), final_now)
