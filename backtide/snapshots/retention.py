"""Retention: which snapshots to delete. Pure: no clock reads, no I/O.

Policy, by age (``now - taken_at``); every interval is half-open:

- younger than ``KEEP_ALL_FOR`` (2 h), or a negative age from clock skew: keep all;
- 2 h to ``HOURLY_FOR`` (24 h): keep the newest of each UTC hour;
- 24 h to ``DAILY_FOR`` (30 d): keep the newest of each UTC day;
- 30 d and older: keep the newest of each ISO week (Monday 00:00 UTC), forever.

Only reasons in ``PRUNABLE_REASONS`` (today just ``periodic``) are ever deleted. Every other
reason, known or unknown, stays until someone deletes it explicitly and is never a bucket's
representative. Keeping the newest of a bucket is right for rewinding: it is that period's end
state. Anchor rule: each protected snapshot also keeps the newest periodic snapshot taken before
it (ties by id), so "rewind to just before the problem" still works hours later.

Why the policy is stable:

(a) Buckets nest: a UTC hour lies inside one UTC day, which lies inside one ISO week, and a
    snapshot only moves to coarser tiers as it ages. The newest of a coarse bucket is the newest
    of every finer bucket holding it, so every earlier prune kept it too. A snapshot thinned now
    has a newer sibling in its bucket, and the bucket's newest is never thinned while the bucket
    decides, so every later prune would thin it again. Hence pruning a little at a time leaves
    exactly the survivors of one batch prune over the whole history.
(b) Each threshold is at least as long as the bucket it starts (2 h >= 1 hour, 24 h >= 1 day,
    30 d >= 7 days; a unit test pins this). A snapshot is thinned only once its whole bucket has
    ended, so a snapshot dated in the future can never share a bucket with one being thinned and
    can never make it lose its place.
(c) The newest periodic snapshot overall is the newest of every bucket it belongs to, so it is
    always kept, with no special case.
(d) Coverage: while a bucket is in its tier, its newest periodic snapshot is kept, so every hour
    of the last day, every day of the last month and every older week that had a periodic
    snapshot still has one.
(e) Anchors only ADD keeps. With a forward-moving clock, when a protected snapshot A is taken its
    predecessor P is the newest periodic snapshot overall, kept by (c) until then and anchored
    from then on; no later periodic snapshot can sort between them. So anchors are the same
    whether computed over the survivors or over the whole history, and (a) still holds. A clock
    that steps back can put a periodic snapshot between P and A and move the anchor; buckets and
    anchors follow timestamps, not real order (both pinned by tests).

Steady state with 2-minute periodic snapshots and continuous activity: about 60 + 22 + 29
snapshots, plus one per week older than 30 days, plus at most two per protected snapshot (itself
and its anchor). Days are UTC days: in Spanish summer time a "day" runs 02:00 to 02:00.
"""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from backtide.snapshots.model import Reason, Snapshot

KEEP_ALL_FOR: timedelta = timedelta(hours=2)
HOURLY_FOR: timedelta = timedelta(hours=24)
DAILY_FOR: timedelta = timedelta(days=30)  # older: one per ISO week, forever
# Allowlist: every other reason, known or unknown, is never auto-deleted and anchors its
# periodic predecessor.
PRUNABLE_REASONS: frozenset[str] = frozenset({Reason.PERIODIC})

type _Bucket = tuple[object, ...]


def select_expired(snapshots: Iterable[Snapshot], now: datetime) -> list[Snapshot]:
    """Return the snapshots retention deletes at ``now``, oldest first.

    ``now`` must be timezone-aware (ValueError otherwise); duplicates in the input are ignored.
    """
    now = _as_utc(now)
    ordered = sorted(set(snapshots), key=_order)
    candidates = [snap for snap in ordered if snap.reason in PRUNABLE_REASONS]
    newest_in = _newest_per_bucket(candidates)
    anchors = _anchors(ordered)
    return [snap for snap in candidates if not _is_kept(snap, now, newest_in, anchors)]


def _as_utc(now: datetime) -> datetime:
    if now.utcoffset() is None:
        raise ValueError(f"now must be a timezone-aware datetime, got {now!r}")
    return now.astimezone(UTC)


def _order(snapshot: Snapshot) -> tuple[datetime, str]:
    # The same order as (taken_at, id): equal timestamps share the id's prefix, so the reason
    # breaks the tie exactly as the id would, without formatting an id per snapshot.
    return snapshot.taken_at, snapshot.reason


def _hour(taken_at: datetime) -> _Bucket:
    return ("hour", taken_at.replace(minute=0, second=0, microsecond=0))


def _day(taken_at: datetime) -> _Bucket:
    return ("day", taken_at.date())


def _week(taken_at: datetime) -> _Bucket:
    iso = taken_at.isocalendar()  # never %W or the calendar year: 2027-01-01 is in 2026-W53
    return ("week", iso.year, iso.week)


def _newest_per_bucket(candidates: list[Snapshot]) -> dict[_Bucket, Snapshot]:
    """Map every hour, day and week bucket to its newest candidate (input in ascending order)."""
    newest_in: dict[_Bucket, Snapshot] = {}
    for snap in candidates:
        for bucket in (_hour(snap.taken_at), _day(snap.taken_at), _week(snap.taken_at)):
            newest_in[bucket] = snap
    return newest_in


def _anchors(ordered: list[Snapshot]) -> set[Snapshot]:
    """The newest candidate taken before each protected snapshot (input in ascending order)."""
    anchors: set[Snapshot] = set()
    last_candidate: Snapshot | None = None
    for snap in ordered:
        if snap.reason in PRUNABLE_REASONS:
            last_candidate = snap
        elif last_candidate is not None:
            anchors.add(last_candidate)
    return anchors


def _is_kept(
    snap: Snapshot,
    now: datetime,
    newest_in: dict[_Bucket, Snapshot],
    anchors: set[Snapshot],
) -> bool:
    age = now - snap.taken_at
    if age < KEEP_ALL_FOR or snap in anchors:
        return True
    return newest_in[_tier_bucket(snap.taken_at, age)] == snap


def _tier_bucket(taken_at: datetime, age: timedelta) -> _Bucket:
    if age < HOURLY_FOR:
        return _hour(taken_at)
    if age < DAILY_FOR:
        return _day(taken_at)
    return _week(taken_at)
