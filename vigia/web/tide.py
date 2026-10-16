"""The tide: the last 24 hours as one line, with a mark for every snapshot and the dot at the head
(now). Pure geometry; the page draws it as inline SVG.

The line is the brand's tide (a sine) and its height is the agent's activity: calm where nothing
happened, a swell where it was busy. So the drawing says something true at a glance ("it worked
around 15:00, then went quiet") instead of being decoration. The wave is anchored so that it
crosses the baseline exactly at the head: the dot always rests on the line at "now", which lets
the page keep the dot outside the part that is redrawn every minute.
"""

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from vigia.blackbox import Event
from vigia.snapshots import Snapshot

WINDOW = timedelta(hours=24)
WIDTH = 600.0
HEIGHT = 44.0
BASE = HEIGHT / 2  # the still line
PAD = 8.0
MAX_MARKS = 300
AMPLITUDE = 8.5  # the highest swell, in viewBox units (keeps the wave and marks inside)
WAVELENGTH = 40.0
BUCKETS = 144  # ten minutes each
BUSY = 40  # events in ten minutes that already make a full swell
STEP = 1.5  # distance between two points of the path
SWELL_SPAN = 60.0  # the stretch before the head that swells when something happens
FADE = 0.22  # the fade-in at the start of the line, as a fraction of its length
_KERNEL = (0.06, 0.12, 0.2, 0.24, 0.2, 0.12, 0.06)  # a gentle smoothing between buckets


@dataclass(frozen=True)
class Mark:
    x: float
    ts: str
    y: float = BASE
    at: str = ""  # when the snapshot was taken (ISO 8601, UTC): the snapshots page matches it


@dataclass(frozen=True)
class Tide:
    width: float
    left: float  # where the line starts
    right: float  # where the dot rests (now)
    marks: tuple[Mark, ...]
    total: int
    height: float = HEIGHT
    base: float = BASE
    path: str = ""  # the line from the start to where the swell begins
    swell: str = ""  # the last stretch, which the page swells when events arrive
    fade_to: float = PAD  # where the fade-in ends
    events: int = 0  # events read in the window
    more: bool = False  # there were more events than were read
    hours: int = 24  # how far back the line goes


def _taken_at(event: Event) -> datetime:
    """When the snapshot was taken (the point to go back to), else when it was recorded."""
    snapshot = Snapshot.parse(event.snapshot_id) if event.snapshot_id else None
    return snapshot.taken_at if snapshot is not None else datetime.fromisoformat(event.ts)


def activity_levels(
    moments: Iterable[datetime], now: datetime, window: timedelta = WINDOW
) -> list[float]:
    """How busy each stretch of the window (ten minutes of a day) was, from 0 (nothing) to 1
    (``BUSY`` events or more), smoothed so that the line swells and calms instead of jumping."""
    counts = [0] * BUCKETS
    busy = BUSY * (window / WINDOW)  # a longer window has longer stretches
    for moment in moments:
        fraction = 1 - (now - moment) / window
        if 0 <= fraction <= 1:
            counts[min(int(fraction * BUCKETS), BUCKETS - 1)] += 1
    top = math.log1p(max(busy, 2.0))
    raw = [min(math.log1p(c) / top, 1.0) for c in counts]
    half = len(_KERNEL) // 2
    smooth = []
    for i in range(BUCKETS):
        total = sum(
            weight * raw[i + j - half]
            for j, weight in enumerate(_KERNEL)
            if 0 <= i + j - half < BUCKETS
        )
        smooth.append(min(total * 2.5, 1.0))  # a single busy bucket still makes a visible swell
    return smooth


def _envelope(levels: list[float], fraction: float) -> float:
    """The activity at ``fraction`` of the window, between bucket centres."""
    if not levels:
        return 0.0
    position = fraction * len(levels) - 0.5
    i = math.floor(position)
    t = position - i
    a = levels[min(max(i, 0), len(levels) - 1)]
    b = levels[min(max(i + 1, 0), len(levels) - 1)]
    return a + (b - a) * t


def wave_y(x: float, levels: list[float], left: float, right: float) -> float:
    """The height of the line at ``x``: a sine whose size is the activity there, crossing the
    baseline at the head."""
    level = _envelope(levels, (x - left) / (right - left))
    return BASE - AMPLITUDE * level * math.sin(2 * math.pi * (right - x) / WAVELENGTH)


def _path(xs: list[float], ys: list[float]) -> str:
    """An SVG path through the points, leaving out the middle of every flat stretch."""
    keep: list[int] = []
    for i, y in enumerate(ys):
        flat = 0 < i < len(ys) - 1 and abs(y - BASE) < 0.05
        if flat and abs(ys[i - 1] - BASE) < 0.05 and abs(ys[i + 1] - BASE) < 0.05:
            continue
        keep.append(i)
    return "".join(f"{'L' if n else 'M'}{xs[i]:.1f},{ys[i]:.1f}" for n, i in enumerate(keep))


def build_tide(
    takes: list[Event],
    now: datetime,
    activity: Iterable[datetime] = (),
    *,
    more: bool = False,
    window: timedelta = WINDOW,
    snapshots: Sequence[Snapshot] | None = None,
) -> Tide:
    """``takes``: the ``snapshot/take`` events of the window, any order. ``activity``: when the
    events of the window happened (any order); ``more`` says the list was cut. ``window``: how
    far back the line goes (a day on "Ahora"; the snapshots page fits it to its list).
    ``snapshots``: the snapshots to mark instead of ``takes`` (the snapshots page marks the very
    list it shows, read from the volume)."""
    left, right = PAD, WIDTH - PAD
    span = right - left
    moments = list(activity)
    levels = activity_levels(moments, now, window)
    if more and moments:
        # The oldest events were not read: from the start of the window to the oldest one read,
        # say "busy" rather than pretend it was calm.
        cut = 1 - (now - min(moments)) / window
        for i in range(min(max(int(cut * BUCKETS), 0), BUCKETS)):
            levels[i] = 1.0

    # Split the line at a zero crossing before the head, so the swell joins it on the baseline.
    half = WAVELENGTH / 2
    split = right - half * max(round(SWELL_SPAN / half), 1)
    count = max(int(span / STEP), 2)
    xs = [left + span * i / count for i in range(count + 1)]
    xs = sorted({*xs, split})
    ys = [wave_y(x, levels, left, right) for x in xs]
    ys[-1] = BASE
    at = xs.index(split)
    ys[at] = BASE

    if snapshots is not None:
        points = [(snap.taken_at, snap.taken_at.isoformat()) for snap in snapshots]
        points.sort()
    else:
        points = [(_taken_at(event), event.ts) for event in takes]
    points = [p for p in points if now - p[0] <= window]  # the count says "in the window"
    marks: list[Mark] = []
    for moment, ts in points[-MAX_MARKS:]:
        fraction = 1 - (now - moment) / window
        if fraction >= 0:  # a clock a little behind the box's puts the mark at "now"
            x = round(left + span * min(fraction, 1), 1)
            y = round(wave_y(x, levels, left, right), 1)
            marks.append(Mark(x, ts, y, moment.astimezone(UTC).isoformat()))
    return Tide(
        WIDTH,
        left,
        right,
        tuple(marks),
        len(points),
        path=_path(xs[: at + 1], ys[: at + 1]),
        swell=_path(xs[at:], ys[at:]),
        fade_to=round(left + span * FADE, 1),
        events=len(moments),
        more=more,
        hours=max(round(window / timedelta(hours=1)), 1),
    )
