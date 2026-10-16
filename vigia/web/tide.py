"""The tide: a thin line over the last 24 hours with a mark for every snapshot and the dot at
the head (now). Pure geometry; the page draws it as inline SVG."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from vigia.blackbox import Event
from vigia.snapshots import Snapshot

WINDOW = timedelta(hours=24)
WIDTH = 600.0
PAD = 8.0
MAX_MARKS = 300


@dataclass(frozen=True)
class Mark:
    x: float
    ts: str


@dataclass(frozen=True)
class Tide:
    width: float
    left: float  # where the line starts
    right: float  # where the dot rests (now)
    marks: tuple[Mark, ...]
    total: int


def _taken_at(event: Event) -> datetime:
    """When the snapshot was taken (the point to go back to), else when it was recorded."""
    snapshot = Snapshot.parse(event.snapshot_id) if event.snapshot_id else None
    return snapshot.taken_at if snapshot is not None else datetime.fromisoformat(event.ts)


def build_tide(takes: list[Event], now: datetime) -> Tide:
    """``takes``: the ``snapshot/take`` events of the window, any order."""
    left, right = PAD, WIDTH - PAD
    span = right - left
    marks: list[Mark] = []
    for event in takes[-MAX_MARKS:]:
        moment = _taken_at(event)
        fraction = 1 - (now - moment) / WINDOW
        if fraction >= 0:  # a clock a little behind the box's puts the mark at "now"
            marks.append(Mark(round(left + span * min(fraction, 1), 1), event.ts))
    return Tide(WIDTH, left, right, tuple(marks), len(takes))
