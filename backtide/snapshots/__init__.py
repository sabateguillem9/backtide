"""Btrfs snapshots of the agent's workspace: take, list, rewind and prune.

Design and rationale: docs/10-diseno-t01-instantaneas.md.
"""

from backtide.snapshots.model import (
    PruneIncomplete,
    Reason,
    RestoreIncomplete,
    RestoreResult,
    Snapshot,
    SnapshotBusy,
    SnapshotError,
    SnapshotNoSpace,
    utc_now,
)
from backtide.snapshots.retention import select_expired
from backtide.snapshots.store import SnapshotStore

__all__ = [
    "PruneIncomplete",
    "Reason",
    "RestoreIncomplete",
    "RestoreResult",
    "Snapshot",
    "SnapshotBusy",
    "SnapshotError",
    "SnapshotNoSpace",
    "SnapshotStore",
    "select_expired",
    "utc_now",
]
