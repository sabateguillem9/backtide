"""Did the workspace change? Decided by Btrfs's own counters, never by inotify. Pure: no I/O.

Design: docs/19-diseno-t04.md, section 2. ``ctransid`` of a subvolume moves at once with any
change (create, write, chmod, mmap, delete) and not with a read; a snapshot copies the
``ctransid`` of its origin. So "the workspace changed" is "its ctransid differs from that of the
snapshot it was last copied into", and a file watcher that overflows, hits a limit or dies can
never make backtide skip a snapshot.

The reference to compare with follows the lineage (``parent_uuid``), never "the newest snapshot
of all": after a rewind the newest one is the pre_restore, which is the OLD workspace.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from backtide.snapshots.btrfs import SubvolumeInfo
from backtide.snapshots.model import Snapshot


@dataclass(frozen=True)
class SnapshotInfo:
    """A published snapshot and what its subvolume says about itself."""

    snapshot: Snapshot
    info: SubvolumeInfo


def lineage_reference(
    workspace: SubvolumeInfo, snapshots: Iterable[SnapshotInfo]
) -> SnapshotInfo | None:
    """The snapshot to compare the workspace with.

    The newest snapshot taken OF this workspace (``parent_uuid`` is the workspace's ``uuid``).
    If there is none (right after a rewind), the target the workspace was copied from (its
    ``uuid`` is the workspace's ``parent_uuid``). None if neither exists."""
    newest: SnapshotInfo | None = None
    target: SnapshotInfo | None = None
    for candidate in snapshots:
        if candidate.info.parent_uuid == workspace.uuid:
            if newest is None or _order(candidate) > _order(newest):
                newest = candidate
        elif workspace.parent_uuid is not None and candidate.info.uuid == workspace.parent_uuid:
            target = candidate
    return newest or target


def changed_since(workspace: SubvolumeInfo, reference: SubvolumeInfo | None) -> bool:
    """True if the workspace may have changed since ``reference`` (a ``lineage_reference``).

    Without a reference, or with one that is neither a snapshot of this workspace nor the
    snapshot it was copied from: changed (a false positive only costs one snapshot).
    Otherwise it changed when ``ctransid`` differs. If it matches, the backup signal is
    ``generation`` (it only moves when a transaction commits, so the caller runs a
    ``btrfs filesystem sync`` and reads the workspace again first): it must still be the
    transaction that created the reference, or, right after a rewind when the reference is the
    target, the one that created the workspace itself."""
    if reference is None:
        return True
    if reference.parent_uuid == workspace.uuid:  # a snapshot of this workspace
        created_at = reference.otransid
    elif workspace.parent_uuid is not None and reference.uuid == workspace.parent_uuid:
        created_at = workspace.otransid  # the target the workspace was copied from
    else:
        return True
    if workspace.ctransid != reference.ctransid:
        return True
    return workspace.generation != created_at


def _order(candidate: SnapshotInfo) -> tuple[datetime, str]:
    return candidate.snapshot.taken_at, candidate.snapshot.id
