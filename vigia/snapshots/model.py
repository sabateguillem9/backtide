"""Snapshot identity, reasons, restore results and errors. Pure: no I/O.

A snapshot's directory name IS its id: ``<UTC %Y%m%dT%H%M%S.%f>Z-<reason>``,
for example ``20261005T201530.123456Z-periodic``. Ids sort chronologically as
plain strings, never contain ``/``, ``..`` or non-ASCII characters, and are the
stable ``snapshot_id`` used by black-box events.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

_REASON_RE = re.compile(r"[a-z][a-z_]{0,31}", re.ASCII)
_ID_RE = re.compile(r"(\d{8}T\d{6}\.\d{6})Z-([a-z][a-z_]{0,31})", re.ASCII)
_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S.%f"


class Reason(StrEnum):
    """Why a snapshot was taken. Only PERIODIC snapshots are ever pruned automatically."""

    PERIODIC = "periodic"
    MANUAL = "manual"
    PRE_RESTORE = "pre_restore"
    RECOVERED = "recovered"


@dataclass(frozen=True)
class Snapshot:
    """A point in time of the workspace. ``reason`` is kept as a plain string so that
    snapshots written by a newer Vigía (with reasons this version doesn't know) still parse."""

    taken_at: datetime
    reason: str

    def __post_init__(self) -> None:
        if self.taken_at.utcoffset() != timedelta(0):
            raise ValueError(f"taken_at must be an aware UTC datetime, got {self.taken_at!r}")
        reason = str(self.reason)
        if not _REASON_RE.fullmatch(reason):
            raise ValueError(f"invalid snapshot reason: {reason!r}")
        object.__setattr__(self, "taken_at", self.taken_at.astimezone(UTC))
        object.__setattr__(self, "reason", reason)

    @property
    def id(self) -> str:
        return f"{self.taken_at:{_TIMESTAMP_FORMAT}}Z-{self.reason}"

    @classmethod
    def parse(cls, name: str) -> "Snapshot | None":
        """Return the snapshot named ``name``, or None if it is not a valid id.

        This is the single guard for ids that come from outside (CLI, web, Telegram).
        It never raises."""
        match = _ID_RE.fullmatch(name)
        if match is None:
            return None
        try:
            taken_at = datetime.strptime(match.group(1), _TIMESTAMP_FORMAT).replace(tzinfo=UTC)
            snapshot = cls(taken_at, match.group(2))
        except ValueError:
            return None
        return snapshot if snapshot.id == name else None


@dataclass(frozen=True)
class RestoreResult:
    target: Snapshot
    undo: Snapshot | None  # the pre_restore undo point; None only if there was no workspace
    recovered: tuple[Snapshot, ...] = ()  # leftovers published by the recovery that ran first


def utc_now() -> datetime:
    return datetime.now(UTC)


class SnapshotError(Exception):
    """A snapshot operation failed. Raised by restore() only when the workspace was NOT changed."""

    def __init__(self, message: str, *, errno: int | None = None) -> None:
        super().__init__(message)
        self.errno = errno


class SnapshotBusy(SnapshotError):
    """The volume lock was not acquired within the timeout."""


class SnapshotNoSpace(SnapshotError):
    """The volume is out of space (ENOSPC or EDQUOT)."""


class PruneIncomplete(SnapshotError):
    """Some expired snapshots could not be deleted. Raised after every one was attempted."""

    def __init__(self, deleted: list[Snapshot], failed: list[Snapshot]) -> None:
        super().__init__(f"prune deleted {len(deleted)} snapshots but failed on {len(failed)}")
        self.deleted = deleted
        self.failed = failed


class RestoreIncomplete(Exception):  # noqa: N818 - deliberately not a SnapshotError
    """The rewind DID take effect, but publishing the undo point failed.

    Deliberately not a SnapshotError: callers that catch SnapshotError as "nothing changed"
    must not treat a completed rewind as a failed one."""

    def __init__(self, target: Snapshot, leftover: Path) -> None:
        super().__init__(
            f"workspace WAS restored to {target.id}; previous state kept at {leftover}; "
            "the next recover() publishes it"
        )
        self.target = target
        self.leftover = leftover
