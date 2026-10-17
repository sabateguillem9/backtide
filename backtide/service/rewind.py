"""What a rewind leaves outside the Guardian: its intent on disk and its outcome.

Design: docs/19-diseno-t04.md, section 4. ``Guardian.rewind`` is the single entry point; this
module only holds the pieces it shares with the startup reconciliation and the CLI (T04c-2).

- ``rewind.pending`` (``ServiceConfig.pending_file``, in backtide's 0700 state folder, never in the
  volume) is written and fsynced BEFORE the rewind changes anything: request id, target and the
  workspace id it starts from. If the process dies half way, a fresh Guardian compares
  ``workspace_id()`` with ``from_workspace_id`` and records what really happened. It is written
  atomically (a temporary file, fsync, rename, fsync of the folder) and read without following
  symlinks; an unreadable one is an error, never a guess.
- ``RewindOutcome`` is what the caller gets back: a status, the undo point and a message for the
  person. ``exit_code`` follows the CLI's codes (docs/19, "La CLI").
"""

import json
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from backtide.snapshots import RestoreIncomplete, Snapshot, SnapshotNoSpace

MAX_PENDING_BYTES = 4096
_TMP_SUFFIX = ".tmp"
_KEYS = ("request_id", "target", "from_workspace_id", "requested_by")


class PendingError(Exception):
    """``rewind.pending`` exists but cannot be read or does not say what it should."""


@dataclass(frozen=True)
class PendingRewind:
    """The intent of a rewind in progress."""

    request_id: str
    target: str  # a snapshot id
    from_workspace_id: int  # the workspace's subvolume id before the rewind
    requested_by: str


class RewindStatus(StrEnum):
    DONE = "done"  # rewound, and everything after it went well
    PROBLEM = "problem"  # rewound, but something failed (undo point, agent, black box)
    FAILED = "failed"  # not rewound: the workspace is unchanged
    INVALID = "invalid"  # the id is not a snapshot id: nothing was done, nothing recorded
    UNKNOWN = "unknown"  # the workspace id cannot be read: the next start reconciles it


EXIT_CODES = {
    RewindStatus.DONE: 0,
    RewindStatus.FAILED: 1,
    RewindStatus.INVALID: 2,
    RewindStatus.PROBLEM: 3,
    RewindStatus.UNKNOWN: 3,
}


@dataclass(frozen=True)
class RewindOutcome:
    """What ``Guardian.rewind`` did. ``message`` is for the person, in Spanish, and carries
    nothing of the agent's; the details are in the black box (``rewind_done`` or
    ``rewind_failed``, by ``request_id``)."""

    status: RewindStatus
    target: str
    message: str
    request_id: str | None = None
    undo: str | None = None  # the undo point: rewind to it to undo this rewind
    agent_started: bool = False
    error: str | None = None

    @property
    def rewound(self) -> bool:
        return self.status in (RewindStatus.DONE, RewindStatus.PROBLEM)

    @property
    def exit_code(self) -> int:
        """0 rewound; 1 not done, workspace unchanged; 2 invalid id; 3 rewound with a problem
        (or cannot tell)."""
        return EXIT_CODES[self.status]


def is_space_error(error: BaseException | None) -> bool:
    """A rewind that failed for lack of space: ``SnapshotNoSpace``, or a ``RestoreIncomplete``
    (rewound, undo point not published) caused by it."""
    if isinstance(error, SnapshotNoSpace):
        return True
    return isinstance(error, RestoreIncomplete) and isinstance(error.__cause__, SnapshotNoSpace)


def write_pending(path: Path, intent: PendingRewind) -> None:
    """Write ``intent`` to ``path`` durably (0600, atomic, fsynced with its folder). Raises
    OSError. A stale temporary file (a crash in the middle of a write) is replaced, and a
    symlink in its place is removed, never followed."""
    path = Path(path)
    tmp = path.with_name(path.name + _TMP_SUFFIX)
    content = json.dumps({key: getattr(intent, key) for key in _KEYS}).encode() + b"\n"
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            os.unlink(tmp.name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(tmp.name, flags, 0o600, dir_fd=dir_fd)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp.name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def read_pending(path: Path) -> PendingRewind | None:
    """The intent at ``path``, or None if there is none. Raises PendingError if it exists but
    is not a regular file of at most 4 KiB holding exactly what ``write_pending`` writes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:  # ELOOP: a symlink
        raise PendingError(f"cannot open {path} (a symbolic link?): {error}") from error
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PendingError(f"{path} is not a regular file")
        raw = os.read(fd, MAX_PENDING_BYTES + 1)
    except OSError as error:
        raise PendingError(f"cannot read {path}: {error}") from error
    finally:
        os.close(fd)
    if len(raw) > MAX_PENDING_BYTES:
        raise PendingError(f"{path} is larger than {MAX_PENDING_BYTES} bytes")
    try:
        data: Any = json.loads(raw)
    except ValueError as error:
        raise PendingError(f"{path} is not JSON: {error}") from error
    if not isinstance(data, dict) or set(data) != set(_KEYS):
        raise PendingError(f"{path} does not hold the keys {list(_KEYS)}")
    request_id, target = data["request_id"], data["target"]
    workspace_id, requested_by = data["from_workspace_id"], data["requested_by"]
    if (
        not isinstance(request_id, str)
        or not request_id
        or not isinstance(target, str)
        or Snapshot.parse(target) is None
        or type(workspace_id) is not int
        or not isinstance(requested_by, str)
    ):
        raise PendingError(f"{path} holds values of the wrong kind")
    return PendingRewind(request_id, target, workspace_id, requested_by)


def remove_pending(path: Path) -> None:
    """Remove the intent (and its folder entry, durably). Nothing there is not an error."""
    path = Path(path)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


__all__ = [
    "EXIT_CODES",
    "PendingError",
    "PendingRewind",
    "RewindOutcome",
    "RewindStatus",
    "is_space_error",
    "read_pending",
    "remove_pending",
    "write_pending",
]
