"""SnapshotStore: snapshots and rewinds of the agent's workspace on one Btrfs volume.

Layout (docs/10-diseno-t01-instantaneas.md)::

    <root>/                 0700, owned by the effective uid (checked, never fixed)
      .lock                 0600: the flock every change holds
      workspace/            the writable subvolume, the only thing the agent sees
      workspace.restore     IN PROGRESS: the staging copy before the swap, or the old
                            workspace right after it
      snapshots/            0700 plain directory
        <id>                read-only snapshots: the only entries ever listed
        .incoming-<id>      IN PROGRESS: an old workspace being published
        .trash-<id>         IN PROGRESS: a snapshot being deleted

- Every change (init, take, restore, delete, prune, recover) holds one exclusive flock on
  ``<root>/.lock``, and btrfs children inherit it. So a leftover seen under the lock always
  belongs to a dead process. ``snapshots()`` and ``workspace_id()`` take no lock: names appear
  and disappear atomically, and in-progress names never parse as ids.
- Data moves only through btrfs snapshots and ``renameat2`` relative to a ``<root>`` fd, with
  NOREPLACE (never overwrites) or EXCHANGE (the atomic swap). Nothing is copied by hand.
- There is no journal: the names on disk are the state. recover() only keeps data or finishes
  deletes that had already started.
- Snapshots are crash-consistent, not application-consistent.
- Space cap (T03b, docs/16): on a volume formatted with simple quotas, the workspace can carry
  a qgroup limit. A limit belongs to the subvolume, not the path, so the store moves it by
  hand: restore() caps the staging copy before quiesce (copying the current workspace's
  limit) and fails closed if it cannot, and a former workspace is uncapped before any ro flip
  on it, because at its cap that flip fails with EDQUOT.
"""

import errno
import fcntl
import logging
import os
import shutil
import stat
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime
from pathlib import Path

from backtide.snapshots import btrfs
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

logger = logging.getLogger(__name__)

WORKSPACE = "workspace"
SNAPSHOTS = "snapshots"
STAGING = "workspace.restore"
INCOMING_PREFIX = ".incoming-"
TRASH_PREFIX = ".trash-"
LOCK_FILE = ".lock"
WARN_SNAPSHOT_COUNT = 300
WARN_FREE_FRACTION = 0.10
LOCK_POLL_INTERVAL = 0.05  # seconds between two flock attempts

# Measured in the VM (T01b): when the agent's own files fill the metadata, deleting snapshots
# frees almost nothing, because they share those files with the workspace.
NO_SPACE_HINT = (
    "the volume is out of space: delete snapshots (oldest first) or grow the volume, then "
    "retry. A deleted snapshot frees only what it alone holds, a few seconds later; when the "
    "agent's own files fill the volume that is almost nothing, so grow it"
)
_NESTED_SUBVOLUME_STDERR = "Directory not empty"  # what btrfs says when a nested one blocks it
_NO_SPACE_TEXTS = ("Disk quota exceeded", "No space left on device")

type SetLimit = Callable[[Path, int | None], None]


class SnapshotStore:
    """Snapshots and rewinds of ``<root>/workspace``. Synchronous: async callers use
    ``asyncio.to_thread``. Every method that changes the volume takes the lock once."""

    def __init__(
        self,
        root: Path,
        *,
        clock: Callable[[], datetime] = utc_now,
        lock_timeout: float = 30.0,
        workspace_limit: int | None = None,
        set_limit: SetLimit | None = None,
    ) -> None:
        """No disk access. ``root`` must be absolute (ValueError otherwise).

        ``workspace_limit`` (bytes) is the cap init() gives the workspace; it needs a volume
        formatted with simple quotas. Without it, restore() still copies whatever cap the
        current workspace has, so the cap follows the workspace and not this process's config.
        ``set_limit`` sets or clears (None) a subvolume's limit and needs CAP_SYS_ADMIN; it
        defaults to btrfs.set_qgroup_limit (backtide runs as root). The VM tests inject the same
        command behind ``sudo -n``. Anything it raises becomes a SnapshotError."""
        root = Path(root)
        if not root.is_absolute():
            raise ValueError(f"the snapshot root must be an absolute path, got {str(root)!r}")
        if workspace_limit is not None and (
            isinstance(workspace_limit, bool)
            or not isinstance(workspace_limit, int)
            or workspace_limit <= 0
        ):
            raise ValueError(
                f"workspace_limit must be a positive number of bytes, got {workspace_limit!r}"
            )
        self.root = root
        self.workspace = root / WORKSPACE
        self.snapshots_dir = root / SNAPSHOTS
        self._staging = root / STAGING
        self._clock = clock
        self._lock_timeout = lock_timeout
        self._workspace_limit = workspace_limit
        self._set_limit = set_limit

    # Public API

    def init(self) -> None:
        """Create ``snapshots/`` and an empty workspace subvolume where missing. Idempotent.

        Refuses to create an empty workspace when snapshots exist: restoring one recreates it.
        A read-only workspace is only logged, so the agent cannot stop the guardian starting.
        With ``workspace_limit``, the volume must use simple quotas (checked before anything is
        created) and the workspace gets that cap, new or existing: a changed config takes
        effect at the next start."""
        with self._lock() as root_fd:
            self._check_private_dir(self.root)
            if self._workspace_limit is not None:
                self._require_simple_quotas()
            if not os.path.lexists(self.snapshots_dir):
                _mkdir_private(root_fd, SNAPSHOTS)
            self._check_layout(require_workspace=False)
            if btrfs.is_subvolume(self.workspace):
                if btrfs.is_readonly(self.workspace):
                    logger.warning(
                        "%s is read-only; take() and restore() still work", self.workspace
                    )
            else:
                existing = self._list()
                if existing:
                    raise SnapshotError(
                        f"{self.workspace} is missing but {len(existing)} snapshots exist; "
                        "refusing to create an empty workspace: "
                        f"restore({existing[-1].id!r}) recreates it"
                    )
                btrfs.create_subvolume(self.workspace)
            if self._workspace_limit is not None:
                self._apply_cap(self.workspace, self._workspace_limit)

    def take(self, reason: Reason) -> Snapshot:
        """Take a read-only snapshot of the workspace, durable on return.

        Never runs recovery: it is the last safety net and must work next to crash leftovers."""
        reason = Reason(reason)  # only enum members: no free text reaches a directory name
        with self._lock():
            self._check_layout(require_workspace=True)
            snap = Snapshot(self._clock(), reason)
            self._check_clock(snap)
            path = self.snapshots_dir / snap.id
            try:
                btrfs.snapshot(self.workspace, path, readonly=True)
            except SnapshotError as error:
                if error.errno == errno.EEXIST or not _is_readonly_subvolume(path, error):
                    raise
                # Creation is atomic in the kernel: if it exists read-only, it is complete.
                logger.warning(
                    "btrfs reported a failure but %s exists read-only, so it was taken: %s",
                    path,
                    error,
                )
            return snap

    def snapshots(self) -> list[Snapshot]:
        """Every published snapshot, sorted by (taken_at, id). Takes no lock."""
        return self._list()

    def restore(
        self, snapshot_id: str, *, quiesce: Callable[[], AbstractContextManager[object]]
    ) -> RestoreResult:
        """Rewind the workspace to ``snapshot_id``; the old workspace becomes the undo point.

        ``quiesce`` is required. Under the lock, after the staging copy is ready, it is entered
        around the swap, the publishing of the undo point and os.sync(): T04 stops the agent and
        the file watcher on enter, and re-arms the watcher and starts the agent on exit.

        - SnapshotError: the workspace was NOT changed.
        - RestoreIncomplete (not a SnapshotError): the rewind DID happen, but the old workspace
          could not be published; it stays at ``leftover`` and the next recover() publishes it.
        - An exception from entering ``quiesce`` propagates unchanged, with nothing changed.
        - An exception from exiting ``quiesce`` propagates unchanged (same object, same type),
          even a SnapshotError, and it replaces restore's own outcome. So it carries a note
          saying what restore did: rewound (with the undo point), RestoreIncomplete's message,
          or workspace unchanged.
        - If the recovery that runs first published leftovers and restore then fails, the error
          carries a note naming them.

        ``quiesce`` must STOP the agent, not pause it: a paused (frozen) container keeps the old
        workspace mounted, and after the swap that is the uncapped undo point.

        Afterwards, fds, cwd and inotify watches that pointed into the old workspace point at
        ``snapshots/<undo.id>``: re-open by path. Undo is ``restore(result.undo.id, ...)``."""
        target, source = self._path_of(snapshot_id)
        with self._lock() as root_fd:
            self._check_layout(require_workspace=False)
            try:
                recovered = self._recover_locked(root_fd)
            except SnapshotError as error:
                error.add_note("restore did not start: the workspace is unchanged")
                raise
            try:
                undo = self._restore_locked(root_fd, target, source, quiesce)
            except BaseException as error:
                if recovered:
                    error.add_note(f"recovery published first: {_ids(recovered)}")
                raise
        return RestoreResult(target=target, undo=undo, recovered=tuple(recovered))

    def delete(self, snapshot_id: str) -> None:
        """Delete one snapshot, protected reasons included. Committed on return."""
        snap, path = self._path_of(snapshot_id)
        with self._lock() as root_fd:
            self._check_layout(require_workspace=False)
            if not btrfs.is_subvolume(path):
                raise SnapshotError(f"no such snapshot: {snap.id}")
            self._delete_locked(root_fd, snap, commit=True)

    def prune(self) -> list[Snapshot]:
        """Delete what retention expires (only periodic snapshots) and return it, oldest first.

        Attempts every expired snapshot, then raises PruneIncomplete if any failed. Never deletes
        because space is low. Logs a WARNING above WARN_SNAPSHOT_COUNT snapshots (with counts
        per reason) and below WARN_FREE_FRACTION of free space."""
        with self._lock() as root_fd:
            self._check_layout(require_workspace=False)
            listed = self._list()
            deleted: list[Snapshot] = []
            failed: list[Snapshot] = []
            first_error: SnapshotError | None = None
            for snap in select_expired(listed, self._clock()):
                try:
                    self._delete_locked(root_fd, snap, commit=False)
                except SnapshotError as error:
                    logger.error("prune could not delete %s: %s", snap.id, error)
                    failed.append(snap)
                    first_error = first_error or error
                else:
                    deleted.append(snap)
            gone = set(deleted)
            self._warn_about_growth([snap for snap in listed if snap not in gone])
        if failed:
            raise PruneIncomplete(deleted, failed) from first_error
        return deleted

    def recover(self) -> list[Snapshot]:
        """Finish or publish what a dead process left behind; return the snapshots it published.

        T04 calls it at startup: init() → recover() → match events → start the agent."""
        with self._lock() as root_fd:
            self._check_layout(require_workspace=False)
            return self._recover_locked(root_fd)

    def workspace_id(self) -> int:
        """The btrfs subvolume ID of the workspace. Changes exactly when a restore swaps it."""
        return btrfs.subvolume_id(self.workspace)

    def workspace_usage(self) -> btrfs.QgroupUsage | None:
        """The workspace's qgroup (usage and cap), or None on a volume without quotas. Takes
        no lock and needs no root. ``referenced`` only moves when a transaction commits, and
        it can pass the cap: deletes after a snapshot are not checked (docs/16, A13)."""
        if btrfs.quota_mode(self.root) is None:
            return None
        return btrfs.qgroup_usage(self.workspace)

    # Lock and layout

    @contextmanager
    def _lock(self) -> Iterator[int]:
        """Hold the volume lock, yielding an fd of ``<root>`` for renames. Not reentrant."""
        root_fd = _open(str(self.root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            lock_fd = _open(
                LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd
            )
            try:
                self._acquire(lock_fd)
                with btrfs.children_hold(lock_fd):
                    yield root_fd
            finally:
                os.close(lock_fd)
        finally:
            os.close(root_fd)

    def _acquire(self, lock_fd: int) -> None:
        deadline = time.monotonic() + self._lock_timeout
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError as e:
                if time.monotonic() >= deadline:
                    raise SnapshotBusy(
                        f"another operation holds the lock on {self.root}; "
                        f"gave up after {self._lock_timeout} s"
                    ) from e
            except OSError as e:
                raise SnapshotError(
                    f"cannot lock {self.root / LOCK_FILE}: {e}", errno=e.errno
                ) from e
            time.sleep(LOCK_POLL_INTERVAL)

    def _check_layout(self, *, require_workspace: bool) -> None:
        """``<root>`` and ``snapshots/`` are private directories, and the workspace is a
        subvolume (or, unless ``require_workspace``, absent). Never fixes anything."""
        self._check_private_dir(self.root)
        self._check_private_dir(self.snapshots_dir)
        if btrfs.is_subvolume(self.workspace):
            return
        if os.path.lexists(self.workspace):
            raise SnapshotError(f"{self.workspace} is not a subvolume: fix it by hand")
        if require_workspace:
            raise SnapshotError(f"{self.workspace} is missing: restore a snapshot to recreate it")

    @staticmethod
    def _check_private_dir(path: Path) -> None:
        """A real directory (not a symlink), owned by the euid, closed to group and others."""
        try:
            st = os.lstat(path)
        except FileNotFoundError as e:
            raise SnapshotError(f"{path} is missing: run init() first", errno=e.errno) from e
        except OSError as e:
            raise SnapshotError(f"cannot stat {path}: {e}", errno=e.errno) from e
        if not stat.S_ISDIR(st.st_mode):
            raise SnapshotError(f"{path} is not a directory (a symlink or a file?): fix it by hand")
        if st.st_uid != os.geteuid():
            raise SnapshotError(
                f"{path} is owned by uid {st.st_uid}, not {os.geteuid()}: fix it by hand"
            )
        if st.st_mode & 0o077:
            raise SnapshotError(
                f"{path} has mode {stat.S_IMODE(st.st_mode):04o}, open to group or others: "
                "chmod 700 it by hand"
            )

    # Listing

    def _list(self) -> list[Snapshot]:
        """Published snapshots: entries whose name parses as an id AND that are subvolumes."""
        found = []
        for name in self._snapshot_entries():
            snap = Snapshot.parse(name)
            if snap is not None and btrfs.is_subvolume(self.snapshots_dir / name):
                found.append(snap)
        return sorted(found, key=lambda snap: (snap.taken_at, snap.id))

    def _snapshot_entries(self) -> list[str]:
        try:
            return sorted(os.listdir(self.snapshots_dir))
        except OSError as e:
            raise SnapshotError(f"cannot list {self.snapshots_dir}: {e}", errno=e.errno) from e

    def _path_of(self, snapshot_id: str) -> tuple[Snapshot, Path]:
        """Parse an id that comes from outside. No I/O: an invalid id never touches the disk."""
        snap = Snapshot.parse(snapshot_id)
        if snap is None:
            raise SnapshotError(f"invalid snapshot id: {snapshot_id[:80]!r}")
        return snap, self.snapshots_dir / snap.id

    def _check_clock(self, snap: Snapshot) -> None:
        """Log an ERROR (T04 alerts) when the clock is behind the newest snapshot. Never clamps:
        clamping to a far-future stray would stop pruning altogether."""
        newest = max((listed.taken_at for listed in self._list()), default=None)
        if newest is not None and newest > snap.taken_at:
            logger.error(
                "the clock is behind the newest snapshot by %s (now %s, newest %s)",
                newest - snap.taken_at,
                snap.taken_at.isoformat(),
                newest.isoformat(),
            )

    # Restore

    def _restore_locked(
        self,
        root_fd: int,
        target: Snapshot,
        source: Path,
        quiesce: Callable[[], AbstractContextManager[object]],
    ) -> Snapshot | None:
        self._check_target(target, source)
        workspace_existed = os.path.lexists(self.workspace)
        try:
            cap = self._cap_for_new_workspace(workspace_existed)
        except SnapshotError as error:
            raise _failed_before_swap(error) from error
        self._stage(source, cap)
        return self._swap_quiesced(root_fd, target, workspace_existed, quiesce)

    def _check_target(self, target: Snapshot, source: Path) -> None:
        if not btrfs.is_subvolume(source):
            raise SnapshotError(f"no such snapshot: {target.id}")
        if not btrfs.is_readonly(source):
            raise SnapshotError(
                f"snapshot {target.id} is writable (tampering, or a delete interrupted while "
                "the volume was full): refusing to restore it; inspect it or delete it"
            )

    def _stage(self, source: Path, cap: int | None) -> None:
        """Make the writable copy of the target, before the agent is stopped, and give it the
        cap: the agent never starts on an uncapped workspace. Fails closed."""
        try:
            btrfs.snapshot(source, self._staging, readonly=False)
        except SnapshotError as error:
            if error.errno != errno.EEXIST:  # EEXIST: that staging is not ours to delete
                self._discard_staging(error)
            raise _failed_before_swap(error) from error
        if cap is None:
            return
        try:
            self._apply_cap(self._staging, cap)
        except SnapshotError as error:
            self._discard_staging(error)
            raise _failed_before_swap(error) from error

    def _swap_quiesced(
        self,
        root_fd: int,
        target: Snapshot,
        workspace_existed: bool,
        quiesce: Callable[[], AbstractContextManager[object]],
    ) -> Snapshot | None:
        """Swap and publish inside ``quiesce``. Its __exit__ is called by hand so that it can
        never swallow restore's own errors (see _exit_quiesce)."""
        try:
            quiesced = quiesce()
            quiesced.__enter__()
        except BaseException as error:
            self._discard_staging(error)
            raise
        try:
            undo = self._swap_locked(root_fd, target, workspace_existed)
        except BaseException as error:
            _exit_quiesce(quiesced, error, _failure_outcome(target, error))
            raise
        # Logged before quiesce exits, so the rewind is on record even if exiting raises.
        logger.info("workspace restored to %s; undo point %s", target.id, undo and undo.id)
        _exit_quiesce(quiesced, None, _success_outcome(target, undo))
        return undo

    def _swap_locked(
        self, root_fd: int, target: Snapshot, workspace_existed: bool
    ) -> Snapshot | None:
        flags = btrfs.RENAME_EXCHANGE if workspace_existed else btrfs.RENAME_NOREPLACE
        try:
            btrfs.renameat2(root_fd, STAGING, WORKSPACE, flags)
        except SnapshotError as error:  # a syscall: it did not happen
            self._discard_staging(error)
            raise _failed_before_swap(error) from error
        # From here the rewind HAS happened.
        try:
            return self._publish_undo_locked(root_fd, target) if workspace_existed else None
        finally:
            os.sync()  # commit the swap, the renames and the ro flag before the caller logs it

    def _publish_undo_locked(self, root_fd: int, target: Snapshot) -> Snapshot:
        """Publish the old workspace, now at the staging name, as the pre_restore undo point."""
        undo: Snapshot | None = None
        try:
            undo = Snapshot(self._clock(), Reason.PRE_RESTORE)
            self._publish_locked(root_fd, STAGING, undo)
        except Exception as error:
            leftover = self._undo_leftover(undo)
            logger.error(
                "workspace WAS restored to %s, but publishing the undo point failed; "
                "previous state kept at %s: %s",
                target.id,
                leftover,
                error,
            )
            incomplete = RestoreIncomplete(target, leftover)
            if isinstance(error, SnapshotNoSpace):  # recover() fails the same way until then
                incomplete.add_note(f"publishing it needs space: {NO_SPACE_HINT}")
            raise incomplete from error
        return undo

    def _undo_leftover(self, undo: Snapshot | None) -> Path:
        """Where the old workspace sits after a failed publish."""
        if undo is not None and os.path.lexists(self.root / _incoming_rel(undo)):
            return self.root / _incoming_rel(undo)
        return self._staging

    def _discard_staging(self, error: BaseException) -> None:
        """Delete the staging copy if there is one: before the swap it is a pure copy of the
        target. A failure is attached to ``error``; the next recover() publishes the copy."""
        try:
            if btrfs.is_subvolume(self._staging):
                btrfs.delete_subvolume(self._staging)
        except SnapshotError as e:
            error.add_note(f"deleting the staging copy {self._staging} also failed: {e}")

    # Publish and delete

    def _publish_locked(self, root_fd: int, src_rel: str, snap: Snapshot) -> None:
        """Publish the subvolume at ``<root>/<src_rel>`` as the read-only snapshot ``snap``.

        A read-only subvolume cannot move to another directory (EROFS), so it moves while
        writable and is sealed inside snapshots/. A crash leaves ``.incoming-<id>`` (R2). A
        former workspace loses its cap first: at its cap, every ro flip fails with EDQUOT."""
        src = self.root / src_rel
        self._uncap(src)
        if btrfs.is_readonly(src):
            btrfs.set_readonly(src, False)
        btrfs.renameat2(root_fd, src_rel, _incoming_rel(snap), btrfs.RENAME_NOREPLACE)
        self._seal_locked(root_fd, snap)

    def _seal_locked(self, root_fd: int, snap: Snapshot) -> None:
        btrfs.set_readonly(self.root / _incoming_rel(snap), True)
        btrfs.renameat2(root_fd, _incoming_rel(snap), _snapshot_rel(snap), btrfs.RENAME_NOREPLACE)

    def _delete_locked(self, root_fd: int, snap: Snapshot, *, commit: bool) -> None:
        """Delete ``snapshots/<id>`` through the tombstone ``.trash-<id>``: it leaves the listing
        atomically before its ro flag is cleared, and a crash leaves a name R1 finishes."""
        try:
            btrfs.renameat2(root_fd, _snapshot_rel(snap), _trash_rel(snap), btrfs.RENAME_NOREPLACE)
        except SnapshotNoSpace as error:
            # Full metadata makes every rename fail, but deletes still work (T01a spike), and
            # deleting is how the user frees space (docs/10, "Borrar"). Without the tombstone, a
            # crash between clearing ro and the delete leaves this snapshot listed and writable:
            # restore() refuses it, and delete() or the next prune still remove it.
            logger.warning("%s; deleting %s in place instead", error, snap.id)
            self._delete_in_place_locked(snap, commit=commit)
            return
        self._delete_trash_locked(root_fd, snap, commit=commit)

    def _delete_in_place_locked(self, snap: Snapshot, *, commit: bool) -> None:
        path = self.root / _snapshot_rel(snap)
        try:
            self._uncap(path)  # deleting clears ro first, and at its cap that fails
            _delete_subvolume(snap, path, commit=commit)
        except SnapshotError as error:
            _reseal(path, error)
            raise

    def _delete_trash_locked(self, root_fd: int, snap: Snapshot, *, commit: bool) -> None:
        """Delete ``.trash-<id>``. If that fails, seal it and rename it back to ``<id>``, so it
        is listed again and read-only."""
        try:
            self._uncap(self.root / _trash_rel(snap))
            _delete_subvolume(snap, self.root / _trash_rel(snap), commit=commit)
        except SnapshotError as error:
            _reseal(self.root / _trash_rel(snap), error)
            try:
                btrfs.renameat2(
                    root_fd, _trash_rel(snap), _snapshot_rel(snap), btrfs.RENAME_NOREPLACE
                )
            except SnapshotError as e:
                error.add_note(f"renaming it back to {snap.id} also failed: {e}")
            raise

    # Crash recovery

    def _recover_locked(self, root_fd: int) -> list[Snapshot]:
        """Rules R1-R3 (docs/10). Each leftover is attempted; errors are raised together at the
        end, and nothing is ever thrown away. Unknown entries are only logged."""
        published: list[Snapshot] = []
        errors: list[SnapshotError] = []
        leftovers = 0
        for name in self._snapshot_entries():
            path = self.snapshots_dir / name
            is_subvolume = btrfs.is_subvolume(path)
            if is_subvolume and Snapshot.parse(name) is not None:
                continue
            trashed = _in_progress(name, TRASH_PREFIX) if is_subvolume else None
            incoming = _in_progress(name, INCOMING_PREFIX) if is_subvolume else None
            if trashed is None and incoming is None:
                logger.warning("unexpected entry %s: leaving it untouched", path)
                continue
            leftovers += 1
            try:
                if trashed is not None:  # R1: finish an interrupted delete
                    self._delete_trash_locked(root_fd, trashed, commit=False)
                elif incoming is not None:  # R2: finish an interrupted publish
                    self._finish_incoming_locked(root_fd, incoming)
                    published.append(incoming)
            except SnapshotError as error:
                logger.error("recovery could not handle %s: %s", path, error)
                errors.append(error)
        if os.path.lexists(self._staging):  # R3: publish the staging leftover
            leftovers += 1
            try:
                published.append(self._recover_staging_locked(root_fd))
            except SnapshotError as error:
                logger.error("recovery could not handle %s: %s", self._staging, error)
                errors.append(error)
        if leftovers:
            os.sync()
        if errors:
            raise _recovery_error(errors, published) from errors[0]
        if published:
            logger.warning("recovery published %s", _ids(published))
        return published

    def _finish_incoming_locked(self, root_fd: int, snap: Snapshot) -> None:
        if os.path.lexists(self.root / _snapshot_rel(snap)):
            raise SnapshotError(
                f"cannot publish {self.root / _incoming_rel(snap)}: {snap.id} already exists; "
                "leaving both for a human"
            )
        self._uncap(self.root / _incoming_rel(snap))
        self._seal_locked(root_fd, snap)

    def _recover_staging_locked(self, root_fd: int) -> Snapshot:
        """Either a copy of a restore target (crash before the swap) or the old workspace (crash
        after it): publishing it as 'recovered' loses nothing and needs no new snapshot."""
        if not btrfs.is_subvolume(self._staging):
            raise SnapshotError(
                f"{self._staging} is not a subvolume (a plain directory, a file or a symlink): "
                "tampering? Leaving it untouched for a human"
            )
        snap = Snapshot(self._clock(), Reason.RECOVERED)
        self._publish_locked(root_fd, STAGING, snap)
        return snap

    # Quotas (T03b, docs/16)

    def _require_simple_quotas(self) -> None:
        mode = btrfs.quota_mode(self.root)
        if mode != "squota":
            raise SnapshotError(
                f"a workspace limit needs a volume formatted with simple quotas "
                f"(mkfs.btrfs -O squota); the quota mode of {self.root} is {mode or 'off'}"
            )

    def _cap_for_new_workspace(self, workspace_existed: bool) -> int | None:
        """The cap the next workspace gets: the current workspace's, else the configured one.
        None on a volume without quotas (unless a cap is configured: then it fails closed)."""
        if btrfs.quota_mode(self.root) is None:
            if self._workspace_limit is not None:
                self._require_simple_quotas()  # raises: never hand the agent an uncapped one
            return None
        if workspace_existed:
            usage = btrfs.qgroup_usage(self.workspace)
            if usage.exclusive_limit is not None:
                # backtide never sets one and cannot clear it, so the old workspace could never be
                # uncapped and sealed: refuse now, with nothing changed, not after the swap.
                raise SnapshotError(
                    f"{self.workspace} has an exclusive quota limit, which backtide never sets: "
                    f"clear it by hand with `btrfs qgroup limit -e none {self.workspace}`"
                )
            if usage.limit is not None:
                return usage.limit
        if self._workspace_limit is None:
            logger.error(
                "%s uses simple quotas but no cap is configured and the workspace has none: "
                "the rewound workspace has no space cap",
                self.root,
            )
        return self._workspace_limit

    def _uncap(self, path: Path) -> None:
        """Remove any cap from a subvolume that is no longer the workspace. No-op without
        quotas or without a cap."""
        if btrfs.quota_mode(self.root) is None:
            return
        usage = btrfs.qgroup_usage(path)
        if usage.limit is not None or usage.exclusive_limit is not None:
            self._apply_cap(path, None)

    def _apply_cap(self, path: Path, limit: int | None) -> None:
        """Give ``path`` exactly this referenced limit (None: no cap) and read it back. The
        setter runs only when the value differs, and the bits are what count (docs/16: mkfs
        leaves garbage in the limit fields of 0/5)."""
        if _cap_of(btrfs.qgroup_usage(path)) == (limit, None):
            return
        self._call_set_limit(path, limit)
        after = _cap_of(btrfs.qgroup_usage(path))
        if after == (limit, None):
            return
        message = f"the quota limit of {path} reads back as {after} after setting it to {limit}"
        if after[1] is not None:
            message += (
                "; it has an exclusive limit, which backtide never sets: clear it by hand with "
                f"`btrfs qgroup limit -e none {path}`"
            )
        raise SnapshotError(message)

    def _call_set_limit(self, path: Path, limit: int | None) -> None:
        setter = self._set_limit or btrfs.set_qgroup_limit  # looked up now, so tests can patch
        try:
            setter(path, limit)
        except SnapshotError:
            raise
        except Exception as error:  # an injected setter still honours the error contract
            kind = (
                SnapshotNoSpace if any(t in str(error) for t in _NO_SPACE_TEXTS) else SnapshotError
            )
            raise kind(
                f"cannot set the quota limit of {path} to {limit}: {error}",
                errno=getattr(error, "errno", None),
            ) from error

    # Warnings

    def _warn_about_growth(self, remaining: list[Snapshot]) -> None:
        if len(remaining) > WARN_SNAPSHOT_COUNT:
            counts = Counter(snap.reason for snap in remaining)
            logger.warning(
                "%d snapshots kept, more than %d (%s)",
                len(remaining),
                WARN_SNAPSHOT_COUNT,
                ", ".join(f"{reason}: {count}" for reason, count in sorted(counts.items())),
            )
        try:
            usage = shutil.disk_usage(self.root)
        except OSError as e:
            logger.error("cannot read the free space of %s: %s", self.root, e)
            return
        if usage.free < WARN_FREE_FRACTION * usage.total:
            logger.warning(
                "%s is low on space: %.1f%% free (%d of %d bytes)",
                self.root,
                100 * usage.free / usage.total,
                usage.free,
                usage.total,
            )


def _snapshot_rel(snap: Snapshot) -> str:
    return f"{SNAPSHOTS}/{snap.id}"


def _incoming_rel(snap: Snapshot) -> str:
    return f"{SNAPSHOTS}/{INCOMING_PREFIX}{snap.id}"


def _trash_rel(snap: Snapshot) -> str:
    return f"{SNAPSHOTS}/{TRASH_PREFIX}{snap.id}"


def _in_progress(name: str, prefix: str) -> Snapshot | None:
    """The snapshot an in-progress name such as ``.trash-<id>`` refers to, or None."""
    return Snapshot.parse(name.removeprefix(prefix)) if name.startswith(prefix) else None


def _open(path: str, flags: int, *, dir_fd: int | None = None) -> int:
    try:
        return os.open(path, flags, 0o600, dir_fd=dir_fd)
    except OSError as e:
        raise SnapshotError(f"cannot open {path}: {e}", errno=e.errno) from e


def _mkdir_private(root_fd: int, name: str) -> None:
    try:
        os.mkdir(name, 0o700, dir_fd=root_fd)
    except OSError as e:
        raise SnapshotError(f"cannot create {name}: {e}", errno=e.errno) from e


def _is_readonly_subvolume(path: Path, error: SnapshotError) -> bool:
    """Whether a failed snapshot command created ``path`` anyway. A failed check is noted."""
    try:
        return btrfs.is_subvolume(path) and btrfs.is_readonly(path)
    except SnapshotError as e:
        error.add_note(f"could not check whether {path} was created anyway: {e}")
        return False


def _delete_subvolume(snap: Snapshot, path: Path, *, commit: bool) -> None:
    """btrfs.delete_subvolume, with a hint when a nested subvolume blocks the delete."""
    try:
        btrfs.delete_subvolume(path, commit=commit)
    except SnapshotError as error:
        if _NESTED_SUBVOLUME_STDERR not in str(error):
            raise
        hint = SnapshotError(
            f"cannot delete snapshot {snap.id}: it contains a nested subvolume (planted inside "
            f"the workspace?). It stays listed; only root can remove it: "
            f"btrfs subvolume delete -R {path.parent / snap.id}. Cause: {error}",
            errno=errno.ENOTEMPTY,
        )
        for note in getattr(error, "__notes__", ()):  # e.g. putting ro back also failed
            hint.add_note(note)
        raise hint from error


def _reseal(path: Path, error: SnapshotError) -> None:
    """Make a snapshot whose delete failed read-only again, so it is listed only read-only.

    btrfs.delete_subvolume puts ro back only when it was set on entry, and a crash inside it
    (after clearing ro, before deleting) leaves it cleared for the next attempt. A failure is
    noted on ``error``."""
    try:
        btrfs.set_readonly(path, True)
    except SnapshotError as e:
        error.add_note(f"making {path} read-only again also failed: {e}")


def _exit_quiesce(
    quiesced: AbstractContextManager[object], error: BaseException | None, outcome: str
) -> None:
    """Exit ``quiesced`` after the swap step, passing it restore's own ``error`` (or None).

    An exception from __exit__ propagates unchanged (same object, same type), but it replaces
    restore's outcome, even a SnapshotError after a completed rewind. So it gets a note saying
    what restore did."""
    try:
        if error is None:
            quiesced.__exit__(None, None, None)
        else:
            quiesced.__exit__(type(error), error, error.__traceback__)
    except BaseException as exit_error:
        if exit_error is not error:  # restore's own error already says what happened
            exit_error.add_note(f"raised while exiting quiesce, after restore: {outcome}")
        raise


def _success_outcome(target: Snapshot, undo: Snapshot | None) -> str:
    undo_point = undo.id if undo is not None else "none (there was no workspace)"
    return f"restore DID happen: workspace rewound to {target.id}; undo point {undo_point}"


def _failure_outcome(target: Snapshot, error: BaseException) -> str:
    """What restore did, given the error its swap step raised."""
    if isinstance(error, RestoreIncomplete):  # its notes may hold the no-space hint
        return "; ".join([f"restore DID happen: {error}", *getattr(error, "__notes__", ())])
    if isinstance(error, SnapshotError):  # only raised before the swap (_failed_before_swap)
        return f"restore to {target.id} did NOT happen, workspace unchanged: {error}"
    return (
        f"restore to {target.id} was interrupted by {error!r}: workspace_id() tells whether "
        "the swap happened, and the next recover() publishes any leftover"
    )


def _ids(snapshots: list[Snapshot]) -> str:
    return ", ".join(snap.id for snap in snapshots)


def _cap_of(usage: btrfs.QgroupUsage) -> tuple[int | None, int | None]:
    """(referenced limit, exclusive limit), each None when its bit is not set."""
    return usage.limit, usage.exclusive_limit


def _failed_before_swap(error: SnapshotError) -> SnapshotError:
    """The error restore raises when it stops before the swap: the workspace is unchanged."""
    if isinstance(error, SnapshotNoSpace):
        return SnapshotNoSpace(
            f"restore stopped before the swap, workspace unchanged: {NO_SPACE_HINT}. "
            f"Cause: {error}",
            errno=error.errno,
        )
    return SnapshotError(
        f"restore failed before the swap; workspace unchanged: {error}", errno=error.errno
    )


def _recovery_error(errors: list[SnapshotError], published: list[Snapshot]) -> SnapshotError:
    details = "; ".join(str(error) for error in errors)
    if any(isinstance(error, SnapshotNoSpace) for error in errors):
        aggregated: SnapshotError = SnapshotNoSpace(
            f"crash recovery failed on {len(errors)} leftover(s), nothing was thrown away: "
            f"{NO_SPACE_HINT}. Causes: {details}",
            errno=errno.ENOSPC,
        )
    else:
        aggregated = SnapshotError(
            f"crash recovery failed on {len(errors)} leftover(s), nothing was thrown away: "
            f"{details}"
        )
    for error in errors:  # e.g. "renaming it back also failed": only __cause__ would keep it
        for note in getattr(error, "__notes__", ()):
            aggregated.add_note(note)
    if published:
        aggregated.add_note(f"published first: {_ids(published)}")
    return aggregated
