"""The pieces of a rewind that are not the Guardian: ``rewind.pending`` and the outcome.

``rewind.pending`` is the intent of a rewind in progress, written (and fsynced) before anything
changes, so a fresh Guardian can reconcile a rewind that was killed half way (docs/19, section
4). It lives in Vigía's own state folder: never in the volume, never seen by the agent.
"""

import os
import stat
from pathlib import Path

import pytest

from vigia.service.rewind import (
    PendingError,
    PendingRewind,
    RewindOutcome,
    RewindStatus,
    is_space_error,
    read_pending,
    remove_pending,
    write_pending,
)
from vigia.snapshots import RestoreIncomplete, Snapshot, SnapshotError, SnapshotNoSpace

TARGET = "20261005T080000.000000Z-periodic"


def pending() -> PendingRewind:
    return PendingRewind(
        request_id="0123456789abcdef0123456789abcdef",
        target=TARGET,
        from_workspace_id=258,
        requested_by="cli",
    )


def test_the_intent_round_trips_and_is_private(tmp_path: Path) -> None:
    path = tmp_path / "rewind.pending"
    write_pending(path, pending())
    assert read_pending(path) == pending()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (tmp_path / "rewind.pending.tmp").exists()


def test_no_intent_is_none(tmp_path: Path) -> None:
    assert read_pending(tmp_path / "rewind.pending") is None


def test_writing_replaces_a_stale_intent_and_a_stale_temporary_file(tmp_path: Path) -> None:
    path = tmp_path / "rewind.pending"
    (tmp_path / "rewind.pending.tmp").write_text("left by a crash")
    write_pending(path, pending())
    newer = PendingRewind("f" * 32, TARGET, 300, "cli")
    write_pending(path, newer)
    assert read_pending(path) == newer


def test_removing_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "rewind.pending"
    write_pending(path, pending())
    remove_pending(path)
    remove_pending(path)
    assert not path.exists()


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"[]",
        b'{"request_id": "x"}',
        b'{"request_id": "abc", "target": "nope", "from_workspace_id": 258, "requested_by": "cli"}',
        b'{"request_id": "abc", "target": "' + TARGET.encode() + b'", "from_workspace_id": "258", '
        b'"requested_by": "cli"}',
        b'{"request_id": "abc", "target": "' + TARGET.encode() + b'", "from_workspace_id": true, '
        b'"requested_by": "cli"}',
        b"{" + b" " * 8192 + b"}",
    ],
)
def test_an_unreadable_intent_is_an_error_never_a_guess(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "rewind.pending"
    path.write_bytes(content)
    with pytest.raises(PendingError):
        read_pending(path)


def test_a_symlink_is_never_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    write_pending(elsewhere, pending())
    path = tmp_path / "rewind.pending"
    path.symlink_to(elsewhere)
    with pytest.raises(PendingError, match="regular file|symbolic|link"):
        read_pending(path)


def test_writing_never_follows_a_symlinked_temporary_file(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (tmp_path / "rewind.pending.tmp").symlink_to(victim)
    write_pending(tmp_path / "rewind.pending", pending())
    assert victim.read_text() == "untouched"
    assert read_pending(tmp_path / "rewind.pending") == pending()


def test_space_errors_are_recognised_through_restore_incomplete() -> None:
    target = Snapshot.parse(TARGET)
    assert target is not None
    assert is_space_error(SnapshotNoSpace("full"))
    incomplete = RestoreIncomplete(target, Path("/x"))
    assert not is_space_error(incomplete)
    try:
        raise incomplete from SnapshotNoSpace("full")
    except RestoreIncomplete as error:
        assert is_space_error(error)
    assert not is_space_error(SnapshotError("other"))
    assert not is_space_error(None)
    assert not is_space_error(OSError(28, os.strerror(28)))


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (RewindStatus.DONE, 0),
        (RewindStatus.FAILED, 1),
        (RewindStatus.INVALID, 2),
        (RewindStatus.PROBLEM, 3),
        (RewindStatus.UNKNOWN, 3),
    ],
)
def test_the_exit_code_of_each_outcome(status: RewindStatus, code: int) -> None:
    outcome = RewindOutcome(status=status, target=TARGET, message="x")
    assert outcome.exit_code == code
    assert outcome.rewound is (status in (RewindStatus.DONE, RewindStatus.PROBLEM))
