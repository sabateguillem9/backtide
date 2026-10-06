"""Unit tests for the btrfs wrapper. No btrfs needed: subprocess.run is replaced by a recorder."""

import ctypes
import errno
import logging
import os
import stat
import subprocess
import sys
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from vigia.snapshots import SnapshotError, SnapshotNoSpace, btrfs

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="needs glibc renameat2")


@dataclass(frozen=True)
class Reply:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


OK = Reply()
RO_TRUE = Reply("ro=true\n")
RO_FALSE = Reply("ro=false\n")
NOT_EMPTY = Reply(stderr="ERROR: Could not destroy subvolume: Directory not empty\n", returncode=1)
DENIED = Reply(stderr="ERROR: Permission denied\n", returncode=1)
COMMIT_WAIT_FAILED = Reply(
    stderr="ERROR: unable to do final sync after deletion: No space left on device\n",
    returncode=1,
)


def stat_result(mode: int, ino: int) -> os.stat_result:
    return os.stat_result((mode, ino, 0, 1, 0, 0, 0, 0, 0, 0))


SUBVOLUME_ROOT = stat_result(stat.S_IFDIR | 0o700, btrfs.SUBVOLUME_ROOT_INO)


@dataclass
class Call:
    argv: object
    kwargs: dict[str, object]


class Recorder:
    """Stands in for subprocess.run. Records every call and plays the scripted replies in
    order; an exception in the script is raised instead. With the script empty, it succeeds."""

    def __init__(self) -> None:
        self.calls: list[Call] = []
        self.script: deque[Reply | BaseException] = deque()

    def then(self, *replies: Reply | BaseException) -> None:
        self.script.extend(replies)

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(Call(argv, kwargs))
        reply = self.script.popleft() if self.script else OK
        if isinstance(reply, BaseException):
            raise reply
        return subprocess.CompletedProcess(argv, reply.returncode, reply.stdout, reply.stderr)

    @property
    def argvs(self) -> list[list[str]]:
        return [list(call.argv) for call in self.calls]  # type: ignore[call-overload]


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    fake = Recorder()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def btrfs_argv(base: Path, *args: str) -> list[str]:
    """``@name`` in args stands for the absolute path ``base / name``."""
    return ["btrfs", *(str(base / a[1:]) if a.startswith("@") else a for a in args)]


def get_ro(base: Path, name: str) -> list[str]:
    return btrfs_argv(base, "property", "get", "-ts", f"@{name}", "ro")


def set_ro(base: Path, name: str, value: str) -> list[str]:
    return btrfs_argv(base, "property", "set", "-ts", f"@{name}", "ro", value)


def delete(base: Path, name: str) -> list[str]:
    return btrfs_argv(base, "subvolume", "delete", f"@{name}")


# --- exact argv ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "replies", "expected"),
    [
        pytest.param(
            lambda d: btrfs.create_subvolume(d / "ws"),
            [],
            [("subvolume", "create", "@ws")],
            id="create",
        ),
        pytest.param(
            lambda d: btrfs.snapshot(d / "ws", d / "snap", readonly=True),
            [],
            [("subvolume", "snapshot", "-r", "@ws", "@snap")],
            id="snapshot-readonly",
        ),
        pytest.param(
            lambda d: btrfs.snapshot(d / "ws", d / "snap", readonly=False),
            [],
            [("subvolume", "snapshot", "@ws", "@snap")],
            id="snapshot-writable",
        ),
        pytest.param(
            lambda d: btrfs.is_readonly(d / "ws"),
            [RO_TRUE],
            [("property", "get", "-ts", "@ws", "ro")],
            id="property-get",
        ),
        pytest.param(
            lambda d: btrfs.set_readonly(d / "ws", True),
            [],
            [("property", "set", "-ts", "@ws", "ro", "true")],
            id="property-set-true",
        ),
        pytest.param(
            lambda d: btrfs.set_readonly(d / "ws", False),
            [],
            [("property", "set", "-ts", "@ws", "ro", "false")],
            id="property-set-false",
        ),
        pytest.param(
            lambda d: btrfs.delete_subvolume(d / "subvol"),
            [RO_FALSE],
            [("property", "get", "-ts", "@subvol", "ro"), ("subvolume", "delete", "@subvol")],
            id="delete",
        ),
        pytest.param(
            lambda d: btrfs.delete_subvolume(d / "subvol", commit=True),
            [RO_FALSE],
            [
                ("property", "get", "-ts", "@subvol", "ro"),
                ("subvolume", "delete", "--commit-after", "@subvol"),
            ],
            id="delete-commit",
        ),
        pytest.param(
            lambda d: btrfs.subvolume_id(d / "ws"),
            [Reply("257\n")],
            [("inspect-internal", "rootid", "@ws")],
            id="rootid",
        ),
    ],
)
def test_exact_argv(
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    action: Callable[[Path], object],
    replies: list[Reply],
    expected: list[tuple[str, ...]],
) -> None:
    fake_lstat(monkeypatch, tmp_path / "subvol", SUBVOLUME_ROOT)
    recorder.then(*replies)
    action(tmp_path)
    assert recorder.argvs == [btrfs_argv(tmp_path, *args) for args in expected]


def test_run_uses_a_fixed_argv_list_c_locale_and_a_timeout(
    recorder: Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LC_ALL", "es_ES.UTF-8")
    monkeypatch.setenv("VIGIA_TEST_MARKER", "kept")
    btrfs.run("filesystem", "sync", Path("/vol"))
    (call,) = recorder.calls
    assert call.argv == ["btrfs", "filesystem", "sync", "/vol"]
    env = call.kwargs["env"]
    assert isinstance(env, dict)
    assert env["LC_ALL"] == "C"
    assert env["VIGIA_TEST_MARKER"] == "kept"
    assert call.kwargs.get("shell", False) is False
    assert call.kwargs["timeout"] == btrfs.DEFAULT_TIMEOUT == 120.0
    assert call.kwargs["capture_output"] is True
    assert call.kwargs["check"] is False
    assert call.kwargs["stdin"] == subprocess.DEVNULL
    assert call.kwargs["pass_fds"] == ()


def test_run_passes_a_custom_timeout_and_returns_stdout(recorder: Recorder) -> None:
    recorder.then(Reply("Label: none\n", stderr="WARNING: ignored on success\n"))
    assert btrfs.run("filesystem", "show", timeout=5.0) == "Label: none\n"
    assert recorder.calls[0].kwargs["timeout"] == 5.0


# --- errors ----------------------------------------------------------------------------------


def test_nonzero_exit_raises_with_argv_and_stderr(recorder: Recorder) -> None:
    recorder.then(Reply(stderr="ERROR: cannot create subvolume: Permission denied\n", returncode=1))
    with pytest.raises(SnapshotError) as info:
        btrfs.create_subvolume(Path("/vol/ws"))
    assert not isinstance(info.value, SnapshotNoSpace)
    assert "btrfs subvolume create /vol/ws" in str(info.value)
    assert "Permission denied" in str(info.value)


@pytest.mark.parametrize(
    ("stderr", "code"),
    [("No space left on device", errno.ENOSPC), ("Disk quota exceeded", errno.EDQUOT)],
)
def test_out_of_space_stderr_raises_snapshot_no_space(
    recorder: Recorder, stderr: str, code: int
) -> None:
    recorder.then(Reply(stderr=f"ERROR: cannot snapshot '/vol/ws': {stderr}\n", returncode=1))
    with pytest.raises(SnapshotNoSpace) as info:
        btrfs.create_subvolume(Path("/vol/ws"))
    assert info.value.errno == code
    assert "btrfs subvolume create /vol/ws" in str(info.value)
    assert stderr in str(info.value)


def test_timeout_raises_snapshot_error(recorder: Recorder) -> None:
    recorder.then(subprocess.TimeoutExpired(["btrfs"], 120.0))
    with pytest.raises(SnapshotError, match="timed out") as info:
        btrfs.create_subvolume(Path("/vol/ws"))
    assert "btrfs subvolume create /vol/ws" in str(info.value)
    assert isinstance(info.value.__cause__, subprocess.TimeoutExpired)


def test_missing_btrfs_binary_raises_snapshot_error(recorder: Recorder) -> None:
    recorder.then(FileNotFoundError(errno.ENOENT, "No such file or directory", "btrfs"))
    with pytest.raises(SnapshotError) as info:
        btrfs.create_subvolume(Path("/vol/ws"))
    assert info.value.errno == errno.ENOENT
    assert "btrfs subvolume create /vol/ws" in str(info.value)


@pytest.mark.parametrize(
    "action",
    [
        pytest.param(lambda: btrfs.create_subvolume(Path("ws")), id="create"),
        pytest.param(lambda: btrfs.create_subvolume(Path("--help")), id="option-like"),
        pytest.param(lambda: btrfs.create_subvolume("ws"), id="create-str"),  # type: ignore[arg-type]
        pytest.param(lambda: btrfs.snapshot(Path("ws"), Path("/v/s"), readonly=True), id="src"),
        pytest.param(lambda: btrfs.snapshot(Path("/v/ws"), Path("s"), readonly=True), id="dst"),
        pytest.param(lambda: btrfs.is_readonly(Path("ws")), id="property-get"),
        pytest.param(lambda: btrfs.set_readonly(Path("ws"), True), id="property-set"),
        pytest.param(lambda: btrfs.delete_subvolume(Path("../snap")), id="delete"),
        pytest.param(lambda: btrfs.subvolume_id(Path("ws")), id="rootid"),
        pytest.param(lambda: btrfs.is_subvolume(Path("ws")), id="is-subvolume"),
        pytest.param(lambda: btrfs.run("subvolume", "create", Path("ws")), id="run"),
    ],
)
def test_relative_paths_raise_value_error_before_any_subprocess(
    recorder: Recorder, action: Callable[[], object]
) -> None:
    with pytest.raises(ValueError, match="absolute"):
        action()
    assert recorder.calls == []


@pytest.mark.parametrize("make", [Path.mkdir, Path.touch])
def test_snapshot_never_targets_an_existing_path(
    recorder: Recorder, tmp_path: Path, make: Callable[[Path], None]
) -> None:
    # btrfs would put the snapshot INSIDE an existing directory instead of failing.
    make(tmp_path / "snap")
    with pytest.raises(SnapshotError, match="already exists") as info:
        btrfs.snapshot(tmp_path / "ws", tmp_path / "snap", readonly=True)
    assert info.value.errno == errno.EEXIST
    assert recorder.calls == []


def test_snapshot_never_targets_a_dangling_symlink(recorder: Recorder, tmp_path: Path) -> None:
    (tmp_path / "snap").symlink_to(tmp_path / "nowhere")
    with pytest.raises(SnapshotError, match="already exists"):
        btrfs.snapshot(tmp_path / "ws", tmp_path / "snap", readonly=False)
    assert recorder.calls == []


# --- output parsing --------------------------------------------------------------------------


@pytest.mark.parametrize(("output", "expected"), [("ro=true\n", True), ("ro=false\n", False)])
def test_is_readonly_parses_exact_output(recorder: Recorder, output: str, expected: bool) -> None:
    recorder.then(Reply(output))
    assert btrfs.is_readonly(Path("/vol/ws")) is expected


@pytest.mark.parametrize(
    "output",
    [
        "",
        "\n",
        "ro=true",
        "ro=false",
        "ro=TRUE\n",
        "ro=1\n",
        " ro=true\n",
        "ro=true \n",
        "ro=true\r\n",
        "ro=true\nro=false\n",
        "readonly=true\n",
    ],
)
def test_is_readonly_rejects_anything_else(recorder: Recorder, output: str) -> None:
    recorder.then(Reply(output))
    with pytest.raises(SnapshotError, match="unexpected output"):
        btrfs.is_readonly(Path("/vol/ws"))


@pytest.mark.parametrize(("output", "expected"), [("257\n", 257), ("5\n", 5)])
def test_subvolume_id_parses_an_integer(recorder: Recorder, output: str, expected: int) -> None:
    recorder.then(Reply(output))
    assert btrfs.subvolume_id(Path("/vol/ws")) == expected


@pytest.mark.parametrize(
    "output",
    [
        "",
        "\n",
        "257",
        "abc\n",
        "-5\n",
        "+5\n",
        "0\n",
        "007\n",
        "1_000\n",
        " 257\n",
        "257 \n",
        "257\n258\n",
        "２５７\n",  # fullwidth digits
        "0x101\n",
        "257.0\n",
    ],
)
def test_subvolume_id_rejects_anything_that_is_not_an_integer(
    recorder: Recorder, output: str
) -> None:
    recorder.then(Reply(output))
    with pytest.raises(SnapshotError, match="unexpected output"):
        btrfs.subvolume_id(Path("/vol/ws"))


# --- delete_subvolume ------------------------------------------------------------------------


@pytest.fixture
def snap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """``tmp_path/snap``, which lstat reports as a subvolume root. Nothing is created."""
    target = tmp_path / "snap"
    fake_lstat(monkeypatch, target, SUBVOLUME_ROOT)
    return target


def gone_after_delete(recorder: Recorder) -> Callable[[], os.stat_result | OSError]:
    """lstat results for a subvolume root that disappears once ``subvolume delete`` ran."""

    def result() -> os.stat_result | OSError:
        if any(argv[1:3] == ["subvolume", "delete"] for argv in recorder.argvs):
            return FileNotFoundError(errno.ENOENT, "No such file or directory")
        return SUBVOLUME_ROOT

    return result


def count_syncs(monkeypatch: pytest.MonkeyPatch) -> list[None]:
    """Replaces os.sync; the returned list grows by one per call."""
    calls: list[None] = []
    monkeypatch.setattr(os, "sync", lambda: calls.append(None))
    return calls


def test_delete_readonly_target_order_is_get_then_set_false_then_delete(
    recorder: Recorder, snap: Path
) -> None:
    recorder.then(RO_TRUE, OK, OK)
    btrfs.delete_subvolume(snap)
    assert recorder.argvs == [
        get_ro(snap.parent, "snap"),
        set_ro(snap.parent, "snap", "false"),
        delete(snap.parent, "snap"),
    ]


@pytest.mark.parametrize("commit", [False, True])
def test_successful_delete_never_calls_os_sync(
    recorder: Recorder, snap: Path, monkeypatch: pytest.MonkeyPatch, commit: bool
) -> None:
    syncs = count_syncs(monkeypatch)
    recorder.then(RO_TRUE, OK, OK)
    btrfs.delete_subvolume(snap, commit=commit)
    assert syncs == []


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: p.mkdir(), id="plain-directory"),
        pytest.param(lambda p: p.touch(), id="file"),
        pytest.param(lambda p: None, id="missing"),
        pytest.param(lambda p: p.symlink_to(p.parent / "real-dir"), id="symlink-to-directory"),
        pytest.param(lambda p: p.symlink_to(p.parent / "nowhere"), id="dangling-symlink"),
    ],
)
def test_delete_refuses_anything_but_a_subvolume_root_before_any_subprocess(
    recorder: Recorder, tmp_path: Path, make: Callable[[Path], None]
) -> None:
    (tmp_path / "real-dir").mkdir()
    make(tmp_path / "snap")
    with pytest.raises(SnapshotError, match="not a subvolume root"):
        btrfs.delete_subvolume(tmp_path / "snap", commit=True)
    assert recorder.calls == []
    assert (tmp_path / "real-dir").is_dir()


def test_delete_refuses_a_symlink_to_a_subvolume_root(
    recorder: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # btrfs would call realpath() and delete the target: here, the live workspace.
    fake_lstat(monkeypatch, tmp_path / "workspace", SUBVOLUME_ROOT)
    (tmp_path / "workspace").mkdir()
    (tmp_path / ".trash-x").symlink_to(tmp_path / "workspace")
    with pytest.raises(SnapshotError, match="not a subvolume root"):
        btrfs.delete_subvolume(tmp_path / ".trash-x")
    assert recorder.calls == []


@pytest.mark.parametrize(
    "failure",
    [NOT_EMPTY, subprocess.TimeoutExpired(["btrfs"], 120.0)],
    ids=["exit-code", "timeout"],
)
def test_failed_delete_restores_ro_and_reraises_the_original_error(
    recorder: Recorder, snap: Path, failure: Reply | BaseException
) -> None:
    recorder.then(RO_TRUE, OK, failure, OK)
    with pytest.raises(SnapshotError) as info:
        btrfs.delete_subvolume(snap)
    assert "subvolume delete" in str(info.value)
    assert getattr(info.value, "__notes__", []) == []
    assert recorder.argvs == [
        get_ro(snap.parent, "snap"),
        set_ro(snap.parent, "snap", "false"),
        delete(snap.parent, "snap"),
        set_ro(snap.parent, "snap", "true"),
    ]


def test_failed_delete_keeps_the_original_error_when_restoring_ro_fails_too(
    recorder: Recorder, snap: Path
) -> None:
    recorder.then(RO_TRUE, OK, NOT_EMPTY, DENIED)
    with pytest.raises(SnapshotError, match="Directory not empty") as info:
        btrfs.delete_subvolume(snap)
    (note,) = info.value.__notes__
    assert "restoring ro=true" in note
    assert "Permission denied" in note


@pytest.mark.parametrize("commit", [False, True])
def test_failed_delete_of_a_path_that_is_gone_counts_as_done(
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    commit: bool,
) -> None:
    target = tmp_path / "snap"
    fake_lstat(monkeypatch, target, gone_after_delete(recorder))
    syncs = count_syncs(monkeypatch)
    recorder.then(RO_TRUE, OK, NOT_EMPTY)
    with caplog.at_level(logging.WARNING, logger=btrfs.__name__):
        btrfs.delete_subvolume(target, commit=commit)
    commit_flag = ["--commit-after"] if commit else []
    assert recorder.argvs == [
        get_ro(tmp_path, "snap"),
        set_ro(tmp_path, "snap", "false"),
        ["btrfs", "subvolume", "delete", *commit_flag, str(target)],
    ]
    assert str(target) in caplog.text
    assert len(syncs) == (1 if commit else 0)  # with commit, the commit may be what failed


def test_commit_wait_failure_after_the_delete_falls_back_to_os_sync(
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # btrfs-progs removes the entry, then exits 1 if waiting for the commit fails.
    target = tmp_path / "snap"
    fake_lstat(monkeypatch, target, gone_after_delete(recorder))
    syncs = count_syncs(monkeypatch)
    recorder.then(RO_TRUE, OK, COMMIT_WAIT_FAILED)
    with caplog.at_level(logging.WARNING, logger=btrfs.__name__):
        btrfs.delete_subvolume(target, commit=True)
    assert len(syncs) == 1
    assert "final sync" in caplog.text


def test_failed_delete_when_existence_cannot_be_checked_reraises_with_a_note(
    recorder: Recorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "snap"
    denied = PermissionError(errno.EACCES, "Permission denied")
    lstat_results = iter([SUBVOLUME_ROOT, SUBVOLUME_ROOT, SUBVOLUME_ROOT, denied])
    fake_lstat(monkeypatch, target, lambda: next(lstat_results, SUBVOLUME_ROOT))
    recorder.then(RO_TRUE, OK, NOT_EMPTY, OK)
    with pytest.raises(SnapshotError, match="Directory not empty") as info:
        btrfs.delete_subvolume(target)
    (note,) = info.value.__notes__
    assert "could not check" in note
    assert recorder.argvs[-1] == set_ro(tmp_path, "snap", "true")


def test_delete_never_flips_a_writable_target(recorder: Recorder, snap: Path) -> None:
    recorder.then(RO_FALSE, OK)
    btrfs.delete_subvolume(snap)
    assert recorder.argvs == [get_ro(snap.parent, "snap"), delete(snap.parent, "snap")]


def test_failed_delete_of_a_writable_target_does_not_set_ro(recorder: Recorder, snap: Path) -> None:
    recorder.then(RO_FALSE, NOT_EMPTY)
    with pytest.raises(SnapshotError, match="Directory not empty"):
        btrfs.delete_subvolume(snap)
    assert recorder.argvs == [get_ro(snap.parent, "snap"), delete(snap.parent, "snap")]


def test_delete_stops_when_clearing_ro_fails(recorder: Recorder, snap: Path) -> None:
    recorder.then(RO_TRUE, DENIED)
    with pytest.raises(SnapshotError, match="Permission denied"):
        btrfs.delete_subvolume(snap)
    assert recorder.argvs == [get_ro(snap.parent, "snap"), set_ro(snap.parent, "snap", "false")]


# --- symlinks --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    [
        pytest.param(btrfs.is_readonly, id="property-get"),
        pytest.param(lambda p: btrfs.set_readonly(p, True), id="property-set-true"),
        pytest.param(lambda p: btrfs.set_readonly(p, False), id="property-set-false"),
    ],
)
def test_ro_property_refuses_a_symlink_before_any_subprocess(
    recorder: Recorder, tmp_path: Path, action: Callable[[Path], object]
) -> None:
    (tmp_path / "workspace").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "workspace")
    with pytest.raises(SnapshotError, match="symlink") as info:
        action(tmp_path / "link")
    assert info.value.errno == errno.ELOOP
    assert recorder.calls == []


def test_ro_property_reports_a_path_it_cannot_stat(
    recorder: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_lstat(monkeypatch, tmp_path / "x", PermissionError(errno.EACCES, "Permission denied"))
    with pytest.raises(SnapshotError, match="cannot stat") as info:
        btrfs.set_readonly(tmp_path / "x", True)
    assert info.value.errno == errno.EACCES
    assert recorder.calls == []


# --- children_hold ---------------------------------------------------------------------------


def test_children_hold_passes_the_fd_only_inside_the_block(recorder: Recorder) -> None:
    btrfs.run("--version")
    with btrfs.children_hold(7):
        btrfs.run("--version")
    btrfs.run("--version")
    assert [call.kwargs["pass_fds"] for call in recorder.calls] == [(), (7,), ()]


def test_children_hold_reaches_every_child_of_a_delete(recorder: Recorder, snap: Path) -> None:
    recorder.then(RO_TRUE, OK, OK)
    with btrfs.children_hold(9):
        btrfs.delete_subvolume(snap)
    assert [call.kwargs["pass_fds"] for call in recorder.calls] == [(9,), (9,), (9,)]


def test_children_hold_is_released_when_the_block_raises(recorder: Recorder) -> None:
    with pytest.raises(RuntimeError), btrfs.children_hold(7):
        raise RuntimeError("boom")
    btrfs.run("--version")
    assert recorder.calls[0].kwargs["pass_fds"] == ()


# --- is_subvolume ----------------------------------------------------------------------------


def fake_lstat(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    result: os.stat_result | OSError | Callable[[], os.stat_result | OSError],
) -> None:
    """lstat of ``target`` returns or raises ``result`` (called first if it is a function).
    Any other path gets the real lstat."""
    real_lstat = os.lstat

    def lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path) != os.fspath(target):  # type: ignore[arg-type]
            return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]
        outcome = result() if callable(result) else result
        if isinstance(outcome, OSError):
            raise outcome
        return outcome

    monkeypatch.setattr(os, "lstat", lstat)


@pytest.mark.parametrize(
    ("mode", "ino", "expected"),
    [
        (stat.S_IFDIR | 0o755, 256, True),
        (stat.S_IFDIR | 0o755, 257, False),  # a plain directory
        (stat.S_IFDIR | 0o755, 2, False),  # the stub a nested subvolume leaves in a snapshot
        (stat.S_IFLNK | 0o777, 256, False),
        (stat.S_IFREG | 0o644, 256, False),
    ],
)
def test_is_subvolume_needs_a_directory_with_inode_256(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: int, ino: int, expected: bool
) -> None:
    fake_lstat(monkeypatch, tmp_path / "x", stat_result(mode, ino))
    assert btrfs.is_subvolume(tmp_path / "x") is expected


def test_is_subvolume_is_false_for_missing_paths_files_and_symlinks(tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    (tmp_path / "file").touch()
    (tmp_path / "link").symlink_to(tmp_path / "dir")
    assert btrfs.is_subvolume(tmp_path / "missing") is False
    assert btrfs.is_subvolume(tmp_path / "file" / "below-a-file") is False
    assert btrfs.is_subvolume(tmp_path / "file") is False
    assert btrfs.is_subvolume(tmp_path / "link") is False


def test_is_subvolume_reports_other_stat_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_lstat(monkeypatch, tmp_path / "x", PermissionError(errno.EACCES, "Permission denied"))
    with pytest.raises(SnapshotError) as info:
        btrfs.is_subvolume(tmp_path / "x")
    assert info.value.errno == errno.EACCES


# --- renameat2 -------------------------------------------------------------------------------


class FakeRenameat2:
    """Stands in for the libc function: records the C arguments and fails with ``code``."""

    def __init__(self, code: int = 0) -> None:
        self.code = code
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *args: object) -> int:
        self.calls.append(args)
        if self.code:
            ctypes.set_errno(self.code)
            return -1
        return 0


def use_fake_renameat2(monkeypatch: pytest.MonkeyPatch, code: int = 0) -> FakeRenameat2:
    fake = FakeRenameat2(code)
    monkeypatch.setattr(btrfs, "_libc_renameat2", lambda: fake)
    return fake


@pytest.fixture
def fresh_libc_cache() -> Iterator[None]:
    btrfs._libc_renameat2.cache_clear()
    yield
    btrfs._libc_renameat2.cache_clear()


@pytest.mark.skipif(sys.platform != "darwin", reason="only macOS lacks renameat2")
def test_renameat2_is_unavailable_on_macos(fresh_libc_cache: None) -> None:
    with pytest.raises(SnapshotError, match="renameat2 unavailable"):
        btrfs.renameat2(-1, "a", "b", btrfs.RENAME_NOREPLACE)


def test_renameat2_missing_symbol_raises_snapshot_error(
    monkeypatch: pytest.MonkeyPatch, fresh_libc_cache: None
) -> None:
    class LibcWithoutRenameat2:
        def __init__(self, name: object, use_errno: bool = False) -> None:
            pass

        def __getattr__(self, name: str) -> object:
            raise AttributeError(name)

    monkeypatch.setattr(ctypes, "CDLL", LibcWithoutRenameat2)
    with pytest.raises(SnapshotError, match="renameat2 unavailable"):
        btrfs.renameat2(-1, "a", "b", btrfs.RENAME_NOREPLACE)


def test_renameat2_passes_both_names_relative_to_the_same_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = use_fake_renameat2(monkeypatch)
    btrfs.renameat2(5, "workspace.restore", "workspace", btrfs.RENAME_EXCHANGE)
    btrfs.renameat2(5, "año", "snapshots/.incoming-x", btrfs.RENAME_NOREPLACE)
    assert fake.calls == [
        (5, b"workspace.restore", 5, b"workspace", 2),
        (5, os.fsencode("año"), 5, b"snapshots/.incoming-x", 1),
    ]


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_renameat2_out_of_space_raises_snapshot_no_space(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    use_fake_renameat2(monkeypatch, code)
    with pytest.raises(SnapshotNoSpace) as info:
        btrfs.renameat2(5, "a", "b", btrfs.RENAME_NOREPLACE)
    assert info.value.errno == code


def test_renameat2_other_errors_carry_the_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_renameat2(monkeypatch, errno.EEXIST)
    with pytest.raises(SnapshotError) as info:
        btrfs.renameat2(5, "a", "b", btrfs.RENAME_NOREPLACE)
    assert not isinstance(info.value, SnapshotNoSpace)
    assert info.value.errno == errno.EEXIST
    assert os.strerror(errno.EEXIST) in str(info.value)


@pytest.mark.parametrize(("old", "new"), [("a\0b", "c"), ("a", "c\0d")])
def test_renameat2_rejects_embedded_nul(
    monkeypatch: pytest.MonkeyPatch, old: str, new: str
) -> None:
    fake = use_fake_renameat2(monkeypatch)
    with pytest.raises(ValueError, match="null byte"):
        btrfs.renameat2(5, old, new, btrfs.RENAME_NOREPLACE)
    assert fake.calls == []


@pytest.mark.parametrize(
    "name",
    [
        "/abs",
        "/",
        "",
        ".",
        "..",
        "../x",
        "snapshots/../../x",
        "snapshots/..",
        "./workspace",
        "snapshots/./x",
        "snapshots//x",
        "snapshots/",
    ],
)
@pytest.mark.parametrize("position", ["old", "new"])
def test_renameat2_rejects_names_that_leave_or_bypass_the_dir_fd(
    monkeypatch: pytest.MonkeyPatch, name: str, position: str
) -> None:
    fake = use_fake_renameat2(monkeypatch)
    old, new = (name, "b") if position == "old" else ("a", name)
    with pytest.raises(ValueError, match="must stay below the directory fd"):
        btrfs.renameat2(5, old, new, btrfs.RENAME_NOREPLACE)
    assert fake.calls == []


@pytest.fixture
def dir_fd(tmp_path: Path) -> Iterator[int]:
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    yield fd
    os.close(fd)


def make_dir_with_marker(parent: Path, name: str) -> None:
    (parent / name).mkdir()
    (parent / name / f"marker-{name}").touch()


@linux_only
def test_renameat2_exchanges_two_directories(tmp_path: Path, dir_fd: int) -> None:
    make_dir_with_marker(tmp_path, "a")
    make_dir_with_marker(tmp_path, "b")
    btrfs.renameat2(dir_fd, "a", "b", btrfs.RENAME_EXCHANGE)
    assert [p.name for p in (tmp_path / "a").iterdir()] == ["marker-b"]
    assert [p.name for p in (tmp_path / "b").iterdir()] == ["marker-a"]


@linux_only
def test_renameat2_noreplace_refuses_an_existing_name(tmp_path: Path, dir_fd: int) -> None:
    make_dir_with_marker(tmp_path, "a")
    make_dir_with_marker(tmp_path, "b")
    with pytest.raises(SnapshotError) as info:
        btrfs.renameat2(dir_fd, "a", "b", btrfs.RENAME_NOREPLACE)
    assert info.value.errno == errno.EEXIST
    assert (tmp_path / "a" / "marker-a").exists()
    assert (tmp_path / "b" / "marker-b").exists()


@linux_only
def test_renameat2_noreplace_moves_to_a_new_name(tmp_path: Path, dir_fd: int) -> None:
    make_dir_with_marker(tmp_path, "a")
    (tmp_path / "sub").mkdir()
    btrfs.renameat2(dir_fd, "a", "sub/.incoming-a", btrfs.RENAME_NOREPLACE)
    assert not (tmp_path / "a").exists()
    assert (tmp_path / "sub" / ".incoming-a" / "marker-a").exists()
