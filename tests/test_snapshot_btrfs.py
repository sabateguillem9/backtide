"""Unit tests for the btrfs wrapper. No btrfs needed: subprocess.run is replaced by a recorder."""

import ctypes
import errno
import fcntl
import logging
import os
import stat
import subprocess
import sys
import uuid
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from vigia.snapshots import SnapshotError, SnapshotNoSpace, btrfs

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="needs glibc renameat2")
MIB = 1024**2


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
        pytest.param(
            lambda d: btrfs.set_qgroup_limit(d / "subvol", 256 * MIB),
            [],
            [("qgroup", "limit", "268435456", "@subvol")],
            id="qgroup-limit",
        ),
        pytest.param(
            lambda d: btrfs.set_qgroup_limit(d / "subvol", None),
            [],
            [("qgroup", "limit", "none", "@subvol")],
            id="qgroup-limit-none",
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


def test_run_starts_btrfs_in_a_session_of_its_own(recorder: Recorder) -> None:
    """A Ctrl-C in the terminal must reach Vigía only, not a `btrfs subvolume snapshot` in the
    middle of its work. A timeout still kills the child: subprocess.run kills its pid."""
    btrfs.run("filesystem", "sync", Path("/vol"))
    assert recorder.calls[0].kwargs["start_new_session"] is True


def test_a_real_btrfs_child_is_outside_our_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "bin" / "btrfs"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nps -o pgid= -p $$\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}:{os.environ['PATH']}")
    child_group = int(btrfs.run("version").strip())
    assert child_group != os.getpgrp()


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
        pytest.param(lambda: btrfs.qgroup_limit_args(Path("ws"), MIB), id="qgroup-limit-args"),
        pytest.param(lambda: btrfs.set_qgroup_limit(Path("ws"), MIB), id="qgroup-limit"),
        pytest.param(lambda: btrfs.set_qgroup_limit(Path("ws"), None), id="qgroup-limit-none"),
        pytest.param(lambda: btrfs.fsid(Path("ws")), id="fsid"),
        pytest.param(lambda: btrfs.quota_mode(Path("ws")), id="quota-mode"),
        pytest.param(lambda: btrfs.qgroup_usage(Path("ws")), id="qgroup-usage"),
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


# --- quotas: qgroup limit --------------------------------------------------------------------

U64_MAX = 2**64 - 1  # what `btrfs qgroup limit none` sends: never a valid limit


@pytest.mark.parametrize(
    ("limit", "token"),
    [
        (1, "1"),
        (256 * MIB, "268435456"),
        (U64_MAX - 1, "18446744073709551614"),
        (None, "none"),
    ],
)
def test_qgroup_limit_args_is_the_two_argument_form(limit: int | None, token: str) -> None:
    assert btrfs.qgroup_limit_args(Path("/vol/ws"), limit) == ("qgroup", "limit", token, "/vol/ws")


def test_qgroup_limit_args_never_touches_the_filesystem(recorder: Recorder) -> None:
    # Pure: the path does not exist, and nothing is run or checked.
    assert btrfs.qgroup_limit_args(Path("/nowhere/ws"), MIB)[-1] == "/nowhere/ws"
    assert recorder.calls == []


@pytest.mark.parametrize(
    "limit",
    [True, False, 0, -1, -MIB, 1.0, 1.5, "100", "none", b"1", U64_MAX, U64_MAX + 1],
    ids=repr,
)
def test_qgroup_limit_args_rejects_anything_but_a_positive_int(limit: object) -> None:
    with pytest.raises(ValueError, match="limit"):
        btrfs.qgroup_limit_args(Path("/vol/ws"), limit)  # type: ignore[arg-type]


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, U64_MAX])
def test_set_qgroup_limit_rejects_a_bad_limit_before_any_subprocess(
    recorder: Recorder, snap: Path, limit: object
) -> None:
    with pytest.raises(ValueError, match="limit"):
        btrfs.set_qgroup_limit(snap, limit)  # type: ignore[arg-type]
    assert recorder.calls == []


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
@pytest.mark.parametrize("limit", [MIB, None])
def test_set_qgroup_limit_refuses_anything_but_a_subvolume_root_before_any_subprocess(
    recorder: Recorder, tmp_path: Path, make: Callable[[Path], None], limit: int | None
) -> None:
    (tmp_path / "real-dir").mkdir()
    make(tmp_path / "ws")
    with pytest.raises(SnapshotError, match="refusing"):
        btrfs.set_qgroup_limit(tmp_path / "ws", limit)
    assert recorder.calls == []


def test_set_qgroup_limit_refuses_a_symlink_to_a_subvolume_root(
    recorder: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # btrfs would follow it and limit (or uncap) the target instead.
    fake_lstat(monkeypatch, tmp_path / "workspace", SUBVOLUME_ROOT)
    (tmp_path / "workspace").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "workspace")
    with pytest.raises(SnapshotError, match="symlink") as info:
        btrfs.set_qgroup_limit(tmp_path / "link", None)
    assert info.value.errno == errno.ELOOP
    assert recorder.calls == []


def test_set_qgroup_limit_without_cap_sys_admin_is_a_snapshot_error(
    recorder: Recorder, snap: Path
) -> None:
    recorder.then(
        Reply(
            stderr="ERROR: unable to limit requested quota group: Operation not permitted\n",
            returncode=1,
        )
    )
    with pytest.raises(SnapshotError, match="Operation not permitted") as info:
        btrfs.set_qgroup_limit(snap, MIB)
    assert not isinstance(info.value, SnapshotNoSpace)
    assert f"btrfs qgroup limit 1048576 {snap}" in str(info.value)


def test_set_qgroup_limit_with_quotas_off_is_a_snapshot_error(
    recorder: Recorder, snap: Path
) -> None:
    recorder.then(
        Reply(
            stderr="ERROR: unable to limit requested quota group: quota not enabled\n", returncode=1
        )
    )
    with pytest.raises(SnapshotError, match="quota not enabled") as info:
        btrfs.set_qgroup_limit(snap, None)
    assert not isinstance(info.value, SnapshotNoSpace)


@pytest.mark.parametrize(
    ("stderr", "code"),
    [("No space left on device", errno.ENOSPC), ("Disk quota exceeded", errno.EDQUOT)],
)
def test_set_qgroup_limit_out_of_space_is_snapshot_no_space(
    recorder: Recorder, snap: Path, stderr: str, code: int
) -> None:
    recorder.then(
        Reply(stderr=f"ERROR: unable to limit requested quota group: {stderr}\n", returncode=1)
    )
    with pytest.raises(SnapshotNoSpace) as info:
        btrfs.set_qgroup_limit(snap, MIB)
    assert info.value.errno == code


def test_set_qgroup_limit_follows_the_run_conventions(recorder: Recorder, snap: Path) -> None:
    with btrfs.children_hold(7):
        btrfs.set_qgroup_limit(snap, MIB)
    (call,) = recorder.calls
    assert call.kwargs["timeout"] == btrfs.DEFAULT_TIMEOUT
    assert call.kwargs["pass_fds"] == (7,)
    env = call.kwargs["env"]
    assert isinstance(env, dict)
    assert env["LC_ALL"] == "C"


# --- quotas: fsid ----------------------------------------------------------------------------

FSID = "6f8c00f2-c2dd-4f3f-a7f1-89ab816842a5"


class FakeIoctl:
    """Stands in for fcntl.ioctl: answers BTRFS_IOC_FS_INFO with FSID at bytes 16..32, or
    raises ``error``. Records the fd, request and buffer size of every call."""

    def __init__(self, error: OSError | None = None) -> None:
        self.error = error
        self.calls: list[tuple[int, int, int]] = []

    def __call__(self, fd: int, request: int, arg: bytearray, mutate: bool = True) -> int:
        self.calls.append((fd, request, len(arg)))
        if self.error is not None:
            raise self.error
        arg[16:32] = uuid.UUID(FSID).bytes
        arg[0:8] = (1).to_bytes(8, "little")  # max_id: anything outside the fsid is ignored
        return 0


def use_fake_ioctl(monkeypatch: pytest.MonkeyPatch, error: OSError | None = None) -> FakeIoctl:
    fake = FakeIoctl(error)
    monkeypatch.setattr(fcntl, "ioctl", fake)
    return fake


def test_fsid_reads_the_uuid_from_fs_info(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = use_fake_ioctl(monkeypatch)
    assert btrfs.fsid(tmp_path) == FSID
    ((fd, request, size),) = fake.calls
    assert request == btrfs.BTRFS_IOC_FS_INFO == 0x8400941F
    assert size == 1024  # sizeof(struct btrfs_ioctl_fs_info_args)
    with pytest.raises(OSError) as closed:
        os.fstat(fd)
    assert closed.value.errno == errno.EBADF


def test_fsid_failure_is_a_snapshot_error_and_closes_the_fd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = use_fake_ioctl(monkeypatch, OSError(errno.ENOTTY, "Inappropriate ioctl for device"))
    with pytest.raises(SnapshotError, match="FS_INFO") as info:
        btrfs.fsid(tmp_path)
    assert info.value.errno == errno.ENOTTY
    ((fd, _, _),) = fake.calls
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: p.symlink_to(p.parent / "real-dir"), id="symlink"),
        pytest.param(lambda p: None, id="missing"),
        pytest.param(lambda p: p.touch(), id="file"),
    ],
)
def test_fsid_refuses_symlinks_and_anything_but_a_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, make: Callable[[Path], None]
) -> None:
    fake = use_fake_ioctl(monkeypatch)
    (tmp_path / "real-dir").mkdir()
    make(tmp_path / "x")
    with pytest.raises(SnapshotError):
        btrfs.fsid(tmp_path / "x")
    assert fake.calls == []


# --- quotas: sysfs readers -------------------------------------------------------------------

QGROUP_FILES = ("referenced", "exclusive", "limit_flags", "max_referenced", "max_exclusive")


@pytest.fixture
def sysfs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake /sys/fs/btrfs with this filesystem's directory; fsid() returns FSID."""
    root = tmp_path / "sys-fs-btrfs"
    (root / FSID).mkdir(parents=True)
    monkeypatch.setattr(btrfs, "fsid", lambda path: FSID)
    return root


def write_mode(sysfs: Path, text: str) -> None:
    (sysfs / FSID / "qgroups").mkdir(exist_ok=True)
    (sysfs / FSID / "qgroups" / "mode").write_text(text)


def write_qgroup(sysfs: Path, name: str, **values: str) -> Path:
    """``qgroups/<name>/`` with every file: ``values`` overrides the defaults (decimal + \\n)."""
    directory = sysfs / FSID / "qgroups" / name
    directory.mkdir(parents=True)
    defaults = dict.fromkeys(QGROUP_FILES, "0\n")
    for file, text in (defaults | values).items():
        (directory / file).write_text(text)
    return directory


def test_sysfs_root_is_the_kernel_one_by_default() -> None:
    assert Path("/sys/fs/btrfs") == btrfs.SYSFS_BTRFS


@pytest.mark.parametrize(("text", "mode"), [("squota\n", "squota"), ("qgroup\n", "qgroup")])
def test_quota_mode_reads_sysfs(sysfs: Path, tmp_path: Path, text: str, mode: str) -> None:
    write_mode(sysfs, text)
    assert btrfs.quota_mode(tmp_path, sysfs=sysfs) == mode


def test_quota_mode_is_none_when_quotas_are_off(sysfs: Path, tmp_path: Path) -> None:
    # The kernel removes qgroups/ when quotas are disabled.
    assert btrfs.quota_mode(tmp_path, sysfs=sysfs) is None


def test_quota_mode_without_the_filesystem_directory_is_an_error(
    sysfs: Path, tmp_path: Path
) -> None:
    (sysfs / FSID).rmdir()
    with pytest.raises(SnapshotError, match=FSID):
        btrfs.quota_mode(tmp_path, sysfs=sysfs)


def test_quota_mode_without_the_mode_file_is_an_error(sysfs: Path, tmp_path: Path) -> None:
    (sysfs / FSID / "qgroups").mkdir()
    with pytest.raises(SnapshotError, match="mode"):
        btrfs.quota_mode(tmp_path, sysfs=sysfs)


@pytest.mark.parametrize(
    "text", ["", "\n", "squota", "SQUOTA\n", " squota\n", "squota\n\n", "disabled\n", "simple\n"]
)
def test_quota_mode_rejects_anything_else(sysfs: Path, tmp_path: Path, text: str) -> None:
    write_mode(sysfs, text)
    with pytest.raises(SnapshotError, match="unexpected"):
        btrfs.quota_mode(tmp_path, sysfs=sysfs)


@pytest.fixture
def subvol(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """``tmp_path/ws``, which lstat reports as a subvolume root. Nothing is created."""
    target = tmp_path / "ws"
    fake_lstat(monkeypatch, target, SUBVOLUME_ROOT)
    return target


def test_qgroup_usage_reads_the_level_0_qgroup_of_the_subvolume(
    recorder: Recorder, sysfs: Path, subvol: Path
) -> None:
    write_qgroup(
        sysfs,
        "0_258",
        referenced="16384\n",
        exclusive="16384\n",
        limit_flags="1\n",
        max_referenced="268435456\n",
    )
    write_qgroup(sysfs, "0_257", referenced="999\n")  # another subvolume's qgroup
    recorder.then(Reply("258\n"))
    usage = btrfs.qgroup_usage(subvol, sysfs=sysfs)
    assert usage == btrfs.QgroupUsage(
        referenced=16384,
        exclusive=16384,
        limit_flags=1,
        max_referenced=268435456,
        max_exclusive=0,
    )
    assert recorder.argvs == [["btrfs", "inspect-internal", "rootid", str(subvol)]]


def test_qgroup_usage_accepts_the_largest_u64(
    recorder: Recorder, sysfs: Path, subvol: Path
) -> None:
    write_qgroup(sysfs, "0_258", max_exclusive=f"{U64_MAX}\n")
    recorder.then(Reply("258\n"))
    assert btrfs.qgroup_usage(subvol, sysfs=sysfs).max_exclusive == U64_MAX


def test_qgroup_usage_without_the_qgroup_directory_is_an_error(
    recorder: Recorder, sysfs: Path, subvol: Path
) -> None:
    write_mode(sysfs, "squota\n")
    recorder.then(Reply("258\n"))
    with pytest.raises(SnapshotError, match="0_258"):
        btrfs.qgroup_usage(subvol, sysfs=sysfs)


@pytest.mark.parametrize("missing", QGROUP_FILES)
def test_qgroup_usage_with_a_file_missing_is_an_error(
    recorder: Recorder, sysfs: Path, subvol: Path, missing: str
) -> None:
    (write_qgroup(sysfs, "0_258") / missing).unlink()
    recorder.then(Reply("258\n"))
    with pytest.raises(SnapshotError, match=missing):
        btrfs.qgroup_usage(subvol, sysfs=sysfs)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n",
        "1",
        "-1\n",
        "+1\n",
        "01\n",
        "1 \n",
        " 1\n",
        "1\n\n",
        "1\r\n",
        "0x10\n",
        "1.0\n",
        "1_000\n",
        "１\n",  # fullwidth digit
        f"{U64_MAX + 1}\n",
    ],
)
@pytest.mark.parametrize("file", QGROUP_FILES)
def test_qgroup_usage_rejects_anything_but_a_decimal_u64(
    recorder: Recorder, sysfs: Path, subvol: Path, file: str, text: str
) -> None:
    write_qgroup(sysfs, "0_258", **{file: text})
    recorder.then(Reply("258\n"))
    with pytest.raises(SnapshotError, match="unexpected"):
        btrfs.qgroup_usage(subvol, sysfs=sysfs)


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: p.mkdir(), id="plain-directory"),
        pytest.param(lambda p: None, id="missing"),
        pytest.param(lambda p: p.symlink_to(p.parent / "real-dir"), id="symlink"),
    ],
)
def test_qgroup_usage_refuses_anything_but_a_subvolume_root(
    recorder: Recorder, sysfs: Path, tmp_path: Path, make: Callable[[Path], None]
) -> None:
    # A plain directory would report the qgroup of the subvolume that contains it.
    (tmp_path / "real-dir").mkdir()
    make(tmp_path / "x")
    with pytest.raises(SnapshotError, match="not a subvolume root"):
        btrfs.qgroup_usage(tmp_path / "x", sysfs=sysfs)
    assert recorder.calls == []


@pytest.mark.parametrize(
    ("flags", "limit", "exclusive_limit"),
    [
        (0, None, None),
        (btrfs.QGROUP_LIMIT_MAX_RFER, 300, None),
        (btrfs.QGROUP_LIMIT_MAX_EXCL, None, 700),
        (btrfs.QGROUP_LIMIT_MAX_RFER | btrfs.QGROUP_LIMIT_MAX_EXCL, 300, 700),
        (4 | 8, None, None),  # the compression flags (-c) are no limit
    ],
)
def test_qgroup_usage_limits_only_count_with_their_flag(
    flags: int, limit: int | None, exclusive_limit: int | None
) -> None:
    usage = btrfs.QgroupUsage(
        referenced=0, exclusive=0, limit_flags=flags, max_referenced=300, max_exclusive=700
    )
    assert usage.limit == limit
    assert usage.exclusive_limit == exclusive_limit


def test_qgroup_limit_flags_match_the_kernel() -> None:
    assert (btrfs.QGROUP_LIMIT_MAX_RFER, btrfs.QGROUP_LIMIT_MAX_EXCL) == (1, 2)


# --- GET_SUBVOL_INFO and sync ------------------------------------------------------------------

SUBVOL_UUID = uuid.UUID("11111111-2222-3333-4444-555555555555")
PARENT_UUID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def subvol_info_buffer(
    *,
    treeid: int = 258,
    name: bytes = b"workspace",
    generation: int = 700,
    flags: int = 0,
    own_uuid: uuid.UUID = SUBVOL_UUID,
    parent_uuid: uuid.UUID | None = PARENT_UUID,
    ctransid: int = 650,
    otransid: int = 123,
) -> bytes:
    """A 504-byte btrfs_ioctl_get_subvol_info_args, packed by hand at the documented offsets."""
    buffer = bytearray(504)
    buffer[0:8] = treeid.to_bytes(8, "little")
    buffer[8 : 8 + len(name)] = name
    buffer[264:272] = (5).to_bytes(8, "little")  # parent_id: not read
    buffer[280:288] = generation.to_bytes(8, "little")
    buffer[288:296] = flags.to_bytes(8, "little")
    buffer[296:312] = own_uuid.bytes
    buffer[312:328] = (parent_uuid or uuid.UUID(int=0)).bytes
    buffer[328:344] = b"\xee" * 16  # received_uuid: not read
    buffer[344:352] = ctransid.to_bytes(8, "little")
    buffer[352:360] = otransid.to_bytes(8, "little")
    return bytes(buffer)


class FakeSubvolIoctl:
    """Stands in for fcntl.ioctl: fills the buffer with ``answer``, or raises ``error``."""

    def __init__(self, answer: bytes | None = None, error: OSError | None = None) -> None:
        self.answer = subvol_info_buffer() if answer is None else answer
        self.error = error
        self.calls: list[tuple[int, int, int]] = []

    def __call__(self, fd: int, request: int, arg: bytearray, mutate: bool = True) -> int:
        self.calls.append((fd, request, len(arg)))
        if self.error is not None:
            raise self.error
        arg[:] = self.answer
        return 0


@pytest.fixture
def subvol_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A real directory that lstat reports as a subvolume root (so os.open works on it)."""
    target = tmp_path / "ws"
    target.mkdir()
    fake_lstat(monkeypatch, target, SUBVOLUME_ROOT)
    return target


def test_subvolume_info_decodes_the_fields_at_their_offsets(
    monkeypatch: pytest.MonkeyPatch, subvol_dir: Path
) -> None:
    fake = FakeSubvolIoctl()
    monkeypatch.setattr(fcntl, "ioctl", fake)
    info = btrfs.subvolume_info(subvol_dir)
    assert info == btrfs.SubvolumeInfo(
        treeid=258,
        name="workspace",
        generation=700,
        flags=0,
        uuid=SUBVOL_UUID,
        parent_uuid=PARENT_UUID,
        ctransid=650,
        otransid=123,
    )
    assert not info.readonly
    ((fd, request, size),) = fake.calls
    assert request == btrfs.BTRFS_IOC_GET_SUBVOL_INFO == 0x81F8943C
    assert size == 504
    with pytest.raises(OSError) as closed:
        os.fstat(fd)
    assert closed.value.errno == errno.EBADF


def test_subvolume_info_without_a_parent_is_none_and_flags_say_read_only(
    monkeypatch: pytest.MonkeyPatch, subvol_dir: Path
) -> None:
    answer = subvol_info_buffer(parent_uuid=None, flags=1 | 4)
    monkeypatch.setattr(fcntl, "ioctl", FakeSubvolIoctl(answer))
    info = btrfs.subvolume_info(subvol_dir)
    assert info.parent_uuid is None
    assert info.readonly


def test_subvolume_info_reads_full_width_counters() -> None:
    big = 2**64 - 1
    info = btrfs.parse_subvolume_info(subvol_info_buffer(ctransid=big, generation=2**40))
    assert info.ctransid == big
    assert info.generation == 2**40


def test_subvolume_info_name_stops_at_the_nul_and_survives_bad_utf8() -> None:
    info = btrfs.parse_subvolume_info(subvol_info_buffer(name=b"snap\x00junk\xff"))
    assert info.name == "snap"
    assert btrfs.parse_subvolume_info(subvol_info_buffer(name=b"a\xffb")).name == "a�b"


@pytest.mark.parametrize("size", [0, 503, 505, 1024])
def test_parse_subvolume_info_rejects_a_wrong_size(size: int) -> None:
    with pytest.raises(SnapshotError, match="expected 504"):
        btrfs.parse_subvolume_info(b"\0" * size)


def test_subvolume_info_failure_is_a_snapshot_error_and_closes_the_fd(
    monkeypatch: pytest.MonkeyPatch, subvol_dir: Path
) -> None:
    fake = FakeSubvolIoctl(error=OSError(errno.ENOTTY, "Inappropriate ioctl for device"))
    monkeypatch.setattr(fcntl, "ioctl", fake)
    with pytest.raises(SnapshotError, match="GET_SUBVOL_INFO") as raised:
        btrfs.subvolume_info(subvol_dir)
    assert raised.value.errno == errno.ENOTTY
    ((fd, _, _),) = fake.calls
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: p.symlink_to(p.parent / "real-dir"), id="symlink"),
        pytest.param(lambda p: None, id="missing"),
        pytest.param(lambda p: p.touch(), id="file"),
        pytest.param(lambda p: p.mkdir(), id="plain-directory"),
    ],
)
def test_subvolume_info_refuses_anything_but_a_subvolume_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, make: Callable[[Path], None]
) -> None:
    # A plain directory would make the ioctl answer for the subvolume that contains it.
    fake = FakeSubvolIoctl()
    monkeypatch.setattr(fcntl, "ioctl", fake)
    (tmp_path / "real-dir").mkdir()
    make(tmp_path / "x")
    with pytest.raises(SnapshotError, match="not a subvolume root"):
        btrfs.subvolume_info(tmp_path / "x")
    assert fake.calls == []


def test_subvolume_info_relative_path_is_a_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeSubvolIoctl()
    monkeypatch.setattr(fcntl, "ioctl", fake)
    with pytest.raises(ValueError, match="absolute"):
        btrfs.subvolume_info(Path("ws"))
    assert fake.calls == []


def test_sync_filesystem_runs_filesystem_sync(recorder: Recorder, tmp_path: Path) -> None:
    btrfs.sync_filesystem(tmp_path)
    assert recorder.argvs == [["btrfs", "filesystem", "sync", str(tmp_path)]]


def test_sync_filesystem_failure_is_a_snapshot_error(recorder: Recorder, tmp_path: Path) -> None:
    recorder.then(DENIED)
    with pytest.raises(SnapshotError, match="Permission denied"):
        btrfs.sync_filesystem(tmp_path)


def test_sync_filesystem_relative_path_is_a_value_error(recorder: Recorder) -> None:
    with pytest.raises(ValueError, match="absolute"):
        btrfs.sync_filesystem(Path("mnt"))
    assert recorder.calls == []


# --- quotas: every level-0 qgroup (T04d-2: what holds the space) -------------------------------


def test_level0_qgroups_reads_every_subvolume_qgroup_and_nothing_else(
    sysfs: Path, tmp_path: Path
) -> None:
    write_mode(sysfs, "squota\n")
    write_qgroup(sysfs, "0_258", referenced="100\n", exclusive="100\n")
    write_qgroup(sysfs, "0_300", referenced="7\n", exclusive="7\n")
    write_qgroup(sysfs, "1_100", referenced="999\n")  # a higher level: not a subvolume
    (sysfs / FSID / "qgroups" / "0_bad").mkdir()  # not a qgroup name: ignored
    (sysfs / FSID / "qgroups" / "enabled").write_text("1\n")
    found = btrfs.level0_qgroups(tmp_path, sysfs=sysfs)
    assert sorted(found) == [258, 300]
    assert (found[258].exclusive, found[300].referenced) == (100, 7)


def test_level0_qgroups_without_quotas_is_empty(sysfs: Path, tmp_path: Path) -> None:
    assert btrfs.level0_qgroups(tmp_path, sysfs=sysfs) == {}


def test_level0_qgroups_with_a_bad_value_is_an_error(sysfs: Path, tmp_path: Path) -> None:
    write_mode(sysfs, "squota\n")
    write_qgroup(sysfs, "0_258", exclusive="-1\n")
    with pytest.raises(SnapshotError, match="unexpected"):
        btrfs.level0_qgroups(tmp_path, sysfs=sysfs)
