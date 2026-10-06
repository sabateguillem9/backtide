"""A real, throwaway Btrfs for the VM integration tests, mounted from a sparse file.

Everything runs as the unprivileged Lima user except exactly three ``sudo -n`` commands:
``mount -o loop,...,user_subvol_rm_allowed``, ``chown`` and ``umount`` (plus ``sudo -n true``,
which only checks that sudo works without a password). Every path comes from
``tmp_path_factory`` (never from the environment), and before unmounting the fixture checks
in /proc/self/mountinfo that the mount point is the btrfs loop mount of its own image.

The fixtures are lazy: importing this file (the Mac imports it for ``make test``) never runs
sudo or btrfs. They refuse to run anywhere but the vigia-dev Lima VM (checked by hostname), so
``pytest -m integration`` on a Linux laptop or CI runner never mounts anything there.

Each mount's owner holds an flock on ``owner.lock`` next to it (on tmpfs, outside the mount)
from before the mount until after the unmount. The kernel drops it when the owner dies, so:
- a btrfs under another /tmp/pytest-of-* session whose lock is held belongs to a run that is
  still going (another ``make it`` at the same time) and is left alone;
- one whose lock is free (or missing) was left by a killed run (``kill -9``): it stays until
  the VM reboots, and the next run fails and prints the command to remove it,
  ``sudo umount <mount point>``.
"""

import fcntl
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

GIB = 1024**3
MOUNT_OPTIONS = "loop,noatime,nosuid,nodev,user_subvol_rm_allowed"
COMMAND_TIMEOUT = 60.0
VM_HOSTNAME = "lima-vigia-dev"  # Lima names the guest lima-<instance>; see VM in the Makefile
OWNER_LOCK = "owner.lock"
SUDO_HINT = "integration tests need passwordless sudo in the VM to mount a loop btrfs"
_OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


@dataclass(frozen=True)
class Mount:
    """One line of /proc/self/mountinfo, reduced to what the fixture checks."""

    mount_point: Path
    fs_type: str
    source: str


@pytest.fixture(scope="session")
def btrfs_volume(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A 2 GiB btrfs, owned by the test user, shared by the whole session.

    Above 1 GiB, so mkfs never picks mixed mode. Tests make their own directory inside it."""
    with _mounted_btrfs(tmp_path_factory.mktemp("btrfs"), 2 * GIB) as mnt:
        yield mnt


@pytest.fixture
def tiny_btrfs_volume(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A fresh 1 GiB btrfs per test, only for the disk-full tests.

    Fill it with os.posix_fallocate: preallocated extents are never written, so the image on
    /tmp (tmpfs) stays sparse and the VM's RAM is not used up."""
    with _mounted_btrfs(tmp_path_factory.mktemp("tiny-btrfs"), GIB) as mnt:
        yield mnt


@contextmanager
def _mounted_btrfs(base: Path, size: int) -> Iterator[Path]:
    """Format a sparse ``size``-byte image in ``base`` and mount it at ``base/mnt``.

    ``base`` must come from ``tmp_path_factory.mktemp``, so its parent is this session's
    pytest base directory."""
    base = base.resolve()  # mountinfo and the loop device report resolved paths
    _require_dev_vm_user_with_sudo()
    img, mnt = base / "volume.img", base / "mnt"
    with _owner_lock(base):  # taken before the mount exists, released after it is gone
        _fail_on_stale_mounts(session_dir=base.parent)
        mnt.mkdir()
        with open(img, "xb") as image:  # x: never reuse or overwrite an existing file
            image.truncate(size)
        _run([_require_binary("mkfs.btrfs"), "-q", "-L", "vigia-test", str(img)])
        _sudo("mount", "-o", MOUNT_OPTIONS, str(img), str(mnt))
        try:
            _sudo("chown", f"{os.getuid()}:{os.getgid()}", str(mnt))
            yield mnt
        finally:
            _unmount(img, mnt)


def _require_dev_vm_user_with_sudo() -> None:
    # Never sudo on the Mac, a Linux laptop or a CI runner, even if pytest -m integration runs.
    if sys.platform != "linux" or platform.node() != VM_HOSTNAME:
        pytest.fail(f"integration tests run only inside the {VM_HOSTNAME} VM: use `make it`")
    if os.geteuid() == 0:
        pytest.fail(
            "run the integration tests as the normal user, not root: they test the "
            "unprivileged path"
        )
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, text=True, timeout=COMMAND_TIMEOUT
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        pytest.fail(f"{SUDO_HINT} ({e})")
    if result.returncode != 0:
        pytest.fail(f"{SUDO_HINT} ({result.stderr.strip()})")


@contextmanager
def _owner_lock(base: Path) -> Iterator[None]:
    """Hold an flock on ``base/owner.lock``: proof, for other runs, that this process is alive."""
    fd = os.open(
        base / OWNER_LOCK,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # a brand-new file: nobody else holds it
        yield
    finally:
        os.close(fd)


def _fail_on_stale_mounts(*, session_dir: Path) -> None:
    """A btrfs left mounted under /tmp/pytest-of-* by a killed run must be removed by hand.

    Mounts of other runs that are still alive are not stale and are left alone."""
    candidates = [
        m
        for m in _mounts()
        if m.fs_type == "btrfs"
        and any(part.startswith("pytest-of-") for part in m.mount_point.parts)
        and not m.mount_point.is_relative_to(session_dir)
    ]
    stale = [m for m in candidates if _is_stale(m)]
    if stale:
        commands = "\n".join(shlex.join(["sudo", "umount", str(m.mount_point)]) for m in stale)
        pytest.fail(f"a killed test run left btrfs mounted; remove it with:\n{commands}")


def _is_stale(mount: Mount) -> bool:
    """True unless a live process holds the mount's owner lock, or the mount is gone meanwhile."""
    try:
        fd = os.open(
            mount.mount_point.parent / OWNER_LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except FileNotFoundError:
        return True  # no owner lock at all: nothing proves that its run is alive
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False  # a live run owns it, such as another `make it` at the same time
    finally:
        os.close(fd)  # also releases the lock if this call took it
    # The lock was free, but its owner may have unmounted and exited after _mounts() was read.
    return _mount_at(mount.mount_point) is not None


def _unmount(img: Path, mnt: Path) -> None:
    """Unmount ``mnt`` only if it is exactly the btrfs loop mount of ``img``."""
    mount = _mount_at(mnt)
    if mount is None or mount.fs_type != "btrfs":
        pytest.fail(f"refusing to unmount {mnt}: it is not a btrfs mount point ({mount})")
    backing_file = _loop_backing_file(mount.source)
    if backing_file != img:
        pytest.fail(
            f"refusing to unmount {mnt}: {mount.source} is backed by {backing_file}, not {img}"
        )
    _sudo("umount", str(mnt))


def _mount_at(path: Path) -> Mount | None:
    matches = [m for m in _mounts() if m.mount_point == path]
    return matches[-1] if matches else None  # the last one is the mount on top


def _mounts() -> list[Mount]:
    return [
        _parse_mountinfo_line(line)
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
    ]


def _parse_mountinfo_line(line: str) -> Mount:
    """See proc_pid_mountinfo(5). Optional fields end at the ``-`` separator."""
    fields = line.split(" ")
    separator = fields.index("-", 6)
    return Mount(
        mount_point=Path(_unescape(fields[4])),
        fs_type=fields[separator + 1],
        source=_unescape(fields[separator + 2]),
    )


def _unescape(field: str) -> str:
    """The kernel writes space, tab, newline and backslash as octal escapes like ``\\040``."""
    return _OCTAL_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), field)


def _loop_backing_file(source: str) -> Path | None:
    """The file behind a /dev/loopN device, or None if ``source`` is not a loop device."""
    device = Path(source)
    if device.parent != Path("/dev") or not device.name.startswith("loop"):
        return None
    backing_file = Path("/sys/block") / device.name / "loop" / "backing_file"
    return Path(backing_file.read_text().rstrip("\n"))


def _require_binary(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.fail(f"{name} not found: btrfs-progs must be installed in the VM")
    return path


def _sudo(*args: str) -> None:
    """The only privileged commands: mount, chown and umount (see the module docstring)."""
    _run(["sudo", "-n", *args])


def _run(argv: list[str]) -> None:
    """Run ``argv`` and raise with its stderr if it fails. Never ignored."""
    result = subprocess.run(argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"{shlex.join(argv)} failed with exit code {result.returncode}: {stderr}"
        )
