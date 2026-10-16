"""A real, throwaway Btrfs for the VM integration tests, mounted from a sparse file.

Everything runs as the unprivileged Lima user except exactly four ``sudo -n`` commands:
``mount -o loop,...,user_subvol_rm_allowed``, ``chown``, ``umount`` and, only on a
``quota_volume``, ``btrfs qgroup limit <bytes>|none <path>`` (plus ``sudo -n true``, which only
checks that sudo works without a password). Every path comes from ``tmp_path_factory`` (never
from the environment), and before unmounting the fixture checks in /proc/self/mountinfo that
the mount point is the btrfs loop mount of its own image. ``qgroup limit`` is checked in the
one function that runs it (_sudo_btrfs, whoever calls it): exactly that argv and nothing else,
the loop mount of a test image, and a canonical path (no symlink anywhere) that is a
subvolume root strictly inside that mount, on that same btrfs. test_quota_volume.py tests
each refusal.

Simple quotas are enabled by the unprivileged ``mkfs.btrfs -O squota`` on the image, so
``btrfs quota enable --simple`` is never needed. The tests never run ``btrfs qgroup destroy``
or ``clear-stale``: on kernel 6.19 a missing owner qgroup aborts the transaction.

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

``running_agent`` (T03a) starts the real OpenClaw image in its jail on that btrfs, with docker
and no sudo at all. It pulls the pinned image the first time (about 1.3 GB, by digest). Test
containers and networks carry the pid of the pytest process that made them, so a later run
removes those of a killed run (whose pytest is gone) and leaves a live run's alone. Such a
container may still hold a stale btrfs inside its own mount namespace: removing it, and the
``sudo umount`` above, release the loop device.
"""

import fcntl
import os
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

from vigia.jail import IMAGE, AgentJail, AgentJailConfig, JailError
from vigia.jail import docker as jail_docker
from vigia.snapshots import SnapshotError, btrfs
from vigia.snapshots.store import SnapshotStore

GIB = 1024**3
MOUNT_OPTIONS = "loop,noatime,nosuid,nodev,user_subvol_rm_allowed"
COMMAND_TIMEOUT = 60.0
VM_HOSTNAME = "lima-vigia-dev"  # Lima names the guest lima-<instance>; see VM in the Makefile
OWNER_LOCK = "owner.lock"
VOLUME_IMAGE = "volume.img"  # the sparse file behind each test btrfs, next to its mount point
SUDO_HINT = "integration tests need passwordless sudo in the VM to mount a loop btrfs"
_OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
_DECIMAL_RE = re.compile(r"[1-9][0-9]{0,19}", re.ASCII)  # up to 2**64 - 1: 20 digits


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


@dataclass(frozen=True)
class QuotaVolume:
    """A fresh btrfs with simple quotas (see ``quota_volume``). ``image_file`` is the file
    behind it, readable by the test user (``btrfs inspect-internal dump-tree`` reads it)."""

    mnt: Path
    image_file: Path

    def set_limit(self, path: Path, limit: int | None) -> None:
        """Set (or, with None, lift) the referenced limit of the subvolume at ``path``.

        Runs ``sudo -n btrfs qgroup limit <bytes>|none <path>``: the production argv
        (btrfs.qgroup_limit_args) with only the sudo prefix. Only on a canonical path that is a
        subvolume root strictly inside ``mnt``, on this same btrfs; anything else is refused
        before sudo runs. Raises SnapshotError, or SnapshotNoSpace for ENOSPC/EDQUOT, like
        btrfs.set_qgroup_limit, so it can be injected wherever that one is expected."""
        args = btrfs.qgroup_limit_args(path, limit)  # ValueError for a relative path or limit
        _sudo_btrfs(self.mnt, args)


@pytest.fixture
def quota_volume(tmp_path_factory: pytest.TempPathFactory) -> Iterator[QuotaVolume]:
    """A fresh 1 GiB btrfs per test, formatted with simple quotas (``mkfs.btrfs -O squota``,
    without sudo), and the one privileged quota command bound to it (``set_limit``).

    Fill it like ``tiny_btrfs_volume``. Every subvolume gets its qgroup 0/<id> without limit;
    usage and limits are read without privileges with btrfs.qgroup_usage.

    The quota spike writes real data and metadata, so the image (on the VM's tmpfs, in RAM) is
    deleted once it is unmounted, instead of waiting for pytest's retention."""
    base = tmp_path_factory.mktemp("quota-btrfs").resolve()
    image_file = base / VOLUME_IMAGE
    with _mounted_btrfs(base, GIB, squota=True) as mnt:
        mode = btrfs.quota_mode(mnt)
        if mode != "squota":
            pytest.fail(f"mkfs.btrfs -O squota gave quota mode {mode!r} on {mnt}, not 'squota'")
        yield QuotaVolume(mnt, image_file)
    image_file.unlink()  # only reached after a checked, successful unmount


@pytest.fixture
def sudo_btrfs() -> Callable[[Path, tuple[str, ...]], None]:
    """The one privileged quota command behind QuotaVolume.set_limit, for the tests of its own
    guard (test_quota_volume.py). Every other test goes through set_limit."""
    return _sudo_btrfs


@pytest.fixture(scope="session")
def agent_image() -> str:
    """The pinned OpenClaw image, pulled if the VM does not have it yet, for tests that start a
    throwaway container of their own instead of ``running_agent``."""
    _require_agent_image()
    return IMAGE


@pytest.fixture
def store(btrfs_volume: Path, clock: Callable[[], datetime]) -> SnapshotStore:
    """An initialised snapshot store in this test's own 0700 directory of the shared btrfs,
    reading the fake clock (tests/conftest.py)."""
    root = btrfs_volume / uuid4().hex
    root.mkdir(mode=0o700)
    snapshot_store = SnapshotStore(root, clock=clock)
    snapshot_store.init()
    return snapshot_store


IMAGE_PULL_TIMEOUT = 1800.0  # the first pull of the pinned image is about 1.3 GB
# Test agents are named <prefix><pytest pid>-<random>: see _remove_stale_test_agents.
TEST_CONTAINER_PREFIX = "vigia-test-agent-"
TEST_NETWORK_PREFIX = "vigia-test-net-"


@dataclass(frozen=True)
class RunningAgent:
    """The real OpenClaw in its jail, as the T03a tests see it.

    ``workspace`` is ``<root>/workspace/agente`` on the host: the container's /workspace.
    ``store`` is the SnapshotStore whose workspace contains it. ``exec`` runs inside the
    container as the agent's user; ``quiesce`` is AgentJail.quiesce (stop, then start)."""

    jail: AgentJail
    store: SnapshotStore

    @property
    def name(self) -> str:
        return self.jail.config.name

    @property
    def workspace(self) -> Path:
        return self.jail.config.agent_dir

    def exec(
        self, argv: list[str], *, check: bool = False, timeout: float = 60
    ) -> subprocess.CompletedProcess[str]:
        return self.jail.exec(argv, check=check, timeout=timeout)

    def quiesce(self) -> AbstractContextManager[None]:
        return self.jail.quiesce()


@pytest.fixture(scope="module")
def running_agent(
    btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[RunningAgent]:
    """OpenClaw from the pinned image, running in its jail and ready (/healthz answers).

    One per test module: its own snapshot store on the shared btrfs (real clock), its own
    config folder outside that volume, and its own container and network, with unique names.
    Leftovers of killed runs are removed first. Removed afterwards, also when setup fails
    halfway.

    The agent runs as the Lima user, who also owns the store, Vigía's side and the Docker
    socket: without root, the agent's folders can only belong to that user. A concession of
    these tests (``allow_shared_ids``), never of production: there Vigía runs as root and the
    agent has ids of its own (docs/13)."""
    _require_agent_image()
    _remove_stale_test_agents()
    root = btrfs_volume / f"agent-{uuid4().hex}"
    root.mkdir(mode=0o700)
    agent_store = SnapshotStore(root)
    agent_store.init()
    name, network = _agent_names(os.getpid())
    config = AgentJailConfig(
        workspace=agent_store.workspace,
        config_dir=tmp_path_factory.mktemp("agent-config"),
        gateway_token=secrets.token_urlsafe(32),
        name=name,
        network=network,
        uid=os.getuid(),
        gid=os.getgid(),
        allow_shared_ids=True,
        memory="2g",
        cpus="2",
    )
    jail = AgentJail(config)
    try:
        jail.ensure_network()
        jail.prepare_workspace()
        jail.write_config()
        jail.create()
        jail.start()
        jail.wait_ready()
        yield RunningAgent(jail=jail, store=agent_store)
    finally:
        _remove_agent(jail)


def _require_agent_image() -> None:
    """Pull the pinned OpenClaw image if the VM does not have it yet (by digest, so the
    registry cannot hand over anything else)."""
    if jail_docker.run(["image", "inspect", IMAGE], check=False).returncode == 0:
        return
    jail_docker.run(["pull", "--quiet", IMAGE], timeout=IMAGE_PULL_TIMEOUT)


class AgentLeftovers:
    """How test agents are named, and the cleanup of a killed run's leftovers."""

    @staticmethod
    def names(pid: int) -> tuple[str, str]:
        return _agent_names(pid)

    @staticmethod
    def remove_stale() -> list[str]:
        return _remove_stale_test_agents()


@pytest.fixture
def agent_leftovers() -> AgentLeftovers:
    """For the test of the cleanup itself (test_jail.py)."""
    return AgentLeftovers()


def _agent_names(pid: int) -> tuple[str, str]:
    """Container and network names for a test agent made by the pytest process ``pid``."""
    suffix = f"{pid}-{uuid4().hex[:12]}"
    return f"{TEST_CONTAINER_PREFIX}{suffix}", f"{TEST_NETWORK_PREFIX}{suffix}"


def _remove_stale_test_agents() -> list[str]:
    """Remove the test containers, then the test networks, whose pytest process is gone (a
    run killed with kill -9 or a second Ctrl-C), and return their names. A live run's are
    left alone, such as another `make it` at the same time."""
    containers = _docker_lines(["ps", "--all", "--format", "{{.Names}}"])
    networks = _docker_lines(["network", "ls", "--format", "{{.Name}}"])
    stale_containers = [n for n in containers if _is_stale_test_name(n, TEST_CONTAINER_PREFIX)]
    stale_networks = [n for n in networks if _is_stale_test_name(n, TEST_NETWORK_PREFIX)]
    for name in stale_containers:
        jail_docker.run(["rm", "--force", name])  # a missing container is not an error
    for name in stale_networks:
        result = jail_docker.run(["network", "rm", name], check=False)
        if result.returncode != 0 and "not found" not in result.stderr:
            raise JailError(f"cannot remove the stale test network {name}: {result.stderr}")
    return stale_containers + stale_networks


def _docker_lines(args: list[str]) -> list[str]:
    return jail_docker.run(args).stdout.split()


def _is_stale_test_name(name: str, prefix: str) -> bool:
    if not name.startswith(prefix):
        return False
    pid, _, _ = name.removeprefix(prefix).partition("-")
    if not pid.isdigit():
        return True  # named before names carried a pid: left by a run killed back then
    return not _is_pytest_alive(int(pid))


def _is_pytest_alive(pid: int) -> bool:
    """True if ``pid`` is a running pytest. Another process that reused the pid is not."""
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return b"pytest" in cmdline


def _remove_agent(jail: AgentJail) -> None:
    """Remove the container, then its network. Both are attempted; a failure is raised."""
    errors: list[JailError] = []
    for step in (jail.remove, jail.remove_network):
        try:
            step()
        except JailError as error:
            errors.append(error)
    if errors:
        raise errors[0]


@contextmanager
def _mounted_btrfs(base: Path, size: int, *, squota: bool = False) -> Iterator[Path]:
    """Format a sparse ``size``-byte image in ``base`` and mount it at ``base/mnt``.

    ``base`` must come from ``tmp_path_factory.mktemp``, so its parent is this session's
    pytest base directory. ``squota`` formats it with simple quotas enabled (mkfs runs on the
    image file, so it needs no privileges)."""
    base = base.resolve()  # mountinfo and the loop device report resolved paths
    _require_dev_vm_user_with_sudo()
    img, mnt = base / VOLUME_IMAGE, base / "mnt"
    with _owner_lock(base):  # taken before the mount exists, released after it is gone
        _fail_on_stale_mounts(session_dir=base.parent)
        mnt.mkdir()
        with open(img, "xb") as image:  # x: never reuse or overwrite an existing file
            image.truncate(size)
        features = ["-O", "squota"] if squota else []
        _run([_require_binary("mkfs.btrfs"), "-q", "-L", "vigia-test", *features, str(img)])
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
        pytest.fail(
            f"a killed test run left btrfs mounted; remove it with:\n{commands}\n"
            "(a test agent that run left behind is removed by the next jail test module)"
        )


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
    """mount, chown and umount: with _sudo_btrfs, the only privileged commands (see the
    module docstring)."""
    _run(["sudo", "-n", *args])


def _require_qgroup_limit_args(args: tuple[str, ...]) -> Path:
    """Refuse (SnapshotError) anything but exactly ``("qgroup", "limit", <bytes>|"none",
    <absolute path>)``, character for character as btrfs.qgroup_limit_args builds it: no other
    subcommand (never ``destroy`` or ``clear-stale``), no options, no qgroup ids and no
    spelling of a number or a path that the round trip changes. Returns the path."""
    if (
        not isinstance(args, tuple)
        or len(args) != 4
        or not all(isinstance(arg, str) for arg in args)
        or args[:2] != ("qgroup", "limit")
    ):
        raise SnapshotError(f"refusing sudo btrfs {args!r}: only 'qgroup limit' is allowed")
    value, path = args[2], Path(args[3])
    if value != "none" and not _DECIMAL_RE.fullmatch(value):
        raise SnapshotError(f"refusing sudo btrfs {args!r}: the limit must be bytes or 'none'")
    limit = None if value == "none" else int(value)
    try:
        expected = btrfs.qgroup_limit_args(path, limit)
    except ValueError as e:
        raise SnapshotError(f"refusing sudo btrfs {args!r}: {e}") from e
    if args != expected:
        raise SnapshotError(f"refusing sudo btrfs {args!r}: not the form {expected!r}")
    return path


def _require_test_mount(mnt: Path) -> None:
    """Refuse (SnapshotError) unless ``mnt`` is the mount point of a test btrfs: canonical,
    under a pytest-of-* directory, and the btrfs loop mount of the image next to it (the
    check _unmount makes before its sudo)."""
    mnt = Path(mnt)
    mount = _mount_at(mnt) if Path(os.path.realpath(mnt)) == mnt else None
    if (
        mount is None
        or mount.fs_type != "btrfs"
        or not any(part.startswith("pytest-of-") for part in mnt.parts)
        or _loop_backing_file(mount.source) != mnt.parent / VOLUME_IMAGE
    ):
        raise SnapshotError(f"refusing sudo on {mnt}: not the mount point of a test btrfs")


def _require_own_subvolume(mnt: Path, path: Path) -> None:
    """Refuse (SnapshotError) unless ``path`` is canonical (absolute, no symlink, ``.`` or
    ``..`` anywhere), a subvolume root, strictly inside ``mnt`` (never the top-level subvolume
    0/5) and on the same btrfs as ``mnt``. Called right before sudo runs on ``path``."""
    path = Path(path)
    real = Path(os.path.realpath(path))
    if real != path:
        raise SnapshotError(f"refusing sudo on {path}: not canonical (it resolves to {real})")
    if real == mnt or not real.is_relative_to(mnt):
        raise SnapshotError(f"refusing sudo on {path}: not strictly inside the test mount {mnt}")
    if not btrfs.is_subvolume(path):  # also False for a symlink or a missing path
        raise SnapshotError(f"refusing sudo on {path}: not a subvolume root")
    if btrfs.fsid(path) != btrfs.fsid(mnt):
        raise SnapshotError(f"refusing sudo on {path}: not on the btrfs mounted at {mnt}")


def _sudo_btrfs(mnt: Path, args: tuple[str, ...]) -> None:
    """``sudo -n btrfs qgroup limit <bytes>|none <path>``, and nothing else, on a subvolume of
    the test btrfs mounted at ``mnt``. Everything is checked here, before sudo runs, whoever
    the caller: the exact argv (_require_qgroup_limit_args), the mount (_require_test_mount)
    and the path (_require_own_subvolume); a refusal is a SnapshotError.

    Runs with btrfs.run's conventions (fixed argv, LC_ALL=C, timeout) and its error mapping:
    SnapshotError, or SnapshotNoSpace for ENOSPC/EDQUOT."""
    path = _require_qgroup_limit_args(args)
    _require_test_mount(mnt)
    _require_own_subvolume(mnt, path)
    argv = ["sudo", "-n", "btrfs", *args]
    command = shlex.join(argv)
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=COMMAND_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as e:
        raise SnapshotError(f"{command} timed out after {COMMAND_TIMEOUT} s") from e
    except OSError as e:
        raise SnapshotError(f"cannot run {command}: {e}", errno=e.errno) from e
    if result.returncode != 0:
        btrfs._raise_failure(command, result.returncode, result.stderr.strip())


def _run(argv: list[str]) -> None:
    """Run ``argv`` and raise with its stderr if it fails. Never ignored."""
    result = subprocess.run(argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"{shlex.join(argv)} failed with exit code {result.returncode}: {stderr}"
        )
