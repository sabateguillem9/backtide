"""The T03b spike: what simple quotas (squota) really do on kernel 6.19, checked in the VM.

Each test pins one behaviour that the workspace cap (T03b-2) relies on, or measures a number
that sizes it (docs/backlog.md, T03b). Behaviours the design relies on are asserted, so a
kernel or btrfs-progs upgrade that changes them stops T03b-2. Measurements are reported with
``report`` (shown with ``pytest -rP``, kept in the JUnit XML) for the devlog; the tests that
only record say so in their docstring. Sections follow the checks A1-A14 of the T03b design
(A9 is part of A6; A12, reading free space without root, is the ``space`` helper); A15, the
SELinux relabel at each start, came out of the review.

Everything runs as the unprivileged Lima user on a fresh 1 GiB btrfs formatted with
``mkfs.btrfs -O squota`` (``quota_volume`` in conftest.py), through the vigia.snapshots.btrfs
functions. The only privileged command is ``quota_volume.set_limit`` (``sudo -n btrfs qgroup
limit``). No test runs ``btrfs qgroup destroy`` or ``clear-stale``.

Sizes: the image lives on the VM's tmpfs, so fills use posix_fallocate (never written, the
image stays sparse) unless the test is about real writes or metadata. conftest.py deletes each
quota volume's image after its unmount.
"""

import errno
import fcntl
import itertools
import json
import os
import re
import struct
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import pytest

from vigia.jail import docker as jail_docker
from vigia.jail.config import CONTAINER_WORKSPACE
from vigia.snapshots import SnapshotError, SnapshotNoSpace, btrfs

pytestmark = pytest.mark.integration


class QuotaVolume(Protocol):
    """What conftest.py's ``quota_volume`` fixture gives (not imported: two conftest.py)."""

    mnt: Path
    image_file: Path

    def set_limit(self, path: Path, limit: int | None) -> None: ...


class AgentLeftovers(Protocol):
    """conftest.py's ``agent_leftovers``: names a test container so a later run can remove it
    if this one is killed."""

    def names(self, pid: int) -> tuple[str, str]: ...


KIB = 1024
MIB = 1024**2
NODESIZE = 16 * KIB  # mkfs default: every fs-tree block is charged as one node
SMALL_FILE = b"x" * 2000  # under max_inline (2048): stored in the metadata tree
SMALL_CAP = 32 * MIB  # behaviour tests: small, so the fills are quick
# The cap for T03b-2's tests on the 1 GiB volume: the largest tried that left room for a
# rewind after every fill here, all without reflinks (T03b-2 blocks copy_file_range). 256 MiB
# did not: metadata right after deleting buffered data got ENOSPC before EDQUOT (A14).
TEST_CAP = 192 * MIB
MIN_UNALLOCATED_AFTER_FILL = 128 * MIB  # "far from full"
TOP_LEVEL_SUBVOLUME_ID = 5
FILL_TIMEOUT = 300.0  # seconds; a fill that takes longer fails the test with its progress
FILL_BATCH = 1000  # small files created between two deadline checks
CLEANER_TIMEOUT = 60.0  # seconds to wait for the cleaner to drop a deleted subvolume
CHUNK_TREE_TIMEOUT = 30.0  # seconds to get a chunk tree that agrees with /sys
STOP_ERRNOS = (errno.EDQUOT, errno.ENOSPC)
DELETE_STRIDE = 7  # about 7 small files share a leaf: one delete per leaf copies them all
# FIEMAP (linux/fiemap.h): unprivileged, reports where each extent of a file lives on disk.
FS_IOC_FIEMAP = 0xC020660B  # _IOWR('f', 11, struct fiemap)
FIEMAP_FLAG_SYNC = 0x1
FIEMAP_EXTENT_SHARED = 0x2000
_FIEMAP_HEADER = struct.Struct("=QQIIII")  # start, length, flags, mapped, count, reserved
_FIEMAP_EXTENT = struct.Struct("=QQQ2Q4I")  # logical, physical, length, reserved, flags
# One chunk in ``btrfs inspect-internal dump-tree -t chunk`` (btrfs-progs 6.19): its logical
# start, its length and its type, such as DATA|single or METADATA|DUP.
_CHUNK_ITEM_RE = re.compile(
    r"CHUNK_ITEM (\d+)\) itemoff \d+ itemsize \d+\n\s+length (\d+) owner \d+ "
    r"stripe_len \d+ type (\S+)",
    re.ASCII,
)


# Reading quota state and free space, without privileges


def commit(path: Path) -> None:
    """Commit the transaction (``btrfs filesystem sync``, unprivileged): delayed refs run, so
    ``referenced`` is current."""
    btrfs.run("filesystem", "sync", path)


def usage(path: Path) -> btrfs.QgroupUsage:
    """The subvolume's qgroup after a commit."""
    commit(path)
    return btrfs.qgroup_usage(path)


def qgroup_dir(mnt: Path, subvolume_id: int) -> Path:
    return btrfs.SYSFS_BTRFS / btrfs.fsid(mnt) / "qgroups" / f"0_{subvolume_id}"


def read_qgroup_dir(directory: Path) -> dict[str, int] | None:
    """The raw counters of a qgroup directory, or None if it is gone (for deleted subvolumes,
    whose path no longer exists)."""
    if not directory.exists():
        return None
    names = ("referenced", "exclusive", "limit_flags", "max_referenced")
    return {name: int((directory / name).read_text()) for name in names}


@dataclass(frozen=True)
class Space:
    """Free space of the whole volume from /sys/fs/btrfs/<fsid>/allocation and statvfs.

    ``*_used`` and ``*_total`` are logical bytes; ``*_disk_*`` are raw (x2 for DUP)."""

    device: int
    allocated: int  # raw bytes in chunks (all block groups)
    data_total: int
    data_used: int
    metadata_total: int
    metadata_used: int
    metadata_disk_used: int
    global_rsv: int
    statvfs_free: int

    @property
    def unallocated(self) -> int:
        return self.device - self.allocated

    def summary(self) -> str:
        return (
            f"unallocated {mib(self.unallocated)}, data {mib(self.data_used)}/"
            f"{mib(self.data_total)}, metadata {mib(self.metadata_used)}/"
            f"{mib(self.metadata_total)} (raw used {mib(self.metadata_disk_used)}), "
            f"global rsv {mib(self.global_rsv)}, statvfs free {mib(self.statvfs_free)}"
        )


def space(mnt: Path) -> Space:
    commit(mnt)
    fs = btrfs.SYSFS_BTRFS / btrfs.fsid(mnt)
    allocation = fs / "allocation"
    (device,) = (fs / "devices").iterdir()  # one loop device

    def read(*parts: str) -> int:
        return int(allocation.joinpath(*parts).read_text())

    st = os.statvfs(mnt)
    return Space(
        device=int((device / "size").read_text()) * 512,
        allocated=sum(read(kind, "disk_total") for kind in ("data", "metadata", "system")),
        data_total=read("data", "total_bytes"),
        data_used=read("data", "bytes_used"),
        metadata_total=read("metadata", "total_bytes"),
        metadata_used=read("metadata", "bytes_used"),
        metadata_disk_used=read("metadata", "disk_used"),
        global_rsv=read("global_rsv_size"),
        statvfs_free=st.f_bavail * st.f_frsize,
    )


def limits(found: btrfs.QgroupUsage) -> tuple[int, int, int]:
    return found.limit_flags, found.max_referenced, found.max_exclusive


def mib(n: int) -> str:
    return f"{n / MIB:.1f} MiB"


def report(record_property: Callable[[str, object], None], name: str, outcome: str) -> None:
    """Shown with ``pytest -rP``, and kept in the JUnit XML, for the devlog."""
    print(f"{name}: {outcome}")
    record_property(name, outcome)


# Subvolumes


def make_subvolume(path: Path) -> Path:
    btrfs.create_subvolume(path)
    return path


def capped_subvolume(volume: QuotaVolume, name: str, limit: int) -> Path:
    path = make_subvolume(volume.mnt / name)
    volume.set_limit(path, limit)
    return path


def open_dir(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def exchange(mnt: Path, a: str, b: str) -> None:
    fd = open_dir(mnt)
    try:
        btrfs.renameat2(fd, a, b, btrfs.RENAME_EXCHANGE)
    finally:
        os.close(fd)


# Fills. Each stops at EDQUOT or ENOSPC (any other error fails the test), checks a deadline
# between batches, and reports how far it got.


@dataclass(frozen=True)
class Fill:
    """How a fill ended: ``amount`` (bytes, or files for small files), the errno that stopped
    it, which call got it, and how long the fill took."""

    amount: int
    errno: int
    call: str
    seconds: float

    def summary(self, unit: str = "bytes") -> str:
        amount = mib(self.amount) if unit == "bytes" else f"{self.amount} {unit}"
        return (
            f"{amount} until {errno.errorcode[self.errno]} ({self.errno}) at {self.call}, "
            f"{self.seconds:.1f} s"
        )


class Deadline:
    def __init__(self, what: str, timeout: float = FILL_TIMEOUT) -> None:
        self.what, self.timeout = what, timeout
        self.start = time.monotonic()

    def check(self, progress: str) -> None:
        if self.elapsed() > self.timeout:
            pytest.fail(f"{self.what} took over {self.timeout:.0f} s ({progress})")

    def elapsed(self) -> float:
        return time.monotonic() - self.start


def stop_errno(error: OSError) -> int:
    """The errno of an error that ends a fill; anything else is re-raised."""
    if error.errno not in STOP_ERRNOS:
        raise error
    return error.errno


def create(path: Path) -> int:
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def fill_by_writing(directory: Path, *, file_size: int = 64 * MIB) -> Fill:
    """Buffered write() of 1 MiB blocks into new files of ``file_size``."""
    deadline = Deadline("write fill")
    block = b"\0" * MIB
    written = 0
    for index in itertools.count():
        deadline.check(mib(written))
        call = "create"
        try:
            fd = create(directory / f"data-{index}")
            call = "write"
            try:
                while os.fstat(fd).st_size < file_size:
                    written += os.write(fd, block)  # a short write: the next one fails
            finally:
                os.close(fd)
        except OSError as e:
            return Fill(written, stop_errno(e), call, deadline.elapsed())
    raise AssertionError("unreachable")


def fill_by_preallocating(directory: Path, steps: tuple[int, ...] = (64 * MIB, MIB)) -> Fill:
    """posix_fallocate new files of each size in ``steps`` until it fails. Never writes the
    data, so the image stays sparse."""
    deadline = Deadline("fallocate fill")
    preallocated, stopped, call = 0, 0, ""
    for size in steps:
        for index in itertools.count():
            deadline.check(mib(preallocated))
            call = "create"
            try:
                fd = create(directory / f"prealloc-{size}-{index}")
                call = "fallocate"
                try:
                    os.posix_fallocate(fd, 0, size)
                finally:
                    os.close(fd)
            except OSError as e:
                stopped = stop_errno(e)
                break
            preallocated += size
    return Fill(preallocated, stopped, call, deadline.elapsed())


def fill_with_small_files(directory: Path) -> Fill:
    """Create ``directory`` and 2,000-byte files f0, f1, ... in it (inline: metadata only).
    Consecutive files share fs-tree leaves, about 7 per leaf."""
    directory.mkdir()
    deadline = Deadline("small-file fill")
    for count in itertools.count():
        if count % FILL_BATCH == 0:
            deadline.check(f"{count} files")
        call = "create"
        try:
            fd = create(directory / f"f{count}")
            call = "write"
            try:
                os.write(fd, SMALL_FILE)
            finally:
                os.close(fd)
        except OSError as e:
            return Fill(count, stop_errno(e), call, deadline.elapsed())
    raise AssertionError("unreachable")


def preallocate(path: Path, size: int) -> None:
    fd = create(path)
    try:
        os.posix_fallocate(fd, 0, size)
    finally:
        os.close(fd)


def push_past_cap(mnt: Path, subvolume: Path) -> btrfs.QgroupUsage:
    """Fill ``subvolume`` with small files until EDQUOT, then delete_after_snapshot."""
    fill = fill_with_small_files(subvolume / "small")
    assert fill.errno == errno.EDQUOT, fill
    return delete_after_snapshot(mnt, subvolume, subvolume / "small")


def delete_after_snapshot(mnt: Path, subvolume: Path, small: Path) -> btrfs.QgroupUsage:
    """Take a snapshot of ``subvolume``, then delete one of the small files f0, f1, ... in
    ``small`` in each of the first leaves. Deletes are not quota-checked, and each copies a
    leaf the snapshot shares, so a subvolume at its cap ends past it (see the
    delete-after-snapshot test)."""
    btrfs.snapshot(subvolume, mnt / "past-cap", readonly=True)
    for index in range(0, DELETE_STRIDE * 64, DELETE_STRIDE):
        os.unlink(small / f"f{index}")
    found = usage(subvolume)
    assert found.limit is not None
    assert found.referenced > found.limit, f"precondition: not past the cap ({found})"
    return found


def try_rewind(volume: QuotaVolume, workspace: Path, limit: int) -> str:
    """The space steps of a rewind in T03b-2's order: a writable snapshot into <root>, its
    cap, the EXCHANGE, the old workspace moved into snapshots/, uncapped and made read-only.
    "ok", or where it stopped with SnapshotNoSpace; any other error fails the test."""
    mnt = volume.mnt
    staging, name = mnt / "workspace.restore", workspace.name
    steps: list[tuple[str, Callable[[], None]]] = [
        ("snapshot", lambda: btrfs.snapshot(workspace, staging, readonly=False)),
        ("cap", lambda: volume.set_limit(staging, limit)),
        ("exchange", lambda: exchange(mnt, staging.name, name)),
        ("mkdir", lambda: (mnt / "snapshots").mkdir(exist_ok=True)),
        ("move", lambda: rename(mnt, staging.name, "snapshots/old")),
        ("uncap", lambda: volume.set_limit(mnt / "snapshots" / "old", None)),
        ("ro", lambda: btrfs.set_readonly(mnt / "snapshots" / "old", True)),
    ]
    for step, action in steps:
        try:
            action()
        except SnapshotNoSpace as e:
            return f"{step}: SnapshotNoSpace ({e})"
        except OSError as e:
            return f"{step}: {errno.errorcode[stop_errno(e)]}"
    return "ok"


def rename(mnt: Path, old: str, new: str) -> None:
    fd = open_dir(mnt)
    try:
        btrfs.renameat2(fd, old, new, btrfs.RENAME_NOREPLACE)
    finally:
        os.close(fd)


def write_data(path: Path, size: int) -> None:
    """Buffered write() of ``size`` bytes into a new file, without fsync (delalloc)."""
    fd = create(path)
    try:
        block = b"\0" * min(size, MIB)
        written = 0
        while written < size:
            written += os.write(fd, block[: size - written])  # a short write: the next fails
    finally:
        os.close(fd)


def fill_with_units(
    directory: Path, writer: Callable[[Path, int], None]
) -> tuple[list[Path], Fill]:
    """Files of 1 MiB written by ``writer`` until it fails: each one extent, so the data fill
    can later be thinned out extent by extent. Returns every file (the one that failed too,
    with whatever it got) and how the fill ended; ``Fill.amount`` counts complete files only,
    so read the charged bytes from the qgroup."""
    deadline = Deadline("1 MiB file fill")
    files: list[Path] = []
    for index in itertools.count():
        deadline.check(f"{index} files")
        path = directory / f"unit-{index}"
        try:
            writer(path, MIB)
        except OSError as e:
            if os.path.lexists(path):
                files.append(path)
            return files, Fill(index * MIB, stop_errno(e), writer.__name__, deadline.elapsed())
        files.append(path)
    raise AssertionError("unreachable")


def data_chunks(volume: QuotaVolume) -> list[tuple[int, int]]:
    """(logical start, length) of every data chunk, from the chunk tree in the image file
    after a commit (``dump-tree`` reads the file without privileges). Read until it agrees
    with the data total in /sys, which also shows a chunk added or dropped since the last
    commit; so a parsing mistake fails here too."""
    deadline = Deadline("a chunk tree that agrees with /sys", CHUNK_TREE_TIMEOUT)
    while True:
        commit(volume.mnt)
        tree = btrfs.run("inspect-internal", "dump-tree", "-t", "chunk", volume.image_file)
        chunks = [
            (int(start), int(length))
            for start, length, kind in _CHUNK_ITEM_RE.findall(tree)
            if kind.split("|")[0] == "DATA"
        ]
        total = space(volume.mnt).data_total
        if chunks and sum(length for _, length in chunks) == total:
            return chunks
        deadline.check(f"data chunks {[(a / MIB, b / MIB) for a, b in chunks]}, /sys {mib(total)}")
        time.sleep(1)


def first_file_in_each_chunk(
    files: list[Path], chunks: list[tuple[int, int]]
) -> dict[tuple[int, int], Path]:
    """For each data chunk that holds data of ``files``, the file whose first extent comes
    first in it. A file with no extent on disk is skipped."""
    placed = sorted((extents[0][0], path) for path in files if (extents := physical_extents(path)))
    keepers: dict[tuple[int, int], Path] = {}
    for physical, path in placed:
        chunk = next((c for c in chunks if c[0] <= physical < c[0] + c[1]), None)
        assert chunk is not None, f"{path} starts at {physical}, in no data chunk {chunks}"
        keepers.setdefault(chunk, path)
    return keepers


def delete_every(directory: Path, count: int, *, first: int, stride: int) -> int | None:
    """Unlink f<first>, f<first + stride>, ... below f<count>. None, or the errno that stopped
    it (a delete is never quota-checked, but it can still run out of space)."""
    deadline = Deadline("deletes")
    for index in range(first, count, stride):
        if index % FILL_BATCH == first:
            deadline.check(f"at f{index}")
        try:
            os.unlink(directory / f"f{index}")
        except OSError as e:
            return stop_errno(e)
    return None


def state(volume: QuotaVolume, subvolume: Path) -> str:
    found, free = usage(subvolume), space(volume.mnt)
    limit = found.limit or 1
    return (
        f"referenced {mib(found.referenced)} ({found.referenced / limit:.2f} x limit), "
        f"{free.summary()}"
    )


def try_set_limit(volume: QuotaVolume, path: Path, limit: int | None) -> str:
    try:
        volume.set_limit(path, limit)
    except SnapshotError as e:
        return f"{type(e).__name__} ({e})"
    return "ok"


def mount_options(mnt: Path) -> set[str]:
    """Per-mount and superblock options of ``mnt`` from /proc/self/mountinfo."""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split(" ")
        if fields[4] == str(mnt):
            separator = fields.index("-", 6)
            return set(fields[5].split(",")) | set(fields[separator + 3].split(","))
    raise AssertionError(f"{mnt} is not mounted")


def loop_device(mnt: Path) -> str:
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split(" ")
        if fields[4] == str(mnt):
            return Path(fields[fields.index("-", 6) + 2]).name
    raise AssertionError(f"{mnt} is not mounted")


def kernel_btrfs_problems(mnt: Path, since: float) -> list[str] | None:
    """Kernel log lines about this volume's loop device since ``since`` that mention an abort,
    an error or read-only. None when the log is not readable (journalctl -k works for the
    systemd-journal group, which the Lima user is in; dmesg needs root)."""
    try:
        result = subprocess.run(
            ["journalctl", "-k", "-q", "--no-pager", "-o", "cat", f"--since=@{since:.0f}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    device = f"device {loop_device(mnt)}"
    words = ("abort", "error", "read-only", "readonly")
    return [
        line
        for line in result.stdout.splitlines()
        if device in line and any(word in line.lower() for word in words)
    ]


def physical_extents(path: Path) -> list[tuple[int, int, int]]:
    """(physical, length, flags) of each extent of ``path``, from FIEMAP after a sync."""
    count = 64
    buffer = bytearray(_FIEMAP_HEADER.size + count * _FIEMAP_EXTENT.size)
    _FIEMAP_HEADER.pack_into(buffer, 0, 0, 2**64 - 1, FIEMAP_FLAG_SYNC, 0, count, 0)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.ioctl(fd, FS_IOC_FIEMAP, buffer)
    finally:
        os.close(fd)
    mapped = _FIEMAP_HEADER.unpack_from(buffer)[3]
    assert mapped < count, f"{path} has too many extents for this check"
    extents = []
    for index in range(mapped):
        fields = _FIEMAP_EXTENT.unpack_from(
            buffer, _FIEMAP_HEADER.size + index * _FIEMAP_EXTENT.size
        )
        extents.append((fields[1], fields[2], fields[5]))
    return extents


def shares_extents(copy: Path, original: Path) -> bool:
    """True if ``copy`` is a reflink of ``original``: the same physical extents, flagged
    shared. A real copy has extents of its own."""
    original_extents = {physical for physical, _, _ in physical_extents(original)}
    copy_extents = physical_extents(copy)
    assert original_extents and copy_extents, "no extents on disk: nothing to compare"
    same_place = {physical for physical, _, _ in copy_extents} == original_extents
    return same_place and all(flags & FIEMAP_EXTENT_SHARED for _, _, flags in copy_extents)


def write_file(path: Path, size: int) -> None:
    with open(path, "xb") as file:
        file.write(os.urandom(size))
        os.fsync(file.fileno())


def clone(source: Path, destination: Path) -> int:
    """os.copy_file_range of the whole file (the syscall cp and libuv use)."""
    size = source.stat().st_size
    with open(source, "rb") as src, open(destination, "xb") as dst:
        copied = 0
        while copied < size:
            copied += os.copy_file_range(src.fileno(), dst.fileno(), size - copied)
    return copied


# A1. Quotas on without privileges


def test_mkfs_with_squota_enables_simple_quotas_without_privileges(
    quota_volume: QuotaVolume, btrfs_volume: Path
) -> None:
    """conftest.py formats the image as the Lima user: no ``quota enable`` (Plan B) needed."""
    assert btrfs.quota_mode(quota_volume.mnt) == "squota"
    status = btrfs.run("quota", "status", quota_volume.mnt)  # unprivileged: reads sysfs
    assert re.search(r"^\s*Enabled:\s+yes$", status, re.MULTILINE), status
    assert re.search(r"^\s*Mode:\s+squota\b", status, re.MULTILINE), status
    assert btrfs.quota_mode(btrfs_volume) is None  # the other fixtures stay without quotas


# A2. Reading usage and limits without privileges


def test_the_top_level_qgroup_has_no_limit_bits_despite_mkfs_garbage(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """Snapshots, renames and deletes in <root> reserve against 0/5, so it must stay uncapped.

    btrfs-progs 6.19.1 writes the QGROUP_LIMIT item of 0/5 with btrfs_insert_empty_item and
    never zeroes it (mkfs/main.c, insert_qgroup_items): the flags and maxima are leftover
    bytes. None of the MAX_RFER/MAX_EXCL bits happen to be set, so nothing is enforced; this
    is why limits are always read through those bits (QgroupUsage.limit), never as
    ``limit_flags == 0``."""
    mnt = quota_volume.mnt
    assert btrfs.fsid(mnt) in os.listdir(btrfs.SYSFS_BTRFS)
    assert btrfs.subvolume_id(mnt) == TOP_LEVEL_SUBVOLUME_ID
    top = btrfs.qgroup_usage(mnt)
    assert (top.limit, top.exclusive_limit) == (None, None)
    report(
        record_property,
        "top_level_limit_item",
        f"0/5 limit_flags {top.limit_flags:#x}, max_referenced {top.max_referenced}, "
        f"max_exclusive {top.max_exclusive}",
    )


def test_every_new_subvolume_gets_an_uncapped_qgroup_readable_without_privileges(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    mnt = quota_volume.mnt
    workspace = make_subvolume(mnt / "workspace")
    created = btrfs.qgroup_usage(workspace)  # no commit yet: the qgroup exists at once
    btrfs.snapshot(workspace, mnt / "snap", readonly=True)
    btrfs.snapshot(workspace, mnt / "copy", readonly=False)

    for path in (workspace, mnt / "snap", mnt / "copy"):
        qgroup = qgroup_dir(mnt, btrfs.subvolume_id(path))
        assert qgroup.is_dir()
        found = usage(path)
        assert found.limit_flags == 0
        assert (found.limit, found.exclusive_limit) == (None, None)
        assert found.referenced == found.exclusive
    report(
        record_property,
        "new_qgroups",
        f"subvolume right after create: referenced {created.referenced}; after a commit: "
        f"workspace {usage(workspace).referenced}, snapshot -r {usage(mnt / 'snap').referenced}"
        f", writable snapshot {usage(mnt / 'copy').referenced} bytes",
    )


def test_snapshot_reservations_on_the_top_level_qgroup(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """Recorded, not asserted. The research suspects that create_snapshot reserves on the
    destination directory's root (0/5) but frees on the source's, leaking 3 nodes per
    snapshot on 0/5: harmless while 0/5 has no limit bits (see above)."""
    mnt = quota_volume.mnt
    workspace = make_subvolume(mnt / "workspace")
    top = qgroup_dir(mnt, TOP_LEVEL_SUBVOLUME_ID)
    names = ("rsv_data", "rsv_meta_pertrans", "rsv_meta_prealloc")

    def reservations() -> dict[str, int]:
        commit(mnt)
        return {name: int((top / name).read_text()) for name in names}

    before = reservations()
    for index in range(20):
        btrfs.snapshot(workspace, mnt / f"snap-{index}", readonly=True)
    report(
        record_property,
        "top_level_reservations",
        f"0/5 before {before}, after 20 snapshots {reservations()}",
    )


# A3. Setting and lifting the cap


def test_qgroup_limit_caps_exactly_that_subvolume_also_when_read_only(
    quota_volume: QuotaVolume,
) -> None:
    mnt = quota_volume.mnt
    workspace = make_subvolume(mnt / "workspace")
    sibling = make_subvolume(mnt / "sibling")
    frozen = make_subvolume(mnt / "frozen")
    btrfs.set_readonly(frozen, True)
    top = btrfs.qgroup_usage(mnt)

    quota_volume.set_limit(workspace, SMALL_CAP)
    quota_volume.set_limit(frozen, 2 * SMALL_CAP)

    capped = btrfs.qgroup_usage(workspace)  # no commit: the limit shows at once
    assert capped.limit_flags == btrfs.QGROUP_LIMIT_MAX_RFER
    assert (capped.limit, capped.exclusive_limit) == (SMALL_CAP, None)
    assert btrfs.qgroup_usage(frozen).limit == 2 * SMALL_CAP
    assert btrfs.is_readonly(frozen)
    assert btrfs.qgroup_usage(sibling).limit_flags == 0
    assert limits(btrfs.qgroup_usage(mnt)) == limits(top)  # 0/5 untouched

    quota_volume.set_limit(workspace, None)
    quota_volume.set_limit(frozen, None)

    for lifted in (workspace, frozen):
        assert btrfs.qgroup_usage(lifted).limit_flags == 0
        assert btrfs.qgroup_usage(lifted).max_referenced == 0


def test_qgroup_limit_without_privileges_fails_with_eperm(quota_volume: QuotaVolume) -> None:
    """Why the store gets the setter injected, and why the agent cannot lift its own cap
    (it also has no CAP_SYS_ADMIN and seccomp blocks every 0x94 ioctl)."""
    workspace = make_subvolume(quota_volume.mnt / "workspace")
    quota_volume.set_limit(workspace, SMALL_CAP)

    for limit in (None, 2 * SMALL_CAP):
        with pytest.raises(SnapshotError, match="Operation not permitted") as excinfo:
            btrfs.set_qgroup_limit(workspace, limit)
        assert not isinstance(excinfo.value, SnapshotNoSpace)

    assert btrfs.qgroup_usage(workspace).limit == SMALL_CAP


# A4. The cap belongs to the subvolume id, not to the path


def test_the_cap_does_not_follow_snapshots_or_the_exchange(quota_volume: QuotaVolume) -> None:
    """So the store must cap every new workspace subvolume itself (T03b-2)."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    workspace_id = btrfs.subvolume_id(workspace)
    btrfs.snapshot(workspace, mnt / "snap", readonly=True)
    btrfs.snapshot(workspace, mnt / "workspace.restore", readonly=False)

    for snapshot in ("snap", "workspace.restore"):
        assert btrfs.qgroup_usage(mnt / snapshot).limit_flags == 0

    exchange(mnt, "workspace.restore", "workspace")

    assert btrfs.subvolume_id(mnt / "workspace.restore") == workspace_id
    assert btrfs.qgroup_usage(mnt / "workspace.restore").limit == SMALL_CAP
    assert btrfs.qgroup_usage(mnt / "workspace").limit_flags == 0


# A5. Enforcement


FILLS: dict[str, Callable[[Path], Fill]] = {
    "write": fill_by_writing,
    "fallocate": fill_by_preallocating,
    "small_files": fill_with_small_files,
}


@pytest.mark.parametrize("method", FILLS)
def test_a_capped_subvolume_stops_writes_with_edquot_far_from_a_full_volume(
    quota_volume: QuotaVolume, method: str, record_property: Callable[[str, object], None]
) -> None:
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", TEST_CAP)
    empty, before = usage(workspace), space(mnt)
    target = workspace / "fill" if method == "small_files" else workspace

    fill = FILLS[method](target)

    full, after = usage(workspace), space(mnt)
    charged = full.referenced - empty.referenced
    raw_metadata = after.metadata_disk_used - before.metadata_disk_used
    raw_data = after.data_used - before.data_used
    report(
        record_property,
        f"edquot_{method}",
        f"cap {mib(TEST_CAP)}: {fill.summary('files' if method == 'small_files' else 'bytes')}; "
        f"referenced - limit = {full.referenced - TEST_CAP} bytes; charged {mib(charged)}, "
        f"raw metadata +{mib(raw_metadata)} (x{raw_metadata / charged:.2f} of charged), "
        f"data +{mib(raw_data)}; volume: {after.summary()}",
    )
    assert fill.errno == errno.EDQUOT == 122  # not ENOSPC (28): the volume is not full
    assert after.unallocated >= MIN_UNALLOCATED_AFTER_FILL
    victim = next(path for path in target.iterdir() if path.is_file())
    os.unlink(victim)  # never quota-checked: the agent can always delete to get back under
    assert not victim.exists()
    rewind = try_rewind(quota_volume, workspace, TEST_CAP)
    report(record_property, f"rewind_after_{method}", rewind)
    assert rewind == "ok"


# A6. Fresh budget and history


def test_a_writable_snapshot_starts_with_a_fresh_budget_and_pays_for_its_own_writes(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """The staging copy of a rewind (the next workspace) starts at about one node: what it
    inherits stays charged to the subvolume that wrote it. Each rewind gives a full cap."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    preallocate(workspace / "inherited", 16 * MIB)
    source = usage(workspace)

    btrfs.snapshot(workspace, mnt / "workspace.restore", readonly=False)
    staging = mnt / "workspace.restore"
    fresh = usage(staging)
    preallocate(staging / "new", 8 * MIB)
    grown, source_after = usage(staging), usage(workspace)

    report(
        record_property,
        "fresh_budget",
        f"source {source.referenced}, writable snapshot at birth {fresh.referenced}, after 8 MiB "
        f"in it {grown.referenced}; source afterwards {source_after.referenced} bytes",
    )
    assert fresh.referenced <= NODESIZE
    assert grown.referenced - fresh.referenced >= 8 * MIB
    assert source_after.referenced == source.referenced


def test_history_stays_charged_until_no_snapshot_holds_it(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    preallocate(workspace / "history", 16 * MIB)
    full = usage(workspace)
    btrfs.snapshot(workspace, mnt / "snap", readonly=True)
    snap_qgroup = qgroup_dir(mnt, btrfs.subvolume_id(mnt / "snap"))

    os.unlink(workspace / "history")
    held = usage(workspace)
    assert held.referenced >= full.referenced  # the snapshot still holds the 16 MiB

    btrfs.delete_subvolume(mnt / "snap", commit=True)
    deadline = Deadline("cleaner", CLEANER_TIMEOUT)
    while (released := usage(workspace)).referenced > full.referenced - 15 * MIB:
        deadline.check(f"referenced {released.referenced}")
        time.sleep(0.5)
    released_after = deadline.elapsed()
    while snap_qgroup.exists() and deadline.elapsed() < released_after + 10:
        commit(mnt)
        time.sleep(0.5)
    report(
        record_property,
        "history",
        f"16 MiB file: referenced {full.referenced}, deleted under a snapshot "
        f"{held.referenced}, {released_after:.1f} s after deleting the snapshot "
        f"{released.referenced} bytes; the snapshot's own qgroup "
        f"{'is still there' if snap_qgroup.exists() else 'was removed'} "
        f"after {deadline.elapsed():.1f} s",
    )


def test_a_deleted_subvolume_whose_data_lives_on_keeps_its_qgroup(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """Recorded, not asserted: a former workspace deleted while a snapshot still holds its
    data ("squota space holder"). Never destroyed or cleared here (kernel 6.19 aborts the
    transaction when an extent's owner qgroup is missing)."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    preallocate(workspace / "kept", 8 * MIB)
    btrfs.snapshot(workspace, mnt / "snap", readonly=True)
    workspace_qgroup = qgroup_dir(mnt, btrfs.subvolume_id(workspace))
    before = read_qgroup_dir(workspace_qgroup)

    btrfs.delete_subvolume(workspace, commit=True)
    deadline = Deadline("cleaner", CLEANER_TIMEOUT)
    states = []
    while deadline.elapsed() < 10:
        commit(mnt)
        states.append(read_qgroup_dir(workspace_qgroup))
        time.sleep(1)
    report(
        record_property,
        "space_holder",
        f"before delete {before}; after, every second for 10 s: {states[0]} ... {states[-1]}; "
        f"snapshot still reads: {(mnt / 'snap' / 'kept').stat().st_size} bytes",
    )


# A7. Flipping ro at the cap


def test_flipping_ro_at_the_cap_fails_with_edquot_until_the_cap_is_lifted(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """SUBVOL_SETFLAGS reserves one node against the subvolume's OWN qgroup, so sealing a
    former workspace at its cap as the undo point fails: T03b-2 uncaps it first."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    past = push_past_cap(mnt, workspace)

    with pytest.raises(SnapshotNoSpace) as excinfo:
        btrfs.set_readonly(workspace, True)
    assert excinfo.value.errno == errno.EDQUOT
    assert not btrfs.is_readonly(workspace)

    quota_volume.set_limit(workspace, None)
    btrfs.set_readonly(workspace, True)
    assert btrfs.is_readonly(workspace)
    report(record_property, "ro_flip", f"past the cap by {past.referenced - SMALL_CAP} bytes")


def test_clearing_ro_to_delete_at_the_cap_fails_until_the_cap_is_lifted(
    quota_volume: QuotaVolume,
) -> None:
    """delete_subvolume clears ro first, so pruning a capped read-only subvolume fails too."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    push_past_cap(mnt, workspace)
    quota_volume.set_limit(workspace, None)
    btrfs.set_readonly(workspace, True)
    quota_volume.set_limit(workspace, SMALL_CAP)  # a read-only subvolume at its cap

    with pytest.raises(SnapshotNoSpace) as excinfo:
        btrfs.set_readonly(workspace, False)
    assert excinfo.value.errno == errno.EDQUOT
    with pytest.raises(SnapshotNoSpace):
        btrfs.delete_subvolume(workspace, commit=True)
    assert btrfs.is_readonly(workspace)

    quota_volume.set_limit(workspace, None)
    btrfs.delete_subvolume(workspace, commit=True)
    assert not os.path.lexists(workspace)


# A8. What the cap does not block


def test_snapshots_renames_and_deletes_in_root_ignore_the_cap(quota_volume: QuotaVolume) -> None:
    """They reserve against the parent directory's subvolume (0/5, uncapped), so take(), the
    staging copy, the swap and pruning keep working with the workspace past its cap."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    push_past_cap(mnt, workspace)
    (mnt / "snapshots").mkdir()

    btrfs.snapshot(workspace, mnt / "snapshots" / "taken", readonly=True)
    btrfs.snapshot(workspace, mnt / "workspace.restore", readonly=False)
    exchange(mnt, "workspace.restore", "workspace")
    rename(mnt, "workspace.restore", "snapshots/.incoming-x")  # the capped one, to another dir

    capped = mnt / "snapshots" / ".incoming-x"
    assert btrfs.qgroup_usage(capped).limit == SMALL_CAP
    with pytest.raises(OSError) as excinfo:
        (capped / "more").write_bytes(SMALL_FILE)
    assert excinfo.value.errno == errno.EDQUOT  # still at its cap: the moves were not blocked
    for uncapped in (mnt / "snapshots" / "taken", mnt / "past-cap", mnt / "workspace"):
        btrfs.delete_subvolume(uncapped, commit=True)
        assert not os.path.lexists(uncapped)


# A10. Setting a cap with the metadata full


def test_qgroup_limit_with_metadata_full_leaves_the_volume_writable(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """On 6.19.10 the qgroup ioctls join the transaction without reserving metadata (fixed
    later upstream), so moving a cap when metadata is full might abort the transaction. It
    must work or fail cleanly, never turn the volume read-only (if it did: Plan B, cap the
    staging copy at birth with SNAP_CREATE_V2 and QGROUP_INHERIT_SET_LIMITS)."""
    mnt = quota_volume.mnt
    since = time.time()
    workspace = make_subvolume(mnt / "workspace")
    filler = make_subvolume(mnt / "filler")
    data = fill_by_preallocating(filler)
    small = fill_with_small_files(filler / "small")
    full = space(mnt)
    assert (data.errno, small.errno) == (errno.ENOSPC, errno.ENOSPC)
    # The precondition: metadata, not data, is what ran out. Creating an empty file reserves
    # metadata only, and there is no room left for another metadata chunk.
    assert small.call == "create", small
    assert full.unallocated < 16 * MIB, full.summary()
    assert full.metadata_total - full.metadata_used - full.global_rsv < 8 * MIB, full.summary()

    capped = try_set_limit(quota_volume, workspace, SMALL_CAP)
    capped_reads = btrfs.qgroup_usage(workspace).limit
    lifted = try_set_limit(quota_volume, workspace, None)

    os.unlink(filler / "small" / "f0")
    commit(mnt)
    problems = kernel_btrfs_problems(mnt, since)
    report(
        record_property,
        "limit_with_metadata_full",
        f"after {small.summary('small files')}: {full.summary()}; qgroup limit: {capped} "
        f"(reads {capped_reads}); limit none: {lifted}; kernel log: "
        f"{'not readable' if problems is None else problems or 'clean'}",
    )
    assert "ro" not in mount_options(mnt)
    assert not (filler / "small" / "f0").exists()
    assert problems in (None, [])


# A11. copy_file_range: reflinks the seccomp rule for 0x94 does not stop


# Runs inside the agent's container (python3 and node of the image). Prints one JSON object.
CLONE_PROBE = r"""
import json, os, subprocess, sys

base = sys.argv[1]
src = os.path.join(base, "src.bin")
with open(src, "wb") as f:
    f.write(os.urandom(1 << 20))
    os.fsync(f.fileno())

def copy_file_range(dst):
    with open(src, "rb") as s, open(dst, "wb") as d:
        try:
            return os.copy_file_range(s.fileno(), d.fileno(), 1 << 20)
        except OSError as e:
            return -e.errno

def run(*argv):
    done = subprocess.run(argv, capture_output=True, text=True)
    return [done.returncode, done.stderr.strip()[-200:]]

def out(name):
    return os.path.join(base, name + ".bin")

def read_write(dst):
    with open(src, "rb") as s, open(dst, "wb") as d:
        d.write(s.read())
        d.flush()
        os.fsync(d.fileno())
    return 0

NODE_COPY = "require('fs').copyFileSync(process.argv[1], process.argv[2], +process.argv[3])"
print(json.dumps({
    "read_write": read_write(out("read_write")),  # the control: a real copy
    "copy_file_range": copy_file_range(out("copy_file_range")),
    "cp": run("cp", src, out("cp")),
    "cp_reflink_auto": run("cp", "--reflink=auto", src, out("cp_reflink_auto")),
    "node_copyfile": run("node", "-e", NODE_COPY, src, out("node_copyfile"), "0"),
    "node_copyfile_ficlone": run("node", "-e", NODE_COPY, src, out("node_copyfile_ficlone"), "2"),
}))
"""


def test_a_clone_stays_charged_to_its_owner_and_the_cloner_pays_only_metadata(
    quota_volume: QuotaVolume, record_property: Callable[[str, object], None]
) -> None:
    """A reflink adds no data: the extent stays charged to the subvolume that wrote it, so a
    clone of 32 MiB fits under a 16 MiB cap. The cloner pays its fs-tree items; the
    extent-tree backrefs each clone adds are charged to nobody (measured here)."""
    mnt = quota_volume.mnt
    owner = make_subvolume(mnt / "owner")
    cloner = capped_subvolume(quota_volume, "cloner", 16 * MIB)
    write_file(owner / "big.bin", 32 * MIB)
    write_file(owner / "block.bin", 4 * KIB)
    owner_before, cloner_before = usage(owner), usage(cloner)

    assert clone(owner / "big.bin", cloner / "big.bin") == 32 * MIB

    owner_after, cloner_after, before = usage(owner), usage(cloner), space(mnt)
    assert shares_extents(cloner / "big.bin", owner / "big.bin")
    assert owner_after.referenced == owner_before.referenced
    assert cloner_after.referenced - cloner_before.referenced < MIB

    clones = 20_000
    with open(owner / "block.bin", "rb") as src, open(cloner / "blocks.bin", "xb") as dst:
        for index in range(clones):
            os.copy_file_range(src.fileno(), dst.fileno(), 4 * KIB, 0, index * 4 * KIB)
    many, after = usage(cloner), space(mnt)
    charged = many.referenced - cloner_after.referenced
    metadata = after.metadata_used - before.metadata_used
    report(
        record_property,
        "clones",
        f"32 MiB clone: cloner +{cloner_after.referenced - cloner_before.referenced} bytes, "
        f"owner +{owner_after.referenced - owner_before.referenced}; {clones} clones of one "
        f"4 KiB block: charged {mib(charged)} ({charged / clones:.0f} B/clone), metadata "
        f"+{mib(metadata)} logical, uncharged {(metadata - charged) / clones:.0f} B/clone "
        f"= {(metadata - charged) / charged:.2f} x charged (x2 raw with DUP)",
    )
    assert usage(owner).referenced == owner_before.referenced


# A13. Deletes after a snapshot are not quota-checked


@pytest.mark.parametrize(
    ("cap", "rounds"),
    [(64 * MIB, 2), (TEST_CAP, 1), (160 * MIB, 1)],  # 64 MiB: the ratio; the others: room
    ids=lambda value: mib(value) if value > MIB else f"rounds={value}",
)
def test_deletes_after_a_snapshot_push_the_subvolume_past_its_cap(
    quota_volume: QuotaVolume,
    cap: int,
    rounds: int,
    record_property: Callable[[str, object], None],
) -> None:
    """Each delete copies the leaf a snapshot shares and charges the copy without a check:
    one delete per leaf after each snapshot costs about the whole fs tree again. T04 pauses
    the agent when referenced passes its limit; this measures by how much, and checks that
    with the test cap one such round still leaves room for a rewind."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", cap)
    fill = fill_with_small_files(workspace / "small")
    assert fill.errno == errno.EDQUOT
    lines = [f"cap {mib(cap)}, {fill.summary('files')}: {state(quota_volume, workspace)}"]

    for round_ in range(rounds):
        btrfs.snapshot(workspace, mnt / f"round-{round_}", readonly=True)
        started = time.monotonic()
        stopped = delete_every(workspace / "small", fill.amount, first=round_, stride=DELETE_STRIDE)
        seconds = time.monotonic() - started
        found = usage(workspace)
        lines.append(
            f"round {round_ + 1}, snapshot + every {DELETE_STRIDE}th file deleted in "
            f"{seconds:.1f} s (stopped: {stopped}): {state(quota_volume, workspace)}"
        )
        assert stopped is None
        assert found.limit is not None
        assert found.referenced > found.limit
    rewind = try_rewind(quota_volume, workspace, cap)
    report(
        record_property,
        f"deletes_after_snapshot_{cap // MIB}",
        "; ".join([*lines, f"rewind: {rewind}"]),
    )
    assert rewind == "ok"


# A14. Data, then metadata: data chunks that stay allocated. The cap is one number for data
# and metadata and does not see chunks, and a data chunk cannot hold metadata.

UNIT_WRITERS: dict[str, Callable[[Path, int], None]] = {
    "fallocate": preallocate,
    "write": write_data,  # buffered: btrfs allocates more data chunks than the data needs
}


@pytest.mark.parametrize("cap", [256 * MIB, TEST_CAP, 160 * MIB], ids=mib)
@pytest.mark.parametrize("writer", UNIT_WRITERS)
def test_data_then_metadata_with_every_data_chunk_pinned(
    quota_volume: QuotaVolume,
    writer: str,
    cap: int,
    record_property: Callable[[str, object], None],
) -> None:
    """Fill the cap with 1 MiB files, keep only the first one in each data chunk and delete
    the rest: btrfs gives back only an empty chunk, so one live extent pins it for good, while
    almost the whole cap is free again. Then spend the cap on metadata. Up to TEST_CAP the cap
    must still stop it first and leave room for a rewind; 256 MiB is only recorded."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", cap)
    (workspace / "data").mkdir()
    empty = usage(workspace)
    files, data = fill_with_units(workspace / "data", UNIT_WRITERS[writer])
    charged = usage(workspace).referenced - empty.referenced
    after_data = space(mnt)
    chunks = data_chunks(quota_volume)
    keepers = first_file_in_each_chunk(files, chunks)
    kept = set(keepers.values())
    for path in files:
        if path not in kept:
            path.unlink()
    after_delete = state(quota_volume, workspace)

    metadata = fill_with_small_files(workspace / "small")
    pinned_after_metadata = set(keepers) <= set(data_chunks(quota_volume))
    after_metadata = state(quota_volume, workspace)
    rewind = try_rewind(quota_volume, workspace, cap)
    report(
        record_property,
        f"pinned_data_then_metadata_{writer}_{cap // MIB}",
        f"cap {mib(cap)}, 1 MiB files by {writer} until {errno.errorcode[data.errno]}: charged "
        f"{mib(charged)}, {after_data.summary()}; data chunks (MiB) "
        f"{[(round(start / MIB, 1), round(length / MIB, 1)) for start, length in chunks]}, "
        f"{len(keepers)} pinned by one file each, {len(chunks) - len(keepers)} without data; "
        f"the rest deleted: {after_delete}; metadata {metadata.summary('small files')}: "
        f"{after_metadata}; rewind: {rewind}",
    )
    assert data.errno == errno.EDQUOT
    assert pinned_after_metadata  # every chunk with a keeper was still allocated
    assert metadata.errno in STOP_ERRNOS
    if cap <= TEST_CAP:
        assert metadata.errno == errno.EDQUOT
        assert rewind == "ok"


@pytest.mark.parametrize("cap", [256 * MIB, TEST_CAP, 160 * MIB], ids=mib)
def test_data_then_metadata_before_the_emptied_data_chunks_come_back(
    quota_volume: QuotaVolume, cap: int, record_property: Callable[[str, object], None]
) -> None:
    """Buffered writes of 64 MiB files allocate far more data chunks than the data needs, and
    chunks emptied by deletes come back only some 10 s later (measured; probably because the
    volume is mounted with discard=async). Spend the cap on metadata
    right after deleting all the data, racing that delay. Up to TEST_CAP the cap must still
    stop it first and leave room for a rewind; 256 MiB is only recorded."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", cap)
    (workspace / "data").mkdir()
    data = fill_by_writing(workspace / "data")
    after_data = space(mnt)
    for path in (workspace / "data").iterdir():
        path.unlink()
    deleted = time.monotonic()

    metadata = fill_with_small_files(workspace / "small")
    seconds = time.monotonic() - deleted
    after_metadata = state(quota_volume, workspace)
    rewind = try_rewind(quota_volume, workspace, cap)
    report(
        record_property,
        f"unreturned_data_then_metadata_{cap // MIB}",
        f"cap {mib(cap)}, 64 MiB files by write: {data.summary()}, {after_data.summary()}; all "
        f"deleted; metadata {metadata.summary('small files')}, ending {seconds:.1f} s after "
        f"the deletes: {after_metadata}; rewind: {rewind}",
    )
    assert data.errno == errno.EDQUOT
    assert metadata.errno in STOP_ERRNOS
    if cap <= TEST_CAP:
        assert metadata.errno == errno.EDQUOT
        assert rewind == "ok"


# A15. Docker's SELinux relabel at each start. The jail mounts the workspace with :z, and a
# relabel is one setxattr per file, which reserves metadata against the subvolume's own
# qgroup (like the ro flip, A7).

SELINUX_XATTR = "security.selinux"
# Runs in the container: small files like fill_with_small_files, until it fails.
CONTAINER_FILL = r"""
import os, sys

directory = sys.argv[1]
os.mkdir(directory)
count = 0
try:
    while True:
        with open(os.path.join(directory, f"f{count}"), "xb") as f:
            f.write(b"x" * 2000)
        count += 1
except OSError as e:
    print(count, e.errno)
"""


def throwaway_container(
    image: str, name: str, source: Path, *command: str
) -> subprocess.CompletedProcess[str]:
    """``docker run`` with ``source`` mounted like the jail's workspace (``:z``), as the test
    user, without network or capabilities. Without ``command`` it only starts (``true``):
    the start is where Docker relabels."""
    entrypoint, *args = command or ("true",)
    return jail_docker.run(
        [
            "run",
            "--rm",
            "--name",
            name,
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "-v",
            f"{source}:{CONTAINER_WORKSPACE}:z",
            "--entrypoint",
            entrypoint,
            image,
            *args,
        ],
        check=False,
        timeout=FILL_TIMEOUT,
    )


def first_line(text: str) -> str:
    return next(iter(text.strip().splitlines()), "")


def selinux_label(path: Path) -> str:
    return os.getxattr(path, SELINUX_XATTR, follow_symlinks=False).rstrip(b"\0").decode()


def test_docker_relabel_at_start_fails_past_the_cap_only_for_files_labeled_otherwise(
    quota_volume: QuotaVolume,
    agent_image: str,
    agent_leftovers: AgentLeftovers,
    record_property: Callable[[str, object], None],
) -> None:
    """Docker relabels only the files whose label is not exactly the one it sets, and the
    files the agent creates in the container already have it. So a start with the workspace
    past its cap works and charges nothing. A file created from the host has another label
    (unconfined_u): past the cap, the next start fails with EDQUOT and the container does not
    start (fail closed). With the cap lifted, the same start relabels it."""
    mnt = quota_volume.mnt
    workspace = capped_subvolume(quota_volume, "workspace", SMALL_CAP)
    agent_dir = workspace / "agente"
    agent_dir.mkdir()
    names = [agent_leftovers.names(os.getpid())[0] for _ in range(4)]
    try:
        fill = throwaway_container(
            agent_image, names[0], agent_dir, "python3", "-c", CONTAINER_FILL, "/workspace/small"
        )
        assert fill.returncode == 0, fill.stderr
        files, error = (int(word) for word in fill.stdout.split())
        assert error == errno.EDQUOT, fill.stdout
        past = delete_after_snapshot(mnt, workspace, agent_dir / "small")

        restart = throwaway_container(agent_image, names[1], agent_dir)
        after_restart = usage(workspace)
        quota_volume.set_limit(workspace, None)
        (agent_dir / "from-the-host").write_bytes(SMALL_FILE)
        host_label = selinux_label(agent_dir / "from-the-host")
        quota_volume.set_limit(workspace, SMALL_CAP)
        blocked = throwaway_container(agent_image, names[2], agent_dir)
        quota_volume.set_limit(workspace, None)
        uncapped = throwaway_container(agent_image, names[3], agent_dir)
    finally:
        for name in names:
            jail_docker.run(["rm", "--force", name], check=False)
    labels = {selinux_label(agent_dir), selinux_label(agent_dir / "small" / "f1")}
    report(
        record_property,
        "relabel_at_start",
        f"{files} files made in the container, labeled {labels}; past the cap by "
        f"{past.referenced - SMALL_CAP} bytes: a start exits {restart.returncode} and charges "
        f"{after_restart.referenced - past.referenced} bytes; with one file made from the host "
        f"({host_label}) it exits {blocked.returncode} "
        f"({jail_docker.sanitize(first_line(blocked.stderr))[-200:]}); uncapped, "
        f"{uncapped.returncode}, and the file becomes {selinux_label(agent_dir / 'from-the-host')}",
    )
    assert len(labels) == 1  # the agent's files carry the root's label
    assert restart.returncode == 0, restart.stderr
    assert after_restart.referenced == past.referenced  # nothing relabeled, nothing charged
    assert host_label not in labels
    assert blocked.returncode != 0
    assert "disk quota exceeded" in blocked.stderr.lower()
    assert uncapped.returncode == 0, uncapped.stderr
    assert selinux_label(agent_dir / "from-the-host") in labels


# A11 in the jail. Last: it starts the real agent (module-scoped running_agent).


def test_copy_file_range_in_the_jail_makes_reflinks(
    running_agent, record_property: Callable[[str, object], None]
) -> None:
    """copy_file_range(2) is a syscall, not a 0x94 ioctl, so the T03a seccomp rule lets it
    through, and on btrfs it clones. T03b-2 blocks it (founder decision, 2026-10-06); this
    test then has to show the fallback instead."""
    name = f"clone-probe-{uuid4().hex[:8]}"
    inside = f"{CONTAINER_WORKSPACE}/work/{name}"
    host = running_agent.workspace / "work" / name
    running_agent.exec(["mkdir", inside], check=True)
    try:
        result = running_agent.exec(["python3", "-c", CLONE_PROBE, inside], check=True)
        probe = json.loads(result.stdout)
        shared = {
            copy: shares_extents(host / f"{copy}.bin", host / "src.bin")
            for copy in probe
            if (host / f"{copy}.bin").exists()
        }
    finally:
        running_agent.exec(["rm", "-rf", inside], check=True)
    report(record_property, "clones_in_the_jail", f"results {probe}; reflinked {shared}")
    assert shared["read_write"] is False  # the FIEMAP check tells a copy from a clone
    assert probe["copy_file_range"] == MIB
    assert shared["copy_file_range"] is True
