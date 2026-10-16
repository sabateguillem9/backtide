"""Free space of the volume, read without root, and the pause conditions P1 to P7.

Design: docs/19-diseno-t04.md, section 5, built on the measurements of docs/16.

A workspace cap (T03b) stops the agent from RESERVING more than L, but it does not see what a
cap cannot: deletes after a snapshot (docs/16 A13), data chunks that cannot hold metadata
(A14), the history that snapshots keep, and a failing black box. So Vigía also watches the
volume's own signals and freezes the agent before the metadata run out: without metadata
nothing can be renamed, so nothing can be rewound.

- ``volume_space`` reads the signals: the device from BTRFS_IOC_DEV_INFO and the allocation of
  each kind (data, metadata) from /sys/fs/btrfs/<fsid>/allocation. Never statvfs (with the
  metadata full it still reports free space) and never /sys/block/loopN/size (the size of the
  image file, not what btrfs uses). Unprivileged, nothing swallowed: a signal that cannot be
  read raises SnapshotError.
- ``sample`` reads everything one evaluation needs and turns every failure into a string, so a
  signal that cannot be read is a pause (P4), never a crash or a silent pass.
- ``evaluate_sample`` is the entry point for the guardian: it evaluates a ``sample`` and counts
  every failed read as P4.
- ``evaluate`` is pure: signals in, a list of ``Condition`` out. Empty means the agent may run.
  It does no I/O, so the table tests run it with the numbers measured in the VM.

Nothing here sends a signal to the agent or touches the volume; the guardian (T04d-2) freezes.
"""

import fcntl
import os
import struct
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from vigia.snapshots import btrfs
from vigia.snapshots.model import SnapshotError

KIB = 1024
MIB = 1024**2
GIB = 1024**3

# _IOWR(0x94, 30, struct btrfs_ioctl_dev_info_args): 4096 bytes. No capability check.
BTRFS_IOC_DEV_INFO = 0xD000941E
_DEV_INFO_SIZE = 4096
_DEV_INFO = struct.Struct("<Q16sQQ")  # devid, uuid, bytes_used, total_bytes
# struct btrfs_ioctl_fs_info_args (btrfs.BTRFS_IOC_FS_INFO, 1024 bytes): max_id and num_devices
# first, then the fsid at 16..32 and the nodesize.
_FS_INFO_SIZE = 1024
_FS_INFO = struct.Struct("<QQ16sI")
_U64_MAX = 2**64 - 1

# The allocation files of one kind, in /sys/fs/btrfs/<fsid>/allocation/<kind>/.
_ALLOCATION_FILES = (
    "total_bytes",
    "disk_total",
    "bytes_used",
    "bytes_reserved",
    "bytes_pinned",
    "bytes_may_use",
    "bytes_readonly",
    "bytes_zone_unusable",
)
# With no chunk of a kind yet there is no measured profile: assume it is mirrored (DUP, the
# metadata default), which makes every estimate lower, so the safe side.
_FALLBACK_FACTOR = 2

type Kind = Literal["metadata", "data", "usage", "blind", "uncapped", "host", "blackbox"]


@dataclass(frozen=True)
class SpaceConfig:
    """The numbers of the conditions (docs/19, "Decidido por defecto"). Defaults are the design's.

    P1 budgets what the agent can still spend of metadata between two checks, on top of R:
    - ``cap_tenths`` (2.2 L): its own cap spent on metadata (up to 1.19 L) and one round of
      "snapshot and delete" (up to 0.93 L), both in tenths of the cap L;
    - the data chunks that buffered writes reserve beyond what they need (A14b), which come out
      of metadata through the unallocated space: ``max(overreserve_tenths x L, overreserve_chunks
      x C)``. That is a NUMBER OF CHUNKS, not a multiple of L: 64 MiB of buffered data reserved
      two 112 MiB chunks (1.75 L of metadata); at large caps it is about 2.4 L of chunks (1.2 L
      of metadata), at small caps the chunks dominate;
    - C, one more chunk's worth, because the spend can start with the chunk already half used."""

    reserve: int = (
        32 * MIB
    )  # R: twice what the EXCHANGE needs (it fails with 10 MiB, works at 15.7)
    cap_tenths: int = 22
    overreserve_tenths: int = 12
    overreserve_chunks: int = 2
    max_chunk: int = GIB
    chunk_fraction_pct: int = 10  # btrfs sizes a new chunk at about 10 % of the device
    chunk_round: int = 16 * MIB
    host_min_free: int = GIB
    host_min_free_pct: int = 5
    stale_after: float = 3.0  # seconds without a check, with the agent running (P4)
    blackbox_failures: int = 3  # consecutive failed appends...
    blackbox_failing_for: float = 10.0  # ...for more than this many seconds (P7)
    warn_usage_pct: int = 80  # early warning: referenced over this % of L
    warn_metadata_tenths: int = 15  # early warning: meta_avail under this x P1


DEFAULT_CONFIG = SpaceConfig()


@dataclass(frozen=True)
class DevInfo:
    """BTRFS_IOC_DEV_INFO of the volume's only device: what btrfs sees, not the image's size."""

    devid: int
    total_bytes: int
    bytes_used: int  # raw bytes in chunks of every kind, system included

    @property
    def unallocated(self) -> int:
        """U: what btrfs has not handed out to chunks yet."""
        return max(self.total_bytes - self.bytes_used, 0)


@dataclass(frozen=True)
class FsInfo:
    """BTRFS_IOC_FS_INFO, reduced to what the signals need."""

    fsid: str
    num_devices: int
    max_id: int
    nodesize: int


@dataclass(frozen=True)
class Allocation:
    """One kind of chunk (``data`` or ``metadata``) in /sys/fs/btrfs/<fsid>/allocation/<kind>/.

    Logical bytes, except ``disk_total`` (raw: twice ``total_bytes`` for mirrored metadata)."""

    total_bytes: int
    disk_total: int
    bytes_used: int
    bytes_reserved: int = 0
    bytes_pinned: int = 0
    bytes_may_use: int = 0  # includes the global reserve
    bytes_readonly: int = 0
    bytes_zone_unusable: int = 0

    @property
    def free(self) -> int:
        """Room left inside the chunks that already exist, after everything spoken for."""
        taken = (
            self.bytes_used
            + self.bytes_reserved
            + self.bytes_pinned
            + self.bytes_may_use
            + self.bytes_readonly
            + self.bytes_zone_unusable
        )
        return max(self.total_bytes - taken, 0)

    def from_unallocated(self, unallocated: int) -> int:
        """How much of this kind ``unallocated`` raw bytes can still become: divided by the
        factor f = disk_total / total_bytes (2 for mirrored metadata, 1 for single data). The
        measured factor is used, so the profile never has to be guessed."""
        if self.total_bytes == 0 or self.disk_total == 0:
            return unallocated // _FALLBACK_FACTOR
        return unallocated * self.total_bytes // self.disk_total

    def available(self, unallocated: int) -> int:
        return self.free + self.from_unallocated(unallocated)


@dataclass(frozen=True)
class VolumeSpace:
    """Everything one evaluation reads of the volume."""

    device_total: int  # total_bytes of DEV_INFO
    unallocated: int  # U
    data: Allocation
    metadata: Allocation

    @property
    def meta_avail(self) -> int:
        """Metadata that can still be written: the free room in metadata chunks plus U / f."""
        return self.metadata.available(self.unallocated)

    @property
    def data_avail(self) -> int:
        return self.data.available(self.unallocated)


@dataclass(frozen=True)
class HostSpace:
    """Free space on the disk that holds Vigía's state (the black box grows there, outside the
    volume's cap, and cannot be pruned)."""

    total: int
    free: int


@dataclass(frozen=True)
class Sample:
    """One reading of every signal. A signal that could not be read is None and has its reason
    in ``errors``. ``usage`` is None without error when the volume has no quotas at all."""

    space: VolumeSpace | None
    usage: btrfs.QgroupUsage | None
    host: HostSpace | None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class Health:
    """What the guardian knows that is not a number on the disk (P4 and P7). Defaults: healthy."""

    read_errors: Sequence[str] = ()
    # Seconds since the space thread last finished a check, by time.monotonic() (never the wall
    # clock, which can jump). None means "no check yet" and counts against a running agent, like
    # a negative age (a clock that went backwards): fail closed. The thread's own evaluation
    # of a reading it just took passes 0.0.
    check_age: float | None = None
    agent_running: bool = True  # a stopped agent cannot run code, so a late check is harmless
    blackbox_failures: int = 0  # consecutive failed appends
    blackbox_failing_for: float = 0.0  # seconds since the first of them


@dataclass(frozen=True)
class Condition:
    """One pause condition that holds. ``value`` and ``threshold`` are bytes (or None when the
    condition is not about a quantity); ``message`` has the figures for the log and the alert."""

    code: Literal["P1", "P2", "P3", "P4", "P5", "P6", "P7", "W3", "W1"]
    kind: Kind
    message: str
    value: int | None = None
    threshold: int | None = None

    @property
    def reason(self) -> Literal["space", "blackbox"]:
        """The ``pause_reasons`` entry: only P7 is about the black box, the rest about space."""
        return "blackbox" if self.kind == "blackbox" else "space"


# The signals


def parse_fs_info(buffer: bytes) -> FsInfo:
    """The fields of a BTRFS_IOC_FS_INFO result that matter here. Pure."""
    if len(buffer) < _FS_INFO_SIZE:
        raise SnapshotError(f"BTRFS_IOC_FS_INFO returned {len(buffer)} bytes")
    max_id, num_devices, fsid, nodesize = _FS_INFO.unpack_from(bytes(buffer))
    return FsInfo(
        fsid=str(uuid.UUID(bytes=fsid)),
        num_devices=num_devices,
        max_id=max_id,
        nodesize=nodesize,
    )


def parse_dev_info(buffer: bytes) -> DevInfo:
    """The fields of a BTRFS_IOC_DEV_INFO result that matter here. Pure."""
    if len(buffer) < _DEV_INFO_SIZE:
        raise SnapshotError(f"BTRFS_IOC_DEV_INFO returned {len(buffer)} bytes")
    devid, _uuid, bytes_used, total_bytes = _DEV_INFO.unpack_from(bytes(buffer))
    return DevInfo(devid=devid, total_bytes=total_bytes, bytes_used=bytes_used)


def fs_info(path: Path) -> FsInfo:
    """BTRFS_IOC_FS_INFO of the btrfs that holds the directory ``path``. Unprivileged. Refuses
    a symlink (O_NOFOLLOW)."""
    buffer = bytearray(_FS_INFO_SIZE)
    _ioctl(path, btrfs.BTRFS_IOC_FS_INFO, buffer, "BTRFS_IOC_FS_INFO")
    return parse_fs_info(bytes(buffer))


def dev_info(path: Path, devid: int) -> DevInfo:
    """BTRFS_IOC_DEV_INFO for device ``devid`` of the btrfs that holds ``path``. Unprivileged."""
    buffer = bytearray(_DEV_INFO_SIZE)
    struct.pack_into("<Q", buffer, 0, devid)
    _ioctl(path, BTRFS_IOC_DEV_INFO, buffer, "BTRFS_IOC_DEV_INFO")
    found = parse_dev_info(bytes(buffer))
    if found.devid != devid:
        raise SnapshotError(f"BTRFS_IOC_DEV_INFO on {path} answered for device {found.devid}")
    return found


def volume_space(path: Path, *, sysfs: Path = btrfs.SYSFS_BTRFS) -> VolumeSpace:
    """The space signals of the btrfs that holds ``path`` (docs/19, section 5). Unprivileged.

    U = total_bytes - bytes_used of the device; per kind k, free(k) is what is left inside
    the existing chunks and meta_avail = free(metadata) + U / f(metadata) (data likewise).
    Only a volume of one device is understood; anything else raises SnapshotError, as does any
    signal that cannot be read or is not a decimal u64."""
    path = Path(path)
    info = fs_info(path)
    if info.num_devices != 1:
        raise SnapshotError(
            f"{path} is on a btrfs with {info.num_devices} devices: only one is supported"
        )
    device = dev_info(path, info.max_id)
    allocation = sysfs / info.fsid / "allocation"
    return VolumeSpace(
        device_total=device.total_bytes,
        unallocated=device.unallocated,
        data=_read_allocation(allocation / "data"),
        metadata=_read_allocation(allocation / "metadata"),
    )


def host_space(path: Path) -> HostSpace:
    """Total and available bytes of the disk that holds ``path``. Available means what an
    unprivileged writer could use (``f_bavail``): the smaller, safer number."""
    try:
        st = os.statvfs(path)
    except OSError as e:
        raise SnapshotError(f"cannot read the free space of {path}: {e}", errno=e.errno) from e
    return HostSpace(total=st.f_blocks * st.f_frsize, free=st.f_bavail * st.f_frsize)


def sample(
    root: Path,
    workspace: Path,
    state_dir: Path,
    *,
    sync: bool = False,
    sysfs: Path = btrfs.SYSFS_BTRFS,
) -> Sample:
    """Read every signal one evaluation needs. Never raises SnapshotError or OSError: each
    failure becomes a string in ``errors`` (and a None) for ``evaluate`` to turn into P4.

    ``root`` is the volume's root, ``workspace`` the capped subvolume, ``state_dir`` any path on
    the disk that holds Vigía's data. With ``sync``, ``btrfs filesystem sync`` runs first:
    ``referenced`` only moves when a transaction commits, up to about 30 s later."""
    errors: list[str] = []
    if sync:
        _attempt(errors, "btrfs filesystem sync", lambda: btrfs.run("filesystem", "sync", root))
    space = _attempt(errors, "volume space", lambda: volume_space(root, sysfs=sysfs))
    host = _attempt(errors, "host space", lambda: host_space(state_dir))
    usage = _attempt(errors, "workspace quota", lambda: _workspace_usage(root, workspace, sysfs))
    return Sample(space=space, usage=usage, host=host, errors=tuple(errors))


# The conditions


def chunk_estimate(device_total: int, cfg: SpaceConfig = DEFAULT_CONFIG) -> int:
    """The size of a new data chunk: 10 % of the device rounded up to 16 MiB, at most 1 GiB.
    Matches what was measured: 112 MiB on 1 GiB and 1 GiB on 20 GiB."""
    tenth = device_total * cfg.chunk_fraction_pct // 100
    rounded = -(-tenth // cfg.chunk_round) * cfg.chunk_round
    return min(cfg.max_chunk, rounded)


def metadata_threshold(space: VolumeSpace, limit: int, cfg: SpaceConfig = DEFAULT_CONFIG) -> int:
    """P1's minimum: R + C + max(1.2 L, 2 C) + 2.2 L (see SpaceConfig). C is a data chunk
    expressed in metadata (divided by f). With large caps it is the old R + C + 3.4 L; with
    small ones the two over-reserved chunks dominate."""
    chunk = space.metadata.from_unallocated(chunk_estimate(space.device_total, cfg))
    overreserved = max(limit * cfg.overreserve_tenths // 10, cfg.overreserve_chunks * chunk)
    return cfg.reserve + chunk + overreserved + limit * cfg.cap_tenths // 10


def host_threshold(host: HostSpace, cfg: SpaceConfig = DEFAULT_CONFIG) -> int:
    """P6's minimum: max(1 GiB, 5 % of the disk)."""
    return max(cfg.host_min_free, host.total * cfg.host_min_free_pct // 100)


def evaluate(
    space: VolumeSpace | None,
    usage: btrfs.QgroupUsage | None,
    limit: int,
    host: HostSpace | None,
    cfg: SpaceConfig = DEFAULT_CONFIG,
    health: Health | None = None,
) -> list[Condition]:
    """The pause conditions that hold, in order P1 to P7. Empty: the agent may run. Pure.

    ``limit`` is L, the cap the workspace should have; ``usage`` its qgroup (None: no quotas).
    Anything missing counts against the agent: no ``space`` or ``host`` is P4, no ``usage`` is
    P5 (an agent never runs without a cap)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError(f"limit must be a positive number of bytes, got {limit!r}")
    health = health or Health()
    found: list[Condition] = []

    if space is not None:
        minimum = metadata_threshold(space, limit, cfg)
        if space.meta_avail < minimum:
            found.append(
                Condition(
                    "P1",
                    "metadata",
                    f"metadata: {_mib(space.meta_avail)} left, minimum {_mib(minimum)}",
                    space.meta_avail,
                    minimum,
                )
            )
        if space.data_avail < limit:
            found.append(
                Condition(
                    "P2",
                    "data",
                    f"data: {_mib(space.data_avail)} left, minimum {_mib(limit)}",
                    space.data_avail,
                    limit,
                )
            )
    if usage is not None and usage.referenced > limit:
        found.append(
            Condition(
                "P3",
                "usage",
                f"workspace uses {_mib(usage.referenced)}, over its cap of {_mib(limit)}",
                usage.referenced,
                limit,
            )
        )
    found += _blind(space, host, health, cfg)
    found += _uncapped(usage, limit)
    if host is not None:
        minimum = host_threshold(host, cfg)
        if host.free < minimum:
            found.append(
                Condition(
                    "P6",
                    "host",
                    f"host disk: {_mib(host.free)} free, minimum {_mib(minimum)}",
                    host.free,
                    minimum,
                )
            )
    p7 = blackbox_condition(health.blackbox_failures, health.blackbox_failing_for, cfg)
    if p7 is not None:
        found.append(p7)
    return found


def blackbox_condition(
    failures: int, failing_for: float, cfg: SpaceConfig = DEFAULT_CONFIG
) -> Condition | None:
    """P7 alone: the black box failed ``failures`` appends in a row, for ``failing_for``
    seconds. The guardian checks it with every space check, from its own counters. Pure."""
    if failures >= cfg.blackbox_failures and failing_for > cfg.blackbox_failing_for:
        return Condition(
            "P7",
            "blackbox",
            f"the black box failed {failures} times in a row, for {failing_for:.0f} s: "
            "nothing is being recorded",
        )
    return None


def evaluate_sample(
    reading: Sample,
    limit: int,
    cfg: SpaceConfig = DEFAULT_CONFIG,
    health: Health | None = None,
) -> list[Condition]:
    """THE entry point for the guardian (T04d-2): evaluate a ``sample``, with every read failure
    of the sample merged into ``health.read_errors``, so a signal that could not be read is P4
    even when the caller forgets to pass it on (fail closed). Pure."""
    health = health or Health()
    merged = replace(health, read_errors=(*health.read_errors, *reading.errors))
    return evaluate(reading.space, reading.usage, limit, reading.host, cfg, merged)


def early_warnings(
    space: VolumeSpace | None,
    usage: btrfs.QgroupUsage | None,
    limit: int,
    cfg: SpaceConfig = DEFAULT_CONFIG,
) -> list[Condition]:
    """The "getting low" signals that do not pause: referenced over 80 % of L, or meta_avail
    under 1.5 x P1. Pure. The caller (T04d-2) records ``system/space_low`` at most once an
    hour per condition, and only when ``evaluate`` found nothing."""
    found: list[Condition] = []
    if usage is not None and usage.referenced * 100 > limit * cfg.warn_usage_pct:
        found.append(
            Condition(
                "W3",
                "usage",
                f"workspace uses {_mib(usage.referenced)} of its cap of {_mib(limit)}",
                usage.referenced,
                limit,
            )
        )
    if space is not None:
        minimum = metadata_threshold(space, limit, cfg) * cfg.warn_metadata_tenths // 10
        if space.meta_avail < minimum:
            found.append(
                Condition(
                    "W1",
                    "metadata",
                    f"metadata: {_mib(space.meta_avail)} left, getting close to the minimum "
                    f"(warning under {_mib(minimum)})",
                    space.meta_avail,
                    minimum,
                )
            )
    return found


def _blind(
    space: VolumeSpace | None, host: HostSpace | None, health: Health, cfg: SpaceConfig
) -> list[Condition]:
    """P4: a signal is missing or the checks are late."""
    reasons = list(health.read_errors)
    if space is None and not reasons:
        reasons.append("the volume's space signals are missing")
    if host is None and not reasons:
        reasons.append("the host disk's free space is missing")
    if health.agent_running:
        age = health.check_age
        if age is None:
            reasons.append("no space check yet")
        elif age < 0:
            reasons.append(f"the time since the last check is negative ({age:.1f} s)")
        elif age > cfg.stale_after:
            reasons.append(f"no check for {age:.1f} s (more than {cfg.stale_after:.0f} s)")
    if not reasons:
        return []
    return [Condition("P4", "blind", "cannot see the space: " + "; ".join(reasons))]


def _uncapped(usage: btrfs.QgroupUsage | None, limit: int) -> list[Condition]:
    """P5: the workspace has no cap, or not the configured one (read from the limit bits)."""
    if usage is None:
        return [Condition("P5", "uncapped", "the workspace has no quota information: no cap")]
    if usage.limit is None:
        return [Condition("P5", "uncapped", f"the workspace has no cap (should be {_mib(limit)})")]
    if usage.limit != limit:
        return [
            Condition(
                "P5",
                "uncapped",
                f"the workspace cap is {_mib(usage.limit)}, not {_mib(limit)}",
                usage.limit,
                limit,
            )
        ]
    return []


# Helpers


def _workspace_usage(root: Path, workspace: Path, sysfs: Path) -> btrfs.QgroupUsage | None:
    """The workspace's qgroup, or None on a volume without quotas."""
    if btrfs.quota_mode(root, sysfs=sysfs) is None:
        return None
    return btrfs.qgroup_usage(workspace, sysfs=sysfs)


def _attempt[T](errors: list[str], what: str, read: Callable[[], T]) -> T | None:
    try:
        return read()
    except (SnapshotError, OSError, ValueError) as e:
        errors.append(f"{what}: {e}")
        return None


def _read_allocation(directory: Path) -> Allocation:
    values = {name: _read_u64(directory / name) for name in _ALLOCATION_FILES}
    return Allocation(**values)


def _read_u64(path: Path) -> int:
    try:
        text = path.read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError) as e:
        raise SnapshotError(f"cannot read {path}: {e}", errno=getattr(e, "errno", None)) from e
    digits = text.removesuffix("\n")
    if not digits.isascii() or not digits.isdigit() or int(digits) > _U64_MAX:
        raise SnapshotError(f"unexpected content in {path}: {text!r}")
    if len(digits) > 1 and digits.startswith("0"):
        raise SnapshotError(f"unexpected content in {path}: {text!r}")
    return int(digits)


def _ioctl(path: Path, request: int, buffer: bytearray, name: str) -> None:
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise SnapshotError(f"cannot open {path}: {e}", errno=e.errno) from e
    try:
        fcntl.ioctl(fd, request, buffer)
    except OSError as e:
        raise SnapshotError(f"{name} on {path} failed: {e}", errno=e.errno) from e
    finally:
        os.close(fd)


def _mib(size: int) -> str:
    return f"{size / MIB:.1f} MiB"
