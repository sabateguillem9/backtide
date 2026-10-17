"""Emergency growth of the volume (T04e-1): a rewind failed for lack of space, so the volume
grows once, within a limit, and the Guardian retries. Design: docs/19-diseno-t04.md, section 6.

- **Never deletes a snapshot to make room.** This module has no access to the store at all:
  if filling the disk made Vigía delete snapshots, the agent could erase the evidence that way.
- **Grows only, and checks every step by reading it back:** the image file (``grow_file``),
  the loop device that shows it (``set_capacity``: ``losetup --set-capacity``) and the btrfs on
  it (``resize``: ``btrfs filesystem resize max``). A step whose size is already there is
  skipped, so a growth cut half way is finished by the next one, never doubled.
- **Within limits** (docs/19, "Decidido por defecto"): once per failed rewind (per request id),
  never with the agent running, never on a loop that is not backed by the configured image,
  never above ``max_volume_bytes``, and only if the host keeps free, in the image's folder,
  what the sparse image can still take (its new size minus its allocated blocks, so the holes
  of earlier growths count too) plus max(10 %, 2 GiB). The step is S = max(256 MiB, 10 % of
  the volume), rounded up to 64 MiB.
- **Never without its record:** if ``requested`` cannot be written to the black box, nothing
  grows (refused ``blackbox``).
- **The privileged steps are injected** (``PrivilegedSteps``), like ``set_limit`` in T03b: the
  Mac tests use fakes and the VM test its own ``sudo -n``. Nothing in ``vigia/`` runs sudo.
  Until T13 (the installer) decides how Vigía gets that privilege, production has
  ``NOT_CONFIGURED``: every step raises ``GrowNotConfigured``, so a growth is requested,
  recorded as failed at its first step, and nothing on disk changes. ``truncate_grow``,
  ``set_capacity_argv`` and ``resize_argv`` are the pieces T13 (and the VM test) put together.
- **Recorded:** ``snapshot/volume_grow`` with ``phase`` ``refused`` (nothing was tried, and
  why), or ``requested`` and then ``done`` or ``failed`` (the step, its error and the steps
  done before it). ``failed`` is risk 3: the volume may be half grown (a bigger file that the
  loop device does not show yet).

Reading the sizes needs no privilege (``SystemProbe``): ``/proc/self/mountinfo``,
``/sys/block/loopN``, ``stat`` and BTRFS_IOC_DEV_INFO.
"""

import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from vigia.snapshots import space
from vigia.snapshots.model import SnapshotError
from vigia.snapshots.space import GIB, MIB

STEP_MIN = 256 * MIB
STEP_ALIGN = 64 * MIB
STEP_PCT = 10
HOST_MARGIN_MIN = 2 * GIB
HOST_MARGIN_PCT = 10
SECTOR = 512  # /sys/block/<dev>/size counts 512-byte sectors, whatever the device
MAX_ERROR_CHARS = 500
MAX_REMEMBERED = 64  # request ids that already grew, kept in memory

MOUNTINFO = Path("/proc/self/mountinfo")
SYS_BLOCK = Path("/sys/block")
_LOOP_RE = re.compile(r"/dev/(loop[0-9]{1,6})", re.ASCII)
_DECIMAL_RE = re.compile(r"(0|[1-9][0-9]{0,19})\n?", re.ASCII)
_OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


class GrowError(Exception):
    """A step of the growth cannot be done."""


class GrowNotConfigured(GrowError):
    """Vigía has no way to run the privileged steps yet (T13 decides how)."""


class PrivilegedSteps(Protocol):
    """The three steps that change sizes. Each raises on failure; none is ever asked to shrink."""

    def grow_file(self, image: Path, size: int) -> None:
        """Make the image file ``size`` bytes long (sparse). Needs to own the file."""
        ...

    def set_capacity(self, loop: str) -> None:
        """``losetup --set-capacity /dev/<loop>``: the loop device shows the new file size.
        Needs CAP_SYS_ADMIN."""
        ...

    def resize(self, mount: Path) -> None:
        """``btrfs filesystem resize max <mount>``: btrfs takes the whole device. Needs
        CAP_SYS_ADMIN."""
        ...


class _NotConfigured:
    """Production until T13: no privilege, so every step says so and nothing changes."""

    _MESSAGE = (
        "growing the volume is not configured yet: Vigía has no privilege to run "
        "losetup --set-capacity and btrfs filesystem resize (the installer, T13, sets it up)"
    )

    def grow_file(self, image: Path, size: int) -> None:
        raise GrowNotConfigured(self._MESSAGE)

    def set_capacity(self, loop: str) -> None:
        raise GrowNotConfigured(self._MESSAGE)

    def resize(self, mount: Path) -> None:
        raise GrowNotConfigured(self._MESSAGE)


NOT_CONFIGURED: PrivilegedSteps = _NotConfigured()


@dataclass(frozen=True)
class MountedOn:
    """The mount that holds the volume: its mount point, type and source device."""

    mount_point: Path
    fs_type: str
    source: str


class VolumeProbe(Protocol):
    """The unprivileged readings the growth checks against (``SystemProbe`` in production)."""

    def mount_of(self, path: Path) -> MountedOn: ...

    def backing_file(self, loop: str) -> Path: ...

    def loop_bytes(self, loop: str) -> int: ...

    def file_bytes(self, image: Path) -> int: ...

    def allocated_bytes(self, image: Path) -> int: ...

    def fs_bytes(self, mount: Path) -> int: ...

    def host(self, folder: Path) -> space.HostSpace: ...


class SystemProbe:
    """The real readings. Raises SnapshotError for anything it cannot read or does not expect."""

    def __init__(self, *, mountinfo: Path = MOUNTINFO, sys_block: Path = SYS_BLOCK) -> None:
        self._mountinfo = mountinfo
        self._sys_block = sys_block

    def mount_of(self, path: Path) -> MountedOn:
        """The mount on top whose mount point is ``path`` or its closest parent."""
        resolved = Path(os.path.realpath(path))
        best: MountedOn | None = None
        try:
            lines = self._mountinfo.read_text().splitlines()
        except OSError as error:
            raise SnapshotError(f"cannot read {self._mountinfo}: {error}") from error
        for line in lines:
            mount = parse_mountinfo_line(line)
            if not resolved.is_relative_to(mount.mount_point):
                continue
            # The longest mount point wins; at equal length the later one is on top.
            if best is None or len(mount.mount_point.parts) >= len(best.mount_point.parts):
                best = mount
        if best is None:
            raise SnapshotError(f"no mount holds {resolved}")
        return best

    def backing_file(self, loop: str) -> Path:
        text = self._read(self._loop_dir(loop) / "loop" / "backing_file")
        return Path(text.rstrip("\n"))

    def loop_bytes(self, loop: str) -> int:
        path = self._loop_dir(loop) / "size"
        text = self._read(path)
        if not _DECIMAL_RE.fullmatch(text):
            raise SnapshotError(f"unexpected content in {path}: {text[:40]!r}")
        return int(text) * SECTOR

    def file_bytes(self, image: Path) -> int:
        try:
            info = os.stat(image, follow_symlinks=False)
        except OSError as error:
            raise SnapshotError(f"cannot read the size of {image}: {error}") from error
        if not stat.S_ISREG(info.st_mode):
            raise SnapshotError(f"{image} is not a regular file")
        return info.st_size

    def allocated_bytes(self, image: Path) -> int:
        """What the (sparse) image really takes on the host disk now: its allocated blocks."""
        try:
            info = os.stat(image, follow_symlinks=False)
        except OSError as error:
            raise SnapshotError(f"cannot read the blocks of {image}: {error}") from error
        if not stat.S_ISREG(info.st_mode):
            raise SnapshotError(f"{image} is not a regular file")
        return info.st_blocks * SECTOR

    def fs_bytes(self, mount: Path) -> int:
        """What btrfs uses of its only device (BTRFS_IOC_DEV_INFO), not the image's size."""
        info = space.fs_info(mount)
        if info.num_devices != 1:
            raise SnapshotError(f"{mount} has {info.num_devices} devices: only one is supported")
        return space.dev_info(mount, info.max_id).total_bytes

    def host(self, folder: Path) -> space.HostSpace:
        return space.host_space(folder)

    def _loop_dir(self, loop: str) -> Path:
        if not re.fullmatch(r"loop[0-9]{1,6}", loop, re.ASCII):
            raise SnapshotError(f"{loop!r} is not a loop device name")
        return self._sys_block / loop

    @staticmethod
    def _read(path: Path) -> str:
        try:
            return path.read_text()
        except OSError as error:
            raise SnapshotError(f"cannot read {path}: {error}") from error


def parse_mountinfo_line(line: str) -> MountedOn:
    """One line of /proc/self/mountinfo (proc_pid_mountinfo(5)). Optional fields end at ``-``."""
    fields = line.split(" ")
    try:
        separator = fields.index("-", 6)
        return MountedOn(
            mount_point=Path(_unescape(fields[4])),
            fs_type=fields[separator + 1],
            source=_unescape(fields[separator + 2]),
        )
    except (ValueError, IndexError) as error:
        raise SnapshotError(f"unexpected line in mountinfo: {line[:200]!r}") from error


def loop_name(source: str) -> str | None:
    """``loopN`` for a ``/dev/loopN`` source, None for anything else."""
    match = _LOOP_RE.fullmatch(source)
    return match.group(1) if match else None


def step_for(volume_bytes: int) -> int:
    """S = max(256 MiB, 10 % of the volume), rounded up to 64 MiB: 256 MiB on 1 GiB, 2 GiB on
    20 GiB."""
    wanted = max(STEP_MIN, volume_bytes * STEP_PCT // 100)
    return -(-wanted // STEP_ALIGN) * STEP_ALIGN


def host_margin(host: space.HostSpace, still_to_fill: int) -> int:
    """What the image's folder must keep free on the host: ``still_to_fill`` (what the sparse
    image, once grown, can still take from the host: its new size minus what it has already
    allocated, so the holes of earlier growths count too) plus max(2 GiB, 10 % of the disk)."""
    return max(still_to_fill, 0) + max(HOST_MARGIN_MIN, host.total * HOST_MARGIN_PCT // 100)


# The pieces of the real privileged steps, for T13 and the VM test


def truncate_grow(image: Path, size: int) -> None:
    """Make the regular file ``image`` at least ``size`` bytes long (sparse). Never shrinks it,
    never follows a symlink. Raises GrowError."""
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise GrowError(f"the new size must be a positive number of bytes, got {size!r}")
    try:
        fd = os.open(image, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as error:
        raise GrowError(f"cannot open {image}: {error}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise GrowError(f"{image} is not a regular file")
        if info.st_size >= size:
            return
        os.ftruncate(fd, size)
        os.fsync(fd)
    except OSError as error:
        raise GrowError(f"cannot grow {image} to {size} bytes: {error}") from error
    finally:
        os.close(fd)


def set_capacity_argv(loop: str) -> tuple[str, ...]:
    """The argv of the loop step: ``losetup --set-capacity /dev/<loop>``. Pure."""
    if not re.fullmatch(r"loop[0-9]{1,6}", loop, re.ASCII):
        raise ValueError(f"{loop!r} is not a loop device name")
    return ("losetup", "--set-capacity", f"/dev/{loop}")


def resize_argv(mount: Path) -> tuple[str, ...]:
    """The argv of the btrfs step: ``btrfs filesystem resize max <mount>``. Pure."""
    mount = Path(mount)
    if not mount.is_absolute() or "\0" in str(mount):
        raise ValueError(f"the mount point must be an absolute path, got {str(mount)!r}")
    return ("btrfs", "filesystem", "resize", "max", str(mount))


# The growth


class GrowStatus(StrEnum):
    DONE = "done"  # grown and checked: the rewind may be retried
    REFUSED = "refused"  # nothing was tried (see ``reason``)
    FAILED = "failed"  # a step failed (see ``step``): the volume may be half grown


@dataclass(frozen=True)
class GrowLimits:
    """What a growth needs from the configuration: the image file behind the volume's loop
    device, and the size the volume may never pass."""

    image: Path
    max_volume_bytes: int


@dataclass(frozen=True)
class GrowResult:
    status: GrowStatus
    reason: str | None = None  # why it was refused
    step: str | None = None  # the step that failed: grow_file, set_capacity, resize
    error: str | None = None
    from_bytes: int | None = None
    to_bytes: int | None = None
    reached_bytes: int | None = None
    done_steps: tuple[str, ...] = field(default_factory=tuple)

    @property
    def grown(self) -> bool:
        return self.status is GrowStatus.DONE


# Appends one ``volume_grow`` to the black box; False if it could not be recorded.
type Record = Callable[[dict[str, Any], int], bool]


@dataclass(frozen=True)
class _Plan:
    image: Path
    max_volume_bytes: int
    mount: Path
    loop: str
    fs_bytes: int
    file_bytes: int
    loop_bytes: int
    host_free: int
    to_bytes: int


class _Refused(Exception):  # noqa: N818 - an outcome, not an error
    def __init__(self, reason: str, error: str | None = None, **facts: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.error = error
        self.facts = facts


class VolumeGrower:
    """Grows the volume at ``volume`` once per failed rewind. ``limits`` None means growth is
    not configured: every call is refused (``not_configured``) without reading anything."""

    def __init__(
        self,
        volume: Path | None,
        limits: GrowLimits | None,
        *,
        steps: PrivilegedSteps = NOT_CONFIGURED,
        probe: VolumeProbe | None = None,
    ) -> None:
        self._volume = volume
        self._limits = limits
        self._steps = steps
        self._probe: VolumeProbe = probe if probe is not None else SystemProbe()
        self._grown: list[str] = []

    @property
    def configured(self) -> bool:
        return self._volume is not None and self._limits is not None

    @property
    def can_grow(self) -> bool:
        """Configured AND given real privileged steps (not the ``NOT_CONFIGURED`` stub)."""
        return self.configured and self._steps is not NOT_CONFIGURED

    def grow(
        self, request_id: str, *, agent_stopped: Callable[[], bool], record: Record
    ) -> GrowResult:
        """Grow once for the rewind ``request_id``. Never raises for a failed growth: the
        result says what happened and ``record`` (``snapshot/volume_grow``) has it.

        The caller holds whatever keeps the agent from starting meanwhile (the Guardian's
        ``agent_lock``); ``agent_stopped`` is asked once, before anything changes."""
        if request_id in self._grown:
            return self._refuse(record, request_id, _Refused("already_grown"))
        self._grown = [*self._grown[-(MAX_REMEMBERED - 1) :], request_id]
        try:
            plan = self._plan(agent_stopped)
        except _Refused as refused:
            return self._refuse(record, request_id, refused)
        base: dict[str, Any] = {
            "request_id": request_id,
            "from_bytes": plan.fs_bytes,
            "to_bytes": plan.to_bytes,
        }
        recorded = record(
            {
                "phase": "requested",
                **base,
                "max_volume_bytes": plan.max_volume_bytes,
                "loop": plan.loop,
                "signals": {
                    "fs_bytes": plan.fs_bytes,
                    "file_bytes": plan.file_bytes,
                    "loop_bytes": plan.loop_bytes,
                    "host_free": plan.host_free,
                },
            },
            2,
        )
        if not recorded:
            # Growing changes the host: never without its record (the rewind itself goes on
            # without one because it is the person's safety action; growing is not).
            return self._refuse(record, request_id, _Refused("blackbox", **base_facts(plan)))
        done: list[str] = []
        skipped: list[str] = []
        step = "grow_file"
        try:
            if plan.file_bytes < plan.to_bytes:
                self._steps.grow_file(plan.image, plan.to_bytes)
                self._check(step, self._probe.file_bytes(plan.image), plan.to_bytes)
                done.append(step)
            else:
                skipped.append(step)
            step = "set_capacity"
            if plan.loop_bytes < plan.to_bytes:
                self._steps.set_capacity(plan.loop)
                self._check(step, self._probe.loop_bytes(plan.loop), plan.to_bytes)
                done.append(step)
            else:
                skipped.append(step)
            step = "resize"
            self._steps.resize(plan.mount)
            reached = self._probe.fs_bytes(plan.mount)
            self._check(step, reached, plan.to_bytes)
            done.append(step)
        except Exception as error:  # every failure is recorded and returned, never swallowed
            text = _short(error)
            record(
                {
                    "phase": "failed",
                    **base,
                    "step": step,
                    "error": text,
                    "not_configured": isinstance(error, GrowNotConfigured),
                    "done_steps": done,
                    "skipped_steps": skipped,
                },
                3,
            )
            return GrowResult(
                GrowStatus.FAILED,
                reason="not_configured" if isinstance(error, GrowNotConfigured) else None,
                step=step,
                error=text,
                from_bytes=plan.fs_bytes,
                to_bytes=plan.to_bytes,
                done_steps=tuple(done),
            )
        record(
            {
                "phase": "done",
                **base,
                "reached_bytes": reached,
                "done_steps": done,
                "skipped_steps": skipped,
            },
            2,
        )
        return GrowResult(
            GrowStatus.DONE,
            from_bytes=plan.fs_bytes,
            to_bytes=plan.to_bytes,
            reached_bytes=reached,
            done_steps=tuple(done),
        )

    def _plan(self, agent_stopped: Callable[[], bool]) -> _Plan:
        """Every check that comes before anything changes. Raises _Refused."""
        if self._volume is None or self._limits is None:
            raise _Refused("not_configured")
        try:
            stopped = agent_stopped()
        except Exception as error:
            raise _Refused("agent_state_unknown", _short(error)) from error
        if not stopped:
            raise _Refused("agent_running")
        image, ceiling = self._limits.image, self._limits.max_volume_bytes
        try:
            mount = self._probe.mount_of(self._volume)
            loop = loop_name(mount.source)
            if mount.fs_type != "btrfs" or loop is None:
                raise _Refused("not_a_loop")
            backing = self._probe.backing_file(loop)
            if os.path.realpath(backing) != os.path.realpath(image):
                raise _Refused("not_the_image")
            fs_bytes = self._probe.fs_bytes(mount.mount_point)
            file_bytes = self._probe.file_bytes(image)
            allocated = self._probe.allocated_bytes(image)
            loop_bytes = self._probe.loop_bytes(loop)
            host = self._probe.host(image.parent)
        except _Refused:
            raise
        except Exception as error:
            raise _Refused("unreadable", _short(error)) from error
        step = step_for(fs_bytes)
        to_bytes = fs_bytes + step
        facts = {"from_bytes": fs_bytes, "to_bytes": to_bytes, "max_volume_bytes": ceiling}
        # resize max takes the whole device, so neither the file nor the loop may already be
        # above the ceiling either.
        if max(to_bytes, file_bytes, loop_bytes) > ceiling:
            raise _Refused("ceiling", file_bytes=file_bytes, loop_bytes=loop_bytes, **facts)
        need = host_margin(host, max(to_bytes, file_bytes) - allocated)
        if host.free < need:
            raise _Refused("host_space", host_free=host.free, host_needed=need, **facts)
        return _Plan(
            image=image,
            max_volume_bytes=ceiling,
            mount=mount.mount_point,
            loop=loop,
            fs_bytes=fs_bytes,
            file_bytes=file_bytes,
            loop_bytes=loop_bytes,
            host_free=host.free,
            to_bytes=to_bytes,
        )

    @staticmethod
    def _check(step: str, reached: int, wanted: int) -> None:
        if reached < wanted:
            raise GrowError(f"after {step} the size is {reached} bytes, not {wanted}")

    @staticmethod
    def _refuse(record: Record, request_id: str, refused: _Refused) -> GrowResult:
        details: dict[str, Any] = {
            "phase": "refused",
            "request_id": request_id,
            "reason": refused.reason,
            **refused.facts,
        }
        if refused.error is not None:
            details["error"] = refused.error
        record(details, 2)
        return GrowResult(
            GrowStatus.REFUSED,
            reason=refused.reason,
            error=refused.error,
            from_bytes=refused.facts.get("from_bytes"),
            to_bytes=refused.facts.get("to_bytes"),
        )


def base_facts(plan: _Plan) -> dict[str, int]:
    return {"from_bytes": plan.fs_bytes, "to_bytes": plan.to_bytes}


def _unescape(text: str) -> str:
    """mountinfo writes space, tab, newline and backslash as octal escapes like ``\\040``."""
    return _OCTAL_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), text)


def _short(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]


__all__ = [
    "NOT_CONFIGURED",
    "GrowError",
    "GrowLimits",
    "GrowNotConfigured",
    "GrowResult",
    "GrowStatus",
    "MountedOn",
    "PrivilegedSteps",
    "SystemProbe",
    "VolumeGrower",
    "VolumeProbe",
    "host_margin",
    "loop_name",
    "parse_mountinfo_line",
    "resize_argv",
    "set_capacity_argv",
    "step_for",
    "truncate_grow",
]
