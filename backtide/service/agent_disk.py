"""What an agent other than the main one has on the machine's disk (T26-6a; docs/47, 6.3 and 8.2).

The main agent's volume and channel are mounted by units the installer wrote, which run before the
service. The others come and go while the service runs, and what the hardened service mounts itself
stays in its own mount namespace, where Docker never sees it (docs/25, section 1). So the service
asks systemd: ``systemd-mount`` starts a transient mount unit in the machine's namespace, and it
shows up in the service's too. Measured under the real unit, in vigia-dev: the btrfs in its file
with its loop device, the tmpfs, ``mkfs.btrfs``, the filter of calls and the read-only ``/etc``.

Transient units do not survive a reboot, on purpose: nothing is written in ``/etc/systemd`` and the
service needs no right to write there. ``ensure_on_disk`` runs every time an agent is about to
start, also after a reboot, and mounts what is not there.

The check, ``volume_problem``, is what stops the worst of it: on a machine whose disk is btrfs, a
volume that is not mounted would be a plain folder of that disk, and everything would work with no
cap at all (review of T26-2b). So ``volume`` must be the mount point of a btrfs on a loop device
whose file is this agent's image. Whoever writes a file by hand has the same rule.

Outside a unit (a test, ``make demo``) nothing is mounted here: the check still holds.
"""

import os
from collections.abc import Callable
from pathlib import Path

from backtide.jail.proxy_config import CHANNEL_SIZE, CHANNEL_TMPFS_SOURCE, channel_tmpfs_options
from backtide.service.agents import image_of
from backtide.service.config import ServiceConfig
from backtide.setup import host
from backtide.setup.host import Runner
from backtide.setup.volume import MOUNTPOINT_MODE, VolumeError, prepare_mountpoint

SYSTEMD_RUN_MARK = "INVOCATION_ID"  # systemd sets it for every service it runs
AGENT_VOLUMES_ENV = "BACKTIDE_AGENT_VOLUMES"  # where the unit says the agents' volumes go
MOUNTINFO = Path("/proc/self/mountinfo")
_LOOP_BACKING = "/sys/block/{name}/loop/backing_file"
VOLUME_OPTIONS = "loop,noatime,nosuid,nodev"  # those of deploy/systemd/volume.mount.in
STOPPED_MARK = "stopped"  # in the agent's folder: the owner stopped it, and a restart respects it
_MAX_BACKING = 4096


class AgentDiskError(Exception):
    """An agent's volume or channel is not as it must be. It does not start."""


def under_unit() -> bool:
    return SYSTEMD_RUN_MARK in os.environ


def volume_mount_argv(image: Path, volume: Path) -> tuple[str, ...]:
    return (
        "systemd-mount", "--no-ask-password", "--no-pager", "--collect", "--type=btrfs",
        f"--options={VOLUME_OPTIONS}", str(image), str(volume),
    )  # fmt: skip


def channel_mount_argv(channel: Path, uid: int, gid: int) -> tuple[str, ...]:
    options = channel_tmpfs_options(CHANNEL_SIZE, uid, gid)
    return (
        "systemd-mount", "--no-ask-password", "--no-pager", "--collect", "--type=tmpfs",
        f"--options={options}", CHANNEL_TMPFS_SOURCE, str(channel),
    )  # fmt: skip


def umount_argv(point: Path) -> tuple[str, ...]:
    return ("systemd-umount", "--no-ask-password", "--no-pager", str(point))


def read_mountinfo() -> str:
    return MOUNTINFO.read_text(encoding="utf-8", errors="surrogateescape")


def read_backing(device: str) -> str | None:
    """The file behind a loop device (``loop3``), or None if it is not one that has a file."""
    try:
        with open(_LOOP_BACKING.format(name=device), encoding="utf-8") as found:
            return found.read(_MAX_BACKING).strip()
    except OSError:
        return None


def mounted_at(point: Path, mountinfo: str) -> tuple[str, str] | None:
    """What is on top at ``point`` (links resolved): its type and its source. None if nothing."""
    real = os.path.realpath(point)
    found = None
    for line in mountinfo.splitlines():
        left, separator, right = line.partition(" - ")
        fields, tail = left.split(), right.split()
        if separator and len(fields) >= 5 and len(tail) >= 2 and _unescape(fields[4]) == real:
            found = (tail[0], _unescape(tail[1]))  # the last one is the one on top
    return found


def _unescape(field: str) -> str:
    """mountinfo writes space, tab, newline and backslash as octal escapes."""
    for octal, plain in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        field = field.replace(octal, plain)
    return field


def volume_problem(
    config: ServiceConfig,
    *,
    mountinfo: Callable[[], str] = read_mountinfo,
    backing: Callable[[str], str | None] = read_backing,
) -> str | None:
    """Why the volume of ``config`` cannot be used, or None: it must be the mount point of a btrfs
    on a loop device of its own image. Anything else is the machine's disk, or someone else's."""
    volume, image = config.volume, image_of(config)
    found = mounted_at(volume, mountinfo())
    if found is None:
        return f"{volume} is not mounted: it would write on the machine's disk, with no cap"
    kind, source = found
    if kind != "btrfs":
        return f"{volume} is a {kind}, not the btrfs of its image"
    device = source.removeprefix("/dev/")
    file = backing(device) if device.startswith("loop") else None
    if file != os.path.realpath(image):
        return f"{volume} is mounted, but not from {image}"
    return None


def ensure_on_disk(
    config: ServiceConfig,
    *,
    run: Runner = host.run,
    mountinfo: Callable[[], str] = read_mountinfo,
    backing: Callable[[str], str | None] = read_backing,
    mounting: bool | None = None,
) -> None:
    """The volume and the channel of this agent, mounted if they were not (under the unit), and the
    volume checked in any case. Raises AgentDiskError. Run before the agent is built."""
    if under_unit() if mounting is None else mounting:
        if mounted_at(config.volume, mountinfo()) is None:
            image = image_of(config)
            if not os.path.isfile(image):
                raise AgentDiskError(f"its volume's image {image} is not there")
            try:
                prepare_mountpoint(config.volume)
            except VolumeError as error:
                raise AgentDiskError(str(error)) from None
            mount(volume_mount_argv(image, config.volume), run)
        channel = config.proxy_jail_config()
        if mounted_at(channel.channel_dir, mountinfo()) is None:
            try:
                os.mkdir(channel.channel_dir, MOUNTPOINT_MODE)
            except FileExistsError:
                pass  # a folder is fine; anything else, systemd refuses to mount on it
            except OSError as error:
                raise AgentDiskError(
                    f"cannot make {channel.channel_dir}: {error.strerror}"
                ) from None
            mount(channel_mount_argv(channel.channel_dir, channel.uid, channel.gid), run)
    problem = volume_problem(config, mountinfo=mountinfo, backing=backing)
    if problem is not None:
        raise AgentDiskError(problem)


def mount(argv: tuple[str, ...], run: Runner) -> None:
    ran = run(argv)
    if ran is None:
        raise AgentDiskError(f"{argv[0]} is not installed: this machine cannot mount for an agent")
    if ran.returncode != 0:
        said = " ".join((ran.stderr or ran.stdout).split())[:300]
        raise AgentDiskError(f"`{argv[0]} ... {argv[-1]}` failed ({ran.returncode}): {said}")


def seal_root(point: Path, mountinfo: str) -> None:
    """The root of a new volume, which mkfs leaves 0755, goes to 0700, or backtide refuses to start
    on it (T13-1). Never the folder underneath: it must be the btrfs just mounted. Not with
    ``setup.volume.seal_mounted_root``: its ``findmnt`` sees this mount twice from the service's
    namespace, once per bind of its folders."""
    found = mounted_at(point, mountinfo)
    if found is None or found[0] != "btrfs":
        raise AgentDiskError(f"{point} is not mounted as a btrfs: its root stays as it was")
    fd = os.open(point, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(fd, MOUNTPOINT_MODE)
    finally:
        os.close(fd)


def is_stopped(config: ServiceConfig) -> bool:
    """Whether the owner stopped this agent. A file, so a reboot does not start it again."""
    return os.path.lexists(config.agent_dir / STOPPED_MARK)


def mark_stopped(config: ServiceConfig) -> None:
    """Before it stops: if the machine dies half way, it stays stopped. Raises OSError."""
    mark = config.agent_dir / STOPPED_MARK
    os.close(os.open(mark, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))


def clear_stopped(config: ServiceConfig) -> None:
    """Raises OSError if it cannot go: then it would not start after a restart, and it is said."""
    try:
        os.unlink(config.agent_dir / STOPPED_MARK)
    except FileNotFoundError:
        pass
