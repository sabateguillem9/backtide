"""The agent's volume: a sparse file, formatted Btrfs with simple quotas, mounted by systemd.

Design: docs/25, section 1, with what T13-1 changed. The steps, in order (``plan``):
1. ``create_image``: a new file, 0600, never one that exists (O_EXCL, no symlinks). On a Btrfs
   host, ``chattr +C`` while it is still empty (no copy-on-write on top of copy-on-write).
2. ``format_image``: ``mkfs.btrfs -O squota`` (never ``-f``: mkfs then refuses an image that
   already holds a filesystem). Plan B, if this btrfs-progs does not know ``squota``: format
   without it and ``quota enable --simple`` once mounted (T13-1 never needed it).
3. ``prepare_mountpoint``: the mount point, 0700 and ours.
4. The mount unit mounts it (backtide.setup.units; run by the installer, T13-3).
5. ``seal_mounted_root``: the root of the new filesystem, which mkfs leaves 0755, goes to 0700,
   or backtide refuses to start on it (T13-1). It is stored in the filesystem: once is enough.
The workspace subvolume, its cap and the first snapshot are SnapshotStore.init()'s, at the
service's first start. Every command goes through an injected runner (backtide.setup.host).
"""

import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from backtide.jail.docker import sanitize
from backtide.setup import layout
from backtide.setup.host import Ran, Runner

MIB = 1024**2
IMAGE_MODE = 0o600
MOUNTPOINT_MODE = 0o700
_SQUOTA_UNKNOWN = ("unrecognized", "unknown", "invalid")  # mkfs's words for a feature it lacks


class VolumeError(Exception):
    """A volume step failed; the message says what and how to go on (in Spanish)."""


@dataclass(frozen=True)
class Step:
    key: str
    describe: str  # one line, for the person (and --dry-run)


def plan(image: Path, mountpoint: Path, size: int, *, nocow: bool) -> list[Step]:
    steps = [Step("image", f"Crear {image} (0600, nuevo: nunca se pisa uno que exista)")]
    if nocow:
        steps.append(Step("nocow", f"chattr +C {image} (el disco es Btrfs: sin copia sobre copia)"))
    return [
        *steps,
        Step("size", f"Darle {size // layout.GIB} GiB dispersos (solo ocupa lo que se escribe)"),
        Step("format", f"mkfs.btrfs -O squota -L {layout.VOLUME_LABEL} {image}"),
        Step("mountpoint", f"Crear {mountpoint} (0700)"),
        Step("mount", f"Montarlo con su unidad de systemd en {mountpoint}"),
        Step("seal", "Dejar la raíz del volumen en 0700 (mkfs la deja en 0755)"),
    ]


def create_image(image: Path, size: int, *, run: Runner, nocow: bool) -> None:
    """Create the sparse image file. Refuses an existing file or a symlink in its place; if a
    later part fails, the new (still empty) file is removed."""
    if size <= 0 or size % MIB:
        raise ValueError(f"the volume size must be a positive number of MiB, got {size!r}")
    parent = _open_dir(image.parent)  # nobody else may swap the file between our steps
    try:
        _require_private(image.parent, os.fstat(parent))
    finally:
        os.close(parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(image, flags, IMAGE_MODE)
    except FileExistsError:
        raise VolumeError(
            f"{image} ya existe: es la historia del agente y nunca se pisa. Si quieres empezar "
            "de cero, desinstala antes con --borrar-datos."
        ) from None
    except OSError as e:
        raise VolumeError(f"no se puede crear {image}: {e.strerror}") from e
    try:
        os.fchmod(fd, IMAGE_MODE)  # the umask may have taken bits off
        if nocow:
            _check(run, ("chattr", "+C", str(image)))
        os.ftruncate(fd, size)
    except BaseException:
        os.close(fd)
        fd = -1
        os.unlink(image)  # ours: O_EXCL made it a moment ago, and it is still empty
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def mkfs_argv(image: Path, *, squota: bool = True) -> tuple[str, ...]:
    features = ("-O", "squota") if squota else ()
    return ("mkfs.btrfs", *features, "-L", layout.VOLUME_LABEL, str(image))


def quota_enable_argv(mountpoint: Path) -> tuple[str, ...]:
    return ("btrfs", "quota", "enable", "--simple", str(mountpoint))


def format_image(image: Path, *, run: Runner) -> bool:
    """Format the image. True means plan B: run ``quota_enable_argv`` once it is mounted."""
    ran = run(mkfs_argv(image))
    if ran is not None and ran.returncode == 0:
        return False
    error = ran.stderr.lower() if ran is not None else ""
    if "squota" in error and any(word in error for word in _SQUOTA_UNKNOWN):
        _check(run, mkfs_argv(image, squota=False))
        return True
    raise _failed(mkfs_argv(image), ran)


def host_is_btrfs(directory: Path, *, run: Runner) -> bool:
    """Whether ``directory`` lives on Btrfs (then the image needs ``chattr +C``)."""
    return _check(run, ("stat", "-f", "-c", "%T", str(directory))).stdout.strip() == "btrfs"


def prepare_mountpoint(path: Path) -> None:
    """Create the mount point (0700) or check the existing one: a real folder, ours, closed."""
    try:
        os.mkdir(path, MOUNTPOINT_MODE)
    except FileExistsError:
        pass
    except OSError as e:
        raise VolumeError(f"no se puede crear {path}: {e.strerror}") from e
    fd = _open_dir(path)
    try:
        _require_private(path, os.fstat(fd))
    finally:
        os.close(fd)


def findmnt_argv(path: Path) -> tuple[str, ...]:
    """What is mounted exactly at ``path`` (not what contains it): its type and label."""
    return ("findmnt", "-n", "-o", "FSTYPE,LABEL", "--mountpoint", str(path))


def seal_mounted_root(path: Path, *, run: Runner) -> None:
    """Close the root of the freshly mounted volume (0700). Refuses unless ``path`` is the
    mount point of a Btrfs filesystem labelled VOLUME_LABEL: never chmod the folder underneath,
    or another filesystem, by mistake."""
    ran = run(findmnt_argv(path))
    if ran is None or ran.returncode != 0 or ran.stdout.split() != ["btrfs", layout.VOLUME_LABEL]:
        raise VolumeError(
            f"{path} no está montado como el volumen Btrfs de backtide: mira "
            f"`systemctl status` de su unidad de montaje"
        )
    fd = _open_dir(path)
    try:
        if os.fstat(fd).st_uid != os.geteuid():
            raise VolumeError(f"la raíz del volumen {path} no es de quien instala")
        os.fchmod(fd, MOUNTPOINT_MODE)
    finally:
        os.close(fd)


def _open_dir(path: Path) -> int:
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise VolumeError(f"{path} no es una carpeta de verdad: {e.strerror}") from e


def _require_private(path: Path, info: os.stat_result) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != os.geteuid():
        raise VolumeError(f"{path} no es de quien instala (dueño {info.st_uid})")
    if mode & 0o077:
        raise VolumeError(
            f"{path} está en {mode:04o}: tiene que ser 0700, solo de root. Revisa quién la "
            "creó antes de cambiarla."
        )


def _check(run: Runner, argv: Sequence[str]) -> Ran:
    ran = run(argv)
    if ran is None or ran.returncode != 0:
        raise _failed(argv, ran)
    return ran


def _failed(argv: Sequence[str], ran: Ran | None) -> VolumeError:
    command = " ".join(argv)
    if ran is None:
        return VolumeError(f"{argv[0]} no está instalado (hacía falta para `{command}`)")
    detail = sanitize(ran.stderr.strip() or ran.stdout.strip(), 300)
    return VolumeError(f"`{command}` falló ({ran.returncode}): {detail}")
