"""`backtide exportar`: the agent's code, out of the jail into a folder the owner names (T17a-4).

Design: docs/34-diseno-t17-cualquier-agente.md, section 7 ("El código ... sale con un push
aprobado o con `backtide exportar`") and decision 7 (no push from the jail yet). The service
copies, never the agent: the agent cannot choose where its files land, nor see that they left.

- The source is a read-only snapshot taken for the export (the Guardian takes it): nothing the
  agent does meanwhile can change what is copied, or swap a folder for a link halfway.
- Nothing from the workspace is followed: every folder is opened with ``O_NOFOLLOW`` relative to
  its parent, a symbolic link is never copied nor followed (it is counted as skipped), and only
  regular files and folders are copied (a FIFO, a socket or a device is skipped; a file is
  opened ``O_NONBLOCK`` so a FIFO never blocks the service).
- The destination is created here, and must not exist yet: nothing is ever overwritten
  (``mkdir`` and ``O_EXCL`` refuse an existing name, a link included). It must be an absolute
  path, without ``..``, whose parent folder exists, and outside what backtide protects (the
  volume, backtide's state: the agent would see it, or it would hold the black box).
- The copies keep only the permission bits that matter (read, write, execute for the owner,
  read and execute for the rest): never setuid, setgid or sticky. They belong to the user the
  service runs as.
- Bounded before anything is written: a first pass counts the files and their bytes and refuses
  an export of more than ``MAX_BYTES`` (a sparse file of a terabyte takes no space in the
  workspace) or ``MAX_ENTRIES`` entries, and folders deeper than ``MAX_DEPTH`` are skipped.
"""

import errno
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 8 * 1024**3  # 8 GiB: a repository, not a disk
MAX_ENTRIES = 500_000
MAX_DEPTH = 128
MAX_PATH = 4096
_CHUNK = 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_KEPT_BITS = 0o755  # rwx for the owner, r-x for the rest: never setuid, setgid or sticky


class ExportError(Exception):
    """The export cannot be done. The message is Spanish, for the owner; it quotes the owner's
    destination, never a name from the workspace."""


@dataclass(frozen=True)
class ExportResult:
    files: int
    folders: int
    bytes: int
    skipped_links: int
    skipped_other: int  # FIFOs, sockets, devices, and folders deeper than MAX_DEPTH

    def details(self) -> dict[str, int]:
        return {
            "files": self.files,
            "folders": self.folders,
            "bytes": self.bytes,
            "skipped_links": self.skipped_links,
            "skipped_other": self.skipped_other,
        }


def check_destination(text: object, protected: Iterable[Path]) -> Path:
    """The owner's destination as a Path, or ExportError: an absolute path without ``..``, NUL or
    trailing separators, whose parent folder exists, that does not exist itself, and that is
    neither inside nor around any of ``protected`` (after resolving the parent's links: the
    owner's own path may have them)."""
    if not isinstance(text, str) or not text or len(text) > MAX_PATH or "\0" in text:
        raise ExportError("la carpeta de destino no es una ruta válida")
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts or os.path.normpath(text) != text:
        raise ExportError(f"el destino tiene que ser una ruta absoluta y sin '..': {text}")
    if path == path.parent:
        raise ExportError("el destino no puede ser la raíz")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        raise ExportError(f"no existe la carpeta donde crear el destino: {path.parent}") from None
    if not parent.is_dir():
        raise ExportError(f"{path.parent} no es una carpeta")
    if os.path.lexists(path):
        raise ExportError(f"ya existe {path}: elige una carpeta nueva (nunca se sobrescribe nada)")
    target = parent / path.name
    for folder in protected:
        guarded = Path(os.path.realpath(folder))
        if target == guarded or target.is_relative_to(guarded) or guarded.is_relative_to(target):
            raise ExportError(
                f"{path} está dentro de lo que backtide protege ({folder}) o lo contiene: elige "
                "otra carpeta"
            )
    return target


def export_tree(source: Path, destination: Path) -> ExportResult:
    """Copy the folder ``source`` (in a read-only snapshot) into the new folder ``destination``
    (checked with check_destination). The last component of ``source`` is opened without
    following a link too. Raises ExportError, with nothing created, if the source cannot be
    opened or is too big; an error halfway leaves what was copied (never deleted: the owner
    decides), and says so."""
    try:
        source_fd = os.open(source, _DIR_FLAGS)
    except OSError as error:
        raise ExportError(
            f"no se puede abrir la carpeta de trabajo del agente en la instantánea "
            f"({os.strerror(error.errno or 0)}): ¿es un enlace?"
        ) from None
    try:
        counted = _count(source_fd)
        if counted.bytes > MAX_BYTES or counted.files + counted.folders > MAX_ENTRIES:
            raise ExportError(
                f"la carpeta de trabajo es demasiado grande para exportarla ({counted.bytes} "
                f"bytes en {counted.files} archivos; el máximo es {MAX_BYTES} bytes y "
                f"{MAX_ENTRIES} entradas)"
            )
        try:
            os.mkdir(destination, 0o755)
        except FileExistsError:
            raise ExportError(f"ya existe {destination}: nunca se sobrescribe nada") from None
        except OSError as error:
            raise ExportError(
                f"no se puede crear {destination}: {os.strerror(error.errno or 0)}"
            ) from None
        try:
            destination_fd = os.open(destination, _DIR_FLAGS)
        except OSError as error:
            raise ExportError(
                f"no se puede abrir {destination}: {os.strerror(error.errno or 0)}"
            ) from None
        try:
            return _copy(source_fd, destination_fd)
        except OSError as error:
            raise ExportError(
                f"la copia a {destination} se ha quedado a medias "
                f"({os.strerror(error.errno or 0)}): lo copiado se queda ahí"
            ) from None
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


@dataclass
class _Tally:
    files: int = 0
    folders: int = 0
    bytes: int = 0
    skipped_links: int = 0
    skipped_other: int = 0

    def result(self) -> ExportResult:
        return ExportResult(
            self.files, self.folders, self.bytes, self.skipped_links, self.skipped_other
        )


def _kind(dir_fd: int, name: str) -> tuple[str, os.stat_result]:
    info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        return "link", info
    if stat.S_ISDIR(info.st_mode):
        return "dir", info
    if stat.S_ISREG(info.st_mode):
        return "file", info
    return "other", info


def _count(root_fd: int) -> ExportResult:
    """What the copy would take, without writing anything."""
    tally = _Tally()
    stack = [(os.dup(root_fd), 0)]
    try:
        while stack:
            fd, depth = stack.pop()
            try:
                for name in sorted(os.listdir(fd)):
                    kind, info = _kind(fd, name)
                    if kind == "file":
                        tally.files += 1
                        tally.bytes += info.st_size
                    elif kind == "dir" and depth + 1 <= MAX_DEPTH:
                        tally.folders += 1
                        stack.append((os.open(name, _DIR_FLAGS, dir_fd=fd), depth + 1))
                    if tally.files + tally.folders > MAX_ENTRIES or tally.bytes > MAX_BYTES:
                        return tally.result()
            finally:
                os.close(fd)
    finally:
        for fd, _ in stack:
            os.close(fd)
    return tally.result()


def _copy(source_fd: int, destination_fd: int) -> ExportResult:
    tally = _Tally()
    stack = [(os.dup(source_fd), os.dup(destination_fd), 0)]
    try:
        while stack:
            src, dst, depth = stack.pop()
            try:
                for name in sorted(os.listdir(src)):
                    kind, info = _kind(src, name)
                    if kind == "link":
                        tally.skipped_links += 1
                    elif kind == "dir":
                        if depth + 1 > MAX_DEPTH:
                            tally.skipped_other += 1
                            continue
                        child = os.open(name, _DIR_FLAGS, dir_fd=src)
                        try:
                            os.mkdir(name, 0o700, dir_fd=dst)
                            made = os.open(name, _DIR_FLAGS, dir_fd=dst)
                        except BaseException:
                            os.close(child)
                            raise
                        os.fchmod(made, info.st_mode & _KEPT_BITS | 0o700)
                        tally.folders += 1
                        stack.append((child, made, depth + 1))
                    elif kind == "file":
                        if _copy_file(src, dst, name):
                            tally.files += 1
                            tally.bytes += info.st_size
                        else:
                            tally.skipped_other += 1
                    else:
                        tally.skipped_other += 1
            finally:
                os.close(src)
                os.close(dst)
    finally:
        for src, dst, _ in stack:
            os.close(src)
            os.close(dst)
    return tally.result()


def _copy_file(src_dir: int, dst_dir: int, name: str) -> bool:
    """Copy one regular file; False if it is not one when opened (it changed kind)."""
    try:
        source = os.open(name, _FILE_FLAGS, dir_fd=src_dir)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENXIO):  # a link, or a FIFO/socket after all
            return False
        raise
    try:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode):
            return False
        target = os.open(name, _NEW_FILE_FLAGS, 0o600, dir_fd=dst_dir)
        try:
            while chunk := os.read(source, _CHUNK):
                view = memoryview(chunk)
                while view:
                    view = view[os.write(target, view) :]
            os.fchmod(target, info.st_mode & _KEPT_BITS | 0o600)
        finally:
            os.close(target)
    finally:
        os.close(source)
    return True
