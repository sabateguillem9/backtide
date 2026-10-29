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

After the security review of T17a-4 (finding A1): what the agent writes must never run by
itself on the host. Git runs code from a repository's config (``core.fsmonitor``, the pager,
hooks) as soon as the owner runs git, or a prompt that shows the branch, inside it. So the copy
never takes a ``.git`` folder or file (compared without case: APFS would open ``.GIT`` as
``.git``), nor a folder shaped like a repository (``HEAD`` and ``objects``, ``refs`` or
``commondir``: a bare one hidden in a subfolder); a work folder shaped like one loses its
``HEAD``. Commits leave as a git bundle instead (``export_bundle``): one plain file that the
agent made inside the jail, which is data (``git clone`` of it takes no config nor hooks). A
name that is not printable is skipped (B6), and so is one that the destination already has
because it ignores case (APFS: ``readme`` after ``README``). What is skipped is counted and the
first ``MAX_NAMED`` are named, escaped. And the destination is never where code is loaded from
(B5): backtide's own checkout, a Python environment, any folder of ``sys.path``.

After the final security review of T17a-4 (finding 5, and M4 of its review): nor what the
owner's own tools run or read by themselves when the owner opens the folder: Claude Code's hooks
in ``.claude/settings.json`` and MCP servers in ``.mcp.json``, ``CLAUDE.md``, VS Code's
``tasks.json`` with ``runOn: folderOpen``, direnv's ``.envrc``, a dev container's
``initializeCommand``, GitHub's workflows, actions and agent instructions in ``.github/``... A
prompt-injected agent writes them as a normal part of a project, so the owner would not suspect
them. A list of such names always lags behind the tools, so it goes the other way round: every
file or folder whose name starts with a dot is left out, except the files of ``DOT_ALLOWED``,
which no tool runs (no ``.pre-commit-config.yaml``, which runs hooks on commit, nor an
``.eslintrc.js``, a ``.pylintrc`` with an ``init-hook`` or a ``.flake8`` with local plugins,
which an editor's linter runs on open). Some names without a dot are left out too
(``CONFIG_NAMES``, ``CONFIG_SUFFIXES``: the instructions of coding agents and their MCP
configs, a VS Code workspace). All at any depth and without case, counted and named like the
git paths; ``include_config`` takes them (``.git`` keeps its own rule, and never leaves).
"""

import errno
import os
import re
import stat
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any

MAX_BYTES = 8 * 1024**3  # 8 GiB: a repository, not a disk
MAX_ENTRIES = 500_000
MAX_DEPTH = 128
MAX_PATH = 4096
_CHUNK = 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_KEPT_BITS = 0o755  # rwx for the owner, r-x for the rest: never setuid, setgid or sticky
MAX_NAMED = 20  # how many skipped names an export reports
MAX_SHOWN = 200  # characters of each
GIT = ".git"
# A folder is a repository for git with HEAD and its objects and refs, or a commondir that
# points at them; any of the three with HEAD is enough here (it skips more, never less).
_REPO_HEAD = "head"
_REPO_PARTS = frozenset({"objects", "refs", "commondir"})
# `backtide exportar --git`: the bundle the agent makes inside the jail, in its HOME.
BUNDLE_DIR = ".backtide-export"
BUNDLE_RE = re.compile(r"export-[0-9a-f]{32}\.bundle", re.ASCII)
BUNDLE_HEADERS = (b"# v2 git bundle\n", b"# v3 git bundle\n")
# What the owner's tools on the host run or read by themselves when the owner opens the folder
# (finding 5 of the final review, M4 of its review): every name with a dot first, but these
# files (never folders), which only say how to ignore, format or pick a version. Compared
# without case, at any depth.
DOT_ALLOWED = frozenset(
    {
        ".gitignore", ".gitattributes", ".editorconfig", ".dockerignore", ".python-version",
        ".nvmrc", ".node-version", ".prettierrc", ".prettierrc.json", ".prettierrc.json5",
        ".prettierrc.yaml", ".prettierrc.yml", ".prettierrc.toml", ".eslintrc", ".eslintrc.json",
        ".eslintrc.yaml", ".eslintrc.yml", ".prettierignore", ".eslintignore", ".ruff.toml",
    }
)  # fmt: skip
# And these names without a dot: what coding agents read as instructions, their MCP configs.
CONFIG_NAMES = frozenset(
    {
        "claude.md", "claude.local.md", "agents.md", "gemini.md", "opencode.json",
        "claude_desktop_config.json", "mcp_config.json",
    }
)  # fmt: skip
CONFIG_SUFFIXES = (".code-workspace",)  # a VS Code workspace: its settings, tasks, extensions


# Set by an installed service's unit (deploy/systemd/backtide.service.in): the only folder that
# systemd lets the service write the owner's copies to (code review of 2026-10-29, S1).
EXPORT_DIR_ENV = "BACKTIDE_EXPORT_DIR"


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
    skipped_git: int = 0  # .git folders and files, and folders shaped like a repository
    skipped_names: int = 0  # names that are not printable
    skipped_collisions: int = 0  # names the destination already had, ignoring case
    skipped_config: int = 0  # what the owner's tools run or read by themselves (CONFIG_*)
    # ("git" | "name" | "case" | "config", relative path, escaped)
    named: tuple[tuple[str, str], ...] = ()

    def details(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "folders": self.folders,
            "bytes": self.bytes,
            "skipped_links": self.skipped_links,
            "skipped_other": self.skipped_other,
            "skipped_git": self.skipped_git,
            "skipped_names": self.skipped_names,
            "skipped_collisions": self.skipped_collisions,
            "skipped_config": self.skipped_config,
            "skipped": [list(item) for item in self.named],
        }


def check_destination(
    text: object, protected: Iterable[Path], *, inside: Path | None = None
) -> Path:
    """The owner's destination as a Path, or ExportError: an absolute path without ``..``, NUL or
    trailing separators, whose parent folder exists, that does not exist itself, and that is
    neither inside nor around any of ``protected`` (after resolving the parent's links: the
    owner's own path may have them). With ``inside`` (an installed service, which systemd keeps
    from writing anywhere else: code review of 2026-10-29, S1), it must also be in that folder,
    checked first so that the owner hears where to export instead of a misleading error."""
    if not isinstance(text, str) or not text or len(text) > MAX_PATH or "\0" in text:
        raise ExportError("la carpeta de destino no es una ruta válida")
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts or os.path.normpath(text) != text:
        raise ExportError(f"el destino tiene que ser una ruta absoluta y sin '..': {text}")
    if path == path.parent:
        raise ExportError("el destino no puede ser la raíz")
    if inside is not None and not path.is_relative_to(inside):
        raise ExportError(
            f"en una instalación, backtide solo puede exportar dentro de {inside} (el servicio "
            f"está aislado y no ve otras carpetas): por ejemplo {inside / 'mi-trabajo'}"
        )
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        raise ExportError(f"no existe la carpeta donde crear el destino: {path.parent}") from None
    if not parent.is_dir():
        raise ExportError(f"{path.parent} no es una carpeta")
    if os.path.lexists(path):
        raise ExportError(f"ya existe {path}: elige una carpeta nueva (nunca se sobrescribe nada)")
    target = parent / path.name
    if inside is not None and not target.is_relative_to(Path(os.path.realpath(inside))):
        raise ExportError(f"{path} sale de {inside} por un enlace: elige una carpeta dentro")
    _refuse_code_places(target, path)
    for folder in protected:
        guarded = Path(os.path.realpath(folder))
        if target == guarded or target.is_relative_to(guarded) or guarded.is_relative_to(target):
            raise ExportError(
                f"{path} está dentro de lo que backtide protege ({folder}) o lo contiene: elige "
                "otra carpeta"
            )
    return target


def code_places() -> list[Path]:
    """Where this Python loads code from: every folder of ``sys.path`` (``""`` is the current
    folder), its prefixes, and backtide's own checkout (or the folder that holds it)."""
    places = [Path(__file__).resolve().parents[2]]
    for entry in (*sys.path, sys.prefix, sys.exec_prefix, sys.base_prefix):
        if isinstance(entry, str):
            places.append(Path(os.path.realpath(entry or os.curdir)))
    return places


def _folded(path: Path) -> PurePath:
    return PurePath(str(path).casefold())


def _refuse_code_places(target: Path, shown: Path) -> None:
    """ExportError if ``target`` (its parent resolved) is inside a place code is loaded from:
    a file there could run with the next import (B5 of the review). Compared without case."""
    folded = _folded(target)
    for place in code_places():
        if folded.is_relative_to(_folded(place)):
            raise ExportError(
                f"{shown} está dentro de una carpeta de la que se carga código ({place}): lo que "
                "escribió el agente podría ejecutarse solo. Elige una carpeta fuera del "
                "repositorio y de cualquier entorno de Python"
            )
    for folder in target.parents:
        if os.path.lexists(folder / "pyvenv.cfg"):
            raise ExportError(
                f"{shown} está dentro de un entorno de Python ({folder}), una carpeta de la que se "
                "carga código: elige otra"
            )


def export_tree(source: Path, destination: Path, *, include_config: bool = False) -> ExportResult:
    """Copy the folder ``source`` (in a read-only snapshot) into the new folder ``destination``
    (checked with check_destination). The last component of ``source`` is opened without
    following a link too. What the owner's tools run by themselves is left out unless
    ``include_config``. Raises ExportError, with nothing created, if the source cannot be
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
        try:
            root_is_repo = _shaped_like_a_repo(source_fd)
            counted = _count(source_fd, root_is_repo, include_config)
        except OSError as error:
            raise ExportError(
                f"no se puede leer la carpeta de trabajo en la instantánea "
                f"({os.strerror(error.errno or 0)}): no se ha copiado nada"
            ) from None
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
            return _copy(source_fd, destination_fd, root_is_repo, include_config)
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
    skipped_git: int = 0
    skipped_names: int = 0
    skipped_collisions: int = 0
    skipped_config: int = 0
    named: list[tuple[str, str]] = field(default_factory=list)

    def skip(self, why: str, relative: str) -> None:
        if why == "git":
            self.skipped_git += 1
        elif why == "name":
            self.skipped_names += 1
        elif why == "config":
            self.skipped_config += 1
        else:
            self.skipped_collisions += 1
        if len(self.named) < MAX_NAMED:
            self.named.append((why, _shown(relative)))

    def result(self) -> ExportResult:
        return ExportResult(
            files=self.files,
            folders=self.folders,
            bytes=self.bytes,
            skipped_links=self.skipped_links,
            skipped_other=self.skipped_other,
            skipped_git=self.skipped_git,
            skipped_names=self.skipped_names,
            skipped_collisions=self.skipped_collisions,
            skipped_config=self.skipped_config,
            named=tuple(self.named),
        )


def _shown(relative: str) -> str:
    """A workspace path for the owner: control characters, invisible ones and undecodable
    bytes escaped, bounded."""
    text = "".join(c if c.isprintable() else repr(c)[1:-1] for c in relative)
    return text if len(text) <= MAX_SHOWN else text[: MAX_SHOWN - 1] + "…"


def _shaped_like_a_repo(dir_fd: int) -> bool:
    """Whether git would take the folder open at ``dir_fd`` for a repository (a bare one, or a
    worktree's gitdir): ``HEAD`` with ``objects``, ``refs`` or ``commondir``, without case."""
    names = {name.casefold() for name in os.listdir(dir_fd)}
    return _REPO_HEAD in names and bool(names & _REPO_PARTS)


def _git_skip(name: str, kind: str, parent_fd: int, depth: int, root_is_repo: bool) -> str | None:
    """Why an entry of a folder at ``depth`` is not copied ("name" or "git"), or None. Links
    are counted apart, before this."""
    if not name.isprintable():
        return "name"
    folded = name.casefold()
    if folded == GIT:
        return "git"
    if depth == 0 and root_is_repo and (folded == _REPO_HEAD or folded == "commondir"):
        return "git"
    if kind == "dir":
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        try:
            if _shaped_like_a_repo(fd):
                return "git"
        finally:
            os.close(fd)
    return None


def _skip(name: str, kind: str, parent_fd: int, depth: int, flags: tuple[bool, bool]) -> str | None:
    """Why an entry is not copied ("name", "git" or "config"), or None. ``flags`` is
    (root_is_repo, include_config)."""
    root_is_repo, include_config = flags
    if why := _git_skip(name, kind, parent_fd, depth, root_is_repo):
        return why
    if include_config or not is_config(name, kind):
        return None
    return "config"


def is_config(name: str, kind: str) -> bool:
    """Whether an entry is something the owner's tools may run or read by themselves: a name
    with a dot first (unless a file of ``DOT_ALLOWED``), or one of ``CONFIG_NAMES`` or
    ``CONFIG_SUFFIXES``, without case."""
    folded = name.casefold()
    if folded.startswith("."):
        return not (kind == "file" and folded in DOT_ALLOWED)
    return folded in CONFIG_NAMES or folded.endswith(CONFIG_SUFFIXES)


def _kind(dir_fd: int, name: str) -> tuple[str, os.stat_result]:
    info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        return "link", info
    if stat.S_ISDIR(info.st_mode):
        return "dir", info
    if stat.S_ISREG(info.st_mode):
        return "file", info
    return "other", info


def _enter(stack: list[Any], fd: int, *rest: Any) -> None:
    """Push the folder open at ``fd`` with its sorted names; ``fd`` is closed if they cannot
    be read. The walks below keep a folder open only while it is on the path being walked: at
    most MAX_DEPTH + 1 of them however wide a folder is (code review of 2026-10-29, S2: one
    per queued subfolder ran out of descriptors in a node_modules)."""
    try:
        names = iter(sorted(os.listdir(fd)))
    except BaseException:
        os.close(fd)
        raise
    stack.append((fd, *rest, names))


def _count(root_fd: int, root_is_repo: bool, include_config: bool) -> ExportResult:
    """What the copy would take, without writing anything (nor counting what it skips)."""
    tally = _Tally()
    flags = (root_is_repo, include_config)
    stack: list[tuple[int, int, Iterator[str]]] = []
    _enter(stack, os.dup(root_fd), 0)
    try:
        while stack:
            fd, depth, names = stack[-1]
            name = next(names, None)
            if name is None:
                os.close(stack.pop()[0])
                continue
            kind, info = _kind(fd, name)
            if kind == "link" or _skip(name, kind, fd, depth, flags):
                continue
            if kind == "file":
                tally.files += 1
                tally.bytes += info.st_size
            elif kind == "dir" and depth + 1 <= MAX_DEPTH:
                tally.folders += 1
                _enter(stack, os.open(name, _DIR_FLAGS, dir_fd=fd), depth + 1)
            if tally.files + tally.folders > MAX_ENTRIES or tally.bytes > MAX_BYTES:
                return tally.result()
    finally:
        for fd, *_ in stack:
            os.close(fd)
    return tally.result()


def _copy(
    source_fd: int, destination_fd: int, root_is_repo: bool, include_config: bool
) -> ExportResult:
    tally = _Tally()
    flags = (root_is_repo, include_config)
    stack: list[tuple[int, int, int, str, Iterator[str]]] = []
    destination = os.dup(destination_fd)
    try:
        _enter(stack, os.dup(source_fd), destination, 0, "")
    except BaseException:
        os.close(destination)
        raise
    try:
        while stack:
            src, dst, depth, prefix, names = stack[-1]
            name = next(names, None)
            if name is None:
                stack.pop()
                os.close(src)
                os.close(dst)
                continue
            kind, info = _kind(src, name)
            relative = f"{prefix}{name}"
            if kind == "link":
                tally.skipped_links += 1
            elif why := _skip(name, kind, src, depth, flags):
                tally.skip(why, relative)
            elif kind == "dir":
                if depth + 1 > MAX_DEPTH:
                    tally.skipped_other += 1
                    continue
                child = os.open(name, _DIR_FLAGS, dir_fd=src)
                try:
                    os.mkdir(name, 0o700, dir_fd=dst)
                    made = os.open(name, _DIR_FLAGS, dir_fd=dst)
                except FileExistsError:  # the destination ignores case (APFS)
                    os.close(child)
                    tally.skip("case", relative)
                    continue
                except BaseException:
                    os.close(child)
                    raise
                try:
                    os.fchmod(made, info.st_mode & _KEPT_BITS | 0o700)
                except BaseException:
                    os.close(child)
                    os.close(made)
                    raise
                tally.folders += 1
                try:
                    _enter(stack, child, made, depth + 1, f"{relative}/")
                except BaseException:
                    os.close(made)
                    raise
            elif kind == "file":
                try:
                    copied = _copy_file(src, dst, name)
                except FileExistsError:  # the destination ignores case (APFS)
                    tally.skip("case", relative)
                    continue
                if copied:
                    tally.files += 1
                    tally.bytes += info.st_size
                else:
                    tally.skipped_other += 1
            else:
                tally.skipped_other += 1
    finally:
        for src, dst, *_ in stack:
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


def export_bundle(home: Path, name: str, destination: Path) -> ExportResult:
    """`backtide exportar --git`: copy the git bundle ``name`` that the agent made in
    ``<HOME>/.backtide-export/`` (``home`` is that HOME in a read-only snapshot) into the new
    file ``destination`` (checked with check_destination), 0644. Each folder is opened without
    following a link, the file must be a regular one no bigger than ``MAX_BYTES`` and start
    like a git bundle (v2 or v3). Raises ExportError, with nothing created, if not."""
    if not isinstance(name, str) or not BUNDLE_RE.fullmatch(name):
        raise ExportError("el nombre del bundle no tiene la forma esperada")
    try:
        home_fd = os.open(home, _DIR_FLAGS)
    except OSError as error:
        raise ExportError(
            f"no se puede abrir el HOME del agente en la instantánea "
            f"({os.strerror(error.errno or 0)}): ¿es un enlace?"
        ) from None
    try:
        folder_fd = os.open(BUNDLE_DIR, _DIR_FLAGS, dir_fd=home_fd)
    except OSError as error:
        raise ExportError(
            f"no está la carpeta del bundle en la instantánea ({os.strerror(error.errno or 0)})"
        ) from None
    finally:
        os.close(home_fd)
    try:
        try:
            source = os.open(name, _FILE_FLAGS, dir_fd=folder_fd)
        except OSError as error:
            raise ExportError(
                f"no está el bundle en la instantánea ({os.strerror(error.errno or 0)})"
            ) from None
    finally:
        os.close(folder_fd)
    try:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode):
            raise ExportError("lo que hay en el sitio del bundle no es un archivo normal")
        if info.st_size > MAX_BYTES:
            raise ExportError(f"el bundle pasa de {MAX_BYTES} bytes")
        head = os.pread(source, max(len(h) for h in BUNDLE_HEADERS), 0)
        if not any(head.startswith(header) for header in BUNDLE_HEADERS):
            raise ExportError("el archivo no empieza como un bundle de git: no se exporta")
        try:
            target = os.open(destination, _NEW_FILE_FLAGS, 0o600)
        except FileExistsError:
            raise ExportError(f"ya existe {destination}: nunca se sobrescribe nada") from None
        except OSError as error:
            raise ExportError(
                f"no se puede crear {destination}: {os.strerror(error.errno or 0)}"
            ) from None
        try:
            copied = 0
            while chunk := os.read(source, _CHUNK):
                view = memoryview(chunk)
                while view:
                    view = view[os.write(target, view) :]
                copied += len(chunk)
            os.fchmod(target, 0o644)
        except OSError as error:
            raise ExportError(
                f"la copia a {destination} se ha quedado a medias "
                f"({os.strerror(error.errno or 0)}): no uses ese archivo"
            ) from None
        finally:
            os.close(target)
    finally:
        os.close(source)
    return ExportResult(1, 0, copied, 0, 0)
