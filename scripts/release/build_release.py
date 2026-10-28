"""Build backtide's release archive (T14, the fix of R1 from the T13-3 review; docs/25).

Run by us, never by the installer: ``make release`` (``python -m scripts.release.build_release``).

The archive is what ``install.sh --desde ARCHIVE --sha256 HEX`` installs, and its own sha256 is
the one the installer checks. It holds only what backtide needs to run and to be installed:

- backtide's code as it is (``backtide/``, ``deploy/``, ``lima/backtide-mac.yaml``), plus
  ``pyproject.toml``, ``uv.lock``, ``LICENSE``, ``README.md``, ``SECURITY.md``;
- ``install.sh`` and ``install-mac.sh``;
- ``requirements.txt``: the runtime dependencies exported from ``uv.lock``, each pinned with
  ``==`` and every sha256 the lock knows for it (``uv export --frozen --no-dev
  --no-emit-project --hashes``);
- ``release.txt``: which commit it comes from and which uv exported the requirements.

Nothing is built, here or on the user's machine: backtide is not a wheel. ``install.sh``
installs only the dependencies' wheels (``--require-hashes --no-build``) and runs backtide from
its folder. That keeps the layout every installer test has used (the code in the release folder,
next to ``deploy/``), and leaves no build backend to pin.

Reproducible: the same commit, with the same uv and the same Python, gives the same bytes. The
blobs are read raw (no git filters, no attributes). The members are
sorted, regular files only, owned by 0:0, with mode 0644 or 0755 and the commit's time; the tar
is not compressed (a compressor's output can change between versions).

``--arbol`` takes the working tree instead (tracked and new files, as the labs need to try
uncommitted work): the name says ``-arbol`` and ``release.txt`` says so. Never published.
"""

import argparse
import hashlib
import io
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# What goes in, and nothing else. A folder takes every file under it.
RELEASE_PATHS = (
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "backtide",
    "deploy",
    "install-mac.sh",
    "install.sh",
    "lima/backtide-mac.yaml",
    "pyproject.toml",
    "uv.lock",
)
EXPORT = ("export", "--frozen", "--no-dev", "--no-emit-project", "--hashes")
EXPORT_FLAGS = (*EXPORT, "--no-header", "--no-annotate", "--no-config")
REQUIREMENTS = "requirements.txt"
INFO = "release.txt"
DEFAULT_OUT = Path("dist") / "release"

# The only bytes `uv export --hashes --no-header --no-annotate` writes: no "#", tab, \r or
# anything outside ASCII, so no comment can hide a line from this check (review of T14-R1).
ALLOWED = re.compile(r"[A-Za-z0-9 ._=:;<>!~()'\"\\+\n-]*")
PIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!]+")
MARKER = re.compile(r"(?!-)[A-Za-z0-9_.<>=!~()'\"-]+")
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")


class ReleaseError(Exception):
    pass


@dataclass(frozen=True)
class Source:
    files: dict[str, tuple[bytes, bool]]  # path -> (content, executable)
    mtime: int
    commit: str
    from_tree: bool


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if done.returncode != 0:
        raise ReleaseError(f"git {' '.join(args)}: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def _commit_of(repo: Path, ref: str) -> tuple[str, int]:
    if ref.startswith("-"):
        raise ReleaseError(f"no es un commit: {ref}")
    sha = git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").decode().strip()
    when = int(git(repo, "show", "-s", "--format=%ct", sha).decode().strip())
    return sha, when


def from_commit(repo: Path, ref: str) -> Source:
    """The files of a commit, as git keeps them: what is not committed does not go in. The blobs
    are read raw (``ls-tree`` and ``cat-file --batch``), with none of git's filters: no line-end
    conversion, no ``export-subst`` or ``export-ignore`` from an attributes file (review of
    T14-R1), so a clone's settings cannot change the bytes."""
    sha, when = _commit_of(repo, ref)
    listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", sha, "--", *RELEASE_PATHS)
    entries: list[tuple[str, str, str]] = []  # (path, blob, mode)
    for record in listing.decode().split("\0"):
        if not record:
            continue
        meta, name = record.split("\t", 1)
        mode, kind, blob = meta.split(" ")
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ReleaseError(f"{name} no es un archivo normal (¿un enlace?): no entra")
        entries.append((name, blob, mode))
    batch = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input="".join(f"{blob}\n" for _, blob, _ in entries).encode(),
        capture_output=True,
        check=False,
    )
    if batch.returncode != 0:
        raise ReleaseError(f"git cat-file: {batch.stderr.decode(errors='replace').strip()}")
    out = batch.stdout
    files: dict[str, tuple[bytes, bool]] = {}
    for name, blob, mode in entries:
        header, out = out.split(b"\n", 1)
        got, kind, size = header.decode().split(" ")
        if got != blob or kind != "blob":
            raise ReleaseError(f"no se puede leer {name} del commit")
        files[name] = (out[: int(size)], mode == "100755")
        out = out[int(size) + 1 :]
    return Source(files=files, mtime=when, commit=sha, from_tree=False)


def from_tree(repo: Path) -> Source:
    """The working tree (tracked and new files, not ignored ones): for the labs only."""
    sha, when = _commit_of(repo, "HEAD")
    listed = git(repo, "ls-files", "-co", "--exclude-standard", "-z", "--", *RELEASE_PATHS)
    files: dict[str, tuple[bytes, bool]] = {}
    for name in sorted({n for n in listed.decode().split("\0") if n}):
        path = repo / name
        if not path.exists() and not path.is_symlink():
            continue  # deleted in the tree
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"{name} no es un archivo normal (¿un enlace?): no entra")
        files[name] = (path.read_bytes(), bool(path.stat().st_mode & 0o100))
    return Source(files=files, mtime=when, commit=sha, from_tree=True)


def check_requirements(text: str) -> list[str]:
    """The rules of install.sh's ``check_requirements``: only the bytes uv export writes, lines
    split at ``\\n`` only, joined only at a final `` \\``, and each one ``name==version`` with
    optional markers and one or more ``--hash=sha256:``; no comments, options, URLs, paths or
    editables. Returns what is wrong (empty if nothing)."""
    if not ALLOWED.fullmatch(text):
        return ["bytes que uv export no escribe (#, tabuladores, \\r, no ASCII…)"]
    problems: list[str] = []
    pinned = 0
    joined = ""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()  # the newline that ends the last line, as awk reads it
    for number, raw in enumerate(lines, start=1):
        if raw.endswith("\\"):
            head = raw[:-1]
            if "\\" in head or not head.endswith(" "):
                problems.append(f"{number}: barra fuera de sitio")
            joined += head
            continue
        if "\\" in raw:
            problems.append(f"{number}: barra fuera de sitio")
            joined = ""
            continue
        tokens = (joined + raw).split(" ")
        tokens = [token for token in tokens if token]
        joined = ""
        if not tokens:
            continue
        if not PIN.fullmatch(tokens[0]):
            problems.append(f"{number}: no es nombre==versión: {tokens[0]}")
            continue
        rest = tokens[1:]
        if rest[:1] == [";"]:
            rest = rest[1:]
            while rest and not rest[0].startswith("--hash=") and MARKER.fullmatch(rest[0]):
                rest = rest[1:]
            if rest and not rest[0].startswith("--hash="):
                problems.append(f"{number}: marcador raro: {rest[0]}")
                continue
        if not rest:
            problems.append(f"{number}: sin sha256: {tokens[0]}")
            continue
        bad = [token for token in rest if not HASH.fullmatch(token)]
        if bad:
            problems.append(f"{number}: no es una sha256: {bad[0]}")
            continue
        pinned += 1
    if joined:
        problems.append("acaba en una barra")
    if not pinned:
        problems.append("no hay dependencias")
    return problems


def uv_version(uv: str) -> str:
    done = subprocess.run([uv, "--version"], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise ReleaseError(f"no se puede ejecutar {uv}")
    return " ".join(done.stdout.split()[:2])


def export_requirements(files: dict[str, tuple[bytes, bool]], uv: str) -> str:
    """``uv export`` of the archive's own pyproject.toml and uv.lock, in a folder apart: it reads
    the lock only (``--frozen``) and builds nothing."""
    with tempfile.TemporaryDirectory(prefix="backtide-release-") as tmp:
        for name in ("pyproject.toml", "uv.lock"):
            Path(tmp, name).write_bytes(files[name][0])
        env = {k: v for k, v in os.environ.items() if not k.startswith("UV_")}
        env["UV_NO_CONFIG"] = "1"
        done = subprocess.run(
            [uv, *EXPORT_FLAGS], cwd=tmp, capture_output=True, text=True, env=env, check=False
        )
    if done.returncode != 0:
        raise ReleaseError(f"uv export falló: {done.stderr.strip()}")
    return done.stdout


def version_of(files: dict[str, tuple[bytes, bool]]) -> str:
    version = tomllib.loads(files["pyproject.toml"][0].decode())["project"]["version"]
    if not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ReleaseError(f"versión rara en pyproject.toml: {version!r}")
    return version


def release_files(source: Source, uv: str) -> tuple[str, dict[str, tuple[bytes, bool]]]:
    files = dict(source.files)
    missing = [p for p in RELEASE_PATHS if not any(n == p or n.startswith(p + "/") for n in files)]
    if missing:
        raise ReleaseError(f"faltan en el archivo: {', '.join(missing)}")
    for reserved in (REQUIREMENTS, INFO):
        if reserved in files:
            raise ReleaseError(f"{reserved} lo escribe este script: no puede venir del árbol")
    requirements = export_requirements(files, uv)
    problems = check_requirements(requirements)
    if problems:
        raise ReleaseError("requirements.txt no vale: " + "; ".join(problems))
    if "backtide" in {line.split("==")[0] for line in requirements.splitlines()}:
        raise ReleaseError("requirements.txt incluye el propio backtide")
    version = version_of(files)
    origin = source.commit + (" plus uncommitted changes (lab only)" if source.from_tree else "")
    info = (
        f"backtide {version}\n"
        f"commit {origin}\n"
        f"requirements.txt: uv {' '.join(EXPORT)} ({uv_version(uv)})\n"
        f"tar written by Python {platform.python_version()} (same commit, uv, Python: same bytes)\n"
        "Install it with: sudo sh install.sh --desde <this archive> --sha256 <its sha256>\n"
        "Nothing is built: only the wheels of requirements.txt, each checked against its sha256.\n"
    )
    files[REQUIREMENTS] = (requirements.encode(), False)
    files[INFO] = (info.encode(), False)
    return version, files


def write_archive(files: dict[str, tuple[bytes, bool]], mtime: int, out: Path) -> None:
    """A plain tar, the same bytes for the same files and time."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name in sorted(files):
            if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                raise ReleaseError(f"ruta rara: {name}")
            data, executable = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            info.mode = 0o755 if executable else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(buffer.getvalue())
    os.replace(tmp, out)


def build(
    repo: Path, out_dir: Path, *, ref: str = "HEAD", tree: bool = False, uv: str = "uv"
) -> Path:
    source = from_tree(repo) if tree else from_commit(repo, ref)
    version, files = release_files(source, uv)
    archive = out_dir / f"backtide-{version}{'-arbol' if tree else ''}.tar"
    write_archive(files, source.mtime, archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(f"{digest}  {archive.name}\n")
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="El archivo de una versión de backtide (T14).")
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--commit", default="HEAD", help="el commit (por defecto, HEAD)")
    where.add_argument(
        "--arbol", action="store_true", help="el árbol de trabajo, para los laboratorios"
    )
    parser.add_argument("--salida", type=Path, default=None, help="carpeta (dist/release)")
    parser.add_argument("--repo", type=Path, default=None, help="el repositorio (este)")
    args = parser.parse_args(argv)
    uv = os.environ.get("UV") or shutil.which("uv")
    if not uv:
        print("backtide: hace falta uv para exportar uv.lock", file=sys.stderr)
        return 1
    try:
        repo = args.repo or Path(git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip())
        out = args.salida or repo / DEFAULT_OUT
        archive = build(repo, out, ref=args.commit, tree=args.arbol, uv=uv)
    except ReleaseError as error:
        print(f"backtide: {error}", file=sys.stderr)
        return 1
    digest = archive.with_name(archive.name + ".sha256").read_text().split()[0]
    print(f"{archive}\nsha256 {digest}")
    if args.arbol:
        print("(del árbol de trabajo: solo para los laboratorios, nunca se publica)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
