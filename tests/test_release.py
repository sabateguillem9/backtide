"""The release archive (T14, R1 of the T13-3 review; scripts/release/build_release.py).

Built from a small git repository made here (and once from this repository's HEAD): what goes in
and what does not, that a commit's archive ignores uncommitted work, that two builds give the same
bytes, and that requirements.txt pins every dependency by hash and holds nothing to build.
Needs git and uv on the PATH (both are there wherever `make test` runs).
"""

import hashlib
import io
import os
import platform
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts.release import build_release as release

ROOT = Path(__file__).resolve().parents[1]
UV = shutil.which("uv")
pytestmark = pytest.mark.skipif(UV is None or shutil.which("git") is None, reason="git and uv")
HEX = "0123456789abcdef" * 4


def run_git(repo: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-10-28T10:00:00Z",
        "GIT_COMMITTER_DATE": "2026-10-28T10:00:00Z",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.test", *args],
        check=True,
        capture_output=True,
        env=env,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository with everything a release takes, the real pyproject.toml and uv.lock, and
    things that must stay out (tests, docs, CLAUDE.md)."""
    repo = tmp_path / "repo"
    files = {
        "backtide/__init__.py": "",
        "backtide/cli.py": "def main():\n    return 0\n",
        "deploy/systemd/backtide.service.in": "[Unit]\n",
        "lima/backtide-mac.yaml": "# backtide-mac: test\n",
        "lima/vigia-dev.yaml": "# dev only\n",
        "install.sh": "#!/bin/sh\n",
        "install-mac.sh": "#!/bin/sh\n",
        "LICENSE": "license\n",
        "README.md": "readme\n",
        "SECURITY.md": "security\n",
        "tests/test_x.py": "def test_x(): pass\n",
        "docs/plan.md": "private\n",
        "CLAUDE.md": "private\n",
    }
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    (repo / "install.sh").chmod(0o755)
    shutil.copy(ROOT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy(ROOT / "uv.lock", repo / "uv.lock")
    run_git(repo, "init", "-q")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "first")
    return repo


def members(archive: Path) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(archive) as tar:
        return {m.name: m for m in tar.getmembers()}


def read(archive: Path, name: str) -> str:
    with tarfile.open(archive) as tar:
        data = tar.extractfile(name)
        assert data is not None
        return data.read().decode()


def test_it_takes_what_runs_and_installs_and_nothing_else(repo: Path, tmp_path: Path) -> None:
    archive = release.build(repo, tmp_path / "out", uv=UV)
    assert archive.name == "backtide-0.1.0.tar"
    assert sorted(members(archive)) == [
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "backtide/__init__.py",
        "backtide/cli.py",
        "deploy/systemd/backtide.service.in",
        "install-mac.sh",
        "install.sh",
        "lima/backtide-mac.yaml",
        "pyproject.toml",
        "release.txt",
        "requirements.txt",
        "uv.lock",
    ]
    commit_time = int(
        subprocess.run(
            ["git", "-C", str(repo), "show", "-s", "--format=%ct", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    for member in members(archive).values():
        assert member.isfile()
        assert (member.uid, member.gid, member.uname, member.gname) == (0, 0, "", "")
        assert member.mtime == commit_time
        assert member.mode == (0o755 if member.name == "install.sh" else 0o644), member.name
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sidecar = archive.with_name("backtide-0.1.0.tar.sha256").read_text()
    assert sidecar == f"{digest}  backtide-0.1.0.tar\n"  # the format of sha256sum -c
    info = read(archive, "release.txt")
    assert "backtide 0.1.0\n" in info and "uv export --frozen --no-dev" in info
    assert f"Python {platform.python_version()} " in info
    assert "uncommitted" not in info


def test_two_builds_of_one_commit_are_the_same_bytes(repo: Path, tmp_path: Path) -> None:
    first = release.build(repo, tmp_path / "a", uv=UV).read_bytes()
    # Another checkout time, other file modes on disk: nothing of it reaches the archive.
    os.utime(repo / "README.md", (1, 1))
    (repo / "LICENSE").chmod(0o600)
    second = release.build(repo, tmp_path / "b", uv=UV).read_bytes()
    assert first == second


def test_a_commit_ignores_uncommitted_work_and_the_tree_takes_it(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "backtide" / "cli.py").write_text("def main():\n    return 1  # not committed\n")
    (repo / "backtide" / "nuevo.py").write_text("X = 1\n")
    committed = release.build(repo, tmp_path / "c", uv=UV)
    assert "not committed" not in read(committed, "backtide/cli.py")
    assert "backtide/nuevo.py" not in members(committed)

    tree = release.build(repo, tmp_path / "t", tree=True, uv=UV)
    assert tree.name == "backtide-0.1.0-arbol.tar"
    assert "not committed" in read(tree, "backtide/cli.py")
    assert "backtide/nuevo.py" in members(tree)
    assert "uncommitted changes (lab only)" in read(tree, "release.txt")


def test_requirements_pin_every_dependency_by_hash_and_leave_out_backtide_and_dev(
    repo: Path, tmp_path: Path
) -> None:
    archive = release.build(repo, tmp_path / "out", uv=UV)
    text = read(archive, "requirements.txt")
    assert release.check_requirements(text) == []
    names = {line.split("==")[0] for line in text.splitlines() if "==" in line}
    assert {"fastapi", "jinja2", "uvicorn", "pydantic-core", "starlette"} <= names
    assert not names & {"backtide", "pytest", "ruff", "httpx2", "hatchling"}
    assert "-e " not in text and "file:" not in text and "--index" not in text
    # The same as uv's own export of the archive's lock: nothing added, nothing dropped.
    again = subprocess.run(
        [UV, *release.EXPORT_FLAGS],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "UV_NO_CONFIG": "1"},
    ).stdout
    assert text == again


def test_this_repository_head_makes_a_valid_release(tmp_path: Path) -> None:
    archive = release.build(ROOT, tmp_path / "out", uv=UV)
    names = members(archive)
    for needed in ("install.sh", "install-mac.sh", "lima/backtide-mac.yaml", "backtide/cli.py"):
        assert needed in names
    assert not [n for n in names if n.startswith(("tests/", "docs/", "site/", "informes/"))]
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc")]


def test_a_link_in_the_commit_is_refused(repo: Path, tmp_path: Path) -> None:
    (repo / "backtide" / "enlace.py").symlink_to("/etc/passwd")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "link")
    with pytest.raises(release.ReleaseError, match="no es un archivo normal"):
        release.build(repo, tmp_path / "out", uv=UV)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("missing", ["install.sh", "lima/backtide-mac.yaml", "uv.lock"])
def test_a_commit_without_a_needed_file_is_refused(
    repo: Path, tmp_path: Path, missing: str
) -> None:
    run_git(repo, "rm", "-q", missing)
    run_git(repo, "commit", "-q", "-m", "gone")
    with pytest.raises(release.ReleaseError):
        release.build(repo, tmp_path / "out", uv=UV)


def test_a_requirements_file_in_the_repository_is_never_taken(repo: Path, tmp_path: Path) -> None:
    """requirements.txt and release.txt are written by the script, never taken from the tree."""
    (repo / "requirements.txt").write_text("evil==1.0\n")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "smuggled")
    # Not in RELEASE_PATHS, so a commit never takes it; and the tree mode neither.
    archive = release.build(repo, tmp_path / "out", uv=UV)
    assert "evil" not in read(archive, "requirements.txt")


def test_a_bad_ref_is_refused(repo: Path, tmp_path: Path) -> None:
    with pytest.raises(release.ReleaseError):
        release.build(repo, tmp_path / "out", ref="--output=/tmp/x", uv=UV)
    with pytest.raises(release.ReleaseError):
        release.build(repo, tmp_path / "out", ref="no-such-branch", uv=UV)


GOOD = f"""annotated-doc==0.0.5 \\
    --hash=sha256:{HEX} \\
    --hash=sha256:{HEX}
colorama==0.4.6 ; sys_platform == 'win32' \\
    --hash=sha256:{HEX}
"""
BAD = {
    "unpinned": f"fastapi>=0.143 --hash=sha256:{HEX}\n",
    "unhashed": "fastapi==0.143.2\n",
    "md5": "fastapi==0.143.2 --hash=md5:0123456789abcdef0123456789abcdef\n",
    "short hash": "fastapi==0.143.2 --hash=sha256:0123\n",
    "editable": "-e .\n",
    "project": f".  --hash=sha256:{HEX}\n",
    "url": f"fastapi @ https://example.test/fastapi.whl --hash=sha256:{HEX}\n",
    "path": f"./fastapi-0.143.2-py3-none-any.whl --hash=sha256:{HEX}\n",
    "index": f"--index-url https://example.test/simple\nfastapi==1 --hash=sha256:{HEX}\n",
    "extra index": f"--extra-index-url https://example.test\nfastapi==1 --hash=sha256:{HEX}\n",
    "nested": f"-r other.txt\nfastapi==1 --hash=sha256:{HEX}\n",
    "find links": f"--find-links /tmp\nfastapi==1 --hash=sha256:{HEX}\n",
    "no binary": f"--no-binary :all:\nfastapi==1 --hash=sha256:{HEX}\n",
    "trailing": f"fastapi==1 --hash=sha256:{HEX} junk\n",
    "odd marker": f"fastapi==1 ; $(id) --hash=sha256:{HEX}\n",
    "empty": "",
    "only comments": "# nothing\n",
    "ends in a backslash": f"fastapi==1 --hash=sha256:{HEX} \\\n",
    # Review of T14-R1: uv ends a comment at its own line, so a comment "continued" with a final
    # backslash hid the next line (here `-r`) from the check, but not from uv.
    "comment continues": f"fastapi==1 --hash=sha256:{HEX}\n# note \\\n-r other.txt\n",
    "comment": f"# from uv.lock\nfastapi==1 --hash=sha256:{HEX}\n",
    "carriage return": f"fastapi==1 --hash=sha256:{HEX}\r-r other.txt\n",
    "crlf": f"fastapi==1 --hash=sha256:{HEX}\r\n",
    "form feed": f"fastapi==1 --hash=sha256:{HEX}\f-r other.txt\n",
    "tab": f"fastapi==1\t--hash=sha256:{HEX}\n",
    "nul": f"fastapi==1 --hash=sha256:{HEX}\x00\n",
    "non-ascii": f"fastäpi==1 --hash=sha256:{HEX}\n",
    "backslash inside": f"fastapi==1 \\ --hash=sha256:{HEX}\n",
    "continuation without a space": f"fastapi==1\\\n    --hash=sha256:{HEX}\n",
    "option as a marker": f"fastapi==1 ; --no-build-isolation --hash=sha256:{HEX}\n",
}


def test_the_requirements_check_takes_what_uv_export_writes() -> None:
    assert release.check_requirements(GOOD) == []


@pytest.mark.parametrize("case", sorted(BAD))
def test_the_requirements_check_refuses_anything_else(case: str) -> None:
    assert release.check_requirements(BAD[case]) != [], case


def test_the_archive_is_a_plain_tar_that_install_sh_unpacks(repo: Path, tmp_path: Path) -> None:
    """Not compressed (a compressor can change its bytes between versions), and flat: install.sh,
    install-mac.sh and the labs read `install.sh` and `lima/backtide-mac.yaml` at the top."""
    archive = release.build(repo, tmp_path / "out", uv=UV)
    assert archive.read_bytes()[257:262] == b"ustar"
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode="r:") as tar:
        assert tar.getmember("install.sh").isfile()


def test_the_blobs_go_in_raw_whatever_the_clone_says(repo: Path, tmp_path: Path) -> None:
    """Review of T14-R1: git archive applies a clone's attributes and line-end settings
    (export-subst, export-ignore, eol). The release reads the blobs raw: the same bytes from any
    clone of the commit."""
    (repo / "backtide" / "version.py").write_text("COMMIT = '$Format:%H$'\nLINE = 'a'\n")
    (repo / ".gitattributes").write_text("backtide/version.py export-subst\n")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "subst")
    clean = release.build(repo, tmp_path / "clean", uv=UV).read_bytes()
    info = repo / ".git" / "info"
    info.mkdir(exist_ok=True)
    (info / "attributes").write_text("* text eol=crlf\nbacktide/cli.py export-ignore\n")
    run_git(repo, "config", "core.autocrlf", "true")
    dirty = release.build(repo, tmp_path / "dirty", uv=UV)
    assert dirty.read_bytes() == clean
    assert read(dirty, "backtide/version.py") == "COMMIT = '$Format:%H$'\nLINE = 'a'\n"
    assert "backtide/cli.py" in members(dirty)
