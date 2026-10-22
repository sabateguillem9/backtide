"""`backtide exportar`'s copy (T17a-4, backtide/service/export.py): it never overwrites, never
follows a link from the workspace, never leaves the owner's folder, and is bounded."""

import os
import stat
import threading
from pathlib import Path

import pytest

from backtide.service import export
from backtide.service.export import ExportError, check_destination, export_tree


@pytest.fixture
def source(tmp_path: Path) -> Path:
    """A work folder as an agent leaves it: files, folders, links and a FIFO."""
    work = tmp_path / "snap" / "work"
    (work / "src" / "deep").mkdir(parents=True)
    (work / "README.md").write_text("hola\n")
    (work / "src" / "main.py").write_text("print(1)\n")
    (work / "src" / "deep" / "data.bin").write_bytes(bytes(range(256)) * 10)
    run = work / "run.sh"
    run.write_text("#!/bin/sh\n")
    run.chmod(0o4755)  # setuid: never kept
    secret = tmp_path / "host-secret"
    secret.write_text("the host's\n")
    (work / "link-to-host").symlink_to(secret)
    (work / "dir-link").symlink_to(tmp_path)
    (work / "src" / "relative").symlink_to("../README.md")
    os.mkfifo(work / "pipe")
    return work


def test_it_copies_files_and_folders_and_skips_links_and_others(
    source: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    result = export_tree(source, out)
    assert (out / "README.md").read_text() == "hola\n"
    assert (out / "src" / "main.py").read_text() == "print(1)\n"
    assert (out / "src" / "deep" / "data.bin").read_bytes() == bytes(range(256)) * 10
    assert not (out / "link-to-host").exists() and not (out / "link-to-host").is_symlink()
    assert not os.path.lexists(out / "dir-link") and not os.path.lexists(out / "src" / "relative")
    assert not os.path.lexists(out / "pipe")
    assert (result.files, result.folders) == (4, 2)
    assert result.bytes == 5 + 9 + 2560 + 10
    assert (result.skipped_links, result.skipped_other) == (3, 1)
    mode = (out / "run.sh").stat().st_mode
    assert mode & 0o755 == 0o755 and not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)


def test_a_fifo_never_blocks_the_copy(source: Path, tmp_path: Path) -> None:
    done = threading.Event()
    threading.Thread(target=lambda: (export_tree(source, tmp_path / "o"), done.set())).start()
    assert done.wait(10)


def test_the_work_folder_itself_as_a_link_is_refused(tmp_path: Path, source: Path) -> None:
    linked = tmp_path / "linked-work"
    linked.symlink_to(source)
    with pytest.raises(ExportError, match="enlace"):
        export_tree(linked, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_an_existing_destination_is_never_overwritten(source: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "mine").write_text("keep")
    with pytest.raises(ExportError, match="nunca se sobrescribe"):
        export_tree(source, out)
    assert sorted(p.name for p in out.iterdir()) == ["mine"]


def test_too_big_is_refused_before_anything_is_written(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(export, "MAX_BYTES", 100)
    with pytest.raises(ExportError, match="demasiado grande"):
        export_tree(source, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    monkeypatch.setattr(export, "MAX_BYTES", 10**9)
    monkeypatch.setattr(export, "MAX_ENTRIES", 3)
    with pytest.raises(ExportError, match="demasiado grande"):
        export_tree(source, tmp_path / "out")


def test_a_sparse_file_counts_by_its_size(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    with open(work / "sparse", "wb") as handle:
        handle.truncate(10**12)  # a terabyte that takes no space in the workspace
    with pytest.raises(ExportError, match="demasiado grande"):
        export_tree(work, tmp_path / "out")


def test_folders_deeper_than_the_bound_are_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(export, "MAX_DEPTH", 2)
    work = tmp_path / "work"
    (work / "a" / "b" / "c").mkdir(parents=True)
    (work / "a" / "b" / "c" / "f").write_text("x")
    result = export_tree(work, tmp_path / "out")
    assert (tmp_path / "out" / "a" / "b").is_dir()
    assert not (tmp_path / "out" / "a" / "b" / "c").exists()
    assert result.skipped_other == 1


# --- the destination ----------------------------------------------------------------------------


@pytest.fixture
def protected(tmp_path: Path) -> list[Path]:
    state, volume = tmp_path / "state", tmp_path / "volume"
    state.mkdir()
    volume.mkdir()
    return [state, volume]


def test_a_new_folder_in_an_existing_one_is_fine(tmp_path: Path, protected: list[Path]) -> None:
    target = check_destination(str(tmp_path / "out"), protected)
    assert target == tmp_path.resolve() / "out"


@pytest.mark.parametrize(
    "text",
    ["", "out", "./out", "/srv/../etc/x", "/a//b", "/a/b/", "/a\0b", "/", None, 3],
)
def test_odd_destinations_are_refused(text: object, protected: list[Path]) -> None:
    with pytest.raises(ExportError):
        check_destination(text, protected)


def test_a_missing_parent_is_refused(tmp_path: Path, protected: list[Path]) -> None:
    with pytest.raises(ExportError, match="no existe la carpeta"):
        check_destination(str(tmp_path / "nope" / "out"), protected)


def test_an_existing_name_or_link_is_refused(tmp_path: Path, protected: list[Path]) -> None:
    (tmp_path / "file").write_text("x")
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    for name in ("file", "dangling"):
        with pytest.raises(ExportError, match="ya existe"):
            check_destination(str(tmp_path / name), protected)


def test_inside_or_around_what_backtide_protects_is_refused(
    tmp_path: Path, protected: list[Path]
) -> None:
    state, volume = protected
    (tmp_path / "alias").symlink_to(state)
    for text in (state / "x", volume / "workspace", tmp_path / "alias" / "x"):
        with pytest.raises(ExportError, match="protege"):
            check_destination(str(text), protected)
    # A protected folder that does not exist yet below the destination: around it, refused.
    with pytest.raises(ExportError, match="protege"):
        check_destination(str(tmp_path / "new"), [tmp_path / "new" / "state"])
