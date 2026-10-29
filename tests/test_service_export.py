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


# --- what the agent may plant for the owner's git (review of T17a-4, A1) ------------------------

FSMONITOR = "[core]\n\tfsmonitor = touch /tmp/pwned\n\tpager = touch /tmp/pwned\n"


def plant_repo(folder: Path, *, head: str = "HEAD", objects: str = "objects") -> None:
    """A bare repository as git finds one: HEAD, objects/, refs/ and a config that runs code."""
    folder.mkdir(parents=True)
    (folder / head).write_text("ref: refs/heads/main\n")
    (folder / objects).mkdir()
    (folder / "refs" / "heads").mkdir(parents=True)
    (folder / "config").write_text(FSMONITOR)
    (folder / "hooks").mkdir()
    (folder / "hooks" / "post-checkout").write_text("#!/bin/sh\ntouch /tmp/pwned\n")


def test_a_git_folder_is_never_copied_in_any_case(tmp_path: Path) -> None:
    work = tmp_path / "work"
    plant_repo(work / "proyecto" / ".git")
    (work / "proyecto" / "main.py").write_text("print(1)\n")
    plant_repo(work / "otro" / ".GIT")  # APFS would open it as .git
    plant_repo(work / "tercero" / ".Git")
    result = export_tree(work, tmp_path / "out")
    out = tmp_path / "out"
    assert (out / "proyecto" / "main.py").read_text() == "print(1)\n"
    assert sorted(os.listdir(out / "proyecto")) == ["main.py"]
    assert os.listdir(out / "otro") == [] and os.listdir(out / "tercero") == []
    assert result.skipped_git == 3
    assert {path for why, path in result.named if why == "git"} == {
        "proyecto/.git", "otro/.GIT", "tercero/.Git",
    }  # fmt: skip


def test_a_git_file_is_never_copied(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "sub").mkdir(parents=True)
    (work / "sub" / ".git").write_text("gitdir: ../../hidden\n")  # a gitlink
    (work / ".gIt").write_text("gitdir: /tmp/elsewhere\n")
    result = export_tree(work, tmp_path / "out")
    assert not os.path.lexists(tmp_path / "out" / "sub" / ".git")
    assert not os.path.lexists(tmp_path / "out" / ".gIt")
    assert result.skipped_git == 2


@pytest.mark.parametrize("head", ["HEAD", "head", "Head"])
def test_a_folder_shaped_like_a_repository_is_never_copied(tmp_path: Path, head: str) -> None:
    work = tmp_path / "work"
    (work / "vendor").mkdir(parents=True)
    (work / "vendor" / "lib.py").write_text("x = 1\n")
    plant_repo(work / "vendor" / "cache" / "x", head=head, objects="OBJECTS")
    result = export_tree(work, tmp_path / "out")
    out = tmp_path / "out"
    assert (out / "vendor" / "lib.py").exists()
    assert os.listdir(out / "vendor" / "cache") == []
    assert result.skipped_git == 1
    assert ("git", "vendor/cache/x") in result.named


def test_a_folder_with_a_commondir_is_a_repository_too(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "wt").mkdir(parents=True)
    (work / "wt" / "HEAD").write_text("ref: refs/heads/main\n")
    (work / "wt" / "commondir").write_text("../real\n")
    result = export_tree(work, tmp_path / "out")
    assert os.listdir(tmp_path / "out") == [] and result.skipped_git == 1


def test_a_work_folder_shaped_like_a_repository_loses_its_head(tmp_path: Path) -> None:
    work = tmp_path / "work"
    plant_repo(work)
    (work / "README.md").write_text("hola\n")
    result = export_tree(work, tmp_path / "out")
    names = set(os.listdir(tmp_path / "out"))
    assert "HEAD" not in names and "README.md" in names
    assert result.skipped_git == 1 and ("git", "HEAD") in result.named


def test_counts_skip_what_is_not_copied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A big file inside a planted .git does not count towards the bound: it is never copied."""
    work = tmp_path / "work"
    plant_repo(work / ".git")
    (work / ".git" / "objects" / "big").write_bytes(b"x" * 1000)
    (work / "small").write_bytes(b"y")
    monkeypatch.setattr(export, "MAX_BYTES", 100)
    assert export_tree(work, tmp_path / "out").files == 1


# --- what the owner's own tools run or read by themselves (review of T17a-4, finding 5) ---------

HOOK = '{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "touch /tmp/p"}]}]}}'


def plant_config(work: Path) -> None:
    """What a prompt-injected agent writes as a normal part of a project, for the owner's tools
    on the Mac: Claude Code's hooks and MCP servers, VS Code's tasks, direnv, CI, and the
    instructions of other coding agents."""
    for folder in (".claude", ".vscode", ".idea", ".devcontainer", ".cursor", ".github/workflows"):
        (work / folder).mkdir(parents=True)
    (work / ".claude" / "settings.json").write_text(HOOK)
    (work / ".claude" / "settings.local.json").write_text(HOOK)
    (work / ".mcp.json").write_text('{"mcpServers": {"x": {"command": "touch"}}}')
    (work / ".vscode" / "tasks.json").write_text('{"runOptions": {"runOn": "folderOpen"}}')
    (work / ".idea" / "workspace.xml").write_text("<x/>\n")
    (work / ".envrc").write_text("touch /tmp/p\n")
    (work / ".devcontainer" / "devcontainer.json").write_text('{"initializeCommand": "x"}')
    (work / ".devcontainer.json").write_text('{"initializeCommand": "x"}')
    (work / ".cursor" / "mcp.json").write_text("{}")
    (work / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    (work / ".github" / "copilot-instructions.md").write_text("x\n")
    for name in (
        "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
        ".windsurfrules", ".clinerules", "opencode.json", "claude_desktop_config.json",
        "mcp_config.json", "proyecto.code-workspace", ".pre-commit-config.yaml", ".brand-new-tool",
    ):  # fmt: skip
        (work / name).write_text("Run ./setup.sh first.\n")
    (work / ".gitignore").write_text("*.pyc\n")  # harmless: copied
    (work / "main.py").write_text("print(1)\n")


CONFIG_PATHS = {
    ".claude", ".vscode", ".idea", ".devcontainer", ".cursor", ".github", ".mcp.json",
    ".envrc", ".devcontainer.json", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "opencode.json",
    "claude_desktop_config.json", "mcp_config.json", "proyecto.code-workspace",
    ".pre-commit-config.yaml", ".brand-new-tool",
}  # fmt: skip


def test_what_the_owners_tools_run_by_themselves_is_left_out_and_named(tmp_path: Path) -> None:
    work = tmp_path / "work"
    plant_config(work)
    result = export_tree(work, tmp_path / "out")
    assert sorted(os.listdir(tmp_path / "out")) == [".gitignore", "main.py"]
    assert result.skipped_config == len(CONFIG_PATHS) and result.files == 2
    named = [path for why, path in result.named if why == "config"]
    assert set(named) <= CONFIG_PATHS and len(named) == export.MAX_NAMED  # the first ones
    assert result.details()["skipped_config"] == len(CONFIG_PATHS)


@pytest.mark.parametrize(
    "path",
    [
        ".VSCode/tasks.json", ".Claude/settings.json", "sub/.claude/settings.json",
        "a/b/.MCP.JSON", "pkg/claude.md", "pkg/Claude.Local.MD", "x/.ENVRC", "x/.IDEA/w.xml",
        "lib/.GitHub/Workflows/ci.yml", ".cursor/rules", ".devcontainer/Dockerfile",
        "AGENTS.md", "sub/agents.MD", "GEMINI.md", "pkg/Gemini.md", ".cursorrules",
        "a/.CursorRules", ".windsurfrules", "b/.WindsurfRules", ".clinerules", "c/.ClineRules",
        ".clinerules/01-style.md", "d/.CLINERULES/x.md", ".github/copilot-instructions.md",
        "e/.GitHub/Copilot-Instructions.MD", ".github/prompts/p.prompt.md",
        ".github/agents/a.md", ".github/actions/x/action.yml", "opencode.json",
        "f/OpenCode.JSON", "claude_desktop_config.json", "g/MCP_Config.json",
        "w.code-workspace", "h/W.Code-Workspace", ".pre-commit-config.yaml", ".husky/pre-commit",
        ".eslintrc.js", ".eslintrc.cjs", ".prettierrc.js", ".prettierrc.mjs", ".pylintrc",
        ".flake8", ".npmrc", ".env", ".tool-versions", ".mise.toml", ".zed/settings.json",
        ".windsurf/rules.md", ".roo/rules.md", ".amazonq/rules/x.md", ".aider.conf.yml",
        ".continue/config.json", "i/.anything-new",
    ],
)  # fmt: skip
def test_in_any_case_and_at_any_depth(tmp_path: Path, path: str) -> None:
    """APFS opens ``.VSCode`` as ``.vscode``, and Claude Code reads a CLAUDE.md or a
    ``.claude/`` of a subfolder too. A name with a dot first is out unless it is known to be
    harmless: the list of tools that run them by themselves always lags behind."""
    work = tmp_path / "work"
    (work / path).parent.mkdir(parents=True, exist_ok=True)
    (work / path).write_text("x\n")
    (work / "keep.txt").write_text("y\n")
    result = export_tree(work, tmp_path / "out")
    assert not os.path.lexists(tmp_path / "out" / path)
    assert (tmp_path / "out" / "keep.txt").exists()
    assert result.skipped_config == 1 and result.files == 1


@pytest.mark.parametrize(
    "name",
    [
        ".gitignore", ".GitIgnore", ".gitattributes", ".editorconfig", ".dockerignore",
        ".python-version", ".nvmrc", ".node-version", ".prettierrc", ".prettierrc.json",
        ".prettierrc.yaml", ".prettierrc.yml", ".prettierrc.toml", ".prettierrc.json5",
        ".eslintrc", ".eslintrc.json", ".eslintrc.yaml", ".eslintrc.yml", ".prettierignore",
        ".eslintignore", ".ruff.toml",
    ],
)  # fmt: skip
def test_harmless_dot_files_are_copied_at_any_depth(tmp_path: Path, name: str) -> None:
    work = tmp_path / "work"
    (work / "sub").mkdir(parents=True)
    (work / name).write_text("x\n")
    (work / "sub" / name).write_text("y\n")
    result = export_tree(work, tmp_path / "out")
    assert (tmp_path / "out" / name).read_text() == "x\n"
    assert (tmp_path / "out" / "sub" / name).read_text() == "y\n"
    assert result.skipped_config == 0 and result.files == 2


def test_a_harmless_name_as_a_folder_is_still_out(tmp_path: Path) -> None:
    """Only files: a folder called ``.gitignore`` is no file of git's."""
    work = tmp_path / "work"
    (work / ".gitignore").mkdir(parents=True)
    (work / ".gitignore" / "x").write_text("x\n")
    result = export_tree(work, tmp_path / "out")
    assert os.listdir(tmp_path / "out") == [] and result.skipped_config == 1


def test_names_like_the_left_out_ones_are_copied(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "docs" / "workflows").mkdir(parents=True)
    (work / "docs" / "workflows" / "a.md").write_text("x\n")
    (work / "claude.md.txt").write_text("x\n")
    (work / "docs" / "copilot-instructions.md").write_text("x\n")
    (work / "docs" / "agents.md.bak").write_text("x\n")
    (work / "code-workspace.md").write_text("x\n")
    (work / "file.").write_text("x\n")
    result = export_tree(work, tmp_path / "out")
    out = tmp_path / "out"
    assert (out / "docs" / "workflows" / "a.md").exists()
    assert (out / "docs" / "copilot-instructions.md").exists()
    assert (out / "docs" / "agents.md.bak").exists() and (out / "code-workspace.md").exists()
    assert (out / "claude.md.txt").exists() and (out / "file.").exists()
    assert result.skipped_config == 0


def test_include_config_takes_them_but_never_git(tmp_path: Path) -> None:
    work = tmp_path / "work"
    plant_config(work)
    plant_repo(work / ".git")
    result = export_tree(work, tmp_path / "out", include_config=True)
    out = tmp_path / "out"
    assert (out / ".claude" / "settings.json").read_text() == HOOK
    assert (out / ".mcp.json").exists() and (out / ".github" / "workflows" / "ci.yml").exists()
    assert (out / "AGENTS.md").exists() and (out / ".github" / "copilot-instructions.md").exists()
    assert (out / ".brand-new-tool").exists() and (out / "proyecto.code-workspace").exists()
    assert not os.path.lexists(out / ".git")
    assert result.skipped_config == 0 and result.skipped_git == 1


def test_config_left_out_does_not_count_towards_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    (work / ".claude").mkdir(parents=True)
    (work / ".claude" / "big").write_bytes(b"x" * 1000)
    (work / "small").write_bytes(b"y")
    monkeypatch.setattr(export, "MAX_BYTES", 100)
    assert export_tree(work, tmp_path / "out").files == 1
    with pytest.raises(ExportError, match="demasiado grande"):
        export_tree(work, tmp_path / "out2", include_config=True)


# --- names (B6) ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a\x1b[31mred", "zero​width", "tab\tname", "bell\x07"])
def test_a_name_that_is_not_printable_is_skipped_and_named_escaped(
    tmp_path: Path, name: str
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / name).write_text("x")
    (work / "ok.txt").write_text("y")
    result = export_tree(work, tmp_path / "out")
    assert os.listdir(tmp_path / "out") == ["ok.txt"]
    assert result.skipped_names == 1
    ((why, shown),) = result.named
    assert why == "name" and shown.isprintable() and "\\" in shown


def test_a_name_that_collides_by_case_is_skipped_and_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a case-insensitive destination (APFS), ``readme`` after ``README`` already exists:
    it is skipped and named, and the copy goes on (the source here cannot hold both names on
    the Mac, so the destination says it, as APFS would)."""
    work = tmp_path / "work"
    (work / "Src").mkdir(parents=True)
    (work / "README").write_text("uno\n")
    (work / "Src" / "a.py").write_text("a\n")
    real_open, real_mkdir = os.open, os.mkdir

    def open_(path: object, flags: int, *args: object, **options: object) -> int:
        if path == "README" and flags & os.O_EXCL:
            raise FileExistsError(17, "File exists")
        return real_open(path, flags, *args, **options)  # type: ignore[arg-type]

    def mkdir(path: object, *args: object, **options: object) -> None:
        if path == "Src":
            raise FileExistsError(17, "File exists")
        real_mkdir(path, *args, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(export.os, "open", open_)
    monkeypatch.setattr(export.os, "mkdir", mkdir)
    result = export_tree(work, tmp_path / "out")
    assert result.skipped_collisions == 2
    assert {("case", "README"), ("case", "Src")} <= set(result.named)


def test_only_the_first_names_are_kept(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    for index in range(export.MAX_NAMED + 5):
        (work / f"{index}\x1b").write_text("x")
    result = export_tree(work, tmp_path / "out")
    assert result.skipped_names == export.MAX_NAMED + 5
    assert len(result.named) == export.MAX_NAMED
    assert result.details()["skipped"] == [list(item) for item in result.named]


# --- where code runs from (B5) ------------------------------------------------------------------


def test_inside_a_python_environment_is_refused(tmp_path: Path, protected: list[Path]) -> None:
    venv = tmp_path / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    with pytest.raises(ExportError, match="código"):
        check_destination(str(venv / "lib" / "out"), protected)


def test_inside_an_import_path_is_refused(
    tmp_path: Path, protected: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    lib = tmp_path / "Lib"
    lib.mkdir()
    monkeypatch.setattr(export.sys, "path", [*export.sys.path, str(lib)])
    for text in (lib / "pkg", tmp_path / "lib" / "pkg"):  # the case does not save it (APFS)
        if text.parent.exists():
            with pytest.raises(ExportError, match="código"):
                check_destination(str(text), protected)


def test_inside_backtides_own_checkout_is_refused(protected: list[Path]) -> None:
    checkout = Path(export.__file__).resolve().parents[2]
    with pytest.raises(ExportError, match="código"):
        check_destination(str(checkout / "exportado"), protected)


# --- a git bundle (A1: the commits, as data) ----------------------------------------------------


def bundle_home(
    tmp_path: Path, body: bytes = b"# v2 git bundle\nabc refs/heads/main\n\nPACK"
) -> Path:
    home = tmp_path / "snap" / "home"
    (home / export.BUNDLE_DIR).mkdir(parents=True)
    (home / export.BUNDLE_DIR / BUNDLE).write_bytes(body)
    return home


BUNDLE = "export-" + "ab" * 16 + ".bundle"


def test_a_bundle_is_copied_as_one_plain_file(tmp_path: Path) -> None:
    home = bundle_home(tmp_path)
    out = tmp_path / "proyecto.bundle"
    result = export.export_bundle(home, BUNDLE, out)
    assert out.read_bytes().startswith(b"# v2 git bundle\n")
    assert stat.S_IMODE(out.stat().st_mode) == 0o644
    assert (result.files, result.folders, result.bytes) == (1, 0, out.stat().st_size)


@pytest.mark.parametrize(
    "body", [b"[core]\n\tfsmonitor = x\n", b"", b"# v2 git bundl", b"#!/bin/sh\n"]
)
def test_what_is_not_a_bundle_is_refused(tmp_path: Path, body: bytes) -> None:
    home = bundle_home(tmp_path, body)
    with pytest.raises(ExportError, match="bundle"):
        export.export_bundle(home, BUNDLE, tmp_path / "x.bundle")
    assert not os.path.lexists(tmp_path / "x.bundle")


def test_a_bundle_behind_a_link_is_refused(tmp_path: Path) -> None:
    home = bundle_home(tmp_path)
    real = home / export.BUNDLE_DIR / BUNDLE
    (home / "elsewhere").mkdir()
    real.rename(home / "elsewhere" / BUNDLE)
    real.symlink_to(home / "elsewhere" / BUNDLE)
    with pytest.raises(ExportError):
        export.export_bundle(home, BUNDLE, tmp_path / "a.bundle")
    folder = home / export.BUNDLE_DIR
    os.unlink(real)
    folder.rmdir()
    folder.symlink_to(home / "elsewhere")
    with pytest.raises(ExportError):
        export.export_bundle(home, BUNDLE, tmp_path / "b.bundle")
    assert not os.path.lexists(tmp_path / "a.bundle") and not os.path.lexists(tmp_path / "b.bundle")


@pytest.mark.parametrize("name", ["../x.bundle", "export-zz.bundle", "config", ""])
def test_an_odd_bundle_name_is_refused(tmp_path: Path, name: str) -> None:
    with pytest.raises(ExportError):
        export.export_bundle(bundle_home(tmp_path), name, tmp_path / "x.bundle")


def test_a_bundle_never_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "x.bundle"
    out.write_text("mine")
    with pytest.raises(ExportError, match="nunca se sobrescribe"):
        export.export_bundle(bundle_home(tmp_path), BUNDLE, out)
    assert out.read_text() == "mine"


# -- code review of 2026-10-29 ---------------------------------------------------------------


def test_an_installed_service_exports_only_into_its_folder(
    tmp_path: Path, protected: list[Path]
) -> None:
    """S1: systemd lets an installed service write only its export folder; elsewhere the owner
    hears where to export, not a misleading "no existe" (ProtectHome) or a copy lost in a
    private /tmp."""
    folder = tmp_path / "backtide-export"
    folder.mkdir()
    assert check_destination(str(folder / "mine"), protected, inside=folder) == folder / "mine"
    private_tmp = Path("/tmp") / "mine"  # what PrivateTmp hid  # noqa: S108
    for elsewhere in (tmp_path / "mine", tmp_path / "nope" / "mine", private_tmp):
        with pytest.raises(ExportError, match=f"solo puede exportar dentro de {folder}"):
            check_destination(str(elsewhere), protected, inside=folder)
    (folder / "out").symlink_to(tmp_path)  # a way out by a link
    with pytest.raises(ExportError, match="por un enlace"):
        check_destination(str(folder / "out" / "mine"), protected, inside=folder)


def test_a_wide_folder_needs_few_descriptors(tmp_path: Path) -> None:
    """S2: one descriptor per queued subfolder ran out in a node_modules; now only the path
    being walked is open, so 300 folders copy with 40 descriptors to spare."""
    import resource

    work = tmp_path / "work"
    for i in range(300):
        (work / "node_modules" / f"pkg{i}").mkdir(parents=True)
        (work / "node_modules" / f"pkg{i}" / "index.js").write_text("x")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    already = len(os.listdir("/dev/fd"))  # what the test run holds open already
    resource.setrlimit(resource.RLIMIT_NOFILE, (already + 40, hard))
    try:
        result = export_tree(work, tmp_path / "out")
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    assert (result.files, result.folders) == (300, 301)
    assert (tmp_path / "out" / "node_modules" / "pkg299" / "index.js").read_text() == "x"


def test_a_folder_that_cannot_be_read_is_an_export_error(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*_: object) -> None:
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(export, "_count", failing)
    with pytest.raises(ExportError, match="no se puede leer la carpeta de trabajo"):
        export_tree(source, tmp_path / "out")
    assert not (tmp_path / "out").exists()
