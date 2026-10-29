"""The service's side of `backtide entrar`, `tarea`, `importar` and `exportar` (T17a-4,
``Guardian.open_shell`` and ``Guardian.export``): `entrar` and `tarea` for a profile with shell
commands (OpenClaw too, D27), `importar` and `exportar` only for a shell profile, only with the
agent running, always recorded first. The Guardian is test_service_guardian.py's, with its fakes."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from backtide.jail.profiles import CLAUDE_CODE, OPENCLAW
from backtide.service.guardian import AgentState
from backtide.service.shell import ExportStatus, ShellStatus
from backtide.snapshots import Reason, Snapshot
from tests.test_service_guardian import World, world  # noqa: F401 - the fixture

NAME = "backtide-agente"


def shellable(world: World, profile: object = CLAUDE_CODE) -> World:  # noqa: F811
    world.jail.config = SimpleNamespace(  # type: ignore[attr-defined]
        profile=profile, name=NAME, uid=61000, gid=61000
    )
    return world


@pytest.fixture
def shell_world(world: World) -> World:  # noqa: F811
    shellable(world)
    world.guardian.start()
    return world


def test_a_running_shell_agent_is_opened_and_recorded(shell_world: World) -> None:
    outcome = shell_world.guardian.open_shell("task", resume=True, requested_by="cli (uid 1)")
    assert outcome.status is ShellStatus.READY
    assert (outcome.container, outcome.user, outcome.workdir) == (
        NAME,
        "61000:61000",
        "/workspace/work",
    )
    assert outcome.container_id == "c0de" * 16  # the container it started and checked (B4)
    event = shell_world.only("agent_shell")
    assert (event.source, event.target) == ("system", "task")
    assert event.details == {"kind": "task", "continue": True, "requested_by": "cli (uid 1)"}


def test_an_import_records_its_counts(shell_world: World) -> None:
    details = {"name": "repo", "source": "/home/me/repo", "files": 3, "bytes": 10, "replace": False}
    outcome = shell_world.guardian.open_shell("import", requested_by="cli", details=details)
    assert outcome.ready
    assert shell_world.only("agent_shell").details == {
        **details,
        "kind": "import",
        "continue": False,
        "requested_by": "cli",
    }


def test_openclaw_is_opened_for_a_task_and_recorded_with_what_was_asked(world: World) -> None:  # noqa: F811
    """D27: `tarea` reaches OpenClaw too (a turn through its Gateway), recorded first like
    Claude Code's, with what was asked (struck and cut by the control socket)."""
    shellable(world, OPENCLAW)
    world.guardian.start()
    asked = {"prompt": "/new hola [tachado]", "slash": True}
    outcome = world.guardian.open_shell("task", requested_by="cli", details=asked)
    assert outcome.ready and outcome.workdir == "/workspace/work"
    assert world.only("agent_shell").details == {
        **asked,
        "kind": "task",
        "continue": False,
        "requested_by": "cli",
    }


@pytest.mark.parametrize("kind", ["session", "import", "bundle"])
def test_openclaw_is_never_opened_for_a_session_an_import_or_an_export(
    world: World,  # noqa: F811
    kind: str,
) -> None:  # noqa: F811
    shellable(world, OPENCLAW)
    world.guardian.start()
    outcome = world.guardian.open_shell(kind, requested_by="cli")
    assert outcome.status is ShellStatus.NOT_SHELL and "openclaw" in outcome.message
    assert not world.events("agent_shell")
    assert world.guardian.export("/tmp/x", requested_by="cli").status is ExportStatus.NOT_SHELL  # noqa: S108


def test_an_agent_without_shell_commands_is_never_opened(world: World) -> None:  # noqa: F811
    import dataclasses

    from backtide.jail.profile import ShellCommands

    shellable(world, dataclasses.replace(OPENCLAW, shell=None))
    world.guardian.start()
    for kind in ("session", "task"):
        assert world.guardian.open_shell(kind, requested_by="cli").status is ShellStatus.NOT_SHELL
    no_session = ShellCommands(session=(), task=("/bin/agent",))
    shellable(world, dataclasses.replace(OPENCLAW, shell=no_session))
    assert world.guardian.open_shell("session", requested_by="cli").status is ShellStatus.NOT_SHELL
    assert world.guardian.open_shell("task", requested_by="cli").ready
    assert [e.target for e in world.events("agent_shell")] == ["task"]


def test_before_the_service_runs_nothing_is_opened(world: World) -> None:  # noqa: F811
    shellable(world)
    outcome = world.guardian.open_shell("session", requested_by="cli")
    assert outcome.status is ShellStatus.NOT_RUNNING


def test_a_paused_or_stopped_agent_is_not_opened(shell_world: World) -> None:
    guardian = shell_world.guardian
    guardian._set_state(AgentState.FROZEN)  # noqa: SLF001 - what a pause by space leaves
    outcome = guardian.open_shell("session", requested_by="cli")
    assert outcome.status is ShellStatus.NOT_RUNNING and "backtide seguir" in outcome.message
    guardian._set_state(AgentState.STARTING)  # noqa: SLF001
    outcome = guardian.open_shell("session", requested_by="cli")
    assert outcome.status is ShellStatus.NOT_RUNNING and "starting" in outcome.message
    assert not shell_world.events("agent_shell")


def test_without_a_black_box_nothing_is_opened(shell_world: World) -> None:
    from backtide.blackbox import BlackBoxError

    shell_world.box.append_error = BlackBoxError("disk full")
    outcome = shell_world.guardian.open_shell("session", requested_by="cli")
    assert outcome.status is ShellStatus.FAILED and "caja negra" in outcome.message
    assert outcome.container == ""


def test_an_unknown_kind_is_refused(shell_world: World) -> None:
    assert shell_world.guardian.open_shell("root", requested_by="cli").status is ShellStatus.FAILED


# --- exportar -----------------------------------------------------------------------------------


def with_work(world: World, files: dict[str, str]) -> None:  # noqa: F811
    """Every snapshot the fake volume takes gets ``files`` in its work folder."""
    volume = world.volume
    take = volume.take

    def taking(reason: Reason) -> Snapshot:
        snapshot = take(reason)
        work = volume.snapshots_dir / snapshot.id / "agente" / "work"
        work.mkdir(parents=True)
        for name, text in files.items():
            (work / name).write_text(text)
        return snapshot

    volume.take = taking  # type: ignore[method-assign]


def test_an_export_takes_a_snapshot_and_copies_its_work_folder(
    shell_world: World, tmp_path: Path
) -> None:
    with_work(shell_world, {"notes.txt": "uno\n"})
    out = tmp_path / "out"
    outcome = shell_world.guardian.export(str(out), requested_by="cli (uid 1)")
    assert outcome.status is ExportStatus.DONE, outcome.message
    assert (out / "notes.txt").read_text() == "uno\n"
    take = [e for e in shell_world.events("take") if e.details["trigger"] == "export"]
    assert take and take[0].details["reason"] == "manual"
    event = shell_world.only("export")
    assert (event.source, event.target, event.risk) == ("system", str(out.resolve()), 1)
    assert event.snapshot_id == outcome.snapshot == take[0].snapshot_id
    assert event.details["files"] == 1 and event.details["requested_by"] == "cli (uid 1)"


def test_an_export_into_backtides_state_is_refused_without_a_snapshot(shell_world: World) -> None:
    before = len(shell_world.events("take"))
    target = shell_world.config.state_dir / "out"
    outcome = shell_world.guardian.export(str(target), requested_by="cli")
    assert outcome.status is ExportStatus.INVALID and "protege" in outcome.message
    assert len(shell_world.events("take")) == before and not target.exists()


def test_an_export_that_fails_is_recorded(shell_world: World, tmp_path: Path) -> None:
    out = tmp_path / "out"  # the fake snapshot has no work folder: it cannot be opened
    outcome = shell_world.guardian.export(str(out), requested_by="cli")
    assert outcome.status is ExportStatus.FAILED
    assert shell_world.only("export_failed").risk == 1


def test_any_failure_of_the_copy_is_recorded(
    shell_world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S2: not only an ExportError: a raw error is recorded too, by its kind only (an OSError
    may quote a name the agent chose), and the owner is told."""
    from backtide.service import guardian

    def failing(*_: object, **__: object) -> None:
        raise OSError(24, "Too many open files", "agent-chosen-name")

    monkeypatch.setattr(guardian, "export_tree", failing)
    outcome = shell_world.guardian.export(str(tmp_path / "out"), requested_by="cli")
    assert outcome.status is ExportStatus.FAILED and "inesperado" in outcome.message
    assert shell_world.only("export_failed").details["error"] == "OSError"


def test_an_installed_service_says_where_to_export(
    shell_world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide.service.export import EXPORT_DIR_ENV

    folder = tmp_path / "backtide-export"
    folder.mkdir()
    monkeypatch.setenv(EXPORT_DIR_ENV, str(folder))
    outcome = shell_world.guardian.export(str(tmp_path / "out"), requested_by="cli")
    assert outcome.status is ExportStatus.INVALID and str(folder) in outcome.message


def test_no_snapshot_no_export(shell_world: World, tmp_path: Path) -> None:
    from backtide.snapshots import SnapshotError

    shell_world.volume.take_error = SnapshotError("busy")
    outcome = shell_world.guardian.export(str(tmp_path / "out"), requested_by="cli")
    assert outcome.status is ExportStatus.FAILED and "instantánea" in outcome.message
    assert not (tmp_path / "out").exists()


def test_a_container_this_service_did_not_check_is_never_opened(shell_world: World) -> None:
    shell_world.jail.checked_id = None  # running, but not the one start() checked
    outcome = shell_world.guardian.open_shell("session", requested_by="cli")
    assert outcome.status is ShellStatus.FAILED and outcome.container_id == ""


def test_an_export_is_recorded_as_started_before_anything_is_copied(
    shell_world: World, tmp_path: Path
) -> None:
    with_work(shell_world, {"notes.txt": "uno\n"})
    out = tmp_path / "out"
    seen: list[bool] = []
    from backtide.service import guardian as guardian_module

    real = guardian_module.export_tree

    def copying(source: Path, target: Path, **options: bool) -> object:
        seen.append(bool(shell_world.events("export_started")))
        return real(source, target, **options)

    guardian_module.export_tree = copying  # type: ignore[assignment]
    try:
        outcome = shell_world.guardian.export(str(out), requested_by="cli")
    finally:
        guardian_module.export_tree = real  # type: ignore[assignment]
    assert outcome.status is ExportStatus.DONE and seen == [True]
    started = shell_world.only("export_started")
    assert started.details == {"kind": "tree", "include_config": False, "requested_by": "cli"}
    assert started.snapshot_id == outcome.snapshot
    assert shell_world.only("export").details["kind"] == "tree"


def test_what_the_owners_tools_run_is_left_out_and_recorded_by_name(
    shell_world: World, tmp_path: Path
) -> None:
    """Finding 5 of the final review: `.mcp.json`, `CLAUDE.md`, `.envrc`... stay in the jail
    unless the owner says `--incluir-config`, and the record names them."""
    with_work(shell_world, {".mcp.json": "{}", "CLAUDE.md": "x", ".envrc": "x", "a.py": "1"})
    out = tmp_path / "out"
    outcome = shell_world.guardian.export(str(out), requested_by="cli")
    assert outcome.status is ExportStatus.DONE, outcome.message
    assert sorted(path.name for path in out.iterdir()) == ["a.py"]
    event = shell_world.only("export")
    assert event.details["skipped_config"] == 3 and event.details["include_config"] is False
    assert sorted(path for why, path in event.details["skipped"] if why == "config") == [
        ".envrc", ".mcp.json", "CLAUDE.md",
    ]  # fmt: skip
    assert outcome.details["skipped_config"] == 3


def test_include_config_takes_them_and_is_recorded(shell_world: World, tmp_path: Path) -> None:
    with_work(shell_world, {".mcp.json": "{}", "a.py": "1"})
    out = tmp_path / "out"
    outcome = shell_world.guardian.export(str(out), requested_by="cli", include_config=True)
    assert outcome.status is ExportStatus.DONE, outcome.message
    assert (out / ".mcp.json").exists()
    assert shell_world.only("export_started").details["include_config"] is True
    assert shell_world.only("export").details["skipped_config"] == 0


def test_without_a_black_box_nothing_is_exported(shell_world: World, tmp_path: Path) -> None:
    from backtide.blackbox import BlackBoxError

    with_work(shell_world, {"notes.txt": "uno\n"})
    shell_world.box.append_error = BlackBoxError("disk full")  # the snapshot is still taken
    outcome = shell_world.guardian.export(str(tmp_path / "out"), requested_by="cli")
    assert outcome.status is ExportStatus.FAILED and "caja negra" in outcome.message
    assert outcome.snapshot  # taken, kept: nothing copied from it
    assert not (tmp_path / "out").exists()


def test_a_planted_git_folder_never_leaves(shell_world: World, tmp_path: Path) -> None:
    with_work(shell_world, {"main.py": "print(1)\n"})
    volume = shell_world.volume
    take = volume.take

    def planting(reason: Reason) -> Snapshot:
        snapshot = take(reason)
        git = volume.snapshots_dir / snapshot.id / "agente" / "work" / ".git"
        git.mkdir()
        (git / "config").write_text("[core]\n\tfsmonitor = touch /tmp/pwned\n")
        return snapshot

    volume.take = planting  # type: ignore[method-assign]
    out = tmp_path / "out"
    outcome = shell_world.guardian.export(str(out), requested_by="cli")
    assert outcome.status is ExportStatus.DONE
    assert sorted(p.name for p in out.iterdir()) == ["main.py"]
    assert outcome.details["skipped_git"] == 1 and outcome.details["skipped"] == [["git", ".git"]]
    assert shell_world.only("export").details["skipped_git"] == 1


BUNDLE = "export-" + "0f" * 16 + ".bundle"


def with_bundle(world: World, body: bytes) -> None:  # noqa: F811
    volume = world.volume
    take = volume.take

    def taking(reason: Reason) -> Snapshot:
        snapshot = take(reason)
        folder = volume.snapshots_dir / snapshot.id / "agente" / "home" / ".backtide-export"
        folder.mkdir(parents=True)
        (folder / BUNDLE).write_bytes(body)
        return snapshot

    volume.take = taking  # type: ignore[method-assign]


def test_a_bundle_export_copies_only_the_bundle(shell_world: World, tmp_path: Path) -> None:
    with_bundle(shell_world, b"# v2 git bundle\nabc refs/heads/main\n\nPACK")
    out = tmp_path / "proyecto.bundle"
    outcome = shell_world.guardian.export(
        str(out), requested_by="cli", bundle=BUNDLE, repo="proyecto"
    )
    assert outcome.status is ExportStatus.DONE, outcome.message
    assert out.read_bytes().startswith(b"# v2 git bundle")
    event = shell_world.only("export")
    assert (event.details["kind"], event.details["repo"], event.details["files"]) == (
        "bundle",
        "proyecto",
        1,
    )


@pytest.mark.parametrize("name", ["../../etc/passwd", "x.bundle", ""])
def test_an_odd_bundle_name_is_refused_before_a_snapshot(
    shell_world: World, tmp_path: Path, name: str
) -> None:
    before = len(shell_world.events("take"))
    outcome = shell_world.guardian.export(str(tmp_path / "x"), requested_by="cli", bundle=name)
    assert outcome.status is ExportStatus.INVALID
    assert len(shell_world.events("take")) == before


def test_what_is_not_a_bundle_is_not_exported(shell_world: World, tmp_path: Path) -> None:
    with_bundle(shell_world, b"[core]\n\tfsmonitor = touch /tmp/pwned\n")
    out = tmp_path / "x.bundle"
    outcome = shell_world.guardian.export(str(out), requested_by="cli", bundle=BUNDLE, repo=".")
    assert outcome.status is ExportStatus.FAILED and not out.exists()
    assert shell_world.only("export_failed").details["kind"] == "bundle"
