"""The logic of scripts/demo/demo.py that does not need the VM: the config it writes, the
refusals before any privileged command, and the lines of the live view."""

import secrets
import tomllib
from datetime import datetime
from pathlib import Path

import pytest

from backtide.blackbox import Event, Source
from backtide.service.config import ServiceConfig
from backtide.snapshots import SnapshotError
from scripts.demo import demo


def test_the_written_config_is_one_the_service_accepts(tmp_path: Path) -> None:
    paths = demo.Paths(tmp_path / "demo")
    paths.state.mkdir(parents=True, mode=0o700)
    paths.volume.mkdir(parents=True)
    (paths.state / "gateway.token").write_text(secrets.token_urlsafe(32) + "\n")
    (paths.state / "gateway.token").chmod(0o600)
    paths.config.write_text(demo.render_config(paths, 1000, 1000))
    paths.config.chmod(0o600)

    config = ServiceConfig.from_file(paths.config)

    assert config.workspace_limit == 192 * 1024**2
    assert config.cycle_interval == demo.CYCLE_INTERVAL
    assert config.volume == paths.volume
    assert config.state_dir == paths.state
    assert config.jail_config().name == demo.CONTAINER
    assert tomllib.loads(paths.config.read_text())["agent"]["network"] == demo.NETWORK
    assert "allow_shared_ids" not in paths.config.read_text()  # never a setting of the file


def test_mountinfo_lines_are_read_with_their_escapes() -> None:
    line = "40 29 0:35 / /home/me/my\\040demo/mnt rw,noatime shared:1 - btrfs /dev/loop3 rw"
    mount = demo.parse_mountinfo_line(line)
    assert mount == demo.Mount(Path("/home/me/my demo/mnt"), "btrfs", "/dev/loop3")
    assert demo.mount_at(Path("/home/me/my demo/mnt"), line) == mount
    assert demo.mount_at(Path("/elsewhere"), line) is None


def test_a_folder_without_the_demo_mark_is_never_deleted(tmp_path: Path) -> None:
    other = tmp_path / "somebody-elses"
    other.mkdir()
    (other / "precious.txt").write_text("keep")

    with pytest.raises(demo.DemoError, match="no es de la demo"):
        demo.teardown(demo.Paths(other))

    assert (other / "precious.txt").read_text() == "keep"


def test_only_the_known_sudo_commands_are_allowed() -> None:
    with pytest.raises(demo.DemoError, match="no está permitido"):
        demo.sudo("rm", "-rf", "/")


def test_the_quota_command_is_refused_outside_the_demo_volume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def never(*args: object, **kwargs: object) -> None:
        raise AssertionError("sudo must not run")

    monkeypatch.setattr(demo, "is_demo_mount", lambda paths: False)
    monkeypatch.setattr(demo.subprocess, "run", never)

    with pytest.raises(SnapshotError, match="not the demo volume"):
        demo.sudo_qgroup_limit(tmp_path, 1024)


def test_the_project_files_are_recognised_in_a_snapshot(tmp_path: Path) -> None:
    for name, text in demo.DEMO_FILES.items():
        (tmp_path / name).write_text(text)
    assert demo.project_matches(tmp_path, present=True)
    assert not demo.project_matches(tmp_path, present=False)

    for name in demo.DELETED_FILES:
        (tmp_path / name).unlink()
    assert not demo.project_matches(tmp_path, present=True)
    assert demo.project_matches(tmp_path, present=False)
    assert not demo.project_matches(tmp_path / "missing", present=False)


def _event(source: Source, action: str, target: str) -> Event:
    return Event(
        seq=1,
        ts="2026-10-16T15:19:47.123456Z",
        source=source,
        action=action,
        target=target,
        details={},
        risk=0,
        snapshot_id=None,
        prev_hash="0" * 64,
        hash="1" * 64,
    )


def test_the_live_view_shows_the_demo_files_and_hides_the_agents_own_noise() -> None:
    assert demo.describe(_event(Source.FILE, "modify", "state/state/openclaw.sqlite-wal")) is None
    line = demo.describe(_event(Source.FILE, "delete", "work/proyecto/clientes.csv"))
    assert line is not None
    assert "archivo" in line and "delete" in line and line.endswith("work/proyecto/clientes.csv")
    snapshot = demo.describe(_event(Source.SNAPSHOT, "take", "20261016T151947.648086Z-periodic"))
    assert snapshot is not None and "instantánea" in snapshot
    assert datetime.strptime(snapshot[:8], "%H:%M:%S")  # a time, in the local zone


def _paths_with_state(tmp_path: Path) -> "demo.Paths":
    paths = demo.Paths(tmp_path / "demo")
    paths.state.mkdir(parents=True, mode=0o700)
    return paths


def test_the_founders_bot_is_copied_with_mode_600(tmp_path: Path) -> None:
    source = tmp_path / "telegram.toml"
    source.write_bytes(b'token = "1:fake"\nchat_id = 1\n')
    source.chmod(0o600)
    paths = _paths_with_state(tmp_path)
    assert demo.copy_telegram(paths, source)
    copied = paths.state / "telegram.toml"
    assert copied.read_bytes() == source.read_bytes()
    assert copied.stat().st_mode & 0o777 == 0o600


def test_without_a_bot_there_is_nothing_to_copy(tmp_path: Path) -> None:
    paths = _paths_with_state(tmp_path)
    assert not demo.copy_telegram(paths, tmp_path / "missing.toml")
    assert not (paths.state / "telegram.toml").exists()


def test_a_bot_file_others_can_read_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "telegram.toml"
    source.write_bytes(b'token = "1:fake"\n')
    source.chmod(0o644)
    with pytest.raises(demo.DemoError, match="600"):
        demo.copy_telegram(_paths_with_state(tmp_path), source)


def test_a_linked_bot_file_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.toml"
    real.write_bytes(b'token = "1:fake"\n')
    real.chmod(0o600)
    link = tmp_path / "telegram.toml"
    link.symlink_to(real)
    with pytest.raises(demo.DemoError, match="archivo normal"):
        demo.copy_telegram(_paths_with_state(tmp_path), link)


def test_stopping_the_demo_also_removes_the_old_names_the_proxy_and_the_fake_internet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> object:
        commands.append(argv)
        listing = "\n".join([demo.OLD_NETWORK, demo.PROXY_NETWORK, "someone-elses-net"])
        return type("Done", (), {"stdout": listing})()

    monkeypatch.setattr(demo, "run", fake_run)

    demo.remove_agent()

    removed_containers = {c[-1] for c in commands if c[:2] == ["docker", "rm"]}
    removed_networks = {c[-1] for c in commands if c[:3] == ["docker", "network", "rm"]}
    assert removed_containers == {
        demo.CONTAINER,
        demo.PROXY_CONTAINER,
        demo.OLD_CONTAINER,
        demo.FAKE_INTERNET,
    }
    assert removed_networks == {demo.OLD_NETWORK, demo.PROXY_NETWORK}  # not someone-elses-net
    assert all("--volumes" in c for c in commands if c[:2] == ["docker", "rm"])
