import os
import stat
from pathlib import Path

import pytest

from tests.conftest import call_unblocking_fifo
from vigia.blackbox import KEY_SIZE, BlackBoxError, create_key, load_key


def test_create_key_writes_32_random_bytes_readable_only_by_the_owner(tmp_path: Path) -> None:
    path = tmp_path / "blackbox.key"
    key = create_key(path)
    assert len(key) == KEY_SIZE
    assert path.read_bytes() == key
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    assert load_key(path) == key


def test_create_key_ignores_a_permissive_umask(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        path = tmp_path / "k"
        create_key(path)
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_every_key_is_different(tmp_path: Path) -> None:
    assert create_key(tmp_path / "a") != create_key(tmp_path / "b")


def test_create_key_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "k"
    original = create_key(path)
    with pytest.raises(BlackBoxError, match="already exists"):
        create_key(path)
    assert path.read_bytes() == original


def test_create_key_does_not_follow_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    link = tmp_path / "k"
    link.symlink_to(target)
    with pytest.raises(BlackBoxError):
        create_key(link)
    assert not target.exists()


def test_create_key_in_a_missing_folder_fails_clearly(tmp_path: Path) -> None:
    with pytest.raises(BlackBoxError, match="cannot create"):
        create_key(tmp_path / "missing" / "k")


def _write_key(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


@pytest.mark.parametrize("size", [0, 16, KEY_SIZE - 1, KEY_SIZE + 1, 64])
def test_load_key_requires_exactly_32_bytes(tmp_path: Path, size: int) -> None:
    path = _write_key(tmp_path / "k", b"x" * size)
    with pytest.raises(BlackBoxError, match="exactly 32 bytes"):
        load_key(path)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o666, 0o610, 0o601])
def test_load_key_rejects_keys_open_to_group_or_others(tmp_path: Path, mode: int) -> None:
    path = _write_key(tmp_path / "k", b"x" * KEY_SIZE, mode)
    with pytest.raises(BlackBoxError, match="group or others"):
        load_key(path)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_load_key_accepts_owner_only_modes(tmp_path: Path, mode: int) -> None:
    path = _write_key(tmp_path / "k", b"x" * KEY_SIZE, mode)
    assert load_key(path) == b"x" * KEY_SIZE


def test_load_key_rejects_a_symlink(tmp_path: Path) -> None:
    real = _write_key(tmp_path / "real", b"x" * KEY_SIZE)
    link = tmp_path / "k"
    link.symlink_to(real)
    with pytest.raises(BlackBoxError, match="symlink"):
        load_key(link)


def test_load_key_rejects_a_directory(tmp_path: Path) -> None:
    folder = tmp_path / "k"
    folder.mkdir(mode=0o700)
    with pytest.raises(BlackBoxError):
        load_key(folder)


def test_load_key_of_a_missing_file_fails_clearly(tmp_path: Path) -> None:
    with pytest.raises(BlackBoxError, match="cannot open"):
        load_key(tmp_path / "missing")


def test_load_key_rejects_a_key_owned_by_another_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_key(tmp_path / "blackbox.key", b"k" * KEY_SIZE)
    owner = path.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(BlackBoxError, match="not owned by this user"):
        load_key(path)


def test_load_key_never_blocks_on_a_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "blackbox.key"
    os.mkfifo(fifo, 0o600)
    outcome = call_unblocking_fifo(lambda: load_key(fifo), fifo)
    assert isinstance(outcome, BlackBoxError), outcome
    assert "not a regular file" in str(outcome)
