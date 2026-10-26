"""The web reads only the paths it needs from the configuration: never the gateway token, never
the black box's key. (ServiceConfig.from_file reads both, which is why the web does not use it.)"""

import os
from pathlib import Path

import pytest

from backtide.service.config import ConfigError
from backtide.web.paths import WebPaths


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    path.write_text(text)
    path.chmod(mode)
    return path


def test_it_reads_the_state_and_the_volume_and_nothing_else(tmp_path: Path) -> None:
    config = write(
        tmp_path / "backtide.toml", 'state_dir = "/var/lib/backtide"\nvolume = "/mnt/vol"\n'
    )
    paths = WebPaths.from_file(config)
    assert paths.blackbox_db == Path("/var/lib/backtide/blackbox.db")
    assert paths.volume == Path("/mnt/vol")
    # T12b: where the service listens (the web only connects; it never opens a secret)
    assert paths.control_socket == Path("/var/lib/backtide/control.sock")


def test_a_complete_service_config_is_accepted_as_it_is(tmp_path: Path) -> None:
    config = write(
        tmp_path / "backtide.toml",
        'state_dir = "/var/lib/backtide"\nvolume = "/mnt/vol"\ncycle_interval = 60\n'
        'workspace_limit = 1000000\n[agent]\nmemory = "1g"\n',
    )
    assert WebPaths.from_file(config).volume == Path("/mnt/vol")


def test_the_token_and_the_key_are_never_opened(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "gateway.token").write_text("a-secret")
    (state / "blackbox.key").write_bytes(bytes(32))
    for name in ("gateway.token", "blackbox.key"):
        (state / name).chmod(0)  # an unprivileged user could not read them: still fine
    config = write(tmp_path / "backtide.toml", f'state_dir = "{state}"\nvolume = "{tmp_path}/v"\n')
    opened: list[str] = []
    real_open = os.open
    monkeypatch.setattr(
        os, "open", lambda p, *a, **k: (opened.append(str(p)), real_open(p, *a, **k))[1]
    )
    WebPaths.from_file(config)
    assert opened == [str(config)]


@pytest.mark.parametrize(
    "text",
    [
        "",
        'volume = "/mnt/vol"\n',
        'state_dir = "/s"\n',
        'state_dir = "relative"\nvolume = "/v"\n',
        'state_dir = "/s/../x"\nvolume = "/v"\n',
        'state_dir = "/s"\nvolume = 5\n',
        "this is not toml",
    ],
)
def test_bad_configs_are_config_errors(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        WebPaths.from_file(write(tmp_path / "backtide.toml", text))


def test_a_config_others_can_write_is_refused(tmp_path: Path) -> None:
    config = write(tmp_path / "backtide.toml", 'state_dir = "/s"\nvolume = "/v"\n', 0o666)
    with pytest.raises(ConfigError, match="writable"):
        WebPaths.from_file(config)


def test_a_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        WebPaths.from_file(tmp_path / "nope.toml")


class _OwnedBy:
    """An ``os.fstat`` result as if the file belonged to ``uid`` (the Mac cannot chown)."""

    def __init__(self, real: os.stat_result, uid: int) -> None:
        self.st_mode, self.st_size, self.st_uid = real.st_mode, real.st_size, uid


def _files_owned_by(monkeypatch: pytest.MonkeyPatch, uid: int) -> None:
    import backtide.service.config as config_module

    real_fstat = os.fstat
    monkeypatch.setattr(config_module.os, "fstat", lambda fd: _OwnedBy(real_fstat(fd), uid))


def test_an_installed_web_reads_roots_web_toml_with_its_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T13-3: backtide-web.service reads /etc/backtide/web.toml, root's, 0640 with the group
    backtide-web. Root's (or the reader's own) is accepted; anybody else's is not."""
    config = write(tmp_path / "web.toml", 'state_dir = "/s"\nvolume = "/v"\n', 0o640)
    _files_owned_by(monkeypatch, 0)
    assert WebPaths.from_file(config).volume == Path("/v")


def test_a_web_toml_of_another_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write(tmp_path / "web.toml", 'state_dir = "/s"\nvolume = "/v"\n', 0o640)
    _files_owned_by(monkeypatch, os.geteuid() + 4242)
    with pytest.raises(ConfigError, match="owned by uid"):
        WebPaths.from_file(config)


def test_a_web_toml_its_group_can_write_is_refused_even_from_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write(tmp_path / "web.toml", 'state_dir = "/s"\nvolume = "/v"\n', 0o660)
    _files_owned_by(monkeypatch, 0)
    with pytest.raises(ConfigError, match="writable"):
        WebPaths.from_file(config)
