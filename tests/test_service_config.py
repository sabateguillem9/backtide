"""ServiceConfig: the TOML, the gateway token and the path checks. The token must never reach an
error message, a repr or a log (docs/19, section "Disposición")."""

import copy
import logging
import os
import pickle
from pathlib import Path

import pytest

from vigia.jail import AgentJailConfig
from vigia.service.config import (
    ConfigError,
    Secret,
    ServiceConfig,
    _require_private_state_dir,
)

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2  # 38 URL-safe characters
OTHER_TOKEN = "Another0Token_" + "Z9y8X7w6V5u4T3s2R1q0" * 2


@pytest.fixture
def layout(tmp_path: Path) -> Path:
    """``tmp_path/state`` (0700) with a good token file, next to an empty ``tmp_path/volume``."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    write_token(state / "gateway.token", TOKEN)
    (tmp_path / "volume").mkdir()
    return tmp_path


def write_token(path: Path, text: str, mode: int = 0o600) -> None:
    path.write_text(text + "\n")
    path.chmod(mode)


def write_toml(layout: Path, extra: str = "", mode: int = 0o600) -> Path:
    path = layout / "vigia.toml"
    path.write_text(f'state_dir = "{layout / "state"}"\nvolume = "{layout / "volume"}"\n{extra}')
    path.chmod(mode)
    return path


def everything_said_about(config: ServiceConfig) -> list[str]:
    return [repr(config), str(config), f"{config}", f"{config.gateway_token}", repr(vars(config))]


# --- Secret ------------------------------------------------------------------------------------


def test_a_secret_hides_its_value_everywhere_it_is_printed() -> None:
    secret = Secret(TOKEN)
    for text in (repr(secret), str(secret), f"{secret}", f"{secret!r}", "%s" % secret):  # noqa: UP031
        assert text == "[REDACTED]"
    assert secret.reveal() == TOKEN


def test_a_secret_in_a_container_or_an_exception_is_redacted() -> None:
    secret = Secret(TOKEN)
    assert TOKEN not in repr({"token": secret, "list": [secret], "tuple": (secret,)})
    assert TOKEN not in str(ValueError("bad", secret))
    assert TOKEN not in "".join(logging.Formatter().format(_record("value: %s", secret)))


def _record(message: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord("t", logging.ERROR, __file__, 1, message, args, None)


def test_a_secret_cannot_be_pickled_or_copied() -> None:
    secret = Secret(TOKEN)
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with pytest.raises(TypeError):
        copy.deepcopy(secret)


def test_a_secret_must_hold_a_string() -> None:
    with pytest.raises(TypeError):
        Secret(b"bytes")  # type: ignore[arg-type]


# --- loading -----------------------------------------------------------------------------------


def test_loads_a_minimal_file_with_the_defaults(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    assert config.state_dir == layout / "state"
    assert config.volume == layout / "volume"
    assert config.workspace_limit is None
    assert config.cycle_interval == 120.0
    assert config.prune_interval == 600.0
    assert config.gateway_token.reveal() == TOKEN


def test_the_state_layout_is_the_one_in_the_design(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    state = layout / "state"
    assert config.blackbox_db == state / "blackbox.db"
    assert config.blackbox_key == state / "blackbox.key"
    assert config.blackbox_checkpoint == state / "blackbox.checkpoint"
    assert config.gateway_token_file == state / "gateway.token"
    assert config.agent_config_dir == state / "openclaw"
    assert config.lock_file == state / "vigia.lock"
    assert config.pending_file == state / "rewind.pending"
    assert config.control_socket == state / "control.sock"


def test_the_options_are_read(layout: Path) -> None:
    config = ServiceConfig.from_file(
        write_toml(
            layout,
            "workspace_limit = 67108864\ncycle_interval = 30\nprune_interval = 90.5\n"
            '[agent]\nname = "mi-agente"\nmemory = "1g"\nuid = 62000\ngid = 62000\n',
        )
    )
    assert config.workspace_limit == 64 * 1024**2
    assert config.cycle_interval == 30
    assert config.prune_interval == 90.5
    jail = config.jail_config()
    assert isinstance(jail, AgentJailConfig)
    assert (jail.name, jail.memory, jail.uid, jail.gid) == ("mi-agente", "1g", 62000, 62000)


def test_the_jail_config_points_at_the_workspace_and_a_config_outside_the_volume(
    layout: Path,
) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    jail = config.jail_config()
    assert jail.workspace == layout / "volume" / "workspace"
    assert jail.config_dir == layout / "state" / "openclaw"
    assert jail.gateway_token == TOKEN


def test_no_representation_of_the_config_contains_the_token(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    for text in everything_said_about(config):
        assert TOKEN not in text
    assert "[REDACTED]" in repr(config)


def test_the_jail_config_does_not_print_the_token_either(layout: Path) -> None:
    jail = ServiceConfig.from_file(write_toml(layout)).jail_config()
    assert TOKEN not in repr(jail)


# --- the token never reaches an error ----------------------------------------------------------


@pytest.mark.parametrize(
    "bad_token",
    [
        pytest.param("short", id="too-short"),
        pytest.param("has spaces in it " * 4, id="not-url-safe"),
        pytest.param("", id="empty"),
    ],
)
def test_an_invalid_token_is_rejected_without_quoting_it(layout: Path, bad_token: str) -> None:
    write_token(layout / "state" / "gateway.token", bad_token)
    with pytest.raises(ConfigError) as raised:
        ServiceConfig.from_file(write_toml(layout))
    assert "gateway" in str(raised.value)
    if bad_token:
        assert bad_token not in str(raised.value)
        assert bad_token not in repr(raised.value)


def test_a_token_in_the_toml_is_rejected_without_quoting_it(layout: Path) -> None:
    path = write_toml(layout, f'gateway_token = "{OTHER_TOKEN}"\n')
    with pytest.raises(ConfigError, match="gateway_token") as raised:
        ServiceConfig.from_file(path)
    assert OTHER_TOKEN not in str(raised.value)
    assert "gateway.token" in str(raised.value)  # says where it belongs


def test_a_syntax_error_in_the_toml_does_not_quote_the_file(layout: Path) -> None:
    path = layout / "vigia.toml"
    path.write_text(f'state_dir = "{layout}"\nvolume = = "{OTHER_TOKEN}"\n')
    path.chmod(0o600)
    with pytest.raises(ConfigError) as raised:
        ServiceConfig.from_file(path)
    assert OTHER_TOKEN not in str(raised.value)
    assert "line 2" in str(raised.value)


def test_a_token_that_is_not_text_is_rejected_without_quoting_it(layout: Path) -> None:
    token_file = layout / "state" / "gateway.token"
    token_file.write_bytes(b"\xff\xfe" + TOKEN.encode())
    token_file.chmod(0o600)
    with pytest.raises(ConfigError) as raised:
        ServiceConfig.from_file(write_toml(layout))
    assert TOKEN not in str(raised.value)


def test_errors_about_the_token_file_say_size_and_permissions(layout: Path) -> None:
    token_file = layout / "state" / "gateway.token"
    token_file.chmod(0o644)
    with pytest.raises(ConfigError) as raised:
        ServiceConfig.from_file(write_toml(layout))
    message = str(raised.value)
    assert "0644" in message
    assert f"{len(TOKEN) + 1} bytes" in message
    assert TOKEN not in message


# --- the token file and the toml itself --------------------------------------------------------


def test_a_missing_token_file_is_an_error_that_names_it(layout: Path) -> None:
    (layout / "state" / "gateway.token").unlink()
    with pytest.raises(ConfigError, match="gateway.token"):
        ServiceConfig.from_file(write_toml(layout))


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o666])
def test_a_token_readable_by_group_or_others_is_refused(layout: Path, mode: int) -> None:
    (layout / "state" / "gateway.token").chmod(mode)
    with pytest.raises(ConfigError, match="group or others"):
        ServiceConfig.from_file(write_toml(layout))


def test_a_token_that_is_a_symlink_is_refused(layout: Path) -> None:
    real = layout / "elsewhere"
    write_token(real, TOKEN)
    token_file = layout / "state" / "gateway.token"
    token_file.unlink()
    token_file.symlink_to(real)
    with pytest.raises(ConfigError, match="symlink"):
        ServiceConfig.from_file(write_toml(layout))


def test_a_token_that_is_not_a_regular_file_is_refused_without_blocking(layout: Path) -> None:
    token_file = layout / "state" / "gateway.token"
    token_file.unlink()
    os.mkfifo(token_file, 0o600)
    with pytest.raises(ConfigError, match="regular file"):
        ServiceConfig.from_file(write_toml(layout))


def test_a_huge_token_file_is_refused_by_size(layout: Path) -> None:
    token_file = layout / "state" / "gateway.token"
    token_file.write_text("a" * 100_000)
    token_file.chmod(0o600)
    with pytest.raises(ConfigError, match="bytes"):
        ServiceConfig.from_file(write_toml(layout))


def test_a_token_owned_by_someone_else_is_refused(
    layout: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(layout).st_uid + 1)
    with pytest.raises(ConfigError, match="owned by uid"):
        ServiceConfig.from_file(write_toml(layout))


def test_a_config_file_others_can_write_is_refused(layout: Path) -> None:
    with pytest.raises(ConfigError, match="writable"):
        ServiceConfig.from_file(write_toml(layout, mode=0o666))


def test_a_config_file_readable_by_others_is_fine(layout: Path) -> None:
    # It holds paths and numbers, never a secret.
    config = ServiceConfig.from_file(write_toml(layout, mode=0o644))
    assert config.volume == layout / "volume"


def test_a_missing_config_file_is_a_config_error(layout: Path) -> None:
    with pytest.raises(ConfigError, match="vigia.toml"):
        ServiceConfig.from_file(layout / "vigia.toml")


# --- validation --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param("surprise = 1\n", id="unknown-key"),
        pytest.param("[agent]\nallow_shared_ids = true\n", id="test-only-agent-option"),
        pytest.param('[agent]\ngateway_token = "x"\n', id="token-in-agent"),
        pytest.param("[agent]\nwhat = 1\n", id="unknown-agent-key"),
    ],
)
def test_unknown_keys_are_refused(layout: Path, extra: str) -> None:
    with pytest.raises(ConfigError, match="unknown"):
        ServiceConfig.from_file(write_toml(layout, extra))


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        pytest.param("workspace_limit = 0\n", "workspace_limit", id="limit-zero"),
        pytest.param("workspace_limit = -5\n", "workspace_limit", id="limit-negative"),
        pytest.param("workspace_limit = true\n", "workspace_limit", id="limit-bool"),
        pytest.param('workspace_limit = "big"\n', "workspace_limit", id="limit-string"),
        pytest.param("cycle_interval = 0\n", "cycle_interval", id="cycle-zero"),
        pytest.param("cycle_interval = true\n", "cycle_interval", id="cycle-bool"),
        pytest.param("prune_interval = -1\n", "prune_interval", id="prune-negative"),
        pytest.param('[agent]\nmemory = "lots"\n', "agent", id="agent-memory"),
        pytest.param("[agent]\nuid = 0\n", "agent", id="agent-root"),
    ],
)
def test_invalid_values_are_refused(layout: Path, extra: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        ServiceConfig.from_file(write_toml(layout, extra))


def test_missing_required_keys_are_named(layout: Path) -> None:
    path = layout / "vigia.toml"
    path.write_text(f'state_dir = "{layout / "state"}"\n')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="volume"):
        ServiceConfig.from_file(path)


@pytest.mark.parametrize("key", ["state_dir", "volume"])
def test_relative_paths_are_refused(layout: Path, key: str) -> None:
    other = "volume" if key == "state_dir" else "state_dir"
    path = layout / "vigia.toml"
    directory = {"state_dir": layout / "state", "volume": layout / "volume"}
    path.write_text(f'{key} = "relative/dir"\n{other} = "{directory[other]}"\n')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="absolute"):
        ServiceConfig.from_file(path)


@pytest.mark.parametrize(
    ("state", "volume"),
    [
        pytest.param("same", "same", id="same"),
        pytest.param("outer/state", "outer", id="state-inside-volume"),
        pytest.param("outer", "outer/volume", id="volume-inside-state"),
    ],
)
def test_state_and_volume_must_not_contain_each_other(
    tmp_path: Path, state: str, volume: str
) -> None:
    # The agent can write the volume: Vigía's black box must never live inside it.
    with pytest.raises(ConfigError, match="contain each other"):
        ServiceConfig(
            state_dir=tmp_path / state, volume=tmp_path / volume, gateway_token=Secret(TOKEN)
        )


def test_the_agent_config_dir_cannot_expose_the_state_dir(tmp_path: Path) -> None:
    # config_dir is mounted into the agent: a parent of state_dir would hand it the black box.
    with pytest.raises(ConfigError, match="state_dir"):
        ServiceConfig(
            state_dir=tmp_path / "state",
            volume=tmp_path / "volume",
            gateway_token=Secret(TOKEN),
            agent={"config_dir": tmp_path},
        )
    with pytest.raises(ConfigError, match="state_dir"):
        ServiceConfig(
            state_dir=tmp_path / "state",
            volume=tmp_path / "volume",
            gateway_token=Secret(TOKEN),
            agent={"config_dir": tmp_path / "state"},
        )


def test_the_agent_config_dir_cannot_live_in_the_volume(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="contain each other"):
        ServiceConfig(
            state_dir=tmp_path / "state",
            volume=tmp_path / "volume",
            gateway_token=Secret(TOKEN),
            agent={"config_dir": tmp_path / "volume" / "workspace" / "cfg"},
        )


def test_the_token_must_be_a_secret(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Secret"):
        ServiceConfig(
            state_dir=tmp_path / "state",
            volume=tmp_path / "volume",
            gateway_token=TOKEN,  # type: ignore[arg-type]
        )


# --- paths are not lexical tricks ---------------------------------------------------------------


@pytest.mark.parametrize("bad", ["{base}/state/../elsewhere", "{base}/./state", "{base}/state/."])
@pytest.mark.parametrize("key", ["state_dir", "volume"])
def test_dot_components_are_refused_in_the_toml(layout: Path, key: str, bad: str) -> None:
    other = "volume" if key == "state_dir" else "state_dir"
    directory = {"state_dir": layout / "state", "volume": layout / "volume"}
    path = layout / "vigia.toml"
    path.write_text(f'{key} = "{bad.format(base=layout)}"\n{other} = "{directory[other]}"\n')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match=r"'\.\.' or '\.'"):
        ServiceConfig.from_file(path)


def test_dot_components_are_refused_in_the_agent_config_dir(layout: Path) -> None:
    extra = f'[agent]\nconfig_dir = "{layout}/state/openclaw/../.."\n'
    with pytest.raises(ConfigError, match=r"'\.\.' or '\.'"):
        ServiceConfig.from_file(write_toml(layout, extra))


@pytest.mark.parametrize("key", ["state_dir", "volume"])
def test_dotdot_is_refused_when_building_the_config_in_code(tmp_path: Path, key: str) -> None:
    paths = {"state_dir": tmp_path / "state", "volume": tmp_path / "volume"}
    paths[key] = tmp_path / "a" / ".." / "b"
    with pytest.raises(ConfigError, match=r"'\.\.'"):
        ServiceConfig(gateway_token=Secret(TOKEN), **paths)


def test_dotdot_is_refused_in_the_agent_config_dir_in_code(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"'\.\.'"):
        ServiceConfig(
            state_dir=tmp_path / "state",
            volume=tmp_path / "volume",
            gateway_token=Secret(TOKEN),
            agent={"config_dir": tmp_path / "x" / ".." / "y"},
        )


# --- the state folder must be Vigía's alone ----------------------------------------------------


def test_a_state_dir_others_can_write_is_refused(layout: Path) -> None:
    """Whoever can write there can swap the lock, the key or the token for their own."""
    (layout / "state").chmod(0o770)
    with pytest.raises(ConfigError, match="state_dir .* writable by group or others"):
        ServiceConfig.from_file(write_toml(layout))
    (layout / "state").chmod(0o707)
    with pytest.raises(ConfigError, match="state_dir .* writable by group or others"):
        ServiceConfig.from_file(write_toml(layout))


def test_a_state_dir_readable_by_others_but_not_writable_is_accepted(layout: Path) -> None:
    (layout / "state").chmod(0o755)
    ServiceConfig.from_file(write_toml(layout))


def test_a_state_dir_of_another_user_is_refused(
    layout: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(ConfigError, match="state_dir .* owned by uid"):
        _require_private_state_dir(layout / "state")  # from_file reads the TOML first


def test_a_state_dir_that_is_a_file_or_missing_is_refused(layout: Path) -> None:
    path = write_toml(layout)
    (layout / "state" / "gateway.token").unlink()
    (layout / "state").rmdir()
    with pytest.raises(ConfigError, match="cannot read state_dir"):
        ServiceConfig.from_file(path)
