"""ServiceConfig: the TOML, the gateway token and the path checks. The token must never reach an
error message, a repr or a log (docs/19, section "Disposición")."""

import copy
import logging
import os
import pickle
from pathlib import Path

import pytest

from backtide.jail import AgentJailConfig
from backtide.jail.proxy_config import ProxyJailConfig
from backtide.service.config import (
    ConfigError,
    Provider,
    ProxySettings,
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
    path = layout / "backtide.toml"
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
    assert config.lock_file == state / "backtide.lock"
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
    path = layout / "backtide.toml"
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
    with pytest.raises(ConfigError, match="backtide.toml"):
        ServiceConfig.from_file(layout / "backtide.toml")


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
    path = layout / "backtide.toml"
    path.write_text(f'state_dir = "{layout / "state"}"\n')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="volume"):
        ServiceConfig.from_file(path)


@pytest.mark.parametrize("key", ["state_dir", "volume"])
def test_relative_paths_are_refused(layout: Path, key: str) -> None:
    other = "volume" if key == "state_dir" else "state_dir"
    path = layout / "backtide.toml"
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
    # The agent can write the volume: backtide's black box must never live inside it.
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
    path = layout / "backtide.toml"
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


# --- the state folder must be backtide's alone ----------------------------------------------------


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


# --- the emergency growth (T04e-1) -------------------------------------------------------------


def test_growth_is_off_by_default(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    assert config.volume_image is None and config.max_volume_bytes is None


def test_growth_reads_the_image_and_the_ceiling(layout: Path) -> None:
    image = layout / "volume.img"
    config = ServiceConfig.from_file(
        write_toml(layout, f'volume_image = "{image}"\nmax_volume_bytes = 1610612736\n')
    )
    assert config.volume_image == image
    assert config.max_volume_bytes == 3 * 1024**3 // 2


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        pytest.param('volume_image = "/srv/v.img"\n', "go together", id="image-alone"),
        pytest.param("max_volume_bytes = 10\n", "go together", id="ceiling-alone"),
        pytest.param(
            'volume_image = "v.img"\nmax_volume_bytes = 10\n', "absolute", id="relative-image"
        ),
        pytest.param(
            'volume_image = "/srv/../v.img"\nmax_volume_bytes = 10\n', "'\\.\\.'", id="dotdot"
        ),
        pytest.param(
            'volume_image = "/srv/v.img"\nmax_volume_bytes = 0\n', "max_volume", id="zero"
        ),
        pytest.param(
            'volume_image = "/srv/v.img"\nmax_volume_bytes = true\n', "max_volume", id="bool"
        ),
    ],
)
def test_invalid_growth_settings_are_refused(layout: Path, extra: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        ServiceConfig.from_file(write_toml(layout, extra))


@pytest.mark.parametrize("where", ["volume", "state/openclaw"])
def test_the_image_never_lives_where_the_agent_sees_it(layout: Path, where: str) -> None:
    image = layout / where / "volume.img"
    with pytest.raises(ConfigError, match="must not be inside"):
        ServiceConfig.from_file(
            write_toml(layout, f'volume_image = "{image}"\nmax_volume_bytes = 10\n')
        )


# --- [proxy] (T06, docs/21) ---------------------------------------------------------------------


def test_the_proxy_folders_live_in_the_state(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    state = layout / "state"
    assert config.proxy_ca_dir == state / "proxy-ca"
    assert config.agent_ca_dir == state / "agent-ca"
    assert config.proxy_channel_dir == state / "proxy-channel"
    assert config.keys_dir == state / "keys"
    assert config.jail_config().ca_dir == state / "agent-ca"  # what the agent sees
    paths = config.ca_paths()
    assert (paths.proxy_dir, paths.agent_dir, paths.gid) == (
        state / "proxy-ca",
        state / "agent-ca",
        61001,
    )


def test_the_proxy_defaults_are_the_designs(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    proxy = config.proxy_jail_config()
    assert isinstance(proxy, ProxyJailConfig)
    assert (proxy.ca_dir, proxy.channel_dir) == (config.proxy_ca_dir, config.proxy_channel_dir)
    assert (proxy.uid, proxy.gid) == (61001, 61001)
    assert proxy.agent_network == config.jail_config().network
    assert (proxy.internal_egress, proxy.allow_shared_ids) == (False, False)
    assert config.proxy_settings() == ProxySettings(allow_hosts=(), providers=())


def test_the_proxy_options_are_read(layout: Path) -> None:
    keys = layout / "state" / "keys"
    keys.mkdir(mode=0o700)
    for name in ("anthropic", "groq"):
        write_token(keys / f"{name}.key", f"sk-test-made-up-{name}-key-0123456789")
    config = ServiceConfig.from_file(
        write_toml(
            layout,
            '[agent]\nnetwork = "agent-net-2"\nuid = 62000\ngid = 62000\n'
            '[proxy]\nname = "proxy-2"\nnetwork = "egress-2"\nuid = 62001\ngid = 62001\n'
            'memory = "512m"\nallow_hosts = ["github.com", "*.pypi.org"]\n'
            '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
            '[[proxy.providers]]\nname = "groq"\nkind = "openai"\nhost = "api.groq.com"\n'
            'models = ["llama-3.3-70b"]\n',
        )
    )
    proxy = config.proxy_jail_config()
    assert (proxy.name, proxy.network, proxy.memory) == ("proxy-2", "egress-2", "512m")
    assert (proxy.uid, proxy.gid, proxy.agent_uid, proxy.agent_gid) == (62001, 62001, 62000, 62000)
    assert proxy.agent_network == "agent-net-2"
    assert config.ca_paths().gid == 62001
    assert config.proxy_settings() == ProxySettings(
        allow_hosts=("github.com", "*.pypi.org"),
        providers=(
            Provider("anthropic", "anthropic", "api.anthropic.com"),
            Provider("groq", "openai", "api.groq.com", ("llama-3.3-70b",)),
        ),
    )


@pytest.mark.parametrize(
    "extra",
    [
        '[proxy]\napi_key = "sk-ant-api03-REAL"\n',
        '[proxy]\nanthropic_key = "sk-ant-api03-REAL"\n',
        '[proxy]\ntoken = "sk-ant-api03-REAL"\n',
        '[[proxy.providers]]\nname = "a"\nkind = "anthropic"\napi_key = "sk-ant-api03-REAL"\n',
        '[[proxy.providers]]\nname = "a"\nkind = "openai"\napiKey = "sk-ant-api03-REAL"\n',
    ],
)
def test_a_key_in_the_proxy_section_is_refused_without_quoting_it(layout: Path, extra: str) -> None:
    with pytest.raises(ConfigError, match="never hold a key") as error:
        ServiceConfig.from_file(write_toml(layout, extra))
    assert "sk-ant" not in str(error.value)
    assert "keys/" in str(error.value)


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        pytest.param("proxy = 3\n", r"\[proxy\] must be a table", id="not-a-table"),
        pytest.param("[proxy]\nsurprise = 1\n", "unknown", id="unknown-key"),
        pytest.param("[proxy]\ninternal_egress = true\n", "unknown", id="test-only-egress"),
        pytest.param("[proxy]\nallow_shared_ids = true\n", "unknown", id="test-only-ids"),
        pytest.param("[proxy]\nuid = 0\n", "proxy", id="root"),
        pytest.param('[proxy]\nimage = "mitmproxy/mitmproxy:latest"\n', "proxy", id="unpinned"),
        pytest.param('[proxy]\nnetwork = "backtide-agente-net"\n', "proxy", id="agents-network"),
        pytest.param('[proxy]\nallow_hosts = "github.com"\n', "allow_hosts", id="hosts-str"),
        pytest.param('[proxy]\nallow_hosts = ["*"]\n', "allow_hosts", id="hosts-everything"),
        pytest.param('[proxy]\nallow_hosts = ["a b"]\n', "allow_hosts", id="hosts-space"),
        pytest.param('[proxy]\nallow_hosts = ["evil.com/x"]\n', "allow_hosts", id="hosts-path"),
        pytest.param('[proxy]\nallow_hosts = ["127.0.0.1:22"]\n', "allow_hosts", id="hosts-port"),
        pytest.param("[proxy]\nallow_hosts = [3]\n", "allow_hosts", id="hosts-number"),
        pytest.param('[proxy]\nallow_hosts = [".com"]\n', "allow_hosts", id="hosts-dot"),
        pytest.param("[proxy]\nproviders = [1]\n", "table", id="provider-not-table"),
        pytest.param(
            '[[proxy.providers]]\nname = "x"\nkind = "gemini"\n', "kind", id="provider-kind"
        ),
        pytest.param(
            '[[proxy.providers]]\nname = "Bad Name"\nkind = "openai"\n', "name", id="provider-name"
        ),
        pytest.param(
            '[[proxy.providers]]\nname = "x"\nkind = "openai"\nhost = "*.openai.com"\n',
            "exact",
            id="provider-wildcard",
        ),
        pytest.param(
            '[[proxy.providers]]\nname = "x"\nkind = "openai"\nweird = 1\n',
            "unknown",
            id="provider-unknown",
        ),
        pytest.param(
            '[[proxy.providers]]\nname = "x"\nkind = "openai"\n'
            '[[proxy.providers]]\nname = "x"\nkind = "anthropic"\n',
            "once",
            id="provider-twice",
        ),
    ],
)
def test_invalid_proxy_settings_are_refused(layout: Path, extra: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        ServiceConfig.from_file(write_toml(layout, extra))


@pytest.mark.parametrize("folder", ["proxy-ca", "agent-ca", "proxy-channel", "keys"])
def test_the_agent_config_dir_is_never_a_folder_of_the_proxy(layout: Path, folder: str) -> None:
    """The agent's config folder is mounted into the agent: it must never be (or hold) the CA's
    key, the channel or the real keys (invariant 1)."""
    state = layout / "state"
    for config_dir in (state / folder, state / folder / "openclaw"):
        with pytest.raises(ConfigError, match="must not (be or )?contain"):
            ServiceConfig(
                state_dir=state,
                volume=layout / "volume",
                gateway_token=Secret(TOKEN),
                agent={"config_dir": config_dir},
            )


# --- [sensor] (T07-3, docs/23) -----------------------------------------------------------------


def test_the_sensor_defaults_are_the_designs(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    state = layout / "state"
    assert config.sensor_dir == state / "sensor"
    assert config.sensor_required is False  # decision 7: the agent runs without it, warned
    jail = config.sensor_jail_config()
    assert (jail.state_dir, jail.name, jail.memory, jail.cpus) == (
        state / "sensor",
        "backtide-sensor",
        "1g",
        "1",
    )
    assert (jail.cgroup_rate, jail.file_perm) == ("1000,1s", "600")
    reader = config.sensor_reader_config()
    assert (reader.events_dir, reader.cursor_file) == (jail.events_dir, jail.cursor_file)
    assert reader.agent_name == config.jail_config().name
    assert (reader.exec_rate, reader.exec_burst, reader.exec_daily) == (20.0, 500, 100_000)
    assert (reader.net_rate, reader.net_burst, reader.net_daily) == (20.0, 200, 50_000)
    assert config.sensor_novelty_streak == 600.0  # the founder's decision B: 10 minutes


def test_the_sensor_options_are_read(layout: Path) -> None:
    config = ServiceConfig.from_file(
        write_toml(
            layout,
            '[sensor]\nname = "sensor-2"\nrequired = true\nmemory = "2g"\ncpus = "0.5"\n'
            'cgroup_rate = "500,1s"\nexec_rate = 10\nexec_burst = 100\nexec_daily = 1000\n'
            "net_rate = 5.5\nnet_burst = 50\nnet_daily = 500\nnovelty_streak_minutes = 2.5\n",
        )
    )
    assert config.sensor_required is True
    assert config.sensor_novelty_streak == 150.0
    jail = config.sensor_jail_config()
    assert (jail.memory, jail.cpus, jail.cgroup_rate) == ("2g", "0.5", "500,1s")
    assert jail.name == config.sensor_reader_config().sensor_name == "sensor-2"
    reader = config.sensor_reader_config()
    assert (reader.exec_rate, reader.exec_burst, reader.exec_daily) == (10, 100, 1000)
    assert (reader.net_rate, reader.net_burst, reader.net_daily) == (5.5, 50, 500)


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        pytest.param("sensor = 3\n", r"\[sensor\] must be a table", id="not-a-table"),
        pytest.param("[sensor]\nsurprise = 1\n", "unknown", id="unknown-key"),
        pytest.param('[sensor]\nimage = "quay.io/cilium/tetragon:latest"\n', "unknown", id="image"),
        pytest.param('[sensor]\nfile_perm = "644"\n', "unknown", id="test-only-perm"),
        pytest.param('[sensor]\nstate_dir = "/tmp/x"\n', "unknown", id="state-dir"),
        pytest.param('[sensor]\nrequired = "yes"\n', "required", id="required-str"),
        pytest.param('[sensor]\nmemory = "lots"\n', "sensor", id="memory"),
        pytest.param('[sensor]\ncgroup_rate = "1000"\n', "sensor", id="rate"),
        pytest.param("[sensor]\nexec_rate = 0\n", "exec_rate", id="exec-rate-0"),
        pytest.param("[sensor]\nexec_burst = 1.5\n", "exec_burst", id="burst-float"),
        pytest.param("[sensor]\nnet_daily = -1\n", "net_daily", id="daily-negative"),
        pytest.param("[sensor]\nnet_daily = true\n", "net_daily", id="daily-bool"),
        pytest.param('[sensor]\ntoken = "x"\n', "never hold a key", id="secret"),
        pytest.param(
            "[sensor]\nnovelty_streak_minutes = 0.5\n", "novelty_streak", id="streak-short"
        ),
        pytest.param(
            "[sensor]\nnovelty_streak_minutes = true\n", "novelty_streak", id="streak-bool"
        ),
        pytest.param(
            '[sensor]\nnovelty_streak_minutes = "10"\n', "novelty_streak", id="streak-str"
        ),
        pytest.param('[sensor]\nname = "backtide-agente"\n', "another container", id="agents"),
        pytest.param('[sensor]\nname = "backtide-proxy"\n', "another container", id="proxys"),
        pytest.param('[sensor]\nname = "-x"\n', "sensor", id="bad-name"),
    ],
)
def test_invalid_sensor_settings_are_refused(layout: Path, extra: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        ServiceConfig.from_file(write_toml(layout, extra))


def test_the_agent_config_dir_never_overlaps_the_sensors_folder(layout: Path) -> None:
    """T07-2's review: the sensor's folder (its events, its settings, the cursor) is never
    mounted into the agent (invariant 1)."""
    state = layout / "state"
    for config_dir in (state / "sensor", state / "sensor" / "events", state / "sensor" / "x"):
        with pytest.raises(ConfigError, match="sensor"):
            ServiceConfig(
                state_dir=state,
                volume=layout / "volume",
                gateway_token=Secret(TOKEN),
                agent={"config_dir": config_dir},
            )


# --- [proxy] allow_provider_tools (T06-6) --------------------------------------------------------


def test_no_provider_tool_is_allowed_by_default(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    assert config.proxy_settings().allow_provider_tools == ()


def test_the_allowed_provider_tools_are_read(layout: Path) -> None:
    config = ServiceConfig.from_file(
        write_toml(layout, '[proxy]\nallow_provider_tools = ["web_search_20250305", "mcp"]\n')
    )
    assert config.proxy_settings().allow_provider_tools == ("web_search_20250305", "mcp")


@pytest.mark.parametrize(
    "value", ['"mcp"', '["Web Search"]', "[1]", '["*"]', "[" + ", ".join(['"t"'] * 65) + "]"]
)
def test_bad_allowed_provider_tools_are_refused(layout: Path, value: str) -> None:
    with pytest.raises(ConfigError, match="allow_provider_tools"):
        ServiceConfig.from_file(
            write_toml(layout, f"[proxy]\nallow_provider_tools = {value}\n")
        ).proxy_settings()
