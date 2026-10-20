"""The model providers' keys (T06-5, docs/21 section 6): the real one read from
``<state_dir>/keys/<name>.key``, the fake one made once per installation in ``<name>.fake``,
the fake one in OpenClaw's config and both in the proxy's policy.

The real key must never reach an error, a repr, the agent's config or its environment. Every
key here is made up by the test."""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from backtide.gate.providers import FAKE_KEY_PREFIX, Providers, is_fake_key
from backtide.jail import AgentJail
from backtide.jail.config import container_env, docker_create_argv, openclaw_config, token_env
from backtide.jail.openclaw import ModelProvider, check_rewindable
from backtide.jail.proxy import ProxyJail
from backtide.service.config import ConfigError, ProviderKey, Secret, ServiceConfig
from backtide.service.runner import build_egress

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
REAL_ANTHROPIC = "sk-test-real-anthropic-" + "Q" * 24  # made up: never a real key
REAL_OPENAI = "sk-test-real-openai-" + "W" * 24
PROVIDERS = (
    '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
    '[[proxy.providers]]\nname = "groq"\nkind = "openai"\nhost = "api.groq.com"\n'
    'models = ["llama-3.3-70b", "qwen3.5:9b"]\n'
)


@pytest.fixture
def layout(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    token = state / "gateway.token"
    token.write_text(TOKEN + "\n")
    token.chmod(0o600)
    (tmp_path / "volume").mkdir()
    return tmp_path


def write_toml(layout: Path, extra: str = "") -> Path:
    path = layout / "backtide.toml"
    path.write_text(f'state_dir = "{layout / "state"}"\nvolume = "{layout / "volume"}"\n{extra}')
    path.chmod(0o600)
    return path


def keys_dir(layout: Path) -> Path:
    return layout / "state" / "keys"


def write_key(layout: Path, name: str, value: str, mode: int = 0o600) -> Path:
    folder = keys_dir(layout)
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / f"{name}.key"
    path.write_text(value + "\n")
    path.chmod(mode)
    return path


def configured(layout: Path) -> ServiceConfig:
    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_OPENAI)
    return ServiceConfig.from_file(write_toml(layout, PROVIDERS))


def said(config: ServiceConfig) -> str:
    return " ".join([repr(config), str(config), repr(vars(config)), repr(config.provider_keys)])


# --- reading keys/ ---------------------------------------------------------------------------


def test_without_providers_no_keys_folder_is_needed(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    assert config.provider_keys == {}
    assert config.model_providers().items == ()
    assert not keys_dir(layout).exists()


def test_the_real_key_is_read_and_a_fake_one_is_made_once(layout: Path) -> None:
    config = configured(layout)
    assert set(config.provider_keys) == {"anthropic", "groq"}
    key = config.provider_keys["anthropic"]
    assert isinstance(key, ProviderKey) and isinstance(key.real, Secret)
    assert key.real.reveal() == REAL_ANTHROPIC
    assert is_fake_key(key.fake, "anthropic") and key.fake.startswith(FAKE_KEY_PREFIX)
    fake_file = keys_dir(layout) / "anthropic.fake"
    info = fake_file.lstat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid()
    assert fake_file.read_text().strip() == key.fake
    again = ServiceConfig.from_file(write_toml(layout, PROVIDERS))
    assert again.provider_keys["anthropic"].fake == key.fake  # made once per installation
    assert again.provider_keys["groq"].fake != key.fake


def test_no_key_is_ever_said(layout: Path) -> None:
    config = configured(layout)
    text = said(config)
    for key in config.provider_keys.values():
        assert key.real.reveal() not in text
        assert key.fake not in text
    assert repr(config.model_providers()) == "Providers(anthropic, groq)"


def test_a_provider_without_its_key_is_refused(layout: Path) -> None:
    write_key(layout, "anthropic", REAL_ANTHROPIC)  # groq has none
    with pytest.raises(ConfigError, match=r"keys/groq\.key"):
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))


def test_a_missing_keys_folder_is_refused(layout: Path) -> None:
    with pytest.raises(ConfigError, match="keys"):
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_a_key_file_others_can_read_is_refused_without_quoting_it(layout: Path, mode: int) -> None:
    write_key(layout, "anthropic", REAL_ANTHROPIC, mode)
    write_key(layout, "groq", REAL_OPENAI)
    with pytest.raises(ConfigError, match="600") as error:
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))
    assert REAL_ANTHROPIC not in str(error.value)


@pytest.mark.parametrize("mode", [0o750, 0o705, 0o755])
def test_a_keys_folder_others_can_enter_is_refused(layout: Path, mode: int) -> None:
    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_OPENAI)
    keys_dir(layout).chmod(mode)
    with pytest.raises(ConfigError, match="700"):
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))


def test_a_symlinked_key_is_refused(layout: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere.key"
    elsewhere.write_text(REAL_ANTHROPIC)
    elsewhere.chmod(0o600)
    keys_dir(layout).mkdir(mode=0o700)
    (keys_dir(layout) / "anthropic.key").symlink_to(elsewhere)
    write_key(layout, "groq", REAL_OPENAI)
    with pytest.raises(ConfigError, match="symlink"):
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))


def test_a_symlinked_keys_folder_is_refused(layout: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "keys-elsewhere"
    elsewhere.mkdir(mode=0o700)
    keys_dir(layout).symlink_to(elsewhere)
    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_OPENAI)
    with pytest.raises(ConfigError, match="symlink"):
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))


@pytest.mark.parametrize(
    "value",
    [
        "short-key",
        "sk-test with a space inside it ok",
        "",
        f"{FAKE_KEY_PREFIX}anthropic-" + "a" * 32,
    ],
    ids=["too-short", "space", "empty", "a-fake-key"],
)
def test_a_bad_real_key_is_refused_without_quoting_it(layout: Path, value: str) -> None:
    write_key(layout, "anthropic", value)
    write_key(layout, "groq", REAL_OPENAI)
    with pytest.raises(ConfigError, match="anthropic") as error:
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))
    assert not value or value not in str(error.value)


def test_a_provider_openclaw_does_not_know_needs_its_models(layout: Path) -> None:
    write_key(layout, "groq", REAL_OPENAI)
    extra = '[[proxy.providers]]\nname = "groq"\nkind = "openai"\nhost = "api.groq.com"\n'
    with pytest.raises(ConfigError, match="model ids"):
        ServiceConfig.from_file(write_toml(layout, extra))


@pytest.mark.parametrize("models", ['"x"', '["a b"]', "[1]", '["-x"]'])
def test_bad_model_ids_are_refused(layout: Path, models: str) -> None:
    extra = f'[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\nmodels = {models}\n'
    with pytest.raises(ConfigError, match="models"):
        ServiceConfig.from_file(write_toml(layout, extra))


@pytest.mark.parametrize(
    ("kind", "host"), [("anthropic", "api.openai.com"), ("openai", "API.anthropic.com.")]
)
def test_a_provider_on_another_kinds_host_is_refused(layout: Path, kind: str, host: str) -> None:
    extra = f'[[proxy.providers]]\nname = "x"\nkind = "{kind}"\nhost = "{host}"\nmodels = ["m"]\n'
    with pytest.raises(ConfigError, match="wrong provider"):
        ServiceConfig.from_file(write_toml(layout, extra))


def test_two_providers_with_the_same_real_key_are_refused(layout: Path) -> None:
    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_ANTHROPIC)
    with pytest.raises(ConfigError, match="share") as error:
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))
    assert REAL_ANTHROPIC not in str(error.value)


def test_a_fake_file_that_is_not_a_fake_key_is_refused(layout: Path) -> None:
    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_OPENAI)
    fake = keys_dir(layout) / "anthropic.fake"
    fake.write_text("sk-ant-api03-something-real-looking\n")
    fake.chmod(0o600)
    with pytest.raises(ConfigError, match=r"anthropic\.fake") as error:
        ServiceConfig.from_file(write_toml(layout, PROVIDERS))
    assert "something-real-looking" not in str(error.value)


def test_a_constructed_config_needs_a_key_for_each_provider(layout: Path) -> None:
    proxy = {"providers": [{"name": "anthropic", "kind": "anthropic"}]}
    with pytest.raises(ConfigError, match="anthropic"):
        ServiceConfig(
            state_dir=layout / "state",
            volume=layout / "volume",
            gateway_token=Secret(TOKEN),
            proxy=proxy,
        )
    with pytest.raises(ConfigError, match="no provider"):
        ServiceConfig(
            state_dir=layout / "state",
            volume=layout / "volume",
            gateway_token=Secret(TOKEN),
            provider_keys={"other": ProviderKey(Secret(REAL_OPENAI), "x")},
        )


# --- the agent sees the fake one, in openclaw.json only ---------------------------------------


def test_the_agent_config_holds_the_fake_key_and_never_the_real_one(layout: Path) -> None:
    config = configured(layout)
    jail = config.jail_config()
    assert jail.model_providers == (
        ModelProvider(
            "anthropic", "anthropic", "api.anthropic.com", config.provider_keys["anthropic"].fake
        ),
        ModelProvider(
            "groq",
            "openai",
            "api.groq.com",
            config.provider_keys["groq"].fake,
            ("llama-3.3-70b", "qwen3.5:9b"),
        ),
    )
    claw = openclaw_config(jail)
    providers = claw["models"]["providers"]
    assert providers["anthropic"]["apiKey"] == config.provider_keys["anthropic"].fake
    assert providers["anthropic"]["baseUrl"] == "https://api.anthropic.com"
    assert providers["groq"]["apiKey"] == config.provider_keys["groq"].fake
    assert providers["groq"]["baseUrl"] == "https://api.groq.com/v1"
    assert (providers["anthropic"]["api"], providers["groq"]["api"]) == (
        "anthropic-messages",
        "openai-completions",
    )
    assert providers["anthropic"]["auth"] == "api-key"  # the literal wins over env and profiles
    assert "models" not in providers["anthropic"]  # OpenClaw's own catalog
    assert providers["groq"]["models"] == [
        {"id": "llama-3.3-70b", "name": "llama-3.3-70b"},
        {"id": "qwen3.5:9b", "name": "qwen3.5:9b"},
    ]
    assert claw["models"]["mode"] == "merge"
    assert claw["agents"]["defaults"]["model"] == {"primary": "groq/llama-3.3-70b"}
    check_rewindable(claw)  # an API key profile, never OAuth
    text = json.dumps(claw)
    assert REAL_ANTHROPIC not in text and REAL_OPENAI not in text
    argv = " ".join(docker_create_argv(jail))
    environment = " ".join(f"{k}={v}" for k, v in container_env(jail)) + repr(token_env(jail))
    for key in config.provider_keys.values():
        # Neither key in the container's argv or environment: the fake one only in the file.
        for where in (argv, environment, repr(jail)):
            assert key.real.reveal() not in where
            assert key.fake not in where
    assert not [name for name, _ in container_env(jail) if "KEY" in name.upper()]


def test_the_agent_config_without_providers_has_none(layout: Path) -> None:
    config = ServiceConfig.from_file(write_toml(layout))
    assert config.jail_config().model_providers == ()
    assert "providers" not in openclaw_config(config.jail_config())["models"]


def test_write_config_writes_the_fake_key(layout: Path) -> None:
    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_OPENAI)
    own_ids = f"[agent]\nuid = {os.getuid()}\ngid = {os.getgid()}\n"
    config = ServiceConfig.from_file(write_toml(layout, own_ids + PROVIDERS))
    jail = AgentJail(config.jail_config())
    jail.write_config()
    written = json.loads(config.jail_config().config_file.read_text())
    assert written["models"]["providers"]["anthropic"]["apiKey"] == (
        config.provider_keys["anthropic"].fake
    )


# --- the proxy gets both, through the channel's policy ----------------------------------------


def test_the_egress_policy_has_the_providers_and_their_hosts(layout: Path) -> None:
    config = configured(layout)
    agent = AgentJail(config.jail_config())
    box = SimpleNamespace(append=lambda *args, **kwargs: None, events=lambda **query: [])
    egress = build_egress(config, agent, box, proxy=ProxyJail(config.proxy_jail_config()))  # type: ignore[arg-type]
    policy = egress._policy  # noqa: SLF001 - what the channel will send
    assert isinstance(policy.providers, Providers)
    assert [p.name for p in policy.providers.items] == ["anthropic", "groq"]
    anthropic = policy.providers.for_host("api.anthropic.com")
    assert anthropic is not None and anthropic.real_key.reveal() == REAL_ANTHROPIC
    assert anthropic.fake_key == config.provider_keys["anthropic"].fake
    allow = policy.allow_list()
    assert allow.allows("api.anthropic.com") and allow.allows("api.groq.com")
    assert TOKEN in policy.secrets  # the Gateway token is struck too
    assert REAL_ANTHROPIC not in repr(policy) and REAL_ANTHROPIC not in repr(egress._policy)  # noqa: SLF001


def test_the_proxy_gets_each_providers_models(layout: Path) -> None:
    """T06-6: a provider that lists its models only takes those (the gate checks the model)."""
    by_name = {p.name: p for p in configured(layout).model_providers().items}
    assert by_name["groq"].models == ("llama-3.3-70b", "qwen3.5:9b")
    assert by_name["anthropic"].models == ()


def test_the_egress_policy_gates_unknown_hosts_and_trusts_the_owners_chat(layout: Path) -> None:
    """T10-3: ``[gate]``'s defaults (decision 1, docs/32 section 9). The owner's chat comes from
    ``telegram.toml`` (a made-up token: the shape of one, never a real one)."""
    from backtide.service.runner import egress_policy

    config = configured(layout)
    policy = egress_policy(config, config.model_providers())
    assert policy.unknown_hosts == "hold" and policy.trusted == ()
    settings = config.state_dir / "telegram.toml"
    settings.write_text('token = "123456789:' + "Zx9_-" * 7 + '"\nchat_id = 4242\n')
    settings.chmod(0o600)
    policy = egress_policy(config, config.model_providers())
    assert [(t.translator, t.recipient) for t in policy.trusted] == [("telegram", "4242")]


def test_a_trusted_mail_recipient_is_said_to_be_inactive(
    layout: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Final review of T10, finding 2: until the owner's mail accounts exist (approved decision
    4), a mail address in ``[gate] trusted`` trusts nothing (``all_trusted``); the log says so
    at start instead of letting the person believe those mails pass."""
    from backtide.service.runner import egress_policy

    write_key(layout, "anthropic", REAL_ANTHROPIC)
    write_key(layout, "groq", REAL_OPENAI)
    gate = '\n[gate]\ntrusted = [{translator = "gmail", email = "ana@ejemplo.com"}]\n'
    config = ServiceConfig.from_file(write_toml(layout, PROVIDERS + gate))
    with caplog.at_level("WARNING", logger="backtide.service.runner"):
        policy = egress_policy(config, config.model_providers())
    assert [(t.translator, t.recipient) for t in policy.trusted] == [("gmail", "ana@ejemplo.com")]
    assert "1 mail recipient(s) are not used" in caplog.text
