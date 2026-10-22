"""`[agent]` in backtide.toml and the restricted ``custom`` profile (T17a-3, docs/34 sections 6,
7 and 11): what a custom agent may say about itself, each thing it may not (one test each), the
Gateway token only for the profile that uses it, and the fake key only in the declared variable.
OpenClaw's own jail, byte for byte, is still test_jail_openclaw_snapshot.py."""

import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from backtide.gate.providers import FAKE_KEY_PREFIX, is_fake_key
from backtide.jail import model as model_module
from backtide.jail import openclaw as old_openclaw
from backtide.jail.config import (
    AgentJailConfig,
    container_env,
    docker_create_argv,
    token_env,
)
from backtide.jail.profile import secret_shaped
from backtide.jail.profiles import CLAUDE_CODE, NAMED, OPENCLAW, profile_names
from backtide.jail.profiles import openclaw as openclaw_profile
from backtide.jail.profiles.custom import UNKNOWN_AGENT_NOTICE
from backtide.jail.verify import container_problems
from backtide.service.config import ConfigError, Secret, ServiceConfig, agent_profile_of
from backtide.service.notice import rewind_notice
from backtide.web.paths import WebPaths

IMAGE = "ghcr.io/acme/agent@sha256:" + "c" * 64
TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
# A custom agent with every field of section 7 that T17a-3 takes.
CUSTOM = f"""
[agent]
profile = "custom"
image = "{IMAGE}"
entrypoint = ["tini", "-s", "--"]
command = ["my-agent", "serve"]
workdir = "work"
memory = "1g"
env = {{ MY_AGENT_TELEMETRY = "0", XDG_CONFIG_HOME = "/workspace/home/.config" }}

[agent.model]
provider = "anthropic"
key_env = "ANTHROPIC_API_KEY"
allow_params = ["diagnostics"]

[agent.ready]
log_line = "my-agent ready"
probe = ["/bin/true"]
timeout = 45

[agent.rewind]
notice = ["Lo que el agente ya mandó fuera no vuelve."]

[proxy]
{PROVIDER}"""


@pytest.fixture
def layout(tmp_path: Path) -> Path:
    """``tmp_path/state`` (0700, with NO gateway token: a custom agent has none) next to an
    empty ``tmp_path/volume``."""
    (tmp_path / "state").mkdir(mode=0o700)
    (tmp_path / "volume").mkdir()
    return tmp_path


def write_toml(layout: Path, text: str) -> Path:
    path = layout / "backtide.toml"
    path.write_text(f'state_dir = "{layout / "state"}"\nvolume = "{layout / "volume"}"\n{text}')
    path.chmod(0o600)
    return path


def load(layout: Path, text: str = CUSTOM) -> ServiceConfig:
    return ServiceConfig.from_file(write_toml(layout, text))


def custom(**changes: str) -> str:
    """CUSTOM with lines of its [agent] replaced (``key = value`` as TOML), or added."""
    lines = CUSTOM.split("\n")
    head = lines.index("[agent]")
    for key, value in changes.items():
        found = [i for i, line in enumerate(lines) if line.startswith(f"{key} = ")]
        if found and found[0] < lines.index("[agent.model]"):
            lines[found[0]] = f"{key} = {value}"
        else:
            lines.insert(head + 1, f"{key} = {value}")
    return "\n".join(lines)


# --- the shape ------------------------------------------------------------------------------


def test_a_custom_agent_is_what_its_toml_says(layout: Path) -> None:
    config = load(layout)
    profile = config.agent_profile
    assert profile.name == "custom"
    assert profile.image == IMAGE
    # Docker's --entrypoint takes the program alone: its arguments go first in the command.
    assert (profile.entrypoint, profile.command) == ("tini", ("-s", "--", "my-agent", "serve"))
    assert profile.workdir == PurePosixPath("/workspace/work")
    assert profile.workspace_dirs == ("home", "work")
    assert dict(profile.env) == {
        "MY_AGENT_TELEMETRY": "0",
        "XDG_CONFIG_HOME": "/workspace/home/.config",
    }
    assert profile.fake_key_env == (("ANTHROPIC_API_KEY", "anthropic"),)
    assert profile.provider_params == ("param:diagnostics",)
    assert (profile.ready_log_line, profile.ready_probe) == ("my-agent ready", ("/bin/true",))
    assert profile.rewind_notice_lines == (
        UNKNOWN_AGENT_NOTICE,
        "Lo que el agente ya mandó fuera no vuelve.",
    )
    assert profile.token_env is None and profile.config_names == ()
    # Its request fields reach the gate, for it alone (decision 5).
    assert config.proxy_settings().allow_provider_tools == ("param:diagnostics",)


def test_the_jail_of_a_custom_agent(layout: Path) -> None:
    config = load(layout)
    jail = config.jail_config()
    assert jail.profile == config.agent_profile
    assert jail.image == IMAGE
    assert (jail.memory, jail.ready_timeout) == ("1g", 45)  # [agent.ready] timeout
    assert jail.config_dir == layout / "state" / "custom"  # named after the profile, empty
    assert jail.config_files == ()
    argv = docker_create_argv(jail)
    assert argv[argv.index("--workdir") :] == [
        "--workdir", "/workspace/work", "--entrypoint", "tini", IMAGE,
        "-s", "--", "my-agent", "serve",
    ]  # fmt: skip
    env = dict(container_env(jail))
    assert env["MY_AGENT_TELEMETRY"] == "0"
    assert env["HOME"] == "/workspace/home"  # the jail's, always


def test_a_custom_agent_cannot_change_any_security_option_of_the_argv(layout: Path) -> None:
    jail = load(layout).jail_config()
    openclaw = AgentJailConfig(
        workspace=jail.workspace,
        config_dir=jail.config_dir,
        ca_dir=jail.ca_dir,
        gateway_token=TOKEN,
        memory=jail.memory,
        protected=jail.protected,
    )
    argv = docker_create_argv(jail)
    reference = docker_create_argv(openclaw)
    assert argv[: argv.index("--env")] == reference[: reference.index("--env")]


def test_the_defaults_of_a_custom_agent(layout: Path) -> None:
    text = f'[agent]\nprofile = "custom"\nimage = "{IMAGE}"\nentrypoint = ["/usr/bin/agent"]\n'
    config = load(layout, text)
    profile = config.agent_profile
    assert (profile.entrypoint, profile.command, profile.workdir) == ("/usr/bin/agent", (), None)
    assert profile.env == () and profile.fake_key_env == () and profile.provider_params == ()
    assert (profile.ready_log_line, profile.ready_probe) == ("", ())
    assert profile.rewind_notice_lines == (UNKNOWN_AGENT_NOTICE,)
    assert "--workdir" not in docker_create_argv(config.jail_config())


def test_openclaw_is_still_the_default_and_takes_its_name(layout: Path) -> None:
    assert agent_profile_of({}) is OPENCLAW
    assert agent_profile_of({"profile": "openclaw"}) is OPENCLAW
    assert profile_names() == ("openclaw", "claude-code", "custom")
    assert dict(NAMED) == {"openclaw": OPENCLAW, "claude-code": CLAUDE_CODE}
    with pytest.raises(TypeError):
        NAMED["codex"] = OPENCLAW  # type: ignore[index] - a named profile is added in code


def test_a_named_profile_may_still_change_its_image(layout: Path) -> None:
    (layout / "state" / "gateway.token").write_text(TOKEN + "\n")
    (layout / "state" / "gateway.token").chmod(0o600)
    config = load(layout, f'[agent]\nimage = "{IMAGE}"\n')
    assert config.agent_profile is OPENCLAW
    assert config.jail_config().image == IMAGE


# --- the Gateway token: only for the profile that uses it ----------------------------------


def test_a_custom_agent_needs_no_gateway_token_and_gets_none(layout: Path) -> None:
    config = load(layout)  # the fixture wrote no gateway.token
    assert config.gateway_token is None
    assert config.gateway_secrets() == []
    jail = config.jail_config()
    assert jail.gateway_token is None
    assert openclaw_profile.TOKEN_ENV not in dict(container_env(jail)) | token_env(jail)


def test_a_gateway_token_file_is_never_used_for_a_custom_agent(layout: Path) -> None:
    token = layout / "state" / "gateway.token"
    token.write_text(TOKEN + "\n")
    token.chmod(0o644)  # unusable for OpenClaw: never used for a custom agent, only struck
    assert load(layout).gateway_token is None


def test_openclaw_still_needs_its_gateway_token(layout: Path) -> None:
    with pytest.raises(ConfigError, match="gateway token"):
        load(layout, "")
    with pytest.raises(ConfigError, match="needs the gateway token"):
        ServiceConfig(state_dir=layout / "state", volume=layout / "volume")


def test_an_old_gateway_token_is_still_struck_for_a_custom_agent(layout: Path) -> None:
    """Review of the profiles, L10: an OpenClaw ran on this volume before, so its Gateway token
    may be in the snapshots and the logs. The file is read only to strike it, also when it
    could not be used for OpenClaw (open to others), and never reaches the container."""
    token = layout / "state" / "gateway.token"
    token.write_text(TOKEN + "\n")
    token.chmod(0o644)
    config = load(layout)
    assert config.gateway_token is None
    assert config.gateway_secrets() == [TOKEN]
    jail = config.jail_config()
    assert jail.gateway_token is None and TOKEN not in token_env(jail).values()
    assert TOKEN not in " ".join(docker_create_argv(jail)) + repr(config) + repr(jail)


@pytest.mark.parametrize("content", ["", "short", "\xff\xfe"])
def test_an_unusable_old_token_is_not_struck_and_never_fails(layout: Path, content: str) -> None:
    token = layout / "state" / "gateway.token"
    token.write_bytes(content.encode("latin-1"))
    assert load(layout).gateway_secrets() == []


def test_an_old_token_through_a_link_is_not_read(layout: Path) -> None:
    elsewhere = layout / "elsewhere"
    elsewhere.write_text(TOKEN + "\n")
    (layout / "state" / "gateway.token").symlink_to(elsewhere)
    assert load(layout).gateway_secrets() == []


def test_a_token_given_anyway_is_struck_but_never_reaches_the_container(layout: Path) -> None:
    config = ServiceConfig(
        state_dir=layout / "state",
        volume=layout / "volume",
        gateway_token=Secret(TOKEN),
        agent={"profile": "custom", "image": IMAGE, "entrypoint": ["agent"]},
    )
    assert config.gateway_secrets() == [TOKEN]  # runner strikes it wherever it shows
    jail = config.jail_config()
    assert jail.gateway_token is None and token_env(jail) == {}
    assert TOKEN not in " ".join(docker_create_argv(jail))


def test_the_jail_refuses_a_token_for_a_profile_without_one() -> None:
    profile = agent_profile_of({"profile": "custom", "image": IMAGE, "entrypoint": ["agent"]})
    fields: dict[str, Any] = {
        "workspace": Path("/srv/bt/volume/workspace"),
        "config_dir": Path("/srv/bt/state/custom"),
        "ca_dir": Path("/srv/bt/state/agent-ca"),
        "profile": profile,
    }
    with pytest.raises(ValueError, match="uses no gateway token"):
        AgentJailConfig(**fields, gateway_token=TOKEN)
    with pytest.raises(ValueError, match="gateway_token must be"):
        AgentJailConfig(**(fields | {"profile": OPENCLAW}))


# --- the fake key: only in the declared variable --------------------------------------------


def test_the_fake_key_reaches_only_the_declared_variable(layout: Path) -> None:
    config = load(layout)
    jail = config.jail_config()
    fake = config.provider_keys["anthropic"].fake
    assert is_fake_key(fake, "anthropic")
    assert token_env(jail) == {"ANTHROPIC_API_KEY": fake}  # the docker CLI's env, by name
    every = [*container_env(jail), *token_env(jail).items()]
    assert [name for name, value in every if FAKE_KEY_PREFIX in value] == ["ANTHROPIC_API_KEY"]
    argv = docker_create_argv(jail)
    assert fake not in " ".join(argv)
    assert argv[argv.index("ANTHROPIC_API_KEY") - 1] == "--env"


def test_verify_refuses_the_fake_key_anywhere_else(layout: Path) -> None:
    jail = load(layout).jail_config()
    fake = token_env(jail)["ANTHROPIC_API_KEY"]
    snapshot = json.loads(
        (Path(__file__).parent / "fixtures" / "openclaw_jail_snapshot.json").read_text()
    )
    info = snapshot["configs"]["plain"]["good_info"]
    env = dict(entry.split("=", 1) for entry in snapshot["image_env"])
    env |= dict(container_env(jail)) | token_env(jail)
    info["Config"] |= {
        "Image": jail.image,
        "Entrypoint": [jail.profile.entrypoint],
        "Cmd": list(jail.profile.command),
        "WorkingDir": "/workspace/work",
        "Env": [f"{name}={value}" for name, value in env.items()],
        "User": f"{jail.uid}:{jail.gid}",
    }
    info["HostConfig"] |= {
        "Binds": [
            f"{jail.agent_dir}:/workspace:z",
            f"{jail.config_dir}:/config:ro,z",
            f"{jail.ca_dir}:/etc/backtide-ca:ro,z",
        ],
        "Memory": 1024**3,
        "MemorySwap": 1024**3,
    }
    info["HostConfig"]["SecurityOpt"] = [
        "no-new-privileges=true",
        f"seccomp={json.dumps(snapshot['seccomp_profile'])}",
    ]
    info["HostConfig"]["NetworkMode"] = jail.network
    info["NetworkSettings"]["Networks"] = {jail.network: {}}

    def problems(changed: dict[str, Any]) -> list[str]:
        return container_problems(
            jail,
            changed,
            seccomp_profile=snapshot["seccomp_profile"],
            image_env=snapshot["image_env"],
        )

    assert problems(info) == []
    leaked = json.loads(json.dumps(info))
    leaked["Config"]["Env"].append(f"OTHER_VAR={fake}")
    assert problems(leaked) == ["its environment differs in ['OTHER_VAR']"]
    assert fake not in " ".join(problems(leaked))


def test_the_jail_points_the_files_programs_source_at_dev_null(layout: Path) -> None:
    """BASH_ENV and CLAUDE_ENV_FILE are the jail's, for every profile: the Claude Code image
    sets both to a file of its own (T17a-1), and they must not survive from the image."""
    for jail in (load(layout).jail_config(), _openclaw(layout)):
        env = dict(container_env(jail))
        assert (env["BASH_ENV"], env["CLAUDE_ENV_FILE"]) == ("/dev/null", "/dev/null")


def test_verify_refuses_the_images_own_bash_env(layout: Path) -> None:
    jail = load(layout).jail_config()
    image_env = ["PATH=/usr/bin:/bin", "BASH_ENV=/etc/sandbox-persistent.sh"]
    created = dict(container_env(jail)) | token_env(jail)
    good = [f"{name}={value}" for name, value in ({"PATH": "/usr/bin:/bin"} | created).items()]
    info = {"Config": {"Env": good}}

    def env_problems(env: list[str]) -> list[str]:
        found = container_problems(
            jail, {"Config": {"Env": env}}, seccomp_profile={}, image_env=image_env
        )
        return [problem for problem in found if "environment" in problem]

    assert env_problems(info["Config"]["Env"]) == []
    survived = [
        e if not e.startswith("BASH_ENV=") else "BASH_ENV=/etc/sandbox-persistent.sh" for e in good
    ]
    assert env_problems(survived) == ["its environment differs in ['BASH_ENV']"]
    emptied = [e for e in good if not e.startswith("CLAUDE_ENV_FILE=")]
    assert env_problems(emptied) == ["its environment differs in ['CLAUDE_ENV_FILE']"]


def _openclaw(layout: Path) -> AgentJailConfig:
    return AgentJailConfig(
        workspace=layout / "volume" / "workspace",
        config_dir=layout / "state" / "openclaw",
        ca_dir=layout / "state" / "agent-ca",
        gateway_token=TOKEN,
    )


# --- every rejection (docs/34, section 7), one test each --------------------------------------

RESERVED = (
    "HOME", "PATH", "DO_NOT_TRACK", "HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY",
    "no_proxy", "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "NODE_OPTIONS", "BASH_ENV", "CLAUDE_ENV_FILE", "ENV", "PYTHONPATH",
    "NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY",
)  # fmt: skip


@pytest.mark.parametrize("name", RESERVED)
def test_a_reserved_variable_is_refused(layout: Path, name: str) -> None:
    with pytest.raises(ConfigError, match=f"{name} is set by the jail"):
        load(layout, custom(env=f'{{ {name} = "x" }}'))


@pytest.mark.parametrize("name", ["HTTPS_PROXY", "HOME", "LD_PRELOAD", "NODE_OPTIONS"])
def test_the_fake_key_cannot_go_in_a_reserved_variable(layout: Path, name: str) -> None:
    text = CUSTOM.replace('key_env = "ANTHROPIC_API_KEY"', f'key_env = "{name}"')
    with pytest.raises(ConfigError, match=f"{name} is set by the jail"):
        load(layout, text)


@pytest.mark.parametrize("name", ["MY_AGENT_MODEL_AUTH", "MODEL", "ANTHROPIC_BASE_URL", "KEYS"])
def test_the_fake_key_variable_must_say_it_holds_a_key(layout: Path, name: str) -> None:
    """Review of the profiles, L4: it ends in _KEY, _API_KEY or _TOKEN. So it can never be one
    of the agent's own variables either (those never carry a secret's name)."""
    text = CUSTOM.replace('key_env = "ANTHROPIC_API_KEY"', f'key_env = "{name}"')
    with pytest.raises(ConfigError, match="must end in _KEY, _API_KEY or _TOKEN"):
        load(layout, text)


@pytest.mark.parametrize("name", ["MY_AGENT_KEY", "OPENAI_API_KEY", "AGENT_TOKEN", "x_api_key"])
def test_a_fake_key_variable_that_says_so(layout: Path, name: str) -> None:
    text = CUSTOM.replace('key_env = "ANTHROPIC_API_KEY"', f'key_env = "{name}"')
    assert load(layout, text).agent_profile.fake_key_env == ((name, "anthropic"),)


# What the docker CLI (and the Go programs it runs) reads from its own environment on the host:
# the fake key and the profile's variables travel there (review of the profiles, L4 and L8).
DOCKER_CLI_NAMES = (
    "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION", "DOCKER_AUTH_TOKEN", "docker_host", "BUILDKIT_PROGRESS",
    "BUILDX_BUILDER", "COMPOSE_PROJECT_NAME", "GODEBUG", "GOMAXPROCS", "GOTRACEBACK", "GOFLAGS",
    "GOAUTH_TOKEN", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS",
    "NOTARY_AUTH_TOKEN", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "LC_ALL", "TMPDIR",
    "XDG_RUNTIME_DIR", "KUBECONFIG", "CONTAINERD_ADDRESS",
)  # fmt: skip


@pytest.mark.parametrize("name", ["LANG", "LC_MESSAGES", "XDG_CONFIG_HOME", "MY_AGENT_GOAL"])
def test_an_own_variable_the_docker_cli_ignores(layout: Path, name: str) -> None:
    """The CLI's own messages stay C (docker.run sets LC_ALL last), and it reads no XDG folder
    but its runtime one: these reach the agent through it, unchanged (GO* is a prefix)."""
    assert dict(load(layout, custom(env=f'{{ {name} = "x" }}')).agent_profile.env) == {name: "x"}


@pytest.mark.parametrize("name", [n for n in DOCKER_CLI_NAMES if n.upper().endswith("_TOKEN")])
def test_the_fake_key_never_goes_where_the_docker_cli_reads(layout: Path, name: str) -> None:
    text = CUSTOM.replace('key_env = "ANTHROPIC_API_KEY"', f'key_env = "{name}"')
    with pytest.raises(ConfigError, match="read by the docker CLI on the host"):
        load(layout, text)


@pytest.mark.parametrize("name", ["DOCKER_HOST", "DOCKER_CONFIG", "OTEL_EXPORTER_OTLP_ENDPOINT"])
def test_a_key_env_the_docker_cli_reads_is_refused(layout: Path, name: str) -> None:
    """The finding's own case: ``key_env = "DOCKER_HOST"`` would hand backtide's docker the
    fake key as the daemon's address. Refused for its name (and its suffix)."""
    text = CUSTOM.replace('key_env = "ANTHROPIC_API_KEY"', f'key_env = "{name}"')
    with pytest.raises(ConfigError, match="docker CLI on the host|must end in _KEY"):
        load(layout, text)


@pytest.mark.parametrize("name", [n for n in DOCKER_CLI_NAMES if "TOKEN" not in n.upper()])
def test_an_own_variable_never_goes_where_the_docker_cli_reads(layout: Path, name: str) -> None:
    with pytest.raises(ConfigError, match="read by the docker CLI on the host"):
        load(layout, custom(env=f'{{ {name} = "x" }}'))


@pytest.mark.parametrize(
    "image",
    [
        '"ghcr.io/acme/agent:latest"',
        '"ghcr.io/acme/agent"',
        '"ghcr.io/acme/agent@sha256:abc"',
        '"ghcr.io/acme/agent:1.0@sha256:' + "c" * 63 + '"',
        '"--privileged@sha256:' + "c" * 64 + '"',
        "1",
    ],
    ids=["tag", "bare", "short-digest", "63-hex", "an-option", "not-a-text"],
)
def test_an_image_without_a_digest_is_refused(layout: Path, image: str) -> None:
    with pytest.raises(ConfigError, match="pinned by digest"):
        load(layout, custom(image=image))


def test_a_custom_agent_without_an_image_is_refused(layout: Path) -> None:
    text = "\n".join(line for line in CUSTOM.split("\n") if not line.startswith("image = "))
    with pytest.raises(ConfigError, match="needs \\[agent\\] image"):
        load(layout, text)


SECRET_VALUES = {
    "openai": "sk-" + "A1b2C3d4" * 4,
    "anthropic": "sk-ant-api03-" + "Zz9" * 10,
    "github": "ghp_" + "a" * 36,
    "slack": "xoxb-" + "1" * 20,
    "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
    "url-password": "https://user:hunter2@example.com/path",
    "bearer": "Bearer abcdefgh12345678",
    "pem": "-----BEGIN PRIVATE KEY-----",
    "fake-key": "backtide-fake-anthropic-" + "k" * 32,
    "named-pair": "token=abcd1234",
}


@pytest.mark.parametrize("value", SECRET_VALUES.values(), ids=SECRET_VALUES.keys())
def test_a_value_shaped_like_a_secret_is_refused_and_never_quoted(layout: Path, value: str) -> None:
    with pytest.raises(ConfigError, match="looks like a secret") as caught:
        load(layout, custom(env=f'{{ MY_AGENT_SETTING = "{value}" }}'))
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    "name", ["MY_API_KEY", "GH_TOKEN", "DB_PASSWORD", "AWS_SECRET", "CREDS_CREDENTIAL"]
)
def test_a_variable_named_like_a_secret_is_refused(layout: Path, name: str) -> None:
    with pytest.raises(ConfigError, match="never carry a secret") as caught:
        load(layout, custom(env=f'{{ {name} = "plain-value-0" }}'))
    assert "plain-value-0" not in str(caught.value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GPG_KEY", "7169605F62C751356D054A26A821E680E5FA6305"),  # python's images: public
        ("API_TOKEN", ""),  # a name alone, empty, holds no secret
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("PYTHON_SHA256", "7e32597b99e5d9a39abed35de4693fa169df3e5850d4c334337ffd6a19a36db6"),
        ("NODE_VERSION", "24.21.0"),
    ],
)
def test_what_is_not_shaped_like_a_secret(name: str, value: str) -> None:
    assert not secret_shaped(name, value)


@pytest.mark.parametrize("key", ["ports", "publish", "expose", "publish_all"])
def test_ports_are_refused(layout: Path, key: str) -> None:
    with pytest.raises(ConfigError, match="publishes no port"):
        load(layout, custom(**{key: '["127.0.0.1:8080:8080"]'}))


JAIL_KEYS = (
    "privileged", "cap_add", "cap_drop", "capabilities", "security_opt", "seccomp",
    "seccomp_profile", "apparmor", "no_new_privileges", "read_only", "user", "volumes", "mounts",
    "binds", "tmpfs", "devices", "network_mode", "networks", "dns", "dns_search", "extra_hosts",
    "add_host", "links", "pid", "ipc", "uts", "userns", "cgroup", "cgroup_parent", "sysctls",
    "group_add", "runtime", "init", "ulimits", "oom_kill_disable", "restart", "log_driver",
    "protected", "home", "proxy_url", "no_proxy", "ca_dir", "ca_file", "workspace",
)  # fmt: skip


@pytest.mark.parametrize("key", JAIL_KEYS)
def test_a_security_setting_is_refused(layout: Path, key: str) -> None:
    with pytest.raises(ConfigError, match="the jail decides it"):
        load(layout, custom(**{key: "true"}))


@pytest.mark.parametrize("key", ["privileged", "ports", "cap_add"])
def test_a_security_setting_is_refused_for_openclaw_too(layout: Path, key: str) -> None:
    with pytest.raises(ConfigError, match="the jail decides it|publishes no port"):
        load(layout, f"[agent]\n{key} = true\n")


@pytest.mark.parametrize(
    "key",
    ["privileged", "cap_add", "user", "volumes", "network", "uid", "ports", "image", "dns"],
)
def test_a_nested_table_cannot_set_a_security_setting(layout: Path, key: str) -> None:
    for table in ("[agent.model]", "[agent.ready]", "[agent.rewind]"):
        text = CUSTOM.replace(table, f"{table}\n{key} = true", 1)
        with pytest.raises(ConfigError, match="unknown"):
            load(layout, text)


def test_allow_shared_ids_is_still_unknown(layout: Path) -> None:
    with pytest.raises(ConfigError, match="unknown"):
        load(layout, custom(allow_shared_ids="true"))


@pytest.mark.parametrize(
    "workdir", ['"/etc"', '"/workspace/work"', '"../etc"', '"work/../../etc"', '"tmp"', '""', "1"]
)
def test_a_workdir_outside_the_agents_folder_is_refused(layout: Path, workdir: str) -> None:
    with pytest.raises(ConfigError, match="workdir"):
        load(layout, custom(workdir=workdir))


def test_a_workdir_below_work_or_home(layout: Path) -> None:
    profile = load(layout, custom(workdir='"work/repo"')).agent_profile
    assert profile.workdir == PurePosixPath("/workspace/work/repo")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("[]", "must name a program"),
        ('["--privileged"]', "invalid entrypoint"),
        ('["-v", "/:/host"]', "invalid entrypoint"),
        ('["tini agent"]', "invalid entrypoint"),
        ('"tini"', "list of texts"),
        ("[1]", "list of texts"),
    ],
)
def test_a_bad_entrypoint_is_refused(layout: Path, value: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load(layout, custom(entrypoint=value))


def test_a_custom_agent_without_an_entrypoint_is_refused(layout: Path) -> None:
    text = "\n".join(line for line in CUSTOM.split("\n") if not line.startswith("entrypoint"))
    with pytest.raises(ConfigError, match="needs entrypoint"):
        load(layout, text)


@pytest.mark.parametrize("value", ['"agent"', '["a\\nb"]', "[1]"])
def test_a_bad_command_is_refused(layout: Path, value: str) -> None:
    with pytest.raises(ConfigError, match="command"):
        load(layout, custom(command=value))


@pytest.mark.parametrize("value", ["{ A = 1 }", '{ A = "two\\nlines" }', '"A=1"'])
def test_a_bad_env_is_refused(layout: Path, value: str) -> None:
    with pytest.raises(ConfigError, match="env|value of A"):
        load(layout, custom(env=value))


@pytest.mark.parametrize("key", ["entrypoint", "command", "workdir", "env"])
def test_a_named_profile_takes_none_of_a_custom_agents_settings(layout: Path, key: str) -> None:
    with pytest.raises(ConfigError, match='only for profile = "custom"'):
        load(layout, f'[agent]\nprofile = "openclaw"\n{key} = ["x"]\n')


@pytest.mark.parametrize("table", ["model", "ready", "rewind"])
def test_a_named_profile_takes_none_of_a_custom_agents_tables(layout: Path, table: str) -> None:
    with pytest.raises(ConfigError, match='only for profile = "custom"'):
        load(layout, f"[agent]\n[agent.{table}]\n")


@pytest.mark.parametrize("name", ['"claude"', '"OpenClaw"', '"../x"', "1"])
def test_an_unknown_profile_is_refused(layout: Path, name: str) -> None:
    with pytest.raises(
        ConfigError, match="profile must be one of 'openclaw', 'claude-code', 'custom'"
    ):
        load(layout, custom(profile=name))


def test_the_model_provider_must_be_one_of_the_proxys(layout: Path) -> None:
    text = CUSTOM.replace('provider = "anthropic"', 'provider = "groq"')
    with pytest.raises(ConfigError, match="'groq' is not one of \\[\\[proxy.providers\\]\\]"):
        load(layout, text)


@pytest.mark.parametrize(
    "text",
    ['[agent.model]\nprovider = "anthropic"\n', '[agent.model]\nkey_env = "ANTHROPIC_API_KEY"\n'],
)
def test_the_model_needs_its_provider_and_variable(layout: Path, text: str) -> None:
    head = CUSTOM.split("[agent.model]")[0]
    with pytest.raises(ConfigError, match="needs provider"):
        load(layout, head + text + "[proxy]\n" + PROVIDER)


@pytest.mark.parametrize("params", ['["Diagnostics"]', '["a b"]', '[""]', '"diagnostics"'])
def test_bad_provider_params_are_refused(layout: Path, params: str) -> None:
    text = CUSTOM.replace('allow_params = ["diagnostics"]', f"allow_params = {params}")
    with pytest.raises(ConfigError):
        load(layout, text)


@pytest.mark.parametrize(
    "name",
    ["mcp_servers", "search_parameters", "extra_body", "web_search_options", "searchParameters"],
)
def test_a_provider_param_is_never_a_provider_side_tool(layout: Path, name: str) -> None:
    """Review of the profiles, M3: a field that switches on a search, a retrieval or a tool at
    the provider comes only from the owner's [proxy] allow_provider_tools. (``searchParameters``
    is refused for its case already: the gate folds a field's name to lower case.)"""
    text = CUSTOM.replace('allow_params = ["diagnostics"]', f'allow_params = ["{name}"]')
    with pytest.raises(ConfigError, match="provider's side|lower-case"):
        load(layout, text)


def test_the_owner_may_still_allow_a_provider_side_field(layout: Path) -> None:
    text = CUSTOM.replace(
        "[proxy]\n", '[proxy]\nallow_provider_tools = ["param:search_parameters"]\n', 1
    )
    config = load(layout, text)
    assert config.agent_profile.provider_params == ("param:diagnostics",)
    assert config.proxy_settings().allow_provider_tools == (
        "param:search_parameters",
        "param:diagnostics",
    )


def test_two_ready_timeouts_are_refused(layout: Path) -> None:
    with pytest.raises(ConfigError, match="set only one"):
        load(layout, custom(ready_timeout="30"))


@pytest.mark.parametrize(
    "timeout", ["0", "-1", '"60"', "true", "inf", "+inf", "-inf", "nan", "1e9", "600.5"]
)
def test_a_bad_ready_timeout_is_refused(layout: Path, timeout: str) -> None:
    """Review of the profiles, M1: wait_ready holds agent_lock while the agent already runs, so
    an endless wait (TOML has inf and nan) would freeze the cycle and the sensor's hooks."""
    with pytest.raises(ConfigError, match="timeout must be a number of seconds above 0"):
        load(layout, CUSTOM.replace("timeout = 45", f"timeout = {timeout}"))


@pytest.mark.parametrize("timeout", ["inf", "nan", "1e9", "601"])
def test_a_bad_ready_timeout_is_refused_for_openclaw_too(layout: Path, timeout: str) -> None:
    (layout / "state" / "gateway.token").write_text(TOKEN + "\n")
    (layout / "state" / "gateway.token").chmod(0o600)
    with pytest.raises(ConfigError, match="ready_timeout must be a number of seconds"):
        load(layout, f"[agent]\nready_timeout = {timeout}\n")


def test_the_longest_ready_timeout(layout: Path) -> None:
    jail = load(layout, CUSTOM.replace("timeout = 45", "timeout = 600")).jail_config()
    assert jail.ready_timeout == 600


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('log_line = "my-agent ready"', 'log_line = "two\\nlines"'),
        ('log_line = "my-agent ready"', "log_line = 1"),
        ('probe = ["/bin/true"]', 'probe = "/bin/true"'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = [""]'),
        # Review of the profiles, L9: printable, and a sentence, not a page.
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = ["a\\u001b[2Jb"]'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = ["a\\u202eb"]'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = ["a\\u200bb"]'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = ["a\\tb"]'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', f'notice = ["{"x" * 301}"]'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = "x"'),
        ('notice = ["Lo que el agente ya mandó fuera no vuelve."]', 'notice = ["x"] \n extra = 1'),
    ],
)
def test_bad_ready_and_notice_settings_are_refused(layout: Path, old: str, new: str) -> None:
    with pytest.raises(ConfigError):
        load(layout, CUSTOM.replace(old, new))


# --- a provider any profile can use; the old imports -----------------------------------------


def test_a_custom_agent_may_use_a_provider_openclaw_could_not(layout: Path) -> None:
    text = CUSTOM.replace(
        PROVIDER, '[[proxy.providers]]\nname = "local"\nkind = "openai"\nhost = "llm.example.com"\n'
    ).replace('provider = "anthropic"', 'provider = "local"')
    jail = load(layout, text).jail_config()  # OpenClaw would want its model ids
    assert [provider.name for provider in jail.model_providers] == ["local"]
    assert list(token_env(jail)) == ["ANTHROPIC_API_KEY"]


def test_model_provider_lives_apart_and_the_old_imports_still_work() -> None:
    assert openclaw_profile.ModelProvider is model_module.ModelProvider
    assert old_openclaw.ModelProvider is model_module.ModelProvider
    assert openclaw_profile.MODEL_ID is model_module.MODEL_ID


# --- the rewind notice says what the profile says --------------------------------------------


def test_the_rewind_notice_carries_the_profiles_lines(layout: Path) -> None:
    config = load(layout)
    lines = config.agent_profile.rewind_notice_lines
    paths = WebPaths.from_file(layout / "backtide.toml")
    assert paths.agent_lines == lines
    now = datetime(2026, 10, 22, 12, tzinfo=UTC)
    notice = rewind_notice(now, now=now, tz=UTC, agent_lines=lines)
    assert UNKNOWN_AGENT_NOTICE in notice
    assert not set(OPENCLAW.rewind_notice_lines) & set(notice)
