"""Unit tests for the jail's pure config: the docker argv, the network and OpenClaw's config."""

# ruff: noqa: S108 - the /tmp here is the tmpfs inside the agent's container

import json
from dataclasses import replace
from pathlib import Path

import pytest

from vigia.jail import config as jail_config
from vigia.jail.config import (
    AgentJailConfig,
    docker_create_argv,
    network_create_argv,
    openclaw_config,
    token_env,
)

TOKEN = "t" * 43  # the length of secrets.token_urlsafe(32)
WORKSPACE = Path("/srv/vigia/volume/workspace")
CONFIG_DIR = Path("/srv/vigia/agent-config")
SECRET_WORDS = ("KEY", "SECRET", "PASSWORD")
# Options that would open a hole in the jail. None may ever appear in the argv.
FORBIDDEN_OPTIONS = {
    "-p",
    "--publish",
    "-P",
    "--publish-all",
    "--privileged",
    "--cap-add",
    "--add-host",
    "--device",
    "--mount",
    "--pid",
    "--ipc",
    "--uts",
    "--userns",
    "--cgroupns",
    "--volumes-from",
    "--group-add",
    "--sysctl",
}


@pytest.fixture
def cfg() -> AgentJailConfig:
    return AgentJailConfig(workspace=WORKSPACE, config_dir=CONFIG_DIR, gateway_token=TOKEN)


def option_values(argv: list[str], option: str) -> list[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == option]


# docker create


def test_create_argv_has_every_option_of_the_design(cfg: AgentJailConfig) -> None:
    argv = docker_create_argv(cfg)
    assert argv[0] == "create"
    expected = {
        "--name": ["vigia-agente"],
        "--hostname": ["agente"],
        "--user": ["61000:61000"],  # the agent's own ids: no host account, not Vigía's
        "--cap-drop": ["ALL"],
        "--security-opt": ["no-new-privileges=true", f"seccomp={jail_config.SECCOMP_PROFILE}"],
        "--tmpfs": ["/tmp:rw,nosuid,nodev,size=256m"],
        "--network": ["vigia-agente-net"],
        "--restart": ["no"],
        "--memory": ["2g"],
        "--memory-swap": ["2g"],
        "--pids-limit": ["512"],
        "--cpus": ["2"],
        "--entrypoint": ["tini"],
    }
    for option, values in expected.items():
        assert option_values(argv, option) == values, option
    assert "--read-only" in argv


def test_create_argv_mounts_only_the_agent_folder_and_the_config(cfg: AgentJailConfig) -> None:
    argv = docker_create_argv(cfg)
    assert option_values(argv, "--volume") == [
        f"{WORKSPACE}/agente:/workspace:z",
        f"{CONFIG_DIR}:/config:ro,z",
    ]
    assert "-v" not in argv and "--mount" not in argv


def test_create_argv_ends_with_the_pinned_image_and_the_gateway(cfg: AgentJailConfig) -> None:
    argv = docker_create_argv(cfg)
    image_at = argv.index(jail_config.IMAGE)
    assert argv[image_at + 1 :] == ["-s", "--", "node", "openclaw.mjs", "gateway"]
    assert "@sha256:" in argv[image_at]


def test_create_argv_never_opens_a_hole(cfg: AgentJailConfig) -> None:
    argv = docker_create_argv(cfg)
    assert FORBIDDEN_OPTIONS.isdisjoint(argv)
    assert not any(arg.startswith(("--publish=", "-p=", "--network=host")) for arg in argv)
    text = " ".join(argv)
    for needle in ("docker.sock", "host.docker.internal", "host-gateway", "unconfined"):
        assert needle not in text
    assert option_values(argv, "--network") == [cfg.network]
    assert option_values(argv, "--restart") == ["no"]


def test_create_argv_carries_no_secret(cfg: AgentJailConfig) -> None:
    argv = docker_create_argv(cfg)
    assert TOKEN not in " ".join(argv)
    env = option_values(argv, "--env")
    names = [entry.split("=", 1)[0] for entry in env]
    assert [n for n in names if any(word in n.upper() for word in SECRET_WORDS)] == []
    # The token is passed by name only; the docker CLI copies it from its own environment.
    assert "OPENCLAW_GATEWAY_TOKEN" in env
    assert token_env(cfg) == {"OPENCLAW_GATEWAY_TOKEN": TOKEN}


def test_create_argv_sets_the_environment_of_the_design(cfg: AgentJailConfig) -> None:
    env = dict(
        entry.split("=", 1) for entry in option_values(docker_create_argv(cfg), "--env")[:-1]
    )
    assert env == {
        "HOME": "/workspace/home",
        "OPENCLAW_STATE_DIR": "/workspace/state",
        "OPENCLAW_WORKSPACE_DIR": "/workspace/work",
        "OPENCLAW_CONFIG_PATH": "/config/openclaw.json",
        "OPENCLAW_CONFIG_READONLY": "1",
        "OPENCLAW_NO_AUTO_UPDATE": "1",
        "OPENCLAW_OFFLINE": "1",
        "OPENCLAW_DISABLE_BONJOUR": "1",
        "OPENCLAW_SKIP_CRON": "1",
        "OPENCLAW_SKIP_CANVAS_HOST": "1",
        "OPENCLAW_SKIP_GMAIL_WATCHER": "1",
        "CLAWHUB_DISABLE_TELEMETRY": "1",
        "DO_NOT_TRACK": "1",
    }


def test_create_argv_follows_the_config(cfg: AgentJailConfig) -> None:
    custom = replace(
        cfg,
        name="agent-2",
        network="net-2",
        hostname="agent-two",
        uid=501,
        gid=20,
        memory="512m",
        pids_limit=64,
        cpus="0.5",
        tmp_size="64m",
        seccomp_profile=Path("/etc/vigia/agent.json"),
        stop_timeout=5,
    )
    argv = docker_create_argv(custom)
    assert option_values(argv, "--name") == ["agent-2"]
    assert option_values(argv, "--network") == ["net-2"]
    assert option_values(argv, "--hostname") == ["agent-two"]
    assert option_values(argv, "--user") == ["501:20"]
    assert option_values(argv, "--memory") == ["512m"]
    assert option_values(argv, "--pids-limit") == ["64"]
    assert option_values(argv, "--cpus") == ["0.5"]
    assert option_values(argv, "--tmpfs") == ["/tmp:rw,nosuid,nodev,size=64m"]
    assert "seccomp=/etc/vigia/agent.json" in option_values(argv, "--security-opt")
    assert option_values(argv, "--stop-timeout") == ["5"]


def test_logs_are_bounded(cfg: AgentJailConfig) -> None:
    argv = docker_create_argv(cfg)
    assert option_values(argv, "--log-driver") == ["local"]
    assert option_values(argv, "--log-opt") == ["max-size=10m", "max-file=3"]


@pytest.mark.parametrize(
    ("size", "expected"), [("2g", 2 * 1024**3), ("1536m", 1536 * 1024**2), ("64k", 65536)]
)
def test_memory_sizes_are_read_like_docker(size: str, expected: int) -> None:
    assert jail_config.memory_bytes(size) == expected


@pytest.mark.parametrize(
    ("cpus", "expected"), [("2", 2_000_000_000), ("0.5", 500_000_000), ("1.25", 1_250_000_000)]
)
def test_cpus_are_read_like_docker(cpus: str, expected: int) -> None:
    assert jail_config.nano_cpus(cpus) == expected


def test_the_seccomp_profile_ships_with_the_repo() -> None:
    assert jail_config.SECCOMP_PROFILE.is_file()
    assert jail_config.SECCOMP_PROFILE.name == "agent.json"


# The network


def test_network_is_internal_and_isolated_from_the_host(cfg: AgentJailConfig) -> None:
    argv = network_create_argv(cfg)
    assert argv[:2] == ["network", "create"]
    assert argv[-1] == cfg.network
    assert "--internal" in argv
    assert option_values(argv, "--driver") == ["bridge"]
    assert option_values(argv, "--opt") == [
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "com.docker.network.bridge.gateway_mode_ipv6=isolated",
    ]


# OpenClaw's config


def test_openclaw_config_is_the_hardened_baseline(cfg: AgentJailConfig) -> None:
    assert openclaw_config(cfg) == {
        "gateway": {"mode": "local", "bind": "loopback", "port": 18789, "auth": {"mode": "token"}},
        "update": {"checkOnStart": False, "auto": {"enabled": False}},
        "models": {"catalogRefresh": {"enabled": False}},
        "cron": {"enabled": False},
        "memory": {"search": {"provider": "none"}},
        "discovery": {"mdns": {"mode": "off"}},
        "agents": {"defaults": {"workspace": "/workspace/work", "sandbox": {"mode": "off"}}},
        "tools": {
            "elevated": {"enabled": False},
            "deny": ["group:automation", "sessions_spawn", "sessions_send"],
        },
    }


def test_openclaw_config_holds_no_secret(cfg: AgentJailConfig) -> None:
    config = openclaw_config(cfg)
    assert TOKEN not in json.dumps(config)
    secret_keys = {"token", "password", "apikey", "secret"}
    assert [key for key in _keys(config) if key.lower() in secret_keys] == []


def _keys(value: object) -> list[str]:
    """Every dictionary key in a nested JSON value."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found += [key, *_keys(child)]
    elif isinstance(value, list):
        for child in value:
            found += _keys(child)
    return found


# Validation


def test_paths_of_the_agent(cfg: AgentJailConfig) -> None:
    assert cfg.agent_dir == WORKSPACE / "agente"
    assert cfg.config_file == CONFIG_DIR / "openclaw.json"


def test_repr_hides_the_token(cfg: AgentJailConfig) -> None:
    assert TOKEN not in repr(cfg)


@pytest.mark.parametrize(
    "changes",
    [
        {"uid": 0},
        {"gid": 0},
        {"uid": -1},
        {"uid": True},
        {"uid": "1000"},
        {"pids_limit": 0},
        {"stop_timeout": 0},
        {"ready_timeout": 0},
        {"workspace": Path("relative/workspace")},
        {"config_dir": Path("config")},
        {"seccomp_profile": Path("agent.json")},
        {"workspace": Path("/srv/with:colon/workspace")},
        {"config_dir": Path("/srv/with,comma")},
        {"config_dir": WORKSPACE / "agente" / "config"},  # inside the workspace
        {"config_dir": WORKSPACE},
        {"workspace": CONFIG_DIR / "workspace"},  # the other way round
        {"name": "-rm"},
        {"name": "has space"},
        {"name": ""},
        {"network": "host network"},
        {"hostname": "Agente"},
        {"hostname": "-agente"},
        {"image": "ghcr.io/openclaw/openclaw:latest"},  # not pinned by digest
        {"image": "ghcr.io/openclaw/openclaw@sha256:abc"},
        {"memory": "2"},
        {"memory": "0g"},
        {"memory": "2gb"},
        {"tmp_size": "lots"},
        {"cpus": "0"},
        {"cpus": "-1"},
        {"cpus": "two"},
        {"gateway_token": "short"},
        {"gateway_token": "t" * 40 + "\n"},
        {"gateway_token": "t" * 40 + "=="},
        {"allow_shared_ids": "yes"},
    ],
)
def test_invalid_configs_are_refused(changes: dict[str, object]) -> None:
    fields = {"workspace": WORKSPACE, "config_dir": CONFIG_DIR, "gateway_token": TOKEN}
    with pytest.raises(ValueError):
        AgentJailConfig(**(fields | changes))  # type: ignore[arg-type]


def test_valid_custom_config_is_accepted() -> None:
    config = AgentJailConfig(
        workspace=WORKSPACE,
        config_dir=CONFIG_DIR,
        gateway_token="A-b_9" * 8,
        name="vigia-test-agent-0123abcd",
        network="vigia-test-net-0123abcd",
        uid=501,
        gid=1000,
        cpus="1.5",
        memory="1536m",
    )
    assert config.uid == 501
