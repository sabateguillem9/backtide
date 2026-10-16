"""Unit tests for vigia/jail/verify.py: is an existing container exactly the jail?

GOOD is what ``docker container inspect`` reported in the VM (Docker 29.8.2) for a container
made by docker_create_argv, reduced to the fields that matter. The VM test
test_container_settings runs the same check against a real container."""

# ruff: noqa: S108 - the /tmp here is the tmpfs inside the agent's container

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from vigia.jail.config import IMAGE, AgentJailConfig
from vigia.jail.verify import container_problems

TOKEN = "t" * 43
WORKSPACE = Path("/srv/vigia/volume/workspace")
CONFIG_DIR = Path("/srv/vigia/agent-config")
PROFILE = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": ["read"]}]}
IMAGE_ENV = ["PATH=/usr/local/bin:/usr/bin:/bin", "NODE_ENV=production"]
JAIL_ENV = [
    "HOME=/workspace/home",
    "OPENCLAW_STATE_DIR=/workspace/state",
    "OPENCLAW_WORKSPACE_DIR=/workspace/work",
    "OPENCLAW_CONFIG_PATH=/config/openclaw.json",
    "OPENCLAW_CONFIG_READONLY=1",
    "OPENCLAW_NO_AUTO_UPDATE=1",
    "OPENCLAW_OFFLINE=1",
    "OPENCLAW_DISABLE_BONJOUR=1",
    "OPENCLAW_SKIP_CRON=1",
    "OPENCLAW_SKIP_CANVAS_HOST=1",
    "OPENCLAW_SKIP_GMAIL_WATCHER=1",
    "CLAWHUB_DISABLE_TELEMETRY=1",
    "DO_NOT_TRACK=1",
    f"OPENCLAW_GATEWAY_TOKEN={TOKEN}",
]

MASK_OPTIONS = "ro,nosuid,nodev,noexec,size=4k,mode=0555"  # the /sys masks, as docker keeps them

GOOD: dict[str, Any] = {
    "Config": {
        "Image": IMAGE,
        "User": "61000:61000",
        "Hostname": "agente",
        "Entrypoint": ["tini"],
        "Cmd": ["-s", "--", "node", "openclaw.mjs", "gateway"],
        "StopTimeout": 30,
        "Env": [*IMAGE_ENV, *JAIL_ENV],
    },
    "HostConfig": {
        "Binds": [f"{WORKSPACE}/agente:/workspace:z", f"{CONFIG_DIR}:/config:ro,z"],
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "Cgroup": "",
        "CgroupnsMode": "private",
        "DeviceCgroupRules": None,
        "DeviceRequests": None,
        "Devices": [],
        "ExtraHosts": None,
        "GroupAdd": None,
        "IpcMode": "private",
        "Links": None,
        "LogConfig": {"Type": "local", "Config": {"max-file": "3", "max-size": "10m"}},
        "Memory": 2147483648,
        "MemorySwap": 2147483648,
        "NanoCpus": 2000000000,
        "NetworkMode": "vigia-agente-net",
        "OomKillDisable": False,
        "PidMode": "",
        "PidsLimit": 512,
        "PortBindings": {},
        "Privileged": False,
        "PublishAllPorts": False,
        "ReadonlyRootfs": True,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "SecurityOpt": ["no-new-privileges=true", f"seccomp={json.dumps(PROFILE)}"],
        "Tmpfs": {
            "/tmp": "rw,nosuid,nodev,size=256m",
            "/sys/fs/btrfs": MASK_OPTIONS,
            "/sys/devices/virtual/block": MASK_OPTIONS,
        },
        "UTSMode": "",
        "UsernsMode": "",
        "VolumeDriver": "",
        "VolumesFrom": None,
    },
    "NetworkSettings": {"Networks": {"vigia-agente-net": {"IPAddress": ""}}},
}


@pytest.fixture
def cfg() -> AgentJailConfig:
    return AgentJailConfig(workspace=WORKSPACE, config_dir=CONFIG_DIR, gateway_token=TOKEN)


def problems(cfg: AgentJailConfig, info: dict[str, Any]) -> list[str]:
    return container_problems(cfg, info, seccomp_profile=PROFILE, image_env=IMAGE_ENV)


def changed(path: str, value: object) -> dict[str, Any]:
    """GOOD with the field at ``path`` (dotted) set to ``value``."""
    info = copy.deepcopy(GOOD)
    *parents, last = path.split(".")
    node = info
    for name in parents:
        node = node[name]
    node[last] = value
    return info


def test_the_jail_itself_passes(cfg: AgentJailConfig) -> None:
    assert problems(cfg, GOOD) == []


def test_the_order_of_lists_docker_keeps_does_not_matter(cfg: AgentJailConfig) -> None:
    info = changed("Config.Env", list(reversed(GOOD["Config"]["Env"])))
    info["HostConfig"]["Binds"].reverse()
    info["HostConfig"]["SecurityOpt"].reverse()
    assert problems(cfg, info) == []


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        # Who and what runs
        ("Config.Image", "ghcr.io/openclaw/openclaw:latest", "Image"),
        ("Config.User", "1000:1000", "User"),
        ("Config.User", "", "User"),
        ("Config.Hostname", "debug", "Hostname"),
        ("Config.Entrypoint", ["docker-entrypoint.sh"], "Entrypoint"),
        ("Config.Cmd", ["sh"], "Cmd"),
        ("Config.StopTimeout", 1, "StopTimeout"),
        # Privileges
        ("HostConfig.Privileged", True, "Privileged"),
        ("HostConfig.CapAdd", ["SYS_ADMIN"], "CapAdd"),
        ("HostConfig.CapDrop", None, "CapDrop"),
        ("HostConfig.CapDrop", ["NET_RAW"], "CapDrop"),
        ("HostConfig.ReadonlyRootfs", False, "ReadonlyRootfs"),
        ("HostConfig.SecurityOpt", [f"seccomp={json.dumps(PROFILE)}"], "security options"),
        (
            "HostConfig.SecurityOpt",
            ["no-new-privileges=true", "seccomp=unconfined"],
            "seccomp profile",
        ),
        (
            "HostConfig.SecurityOpt",
            ["no-new-privileges=true", 'seccomp={"defaultAction": "SCMP_ACT_ALLOW"}'],
            "seccomp profile",
        ),
        ("HostConfig.SecurityOpt", ["no-new-privileges=true"], "seccomp profile"),
        (
            "HostConfig.SecurityOpt",
            [*GOOD["HostConfig"]["SecurityOpt"], "label=disable"],
            "security options",
        ),
        (
            "HostConfig.SecurityOpt",
            [*GOOD["HostConfig"]["SecurityOpt"], "systempaths=unconfined"],
            "security options",
        ),
        ("HostConfig.Devices", [{"PathOnHost": "/dev/kmsg"}], "Devices"),
        ("HostConfig.DeviceCgroupRules", ["b *:* rwm"], "DeviceCgroupRules"),
        ("HostConfig.DeviceRequests", [{"Driver": "nvidia"}], "DeviceRequests"),
        ("HostConfig.GroupAdd", ["docker"], "GroupAdd"),
        ("HostConfig.Sysctls", {"net.ipv4.ip_forward": "1"}, "Sysctls"),
        # What it sees of the host
        ("HostConfig.Binds", [f"{WORKSPACE}/agente:/workspace:z"], "mounts"),
        (
            "HostConfig.Binds",
            [*GOOD["HostConfig"]["Binds"], "/var/run/docker.sock:/var/run/docker.sock"],
            "mounts",
        ),
        ("HostConfig.Binds", [f"{WORKSPACE}:/workspace:z", f"{CONFIG_DIR}:/config:ro,z"], "mounts"),
        (
            "HostConfig.Binds",
            [f"{WORKSPACE}/agente:/workspace:z", f"{CONFIG_DIR}:/config:z"],
            "mounts",
        ),
        ("HostConfig.Mounts", [{"Type": "bind", "Source": "/", "Target": "/host"}], "Mounts"),
        ("HostConfig.VolumesFrom", ["vigia"], "VolumesFrom"),
        ("HostConfig.Tmpfs", {"/tmp": "rw,exec,size=256m"}, "Tmpfs"),
        # A container from before the /sys masks (or one that lost one) shows the agent the host
        (
            "HostConfig.Tmpfs",
            {"/tmp": "rw,nosuid,nodev,size=256m", "/sys/devices/virtual/block": MASK_OPTIONS},
            "Tmpfs",
        ),
        (
            "HostConfig.Tmpfs",
            {"/tmp": "rw,nosuid,nodev,size=256m", "/sys/fs/btrfs": MASK_OPTIONS},
            "Tmpfs",
        ),
        ("HostConfig.Tmpfs", {"/tmp": "rw,nosuid,nodev,size=256m"}, "Tmpfs"),
        ("HostConfig.Tmpfs", None, "Tmpfs"),
        (  # writable, or bigger, is not a mask
            "HostConfig.Tmpfs",
            {
                "/tmp": "rw,nosuid,nodev,size=256m",
                "/sys/fs/btrfs": "rw,nosuid,nodev,noexec,size=4k,mode=0555",
                "/sys/devices/virtual/block": MASK_OPTIONS,
            },
            "Tmpfs",
        ),
        (  # an extra tmpfs
            "HostConfig.Tmpfs",
            {
                "/tmp": "rw,nosuid,nodev,size=256m",
                "/sys/fs/btrfs": MASK_OPTIONS,
                "/sys/devices/virtual/block": MASK_OPTIONS,
                "/var/run": "rw",
            },
            "Tmpfs",
        ),
        ("HostConfig.PidMode", "host", "PidMode"),
        ("HostConfig.IpcMode", "host", "IpcMode"),
        ("HostConfig.IpcMode", "container:vigia", "IpcMode"),
        ("HostConfig.UTSMode", "host", "UTSMode"),
        ("HostConfig.UsernsMode", "host", "UsernsMode"),
        ("HostConfig.CgroupnsMode", "host", "CgroupnsMode"),
        ("HostConfig.Cgroup", "host", "Cgroup"),
        # The network
        ("HostConfig.NetworkMode", "host", "networks"),
        ("HostConfig.NetworkMode", "bridge", "networks"),
        ("NetworkSettings.Networks", {"vigia-agente-net": {}, "bridge": {}}, "networks"),
        ("HostConfig.PortBindings", {"18789/tcp": [{"HostPort": "18789"}]}, "PortBindings"),
        ("HostConfig.PublishAllPorts", True, "PublishAllPorts"),
        ("HostConfig.ExtraHosts", ["host.docker.internal:host-gateway"], "ExtraHosts"),
        ("HostConfig.Links", ["/vigia:/agente/vigia"], "Links"),
        # Limits
        ("HostConfig.RestartPolicy", {"Name": "always"}, "RestartPolicy"),
        ("HostConfig.Memory", 0, "Memory"),
        ("HostConfig.MemorySwap", -1, "MemorySwap"),
        ("HostConfig.PidsLimit", None, "PidsLimit"),
        ("HostConfig.NanoCpus", 0, "NanoCpus"),
        ("HostConfig.OomKillDisable", True, "OomKillDisable"),
        ("HostConfig.LogConfig", {"Type": "json-file", "Config": {}}, "LogConfig"),
    ],
)
def test_any_difference_is_reported(
    cfg: AgentJailConfig, path: str, value: object, expected: str
) -> None:
    found = problems(cfg, changed(path, value))
    assert found, f"{path}={value!r} went unnoticed"
    assert any(expected in problem for problem in found), found


@pytest.mark.parametrize(
    "env",
    [
        [*IMAGE_ENV, *JAIL_ENV[:-1]],  # no token
        [*IMAGE_ENV, *JAIL_ENV[:-1], "OPENCLAW_GATEWAY_TOKEN=" + "u" * 43],  # another token
        [*IMAGE_ENV, *JAIL_ENV, "ANTHROPIC_API_KEY=sk-ant-fake"],
        [*IMAGE_ENV, *JAIL_ENV[1:]],  # no HOME under /workspace
        [*IMAGE_ENV, *(e for e in JAIL_ENV if not e.startswith("OPENCLAW_CONFIG_READONLY"))],
        [*IMAGE_ENV[1:], *JAIL_ENV],  # an image variable missing
    ],
)
def test_any_difference_in_the_environment_is_reported_by_name_only(
    cfg: AgentJailConfig, env: list[str]
) -> None:
    found = problems(cfg, changed("Config.Env", env))
    assert len(found) == 1 and "environment differs" in found[0]
    assert TOKEN not in found[0] and "u" * 43 not in found[0] and "sk-ant" not in found[0]


def test_the_config_decides_the_expected_values(cfg: AgentJailConfig) -> None:
    other = replace(cfg, uid=61001, memory="512m", cpus="0.5", pids_limit=64, tmp_size="64m")
    found = " ".join(problems(other, GOOD))
    for field in ("User", "Memory", "MemorySwap", "NanoCpus", "PidsLimit", "Tmpfs"):
        assert field in found, field
    info = changed("Config.User", "61001:61000")
    host = info["HostConfig"]
    host["Memory"] = host["MemorySwap"] = 512 * 1024**2
    host["NanoCpus"] = 500_000_000
    host["PidsLimit"] = 64
    host["Tmpfs"] = {**host["Tmpfs"], "/tmp": "rw,nosuid,nodev,size=64m"}
    assert problems(other, info) == []


def test_missing_sections_are_problems_not_crashes(cfg: AgentJailConfig) -> None:
    assert problems(cfg, {}) != []
    assert problems(cfg, {"Config": None, "HostConfig": "x"}) != []
