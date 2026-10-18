"""Unit tests for backtide/jail/verify.py: is an existing container exactly the jail?

GOOD is what ``docker container inspect`` reported in the VM (Docker 29.8.2) for a container
made by docker_create_argv, reduced to the fields that matter, and PROXY_GOOD the same for the
egress proxy (proxy_create_argv). The VM tests test_container_settings and
test_proxy_container.py run the same checks against real containers."""

# ruff: noqa: S108 - the /tmp here is the tmpfs inside the agent's container

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from backtide.jail import proxy_config
from backtide.jail.config import IMAGE, AgentJailConfig
from backtide.jail.proxy_config import ProxyJailConfig
from backtide.jail.verify import container_problems, proxy_container_problems

TOKEN = "t" * 43
WORKSPACE = Path("/srv/backtide/volume/workspace")
CONFIG_DIR = Path("/srv/backtide/agent-config")
CA_DIR = Path("/srv/backtide/agent-ca")
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
    "HTTP_PROXY=http://backtide-proxy:8080",
    "HTTPS_PROXY=http://backtide-proxy:8080",
    "http_proxy=http://backtide-proxy:8080",
    "https_proxy=http://backtide-proxy:8080",
    "OPENCLAW_PROXY_URL=http://backtide-proxy:8080",
    "NO_PROXY=localhost,127.0.0.1,::1",
    "no_proxy=localhost,127.0.0.1,::1",
    "NODE_USE_ENV_PROXY=1",
    "NODE_EXTRA_CA_CERTS=/etc/backtide-ca/ca.pem",
    "SSL_CERT_FILE=/etc/backtide-ca/ca.pem",
    "REQUESTS_CA_BUNDLE=/etc/backtide-ca/ca.pem",
    "CURL_CA_BUNDLE=/etc/backtide-ca/ca.pem",
    "GIT_SSL_CAINFO=/etc/backtide-ca/ca.pem",
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
        "Binds": [
            f"{WORKSPACE}/agente:/workspace:z",
            f"{CONFIG_DIR}:/config:ro,z",
            f"{CA_DIR}:/etc/backtide-ca:ro,z",
        ],
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "Cgroup": "",
        "CgroupnsMode": "private",
        "DeviceCgroupRules": None,
        "DeviceRequests": None,
        "Devices": [],
        "Dns": [],
        "DnsOptions": [],
        "DnsSearch": [],
        "ExtraHosts": None,
        "GroupAdd": None,
        "IpcMode": "private",
        "Links": None,
        "LogConfig": {"Type": "local", "Config": {"max-file": "3", "max-size": "10m"}},
        "Memory": 2147483648,
        "MemorySwap": 2147483648,
        "NanoCpus": 2000000000,
        "NetworkMode": "backtide-agente-net",
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
    "NetworkSettings": {"Networks": {"backtide-agente-net": {"IPAddress": ""}}},
}


@pytest.fixture
def cfg() -> AgentJailConfig:
    return AgentJailConfig(
        workspace=WORKSPACE, config_dir=CONFIG_DIR, ca_dir=CA_DIR, gateway_token=TOKEN
    )


def problems(cfg: AgentJailConfig, info: dict[str, Any]) -> list[str]:
    return container_problems(cfg, info, seccomp_profile=PROFILE, image_env=IMAGE_ENV)


def changed(path: str, value: object, good: dict[str, Any] | None = None) -> dict[str, Any]:
    """GOOD (or ``good``) with the field at ``path`` (dotted) set to ``value``."""
    info = copy.deepcopy(GOOD if good is None else good)
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
        ("HostConfig.Sysctls", {"net.ipv4.ip_forward": "0"}, "Sysctls"),  # IPv6 forwarding
        # What it sees of the host
        ("HostConfig.Binds", [f"{WORKSPACE}/agente:/workspace:z"], "mounts"),
        # Without the CA (no way out), or with the proxy's folder and its key
        ("HostConfig.Binds", GOOD["HostConfig"]["Binds"][:2], "mounts"),
        (
            "HostConfig.Binds",
            [*GOOD["HostConfig"]["Binds"][:2], "/srv/backtide/proxy-ca:/etc/backtide-ca:ro,z"],
            "mounts",
        ),
        (
            "HostConfig.Binds",
            [*GOOD["HostConfig"]["Binds"][:2], f"{CA_DIR}:/etc/backtide-ca:z"],
            "mounts",
        ),
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
        ("HostConfig.VolumesFrom", ["backtide"], "VolumesFrom"),
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
        ("HostConfig.IpcMode", "container:backtide", "IpcMode"),
        ("HostConfig.UTSMode", "host", "UTSMode"),
        ("HostConfig.UsernsMode", "host", "UsernsMode"),
        ("HostConfig.CgroupnsMode", "host", "CgroupnsMode"),
        ("HostConfig.Cgroup", "host", "Cgroup"),
        # The network
        ("HostConfig.NetworkMode", "host", "networks"),
        ("HostConfig.NetworkMode", "bridge", "networks"),
        ("NetworkSettings.Networks", {"backtide-agente-net": {}, "bridge": {}}, "networks"),
        ("HostConfig.PortBindings", {"18789/tcp": [{"HostPort": "18789"}]}, "PortBindings"),
        ("HostConfig.PublishAllPorts", True, "PublishAllPorts"),
        ("HostConfig.ExtraHosts", ["host.docker.internal:host-gateway"], "ExtraHosts"),
        ("HostConfig.Links", ["/backtide:/agente/backtide"], "Links"),
        # A DNS server of its own: Docker would forward outside names to it (T06-1, P5)
        ("HostConfig.Dns", ["192.0.2.53"], "Dns"),
        ("HostConfig.DnsOptions", ["ndots:0"], "DnsOptions"),
        ("HostConfig.DnsSearch", ["example.com"], "DnsSearch"),
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
        [*IMAGE_ENV, *(e for e in JAIL_ENV if not e.startswith("HTTPS_PROXY="))],
        [*IMAGE_ENV, *(e for e in JAIL_ENV if not e.startswith("NODE_EXTRA_CA_CERTS="))],
        [*IMAGE_ENV, *JAIL_ENV, "NODE_TLS_REJECT_UNAUTHORIZED=0"],
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


# The egress proxy

PROXY_CA = Path("/srv/backtide/proxy-ca")
CHANNEL = Path("/srv/backtide/proxy-channel")
PACKAGE = Path("/opt/backtide-src/backtide")
PROXY_IMAGE_ENV = ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"]
PROXY_ENV = [
    "PYTHONPATH=/opt/backtide",
    "HOME=/tmp",
    "PYTHONUNBUFFERED=1",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONSAFEPATH=1",
    "PYTHONNOUSERSITE=1",
    "BACKTIDE_UID=0",
]
PROXY_GOOD: dict[str, Any] = {
    "Config": {
        "Image": proxy_config.IMAGE,
        "User": "61001:61001",
        "Entrypoint": ["python3"],
        "Cmd": ["-m", "backtide.gate.main"],
        "StopTimeout": 10,
        "Env": [*PROXY_IMAGE_ENV, *PROXY_ENV],
    },
    "HostConfig": {
        "Binds": [
            f"{PROXY_CA}:/ca:ro,z",
            f"{CHANNEL}:/run/backtide:z",
            f"{PACKAGE}:/opt/backtide/backtide:ro,z",
        ],
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "Cgroup": "",
        "CgroupnsMode": "private",
        "DeviceCgroupRules": None,
        "DeviceRequests": None,
        "Devices": [],
        "Dns": [],
        "DnsOptions": [],
        "DnsSearch": [],
        "ExtraHosts": None,
        "GroupAdd": None,
        "IpcMode": "private",
        "Links": None,
        "LogConfig": {"Type": "local", "Config": {"max-file": "3", "max-size": "10m"}},
        "Memory": 1073741824,
        "MemorySwap": 1073741824,
        "NanoCpus": 1000000000,
        "NetworkMode": "backtide-agente-net",
        "OomKillDisable": False,
        "PidMode": "",
        "PidsLimit": 128,
        "PortBindings": {},
        "Privileged": False,
        "PublishAllPorts": False,
        "ReadonlyRootfs": True,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "SecurityOpt": ["no-new-privileges=true"],
        "Sysctls": {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
        "MaskedPaths": ["/proc/kcore", "/proc/keys"],
        "ReadonlyPaths": ["/proc/bus", "/proc/sys"],
        "Runtime": "runc",
        "CgroupParent": "",
        "Tmpfs": {
            "/tmp": "rw,nosuid,nodev,noexec,size=64m",
            "/home/mitmproxy/.mitmproxy": "ro,nosuid,nodev,noexec,size=4k,mode=0555",
        },
        "Ulimits": [{"Name": "nofile", "Hard": 4096, "Soft": 4096}],
        "UTSMode": "",
        "UsernsMode": "",
        "VolumeDriver": "",
        "VolumesFrom": None,
    },
    "Mounts": [
        {"Type": "bind", "Source": str(PROXY_CA), "Destination": "/ca", "RW": False},
        {"Type": "bind", "Source": str(CHANNEL), "Destination": "/run/backtide", "RW": True},
    ],
    "NetworkSettings": {
        "Networks": {
            "backtide-agente-net": {"Aliases": ["backtide-proxy"], "IPAddress": "172.30.0.2"},
            "backtide-salida-net": {"Aliases": None, "IPAddress": "172.31.0.2"},
        }
    },
}


@pytest.fixture
def proxy_cfg() -> ProxyJailConfig:
    return ProxyJailConfig(ca_dir=PROXY_CA, channel_dir=CHANNEL, package_dir=PACKAGE)


def proxy_problems(cfg: ProxyJailConfig, info: dict[str, Any]) -> list[str]:
    return proxy_container_problems(cfg, info, image_env=PROXY_IMAGE_ENV)


def test_the_proxy_itself_passes(proxy_cfg: ProxyJailConfig) -> None:
    assert proxy_problems(proxy_cfg, PROXY_GOOD) == []
    info = changed("HostConfig.NetworkMode", "backtide-salida-net", PROXY_GOOD)
    assert proxy_problems(proxy_cfg, info) == []  # whichever network docker calls the first


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        ("Config.Image", "mitmproxy/mitmproxy:latest", "Image"),
        ("Config.User", "0:0", "User"),
        ("Config.User", "61000:61000", "User"),  # the agent's ids
        ("Config.Entrypoint", ["docker-entrypoint.sh"], "Entrypoint"),  # gosu, as root
        ("Config.Cmd", ["mitmdump", "-s", "/opt/addon.py"], "Cmd"),  # an addon that may not load
        ("Config.StopTimeout", 300, "StopTimeout"),
        ("HostConfig.Privileged", True, "Privileged"),
        ("HostConfig.CapAdd", ["NET_ADMIN"], "CapAdd"),
        ("HostConfig.CapDrop", None, "CapDrop"),
        ("HostConfig.ReadonlyRootfs", False, "ReadonlyRootfs"),
        ("HostConfig.SecurityOpt", [], "security options"),
        ("HostConfig.SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"], "security"),
        ("HostConfig.SecurityOpt", ["no-new-privileges=true", "label=disable"], "security"),
        ("HostConfig.Sysctls", None, "Sysctls"),  # inherits the host's ip_forward=1
        ("HostConfig.Sysctls", {"net.ipv4.ip_forward": "1"}, "Sysctls"),
        (
            "HostConfig.Sysctls",
            {"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.route_localnet": "1"},
            "Sysctls",
        ),
        ("HostConfig.Binds", PROXY_GOOD["HostConfig"]["Binds"][:2], "mounts"),
        (
            "HostConfig.Binds",
            [*PROXY_GOOD["HostConfig"]["Binds"], "/var/run/docker.sock:/var/run/docker.sock"],
            "mounts",
        ),
        (
            "HostConfig.Binds",
            [*PROXY_GOOD["HostConfig"]["Binds"], "/srv/backtide/keys:/keys:ro"],
            "mounts",
        ),
        (
            "HostConfig.Binds",
            [f"{PROXY_CA}:/ca:z", *PROXY_GOOD["HostConfig"]["Binds"][1:]],  # writable CA
            "mounts",
        ),
        ("HostConfig.Mounts", [{"Type": "bind", "Source": "/srv/backtide"}], "Mounts"),
        ("HostConfig.Tmpfs", {"/tmp": "rw,size=64m"}, "Tmpfs"),
        ("HostConfig.Tmpfs", None, "Tmpfs"),
        # Without the cover, the image's VOLUME is a writable volume that outlives the proxy
        ("HostConfig.Tmpfs", {"/tmp": "rw,nosuid,nodev,noexec,size=64m"}, "Tmpfs"),
        (
            "Mounts",
            [{"Type": "volume", "Name": "abc", "Destination": "/home/mitmproxy/.mitmproxy"}],
            "volumes",
        ),
        ("HostConfig.Ulimits", None, "Ulimits"),
        ("HostConfig.Ulimits", [{"Name": "nofile", "Hard": 1048576, "Soft": 1048576}], "Ulimits"),
        ("HostConfig.Memory", 0, "Memory"),
        ("HostConfig.MemorySwap", -1, "MemorySwap"),
        ("HostConfig.PidsLimit", None, "PidsLimit"),
        ("HostConfig.NanoCpus", 0, "NanoCpus"),
        ("HostConfig.RestartPolicy", {"Name": "always"}, "RestartPolicy"),
        ("HostConfig.LogConfig", {"Type": "json-file", "Config": {}}, "LogConfig"),
        ("HostConfig.PortBindings", {"8080/tcp": [{"HostPort": "8080"}]}, "PortBindings"),
        ("HostConfig.PublishAllPorts", True, "PublishAllPorts"),
        ("HostConfig.PidMode", "host", "PidMode"),
        ("HostConfig.IpcMode", "host", "IpcMode"),
        ("HostConfig.UsernsMode", "host", "UsernsMode"),
        ("HostConfig.CgroupnsMode", "host", "CgroupnsMode"),
        ("HostConfig.Devices", [{"PathOnHost": "/dev/net/tun"}], "Devices"),
        ("HostConfig.Dns", ["192.0.2.53"], "Dns"),
        ("HostConfig.Runtime", "runsc-debug", "Runtime"),
        ("HostConfig.CgroupParent", "/system.slice", "CgroupParent"),
        ("HostConfig.MaskedPaths", [], "MaskedPaths"),
        ("HostConfig.ReadonlyPaths", None, "ReadonlyPaths"),
        ("Config.Healthcheck", {"Test": ["CMD", "sh", "-c", "id"]}, "Healthcheck"),
        ("HostConfig.NetworkMode", "host", "networks"),
        (
            "NetworkSettings.Networks",
            {"backtide-agente-net": {"Aliases": ["backtide-proxy"]}},
            "networks",
        ),
        (
            "NetworkSettings.Networks",
            {**PROXY_GOOD["NetworkSettings"]["Networks"], "bridge": {}},
            "networks",
        ),
        (
            "NetworkSettings.Networks",
            {
                "backtide-agente-net": {"Aliases": []},
                "backtide-salida-net": {"Aliases": ["backtide-proxy"]},
            },
            "alias",
        ),
    ],
)
def test_any_difference_of_the_proxy_is_reported(
    proxy_cfg: ProxyJailConfig, path: str, value: object, expected: str
) -> None:
    found = proxy_problems(proxy_cfg, changed(path, value, PROXY_GOOD))
    assert found, f"{path}={value!r} went unnoticed"
    assert any(expected in problem for problem in found), found


@pytest.mark.parametrize(
    "env",
    [
        PROXY_IMAGE_ENV + PROXY_ENV[1:],  # no PYTHONPATH
        [*PROXY_IMAGE_ENV, *(e for e in PROXY_ENV if not e.startswith("PYTHONUNBUFFERED"))],
        [*PROXY_IMAGE_ENV, *PROXY_ENV, "ANTHROPIC_API_KEY=sk-ant-real"],
        [*PROXY_IMAGE_ENV, *PROXY_ENV, "SSLKEYLOGFILE=/tmp/keys"],
        [*PROXY_IMAGE_ENV[1:], *PROXY_ENV],
    ],
)
def test_any_difference_in_the_proxy_environment_is_reported_by_name_only(
    proxy_cfg: ProxyJailConfig, env: list[str]
) -> None:
    found = proxy_problems(proxy_cfg, changed("Config.Env", env, PROXY_GOOD))
    assert len(found) == 1 and "environment differs" in found[0]
    assert "sk-ant" not in found[0]


def test_the_proxy_config_decides_the_expected_values(proxy_cfg: ProxyJailConfig) -> None:
    other = replace(proxy_cfg, uid=501, gid=20, memory="512m", nofile=1024, network="egress-2")
    found = " ".join(proxy_problems(other, PROXY_GOOD))
    for field in ("User", "Memory", "MemorySwap", "Ulimits", "networks"):
        assert field in found, field


def test_missing_proxy_sections_are_problems_not_crashes(proxy_cfg: ProxyJailConfig) -> None:
    assert proxy_problems(proxy_cfg, {}) != []
    assert proxy_problems(proxy_cfg, {"Config": None, "HostConfig": "x"}) != []
    info = changed("NetworkSettings.Networks", ["not", "a", "dict"], PROXY_GOOD)
    assert proxy_problems(proxy_cfg, info) != []
