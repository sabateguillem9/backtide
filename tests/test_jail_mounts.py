"""Unit tests for backtide/jail/mounts.py: would the agent's container see what it must not (T14a)?

GOOD is the part of ``docker container inspect`` that matters, as Docker 29.8.2 reported it in
the VM for a container made by docker_create_argv. The host is a fake (``FakeHost``): which
paths are symlinks to where, which are sockets or devices, and what is mounted. One test uses
real symlinks on disk.
"""

# ruff: noqa: S108 - the /tmp here is the tmpfs inside the agent's container

import copy
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest

from backtide.jail.config import AgentJailConfig, Protected, docker_create_argv
from backtide.jail.mounts import (
    HostView,
    agent_policy,
    exposure_problems,
    parse_mountinfo,
    planned_info,
)

TOKEN = "t" * 43
ROOT = Path("/srv/bt")
STATE = ROOT / "state"
VOLUME = ROOT / "volume"
WORKSPACE = VOLUME / "workspace"
CONFIG_DIR = STATE / "openclaw"
CA_DIR = STATE / "agent-ca"
AGENT_DIR = WORKSPACE / "agente"
PROTECTED = (
    Protected("backtide's state folder", STATE, inside_ok=True),
    Protected("the black box", STATE / "blackbox.db"),
    Protected("the black box's key", STATE / "blackbox.key"),
    Protected("the control socket", STATE / "control.sock"),
    Protected("the providers' real keys", STATE / "keys"),
    Protected("the proxy's channel", STATE / "proxy-channel"),
    Protected("the proxy's CA and its key", STATE / "proxy-ca"),
    Protected("the snapshot volume", VOLUME, inside_ok=True),
    Protected("the snapshots", VOLUME / "snapshots"),
)

GOOD: dict[str, Any] = {
    "Mounts": [
        {
            "Type": "bind",
            "Source": str(CONFIG_DIR),
            "Destination": "/config",
            "Mode": "ro,z",
            "RW": False,
            "Propagation": "rprivate",
        },
        {
            "Type": "bind",
            "Source": str(AGENT_DIR),
            "Destination": "/workspace",
            "Mode": "z",
            "RW": True,
            "Propagation": "rprivate",
        },
        {
            "Type": "bind",
            "Source": str(CA_DIR),
            "Destination": "/etc/backtide-ca",
            "Mode": "ro,z",
            "RW": False,
            "Propagation": "rprivate",
        },
    ],
    "HostConfig": {
        "Binds": [
            f"{AGENT_DIR}:/workspace:z",
            f"{CONFIG_DIR}:/config:ro,z",
            f"{CA_DIR}:/etc/backtide-ca:ro,z",
        ],
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "CgroupnsMode": "private",
        "DeviceCgroupRules": None,
        "DeviceRequests": None,
        "Devices": [],
        "IpcMode": "private",
        "Mounts": None,
        "NetworkMode": "backtide-agente-net",
        "PidMode": "",
        "Privileged": False,
        "SecurityOpt": ["no-new-privileges=true", "seccomp={}"],
        "Tmpfs": {
            "/tmp": "rw,nosuid,nodev,size=256m",
            "/sys/fs/btrfs": "ro,nosuid,nodev,noexec,size=4k,mode=0555",
            "/sys/devices/virtual/block": "ro,nosuid,nodev,noexec,size=4k,mode=0555",
        },
        "UTSMode": "",
        "UsernsMode": "",
        "VolumeDriver": "",
        "VolumesFrom": None,
        "MaskedPaths": ["/proc/kcore", "/sys/firmware"],
        "ReadonlyPaths": ["/proc/bus", "/proc/sys"],
    },
}


@dataclass
class FakeHost:
    """The host as mounts.py sees it: symlinks (path prefix -> target), kinds and mounts."""

    links: dict[str, str] = field(default_factory=dict)
    kinds: dict[str, str] = field(default_factory=dict)
    points: list[str] | None = field(default_factory=lambda: ["/", "/proc", "/srv/bt/volume"])
    home_dirs: list[str] = field(default_factory=lambda: ["/home/alice", "/root"])

    def realpath(self, path: str) -> str:
        for link, target in self.links.items():
            if path == link or path.startswith(link + "/"):
                return target + path[len(link) :]
        return path

    def view(self) -> HostView:
        return HostView(
            realpath=self.realpath,
            kind=lambda path: self.kinds.get(path, "dir"),
            mount_points=lambda: self.points,
            homes=lambda: self.home_dirs,
        )


@pytest.fixture
def cfg() -> AgentJailConfig:
    return AgentJailConfig(
        workspace=WORKSPACE,
        config_dir=CONFIG_DIR,
        ca_dir=CA_DIR,
        gateway_token=TOKEN,
        protected=PROTECTED,
    )


def check(cfg: AgentJailConfig, info: dict[str, Any], host: FakeHost | None = None) -> list[str]:
    return exposure_problems(info, agent_policy(cfg), (host or FakeHost()).view())


def with_mount(
    source: str, destination: str, *, kind: str = "bind", rw: bool = True, name: str = ""
) -> dict[str, Any]:
    """GOOD plus one mount, in the daemon's list and (for a bind) in HostConfig.Binds."""
    info = copy.deepcopy(GOOD)
    info["Mounts"].append(
        {"Type": kind, "Source": source, "Destination": destination, "RW": rw, "Name": name}
    )
    if kind == "bind":
        info["HostConfig"]["Binds"].append(f"{source}:{destination}{'' if rw else ':ro'}")
    return info


def changed(key: str, value: object) -> dict[str, Any]:
    info = copy.deepcopy(GOOD)
    info["HostConfig"][key] = value
    return info


def test_the_jail_itself_passes(cfg: AgentJailConfig) -> None:
    assert check(cfg, GOOD) == []


def test_the_planned_jail_passes(cfg: AgentJailConfig) -> None:
    info, unreadable = planned_info(docker_create_argv(cfg))
    assert unreadable == []
    assert check(cfg, info) == []


# --- every way of mounting something the agent must not see ------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # backtide's own state, whole or in parts
        (str(STATE), "holds backtide's state folder"),
        (str(ROOT), "holds backtide's state folder"),  # a parent of the state folder
        (str(STATE / "blackbox.db"), "holds the black box"),
        (str(STATE / "blackbox.key"), "holds the black box's key"),
        (str(STATE / "control.sock"), "holds the control socket"),
        (str(STATE / "keys"), "holds the providers' real keys"),
        (str(STATE / "keys" / "anthropic.key"), "is inside the providers' real keys"),
        (str(STATE / "proxy-channel"), "holds the proxy's channel"),
        (str(STATE / "proxy-ca"), "holds the proxy's CA"),
        (str(STATE / "telegram.toml"), "is inside backtide's state folder"),
        # the snapshots
        (str(VOLUME), "holds the snapshots"),
        (str(VOLUME / "snapshots"), "holds the snapshots"),
        (str(VOLUME / "snapshots" / "20261021T1200"), "is inside the snapshots"),
        # Docker's socket and the host's sensitive places
        ("/var/run/docker.sock", "Docker's socket"),
        ("/run/docker.sock", "Docker's socket"),
        ("/run/containerd/containerd.sock", "is inside the host's /run"),
        ("/", "would show the host's /"),
        ("/etc", "would show the host's /etc"),
        ("/etc/ssh", "is inside the host's /etc"),
        ("/root", "would show the host's /root"),
        ("/home", "would show the host's /home"),
        ("/home/alice", "would show the host's /home/alice"),
        ("/var", "would show the host's /var"),
        ("/var/run", "would show the host's /var/run"),
        ("/var/lib/docker/volumes/x/_data", "is inside the host's /var/lib/docker"),
        ("/proc", "would show the host's /proc"),
        ("/sys/kernel", "is inside the host's /sys"),
        ("/dev/sda", "is inside the host's /dev"),
        ("/usr", "would show the host's /usr"),
    ],
)
def test_an_extra_bind_is_refused_and_says_what_it_shows(
    cfg: AgentJailConfig, source: str, expected: str
) -> None:
    found = check(cfg, with_mount(source, "/mnt/x"))
    assert any("the agent may only see its workspace" in p for p in found), found
    assert any(expected in p for p in found), found


@pytest.mark.parametrize("rw", [True, False])
def test_a_bind_is_refused_read_only_too(cfg: AgentJailConfig, rw: bool) -> None:
    found = check(cfg, with_mount(str(STATE / "keys"), "/mnt/keys", rw=rw))
    assert any("holds the providers' real keys" in p for p in found)


def test_docker_s_socket_under_another_name(cfg: AgentJailConfig) -> None:
    host = FakeHost(kinds={"/srv/tools/engine": "socket"})
    found = check(cfg, with_mount("/srv/tools/engine", "/var/lib/engine"), host)
    assert any("is a Unix socket (Docker's, under another name?)" in p for p in found), found


def test_docker_s_socket_through_a_symlink_with_another_name(cfg: AgentJailConfig) -> None:
    host = FakeHost(links={"/srv/tools/engine": "/var/run/docker.sock"})
    found = check(cfg, with_mount("/srv/tools/engine", "/engine"), host)
    assert any("/srv/tools/engine (really /var/run/docker.sock)" in p for p in found), found
    assert any("is Docker's socket" in p for p in found)


def test_a_device_node(cfg: AgentJailConfig) -> None:
    host = FakeHost(kinds={"/srv/disk": "device"})
    found = check(cfg, with_mount("/srv/disk", "/disk"), host)
    assert any("is a device of the host" in p for p in found), found


def test_a_symlinked_path_that_resolves_into_the_state_folder(cfg: AgentJailConfig) -> None:
    host = FakeHost(links={"/opt/innocent": str(STATE)})
    found = check(cfg, with_mount("/opt/innocent/keys", "/data"), host)
    assert any(
        "/opt/innocent/keys (really /srv/bt/state/keys)" in p
        and "holds the providers' real keys" in p
        for p in found
    ), found


def test_the_agent_s_own_folder_resolving_into_the_state_folder(cfg: AgentJailConfig) -> None:
    """The expected bind, by name, but its folder is a symlink to backtide's state."""
    host = FakeHost(links={str(CONFIG_DIR): str(STATE)})
    found = check(cfg, GOOD, host)
    assert any("holds backtide's state folder" in p for p in found), found
    assert any("holds the black box" in p for p in found)


def test_real_symlinks_on_disk(tmp_path: Path) -> None:
    state = tmp_path / "state"
    (state / "keys").mkdir(parents=True)
    (tmp_path / "link").symlink_to(state)
    policy = replace(
        agent_policy(
            AgentJailConfig(
                workspace=tmp_path / "volume" / "workspace",
                config_dir=state / "openclaw",
                ca_dir=state / "agent-ca",
                gateway_token=TOKEN,
                protected=(
                    Protected("backtide's state folder", state, inside_ok=True),
                    Protected("the keys", state / "keys"),
                ),
            )
        ),
        binds=(),
    )
    info = {
        "HostConfig": {"CapDrop": ["ALL"], "MaskedPaths": ["x"], "ReadonlyPaths": ["x"]},
        "Mounts": [{"Type": "bind", "Source": str(tmp_path / "link" / "keys"), "RW": False}],
    }
    found = exposure_problems(info, policy, HostView(mount_points=lambda: [], homes=lambda: []))
    assert any("holds the keys" in p for p in found), found


def test_a_docker_volume_whose_folder_is_under_the_state_folder(cfg: AgentJailConfig) -> None:
    info = with_mount(str(STATE / "vol"), "/data", kind="volume", name="sneaky")
    found = check(cfg, info)
    assert any("a Docker volume sneaky is mounted at /data" in p for p in found), found
    assert any("is inside backtide's state folder" in p for p in found)


@pytest.mark.parametrize("spec", ["sneaky:/data", "/data"])
def test_named_and_anonymous_volumes(cfg: AgentJailConfig, spec: str) -> None:
    info = copy.deepcopy(GOOD)
    info["HostConfig"]["Binds"].append(spec)
    found = check(cfg, info)
    assert any("Docker volume" in p and "/data" in p for p in found), found


def test_another_kind_of_mount(cfg: AgentJailConfig) -> None:
    found = check(cfg, with_mount("", "/x", kind="cluster"))
    assert any("a cluster is mounted at /x" in p for p in found), found


def test_a_tmpfs_is_fine_anywhere_even_over_the_workspace(cfg: AgentJailConfig) -> None:
    info = changed("Tmpfs", {**GOOD["HostConfig"]["Tmpfs"], "/workspace": "rw,size=1m"})
    info["Mounts"].append({"Type": "tmpfs", "Source": "", "Destination": "/proc/x", "RW": True})
    assert check(cfg, info) == []


def test_a_read_only_folder_made_writable(cfg: AgentJailConfig) -> None:
    info = copy.deepcopy(GOOD)
    info["Mounts"][0]["RW"] = True  # /config
    assert check(cfg, info) == ["/config is writable: the agent must only read it"]


def test_the_workspace_mounted_somewhere_else(cfg: AgentJailConfig) -> None:
    found = check(cfg, with_mount(str(AGENT_DIR), "/elsewhere"))
    assert any("is mounted at /elsewhere" in p for p in found), found


def test_a_bind_over_the_kernel_s_views(cfg: AgentJailConfig) -> None:
    found = check(cfg, with_mount("/srv/fake-proc", "/proc"))
    assert any("over the kernel's /proc or /sys" in p for p in found), found
    found = check(cfg, with_mount("/srv/x", "/sys/kernel/x"))
    assert any("over the kernel's /proc or /sys" in p for p in found), found


def test_a_bind_over_the_root(cfg: AgentJailConfig) -> None:
    found = check(cfg, with_mount("/srv/root", "/"))
    assert any("over the container's root" in p for p in found), found


def test_a_host_mount_inside_a_mounted_folder(cfg: AgentJailConfig) -> None:
    host = FakeHost(points=["/", str(VOLUME), f"{AGENT_DIR}/work/host-disk"])
    found = check(cfg, GOOD, host)
    assert found == [
        f"the host has mounts inside {AGENT_DIR} ({AGENT_DIR}/work/host-disk): Docker would "
        "carry them to /workspace"
    ]


def test_an_unreadable_mount_table_fails_closed(cfg: AgentJailConfig) -> None:
    found = check(cfg, GOOD, FakeHost(points=None))
    assert found == ["the host's mount table cannot be read: nothing mounted is checked"]


def test_the_same_problem_is_said_once(cfg: AgentJailConfig) -> None:
    found = check(cfg, with_mount("/var/run/docker.sock", "/sock"))
    assert len(found) == len(set(found))


def test_a_mount_asked_for_through_hostconfig_mounts(cfg: AgentJailConfig) -> None:
    mount = {"Type": "bind", "Source": str(STATE), "Target": "/s", "ReadOnly": True}
    found = check(cfg, changed("Mounts", [mount]))
    assert any("holds backtide's state folder" in p for p in found), found


# --- privileges and namespaces ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("Privileged", True, "it is privileged"),
        ("CapAdd", ["SYS_ADMIN"], "it adds capabilities"),
        ("CapDrop", None, "it keeps Docker's default capabilities"),
        ("CapDrop", ["NET_RAW"], "it keeps Docker's default capabilities"),
        ("PidMode", "host", "process namespace of the host"),
        ("PidMode", "container:backtide-sensor", "process namespace of backtide-sensor"),
        ("NetworkMode", "host", "network namespace of the host"),
        ("NetworkMode", "container:backtide-proxy", "network namespace of backtide-proxy"),
        ("IpcMode", "host", "IPC namespace of the host"),
        ("UTSMode", "host", "hostname namespace of the host"),
        ("UsernsMode", "host", "user namespace of the host"),
        ("CgroupnsMode", "host", "cgroup namespace of the host"),
        ("Devices", [{"PathOnHost": "/dev/sda"}], "devices of the host"),
        ("DeviceCgroupRules", ["b *:* rwm"], "devices of the host"),
        ("DeviceRequests", [{"Count": -1}], "devices of the host"),
        ("VolumesFrom", ["backtide-proxy"], "volumes of other containers"),
        ("VolumeDriver", "evil", "volume driver"),
        ("SecurityOpt", ["seccomp=unconfined"], "--security-opt seccomp=unconfined"),
        ("SecurityOpt", ["apparmor=unconfined"], "--security-opt apparmor=unconfined"),
        ("SecurityOpt", ["label=disable"], "--security-opt label=disable"),
        ("SecurityOpt", ["label:disable"], "--security-opt label:disable"),
        ("SecurityOpt", ["systempaths=unconfined"], "systempaths=unconfined"),
        ("SecurityOpt", "seccomp=unconfined", "security options cannot be read"),
        ("MaskedPaths", [], "/proc and /sys would not be masked"),
        ("ReadonlyPaths", None, "/proc and /sys would not be masked"),
    ],
)
def test_privileges_and_namespaces(
    cfg: AgentJailConfig, key: str, value: object, expected: str
) -> None:
    found = check(cfg, changed(key, value))
    assert any(expected in p for p in found), found


# --- what cannot be read is not run ---------------------------------------------------------


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        ({}, "no HostConfig"),
        ({"HostConfig": "x", "Mounts": []}, "no HostConfig"),
        ({**GOOD, "Mounts": None}, "no Mounts list"),
        ({**GOOD, "Mounts": [*GOOD["Mounts"], "junk"]}, "cannot be read"),
        ({**GOOD, "HostConfig": {**GOOD["HostConfig"], "Binds": [7]}}, "cannot be read"),
        ({**GOOD, "HostConfig": {**GOOD["HostConfig"], "Binds": ["a:b:c:d"]}}, "cannot be read"),
        ({**GOOD, "HostConfig": {**GOOD["HostConfig"], "Mounts": ["x"]}}, "cannot be read"),
        ({**GOOD, "HostConfig": {**GOOD["HostConfig"], "Tmpfs": ["/x"]}}, "cannot be read"),
    ],
)
def test_unreadable_inspect_data_fails_closed(
    cfg: AgentJailConfig, info: dict[str, Any], expected: str
) -> None:
    found = check(cfg, info)
    assert any(expected in p for p in found), found


# --- the planned container ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (["--volume", "/var/run/docker.sock:/var/run/docker.sock"], "Docker's socket"),
        (["-v", f"{STATE}:/state:ro"], "holds backtide's state folder"),
        (["--mount", f"type=bind,source={STATE / 'keys'},target=/k,readonly"], "real keys"),
        (["--mount", "type=volume,source=data,target=/data"], "Docker volume data"),
        (["--privileged"], "it is privileged"),
        (["--privileged"], "/proc and /sys would not be masked"),
        (["--cap-add", "SYS_ADMIN"], "it adds capabilities"),
        (["--pid=host"], "process namespace of the host"),
        (["--network", "host"], "network namespace of the host"),
        (["--userns", "host"], "user namespace of the host"),
        (["--device", "/dev/sda"], "devices of the host"),
        (["--volumes-from", "backtide-proxy"], "volumes of other containers"),
        (["--security-opt", "systempaths=unconfined"], "/proc and /sys would not be masked"),
        (["--publish", "80:80"], "unknown docker create option '--publish'"),
    ],
)
def test_the_planned_container_with_one_more_option(
    cfg: AgentJailConfig, extra: list[str], expected: str
) -> None:
    argv = docker_create_argv(cfg)
    argv[1:1] = extra
    info, unreadable = planned_info(argv)
    found = unreadable + check(cfg, info)
    assert any(expected in p for p in found), found


def test_an_option_without_its_value() -> None:
    assert planned_info(["create", "--volume"])[1] == ["--volume has no value"]


def test_the_command_after_the_image_is_not_read_as_options(cfg: AgentJailConfig) -> None:
    argv = [*docker_create_argv(cfg), "--privileged", "-v", "/:/host"]
    info, unreadable = planned_info(argv)
    assert unreadable == []
    assert check(cfg, info) == []


def test_only_docker_create_is_planned() -> None:
    assert planned_info(["run"])[1] == []
    assert planned_info(["exec", "x"])[1] == ["not a docker create command: ['exec']"]


def test_parse_mountinfo_undoes_the_octal_escapes() -> None:
    text = (
        "22 1 0:21 / / rw,relatime - btrfs /dev/vda rw\n"
        "88 22 0:44 / /srv/my\\040disk rw - tmpfs tmpfs rw\n"
        "short line\n"
    )
    assert parse_mountinfo(text) == ["/", "/srv/my disk"]


# --- the jail's own config refuses it by name -----------------------------------------------


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"config_dir": STATE, "ca_dir": ROOT / "ca"}, "would show it backtide's state folder"),
        ({"config_dir": ROOT / "x"}, None),  # nothing protected there: fine
        ({"ca_dir": STATE / "proxy-ca"}, "would show it the proxy's CA"),
        ({"config_dir": STATE / "keys" / "openclaw"}, "lies inside the providers' real keys"),
        ({"workspace": VOLUME / "snapshots" / "w"}, "lies inside the snapshots"),
        ({"workspace": ROOT / "elsewhere" / "workspace"}, None),
    ],
)
def test_the_jail_config_refuses_a_folder_that_shows_a_protected_path(
    changes: dict[str, Path], expected: str | None
) -> None:
    options: dict[str, Any] = {
        "workspace": WORKSPACE,
        "config_dir": CONFIG_DIR,
        "ca_dir": CA_DIR,
        "gateway_token": TOKEN,
        "protected": PROTECTED,
        **changes,
    }
    if expected is None:
        AgentJailConfig(**options)
        return
    with pytest.raises(ValueError, match=expected):
        AgentJailConfig(**options)


def test_protected_must_be_protected_paths() -> None:
    with pytest.raises(ValueError, match="tuple of Protected"):
        AgentJailConfig(
            workspace=WORKSPACE,
            config_dir=CONFIG_DIR,
            ca_dir=CA_DIR,
            gateway_token=TOKEN,
            protected=[STATE],  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="absolute"):
        Protected("x", Path("relative"))
