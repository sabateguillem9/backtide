"""T03a in the VM: the real OpenClaw in its jail (docs/13-diseno-t03-jaula.md, "Tests").

Everything runs against this module's ``running_agent`` (conftest.py): one container of the
pinned image, started once and removed at the end. Probes run only inside that container and
only towards addresses that cannot cause harm: TEST-NET-1 (192.0.2.1) and 1.1.1.1 just to show
there is no route, and the VM's own addresses to show the host is unreachable. No data is
sent anywhere.

The rewind test stops and starts the agent, so it is the last test of the module.
"""

# ruff: noqa: S108 - every /tmp and /var/tmp path here is inside the agent's container

import ipaddress
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from vigia.jail import AgentJail, JailError, docker
from vigia.jail.config import (
    AGENT_DIR,
    AGENT_SUBDIRS,
    CONTAINER_CONFIG_DIR,
    CONTAINER_HOME,
    CONTAINER_WORKSPACE,
    HEALTH_URL,
    IMAGE,
    READY_LOG_LINE,
    SECCOMP_PROFILE,
    TOKEN_ENV,
    docker_create_argv,
    token_env,
)
from vigia.jail.seccomp import BLOCKED_ERRNO
from vigia.jail.verify import container_problems
from vigia.snapshots import Reason, btrfs

pytestmark = pytest.mark.integration

PROBE_PORT = 22  # sshd listens on every address of the VM: a connection would prove a route
CONNECT_TIMEOUT = 3
DOCKER_ETC_FILES = {"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}  # Docker's, read-only
# What every Docker container has: the read-only image, the kernel's views and its own /dev.
DOCKER_STANDARD_MOUNTS = {"/", "/proc", "/dev", "/dev/pts", "/dev/mqueue", "/dev/shm", "/sys"}
DOCKER_STANDARD_MOUNTS |= {"/sys/fs/cgroup"} | DOCKER_ETC_FILES
# Writable mounts that belong to the container itself (nothing of the host's disk in them).
CONTAINER_WRITABLE = {"/proc", "/dev", "/dev/pts", "/dev/mqueue", "/dev/shm"}
SECRET_WORDS = ("KEY", "SECRET", "PASSWORD")
NO_CAPABILITIES = "0" * 16
GIB = 1024**3
# Docker's default profile, without the btrfs block: what an older Vigía's container has.
DOCKER_DEFAULT_PROFILE = SECCOMP_PROFILE.with_name("docker-default.json")

# Runs inside the container (python3 of the image). Prints one JSON object.
SUBVOLUME_PROBE = r"""
import array, errno, fcntl, json, os, struct, subprocess, sys, termios

base = sys.argv[1]
SUBVOL_CREATE = 0x5000940E  # _IOW(0x94, 14, struct btrfs_ioctl_vol_args), 4096 bytes

def subvolume(name, request):
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        args = bytearray(struct.pack("q4088s", 0, name.encode()))
        fcntl.ioctl(fd, request, args, True)
        return 0
    except OSError as e:
        return e.errno
    finally:
        os.close(fd)

def copy(mode, src, dst):
    done = subprocess.run(["cp", "--reflink=" + mode, src, dst], capture_output=True, text=True)
    same = os.path.exists(dst) and open(dst, "rb").read() == open(src, "rb").read()
    return {"rc": done.returncode, "same": same, "stderr": done.stderr.strip()}

src = os.path.join(base, "reflink-src.bin")
with open(src, "wb") as f:
    f.write(os.urandom(256 * 1024))
r, w = os.pipe()
os.write(w, b"abc")
pending = array.array("i", [0])
fcntl.ioctl(r, termios.FIONREAD, pending, True)
lsattr = subprocess.run(["lsattr", src], capture_output=True, text=True)
print(json.dumps({
    "subvol_create": subvolume("nested-a", SUBVOL_CREATE),
    "subvol_create_high_bits": subvolume("nested-b", SUBVOL_CREATE | (0xFFFFFFFF << 32)),
    "nested_exists": [os.path.lexists(os.path.join(base, n)) for n in ("nested-a", "nested-b")],
    "cp_always": copy("always", src, os.path.join(base, "reflink-always.bin")),
    "cp_auto": copy("auto", src, os.path.join(base, "reflink-auto.bin")),
    "fionread": pending[0],
    "lsattr_rc": lsattr.returncode,
}))
"""

# Runs inside the container: one TCP connection attempt per address, printed as JSON.
CONNECT_PROBE = r"""
import json, socket, sys

port, timeout = int(sys.argv[1]), float(sys.argv[2])
results = {}
for address in sys.argv[3:]:
    try:
        socket.create_connection((address, port), timeout=timeout).close()
        results[address] = "connected"
    except OSError as e:
        results[address] = type(e).__name__ + ": " + str(e)
print(json.dumps(results))
"""


def sh(agent, script: str) -> subprocess.CompletedProcess[str]:
    return agent.exec(["sh", "-c", script])


# OpenClaw starts


def test_gateway_is_ready_and_healthy(running_agent) -> None:
    health = running_agent.exec(["curl", "--fail", "--silent", HEALTH_URL], check=True)
    assert json.loads(health.stdout)["ok"] is True
    logs = docker.run(["logs", running_agent.name])
    assert READY_LOG_LINE in logs.stdout + logs.stderr


def test_no_errors_without_network(running_agent) -> None:
    log = sh(running_agent, "cat /tmp/openclaw/*.log")
    assert log.returncode == 0, log.stderr
    errors = [entry for entry in _json_lines(log.stdout) if _level(entry) in {"ERROR", "FATAL"}]
    assert errors == []


def test_config_validates_and_is_read_only(running_agent) -> None:
    validate = running_agent.exec(["node", "openclaw.mjs", "config", "validate"])
    assert validate.returncode == 0, validate.stdout + validate.stderr
    overwrite = sh(running_agent, f"echo '{{}}' > {CONTAINER_CONFIG_DIR}/openclaw.json")
    assert overwrite.returncode != 0
    assert "Read-only file system" in overwrite.stderr


# What the container is


def test_container_settings(running_agent) -> None:
    info = _inspect_container(running_agent.name)
    host, config = info["HostConfig"], info["Config"]
    jail = running_agent.jail.config
    assert config["User"] == f"{jail.uid}:{jail.gid}"
    assert host["ReadonlyRootfs"] is True
    assert host["Privileged"] is False
    assert host["CapDrop"] == ["ALL"]
    assert not host["CapAdd"]
    assert "no-new-privileges=true" in host["SecurityOpt"]
    seccomp = [opt for opt in host["SecurityOpt"] if opt.startswith("seccomp=")]
    assert len(seccomp) == 1
    applied = json.loads(seccomp[0].removeprefix("seccomp="))
    assert applied == json.loads(jail.seccomp_profile.read_text())  # deploy/seccomp/agent.json
    assert host["RestartPolicy"]["Name"] == "no"
    assert not host["PortBindings"] and host["PublishAllPorts"] is False
    assert not host["ExtraHosts"]
    assert not host.get("Devices")
    assert sorted(host["Binds"]) == sorted(
        [
            f"{jail.agent_dir}:{CONTAINER_WORKSPACE}:z",
            f"{jail.config_dir}:{CONTAINER_CONFIG_DIR}:ro,z",
        ]
    )
    assert list(info["NetworkSettings"]["Networks"]) == [jail.network]
    # The check start() makes before every start accepts what Docker really reports.
    image_env = json.loads(
        docker.run(["image", "inspect", "--format", "{{json .Config.Env}}", jail.image]).stdout
    )
    profile = json.loads(jail.seccomp_profile.read_text())
    assert container_problems(jail, info, seccomp_profile=profile, image_env=image_env) == []


def test_resource_limits_are_applied(running_agent) -> None:
    """What the daemon applied, not just the argv: the fixture asks for 2 GiB, 2 CPUs and the
    default 512 processes, without swap on top, and bounded logs."""
    info = _inspect_container(running_agent.name)
    host = info["HostConfig"]
    assert host["Memory"] == host["MemorySwap"] == 2 * GIB
    assert host["NanoCpus"] == 2_000_000_000
    assert host["PidsLimit"] == 512
    assert info["Config"]["StopTimeout"] == 30
    assert host["LogConfig"] == {"Type": "local", "Config": {"max-size": "10m", "max-file": "3"}}
    cgroup = {
        name: running_agent.exec(["cat", f"/sys/fs/cgroup/{name}"], check=True).stdout.strip()
        for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")
    }
    assert cgroup == {
        "memory.max": str(2 * GIB),
        "memory.swap.max": "0",
        "pids.max": "512",
        "cpu.max": "200000 100000",
    }


def test_the_agent_is_confined_by_selinux(running_agent) -> None:
    """dockerd runs with selinux-enabled (lima/vigia-dev.yaml), so the agent is container_t, a
    second wall behind the namespaces, and not spc_t (unconfined) as with SELinux off. The two
    mounts are labelled container_file_t without categories (:z, shared), so a container
    created again, with other categories, can still use the workspace and its snapshots."""
    for path in ("/proc/self/attr/current", "/proc/1/attr/current"):
        label = running_agent.exec(["cat", path], check=True).stdout.rstrip("\x00\n")
        assert label.split(":")[2] == "container_t", (path, label)
    for host_path in (running_agent.workspace, running_agent.jail.config.config_file):
        context = os.getxattr(host_path, "security.selinux").rstrip(b"\x00").decode()
        assert context.split(":")[2:] == ["container_file_t", "s0"], (host_path, context)


def test_network_is_internal_and_the_host_has_no_address_on_it(running_agent) -> None:
    network = running_agent.jail.config.network
    info = json.loads(docker.run(["network", "inspect", "--format", "{{json .}}", network]).stdout)
    assert info["Internal"] is True
    assert info["Options"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
    assert all("Gateway" not in pool for pool in info["IPAM"]["Config"])
    attached = [container["Name"] for container in info["Containers"].values()]
    assert attached == [running_agent.name]


# Isolation, seen from inside


def test_agent_is_not_root_and_has_no_privileges(running_agent) -> None:
    status = _proc_status(running_agent.exec(["cat", "/proc/self/status"], check=True).stdout)
    assert "0" not in status["Uid"].split()
    assert "0" not in status["Gid"].split()
    for capabilities in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert status[capabilities] == NO_CAPABILITIES, capabilities
    assert status["NoNewPrivs"] == "1"
    assert status["Seccomp"] == "2"  # a filter is installed


def test_no_docker_socket(running_agent) -> None:
    for path in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd"):
        assert running_agent.exec(["test", "-e", path]).returncode == 1, path
    sockets = sh(
        running_agent,
        r"find / \( -path /proc -o -path /sys \) -prune -o -type s -print 2>/dev/null",
    ).stdout.split()
    assert [s for s in sockets if "docker" in s or "containerd" in s] == []


def test_only_the_workspace_the_config_tmp_and_the_sys_masks_are_added(running_agent) -> None:
    """Besides Docker's standard mounts, only /workspace, /config (read-only), /tmp and the two
    empty read-only tmpfs that hide /sys/fs/btrfs and /sys/devices/virtual/block."""
    jail = running_agent.jail.config
    mounts = _mountinfo(running_agent.exec(["cat", "/proc/self/mountinfo"], check=True).stdout)
    masks = [m for m in mounts if _is_docker_mask(m["point"])]
    others = [m for m in mounts if not _is_docker_mask(m["point"])]
    sys_masks = {"/sys/fs/btrfs", "/sys/devices/virtual/block"}  # spelled out: not from config
    ours = {str(CONTAINER_WORKSPACE), str(CONTAINER_CONFIG_DIR), "/tmp", *sys_masks}
    assert sorted(m["point"] for m in others) == sorted(DOCKER_STANDARD_MOUNTS | ours)
    # Docker hides parts of /proc and /sys: read-only, or its own /dev/null bound over them.
    assert [m for m in masks if m["options"][0] != "ro" and m["root"] != "/null"] == []
    by_point = {m["point"]: m for m in others}
    for read_only in ("/", "/sys", str(CONTAINER_CONFIG_DIR), *DOCKER_ETC_FILES, *sys_masks):
        assert by_point[read_only]["options"][0] == "ro", read_only
    writable = {m["point"] for m in others if m["options"][0] == "rw"}
    assert writable == CONTAINER_WRITABLE | {str(CONTAINER_WORKSPACE), "/tmp"}
    assert by_point[str(CONTAINER_WORKSPACE)]["root"].endswith(f"/workspace/{AGENT_DIR}")
    assert by_point[str(CONTAINER_CONFIG_DIR)]["root"].endswith(f"/{jail.config_dir.name}")
    tmp = by_point["/tmp"]
    assert tmp["fs"] == "tmpfs" and tmp["root"] == "/"  # a fresh tmpfs, not a host folder
    assert {"rw", "nosuid", "nodev"} <= set(tmp["options"])
    for mask in sys_masks:  # also fresh tmpfs: no host path shows in the mount table
        assert by_point[mask]["fs"] == "tmpfs" and by_point[mask]["root"] == "/", mask
        assert {"ro", "nosuid", "nodev", "noexec"} <= set(by_point[mask]["options"]), mask


# What the agent could read about its own volume in /sys. Prints four sections separated by
# "---": the entries of /sys/fs/btrfs and of /sys/devices/virtual/block, then the host path of
# every loop device's image reached through /sys/block, then through find.
SYSFS_PROBE = r"""
ls -A /sys/fs/btrfs 2>&1
echo ---
ls -A /sys/devices/virtual/block 2>&1
echo ---
cat /sys/block/loop*/loop/backing_file 2>/dev/null
echo ---
find -L /sys/block /sys/class/block /sys/dev/block -maxdepth 4 -name backing_file \
  -exec cat {} + 2>/dev/null
exit 0
"""


def _sysfs_probe(output: str) -> list[list[str]]:
    sections = output.split("---\n")
    assert len(sections) == 4, output
    return [section.split() for section in sections]


def test_the_agent_cannot_see_the_btrfs_sysfs_or_where_the_volume_image_lives(
    running_agent,
) -> None:
    """/sys/fs/btrfs (the volume's usage, its qgroups, when snapshots appear) and
    ``backing_file`` (the host path of the image) are hidden; the same probe in a container
    without the masks sees both, so this test goes red if a mask is ever removed."""
    host_images = sorted(
        {
            text
            for path in Path("/sys/block").glob("loop*/loop/backing_file")
            if (text := path.read_text().strip()).endswith("/volume.img")
        }
    )
    fsid = btrfs.fsid(running_agent.store.root)
    # The precondition: the VM shows both things to a container that has no masks.
    assert host_images and (Path("/sys/fs/btrfs") / fsid).is_dir()

    image = running_agent.jail.config.image
    control = docker.run(
        ["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL"]
        + ["--entrypoint", "sh", image, "-c", SYSFS_PROBE],
        timeout=120,
    )
    seen_btrfs, seen_block, seen_by_block, seen_by_find = _sysfs_probe(control.stdout)
    assert fsid in seen_btrfs
    assert any(name.startswith("loop") for name in seen_block)
    assert set(host_images) <= set(seen_by_block) and set(host_images) <= set(seen_by_find)

    hidden = running_agent.exec(["sh", "-c", SYSFS_PROBE], check=True)
    assert _sysfs_probe(hidden.stdout) == [[], [], [], []]
    for path in ("/sys/fs/btrfs", "/sys/devices/virtual/block"):
        assert running_agent.exec(["touch", f"{path}/probe"]).returncode != 0, path
    assert "Read-only file system" in running_agent.exec(["touch", "/sys/fs/btrfs/x"]).stderr
    for name in sorted({Path(p).name for p in Path("/sys/block").glob("loop*")}):
        reached = [
            f"/sys/block/{name}/loop/backing_file",
            f"/sys/class/block/{name}/loop/backing_file",
            f"/sys/devices/virtual/block/{name}/loop/backing_file",
        ]
        for path in reached:
            assert running_agent.exec(["test", "-e", path]).returncode == 1, path


def test_vigia_files_are_invisible(running_agent) -> None:
    """Snapshots and Vigía's own data (the black box lives next to them) never show up."""
    marker = running_agent.store.root / f"vigia-blackbox-stand-in-{uuid4().hex}"
    marker.write_text("only Vigía may see this\n")
    try:
        snap = running_agent.store.take(Reason.MANUAL)
        found = sh(
            running_agent,
            r"find / \( -path /proc -o -path /sys \) -prune -o "
            rf"\( -name {marker.name} -o -name {snap.id} \) -print 2>/dev/null",
        )
        assert found.stdout.split() == []
        listing = running_agent.exec(["ls", "-A", str(CONTAINER_WORKSPACE)], check=True)
        assert set(listing.stdout.split()) == set(AGENT_SUBDIRS)
    finally:
        marker.unlink()


def test_no_route_to_the_internet(running_agent) -> None:
    for url in ("https://1.1.1.1", "http://192.0.2.1"):
        result = running_agent.exec(
            ["curl", "--silent", "--show-error", "--max-time", "5", url], timeout=30
        )
        assert result.returncode != 0, url
    routes = running_agent.exec(["cat", "/proc/net/route"], check=True).stdout.splitlines()[1:]
    assert [r for r in routes if r.split()[1] == "00000000"] == []  # no default route
    inet6 = running_agent.exec(["cat", "/proc/net/if_inet6"], check=True).stdout.splitlines()
    assert [line for line in inet6 if not line.endswith(" lo")] == []  # IPv6 only on lo


def test_names_do_not_resolve(running_agent) -> None:
    for name in ("example.com", "github.com"):
        result = running_agent.exec(["getent", "hosts", name], timeout=30)
        assert result.returncode != 0 and result.stdout == "", name


def test_host_is_unreachable(running_agent) -> None:
    """No connection to any address of the VM, nor to the first address of the agent's
    subnet, where Docker puts the host's side of a bridge that is not isolated. With an
    isolated gateway Docker hands that first address to the container itself, so the agent's
    own addresses are left out. A refusal counts as reaching: the address answered."""
    jail = running_agent.jail.config
    candidates = _host_ipv4_addresses() | _network_first_hosts(jail)
    targets = sorted(candidates - _container_ipv4_addresses(running_agent.name, jail.network))
    assert targets, "nothing left to probe"
    result = running_agent.exec(
        ["python3", "-c", CONNECT_PROBE, str(PROBE_PORT), str(CONNECT_TIMEOUT), *targets],
        check=True,
        timeout=60,
    )
    outcomes = json.loads(result.stdout)
    assert set(outcomes) == set(targets)
    reached = {
        address: outcome
        for address, outcome in outcomes.items()
        if outcome == "connected" or outcome.startswith("ConnectionRefusedError")
    }
    assert reached == {}


def test_root_filesystem_is_read_only(running_agent) -> None:
    # /var/tmp is world-writable in the image: only the read-only mount stops the write.
    for path in ("/var/tmp/vigia-probe", "/etc/vigia-probe", "/app/vigia-probe"):
        result = running_agent.exec(["touch", path])
        assert result.returncode != 0, path
    assert "Read-only file system" in running_agent.exec(["touch", "/var/tmp/x"]).stderr
    for path in (f"{CONTAINER_WORKSPACE}/work/vigia-probe", "/tmp/vigia-probe"):
        running_agent.exec(["touch", path], check=True)
        running_agent.exec(["rm", path], check=True)


def test_environment_has_no_keys(running_agent) -> None:
    entries = running_agent.exec(["env", "-0"], check=True).stdout.split("\0")
    names = [entry.split("=", 1)[0] for entry in entries if entry]
    assert [n for n in names if any(word in n.upper() for word in SECRET_WORDS)] == []
    assert TOKEN_ENV in names  # accepted in docs/13: it only lets the agent drive itself


# No nested subvolumes


def test_cannot_create_subvolumes_but_copies_fall_back(running_agent) -> None:
    """``cp --reflink=always`` fails, and ``cp --reflink=auto`` ends well as a plain copy:
    FICLONE is blocked (0x94) and so is copy_file_range, which answers EXDEV (T03b-2;
    test_quota_assumptions.py checks that no copier shares blocks)."""
    work = f"{CONTAINER_WORKSPACE}/work/subvolume-probe-{uuid4().hex[:8]}"
    running_agent.exec(["mkdir", work], check=True)
    try:
        result = running_agent.exec(["python3", "-c", SUBVOLUME_PROBE, work], check=True)
        probe = json.loads(result.stdout)
        assert probe["subvol_create"] == BLOCKED_ERRNO
        assert probe["subvol_create_high_bits"] == BLOCKED_ERRNO
        assert probe["nested_exists"] == [False, False]
        assert probe["cp_always"]["rc"] != 0 and not probe["cp_always"]["same"]
        assert probe["cp_auto"] == {"rc": 0, "same": True, "stderr": ""}
        assert probe["fionread"] == 3  # other ioctls still work
        assert probe["lsattr_rc"] == 0
    finally:
        running_agent.exec(["rm", "-rf", work], check=True)
    host_side = running_agent.workspace / "work"
    assert all(entry.stat().st_ino != 256 for entry in host_side.iterdir())  # no subvolume


# What Vigía reads from the container is the agent's, never trusted


def test_readiness_ignores_a_curlrc_planted_by_the_agent(running_agent) -> None:
    """HOME is the agent's /workspace/home, and curl reads ~/.curlrc. One there would hand
    Vigía's own /healthz probe a URL of the agent's choosing first (``file:///dev/zero`` made
    it print 1 GB/s). This one is harmless: the hostname printed before the JSON would just
    keep the probe failing, so wait_ready would time out."""
    curlrc = f"{CONTAINER_HOME}/.curlrc"
    plant = f"printf 'url = \"file:///etc/hostname\"\\nnext\\n' > {curlrc}"
    running_agent.exec(["sh", "-c", plant], check=True)
    try:
        hijacked = running_agent.exec(["curl", "--fail", "--silent", "--max-time", "5", HEALTH_URL])
        assert hijacked.stdout.startswith("agente\n")  # a plain curl does read it
        running_agent.jail.wait_ready(timeout=20)
    finally:
        running_agent.exec(["rm", "-f", curlrc], check=True)


@pytest.mark.parametrize("kind", ["an older jail", "a debug container"])
def test_start_refuses_a_container_that_is_not_the_jail(
    running_agent, agent_leftovers, kind: str
) -> None:
    """A container under the jail's name made by an older Vigía (here: without the btrfs
    block in its seccomp profile, which Docker read when it was created) or by hand (a plain
    ``docker create``) is never started as if it were the jail."""
    name, _ = agent_leftovers.names(os.getpid())
    jail = replace(running_agent.jail.config, name=name)
    if kind == "an older jail":
        older = replace(jail, seccomp_profile=DOCKER_DEFAULT_PROFILE)
        docker.run(docker_create_argv(older), env=token_env(older))
        expected = "seccomp profile is not the current one"
    else:
        docker.run(["create", "--name", name, "--network", jail.network, jail.image])
        expected = "CapDrop"
    try:
        with pytest.raises(JailError, match=f"not the jail.*{expected}"):
            AgentJail(jail).start()
        state = _inspect_container(name)["State"]
        assert state["Running"] is False and state["StartedAt"].startswith("0001-")
    finally:
        docker.run(["rm", "--force", name])


def test_leftovers_of_a_killed_run_are_removed(running_agent, agent_leftovers) -> None:
    """Test agents and networks whose pytest is gone (a run killed with kill -9) are removed;
    those of a live run, this one included, stay."""
    gone = subprocess.Popen([sys.executable, "-c", ""])
    gone.wait()
    stale, live = agent_leftovers.names(gone.pid), agent_leftovers.names(os.getpid())
    try:
        for container, network in (stale, live):
            docker.run(["network", "create", "--internal", network])
            docker.run(["create", "--name", container, "--network", network, IMAGE])
        removed = agent_leftovers.remove_stale()
        assert set(stale) <= set(removed)
        assert set(removed).isdisjoint({*live, running_agent.name})
        names = docker.run(["ps", "--all", "--format", "{{.Names}}"]).stdout.split()
        networks = docker.run(["network", "ls", "--format", "{{.Name}}"]).stdout.split()
        assert stale[0] not in names and stale[1] not in networks
        assert live[0] in names and live[1] in networks
        assert running_agent.name in names
    finally:
        docker.run(["rm", "--force", stale[0], live[0]])
        for network in (stale[1], live[1]):
            docker.run(["network", "rm", network], check=False)


# Rewind with the real agent (last: it restarts the container)


def test_rewind_with_the_real_agent(running_agent) -> None:
    note = f"{CONTAINER_WORKSPACE}/work/rewind-note.txt"
    host_note = running_agent.workspace / "work" / "rewind-note.txt"
    running_agent.exec(["sh", "-c", f"echo before > {note}"], check=True)
    snap = running_agent.store.take(Reason.MANUAL)
    snapshot_state = running_agent.store.snapshots_dir / snap.id / AGENT_DIR / "state"
    assert any(snapshot_state.iterdir())  # OpenClaw's sessions and memory are in the snapshot
    running_agent.exec(["rm", note], check=True)
    assert not host_note.exists()
    started_before = _inspect_container(running_agent.name)["State"]["StartedAt"]
    workspace_before = running_agent.store.workspace_id()

    result = running_agent.store.restore(snap.id, quiesce=running_agent.quiesce)

    assert result.target == snap
    assert running_agent.store.workspace_id() != workspace_before
    assert host_note.read_text() == "before\n"
    state = _inspect_container(running_agent.name)["State"]
    assert state["Running"] is True and state["StartedAt"] != started_before  # really restarted
    inside = running_agent.exec(["cat", note], check=True)
    assert inside.stdout == "before\n"  # the container mounts the rewound workspace
    health = running_agent.exec(["curl", "--fail", "--silent", HEALTH_URL], check=True)
    assert json.loads(health.stdout)["ok"] is True


# Helpers


def _inspect_container(name: str) -> dict:
    return json.loads(docker.run(["container", "inspect", name]).stdout)[0]


def _proc_status(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()
    return fields


def _mountinfo(text: str) -> list[dict]:
    """proc_pid_mountinfo(5): root, mount point and options, and the fs type after ``-``."""
    mounts = []
    for line in text.splitlines():
        fields = line.split(" ")
        separator = fields.index("-", 6)
        mounts.append(
            {
                "root": fields[3],
                "point": fields[4],
                "options": fields[5].split(","),
                "fs": fields[separator + 1],
            }
        )
    return mounts


def _is_docker_mask(point: str) -> bool:
    return point.startswith("/proc/") or point == "/sys/firmware"


def _json_lines(text: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _level(entry: dict) -> str:
    meta = entry.get("_meta")
    return str(meta.get("logLevelName", "")) if isinstance(meta, dict) else ""


def _host_ipv4_addresses() -> set[str]:
    """Every IPv4 address of the VM (the agent's host), from ``ip -j addr``."""
    output = subprocess.run(
        ["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, check=True, timeout=30
    ).stdout
    addresses = {
        info["local"]
        for link in json.loads(output)
        for info in link.get("addr_info", [])
        if not ipaddress.ip_address(info["local"]).is_loopback
    }
    assert addresses, "the VM should have at least one non-loopback IPv4 address"
    return addresses


def _container_ipv4_addresses(name: str, network: str) -> set[str]:
    """The container's own IPv4 addresses on ``network``, from ``docker inspect``."""
    settings = _inspect_container(name)["NetworkSettings"]["Networks"][network]
    return {settings["IPAddress"]} if settings.get("IPAddress") else set()


def _network_first_hosts(jail_config) -> set[str]:
    """The first address of the agent network's subnets: where Docker would put the host's
    gateway address if the network were not isolated."""
    info = json.loads(
        docker.run(["network", "inspect", "--format", "{{json .}}", jail_config.network]).stdout
    )
    return {
        str(next(ipaddress.ip_network(pool["Subnet"]).hosts()))
        for pool in info["IPAM"]["Config"]
        if ipaddress.ip_network(pool["Subnet"]).version == 4
    }
