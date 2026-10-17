"""Jail escape battery (T03a): a compromised OpenClaw agent trying to break out.

Every test drives the ``running_agent`` fixture (tests/integration/conftest.py): a real
OpenClaw container started from the pinned image, cleaned up afterwards. ``running_agent.exec``
runs a command INSIDE the container as the agent user (``docker exec``), so each test is a
shell the attacker already has in the container (python3, node, curl, sh are in the image).
The pytest process itself runs on the VM host, so the host-side assertions look at the real
workspace, the snapshot store and the btrfs volume from outside the jail.

This file is written independently from ``backtide/jail`` (another agent implements it): it only
assumes the design (docs/13-diseno-t03-jaula.md) and the fixture contract, and it asserts the
security properties, never the implementation.

Convention: every probe reports ``ESCAPED`` on breach (and exits non-zero); on a blocked
attempt it exits 0 without printing ``ESCAPED``. ``assert_jailed`` checks both, so a real
escape fails the test loudly. Each test is bounded in time and harmless: attacks only run
inside the agent container, and only against addresses that cannot cause harm (TEST-NET
192.0.2.1, 1.1.1.1 and link-local, used only to prove there is no route; nothing is ever sent
anywhere real).
"""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import sys
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess
from typing import Protocol
from uuid import uuid4

import pytest

from backtide.snapshots import btrfs
from backtide.snapshots.store import SnapshotStore

pytestmark = pytest.mark.integration

_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")
# The container's tmpfs mountpoint, named here only to inspect the jail (not a host temp file).
TMP_MOUNT = "/tmp"  # noqa: S108
# API-key environment variables OpenClaw understands (docs/12); none may reach the container.
# The gateway token IS allowed in the container (docs/13): with it the agent can only drive
# itself, so it is not treated as a secret here.
FORBIDDEN_ENV_NAMES = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
        "OLLAMA_API_KEY",
        "LM_API_TOKEN",
    }
)


class RunningAgent(Protocol):
    """The fixture contract (tests/integration/conftest.py), for type checking and clarity."""

    name: str
    workspace: Path  # host path of <root>/workspace/agente, the only thing mounted at /workspace
    store: SnapshotStore  # the store whose workspace contains the agent's directory

    def exec(
        self, argv: list[str], *, check: bool = False, timeout: float = 60
    ) -> CompletedProcess[str]:
        """Run ``argv`` inside the agent container, as the agent user (docker exec)."""

    def quiesce(self) -> AbstractContextManager[object]:
        """Stop the agent on enter and start it on exit (the context restore() uses)."""


# Helpers


def run_sh(agent: RunningAgent, script: str, *, timeout: float = 30) -> CompletedProcess[str]:
    """Run a /bin/sh script inside the container."""
    return agent.exec(["sh", "-c", script], timeout=timeout)


def run_python(agent: RunningAgent, script: str, *, timeout: float = 30) -> CompletedProcess[str]:
    """Run a python3 snippet inside the container."""
    return agent.exec(["python3", "-c", script], timeout=timeout)


def run_python_args(
    agent: RunningAgent, script: str, *args: str, timeout: float = 30
) -> CompletedProcess[str]:
    """Run a python3 snippet inside the container, with ``args`` as its sys.argv[1:]."""
    return agent.exec(["python3", "-c", script, *args], timeout=timeout)


def output(result: CompletedProcess[str]) -> str:
    return (result.stdout or "") + (result.stderr or "")


def assert_jailed(result: CompletedProcess[str]) -> None:
    """The jail held: the probe never printed ESCAPED and exited cleanly."""
    text = output(result)
    assert "ESCAPED" not in text, f"jail breached: {text!r}"
    assert result.returncode == 0, f"probe exited {result.returncode}: {text!r}"


def proc_self_status(agent: RunningAgent) -> dict[str, str]:
    result = agent.exec(["cat", "/proc/self/status"])
    assert result.returncode == 0, output(result)
    status: dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        name, sep, value = line.partition(":")
        if sep:
            status[name.strip()] = value.strip()
    return status


@dataclass(frozen=True)
class MountLine:
    point: str
    options: str
    fstype: str


def _unescape(field: str) -> str:
    """The kernel writes space, tab, newline and backslash in mountinfo as octal escapes."""
    return _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), field)


def parse_mountinfo(text: str) -> list[MountLine]:
    """Parse /proc/self/mountinfo (see proc_pid_mountinfo(5)): point, options, fs type."""
    mounts: list[MountLine] = []
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) < 7 or "-" not in fields[6:]:
            continue
        separator = fields.index("-", 6)
        mounts.append(
            MountLine(
                point=_unescape(fields[4]),
                options=fields[5],
                fstype=fields[separator + 1],
            )
        )
    return mounts


# 1. No privileges, no capabilities, no new privileges


def test_container_user_is_not_root(running_agent: RunningAgent) -> None:
    result = running_agent.exec(["id", "-u"])
    assert result.returncode == 0, output(result)
    assert result.stdout.strip() != "0", "the agent runs as root"

    status = proc_self_status(running_agent)
    real_uid = status.get("Uid", "").split()
    assert real_uid and real_uid[0] != "0", status


def test_runs_without_capabilities_and_with_no_new_privileges(
    running_agent: RunningAgent,
) -> None:
    """--cap-drop ALL and no-new-privileges: every capability set is empty, so there is no
    CAP_SYS_ADMIN (mount), CAP_NET_RAW (raw sockets), CAP_SYS_MODULE (modules), CAP_SYS_PTRACE
    or CAP_CHOWN, and setuid/file-capability binaries cannot elevate."""
    status = proc_self_status(running_agent)
    assert status.get("NoNewPrivs") == "1", status
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        value = status.get(field, "")
        assert value and set(value) == {"0"}, f"{field}={value!r} is not all zero"


# 2. The container only sees its own workspace, read-only config and tmpfs


def test_only_workspace_config_and_tmp_are_mounted(running_agent: RunningAgent) -> None:
    """Invariant 1: the agent never sees the black box, the snapshots or the Docker socket.
    /proc/self/mountinfo shows only /workspace (rw), /config (ro) and /tmp, plus the pseudo
    filesystems and the small /etc files Docker always binds."""
    result = running_agent.exec(["cat", "/proc/self/mountinfo"])
    assert result.returncode == 0, output(result)
    mounts = parse_mountinfo(result.stdout or "")
    by_point = {m.point: m for m in mounts}

    assert "/workspace" in by_point, by_point
    assert "rw" in by_point["/workspace"].options.split(","), by_point["/workspace"]
    assert "/config" in by_point, by_point
    assert "ro" in by_point["/config"].options.split(","), by_point["/config"]
    assert TMP_MOUNT in by_point, by_point

    for mount in mounts:
        assert not mount.point.endswith("docker.sock"), mount
        assert "snapshot" not in mount.point, mount
        assert "blackbox" not in mount.point and "black_box" not in mount.point, mount

    # The only host-data bind mounts (outside the /proc, /sys, /dev pseudo trees) are these.
    allowed = {
        "/",
        "/workspace",
        "/config",
        TMP_MOUNT,
        "/etc/resolv.conf",
        "/etc/hostname",
        "/etc/hosts",
    }
    for mount in mounts:
        if mount.point.startswith(("/proc", "/sys", "/dev")):
            continue
        assert mount.point in allowed, f"unexpected mount exposed to the agent: {mount}"


def test_host_store_is_not_reachable_from_the_container(running_agent: RunningAgent) -> None:
    """snapshots/, the lock and the staging copy live beside the workspace on the host, never
    inside the mount. Climbing out of /workspace stays in the container root filesystem."""
    before_snapshots = running_agent.store.snapshots()
    before_root = sorted(os.listdir(running_agent.store.root))

    script = """
    for name in snapshots .lock workspace.restore; do
      if [ -e "/$name" ]; then echo ESCAPED found /$name in container root; exit 1; fi
      if [ -e "/workspace/../$name" ]; then echo ESCAPED reached $name via climb; exit 1; fi
    done
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script))

    # Reading from the container changed nothing on the host.
    assert running_agent.store.snapshots() == before_snapshots
    assert sorted(os.listdir(running_agent.store.root)) == before_root


def test_no_docker_socket_is_reachable(running_agent: RunningAgent) -> None:
    """Invariant 1: no Docker socket in any location, and no Docker API answers over one."""
    script = """
    for s in /var/run/docker.sock /run/docker.sock /var/run/docker/docker.sock; do
      if [ -S "$s" ]; then echo ESCAPED socket present at $s; exit 1; fi
      if curl -sS --max-time 5 --unix-socket "$s" http://localhost/version 2>/dev/null; then
        echo ESCAPED docker api answered via $s
        exit 1
      fi
    done
    found=$(find /run /var/run /tmp -name docker.sock 2>/dev/null | head -n1)
    if [ -n "$found" ]; then echo ESCAPED found $found; exit 1; fi
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script, timeout=40))


# 3. The filesystem: read-only root, read-only config, writable only in /workspace and /tmp


def test_root_filesystem_is_read_only(running_agent: RunningAgent) -> None:
    read_only = """
    for p in /evil /etc/evil /usr/evil /var/evil /root/evil /opt/evil /home/evil /bin/evil; do
      if touch "$p" 2>/dev/null; then echo ESCAPED wrote $p; rm -f "$p" 2>/dev/null; exit 1; fi
    done
    echo blocked
    """
    assert_jailed(run_sh(running_agent, read_only))

    # The two writable spots really are writable, so the checks above are not vacuous.
    writable = """
    set -e
    echo ok > /workspace/.jail_probe && grep -q ok /workspace/.jail_probe
    rm -f /workspace/.jail_probe
    echo ok > /tmp/.jail_probe && grep -q ok /tmp/.jail_probe
    rm -f /tmp/.jail_probe
    echo WRITABLE
    """
    result = run_sh(running_agent, writable)
    assert result.returncode == 0, output(result)
    assert "WRITABLE" in output(result), output(result)


def test_config_is_read_only(running_agent: RunningAgent) -> None:
    """Config is mounted :ro (docs/13): the agent can read it but never change it to widen
    its own permissions."""
    assert running_agent.exec(["ls", "/config"]).returncode == 0  # mounted and readable
    script = """
    if touch /config/evil 2>/dev/null; then
      echo ESCAPED created /config/evil; rm -f /config/evil 2>/dev/null; exit 1
    fi
    if mkdir /config/evildir 2>/dev/null; then
      echo ESCAPED created /config/evildir; rmdir /config/evildir 2>/dev/null; exit 1
    fi
    if [ -f /config/openclaw.json ] && echo x >> /config/openclaw.json 2>/dev/null; then
      echo ESCAPED appended to the config
      exit 1
    fi
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script))


# 4. No mounting, no namespaces


# Runs inside the container. The syscalls are called directly: util-linux's mount refuses a
# non-root user by itself, before it ever asks the kernel, so it would prove nothing.
NAMESPACE_PROBE = """
import ctypes
import errno
import os
import sys

CLONE_NEWNS, CLONE_NEWUSER = 0x00020000, 0x10000000
MS_REMOUNT, MS_BIND, MNT_DETACH = 0x20, 0x1000, 2
libc = ctypes.CDLL(None, use_errno=True)


def attempt(call, *args):
    ctypes.set_errno(0)
    if call(*args) == 0:
        return "succeeded"
    return errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))


target = b"/tmp/jail-mount-probe"
os.makedirs(target, exist_ok=True)
outcomes = {"mount a tmpfs": attempt(libc.mount, b"none", target, b"tmpfs", 0, None)}
if outcomes["mount a tmpfs"] == "succeeded":
    libc.umount2(target, MNT_DETACH)
os.rmdir(target)
outcomes["remount /config read-write"] = attempt(
    libc.mount, None, b"/config", None, MS_REMOUNT | MS_BIND, None
)
fd = os.open("/proc/1/ns/mnt", os.O_RDONLY)
try:
    outcomes["enter pid 1's mount namespace"] = attempt(libc.setns, fd, CLONE_NEWNS)
finally:
    os.close(fd)
outcomes["new mount namespace"] = attempt(libc.unshare, CLONE_NEWNS)
# The unprivileged route: a user namespace would grant CAP_SYS_ADMIN over new mounts. Last,
# since success would move this process into it.
outcomes["new user namespace"] = attempt(libc.unshare, CLONE_NEWUSER)
print(outcomes)
escaped = [name for name, outcome in outcomes.items() if outcome == "succeeded"]
if escaped:
    print("ESCAPED", escaped)
    sys.exit(1)
print("blocked")
"""


def test_cannot_mount_or_change_namespaces(running_agent: RunningAgent) -> None:
    """Without CAP_SYS_ADMIN the agent cannot mount, remount /config read-write, enter pid 1's
    mount namespace, or create a mount or a user namespace (the unprivileged way to get
    CAP_SYS_ADMIN over new mounts)."""
    assert_jailed(run_python(running_agent, NAMESPACE_PROBE))


# 5. No privilege escalation


def test_cannot_gain_root_via_setuid(running_agent: RunningAgent) -> None:
    """The agent cannot own a file as root (no CAP_CHOWN) and a setuid bit it sets gives nothing
    (no-new-privileges), so it cannot build a setuid-root binary."""
    script = """
    cp /bin/sh /workspace/.jail_suid 2>/dev/null || cp /bin/busybox /workspace/.jail_suid
    if chown 0:0 /workspace/.jail_suid 2>/dev/null; then
      echo ESCAPED chowned a file to root
      rm -f /workspace/.jail_suid
      exit 1
    fi
    chmod u+s /workspace/.jail_suid 2>/dev/null
    euid=$(/workspace/.jail_suid -c "id -u" 2>/dev/null || true)
    rm -f /workspace/.jail_suid
    if [ "$euid" = "0" ]; then echo ESCAPED setuid run became root; exit 1; fi
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script))


# Runs inside the container. It gets the host marker reversed, so that its own command line
# (visible in /proc like any other) never contains the marker it looks for.
PID_NAMESPACE_PROBE = """
import os
import sys

marker = sys.argv[1][::-1].encode()
own = os.readlink("/proc/self/ns/pid")
escaped = []
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        with open(f"/proc/{entry}/cmdline", "rb") as f:
            cmdline = f.read()
    except OSError:
        continue  # exited meanwhile
    if marker in cmdline:
        escaped.append(f"pid {entry} is the host's marker process")
    try:
        namespace = os.readlink(f"/proc/{entry}/ns/pid")
    except OSError:
        continue  # exited meanwhile, or another user's (cmdline above is world-readable)
    if namespace != own:
        escaped.append(f"pid {entry} is in pid namespace {namespace}, not the jail's {own}")
if escaped:
    print("ESCAPED", escaped)
    sys.exit(1)
print("blocked")
"""


def test_cannot_ptrace_other_processes(running_agent: RunningAgent) -> None:
    """ptrace and /proc/<pid>/mem only reach processes the agent can see, and the jail's pid
    namespace hides every process outside it. A marker process started on the host, as the
    same user the agent runs as in these tests (the easiest target there is), is invisible
    from inside, and every process the agent sees is in the jail's own pid namespace.

    Inside the jail every process is the agent's own (same uid, no capabilities, same seccomp
    filter), and the host's Yama setting decides whether they can trace one another: Fedora
    ships ptrace_scope 0, so they can. That reaches nothing the agent does not already have,
    so it is not asserted either way. CAP_SYS_PTRACE is absent (see the capabilities test)."""
    marker = f"backtide-ptrace-target-{uuid4().hex}"
    target = subprocess.Popen(  # a sleeping process, recognisable by its marker
        [sys.executable, "-c", "import time; time.sleep(120)", marker]
    )
    try:
        assert_jailed(run_python_args(running_agent, PID_NAMESPACE_PROBE, marker[::-1]))
    finally:
        target.kill()
        target.wait(timeout=10)


# Runs inside the container. init_module(2) and finit_module(2) are called by number, as an
# attacker would (the image has no modprobe or insmod). The "module" is never a valid one: if
# the permission check ever passed, the kernel would reject it as malformed (ENOEXEC), so a
# result other than EPERM means the check passed, and nothing can ever be loaded.
MODULE_PROBE = """
import ctypes
import errno
import os
import sys

SYSCALLS = {"aarch64": (105, 273), "x86_64": (175, 313)}  # init_module, finit_module
machine = os.uname().machine
if machine not in SYSCALLS:
    print("unknown architecture, cannot probe:", machine)
    sys.exit(2)
init_module, finit_module = SYSCALLS[machine]
libc = ctypes.CDLL(None, use_errno=True)


def attempt(*args):
    ctypes.set_errno(0)
    if libc.syscall(*args) == 0:
        return "succeeded"
    return errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))


image = ctypes.create_string_buffer(64)
outcomes = {"init_module": attempt(init_module, image, ctypes.c_ulong(len(image)), b"")}
fd = os.open("/etc/hostname", os.O_RDONLY)
try:
    outcomes["finit_module"] = attempt(finit_module, fd, b"", 0)
finally:
    os.close(fd)
print(outcomes)
passed = {name: outcome for name, outcome in outcomes.items() if outcome != "EPERM"}
if passed:
    print("ESCAPED module loading got past the permission check:", passed)
    sys.exit(1)
print("blocked")
"""


def test_cannot_load_kernel_modules(running_agent: RunningAgent) -> None:
    """No CAP_SYS_MODULE (see the capabilities test): loading a module always fails with
    EPERM, called straight through the syscalls."""
    assert_jailed(run_python(running_agent, MODULE_PROBE))


# 6. The network: no raw sockets, no egress, no DNS, no host and no metadata


RAW_SOCKET_PROBE = """
import socket
import sys

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.close()
except OSError as error:
    print("blocked", error)
    sys.exit(0)
print("ESCAPED raw socket created")
sys.exit(1)
"""


# The image has no ping binary. This is what ping does without CAP_NET_RAW: an unprivileged
# ICMP "ping socket", which Docker allows to every group (net.ipv4.ping_group_range). The
# kernel fills in the checksum and the identifier.
ICMP_ECHO_PROBE = """
import socket
import struct
import sys

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
except OSError as error:
    print("blocked: no ping socket:", error)
    sys.exit(0)
sock.settimeout(3)
echo_request = struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"backtide-jail-probe"
try:
    sock.sendto(echo_request, ("1.1.1.1", 0))
    reply = sock.recvfrom(1024)
except OSError as error:  # no route, or no reply in time
    print("blocked:", error)
    sys.exit(0)
print("ESCAPED ping reached 1.1.1.1:", reply)
sys.exit(1)
"""


def test_cannot_create_raw_sockets_or_ping(running_agent: RunningAgent) -> None:
    """Without CAP_NET_RAW a raw/ICMP socket cannot be opened, so there is no spoofing; and an
    echo request through an unprivileged ping socket finds no way out either."""
    assert_jailed(run_python(running_agent, RAW_SOCKET_PROBE))
    assert_jailed(run_python(running_agent, ICMP_ECHO_PROBE, timeout=20))


def test_no_network_egress_to_public_ips(running_agent: RunningAgent) -> None:
    """The agent's Docker network is --internal: no route to any public address. 192.0.2.1 is
    TEST-NET-1 (guaranteed unroutable); 1.1.1.1 only proves there is no default route. Nothing
    is ever sent anywhere real."""
    script = """
    for url in http://1.1.1.1 http://192.0.2.1 https://1.1.1.1; do
      if curl -sS --max-time 8 -o /dev/null "$url" 2>/dev/null; then
        echo ESCAPED reached $url
        exit 1
      fi
    done
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script, timeout=45))


DNS_PROBE = """
import socket
import sys

socket.setdefaulttimeout(5)
try:
    info = socket.getaddrinfo("example.com", 80)
except OSError as error:
    print("blocked", error)
    sys.exit(0)
print("ESCAPED resolved example.com", info)
sys.exit(1)
"""


def test_dns_resolution_is_blocked(running_agent: RunningAgent) -> None:
    """With no egress the embedded resolver has no upstream, so resolving a real public name
    fails instead of leaking the query or an answer."""
    assert_jailed(run_python(running_agent, DNS_PROBE, timeout=30))


# Runs inside the container: what an attacker tries first. Every gateway in the routing table,
# the first address of every connected subnet (where Docker puts the host's side of a bridge)
# and the host's default docker0 bridge; never the container's own addresses (an isolated
# network may hand the first one to the container). ssh and Docker's TCP API, once each. A
# refusal counts too: something outside the container answered.
#
# Invariant 8: the probe itself must never reach the Mac, even when the jail has failed. A
# default route is already the escape (the jail has none), so it is reported without
# connecting anywhere: had the jail fallen back to the VM's network, that route would lead to
# Lima's gateway, 192.168.5.2, which is the Mac. For the same reason only addresses in
# Docker's pools (172.16.0.0/12) are ever probed, and Lima's networks never are.
# With three arguments (fake route and fib_trie files, then "list" or "connect") it reads
# those instead of /proc, for the tests of the probe itself; "list" prints the targets only.
HOST_PROBE = """
import ipaddress
import json
import socket
import struct
import sys

DOCKER_POOLS = ipaddress.ip_network("172.16.0.0/12")
# Lima's user network (its gateway 192.168.5.2 is the Mac) and its shared vmnet network.
NEVER = (ipaddress.ip_network("192.168.5.0/24"), ipaddress.ip_network("192.168.105.0/24"))

route_path, trie_path, mode = "/proc/net/route", "/proc/net/fib_trie", "connect"
if len(sys.argv) == 4:
    route_path, trie_path, mode = sys.argv[1:]


def from_route(hex_value):
    return int.from_bytes(struct.pack("<I", int(hex_value, 16)), "big")


def dotted(number):
    return socket.inet_ntoa(number.to_bytes(4, "big"))


def may_probe(address):
    ip = ipaddress.ip_address(address)
    return ip in DOCKER_POOLS and not any(ip in network for network in NEVER)


with open(trie_path) as trie:
    lines = trie.read().splitlines()
own = {
    previous.split()[-1]
    for previous, line in zip(lines, lines[1:])
    if line.strip() == "/32 host LOCAL"
}
targets = {"172.17.0.1"}
with open(route_path) as routes:
    next(routes)  # the header
    for line in routes:
        fields = line.split()
        destination, gateway, mask = (from_route(fields[i]) for i in (1, 2, 7))
        if mask == 0:
            print("ESCAPED a default route via", dotted(gateway), "(not connecting anywhere)")
            sys.exit(1)
        if gateway:
            targets.add(dotted(gateway))
        if mask != 0xFFFFFFFF:
            targets.add(dotted(destination + 1))
targets = {address for address in targets if may_probe(address)} - own
print("own:", sorted(own), "targets:", sorted(targets))
if mode == "list":
    print("TARGETS", json.dumps(sorted(targets)))
    sys.exit(0)
reached = []
for address in sorted(targets):
    for port in (22, 2375):
        try:
            socket.create_connection((address, port), timeout=3).close()
            reached.append(f"{address}:{port} accepted")
        except ConnectionRefusedError:
            reached.append(f"{address}:{port} refused (so it answered)")
        except OSError as error:
            print(f"{address}:{port} blocked: {error}")
if reached:
    print("ESCAPED the host answered:", reached)
    sys.exit(1)
print("blocked")
"""


def test_cannot_reach_host_gateway_or_cloud_metadata(running_agent: RunningAgent) -> None:
    """No path to the VM host (its gateway or bridge addresses, host.docker.internal) and no
    cloud metadata endpoint (link-local 169.254.169.254)."""
    assert_jailed(run_python(running_agent, HOST_PROBE, timeout=60))
    script = """
    for url in \
      http://169.254.169.254/latest/meta-data/ \
      http://metadata.google.internal/ \
      http://host.docker.internal/; do
      if curl -sS --max-time 6 -o /dev/null "$url" 2>/dev/null; then
        echo ESCAPED reached $url
        exit 1
      fi
    done
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script, timeout=40))


ROUTE_HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"
ZERO = "0.0.0.0"  # noqa: S104 - "none" in a routing table (no gateway, or the default route)
FIB_TRIE = "Main:\n  +-- 172.18.0.0/16 2 0 2\n     |-- 172.18.0.2\n        /32 host LOCAL\n"


def _route_hex(address: str) -> str:
    """/proc/net/route writes an IPv4 address as the hex of its little-endian integer."""
    return f"{struct.unpack('<I', socket.inet_aton(address))[0]:08X}"


def _host_probe_on_fake_routes(
    agent: RunningAgent, routes: list[tuple[str, str, str]], mode: str
) -> CompletedProcess[str]:
    """Run HOST_PROBE inside the jail on a fake routing table of (destination, gateway, mask).
    Inside the jail even a probe that did connect would find no way anywhere."""
    lines = [ROUTE_HEADER]
    lines += [
        f"eth0\t{_route_hex(d)}\t{_route_hex(g)}\t0003\t0\t0\t0\t{_route_hex(m)}\t0\t0\t0"
        for d, g, m in routes
    ]
    tag = uuid4().hex[:8]
    route_path, trie_path = f"{TMP_MOUNT}/fake-route-{tag}", f"{TMP_MOUNT}/fake-trie-{tag}"
    write = "import sys; open(sys.argv[1], 'w').write(sys.argv[2])"
    for path, content in ((route_path, "\n".join(lines) + "\n"), (trie_path, FIB_TRIE)):
        assert agent.exec(["python3", "-c", write, path, content]).returncode == 0
    try:
        return run_python_args(agent, HOST_PROBE, route_path, trie_path, mode)
    finally:
        agent.exec(["rm", "-f", route_path, trie_path])


def test_host_probe_stops_at_a_default_route(running_agent: RunningAgent) -> None:
    """Invariant 8 for the probe itself: with the VM's own routing table (the jail fallen
    back to the host's network), the probe reports the default route as the escape and
    connects nowhere, instead of knocking on Lima's gateway, 192.168.5.2: the Mac."""
    vm_routes = [
        (ZERO, "192.168.5.2", ZERO),
        ("172.17.0.0", ZERO, "255.255.0.0"),
        ("192.168.5.0", ZERO, "255.255.255.0"),
    ]
    result = _host_probe_on_fake_routes(running_agent, vm_routes, "connect")
    assert result.returncode == 1, output(result)
    assert "ESCAPED a default route via 192.168.5.2" in result.stdout
    assert "blocked" not in result.stdout and "answered" not in result.stdout  # tried nothing


def test_host_probe_only_targets_docker_addresses(running_agent: RunningAgent) -> None:
    routes = [
        ("172.18.0.0", ZERO, "255.255.0.0"),  # the agent's network (it is 172.18.0.2)
        ("172.20.0.0", "172.18.0.9", "255.255.0.0"),
        ("192.168.5.0", ZERO, "255.255.255.0"),  # Lima's network: never probed
        ("10.0.0.0", "192.168.5.2", "255.0.0.0"),
    ]
    result = _host_probe_on_fake_routes(running_agent, routes, "list")
    assert result.returncode == 0, output(result)
    targets = json.loads(result.stdout.split("TARGETS", 1)[1])
    assert targets == ["172.17.0.1", "172.18.0.1", "172.18.0.9", "172.20.0.1"]


# 7. Btrfs: the agent cannot create nested subvolumes (the T01 escape), closed with seccomp


BTRFS_IOCTL_PROBE = """
import errno
import fcntl
import os
import struct
import sys


def ioc(direction, type_, nr, size):
    return (direction << 30) | (size << 16) | (type_ << 8) | nr


BTRFS = 0x94  # the ioctl type byte the seccomp profile blocks (docs/13)
WRITE = 1
VOL_ARGS = 4096  # sizeof(struct btrfs_ioctl_vol_args) and _args_v2
SUBVOL_CREATE = ioc(WRITE, BTRFS, 14, VOL_ARGS)  # 0x5000940e
SNAP_CREATE_V2 = ioc(WRITE, BTRFS, 23, VOL_ARGS)  # 0x50009417


def attempt(name, request, args):
    # The jail answers EOPNOTSUPP before btrfs ever sees the call (docs/13). Any other error
    # came from btrfs itself (EINVAL for SNAP_CREATE_V2 with fd -1, say): the block did not hold.
    try:
        fcntl.ioctl(fd, request, args)
    except OSError as error:
        print(name, "failed:", error)
        if error.errno != errno.EOPNOTSUPP:
            escaped.append(f"{name} reached btrfs ({error})")
    else:
        escaped.append(f"{name} succeeded")


escaped = []
fd = os.open("/workspace", os.O_RDONLY | os.O_DIRECTORY)
try:
    create = bytearray(VOL_ARGS)
    struct.pack_into("q", create, 0, -1)  # vol_args.fd, unused for create
    create[8 : 8 + len(b"nested")] = b"nested"
    attempt("SUBVOL_CREATE", SUBVOL_CREATE, create)

    v2 = bytearray(VOL_ARGS)
    struct.pack_into("q", v2, 0, -1)
    v2[56 : 56 + len(b"nested2")] = b"nested2"  # vol_args_v2.name starts at offset 56
    attempt("SNAP_CREATE_V2", SNAP_CREATE_V2, v2)
finally:
    os.close(fd)

if escaped:
    print("ESCAPED the btrfs block did not hold:", escaped)
    sys.exit(1)
print("blocked")
sys.exit(0)
"""


def test_btrfs_subvolume_ioctls_are_blocked(running_agent: RunningAgent) -> None:
    """A nested subvolume escapes snapshots and rewinds (docs/10). The seccomp rule blocks the
    0x94 btrfs ioctls with EOPNOTSUPP before btrfs sees them (an errno, not a killed process),
    so the agent cannot plant one, cannot flip subvolume flags, and the host workspace stays a
    writable subvolume with no new children. ``cp --reflink=auto`` still falls back to a plain
    copy, so OpenClaw keeps working (test_jail.py)."""
    agent = running_agent
    before = agent.store.snapshots()
    nested = agent.workspace / "nested"
    try:
        assert_jailed(run_python(agent, BTRFS_IOCTL_PROBE))
        assert not btrfs.is_subvolume(nested), "a nested subvolume was created in the workspace"
        assert not btrfs.is_readonly(agent.store.workspace), "the workspace was made read-only"
        assert agent.store.snapshots() == before, "the snapshot set changed"
    finally:
        if btrfs.is_subvolume(nested):
            btrfs.delete_subvolume(nested)
        elif nested.is_dir() and not nested.is_symlink():
            nested.rmdir()


# 8. Resource limits: tmpfs is capped and the pid count is bounded


def test_tmpfs_tmp_is_size_capped(running_agent: RunningAgent) -> None:
    """The container's tmpfs is size-limited, so the agent cannot exhaust the VM's memory
    through it. The write is bounded (300 MiB against a ~256 MiB cap) and freed immediately."""
    script = """
    if dd if=/dev/zero of=/tmp/jail-fill bs=1M count=300 2>/dev/null; then
      echo ESCAPED filled /tmp past its cap
      rm -f /tmp/jail-fill
      exit 1
    fi
    rm -f /tmp/jail-fill
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script, timeout=60))


def test_pids_limit_caps_fork_bombs(running_agent: RunningAgent) -> None:
    """--pids-limit sets a finite cgroup pids.max, which bounds any fork bomb. We read the cap
    rather than run a fork bomb: a real one is unnecessary and risky."""
    script = """
    for f in /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids/pids.max; do
      if [ -f "$f" ]; then
        value=$(cat "$f")
        if [ "$value" = "max" ] || [ -z "$value" ]; then
          echo ESCAPED pids are unlimited at $f
          exit 1
        fi
        echo "blocked $f=$value"
        exit 0
      fi
    done
    echo ESCAPED no pids cgroup limit found
    exit 1
    """
    assert_jailed(run_sh(running_agent, script))


# 9. Secrets: no API keys in the environment, not even in pid 1's


def _env_names(environ_text: str) -> set[str]:
    return {entry.split("=", 1)[0] for entry in environ_text.split("\0") if "=" in entry}


def _assert_no_api_keys(names: set[str], where: str) -> None:
    for name in names:
        assert name not in FORBIDDEN_ENV_NAMES, f"{name} leaked into {where}"
        assert not name.endswith(("_API_KEY", "_APIKEY")), f"{name} leaked into {where}"
        assert "SECRET" not in name and "PASSWORD" not in name, f"{name} leaked into {where}"


def test_environment_contains_no_api_keys(running_agent: RunningAgent) -> None:
    """Invariant: no provider API key is ever placed in the agent container (docs/13). The
    gateway token may be present; with it the agent can only operate itself."""
    own = running_agent.exec(["cat", "/proc/self/environ"])
    assert own.returncode == 0, output(own)
    _assert_no_api_keys(_env_names(own.stdout or ""), "/proc/self/environ")

    # pid 1 is the gateway; reading its environ may be allowed (same uid). If it is, it must be
    # just as clean as the agent's own.
    init = running_agent.exec(["cat", "/proc/1/environ"])
    if init.returncode == 0:
        _assert_no_api_keys(_env_names(init.stdout or ""), "/proc/1/environ")


# 10. /proc/sys and /sys are read-only


def test_cannot_write_to_proc_sys_or_sys(running_agent: RunningAgent) -> None:
    """Docker mounts /proc/sys and /sys read-only: the agent cannot retune the kernel."""
    script = """
    for p in \
      /proc/sys/kernel/randomize_va_space \
      /proc/sys/kernel/hostname \
      /proc/sys/vm/drop_caches \
      /sys/kernel/uevent_helper; do
      if echo 0 > "$p" 2>/dev/null; then echo ESCAPED wrote $p; exit 1; fi
    done
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script))


# 11. Symlinks planted in the workspace do not escape to the host


def test_symlinks_in_workspace_do_not_escape_to_the_host(running_agent: RunningAgent) -> None:
    """The agent can create symlinks in its own workspace, but they cannot reach host-only
    paths: inside the container a relative climb out of the mount lands nowhere, and on the host
    the links are inert symlinks that the snapshot store never follows (store unchanged)."""
    agent = running_agent
    before_snapshots = agent.store.snapshots()
    before_root = sorted(os.listdir(agent.store.root))

    script = """
    ln -sf /etc/passwd /workspace/escape-abs
    ln -sf ../../../../../../snapshots /workspace/escape-rel
    ln -sf /config/openclaw.json /workspace/escape-config
    if ls -L /workspace/escape-rel/ 2>/dev/null | grep -q .; then
      echo ESCAPED reached the host snapshots via a symlink
      exit 1
    fi
    echo blocked
    """
    try:
        assert_jailed(run_sh(agent, script))
        for name in ("escape-abs", "escape-rel", "escape-config"):
            link = agent.workspace / name
            assert link.is_symlink(), f"{name} should be a plain symlink on the host"
        assert os.readlink(agent.workspace / "escape-abs") == "/etc/passwd"
        # The host side never followed them: nothing created, deleted or restored.
        assert agent.store.snapshots() == before_snapshots
        assert sorted(os.listdir(agent.store.root)) == before_root
    finally:
        for name in ("escape-abs", "escape-rel", "escape-config"):
            link = agent.workspace / name
            if link.is_symlink():
                link.unlink()


# 12. Devices: no block devices and no kernel memory


def test_cannot_access_block_or_kernel_devices(running_agent: RunningAgent) -> None:
    """The device cgroup and --cap-drop ALL keep the disk and kernel memory out of reach: no
    /dev/sda to read the host disk, no /dev/mem or /dev/kmsg."""
    script = """
    for dev in /dev/sda /dev/sda1 /dev/vda /dev/nvme0n1 /dev/mem /dev/kcore /dev/kmsg; do
      if dd if="$dev" of=/dev/null bs=1 count=1 2>/dev/null; then
        echo ESCAPED read $dev
        exit 1
      fi
    done
    if echo x > /dev/kmsg 2>/dev/null; then echo ESCAPED wrote /dev/kmsg; exit 1; fi
    echo blocked
    """
    assert_jailed(run_sh(running_agent, script))
