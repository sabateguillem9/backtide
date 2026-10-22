"""What of the host the agent's container would see, or does: the mount check (T14a).

Invariants 1 and 2 (CLAUDE.md): the agent never sees the black box, the snapshots, backtide's
config and state, the keys, the control socket, the proxy's channel or Docker's socket, and it
never has more privileges than it needs. config.py builds the jail that way and verify.py
compares a container with it field by field; this module asks the other question, the one
that does not depend on how the container was built: **would this container show the agent
anything it must not see?** It is asked three times (agent.py):

- before ``docker create``, of the planned argv (``planned_info``);
- before ``docker start``, of ``docker container inspect``;
- right after it, and at every cycle of the Guardian, of the running container (a container
  recreated under backtide with one more ``-v`` is killed).

``exposure_problems`` returns the problems as sentences, empty when there is none. Paths are
compared with symlinks resolved, on the host (``HostView``): a bind of ``/srv/link`` that
resolves into the state folder is the state folder. Docker binds are recursive, so a host
mount below a mounted folder would show too: the host's mount table is read for that, and if
it cannot be read on Linux that is a problem as well (fail closed).

Only bind mounts can show the host. tmpfs mounts are private memory and are fine wherever
they land; a Docker volume is refused (the agent gets none), and so is any other kind.
"""

import os
import pwd
import stat
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from backtide.jail.config import (
    CONTAINER_CA_DIR,
    CONTAINER_CONFIG_DIR,
    CONTAINER_WORKSPACE,
    AgentJailConfig,
    Protected,
)

# Host folders no mount of the agent may be or contain: the whole system, the homes, Docker's
# own data. (Being inside some of them is fine: an installation may keep its volume in /var.)
SENSITIVE_ROOTS = (
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/proc", "/root", "/run",
    "/sbin", "/sys", "/usr", "/var", "/var/run", "/var/lib/docker", "/var/lib/containerd",
)  # fmt: skip
# Host folders no mount of the agent may come from at all: the kernel's views, the devices,
# the sockets and runtime state of the daemons (Docker's socket lives in /run), the system's
# config, and Docker's own data.
NEVER_INSIDE = (
    "/boot", "/dev", "/etc", "/proc", "/run", "/sys", "/var/run", "/var/lib/docker",
    "/var/lib/containerd",
)  # fmt: skip
DOCKER_SOCKETS = (
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
)
# Namespaces a container may share with the host ("host") or with another one ("container:x").
_NAMESPACES = (
    ("PidMode", "process"),
    ("IpcMode", "IPC"),
    ("UTSMode", "hostname"),
    ("UsernsMode", "user"),
    ("NetworkMode", "network"),
    ("CgroupnsMode", "cgroup"),
)
_UNCONFINED = (
    "seccomp=unconfined",
    "seccomp:unconfined",
    "apparmor=unconfined",
    "apparmor:unconfined",
    "label=disable",
    "label:disable",
    "systempaths=unconfined",
)
_KERNEL_VIEWS = (PurePosixPath("/proc"), PurePosixPath("/sys"))


@dataclass(frozen=True)
class ExpectedBind:
    """One host folder the agent may see, where, and whether only for reading."""

    source: str
    destination: str
    read_only: bool


@dataclass(frozen=True)
class MountPolicy:
    """What may be mounted into the agent and what must never be seen."""

    binds: tuple[ExpectedBind, ...]
    protected: tuple[Protected, ...] = ()


def agent_policy(config: AgentJailConfig) -> MountPolicy:
    """The agent's folders (config.volume_binds) and the paths it must never see."""
    return MountPolicy(
        binds=(
            ExpectedBind(str(config.agent_dir), str(CONTAINER_WORKSPACE), read_only=False),
            ExpectedBind(str(config.config_dir), str(CONTAINER_CONFIG_DIR), read_only=True),
            ExpectedBind(str(config.ca_dir), str(CONTAINER_CA_DIR), read_only=True),
        ),
        protected=config.protected,
    )


def _file_kind(path: str) -> str | None:
    """``dir``, ``file``, ``socket``, ``device`` or ``other``; None when it is not there."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    return "other"


def _mount_points() -> list[str] | None:
    """Every mount point of the host (``/proc/self/mountinfo``: backtide runs in the host's
    mount namespace). None if it cannot be read on Linux; [] elsewhere (the Mac's unit tests:
    backtide only runs agents on Linux)."""
    if not sys.platform.startswith("linux"):
        return []
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as f:
            text = f.read()
    except OSError:
        return None
    return parse_mountinfo(text)


def parse_mountinfo(text: str) -> list[str]:
    """The mount points of a ``/proc/<pid>/mountinfo`` (field 5, octal escapes undone)."""
    points = []
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) > 4:
            points.append(_unescape(fields[4]))
    return points


def _unescape(field_text: str) -> str:
    out, i = [], 0
    while i < len(field_text):
        chunk = field_text[i : i + 4]
        if len(chunk) == 4 and chunk[0] == "\\" and all(c in "01234567" for c in chunk[1:]):
            out.append(chr(int(chunk[1:], 8)))
            i += 4
        else:
            out.append(field_text[i])
            i += 1
    return "".join(out)


def _homes() -> list[str]:
    homes = {os.path.expanduser("~")}
    try:
        homes.update(entry.pw_dir for entry in pwd.getpwall())
    except OSError:
        pass  # the explicit list (/home, /root) still stands
    return sorted(h for h in homes if h.startswith("/") and h != "/")


@dataclass(frozen=True)
class HostView:
    """How the host is looked at. The defaults are the real host; the tests hand in theirs."""

    realpath: Callable[[str], str] = os.path.realpath
    kind: Callable[[str], str | None] = _file_kind
    mount_points: Callable[[], list[str] | None] = _mount_points
    homes: Callable[[], list[str]] = _homes


@dataclass
class _Mount:
    kind: str  # bind, volume, tmpfs or whatever Docker says
    source: str
    destination: str
    read_only: bool
    name: str = ""
    origin: str = field(default="Mounts", compare=False)


def exposure_problems(
    info: dict[str, Any], policy: MountPolicy, host: HostView | None = None
) -> list[str]:
    """What the container of ``info`` (``docker container inspect``, or ``planned_info``) would
    show the agent that it must not see, or let it do that it must not; empty when nothing.
    Unreadable parts of ``info`` are problems too: what cannot be checked is not run."""
    host = host or HostView()
    hostconfig = info.get("HostConfig")
    if not isinstance(hostconfig, dict):
        return ["docker inspect does not say how the container is set up (no HostConfig)"]
    problems = _privilege_problems(hostconfig)
    mounts, unreadable = _mounts(info, hostconfig)
    problems += unreadable
    context = _Context(policy, host)
    for mount in mounts:
        problems += context.mount_problems(mount)
    return list(dict.fromkeys(problems))


def _privilege_problems(host: dict[str, Any]) -> list[str]:
    problems = []
    if host.get("Privileged"):
        problems.append("it is privileged (--privileged): it would see every device of the host")
    if host.get("CapAdd"):
        problems.append(f"it adds capabilities: {host['CapAdd']!r}")
    drop = host.get("CapDrop")
    if not isinstance(drop, list) or "ALL" not in [str(c).upper() for c in drop]:
        problems.append(f"it keeps Docker's default capabilities (CapDrop is {drop!r}, not ALL)")
    for key, what in _NAMESPACES:
        value = host.get(key)
        if _shares(value):
            owner = "the host" if value == "host" else value.removeprefix("container:")
            problems.append(f"it shares the {what} namespace of {owner} ({key}={value!r})")
    for key in ("Devices", "DeviceCgroupRules", "DeviceRequests"):
        if host.get(key):
            problems.append(f"it is given devices of the host ({key}={host[key]!r})")
    if host.get("VolumesFrom"):
        problems.append(f"it mounts the volumes of other containers: {host['VolumesFrom']!r}")
    if host.get("VolumeDriver"):
        problems.append(f"it uses the volume driver {host['VolumeDriver']!r}")
    options = host.get("SecurityOpt") or []
    if not isinstance(options, list):
        problems.append(f"its security options cannot be read: {options!r}")
        options = []
    for option in options:
        if isinstance(option, str) and option.replace(" ", "") in _UNCONFINED:
            problems.append(f"it turns a protection off: --security-opt {option}")
    for key in ("MaskedPaths", "ReadonlyPaths"):
        if not host.get(key):
            problems.append(f"HostConfig.{key} is empty: /proc and /sys would not be masked")
    return problems


def _shares(value: object) -> bool:
    """A namespace mode that shares the host's (``host``) or another container's."""
    return isinstance(value, str) and (value == "host" or value.startswith("container:"))


def _mounts(info: dict[str, Any], host: dict[str, Any]) -> tuple[list[_Mount], list[str]]:
    """Every mount ``info`` names: the daemon's list (``Mounts``) and what was asked for
    (``HostConfig.Binds``, ``HostConfig.Mounts``, ``HostConfig.Tmpfs``)."""
    mounts: list[_Mount] = []
    problems: list[str] = []
    listed = info.get("Mounts")
    if not isinstance(listed, list):
        problems.append("docker inspect does not say what is mounted (no Mounts list)")
        listed = []
    for entry in listed:
        if not isinstance(entry, dict):
            problems.append(f"a mount docker inspect lists cannot be read: {entry!r:.200}")
            continue
        mounts.append(
            _Mount(
                kind=str(entry.get("Type") or ""),
                source=str(entry.get("Source") or ""),
                destination=str(entry.get("Destination") or ""),
                read_only=entry.get("RW") is False,
                name=str(entry.get("Name") or ""),
            )
        )
    for bind in host.get("Binds") or []:
        mount = parse_volume(bind) if isinstance(bind, str) else None
        if mount is None:
            problems.append(f"a bind of HostConfig.Binds cannot be read: {bind!r:.200}")
        else:
            mounts.append(mount)
    for entry in host.get("Mounts") or []:
        if not isinstance(entry, dict):
            problems.append(f"a mount of HostConfig.Mounts cannot be read: {entry!r:.200}")
            continue
        mounts.append(
            _Mount(
                kind=str(entry.get("Type") or ""),
                source=str(entry.get("Source") or ""),
                destination=str(entry.get("Target") or ""),
                read_only=entry.get("ReadOnly") is True,
                origin="HostConfig.Mounts",
            )
        )
    tmpfs = host.get("Tmpfs") or {}
    if isinstance(tmpfs, dict):
        mounts += [_Mount("tmpfs", "", str(target), False) for target in tmpfs]
    else:
        problems.append(f"HostConfig.Tmpfs cannot be read: {tmpfs!r:.200}")
    return mounts, problems


def parse_volume(spec: str) -> _Mount | None:
    """A ``-v``/``HostConfig.Binds`` entry: ``/src:/dst[:opts]`` is a bind, ``name:/dst`` a
    named volume and ``/dst`` an anonymous one. None if it cannot be read."""
    parts = spec.split(":")
    if len(parts) == 1:
        return _Mount("volume", "", parts[0], False, origin="-v")
    if len(parts) > 3 or not parts[0] or not parts[1]:
        return None
    options = parts[2].split(",") if len(parts) == 3 else []
    kind = "bind" if parts[0].startswith("/") else "volume"
    return _Mount(
        kind,
        parts[0] if kind == "bind" else "",
        parts[1],
        "ro" in options,
        name="" if kind == "bind" else parts[0],
        origin="-v",
    )


@dataclass
class _Context:
    policy: MountPolicy
    host: HostView
    _points: list[str] | None = None
    _points_read: bool = False

    def mount_problems(self, mount: _Mount) -> list[str]:
        if mount.kind == "tmpfs":
            return []  # private memory: it shows nothing of the host, wherever it lands
        problems = []
        dest = mount.destination
        if PurePosixPath(dest or "/") == PurePosixPath("/"):
            problems.append(f"something is mounted over the container's root: {mount.source!r}")
        if any(_within(dest, view) for view in _KERNEL_VIEWS):
            problems.append(f"{dest} is mounted from the host over the kernel's /proc or /sys")
        if mount.kind == "volume":
            name = mount.name or "(anonymous)"
            problems.append(
                f"a Docker volume {name} is mounted at {dest}: the agent gets no Docker volume"
            )
            if mount.source:
                problems += self._path_problems(mount.source, dest, expected=False)
            return problems
        if mount.kind != "bind":
            return [*problems, f"a {mount.kind or 'mount of no type'} is mounted at {dest}"]
        expected = self._expected(mount)
        if expected is None:
            problems.append(
                f"{mount.source} is mounted at {dest}: the agent may only see its workspace, "
                "its config and the CA certificate"
            )
        elif expected.read_only and not mount.read_only:
            problems.append(f"{dest} is writable: the agent must only read it")
        return problems + self._path_problems(mount.source, dest, expected=expected is not None)

    def _expected(self, mount: _Mount) -> ExpectedBind | None:
        real = self.host.realpath(mount.source)
        for bind in self.policy.binds:
            if bind.destination == mount.destination and self.host.realpath(bind.source) == real:
                return bind
        return None

    def _path_problems(self, source: str, dest: str, *, expected: bool) -> list[str]:
        """What a host path mounted at ``dest`` would show, symlinks resolved."""
        real = self.host.realpath(source)
        shown = f"{source}" if real == source else f"{source} (really {real})"
        problems = []
        for item in self.policy.protected:
            protected = self.host.realpath(str(item.path))
            if _within(protected, real):
                problems.append(f"{shown}, mounted at {dest}, holds {item.label} ({item.path})")
            elif _within(real, protected) and not (item.inside_ok and expected):
                problems.append(f"{shown}, mounted at {dest}, is inside {item.label}")
        for root in (*SENSITIVE_ROOTS, *self.host.homes()):
            if _within(root, real):
                problems.append(f"{shown}, mounted at {dest}, would show the host's {root}")
                break
        for folder in NEVER_INSIDE:
            if _within(real, folder) and real != folder:
                problems.append(f"{shown}, mounted at {dest}, is inside the host's {folder}")
                break
        kind = self.host.kind(real)
        if real in DOCKER_SOCKETS or os.path.basename(real) == "docker.sock":
            problems.append(f"{shown}, mounted at {dest}, is Docker's socket")
        elif kind == "socket":
            problems.append(
                f"{shown}, mounted at {dest}, is a Unix socket (Docker's, under another name?)"
            )
        elif kind == "device":
            problems.append(f"{shown}, mounted at {dest}, is a device of the host")
        points = self._mount_points()
        if points is None:
            problems.append("the host's mount table cannot be read: nothing mounted is checked")
        else:
            below = sorted(p for p in points if _within(p, real) and p != real)
            if below:
                problems.append(
                    f"the host has mounts inside {shown} ({', '.join(below[:3])}): Docker would "
                    f"carry them to {dest}"
                )
        return problems

    def _mount_points(self) -> list[str] | None:
        if not self._points_read:
            self._points = self.host.mount_points()
            self._points_read = True
        return self._points


def _within(path: str, folder: object) -> bool:
    """``path`` is ``folder`` or inside it (by name: both resolved already)."""
    try:
        return PurePosixPath(path).is_relative_to(PurePosixPath(str(folder)))
    except (TypeError, ValueError):
        return False


# --- the planned container: docker_create_argv as docker inspect would show it ---------------

# Options of `docker create` that take a value (in either ``--x v`` or ``--x=v`` form), and
# those that do not. Anything else is unknown, and an unknown option is a problem: whatever it
# does has not been checked.
_VALUE_OPTIONS = frozenset(
    {
        "--name", "--hostname", "-h", "--user", "-u", "--cap-drop", "--cap-add",
        "--security-opt", "--network", "--net", "--restart", "--memory", "-m", "--memory-swap",
        "--pids-limit", "--cpus", "--stop-timeout", "--log-driver", "--log-opt", "--tmpfs",
        "--volume", "-v", "--mount", "--env", "-e", "--entrypoint", "--pid", "--ipc", "--uts",
        "--userns", "--cgroupns", "--device", "--device-cgroup-rule", "--gpus",
        "--volumes-from", "--volume-driver", "--workdir", "-w", "--label", "-l",
        "--network-alias", "--stop-signal",
    }
)  # fmt: skip
_FLAG_OPTIONS = frozenset({"--read-only", "--privileged", "--init", "--interactive", "-i"})
_LIST_KEYS = {
    "--cap-add": "CapAdd",
    "--cap-drop": "CapDrop",
    "--security-opt": "SecurityOpt",
    "--device": "Devices",
    "--device-cgroup-rule": "DeviceCgroupRules",
    "--gpus": "DeviceRequests",
    "--volumes-from": "VolumesFrom",
}
_TEXT_KEYS = {
    "--pid": "PidMode",
    "--ipc": "IpcMode",
    "--uts": "UTSMode",
    "--userns": "UsernsMode",
    "--cgroupns": "CgroupnsMode",
    "--network": "NetworkMode",
    "--net": "NetworkMode",
    "--volume-driver": "VolumeDriver",
}
# What Docker masks in /proc and /sys unless told not to (the list itself is the daemon's).
_DOCKER_MASKS = ["(Docker's default masks)"]
_NO_MASKS = "systempaths=unconfined"


def planned_info(argv: Sequence[str]) -> tuple[dict[str, Any], list[str]]:
    """``docker create`` arguments (without the program name) as the parts of ``docker
    container inspect`` that exposure_problems reads, and what could not be read."""
    args = list(argv)
    problems: list[str] = []
    if not args or args[0] not in ("create", "run"):
        return {}, [f"not a docker create command: {args[:1]!r}"]
    host: dict[str, Any] = {"MaskedPaths": _DOCKER_MASKS, "ReadonlyPaths": _DOCKER_MASKS}
    mounts: list[dict[str, Any]] = []
    for option, value in _options(args[1:], problems):
        if option == "--privileged":
            host["Privileged"] = True
        elif option in _LIST_KEYS:
            host.setdefault(_LIST_KEYS[option], []).append(value)
        elif option in _TEXT_KEYS:
            key = _TEXT_KEYS[option]
            if not _shares(host.get(key)):  # given twice: a shared namespace is kept
                host[key] = value
        elif option in ("--volume", "-v"):
            mount = parse_volume(value)
            if mount is None:
                problems.append(f"cannot read --volume {value!r}")
            else:
                mounts.append(_listed(mount))
        elif option == "--mount":
            mounts.append(_mount_option(value))
        elif option == "--tmpfs":
            host.setdefault("Tmpfs", {})[value.split(":", 1)[0]] = value.partition(":")[2]
    unmasked = any(o.replace(" ", "") == _NO_MASKS for o in host.get("SecurityOpt") or [])
    if host.get("Privileged") or unmasked:
        host["MaskedPaths"] = host["ReadonlyPaths"] = []
    return {"HostConfig": host, "Mounts": mounts}, problems


def _options(args: list[str], problems: list[str]) -> Iterable[tuple[str, str]]:
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-"):
            return  # the image: what follows is the command
        name, eq, inline = arg.partition("=")
        if name in _FLAG_OPTIONS:
            yield name, ""
            i += 1
        elif name in _VALUE_OPTIONS:
            if eq:
                yield name, inline
                i += 1
            elif i + 1 < len(args):
                yield name, args[i + 1]
                i += 2
            else:
                problems.append(f"{name} has no value")
                return
        else:
            problems.append(f"unknown docker create option {name!r}: it has not been checked")
            return


def _listed(mount: _Mount) -> dict[str, Any]:
    return {
        "Type": mount.kind,
        "Source": mount.source,
        "Destination": mount.destination,
        "RW": not mount.read_only,
        "Name": mount.name,
    }


def _mount_option(value: str) -> dict[str, Any]:
    """``--mount type=bind,source=/a,target=/b,readonly``."""
    fields: dict[str, str] = {}
    for part in value.split(","):
        key, _, item = part.partition("=")
        fields[key.strip()] = item.strip()
    kind = fields.get("type", "volume")
    source = fields.get("source", fields.get("src", ""))
    read_only = "readonly" in fields or "ro" in fields
    if fields.get("readonly") in ("false", "0") or fields.get("ro") in ("false", "0"):
        read_only = False
    return {
        "Type": kind,
        "Source": source if kind == "bind" else "",
        "Destination": fields.get("target", fields.get("destination", fields.get("dst", ""))),
        "RW": not read_only,
        "Name": source if kind == "volume" else "",
    }
