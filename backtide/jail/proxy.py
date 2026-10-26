"""The egress proxy's container: set up its network and channel folder, create, start and stop it.

Design: docs/21-diseno-t06-proxy.md, sections 1, 2 and 9. The sibling of agent.py, in the same
style: synchronous, no state of its own (every method asks Docker or the disk), fixed argv.

- The egress network is a plain bridge where only the proxy may be: ensure_network() creates
  it, or checks the existing one (not internal, no IPv6, nobody else on it), and start()
  checks the "nobody else" part again.
- create() and start() refuse a proxy that shares backtide's ids or the agent's (unless the
  VM tests' ``allow_shared_ids``), and check each folder right before Docker mounts it: the
  CA's holds exactly the CA and its dhparam (ca.py writes them), the channel's is the proxy's
  own, and the package is backtide's code. start() refuses a container that is not exactly
  this config's proxy (verify.proxy_container_problems).
- The proxy is untrusted once it runs (it parses what the agent sends): its logs are bounded
  and sanitized before they reach a message, as the agent's are.
- The channel folder is a small tmpfs mounted by backtide (root) in prepare_channel(), so the
  proxy cannot fill the disk of ``state_dir`` (T06-4); create() and start() refuse a channel
  folder that is not that tmpfs. Only the VM tests go without it (``channel_tmpfs=False``).
  An installed backtide finds it already mounted by its systemd unit (docs/25, section 1), and
  takes it only if it is exactly the one ``channel_mount_argv`` would make (T13-3): the topmost
  mount on the folder, a tmpfs named CHANNEL_TMPFS_SOURCE, of the channel's size, mode and ids,
  and ``nosuid,nodev,noexec``. Any other tmpfs found there is refused, never used.
- ``check_agent_network`` (T06-4): on the agent's network there is nobody but the agent and
  the proxy.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backtide.jail import docker
from backtide.jail.ca import CA_FILE, DHPARAM_FILE
from backtide.jail.docker import JailError
from backtide.jail.proxy_config import (
    CHANNEL_TMPFS_SOURCE,
    EGRESS_LABEL,
    READY_LOG_LINE,
    ProxyJailConfig,
    channel_mount_argv,
    network_create_argv,
    proxy_create_argv,
)
from backtide.jail.verify import proxy_container_problems

POLL_INTERVAL = 0.25  # seconds between two readiness checks (it listens in about 0.7 s)
LOGS_MAX_OUTPUT = 1024 * 1024
LOG_TAIL_LINES = 20
LOG_TAIL_MAX_OUTPUT = 512 * 1024
CHANNEL_DIR_MODE = 0o700
_CA_FILES = sorted((CA_FILE, DHPARAM_FILE))
_NO_SUCH_CONTAINER = "No such container"
_NOT_RUNNING = "is not running"
_NETWORK_NOT_FOUND = "not found"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
MOUNTINFO = Path("/proc/self/mountinfo")
MOUNT_TIMEOUT = 30


def run_mount(argv: list[str]) -> None:
    """Run ``mount`` with a fixed argv (backtide runs as root in production)."""
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=MOUNT_TIMEOUT, check=False
    )
    if result.returncode != 0:
        raise JailError(
            f"cannot mount the channel folder's tmpfs (backtide must run as root): "
            f"{docker.sanitize(result.stderr.strip())}"
        )


class ProxyJail:
    """One proxy container, described by a ProxyJailConfig. ``mount`` runs the tmpfs's mount
    and ``mountinfo`` reads the mount table (both replaced by the unit tests)."""

    def __init__(
        self,
        config: ProxyJailConfig,
        *,
        mount: Callable[[list[str]], None] = run_mount,
        mountinfo: Callable[[], str] = lambda: MOUNTINFO.read_text(),
    ) -> None:
        self.config = config
        self._mount = mount
        self._mountinfo = mountinfo

    # Setup

    def ensure_network(self) -> None:
        """Create the egress network, or check that the existing one is safe for the proxy.
        A network that fails the check is never reused."""
        info = self._network_info()
        if info is None:
            try:
                docker.run(network_create_argv(self.config))
            except JailError as error:
                info = self._network_info()  # someone else may have made it meanwhile
                if info is None:
                    raise error from None
            else:
                info = self._network_info()
            if info is None:
                raise JailError(f"network {self.config.network} vanished right after creation")
        self._check_network(info)

    def remove_network(self) -> None:
        """Remove the egress network. A missing network is not an error."""
        result = docker.run(["network", "rm", self.config.network], check=False)
        if result.returncode != 0 and _NETWORK_NOT_FOUND not in result.stderr:
            raise _failed(f"docker network rm {self.config.network}", result)

    def prepare_channel(self) -> None:
        """Create the channel folder (0700, the proxy's own: it makes its socket there) or
        check the existing one, and mount its tmpfs if it is not mounted yet. Giving it to
        another uid, and mounting, need root (JailError otherwise)."""
        path = self.config.channel_dir
        try:
            os.mkdir(path, CHANNEL_DIR_MODE)
        except FileExistsError:
            pass
        except OSError as e:
            raise JailError(f"cannot create {path}: {e}") from e
        if self.config.channel_tmpfs:
            mounted = self._channel_mount()
            if mounted is None:
                os.close(_open_dir(path))  # a real folder, not a symlink, before mounting on it
                self._mount(channel_mount_argv(self.config))
                mounted = self._channel_mount()
                if mounted is None:
                    raise JailError(f"{path} is still not a tmpfs after mounting one on it")
            problem = self._channel_mount_problem(mounted)
            if problem is not None:
                raise JailError(f"{path} is mounted, but not as the channel's tmpfs: {problem}")
        fd = _open_dir(path)
        try:
            uid, gid = self.config.uid, self.config.gid
            try:
                st = os.fstat(fd)
                if (st.st_uid, st.st_gid) != (uid, gid) and st.st_uid == os.geteuid():
                    os.fchown(fd, uid, gid)  # a folder we just made, or ours from before
                os.fchmod(fd, CHANNEL_DIR_MODE)
            except OSError as e:
                raise JailError(
                    f"cannot give {path} to the proxy ({uid}:{gid}): backtide must run as root "
                    f"({e})"
                ) from e
            self._check_channel(fd)
        finally:
            os.close(fd)

    # Lifecycle

    def create(self) -> None:
        """Create the container, stopped. Fails if a container with that name exists."""
        self._check_ids_not_shared()
        self._check_mount_sources()
        docker.run(proxy_create_argv(self.config))

    def start(self) -> None:
        """Start the container: it must exist and be exactly this config's proxy, and the
        egress network must hold nobody else. Returns before mitmproxy listens."""
        self._check_ids_not_shared()
        self._check_mount_sources()
        self._check_container()
        info = self._network_info()
        if info is None:
            raise JailError(f"network {self.config.network} is missing: ensure_network() first")
        self._check_network(info)
        self._empty_channel()
        docker.run(["start", self.config.name])

    def stop(self) -> None:
        timeout = self.config.stop_timeout
        docker.run(["stop", "--time", str(timeout), self.config.name], timeout=timeout + 60)

    def kill(self) -> None:
        """SIGKILL the container. A missing or stopped container is not an error."""
        result = docker.run(["kill", self.config.name], check=False)
        if result.returncode == 0:
            return
        if _NO_SUCH_CONTAINER in result.stderr or _NOT_RUNNING in result.stderr:
            return
        raise _failed(f"docker kill {self.config.name}", result)

    def remove(self) -> None:
        """Remove the container, running or not. A missing container is not an error."""
        docker.run(["rm", "--force", "--volumes", self.config.name])

    def exists(self) -> bool:
        return self._state() is not None

    def is_running(self) -> bool:
        state = self._state()
        return state is not None and state.get("Running") is True

    def wait_ready(self, timeout: float | None = None) -> None:
        """Wait until this start of the proxy has logged that it listens. Raises JailError,
        with the last log lines, if it stops or ``timeout`` (default: the config's) passes."""
        timeout = self.config.ready_timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            state = self._state()
            if state is None:
                raise JailError(f"container {self.config.name} does not exist")
            if state.get("Running") is not True:
                raise JailError(
                    f"the proxy stopped before it was ready (exit code {state.get('ExitCode')}): "
                    f"{self.log_tail()}"
                )
            if self._logged_ready(str(state.get("StartedAt", ""))):
                return
            if time.monotonic() >= deadline:
                raise JailError(f"the proxy was not ready after {timeout} s: {self.log_tail()}")
            time.sleep(POLL_INTERVAL)

    def log_tail(self, lines: int = LOG_TAIL_LINES) -> str:
        """The container's last log lines, sanitized, for error messages. Never raises."""
        try:
            result = docker.run(
                ["logs", "--tail", str(lines), self.config.name],
                check=False,
                max_output=LOG_TAIL_MAX_OUTPUT,
            )
        except JailError as error:
            return f"(no log tail: {error})"
        tail = (result.stdout + result.stderr).strip()
        return docker.sanitize(tail[-docker.MESSAGE_LIMIT :])

    def _empty_channel(self) -> None:
        """The proxy writes its channel folder: nothing it left there outlives a start (a
        planted symlink, a stale socket). Never follows a symlink."""
        fd = _open_dir(self.config.channel_dir)
        try:
            for name in os.listdir(fd):
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                try:
                    if stat.S_ISDIR(st.st_mode):
                        shutil.rmtree(name, dir_fd=fd)
                    else:
                        os.unlink(name, dir_fd=fd)
                except OSError as e:
                    raise JailError(f"cannot empty {self.config.channel_dir}: {e}") from e
        finally:
            os.close(fd)

    def check_agent_network(self, agent_name: str) -> None:
        """Nobody is on the agent's network but the agent and the proxy (JailError otherwise):
        anything else there would be a neighbour the agent reaches without the proxy."""
        result = docker.run(
            ["network", "inspect", "--format", "{{json .Containers}}", self.config.agent_network]
        )
        try:
            containers = json.loads(result.stdout) or {}
        except ValueError as e:
            raise JailError(f"unexpected output for network {self.config.agent_network}") from e
        if not isinstance(containers, dict):
            raise JailError(f"unexpected output for network {self.config.agent_network}")
        names = sorted(
            str(entry.get("Name")) if isinstance(entry, dict) else "?"
            for entry in containers.values()
        )
        others = [name for name in names if name not in {agent_name, self.config.name}]
        if others:
            raise JailError(
                f"the agent's network {self.config.agent_network} holds more than the agent and "
                f"the proxy: {others}. Disconnect them (docker network disconnect)"
            )

    def agent_subnets(self) -> list[str]:
        """The subnets of the agent's network (T20: a local model is never inside one)."""
        result = docker.run(
            ["network", "inspect", "--format", "{{json .IPAM.Config}}", self.config.agent_network]
        )
        try:
            entries = json.loads(result.stdout) or []
        except ValueError as e:
            raise JailError(f"unexpected output for network {self.config.agent_network}") from e
        if not isinstance(entries, list):
            raise JailError(f"unexpected output for network {self.config.agent_network}")
        subnets = [str(e.get("Subnet")) for e in entries if isinstance(e, dict) and e.get("Subnet")]
        if not subnets:
            raise JailError(f"the agent's network {self.config.agent_network} has no subnet")
        return subnets

    def container_id(self) -> str:
        """The running container's full id (its cgroup is named after it)."""
        result = docker.run(["container", "inspect", "--format", "{{.Id}}", self.config.name])
        container_id = result.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise JailError(f"unexpected id for container {self.config.name}")
        return container_id

    def _channel_mount(self) -> "_Mount | None":
        """The topmost mount on the channel folder (the one a process sees), or None."""
        target = os.path.realpath(self.config.channel_dir)
        try:
            table = self._mountinfo()
        except OSError as e:
            raise JailError(f"cannot read the mount table: {e}") from e
        found = [mount for mount in _mounts(table) if mount.point == target]
        return found[-1] if found else None

    def _channel_mount_problem(self, mounted: "_Mount") -> str | None:
        """Why ``mounted`` is not the tmpfs channel_mount_argv makes, or None (T13-3)."""
        return channel_mount_problem(mounted, self.config)

    # Checks

    def _check_ids_not_shared(self) -> None:
        if self.config.allow_shared_ids:
            return
        uid, gid = self.config.uid, self.config.gid
        shared = []
        if uid == os.geteuid():
            shared.append(f"backtide's uid {uid}")
        if gid == os.getegid() or gid in os.getgroups():
            shared.append(f"backtide's gid {gid}")
        if uid == self.config.agent_uid:
            shared.append(f"the agent's uid {uid}")
        if gid == self.config.agent_gid:
            shared.append(f"the agent's gid {gid}")
        if shared:
            raise JailError(
                f"the proxy would share {' and '.join(shared)}: give it ids of its own (the "
                "default) and run backtide as root"
            )

    def _check_mount_sources(self) -> None:
        """``docker -v`` would create a missing source as root and it follows symlinks: every
        source must already be a real directory, holding what it should and nothing more."""
        if self.config.channel_tmpfs:
            mounted = self._channel_mount()
            problem = "nothing is mounted there" if mounted is None else None
            problem = problem or (mounted and self._channel_mount_problem(mounted))
            if problem:
                raise JailError(
                    f"{self.config.channel_dir} is not the channel's tmpfs ({problem}): "
                    "prepare_channel() first"
                )
        fd = _open_dir(self.config.channel_dir)
        try:
            self._check_channel(fd)
        finally:
            os.close(fd)
        _check_ca_dir(self.config.ca_dir)
        package = self.config.package_dir
        fd = _open_dir(package)
        try:
            # Whoever may write the gate's code controls the way out: root's or ours only.
            for name in (".", "gate", "__init__.py", "gate/__init__.py", "gate/main.py"):
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError as e:
                    raise JailError(f"{package} is not backtide's package: no {name} ({e})") from e
                wanted = stat.S_ISDIR if name in (".", "gate") else stat.S_ISREG
                if not wanted(st.st_mode):
                    raise JailError(f"{package / name} is not a regular file or folder")
                if st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:
                    raise JailError(
                        f"{package / name} may be changed by someone but root or backtide"
                    )
        finally:
            os.close(fd)

    def _check_channel(self, fd: int) -> None:
        path = self.config.channel_dir
        st = os.fstat(fd)
        if st.st_uid != self.config.uid:
            raise JailError(
                f"{path} is owned by uid {st.st_uid}, not the proxy's {self.config.uid}: "
                "fix it by hand"
            )
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise JailError(f"{path} is open to group or others: it must be 0700")

    def _check_container(self) -> None:
        name = self.config.name
        info = self._inspect_container("{{json .}}", "the settings of")
        if info is None:
            raise JailError(f"container {name} does not exist: create() it first")
        problems = proxy_container_problems(self.config, info, image_env=self._image_env())
        if problems:
            raise JailError(
                f"container {name} is not the proxy this backtide expects: "
                f"{'; '.join(problems)}. Remove it (docker rm -f {name}) and let backtide "
                "create it again"
            )

    def _check_network(self, info: dict[str, Any]) -> None:
        """A bridge, internal only for the VM tests (then isolated), without IPv6, and with
        nobody on it but the proxy."""
        name = self.config.network
        problems = []
        if info.get("Driver") != "bridge":
            problems.append(f"its driver is {info.get('Driver')!r}, not 'bridge'")
        internal = info.get("Internal") is True
        if internal != self.config.internal_egress:
            problems.append("it is --internal (no way out)" if internal else "it is not --internal")
        if self.config.internal_egress:
            options = info.get("Options") or {}
            if options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated":
                problems.append("its IPv4 gateway is not isolated (the host is reachable)")
        if info.get("EnableIPv6"):
            problems.append("it has IPv6")
        key, _, value = EGRESS_LABEL.partition("=")
        if (info.get("Labels") or {}).get(key) != value:
            problems.append(f"it is not one backtide made (no label {EGRESS_LABEL})")
        containers = info.get("Containers") or {}
        others = sorted(
            str(entry.get("Name")) if isinstance(entry, dict) else str(entry)
            for entry in (containers.values() if isinstance(containers, dict) else [containers])
            if not (
                isinstance(entry, dict)
                and entry.get("Name") in {self.config.name, *self.config.egress_neighbours}
            )
        )
        if others:
            problems.append(f"others are on it: {others}")
        if problems:
            raise JailError(
                f"network {name} is unsafe as the proxy's way out: {'; '.join(problems)}. "
                f"Remove it (docker network rm {name}) and let backtide create it"
            )

    # Docker

    def _state(self) -> dict[str, Any] | None:
        return self._inspect_container("{{json .State}}", "the state of")

    def _inspect_container(self, template: str, what: str) -> dict[str, Any] | None:
        result = docker.run(
            ["container", "inspect", "--format", template, self.config.name], check=False
        )
        if result.returncode != 0:
            if _NO_SUCH_CONTAINER in result.stderr:
                return None
            raise _failed(f"docker container inspect {self.config.name}", result)
        return _json_object(result.stdout, f"{what} container {self.config.name}")

    def _network_info(self) -> dict[str, Any] | None:
        result = docker.run(
            ["network", "inspect", "--format", "{{json .}}", self.config.network], check=False
        )
        if result.returncode != 0:
            if _NETWORK_NOT_FOUND in result.stderr:
                return None
            raise _failed(f"docker network inspect {self.config.network}", result)
        return _json_object(result.stdout, f"network {self.config.network}")

    def _image_env(self) -> list[str]:
        result = docker.run(
            ["image", "inspect", "--format", "{{json .Config.Env}}", self.config.image]
        )
        try:
            env = json.loads(result.stdout)
        except ValueError:
            env = False
        if env is None:
            return []
        if not isinstance(env, list) or not all(isinstance(entry, str) for entry in env):
            raise JailError(f"unexpected environment for image {self.config.image}")
        return env

    def _logged_ready(self, started_at: str) -> bool:
        if not started_at:
            return False
        result = docker.run(
            ["logs", "--since", started_at, self.config.name],
            check=False,
            max_output=LOGS_MAX_OUTPUT,
        )
        return READY_LOG_LINE in result.stdout or READY_LOG_LINE in result.stderr


@dataclass(frozen=True)
class _Mount:
    """One line of a mountinfo table (proc(5)): where, what, and its two option lists."""

    point: str
    fstype: str
    source: str
    options: frozenset[str]  # the mount's own (rw, nosuid...)
    super_options: dict[str, str]  # the filesystem's (size=1024k, mode=700...)


def _mounts(table: str) -> list[_Mount]:
    """Each mount of a mountinfo table, in its order (a later one covers an earlier one)."""
    mounts = []
    for line in table.splitlines():
        before, sep, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not sep or len(fields) < 6 or not tail:
            continue
        supers: dict[str, str] = {}
        for option in (tail[2] if len(tail) > 2 else "").split(","):
            name, _, value = option.partition("=")
            supers[name] = value
        mounts.append(
            _Mount(
                point=_unescape(fields[4]),
                fstype=tail[0],
                source=_unescape(tail[1]) if len(tail) > 1 else "",
                options=frozenset(fields[5].split(",")),
                super_options=supers,
            )
        )
    return mounts


_SIZE_UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3}


def _size_bytes(text: str) -> int | None:
    """``1m``, ``1024k`` or ``1048576`` (how ``mount`` takes a tmpfs size and how the kernel
    shows it) in bytes; None for anything else."""
    unit = _SIZE_UNITS.get(text[-1:].lower(), 1) if text else 1
    digits = text[:-1] if text[-1:].lower() in _SIZE_UNITS else text
    return int(digits) * unit if digits.isdigit() else None


def channel_mount_problem(mounted: _Mount, config: ProxyJailConfig) -> str | None:
    """Why ``mounted`` is not the channel's tmpfs as channel_mount_argv makes it (the systemd
    unit of an installed backtide uses the same options), or None."""
    if mounted.fstype != "tmpfs":
        return f"it is {mounted.fstype}, not tmpfs"
    problems = []
    if mounted.source != CHANNEL_TMPFS_SOURCE:
        problems.append(f"its source is {docker.sanitize(mounted.source, 64)!r}")
    missing = sorted({"rw", "nosuid", "nodev", "noexec"} - mounted.options)
    if missing:
        problems.append(f"it is mounted without {','.join(missing)}")
    supers = mounted.super_options
    if _size_bytes(supers.get("size", "")) != _size_bytes(config.channel_size):
        problems.append(f"its size is {docker.sanitize(supers.get('size', '?'), 32)}")
    wanted = {"mode": f"{CHANNEL_DIR_MODE:o}", "uid": str(config.uid), "gid": str(config.gid)}
    for name, value in wanted.items():
        if supers.get(name, "").lstrip("0") != value.lstrip("0"):
            problems.append(f"its {name} is {docker.sanitize(supers.get(name, '?'), 32)}")
    return "; ".join(problems) or None


def _unescape(field: str) -> str:
    """mountinfo writes space, tab, newline and backslash as octal escapes."""
    for code in ("040", "011", "012", "134"):
        field = field.replace(f"\\{code}", chr(int(code, 8)))
    return field


def _check_ca_dir(path: Path) -> None:
    """The CA's folder: backtide's, not writable by others, holding exactly the CA and its
    dhparam as regular files (ca.py). Nothing else of backtide may reach the proxy."""
    fd = _open_dir(path)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            raise JailError(f"{path} is owned by uid {st.st_uid}, not backtide's {os.geteuid()}")
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise JailError(f"{path} is writable by group or others")
        names = sorted(os.listdir(fd))
        if names != _CA_FILES:
            raise JailError(
                f"{path} is mounted into the proxy and must hold exactly {_CA_FILES}; found "
                f"{names}: let backtide make the CA (backtide/jail/ca.py)"
            )
        for name in names:
            if not stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                raise JailError(f"{path / name} is not a regular file")
    finally:
        os.close(fd)


def _open_dir(path: Path) -> int:
    try:
        return os.open(path, _DIR_FLAGS)
    except FileNotFoundError as e:
        raise JailError(f"{path} is missing") from e
    except OSError as e:  # ELOOP: a symlink; ENOTDIR: a file
        raise JailError(f"{path} is not a directory (a symlink or a file?): {e}") from e


def _failed(command: str, result: Any) -> JailError:
    stderr = docker.sanitize(result.stderr.strip())
    return JailError(f"{command} failed: {stderr}", returncode=result.returncode, stderr=stderr)


def _json_object(text: str, what: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except ValueError as e:
        raise JailError(f"unexpected output for {what}: {text[:200]!r}") from e
    if not isinstance(value, dict):
        raise JailError(f"unexpected output for {what}: {text[:200]!r}")
    return value
