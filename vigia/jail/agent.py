"""The agent's container: set it up, start it, wait until it is ready and pause it for rewinds.

Design: docs/13-diseno-t03-jaula.md. Synchronous, like SnapshotStore: async callers use
``asyncio.to_thread``.

- Setup is idempotent: ensure_network(), prepare_workspace() and write_config() create what is
  missing and check what exists, refusing (JailError) anything they cannot trust.
- Nothing here follows a symlink below the workspace: the agent controls everything inside
  ``agente/``, and a symlink there must never make Vigía change, or Docker mount, a host path.
- quiesce() is what SnapshotStore.restore() takes: the container is stopped around the swap and
  started again afterwards, so Docker re-resolves the bind mount and the agent sees the
  rewound workspace (a running container would keep the old one mounted).
- create() and start() refuse an agent that shares Vigía's uid or gid (see AgentJailConfig),
  and start() refuses a container that is not exactly this config's jail (vigia/jail/verify.py)
  or whose mounted config folder holds anything but openclaw.json.
- Whatever comes out of the container (exec output, logs) is the agent's: bounded in size,
  sanitized before it reaches a message, and never trusted to configure Vigía's own probes.
"""

import json
import logging
import os
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vigia.jail import docker
from vigia.jail.config import (
    AGENT_DIR,
    AGENT_SUBDIRS,
    CONFIG_FILE,
    HEALTH_URL,
    READY_LOG_LINE,
    AgentJailConfig,
    docker_create_argv,
    network_create_argv,
    openclaw_config,
    token_env,
)
from vigia.jail.docker import JailError
from vigia.jail.openclaw import check_rewindable
from vigia.jail.verify import container_problems

logger = logging.getLogger(__name__)

POLL_INTERVAL = 0.5  # seconds between two readiness checks
EXEC_TIMEOUT = 60.0
EXEC_MAX_OUTPUT = 1024 * 1024  # bytes a docker exec may print by default
HEALTH_TIMEOUT = 15.0  # one /healthz probe, docker exec included
HEALTH_MAX_OUTPUT = 64 * 1024  # /healthz answers with a few bytes of JSON
# -q first: curl must not read a .curlrc from HOME, which is the agent's /workspace/home (one
# with `url = file:///dev/zero` and `next` made this probe print 1 GB/s). The agent can still
# trace curl or answer on the Gateway's port itself, so the output is bounded as well.
HEALTH_PROBE = (
    "curl", "-q", "--fail", "--silent", "--max-time", "5", "--max-filesize", "4096", HEALTH_URL,
)  # fmt: skip
LOGS_MAX_OUTPUT = 1024 * 1024  # the logs of one start, read until [gateway] ready shows up
LOG_TAIL_LINES = 20
LOG_TAIL_MAX_OUTPUT = 512 * 1024  # 20 log entries of at most 16 KiB each, with room to spare
AGENT_DIR_MODE = 0o700
CONFIG_DIR_MODE = 0o750  # group: the agent's gid, so it can read its config and nothing else
CONFIG_FILE_MODE = 0o640
_TMP_CONFIG = f".{CONFIG_FILE}.tmp"
_NO_SUCH_CONTAINER = "No such container"
_NOT_RUNNING = "is not running"
_NETWORK_NOT_FOUND = "not found"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

# Whether quiesce starts the agent on exit, given the exception of its body (or None).
type StartIf = Callable[[BaseException | None], bool]


class AgentJail:
    """One agent container, described by an AgentJailConfig. Holds no state of its own:
    every method asks Docker or the disk, so two instances with the same config agree."""

    def __init__(self, config: AgentJailConfig) -> None:
        self.config = config

    # Setup

    def ensure_network(self) -> None:
        """Create the agent's network, or check that the existing one is internal and has no
        host address (isolated gateway). A network that fails the check is never reused."""
        info = self._network_info()
        if info is None:
            try:
                docker.run(network_create_argv(self.config))
            except JailError as error:
                # Someone else may have created it meanwhile; it must then pass the check.
                info = self._network_info()
                if info is None:
                    raise error from None
            else:
                info = self._network_info()
            if info is None:
                raise JailError(f"network {self.config.network} vanished right after creation")
        _check_network(self.config.network, info)

    def remove_network(self) -> None:
        """Remove the agent's network. A missing network is not an error."""
        result = docker.run(["network", "rm", self.config.network], check=False)
        if result.returncode != 0 and _NETWORK_NOT_FOUND not in result.stderr:
            stderr = docker.sanitize(result.stderr.strip())
            raise JailError(
                f"docker network rm {self.config.network} failed: {stderr}",
                returncode=result.returncode,
                stderr=stderr,
            )

    def prepare_workspace(self) -> None:
        """Create ``agente/`` and its ``home``, ``state`` and ``work`` folders where missing,
        owned by the agent's uid and gid with mode 0700.

        Existing folders are only checked (a real directory, owned by the agent's uid): they
        belong to the agent and to its snapshots, so they are never changed. Creating them for
        another uid needs root (JailError otherwise). ``<root>/workspace`` must exist:
        SnapshotStore.init() creates it."""
        workspace_fd = _open_dir(self.config.workspace)
        try:
            agent_fd = self._ensure_agent_dir(workspace_fd, AGENT_DIR, self.config.agent_dir)
            try:
                for name in AGENT_SUBDIRS:
                    path = self.config.agent_dir / name
                    os.close(self._ensure_agent_dir(agent_fd, name, path))
            finally:
                os.close(agent_fd)
        finally:
            os.close(workspace_fd)

    def write_config(self) -> None:
        """Write OpenClaw's config into ``config_dir`` (created when missing), atomically.

        The folder holds only openclaw.json (anything else there is refused, so nothing of
        Vigía is ever mounted by mistake). Folder 0750 and file 0640, owned by Vigía, group the
        agent's gid: the agent can read them, and the mount is read-only anyway. Raises
        ``UnrewindableConfig`` (a ValueError, before touching the disk) when the config has
        authorization that a rewind would revive (docs/20, section 8)."""
        config = openclaw_config(self.config)
        check_rewindable(config)  # an unsafe config is never written (UnrewindableConfig)
        path = self.config.config_dir
        try:
            os.mkdir(path, CONFIG_DIR_MODE)
        except FileExistsError:
            pass
        except OSError as e:
            raise JailError(f"cannot create {path}: {e}") from e
        dir_fd = _open_dir(path)
        try:
            self._check_config_dir(dir_fd, path)
            content = json.dumps(config, indent=2) + "\n"
            self._replace_config(dir_fd, content.encode())
        finally:
            os.close(dir_fd)

    # Lifecycle

    def create(self) -> None:
        """Create the container, stopped. Fails if a container with that name exists."""
        self._check_ids_not_shared()
        self._check_mount_sources()
        docker.run(docker_create_argv(self.config), env=token_env(self.config))

    def start(self) -> None:
        """Start the container. It must exist and be exactly this config's jail (anything
        else, such as a container left by an older Vigía, raises JailError: remove it and
        create it again). Returns before OpenClaw is ready."""
        self._check_ids_not_shared()
        self._check_mount_sources()
        self._check_container()
        docker.run(["start", self.config.name])

    def stop(self) -> None:
        """Stop the container: SIGTERM, then SIGKILL after ``stop_timeout`` seconds."""
        timeout = self.config.stop_timeout
        docker.run(["stop", "--time", str(timeout), self.config.name], timeout=timeout + 60)

    def kill(self) -> None:
        """SIGKILL the container, at once: it runs nothing more. A frozen container must be
        killed, not stopped: ``docker stop`` wakes it up to deliver SIGTERM, and the agent runs
        code again for up to ``stop_timeout`` seconds. A missing or already stopped container
        is not an error."""
        result = docker.run(["kill", self.config.name], check=False)
        if result.returncode == 0:
            return
        if _NO_SUCH_CONTAINER in result.stderr or _NOT_RUNNING in result.stderr:
            return
        stderr = docker.sanitize(result.stderr.strip())
        raise JailError(
            f"docker kill {self.config.name} failed: {stderr}",
            returncode=result.returncode,
            stderr=stderr,
        )

    def remove(self) -> None:
        """Remove the container, running or not. A missing container is not an error."""
        docker.run(["rm", "--force", self.config.name])

    def exists(self) -> bool:
        return self._state() is not None

    def is_running(self) -> bool:
        state = self._state()
        return state is not None and state.get("Running") is True

    def is_paused(self) -> bool:
        """Whether the container is frozen (``docker pause``). Read from Docker, never from
        memory: a frozen container still reports ``Running`` as true."""
        state = self._state()
        return state is not None and state.get("Paused") is True

    def wait_ready(self, timeout: float | None = None) -> None:
        """Wait until this run of the Gateway has logged ``[gateway] ready`` and /healthz
        answers from inside the container. Raises JailError, with the last log lines, if the
        container stops or ``timeout`` (default: the config's) passes first, and also if the
        probe or the logs print more than their bound (the agent is not to be trusted then).
        A frozen container fails at once."""
        timeout = self.config.ready_timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            state = self._state()
            if state is None:
                raise JailError(f"container {self.config.name} does not exist")
            if state.get("Running") is not True:
                raise JailError(
                    f"the agent stopped before it was ready (exit code "
                    f"{state.get('ExitCode')}): {self.log_tail()}"
                )
            if state.get("Paused") is True:
                # Frozen (the pause by space, maybe in the middle of a start): it will not get
                # ready, and waiting would only hold agent_lock for nothing.
                raise JailError(f"the agent {self.config.name} is frozen: it cannot get ready")
            if self._logged_ready(str(state.get("StartedAt", ""))) and self._healthy():
                return
            if time.monotonic() >= deadline:
                raise JailError(f"the agent was not ready after {timeout} s: {self.log_tail()}")
            time.sleep(POLL_INTERVAL)

    @contextmanager
    def quiesce(self, start_if: StartIf | None = None) -> Iterator[None]:
        """Stop the agent on entry and start it again on exit, waiting until it is ready.

        The ``quiesce`` that SnapshotStore.restore() takes. A frozen agent (``docker pause``)
        is killed, never stopped: ``docker stop`` would wake it to run its SIGTERM handler for
        up to ``stop_timeout`` seconds. If stopping fails the body never runs, and the agent is
        started again if it stopped anyway (a CLI timeout does not cancel the daemon's stop).

        Whether it starts on exit: without ``start_if``, if it was running and not frozen on
        entry, even if the body raised (the workspace is then unchanged or rewound, and both
        are fine to run on); an agent that was stopped or frozen was put so on purpose and is
        left stopped. With ``start_if``, that function decides, called with the body's
        exception (or None, or the failed stop's JailError): the Guardian's rewind passes one
        that looks at the error and the space (docs/19, section 4)."""
        state = self._state() or {}
        was_running = state.get("Running") is True
        was_paused = was_running and state.get("Paused") is True
        if was_running:
            try:
                # Read again right before stopping: the space thread freezes without waiting
                # for anyone, and `docker stop` would wake a frozen agent.
                if was_paused or self.is_paused():
                    self.kill()
                else:
                    self.stop()
                if self.is_running():
                    raise JailError(
                        f"container {self.config.name} is still running after being stopped: "
                        "refusing to swap its workspace under it"
                    )
            except JailError as error:
                self._restart_after_failed_stop(error, start_if, was_paused)
                raise
        body_error: BaseException | None = None
        try:
            yield
        except BaseException as error:
            body_error = error
            raise
        finally:
            start = (was_running and not was_paused) if start_if is None else start_if(body_error)
            if start:
                self.start()
                self.wait_ready()

    def _restart_after_failed_stop(
        self, error: JailError, start_if: StartIf | None, was_paused: bool
    ) -> None:
        """quiesce could not stop the agent, so its body never runs. The daemon may have
        stopped it anyway: then start it again, as it was (or as ``start_if`` says). A failure
        to do so is added to ``error`` as a note (the caller raises ``error``)."""
        try:
            if self.is_running():
                return
            if (not was_paused) if start_if is None else start_if(error):
                self.start()
                self.wait_ready()
        except JailError as restart_error:
            error.add_note(
                f"starting the agent again after the failed stop failed too: {restart_error}"
            )

    # Inside the container

    def exec(
        self,
        argv: Sequence[str],
        *,
        check: bool = False,
        timeout: float = EXEC_TIMEOUT,
        max_output: int = EXEC_MAX_OUTPUT,
    ) -> subprocess.CompletedProcess[str]:
        """Run ``argv`` inside the running container as the agent's user (docker exec).

        What it prints is the agent's to choose: more than ``max_output`` bytes raises
        JailError (see docker.run)."""
        user = f"{self.config.uid}:{self.config.gid}"
        return docker.run(
            ["exec", "--user", user, self.config.name, *argv],
            timeout=timeout,
            check=check,
            max_output=max_output,
        )

    def log_tail(self, lines: int = LOG_TAIL_LINES) -> str:
        """The container's last log lines (stdout and stderr), sanitized, for error messages.

        Never raises: when the logs cannot be read it says so instead."""
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

    # Helpers

    def _state(self) -> dict[str, Any] | None:
        """``.State`` of the container, or None if it does not exist."""
        return self._inspect_container("{{json .State}}", "the state of")

    def _inspect_container(self, template: str, what: str) -> dict[str, Any] | None:
        """``docker container inspect`` with a JSON ``template``, or None if it does not
        exist."""
        result = docker.run(
            ["container", "inspect", "--format", template, self.config.name], check=False
        )
        if result.returncode != 0:
            if _NO_SUCH_CONTAINER in result.stderr:
                return None
            stderr = docker.sanitize(result.stderr.strip())
            raise JailError(
                f"cannot inspect container {self.config.name}: {stderr}",
                returncode=result.returncode,
                stderr=stderr,
            )
        return _json_object(result.stdout, f"{what} container {self.config.name}")

    def _check_container(self) -> None:
        """The existing container must be exactly the jail of this config (verify.py)."""
        name = self.config.name
        info = self._inspect_container("{{json .}}", "the settings of")
        if info is None:
            raise JailError(f"container {name} does not exist: create() it first")
        problems = container_problems(
            self.config,
            info,
            seccomp_profile=self._seccomp_profile(),
            image_env=self._image_env(),
        )
        if problems:
            raise JailError(
                f"container {name} is not the jail this Vigía expects: {'; '.join(problems)}. "
                f"Remove it (docker rm -f {name}) and let Vigía create it again"
            )

    def _seccomp_profile(self) -> object:
        path = self.config.seccomp_profile
        try:
            return json.loads(path.read_bytes())
        except (OSError, ValueError) as e:
            raise JailError(f"cannot read the seccomp profile {path}: {e}") from e

    def _image_env(self) -> list[str]:
        """The image's own environment, which Docker merges into the container's."""
        result = docker.run(
            ["image", "inspect", "--format", "{{json .Config.Env}}", self.config.image]
        )
        unexpected = JailError(
            f"unexpected environment for image {self.config.image}: {result.stdout[:200]!r}"
        )
        try:
            env = json.loads(result.stdout)
        except ValueError as e:
            raise unexpected from e
        if env is None:
            return []  # an image without any variable
        if not isinstance(env, list) or not all(isinstance(entry, str) for entry in env):
            raise unexpected
        return env

    def _network_info(self) -> dict[str, Any] | None:
        result = docker.run(
            ["network", "inspect", "--format", "{{json .}}", self.config.network], check=False
        )
        if result.returncode != 0:
            if _NETWORK_NOT_FOUND in result.stderr:
                return None
            stderr = docker.sanitize(result.stderr.strip())
            raise JailError(
                f"cannot inspect network {self.config.network}: {stderr}",
                returncode=result.returncode,
                stderr=stderr,
            )
        return _json_object(result.stdout, f"network {self.config.network}")

    def _logged_ready(self, started_at: str) -> bool:
        if not started_at:
            return False
        result = docker.run(
            ["logs", "--since", started_at, self.config.name],
            check=False,
            max_output=LOGS_MAX_OUTPUT,
        )
        return READY_LOG_LINE in result.stdout or READY_LOG_LINE in result.stderr

    def _healthy(self) -> bool:
        result = self.exec(HEALTH_PROBE, timeout=HEALTH_TIMEOUT, max_output=HEALTH_MAX_OUTPUT)
        if result.returncode != 0:
            return False
        try:
            return json.loads(result.stdout).get("ok") is True
        except (ValueError, AttributeError):
            return False

    def _ensure_agent_dir(self, parent_fd: int, name: str, path: Path) -> int:
        """Open ``name`` below ``parent_fd`` as a directory, creating it for the agent first
        if missing, and return its fd. Never follows a symlink."""
        try:
            os.mkdir(name, AGENT_DIR_MODE, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            created = False
        except OSError as e:
            raise JailError(f"cannot create {path}: {e}") from e
        fd = _open_dir(path, name=name, dir_fd=parent_fd)
        try:
            if created:
                self._give_to_agent(fd, path)
            owner = os.fstat(fd).st_uid
            if owner != self.config.uid:
                raise JailError(
                    f"{path} is owned by uid {owner}, not the agent's {self.config.uid}: "
                    "fix it by hand"
                )
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _give_to_agent(self, fd: int, path: Path) -> None:
        uid, gid = self.config.uid, self.config.gid
        try:
            os.fchmod(fd, AGENT_DIR_MODE)  # mkdir's mode is filtered by the umask
            st = os.fstat(fd)
            if (st.st_uid, st.st_gid) != (uid, gid):
                os.fchown(fd, uid, gid)
        except OSError as e:
            raise JailError(
                f"cannot give {path} to the agent ({uid}:{gid}): Vigía must run as root ({e})"
            ) from e

    def _check_config_dir(self, dir_fd: int, path: Path) -> None:
        _require_owned_by_vigia(dir_fd, path)
        _unlink_if_present(dir_fd, _TMP_CONFIG)  # left by a crash in the middle of a write
        _require_only_the_config(dir_fd, path)
        self._share_with_agent_group(dir_fd, path, CONFIG_DIR_MODE)

    def _replace_config(self, dir_fd: int, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        tmp_path = self.config.config_dir / _TMP_CONFIG
        try:
            fd = os.open(_TMP_CONFIG, flags, CONFIG_FILE_MODE, dir_fd=dir_fd)
        except OSError as e:
            raise JailError(f"cannot create {tmp_path}: {e}") from e
        try:
            self._share_with_agent_group(fd, tmp_path, CONFIG_FILE_MODE)
            _write_all(fd, content, tmp_path)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rename(_TMP_CONFIG, CONFIG_FILE, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError as e:
            raise JailError(f"cannot replace {self.config.config_file}: {e}") from e

    def _share_with_agent_group(self, fd: int, path: Path, mode: int) -> None:
        try:
            os.fchmod(fd, mode)
            if os.fstat(fd).st_gid != self.config.gid:
                os.fchown(fd, -1, self.config.gid)
        except OSError as e:
            raise JailError(
                f"cannot give {path} to group {self.config.gid}: Vigía must run as root ({e})"
            ) from e

    def _check_ids_not_shared(self) -> None:
        """The agent's uid and gid must not be Vigía's: see AgentJailConfig."""
        if self.config.allow_shared_ids:
            return
        shared = []
        if self.config.uid == os.geteuid():
            shared.append(f"uid {self.config.uid}")
        if self.config.gid == os.getegid() or self.config.gid in os.getgroups():
            shared.append(f"gid {self.config.gid}")
        if shared:
            raise JailError(
                f"the agent would share {' and '.join(shared)} with Vigía: give the agent ids "
                "of its own (the default) and run Vigía as root"
            )

    def _check_mount_sources(self) -> None:
        """``docker -v`` would create a missing source as an empty root-owned folder, and it
        follows symlinks: so both sources must already be real directories. The config folder
        is checked again here, right before the agent can see it: Vigía's and nothing else."""
        os.close(_open_dir(self.config.agent_dir))
        config_fd = _open_dir(self.config.config_dir)
        try:
            _require_owned_by_vigia(config_fd, self.config.config_dir)
            _require_only_the_config(config_fd, self.config.config_dir)
        finally:
            os.close(config_fd)
        try:
            st = os.lstat(self.config.config_file)
        except OSError as e:
            raise JailError(f"{self.config.config_file} is missing: run write_config()") from e
        if not stat.S_ISREG(st.st_mode):
            raise JailError(f"{self.config.config_file} is not a regular file")


def _require_owned_by_vigia(dir_fd: int, path: Path) -> None:
    owner = os.fstat(dir_fd).st_uid
    if owner != os.geteuid():
        raise JailError(f"{path} is owned by uid {owner}, not Vigía's {os.geteuid()}")


def _require_only_the_config(dir_fd: int, path: Path) -> None:
    strays = sorted(set(os.listdir(dir_fd)) - {CONFIG_FILE})
    if strays:
        raise JailError(
            f"{path} is mounted into the agent and must hold only {CONFIG_FILE}; "
            f"found {strays}: move them elsewhere (a stray {_TMP_CONFIG}: run write_config())"
        )


def _check_network(name: str, info: dict[str, Any]) -> None:
    """The agent's network must be an internal bridge whose host side has no address."""
    options = info.get("Options") or {}
    problems = []
    if info.get("Driver") != "bridge":
        problems.append(f"driver is {info.get('Driver')!r}, not 'bridge'")
    if info.get("Internal") is not True:
        problems.append("it is not --internal (it has a route out)")
    if options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated":
        problems.append("its IPv4 gateway is not isolated (the host is reachable)")
    if info.get("EnableIPv6") and (
        options.get("com.docker.network.bridge.gateway_mode_ipv6") != "isolated"
    ):
        problems.append("its IPv6 gateway is not isolated (the host is reachable)")
    if problems:
        raise JailError(
            f"network {name} exists but is unsafe for the agent: {'; '.join(problems)}. "
            f"Remove it (docker network rm {name}) and let Vigía create it"
        )


def _open_dir(path: Path, *, name: str | None = None, dir_fd: int | None = None) -> int:
    """Open a directory without following a symlink in its last component."""
    try:
        return os.open(path if name is None else name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError as e:
        raise JailError(f"{path} is missing") from e
    except OSError as e:  # ELOOP: a symlink; ENOTDIR: a file
        raise JailError(f"{path} is not a directory (a symlink or a file?): {e}") from e


def _unlink_if_present(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass


def _write_all(fd: int, content: bytes, path: Path) -> None:
    view = memoryview(content)
    while view:
        try:
            written = os.write(fd, view)
        except OSError as e:
            raise JailError(f"cannot write {path}: {e}") from e
        view = view[written:]


def _json_object(text: str, what: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except ValueError as e:
        raise JailError(f"unexpected output for {what}: {text[:200]!r}") from e
    if not isinstance(value, dict):
        raise JailError(f"unexpected output for {what}: {text[:200]!r}")
    return value
