"""The agent's container: set it up, start it, wait until it is ready and pause it for rewinds.

Design: docs/13-diseno-t03-jaula.md. Synchronous, like SnapshotStore: async callers use
``asyncio.to_thread``.

- Setup is idempotent: ensure_network(), prepare_workspace() and write_config() create what is
  missing and check what exists, refusing (JailError) anything they cannot trust.
- Nothing here follows a symlink below the workspace: the agent controls everything inside
  ``agente/``, and a symlink there must never make backtide change, or Docker mount, a host path.
- quiesce() is what SnapshotStore.restore() takes: the container is stopped around the swap and
  started again afterwards, so Docker re-resolves the bind mount and the agent sees the
  rewound workspace (a running container would keep the old one mounted).
- create() and start() refuse an agent that shares backtide's uid or gid (see AgentJailConfig),
  and start() refuses a container that is not exactly this config's jail (backtide/jail/verify.py)
  or whose mounted config folder holds anything but the profile's config files (OpenClaw:
  openclaw.json), or whose CA folder holds anything but the certificate (ca.py writes it; the
  CA's key never goes there).
- What the agent is (its folders in /workspace, its config files, how it says it is ready)
  comes from the config's agent profile (backtide/jail/profile.py); every check here is the
  same for every agent.
- The mount check (T14a, backtide/jail/mounts.py): create() refuses a planned container, and
  start() an existing one, that would show the agent what it must not (ExposedJail); right
  after ``docker start`` the running container is checked again and killed if it does.
  running_exposure() is the same check for the Guardian's cycle. A running container must also
  still be the very container start() checked (its Id: one recreated by hand under backtide,
  even with the same mounts, is not), still be this config's jail (verify.py, against the
  seccomp profile and image environment start() used: ``docker update`` changes some fields)
  and have nothing mounted inside it that Docker does not know about (mounts.py,
  live_mount_problems).
- Whatever comes out of the container (exec output, logs) is the agent's: bounded in size,
  sanitized before it reaches a message, and never trusted to configure backtide's own probes.
"""

import json
import logging
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backtide.jail import docker
from backtide.jail.ca import certificates_only
from backtide.jail.config import (
    AGENT_DIR,
    CA_CERT_FILE,
    AgentJailConfig,
    docker_create_argv,
    network_create_argv,
    token_env,
)
from backtide.jail.docker import JailError
from backtide.jail.mounts import (
    agent_policy,
    exposure_problems,
    live_mount_problems,
    planned_info,
)
from backtide.jail.verify import container_problems

logger = logging.getLogger(__name__)

POLL_INTERVAL = 0.5  # seconds between two readiness checks
EXEC_TIMEOUT = 60.0
EXEC_MAX_OUTPUT = 1024 * 1024  # bytes a docker exec may print by default
HEALTH_TIMEOUT = 15.0  # one run of the profile's ready probe, docker exec included
HEALTH_MAX_OUTPUT = 64 * 1024  # OpenClaw's /healthz answers with a few bytes of JSON
LOGS_MAX_OUTPUT = 1024 * 1024  # the logs of one start, read until the ready line shows up
LOG_TAIL_LINES = 20
LOG_TAIL_MAX_OUTPUT = 512 * 1024  # 20 log entries of at most 16 KiB each, with room to spare
AGENT_DIR_MODE = 0o700
CONFIG_DIR_MODE = 0o750  # group: the agent's gid, so it can read its config and nothing else
CONFIG_FILE_MODE = 0o640
_NO_SUCH_CONTAINER = "No such container"
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_NOT_RUNNING = "is not running"
_NOT_PAUSED = "is not paused"
PAUSE_TIMEOUT = 10.0  # seconds for docker pause / unpause, which take milliseconds
_NETWORK_NOT_FOUND = "not found"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CA_CERT_MAX = 64 * 1024  # one PEM certificate is about 2 KB

# Whether quiesce starts the agent on exit, given the exception of its body (or None).
type StartIf = Callable[[BaseException | None], bool]


class ExposedJail(JailError):
    """The agent's container would see, or sees, what it must not (T14a, mounts.py), or is no
    longer the jail backtide started: it is not created, not started, or killed. ``problems``
    says what, one sentence each; ``still_running`` that the kill failed too."""

    def __init__(self, message: str, problems: list[str], *, still_running: bool = False) -> None:
        super().__init__(message)
        self.problems = list(problems)
        self.still_running = still_running


@dataclass(frozen=True)
class _Checked:
    """A container start() checked: its Id, and the seccomp profile and image environment it
    was checked against (both fixed for the container's whole life)."""

    container_id: str
    seccomp_profile: object
    image_env: list[str]


class AgentJail:
    """One agent container, described by an AgentJailConfig. Holds no state of its own but
    one thing: the container it last started and checked (``running_exposure`` compares the
    running one with it). Everything else is asked of Docker or the disk."""

    def __init__(self, config: AgentJailConfig) -> None:
        self.config = config
        self._started: _Checked | None = None

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
        """Create ``agente/`` and the profile's folders in it (OpenClaw: ``home``, ``state`` and
        ``work``) where missing, owned by the agent's uid and gid with mode 0700.

        Existing folders are only checked (a real directory, owned by the agent's uid): they
        belong to the agent and to its snapshots, so they are never changed. Creating them for
        another uid needs root (JailError otherwise). ``<root>/workspace`` must exist:
        SnapshotStore.init() creates it. Nothing is created for a container that would show
        the agent what it must not (ExposedJail)."""
        self._check_planned("is not prepared")
        workspace_fd = _open_dir(self.config.workspace)
        try:
            agent_fd = self._ensure_agent_dir(workspace_fd, AGENT_DIR, self.config.agent_dir)
            try:
                for name in self.config.profile.workspace_dirs:
                    path = self.config.agent_dir / name
                    os.close(self._ensure_agent_dir(agent_fd, name, path))
            finally:
                os.close(agent_fd)
        finally:
            os.close(workspace_fd)

    def write_config(self) -> None:
        """Write the profile's config files into ``config_dir`` (created when missing), each
        atomically (OpenClaw: openclaw.json; a profile may write none, and the folder is still
        there, empty).

        The folder holds only those files (anything else there is refused, so nothing of
        backtide is ever mounted by mistake). Folder 0750 and files 0640, owned by backtide,
        group the agent's gid: the agent can read them, and the mount is read-only anyway.
        Raises the profile's ProfileError (a ValueError, before touching the disk) when the
        config cannot be run safely: OpenClaw's ``UnrewindableConfig``, for authorization that
        a rewind would revive (docs/20, section 8)."""
        profile = self.config.profile
        files = dict(profile.render_config(self.config))
        if sorted(files) != sorted(profile.config_names) or not all(
            isinstance(text, str) for text in files.values()
        ):
            raise JailError(
                f"profile {profile.name} rendered {sorted(files)}, not its config files "
                f"{sorted(profile.config_names)}"
            )
        profile.check_config(files)  # an unsafe config is never written (ProfileError)
        self._check_planned("gets no config")  # never written where the agent must not look
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
            for name in profile.config_names:
                self._replace_config(dir_fd, name, files[name].encode())
        finally:
            os.close(dir_fd)

    # Lifecycle

    def create(self) -> None:
        """Create the container, stopped. Fails if a container with that name exists, and
        refuses (ExposedJail) a container that would show the agent what it must not."""
        self._check_ids_not_shared()
        self._check_mount_sources()
        self._check_planned("is not created")
        docker.run(docker_create_argv(self.config), env=token_env(self.config))

    def start(self) -> None:
        """Start the container. It must exist and be exactly this config's jail (anything
        else, such as a container left by an older backtide, raises JailError: remove it and
        create it again). Returns before the agent is ready."""
        self._check_ids_not_shared()
        self._check_mount_sources()
        checked = self._check_container()
        self._started = None  # whatever ran before is not what runs now
        docker.run(["start", self.config.name])
        self._check_started(checked)

    def running_exposure(self) -> list[str]:
        """What is wrong with the running container (T14a): it shows the agent what it must
        not, it is not the container start() checked (recreated under backtide), it is no
        longer this config's jail (``docker update``), or something is mounted inside it that
        Docker does not know about. Empty if nothing is, or if no container runs. A container
        that cannot be inspected, and a check that fails, are problems: what cannot be checked
        does not run."""
        return self._running_problems(self._started)

    def _running_problems(self, checked: _Checked | None) -> list[str]:
        try:
            info = self._inspect_container("{{json .}}", "the settings of")
        except JailError as error:
            return [f"the agent's container cannot be inspected: {error}"]
        if info is None:
            return []
        state = info.get("State")
        if isinstance(state, dict) and state.get("Running") is False:
            return []
        try:
            return self._problems_of_running(info, checked)
        except Exception as error:  # a check that fails is never a pass (B1 of the review)
            logger.exception("the check of the agent's running container failed")
            return [f"the check of the agent's container failed: {type(error).__name__}: {error}"]

    def _problems_of_running(self, info: dict[str, Any], checked: _Checked | None) -> list[str]:
        if checked is None:
            return [
                "it runs, but this backtide did not start it (or its checks failed when it did)",
                *self._exposure(info),
            ]
        problems = []
        running_id = info.get("Id")
        if running_id != checked.container_id:
            problems.append(
                "it is not the container backtide started and checked: it was recreated "
                f"(Id {checked.container_id[:12]} is now {str(running_id)[:12]})"
            )
        problems += self._exposure(info)
        problems += live_mount_problems(info, agent_policy(self.config))
        problems += [
            f"it is no longer the jail: {problem}"
            for problem in container_problems(
                self.config,
                info,
                seccomp_profile=checked.seccomp_profile,
                image_env=checked.image_env,
            )
        ]
        return list(dict.fromkeys(problems))

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

    def pause(self) -> None:
        """Freeze every process of the container (``docker pause``, the cgroup freezer): they
        keep their memory and connections and run nothing until ``unpause``. Takes a few
        milliseconds, so a CLI that hangs is cut after ``PAUSE_TIMEOUT``. Any failure raises
        JailError, also a container that is missing or not running: the caller decides what
        an agent that could not be frozen means (the Guardian kills it)."""
        docker.run(["pause", self.config.name], timeout=PAUSE_TIMEOUT)

    def unpause(self) -> None:
        """Thaw a frozen container. One that is not frozen is not an error."""
        result = docker.run(["unpause", self.config.name], check=False, timeout=PAUSE_TIMEOUT)
        if result.returncode == 0 or _NOT_PAUSED in result.stderr:
            return
        stderr = docker.sanitize(result.stderr.strip())
        raise JailError(
            f"docker unpause {self.config.name} failed: {stderr}",
            returncode=result.returncode,
            stderr=stderr,
        )

    def remove(self) -> None:
        """Remove the container, running or not. A missing container is not an error."""
        docker.run(["rm", "--force", "--volumes", self.config.name])

    def exists(self) -> bool:
        return self._state() is not None

    def is_running(self) -> bool:
        state = self._state()
        return state is not None and state.get("Running") is True

    def container_id(self) -> str | None:
        """The container's full id (64 hex characters), or None if it does not exist. The
        process sensor attributes events by it (T07-3)."""
        result = docker.run(
            ["container", "inspect", "--format", "{{json .Id}}", self.config.name], check=False
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
        try:
            value = json.loads(result.stdout)
        except ValueError:
            value = None
        if not isinstance(value, str) or not _CONTAINER_ID_RE.fullmatch(value):
            raise JailError(
                f"unexpected id for container {self.config.name}: {result.stdout[:100]!r}"
            )
        return value

    def is_paused(self) -> bool:
        """Whether the container is frozen (``docker pause``). Read from Docker, never from
        memory: a frozen container still reports ``Running`` as true."""
        state = self._state()
        return state is not None and state.get("Paused") is True

    def wait_ready(self, timeout: float | None = None) -> None:
        """Wait until this run of the agent is ready as its profile says: it has logged the
        profile's ready line and the ready probe answers from inside the container (OpenClaw:
        ``[gateway] ready``, and /healthz says ``{"ok": true}``); without either, once it runs.
        Raises JailError, with the last log lines, if the
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

    def _check_planned(self, what: str) -> None:
        """The container docker_create_argv would make shows the agent nothing it must not
        (mounts.py, symlinks resolved): checked before anything is set up for it."""
        info, unreadable = planned_info(docker_create_argv(self.config))
        self._refuse_exposure(unreadable + self._exposure(info), what)

    def _exposure(self, info: dict[str, Any]) -> list[str]:
        return exposure_problems(info, agent_policy(self.config))

    def _refuse_exposure(
        self, problems: list[str], what: str, *, still_running: bool = False
    ) -> None:
        if problems:
            name = self.config.name
            raise ExposedJail(
                f"the agent's container {name} {what}: it would see what it must not: "
                f"{'; '.join(problems)}. Remove it (docker rm -f {name}), check backtide's "
                "config, and let backtide create it again",
                problems,
                still_running=still_running,
            )

    def _check_started(self, checked: _Checked) -> None:
        """Right after ``docker start``: the container that runs is the very one checked before
        (it could have been swapped since), and it is still the jail and shows the agent
        nothing it must not. Then it is the one ``running_exposure`` compares with. If it is
        not, or it cannot be told, it is killed."""
        problems = self._running_problems(checked)
        if not problems:
            self._started = checked
            return
        still_running = False
        try:
            self.kill()
        except JailError as error:
            problems.append(f"and it could not be killed: {error}")
            still_running = True
        self._refuse_exposure(
            problems, "was killed right after it started", still_running=still_running
        )

    def _check_container(self) -> _Checked:
        """The existing container must show the agent nothing it must not (mounts.py) and be
        exactly the jail of this config (verify.py). Returns what it was checked with."""
        name = self.config.name
        info = self._inspect_container("{{json .}}", "the settings of")
        if info is None:
            raise JailError(f"container {name} does not exist: create() it first")
        self._refuse_exposure(self._exposure(info), "is not started")
        container_id = info.get("Id")
        if not isinstance(container_id, str) or not _CONTAINER_ID_RE.fullmatch(container_id):
            raise JailError(f"unexpected id for container {name}: {container_id!r:.100}")
        checked = _Checked(container_id, self._seccomp_profile(), self._image_env())
        problems = container_problems(
            self.config,
            info,
            seccomp_profile=checked.seccomp_profile,
            image_env=checked.image_env,
        )
        if problems:
            raise JailError(
                f"container {name} is not the jail this backtide expects: {'; '.join(problems)}. "
                f"Remove it (docker rm -f {name}) and let backtide create it again"
            )
        return checked

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
        line = self.config.profile.ready_log_line
        if not line:
            return True
        if not started_at:
            return False
        result = docker.run(
            ["logs", "--since", started_at, self.config.name],
            check=False,
            max_output=LOGS_MAX_OUTPUT,
        )
        return line in result.stdout or line in result.stderr

    def _healthy(self) -> bool:
        profile = self.config.profile
        if not profile.ready_probe:
            return True
        result = self.exec(
            profile.ready_probe, timeout=HEALTH_TIMEOUT, max_output=HEALTH_MAX_OUTPUT
        )
        return result.returncode == 0 and profile.ready_answer(result.stdout) is True

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
                f"cannot give {path} to the agent ({uid}:{gid}): backtide must run as root ({e})"
            ) from e

    def _check_config_dir(self, dir_fd: int, path: Path) -> None:
        names = self.config.profile.config_names
        _require_owned_by_backtide(dir_fd, path)
        for name in names:
            _unlink_if_present(dir_fd, _tmp_name(name))  # left by a crash in a write
        _require_only_the_config(dir_fd, path, names)
        self._share_with_agent_group(dir_fd, path, CONFIG_DIR_MODE)

    def _replace_config(self, dir_fd: int, name: str, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        tmp = _tmp_name(name)
        tmp_path = self.config.config_dir / tmp
        try:
            fd = os.open(tmp, flags, CONFIG_FILE_MODE, dir_fd=dir_fd)
        except OSError as e:
            raise JailError(f"cannot create {tmp_path}: {e}") from e
        try:
            self._share_with_agent_group(fd, tmp_path, CONFIG_FILE_MODE)
            _write_all(fd, content, tmp_path)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError as e:
            raise JailError(f"cannot replace {self.config.config_dir / name}: {e}") from e

    def _share_with_agent_group(self, fd: int, path: Path, mode: int) -> None:
        try:
            os.fchmod(fd, mode)
            if os.fstat(fd).st_gid != self.config.gid:
                os.fchown(fd, -1, self.config.gid)
        except OSError as e:
            raise JailError(
                f"cannot give {path} to group {self.config.gid}: backtide must run as root ({e})"
            ) from e

    def _check_ids_not_shared(self) -> None:
        """The agent's uid and gid must not be backtide's: see AgentJailConfig."""
        if self.config.allow_shared_ids:
            return
        shared = []
        if self.config.uid == os.geteuid():
            shared.append(f"uid {self.config.uid}")
        if self.config.gid == os.getegid() or self.config.gid in os.getgroups():
            shared.append(f"gid {self.config.gid}")
        if shared:
            raise JailError(
                f"the agent would share {' and '.join(shared)} with backtide: give the agent ids "
                "of its own (the default) and run backtide as root"
            )

    def _check_mount_sources(self) -> None:
        """``docker -v`` would create a missing source as an empty root-owned folder, and it
        follows symlinks: so every source must already be a real directory. The config and CA
        folders are checked again here, right before the agent can see them: backtide's, and
        nothing in them but their one file."""
        os.close(_open_dir(self.config.agent_dir))
        _check_ca_dir(self.config.ca_dir)
        config_fd = _open_dir(self.config.config_dir)
        try:
            _require_owned_by_backtide(config_fd, self.config.config_dir)
            _require_only_the_config(
                config_fd, self.config.config_dir, self.config.profile.config_names
            )
        finally:
            os.close(config_fd)
        for config_file in self.config.config_files:
            try:
                st = os.lstat(config_file)
            except OSError as e:
                raise JailError(f"{config_file} is missing: run write_config()") from e
            if not stat.S_ISREG(st.st_mode):
                raise JailError(f"{config_file} is not a regular file")
            if st.st_nlink != 1:
                raise JailError(
                    f"{config_file} has {st.st_nlink} names (a hard link to another "
                    "file?): run write_config()"
                )


def _require_owned_by_backtide(dir_fd: int, path: Path) -> None:
    owner = os.fstat(dir_fd).st_uid
    if owner != os.geteuid():
        raise JailError(f"{path} is owned by uid {owner}, not backtide's {os.geteuid()}")


def _tmp_name(name: str) -> str:
    """Where a config file is written before it replaces the old one."""
    return f".{name}.tmp"


def _require_only_the_config(dir_fd: int, path: Path, names: Sequence[str]) -> None:
    strays = sorted(set(os.listdir(dir_fd)) - set(names))
    if strays:
        only = f"hold only {', '.join(names)}" if names else "be empty"
        tmps = ", ".join(_tmp_name(name) for name in names)
        hint = f" (a stray {tmps}: run write_config())" if names else ""
        raise JailError(
            f"{path} is mounted into the agent and must {only}; "
            f"found {strays}: move them elsewhere{hint}"
        )


def _check_ca_dir(path: Path) -> None:
    """The CA folder the agent sees: backtide's, holding only ``ca.pem``, a regular file. Never
    the key: ca.py writes the certificate alone, and a stray file here is refused."""
    fd = _open_dir(path)
    try:
        _require_owned_by_backtide(fd, path)
        if stat.S_IMODE(os.fstat(fd).st_mode) & 0o022:
            raise JailError(f"{path} is writable by group or others")
        names = sorted(os.listdir(fd))
        if names != [CA_CERT_FILE]:
            raise JailError(
                f"{path} is mounted into the agent and must hold only {CA_CERT_FILE}; found "
                f"{names}: let backtide write it again (backtide/jail/ca.py)"
            )
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            file_fd = os.open(CA_CERT_FILE, flags, dir_fd=fd)
        except OSError as e:  # ELOOP: a symlink
            raise JailError(f"cannot open {path / CA_CERT_FILE}: {e}") from e
        try:
            file_stat = os.fstat(file_fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise JailError(f"{path / CA_CERT_FILE} is not a regular file")
            if file_stat.st_uid != os.geteuid() or stat.S_IMODE(file_stat.st_mode) & 0o022:
                raise JailError(f"{path / CA_CERT_FILE} may be changed by someone but backtide")
            if file_stat.st_nlink != 1:
                raise JailError(
                    f"{path / CA_CERT_FILE} has {file_stat.st_nlink} names (a hard link to "
                    "another file?): let backtide write it again"
                )
            content = os.read(file_fd, _CA_CERT_MAX + 1)
        finally:
            os.close(file_fd)
        # PEM CERTIFICATE blocks and nothing else: no key, no parameters, no stray text.
        if len(content) > _CA_CERT_MAX or not content or certificates_only(content) != content:
            raise JailError(
                f"{path / CA_CERT_FILE} is not just a certificate: refusing to show it to the agent"
            )
    finally:
        os.close(fd)


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
            f"Remove it (docker network rm {name}) and let backtide create it"
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
