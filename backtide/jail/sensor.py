"""The process sensor's container: Tetragon, its settings, its policy and its lifecycle.

Design: docs/23-diseno-t07-tetragon.md, sections 1 and 2, with the plan Bs of T07-1
("Resultados en la VM"). The sibling of AgentJail: fixed argv, checked with verify.py before
every start, and nothing here is ever mounted into the agent (invariant 1).

- This is, on purpose, the most privileged container of the install: ``--privileged``
  (T07-1, P12: without it Tetragon cannot create its folder in /sys/fs/bpf), ``--pid=host``
  and ``--cgroupns=host``. In exchange it has no network (``--network none``), no ports, no
  environment of backtide's and only its own folders: the events (read-write), tp.d and conf.d
  (read-only) and the kernel's BTF (read-only). Never the black box, the snapshots, ``keys/``,
  the agent's volume or docker.sock.
- Tetragon only observes: the policy has no enforcement action (decision 11).
- Its settings are files in conf.d (one per option, Tetragon's recommended way; nothing shows
  in ``docker inspect``), rewritten from this code on every prepare(), as is the policy in
  tp.d: nothing left on the disk decides. The environment of processes is never turned on.
- Bind sources are never relabelled for SELinux (no ``:z``): a privileged container runs
  unconfined (``spc_t``, T07-1 P2), and relabelling the host's BTF would be wrong.
"""

import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backtide.jail import docker
from backtide.jail.docker import JailError

logger = logging.getLogger(__name__)

# Tetragon v1.7.1 (docs/23, section 1). The tag is for people: the digest decides. Bump the
# digest and the version together, after running test_sensor_assumptions.py in the VM.
TETRAGON_VERSION = "v1.7.1"
IMAGE = (
    "quay.io/cilium/tetragon"
    "@sha256:afc9458ba4bc3f2795da3df6b03d88ce50e175ac3903027de8036e2046b84a02"
)
ENTRYPOINT = "/usr/bin/tetragon"
BTF = Path("/sys/kernel/btf/vmlinux")
PRIVILEGES = ("--privileged", "--pid=host", "--cgroupns=host")
NETWORK = "none"
LOG_DRIVER = "local"
LOG_OPTIONS = {"max-size": "10m", "max-file": "3"}

# Inside the sensor's container.
CONTAINER_BTF = "/var/lib/tetragon/btf"
CONTAINER_EVENTS = "/var/log/tetragon"
CONTAINER_TP = "/etc/tetragon/tetragon.tp.d"
CONTAINER_CONF = "/etc/tetragon/tetragon.conf.d"
SOCKET = "unix:///var/run/tetragon/tetragon.sock"  # gRPC stays inside the container

# On the host, below the sensor's state folder.
EVENTS_DIR = "events"
TP_DIR = "tp.d"
CONF_DIR = "conf.d"
EVENTS_FILE = "tetragon.log"
CURSOR_FILE = "cursor.json"
STATE_MODE = 0o700
EVENTS_MODE = 0o700  # root only: Tetragon writes there, backtide reads
SETTINGS_DIR_MODE = 0o755
SETTINGS_FILE_MODE = 0o644  # Tetragon's settings and policy are not secret

POLICY_FILE = Path(__file__).resolve().parents[2] / "deploy" / "tetragon" / "backtide-connect.yaml"

# The first barrier against secrets in command lines (docs/23, section 5): RE2 rules whose
# capture groups Tetragon replaces with ***** before a line reaches the file. Checked in the VM
# (T07-1, P11) with the capture refined afterwards to ``([^\s"']+)``, so a closing quote stays.
# The second barrier is backtide/sensors/procs.py (redact and its own patterns).
_SECRET_VALUE = r"""([^\s"']+)"""  # noqa: S105 - a pattern, not a secret
REDACTION_RULES: tuple[tuple[str, ...], ...] = (
    (
        r"(?i)(?:authorization|x-api-key|api-key|x-goog-api-key|cookie)[\"']?\s*[:=]\s*"
        r"(?:bearer\s+|basic\s+)?" + _SECRET_VALUE,
    ),
    (r"(?:--?(?:password|passwd|secret|token|api-key|apikey))(?:\s+|=)" + _SECRET_VALUE,),
    (
        r"\b(sk-[A-Za-z0-9_-]{16,})",
        r"\b(gh[pousr]_[A-Za-z0-9]{20,})",
        r"\b(AKIA[A-Z0-9]{16})\b",
        r"(?://[^/\s:@]+:)([^/\s@]+)(?:@)",
    ),
)
# Plan B of T07-1, P10: THROTTLE events carry no process, so no container id, and the
# container filter alone dropped them. Lines are OR-ed.
EXPORT_ALLOWLIST = ({"container_id": ["."]}, {"event_set": ["PROCESS_THROTTLE"]})
# Halves an exec line (T07-1, P11: 1,050 to 525 bytes) and keeps all procs.py reads.
EXEC_FIELDS = (
    "process.exec_id",
    "process.pid",
    "process.uid",
    "process.cwd",
    "process.binary",
    "process.arguments",
    "process.flags",
    "process.start_time",
    "process.docker",
    "process.in_init_tree",
    "process.parent_exec_id",
    "parent.pid",
    "parent.binary",
)

_DOCKER_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", re.ASCII)
_PINNED_IMAGE_RE = re.compile(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", re.ASCII)
_SIZE_RE = re.compile(r"[1-9][0-9]{0,9}[kmg]", re.ASCII)
_CPUS_RE = re.compile(r"(?:[1-9][0-9]{0,2}|0)(?:\.[0-9]{1,2})?", re.ASCII)
_RATE_RE = re.compile(r"[1-9][0-9]{0,6},[1-9][0-9]{0,3}(?:ms|s|m)", re.ASCII)
_ID_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_NO_SUCH_CONTAINER = "No such container"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class SensorJailConfig:
    """Everything that defines the sensor's container. Validated on creation (ValueError).

    ``state_dir`` is ``<state>/sensor``: it holds ``events/``, ``tp.d/``, ``conf.d/`` and the
    reader's ``cursor.json``, and none of it is ever mounted into the agent."""

    state_dir: Path
    name: str = "backtide-sensor"
    image: str = IMAGE
    btf: Path = BTF
    memory: str = "1g"  # T07-1, P14: 102 MiB at rest, 194 MiB at the peak of a flood
    cpus: str = "1"
    stop_timeout: int = 10  # SIGTERM first, so Tetragon unloads its programs itself
    file_max_size_mb: int = 50
    file_max_backups: int = 8
    cgroup_rate: str = "1000,1s"  # exec/exit per second and cgroup, cut in the kernel
    ready_timeout: float = 30.0  # T07-1, P13: ready = a probe exec seen, 1.2 s in the VM

    def __post_init__(self) -> None:
        for label, path in (("state_dir", self.state_dir), ("btf", self.btf)):
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError(f"{label} must be an absolute Path, got {path!r}")
            if any(char in str(path) for char in ":,\n\0"):
                raise ValueError(f"{label} must not contain ':', ',', a newline or NUL: {path}")
        _require_match("name", self.name, _DOCKER_NAME_RE)
        _require_match("image (pinned by digest)", self.image, _PINNED_IMAGE_RE)
        _require_match("memory", self.memory, _SIZE_RE)
        _require_match("cpus", self.cpus, _CPUS_RE)
        _require_match("cgroup_rate", self.cgroup_rate, _RATE_RE)
        if float(self.cpus) <= 0:
            raise ValueError(f"cpus must be positive, got {self.cpus!r}")
        for label, number in (
            ("stop_timeout", self.stop_timeout),
            ("file_max_size_mb", self.file_max_size_mb),
            ("file_max_backups", self.file_max_backups),
        ):
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise ValueError(f"{label} must be a positive integer, got {number!r}")
        if self.ready_timeout <= 0:
            raise ValueError(f"ready_timeout must be positive, got {self.ready_timeout!r}")

    @property
    def events_dir(self) -> Path:
        return self.state_dir / EVENTS_DIR

    @property
    def events_file(self) -> Path:
        return self.events_dir / EVENTS_FILE

    @property
    def tp_dir(self) -> Path:
        return self.state_dir / TP_DIR

    @property
    def conf_dir(self) -> Path:
        return self.state_dir / CONF_DIR

    @property
    def cursor_file(self) -> Path:
        return self.state_dir / CURSOR_FILE


def sensor_settings(config: SensorJailConfig) -> dict[str, str]:
    """Tetragon's settings, one file of conf.d per option (docs/23, section 2). Never
    ``enable-process-environment-variables``: environments carry secrets."""
    return {
        "export-filename": f"{CONTAINER_EVENTS}/{EVENTS_FILE}",
        "export-file-max-size-mb": str(config.file_max_size_mb),
        "export-file-max-backups": str(config.file_max_backups),
        # A compressed rotated file cannot be read halfway: the reader must finish old ones.
        "export-file-compress": "false",
        "export-file-perm": "600",
        "export-allowlist": "\n".join(json.dumps(rule) for rule in EXPORT_ALLOWLIST),
        "field-filters": json.dumps(
            {"event_set": ["PROCESS_EXEC"], "fields": ",".join(EXEC_FIELDS), "action": "INCLUDE"}
        ),
        "cgroup-rate": config.cgroup_rate,
        "redaction-filters": "\n".join(
            json.dumps({"redact": list(rules)}) for rules in REDACTION_RULES
        ),
        "server-address": SOCKET,
        "health-server-address": "",  # empty: no health port at all
        "log-level": "warn",
    }


def policy_text() -> str:
    """The connect policy (deploy/tetragon/backtide-connect.yaml), tested in the VM (P7)."""
    try:
        return POLICY_FILE.read_text()
    except OSError as e:
        raise JailError(f"cannot read the sensor's policy {POLICY_FILE}: {e}") from e


def volume_binds(config: SensorJailConfig) -> list[str]:
    """The only four host paths the sensor sees. -v, so ``docker inspect`` lists them in
    HostConfig.Binds (verify.py wants HostConfig.Mounts empty); a missing source would be
    created as a root folder, so SensorJail.create() checks them first."""
    return [
        f"{config.btf}:{CONTAINER_BTF}:ro",
        f"{config.events_dir}:{CONTAINER_EVENTS}",
        f"{config.tp_dir}:{CONTAINER_TP}:ro",
        f"{config.conf_dir}:{CONTAINER_CONF}:ro",
    ]


def sensor_create_argv(config: SensorJailConfig) -> list[str]:
    """Arguments for ``docker`` (without the program name) that create the sensor, stopped.
    The entrypoint is the image's own, set explicitly so that Cmd is empty and verify.py can
    expect exact values."""
    argv = [
        "create",
        "--name", config.name,
        *PRIVILEGES,
        "--network", NETWORK,
        "--restart", "no",  # the Guardian starts and watches it
        "--memory", config.memory,
        "--memory-swap", config.memory,  # the same value: no swap on top of the limit
        "--cpus", config.cpus,
        "--stop-timeout", str(config.stop_timeout),
        "--log-driver", LOG_DRIVER,
    ]  # fmt: skip
    for name, value in LOG_OPTIONS.items():
        argv += ["--log-opt", f"{name}={value}"]
    for bind in volume_binds(config):
        argv += ["--volume", bind]
    argv += ["--entrypoint", ENTRYPOINT, config.image]
    return argv


class SensorJail:
    """The sensor container of a SensorJailConfig. Holds no state: every method asks Docker
    or the disk. Synchronous, like AgentJail."""

    def __init__(self, config: SensorJailConfig) -> None:
        self.config = config

    # Setup

    def prepare(self) -> None:
        """Create the sensor's folders where missing and (re)write its settings and policy.

        The folders must be real directories owned by backtide; their modes are set again.
        conf.d and tp.d end up holding exactly this code's files (anything else is removed, a
        directory there is refused). The events are left alone."""
        config = self.config
        try:
            os.mkdir(config.state_dir, STATE_MODE)
        except FileExistsError:
            pass
        except OSError as e:
            raise JailError(f"cannot create {config.state_dir}: {e}") from e
        state_fd = _open_dir(config.state_dir)
        try:
            _own(state_fd, config.state_dir, STATE_MODE)
            os.close(_ensure_subdir(state_fd, EVENTS_DIR, config.events_dir, EVENTS_MODE))
            settings = {name: value.encode() for name, value in sensor_settings(config).items()}
            policy = {POLICY_FILE.name: policy_text().encode()}
            for name, path, files in (
                (CONF_DIR, config.conf_dir, settings),
                (TP_DIR, config.tp_dir, policy),
            ):
                fd = _ensure_subdir(state_fd, name, path, SETTINGS_DIR_MODE)
                try:
                    _write_exactly(fd, path, files)
                finally:
                    os.close(fd)
        finally:
            os.close(state_fd)

    # Lifecycle

    def create(self) -> None:
        """Create the container, stopped. Fails if a container with that name exists."""
        self._check_mount_sources()
        docker.run(sensor_create_argv(self.config))

    def start(self) -> None:
        """Start the container. It must exist and be exactly this config's sensor
        (verify.py); anything else raises JailError: remove it and create it again."""
        self._check_mount_sources()
        self._check_container()
        docker.run(["start", self.config.name])

    def stop(self) -> None:
        """SIGTERM (Tetragon unloads its programs), then SIGKILL after ``stop_timeout``."""
        timeout = self.config.stop_timeout
        docker.run(["stop", "--time", str(timeout), self.config.name], timeout=timeout + 60)

    def remove(self) -> None:
        """Remove the container, running or not. A missing container is not an error."""
        docker.run(["rm", "--force", self.config.name])

    def exists(self) -> bool:
        return self._inspect("{{json .State}}") is not None

    def is_running(self) -> bool:
        state = self._inspect("{{json .State}}")
        return isinstance(state, dict) and state.get("Running") is True

    def container_id(self) -> str | None:
        """The container's full id, or None if it does not exist."""
        value = self._inspect("{{json .Id}}")
        if value is None:
            return None
        if not isinstance(value, str) or not _ID_RE.fullmatch(value):
            raise JailError(f"unexpected id for container {self.config.name}: {value!r:.100}")
        return value

    # Helpers

    def _inspect(self, template: str) -> Any:
        """``docker container inspect`` with a JSON ``template``; None if it does not exist."""
        name = self.config.name
        result = docker.run(["container", "inspect", "--format", template, name], check=False)
        if result.returncode != 0:
            if _NO_SUCH_CONTAINER in result.stderr:
                return None
            stderr = docker.sanitize(result.stderr.strip())
            raise JailError(
                f"cannot inspect container {name}: {stderr}",
                returncode=result.returncode,
                stderr=stderr,
            )
        try:
            return json.loads(result.stdout)
        except ValueError as e:
            raise JailError(f"unexpected output inspecting {name}: {result.stdout[:200]!r}") from e

    def _check_container(self) -> None:
        # Imported here: verify.py imports this module's config and builders.
        from backtide.jail.verify import sensor_container_problems

        name = self.config.name
        info = self._inspect("{{json .}}")
        if info is None:
            raise JailError(f"container {name} does not exist: create() it first")
        if not isinstance(info, dict):
            raise JailError(f"unexpected settings for container {name}")
        problems = sensor_container_problems(self.config, info, image_env=self._image_env())
        if problems:
            raise JailError(
                f"container {name} is not the sensor this backtide expects: "
                f"{'; '.join(problems)}. Remove it (docker rm -f {name}) and let backtide "
                "create it again"
            )

    def _image_env(self) -> list[str]:
        """The image's own environment, which Docker copies into the container's."""
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

    def _check_mount_sources(self) -> None:
        """``docker -v`` would create a missing source as a root folder and follows symlinks:
        the three folders must be real directories and the BTF a regular file."""
        config = self.config
        for path in (config.events_dir, config.tp_dir, config.conf_dir):
            os.close(_open_dir(path))
        try:
            st = os.stat(config.btf, follow_symlinks=False)
        except OSError as e:
            raise JailError(f"the kernel's BTF {config.btf} is missing: {e}") from e
        if not stat.S_ISREG(st.st_mode):
            raise JailError(f"the kernel's BTF {config.btf} is not a regular file")


def _require_match(label: str, value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")


def _open_dir(path: Path, *, name: str | None = None, dir_fd: int | None = None) -> int:
    """Open a directory without following a symlink in its last component."""
    try:
        return os.open(path if name is None else name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError as e:
        raise JailError(f"{path} is missing") from e
    except OSError as e:  # ELOOP: a symlink; ENOTDIR: a file
        raise JailError(f"{path} is not a directory (a symlink or a file?): {e}") from e


def _own(fd: int, path: Path, mode: int) -> None:
    """The directory must be backtide's; its mode is set to ``mode``."""
    owner = os.fstat(fd).st_uid
    if owner != os.geteuid():
        raise JailError(f"{path} is owned by uid {owner}, not backtide's {os.geteuid()}")
    try:
        os.fchmod(fd, mode)
    except OSError as e:
        raise JailError(f"cannot set the mode of {path}: {e}") from e


def _ensure_subdir(parent_fd: int, name: str, path: Path, mode: int) -> int:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as e:
        raise JailError(f"cannot create {path}: {e}") from e
    fd = _open_dir(path, name=name, dir_fd=parent_fd)
    try:
        _own(fd, path, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _write_exactly(dir_fd: int, path: Path, files: dict[str, bytes]) -> None:
    """Leave in the directory exactly ``files``, each written atomically (mode 0644)."""
    for entry in os.listdir(dir_fd):
        if entry in files:
            continue
        st = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            raise JailError(f"{path / entry} is a directory: {path} must hold only files")
        logger.warning("removing %s: not one of backtide's sensor files", path / entry)
        os.unlink(entry, dir_fd=dir_fd)
    for name, content in files.items():
        tmp = f".{name}.tmp"
        try:
            fd = os.open(tmp, _NEW_FILE_FLAGS, SETTINGS_FILE_MODE, dir_fd=dir_fd)
            try:
                os.fchmod(fd, SETTINGS_FILE_MODE)  # the mode of open() is filtered by the umask
                view = memoryview(content)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except OSError as e:
            raise JailError(f"cannot write {path / name}: {e}") from e
    os.fsync(dir_fd)
