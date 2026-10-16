"""The service's configuration: one TOML file, the gateway token and the paths.

Design: docs/19-diseno-t04.md, section "Disposición".

- ``/etc/vigia/vigia.toml`` holds paths, numbers and the agent's container options. NEVER a secret:
  the gateway token is read from ``<state_dir>/gateway.token`` (0600), and a ``gateway_token`` key
  in the TOML is refused.
- Tokens live in a ``Secret``, whose ``repr`` and ``str`` are ``[REDACTED]``. Errors about the
  token or its file say the size and the permissions, never the content, and no error quotes the
  TOML either (a syntax error says the line, and that is all).
- State and the agent's volume must be apart: the agent writes the volume, so the black box can
  never live inside it, and the one folder mounted into the agent (the config dir) can never
  contain the state.
- Reading the configuration touches no Docker, no btrfs and no black box. Vigía runs on the host,
  not in a container (docs/19), so these paths are host paths.
"""

import errno
import os
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from vigia.jail.config import AgentJailConfig

DEFAULT_CYCLE_INTERVAL = 120.0  # seconds between two "did anything change?" checks
DEFAULT_PRUNE_INTERVAL = 600.0
MAX_CONFIG_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 1024

STATE_DB = "blackbox.db"
STATE_KEY = "blackbox.key"
STATE_CHECKPOINT = "blackbox.checkpoint"
STATE_TOKEN = "gateway.token"  # noqa: S105 - the file's name, not a secret
STATE_AGENT_CONFIG = "openclaw"
STATE_LOCK = "vigia.lock"
STATE_PENDING = "rewind.pending"
STATE_SOCKET = "control.sock"

_TOP_LEVEL_KEYS = frozenset(
    {"state_dir", "volume", "workspace_limit", "cycle_interval", "prune_interval", "agent"}
)
_OPTIONAL_KEYS = ("workspace_limit", "cycle_interval", "prune_interval")
# The container options a file may change. ``allow_shared_ids`` is a test-only concession and
# ``seccomp_profile`` ships with Vigía, so neither is here; the token is never a setting.
_AGENT_KEYS = frozenset(
    {
        "name", "network", "hostname", "image", "uid", "gid", "memory", "pids_limit", "cpus",
        "tmp_size", "stop_timeout", "ready_timeout", "config_dir",
    }
)  # fmt: skip


class ConfigError(ValueError):
    """The configuration is unusable. The message never contains a secret."""


class Secret:
    """A string that must not reach a log, an error or the black box: it prints as
    ``[REDACTED]``. ``reveal()`` is the only way to read it, so a search for it finds every
    place that uses the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("a Secret holds a str")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED]"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return "[REDACTED]"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a Secret cannot be pickled or copied")


@dataclass(frozen=True)
class ServiceConfig:
    """What the service needs, validated on creation (ConfigError).

    ``state_dir`` is Vigía's own folder (black box, token, the agent's config) and ``volume``
    the root of the snapshot store (``<volume>/workspace`` is the agent's subvolume). ``agent``
    holds overrides of AgentJailConfig's options."""

    state_dir: Path
    volume: Path
    gateway_token: Secret
    workspace_limit: int | None = None
    cycle_interval: float = DEFAULT_CYCLE_INTERVAL
    prune_interval: float = DEFAULT_PRUNE_INTERVAL
    agent: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, path in (("state_dir", self.state_dir), ("volume", self.volume)):
            if not isinstance(path, Path) or not path.is_absolute() or "\0" in str(path):
                raise ConfigError(f"{label} must be an absolute path, got {str(path)!r}")
            _require_no_dotdot(label, path)
        if _overlap(self.state_dir, self.volume):
            raise ConfigError(
                f"state_dir {self.state_dir} and volume {self.volume} must not contain each "
                "other: the agent writes the volume, so Vigía's black box can never live in it"
            )
        if not isinstance(self.gateway_token, Secret):
            raise ConfigError("gateway_token must be a Secret")
        if self.workspace_limit is not None and not _positive_int(self.workspace_limit):
            raise ConfigError(
                f"workspace_limit must be a positive number of bytes, got {self.workspace_limit!r}"
            )
        for label, seconds in (
            ("cycle_interval", self.cycle_interval),
            ("prune_interval", self.prune_interval),
        ):
            if isinstance(seconds, bool) or not isinstance(seconds, int | float) or seconds <= 0:
                raise ConfigError(f"{label} must be a positive number of seconds, got {seconds!r}")
        unknown = sorted(set(self.agent) - _AGENT_KEYS)
        if unknown:
            raise ConfigError(f"unknown [agent] settings: {', '.join(map(repr, unknown))}")
        config_dir = self.agent_config_dir
        _require_no_dotdot("[agent] config_dir", config_dir)
        if self.state_dir.is_relative_to(config_dir):
            raise ConfigError(
                f"the agent's config_dir {config_dir} is mounted into the agent and must not "
                f"contain state_dir {self.state_dir}: the agent would see the black box"
            )
        self.jail_config()  # validates every agent option; the result is rebuilt on demand

    # Where things live (docs/19, "Disposición")

    @property
    def blackbox_db(self) -> Path:
        return self.state_dir / STATE_DB

    @property
    def blackbox_key(self) -> Path:
        return self.state_dir / STATE_KEY

    @property
    def blackbox_checkpoint(self) -> Path:
        return self.state_dir / STATE_CHECKPOINT

    @property
    def gateway_token_file(self) -> Path:
        return self.state_dir / STATE_TOKEN

    @property
    def agent_config_dir(self) -> Path:
        configured = self.agent.get("config_dir")
        return Path(configured) if configured is not None else self.state_dir / STATE_AGENT_CONFIG

    @property
    def lock_file(self) -> Path:
        return self.state_dir / STATE_LOCK

    @property
    def pending_file(self) -> Path:
        return self.state_dir / STATE_PENDING

    @property
    def control_socket(self) -> Path:
        return self.state_dir / STATE_SOCKET

    @property
    def workspace(self) -> Path:
        return self.volume / "workspace"

    def jail_config(self) -> AgentJailConfig:
        """The agent's container settings. It carries the token in the clear (it must reach
        ``docker create``'s environment), so do not log it; AgentJailConfig's repr hides it."""
        options = {key: value for key, value in self.agent.items() if key != "config_dir"}
        try:
            return AgentJailConfig(
                workspace=self.workspace,
                config_dir=self.agent_config_dir,
                gateway_token=self.gateway_token.reveal(),
                **options,
            )
        except ValueError as error:
            raise ConfigError(f"invalid [agent] settings: {error}") from error

    @classmethod
    def from_file(cls, path: Path) -> "ServiceConfig":
        """Read the TOML at ``path`` and the token next to the state. Raises ConfigError."""
        text = _decode(
            _read_file(Path(path), "configuration file", MAX_CONFIG_BYTES, private=False)
        )
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise ConfigError(f"{path} is not valid TOML: {error}") from error
        _reject_unknown(data)
        state_dir = _path(data, "state_dir")
        _require_private_state_dir(state_dir)
        volume = _path(data, "volume")
        agent = data.get("agent", {})
        if not isinstance(agent, dict):
            raise ConfigError("[agent] must be a table")
        agent = dict(agent)
        if "config_dir" in agent:
            agent["config_dir"] = _as_path("[agent] config_dir", agent["config_dir"])
        token_file = state_dir / STATE_TOKEN
        token = _decode(_read_file(token_file, "gateway token file", MAX_TOKEN_BYTES, private=True))
        optional = {key: data[key] for key in _OPTIONAL_KEYS if key in data}
        return cls(
            state_dir=state_dir,
            volume=volume,
            gateway_token=Secret(token.strip()),
            agent=agent,
            **optional,
        )


def _require_private_state_dir(path: Path) -> None:
    """Vigía's state (the lock, the black box's key, the token) lives here: only we may write
    in it, or someone else could swap those files for their own."""
    try:
        info = os.stat(path)
    except OSError as error:
        raise ConfigError(
            f"cannot read state_dir {path}: {os.strerror(error.errno or 0)}"
        ) from None
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError(f"state_dir {path} is not a directory")
    if info.st_uid != os.geteuid():
        raise ConfigError(
            f"state_dir {path} is owned by uid {info.st_uid}, not {os.geteuid()} ({mode:04o})"
        )
    if mode & 0o022:
        raise ConfigError(
            f"state_dir {path} is writable by group or others (mode {mode:04o}): chmod 700 it"
        )


def _reject_unknown(data: dict[str, Any]) -> None:
    unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
    if not unknown:
        return
    hint = ""
    if any("token" in key for key in unknown):
        hint = f" (the gateway token is never set here: it lives in <state_dir>/{STATE_TOKEN})"
    raise ConfigError(f"unknown settings: {', '.join(map(repr, unknown))}{hint}")


def _path(data: dict[str, Any], key: str) -> Path:
    if key not in data:
        raise ConfigError(f"the setting {key!r} is required")
    return _as_path(key, data[key])


def _as_path(label: str, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label} must be a path, got {value!r}")
    path = Path(value)
    if not path.is_absolute():
        raise ConfigError(f"{label} must be an absolute path, got {value!r}")
    if {".", ".."} & set(value.split("/")):  # pathlib would quietly drop the "." parts
        raise ConfigError(f"{label} must not have '..' or '.' components, got {value!r}")
    return path


def _require_no_dotdot(label: str, path: Path) -> None:
    """Containment is checked lexically (``_overlap``), so a ``..`` could hide that a folder is
    really inside another."""
    if ".." in path.parts:
        raise ConfigError(f"{label} must not have '..' components, got {str(path)!r}")


def _read_file(path: Path, what: str, max_bytes: int, *, private: bool) -> bytes:
    """The content of a small file that only its owner may have written (and, if ``private``,
    read). Errors say what the file IS (size, mode, owner), never what it holds. Opens without
    following a symlink or blocking on a FIFO."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ConfigError(f"{what} {path} is a symlink: refusing it") from None
        raise ConfigError(f"cannot open {what} {path}: {os.strerror(error.errno or 0)}") from None
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        facts = f"{info.st_size} bytes, mode {mode:04o}"
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{what} {path} is not a regular file")
        if info.st_uid != os.geteuid():
            raise ConfigError(
                f"{what} {path} is owned by uid {info.st_uid}, not {os.geteuid()} ({facts})"
            )
        if private and mode & 0o077:
            raise ConfigError(
                f"{what} {path} is open to group or others ({facts}): chmod 600 it by hand"
            )
        if not private and mode & 0o022:
            raise ConfigError(f"{what} {path} is writable by group or others ({facts})")
        if info.st_size > max_bytes:
            raise ConfigError(f"{what} {path} is too big ({facts}; the limit is {max_bytes})")
        data = os.read(fd, max_bytes + 1)
    except OSError as error:
        raise ConfigError(f"cannot read {what} {path}: {os.strerror(error.errno or 0)}") from None
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ConfigError(f"{what} {path} is too big (the limit is {max_bytes} bytes)")
    return data


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"the file is not valid UTF-8 ({len(data)} bytes)") from None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _overlap(a: Path, b: Path) -> bool:
    return a.is_relative_to(b) or b.is_relative_to(a)
