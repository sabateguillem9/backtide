"""The service's configuration: one TOML file, the gateway token and the paths.

Design: docs/19-diseno-t04.md, section "Disposición".

- ``/etc/backtide/backtide.toml`` holds paths, numbers and the agent's container options. NEVER a
  secret: the gateway token is read from ``<state_dir>/gateway.token`` (0600), and a
  ``gateway_token`` key in the TOML is refused.
- Tokens live in a ``Secret``, whose ``repr`` and ``str`` are ``[REDACTED]``. Errors about the
  token or its file say the size and the permissions, never the content, and no error quotes the
  TOML either (a syntax error says the line, and that is all).
- State and the agent's volume must be apart: the agent writes the volume, so the black box can
  never live inside it, and the one folder mounted into the agent (the config dir) can never
  contain the state.
- Reading the configuration touches no Docker, no btrfs and no black box. backtide runs on the host,
  not in a container (docs/19), so these paths are host paths.
- ``[proxy]`` (T06, docs/21): the egress proxy's container options, the allowed hosts and the
  model providers (name, kind, host). NEVER a key: the real ones live in ``<state_dir>/keys/``
  (T06-4), and a key-like setting is refused. The proxy's CA and channel folders live in the
  state too, and the agent's config folder may never be or contain any of them.
"""

import errno
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from backtide.jail.ca import CaPaths
from backtide.jail.config import AgentJailConfig
from backtide.jail.proxy_config import ProxyJailConfig

DEFAULT_CYCLE_INTERVAL = 120.0  # seconds between two "did anything change?" checks
DEFAULT_PRUNE_INTERVAL = 600.0
MAX_CONFIG_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 1024

STATE_DB = "blackbox.db"
STATE_KEY = "blackbox.key"
STATE_CHECKPOINT = "blackbox.checkpoint"
STATE_TOKEN = "gateway.token"  # noqa: S105 - the file's name, not a secret
STATE_AGENT_CONFIG = "openclaw"
STATE_LOCK = "backtide.lock"
STATE_PENDING = "rewind.pending"
STATE_SOCKET = "control.sock"
STATE_RULES = "rules.toml"  # the risk rules (T08); absent: the ones that ship with backtide
STATE_PROXY_CA = "proxy-ca"  # the CA's key and certificate: the proxy's /ca (docs/21)
STATE_AGENT_CA = "agent-ca"  # the CA's certificate alone: the agent's /etc/backtide-ca
STATE_PROXY_CHANNEL = "proxy-channel"  # the proxy's folder for the channel's socket
STATE_KEYS = "keys"  # the real keys of the model providers (T06-4): never mounted anywhere
MAX_RULES_BYTES = 64 * 1024

_TOP_LEVEL_KEYS = frozenset(
    {
        "state_dir", "volume", "workspace_limit", "cycle_interval", "prune_interval", "agent",
        "volume_image", "max_volume_bytes", "proxy",
    }
)  # fmt: skip
_OPTIONAL_KEYS = ("workspace_limit", "cycle_interval", "prune_interval", "max_volume_bytes")
# The container options a file may change. ``allow_shared_ids`` is a test-only concession and
# ``seccomp_profile`` ships with backtide, so neither is here; the token is never a setting.
_AGENT_KEYS = frozenset(
    {
        "name", "network", "hostname", "image", "uid", "gid", "memory", "pids_limit", "cpus",
        "tmp_size", "stop_timeout", "ready_timeout", "config_dir",
    }
)  # fmt: skip
# [proxy]: the container options a file may change (``internal_egress`` and ``allow_shared_ids``
# are test-only concessions, so not here), and what the proxy lets out. Never a key.
_PROXY_CONTAINER_KEYS = frozenset(
    {"name", "network", "image", "uid", "gid", "memory", "cpus", "pids_limit"}
)
_PROXY_KEYS = _PROXY_CONTAINER_KEYS | {"allow_hosts", "providers"}
_PROVIDER_KEYS = frozenset({"name", "kind", "host"})
# docs/21, section 6: the providers of T06 and their default hosts.
PROVIDER_HOSTS = {"anthropic": "api.anthropic.com", "openai": "api.openai.com"}
MAX_ALLOW_HOSTS = 1000
MAX_PROVIDERS = 16
_SECRET_WORDS = ("key", "token", "secret", "password", "credential")
_PROVIDER_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}", re.ASCII)
# A host name, or ``*.`` and a domain. Matching (case, trailing dot, IDNA) is the gate's job.
_HOST_RE = re.compile(r"(?:\*\.)?[^\s/\\:@*?#%\[\]]{1,253}")


class ConfigError(ValueError):
    """The configuration is unusable. The message never contains a secret."""


@dataclass(frozen=True)
class Provider:
    """A model provider the proxy knows (docs/21, section 6): its name, its ``kind`` (which
    header carries the key) and its host. Its keys are never here."""

    name: str
    kind: str
    host: str


@dataclass(frozen=True)
class ProxySettings:
    """What ``[proxy]`` says the proxy lets out: the hosts the user allows and the providers."""

    allow_hosts: tuple[str, ...]
    providers: tuple[Provider, ...]


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

    ``state_dir`` is backtide's own folder (black box, token, the agent's config) and ``volume``
    the root of the snapshot store (``<volume>/workspace`` is the agent's subvolume). ``agent``
    holds overrides of AgentJailConfig's options.

    ``volume_image`` (the file behind the volume's loop device) and ``max_volume_bytes`` (the
    size the volume may never pass) go together: with both, a rewind that fails for lack of
    space may grow the volume once (T04e-1, ``backtide.snapshots.grow``); without them it is never
    grown. T13 writes them (by default 1.5 times the installed size)."""

    state_dir: Path
    volume: Path
    gateway_token: Secret
    workspace_limit: int | None = None
    cycle_interval: float = DEFAULT_CYCLE_INTERVAL
    prune_interval: float = DEFAULT_PRUNE_INTERVAL
    agent: Mapping[str, Any] = field(default_factory=dict)
    volume_image: Path | None = None
    max_volume_bytes: int | None = None
    proxy: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, path in (("state_dir", self.state_dir), ("volume", self.volume)):
            if not isinstance(path, Path) or not path.is_absolute() or "\0" in str(path):
                raise ConfigError(f"{label} must be an absolute path, got {str(path)!r}")
            _require_no_dotdot(label, path)
        if _overlap(self.state_dir, self.volume):
            raise ConfigError(
                f"state_dir {self.state_dir} and volume {self.volume} must not contain each "
                "other: the agent writes the volume, so backtide's black box can never live in it"
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
        self._check_growth(config_dir)
        self._check_proxy(config_dir)

    def _check_proxy(self, config_dir: Path) -> None:
        if not isinstance(self.proxy, Mapping):
            raise ConfigError("[proxy] must be a table")
        _reject_secret_keys("[proxy]", self.proxy)
        unknown = sorted(set(self.proxy) - _PROXY_KEYS)
        if unknown:
            raise ConfigError(f"unknown [proxy] settings: {', '.join(map(repr, unknown))}")
        for label, folder in (
            ("the proxy's CA folder", self.proxy_ca_dir),
            ("the agent's CA folder", self.agent_ca_dir),
            ("the proxy's channel folder", self.proxy_channel_dir),
            ("the keys folder", self.keys_dir),
        ):
            if _overlap(config_dir, folder):
                raise ConfigError(
                    f"the agent's config_dir {config_dir} must not be or contain {label} "
                    f"{folder}: the agent would see it"
                )
        self.proxy_settings()
        self.proxy_jail_config()

    def _check_growth(self, config_dir: Path) -> None:
        image, ceiling = self.volume_image, self.max_volume_bytes
        if (image is None) != (ceiling is None):
            raise ConfigError(
                "volume_image and max_volume_bytes go together: set both to let backtide grow the "
                "volume when a rewind runs out of space, or neither"
            )
        if image is None:
            return
        if not isinstance(image, Path) or not image.is_absolute() or "\0" in str(image):
            raise ConfigError(f"volume_image must be an absolute path, got {str(image)!r}")
        _require_no_dotdot("volume_image", image)
        for label, folder in (("volume", self.volume), ("[agent] config_dir", config_dir)):
            if image.is_relative_to(folder):
                raise ConfigError(
                    f"volume_image {image} must not be inside {label} {folder}: the agent "
                    "would see (and could change) the file behind its own volume"
                )
        if not _positive_int(ceiling):
            raise ConfigError(
                f"max_volume_bytes must be a positive number of bytes, got {ceiling!r}"
            )

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
    def rules_file(self) -> Path:
        """The user's risk rules. backtide's own config: it lives in ``state_dir``, which the agent
        never sees (invariant 1)."""
        return self.state_dir / STATE_RULES

    @property
    def proxy_ca_dir(self) -> Path:
        return self.state_dir / STATE_PROXY_CA

    @property
    def agent_ca_dir(self) -> Path:
        return self.state_dir / STATE_AGENT_CA

    @property
    def proxy_channel_dir(self) -> Path:
        return self.state_dir / STATE_PROXY_CHANNEL

    @property
    def keys_dir(self) -> Path:
        return self.state_dir / STATE_KEYS

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
                ca_dir=self.agent_ca_dir,
                gateway_token=self.gateway_token.reveal(),
                **options,
            )
        except ValueError as error:
            raise ConfigError(f"invalid [agent] settings: {error}") from error

    def proxy_jail_config(self) -> ProxyJailConfig:
        """The egress proxy's container settings, on the agent's network and apart from its
        ids. No secret in it."""
        agent = self.jail_config()
        options = {key: value for key, value in self.proxy.items() if key in _PROXY_CONTAINER_KEYS}
        try:
            return ProxyJailConfig(
                ca_dir=self.proxy_ca_dir,
                channel_dir=self.proxy_channel_dir,
                agent_network=agent.network,
                agent_uid=agent.uid,
                agent_gid=agent.gid,
                **options,
            )
        except (TypeError, ValueError) as error:
            raise ConfigError(f"invalid [proxy] settings: {error}") from error

    def ca_paths(self) -> CaPaths:
        """Where ca.py makes the proxy's CA, readable by the proxy's group only."""
        return CaPaths(
            proxy_dir=self.proxy_ca_dir,
            agent_dir=self.agent_ca_dir,
            gid=self.proxy_jail_config().gid,
        )

    def proxy_settings(self) -> ProxySettings:
        """``allow_hosts`` and ``providers`` of ``[proxy]``, checked (ConfigError)."""
        hosts = self.proxy.get("allow_hosts", [])
        if not isinstance(hosts, list) or len(hosts) > MAX_ALLOW_HOSTS:
            raise ConfigError(
                f"[proxy] allow_hosts must be a list of at most {MAX_ALLOW_HOSTS} host names"
            )
        for host in hosts:
            _check_host("[proxy] allow_hosts", host)
        entries = self.proxy.get("providers", [])
        if not isinstance(entries, list) or len(entries) > MAX_PROVIDERS:
            raise ConfigError(f"[proxy] providers must be a list of at most {MAX_PROVIDERS} tables")
        providers = tuple(_provider(entry) for entry in entries)
        names = [provider.name for provider in providers]
        if len(set(names)) != len(names):
            raise ConfigError("[proxy] providers: each name must appear once")
        return ProxySettings(allow_hosts=tuple(hosts), providers=providers)

    def read_rules(self) -> str | None:
        """The text of ``rules_file``, or None if there is none (the default rules apply). Read
        like the rest of the config: no symlink, ours, not writable by others. Raises
        ConfigError."""
        if not os.path.lexists(self.rules_file):
            return None
        data = _read_file(self.rules_file, "rules file", MAX_RULES_BYTES, private=False)
        return _decode(data)

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
        if "volume_image" in data:
            optional["volume_image"] = _as_path("volume_image", data["volume_image"])
        if "proxy" in data:
            if not isinstance(data["proxy"], dict):
                raise ConfigError("[proxy] must be a table")
            optional["proxy"] = dict(data["proxy"])
        return cls(
            state_dir=state_dir,
            volume=volume,
            gateway_token=Secret(token.strip()),
            agent=agent,
            **optional,
        )


def _require_private_state_dir(path: Path) -> None:
    """backtide's state (the lock, the black box's key, the token) lives here: only we may write
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


def _reject_secret_keys(label: str, table: Mapping[str, Any]) -> None:
    """A key, token or password in the TOML is refused without quoting it: the real keys of the
    providers live in ``<state_dir>/keys/``, never in this file (docs/21, section 6)."""
    secret = sorted(key for key in table if any(word in str(key).lower() for word in _SECRET_WORDS))
    if secret:
        raise ConfigError(
            f"{label} must never hold a key ({', '.join(map(repr, secret))}): the providers' "
            f"keys live in <state_dir>/{STATE_KEYS}/, never in the configuration file"
        )


def _check_host(label: str, host: object) -> None:
    if not isinstance(host, str) or not _HOST_RE.fullmatch(host) or host.startswith("."):
        raise ConfigError(f"{label}: {host!r} is not a host name nor '*.' and a domain")


def _provider(entry: object) -> Provider:
    if not isinstance(entry, dict):
        raise ConfigError("[proxy] providers: each one must be a table (name, kind, host)")
    _reject_secret_keys("[proxy] providers", entry)
    unknown = sorted(set(entry) - _PROVIDER_KEYS)
    if unknown:
        raise ConfigError(f"unknown [proxy] providers settings: {', '.join(map(repr, unknown))}")
    name, kind = entry.get("name"), entry.get("kind")
    if not isinstance(name, str) or not _PROVIDER_NAME_RE.fullmatch(name):
        raise ConfigError(f"[proxy] providers: invalid name {name!r} (a-z, 0-9 and '-')")
    if kind not in PROVIDER_HOSTS:
        raise ConfigError(
            f"[proxy] providers: {name} has kind {kind!r}, not one of {sorted(PROVIDER_HOSTS)}"
        )
    host = entry.get("host", PROVIDER_HOSTS[kind])
    _check_host(f"[proxy] providers: {name}'s host", host)
    if "*" in host:
        raise ConfigError(f"[proxy] providers: {name}'s host must be one exact name")
    return Provider(name=name, kind=kind, host=host)


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
