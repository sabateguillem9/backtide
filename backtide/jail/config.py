"""The agent jail's settings and the ``docker`` argv that builds it. Pure.

Design: docs/13-diseno-t03-jaula.md. Nothing here touches the disk or runs a command, so the
Mac unit tests check every security option of the container. What changes from one agent to
another (image, command, variables, config files: docs/34, section 7) comes from the config's
AgentProfile (backtide/jail/profile.py; OpenClaw's is the default); everything below that
decides security is the same for every agent, and no profile field reaches it.

- The image is pinned by digest, the user is never root and every capability is dropped.
  By default the agent runs as a uid and gid of its own (61000), meant to be nobody else's.
- The root filesystem is read-only. The agent writes only to ``/workspace`` (its folder in the
  snapshotted volume) and to a small ``/tmp`` tmpfs; its config folder is mounted read-only.
  ``/sys/fs/btrfs`` and ``/sys/devices/virtual/block`` are covered with empty read-only tmpfs.
- The network is ``--internal`` with an isolated gateway: no route out and no address of the
  host on the bridge. No ports are published and no host entries are added.
- No real API key ever reaches the container. The profile's token (OpenClaw's Gateway token),
  its fake keys and its own variables reach it through the docker CLI's environment (``-e NAME``
  without a value, create_env), never through an argv that ``ps`` or an error message shows.
- No healthcheck: ``--no-healthcheck`` keeps an image's ``HEALTHCHECK`` from running a command
  of its own inside the agent's container every few seconds (verify.py requires it off).
- The only way out is the egress proxy (docs/21-diseno-t06-proxy.md), a neighbour on the same
  internal network under the alias ``backtide-proxy``. The variables only help programs find
  it: whatever ignores them has no route at all. The agent trusts the proxy's CA through its
  certificate alone, mounted read-only from ``ca_dir`` (ca.py writes it; the key never leaves
  the proxy's folder). No ``--dns``, ever: with one, Docker forwards outside names even from an
  internal network (T06-1, P5), and verify.py requires it empty.
"""

import math
import re
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path, PurePosixPath

from backtide.jail.model import ModelProvider
from backtide.jail.profile import (
    CONTAINER_CONFIG_DIR,
    CONTAINER_HOME,
    CONTAINER_WORKSPACE,
    PINNED_IMAGE_RE,
    AgentProfile,
)
from backtide.jail.profile import CONTAINER_STATE as CONTAINER_STATE
from backtide.jail.profile import CONTAINER_WORK as CONTAINER_WORK
from backtide.jail.profiles import DEFAULT_PROFILE

# OpenClaw's names, kept here for the imports that predate the profile (the tests, the VM kits).
# The jail reads them from config.profile; they live in backtide/jail/profiles/openclaw.py.
from backtide.jail.profiles.openclaw import AGENT_SUBDIRS as AGENT_SUBDIRS
from backtide.jail.profiles.openclaw import COMMAND as COMMAND
from backtide.jail.profiles.openclaw import CONFIG_FILE as CONFIG_FILE
from backtide.jail.profiles.openclaw import ENTRYPOINT as ENTRYPOINT
from backtide.jail.profiles.openclaw import GATEWAY_PORT as GATEWAY_PORT
from backtide.jail.profiles.openclaw import HEALTH_URL as HEALTH_URL
from backtide.jail.profiles.openclaw import IMAGE as IMAGE
from backtide.jail.profiles.openclaw import OPENCLAW_VERSION as OPENCLAW_VERSION
from backtide.jail.profiles.openclaw import READY_LOG_LINE as READY_LOG_LINE
from backtide.jail.profiles.openclaw import TOKEN_ENV as TOKEN_ENV
from backtide.jail.profiles.openclaw import openclaw_config as openclaw_config

AGENT_DIR = "agente"  # inside <root>/workspace: the ONLY host directory the agent sees

CONTAINER_CA_DIR = PurePosixPath("/etc/backtide-ca")
CA_CERT_FILE = "ca.pem"  # the only file of ca_dir: the CA's certificate, never its key
CONTAINER_CA_FILE = CONTAINER_CA_DIR / CA_CERT_FILE

# Docker mounts /sys read-only in the container, and it shows the host's. These two directories
# are covered with an empty read-only tmpfs (docs/19, section 5):
# - /sys/fs/btrfs shows the agent its own space usage and when a snapshot is made (the qgroups);
# - /sys/devices/virtual/block/loopN/loop/backing_file is the host path of the volume's image.
SYS_MASKS = (PurePosixPath("/sys/fs/btrfs"), PurePosixPath("/sys/devices/virtual/block"))
SYS_MASK_OPTIONS = "ro,nosuid,nodev,noexec,size=4k,mode=0555"

# deploy/seccomp/agent.json: Docker's default profile plus the Btrfs ioctl and copy_file_range
# blocks.
SECCOMP_PROFILE = Path(__file__).resolve().parents[2] / "deploy" / "seccomp" / "agent.json"

# The agent's own uid and gid. Not 1000 (the image's `node`, and the first person's account on
# most Linux hosts) and not backtide's: the kernel counts some limits per uid (inotify instances,
# processes), and a shared uid would also hand the agent the owner's permissions on anything
# that ever leaked into its view. 61000 is outside systemd's ranges for people, homed,
# container-mapped and DynamicUser= users, and below 65536 (Docker's userns-remap range).
AGENT_UID = 61000
AGENT_GID = 61000

NO_NEW_PRIVILEGES = "no-new-privileges=true"
# How long wait_ready may wait at most (review of the profiles, M1): it holds agent_lock while
# the agent already runs, so the cycle (its snapshots) and the sensor's hooks wait behind it.
MAX_READY_TIMEOUT = 600.0
LOG_DRIVER = "local"
LOG_OPTIONS = {"max-size": "10m", "max-file": "3"}  # bounded: the agent prints what it likes

# The egress proxy (docs/21, sections 1 and 2): its alias exists only on the agent's network.
PROXY_ALIAS = "backtide-proxy"
PROXY_PORT = 8080
PROXY_URL = f"http://{PROXY_ALIAS}:{PROXY_PORT}"
NO_PROXY_HOSTS = "localhost,127.0.0.1,::1"  # an agent may listen in the container itself

# The jail's variables, around the profile's own (docs/34, section 6): HOME first, the profile's
# after it, then the rest. A profile can set none of these (profile.RESERVED_ENV).
_HOME_ENV = (("HOME", str(CONTAINER_HOME)),)
_NO_TRACKING_ENV = (("DO_NOT_TRACK", "1"),)

# The way out and the CA (docs/21, sections 2 and 3). Both spellings of the proxy variables:
# curl reads only the lowercase http_proxy. NODE_USE_ENV_PROXY makes Node's own fetch and http
# honour them (for the agent's node scripts; OpenClaw has its own dispatcher, T06-1 P9, which
# reads the profile's proxy_url_env). NODE_EXTRA_CA_CERTS adds the CA to Node's; the other four
# REPLACE the system's CAs with ours for curl, Python and git: everything goes through the
# proxy, which signs every certificate. The profile's proxy_url_env go right after the four
# proxy variables, and its ca_file_env after the CA's.
_PROXY_URL_ENV = (
    ("HTTP_PROXY", PROXY_URL),
    ("HTTPS_PROXY", PROXY_URL),
    ("http_proxy", PROXY_URL),
    ("https_proxy", PROXY_URL),
)
_PROXY_REST_ENV = (
    ("NO_PROXY", NO_PROXY_HOSTS),
    ("no_proxy", NO_PROXY_HOSTS),
    ("NODE_USE_ENV_PROXY", "1"),
    ("NODE_EXTRA_CA_CERTS", str(CONTAINER_CA_FILE)),
    ("SSL_CERT_FILE", str(CONTAINER_CA_FILE)),
    ("REQUESTS_CA_BUNDLE", str(CONTAINER_CA_FILE)),
    ("CURL_CA_BUNDLE", str(CONTAINER_CA_FILE)),
    ("GIT_SSL_CAINFO", str(CONTAINER_CA_FILE)),
)

# Files programs source by themselves before running anything (T17a-1: the Claude Code image
# sets both to /etc/sandbox-persistent.sh): pointed at /dev/null, so whatever reads them reads
# nothing and whatever appends to them writes nowhere. Measured in the VM with that image: a
# non-interactive ``bash -c`` sources nothing with /dev/null (nor with an empty value). A login or
# interactive bash still exports the image's own value again (its /etc/profile.d and
# /etc/bash.bashrc): that is code of the pinned image, on the read-only root.
_NEUTRAL_ENV = (
    ("BASH_ENV", "/dev/null"),
    ("CLAUDE_ENV_FILE", "/dev/null"),
)

# Docker object names, a hostname label, docker's memory sizes and CPU counts.
_DOCKER_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", re.ASCII)
_HOSTNAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_SIZE_RE = re.compile(r"[1-9][0-9]{0,9}[kmg]", re.ASCII)
_CPUS_RE = re.compile(r"(?:[1-9][0-9]{0,2}|0)(?:\.[0-9]{1,2})?", re.ASCII)
# What secrets.token_urlsafe produces; at least 32 characters.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,256}", re.ASCII)


@dataclass(frozen=True)
class Protected:
    """A host path the agent must never see (T14a, backtide/jail/mounts.py): backtide's state
    folder, the black box, the keys, the control socket, the snapshots... No folder mounted
    into the agent may be it or contain it, or lie inside it, except exactly the folders of
    ``allowed_inside``: backtide's state folder holds the agent's config and CA folders by
    default, and the snapshot volume holds its workspace. Anything else there (a restore in
    progress, a folder some later version adds) is protected without having to be listed."""

    label: str
    path: Path
    allowed_inside: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label:
            raise ValueError(f"a protected path needs a label, got {self.label!r}")
        _require_absolute(f"protected path {self.label!r}", self.path)
        if not isinstance(self.allowed_inside, tuple):
            raise ValueError(f"allowed_inside must be a tuple, got {self.allowed_inside!r}")
        for folder in self.allowed_inside:
            _require_absolute(f"a folder allowed inside {self.label!r}", folder)
            if folder == self.path or not folder.is_relative_to(self.path):
                raise ValueError(
                    f"{folder} is allowed inside {self.label} ({self.path}) but is not inside it"
                )


@dataclass(frozen=True)
class AgentJailConfig:
    """Everything that defines the agent's container. Validated on creation (ValueError).

    ``workspace`` is ``<root>/workspace``, the snapshotted subvolume; only its ``agente/``
    folder is mounted. ``config_dir`` holds only the profile's config files (OpenClaw:
    ``openclaw.json``) and must live outside the workspace. ``ca_dir`` holds only ``ca.pem``,
    the egress proxy's CA certificate (ca.py), and lives apart from both. ``uid``/``gid`` are
    the agent's: AgentJail refuses to create or start the container when either is backtide's
    own (or one of backtide's groups), unless ``allow_shared_ids`` says so. Only the VM tests
    set it: they run without root, so the agent's folders can only belong to the test user.

    ``profile`` says which agent runs (OpenClaw by default) and only fills in the image (when
    ``image`` is empty), the command, the variables and the config files: every other field
    here is the jail's, the same for every agent. ``gateway_token`` is for a profile that has a
    ``token_env`` (OpenClaw's Gateway), required there and refused for any other: nothing that
    no profile asked for reaches the container."""

    workspace: Path
    config_dir: Path
    ca_dir: Path
    gateway_token: str | None = field(default=None, repr=False)
    # The model providers with their FAKE keys, for the profile (T06-5; OpenClaw puts them in
    # openclaw.json): never in the argv. The real keys never reach this object.
    model_providers: tuple[ModelProvider, ...] = field(default=(), repr=False)
    name: str = "backtide-agente"
    network: str = "backtide-agente-net"
    # Fixed, so a Gateway owner lease restored from a snapshot names this same host and
    # OpenClaw can see that its process is gone (otherwise it refuses to start for 5 min).
    hostname: str = "agente"
    image: str = ""  # pinned by digest; empty: the profile's
    uid: int = AGENT_UID
    gid: int = AGENT_GID
    memory: str = "2g"
    pids_limit: int = 512
    cpus: str = "2"
    tmp_size: str = "256m"
    seccomp_profile: Path = SECCOMP_PROFILE
    stop_timeout: int = 30  # seconds docker waits after SIGTERM before SIGKILL
    ready_timeout: float = 120.0  # seconds wait_ready waits by default
    allow_shared_ids: bool = False  # a test-only concession, see the docstring
    # What the agent must never see (T14a): ServiceConfig.jail_config() fills it in.
    protected: tuple[Protected, ...] = ()
    # Which agent runs in the jail (docs/34, section 7): never anything of the above.
    profile: AgentProfile = DEFAULT_PROFILE

    def __post_init__(self) -> None:
        if not isinstance(self.profile, AgentProfile):
            raise ValueError(f"profile must be an AgentProfile, got {type(self.profile).__name__}")
        if self.image == "":
            object.__setattr__(self, "image", self.profile.image)
        for label, path in (
            ("workspace", self.workspace),
            ("config_dir", self.config_dir),
            ("ca_dir", self.ca_dir),
            ("seccomp_profile", self.seccomp_profile),
        ):
            _require_absolute(label, path)
            _require_no_separator(label, str(path))
        if _overlap(self.workspace, self.config_dir):
            raise ValueError(
                f"config_dir {self.config_dir} and workspace {self.workspace} must not contain "
                "each other: the agent must never see or snapshot its own config"
            )
        for label, other in (("workspace", self.workspace), ("config_dir", self.config_dir)):
            if _overlap(self.ca_dir, other):
                raise ValueError(
                    f"ca_dir {self.ca_dir} and {label} {other} must not contain each other: the "
                    "CA's folder holds only its certificate, and the agent must never write it"
                )
        for label, value in (("name", self.name), ("network", self.network)):
            _require_match(label, value, _DOCKER_NAME_RE)
        _require_match("hostname", self.hostname, _HOSTNAME_RE)
        _require_match("image (pinned by digest)", self.image, PINNED_IMAGE_RE)
        _require_match("memory", self.memory, _SIZE_RE)
        _require_match("tmp_size", self.tmp_size, _SIZE_RE)
        _require_match("cpus", self.cpus, _CPUS_RE)
        if float(self.cpus) <= 0:
            raise ValueError(f"cpus must be positive, got {self.cpus!r}")
        if self.profile.token_env is None:
            if self.gateway_token is not None:
                raise ValueError(f"profile {self.profile.name} uses no gateway token")
        elif not isinstance(self.gateway_token, str) or not _TOKEN_RE.fullmatch(self.gateway_token):
            raise ValueError(
                "gateway_token must be 32 to 256 URL-safe characters (secrets.token_urlsafe)"
            )
        for label, number in (("uid", self.uid), ("gid", self.gid)):
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise ValueError(f"{label} must be a positive integer (never root), got {number!r}")
        for label, number in (
            ("pids_limit", self.pids_limit),
            ("stop_timeout", self.stop_timeout),
        ):
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise ValueError(f"{label} must be a positive integer, got {number!r}")
        if (
            isinstance(self.ready_timeout, bool)
            or not isinstance(self.ready_timeout, int | float)
            or not math.isfinite(self.ready_timeout)
            or not 0 < self.ready_timeout <= MAX_READY_TIMEOUT
        ):
            raise ValueError(
                f"ready_timeout must be a number of seconds above 0 and at most "
                f"{MAX_READY_TIMEOUT:g}, got {self.ready_timeout!r}"
            )
        if not isinstance(self.allow_shared_ids, bool):
            raise ValueError(f"allow_shared_ids must be a bool, got {self.allow_shared_ids!r}")
        if not isinstance(self.model_providers, tuple) or not all(
            isinstance(p, ModelProvider) for p in self.model_providers
        ):
            raise ValueError("model_providers must be a tuple of ModelProvider")
        names = [p.name for p in self.model_providers]
        if len(set(names)) != len(names):
            raise ValueError("two model providers have the same name")
        self.profile.check_providers(self.model_providers)
        self._check_protected()

    def _check_protected(self) -> None:
        """No folder mounted into the agent is, contains or lies inside a protected path, unless
        it is exactly one of the folders that path allows inside. By name only: mounts.py checks
        again with symlinks resolved, right before Docker gets it."""
        if not isinstance(self.protected, tuple) or not all(
            isinstance(p, Protected) for p in self.protected
        ):
            raise ValueError("protected must be a tuple of Protected")
        problems = []
        for label, folder in (
            ("the agent's folder", self.agent_dir),
            ("config_dir", self.config_dir),
            ("ca_dir", self.ca_dir),
        ):
            for item in self.protected:
                if item.path.is_relative_to(folder):
                    problems.append(
                        f"{label} {folder} is mounted into the agent and would show it "
                        f"{item.label} ({item.path})"
                    )
                elif folder.is_relative_to(item.path) and folder not in item.allowed_inside:
                    problems.append(
                        f"{label} {folder} is mounted into the agent and lies inside "
                        f"{item.label} ({item.path})"
                    )
        if problems:
            raise ValueError("; ".join(problems))

    @property
    def agent_dir(self) -> Path:
        """``<root>/workspace/agente`` on the host: what the container sees as /workspace."""
        return self.workspace / AGENT_DIR

    @property
    def config_files(self) -> tuple[Path, ...]:
        """The profile's files in ``config_dir`` (OpenClaw: openclaw.json alone)."""
        return tuple(self.config_dir / name for name in self.profile.config_names)

    @property
    def config_file(self) -> Path:
        """The profile's one config file (OpenClaw: openclaw.json). ValueError for a profile
        that writes none or several: use ``config_files``."""
        files = self.config_files
        if len(files) != 1:
            raise ValueError(f"profile {self.profile.name} does not write exactly one config file")
        return files[0]

    @property
    def ca_file(self) -> Path:
        return self.ca_dir / CA_CERT_FILE


def container_env(config: AgentJailConfig) -> list[tuple[str, str]]:
    """The variables the agent sees, without those of token_env: the jail's, with the profile's
    own after HOME and the profile's names for the proxy's URL and the CA's path among the
    jail's. Their values are always the jail's."""
    profile = config.profile
    return [
        *_HOME_ENV,
        *profile.env,
        *_NO_TRACKING_ENV,
        *_PROXY_URL_ENV,
        *((name, PROXY_URL) for name in profile.proxy_url_env),
        *_PROXY_REST_ENV,
        *((name, str(CONTAINER_CA_FILE)) for name in profile.ca_file_env),
        *_NEUTRAL_ENV,
    ]


def jail_env_names() -> frozenset[str]:
    """Every variable the jail sets itself, whatever the profile: none may come from one."""
    return frozenset(
        name
        for name, _ in (
            *_HOME_ENV,
            *_NO_TRACKING_ENV,
            *_PROXY_URL_ENV,
            *_PROXY_REST_ENV,
            *_NEUTRAL_ENV,
        )
    )


def token_env(config: AgentJailConfig) -> dict[str, str]:
    """The secret values of the agent's environment: the profile's token (OpenClaw: the Gateway
    token) and the FAKE key of each provider the profile reads from a variable (none for
    OpenClaw: its fake keys are in openclaw.json). They reach ``docker create`` by create_env."""
    profile = config.profile
    env: dict[str, str] = {}
    if profile.token_env is not None and config.gateway_token is not None:
        env[profile.token_env] = config.gateway_token
    fake_keys = {provider.name: provider.fake_key for provider in config.model_providers}
    for name, provider in profile.fake_key_env:
        if provider in fake_keys:
            env[name] = fake_keys[provider]
    return env


def create_env(config: AgentJailConfig) -> dict[str, str]:
    """The environment the docker CLI needs for ``docker create``: every value that never goes
    in an argv (``ps`` shows it, and JailError messages quote the command). The profile's own
    variables (review of the profiles, L8: an owner's variable is not a secret, but nothing of
    the agent's environment needs to show), then token_env's. None of their names is one the
    docker CLI reads itself (profile.reaches_docker_cli)."""
    return dict(config.profile.env) | token_env(config)


def volume_binds(config: AgentJailConfig) -> list[str]:
    """The only three host folders the container sees: its workspace, its config (read-only)
    and the proxy's CA certificate (read-only).

    -v (not --mount) because only -v relabels for SELinux (:z). It would create a missing
    source as root, so agent.py checks every source right before create and start."""
    return [
        f"{config.agent_dir}:{CONTAINER_WORKSPACE}:z",
        f"{config.config_dir}:{CONTAINER_CONFIG_DIR}:ro,z",
        f"{config.ca_dir}:{CONTAINER_CA_DIR}:ro,z",
    ]


def tmpfs_options(config: AgentJailConfig) -> str:
    return f"rw,nosuid,nodev,size={config.tmp_size}"


def tmpfs_mounts(config: AgentJailConfig) -> dict[str, str]:
    """Every tmpfs of the container, mount point to options: /tmp and the /sys masks.

    --tmpfs (not --mount type=tmpfs, which docker keeps in HostConfig.Mounts, and verify.py
    requires that empty) lands in HostConfig.Tmpfs with this exact text. docker_create_argv and
    verify.py both read it from here. A bind of an empty folder would also hide the directory,
    but would show a path of the host in the mount table."""
    tmp = "/tmp"  # noqa: S108 - inside the container
    return {tmp: tmpfs_options(config), **{str(mask): SYS_MASK_OPTIONS for mask in SYS_MASKS}}


def memory_bytes(size: str) -> int:
    """What docker makes of a size such as ``2g``: binary units."""
    units = {"k": 1024, "m": 1024**2, "g": 1024**3}
    return int(size[:-1]) * units[size[-1]]


def nano_cpus(cpus: str) -> int:
    """What docker makes of ``--cpus``: billionths of a CPU."""
    return int(Decimal(cpus) * 1_000_000_000)


def docker_create_argv(config: AgentJailConfig) -> list[str]:
    """Arguments for ``docker`` (without the program name) that create the agent container.

    Run it with create_env(config) in the CLI's environment: ``-e OPENCLAW_GATEWAY_TOKEN``
    without a value makes the CLI copy it from there, and so for the profile's own variables.
    ``--no-healthcheck`` turns off an image's own HEALTHCHECK. Only the image, the entrypoint, the
    command, the working folder and the variables come from the profile, always after every
    security option, and the profile's checks keep each a single argument docker cannot read as
    an option of its own."""
    argv = [
        "create",
        "--name", config.name,
        "--hostname", config.hostname,
        "--user", f"{config.uid}:{config.gid}",
        "--cap-drop", "ALL",
        "--security-opt", NO_NEW_PRIVILEGES,
        "--security-opt", f"seccomp={config.seccomp_profile}",
        "--read-only",
        "--no-healthcheck",
        "--network", config.network,
        "--restart", "no",
        "--memory", config.memory,
        "--memory-swap", config.memory,  # the same value: no swap on top of the limit
        "--pids-limit", str(config.pids_limit),
        "--cpus", config.cpus,
        "--stop-timeout", str(config.stop_timeout),
        "--log-driver", LOG_DRIVER,
    ]  # fmt: skip
    for name, value in LOG_OPTIONS.items():
        argv += ["--log-opt", f"{name}={value}"]
    for target, options in tmpfs_mounts(config).items():
        argv += ["--tmpfs", f"{target}:{options}"]
    for bind in volume_binds(config):
        argv += ["--volume", bind]
    own = {name for name, _ in config.profile.env}
    for name, value in container_env(config):
        # The profile's own by name only: the value comes from the CLI's environment.
        argv += ["--env", name if name in own else f"{name}={value}"]
    for name in token_env(config):
        argv += ["--env", name]  # value taken from the CLI's environment, see create_env
    profile = config.profile
    if profile.workdir is not None:
        argv += ["--workdir", str(profile.workdir)]
    argv += ["--entrypoint", profile.entrypoint, config.image, *profile.command]
    return argv


def network_create_argv(config: AgentJailConfig) -> list[str]:
    """``docker network create`` for the agent: internal, and the host has no address on it.

    ``--internal`` alone leaves the bridge's gateway address on the host, so the agent could
    reach the host's services (sshd answered in the VM). ``isolated`` removes that address."""
    return [
        "network", "create",
        "--driver", "bridge",
        "--internal",
        "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "--opt", "com.docker.network.bridge.gateway_mode_ipv6=isolated",
        config.network,
    ]  # fmt: skip


def _require_absolute(label: str, path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{label} must be an absolute Path, got {path!r}")


def _require_no_separator(label: str, text: str) -> None:
    # ':' and ',' split docker's -v and --security-opt values; newlines break logs.
    if any(char in text for char in ":,\n\0"):
        raise ValueError(f"{label} must not contain ':', ',', a newline or NUL: {text!r}")


def _require_match(label: str, value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")


def _overlap(a: Path, b: Path) -> bool:
    return a.is_relative_to(b) or b.is_relative_to(a)
