"""The agent jail's settings, the ``docker`` argv that builds it and OpenClaw's config. Pure.

Design: docs/13-diseno-t03-jaula.md. Nothing here touches the disk or runs a command, so the
Mac unit tests check every security option of the container.

- The image is pinned by digest, the user is never root and every capability is dropped.
  By default the agent runs as a uid and gid of its own (61000), meant to be nobody else's.
- The root filesystem is read-only. The agent writes only to ``/workspace`` (its folder in the
  snapshotted volume) and to a small ``/tmp`` tmpfs; OpenClaw's config is mounted read-only.
- The network is ``--internal`` with an isolated gateway: no route out and no address of the
  host on the bridge. No ports are published and no host entries are added.
- No API key ever reaches the container. The Gateway token reaches it through the docker
  CLI's environment (``-e NAME`` without a value), never through an argv that ``ps`` shows.
"""

import re
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any

# OpenClaw 2026.9.8 (docs/12). Bump the digest and the version together, after testing in the VM.
OPENCLAW_VERSION = "2026.9.8"
IMAGE = (
    "ghcr.io/openclaw/openclaw"
    "@sha256:d0ded1dd76939b2bf4d67ef2d13247b8b160aa5666331d4a0b0e58811182cbb8"
)
GATEWAY_PORT = 18789
READY_LOG_LINE = "[gateway] ready"
HEALTH_URL = f"http://127.0.0.1:{GATEWAY_PORT}/healthz"

AGENT_DIR = "agente"  # inside <root>/workspace: the ONLY host directory the agent sees
AGENT_SUBDIRS = ("home", "state", "work")
CONFIG_FILE = "openclaw.json"
TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN"  # noqa: S105 - the variable's name, not a secret

CONTAINER_WORKSPACE = PurePosixPath("/workspace")
CONTAINER_CONFIG_DIR = PurePosixPath("/config")
CONTAINER_HOME = CONTAINER_WORKSPACE / "home"
CONTAINER_STATE = CONTAINER_WORKSPACE / "state"
CONTAINER_WORK = CONTAINER_WORKSPACE / "work"

# deploy/seccomp/agent.json: Docker's default profile plus the Btrfs ioctl block.
SECCOMP_PROFILE = Path(__file__).resolve().parents[2] / "deploy" / "seccomp" / "agent.json"

# The agent's own uid and gid. Not 1000 (the image's `node`, and the first person's account on
# most Linux hosts) and not Vigía's: the kernel counts some limits per uid (inotify instances,
# processes), and a shared uid would also hand the agent the owner's permissions on anything
# that ever leaked into its view. 61000 is outside systemd's ranges for people, homed,
# container-mapped and DynamicUser= users, and below 65536 (Docker's userns-remap range).
AGENT_UID = 61000
AGENT_GID = 61000

NO_NEW_PRIVILEGES = "no-new-privileges=true"
LOG_DRIVER = "local"
LOG_OPTIONS = {"max-size": "10m", "max-file": "3"}  # bounded: the agent prints what it likes

# The image's entrypoint runs `openclaw doctor --fix` first, which exits 1 when the config is
# read-only (OPENCLAW_CONFIG_READONLY=1) and fails on the read-only root without it (checked in
# the VM with 2026.9.8). Doctor only migrates or repairs state left by OTHER versions, and the
# image is pinned, so the jail starts the Gateway directly under the image's own tini.
ENTRYPOINT = "tini"
COMMAND = ("-s", "--", "node", "openclaw.mjs", "gateway")

# Turn off everything that would phone home or start background work (docs/12).
_FIXED_ENV = (
    ("HOME", str(CONTAINER_HOME)),
    ("OPENCLAW_STATE_DIR", str(CONTAINER_STATE)),
    ("OPENCLAW_WORKSPACE_DIR", str(CONTAINER_WORK)),
    ("OPENCLAW_CONFIG_PATH", str(CONTAINER_CONFIG_DIR / CONFIG_FILE)),
    ("OPENCLAW_CONFIG_READONLY", "1"),
    ("OPENCLAW_NO_AUTO_UPDATE", "1"),
    ("OPENCLAW_OFFLINE", "1"),
    ("OPENCLAW_DISABLE_BONJOUR", "1"),
    ("OPENCLAW_SKIP_CRON", "1"),
    ("OPENCLAW_SKIP_CANVAS_HOST", "1"),
    ("OPENCLAW_SKIP_GMAIL_WATCHER", "1"),
    ("CLAWHUB_DISABLE_TELEMETRY", "1"),
    ("DO_NOT_TRACK", "1"),
)

# Docker object names, a hostname label, docker's memory sizes and CPU counts.
_DOCKER_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", re.ASCII)
_HOSTNAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_SIZE_RE = re.compile(r"[1-9][0-9]{0,9}[kmg]", re.ASCII)
_CPUS_RE = re.compile(r"(?:[1-9][0-9]{0,2}|0)(?:\.[0-9]{1,2})?", re.ASCII)
_PINNED_IMAGE_RE = re.compile(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", re.ASCII)
# What secrets.token_urlsafe produces; at least 32 characters.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,256}", re.ASCII)


@dataclass(frozen=True)
class AgentJailConfig:
    """Everything that defines the agent's container. Validated on creation (ValueError).

    ``workspace`` is ``<root>/workspace``, the snapshotted subvolume; only its ``agente/``
    folder is mounted. ``config_dir`` holds only ``openclaw.json`` and must live outside the
    workspace. ``uid``/``gid`` are the agent's: AgentJail refuses to create or start the
    container when either is Vigía's own (or one of Vigía's groups), unless
    ``allow_shared_ids`` says so. Only the VM tests set it: they run without root, so the
    agent's folders can only belong to the test user."""

    workspace: Path
    config_dir: Path
    gateway_token: str = field(repr=False)
    name: str = "vigia-agente"
    network: str = "vigia-agente-net"
    # Fixed, so a Gateway owner lease restored from a snapshot names this same host and
    # OpenClaw can see that its process is gone (otherwise it refuses to start for 5 min).
    hostname: str = "agente"
    image: str = IMAGE
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

    def __post_init__(self) -> None:
        for label, path in (
            ("workspace", self.workspace),
            ("config_dir", self.config_dir),
            ("seccomp_profile", self.seccomp_profile),
        ):
            _require_absolute(label, path)
            _require_no_separator(label, str(path))
        if _overlap(self.workspace, self.config_dir):
            raise ValueError(
                f"config_dir {self.config_dir} and workspace {self.workspace} must not contain "
                "each other: the agent must never see or snapshot its own config"
            )
        for label, value in (("name", self.name), ("network", self.network)):
            _require_match(label, value, _DOCKER_NAME_RE)
        _require_match("hostname", self.hostname, _HOSTNAME_RE)
        _require_match("image (pinned by digest)", self.image, _PINNED_IMAGE_RE)
        _require_match("memory", self.memory, _SIZE_RE)
        _require_match("tmp_size", self.tmp_size, _SIZE_RE)
        _require_match("cpus", self.cpus, _CPUS_RE)
        if float(self.cpus) <= 0:
            raise ValueError(f"cpus must be positive, got {self.cpus!r}")
        if not _TOKEN_RE.fullmatch(self.gateway_token):
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
        if self.ready_timeout <= 0:
            raise ValueError(f"ready_timeout must be positive, got {self.ready_timeout!r}")
        if not isinstance(self.allow_shared_ids, bool):
            raise ValueError(f"allow_shared_ids must be a bool, got {self.allow_shared_ids!r}")

    @property
    def agent_dir(self) -> Path:
        """``<root>/workspace/agente`` on the host: what the container sees as /workspace."""
        return self.workspace / AGENT_DIR

    @property
    def config_file(self) -> Path:
        return self.config_dir / CONFIG_FILE


def container_env(config: AgentJailConfig) -> list[tuple[str, str]]:
    """The variables the agent sees, without the token's value (see token_env)."""
    del config  # the same for every agent today; kept for symmetry with the other builders
    return list(_FIXED_ENV)


def token_env(config: AgentJailConfig) -> dict[str, str]:
    """The environment the docker CLI needs for ``docker create``: only the Gateway token."""
    return {TOKEN_ENV: config.gateway_token}


def volume_binds(config: AgentJailConfig) -> list[str]:
    """The only two host folders the container sees: its workspace and its config (read-only).

    -v (not --mount) because only -v relabels for SELinux (:z). It would create a missing
    source as root, so agent.py checks both sources right before create and start."""
    return [
        f"{config.agent_dir}:{CONTAINER_WORKSPACE}:z",
        f"{config.config_dir}:{CONTAINER_CONFIG_DIR}:ro,z",
    ]


def tmpfs_options(config: AgentJailConfig) -> str:
    return f"rw,nosuid,nodev,size={config.tmp_size}"


def memory_bytes(size: str) -> int:
    """What docker makes of a size such as ``2g``: binary units."""
    units = {"k": 1024, "m": 1024**2, "g": 1024**3}
    return int(size[:-1]) * units[size[-1]]


def nano_cpus(cpus: str) -> int:
    """What docker makes of ``--cpus``: billionths of a CPU."""
    return int(Decimal(cpus) * 1_000_000_000)


def docker_create_argv(config: AgentJailConfig) -> list[str]:
    """Arguments for ``docker`` (without the program name) that create the agent container.

    Run it with token_env(config) in the CLI's environment: ``-e OPENCLAW_GATEWAY_TOKEN``
    without a value makes the CLI copy it from there."""
    tmpfs = f"/tmp:{tmpfs_options(config)}"  # noqa: S108 - inside the container
    argv = [
        "create",
        "--name", config.name,
        "--hostname", config.hostname,
        "--user", f"{config.uid}:{config.gid}",
        "--cap-drop", "ALL",
        "--security-opt", NO_NEW_PRIVILEGES,
        "--security-opt", f"seccomp={config.seccomp_profile}",
        "--read-only",
        "--tmpfs", tmpfs,
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
    for bind in volume_binds(config):
        argv += ["--volume", bind]
    for name, value in container_env(config):
        argv += ["--env", f"{name}={value}"]
    argv += ["--env", TOKEN_ENV]  # value taken from the CLI's environment, see token_env
    argv += ["--entrypoint", ENTRYPOINT, config.image, *COMMAND]
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


def openclaw_config(config: AgentJailConfig) -> dict[str, Any]:
    """OpenClaw's openclaw.json: the hardened baseline of docs/12, with no secrets in it.

    Validated against the pinned image with ``openclaw config validate`` (a VM test)."""
    del config  # the same for every agent today
    return {
        "gateway": {
            "mode": "local",
            "bind": "loopback",
            "port": GATEWAY_PORT,
            "auth": {"mode": "token"},  # the token comes from OPENCLAW_GATEWAY_TOKEN
        },
        "update": {"checkOnStart": False, "auto": {"enabled": False}},
        "models": {"catalogRefresh": {"enabled": False}},
        "cron": {"enabled": False},
        "memory": {"search": {"provider": "none"}},  # OpenClaw's built-in "no embeddings"
        "discovery": {"mdns": {"mode": "off"}},
        "agents": {
            "defaults": {"workspace": str(CONTAINER_WORK), "sandbox": {"mode": "off"}},
        },
        "tools": {
            "elevated": {"enabled": False},
            "deny": ["group:automation", "sessions_spawn", "sessions_send"],
        },
    }


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
