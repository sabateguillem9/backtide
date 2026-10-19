"""The egress proxy's settings, the ``docker`` argv that builds it and its network. Pure.

Design: docs/21-diseno-t06-proxy.md, sections 1 and 2. The sibling of config.py: nothing here
touches the disk or runs a command, so the Mac unit tests check every option of the container.

- The proxy is the agent's only neighbour and its only way out: one container on two networks,
  the agent's (internal, under the alias ``backtide-proxy``) and the egress one (a plain bridge
  where nobody else is). It is created with both in a single ``docker create`` (T06-1, P4).
- The pinned mitmproxy image, started from Python (``python3 -m backtide.gate.main``, never the
  image's entrypoint nor ``mitmdump -s``), as a uid of its own (61001), with every capability
  dropped, no new privileges, Docker's default seccomp profile and a read-only root.
- ``--sysctl net.ipv4.ip_forward=0``: a container inherits the host's 1 (T06-1, P4), and the
  proxy must never route packets between its two networks.
- It sees three host folders and nothing else: the CA (key and certificate, read-only), its
  channel folder (read-write: it creates the socket there, T06-1 P3) and backtide's package
  (read-only). Never the black box, the snapshots, the volume, backtide's config, ``keys/`` or
  the Docker socket. No variable carries a secret: the real keys arrive by the channel (T06-4).
- ``PYTHONUNBUFFERED=1``, or mitmproxy's own log (an addon's errors) stays in stdout's buffer
  and never reaches ``docker logs`` (T06-1, P7). ``BACKTIDE_UID`` is the one uid the proxy lets
  connect to its channel (backtide's own, root in production).
- The channel folder is a small tmpfs that backtide mounts as root (``channel_mount_argv``): the
  proxy writes there, and it must not be able to fill the disk of ``state_dir`` (T06-4).
"""

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from backtide.jail.config import (
    AGENT_GID,
    AGENT_UID,
    LOG_DRIVER,
    LOG_OPTIONS,
    NO_NEW_PRIVILEGES,
    PROXY_ALIAS,
)

# mitmproxy 12.2.3 (12 May 2026), the multi-arch index (T06-1, "Resultados en la VM"). Bump the
# version and the digest together, after running tests/integration/test_proxy_assumptions.py.
MITMPROXY_VERSION = "12.2.3"
IMAGE = (
    f"mitmproxy/mitmproxy:{MITMPROXY_VERSION}"
    "@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
)

# The proxy's own uid and gid: neither the agent's (61000) nor backtide's. The CA's folder is
# group-readable by this gid only (ca.py).
PROXY_UID = 61001
PROXY_GID = 61001

CONTAINER_CA_DIR = PurePosixPath("/ca")  # mitmproxy's confdir
CONTAINER_CHANNEL_DIR = PurePosixPath("/run/backtide")
CONTAINER_CODE_DIR = PurePosixPath("/opt/backtide")  # PYTHONPATH
CONTAINER_PACKAGE_DIR = CONTAINER_CODE_DIR / "backtide"
CONTAINER_TMP = PurePosixPath("/tmp")  # noqa: S108 - a tmpfs inside the container

# The folder of the backtide package itself: what the proxy imports (backtide.gate).
PACKAGE_DIR = Path(__file__).resolve().parents[1]
# backtide/gate/main.py prints it (the same text, kept in step by a test) once mitmproxy listens.
READY_LOG_LINE = "backtide-proxy ready"

ENTRYPOINT = "python3"
COMMAND = ("-m", "backtide.gate.main")

# The image declares ``VOLUME /home/mitmproxy/.mitmproxy``: without a mount there, Docker adds
# a writable anonymous volume (seen in the VM, T06-2). An empty read-only tmpfs covers it; the
# confdir is /ca. verify.py refuses any anonymous volume, so a new one in the image shows up.
IMAGE_VOLUMES = (PurePosixPath("/home/mitmproxy/.mitmproxy"),)
VOLUME_MASK_OPTIONS = "ro,nosuid,nodev,noexec,size=4k,mode=0555"

# Docker's sysctl, not the host's: forwarding off inside the proxy (T06-1, P4).
SYSCTLS = {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}
# Set on the egress network when backtide creates it, and required when it is reused: a network
# someone else made (Docker's default ``bridge``, say) is never taken for the proxy's way out.
EGRESS_LABEL = "backtide.role=egress"
_RESERVED_NETWORKS = frozenset({"bridge", "host", "none", "default"})

_FIXED_ENV = (
    ("PYTHONPATH", str(CONTAINER_CODE_DIR)),
    ("HOME", str(CONTAINER_TMP)),
    ("PYTHONUNBUFFERED", "1"),  # mitmproxy's errors reach docker logs (T06-1, P7)
    ("PYTHONDONTWRITEBYTECODE", "1"),  # the code is read-only: no __pycache__ attempts
    ("PYTHONSAFEPATH", "1"),  # `python3 -m` never puts the working directory on sys.path
    ("PYTHONNOUSERSITE", "1"),  # nothing from a user site-packages in the writable HOME
)

CHANNEL_TMPFS_SOURCE = "backtide-proxy-channel"  # the tmpfs's name in mountinfo
_ADDRESS_RE = re.compile(r"[0-9a-fA-F.:]{2,45}", re.ASCII)
_DOCKER_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", re.ASCII)
_SIZE_RE = re.compile(r"[1-9][0-9]{0,9}[kmg]", re.ASCII)
_CPUS_RE = re.compile(r"(?:[1-9][0-9]{0,2}|0)(?:\.[0-9]{1,2})?", re.ASCII)
# Pinned by digest; an optional tag in front of it says which version that digest is.
_PINNED_IMAGE_RE = re.compile(
    r"[a-z0-9./_-]+(?::[A-Za-z0-9._-]{1,128})?@sha256:[0-9a-f]{64}", re.ASCII
)


@dataclass(frozen=True)
class ProxyJailConfig:
    """Everything that defines the proxy's container. Validated on creation (ValueError).

    ``ca_dir`` is the CA's folder (``mitmproxy-ca.pem`` and ``mitmproxy-dhparam.pem``, made by
    ca.py), ``channel_dir`` the proxy's own folder for the channel's socket. ``agent_network``
    must be the agent's (AgentJailConfig.network); ``network`` is the egress one.

    ``uid``/``gid`` are the proxy's: ProxyJail refuses to create or start it when either is
    backtide's (or one of its groups), or the agent's (``agent_uid``/``agent_gid``), unless
    ``allow_shared_ids`` says so. ``backtide_uid`` is the one uid the proxy lets connect to its
    channel (backtide's euid; root in production).

    The rest are concessions of the VM tests only (no root, and fake servers instead of the
    internet: docs/21, "En la VM"); backtide's own config can set none of them:
    ``internal_egress`` makes the egress network ``--internal`` with an isolated gateway, so
    nothing can reach the internet; ``egress_neighbours`` are the containers allowed on it
    besides the proxy (the fake internet); ``test_public_addresses`` are addresses the proxy
    lets through as if they were public (the fake internet's); ``test_upstream_ca`` is the PEM
    of the fake internet's CA; ``channel_tmpfs=False`` leaves the channel folder on the
    disk (mounting the tmpfs needs root); and ``test_dns`` makes a fake resolver the proxy's
    upstream (``--dns``, as T06-1 P5), so a test sees every name the proxy resolves (T06-7,
    ``dns-tunel``). In production the proxy has no ``--dns``, and verify.py requires so."""

    ca_dir: Path
    channel_dir: Path
    name: str = "backtide-proxy"
    agent_network: str = "backtide-agente-net"
    network: str = "backtide-salida-net"
    image: str = IMAGE
    uid: int = PROXY_UID
    gid: int = PROXY_GID
    agent_uid: int = AGENT_UID
    agent_gid: int = AGENT_GID
    memory: str = "1g"
    pids_limit: int = 128
    cpus: str = "1"
    nofile: int = 4096
    tmp_size: str = "64m"
    stop_timeout: int = 10  # seconds docker waits after SIGTERM before SIGKILL
    ready_timeout: float = 30.0  # seconds wait_ready waits by default
    package_dir: Path = PACKAGE_DIR
    backtide_uid: int = 0
    channel_size: str = "1m"  # the channel folder's tmpfs: a socket needs next to nothing
    internal_egress: bool = False  # a test-only concession, see the docstring
    allow_shared_ids: bool = False  # a test-only concession, see the docstring
    egress_neighbours: tuple[str, ...] = ()  # a test-only concession, see the docstring
    test_public_addresses: tuple[str, ...] = ()  # a test-only concession, see the docstring
    test_upstream_ca: str | None = field(default=None, repr=False)  # test-only, see above
    channel_tmpfs: bool = True  # False is a test-only concession, see the docstring
    test_dns: tuple[str, ...] = ()  # a test-only concession, see the docstring

    def __post_init__(self) -> None:
        folders = (
            ("ca_dir", self.ca_dir),
            ("channel_dir", self.channel_dir),
            ("package_dir", self.package_dir),
        )
        for label, path in folders:
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError(f"{label} must be an absolute Path, got {path!r}")
            if any(char in str(path) for char in ":,\n\0"):
                raise ValueError(f"{label} must not contain ':', ',', a newline or NUL: {path}")
        for index, (label, path) in enumerate(folders):
            for other_label, other in folders[index + 1 :]:
                if path.is_relative_to(other) or other.is_relative_to(path):
                    raise ValueError(
                        f"{label} {path} and {other_label} {other} must not contain each other"
                    )
        for label, value in (
            ("name", self.name),
            ("agent_network", self.agent_network),
            ("network", self.network),
        ):
            _require_match(label, value, _DOCKER_NAME_RE)
        for label, value in (("agent_network", self.agent_network), ("network", self.network)):
            if value in _RESERVED_NETWORKS:
                raise ValueError(f"{label} must be backtide's own network, not Docker's {value!r}")
        if self.network == self.agent_network:
            raise ValueError(
                f"the egress network must not be the agent's ({self.network!r}): the agent "
                "would sit on the network with a way out"
            )
        _require_match("image (pinned by digest)", self.image, _PINNED_IMAGE_RE)
        _require_match("memory", self.memory, _SIZE_RE)
        _require_match("tmp_size", self.tmp_size, _SIZE_RE)
        _require_match("cpus", self.cpus, _CPUS_RE)
        if float(self.cpus) <= 0:
            raise ValueError(f"cpus must be positive, got {self.cpus!r}")
        for label, number in (
            ("uid", self.uid),
            ("gid", self.gid),
            ("agent_uid", self.agent_uid),
            ("agent_gid", self.agent_gid),
            ("pids_limit", self.pids_limit),
            ("nofile", self.nofile),
            ("stop_timeout", self.stop_timeout),
        ):
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise ValueError(f"{label} must be a positive integer, got {number!r}")
        if isinstance(self.backtide_uid, bool) or not isinstance(self.backtide_uid, int):
            raise ValueError(f"backtide_uid must be an integer, got {self.backtide_uid!r}")
        if self.backtide_uid < 0:
            raise ValueError(f"backtide_uid must not be negative, got {self.backtide_uid!r}")
        _require_match("channel_size", self.channel_size, _SIZE_RE)
        for name in self.egress_neighbours:
            _require_match("egress_neighbours", name, _DOCKER_NAME_RE)
            if name == self.name:
                raise ValueError("the proxy is not its own neighbour")
        for address in self.test_public_addresses:
            _require_match("test_public_addresses", address, _ADDRESS_RE)
        if not isinstance(self.test_dns, tuple):
            raise ValueError(f"test_dns must be a tuple of addresses, got {self.test_dns!r}")
        for address in self.test_dns:
            _require_match("test_dns", address, _ADDRESS_RE)
        if self.test_upstream_ca is not None and (
            not isinstance(self.test_upstream_ca, str)
            or "-----BEGIN CERTIFICATE-----" not in self.test_upstream_ca
            or "PRIVATE KEY" in self.test_upstream_ca
        ):
            raise ValueError("test_upstream_ca must be the PEM of a certificate, and only that")
        if self.ready_timeout <= 0:
            raise ValueError(f"ready_timeout must be positive, got {self.ready_timeout!r}")
        for label, flag in (
            ("internal_egress", self.internal_egress),
            ("allow_shared_ids", self.allow_shared_ids),
            ("channel_tmpfs", self.channel_tmpfs),
        ):
            if not isinstance(flag, bool):
                raise ValueError(f"{label} must be a bool, got {flag!r}")


def proxy_env(config: ProxyJailConfig) -> list[tuple[str, str]]:
    """The variables the proxy sees. None is a secret: the keys come by the channel."""
    env = [*_FIXED_ENV, ("BACKTIDE_UID", str(config.backtide_uid))]
    if config.test_public_addresses:
        env.append(("BACKTIDE_TEST_PUBLIC", ",".join(config.test_public_addresses)))
    if config.test_upstream_ca is not None:
        env.append(("BACKTIDE_TEST_UPSTREAM_CA", config.test_upstream_ca))
    return env


def channel_mount_argv(config: ProxyJailConfig) -> list[str]:
    """``mount`` (as root) of the channel folder's tmpfs: small, the proxy's own, no devices,
    no set-uid, nothing executable."""
    options = (
        f"size={config.channel_size},mode=0700,uid={config.uid},gid={config.gid},"
        "nosuid,nodev,noexec"
    )
    return ["mount", "-t", "tmpfs", "-o", options, CHANNEL_TMPFS_SOURCE, str(config.channel_dir)]


def volume_binds(config: ProxyJailConfig) -> list[str]:
    """The only three host folders the proxy sees. -v (not --mount): only -v relabels for
    SELinux (:z). proxy.py checks every source right before create and start."""
    return [
        f"{config.ca_dir}:{CONTAINER_CA_DIR}:ro,z",
        f"{config.channel_dir}:{CONTAINER_CHANNEL_DIR}:z",
        f"{config.package_dir}:{CONTAINER_PACKAGE_DIR}:ro,z",
    ]


def tmpfs_mounts(config: ProxyJailConfig) -> dict[str, str]:
    """Every tmpfs of the proxy, mount point to options, as Docker keeps them (HostConfig.Tmpfs):
    /tmp, and the empty read-only cover of the image's volume."""
    return {
        str(CONTAINER_TMP): f"rw,nosuid,nodev,noexec,size={config.tmp_size}",
        **{str(volume): VOLUME_MASK_OPTIONS for volume in IMAGE_VOLUMES},
    }


def ulimits(config: ProxyJailConfig) -> list[dict[str, object]]:
    """``--ulimit nofile=N`` as Docker keeps it (HostConfig.Ulimits): soft and hard."""
    return [{"Name": "nofile", "Hard": config.nofile, "Soft": config.nofile}]


def proxy_create_argv(config: ProxyJailConfig) -> list[str]:
    """Arguments for ``docker`` (without the program name) that create the proxy container."""
    argv = [
        "create",
        "--name", config.name,
        "--user", f"{config.uid}:{config.gid}",
        "--cap-drop", "ALL",
        "--security-opt", NO_NEW_PRIVILEGES,
        "--read-only",
        # Both networks in the one create (T06-1, P4); the alias only on the agent's.
        "--network", f"name={config.agent_network},alias={PROXY_ALIAS}",
        "--network", config.network,
        "--restart", "no",
        "--memory", config.memory,
        "--memory-swap", config.memory,  # no swap on top of the limit
        "--pids-limit", str(config.pids_limit),
        "--cpus", config.cpus,
        "--ulimit", f"nofile={config.nofile}",
        "--stop-timeout", str(config.stop_timeout),
        "--log-driver", LOG_DRIVER,
    ]  # fmt: skip
    for name, value in LOG_OPTIONS.items():
        argv += ["--log-opt", f"{name}={value}"]
    for name, value in SYSCTLS.items():
        argv += ["--sysctl", f"{name}={value}"]
    for address in config.test_dns:  # the VM tests' fake resolver only (T06-7)
        argv += ["--dns", address]
    for target, options in tmpfs_mounts(config).items():
        argv += ["--tmpfs", f"{target}:{options}"]
    for bind in volume_binds(config):
        argv += ["--volume", bind]
    for name, value in proxy_env(config):
        argv += ["--env", f"{name}={value}"]
    argv += ["--entrypoint", ENTRYPOINT, config.image, *COMMAND]
    return argv


def network_create_argv(config: ProxyJailConfig) -> list[str]:
    """``docker network create`` for the egress network: a plain bridge without IPv6 (the way
    out is NAT through the host). With ``internal_egress`` (VM tests only) it is internal and
    isolated like the agent's, so the fake internet in it is all the proxy can reach."""
    argv = ["network", "create", "--driver", "bridge", "--ipv6=false", "--label", EGRESS_LABEL]
    if config.internal_egress:
        argv += [
            "--internal",
            "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        ]  # fmt: skip
    return [*argv, config.network]


def _require_match(label: str, value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")
