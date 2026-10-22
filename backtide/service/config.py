"""The service's configuration: one TOML file, the gateway token and the paths.

Design: docs/19-diseno-t04.md, section "Disposición".

- ``/etc/backtide/backtide.toml`` holds paths, numbers and the agent's container options. NEVER a
  secret: the gateway token is read from ``<state_dir>/gateway.token`` (0600), and a
  ``gateway_token`` key in the TOML is refused. The token is OpenClaw's Gateway's: only read,
  passed to the jail and struck for a profile that uses one. For any other profile a token file
  left there (an OpenClaw that ran on the same volume before) is still read, leniently, only
  to strike it wherever it shows: never passed to the agent.
- ``[agent] profile`` (T17a-3, docs/34 section 7): ``"openclaw"`` (the default) or ``"custom"``,
  whose own settings (image by digest, entrypoint, command, workdir, env, ``[agent.model]``,
  ``[agent.ready]``, ``[agent.rewind]``) describe any other agent (backtide/jail/profiles/
  custom.py). Nothing of the jail is an [agent] setting: ``ports`` and every security option
  are refused by name. The agent's config folder is ``<state_dir>/<profile>``.
- Tokens live in a ``Secret``, whose ``repr`` and ``str`` are ``[REDACTED]``. Errors about the
  token or its file say the size and the permissions, never the content, and no error quotes the
  TOML either (a syntax error says the line, and that is all).
- State and the agent's volume must be apart: the agent writes the volume, so the black box can
  never live inside it, and the one folder mounted into the agent (the config dir) can never
  contain the state.
- Reading the configuration touches no Docker, no btrfs and no black box. backtide runs on the host,
  not in a container (docs/19), so these paths are host paths.
- ``[proxy]`` (T06, docs/21): the egress proxy's container options, the allowed hosts and the model
  providers (name, kind, host, models, and for a public ``openai`` one ``stream_usage``: whether the
  proxy asks it for a streamed call's usage, T11; on by default). NEVER a key: a key-like setting is
  refused. The real key of each provider lives in ``<state_dir>/keys/<name>.key`` (0600, in a 0700
  folder, both ours, no symlinks), read here into a ``Secret`` that only the proxy's channel reveals
  (T06-5). Its fake key, ``<name>.fake``, is made once per installation the first time it is needed;
  only the fake one reaches the agent (in openclaw.json). The proxy's CA and channel folders live in
  the state too, and the agent's config folder may never be or contain any of them.
- ``[gate]`` (T10-3, docs/32 sections 5, 8 and 9): what the gate does with hosts off the allowed
  list (``unknown_hosts``: ``"hold"``, the default, lets reads pass with decision 1's guard and
  holds writes; ``"deny"`` is the optional strict mode of T06), the trusted recipients
  (``trusted``; the owner's Telegram chat of ``telegram.toml`` is trusted too unless
  ``trust_owner_chat = false``), the extra read endpoints of the ``read_post`` translator
  (``read_endpoints``, ``host/path``) and the times (``wait_s``, ``hold_s``, ``preapproval_s``:
  only shorter than the design's 90 s, 5 min and 10 min), and what reads to unknown hosts may
  carry out per hour (``read_budget_host_kib``, 256, and ``read_budget_total_kib``, 2048: either
  way, review of T10-3, M5). A Slack channel is trusted by its id (``C…``, ``G…`` or ``D…``),
  never by its name. NEVER a key.
- ``[budget]`` (T11, docs/33): the spending caps in dollars (``daily_usd``, 5, and ``monthly_usd``,
  50, by default: decided by default, revisable), the time zone of "a day" (``timezone``, IANA;
  the machine's by default), how many model calls may be in flight at once (``max_inflight``, 4),
  whether the prices update themselves from Anthropic's page (``auto_prices``, on; ``prices_url``
  only for the tests' fake page) and the owner's own prices (``[budget.prices."<model>"]`` with
  ``input`` and ``output`` in $/MTok, and optionally ``cache_read``, ``cache_write_5m`` and
  ``cache_write_1h``), which win over every other table. NEVER a key.
- A **local** provider (T20, docs/35 section 6.1): ``local = "http://<name or IPv4>:<port>"`` in
  its ``[[proxy.providers]]`` table (an Ollama on the owner's Mac or LAN). Its host is its
  virtual name, ``<name>.backtide.internal`` (``host`` is refused), its ``models`` are required
  and never Ollama's cloud ones, and it has no real key (a ``keys/<name>.key`` is only struck).
  At most MAX_LOCAL. An IPv4 must be private (``10/8``, ``172.16/12``, ``192.168/16``,
  ``100.64/10``); a name is resolved by the service (``local_models.py``), never here. The
  ``[budget] max_inflight_local`` (2) calls to the local providers in flight are apart from
  ``max_inflight``: they cost nothing and are never stopped by the caps.
- **Ollama's cloud API** (the founder's addition to T20): a public provider like any other
  (``host = "ollama.com"``, its real key in the Settings page, the fake one in the jail). It
  bills by plan, not by token, so backtide cannot know its price: each of its ``models`` must
  have an owner's price in ``[budget.prices]`` (decided: the owner sets it; no guess).
- ``[sensor]`` (T07-3, docs/23): whether the agent may run without the process sensor
  (``required``, false by default: decision 7), the sensor container's limits and the reader's
  rate limits. Never the image (pinned in backtide/jail/sensor.py) nor its folder, which is
  ``<state_dir>/sensor`` and never overlaps anything mounted into the agent.
"""

import dataclasses
import errno
import math
import os
import re
import stat
import time
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, NoReturn
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from backtide.blackbox.redact import MIN_KNOWN_SECRET
from backtide.gate.decide import UNKNOWN_HOSTS
from backtide.gate.policy import is_ip, normalize_host, numeric_ipv4
from backtide.gate.protocol import MAX_READ_ENDPOINTS
from backtide.gate.provider_tools import check_allow_entry
from backtide.gate.providers import (
    LOCAL_SUFFIX,
    MAX_LOCAL,
    Providers,
    is_cloud_model,
    is_fake_key,
    is_ollama_cloud,
    local_address_ok,
    new_fake_key,
    virtual_host,
)
from backtide.gate.providers import Provider as GateProvider
from backtide.gate.providers import Secret as GateSecret
from backtide.gate.translate.base import Trusted, normalize_trusted
from backtide.gate.translate.read_post import check_read_endpoint
from backtide.jail.ca import CaPaths
from backtide.jail.config import AGENT_DIR, MAX_READY_TIMEOUT, AgentJailConfig, Protected
from backtide.jail.model import MODEL_ID, ModelProvider
from backtide.jail.profile import PROVIDER_NAME_RULE, AgentProfile, is_provider_name
from backtide.jail.profiles import CUSTOM, DEFAULT_PROFILE, NAMED, WITH_PROVIDER, profile_names
from backtide.jail.profiles.custom import KEYS as CUSTOM_KEYS
from backtide.jail.profiles.custom import custom_profile
from backtide.jail.proxy_config import ProxyJailConfig
from backtide.jail.sensor import SensorJailConfig
from backtide.sensors.tetragon import ReaderConfig
from backtide.service.holds import HoldTimings
from backtide.service.price_update import PRICES_URL, check_url
from backtide.service.prices import (
    CACHE_1H,
    CACHE_5M,
    CACHE_READ,
    Price,
    PriceBook,
    PriceError,
    to_decimal,
)
from backtide.service.read_budget import DEFAULT_HOST_BYTES, DEFAULT_TOTAL_BYTES
from backtide.service.spend import (
    DEFAULT_DAILY_USD,
    DEFAULT_MAX_INFLIGHT,
    DEFAULT_MAX_INFLIGHT_LOCAL,
    DEFAULT_MONTHLY_USD,
    MAX_CAP_USD,
    MAX_INFLIGHT,
    BudgetSettings,
    check_cap,
)
from backtide.snapshots.store import SNAPSHOTS

DEFAULT_CYCLE_INTERVAL = 120.0  # seconds between two "did anything change?" checks
DEFAULT_PRUNE_INTERVAL = 600.0
MAX_CONFIG_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 1024
MAX_KEY_BYTES = 4096
# A real key file is read twice, this long apart, and taken only if neither the file nor what it
# holds changed in between (review of T09b, finding 3: a key written by hand may be half written).
KEY_SETTLE_S = 0.01
# And only once it has not changed for this long (review of 40dfd53, finding 6): a fresher one is
# waited for, once; one that changes again meanwhile waits until the next reload. 0 turns it off.
KEY_STILL_S = 0.5

STATE_DB = "blackbox.db"
STATE_KEY = "blackbox.key"
STATE_CHECKPOINT = "blackbox.checkpoint"
STATE_TOKEN = "gateway.token"  # noqa: S105 - the file's name, not a secret
STATE_LOCK = "backtide.lock"
STATE_PENDING = "rewind.pending"
STATE_SOCKET = "control.sock"
STATE_RULES = "rules.toml"  # the risk rules (T08); absent: the ones that ship with backtide
STATE_PROXY_CA = "proxy-ca"  # the CA's key and certificate: the proxy's /ca (docs/21)
STATE_AGENT_CA = "agent-ca"  # the CA's certificate alone: the agent's /etc/backtide-ca
STATE_PROXY_CHANNEL = "proxy-channel"  # the proxy's folder for the channel's socket
STATE_KEYS = "keys"  # the real keys of the model providers (T06-4): never mounted anywhere
STATE_SENSOR = "sensor"  # Tetragon's events, settings and the reader's cursor (T07)
MAX_RULES_BYTES = 64 * 1024
MAX_OWNER_PRICES = 64

_TOP_LEVEL_KEYS = frozenset(
    {
        "state_dir", "volume", "workspace_limit", "cycle_interval", "prune_interval", "agent",
        "volume_image", "max_volume_bytes", "proxy", "sensor", "gate", "budget",
    }
)  # fmt: skip
_BUDGET_KEYS = frozenset(
    {"daily_usd", "monthly_usd", "timezone", "max_inflight", "max_inflight_local", "auto_prices",
     "prices_url", "prices"}
)  # fmt: skip
_PRICE_KEYS = frozenset({"input", "output", "cache_read", "cache_write_5m", "cache_write_1h"})
_OPTIONAL_KEYS = ("workspace_limit", "cycle_interval", "prune_interval", "max_volume_bytes")
# The container options a file may change. ``allow_shared_ids`` is a test-only concession and
# ``seccomp_profile`` ships with backtide, so neither is here; the token is never a setting.
_AGENT_KEYS = frozenset(
    {
        "name", "network", "hostname", "image", "uid", "gid", "memory", "pids_limit", "cpus",
        "tmp_size", "stop_timeout", "ready_timeout", "config_dir",
    }
)  # fmt: skip
# What the jail decides, the same for every agent (docs/34, section 6): never an [agent] setting,
# refused by name so the owner reads why. ``ports`` has its own words (_PORTS).
_JAIL_KEYS = frozenset(
    {
        "privileged", "cap_add", "cap_drop", "capabilities", "security_opt", "seccomp",
        "seccomp_profile", "apparmor", "no_new_privileges", "read_only", "user", "volumes",
        "volume", "mounts", "binds", "tmpfs", "devices", "device", "network_mode", "networks",
        "dns", "dns_search", "dns_options", "extra_hosts", "add_host", "links", "pid", "ipc",
        "uts", "userns", "cgroup", "cgroup_parent", "cgroupns", "sysctls", "group_add",
        "runtime", "init", "ulimits", "oom_kill_disable", "restart", "log_driver", "log_opt",
        "protected", "home", "proxy_url", "no_proxy", "ca_dir", "ca_file",
        "workspace",
    }
)  # fmt: skip
_PORTS = frozenset({"ports", "publish", "expose", "publish_all"})
# [proxy]: the container options a file may change (``internal_egress`` and ``allow_shared_ids``
# are test-only concessions, so not here), and what the proxy lets out. Never a key.
_PROXY_CONTAINER_KEYS = frozenset(
    {"name", "network", "image", "uid", "gid", "memory", "cpus", "pids_limit"}
)
_PROXY_KEYS = _PROXY_CONTAINER_KEYS | {"allow_hosts", "providers", "allow_provider_tools"}
_PROVIDER_KEYS = frozenset({"name", "kind", "host", "models", "local", "stream_usage"})
# T20: ``local = "http://<name or IPv4>:<port>"``, exactly (no path, user, query or https).
_LOCAL_RE = re.compile(r"http://(?P<host>[A-Za-z0-9.-]{1,253}):(?P<port>[0-9]{1,5})", re.ASCII)
MAX_PROVIDER_MODELS = 32
# [sensor]: the container's limits, the reader's rate limits and `required`. Not the image (it is
# pinned in code), not `file_perm` (a test-only concession) and not its folder.
_SENSOR_CONTAINER_KEYS = frozenset({"name", "memory", "cpus", "cgroup_rate"})
_SENSOR_RATES = frozenset({"exec_rate", "net_rate"})
_SENSOR_COUNTS = frozenset({"exec_burst", "exec_daily", "net_burst", "net_daily"})
# novelty_streak_minutes: the founder's decision B (2026-10-19), see ProcessSensor.
_SENSOR_KEYS = (
    _SENSOR_CONTAINER_KEYS | _SENSOR_RATES | _SENSOR_COUNTS | {"required", "novelty_streak_minutes"}
)
NOVELTY_STREAK_MINUTES = 10.0
# [gate] (T10-3): the keys, how each translator names its recipient, and the times' ranges (in
# seconds; only shorter than the design's: a yes is good for 10 min at most, a hold lives 5).
_GATE_KEYS = frozenset(
    {"unknown_hosts", "trusted", "trust_owner_chat", "read_endpoints", "wait_s", "hold_s",
     "preapproval_s", "read_budget_host_kib", "read_budget_total_kib"}
)  # fmt: skip
_TRUSTED_FIELD = {"telegram": "chat", "gmail": "email", "graph_mail": "email", "slack": "channel",
                  "discord": "channel"}  # fmt: skip
_GATE_TIMES = {"wait_s": ("wait", 1, 90), "hold_s": ("life", 30, 300),
               "preapproval_s": ("preapproval", 30, 600)}  # fmt: skip
MAX_TRUSTED = 256
# [gate] read_budget_*_kib (review of T10-3, M5): what reads to unknown hosts may carry out per
# hour, per host and in total. Either way from the defaults (256 KiB and 2 MiB); 0 holds every
# read to an unknown host that carries anything; 1 GiB at most.
_READ_BUDGETS = {"read_budget_host_kib": DEFAULT_HOST_BYTES // 1024,
                 "read_budget_total_kib": DEFAULT_TOTAL_BYTES // 1024}  # fmt: skip
MAX_READ_BUDGET_KIB = 1024 * 1024
MIN_NOVELTY_STREAK_MINUTES = 1.0
# docs/21, section 6: the providers of T06 and their default hosts.
PROVIDER_HOSTS = {"anthropic": "api.anthropic.com", "openai": "api.openai.com"}
MAX_ALLOW_HOSTS = 1000
MAX_PROVIDER_TOOLS = 64
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
    header carries the key), its host and the model ids OpenClaw should know (required for a
    name that is not one of OpenClaw's own providers). Its keys are never here."""

    name: str
    kind: str
    host: str
    models: tuple[str, ...] = ()
    # T20: a local provider's ``local`` (a host name or an IPv4, and a port), as written: the
    # service resolves a name (local_models.py). ``host`` is then its virtual name.
    local: tuple[str, int] | None = None
    # T11 (docs/33, "include_usage"): ``stream_usage = false`` stops the proxy from asking this
    # ``openai`` provider for the usage of a streamed call (a compatible API that refuses fields
    # it does not know). On by default.
    stream_usage: bool = True


@dataclass(frozen=True)
class ProxySettings:
    """What ``[proxy]`` says the proxy lets out: the hosts the user allows, the providers, and
    the provider-side tools that may go to a provider anyway (T06-6; none by default)."""

    allow_hosts: tuple[str, ...]
    providers: tuple[Provider, ...]
    allow_provider_tools: tuple[str, ...] = ()


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


KEY_MISSING = "missing"  # no <name>.key yet: the owner has not set it
KEY_UNUSABLE = "unusable"  # a <name>.key that cannot be used (not 0600, a link, empty, malformed)


@dataclass(frozen=True)
class ProviderKey:
    """The two keys of one model provider: the real one (only the proxy's channel reveals it)
    and the fake one the agent gets. Neither shows in a repr.

    ``real`` is None while the provider waits for its key (docs/21, section 6): ``problem`` says
    why (``KEY_MISSING`` or ``KEY_UNUSABLE``) and ``why`` what is wrong with the file, in the
    words of the reader (what the file IS, never what it holds); ``strike`` is what an unusable
    file holds, if anything (``read_strike_only``)."""

    real: Secret | None = field(repr=False)
    fake: str = field(repr=False)
    problem: str | None = None
    why: str | None = None
    # While it waits because its file cannot be used: what the file holds anyway, to strike
    # wherever it shows and never to swap in (review of T09b, finding 2). None otherwise.
    strike: Secret | None = field(default=None, repr=False)


@dataclass(frozen=True)
class GateSettings:
    """What ``[gate]`` says (docs/32): the mode for unknown hosts, the trusted recipients, the
    extra read endpoints and the gate's times."""

    unknown_hosts: str = "hold"
    trusted: tuple[Trusted, ...] = ()
    read_endpoints: tuple[str, ...] = ()
    timings: HoldTimings = field(default_factory=HoldTimings)
    read_budget_host: int = DEFAULT_HOST_BYTES  # bytes per host and hour (M5)
    read_budget_total: int = DEFAULT_TOTAL_BYTES  # bytes per hour, every unknown host together


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
    # OpenClaw's Gateway token, for a profile that uses one (required then): None otherwise.
    gateway_token: Secret | None = None
    # For a profile without one: what an old gateway.token holds, to strike and nothing else.
    struck_token: Secret | None = field(default=None, repr=False)
    workspace_limit: int | None = None
    cycle_interval: float = DEFAULT_CYCLE_INTERVAL
    prune_interval: float = DEFAULT_PRUNE_INTERVAL
    agent: Mapping[str, Any] = field(default_factory=dict)
    volume_image: Path | None = None
    max_volume_bytes: int | None = None
    proxy: Mapping[str, Any] = field(default_factory=dict)
    sensor: Mapping[str, Any] = field(default_factory=dict)
    gate: Mapping[str, Any] = field(default_factory=dict)
    budget: Mapping[str, Any] = field(default_factory=dict)
    # One per provider of [proxy] (from_file reads them from keys/): the real and fake keys.
    provider_keys: Mapping[str, ProviderKey] = field(default_factory=dict, repr=False)

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
        profile = agent_profile_of(self.agent)  # every [agent] setting, the profile's first
        if self.gateway_token is not None and not isinstance(self.gateway_token, Secret):
            raise ConfigError("gateway_token must be a Secret")
        if self.struck_token is not None and not isinstance(self.struck_token, Secret):
            raise ConfigError("struck_token must be a Secret")
        if profile.token_env is not None and self.gateway_token is None:
            raise ConfigError(
                f"profile {profile.name} needs the gateway token: <state_dir>/{STATE_TOKEN}"
            )
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
        config_dir = self.agent_config_dir
        _require_no_dotdot("[agent] config_dir", config_dir)
        if self.state_dir.is_relative_to(config_dir):
            raise ConfigError(
                f"the agent's config_dir {config_dir} is mounted into the agent and must not "
                f"contain state_dir {self.state_dir}: the agent would see the black box"
            )
        self._check_growth(config_dir)
        self._check_proxy(config_dir)
        self._check_model(profile)
        self._check_sensor(config_dir)
        # Every agent option, and that no folder of the agent shows a protected path (T14a).
        # Last, so the checks above say first what is wrong in their own words.
        self.jail_config()  # the result is rebuilt on demand
        self.gate_settings()  # validates [gate]
        self.budget_settings()  # validates [budget]
        self._check_cloud_prices()

    def _check_cloud_prices(self) -> None:
        """Ollama's cloud API bills by plan, not by token (T20): the owner prices each of its
        models (``[budget.prices]``), or the spending cap could not count it."""
        owner = PriceBook(owner=dict(self.budget_settings().owner_prices), defaults={})
        for provider in self.proxy_settings().providers:
            if not is_ollama_cloud(provider.host):
                continue
            unpriced = [m for m in provider.models if (owner.lookup(m) or (None, ""))[1] != "owner"]
            if not provider.models or unpriced:
                raise ConfigError(
                    f"[proxy] providers: {provider.name} is Ollama's cloud API, which bills by "
                    "plan and not by token, so backtide cannot know its prices: list its models "
                    'and give each one a price in [budget.prices."<model>"] (input and output, '
                    f"$/MTok){': missing ' + ', '.join(unpriced) if unpriced else ''}"
                )

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
        names = [provider.name for provider in self.proxy_settings().providers]
        missing = [name for name in names if name not in self.provider_keys]
        if missing:  # from_file always reads them; a config made by hand may forget them
            raise ConfigError(
                f"[proxy] providers {', '.join(missing)} have no fake key (from_file reads them "
                f"from <state_dir>/{STATE_KEYS}/)"
            )
        extra = sorted(set(self.provider_keys) - set(names))
        if extra:
            raise ConfigError(f"keys for no provider of [proxy]: {', '.join(extra)}")
        if not all(isinstance(key, ProviderKey) for key in self.provider_keys.values()):
            raise ConfigError("provider_keys must map each provider to its ProviderKey")
        self.model_providers()
        self.proxy_jail_config()

    def _check_model(self, profile: AgentProfile) -> None:
        """The providers whose fake key the profile puts in a variable are in ``[proxy]``."""
        names = {provider.name for provider in self.proxy_settings().providers}
        for variable, provider in profile.fake_key_env:
            if provider not in names:
                raise ConfigError(
                    f"[agent.model] provider {provider!r} is not one of [[proxy.providers]]: "
                    f"{variable} would get no key"
                )

    def _check_sensor(self, config_dir: Path) -> None:
        if not isinstance(self.sensor, Mapping):
            raise ConfigError("[sensor] must be a table")
        _reject_secret_keys("[sensor]", self.sensor)
        unknown = sorted(set(self.sensor) - _SENSOR_KEYS)
        if unknown:
            raise ConfigError(f"unknown [sensor] settings: {', '.join(map(repr, unknown))}")
        if not isinstance(self.sensor.get("required", False), bool):
            raise ConfigError("[sensor] required must be true or false")
        streak = self.sensor.get("novelty_streak_minutes", NOVELTY_STREAK_MINUTES)
        if (
            isinstance(streak, bool)
            or not isinstance(streak, int | float)
            or not streak >= MIN_NOVELTY_STREAK_MINUTES
        ):
            raise ConfigError(
                f"[sensor] novelty_streak_minutes must be a number of minutes of at least "
                f"{MIN_NOVELTY_STREAK_MINUTES:g}, got {streak!r}"
            )
        if _overlap(config_dir, self.sensor_dir):
            raise ConfigError(
                f"the agent's config_dir {config_dir} must not be, contain or be inside the "
                f"sensor's folder {self.sensor_dir}: the agent would see what the sensor saw"
            )
        name = self.sensor_jail_config().name
        if name in (self.jail_config().name, self.proxy_jail_config().name):
            raise ConfigError(f"[sensor] name {name!r} is the name of another container")
        self.sensor_reader_config()

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
        """``[agent] config_dir``, or ``<state_dir>/<profile>`` (OpenClaw's: ``openclaw``)."""
        configured = self.agent.get("config_dir")
        if configured is not None:
            return Path(configured)
        return self.state_dir / self.agent_profile.name

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
    def sensor_dir(self) -> Path:
        """The process sensor's folder: never mounted into the agent (invariant 1)."""
        return self.state_dir / STATE_SENSOR

    @property
    def sensor_novelty_streak(self) -> float:
        """Seconds of command lines folded unseen, with no window free of them, after which a
        required sensor stops the agent (the founder's decision B, 2026-10-19)."""
        return float(self.sensor.get("novelty_streak_minutes", NOVELTY_STREAK_MINUTES)) * 60.0

    @property
    def sensor_required(self) -> bool:
        """Whether the agent may only run with the process sensor working (decision 7)."""
        return self.sensor.get("required", False) is True

    @property
    def workspace(self) -> Path:
        return self.volume / "workspace"

    @property
    def agent_profile(self) -> AgentProfile:
        """Which agent runs in the jail (docs/34, section 7): ``[agent] profile``, OpenClaw by
        default, or the ``custom`` one its settings describe."""
        return agent_profile_of(self.agent)

    def gateway_secrets(self) -> list[str]:
        """The Gateway token, to strike wherever it shows, when there is one: the profile's, or
        the one an OpenClaw left in ``gateway.token`` before the profile changed (the volume,
        the logs and the snapshots may still hold it). Only to strike: jail_config() passes the
        token to a profile that uses one, and never ``struck_token``."""
        return [
            token.reveal() for token in (self.gateway_token, self.struck_token) if token is not None
        ]

    def jail_config(self) -> AgentJailConfig:
        """The agent's container settings. It carries the token in the clear (it must reach
        ``docker create``'s environment), so do not log it; AgentJailConfig's repr hides it.
        The model providers go with their FAKE keys only (for the profile: OpenClaw puts them in
        openclaw.json, a custom agent gets one in its ``key_env``). The token only goes to a
        profile that uses it."""
        profile = self.agent_profile
        options = {
            key: value
            for key, value in self.agent.items()
            if key in _AGENT_KEYS and key != "config_dir"
        }
        ready = self.agent.get("ready")
        if isinstance(ready, Mapping) and "timeout" in ready:
            options["ready_timeout"] = ready["timeout"]  # agent_profile_of checked it
        token = self.gateway_token if profile.token_env is not None else None
        try:
            providers = tuple(
                ModelProvider(
                    name=p.name,
                    kind=p.kind,
                    host=p.host,
                    fake_key=self.provider_keys[p.name].fake,
                    models=p.models,
                    local=p.local is not None,  # T20: never where it is, only that it is local
                )
                for p in self.proxy_settings().providers
                if p.name in self.provider_keys
            )
            profile.check_providers(providers)
        except ValueError as error:
            raise ConfigError(f"invalid [proxy] providers: {error}") from error
        try:
            return AgentJailConfig(
                workspace=self.workspace,
                config_dir=self.agent_config_dir,
                ca_dir=self.agent_ca_dir,
                gateway_token=None if token is None else token.reveal(),
                model_providers=providers,
                protected=self.agent_protected(),
                profile=profile,
                **options,
            )
        except ValueError as error:
            raise ConfigError(f"invalid [agent] settings: {error}") from error

    def agent_protected(self) -> tuple[Protected, ...]:
        """What the agent must never see (T14a, backtide/jail/mounts.py). Its config and CA
        folders live in ``state_dir`` by default, and its workspace in ``volume``: exactly
        those may be mounted from there, and nothing else (a restore in progress, a folder a
        later version adds)."""
        in_state = tuple(
            folder
            for folder in (self.agent_config_dir, self.agent_ca_dir)
            if folder.is_relative_to(self.state_dir) and folder != self.state_dir
        )
        protected = [
            Protected("backtide's state folder", self.state_dir, allowed_inside=in_state),
            Protected("the black box", self.blackbox_db),
            Protected("the black box's key", self.blackbox_key),
            Protected("the black box's checkpoint", self.blackbox_checkpoint),
            Protected("the gateway token", self.gateway_token_file),
            Protected("the control socket", self.control_socket),
            Protected("the service lock", self.lock_file),
            Protected("the risk rules", self.rules_file),
            Protected("the providers' real keys", self.keys_dir),
            Protected("the proxy's channel", self.proxy_channel_dir),
            Protected("the proxy's CA and its key", self.proxy_ca_dir),
            Protected("the sensor's folder", self.sensor_dir),
            Protected(
                "the snapshot volume",
                self.volume,
                allowed_inside=(self.workspace / AGENT_DIR,),
            ),
            Protected("the snapshots", self.volume / SNAPSHOTS),
        ]
        if self.volume_image is not None:
            protected.append(Protected("the volume's image", self.volume_image))
        return tuple(protected)

    def model_providers(self) -> Providers:
        """The providers as the proxy gets them through the channel (docs/21, section 6): host,
        fake key and real key (inside the gate's own Secret; None while it waits for its key).
        ConfigError, never quoting a key, for a provider the gate cannot use or two providers
        that clash. A real key the gate cannot use is not an error: that provider waits."""
        return self.model_providers_and_problems()[0]

    def model_providers_and_problems(
        self, upstreams: Mapping[str, tuple[str, int]] | None = None
    ) -> tuple[Providers, dict[str, tuple[str, str]]]:
        """``model_providers`` and, for each provider that waits for its key, why
        (``KEY_MISSING`` or ``KEY_UNUSABLE``) and what is wrong, never quoting a key. Fails
        closed: a key file that cannot be read, a key of the wrong shape, a key two providers
        share and another provider's fake key all leave their provider waiting, never let
        through without its key. What such a file holds (if it is long enough to search for and
        not a fake key) is still struck and searched for: ``Providers.strike_only``.

        A local provider (T20) has no real key: whatever its key file holds is struck only. Its
        address is the one ``upstreams`` gives (the service resolved it), or its IPv4 as
        written; with neither (a name not resolved yet) it has none, and the channel will not
        hand it to the proxy (``runner.egress_policy`` resolves first)."""
        items: list[GateProvider] = []
        problems: dict[str, tuple[str, str]] = {}
        struck: list[str] = []  # real keys never swapped in: struck only (review of T09b)
        configured = [p for p in self.proxy_settings().providers if p.name in self.provider_keys]
        fakes = [self.provider_keys[p.name].fake for p in configured]
        for provider in configured:
            key = self.provider_keys[provider.name]
            if key.strike is not None:
                struck.append(key.strike.reveal())
            if provider.local is not None:
                if key.real is not None:
                    struck.append(key.real.reveal())  # never sent: struck wherever it shows
                items.append(self._local_provider(provider, key.fake, upstreams))
                continue
            fields = {
                "name": provider.name,
                "kind": provider.kind,
                "host": provider.host,
                "fake_key": key.fake,
                "models": provider.models,
                "stream_usage": provider.stream_usage,
            }
            try:
                waiting = GateProvider(**fields, real_key=None)  # type: ignore[arg-type]
            except ValueError as error:  # Provider's messages never hold a key
                raise ConfigError(f"[proxy] providers: {error}") from None
            if key.real is None:
                problems[provider.name] = (
                    key.problem or KEY_MISSING,
                    key.why or "no key file yet",
                )
                items.append(waiting)
                continue
            real = key.real.reveal()
            if holds_fake(real, fakes):  # another provider's fake key: it would clash
                problems[provider.name] = (
                    KEY_UNUSABLE,
                    f"provider {provider.name}: the real key cannot be a fake key",
                )
                items.append(waiting)
                continue
            try:
                items.append(
                    GateProvider(**fields, real_key=GateSecret(real))  # type: ignore[arg-type]
                )
            except ValueError as error:  # the real key's shape: it waits (fail closed)
                problems[provider.name] = (KEY_UNUSABLE, str(error))
                items.append(waiting)
                struck.append(real)
        reals = [p.real_key.reveal() for p in items if p.real_key is not None]
        shared = {real for real in reals if reals.count(real) > 1}
        for index, item in enumerate(items):
            if item.real_key is not None and item.real_key.reveal() in shared:
                struck.append(item.real_key.reveal())
                items[index] = dataclasses.replace(item, real_key=None)
                problems[item.name] = (KEY_UNUSABLE, "the same real key as another provider")
        strike_only = [k for k in struck if len(k) >= MIN_KNOWN_SECRET and not holds_fake(k, fakes)]
        try:
            return Providers(items, strike_only=strike_only), problems
        except ValueError as error:
            raise ConfigError(f"[proxy] providers: {error}") from None

    @staticmethod
    def _local_provider(
        provider: Provider, fake: str, upstreams: Mapping[str, tuple[str, int]] | None
    ) -> GateProvider:
        target = provider.local
        if target is None:
            raise ConfigError(f"[proxy] providers: {provider.name} is not local")
        upstream = (upstreams or {}).get(provider.name)
        if upstream is None and local_address_ok(target[0]):
            upstream = target  # an IPv4 as written: nothing to resolve
        try:
            return GateProvider(
                name=provider.name,
                kind=provider.kind,  # type: ignore[arg-type]
                host=provider.host,
                fake_key=fake,
                real_key=None,
                models=provider.models,
                local=True,
                upstream=upstream,
            )
        except ValueError as error:  # Provider's messages never hold a key
            raise ConfigError(f"[proxy] providers: {error}") from None

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
                backtide_uid=os.geteuid(),  # the one uid the proxy lets onto its channel
                **options,
            )
        except (TypeError, ValueError) as error:
            raise ConfigError(f"invalid [proxy] settings: {error}") from error

    def sensor_jail_config(self) -> SensorJailConfig:
        """The process sensor's container (docs/23, section 2). No secret in it."""
        options = {k: v for k, v in self.sensor.items() if k in _SENSOR_CONTAINER_KEYS}
        try:
            return SensorJailConfig(state_dir=self.sensor_dir, **options)
        except (TypeError, ValueError) as error:
            raise ConfigError(f"invalid [sensor] settings: {error}") from error

    def sensor_reader_config(self) -> ReaderConfig:
        """The reader of the sensor's events, with the rate limits of docs/23, section 6."""
        limits: dict[str, Any] = {}
        for key in sorted(_SENSOR_RATES | _SENSOR_COUNTS):
            if key not in self.sensor:
                continue
            value = self.sensor[key]
            number = int | float if key in _SENSOR_RATES else int
            if isinstance(value, bool) or not isinstance(value, number) or value <= 0:
                kind = "number" if key in _SENSOR_RATES else "whole number"
                raise ConfigError(f"[sensor] {key} must be a positive {kind}, got {value!r}")
            limits[key] = value
        jail = self.sensor_jail_config()
        return ReaderConfig(
            events_dir=jail.events_dir,
            cursor_file=jail.cursor_file,
            agent_name=self.jail_config().name,
            sensor_name=jail.name,
            **limits,
        )

    def ca_paths(self) -> CaPaths:
        """Where ca.py makes the proxy's CA, readable by the proxy's group only."""
        return CaPaths(
            proxy_dir=self.proxy_ca_dir,
            agent_dir=self.agent_ca_dir,
            gid=self.proxy_jail_config().gid,
        )

    def proxy_settings(self) -> ProxySettings:
        """``allow_hosts``, ``providers`` and ``allow_provider_tools`` of ``[proxy]``, checked
        (ConfigError)."""
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
        if sum(1 for provider in providers if provider.local is not None) > MAX_LOCAL:
            raise ConfigError(f"[proxy] providers: at most {MAX_LOCAL} local providers")
        tools = self.proxy.get("allow_provider_tools", [])
        if not isinstance(tools, list) or len(tools) > MAX_PROVIDER_TOOLS:
            raise ConfigError(
                f"[proxy] allow_provider_tools must be a list of at most {MAX_PROVIDER_TOOLS} "
                "tool names"
            )
        try:
            allowed = tuple(dict.fromkeys(check_allow_entry(tool) for tool in tools))
        except ValueError as error:
            raise ConfigError(f"[proxy] allow_provider_tools: {error}") from None
        # The fields the agent's own model client sends (decision 5 of docs/34): its profile's,
        # for it alone. Only top-level fields by name, never a provider-side tool.
        allowed = tuple(dict.fromkeys((*allowed, *self.agent_profile.provider_params)))
        if len(allowed) > MAX_PROVIDER_TOOLS:
            raise ConfigError(
                f"[proxy] allow_provider_tools and the agent's profile allow more than "
                f"{MAX_PROVIDER_TOOLS} provider fields and tools"
            )
        return ProxySettings(
            allow_hosts=tuple(hosts), providers=providers, allow_provider_tools=allowed
        )

    def gate_settings(self, owner_chat: int | None = None) -> GateSettings:
        """``[gate]``, checked (ConfigError). ``owner_chat``: the ``chat_id`` of
        ``telegram.toml``, trusted (with any bot, docs/32 section 9) unless ``trust_owner_chat
        = false``."""
        if not isinstance(self.gate, Mapping):
            raise ConfigError("[gate] must be a table")
        _reject_secret_keys("[gate]", self.gate)
        unknown = sorted(set(self.gate) - _GATE_KEYS)
        if unknown:
            raise ConfigError(f"unknown [gate] settings: {', '.join(map(repr, unknown))}")
        mode = self.gate.get("unknown_hosts", "hold")
        if mode not in UNKNOWN_HOSTS:
            raise ConfigError('[gate] unknown_hosts must be "hold" (the default) or "deny"')
        trust_owner = self.gate.get("trust_owner_chat", True)
        if not isinstance(trust_owner, bool):
            raise ConfigError("[gate] trust_owner_chat must be true or false")
        trusted = [_trusted(entry) for entry in _gate_list("trusted", self.gate, MAX_TRUSTED)]
        if trust_owner and owner_chat is not None:
            trusted.insert(0, normalize_trusted("telegram", str(owner_chat)))
        try:
            endpoints = tuple(
                dict.fromkeys(
                    check_read_endpoint(entry)
                    for entry in _gate_list("read_endpoints", self.gate, MAX_READ_ENDPOINTS)
                )
            )
        except ValueError as error:
            raise ConfigError(f"[gate] read_endpoints: {error}") from None
        times: dict[str, float] = {}
        for key, (name, low, high) in _GATE_TIMES.items():
            if key not in self.gate:
                continue
            value = self.gate[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ConfigError(f"[gate] {key} must be a whole number of seconds, {low}-{high}")
            times[name] = float(value)
        budgets: dict[str, int] = {}
        for key, default in _READ_BUDGETS.items():
            value = self.gate.get(key, default)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= MAX_READ_BUDGET_KIB
            ):
                raise ConfigError(
                    f"[gate] {key} must be a whole number of KiB, 0-{MAX_READ_BUDGET_KIB}"
                )
            budgets[key] = value * 1024
        return GateSettings(
            unknown_hosts=mode,
            trusted=tuple(dict.fromkeys(trusted)),
            read_endpoints=endpoints,
            timings=HoldTimings(**times),
            read_budget_host=budgets["read_budget_host_kib"],
            read_budget_total=budgets["read_budget_total_kib"],
        )

    def budget_settings(self) -> BudgetSettings:
        """``[budget]``, checked (ConfigError): the spending caps and the prices (T11)."""
        if not isinstance(self.budget, Mapping):
            raise ConfigError("[budget] must be a table")
        _reject_secret_keys("[budget]", self.budget)
        unknown = sorted(set(self.budget) - _BUDGET_KEYS)
        if unknown:
            raise ConfigError(f"unknown [budget] settings: {', '.join(map(repr, unknown))}")
        caps: dict[str, Decimal] = {}
        for key, default in (
            ("daily_usd", DEFAULT_DAILY_USD),
            ("monthly_usd", DEFAULT_MONTHLY_USD),
        ):
            value = self.budget.get(key, default)
            cap = value if isinstance(value, Decimal) else check_cap(_cap_text(value))
            if cap is None:
                raise ConfigError(
                    f"[budget] {key} must be a positive number of dollars, two decimals at most, "
                    f"up to {MAX_CAP_USD}"
                )
            caps[key] = cap
        zone_name = self.budget.get("timezone", "local")
        zone = None
        if zone_name != "local":
            try:
                zone = ZoneInfo(zone_name) if isinstance(zone_name, str) else None
            except (ZoneInfoNotFoundError, ValueError):
                zone = None
            if zone is None:
                raise ConfigError(
                    '[budget] timezone must be an IANA zone ("Europe/Madrid") or "local"'
                )
        inflight = self.budget.get("max_inflight", DEFAULT_MAX_INFLIGHT)
        if (
            isinstance(inflight, bool)
            or not isinstance(inflight, int)
            or not 1 <= inflight <= MAX_INFLIGHT
        ):
            raise ConfigError(f"[budget] max_inflight must be a whole number, 1-{MAX_INFLIGHT}")
        local_inflight = self.budget.get("max_inflight_local", DEFAULT_MAX_INFLIGHT_LOCAL)
        if (
            isinstance(local_inflight, bool)
            or not isinstance(local_inflight, int)
            or not 1 <= local_inflight <= MAX_INFLIGHT
        ):
            raise ConfigError(
                f"[budget] max_inflight_local must be a whole number, 1-{MAX_INFLIGHT}"
            )
        auto = self.budget.get("auto_prices", True)
        if not isinstance(auto, bool):
            raise ConfigError("[budget] auto_prices must be true or false")
        url = self.budget.get("prices_url", PRICES_URL)
        try:
            url = check_url(url)
        except ValueError as error:
            raise ConfigError(f"[budget] {error}") from None
        return BudgetSettings(
            daily_usd=caps["daily_usd"],
            monthly_usd=caps["monthly_usd"],
            timezone=zone,
            timezone_name=str(zone_name),
            max_inflight=inflight,
            max_inflight_local=local_inflight,
            auto_prices=auto,
            prices_url=url,
            owner_prices=_owner_prices(self.budget.get("prices", {})),
        )

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
        token = struck = None
        token_file = state_dir / STATE_TOKEN
        if agent_profile_of(agent).token_env is not None:  # OpenClaw's Gateway; others have none
            text = _decode(
                _read_file(token_file, "gateway token file", MAX_TOKEN_BYTES, private=True)
            )
            token = Secret(text.strip())
        else:
            struck = read_token_to_strike(token_file)
        optional = {key: data[key] for key in _OPTIONAL_KEYS if key in data}
        if "volume_image" in data:
            optional["volume_image"] = _as_path("volume_image", data["volume_image"])
        if "proxy" in data:
            if not isinstance(data["proxy"], dict):
                raise ConfigError("[proxy] must be a table")
            optional["proxy"] = dict(data["proxy"])
        if "sensor" in data:
            if not isinstance(data["sensor"], dict):
                raise ConfigError("[sensor] must be a table")
            optional["sensor"] = dict(data["sensor"])
        if "gate" in data:
            if not isinstance(data["gate"], dict):
                raise ConfigError("[gate] must be a table")
            optional["gate"] = dict(data["gate"])
        if "budget" in data:
            if not isinstance(data["budget"], dict):
                raise ConfigError("[budget] must be a table")
            optional["budget"] = dict(data["budget"])
        names = _provider_names(optional.get("proxy", {}))
        if names:
            optional["provider_keys"] = read_provider_keys(state_dir / STATE_KEYS, names)
        return cls(
            state_dir=state_dir,
            volume=volume,
            gateway_token=token,
            struck_token=struck,
            agent=agent,
            **optional,
        )


def agent_profile_of(agent: Mapping[str, Any]) -> AgentProfile:
    """The agent profile ``[agent]`` describes (docs/34, section 7): ``profile`` names one of
    the named profiles (OpenClaw by default) or ``custom``, whose own settings describe it
    (profiles/custom.py). Refuses (ConfigError) any setting of the jail, ``ports``, a setting
    only a custom agent has given to a named profile, and every check of the profile. Pure: the
    image's own environment is checked when the agent starts (AgentJail)."""
    if not isinstance(agent, Mapping):
        raise ConfigError("[agent] must be a table")
    ports = sorted(set(agent) & _PORTS)
    if ports:
        raise ConfigError(
            f"[agent] {', '.join(map(repr, ports))}: an agent on its internal network publishes "
            "no port (docs/34, P9); a web of the agent would need a relay of backtide"
        )
    jail = sorted(set(agent) & _JAIL_KEYS)
    if jail:
        raise ConfigError(
            f"[agent] {', '.join(map(repr, jail))}: the jail decides it, the same for every "
            "agent (docs/34, section 6), and no setting changes it"
        )
    unknown = sorted(set(agent) - _AGENT_KEYS - CUSTOM_KEYS - {"profile"})
    if unknown:
        raise ConfigError(f"unknown [agent] settings: {', '.join(map(repr, unknown))}")
    name = agent.get("profile", DEFAULT_PROFILE.name)
    own = {key: value for key, value in agent.items() if key in CUSTOM_KEYS}
    if name != CUSTOM:
        if name not in NAMED:
            raise ConfigError(
                f"[agent] profile must be one of {', '.join(map(repr, profile_names()))}, "
                f"got {name!r:.80}"
            )
        if own and (name not in WITH_PROVIDER or set(own) != {"model"}):
            raise ConfigError(
                f'[agent] {", ".join(map(repr, sorted(own)))}: only for profile = "{CUSTOM}" '
                f"(the {name} profile has its own)"
            )
        if own:
            return _named_with_provider(name, own["model"])
        return NAMED[name]
    _check_ready_timeout(agent)
    try:
        return custom_profile(agent.get("image"), own)
    except ValueError as error:
        raise ConfigError(f"invalid [agent] (profile custom): {error}") from None


def _named_with_provider(name: str, model: object) -> AgentProfile:
    """A named profile thinking with the provider ``[agent.model] provider`` names (T20-4:
    Claude Code with a local Ollama). Only ``provider``: the rest is the profile's own."""
    if (
        not isinstance(model, Mapping)
        or set(model) != {"provider"}
        or not isinstance(model["provider"], str)
    ):
        raise ConfigError(
            f'[agent.model] of the {name} profile takes only provider = "<a name of '
            '[[proxy.providers]]>"'
        )
    if not is_provider_name(model["provider"]):  # never quoted: it may be a pasted key
        raise ConfigError(
            f"[agent.model] provider of the {name} profile is not a provider name "
            f"({PROVIDER_NAME_RULE})"
        )
    try:
        return WITH_PROVIDER[name](model["provider"])
    except ValueError as error:
        raise ConfigError(f"invalid [agent.model] (profile {name}): {error}") from None


def _check_ready_timeout(agent: Mapping[str, Any]) -> None:
    ready = agent.get("ready")
    if not isinstance(ready, Mapping) or "timeout" not in ready:
        return
    if "ready_timeout" in agent:
        raise ConfigError("[agent] ready_timeout and [agent.ready] timeout: set only one")
    timeout = ready["timeout"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or not math.isfinite(timeout)  # TOML has inf and nan
        or not 0 < timeout <= MAX_READY_TIMEOUT
    ):
        raise ConfigError(
            "[agent.ready] timeout must be a number of seconds above 0 and at most "
            f"{MAX_READY_TIMEOUT:g} (backtide waits for the agent that long with the cycle on hold)"
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


def _provider_names(proxy: Mapping[str, Any]) -> list[str]:
    """The names of the providers of ``[proxy]`` (each checked), to read their keys."""
    entries = proxy.get("providers", []) if isinstance(proxy, Mapping) else []
    if not isinstance(entries, list) or len(entries) > MAX_PROVIDERS:
        return []  # the full check (ServiceConfig) says what is wrong
    names = [_provider(entry).name for entry in entries]
    if len(set(names)) != len(names):
        raise ConfigError("[proxy] providers: each name must appear once")
    return names


def read_provider_keys(folder: Path, names: list[str]) -> dict[str, ProviderKey]:
    """The keys of each provider in ``names``: ``<name>.key``, the real one, which the person
    puts there (the Settings page, or by hand); and ``<name>.fake``, made here the first time
    (0600, never replaced). The folder is made (0700) if there is none yet; it must be ours and
    0700, and nothing in it a symlink.

    A provider whose ``<name>.key`` is missing, or cannot be used, waits for its key
    (``real`` None, ``read_real_key``): backtide starts and the proxy refuses its calls. A
    folder or a fake key that cannot be used is a ConfigError, saying what a file IS (path,
    size, mode, owner) and never what it holds."""
    try:
        os.mkdir(folder, 0o700)  # the umask can only take bits away; checked below
    except FileExistsError:
        pass  # whatever is there (a link, a folder open to others) the check refuses
    except OSError as error:
        raise ConfigError(
            f"cannot make the keys folder {folder}: {os.strerror(error.errno or 0)}"
        ) from None
    _require_private_dir(folder, "the keys folder")
    keys = {}
    for name in names:
        fake = _fake_key(folder / f"{name}.fake", name)
        real, problem, why = read_real_key(folder, name)
        strike = read_strike_only(folder, name) if problem == KEY_UNUSABLE else None
        keys[name] = ProviderKey(real=real, fake=fake, problem=problem, why=why, strike=strike)
    return keys


def read_real_keys(
    folder: Path, names: list[str]
) -> dict[str, tuple[Secret | None, str | None, str | None]]:
    """``read_real_key`` for each of ``names``, after checking the folder (ours, 0700, not a
    link). A folder that cannot be used leaves every provider waiting (``KEY_UNUSABLE``).
    Never raises."""
    try:
        _require_private_dir(folder, "the keys folder")
    except ConfigError as error:
        return {name: (None, KEY_UNUSABLE, str(error)) for name in names}
    return {name: read_real_key(folder, name) for name in names}


def read_real_key(
    folder: Path,
    name: str,
    *,
    pause: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> tuple[Secret | None, str | None, str | None]:
    """``(key, None, None)`` from ``<folder>/<name>.key``, or ``(None, problem, why)`` when
    there is none (``KEY_MISSING``) or it cannot be used (``KEY_UNUSABLE``: not 0600 and ours,
    a link, too big, not UTF-8, empty, or changed while it was read). ``why`` says what the file
    IS, never what it holds. The folder is the caller's to check. Never raises.

    The file is read twice, ``KEY_SETTLE_S`` apart (``pause``), and taken only if it is the same
    file with the same size, times and bytes both times: a key written by hand may be half
    written (review of T09b, finding 3). A change waits; the next reload reads it again. The
    Settings page writes atomically, and so does ``mv`` from a temporary file.

    Before that, the file must not have changed (its contents nor its inode: mtime and ctime)
    for ``KEY_STILL_S`` by ``clock`` (review of 40dfd53, finding 6): a hand that writes a key in
    two goes with a pause between them is not caught by the double read alone. A fresher file
    is waited for once, at most ``KEY_STILL_S`` (the Settings page's own reload meets that);
    if it is still fresh after it (written again, or a time in the future), it waits until the
    next reload."""
    path = folder / f"{name}.key"
    still = KEY_STILL_S  # read now: the unit tests turn it off
    try:
        if not os.path.lexists(path):
            return None, KEY_MISSING, f"there is no {path} yet"
        first, before = _read_file_info(path, "real key file", MAX_KEY_BYTES, private=True)
        if still > 0 and (fresh := still - _age(before, clock)) > 0:
            pause(min(fresh, still))
            first, before = _read_file_info(path, "real key file", MAX_KEY_BYTES, private=True)
        settled = still <= 0 or _age(before, clock) >= still
        pause(KEY_SETTLE_S)
        second, after = _read_file_info(path, "real key file", MAX_KEY_BYTES, private=True)
    except ConfigError as error:
        return None, KEY_UNUSABLE, str(error)
    except OSError as error:
        return None, KEY_UNUSABLE, f"cannot read {path}: {os.strerror(error.errno or 0)}"
    if not settled:
        return (
            None,
            KEY_UNUSABLE,
            (
                f"real key file {path} of provider {name} changed a moment ago (or its time is "
                "in the future): write keys with the Settings page, or with mv from a temporary "
                "file; it is read again at the next reload"
            ),
        )
    if first != second or _identity(before) != _identity(after):
        return (
            None,
            KEY_UNUSABLE,
            (
                f"real key file {path} of provider {name} changed while it was read: write keys "
                "with the Settings page, or with mv from a temporary file; it is read again at the "
                "next reload"
            ),
        )
    del second
    try:
        real = _decode(first).strip()
    except ConfigError as error:
        return None, KEY_UNUSABLE, str(error)
    if not real:
        return None, KEY_UNUSABLE, f"real key file {path} of provider {name} is empty"
    return Secret(real), None, None


def read_token_to_strike(path: Path) -> Secret | None:
    """What a ``gateway.token`` left by an OpenClaw holds, for a profile that has no token: to
    strike wherever it shows (the agent's volume and snapshots may hold it), never to use. Only
    a regular file of the service's own user, never through a link, at most MAX_TOKEN_BYTES of
    UTF-8; None if there is none or nothing of MIN_KNOWN_SECRET characters. Never raises, never
    says what it read: a file that cannot be used for OpenClaw can still be struck."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_size > MAX_TOKEN_BYTES
        ):
            return None
        data = os.read(fd, MAX_TOKEN_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if len(data) > MAX_TOKEN_BYTES or len(value) < MIN_KNOWN_SECRET:
        return None
    return Secret(value)


def read_strike_only(folder: Path, name: str) -> Secret | None:
    """What ``<folder>/<name>.key`` holds although it cannot be used as a key (open to others,
    of the wrong shape, changed while read), to strike wherever it shows and never to swap in
    (review of T09b, finding 2). Only a regular file of the service's own user (review of
    40dfd53, finding 5), never through a link, at most MAX_KEY_BYTES of UTF-8; None if there is
    nothing of MIN_KNOWN_SECRET characters or more. Never raises, never says what it read."""
    path = folder / f"{name}.key"
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_size > MAX_KEY_BYTES
        ):
            return None
        data = os.read(fd, MAX_KEY_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > MAX_KEY_BYTES:
        return None
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    return Secret(value) if len(value) >= MIN_KNOWN_SECRET else None


def _age(info: os.stat_result, clock: Callable[[], float]) -> float:
    """Seconds since the file last changed (its contents or its inode), by ``clock``."""
    return clock() - max(info.st_mtime, info.st_ctime)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """What tells a file, and a change to it, apart: device, inode, size and both times."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def holds_fake(key: str, fakes: list[str]) -> bool:
    """Whether ``key`` is, holds or is held in one of the providers' fake keys."""
    return any(key in fake or fake in key for fake in fakes)


def _fake_key(path: Path, name: str) -> str:
    """The fake key in ``path``, made (``O_EXCL``, 0600) if there is none yet."""
    if not os.path.lexists(path):
        fake = new_fake_key(name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            pass  # made meanwhile by another backtide: read it below
        except OSError as error:
            raise ConfigError(
                f"cannot make fake key file {path}: {os.strerror(error.errno or 0)}"
            ) from None
        else:
            try:
                os.write(fd, (fake + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
    value = _decode(_read_file(path, "fake key file", MAX_KEY_BYTES, private=True)).strip()
    if not is_fake_key(value, name):
        raise ConfigError(
            f"fake key file {path} does not hold a fake key of provider {name}: delete it and "
            "backtide makes a new one"
        )
    return value


def _require_private_dir(path: Path, what: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise ConfigError(
            f"cannot read {what} {path}: {os.strerror(error.errno or 0)} (it holds the providers' "
            "real keys: create it, 0700, and put each key in <name>.key, 0600)"
        ) from None
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        raise ConfigError(f"{what} {path} is a symlink: refusing it")
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError(f"{what} {path} is not a directory")
    if info.st_uid != os.geteuid():
        raise ConfigError(f"{what} {path} is owned by uid {info.st_uid}, not {os.geteuid()}")
    if mode & 0o077:
        raise ConfigError(f"{what} {path} is open to group or others ({mode:04o}): chmod 700 it")


def _cap_text(value: object) -> str | None:
    """A cap from TOML: a number (never a bool) or a text, as ``check_cap`` reads it."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return repr(value) if isinstance(value, float) else str(value)
    return value if isinstance(value, str) else None


def _owner_prices(table: object) -> dict[str, Price]:
    """``[budget.prices]``: per model, ``input`` and ``output`` in $/MTok and optionally the cache's
    prices (by default 0.1x, 1.25x and 2x of the input)."""
    if not isinstance(table, Mapping):
        raise ConfigError("[budget.prices] must be a table of models")
    if len(table) > MAX_OWNER_PRICES:
        raise ConfigError(f"[budget.prices] has more than {MAX_OWNER_PRICES} models")
    prices: dict[str, Price] = {}
    for model, entry in table.items():
        if not isinstance(model, str) or not 0 < len(model) <= 128 or not model.isprintable():
            raise ConfigError("[budget.prices]: a model name must be a short text")
        if not isinstance(entry, Mapping) or not {"input", "output"} <= set(entry):
            raise ConfigError(f"[budget.prices] {model!r}: needs input and output ($/MTok)")
        unknown = sorted(set(entry) - _PRICE_KEYS)
        if unknown:
            raise ConfigError(f"[budget.prices] {model!r}: unknown fields {unknown}")
        try:
            values = {name: to_decimal(value) for name, value in entry.items()}
            base = values["input"]
            prices[model] = Price(
                input=base,
                output=values["output"],
                cache_write_5m=values.get("cache_write_5m", base * CACHE_5M),
                cache_write_1h=values.get("cache_write_1h", base * CACHE_1H),
                cache_read=values.get("cache_read", base * CACHE_READ),
            )
        except PriceError as error:
            raise ConfigError(f"[budget.prices] {model!r}: {error}") from None
    return prices


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
    stream_usage = entry.get("stream_usage", True)
    if "stream_usage" in entry and (
        not isinstance(stream_usage, bool) or kind != "openai" or "local" in entry
    ):
        raise ConfigError(
            f"[proxy] providers: {name}'s stream_usage is true or false, and only for a provider "
            'of kind "openai" that is not local (the proxy never asks the others)'
        )
    if "local" in entry:
        return _local_provider(name, kind, entry)
    host = entry.get("host", PROVIDER_HOSTS[kind])
    _check_host(f"[proxy] providers: {name}'s host", host)
    if "*" in host:
        raise ConfigError(f"[proxy] providers: {name}'s host must be one exact name")
    if host.lower().rstrip(".").endswith(LOCAL_SUFFIX):
        raise ConfigError(
            f"[proxy] providers: {name}'s host is a virtual name of backtide's: a local provider "
            'says where it is with local = "http://<name or IPv4>:<port>"'
        )
    others = {default for other, default in PROVIDER_HOSTS.items() if other != kind}
    if host.lower().rstrip(".") in others:
        raise ConfigError(
            f"[proxy] providers: {name} is of kind {kind} but its host is another kind's: its "
            "real key would go to the wrong provider"
        )
    models = entry.get("models", [])
    if (
        not isinstance(models, list)
        or len(models) > MAX_PROVIDER_MODELS
        or not all(isinstance(m, str) and MODEL_ID.fullmatch(m) for m in models)
    ):
        raise ConfigError(
            f"[proxy] providers: {name}'s models must be a list of at most "
            f"{MAX_PROVIDER_MODELS} model ids"
        )
    return Provider(
        name=name, kind=kind, host=host, models=tuple(models), stream_usage=stream_usage
    )


def _local_provider(name: str, kind: str, entry: Mapping[str, Any]) -> Provider:
    """A local provider (T20, docs/35 section 6.1): ``local`` exactly ``http://<name or
    IPv4>:<port>``, no ``host`` (its host is its virtual name), its models listed and none of
    Ollama's cloud. A name is resolved by the service; an IPv4 must be private already."""
    if "host" in entry:
        raise ConfigError(
            f"[proxy] providers: {name} is local: its host is {virtual_host(name)}, so it has "
            "no host setting"
        )
    text = entry["local"]
    match = _LOCAL_RE.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise ConfigError(
            f"[proxy] providers: {name}'s local must be exactly http://<name or IPv4>:<port> "
            "(no path, user, query or https: Ollama speaks plain HTTP)"
        )
    target, port = match.group("host"), int(match.group("port"))
    if not 0 < port < 65536:
        raise ConfigError(f"[proxy] providers: {name}'s local port must be 1-65535")
    numeric = numeric_ipv4(target)
    if numeric is not None:
        if numeric != target or not local_address_ok(target):
            raise ConfigError(
                f"[proxy] providers: {name}'s local address must be a private IPv4 written "
                "a.b.c.d, in 10/8, 172.16/12, 192.168/16 or 100.64/10 (never loopback, "
                "link-local or public)"
            )
    else:
        host = normalize_host(target)
        if host is None or is_ip(host) or host == "localhost" or host.endswith(".localhost"):
            raise ConfigError(
                f"[proxy] providers: {name}'s local must name a machine (loopback is the proxy "
                "itself: use host.lima.internal for the Mac)"
            )
        target = host
    models = entry.get("models", [])
    if (
        not isinstance(models, list)
        or not models
        or len(models) > MAX_PROVIDER_MODELS
        or not all(isinstance(m, str) and MODEL_ID.fullmatch(m) for m in models)
    ):
        raise ConfigError(
            f"[proxy] providers: {name} is local, so it lists its models (1 to "
            f"{MAX_PROVIDER_MODELS} model ids)"
        )
    cloud = [m for m in models if is_cloud_model(m)]
    if cloud:
        raise ConfigError(
            f"[proxy] providers: {name} is local, but {', '.join(cloud)} runs in Ollama's cloud "
            "(its data would leave home): list local models only"
        )
    return Provider(
        name=name, kind=kind, host=virtual_host(name), models=tuple(models), local=(target, port)
    )


def _gate_list(key: str, gate: Mapping[str, Any], limit: int) -> list[Any]:
    value = gate.get(key, [])
    if not isinstance(value, list) or len(value) > limit:
        raise ConfigError(f"[gate] {key} must be a list of at most {limit} entries")
    return value


def _trusted(entry: object) -> Trusted:
    """A ``[gate] trusted`` entry: ``{translator = "telegram", chat = "..."}``, ``{translator =
    "gmail", email = "..."}`` or ``{translator = "slack", channel = "C..."}``."""
    if not isinstance(entry, dict) or not isinstance(entry.get("translator"), str):
        raise ConfigError("[gate] trusted: each entry is a table with a translator")
    translator = entry["translator"]
    name = _TRUSTED_FIELD.get(translator)
    if name is None:
        raise ConfigError(
            f"[gate] trusted: translator must be one of {', '.join(sorted(_TRUSTED_FIELD))}"
        )
    if set(entry) != {"translator", name}:
        raise ConfigError(f"[gate] trusted: a {translator} entry has translator and {name}")
    value = entry[name]
    if isinstance(value, int) and not isinstance(value, bool) and name == "chat":
        value = str(value)
    if not isinstance(value, str):
        raise ConfigError(f"[gate] trusted: {name} must be a text")
    try:
        return normalize_trusted(translator, value)
    except ValueError as error:
        raise ConfigError(f"[gate] trusted: {error}") from None


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
    return _read_file_info(path, what, max_bytes, private=private)[0]


def _read_file_info(
    path: Path, what: str, max_bytes: int, *, private: bool
) -> tuple[bytes, os.stat_result]:
    """``_read_file``, and the ``fstat`` of the file it read."""
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
    return data, info


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"the file is not valid UTF-8 ({len(data)} bytes)") from None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _overlap(a: Path, b: Path) -> bool:
    return a.is_relative_to(b) or b.is_relative_to(a)
