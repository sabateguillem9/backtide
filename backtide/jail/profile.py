"""What changes from one agent to another, and nothing else: the agent profile (T17). Pure.

Design: docs/34-diseno-t17-cualquier-agente.md, sections 5 to 7. The jail is the same for every
agent; a profile only fills in what the agent needs to work inside it: its image, how it starts,
the variables it reads, the files backtide writes for it in ``/config``, how it gets its fake
model key, how backtide knows it is ready, what the rewind notice says about it and the
provider-side fields its model client sends.

Nothing that decides the jail's security comes from here, and an AgentProfile has no field for
it: the uid and gid, the capabilities, seccomp, the read-only root, the tmpfs and the /sys
masks, the mounts, the network, the limits, ``HOME``, the proxy's variables and the CA's path
are AgentJailConfig's (backtide/jail/config.py) and the same for every agent. A profile cannot
set a variable the jail sets itself, nor one of the families that change how programs load code
or find the network (``is_reserved_env``: ``LD_*``, ``NODE_OPTIONS``, ``PYTHON*``, ``PERL5*``,
``GIT_CONFIG_*``, ``npm_config_*``, ``BASH_FUNC_*``, every ``*_PROXY``...). The list is by
families and grows when a new way to load code shows up: it is a floor, not a complete list of
what an environment variable can do. A profile cannot either name a variable the docker CLI
reads on the host (``reaches_docker_cli``: its values travel in that CLI's environment), nor
allow anything at the provider but plain top-level fields by name (``param:<name>``, decision
5): never a provider-side tool, search or retrieval. A wrong profile can stop its agent from
working, never let it escape or send anything unrecorded.

The jail's layout inside the container lives here too: a profile names those paths (OpenClaw's
state folder, its config file) but never changes them.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from backtide.blackbox.redact import strike_text
from backtide.gate.provider_tools import check_profile_param
from backtide.gate.providers import FAKE_KEY_PREFIX

if TYPE_CHECKING:
    from backtide.jail.config import AgentJailConfig
    from backtide.jail.model import ModelProvider

# The container's layout: the same for every profile. The agent writes only below /workspace
# (its folder in the snapshotted volume); /config is read-only.
CONTAINER_WORKSPACE = PurePosixPath("/workspace")
CONTAINER_CONFIG_DIR = PurePosixPath("/config")
HOME_DIR = "home"  # HOME is always /workspace/home: the jail sets it, never a profile
CONTAINER_HOME = CONTAINER_WORKSPACE / HOME_DIR
CONTAINER_STATE = CONTAINER_WORKSPACE / "state"
CONTAINER_WORK = CONTAINER_WORKSPACE / "work"

# Variables a profile may never set (docs/34, section 6): those the jail sets itself (config.py
# checks it has them all), and those that change how a program finds its code, its shell or its
# network. By name here and by family below (_RESERVED_SHAPES), whatever the case: not a
# complete list of what a variable can do, a floor that grows with each new way found.
RESERVED_ENV = frozenset(
    {
        "HOME", "DO_NOT_TRACK", "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
        "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_OPTIONS",
        "BASH_ENV", "CLAUDE_ENV_FILE", "ENV", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
        "NODE_PATH", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_SSL_NO_VERIFY",
        "NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY", "NODE_REPL_EXTERNAL_MODULE",
        "NODE_ICU_DATA", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS",
        "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF",
        "PROMPT_COMMAND", "PS4", "SHELLOPTS", "BASHOPTS", "ZDOTDIR", "PERLLIB",
        "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "GCONV_PATH", "GLIBC_TUNABLES", "HOSTALIASES",
        "LOCALDOMAIN", "RES_OPTIONS", "OPENSSL_CONF", "OPENSSL_MODULES", "SSLKEYLOGFILE",
        "CURL_HOME", "WGETRC", "LUA_INIT", "LUA_PATH", "LUA_CPATH",
    }
)  # fmt: skip
# By family, whatever the case: every *_PROXY (HTTP_PROXY, ALL_PROXY, No_proxy...), the dynamic
# loaders' LD_* and DYLD_*, git's GIT_CONFIG_* (GIT_CONFIG_COUNT, KEY_0, VALUE_0, PARAMETERS),
# bash's exported functions, Perl's, Ruby's, Python's and Java's own, and npm's settings.
_RESERVED_SHAPES = tuple(
    re.compile(shape, re.IGNORECASE)
    for shape in (
        r".*_PROXY", r"LD_.*", r"DYLD_.*", r"GIT_CONFIG_.*", r"BASH_FUNC_.*", r"PERL5.*",
        r"RUBY.*", r"PYTHON.*", r".*_JAVA_OPTIONS", r"NPM_CONFIG_.*",
    )
)  # fmt: skip
# Code, or settings that run code, as they are read (shell code, git's config given by
# variables: ``core.fsmonitor``, ``core.sshCommand``...): an image may set none of them, there
# is no path to look at.
_CODE_SHAPES = tuple(
    re.compile(shape, re.IGNORECASE)
    for shape in (
        r"PROMPT_COMMAND", r"PS4", r"ENV", r"BASH_FUNC_.*", r"SHELLOPTS", r"BASHOPTS",
        r"GIT_CONFIG_(?:COUNT|KEY_.*|VALUE_.*|PARAMETERS)", r"GIT_SSH_COMMAND",
        r"GIT_PROXY_COMMAND",
    )
)  # fmt: skip
# Lists of folders a program looks for code in, ``:``-separated: every entry must be absolute.
_PATH_LIST_SHAPES = tuple(
    re.compile(shape, re.IGNORECASE)
    for shape in (
        r".*PATH", r"LD_LIBRARY_PATH", r"PERL5LIB", r"PERLLIB", r"RUBYLIB", r"GCONV_PATH",
    )
)  # fmt: skip
# Where the agent can write inside its container, or reach what it writes: a variable of the
# image that points there hands it code that runs in every later process (the jail's probes,
# the battery's scripts, ``/bin/true``). ``~`` and ``$`` expand to who knows where (HOME is
# /workspace/home).
_AGENT_WRITABLE = ("/workspace", "/tmp", "/var/tmp", "/dev/shm", "/proc", "/dev/fd", "/run")  # noqa: S108 - inside the container
_EXPANSIONS = ("~", "$", "`")
_NUMBER_RE = re.compile(r"[0-9][0-9.]*[kmgKMG%]?", re.ASCII)
# What the docker CLI (and the Go programs it runs: its plugins, credential helpers) reads from
# its own environment on the host. The profile's variables, the token and the fake key reach
# ``docker create`` through that environment (``--env NAME``, never their values in the argv),
# so none of them may be one of these: ``DOCKER_HOST`` would point backtide's own docker at
# another daemon, ``DOCKER_CONFIG`` at another config, ``GO*`` and ``OTEL_*`` change how the
# CLI runs or where it reports, ``SSH_*`` and ``DBUS_*`` what its ssh:// contexts and credential
# helpers talk to. ``LC_ALL`` is always ``C`` for the CLI (docker.run sets it last), so a
# profile's value could never reach the agent: refused too.
_DOCKER_CLI_SHAPES = tuple(
    re.compile(shape, re.IGNORECASE)
    for shape in (
        r"DOCKER_.*", r"BUILDKIT_.*", r"BUILDX_.*", r"COMPOSE_.*", r"GO.*", r"OTEL_.*",
        r"NOTARY_.*", r"SSH_.*", r"DBUS_.*", r"LC_ALL", r"TMPDIR", r"XDG_RUNTIME_DIR",
        r"KUBECONFIG", r"CONTAINERD_.*", r"MOBY_.*",
    )
)  # fmt: skip
# The variable that gets a fake model key says so by its name (``ANTHROPIC_API_KEY``,
# ``OPENAI_API_KEY``, ``..._TOKEN``): never one that means something else to a program.
_KEY_SUFFIXES = ("_KEY", "_TOKEN")
# A profile's own variables never carry a secret: the fake key and the Gateway token have their
# own fields, and their values never go in the argv.
_SECRET_WORDS = ("KEY", "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL")
# What the image's own environment may hold under a secret's name, being public: the GPG key
# id that python's images verify their download with, checksums and versions.
_PUBLIC_IMAGE_NAMES = ("GPG_KEY",)
_PUBLIC_IMAGE_SUFFIXES = ("_SHA256", "_VERSION")
MAX_NOTICE_LINE = 300  # characters of one line of the rewind notice: a sentence, not a page

# Never a first "-": docker would read the image as one of its own options.
PINNED_IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}", re.ASCII)
_PROFILE_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", re.ASCII)
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}", re.ASCII)
# A program name or path: never something docker could read as one of its own options.
_PROGRAM_RE = re.compile(r"[A-Za-z0-9_./][A-Za-z0-9_./+-]{0,255}", re.ASCII)
_DIR_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}", re.ASCII)
# A file of /config: no dot first (``.<name>.tmp`` is the write in progress), no path.
_CONFIG_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", re.ASCII)
_PROVIDER_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", re.ASCII)
MAX_ARGS = 64
MAX_TEXT = 4096


class ProfileError(ValueError):
    """The config a profile renders cannot be run safely (OpenClaw: a setting a rewind would
    revive, ``UnrewindableConfig``). ``notice`` is one Spanish line for the user and ``paths``
    say where; neither holds a value of the config, so no secret can reach a log."""

    @property
    def notice(self) -> str:
        return (
            "La configuración del agente no se puede usar con seguridad; el detalle está en el log."
        )

    @property
    def paths(self) -> tuple[str, ...]:
        return ()


def is_reserved_env(name: str) -> bool:
    """Whether ``name`` is a variable only the jail may set, or none may."""
    return name.upper() in RESERVED_ENV or any(shape.fullmatch(name) for shape in _RESERVED_SHAPES)


def reaches_docker_cli(name: str) -> bool:
    """Whether the docker CLI on the host, or a program it runs, reads ``name`` itself."""
    return any(shape.fullmatch(name) for shape in _DOCKER_CLI_SHAPES)


def image_secret(name: str, value: str) -> bool:
    """Whether the image's own variable ``name=value`` looks like it carries a secret: as for a
    profile's (``secret_shaped``), or a non-empty value under a secret's name (``..._TOKEN``,
    ``..._KEY``, ``PASSWORD``...), except the public ones images carry (``GPG_KEY``,
    ``*_SHA256``, ``*_VERSION``). Docker hands every one of them to the agent."""
    if secret_shaped(name, value):
        return True
    upper = name.upper()
    if not value or upper in _PUBLIC_IMAGE_NAMES or upper.endswith(_PUBLIC_IMAGE_SUFFIXES):
        return False
    return any(word in upper for word in _SECRET_WORDS)


def image_env_problem(name: str, value: str) -> str | None:
    """Why the image's own variable ``name=value`` cannot reach the agent, or None. Only for a
    reserved name (``is_reserved_env``) that the jail does not set itself (the jail's value
    wins over the image's): a proxy setting, code (shell, git's config), or something that
    points where the agent writes (``/workspace``, ``/tmp``...), expands (``~``, ``$``) or is
    relative (a folder the agent is in). Never quotes the value. What passes is the pinned
    image's own (absolute paths on the read-only root), and AgentJail logs it."""
    if not value or not is_reserved_env(name):
        return None
    if name.upper().endswith("_PROXY"):
        return "a proxy setting: the jail's alone"
    if any(shape.fullmatch(name) for shape in _CODE_SHAPES):
        return "code that runs as it is read"
    if any(mark in value for mark in _EXPANSIONS):
        return "it expands: unchecked"
    for token in re.split(r"[\s:=,;]+", value):
        if not token or token.startswith("-"):
            continue
        if token.startswith("/"):
            if any(token == place or token.startswith(f"{place}/") for place in _AGENT_WRITABLE):
                return "points where the agent writes"
        elif "/" in token or token.startswith("."):
            return "a relative path: the agent's folder"
        elif name.upper() == "NODE_OPTIONS" and not _NUMBER_RE.fullmatch(token):
            # --require x, --import x, --loader x: Node looks for x from where it runs.
            return "a module Node looks for in the agent's folder"
    if any(shape.fullmatch(name) for shape in _PATH_LIST_SHAPES) and any(
        not entry.startswith("/") for entry in value.split(":")
    ):
        return "an empty or relative entry: the agent's folder"
    return None


def secret_shaped(name: str, value: str) -> bool:
    """Whether the variable ``name=value`` looks like it carries a secret: a value of a known
    secret's shape (``sk-...``, ``ghp_...``, a JWT, a URL with a password...), a fake key, or a
    non-empty value under a secret's name (``..._TOKEN``, ``..._API_KEY``...: the black box's
    own rules, backtide/blackbox/redact.py). Used for a profile's variables and for the image's
    own environment (docs/34, section 6); a name alone, with an empty value, is no secret."""
    if not value:
        return False
    pair = f"{name}={value}"
    return FAKE_KEY_PREFIX in value or strike_text(value) != value or strike_text(pair) != pair


def _no_files(config: "AgentJailConfig") -> dict[str, str]:
    del config
    return {}


def _no_check(files: Mapping[str, str]) -> None:
    del files


def _any_answer(output: str) -> bool:
    del output
    return True


def _any_providers(providers: "tuple[ModelProvider, ...]") -> None:
    del providers


@dataclass(frozen=True)
class AgentProfile:
    """One agent, as the jail needs to know it. Validated on creation (ValueError).

    - ``image``: pinned by digest; ``[agent] image`` may replace it, pinned too.
    - ``entrypoint`` and ``command``: what the container runs (``--entrypoint`` and the
      arguments after the image). ``workdir``: where it starts, inside /workspace; None leaves
      the image's.
    - ``workspace_dirs``: the folders of /workspace backtide creates for the agent; ``home``
      always (HOME points there).
    - ``env``: the profile's own variables, after HOME and before the jail's. ``proxy_url_env``
      and ``ca_file_env``: other names the agent reads the proxy's URL or the CA's path from;
      the profile names them, the values are always the jail's.
    - ``token_env``: the variable that gets AgentJailConfig.gateway_token (OpenClaw's Gateway),
      or None. ``fake_key_env``: (variable, provider) pairs that get that provider's FAKE key.
      Both reach the container through the docker CLI's environment, never the argv.
    - ``config_names`` and ``render_config``: the files backtide writes in /config, exactly
      those, and their text for a jail config. ``check_config`` refuses a rendered config that
      cannot be run safely (ProfileError) before anything is written.
    - ``ready_log_line``, ``ready_probe`` and ``ready_answer``: a line the agent logs when it is
      ready, an argv run inside the container that must exit 0, and what its output must be.
      Without them, ready means running. The probe runs where the agent can interfere: its
      output is bounded by AgentJail and never decides anything about security.
    - ``rewind_notice_lines``: what the rewind notice says about this agent (docs/19, section 7).
    - ``provider_params``: top-level fields its model client sends that the gate's list does not
      know (``param:<name>``, decision 5 of docs/34); allowed for this profile only.
    - ``check_providers``: refuses (ValueError) model providers this agent cannot use (OpenClaw:
      one it has no catalog of, without its model ids)."""

    name: str
    version: str
    image: str
    entrypoint: str
    command: tuple[str, ...]
    workdir: PurePosixPath | None = None
    workspace_dirs: tuple[str, ...] = (HOME_DIR, "work")
    env: tuple[tuple[str, str], ...] = ()
    proxy_url_env: tuple[str, ...] = ()
    ca_file_env: tuple[str, ...] = ()
    token_env: str | None = None
    fake_key_env: tuple[tuple[str, str], ...] = ()
    config_names: tuple[str, ...] = ()
    render_config: Callable[["AgentJailConfig"], Mapping[str, str]] = _no_files
    check_config: Callable[[Mapping[str, str]], None] = _no_check
    ready_log_line: str = ""
    ready_probe: tuple[str, ...] = ()
    ready_answer: Callable[[str], bool] = _any_answer
    rewind_notice_lines: tuple[str, ...] = ()
    provider_params: tuple[str, ...] = ()
    check_providers: "Callable[[tuple[ModelProvider, ...]], None]" = _any_providers

    def __post_init__(self) -> None:
        _match("profile name", self.name, _PROFILE_NAME_RE)
        _text("version", self.version, allow_empty=False)
        _match("image (pinned by digest)", self.image, PINNED_IMAGE_RE)
        _match("entrypoint", self.entrypoint, _PROGRAM_RE)
        _args("command", self.command)
        self._check_workdir()
        _names("workspace_dirs", self.workspace_dirs, _DIR_NAME_RE)
        if HOME_DIR not in self.workspace_dirs:
            raise ValueError(f"workspace_dirs must include {HOME_DIR!r}: HOME is /workspace/home")
        self._check_env()
        _names("config_names", self.config_names, _CONFIG_NAME_RE)
        for label, function in (
            ("render_config", self.render_config),
            ("check_config", self.check_config),
            ("ready_answer", self.ready_answer),
            ("check_providers", self.check_providers),
        ):
            if not callable(function):
                raise ValueError(f"{label} must be callable")
        _text("ready_log_line", self.ready_log_line)
        _args("ready_probe", self.ready_probe)
        if not isinstance(self.rewind_notice_lines, tuple):
            raise ValueError("rewind_notice_lines must be a tuple of texts")
        for line in self.rewind_notice_lines:
            _text("a rewind notice line", line, allow_empty=False)
            # Printed as it is in the terminal, Telegram and the web: no escape sequence, no
            # bidi override, no zero-width trick, and a sentence, not a wall of text.
            if not line.isprintable() or len(line) > MAX_NOTICE_LINE:
                raise ValueError(
                    f"a rewind notice line must be printable text of at most {MAX_NOTICE_LINE} "
                    "characters"
                )
        if not isinstance(self.provider_params, tuple):
            raise ValueError("provider_params must be a tuple")
        for entry in self.provider_params:
            check_profile_param(entry)
        if len(set(self.provider_params)) != len(self.provider_params):
            raise ValueError("provider_params has the same field twice")

    def _check_workdir(self) -> None:
        if self.workdir is None:
            return
        path = self.workdir
        if (
            not isinstance(path, PurePosixPath)
            or not path.is_absolute()
            or ".." in path.parts
            or not path.is_relative_to(CONTAINER_WORKSPACE)
            or any(char in str(path) for char in ":,\n\0")
        ):
            raise ValueError(f"workdir must be a plain path inside {CONTAINER_WORKSPACE}: {path!r}")

    def _check_env(self) -> None:
        if not isinstance(self.env, tuple) or not all(
            isinstance(pair, tuple) and len(pair) == 2 for pair in self.env
        ):
            raise ValueError("env must be a tuple of (name, value) pairs")
        if not isinstance(self.fake_key_env, tuple) or not all(
            isinstance(pair, tuple) and len(pair) == 2 for pair in self.fake_key_env
        ):
            raise ValueError("fake_key_env must be a tuple of (variable, provider) pairs")
        for label, names in (
            ("proxy_url_env", self.proxy_url_env),
            ("ca_file_env", self.ca_file_env),
        ):
            if not isinstance(names, tuple):
                raise ValueError(f"{label} must be a tuple of variable names")
        own = [name for name, _ in self.env]
        for name, value in self.env:
            if any(word in name.upper() for word in _SECRET_WORDS):
                raise ValueError(
                    f"env {name!r}: a profile's variables never carry a secret (the fake key "
                    "and the token have their own fields)"
                )
            _text(f"the value of {name}", value)
            if secret_shaped(name, value):
                raise ValueError(
                    f"env {name}: its value looks like a secret (never quoted here): a profile's "
                    "variables never carry one, and the fake key has its own field"
                )
        for _, provider in self.fake_key_env:
            _match("a fake key's provider", provider, _PROVIDER_NAME_RE)
        every = [
            *own,
            *self.proxy_url_env,
            *self.ca_file_env,
            *([] if self.token_env is None else [self.token_env]),
            *(name for name, _ in self.fake_key_env),
        ]
        for name in every:
            _match("variable name", name, _ENV_NAME_RE)
            if is_reserved_env(name):
                raise ValueError(f"{name} is set by the jail, never by a profile")
        # These reach `docker create` through the docker CLI's own environment on the host.
        for name in [*own, *(name for name, _ in self.fake_key_env)] + (
            [] if self.token_env is None else [self.token_env]
        ):
            if reaches_docker_cli(name):
                raise ValueError(
                    f"{name} is read by the docker CLI on the host, and the agent's variables "
                    "reach it through that CLI's environment: use another name"
                )
        for name, _ in self.fake_key_env:
            if not name.upper().endswith(_KEY_SUFFIXES):
                raise ValueError(
                    f"{name}: the variable that gets the fake model key must end in _KEY, "
                    "_API_KEY or _TOKEN"
                )
        if len(set(every)) != len(every):
            raise ValueError("the profile sets the same variable twice")


def _match(label: str, value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")


def _text(label: str, value: object, *, allow_empty: bool = True) -> None:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > MAX_TEXT
        or any(char in value for char in "\n\r\0")
    ):
        raise ValueError(f"{label} must be one line of text")


def _args(label: str, args: object) -> None:
    if not isinstance(args, tuple) or len(args) > MAX_ARGS:
        raise ValueError(f"{label} must be a tuple of at most {MAX_ARGS} arguments")
    for arg in args:
        _text(f"an argument of {label}", arg)


def _names(label: str, names: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(names, tuple):
        raise ValueError(f"{label} must be a tuple of names")
    for name in names:
        _match(f"name in {label}", name, pattern)
    if len(set(names)) != len(names):
        raise ValueError(f"{label} has the same name twice")
