"""The agents of an installation (T26-2a): the main one and the files of the others.

Design: docs/47-diseno-t26-web-agentes.md, sections 6.2, 6.3 and 6.8.

An installation of before T26-2 has one agent, ``principal``: ``backtide.toml`` describes it and
nothing of it moves. Each other agent is a file, ``agents/<slug>.toml`` next to ``backtide.toml``,
and a ``ServiceConfig`` of its own made from the machine's with what that file says. The file name
is the slug (backtide/jail/identity.py), so an agent has no way to name a folder outside its own.

What a file holds, and all it may hold (written by the service, T26-6a, or by hand with ``sudo``):

    number = 1                 # 1-99: its ids (61100 + n, 61200 + n). Never reused
    name = "Revisor"           # optional: what to call it in the web
    volume = "/var/lib/backtide-agents/revisor"
    volume_image = "..."       # with max_volume_bytes, as in backtide.toml
    max_volume_bytes = 0
    workspace_limit = 0        # required (T26-6a): an agent with no cap is an agent with no pause

    [agent]                    # as in backtide.toml, but its names, ids and folder: those are not
    profile = "claude-code"    # settings (ServiceConfig refuses them and every setting of the jail)
    memory = "1g"

    [proxy]                    # lower or higher limits than the machine's [proxy]
    memory = "256m"

    [budget]                   # its own caps, under the whole installation's (T26-2c): optional
    daily_usd = 1
    monthly_usd = 10

Everything else is the machine's, in ``backtide.toml`` (``[sensor]``, ``[gate]``, the rest of
``[budget]``, ``[web]``, what ``[proxy]`` lets out, its limits by default) and comes along. Reading
makes the agent's folder and its fake keys, as ``from_file`` makes the main one's, and starts
nothing. A file that cannot be used is a ConfigError, never skipped: an agent that was asked for
and does not run is not something to find out later. ``workspace_limit`` is required here, unlike
in ``backtide.toml`` (review of T26-2b): whether the volume is really mounted is checked before the
agent runs (``backtide.service.agent_disk``), and together they are why an agent never writes on
the machine's disk with no cap.

An agent that was deleted (T26-6c, ``backtide.service.trash``) has a mark in its folder, and with
the mark it is nobody here: its file, if a machine that died left it, is not read.

Together, agents share nothing that would let one reach another: no container or network name, no
uid or gid, no folder (a volume, the image behind one, a config folder) that holds another's, links
resolved, and no secret (a fake key, a Gateway token, a black box's key: a copied folder would
share them). And an agent's ids belong to no account of the machine.

With other agents, each one's jail is told what is theirs (T26-2b, ``neighbours``): their volumes,
their images and their config folders are protected paths like the black box, so a container that
mounts one is refused or killed. With no other agent nothing is told: ``main`` stays what
``from_file`` gave.
"""

import dataclasses
import grp
import os
import pwd
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backtide.jail import identity
from backtide.jail.config import Protected
from backtide.jail.identity import MAX_AGENTS as MAX_AGENTS
from backtide.service.config import (
    _DECIDED_PROXY_KEYS,
    AGENTS_FOLDER,
    MAX_CONFIG_BYTES,
    MAX_TOKEN_BYTES,
    RETIRED_MARK,
    SAVED_AGENT_FILE,
    STATE_TOKEN,
    ConfigError,
    Secret,
    ServiceConfig,
    _as_path,
    _decode,
    _overlap,
    _provider_names,
    _read_file,
    agent_profile_of,
    ensure_state_folder,
    read_provider_keys,
    read_token_to_strike,
    require_own_folder,
)

_FILE_SUFFIX = ".toml"
_KEYS = frozenset(
    {"number", "name", "volume", "volume_image", "max_volume_bytes", "workspace_limit", "agent",
     "proxy", "budget"}
)  # fmt: skip
_PROXY_LIMITS = frozenset({"memory", "cpus", "pids_limit"})
_OWN_CAPS = frozenset({"daily_usd", "monthly_usd"})
_IMAGE = "volume.img"  # the file behind an agent's volume, when it is in its folder (docs/47, 6.3)
_MAX_KEY_FILE = 1024


@dataclass(frozen=True)
class Installation:
    """The agents of this machine: the main one and the others, by number."""

    main: ServiceConfig
    others: tuple[ServiceConfig, ...] = ()

    @property
    def agents(self) -> tuple[ServiceConfig, ...]:
        return (self.main, *self.others)

    def agent(self, slug: str | None) -> ServiceConfig:
        """The agent ``slug`` of this installation (None: the main one). ConfigError if there is
        none: it is compared with what was read, so it never names a file."""
        if slug is None:
            return self.main
        for config in self.agents:
            if config.slug == slug:
                return config
        raise ConfigError(f"no agent {slug!r} here: {', '.join(c.slug for c in self.agents)}")


def load_installation(path: Path) -> Installation:
    """``backtide.toml`` at ``path`` and the files of ``agents/`` beside it. Without that folder,
    exactly ``ServiceConfig.from_file(path)``: nothing else is read or made. Raises ConfigError."""
    main = ServiceConfig.from_file(path)
    folder = Path(path).parent / AGENTS_FOLDER
    if not os.path.lexists(folder):
        return Installation(main)
    require_own_folder(folder, "the agents' files folder")
    try:
        names = sorted(os.listdir(folder))
    except OSError as error:
        raise ConfigError(f"cannot read {folder}: {os.strerror(error.errno or 0)}") from None
    slugs = [name.removesuffix(_FILE_SUFFIX) for name in names if name.endswith(_FILE_SUFFIX)]
    for slug in slugs:  # all of them first: a bad name makes no folder for the good ones
        _check_slug(slug)
    slugs = [slug for slug in slugs if not is_retired(main, slug)]
    if 1 + len(slugs) > MAX_AGENTS:
        raise ConfigError(f"at most {MAX_AGENTS} agents, the main one included")
    others = [_read_agent(main, folder / f"{slug}{_FILE_SUFFIX}", slug) for slug in slugs]
    others.sort(key=lambda config: config.number)
    agents = (main, *others)
    _check_apart(agents)
    for config in others:
        _check_ids_free(config)
    if not others:
        return Installation(main)  # an empty agents/: nothing changes
    first, *rest = [_told_of_neighbours(config, agents) for config in agents]
    return Installation(first, tuple(rest))


def load_agent(path: Path, slug: str | None = None) -> ServiceConfig:
    """One agent and the machine's file, whatever the other agents' files say (T26-2c): what
    stops or undoes must work with a neighbour's file broken. Not told of its neighbours, so this
    is for what never starts a container; to run an agent, ``load_installation``. Raises ConfigError
    if this agent's own file, or ``backtide.toml``, cannot be used."""
    main = ServiceConfig.from_file(path)
    if slug is None or slug == identity.MAIN_SLUG:
        return main
    _check_slug(slug)  # a slug, so that it can only name a file of this folder
    folder = Path(path).parent / AGENTS_FOLDER
    file = folder / f"{slug}{_FILE_SUFFIX}"
    if not os.path.lexists(file):
        raise ConfigError(f"no agent {slug!r} here: there is no {file}")
    if is_retired(main, slug):
        raise ConfigError(f"no agent {slug!r} here: it was deleted, whatever {file} says")
    require_own_folder(folder, "the agents' files folder")
    return _read_agent(main, file, slug)


def is_retired(main: ServiceConfig, slug: str) -> bool:
    """Whether the agent ``slug`` was deleted (T26-6c). The mark is the truth: with it there is no
    such agent, whatever ``agents/<slug>.toml`` says, and nothing of it runs. ``slug`` is a checked
    one."""
    return os.path.lexists(main.agents_dir / slug / RETIRED_MARK)


def load_retired(path: Path, slug: str) -> ServiceConfig:
    """A deleted agent as it was, from the copy of its file beside its black box (T26-6c): what
    finishes deleting it or brings it back. It is not an agent of the installation: nothing runs
    from this but what the order about it does. Raises ConfigError."""
    _check_slug(slug)
    main = ServiceConfig.from_file(path)
    return _read_agent(main, main.agents_dir / slug / SAVED_AGENT_FILE, slug)


def check_fits(installation: Installation, config: ServiceConfig) -> None:
    """Whether ``config`` could be one more agent of ``installation``: the same as reading them all
    with it there, before anything is touched. Raises ConfigError."""
    _check_apart((*installation.agents, config))
    _check_ids_free(config)


def _check_slug(slug: str) -> None:
    try:
        identity.check_slug(slug)
    except identity.SlugError as error:
        raise ConfigError(f"agents/: a file for no agent: {error}") from None


def check_alone(path: Path, config: ServiceConfig) -> None:
    """For what touches this agent's volume in this process, with no service to say it is whose
    (T26-2c): no other agent whose file can be read holds any of its folders. A file copied without
    changing its volume stops the service, and rewinding here would rewind the other's and write
    it in this one's box. ConfigError if so. A file that cannot be read stops nothing."""
    main = ServiceConfig.from_file(path)
    others = [] if config.is_main else [main]
    folder = Path(path).parent / AGENTS_FOLDER
    if os.path.lexists(folder):
        require_own_folder(folder, "the agents' files folder")
        for name in sorted(os.listdir(folder)):
            slug = name.removesuffix(_FILE_SUFFIX)
            if not name.endswith(_FILE_SUFFIX) or slug == config.slug:
                continue
            try:
                _check_slug(slug)
                if not is_retired(main, slug):
                    others.append(_read_agent(main, folder / name, slug))
            except ConfigError:
                continue  # `_say_if_a_file_is_broken` says it: that one is not for this to judge
    for other in others:
        _check_folders_apart(config, other)


def _read_agent(main: ServiceConfig, path: Path, slug: str) -> ServiceConfig:
    """The ServiceConfig of the agent of ``path``. Whatever is wrong with the file is a ConfigError,
    also a value of the wrong type that makes something below raise: what gets by with a broken
    file only knows that one. The message has the file's name and never what it holds."""
    try:
        return _agent_from_file(main, path, slug)
    except ConfigError:
        raise
    except Exception as error:
        raise ConfigError(
            f"{path}: it cannot be used: a setting has the wrong type ({type(error).__name__})"
        ) from None


def _agent_from_file(main: ServiceConfig, path: Path, slug: str) -> ServiceConfig:
    """The machine's config, with what the agent's file says."""
    data = _read_toml(path)
    unknown = sorted(set(data) - _KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown settings: {', '.join(map(repr, unknown))}")
    agent = _table(path, data, "agent")
    proxy = _table(path, data, "proxy")
    budget = _table(path, data, "budget")
    unknown = sorted(set(budget) - _OWN_CAPS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown [budget] settings: {', '.join(map(repr, unknown))}: an agent's file "
            "only sets its own caps (daily_usd, monthly_usd), and the rest is the machine's"
        )
    unknown = sorted(set(proxy) - _PROXY_LIMITS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown [proxy] settings: {', '.join(map(repr, unknown))}: an agent's file "
            "only sets its proxy's limits, and what it lets out is the machine's"
        )
    if "number" not in data:
        raise ConfigError(f"{path}: the setting 'number' is required")
    if "volume" not in data:
        raise ConfigError(f"{path}: the setting 'volume' is required")
    if "workspace_limit" not in data:
        raise ConfigError(
            f"{path}: the setting 'workspace_limit' is required: without a cap the agent is never "
            "paused for lack of space"
        )
    image = data.get("volume_image")
    image = None if image is None else _as_path("volume_image", image)
    home = main.agents_dir / slug
    state = Path(os.path.realpath(main.state_dir))  # a link may lead there: what counts is where
    if image is not None and (
        image.is_relative_to(main.state_dir) or Path(os.path.realpath(image)).is_relative_to(state)
    ):
        allowed = home / _IMAGE
        if os.path.realpath(image) != os.path.join(state, allowed.relative_to(main.state_dir)):
            raise ConfigError(
                f"{path}: volume_image {image} is in the state, and the only one allowed there is "
                f"{allowed}: the rest of it is black boxes and keys"
            )
    volume = _as_path("volume", data["volume"])
    if _overlap(state, Path(os.path.realpath(volume))):
        raise ConfigError(
            f"{path}: volume {volume} is in the state, or holds it: the agent writes its volume, "
            "and the state is black boxes and keys"
        )
    ensure_state_folder(main.agents_dir, "the agents' folder")
    ensure_state_folder(home, "the agent's folder")  # checked before anything is read from it
    token, struck = None, None
    if agent_profile_of(agent).token_env is None:
        struck = read_token_to_strike(home / STATE_TOKEN)
    else:
        token = _read_token(home / STATE_TOKEN)
    machine_proxy = {k: v for k, v in main.proxy.items() if k not in _DECIDED_PROXY_KEYS}
    names = _provider_names(machine_proxy)
    keys = read_provider_keys(main.keys_dir, names, fakes=home) if names else {}
    return dataclasses.replace(
        main,
        slug=slug,
        number=data["number"],
        display_name=_display_name(path, data.get("name")),
        volume=volume,
        volume_image=image,
        max_volume_bytes=data.get("max_volume_bytes"),
        workspace_limit=data.get("workspace_limit"),
        agent=agent,
        proxy={**machine_proxy, **proxy},
        budget={**main.budget, **budget},
        own_caps=tuple(sorted(budget)),
        gateway_token=token,
        struck_token=struck,
        provider_keys=keys,
    )


def _read_toml(path: Path) -> dict[str, Any]:
    text = _decode(_read_file(path, "agent file", MAX_CONFIG_BYTES, private=False))
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:  # a line and a column, never what the file holds
        raise ConfigError(f"{path} is not valid TOML: {error}") from error


def _table(path: Path, data: dict[str, Any], key: str) -> dict[str, Any]:
    table = data.get(key, {})
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: [{key}] must be a table")
    return dict(table)


def _read_token(path: Path) -> Secret:
    return Secret(
        _decode(_read_file(path, "gateway token file", MAX_TOKEN_BYTES, private=True)).strip()
    )


def _display_name(path: Path, name: object) -> str | None:
    """What to call the agent in the web: short, and nothing that moves a terminal or a page
    around (no control or format character, which covers the direction marks)."""
    if name is None:
        return None
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > identity.MAX_NAME
        or any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in name)
    ):
        raise ConfigError(
            f"{path}: the setting 'name' must be 1 to {identity.MAX_NAME} characters, none of them "
            "a control character"
        )
    return name


def _check_apart(agents: tuple[ServiceConfig, ...]) -> None:
    """No two agents share a Docker name, an id, or a folder that holds the other's."""
    names: dict[str, str] = {}
    ids: dict[int, str] = {}
    for config in agents:
        jail, proxy = config.jail_config(), config.proxy_jail_config()
        for name in sorted(
            {jail.name, proxy.name, jail.network, proxy.network, proxy.agent_network}
        ):
            _only_once(names, name, config.slug, "the Docker name")
        for number in sorted({jail.uid, jail.gid, proxy.uid, proxy.gid}):
            _only_once(ids, number, config.slug, "the id")
    for index, config in enumerate(agents):
        for other in agents[index + 1 :]:
            _check_folders_apart(config, other)
    _check_no_shared_secret(agents)


def _check_folders_apart(config: ServiceConfig, other: ServiceConfig) -> None:
    """A volume, its image or a config folder holds only one agent, links resolved."""
    for mine in _held(config):
        for theirs in _held(other):
            if _overlap(Path(os.path.realpath(mine)), Path(os.path.realpath(theirs))):
                raise ConfigError(
                    f"the agents {config.slug} and {other.slug} share a folder: {mine} and "
                    f"{theirs} (a volume, its image or a config folder holds only one agent)"
                )


def _check_no_shared_secret(agents: tuple[ServiceConfig, ...]) -> None:
    """Each agent's secrets are its own. They are made apart: this is for a folder copied by hand
    (``cp -a``), which would give two agents one chain and spending counted to the wrong one.
    The message never holds a secret."""
    seen: dict[bytes, str] = {}
    for config in agents:
        for secret in _secrets_of(config):
            if seen.setdefault(secret, config.slug) != config.slug:
                raise ConfigError(
                    f"the agents {seen[secret]} and {config.slug} share a secret (a fake key, a "
                    "Gateway token or a black box's key): each has its own. Was a folder copied?"
                )


def _secrets_of(config: ServiceConfig) -> set[bytes]:
    secrets = {key.fake.encode() for key in config.provider_keys.values()}
    if config.gateway_token is not None:
        secrets.add(config.gateway_token.reveal().encode())
    if os.path.lexists(config.blackbox_key):
        secrets.add(_read_file(config.blackbox_key, "black box key", _MAX_KEY_FILE, private=True))
    return secrets


def _check_ids_free(config: ServiceConfig) -> None:
    """An agent's ids are nobody's: running as an account's uid would hand it that account's
    files if it got out, and share the kernel's limits per uid (docs/47, section 6.8). The main
    agent's are checked when installing, as they always were."""
    for number in (identity.agent_id(config.number), identity.proxy_id(config.number)):
        if id_taken(number):
            raise ConfigError(
                f"the agent {config.slug} would run as id {number}, which is an account or a group "
                "of this machine: give it another number, or change that account's id"
            )


def id_taken(number: int) -> bool:
    try:
        pwd.getpwuid(number)
    except KeyError:
        pass
    else:
        return True
    try:
        grp.getgrgid(number)
    except KeyError:
        return False
    return True


def _told_of_neighbours(config: ServiceConfig, agents: tuple[ServiceConfig, ...]) -> ServiceConfig:
    """``config``, its jail told what of the others it must never see. Made again, so what it may
    mount is checked against them too (a ConfigError if it would show one)."""
    neighbours: list[Protected] = []
    for other in agents:
        if other.slug != config.slug:
            neighbours += protected_of(other)
    return dataclasses.replace(config, neighbours=tuple(neighbours))


def protected_of(other: ServiceConfig) -> list[Protected]:
    """What of the agent ``other`` every other agent's jail must never show."""
    found = [Protected(f"the volume of the agent {other.slug}", other.volume)]
    if other.volume_image is not None:
        found.append(Protected(f"the image of the agent {other.slug}", other.volume_image))
    found.append(Protected(f"the config of the agent {other.slug}", other.agent_config_dir))
    return found


def image_of(config: ServiceConfig) -> Path:
    """The file behind this agent's volume: what its file says, or the one in its folder."""
    return config.volume_image if config.volume_image is not None else config.agent_dir / _IMAGE


def _only_once[T](seen: dict[T, str], value: T, slug: str, what: str) -> None:
    if seen.setdefault(value, slug) != slug:
        raise ConfigError(f"the agents {seen[value]} and {slug} both use {what} {value}")


def _held(config: ServiceConfig) -> list[Path]:
    """What is this agent's alone, wherever the configuration put it."""
    held = [config.volume, config.agent_config_dir]
    if config.volume_image is not None:
        held.append(config.volume_image)
    return held
