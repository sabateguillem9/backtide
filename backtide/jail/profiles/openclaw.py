"""The OpenClaw profile (T17a-2): how OpenClaw runs in the jail, which configs can be rewound
safely (T04), and where OpenClaw reads the fake key of each model provider (T06-5).

Everything here is OpenClaw's own: its pinned image and how it starts, its variables, its
openclaw.json, how backtide knows its Gateway is ready, its lines of the rewind notice. The jail
around it (uid, mounts, network, proxy, CA, seccomp...) is backtide/jail/config.py's and the
same for every agent; ``OPENCLAW`` at the end is the AgentProfile that puts it together.

Rewinding the agent's volume also rewinds OpenClaw's SQLite state. Anything that authorizes
someone or something and lives there would come back after a rewind (a sender the user revoked,
an "allow always" they removed, a paired device), and the agent, which runs as the same user as
OpenClaw, could also create it itself. So every authorization must come from openclaw.json,
which is read-only. ``check_rewindable`` enforces that on the config backtide writes.

The rules, with their sources in OpenClaw 2026.9.8, are docs/20-openclaw-autorizacion-y-
rebobinado.md, section 8 (numbered the same here). Rule 12 is not about rewinding but about the
gate's notices: OpenClaw's Telegram command menu (T10-5). Where OpenClaw's default is the unsafe
choice (``dmPolicy`` is "pairing" when absent), the key must be written. The check never
repeats a value of the config in its messages: only paths, so no secret can reach a log.
"""

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from backtide.jail.model import MODEL_ID as MODEL_ID
from backtide.jail.model import ModelProvider
from backtide.jail.profile import (
    CONTAINER_CONFIG_DIR,
    CONTAINER_STATE,
    CONTAINER_WORK,
    AgentProfile,
    ProfileError,
)

if TYPE_CHECKING:
    from backtide.jail.config import AgentJailConfig

# OpenClaw 2026.9.8 (docs/12). Bump the digest and the version together, after testing in the VM.
OPENCLAW_VERSION = "2026.9.8"
IMAGE = (
    "ghcr.io/openclaw/openclaw"
    "@sha256:d0ded1dd76939b2bf4d67ef2d13247b8b160aa5666331d4a0b0e58811182cbb8"
)
GATEWAY_PORT = 18789
READY_LOG_LINE = "[gateway] ready"
HEALTH_URL = f"http://127.0.0.1:{GATEWAY_PORT}/healthz"
# -q first: curl must not read a .curlrc from HOME, which is the agent's /workspace/home (one
# with `url = file:///dev/zero` and `next` made this probe print 1 GB/s). The agent can still
# trace curl or answer on the Gateway's port itself, so AgentJail bounds the output as well.
HEALTH_PROBE = (
    "curl", "-q", "--fail", "--silent", "--max-time", "5", "--max-filesize", "4096", HEALTH_URL,
)  # fmt: skip

AGENT_SUBDIRS = ("home", "state", "work")
CONFIG_FILE = "openclaw.json"
TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN"  # noqa: S105 - the variable's name, not a secret

# The image's entrypoint runs `openclaw doctor --fix` first, which exits 1 when the config is
# read-only (OPENCLAW_CONFIG_READONLY=1) and fails on the read-only root without it (checked in
# the VM with 2026.9.8). Doctor only migrates or repairs state left by OTHER versions, and the
# image is pinned, so the jail starts the Gateway directly under the image's own tini.
ENTRYPOINT = "tini"
COMMAND = ("-s", "--", "node", "openclaw.mjs", "gateway")

# Turn off everything that would phone home or start background work (docs/12). HOME and
# DO_NOT_TRACK are the jail's, around these.
ENV = (
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
)
# OpenClaw has its own HTTP dispatcher, which reads the proxy from here (T06-1, P9).
PROXY_URL_ENV = ("OPENCLAW_PROXY_URL",)

# The only channel allowed (rule 1); the others hold ratchet credentials or are not verified.
CHANNELS = ("telegram",)
SAFE_DM_POLICIES = ("allowlist", "disabled")
SAFE_EXEC_MODES = ("full", "deny")
SAFE_GATEWAY_AUTH = ("token", "password")
# OpenClaw's lines of the rewind notice (docs/19, section 7; backtide/service/notice.py puts them
# between the generic part and the undo point). Plain Spanish, the same for every config:
# channels that check_rewindable refuses are said to be unavailable, not hidden.
REWIND_NOTICE_LINES = (
    "Telegram: los mensajes que Telegram ya le entregó al agente no le vuelven a llegar. Si "
    "algo de esa conversación importa, díselo de nuevo.",
    "WhatsApp y Signal no se pueden usar en esta versión: sus sesiones no aguantan volver atrás "
    "y habría que vincularlas de nuevo.",
    "El correo (IMAP) tampoco se puede usar todavía: tras rebobinar, el agente volvería a leer "
    "el correo llegado desde esa hora.",
)
_NUMERIC_ID = re.compile(r"(?:(?:telegram|tg):)?[0-9]+")
_WILDCARD = re.compile(r"(?:(?:telegram|tg):)?\s*\*\s*")


# The fake key (T06-5, docs/21 section 6). OpenClaw reads it as a literal
# ``models.providers.<name>.apiKey`` (T06-1, P9); with ``auth: "api-key"`` that literal wins over
# auth profiles and environment variables. It sends it as ``x-api-key`` (anthropic-messages) or
# ``Authorization: Bearer`` (openai-completions), and the proxy swaps it for the real one. OpenClaw
# also copies it into its state (``agents/<id>/agent/models.json``): it is the fake one, so the
# agent finding it there is expected. Only "anthropic" and "openai" are providers OpenClaw knows by
# itself (their model catalogs); any other name needs its model list (OpenClaw's schema refuses a
# custom provider without one).
BUILT_IN_PROVIDERS = ("anthropic", "openai")
_API = {"anthropic": "anthropic-messages", "openai": "openai-completions"}
# anthropic-messages adds /v1/messages to its base; the OpenAI client adds only /chat/completions.
_BASE_PATH = {"anthropic": "", "openai": "/v1"}


def check_providers(providers: tuple[ModelProvider, ...]) -> None:
    """OpenClaw only knows the models of its built-in providers: any other name needs its model
    ids (OpenClaw's schema refuses a custom provider without them). ValueError otherwise."""
    for provider in providers:
        if provider.name not in BUILT_IN_PROVIDERS and not provider.models:
            raise ValueError(
                f"provider {provider.name}: OpenClaw needs its model ids (it only knows the models "
                f"of {', '.join(BUILT_IN_PROVIDERS)} by itself)"
            )


def model_settings(providers: Iterable[ModelProvider]) -> dict[str, Any]:
    """What openclaw.json says of the providers: ``models`` (merged with OpenClaw's catalog) and
    the agent's default model. Empty without providers."""
    items = tuple(providers)
    if not items:
        return {}
    entries: dict[str, Any] = {}
    for provider in items:
        entry: dict[str, Any] = {
            "baseUrl": f"https://{provider.host}{_BASE_PATH[provider.kind]}",
            "api": _API[provider.kind],
            "auth": "api-key",
            "apiKey": provider.fake_key,
        }
        if provider.models:
            entry["models"] = [{"id": model, "name": model} for model in provider.models]
        entries[provider.name] = entry
    settings: dict[str, Any] = {"models": {"mode": "merge", "providers": entries}}
    default = next((p for p in items if p.models), None)
    if default is not None:
        settings["primary"] = f"{default.name}/{default.models[0]}"
    return settings


@dataclass(frozen=True)
class RewindProblem:
    """One thing in the config that a rewind could undo: where (a dotted path) and why."""

    path: str
    why: str


class UnrewindableConfig(ProfileError):
    """The config has settings whose authorization a rewind would revive or let the agent forge.

    ``str(error)`` is the English log text with every problem; ``notice`` is the one Spanish
    line for the user. Neither contains values from the config, only paths."""

    def __init__(self, problems: list[RewindProblem]) -> None:
        self.problems = tuple(problems)
        lines = [f"  {problem.path}: {problem.why}" for problem in self.problems]
        super().__init__(
            "the OpenClaw config cannot be rewound safely "
            "(docs/20-openclaw-autorizacion-y-rebobinado.md, section 8):\n" + "\n".join(lines)
        )

    @property
    def notice(self) -> str:
        count = len(self.problems)
        what = "1 problema" if count == 1 else f"{count} problemas"
        where = ", ".join(problem.path for problem in self.problems)
        return (
            "La configuración de OpenClaw no se puede rebobinar con seguridad "
            f"({what}: {where}). El agente no arranca hasta corregirla; el detalle está en el log."
        )

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(problem.path for problem in self.problems)


def check_rewindable(config: dict[str, Any]) -> None:
    """Raise UnrewindableConfig, listing every problem, unless the config is safe to rewind."""
    problems = problems_in(config)
    if problems:
        raise UnrewindableConfig(problems)


def problems_in(config: dict[str, Any]) -> list[RewindProblem]:
    """Every rule broken by ``config``, in a stable order (empty when it is safe)."""
    if not isinstance(config, dict):
        return [RewindProblem("<config>", "the config must be a JSON object")]
    found = _Findings()
    _channels(config, found)  # rules 1-4 and 12
    _exec(config, found)  # rule 5
    _oauth(config, found)  # rule 6
    for path, value in _walk(config, ""):  # rule 7
        if isinstance(value, dict) and "source" in value and "provider" in value:
            if value["source"] != "env":
                found.add(
                    f"{path}.source" if path else "source",
                    'a secret reference must use source "env": file, exec and store sources '
                    "live outside the config and a rewind brings deleted secrets back",
                )
    _gateway(config, found)  # rule 8
    _automation(config, found)  # rule 9
    _plugins(config, found)  # rules 8 (device-pair), 10, 11
    return found.problems


class _Findings:
    def __init__(self) -> None:
        self.problems: list[RewindProblem] = []

    def add(self, path: str, why: str) -> None:
        self.problems.append(RewindProblem(path, why))


# Navigation helpers. The config is data from a file: any value can have the wrong type.


def _seg(key: object) -> str:
    """A key as a path segment: printable ASCII only, so it cannot forge a log line."""
    text = str(key)
    return "".join(c if c.isascii() and c.isprintable() else "?" for c in text)


def _dict(parent: dict[str, Any], key: str, path: str, found: _Findings) -> dict[str, Any]:
    """parent[key] when it is an object, {} when absent; a wrong type is a problem."""
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        found.add(_join(path, key), "must be an object")
        return {}
    return value


def _children(
    parent: dict[str, Any], key: str, path: str, found: _Findings
) -> Iterator[tuple[str, dict[str, Any]]]:
    """The object values of parent[key] (a map of name -> object), with their paths."""
    for name, value in _dict(parent, key, path, found).items():
        child_path = f"{_join(path, key)}.{_seg(name)}"
        if isinstance(value, dict):
            yield child_path, value
        elif value is not None:
            found.add(child_path, "must be an object")


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _walk(value: object, path: str) -> Iterator[tuple[str, object]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, _join(path, _seg(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


# Rules 1-4: channels


def _channels(config: dict[str, Any], found: _Findings) -> None:
    channels = _dict(config, "channels", "", found)
    for name in channels:
        if name not in CHANNELS:
            found.add(
                f"channels.{_seg(name)}",
                "only the telegram channel is supported: other channels keep credentials or "
                "sessions that a rewind breaks (whatsapp, signal, matrix) or are not verified",
            )
    telegram = channels.get("telegram")
    if telegram is None:
        return
    if not isinstance(telegram, dict):
        found.add("channels.telegram", "must be an object")
        return
    path = "channels.telegram"
    _telegram_scope(telegram, path, None, found)
    for account_path, account in _children(telegram, "accounts", path, found):
        _telegram_scope(account, account_path, telegram, found)


def _telegram_scope(
    scope: dict[str, Any], path: str, root: dict[str, Any] | None, found: _Findings
) -> None:
    """Check the root of channels.telegram or one of its accounts (rules 2, 3, 4 and 12)."""
    if root is None:  # channels.telegram itself
        policy = _dm_policy(scope, path, found, required=True)
        allow = scope.get("allowFrom")
    else:
        own = _dm_policy(scope, path, found, required=False)
        policy = own if scope.get("dmPolicy") is not None else _inherited_policy(root)
        allow = scope["allowFrom"] if "allowFrom" in scope else root.get("allowFrom")
    if "allowFrom" in scope:
        _ids(scope["allowFrom"], f"{path}.allowFrom", found, non_empty=policy == "allowlist")
    elif policy == "allowlist" and not _has_ids(allow):
        found.add(path if root else f"{path}.allowFrom", _EMPTY_ALLOW)
    for direct_path, direct in _children(scope, "direct", path, found):
        _direct_chat(direct, direct_path, policy, allow, found)
    _groups(scope, path, found)
    _command_menu(scope, path, root is None, found)


_EMPTY_ALLOW = (
    'dmPolicy "allowlist" with an empty allowFrom: nobody could talk to the agent; '
    'use dmPolicy "disabled" when there is nobody to allow'
)


def _inherited_policy(root: dict[str, Any]) -> str | None:
    value = root.get("dmPolicy")
    return value if isinstance(value, str) and value in SAFE_DM_POLICIES else None


def _dm_policy(scope: dict[str, Any], path: str, found: _Findings, *, required: bool) -> str | None:
    """The safe dmPolicy of this scope, or None (after reporting why it is not)."""
    where = f"{path}.dmPolicy"
    value = scope.get("dmPolicy")
    if value is None:
        if required:
            found.add(
                where,
                'must be written: OpenClaw defaults to "pairing" (approvals kept in the SQLite)',
            )
        return None
    if isinstance(value, str) and value in SAFE_DM_POLICIES:
        return value
    found.add(
        where,
        'must be "allowlist" or "disabled": "pairing" and "open" keep who may talk to '
        "the agent in the SQLite, where a rewind revives revoked senders and the agent can edit it",
    )
    return None


def _direct_chat(
    direct: dict[str, Any],
    path: str,
    parent_policy: str | None,
    parent_allow: object,
    found: _Findings,
) -> None:
    own = _dm_policy(direct, path, found, required=False)
    policy = own if direct.get("dmPolicy") is not None else parent_policy
    if "allowFrom" in direct:
        _ids(direct["allowFrom"], f"{path}.allowFrom", found, non_empty=policy == "allowlist")
    elif policy == "allowlist" and not _has_ids(parent_allow):
        found.add(path, _EMPTY_ALLOW)
    _topics(direct, path, found)


def _has_ids(value: object) -> bool:
    return isinstance(value, list) and len(value) > 0


def _ids(value: object, path: str, found: _Findings, *, non_empty: bool = False) -> None:
    """A list of numeric Telegram user ids: no wildcard, no @usernames, no groups of senders."""
    if not isinstance(value, list):
        found.add(path, "must be a list of numeric Telegram user ids")
        return
    if non_empty and not value:
        found.add(path, _EMPTY_ALLOW)
    for index, entry in enumerate(value):
        where = f"{path}[{index}]"
        if isinstance(entry, str) and _WILDCARD.fullmatch(entry):
            found.add(where, "a wildcard allows everybody")
        elif isinstance(entry, bool) or not _is_numeric_id(entry):
            found.add(where, "must be a numeric Telegram user id (no @username or named group)")


def _is_numeric_id(entry: object) -> bool:
    if isinstance(entry, int):
        return entry >= 0
    return isinstance(entry, str) and _NUMERIC_ID.fullmatch(entry) is not None


def _groups(scope: dict[str, Any], path: str, found: _Findings) -> None:
    _group_policy(scope, path, found)
    if "groupAllowFrom" in scope:
        _ids(scope["groupAllowFrom"], f"{path}.groupAllowFrom", found)
    for group_path, group in _children(scope, "groups", path, found):
        _group_policy(group, group_path, found)
        if "allowFrom" in group:
            _ids(group["allowFrom"], f"{group_path}.allowFrom", found)
        _topics(group, group_path, found)


def _group_policy(scope: dict[str, Any], path: str, found: _Findings) -> None:
    if scope.get("groupPolicy") == "open":
        found.add(
            f"{path}.groupPolicy", 'must not be "open": any group member could talk to the agent'
        )


def _topics(scope: dict[str, Any], path: str, found: _Findings) -> None:
    for topic_path, topic in _children(scope, "topics", path, found):
        if "allowFrom" in topic:
            _ids(topic["allowFrom"], f"{topic_path}.allowFrom", found)


# Rule 12: the Telegram command menu
#
# At every start OpenClaw publishes its command menu with setMyCommands (OpenClaw 2026.9.8,
# extensions/telegram/src/bot-native-command-menu.ts). The gate holds that call as a bot
# administration action at risk 3 (docs/32, section 18, default decision 12): one notice per
# start, retried every ~12 s. With ``commands.native: false`` and no ``customCommands`` the list is
# empty and OpenClaw only clears the menu (deleteMyCommands, which passes). The setting is read as
# account.commands.native, else the global ``commands.native``, else on (Telegram's auto default).
# An account is its own config spread over the root one, SHALLOWLY (account-config.ts,
# mergeAccountConfig): an account without ``commands`` inherits the root's, but one that has a
# ``commands`` object, even an empty one, replaces it and falls back to the default (on).


def _command_menu(scope: dict[str, Any], path: str, is_root: bool, found: _Findings) -> None:
    if scope.get("customCommands"):
        found.add(
            f"{path}.customCommands",
            "must be empty: custom commands are published with setMyCommands even when native "
            "commands are off, and the gate holds that call (risk 3, one notice per start)",
        )
    if not is_root and "commands" not in scope:
        return  # inherits the root's, which is checked on its own
    where = f"{path}.commands"
    commands = scope.get("commands")
    if commands is not None and not isinstance(commands, dict):
        found.add(where, "must be an object")
        return
    if (commands or {}).get("native") is not False:
        found.add(
            f"{where}.native",
            "must be written as false: OpenClaw publishes its command menu with setMyCommands at "
            "every start, which the gate holds as a bot administration action (risk 3, one notice "
            "per start, retried every few seconds)"
            + ("" if is_root else "; an account with its own commands object does not inherit it"),
        )


# Rule 5: exec approvals


def _exec(config: dict[str, Any], found: _Findings) -> None:
    tools = _dict(config, "tools", "", found)
    _exec_block(_dict(tools, "exec", "tools", found), "tools.exec", found)
    agents = _dict(config, "agents", "", found)
    defaults = _dict(agents, "defaults", "agents", found)
    _exec_block(
        _dict(
            _dict(defaults, "tools", "agents.defaults", found),
            "exec",
            "agents.defaults.tools",
            found,
        ),
        "agents.defaults.tools.exec",
        found,
    )
    for entry_path, entry in _children(agents, "entries", "agents", found):
        block = _dict(
            _dict(entry, "tools", entry_path, found), "exec", f"{entry_path}.tools", found
        )
        _exec_block(block, f"{entry_path}.tools.exec", found)


def _exec_block(block: dict[str, Any], path: str, found: _Findings) -> None:
    if "mode" in block and block["mode"] not in SAFE_EXEC_MODES:
        found.add(
            f"{path}.mode",
            'must be "full" or "deny": the allowlist, ask and auto modes use "allow always" '
            "entries stored in the SQLite, which a rewind brings back",
        )
    if block.get("security") == "allowlist" and block.get("ask") != "always":
        found.add(
            f"{path}.security",
            'the old security "allowlist" needs ask "always": otherwise "allow always" '
            "entries stored in the SQLite are used, and a rewind brings them back",
        )


# Rule 6: OAuth


def _oauth(config: dict[str, Any], found: _Findings) -> None:
    for profile_path, profile in _children(
        _dict(config, "auth", "", found), "profiles", "auth", found
    ):
        if profile.get("mode") == "oauth":
            found.add(f"{profile_path}.mode", _OAUTH)
    for provider_path, provider in _children(
        _dict(config, "models", "", found), "providers", "models", found
    ):
        if provider.get("auth") == "oauth":
            found.add(f"{provider_path}.auth", _OAUTH)
    for server_path, server in _children(_dict(config, "mcp", "", found), "servers", "mcp", found):
        if server.get("auth") == "oauth":
            found.add(f"{server_path}.auth", _OAUTH)


_OAUTH = (
    "OAuth refresh tokens rotate on every use and live in the SQLite: a rewind brings back a "
    "spent one and the login breaks. Use an API key or a token"
)


# Rule 8: gateway


def _gateway(config: dict[str, Any], found: _Findings) -> None:
    gateway = _dict(config, "gateway", "", found)
    if gateway.get("bind") != "loopback":
        found.add(
            "gateway.bind",
            'must be "loopback": a revived device token needs network reach to be used',
        )
    auth = _dict(gateway, "auth", "gateway", found)
    if auth.get("mode") not in SAFE_GATEWAY_AUTH:
        found.add("gateway.auth.mode", 'must be "token" or "password", never none or trusted-proxy')
    pairing = _dict(_dict(gateway, "nodes", "gateway", found), "pairing", "gateway.nodes", found)
    if pairing.get("sshVerify") is not False:
        found.add(
            "gateway.nodes.pairing.sshVerify",
            "must be false: it is on by default and makes the gateway try SSH to private peers",
        )
    if pairing.get("autoApproveCidrs"):
        found.add(
            "gateway.nodes.pairing.autoApproveCidrs",
            "must not be set: it approves device pairing by network address",
        )


# Rule 9: automation


def _automation(config: dict[str, Any], found: _Findings) -> None:
    if _dict(config, "cron", "", found).get("enabled") is not False:
        found.add(
            "cron.enabled",
            "must be false: cron jobs and standing grants live in the SQLite and come back",
        )
    deny = _dict(config, "tools", "", found).get("deny")
    if not isinstance(deny, list) or "group:automation" not in deny:
        found.add(
            "tools.deny",
            'must include "group:automation": cron jobs the agent created would come back',
        )


# Rules 8 (device-pair), 10 and 11: plugins


def _plugins(config: dict[str, Any], found: _Findings) -> None:
    plugins = _dict(config, "plugins", "", found)
    entries = _dict(plugins, "entries", "plugins", found)
    device_pair = entries.get("device-pair")
    if not isinstance(device_pair, dict) or device_pair.get("enabled") is not False:
        found.add(
            "plugins.entries.device-pair.enabled",
            "must be false: it is on by default and its pairing codes revive after a rewind",
        )
    imap = entries.get("imap")
    if imap is not None and not (isinstance(imap, dict) and imap.get("enabled") is False):
        found.add(
            "plugins.entries.imap",
            "IMAP is not supported yet: a rewind re-delivers the mail that arrived since the "
            "snapshot (the cursor lives in the SQLite), including the mail that caused the problem",
        )
    if _dict(plugins, "load", "plugins", found).get("paths"):
        found.add(
            "plugins.load.paths", "must be empty: code loaded from other paths is not verified"
        )
    allow = plugins.get("allow")
    if allow is not None:
        if not isinstance(allow, list):
            found.add("plugins.allow", "must be a list")
            return
        for index, name in enumerate(allow):
            if name not in CHANNELS:
                found.add(
                    f"plugins.allow[{index}]",
                    "only verified channel plugins may be allowed (telegram)",
                )


# openclaw.json and the profile


def openclaw_config(config: "AgentJailConfig") -> dict[str, Any]:
    """OpenClaw's openclaw.json: the hardened baseline of docs/12, with no secrets in it, and
    the model providers with their FAKE keys (T06-5: model_settings).

    Validated against the pinned image with ``openclaw config validate`` (a VM test), and it
    passes ``check_rewindable`` (the profile's check_config, which AgentJail.write_config runs)."""
    claw = _baseline()
    models = model_settings(config.model_providers)
    if models:
        claw["models"].update(models["models"])
        if "primary" in models:
            claw["agents"]["defaults"]["model"] = {"primary": models["primary"]}
    return claw


def _baseline() -> dict[str, Any]:
    return {
        "gateway": {
            "mode": "local",
            "bind": "loopback",
            "port": GATEWAY_PORT,
            "auth": {"mode": "token"},  # the token comes from OPENCLAW_GATEWAY_TOKEN
            # On by default: the gateway would try SSH towards private peers (docs/20, rule 8).
            "nodes": {"pairing": {"sshVerify": False}},
        },
        # Active by default: its /pair codes would come back after a rewind (docs/20, rule 8).
        "plugins": {"entries": {"device-pair": {"enabled": False}}},
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


def render_config(config: "AgentJailConfig") -> dict[str, str]:
    """The one file of /config: openclaw.json, as AgentJail writes it."""
    return {CONFIG_FILE: json.dumps(openclaw_config(config), indent=2) + "\n"}


def check_config(files: Mapping[str, str]) -> None:
    """``check_rewindable`` on the openclaw.json about to be written (UnrewindableConfig)."""
    check_rewindable(json.loads(files[CONFIG_FILE]))


def gateway_answer(output: str) -> bool:
    """Whether /healthz said ``{"ok": true}``."""
    try:
        return json.loads(output).get("ok") is True
    except (ValueError, AttributeError):
        return False


OPENCLAW = AgentProfile(
    name="openclaw",
    version=OPENCLAW_VERSION,
    image=IMAGE,
    entrypoint=ENTRYPOINT,
    command=COMMAND,
    workspace_dirs=AGENT_SUBDIRS,
    env=ENV,
    proxy_url_env=PROXY_URL_ENV,
    token_env=TOKEN_ENV,
    config_names=(CONFIG_FILE,),
    render_config=render_config,
    check_config=check_config,
    ready_log_line=READY_LOG_LINE,
    ready_probe=HEALTH_PROBE,
    ready_answer=gateway_answer,
    rewind_notice_lines=REWIND_NOTICE_LINES,
    check_providers=check_providers,
    # The fake keys go in openclaw.json (model_settings), never in a variable; and OpenClaw sends
    # no field the gate's lists lack (probar's param:fallbacks is the owner's allow_provider_tools).
    provider_params=(),
)
