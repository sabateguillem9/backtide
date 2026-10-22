"""The ``custom`` profile: any agent image, described in ``[agent]`` of backtide.toml (T17a-3).

Design: docs/34-diseno-t17-cualquier-agente.md, section 7 (approved decision 9). A named profile
(OpenClaw's) lives in code with its tests; this one is put together from the owner's TOML and
goes through exactly the same checks of AgentProfile, plus those of its own shape here:

- the image, always by digest (``[agent] image``, required);
- ``entrypoint`` (a program and its first arguments: Docker's ``--entrypoint`` takes only the
  program, the rest goes first in the command) and ``command``;
- ``workdir``: where it starts, inside /workspace (``work``, ``home`` or below them);
- ``env``: its own variables, never a reserved name (the jail's, ``*_PROXY``, the CA's, HOME,
  PATH, and the families that load code: ``LD_*``, ``NODE_OPTIONS``, ``PYTHON*``,
  ``GIT_CONFIG_*``, ``npm_config_*``...), a name the docker CLI reads on the host
  (``DOCKER_*``, ``GO*``, ``OTEL_*``...: the values travel in that CLI's environment), a
  secret's name or a value shaped like a secret;
- ``[agent.model]``: which provider of ``[[proxy.providers]]`` it uses, the variable that gets
  its FAKE key (``key_env``: the only variable the fake key reaches; its name ends in ``_KEY``,
  ``_API_KEY`` or ``_TOKEN``) and the plain request fields of the provider its model client
  sends (``allow_params``, decision 5): never one that switches on a search, a retrieval or a
  tool at the provider (``search_parameters``, ``extra_body``...), which only ``[proxy]
  allow_provider_tools`` can allow;
- ``[agent.ready]``: an optional log line and probe (the timeout is AgentJailConfig's
  ``ready_timeout``, which ServiceConfig fills in: 600 s at most);
- ``[agent.rewind]``: lines of the rewind notice (printable, 300 characters at most), after one
  that says backtide does not know this agent.

It writes nothing in /config (the folder is still mounted, empty), has no Gateway token, and
nothing of the jail (uid, mounts, network, ports, capabilities, seccomp...) is among its keys:
ServiceConfig refuses those by name before this module sees the table.
"""

from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from backtide.jail.profile import CONTAINER_WORKSPACE, CUSTOM_NAME, HOME_DIR, AgentProfile

CUSTOM = CUSTOM_NAME
WORKSPACE_DIRS = (HOME_DIR, "work")
# The keys of [agent] that describe a custom agent (the others are the container's options).
KEYS = frozenset({"entrypoint", "command", "workdir", "env", "model", "ready", "rewind"})
MODEL_KEYS = frozenset({"provider", "key_env", "allow_params"})
READY_KEYS = frozenset({"log_line", "probe", "timeout"})
REWIND_KEYS = frozenset({"notice"})
MAX_ENV = 64
MAX_NOTICE_LINES = 8
MAX_PARAMS = 16
# First line of its part of the rewind notice (docs/34, section 7): backtide cannot know what an
# agent it does not know keeps in its folder.
UNKNOWN_AGENT_NOTICE = (
    "backtide no conoce este agente: rebobina toda su carpeta, pero no sabe si guarda permisos "
    "o sesiones que no aguantan volver atrás."
)


def custom_profile(image: object, table: Mapping[str, Any]) -> AgentProfile:
    """The AgentProfile of a custom agent: ``image`` is ``[agent] image`` and ``table`` the
    custom keys of ``[agent]`` (``KEYS``). Raises ValueError, never quoting a variable's value
    (the checks of AgentProfile say only names)."""
    if image is None or image == "":
        raise ValueError(
            'profile "custom" needs [agent] image, pinned by digest (name@sha256:<64 hex>)'
        )
    unknown = sorted(set(table) - KEYS)
    if unknown:
        raise ValueError(f"unknown settings of a custom agent: {', '.join(map(repr, unknown))}")
    entrypoint = _strings("entrypoint", table.get("entrypoint"), required=True)
    if not entrypoint:
        raise ValueError('entrypoint must name a program: a list such as ["tini", "--"]')
    command = _strings("command", table.get("command", []))
    model = _table("model", table.get("model", {}), MODEL_KEYS)
    ready = _table("ready", table.get("ready", {}), READY_KEYS)
    rewind = _table("rewind", table.get("rewind", {}), REWIND_KEYS)
    notice = _strings("[agent.rewind] notice", rewind.get("notice", []))
    if len(notice) > MAX_NOTICE_LINES:
        raise ValueError(f"[agent.rewind] notice has at most {MAX_NOTICE_LINES} lines")
    return AgentProfile(
        name=CUSTOM,
        version=CUSTOM,
        image=image,  # type: ignore[arg-type] - AgentProfile checks it is a pinned name
        entrypoint=entrypoint[0],
        command=(*entrypoint[1:], *command),
        workdir=_workdir(table.get("workdir")),
        workspace_dirs=WORKSPACE_DIRS,
        env=_env(table.get("env", {})),
        fake_key_env=_fake_key_env(model),
        ready_log_line=_line("[agent.ready] log_line", ready.get("log_line", "")),
        ready_probe=_strings("[agent.ready] probe", ready.get("probe", [])),
        rewind_notice_lines=(UNKNOWN_AGENT_NOTICE, *notice),
        provider_params=_params(model.get("allow_params", [])),
    )


def _table(label: str, value: object, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"[agent.{label}] must be a table")
    unknown = sorted(set(value) - keys)
    if unknown:
        raise ValueError(f"unknown [agent.{label}] settings: {', '.join(map(repr, unknown))}")
    return value


def _strings(label: str, value: object, *, required: bool = False) -> tuple[str, ...]:
    if value is None and required:
        raise ValueError(f'profile "custom" needs {label}: a list such as ["tini", "--"]')
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a list of texts")
    return tuple(value)


def _line(label: str, value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a text")
    return value


def _workdir(value: object) -> PurePosixPath | None:
    """``work``, ``home`` or a folder below them, relative to /workspace; None: the image's."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError('workdir must be a folder of /workspace, such as "work"')
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.parts[0] not in WORKSPACE_DIRS:
        raise ValueError(
            f"workdir must be {' or '.join(WORKSPACE_DIRS)}, or a folder below them, relative "
            "to /workspace"
        )
    return CONTAINER_WORKSPACE / path


def _env(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise ValueError('[agent] env must be a table of NAME = "value"')
    if len(value) > MAX_ENV:
        raise ValueError(f"[agent] env has at most {MAX_ENV} variables")
    pairs = []
    for name, text in value.items():
        if not isinstance(text, str):
            raise ValueError(f"[agent] env {name!r}: the value must be a text")
        pairs.append((str(name), text))
    return tuple(pairs)


def _fake_key_env(model: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Where the FAKE key of ``provider`` goes: the variable ``key_env``, and nowhere else."""
    if not model:
        return ()
    provider, key_env = model.get("provider"), model.get("key_env")
    if not isinstance(provider, str) or not isinstance(key_env, str):
        raise ValueError(
            "[agent.model] needs provider (a name of [[proxy.providers]]) and key_env (the "
            "variable that gets its fake key)"
        )
    return ((key_env, provider),)


def _params(value: object) -> tuple[str, ...]:
    """``allow_params = ["diagnostics"]``: the request fields, by name, as ``param:<name>``."""
    names = _strings("[agent.model] allow_params", value)
    if len(names) > MAX_PARAMS:
        raise ValueError(f"[agent.model] allow_params has at most {MAX_PARAMS} names")
    return tuple(f"param:{name}" for name in names)
