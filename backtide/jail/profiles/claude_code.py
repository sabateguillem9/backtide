"""The Claude Code profile (T17a-4): Claude Code in the jail, in the ``shell`` mode.

Design: docs/34-diseno-t17-cualquier-agente.md, sections 4 ("Resultados de T17a-1"), 7 and 8,
and decisions 2 to 5 and 10. Everything here was measured in the VM with the pinned image
(tests/integration/test_agent_profile_assumptions.py) and is Claude Code's own: the jail around
it (uid, mounts, network, proxy, CA, seccomp...) is backtide/jail/config.py's, the same as for
any agent.

- The image: Docker's template for Claude Code, by digest (decision 10), with Claude Code
  2.1.306 at ``/home/agent/.local/bin/claude``, readable by any uid and in the image's PATH.
- The ``shell`` mode: the container waits under the image's tini (``tini -- sleep infinity``);
  the owner runs Claude Code inside it with `backtide entrar` (interactive) and `backtide tarea`
  (``claude -p``), always with ``--settings /config/claude.json`` and with its own permission
  prompts off: inside the jail they protect nothing the jail and the gate do not (docs/34,
  section 5). Its working folder is /workspace/work; everything it keeps lives in HOME
  (/workspace/home), inside what is rewound.
- The fake key: in ``ANTHROPIC_API_KEY`` (P3: it goes out as ``x-api-key`` and nothing else).
  Only an API key in v1 (decision 4): a subscription's OAuth is blocked by the proxy.
- ``param:diagnostics``: Claude Code sends that top-level field in every model call (P5); the
  gate refuses unknown fields, so this profile allows it (decision 5).
- Its variables: no non-essential traffic (P4: two reads at start, which the gate refuses
  without harm), no marketplace autoinstall, and npm's three harmless settings that a named
  profile may set (REVIEWED_RESERVED_ENV: no audit POST after an install, no funding message,
  no update check).
- /config/claude.json: the settings backtide gives it (decision 7): no WebFetch preflight to
  api.anthropic.com (the gate refuses it and WebFetch fails), no bypass-mode warning (the
  interactive session would stop on it), and WebSearch denied (a provider-side tool the gate
  refuses). ``check_settings`` refuses anything else in that file before it is written.
- `backtide entrar` writes the first-run answers into ~/.claude.json first (``SEED``): UI state,
  not authorization. If the agent changes it, or a rewind brings an old one back, Claude Code
  only asks again.
"""

import json
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from backtide.jail.model import ModelProvider
from backtide.jail.profile import (
    CONTAINER_CONFIG_DIR,
    CONTAINER_WORK,
    HOME_DIR,
    SHELL_MODE,
    AgentProfile,
    ProfileError,
    ShellCommands,
)

if TYPE_CHECKING:
    from backtide.jail.config import AgentJailConfig

NAME = "claude-code"
# docker/sandbox-templates:claude-code, the multi-arch index of 2026-10-21 (Ubuntu 26.04), with
# Claude Code 2.1.306. Bump the digest, the version and docs/34 together, after running
# tests/integration/test_agent_profile_assumptions.py and test_claude_code.py in the VM.
CLAUDE_CODE_VERSION = "2.1.306"
IMAGE = (
    "docker/sandbox-templates"
    "@sha256:30ec2b1bb76e3993aff912c553a5c249ad95b595249a32fde7158eafb71bda25"
)
CLAUDE = "/home/agent/.local/bin/claude"  # a link to ~agent/.local/share/claude/versions/<v>
ENTRYPOINT = "tini"
COMMAND = ("--", "sleep", "infinity")
WORKDIR = CONTAINER_WORK  # /workspace/work: the folder Claude Code trusts (SEED)

SETTINGS_FILE = "claude.json"
SETTINGS_PATH = str(CONTAINER_CONFIG_DIR / SETTINGS_FILE)
# Measured with 2.1.306 (docs/34, "Resultados de T17a-1"): each one, and nothing else.
SETTINGS: Mapping[str, Any] = {
    "skipWebFetchPreflight": True,
    "skipDangerousModePermissionPrompt": True,
    "permissions": {"deny": ["WebSearch"]},
}

KEY_ENV = "ANTHROPIC_API_KEY"
PROVIDER = "anthropic"  # the [[proxy.providers]] it uses: kind anthropic, the real host
API_HOST = "api.anthropic.com"  # Claude Code calls it itself: no ANTHROPIC_BASE_URL
ENV = (
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
    ("CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL", "1"),
    # npm's, reviewed (profile.REVIEWED_RESERVED_ENV): only a named profile may set them.
    ("npm_config_audit", "false"),
    ("npm_config_fund", "false"),
    ("npm_config_update_notifier", "false"),
)
PROVIDER_PARAMS = ("param:diagnostics",)

# Both with its permission prompts off and backtide's settings (decision 3; docs/34 section 5).
_COMMON = ("--dangerously-skip-permissions", "--settings", SETTINGS_PATH)
SESSION = (CLAUDE, *_COMMON)
TASK = (CLAUDE, "-p", "--output-format", "json", *_COMMON)
RESUME = "--continue"
KEY_TAIL = 20  # Claude Code shows, and remembers, the last 20 characters of the key it uses

# The first-run answers of an interactive session, written into ~/.claude.json when they are
# missing (docs/34, "Los primeros pasos de la interfaz"): the onboarding (without it the first
# screen checks api.anthropic.com/api/hello, the gate refuses it and Claude Code stops), the
# trust of /workspace/work, and the use of the key in ANTHROPIC_API_KEY (its last 20 characters:
# the FAKE key's, the only one there is). Runs as ``python3 -I -`` inside the container, as the
# agent; prints "seeded" or "unchanged", and exits with a message when the file is not a JSON
# object (it is left as it is).
SEED = f"""\
import json
import os
import sys

PROJECT = {json.dumps(str(WORKDIR))}
KEY_ENV = {json.dumps(KEY_ENV)}
TAIL = {KEY_TAIL}

home = os.environ.get("HOME", "")
if not home.startswith("/"):
    sys.exit("backtide: HOME is not an absolute path")
path = os.path.join(home, ".claude.json")
try:
    with open(path, encoding="utf-8") as handle:
        state = json.load(handle)
except FileNotFoundError:
    state = {{}}
except (OSError, ValueError) as error:
    sys.exit(f"backtide: ~/.claude.json cannot be read ({{type(error).__name__}}): left as it is")
if not isinstance(state, dict):
    sys.exit("backtide: ~/.claude.json is not a JSON object: left as it is")
before = json.dumps(state, sort_keys=True)
if state.get("hasCompletedOnboarding") is not True:
    state["hasCompletedOnboarding"] = True
projects = state.get("projects")
if not isinstance(projects, dict):
    projects = state["projects"] = {{}}
project = projects.get(PROJECT)
if not isinstance(project, dict):
    project = projects[PROJECT] = {{}}
if project.get("hasTrustDialogAccepted") is not True:
    project["hasTrustDialogAccepted"] = True
key = os.environ.get(KEY_ENV, "")
if key:
    tail = key[-TAIL:]
    responses = state.get("customApiKeyResponses")
    if not isinstance(responses, dict):
        responses = state["customApiKeyResponses"] = {{}}
    for name in ("approved", "rejected"):
        if not isinstance(responses.get(name), list):
            responses[name] = []
    if tail not in responses["approved"]:
        responses["approved"].append(tail)
    responses["rejected"] = [item for item in responses["rejected"] if item != tail]
if json.dumps(state, sort_keys=True) == before:
    print("unchanged")
    sys.exit(0)
temporary = f"{{path}}.backtide-{{os.getpid()}}"
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(state, handle, indent=2)
    handle.write("\\n")
os.replace(temporary, path)
print("seeded")
"""
SEED_ARGV = ("python3", "-I", "-")

# Its lines of the rewind notice (docs/34, section 7; measured in T17a-1: the session is cut,
# and `claude -p --continue` resumes the conversation of the snapshot).
REWIND_NOTICE_LINES = (
    "Claude Code: sus conversaciones vuelven a como estaban en la instantánea; "
    "`backtide tarea --continue` retoma la de ese momento.",
    "Si había una sesión abierta con `backtide entrar`, se ha cortado: entra de nuevo "
    "(`backtide entrar --continue` sigue la conversación de la instantánea).",
    "Lo que ya salió de la jaula (un push, un paquete publicado o lo que sacaste con "
    "`backtide exportar`) no vuelve.",
)


class UnsafeSettings(ProfileError):
    """/config/claude.json would hold something backtide did not review: never written. Names
    the keys only (``paths``), never a value."""

    def __init__(self, paths: tuple[str, ...]) -> None:
        super().__init__(f"claude.json: not the reviewed settings at {', '.join(paths)}")
        self._paths = paths

    @property
    def paths(self) -> tuple[str, ...]:
        return self._paths


def render_settings(config: "AgentJailConfig") -> dict[str, str]:
    """The one file of /config: claude.json, the same for every config."""
    del config
    return {SETTINGS_FILE: json.dumps(SETTINGS, indent=2) + "\n"}


def check_settings(files: Mapping[str, str]) -> None:
    """Refuse (UnsafeSettings) a claude.json that is not exactly the reviewed settings: every
    key of ``SETTINGS`` with its value, and nothing more. Claude Code's settings can run programs
    (``apiKeyHelper``, ``hooks``, ``statusLine``), set its environment (``env``) or allow tools:
    none of that is backtide's to give, so the check is a list of what may be there."""
    try:
        settings = json.loads(files[SETTINGS_FILE])
    except (KeyError, ValueError):
        raise UnsafeSettings(("<file>",)) from None
    if not isinstance(settings, dict):
        raise UnsafeSettings(("<root>",))
    wrong = sorted(
        str(key)
        for key in settings.keys() | SETTINGS.keys()
        if key not in settings or key not in SETTINGS or not _same(settings[key], SETTINGS[key])
    )
    if wrong:
        raise UnsafeSettings(tuple(wrong))


def _same(found: object, reviewed: object) -> bool:
    """Equal and of the same types all the way down (B2 of the review of T17a-4): ``1`` is not
    ``true``, nor ``1.0``, even though Python says they are equal."""
    if type(found) is not type(reviewed):
        return False
    if isinstance(reviewed, dict) and isinstance(found, dict):
        return found.keys() == reviewed.keys() and all(
            _same(found[key], reviewed[key]) for key in reviewed
        )
    if isinstance(reviewed, list | tuple) and isinstance(found, list | tuple):
        return len(found) == len(reviewed) and all(map(_same, found, reviewed))
    return found == reviewed


def check_providers(providers: tuple[ModelProvider, ...]) -> None:
    """Claude Code calls api.anthropic.com itself (no base URL): its provider must be an
    anthropic one at that host, or the gate would see its fake key go to an unknown host."""
    for provider in providers:
        if provider.name == PROVIDER and (
            provider.kind != "anthropic" or provider.host != API_HOST
        ):
            raise ValueError(
                f'provider {PROVIDER}: Claude Code needs kind = "anthropic" and host = '
                f'"{API_HOST}" (it calls that host itself)'
            )


def version_answer(output: str) -> bool:
    """Whether ``claude --version`` printed the pinned version."""
    return output.strip() == f"{CLAUDE_CODE_VERSION} (Claude Code)"


CLAUDE_CODE = AgentProfile(
    name=NAME,
    version=CLAUDE_CODE_VERSION,
    image=IMAGE,
    entrypoint=ENTRYPOINT,
    command=COMMAND,
    workdir=PurePosixPath(WORKDIR),
    workspace_dirs=(HOME_DIR, "work"),
    env=ENV,
    fake_key_env=((KEY_ENV, PROVIDER),),
    config_names=(SETTINGS_FILE,),
    render_config=render_settings,
    check_config=check_settings,
    ready_probe=(CLAUDE, "--version"),
    ready_answer=version_answer,
    rewind_notice_lines=REWIND_NOTICE_LINES,
    provider_params=PROVIDER_PARAMS,
    check_providers=check_providers,
    mode=SHELL_MODE,
    shell=ShellCommands(session=SESSION, task=TASK, resume=RESUME, seed=SEED_ARGV, seed_input=SEED),
)
