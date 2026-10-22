"""`backtide entrar`, `tarea`, `importar` and `exportar`: the owner and an agent of the ``shell``
mode (T17a-4, docs/34 section 7 and decision 3). Messages for the user are in Spanish.

They run as the owner, on the host, like `backtide rebobinar`: each asks the running service
first, over its control socket (backtide/service/control.py), which checks that the agent is a
shell one and is running, and records the request in the black box before anything happens.

- `entrar`: writes the first-run answers of the profile (Claude Code: ``~/.claude.json``) with
  ``docker exec -i`` as the agent, then ``docker exec -it`` of its interactive program, as the
  agent's user, in its working folder, connected to this terminal. What the agent prints goes
  straight to the terminal (docs/34, R5).
- `tarea`: ``docker exec`` of the headless run with the prompt as one argument after ``--``,
  and the answer printed (Claude Code: ``result`` of its JSON). The output is bounded.
- `importar`: a host folder into the agent's working folder, as a tar stream into ``tar -x``
  run as the agent (so it can write nothing the agent itself cannot). The host folder is read
  without following links: a link is skipped and named, and so is anything that is not a file
  or a folder. Bounded, and never over an existing folder unless ``--reemplazar``.
- `exportar`: the service copies (backtide/service/export.py); this only asks and reports.
  With ``--git <carpeta>``, the agent makes a git bundle of that repository inside the jail
  (``git bundle create``, run as the agent in the container: never git of the host over the
  agent's repository, whose config could run code) and the service exports only that file.

After the security review of T17a-4: everything goes to the container by its id, not its name
(B4); `entrar` puts the terminal back as it was and resets it when the session ends (M1);
`tarea` runs under ``timeout`` inside the container, is stopped there if this side gives up,
and a second ``--continue`` waits for the first (M4); `importar` leaves out what looks like a
secret unless ``--incluir-secretos``, and never takes the owner's HOME or its key folders (M2);
and `exportar` warns that what it took out was written by the agent (A1).

After the final security review of T17a-4 and its review: `exportar` leaves out what the
owner's own tools may run or read by themselves (every name with a dot first but a few harmless
files, ``CLAUDE.md``, ``AGENTS.md``...) unless ``--incluir-config`` (finding 5,
backtide/service/export.py), and a bundle says that its commits may carry them (M1); `importar`
reads the agent configs that often carry a token (``.mcp.json``, ``.claude.json``,
``.claude/settings*.json``, Gemini's, Claude Desktop's, Codex's) like a ``.git/config``,
failing closed: one with a secret inside is left out (6, M2, M3, B1, B2), and what was read is
what is copied (B3). ``~/.claude`` is never a source.
"""

import contextlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile
import termios
import threading
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from backtide.blackbox import redact
from backtide.blackbox.redact import strike_text
from backtide.blackbox.secret_words import CONFIG_WORDS, ENV_WORDS
from backtide.jail import docker
from backtide.jail.docker import JailError
from backtide.jail.profile import CONTAINER_HOME, SHELL_MODE, ShellCommands, check_prompt
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_export,
    ask_shell,
)
from backtide.service.export import BUNDLE_DIR
from backtide.service.shell import REPO_RE

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_PROBLEM = 3
SEED_TIMEOUT = 30.0
SEED_MAX_OUTPUT = 64 * 1024
TASK_MAX_OUTPUT = 8 * 1024 * 1024  # the JSON of one `claude -p`: its answer and a few counters
DEFAULT_TASK_MINUTES = 60
MAX_IMPORT_BYTES = 1024**3  # 1 GiB: the workspace has its own cap anyway
MAX_IMPORT_ENTRIES = 100_000
MAX_IMPORT_DEPTH = 64
MAX_LISTED_SKIPPED = 10
MAX_LISTED_SECRETS = 50  # each one left out is named: the owner decides about each
IMPORT_TIMEOUT = 30 * 60.0
# `tarea`: the run goes under coreutils' timeout inside the container (the image is Ubuntu's),
# which signals the run's whole process group and kills it KILL_AFTER seconds later.
TIMEOUT = "/usr/bin/timeout"
KILL_AFTER = 30
TIMED_OUT = 124  # timeout's code when it stopped the run; 137 when it had to kill it
PROBE_TIMEOUT = 30.0
# `entrar`: when the session ends, what the agent may have left in the terminal is undone: a soft
# reset (DECSTR), out of the alternate screen, no mouse reporting, no bracketed paste, cursor on.
TERMINAL_RESET = (
    "\x1b[!p\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l"
    "\x1b[?2004l\x1b[?25h"
)
SESSION_CLOSED = "Sesión de Claude Code cerrada. Estás otra vez en tu terminal."
SETTLE = 0.1  # what the terminal still answers to the agent's last queries arrives meanwhile
BUNDLE_TIMEOUT = 10 * 60.0
EXPORTED_WARNING = (
    "Lo exportado lo escribió el agente: no ejecutes nada de ahí (git, make, npm, tests, abrirlo "
    "en el editor o en Claude Code) sin revisarlo. Lo más delicado es lo que tus herramientas "
    "ejecutan o leen solas al abrir la carpeta (.claude/, .mcp.json, .vscode/, .envrc, .github/, "
    "CLAUDE.md, AGENTS.md…): un agente engañado lo escribe como una parte normal del proyecto. "
    "Por eso `exportar` deja fuera, salvo con --incluir-config, todo lo que empieza por punto "
    "(menos unos pocos archivos inofensivos, como .gitignore o .editorconfig), CLAUDE.md, "
    "AGENTS.md, GEMINI.md, las configuraciones de MCP y los *.code-workspace."
)
INCLUDED_CONFIG_WARNING = (
    "Con --incluir-config han salido también .claude/, .mcp.json, .vscode/, .envrc, .github/, "
    "CLAUDE.md y el resto de lo que tus herramientas pueden ejecutar o leer solas: revísalo uno a "
    "uno antes de abrir la carpeta con Claude Code, tu editor o direnv."
)
BUNDLE_WARNING = (
    "Lo exportado lo escribió el agente, y en un bundle no se deja nada fuera: los commits pueden "
    "traer .claude/, .mcp.json, .vscode/, .envrc, .github/, CLAUDE.md… que tus herramientas "
    "ejecutan o leen solas al abrir la carpeta. Clona con `git clone --no-checkout` y revisa "
    "`git ls-tree -r --name-only HEAD` (y `git log -p`) antes de sacar los archivos o abrir la "
    "carpeta."
)
_TERM_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}", re.ASCII)
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", re.ASCII)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
NO_SERVICE = (
    "no hay un servicio de backtide en marcha (o no contesta): arranca `backtide vigilar` y "
    "vuelve a probar."
)

Runner = Callable[[list[str]], int]  # an interactive docker command: its exit code


def error(message: str) -> None:
    print(f"ERROR: {printable(redact(message))}", file=sys.stderr)


def printable(text: str, *, keep_lines: bool = False) -> str:
    """``text`` with control characters escaped (``\\n`` and ``\\t`` kept with ``keep_lines``):
    the agent's text never moves the cursor or rewrites what the terminal shows."""
    kept = "\n\t" if keep_lines else ""
    return "".join(c if c.isprintable() or c in kept else repr(c)[1:-1] for c in text)


def shell_of(config: ServiceConfig) -> ShellCommands | None:
    """The profile's shell commands, or None (and the error said) for a service-mode agent."""
    profile = config.agent_profile
    if profile.mode != SHELL_MODE or profile.shell is None:
        error(
            f"el agente de esta instalación (perfil {profile.name}) no es de modo shell: "
            "`backtide entrar`, `tarea`, `importar` y `exportar` son para agentes de programación "
            'como claude-code ([agent] profile = "claude-code").'
        )
        return None
    return profile.shell


def _ask(config: ServiceConfig, kind: str, **options: Any) -> dict[str, Any] | None:
    try:
        reply = ask_shell(config.control_socket, kind, **options)
    except ControlUnavailable:
        error(NO_SERVICE)
        return None
    except ControlError as problem:
        error(str(problem))
        return None
    if not reply["ok"]:
        error(reply["message"])
        return None
    return reply


def _exec_prefix(reply: dict[str, Any], *flags: str, workdir: str | None = None) -> list[str]:
    """``docker exec`` as the agent, in its folder, into the container the service started and
    checked: by its full id, never by a name another container could have taken (B4)."""
    return [
        "exec", *flags, "--user", reply["user"], "--workdir", workdir or reply["workdir"],
        reply["container_id"],
    ]  # fmt: skip


def _interactive(argv: list[str]) -> int:
    """The docker CLI connected to this terminal (``docker exec -it``)."""
    try:
        return subprocess.call([docker.PROGRAM, *argv])
    except OSError as problem:
        error(f"no se puede ejecutar {docker.PROGRAM}: {problem}")
        return 127


# -- entrar --------------------------------------------------------------------------------------


def terminal_guard(fd: int, out: Any) -> Callable[[], None]:
    """Save the terminal's settings of ``fd`` now (if it is a terminal) and return what puts
    them back after a session (M1 of the review): wait ``SETTLE`` for the terminal's late
    answers, throw away whatever input is pending (an answer to the agent's queries would
    otherwise be typed into the owner's shell), restore the settings, and write the soft reset
    on ``out`` if it is a terminal. Never raises."""
    try:
        saved = termios.tcgetattr(fd) if os.isatty(fd) else None
    except (OSError, termios.error):
        saved = None

    def restore() -> None:
        if saved is None:
            return
        time.sleep(SETTLE)
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            termios.tcflush(fd, termios.TCIFLUSH)
        except (OSError, termios.error) as problem:
            error(f"no se ha podido dejar la terminal como estaba: {problem}")
        with contextlib.suppress(OSError, ValueError):
            if out.isatty():
                out.write(TERMINAL_RESET)
                out.flush()

    return restore


def _stdin_fd() -> int:
    try:
        return sys.stdin.fileno()
    except (OSError, ValueError, AttributeError):
        return -1


def entrar(config: ServiceConfig, *, resume: bool = False, run: Runner = _interactive) -> int:
    shell = shell_of(config)
    if shell is None:
        return EXIT_ERROR
    reply = _ask(config, "session", resume=resume)
    if reply is None:
        return EXIT_FAILED
    if shell.seed:
        try:
            seeded = docker.run(
                [*_exec_prefix(reply, "--interactive"), *shell.seed],
                input=shell.seed_input,
                timeout=SEED_TIMEOUT,
                check=False,
                max_output=SEED_MAX_OUTPUT,
            )
        except JailError as problem:
            error(f"no se han podido preparar los primeros pasos del agente: {problem}")
            return EXIT_FAILED
        if seeded.returncode != 0:
            tail = docker.sanitize((seeded.stderr or seeded.stdout).strip()[-500:])
            error(f"no se han podido preparar los primeros pasos del agente: {tail}")
            return EXIT_FAILED
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    term = os.environ.get("TERM", "")
    flags = ["--interactive", *(["--tty"] if tty else [])]
    if _TERM_RE.fullmatch(term):
        flags += ["--env", f"TERM={term}"]
    print("Entrando en el agente (sal con /exit o Ctrl-D). Todo lo que haga queda grabado.")
    sys.stdout.flush()
    restore = terminal_guard(_stdin_fd(), sys.stdout)
    try:
        code = run([*_exec_prefix(reply, *flags), *shell.session_argv(resume=resume)])
    finally:
        restore()
    print(SESSION_CLOSED)
    if code == 0:
        return EXIT_OK
    print(
        f"La sesión ha terminado con el código {code} (137: cortada, por ejemplo por un "
        "rebobinado). `backtide entrar --continue` retoma la conversación.",
        file=sys.stderr,
    )
    return EXIT_FAILED


# -- tarea ---------------------------------------------------------------------------------------


def tarea(config: ServiceConfig, prompt: str, *, resume: bool = False, minutes: float = 60) -> int:
    shell = shell_of(config)
    if shell is None:
        return EXIT_ERROR
    try:
        argv = shell.task_argv(check_prompt(prompt), resume=resume)
    except ValueError as problem:
        error(f"la tarea no vale: {problem}")
        return EXIT_ERROR
    if not 0 < minutes <= 24 * 60:
        error("--minutos tiene que estar entre 1 y 1440")
        return EXIT_ERROR
    reply = _ask(config, "task", resume=resume)
    if reply is None:
        return EXIT_FAILED
    pattern = _task_pattern(shell)
    if resume:
        running = _task_running(reply, pattern)
        if running is not False:
            error(
                "ya hay una tarea en marcha dentro del agente: espera a que termine antes de "
                "seguir la conversación con --continue"
                if running
                else "no se ha podido comprobar si hay otra tarea en marcha, así que no se sigue "
                "la conversación: inténtalo de nuevo"
            )
            return EXIT_FAILED
    seconds = round(minutes * 60)
    try:
        done = docker.run(
            [*_exec_prefix(reply), TIMEOUT, "-k", str(KILL_AFTER), str(seconds), *argv],
            timeout=seconds + KILL_AFTER + 30,
            check=False,
            max_output=TASK_MAX_OUTPUT,
        )
    except JailError as problem:
        stopped = _stop_task(reply, pattern)
        error(
            f"la tarea no ha terminado bien ({problem}). "
            + (
                "Se ha parado dentro del agente."
                if stopped
                else "Puede seguir en marcha dentro del agente: mira la caja negra."
            )
        )
        return EXIT_PROBLEM
    if done.returncode in (TIMED_OUT, 137):
        error(
            f"la tarea se ha cortado: pasó de {minutes:g} minutos (--minutos)"
            if done.returncode == TIMED_OUT
            else "la tarea se ha cortado (se pasó del tiempo, o un rebobinado la paró)"
        )
        return EXIT_FAILED
    return _report_task(done)


def _task_pattern(shell: ShellCommands) -> str:
    """What ``pgrep -f`` finds of a task (M4): the timeout around the profile's task program.
    An extended regex: the dots of the path are literal."""
    program = shell.task[0].replace(".", "[.]")
    return f"^{TIMEOUT} -k {KILL_AFTER} [0-9]+ {program} "


def _task_running(reply: dict[str, Any], pattern: str) -> bool | None:
    """Whether a task runs now inside the agent (``pgrep`` as the agent), or None if that
    cannot be said."""
    uid = reply["user"].split(":")[0]
    try:
        found = docker.run(
            [*_exec_prefix(reply), "pgrep", "-u", uid, "-f", pattern],
            check=False,
            timeout=PROBE_TIMEOUT,
        )
    except JailError:
        return None
    return {0: True, 1: False}.get(found.returncode)


def _stop_task(reply: dict[str, Any], pattern: str) -> bool:
    """A task this side gave up on (its docker CLI timed out or broke) is stopped inside: a
    TERM to its timeout, which passes it to the whole run and kills it ``KILL_AFTER`` seconds
    later. True if nothing of it is left running, or it was signalled."""
    uid = reply["user"].split(":")[0]
    try:
        done = docker.run(
            [*_exec_prefix(reply), "pkill", "-TERM", "-u", uid, "-f", pattern],
            check=False,
            timeout=PROBE_TIMEOUT,
        )
    except JailError:
        return False
    return done.returncode in (0, 1)


def _report_task(done: subprocess.CompletedProcess[str]) -> int:
    """Print the answer of a headless run: ``result`` of its JSON (Claude Code)."""
    try:
        answer = json.loads(done.stdout)
    except ValueError:
        answer = None
    if not isinstance(answer, dict) or not isinstance(answer.get("result"), str):
        tail = (done.stderr or done.stdout).strip()[-2000:]
        error(f"la tarea ha terminado con el código {done.returncode} y sin respuesta: {tail}")
        return EXIT_FAILED
    print(printable(answer["result"], keep_lines=True))
    if done.returncode != 0 or answer.get("is_error") is True:
        error(f"la tarea ha terminado con un error (código {done.returncode})")
        return EXIT_FAILED
    return EXIT_OK


# -- importar ------------------------------------------------------------------------------------


class ImportRefused(Exception):
    """The host folder cannot be imported; the message is Spanish."""


Identity = tuple[int, int, int, int, int]  # st_dev, st_ino, st_mtime_ns, st_ctime_ns, st_size


@dataclass
class ImportPlan:
    """What a host folder holds, read without following links."""

    dirs: list[str] = field(default_factory=list)  # relative, parents first
    files: list[tuple[str, int]] = field(default_factory=list)  # relative, size
    skipped: list[str] = field(default_factory=list)  # links and others, relative
    secrets: list[str] = field(default_factory=list)  # what looks like a secret, left out
    bytes: int = 0  # of ``files``, kept as they are added
    scanned: dict[str, Identity] = field(default_factory=dict)  # read for secrets, as read


# What looks like a secret (M2 of the review of T17a-4): left out of an import unless the owner
# says --incluir-secretos. By the name, without case; a folder is left out whole.
SECRET_DIRS = frozenset(
    {".ssh", ".aws", ".gnupg", ".docker", ".kube", ".azure", ".password-store", ".gcloud"}
)
SECRET_FILES = frozenset(
    {
        ".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", ".git-credentials", ".dockercfg",
        ".htpasswd", ".boto", ".s3cfg", "secrets.json", "secrets.yaml", "secrets.yml",
        "secrets.toml",
    }
)  # fmt: skip
_SECRET_NAME_RE = re.compile(
    r"\.env.*|\.?credentials.*|id_[a-z0-9_-]+(?:\.pub)?|service-account.*\.json"
    r"|.*\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk|keytab|tfvars|tfstate)",
    re.IGNORECASE | re.DOTALL,
)
# A git config with a remote that carries a password or a token: user:password@ (and
# x-access-token:<token>@, oauth2:<token>@), a long token alone before the @, or an
# http.extraheader (CI checkouts put an Authorization header there).
_URL_SECRET_RE = re.compile(r"://(?:[^/@\s]*:[^/@\s]*|[^/@\s:]{20,})@|extraheader", re.IGNORECASE)
MAX_GIT_CONFIG = 1024 * 1024
# An agent's config that often carries a real token (finding 6 of the final review of T17a-4,
# M2, M3, B1 and B2 of its review): an MCP server's "env" or "headers" in .mcp.json,
# .claude.json, the "env" or the apiKeyHelper of .claude/settings.local.json, Gemini's, Claude
# Desktop's, Codex's (TOML). Read like a git config, failing closed: left out when the raw text
# or any text in it has a secret's shape (backtide's redact patterns, also each array's texts
# joined with spaces), when a name that sounds like a secret (CONFIG_WORDS, ENV_WORDS, or
# ending in "key", anywhere and without case) has any literal under it, or when anything under
# "env" or "headers" is a literal. Only an exact "${VAR}" is not a literal. Every key is seen,
# repeated ones too. One that cannot be read or parsed, or that is bigger than
# MAX_AGENT_CONFIG, is taken as one. Compared without case, at any depth.
_AGENT_CONFIG_RE = re.compile(
    r"\.mcp\.json|\.claude\.json(?:\..*)?|claude_desktop_config\.json|mcp_config\.json",
    re.DOTALL,
)
AGENT_CONFIG_IN = frozenset(
    {
        (".claude", "settings.json"),
        (".claude", "settings.local.json"),
        (".claude", ".credentials.json"),  # left out by its name anyway
        (".cursor", "mcp.json"),
        (".vscode", "mcp.json"),
        (".gemini", "settings.json"),
    }
)
TOML_AGENT_CONFIG_IN = frozenset({(".codex", "config.toml")})
MAX_AGENT_CONFIG = 8 * 1024 * 1024  # .claude.json keeps a history per project
_SECRET_KEY_RE = re.compile(rf"{CONFIG_WORDS}|{ENV_WORDS}|key$", re.IGNORECASE)
_ENV_REFERENCE_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")
# In the raw text, a pair whose value is a reference or empty is not a secret: taken out first.
_REFERENCE_PAIR_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"\s*:\s*"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\})?"', re.DOTALL
)
_HOT_KEYS = frozenset({"env", "environment", "headers"})  # every literal under them is a secret
_PAIR_NAMES = frozenset({"name", "key", "header"})  # {"Name": "Authorization", "Value": ...}
_PAIR_VALUES = frozenset({"value", "values"})
# Folders of the owner's HOME that are never a source, nor inside one (with HOME itself and
# every folder above it).
PRIVATE_HOME_DIRS = (".ssh", ".aws", ".gnupg", ".config", ".docker", ".kube", ".claude")


def looks_secret(relative: str, kind: str) -> bool:
    """Whether a file or folder of an import looks like it holds a secret, by its name."""
    name = relative.rsplit("/", 1)[-1].casefold()
    if kind == "dir":
        return name in SECRET_DIRS
    return name in SECRET_FILES or bool(_SECRET_NAME_RE.fullmatch(name))


def _identity(info: os.stat_result) -> Identity:
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)


def _scan_kind(relative: str) -> str | None:
    """Which reader a file of an import needs before it goes in: "git" (a ``config`` inside a
    ``.git``), "json" or "toml" (an agent's config), or None."""
    parts = relative.casefold().split("/")
    pair = tuple(parts[-2:])
    if parts[-1] == "config" and ".git" in parts[:-1]:
        return "git"
    if _AGENT_CONFIG_RE.fullmatch(parts[-1]) or pair in AGENT_CONFIG_IN:
        return "json"
    if pair in TOML_AGENT_CONFIG_IN:
        return "toml"
    return None


def _scanned_secret(dir_fd: int, name: str, relative: str, plan: "ImportPlan") -> bool:
    """Whether a file that has to be read before it goes in (``_scan_kind``) holds a secret.
    One that cannot be read, is too big or cannot be parsed is taken as one (it is left out,
    and said). One without is noted in ``plan.scanned`` as it was read (B3 of the review): the
    copy refuses it if it changed since."""
    kind = _scan_kind(relative)
    if kind is None:
        return False
    limit = MAX_GIT_CONFIG if kind == "git" else MAX_AGENT_CONFIG
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError:
        return True
    try:
        identity = _identity(os.fstat(fd))
        chunks, size = [], 0
        while size <= limit and (chunk := os.read(fd, limit + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
    except OSError:
        return True
    finally:
        os.close(fd)
    if size > limit:
        return True
    raw = b"".join(chunks)
    if kind == "git":
        secret = bool(_URL_SECRET_RE.search(raw.decode("utf-8", errors="replace")))
    else:
        secret = _config_holds_secret(raw, toml=kind == "toml")
    if not secret:
        plan.scanned[relative] = identity
    return secret


class _Pairs(list[tuple[str, Any]]):
    """A JSON object as all its pairs, in order: a repeated key is never lost (B1)."""


def _config_holds_secret(raw: bytes, *, toml: bool) -> bool:
    try:
        text = raw.decode("utf-8")
        data = tomllib.loads(text) if toml else json.loads(text, object_pairs_hook=_Pairs)
    except (ValueError, RecursionError):
        return True
    if toml:
        data = _as_pairs(data)
    elif strike_text(_REFERENCE_PAIR_RE.sub("", text)) != _REFERENCE_PAIR_RE.sub("", text):
        return True
    return _holds_secret(data)


def _as_pairs(data: object) -> object:
    """Parsed TOML in the shape _holds_secret walks: tables as _Pairs (its dates are left as
    they are: never a secret)."""
    stack: list[tuple[object, Any]] = []
    root = _Pairs()
    top = data if isinstance(data, dict) else {}
    stack.append((top, root))
    while stack:
        node, into = stack.pop()
        items = node.items() if isinstance(node, dict) else enumerate(node)  # type: ignore[union-attr]
        for key, value in items:
            if isinstance(value, dict):
                made: Any = _Pairs()
                stack.append((value, made))
            elif isinstance(value, list):
                made = []
                stack.append((value, made))
            else:
                made = value
            if isinstance(into, _Pairs):
                into.append((key, made))
            else:
                into.append(made)
    return root


def _is_literal(value: object) -> bool:
    """A value given as it is: a non-empty text that is not exactly ``${VAR}``, or a number."""
    if isinstance(value, str):
        return bool(value.strip()) and not _ENV_REFERENCE_RE.fullmatch(value)
    return isinstance(value, int | float) and not isinstance(value, bool)


def _secret_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SECRET_KEY_RE.search(key.strip()))


def _holds_secret(data: object) -> bool:
    """Whether parsed config holds a secret (see _AGENT_CONFIG_RE above). ``hot``: under a
    secret's name, ``env`` or ``headers``, every literal counts."""
    stack: list[tuple[object, bool]] = [(data, False)]
    while stack:
        node, hot = stack.pop()
        if isinstance(node, _Pairs):
            named = any(key.casefold() in _PAIR_NAMES and _secret_key(value) for key, value in node)
            for key, value in node:
                if strike_text(key) != key:
                    return True
                folded = key.casefold()
                warm = folded in _HOT_KEYS or _secret_key(key) or (named and folded in _PAIR_VALUES)
                stack.append((value, hot or warm))
        elif isinstance(node, list):
            texts = " ".join(item for item in node if isinstance(item, str))
            if strike_text(texts) != texts:
                return True
            pair = len(node) == 2 and isinstance(node[0], str) and _secret_key(node[0])
            stack.extend((item, hot or (pair and index == 1)) for index, item in enumerate(node))
        elif isinstance(node, str) and strike_text(node) != node:
            return True
        elif hot and _is_literal(node):
            return True
    return False


def plan_import(source_fd: int, *, include_secrets: bool = False) -> ImportPlan:
    """Walk the folder open at ``source_fd`` (opened without following a link) and say what
    would be imported: what looks like a secret is left out (``secrets``) unless
    ``include_secrets``. Raises ImportRefused past the bounds."""
    plan = ImportPlan()
    stack: list[tuple[int, str, int]] = [(os.dup(source_fd), "", 0)]
    try:
        while stack:
            fd, prefix, depth = stack.pop()
            try:
                for name in sorted(os.listdir(fd)):
                    rel = f"{prefix}{name}"
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    is_dir = stat.S_ISDIR(info.st_mode)
                    if (is_dir or stat.S_ISREG(info.st_mode)) and not include_secrets:
                        if looks_secret(rel, "dir" if is_dir else "file") or (
                            not is_dir and _scanned_secret(fd, name, rel, plan)
                        ):
                            plan.secrets.append(rel)
                            continue
                    if is_dir and depth < MAX_IMPORT_DEPTH:
                        plan.dirs.append(rel)
                        stack.append((os.open(name, _DIR_FLAGS, dir_fd=fd), f"{rel}/", depth + 1))
                    elif stat.S_ISREG(info.st_mode):
                        plan.files.append((rel, info.st_size))
                        plan.bytes += info.st_size
                    else:
                        plan.skipped.append(rel)
                    if len(plan.dirs) + len(plan.files) > MAX_IMPORT_ENTRIES:
                        raise ImportRefused(
                            f"la carpeta tiene más de {MAX_IMPORT_ENTRIES} archivos y carpetas"
                        )
                    if plan.bytes > MAX_IMPORT_BYTES:
                        raise ImportRefused(
                            f"la carpeta pasa de {MAX_IMPORT_BYTES // 1024**2} MiB: importa solo "
                            "lo que el agente necesita"
                        )
            finally:
                os.close(fd)
    finally:
        for fd, _, _ in stack:
            os.close(fd)
    return plan


def write_tar(source_fd: int, plan: ImportPlan, out: BinaryIO) -> None:
    """The plan as a tar stream on ``out``: folders and regular files only, each opened again
    from its parent without following a link (a file that became something else fails)."""
    with tarfile.open(fileobj=out, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for rel in plan.dirs:
            info = tarfile.TarInfo(rel)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tar.addfile(info)
        for rel, _ in plan.files:
            fd = _open_below(source_fd, rel)
            try:
                found = os.fstat(fd)
                if not stat.S_ISREG(found.st_mode):
                    raise ImportRefused(f"{rel} ha dejado de ser un archivo normal")
                if rel in plan.scanned and _identity(found) != plan.scanned[rel]:
                    raise ImportRefused(
                        f"{rel} ha cambiado desde que se revisó si llevaba secretos: no se importa"
                    )
                info = tarfile.TarInfo(rel)
                info.size = found.st_size
                info.mode = found.st_mode & 0o755 | 0o600
                with os.fdopen(os.dup(fd), "rb") as handle:
                    tar.addfile(info, handle)
            finally:
                os.close(fd)


def _open_below(root_fd: int, rel: str) -> int:
    parts = rel.split("/")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=fd)
    finally:
        os.close(fd)


def _refuse_private(path: Path) -> None:
    """ImportRefused for the owner's HOME, any folder above it, and its key folders (``.ssh``,
    ``.aws``…) or anything inside them (M2), compared after resolving links and without case."""
    home = Path(os.path.realpath(Path.home()))
    real = Path(os.path.realpath(path))
    folded, home_folded = Path(str(real).casefold()), Path(str(home).casefold())
    if home_folded.is_relative_to(folded):
        raise ImportRefused(
            f"{path} es tu carpeta personal o la contiene: importa solo la carpeta del proyecto"
        )
    for name in PRIVATE_HOME_DIRS:
        if folded.is_relative_to(home_folded / name):
            raise ImportRefused(
                f"{path} está en ~/{name}, donde se guardan claves: no se importa nunca"
            )


def open_source(text: str) -> tuple[int, Path]:
    """The host folder, opened without following a link in its last component (never the
    owner's HOME, a folder above it, nor its key folders)."""
    path = Path(text).expanduser()
    path = Path(os.path.abspath(path))
    _refuse_private(path)
    try:
        return os.open(path, _DIR_FLAGS), path
    except OSError as problem:
        raise ImportRefused(
            f"no se puede abrir la carpeta {path}: {os.strerror(problem.errno or 0)} (un enlace "
            "simbólico no vale: da la carpeta de verdad)"
        ) from None


def importar(
    config: ServiceConfig,
    source: str,
    *,
    name: str | None = None,
    replace: bool = False,
    include_secrets: bool = False,
    popen: Callable[..., Any] = subprocess.Popen,
) -> int:
    shell = shell_of(config)
    if shell is None:
        return EXIT_ERROR
    try:
        source_fd, path = open_source(source)
    except ImportRefused as problem:
        error(str(problem))
        return EXIT_ERROR
    try:
        target_name = name if name is not None else path.name
        if not _NAME_RE.fullmatch(target_name) or target_name in (".", ".."):
            error(
                f"{target_name!r} no vale como nombre de carpeta en el agente: usa --nombre con "
                "letras, números, '.', '_' o '-'"
            )
            return EXIT_ERROR
        try:
            plan = plan_import(source_fd, include_secrets=include_secrets)
        except ImportRefused as problem:
            error(f"no se importa nada: {problem}")
            return EXIT_ERROR
        except OSError as problem:
            error(f"no se puede leer {path}: {os.strerror(problem.errno or 0)}")
            return EXIT_ERROR
        details = {
            "name": target_name,
            "source": str(path)[:1024],
            "files": len(plan.files),
            "bytes": plan.bytes,
            "replace": replace,
            "secrets_left_out": len(plan.secrets),
            "include_secrets": include_secrets,
        }
        reply = _ask(config, "import", import_details=details)
        if reply is None:
            return EXIT_FAILED
        target = str(PurePosixPath(reply["workdir"]) / target_name)
        return _extract(reply, source_fd, plan, target, replace=replace, popen=popen, path=path)
    finally:
        os.close(source_fd)


def _extract(
    reply: dict[str, Any],
    source_fd: int,
    plan: ImportPlan,
    target: str,
    *,
    replace: bool,
    popen: Callable[..., Any],
    path: Path,
) -> int:
    mkdir = ["mkdir", *(["-p"] if replace else []), "--", target]
    try:
        made = docker.run([*_exec_prefix(reply), *mkdir], check=False, timeout=60)
    except JailError as problem:
        error(f"no se ha podido preparar {target} en el agente: {problem}")
        return EXIT_FAILED
    if made.returncode != 0:
        if "exists" in made.stderr:
            error(f"ya existe {target} en el agente: usa --reemplazar para escribir encima")
        else:
            error(f"no se ha podido crear {target} en el agente: {docker.sanitize(made.stderr)}")
        return EXIT_FAILED
    extract = ["tar", "-x", "-f", "-", "--no-same-owner", "-C", target]
    if not replace:
        extract.insert(2, "--keep-old-files")
    argv = [docker.PROGRAM, *_exec_prefix(reply, "--interactive"), *extract]
    failure: Exception | str | None = None
    # tar's stderr goes to a file (a pipe nobody reads could fill and stop it), and the whole
    # import, the writing included, has one deadline: past it, the docker CLI is killed and the
    # write fails (B3 of the review).
    with tempfile.TemporaryFile() as stderr_file:
        process = popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=stderr_file)
        deadline = time.monotonic() + IMPORT_TIMEOUT
        expired = threading.Event()

        def expire() -> None:
            expired.set()
            with contextlib.suppress(OSError):
                process.kill()

        timer = threading.Timer(IMPORT_TIMEOUT, expire)
        timer.daemon = True
        timer.start()
        try:
            try:
                write_tar(source_fd, plan, process.stdin)
            except (ImportRefused, OSError, tarfile.TarError) as problem:
                failure = problem
            finally:
                with contextlib.suppress(OSError):  # the docker CLI went away: its code says why
                    process.stdin.close()
            try:
                process.wait(timeout=max(1.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                expire()
                process.wait()
        finally:
            timer.cancel()
        if expired.is_set():
            failure = f"se ha pasado el tiempo ({IMPORT_TIMEOUT / 60:g} minutos)"
        stderr = _tail(stderr_file, 64 * 1024)
    if failure is not None or process.returncode != 0:
        text = stderr.decode(errors="replace")
        why = str(failure) if failure is not None else docker.sanitize(text.strip()[-500:])
        error(f"la importación se ha quedado a medias en {target}: {why}")
        return EXIT_PROBLEM
    print(
        f"Importado {path} en {target}: {len(plan.files)} archivos y {len(plan.dirs)} carpetas "
        f"({plan.bytes} bytes)."
    )
    if plan.skipped:
        print(
            "Sin copiar (enlaces simbólicos u otros que no son archivos ni carpetas): "
            + _listed(plan.skipped)
        )
    if plan.secrets:
        print(
            "Sin copiar porque parecen secretos (claves, tokens, .env, una URL de git con "
            "contraseña, un .mcp.json o unos ajustes de Claude Code con un token…): "
            f"{_listed(plan.secrets, MAX_LISTED_SECRETS)}. Si el agente de verdad los necesita, "
            "vuelve a importar con --incluir-secretos (y recuerda que el agente los podrá leer)."
        )
    return EXIT_OK


def _listed(names: list[str], limit: int = MAX_LISTED_SKIPPED) -> str:
    shown = ", ".join(printable(name) for name in names[:limit])
    more = len(names) - limit
    return shown + (f" y {more} más" if more > 0 else "")


def _tail(handle: BinaryIO, limit: int) -> bytes:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    handle.seek(max(0, size - limit))
    return handle.read(limit)


# -- exportar ------------------------------------------------------------------------------------


def exportar(
    config: ServiceConfig,
    destination: str,
    *,
    git: str | None = None,
    include_config: bool = False,
) -> int:
    shell = shell_of(config)
    if shell is None:
        return EXIT_ERROR
    path = Path(os.path.abspath(Path(destination).expanduser()))
    if git is not None and include_config:
        error(
            "--incluir-config es para exportar la carpeta de trabajo; con --git sale un bundle "
            "con los commits, que ya llevan esos archivos (revísalos antes de sacarlos)"
        )
        return EXIT_ERROR
    if git is not None:
        if not REPO_RE.fullmatch(git):
            error(
                f"{printable(git)!r} no vale como carpeta del repositorio: di una carpeta de "
                "/workspace/work, relativa (por ejemplo `proyecto`, o `.` para la carpeta entera)"
            )
            return EXIT_ERROR
        return _export_bundle(config, path, git)
    reply = _ask_export(config, path, **({"include_config": True} if include_config else {}))
    if isinstance(reply, int):
        return reply
    counts = reply["details"]
    print(
        f"Exportado a {printable(reply['destination'])}: {counts.get('files', 0)} archivos y "
        f"{counts.get('folders', 0)} carpetas ({counts.get('bytes', 0)} bytes), de la "
        f"instantánea {reply['snapshot']}."
    )
    skipped = counts.get("skipped_links", 0) + counts.get("skipped_other", 0)
    if skipped:
        print(
            f"Sin copiar: {counts.get('skipped_links', 0)} enlaces simbólicos y "
            f"{counts.get('skipped_other', 0)} cosas que no son archivos ni carpetas."
        )
    _report_skipped(counts, reply.get("skipped", []))
    print(f"AVISO: {EXPORTED_WARNING}")
    if include_config:
        print(f"AVISO: {INCLUDED_CONFIG_WARNING}")
    return EXIT_OK


def _ask_export(config: ServiceConfig, path: Path, **options: Any) -> dict[str, Any] | int:
    """The service's answer to an export, or the exit code (the error said)."""
    try:
        reply = ask_export(config.control_socket, str(path), **options)
    except ControlUnavailable:
        error(NO_SERVICE)
        return EXIT_FAILED
    except ControlOutcomeUnknown as problem:
        error(str(problem))
        return EXIT_PROBLEM
    except ControlError as problem:
        error(str(problem))
        return EXIT_ERROR
    if not reply["ok"]:
        error(reply["message"])
        return EXIT_ERROR if reply["outcome"] in ("invalid", "not_shell", "refused") else 1
    return reply


SKIPPED_WHY = {
    "git": (
        "skipped_git",
        "repositorios de git (.git, o carpetas con forma de repositorio), para que nada se "
        "ejecute solo en este ordenador; los commits salen con `backtide exportar --git "
        "<carpeta> <ruta.bundle>`",
    ),
    "name": ("skipped_names", "nombres con caracteres de control o invisibles"),
    "config": (
        "skipped_config",
        "archivos o carpetas que tus herramientas pueden ejecutar o leer solas al abrir la "
        "carpeta (lo que empieza por punto, salvo inofensivos como .gitignore, y CLAUDE.md, "
        "AGENTS.md, GEMINI.md, configuraciones de MCP, *.code-workspace); si de verdad los "
        "quieres, vuelve a exportar con --incluir-config",
    ),
    "case": (
        "skipped_collisions",
        "nombres que solo cambian en mayúsculas y minúsculas de otro que ya estaba (el destino "
        "no las distingue)",
    ),
}


def _report_skipped(counts: dict[str, int], named: list[list[str]]) -> None:
    for why, (key, what) in SKIPPED_WHY.items():
        total = counts.get(key, 0)
        if not total:
            continue
        names = [printable(path) for kind, path in named if kind == why]
        more = total - len(names)
        listed = ", ".join(names) + (f" y {more} más" if names and more > 0 else "")
        print(f"Sin copiar: {total} {what}" + (f": {listed}." if names else "."))


def _export_bundle(config: ServiceConfig, path: Path, repo: str) -> int:
    """`exportar --git`: the agent makes the bundle inside the jail (``git bundle create``, as
    the agent, in the container: the repository's config can only run code there), and the
    service exports only that file, from a fresh snapshot."""
    reply = _ask(config, "bundle")
    if reply is None:
        return EXIT_FAILED
    name = f"export-{secrets.token_hex(16)}.bundle"
    folder = f"{CONTAINER_HOME}/{BUNDLE_DIR}"
    bundle = f"{folder}/{name}"
    repo_dir = reply["workdir"] if repo == "." else f"{reply['workdir']}/{repo}"
    try:
        try:
            docker.run([*_exec_prefix(reply), "mkdir", "-p", "--", folder], timeout=60)
            made = docker.run(
                [*_exec_prefix(reply), "git", "-C", repo_dir, "bundle", "create", bundle, "--all"],
                check=False,
                timeout=BUNDLE_TIMEOUT,
                max_output=SEED_MAX_OUTPUT,
            )
        except JailError as problem:
            error(f"no se ha podido hacer el bundle dentro del agente: {problem}")
            return EXIT_FAILED
        if made.returncode != 0:
            tail = docker.sanitize((made.stderr or made.stdout).strip()[-500:])
            error(f"git no ha podido hacer el bundle de {repo} dentro del agente: {tail}")
            return EXIT_FAILED
        answer = _ask_export(config, path, bundle=name, repo=repo)
    finally:
        with contextlib.suppress(JailError):  # tidy only: the snapshot keeps it as the record
            docker.run([*_exec_prefix(reply), "rm", "-f", "--", bundle], check=False, timeout=60)
    if isinstance(answer, int):
        return answer
    shown = printable(answer["destination"])
    print(
        f"Exportado el bundle de git de {printable(repo)} a {shown} "
        f"({answer['details'].get('bytes', 0)} bytes), de la instantánea {answer['snapshot']}. "
        f"Un bundle son solo datos: `git clone --no-checkout {shown} <carpeta-nueva>` no trae ni "
        "la configuración ni los hooks del agente; revisa los commits (git log -p) antes de "
        "sacar los archivos."
    )
    print(f"AVISO: {BUNDLE_WARNING}")
    return EXIT_OK
