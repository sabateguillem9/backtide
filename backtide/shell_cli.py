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
"""

import contextlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from backtide.blackbox import redact
from backtide.jail import docker
from backtide.jail.docker import JailError
from backtide.jail.profile import SHELL_MODE, ShellCommands, check_prompt
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_export,
    ask_shell,
)

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
IMPORT_TIMEOUT = 30 * 60.0
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
    return [
        "exec", *flags, "--user", reply["user"], "--workdir", workdir or reply["workdir"],
        reply["container"],
    ]  # fmt: skip


def _interactive(argv: list[str]) -> int:
    """The docker CLI connected to this terminal (``docker exec -it``)."""
    try:
        return subprocess.call([docker.PROGRAM, *argv])
    except OSError as problem:
        error(f"no se puede ejecutar {docker.PROGRAM}: {problem}")
        return 127


# -- entrar --------------------------------------------------------------------------------------


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
    code = run([*_exec_prefix(reply, *flags), *shell.session_argv(resume=resume)])
    if code == 0:
        print("Sesión cerrada.")
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
    try:
        done = docker.run(
            [*_exec_prefix(reply), *argv],
            timeout=minutes * 60,
            check=False,
            max_output=TASK_MAX_OUTPUT,
        )
    except JailError as problem:
        error(
            f"la tarea no ha terminado bien ({problem}). Puede seguir en marcha dentro del "
            "agente: mira la caja negra."
        )
        return EXIT_PROBLEM
    return _report_task(done)


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


@dataclass
class ImportPlan:
    """What a host folder holds, read without following links."""

    dirs: list[str] = field(default_factory=list)  # relative, parents first
    files: list[tuple[str, int]] = field(default_factory=list)  # relative, size
    skipped: list[str] = field(default_factory=list)  # links and others, relative

    @property
    def bytes(self) -> int:
        return sum(size for _, size in self.files)


def plan_import(source_fd: int) -> ImportPlan:
    """Walk the folder open at ``source_fd`` (opened without following a link) and say what
    would be imported. Raises ImportRefused past the bounds."""
    plan = ImportPlan()
    stack: list[tuple[int, str, int]] = [(os.dup(source_fd), "", 0)]
    try:
        while stack:
            fd, prefix, depth = stack.pop()
            try:
                for name in sorted(os.listdir(fd)):
                    rel = f"{prefix}{name}"
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode) and depth < MAX_IMPORT_DEPTH:
                        plan.dirs.append(rel)
                        stack.append((os.open(name, _DIR_FLAGS, dir_fd=fd), f"{rel}/", depth + 1))
                    elif stat.S_ISREG(info.st_mode):
                        plan.files.append((rel, info.st_size))
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


def open_source(text: str) -> tuple[int, Path]:
    """The host folder, opened without following a link in its last component."""
    path = Path(text).expanduser()
    path = Path(os.path.abspath(path))
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
            plan = plan_import(source_fd)
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
    process = popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    failure = None
    try:
        write_tar(source_fd, plan, process.stdin)
    except (ImportRefused, OSError, tarfile.TarError) as problem:
        failure = problem
    finally:
        with contextlib.suppress(OSError):  # the docker CLI went away: its exit code says why
            process.stdin.close()
    stderr = process.stderr.read(64 * 1024) if process.stderr is not None else b""
    try:
        process.wait(timeout=IMPORT_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    if failure is not None or process.returncode != 0:
        text = stderr.decode(errors="replace") if isinstance(stderr, bytes) else str(stderr)
        why = str(failure) if failure is not None else docker.sanitize(text.strip()[-500:])
        error(f"la importación se ha quedado a medias en {target}: {why}")
        return EXIT_PROBLEM
    print(
        f"Importado {path} en {target}: {len(plan.files)} archivos y {len(plan.dirs)} carpetas "
        f"({plan.bytes} bytes)."
    )
    if plan.skipped:
        shown = ", ".join(printable(name) for name in plan.skipped[:MAX_LISTED_SKIPPED])
        more = len(plan.skipped) - MAX_LISTED_SKIPPED
        print(
            f"Sin copiar (enlaces simbólicos u otros que no son archivos ni carpetas): {shown}"
            + (f" y {more} más" if more > 0 else "")
        )
    return EXIT_OK


# -- exportar ------------------------------------------------------------------------------------


def exportar(config: ServiceConfig, destination: str) -> int:
    if shell_of(config) is None:
        return EXIT_ERROR
    path = Path(os.path.abspath(Path(destination).expanduser()))
    try:
        reply = ask_export(config.control_socket, str(path))
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
    return EXIT_OK
