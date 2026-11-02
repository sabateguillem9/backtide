"""The service runs the tasks (T26-5a, docs/47 section 7.1): one thing for `backtide tarea` and the
web's chat.

``AgentTasks`` is one agent's: each ``Guardian`` has its own, so with several agents in a process
(T26-2b) the tasks, their answers and their cap are per agent by construction.

- ``start`` gives an id at once. The record, the checks and the run are on the task's own thread:
  ``open_shell`` waits for a rewind in flight and a run lasts hours, and the socket's threads (four
  at most on the web's) never wait for either.
- A task is what `tarea` always did: recorded first (``system/agent_shell``, the prompt struck and
  cut), then ``docker exec`` of the profile's headless run as the agent, under coreutils' timeout
  inside the container (the image is Ubuntu's, whose timeout signals the run's whole process group
  and kills it KILL_AFTER seconds later), bounded, and two runs of one conversation never at once
  (M4). A CLI that goes away (Ctrl-C asks ``stop``; closing the terminal asks nothing) or a browser
  that closes does not stop it: it ends at its deadline, and its end is recorded.
- The end goes to the black box too (``system/agent_task_end``): the outcome, the code, how long it
  took and the answer's length. Never the answer, nor the tail of an error, nor docker's own message
  (which has the whole prompt in it): an answer can carry what the agent read, a secret included
  (invariant 5). So neither reaches a log either, which the log bridge records.
- The answers live in this process's memory: the last MAX_KEPT of the agent, MAX_KEPT_CHARS in all,
  and they are lost on a restart (docs/47, decision 20). Who reads them needs a session on the web's
  socket: they are not in the black box.
- A service that stops signals what runs and records its end before the black box closes
  (``close``, from ``Guardian.stop``), since stopping the agent ends the tasks anyway. A service
  that dies leaves a task without its end in the black box: its container goes at the next start
  (``_stop_unsupervised_agent``).

Stopping one task stops the agent's others that run at the same moment too: the pattern finds them
all, as it always did in `tarea` (see "Después" in docs/backlog.md).
"""

import logging
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from backtide.blackbox import redact
from backtide.jail import docker
from backtide.jail.docker import JailError
from backtide.jail.profile import TASK_BUSY, TASK_OK, TASK_TIMED_OUT, ShellCommands
from backtide.service.shell import ShellOutcome, recorded_prompt

logger = logging.getLogger(__name__)

TASK_MAX_OUTPUT = 8 * 1024 * 1024  # the JSON of one run: its answer and its counters
MAX_TASK_SECONDS = 24 * 60 * 60
TIMEOUT = "/usr/bin/timeout"
KILL_AFTER = 30
# A task program with a deadline of its own (``ShellCommands.timeout_flag``: OpenClaw's, which
# its Gateway enforces) gets it first; the timeout around it comes GRACE seconds later, as the
# backstop that kills what is left.
GRACE = 30
TIMED_OUT = 124  # timeout's code when it stopped the run; 137 when it had to kill it
KILLED = 137
PROBE_TIMEOUT = 30.0
# By their paths: never a pgrep or pkill the agent put earlier in the PATH of a docker exec.
PGREP = "/usr/bin/pgrep"
PKILL = "/usr/bin/pkill"
TAIL_CHARS = 2000
MAX_KEPT = 20  # the answers of an agent, in memory (docs/47, section 7.1)
MAX_KEPT_CHARS = 16 * 1024 * 1024  # at least a whole answer: the agent decides how long they are
# A thread and a docker exec for hours each: a chat that asks without end runs out of these first.
MAX_RUNNING = 8
STOP_TRIES = 3  # Ctrl-C just as docker exec starts: pkill finds nothing yet, so it looks again
STOP_RETRY = 0.5
CLOSE_WAIT = 5.0  # the tasks' last words at a stop: what takes longer is recorded from here
BUSY_TEXT = {
    False: "ya hay una tarea en marcha dentro del agente: espera a que termine antes de seguir la "
    "conversación con --continue",
    True: "ya hay una tarea en marcha dentro del agente, y este agente tiene una sola "
    "conversación: espera a que termine",
}
UNKNOWN_IF_BUSY = (
    "no se ha podido comprobar si hay otra tarea en marcha, así que no se sigue la conversación: "
    "inténtalo de nuevo"
)
STOPPED_INSIDE = "Se ha parado dentro del agente."
MAY_RUN_ON = "Puede seguir en marcha dentro del agente: mira la caja negra."
DOCKER_GAVE_UP = "docker falló, se pasó de tiempo o la tarea imprimió demasiado"
SERVICE_STOPPED = "El servicio de backtide se ha parado, y la tarea con él."
BUG = "Ha fallado algo inesperado en el servicio: mira su registro."


class TaskOutcome(StrEnum):
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"  # it ended with an error, or without an answer
    TIMED_OUT = "timed_out"  # past its deadline
    KILLED = "killed"  # killed: past its deadline and its grace, or a rewind stopped the agent
    BUSY = "busy"  # another run of the same conversation was going on: this one ran nothing
    REFUSED = "refused"  # the service said no (paused, not recorded): nothing was run
    CUT = "cut"  # docker gave up on it: how it ended is not known
    STOPPED = "stopped"  # asked to stop (Ctrl-C), or the service stopped


@dataclass(frozen=True)
class TaskStart:
    """An id, or (None) why not: ``message`` is for the owner, in Spanish."""

    task_id: str | None
    message: str = ""


@dataclass(frozen=True)
class TaskStatus:
    """What a task's asker sees. ``answer`` and ``message`` can carry the agent's text, unescaped:
    whoever shows them escapes them, and neither ever goes to the black box or a log."""

    task_id: str
    outcome: TaskOutcome
    message: str = ""
    answer: str | None = None
    code: int | None = None
    seconds: float | None = None


@dataclass(eq=False)
class _Task:
    id: str
    prompt: str
    resume: bool
    seconds: int | None
    requested_by: str
    started: float
    target: ShellOutcome | None = None  # once recorded: the container, by what open_shell said
    stop_asked: bool = False
    claimed: bool = False  # somebody is writing its end: only once
    status: TaskStatus | None = None  # the end, once recorded
    finished: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class AgentTasks:
    """One agent's tasks. ``commands`` gives the profile's shell commands, ``open_shell`` is
    ``Guardian.open_shell`` (the record, and whether the agent may run now) and ``record_end``
    writes the end to the black box."""

    def __init__(
        self,
        *,
        commands: Callable[[], ShellCommands | None],
        open_shell: Callable[..., ShellOutcome],
        record_end: Callable[[dict[str, Any]], None],
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._shell = commands
        self._open_shell = open_shell
        self._record_end = record_end
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._tasks: dict[str, _Task] = {}  # in the order they started
        self._ended: list[_Task] = []  # in the order they ended: the first to be forgotten
        self._closing = False

    def start(
        self,
        prompt: str,
        *,
        resume: bool = False,
        seconds: int | None = None,
        requested_by: str,
    ) -> TaskStart:
        """Take a task (its prompt already checked, ``check_prompt``): its id, at once. Whether it
        may run, and how it ended, ``status`` says."""
        task = _Task(secrets.token_hex(16), prompt, resume, seconds, requested_by, self._clock())
        task.thread = threading.Thread(
            target=self._run, args=(task,), name=f"backtide-task-{task.id[:8]}", daemon=True
        )
        with self._lock:
            if self._closing:
                return TaskStart(None, "El servicio se está parando: no se empieza ninguna tarea.")
            if sum(1 for one in self._tasks.values() if not one.claimed) >= MAX_RUNNING:
                return TaskStart(
                    None, f"Este agente ya tiene {MAX_RUNNING} tareas a la vez: espera a alguna."
                )
            self._tasks[task.id] = task
            # Under the lock: ``close`` joins what it finds in the list, so all of it has begun.
            try:
                task.thread.start()
            except RuntimeError as error:  # no more threads: this one was never a task
                del self._tasks[task.id]
                logger.error("a task could not start its thread: %s", error)
                return TaskStart(None, "El servicio no puede empezar otra tarea ahora mismo.")
        return TaskStart(task.id)

    def status(self, task_id: str) -> TaskStatus | None:
        """How the task goes; None if this service never knew it, or has forgotten it."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            return task.status or TaskStatus(task.id, TaskOutcome.RUNNING)

    def stop(self, task_id: str) -> bool | None:
        """Stop it inside the agent (Ctrl-C): True if nothing of it is left or it was signalled,
        False if it may run on, None if there is no such task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            if task.claimed:
                return True
            task.stop_asked = True
            target = task.target
        if target is None:  # not at the container yet: its thread sees ``stop_asked``
            return True
        return self._stop_inside(task, target)

    def close(self, wait: float | None = None) -> None:
        """The service stops, before the agent and the black box: signal what runs, let it finish
        for a moment (``CLOSE_WAIT``), and record the end of what has not. Idempotent."""
        with self._lock:
            self._closing = True
            running = [task for task in self._tasks.values() if not task.claimed]
            for task in running:
                task.stop_asked = True
        if not running:
            return
        target = next((task.target for task in running if task.target is not None), None)
        if target is not None:  # one TERM reaches them all: the pattern is the agent's
            self._stop_inside(running[0], target, tries=1)
        deadline = self._clock() + (CLOSE_WAIT if wait is None else wait)
        for task in running:
            if task.thread is not None:
                task.thread.join(max(0.0, deadline - self._clock()))
        for task in running:
            self._finish(task, TaskOutcome.STOPPED, SERVICE_STOPPED)

    # The task's own thread

    def _run(self, task: _Task) -> None:
        try:
            self._work(task)
        except Exception as error:
            # Its type alone: the text of an exception here could carry the prompt or the answer,
            # and the log reaches the black box.
            logger.error("task %s failed with %s", task.id[:8], type(error).__name__)
            self._finish(task, TaskOutcome.FAILED, BUG)

    def _work(self, task: _Task) -> None:
        opened = self._open_shell(
            "task",
            resume=task.resume,
            requested_by=task.requested_by,
            details={**recorded_prompt(task.prompt), "task": task.id},
        )
        if not opened.ready:
            self._finish(task, TaskOutcome.REFUSED, opened.message, recorded=False)
            return
        with self._lock:
            task.target = opened
        shell = self._shell()
        if shell is None:  # never: open_shell said yes because the profile has them
            self._finish(task, TaskOutcome.FAILED, BUG)
            return
        if (task.resume or shell.one_conversation) and self._refused_as_busy(task, shell, opened):
            return
        with self._lock:
            stop_asked = task.stop_asked
        if stop_asked:
            self._finish(task, TaskOutcome.STOPPED)
            return
        seconds = task.seconds if task.seconds is not None else shell.default_minutes * 60
        limit = seconds + (GRACE if shell.timeout_flag else 0)
        argv = shell.task_argv(task.prompt, resume=task.resume, seconds=seconds)
        try:
            done = docker.run(
                [*_exec_prefix(opened), TIMEOUT, "-k", str(KILL_AFTER), str(limit), *argv],
                timeout=limit + KILL_AFTER + 30,
                check=False,
                max_output=TASK_MAX_OUTPUT,
            )
        except JailError:
            # Never its text: it has the whole command, and the prompt with it.
            logger.warning("task %s: its docker exec failed or took too long", task.id[:8])
            stopped = self._stop_inside(task, opened)
            self._finish(
                task,
                TaskOutcome.CUT,
                f"la tarea no ha terminado bien ({DOCKER_GAVE_UP}). "
                + (STOPPED_INSIDE if stopped else MAY_RUN_ON),
            )
            return
        self._finish_run(task, done.returncode, done.stdout, done.stderr, shell, seconds)

    def _refused_as_busy(self, task: _Task, shell: ShellCommands, opened: ShellOutcome) -> bool:
        """Two runs of one conversation never go at once (M4). The list here first: an earlier task
        that has not reached the container yet is one too, and ``pgrep`` would not see it."""
        with self._lock:
            earlier = False
            for other in self._tasks.values():
                if other is task:
                    break
                earlier = earlier or not other.claimed
        running = True if earlier else _task_running(opened, task_pattern(shell))
        if running is False:
            return False
        said = BUSY_TEXT[shell.one_conversation] if running else UNKNOWN_IF_BUSY
        self._finish(task, TaskOutcome.BUSY, said)
        return True

    def _finish_run(
        self,
        task: _Task,
        code: int,
        stdout: str,
        stderr: str,
        shell: ShellCommands,
        seconds: int,
    ) -> None:
        """How the run ended, as the profile reads it (``shell.answer``)."""
        with self._lock:
            stop_asked = task.stop_asked
        if stop_asked:  # whatever code its TERM comes back with, it says nothing of a deadline
            self._finish(task, TaskOutcome.STOPPED, STOPPED_INSIDE, code=code)
        elif code == TIMED_OUT:
            self._finish(task, TaskOutcome.TIMED_OUT, _timed_out(seconds), code=code)
        elif code == KILLED:
            said = "la tarea se ha cortado (se pasó del tiempo, o un rebobinado la paró)"
            self._finish(task, TaskOutcome.KILLED, said, code=code)
        else:
            self._finish_answer(task, code, stdout, stderr, shell, seconds)

    def _finish_answer(
        self,
        task: _Task,
        code: int,
        stdout: str,
        stderr: str,
        shell: ShellCommands,
        seconds: int,
    ) -> None:
        answer = shell.answer(stdout)
        if answer is None:
            tail = (stderr or stdout).strip()[-TAIL_CHARS:]
            said = f"la tarea ha terminado con el código {code} y sin respuesta: {tail}"
            self._finish(task, TaskOutcome.FAILED, redact(said), code=code)
        elif answer.outcome == TASK_TIMED_OUT:
            said = _timed_out(seconds)
            self._finish(task, TaskOutcome.TIMED_OUT, said, answer.text, code)
        elif answer.outcome == TASK_BUSY:
            self._finish(task, TaskOutcome.BUSY, BUSY_TEXT[True], answer.text, code)
        elif code != 0 or answer.outcome != TASK_OK:
            said = f"la tarea ha terminado con un error (código {code})"
            self._finish(task, TaskOutcome.FAILED, said, answer.text, code)
        else:
            self._finish(task, TaskOutcome.OK, "", answer.text, code)

    def _stop_inside(self, task: _Task, opened: ShellOutcome, *, tries: int = STOP_TRIES) -> bool:
        """A task this side gave up on is stopped inside: a TERM to its timeout, which passes it to
        the task program (OpenClaw then asks its Gateway to abort the turn) and kills it
        ``KILL_AFTER`` seconds later. True if nothing of it is left running, or it was signalled.
        What the agent itself started and detached from the task is not this: the snapshots and
        the gate are."""
        shell = self._shell()
        if shell is None:
            return False
        for attempt in range(tries):
            code = _signal_task(opened, task_pattern(shell))
            if code != 1:  # 0: found and signalled; else pkill or docker failed
                return code == 0
            if task.finished.is_set() or attempt + 1 == tries:
                break
            self._sleep(STOP_RETRY)
        return True

    def _finish(
        self,
        task: _Task,
        outcome: TaskOutcome,
        message: str = "",
        answer: str | None = None,
        code: int | None = None,
        *,
        recorded: bool = True,
    ) -> None:
        """The end, once: first the black box, and only then what the asker can read, so a CLI that
        printed an answer finds its end recorded. Never raises."""
        with self._lock:
            if task.claimed:
                return
            task.claimed = True
        took = round(self._clock() - task.started, 1)
        if recorded:
            try:
                self._record_end(
                    {
                        "task": task.id,
                        "outcome": str(outcome),
                        "code": code,
                        "seconds": took,
                        "answer_chars": len(answer or ""),
                        "requested_by": task.requested_by,
                    }
                )
            except Exception as error:
                logger.error(
                    "task %s: its end could not be recorded: %s", task.id[:8], type(error).__name__
                )
        with self._lock:
            task.status = TaskStatus(task.id, outcome, message, answer, code, took)
            task.prompt = ""
            self._ended.append(task)
            self._forget_the_oldest()
        task.finished.set()

    def _forget_the_oldest(self) -> None:
        """At most the last MAX_KEPT that ended, and MAX_KEPT_CHARS of them: the one that has just
        ended always stays, whenever it began, and a task that runs never goes. With the lock."""
        held = sum(_chars_of(task) for task in self._ended)
        while len(self._ended) > 1 and (len(self._ended) > MAX_KEPT or held > MAX_KEPT_CHARS):
            oldest = self._ended.pop(0)
            held -= _chars_of(oldest)
            del self._tasks[oldest.id]


def _chars_of(task: _Task) -> int:
    status = task.status
    return 0 if status is None else len(status.answer or "") + len(status.message)


def _timed_out(seconds: int) -> str:
    return f"la tarea se ha cortado: pasó de {seconds / 60:g} minutos (--minutos)"


def _exec_prefix(opened: ShellOutcome) -> list[str]:
    """``docker exec`` as the agent, in its folder, into the container the service started and
    checked: by its full id, never by a name another container could have taken (B4)."""
    return ["exec", "--user", opened.user, "--workdir", opened.workdir, opened.container_id]


def task_pattern(shell: ShellCommands) -> str:
    """What ``pgrep -f`` finds of a task (M4): the timeout around the profile's whole task
    program, as it is started here (OpenClaw's: ``.../openclaw.mjs agent --agent main --json``).
    An extended regex with every special character literal. With ``-P 0`` (see _task_running)
    it only finds what a docker exec started: the agent can write the same command line, but
    what it starts has a parent in its container (its own orphans go to the container's init,
    the only other process without one, which the jail chooses)."""
    program = " ".join(_literal(arg) for arg in shell.task)
    return f"^{_literal(TIMEOUT)} -k {KILL_AFTER} [0-9]+ {program}( |$)"


def _literal(text: str) -> str:
    """``text`` as a POSIX extended regex that matches only itself."""
    return "".join(f"[{c}]" if c in ".[]()*+?{}|$" else f"\\{c}" if c in "\\^" else c for c in text)


def _task_running(opened: ShellOutcome, pattern: str) -> bool | None:
    """Whether a task runs now inside the agent (``pgrep`` as the agent), or None if that
    cannot be said."""
    uid = opened.user.split(":")[0]
    try:
        found = docker.run(
            [*_exec_prefix(opened), PGREP, "-P", "0", "-u", uid, "-f", pattern],
            check=False,
            timeout=PROBE_TIMEOUT,
        )
    except JailError:
        return None
    if found.returncode == 1 and found.stderr.strip():
        return None  # docker's own 1 (a paused container): pgrep finding nothing says nothing
    return {0: True, 1: False}.get(found.returncode)


def _signal_task(opened: ShellOutcome, pattern: str) -> int:
    """``pkill``'s code, as the agent: 0 found and signalled, 1 nothing found, -1 no answer. A
    1 with something on stderr is docker's, not pkill's (a paused container refuses the exec):
    the task is still there, frozen, and goes on when the agent is resumed."""
    uid = opened.user.split(":")[0]
    try:
        done = docker.run(
            [*_exec_prefix(opened), PKILL, "-TERM", "-P", "0", "-u", uid, "-f", pattern],
            check=False,
            timeout=PROBE_TIMEOUT,
        )
    except JailError:
        return -1
    return -1 if done.returncode == 1 and done.stderr.strip() else done.returncode
