"""T26-5a (docs/47, section 7.1): the service runs the tasks, for the CLI and for the web.

``AgentTasks`` with a double of the container (``docker.run``): what it runs, one conversation at
a time, the deadline, a run that goes wrong, stopping it, a service that stops halfway, what the
black box gets (never the answer) and what stays in memory (the last 20, per agent).
"""

import json
import re
import subprocess
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from backtide.jail import docker
from backtide.jail.profile import ShellCommands
from backtide.jail.profiles import CLAUDE_CODE, OPENCLAW
from backtide.jail.profiles.claude_code import CLAUDE
from backtide.service import tasks as tasks_module
from backtide.service.shell import ShellOutcome, ShellStatus
from backtide.service.tasks import (
    ASKED_CHARS,
    GRACE,
    MAX_KEPT,
    MAX_KEPT_CHARS,
    MAX_RUNNING,
    PKILL,
    TASK_MAX_OUTPUT,
    AgentTasks,
    TaskOutcome,
    task_pattern,
)

CONTAINER_ID = "ab12" * 16
READY = ShellOutcome(
    ShellStatus.READY, "", "backtide-agente", "61000:61000", "/workspace/work", CONTAINER_ID
)
# By the id of the container the service checked, never by its name (B4).
PREFIX = ["exec", "--user", "61000:61000", "--workdir", "/workspace/work", CONTAINER_ID]
TIMEOUT = ["/usr/bin/timeout", "-k", "30"]
SETTINGS = ["--dangerously-skip-permissions", "--settings", "/config/claude.json"]
OPENCLAW_TURN = [
    "/usr/local/bin/node", "/app/openclaw.mjs", "agent", "--agent", "main", "--json",
]  # fmt: skip
NOT_FOUND = subprocess.CompletedProcess([], 1, "", "")  # pgrep and pkill: nothing matched
FOUND = subprocess.CompletedProcess([], 0, "", "")
BROKEN = subprocess.CompletedProcess([], 2, "", "")
PAUSED = subprocess.CompletedProcess(
    [], 1, "", "Error response from daemon: Container ab12 is paused, unpause it first\n"
)
SECRET_ANSWER = "la clave era sk-ant-api03-" + "A1b2C3d4" * 8
WAIT = 10.0


def answer(result: str, *, error: bool = False, code: int = 0) -> subprocess.CompletedProcess[str]:
    body = json.dumps({"type": "result", "is_error": error, "result": result})
    return subprocess.CompletedProcess([], code, body, "")


def turn(text: str, status: str = "ok", code: int = 0) -> subprocess.CompletedProcess[str]:
    body = {"runId": "r1", "status": status, "result": {"payloads": [{"text": text}]}}
    return subprocess.CompletedProcess([], code, json.dumps(body, indent=2), "")


class Container:
    """A double of ``docker.run``: answers in turn from ``results``. An exception in the list is
    raised; an ``Event`` in it holds the call until it is set, then takes the next result."""

    def __init__(self) -> None:
        self.runs: list[tuple[list[str], dict[str, Any]]] = []
        self.results: list[Any] = []
        self.entered = threading.Semaphore(0)  # a hold in ``results`` was reached

    def run(self, args: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        self.runs.append((list(args), options))
        result = self.results.pop(0) if self.results else NOT_FOUND
        while isinstance(result, threading.Event):
            self.entered.release()
            assert result.wait(WAIT), "the test never let the run go"
            result = self.results.pop(0) if self.results else NOT_FOUND
        if isinstance(result, BaseException):
            raise result
        return result

    def tasks(self) -> list[list[str]]:
        return [args for args, _ in self.runs if TIMEOUT[0] in args]


class Lab:
    """One agent's ``AgentTasks`` with a double of the container, of ``open_shell`` and of the
    black box."""

    def __init__(self, container: Container, shell: ShellCommands | None) -> None:
        self.container = container
        self.shell = shell
        self.outcome = READY
        self.opened: list[dict[str, Any]] = []
        self.ended: list[dict[str, Any]] = []
        self.gate: threading.Event | None = None
        self.tasks = AgentTasks(
            commands=lambda: self.shell,
            open_shell=self.open_shell,
            record_end=self.ended.append,
            sleep=lambda _: None,
        )

    def open_shell(self, kind: str, **options: Any) -> ShellOutcome:
        self.opened.append({"kind": kind, **options})
        if self.gate is not None:
            assert self.gate.wait(WAIT)
        return self.outcome

    def run(self, prompt: str = "hola", **options: Any) -> Any:
        """A task from start to end: what ``status`` then says."""
        return self.settled(self.start(prompt, **options))

    def start(self, prompt: str = "hola", **options: Any) -> str:
        options.setdefault("requested_by", "cli (uid 0, pid 1)")
        started = self.tasks.start(prompt, **options)
        assert started.task_id is not None, started.message
        return started.task_id

    def settled(self, task_id: str) -> Any:
        assert self.tasks._tasks[task_id].finished.wait(WAIT)  # noqa: SLF001
        return self.tasks.status(task_id)


@pytest.fixture
def container(monkeypatch: pytest.MonkeyPatch) -> Container:
    made = Container()
    monkeypatch.setattr(docker, "run", made.run)
    return made


@pytest.fixture
def lab(container: Container) -> Iterator[Lab]:
    made = Lab(container, CLAUDE_CODE.shell)
    yield made
    made.tasks.close(wait=0.5)


@pytest.fixture
def claw(container: Container) -> Iterator[Lab]:
    made = Lab(container, OPENCLAW.shell)
    yield made
    made.tasks.close(wait=0.5)


# --- what it runs -------------------------------------------------------------------------------


def test_a_task_runs_claude_p_with_the_prompt_after_dashes(lab: Lab) -> None:
    lab.container.results = [NOT_FOUND, answer("listo\nhecho \x1b[2J")]
    status = lab.run("-rf todo", resume=True)
    assert status.outcome is TaskOutcome.OK and status.answer == "listo\nhecho \x1b[2J"
    (probe, _), (argv, options) = lab.container.runs  # --continue: pgrep finds no other task
    assert probe[: len(PREFIX)] == PREFIX and probe[len(PREFIX) : -1] == [
        "/usr/bin/pgrep", "-P", "0", "-u", "61000", "-f",
    ]  # fmt: skip
    assert argv == [*PREFIX, *TIMEOUT, "3600", CLAUDE, "-p", "--output-format", "json",
                    *SETTINGS, "--continue", "--", "-rf todo"]  # fmt: skip
    assert options["timeout"] > 3600 + 30 and options["max_output"] == TASK_MAX_OUTPUT
    assert options["check"] is False


def test_the_seconds_asked_are_the_deadline(lab: Lab) -> None:
    lab.container.results = [answer("ok")]
    assert lab.run("haz x", seconds=120).outcome is TaskOutcome.OK
    assert lab.container.tasks()[0][len(PREFIX) : len(PREFIX) + 4] == [*TIMEOUT, "120"]


def test_openclaw_is_one_turn_through_its_gateway(claw: Lab) -> None:
    """Argv only, the prompt glued to --message, its own deadline and the timeout around it.
    Its one conversation is checked first: no other task of it runs (M4)."""
    claw.container.results = [NOT_FOUND, turn("hecho\n\x1b]0;evil\x07 ok")]
    status = claw.run("-rf todo; $(rm x)", seconds=120)
    assert status.outcome is TaskOutcome.OK
    (probe, _), (argv, options) = claw.container.runs
    assert probe[len(PREFIX) : len(PREFIX) + 3] == ["/usr/bin/pgrep", "-P", "0"]
    assert probe[-1] == task_pattern(OPENCLAW.shell)
    # Its own deadline first (the Gateway stops the turn there), the timeout around it after.
    assert argv == [*PREFIX, *TIMEOUT, "150", *OPENCLAW_TURN, "--timeout=120",
                    "--message=-rf todo; $(rm x)"]  # fmt: skip
    assert options["max_output"] == TASK_MAX_OUTPUT and options["timeout"] > 150 + 30


def test_the_default_deadline_is_the_profiles(claw: Lab, lab: Lab) -> None:
    claw.container.results = [NOT_FOUND, turn("ok")]
    claw.run()
    assert claw.container.tasks()[0][len(PREFIX) + 3] == str(15 * 60 + GRACE)
    assert "--timeout=900" in claw.container.tasks()[0]
    claw.container.results = [answer("ok")]
    lab.run()  # Claude Code: 60 minutes (the double is shared: the last task is its own)
    assert lab.container.tasks()[-1][len(PREFIX) + 3] == "3600"


# --- the record ---------------------------------------------------------------------------------


def test_the_start_is_recorded_first_struck_and_cut_with_the_tasks_id(lab: Lab) -> None:
    """The black box gets what `tarea` always recorded (``recorded_prompt``), before the run:
    the open comes first and carries the id that ties it to the end."""
    secret = "sk-ant-api03-" + "A1b2C3d4" * 8
    prompt = f"usa la clave {secret} y " + "x" * 400
    lab.container.results = [answer("ok")]
    task_id = lab.start(prompt, requested_by="web (uid 5, pid 6)")
    lab.settled(task_id)
    (opened,) = lab.opened
    assert opened["kind"] == "task" and opened["resume"] is False
    assert opened["requested_by"] == "web (uid 5, pid 6)"
    details = opened["details"]
    assert secret not in details["prompt"] and secret[:20] not in details["prompt"]
    assert details["prompt"].startswith("usa la clave ") and len(details["prompt"]) == 200
    assert details["slash"] is False and details["task"] == task_id


def test_nothing_runs_when_the_service_says_no(lab: Lab) -> None:
    """Stopped, paused, or a black box that cannot record: no docker, no end to record."""
    lab.outcome = ShellOutcome(ShellStatus.NOT_RUNNING, "El agente está en pausa.")
    status = lab.run()
    assert status.outcome is TaskOutcome.REFUSED and status.message == "El agente está en pausa."
    assert lab.container.runs == [] and lab.ended == []


def test_the_end_goes_to_the_black_box_without_the_answer(
    lab: Lab, caplog: pytest.LogCaptureFixture
) -> None:
    """Code, duration and the answer's length (invariant 5): the answer, its error's tail and the
    message stay out."""
    lab.container.results = [answer(SECRET_ANSWER)]
    task_id = lab.start(requested_by="cli (uid 0, pid 1)")
    status = lab.settled(task_id)
    assert status.answer == SECRET_ANSWER
    (ended,) = lab.ended
    assert set(ended) == {"task", "outcome", "code", "seconds", "answer_chars", "requested_by"}
    assert ended["task"] == task_id and ended["outcome"] == "ok" and ended["code"] == 0
    assert ended["answer_chars"] == len(SECRET_ANSWER) and ended["seconds"] >= 0
    assert ended["requested_by"] == "cli (uid 0, pid 1)"
    assert "sk-ant" not in json.dumps(ended)
    assert "sk-ant" not in caplog.text  # the log reaches the black box too


def test_the_end_is_recorded_before_anyone_can_read_it(lab: Lab) -> None:
    """A CLI that printed the answer finds the end in the black box."""
    seen: list[TaskOutcome] = []
    lab.tasks._record_end = lambda details: seen.append(  # noqa: SLF001
        lab.tasks.status(details["task"]).outcome
    )
    lab.container.results = [answer("ok")]
    assert lab.run().outcome is TaskOutcome.OK
    assert seen == [TaskOutcome.RUNNING]


def test_an_error_tail_never_reaches_the_black_box_nor_the_log(
    lab: Lab, caplog: pytest.LogCaptureFixture
) -> None:
    lab.container.results = [subprocess.CompletedProcess([], 1, "", "MARCA-DEL-AGENTE boom")]
    status = lab.run()
    assert status.outcome is TaskOutcome.FAILED and "MARCA-DEL-AGENTE" in status.message
    assert "MARCA-DEL-AGENTE" not in json.dumps(lab.ended)
    assert "MARCA-DEL-AGENTE" not in caplog.text


def test_a_black_box_that_fails_at_the_end_does_not_lose_the_answer(lab: Lab) -> None:
    def failing(details: dict[str, Any]) -> None:
        raise RuntimeError("no se puede grabar")

    lab.tasks._record_end = failing  # noqa: SLF001
    lab.container.results = [answer("ok")]
    assert lab.run().answer == "ok"


# --- how a run ends -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result",
    [
        answer("falló", error=True),
        answer("ok", code=1),
        subprocess.CompletedProcess([], 1, "not json", "boom"),
        subprocess.CompletedProcess([], 0, "[]", ""),
    ],
)
def test_a_task_that_went_wrong_fails(lab: Lab, result: subprocess.CompletedProcess[str]) -> None:
    lab.container.results = [result]
    assert lab.run().outcome is TaskOutcome.FAILED


def test_a_failed_run_keeps_what_it_answered(lab: Lab) -> None:
    lab.container.results = [answer("a medias", error=True, code=1)]
    status = lab.run()
    assert status.answer == "a medias" and status.code == 1
    assert "terminado con un error (código 1)" in status.message


@pytest.mark.parametrize(
    ("code", "outcome", "said"),
    [
        (124, TaskOutcome.TIMED_OUT, "pasó de 60 minutos"),
        (137, TaskOutcome.KILLED, "se ha cortado"),
    ],
)
def test_a_task_cut_by_its_timeout_says_so(
    lab: Lab, code: int, outcome: TaskOutcome, said: str
) -> None:
    lab.container.results = [subprocess.CompletedProcess([], code, "", "")]
    status = lab.run()
    assert status.outcome is outcome and said in status.message and status.code == code


@pytest.mark.parametrize(
    ("result", "outcome", "said"),
    [
        (turn("", "timeout", 1), TaskOutcome.TIMED_OUT, "pasó de 15 minutos"),
        (turn("", "in_flight", 0), TaskOutcome.BUSY, "una sola conversación"),
        (turn("a medias", "error", 1), TaskOutcome.FAILED, "terminado con un error"),
        (turn("ok", "ok", 1), TaskOutcome.FAILED, "terminado con un error"),
        (subprocess.CompletedProcess([], 1, "", "gateway closed"), TaskOutcome.FAILED,
         "sin respuesta"),
    ],
)  # fmt: skip
def test_an_openclaw_turn_that_went_wrong(
    claw: Lab, result: subprocess.CompletedProcess[str], outcome: TaskOutcome, said: str
) -> None:
    claw.container.results = [NOT_FOUND, result]
    status = claw.run()
    assert status.outcome is outcome and said in status.message


def test_a_secret_in_an_error_tail_is_struck(lab: Lab) -> None:
    lab.container.results = [subprocess.CompletedProcess([], 1, "", SECRET_ANSWER)]
    assert "sk-ant" not in lab.run().message


def test_something_unexpected_is_a_failure_that_says_nothing_of_it(
    lab: Lab, caplog: pytest.LogCaptureFixture
) -> None:
    """A bug on this path ends the task and is logged, without the text it carries (the log
    reaches the black box)."""
    lab.container.results = [RuntimeError("MARCA-DEL-AGENTE")]
    status = lab.run()
    assert status.outcome is TaskOutcome.FAILED
    assert "MARCA-DEL-AGENTE" not in status.message and "MARCA-DEL-AGENTE" not in caplog.text
    assert "RuntimeError" in caplog.text
    assert lab.ended[0]["outcome"] == "failed"


# --- a run this side gave up on -----------------------------------------------------------------


def test_a_run_docker_gave_up_on_is_stopped_inside(lab: Lab) -> None:
    """M4: the docker CLI timed out (or broke), so the task may run on: a TERM to its timeout,
    as the agent, by the pattern of the task, and the outcome is unknown. The message does not
    carry docker's own text, which has the whole prompt in it."""
    lab.container.results = [docker.JailError("docker exec ... MARCA-DEL-PROMPT timed out"), FOUND]
    status = lab.run("MARCA-DEL-PROMPT")
    assert status.outcome is TaskOutcome.CUT and "Se ha parado dentro del agente" in status.message
    assert "MARCA-DEL-PROMPT" not in status.message
    assert lab.container.runs[-1][0] == [
        *PREFIX, PKILL, "-TERM", "-P", "0", "-u", "61000", "-f", task_pattern(CLAUDE_CODE.shell),
    ]  # fmt: skip


def test_a_stop_that_fails_says_it_may_run_on(lab: Lab) -> None:
    lab.container.results = [docker.JailError("timed out"), BROKEN]
    assert "Puede seguir en marcha" in lab.run().message


def test_a_stop_that_cannot_reach_docker_says_it_may_run_on(lab: Lab) -> None:
    lab.container.results = [docker.JailError("timed out"), docker.JailError("no docker")]
    status = lab.run()
    assert status.outcome is TaskOutcome.CUT and "Puede seguir en marcha" in status.message


# --- one conversation at a time ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pgrep", "said"), [(FOUND, "tarea en marcha"), (BROKEN, "no se ha podido comprobar")]
)
def test_a_second_continue_waits_for_the_first(
    lab: Lab, pgrep: subprocess.CompletedProcess[str], said: str
) -> None:
    """M4: with a task running inside (pgrep finds it), or when that cannot be said, --continue
    does not start a second run of the same conversation. It is recorded all the same."""
    lab.container.results = [pgrep]
    status = lab.run("sigue", resume=True)
    assert status.outcome is TaskOutcome.BUSY and said in status.message
    assert len(lab.container.runs) == 1 and lab.container.tasks() == []
    assert len(lab.opened) == 1 and lab.ended[0]["outcome"] == "busy"


def test_a_paused_agent_cannot_say_no_task_runs(lab: Lab) -> None:
    lab.container.results = [PAUSED]
    status = lab.run("sigue", resume=True)
    assert status.outcome is TaskOutcome.BUSY and "no se ha podido comprobar" in status.message
    assert lab.container.tasks() == []


def test_a_probe_that_cannot_reach_docker_runs_nothing(lab: Lab) -> None:
    lab.container.results = [docker.JailError("no docker")]
    assert lab.run("sigue", resume=True).outcome is TaskOutcome.BUSY
    assert lab.container.tasks() == []


def test_a_new_conversation_does_not_wait(lab: Lab) -> None:
    lab.container.results = [answer("ok")]
    assert lab.run("otra").outcome is TaskOutcome.OK
    assert len(lab.container.runs) == 1  # no pgrep: only --continue shares a conversation


@pytest.mark.parametrize(
    ("pgrep", "said"), [(FOUND, "una sola conversación"), (BROKEN, "no se ha podido comprobar")]
)
def test_a_second_openclaw_task_waits_for_the_first(
    claw: Lab, pgrep: subprocess.CompletedProcess[str], said: str
) -> None:
    """Its one conversation is shared by every task: even without --continue."""
    claw.container.results = [pgrep]
    status = claw.run("otra")
    assert status.outcome is TaskOutcome.BUSY and said in status.message
    assert claw.container.tasks() == []


def test_two_at_once_cannot_both_slip_through_the_check(claw: Lab) -> None:
    """A second task that asks while the first has not reached the container yet: pgrep would
    find nothing, so the service's own list says no. The first goes on."""
    hold = threading.Event()
    claw.container.results = [hold, NOT_FOUND, turn("ok")]  # the first waits in its pgrep
    first = claw.start("uno")
    assert claw.container.entered.acquire(timeout=WAIT)
    second = claw.settled(claw.start("dos"))
    assert second.outcome is TaskOutcome.BUSY and "una sola conversación" in second.message
    hold.set()
    assert claw.settled(first).outcome is TaskOutcome.OK
    assert len(claw.container.tasks()) == 1


def test_the_running_tasks_of_an_agent_have_a_cap(lab: Lab) -> None:
    """Each is a thread and a docker exec for hours: a web asking without end runs out of them
    long before the machine does."""
    hold = threading.Event()
    lab.container.results = [hold] * MAX_RUNNING + [answer("ok")] * MAX_RUNNING
    running = [lab.start(f"t{n}") for n in range(MAX_RUNNING)]
    refused = lab.tasks.start("una más", requested_by="web")
    assert refused.task_id is None and "a la vez" in refused.message
    assert len(lab.opened) <= MAX_RUNNING
    hold.set()
    assert all(lab.settled(task).outcome is TaskOutcome.OK for task in running)
    assert lab.tasks.start("ahora sí", requested_by="web").task_id is not None


def test_a_thread_that_cannot_start_leaves_no_task_behind(
    lab: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_more(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", no_more)
    refused = lab.tasks.start("hola", requested_by="cli")
    assert refused.task_id is None and "otra tarea" in refused.message
    monkeypatch.undo()
    assert lab.tasks._tasks == {}  # noqa: SLF001


# --- it never makes anyone wait -----------------------------------------------------------------


def test_starting_never_waits_for_the_task_nor_for_a_rewind(lab: Lab) -> None:
    """The socket's thread gets an id at once: the record (``open_shell`` waits for a rewind in
    flight) and the run are on the task's own thread."""
    lab.gate = threading.Event()
    lab.container.results = [answer("ok")]
    task_id = lab.start()
    assert lab.tasks.status(task_id).outcome is TaskOutcome.RUNNING
    lab.gate.set()
    assert lab.settled(task_id).outcome is TaskOutcome.OK


def test_a_long_task_says_it_is_running(lab: Lab) -> None:
    hold = threading.Event()
    lab.container.results = [hold, answer("ya")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    status = lab.tasks.status(task_id)
    assert status.outcome is TaskOutcome.RUNNING and status.answer is None and status.code is None
    hold.set()
    assert lab.settled(task_id).answer == "ya"


# --- stopping it (Ctrl-C in the CLI) ------------------------------------------------------------


def test_stopping_signals_the_task_inside(lab: Lab) -> None:
    hold = threading.Event()
    lab.container.results = [hold, FOUND, subprocess.CompletedProcess([], 124, "", "")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id) is True
    assert PKILL in lab.container.runs[-1][0]
    hold.set()
    status = lab.settled(task_id)  # its TERM comes back as 124: not a deadline, a stop
    assert status.outcome is TaskOutcome.STOPPED and lab.ended[0]["outcome"] == "stopped"


def test_a_stop_that_fails_is_said(lab: Lab) -> None:
    hold = threading.Event()
    lab.container.results = [hold, BROKEN, answer("ok")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id) is False
    hold.set()
    lab.settled(task_id)


def test_a_paused_agent_is_not_a_task_that_has_gone(lab: Lab) -> None:
    """Docker refuses an exec into a paused container with the same 1 as a pkill that found
    nothing. The task is frozen and goes on at `backtide seguir`, so nobody may say it stopped."""
    hold = threading.Event()
    lab.container.results = [hold, PAUSED, answer("ok")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id) is False
    assert len([args for args, _ in lab.container.runs if PKILL in args]) == 1
    hold.set()
    lab.settled(task_id)


def test_a_run_docker_gave_up_on_in_a_paused_agent_may_run_on(lab: Lab) -> None:
    lab.container.results = [docker.JailError("timed out"), PAUSED]
    status = lab.run()
    assert status.outcome is TaskOutcome.CUT and "Puede seguir en marcha" in status.message


def test_a_stop_looks_again_for_a_task_about_to_appear(lab: Lab) -> None:
    """Ctrl-C just as docker exec starts: pkill finds nothing yet; it looks again, or the CLI
    would say it stopped a task that goes on."""
    hold = threading.Event()
    lab.container.results = [hold, NOT_FOUND, FOUND, answer("ok")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id) is True
    assert len([args for args, _ in lab.container.runs if PKILL in args]) == 2
    hold.set()
    lab.settled(task_id)


def test_a_task_stopped_before_it_reached_the_container_never_runs(lab: Lab) -> None:
    lab.gate = threading.Event()
    task_id = lab.start()
    assert lab.tasks.stop(task_id) is True
    lab.gate.set()
    assert lab.settled(task_id).outcome is TaskOutcome.STOPPED
    assert lab.container.tasks() == []


def test_a_stop_from_the_web_is_named_in_the_end(lab: Lab) -> None:
    """T26-5b. Ctrl-C's end keeps the fields it always had: see the end's own test."""
    hold = threading.Event()
    lab.container.results = [hold, FOUND, subprocess.CompletedProcess([], 143, "", "")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id, requested_by="web (uid 5, pid 6)") is True
    hold.set()
    assert lab.settled(task_id).outcome is TaskOutcome.STOPPED
    assert lab.ended[0]["stopped_by"] == "web (uid 5, pid 6)"


def test_a_ctrl_c_after_the_webs_stop_does_not_take_its_name_out(lab: Lab) -> None:
    hold = threading.Event()
    lab.container.results = [hold, FOUND, FOUND, subprocess.CompletedProcess([], 143, "", "")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id, requested_by="web (uid 5, pid 6)") is True
    assert lab.tasks.stop(task_id) is True
    hold.set()
    lab.settled(task_id)
    assert lab.ended[0]["stopped_by"] == "web (uid 5, pid 6)"


def test_stopping_from_the_cli_adds_nothing_to_the_end(lab: Lab) -> None:
    hold = threading.Event()
    lab.container.results = [hold, FOUND, subprocess.CompletedProcess([], 143, "", "")]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    assert lab.tasks.stop(task_id) is True
    hold.set()
    lab.settled(task_id)
    assert "stopped_by" not in lab.ended[0]


def test_stopping_what_ended_or_never_was(lab: Lab) -> None:
    lab.container.results = [answer("ok")]
    done = lab.start()
    lab.settled(done)
    runs = len(lab.container.runs)
    assert lab.tasks.stop(done) is True and len(lab.container.runs) == runs
    assert lab.tasks.stop("f" * 32) is None


# --- a service that stops halfway ---------------------------------------------------------------


def test_closing_stops_what_runs_and_records_its_end(lab: Lab) -> None:
    """The black box closes right after: each task's end goes in first."""
    hold = threading.Event()
    lab.container.results = [hold, FOUND]
    task_id = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    lab.tasks.close(wait=0.05)
    assert PKILL in lab.container.runs[-1][0]
    status = lab.tasks.status(task_id)
    assert status.outcome is TaskOutcome.STOPPED and "servicio" in status.message
    assert [e["outcome"] for e in lab.ended] == ["stopped"]
    hold.set()  # the run comes back late: its end is not written twice
    lab.tasks._tasks[task_id].thread.join(WAIT)  # noqa: SLF001
    assert len(lab.ended) == 1


def test_no_task_starts_once_closing(lab: Lab) -> None:
    lab.tasks.close(wait=0.05)
    refused = lab.tasks.start("tarde", requested_by="cli")
    assert refused.task_id is None and "parando" in refused.message
    assert lab.opened == []


def test_closing_with_nothing_running_touches_nothing(lab: Lab) -> None:
    lab.tasks.close(wait=0.05)
    lab.tasks.close(wait=0.05)
    assert lab.container.runs == []


def test_a_restart_forgets_the_answers(container: Container) -> None:
    """Only in memory: a new service (a new AgentTasks) knows nothing of the id."""
    first = Lab(container, CLAUDE_CODE.shell)
    container.results = [answer(SECRET_ANSWER)]
    task_id = first.start()
    first.settled(task_id)
    first.tasks.close(wait=0.05)
    assert Lab(container, CLAUDE_CODE.shell).tasks.status(task_id) is None


# --- what stays in memory -----------------------------------------------------------------------


def test_the_last_twenty_stay_and_the_older_go(lab: Lab) -> None:
    ids = []
    for n in range(MAX_KEPT + 3):
        lab.container.results = [answer(f"respuesta {n}")]
        ids.append(lab.start())
        lab.settled(ids[-1])
    assert [lab.tasks.status(old) for old in ids[:3]] == [None] * 3
    assert lab.tasks.status(ids[3]).answer == "respuesta 3"
    assert lab.tasks.status(ids[-1]).answer == f"respuesta {MAX_KEPT + 2}"


def test_a_task_running_is_never_forgotten(lab: Lab) -> None:
    """And when it ends, the oldest that began, its answer is the newest: its asker gets it."""
    hold = threading.Event()
    lab.container.results = [hold]
    long_one = lab.start()
    assert lab.container.entered.acquire(timeout=WAIT)
    for _ in range(MAX_KEPT + 3):
        lab.container.results = [answer("corta")]
        lab.settled(lab.start())
    assert lab.tasks.status(long_one).outcome is TaskOutcome.RUNNING
    lab.container.results = [answer("la larga")]
    hold.set()
    assert lab.settled(long_one).answer == "la larga"


def test_what_is_kept_has_a_cap_in_size(monkeypatch: pytest.MonkeyPatch, lab: Lab) -> None:
    """20 answers of 8 MiB, which the agent decides, are not 160 MiB of the service's memory.
    The oldest go first, and the newest always stays."""
    monkeypatch.setattr(tasks_module, "MAX_KEPT_CHARS", 1000)
    assert MAX_KEPT_CHARS > TASK_MAX_OUTPUT  # the real cap holds at least one whole answer
    lab.container.results = [answer("a" * 600)]
    old = lab.start()
    lab.settled(old)
    lab.container.results = [answer("b" * 600)]
    new = lab.start()
    lab.settled(new)
    assert lab.tasks.status(old) is None and lab.tasks.status(new).answer == "b" * 600
    lab.container.results = [answer("c" * 2000)]
    bigger = lab.start()
    assert lab.settled(bigger).answer == "c" * 2000
    assert lab.tasks.status(new) is None


def test_what_brought_no_answer_goes_before_any_answer(lab: Lab) -> None:
    """T26-5b: twenty refusals in a row must not push out the answers somebody came to read."""
    lab.container.results = [answer("la que importa")]
    kept = lab.start()
    lab.settled(kept)
    lab.outcome = ShellOutcome(ShellStatus.NOT_RUNNING, "en pausa")
    refused = []
    for _ in range(MAX_KEPT + 3):
        refused.append(lab.start())
        lab.settled(refused[-1])
    assert lab.tasks.status(kept).answer == "la que importa"
    assert lab.tasks.status(refused[-1]).outcome is TaskOutcome.REFUSED  # the last always stays
    assert lab.tasks.status(refused[0]) is None
    assert len(lab.tasks.listing()) == MAX_KEPT


def test_a_refusal_goes_before_an_older_answer_only_when_there_are_too_many(lab: Lab) -> None:
    lab.outcome = ShellOutcome(ShellStatus.NOT_RUNNING, "en pausa")
    refused = lab.start()
    lab.settled(refused)
    lab.outcome = READY
    answers = []
    for n in range(MAX_KEPT - 1):
        lab.container.results = [answer(f"respuesta {n}")]
        answers.append(lab.start())
        lab.settled(answers[-1])
    assert lab.tasks.status(refused) is not None  # twenty so far: nothing goes yet
    lab.container.results = [answer("otra")]
    lab.settled(lab.start())
    assert lab.tasks.status(refused) is None
    assert all(lab.tasks.status(one) is not None for one in answers)


def test_past_the_size_the_oldest_goes_even_with_a_refusal_around(
    monkeypatch: pytest.MonkeyPatch, lab: Lab
) -> None:
    """A refusal measures nothing: taking it out would not bring the size down."""
    monkeypatch.setattr(tasks_module, "MAX_KEPT_CHARS", 1000)
    lab.container.results = [answer("a" * 600)]
    big = lab.start()
    lab.settled(big)
    lab.outcome = ShellOutcome(ShellStatus.NOT_RUNNING, "en pausa")
    refused = lab.start()
    lab.settled(refused)
    lab.outcome = READY
    lab.container.results = [answer("b" * 600)]
    lab.settled(lab.start())
    assert lab.tasks.status(big) is None and lab.tasks.status(refused) is not None


# --- the chat's list (T26-5b) -------------------------------------------------------------------


def test_the_list_says_what_was_asked_and_how_each_goes_in_order(lab: Lab) -> None:
    hold = threading.Event()
    lab.container.results = [answer("ya"), hold, answer("luego")]
    first = lab.start("uno", requested_by="web (uid 5, pid 6)")
    lab.settled(first)
    second = lab.start("dos", requested_by="cli (uid 0, pid 1)")
    assert lab.container.entered.acquire(timeout=WAIT)
    one, two = lab.tasks.listing()
    assert (one.task_id, one.asked, one.via, one.outcome) == (first, "uno", "web", TaskOutcome.OK)
    assert one.answer_chars == 2 and one.seconds is not None and one.asked_at > 0
    assert (two.task_id, two.asked, two.via) == (second, "dos", "cli")
    assert two.outcome is TaskOutcome.RUNNING and two.answer_chars == 0
    hold.set()
    lab.settled(second)


def test_the_list_never_has_an_answer(lab: Lab) -> None:
    lab.container.results = [answer(SECRET_ANSWER)]
    lab.settled(lab.start())
    assert SECRET_ANSWER not in repr(lab.tasks.listing())


def test_the_list_strikes_what_was_asked_and_then_cuts_it(lab: Lab) -> None:
    """A secret said in a prompt is never kept once it has run, and a secret at the cut's edge is
    struck whole: in that order, as in the black box."""
    secret = "sk-ant-api03-" + "A1b2C3d4" * 8
    lab.container.results = [answer("ok")]
    task_id = lab.start("usa " + secret + " y ya")
    lab.settled(task_id)
    (entry,) = lab.tasks.listing()
    assert secret not in entry.asked and "usa " in entry.asked and "y ya" in entry.asked
    lab.container.results = [answer("ok")]
    edge = lab.start("x" * (ASKED_CHARS - 10) + " " + secret)
    lab.settled(edge)
    cut = lab.tasks.listing()[-1].asked
    assert len(cut) == ASKED_CHARS + 1 and cut.endswith("…") and "sk-ant" not in cut


def test_what_the_list_keeps_counts_for_the_size(monkeypatch: pytest.MonkeyPatch, lab: Lab) -> None:
    monkeypatch.setattr(tasks_module, "MAX_KEPT_CHARS", 100)
    lab.container.results = [answer("a")]
    old = lab.start("p" * 60)
    lab.settled(old)
    lab.container.results = [answer("b")]
    new = lab.start("q" * 60)
    lab.settled(new)
    assert lab.tasks.status(old) is None and lab.tasks.status(new) is not None


def test_the_prompt_is_not_kept_past_its_run(lab: Lab) -> None:
    lab.container.results = [answer("ok")]
    task_id = lab.start("clave sk-ant-api03-" + "A1b2C3d4" * 8)
    lab.settled(task_id)
    assert lab.tasks._tasks[task_id].prompt == ""  # noqa: SLF001


# --- the pattern --------------------------------------------------------------------------------


def test_the_task_pattern_finds_the_task_and_only_it() -> None:
    assert CLAUDE_CODE.shell is not None
    pattern = re.compile(task_pattern(CLAUDE_CODE.shell))
    run = ["/usr/bin/timeout", "-k", "30", "3600", *CLAUDE_CODE.shell.task_argv("hola")]
    task = " ".join(run)
    assert pattern.search(task)
    assert pattern.search(" ".join(run[:4] + list(CLAUDE_CODE.shell.task)))  # nothing after
    assert not pattern.search(task.replace(".local", "xlocal"))  # the dots are literal
    assert not pattern.search(f"sh -c {task}") and not pattern.search(f"{CLAUDE} -p hola")
    # The whole program, not just its first word: an interactive session is not a task.
    assert not pattern.search(" ".join([*run[:4], CLAUDE, *SETTINGS]))


def test_the_openclaw_task_pattern_finds_the_turn_and_only_it() -> None:
    pattern = re.compile(task_pattern(OPENCLAW.shell))
    timeout = ["/usr/bin/timeout", "-k", "30", "60"]
    assert pattern.search(" ".join([*timeout, *OPENCLAW_TURN, "--timeout=30", "--message=x"]))
    assert not pattern.search("node openclaw.mjs gateway")
    assert not pattern.search(" ".join(OPENCLAW_TURN))
    # Anchored to the CLI itself: any other node under a timeout is not a task.
    assert not pattern.search(" ".join([*timeout, "/usr/local/bin/node", "/workspace/x.mjs"]))
    assert not pattern.search(" ".join([*timeout, *OPENCLAW_TURN[:3], "--agent", "otro"]))
