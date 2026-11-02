"""T26-5b: the chat of the web (docs/47, sections 7.1 and 7.3).

Over fakes, what the page, its POST and its stream do; then the web over a real ``WebControlServer``
on a real Unix socket, with the real ``AgentTasks`` and a double of the container: a task from the
form to the answer on the page, and that without a session the service says no by itself. What the
agent writes is hostile: every view of it is walked with an HTML parser (``tests.webkit``)."""

import ast
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backtide.jail import docker
from backtide.jail.profile import MAX_PROMPT
from backtide.jail.profiles import CLAUDE_CODE
from backtide.service.control import ask_task_stop
from backtide.service.sessions import Sessions
from backtide.service.tasks import PKILL, AgentTasks
from backtide.service.web_control import WebControlServer
from backtide.web.agents import AgentSource
from backtide.web.reader import BoxReader
from backtide.web.rewind import Availability
from backtide.web.security import CSP, MAX_PROMPT_FORM_BYTES, ServiceAccess
from backtide.web.talk import SHOWN_CHARS, ControlTasks, known_id, known_of
from backtide.web.text import MAX_MARKERS
from tests.test_service_tasks import READY, answer
from tests.test_service_web_control import GROUP, FakeGuardian, the_web
from tests.test_web_rewind import POST_HEADERS, text_of
from tests.webkit import (
    HOSTILE_ANSWER,
    SESSION,
    START,
    answer_problems,
    new_box,
    new_client,
    parse_sse,
)

fake_ollama_file = Path(__file__).parent / "integration" / "proxy_fixtures" / "fake_ollama.py"
TASK_A, TASK_B = "a" * 32, "b" * 32
AT = START.timestamp() - 600
PAGE, SEND, STREAM = "/hablar", "/hablar/pedir", "/hablar/stream"


def line(task: str = TASK_A, outcome: str = "ok", asked: str = "hola", via: str = "web") -> dict:
    return {
        "task": task,
        "asked": asked,
        "asked_at": AT,
        "via": via,
        "outcome": outcome,
        "seconds": None if outcome == "running" else 1.5,
        "answer_chars": 0,
    }


class FakeTasks:
    """Answers from ``entries`` and ``answers``, and writes down what it is asked."""

    def __init__(self, state: Availability = Availability.READY, enabled: bool = True) -> None:
        self.enabled = enabled
        self.state = state
        self.entries: list[dict[str, Any]] = []
        self.answers: dict[str, dict[str, Any]] = {}
        self.started: list[tuple[str, bool, str | None]] = []
        self.statuses: list[tuple[str, str | None]] = []
        self.listed: list[str | None] = []
        self.reply: dict[str, Any] = {"ok": True, "outcome": "started", "message": "", "task": "x"}
        self.error: Exception | None = None
        self.status_error: Exception | None = None
        self.stops: list[tuple[str, str | None]] = []
        self.stopped = True

    def availability(self) -> Availability:
        return self.state

    def tasks(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        self.listed.append(agent)
        if self.error is not None:
            raise self.error
        return list(self.entries)

    def status(self, task_id: str, *, agent: str | None = None) -> dict[str, Any]:
        self.statuses.append((task_id, agent))
        if self.status_error is not None:
            raise self.status_error
        return self.answers.get(task_id, said(task_id))

    def start(
        self, prompt: str, *, resume: bool = False, agent: str | None = None
    ) -> dict[str, Any]:
        self.started.append((prompt, resume, agent))
        if self.error is not None:
            raise self.error
        return self.reply

    def stop(self, task_id: str, *, agent: str | None = None) -> bool:
        self.stops.append((task_id, agent))
        if self.error is not None:
            raise self.error
        return self.stopped


def said(text: str = "listo", outcome: str = "ok", message: str = "", chars: int | None = None):
    return {
        "ok": True,
        "outcome": outcome,
        "message": message,
        "answer": text,
        "answer_chars": len(text) if chars is None else chars,
        "code": 0,
        "seconds": 1.5,
    }


@pytest.fixture
def tasks() -> FakeTasks:
    return FakeTasks()


@pytest.fixture
def web(tmp_path: Path, tasks: FakeTasks) -> TestClient:
    new_box(tmp_path)
    return new_client(tmp_path, tasks=tasks)


def csrf_of(page: str) -> str:
    found = hidden(page, "csrf")
    assert found
    return found


def hidden(page: str, name: str) -> str | None:
    start = page.find(f'name="{name}" value="')
    if start < 0:
        return None
    start += len(f'name="{name}" value="')
    return page[start : page.index('"', start)]


def send(web: TestClient, text: str = "di hola", **fields: str) -> Any:
    form = {"csrf": csrf_of(web.get(PAGE).text), "pedido": text, **fields}
    return web.post(SEND, data=form, headers=POST_HEADERS, follow_redirects=False)


# --- the page -------------------------------------------------------------------------------------


def test_the_page_has_the_box_the_list_and_the_stream(web: TestClient, tasks: FakeTasks) -> None:
    tasks.entries = [line(TASK_A, asked="primero"), line(TASK_B, "running", "segundo")]
    tasks.answers[TASK_A] = said("la respuesta")
    page = web.get(PAGE)
    assert page.status_code == 200
    html = page.text
    assert '<textarea class="talk-input"' in html and f'maxlength="{MAX_PROMPT}"' in html
    assert "primero" in html and "la respuesta" in html and "segundo" in html
    assert "Una tarea en marcha" in html
    assert 'sse-connect="/s/' in html and f"hablar/stream?visto=e{TASK_A},r{TASK_B}" in html
    # The newest first, right under the box.
    assert html.index("segundo") < html.index("primero")


def test_the_page_never_asks_again_for_what_is_running(web: TestClient, tasks: FakeTasks) -> None:
    tasks.entries = [line(TASK_A, "running")]
    web.get(PAGE)
    assert tasks.statuses == []


@pytest.mark.parametrize(
    "state", [Availability.DISABLED, Availability.NO_SERVICE, Availability.OTHER_USER]
)
def test_a_web_that_cannot_ask_says_why_and_has_no_box(tmp_path: Path, state: Availability) -> None:
    new_box(tmp_path)
    fake = FakeTasks(state, enabled=state is not Availability.DISABLED)
    html = new_client(tmp_path, tasks=fake).get(PAGE).text
    assert "<textarea" not in html and "sse-connect" not in html
    assert "backtide" in text_of(html)
    assert fake.listed == []


def test_without_tareas_there_is_no_door(tmp_path: Path) -> None:
    new_box(tmp_path)
    fake = FakeTasks(Availability.DISABLED, enabled=False)
    web = new_client(tmp_path, tasks=fake)
    form = {"csrf": "x", "pedido": "borra todo"}
    assert web.post(SEND, data=form, headers=POST_HEADERS).status_code == 405
    assert fake.started == []
    assert "backtide web --tareas" in web.get(PAGE).text.replace("<code>", "").replace(
        "</code>", ""
    )


def test_a_list_that_cannot_be_read_is_said_and_not_nothing(
    web: TestClient, tasks: FakeTasks
) -> None:
    from backtide.service.control import ControlError

    tasks.error = ControlError("MARCA")
    html = web.get(PAGE).text
    assert "No se puede preguntar al servicio" in html
    assert "MARCA" not in html


def test_an_end_that_cannot_be_read_is_asked_again_by_the_stream(
    web: TestClient, tasks: FakeTasks
) -> None:
    from backtide.service.control import ControlError

    tasks.entries = [line(TASK_A)]
    tasks.status_error = ControlError("MARCA")
    html = web.get(PAGE).text
    assert "No se ha podido leer" in html and f"r{TASK_A}" in html and "MARCA" not in html


def test_a_refused_read_of_an_end_is_not_how_the_task_ended(
    web: TestClient, tasks: FakeTasks
) -> None:
    """ "refused" from the socket (a full bucket) is not the task's own "refused"."""
    tasks.entries = [line(TASK_A)]
    tasks.answers[TASK_A] = {"ok": False, "outcome": "refused", "message": "Demasiadas"}
    html = web.get(PAGE).text
    assert "No se ha podido leer" in html and "No ha empezado" not in html


def test_a_task_the_cli_gave_says_so(web: TestClient, tasks: FakeTasks) -> None:
    tasks.entries = [line(via="cli")]
    assert "desde la terminal" in web.get(PAGE).text


def test_an_answer_too_long_for_the_page_says_how_much_is_shown(
    web: TestClient, tasks: FakeTasks
) -> None:
    tasks.entries = [line()]
    tasks.answers[TASK_A] = said("x" * 100, chars=5000)
    html = web.get(PAGE).text
    assert "los primeros 100 caracteres de 5000" in html


def test_a_whole_answer_with_windows_line_ends_is_not_called_cut(
    web: TestClient, tasks: FakeTasks
) -> None:
    """Seen in the browser: CR LF becomes LF, and the page said "the first 373 of 374"."""
    tasks.entries = [line()]
    tasks.answers[TASK_A] = said("uno\r\ndos")
    html = web.get(PAGE).text
    assert "uno\ndos" in html and "caracteres de" not in html


@pytest.mark.parametrize(
    ("outcome", "word"),
    [
        ("failed", "Ha fallado"),
        ("timed_out", "Se pasó de tiempo"),
        ("killed", "Cortada"),
        ("busy", "había otra en marcha"),
        ("refused", "No ha empezado"),
        ("cut", "no se sabe cómo acabó"),
        ("stopped", "Parada"),
    ],
)
def test_every_end_has_its_words(
    web: TestClient, tasks: FakeTasks, outcome: str, word: str
) -> None:
    tasks.entries = [line(outcome=outcome)]
    tasks.answers[TASK_A] = {**said(), "outcome": outcome, "answer": None, "message": "El motivo"}
    html = web.get(PAGE).text
    assert word in html and "El motivo" in html


# --- what the agent writes ------------------------------------------------------------------------


def test_the_scenarios_fake_model_answers_this_same_text() -> None:
    """respuesta-que-pinta runs it against the real thing in the VM: the fake model stands alone."""
    source = Path(fake_ollama_file).read_text()
    module = ast.parse(source)
    found = next(
        node.value
        for node in module.body
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "PAINT_TEXT"
    )
    assert ast.literal_eval(found) == HOSTILE_ANSWER


def test_a_hostile_answer_is_only_text(web: TestClient, tasks: FakeTasks) -> None:
    tasks.entries = [line()]
    tasks.answers[TASK_A] = said(HOSTILE_ANSWER)
    page = web.get(PAGE)
    assert answer_problems(page.text) == []
    assert page.headers["content-security-policy"] == CSP


def test_a_hostile_message_is_only_text_too(web: TestClient, tasks: FakeTasks) -> None:
    """The tail of a failed run is the agent's, and it comes as the message."""
    tasks.entries = [line(outcome="failed")]
    tasks.answers[TASK_A] = {
        **said(),
        "outcome": "failed",
        "answer": None,
        "message": HOSTILE_ANSWER,
    }
    assert answer_problems(web.get(PAGE).text) == []


def test_what_was_asked_is_only_text_too(web: TestClient, tasks: FakeTasks) -> None:
    """A task the CLI gave, or a copy of what the agent wrote pasted in the box."""
    tasks.entries = [line(asked=HOSTILE_ANSWER)]
    assert answer_problems(web.get(PAGE).text) == []


def test_a_refusal_that_echoes_is_only_text(web: TestClient, tasks: FakeTasks) -> None:
    tasks.reply = {"ok": False, "outcome": "refused", "message": HOSTILE_ANSWER}
    page = send(web, "hola")
    assert page.status_code == 409 and answer_problems(page.text) == []


def test_what_was_typed_comes_back_inside_its_box(web: TestClient, tasks: FakeTasks) -> None:
    tasks.reply = {"ok": False, "outcome": "refused", "message": "no"}
    page = send(web, "</textarea><script>alert(1)</script>")
    assert "&lt;/textarea&gt;&lt;script&gt;alert(1)&lt;/script&gt;</textarea>" in page.text


def test_a_hostile_answer_in_the_stream_is_only_text(tmp_path: Path, tasks: FakeTasks) -> None:
    new_box(tmp_path)
    web = new_client(tmp_path, tasks=tasks, stream_seconds=0.2, poll_interval=0.01)
    tasks.entries = [line()]
    tasks.answers[TASK_A] = said(HOSTILE_ANSWER)
    body = web.get(STREAM).text
    data = "\n".join(e["data"] for e in parse_sse(body) if e.get("event") == "tasks")
    assert TASK_A in data and answer_problems(data) == []


# --- giving a task --------------------------------------------------------------------------------


def test_a_task_goes_to_the_service_and_back_to_the_page(web: TestClient, tasks: FakeTasks) -> None:
    reply = send(web, "línea uno\r\nlínea dos")
    assert reply.status_code == 303 and reply.headers["location"].endswith("/hablar")
    assert tasks.started == [("línea uno\nlínea dos", False, None)]


def test_going_on_with_the_conversation_is_asked_for(web: TestClient, tasks: FakeTasks) -> None:
    send(web, "sigue", seguir="1")
    assert tasks.started == [("sigue", True, None)]


def test_a_task_needs_the_forms_token(web: TestClient, tasks: FakeTasks) -> None:
    web.get(PAGE)
    form = {"csrf": "no-es", "pedido": "borra todo"}
    assert web.post(SEND, data=form, headers=POST_HEADERS).status_code == 403
    assert tasks.started == []


def test_a_task_needs_a_session(tmp_path: Path, tasks: FakeTasks) -> None:
    new_box(tmp_path)
    web = new_client(tmp_path, tasks=tasks, logged_in=False)
    form = {"csrf": "x", "pedido": "borra todo"}
    assert web.post(SEND, data=form, headers=POST_HEADERS).status_code == 401
    assert web.get(PAGE).status_code == 401
    assert web.get(STREAM).status_code == 401
    assert tasks.started == [] and tasks.listed == []


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"origin": "http://evil.example"},
        {**POST_HEADERS, "sec-fetch-site": "cross-site"},
        {**POST_HEADERS, "sec-fetch-site": "same-site"},
    ],
)
def test_a_task_comes_from_our_own_page(
    web: TestClient, tasks: FakeTasks, headers: dict[str, str]
) -> None:
    form = {"csrf": csrf_of(web.get(PAGE).text), "pedido": "borra todo"}
    assert web.post(SEND, data=form, headers=headers).status_code == 403
    assert tasks.started == []


def test_the_long_form_is_only_for_this_path(web: TestClient, tasks: FakeTasks) -> None:
    long_text = "x" * 4000
    form = {"csrf": csrf_of(web.get(PAGE).text), "id": long_text, "ticket": "t"}
    refused = web.post("/instantaneas/rebobinar", data=form, headers=POST_HEADERS)
    assert refused.status_code == 413
    assert send(web, long_text).status_code == 303


def test_a_prompt_past_the_limit_is_said_and_kept(web: TestClient, tasks: FakeTasks) -> None:
    page = send(web, "y" * (MAX_PROMPT + 1))
    assert page.status_code == 400 and "demasiado largo" in page.text and "y" * 100 in page.text
    assert tasks.started == []
    assert send(web, "y" * MAX_PROMPT).status_code == 303


def test_a_body_past_the_guards_limit_is_refused(web: TestClient, tasks: FakeTasks) -> None:
    form = {"csrf": csrf_of(web.get(PAGE).text), "pedido": "😀" * (MAX_PROMPT_FORM_BYTES // 12 + 1)}
    assert web.post(SEND, data=form, headers=POST_HEADERS).status_code == 413
    assert tasks.started == []


def test_a_whole_prompt_of_the_longest_letters_fits(web: TestClient, tasks: FakeTasks) -> None:
    assert send(web, "😀" * MAX_PROMPT).status_code == 303
    assert len(tasks.started[0][0]) == MAX_PROMPT


def test_a_prompt_can_carry_what_a_person_pastes(web: TestClient, tasks: FakeTasks) -> None:
    """A no-break space or the joiner of an emoji are no reason to refuse it: the service's rules
    are about what fits in an argument, and the page shows them as marks."""
    assert send(web, "a b 👨‍💻\tc").status_code == 303
    assert tasks.started[0][0] == "a b 👨‍💻\tc"


@pytest.mark.parametrize("text", ["", "   ", "\r\n"])
def test_nothing_to_ask_asks_nothing(web: TestClient, tasks: FakeTasks, text: str) -> None:
    page = send(web, text)
    assert page.status_code == 400 and tasks.started == []


def test_a_form_with_more_than_its_fields_is_refused(web: TestClient, tasks: FakeTasks) -> None:
    form = {"csrf": csrf_of(web.get(PAGE).text), "pedido": "hola", "continue": "1"}
    assert web.post(SEND, data=form, headers=POST_HEADERS).status_code == 400
    assert tasks.started == []


def test_a_refusal_keeps_what_was_typed(web: TestClient, tasks: FakeTasks) -> None:
    tasks.reply = {"ok": False, "outcome": "refused", "message": "Ya tiene 8 tareas."}
    page = send(web, "lo que escribí")
    assert page.status_code == 409
    assert "lo que escribí</textarea>" in page.text and "Ya tiene 8 tareas." in page.text


@pytest.mark.parametrize(
    ("error", "word", "status"),
    [("ControlUnavailable", "no se ha pedido nada", 503),
     ("ControlOutcomeUnknown", "puede haber empezado", 503),
     ("ControlError", "no se ha pedido nada", 503)],
)  # fmt: skip
def test_a_service_that_does_not_answer_is_said(
    web: TestClient,
    tasks: FakeTasks,
    caplog: pytest.LogCaptureFixture,
    error: str,
    word: str,
    status: int,
) -> None:
    from backtide.service import control

    form = {"csrf": csrf_of(web.get(PAGE).text), "pedido": "PEDIDO-SECRETO"}
    tasks.error = getattr(control, error)("MARCA")
    page = web.post(SEND, data=form, headers=POST_HEADERS)
    assert page.status_code == status and word in page.text and "MARCA" not in page.text
    assert "PEDIDO-SECRETO" not in caplog.text and "MARCA" not in caplog.text


def test_a_service_that_went_away_between_page_and_post(web: TestClient, tasks: FakeTasks) -> None:
    form = {"csrf": csrf_of(web.get(PAGE).text), "pedido": "hola"}
    tasks.state = Availability.NO_SERVICE
    page = web.post(SEND, data=form, headers=POST_HEADERS)
    assert page.status_code == 503 and "hola</textarea>" in page.text
    assert "backtide vigilar" in text_of(page.text) and "sse-connect" not in page.text
    assert tasks.started == []


# --- stopping one ---------------------------------------------------------------------------------

STOP = "/hablar/parar"


def test_a_running_task_has_its_button_and_an_ended_one_does_not(
    web: TestClient, tasks: FakeTasks
) -> None:
    tasks.entries = [line(TASK_A), line(TASK_B, "running")]
    html = web.get(PAGE).text
    assert html.count('class="task-stop"') == 1
    assert f'name="tarea" value="{TASK_B}"' in html and f'name="tarea" value="{TASK_A}"' not in html


def test_with_several_running_the_page_says_a_stop_stops_them_all(
    web: TestClient, tasks: FakeTasks
) -> None:
    """The pattern finds them all (see "Después" in docs/backlog.md): the button must not lie."""
    tasks.entries = [line(TASK_A, "running")]
    assert "Parar una las para todas" not in web.get(PAGE).text
    tasks.entries = [line(TASK_A, "running"), line(TASK_B, "running")]
    assert "Parar una las para todas" in web.get(PAGE).text


def test_the_streams_line_has_the_button_with_the_sessions_token(
    live: TestClient, tasks: FakeTasks
) -> None:
    tasks.entries = [line(outcome="running")]
    csrf = csrf_of(live.get(PAGE).text)
    data = events(stream_of(live), "tasks")[0]["data"]
    assert f'name="csrf" value="{csrf}"' in data and f'name="tarea" value="{TASK_A}"' in data


def stop(web: TestClient, task: str = TASK_A, **fields: str) -> Any:
    form = {"csrf": csrf_of(web.get(PAGE).text), "tarea": task, **fields}
    return web.post(STOP, data=form, headers=POST_HEADERS, follow_redirects=False)


def test_a_stop_goes_to_the_service_and_back_to_the_page(web: TestClient, tasks: FakeTasks) -> None:
    reply = stop(web)
    assert reply.status_code == 303 and reply.headers["location"].endswith("/hablar")
    assert tasks.stops == [(TASK_A, None)]


def test_a_stop_goes_to_the_agent_the_form_says(two: TestClient, tasks: FakeTasks) -> None:
    form = {"csrf": csrf_of(two.get(PAGE).text), "tarea": TASK_A, "agente": SLUG}
    reply = two.post(STOP, data=form, headers=POST_HEADERS, follow_redirects=False)
    assert reply.status_code == 303 and reply.headers["location"].endswith(
        f"/agentes/{SLUG}/hablar"
    )
    assert tasks.stops == [(TASK_A, SLUG)]


def test_a_stop_needs_the_forms_token(web: TestClient, tasks: FakeTasks) -> None:
    web.get(PAGE)
    form = {"csrf": "no-es", "tarea": TASK_A}
    assert web.post(STOP, data=form, headers=POST_HEADERS).status_code == 403
    assert tasks.stops == []


def test_a_stop_needs_a_session(tmp_path: Path, tasks: FakeTasks) -> None:
    new_box(tmp_path)
    web = new_client(tmp_path, tasks=tasks, logged_in=False)
    form = {"csrf": "x", "tarea": TASK_A}
    assert web.post(STOP, data=form, headers=POST_HEADERS).status_code == 401
    assert tasks.stops == []


def test_a_stop_comes_from_our_own_page(web: TestClient, tasks: FakeTasks) -> None:
    form = {"csrf": csrf_of(web.get(PAGE).text), "tarea": TASK_A}
    assert web.post(STOP, data=form).status_code == 403
    evil = {**POST_HEADERS, "origin": "http://evil.example"}
    assert web.post(STOP, data=form, headers=evil).status_code == 403
    assert web.get(STOP).status_code in (404, 405)
    assert tasks.stops == []


@pytest.mark.parametrize("task", ["", "x", "A" * 32, "a" * 31, "a" * 33, "../../etc"])
def test_only_a_task_id_can_be_stopped(web: TestClient, tasks: FakeTasks, task: str) -> None:
    assert stop(web, task).status_code == 400 and tasks.stops == []


def test_without_tareas_there_is_no_stop_either(tmp_path: Path) -> None:
    new_box(tmp_path)
    fake = FakeTasks(Availability.DISABLED, enabled=False)
    web = new_client(tmp_path, tasks=fake)
    form = {"csrf": "x", "tarea": TASK_A}
    assert web.post(STOP, data=form, headers=POST_HEADERS).status_code == 405
    assert fake.stops == []


def test_a_stop_that_failed_says_it_may_run_on(web: TestClient, tasks: FakeTasks) -> None:
    tasks.stopped = False
    page = stop(web)
    assert page.status_code == 503 and "puede seguir en marcha" in page.text


def test_a_service_that_does_not_answer_a_stop(web: TestClient, tasks: FakeTasks) -> None:
    from backtide.service.control import ControlOutcomeUnknown

    form = {"csrf": csrf_of(web.get(PAGE).text), "tarea": TASK_A}
    tasks.error = ControlOutcomeUnknown("MARCA")
    page = web.post(STOP, data=form, headers=POST_HEADERS)
    assert page.status_code == 503 and "MARCA" not in page.text


# --- which agent ----------------------------------------------------------------------------------

SLUG = "revisor"


@pytest.fixture
def two(tmp_path: Path, tasks: FakeTasks) -> TestClient:
    new_box(tmp_path)
    other = tmp_path / "otro"
    other.mkdir()
    new_box(other)
    source = AgentSource(SLUG, "Revisor", BoxReader(other / "blackbox.db"), list)
    return new_client(tmp_path, tasks=tasks, others=[source], agent_name="Principal")


def test_each_agent_has_its_own_page_and_its_form_says_whose(
    two: TestClient, tasks: FakeTasks
) -> None:
    page = two.get(f"/agentes/{SLUG}/hablar").text
    assert hidden(page, "agente") == SLUG and tasks.listed == [SLUG]
    assert f"/agentes/{SLUG}/hablar/stream" in page
    assert 'href="/s/' in page and "/hablar" in page
    main_page = two.get(PAGE).text
    assert hidden(main_page, "agente") is None and tasks.listed == [SLUG, None]


def test_a_task_goes_to_the_agent_the_form_says(two: TestClient, tasks: FakeTasks) -> None:
    page = two.get(f"/agentes/{SLUG}/hablar").text
    form = {"csrf": csrf_of(page), "pedido": "hola", "agente": SLUG}
    reply = two.post(SEND, data=form, headers=POST_HEADERS, follow_redirects=False)
    assert reply.status_code == 303 and reply.headers["location"].endswith(
        f"/agentes/{SLUG}/hablar"
    )
    assert tasks.started == [("hola", False, SLUG)]


def test_an_agent_that_is_nobodys_is_not_here(two: TestClient, tasks: FakeTasks) -> None:
    page = two.get(PAGE).text
    form = {"csrf": csrf_of(page), "pedido": "hola", "agente": "../otro"}
    assert two.post(SEND, data=form, headers=POST_HEADERS).status_code == 404
    assert two.get("/agentes/nadie/hablar").status_code == 404
    assert two.get("/agentes/nadie/hablar/stream").status_code == 404
    assert tasks.started == []


def test_an_agent_that_is_not_watched_is_not_asked(tmp_path: Path, tasks: FakeTasks) -> None:
    new_box(tmp_path)
    other = tmp_path / "otro"
    other.mkdir()
    new_box(other)
    source = AgentSource(SLUG, "Revisor", BoxReader(other / "blackbox.db"), list, watched=False)
    web = new_client(tmp_path, tasks=tasks, others=[source])
    page = web.get(f"/agentes/{SLUG}/hablar").text
    assert "<textarea" not in page and "no se está vigilando" in page and tasks.listed == []


# --- the stream -----------------------------------------------------------------------------------


def stream_of(web: TestClient, url: str = STREAM, **headers: str) -> list[dict[str, str]]:
    return parse_sse(web.get(url, headers=headers).text)


@pytest.fixture
def live(tmp_path: Path, tasks: FakeTasks) -> TestClient:
    new_box(tmp_path)
    return new_client(tmp_path, tasks=tasks, stream_seconds=0.2, poll_interval=0.01)


def events(found: list[dict[str, str]], name: str) -> list[dict[str, str]]:
    return [e for e in found if e.get("event") == name]


def test_a_new_task_comes_at_the_top_and_its_end_in_place(
    live: TestClient, tasks: FakeTasks
) -> None:
    tasks.entries = [line(outcome="running")]
    first = stream_of(live)
    new = events(first, "tasks")[0]
    assert f'id="task-{TASK_A}"' in new["data"] and "hx-swap-oob" not in new["data"]
    assert new["id"] == f"r{TASK_A}" and tasks.statuses == []
    assert "Una tarea en marcha" in events(first, "talk-state")[0]["data"]

    tasks.entries = [line()]
    tasks.answers[TASK_A] = said("la respuesta")
    second = stream_of(live, f"{STREAM}?visto=r{TASK_A}")
    end = events(second, "tasks")[0]
    assert 'hx-swap-oob="true"' in end["data"] and "la respuesta" in end["data"]
    assert end["id"] == f"e{TASK_A}"
    assert "Nada en marcha" in events(second, "talk-state")[0]["data"]


def test_a_task_that_ended_is_read_once(live: TestClient, tasks: FakeTasks) -> None:
    """T26-5a's point for this task: the stream asks every second, and the answer can be 8 MiB."""
    tasks.entries = [line()]
    found = stream_of(live)
    assert len(events(found, "tasks")) == 1
    assert tasks.statuses == [(TASK_A, None)]
    assert len(tasks.listed) > 1  # it did go on looking


def test_what_the_page_has_is_not_asked_for_nor_sent(live: TestClient, tasks: FakeTasks) -> None:
    tasks.entries = [line()]
    assert events(stream_of(live, f"{STREAM}?visto=e{TASK_A}"), "tasks") == []
    assert tasks.statuses == []


def test_a_reconnect_goes_by_what_the_stream_last_said(live: TestClient, tasks: FakeTasks) -> None:
    """Last-Event-ID, newer than the address the page was drawn with."""
    tasks.entries = [line()]
    found = stream_of(live, f"{STREAM}?visto=r{TASK_A}", **{"last-event-id": f"e{TASK_A}"})
    assert events(found, "tasks") == [] and tasks.statuses == []


@pytest.mark.parametrize("nonsense", ["<script>", "e" + "x" * 32, f"e{TASK_A}" + ",," * 5000, "x"])
def test_a_made_up_position_only_sends_things_again(
    live: TestClient, tasks: FakeTasks, nonsense: str
) -> None:
    tasks.entries = [line(TASK_B)]
    found = stream_of(live, **{"last-event-id": nonsense})
    assert TASK_B in events(found, "tasks")[0]["data"]


def test_known_of_is_the_inverse_of_known_id() -> None:
    known = {TASK_A: True, TASK_B: False}
    assert known_of(known_id(known)) == known
    assert known_of("") == {} and known_of("e123,z" + TASK_A) == {}


def test_a_running_task_the_service_forgot_says_so(live: TestClient, tasks: FakeTasks) -> None:
    """A service that restarted: nothing will end it, and what was asked stays on the page."""
    found = stream_of(live, f"{STREAM}?visto=r{TASK_A}")
    lost = events(found, "tasks")[0]
    assert f'id="task-head-{TASK_A}"' in lost["data"] and "ya no la conoce" in lost["data"]
    assert lost["id"] == f"e{TASK_A}"


def test_a_list_that_fails_is_not_a_service_that_forgot(live: TestClient, tasks: FakeTasks) -> None:
    from backtide.service.control import ControlError

    tasks.error = ControlError("MARCA")
    found = stream_of(live, f"{STREAM}?visto=r{TASK_A}")
    assert events(found, "tasks") == []
    assert "No se puede preguntar" in events(found, "talk-state")[0]["data"]
    assert "MARCA" not in str(found)


def test_an_end_that_could_not_be_read_is_asked_again(live: TestClient, tasks: FakeTasks) -> None:
    from backtide.service.control import ControlError

    tasks.entries = [line()]
    tasks.status_error = ControlError("MARCA")
    found = stream_of(live)
    assert TASK_A in events(found, "tasks")[0]["data"]
    assert len(tasks.statuses) > 1


def test_a_stream_ends_with_its_session(tmp_path: Path, tasks: FakeTasks) -> None:
    new_box(tmp_path)
    sessions = Sessions()
    sessions.preset(SESSION)
    from backtide.web.security import LocalAccess

    web = new_client(
        tmp_path,
        tasks=tasks,
        access=LocalAccess(sessions),
        session_recheck=0.0,
        poll_interval=0.01,
    )
    # The stream checks it at the door; the moment it is over, it says so and stops by itself.
    real_tasks = tasks.tasks

    def ending(*, agent: str | None = None) -> list[dict[str, Any]]:
        sessions.end(SESSION)
        return real_tasks(agent=agent)

    tasks.tasks = ending  # type: ignore[method-assign]
    found = stream_of(web)
    assert events(found, "session")[0]["data"] == "expired"


def test_a_tab_whose_session_died_stops_before_it_asks_again(
    tmp_path: Path, tasks: FakeTasks
) -> None:
    """A read with a dead session is a WARNING, recorded and alerted as what a web taken over would
    do: with the minute of the other streams, a tab left open would say it sixty times."""
    new_box(tmp_path)
    sessions = Sessions()
    sessions.preset(SESSION)
    from backtide.web.security import LocalAccess

    web = new_client(tmp_path, tasks=tasks, access=LocalAccess(sessions), poll_interval=0.01)
    real_tasks = tasks.tasks

    def ending(*, agent: str | None = None) -> list[dict[str, Any]]:
        sessions.end(SESSION)
        return real_tasks(agent=agent)

    tasks.tasks = ending  # type: ignore[method-assign]
    assert events(stream_of(web), "session")[0]["data"] == "expired"
    assert len(tasks.listed) == 1


def test_many_invisibles_in_an_answer_are_a_small_page(web: TestClient, tasks: FakeTasks) -> None:
    """An agent chooses them, and a tab that hangs takes its stop button with it."""
    tasks.entries = [line(TASK_A), line(TASK_B)]
    tasks.answers[TASK_A] = said("\u200b" * SHOWN_CHARS)
    tasks.answers[TASK_B] = said("\u200b\u200c" * (SHOWN_CHARS // 2))
    html = web.get(PAGE).text
    assert html.count('class="esc"') <= 1 + MAX_MARKERS
    assert len(html) < 1024 * 1024 and "U+200B×" in html and 'class="cut"' in html


def test_the_app_has_no_answer_in_any_other_path(web: TestClient, tasks: FakeTasks) -> None:
    """The panel and the agent's pages know nothing of tasks."""
    tasks.entries = [line()]
    tasks.answers[TASK_A] = said("RESPUESTA-MARCA")
    for path in ("/panel", "/ahora", "/historia"):
        assert "RESPUESTA-MARCA" not in web.get(path).text
    assert tasks.statuses == []


def test_the_tab_is_there_on_every_page_of_the_agent(web: TestClient) -> None:
    for path in ("/ahora", "/historia", "/instantaneas", "/ahora/preguntar", PAGE):
        page = web.get(path).text
        assert '/hablar"' in page and "Hablar" in page, path


# --- the web over a real socket ---------------------------------------------------------------


ANSWER = "listo <b>de verdad</b>"


class TaskingGuardian(FakeGuardian):
    """A Guardian whose tasks are the real ``AgentTasks``, with a double of the container."""

    def __init__(self) -> None:
        super().__init__()
        self.ended: list[dict[str, Any]] = []
        self.answers = [ANSWER]
        self.real = AgentTasks(
            commands=lambda: CLAUDE_CODE.shell,
            open_shell=lambda kind, **options: READY,
            record_end=self.ended.append,
            sleep=lambda _: None,
        )

    def task_start(self, prompt: str, **options: Any) -> Any:
        return self.real.start(prompt, **options)

    def task_status(self, task_id: str) -> Any:
        return self.real.status(task_id)

    def task_list(self) -> Any:
        return self.real.listing()

    def task_stop(self, task_id: str, **options: Any) -> Any:
        return self.real.stop(task_id, **options)

    def settled(self) -> None:
        for task in list(self.real._tasks.values()):  # noqa: SLF001
            assert task.finished.wait(10)


@pytest.fixture
def folder() -> Iterator[Path]:
    made = Path(tempfile.mkdtemp(prefix="bt", dir="/tmp"))  # a Unix socket's path is short
    yield made
    shutil.rmtree(made, ignore_errors=True)


@pytest.fixture
def service(
    folder: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[WebControlServer, TaskingGuardian, Sessions]]:
    guardian = TaskingGuardian()
    monkeypatch.setattr(docker, "run", lambda args, **options: answer(guardian.answers[0]))
    sessions = Sessions()
    sessions.preset(SESSION)
    server = WebControlServer(
        guardian,
        folder / "web.sock",
        group=GROUP,
        user=os.geteuid(),
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: True,
    )
    server.start()
    yield server, guardian, sessions
    guardian.real.close(wait=0.5)
    server.close()


def real_web(tmp_path: Path, server: WebControlServer, **options: Any) -> TestClient:
    new_box(tmp_path)
    uid = os.geteuid()
    peer = _service_is(uid)
    return new_client(
        tmp_path,
        access=ServiceAccess(server.path, server_uid=uid, peer=peer),
        tasks=ControlTasks(
            server.path, enabled=True, server_uid=uid, peer=peer, egid=lambda: GROUP
        ),
        **options,
    )


def _service_is(uid: int) -> Any:
    return lambda sock: (1, uid, GROUP)


def test_a_task_from_the_form_to_the_answer_on_the_page(tmp_path: Path, service: Any) -> None:
    server, guardian, _ = service
    web = real_web(tmp_path, server)
    reply = send(web, "di hola")
    assert reply.status_code == 303
    guardian.settled()
    html = web.get(PAGE).text
    assert "di hola" in html and "listo &lt;b&gt;de verdad&lt;/b&gt;" in html
    assert "<b>de verdad" not in html
    assert guardian.ended[0]["requested_by"].startswith("web ")
    assert ANSWER not in str(guardian.ended) and "di hola" not in str(guardian.ended)


def test_a_task_that_runs_is_stopped_from_the_page(
    tmp_path: Path, service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The button, for real down to the signal: the end says stopped, and who asked."""
    server, guardian, _ = service
    running, stopped = threading.Event(), threading.Event()
    signals: list[list[str]] = []

    def container(args: list[str], **options: Any) -> Any:
        if PKILL in args:
            signals.append(args)
            stopped.set()
            return subprocess.CompletedProcess([], 0, "", "")
        running.set()
        assert stopped.wait(10)
        return subprocess.CompletedProcess([], 143, "", "")

    monkeypatch.setattr(docker, "run", container)
    web = real_web(tmp_path, server)
    assert send(web, "tarda mucho").status_code == 303
    assert running.wait(10)
    page = web.get(PAGE).text
    (task_id,) = [entry.task_id for entry in guardian.real.listing()]
    assert f'name="tarea" value="{task_id}"' in page
    form = {"csrf": csrf_of(page), "tarea": task_id}
    assert (
        web.post(STOP, data=form, headers=POST_HEADERS, follow_redirects=False).status_code == 303
    )
    guardian.settled()
    assert len(signals) == 1
    html = web.get(PAGE).text
    assert "Parada" in html and "task-stop" not in html
    assert guardian.ended[0]["outcome"] == "stopped"
    assert guardian.ended[0]["stopped_by"].startswith("web (uid ")


def test_the_service_itself_wants_a_session_for_a_stop(tmp_path: Path, service: Any) -> None:
    server, guardian, sessions = service
    uid = os.geteuid()
    ask = {"server_uid": uid, "peer": _service_is(uid), "wait": 0, "via": "web"}
    assert ask_task_stop(server.path, TASK_A, **ask) is False
    assert ask_task_stop(server.path, TASK_A, session="s" * 43, **ask) is False
    sessions.end(SESSION)
    assert ask_task_stop(server.path, TASK_A, session=SESSION, **ask) is False
    assert guardian.real.listing() == []


def test_a_long_prompt_reaches_the_service_through_the_socket(tmp_path: Path, service: Any) -> None:
    server, guardian, _ = service
    web = real_web(tmp_path, server)
    assert send(web, "😀" * MAX_PROMPT).status_code == 303
    assert len(guardian.real.listing()) == 1


def test_the_stream_reads_with_the_session_of_the_page(tmp_path: Path, service: Any) -> None:
    server, guardian, _ = service
    web = real_web(tmp_path, server, stream_seconds=0.5, poll_interval=0.02)
    send(web, "di hola")
    guardian.settled()
    found = stream_of(web)
    assert "listo &lt;b&gt;de verdad&lt;/b&gt;" in events(found, "tasks")[0]["data"]


def test_the_service_itself_wants_a_session_for_the_list(tmp_path: Path, service: Any) -> None:
    """Whatever the web says: asked without one, or with another, it gives nothing."""
    from backtide.service.control import ControlError, ask_task_list

    server, _, sessions = service
    uid = os.geteuid()
    ask = {"server_uid": uid, "peer": _service_is(uid), "wait": 0}
    with pytest.raises(ControlError, match="sesión"):
        ask_task_list(server.path, **ask)
    with pytest.raises(ControlError, match="sesión"):
        ask_task_list(server.path, session="s" * 43, **ask)
    assert ask_task_list(server.path, session=SESSION, **ask) == []
    sessions.end(SESSION)
    with pytest.raises(ControlError, match="sesión"):
        ask_task_list(server.path, session=SESSION, **ask)


def test_nothing_of_a_task_reaches_a_file_of_the_web(tmp_path: Path, service: Any) -> None:
    """The answer lives in the service's memory (invariant 5): the web writes it nowhere."""
    server, guardian, _ = service
    web = real_web(tmp_path, server)
    send(web, "di hola")
    guardian.settled()
    assert "de verdad" in web.get(PAGE).text
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert b"de verdad" not in path.read_bytes(), path


def test_shown_chars_reaches_the_service(tmp_path: Path, service: Any) -> None:
    server, guardian, _ = service
    web = real_web(tmp_path, server)
    guardian.answers[0] = "z" * (SHOWN_CHARS + 500)
    send(web, "dilo todo")
    guardian.settled()
    html = web.get(PAGE).text
    assert f"los primeros {SHOWN_CHARS} caracteres de {SHOWN_CHARS + 500}" in html
    assert "z" * (SHOWN_CHARS + 1) not in html
