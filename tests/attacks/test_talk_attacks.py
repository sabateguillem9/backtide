"""The evil-agent scenario of the web's chat (T26-5b, docs/47 section 7.3): ``respuesta-que-pinta``.

What an agent answers reaches a page that can approve, rewind and give it more tasks, so an answer
that became HTML would act with the owner's session. The lab is
tests/integration/test_local_profiles.py's: `backtide vigilar` with the real OpenClaw and the fake
Ollama, whose answer to ``T26-PAINT-<marker>`` is ``PAINT_TEXT``: nothing real, no real key
(invariant 8). The task goes in by the web's real form and real control socket, and the answer comes
out on the real page and its real stream.

Green when: every view is only text, as an HTML parser reads it (``tests.webkit.answer_problems``):
no element or attribute of the agent's, nothing of it out of its frame, none of the characters that
deceive as themselves, and the page's CSP on the response. The black box has that the task was given
by the web and that it ended, and nothing of the answer (invariant 5).

There is no browser in the VM. That a real one runs nothing of this and that its CSP has nothing to
say was looked at on the Mac, with `scripts/web-demo/serve.py` and the same text.
"""

import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from attack_kit import Attack, scenario
from test_web_attacks import POST_HEADERS, hidden_fields, web_for

from backtide.web.security import CSP
from backtide.web.talk import ControlTasks
from tests.integration.ollama_kit import PAINT_TAIL
from tests.integration.service_kit import wait_until
from tests.integration.test_local_profiles import TURN_TIMEOUT, Lab, make_lab
from tests.webkit import answer_problems, parse_sse

PAGE, SEND = "/hablar", "/hablar/pedir"
# Proof that the hostile answer did reach the page, as text: without them a page that lost it would
# have nothing wrong with it.
AS_TEXT = (
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&lt;img src=",
    "javascript:alert(3)",
    "hx-post=",
    "U+202E",
)


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    yield from make_lab(btrfs_volume, tmp_path_factory, kind="openai")


@scenario("respuesta-que-pinta")
def test_a_hostile_answer_is_only_text_on_the_chats_page(attack: Attack, lab: Lab) -> None:
    service = lab.service
    found = service.box.head()
    since = found[0] if found is not None else 0
    marker = uuid.uuid4().hex[:16]
    tasks = ControlTasks(service.config.control_socket, enabled=True)
    web = web_for(service, tasks=tasks)
    form = {
        "csrf": hidden_fields(web.get(PAGE).text)["csrf"],
        "pedido": f"T26-PAINT-{marker} di algo",
    }
    sent = web.post(SEND, data=form, headers=POST_HEADERS, follow_redirects=False)
    assert sent.status_code == 303, sent.text[:300]
    tail = f"{PAINT_TAIL}{marker}"
    wait_until(
        lambda: tail in web.get(PAGE).text,
        TURN_TIMEOUT,
        "the hostile answer on the chat's page",
        context=service.diagnosis,
    )

    page = web.get(PAGE)
    # A stream that has not seen it yet: what it sends goes into the same page by htmx.
    live = web_for(service, tasks=tasks, stream_seconds=1.5, poll_interval=0.05)
    body = live.get(f"{PAGE}/stream").text
    streamed = "\n".join(e.get("data", "") for e in parse_sse(body) if e.get("event") == "tasks")
    problems = {"page": answer_problems(page.text), "stream": answer_problems(streamed)}
    shown = {text: text in page.text and text in streamed for text in AS_TEXT}
    attack.check(
        "stopped",
        not problems["page"]
        and not problems["stream"]
        and all(shown.values())
        and tail in streamed
        and page.headers.get("content-security-policy") == CSP,
        f"lo que está mal en la página y en el directo: {problems}; lo que tiene que salir como "
        f"texto, en los dos: {shown}; la CSP: {page.headers.get('content-security-policy')!r}",
    )

    events = [e for e in service.events() if e.seq > since]
    opened = [e for e in events if e.action == "agent_shell" and e.target == "task"]
    ended = [e for e in events if e.action == "agent_task_end"]
    every = json.dumps([[e.target, e.details] for e in events], ensure_ascii=False, default=str)
    details = ended[0].details if ended else {}
    attack.check(
        "recorded",
        len(opened) == 1
        and str(opened[0].details.get("requested_by", "")).startswith("web ")
        and str(opened[0].details.get("prompt", "")).startswith("T26-PAINT-")
        and len(ended) == 1
        and details.get("outcome") == "ok"
        and int(details.get("answer_chars", 0)) > 0
        and "alert(1)" not in every
        and tail not in every,
        f"{len(opened)} system/agent_shell de la web "
        f"({opened[0].details if opened else None}) y {len(ended)} system/agent_task_end "
        f"({details}); la respuesta en algún evento de {len(events)}: "
        f"{'alert(1)' in every or tail in every}",
    )
