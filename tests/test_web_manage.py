"""T26-6b: the agents' pages. What the list says of each agent (its kind, its version, "Tarea en
marcha", "retirado"), the closed form, the confirmations, and an order that takes minutes without a
page that hangs or lies. Here a fake stands in for the service; what it decides is in
tests/test_service_web_agent_orders.py, and both meet over a real socket at the end."""

import os
import re
import shutil
import socket
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backtide.service.control import ControlOutcomeUnknown, ControlUnavailable
from backtide.service.roster import STARTING, STOP_FAILED, STOPPED_BY_OWNER, STOPPING
from backtide.service.sessions import Sessions
from backtide.service.web_control import WebControlServer
from backtide.web.agents import AgentFacts, Listing, RetiredAgent
from backtide.web.i18n import EN, ES
from backtide.web.manage import ACTIONS_OF, ControlAgentOrders, Order, OrderBook, row_of, word_of
from backtide.web.rewind import Availability
from backtide.web.security import AGENT_CREATE_PATH, AGENT_ORDER_PATH, CSP
from tests.test_service_control import FakeGuardian
from tests.test_service_web_agent_orders import FakeFleet
from tests.test_service_web_control import GROUP
from tests.test_web_rewind import POST_HEADERS
from tests.webkit import PREFIX_PATH, SESSION, new_box, new_client

ME = os.geteuid()
CLAUDE = "Claude Code 2.1.306"
WAIT = 10.0


class FakeOrders:
    """The service, as the web sees it: what it says, and what it was asked."""

    enabled = True

    def __init__(self) -> None:
        self.state = Availability.READY
        self.facts = Listing(
            (
                AgentFacts("principal", "Uno", True, True, "running", "openclaw", "2026.9.8"),
                AgentFacts("codigo", "Código", False, True, "running", "claude-code", "2.1.306"),
            )
        )
        self.asked: list[tuple[dict[str, Any], str | None]] = []
        self.reply: dict[str, Any] = {"ok": True, "outcome": "stopped", "message": "Agente parado."}
        self.fails: Exception | None = None
        self.hold: threading.Event | None = None
        self.holding = threading.Event()

    def availability(self) -> Availability:
        return self.state

    def listing(self) -> Listing | None:
        return self.facts

    def ask(self, request: dict[str, Any], session: str | None) -> dict[str, Any]:
        self.asked.append((request, session))
        if self.hold is not None:
            self.holding.set()
            assert self.hold.wait(WAIT)
        if self.fails is not None:
            raise self.fails
        return self.reply


@pytest.fixture
def orders() -> Iterator[FakeOrders]:
    found = FakeOrders()
    yield found
    if found.hold is not None:
        found.hold.set()


@pytest.fixture
def web(tmp_path: Path, orders: FakeOrders) -> TestClient:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "agent")
    other = new_box_at(tmp_path / "codigo")
    other.append("system", "agent_start", "agent")
    return new_client(
        tmp_path,
        agent_orders=orders,
        others=[source_of(tmp_path / "codigo", "codigo", "Código")],
        agent_name="Uno",
    )


def new_box_at(folder: Path) -> Any:
    folder.mkdir()
    return new_box(folder)


def source_of(folder: Path, slug: str, name: str) -> Any:
    from backtide.web import BoxReader
    from backtide.web.agents import AgentSource

    return AgentSource(slug, name, BoxReader(folder / "blackbox.db"))


def hidden(page: str) -> dict[str, str]:
    return dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page))


def post(web: TestClient, path: str, fields: dict[str, str], **options: Any) -> Any:
    return web.post(path, data=fields, headers=POST_HEADERS, follow_redirects=False, **options)


def create_form(web: TestClient) -> dict[str, str]:
    page = web.get("/agentes/nuevo")
    assert page.status_code == 200
    return {**hidden(page.text), "slug": "tercero", "perfil": "claude-code", "tamano": "10"}


def order_form(web: TestClient, verb: str, slug: str = "codigo") -> dict[str, str]:
    page = web.get(f"/agentes/orden?v={verb}&agente={slug}")
    assert page.status_code == 200, page.text
    return hidden(page.text)


def wait_done(web: TestClient, location: str) -> Any:
    for _ in range(500):
        page = web.get(location)
        if 'data-view="running"' not in page.text:
            return page
        threading.Event().wait(0.01)
    raise AssertionError("the order did not end")


# --- the list -----------------------------------------------------------------------------------


def test_the_list_says_each_agents_kind_and_version(web: TestClient) -> None:
    page = web.get("/agentes")
    assert page.status_code == 200 and page.headers["content-security-policy"] == CSP
    assert "OpenClaw 2026.9.8" in page.text and CLAUDE in page.text
    assert 'aria-current="page">Agentes' in page.text


def test_the_list_says_task_running_while_it_runs_and_only_then(
    web: TestClient, orders: FakeOrders
) -> None:
    assert ES["agents.in_use.task"] not in web.get("/agentes").text
    orders.facts = Listing(
        (
            orders.facts.agents[0],
            AgentFacts(
                "codigo", "Código", False, True, "running", "claude-code", "2.1.306", "task"
            ),
        )
    )
    assert "Tarea en marcha" in web.get("/agentes").text
    assert "Tarea en marcha" in web.get("/panel").text


def test_the_card_and_the_agents_own_page_say_which_agent_it_is(web: TestClient) -> None:
    assert CLAUDE in web.get("/panel").text
    assert CLAUDE in web.get("/agentes/codigo/ahora").text


def test_a_deleted_agent_is_retired_and_has_no_buttons(web: TestClient, orders: FakeOrders) -> None:
    orders.facts = Listing(
        orders.facts.agents,
        (
            RetiredAgent(
                "viejo",
                "Viejo",
                datetime(2026, 11, 1, 9, tzinfo=UTC),
                datetime(2026, 11, 8, 9, tzinfo=UTC),
                purged=False,
            ),
            RetiredAgent("vaciado", None, None, None, purged=True),
        ),
    )
    page = web.get("/agentes").text
    assert "Retirados" in page and "retirado" in page
    assert "sudo backtide agentes recuperar viejo" in page
    assert "agente=viejo" not in page and "agente=vaciado" not in page
    assert ES["agents.retired.purged"] in page


def test_a_stopped_agent_offers_to_start_and_a_running_one_to_stop(
    web: TestClient, orders: FakeOrders
) -> None:
    page = web.get("/agentes").text
    assert "v=parar&amp;agente=codigo" in page and "v=pausar&amp;agente=codigo" in page
    assert "v=arrancar" not in page
    orders.facts = Listing(
        (
            orders.facts.agents[0],
            AgentFacts("codigo", "Código", False, False, STOPPED_BY_OWNER, "claude-code"),
        )
    )
    page = web.get("/agentes").text
    assert "v=arrancar&amp;agente=codigo" in page and "v=parar" not in page


def test_the_main_agent_has_no_button(web: TestClient) -> None:
    page = web.get("/agentes").text
    assert "agente=principal" not in page
    for verb in ("parar", "pausar", "seguir", "arrancar", "borrar"):
        said = web.get(f"/agentes/orden?v={verb}&agente=principal")
        assert 'name="ticket"' not in said.text and "principal" in said.text


@pytest.mark.parametrize(
    ("facts", "asked", "word"),
    [
        (AgentFacts("x", watched=True, state="running"), None, "running"),
        (AgentFacts("x", watched=True, state="frozen"), None, "frozen"),
        (AgentFacts("x", watched=True, state="stopped"), None, "still"),
        (AgentFacts("x", watched=False, state=STOPPED_BY_OWNER), None, "stopped"),
        (AgentFacts("x", watched=False), None, "unwatched"),
        # An order first: "stopped" is not true until it ends, whatever the mark says.
        (AgentFacts("x", watched=False, state=STOPPED_BY_OWNER, order=STOPPING), None, STOPPING),
        (AgentFacts("x", watched=False, state=STOPPED_BY_OWNER, order=STOP_FAILED), None,
         STOP_FAILED),
        (AgentFacts("x", watched=True, state="running"), "parar", STOPPING),
        (AgentFacts("x", watched=True, state="running"), "pausar", "pausing"),
        (None, None, "unknown"),
    ],
)  # fmt: skip
def test_what_a_row_says(facts: AgentFacts | None, asked: str | None, word: str) -> None:
    assert word_of(facts, asked) == word
    assert f"agents.state.{word}" in ES and f"agents.state.{word}" in EN


def test_one_coming_up_cannot_be_stopped_from_here_and_says_where_it_can(
    web: TestClient, orders: FakeOrders
) -> None:
    """Its start does not look at a stop until it ends (``Guardian.run``): a button would promise
    what it cannot do, so the row says how long, and where the brake is."""
    assert STARTING not in ACTIONS_OF
    orders.facts = Listing(
        (
            orders.facts.agents[0],
            AgentFacts("codigo", "Código", False, False, None, "claude-code", order=STARTING),
        )
    )
    page = web.get("/agentes").text
    assert "v=parar" not in page and "sudo backtide agentes parar codigo" in page
    assert ES["agents.state.starting"] in page


def test_a_row_being_changed_offers_nothing() -> None:
    busy = AgentFacts("x", watched=False, state=STOPPED_BY_OWNER, order=STOPPING)
    assert row_of("x", None, False, 1, None, busy, None).actions == ()
    assert row_of("x", None, False, 1, None, AgentFacts("x"), "parar").actions == ()
    stuck = AgentFacts("x", watched=False, state=STOPPED_BY_OWNER, order=STOP_FAILED)
    assert row_of("x", None, False, 1, None, stuck, None).actions == ("parar",)
    assert row_of("x", None, True, 1, None, AgentFacts("x", state="running"), None).actions == ()
    assert row_of("x", None, False, 1, None, None, None).actions == ()


def test_the_list_lives_on_its_stream(tmp_path: Path, orders: FakeOrders) -> None:
    new_box(tmp_path).append("system", "agent_start", "agent")
    web = new_client(tmp_path, agent_orders=orders, stream_seconds=0.05, poll_interval=0.01)
    assert 'sse-swap="list"' in web.get("/agentes").text
    stream = web.get("/agentes/stream")
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert stream.headers["content-security-policy"] == CSP
    assert "event: list" in stream.text and "OpenClaw 2026.9.8" in stream.text


def test_the_stream_is_for_a_session(tmp_path: Path, orders: FakeOrders) -> None:
    new_box(tmp_path).append("system", "agent_start", "agent")
    web = new_client(tmp_path, agent_orders=orders, logged_in=False)
    assert web.get("/agentes").status_code == 401
    assert web.get("/agentes/stream").status_code == 401
    assert web.get("/agentes/nuevo").status_code == 401
    assert web.get("/agentes/orden?v=parar&agente=codigo").status_code == 401
    assert web.get("/agentes/en-curso?id=x").status_code == 401


# --- without --gestionar ------------------------------------------------------------------------


def test_without_it_the_list_is_read_only_and_there_is_no_door(tmp_path: Path) -> None:
    new_box(tmp_path).append("system", "agent_start", "agent")
    orders = FakeOrders()
    orders.enabled = False
    orders.state = Availability.DISABLED
    web = new_client(tmp_path, agent_orders=orders)
    page = web.get("/agentes").text
    assert "--gestionar" in page and "/agentes/nuevo" not in page and "v=parar" not in page
    assert 'name="ticket"' not in web.get("/agentes/nuevo").text
    for path in (AGENT_CREATE_PATH, AGENT_ORDER_PATH):
        assert web.post(path, data={}, headers=POST_HEADERS).status_code == 405
    assert not orders.asked


def test_on_roots_socket_it_stays_off_whatever_the_flag_says(tmp_path: Path) -> None:
    """There an order would carry no session and no key."""
    assert ControlAgentOrders(tmp_path / "c.sock", lambda: None, enabled=True).enabled is False
    on = ControlAgentOrders(tmp_path / "c.sock", lambda: None, enabled=True, server_uid=0)
    assert on.enabled is True
    off = ControlAgentOrders(tmp_path / "c.sock", lambda: None, enabled=False, server_uid=0)
    assert off.enabled is False and off.availability() is Availability.DISABLED


# --- the form -----------------------------------------------------------------------------------


def test_the_form_has_a_slug_and_two_lists_and_nothing_else(web: TestClient) -> None:
    page = web.get("/agentes/nuevo").text
    named = re.findall(r'<(?:input|select|textarea)[^>]*\bname="(\w+)"', page)
    assert set(named) == {"csrf", "ticket", "slug", "perfil", "tamano"}
    assert re.findall(r'<option value="([^"]*)"', page) == [
        "claude-code", "openclaw", "10", "20", "50",
    ]  # fmt: skip
    assert "custom" not in page and "<textarea" not in page and CLAUDE in page


def test_a_good_form_asks_for_exactly_three_fields(web: TestClient, orders: FakeOrders) -> None:
    orders.reply = {"ok": True, "outcome": "created", "message": "Creado."}
    sent = post(web, AGENT_CREATE_PATH, create_form(web))
    assert sent.status_code == 303
    page = wait_done(web, sent.headers["location"].removeprefix(PREFIX_PATH))
    assert "Agente creado y en marcha" in page.text
    assert orders.asked == [
        (
            {"cmd": "agent_create", "slug": "tercero", "profile": "claude-code", "volume_gib": 10},
            SESSION,
        )
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("perfil", "custom"),
        ("perfil", "../../etc/passwd"),
        ("perfil", ""),
        ("tamano", "7"),
        ("tamano", "010"),
        ("tamano", "1e1"),
        ("tamano", ""),
        ("slug", "../x"),
        ("slug", "/etc"),
        ("slug", "principal"),
        ("slug", "Mayus"),
        ("slug", ""),
    ],
)
def test_what_is_off_the_lists_asks_nothing(
    web: TestClient, orders: FakeOrders, field: str, value: str
) -> None:
    sent = post(web, AGENT_CREATE_PATH, {**create_form(web), field: value})
    assert sent.status_code == 400 and 'data-view="new"' in sent.text
    assert not orders.asked


@pytest.mark.parametrize("extra", ["image", "mounts", "privileged", "restart", "name", "memory"])
def test_a_field_of_more_is_no_form(web: TestClient, orders: FakeOrders, extra: str) -> None:
    sent = post(web, AGENT_CREATE_PATH, {**create_form(web), extra: "x"})
    assert sent.status_code == 400 and not orders.asked


def test_a_slug_in_the_form_comes_back_escaped(web: TestClient) -> None:
    sent = post(web, AGENT_CREATE_PATH, {**create_form(web), "slug": '"><script>x</script>'})
    assert sent.status_code == 400 and "<script>x" not in sent.text
    assert "&lt;script&gt;" in sent.text


def test_a_form_of_another_session_and_a_ticket_used_or_made_up(
    web: TestClient, orders: FakeOrders
) -> None:
    form = create_form(web)
    assert post(web, AGENT_CREATE_PATH, {**form, "csrf": "x" * 20}).status_code == 403
    assert post(web, AGENT_CREATE_PATH, {**form, "ticket": "x" * 20}).status_code == 400
    assert not orders.asked
    assert post(web, AGENT_CREATE_PATH, form).status_code == 303
    again = post(web, AGENT_CREATE_PATH, form)
    assert again.status_code == 400 and ES["manage.err.used"] in again.text
    assert len(orders.asked) == 1


def test_a_post_from_another_site_never_gets_there(web: TestClient, orders: FakeOrders) -> None:
    form = create_form(web)
    for headers in (
        {"origin": "https://otro.ejemplo.test", "sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-origin"},
    ):
        sent = web.post(AGENT_CREATE_PATH, data=form, headers=headers)
        assert sent.status_code == 403
    assert not orders.asked


def test_a_cookie_is_what_a_post_takes(tmp_path: Path, orders: FakeOrders) -> None:
    new_box(tmp_path).append("system", "agent_start", "agent")
    web = new_client(tmp_path, agent_orders=orders, logged_in=False)
    sent = web.post(
        AGENT_CREATE_PATH,
        data={"csrf": "x", "ticket": "x", "slug": "x", "perfil": "openclaw", "tamano": "10"},
        headers=POST_HEADERS,
    )
    assert sent.status_code == 401 and not orders.asked


# --- the key ------------------------------------------------------------------------------------


class Touchy:
    """An access whose session has to touch its key, as the installed web's."""

    passwords = True

    def __init__(self) -> None:
        self.sessions = Sessions()
        self.sessions.preset(SESSION)
        self.needs = True

    def open(self, token: str) -> Any:
        return None

    def session_of(self, cookie: str | None, *, use: bool = True) -> Any:
        return self.sessions.check(SESSION, use=use)

    def end(self, session_id: str, *, every: bool = False) -> bool:
        return True

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        return {"ok": True, "needs": self.needs}


@pytest.fixture
def touchy(tmp_path: Path, orders: FakeOrders) -> tuple[TestClient, Touchy]:
    new_box(tmp_path).append("system", "agent_start", "agent")
    other = new_box_at(tmp_path / "codigo")
    other.append("system", "agent_start", "agent")
    access = Touchy()
    web = new_client(
        tmp_path,
        agent_orders=orders,
        access=access,
        others=[source_of(tmp_path / "codigo", "codigo", "Código")],
    )
    return web, access


def test_creating_sends_you_to_touch_the_key_first(
    touchy: tuple[TestClient, Touchy], orders: FakeOrders
) -> None:
    web, access = touchy
    sent = web.get("/agentes/nuevo", follow_redirects=False)
    assert sent.status_code == 303 and "/tocar?volver=agentes-nuevo" in sent.headers["location"]
    access.needs = False
    form = create_form(web)
    access.needs = True  # it went by while the form was being filled in
    sent = post(web, AGENT_CREATE_PATH, form)
    assert sent.status_code == 303 and "/tocar?volver=agentes-nuevo" in sent.headers["location"]
    assert not orders.asked


def test_deleting_sends_you_to_touch_the_key_and_stopping_does_not(
    touchy: tuple[TestClient, Touchy], orders: FakeOrders
) -> None:
    web, _ = touchy
    sent = web.get("/agentes/orden?v=borrar&agente=codigo", follow_redirects=False)
    assert sent.status_code == 303 and "/tocar?volver=agentes" in sent.headers["location"]
    assert 'name="ticket"' in web.get("/agentes/orden?v=parar&agente=codigo").text


def test_the_touch_page_goes_back_to_the_form(touchy: tuple[TestClient, Touchy]) -> None:
    web, _ = touchy
    page = web.get("/tocar?volver=agentes-nuevo", headers={"host": "backtide.localhost:8765"})
    assert f'data-target="{PREFIX_PATH}/agentes/nuevo"' in page.text


# --- the orders ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("verb", "command"),
    [
        ("parar", "agent_stop"),
        ("arrancar", "agent_start"),
        ("pausar", "agent_pause"),
        ("seguir", "agent_resume"),
    ],
)
def test_each_order_goes_to_the_service_with_its_session(
    web: TestClient, orders: FakeOrders, verb: str, command: str
) -> None:
    sent = post(web, AGENT_ORDER_PATH, order_form(web, verb))
    assert sent.status_code == 303
    assert orders.asked == [({"cmd": command, "agent": "codigo"}, SESSION)]


def test_a_ticket_is_of_one_order_about_one_agent(web: TestClient, orders: FakeOrders) -> None:
    form = order_form(web, "parar")
    assert post(web, AGENT_ORDER_PATH, {**form, "v": "pausar"}).status_code == 400
    assert not orders.asked
    form = order_form(web, "parar")
    assert post(web, AGENT_ORDER_PATH, {**form, "agente": "principal"}).status_code == 400
    assert post(web, AGENT_ORDER_PATH, {**form, "agente": "nadie"}).status_code == 404
    assert post(web, AGENT_ORDER_PATH, {**form, "agente": "../principal"}).status_code == 404
    assert post(web, AGENT_ORDER_PATH, {**form, "v": "vaciar"}).status_code == 404
    assert post(web, AGENT_ORDER_PATH, {**form, "v": "recuperar"}).status_code == 404
    assert not orders.asked


def test_the_trash_has_no_verb_here(web: TestClient) -> None:
    for verb in ("vaciar", "recuperar", "agent_purge", "agent_restore"):
        page = web.get(f"/agentes/orden?v={verb}&agente=codigo")
        assert page.status_code == 404 and 'name="ticket"' not in page.text


def test_deleting_wants_the_name_written(web: TestClient, orders: FakeOrders) -> None:
    form = order_form(web, "borrar")
    assert (
        "sudo backtide agentes recuperar codigo"
        in web.get("/agentes/orden?v=borrar&agente=codigo").text
    )
    assert post(web, AGENT_ORDER_PATH, form).status_code == 400  # no name
    wrong = post(web, AGENT_ORDER_PATH, {**form, "escrito": "otro"})
    assert wrong.status_code == 400 and ES["manage.err.typed"] in wrong.text
    assert not orders.asked
    sent = post(web, AGENT_ORDER_PATH, {**form, "escrito": "codigo"})
    assert sent.status_code == 303
    assert orders.asked == [
        ({"cmd": "agent_delete", "agent": "codigo", "typed": "codigo"}, SESSION)
    ]


# --- an order that takes minutes ----------------------------------------------------------------


def test_a_long_stop_does_not_hang_the_page_nor_say_it_stopped(
    web: TestClient, orders: FakeOrders
) -> None:
    orders.hold = threading.Event()
    form = order_form(web, "parar")
    sent = post(web, AGENT_ORDER_PATH, form)
    assert sent.status_code == 303  # at once, with the order still running
    assert orders.holding.wait(WAIT)
    location = sent.headers["location"].removeprefix(PREFIX_PATH)
    page = web.get(location)
    assert 'data-view="running"' in page.text and "Parando…" in page.text
    assert ES["agents.running.note"] in page.text
    assert '<meta http-equiv="refresh"' in page.text
    assert ES["agents.out.stopped"] not in page.text
    # The list says it too, and offers nothing about it meanwhile.
    listing = web.get("/agentes").text
    assert "parando…" in listing and "v=parar&amp;agente=codigo" not in listing
    # A second one is told so, and is not sent.
    again = post(web, AGENT_ORDER_PATH, order_form(web, "pausar"))
    assert again.status_code == 409 and len(orders.asked) == 1
    assert ES["manage.err.running"] in again.text

    orders.hold.set()
    page = wait_done(web, location)
    assert ES["agents.out.stopped"] in page.text and "Agente parado." in page.text
    assert '<meta http-equiv="refresh"' not in page.text


@pytest.mark.parametrize(
    ("error", "said"),
    [
        (ControlOutcomeUnknown("perdida"), "agents.out.unknown"),
        (ControlUnavailable("nadie"), "agents.out.no_service"),
        (RuntimeError("algo"), "agents.out.unknown"),
    ],
)
def test_an_order_whose_end_nobody_knows_says_so(
    web: TestClient, orders: FakeOrders, error: Exception, said: str
) -> None:
    orders.fails = error
    sent = post(web, AGENT_ORDER_PATH, order_form(web, "parar"))
    page = wait_done(web, sent.headers["location"].removeprefix(PREFIX_PATH))
    assert ES[said] in page.text and ES["agents.out.stopped"] not in page.text
    assert ES["agents.out.look"] in page.text


@pytest.mark.parametrize(
    ("reply", "said"),
    [
        ({"ok": False, "outcome": "refused", "message": "Ya hay otra orden."}, "agents.out.no"),
        ({"ok": False, "outcome": "busy", "message": "Espera."}, "agents.out.no"),
        ({"ok": False, "outcome": "failed", "message": "No se ha podido."}, "agents.out.failed"),
        ({"ok": False, "outcome": "still_running", "message": "Sigue."}, "agents.out.failed"),
        ({"ok": True, "outcome": "stopped", "message": "Parado."}, "agents.out.stopped"),
        ({"ok": True, "outcome": "other", "message": "Hecho."}, "agents.out.ok"),
    ],
)
def test_what_the_page_says_is_what_the_service_said(
    web: TestClient, orders: FakeOrders, reply: dict[str, Any], said: str
) -> None:
    orders.reply = reply
    sent = post(web, AGENT_ORDER_PATH, order_form(web, "parar"))
    page = wait_done(web, sent.headers["location"].removeprefix(PREFIX_PATH))
    assert ES[said] in page.text and reply["message"] in page.text


def test_stopping_while_it_came_up_does_not_read_as_started(
    web: TestClient, orders: FakeOrders
) -> None:
    orders.reply = {"ok": True, "outcome": "stopped", "message": "No sigue."}
    sent = post(web, AGENT_ORDER_PATH, order_form(web, "arrancar"))
    page = wait_done(web, sent.headers["location"].removeprefix(PREFIX_PATH))
    assert ES["agents.out.started"] not in page.text and ES["agents.out.stopped"] in page.text


def test_the_first_neighbour_says_the_exact_command(web: TestClient, orders: FakeOrders) -> None:
    orders.reply = {"ok": False, "outcome": "needs_restart", "message": "Hay que reiniciar."}
    sent = post(web, AGENT_CREATE_PATH, create_form(web))
    page = wait_done(web, sent.headers["location"].removeprefix(PREFIX_PATH))
    assert ES["agents.out.no"] in page.text
    assert (
        "sudo backtide agentes crear tercero --perfil claude-code --volumen 10 --reiniciar"
        in page.text
    )
    # Never a checkbox here that would say yes for the main agent.
    assert 'name="restart"' not in page.text and 'type="checkbox"' not in page.text


def test_an_order_this_web_does_not_know_is_said_to_be_unknown(web: TestClient) -> None:
    for given in ("nada", "x" * 500, ""):
        page = web.get(f"/agentes/en-curso?id={given}")
        assert page.status_code == 200 and ES["agents.lost"] in page.text


def test_the_book_takes_one_order_per_agent_and_keeps_no_session() -> None:
    hold = threading.Event()
    seen: list[str | None] = []

    def ask(request: dict[str, Any], session: str | None) -> dict[str, Any]:
        seen.append(session)
        hold.wait(WAIT)
        return {"ok": True, "outcome": "stopped", "message": ""}

    book = OrderBook(ask)
    first = book.start("parar", "a", {"cmd": "agent_stop", "agent": "a"}, "la-sesion")
    assert isinstance(first, Order)
    assert book.start("pausar", "a", {"cmd": "agent_pause", "agent": "a"}, "la-sesion") is None
    assert book.running() == {"a": "parar"}
    for slug in ("b", "c", "d"):
        assert book.start("parar", slug, {"cmd": "agent_stop"}, "la-sesion") is not None
    assert book.start("parar", "e", {"cmd": "agent_stop"}, "la-sesion") is None  # too many
    assert "la-sesion" not in repr(first)
    hold.set()
    assert first.done.wait(WAIT) and first.what == "asked"
    assert book.find(first.id) is first and book.find("otro") is None


def test_the_book_forgets_the_oldest_of_those_that_ended() -> None:
    book = OrderBook(lambda request, session: {"ok": True, "outcome": "x", "message": ""})
    ids = []
    for index in range(40):
        order = book.start("parar", f"a{index}", {"cmd": "agent_stop"}, None)
        assert order is not None and order.done.wait(WAIT)
        ids.append(order.id)
    assert book.find(ids[0]) is None and book.find(ids[-1]) is not None


# --- both ends, over a real socket --------------------------------------------------------------


@pytest.fixture
def short_folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vt"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def test_the_real_client_reaches_the_real_socket_with_the_session(short_folder: Path) -> None:
    sessions = Sessions()
    sessions.preset(SESSION)
    fleet = FakeFleet()

    def peer(sock: socket.socket) -> tuple[int, int, int]:
        return 4242, ME, GROUP

    server = WebControlServer(
        FakeGuardian(),
        short_folder / "web.sock",
        group=GROUP,
        snapshots=list,
        peer=peer,
        sessions=sessions,
        on_entry=lambda action, details: True,
        fleet=fleet,
    )
    server.start()
    try:
        client = ControlAgentOrders(
            short_folder / "web.sock", lambda: None, enabled=True, server_uid=ME, peer=peer
        )
        stop = {"cmd": "agent_stop", "agent": "revisor"}
        assert client.ask(stop, SESSION)["ok"] is True
        assert fleet.calls[0][1] == stop and fleet.calls[0][2].startswith("web (uid ")
        assert client.ask(stop, "otra-sesion")["outcome"] == "refused"
        assert client.ask(stop, None)["outcome"] == "refused"
        assert len(fleet.calls) == 1
    finally:
        server.close()
