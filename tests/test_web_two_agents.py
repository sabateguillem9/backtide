"""T26-2d: the web with the service's list of agents, rewinding and approving on each of them.

The first half is the pages over fakes: what each page names and what each order carries. The
second is the web over a real ``WebControlServer`` with a real ``Roster``, on a real Unix socket:
what the service is really told, and that it, not the web, decides who an order is about."""

import os
import shutil
import tempfile
import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

import backtide.web.app as app_module
from backtide.blackbox import BlackBox
from backtide.service.config import AGENTS_FOLDER, STATE_DB
from backtide.service.control import ControlError, ask_rewind
from backtide.service.roster import Desk, Roster
from backtide.service.sessions import Sessions
from backtide.service.web_control import WebControlServer
from backtide.snapshots import Reason, Snapshot
from backtide.web import BoxReader, live
from backtide.web.agents import AgentSource
from backtide.web.approve import ControlApprover
from backtide.web.live import LiveAgents
from backtide.web.paths import WebPaths
from backtide.web.rewind import Availability, ControlRewinder
from backtide.web.security import ServiceAccess
from tests import test_web_decide as decide
from tests.conftest import FakeClock
from tests.test_service_agent_orders import Agent
from tests.test_service_web_control import GROUP, the_web
from tests.test_web_panel import request
from tests.test_web_rewind import POST_HEADERS, FakeRewinder, form_of, text_of
from tests.webkit import (
    KEY,
    PREFIX_PATH,
    SESSION,
    START,
    WatchedReader,
    new_box,
    new_client,
    parse_sse,
)

NOW = decide.NOW  # while the held requests of tests.test_web_decide still wait
ME = os.geteuid()
REWIND = "/instantaneas/rebobinar"
DECIDE = "/peticiones/decidir"
SLUG = "revisor"
NAME = "Revisor de código"
MAIN_SNAP = Snapshot(NOW - timedelta(minutes=20), str(Reason.PERIODIC))
OTHER_SNAP = Snapshot(NOW - timedelta(minutes=10), str(Reason.PERIODIC))
HOLD_A, HOLD_B = "h-aaaaaaaaaaaa", "h-bbbbbbbbbbbb"
FOR_AGENT = "Para el agente"


def other_box(tmp_path: Path, slug: str = SLUG) -> BlackBox:
    home = tmp_path / "agents" / slug
    home.mkdir(parents=True)
    return BlackBox(home / "blackbox.db", KEY, checkpoint_path=home / "cp", clock=FakeClock(START))


class Rewinder(FakeRewinder):
    """A fake that writes down who each rewind was about."""

    def __init__(self) -> None:
        super().__init__()
        self.about: list[tuple[str, str | None]] = []

    def rewind(self, snapshot_id: str, *, agent: str | None = None) -> dict[str, Any]:
        self.about.append((snapshot_id, agent))
        return self.reply


class Approver(decide.FakeApprover):
    """A fake with each agent's own lists, that writes down who each order was about."""

    def __init__(self) -> None:
        super().__init__()
        self.of: dict[str | None, list[dict[str, Any]]] = {
            None: [decide.hold(HOLD_A, seq=None)],
            SLUG: [decide.hold(HOLD_B, seq=None)],
        }
        self.orders: list[tuple[str, str, str | None]] = []
        self.failing: set[str | None] = set()
        self.asked: list[str | None] = []

    def holds(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        self.asked.append(agent)
        if agent in self.failing:
            raise ControlError("it cannot say")
        return self.of[agent]

    def decide(self, hold_id: str, verdict: str, *, agent: str | None = None) -> dict[str, Any]:
        self.orders.append((verdict, hold_id, agent))
        return {"ok": True, "outcome": "released", "message": "Hecho."}

    def trust(self, hold_id: str, *, agent: str | None = None) -> dict[str, Any]:
        self.orders.append(("trust", hold_id, agent))
        return {"ok": True, "outcome": "trusted", "message": "Hecho.", "hold": "released"}

    def trusted(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        tail = "aaaaaaaa" if agent is None else "bbbbbbbb"
        return [{"trust_id": f"t-{tail}", "translator": "telegram", "recipient": f"55{tail}",
                 "added_at": "2026-10-16T09:00:00Z", "by": "web"}]  # fmt: skip

    def untrust(self, trust_id: str, *, agent: str | None = None) -> dict[str, Any]:
        self.orders.append(("untrust", trust_id, agent))
        return {"ok": True, "outcome": "removed", "message": "Hecho."}

    def batches(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        tail = "aaaaaaaa" if agent is None else "bbbbbbbb"
        return [{"rule_id": f"b-{tail}", "scope": "kind", "translator": None, "method": "POST",
                 "host": "api.ejemplo.dev", "route": f"/{tail}/*", "until": "2026-10-16T11:00:00Z",
                 "uses": 1}]  # fmt: skip

    def end_batch(self, rule_id: str, *, agent: str | None = None) -> dict[str, Any]:
        self.orders.append(("end_batch", rule_id, agent))
        return {"ok": True, "outcome": "ended", "message": "Hecho."}


def source(tmp_path: Path, **changes: Any) -> AgentSource:
    values: dict[str, Any] = {
        "slug": SLUG,
        "name": NAME,
        "reader": BoxReader(tmp_path / "agents" / SLUG / "blackbox.db"),
        "snapshots": lambda: [OTHER_SNAP],
        "notice_lines": ("Lo que dice el perfil de este agente.",),
    }
    return AgentSource(**(values | changes))


@pytest.fixture
def boxes(tmp_path: Path) -> dict[str, BlackBox]:
    main, other = new_box(tmp_path), other_box(tmp_path)
    main.append("exec", "run", "del-principal")
    other.append("exec", "run", "del-vecino")
    return {"main": main, "other": other}


@pytest.fixture
def rewinder() -> Rewinder:
    return Rewinder()


@pytest.fixture
def approver() -> Approver:
    return Approver()


@pytest.fixture
def web(tmp_path: Path, boxes: dict, rewinder: Rewinder, approver: Approver) -> TestClient:
    return new_client(
        tmp_path,
        clock=lambda: NOW,
        agent_name="Principal",
        snapshots=lambda: [MAIN_SNAP],
        others=[source(tmp_path)],
        rewinder=rewinder,
        approver=approver,
    )


def post_rewind(web: TestClient, fields: dict[str, str]) -> Any:
    return web.post(REWIND, data=fields, headers=POST_HEADERS)


def post_decide(web: TestClient, fields: dict[str, str]) -> Any:
    return web.post(DECIDE, data=fields, headers=decide.POST_HEADERS)


def rewind_form(web: TestClient, snapshot: Snapshot = OTHER_SNAP) -> dict[str, str]:
    page = web.get(f"/agentes/{SLUG}{REWIND}?{urlencode({'id': snapshot.id})}")
    assert page.status_code == 200 and 'name="ticket"' in page.text, text_of(page.text)[:400]
    return form_of(page.text)


def decide_form(web: TestClient, verb: str, subject: str = HOLD_B) -> dict[str, str]:
    page = web.get(f"/agentes/{SLUG}{DECIDE}?{urlencode({'id': subject, 'v': verb})}")
    assert page.status_code == 200 and 'name="ticket"' in page.text, text_of(page.text)[:400]
    return form_of(page.text)


# -- one agent: as it always was ------------------------------------------------------------------


def test_with_one_agent_the_rewind_says_no_agent_anywhere(
    tmp_path: Path, rewinder: Rewinder
) -> None:
    new_box(tmp_path)
    web = new_client(tmp_path, clock=lambda: NOW, snapshots=lambda: [MAIN_SNAP], rewinder=rewinder)
    page = web.get(f"{REWIND}?{urlencode({'id': MAIN_SNAP.id})}").text
    assert FOR_AGENT not in text_of(page) and 'name="agente"' not in page
    assert "agentbar" not in page, "the confirmation of one agent looks as it did"
    assert set(form_of(page)) == {"csrf", "id", "ticket"}
    assert post_rewind(web, form_of(page)).status_code == 200
    assert FOR_AGENT not in text_of(post_rewind(web, form_of(page)).text)
    assert rewinder.about == [(MAIN_SNAP.id, None)], (
        "not even its own name: the order it always was"
    )


def test_with_one_agent_the_decision_says_no_agent_anywhere(
    tmp_path: Path, approver: Approver
) -> None:
    new_box(tmp_path)
    web = new_client(tmp_path, clock=lambda: NOW, approver=approver)
    panel = web.get("/panel").text
    assert f"{PREFIX_PATH}{DECIDE}?id={HOLD_A}" in panel and "/agentes/" not in panel
    page = web.get(f"{DECIDE}?{urlencode({'id': HOLD_A, 'v': 'aprobar'})}").text
    assert FOR_AGENT not in text_of(page)
    assert set(form_of(page)) == {"csrf", "id", "ticket", "v"}
    assert post_decide(web, form_of(page)).status_code == 200
    assert approver.orders == [("approve", HOLD_A, None)]
    assert approver.asked and set(approver.asked) == {None}


# -- rewinding the second one ----------------------------------------------------------------------


def test_each_agents_snapshots_lead_to_its_own_confirmation(web: TestClient) -> None:
    mine = web.get("/instantaneas").text
    theirs = web.get(f"/agentes/{SLUG}/instantaneas").text
    assert f"{PREFIX_PATH}{REWIND}?id={MAIN_SNAP.id}" in mine and OTHER_SNAP.id not in mine
    assert f"{PREFIX_PATH}/agentes/{SLUG}{REWIND}?id={OTHER_SNAP.id}" in theirs
    assert MAIN_SNAP.id not in theirs


def test_the_second_agent_is_rewound_and_the_page_says_it_is_that_one(
    web: TestClient, rewinder: Rewinder
) -> None:
    page = web.get(f"/agentes/{SLUG}{REWIND}?{urlencode({'id': OTHER_SNAP.id})}").text
    said = text_of(page)
    assert f"{FOR_AGENT} {NAME}" in said
    assert "Lo que dice el perfil de este agente." in said, "its own lines of the notice"
    assert form_of(page)["agente"] == SLUG
    done = post_rewind(web, form_of(page))
    assert 'data-outcome="done"' in done.text and f"{FOR_AGENT} {NAME}" in text_of(done.text)
    assert rewinder.about == [(OTHER_SNAP.id, SLUG)]
    assert f"/agentes/{SLUG}/instantaneas" in done.text, "back to its own list"


def test_the_main_one_is_named_too_when_there_are_several(
    web: TestClient, rewinder: Rewinder
) -> None:
    page = web.get(f"{REWIND}?{urlencode({'id': MAIN_SNAP.id})}").text
    assert f"{FOR_AGENT} Principal" in text_of(page)
    assert "agente" not in form_of(page), "an order about it still names no agent"
    assert post_rewind(web, form_of(page)).status_code == 200
    assert rewinder.about == [(MAIN_SNAP.id, None)]


def test_a_snapshot_of_one_is_not_in_the_others_list(web: TestClient, rewinder: Rewinder) -> None:
    page = web.get(f"/agentes/{SLUG}{REWIND}?{urlencode({'id': MAIN_SNAP.id})}")
    assert 'name="ticket"' not in page.text
    assert rewinder.about == []


@pytest.mark.parametrize("change", [{"agente": "principal"}, {"agente": None}])
def test_a_form_for_one_does_nothing_to_another(
    web: TestClient, rewinder: Rewinder, change: dict[str, str | None]
) -> None:
    """Changing whom it is about leaves the ticket, which was for that agent, good for nothing:
    the id is even in the other's list."""
    fields = rewind_form(web)
    fields.update({k: v for k, v in change.items() if v is not None})
    if change["agente"] is None:
        del fields["agente"]
    fields["id"] = MAIN_SNAP.id
    answer = post_rewind(web, fields)
    assert answer.status_code == 400 and rewinder.about == []


@pytest.mark.parametrize("to_the_main", [True, False])
def test_the_ticket_is_what_says_whose_even_with_the_same_snapshot_in_both(
    tmp_path: Path, boxes: dict, rewinder: Rewinder, to_the_main: bool
) -> None:
    """The list would let it through, so only the ticket can stop it, and it says it has."""
    web = new_client(
        tmp_path,
        clock=lambda: NOW,
        snapshots=lambda: [OTHER_SNAP],
        others=[source(tmp_path)],
        rewinder=rewinder,
    )
    path = f"/agentes/{SLUG}{REWIND}" if to_the_main else REWIND
    fields = form_of(web.get(f"{path}?{urlencode({'id': OTHER_SNAP.id})}").text)
    if to_the_main:
        del fields["agente"]
    else:
        fields["agente"] = SLUG
    answer = post_rewind(web, fields)
    assert answer.status_code == 400 and "Esta confirmación ya no vale" in text_of(answer.text)
    assert rewinder.about == []


def test_a_ticket_for_the_main_one_does_nothing_to_the_second(
    web: TestClient, rewinder: Rewinder
) -> None:
    fields = form_of(web.get(f"{REWIND}?{urlencode({'id': MAIN_SNAP.id})}").text)
    assert post_rewind(web, {**fields, "agente": SLUG}).status_code == 400
    assert rewinder.about == []


def test_an_invented_agent_is_nothing_here_and_nothing_is_asked(
    web: TestClient, rewinder: Rewinder
) -> None:
    for slug in ("nadie", "%2e%2e%2fetc", "a" * 40):
        page = web.get(f"/agentes/{slug}{REWIND}?id={OTHER_SNAP.id}")
        assert page.status_code == 404 and "Aquí no hay nada" in page.text
    fields = rewind_form(web)
    for slug in ("nadie", "../revisor", "/etc", "a" * 40):
        answer = post_rewind(web, {**fields, "agente": slug})
        assert answer.status_code == 404 and "Aquí no hay nada" in answer.text
    assert rewinder.about == []
    assert post_rewind(web, fields).status_code == 200, "a wrong name spent nothing"


def test_without_a_session_nothing_says_who_exists(
    tmp_path: Path, boxes: dict, rewinder: Rewinder
) -> None:
    web = new_client(
        tmp_path,
        logged_in=False,
        clock=lambda: NOW,
        snapshots=lambda: [MAIN_SNAP],
        others=[source(tmp_path)],
        rewinder=rewinder,
    )
    known = web.get(f"/agentes/{SLUG}{REWIND}?id={OTHER_SNAP.id}")
    invented = web.get(f"/agentes/nadie{REWIND}?id={OTHER_SNAP.id}")
    assert known.status_code == invented.status_code == 401
    answer = post_rewind(web, {"csrf": "x", "ticket": "y", "id": OTHER_SNAP.id, "agente": SLUG})
    assert answer.status_code == 401 and rewinder.about == []


def test_a_form_of_another_session_does_nothing(web: TestClient, rewinder: Rewinder) -> None:
    fields = rewind_form(web)
    assert post_rewind(web, {**fields, "csrf": "of-another"}).status_code == 403
    assert rewinder.about == []


def test_a_rewind_of_one_does_not_keep_the_other_waiting(tmp_path: Path, boxes: dict) -> None:
    class Slow(Rewinder):
        def __init__(self) -> None:
            super().__init__()
            self.gate, self.entered = threading.Event(), threading.Event()

        def rewind(self, snapshot_id: str, *, agent: str | None = None) -> dict[str, Any]:
            if agent is None:
                self.entered.set()
                assert self.gate.wait(10)
            return super().rewind(snapshot_id, agent=agent)

    slow = Slow()
    web = new_client(
        tmp_path,
        clock=lambda: NOW,
        snapshots=lambda: [MAIN_SNAP],
        others=[source(tmp_path)],
        rewinder=slow,
    )
    theirs = rewind_form(web)
    mine = form_of(web.get(f"{REWIND}?{urlencode({'id': MAIN_SNAP.id})}").text)
    first = threading.Thread(target=post_rewind, args=(web, mine))
    first.start()
    assert slow.entered.wait(10)
    try:
        assert 'data-outcome="done"' in post_rewind(web, theirs).text
        assert slow.about == [(OTHER_SNAP.id, SLUG)]
    finally:
        slow.gate.set()
        first.join()


# -- approving on each ---------------------------------------------------------------------------


def test_the_panel_lists_what_waits_of_each_with_its_own_links(web: TestClient) -> None:
    panel = web.get("/panel").text
    assert f"{PREFIX_PATH}{DECIDE}?id={HOLD_A}&amp;v=aprobar" in panel
    assert f"{PREFIX_PATH}/agentes/{SLUG}{DECIDE}?id={HOLD_B}&amp;v=aprobar" in panel
    assert f"{PREFIX_PATH}/agentes/{SLUG}/peticiones/ver?id={HOLD_B}" in panel


@pytest.mark.parametrize(
    ("verb", "order"), [("aprobar", "approve"), ("rechazar", "reject"), ("confiar", "trust")]
)
def test_the_second_agents_hold_is_decided_and_the_page_says_whose(
    web: TestClient, approver: Approver, verb: str, order: str
) -> None:
    page = web.get(f"/agentes/{SLUG}{DECIDE}?{urlencode({'id': HOLD_B, 'v': verb})}").text
    assert f"{FOR_AGENT} {NAME}" in text_of(page)
    fields = form_of(page)
    assert fields["agente"] == SLUG
    if verb == "confiar":
        fields["confirmo"] = "si"
    done = post_decide(web, fields)
    assert done.status_code == 200 and f"{FOR_AGENT} {NAME}" in text_of(done.text)
    assert approver.orders == [(order, HOLD_B, SLUG)]


def test_a_hold_of_one_agent_is_nothing_on_the_others_page(web: TestClient) -> None:
    """Two agents, one id: each is looked for among its own."""
    page = web.get(f"/agentes/{SLUG}{DECIDE}?{urlencode({'id': HOLD_A, 'v': 'aprobar'})}")
    assert 'name="ticket"' not in page.text
    assert "agente" not in form_of(page.text)


def test_the_same_id_in_two_agents_is_each_ones(web: TestClient, approver: Approver) -> None:
    approver.of[None] = [decide.hold(HOLD_A, seq=None, reason="send")]
    approver.of[SLUG] = [decide.hold(HOLD_A, seq=None, reason="delete")]
    fields = decide_form(web, "aprobar", HOLD_A)
    assert post_decide(web, fields).status_code == 200
    assert approver.orders == [("approve", HOLD_A, SLUG)]


@pytest.mark.parametrize("change", [{"agente": "principal"}, {"agente": None}])
def test_a_decision_for_one_does_nothing_to_another(
    web: TestClient, approver: Approver, change: dict[str, str | None]
) -> None:
    fields = decide_form(web, "aprobar")
    fields.update({k: v for k, v in change.items() if v is not None})
    if change["agente"] is None:
        del fields["agente"]
    assert post_decide(web, fields).status_code == 400
    assert approver.orders == []


def test_an_invented_agents_decision_is_nothing_here(web: TestClient, approver: Approver) -> None:
    assert web.get(f"/agentes/nadie{DECIDE}?id={HOLD_B}&v=aprobar").status_code == 404
    assert web.get(f"/agentes/nadie/peticiones/ver?id={HOLD_B}").status_code == 404
    fields = decide_form(web, "aprobar")
    answer = post_decide(web, {**fields, "agente": "nadie"})
    assert answer.status_code == 404 and "Aquí no hay nada" in answer.text
    assert approver.orders == []


def test_batches_and_trusted_recipients_are_each_agents(
    web: TestClient, approver: Approver
) -> None:
    page = web.get("/peticiones").text
    assert f"{PREFIX_PATH}{DECIDE}?id=b-aaaaaaaa&amp;v=revocar" in page
    assert f"{PREFIX_PATH}/agentes/{SLUG}{DECIDE}?id=b-bbbbbbbb&amp;v=revocar" in page
    assert f"{PREFIX_PATH}/agentes/{SLUG}{DECIDE}?id=t-bbbbbbbb&amp;v=olvidar" in page
    assert f"{FOR_AGENT} {NAME}" in text_of(page) and f"{FOR_AGENT} Principal" in text_of(page)
    for verb, subject, order in (
        ("revocar", "b-bbbbbbbb", "end_batch"),
        ("olvidar", "t-bbbbbbbb", "untrust"),
    ):
        assert post_decide(web, decide_form(web, verb, subject)).status_code == 200
        assert approver.orders.pop() == (order, subject, SLUG)
    # What is the other's is not on this one's list.
    assert 'name="ticket"' not in (web.get(f"/agentes/{SLUG}{DECIDE}?id=b-aaaaaaaa&v=revocar").text)


def test_ver_reads_the_box_of_that_agent(tmp_path: Path, boxes: dict, approver: Approver) -> None:
    held = boxes["other"].append(
        "gate", "held", "x", details={"hold_id": HOLD_B, "method": "DELETE",
                                      "host": "solo-del-vecino.test", "path": "/"},
    )  # fmt: skip
    approver.of[SLUG] = [decide.hold(HOLD_B, seq=held.seq, host="solo-del-vecino.test")]
    web = new_client(tmp_path, clock=lambda: NOW, others=[source(tmp_path)], approver=approver)
    page = web.get(f"/agentes/{SLUG}/peticiones/ver?id={HOLD_B}").text
    assert "solo-del-vecino.test" in page and f"{FOR_AGENT} {NAME}" in text_of(page)
    assert web.get(f"/peticiones/ver?id={HOLD_B}").status_code == 404


def test_an_agent_may_be_called_like_anything(tmp_path: Path, approver: Approver) -> None:
    """A slug is any word, and what the page keeps of the holds is not in the same place."""
    new_box(tmp_path).append("exec", "run", "algo")
    box = other_box(tmp_path, "partial")
    box.append(
        "gate", "held", "x",
        details={"hold_id": HOLD_B, "method": "DELETE", "host": "un.host.test", "path": "/",
                 "expires_at": (NOW + timedelta(minutes=4)).isoformat()},
    )  # fmt: skip
    approver.state = Availability.DISABLED
    reader = BoxReader(tmp_path / "agents" / "partial" / "blackbox.db")
    web = new_client(
        tmp_path,
        clock=lambda: NOW,
        others=[source(tmp_path, slug="partial", reader=reader)],
        approver=approver,
    )
    web.get("/panel")
    panel = web.get("/panel").text
    assert HOLD_B in panel and "is-stale" not in panel


def test_an_agent_that_cannot_say_hides_nothing_of_the_others(
    web: TestClient, approver: Approver
) -> None:
    approver.failing = {SLUG}
    panel = web.get("/panel").text
    assert HOLD_A in panel and HOLD_B not in panel
    assert "is-stale" in panel, "and the page says the list may not be whole"
    approver.failing = {None}
    panel = web.get("/panel").text
    assert HOLD_B in panel and HOLD_A not in panel and "is-stale" in panel


def test_the_stream_keeps_the_good_ones_when_one_cannot_say(
    tmp_path: Path, boxes: dict, approver: Approver
) -> None:
    """Not the last whole list for ever: a new hold of who can say still arrives."""
    approver.failing = {SLUG}
    web = new_client(
        tmp_path,
        clock=lambda: NOW,
        others=[source(tmp_path)],
        approver=approver,
        stream_seconds=0.3,
        poll_interval=0.02,
    )
    events = parse_sse(web.get("/panel/stream").text)
    requests = next(e for e in events if e.get("event") == "requests")
    assert HOLD_A in requests["data"]


# -- an agent the service has and is not watching --------------------------------------------------


def test_an_agent_not_watched_says_so_and_is_not_asked(
    tmp_path: Path, boxes: dict, rewinder: Rewinder, approver: Approver
) -> None:
    web = new_client(
        tmp_path,
        clock=lambda: NOW,
        others=[source(tmp_path, watched=False)],
        rewinder=rewinder,
        approver=approver,
    )
    assert approver.asked == [] or SLUG not in approver.asked
    panel = web.get("/panel").text
    assert SLUG not in approver.asked, "its gate is not up: nobody could answer it"
    card = panel[panel.index(f'id="card-{SLUG}"') :]
    assert "st-stopped" in card[: card.index("</article>")]
    page = web.get(f"/agentes/{SLUG}/instantaneas").text
    assert "no se está vigilando" in text_of(page) and "rewind-go" not in page
    confirm = web.get(f"/agentes/{SLUG}{REWIND}?{urlencode({'id': OTHER_SNAP.id})}").text
    assert "no se está vigilando" in text_of(confirm) and 'name="ticket"' not in confirm


# -- what each page shows --------------------------------------------------------------------------


def test_the_events_of_one_are_not_on_the_pages_of_the_other(web: TestClient) -> None:
    for path in ("/ahora", "/historia"):
        mine, theirs = web.get(path).text, web.get(f"/agentes/{SLUG}{path}").text
        assert "del-principal" in mine and "del-vecino" not in mine
        assert "del-vecino" in theirs and "del-principal" not in theirs


@pytest.mark.parametrize(
    ("path", "whose", "mine", "theirs"),
    [
        ("/ahora/stream", "main", "nueva-del-principal", "nueva-del-vecino"),
        (f"/agentes/{SLUG}/ahora/stream", "other", "nueva-del-vecino", "nueva-del-principal"),
    ],
)
def test_the_live_stream_of_one_says_nothing_of_the_other(
    tmp_path: Path, boxes: dict[str, BlackBox], path: str, whose: str, mine: str, theirs: str
) -> None:
    main_reader = WatchedReader(tmp_path / "blackbox.db")
    other_reader = WatchedReader(tmp_path / "agents" / SLUG / "blackbox.db")
    watched = main_reader if whose == "main" else other_reader
    web = new_client(
        tmp_path,
        reader=main_reader,
        others=[source(tmp_path, reader=other_reader)],
        clock=lambda: NOW,
        stream_seconds=0.4,
        poll_interval=0.02,
    )

    def later() -> None:
        watched.wait_read()
        boxes["other"].append("exec", "run", "nueva-del-vecino")
        boxes["main"].append("exec", "run", "nueva-del-principal")

    writer = threading.Thread(target=later)
    writer.start()
    body = web.get(f"{path}?after=1").text
    writer.join()
    assert mine in body and theirs not in body


def test_the_panels_stream_says_whose_each_line_is(
    tmp_path: Path, boxes: dict[str, BlackBox]
) -> None:
    """The one place both are together, each line under its own name and its own id."""
    other_reader = WatchedReader(tmp_path / "agents" / SLUG / "blackbox.db")
    web = new_client(
        tmp_path,
        others=[source(tmp_path, reader=other_reader)],
        clock=lambda: NOW,
        stream_seconds=0.4,
        poll_interval=0.02,
    )

    def later() -> None:
        other_reader.wait_read()
        boxes["other"].append("exec", "run", "nueva-del-vecino")
        boxes["main"].append("exec", "run", "nueva-del-principal")

    writer = threading.Thread(target=later)
    writer.start()
    body = web.get("/panel/stream").text
    writer.join()
    lines = [e["data"] for e in parse_sse(body) if e.get("event") == "feed"]
    seen = "\n".join(lines)
    assert "nueva-del-vecino" in seen and "nueva-del-principal" in seen
    for block in seen.split("</li>"):
        if "nueva-del-vecino" in block:
            assert f'id="p-{SLUG}-' in block and NAME in block
        if "nueva-del-principal" in block:
            assert 'id="p-principal-' in block and NAME not in block


# -- the service says who there is -----------------------------------------------------------------


class Moving:
    """What ``agents_from`` hands the app: what a test says."""

    def __init__(self, *sources: AgentSource) -> None:
        self.sources: tuple[AgentSource, ...] | None = sources

    def __call__(self) -> tuple[AgentSource, ...] | None:
        return self.sources


def test_a_new_agent_appears_and_one_that_cannot_be_told_stays(tmp_path: Path, boxes: dict) -> None:
    moving = Moving()
    web = new_client(tmp_path, clock=lambda: NOW, agents_from=moving)
    assert web.get(f"/agentes/{SLUG}/ahora").status_code == 404
    assert 'id="card-' + SLUG not in web.get("/panel").text
    moving.sources = (source(tmp_path),)
    assert web.get(f"/agentes/{SLUG}/ahora").status_code == 200
    assert f'id="card-{SLUG}"' in web.get("/panel").text
    moving.sources = None  # it cannot say: not "there are none"
    assert web.get(f"/agentes/{SLUG}/ahora").status_code == 200
    moving.sources = ()
    assert web.get(f"/agentes/{SLUG}/ahora").status_code == 404


def test_a_list_that_makes_no_sense_takes_no_page_down(
    tmp_path: Path, boxes: dict, caplog: pytest.LogCaptureFixture
) -> None:
    def broken() -> None:
        raise RuntimeError("nonsense")

    web = new_client(tmp_path, clock=lambda: NOW, agents_from=broken)
    assert web.get("/panel").status_code == 200
    assert "the list of agents cannot be used" in caplog.text


def test_the_panels_stream_tells_the_page_when_the_agents_change(
    tmp_path: Path, boxes: dict
) -> None:
    """It opens with one agent and the service then has two: there is no card to send the new one
    to, so the page has to load again, and the stream ends here (not at its minute 10)."""
    asked: list[int] = []
    other = source(tmp_path)

    def agents() -> tuple[AgentSource, ...]:
        asked.append(1)
        return () if len(asked) == 1 else (other,)

    web = new_client(
        tmp_path, clock=lambda: NOW, agents_from=agents, stream_seconds=30.0, poll_interval=0.01
    )
    events = parse_sse(web.get("/panel/stream").text)
    assert events[-1].get("event") == "roster"
    assert not any(e.get("event") == f"card-{SLUG}" for e in events)


def test_the_panel_has_where_to_hear_it(web: TestClient) -> None:
    assert 'sse-swap="roster"' in web.get("/panel").text
    js = (Path(__file__).parent.parent / "backtide/web/static/web.js").read_text()
    assert 'hasAttribute("data-roster")' in js and "location.reload()" in js


# -- over the real socket --------------------------------------------------------------------------


class Rig:
    """Two agents on one roster, as ``serve`` makes them, behind the real narrow socket."""

    def __init__(self, folder: Path, tmp_path: Path) -> None:
        self.main, self.other = Agent(), Agent()
        self.main.holds = [decide.hold(HOLD_A, seq=None)]
        self.other.holds = [decide.hold(HOLD_B, seq=None)]
        self.roster = Roster(
            Desk("principal", self.main, snapshots=lambda: [MAIN_SNAP], name=None),
            [(SLUG, NAME), ("parado", None)],
        )
        self.roster.publish(
            Desk(
                SLUG,
                self.other,
                snapshots=lambda: [OTHER_SNAP],
                name=NAME,
                notice=("Lo que dice el perfil de este agente.",),
            )
        )
        sessions = Sessions()
        sessions.preset(SESSION)
        self.server = WebControlServer(
            self.main,
            folder / "w.sock",
            group=GROUP,
            peer=the_web,
            snapshots=lambda: [MAIN_SNAP],
            sessions=sessions,
            on_entry=lambda action, details: True,
            roster=self.roster,
        )
        self.server.start()
        self.ours: dict[str, Any] = {"server_uid": ME, "egid": lambda: GROUP, "peer": the_web}
        paths = WebPaths(tmp_path / "blackbox.db", tmp_path / "volume", self.server.path)
        self.agents = LiveAgents(
            self.server.path,
            box_of=paths.agent_box,
            every=0,
            **self.ours,
        )

    def web(self, tmp_path: Path, **options: Any) -> TestClient:
        return new_client(
            tmp_path,
            clock=lambda: NOW,
            snapshots=lambda: [MAIN_SNAP],
            agents_from=self.agents,
            rewinder=ControlRewinder(self.server.path, enabled=True, wait=0, **self.ours),
            approver=ControlApprover(self.server.path, enabled=True, wait=0, **self.ours),
            access=ServiceAccess(self.server.path, server_uid=ME, wait=0, peer=the_web),
            **options,
        )

    def close(self) -> None:
        self.server.close()


@pytest.fixture
def rig(tmp_path: Path, boxes: dict) -> Iterator[Rig]:
    folder = Path(tempfile.mkdtemp(prefix="vw"))
    folder.chmod(0o700)
    found = Rig(folder, tmp_path)
    yield found
    found.close()
    shutil.rmtree(folder, ignore_errors=True)


def test_the_panel_shows_the_services_agents(rig: Rig, tmp_path: Path) -> None:
    panel = rig.web(tmp_path).get("/panel").text
    assert 'id="card-principal"' in panel and f'id="card-{SLUG}"' in panel
    assert 'id="card-parado"' in panel
    card = panel[panel.index('id="card-parado"') :]
    assert "st-stopped" in card[: card.index("</article>")], "the service says it is not watched"
    assert "del-vecino" in panel, "its box, at the place the service keeps it"


def test_the_second_agent_is_rewound_on_the_real_socket_and_only_it(
    rig: Rig, tmp_path: Path
) -> None:
    web = rig.web(tmp_path)
    theirs = web.get(f"/agentes/{SLUG}/instantaneas").text
    assert f"/agentes/{SLUG}{REWIND}?id={OTHER_SNAP.id}" in theirs, "the list the service gave"
    assert 'data-outcome="done"' in post_rewind(web, rewind_form(web)).text
    assert rig.other.calls == [(OTHER_SNAP.id, f"web (uid {ME}, pid 4242)")]
    assert rig.main.calls == []


def test_the_main_one_rewinds_as_it_always_did_with_a_neighbour_there(
    rig: Rig, tmp_path: Path
) -> None:
    web = rig.web(tmp_path)
    page = web.get(f"{REWIND}?{urlencode({'id': MAIN_SNAP.id})}").text
    assert 'data-outcome="done"' in post_rewind(web, form_of(page)).text
    assert rig.main.calls == [(MAIN_SNAP.id, f"web (uid {ME}, pid 4242)")] and rig.other.calls == []


def test_the_second_agents_hold_is_decided_on_the_real_socket_and_only_it(
    rig: Rig, tmp_path: Path
) -> None:
    web = rig.web(tmp_path)
    panel = web.get("/panel").text
    assert HOLD_A in panel and HOLD_B in panel
    assert post_decide(web, decide_form(web, "rechazar")).status_code == 200
    assert rig.other.decisions == [(HOLD_B, "reject", "web", f"web (uid {ME}, pid 4242)")]
    assert rig.main.decisions == []


def test_the_service_decides_too_when_the_webs_list_is_old(rig: Rig, tmp_path: Path) -> None:
    """The web thinks the neighbour is there, with a good ticket, and the service has retired it
    in between: nothing reaches anybody, and the page does not fall over."""
    web = rig.web(tmp_path)
    rewinding, deciding = rewind_form(web), decide_form(web, "aprobar")
    rig.roster.retire(SLUG)
    assert post_rewind(web, rewinding).status_code == 503, "it cannot give its list of snapshots"
    answer = post_decide(web, deciding)
    assert answer.status_code == 400 and "no se está vigilando" in answer.text
    assert rig.other.calls == rig.main.calls == []
    assert rig.other.decisions == rig.main.decisions == []


def test_a_rewind_with_no_session_stops_at_the_service_as_well(rig: Rig, tmp_path: Path) -> None:
    """A web taken over: the socket itself, without a session, whatever agent it names."""
    reply = ask_rewind(
        rig.server.path, OTHER_SNAP.id, via="web", wait=0, peer=the_web, server_uid=ME, agent=SLUG
    )
    assert reply["ok"] is False and rig.other.calls == []
    reply = ask_rewind(
        rig.server.path,
        OTHER_SNAP.id,
        via="web",
        wait=0,
        peer=the_web,
        server_uid=ME,
        session=SESSION,
        agent="nadie",
    )
    assert reply["outcome"] == "refused" and rig.other.calls == [] and rig.main.calls == []


def test_live_agents_ask_at_most_so_often_and_keep_the_last_answer(
    rig: Rig, tmp_path: Path
) -> None:
    moment = [100.0]
    live = LiveAgents(
        rig.server.path,
        box_of=lambda slug: tmp_path / slug,
        every=5.0,
        monotonic=lambda: moment[0],
        **rig.ours,
    )
    first = live()
    assert first is not None and [a.slug for a in first] == [SLUG, "parado"]
    assert [a.watched for a in first] == [True, False]
    assert first[0].notice_lines == ("Lo que dice el perfil de este agente.",)
    assert first[0].name == NAME and first[0].reader is live()[0].reader
    rig.roster.retire(SLUG)
    assert live()[0].watched is True, "not asked yet"
    moment[0] += 6
    assert live()[0].watched is False
    # A service that is gone says nothing: the list stays.
    rig.server.close()
    moment[0] += 6
    assert [a.slug for a in live()] == [SLUG, "parado"]


def test_an_agent_gone_while_the_page_was_being_made_is_left_out(
    rig: Rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T26-6c: the list can change between reading what it holds and showing it, and a list that
    says someone who is not there anymore is not a reason for a page to fail."""
    gone = SimpleNamespace(agent="borrado")
    monkeypatch.setattr(app_module, "batch_views", lambda *_: [gone])
    monkeypatch.setattr(app_module, "trust_views", lambda *_: [gone])
    web = rig.web(tmp_path)
    page = web.get("/peticiones")
    assert page.status_code == 200
    assert "borrado" not in page.text and "v=revocar" not in page.text


def test_a_request_of_an_agent_that_went_is_left_out(
    tmp_path: Path, boxes: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    gone = request(id="gone", agent="borrado")
    monkeypatch.setattr(app_module, "live_requests", lambda *_: [gone])
    page = new_client(tmp_path, clock=lambda: NOW, pending=lambda: []).get("/peticiones")
    assert page.status_code == 200 and 'id="req-gone"' not in page.text


def test_a_reader_goes_with_the_agent_it_read(rig: Rig, tmp_path: Path) -> None:
    """T26-6c: an open reader is what keeps the service from taking a deleted box out of WAL."""
    live = LiveAgents(rig.server.path, box_of=lambda slug: tmp_path / slug, every=0, **rig.ours)
    first = live()
    assert first is not None
    reader = first[0].reader
    closed: list[str] = []
    real = reader.close
    reader.close = lambda: (closed.append("yes"), real())  # type: ignore[method-assign]
    rig.roster.forget(SLUG)
    found = live()
    assert found is not None and SLUG not in [a.slug for a in found]
    assert closed == ["yes"] and SLUG not in live._readers
    rig.roster.add(SLUG, NAME)
    again = live()
    assert again is not None and [a for a in again if a.slug == SLUG][0].reader is not reader


def test_live_agents_say_nothing_before_the_first_answer(tmp_path: Path) -> None:
    live = LiveAgents(tmp_path / "no.sock", box_of=lambda slug: tmp_path / slug, every=0)
    assert live() is None


def test_live_agents_only_take_slugs_for_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even from the service's own reply: a name becomes a folder only if it is a slug, and one the
    web cannot show leaves the others standing."""
    item = {"main": False, "watched": True, "state": None, "notice": []}
    listed = [
        {"slug": "principal", "name": None, **item, "main": True},
        {"slug": "../../etc", "name": None, **item},
        {"slug": "largo", "name": "x" * 200, **item},
        {"slug": "bueno", "name": None, **item},
    ]
    monkeypatch.setattr(live, "ask_agents", lambda *args, **options: listed)
    monkeypatch.setattr(live, "availability_of", lambda *args, **options: Availability.READY)
    asked: list[str] = []

    def box_of(slug: str) -> Path:
        asked.append(slug)
        return tmp_path / slug

    found = LiveAgents(tmp_path / "s.sock", box_of=box_of, every=0)()
    assert found is not None and [a.slug for a in found] == ["bueno"]
    assert "../../etc" not in asked and "principal" not in asked


def test_the_agents_box_is_where_the_service_keeps_it(tmp_path: Path) -> None:
    paths = WebPaths(tmp_path / STATE_DB, tmp_path / "volume", tmp_path / "control.sock")
    assert paths.agent_box(SLUG) == tmp_path / AGENTS_FOLDER / SLUG / STATE_DB
