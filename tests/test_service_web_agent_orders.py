"""T26-6b: the agents' orders on the web's narrow socket. What is on its list and what never will
be, the session and the key it asks for, and how much narrower it is than root's socket: a closed
``agent_create``, nothing about the main agent, and no restart. Decided in the service, not in the
web: these talk to the socket as a web taken over would.

Next to them, what the list says of each agent (D42), and that a stop does not wait behind a start
(tests/test_service_fleet.py has the machine these use)."""

import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.service.agents import kind_of, load_installation
from backtide.service.control import ControlServer, ask_fleet
from backtide.service.fleet import PROFILES
from backtide.service.roster import (
    IN_USE_TASK,
    STARTING,
    STOP_FAILED,
    STOPPING,
    AgentKind,
    Desk,
    Roster,
)
from backtide.service.tasks import AgentTasks
from backtide.service.web_control import (
    AGENT_ORDERS,
    AGENT_STOPS,
    CHANGES_BURST,
    COMMANDS,
    LONG_ORDERS,
    MAX_WEB_CONNECTIONS,
    STOPS_BURST,
    TASK_STOPS,
    TOUCH_CHANGES,
    Bucket,
    WebControlServer,
)
from backtide.web.security import CHECKS_AT_ONCE
from tests.test_service_agents import home as home  # noqa: F401, PLC0414 - the fixture
from tests.test_service_agents import main_config
from tests.test_service_control import FakeGuardian, me
from tests.test_service_fleet import GOOD, FakeNeighbours, World
from tests.test_service_fleet import alone as alone  # noqa: F401, PLC0414 - the fixture
from tests.test_service_fleet import world as world  # noqa: F401, PLC0414 - the fixture
from tests.test_service_web_control import (
    SESSION,
    Keyed,
    keyed_server,
    signed,
    talk,
    touched,
)
from tests.test_service_web_control import budget as budget  # noqa: F401, PLC0414
from tests.test_service_web_control import folder as folder  # noqa: F401, PLC0414
from tests.test_service_web_control import guardian as guardian  # noqa: F401, PLC0414
from tests.test_service_web_control import keyed as keyed  # noqa: F401, PLC0414
from tests.test_service_web_control import make_server as make_server  # noqa: F401, PLC0414
from tests.test_service_web_control import passkeys as passkeys  # noqa: F401, PLC0414
from tests.test_service_web_control import settings as settings  # noqa: F401, PLC0414

CREATE = {"cmd": "agent_create", "slug": "tercero", "profile": "claude-code", "volume_gib": 10}
START = {"cmd": "agent_start", "agent": "revisor"}
STOP = {"cmd": "agent_stop", "agent": "revisor"}
DELETE = {"cmd": "agent_delete", "agent": "revisor", "typed": "revisor"}
MADE_UP = "n" * 43


class FakeFleet:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []
        self.reply = {"ok": True, "outcome": "done", "message": "hecho"}
        self.hold: threading.Event | None = None
        self.holding = threading.Semaphore(0)

    def _order(self, name: str, request: Any, requested_by: str) -> dict[str, Any]:
        self.calls.append((name, dict(request), requested_by))
        hold = self.hold
        if hold is not None:
            self.holding.release()
            hold.wait(10)
        return self.reply

    def create(self, request: Any, requested_by: str) -> dict[str, Any]:
        return self._order("create", request, requested_by)

    def start(self, request: Any, requested_by: str) -> dict[str, Any]:
        return self._order("start", request, requested_by)

    def stop(self, request: Any, requested_by: str) -> dict[str, Any]:
        return self._order("stop", request, requested_by)

    def delete(self, request: Any, requested_by: str) -> dict[str, Any]:
        return self._order("delete", request, requested_by)

    def restore(self, request: Any, requested_by: str) -> dict[str, Any]:
        return self._order("restore", request, requested_by)

    def purge(self, request: Any, requested_by: str) -> dict[str, Any]:
        return self._order("purge", request, requested_by)


class Freezable(FakeGuardian):
    def __init__(self) -> None:
        super().__init__()
        self.paused: list[str] = []

    def pause_by_user(self, *, requested_by: str) -> Any:
        from backtide.service.guardian import PauseOutcome, PauseStatus

        self.paused.append(requested_by)
        return PauseOutcome(PauseStatus.FROZEN, "congelado", "frozen")


@pytest.fixture
def fleet() -> FakeFleet:
    return FakeFleet()


@pytest.fixture
def desk() -> Freezable:
    return Freezable()


@pytest.fixture
def main_desk() -> Freezable:
    return Freezable()


@pytest.fixture
def server(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    fleet: FakeFleet,
    desk: Freezable,
    main_desk: Freezable,
) -> WebControlServer:
    roster = Roster(Desk("principal", main_desk), [("revisor", "Revisor")])
    roster.publish(Desk("revisor", desk))
    return make_server(fleet=fleet, roster=roster)


@pytest.fixture
def roomy(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    fleet: FakeFleet,
    desk: Freezable,
    main_desk: Freezable,
) -> WebControlServer:
    """The same, with a bucket of changes that does not run out in the middle of a flood."""
    roster = Roster(Desk("principal", main_desk), [("revisor", "Revisor")])
    roster.publish(Desk("revisor", desk))
    return make_server(
        fleet=fleet,
        roster=roster,
        changes=Bucket(1000, 1000.0),
        stops=Bucket(1000, 1000.0),
    )


# --- the list ------------------------------------------------------------------------------------


def test_what_is_on_the_list_and_what_never_will_be() -> None:
    assert (
        frozenset(
            {
                "agent_create",
                "agent_start",
                "agent_stop",
                "agent_pause",
                "agent_resume",
                "agent_delete",
            }
        )
        == AGENT_ORDERS
    )
    assert AGENT_ORDERS <= COMMANDS
    # Bringing back and emptying are for the server's terminal: docs/47, section 8.5.
    assert {"agent_restore", "agent_purge"}.isdisjoint(COMMANDS)
    assert {"agent_create", "agent_delete"} <= TOUCH_CHANGES
    assert {"agent_start", "agent_stop", "agent_pause", "agent_resume"}.isdisjoint(TOUCH_CHANGES)


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "agent_restore", "agent": "revisor"},
        {"cmd": "agent_restore", "agent": "revisor", "restart": True},
        {"cmd": "agent_purge", "agent": "revisor", "typed": "revisor"},
    ],
)
def test_the_trash_is_out_of_reach_with_a_live_session(
    server: WebControlServer, fleet: FakeFleet, request_: dict[str, Any]
) -> None:
    reply = talk(server, signed(request_))
    assert reply["outcome"] == "refused" and "socket de la web" in reply["message"]
    assert not fleet.calls


# --- the session --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_",
    [
        CREATE,
        START,
        STOP,
        DELETE,
        {"cmd": "agent_pause", "agent": "revisor"},
        {"cmd": "agent_resume", "agent": "revisor"},
    ],
)
@pytest.mark.parametrize("session", [None, MADE_UP, 7])
def test_without_a_live_session_nothing_is_asked(
    server: WebControlServer,
    fleet: FakeFleet,
    desk: Freezable,
    request_: dict[str, Any],
    session: Any,
) -> None:
    asked = dict(request_) if session is None else {**request_, "session": session}
    reply = talk(server, asked)
    assert reply["outcome"] == "refused" and "sesión viva" in reply["message"]
    assert not fleet.calls and not desk.paused and not desk.resumes


def test_a_session_that_ended_is_no_session(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    fleet: FakeFleet,
) -> None:
    server = make_server(fleet=fleet)
    assert talk(server, {"cmd": "session_end", "session": SESSION})["outcome"] == "ended"
    assert talk(server, signed(CREATE))["outcome"] == "refused"
    assert not fleet.calls


# --- the key ------------------------------------------------------------------------------------


@pytest.mark.parametrize("request_", [CREATE, DELETE])
def test_creating_and_deleting_ask_for_the_key_touched(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    keyed: Keyed,  # noqa: F811
    fleet: FakeFleet,
    request_: dict[str, Any],
) -> None:
    server = keyed_server(make_server, keyed, fleet=fleet)
    reply = talk(server, {**request_, "session": keyed.session})
    assert reply["outcome"] == "refused" and "tocar tu llave" in reply["message"]
    assert not fleet.calls
    touched(server, keyed)
    assert talk(server, {**request_, "session": keyed.session})["ok"] is True
    assert len(fleet.calls) == 1


def test_a_touch_of_five_minutes_ago_is_not_enough(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    passkeys: Any,  # noqa: F811
    fleet: FakeFleet,
) -> None:
    from tests.test_service_web_control import Ticks

    clock = Ticks()
    keyed_ = Keyed(passkeys, clock)
    server = keyed_server(make_server, keyed_, fleet=fleet)
    touched(server, keyed_)
    clock.now += 5 * 60
    reply = talk(server, {**CREATE, "session": keyed_.session})
    assert "tocar tu llave" in reply["message"] and not fleet.calls


@pytest.mark.parametrize("request_", [START, STOP])
def test_what_can_be_undone_does_not_ask_for_the_key(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    keyed: Keyed,  # noqa: F811
    fleet: FakeFleet,
    request_: dict[str, Any],
) -> None:
    server = keyed_server(make_server, keyed, fleet=fleet)
    assert talk(server, {**request_, "session": keyed.session})["ok"] is True
    assert len(fleet.calls) == 1


def test_with_no_keys_through_the_tunnel_the_session_is_enough(
    server: WebControlServer, fleet: FakeFleet
) -> None:
    """D40, what ``_needs_touch`` says of the rest: without a key there is nothing to touch."""
    assert talk(server, signed(CREATE))["ok"] is True
    assert [name for name, _, _ in fleet.calls] == ["create"]


def test_with_no_keys_behind_a_domain_it_is_refused(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    fleet: FakeFleet,
    tmp_path: Path,
) -> None:
    from backtide.service.passkeys import Passkeys

    keys = Passkeys(tmp_path, origins=["https://b.ejemplo.test"], rp_id="b.ejemplo.test")
    assert keys.on_a_domain
    server = make_server(fleet=fleet, passkeys=keys)
    reply = talk(server, signed(CREATE))
    assert "tocar tu llave" in reply["message"] and not fleet.calls


# --- the closed form ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"restart": True},
        {"restart": False},
        {"name": "Otro"},
        {"memory": "4g"},
        {"cpus": 4},
        {"proxy_memory": "1g"},
        {"workspace_mib": 128},
        {"daily_usd": "5"},
        {"monthly_usd": "5"},
        {"image": "alpine"},
        {"mounts": ["/etc:/etc"]},
        {"privileged": True},
        {"path": "/root"},
        {"entrypoint": "sh"},
    ],
)
def test_creating_takes_three_fields_and_no_other(
    server: WebControlServer, fleet: FakeFleet, extra: dict[str, Any]
) -> None:
    """Also what root's socket takes: a web taken over chooses no name, no caps and no restart."""
    reply = talk(server, signed({**CREATE, **extra}))
    assert (reply["ok"], reply["outcome"]) == (False, "invalid")
    assert not fleet.calls


@pytest.mark.parametrize(
    "fields",
    [
        {"profile": "custom"},
        {"profile": "../../etc/passwd"},
        {"profile": None},
        {"volume_gib": 7},
        {"volume_gib": "10"},
        {"volume_gib": 10.0},
        {"volume_gib": True},
        {"slug": "../x"},
        {"slug": "/etc"},
        {"slug": "principal"},
        {"slug": "agente"},
        {"slug": "Mayusculas"},
        {"slug": ""},
        {"slug": 7},
    ],
)
def test_a_real_fleet_refuses_what_is_off_its_lists_and_touches_nothing(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    world: World,  # noqa: F811
    fields: dict[str, Any],
) -> None:
    server = make_server(fleet=world.fleet, roster=world.roster)
    before = len(world.machine.ran)
    reply = talk(server, signed({**CREATE, **fields}))
    assert (reply["ok"], reply["outcome"]) == (False, "invalid")
    assert len(world.machine.ran) == before and not world.recorded
    assert not world.created_home("tercero").exists()


def test_what_has_its_shape_is_made_and_the_box_says_the_web_asked(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    world: World,  # noqa: F811
) -> None:
    server = make_server(fleet=world.fleet, roster=world.roster)
    reply = talk(server, signed(CREATE))
    assert reply["ok"] is True and reply["outcome"] == "created"
    action, target, details = world.recorded[0]
    assert (action, target) == ("agent_create", "tercero")
    assert details["requested_by"].startswith("web (uid ")


def test_the_first_neighbour_is_not_made_from_here(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    alone: World,  # noqa: F811
) -> None:
    """It restarts the service and the main agent with it: the web has no word for that."""
    server = make_server(fleet=alone.fleet, roster=alone.roster)
    reply = talk(server, signed(CREATE))
    assert (reply["ok"], reply["outcome"]) == (False, "needs_restart")
    assert not alone.stop.is_set() and not alone.created_home("tercero").exists()
    reply = talk(server, signed({**CREATE, "restart": True}))
    assert (reply["ok"], reply["outcome"]) == (False, "invalid")
    assert not alone.stop.is_set() and not alone.created_home("tercero").exists()


def test_the_orders_that_name_their_agent_keep_their_closed_shape(
    make_server: Callable[..., WebControlServer],  # noqa: F811
    world: World,  # noqa: F811
) -> None:
    server = make_server(fleet=world.fleet, roster=world.roster)
    for request_ in (
        {**STOP, "force": True},
        {"cmd": "agent_stop"},
        {"cmd": "agent_stop", "agent": "../principal"},
        {"cmd": "agent_start", "agent": "/etc"},
        {"cmd": "agent_delete", "agent": "revisor", "typed": "otro"},
        {"cmd": "agent_delete", "agent": "revisor"},
    ):
        reply = talk(server, signed(request_))
        assert (reply["ok"], reply["outcome"]) == (False, "invalid"), request_
    assert not world.recorded and world.neighbours is not None
    assert world.neighbours.running == {"revisor"}


# --- who asked ----------------------------------------------------------------------------------


def test_each_order_is_recorded_as_the_web(
    server: WebControlServer, fleet: FakeFleet, desk: Freezable
) -> None:
    for request_ in (CREATE, START, STOP, DELETE):
        assert talk(server, signed(request_))["ok"] is True
    assert talk(server, signed({"cmd": "agent_pause", "agent": "revisor"}))["ok"] is True
    talk(server, signed({"cmd": "agent_resume", "agent": "revisor"}))
    who = {by for _, _, by in fleet.calls} | set(desk.paused) | {by for by in desk.resumes}
    assert who and all(by.startswith("web (uid ") and "pid 4242" in by for by in who)


def test_it_cannot_say_it_was_someone_else(server: WebControlServer, fleet: FakeFleet) -> None:
    reply = talk(server, signed({**STOP, "via": "cli"}))
    assert reply["outcome"] == "refused" and not fleet.calls
    # "web" is what it is, so saying it adds nothing: it never reaches the order's closed shape.
    assert talk(server, signed({**STOP, "via": "web"}))["ok"] is True
    assert fleet.calls[0][1] == STOP


def test_the_session_never_reaches_the_order(server: WebControlServer, fleet: FakeFleet) -> None:
    talk(server, signed(CREATE))
    assert fleet.calls[0][1] == CREATE


def test_a_web_freezes_a_neighbour_and_thaws_it(server: WebControlServer, desk: Freezable) -> None:
    reply = talk(server, signed({"cmd": "agent_pause", "agent": "revisor"}))
    assert reply["ok"] is True and reply["agent_state"] == "frozen" and len(desk.paused) == 1
    talk(server, signed({"cmd": "agent_resume", "agent": "revisor"}))
    assert len(desk.resumes) == 1


# --- the main agent -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "agent_pause", "agent": "principal"},
        {"cmd": "agent_resume", "agent": "principal"},
        {"cmd": "agent_stop", "agent": "principal"},
        {"cmd": "agent_start", "agent": "principal"},
        {"cmd": "agent_delete", "agent": "principal", "typed": "principal"},
    ],
)
def test_nothing_of_this_reaches_the_main_agent(
    server: WebControlServer,
    fleet: FakeFleet,
    main_desk: Freezable,
    request_: dict[str, Any],
) -> None:
    reply = talk(server, signed(request_))
    assert reply["ok"] is False and reply["outcome"] == "refused"
    assert "principal" in reply["message"]
    assert not fleet.calls and not main_desk.paused and not main_desk.resumes


def test_saying_no_agent_is_not_a_way_to_the_main_one(
    server: WebControlServer, main_desk: Freezable
) -> None:
    for command in ("agent_pause", "agent_resume"):
        reply = talk(server, signed({"cmd": command}))
        assert reply["ok"] is False
    assert not main_desk.paused and not main_desk.resumes


def test_an_agent_nobody_has_touches_nobody(
    server: WebControlServer, desk: Freezable, main_desk: Freezable
) -> None:
    for slug in ("nadie", "../principal", 7, None):
        reply = talk(server, signed({"cmd": "agent_pause", "agent": slug}))
        assert reply["ok"] is False, slug
    assert not desk.paused and not main_desk.paused


# --- how many -----------------------------------------------------------------------------------


def test_long_orders_leave_connections_for_the_pages_and_never_stop_a_brake(
    server: WebControlServer, fleet: FakeFleet, desk: Freezable
) -> None:
    """A start holds its connection for minutes. Past ``LONG_ORDERS``, a word at once; every page
    goes on being answered while they run. And freezing and stopping do not wait behind them: a
    stolen session that keeps two starts going must not take the owner's brake away."""
    held_by = threading.Event()
    fleet.hold = held_by
    held = []
    threads = []
    for _ in range(LONG_ORDERS):
        thread = threading.Thread(target=lambda: held.append(talk(server, signed(START))))
        thread.start()
        threads.append(thread)
    try:
        for _ in range(LONG_ORDERS):
            assert fleet.holding.acquire(timeout=10)
        reply = talk(server, signed(START))
        assert (reply["ok"], reply["outcome"]) == (False, "busy")
        assert [name for name, _, _ in fleet.calls] == ["start"] * LONG_ORDERS
        assert talk(server, {"cmd": "agents"})["ok"] is True
        fleet.hold = None  # those already waiting go on waiting on theirs
        assert talk(server, signed({"cmd": "agent_pause", "agent": "revisor"}))["ok"] is True
        assert len(desk.paused) == 1
        assert talk(server, signed(STOP))["ok"] is True
        assert fleet.calls[-1][0] == "stop"
    finally:
        held_by.set()
        for thread in threads:
            thread.join(10)
    assert all(reply["ok"] for reply in held)
    assert talk(server, signed(START))["ok"] is True  # the room comes back


FREE_FOR_PAGES = 2  # connections that no order of a kind that lasts may take: pages and the freeze


def test_the_orders_that_last_never_take_every_connection() -> None:
    """The sum of what may hold a connection for minutes, with room left for a page and a brake,
    and the cookie checks (which also come through here) fitting in that room."""
    longest = LONG_ORDERS + AGENT_STOPS + TASK_STOPS
    assert longest + FREE_FOR_PAGES <= MAX_WEB_CONNECTIONS
    assert CHECKS_AT_ONCE <= MAX_WEB_CONNECTIONS - longest


class SlowTaskStop:
    """A guardian whose ``task_stop`` takes as long as the test lets it (a ``pkill`` of 30 s)."""

    def __init__(self, guardian: Any) -> None:
        self.release = threading.Event()
        self.holding = threading.Semaphore(0)
        self.calls: list[str] = []
        guardian.task_stop = self.task_stop

    def task_stop(self, task_id: str, *, requested_by: str | None = None) -> bool:
        self.calls.append(task_id)
        self.holding.release()
        self.release.wait(10)
        return True


def quick_task_stop(desk: Any) -> list[str]:
    stopped: list[str] = []

    def task_stop(task_id: str, *, requested_by: str | None = None) -> bool:
        stopped.append(task_id)
        return True

    desk.task_stop = task_stop
    return stopped


TASK_STOP = {"cmd": "task_stop", "task": "c0de" * 8}
TASK_STOP_REVISOR = {**TASK_STOP, "agent": "revisor"}


def test_the_stops_count_and_two_starts_with_repeated_stops_leave_the_brake_free(
    server: WebControlServer, fleet: FakeFleet, desk: Freezable, main_desk: Freezable
) -> None:
    """The finding of the review of T26-6b, with the bucket of changes as it comes: two starts, a
    stop of an agent and a stop of a task held, and the same stops asked again and again. Each
    repeat is a word at once and spends nothing, so the pages go on being answered and the freeze
    goes through."""
    slow = SlowTaskStop(main_desk)  # the main agent's desk: no `agent` in the order
    held_by = threading.Event()
    fleet.hold = held_by
    held: list[dict[str, Any]] = []
    threads = [
        threading.Thread(target=lambda r=r: held.append(talk(server, signed(r))))
        for r in (*([START] * LONG_ORDERS), STOP, TASK_STOP)
    ]
    for thread in threads:
        thread.start()
    try:
        for _ in range(LONG_ORDERS + AGENT_STOPS):
            assert fleet.holding.acquire(timeout=10)
        assert slow.holding.acquire(timeout=10)
        for _ in range(30):  # the stops asked again, over and over
            again = talk(server, signed(STOP))
            assert (again["ok"], again["outcome"]) == (False, "busy")
            task_again = talk(server, signed(TASK_STOP))
            assert (task_again["ok"], task_again["outcome"]) == (False, "refused")
            assert "espera" in task_again["message"]
        assert [name for name, _, _ in fleet.calls].count("stop") == AGENT_STOPS
        assert len(slow.calls) == 1
        fleet.hold = None
        assert talk(server, {"cmd": "agents"})["ok"] is True
        assert talk(server, signed({"cmd": "agent_pause", "agent": "revisor"}))["ok"] is True
        assert len(desk.paused) == 1
    finally:
        slow.release.set()
        held_by.set()
        for thread in threads:
            thread.join(10)
    assert len(held) == len(threads) and all(reply["ok"] for reply in held)
    assert talk(server, signed(STOP))["ok"] is True  # the room comes back
    assert talk(server, signed(TASK_STOP))["ok"] is True


def test_the_slow_stop_of_one_agents_task_does_not_refuse_anothers(
    server: WebControlServer, desk: Freezable, main_desk: Freezable
) -> None:
    """A hostile agent can make the stop of its own tasks last (its ``pkill`` hangs). The room is
    each agent's: another one's stop still goes through, and so does a stop of the main agent."""
    slow = SlowTaskStop(desk)
    stopped_in_main = quick_task_stop(main_desk)
    held: list[dict[str, Any]] = []
    thread = threading.Thread(target=lambda: held.append(talk(server, signed(TASK_STOP_REVISOR))))
    thread.start()
    try:
        assert slow.holding.acquire(timeout=10)
        again = talk(server, signed(TASK_STOP_REVISOR))  # the same agent's: one at a time
        assert (again["ok"], again["outcome"]) == (False, "refused")
        reply = talk(server, signed(TASK_STOP))  # the main agent's
        assert (reply["ok"], reply["outcome"]) == (True, "stopped")
        assert stopped_in_main == [TASK_STOP["task"]]
        assert len(slow.calls) == 1
    finally:
        slow.release.set()
        thread.join(10)
    assert held and held[0]["ok"] is True
    assert talk(server, signed(TASK_STOP_REVISOR))["ok"] is True  # and its room came back


def test_the_stops_in_flight_are_capped_whatever_the_agents(
    roomy: WebControlServer, desk: Freezable, main_desk: Freezable
) -> None:
    """Each agent has its room, but all of them together never pass ``TASK_STOPS``: the
    connections are the ones that are left."""
    slows = [SlowTaskStop(main_desk), SlowTaskStop(desk)]
    requests = [TASK_STOP, TASK_STOP_REVISOR]
    assert TASK_STOPS == len(requests)
    held: list[dict[str, Any]] = []
    threads = [
        threading.Thread(target=lambda r=r: held.append(talk(roomy, signed(r)))) for r in requests
    ]
    for thread in threads:
        thread.start()
    try:
        for slow in slows:
            assert slow.holding.acquire(timeout=10)
        # An agent that nobody has takes no room either, but is refused all the same.
        third = talk(roomy, signed({**TASK_STOP, "agent": "tercero"}))
        assert third["ok"] is False and third["outcome"] == "refused"
        assert "Ya hay una parada" in third["message"]
    finally:
        for slow in slows:
            slow.release.set()
        for thread in threads:
            thread.join(10)
    assert len(held) == 2 and all(reply["ok"] for reply in held)


def test_a_stop_that_fails_gives_its_room_back(
    roomy: WebControlServer, fleet: FakeFleet, main_desk: Freezable
) -> None:
    def explode(task_id: str, *, requested_by: str | None = None) -> bool:
        raise RuntimeError("boom")

    main_desk.task_stop = explode  # type: ignore[attr-defined]
    for _ in range(AGENT_STOPS + TASK_STOPS + 2):
        assert talk(roomy, signed(TASK_STOP))["outcome"] == "failed"
    original = fleet.stop

    def broken(request: Any, requested_by: str) -> dict[str, Any]:
        raise RuntimeError("boom")

    fleet.stop = broken  # type: ignore[method-assign]
    for _ in range(AGENT_STOPS + 2):
        assert talk(roomy, signed(STOP))["outcome"] == "failed"
    fleet.stop = original  # type: ignore[method-assign]
    assert talk(roomy, signed(STOP))["ok"] is True


def test_a_stream_of_stops_never_empties_the_bucket_of_the_freeze(
    server: WebControlServer, fleet: FakeFleet, desk: Freezable
) -> None:
    """The stops have a bucket of their own: spamming "Parar" runs out that one, and "Congelar"
    and the other changes keep theirs (the bucket of changes as it comes, nothing disabled)."""
    replies = [talk(server, signed(STOP)) for _ in range(STOPS_BURST + 6)]
    assert sum(1 for reply in replies if reply["ok"]) == STOPS_BURST
    assert "Demasiadas paradas" in replies[-1]["message"]
    task_replies = [talk(server, signed(TASK_STOP)) for _ in range(3)]
    assert "Demasiadas paradas" in task_replies[-1]["message"]  # the same bucket: both are stops
    assert len(fleet.calls) == STOPS_BURST
    for _ in range(CHANGES_BURST):  # every change that is not a stop is still there
        assert talk(server, signed({"cmd": "agent_pause", "agent": "revisor"}))["ok"] is True
    assert len(desk.paused) == CHANGES_BURST


def test_a_stream_of_orders_runs_out_of_its_bucket(
    server: WebControlServer, fleet: FakeFleet
) -> None:
    replies = [talk(server, signed(START)) for _ in range(12)]
    assert sum(1 for reply in replies if reply["ok"]) == 10
    assert "Demasiados cambios" in replies[-1]["message"]
    assert len(fleet.calls) == 10


# --- what the list says -------------------------------------------------------------------------


def test_the_list_says_which_agent_it_is_its_version_and_whether_it_is_in_use() -> None:
    class Working(FakeGuardian):
        agent_state = "running"
        busy = False

        def task_running(self) -> bool:
            return self.busy

    guardian_ = Working()
    roster = Roster(
        Desk("principal", guardian_),
        [("revisor", None), ("otro", None)],
        kinds={
            "principal": AgentKind("openclaw", "2026.9.8"),
            "revisor": AgentKind("claude-code", "2.1.306"),
        },
    )
    by_slug = {item["slug"]: item for item in roster.listing()}
    assert (by_slug["principal"]["kind"], by_slug["principal"]["version"]) == (
        "openclaw",
        "2026.9.8",
    )
    assert (by_slug["revisor"]["kind"], by_slug["revisor"]["version"]) == ("claude-code", "2.1.306")
    assert by_slug["otro"]["kind"] is None and by_slug["otro"]["version"] is None
    assert by_slug["principal"]["in_use"] is None
    guardian_.busy = True
    assert roster.listing()[0]["in_use"] == IN_USE_TASK
    assert by_slug["revisor"]["in_use"] is None  # not watched: nothing runs in it


def test_what_an_order_is_doing_is_in_the_list_until_it_ends() -> None:
    roster = Roster(Desk("principal", FakeGuardian()), [("revisor", None)])
    roster.note_order("revisor", STOPPING)
    assert roster.listing()[1]["order"] == STOPPING
    roster.clear_order("revisor", STARTING)  # another's word stays
    assert roster.listing()[1]["order"] == STOPPING
    roster.note_order("revisor", None)
    assert roster.listing()[1]["order"] is None
    roster.note_order("revisor", STOP_FAILED)
    roster.forget("revisor")
    roster.add("revisor", None)
    assert roster.listing()[1]["order"] is None and roster.listing()[1]["kind"] is None


def test_a_task_runs_until_it_ends_whoever_asked() -> None:
    release = threading.Event()
    opened = threading.Event()

    def open_shell(*_: Any, **__: Any) -> Any:
        opened.set()
        release.wait(10)
        raise RuntimeError("the task ends here")

    tasks = AgentTasks(
        commands=lambda: None, open_shell=open_shell, record_end=lambda details: None
    )
    assert tasks.running() is False
    started = tasks.start("hola", requested_by="cli (uid 0, pid 1)")
    assert started.task_id is not None and tasks.running() is True
    release.set()
    for _ in range(500):
        if not tasks.running():
            break
        threading.Event().wait(0.01)
    assert tasks.running() is False


def test_the_kind_comes_from_the_agents_file_and_never_from_the_agent(
    world: World,  # noqa: F811
) -> None:
    found = load_installation(main_config(world.home))
    assert kind_of(found.main).profile == "openclaw" and kind_of(found.main).version
    assert kind_of(found.others[0]).profile in PROFILES


def test_a_made_agent_comes_into_the_list_with_its_kind(world: World) -> None:  # noqa: F811
    assert world.fleet.create(GOOD, "cli (uid 0, pid 1)")["ok"] is True
    item = next(one for one in world.roster.listing() if one["slug"] == "tercero")
    assert item["kind"] == "claude-code" and item["version"] and item["order"] is None


def test_the_client_keeps_only_what_looks_like_a_word(folder: Path) -> None:  # noqa: F811
    class Listing(ControlServer):
        def _handle(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
            return {
                "ok": True,
                "outcome": "listed",
                "message": "",
                "agents": [
                    {
                        "slug": "principal",
                        "name": None,
                        "main": True,
                        "watched": True,
                        "state": "running",
                        "notice": [],
                        "kind": "claude-code",
                        "version": "2.1.306",
                        "in_use": "task",
                        "order": "<script>",
                    },
                    {
                        "slug": "revisor",
                        "name": None,
                        "main": False,
                        "watched": False,
                        "state": None,
                        "kind": 7,
                        "version": "x" * 41,
                    },
                ],
                "deleted": [
                    {
                        "slug": "viejo",
                        "name": None,
                        "state": "retired",
                        "deleted_at": "2026-11-01T00:00:00+00:00",
                        "purge_after": "2026-11-08T00:00:00+00:00",
                        "purged": False,
                    },
                    {"slug": "../x"},
                ],
            }

    server = Listing(FakeGuardian(), folder / "c.sock", peer=me)
    server.start()
    try:
        agents, deleted = ask_fleet(folder / "c.sock", wait=1, peer=me)
    finally:
        server.close()
    assert agents[0]["kind"] == "claude-code" and agents[0]["in_use"] == "task"
    assert agents[0]["order"] is None  # what it does not understand is not said
    assert agents[1]["kind"] is None and agents[1]["version"] is None
    assert [item["slug"] for item in deleted] == ["viejo"]


# --- a stop does not wait behind a start ---------------------------------------------------------


class Slow(FakeNeighbours):
    """An agent that comes up only when it is told to."""

    def __init__(self, roster: Roster) -> None:
        super().__init__(roster)
        self.up = threading.Event()
        self.waiting = threading.Event()

    def start_one(self, config: Any) -> None:
        self.calls.append(("start", config.slug))
        self.configs[config.slug] = config
        self.running.add(config.slug)

    def wait_settled(self, slug: str, timeout: float) -> None:
        self.waiting.set()
        assert self.up.wait(10)
        if slug in self.running and self.roster is not None:
            self.roster.publish(Desk(slug, FakeGuardian()))


@pytest.fixture
def slow(world: World) -> Iterator[World]:  # noqa: F811
    neighbours = Slow(world.roster)
    assert world.neighbours is not None
    neighbours.configs = world.neighbours.configs
    neighbours.running = world.neighbours.running
    world.neighbours = neighbours
    world.fleet = world.make()
    yield world
    neighbours.up.set()


def test_a_stop_gets_through_while_another_agent_comes_up(slow: World) -> None:
    """Up to 240 s behind a start would be no brake at all (review of T26-6a)."""
    neighbours = slow.neighbours
    assert isinstance(neighbours, Slow)
    said: list[dict[str, Any]] = []
    creating = threading.Thread(
        target=lambda: said.append(slow.fleet.create(GOOD, "web (uid 1, pid 2)"))
    )
    creating.start()
    assert neighbours.waiting.wait(10)
    assert slow.roster.listing()[-1]["order"] == STARTING

    stopped = slow.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "web (uid 1, pid 2)")
    assert stopped["outcome"] == "stopped", stopped
    assert "revisor" not in neighbours.running

    neighbours.up.set()
    creating.join(10)
    assert said[0]["outcome"] == "created"
    assert slow.roster.listing()[-1]["order"] is None


def test_stopping_the_one_that_comes_up_says_so(slow: World) -> None:
    neighbours = slow.neighbours
    assert isinstance(neighbours, Slow)
    said: list[dict[str, Any]] = []
    creating = threading.Thread(
        target=lambda: said.append(slow.fleet.create(GOOD, "web (uid 1, pid 2)"))
    )
    creating.start()
    assert neighbours.waiting.wait(10)
    stopped = slow.fleet.stop({"cmd": "agent_stop", "agent": "tercero"}, "web (uid 1, pid 2)")
    assert stopped["outcome"] == "stopped", stopped
    neighbours.up.set()
    creating.join(10)
    assert said[0]["outcome"] == "stopped" and "mientras arrancaba" in said[0]["message"]


def test_what_takes_what_the_others_check_is_still_one_at_a_time(world: World) -> None:  # noqa: F811
    """The lock lets go only for the wait: while one is being made, the next is told so."""
    entered, leave = threading.Event(), threading.Event()
    real = world.fleet._create

    def held(*args: Any) -> Any:
        entered.set()
        assert leave.wait(10)
        return real(*args)

    world.fleet._create = held  # type: ignore[method-assign]
    first = threading.Thread(target=lambda: world.fleet.create(GOOD, "cli (uid 0, pid 1)"))
    first.start()
    assert entered.wait(10)
    reply = world.fleet.create({**GOOD, "slug": "cuarto"}, "cli (uid 0, pid 1)")
    leave.set()
    first.join(10)
    assert reply["outcome"] == "refused" and "otra orden" in reply["message"]


def test_a_stop_that_fails_is_what_the_list_says(world: World) -> None:  # noqa: F811
    """«Parado» is Docker's word: the mark alone would have the list say it of a live one."""
    assert world.neighbours is not None
    world.neighbours.stuck = True
    reply = world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "web (uid 1, pid 2)")
    assert reply["outcome"] == "failed"
    item = next(one for one in world.roster.listing() if one["slug"] == "revisor")
    assert item["order"] == STOP_FAILED
    world.neighbours.stuck = False
    assert world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "x")["outcome"] == "stopped"
    item = next(one for one in world.roster.listing() if one["slug"] == "revisor")
    assert item["order"] is None


def test_a_stop_that_raises_does_not_say_stopping_for_good(world: World) -> None:  # noqa: F811
    assert world.neighbours is not None

    def boom(slug: str, requested_by: str = "") -> None:
        raise RuntimeError("docker se ha ido")

    world.neighbours.stop_one = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "web (uid 1, pid 2)")
    item = next(one for one in world.roster.listing() if one["slug"] == "revisor")
    assert item["order"] == STOP_FAILED


def test_a_delete_that_could_not_stop_it_does_not_leave_it_stopped_in_the_list(
    world: World,  # noqa: F811
) -> None:
    """The mark is there and the container is alive: the list says that, not «parado»."""
    assert world.neighbours is not None
    world.neighbours.stuck = True
    reply = world.fleet.delete(
        {"cmd": "agent_delete", "agent": "revisor", "typed": "revisor"}, "web (uid 1, pid 2)"
    )
    assert reply["outcome"] == "failed"
    item = next(one for one in world.roster.listing() if one["slug"] == "revisor")
    assert item["order"] == STOP_FAILED


def test_a_delete_refused_before_it_stopped_anything_leaves_no_word(
    world: World,  # noqa: F811
) -> None:
    world.record_works = False  # not recorded, not done
    reply = world.fleet.delete(
        {"cmd": "agent_delete", "agent": "revisor", "typed": "revisor"}, "web (uid 1, pid 2)"
    )
    assert reply["ok"] is False
    item = next(one for one in world.roster.listing() if one["slug"] == "revisor")
    assert item["order"] is None
