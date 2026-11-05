"""T26-2c: every order of the sockets and the CLI says which agent it is about (docs/47, 6.9).

Real sockets and a fake Guardian per agent, so "the other agent was not touched" is something a test
can state. The real thing, with two Claude Codes, is tests/attacks/test_two_agents_attacks.py.
"""

import json
import logging
import shutil
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from backtide import cli
from backtide.jail import AgentJail
from backtide.notify import LogBridge
from backtide.service import gasto, retenidas, runner, scope, seguir, web_control
from backtide.service.agents import load_agent, load_installation
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlServer,
    ask_agents,
    ask_budget,
    ask_decide,
    ask_end_batch,
    ask_export,
    ask_holds,
    ask_list,
    ask_resume,
    ask_rewind,
    ask_set_budget,
    ask_shell,
    ask_snapshots,
    ask_task_start,
    ask_task_status,
    ask_task_stop,
    ask_untrust,
)
from backtide.service.roster import Desk, Roster
from backtide.service.runner import ServiceRunning
from backtide.service.shell import ExportOutcome, ExportStatus, ShellOutcome, ShellStatus
from backtide.service.tasks import TaskOutcome, TaskStart, TaskStatus
from backtide.service.web_control import WebControlServer
from backtide.snapshots import Snapshot
from tests.test_service_agents import add_agent, main_config, write_main
from tests.test_service_agents import home as home  # noqa: F401, PLC0414 - the fixture
from tests.test_service_control import HOLD, SNAPSHOT, FakeGuardian, me
from tests.test_service_web_control import (
    GROUP,
    LISTED,
    NEWER,
    SESSION,
    UNLISTED,
    FakeBudget,
    signed_in,
    the_web,
)

TASK = "a" * 32


@pytest.fixture(autouse=True)
def _nothing_to_mount(monkeypatch: pytest.MonkeyPatch) -> None:
    """What is mounted is tests/test_service_fleet.py's, and the lab's: here nothing is."""
    monkeypatch.setattr(runner, "ensure_on_disk", lambda _: None)


class Agent(FakeGuardian):
    """A Guardian with its tasks and its shell, all of it written down."""

    agent_state = "running"

    def __init__(self) -> None:
        super().__init__()
        self.tasks: list[tuple[Any, ...]] = []
        self.shells: list[str] = []
        self.exports: list[str] = []

    def task_start(self, prompt: str, *, resume: bool = False, seconds: Any = None,
                   requested_by: str) -> TaskStart:  # fmt: skip
        self.tasks.append(("start", prompt, requested_by))
        return TaskStart(TASK)

    def task_status(self, task_id: str) -> TaskStatus | None:
        self.tasks.append(("status", task_id))
        return TaskStatus(task_id, TaskOutcome.RUNNING)

    def task_stop(self, task_id: str) -> bool | None:
        self.tasks.append(("stop", task_id))
        return True

    def open_shell(self, kind: str, **_: Any) -> ShellOutcome:
        self.shells.append(kind)
        return ShellOutcome(ShellStatus.REFUSED, "no")

    def export(self, destination: str, **_: Any) -> ExportOutcome:
        self.exports.append(destination)
        return ExportOutcome(ExportStatus.REFUSED, "no")

    def touched(self) -> bool:
        return bool(
            self.calls or self.resumes or self.decisions or self.tasks or self.shells
            or self.exports
        )  # fmt: skip


class Two:
    """Both servers on one roster, as ``serve`` makes them."""

    def __init__(self, folder: Path) -> None:
        self.main, self.other = Agent(), Agent()
        self.main_budget, self.other_budget, self.whole = FakeBudget(), FakeBudget(), FakeBudget()
        self.roster = Roster(
            Desk("principal", self.main, self.main_budget, lambda: {}, lambda: [LISTED], "Uno"),
            [("revisor", "Revisor"), ("parado", None)],
        )
        self.desk = Desk(
            "revisor",
            self.other,
            self.other_budget,
            lambda: {"anthropic": "x"},
            lambda: [NEWER],
            notice=("Sus canales.",),
        )
        self.roster.publish(self.desk)
        self.control = ControlServer(
            self.main, folder / "c.sock", peer=me, roster=self.roster, whole_budget=self.whole
        )
        self.web = WebControlServer(
            self.main,
            folder / "w.sock",
            group=GROUP,
            peer=the_web,
            snapshots=lambda: [LISTED],
            sessions=signed_in(),
            on_entry=lambda action, details: True,
            roster=self.roster,
            whole_budget=self.whole,
        )
        self.control.start()
        self.web.start()

    def close(self) -> None:
        self.control.close()
        self.web.close()

    def nobody_touched(self) -> bool:
        return not (self.main.touched() or self.other.touched())


@pytest.fixture
def two() -> Iterator[Two]:
    folder = Path(tempfile.mkdtemp(prefix="vg"))
    folder.chmod(0o700)
    found = Two(folder)
    yield found
    found.close()
    shutil.rmtree(folder, ignore_errors=True)


def talk(server: ControlServer, request: dict[str, Any]) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(server.path))
        sock.sendall(json.dumps(request).encode() + b"\n")
        sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    return json.loads(raw)


# --- the control socket ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "rewind", "snapshot_id": SNAPSHOT},
        {"cmd": "resume"},
        {"cmd": "decide", "hold_id": HOLD, "verdict": "reject"},
        {"cmd": "untrust", "trust_id": "t-0a1b2c3d"},
        {"cmd": "end_batch", "rule_id": "b-01234567"},
        {"cmd": "shell", "kind": "session", "continue": False},
        {"cmd": "task_start", "prompt": "hola"},
        {"cmd": "task_status", "task": TASK},
        {"cmd": "task_stop", "task": TASK},
        {"cmd": "export", "dest": "/exportada/a"},
    ],
    ids=lambda r: r["cmd"],
)
def test_an_order_reaches_the_agent_it_names_and_no_other(
    two: Two, request_: dict[str, Any]
) -> None:
    talk(two.control, {**request_, "agent": "revisor"})
    assert two.other.touched() and not two.main.touched()


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "rewind", "snapshot_id": SNAPSHOT},
        {"cmd": "resume"},
        {"cmd": "decide", "hold_id": HOLD, "verdict": "reject"},
        {"cmd": "task_start", "prompt": "hola"},
    ],
    ids=lambda r: r["cmd"],
)
def test_without_the_field_or_with_principal_it_is_the_main_agents(
    two: Two, request_: dict[str, Any]
) -> None:
    talk(two.control, request_)
    assert two.main.touched() and not two.other.touched()
    before = len(two.main.calls + two.main.decisions + two.main.resumes + two.main.tasks)
    talk(two.control, {**request_, "agent": "principal"})
    assert len(two.main.calls + two.main.decisions + two.main.resumes + two.main.tasks) > before
    assert not two.other.touched()


@pytest.mark.parametrize(
    "named",
    ["nadie", "../revisor", "/etc/passwd", "revisor/", "REVISOR", "", None, 7, ["revisor"],
     {"a": 1}, True],
)  # fmt: skip
@pytest.mark.parametrize("server", ["control", "web"])
def test_an_agent_that_is_nobodys_is_refused_with_nobody_touched(
    two: Two, named: object, server: str, caplog: pytest.LogCaptureFixture
) -> None:
    target = two.control if server == "control" else two.web
    request = {"cmd": "rewind", "snapshot_id": LISTED.id, "agent": named}
    if server == "web":
        request["session"] = SESSION
    with caplog.at_level(logging.WARNING, logger="backtide"):
        reply = talk(target, request)
    assert reply["outcome"] == "refused" and "agente" in reply["message"]
    assert two.nobody_touched()
    assert any("does not have" in record.getMessage() for record in caplog.records)
    if isinstance(named, str) and named:
        assert named not in " ".join(r.getMessage() for r in caplog.records)  # nor what it said


def test_an_agent_that_is_not_watched_is_said_so_and_nobody_is_touched(two: Two) -> None:
    reply = talk(two.control, {"cmd": "resume", "agent": "parado"})
    assert reply["outcome"] == "refused" and "no se está vigilando" in reply["message"]
    assert two.nobody_touched()


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "secrets"},
        {"cmd": "set_secret", "kind": "anthropic", "value": "x"},
        {"cmd": "clear_secret", "kind": "anthropic"},
        {"cmd": "web_link"},
        {"cmd": "passkeys"},
        {"cmd": "agents"},
    ],
    ids=lambda r: r["cmd"],
)
def test_what_is_the_machines_takes_no_agent(two: Two, request_: dict[str, Any]) -> None:
    assert talk(two.control, {**request_, "agent": "revisor"})["outcome"] == "refused"


def test_the_clients_send_the_field_only_when_told(two: Two) -> None:
    path = two.control.path
    assert ask_resume(path, peer=me)["ok"] and two.main.resumes and not two.other.resumes
    assert ask_resume(path, peer=me, agent="revisor")["ok"] and two.other.resumes
    assert ask_rewind(path, SNAPSHOT, peer=me, agent="revisor")["ok"]
    assert two.other.calls and not two.main.calls
    assert ask_decide(path, HOLD, "reject", peer=me, agent="revisor")["ok"]
    assert two.other.decisions and not two.main.decisions
    assert ask_untrust(path, "t-0a1b2c3d", peer=me, agent="revisor")["ok"]
    assert ask_end_batch(path, "b-01234567", peer=me, agent="revisor")["ok"]
    assert not two.main.decisions
    two.other.holds = [{"hold_id": HOLD, "risk": 2}]
    assert [h["hold_id"] for h in ask_holds(path, peer=me, agent="revisor")] == [HOLD]
    assert ask_holds(path, peer=me) == []
    assert ask_list(path, "trusted", peer=me, agent="revisor")
    assert ask_snapshots(path, peer=me, server_uid=None, agent="revisor") == [NEWER]
    assert ask_snapshots(path, peer=me, server_uid=None) == [LISTED]
    assert not ask_shell(path, "session", peer=me, agent="revisor")["ok"]
    assert two.other.shells and not two.main.shells
    assert not ask_export(path, "/exportada/x", peer=me, agent="revisor")["ok"]
    assert two.other.exports and not two.main.exports


def test_a_list_about_nobody_says_why(two: Two) -> None:
    with pytest.raises(ControlError, match="no existe en esta instalación"):
        ask_holds(two.control.path, peer=me, agent="nadie")
    with pytest.raises(ControlError, match="no se está vigilando"):
        ask_list(two.control.path, "batches", peer=me, agent="parado")


def test_each_agent_has_its_own_tasks(two: Two) -> None:
    """T26-5a: an `AgentTasks` per Guardian, so the field chooses whose."""
    path = two.control.path
    assert ask_task_start(path, "hola", peer=me, agent="revisor")["task"] == TASK
    assert ask_task_status(path, TASK, peer=me, agent="revisor")["ok"]
    assert ask_task_stop(path, TASK, peer=me, agent="revisor")
    assert [call[0] for call in two.other.tasks] == ["start", "status", "stop"]
    assert two.main.tasks == []
    assert "revisor" not in str(two.other.tasks[0][2])  # who asked, and never whose it is


def test_the_list_of_agents_has_no_path(two: Two) -> None:
    agents = ask_agents(two.control.path, peer=me)
    words = {"kind": None, "version": None, "in_use": None, "order": None}
    assert agents == [
        {"slug": "principal", "name": "Uno", "main": True, "watched": True, "state": "running",
         "notice": [], **words},
        {"slug": "revisor", "name": "Revisor", "main": False, "watched": True, "state": "running",
         "notice": ["Sus canales."], **words},
        {"slug": "parado", "name": None, "main": False, "watched": False, "state": None,
         "notice": [], **words},
    ]  # fmt: skip


def test_what_the_list_says_is_checked_on_the_way_back(
    two: Two, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        two.roster,
        "listing",
        lambda: [
            {"slug": "../x", "name": None, "main": False, "watched": True, "state": None},
            {"slug": "ok", "name": 7, "main": False, "watched": True, "state": None},
            {"slug": "bueno", "name": None, "main": False, "watched": False, "state": None},
        ],
    )
    assert [a["slug"] for a in ask_agents(two.control.path, peer=me)] == ["bueno"]


# --- the spending, by socket ----------------------------------------------------------------------


def test_each_agents_spending_and_a_cap_of_its_own(two: Two) -> None:
    path = two.control.path
    assert ask_budget(path, peer=me, agent="revisor")["models_waiting"] == ["anthropic"]
    assert ask_budget(path, peer=me)["models_waiting"] == []
    assert ask_set_budget(path, daily_usd="1", monthly_usd=None, peer=me, agent="revisor")["ok"]
    assert len(two.other_budget.caps) == 1 and two.whole.caps == two.main_budget.caps == []


def test_a_cap_that_names_nobody_is_the_whole_installations(two: Two) -> None:
    assert ask_set_budget(two.control.path, daily_usd="9", monthly_usd=None, peer=me)["ok"]
    assert len(two.whole.caps) == 1 and two.main_budget.caps == two.other_budget.caps == []
    # And `--agente principal` is that agent's own, which is what tells them apart.
    ask_set_budget(two.control.path, daily_usd="1", monthly_usd=None, peer=me, agent="principal")
    assert len(two.main_budget.caps) == 1 and len(two.whole.caps) == 1


def test_with_one_agent_a_cap_is_that_agents_as_it_always_was() -> None:
    folder = Path(tempfile.mkdtemp(prefix="vg"))
    folder.chmod(0o700)
    budget = FakeBudget()
    server = ControlServer(Agent(), folder / "c.sock", peer=me, budget=budget)
    server.start()
    try:
        assert ask_set_budget(server.path, daily_usd="9", monthly_usd=None, peer=me)["ok"]
        assert ask_budget(server.path, peer=me, agent="principal")
        assert talk(server, {"cmd": "resume", "agent": "revisor"})["outcome"] == "refused"
    finally:
        server.close()
        shutil.rmtree(folder, ignore_errors=True)
    assert len(budget.caps) == 1


# --- the narrow socket ----------------------------------------------------------------------------


def signed(request: dict[str, Any]) -> dict[str, Any]:
    return {**request, "session": SESSION}


def test_one_live_session_is_good_for_all_and_each_order_says_which(two: Two) -> None:
    reply = talk(two.web, signed({"cmd": "decide", "hold_id": HOLD, "verdict": "approve",
                                  "agent": "revisor"}))  # fmt: skip
    assert reply["ok"]
    assert two.main.decisions == []
    assert two.other.decisions[0][2:] == ("web", f"web (uid {two_uid()}, pid 4242)")
    talk(two.web, signed({"cmd": "decide", "hold_id": HOLD, "verdict": "approve"}))
    assert len(two.main.decisions) == 1


def two_uid() -> int:
    return the_web(None)[1]  # type: ignore[arg-type]


def test_without_a_session_naming_an_agent_changes_nothing(two: Two) -> None:
    reply = talk(two.web, {"cmd": "decide", "hold_id": HOLD, "verdict": "approve",
                           "agent": "revisor"})  # fmt: skip
    assert reply["outcome"] == "refused"
    assert two.nobody_touched()


def test_a_rewind_goes_only_to_a_snapshot_on_that_agents_list(two: Two) -> None:
    """The defence of the narrow socket is per agent, and the field does not get round it."""
    rewind = {"cmd": "rewind", "via": "web"}
    theirs = signed({**rewind, "snapshot_id": NEWER.id, "agent": "revisor"})
    mine_elsewhere = signed({**rewind, "snapshot_id": LISTED.id, "agent": "revisor"})
    nobodys = signed({**rewind, "snapshot_id": UNLISTED.id, "agent": "revisor"})
    assert talk(two.web, mine_elsewhere)["outcome"] == "invalid"
    assert talk(two.web, nobodys)["outcome"] == "invalid"
    assert two.nobody_touched()
    assert talk(two.web, theirs)["ok"]
    assert [c[0] for c in two.other.calls] == [NEWER.id] and two.main.calls == []
    assert talk(two.web, signed({**rewind, "snapshot_id": NEWER.id}))["outcome"] == "invalid"


def test_the_narrow_socket_lists_agents_and_each_ones_snapshots(two: Two) -> None:
    assert [a["slug"] for a in talk(two.web, {"cmd": "agents"})["agents"]] == [
        "principal", "revisor", "parado",
    ]  # fmt: skip
    assert talk(two.web, {"cmd": "snapshots", "agent": "revisor"})["snapshots"] == [NEWER.id]
    assert talk(two.web, {"cmd": "snapshots"})["snapshots"] == [LISTED.id]
    assert talk(two.web, {"cmd": "snapshots", "agent": "parado"})["outcome"] == "refused"


def test_a_tasks_answer_still_takes_a_session_whoever_it_is_about(two: Two) -> None:
    read = {"cmd": "task_status", "task": TASK, "agent": "revisor"}
    assert talk(two.web, read)["outcome"] == "refused"
    assert two.nobody_touched()
    assert talk(two.web, signed(read))["ok"]
    assert two.other.tasks and not two.main.tasks


def test_what_the_narrow_socket_never_serves_it_never_serves_for_an_agent(two: Two) -> None:
    for request in (
        {"cmd": "resume", "agent": "revisor"},
        {"cmd": "shell", "kind": "session", "continue": False, "agent": "revisor"},
        {"cmd": "export", "dest": "/exportada/x", "agent": "revisor"},
        {"cmd": "task_stop", "task": TASK, "agent": "revisor"},
    ):
        assert talk(two.web, signed(request))["outcome"] == "refused"
    assert two.nobody_touched()


# --- who is logged, and who is waited for ---------------------------------------------------------


def test_what_an_order_logs_is_that_agents(two: Two) -> None:
    """A connection runs on the sockets' thread: without this, what goes wrong in a neighbour's
    rewind would land in the main agent's black box."""
    heard: dict[str, list[str]] = {"principal": [], "revisor": []}
    bridges = [
        LogBridge(
            lambda problem, slug=slug: heard[slug].append(problem.message),
            accepts=scope.belongs_to(None if slug == "principal" else slug),
        )
        for slug in heard
    ]
    backtide_logger = logging.getLogger("backtide")
    for bridge in bridges:
        bridge.start()
        backtide_logger.addHandler(bridge)
    two.other.error = RuntimeError("it broke")
    try:
        assert talk(two.control, {"cmd": "resume", "agent": "revisor"})["outcome"] == "problem"
    finally:
        for bridge in bridges:
            backtide_logger.removeHandler(bridge)
            bridge.flush()
            bridge.close()
    assert any("resuming raised" in message for message in heard["revisor"])
    assert not any("resuming raised" in message for message in heard["principal"])


def test_an_order_in_flight_ends_before_its_agent_stops(two: Two) -> None:
    two.other.gate = threading.Event()
    done: list[dict[str, Any]] = []
    asking = threading.Thread(
        target=lambda: done.append(
            talk(two.control, {"cmd": "rewind", "snapshot_id": SNAPSHOT, "agent": "revisor"})
        )  # fmt: skip
    )
    asking.start()
    assert two.other.entered.wait(10)
    retired = threading.Event()
    stopping = threading.Thread(
        target=lambda: (two.roster.retire("revisor"), retired.set())
    )  # fmt: skip
    stopping.start()
    assert not retired.wait(0.2), "it stopped under a rewind in flight"
    # No new one meanwhile.
    assert talk(two.control, {"cmd": "resume", "agent": "revisor"})["outcome"] == "refused"
    two.other.gate.set()
    assert retired.wait(10)
    asking.join(10)
    stopping.join(10)
    assert done[0]["ok"]


def test_a_stuck_order_never_holds_a_stop_for_ever(
    two: Two, caplog: pytest.LogCaptureFixture
) -> None:
    with two.roster.using("revisor"):
        two.roster.retire("revisor", wait=0.01)
    assert "still running" in caplog.text


# --- the wiring -----------------------------------------------------------------------------------


def two_configs(home: Path) -> tuple[ServiceConfig, tuple[ServiceConfig, ...]]:  # noqa: F811
    write_main(home, "[budget]\nauto_prices = false\n")
    add_agent(home, "bueno", number=1)
    found = load_installation(main_config(home))
    return found.main, found.others


def test_serve_gives_both_sockets_one_roster_and_each_agent_comes_and_goes_on_it(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main, others = two_configs(home)
    servers: list[dict[str, Any]] = []
    budgets: dict[str, Any] = {}
    seen: dict[str, Any] = {}
    real_build = runner.build_guardian
    published = threading.Event()

    class Server:
        def __init__(self, guardian: Any, path: Path, **kwargs: Any) -> None:
            servers.append(kwargs)

        def start(self) -> None: ...
        def close(self) -> None: ...

    def build(config: ServiceConfig, **kwargs: Any) -> Any:
        budgets[config.slug] = kwargs["spend_total"]
        return real_build(config, **{**kwargs, "jail": AgentJail(config.jail_config())})

    def run(guardian: Any, alerts: Any, box: Any, *, stop: threading.Event, control: Any,
            **_: Any) -> None:  # fmt: skip
        control.start()
        if threading.current_thread() is threading.main_thread():
            assert published.wait(30)
            roster = servers[0]["roster"]
            seen["up"] = {a["slug"]: a["watched"] for a in roster.listing()}
            stop.set()
        else:
            published.set()
            stop.wait(30)
            control.close()
            seen["gone"] = {a["slug"]: a["watched"] for a in servers[0]["roster"].listing()}

    monkeypatch.setattr(runner, "build_guardian", build)
    monkeypatch.setattr(runner, "run_guardian", run)
    monkeypatch.setattr(runner, "ControlServer", Server)
    runner.serve(main, others=others, handle_signals=False)
    assert seen["up"] == {"principal": True, "bueno": True}
    assert seen["gone"] == {"principal": True, "bueno": False}
    assert budgets["principal"] is budgets["bueno"] is servers[0]["whole_budget"]
    assert budgets["principal"] is not None


def test_a_neighbours_budget_has_only_the_caps_of_its_file(home: Path) -> None:  # noqa: F811
    write_main(home, "[budget]\ndaily_usd = 7\nauto_prices = false\n")
    add_agent(home, "bueno", number=1)
    add_agent(
        home,
        "bajo",
        f'number = 2\nvolume = "{home / "agent-volumes" / "bajo"}"\n[agent]\n'
        'profile = "claude-code"\n[budget]\ndaily_usd = 2\n',
    )
    found = load_installation(main_config(home))
    by_slug = {config.slug: config for config in found.agents}

    class Box:
        def append(self, *_: Any, **__: Any) -> None: ...
        def events(self, **_: Any) -> list[Any]:
            return []

    total = runner.build_spend_total(found.main, found.others)
    tops = {}
    for slug, config in by_slug.items():
        budget, _ = runner.build_budget(config, Box(), None, total)  # type: ignore[arg-type]
        budget.open()
        tops[slug] = budget.status()
    assert tops["bajo"]["own_caps"]["day"] == 2_000_000 and tops["bajo"]["day"]["cap_micro"] == (
        2_000_000
    )
    assert tops["bueno"]["own_caps"] == {"day": None, "month": None}
    assert tops["principal"]["own_caps"] == {"day": None, "month": None}
    assert tops["bueno"]["day"]["cap_micro"] == 7_000_000  # the total's
    assert total.status()["day"]["cap_micro"] == 7_000_000
    # Without a total nothing changes: the machine's are the agent's.
    alone, _ = runner.build_budget(found.main, Box(), None)  # type: ignore[arg-type]
    alone.open()
    assert alone.status()["day"]["cap_micro"] == 7_000_000


@pytest.mark.parametrize(
    "setting",
    ['timezone = "UTC"', "max_inflight = 9", 'prices_url = "http://x"', "auto_prices = 0"],
)
def test_an_agents_file_only_sets_its_caps(home: Path, setting: str) -> None:  # noqa: F811
    add_agent(
        home,
        "bueno",
        f'number = 1\nvolume = "{home / "agent-volumes" / "bueno"}"\n[agent]\n'
        f'profile = "claude-code"\n[budget]\n{setting}\n',
    )
    with pytest.raises(ConfigError, match=r"\[budget\]"):
        load_installation(main_config(home))


@pytest.mark.parametrize("cap", ["0", "-1", '"nada"', "1000000"])
def test_a_cap_that_is_not_one_is_refused_in_an_agents_file(home: Path, cap: str) -> None:  # noqa: F811
    add_agent(
        home,
        "bueno",
        f'number = 1\nvolume = "{home / "agent-volumes" / "bueno"}"\n[agent]\n'
        f'profile = "claude-code"\n[budget]\ndaily_usd = {cap}\n',
    )
    with pytest.raises(ConfigError, match="daily_usd"):
        load_installation(main_config(home))


# --- one agent's file alone -----------------------------------------------------------------------


def test_load_agent_reads_only_that_file(home: Path) -> None:  # noqa: F811
    add_agent(home, "bueno", number=1)
    add_agent(home, "roto", "number = 2\n")  # no volume
    with pytest.raises(ConfigError, match="roto.toml"):
        load_installation(main_config(home))
    assert load_agent(main_config(home)).slug == "principal"
    assert load_agent(main_config(home), "principal").slug == "principal"
    assert load_agent(main_config(home), "bueno").slug == "bueno"
    with pytest.raises(ConfigError, match="roto.toml"):
        load_agent(main_config(home), "roto")


@pytest.mark.parametrize("slug", ["../x", "/etc/passwd", "a/b", "todos", ".."])
def test_load_agent_never_takes_a_path(home: Path, slug: str) -> None:  # noqa: F811
    with pytest.raises(ConfigError):
        load_agent(main_config(home), slug)


def test_load_agent_says_there_is_no_such_agent(home: Path) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match="no agent 'nadie'"):
        load_agent(main_config(home), "nadie")


# --- the CLI --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "order",
    [
        ["retenidas"],
        ["seguir"],
        ["instantaneas"],
        ["gasto"],
        ["tope"],
        ["aprobar", HOLD],
        ["rechazar", HOLD],
        ["rebobinar", SNAPSHOT],
        ["tarea", "hola"],
        ["entrar"],
        ["importar", "/exportada/x"],
        ["exportar", "/exportada/x"],
    ],
    ids=lambda order: order[0],
)
@pytest.mark.parametrize("name", ["../x", "/etc", "a/b", "todos", "A", ""])
def test_agente_never_takes_a_path(
    home: Path,  # noqa: F811
    order: list[str],
    name: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as out:
        cli.main([*order, "--agente", name, "--config", str(main_config(home))])
    assert out.value.code == cli.EXIT_ERROR
    assert "--agente" in capsys.readouterr().err


def service_running(monkeypatch: pytest.MonkeyPatch, *modules: Any) -> None:
    def taken(path: Path) -> Any:
        raise ServiceRunning("busy")

    for module in modules:
        monkeypatch.setattr(module, "take_lock", taken)


def broken_neighbour(home: Path) -> None:  # noqa: F811
    add_agent(home, "bueno", number=1)
    add_agent(home, "roto", "number = 2\n")  # no volume


def test_rechazar_goes_on_with_a_broken_file_and_says_so(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    broken_neighbour(home)
    service_running(monkeypatch, retenidas)
    asked: list[tuple[Any, ...]] = []

    def ask(path: Path, hold: str, verdict: str, **options: Any) -> dict[str, Any]:
        asked.append((hold, verdict, options))
        return {"ok": True, "outcome": "rejected", "message": "Rechazada."}

    monkeypatch.setattr(retenidas, "ask_decide", ask)
    config = str(main_config(home))
    hold = HOLD
    assert cli.main(["rechazar", hold, "--config", config]) == 0
    assert cli.main(["rechazar", hold, "--agente", "roto", "--config", config]) == 0
    assert asked == [(hold, "reject", {}), (hold, "reject", {"agent": "roto"})]
    err = capsys.readouterr().err
    assert "AVISO" in err and "roto.toml" in err


def test_aprobar_lets_something_out_so_it_reads_them_all(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    broken_neighbour(home)
    monkeypatch.setattr(retenidas, "ask_decide", lambda *a, **k: pytest.fail("it asked"))
    code = cli.main(["aprobar", HOLD, "--config", str(main_config(home))])
    assert code == cli.EXIT_ERROR and "roto.toml" in capsys.readouterr().err


def test_aprobar_says_which_agent(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_agent(home, "bueno", number=1)
    service_running(monkeypatch, retenidas)
    asked: list[dict[str, Any]] = []

    def ask(path: Path, hold: str, verdict: str, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return {"ok": True, "outcome": "released", "message": "Aprobada."}

    monkeypatch.setattr(retenidas, "ask_decide", ask)
    config = str(main_config(home))
    hold = HOLD
    assert cli.main(["aprobar", hold, "--agente", "bueno", "--config", config]) == 0
    assert asked == [{"agent": "bueno"}]
    assert cli.main(["aprobar", hold, "--agente", "nadie", "--config", config]) == cli.EXIT_ERROR
    assert len(asked) == 1


def test_seguir_goes_on_with_a_broken_file(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken_neighbour(home)
    service_running(monkeypatch, seguir)
    asked: list[dict[str, Any]] = []

    def ask(path: Path, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return {"ok": True, "outcome": "resumed", "message": "Sigue.", "agent_state": "running"}

    monkeypatch.setattr(seguir, "ask_resume", ask)
    assert cli.main(["seguir", "--agente", "roto", "--config", str(main_config(home))]) == 0
    assert asked == [{"agent": "roto"}]


@pytest.mark.parametrize(
    "broken",
    ['[agent]\nprofile = ["x"]\n', "[agent]\nprofile = 7\n", "number = 2\n", "no es toml ["],
    ids=["a list", "a number", "no volume", "not toml"],
)
def test_whatever_is_wrong_with_a_file_rejecting_goes_on(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    broken: str,
) -> None:
    """Review of T26-2c: a value of the wrong type raised a TypeError, and the warning itself
    stopped the very thing it warned about."""
    volume = home / "agent-volumes" / "roto"
    start = "" if broken.startswith(("number", "no es")) else f'number = 2\nvolume = "{volume}"\n'
    add_agent(home, "roto", start + broken)
    service_running(monkeypatch, retenidas)
    monkeypatch.setattr(
        retenidas,
        "ask_decide",
        lambda *a, **k: {"ok": True, "outcome": "rejected", "message": "Rechazada."},
    )
    assert cli.main(["rechazar", HOLD, "--config", str(main_config(home))]) == 0
    assert "AVISO" in capsys.readouterr().err
    with pytest.raises(ConfigError):
        load_installation(main_config(home))


def test_a_value_of_the_wrong_type_never_reaches_the_message(home: Path) -> None:  # noqa: F811
    volume = home / "agent-volumes" / "roto"
    add_agent(home, "roto", f'number = 2\nvolume = "{volume}"\n[agent]\nprofile = ["secreto"]\n')
    with pytest.raises(ConfigError) as refused:
        load_agent(main_config(home), "roto")
    assert "secreto" not in str(refused.value)


def test_rebobinar_with_no_service_refuses_a_volume_that_is_anothers_too(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review of T26-2c: a file copied without changing its volume. The service refuses it; with no
    service, rewinding b would rewind a's and write it in b's box."""
    same = home / "agent-volumes" / "a"
    for slug, number in (("a", 1), ("b", 2)):
        add_agent(
            home, slug, f'number = {number}\nvolume = "{same}"\n[agent]\nprofile = "claude-code"\n'
        )
    add_agent(home, "roto", "number = 3\n")
    target = Snapshot.parse(SNAPSHOT)

    class Store:
        def __init__(self, volume: Path, **_: Any) -> None: ...
        def snapshots(self) -> list[Any]:
            return [target]

    monkeypatch.setattr(cli, "SnapshotStore", Store)
    monkeypatch.setattr(cli, "_rewind_in_process", lambda *a: pytest.fail("it rewound"))
    code = cli.main(
        ["rebobinar", SNAPSHOT, "--si", "--agente", "b", "--config", str(main_config(home))]
    )
    assert code == cli.EXIT_ERROR
    assert "share a folder" in capsys.readouterr().err


def test_rebobinar_with_no_service_is_not_stopped_by_a_file_that_cannot_be_read(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken_neighbour(home)
    target = Snapshot.parse(SNAPSHOT)
    done: list[tuple[Any, ...]] = []

    class Store:
        def __init__(self, volume: Path, **_: Any) -> None: ...
        def snapshots(self) -> list[Any]:
            return [target]

    monkeypatch.setattr(cli, "SnapshotStore", Store)
    monkeypatch.setattr(cli, "_rewind_in_process", lambda *a: done.append(a) or 0)
    code = cli.main(
        ["rebobinar", SNAPSHOT, "--si", "--agente", "bueno", "--config", str(main_config(home))]
    )
    assert code == 0 and len(done) == 1


def test_a_broken_machine_file_stops_even_what_stops(
    home: Path,  # noqa: F811
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_main(home, "nothing_of_this = 1\n")
    assert cli.main(["seguir", "--config", str(main_config(home))]) == cli.EXIT_ERROR
    assert "configuración no válida" in capsys.readouterr().err


def test_retenidas_lists_every_agent_so_no_hold_goes_unseen(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    add_agent(home, "bueno", number=1)
    service_running(monkeypatch, retenidas)
    monkeypatch.setattr(
        retenidas,
        "ask_agents",
        lambda path: [
            {"slug": "principal", "watched": True},
            {"slug": "bueno", "watched": True},
            {"slug": "parado", "watched": False},
        ],
    )

    def holds(path: Path, *, agent: str) -> list[dict[str, Any]]:
        if agent == "bueno":
            return [{"hold_id": HOLD, "risk": 2, "method": "DELETE",
                     "host": "cubos.ejemplo.test"}]  # fmt: skip
        return []

    monkeypatch.setattr(retenidas, "ask_holds", holds)
    assert cli.main(["retenidas", "--config", str(main_config(home))]) == 0
    out = capsys.readouterr().out
    assert out.index("Agente principal:") < out.index("Agente bueno:") < out.index("h-0123456789")
    assert "Agente parado:\n  no se está vigilando." in out
    assert "--agente <agente>" in out


def test_retenidas_with_one_agent_looks_as_it_always_did(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    service_running(monkeypatch, retenidas)
    monkeypatch.setattr(
        retenidas, "ask_agents", lambda path: [{"slug": "principal", "watched": True}]
    )
    monkeypatch.setattr(retenidas, "ask_holds", lambda path: [])
    assert cli.main(["retenidas", "--config", str(main_config(home))]) == 0
    assert capsys.readouterr().out == f"{retenidas.NONE_HELD}\n"


def test_rebobinar_looks_at_that_agents_volume_and_asks_about_it(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    add_agent(home, "bueno", number=1)
    target = Snapshot.parse(SNAPSHOT)
    looked: list[Path] = []

    class Store:
        def __init__(self, volume: Path, **_: Any) -> None:
            looked.append(volume)

        def snapshots(self) -> list[Any]:
            return [target]

    asked: list[dict[str, Any]] = []

    def ask(path: Path, snapshot: str, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return {"ok": True, "outcome": "done", "undo": SNAPSHOT, "message": "Hecho.",
                "agent_started": True}  # fmt: skip

    monkeypatch.setattr(cli, "SnapshotStore", Store)
    monkeypatch.setattr(cli, "ask_rewind", ask)
    service_running(monkeypatch, cli)
    code = cli.main(
        ["rebobinar", SNAPSHOT, "--si", "--agente", "bueno", "--config", str(main_config(home))]
    )
    assert code == 0
    assert looked == [home / "agent-volumes" / "bueno"]
    assert asked == [{"agent": "bueno"}]
    assert f"backtide rebobinar {SNAPSHOT} --agente bueno" in capsys.readouterr().out


def test_rebobinar_goes_on_with_a_neighbours_broken_file(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken_neighbour(home)
    target = Snapshot.parse(SNAPSHOT)

    class Store:
        def __init__(self, volume: Path, **_: Any) -> None: ...
        def snapshots(self) -> list[Any]:
            return [target]

    asked: list[dict[str, Any]] = []

    def ask(path: Path, snapshot: str, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return {"ok": True, "outcome": "done", "undo": None, "message": "Hecho.",
                "agent_started": True}  # fmt: skip

    monkeypatch.setattr(cli, "SnapshotStore", Store)
    monkeypatch.setattr(cli, "ask_rewind", ask)
    service_running(monkeypatch, cli)
    config = str(main_config(home))
    assert cli.main(["rebobinar", SNAPSHOT, "--si", "--config", config]) == 0
    assert cli.main(["rebobinar", SNAPSHOT, "--si", "--agente", "bueno", "--config", config]) == 0
    assert asked == [{}, {"agent": "bueno"}]


def test_rebobinar_with_its_own_broken_file_asks_the_running_service(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """It may be running with what it read when it started, and it is the one to undo."""
    broken_neighbour(home)
    target = Snapshot.parse(SNAPSHOT)
    listed: list[dict[str, Any]] = []
    asked: list[dict[str, Any]] = []

    def snapshots(path: Path, **options: Any) -> list[Any]:
        listed.append(options)
        return [target]

    def ask(path: Path, snapshot: str, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return {"ok": True, "outcome": "done", "undo": None, "message": "Hecho.",
                "agent_started": True}  # fmt: skip

    monkeypatch.setattr(cli, "ask_snapshots", snapshots)
    monkeypatch.setattr(cli, "ask_rewind", ask)
    service_running(monkeypatch, cli)
    code = cli.main(
        ["rebobinar", SNAPSHOT, "--si", "--agente", "roto", "--config", str(main_config(home))]
    )
    assert code == 0
    assert listed == [{"server_uid": None, "agent": "roto"}]
    assert asked == [{"agent": "roto"}]
    assert "roto.toml" in capsys.readouterr().err


def test_rebobinar_with_its_own_broken_file_and_no_service_is_refused(
    home: Path,  # noqa: F811
    capsys: pytest.CaptureFixture[str],
) -> None:
    broken_neighbour(home)
    code = cli.main(
        ["rebobinar", SNAPSHOT, "--si", "--agente", "roto", "--config", str(main_config(home))]
    )
    assert code == cli.EXIT_ERROR
    assert "hace falta el archivo" in capsys.readouterr().err


def test_instantaneas_of_an_agent_that_does_not_exist_is_said(
    home: Path,  # noqa: F811
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = cli.main(["instantaneas", "--agente", "nadie", "--config", str(main_config(home))])
    assert code == cli.EXIT_ERROR
    assert "nadie" in capsys.readouterr().err


def test_gasto_says_the_total_and_each_ones_part(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    service_running(monkeypatch, gasto)
    part = {"spent_micro": 1_000_000, "cap_micro": 5_000_000}
    status = {
        "available": True,
        "day": part,
        "month": part,
        "blocked": None,
        "prices": {"defaults_on": "2026-01-01", "updated_on": None},
        "own_caps": {"day": 2_000_000, "month": None},
        "installation": {
            "available": True,
            "day": part,
            "month": part,
            "blocked": None,
            "agents": {"bueno": {"day_micro": 1_000_000, "month_micro": 1_000_000}},
        },
    }
    asked: list[dict[str, Any]] = []

    def read(path: Path, **options: Any) -> dict[str, Any]:
        asked.append(options)
        return status

    monkeypatch.setattr(gasto, "ask_budget", read)
    config = str(main_config(home))
    assert cli.main(["gasto", "--config", config]) == 0
    assert "Total de la instalación hoy: 1,00 $ de 5,00 $." in capsys.readouterr().out
    assert cli.main(["tope", "--agente", "principal", "--config", config]) == 0
    out = capsys.readouterr().out
    assert "Tope diario de toda la instalación: 5,00 $" in out
    assert "Tope diario de principal: 2,00 $" in out
    assert "Tope mensual de principal: no tiene" in out
    assert asked == [{}, {"agent": "principal"}]
    assert cli.main(["tope", "--config", config]) == 0
    assert "Tope mensual de toda la instalación" in capsys.readouterr().out


def test_a_total_that_makes_no_sense_is_not_shown(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    service_running(monkeypatch, gasto)
    part = {"spent_micro": 1, "cap_micro": 5}
    monkeypatch.setattr(
        gasto,
        "ask_budget",
        lambda path: {
            "available": True,
            "day": part,
            "month": part,
            "prices": {"defaults_on": "2026-01-01"},
            "installation": {"available": True, "day": part, "month": {"spent_micro": "x"}},
        },
    )
    assert cli.main(["gasto", "--config", str(main_config(home))]) == cli.EXIT_ERROR
    assert "no es la esperada" in capsys.readouterr().err


def test_the_shell_orders_name_a_neighbour_and_not_the_main_one(home: Path) -> None:  # noqa: F811
    from backtide import shell_cli  # noqa: PLC0415

    add_agent(home, "bueno", number=1)
    found = load_installation(main_config(home))
    assert shell_cli._about(found.main) == {}  # noqa: SLF001
    assert shell_cli._about(found.others[0]) == {"agent": "bueno"}  # noqa: SLF001


def test_the_web_still_finds_the_snapshots_client_where_it_was() -> None:
    assert web_control.ask_snapshots is ask_snapshots


@pytest.mark.parametrize("notice", [7, ["x" * 601], ["uno"] * 9, [7], None])
def test_a_notice_that_makes_no_sense_is_none(two: Two, notice: object) -> None:
    """What the web shows on a rewind's confirmation is checked like the rest of the list."""
    item = {"slug": "bueno", "name": None, "main": False, "watched": True, "state": None}
    with patch.object(two.roster, "listing", return_value=[{**item, "notice": notice}]):
        assert ask_agents(two.control.path, peer=me) == [
            {**item, "notice": [], "kind": None, "version": None, "in_use": None, "order": None}
        ]


@pytest.mark.parametrize(
    ("agent", "seen"),
    [("revisor", "the agent revisor"), (None, None)],
)
def test_trusting_warns_in_the_box_of_that_agent_and_names_it(
    two: Two, caplog: pytest.LogCaptureFixture, agent: str | None, seen: str | None
) -> None:
    """The warning of a recipient trusted for good: while that agent's order runs, so the log
    bridge takes it to its box, and saying whose (review of T26-2c)."""
    scopes: list[str | None] = []

    class Note(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if "to trust a recipient" in record.getMessage():
                scopes.append(scope.current())

    note = Note()
    logging.getLogger("backtide.service.web_control").addHandler(note)
    try:
        request = {"cmd": "trust", "hold_id": HOLD, "session": SESSION, "via": "web"}
        talk(two.web, {**request, **({"agent": agent} if agent else {})})
    finally:
        logging.getLogger("backtide.service.web_control").removeHandler(note)
    message = next(
        r.getMessage() for r in caplog.records if "to trust a recipient" in r.getMessage()
    )
    assert (seen in message) if seen else ("the agent" not in message)
    assert scopes == [agent]


def test_trusting_nobody_warns_only_of_the_refusal(
    two: Two, caplog: pytest.LogCaptureFixture
) -> None:
    request = {"cmd": "trust", "hold_id": HOLD, "session": SESSION, "agent": "nadie"}
    assert talk(two.web, request)["outcome"] == "refused"
    assert "to trust a recipient" not in caplog.text
