"""T26-2e: one Telegram bot and two agents (docs/47, section 6.10).

The whole of the bot's side, as ``serve`` puts it together (``telegram_parts``), against the fake
Bot API: the real desks, the real ``GuardianActions``, the real control socket with its roster, a
real black box per agent, and a fake Guardian per agent, so "the other agent was not touched" is
something a test can state. The real thing, with two Claude Codes under the unit, is the scenario
``boton-de-otro-agente`` (tests/attacks/test_two_agents_telegram_attacks.py).
"""

import logging
import os
import shutil
import socket
import tempfile
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from telegram_fake import OWNER, STRANGER, TOKEN, Call, FakeBotApi, buttons
from test_notify_hold import notice
from test_service_control import FakeGuardian

from backtide.blackbox import BlackBox, create_key
from backtide.notify import Alert, AlertLevel, Labelled
from backtide.notify.buttons import Action, ButtonBook
from backtide.notify.hold_notice import AGENT, AGENT_END, AGENT_HEAD, HoldDesk, quote_entities
from backtide.notify.telegram import (
    HELP,
    MAX_TEXT,
    NOBODY_BUTTON,
    AgentSide,
    TelegramBot,
    TelegramNotifier,
)
from backtide.notify.telegram_api import BotApi
from backtide.service import scope
from backtide.service.agents import load_installation
from backtide.service.bot import (
    GuardianActions,
    TelegramNeighbour,
    TelegramParts,
    telegram_parts,
)
from backtide.service.config import Secret, ServiceConfig
from backtide.service.control import ControlServer, ask_decide, ask_rewind
from backtide.service.holds import BatchOutcome, BatchStatus, HoldStatus
from backtide.service.pause import PauseOutcome, PauseStatus, ResumeOutcome, ResumeStatus
from backtide.service.roster import Desk, Roster
from backtide.service.runner import _Neighbours
from backtide.service.telegram_config import TelegramSettings
from backtide.snapshots import Snapshot
from tests.test_service_agents import add_agent, main_config
from tests.test_service_agents import home as home  # noqa: F401, PLC0414 - the fixture

WAIT = 5.0
MAIN, OTHER = "principal", "revisor"
HOLD = "h-0123456789ab"
BEFORE = datetime(2026, 10, 1, 12, tzinfo=UTC)
MAIN_SNAPSHOT = Snapshot(BEFORE, "periodic")
OTHER_SNAPSHOT = Snapshot(BEFORE + timedelta(minutes=1), "periodic")


def ours(sock: socket.socket) -> tuple[int, int, int]:
    """The bot lives in the service: only its own process may ask as ``telegram``."""
    return os.getpid(), os.geteuid(), os.getegid()


class Guard(FakeGuardian):
    """One agent's Guardian, with all the bot may ask of it written down."""

    agent_state = "running"
    pause_reasons: frozenset[str] = frozenset()
    late_pause_lifts = False

    def __init__(self, mark: int = 7) -> None:
        super().__init__()
        self.mark = mark
        self.marks_seen: list[int | None] = []
        self.pauses: list[str] = []
        self.batches_made: list[tuple[str, str]] = []
        self.ended: list[str] = []
        self.rules: list[dict[str, Any]] = []

    def pause_by_user(self, *, requested_by: str) -> PauseOutcome:
        self.pauses.append(requested_by)
        return PauseOutcome(PauseStatus.FROZEN, "Agente congelado: no hace nada hasta /seguir.")

    def user_pause_mark(self) -> int:
        return self.mark

    def resume(self, *, requested_by: str, pause_mark: int | None = None) -> ResumeOutcome:  # type: ignore[override]
        self.resumes.append(requested_by)
        self.marks_seen.append(pause_mark)
        return ResumeOutcome(ResumeStatus.RESUMED, "El agente sigue donde estaba.")

    def batches(self) -> list[dict[str, Any]]:
        return list(self.rules)

    def create_batch(self, hold_id: str, kind: str, *, via: str, requested_by: str) -> BatchOutcome:
        self.batches_made.append((hold_id, kind))
        return BatchOutcome(BatchStatus.CREATED, hold_id, "b-01234567", HoldStatus.RELEASED)

    def end_batch(self, rule_id: str, *, via: str) -> bool:
        self.ended.append(rule_id)
        return True

    def touched(self) -> bool:
        return bool(
            self.pauses or self.resumes or self.calls or self.decisions or self.batches_made
            or self.ended
        )  # fmt: skip


class Store:
    def __init__(self, *found: Snapshot) -> None:
        self.found = list(found)

    def snapshots(self) -> list[Snapshot]:
        return list(self.found)


class Rig:
    """Two agents behind one bot: the service's parts, one control socket, one roster."""

    def __init__(self, home: Path, sockets: Path, fake: FakeBotApi) -> None:
        self.fake = fake
        add_agent(home, OTHER)
        found = load_installation(main_config(home))
        main, others = found.main, found.others
        main = _with_short_socket(main, sockets)
        self.settings = TelegramSettings(_secret(), OWNER, fake.base)
        self.parts: TelegramParts = telegram_parts(main, self.settings, others)
        self.side = self.parts.neighbours[OTHER]
        # SO_PEERCRED is Linux's: on the Mac the client is told who the server is.
        for actions in (self.parts.actions, self.side.actions):
            actions._ask = partial(ask_rewind, peer=ours)  # noqa: SLF001
            actions._ask_decision = partial(ask_decide, peer=ours)  # noqa: SLF001
        self.book: ButtonBook = self.parts.bot._book  # noqa: SLF001
        self.main, self.other = Guard(mark=7), Guard(mark=3)  # their pauses are each its own
        self.main_box = _box(sockets / "m")
        self.other_box = _box(sockets / "o")
        self.parts.actions.bind(self.main, self.main_box, Store(MAIN_SNAPSHOT))  # type: ignore[arg-type]
        self.roster = Roster(Desk(MAIN, self.main), [(OTHER, None)])
        self.roster.publish(Desk(OTHER, self.other))
        self.server = ControlServer(self.main, main.control_socket, peer=ours, roster=self.roster)
        self.server.start()
        self.watch = self.side.watch(self.other, self.other_box, Store(OTHER_SNAPSHOT))
        self.watch.start()
        self.parts.bot.start()
        self.notifiers = {
            slug: Labelled(self.parts.notifier, slug, threading.Lock()) for slug in (MAIN, OTHER)
        }
        deadline = time.monotonic() + WAIT
        while fake.polls() < 1:
            assert time.monotonic() < deadline, "the bot never polled"
            time.sleep(0.01)

    def close(self) -> None:
        self.parts.bot.close()
        self.watch.close()
        self.server.close()
        self.main_box.close()
        self.other_box.close()

    # What the owner sees

    def bound(self, call: Call) -> Call:
        tokens = [data for _, data in buttons(call)]
        deadline = time.monotonic() + WAIT
        while not all(
            (found := self.book.peek(token)) is not None and found.message_id == call.message_id
            for token in tokens
        ):
            assert time.monotonic() < deadline, "the buttons were never bound"
            time.sleep(0.01)
        return call

    def message(self, contains: str, after: float = float("-inf")) -> Call:
        found = self.fake.wait_call(
            "sendMessage", lambda c: contains in c.params.get("text", ""), after=after
        )
        return self.bound(found)

    def alert(self, slug: str, box: BlackBox) -> Call:
        seq = box.append("system", "space_pause", "", details={}, risk=2).seq
        before = time.monotonic()
        self.notifiers[slug].send(Alert(AlertLevel.ERROR, "Algo", "cuerpo", seq))
        return self.bound(self.fake.wait_call("sendMessage", after=before))

    def press(self, call: Call, label: str) -> float:
        before = time.monotonic()
        self.fake.push_callback(dict(buttons(call))[label], call.message_id)
        return before

    def say(self, text: str, **options: Any) -> float:
        before = time.monotonic()
        self.fake.push_message(text, **options)
        return before

    def settle(self) -> None:
        last = self.fake.next_update_id
        deadline = time.monotonic() + WAIT
        while self.fake.confirmed() < last:
            assert time.monotonic() < deadline, "the bot did not take the updates"
            time.sleep(0.01)
        time.sleep(0.1)  # the work and send threads

    def replies_after(self, before: float) -> list[str]:
        self.settle()
        return [c.params["text"] for c in self.fake.sent() if c.at >= before]

    def ignored(self) -> list[dict[str, Any]]:
        return [e.details for e in self.main_box.events() if e.action == "telegram_ignored"]


def _secret() -> Secret:
    return Secret(TOKEN)


def _with_short_socket(config: ServiceConfig, sockets: Path) -> Any:
    """A Unix socket's path is short, and ``tmp_path`` is not: ``control_socket`` is a property of
    the state folder, so this asks for it through a small stand-in."""

    class Short:
        control_socket = sockets / "c.sock"
        slug = config.slug
        agent_profile = config.agent_profile

    return Short()


def _box(folder: Path) -> BlackBox:
    folder.mkdir()
    made = BlackBox(folder / "bb.db", create_key(folder / "bb.key"))
    made.open()
    return made


@pytest.fixture
def rig(home: Path) -> Iterator[Rig]:  # noqa: F811
    sockets = Path(tempfile.mkdtemp(prefix="vg"))
    sockets.chmod(0o700)
    with FakeBotApi(max_poll=1.0) as fake:
        made = Rig(home, sockets, fake)
        try:
            yield made
        finally:
            made.close()
    shutil.rmtree(sockets, ignore_errors=True)


# --- the alerts -----------------------------------------------------------------------------------


def test_a_neighbours_alert_says_whose_and_its_pause_acts_on_it_alone(rig: Rig) -> None:
    call = rig.alert(OTHER, rig.other_box)
    assert f"{OTHER}: Algo" in call.params["text"]
    assert [label for label, _ in buttons(call)] == ["Pausar", "Rebobinar"]
    before = rig.press(call, "Pausar")
    reply = rig.message("congelado", after=before)
    assert reply.params["text"].startswith(f"Agente {OTHER}:\n")
    assert rig.other.pauses == ["telegram"]
    assert not rig.main.touched()


def test_the_main_agents_alert_acts_on_it_alone(rig: Rig) -> None:
    call = rig.alert(MAIN, rig.main_box)
    assert f"{MAIN}: Algo" in call.params["text"]
    rig.press(call, "Pausar")
    rig.message("congelado")
    assert rig.main.pauses == ["telegram"]
    assert not rig.other.touched()


def test_rewinding_from_a_neighbours_alert_offers_and_rewinds_its_own_snapshot(rig: Rig) -> None:
    call = rig.alert(OTHER, rig.other_box)
    button = rig.book.peek(dict(buttons(call))["Rebobinar"])
    assert button is not None and button.snapshot_id == OTHER_SNAPSHOT.id
    before = rig.press(call, "Rebobinar")
    question = rig.message("¿Rebobinar?", after=before)
    assert question.params["text"].startswith(f"Agente {OTHER}:\n")
    before = rig.press(question, "Sí, rebobinar")
    done = rig.message("Rebobinado", after=before)
    assert done.params["text"].startswith(f"Agente {OTHER}:\n")
    assert [snapshot for snapshot, _ in rig.other.calls] == [OTHER_SNAPSHOT.id]
    assert rig.other.calls[0][1].startswith("telegram (uid")
    assert not rig.main.touched()


def test_rewinding_the_main_agent_goes_on_as_always(rig: Rig) -> None:
    call = rig.alert(MAIN, rig.main_box)
    before = rig.press(call, "Rebobinar")
    question = rig.message("¿Rebobinar?", after=before)
    rig.press(question, "Sí, rebobinar")
    rig.message("Rebobinado", after=before)
    assert [snapshot for snapshot, _ in rig.main.calls] == [MAIN_SNAPSHOT.id]
    assert not rig.other.touched()


def test_a_rewind_the_neighbour_can_no_longer_take_touches_nobody(rig: Rig) -> None:
    """Gone from the roster between the question and the yes: the socket says so, by name."""
    call = rig.alert(OTHER, rig.other_box)
    before = rig.press(call, "Rebobinar")
    question = rig.message("¿Rebobinar?", after=before)
    rig.roster.retire(OTHER)
    before = rig.press(question, "Sí, rebobinar")
    said = rig.message("no se está vigilando", after=before)
    assert said.params["text"].startswith(f"Agente {OTHER}:\n")
    assert not rig.other.touched() and not rig.main.touched()


@pytest.mark.parametrize("agent", [None, "borrado"])
def test_an_alert_of_nobody_on_the_list_offers_no_button(rig: Rig, agent: str | None) -> None:
    before = time.monotonic()
    rig.parts.notifier.send(Alert(AlertLevel.WARNING, "Algo", "cuerpo", 1, agent=agent))
    sent = rig.fake.wait_call("sendMessage", after=before)
    assert "reply_markup" not in sent.params
    assert len(rig.book) == 0


# --- the held requests ----------------------------------------------------------------------------


def _notice_of(rig: Rig, slug: str, **changes: Any) -> Call:
    before = time.monotonic()
    desk = rig.side.desk if slug == OTHER else rig.parts.desk
    desk.held(notice(**changes))
    return rig.bound(rig.fake.wait_call("sendMessage", after=before))


def test_a_neighbours_hold_says_whose_first_and_its_yes_goes_to_it_alone(rig: Rig) -> None:
    call = _notice_of(rig, OTHER)
    assert call.params["text"].startswith(f"Agente {OTHER}:\n⏸ backtide · RETENIDA")
    before = rig.press(call, "Aprobar")
    rig.fake.wait_call("answerCallbackQuery", after=before)
    deadline = time.monotonic() + WAIT
    while not rig.other.decisions:
        assert time.monotonic() < deadline, "the neighbour was never asked"
        time.sleep(0.01)
    assert rig.other.decisions[0][:3] == (HOLD, "approve", "telegram")
    assert not rig.main.touched()


def test_the_same_hold_id_on_each_agent_is_two_holds(rig: Rig) -> None:
    """Each gate makes its own ids: the end of one uses up no button of the other's."""
    mine = _notice_of(rig, MAIN)
    theirs = _notice_of(rig, OTHER)
    rig.parts.desk.closed(HOLD, "rejected", "web")
    rig.fake.wait_call("editMessageText", lambda c: c.params["message_id"] == mine.message_id)
    before = rig.press(mine, "Aprobar")
    rig.fake.wait_call(
        "answerCallbackQuery", lambda c: "ya está cerrada" in c.params["text"], after=before
    )
    assert not rig.main.decisions
    rig.press(theirs, "Rechazar")
    deadline = time.monotonic() + WAIT
    while not rig.other.decisions:
        assert time.monotonic() < deadline, "the other hold died with the first"
        time.sleep(0.01)
    assert rig.other.decisions[0][:2] == (HOLD, "reject")


def test_ver_reads_the_neighbours_own_black_box(rig: Rig) -> None:
    rig.main_box.append("gate", "held", "", details={"body": {"excerpt": "del principal"}}, risk=2)
    seq = rig.other_box.append(
        "gate", "held", "", details={"body": {"excerpt": "del vecino"}}, risk=2
    ).seq
    call = _notice_of(rig, OTHER, seq=seq)
    before = rig.press(call, "Ver")
    shown = rig.message("del vecino", after=before)
    assert shown.params["text"].startswith(f"Agente {OTHER}:\n")
    assert "del principal" not in shown.params["text"]


def test_a_neighbours_batch_takes_two_taps_on_its_own_gate(rig: Rig) -> None:
    call = _notice_of(rig, OTHER)
    before = rig.press(call, "Todo a este destinatario (sesión)")
    question = rig.message("¿Crear un lote?", after=before)
    assert question.params["text"].startswith(f"Agente {OTHER}:\n")
    before = rig.press(question, "Sí, crear el lote")
    deadline = time.monotonic() + WAIT
    while not rig.other.batches_made:
        assert time.monotonic() < deadline, "the batch never reached the neighbour"
        time.sleep(0.01)
    assert rig.other.batches_made == [(HOLD, "recipient")]
    assert not rig.main.touched()


def test_the_end_of_a_neighbours_hold_is_edited_saying_whose(rig: Rig) -> None:
    call = _notice_of(rig, OTHER)
    rig.side.desk.closed(HOLD, "expired", "timeout")
    edit = rig.fake.wait_call(
        "editMessageText", lambda c: c.params["message_id"] == call.message_id
    )
    assert edit.params["text"].startswith(f"Agente {OTHER}:\n⏸")
    assert "Resultado: Caducada" in edit.params["text"]


def test_the_agents_text_cannot_pass_for_the_name_of_another(rig: Rig) -> None:
    """The name is ours, first and outside the agent's block. Its block stays a quote."""
    fake_head = f"Agente {MAIN}:\n⏸ backtide · RETENIDA · riesgo 2 · {HOLD}"
    call = _notice_of(rig, OTHER, reading={"first_lines": fake_head})
    text = call.params["text"]
    lines = text.split("\n")
    assert lines[0] == f"Agente {OTHER}:"
    agent = lines[lines.index(AGENT_HEAD) + 1 : lines.index(AGENT_END)]
    assert f"{AGENT}Agente {MAIN}:" in agent
    assert all(line.startswith(AGENT) for line in agent)
    assert call.params["entities"] == quote_entities(text)
    entity = call.params["entities"][0]
    quoted = text.encode("utf-16-le")[
        2 * entity["offset"] : 2 * (entity["offset"] + entity["length"])
    ]
    assert quoted.decode("utf-16-le").startswith(AGENT)


def test_a_flood_of_a_neighbour_uses_up_only_its_own_budget(rig: Rig) -> None:
    for n in range(8):
        rig.side.desk.held(notice(hold_id=f"h-{n:012x}"))
    rig.fake.wait_call("sendMessage", lambda c: "retenidas más" in c.params["text"])
    summary = rig.message("retenidas más")
    assert summary.params["text"].startswith(f"Agente {OTHER}:\n")
    before = rig.press(summary, "Pausar")
    rig.message("congelado", after=before)
    assert rig.other.pauses == ["telegram"] and not rig.main.touched()
    mine = _notice_of(rig, MAIN)
    assert mine.params["text"].startswith(f"Agente {MAIN}:\n⏸")


# --- written orders -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("order", "acted", "untouched"),
    [(f"/pausar {OTHER}", "other", "main"), (f"/pausar {MAIN}", "main", "other")],
)
def test_pausar_naming_an_agent_freezes_it_alone(
    rig: Rig, order: str, acted: str, untouched: str
) -> None:
    before = rig.say(order)
    rig.message("congelado", after=before)
    assert getattr(rig, acted).pauses == ["telegram"]
    assert not getattr(rig, untouched).touched()


def test_a_late_pausar_naming_an_agent_still_freezes_it(rig: Rig) -> None:
    before = rig.say(f"/pausar {OTHER}", date=time.time() - 10_000)
    rig.message("congelado", after=before)
    assert rig.other.pauses == ["telegram"]


def test_pausar_without_saying_which_asks_and_touches_nobody(rig: Rig) -> None:
    before = rig.say("/pausar")
    asked = rig.message("todavía no se ha congelado ninguno", after=before)
    assert MAIN in asked.params["text"] and OTHER in asked.params["text"]
    assert [label for label, _ in buttons(asked)] == [
        "Pausar todos", f"Pausar {MAIN}", f"Pausar {OTHER}",
    ]  # fmt: skip
    assert not rig.main.touched() and not rig.other.touched()
    before = rig.press(asked, f"Pausar {OTHER}")
    rig.message("congelado", after=before)
    assert rig.other.pauses == ["telegram"] and not rig.main.touched()


def test_pausar_todos_freezes_each_and_says_so_for_each(rig: Rig) -> None:
    before = rig.say("/pausar")
    asked = rig.message("todavía no se ha congelado ninguno", after=before)
    before = rig.press(asked, "Pausar todos")
    said = rig.message("congelado", after=before).params["text"]
    assert f"Agente {MAIN}:\n" in said and f"Agente {OTHER}:\n" in said
    assert rig.main.pauses == ["telegram"] and rig.other.pauses == ["telegram"]


def test_pausar_todos_goes_on_past_one_that_fails(rig: Rig, caplog: Any) -> None:
    def fails(*, requested_by: str) -> PauseOutcome:
        raise RuntimeError("no docker")

    rig.main.pause_by_user = fails  # type: ignore[method-assign]
    before = rig.say("/pausar")
    asked = rig.message("todavía no se ha congelado ninguno", after=before)
    with caplog.at_level(logging.ERROR, logger="backtide.telegram"):
        before = rig.press(asked, "Pausar todos")
        said = rig.message("congelado", after=before).params["text"]
    assert "No se ha podido congelar" in said and rig.other.pauses == ["telegram"]
    assert "could not be paused" in caplog.text


def test_seguir_without_saying_which_refuses_and_touches_nobody(rig: Rig) -> None:
    before = rig.say("/seguir")
    said = rig.message("no se ha reanudado ninguno", after=before)
    assert MAIN in said.params["text"] and OTHER in said.params["text"]
    assert rig.main.resumes == [] and rig.other.resumes == []


def test_seguir_naming_an_agent_resumes_it_alone(rig: Rig) -> None:
    before = rig.say(f"/seguir {OTHER}")
    said = rig.message("donde estaba", after=before)
    assert said.params["text"].startswith(f"Agente {OTHER}:\n")
    assert rig.other.resumes == ["telegram"] and rig.main.resumes == []
    assert rig.other.marks_seen == [3]  # its own: "a /pausar sent after this /seguir wins"
    before = rig.say(f"/seguir {MAIN}")
    rig.message("donde estaba", after=before)
    assert rig.main.marks_seen == [7]


def test_a_late_seguir_naming_an_agent_is_not_run(rig: Rig) -> None:
    before = rig.say(f"/seguir {OTHER}", date=time.time() - 10_000)
    rig.message("ha llegado tarde", after=before)
    assert rig.other.resumes == []


@pytest.mark.parametrize("command", ["pausar", "seguir", "estado", "retenidas", "lotes"])
@pytest.mark.parametrize(
    "word",
    ["nadie", "../revisor", "/etc", "..", "revisor/../principal", "REVISOR", "revisor principal"],
)
def test_a_made_up_name_is_nobody_and_is_not_repeated(rig: Rig, command: str, word: str) -> None:
    before = rig.say(f"/{command} {word}")
    (said,) = rig.replies_after(before)
    assert "no existe en esta instalación" in said
    assert word not in said.replace(OTHER, "").replace(MAIN, "") or word in (MAIN, OTHER)
    assert not rig.main.touched() and not rig.other.touched()
    recorded = rig.ignored()
    assert [item["reason"] for item in recorded] == ["unknown_agent"]
    assert word not in str(recorded)


def test_a_stranger_naming_an_agent_gets_nothing(rig: Rig) -> None:
    before = rig.say(f"/pausar {OTHER}", chat_id=STRANGER)
    assert rig.replies_after(before) == []
    assert rig.other.pauses == []
    assert [item["reason"] for item in rig.ignored()] == ["not_owner"]


def test_estado_without_saying_which_shows_each_under_its_name(rig: Rig) -> None:
    before = rig.say("/estado")
    (said,) = rig.replies_after(before)
    assert f"Agente {MAIN}:\nAgente: en marcha." in said
    assert f"Agente {OTHER}:\nAgente: en marcha." in said


def test_estado_naming_an_agent_shows_it_alone(rig: Rig) -> None:
    rig.other.agent_state = "frozen"
    before = rig.say(f"/estado {OTHER}")
    (said,) = rig.replies_after(before)
    assert said.startswith(f"Agente {OTHER}:\nAgente: congelado.")
    assert MAIN not in said


def test_the_status_of_a_neighbour_counts_its_own_snapshots(rig: Rig) -> None:
    rig.side.actions.bind(rig.other, rig.other_box, Store(OTHER_SNAPSHOT, MAIN_SNAPSHOT))  # type: ignore[arg-type]
    before = rig.say(f"/estado {OTHER}")
    (said,) = rig.replies_after(before)
    assert "hay 2." in said


def test_the_help_with_several_says_how_to_name_them(rig: Rig) -> None:
    before = rig.say("/nada")
    (said,) = rig.replies_after(before)
    assert f"Hay varios agentes: {MAIN}, {OTHER}." in said
    assert "/pausar <agente>" in said and len(said) < MAX_TEXT


def test_retenidas_lists_each_agents_under_its_name_with_buttons_for_it(rig: Rig) -> None:
    rig.other.holds = [
        {"hold_id": HOLD, "risk": 2, "expires_in_s": 200, "method": "DELETE", "host": "x.test",
         "path": "/y", "reason": "delete"}
    ]  # fmt: skip
    before = rig.say("/retenidas")
    head = rig.message("Hay 1 retenidas", after=before)
    assert head.params["text"].startswith(f"Agente {OTHER}:\n")
    call = rig.message("⏸ backtide", after=before)
    assert call.params["text"].startswith(f"Agente {OTHER}:\n")
    told = rig.message("No hay ninguna petición retenida", after=before)
    assert told.params["text"].startswith(f"Agente {MAIN}:\n")
    rig.press(call, "Rechazar")
    deadline = time.monotonic() + WAIT
    while not rig.other.decisions:
        assert time.monotonic() < deadline, "the neighbour was never asked"
        time.sleep(0.01)
    assert rig.other.decisions[0][:2] == (HOLD, "reject") and rig.main.decisions == []


def test_retenidas_naming_an_agent_lists_it_alone(rig: Rig) -> None:
    rig.main.holds = [{"hold_id": "h-aaaaaaaaaaaa", "risk": 2, "expires_in_s": 200}]
    before = rig.say(f"/retenidas {OTHER}")
    (said,) = rig.replies_after(before)
    assert said == f"Agente {OTHER}:\nNo hay ninguna petición retenida."


def test_revoking_a_neighbours_batch_ends_its_own_rule(rig: Rig) -> None:
    rig.other.rules = [{"rule_id": "b-01234567", "left_s": 100, "method": "POST", "host": "h.test",
                        "route": "/r", "translator": None, "uses": 1}]  # fmt: skip
    before = rig.say(f"/lotes {OTHER}")
    listed = rig.message("Lotes activos", after=before)
    assert listed.params["text"].startswith(f"Agente {OTHER}:\n")
    rig.press(listed, "Revocar 1")
    deadline = time.monotonic() + WAIT
    while not rig.other.ended:
        assert time.monotonic() < deadline, "the neighbour's rule was never ended"
        time.sleep(0.01)
    assert rig.other.ended == ["b-01234567"] and rig.main.ended == []


# --- a button only ever acts on its agent ---------------------------------------------------------


def test_the_data_of_a_button_is_only_a_token_within_telegrams_limit(rig: Rig) -> None:
    calls = [rig.alert(OTHER, rig.other_box), _notice_of(rig, OTHER)]
    for call in calls:
        for _, data in buttons(call):
            assert len(data.encode()) <= 64
            assert OTHER not in data


def test_every_button_of_a_neighbour_is_written_down_as_its(rig: Rig) -> None:
    calls = [rig.alert(OTHER, rig.other_box), _notice_of(rig, OTHER)]
    before = rig.press(calls[0], "Rebobinar")
    calls.append(rig.message("¿Rebobinar?", after=before))
    before = rig.press(calls[1], "Todo a este destinatario (sesión)")
    calls.append(rig.message("¿Crear un lote?", after=before))
    for call in calls:
        for label, data in buttons(call):
            button = rig.book.peek(data)
            assert button is not None and button.agent == OTHER, label


def test_a_made_up_button_acts_on_nobody(rig: Rig) -> None:
    call = rig.alert(MAIN, rig.main_box)
    for data in (f"pause:{OTHER}", OTHER, "pause", "x" * 64, f"{OTHER}:{MAIN_SNAPSHOT.id}"):
        rig.fake.push_callback(data, call.message_id)
    rig.settle()
    assert not rig.main.touched() and not rig.other.touched()
    assert {item["reason"] for item in rig.ignored()} == {"unknown_button"}


def test_one_agents_button_on_another_agents_message_does_nothing(rig: Rig) -> None:
    mine, theirs = rig.alert(MAIN, rig.main_box), rig.alert(OTHER, rig.other_box)
    rig.fake.push_callback(dict(buttons(mine))["Pausar"], theirs.message_id)
    rig.settle()
    assert not rig.main.touched() and not rig.other.touched()
    assert [item["reason"] for item in rig.ignored()] == ["wrong_message"]


@pytest.mark.parametrize("agent", [None, "borrado", "../revisor"])
def test_a_button_of_nobody_on_the_list_acts_on_nobody(rig: Rig, agent: str | None) -> None:
    """Never the main agent in its place: this is the old button of an agent that is gone."""
    token = rig.book.issue(Action.PAUSE, agent=agent)
    rig.book.bind([token], 99)
    before = time.monotonic()
    rig.fake.push_callback(token, 99)
    rig.fake.wait_call(
        "answerCallbackQuery", lambda c: c.params["text"] == NOBODY_BUTTON, after=before
    )
    rig.settle()
    assert not rig.main.touched() and not rig.other.touched()
    assert [item["reason"] for item in rig.ignored()] == ["unknown_agent"]


def test_a_neighbour_that_stops_takes_its_buttons_and_says_so(rig: Rig) -> None:
    mine = rig.alert(MAIN, rig.main_box)
    theirs = rig.alert(OTHER, rig.other_box)
    rig.watch.close()
    before = rig.press(theirs, "Pausar")
    rig.fake.wait_call(
        "answerCallbackQuery", lambda c: "ya no vale" in c.params["text"], after=before
    )
    assert rig.other.pauses == []
    before = rig.say(f"/pausar {OTHER}")
    rig.message("no se está vigilando", after=before)
    before = rig.say(f"/seguir {OTHER}")
    rig.message("no se está vigilando", after=before)
    before = rig.say(f"/estado {OTHER}")
    rig.message("no se está vigilando", after=before)
    assert not rig.other.touched()
    before = rig.press(mine, "Pausar")
    rig.message("congelado", after=before)
    assert rig.main.pauses == ["telegram"]
    # Its alerts of then still go out, offering nothing it cannot do any more.
    rig.notifiers[OTHER].send(Alert(AlertLevel.ERROR, "Se para", "cuerpo", 1))
    last = rig.fake.wait_call("sendMessage", lambda c: "Se para" in c.params["text"])
    assert [label for label, _ in buttons(last)] == ["Pausar"]


def test_a_neighbour_not_up_yet_says_so_and_never_starts_as_the_main_one(tmp_path: Path) -> None:
    actions = GuardianActions(tmp_path / "c.sock", agent=OTHER)
    for said in (actions.pause(), actions.resume(None), actions.status(), actions.end_batch("b")):
        assert f"El agente {OTHER} no se está vigilando" in said
    assert actions.create_batch("h", "kind")[0] == "failed"
    assert actions.pause_mark() is None and actions.target_for(1) is None
    assert actions.batches() == [] and actions.pending_holds() == []
    assert actions.held_details(1) is None


# --- what is added to a message opens no way for a secret (invariant 5) ---------------------------


def test_a_name_with_the_shape_of_a_key_never_goes_out_as_it_is(tmp_path: Path) -> None:
    key = "sk-ant-api03-aaaaaaaaaaaaaaaaaaa"
    with FakeBotApi(max_poll=1.0) as fake:
        api = BotApi(TOKEN, base=fake.base)
        book = ButtonBook()
        actions = GuardianActions(tmp_path / "c.sock", agent=key)
        desk = HoldDesk(api, OWNER, book, actions, agent=key)
        agents = {key: AgentSide(actions, desk), MAIN: AgentSide(actions, desk)}
        bot = TelegramBot(api, OWNER, book, actions, desk=desk, agents=agents, poll_timeout=1)
        notifier = TelegramNotifier(api, OWNER, book, actions, agents=agents)
        Labelled(notifier, key, threading.Lock()).send(Alert(AlertLevel.ERROR, "Algo", "c"))
        desk.send_notice(notice())
        bot.start()
        try:
            fake.push_message("/pausar")
            fake.push_message(f"/estado {key}")
            fake.push_message("/nada")
            fake.wait_call("sendMessage", lambda c: "Pausar todos" in str(c.params))
            fake.wait_call("sendMessage", lambda c: "Hay varios agentes:" in c.params["text"])
            fake.wait_call("sendMessage", lambda c: "no se está vigilando" in c.params["text"])
        finally:
            bot.close()
        assert key not in str([call.params for call in fake.calls])
        assert "[REDACTED]" in str([call.params for call in fake.calls])


# --- whose logs, whose thread ---------------------------------------------------------------------


def test_what_the_bot_does_for_a_neighbour_works_for_it(rig: Rig) -> None:
    """A problem met on the bot's threads reaches the neighbour's box, not the main one's."""
    seen: list[str | None] = []
    real = rig.other.pause_by_user

    def pause(*, requested_by: str) -> PauseOutcome:
        seen.append(scope.current())
        return real(requested_by=requested_by)

    rig.other.pause_by_user = pause  # type: ignore[method-assign]
    before = rig.say(f"/pausar {OTHER}")
    rig.message("congelado", after=before)
    assert seen == [OTHER]


def test_the_desk_of_a_neighbour_runs_on_a_thread_of_that_neighbour(tmp_path: Path) -> None:
    """Started by its hook, on the neighbour's thread: `the held request of risk 3 got no notice`
    is then logged in its box."""
    seen: list[str | None] = []

    class Api:
        def call(self, method: str, params: dict[str, Any], **_: Any) -> Any:
            seen.append(scope.current())
            return {"message_id": 1}

    scope.hand_down()
    actions = GuardianActions(tmp_path / "c.sock", agent=OTHER)
    book = ButtonBook()
    desk = HoldDesk(Api(), OWNER, book, actions, agent=OTHER)  # type: ignore[arg-type]
    side = TelegramNeighbour(OTHER, actions, desk, book)
    watch = side.watch(Guard(), None, Store())  # type: ignore[arg-type]

    def the_neighbours_thread() -> None:
        scope.enter(OTHER)
        watch.start()

    thread = threading.Thread(target=the_neighbours_thread)
    thread.start()
    thread.join()
    desk.held(notice())
    deadline = time.monotonic() + WAIT
    while not seen:
        assert time.monotonic() < deadline, "the desk never sent it"
        time.sleep(0.01)
    watch.close()
    assert seen[0] == OTHER


# --- as ``serve`` puts it together ----------------------------------------------------------------


def test_each_neighbour_gets_its_own_desk_and_the_machines_socket(home: Path) -> None:  # noqa: F811
    add_agent(home, OTHER)
    add_agent(home, "tercero", number=2)
    found = load_installation(main_config(home))
    main, others = found.main, found.others
    parts = telegram_parts(main, TelegramSettings(_secret(), OWNER, "http://127.0.0.1:9"), others)
    assert set(parts.neighbours) == {OTHER, "tercero"}
    desks = {id(parts.desk), *(id(side.desk) for side in parts.neighbours.values())}
    assert len(desks) == 3
    for slug, side in parts.neighbours.items():
        assert side.actions._socket == main.control_socket  # noqa: SLF001
        assert side.actions._about == {"agent": slug}  # noqa: SLF001
        assert side.book is parts.bot._book  # noqa: SLF001
    assert parts.actions._about == {}  # noqa: SLF001 - the main agent's order is as it always was
    assert set(parts.bot._agents) == {MAIN, OTHER, "tercero"}  # noqa: SLF001


def test_the_neighbours_watch_hands_the_gate_its_desk_and_binds_while_up(
    home: Path,  # noqa: F811
) -> None:
    add_agent(home, OTHER)
    found = load_installation(main_config(home))
    main, others = found.main, found.others
    parts = telegram_parts(main, TelegramSettings(_secret(), OWNER, "http://127.0.0.1:9"), others)
    side = parts.neighbours[OTHER]
    guard = Guard()
    options_seen: dict[str, Any] = {}
    during: list[str] = []

    class Box:
        def close(self) -> None: ...

    def build(config: ServiceConfig, **options: Any) -> Any:
        options_seen.update(options)
        return guard, "alerts", Box()

    def run(*_: Any, control: Any, stop: threading.Event, **__: Any) -> None:
        during.append(side.actions.pause())  # not up: it says so, and nobody is touched
        control.start()
        during.append(side.actions.pause())
        control.close()
        during.append(side.actions.pause())

    stop = threading.Event()
    roster = Roster(Desk(MAIN, Guard()), [(OTHER, None)])
    neighbours = _Neighbours(
        main, others, notifier_for=lambda slug: None, stop=stop, share=None,  # type: ignore[arg-type,return-value]
        told=None, build=build, run=run, roster=roster, telegram=parts.neighbours,  # type: ignore[arg-type]
        prepare=lambda config: None,
    )  # fmt: skip
    neighbours.start()
    neighbours.join(10)
    assert options_seen["hold_watch"] is side.desk
    assert "no se está vigilando" in during[0]
    assert "congelado" in during[1]
    assert "no se está vigilando" in during[2]
    assert guard.pauses == ["telegram"]


# --- one agent: as it always was ------------------------------------------------------------------


@pytest.fixture
def alone(home: Path) -> Iterator[tuple[FakeBotApi, TelegramParts, Guard, BlackBox]]:  # noqa: F811
    sockets = Path(tempfile.mkdtemp(prefix="vg"))
    with FakeBotApi(max_poll=1.0) as fake:
        found = load_installation(main_config(home))
        main, others = found.main, found.others
        assert others == ()
        parts = telegram_parts(main, TelegramSettings(_secret(), OWNER, fake.base), others)
        box = _box(sockets / "b")
        guard = Guard()
        parts.actions.bind(guard, box, Store(MAIN_SNAPSHOT))  # type: ignore[arg-type]
        parts.bot.start()
        try:
            yield fake, parts, guard, box
        finally:
            parts.bot.close()
            box.close()
    shutil.rmtree(sockets, ignore_errors=True)


def test_alone_nothing_is_labelled_and_no_button_names_an_agent(alone: Any) -> None:
    fake, parts, guard, box = alone
    assert parts.neighbours == {}
    seq = box.append("system", "x", "", details={}, risk=2).seq
    parts.notifier.send(Alert(AlertLevel.ERROR, "Algo", "cuerpo", seq))
    call = fake.wait_call("sendMessage")
    assert call.params["text"].startswith("backtide, ALERTA: Algo")
    for _, data in buttons(call):
        found = parts.bot._book.peek(data)  # noqa: SLF001
        assert found is not None and found.agent is None
    parts.desk.held(notice())
    held = fake.wait_call("sendMessage", lambda c: "RETENIDA" in c.params["text"])
    assert held.params["text"].startswith("⏸ backtide · RETENIDA")


@pytest.mark.parametrize("order", ["/pausar", "/pausar otro", "/pausar@MiBot ../x y z"])
def test_alone_pausar_acts_whatever_comes_after_as_it_always_did(alone: Any, order: str) -> None:
    fake, _, guard, _ = alone
    fake.push_message(order)
    said = fake.wait_call("sendMessage", lambda c: "congelado" in c.params["text"])
    assert said.params["text"] == "Agente congelado: no hace nada hasta /seguir."
    assert guard.pauses == ["telegram"]


def test_alone_the_other_orders_and_the_help_are_the_same(alone: Any) -> None:
    fake, _, guard, _ = alone
    fake.push_message("/seguir")
    said = fake.wait_call("sendMessage", lambda c: "donde estaba" in c.params["text"])
    assert said.params["text"] == "El agente sigue donde estaba."
    assert guard.resumes == ["telegram"]
    fake.push_message("/estado")
    said = fake.wait_call("sendMessage", lambda c: "en marcha" in c.params["text"])
    assert said.params["text"].startswith("Agente: en marcha.\n")
    fake.push_message("/retenidas")
    said = fake.wait_call("sendMessage", lambda c: "ninguna" in c.params["text"])
    assert said.params["text"] == "No hay ninguna petición retenida."
    fake.push_message("/nada")
    said = fake.wait_call("sendMessage", lambda c: "Órdenes:" in c.params["text"])
    assert said.params["text"] == HELP
