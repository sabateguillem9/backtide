"""The Telegram notice of a held request (T10-4, ``backtide.notify.hold_notice``, docs/32
sections 10 and 11), against the fake Bot API with fake actions: the notice struck and inert, ours
apart from the agent's; the buttons bound to their hold and message, used up when it ends and
answered "cerrada" after; "Ver"; the batches' two taps; the notice budget and its summary;
/retenidas and /lotes. The real gate behind the actions is in test_service_proxy_channel.py and,
with the real agent, in the VM (tests/attacks/test_hold_telegram_attacks.py)."""

import logging
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from telegram_fake import OWNER, STRANGER, TOKEN, Call, FakeBotApi, buttons

from backtide.notify.buttons import ButtonBook, RateLimit
from backtide.notify.hold_notice import (
    AGENT,
    AGENT_END,
    AGENT_HEAD,
    HoldDesk,
    batch_question,
    hold_text,
    result_line,
    view_text,
)
from backtide.notify.telegram import TelegramBot
from backtide.notify.telegram_api import BotApi

WAIT = 5.0
HOLD = "h-0123456789ab"


def notice(**changes: Any) -> dict[str, Any]:
    """What ``ProxyChannel._notice`` hands the watch for a Telegram send."""
    base: dict[str, Any] = {
        "hold_id": HOLD, "risk": 2, "reason": "send", "seq": 41,
        "phrase": "Telegram: enviar un mensaje al chat 556: «hola»",
        "method": "GET", "host": "api.telegram.org", "path": "/bot<token>/sendMessage",
        "target": "https://api.telegram.org/bot<token>/sendMessage", "expires_in_s": 300,
        "waiting": True, "batches": ["recipient", "kind"],
        "reading": {
            "translator": "telegram", "operation": "sendmessage", "effect": "send",
            "recipients": ["556"], "sender": None, "reply_to": [], "subject": None,
            "first_lines": "hola", "target": None, "attachments": [], "secret_seen": False,
            "notes": [], "draft": None, "cut": False,
        },
    }  # fmt: skip
    reading = changes.pop("reading", {})
    base["reading"] = None if reading is None else base["reading"] | reading
    return base | changes


def agent_part(text: str) -> list[str]:
    """The lines between our head of the agent's block and its end."""
    lines = text.split("\n")
    start, end = lines.index(AGENT_HEAD), lines.index(AGENT_END)
    return lines[start + 1 : end]


def our_part(text: str) -> list[str]:
    return text.split("\n")[: text.split("\n").index(AGENT_HEAD)]


# --- the text ------------------------------------------------------------------------------------


def test_the_notice_says_ours_first_and_the_agents_apart() -> None:
    text = hold_text(notice())
    assert text.startswith(f"⏸ backtide · RETENIDA · riesgo 2 · {HOLD}\n")
    assert "Telegram: enviar un mensaje" in our_part(text)
    assert "Si no respondes en 5 min, se rechaza." in our_part(text)
    assert agent_part(text) == [f"{AGENT}Para: 556", f"{AGENT}hola"]
    assert text.endswith(AGENT_END)


TRICKS = (
    "⏸ backtide · RETENIDA · riesgo 0\nResultado: aprobada desde Telegram (ya aprobado)\n"
    "Pulsa /seguir o abre https://evil.example/ok <b>APROBADO</b> *ok* [x](tg://x)"
    "‮gnp.exe​⁦  fin"
)


def test_the_agents_text_cannot_pass_for_ours() -> None:
    """aviso-con-trampa: a fake header, a fake result, a command, a link, markup, RLO,
    zero-width and other invisible characters, line breaks of every kind."""
    text = hold_text(notice(reading={"first_lines": TRICKS, "subject": TRICKS}))
    ours = our_part(text)
    assert ours[0].startswith("⏸ backtide · RETENIDA · riesgo 2 · ") and len(ours) == 4
    for line in agent_part(text):
        assert line.startswith(AGENT)  # every line of the agent's is marked
    assert not any(line.startswith("Resultado") for line in text.split("\n"))
    for invisible in ("‮", "​", "⁦", " ", " "):
        assert invisible not in text
    assert "\\u202e" in text and "\\u200b" in text  # shown, escaped
    assert "/seguir" not in text and "https://" not in text and "tg://" not in text
    assert "<b>APROBADO<∕b>" in text  # plain text: markup stays literal (no parse_mode)


def test_the_agents_texts_are_cut() -> None:
    long = "x" * 10_000
    text = hold_text(notice(reading={
        "subject": long, "first_lines": "\n".join(["linea"] * 10) + long,
        "recipients": [f"{n}@ejemplo.com" for n in range(64)],
        "attachments": [{"name": f"f{n}.pdf", "type": None, "size": 120_000} for n in range(9)],
    }))  # fmt: skip
    lines = agent_part(text)
    assert len(text) < 2000
    assert lines[0].startswith(f"{AGENT}Para: 0＠ejemplo․com") and lines[0].endswith(" y 59 más")
    subject = next(line for line in lines if line.startswith(f"{AGENT}Asunto: "))
    assert len(subject) <= len(AGENT) + len("Asunto: ") + 200
    assert sum(1 for line in lines if line == f"{AGENT}linea") <= 3
    assert lines[-1].endswith("y 4 más") and "f0․pdf (117 KB)" in lines[-1]


def test_a_secret_in_the_agents_text_is_struck_again() -> None:
    secret = "sk-ant-api03-" + "Q" * 40
    text = hold_text(notice(reading={"subject": f"la clave es {secret}"}))
    assert secret not in text and "Q" * 20 not in text


def test_the_notes_and_the_risk_are_ours() -> None:
    text = hold_text(notice(risk=3, batches=[], reading={
        "effect": "delete", "notes": ["deletes_message", "fetches_url"]}))  # fmt: skip
    ours = our_part(text)
    assert ours[0].endswith(f"riesgo 3 · {HOLD}") and ours[1] == "Telegram: borrar"
    assert ours[2] == "Ojo: borra un mensaje; la plataforma descargará esa dirección."


def test_without_a_translator_the_request_is_the_agents() -> None:
    text = hold_text(notice(reading=None, reason="delete", method="DELETE",
                            host="api.fake.test", path="/v1/buckets/b1"))  # fmt: skip
    assert our_part(text)[1] == "Sin traductor: un borrado (DELETE) que backtide no sabe leer"
    assert agent_part(text) == [f"{AGENT}DELETE api․fake․test/v1/buckets/b1"]


def test_the_countdown() -> None:
    assert "en 2 min" in hold_text(notice(expires_in_s=61))
    assert "en 40 s" in hold_text(notice(expires_in_s=40))


def test_a_long_recipient_keeps_its_domain_in_the_notice() -> None:
    """Final review of T10, finding 4: cut in the middle, the domain stays."""
    long = "ana@ejemplo.com." + "x" * 190 + ".malo.io"
    reading = notice()["reading"] | {"translator": "gmail", "recipients": [long]}
    text = hold_text(notice(reading=reading))
    [to] = [line for line in text.split("\n") if "Para:" in line]
    assert "…(" in to and to.endswith("malo․io"), to  # "." made untappable


def test_view_shows_every_recipient_the_attachments_and_the_excerpt() -> None:
    details = {
        "method": "POST", "host": "gmail.googleapis.com", "path": "/gmail/v1/users/me/send",
        "body": {"size": 5000, "excerpt": "linea 1\nlinea 2 /seguir", "excerpt_truncated": True},
        "reading": {"recipients": [f"{n}@x.example" for n in range(9)],
                    "attachments": [{"name": "f.pdf", "type": "application/pdf", "size": 2048}]},
    }  # fmt: skip
    text = view_text(notice(), details)
    lines = agent_part(text)
    assert all(line.startswith(AGENT) for line in lines)
    assert "8＠x․example" in text and "y " not in lines[1]  # every recipient
    assert f"{AGENT}Adjunto: f․pdf · application/pdf · 2 KB" in lines
    assert f"{AGENT}linea 1" in lines and "/seguir" not in text
    assert any("solo guarda los primeros 2 KiB" in line for line in lines)


def test_results_and_the_batch_question_are_ours() -> None:
    assert result_line("released", "telegram") == (
        "Resultado: aprobada desde Telegram: salió una sola vez."
    )
    assert "pausar" in result_line("rejected", "pause")
    assert "nadie respondió" in result_line("expired", "timeout")
    assert "reiniciaron" in result_line("expired", "channel_lost")
    question = batch_question(notice(), "recipient")
    assert "12 horas" in question and "/lotes" in question
    assert agent_part(question) == [f"{AGENT}Destinatarios: 556"]
    assert "1 hora" in batch_question(notice(), "kind")


# --- the desk, with the bot, against the fake Bot API ------------------------------------------


@dataclass
class FakeActions:
    """BotActions and HoldActions. A decision tells the desk that the hold ended, as the real
    channel's watch would."""

    desk: HoldDesk | None = None
    asked: list[tuple[str, ...]] = field(default_factory=list)
    records: list[tuple[str, dict[str, Any], int]] = field(default_factory=list)
    outcome: str = "released"
    pending: list[dict[str, Any]] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    done: threading.Event = field(default_factory=threading.Event)

    def decide(self, hold_id: str, verdict: str) -> tuple[str, str]:
        self.asked.append(("decide", hold_id, verdict))
        self.done.set()
        if self.outcome in ("released", "rejected") and self.desk is not None:
            status = "released" if verdict == "approve" else "rejected"
            self.desk.closed(hold_id, status, "telegram")
            return status, f"hecho: {status}"
        return self.outcome, f"no: {self.outcome}"

    def create_batch(self, hold_id: str, kind: str) -> tuple[str, str]:
        self.asked.append(("batch", hold_id, kind))
        self.done.set()
        return "created", "Lote creado."

    def end_batch(self, rule_id: str) -> str:
        self.asked.append(("end", rule_id))
        self.done.set()
        return "Lote revocado."

    def batches(self) -> list[dict[str, Any]]:
        return list(self.rules)

    def pending_holds(self) -> list[dict[str, Any]]:
        return list(self.pending)

    def held_details(self, seq: int) -> dict[str, Any] | None:
        self.asked.append(("details", str(seq)))
        return {"body": {"excerpt": "el cuerpo entero"}}

    # BotActions (T09), unused here
    def pause(self) -> str:
        self.asked.append(("pause",))
        return "Agente congelado."

    def pause_mark(self) -> int | None:
        return 0

    def resume(self, pause_mark: int | None) -> str:
        return "sigue"

    def status(self) -> str:
        return "Agente: en marcha."

    def rewind(self, snapshot_id: str) -> str:
        return "no"

    def notice(self, snapshot_id: str) -> str | None:
        return None

    def target_for(self, event_seq: int) -> str | None:
        return None

    def record(self, action: str, details: dict[str, Any], risk: int) -> None:
        self.records.append((action, details, risk))

    def wait(self) -> None:
        assert self.done.wait(WAIT), self.asked
        self.done.clear()


@dataclass
class Rig:
    fake: FakeBotApi
    actions: FakeActions
    book: ButtonBook
    desk: HoldDesk
    bot: TelegramBot

    def notice(self, **changes: Any) -> Call:
        before = time.monotonic()
        self.desk.held(notice(**changes))
        found = self.fake.wait_call("sendMessage", after=before)
        self.bound(found)
        return found

    def bound(self, call: Call) -> None:
        """Wait until every button of ``call`` is bound to its message: the desk binds them
        once the Bot API's answer reaches it, and a press before that is "wrong message"."""
        tokens = [data for _, data in buttons(call)]
        deadline = time.monotonic() + WAIT
        while not all(
            (found := self.book.peek(token)) is not None and found.message_id == call.message_id
            for token in tokens
        ):
            assert time.monotonic() < deadline, "the buttons were never bound"
            time.sleep(0.01)

    def press(self, call: Call, label: str, **who: Any) -> None:
        data = dict(buttons(call))[label]
        self.fake.push_callback(data, call.message_id, **who)

    def edit_of(self, call: Call) -> Call:
        return self.fake.wait_call(
            "editMessageText", lambda c: c.params.get("message_id") == call.message_id
        )

    def press_answered(self, call: Call, label: str, **who: Any) -> str:
        """Press, and the text of the answer to THIS press. The bot answers each press of the
        owner exactly once, but through its outbox (a thread of its own): on a slow machine an
        earlier answer can arrive late, so every earlier press must have been answered first
        (this waits for that too) and the answer is told by its position, not its time."""
        answers = self.fake.sent("answerCallbackQuery")
        seen = len(answers)
        self.press(call, label, **who)
        deadline = time.monotonic() + WAIT
        while len(answers := self.fake.sent("answerCallbackQuery")) <= seen:
            assert time.monotonic() < deadline, "the press was never answered"
            time.sleep(0.01)
        return str(answers[seen].params.get("text"))

    def answered(self, count: int) -> None:
        """Wait until ``count`` presses have been answered."""
        deadline = time.monotonic() + WAIT
        while len(self.fake.sent("answerCallbackQuery")) < count:
            assert time.monotonic() < deadline, "a press was never answered"
            time.sleep(0.01)

    def settle(self) -> None:
        last = self.fake.next_update_id
        deadline = time.monotonic() + WAIT
        while self.fake.updates and self.fake.confirmed() < last:
            assert time.monotonic() < deadline, "the bot did not take the updates"
            time.sleep(0.01)
        time.sleep(0.15)


@pytest.fixture
def rig() -> Iterator[Rig]:
    with FakeBotApi(max_poll=1.0) as fake:
        api = BotApi(TOKEN, base=fake.base)
        actions = FakeActions()
        book = ButtonBook()
        desk = HoldDesk(api, OWNER, book, actions, summary_every=0.0)
        actions.desk = desk
        bot = TelegramBot(api, OWNER, book, actions, poll_timeout=1,
                          limit=RateLimit(100, 0.01), desk=desk)  # fmt: skip
        bot.start()
        made = Rig(fake, actions, book, desk, bot)
        try:
            deadline = time.monotonic() + WAIT
            while fake.polls() < 1:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            yield made
        finally:
            bot.close()


def test_the_notice_goes_as_plain_text_with_our_buttons(rig: Rig) -> None:
    call = rig.notice()
    assert "parse_mode" not in call.params
    assert call.params["link_preview_options"] == {"is_disabled": True}
    assert call.params["chat_id"] == OWNER
    assert [label for label, _ in buttons(call)] == [
        "Aprobar", "Rechazar", "Ver", "Todo a este destinatario (sesión)",
        "Envíos de Telegram, 1 h",
    ]  # fmt: skip
    assert all(len(data) >= 20 for _, data in buttons(call))  # opaque tokens, not ids


def test_no_batch_buttons_when_the_hold_may_not_make_one(rig: Rig) -> None:
    call = rig.notice(risk=3, batches=[], reading={"effect": "delete"})
    assert [label for label, _ in buttons(call)] == ["Aprobar", "Rechazar", "Ver"]


def test_approve_goes_through_the_actions_once_and_the_message_says_how_it_ended(
    rig: Rig,
) -> None:
    call = rig.notice()
    assert rig.press_answered(call, "Aprobar") == "Aprobando…"
    rig.actions.wait()
    assert rig.actions.asked == [("decide", HOLD, "approve")]
    edit = rig.edit_of(call)
    assert edit.params["text"].startswith(call.params["text"])
    assert edit.params["text"].endswith("Resultado: aprobada desde Telegram: salió una sola vez.")
    assert edit.params["reply_markup"] == {"inline_keyboard": []}
    # Pressed again, replayed, or "Rechazar" after it: nothing is asked; it says how it ended.
    assert "ya está cerrada: aprobada" in rig.press_answered(call, "Aprobar")
    assert "ya está cerrada: aprobada" in rig.press_answered(call, "Rechazar")
    rig.settle()
    assert rig.actions.asked == [("decide", HOLD, "approve")]
    assert [r[1]["reason"] for r in rig.actions.records] == ["used_button", "used_button"]


def test_reject(rig: Rig) -> None:
    call = rig.notice()
    rig.press(call, "Rechazar")
    rig.actions.wait()
    assert rig.actions.asked == [("decide", HOLD, "reject")]
    assert (
        rig.edit_of(call).params["text"].endswith("Resultado: rechazada desde Telegram. No salió.")
    )


def test_a_press_from_another_chat_or_person_does_nothing_and_gets_no_answer(rig: Rig) -> None:
    call = rig.notice()
    rig.press(call, "Aprobar", from_id=STRANGER)  # another person, in their chat
    rig.press(call, "Aprobar", from_id=STRANGER, chat_id=OWNER)  # someone else in the chat
    rig.press(call, "Aprobar", from_id=OWNER, chat_id=STRANGER)  # the owner, in another chat
    rig.settle()
    assert rig.actions.asked == [] and rig.fake.sent("answerCallbackQuery") == []
    assert [r[1]["reason"] for r in rig.actions.records] == ["not_owner"] * 3


def test_a_button_on_another_message_or_a_guessed_one_does_nothing(rig: Rig) -> None:
    first = rig.notice()
    second = rig.notice(hold_id="h-ba9876543210")
    data = dict(buttons(first))["Aprobar"]
    rig.fake.push_callback(data, second.message_id)  # moved onto the other hold's message
    rig.fake.push_callback("A" * 24, first.message_id)  # guessed
    rig.fake.push_callback(HOLD, first.message_id)  # the hold id itself is no button
    rig.settle()
    assert rig.actions.asked == []
    reasons = [r[1]["reason"] for r in rig.actions.records]
    assert reasons == ["wrong_message", "unknown_button", "unknown_button"]


def test_a_decision_elsewhere_edits_the_notice_and_uses_its_buttons_up(rig: Rig) -> None:
    call = rig.notice()
    rig.desk.closed(HOLD, "rejected", "pause")  # /pausar, the terminal or the web
    edit = rig.edit_of(call)
    assert edit.params["text"].endswith("Resultado: rechazada al pausar el agente. No salió.")
    assert "ya está cerrada: rechazada" in rig.press_answered(call, "Aprobar")
    rig.settle()
    assert rig.actions.asked == []


def test_an_expired_hold_says_so(rig: Rig) -> None:
    call = rig.notice()
    rig.desk.closed(HOLD, "expired", "timeout")
    assert "nadie respondió en 5 minutos" in rig.edit_of(call).params["text"]
    assert "caducada" in rig.press_answered(call, "Rechazar")


def test_buttons_expire_with_the_hold(rig: Rig) -> None:
    call = rig.notice(expires_in_s=1)
    time.sleep(1.2)
    assert "caducado" in rig.press_answered(call, "Aprobar")
    rig.settle()
    assert rig.actions.asked == []


def test_a_decision_that_did_not_close_the_hold_leaves_its_buttons(rig: Rig) -> None:
    """The agent is paused: nothing is approved and the hold stays, so its buttons do too."""
    rig.actions.outcome = "paused"
    call = rig.notice()
    rig.press(call, "Aprobar")
    rig.actions.wait()
    rig.fake.wait_call("sendMessage", lambda c: c.params.get("text") == "no: paused")
    rig.actions.outcome = "released"
    rig.press(call, "Aprobar")
    rig.actions.wait()
    assert rig.actions.asked == [("decide", HOLD, "approve")] * 2


def test_view_sends_what_the_black_box_keeps_and_is_not_used_up(rig: Rig) -> None:
    call = rig.notice()
    for _ in range(2):
        before = time.monotonic()
        rig.press(call, "Ver")
        sent = rig.fake.wait_call("sendMessage", after=before)
        assert sent.params["text"].startswith(f"backtide · detalle de la retención {HOLD}")
        assert f"{AGENT}el cuerpo entero" in sent.params["text"]
        assert "reply_markup" not in sent.params
    assert rig.actions.asked == [("details", "41"), ("details", "41")]


def test_a_batch_takes_two_taps(rig: Rig) -> None:
    call = rig.notice()
    before = time.monotonic()
    rig.press(call, "Todo a este destinatario (sesión)")
    question = rig.fake.wait_call("sendMessage", after=before)
    rig.bound(question)
    assert "¿Crear un lote?" in question.params["text"] and rig.actions.asked == []
    assert [label for label, _ in buttons(question)] == ["Sí, crear el lote", "Cancelar"]
    rig.press(question, "Sí, crear el lote")
    rig.actions.wait()
    assert rig.actions.asked == [("batch", HOLD, "recipient")]
    rig.press(question, "Sí, crear el lote")  # once
    rig.fake.wait_call("answerCallbackQuery", lambda c: "ya se usó" in c.params.get("text", ""))


def test_a_batch_cancelled_is_not_made(rig: Rig) -> None:
    call = rig.notice()
    before = time.monotonic()
    rig.press(call, "Envíos de Telegram, 1 h")
    question = rig.fake.wait_call("sendMessage", after=before)
    rig.bound(question)
    rig.press(question, "Cancelar")
    rig.fake.wait_call("sendMessage", lambda c: "No se ha creado" in c.params.get("text", ""))
    rig.press(question, "Sí, crear el lote")
    rig.fake.wait_call("answerCallbackQuery", lambda c: "ya se usó" in c.params.get("text", ""))
    rig.settle()
    assert rig.actions.asked == []


def test_at_most_6_notices_a_minute_and_one_summary(rig: Rig) -> None:
    for n in range(10):
        rig.desk.held(notice(hold_id=f"h-{n:012x}"))
    summary = rig.fake.wait_call("sendMessage", lambda c: "retenidas más" in c.params["text"])
    assert summary.params["text"].startswith("backtide · 1 retenidas más")
    rig.fake.wait_call("editMessageText", lambda c: "4 retenidas más" in c.params["text"])
    rig.settle()
    notices = [c for c in rig.fake.sent() if c.params["text"].startswith("⏸")]
    assert len(notices) == 6
    assert [label for label, _ in buttons(summary)] == ["Pausar"]
    # More: the same summary is edited, not a new message.
    for n in range(10, 13):
        rig.desk.held(notice(hold_id=f"h-{n:012x}"))
    edit = rig.fake.wait_call("editMessageText", lambda c: "7 retenidas" in c.params["text"])
    assert edit.params["message_id"] == summary.message_id
    assert len([c for c in rig.fake.sent() if "retenidas más" in c.params["text"]]) == 1
    rig.press(summary, "Pausar")
    rig.settle()
    assert ("pause",) in rig.actions.asked


def test_retenidas_sends_the_open_holds_again_with_their_buttons(rig: Rig) -> None:
    rig.actions.pending = [notice(hold_id=f"h-{n:012x}", expires_in_s=200) for n in range(12)]
    rig.fake.push_message("/retenidas")
    head = rig.fake.wait_call("sendMessage", lambda c: "Hay 12 retenidas" in c.params["text"])
    assert "primero las de más riesgo" in head.params["text"]
    deadline = time.monotonic() + WAIT
    while len([c for c in rig.fake.sent() if c.params["text"].startswith("⏸")]) < 10:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    rig.settle()
    notices = [c for c in rig.fake.sent() if c.params["text"].startswith("⏸")]
    assert len(notices) == 10 and "en 4 min" in notices[0].params["text"]
    rig.bound(notices[3])
    rig.press(notices[3], "Aprobar")
    rig.actions.wait()
    assert rig.actions.asked == [("decide", "h-000000000003", "approve")]


def test_retenidas_with_none_open(rig: Rig) -> None:
    rig.fake.push_message("/retenidas")
    rig.fake.wait_call("sendMessage", lambda c: "No hay ninguna" in c.params["text"])


def test_lotes_lists_the_batches_and_revokes_one(rig: Rig) -> None:
    rig.actions.rules = [
        {"rule_id": "b-01234567", "scope": "recipient", "translator": "telegram",
         "effect": "send", "recipients": ["556"], "left_s": 3600, "uses": 2},
        {"rule_id": "b-89abcdef", "scope": "kind", "translator": None, "method": "POST",
         "host": "api.fake.test", "route": "/v1/*/notes", "left_s": 120, "uses": 0},
    ]  # fmt: skip
    rig.fake.push_message("/lotes")
    listing = rig.fake.wait_call("sendMessage", lambda c: "Lotes activos" in c.params["text"])
    rig.bound(listing)
    text = listing.params["text"]
    assert (
        "1. Telegram, todo a unos destinatarios, sesión: quedan 1 h 0 min; usado 2 veces." in text
    )
    assert f"{AGENT}1. 556" in text and f"{AGENT}2. api.fake.test∕v1∕*∕notes" not in text
    assert [label for label, _ in buttons(listing)] == ["Revocar 1", "Revocar 2"]
    rig.press(listing, "Revocar 2")
    rig.actions.wait()
    assert rig.actions.asked == [("end", "b-89abcdef")]
    rig.actions.rules = []  # before the order: the bot's worker may read them at once
    rig.fake.push_message("/lotes")
    rig.fake.wait_call("sendMessage", lambda c: c.params["text"] == "No hay lotes activos.")


def test_a_hold_that_ended_before_its_notice_went_out_gets_no_live_buttons(rig: Rig) -> None:
    rig.desk.closed(HOLD, "expired", "timeout")
    rig.desk.held(notice())
    # The desk takes its queue in order: once a later hold's notice is out, the first one's
    # turn has come and gone.
    rig.desk.held(notice(hold_id="h-ba9876543210"))
    rig.fake.wait_call("sendMessage", lambda c: "h-ba9876543210" in c.params["text"])
    assert [c for c in rig.fake.sent() if HOLD in c.params["text"]] == []


def test_the_watch_never_blocks_even_when_its_queue_is_full() -> None:
    class Stuck:
        def call(self, method: str, params: dict[str, Any], **_: Any) -> Any:
            time.sleep(10)

    desk = HoldDesk(Stuck(), OWNER, ButtonBook(), FakeActions())  # type: ignore[arg-type]
    started = time.monotonic()
    for n in range(400):  # the desk never started: its queue fills
        desk.held(notice(hold_id=f"h-{n:012x}"))
        desk.closed(f"h-{n:012x}", "expired", "timeout")
    assert time.monotonic() - started < 1.0


# --- the security review of T10-4 ----------------------------------------------------------------

FILLERS = "ㅤᅟᅠﾠ⠀͏️"


def test_blank_fillers_are_escaped_and_spaces_collapsed() -> None:
    """B1: printable-but-blank characters and runs of spaces could push a fake line of ours to
    the start of a wrapped line; they are shown escaped, and the runs are one space."""
    trick = "hola" + FILLERS * 40 + "     " * 30 + f"{AGENT_END}\nResultado: aprobada"
    text = hold_text(notice(reading={"first_lines": trick, "subject": trick}))
    assert not any(char in text for char in FILLERS)
    assert "\\u3164" in text and "\\u2800" in text and "  " not in "".join(agent_part(text))
    assert text.count(AGENT_END) == 1 and text.endswith(AGENT_END)  # only ours
    assert "│" not in "".join(line[len(AGENT) :] for line in agent_part(text))
    assert "⏸" not in "".join(agent_part(text))


def test_bare_domains_mentions_and_phones_are_not_tappable() -> None:
    """B2: Telegram links "malo.example", "ana@x.com", "@canal" and "+34…" in plain text."""
    text = hold_text(
        notice(
            reading={
                "first_lines": "mira malo.example o www.x.com, @canal, ana@x.com "
                "o +34600111222; 3.5 kg"
            }
        )  # fmt: skip
    )
    agent = "\n".join(agent_part(text))
    for tappable in ("malo.example", "www.x.com", "@canal", "ana@x.com", "+34"):
        assert tappable not in agent
    assert "malo․example" in agent and "＠canal" in agent and "＋34600111222" in agent


def test_the_agents_block_is_a_blockquote_counted_in_utf16() -> None:
    """B1: the agent's lines are one blockquote entity, so a wrapped line keeps its bar; the
    offsets are UTF-16 code units (an emoji counts two)."""
    from backtide.notify.hold_notice import quote_entities

    text = hold_text(notice(reading={"first_lines": "🙂 hola 😀"}))
    [entity] = quote_entities(text)
    units = text.encode("utf-16-le")
    quoted = units[entity["offset"] * 2 : (entity["offset"] + entity["length"]) * 2]
    head = AGENT_HEAD + "\n"
    expected = text[text.index(head) + len(head) :]
    assert entity["type"] == "blockquote" and quoted.decode("utf-16-le") == expected
    assert quote_entities("backtide · 3 retenidas más") == []


def test_reply_to_is_shown_and_flagged() -> None:
    """M2: answers that go elsewhere are our note in the notice and in the batch question."""
    reading = {"reply_to": ["x@malo.example"], "recipients": ["ana@ejemplo.com"]}
    text = hold_text(notice(reading=reading))
    assert any("las respuestas irían" in line for line in our_part(text))
    assert f"{AGENT}Responder a: x＠malo․example" in agent_part(text)
    question = batch_question(notice(reading=reading), "kind")
    assert f"{AGENT}Responder a: x＠malo․example" in agent_part(question)
    same = hold_text(notice(reading={"reply_to": ["556"]}))
    assert not any("las respuestas" in line for line in our_part(same))


class Recorder:
    """A Bot API that answers at once and keeps every call."""

    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail = fail

    def call(self, method: str, params: dict[str, Any], **_: Any) -> Any:
        from backtide.notify.telegram_api import TelegramError

        self.calls.append((method, params))
        if self.fail:
            raise TelegramError("down")
        return {"message_id": len(self.calls)}

    def texts(self) -> list[str]:
        return [params["text"] for method, params in self.calls if method == "sendMessage"]


class Tick:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def sync_desk(api: Recorder, clock: Tick) -> HoldDesk:
    """A desk whose queue the test drains by hand (no thread)."""
    return HoldDesk(api, OWNER, ButtonBook(clock=clock), FakeActions(), clock=clock,  # type: ignore[arg-type]
                    summary_every=0.0)  # fmt: skip


def drain(desk: HoldDesk) -> None:
    while not desk._queue.empty():  # noqa: SLF001
        item = desk._queue.get_nowait()  # noqa: SLF001
        if item and item[0] == "held":
            desk._on_held(item[1])  # noqa: SLF001
        elif item and item[0] == "closed":
            desk._on_closed(*item[1:])  # noqa: SLF001
        desk._tell_summary()  # noqa: SLF001


def test_the_countdown_and_the_buttons_count_from_when_the_notice_goes_out() -> None:
    """B5: a notice queued at 300 s and sent 200 s later says 2 min, and its buttons live
    100 s, not 300."""
    api, clock = Recorder(), Tick()
    desk = sync_desk(api, clock)
    desk.held(notice(expires_in_s=300))
    clock.now += 200
    drain(desk)
    [text] = api.texts()
    assert "Si no respondes en 2 min, se rechaza." in text
    approve = api.calls[0][1]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
    button = desk._book.peek(approve)  # noqa: SLF001
    assert button is not None and button.expires == clock.now + 100
    desk.held(notice(hold_id="h-111111111111", expires_in_s=30))
    clock.now += 31
    drain(desk)
    assert len(api.texts()) == 1  # expired before it went out: nothing to press


def test_risk_3_has_a_budget_of_its_own_and_the_summary_counts_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """M3 and M4: ten low-risk holds never hide one of risk 3; past its own budget, the
    summary says how many of risk 3 it has, and the log (the bridge) says it went unannounced."""
    api, clock = Recorder(), Tick()
    desk = sync_desk(api, clock)
    for n in range(10):
        desk.held(notice(hold_id=f"h-{n:012x}"))
    desk.held(notice(hold_id="h-333333333333", risk=3, batches=[]))
    drain(desk)
    notices = [text for text in api.texts() if text.startswith("⏸")]
    assert len(notices) == 7 and "riesgo 3 · h-333333333333" in notices[-1]
    with caplog.at_level(logging.WARNING, logger="backtide.holds"):
        for n in range(7):
            desk.held(notice(hold_id=f"h-3{n:011x}", risk=3, batches=[]))
        drain(desk)
    summaries = [params["text"] for _, params in api.calls if "retenidas más" in params["text"]]
    assert summaries[-1].startswith("backtide · 6 retenidas más sin aviso propio, 2 de riesgo 3")
    assert [r.name for r in caplog.records].count("backtide.holds") == 2
    assert "h-3" in caplog.records[-1].getMessage()


def test_a_risk_3_notice_telegram_did_not_take_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """M4: Telegram down, or the desk's queue full: the bridge hears of it."""
    api, clock = Recorder(fail=True), Tick()
    desk = sync_desk(api, clock)
    with caplog.at_level(logging.WARNING, logger="backtide.holds"):
        desk.held(notice(risk=3, batches=[]))
        drain(desk)
        desk.held(notice(hold_id="h-222222222222"))  # risk 2: no warning of its own
        drain(desk)
    assert [r.getMessage() for r in caplog.records if r.name == "backtide.holds"] == [
        f"a held request of risk 3 ({HOLD}) got no Telegram notice of its own "
        "(telegram_failed): see it with /retenidas or `backtide retenidas`"
    ]
    full = sync_desk(Recorder(), clock)
    for n in range(300):
        full.held(notice(hold_id=f"h-{n:012x}"))
    with caplog.at_level(logging.WARNING, logger="backtide.holds"):
        full.held(notice(hold_id="h-999999999999", risk=3, batches=[]))
    assert "queue_full" in caplog.records[-1].getMessage()


def test_retenidas_sends_the_riskiest_first(rig: Rig) -> None:
    """M3: a risk 3 behind eleven low-risk holds is among the ten /retenidas sends, first."""
    rig.actions.pending = [notice(hold_id=f"h-{n:012x}", expires_in_s=200) for n in range(11)]
    rig.actions.pending.append(
        notice(hold_id="h-333333333333", risk=3, batches=[], expires_in_s=200)
    )
    rig.fake.push_message("/retenidas")
    first = rig.fake.wait_call("sendMessage", lambda c: c.params["text"].startswith("⏸"))
    assert "riesgo 3 · h-333333333333" in first.params["text"]


def test_a_notice_carries_its_blockquote_and_its_edit_too(rig: Rig) -> None:
    call = rig.notice()
    [entity] = call.params["entities"]
    assert entity["type"] == "blockquote" and "parse_mode" not in call.params
    rig.press(call, "Rechazar")
    edit = rig.edit_of(call)
    assert edit.params["entities"] == call.params["entities"]


def test_a_confirmation_refused_by_the_rate_limit_is_not_used_up(rig: Rig) -> None:
    """Review of T10-4: "Sí, crear el lote" pressed past the rate limit does nothing, and is
    still there to press once the limit allows it."""
    call = rig.notice()
    before = time.monotonic()
    rig.press_answered(call, "Todo a este destinatario (sesión)")
    question = rig.fake.wait_call("sendMessage", after=before)
    rig.bound(question)
    rig.bot._limit = RateLimit(1, 3600)  # noqa: SLF001
    rig.bot._limit.allow()  # noqa: SLF001 - used up
    assert "Demasiadas órdenes" in rig.press_answered(question, "Sí, crear el lote")
    rig.settle()
    assert rig.actions.asked == []
    rig.bot._limit = RateLimit(100, 0.01)  # noqa: SLF001
    rig.press(question, "Sí, crear el lote")
    rig.actions.wait()
    assert rig.actions.asked == [("batch", HOLD, "recipient")]


def test_printable_escapes_blank_fillers_and_inert_keeps_t09_alerts_as_they_were() -> None:
    """B1 in ``printable`` (every message); B2 only in the agent's text of a notice."""
    from backtide.notify.text import agent_text, inert, printable

    assert printable("aㅤb⠀c\td\x1b") == "a\\u3164b\\u2800c\\td\\x1b"
    assert printable("\U000e0041") == "\\U000e0041"  # a tag character
    assert inert("ver informe.pdf en a@b.c") == "ver informe.pdf en a@b.c"
    assert agent_text("a  b   c │└⏸", "│└⏸") == "a b c \\u2502\\u2514\\u23f8"
