"""The Telegram notice of a held request (T10-4, ``backtide.notify.hold_notice``, docs/32
sections 10 and 11), against the fake Bot API with fake actions: the notice struck and inert, ours
apart from the agent's; the buttons bound to their hold and message, used up when it ends and
answered "cerrada" after; "Ver"; the batches' two taps; the notice budget and its summary;
/retenidas and /lotes. The real gate behind the actions is in test_service_proxy_channel.py and,
with the real agent, in the VM (tests/attacks/test_hold_telegram_attacks.py)."""

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
    assert lines[0].startswith(f"{AGENT}Para: 0@ejemplo.com") and lines[0].endswith(" y 59 más")
    subject = next(line for line in lines if line.startswith(f"{AGENT}Asunto: "))
    assert len(subject) <= len(AGENT) + len("Asunto: ") + 200
    assert sum(1 for line in lines if line == f"{AGENT}linea") <= 3
    assert lines[-1].endswith("y 4 más") and "f0.pdf (117 KB)" in lines[-1]


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
    assert agent_part(text) == [f"{AGENT}DELETE api.fake.test/v1/buckets/b1"]


def test_the_countdown() -> None:
    assert "en 2 min" in hold_text(notice(expires_in_s=61))
    assert "en 40 s" in hold_text(notice(expires_in_s=40))


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
    assert "8@x.example" in text and "y " not in lines[1]  # every recipient
    assert f"{AGENT}Adjunto: f.pdf · application/pdf · 2 KB" in lines
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
        time.sleep(0.1)  # the desk binds the buttons once the answer reaches it
        return found

    def press(self, call: Call, label: str, **who: Any) -> None:
        data = dict(buttons(call))[label]
        self.fake.push_callback(data, call.message_id, **who)

    def edit_of(self, call: Call) -> Call:
        return self.fake.wait_call(
            "editMessageText", lambda c: c.params.get("message_id") == call.message_id
        )

    def answer(self, after: float) -> str:
        found = self.fake.wait_call("answerCallbackQuery", after=after)
        return str(found.params.get("text"))

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
    rig.press(call, "Aprobar")
    rig.actions.wait()
    assert rig.actions.asked == [("decide", HOLD, "approve")]
    edit = rig.edit_of(call)
    assert edit.params["text"].startswith(call.params["text"])
    assert edit.params["text"].endswith("Resultado: aprobada desde Telegram: salió una sola vez.")
    assert edit.params["reply_markup"] == {"inline_keyboard": []}
    # Pressed again, replayed, or "Rechazar" after it: nothing is asked; it says how it ended.
    before = time.monotonic()
    rig.press(call, "Aprobar")
    assert "ya está cerrada: aprobada" in rig.answer(before)
    before = time.monotonic()
    rig.press(call, "Rechazar")
    assert "ya está cerrada: aprobada" in rig.answer(before)
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
    before = time.monotonic()
    rig.press(call, "Aprobar")
    assert "ya está cerrada: rechazada" in rig.answer(before)
    rig.settle()
    assert rig.actions.asked == []


def test_an_expired_hold_says_so(rig: Rig) -> None:
    call = rig.notice()
    rig.desk.closed(HOLD, "expired", "timeout")
    assert "nadie respondió en 5 minutos" in rig.edit_of(call).params["text"]
    before = time.monotonic()
    rig.press(call, "Rechazar")
    assert "caducada" in rig.answer(before)


def test_buttons_expire_with_the_hold(rig: Rig) -> None:
    call = rig.notice(expires_in_s=1)
    time.sleep(1.2)
    before = time.monotonic()
    rig.press(call, "Aprobar")
    assert "caducado" in rig.answer(before)
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
    time.sleep(0.1)  # bound once the answer reaches the desk
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
    time.sleep(0.1)  # bound once the answer reaches the desk
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
    assert "las 10 más antiguas" in head.params["text"]
    deadline = time.monotonic() + WAIT
    while len([c for c in rig.fake.sent() if c.params["text"].startswith("⏸")]) < 10:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    rig.settle()
    notices = [c for c in rig.fake.sent() if c.params["text"].startswith("⏸")]
    assert len(notices) == 10 and "en 4 min" in notices[0].params["text"]
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
    time.sleep(0.1)
    text = listing.params["text"]
    assert (
        "1. Telegram, todo a unos destinatarios, sesión: quedan 1 h 0 min; usado 2 veces." in text
    )
    assert f"{AGENT}1. 556" in text and f"{AGENT}2. api.fake.test∕v1∕*∕notes" not in text
    assert [label for label, _ in buttons(listing)] == ["Revocar 1", "Revocar 2"]
    rig.press(listing, "Revocar 2")
    rig.actions.wait()
    assert rig.actions.asked == [("end", "b-89abcdef")]
    rig.fake.push_message("/lotes")
    rig.actions.rules = []
    rig.fake.wait_call("sendMessage", lambda c: c.params["text"] == "No hay lotes activos.")


def test_a_hold_that_ended_before_its_notice_went_out_gets_no_live_buttons(rig: Rig) -> None:
    rig.desk.closed(HOLD, "expired", "timeout")
    rig.desk.held(notice())
    time.sleep(0.3)
    assert [c for c in rig.fake.sent() if c.params["text"].startswith("⏸")] == []


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
