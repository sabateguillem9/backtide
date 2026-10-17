"""The Telegram bot (T09) against the fake Bot API, with fake actions: who may command, the
buttons, the rate limit, late commands, and that the token never shows up.

The real Guardian behind the actions is tested in test_service_user_pause.py and
test_service_bot.py; the whole thing with the real agent, in the VM (tests/attacks)."""

import logging
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from telegram_fake import OWNER, STRANGER, TOKEN, Call, FakeBotApi, buttons

from vigia.notify import Alert, AlertLevel, AlertQueue
from vigia.notify.buttons import ButtonBook, RateLimit
from vigia.notify.telegram import (
    IGNORED_PER_MINUTE,
    TelegramBot,
    TelegramNotifier,
    alert_text,
    printable,
)
from vigia.notify.telegram_api import BotApi

SNAPSHOT = "20261016T120000.000000Z-periodic"
WAIT = 5.0


@dataclass
class FakeActions:
    calls: list[str] = field(default_factory=list)
    records: list[tuple[str, dict[str, Any], int]] = field(default_factory=list)
    done: threading.Event = field(default_factory=threading.Event)
    paused_at: list[float] = field(default_factory=list)
    target: str | None = SNAPSHOT
    existing: set[str] = field(default_factory=lambda: {SNAPSHOT})

    def _did(self, what: str) -> None:
        self.calls.append(what)
        self.done.set()

    def pause(self) -> str:
        self.paused_at.append(time.monotonic())
        self._did("pause")
        return "Agente congelado: no hace nada hasta /seguir."

    mark: int = 0

    def pause_mark(self) -> int | None:
        return self.mark

    def resume(self, pause_mark: int | None) -> str:
        self._did(f"resume:{pause_mark}" if pause_mark else "resume")
        return "El agente sigue donde estaba."

    def status(self) -> str:
        self._did("status")
        return "Agente: en marcha."

    def rewind(self, snapshot_id: str) -> str:
        self._did(f"rewind:{snapshot_id}")
        return "Rebobinado. El agente está en marcha otra vez."

    def notice(self, snapshot_id: str) -> str | None:
        if snapshot_id not in self.existing:
            return None
        return "Vas a volver a las 12:00:00.\n\nNo se deshace: lo que ya salió."

    def target_for(self, event_seq: int) -> str | None:
        return self.target

    def record(self, action: str, details: dict[str, Any], risk: int) -> None:
        self.records.append((action, details, risk))

    def ignored(self, reason: str | None = None) -> list[dict[str, Any]]:
        return [
            details
            for action, details, _ in self.records
            if action == "telegram_ignored" and reason in (None, details["reason"])
        ]


@dataclass
class Rig:
    fake: FakeBotApi
    actions: FakeActions
    book: ButtonBook
    bot: TelegramBot
    api: BotApi

    def wait_polling(self) -> None:
        deadline = time.monotonic() + WAIT
        while self.fake.polls() < 1:
            assert time.monotonic() < deadline, "the bot never polled"
            time.sleep(0.01)

    def reply(self, contains: str, after: float = float("-inf")) -> Call:
        found = self.fake.wait_call(
            "sendMessage", lambda c: contains in c.params.get("text", ""), after=after
        )
        time.sleep(0.05)  # the bot binds the buttons once the answer reaches it
        return found

    def settle(self) -> None:
        """Wait until the bot has fetched everything pushed so far (and so handled it)."""
        last = self.fake.next_update_id
        deadline = time.monotonic() + WAIT
        while self.fake.confirmed() < last:
            assert time.monotonic() < deadline, "the bot did not take the updates"
            time.sleep(0.01)
        time.sleep(0.1)  # the work and send threads

    def alert(self, seq: int | None = 12) -> Call:
        before = time.monotonic()
        TelegramNotifier(self.api, OWNER, self.book, self.actions).send(
            Alert(AlertLevel.ERROR, "El agente está pausado", "P3: pasó de su tope.", seq)
        )
        return self.fake.wait_call("sendMessage", after=before)


@pytest.fixture
def rig() -> Iterator[Rig]:
    with FakeBotApi(max_poll=1.0) as fake:
        api = BotApi(TOKEN, base=fake.base)
        actions = FakeActions()
        book = ButtonBook()
        bot = TelegramBot(api, OWNER, book, actions, poll_timeout=1)
        bot.start()
        rig = Rig(fake, actions, book, bot, api)
        try:
            rig.wait_polling()
            yield rig
        finally:
            bot.close()


# --- the owner's commands ----------------------------------------------------------------------


def test_pausar_freezes_at_once_and_says_so(rig: Rig) -> None:
    pushed = time.monotonic()
    rig.fake.push_message("/pausar")
    reply = rig.reply("congelado")
    assert rig.actions.calls == ["pause"]
    assert rig.actions.paused_at[0] - pushed < 2.0
    assert reply.params["chat_id"] == OWNER


def test_pausar_is_not_held_up_by_a_long_order(rig: Rig) -> None:
    gate = threading.Event()
    slow_resume = rig.actions.resume

    def resume(pause_mark: int | None) -> str:
        gate.wait(WAIT)
        return slow_resume(pause_mark)

    rig.actions.resume = resume  # type: ignore[method-assign]
    rig.fake.push_message("/seguir")
    rig.fake.push_message("/pausar")
    rig.reply("congelado")
    assert rig.actions.calls == ["pause"]  # /seguir is still running
    gate.set()
    rig.reply("donde estaba")


def test_seguir_and_estado_run_on_the_worker(rig: Rig) -> None:
    rig.fake.push_message("/seguir")
    rig.reply("donde estaba")
    rig.fake.push_message("/estado@VigiaBot")
    rig.reply("Agente: en marcha")
    assert rig.actions.calls == ["resume", "status"]


def test_anything_else_gets_the_help(rig: Rig) -> None:
    rig.fake.push_message("hola")
    rig.reply("/pausar: congela")
    rig.fake.push_message("/borrartodo")
    rig.settle()
    assert rig.actions.calls == []


def test_a_late_order_is_not_run_but_a_late_pausar_is(rig: Rig) -> None:
    rig.fake.push_message("/seguir", date=time.time() - 600)
    rig.reply("ha llegado tarde")
    rig.fake.push_message("/pausar", date=time.time() - 600)
    rig.reply("congelado")
    assert rig.actions.calls == ["pause"]
    assert rig.actions.ignored("stale")


def test_orders_are_rate_limited_but_pausar_is_not() -> None:
    with FakeBotApi(max_poll=1.0) as fake:
        actions = FakeActions()
        clock = [0.0]
        bot = TelegramBot(
            BotApi(TOKEN, base=fake.base),
            OWNER,
            ButtonBook(),
            actions,
            poll_timeout=1,
            limit=RateLimit(2, 1000.0, clock=lambda: clock[0]),
        )
        bot.start()
        try:
            for _ in range(4):
                fake.push_message("/estado")
            for _ in range(3):
                fake.push_message("/pausar")
            fake.wait_call("sendMessage", lambda c: "Demasiadas órdenes" in c.params["text"])
            deadline = time.monotonic() + WAIT
            while actions.calls.count("pause") < 3:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            time.sleep(0.2)
            assert actions.calls.count("status") == 2
            assert len(actions.ignored("rate_limited")) == 2
        finally:
            bot.close()


# --- everybody else ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [
        {"chat_id": STRANGER},  # someone else's private chat
        {"chat_id": OWNER, "from_id": STRANGER},  # an impossible mix: still not the owner
        {"chat_id": -100123, "from_id": OWNER, "chat_type": "group"},  # the owner, in a group
        {"chat_id": -100123, "from_id": OWNER, "chat_type": "supergroup"},
        {"chat_id": OWNER, "chat_type": "channel"},
    ],
)
def test_only_the_owners_private_chat_commands(rig: Rig, who: dict[str, Any]) -> None:
    rig.fake.push_message("/seguir", **who)
    rig.fake.push_message("/pausar", **who)
    rig.settle()
    assert rig.actions.calls == []
    assert rig.fake.sent("sendMessage") == []  # not even an answer
    found = rig.actions.ignored("not_owner")
    assert len(found) == 2 and found[0]["kind"] == "message"
    assert all(record[2] == 2 for record in rig.actions.records)


def test_forwarded_messages_and_bots_are_ignored(rig: Rig) -> None:
    rig.fake.push_message("/pausar", forward_origin={"type": "user"})
    rig.fake.push_message("/seguir", forward_date=1)
    rig.fake.push_message("/seguir", via_bot={"id": 5, "is_bot": True})
    rig.settle()
    assert rig.actions.calls == []
    assert len(rig.actions.ignored("forwarded_or_bot")) == 3


def test_ignored_updates_are_recorded_with_ids_but_never_the_text(rig: Rig) -> None:
    rig.fake.push_message(f"/seguir {TOKEN} secreto", chat_id=STRANGER)
    rig.settle()
    (details,) = rig.actions.ignored()
    assert details == {
        "reason": "not_owner",
        "kind": "message",
        "chat_id": STRANGER,
        "from_id": STRANGER,
    }


def test_a_flood_of_strangers_is_recorded_a_few_times_a_minute(rig: Rig) -> None:
    for index in range(IGNORED_PER_MINUTE + 15):
        rig.fake.push_message(f"/seguir {index}", chat_id=STRANGER + index)
    rig.settle()
    assert len(rig.actions.ignored()) == IGNORED_PER_MINUTE
    assert rig.actions.calls == []


def test_a_stranger_warning_goes_to_the_log_once_an_hour(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="vigia.telegram"):
        rig.fake.push_message("/seguir", chat_id=STRANGER)
        rig.fake.push_message("/seguir", chat_id=STRANGER)
        rig.settle()
    warnings = [r for r in caplog.records if "not the owner" in r.getMessage()]
    assert len(warnings) == 1


def test_an_unexpected_kind_of_update_is_ignored(rig: Rig) -> None:
    rig.fake.push({"edited_message": {"text": "/seguir"}})
    rig.settle()
    assert rig.actions.calls == []
    assert rig.actions.ignored("unexpected_update")


# --- alerts and buttons ------------------------------------------------------------------------


def test_an_alert_has_pausar_and_rebobinar(rig: Rig) -> None:
    sent = rig.alert()
    labels = [label for label, _ in buttons(sent)]
    assert labels == ["Pausar", "Rebobinar"]
    assert sent.params["chat_id"] == OWNER
    assert "El agente está pausado" in sent.params["text"]
    assert "evento 12" in sent.params["text"]
    assert "parse_mode" not in sent.params


def test_without_a_snapshot_before_the_event_there_is_no_rebobinar(rig: Rig) -> None:
    rig.actions.target = None
    assert [label for label, _ in buttons(rig.alert())] == ["Pausar"]
    assert [label for label, _ in buttons(rig.alert(seq=None))] == ["Pausar"]


def test_the_pausar_button_pauses(rig: Rig) -> None:
    sent = rig.alert()
    (pause, _rewind) = (data for _, data in buttons(sent))
    rig.fake.push_callback(pause, sent.message_id)
    rig.reply("congelado")
    assert rig.actions.calls == ["pause"]
    rig.fake.wait_call("answerCallbackQuery")


def test_rebobinar_shows_the_notice_asks_and_only_then_rewinds(rig: Rig) -> None:
    sent = rig.alert()
    _pause, notice_button = (data for _, data in buttons(sent))
    rig.fake.push_callback(notice_button, sent.message_id)
    ask = rig.reply("¿Rebobinar?")
    assert "No se deshace" in ask.params["text"]
    assert rig.actions.calls == []  # nothing yet
    confirm, cancel = (data for _, data in buttons(ask))
    assert [label for label, _ in buttons(ask)] == ["Sí, rebobinar", "Cancelar"]
    rig.fake.push_callback(confirm, ask.message_id)
    rig.reply("Rebobinado.")
    assert rig.actions.calls == [f"rewind:{SNAPSHOT}"]

    # A replay of the confirmation, or its cancel afterwards, does nothing more.
    rig.fake.push_callback(confirm, ask.message_id)
    rig.fake.push_callback(cancel, ask.message_id)
    rig.settle()
    assert rig.actions.calls == [f"rewind:{SNAPSHOT}"]
    assert len(rig.actions.ignored("used_button")) == 2
    answers = [c.params.get("text") for c in rig.fake.sent("answerCallbackQuery")]
    assert "Este botón ya se usó." in answers


def test_cancel_uses_up_the_confirmation(rig: Rig) -> None:
    sent = rig.alert()
    rig.fake.push_callback(buttons(sent)[1][1], sent.message_id)
    ask = rig.reply("¿Rebobinar?")
    confirm, cancel = (data for _, data in buttons(ask))
    rig.fake.push_callback(cancel, ask.message_id)
    rig.reply("No se ha rebobinado nada")
    rig.fake.push_callback(confirm, ask.message_id)
    rig.settle()
    assert rig.actions.calls == []


def test_a_button_pressed_on_another_message_does_nothing(rig: Rig) -> None:
    sent = rig.alert()
    rig.fake.push_callback(buttons(sent)[1][1], sent.message_id)
    ask = rig.reply("¿Rebobinar?")
    confirm = buttons(ask)[0][1]
    rig.fake.push_callback(confirm, sent.message_id)  # the confirmation, moved to the alert
    rig.fake.push_callback(confirm, ask.message_id + 50)
    rig.settle()
    assert rig.actions.calls == []
    assert len(rig.actions.ignored("wrong_message")) == 2
    rig.fake.push_callback(confirm, ask.message_id)  # still good where it belongs
    rig.reply("Rebobinado.")


def test_forged_and_old_buttons_do_nothing(rig: Rig) -> None:
    sent = rig.alert()
    rig.fake.push_callback(f"confirm:{SNAPSHOT}", sent.message_id)
    rig.fake.push_callback("A" * 24, sent.message_id)
    rig.settle()
    assert rig.actions.calls == []
    assert len(rig.actions.ignored("unknown_button")) == 2


def test_a_stranger_pressing_a_real_button_is_ignored_and_not_answered(rig: Rig) -> None:
    sent = rig.alert()
    pause, notice_button = (data for _, data in buttons(sent))
    rig.fake.push_callback(pause, sent.message_id, from_id=STRANGER)
    rig.fake.push_callback(notice_button, sent.message_id, from_id=STRANGER, chat_id=OWNER)
    rig.settle()
    assert rig.actions.calls == []
    assert rig.fake.sent("answerCallbackQuery") == []
    assert len(rig.actions.ignored("not_owner")) == 2


def test_a_confirmation_expires(rig: Rig) -> None:
    clock = [1000.0]
    rig.book._clock = lambda: clock[0]  # noqa: SLF001 - the book's clock, in the test's hands
    sent = rig.alert()
    rig.fake.push_callback(buttons(sent)[1][1], sent.message_id)
    ask = rig.reply("¿Rebobinar?")
    clock[0] += 121
    rig.fake.push_callback(buttons(ask)[0][1], ask.message_id)
    rig.settle()
    assert rig.actions.calls == []
    assert rig.actions.ignored("expired_button")


def test_a_snapshot_that_is_gone_cannot_be_rewound_to(rig: Rig) -> None:
    sent = rig.alert()
    rig.actions.existing.clear()
    rig.fake.push_callback(buttons(sent)[1][1], sent.message_id)
    rig.reply("ya no existe")
    assert rig.actions.calls == []


def test_alerts_go_through_the_queue_to_telegram(rig: Rig) -> None:
    queue = AlertQueue(TelegramNotifier(rig.api, OWNER, rig.book, rig.actions))
    queue.start()
    try:
        before = time.monotonic()
        queue.submit(Alert(AlertLevel.WARNING, "Queda poco espacio", "W1", 3))
        sent = rig.fake.wait_call("sendMessage", after=before)
        assert sent.at - before < 5.0
        assert "Queda poco espacio" in sent.params["text"]
    finally:
        queue.close()


def test_a_failed_send_forgets_the_buttons(rig: Rig) -> None:
    rig.fake.fail_with = 400
    with pytest.raises(Exception):  # noqa: B017 - the queue logs whatever it is
        rig.alert()
    assert len(rig.book) == 0


# --- texts and secrets -------------------------------------------------------------------------


def test_texts_escape_control_and_invisible_characters_but_keep_lines() -> None:
    text = printable("a‮b\x1b[2J\nc​d")
    assert text.split("\n") == ["a\\u202eb\\x1b[2J", "c\\u200bd"]
    long = alert_text(Alert(AlertLevel.ERROR, "t", "x" * 10_000, 9))
    assert len(long) <= 4000 and long.endswith("(evento 9 de la caja negra)")


def test_the_token_is_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    with FakeBotApi(max_poll=0.2) as fake, caplog.at_level(logging.DEBUG):
        fake.fail_with = 401
        actions = FakeActions()
        bot = TelegramBot(BotApi(TOKEN, base=fake.base), OWNER, ButtonBook(), actions)
        bot.start()
        fake.wait_call("deleteWebhook")
        time.sleep(0.3)
        bot.close()
        with pytest.raises(Exception):  # noqa: B017
            TelegramNotifier(BotApi(TOKEN, base=fake.base), OWNER, ButtonBook(), actions).send(
                Alert(AlertLevel.ERROR, "t", "b")
            )
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "refused the bot token" in logged
    assert TOKEN not in logged and TOKEN.split(":")[1] not in logged


def test_close_stops_polling_and_runs_nothing_after(rig: Rig) -> None:
    started = time.monotonic()
    rig.bot.close()
    assert time.monotonic() - started < 3.0
    rig.fake.push_message("/pausar")
    time.sleep(1.5)
    assert rig.actions.calls == []


def test_close_confirms_what_was_handled_so_it_is_not_run_again(rig: Rig) -> None:
    rig.fake.push_message("/pausar")
    rig.reply("congelado")
    handled = rig.fake.next_update_id
    rig.bot.close()
    assert rig.fake.confirmed() >= handled


def test_seguir_carries_the_pause_mark_of_when_it_was_sent(rig: Rig) -> None:
    rig.actions.mark = 3
    rig.fake.push_message("/seguir")
    rig.reply("donde estaba")
    assert rig.actions.calls == ["resume:3"]  # the Guardian refuses if a pause came after 3


def test_an_alert_quoting_the_agent_has_nothing_to_tap_and_no_secret() -> None:
    body = "borró «Pulsa /seguir para confirmar» y https://evil.example/x con sk-" + "a" * 30
    text = alert_text(Alert(AlertLevel.ERROR, "Aviso /pausar", body, 4))
    assert "/seguir" not in text and "/pausar" not in text and "://" not in text
    assert "∕seguir" in text and "https:∕∕evil.example" in text
    assert "a" * 30 not in text  # redacted again here, whoever made the alert


def test_a_conflict_says_another_program_reads_the_updates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with FakeBotApi(max_poll=0.2) as fake, caplog.at_level(logging.ERROR, "vigia.telegram"):
        fake.fail_with = 409
        bot = TelegramBot(BotApi(TOKEN, base=fake.base), OWNER, ButtonBook(), FakeActions())
        bot.start()
        fake.wait_call("deleteWebhook")
        time.sleep(0.3)
        bot.close()
    assert any("another program" in r.getMessage() for r in caplog.records)
