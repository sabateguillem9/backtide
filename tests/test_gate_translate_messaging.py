"""The messaging translators (Telegram, Slack, Discord) in detail: recipients from named fields
only, the multipart bodies, GET-style sends, parameters given twice, what is shown, and the
semantic fingerprint's input (docs/32, sections 8 and 15)."""

import pytest

from backtide.gate.translate import Effect
from backtide.gate.translate.base import Note
from tests.gate_translate_kit import (
    BOT,
    BOT_PATH,
    DISCORD_AUTH,
    OTHER_BOT,
    SLACK_AUTH,
    multipart,
    read,
    request,
    scrubbed,
    tg,
)

# --- Telegram ------------------------------------------------------------------------------------


def test_a_telegram_send_shows_its_text_and_marks_the_token_in_the_path() -> None:
    reading = read(tg("sendMessage", {"chat_id": 42, "text": "uno\ndos\ntres\ncuatro"}))
    assert reading.operation == "sendmessage"
    assert reading.first_lines == "uno\ndos\ntres"
    assert reading.path_credential
    assert reading.account is not None and BOT not in repr(reading)


def test_a_get_that_sends_is_a_send() -> None:
    view = request(
        "GET",
        "api.telegram.org",
        f"{BOT_PATH}/sendMessage?chat_id=%2B0042&text=hola%20extra%C3%B1o",
    )
    reading = read(view)
    assert reading.effect is Effect.SEND
    assert reading.recipients == ("42",)  # +0042 is the chat 42, as Telegram reads it
    assert reading.first_lines == "hola extraño"


@pytest.mark.parametrize("method", ["sendmessage", "SENDMESSAGE", "sEnDmEsSaGe", "SendMessage"])
def test_method_names_are_case_insensitive(method: str) -> None:
    reading = read(tg(method, {"chat_id": 1, "text": "x"}))
    assert reading.effect is Effect.SEND and reading.operation == "sendmessage"


@pytest.mark.parametrize(
    "chat", [True, 1.5, [1], {"a": 1}, "", "abc", "@", "@a b", "1" * 21, "@" + "a" * 65]
)
def test_an_odd_chat_id_is_unknown(chat: object) -> None:
    assert read(tg("sendMessage", {"chat_id": chat, "text": "x"})).effect is Effect.UNKNOWN


def test_a_send_without_a_chat_is_unknown() -> None:
    assert read(tg("sendMessage", {"text": "x"})).effect is Effect.UNKNOWN
    assert read(tg("forwardMessage", {"chat_id": 1, "message_id": 2})).effect is Effect.UNKNOWN


def test_a_parameter_given_twice_is_unknown() -> None:
    both = request(
        "POST",
        "api.telegram.org",
        f"{BOT_PATH}/sendMessage?chat_id=1",
        json_body={"chat_id": 2, "text": "x"},
    )
    assert read(both).effect is Effect.UNKNOWN and Note.DUPLICATE in read(both).notes
    folded = request(
        "POST",
        "api.telegram.org",
        f"{BOT_PATH}/sendMessage?Chat_Id=1",
        json_body={"chat_id": 2, "text": "x"},
    )
    assert read(folded).effect is Effect.UNKNOWN
    twice = request("GET", "api.telegram.org", f"{BOT_PATH}/sendMessage?chat_id=1&chat_id=2")
    assert read(twice).effect is Effect.UNKNOWN
    json_twice = request(
        "POST",
        "api.telegram.org",
        f"{BOT_PATH}/sendMessage",
        body=b'{"chat_id":1,"chat_id":2}',
        headers=(("content-type", "application/json"),),
    )
    assert read(json_twice).effect is Effect.UNKNOWN


def test_a_get_with_a_body_or_a_body_of_another_type_is_unknown() -> None:
    get_body = request("GET", "api.telegram.org", f"{BOT_PATH}/getMe", body=b"chat_id=1")
    assert read(get_body).effect is Effect.UNKNOWN
    xml = request(
        "POST",
        "api.telegram.org",
        f"{BOT_PATH}/sendMessage",
        body=b"<x/>",
        headers=(("content-type", "text/xml"),),
    )
    assert read(xml).effect is Effect.UNKNOWN


def test_the_multipart_of_a_photo_is_read() -> None:
    header, body = multipart(
        [
            ("chat_id", None, None, b"42"),
            ("caption", None, None, b"mira"),
            ("photo", "gato.jpg", "image/jpeg", b"\xff\xd8\xff\xe0\x00\x10JFIF"),
        ]
    )
    reading = read(
        request("POST", "api.telegram.org", f"{BOT_PATH}/sendPhoto", body=body, headers=(header,))
    )
    assert reading.effect is Effect.SEND and reading.recipients == ("42",)
    assert reading.first_lines == "mira"
    assert [(a.name, a.type, a.size) for a in reading.attachments] == [
        ("gato.jpg", "image/jpeg", 10)
    ]
    assert reading.wait_s == 25


def test_an_odd_multipart_is_unknown() -> None:
    header, body = multipart([("chat_id", None, None, b"1"), ("chat_id", None, None, b"2")])
    cases = [
        (header, body),
        (header, body.replace(b"--XbacktideX--", b"")),  # never closed
        (("content-type", "multipart/form-data"), body),  # no boundary
        (("content-type", "multipart/form-data; boundary=a; boundary=XbacktideX"), body),
        (header, b"--XbacktideX\r\nContent-Type: text/plain\r\n\r\nx\r\n--XbacktideX--\r\n"),
    ]
    for content_type, data in cases:
        view = request(
            "POST",
            "api.telegram.org",
            f"{BOT_PATH}/sendMessage",
            body=data,
            headers=(content_type,),
        )
        assert read(view).effect is Effect.UNKNOWN, content_type


def test_a_forward_names_where_the_message_comes_from() -> None:
    reading = read(tg("forwardMessage", {"chat_id": 9, "from_chat_id": "-100777", "message_id": 3}))
    assert reading.effect is Effect.FORWARD
    assert reading.recipients == ("9",) and reading.target == "from chat -100777"


def test_a_key_sent_to_a_chat_is_seen() -> None:
    header, body = multipart(
        [
            ("chat_id", None, None, b"42"),
            ("document", "id_rsa", None, b"-----BEGIN RSA PRIVATE KEY-----\nx"),
        ]
    )
    reading = read(
        request(
            "POST", "api.telegram.org", f"{BOT_PATH}/sendDocument", body=body, headers=(header,)
        )
    )
    assert reading.secret_seen and reading.risk == 3
    fake = "fake-gateway-token-1234567890"
    in_text = read(tg("sendMessage", {"chat_id": 1, "text": "es " + fake}), scrubbed(fake))
    assert in_text.secret_seen and fake not in (in_text.first_lines or "")


def test_the_telegram_canonical_form() -> None:
    def canonical(params: dict[str, object], bot: str = BOT) -> bytes | None:
        return read(tg("sendMessage", params, bot=bot)).canonical

    base = canonical({"chat_id": 1, "text": "hola"})
    assert base == canonical({"chat_id": 1, "text": "hola"})
    assert base != canonical({"chat_id": 2, "text": "hola"})
    assert base != canonical({"chat_id": 1, "text": "hola!"})
    assert base != canonical({"chat_id": 1, "text": "hola"}, bot=OTHER_BOT)
    assert base != canonical(
        {"chat_id": 1, "text": "hola", "reply_markup": {"inline_keyboard": []}}
    )


def test_a_different_bot_is_a_different_account() -> None:
    first = read(tg("sendMessage", {"chat_id": 1, "text": "x"}))
    second = read(tg("sendMessage", {"chat_id": 1, "text": "x"}, bot=OTHER_BOT))
    assert first.account != second.account


# --- Slack ---------------------------------------------------------------------------------------


def _slack(method: str, body: dict[str, object], *headers: tuple[str, str]) -> object:
    return read(
        request(
            "POST", "slack.com", f"/api/{method}", json_body=body, headers=headers or (SLACK_AUTH,)
        )
    )


def test_a_slack_post_shows_its_text() -> None:
    reading = _slack("chat.postMessage", {"channel": "C0123", "text": "hola\nequipo"})
    assert reading.first_lines == "hola\nequipo"  # type: ignore[attr-defined]
    assert reading.account is not None  # type: ignore[attr-defined]


def test_slack_tokens_in_two_places_or_two_channel_fields_are_unknown() -> None:
    twice = request(
        "POST",
        "slack.com",
        "/api/chat.postMessage",
        form="channel=C1&text=x&token=xoxb-1",
        headers=(SLACK_AUTH,),
    )
    assert read(twice).effect is Effect.UNKNOWN
    both = _slack("chat.postMessage", {"channel": "C1", "channel_id": "C2", "text": "x"})
    assert both.effect is Effect.UNKNOWN  # type: ignore[attr-defined]
    odd = _slack("chat.postMessage", {"channel": "C1 C2", "text": "x"})
    assert odd.effect is Effect.UNKNOWN  # type: ignore[attr-defined]
    none = _slack("chat.postMessage", {"text": "x"})
    assert none.effect is Effect.UNKNOWN  # type: ignore[attr-defined]


def test_a_slack_upload_to_several_channels_lists_them_all() -> None:
    reading = _slack(
        "files.completeUploadExternal",
        {"channels": "C1,C2", "files": [{"id": "F1", "title": "plan.pdf"}]},
    )
    assert reading.recipients == ("C1", "C2")  # type: ignore[attr-defined]
    assert [a.name for a in reading.attachments] == ["plan.pdf"]  # type: ignore[attr-defined]


def test_a_slack_webhook_never_shows_its_secret() -> None:
    view = request(
        "POST",
        "hooks.slack.com",
        "/services/T0001/B0002/sEcReTsEcReTsEcReT",
        form='payload={"text":"hola"}',
    )
    reading = read(view)
    assert reading.effect is Effect.SEND and reading.recipients == ("webhook:T0001/B0002",)
    assert "sEcReT" not in repr(reading) and reading.path_credential
    assert reading.first_lines == "hola"


def test_the_slack_canonical_form_leaves_the_token_to_the_account() -> None:
    one = _slack("chat.postMessage", {"channel": "C1", "text": "x"})
    two = _slack("chat.postMessage", {"channel": "C1", "text": "x"}, ("authorization", "Bearer y"))
    assert one.canonical != two.canonical  # type: ignore[attr-defined]
    assert b"xoxb" not in (one.canonical or b"")  # type: ignore[attr-defined]


# --- Discord -------------------------------------------------------------------------------------


def _discord(path: str, body: dict[str, object]) -> object:
    return read(request("POST", "discord.com", path, json_body=body, headers=(DISCORD_AUTH,)))


def test_a_discord_message_shows_its_content_and_files() -> None:
    header, body = multipart(
        [
            ("payload_json", None, "application/json", b'{"content":"el informe","nonce":"5"}'),
            ("files[0]", "informe.pdf", "application/pdf", b"%PDF fake"),
            ("files[1]", "datos.csv", "text/csv", b"a,b\n1,2\n"),
        ]
    )
    reading = read(
        request(
            "POST",
            "discord.com",
            "/api/v10/channels/111/messages",
            body=body,
            headers=(header, DISCORD_AUTH),
        )
    )
    assert reading.effect is Effect.SEND and reading.recipients == ("111",)
    assert reading.first_lines == "el informe"
    assert [a.name for a in reading.attachments] == ["informe.pdf", "datos.csv"]
    assert reading.wait_s == 10


def test_a_discord_multipart_with_loose_fields_is_unknown() -> None:
    header, body = multipart([("content", None, None, b"x"), ("payload_json", None, None, b"{}")])
    reading = read(
        request(
            "POST",
            "discord.com",
            "/api/v10/channels/111/messages",
            body=body,
            headers=(header, DISCORD_AUTH),
        )
    )
    assert reading.effect is Effect.UNKNOWN


def test_a_discord_message_with_a_field_we_do_not_know_is_unknown() -> None:
    reading = _discord("/api/v10/channels/111/messages", {"content": "x", "new_field": 1})
    assert reading.effect is Effect.UNKNOWN  # type: ignore[attr-defined]


def test_the_discord_nonce_is_not_part_of_the_canonical_form() -> None:
    one = _discord("/api/v10/channels/111/messages", {"content": "x", "nonce": "1"})
    two = _discord("/api/v10/channels/111/messages", {"content": "x", "nonce": "2"})
    other = _discord("/api/v10/channels/112/messages", {"content": "x", "nonce": "1"})
    assert one.canonical == two.canonical != other.canonical  # type: ignore[attr-defined]


def test_a_discord_webhook_keeps_its_token_out_and_its_thread_in() -> None:
    plain = read(
        request("POST", "discord.com", "/api/webhooks/222/tOkEn-123", json_body={"content": "x"})
    )
    thread = read(
        request(
            "POST",
            "discord.com",
            "/api/webhooks/222/tOkEn-123?thread_id=9",
            json_body={"content": "x"},
        )
    )
    assert plain.recipients == ("webhook:222",) and plain.path_credential
    assert "tOkEn" not in repr(plain)
    assert plain.canonical != thread.canonical
