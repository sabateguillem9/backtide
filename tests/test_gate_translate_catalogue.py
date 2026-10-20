"""The translators' catalogue (docs/32, section 15): requests in the shape each client really
sends, and the effect and recipients each one must give. The rule that matters most: NO write
in the catalogue is ever read as ``Effect.READ`` (which passes without asking). The few writes
the founder let pass (one message's labels, "typing...", a bare callback answer, deleteWebhook,
opening a DM, asking for an upload URL: docs/32, decision 12) are marked ``harmless``, and listed
by name so a new one cannot slip in unnoticed. Drafts pass too, but only in the owner's own
accounts (``OWNER_DRAFTS``).
"""

from dataclasses import dataclass

import pytest

from backtide.gate.translate import Context, Effect, RequestView, has_translator, translate
from backtide.gate.translate.base import Shape
from tests.gate_translate_kit import (
    BOT_PATH,
    CTX,
    DISCORD_AUTH,
    GITHUB_AUTH,
    GOOGLE_AUTH,
    GRAPH_AUTH,
    SLACK_AUTH,
    gmail_send,
    mail,
    multipart,
    read,
    request,
    tg,
)

READ, SEND, FORWARD, CHANGE, DELETE, ADMIN, UNKNOWN = (
    Effect.READ,
    Effect.SEND,
    Effect.FORWARD,
    Effect.CHANGE,
    Effect.DELETE,
    Effect.ADMIN,
    Effect.UNKNOWN,
)


@dataclass(frozen=True)
class Case:
    id: str
    view: RequestView
    effect: Effect
    recipients: tuple[str, ...] | None = None
    write: bool = True  # False: a read; "harmless" ones are writes the founder lets pass
    harmless: bool = False


def _photo() -> RequestView:
    header, body = multipart(
        [
            ("chat_id", None, None, b"42"),
            ("caption", None, None, b"la foto"),
            ("photo", "gato.jpg", "image/jpeg", b"\xff\xd8\xff\xe0 fake jpeg"),
        ]
    )
    return request(
        "POST", "api.telegram.org", f"{BOT_PATH}/sendPhoto", body=body, headers=(header,)
    )


def _discord_files() -> RequestView:
    header, body = multipart(
        [
            ("payload_json", None, "application/json", b'{"content":"mira esto","nonce":"77"}'),
            ("files[0]", "informe.pdf", "application/pdf", b"%PDF-1.7 fake"),
        ]
    )
    return request(
        "POST",
        "discord.com",
        "/api/v10/channels/111/messages",
        body=body,
        headers=(header, DISCORD_AUTH),
    )


def _gmail_upload(kind: str) -> RequestView:
    raw = mail()
    if kind == "media":
        return request(
            "POST",
            "gmail.googleapis.com",
            "/upload/gmail/v1/users/me/messages/send?uploadType=media",
            body=raw,
            headers=(GOOGLE_AUTH, ("content-type", "message/rfc822")),
        )
    body = (
        b'--rel\r\nContent-Type: application/json\r\n\r\n{"threadId":"t1"}\r\n'
        b"--rel\r\nContent-Type: message/rfc822\r\n\r\n" + raw + b"\r\n--rel--\r\n"
    )
    return request(
        "POST",
        "gmail.googleapis.com",
        "/upload/gmail/v1/users/me/messages/send?uploadType=multipart",
        body=body,
        headers=(GOOGLE_AUTH, ("content-type", "multipart/related; boundary=rel")),
    )


def _graph_mail() -> dict[str, object]:
    return {
        "message": {
            "subject": "Hola",
            "body": {"contentType": "Text", "content": "Te escribo desde Outlook"},
            "toRecipients": [{"emailAddress": {"address": "ana@example.com"}}],
            "ccRecipients": [{"emailAddress": {"address": "Luis@Example.com", "name": "Luis"}}],
        },
        "saveToSentItems": True,
    }


G = "/gmail/v1/users/me"
M = "/v1.0/me"
D = "/api/v10"


def _gmail(method: str, path: str, body: object = None, host: str = "gmail.googleapis.com"):
    return request(method, host, path, json_body=body, headers=(GOOGLE_AUTH,))


def _graph(method: str, path: str, body: object = None) -> RequestView:
    return request(method, "graph.microsoft.com", path, json_body=body, headers=(GRAPH_AUTH,))


def _slack(method: str, body: object = None, *, host: str = "slack.com") -> RequestView:
    return request("POST", host, f"/api/{method}", json_body=body or {}, headers=(SLACK_AUTH,))


def _discord(method: str, path: str, body: object = None, host: str = "discord.com"):
    return request(method, host, path, json_body=body, headers=(DISCORD_AUTH,))


def _gh(query: str) -> RequestView:
    return request(
        "POST", "api.github.com", "/graphql", json_body={"query": query}, headers=(GITHUB_AUTH,)
    )


CATALOGUE = [
    # --- Telegram (grammy: POST with JSON; the Bot API also takes GET and forms) -------------
    Case("tg-send", tg("sendMessage", {"chat_id": 42, "text": "hola"}), SEND, ("42",)),
    Case(
        "tg-send-get",
        request("GET", "api.telegram.org", f"{BOT_PATH}/sendMessage?chat_id=-100123&text=hola"),
        SEND,
        ("-100123",),
    ),
    Case(
        "tg-send-odd-case",
        request("POST", "api.telegram.org", f"{BOT_PATH}/SeNdMeSsAgE", form="chat_id=42&text=hola"),
        SEND,
        ("42",),
    ),
    Case(
        "tg-send-username",
        tg("sendMessage", {"chat_id": "@MiCanal", "text": "x"}),
        SEND,
        ("@micanal",),
    ),
    Case("tg-photo", _photo(), SEND, ("42",)),
    Case(
        "tg-document-get-upper",
        request(
            "GET", "api.telegram.org", f"{BOT_PATH}/SENDDOCUMENT?chat_id=7&document=BQACAgIAAx"
        ),
        SEND,
        ("7",),
    ),
    Case(
        "tg-media-group",
        tg(
            "sendMediaGroup",
            {"chat_id": 42, "media": [{"type": "photo", "media": "AgACAgIAAx", "caption": "dos"}]},
        ),
        SEND,
        ("42",),
    ),
    Case(
        "tg-poll",
        tg("sendPoll", {"chat_id": 42, "question": "¿Sí?", "options": ["a", "b"]}),
        SEND,
        ("42",),
    ),
    Case(
        "tg-location",
        tg("sendLocation", {"chat_id": 42, "latitude": 1, "longitude": 2}),
        SEND,
        ("42",),
    ),
    Case(
        "tg-forward",
        tg("forwardMessage", {"chat_id": 9, "from_chat_id": 42, "message_id": 3}),
        FORWARD,
        ("9",),
    ),
    Case(
        "tg-copy",
        tg("copyMessage", {"chat_id": 9, "from_chat_id": 42, "message_id": 3}),
        FORWARD,
        ("9",),
    ),
    Case(
        "tg-edit",
        tg("editMessageText", {"chat_id": 42, "message_id": 3, "text": "y"}),
        CHANGE,
        ("42",),
    ),
    Case("tg-delete", tg("deleteMessage", {"chat_id": 42, "message_id": 3}), DELETE, ("42",)),
    Case(
        "tg-delete-many",
        tg("deleteMessages", {"chat_id": 42, "message_ids": [3, 4]}),
        DELETE,
        ("42",),
    ),
    Case("tg-set-webhook", tg("setWebhook", {"url": "https://evil.example/hook"}), ADMIN),
    Case("tg-logout", tg("logOut"), ADMIN),
    Case("tg-ban", tg("banChatMember", {"chat_id": -100, "user_id": 5}), ADMIN),
    Case("tg-invite-link", tg("createChatInviteLink", {"chat_id": -100}), ADMIN),
    Case(
        "tg-inline-answer",
        tg("answerInlineQuery", {"inline_query_id": "1", "results": []}),
        UNKNOWN,
    ),
    Case("tg-new-method", tg("sendSomethingNew", {"chat_id": 42}), UNKNOWN),
    Case("tg-get-updates", tg("getUpdates", {"offset": 10, "timeout": 30}), READ, write=False),
    Case("tg-get-me", tg("getMe"), READ, write=False),
    Case("tg-get-file", tg("getFile", {"file_id": "x"}), READ, write=False),
    Case(
        "tg-download",
        request("GET", "api.telegram.org", f"/file{BOT_PATH}/photos/f_1.jpg"),
        READ,
        write=False,
    ),
    Case(
        "tg-typing", tg("sendChatAction", {"chat_id": 9, "action": "typing"}), READ, harmless=True
    ),
    Case("tg-callback", tg("answerCallbackQuery", {"callback_query_id": "1"}), READ, harmless=True),
    Case("tg-commands", tg("setMyCommands", {"commands": []}), ADMIN),
    Case(
        "tg-callback-text",
        tg("answerCallbackQuery", {"callback_query_id": "1", "text": "hecho"}),
        CHANGE,
    ),
    Case("tg-delete-webhook", tg("deleteWebhook"), READ, harmless=True),
    # --- Gmail (gog: POST .../messages/send with {"raw": base64url}) --------------------------
    Case(
        "gm-send",
        gmail_send(mail(cc="luis@example.com", bcc="eva@example.net")),
        SEND,
        ("ana@example.com", "luis@example.com", "eva@example.net"),
    ),
    Case(
        "gm-send-thread", gmail_send(mail(), extra={"threadId": "18c"}), SEND, ("ana@example.com",)
    ),
    Case("gm-upload-media", _gmail_upload("media"), SEND, ("ana@example.com",)),
    Case("gm-upload-multipart", _gmail_upload("multipart"), SEND, ("ana@example.com",)),
    Case(
        "gm-upload-resumable",
        _gmail("POST", "/upload/gmail/v1/users/me/messages/send?uploadType=resumable", {}),
        UNKNOWN,
    ),
    Case("gm-draft-send", _gmail("POST", f"{G}/drafts/send", {"id": "r-1"}), UNKNOWN),
    Case("gm-trash", _gmail("POST", f"{G}/messages/18c/trash"), DELETE),
    Case("gm-thread-trash", _gmail("POST", f"{G}/threads/18c/trash"), DELETE),
    Case("gm-delete", _gmail("DELETE", f"{G}/messages/18c"), DELETE),
    Case("gm-draft-delete", _gmail("DELETE", f"{G}/drafts/r-1"), DELETE),
    Case(
        "gm-batch-delete", _gmail("POST", f"{G}/messages/batchDelete", {"ids": ["1", "2"]}), DELETE
    ),
    Case(
        "gm-modify-trash",
        _gmail("POST", f"{G}/messages/18c/modify", {"addLabelIds": ["TRASH"]}),
        DELETE,
    ),
    Case(
        "gm-batch-modify",
        _gmail("POST", f"{G}/messages/batchModify", {"ids": ["1"], "removeLabelIds": ["INBOX"]}),
        CHANGE,
    ),
    Case("gm-untrash", _gmail("POST", f"{G}/messages/18c/untrash"), CHANGE),
    Case("gm-insert", _gmail("POST", f"{G}/messages/import", {"raw": "eA"}), CHANGE),
    Case("gm-label-create", _gmail("POST", f"{G}/labels", {"name": "x"}), CHANGE),
    Case("gm-filter", _gmail("POST", f"{G}/settings/filters", {"action": {}}), ADMIN),
    Case("gm-autoforward", _gmail("PUT", f"{G}/settings/autoForwarding", {"enabled": True}), ADMIN),
    Case(
        "gm-forwarding-address",
        _gmail("POST", f"{G}/settings/forwardingAddresses", {"forwardingEmail": "x@evil.example"}),
        ADMIN,
    ),
    Case("gm-send-as", _gmail("POST", f"{G}/settings/sendAs", {"sendAsEmail": "x@y.z"}), ADMIN),
    Case("gm-vacation", _gmail("PUT", f"{G}/settings/vacation", {"enableAutoReply": True}), ADMIN),
    Case("gm-watch", _gmail("POST", f"{G}/watch", {"topicName": "projects/x/topics/y"}), ADMIN),
    Case("gm-batch", _gmail("POST", "/batch/gmail/v1", {}), UNKNOWN),
    Case("gm-unknown", _gmail("POST", f"{G}/messages/18c/somethingNew", {}), UNKNOWN),
    Case(
        "gm-calendar-write",
        _gmail("POST", "/calendar/v3/calendars/primary/events", {}, host="www.googleapis.com"),
        UNKNOWN,
    ),
    Case("gm-list", _gmail("GET", f"{G}/messages?q=is:unread"), READ, write=False),
    Case("gm-get", _gmail("GET", f"{G}/messages/18c?format=full"), READ, write=False),
    Case(
        "gm-calendar-read",
        _gmail("GET", "/calendar/v3/calendars/primary/events", host="www.googleapis.com"),
        READ,
        write=False,
    ),
    Case(
        "gm-draft-create",
        _gmail("POST", f"{G}/drafts", {"message": {"raw": "eA"}}),
        CHANGE,
    ),
    Case(
        "gm-draft-update",
        _gmail("PUT", f"{G}/drafts/r-1", {"message": {"raw": "eA"}}),
        CHANGE,
    ),
    Case(
        "gm-label-one",
        _gmail(
            "POST",
            f"{G}/messages/18c/modify",
            {"addLabelIds": ["STARRED"], "removeLabelIds": ["UNREAD"]},
        ),
        READ,
        harmless=True,
    ),
    # --- Microsoft Graph mail ------------------------------------------------------------------
    Case(
        "gr-send",
        _graph("POST", f"{M}/sendMail", _graph_mail()),
        SEND,
        ("ana@example.com", "luis@example.com"),
    ),
    Case(
        "gr-send-user",
        _graph("POST", "/v1.0/users/ana@example.org/sendMail", _graph_mail()),
        SEND,
        ("ana@example.com", "luis@example.com"),
    ),
    Case(
        "gr-send-beta",
        _graph("POST", "/beta/me/sendMail", _graph_mail()),
        SEND,
        ("ana@example.com", "luis@example.com"),
    ),
    Case(
        "gr-forward",
        _graph(
            "POST",
            f"{M}/messages/AAMk1/forward",
            {"comment": "mira", "toRecipients": [{"emailAddress": {"address": "x@example.net"}}]},
        ),
        FORWARD,
        ("x@example.net",),
    ),
    Case("gr-draft-send", _graph("POST", f"{M}/messages/AAMk1/send"), UNKNOWN),
    Case("gr-reply", _graph("POST", f"{M}/messages/AAMk1/reply", {"comment": "ok"}), UNKNOWN),
    Case(
        "gr-reply-all", _graph("POST", f"{M}/messages/AAMk1/replyAll", {"comment": "ok"}), UNKNOWN
    ),
    Case("gr-delete", _graph("DELETE", f"{M}/messages/AAMk1"), DELETE),
    Case("gr-permanent-delete", _graph("POST", f"{M}/messages/AAMk1/permanentDelete"), DELETE),
    Case(
        "gr-move-trash",
        _graph("POST", f"{M}/messages/AAMk1/move", {"destinationId": "deleteditems"}),
        DELETE,
    ),
    Case(
        "gr-move",
        _graph("POST", f"{M}/mailFolders/inbox/messages/AAMk1/move", {"destinationId": "archive"}),
        CHANGE,
    ),
    Case("gr-folder-delete", _graph("DELETE", f"{M}/mailFolders/AQMk2"), DELETE),
    Case(
        "gr-rule",
        _graph("POST", f"{M}/mailFolders/inbox/messageRules", {"displayName": "x"}),
        ADMIN,
    ),
    Case(
        "gr-settings",
        _graph("PATCH", f"{M}/mailboxSettings", {"automaticRepliesSetting": {}}),
        ADMIN,
    ),
    Case("gr-batch", _graph("POST", "/v1.0/$batch", {"requests": []}), UNKNOWN),
    Case("gr-drive-write", _graph("POST", f"{M}/drive/root/children", {"name": "x"}), UNKNOWN),
    Case("gr-list", _graph("GET", f"{M}/messages?$top=5"), READ, write=False),
    Case("gr-drive-read", _graph("GET", f"{M}/drive/root/children"), READ, write=False),
    Case("gr-draft", _graph("POST", f"{M}/messages", {"subject": "x"}), CHANGE),
    Case(
        "gr-draft-edit",
        _graph("PATCH", f"{M}/messages/AAMk1", {"isRead": True}),
        CHANGE,
    ),
    Case("gr-create-reply", _graph("POST", f"{M}/messages/AAMk1/createReply"), CHANGE),
    Case(
        "gr-attachment-add",
        _graph("POST", f"{M}/messages/AAMk1/attachments", {"name": "a.txt"}),
        CHANGE,
    ),
    Case(
        "gr-attachment-delete",
        _graph("DELETE", f"{M}/messages/AAMk1/attachments/AAMkA"),
        DELETE,
    ),
    # --- Slack (@slack/web-api: POST JSON or form; the Web API also takes GET) ----------------
    Case(
        "sl-post",
        _slack("chat.postMessage", {"channel": "C0123", "text": "hola"}),
        SEND,
        ("C0123",),
    ),
    Case(
        "sl-post-form",
        request(
            "POST",
            "slack.com",
            "/api/chat.postMessage",
            form="channel=C0123&text=hola&token=xoxb-0000-fake",
        ),
        SEND,
        ("C0123",),
    ),
    Case(
        "sl-post-get",
        request(
            "GET", "slack.com", "/api/chat.postMessage?channel=D9&text=x", headers=(SLACK_AUTH,)
        ),
        SEND,
        ("D9",),
    ),
    Case(
        "sl-post-workspace",
        _slack("chat.postMessage", {"channel": "C1", "text": "x"}, host="acme.slack.com"),
        SEND,
        ("C1",),
    ),
    Case(
        "sl-ephemeral",
        _slack("chat.postEphemeral", {"channel": "C1", "user": "U1", "text": "x"}),
        SEND,
        ("C1",),
    ),
    Case(
        "sl-schedule",
        _slack("chat.scheduleMessage", {"channel": "C1", "text": "x", "post_at": 1}),
        SEND,
        ("C1",),
    ),
    Case(
        "sl-complete-upload",
        _slack(
            "files.completeUploadExternal",
            {"channel_id": "C1", "files": [{"id": "F1", "title": "informe.pdf"}]},
        ),
        SEND,
        ("C1",),
    ),
    Case(
        "sl-webhook",
        request(
            "POST",
            "hooks.slack.com",
            "/services/T0001/B0002/sEcReTsEcReT",
            json_body={"text": "hola"},
        ),
        SEND,
        ("webhook:T0001/B0002",),
    ),
    Case(
        "sl-update",
        _slack("chat.update", {"channel": "C1", "ts": "1.2", "text": "y"}),
        CHANGE,
        ("C1",),
    ),
    Case("sl-delete", _slack("chat.delete", {"channel": "C1", "ts": "1.2"}), CHANGE, ("C1",)),
    Case("sl-react", _slack("reactions.add", {"channel": "C1", "name": "+1"}), CHANGE, ("C1",)),
    Case("sl-file-delete", _slack("files.delete", {"file": "F1"}), DELETE),
    Case("sl-invite", _slack("conversations.invite", {"channel": "C1", "users": "U2"}), ADMIN),
    Case("sl-create", _slack("conversations.create", {"name": "x"}), ADMIN),
    Case("sl-archive", _slack("conversations.archive", {"channel": "C1"}), ADMIN),
    Case("sl-admin", _slack("admin.users.remove", {"user_id": "U2"}), ADMIN),
    Case("sl-public-file", _slack("files.sharedPublicURL", {"file": "F1"}), ADMIN),
    Case("sl-set-photo", _slack("users.setPhoto", {}), UNKNOWN),
    Case("sl-new-method", _slack("chat.somethingNew", {"channel": "C1"}), UNKNOWN),
    Case("sl-auth-test", _slack("auth.test"), READ, write=False),
    Case("sl-history", _slack("conversations.history", {"channel": "C1"}), READ, write=False),
    Case("sl-users-info", _slack("users.info", {"user": "U1"}), READ, write=False),
    Case("sl-socket", _slack("apps.connections.open"), READ, write=False),
    Case("sl-web-page", request("GET", "slack.com", "/intl/en-gb/"), READ, write=False),
    Case(
        "sl-file-download",
        request("GET", "files.slack.com", "/files-pri/T1-F1/x.png"),
        READ,
        write=False,
    ),
    Case(
        "sl-upload-url",
        _slack("files.getUploadURLExternal", {"filename": "a", "length": 3}),
        READ,
        harmless=True,
    ),
    Case(
        "sl-upload-step",
        request("POST", "files.slack.com", "/upload/v1/ABC123", body=b"abc"),
        SEND,
    ),
    Case("sl-open-dm", _slack("conversations.open", {"users": "U1"}), READ, harmless=True),
    # --- Discord (OpenClaw's REST client on undici) --------------------------------------------
    Case(
        "dc-send",
        _discord("POST", f"{D}/channels/111/messages", {"content": "hola", "nonce": "1"}),
        SEND,
        ("111",),
    ),
    Case("dc-send-files", _discord_files(), SEND, ("111",)),
    Case(
        "dc-send-legacy-host",
        _discord("POST", "/api/channels/111/messages", {"content": "x"}, host="discordapp.com"),
        SEND,
        ("111",),
    ),
    Case(
        "dc-webhook",
        request(
            "POST",
            "discord.com",
            "/api/webhooks/222/tok-en_x?wait=true",
            json_body={"content": "hola"},
        ),
        SEND,
        ("webhook:222",),
    ),
    Case(
        "dc-interaction",
        request(
            "POST",
            "discord.com",
            f"{D}/interactions/333/aW50/callback",
            json_body={"type": 4, "data": {"content": "listo"}},
        ),
        SEND,
        ("interaction:333",),
    ),
    Case(
        "dc-crosspost",
        _discord("POST", f"{D}/channels/111/messages/9/crosspost"),
        FORWARD,
        ("111",),
    ),
    Case(
        "dc-edit",
        _discord("PATCH", f"{D}/channels/111/messages/9", {"content": "y"}),
        CHANGE,
        ("111",),
    ),
    Case("dc-delete", _discord("DELETE", f"{D}/channels/111/messages/9"), DELETE, ("111",)),
    Case(
        "dc-webhook-message-delete",
        request("DELETE", "discord.com", "/api/webhooks/222/tok/messages/9"),
        DELETE,
    ),
    Case(
        "dc-forum-post",
        _discord(
            "POST",
            f"{D}/channels/111/threads",
            {"name": "Tema", "message": {"content": "hola"}},
        ),
        SEND,
        ("111",),
    ),
    Case(
        "dc-forward",
        _discord(
            "POST",
            f"{D}/channels/111/messages",
            {"message_reference": {"type": 1, "message_id": "9", "channel_id": "222"}},
        ),
        FORWARD,
        ("111",),
    ),
    Case(
        "dc-react",
        _discord("PUT", f"{D}/channels/111/messages/9/reactions/x/@me"),
        CHANGE,
        ("111",),
    ),
    Case(
        "dc-webhook-edit",
        request(
            "PATCH", "discord.com", "/api/webhooks/222/tok/messages/9", json_body={"content": "y"}
        ),
        CHANGE,
        ("webhook:222",),
    ),
    Case(
        "dc-bulk-delete",
        _discord("POST", f"{D}/channels/111/messages/bulk-delete", {"messages": ["1", "2"]}),
        DELETE,
    ),
    Case("dc-channel-delete", _discord("DELETE", f"{D}/channels/111"), DELETE),
    Case("dc-webhook-delete", request("DELETE", "discord.com", "/api/webhooks/222/tok"), DELETE),
    Case("dc-create-webhook", _discord("POST", f"{D}/channels/111/webhooks", {"name": "x"}), ADMIN),
    Case("dc-invite", _discord("POST", f"{D}/channels/111/invites", {}), ADMIN),
    Case("dc-role", _discord("POST", f"{D}/guilds/5/roles", {"name": "admin"}), ADMIN),
    Case("dc-guild-channel", _discord("POST", f"{D}/guilds/5/channels", {"name": "x"}), ADMIN),
    Case("dc-ban", _discord("PUT", f"{D}/guilds/5/bans/6", {}), ADMIN),
    Case("dc-unknown", _discord("POST", f"{D}/channels/111/somethingNew", {}), UNKNOWN),
    Case("dc-read", _discord("GET", f"{D}/channels/111/messages?limit=50"), READ, write=False),
    Case("dc-me", _discord("GET", f"{D}/users/@me"), READ, write=False),
    Case("dc-typing", _discord("POST", f"{D}/channels/111/typing"), READ, harmless=True),
    Case(
        "dc-open-dm",
        _discord("POST", f"{D}/users/@me/channels", {"recipient_id": "7"}),
        READ,
        harmless=True,
    ),
    # --- read_post (searches by POST) ----------------------------------------------------------
    Case(
        "rp-tavily",
        request("POST", "api.tavily.com", "/search", json_body={"query": "x"}),
        READ,
        write=False,
    ),
    Case(
        "rp-tavily-extract",
        request("POST", "api.tavily.com", "/extract", json_body={"urls": ["https://example.com"]}),
        READ,
        write=False,
    ),
    Case(
        "rp-exa",
        request("POST", "api.exa.ai", "/search", json_body={"query": "x"}),
        READ,
        write=False,
    ),
    Case(
        "rp-exa-contents",
        request("POST", "api.exa.ai", "/contents", json_body={"ids": ["a"]}),
        READ,
        write=False,
    ),
    Case(
        "rp-firecrawl",
        request(
            "POST",
            "api.firecrawl.dev",
            "/v1/scrape",
            json_body={"url": "https://example.com", "formats": ["markdown"]},
        ),
        READ,
        write=False,
    ),
    Case(
        "rp-firecrawl-v2-search",
        request("POST", "api.firecrawl.dev", "/v2/search", json_body={"query": "x"}),
        READ,
        write=False,
    ),
    Case(
        "rp-firecrawl-webhook",
        request(
            "POST",
            "api.firecrawl.dev",
            "/v1/crawl",
            json_body={"url": "https://example.com", "webhook": "https://evil.example/x"},
        ),
        UNKNOWN,
    ),
    Case(
        "rp-firecrawl-actions",
        request(
            "POST",
            "api.firecrawl.dev",
            "/v1/scrape",
            json_body={"url": "https://bank.example", "actions": [{"type": "click"}]},
        ),
        UNKNOWN,
    ),
    Case("rp-firecrawl-cancel", request("DELETE", "api.firecrawl.dev", "/v1/crawl/abc"), UNKNOWN),
    Case("rp-tavily-unknown", request("POST", "api.tavily.com", "/keys", json_body={}), UNKNOWN),
    # --- GitHub GraphQL (gh) -------------------------------------------------------------------
    Case(
        "gh-query",
        _gh('query($o: String!) { repository(owner: $o, name: "x") { id } }'),
        READ,
        write=False,
    ),
    Case("gh-shorthand", _gh("{ viewer { login } }"), READ, write=False),
    Case(
        "gh-query-fragment",
        _gh("query Q { viewer { ...F } } fragment F on User { login }"),
        READ,
        write=False,
    ),
    Case(
        "gh-mutation",
        _gh('mutation { addStar(input: {starrableId: "x"}) { clientMutationId } }'),
        UNKNOWN,
    ),
    Case("gh-mutation-delete", _gh("mutation { gone: deleteRepository(input: {}) { x } }"), DELETE),
    Case(
        "gh-mixed",
        _gh("query A { viewer { login } } mutation B { addStar(input: {}) { x } }"),
        UNKNOWN,
    ),
    Case("gh-subscription", _gh("subscription { x }"), UNKNOWN),
    Case(
        "gh-get",
        request("GET", "api.github.com", "/graphql?query=%7Bviewer%7Blogin%7D%7D"),
        UNKNOWN,
    ),
]

HARMLESS = {
    "tg-typing",
    "tg-callback",
    "tg-delete-webhook",
    "gm-label-one",
    "sl-upload-url",
    "sl-open-dm",
    "dc-typing",
    "dc-open-dm",
}
# Drafts pass only in the owner's own accounts (``Context.owner_accounts``): without them they
# are held as changes, since a draft in an attacker's mailbox is data out (docs/32, decision 12).
OWNER_DRAFTS = {
    "gm-draft-create",
    "gm-draft-update",
    "gr-draft",
    "gr-draft-edit",
    "gr-create-reply",
    "gr-attachment-add",
}
IDS = [case.id for case in CATALOGUE]


def test_the_catalogue_has_unique_ids_and_covers_every_translator() -> None:
    assert len(IDS) == len(set(IDS))
    translators = {read(case.view).translator for case in CATALOGUE}
    assert translators == {
        "telegram",
        "gmail",
        "graph_mail",
        "slack",
        "discord",
        "read_post",
        "github_graphql",
    }


@pytest.mark.parametrize("case", CATALOGUE, ids=IDS)
def test_catalogue(case: Case) -> None:
    reading = read(case.view)
    assert reading.effect is case.effect, reading.notes
    if case.recipients is not None:
        assert reading.recipients == case.recipients


@pytest.mark.parametrize(
    "case",
    [c for c in CATALOGUE if c.write and not c.harmless],
    ids=[c.id for c in CATALOGUE if c.write and not c.harmless],
)
def test_no_write_in_the_catalogue_is_ever_a_read(case: Case) -> None:
    reading = read(case.view)
    assert reading.effect is not Effect.READ
    assert reading.risk >= 2


def test_only_the_founders_harmless_writes_pass() -> None:
    passing_writes = {c.id for c in CATALOGUE if c.write and read(c.view).effect is Effect.READ}
    assert passing_writes == HARMLESS
    assert {c.id for c in CATALOGUE if c.harmless} == HARMLESS


def test_with_the_owners_accounts_only_the_drafts_pass_as_well() -> None:
    accounts = frozenset(
        account for c in CATALOGUE if (account := read(c.view).account) is not None
    )
    owner = Context(CTX.key, owner_accounts=accounts)
    passing = {c.id for c in CATALOGUE if c.write and read(c.view, owner).effect is Effect.READ}
    assert passing == HARMLESS | OWNER_DRAFTS


def test_risk_follows_the_effect() -> None:
    for case in CATALOGUE:
        reading = read(case.view)
        expected = {READ: 0, DELETE: 3, ADMIN: 3}.get(reading.effect, 2)
        assert reading.risk == max(expected, 3 if reading.secret_seen else 0), case.id


def test_held_readings_carry_the_wait_of_their_client() -> None:
    waits = {case.id: read(case.view).wait_s for case in CATALOGUE}
    assert waits["tg-send"] == 50
    assert waits["tg-photo"] == 25 and waits["tg-document-get-upper"] == 25
    assert waits["dc-send"] == 10
    assert waits["gm-send"] == 25
    assert waits["sl-post"] == 90 and waits["gr-send"] == 90 and waits["gh-mutation"] == 90


def test_each_translator_answers_in_its_apis_shape() -> None:
    shapes = {read(case.view).translator: read(case.view).shape for case in CATALOGUE}
    assert shapes == {
        "telegram": Shape.TELEGRAM,
        "gmail": Shape.GOOGLE,
        "graph_mail": Shape.GRAPH,
        "slack": Shape.SLACK,
        "discord": Shape.DISCORD,
        "read_post": Shape.PLAIN,
        "github_graphql": Shape.PLAIN,
    }


# --- unknown methods and paths on a translated host are held ------------------------------------

ODD = [
    ("api.telegram.org", "PUT", f"{BOT_PATH}/sendMessage"),
    ("api.telegram.org", "DELETE", f"{BOT_PATH}/getMe"),
    ("api.telegram.org", "get", f"{BOT_PATH}/sendMessage?chat_id=1&text=x"),
    ("api.telegram.org", "POST", f"{BOT_PATH}/sendMessage/extra"),
    ("api.telegram.org", "POST", f"{BOT_PATH}/./sendMessage"),
    ("api.telegram.org", "GET", f"{BOT_PATH}//sendMessage?chat_id=1&text=x"),
    ("api.telegram.org", "GET", f"{BOT_PATH}/send%4Dessage?chat_id=1&text=x"),
    ("api.telegram.org", "POST", "/BOT123:abc/sendMessage"),
    ("api.telegram.org", "POST", f"{BOT_PATH}/test/sendMessage"),
    ("gmail.googleapis.com", "PROPFIND", f"{G}/messages"),
    ("gmail.googleapis.com", "PATCH", f"{G}/messages/1"),
    ("gmail.googleapis.com", "POST", f"{G}/messages/../messages/send"),
    ("gmail.googleapis.com", "GET", f"{G}/messages;x=1"),
    ("www.googleapis.com", "GET", "/gmail/v1/users/me/messages/%2e%2e/send"),
    ("graph.microsoft.com", "POST", f"{M}/sendMail/extra"),
    ("graph.microsoft.com", "MOVE", f"{M}/messages/1"),
    ("graph.microsoft.com", "GET", "/v1.0/users('a')/sendMail"),
    ("slack.com", "PUT", "/api/chat.postMessage"),
    ("slack.com", "GET", "/./api/chat.postMessage?channel=C1&text=x"),
    ("slack.com", "GET", "//api/chat.postMessage?channel=C1&text=x"),
    ("slack.com", "POST", "/api/chat.postMessage/x"),
    ("hooks.slack.com", "PUT", "/services/T1/B1/x"),
    ("hooks.slack.com", "POST", "/workflows/T1/A1/x"),
    ("discord.com", "PROPFIND", f"{D}/channels/1/messages"),
    ("discord.com", "POST", f"{D}/channels/x/messages"),
    ("discord.com", "GET", f"{D}/channels/1/%6Dessages"),
    ("discord.com", "POST", "/api/v10/../v10/channels/1/messages"),
    ("api.tavily.com", "PUT", "/search"),
    ("api.github.com", "PUT", "/graphql"),
]


@pytest.mark.parametrize(("host", "method", "path"), ODD)
def test_unknown_methods_and_paths_on_a_translated_host_are_held(
    host: str, method: str, path: str
) -> None:
    reading = read(request(method, host, path, body=b"{}" if method != "GET" else b""))
    assert reading.effect is Effect.UNKNOWN
    assert reading.risk >= 2


def test_hosts_without_a_translator_are_left_to_the_plain_rules() -> None:
    for host, path in (
        ("example.com", "/api/chat.postMessage"),
        ("api.github.com", "/repos/o/r/issues"),
        ("evil.telegram.org.example", f"{BOT_PATH}/sendMessage"),
    ):
        view = request("POST", host, path, json_body={"chat_id": 1})
        assert translate(view, CTX) is None
        assert not has_translator(view, CTX)
    assert has_translator(tg("getMe"), CTX)


def test_the_host_header_never_picks_a_translator() -> None:
    view = request(
        "POST",
        "example.com",
        f"{BOT_PATH}/getUpdates",
        headers=(("host", "api.telegram.org"),),
        json_body={},
    )
    assert translate(view, CTX) is None
