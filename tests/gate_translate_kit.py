"""Builders for the translators' tests (backtide/gate/translate/): requests in the shape each
client really sends them, and MIME mails as gog builds them. Every token and address is fake."""

import base64
import json
from email.message import EmailMessage
from email.policy import SMTP

from backtide.blackbox.redact import KnownScrubber
from backtide.gate.translate import Context, RequestView, translate
from backtide.gate.translate.base import Reading

KEY = bytes(range(32))
CTX = Context(KEY)
BOT = "123456789:AAH4kZ-fakefakefakefakefakefakefake0"
BOT_PATH = f"/bot{BOT}"
OTHER_BOT = "987654321:AAH4kZ-otherotherotherotherotherot1"
GOOGLE_AUTH = ("authorization", "Bearer ya29.fake-google-access-token")
GRAPH_AUTH = ("authorization", "Bearer eyFAKE.graph.token")
SLACK_AUTH = ("authorization", "Bearer xoxb-0000-fake-slack-bot")
DISCORD_AUTH = ("authorization", "Bot fake.discord.bot.token")
GITHUB_AUTH = ("authorization", "Bearer fake-github-token")
GIT_AUTH = ("authorization", "Basic eC1hY2Nlc3MtdG9rZW46ZmFrZS1naXRodWItdG9rZW4=")
JSON = ("content-type", "application/json")
FORM = ("content-type", "application/x-www-form-urlencoded")


def request(
    method: str,
    host: str,
    path: str,
    *,
    json_body: object = None,
    form: str | None = None,
    body: bytes = b"",
    headers: tuple[tuple[str, str], ...] = (),
    port: int = 443,
    trailers: bool = False,
) -> RequestView:
    pairs = list(headers)
    if json_body is not None:
        body = json.dumps(json_body).encode()
        pairs.append(JSON)
    elif form is not None:
        body = form.encode()
        pairs.append(FORM)
    return RequestView(method, host, port, path, tuple(pairs), body, trailers=trailers)


def multipart(
    fields: list[tuple[str, str | None, str | None, bytes]], boundary: str = "XbacktideX"
) -> tuple[tuple[str, str], bytes]:
    """(the Content-Type header, the body) of a multipart/form-data body."""
    chunks = []
    for name, filename, kind, data in fields:
        disposition = f'form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        head = f"--{boundary}\r\nContent-Disposition: {disposition}\r\n"
        if kind is not None:
            head += f"Content-Type: {kind}\r\n"
        chunks.append(head.encode() + b"\r\n" + data + b"\r\n")
    body = b"".join(chunks) + f"--{boundary}--\r\n".encode()
    return ("content-type", f"multipart/form-data; boundary={boundary}"), body


def mail(
    *,
    to: str = "ana@example.com",
    cc: str | None = None,
    bcc: str | None = None,
    reply_to: str | None = None,
    sender: str = "me@example.org",
    subject: str = "Factura de octubre",
    text: str = "Hola Ana,\nte paso la factura.\nUn saludo\nGuillem",
    html: str | None = None,
    attachments: tuple[tuple[str, str, bytes], ...] = (),
    date: str = "Mon, 20 Oct 2026 10:00:00 +0000",
    message_id: str = "<a1@example.org>",
    boundary: str | None = None,
) -> bytes:
    """A mail as gog builds one (Go's mime writer: From, To, Cc, Bcc, Subject, Date,
    Message-ID, a text part and the attachments)."""
    message = EmailMessage(policy=SMTP)
    message["From"] = sender
    message["To"] = to
    if cc is not None:
        message["Cc"] = cc
    if bcc is not None:
        message["Bcc"] = bcc
    if reply_to is not None:
        message["Reply-To"] = reply_to
    message["Subject"] = subject
    message["Date"] = date
    message["Message-ID"] = message_id
    message.set_content(text)
    if html is not None:
        message.add_alternative(html, subtype="html")
    for name, kind, data in attachments:
        main, _, sub = kind.partition("/")
        message.add_attachment(data, maintype=main, subtype=sub, filename=name)
    if boundary is not None and message.is_multipart():
        message.set_boundary(boundary)
    return message.as_bytes()


def gmail_send(
    raw: bytes, *, extra: dict[str, object] | None = None, user: str = "me"
) -> RequestView:
    payload: dict[str, object] = {"raw": base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    payload.update(extra or {})
    return request(
        "POST",
        "gmail.googleapis.com",
        f"/gmail/v1/users/{user}/messages/send",
        json_body=payload,
        headers=(GOOGLE_AUTH,),
    )


def tg(method: str, params: dict[str, object] | None = None, *, bot: str = BOT) -> RequestView:
    """A Telegram call as grammy makes it: POST with a JSON body."""
    return request("POST", "api.telegram.org", f"/bot{bot}/{method}", json_body=params or {})


def read(view: RequestView, context: Context = CTX) -> Reading:
    reading = translate(view, context)
    assert reading is not None, "no translator took it"
    return reading


def scrubbed(*secrets: str) -> Context:
    return Context(KEY, KnownScrubber(secrets))
