"""The mail translators (Gmail and Microsoft Graph) in detail: who a mail really goes to (Bcc
included, display names ignored), what is shown (struck and cut), the attachments, IDN, and the
semantic fingerprint's input, which must not change with Date, Message-ID or MIME boundaries
and must change with anything else (docs/32, decision 2)."""

import base64

from backtide.gate.translate import Effect
from backtide.gate.translate.base import LINES_CHARS, SUBJECT_CHARS, Note
from tests.gate_translate_kit import (
    GOOGLE_AUTH,
    GRAPH_AUTH,
    gmail_send,
    mail,
    read,
    request,
    scrubbed,
)

PDF = ("factura.pdf", "application/pdf", b"%PDF-1.7 fake factura")


def test_a_gog_mail_is_read_whole() -> None:
    reading = read(
        gmail_send(
            mail(
                to='"Ana" <Ana@Example.com>, luis@example.com',
                cc="marta@example.com",
                bcc="eva@example.net",
                reply_to="otra@example.org",
                attachments=(PDF,),
            )
        )
    )
    assert reading.translator == "gmail"
    assert reading.effect is Effect.SEND
    assert reading.operation == "messages.send"
    assert reading.recipients == (
        "ana@example.com",
        "luis@example.com",
        "marta@example.com",
        "eva@example.net",
    )
    assert reading.sender == "me@example.org"
    assert reading.reply_to == ("otra@example.org",)
    assert reading.subject == "Factura de octubre"
    assert reading.first_lines == "Hola Ana,\nte paso la factura.\nUn saludo"
    assert [(a.name, a.type, a.size) for a in reading.attachments] == [
        ("factura.pdf", "application/pdf", len(PDF[2]))
    ]
    assert reading.account is not None and len(reading.account) == 16
    assert reading.risk == 2 and reading.wait_s == 25


def test_only_the_address_counts_never_the_display_name() -> None:
    reading = read(gmail_send(mail(to='"ana@example.com" <evil@malo.example>')))
    assert reading.recipients == ("evil@malo.example",)
    reading = read(gmail_send(mail(to='"Tu banco" <x@malo.example>')))
    assert reading.recipients == ("x@malo.example",)


def test_an_international_domain_is_shown_in_punycode_with_a_note() -> None:
    raw = mail(to="placeholder@example.com").replace(
        b"placeholder@example.com", "ana@bücher.example".encode()
    )
    reading = read(gmail_send(raw))
    assert reading.recipients == ("ana@xn--bcher-kva.example",)
    assert Note.IDN_DOMAIN in reading.notes
    punycode = read(gmail_send(mail(to="ana@xn--bcher-kva.example")))
    assert Note.IDN_DOMAIN in punycode.notes


def test_an_html_only_mail_shows_its_text() -> None:
    message = mail(text="placeholder").replace(b"text/plain", b"text/html")
    message = message.replace(b"placeholder", b"<p>Hola <b>Ana</b></p><p>adios</p>")
    reading = read(gmail_send(message))
    assert reading.first_lines is not None
    assert "Hola" in reading.first_lines and "<b>" not in reading.first_lines


def test_shown_texts_are_struck_and_cut() -> None:
    secret = "sk-" + "a" * 40
    reading = read(
        gmail_send(
            mail(
                subject="clave " + secret + " x" * 5000,
                text="linea 1\n\n\nlinea 2\nlinea 3\nlinea 4\n" + "z" * 9000,
            )
        )
    )
    assert reading.subject is not None and len(reading.subject) <= SUBJECT_CHARS
    assert secret not in reading.subject and "[REDACTED]" in reading.subject
    assert reading.first_lines == "linea 1\nlinea 2\nlinea 3"
    assert reading.secret_seen and reading.risk == 3 and Note.SECRET_SEEN in reading.notes
    long_line = read(gmail_send(mail(text="y" * 10_000)))
    assert long_line.first_lines is not None and len(long_line.first_lines) <= LINES_CHARS


def test_a_known_secret_in_the_body_or_an_attachment_is_seen() -> None:
    fake = "fake-gateway-token-1234567890"
    context = scrubbed(fake)
    in_body = read(gmail_send(mail(text="toma: " + fake)), context)
    assert in_body.secret_seen and fake not in (in_body.first_lines or "")
    key = ("id_rsa", "text/plain", b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")
    in_file = read(gmail_send(mail(attachments=(key,))))
    assert in_file.secret_seen and in_file.risk == 3


def test_attachment_names_are_struck_and_cut() -> None:
    name = "ghp_" + "b" * 36 + "-" + "n" * 300 + ".txt"
    reading = read(gmail_send(mail(attachments=((name, "text/plain", b"hola"),))))
    shown = reading.attachments[0].name
    assert len(shown) <= 100 and "ghp_" not in shown
    assert reading.secret_seen


def test_a_mail_with_no_recipient_or_odd_addresses_is_held_as_unknown() -> None:
    for to in (
        "undisclosed-recipients:;",
        "ana",
        "ana@localhost",
        "ana@[10.0.0.1]",
        '"a b"@example.com',
        "ana@example.com,, luis@example.com",
    ):
        reading = read(gmail_send(mail(to=to)))
        assert reading.effect is Effect.UNKNOWN, to


def test_repeated_or_resent_address_headers_are_unknown() -> None:
    twice = mail().replace(b"To: ana@example.com", b"To: ana@example.com\r\nTo: x@evil.example")
    assert read(gmail_send(twice)).effect is Effect.UNKNOWN
    resent = mail().replace(b"To: ana@example.com", b"To: ana@example.com\r\nResent-To: x@e.io")
    assert read(gmail_send(resent)).effect is Effect.UNKNOWN


def test_the_send_body_must_be_exactly_what_gog_sends() -> None:
    raw = base64.urlsafe_b64encode(mail()).decode()
    for body in (
        {"raw": raw, "payload": {}},
        {"Raw": raw, "raw": raw},
        {"threadId": "x"},
        {"raw": raw + "+/"},
        {"raw": 5},
    ):
        view = request(
            "POST",
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/send",
            json_body=body,
            headers=(GOOGLE_AUTH,),
        )
        assert read(view).effect is Effect.UNKNOWN, body


def test_the_account_is_the_token_and_the_mailbox() -> None:
    base = read(gmail_send(mail()))
    other_box = read(gmail_send(mail(), user="ana@example.org"))
    other_token = request(
        "POST",
        "gmail.googleapis.com",
        "/gmail/v1/users/me/messages/send",
        json_body={"raw": base64.urlsafe_b64encode(mail()).decode()},
        headers=(("authorization", "Bearer other"),),
    )
    assert len({base.account, other_box.account, read(other_token).account}) == 3


# --- the semantic fingerprint's input ------------------------------------------------------------


def _canonical(**options: object) -> bytes:
    reading = read(gmail_send(mail(**options)))  # type: ignore[arg-type]
    assert reading.canonical is not None
    return reading.canonical


def test_a_rebuilt_mail_has_the_same_canonical_form() -> None:
    first = _canonical(attachments=(PDF,), boundary="AAAA")
    again = _canonical(
        attachments=(PDF,),
        boundary="BBBB",
        date="Tue, 21 Oct 2026 11:00:00 +0000",
        message_id="<other@example.org>",
    )
    assert first == again


def test_anything_else_changes_the_canonical_form() -> None:
    base = _canonical(attachments=(PDF,))
    for change in (
        {"bcc": "eva@example.net"},
        {"to": "ana@example.com, luis@example.com"},
        {"subject": "Factura de noviembre"},
        {"text": "Hola Ana,\nte paso la factura!"},
        {"attachments": (("factura.pdf", "application/pdf", b"%PDF-1.7 otra"),)},
        {"attachments": (("otra.pdf", "application/pdf", PDF[2]),)},
        {"reply_to": "x@evil.example"},
    ):
        options = {"attachments": (PDF,)} | change
        assert _canonical(**options) != base, change
    thread = read(gmail_send(mail(attachments=(PDF,)), extra={"threadId": "t2"})).canonical
    assert thread != base


def test_the_canonical_form_stays_out_of_summaries_and_reprs() -> None:
    reading = read(gmail_send(mail(text="muy privado")))
    assert reading.canonical is not None
    assert "canonical" not in reading.summary()
    assert "canonical=" not in repr(reading) and "backtide-semantic" not in repr(reading)


# --- Microsoft Graph -----------------------------------------------------------------------------


def _send_mail(message: dict[str, object]) -> object:
    return read(
        request(
            "POST",
            "graph.microsoft.com",
            "/v1.0/me/sendMail",
            json_body={"message": message},
            headers=(GRAPH_AUTH,),
        )
    )


def _to(*addresses: str) -> list[dict[str, object]]:
    return [{"emailAddress": {"address": address, "name": "Nombre"}} for address in addresses]


def test_graph_send_mail_reads_every_recipient_field() -> None:
    reading = _send_mail(
        {
            "subject": "Hola",
            "body": {"contentType": "HTML", "content": "<p>Uno</p><p>Dos</p>"},
            "toRecipients": _to("Ana@Example.com"),
            "ccRecipients": _to("luis@example.com"),
            "bccRecipients": _to("eva@example.net"),
            "replyTo": _to("otra@example.org"),
            "attachments": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "a.txt",
                    "contentType": "text/plain",
                    "contentBytes": base64.b64encode(b"hola").decode(),
                }
            ],
        }
    )
    assert reading.effect is Effect.SEND  # type: ignore[attr-defined]
    assert reading.recipients == ("ana@example.com", "luis@example.com", "eva@example.net")  # type: ignore[attr-defined]
    assert reading.reply_to == ("otra@example.org",)  # type: ignore[attr-defined]
    assert reading.first_lines == "Uno\nDos"  # type: ignore[attr-defined]
    assert [(a.name, a.size) for a in reading.attachments] == [("a.txt", 4)]  # type: ignore[attr-defined]


def test_graph_send_mail_refuses_what_it_does_not_know() -> None:
    for message in (
        {"toRecipients": _to("a@example.com"), "singleValueExtendedProperties": []},
        {"toRecipients": [{"emailAddress": {"address": "a@example.com"}, "x": 1}]},
        {"toRecipients": _to("not-an-address")},
        {"toRecipients": []},
        {"toRecipients": _to("a@example.com"), "attachments": [{"@odata.type": "#x", "name": "a"}]},
        {
            "toRecipients": _to("a@example.com"),
            "attachments": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "a",
                    "contentBytes": "%%",
                }
            ],
        },
    ):
        assert _send_mail(message).effect is Effect.UNKNOWN, message  # type: ignore[attr-defined]


def test_graph_forward_is_a_forward_to_its_recipients() -> None:
    reading = read(
        request(
            "POST",
            "graph.microsoft.com",
            "/v1.0/me/messages/AAMk1/forward",
            json_body={"comment": "mira", "toRecipients": _to("x@example.net")},
            headers=(GRAPH_AUTH,),
        )
    )
    assert reading.effect is Effect.FORWARD
    assert reading.recipients == ("x@example.net",)
    assert reading.target == "message AAMk1"
    assert reading.first_lines == "mira"


def test_folded_headers_and_encoded_subjects_are_read() -> None:
    many = ", ".join(f"persona{n}@example.com" for n in range(12))
    reading = read(gmail_send(mail(to=many, subject="Factura de año nuevo " + "ñ" * 80)))
    assert len(reading.recipients) == 12 and reading.recipients[-1] == "persona11@example.com"
    assert reading.subject is not None and reading.subject.startswith("Factura de año nuevo ñ")
