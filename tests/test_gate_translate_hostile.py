"""Hostile input against the translators: huge bodies, deep or wide JSON, many recipients, bad
MIME, bad encodings, override headers, and a translator that fails. Each one must be held
(``Effect.UNKNOWN``), never let through and never raise, and in bounded time (docs/32,
section 8: "puro y de coste acotado")."""

import base64
import json
import time

import pytest

from backtide.gate import translate as translate_package
from backtide.gate.translate import Effect, RequestView, translate
from backtide.gate.translate.base import MAX_BODY, MAX_MIME, Note
from tests.gate_translate_kit import (
    BOT_PATH,
    CTX,
    DISCORD_AUTH,
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

# One write endpoint per translator, to throw bodies at.
TARGETS = [
    ("api.telegram.org", f"{BOT_PATH}/sendMessage", ()),
    ("gmail.googleapis.com", "/gmail/v1/users/me/messages/send", (GOOGLE_AUTH,)),
    ("graph.microsoft.com", "/v1.0/me/sendMail", (GRAPH_AUTH,)),
    ("slack.com", "/api/chat.postMessage", (SLACK_AUTH,)),
    ("discord.com", "/api/v10/channels/1/messages", (DISCORD_AUTH,)),
    ("api.tavily.com", "/search", ()),
    ("api.github.com", "/graphql", ()),
]
TARGET_IDS = [host for host, _path, _headers in TARGETS]
JSON = ("content-type", "application/json")


def _held(view: RequestView, seconds: float = 3.0) -> None:
    start = time.monotonic()
    reading = translate(view, CTX)
    elapsed = time.monotonic() - start
    assert reading is not None
    assert reading.effect is Effect.UNKNOWN, reading
    assert reading.risk >= 2
    assert elapsed < seconds, f"took {elapsed:.2f} s"


HOSTILE_BODIES = {
    "huge": b"{" + b'"a":"' + b"x" * (MAX_BODY + 1) + b'"}',
    "deep_lists": b"[" * 200_000 + b"]" * 200_000,
    "deep_objects": b'{"a":' * 50_000 + b"1" + b"}" * 50_000,
    "wide": b"[" + b"0," * 1_100_000 + b"0]",
    "invalid_utf8": b'{"chat_id":1,"text":"\xff\xfe"}',
    "nan": b'{"chat_id":1,"text":NaN}',
    "bom": b'\xef\xbb\xbf{"chat_id":1,"text":"x"}',
    "duplicate": b'{"chat_id":1,"chat_id":2,"text":"x"}',
    "duplicate_folded": b'{"text":"x","TEXT":"y","chat_id":1}',
    "not_an_object": b'["chat_id",1]',
    "truncated": b'{"chat_id":1,"text":"x',
}


@pytest.mark.parametrize(("host", "path", "headers"), TARGETS, ids=TARGET_IDS)
@pytest.mark.parametrize("name", list(HOSTILE_BODIES))
def test_hostile_json_is_held_quickly(
    host: str, path: str, headers: tuple[tuple[str, str], ...], name: str
) -> None:
    _held(request("POST", host, path, body=HOSTILE_BODIES[name], headers=(*headers, JSON)))


def test_a_search_body_that_is_not_an_object_is_held() -> None:
    for body in (b"[1]", b"[" * 100_000, b"\xff"):
        _held(request("POST", "api.tavily.com", "/search", body=body, headers=(JSON,)))


@pytest.mark.parametrize(("host", "path", "headers"), TARGETS, ids=TARGET_IDS)
def test_common_refusals_hold_on_every_translated_host(
    host: str, path: str, headers: tuple[tuple[str, str], ...]
) -> None:
    body = json.dumps({"chat_id": 1, "text": "x"}).encode()
    for extra, kwargs in (
        ((("x-http-method-override", "GET"),), {}),
        ((("X-Original-URL", "/getMe"),), {}),
        ((("content-encoding", "gzip"),), {}),
        ((("content-type", "text/plain"),), {}),  # two Content-Type headers
        ((), {"trailers": True}),
    ):
        view = request("POST", host, path, body=body, headers=(*headers, JSON, *extra), **kwargs)
        reading = translate(view, CTX)
        assert reading is not None and reading.effect is Effect.UNKNOWN, (host, extra)
    huge = request("POST", host, path, body=b" " * (MAX_BODY + 1), headers=(*headers, JSON))
    reading = translate(huge, CTX)
    assert reading is not None and Note.TOO_LARGE in reading.notes


def test_an_override_header_turns_even_a_read_into_held() -> None:
    view = request(
        "GET",
        "api.telegram.org",
        f"{BOT_PATH}/getMe",
        headers=(("X-HTTP-Method-Override", "POST"),),
    )
    _held(view)


def test_many_recipients_are_held() -> None:
    many = ", ".join(f"p{n}@example.com" for n in range(65))
    reading = read(gmail_send(mail(to=many)))
    assert reading.effect is Effect.UNKNOWN and Note.TOO_MANY_RECIPIENTS in reading.notes
    split = read(
        gmail_send(
            mail(
                to=", ".join(f"p{n}@example.com" for n in range(40)),
                bcc=", ".join(f"q{n}@example.com" for n in range(40)),
            )
        )
    )
    assert split.effect is Effect.UNKNOWN
    graph = request(
        "POST",
        "graph.microsoft.com",
        "/v1.0/me/sendMail",
        headers=(GRAPH_AUTH,),
        json_body={
            "message": {
                "toRecipients": [
                    {"emailAddress": {"address": f"p{n}@example.com"}} for n in range(65)
                ]
            }
        },
    )
    assert read(graph).effect is Effect.UNKNOWN
    slack = request(
        "POST",
        "slack.com",
        "/api/files.completeUploadExternal",
        headers=(SLACK_AUTH,),
        json_body={"channels": ",".join(f"C{n}" for n in range(65)), "files": []},
    )
    assert read(slack).effect is Effect.UNKNOWN


def test_many_attachments_are_held() -> None:
    files = tuple((f"f{n}.txt", "text/plain", b"x") for n in range(33))
    assert read(gmail_send(mail(attachments=files))).effect is Effect.UNKNOWN
    fields = [("chat_id", None, None, b"1")] + [
        (f"f{n}", f"f{n}.bin", "application/octet-stream", b"\x00") for n in range(33)
    ]
    header, body = multipart(fields)
    view = request(
        "POST", "api.telegram.org", f"{BOT_PATH}/sendDocument", body=body, headers=(header,)
    )
    assert read(view).effect is Effect.UNKNOWN


@pytest.mark.parametrize(
    "raw",
    [
        b"\x00\xff garbage that is not a mail",
        b"To: ana@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\nno parts",
        b"To: ana@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n"
        b"Content-Type: text/plain\r\n\r\nnever closed",
        b"To: =?utf-8?b?YW5h?=@example.com\r\n\r\nx",
        b"To: ana@example.com\r\nContent-Type: text/plain; charset=nonexistent-9\r\n\r\nx",
        b"To: ana\x01@example.com\r\n\r\nx",
        b"To: ana@ex\xff\xfeample.com\r\n\r\nx",
        b"To: ana@example.com\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n"
        + b"".join(
            b"--a\r\nContent-Type: multipart/mixed; boundary=a%d\r\n\r\n" % n for n in range(40)
        ),
    ],
    ids=[
        "garbage",
        "no-parts",
        "unclosed",
        "encoded-address",
        "unknown-charset",
        "control",
        "bad-utf8",
        "nested",
    ],
)
def test_bad_mime_is_held(raw: bytes) -> None:
    _held(gmail_send(raw))


def test_a_mime_mail_over_the_cap_is_held() -> None:
    raw = mail(text="x" * (MAX_MIME + 10))
    _held(gmail_send(raw))
    upload = request(
        "POST",
        "gmail.googleapis.com",
        "/upload/gmail/v1/users/me/messages/send?uploadType=media",
        body=raw,
        headers=(GOOGLE_AUTH, ("content-type", "message/rfc822")),
    )
    _held(upload)


def test_bad_encodings_in_queries_and_forms_are_held() -> None:
    _held(request("GET", "api.telegram.org", f"{BOT_PATH}/sendMessage?chat_id=1&text=%ff%fe"))
    _held(request("GET", "api.telegram.org", f"{BOT_PATH}/sendMessage?chat_id=1;text=x"))
    _held(request("POST", "api.telegram.org", f"{BOT_PATH}/sendMessage", form="chat_id=1&text=%C3"))
    many = "&".join(f"p{n}=1" for n in range(300))
    _held(request("GET", "api.telegram.org", f"{BOT_PATH}/sendMessage?chat_id=1&{many}"))


def test_raw_that_is_not_base64url_is_held() -> None:
    for raw in ("ab+/", "a b", "====", "é", "YQ===="):
        view = request(
            "POST",
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/send",
            json_body={"raw": raw},
            headers=(GOOGLE_AUTH,),
        )
        _held(view)


def test_a_huge_graphql_document_is_held() -> None:
    body = {"query": "{" + " a" * 200_000 + "}"}
    _held(request("POST", "api.github.com", "/graphql", json_body=body))


def test_a_translator_that_fails_is_held_and_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(view: RequestView, context: object) -> None:
        raise RuntimeError("secret detail never logged")

    entries = tuple(
        entry._replace(read=broken) if entry.name == "telegram" else entry
        for entry in translate_package._TRANSLATORS
    )
    monkeypatch.setattr(translate_package, "_TRANSLATORS", entries)
    reading = translate(tg("getMe"), CTX)
    assert reading is not None and reading.effect is Effect.UNKNOWN
    assert Note.TRANSLATOR_FAILED in reading.notes
    assert "RuntimeError" in caplog.text and "secret detail" not in caplog.text


def test_long_names_and_texts_never_break_the_limits() -> None:
    header, body = multipart(
        [
            ("chat_id", None, None, b"1"),
            ("caption", None, None, ("‮" * 5000).encode()),
            ("photo", "n" * 5000 + ".jpg", "image/jpeg", b"x"),
        ]
    )
    reading = read(
        request("POST", "api.telegram.org", f"{BOT_PATH}/sendPhoto", body=body, headers=(header,))
    )
    assert reading.effect is Effect.SEND
    assert len(reading.attachments[0].name) <= 100
    assert reading.first_lines is not None and len(reading.first_lines) <= 300
    raw = base64.urlsafe_b64encode(mail(subject="s" * 50_000)).decode()
    assert len(raw) > 50_000
    assert read(gmail_send(mail(subject="s" * 50_000))).subject is not None
