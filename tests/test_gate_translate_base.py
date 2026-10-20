"""The translators' shared pieces (backtide/gate/translate/base.py, shapes.py, read_post.py and
github_graphql.py): the strict readers, the Reading's limits and risk, trusted recipients
(docs/32, section 9), the per-API answers for "pending" and "rejected", the read endpoints and
the GraphQL lexer."""

import json

import pytest

from backtide.gate.translate import Context, Effect, Reading
from backtide.gate.translate.base import (
    Note,
    Shape,
    Trusted,
    Unreadable,
    all_trusted,
    normalize_email,
    normalize_trusted,
    parse_pairs,
    semantic_canonical,
    split_path,
    strict_json,
)
from backtide.gate.translate.github_graphql import operations
from backtide.gate.translate.read_post import check_read_endpoint
from backtide.gate.translate.shapes import REFUSAL_REASONS, RETRY_AFTER_S, pending, refused
from tests.gate_translate_kit import KEY, gmail_send, mail, read, request, tg

# --- strict readers -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "",
        "x",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a/%2e%2e/b",
        "/a;b",
        "/a\\b",
        "/a/b#c",
        "/a b",
        "/a/.hidden",
        "/é",
    ],
)
def test_split_path_refuses_what_a_server_could_read_otherwise(path: str) -> None:
    with pytest.raises(Unreadable):
        split_path(path)


def test_split_path_keeps_plain_paths() -> None:
    assert split_path("/v1.0/me/sendMail?$top=1") == (("v1.0", "me", "sendMail"), "$top=1")
    assert split_path("/intl/en/") == (("intl", "en"), "")
    assert split_path("/") == ((), "")
    assert split_path("/users/@me/channels")[0] == ("users", "@me", "channels")


def test_parse_pairs_refuses_repeats_and_odd_separators() -> None:
    assert parse_pairs("a=1&B=2&c=") == {"a": "1", "b": "2", "c": ""}
    for text in ("a=1&a=2", "a=1&A=2", "a=1;b=2", "a=%ff"):
        with pytest.raises(Unreadable):
            parse_pairs(text)


def test_strict_json_folds_keys_and_refuses_ambiguity() -> None:
    assert strict_json(b'{"Chat_ID": 1}') == {"chat_id": 1}
    for data in (b'{"a":1,"A":2}', b"NaN", b'{"a":Infinity}', b"\xef\xbb\xbf{}", b"{", b"\xff"):
        with pytest.raises(Unreadable):
            strict_json(data)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("Ana@Example.COM", ("ana@example.com", False)),
        ("ana@bücher.example", ("ana@xn--bcher-kva.example", True)),
        ("ana@xn--bcher-kva.example", ("ana@xn--bcher-kva.example", True)),
        ("a.b+tag@example.com", ("a.b+tag@example.com", False)),
        ("ana", None),
        ("ana@localhost", None),
        ("ana@10.0.0.1", None),
        (".a@example.com", None),
        ("a..b@example.com", None),
        ('"a"@example.com', None),
        ("=?utf-8?q?a?=@example.com", None),
        ("ana@exa mple.com", None),
        ("a" * 65 + "@example.com", None),
    ],
)
def test_normalize_email(address: str, expected: tuple[str, bool] | None) -> None:
    assert normalize_email(address) == expected


def test_semantic_canonical_is_deterministic_and_bounded() -> None:
    def canonical(**fields: object) -> bytes:
        return semantic_canonical(
            translator="t",
            host="h",
            port=443,
            operation="o",
            account="a",
            recipients=["r"],
            fields=fields,
        )

    assert canonical(b=1, a="x") == canonical(a="x", b=1)
    long = canonical(text="y" * 1_000_000)
    assert len(long) < 1000 and b"y" * 100 not in long
    assert canonical(text="y" * 1_000_000) != canonical(text="y" * 1_000_001)
    assert canonical(nested={"b": [1, 2], "a": None}) == canonical(nested={"a": None, "b": [1, 2]})


# --- the Reading ----------------------------------------------------------------------------------


def test_a_reading_refuses_texts_over_its_limits() -> None:
    with pytest.raises(ValueError):
        Reading("t", "o", Effect.SEND, Shape.PLAIN, 90, subject="s" * 201)
    with pytest.raises(ValueError):
        Reading("t", "o", Effect.SEND, Shape.PLAIN, 91)
    with pytest.raises(ValueError):
        Reading("t", "o", Effect.SEND, Shape.PLAIN, 90, recipients=("r",) * 65)


def test_a_reading_summary_is_json() -> None:
    reading = read(gmail_send(mail(attachments=(("a.pdf", "application/pdf", b"x"),))))
    summary = reading.summary()
    assert json.loads(json.dumps(summary)) == summary
    assert summary["effect"] == "send" and summary["risk"] == 2
    assert summary["attachments"] == [{"name": "a.pdf", "type": "application/pdf", "size": 1}]


def test_the_context_needs_a_real_key() -> None:
    with pytest.raises(ValueError):
        Context(b"short")
    assert repr(KEY) not in repr(Context(KEY)) and KEY.hex() not in repr(Context(KEY))


# --- trusted recipients (docs/32, section 9) ------------------------------------------------------

OWNER = [normalize_trusted("telegram", "42"), normalize_trusted("gmail", "Ana@Example.com")]


def test_messages_to_the_owner_are_trusted_with_any_bot() -> None:
    assert all_trusted(read(tg("sendMessage", {"chat_id": 42, "text": "hola"})), OWNER)
    assert all_trusted(read(tg("sendMessage", {"chat_id": "+042", "text": "x"})), OWNER)
    assert all_trusted(
        read(tg("editMessageText", {"chat_id": 42, "message_id": 1, "text": "y"})), OWNER
    )
    assert all_trusted(read(tg("deleteMessage", {"chat_id": 42, "message_id": 1})), OWNER)


def test_trust_never_covers_other_recipients_effects_or_secrets() -> None:
    cases = [
        tg("sendMessage", {"chat_id": 43, "text": "x"}),
        tg("forwardMessage", {"chat_id": 42, "from_chat_id": 1, "message_id": 1}),
        tg("sendMessage", {"chat_id": 42, "text": "sk-" + "a" * 40}),
        tg("setWebhook", {"url": "https://x.example"}),
        tg("sendSomethingNew", {"chat_id": 42}),
        tg("editMessageText", {"inline_message_id": "1", "text": "y"}),  # no recipient at all
        gmail_send(mail(to="ana@example.com", bcc="otro@example.net")),
    ]
    for view in cases:
        assert not all_trusted(read(view), OWNER), view.path
    assert all_trusted(read(gmail_send(mail(to='"X" <ANA@example.com>'))), OWNER)
    assert not all_trusted(read(gmail_send(mail(to="a.na@example.com"))), OWNER)


def test_a_trusted_recipient_only_counts_for_its_translator() -> None:
    slack = read(
        request(
            "POST", "slack.com", "/api/chat.postMessage", json_body={"channel": "42", "text": "x"}
        )
    )
    assert not all_trusted(slack, OWNER)
    assert all_trusted(slack, [Trusted("slack", "42")])


def test_normalize_trusted_refuses_entries_that_could_never_match() -> None:
    for translator, recipient in (
        ("gmail", "not an address"),
        ("telegram", "abc"),
        ("whatsapp", "1"),
        ("slack", ""),
    ):
        with pytest.raises(ValueError):
            normalize_trusted(translator, recipient)


# --- per-API answers ------------------------------------------------------------------------------


def _body(answer: object) -> dict[str, object]:
    return json.loads(answer.body)  # type: ignore[attr-defined]


def test_pending_is_a_429_with_retry_after_in_each_apis_shape() -> None:
    for shape in Shape:
        answer = pending(shape, "h-1")
        assert answer.status == 429
        assert ("retry-after", "30") in answer.headers
        assert b"h-1" in answer.body
    telegram = _body(pending(Shape.TELEGRAM, "h-1"))
    assert telegram["ok"] is False and telegram["error_code"] == 429
    assert telegram["parameters"] == {"retry_after": RETRY_AFTER_S}
    assert str(telegram["description"]).startswith("Too Many Requests: retry after 30")
    discord = _body(pending(Shape.DISCORD, "h-1"))
    assert discord["retry_after"] == 30 and discord["global"] is False
    assert _body(pending(Shape.SLACK, "h-1"))["error"] == "ratelimited"
    assert _body(pending(Shape.GOOGLE, "h-1"))["error"]["status"] == "RESOURCE_EXHAUSTED"  # type: ignore[index]
    assert _body(pending(Shape.GRAPH, "h-1"))["error"]["code"] == "TooManyRequests"  # type: ignore[index]
    assert pending(Shape.PLAIN, None).body.startswith(b"backtide: waiting")


def test_refused_is_a_403_that_no_client_repeats() -> None:
    for shape in Shape:
        for reason in REFUSAL_REASONS:
            answer = refused(shape, "h-1", reason)
            assert answer.status == 403
            assert all(name != "retry-after" for name, _ in answer.headers)
    assert _body(refused(Shape.TELEGRAM, "h-1", "rejected"))["error_code"] == 403
    assert _body(refused(Shape.GOOGLE, "h-1", "expired"))["error"]["status"] == "PERMISSION_DENIED"  # type: ignore[index]
    with pytest.raises(ValueError):
        refused(Shape.PLAIN, "h-1", "maybe")


@pytest.mark.parametrize("hold_id", ["", "h 1", "h\n1", "<b>", "x" * 65, "h-1‮"])
def test_a_hold_id_must_be_plain(hold_id: str) -> None:
    with pytest.raises(ValueError):
        pending(Shape.TELEGRAM, hold_id)


# --- read endpoints and GraphQL -------------------------------------------------------------------


def test_read_endpoints_from_the_configuration() -> None:
    assert check_read_endpoint("API.Example.com/V1/Search") == "api.example.com/v1/search"
    for entry in ("https://api.example.com/search", "api.example.com", "x/../y", "a/b?c=1", 5):
        with pytest.raises(ValueError):
            check_read_endpoint(entry)
    context = Context(KEY, read_endpoints=frozenset({check_read_endpoint("api.example.com/q")}))
    passes = read(request("POST", "api.example.com", "/q", json_body={"q": "x"}), context)
    assert passes.effect is Effect.READ
    other = read(request("POST", "api.example.com", "/write", json_body={}), context)
    assert other.effect is Effect.UNKNOWN
    hook = read(request("POST", "api.example.com", "/q", json_body={"webhook": "x"}), context)
    assert hook.effect is Effect.UNKNOWN and Note.REMOTE_ACTIONS in hook.notes


def test_a_search_that_carries_a_secret_is_held_with_risk_3() -> None:
    view = request("POST", "api.tavily.com", "/search", json_body={"query": "ghp_" + "c" * 36})
    reading = read(view)
    assert reading.effect is Effect.UNKNOWN and reading.secret_seen and reading.risk == 3


@pytest.mark.parametrize(
    ("document", "kinds"),
    [
        ("{ a }", ["query"]),
        ('query Q($a: Int = 1) @x { a(b: "}") { c } }', ["query"]),
        ('query { a(b: """ mutation { x } \\""" """) }', ["query"]),
        ("# mutation { x }\nquery { a }", ["query"]),
        ("query mutation { a }", ["query"]),
        ("fragment F on X { a } query { ...F }", ["query"]),
        ("mutation { a }", ["mutation"]),
        ("query { a } , mutation { b }", ["query", "mutation"]),
    ],
)
def test_graphql_operations(document: str, kinds: list[str]) -> None:
    assert operations(document)[0] == kinds


@pytest.mark.parametrize(
    "document",
    [
        '{ a(b: "unterminated) }',
        "{ a ",
        "{ a ) }",
        "type X { a: Int }",
        "query { a(b: 1x) }",
        '{ a(b: "\\q") }',
        '{ a(b: "x\ny") }',
        "{ é }",
        "query ( { a }",
    ],
)
def test_graphql_that_is_not_read_strictly_is_unreadable(document: str) -> None:
    with pytest.raises(Unreadable):
        operations(document)


def test_a_graphql_mutation_that_deletes_is_a_deletion() -> None:
    assert operations("mutation { x: deleteIssue(input: {}) { a } }") == (["mutation"], True)
    assert operations("mutation { addStar(input: {}) { a } }") == (["mutation"], False)
    with pytest.raises(Unreadable):
        operations("mutation { ...F } fragment F on M { deleteRepository { a } }")


def test_graphql_bodies_beyond_a_plain_query_are_held() -> None:
    for body in (
        {"query": "{ a }", "extensions": {}},
        [{"query": "{ a }"}],
        {"query": "{ a }", "operationName": 5},
        {"variables": {}},
    ):
        reading = read(request("POST", "api.github.com", "/graphql", json_body=body))
        assert reading.effect is Effect.UNKNOWN, body
