"""The exact fingerprint of a request (backtide/gate/fingerprint.py, docs/32 section 7).

A "yes" is good for one request only: change one byte of the body, the method, the query, any
header but the volatile ones, or a trailer, and it is another fingerprint. The same input gives
the same fingerprint; another key gives another one (and nobody without the key can compute
it).
"""

import gzip
from typing import Any

import pytest

from backtide.gate import fingerprint
from backtide.gate.fingerprint import KEY_BYTES, SHORT, new_key, short
from backtide.gate.fingerprint import fingerprint as fp

KEY = bytes(range(KEY_BYTES))
BASE: dict[str, Any] = {
    "method": "DELETE",
    "host": "api.fake.test",
    "port": 443,
    "path": "/v1/buckets/b1?force=true",
    "headers": [
        ("Content-Type", "application/json"),
        ("Authorization", "Bearer token-one"),
        ("User-Agent", "evil/1.0"),
    ],
    "body": b'{"delete": ["b1", "b1-backup"]}',
}


def of(**changes: Any) -> str:
    return fp(KEY, **(BASE | changes))


def test_the_same_request_gives_the_same_fingerprint() -> None:
    assert of() == of()
    assert len(of()) == 64 and all(c in "0123456789abcdef" for c in of())


@pytest.mark.parametrize(
    "changes",
    [
        {"body": b'{"delete": ["b1", "b1-backuP"]}'},  # one byte of the body
        {"body": BASE["body"] + b" "},
        {"body": b""},
        {"method": "POST"},
        {"method": "delete"},  # the method as it was sent, never normalized
        {"path": "/v1/buckets/b1?force=false"},  # the query
        {"path": "/v1/buckets/b1"},
        {"path": "/v1/buckets/B1?force=true"},
        {"host": "api2.fake.test"},
        {"port": 8443},
        {
            "headers": [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Authorization", "Bearer token-one"),
            ]
        },  # fmt: skip
        {
            "headers": [("Content-Type", "application/json"), ("Authorization", "Bearer token-two")]
        },  # fmt: skip
        {"headers": [("Content-Type", "application/json")]},  # no credential
        {
            "headers": [
                ("Content-Type", "application/json"),
                ("Authorization", "Bearer token-one"),
                ("Cookie", "s=1"),
            ]
        },  # fmt: skip
    ],
)
def test_any_change_that_matters_is_another_fingerprint(changes: dict[str, Any]) -> None:
    assert of(**changes) != of()


def test_volatile_and_hop_by_hop_headers_do_not_count() -> None:
    """The same message sent again (another client version, another trace id, another date) is
    the same request; so is the same body framed another way."""
    other = [("content-type", "application/json"), ("authorization", "Bearer token-one"),
             ("User-Agent", "evil/2.0"), ("Accept-Encoding", "gzip"), ("Date", "today"),
             ("traceparent", "00-abc-def-01"), ("X-Request-Id", "r-2"),
             ("Content-Length", "31"), ("Connection", "keep-alive"), ("TE", "trailers"),
             ("Transfer-Encoding", "chunked"), ("X-Stainless-Retry-Count", "2")]  # fmt: skip
    assert of(headers=other) == of()


# Headers that change what the server does or who it is done as (security review of T10-2, M2).
@pytest.mark.parametrize(
    "extra",
    [
        ("X-HTTP-Method-Override", "DELETE"),
        ("Destination", "https://dav.fake.test/elsewhere"),  # WebDAV MOVE/COPY
        ("Dropbox-API-Arg", '{"path": "/other"}'),
        ("PRIVATE-TOKEN", "glpat-another-account"),  # a credential header: it counts all the same
        ("X-Auth-Token", "another-account"),
        ("Accept", "application/vnd.other+json"),
        ("Overwrite", "T"),
    ],
)
def test_every_other_header_counts(extra: tuple[str, str]) -> None:
    assert of(headers=[*BASE["headers"], extra]) != of()


def test_headers_are_compared_by_name_in_any_order_but_repeats_keep_theirs() -> None:
    shuffled = [("user-agent", "evil/1.0"), ("AUTHORIZATION", "Bearer token-one"),
                ("content-type", "application/json")]  # fmt: skip
    assert of(headers=shuffled) == of()
    one = [*BASE["headers"], ("X-Tag", "a"), ("X-Tag", "b")]
    assert of(headers=one) == of(headers=[("X-Tag", "a"), *BASE["headers"], ("x-tag", "b")])
    assert of(headers=one) != of(headers=[*BASE["headers"], ("X-Tag", "b"), ("X-Tag", "a")])
    assert of(headers=one) != of(headers=[*BASE["headers"], ("X-Tag", "a, b")])


def test_names_and_values_cannot_be_shifted_into_each_other() -> None:
    assert of(headers=[("X-A", "b:c")]) != of(headers=[("X-A:b", "c")])
    assert of(headers=[("X-A", "1"), ("X-B", "2")]) != of(headers=[("X-A", "1X-B2")])


def test_the_trailers_count() -> None:
    assert of(trailers=[("X-Checksum", "1")]) != of()
    assert of(trailers=[("X-Checksum", "1")]) != of(trailers=[("X-Checksum", "2")])
    # A trailer is not the same as the header of the same name.
    assert of(trailers=[("X-A", "1")]) != of(headers=[*BASE["headers"], ("X-A", "1")])


def test_the_host_is_compared_as_the_connection_names_it() -> None:
    assert of(host="API.Fake.Test.") == of()


def test_fields_cannot_be_shifted_into_each_other() -> None:
    """Every field is length-prefixed: moving bytes from the path to the body (or the method to
    the host) never collides."""
    assert of(path="/a", body=b"bc") != of(path="/ab", body=b"c")
    assert of(method="GE", host="tapi.fake.test") != of(method="GET", host="api.fake.test")


def test_the_bytes_of_an_encoded_body_count_as_they_go_out() -> None:
    """The same decoded body can be compressed many ways; an approval is for the bytes that
    leave, so a retry with other compressed bytes is another request (code review G1)."""
    plain = of(encoded=gzip.compress(BASE["body"], mtime=0))
    assert plain == of(encoded=gzip.compress(BASE["body"], mtime=0))
    assert plain != of()  # with and without an encoding
    assert plain != of(encoded=gzip.compress(BASE["body"], mtime=1))
    assert plain != of(encoded=gzip.compress(BASE["body"], compresslevel=1, mtime=0))
    canonical = {"canonical": b"semantic"}
    assert of(**canonical, encoded=b"a") != of(**canonical, encoded=b"b")


def test_another_key_is_another_fingerprint() -> None:
    assert fp(bytes(KEY_BYTES), **BASE) != of()
    assert new_key() != new_key() and len(new_key()) == KEY_BYTES


def test_a_key_of_the_wrong_size_is_refused() -> None:
    with pytest.raises(ValueError):
        fp(b"short", **BASE)


def test_canonical_bytes_replace_the_body_and_never_equal_the_exact_one() -> None:
    """The hook for the translators (T10-3): a semantic fingerprint hashes what the translator
    understood instead of the raw body, and is never the same as an exact one."""
    semantic = of(canonical=b"to=ana@example.com\nsubject=hi")
    assert semantic == of(body=b"another MIME with another Date", canonical=b"to=ana@example.com"
                          b"\nsubject=hi")  # fmt: skip
    assert semantic != of(canonical=b"to=bob@example.com\nsubject=hi")
    assert of(body=b"to=ana@example.com\nsubject=hi") != semantic


def test_the_short_form_is_what_the_black_box_keeps() -> None:
    assert short(of()) == of()[:SHORT] and SHORT == 16
    with pytest.raises(ValueError):
        short("not a fingerprint")


def test_it_imports_only_the_standard_library() -> None:
    """It runs in the proxy (docs/21: only the standard library, mitmproxy and backtide.gate)."""
    source = open(fingerprint.__file__, encoding="utf-8").read()  # noqa: SIM115, PTH123
    imports = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    assert all(
        line.split()[1].split(".")[0] in {"hashlib", "hmac", "secrets", "collections", "backtide"}
        for line in imports
    ), imports
