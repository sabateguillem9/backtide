"""The exact fingerprint of a request (backtide/gate/fingerprint.py, docs/32 section 7).

A "yes" is good for one request only: change one byte of the body, the method, the query, the
Content-Type or the credential, and it is another fingerprint. The same input gives the same
fingerprint; another key gives another one (and nobody without the key can compute it).
"""

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


def test_headers_that_are_not_credentials_or_the_type_do_not_count() -> None:
    """The same message sent by another client version is the same request."""
    other = [("content-type", "application/json"), ("authorization", "Bearer token-one"),
             ("User-Agent", "evil/2.0"), ("Accept", "*/*")]  # fmt: skip
    assert of(headers=other) == of()


def test_the_host_is_compared_as_the_connection_names_it() -> None:
    assert of(host="API.Fake.Test.") == of()


def test_fields_cannot_be_shifted_into_each_other() -> None:
    """Every field is length-prefixed: moving bytes from the path to the body (or the method to
    the host) never collides."""
    assert of(path="/a", body=b"bc") != of(path="/ab", body=b"c")
    assert of(method="GE", host="tapi.fake.test") != of(method="GET", host="api.fake.test")


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
