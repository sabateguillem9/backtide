import copy

import pytest

from backtide.blackbox import REDACTED, redact
from backtide.blackbox.redact import MAX_TEXT_BYTES

LEAKED = "s3cr3tVALUE-0123456789abcdefXYZ"

SPEC_KEYS = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api_key",
    "apikey",
    "api-key",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "private_key",
]


@pytest.mark.parametrize("name", SPEC_KEYS)
def test_secret_dictionary_keys_are_redacted(name: str) -> None:
    assert redact({name: LEAKED}) == {name: REDACTED}


@pytest.mark.parametrize("name", ["Authorization", "X-API-KEY", "Set-Cookie", "PASSWORD"])
def test_secret_keys_match_without_case(name: str) -> None:
    assert redact({name: LEAKED}) == {name: REDACTED}


@pytest.mark.parametrize(
    "name",
    [
        "github_token",
        "DB_PASSWORD",
        "aws_secret_access_key",
        "SECRET_KEY",
        "signing_key",
        "encryption-key",
        "MASTER_KEY",
    ],
)
def test_names_ending_in_a_secret_word_are_redacted_too(name: str) -> None:
    assert redact({name: LEAKED}) == {name: REDACTED}


@pytest.mark.parametrize(
    "name", ["input_tokens", "token_count", "path", "tokenizer", "keyboard", "monkey"]
)
def test_ordinary_keys_are_kept(name: str) -> None:
    assert redact({name: 42}) == {name: 42}


def test_a_secret_key_hides_any_kind_of_value() -> None:
    value = {"password": {"nested": LEAKED}, "token": [LEAKED], "secret": 1234}
    assert redact(value) == {"password": REDACTED, "token": REDACTED, "secret": REDACTED}


def test_redaction_is_recursive_through_dicts_and_lists() -> None:
    value = {"request": {"headers": [{"Cookie": LEAKED}, {"Accept": "text/html"}]}}
    assert redact(value) == {
        "request": {"headers": [{"Cookie": REDACTED}, {"Accept": "text/html"}]}
    }


def test_the_input_is_not_modified() -> None:
    value = {"headers": {"Authorization": LEAKED}, "items": (1, 2)}
    before = copy.deepcopy(value)
    result = redact(value)
    assert value == before
    assert result == {"headers": {"Authorization": REDACTED}, "items": [1, 2]}


@pytest.mark.parametrize("value", [0, 3, 1.5, True, False, None])
def test_scalars_pass_through(value: object) -> None:
    assert redact(value) == value
    assert redact({"n": value}) == {"n": value}


OPENAI_KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0" * 2
ANTHROPIC_KEY = "sk-ant-api03-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3" * 3
GITHUB_PAT = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GITHUB_FINE = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123"
SLACK = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
AWS = "AKIAIOSFODNN7EXAMPLE"
TELEGRAM = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"curl -H 'Authorization: Bearer {LEAKED}' https://api.example.com", LEAKED),
        (f"bearer {LEAKED}", LEAKED),
        (f"OPENAI_KEY is {OPENAI_KEY} ok", OPENAI_KEY),
        (f"key={ANTHROPIC_KEY}", ANTHROPIC_KEY),
        (f"git clone https://{GITHUB_PAT}@github.com/a/b", GITHUB_PAT),
        (f"token {GITHUB_FINE} here", GITHUB_FINE),
        (f"slack {SLACK}", SLACK),
        (f"aws {AWS} creds", AWS),
        (f"https://api.telegram.org/bot{TELEGRAM}/sendMessage", TELEGRAM),
        (f"cookie jwt={JWT}; path=/", JWT),
        (f"key file:\n{PEM}\nend", "b3BlbnNzaC1rZXktdjEAAAAA"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow" + "A" * 100, "MIIEow"),
        (f"https://x.example/cb?code=1&access_token={LEAKED}&state=2", LEAKED),
        (f"https://x.example/?api_key={LEAKED}", LEAKED),
        (f"mysql --password={LEAKED} db", LEAKED),
        (f"export CLIENT_SECRET={LEAKED}", LEAKED),
        (f"https://user:{LEAKED}@db.example.com/x", LEAKED),
        (f"Cookie: session={LEAKED}; theme=dark", LEAKED),
        (f"X-Api-Key: {LEAKED}", LEAKED),
        (f'{{"password": "{LEAKED}", "user": "ana"}}', LEAKED),
        (f"{{'refresh_token': '{LEAKED}'}}", LEAKED),
    ],
)
def test_secret_patterns_inside_any_text_are_redacted(text: str, secret: str) -> None:
    result = redact(text)
    assert secret not in result
    assert REDACTED in result
    assert redact({"note": text})["note"] == result
    assert redact([text]) == [result]


def test_redaction_keeps_the_surrounding_text() -> None:
    url = f"https://x.example/cb?code=1&token={LEAKED}&state=2#top"
    assert redact(url) == f"https://x.example/cb?code=1&token={REDACTED}&state=2#top"
    assert redact(f'{{"password": "{LEAKED}", "user": "ana"}}') == (
        f'{{"password": "{REDACTED}", "user": "ana"}}'
    )


@pytest.mark.parametrize(
    "text",
    [
        "",
        "El agente ha borrado 3 archivos de /workspace/src y ha creado README.md.",
        "The bearer of bad news.",
        "rm -rf /workspace/build && make test",
        "https://example.com/search?q=tokens&page=2",
        '{"model": "claude", "max_tokens": 1024, "input_tokens": 12}',
        "task-1234567890abcdefghijklmnop finished",
        "disk-0123456789abcdefghijklmnop mounted",
        "2026-10-06T12:26:38.774641Z write /w/a.txt",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b",
        "ñandú, acción, 東京, emoji 🙂",
        "basic authentication is configured",
        "Basic Usage of the tool",
        "git push -u origin main",
        "https://example.com/search?keyword=tokens&page=2",
        "the key=value format",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert redact(text) == text


def test_redaction_is_idempotent() -> None:
    text = f"Authorization: Bearer {LEAKED}\n?token={LEAKED} {OPENAI_KEY} {'x' * 6000}"
    once = redact(text)
    assert redact(once) == once


def test_long_texts_are_cut_to_4_kib_with_a_note() -> None:
    text = "a" * 10_000
    result = redact(text)
    assert len(result.encode()) <= MAX_TEXT_BYTES
    head, _, note = result.partition("…")
    assert set(head) == {"a"}
    assert note == f"[truncated {10_000 - len(head)} bytes]"


def test_texts_up_to_the_limit_are_kept_whole() -> None:
    text = "a" * MAX_TEXT_BYTES
    assert redact(text) == text


def test_cutting_never_splits_a_multibyte_character() -> None:
    text = "ñ" * 5000  # 2 bytes each
    result = redact(text)
    assert len(result.encode()) <= MAX_TEXT_BYTES
    head = result.partition("…")[0]
    assert set(head) == {"ñ"}
    assert result.endswith(f"[truncated {10_000 - len(head.encode())} bytes]")


def test_a_secret_beyond_the_cut_is_redacted_before_cutting() -> None:
    text = "a" * (MAX_TEXT_BYTES - 70) + f" token={LEAKED}"
    assert LEAKED not in redact(text)


def test_dictionary_values_and_keys_are_cut() -> None:
    long_key = "k" * 5000
    result = redact({long_key: "v" * 5000})
    [(key, value)] = result.items()
    assert len(key.encode()) <= MAX_TEXT_BYTES
    assert len(value.encode()) <= MAX_TEXT_BYTES


def test_lone_surrogates_become_valid_utf8() -> None:
    path = "/w/bad-\udcff-name"  # an undecodable file name, as os.fsdecode returns it
    result = redact(path)
    result.encode("utf-8")  # must not raise
    assert result == "/w/bad-\\udcff-name"
    assert list(redact({path: path})) == [result]


BASIC = "dXNlcjpodW50ZXIy"  # base64("user:hunter2")
GOOGLE_KEY = "AIza" + ("Sy" + "A1b2C3d4E5" * 4)[:35]
STRIPE_KEY = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0"
GITLAB_TOKEN = "glpat-" + "xY9_zW8-vU7tS6rQ5pO4"


def test_header_pairs_with_a_secret_name_are_redacted() -> None:
    har = {
        "headers": [
            {"name": "Authorization", "value": f"Basic {BASIC}"},
            {"name": "Cookie", "value": f"sessionid={LEAKED}"},
            {"name": "Accept", "value": "text/html"},
        ]
    }
    assert redact(har) == {
        "headers": [
            {"name": "Authorization", "value": REDACTED},
            {"name": "Cookie", "value": REDACTED},
            {"name": "Accept", "value": "text/html"},
        ]
    }


def test_name_value_tuples_with_a_secret_name_are_redacted() -> None:
    headers = [
        ("authorization", f"Basic {BASIC}"),
        ("Set-Cookie", f"a={LEAKED}"),
        ("Set-Cookie", f"b={LEAKED}"),
        ["Accept", "text/html"],
    ]
    assert redact({"headers": headers}) == {
        "headers": [
            ["authorization", REDACTED],
            ["Set-Cookie", REDACTED],
            ["Set-Cookie", REDACTED],
            ["Accept", "text/html"],
        ]
    }


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"Basic {BASIC}", BASIC),
        (f"curl -H 'X-Auth-Token: {LEAKED}' https://api.example.com", LEAKED),
        (f"curl -H 'api-key: {LEAKED}' https://x.openai.azure.com", LEAKED),
        (f"PRIVATE-TOKEN: {GITLAB_TOKEN}", GITLAB_TOKEN),
        (f"https://g.example/v1/models/gemini:generateContent?key={GOOGLE_KEY}", GOOGLE_KEY),
        (f"use {GOOGLE_KEY} later", GOOGLE_KEY),
        (f"STRIPE_SECRET_KEY={STRIPE_KEY}", STRIPE_KEY),
        (f"charge with {STRIPE_KEY} now", STRIPE_KEY),
        (f"push with {GITLAB_TOKEN}", GITLAB_TOKEN),
        (f"mysql --password {LEAKED} db", LEAKED),
        (f"tool --api-key {LEAKED}", LEAKED),
        (f"curl -u admin:{LEAKED} https://x.example", LEAKED),
        (f"curl --user=admin:{LEAKED} https://x.example", LEAKED),
        (f"https://acct.blob.example/c/f?sv=2024&sig={LEAKED}&se=1", LEAKED),
    ],
)
def test_more_credentials_inside_any_text_are_redacted(text: str, secret: str) -> None:
    result = redact(text)
    assert secret not in result
    assert REDACTED in result
    assert redact(result) == result


def test_keys_that_collide_once_redacted_are_all_kept() -> None:
    value = {f"sk-{'a' * 30}": "EVIL exfil payload", f"sk-{'b' * 30}": "benign"}
    result = redact(value)
    assert result == {REDACTED: "EVIL exfil payload", f"{REDACTED}#2": "benign"}
    assert redact(result) == result


def test_keys_that_collide_once_cut_are_all_kept() -> None:
    first, second = "x" * 5000 + "1", "x" * 5000 + "2"
    result = redact({first: "rm -rf /", second: "ls"})
    assert sorted(result.values()) == ["ls", "rm -rf /"]
    assert all(len(key.encode()) <= MAX_TEXT_BYTES for key in result)
