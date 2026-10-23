import copy
from urllib.parse import quote, quote_plus

import pytest

from backtide.blackbox import REDACTED, redact
from backtide.blackbox.redact import MAX_TEXT_BYTES, KnownScrubber, scrub_known
from tests.scaling import assert_linear, best_time

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


# --- credentials in a URL path (Discord and Slack webhooks) -------------------------------------

# Test values with the real shapes: a Discord webhook token is 68 characters, an interaction
# token is longer, a Slack webhook secret is 24 letters and digits.
DISCORD_TOKEN = ("Dq7-Kz_" + "a1B2c3D4e5F6g7H8i9J0" * 4)[:68]
INTERACTION_TOKEN = "aW50ZXJhY3Rpb246" + "Mk9pQ2xVbXpYRjR0N2c" * 8
SLACK_HOOK = "Xy7Bq2Lm9Pw4Rt6Zk3Nc8Vd1"
SLACK_TRIGGER = "0f3a" + "9c2e7b1d" * 3 + "5a6b"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"https://discord.com/api/webhooks/1234567890123456789/{DISCORD_TOKEN}", DISCORD_TOKEN),
        (f"/api/v10/webhooks/1234567890123456789/{DISCORD_TOKEN}?wait=true", DISCORD_TOKEN),
        (f"https://discordapp.com/api/webhooks/42/{DISCORD_TOKEN}/slack", DISCORD_TOKEN),
        (f"/api/webhooks/42/{DISCORD_TOKEN}/github?thread_id=9", DISCORD_TOKEN),
        (f"/api/v9/webhooks/42/{DISCORD_TOKEN}/messages/1122334455", DISCORD_TOKEN),
        (f"/api/v10/interactions/42/{INTERACTION_TOKEN}/callback", INTERACTION_TOKEN),
        (f"/api/v10/webhooks/42/{INTERACTION_TOKEN}/messages/@original", INTERACTION_TOKEN),
        (f"curl -X POST https://discord.com/api/webhooks/42/{DISCORD_TOKEN} -d x", DISCORD_TOKEN),
        (f'{{"url": "https:\\/\\/discord.com\\/api\\/webhooks\\/42\\/{DISCORD_TOKEN}"}}',
         DISCORD_TOKEN),
        (f"https://hooks.slack.com/services/T0123ABCD/B0456EFGH/{SLACK_HOOK}", SLACK_HOOK),
        (f"https://hooks.slack.com/workflows/T0123ABCD/A0456EFGH/1234567890/{SLACK_HOOK}",
         SLACK_HOOK),
        (f"https://hooks.slack.com/triggers/T0123ABCD/1234567890123/{SLACK_TRIGGER}",
         SLACK_TRIGGER),
        (f"https://hooks.slack.com/triggers/E0123ABCD/1234567890123/{SLACK_TRIGGER}",
         SLACK_TRIGGER),
        (f"SLACK_URL=https://hooks.slack.com/services/T0123ABCD/B0456EFGH/{SLACK_HOOK} ./run",
         SLACK_HOOK),
    ],
)  # fmt: skip
def test_credentials_in_a_url_path_are_struck(text: str, secret: str) -> None:
    result = redact(text)
    assert secret not in result
    assert REDACTED in result
    assert redact(result) == result


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        # Doubled, encoded or backslashed slashes, and any letter case.
        (f"//api//webhooks//42//{DISCORD_TOKEN}", DISCORD_TOKEN),
        (f"/api%2Fwebhooks%2f42%2F{DISCORD_TOKEN}", DISCORD_TOKEN),
        (f"/api\\webhooks\\42\\{DISCORD_TOKEN}", DISCORD_TOKEN),
        (f"/API/V10/WEBHOOKS/42/{DISCORD_TOKEN}", DISCORD_TOKEN),
        (f"/api/Interactions/42/{INTERACTION_TOKEN}/CALLBACK", INTERACTION_TOKEN),
        (f"/api/webhooks/%34%32/{DISCORD_TOKEN}", DISCORD_TOKEN),  # an escaped id
        (f"/api/webhooks/42/{DISCORD_TOKEN}/slack", DISCORD_TOKEN),
        (f"//services//T0123ABCD//B0456EFGH//{SLACK_HOOK}", SLACK_HOOK),
        (f"/services%2FT0123ABCD%2fB0456EFGH%2F{SLACK_HOOK}", SLACK_HOOK),
        (f"/SERVICES/t0123abcd/b0456efgh/{SLACK_HOOK}", SLACK_HOOK),
        (f"/services/T0123ABCD/B0456EFGH/{SLACK_HOOK.lower()}", SLACK_HOOK.lower()),
        (f"/services/T0123ABCD/{SLACK_HOOK}", SLACK_HOOK),  # no B…: the rest goes anyway
        (f"/services/T0123ABCD/B0456EFGH/x/{SLACK_HOOK}", SLACK_HOOK),
    ],
)
def test_path_credentials_are_struck_in_hostile_spellings(text: str, secret: str) -> None:
    result = redact(text)
    assert secret not in result
    assert secret.lower() not in result.lower()
    assert redact(result) == result


def test_a_path_credential_loses_only_its_token_and_the_ids_stay() -> None:
    assert redact(f"/api/v10/webhooks/1234567890123456789/{DISCORD_TOKEN}/messages/77?wait=1") == (
        f"/api/v10/webhooks/1234567890123456789/{REDACTED}/messages/77?wait=1"
    )
    assert redact(f"/api/v10/interactions/42/{INTERACTION_TOKEN}/callback") == (
        f"/api/v10/interactions/42/{REDACTED}/callback"
    )
    assert redact(f"/services/T0123ABCD/B0456EFGH/{SLACK_HOOK}?x=1") == (
        f"/services/T0123ABCD/B0456EFGH/{REDACTED}?x=1"
    )
    # Workflows and triggers vary in shape: everything after the team goes.
    assert redact(f"/triggers/T0123ABCD/1234567890123/{SLACK_TRIGGER}") == (
        f"/triggers/T0123ABCD/{REDACTED}"
    )


@pytest.mark.parametrize(
    "text",
    [
        "/repos/ana/app/hooks/12345/deliveries",
        "/api/v1/webhooks/123/deliveries",
        "/api/v10/webhooks/1234567890123456789",  # the webhook itself, with the bot's token
        "/api/v10/interactions/42/short/callback",
        "/services/translate/v2?q=hola",
        "/api/v1/namespaces/default/services/my-service/proxy",
        "/services/T0123ABCD/B0456EFGH/short",
        "https://hooks.slack.com/services/",
    ],
)
def test_paths_that_only_look_like_a_webhook_are_left_alone(text: str) -> None:
    assert redact(text) == text


# --- scrub_known: the secrets backtide knows, wherever they show up -----------------------------

KNOWN = "kn0wnS3cret-" + "Q7w8E9r0T1y2U3i4O5p6"
FAKE = "backtide-fake-anthropic-" + "a" * 32
SPECIAL = "sp3c/al+key=" + "Zz9Yy8Xx7Ww6Vv5Uu4"  # characters that URL encoding changes


@pytest.mark.parametrize(
    "text",
    [
        KNOWN,
        f"prefix {KNOWN} suffix",
        f"https://x.example/a?q={KNOWN}&page=2",
        f"/bot{KNOWN}/sendMessage",
        f"{KNOWN}{KNOWN}",
        f'{{"note": "{KNOWN}"}}',
    ],
)
def test_scrub_known_strikes_each_exact_appearance(text: str) -> None:
    result = scrub_known(text, [KNOWN])
    assert KNOWN not in result
    assert result == text.replace(KNOWN, REDACTED)


@pytest.mark.parametrize(
    "encoded",
    [
        quote(SPECIAL, safe=""),
        quote(SPECIAL, safe="").replace("%2F", "%2f").replace("%2B", "%2b"),  # lower-case hex
        quote(SPECIAL),
        quote_plus(SPECIAL),
    ],
)
def test_scrub_known_strikes_url_encoded_forms(encoded: str) -> None:
    result = scrub_known(f"https://x.example/?v={encoded}&page=2", [SPECIAL])
    assert result == f"https://x.example/?v={REDACTED}&page=2"


@pytest.mark.parametrize(
    "text",
    [
        "x=" + KNOWN[:5] + "%53" + KNOWN[6:],  # partly encoded ("S")
        "x=" + "".join(f"%{ord(c):02X}" for c in KNOWN),  # every character encoded
        "x=" + "".join(f"%{ord(c):02x}" for c in KNOWN),
        "x=" + KNOWN[:5] + "%2553" + KNOWN[6:],  # encoded twice
        '{"v": "' + "".join(f"\\u{ord(c):04x}" for c in KNOWN) + '"}',  # JSON escapes
        "&#" + str(ord(KNOWN[0])) + ";" + KNOWN[1:],  # an HTML entity
    ],
)
def test_scrub_known_strikes_a_whole_text_where_a_decoded_form_shows_a_secret(text: str) -> None:
    assert scrub_known(text, [KNOWN]) == REDACTED


def test_scrub_known_is_recursive_and_strikes_keys_too() -> None:
    value = {
        "a": [KNOWN, ("x", f"y{FAKE}")],
        KNOWN: 1,
        f"k-{FAKE}": {"n": 3, "deep": {"v": quote(KNOWN, safe="")}},
        "other": None,
    }
    assert scrub_known(value, [KNOWN, FAKE]) == {
        "a": [REDACTED, ["x", f"y{REDACTED}"]],
        REDACTED: 1,
        f"k-{REDACTED}": {"n": 3, "deep": {"v": REDACTED}},
        "other": None,
    }


def test_scrub_known_keeps_keys_that_collide_once_struck() -> None:
    result = scrub_known({KNOWN: "a", REDACTED: "b"}, [KNOWN])
    assert sorted(result.values()) == ["a", "b"]
    assert len(result) == 2


def test_scrub_known_leaves_other_texts_and_the_input_alone() -> None:
    value = {"text": "nothing secret here", "items": (1, 2.5, True)}
    before = copy.deepcopy(value)
    assert scrub_known(value, [KNOWN]) == {"text": "nothing secret here", "items": [1, 2.5, True]}
    assert value == before
    assert scrub_known("anything", []) == "anything"


def test_scrub_known_strikes_the_longer_secret_first() -> None:
    longer = KNOWN + "-and-more"
    assert scrub_known(f"a {longer} b", [KNOWN, longer]) == f"a {REDACTED} b"


def test_scrub_known_before_redact_leaves_no_piece_of_a_secret_at_the_cut() -> None:
    text = "a" * (MAX_TEXT_BYTES - 80) + KNOWN + "b" * 200
    assert KNOWN[:10] not in redact(scrub_known(text, [KNOWN]))


def test_scrub_known_is_idempotent() -> None:
    once = scrub_known(f"{KNOWN} and {quote(SPECIAL, safe='')}", [KNOWN, SPECIAL])
    assert scrub_known(once, [KNOWN, SPECIAL]) == once


@pytest.mark.parametrize("secret", ["", "short", "1234567", None, b"bytes-secret-123"])
def test_scrub_known_refuses_secrets_it_cannot_strike_safely(secret: object) -> None:
    with pytest.raises(ValueError):
        scrub_known("text", [secret])  # type: ignore[list-item]


@pytest.mark.parametrize("kept", [4, 10, len(KNOWN) - 1])
def test_scrub_known_with_cut_tails_strikes_the_start_of_a_secret_at_the_end(kept: int) -> None:
    # The proxy cut a field it could not strike: what is left of the secret ends the text.
    text = "user-agent padding " + KNOWN[:kept]
    assert scrub_known(text, [KNOWN], cut_tails=True) == "user-agent padding " + REDACTED
    assert scrub_known({"ua": [text]}, [KNOWN], cut_tails=True) == {
        "ua": ["user-agent padding " + REDACTED]
    }
    assert scrub_known(text, [KNOWN]) == text  # off by default


def test_cut_tails_leaves_short_or_unrelated_ends_alone() -> None:
    assert scrub_known("text " + KNOWN[:3], [KNOWN], cut_tails=True) == "text " + KNOWN[:3]
    assert scrub_known(KNOWN[:10] + " end", [KNOWN], cut_tails=True) == KNOWN[:10] + " end"


def test_a_known_scrubber_is_reusable_and_never_shows_its_secrets() -> None:
    scrubber = KnownScrubber([KNOWN, FAKE])
    assert scrubber(f"a {KNOWN}") == f"a {REDACTED}"
    assert scrubber({"k": FAKE}) == {"k": REDACTED}
    assert KNOWN not in repr(scrubber) and FAKE not in repr(scrubber)
    with pytest.raises(TypeError):
        copy.deepcopy(scrubber)


# --- T07 third-pass H1: no redaction pattern is quadratic on hostile text -------------------

import importlib as _importlib  # noqa: E402

# The package exposes a ``redact`` function, which shadows the submodule by that name.
_redact_mod = _importlib.import_module("backtide.blackbox.redact")


@pytest.mark.parametrize(
    "unit",
    [
        "a.",
        "a-",
        "-x ",
        "eyJ-",
        "token ",
        "basic ",
        "Bearer ",
        "-----BEGIN A",
        "a\n",
        "x://",
        '-u "a:',
        "-u 'a:",
        '"--user=a:',
        "eyJa.eyJa",
        "webhooks/1/",
        "webhooks/1/a",
        "%2f",
        "services/T1/",
        "services/T1/B1/a",
        "triggers/E1/a/",
        "4",
        "4 ",
        "4-",
        "4+",
        "4%20",
        "4.",
        "card_",
        "card[",
        "card%5b",
        "card[]",
        '"cvc',
        '"card_',
        '"cvc": ',
        "'pin':",
        "pin=",
        "--pin",
        "x-",
    ],  # fmt: skip
)
def test_each_pattern_is_fast_on_70_kib_of_hostile_text(unit: str) -> None:
    """0.05 s for one search, about four times what the slowest takes on the Mac. Over it,
    the best of three more: one pause of the machine (another test's thread, the GC) during
    one of the ~1200 searches is not a slow pattern; a backtracking one is slow every time."""
    hostile = (unit * (70 * 1024 // len(unit)))[: 70 * 1024]
    for pattern in (*_redact_mod._TEXT_PATTERNS, _redact_mod._CARD_NUMBER_RE):
        elapsed = best_time(lambda pattern=pattern: pattern.search(hostile))
        if elapsed >= 0.05:
            elapsed = best_time(lambda pattern=pattern: pattern.search(hostile), 3)
        assert elapsed < 0.05, f"{pattern.pattern[:40]!r} took {elapsed:.3f}s on {unit!r}"


def test_redact_a_half_mib_text_is_quick() -> None:
    def hostile(size: int) -> str:
        return ("https://a.a.a.a" * (size // 14 + 1))[:size]

    small, large = hostile(64 * 1024), hostile(512 * 1024)
    assert_linear(redact, small, large, 8, floor=0.01, cap=2.0, label="redact")


def test_a_jwt_with_a_payload_over_4_kib_is_struck() -> None:
    """T07-5: the payload was capped at 4096 characters, so a bigger one was not a JWT at all
    and its head stayed in the (cut) text."""
    payload = "eyJ" + ("Ab3dE6gH9" * 600)  # 5,403 characters
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.Qx7vR2mK9pLt4ZwB8nHc"
    struck = redact(f"token {token} done")
    assert "Ab3dE6gH9Ab3dE6gH9" not in struck and "Qx7vR2mK9pLt4ZwB8nHc" not in struck
    assert struck.endswith("done")
    unsigned = redact(f"x eyJhbGciOiJub25lIn0.{payload}. y")  # alg none: an empty signature
    assert "Ab3dE6gH9Ab3dE6gH9" not in unsigned


# --- Payment cards (T21, docs/36 decision 11): numbers by Luhn, CVV and PIN by name -----------

# Published test numbers of the card networks (all Luhn-valid), of 13 to 19 digits.
CARDS = [
    "4242424242424242",  # Visa
    "4111111111111111",
    "4222222222222",  # Visa, 13 digits
    "5555555555554444",  # Mastercard
    "2223003122003222",  # Mastercard, 2-series
    "378282246310005",  # American Express, 15 digits
    "36227206271667",  # Diners, 14 digits
    "6011111111111117",  # Discover
    "3530111333300000",  # JCB
    "6200000000000005",  # UnionPay
    "6011000990139420007",  # 19 digits
]


def _spaced(number: str, sep: str) -> str:
    return sep.join(number[i : i + 4] for i in range(0, len(number), 4))


@pytest.mark.parametrize("number", CARDS)
def test_a_luhn_valid_card_number_is_struck_in_any_text(number: str) -> None:
    assert redact(f"paid with {number} today") == f"paid with {REDACTED} today"
    assert redact(number) == REDACTED


@pytest.mark.parametrize("sep", [" ", "-", "+", "%20"])
def test_a_card_number_is_struck_with_its_usual_separators(sep: str) -> None:
    text = f"card {_spaced('4242424242424242', sep)} exp 12/30"
    assert redact(text) == f"card {REDACTED} exp 12/30"
    amex = "3782 822463 10005".replace(" ", sep)  # Amex groups 4-6-5
    assert redact(f"[{amex}]") == f"[{REDACTED}]"


@pytest.mark.parametrize(
    "text",
    [
        "4242424242424241",  # one digit off: not Luhn-valid
        "4111 1111 1111 1112",
        "order 5555555555554445 shipped",
        "1729600000000 ms",  # a timestamp in milliseconds (13 digits)
        "1729600000000000000 ns",  # and in nanoseconds (19 digits)
        "1000000000000008",  # Luhn-valid, but no card number starts with 1
        "9000000000000001",  # nor with 9
        "424242424242",  # Luhn-valid, 12 digits: too short
        "42424242424242424242",  # Luhn-valid, 20 digits: too long
        "4242 4242 4242 4242 4242",  # the same, spaced
        "p=0.4242424242424242",  # the decimals of a number
        "4242424242424242.5",
        "call +34 612 345 678",
        "2026-10-22T16:56:26.123456789Z",
    ],
)
def test_numbers_that_are_not_card_numbers_are_kept(text: str) -> None:
    assert redact(text) == text


def test_only_the_card_number_goes_and_the_text_around_stays() -> None:
    text = "Visa 4242 4242 4242 4242, Amex 378282246310005; total 42,00 EUR"
    assert redact(text) == f"Visa {REDACTED}, Amex {REDACTED}; total 42,00 EUR"


def test_a_card_number_in_a_form_body_is_struck() -> None:
    body = "amount=1999&number=4242424242424242&exp_month=12"
    assert redact(body) == f"amount=1999&number={REDACTED}&exp_month=12"
    plus = "number=4242+4242+4242+4242&exp=12%2F30"
    assert redact(plus) == f"number={REDACTED}&exp=12%2F30"


def test_a_card_number_in_a_json_body_is_struck() -> None:
    body = '{"card": {"number": "4242424242424242", "exp_month": 12}}'
    assert redact(body) == f'{{"card": {{"number": "{REDACTED}", "exp_month": 12}}}}'
    assert redact({"card": {"number": "5555 5555 5555 4444"}}) == {"card": {"number": REDACTED}}


CARD_FIELDS = [
    "card_number",
    "cardNumber",
    "card-number",
    "CARDNUMBER",
    "card_num",
    "card_no",
    "credit_card_number",
    "debit-card-number",
    "cc-number",
    "cc_number",
    "ccnum",
    "pan",
    "PAN",
    "primary_account_number",
    "cvv",
    "CVV2",
    "cvc",
    "cvc2",
    "card_cvc",
    "card_cvv",
    "cardCvc",
    "cc-csc",
    "card_cid",
    "security_code",
    "securityCode",
    "card_security_code",
    "card_verification_value",
    "pin",
    "PIN",
    "card_pin",
    "atm-pin",
    "pin_number",
    "pin_block",
    "card[number]",
    "card[cvc]",
    "payment_method_data[card][cvc]",
    "card%5Bcvc%5D",
    "billing.card.cvv",
    "x-card-cvc",
]


@pytest.mark.parametrize("name", CARD_FIELDS)
def test_card_fields_are_struck_by_name_in_a_mapping(name: str) -> None:
    assert redact({name: "123"}) == {name: REDACTED}
    assert redact({name: 123}) == {name: REDACTED}  # a CVV sent as a JSON number
    assert redact([name, "1234"]) == [name, REDACTED]  # a header or argv pair
    assert redact({"name": name, "value": "123"}) == {"name": name, "value": REDACTED}


@pytest.mark.parametrize("name", CARD_FIELDS)
def test_card_fields_are_struck_by_name_in_form_and_json_text(name: str) -> None:
    assert redact(f"a=1&{name}=123&b=2") == f"a=1&{name}={REDACTED}&b=2"
    assert redact(f"{name}=123") == f"{name}={REDACTED}"
    assert redact(f'{{"{name}": "123", "b": 2}}') == f'{{"{name}": "{REDACTED}", "b": 2}}'
    assert redact(f'{{"{name}":123,"b":2}}') == f'{{"{name}":{REDACTED},"b":2}}'
    assert redact(f"{{'{name}': '0042'}}") == f"{{'{name}': '{REDACTED}'}}"
    assert redact(f"--{name} 1234 --x") == f"--{name} {REDACTED} --x"


@pytest.mark.parametrize(
    "name",
    [
        "span",
        "time_span",
        "spin",
        "pinned",
        "pins",
        "japan",
        "company",
        "cc",  # an e-mail's copy
        "bcc",
        "cid",  # an e-mail's Content-ID
        "number",
        "card",
        "card_type",
        "card_brand",
        "card_last4",
        "exp_month",
        "pan_id",
        "topic",
        "pincode",  # a postal code in India
    ],
)
def test_ordinary_names_near_the_card_ones_are_kept(name: str) -> None:
    assert redact({name: "123"}) == {name: "123"}
    assert redact(f"{name}=123") == f"{name}=123"
    assert redact(f'{{"{name}": "123"}}') == f'{{"{name}": "123"}}'


def test_card_patterns_are_idempotent() -> None:
    text = 'card 4242 4242 4242 4242 cvc=123 {"pin": 1234}'
    once = redact(text)
    assert "4242" not in once and "123" not in once and "1234" not in once
    assert redact(once) == once


def test_strike_text_reports_a_card_number_it_strikes() -> None:
    seen: list[str] = []
    struck = _redact_mod.strike_text("x 4242424242424242 y", on_strike=lambda m: seen.append(m[0]))
    assert struck == f"x {REDACTED} y"
    assert seen == ["4242424242424242"]


def test_redact_is_linear_on_hostile_digits() -> None:
    def hostile(size: int) -> str:
        return ("4242 4242 4242 4242 4242 " * (size // 25 + 1))[:size]

    small, large = hostile(64 * 1024), hostile(512 * 1024)
    assert_linear(redact, small, large, 8, floor=0.01, cap=2.0, label="redact on card digits")


def test_redact_is_linear_on_hostile_card_names() -> None:
    def hostile(size: int) -> str:
        return ('"payment_card[card][cvc%5d' * (size // 26 + 1))[:size]

    small, large = hostile(64 * 1024), hostile(512 * 1024)
    assert_linear(redact, small, large, 8, floor=0.01, cap=2.0, label="redact on card names")
