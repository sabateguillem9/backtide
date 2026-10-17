import base64
import pickle
from urllib.parse import quote

import pytest

from backtide.gate.providers import (
    CREDENTIAL_HEADERS,
    FAKE_KEY_PREFIX,
    Kind,
    Provider,
    Providers,
    Secret,
    contains_secret,
    is_fake_key,
    new_fake_key,
    swap_key,
)

# Test values only, generated for these tests: never a real key.
REAL_ANTHROPIC = "sk-ant-api03-TEST" + "r3alK3yAnthr0p1c" * 5
REAL_OPENAI = "sk-proj-TEST" + "r3alK3yOp3nAI" * 4
FAKE_ANTHROPIC = FAKE_KEY_PREFIX + "anthropic-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
FAKE_OPENAI = FAKE_KEY_PREFIX + "openrouter-" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4"


def anthropic() -> Provider:
    return Provider(
        name="anthropic",
        kind=Kind.ANTHROPIC,
        host="api.anthropic.com",
        fake_key=FAKE_ANTHROPIC,
        real_key=Secret(REAL_ANTHROPIC),
    )


def openrouter() -> Provider:
    return Provider(
        name="openrouter",
        kind=Kind.OPENAI,
        host="OpenRouter.ai.",
        fake_key=FAKE_OPENAI,
        real_key=Secret(REAL_OPENAI),
    )


def swap_key_https(provider: Provider, headers: list[tuple[str, str]]) -> object:
    return swap_key(provider, headers, scheme="https", port=443)


def both() -> Providers:
    return Providers([anthropic(), openrouter()])


# --- the fake key ------------------------------------------------------------------------------


def test_a_new_fake_key_has_the_prefix_the_provider_and_32_random_characters() -> None:
    key = new_fake_key("anthropic")
    assert key.startswith("backtide-fake-anthropic-")
    tail = key.removeprefix("backtide-fake-anthropic-")
    assert len(tail) == 32 and tail.isalnum() and tail.isascii()
    assert is_fake_key(key)
    assert new_fake_key("anthropic") != key


def test_a_fake_key_never_looks_like_an_oauth_token() -> None:
    # OpenClaw takes anything with "sk-ant-oat" for an OAuth token (docs/21, section 6).
    assert "sk-ant-oat" not in FAKE_KEY_PREFIX
    for _ in range(200):
        assert "sk-ant-oat" not in new_fake_key("anthropic").lower()
    assert not is_fake_key(FAKE_KEY_PREFIX + "sk-ant-oat-" + "a" * 32)


@pytest.mark.parametrize(
    "value",
    [
        "",
        REAL_ANTHROPIC,
        "backtide-fake-anthropic-short",
        FAKE_ANTHROPIC + "\n",
        FAKE_ANTHROPIC + " ",
        FAKE_ANTHROPIC.replace("A1b2", "A1-2"),
        "backtide-fake--" + "a" * 32,
        "BACKTIDE-FAKE-anthropic-" + "a" * 32,
        None,
    ],
)
def test_other_values_are_not_fake_keys(value: object) -> None:
    assert not is_fake_key(value)


@pytest.mark.parametrize("name", ["", "Anthropic", "a b", "a/b", "-x", "x" * 33])
def test_a_fake_key_needs_a_plain_provider_name(name: str) -> None:
    with pytest.raises(ValueError):
        new_fake_key(name)


# --- the secret and the provider ---------------------------------------------------------------


def test_a_secret_never_prints_its_value() -> None:
    secret = Secret(REAL_ANTHROPIC)
    for text in (repr(secret), str(secret), f"{secret}", f"{secret!r}", repr([secret])):
        assert REAL_ANTHROPIC not in text
    assert secret.reveal() == REAL_ANTHROPIC
    with pytest.raises(TypeError):
        pickle.dumps(secret)


def test_a_provider_never_prints_a_key() -> None:
    provider = anthropic()
    text = repr(provider) + str(provider) + repr(both())
    assert REAL_ANTHROPIC not in text
    assert FAKE_ANTHROPIC not in text


def test_a_provider_normalizes_its_host_and_knows_its_header() -> None:
    assert openrouter().host == "openrouter.ai"
    assert anthropic().header == "x-api-key"
    assert openrouter().header == "authorization"


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Bad Name"},
        {"kind": "gemini"},
        {"host": "not a host"},
        {"host": "8.8.8.8"},
        {"host": "*.anthropic.com"},
        {"fake_key": "not-a-fake-key"},
        {"fake_key": new_fake_key("openai")},  # another provider's name
        {"real_key": REAL_ANTHROPIC},  # not a Secret
        {"real_key": Secret("short")},
        {"real_key": Secret(REAL_ANTHROPIC + "\r\nX-Evil: 1")},  # header injection
        {"real_key": Secret(REAL_ANTHROPIC + " x")},
        {"real_key": Secret(FAKE_ANTHROPIC)},
        {"real_key": Secret(FAKE_KEY_PREFIX + "x" * 40)},
        {"real_key": Secret("sk-ant-api03-é" + "a" * 30)},
    ],
)
def test_a_bad_provider_is_refused(change: dict[str, object]) -> None:
    fields: dict[str, object] = {
        "name": "anthropic",
        "kind": Kind.ANTHROPIC,
        "host": "api.anthropic.com",
        "fake_key": FAKE_ANTHROPIC,
        "real_key": Secret(REAL_ANTHROPIC),
    }
    fields.update(change)
    with pytest.raises(ValueError) as error:
        Provider(**fields)  # type: ignore[arg-type]
    assert REAL_ANTHROPIC not in str(error.value)


def test_providers_must_not_share_a_name_a_host_or_a_key() -> None:
    with pytest.raises(ValueError):
        Providers([anthropic(), anthropic()])
    clash = Provider(
        name="other",
        kind=Kind.OPENAI,
        host="api.anthropic.com",
        fake_key=FAKE_KEY_PREFIX + "other-" + "a" * 32,
        real_key=Secret(REAL_OPENAI),
    )
    with pytest.raises(ValueError):
        Providers([anthropic(), clash])
    same_key = Provider(
        name="other",
        kind=Kind.OPENAI,
        host="api.openai.com",
        fake_key=FAKE_KEY_PREFIX + "other-" + "a" * 32,
        real_key=Secret(REAL_ANTHROPIC),
    )
    with pytest.raises(ValueError):
        Providers([anthropic(), same_key])


def test_a_provider_is_found_by_the_exact_connection_host() -> None:
    providers = both()
    assert providers.for_host("api.anthropic.com") is not None
    assert providers.for_host("API.ANTHROPIC.COM.").name == "anthropic"  # type: ignore[union-attr]
    assert providers.for_host("openrouter.ai").name == "openrouter"  # type: ignore[union-attr]
    for host in ("x.api.anthropic.com", "anthropic.com", "api.anthropic.com.evil.test", "", "a b"):
        assert providers.for_host(host) is None


def test_the_known_secrets_are_every_real_and_fake_key() -> None:
    assert set(both().known_secrets()) == {
        REAL_ANTHROPIC,
        REAL_OPENAI,
        FAKE_ANTHROPIC,
        FAKE_OPENAI,
    }


# --- the swap ----------------------------------------------------------------------------------

BASE = [("content-type", "application/json"), ("anthropic-version", "2023-06-01")]


def test_anthropic_swaps_the_fake_key_for_the_real_one() -> None:
    out = swap_key_https(anthropic(), [*BASE, ("X-Api-Key", FAKE_ANTHROPIC)])
    assert out == [*BASE, ("x-api-key", REAL_ANTHROPIC)]


@pytest.mark.parametrize("value", [f"Bearer {FAKE_OPENAI}", f"bearer {FAKE_OPENAI}"])
def test_openai_swaps_the_bearer_token(value: str) -> None:
    out = swap_key_https(openrouter(), [("Authorization", value), ("accept", "*/*")])
    assert out == [("accept", "*/*"), ("authorization", f"Bearer {REAL_OPENAI}")]


@pytest.mark.parametrize(
    "headers",
    [
        [],  # no key at all
        [*BASE],
        [("x-api-key", "")],
        [("authorization", f"Bearer {FAKE_ANTHROPIC}")],  # the fake key, wrong header
        [("x-api-key", FAKE_OPENAI)],  # another provider's fake key
        [("x-api-key", "sk-ant-api03-" + "u" * 80)],  # a key of the user's, found in a file
        [("x-api-key", "sk-ant-oat01-" + "u" * 80)],  # an OAuth token
        [("x-api-key", FAKE_ANTHROPIC), ("authorization", "Bearer x" * 3)],  # two credentials
        [("x-api-key", FAKE_ANTHROPIC), ("x-api-key", FAKE_ANTHROPIC)],  # twice
        [("x-api-key", FAKE_ANTHROPIC), ("cookie", "session=1")],
        [("x-api-key", FAKE_ANTHROPIC), ("proxy-authorization", "Basic eDp5")],
        [("x-api-key", FAKE_ANTHROPIC), ("api-key", "x")],
        [("x-api-key", FAKE_ANTHROPIC), ("x-goog-api-key", "x")],
        [("x-api-key", FAKE_ANTHROPIC + "x")],
        [("x-api-key", FAKE_ANTHROPIC[:-1])],
        [("x-api-key", f"{FAKE_ANTHROPIC},{FAKE_ANTHROPIC}")],
    ],
)
def test_anthropic_refuses_anything_but_exactly_the_fake_key(
    headers: list[tuple[str, str]],
) -> None:
    assert swap_key_https(anthropic(), headers) is None


@pytest.mark.parametrize(
    "value",
    [
        FAKE_OPENAI,  # no scheme
        f"Basic {FAKE_OPENAI}",
        f"Bearer  {FAKE_OPENAI} extra",
        f"Bearer {FAKE_OPENAI}x",
        f"Bearer {FAKE_ANTHROPIC}",
        f"Bearer {REAL_OPENAI}",
        "Bearer ",
    ],
)
def test_openai_refuses_anything_but_exactly_the_fake_bearer(value: str) -> None:
    assert swap_key_https(openrouter(), [("authorization", value)]) is None
    assert swap_key_https(openrouter(), [("x-api-key", FAKE_OPENAI)]) is None


@pytest.mark.parametrize(
    ("scheme", "port"),
    [("http", 80), ("http", 443), ("https", 80), ("https", 8443), ("HTTPS", 443), ("https", "443")],
)
def test_the_real_key_never_goes_out_in_clear_or_to_another_port(scheme: str, port: object) -> None:
    headers = [("x-api-key", FAKE_ANTHROPIC)]
    assert swap_key(anthropic(), headers, scheme=scheme, port=port) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name", ["authorization ", " x-api-key", "x api", "x:y", "", "x\r\ny", "é"]
)
def test_a_header_name_that_is_not_a_token_is_refused(name: str) -> None:
    headers = [("x-api-key", FAKE_ANTHROPIC), (name, "Bearer stolen")]
    assert swap_key_https(anthropic(), headers) is None


def test_every_credential_header_is_dropped() -> None:
    assert {"authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie",
            "proxy-authorization"} <= CREDENTIAL_HEADERS  # fmt: skip


def test_the_swapped_headers_carry_the_real_key_only_in_the_provider_header() -> None:
    headers = [*BASE, ("User-Agent", "openclaw"), ("X-Api-Key", FAKE_ANTHROPIC)]
    out = swap_key_https(anthropic(), headers)
    assert out is not None
    holders = [name for name, value in out if REAL_ANTHROPIC in value]
    assert holders == ["x-api-key"]
    assert not any(FAKE_ANTHROPIC in value for _, value in out)


# --- the real key, anywhere --------------------------------------------------------------------


@pytest.mark.parametrize(
    "part",
    [
        REAL_ANTHROPIC,
        f"/v1/messages?k={REAL_ANTHROPIC}",
        f"/v1/x?k={quote(REAL_ANTHROPIC, safe='')}",
        "/v1/x?k=" + "".join(f"%{ord(c):02x}" for c in REAL_ANTHROPIC),  # all of it encoded
        f"/v1/x?k={REAL_ANTHROPIC[:6]}%{ord(REAL_ANTHROPIC[6]):02X}{REAL_ANTHROPIC[7:]}",
        f"/x?k={REAL_ANTHROPIC[:6]}%25{ord(REAL_ANTHROPIC[6]):02X}{REAL_ANTHROPIC[7:]}",  # twice
        f'{{"note": "{REAL_ANTHROPIC}"}}',
        '{"n": "' + "".join(f"\\u{ord(c):04x}" for c in REAL_ANTHROPIC) + '"}',
        f"Bearer {REAL_OPENAI}",
        f"data={REAL_OPENAI}&x=1".encode(),
        b"\x00\xff" + REAL_OPENAI.encode() + b"\xfe",
    ],
)
def test_the_real_key_is_found_anywhere(part: str | bytes) -> None:
    assert both().real_key_in("/v1/messages", part)
    assert both().real_key_in(part)


def test_the_real_key_is_found_in_any_header_name_or_value() -> None:
    providers = both()
    assert providers.real_key_in("x-anything", REAL_ANTHROPIC)
    assert providers.real_key_in(f"x-{REAL_OPENAI}", "1")


@pytest.mark.parametrize(
    "part",
    [
        "/v1/messages",
        FAKE_ANTHROPIC,
        REAL_ANTHROPIC[:-1],
        b"",
        None,
        "",
        # Known limit (documented): another encoding of the key is not seen.
        base64.b64encode(REAL_ANTHROPIC.encode()).decode(),
        REAL_ANTHROPIC[:20] + " " + REAL_ANTHROPIC[20:],
    ],
)
def test_other_parts_do_not_hold_the_real_key(part: str | bytes | None) -> None:
    assert not both().real_key_in(part)


def test_contains_secret_needs_long_secrets() -> None:
    with pytest.raises(ValueError):
        contains_secret("text", ["short"])
    assert not contains_secret("text", [])
