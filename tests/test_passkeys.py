"""Registering the web's passkeys (T26-3b-2): only from a live session, a challenge good once,
our own origin and relying party, a verified user, and only public keys kept."""

import json
import os
import stat
from pathlib import Path

import pytest

from backtide.service.passkeys import (
    CHALLENGE_SECONDS,
    MAX_KEYS,
    RP_ID,
    PasskeyError,
    Passkeys,
    origin_for,
    path_of,
)
from tests.passkey_kit import SoftAuthenticator

ORIGIN = origin_for(8765)
SESSION = "s" * 43


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def state(tmp_path: Path) -> Path:
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    return folder


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def keys(state: Path, clock: Clock) -> Passkeys:
    return Passkeys(state, origins=[ORIGIN], clock=clock)


def test_a_passkey_is_registered_and_only_its_public_key_kept(keys: Passkeys, state: Path) -> None:
    authenticator = SoftAuthenticator()
    options = json.loads(keys.begin(SESSION))
    assert options["rp"]["id"] == RP_ID
    assert options["authenticatorSelection"]["userVerification"] == "required"
    key = keys.finish(SESSION, authenticator.create(json.dumps(options), ORIGIN), "portátil")
    assert key.name == "portátil" and len(key.tail) == 4
    assert keys.keys() == [key]
    path = path_of(state)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    text = path.read_text()
    assert "PRIVATE" not in text and key.public_key in text


def test_a_challenge_is_good_once(keys: Passkeys) -> None:
    authenticator = SoftAuthenticator()
    options = keys.begin(SESSION)
    keys.finish(SESSION, authenticator.create(options, ORIGIN), "uno")
    with pytest.raises(PasskeyError, match="no hay un registro pedido"):
        keys.finish(SESSION, SoftAuthenticator().create(options, ORIGIN), "otro")


def test_a_challenge_dies_after_its_two_minutes(keys: Passkeys, clock: Clock) -> None:
    options = keys.begin(SESSION)
    clock.now += CHALLENGE_SECONDS
    with pytest.raises(PasskeyError, match="caducó"):
        keys.finish(SESSION, SoftAuthenticator().create(options, ORIGIN), "tarde")


def test_a_challenge_belongs_to_its_session(keys: Passkeys) -> None:
    options = keys.begin(SESSION)
    with pytest.raises(PasskeyError):
        keys.finish("o" * 43, SoftAuthenticator().create(options, ORIGIN), "ajena")
    assert keys.keys() == []


@pytest.mark.parametrize(
    "bend",
    [
        {"origin": "http://evil.example:8765"},  # another site asked the browser
        {"origin": "http://127.0.0.1:8765"},
        {"origin": origin_for(8766)},
        {"rp_id": "evil.example"},
        {"verified": False},  # nobody touched Touch ID or typed the PIN
        {"challenge": "AAAA"},  # an answer to another challenge
        {"kind": "webauthn.get"},  # a sign-in, not a registration
    ],
)
def test_a_bent_answer_is_refused_and_spends_the_challenge(
    keys: Passkeys, bend: dict[str, object]
) -> None:
    authenticator = SoftAuthenticator()
    options = keys.begin(SESSION)
    origin = str(bend.pop("origin", ORIGIN))
    with pytest.raises(PasskeyError, match="no ha dado una llave válida"):
        keys.finish(SESSION, authenticator.create(options, origin, **bend), "doblada")  # type: ignore[arg-type]
    assert keys.keys() == []
    with pytest.raises(PasskeyError, match="no hay un registro pedido"):
        keys.finish(SESSION, authenticator.create(options, ORIGIN), "otra vez")


@pytest.mark.parametrize("answer", [None, "", "{}", "not json", "x" * 5000, 7])
def test_an_answer_that_is_not_one_is_refused(keys: Passkeys, answer: object) -> None:
    keys.begin(SESSION)
    with pytest.raises(PasskeyError):
        keys.finish(SESSION, answer, "rara")
    assert keys.keys() == []


@pytest.mark.parametrize(
    "name",
    [None, "", "   ", " lead", "x" * 49, "tab\there", 7, "abre t.me/xyz", "@alguien", "a/b"],
)
def test_a_key_needs_a_plain_name(keys: Passkeys, name: object) -> None:
    options = keys.begin(SESSION)
    with pytest.raises(PasskeyError):
        keys.finish(SESSION, SoftAuthenticator().create(options, ORIGIN), name)


def test_the_same_key_twice_is_refused(keys: Passkeys) -> None:
    authenticator = SoftAuthenticator()
    keys.finish(SESSION, authenticator.create(keys.begin(SESSION), ORIGIN), "una")
    options = json.loads(keys.begin(SESSION))
    assert [c["id"] for c in options["excludeCredentials"]] == [keys.keys()[0].id]
    with pytest.raises(PasskeyError, match="ya está registrada"):
        keys.finish(SESSION, authenticator.create(json.dumps(options), ORIGIN), "otra vez")


def test_at_most_ten_keys(keys: Passkeys) -> None:
    for i in range(MAX_KEYS):
        keys.finish(SESSION, SoftAuthenticator().create(keys.begin(SESSION), ORIGIN), f"llave {i}")
    with pytest.raises(PasskeyError, match="ya hay 10"):
        keys.begin(SESSION)


def test_a_file_that_is_not_ours_is_not_used(keys: Passkeys, state: Path) -> None:
    keys.finish(SESSION, SoftAuthenticator().create(keys.begin(SESSION), ORIGIN), "una")
    path_of(state).chmod(0o644)
    with pytest.raises(PasskeyError, match="no es el archivo"):
        keys.keys()


def test_the_origin_is_the_installed_webs() -> None:
    from backtide.service.passkeys import WEB_PORT
    from backtide.web.server import DEFAULT_PORT

    assert WEB_PORT == DEFAULT_PORT
    assert origin_for(WEB_PORT) == "http://backtide.localhost:8765"


def test_only_none_attestation_is_taken_and_no_certificate_parsed(
    keys: Passkeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of T26-3b-2: root never parses a manufacturer's certificate chain."""
    import webauthn.registration.verify_registration_response as verifying

    monkeypatch.setattr(verifying, "verify_registration_response",
                        lambda **kw: pytest.fail("verified"))  # fmt: skip
    options = keys.begin(SESSION)
    packed = SoftAuthenticator().create(
        options, ORIGIN, fmt="packed", statement={"alg": -7, "sig": b"x", "x5c": [b"not a cert"]}
    )
    with pytest.raises(PasskeyError, match="sin certificado"):
        keys.finish(SESSION, packed, "con certificado")
    assert keys.keys() == []


def test_a_deeply_nested_answer_is_a_plain_refusal(keys: Passkeys) -> None:
    keys.begin(SESSION)
    with pytest.raises(PasskeyError):
        keys.finish(SESSION, "[" * 3000 + "]" * 400, "anidada")


def test_verify_writes_nothing_until_kept(keys: Passkeys) -> None:
    key = keys.verify(SESSION, SoftAuthenticator().create(keys.begin(SESSION), ORIGIN), "x")
    assert keys.keys() == []
    keys.keep(key)
    assert keys.keys() == [key]
    with pytest.raises(PasskeyError, match="ya está registrada"):
        keys.keep(key)
