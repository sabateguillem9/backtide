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
    MAX_SIGN_INS,
    RP_ID,
    PasskeyError,
    Passkeys,
    matching,
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


# -- signing in and touching it again (T26-3c) ------------------------------------------------


@pytest.fixture
def owner(keys: Passkeys) -> SoftAuthenticator:
    authenticator = SoftAuthenticator()
    keys.finish(SESSION, authenticator.create(keys.begin(SESSION), ORIGIN), "portátil")
    return authenticator


def test_signing_in_with_the_kept_key(keys: Passkeys, owner: SoftAuthenticator) -> None:
    options = json.loads(keys.sign_in_begin())
    assert options["rpId"] == RP_ID and options["userVerification"] == "required"
    assert [c["id"] for c in options["allowCredentials"]] == [keys.keys()[0].id]
    assert keys.sign_in(owner.get(json.dumps(options), ORIGIN)).name == "portátil"


def test_no_key_nothing_to_sign_in_with(keys: Passkeys) -> None:
    with pytest.raises(PasskeyError, match="ninguna llave"):
        keys.sign_in_begin()
    with pytest.raises(PasskeyError, match="ninguna llave"):
        keys.touch_begin(SESSION)


@pytest.mark.parametrize(
    "bend",
    [
        {"origin": "https://backtide.localhost.evil.example"},
        {"origin": "http://backtide.localhost:9999"},
        {"rp_id": "evil.example"},
        {"verified": False},
        {"kind": "webauthn.create"},
        {"bad_signature": True},
    ],
)
def test_a_signature_bent_any_way_does_not_sign_in(
    keys: Passkeys, owner: SoftAuthenticator, bend: dict
) -> None:
    fields = {"origin": ORIGIN, **bend}
    answer = owner.get(keys.sign_in_begin(), fields.pop("origin"), **fields)
    with pytest.raises(PasskeyError):
        keys.sign_in(answer)


def test_a_signature_counts_once(keys: Passkeys, owner: SoftAuthenticator) -> None:
    answer = owner.get(keys.sign_in_begin(), ORIGIN)
    keys.sign_in(answer)
    with pytest.raises(PasskeyError, match="pendiente"):
        keys.sign_in(answer)


def test_a_failed_answer_spends_its_challenge(keys: Passkeys, owner: SoftAuthenticator) -> None:
    options = keys.sign_in_begin()
    with pytest.raises(PasskeyError):
        keys.sign_in(owner.get(options, "https://evil.example"))
    with pytest.raises(PasskeyError, match="pendiente"):
        keys.sign_in(owner.get(options, ORIGIN))


def test_a_challenge_nobody_asked_for_or_too_old(
    keys: Passkeys, owner: SoftAuthenticator, clock: Clock
) -> None:
    options = keys.sign_in_begin()
    with pytest.raises(PasskeyError, match="pendiente"):
        keys.sign_in(owner.get(options, ORIGIN, challenge="b3RybyByZXRv"))
    clock.now += CHALLENGE_SECONDS
    with pytest.raises(PasskeyError, match="pendiente"):
        keys.sign_in(owner.get(options, ORIGIN))


def test_a_key_that_is_not_kept_does_not_sign_in(keys: Passkeys, owner: SoftAuthenticator) -> None:
    with pytest.raises(PasskeyError, match="no está registrada"):
        keys.sign_in(SoftAuthenticator().get(keys.sign_in_begin(), ORIGIN))


def test_the_same_id_with_another_key_does_not_sign_in(
    keys: Passkeys, owner: SoftAuthenticator
) -> None:
    thief = SoftAuthenticator()
    thief.credential_id = owner.credential_id
    with pytest.raises(PasskeyError, match="firma válida"):
        keys.sign_in(thief.get(keys.sign_in_begin(), ORIGIN))


def test_a_count_that_goes_back_is_a_copied_key(keys: Passkeys, owner: SoftAuthenticator) -> None:
    owner.count = 7
    assert keys.sign_in(owner.get(keys.sign_in_begin(), ORIGIN)).sign_count == 7
    assert keys.keys()[0].sign_count == 7
    owner.count = 7
    with pytest.raises(PasskeyError, match="firma válida"):
        keys.sign_in(owner.get(keys.sign_in_begin(), ORIGIN))
    assert keys.keys()[0].sign_count == 7


def test_only_so_many_challenges_wait(keys: Passkeys, owner: SoftAuthenticator) -> None:
    first = keys.sign_in_begin()
    for _ in range(MAX_SIGN_INS):
        last = keys.sign_in_begin()
    with pytest.raises(PasskeyError, match="pendiente"):
        keys.sign_in(owner.get(first, ORIGIN))
    assert keys.sign_in(owner.get(last, ORIGIN)).name == "portátil"


def test_a_touch_belongs_to_its_session(keys: Passkeys, owner: SoftAuthenticator) -> None:
    options = keys.touch_begin(SESSION)
    with pytest.raises(PasskeyError, match="toque"):
        keys.touch("o" * 43, owner.get(options, ORIGIN))
    options = keys.touch_begin(SESSION)
    assert keys.touch(SESSION, owner.get(options, ORIGIN)).name == "portátil"
    with pytest.raises(PasskeyError, match="toque"):
        keys.touch(SESSION, owner.get(options, ORIGIN))


def test_a_touchs_challenge_does_not_sign_in_nor_the_other_way(
    keys: Passkeys, owner: SoftAuthenticator
) -> None:
    with pytest.raises(PasskeyError, match="pendiente"):
        keys.sign_in(owner.get(keys.touch_begin(SESSION), ORIGIN))
    keys.touch_begin(SESSION)
    with pytest.raises(PasskeyError, match="firma válida"):
        keys.touch(SESSION, owner.get(keys.sign_in_begin(), ORIGIN))


def test_a_key_is_found_by_the_end_of_its_id(keys: Passkeys, owner: SoftAuthenticator) -> None:
    key = keys.keys()[0]
    assert matching(keys.keys(), key.tail) == [key] == matching(keys.keys(), key.id)
    assert matching(keys.keys(), key.tail[1:]) == [] == matching(keys.keys(), "zzzz")


# -- T26-3d: managing the keys ------------------------------------------------------------------


def two_keys(keys: Passkeys) -> tuple[Passkeys, list]:
    for name in ("portátil", "móvil"):
        keys.finish(name, SoftAuthenticator().create(keys.begin(name), ORIGIN), name)
    return keys, keys.keys()


def test_keep_one_takes_a_key_out_while_another_stays(keys: Passkeys) -> None:
    keys, (going, staying) = two_keys(keys)
    assert keys.remove(going.id, keep_one=True) is True
    assert keys.keys() == [staying]


def test_keep_one_refuses_the_last_key_under_the_lock(keys: Passkeys) -> None:
    keys, (going, staying) = two_keys(keys)
    keys.remove(going.id, keep_one=True)
    with pytest.raises(PasskeyError, match="última"):
        keys.remove(staying.id, keep_one=True)
    assert keys.keys() == [staying]


def test_keep_one_says_false_for_a_key_that_is_not_there(keys: Passkeys) -> None:
    keys, (going, staying) = two_keys(keys)
    assert keys.remove("not-a-key", keep_one=True) is False
    assert keys.keys() == [going, staying]


def test_root_can_still_take_the_last_key_out(keys: Passkeys) -> None:
    keys, (going, staying) = two_keys(keys)
    assert keys.remove(going.id) is True and keys.remove(staying.id) is True
    assert keys.keys() == []


def test_a_key_is_renamed_and_nothing_else_of_it_changes(keys: Passkeys) -> None:
    keys, (first, second) = two_keys(keys)
    renamed = keys.rename(first.id, "portátil viejo")
    assert renamed.name == "portátil viejo"
    assert (renamed.id, renamed.public_key, renamed.sign_count, renamed.added) == (
        first.id, first.public_key, first.sign_count, first.added,
    )  # fmt: skip
    assert keys.keys() == [renamed, second]


@pytest.mark.parametrize("name", ["", " x", "x ", "t.me/x", "@someone", "a" * 49, None, 7])
def test_a_new_name_follows_the_rules_of_a_first_name(keys: Passkeys, name: object) -> None:
    keys, listed = two_keys(keys)
    with pytest.raises(PasskeyError):
        keys.rename(listed[0].id, name)
    assert keys.keys() == listed


def test_a_key_that_is_not_there_is_not_renamed(keys: Passkeys) -> None:
    keys, listed = two_keys(keys)
    with pytest.raises(PasskeyError, match="no está"):
        keys.rename("not-a-key", "móvil")
    assert keys.keys() == listed


def test_a_signature_in_flight_does_not_bring_an_old_name_back(
    keys: Passkeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rename while a signature is being checked: the count saved after it keeps the new name."""
    import backtide.service.passkeys as module

    owner = SoftAuthenticator()
    keys.finish(SESSION, owner.create(keys.begin(SESSION), ORIGIN), "portátil")
    real = module.verify_authentication_response

    def renames_meanwhile(**kwargs: object) -> object:
        keys.rename(keys.keys()[0].id, "móvil")
        return real(**kwargs)

    monkeypatch.setattr(module, "verify_authentication_response", renames_meanwhile)
    owner.count = 5
    signed = keys.sign_in(owner.get(keys.sign_in_begin(), ORIGIN))
    assert signed.name == "móvil" and signed.sign_count == 5
    [kept] = keys.keys()
    assert kept.name == "móvil" and kept.sign_count == 5


def test_a_whole_id_reaches_its_key_whatever_its_length_or_the_others(keys: Passkeys) -> None:
    """Review of T26-3d: `--quitar` must reach every key, also one kept before ids were bounded
    or whose whole id is the end of another's."""
    from backtide.service.passkeys import Passkey

    short = Passkey(id="abc", public_key="", sign_count=0, name="corta", added="2026-11-01")
    longer = Passkey(id="xyzabc", public_key="", sign_count=0, name="larga", added="2026-11-01")
    assert matching([short, longer], "abc") == [short]
    assert matching([short, longer], "xyzabc") == [longer]
    assert matching([short, longer], "yz") == []  # the end of an id still takes 4 at least


@pytest.mark.parametrize("size", [1, 8, 15])
def test_a_key_with_a_short_id_is_not_kept(keys: Passkeys, size: int) -> None:
    authenticator = SoftAuthenticator()
    authenticator.credential_id = os.urandom(size)
    answer = authenticator.create(keys.begin(SESSION), ORIGIN)
    with pytest.raises(PasskeyError, match="tamaño"):
        keys.finish(SESSION, answer, "corta")
    assert keys.keys() == []


def test_a_key_with_a_long_id_is_not_kept(keys: Passkeys, monkeypatch: pytest.MonkeyPatch) -> None:
    """The true limit (1023) cannot be reached here: the answer's own 3500 characters come first."""
    import backtide.service.passkeys as module

    monkeypatch.setattr(module, "MAX_ID_BYTES", 32)
    authenticator = SoftAuthenticator()
    authenticator.credential_id = os.urandom(33)
    answer = authenticator.create(keys.begin(SESSION), ORIGIN)
    with pytest.raises(PasskeyError, match="tamaño"):
        keys.finish(SESSION, answer, "larga")
    assert keys.keys() == []


@pytest.mark.parametrize("size", [16, 64])
def test_a_key_with_a_normal_id_is_kept(keys: Passkeys, size: int) -> None:
    authenticator = SoftAuthenticator()
    authenticator.credential_id = os.urandom(size)
    key = keys.finish(SESSION, authenticator.create(keys.begin(SESSION), ORIGIN), "normal")
    assert keys.keys() == [key]
