import hashlib
import hmac
import math

import pytest

from backtide.blackbox import GENESIS, Source, canonical, compute_hash, key_id
from backtide.blackbox.chain import CANONICAL_FIELDS, canonical_json, checkpoint_mac

KEY = bytes(range(32))
FIELDS = {
    "seq": 1,
    "ts": "2026-10-06T12:26:38.774641Z",
    "source": "file",
    "action": "write",
    "target": "/w/año.txt",
    "details": {"b": 1, "a": [1, "ñ", None, True]},
    "risk": 2,
    "snapshot_id": None,
    "prev_hash": GENESIS,
}


def test_genesis_is_64_zeros() -> None:
    assert GENESIS == "0" * 64


def test_canonical_form_is_byte_for_byte_stable() -> None:
    expected = (
        '{"action":"write","details":{"a":[1,"ñ",null,true],"b":1},'
        f'"prev_hash":"{GENESIS}","risk":2,"seq":1,"snapshot_id":null,'
        '"source":"file","target":"/w/año.txt","ts":"2026-10-06T12:26:38.774641Z"}'
    ).encode()
    assert canonical(FIELDS) == expected


def test_canonical_keeps_non_ascii_as_utf8() -> None:
    payload = canonical(FIELDS)
    assert "año".encode() in payload
    assert b"\\u" not in payload


def test_canonical_does_not_depend_on_key_order() -> None:
    reordered = dict(reversed(list(FIELDS.items())))
    reordered["details"] = {"a": [1, "ñ", None, True], "b": 1}
    assert canonical(reordered) == canonical(FIELDS)


def test_canonical_treats_a_source_member_like_its_value() -> None:
    assert canonical({**FIELDS, "source": Source.FILE}) == canonical(FIELDS)


def test_canonical_ignores_the_hash_field_itself() -> None:
    assert canonical({**FIELDS, "hash": "f" * 64}) == canonical(FIELDS)


@pytest.mark.parametrize("missing", CANONICAL_FIELDS)
def test_canonical_requires_every_field(missing: str) -> None:
    fields = {name: value for name, value in FIELDS.items() if name != missing}
    with pytest.raises(KeyError):
        canonical(fields)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_canonical_rejects_values_that_are_not_json(bad: float) -> None:
    with pytest.raises(ValueError):
        canonical({**FIELDS, "details": {"x": bad}})


def test_canonical_json_is_compact_and_sorted() -> None:
    assert canonical_json({"b": [1, 2], "a": {"d": 1, "c": 2}}) == '{"a":{"c":2,"d":1},"b":[1,2]}'


def test_compute_hash_is_hmac_sha256_hex() -> None:
    # RFC 4231, test case 2.
    assert compute_hash(b"Jefe", b"what do ya want for nothing?") == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_compute_hash_depends_on_the_key_and_the_payload() -> None:
    payload = canonical(FIELDS)
    digest = compute_hash(KEY, payload)
    assert digest == hmac.new(KEY, payload, hashlib.sha256).hexdigest()
    assert digest != compute_hash(bytes(32), payload)
    assert digest != compute_hash(KEY, canonical({**FIELDS, "risk": 3}))
    assert digest != hashlib.sha256(payload).hexdigest()  # a plain hash is not enough


def test_key_id_is_short_stable_and_reveals_nothing() -> None:
    assert key_id(KEY) == key_id(bytes(KEY))
    assert key_id(KEY) != key_id(bytes(32))
    assert len(key_id(KEY)) == 16
    assert KEY.hex()[:16] not in key_id(KEY)
    assert key_id(KEY) not in hashlib.sha256(KEY).hexdigest()


def test_key_id_and_checkpoint_mac_keep_their_bytes() -> None:
    """Existing black boxes store key_id and checkpoint macs: the labels must never change."""
    assert key_id(KEY) == "a5e5531163507cc6"
    fields = {"seq": 1, "hash": "0" * 64, "ts": "2026-10-17T00:00:00Z", "key_id": key_id(KEY)}
    assert checkpoint_mac(KEY, fields) == (
        "01d52e1684b84a1540c50c3f924b02e6329970df0755a7456efb11a16d8e7965"
    )


def test_checkpoint_mac_covers_every_field_and_differs_from_event_hashes() -> None:
    fields = {"seq": 3, "hash": "a" * 64, "ts": FIELDS["ts"], "key_id": key_id(KEY)}
    mac = checkpoint_mac(KEY, fields)
    assert mac == checkpoint_mac(KEY, {**fields, "mac": "ignored"})
    for name, other in (("seq", 4), ("hash", "b" * 64), ("ts", "x"), ("key_id", "y")):
        assert checkpoint_mac(KEY, {**fields, name: other}) != mac
    assert checkpoint_mac(bytes(32), fields) != mac
    assert mac != compute_hash(KEY, canonical_json(fields).encode())
