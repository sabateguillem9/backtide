"""The hash chain: canonical form and keyed hashes. Pure: no I/O.

Each event's ``hash`` is HMAC-SHA256(key, canonical(event fields)) and the next event
stores it as ``prev_hash``. Without the key nobody can recompute a valid chain.
"""

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

GENESIS = "0" * 64

# Formats of what the black box stores (ASCII only: no Unicode digits, no surrogates).
HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)  # hashes and macs
KEY_ID_RE = re.compile(r"[0-9a-f]{16}", re.ASCII)
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", re.ASCII)

# The fields covered by an event's hash: every column except the hash itself.
CANONICAL_FIELDS = (
    "seq",
    "ts",
    "source",
    "action",
    "target",
    "details",
    "risk",
    "snapshot_id",
    "prev_hash",
)
CHECKPOINT_FIELDS = ("seq", "hash", "ts", "key_id")

_KEY_ID_LABEL = b"vigia/blackbox/key-id/v1"
_CHECKPOINT_LABEL = b"vigia/blackbox/checkpoint/v1\n"


def canonical_json(value: Any) -> str:
    """The one JSON serialization used for hashing and for the stored ``details``.

    Raises ValueError for NaN or infinity and TypeError for values JSON cannot hold."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def canonical(fields: Mapping[str, Any]) -> bytes:
    """UTF-8 canonical JSON of exactly the CANONICAL_FIELDS taken from ``fields``.

    Other keys (such as ``hash``) are ignored; a missing one raises KeyError."""
    return canonical_json({name: fields[name] for name in CANONICAL_FIELDS}).encode("utf-8")


def compute_hash(key: bytes, payload: bytes) -> str:
    """HMAC-SHA256 of ``payload`` as 64 lowercase hex characters."""
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def key_id(key: bytes) -> str:
    """A short fingerprint that tells keys apart without revealing them."""
    return compute_hash(key, _KEY_ID_LABEL)[:16]


def checkpoint_mac(key: bytes, fields: Mapping[str, Any]) -> str:
    """The checkpoint's ``mac``: an HMAC of its other fields, domain-separated from
    event hashes. A missing field raises KeyError."""
    body = canonical_json({name: fields[name] for name in CHECKPOINT_FIELDS})
    return compute_hash(key, _CHECKPOINT_LABEL + body.encode("utf-8"))
