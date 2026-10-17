"""The black box: an append-only, hash-chained record of everything the agent does.

Design and rationale: docs/11-diseno-t02-caja-negra.md.
"""

from backtide.blackbox.chain import GENESIS, canonical, compute_hash, key_id
from backtide.blackbox.keys import KEY_SIZE, create_key, load_key
from backtide.blackbox.model import (
    BlackBoxError,
    Event,
    Problem,
    ProblemKind,
    Source,
    VerifyReport,
)
from backtide.blackbox.redact import REDACTED, redact
from backtide.blackbox.store import BlackBox

__all__ = [
    "GENESIS",
    "KEY_SIZE",
    "REDACTED",
    "BlackBox",
    "BlackBoxError",
    "Event",
    "Problem",
    "ProblemKind",
    "Source",
    "VerifyReport",
    "canonical",
    "compute_hash",
    "create_key",
    "key_id",
    "load_key",
    "redact",
]
