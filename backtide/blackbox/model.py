"""Black-box events, verification results and errors. Pure: no I/O.

Design and rationale: docs/11-diseno-t02-caja-negra.md.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Source(StrEnum):
    """Who observed the action. Only these values are ever stored."""

    EXEC = "exec"
    FILE = "file"
    NET = "net"
    LLM = "llm"
    GATE = "gate"
    SNAPSHOT = "snapshot"
    SYSTEM = "system"
    # The person's own changes to backtide's settings (T12e): a key set or removed, from the web.
    # Only the kind and who asked are ever recorded, never the key or a piece of it.
    SETTINGS = "settings"


@dataclass(frozen=True)
class Event:
    """One recorded action. ``seq``, ``ts``, ``prev_hash`` and ``hash`` are assigned by
    the black box; ``target`` and ``details`` are already redacted and truncated."""

    seq: int
    ts: str  # UTC with microseconds, e.g. "2026-10-06T12:26:38.774641Z"
    source: Source
    action: str
    target: str
    details: dict[str, Any]
    risk: int  # 0-3
    snapshot_id: str | None
    prev_hash: str
    hash: str


class ProblemKind(StrEnum):
    """What verify() found. ``Problem.seq`` meaning is given per kind."""

    # Failures: they land in VerifyReport.problems and make ok False.
    SCHEMA = "schema"  # a table or a meta row is missing, or a table was altered. seq: None
    TRIGGERS = "triggers"  # an append-only trigger is missing or altered, or a foreign one
    # exists (it could drop events with RAISE(IGNORE)). seq: None
    KEY_MISMATCH = "key_mismatch"  # meta key_id is not this key's id. seq: None
    GAP = "gap"  # seq is not contiguous from 1. seq: the FIRST missing one
    INVALID = "invalid"  # a stored field fails validation. seq: the event (None if the seq
    # itself is not an integer, which only a re-created table can hold)
    BROKEN_CHAIN = "broken_chain"  # prev_hash is not the previous event's hash. seq: the event
    HASH_MISMATCH = "hash_mismatch"  # the recomputed HMAC differs. seq: the event
    TRUNCATED = "truncated"  # checkpoint ahead, events cut at the end. seq: FIRST missing one
    CHECKPOINT_MISMATCH = "checkpoint_mismatch"  # same seq, different hash. seq: that event
    CHECKPOINT_FORGED = "checkpoint_forged"  # malformed or its mac is wrong. seq: None
    CHECKPOINT_DELETED = "checkpoint_deleted"  # the file is gone but there are events. seq: None
    ROLLED_BACK = "rolled_back"  # the chain is behind (or differs from) what this instance
    # already wrote or verified. seq: the first missing event, or the one that changed
    # Warnings: they land in VerifyReport.warnings and never change ok.
    CHECKPOINT_MISSING = "checkpoint_missing"  # none given, or none in an empty box. seq: None
    CHECKPOINT_BEHIND = "checkpoint_behind"  # crash before the checkpoint write. seq: its seq
    CLOCK_BACKWARDS = "clock_backwards"  # ts earlier than the previous event's. seq: the event


@dataclass(frozen=True)
class Problem:
    """A finding of verify(). ``detail`` is in Spanish: it is shown to the user as is."""

    seq: int | None
    kind: ProblemKind
    detail: str


@dataclass(frozen=True)
class VerifyReport:
    checked: int  # events examined (rows in the events table)
    last_seq: int | None  # highest seq found, None if there are no events
    problems: tuple[Problem, ...]
    warnings: tuple[Problem, ...]

    @property
    def ok(self) -> bool:
        return not self.problems


class BlackBoxError(Exception):
    """The black box cannot be opened, read or written, or refuses to extend a chain
    that shows signs of tampering. Invalid arguments raise ValueError instead."""
