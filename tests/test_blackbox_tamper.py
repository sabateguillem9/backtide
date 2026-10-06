"""Tamper tests for the black box (T02), written independently of its implementation.

The attacker here can open the SQLite file and the checkpoint file with plain sqlite3 and plain
file I/O, drop and recreate triggers, lift CHECK constraints and copy files around, but does not
hold the HMAC key. Every attack must make ``verify()`` report ``ok=False`` and point at the right
event; an intact box must report ``ok=True``.

One attack is undetectable by a fresh verifier on this machine by design
(docs/11-diseno-t02-caja-negra.md): rolling the database back together with a genuine older
checkpoint. It is pinned as ``test_known_gap_*`` so the gap stays visible; the recording process
refuses to append over it while it lives, and T09 closes it with a copy of every checkpoint sent
to Telegram. Cutting the tail and deleting the checkpoint IS detected: the box is created with a
genesis checkpoint, so a missing one is never legitimate once there are events.

Only the spec's public API is used, plus raw sqlite3. Problem kinds are matched loosely, by
fragments of their name (the names are the implementer's); problem seqs are asserted exactly
wherever the spec determines them, and as a small documented set where it leaves a choice.
"""

import contextlib
import hashlib
import hmac
import json
import shutil
import sqlite3
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import pytest

from vigia.blackbox.model import BlackBoxError, Source, VerifyReport
from vigia.blackbox.store import BlackBox

KEY = bytes(range(32))
ATTACKER_KEY = bytes(range(100, 132))
GENESIS = "0" * 64
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
SNAP_A = "20261005T075959.000001Z-periodic"
SNAP_B = "20261005T070000.000000Z-manual"
INNOCENT = "/home/agent/innocent.txt"

# Fragments of a Problem.kind (lowercased) that place it in the right family.
HASH = ("hash", "mac", "mismatch", "tamper", "forg")
INVALID = (
    *HASH,
    *("invalid", "field", "source", "risk", "ts", "time", "action", "target", "details"),
    *("json", "snapshot", "malformed", "corrupt", "format", "type", "canonical"),
)
CHAIN = (*HASH, "chain", "prev", "link", "order")
GAP = (*CHAIN, "gap", "seq", "missing", "contig", "delet")
CHECKPOINT = ("checkpoint", "mac", "forg", "key", "trunc", "missing", "delet", "tail", "rollback")
TRIGGER = ("trigger", "append")
KEY_ID = ("key",)


class Clock(Protocol):
    def __call__(self) -> datetime: ...
    def advance(self, delta: timedelta) -> None: ...


@dataclass(frozen=True)
class EventSpec:
    source: str
    action: str
    target: str
    details: dict[str, Any]
    risk: int
    snapshot_id: str | None


EVENTS: tuple[EventSpec, ...] = (
    EventSpec("exec", "run", "ls -la /home/agent", {"exit": 0}, 0, None),
    EventSpec("file", "write", "/home/agent/todo.md", {"bytes": 42}, 1, SNAP_B),
    EventSpec(
        "file",
        "write",
        "/home/agent/café.txt",
        {"bytes": 10, "mode": "w", "note": "café"},
        1,
        SNAP_A,
    ),
    EventSpec(
        "net", "request", "https://example.com/api", {"method": "GET", "status": 200}, 2, None
    ),
    EventSpec("gate", "approve", "rm -rf /home/agent/build", {"by": "founder"}, 3, None),
)
TARGET = 3  # the intermediate event most attacks aim at
LAST = len(EVENTS)


@dataclass(frozen=True)
class Box:
    db: Path
    checkpoint: Path


# --- Building and verifying boxes through the public API ----------------------------------------


def _append(bb: BlackBox, event: EventSpec) -> None:
    bb.append(
        Source(event.source),
        event.action,
        event.target,
        details=event.details,
        risk=event.risk,
        snapshot_id=event.snapshot_id,
    )


def _fill(box: Box, clock: Clock, events: Sequence[EventSpec] = EVENTS, key: bytes = KEY) -> None:
    """Append ``events`` in one session: the only way genuine events get in."""
    with BlackBox(box.db, key, checkpoint_path=box.checkpoint, clock=clock) as bb:
        for event in events:
            _append(bb, event)


def _make_box(
    directory: Path, clock: Clock, events: Sequence[EventSpec] = EVENTS, key: bytes = KEY
) -> Box:
    directory.mkdir()
    box = Box(directory / "blackbox.sqlite3", directory / "blackbox.checkpoint")
    _fill(box, clock, events, key)
    return box


def _verify(box: Box, key: bytes = KEY) -> VerifyReport:
    """Open the box afresh, as ``vigia verificar`` does, and verify it."""
    with BlackBox(box.db, key, checkpoint_path=box.checkpoint) as bb:
        return bb.verify()


def _verify_or_refuse(box: Box, key: bytes) -> VerifyReport | None:
    """Like _verify, but None when the box refuses to open: that is a detection as well."""
    try:
        return _verify(box, key)
    except BlackBoxError:
        return None


@pytest.fixture
def box(tmp_path: Path, clock: Clock) -> Box:
    return _make_box(tmp_path / "victim", clock)


# --- Raw access, as any process with write access to the files ---------------------------------


@contextlib.contextmanager
def _raw(db: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _triggers(conn: sqlite3.Connection, table: str | None = "events") -> list[tuple[str, str]]:
    """(name, sql) of the triggers on ``table``, or on every table when it is None."""
    rows = conn.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger'")
    return [(row["name"], row["sql"]) for row in rows if table is None or row["tbl_name"] == table]


def _fires_on(trigger_sql: str) -> str:
    normalized = " ".join(trigger_sql.upper().split())
    for statement in ("UPDATE", "DELETE", "INSERT"):
        if f"BEFORE {statement}" in normalized or f"AFTER {statement}" in normalized:
            return statement
    return "OTHER"


@contextlib.contextmanager
def tamper(db: Path) -> Iterator[sqlite3.Connection]:
    """Edit the box like a careful attacker: lift CHECK constraints, drop every trigger, make the
    changes and put the very same triggers back, all in one transaction. Only the data changes."""
    with _raw(db) as conn:
        triggers = _triggers(conn, table=None)
        assert _triggers(conn), "the black box must protect its events with triggers"
        conn.execute("PRAGMA ignore_check_constraints = ON")
        conn.execute("BEGIN IMMEDIATE")
        for name, _ in triggers:
            conn.execute(f'DROP TRIGGER "{name}"')
        yield conn
        for _, sql in triggers:
            conn.execute(sql)
        conn.execute("COMMIT")


def _row(conn: sqlite3.Connection, seq: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM events WHERE seq = ?", (seq,)).fetchone()
    assert row is not None, f"event {seq} should exist"
    return dict(row)


def _set(conn: sqlite3.Connection, seq: int, column: str, value: Any) -> None:
    conn.execute(f"UPDATE events SET {column} = ? WHERE seq = ?", (value, seq))  # noqa: S608


def _insert(
    conn: sqlite3.Connection, row: dict[str, Any], table: str = "events", verb: str = "INSERT"
) -> None:
    columns = ", ".join(f'"{column}"' for column in row)
    marks = ", ".join("?" * len(row))
    sql = f"{verb} INTO {table} ({columns}) VALUES ({marks})"  # noqa: S608
    conn.execute(sql, tuple(row.values()))


def _delete(conn: sqlite3.Connection, *seqs: int) -> None:
    conn.executemany("DELETE FROM events WHERE seq = ?", [(seq,) for seq in seqs])


def _move(conn: sqlite3.Connection, seq: int, new_seq: int) -> None:
    conn.execute("UPDATE events SET seq = ? WHERE seq = ?", (new_seq, seq))


def _shift(conn: sqlite3.Connection, first: int, by: int) -> None:
    """Renumber events ``first..`` by ``by``, in two steps so the primary key never collides."""
    conn.execute("UPDATE events SET seq = seq + 10000 WHERE seq >= ?", (first,))
    conn.execute("UPDATE events SET seq = seq - 10000 + ? WHERE seq >= 10000", (by,))


def _swap(conn: sqlite3.Connection, a: int, b: int) -> None:
    _move(conn, a, 10000)
    _move(conn, b, a)
    _move(conn, 10000, b)


def _table(db: Path, table: str) -> list[dict[str, Any]]:
    with _raw(db) as conn:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]  # noqa: S608


def _transplant(victim: Path, donor: Path, *, meta: bool = False) -> None:
    """Replace the victim's events (and optionally its meta table) with the donor's rows."""
    events = _table(donor, "events")
    meta_rows = _table(donor, "meta") if meta else []
    with tamper(victim) as conn:
        conn.execute("DELETE FROM events")
        for row in events:
            _insert(conn, row)
        if meta:
            conn.execute("DELETE FROM meta")
            for row in meta_rows:
                _insert(conn, row, table="meta")


def _backup(source: Path, target: Path) -> None:
    """Copy a SQLite database consistently, WAL included, as a backup tool would."""
    with (
        contextlib.closing(sqlite3.connect(source)) as src,
        contextlib.closing(sqlite3.connect(target)) as dst,
    ):
        src.backup(dst)


def _canonical(data: Any) -> bytes:
    """The spec's canonical JSON, which an attacker can read in the docs."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _unkeyed_event(seq: int, prev_hash: str, ts: str) -> dict[str, Any]:
    """A well-formed event 'signed' with plain SHA-256, the best an attacker without the key
    can do."""
    fields: dict[str, Any] = {
        "seq": seq,
        "ts": ts,
        "source": "exec",
        "action": "run",
        "target": "echo harmless",
        "details": {},
        "risk": 0,
        "snapshot_id": None,
        "prev_hash": prev_hash,
    }
    digest = hashlib.sha256(_canonical(fields)).hexdigest()
    return {**fields, "details": _canonical(fields["details"]).decode(), "hash": digest}


def _load_checkpoint(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert {"seq", "hash", "ts", "key_id", "mac"} <= set(data), data
    return data


def _save_checkpoint(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _unsigned(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in checkpoint.items() if name != "mac"}


def _sha256_mac(checkpoint: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(_unsigned(checkpoint))).hexdigest()


def _attacker_mac(checkpoint: dict[str, Any]) -> str:
    return hmac.new(ATTACKER_KEY, _canonical(_unsigned(checkpoint)), hashlib.sha256).hexdigest()


# --- Reading reports -----------------------------------------------------------------------------


def _describe(report: VerifyReport) -> str:
    problems = [(p.seq, str(p.kind), getattr(p, "detail", "")) for p in report.problems]
    checked = getattr(report, "checked", "<missing>")  # keep failure messages readable
    return f"ok={report.ok} checked={checked} problems={problems}"


def _matches(problem: Any, kinds: Sequence[str]) -> bool:
    kind = str(problem.kind).lower()
    return any(fragment in kind for fragment in kinds)


def _blamed(report: VerifyReport) -> set[int]:
    """Seqs of the events the report points at (box-level problems carry no positive seq)."""
    return {p.seq for p in report.problems if isinstance(p.seq, int) and p.seq > 0}


def _as_set(seq: int | set[int]) -> set[int]:
    return {seq} if isinstance(seq, int) else seq


def assert_detected(report: VerifyReport, seq: int | set[int], kinds: Sequence[str]) -> None:
    """ok=False and some problem at ``seq`` (or at one of a documented set) of the right family."""
    accepted = _as_set(seq)
    assert report.ok is False, _describe(report)
    assert any(p.seq in accepted and _matches(p, kinds) for p in report.problems), (
        f"expected a problem at seq {sorted(accepted)} with a kind like {kinds}: "
        + _describe(report)
    )


def assert_first_blamed(report: VerifyReport, seq: int | set[int]) -> None:
    """Nothing before the tampered event is blamed."""
    assert min(_blamed(report), default=None) in _as_set(seq), _describe(report)


# --- Controls: what is NOT tampering -------------------------------------------------------------


def test_an_intact_box_verifies(box: Box) -> None:
    report = _verify(box)

    assert report.ok is True, _describe(report)
    assert report.checked == LAST
    assert not report.problems


def test_an_intact_box_without_a_checkpoint_verifies(tmp_path: Path, clock: Clock) -> None:
    with BlackBox(tmp_path / "blackbox.sqlite3", KEY, clock=clock) as bb:
        for event in EVENTS:
            _append(bb, event)
        report = bb.verify()

    assert report.ok is True, _describe(report)
    assert report.checked == LAST


def test_a_clock_that_goes_backwards_is_a_warning_not_tampering(
    tmp_path: Path, clock: Clock
) -> None:
    box = Box(tmp_path / "blackbox.sqlite3", tmp_path / "blackbox.checkpoint")
    _fill(box, clock, EVENTS[:2])
    clock.advance(timedelta(hours=-1))
    _fill(box, clock, EVENTS[2:])
    with _raw(box.db) as conn:
        assert _row(conn, 3)["ts"] < _row(conn, 2)["ts"]

    report = _verify(box)

    assert report.ok is True, _describe(report)
    assert report.checked == LAST


def test_reserialising_the_checkpoint_with_the_same_values_is_not_tampering(box: Box) -> None:
    """Control for the forgery tests below: they rewrite the file with json.dumps, so a rewrite
    that keeps every value must still verify (the mac covers the fields, not the file layout)."""
    checkpoint = _load_checkpoint(box.checkpoint)
    box.checkpoint.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")

    report = _verify(box)

    assert report.ok is True, _describe(report)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE events SET risk = 0 WHERE seq = 3",
        "DELETE FROM events WHERE seq = 3",
        "DELETE FROM events WHERE seq = 5",
        "DELETE FROM events",
    ],
)
def test_raw_update_and_delete_are_refused_by_the_triggers(box: Box, statement: str) -> None:
    with _raw(box.db) as conn, pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute(statement)

    assert _verify(box).ok is True


# --- Changing events -----------------------------------------------------------------------------


def _plus_1us(ts: str) -> str:
    return (datetime.strptime(ts, TS_FORMAT) + timedelta(microseconds=1)).strftime(TS_FORMAT)


def _details(**dumps: Any) -> Callable[[str], str]:
    def transform(old: str) -> str:
        return json.dumps(json.loads(old), **dumps)

    return transform


def _details_edit(edit: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[str], str]:
    def transform(old: str) -> str:
        return _canonical(edit(json.loads(old))).decode()

    return transform


FIELD_TAMPERS = [
    pytest.param("ts", _plus_1us, HASH, id="ts-plus-1us"),
    pytest.param("ts", lambda old: old.replace("Z", "+00:00"), INVALID, id="ts-same-instant"),
    pytest.param("ts", lambda old: "yesterday", INVALID, id="ts-malformed"),
    pytest.param("source", lambda old: "exec", HASH, id="source-other-known"),
    pytest.param("source", lambda old: old.upper(), INVALID, id="source-uppercase"),
    pytest.param("source", lambda old: "evil", INVALID, id="source-unknown"),
    pytest.param("action", lambda old: "read", HASH, id="action"),
    pytest.param("action", lambda old: old + " ", INVALID, id="action-trailing-space"),
    pytest.param("target", lambda old: INNOCENT, HASH, id="target"),
    pytest.param(
        "target", lambda old: unicodedata.normalize("NFD", old), INVALID, id="target-unicode-nfd"
    ),
    pytest.param("details", _details_edit(lambda d: {**d, "bytes": 11}), HASH, id="details-value"),
    pytest.param(
        "details", _details_edit(lambda d: {**d, "ok": True}), HASH, id="details-extra-key"
    ),
    pytest.param(
        "details",
        _details_edit(lambda d: {k: v for k, v in d.items() if k != "note"}),
        HASH,
        id="details-dropped-key",
    ),
    pytest.param(
        "details", _details(sort_keys=True, ensure_ascii=False), INVALID, id="details-whitespace"
    ),
    pytest.param(
        "details",
        lambda old: json.dumps(
            dict(reversed(json.loads(old).items())), separators=(",", ":"), ensure_ascii=False
        ),
        INVALID,
        id="details-key-order",
    ),
    pytest.param(
        "details",
        _details(sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        INVALID,
        id="details-ascii-escape",
    ),
    pytest.param("risk", lambda old: 0, HASH, id="risk-lowered"),
    pytest.param("risk", lambda old: 3, HASH, id="risk-raised"),
    pytest.param("risk", lambda old: 7, INVALID, id="risk-out-of-range"),
    pytest.param("risk", lambda old: "high", INVALID, id="risk-not-a-number"),
    pytest.param("snapshot_id", lambda old: SNAP_B, HASH, id="snapshot-other"),
    pytest.param("snapshot_id", lambda old: None, HASH, id="snapshot-removed"),
    pytest.param("snapshot_id", lambda old: "../../etc/passwd", INVALID, id="snapshot-invalid"),
    pytest.param("prev_hash", lambda old: GENESIS, CHAIN, id="prev-hash-genesis"),
    pytest.param("prev_hash", lambda old: old.upper(), CHAIN, id="prev-hash-uppercase"),
    pytest.param("hash", lambda old: "f" * 64, HASH, id="hash-random"),
    pytest.param("hash", lambda old: old.upper(), HASH, id="hash-uppercase"),
]


@pytest.mark.parametrize(("column", "transform", "kinds"), FIELD_TAMPERS)
def test_changing_a_field_of_an_intermediate_event_is_detected(
    box: Box, column: str, transform: Callable[[Any], Any], kinds: Sequence[str]
) -> None:
    with tamper(box.db) as conn:
        old = _row(conn, TARGET)[column]
        new = transform(old)
        assert new != old, "the attack must really change the stored value"
        _set(conn, TARGET, column, new)

    report = _verify(box)

    assert_detected(report, TARGET, kinds)
    assert_first_blamed(report, TARGET)


@pytest.mark.parametrize("seq", [1, LAST])
def test_changing_the_first_or_the_last_event_is_detected(box: Box, seq: int) -> None:
    with tamper(box.db) as conn:
        _set(conn, seq, "target", INNOCENT)

    report = _verify(box)

    assert_detected(report, seq, HASH)
    assert_first_blamed(report, seq)


def test_swapping_prev_hash_with_the_next_event_is_detected(box: Box) -> None:
    with tamper(box.db) as conn:
        this, following = _row(conn, TARGET), _row(conn, TARGET + 1)
        _set(conn, TARGET, "prev_hash", following["prev_hash"])
        _set(conn, TARGET + 1, "prev_hash", this["prev_hash"])

    report = _verify(box)

    assert_detected(report, TARGET, CHAIN)
    assert_first_blamed(report, TARGET)


def test_pointing_prev_hash_at_an_older_event_is_detected(box: Box) -> None:
    with tamper(box.db) as conn:
        _set(conn, TARGET, "prev_hash", _row(conn, 1)["hash"])

    report = _verify(box)

    assert_detected(report, TARGET, CHAIN)
    assert_first_blamed(report, TARGET)


def test_insert_or_replace_cannot_rewrite_an_event_unnoticed(box: Box) -> None:
    """REPLACE deletes the old row without firing DELETE triggers (unless recursive_triggers is
    on in the attacker's own connection), so the spec's two triggers alone cannot stop it.
    Either an extra trigger refuses it and the box stays intact, or the HMAC exposes it."""
    with _raw(box.db) as conn:
        row = _row(conn, TARGET)
        try:
            _insert(conn, {**row, "target": INNOCENT}, verb="INSERT OR REPLACE")
        except sqlite3.DatabaseError as error:
            assert "append-only" in str(error)
        replaced = _row(conn, TARGET)["target"] == INNOCENT

    report = _verify(box)

    if replaced:
        assert_detected(report, TARGET, HASH)
        assert_first_blamed(report, TARGET)
    else:
        assert report.ok is True, _describe(report)


def test_appending_after_tampering_does_not_launder_it(box: Box, clock: Clock) -> None:
    with tamper(box.db) as conn:
        _set(conn, TARGET, "target", INNOCENT)
    _fill(box, clock, EVENTS[:1])

    report = _verify(box)

    assert_detected(report, TARGET, HASH)
    assert_first_blamed(report, TARGET)


@pytest.mark.parametrize(
    "corrupt",
    [
        pytest.param('{"bytes":10,"mode":"w"', id="truncated-json"),
        pytest.param("", id="empty"),
        pytest.param("[1,2,3]", id="not-an-object"),
        pytest.param("null", id="null"),
        pytest.param(12, id="integer"),
        pytest.param(b"\xff\xfe{}", id="invalid-utf8-blob"),
    ],
)
def test_corrupt_details_are_reported_not_raised(box: Box, corrupt: Any) -> None:
    with tamper(box.db) as conn:
        _set(conn, TARGET, "details", corrupt)

    report = _verify(box)

    assert_detected(report, TARGET, INVALID)
    assert_first_blamed(report, TARGET)


# --- Deleting events -----------------------------------------------------------------------------


@pytest.mark.parametrize("deleted", [{TARGET}, {1}, {2, 3}], ids=["middle", "first", "two"])
def test_deleting_intermediate_events_is_detected(box: Box, deleted: set[int]) -> None:
    """The spec leaves open whether a gap is reported at the missing seq or at the first event
    after it, so any seq from the first missing one to the next present one is accepted."""
    with tamper(box.db) as conn:
        _delete(conn, *deleted)
    accepted = set(range(min(deleted), max(deleted) + 2))

    report = _verify(box)

    assert_detected(report, accepted, GAP)
    assert_first_blamed(report, accepted)


@pytest.mark.parametrize("deleted", [1, 2, LAST - 1])
def test_deleting_the_last_events_is_detected_by_the_checkpoint(box: Box, deleted: int) -> None:
    """Only the checkpoint knows how far the chain went. The problem may point at the first
    missing event or at the checkpoint's seq; the events that remain are not blamed."""
    kept = LAST - deleted
    with tamper(box.db) as conn:
        _delete(conn, *range(kept + 1, LAST + 1))

    report = _verify(box)

    assert_detected(report, {kept + 1, LAST}, CHECKPOINT)
    assert all(seq > kept for seq in _blamed(report)), _describe(report)


def test_deleting_every_event_is_detected(box: Box) -> None:
    with tamper(box.db) as conn:
        conn.execute("DELETE FROM events")

    report = _verify(box)

    assert_detected(report, {1, LAST}, CHECKPOINT)
    assert report.checked == 0


def _box_with_backup(tmp_path: Path, clock: Clock) -> tuple[Box, Path, bytes]:
    """A box of LAST events, plus a consistent copy of its database and checkpoint at seq 3."""
    box = Box(tmp_path / "blackbox.sqlite3", tmp_path / "blackbox.checkpoint")
    _fill(box, clock, EVENTS[:3])
    saved_db = tmp_path / "saved.sqlite3"
    _backup(box.db, saved_db)
    saved_checkpoint = box.checkpoint.read_bytes()
    _fill(box, clock, EVENTS[3:])
    return box, saved_db, saved_checkpoint


def test_rolling_the_database_back_to_an_older_copy_is_detected(
    tmp_path: Path, clock: Clock
) -> None:
    box, saved_db, _ = _box_with_backup(tmp_path, clock)
    _backup(saved_db, box.db)

    report = _verify(box)

    assert_detected(report, {4, LAST}, CHECKPOINT)
    assert all(seq >= 4 for seq in _blamed(report)), _describe(report)


def test_known_gap_restoring_an_older_database_and_checkpoint_together(
    tmp_path: Path, clock: Clock
) -> None:
    """KNOWN GAP, accepted by the spec: with an older genuine checkpoint next to the older
    database, nothing on this machine remembers that events 4 and 5 existed. Only the copy of
    the checkpoint sent to Telegram (T09) catches it. If this starts failing, update the spec."""
    box, saved_db, saved_checkpoint = _box_with_backup(tmp_path, clock)
    _backup(saved_db, box.db)
    box.checkpoint.write_bytes(saved_checkpoint)

    report = _verify(box)

    assert report.ok is True, _describe(report)
    assert report.checked == 3


def test_cutting_the_tail_and_deleting_the_checkpoint_is_detected(box: Box) -> None:
    """Scenario D of the T02 review: this used to be a known gap (a missing checkpoint was only
    a warning). The box now starts with a genesis checkpoint, so its absence is tampering."""
    with tamper(box.db) as conn:
        _delete(conn, LAST - 1, LAST)
    box.checkpoint.unlink()

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, CHECKPOINT) for p in report.problems), _describe(report)
    assert report.checked == LAST - 2


def test_after_cutting_the_tail_and_deleting_the_checkpoint_appending_is_refused(
    box: Box, clock: Clock
) -> None:
    """Scenario D, second half: the next genuine append must not write a fresh checkpoint over
    the evidence, which would make the cut tail invisible for good."""
    with tamper(box.db) as conn:
        _delete(conn, LAST - 1, LAST)
    box.checkpoint.unlink()

    with BlackBox(box.db, KEY, checkpoint_path=box.checkpoint, clock=clock) as recorder:
        with pytest.raises(BlackBoxError):
            _append(recorder, EVENTS[0])

    assert not box.checkpoint.exists()
    assert _verify(box).ok is False


def test_rolling_back_the_tail_and_the_checkpoint_is_caught_by_the_live_recorder(
    tmp_path: Path, clock: Clock
) -> None:
    """Scenario C: with a copy of the checkpoint taken at seq 3, the attacker cuts events 4-5
    and restores the copy. A fresh verifier cannot tell (the known gap above), but the process
    that recorded 4-5 reports it and refuses to extend the chain over it."""
    box = Box(tmp_path / "blackbox.sqlite3", tmp_path / "blackbox.checkpoint")
    _fill(box, clock, EVENTS[:3])
    saved_checkpoint = box.checkpoint.read_bytes()
    with BlackBox(box.db, KEY, checkpoint_path=box.checkpoint, clock=clock) as recorder:
        for event in EVENTS[3:]:
            _append(recorder, event)
        with tamper(box.db) as conn:
            _delete(conn, 4, LAST)
        box.checkpoint.write_bytes(saved_checkpoint)

        assert _verify(box).ok is True  # the known gap, for a verifier without memory
        report = recorder.verify()
        with pytest.raises(BlackBoxError):
            _append(recorder, EVENTS[0])

    assert_detected(report, 4, (*CHECKPOINT, "roll", "back"))
    with _raw(box.db) as conn:
        assert conn.execute("SELECT MAX(seq) FROM events").fetchone()[0] == 3


# --- Inserting, reordering and duplicating events ------------------------------------------------


def test_appending_a_fake_event_hashed_without_the_key_is_detected(box: Box) -> None:
    with tamper(box.db) as conn:
        head = _row(conn, LAST)
        _insert(conn, _unkeyed_event(LAST + 1, head["hash"], head["ts"]))

    report = _verify(box)

    assert_detected(report, LAST + 1, HASH)
    assert_first_blamed(report, LAST + 1)


def test_inserting_a_fake_event_in_the_middle_is_detected(box: Box) -> None:
    with tamper(box.db) as conn:
        _shift(conn, TARGET, 1)
        previous = _row(conn, TARGET - 1)
        _insert(conn, _unkeyed_event(TARGET, previous["hash"], previous["ts"]))

    report = _verify(box)

    assert_detected(report, TARGET, HASH)
    assert_first_blamed(report, TARGET)


@pytest.mark.parametrize(("a", "b"), [(1, 2), (2, 4), (LAST - 1, LAST)])
def test_reordering_events_is_detected(box: Box, a: int, b: int) -> None:
    with tamper(box.db) as conn:
        _swap(conn, a, b)

    report = _verify(box)

    assert_detected(report, a, CHAIN)
    assert_first_blamed(report, a)


def test_renumbering_events_is_detected(box: Box) -> None:
    """Events 3..5 become 4..6: a gap at 3, and every moved event's seq no longer matches its
    hash. As with deletions, the gap may be reported at 3 or at 4."""
    with tamper(box.db) as conn:
        _shift(conn, TARGET, 1)

    report = _verify(box)

    assert_detected(report, {TARGET, TARGET + 1}, GAP)
    assert_first_blamed(report, {TARGET, TARGET + 1})


@pytest.mark.parametrize("copied", [TARGET, LAST])
def test_duplicating_an_event_under_a_new_seq_is_detected(box: Box, copied: int) -> None:
    with tamper(box.db) as conn:
        _insert(conn, {**_row(conn, copied), "seq": LAST + 1})

    report = _verify(box)

    assert_detected(report, LAST + 1, CHAIN)
    assert_first_blamed(report, LAST + 1)


# --- Keys ----------------------------------------------------------------------------------------


@pytest.fixture
def forged(tmp_path: Path, clock: Clock) -> Box:
    """The attacker's own box: the victim's events with event 3 rewritten, every hash and the
    checkpoint computed by the real implementation, but with a key that is not the victim's."""
    events = list(EVENTS)
    events[TARGET - 1] = replace(events[TARGET - 1], target=INNOCENT)
    return _make_box(tmp_path / "attacker", clock, events, key=ATTACKER_KEY)


@pytest.mark.parametrize("with_checkpoint", [False, True], ids=["events", "events+checkpoint"])
def test_rechaining_with_another_key_is_detected(
    box: Box, forged: Box, with_checkpoint: bool
) -> None:
    _transplant(box.db, forged.db)
    if with_checkpoint:
        shutil.copyfile(forged.checkpoint, box.checkpoint)

    report = _verify(box)

    assert_detected(report, 1, HASH)
    assert_first_blamed(report, 1)


def test_replacing_the_whole_box_with_an_attacker_keyed_one_is_detected(
    box: Box, forged: Box
) -> None:
    _transplant(box.db, forged.db, meta=True)
    shutil.copyfile(forged.checkpoint, box.checkpoint)
    # Control: the forgery is internally consistent, so only the key can expose it.
    assert _verify(box, ATTACKER_KEY).ok is True

    report = _verify_or_refuse(box, KEY)

    if report is not None:  # refusing to open (BlackBoxError) is a detection too
        assert report.ok is False, _describe(report)
        key_problem = any(_matches(p, KEY_ID) for p in report.problems)
        assert key_problem or 1 in _blamed(report), _describe(report)


def test_opening_with_the_wrong_key_is_detected(box: Box) -> None:
    report = _verify_or_refuse(box, ATTACKER_KEY)

    if report is not None:  # refusing to open (BlackBoxError) is a detection too
        assert report.ok is False, _describe(report)
        key_problem = any(_matches(p, KEY_ID) for p in report.problems)
        assert key_problem or 1 in _blamed(report), _describe(report)


def test_altering_the_stored_key_id_is_detected(box: Box) -> None:
    with tamper(box.db) as conn:
        changed = conn.execute(
            """UPDATE meta SET "value" = 'forged-' || "value" WHERE "key" = 'key_id'"""
        ).rowcount
        assert changed == 1

    report = _verify_or_refuse(box, KEY)

    if report is not None:  # refusing to open (BlackBoxError) is a detection too
        assert report.ok is False, _describe(report)
        assert any(_matches(p, KEY_ID) for p in report.problems), _describe(report)


# --- Checkpoint ----------------------------------------------------------------------------------


CHECKPOINT_FORGERIES = [
    pytest.param(lambda cp: {**cp, "mac": "f" * 64}, id="mac-random"),
    pytest.param(lambda cp: {**cp, "mac": _sha256_mac(cp)}, id="mac-sha256-without-key"),
    pytest.param(lambda cp: {**cp, "mac": _attacker_mac(cp)}, id="mac-hmac-with-another-key"),
    pytest.param(_unsigned, id="mac-missing"),
    pytest.param(lambda cp: {**cp, "seq": cp["seq"] + 1}, id="seq-bumped"),
    pytest.param(lambda cp: {**cp, "hash": "a" * 64}, id="hash-replaced"),
    pytest.param(lambda cp: {**cp, "ts": "2020-01-01T00:00:00.000000Z"}, id="ts-replaced"),
    pytest.param(lambda cp: {**cp, "key_id": f"forged-{cp['key_id']}"}, id="key-id-replaced"),
]


@pytest.mark.parametrize("forge", CHECKPOINT_FORGERIES)
def test_forging_the_checkpoint_is_detected(
    box: Box, forge: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    _save_checkpoint(box.checkpoint, forge(_load_checkpoint(box.checkpoint)))

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, CHECKPOINT) for p in report.problems), _describe(report)
    assert all(seq >= LAST for seq in _blamed(report)), "the events themselves are intact"


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"not json", id="not-json"),
        pytest.param(b"[]", id="not-an-object"),
        pytest.param(b'{"seq": 5}', id="missing-fields"),
        pytest.param(b"\xff\xfe", id="invalid-utf8"),
        pytest.param(
            b'{"seq":3,"hash":"\\ud800","ts":"x","key_id":"x","mac":"x"}', id="lone-surrogate"
        ),
    ],
)
def test_a_corrupt_checkpoint_is_reported_not_raised(box: Box, content: bytes) -> None:
    """A genuine checkpoint is written atomically, so a corrupt one is tampering, not a crash."""
    box.checkpoint.write_bytes(content)

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, CHECKPOINT) for p in report.problems), _describe(report)
    assert all(seq >= LAST for seq in _blamed(report)), "the events themselves are intact"


@pytest.mark.parametrize(
    "forge_mac",
    [
        pytest.param(lambda cp: cp["mac"], id="old-mac"),
        pytest.param(lambda cp: "f" * 64, id="random-mac"),
        pytest.param(_sha256_mac, id="sha256-without-key"),
        pytest.param(_attacker_mac, id="hmac-with-another-key"),
    ],
)
def test_cutting_the_tail_and_rewriting_the_checkpoint_without_the_key_is_detected(
    box: Box, forge_mac: Callable[[dict[str, Any]], str]
) -> None:
    kept = LAST - 2
    with tamper(box.db) as conn:
        head = _row(conn, kept)
        _delete(conn, *range(kept + 1, LAST + 1))
    claim = {
        **_load_checkpoint(box.checkpoint),
        "seq": kept,
        "hash": head["hash"],
        "ts": head["ts"],
    }
    _save_checkpoint(box.checkpoint, {**claim, "mac": forge_mac(claim)})

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, CHECKPOINT) for p in report.problems), _describe(report)
    assert all(seq >= kept for seq in _blamed(report)), _describe(report)


def test_swapping_in_another_genuine_history_of_the_same_length_is_detected(
    box: Box, tmp_path: Path, clock: Clock
) -> None:
    """Same key, same length, different events: every hash is genuine and only the checkpoint
    (same seq, different hash) can tell. This is the spec's 'manipulación' branch."""
    events = [replace(event, target=event.target + ".alt") for event in EVENTS]
    sibling = _make_box(tmp_path / "sibling", clock, events)
    _transplant(box.db, sibling.db)
    # Control: on its own the swapped-in history is genuine.
    assert _verify(Box(box.db, sibling.checkpoint)).ok is True

    report = _verify(box)

    assert_detected(report, LAST, (*CHECKPOINT, *HASH))
    assert all(seq >= LAST for seq in _blamed(report)), _describe(report)


# --- Triggers ------------------------------------------------------------------------------------


@pytest.mark.parametrize("dropped", ["UPDATE", "DELETE", "both"])
def test_dropping_the_append_only_triggers_is_detected(box: Box, dropped: str) -> None:
    with _raw(box.db) as conn:
        triggers = _triggers(conn)
        assert {_fires_on(sql) for _, sql in triggers} >= {"UPDATE", "DELETE"}
        for name, sql in triggers:
            if dropped in ("both", _fires_on(sql)):
                conn.execute(f'DROP TRIGGER "{name}"')

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, TRIGGER) for p in report.problems), _describe(report)
    assert not _blamed(report), "the events themselves are intact"


def test_dropping_the_triggers_under_a_running_box_is_detected(box: Box) -> None:
    with BlackBox(box.db, KEY, checkpoint_path=box.checkpoint) as bb:
        with _raw(box.db) as conn:
            for name, _ in _triggers(conn):
                conn.execute(f'DROP TRIGGER "{name}"')
        report = bb.verify()

    assert report.ok is False, _describe(report)
    assert any(_matches(p, TRIGGER) for p in report.problems), _describe(report)


def test_replacing_the_triggers_with_no_op_ones_is_detected(box: Box) -> None:
    """Goes one step past the literal spec ('que existan'): same-named triggers that do nothing
    leave the box writable, so checking the names alone is not enough."""
    with _raw(box.db) as conn:
        for name, sql in _triggers(conn):
            statement = _fires_on(sql)
            conn.execute(f'DROP TRIGGER "{name}"')
            conn.execute(
                f'CREATE TRIGGER "{name}" BEFORE {statement} ON events BEGIN SELECT 1; END'
            )
        conn.execute("UPDATE events SET risk = risk WHERE seq = 1")  # no longer refused

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, TRIGGER) for p in report.problems), _describe(report)
    assert not _blamed(report), "the events themselves are intact"


# --- Corrupt storage and foreign schema objects (added while reconciling with the implementation) -

TABLE = ("schema", "table")
UNTYPED_EVENTS = (
    "CREATE TABLE events (seq, ts, source, action, target, details, risk, snapshot_id, "
    "prev_hash, hash)"
)


def _recreate_events(conn: sqlite3.Connection, create_sql: str) -> None:
    """Swap the events table for one built with ``create_sql``, keeping every row."""
    conn.execute("ALTER TABLE events RENAME TO events_old")
    conn.execute(create_sql)
    conn.execute("INSERT INTO events SELECT * FROM events_old")
    conn.execute("DROP TABLE events_old")


@pytest.mark.parametrize(
    "column",
    ["ts", "source", "action", "target", "details", "snapshot_id", "prev_hash", "hash"],
)
def test_text_that_is_not_utf8_is_reported_at_its_event_not_raised(box: Box, column: str) -> None:
    """Raw bytes stored as TEXT (not as a BLOB) used to abort the whole walk with a decode
    error and no seq. They are a changed field: blame the event and keep walking."""
    with tamper(box.db) as conn:
        old = _row(conn, TARGET)[column]
        conn.execute(
            f"UPDATE events SET {column} = CAST(? AS TEXT) WHERE seq = ?",  # noqa: S608
            (str(old).encode() + b"\xff", TARGET),
        )

    report = _verify(box)

    assert_detected(report, TARGET, INVALID)
    assert_first_blamed(report, TARGET)
    assert report.checked == LAST


@pytest.mark.parametrize(
    "new_seq",
    [
        pytest.param("x", id="text"),
        pytest.param(None, id="null"),
        pytest.param(2.5, id="real"),
        pytest.param(float(TARGET), id="integral-real"),
        pytest.param(b"\x03", id="blob"),
    ],
)
def test_a_non_integer_seq_in_a_recreated_table_is_reported_not_raised(
    box: Box, new_seq: Any
) -> None:
    """Only a re-created table without INTEGER PRIMARY KEY can hold such a seq. verify() used
    to raise TypeError comparing it; now the table, the odd row and the hole are reported."""
    with tamper(box.db) as conn:
        _recreate_events(conn, UNTYPED_EVENTS)
        _move(conn, TARGET, new_seq)

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, TABLE) for p in report.problems), _describe(report)
    assert_detected(report, TARGET, GAP)
    assert_first_blamed(report, TARGET)
    assert report.checked == LAST


def test_recreating_the_events_table_without_its_constraints_is_detected(box: Box) -> None:
    """Every row is kept intact, but the CHECK on risk and the INTEGER PRIMARY KEY on seq are
    gone: the box would accept rows the spec forbids, so the table itself must be reported."""
    with tamper(box.db) as conn:
        _recreate_events(conn, UNTYPED_EVENTS)

    report = _verify(box)

    assert report.ok is False, _describe(report)
    assert any(_matches(p, TABLE) for p in report.problems), _describe(report)
    assert not _blamed(report), "the events themselves are intact"


def test_a_foreign_trigger_that_silently_drops_events_is_detected(box: Box) -> None:
    """RAISE(IGNORE) in an extra BEFORE INSERT trigger makes SQLite skip the row and still
    commit. append() must not report such an event as recorded, and verify() must flag the
    trigger even with no checkpoint to show the missing tail."""
    with _raw(box.db) as conn:
        conn.execute(
            "CREATE TRIGGER hide_evil BEFORE INSERT ON events WHEN NEW.target LIKE '%evil%' "
            "BEGIN SELECT RAISE(IGNORE); END"
        )

    with BlackBox(box.db, KEY, checkpoint_path=box.checkpoint) as bb:
        with pytest.raises(BlackBoxError):
            bb.append(Source.EXEC, "run", "evil --wipe-logs")
        report = bb.verify()

    assert report.ok is False, _describe(report)
    assert any(_matches(p, TRIGGER) for p in report.problems), _describe(report)
    assert not _blamed(report), "the stored events are intact"
    assert report.checked == LAST
    with BlackBox(box.db, KEY) as bb:  # no checkpoint: the trigger alone must give it away
        assert any(_matches(p, TRIGGER) for p in bb.verify().problems)
