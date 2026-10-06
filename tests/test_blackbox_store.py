"""Implementer-side tests of BlackBox. Attacks on a recorded box live in test_blackbox_tamper.py."""

import contextlib
import json
import multiprocessing
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from dataclasses import asdict
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.conftest import FakeClock, call_unblocking_fifo
from vigia.blackbox import (
    GENESIS,
    REDACTED,
    BlackBox,
    BlackBoxError,
    ProblemKind,
    Source,
    canonical,
    compute_hash,
)
from vigia.blackbox.chain import canonical_json
from vigia.blackbox.checkpoint import (
    CheckpointError,
    checkpoint_lock,
    read_checkpoint,
    write_checkpoint,
)
from vigia.blackbox.redact import MAX_TEXT_BYTES
from vigia.blackbox.store import TRIGGERS

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
LEAKED = "s3cr3tVALUE-0123456789abcdefXYZ"
SNAPSHOT_ID = "20261005T201530.123456Z-periodic"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "blackbox.db"


@pytest.fixture
def checkpoint(tmp_path: Path) -> Path:
    return tmp_path / "blackbox.checkpoint"


@pytest.fixture
def box(db: Path, checkpoint: Path, clock: FakeClock) -> Iterator[BlackBox]:
    with BlackBox(db, KEY, checkpoint_path=checkpoint, clock=clock) as black_box:
        yield black_box


def _raw(db: Path) -> sqlite3.Connection:
    return sqlite3.connect(db, isolation_level=None)


def _fill(box: BlackBox, count: int) -> None:
    for number in range(count):
        box.append(Source.FILE, "write", f"/workspace/file-{number}.txt")


def _kinds(problems: tuple) -> list[ProblemKind]:
    return [problem.kind for problem in problems]


# -- appending -------------------------------------------------------------------------


def test_first_event_starts_the_chain(box: BlackBox) -> None:
    event = box.append(Source.FILE, "write", "/workspace/a.txt", details={"size": 3}, risk=1)
    assert event.seq == 1
    assert event.prev_hash == GENESIS
    assert event.ts == "2026-10-05T08:00:00.000001Z"  # .000000Z went to the genesis checkpoint
    assert event.source is Source.FILE
    assert (event.action, event.target, event.details, event.risk) == (
        "write",
        "/workspace/a.txt",
        {"size": 3},
        1,
    )
    assert event.snapshot_id is None
    assert event.hash == compute_hash(KEY, canonical(asdict(event)))


def test_each_event_chains_to_the_previous_one(box: BlackBox) -> None:
    events = [box.append(Source.EXEC, "run", f"cmd {n}") for n in range(3)]
    assert [event.seq for event in events] == [1, 2, 3]
    assert events[1].prev_hash == events[0].hash
    assert events[2].prev_hash == events[1].hash
    assert events[0].ts < events[1].ts < events[2].ts
    assert len({event.hash for event in events}) == 3


def test_events_survive_reopening(db: Path, checkpoint: Path, clock: FakeClock) -> None:
    with BlackBox(db, KEY, checkpoint_path=checkpoint, clock=clock) as box:
        first = box.append(Source.NET, "request", "https://example.com")
        second = box.append(Source.GATE, "approve", "https://example.com", risk=3)
    with BlackBox(db, KEY, checkpoint_path=checkpoint, clock=clock) as box:
        assert box.events() == [first, second]
        assert box.head() == (2, second.hash)
        assert box.append(Source.SYSTEM, "start", "vigia").prev_hash == second.hash
        assert box.verify().ok


def test_source_may_be_given_as_plain_text(box: BlackBox) -> None:
    assert box.append("snapshot", "take", SNAPSHOT_ID).source is Source.SNAPSHOT


def test_risk_and_snapshot_id_are_stored(box: BlackBox) -> None:
    box.append(Source.FILE, "delete", "/workspace/x", risk=3, snapshot_id=SNAPSHOT_ID)
    [event] = box.events()
    assert (event.risk, event.snapshot_id) == (3, SNAPSHOT_ID)


def test_target_and_details_are_redacted_before_they_reach_the_disk(
    box: BlackBox, tmp_path: Path
) -> None:
    event = box.append(
        Source.NET,
        "request",
        f"https://api.example.com/v1?api_key={LEAKED}",
        details={"headers": {"Authorization": f"Bearer {LEAKED}"}, "body": f"token={LEAKED}"},
    )
    assert event.target == f"https://api.example.com/v1?api_key={REDACTED}"
    assert event.details == {"headers": {"Authorization": REDACTED}, "body": f"token={REDACTED}"}
    assert box.events() == [event]
    box.close()
    for path in tmp_path.iterdir():
        assert LEAKED.encode() not in path.read_bytes(), path


def test_long_target_and_details_are_cut_to_4_kib(box: BlackBox) -> None:
    event = box.append(Source.EXEC, "run", "x" * 10_000, details={"out": "y" * 10_000})
    assert len(event.target.encode()) <= MAX_TEXT_BYTES
    assert len(event.details["out"].encode()) <= MAX_TEXT_BYTES
    assert "truncated" in event.target


def test_details_are_stored_in_canonical_form(box: BlackBox, db: Path) -> None:
    box.append(Source.LLM, "complete", "claude", details={"b": 1, "a": "ñ", "c": [1, 2]})
    [(stored,)] = _raw(db).execute("SELECT details FROM events").fetchall()
    assert stored == '{"a":"ñ","b":1,"c":[1,2]}'


def test_the_returned_event_equals_what_is_read_back(box: BlackBox) -> None:
    event = box.append(Source.FILE, "write", "/w", details={"pair": (1, 2), "none": None})
    assert event.details == {"pair": [1, 2], "none": None}
    assert box.events() == [event]


def test_an_action_of_exactly_64_characters_is_accepted(box: BlackBox) -> None:
    assert box.append(Source.FILE, "a" * 64, "/w").action == "a" * 64


def test_the_action_is_redacted_too(box: BlackBox) -> None:
    assert box.append(Source.NET, f"token={LEAKED}", "/w").action == f"token={REDACTED}"
    with pytest.raises(ValueError, match="once redacted"):
        box.append(Source.NET, "x" * 50 + " cookie:abc", "/w")  # grows past 64 chars


@pytest.mark.parametrize(
    "kwargs",
    [
        {"source": "bogus"},
        {"source": 3},
        {"source": None},
        {"action": ""},
        {"action": "   "},
        {"action": "a" * 65},
        {"action": 5},
        {"action": "bad-\udcff"},
        {"target": None},
        {"target": b"/w"},
        {"details": [1, 2]},
        {"details": "text"},
        {"details": {"x": object()}},
        {"details": {"x": float("nan")}},
        {"details": {"x": b"bytes"}},
        {"details": {1: "a", "b": 2}},
        {"risk": -1},
        {"risk": 4},
        {"risk": True},
        {"risk": "1"},
        {"risk": 1.0},
        {"snapshot_id": "bad"},
        {"snapshot_id": "../20261005T201530.123456Z-periodic"},
        {"snapshot_id": "20261005T201530.123456Z-Periodic"},
        {"snapshot_id": 123},
    ],
)
def test_invalid_arguments_are_rejected_and_nothing_is_recorded(
    box: BlackBox, kwargs: dict
) -> None:
    arguments = {"source": Source.FILE, "action": "write", "target": "/w", **kwargs}
    source, action, target = (
        arguments.pop("source"),
        arguments.pop("action"),
        arguments.pop("target"),
    )
    with pytest.raises(ValueError):
        box.append(source, action, target, **arguments)
    assert box.head() is None
    assert box.append(Source.FILE, "write", "/w").seq == 1  # no seq was used up


def test_the_clock_must_be_timezone_aware(db: Path) -> None:
    with BlackBox(db, KEY, clock=lambda: datetime(2026, 10, 6, 12, 0)) as box:
        with pytest.raises(BlackBoxError, match="aware"):
            box.append(Source.FILE, "write", "/w")
        assert box.head() is None


def test_ts_is_stored_in_utc_with_microseconds(db: Path) -> None:
    madrid = timezone(timedelta(hours=2))
    clock = lambda: datetime(2026, 10, 6, 14, 26, 38, 774641, tzinfo=madrid)  # noqa: E731
    with BlackBox(db, KEY, clock=clock) as box:
        assert box.append(Source.FILE, "write", "/w").ts == "2026-10-06T12:26:38.774641Z"


# -- the database ----------------------------------------------------------------------


def test_database_files_are_private(box: BlackBox, db: Path) -> None:
    box.append(Source.FILE, "write", "/w")
    for path in (db, db.with_name(db.name + "-wal")):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path


def test_database_uses_wal_and_full_sync(box: BlackBox, db: Path) -> None:
    box.append(Source.FILE, "write", "/w")
    assert _raw(db).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn = box._conn
    assert conn is not None
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


def test_meta_holds_schema_version_and_key_id_but_not_the_key(box: BlackBox, db: Path) -> None:
    meta = dict(_raw(db).execute("SELECT key, value FROM meta").fetchall())
    assert set(meta) == {"schema_version", "key_id"}
    assert meta["schema_version"] == "1"
    assert KEY.hex() not in meta["key_id"]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE events SET target = 'x' WHERE seq = 2",
        "UPDATE events SET seq = 10 WHERE seq = 3",
        "DELETE FROM events WHERE seq = 3",
        "DELETE FROM events",
        "INSERT OR REPLACE INTO events SELECT * FROM events WHERE seq = 1",
        "INSERT INTO events (seq, ts, source, action, target, details, risk, prev_hash, hash) "
        "VALUES (10, 't', 'file', 'a', 't', '{}', 0, 'p', 'h')",
        "INSERT INTO events (ts, source, action, target, details, risk, prev_hash, hash) "
        "VALUES ('t', 'file', 'a', 't', '{}', 0, 'p', 'h')",
    ],
)
def test_triggers_make_events_append_only(box: BlackBox, db: Path, statement: str) -> None:
    _fill(box, 3)
    before = box.events()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        _raw(db).execute(statement)
    assert box.events() == before
    assert box.verify().ok


def test_open_never_recreates_a_dropped_trigger(db: Path, checkpoint: Path) -> None:
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as box:
        _fill(box, 2)
    _raw(db).execute("DROP TRIGGER events_no_update")
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as box:
        report = box.verify()
    assert not report.ok
    assert _kinds(report.problems) == [ProblemKind.TRIGGERS]
    triggers = {row[0] for row in _raw(db).execute("SELECT name FROM sqlite_master")}
    assert "events_no_update" not in triggers
    assert set(TRIGGERS) - {"events_no_update"} <= triggers


def test_a_foreign_sqlite_database_is_not_opened(db: Path) -> None:
    _raw(db).execute("CREATE TABLE notes (text TEXT)")
    with pytest.raises(BlackBoxError, match="not a black box"):
        BlackBox(db, KEY).open()


def test_a_file_that_is_not_a_database_is_not_opened(db: Path) -> None:
    db.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(BlackBoxError, match="cannot open"):
        BlackBox(db, KEY).open()


def test_an_unknown_schema_version_is_not_opened(db: Path) -> None:
    BlackBox(db, KEY).open().close()
    _raw(db).execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(BlackBoxError, match="schema version"):
        BlackBox(db, KEY).open()


@pytest.mark.parametrize("key", [b"short", bytes(33), "x" * 32])
def test_the_key_must_be_32_bytes(db: Path, key: object) -> None:
    with pytest.raises(ValueError):
        BlackBox(db, key)  # type: ignore[arg-type]


def test_a_key_that_is_not_this_box_s_cannot_append(db: Path) -> None:
    with BlackBox(db, KEY) as box:
        _fill(box, 2)
    with BlackBox(db, OTHER_KEY) as box:
        with pytest.raises(BlackBoxError, match="does not belong"):
            box.append(Source.FILE, "write", "/w")
        report = box.verify()
        assert box.head() is not None and box.head()[0] == 2
    assert not report.ok
    assert ProblemKind.KEY_MISMATCH in _kinds(report.problems)


def test_methods_open_the_box_on_first_use(db: Path) -> None:
    box = BlackBox(db, KEY)
    assert box.head() is None
    box.append(Source.FILE, "write", "/w")
    box.close()
    assert box.head() is not None  # reopens after close


def test_context_manager_returns_the_box(db: Path) -> None:
    box = BlackBox(db, KEY)
    with box as opened:
        assert opened is box


# -- reading ---------------------------------------------------------------------------


def test_head_of_an_empty_box_is_none(box: BlackBox) -> None:
    assert box.head() is None


def test_head_is_the_last_seq_and_hash(box: BlackBox) -> None:
    _fill(box, 2)
    last = box.append(Source.FILE, "write", "/w")
    assert box.head() == (3, last.hash)


@pytest.fixture
def mixed(box: BlackBox) -> BlackBox:
    for source in ("file", "net", "file", "exec", "file"):
        box.append(source, "act", "/t")
    return box


@pytest.mark.parametrize(
    ("kwargs", "seqs"),
    [
        ({}, [1, 2, 3, 4, 5]),
        ({"since_seq": 0}, [1, 2, 3, 4, 5]),
        ({"since_seq": 2}, [3, 4, 5]),
        ({"since_seq": 5}, []),
        ({"source": "file"}, [1, 3, 5]),
        ({"source": Source.NET}, [2]),
        ({"source": "llm"}, []),
        ({"limit": 2}, [1, 2]),
        ({"limit": 100}, [1, 2, 3, 4, 5]),
        ({"since_seq": 1, "source": "file", "limit": 1}, [3]),
    ],
)
def test_events_filters(mixed: BlackBox, kwargs: dict, seqs: list[int]) -> None:
    assert [event.seq for event in mixed.events(**kwargs)] == seqs


@pytest.mark.parametrize(
    "kwargs",
    [
        {"since_seq": -1},
        {"since_seq": "1"},
        {"since_seq": True},
        {"limit": 0},
        {"limit": -1},
        {"limit": True},
        {"source": "bogus"},
    ],
)
def test_events_rejects_invalid_filters(box: BlackBox, kwargs: dict) -> None:
    with pytest.raises(ValueError):
        box.events(**kwargs)


# -- concurrency -----------------------------------------------------------------------


def _append_from_threads(boxes: list[BlackBox], threads_per_box: int, each: int) -> None:
    errors: list[BaseException] = []

    def work(box: BlackBox, worker: int) -> None:
        try:
            for number in range(each):
                box.append(Source.FILE, "write", f"/w/{worker}/{number}")
        except BaseException as exc:  # reported below, never silenced
            errors.append(exc)

    workers = [
        threading.Thread(target=work, args=(box, index * threads_per_box + offset))
        for index, box in enumerate(boxes)
        for offset in range(threads_per_box)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert errors == []


def _assert_intact(db: Path, checkpoint: Path, total: int) -> None:
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as box:
        events = box.events()
        report = box.verify()
    assert [event.seq for event in events] == list(range(1, total + 1))
    assert report.ok, report.problems
    assert report.warnings == ()
    saved = read_checkpoint(checkpoint, KEY)
    assert saved is not None
    assert (saved.seq, saved.hash) == (total, events[-1].hash)


def test_threads_sharing_one_instance_get_contiguous_seqs(db: Path, checkpoint: Path) -> None:
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as box:
        _append_from_threads([box], threads_per_box=8, each=25)
    _assert_intact(db, checkpoint, 200)


def test_two_instances_on_the_same_database_get_contiguous_seqs(db: Path, checkpoint: Path) -> None:
    first = BlackBox(db, KEY, checkpoint_path=checkpoint).open()
    second = BlackBox(db, KEY, checkpoint_path=checkpoint).open()
    try:
        _append_from_threads([first, second], threads_per_box=4, each=20)
    finally:
        first.close()
        second.close()
    _assert_intact(db, checkpoint, 160)


def _append_in_child(db: str, checkpoint: str, count: int) -> None:
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as box:
        for number in range(count):
            box.append(Source.EXEC, "run", f"{os.getpid()}-{number}")


def test_several_processes_on_the_same_database_get_contiguous_seqs(
    db: Path, checkpoint: Path
) -> None:
    BlackBox(db, KEY, checkpoint_path=checkpoint).open().close()  # create it first
    context = multiprocessing.get_context("spawn")
    children = [
        context.Process(target=_append_in_child, args=(str(db), str(checkpoint), 30))
        for _ in range(3)
    ]
    for child in children:
        child.start()
    for child in children:
        child.join(timeout=60)
    assert [child.exitcode for child in children] == [0, 0, 0]
    _assert_intact(db, checkpoint, 90)


# -- checkpoint ------------------------------------------------------------------------


def test_every_append_rewrites_the_checkpoint(box: BlackBox, checkpoint: Path) -> None:
    for _ in range(3):
        event = box.append(Source.FILE, "write", "/w")
        saved = read_checkpoint(checkpoint, KEY)
        assert saved is not None
        assert (saved.seq, saved.hash, saved.ts) == (event.seq, event.hash, event.ts)
    assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600


def test_checkpoint_writes_leave_no_temporary_files(
    box: BlackBox, db: Path, checkpoint: Path, tmp_path: Path
) -> None:
    _fill(box, 3)
    names = {path.name for path in tmp_path.iterdir()}
    assert names <= {
        db.name,
        db.name + "-wal",
        db.name + "-shm",
        checkpoint.name,
        checkpoint.name + ".lock",
    }


def test_a_failed_checkpoint_write_keeps_the_old_one_and_says_the_event_was_recorded(
    box: BlackBox, checkpoint: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fill(box, 2)
    before = checkpoint.read_bytes()

    def broken_replace(src: object, dst: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("vigia.blackbox.checkpoint.os.replace", broken_replace)
    with pytest.raises(BlackBoxError, match="3 WAS recorded"):
        box.append(Source.FILE, "write", "/w")
    assert checkpoint.read_bytes() == before
    assert not [path for path in tmp_path.iterdir() if path.name.endswith(".tmp")]
    assert box.head() is not None and box.head()[0] == 3

    report = box.verify()  # a checkpoint behind the database is a warning, not tampering
    assert report.ok
    assert _kinds(report.warnings) == [ProblemKind.CHECKPOINT_BEHIND]
    assert report.warnings[0].seq == 2

    monkeypatch.undo()
    box.append(Source.FILE, "write", "/w")  # the next append catches up
    assert box.verify().warnings == ()


def test_append_refuses_when_the_checkpoint_is_ahead_of_the_database(
    tmp_path: Path, checkpoint: Path
) -> None:
    with BlackBox(tmp_path / "old.db", KEY, checkpoint_path=checkpoint) as old:
        _fill(old, 3)
    with BlackBox(tmp_path / "new.db", KEY, checkpoint_path=checkpoint) as box:
        with pytest.raises(BlackBoxError, match="refusing to append"):
            box.append(Source.FILE, "write", "/w")
        assert box.head() is None


def test_append_refuses_when_the_checkpoint_does_not_match_the_head(
    tmp_path: Path, checkpoint: Path
) -> None:
    with BlackBox(tmp_path / "old.db", KEY, checkpoint_path=checkpoint) as old:
        _fill(old, 2)
    with BlackBox(tmp_path / "new.db", KEY, checkpoint_path=checkpoint) as box:
        with pytest.raises(BlackBoxError):
            _fill(box, 1)
    with BlackBox(tmp_path / "other.db", KEY) as box:  # same seq, different hash
        _fill(box, 2)
        head = box.head()
    assert head is not None
    with BlackBox(tmp_path / "old.db", KEY, checkpoint_path=checkpoint) as old:
        write_checkpoint(checkpoint, KEY, seq=2, hash="f" * 64, ts="2026-10-06T00:00:00.000000Z")
        with pytest.raises(BlackBoxError, match="refusing to append"):
            old.append(Source.FILE, "write", "/w")
        assert old.head() is not None and old.head()[0] == 2


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"[]",
        b'{"seq": 1}',
        b'{"seq":1,"hash":"x","ts":"t","key_id":"k","mac":"m"}',
        b'{"seq":1,"hash":"\\ud800","ts":"t","key_id":"k","mac":"m"}',  # a lone surrogate
    ],
)
def test_append_refuses_when_the_checkpoint_is_forged(
    box: BlackBox, checkpoint: Path, content: bytes
) -> None:
    _fill(box, 1)
    checkpoint.write_bytes(content)
    with pytest.raises(BlackBoxError, match="forged or damaged"):
        box.append(Source.FILE, "write", "/w")
    assert box.head() is not None and box.head()[0] == 1


def test_a_checkpoint_signed_with_another_key_is_forged(box: BlackBox, checkpoint: Path) -> None:
    event = box.append(Source.FILE, "write", "/w")
    write_checkpoint(checkpoint, OTHER_KEY, seq=event.seq, hash=event.hash, ts=event.ts)
    report = box.verify()
    assert _kinds(report.problems) == [ProblemKind.CHECKPOINT_FORGED]
    assert "otra clave" in report.problems[0].detail


def test_a_missing_checkpoint_folder_fails_before_creating_the_box(
    db: Path, tmp_path: Path
) -> None:
    box = BlackBox(db, KEY, checkpoint_path=tmp_path / "missing" / "cp")
    with pytest.raises(BlackBoxError, match="checkpoint lock"):
        box.open()
    with _raw(db) as conn:  # no box without its genesis checkpoint
        assert conn.execute("SELECT name FROM sqlite_master").fetchall() == []


# -- verify ----------------------------------------------------------------------------


def test_an_empty_box_verifies(box: BlackBox) -> None:
    report = box.verify()
    assert report.ok
    assert (report.checked, report.last_seq, report.problems) == (0, None, ())
    assert report.warnings == ()  # the genesis checkpoint is there from the start


def test_an_intact_box_verifies_without_warnings(box: BlackBox) -> None:
    _fill(box, 5)
    report = box.verify()
    assert report.ok
    assert (report.checked, report.last_seq) == (5, 5)
    assert report.problems == report.warnings == ()


def test_without_a_checkpoint_verify_warns_but_passes(db: Path) -> None:
    with BlackBox(db, KEY) as box:
        _fill(box, 2)
        report = box.verify()
    assert report.ok
    assert _kinds(report.warnings) == [ProblemKind.CHECKPOINT_MISSING]


def test_a_clock_going_backwards_is_only_a_warning(db: Path, checkpoint: Path) -> None:
    times = iter(
        [
            datetime(2026, 10, 6, 11, 59, tzinfo=UTC),  # the genesis checkpoint
            datetime(2026, 10, 6, 12, 0, tzinfo=UTC),
            datetime(2026, 10, 6, 11, 0, tzinfo=UTC),
            datetime(2026, 10, 6, 13, 0, tzinfo=UTC),
        ]
    )
    with BlackBox(db, KEY, checkpoint_path=checkpoint, clock=lambda: next(times)) as box:
        _fill(box, 3)
        report = box.verify()
    assert report.ok
    assert _kinds(report.warnings) == [ProblemKind.CLOCK_BACKWARDS]
    assert report.warnings[0].seq == 2


def test_verify_reads_a_consistent_snapshot_while_others_append(db: Path, checkpoint: Path) -> None:
    writer = BlackBox(db, KEY, checkpoint_path=checkpoint).open()
    reader = BlackBox(db, KEY, checkpoint_path=checkpoint).open()
    stop = threading.Event()
    reports = []

    def keep_verifying() -> None:
        while not stop.is_set():
            reports.append(reader.verify())

    verifier = threading.Thread(target=keep_verifying)
    verifier.start()
    try:
        _fill(writer, 150)
    finally:
        stop.set()
        verifier.join()
        writer.close()
        reader.close()
    assert reports
    assert all(report.ok for report in reports), [r.problems for r in reports if not r.ok]


# -- review fixes (T02) ----------------------------------------------------------------


def _drop(db: Path, *statements: str) -> None:
    with contextlib.closing(_raw(db)) as conn:
        for statement in statements:
            conn.execute(statement)


def _table_count(db: Path) -> int:
    with contextlib.closing(_raw(db)) as conn:
        return conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]


@pytest.mark.parametrize(
    "details",
    [
        {10: "a", 9: "b"},
        {"n": {2: 1, 10: 2}},
        {1.5: "x", 10: "y"},
        {"items": [{3: 0, 20: 0}]},
    ],
)
def test_details_with_keys_that_are_not_text_still_verify(
    box: BlackBox, db: Path, details: dict
) -> None:
    event = box.append(Source.EXEC, "run", "x", details=details)
    with contextlib.closing(_raw(db)) as conn:
        (stored,) = conn.execute("SELECT details FROM events").fetchone()
    assert stored == canonical_json(json.loads(stored))  # a fixed point, as verify() expects
    assert box.events() == [event]
    report = box.verify()
    assert report.ok, report.problems


def test_creating_the_box_writes_a_genesis_checkpoint(box: BlackBox, checkpoint: Path) -> None:
    saved = read_checkpoint(checkpoint, KEY)
    assert saved is not None
    assert (saved.seq, saved.hash) == (0, GENESIS)


def test_creating_a_box_never_overwrites_an_existing_checkpoint(
    tmp_path: Path, checkpoint: Path
) -> None:
    with BlackBox(tmp_path / "old.db", KEY, checkpoint_path=checkpoint) as old:
        _fill(old, 2)
    before = checkpoint.read_bytes()
    with BlackBox(tmp_path / "new.db", KEY, checkpoint_path=checkpoint) as new:
        assert checkpoint.read_bytes() == before  # it may prove a wiped database
        assert _kinds(new.verify().problems) == [ProblemKind.TRUNCATED]


def test_a_deleted_checkpoint_is_tampering_once_there_are_events(
    box: BlackBox, checkpoint: Path
) -> None:
    _fill(box, 2)
    checkpoint.unlink()
    assert _kinds(box.verify().problems) == [ProblemKind.CHECKPOINT_DELETED]
    with pytest.raises(BlackBoxError, match="refusing to append"):
        box.append(Source.FILE, "write", "/w")
    assert not checkpoint.exists()  # the evidence is not papered over with a new one
    assert box.head() is not None and box.head()[0] == 2


def test_without_events_a_missing_checkpoint_is_only_a_warning(
    box: BlackBox, checkpoint: Path
) -> None:
    checkpoint.unlink()
    report = box.verify()
    assert report.ok
    assert _kinds(report.warnings) == [ProblemKind.CHECKPOINT_MISSING]
    box.append(Source.FILE, "write", "/w")
    assert box.verify().warnings == ()


def test_an_instance_refuses_to_append_once_the_chain_went_back(
    box: BlackBox, db: Path, checkpoint: Path
) -> None:
    _fill(box, 3)
    old_checkpoint = checkpoint.read_bytes()
    _fill(box, 2)
    _drop(
        db,
        "DROP TRIGGER events_no_delete",
        "DELETE FROM events WHERE seq > 3",
        TRIGGERS["events_no_delete"],
    )
    checkpoint.write_bytes(old_checkpoint)  # database and checkpoint agree again at seq 3

    report = box.verify()
    assert _kinds(report.problems) == [ProblemKind.ROLLED_BACK]
    assert report.problems[0].seq == 4
    with pytest.raises(BlackBoxError, match="refusing to append"):
        box.append(Source.FILE, "write", "/w")
    assert box.head() is not None and box.head()[0] == 3


def test_a_verified_head_is_remembered_too(db: Path, checkpoint: Path) -> None:
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as writer:
        _fill(writer, 2)
    with BlackBox(db, KEY, checkpoint_path=checkpoint) as other:
        assert other.verify().ok
        _drop(  # same seq, another hash: a history swapped in under the running process
            db,
            "DROP TRIGGER events_no_update",
            "UPDATE events SET hash = replace(hex(zeroblob(32)), '0', 'e') WHERE seq = 2",
            TRIGGERS["events_no_update"],
        )
        write_checkpoint(checkpoint, KEY, seq=2, hash="e" * 64, ts="2026-10-06T00:00:00.000000Z")
        with pytest.raises(BlackBoxError, match="rolled_back"):
            other.append(Source.FILE, "write", "/w")


def test_append_refuses_a_head_whose_hash_is_not_text(db: Path) -> None:
    with BlackBox(db, KEY) as box:  # no checkpoint: only the head itself can show it
        _fill(box, 1)
    _drop(
        db,
        "DROP TRIGGER events_no_update",
        "UPDATE events SET hash = x'00ff' WHERE seq = 1",
        TRIGGERS["events_no_update"],
    )
    with BlackBox(db, KEY) as fresh:
        with pytest.raises(BlackBoxError, match="malformed"):
            fresh.append(Source.FILE, "write", "/w")


# -- read-only, as `vigia verificar` opens it


def test_a_read_only_box_reads_but_never_writes(box: BlackBox, db: Path, checkpoint: Path) -> None:
    _fill(box, 3)
    box.close()
    before = db.read_bytes()
    with BlackBox(db, KEY, checkpoint_path=checkpoint, readonly=True) as reader:
        assert reader.verify().ok
        assert [event.seq for event in reader.events()] == [1, 2, 3]
        with pytest.raises(BlackBoxError, match="read-only"):
            reader.append(Source.FILE, "write", "/w")
    assert db.read_bytes() == before


@pytest.mark.parametrize("wipe", ["drop-tables", "zero-bytes"])
def test_verifying_read_only_reports_a_wiped_database_and_never_rebuilds_it(
    box: BlackBox, db: Path, checkpoint: Path, wipe: str
) -> None:
    _fill(box, 3)
    box.close()
    if wipe == "drop-tables":
        _drop(db, "DROP TABLE events", "DROP TABLE meta")
    else:
        db.write_bytes(b"")
    before = db.read_bytes()

    with BlackBox(db, KEY, checkpoint_path=checkpoint, readonly=True) as reader:
        report = reader.verify()

    schema = {problem.detail for problem in report.problems if problem.kind is ProblemKind.SCHEMA}
    assert {"falta la tabla events", "falta la tabla meta"} <= schema
    assert ProblemKind.TRUNCATED in _kinds(report.problems)
    assert db.read_bytes() == before
    assert _table_count(db) == 0


def test_read_only_never_creates_a_missing_database(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"
    with pytest.raises(BlackBoxError, match="cannot open"):
        BlackBox(missing, KEY, readonly=True).open()
    assert not missing.exists()


def test_an_unknown_schema_version_is_reported_when_read_only(box: BlackBox, db: Path) -> None:
    box.close()
    _drop(db, "UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with BlackBox(db, KEY, readonly=True) as reader:
        details = [problem.detail for problem in reader.verify().problems]
    assert any("versión de esquema" in detail for detail in details)


# -- what verify() reports as tampering and what it raises as a read error


def _sqlite_error(cls: type[sqlite3.Error], message: str, code: int) -> sqlite3.Error:
    error = cls(message)
    error.sqlite_errorcode = code  # type: ignore[attr-defined]
    return error


@pytest.mark.parametrize(
    "error",
    [
        _sqlite_error(sqlite3.OperationalError, "disk I/O error", sqlite3.SQLITE_IOERR_READ),
        _sqlite_error(sqlite3.OperationalError, "database is locked", sqlite3.SQLITE_BUSY),
        _sqlite_error(sqlite3.DatabaseError, "file is not a database", sqlite3.SQLITE_NOTADB),
    ],
)
def test_verify_raises_when_the_database_cannot_be_read(
    box: BlackBox, monkeypatch: pytest.MonkeyPatch, error: sqlite3.Error
) -> None:
    _fill(box, 1)

    def broken(conn: sqlite3.Connection) -> set[str]:
        raise error

    monkeypatch.setattr("vigia.blackbox.store._table_names", broken)
    with pytest.raises(BlackBoxError, match="cannot read the black box"):
        box.verify()


def test_a_corrupt_database_is_reported_not_raised(
    box: BlackBox, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fill(box, 1)
    error = _sqlite_error(sqlite3.DatabaseError, "malformed", sqlite3.SQLITE_CORRUPT)

    def broken(conn: sqlite3.Connection) -> set[str]:
        raise error

    monkeypatch.setattr("vigia.blackbox.store._table_names", broken)
    assert _kinds(box.verify().problems) == [ProblemKind.SCHEMA]


# -- reading the checkpoint safely


def test_a_checkpoint_that_is_a_folder_is_a_read_error_not_forgery(
    box: BlackBox, checkpoint: Path
) -> None:
    _fill(box, 1)
    checkpoint.unlink()
    checkpoint.mkdir()
    with pytest.raises(BlackBoxError, match="not a regular file") as raised:
        box.verify()
    assert not isinstance(raised.value, CheckpointError)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files whatever their mode")
def test_an_unreadable_checkpoint_is_a_read_error_not_forgery(
    box: BlackBox, checkpoint: Path
) -> None:
    _fill(box, 1)
    checkpoint.chmod(0)
    try:
        with pytest.raises(BlackBoxError, match="cannot read checkpoint") as raised:
            box.verify()
    finally:
        checkpoint.chmod(0o600)
    assert not isinstance(raised.value, CheckpointError)


def test_the_checkpoint_is_never_read_through_a_symlink(
    box: BlackBox, checkpoint: Path, tmp_path: Path
) -> None:
    _fill(box, 1)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(checkpoint.read_bytes())
    checkpoint.unlink()
    checkpoint.symlink_to(elsewhere)
    with pytest.raises(BlackBoxError, match="symlink"):
        read_checkpoint(checkpoint, KEY)


def test_a_fifo_as_checkpoint_never_blocks(checkpoint: Path) -> None:
    os.mkfifo(checkpoint, 0o600)
    outcome = call_unblocking_fifo(lambda: read_checkpoint(checkpoint, KEY), checkpoint)
    assert isinstance(outcome, BlackBoxError), outcome
    assert "not a regular file" in str(outcome)


def test_an_oversized_checkpoint_is_not_read_whole(checkpoint: Path) -> None:
    checkpoint.write_bytes(b" " * 10_000)
    with pytest.raises(CheckpointError, match="4096"):
        read_checkpoint(checkpoint, KEY)


def test_the_checkpoint_lock_is_never_a_symlink(checkpoint: Path, tmp_path: Path) -> None:
    planted = tmp_path / "planted"
    checkpoint.with_name(checkpoint.name + ".lock").symlink_to(planted)
    with pytest.raises(BlackBoxError, match="checkpoint lock"):
        with checkpoint_lock(checkpoint, timeout=1):
            pass
    assert not planted.exists()
