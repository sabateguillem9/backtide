"""BlackBox: the append-only, hash-chained event log in SQLite, plus its checkpoint.

Design and rationale: docs/11-diseno-t02-caja-negra.md.

- ``events``: one row per event. Triggers abort any UPDATE or DELETE, and any INSERT that
  is not exactly the next ``seq`` (which also stops ``INSERT OR REPLACE``, whose implicit
  delete does not fire DELETE triggers).
- ``meta``: ``schema_version`` and ``key_id`` (a fingerprint of the key, never the key).
- The checkpoint file holds the last ``(seq, hash)`` signed with the key. It is what lets
  verify() notice events deleted at the END, which the chain alone cannot show. Creating
  the box writes a genesis checkpoint (seq 0), so a missing one is never legitimate once
  there are events.
- open() only creates the schema in an empty database. It never repairs an existing one,
  so a dropped trigger stays dropped until verify() reports it. verify() also requires the
  exact table SQL and rejects any trigger it did not create. A box opened with
  ``readonly=True`` (what ``backtide verificar`` does) never writes to the database at all.
- Each instance remembers the highest ``(seq, hash)`` it wrote or verified, and refuses to
  append if the chain is ever behind it: that catches a rollback of the database AND the
  checkpoint while the recording process is alive.

Locking order, always: the instance's threading.Lock, then the checkpoint flock, then
SQLite's write lock (BEGIN IMMEDIATE). The flock spans the commit and the checkpoint
write, so appenders in other processes never move the checkpoint backwards.
"""

import hmac
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from backtide.blackbox.chain import (
    GENESIS,
    HEX64_RE,
    TS_RE,
    canonical,
    canonical_json,
    compute_hash,
)
from backtide.blackbox.chain import key_id as compute_key_id
from backtide.blackbox.checkpoint import (
    Checkpoint,
    CheckpointError,
    checkpoint_lock,
    read_checkpoint,
    write_checkpoint,
)
from backtide.blackbox.keys import KEY_SIZE
from backtide.blackbox.model import (
    BlackBoxError,
    Event,
    Problem,
    ProblemKind,
    Source,
    VerifyReport,
)
from backtide.blackbox.redact import redact
from backtide.snapshots.model import Snapshot, utc_now

SCHEMA_VERSION = "1"
BUSY_TIMEOUT = 30.0  # seconds to wait for another writer (SQLite or the checkpoint flock)
MAX_ACTION_CHARS = 64

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# SQLite errors meaning the file cannot be read right now (or is not a database at all),
# as opposed to a database whose content is wrong. verify() raises for these.
_READ_ERRORS = frozenset(
    {
        sqlite3.SQLITE_AUTH,
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_CANTOPEN,
        sqlite3.SQLITE_FULL,
        sqlite3.SQLITE_INTERRUPT,
        sqlite3.SQLITE_IOERR,
        sqlite3.SQLITE_LOCKED,
        sqlite3.SQLITE_NOMEM,
        sqlite3.SQLITE_NOTADB,
        sqlite3.SQLITE_PERM,
        sqlite3.SQLITE_PROTOCOL,
        sqlite3.SQLITE_READONLY,
    }
)
_COLUMN_NAMES = (
    "seq",
    "ts",
    "source",
    "action",
    "target",
    "details",
    "risk",
    "snapshot_id",
    "prev_hash",
    "hash",
)
_COLUMNS = ", ".join(_COLUMN_NAMES)
# Built from constants only.
_SELECT_EVENTS = f"SELECT {_COLUMNS} FROM events"  # noqa: S608
_INSERT_EVENT = f"INSERT INTO events ({_COLUMNS}) VALUES ({', '.join('?' * 10)})"  # noqa: S608

# verify() requires each table to exist with exactly this SQL, so a table re-created
# without its constraints (or with a non-integer seq) is reported, never trusted.
TABLES: dict[str, str] = {
    "events": """CREATE TABLE events (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    risk INTEGER NOT NULL CHECK (risk BETWEEN 0 AND 3),
    snapshot_id TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
)""",
    "meta": "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
}
# verify() requires each of these to exist with exactly this SQL, and no other trigger:
# an extra one could, for example, silently drop events with RAISE(IGNORE).
TRIGGERS: dict[str, str] = {
    "events_no_update": "CREATE TRIGGER events_no_update BEFORE UPDATE ON events "
    "BEGIN SELECT RAISE(ABORT, 'black box is append-only'); END",
    "events_no_delete": "CREATE TRIGGER events_no_delete BEFORE DELETE ON events "
    "BEGIN SELECT RAISE(ABORT, 'black box is append-only'); END",
    "events_append_at_end": "CREATE TRIGGER events_append_at_end BEFORE INSERT ON events "
    "WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM events) "
    "BEGIN SELECT RAISE(ABORT, 'black box is append-only'); END",
}


@dataclass(frozen=True)
class _Record:
    """The validated, redacted caller-supplied part of an event."""

    source: Source
    action: str
    target: str
    details: dict[str, Any]
    details_json: str
    risk: int
    snapshot_id: str | None


@dataclass
class _Findings:
    problems: list[Problem] = field(default_factory=list)
    warnings: list[Problem] = field(default_factory=list)

    def problem(self, seq: int | None, kind: ProblemKind, detail: str) -> None:
        self.problems.append(Problem(seq, kind, detail))

    def warning(self, seq: int | None, kind: ProblemKind, detail: str) -> None:
        self.warnings.append(Problem(seq, kind, detail))


class BlackBox:
    """The black box at ``path``, created (empty, 0600) if it does not exist.

    Use it as a context manager, or call open() and close(). Methods open it on first
    use. One instance can be shared by threads; several instances and processes can
    append to the same database at once. Pass the same ``checkpoint_path`` to all of
    them, and never one inside the snapshot volume.

    With ``readonly=True`` the database must exist and is never written: not created,
    not switched to WAL, not initialized. Use it to verify; append() then raises. With
    ``key=None`` (read-only only) it cannot verify either: it just lists events, and holds no
    secret, which is what a viewer such as the web should do."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        key: bytes | None,
        *,
        checkpoint_path: str | os.PathLike[str] | None = None,
        clock: Callable[[], datetime] = utc_now,
        readonly: bool = False,
    ) -> None:
        if key is None:
            if not readonly:
                raise ValueError("only a read-only black box may go without its key")
        elif not isinstance(key, bytes) or len(key) != KEY_SIZE:
            raise ValueError(f"key must be exactly {KEY_SIZE} bytes")
        self._path = Path(path)
        self._key = key  # None: a reader that lists events (the web) and can verify nothing
        self._key_id = compute_key_id(key) if key is not None else None
        self._checkpoint_path = Path(checkpoint_path) if checkpoint_path is not None else None
        self._clock = clock
        self._readonly = readonly
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        # The highest (seq, hash) this instance wrote or verified: the chain never goes back.
        self._seen: tuple[int, str] | None = None

    # -- lifecycle -----------------------------------------------------------------------

    def open(self) -> "BlackBox":
        with self._lock:
            self._connection()
        return self

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                conn, self._conn = self._conn, None
                conn.close()

    def __enter__(self) -> "BlackBox":
        return self.open()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # -- public API ----------------------------------------------------------------------

    def append(
        self,
        source: Source | str,
        action: str,
        target: str,
        *,
        details: Mapping[str, Any] | None = None,
        risk: int = 0,
        snapshot_id: str | None = None,
    ) -> Event:
        """Record one event and return it. It is on disk when this returns.

        ``target`` and ``details`` are redacted and truncated first. Raises ValueError
        for invalid arguments (nothing is recorded) and BlackBoxError if the database
        fails, the key is not this box's, or the checkpoint shows tampering (the chain
        is never extended over evidence). A BlackBoxError saying the event WAS recorded
        means only the checkpoint write failed: do not append it again."""
        if self._readonly:
            raise BlackBoxError("the black box was opened read-only: cannot append")
        record = _prepare(source, action, target, details, risk, snapshot_id)
        with self._lock:
            conn = self._connection()
            with self._checkpoint_lock():
                event = self._insert(conn, record)
                self._save_checkpoint(event)
        return event

    def events(
        self,
        *,
        since_seq: int | None = None,
        before_seq: int | None = None,
        source: Source | str | None = None,
        action: str | None = None,
        min_risk: int | None = None,
        since_ts: datetime | None = None,
        until_ts: datetime | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> list[Event]:
        """Events in ``seq`` order (``newest_first``: the reverse): those with seq >
        ``since_seq`` and seq < ``before_seq``, from ``source``, with ``action``, risk of at
        least ``min_risk``, recorded from ``since_ts`` (inclusive) until ``until_ts``
        (exclusive; both aware datetimes), at most ``limit``. The web's history page pages
        with ``before_seq`` and filters with the rest. With
        ``newest_first`` and ``limit``, the newest ones: so the startup reconciliation reads
        the last rewind without walking the whole black box. Does not check hashes (that is
        verify()); a row that cannot even be parsed raises BlackBoxError."""
        clauses: list[str] = []
        params: list[Any] = []
        if since_seq is not None:
            if not _is_int(since_seq) or since_seq < 0:
                raise ValueError(f"since_seq must be an int >= 0, got {since_seq!r}")
            clauses.append("seq > ?")
            params.append(since_seq)
        if before_seq is not None:
            if not _is_int(before_seq) or before_seq < 1:
                raise ValueError(f"before_seq must be an int >= 1, got {before_seq!r}")
            clauses.append("seq < ?")
            params.append(before_seq)
        if min_risk is not None:
            if not _is_int(min_risk) or not 0 <= min_risk <= 3:
                raise ValueError(f"min_risk must be an int from 0 to 3, got {min_risk!r}")
            clauses.append("risk >= ?")
            params.append(min_risk)
        for column_op, moment_name, moment in (
            (">=", "since_ts", since_ts),
            ("<", "until_ts", until_ts),
        ):
            if moment is None:
                continue
            if not isinstance(moment, datetime) or moment.utcoffset() is None:
                raise ValueError(f"{moment_name} must be an aware datetime, got {moment!r}")
            clauses.append(f"ts {column_op} ?")  # fixed-width UTC text: it sorts like time
            params.append(_format_ts(moment))
        if source is not None:
            clauses.append("source = ?")
            params.append(_parse_source(source).value)
        if action is not None:
            if not _valid_action(action):
                raise ValueError(f"action must be a non-empty str, got {action!r}")
            clauses.append("action = ?")
            params.append(action)
        if not isinstance(newest_first, bool):
            raise ValueError(f"newest_first must be a bool, got {newest_first!r}")
        sql = _SELECT_EVENTS
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq DESC" if newest_first else " ORDER BY seq"
        if limit is not None:
            if not _is_int(limit) or limit < 1:
                raise ValueError(f"limit must be an int >= 1, got {limit!r}")
            sql += " LIMIT ?"
            params.append(limit)
        with self._lock:
            try:
                rows = self._connection().execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                raise BlackBoxError(f"cannot read the black box: {exc}") from exc
        return [_row_to_event(row) for row in rows]

    def head(self) -> tuple[int, str] | None:
        """(seq, hash) of the last event, or None if there are none."""
        with self._lock:
            try:
                return _read_head(self._connection())
            except sqlite3.Error as exc:
                raise BlackBoxError(f"cannot read the black box: {exc}") from exc

    def verify(self) -> VerifyReport:
        """Check the whole black box. Corrupt or tampered data never raises: it becomes
        a Problem in the report (see ProblemKind for what each kind means). Raises
        BlackBoxError only when the database or the checkpoint cannot be read at all
        (I/O error, busy, not a database): then nothing was verified."""
        if self._key is None:
            raise BlackBoxError("this black box was opened without its key: it cannot verify")
        findings = _Findings()
        count, head = 0, None
        with self._lock:
            conn = self._connection()
            # Read the checkpoint BEFORE the database snapshot: appenders write it after
            # committing, so a concurrent append can never make it look ahead of the db.
            checkpoint, checkpoint_missing = self._checkpoint_for_verify(findings)
            # Text that is not UTF-8 must become an INVALID field of its event, not a
            # decode error that stops the walk; the connection gets str back afterwards.
            conn.text_factory = _decode_leniently
            try:
                with _read_transaction(conn):
                    tables = _table_names(conn)
                    self._check_schema(conn, tables, findings)
                    if "events" in tables:
                        count, head = self._check_events(conn, findings)
                    if checkpoint is not None:
                        _check_checkpoint(conn, checkpoint, head, findings)
                    elif checkpoint_missing:
                        _check_missing_checkpoint(head, findings)
                    _check_seen(conn, self._seen, head, findings)
            except sqlite3.DatabaseError as exc:
                if _is_read_error(exc):
                    raise BlackBoxError(f"cannot read the black box: {exc}") from exc
                findings.problem(None, ProblemKind.SCHEMA, f"no se puede leer entera: {exc}")
            finally:
                conn.text_factory = str
            if head is not None and not findings.problems:
                self._remember(head)
        return VerifyReport(
            checked=count,
            last_seq=head[0] if head else None,
            problems=tuple(findings.problems),
            warnings=tuple(findings.warnings),
        )

    # -- opening -------------------------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        """The open connection, opening it if needed. Call with self._lock held."""
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def _connect(self) -> sqlite3.Connection:
        if self._readonly:
            return self._connect_readonly()
        _create_private_file(self._path)
        try:
            conn = sqlite3.connect(
                self._path,
                timeout=BUSY_TIMEOUT,
                isolation_level=None,  # we issue BEGIN/COMMIT ourselves
                check_same_thread=False,  # shared by threads, always under self._lock
            )
        except sqlite3.Error as exc:
            raise BlackBoxError(f"cannot open black box {self._path}: {exc}") from exc
        try:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode != "wal":
                raise BlackBoxError(f"black box {self._path} cannot use WAL (got {mode!r})")
            conn.execute("PRAGMA synchronous=FULL")
            self._init_schema(conn)
        except BaseException as exc:
            conn.close()
            if isinstance(exc, sqlite3.Error):
                raise BlackBoxError(f"cannot open black box {self._path}: {exc}") from exc
            raise
        return conn

    def _connect_readonly(self) -> sqlite3.Connection:
        """Open the existing file for reading only: SQLite refuses every write."""
        uri = f"{self._path.absolute().as_uri()}?mode=ro"
        try:
            return sqlite3.connect(
                uri,
                uri=True,
                timeout=BUSY_TIMEOUT,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise BlackBoxError(f"cannot open black box {self._path}: {exc}") from exc

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        """Create the schema and the genesis checkpoint in an empty database; leave an
        existing black box untouched."""
        if not _table_names(conn):
            with self._checkpoint_lock(), _write_transaction(conn):
                tables = _table_names(conn)  # again, now that we hold the write lock
                if not tables:
                    for statement in (*TABLES.values(), *TRIGGERS.values()):
                        conn.execute(statement)
                    conn.executemany(
                        "INSERT INTO meta (key, value) VALUES (?, ?)",
                        [("schema_version", SCHEMA_VERSION), ("key_id", self._key_id)],
                    )
                    self._write_genesis_checkpoint()  # before COMMIT: no box without one
        tables = _table_names(conn)
        if not tables & {"events", "meta"}:
            raise BlackBoxError(f"{self._path} is a SQLite database but not a black box")
        if "meta" in tables:
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is not None and row[0] != SCHEMA_VERSION:
                raise BlackBoxError(f"unsupported black box schema version {row[0]!r}")

    # -- appending -----------------------------------------------------------------------

    def _insert(self, conn: sqlite3.Connection, record: _Record) -> Event:
        try:
            with _write_transaction(conn):
                self._require_own_key(conn)
                head = _read_head(conn)
                self._require_untampered(conn, head)
                seq, prev_hash = (head[0] + 1, head[1]) if head else (1, GENESIS)
                ts = _format_ts(self._clock())  # read inside the transaction: ts follow seq
                fields = {
                    "seq": seq,
                    "ts": ts,
                    "source": record.source.value,
                    "action": record.action,
                    "target": record.target,
                    "details": record.details,
                    "risk": record.risk,
                    "snapshot_id": record.snapshot_id,
                    "prev_hash": prev_hash,
                }
                digest = compute_hash(self._key, canonical(fields))
                cursor = conn.execute(
                    _INSERT_EVENT,
                    (
                        seq,
                        ts,
                        record.source.value,
                        record.action,
                        record.target,
                        record.details_json,
                        record.risk,
                        record.snapshot_id,
                        prev_hash,
                        digest,
                    ),
                )
                if cursor.rowcount != 1:  # e.g. a foreign trigger doing RAISE(IGNORE)
                    raise BlackBoxError(
                        f"event {seq} was not stored (the black box was tampered with): "
                        "nothing recorded, run verify"
                    )
        except sqlite3.Error as exc:
            raise BlackBoxError(f"cannot append to the black box: {exc}") from exc
        self._remember((seq, digest))  # committed: from now on the chain reaches it
        return Event(
            seq=seq,
            ts=ts,
            source=record.source,
            action=record.action,
            target=record.target,
            details=record.details,
            risk=record.risk,
            snapshot_id=record.snapshot_id,
            prev_hash=prev_hash,
            hash=digest,
        )

    def _require_own_key(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT value FROM meta WHERE key = 'key_id'").fetchone()
        if row is None:
            raise BlackBoxError("black box has no key_id: refusing to append, run verify")
        if row[0] != self._key_id:
            raise BlackBoxError("this key does not belong to this black box: refusing to append")

    def _require_untampered(self, conn: sqlite3.Connection, head: tuple[int, str] | None) -> None:
        """Never extend a chain that went back, or that its checkpoint contradicts."""
        findings = _Findings()
        _check_seen(conn, self._seen, head, findings)
        if self._checkpoint_path is not None:
            checkpoint = read_checkpoint(self._checkpoint_path, self._key)  # raises if forged
            if checkpoint is None:
                _check_missing_checkpoint(head, findings)
            else:
                _check_checkpoint(conn, checkpoint, head, findings)
        if findings.problems:
            problem = findings.problems[0]
            raise BlackBoxError(
                f"refusing to append, the black box was tampered with ({problem.kind}): "
                f"{problem.detail}"
            )

    def _remember(self, head: tuple[int, str]) -> None:
        if self._seen is None or head[0] > self._seen[0]:
            self._seen = head

    # -- checkpoint ----------------------------------------------------------------------

    def _checkpoint_lock(self) -> AbstractContextManager[None]:
        if self._checkpoint_path is None:
            return nullcontext()
        return checkpoint_lock(self._checkpoint_path, BUSY_TIMEOUT)

    def _save_checkpoint(self, event: Event) -> None:
        if self._checkpoint_path is None:
            return
        try:
            write_checkpoint(
                self._checkpoint_path, self._key, seq=event.seq, hash=event.hash, ts=event.ts
            )
        except OSError as exc:
            raise BlackBoxError(
                f"event {event.seq} WAS recorded, but the checkpoint could not be updated: {exc}"
            ) from exc

    def _write_genesis_checkpoint(self) -> None:
        """Sign "no events yet", so that a missing checkpoint is never legitimate later.
        An existing file is left alone: it may be the evidence of a wiped database."""
        if self._checkpoint_path is None or os.path.lexists(self._checkpoint_path):
            return
        ts = _format_ts(self._clock())
        try:
            write_checkpoint(self._checkpoint_path, self._key, seq=0, hash=GENESIS, ts=ts)
        except OSError as exc:
            raise BlackBoxError(
                f"cannot write the first checkpoint {self._checkpoint_path}: {exc}"
            ) from exc

    def _checkpoint_for_verify(self, findings: _Findings) -> tuple[Checkpoint | None, bool]:
        """(the genuine checkpoint or None, whether a checkpoint was given but has no file).
        Raises BlackBoxError if the file exists but cannot be read."""
        if self._checkpoint_path is None:
            findings.warning(
                None,
                ProblemKind.CHECKPOINT_MISSING,
                "no se ha indicado punto de control: no se puede comprobar si se han "
                "borrado los últimos eventos",
            )
            return None, False
        try:
            checkpoint = read_checkpoint(self._checkpoint_path, self._key)
        except CheckpointError as exc:
            findings.problem(
                None, ProblemKind.CHECKPOINT_FORGED, f"el punto de control {exc.detail}"
            )
            return None, False
        return checkpoint, checkpoint is None

    # -- verifying -----------------------------------------------------------------------

    def _check_schema(
        self, conn: sqlite3.Connection, tables: set[str], findings: _Findings
    ) -> None:
        stored_sql = dict(conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'"))
        for table, sql in TABLES.items():
            if table not in tables:
                findings.problem(None, ProblemKind.SCHEMA, f"falta la tabla {table}")
            elif _normalize_sql(stored_sql.get(table)) != _normalize_sql(sql):
                findings.problem(None, ProblemKind.SCHEMA, f"la tabla {table} ha sido modificada")
        if "meta" in tables:
            meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
            version = meta.get("schema_version")
            if version is None:
                findings.problem(None, ProblemKind.SCHEMA, "falta schema_version en meta")
            elif version != SCHEMA_VERSION:
                findings.problem(
                    None, ProblemKind.SCHEMA, f"versión de esquema desconocida: {_short(version)}"
                )
            stored_key_id = meta.get("key_id")
            if stored_key_id is None:
                findings.problem(
                    None, ProblemKind.KEY_MISMATCH, "falta key_id: no se puede comprobar la clave"
                )
            elif stored_key_id != self._key_id:
                findings.problem(
                    None,
                    ProblemKind.KEY_MISMATCH,
                    "la clave no corresponde a esta caja negra: o es otra clave o han "
                    "cambiado la de la base de datos",
                )
        if "events" in tables:
            _check_triggers(conn, findings)

    def _check_events(
        self, conn: sqlite3.Connection, findings: _Findings
    ) -> tuple[int, tuple[int, str] | None]:
        """Walk every event in seq order. Returns (row count, last (seq, hash))."""
        count = 0
        head: tuple[int, str] | None = None
        expected_seq = 1
        prev_hash: object = GENESIS
        prev_ts: str | None = None
        for row in conn.execute(_SELECT_EVENTS + " ORDER BY seq"):
            count += 1
            seq, ts, stored_prev, stored_hash = row[0], row[1], row[8], row[9]
            if not _is_int(seq):  # only possible in a re-created table (SCHEMA says so)
                findings.problem(
                    None, ProblemKind.INVALID, f"hay un evento con un seq no entero: {_short(seq)}"
                )
                continue  # outside the chain: the gap or broken link it leaves is reported
            if seq > expected_seq:
                findings.problem(expected_seq, ProblemKind.GAP, _missing(expected_seq, seq - 1))
            elif seq < expected_seq:
                findings.problem(seq, ProblemKind.INVALID, f"seq no válido: {seq}")
            details = _check_fields(row, findings)
            if stored_prev != prev_hash:
                findings.problem(
                    seq,
                    ProblemKind.BROKEN_CHAIN,
                    "la cadena está rota: prev_hash no es la huella del evento anterior",
                )
            if details is not None and not self._hash_matches(row, details):
                findings.problem(seq, ProblemKind.HASH_MISMATCH, "la huella no coincide")
            if _valid_ts(ts):
                if prev_ts is not None and ts < prev_ts:
                    findings.warning(
                        seq,
                        ProblemKind.CLOCK_BACKWARDS,
                        f"la hora retrocede respecto al evento anterior ({prev_ts} → {ts})",
                    )
                prev_ts = ts
            expected_seq = max(expected_seq, seq + 1)
            prev_hash = stored_hash
            head = (seq, stored_hash)
        return count, head

    def _hash_matches(self, row: tuple[Any, ...], details: dict[str, Any]) -> bool:
        seq, ts, source, action, target, _, risk, snapshot_id, prev_hash, stored_hash = row
        fields = {
            "seq": seq,
            "ts": ts,
            "source": source,
            "action": action,
            "target": target,
            "details": details,
            "risk": risk,
            "snapshot_id": snapshot_id,
            "prev_hash": prev_hash,
        }
        try:
            expected = compute_hash(self._key, canonical(fields))
        except (TypeError, ValueError):
            return False  # a field JSON cannot hold (already reported as INVALID)
        if not isinstance(stored_hash, str):
            return False
        return hmac.compare_digest(expected.encode("ascii"), _utf8(stored_hash))


# -- validation ------------------------------------------------------------------------


def _prepare(
    source: Source | str,
    action: str,
    target: str,
    details: Mapping[str, Any] | None,
    risk: int,
    snapshot_id: str | None,
) -> _Record:
    parsed_source = _parse_source(source)
    if not _valid_action(action):
        raise ValueError(f"action must be a non-empty str of at most {MAX_ACTION_CHARS} chars")
    redacted_action = redact(action)  # actions are verbs, but never store a secret anyway
    if not _valid_action(redacted_action):
        raise ValueError(f"action is longer than {MAX_ACTION_CHARS} chars once redacted")
    if not isinstance(target, str):
        raise ValueError(f"target must be a str, got {type(target).__name__}")
    if details is None:
        details = {}
    if not isinstance(details, Mapping):
        raise ValueError(f"details must be a mapping, got {type(details).__name__}")
    try:
        # Twice: JSON turns keys that are not text ({10: ...}) into text, which sorts
        # differently, so only the second pass is the form verify() recomputes.
        details_json = canonical_json(json.loads(canonical_json(redact(details))))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"details must be JSON-serializable: {exc}") from exc
    if not _is_int(risk) or not 0 <= risk <= 3:
        raise ValueError(f"risk must be an int from 0 to 3, got {risk!r}")
    if snapshot_id is not None and not _valid_snapshot_id(snapshot_id):
        raise ValueError(f"invalid snapshot_id: {snapshot_id!r}")
    return _Record(
        source=parsed_source,
        action=redacted_action,
        target=redact(target),
        # What is stored, parsed back: the returned Event equals the one events() reads.
        details=json.loads(details_json),
        details_json=details_json,
        risk=int(risk),
        snapshot_id=snapshot_id,
    )


def _parse_source(value: Source | str) -> Source:
    try:
        return Source(value)
    except ValueError:
        raise ValueError(f"unknown source {value!r}") from None


def _valid_action(action: object) -> bool:
    return (
        isinstance(action, str)
        and bool(action.strip())
        and len(action) <= MAX_ACTION_CHARS
        and _encodes_as_utf8(action)
    )


def _valid_snapshot_id(value: object) -> bool:
    return isinstance(value, str) and Snapshot.parse(value) is not None


def _valid_ts(value: object) -> bool:
    if not isinstance(value, str) or not TS_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, _TS_FORMAT)
    except ValueError:
        return False
    return True


def _check_fields(row: tuple[Any, ...], findings: _Findings) -> dict[str, Any] | None:
    """Report every invalid stored field. Returns the parsed details, or None if they are
    not a JSON object (then the hash cannot be recomputed)."""
    seq, ts, source, action, target, details, risk, snapshot_id, prev_hash, digest = row
    reasons: list[str] = []
    if not _valid_ts(ts):
        reasons.append(f"ts mal formado: {_short(ts)}")
    if source not in {member.value for member in Source}:
        reasons.append(f"fuente desconocida: {_short(source)}")
    if not _valid_action(action):
        reasons.append(f"action no válida: {_short(action)}")
    if not isinstance(target, str):
        reasons.append("target no es texto")
    if not _is_int(risk) or not 0 <= risk <= 3:
        reasons.append(f"riesgo fuera de rango: {_short(risk)}")
    if snapshot_id is not None and not _valid_snapshot_id(snapshot_id):
        reasons.append(f"snapshot_id no válido: {_short(snapshot_id)}")
    for name, value in (("prev_hash", prev_hash), ("hash", digest)):
        if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
            reasons.append(f"{name} mal formado")
    parsed, details_reason = _parse_details(details)
    if details_reason:
        reasons.append(details_reason)
    for name, value in zip(_COLUMN_NAMES, row, strict=True):
        if isinstance(value, str) and not _encodes_as_utf8(value):
            reasons.append(f"{name} no es UTF-8 válido")
    for reason in reasons:
        findings.problem(seq, ProblemKind.INVALID, reason)
    return parsed


def _parse_details(raw: object) -> tuple[dict[str, Any] | None, str | None]:
    """(parsed object or None, reason it is invalid or None)."""
    if not isinstance(raw, str):
        return None, "details no es texto"
    try:
        parsed = json.loads(raw)
        canonical_form = canonical_json(parsed)
    except (ValueError, RecursionError):
        return None, "details no es JSON válido"
    if not isinstance(parsed, dict):
        return None, "details no es un objeto JSON"
    if canonical_form != raw:
        return parsed, "details no está en forma canónica"
    return parsed, None


def _check_triggers(conn: sqlite3.Connection, findings: _Findings) -> None:
    stored = dict(conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"))
    for name, sql in TRIGGERS.items():
        if name not in stored:
            findings.problem(None, ProblemKind.TRIGGERS, f"falta el trigger de solo añadir {name}")
        elif _normalize_sql(stored[name]) != _normalize_sql(sql):
            findings.problem(None, ProblemKind.TRIGGERS, f"el trigger {name} ha sido modificado")
    for name in sorted(stored.keys() - TRIGGERS.keys()):
        findings.problem(None, ProblemKind.TRIGGERS, f"hay un trigger ajeno: {_short(name)}")


def _check_checkpoint(
    conn: sqlite3.Connection,
    checkpoint: Checkpoint,
    head: tuple[int, str] | None,
    findings: _Findings,
) -> None:
    last_seq, last_hash = head if head else (0, GENESIS)
    if checkpoint.seq > last_seq:
        findings.problem(
            last_seq + 1,
            ProblemKind.TRUNCATED,
            f"se han borrado eventos del final: el punto de control llega hasta el "
            f"{checkpoint.seq} y la base de datos hasta el {last_seq}",
        )
        return
    stored = last_hash if checkpoint.seq == last_seq else _hash_at(conn, checkpoint.seq)
    if stored is None:
        findings.problem(
            checkpoint.seq,
            ProblemKind.CHECKPOINT_MISMATCH,
            f"falta el evento {checkpoint.seq} del punto de control",
        )
    elif stored != checkpoint.hash:
        findings.problem(
            checkpoint.seq,
            ProblemKind.CHECKPOINT_MISMATCH,
            f"el evento {checkpoint.seq} no coincide con el punto de control",
        )
    elif checkpoint.seq < last_seq:
        findings.warning(
            checkpoint.seq,
            ProblemKind.CHECKPOINT_BEHIND,
            f"el punto de control va por detrás: llega hasta el evento {checkpoint.seq} "
            f"de {last_seq}",
        )


def _check_missing_checkpoint(head: tuple[int, str] | None, findings: _Findings) -> None:
    """A checkpoint was given but its file is gone. Creating the box writes one, so with
    events in the database it was deleted, perhaps together with the last events."""
    if head is None:
        findings.warning(
            None,
            ProblemKind.CHECKPOINT_MISSING,
            "falta el punto de control (la caja negra no tiene eventos)",
        )
        return
    findings.problem(
        None,
        ProblemKind.CHECKPOINT_DELETED,
        f"falta el punto de control y la base de datos llega hasta el evento {head[0]}: "
        "lo han borrado, y con él la prueba de cuántos eventos había",
    )


def _check_seen(
    conn: sqlite3.Connection,
    seen: tuple[int, str] | None,
    head: tuple[int, str] | None,
    findings: _Findings,
) -> None:
    """The chain may only grow beyond what this instance already wrote or verified."""
    if seen is None:
        return
    seen_seq, seen_hash = seen
    last_seq = head[0] if head else 0
    if last_seq < seen_seq:
        findings.problem(
            last_seq + 1,
            ProblemKind.ROLLED_BACK,
            f"la caja negra ha retrocedido: ya llegaba hasta el evento {seen_seq} y ahora "
            f"llega hasta el {last_seq}",
        )
    elif _hash_at(conn, seen_seq) != seen_hash:
        findings.problem(
            seen_seq,
            ProblemKind.ROLLED_BACK,
            f"el evento {seen_seq} ha cambiado desde que se escribió o se verificó",
        )


# -- small helpers ---------------------------------------------------------------------


def _row_to_event(row: tuple[Any, ...]) -> Event:
    seq, ts, source, action, target, details, risk, snapshot_id, prev_hash, digest = row
    try:
        parsed = json.loads(details)
        if not isinstance(parsed, dict):
            raise ValueError("details is not a JSON object")
        return Event(
            seq=seq,
            ts=ts,
            source=Source(source),
            action=action,
            target=target,
            details=parsed,
            risk=risk,
            snapshot_id=snapshot_id,
            prev_hash=prev_hash,
            hash=digest,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise BlackBoxError(f"event {seq} is corrupt ({exc}): run verify") from exc


def _read_head(conn: sqlite3.Connection) -> tuple[int, str] | None:
    """(seq, hash) of the last event. Raises BlackBoxError if they are malformed: the
    chain must never be extended from a head that only a tampered table can hold."""
    row = conn.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    if row is None:
        return None
    seq, digest = row
    if not _is_int(seq) or not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise BlackBoxError(
            f"the last event is malformed (seq {_short(seq)}): the black box was tampered "
            "with, run verify"
        )
    return seq, digest


def _hash_at(conn: sqlite3.Connection, seq: int) -> str | None:
    if seq == 0:
        return GENESIS
    row = conn.execute("SELECT hash FROM events WHERE seq = ?", (seq,)).fetchone()
    return row[0] if row else None


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    return {name for (name,) in rows}


@contextmanager
def _write_transaction(conn: sqlite3.Connection) -> Iterator[None]:
    conn.execute("BEGIN IMMEDIATE")  # waits (busy timeout) for other writers
    try:
        yield
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@contextmanager
def _read_transaction(conn: sqlite3.Connection) -> Iterator[None]:
    conn.execute("BEGIN")  # one consistent snapshot for every read inside
    try:
        yield
    finally:
        if conn.in_transaction:
            conn.execute("ROLLBACK")


def _format_ts(now: datetime) -> str:
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise BlackBoxError(f"the clock must return an aware datetime, got {now!r}")
    return now.astimezone(UTC).strftime(_TS_FORMAT)


def _create_private_file(path: Path) -> None:
    """Create the database file 0600 if missing: SQLite gives its -wal/-shm the same mode."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        return
    except OSError as exc:
        raise BlackBoxError(f"cannot create black box {path}: {exc}") from exc
    os.close(fd)


def _is_read_error(exc: sqlite3.Error) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    return isinstance(code, int) and code & 0xFF in _READ_ERRORS


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _encodes_as_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _decode_leniently(data: bytes) -> str:
    """SQLite TEXT to str for verify(): bytes that are not UTF-8 become lone surrogates,
    which _encodes_as_utf8 then rejects, instead of aborting the whole read."""
    return data.decode("utf-8", "surrogateescape")


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")


def _normalize_sql(sql: object) -> str:
    return " ".join(str(sql).split())


def _missing(first: int, last: int) -> str:
    if first == last:
        return "falta en la base de datos"
    return f"faltan los eventos {first}–{last}"


def _short(value: object, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
