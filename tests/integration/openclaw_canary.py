"""The canary on OpenClaw's SQLite (docs/19, section 7, point 6; docs/20, section 9).

What Vigía promises about channels and rewinds rests on how OpenClaw 2026.9.8 keeps its state:
who may talk to the agent comes only from openclaw.json (read-only), and what its global SQLite
holds a rewind brings back. The canary reads that SQLite in a SNAPSHOT (never the live one) and
says two things:

- the layout is still the one docs/20 was written against (``user_version`` and the tables);
  if a new OpenClaw breaks it, docs/19 section 7 and docs/20 have to be read again;
- which rows in it would authorize someone (``authorizations``): a sender approved in the DM
  pairing store, a pending pairing code, "allow always" exec entries, standing grants, paired
  devices. With the config Vigía writes none of them may authorize anything, but rows there
  are exactly what an agent that tries to authorize itself leaves behind.

Only for the tests: it runs as the test's user on a COPY of the database and its WAL (a
snapshot is read-only, and ``immutable=1`` would ignore what is committed in the WAL but not yet
checkpointed, which on a young database is everything). Vigía itself never opens a SQLite of the
agent (docs/19, section 7: "nunca Vigía como root abriendo una SQLite del agente").
"""

import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

# Relative to the agent's folder (/workspace in the container, "agente" in a snapshot):
# OPENCLAW_STATE_DIR is /workspace/state and OpenClaw keeps its global SQLite in state/.
OPENCLAW_DB = Path("state/state/openclaw.sqlite")
USER_VERSION = 19  # OpenClaw 2026.9.8
# The tables docs/19 (section 7) and docs/20 rely on.
TABLES = (
    "delivery_queue_entries",
    "state_leases",
    "channel_ingress_events",
    "channel_pairing_allow_entries",
    "channel_pairing_requests",
    "plugin_state_entries",
    "exec_approvals_config",
    "plugin_binding_approvals",
    "device_pairing_paired",
    "device_pairing_pending",
    "device_auth_tokens",
    "device_bootstrap_tokens",
    "device_pairing_join_codes",
)
# Where a row authorizes someone or something (docs/20, sections 1, 3 and 4). The DM pairing
# store is the one that matters for channels: OpenClaw reads it only with dmPolicy "pairing".
AUTHORIZATION_TABLES = (
    "channel_pairing_allow_entries",
    "channel_pairing_requests",
    "exec_approvals_config",
    "plugin_binding_approvals",
    "device_pairing_paired",
    "device_pairing_pending",
    "device_auth_tokens",
    "device_bootstrap_tokens",
    "device_pairing_join_codes",
)


@dataclass(frozen=True)
class CanaryReading:
    user_version: int
    tables: frozenset[str]
    authorizations: dict[str, int]  # rows per table of AUTHORIZATION_TABLES that exists
    pairing_entries: tuple[tuple[str, str, str], ...]  # (channel_key, account_id, entry)

    @property
    def missing_tables(self) -> list[str]:
        return [table for table in TABLES if table not in self.tables]

    @property
    def authorized_rows(self) -> dict[str, int]:
        return {table: rows for table, rows in self.authorizations.items() if rows}


def read_openclaw_db(agent_folder: Path, scratch: Path) -> CanaryReading:
    """Read OpenClaw's global SQLite under ``agent_folder`` (a snapshot's "agente" folder),
    through a copy in ``scratch`` (an empty folder of the test's own)."""
    source = agent_folder / OPENCLAW_DB
    copy = scratch / OPENCLAW_DB.name
    for suffix in ("", "-wal"):
        original = source.with_name(source.name + suffix)
        if original.is_symlink():
            raise AssertionError(f"{original} is a symbolic link")
        if original.exists():
            shutil.copyfile(original, copy.with_name(copy.name + suffix))
    if not copy.exists():
        raise AssertionError(f"there is no {OPENCLAW_DB} in {agent_folder}")
    with closing(sqlite3.connect(copy)) as db:
        user_version = db.execute("PRAGMA user_version").fetchone()[0]
        tables = frozenset(
            name for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        )
        authorizations = {
            table: db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]  # noqa: S608
            for table in AUTHORIZATION_TABLES
            if table in tables
        }
        pairing: tuple[tuple[str, str, str], ...] = ()
        if "channel_pairing_allow_entries" in tables:
            pairing = tuple(
                (str(channel), str(account), str(entry))
                for channel, account, entry in db.execute(
                    "SELECT channel_key, account_id, entry FROM channel_pairing_allow_entries"
                )
            )
    return CanaryReading(user_version, tables, authorizations, pairing)
