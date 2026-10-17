"""T04e-2 in the VM: the canary on OpenClaw's SQLite, read in a snapshot (openclaw_canary.py).

If this fails after an update of the pinned image, read docs/19 section 7 and docs/20 again:
what a rewind does to the channels may have changed.
"""

from pathlib import Path

import pytest

from backtide.jail.config import AGENT_DIR
from backtide.snapshots import Reason
from tests.integration.openclaw_canary import USER_VERSION, read_openclaw_db

pytestmark = pytest.mark.integration


def test_the_snapshot_holds_the_sqlite_docs_20_was_written_against(
    running_agent, tmp_path: Path
) -> None:
    snap = running_agent.store.take(Reason.MANUAL)
    folder = running_agent.store.snapshots_dir / snap.id / AGENT_DIR
    reading = read_openclaw_db(folder, tmp_path)
    print(sorted(reading.tables), reading.user_version, reading.authorizations)  # noqa: T201
    assert reading.user_version == USER_VERSION
    assert reading.missing_tables == []
    # With the config backtide writes, nobody is authorized in the SQLite.
    assert reading.authorized_rows == {}
    assert reading.pairing_entries == ()
