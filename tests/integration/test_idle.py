"""T04b-2 in the VM: what an idle OpenClaw costs. The measurement behind "no noise rule".

docs/19-diseno-t04.md, section 2 ("Sin regla de ruido"): the design accepts a snapshot per cycle
while the agent does nothing, instead of letting inotify decide what is noise. This test runs
the real service with its real 120 s cycle against a real OpenClaw that nobody talks to, and
prints how many snapshots and changes that makes. The 10-minute figure of the docs comes from

    make it IT="tests/integration/test_idle.py -s --idle-seconds=600"

By default it runs 250 s (two cycles) so that `make it` stays short. What it asserts is the
structure of the cost, not a number that depends on the machine: at most one snapshot per cycle
(Btrfs decides, once per cycle), every one of them recorded, and the black box intact.
"""

import json
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.integration.service_kit import Service
from vigia.blackbox import Event
from vigia.snapshots import btrfs

pytestmark = pytest.mark.integration

CYCLE_SECONDS = 120.0  # the real one
SAMPLE_EVERY = 10.0


def _utc(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def events_per_minute(files: list[Event], *, started_at: datetime | None) -> list[int]:
    """How many file events fell in each minute of the window: the start-up burst of OpenClaw
    (it unpacks its web UI) is told apart from what it keeps doing when idle."""
    if started_at is None:
        return []
    buckets: Counter[int] = Counter()
    for event in files:
        buckets[int((_utc(event.ts) - started_at).total_seconds() // 60)] += 1
    return [buckets[minute] for minute in range(max(buckets, default=-1) + 1)]


def test_an_idle_openclaw_costs_at_most_one_snapshot_per_cycle(
    request: pytest.FixtureRequest,
    make_real_service: Callable[..., Service],
    tmp_path: Path,
) -> None:
    seconds = int(request.config.getoption("--idle-seconds"))
    service = make_real_service(cycle_interval=CYCLE_SECONDS)
    service.start()
    service.wait_ready()

    snapshots_at_start = len(service.snapshots())
    first_event = service.box.head()
    assert first_event is not None
    started = time.monotonic()
    ctransids = [service.workspace_ctransid()]
    while time.monotonic() - started < seconds:
        time.sleep(SAMPLE_EVERY)
        btrfs.sync_filesystem(service.store.root)  # ctransid moves at once; this only commits
        ctransids.append(service.workspace_ctransid())
    elapsed = time.monotonic() - started

    after_start = [e for e in service.events() if e.seq > first_event[0]]
    cycle_takes = [e for e in after_start if e.action == "take" and e.source == "snapshot"]
    files = [e for e in after_start if e.source == "file"]
    changed_windows = sum(1 for a, b in zip(ctransids, ctransids[1:], strict=False) if a != b)
    windows = len(ctransids) - 1
    by_action = Counter(e.action for e in files)
    per_minute = events_per_minute(
        files, started_at=_utc(after_start[0].ts) if after_start else None
    )
    by_target = Counter(e.target for e in files).most_common(8)
    result = {
        "seconds": round(elapsed),
        "cycle_seconds": CYCLE_SECONDS,
        "snapshots_total_at_start": snapshots_at_start,
        "snapshots_by_the_cycle": len(cycle_takes),
        "cycles_elapsed": int(elapsed // CYCLE_SECONDS),
        f"sample_windows_of_{int(SAMPLE_EVERY)}s": windows,
        "sample_windows_with_a_change": changed_windows,
        "file_events": len(files),
        "file_events_by_action": dict(by_action),
        "file_events_per_minute": per_minute,
        "file_events_top_targets": by_target,
        "alerts_or_logs": [e.details.get("template") for e in after_start if e.action == "log"],
    }
    report = tmp_path / "idle-measurement.json"
    report.write_text(json.dumps(result, indent=2, default=str))
    print("\nIDLE OPENCLAW MEASUREMENT\n" + json.dumps(result, indent=2, default=str))
    print(f"(also in {report})")

    assert cycle_takes, "no cycle ran in the whole window"
    assert len(cycle_takes) <= elapsed // CYCLE_SECONDS + 1  # never more than one per cycle
    assert all(e.details["trigger"] == "cycle" for e in cycle_takes)
    assert not [e for e in after_start if e.action in ("cycle_failed", "take_failed", "busy")]
    assert service.box.verify().ok
