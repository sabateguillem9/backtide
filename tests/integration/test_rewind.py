"""T04c-1 in the VM: rewind with the real service, the real OpenClaw and the real file watcher.

docs/19-diseno-t04.md, section 4, and the criterion of T04 in docs/backlog.md:

- The agent deletes files; the watcher records the delete with the snapshot from BEFORE it; a
  periodic snapshot is taken after the delete (so "the latest snapshot" would be the wrong
  one); ``Guardian.rewind`` to the delete's ``snapshot_id`` brings the files back, the agent is
  ready again within 30 s, and the black box holds the delete, ``rewind_requested``,
  ``watcher_armed`` and ``rewind_done``, intact.
- A rewind killed with SIGKILL just before or just after the swap is reconciled by the next
  service: ``rewind_failed`` or ``rewind_done``, with ``reconciled: true``.

There is no control socket yet (T04c-2), so the first test runs the real service's parts in
this process (``guardian_in_process``) to call ``Guardian.rewind``; the killed rewinds run it in
a process of their own (rewind_main.py) and the reconciliation is `backtide vigilar` itself.
"""

import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest

from backtide.blackbox import Event
from backtide.service.rewind import RewindStatus, read_pending
from backtide.snapshots import Snapshot
from tests.integration.service_kit import (
    CYCLE,
    Service,
    guardian_in_process,
    interrupted_rewind,
    snapshot_holds,
    wait_until,
    workspace_holds,
    write_in_agent,
)
from tests.integration.service_kit import exec_in_agent as exec_ok

pytestmark = pytest.mark.integration

FILES = {f"work/keep/file{i}.txt": f"the content of file {i}\n" for i in range(1, 6)}
WITHIN = CYCLE + 30  # a cycle, the sync, the snapshot and a loaded VM
READY_WITHIN = 30.0  # docs/19: after a rewind the Gateway is ready in less than 30 s


def explain(service: Service, delete: Event) -> str:
    """What the watcher pointed at, and why: the takes and the logged warnings."""
    takes = [(t.seq, t.snapshot_id, t.details.get("trigger")) for t in service.takes()]
    logs = [(e.seq, e.details.get("message")) for e in service.events("log", "system")]
    files = [
        (e.seq, e.action, e.target, e.snapshot_id)
        for e in service.events(source="file")
        if e.target.startswith("work/")
    ]
    return f"delete={delete}\ntakes={takes}\nlogs={logs}\nfile events={files}"


def ts(event: Event) -> datetime:
    return datetime.fromisoformat(event.ts.replace("Z", "+00:00"))


def test_deleted_files_come_back_with_a_rewind_and_the_black_box_says_so(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    with guardian_in_process(service) as guardian:
        write_in_agent(service, FILES)
        # Wait for the TAKE event of a snapshot that holds the files, not just for the snapshot:
        # the event is recorded once the barrier has made it the current one. A delete in the
        # barrier's settle window (0.1 s) would point one snapshot further back, which is the
        # documented cost of the barrier (docs/19, "La barrera").
        wait_until(
            lambda: any(snapshot_holds(service, t.snapshot_id, FILES) for t in service.takes()),
            WITHIN,
            "a snapshot that holds the files",
            context=service.diagnosis,
        )

        # The agent deletes them.
        exec_ok(service, "rm -r /workspace/work/keep")
        deletes: list[Event] = []

        def deleted() -> bool:
            deletes[:] = [
                e
                for e in service.events("delete", "file")
                if e.target in FILES or e.target == "work/keep"
            ]
            return any(e.target in FILES for e in deletes)

        wait_until(deleted, 30, "the file/delete events", context=service.diagnosis)
        delete = next(e for e in deletes if e.target in FILES)
        # The barrier: the delete points at a snapshot that still has the files.
        assert snapshot_holds(service, delete.snapshot_id, FILES), explain(service, delete)

        # A periodic snapshot AFTER the delete: the latest one no longer has the files, and the
        # delete still points at the one before.
        def periodic_after_delete() -> bool:
            later = [t for t in service.takes("cycle") if t.seq > delete.seq]
            return bool(later) and not snapshot_holds(service, later[-1].snapshot_id, FILES)

        wait_until(
            periodic_after_delete, WITHIN, "a snapshot after the delete", context=service.diagnosis
        )
        latest = service.snapshots()[-1]
        assert latest.id != delete.snapshot_id
        assert not snapshot_holds(service, latest.id, FILES)
        assert not workspace_holds(service, FILES)
        workspace_before = service.store.workspace_id()

        # The person rewinds to the point the delete names.
        assert delete.snapshot_id is not None
        started = time.monotonic()
        outcome = guardian.rewind(delete.snapshot_id, requested_by="test")
        took = time.monotonic() - started

        assert outcome.status is RewindStatus.DONE, (outcome, service.diagnosis())
        assert outcome.agent_started and service.jail.is_running()
        assert workspace_holds(service, FILES)
        inside = exec_ok(service, "cat /workspace/work/keep/file1.txt")  # the agent sees them
        assert inside == FILES["work/keep/file1.txt"]
        new_workspace = service.store.workspace_id()
        assert new_workspace != workspace_before
        assert outcome.undo is not None
        undo = Snapshot.parse(outcome.undo)
        assert undo is not None and undo.reason == "pre_restore"
        assert not snapshot_holds(
            service, outcome.undo, FILES
        )  # the undo point is the deleted state

        # The black box: the delete, the request, the watcher armed on the new workspace, the
        # agent stopped and ready again within 30 s, and the rewind done, in that order.
        (requested,) = service.events("rewind_requested", "snapshot")
        (done,) = service.events("rewind_done", "snapshot")
        request_id = requested.details["request_id"]
        assert done.details["request_id"] == request_id
        assert done.snapshot_id == delete.snapshot_id
        assert done.details["undo"] == outcome.undo
        assert done.details["workspace_id"] == new_workspace
        assert done.details["agent_started"] is True
        assert "problems" not in done.details
        armed = [
            e for e in service.events("watcher_armed", "system") if requested.seq < e.seq < done.seq
        ]
        assert [e.details["workspace_id"] for e in armed] == [new_workspace]
        stops = [e for e in service.events("agent_stop", "system") if e.details.get("request_id")]
        starts = [e for e in service.events("agent_start", "system") if e.details.get("request_id")]
        assert [e.details["reason"] for e in stops + starts] == ["rewind", "rewind"]
        assert delete.seq < requested.seq < stops[0].seq < armed[0].seq < starts[0].seq < done.seq
        ready_after = (ts(starts[0]) - ts(stops[0])).total_seconds()
        assert ready_after < READY_WITHIN, f"the agent took {ready_after:.1f} s to be ready"
        assert not service.config.pending_file.exists()

        # The watcher really watches the new workspace: a change after the rewind is described.
        write_in_agent(service, {"work/after.txt": "after the rewind\n"})

        def described() -> list[Event]:
            return [e for e in service.events("create", "file") if e.target == "work/after.txt"]

        wait_until(
            described, 30, "the file event of a change after the rewind", context=service.diagnosis
        )
        assert described()[-1].details["workspace_id"] == new_workspace
        print(f"rewind took {took:.1f} s; the agent was ready {ready_after:.1f} s after it stopped")

    report = service.box.verify()
    assert report.ok, report.problems


def interrupted(make_real_service: Callable[..., Service], when: str) -> tuple[Service, str, int]:
    service = make_real_service()
    target, workspace_before = interrupted_rewind(service, when)
    return service, target, workspace_before


def test_a_rewind_killed_before_the_swap_is_reconciled_as_failed(
    make_real_service: Callable[..., Service],
) -> None:
    service, target, workspace_before = interrupted(make_real_service, "before")

    # What the crash left: the intent, the request without an answer, the workspace untouched.
    intent = read_pending(service.config.pending_file)
    assert intent is not None and intent.target == target
    assert intent.from_workspace_id == workspace_before
    (requested,) = service.events("rewind_requested", "snapshot")
    assert requested.details["request_id"] == intent.request_id
    assert not service.events("rewind_done") and not service.events("rewind_failed")
    assert service.store.workspace_id() == workspace_before
    assert workspace_holds(service, {"work/marker.txt": "v2\n"})
    assert not service.jail.is_running()  # the rewind had stopped it

    service.start()
    service.wait_ready()
    (failed,) = service.events("rewind_failed", "snapshot")
    assert failed.details["reconciled"] is True
    assert failed.details["request_id"] == intent.request_id
    assert not service.events("rewind_done")
    assert not service.config.pending_file.exists()
    assert workspace_holds(service, {"work/marker.txt": "v2\n"})  # nothing was lost
    actions = [f"{e.source}/{e.action}" for e in service.events()]
    assert actions.index("snapshot/rewind_failed") < len(actions) - 1 - actions[::-1].index(
        "system/agent_start"
    )
    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems


def test_a_rewind_killed_after_the_swap_is_reconciled_as_done(
    make_real_service: Callable[..., Service],
) -> None:
    service, target, workspace_before = interrupted(make_real_service, "after")

    intent = read_pending(service.config.pending_file)
    assert intent is not None
    assert service.store.workspace_id() != workspace_before  # the swap happened
    assert workspace_holds(service, {"work/marker.txt": "v1\n"})
    assert not service.events("rewind_done") and not service.events("rewind_failed")

    service.start()
    service.wait_ready()
    (done,) = service.events("rewind_done", "snapshot")
    assert done.details["reconciled"] is True
    assert done.details["request_id"] == intent.request_id
    assert done.details["from_workspace_id"] == workspace_before
    assert done.snapshot_id == target
    undo = done.details["undo"]
    assert undo is not None and Snapshot.parse(undo) is not None
    assert snapshot_holds(service, undo, {"work/marker.txt": "v2\n"})  # the undo point is v2
    assert not service.events("rewind_failed")
    assert not service.config.pending_file.exists()
    assert workspace_holds(service, {"work/marker.txt": "v1\n"})
    assert service.jail.is_running()
    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems


def test_the_intent_lives_outside_the_volume(make_real_service: Callable[..., Service]) -> None:
    """Invariant 1: rewind.pending is backtide's, in its state folder, never in the agent's
    volume."""
    service = make_real_service()
    pending = service.config.pending_file
    assert pending.parent == service.config.state_dir
    assert not Path(pending).is_relative_to(service.store.root)
