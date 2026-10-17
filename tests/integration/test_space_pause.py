"""T04d-2 in the VM: the pause by space with the real OpenClaw, the real `docker pause` and the
real signals of a 1 GiB volume with simple quotas and a 64 MiB cap (docs/19, section 5).

The service is the real `backtide vigilar` (tests/integration/pause_main.py: the cap set through
the tests' one sudo command, the VM's small /tmp not counted as P6) and the person's side is
the real CLI (`backtide seguir`, `backtide rebobinar --si`) talking to it over the control socket.
"Frozen" is checked for real every time: Docker says Paused, the container's cgroup has
``cgroup.freeze`` at 1 and a process writing a heartbeat inside the agent does not move.

- Metadata below P1 (filled from the host in a sibling subvolume): frozen, the alert names
  what holds the space, `backtide seguir` refuses while it stands; a rewind of the frozen agent
  kills it (never wakes it) and leaves it stopped, not frozen, with the pause open; freeing the
  metadata, `backtide seguir` starts it.
- Data below P2: frozen; freed, `backtide seguir` thaws the same run of the agent.
- The workspace past its cap after a snapshot and deletes (P3, what the cap of T03b does not
  see): frozen; a rewind gives a new cap, so it ends green and the agent runs again.
- The service killed (SIGKILL) with the agent frozen: the next one kills the frozen agent at
  boot and keeps it stopped until `backtide seguir`.
"""

import errno
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from test_quota_assumptions import (
    DELETE_STRIDE,
    SMALL_FILE,
    commit,
    create,
    fill_by_preallocating,
    make_subvolume,
)

from backtide.jail import docker as jail_docker
from backtide.snapshots import btrfs, space
from tests.integration.conftest import (
    _agent_names,
    _remove_stale_test_agents,
    _require_agent_image,
)
from tests.integration.service_kit import (
    Service,
    exec_in_agent,
    make_service,
    run_cli,
    wait_until,
)

pytestmark = pytest.mark.integration

MIB = 1024**2
CAP = 64 * MIB  # P1 is 341 MiB on 1 GiB; a new volume has about 494 (docs/19, section 5)
REACT = 30.0  # the space thread checks every second; a loaded VM, a sync and the freeze
FREE_WITHIN = 180.0  # freed data chunks go back to unallocated on a later commit
BEAT = "work/beat"
BATCH = 2000
MARGIN = 16 * MIB  # how far past P1 the fill goes


@pytest.fixture
def service(quota_volume, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Service]:
    _require_agent_image()
    _remove_stale_test_agents()
    root = quota_volume.mnt / f"svc-{uuid4().hex}"
    root.mkdir(mode=0o700)
    made = make_service(
        root,
        tmp_path_factory.mktemp("pause-state"),
        _agent_names(os.getpid()),
        workspace_limit=CAP,
    )
    made.main = "tests.integration.pause_main"
    made.main_args = (str(quota_volume.mnt),)
    try:
        made.start()
        made.wait_ready()
        yield made
    finally:
        made.shutdown()


# --- looking at the agent ----------------------------------------------------------------------


def state(service: Service) -> dict:
    result = jail_docker.run(
        ["container", "inspect", "--format", "{{json .State}}", service.jail.config.name]
    )
    return json.loads(result.stdout)


def cgroup_freeze(pid: int) -> str:
    (line,) = [
        entry
        for entry in Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        if entry.startswith("0::")
    ]
    return (Path("/sys/fs/cgroup") / line[3:].lstrip("/") / "cgroup.freeze").read_text().strip()


def start_heartbeat(service: Service) -> None:
    """A process inside the agent that writes a counter every 0.2 s."""
    exec_in_agent(
        service,
        "mkdir -p /workspace/work && (i=0; while :; do i=$((i+1)); "
        f"echo $i > /workspace/{BEAT}; sleep 0.2; done) >/dev/null 2>&1 &",
    )
    wait_until(lambda: beat(service) is not None, 30, "the heartbeat to start")


def beat(service: Service) -> str | None:
    try:
        return (service.store.workspace / "agente" / BEAT).read_text()
    except OSError:
        return None


def assert_frozen_for_real(service: Service, *, heartbeat: bool = False) -> None:
    found = state(service)
    assert found["Running"] is True and found["Paused"] is True, found
    assert cgroup_freeze(found["Pid"]) == "1"
    if heartbeat:
        before = beat(service)
        time.sleep(2)
        assert beat(service) == before, "the heartbeat moved while the agent was frozen"


def wait_frozen(service: Service, condition: str) -> None:
    wait_until(
        lambda: (
            service.jail.is_paused()
            and any(
                condition in e.details.get("conditions", []) for e in service.events("space_pause")
            )
        ),
        REACT,
        f"the agent to be frozen for {condition}",
        context=service.diagnosis,
    )


def past_the_cap(service: Service) -> bool:
    return btrfs.qgroup_usage(service.store.workspace).referenced > CAP + MIB


def seguir(service: Service) -> int:
    return run_cli(service, "seguir").returncode


# --- filling the volume ------------------------------------------------------------------------


def fill_metadata_until_frozen(service: Service, filler: Path) -> None:
    """Small files (metadata only) in a sibling subvolume, in batches, until the agent is
    frozen for P1, and then on until P1 is red by ``MARGIN`` after a commit: right at the
    edge, the metadata reserved in flight comes back on the next commit and P1 turns green."""
    count = 0
    deadline = time.monotonic() + 300
    while not any("P1" in e.details.get("conditions", []) for e in service.events("space_pause")):
        assert time.monotonic() < deadline, f"never P1 after {count} files\n{service.diagnosis()}"
        count = add_small_files(filler, count, BATCH)
        time.sleep(0.2)
    while True:
        commit(filler)
        found = space.volume_space(filler)
        if found.meta_avail < space.metadata_threshold(found, CAP) - MARGIN:
            return
        assert time.monotonic() < deadline, f"P1 not red by a margin after {count} files"
        count = add_small_files(filler, count, BATCH)


def add_small_files(folder: Path, start: int, how_many: int) -> int:
    """Files f<start>... of 2,000 bytes (inline: metadata only). Stops quietly at ENOSPC."""
    for index in range(start, start + how_many):
        try:
            fd = create(folder / f"f{index}")
        except OSError as error:
            assert error.errno == errno.ENOSPC, error
            return index
        try:
            os.write(fd, SMALL_FILE)
        finally:
            os.close(fd)
    return start + how_many


def empty(folder: Path) -> None:
    for path in folder.iterdir():
        path.unlink()
    commit(folder)


def kill_service(service: Service) -> None:
    service.kill()


# --- the tests ---------------------------------------------------------------------------------


def test_metadata_below_the_minimum_freezes_the_agent_and_seguir_starts_it_once_freed(
    service: Service, quota_volume
) -> None:
    start_heartbeat(service)
    filler = make_subvolume(quota_volume.mnt / "filler")
    fill_metadata_until_frozen(service, filler)
    wait_frozen(service, "P1")
    assert_frozen_for_real(service, heartbeat=True)
    log = service.log_text()
    assert "El agente está pausado" in log
    assert "Lo que más ocupa" in log and "el espacio de trabajo actual" in log
    assert "backtide seguir" in log

    assert seguir(service) == 1  # still red: nothing changes
    assert_frozen_for_real(service)
    assert service.events("resume_refused")

    # Rewinding the frozen agent: killed (never woken by docker stop), and still red, so it
    # stays stopped, NOT frozen, with the pause open.
    first = service.snapshots()[0].id
    rewound = run_cli(service, "rebobinar", "--si", first)
    assert rewound.returncode in (0, 3), rewound.stderr
    after = state(service)
    assert after["Running"] is False and after["Paused"] is False, after
    assert after["ExitCode"] == 137  # SIGKILL: its SIGTERM handler never ran
    done = service.events("rewind_done")[-1]
    assert done.details["agent_started"] is False
    assert seguir(service) == 1

    empty(filler)
    wait_until(lambda: seguir(service) == 0, FREE_WITHIN, "`backtide seguir` to start the agent")
    wait_until(service.jail.is_running, 60, "the agent to run", context=service.diagnosis)
    assert not service.jail.is_paused()
    assert service.events("agent_start")[-1].details == {"reason": "resume"}
    resumed = service.events("space_resume")[-1]
    assert resumed.details["by"] == "user" and resumed.details["agent"] == "started"


def test_data_below_the_minimum_freezes_the_agent_and_seguir_thaws_the_same_run(
    service: Service, quota_volume
) -> None:
    start_heartbeat(service)
    started_at = state(service)["StartedAt"]
    filler = make_subvolume(quota_volume.mnt / "filler")
    fill_by_preallocating(filler, steps=(64 * MIB,))
    wait_frozen(service, "P2")
    assert_frozen_for_real(service, heartbeat=True)

    empty(filler)
    wait_until(lambda: seguir(service) == 0, FREE_WITHIN, "`backtide seguir` to thaw the agent")
    found = state(service)
    assert found["Running"] is True and found["Paused"] is False
    assert found["StartedAt"] == started_at  # thawed: the same run, not a restart
    before = beat(service)
    wait_until(lambda: beat(service) != before, 10, "the heartbeat to move again")
    assert service.events("space_resume")[-1].details["agent"] == "thawed"


def test_the_workspace_past_its_cap_freezes_the_agent_and_a_rewind_gives_a_new_cap(
    service: Service,
) -> None:
    """A13: deleting after a snapshot is charged without any quota check, so the workspace
    ends past its cap. The space thread commits every 5 s and sees it (P3)."""
    first = service.snapshots()[0].id
    small = service.store.workspace / "agente" / "work" / "small"
    small.mkdir(parents=True)
    count = 0
    while True:  # up to the cap: it answers EDQUOT, the one thing the cap of T03b checks
        try:
            fd = create(small / f"f{count}")
            try:
                os.write(fd, SMALL_FILE)
            finally:
                os.close(fd)
        except OSError as error:
            assert error.errno == errno.EDQUOT, error
            break
        count += 1
    commit(small)
    # Rounds of "snapshot, then delete one file per leaf", a batch at a time, until it is just
    # past the cap: every extra leaf is metadata the rewind will need (the volume is 1 GiB). A
    # round copies only the leaves the last snapshot shares, so if one is not enough (the cap
    # counts reservations, so EDQUOT may come well under it), the next snapshot gives more.
    for offset in range(DELETE_STRIDE):
        if past_the_cap(service):
            break
        takes = len(service.takes())
        wait_until(lambda n=takes: len(service.takes()) > n, 60, "a snapshot of the small files")
        victims = iter(range(offset, count, DELETE_STRIDE))
        while not past_the_cap(service):
            batch = [index for _, index in zip(range(100), victims, strict=False)]
            if not batch:
                break
            for index in batch:
                (small / f"f{index}").unlink()
            commit(small)
    assert past_the_cap(service), btrfs.qgroup_usage(service.store.workspace)
    wait_frozen(service, "P3")
    assert_frozen_for_real(service)
    assert "pasó de su tope después de la instantánea" in service.log_text()

    rewound = run_cli(service, "rebobinar", "--si", first)
    pauses = [e.details for e in service.events("space_pause")]
    assert rewound.returncode == 0, (rewound.stdout, rewound.stderr, pauses[-3:])
    assert "El agente está en marcha otra vez" in rewound.stdout
    found = state(service)
    assert found["Running"] is True and found["Paused"] is False
    resumed = service.events("space_resume")[-1]
    assert resumed.details["by"] == "rewind"
    assert btrfs.qgroup_usage(service.store.workspace).limit == CAP  # a whole new cap
    assert seguir(service) == 0  # nothing left to resume


def test_a_service_killed_with_the_agent_frozen_leaves_it_stopped_until_seguir(
    service: Service, quota_volume
) -> None:
    filler = make_subvolume(quota_volume.mnt / "filler")
    fill_metadata_until_frozen(service, filler)
    wait_frozen(service, "P1")
    kill_service(service)
    assert_frozen_for_real(service)  # nobody stopped it: still frozen

    starts = len(service.events("agent_start"))
    service.start()
    wait_until(
        lambda: len(service.events("service_start")) >= 2 and not service.jail.is_running(),
        120,
        "the new service to stop the frozen agent",
        context=service.diagnosis,
    )
    found = state(service)
    assert found["Paused"] is False and found["ExitCode"] == 137  # killed, never woken
    wait_until(
        lambda: [
            e for e in service.events("agent_stop") if e.details.get("reason") == "unsupervised"
        ],
        30,
        "agent_stop {reason: unsupervised}",
        context=service.diagnosis,
    )
    time.sleep(5)  # the boot finishes; the agent must not come back on its own
    assert not service.jail.is_running()
    assert len(service.events("agent_start")) == starts

    empty(filler)
    wait_until(lambda: seguir(service) == 0, FREE_WITHIN, "`backtide seguir` to start the agent")
    wait_until(service.jail.is_running, 60, "the agent to run", context=service.diagnosis)
    assert service.events("agent_start")[-1].details == {"reason": "resume"}
