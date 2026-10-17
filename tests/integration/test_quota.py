"""T03b-2: the space cap follows the workspace through rewinds, and a full agent can still be
rewound (docs/16-diseno-t03b-tope.md).

The criterion of T03b (docs/backlog.md): an agent that tries to fill the data or the metadata
hits its cap before the volume is full, and afterwards the workspace can be rewound. It is
test_a_filling_agent_hits_its_cap_and_the_rewind_still_works, with the real OpenClaw in its jail
on a 1 GiB btrfs with simple quotas, for each way of filling it: data, metadata, and data
followed by metadata. The rest:

- the cap is moved by SnapshotStore at the right moments: init(), restore() and the undo;
- the rewind works when the old workspace is already past its cap (the hardest case for the
  ro flip that publishes the undo point, docs/16 A7 and A13);
- the negative control: with no cap, the same metadata-full volume cannot be rewound, so the
  cap is what saves the rewind (docs/10, the T01b note);
- the evil agent (invariant 7): from inside the jail it cannot lift its cap, and its copies
  cannot dodge it through reflinks.

Everything runs as the unprivileged Lima user. The only privileged command is
``quota_volume.set_limit`` (``sudo -n btrfs qgroup limit``), which the stores get as their
``set_limit``. The fills reuse the helpers of test_quota_assumptions.py (the spike, A1-A15).
"""

import errno
import json
import os
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from test_quota_assumptions import (
    FILL_TIMEOUT,
    MIB,
    TEST_CAP,
    Space,
    commit,
    fill_by_preallocating,
    fill_with_small_files,
    mib,
    probe_copiers,
    push_past_cap,
    report,
    space,
    usage,
)

from backtide.jail import JailError, docker
from backtide.jail.config import (
    CONTAINER_WORKSPACE,
    HEALTH_URL,
    SYS_MASKS,
    docker_create_argv,
    token_env,
)
from backtide.snapshots import Reason, RestoreIncomplete, RestoreResult, SnapshotNoSpace, btrfs
from backtide.snapshots.store import SnapshotStore

pytestmark = pytest.mark.integration

REWIND_RESERVE = 13 * MIB  # what the EXCHANGE and the snapshot reserve (docs/16: ~12.75 MiB)
ROOM_FOR_REWIND = 3 * REWIND_RESERVE  # "well above": the spike's worst case has about 6 times
# The agent writes its own state while it starts (tens of MiB), so "back to what it was" has
# a margin; the generation that was deleted held about a whole cap.
SETTLED_MARGIN = TEST_CAP // 2
NEAR_THE_CAP = 0.9  # a fill that stops at EDQUOT has charged almost the whole cap
SETTLE_TIMEOUT = 90.0  # seconds for the cleaner to free a deleted subvolume
FILL_SECONDS = 240  # the fill script's own deadline, inside the exec timeout
FILLER = f"{CONTAINER_WORKSPACE}/work/filler"
MARKER = f"{CONTAINER_WORKSPACE}/work/marker.txt"


NO_AGENT = nullcontext  # the quiesce of tests with no agent: nothing to stop


# Helpers


def store_on(
    volume, clock: Callable[[], datetime], *, limit: int | None, name: str = "store"
) -> SnapshotStore:
    """An initialised store in a folder of the quota volume, its workspace capped at ``limit``
    bytes (None: no cap) through the volume's own privileged command."""
    root = volume.mnt / name
    root.mkdir(mode=0o700)
    store = SnapshotStore(root, clock=clock, workspace_limit=limit, set_limit=volume.set_limit)
    store.init()
    return store


def cap_of(path: Path) -> tuple[int | None, int | None]:
    """(referenced limit, exclusive limit) of the subvolume at ``path``, as the kernel says."""
    found = btrfs.qgroup_usage(path)
    return found.limit, found.exclusive_limit


def assert_undo_point(store: SnapshotStore, undo_id: str) -> Path:
    """The undo point is published: read-only, in the listing and without a cap."""
    path = store.snapshots_dir / undo_id
    assert btrfs.is_readonly(path)
    assert cap_of(path) == (None, None)
    assert undo_id in [snap.id for snap in store.snapshots()]
    return path


def assert_room_for_a_rewind(found: Space) -> None:
    """The volume is far from full: the metadata chunks, plus half of what is unallocated
    (metadata is DUP), hold several times the ~13 MiB that a rewind reserves."""
    free_metadata = found.metadata_total - found.metadata_used - found.global_rsv
    room = found.unallocated // 2 + free_metadata
    assert room >= ROOM_FOR_REWIND, f"no room for a rewind: {found.summary()}"


# Runs inside the agent's container (python3 of the image) as the agent's user. Fills
# /workspace like fill_by_writing / fill_with_small_files of the spike, and prints one JSON list:
# a dict per phase with the errno that ended it (0: the deadline), the call that got it and how
# much it wrote (bytes for "data", files for "metadata").
FILL_SCRIPT = r"""
import itertools, json, os, shutil, sys, time

mode, base, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
MIB = 1 << 20
BLOCK = b"\0" * MIB
SMALL = b"x" * 2000  # under max_inline (2048): stored in the metadata tree
deadline = time.monotonic() + seconds
phases = []


def end(phase, started, amount, error, call):
    phases.append({
        "phase": phase, "errno": error, "call": call, "amount": amount,
        "seconds": round(time.monotonic() - started, 1),
    })


def fill_data(directory):
    os.makedirs(directory)
    started, written, call = time.monotonic(), 0, "create"
    try:
        for index in itertools.count():
            if time.monotonic() > deadline:
                return end("data", started, written, 0, "deadline")
            call = "create"
            fd = os.open(os.path.join(directory, f"data-{index}"),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                call = "write"
                for _ in range(64):  # 64 MiB files, 1 MiB blocks
                    written += os.write(fd, BLOCK)
            finally:
                os.close(fd)
    except OSError as e:
        end("data", started, written, e.errno, call)


def fill_metadata(directory):
    os.makedirs(directory)
    started, count, call = time.monotonic(), 0, "create"
    try:
        for count in itertools.count():
            if count % 1000 == 0 and time.monotonic() > deadline:
                return end("metadata", started, count, 0, "deadline")
            call = "create"
            fd = os.open(os.path.join(directory, f"f{count}"),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                call = "write"
                os.write(fd, SMALL)
            finally:
                os.close(fd)
    except OSError as e:
        end("metadata", started, count, e.errno, call)


if mode == "data":
    fill_data(base + "/data")
elif mode == "metadata":
    fill_metadata(base + "/small")
else:  # data_then_metadata: the data comes back right before the metadata is spent
    fill_data(base + "/data")
    shutil.rmtree(base + "/data")
    fill_metadata(base + "/small")
print(json.dumps(phases))
"""

# Runs inside the container. The evil agent tries to lift its own cap, and prints one JSON
# object with the errno of each attempt (0: it worked).
LIFT_THE_CAP_SCRIPT = r"""
import fcntl, json, os, struct, sys

fsid, subvolume_id = sys.argv[1], sys.argv[2]
# BTRFS_IOC_QGROUP_LIMIT = _IOR(0x94, 43, struct btrfs_ioctl_qgroup_limit_args): what
# `btrfs qgroup limit none /workspace` sends. qgroupid 0 means the subvolume of the fd.
BTRFS_IOC_QGROUP_LIMIT = 0x8030942B
QGROUP_LIMIT_MAX_RFER = 1
NONE = 2**64 - 1
results = {}


def attempt(name, action):
    try:
        action()
        results[name] = 0
    except OSError as e:
        results[name] = e.errno


def qgroup_limit_ioctl():
    fd = os.open("/workspace", os.O_RDONLY | os.O_DIRECTORY)
    try:
        args = bytearray(struct.pack("=QQQQQQ", 0, QGROUP_LIMIT_MAX_RFER, NONE, 0, 0, 0))
        fcntl.ioctl(fd, BTRFS_IOC_QGROUP_LIMIT, args, True)
    finally:
        os.close(fd)


def read(path):
    def action():
        with open(path) as f:
            f.read()
    return action


def write(path, value):
    def action():
        with open(path, "w") as f:
            f.write(value)
    return action


fs = "/sys/fs/btrfs/" + fsid
# Since T04d-1 the jail covers /sys/fs/btrfs with an empty read-only tmpfs: the agent cannot
# even read its cap, and the files that could lift it do not exist for it.
attempt("max_referenced_read", read(fs + "/qgroups/0_" + subvolume_id + "/max_referenced"))
try:
    with open(fs + "/qgroups/0_" + subvolume_id + "/max_referenced") as f:
        results["max_referenced_seen"] = int(f.read())
except OSError:
    results["max_referenced_seen"] = None
attempt("qgroup_limit_ioctl", qgroup_limit_ioctl)
attempt("quota_override", write(fs + "/quota_override", "1"))
attempt("max_referenced", write(fs + "/qgroups/0_" + subvolume_id + "/max_referenced", str(NONE)))
attempt("limit_flags", write(fs + "/qgroups/0_" + subvolume_id + "/limit_flags", "0"))
attempt("create_in_the_mask", write("/sys/fs/btrfs/backtide-probe", "1"))
print(json.dumps(results))
"""


def fill_in_the_container(agent, mode: str) -> list[dict]:
    """Run FILL_SCRIPT in the agent's container; return the phases it printed."""
    result = agent.exec(
        ["python3", "-c", FILL_SCRIPT, mode, FILLER, str(FILL_SECONDS)],
        check=True,
        timeout=FILL_TIMEOUT + 120,
    )
    return json.loads(result.stdout)


def describe(phases: list[dict]) -> str:
    return "; ".join(
        f"{p['phase']} {mib(p['amount']) if p['phase'] == 'data' else str(p['amount']) + ' files'}"
        f" until {errno.errorcode.get(p['errno'], p['errno'])} at {p['call']}, {p['seconds']} s"
        for p in phases
    )


def wait_until_the_deleted_space_is_free(mnt: Path, before: Space) -> Space:
    """Wait until the data and metadata in use are back to what they were in ``before`` (plus
    ``SETTLED_MARGIN``). Deleting a subvolume returns before its space does: the cleaner frees
    it a little later. Fails the test, with the last reading, if that takes too long."""
    deadline = time.monotonic() + SETTLE_TIMEOUT
    limit = before.data_used + before.metadata_used + SETTLED_MARGIN
    while True:
        found = space(mnt)
        if found.data_used + found.metadata_used <= limit:
            return found
        if time.monotonic() > deadline:
            pytest.fail(f"the deleted space did not come back in time: {found.summary()}")
        time.sleep(1)


def rewind_agent(agent, snap) -> tuple[RestoreResult, bool]:
    """Rewind the agent's workspace to ``snap`` with the real quiesce and check the result:
    another workspace, the marker back, the filler gone, the agent healthy (started here if it
    had crashed: quiesce leaves a stopped agent stopped), the new workspace capped and the undo
    point published. Returns the result and whether this had to start the agent."""
    store = agent.store
    before = store.workspace_id()
    rewound = store.restore(snap.id, quiesce=agent.quiesce)
    restarted = not agent.jail.is_running()
    if restarted:
        agent.jail.start()
        agent.jail.wait_ready()
    assert store.workspace_id() != before
    assert (agent.workspace / "work" / "marker.txt").read_text() == "before\n"
    assert agent.exec(["cat", MARKER], check=True).stdout == "before\n"  # the container sees it
    assert not (agent.workspace / "work" / "filler").exists()
    answer = agent.exec(["curl", "--fail", "--silent", HEALTH_URL], check=True).stdout
    assert json.loads(answer)["ok"] is True
    assert cap_of(store.workspace) == (TEST_CAP, None)
    assert rewound.undo is not None
    assert_undo_point(store, rewound.undo.id)
    return rewound, restarted


def health(agent) -> str:
    """What the Gateway answers on /healthz, or why nothing does."""
    try:
        if not agent.jail.is_running():
            return "container stopped"
        probe = agent.exec(["curl", "--fail", "--silent", "--max-time", "5", HEALTH_URL])
    except JailError as error:
        return f"unreachable ({error})"
    return probe.stdout.strip() or f"curl exited {probe.returncode}"


# The cap follows the workspace (no agent)


def test_the_cap_follows_the_workspace_through_a_rewind_and_its_undo(
    quota_volume, clock: Callable[[], datetime]
) -> None:
    """init() caps the workspace. After restore() the new workspace (another subvolume) has the
    cap and the undo point does not; the same after the undo, whose workspace is capped again."""
    store = store_on(quota_volume, clock, limit=TEST_CAP)
    assert cap_of(store.workspace) == (TEST_CAP, None)
    assert store.workspace_usage().limit == TEST_CAP
    (store.workspace / "kept").write_text("before")
    snap = store.take(Reason.MANUAL)
    assert cap_of(store.snapshots_dir / snap.id) == (None, None)  # snapshots are born uncapped
    (store.workspace / "extra").write_text("only in the old workspace")
    first = store.workspace_id()

    rewound = store.restore(snap.id, quiesce=NO_AGENT)

    second = store.workspace_id()
    assert second != first
    assert cap_of(store.workspace) == (TEST_CAP, None)
    assert (store.workspace / "kept").read_text() == "before"
    assert not (store.workspace / "extra").exists()
    assert rewound.undo is not None
    assert_undo_point(store, rewound.undo.id)
    assert cap_of(store.snapshots_dir / snap.id) == (None, None)

    undone = store.restore(rewound.undo.id, quiesce=NO_AGENT)

    assert store.workspace_id() not in (first, second)
    assert cap_of(store.workspace) == (TEST_CAP, None)
    assert (store.workspace / "extra").read_text() == "only in the old workspace"
    assert undone.undo is not None
    assert_undo_point(store, undone.undo.id)
    assert btrfs.qgroup_usage(store.snapshots_dir / rewound.undo.id).limit is None


def test_a_rewind_works_with_the_old_workspace_past_its_cap(
    quota_volume, clock: Callable[[], datetime], record_property: Callable[[str, object], None]
) -> None:
    """Deleting after a snapshot is not checked against the cap, so a workspace can end past
    it (docs/16, A13), and then even flipping it read-only fails with EDQUOT (A7). The rewind
    must still publish it as the undo point: the old workspace loses its cap first. Then the
    undo point can be deleted."""
    mnt = quota_volume.mnt
    store = store_on(quota_volume, clock, limit=TEST_CAP)
    (store.workspace / "kept").write_text("before")
    snap = store.take(Reason.MANUAL)
    past = push_past_cap(mnt, store.workspace)  # fills to EDQUOT, snapshots, deletes some
    # The precondition: this really is the case the uncapping exists for.
    try:
        btrfs.set_readonly(store.workspace, True)
    except SnapshotNoSpace:
        pass
    else:
        btrfs.set_readonly(store.workspace, False)
        pytest.fail(f"the ro flip worked past the cap, so this test proves nothing: {past}")
    assert not btrfs.is_readonly(store.workspace)
    first = store.workspace_id()

    try:
        rewound = store.restore(snap.id, quiesce=NO_AGENT)
    except RestoreIncomplete as error:
        pytest.fail(f"the old workspace could not be published past its cap: {error}")

    assert store.workspace_id() != first
    assert cap_of(store.workspace) == (TEST_CAP, None)
    assert (store.workspace / "kept").read_text() == "before"
    assert not (store.workspace / "small").exists()
    assert rewound.undo is not None
    undo = assert_undo_point(store, rewound.undo.id)
    undo_usage = usage(undo)
    assert undo_usage.referenced > TEST_CAP  # it kept its charge, only its cap is gone
    assert (undo / "small").is_dir()
    report(
        record_property,
        "rewind_past_the_cap",
        f"old workspace at {mib(past.referenced)} of {mib(TEST_CAP)} before the rewind; the undo "
        f"point reads {mib(undo_usage.referenced)}, read-only, cap {cap_of(undo)}; "
        f"{space(mnt).summary()}",
    )

    store.delete(rewound.undo.id)

    assert not undo.exists()
    assert rewound.undo.id not in [s.id for s in store.snapshots()]


# The criterion of T03b, with the real agent


@pytest.mark.parametrize("mode", ["data", "metadata", "data_then_metadata"])
def test_a_filling_agent_hits_its_cap_and_the_rewind_still_works(
    start_quota_agent, mode: str, record_property: Callable[[str, object], None]
) -> None:
    """The real OpenClaw's container fills /workspace until it gets an error. The error is
    EDQUOT (the cap), never ENOSPC (the volume), and the volume keeps room for a rewind. The
    rewind then works with the agent stopped, crashed or alive: the marker is back, the
    filler is gone, the agent is healthy, the new workspace has the cap, and it hits the cap
    again (a second generation, after the first undo point is deleted), and that one rewinds
    too."""
    agent = start_quota_agent(TEST_CAP)
    store, mnt = agent.store, agent.store.root.parent
    assert store.workspace_usage().limit == TEST_CAP
    agent.exec(["sh", "-c", f"echo before > {MARKER}"], check=True)
    snap = store.take(Reason.MANUAL)
    empty = space(mnt)

    phases = fill_in_the_container(agent, mode)

    os.sync()  # write back what the fill left in the page cache: referenced follows it
    commit(mnt)
    full = space(mnt)
    filled = store.workspace_usage()
    assert filled is not None and filled.limit == TEST_CAP
    still = health(agent)
    running = agent.jail.is_running()
    assert [p["errno"] for p in phases] == [errno.EDQUOT] * len(phases), describe(phases)
    assert filled.referenced >= NEAR_THE_CAP * TEST_CAP, (filled, describe(phases))
    assert_room_for_a_rewind(full)

    rewound, restarted = rewind_agent(agent, snap)

    # A new generation: the cap is per workspace, and the undo point still holds the first
    # fill, so a second one on top would not be about the cap (docs/16: the generations
    # pile up, which T04 has to watch). Delete the undo point and wait for its space.
    store.delete(rewound.undo.id)
    settled = wait_until_the_deleted_space_is_free(mnt, empty)

    again = fill_in_the_container(agent, mode)  # the cap followed the rewind

    os.sync()
    commit(mnt)
    after = space(mnt)
    assert [p["errno"] for p in again] == [errno.EDQUOT] * len(again), describe(again)
    assert_room_for_a_rewind(after)
    rewind_agent(agent, snap)  # and the second generation rewinds too
    report(
        record_property,
        f"filling_agent_{mode}",
        f"{describe(phases)}; {full.summary()}; workspace {mib(filled.referenced)} of "
        f"{mib(TEST_CAP)}; agent running after the fill: {running} ({still}); "
        f"restarted by the test after the rewind: {restarted}; undo point deleted, then "
        f"{settled.summary()}; second fill after the rewind: {describe(again)}; "
        f"{after.summary()}",
    )


# The negative control: without the cap, the rewind is the casualty


def test_without_a_cap_a_metadata_full_volume_cannot_be_rewound(
    quota_volume, clock: Callable[[], datetime], record_property: Callable[[str, object], None]
) -> None:
    """The recipe of the spike (A10): preallocate data until ENOSPC, then create small files
    until ENOSPC. Metadata is what ran out, and the staging snapshot of the rewind, which
    reserves metadata, fails. With the cap (the test above) the same agent stops earlier and
    the rewind works, so the cap is what saves it. The workspace stays as it was."""
    mnt = quota_volume.mnt
    store = store_on(quota_volume, clock, limit=None)
    assert store.workspace_usage().limit is None
    (store.workspace / "kept").write_text("before")
    snap = store.take(Reason.MANUAL)
    (store.workspace / "data").mkdir()
    data = fill_by_preallocating(store.workspace / "data")
    small = fill_with_small_files(store.workspace / "small")
    full = space(mnt)
    assert (data.errno, small.errno) == (errno.ENOSPC, errno.ENOSPC)
    assert small.call == "create", small  # an empty file needs metadata only: that ran out
    assert full.unallocated < 16 * MIB, full.summary()
    assert full.metadata_total - full.metadata_used - full.global_rsv < 8 * MIB, full.summary()
    first = store.workspace_id()

    with pytest.raises(SnapshotNoSpace) as failure:
        store.restore(snap.id, quiesce=NO_AGENT)

    report(
        record_property,
        "uncapped_metadata_full",
        f"{data.summary()}, {small.summary('small files')}; {full.summary()}; "
        f"restore: {failure.value}",
    )
    assert failure.value.errno == errno.ENOSPC
    assert store.workspace_id() == first  # unchanged
    assert (store.workspace / "kept").read_text() == "before"
    assert not (store.root / "workspace.restore").exists()  # no staging left behind
    assert [s.id for s in store.snapshots()] == [snap.id]


# The evil agent (invariant 7)


def run_without_the_sys_masks(agent, agent_leftovers, command: list[str]) -> str:
    """Run ``command`` in a one-off container that is the agent's jail minus the two /sys
    masks: same image, user, capabilities, seccomp profile, read-only root and mounts, but its
    own entrypoint. It shows what is left once the first layer is gone. The container is named
    like a test agent, so a later run removes it if this one is killed."""
    config = agent.jail.config
    name, _ = agent_leftovers.names(os.getpid())
    masks = tuple(f"{mask}:" for mask in SYS_MASKS)
    argv = docker_create_argv(replace(config, name=name))
    kept: list[str] = []
    skip = False
    for index, arg in enumerate(argv):
        if skip:
            skip = False
        elif arg == "--tmpfs" and argv[index + 1].startswith(masks):
            skip = True
        else:
            kept.append(arg)
    assert len(kept) == len(argv) - 4, "expected to drop exactly the two /sys masks"
    kept[0:1] = ["run", "--rm"]
    entrypoint = kept.index("--entrypoint")
    kept[entrypoint + 1] = command[0]  # create has --entrypoint tini <image> <gateway command>
    image = kept.index(config.image)
    run = [*kept[: image + 1], *command[1:]]
    return docker.run(run, env=token_env(config), timeout=120).stdout


def test_the_agent_cannot_lift_its_cap_or_dodge_it_with_reflinks(
    start_quota_agent, agent_leftovers, record_property: Callable[[str, object], None]
) -> None:
    """From inside the jail: the BTRFS_IOC_QGROUP_LIMIT ioctl fails with EOPNOTSUPP (95, the
    seccomp block of the 0x94 ioctls: the agent has no CAP_SYS_ADMIN either), the sysfs files
    that could lift the cap are hidden (/sys/fs/btrfs is an empty read-only tmpfs for the agent:
    nothing to read, nothing to write, nothing to create) and the cap reads the same afterwards.
    copy_file_range returns EXDEV (18) and every copier falls back to a real copy that shares
    no block with its original, so a reflink cannot hide data from the cap (docs/16, A11)."""
    agent = start_quota_agent(TEST_CAP)
    store = agent.store
    fsid, subvolume = btrfs.fsid(store.root), str(store.workspace_id())

    lifting = json.loads(
        agent.exec(["python3", "-c", LIFT_THE_CAP_SCRIPT, fsid, subvolume], check=True).stdout
    )
    unmasked = json.loads(
        run_without_the_sys_masks(
            agent, agent_leftovers, ["python3", "-c", LIFT_THE_CAP_SCRIPT, fsid, subvolume]
        )
    )
    probe, shared = probe_copiers(agent)

    report(
        record_property,
        "evil_agent_cap",
        f"lifting the cap: {lifting}; without the /sys masks: {unmasked}; copiers: {probe}",
    )
    assert lifting["qgroup_limit_ioctl"] == 95  # blocked by seccomp
    # First layer, since T04d-1: the agent cannot even see the qgroups.
    assert lifting["max_referenced_seen"] is None
    assert all(
        lifting[attempt] == errno.ENOENT
        for attempt in ("max_referenced_read", "quota_override", "max_referenced", "limit_flags")
    ), lifting
    assert lifting["create_in_the_mask"] == errno.EROFS, lifting
    # Second layer, proven with a container that has no masks (the jail minus the two tmpfs):
    # the agent reads its real cap, and still cannot write any file that would lift it (sysfs is
    # read-only for it) nor use the ioctl (seccomp).
    assert unmasked["max_referenced_seen"] == TEST_CAP, unmasked
    assert unmasked["max_referenced_read"] == 0, unmasked
    assert unmasked["qgroup_limit_ioctl"] == 95, unmasked
    assert all(
        unmasked[attempt] == errno.EROFS
        for attempt in ("quota_override", "max_referenced", "limit_flags")
    ), unmasked
    assert cap_of(store.workspace) == (TEST_CAP, None)
    assert store.workspace_id() == int(subvolume)
    assert probe["copy_file_range"] == -errno.EXDEV
    assert probe["read_write"] == 0
    assert probe["cp"] == [0, ""] and probe["cp_reflink_auto"] == [0, ""]
    assert probe["node_copyfile"] == [0, ""] and probe["node_copyfile_ficlone"] == [0, ""]
    assert not any(shared.values()), f"a copy shares blocks with its original: {shared}"
