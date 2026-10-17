"""The emergency growth of the volume (T04e-1, docs/19 section 6) with fake steps and readings.

Nothing here runs losetup or btrfs: the three privileged steps are a fake that changes the fake
sizes, so the order of the steps, the check after each one, every refusal and every failure
are tested on the Mac. The real growth is tests/integration/test_grow.py (skipped until the
founder approves its one sudo).
"""

import ast
from pathlib import Path
from typing import Any

import pytest

from backtide.snapshots import grow
from backtide.snapshots.grow import (
    NOT_CONFIGURED,
    GrowError,
    GrowLimits,
    GrowNotConfigured,
    GrowStatus,
    MountedOn,
    SystemProbe,
    VolumeGrower,
)
from backtide.snapshots.space import GIB, MIB, HostSpace

IMAGE = Path("/var/lib/backtide/volume.img")
MOUNT = Path("/srv/backtide")
VOLUME = MOUNT / "vol"


class World:
    """The image, the loop device and the btrfs, with fake privileged steps that grow them."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.records: list[tuple[dict[str, Any], int]] = []
        self.file = GIB
        self.loop = GIB
        self.fs = GIB
        self.host_space = HostSpace(total=100 * GIB, free=50 * GIB)
        self.mount = MountedOn(MOUNT, "btrfs", "/dev/loop3")
        self.backing = IMAGE
        self.fail: dict[str, Exception] = {}
        self.no_effect: set[str] = set()  # a step that "works" but changes nothing
        self.read_error: Exception | None = None
        self.stopped = True
        self.allocated: int | None = None  # None: the image is fully allocated
        self.box_broken = False

    # PrivilegedSteps

    def grow_file(self, image: Path, size: int) -> None:
        self.log.append(f"grow_file({image}, {size})")
        self._maybe_fail("grow_file")
        assert size > self.file  # never asked to shrink or stay
        if "grow_file" not in self.no_effect:
            self.file = size

    def set_capacity(self, loop: str) -> None:
        self.log.append(f"set_capacity({loop})")
        self._maybe_fail("set_capacity")
        if "set_capacity" not in self.no_effect:
            self.loop = self.file

    def resize(self, mount: Path) -> None:
        self.log.append(f"resize({mount})")
        self._maybe_fail("resize")
        if "resize" not in self.no_effect:
            self.fs = self.loop

    def _maybe_fail(self, step: str) -> None:
        if step in self.fail:
            raise self.fail[step]

    # VolumeProbe

    def mount_of(self, path: Path) -> MountedOn:
        self._maybe_unreadable()
        assert path == VOLUME
        return self.mount

    def backing_file(self, loop: str) -> Path:
        self._maybe_unreadable()
        assert loop == "loop3"
        return self.backing

    def loop_bytes(self, loop: str) -> int:
        self._maybe_unreadable()
        return self.loop

    def file_bytes(self, image: Path) -> int:
        self._maybe_unreadable()
        return self.file

    def allocated_bytes(self, image: Path) -> int:
        self._maybe_unreadable()
        return self.file if self.allocated is None else self.allocated

    def fs_bytes(self, mount: Path) -> int:
        self._maybe_unreadable()
        return self.fs

    def host(self, folder: Path) -> HostSpace:
        self._maybe_unreadable()
        assert folder == IMAGE.parent
        return self.host_space

    def _maybe_unreadable(self) -> None:
        if self.read_error is not None:
            raise self.read_error

    # The grower's other inputs

    def record(self, details: dict[str, Any], risk: int) -> bool:
        self.records.append((details, risk))
        return not self.box_broken

    def phases(self) -> list[str]:
        return [details["phase"] for details, _ in self.records]


@pytest.fixture
def world() -> World:
    return World()


CEILING_DEFAULT = 3 * GIB // 2


def grower(world: World, *, ceiling: int = CEILING_DEFAULT) -> VolumeGrower:
    return VolumeGrower(VOLUME, GrowLimits(IMAGE, ceiling), steps=world, probe=world)


def run(world: World, g: VolumeGrower | None = None, request_id: str = "r1") -> grow.GrowResult:
    g = g if g is not None else grower(world)
    return g.grow(request_id, agent_stopped=lambda: world.stopped, record=world.record)


# --- the size of a step ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("volume", "step"),
    [
        (GIB, 256 * MIB),  # 10 % is 102 MiB: the minimum wins
        (20 * GIB, 2 * GIB),  # exactly 10 %
        (3 * GIB, 320 * MIB),  # 307.2 MiB rounded up to 64 MiB
        (0, 256 * MIB),
    ],
)
def test_the_step_is_the_designs(volume: int, step: int) -> None:
    assert grow.step_for(volume) == step


def test_the_host_margin_is_the_step_plus_the_larger_of_10_percent_and_2_gib() -> None:
    assert grow.host_margin(HostSpace(total=10 * GIB, free=0), 256 * MIB) == 256 * MIB + 2 * GIB
    assert grow.host_margin(HostSpace(total=100 * GIB, free=0), GIB) == GIB + 10 * GIB


# --- the growth --------------------------------------------------------------------------------


def test_the_steps_run_in_order_and_each_is_checked(world: World) -> None:
    result = run(world)
    target = GIB + 256 * MIB
    assert world.log == [
        f"grow_file({IMAGE}, {target})",
        "set_capacity(loop3)",
        f"resize({MOUNT})",
    ]
    assert result.status is GrowStatus.DONE and result.grown
    assert (result.from_bytes, result.to_bytes, result.reached_bytes) == (GIB, target, target)
    assert result.done_steps == ("grow_file", "set_capacity", "resize")
    assert world.fs == target
    assert world.phases() == ["requested", "done"]
    requested, risk = world.records[0]
    assert risk == 2
    assert requested["request_id"] == "r1"
    assert (requested["from_bytes"], requested["to_bytes"]) == (GIB, target)
    assert requested["max_volume_bytes"] == 3 * GIB // 2
    assert requested["loop"] == "loop3"
    assert requested["signals"] == {
        "fs_bytes": GIB,
        "file_bytes": GIB,
        "loop_bytes": GIB,
        "host_free": 50 * GIB,
    }
    done, risk = world.records[1]
    assert risk == 2
    assert done["reached_bytes"] == target
    assert done["done_steps"] == ["grow_file", "set_capacity", "resize"]
    assert done["skipped_steps"] == []


def test_a_file_and_loop_already_big_enough_only_resize(world: World) -> None:
    """The VM test's volume (mkfs -b 1G on a 1.25 GiB image), and a growth cut half way
    before: what is already there is not done again, and never doubled."""
    world.file = world.loop = GIB + 256 * MIB
    result = run(world)
    assert world.log == [f"resize({MOUNT})"]
    assert result.grown
    assert world.records[-1][0]["skipped_steps"] == ["grow_file", "set_capacity"]


def test_a_growth_cut_after_the_file_finishes_with_the_loop(world: World) -> None:
    world.file = GIB + 256 * MIB
    assert run(world).grown
    assert world.log == ["set_capacity(loop3)", f"resize({MOUNT})"]


def test_only_once_per_rewind(world: World) -> None:
    g = grower(world)
    assert run(world, g, "r1").grown
    world.log.clear()
    again = run(world, g, "r1")
    assert again.status is GrowStatus.REFUSED and again.reason == "already_grown"
    assert world.log == []
    assert world.records[-1] == (
        {"phase": "refused", "request_id": "r1", "reason": "already_grown"},
        2,
    )
    # Another failed rewind may grow again, within the ceiling.
    assert run(world, g, "r2").grown


def test_a_refused_or_failed_growth_still_counts_as_the_one(world: World) -> None:
    g = grower(world)
    world.stopped = False
    assert run(world, g, "r1").reason == "agent_running"
    world.stopped = True
    assert run(world, g, "r1").reason == "already_grown"
    assert world.log == []


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda w: setattr(w, "stopped", False), "agent_running"),
        (lambda w: setattr(w, "backing", Path("/srv/other.img")), "not_the_image"),
        (lambda w: setattr(w, "backing", Path(f"{IMAGE} (deleted)")), "not_the_image"),
        (lambda w: setattr(w, "mount", MountedOn(MOUNT, "btrfs", "/dev/vda2")), "not_a_loop"),
        (lambda w: setattr(w, "mount", MountedOn(MOUNT, "ext4", "/dev/loop3")), "not_a_loop"),
        (lambda w: setattr(w, "read_error", OSError(5, "EIO")), "unreadable"),
        (lambda w: setattr(w, "fs", 3 * GIB // 2 - 128 * MIB), "ceiling"),
        (lambda w: setattr(w, "file", 2 * GIB), "ceiling"),  # resize max would take it all
        (lambda w: setattr(w, "loop", 2 * GIB), "ceiling"),
        (lambda w: setattr(w, "host_space", HostSpace(100 * GIB, 10 * GIB)), "host_space"),
    ],
)
def test_every_refusal_changes_nothing_and_is_recorded(
    world: World, change: Any, reason: str
) -> None:
    change(world)
    before = (world.file, world.loop, world.fs)
    result = run(world)
    assert result.status is GrowStatus.REFUSED and result.reason == reason
    assert not result.grown
    assert world.log == []
    assert (world.file, world.loop, world.fs) == before
    ((details, risk),) = world.records
    assert risk == 2
    assert details["phase"] == "refused" and details["reason"] == reason


def test_the_host_margin_is_exact(world: World) -> None:
    need = 256 * MIB + 10 * GIB  # 10 % of 100 GiB is more than 2 GiB
    world.host_space = HostSpace(100 * GIB, need - 1)
    assert run(world).reason == "host_space"
    assert world.records[-1][0]["host_needed"] == need
    world.host_space = HostSpace(100 * GIB, need)
    assert run(world, request_id="r2").grown


def test_the_host_margin_counts_what_a_sparse_image_has_not_taken_yet(world: World) -> None:
    """A 1 GiB image that only holds 100 MiB can still take 924 MiB of the host, and 256 MiB
    more once grown: the margin counts all of it, not only the step."""
    world.allocated = 100 * MIB
    need = (GIB + 256 * MIB - 100 * MIB) + 10 * GIB
    world.host_space = HostSpace(100 * GIB, need - 1)
    assert run(world).reason == "host_space"
    assert world.records[-1][0]["host_needed"] == need
    world.host_space = HostSpace(100 * GIB, need)
    assert run(world, request_id="r2").grown


def test_a_growth_whose_request_cannot_be_recorded_changes_nothing(world: World) -> None:
    world.box_broken = True
    result = run(world)
    assert result.status is GrowStatus.REFUSED and result.reason == "blackbox"
    assert world.log == []
    assert world.phases() == ["requested", "refused"]


def test_can_grow_only_with_real_steps(world: World) -> None:
    assert grower(world).can_grow
    stub = VolumeGrower(VOLUME, GrowLimits(IMAGE, CEILING_DEFAULT), probe=world)
    assert stub.configured and not stub.can_grow
    assert not VolumeGrower(None, None, steps=world, probe=world).can_grow


def test_the_ceiling_is_inclusive(world: World) -> None:
    assert run(world, grower(world, ceiling=GIB + 256 * MIB)).grown
    world.fs = world.file = world.loop = GIB
    over = run(world, grower(world, ceiling=GIB + 256 * MIB - 1))
    assert over.reason == "ceiling"


def test_an_agent_whose_state_cannot_be_read_is_not_grown_under(world: World) -> None:
    def broken() -> bool:
        raise RuntimeError("docker inspect failed")

    result = grower(world).grow("r1", agent_stopped=broken, record=world.record)
    assert result.reason == "agent_state_unknown"
    assert "docker inspect failed" in (result.error or "")
    assert world.log == []


def test_without_limits_nothing_is_read_and_it_says_not_configured(world: World) -> None:
    world.read_error = AssertionError("nothing may be read")
    g = VolumeGrower(None, None, probe=world)
    assert not g.configured
    result = run(world, g)
    assert result.reason == "not_configured"
    assert world.records == [
        ({"phase": "refused", "request_id": "r1", "reason": "not_configured"}, 2)
    ]


@pytest.mark.parametrize(
    ("step", "done"),
    [
        ("grow_file", []),
        ("set_capacity", ["grow_file"]),  # the file grew, the loop does not show it
        ("resize", ["grow_file", "set_capacity"]),
    ],
)
def test_a_failing_step_stops_there_and_is_recorded_with_what_was_done(
    world: World, step: str, done: list[str]
) -> None:
    world.fail[step] = OSError(1, "Operation not permitted")
    result = run(world)
    assert result.status is GrowStatus.FAILED and not result.grown
    assert result.step == step
    assert result.done_steps == tuple(done)
    assert "Operation not permitted" in (result.error or "")
    assert world.phases() == ["requested", "failed"]
    failed, risk = world.records[-1]
    assert risk == 3  # the volume may be half grown
    assert failed["step"] == step
    assert failed["done_steps"] == done
    assert failed["not_configured"] is False
    assert len(world.log) == len(done) + 1  # nothing after the failing step


@pytest.mark.parametrize("step", ["grow_file", "set_capacity", "resize"])
def test_a_step_that_changes_nothing_is_a_failure(world: World, step: str) -> None:
    world.no_effect.add(step)
    result = run(world)
    assert result.status is GrowStatus.FAILED and result.step == step
    assert "not" in (result.error or "")


def test_a_reading_that_fails_after_a_step_is_a_failure_of_that_step(world: World) -> None:
    class ReadFails(World):
        def loop_bytes(self, loop: str) -> int:
            if "set_capacity(loop3)" in self.log:
                raise OSError(5, "EIO")
            return super().loop_bytes(loop)

    broken = ReadFails()
    result = run(broken, grower(broken))
    assert result.status is GrowStatus.FAILED and result.step == "set_capacity"


def test_production_steps_are_not_configured_and_change_nothing(world: World) -> None:
    g = VolumeGrower(VOLUME, GrowLimits(IMAGE, 3 * GIB // 2), steps=NOT_CONFIGURED, probe=world)
    result = run(world, g)
    assert result.status is GrowStatus.FAILED
    assert (result.step, result.reason) == ("grow_file", "not_configured")
    assert (world.file, world.loop, world.fs) == (GIB, GIB, GIB)
    failed = world.records[-1][0]
    assert failed["not_configured"] is True
    assert "T13" in failed["error"]
    for call in (
        lambda: NOT_CONFIGURED.grow_file(IMAGE, 2 * GIB),
        lambda: NOT_CONFIGURED.set_capacity("loop3"),
        lambda: NOT_CONFIGURED.resize(MOUNT),
    ):
        with pytest.raises(GrowNotConfigured, match="not configured"):
            call()


def test_the_grower_never_sees_the_snapshots() -> None:
    """Nothing to delete with: the module imports no store and calls nothing that deletes,
    prunes or runs a command (the privileged steps are injected)."""
    tree = ast.parse(Path(grow.__file__).read_text())
    imported = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported <= {
        "os", "re", "stat", "collections.abc", "dataclasses", "enum", "pathlib", "typing",
        "backtide.snapshots", "backtide.snapshots.model", "backtide.snapshots.space",
    }  # fmt: skip
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} | {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    forbidden = {"delete", "delete_subvolume", "prune", "SnapshotStore", "subprocess", "system"}
    assert not names & forbidden


# --- the real pieces that need no privilege ----------------------------------------------------


def test_truncate_grow_only_grows_a_regular_file(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    image.write_bytes(b"\0" * 4096)
    grow.truncate_grow(image, 1 * MIB)
    assert image.stat().st_size == MIB
    grow.truncate_grow(image, 4096)  # never shrinks
    assert image.stat().st_size == MIB
    link = tmp_path / "link.img"
    link.symlink_to(image)
    with pytest.raises(GrowError):
        grow.truncate_grow(link, 2 * MIB)
    with pytest.raises(GrowError):
        grow.truncate_grow(tmp_path, 2 * MIB)
    with pytest.raises(GrowError):
        grow.truncate_grow(image, 0)
    assert image.stat().st_size == MIB


def test_the_argv_of_the_privileged_steps() -> None:
    assert grow.set_capacity_argv("loop3") == ("losetup", "--set-capacity", "/dev/loop3")
    assert grow.resize_argv(MOUNT) == ("btrfs", "filesystem", "resize", "max", str(MOUNT))
    for bad in ("loop", "sda", "loop3 --all", "../loop3"):
        with pytest.raises(ValueError):
            grow.set_capacity_argv(bad)
    with pytest.raises(ValueError):
        grow.resize_argv(Path("relative"))


def _mountinfo(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "mountinfo"
    path.write_text("\n".join(lines) + "\n")
    return path


ROOT_LINE = "22 1 252:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw"
LOOP_LINE = "95 22 0:55 / /srv/backtide rw,noatime shared:50 - btrfs /dev/loop3 rw,space_cache=v2"


def test_the_probe_finds_the_mount_that_holds_the_volume(tmp_path: Path) -> None:
    probe = SystemProbe(mountinfo=_mountinfo(tmp_path, ROOT_LINE, LOOP_LINE))
    found = probe.mount_of(Path("/srv/backtide/vol"))
    assert found == MountedOn(Path("/srv/backtide"), "btrfs", "/dev/loop3")
    assert grow.loop_name(found.source) == "loop3"
    assert probe.mount_of(Path("/srv/other")).source == "/dev/vda2"


def test_the_probe_takes_the_mount_on_top_and_unescapes(tmp_path: Path) -> None:
    over = "96 22 0:56 / /srv/backtide rw shared:51 - tmpfs tmpfs rw"
    spaced = r"97 22 0:57 / /srv/with\040space rw - btrfs /dev/loop4 rw"
    probe = SystemProbe(mountinfo=_mountinfo(tmp_path, ROOT_LINE, LOOP_LINE, over, spaced))
    assert probe.mount_of(Path("/srv/backtide/vol")).fs_type == "tmpfs"
    assert probe.mount_of(Path("/srv/with space/x")).source == "/dev/loop4"


@pytest.mark.parametrize("source", ["/dev/vda2", "/dev/loop", "/dev/loop3p1", "loop3", "tmpfs"])
def test_only_a_whole_loop_device_is_a_loop(source: str) -> None:
    assert grow.loop_name(source) is None


def test_the_probe_reads_the_loop_from_sys_block(tmp_path: Path) -> None:
    loop = tmp_path / "block" / "loop3"
    (loop / "loop").mkdir(parents=True)
    (loop / "loop" / "backing_file").write_text(f"{IMAGE}\n")
    (loop / "size").write_text("2621440\n")
    probe = SystemProbe(sys_block=tmp_path / "block")
    assert probe.backing_file("loop3") == IMAGE
    assert probe.loop_bytes("loop3") == 2621440 * 512
    (loop / "size").write_text("-1\n")
    with pytest.raises(grow.SnapshotError):
        probe.loop_bytes("loop3")
    with pytest.raises(grow.SnapshotError):
        probe.backing_file("../loop3")
    with pytest.raises(grow.SnapshotError):
        probe.backing_file("loop9")  # missing


def test_the_probe_reads_a_regular_files_size_without_following_links(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    image.write_bytes(b"\0" * 10)
    probe = SystemProbe()
    assert probe.file_bytes(image) == 10
    sparse = tmp_path / "sparse.img"
    with open(sparse, "xb") as handle:
        handle.truncate(64 * MIB)
    assert probe.file_bytes(sparse) == 64 * MIB
    assert probe.allocated_bytes(sparse) < MIB  # holes take nothing on the host
    link = tmp_path / "link"
    link.symlink_to(image)
    with pytest.raises(grow.SnapshotError):
        probe.file_bytes(link)
    with pytest.raises(grow.SnapshotError):
        probe.file_bytes(tmp_path / "missing")
