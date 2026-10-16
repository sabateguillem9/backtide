"""T04c-2 in the VM: `vigia rebobinar`, with and without a service, against the real OpenClaw.

docs/19-diseno-t04.md, section 4 ("El socket de control" and "La CLI"). The command is the real
one, run as a process (tests/integration/cli_main.py); the service is the real `vigia vigilar`.

- With the service running, the command goes through the control socket (the real ``SO_PEERCRED``
  on both ends) and the deleted files come back; the id it takes is the one `vigia instantaneas`
  printed.
- Without a service, it rewinds in its own process and leaves the agent stopped (also one that a
  killed service left running); with the lock held and no socket it does nothing and never falls
  back to rewinding on its own.
- The live socket is private, outside the volume and unreachable from the agent; it refuses
  garbage, more than 4 KiB and a silent client without being blocked by it; the client never
  follows a symlink; a symlink where the socket should be stops the service from starting.

What cannot be tested here without root is a connection from another uid: the socket is 0600 in
a 0700 folder, so the kernel refuses it before ``SO_PEERCRED`` is read; the check itself is
tested with a fake uid in tests/test_service_control.py.
"""

import json
import os
import shutil
import socket
import stat
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.integration.service_kit import (
    CYCLE,
    Service,
    run_cli,
    snapshot_holds,
    wait_until,
    workspace_holds,
    write_in_agent,
)
from tests.integration.service_kit import exec_in_agent as exec_ok
from vigia.service.control import ControlError, ask_rewind
from vigia.service.runner import ServiceRunning, take_lock
from vigia.snapshots import Snapshot

pytestmark = pytest.mark.integration

FILES = {f"work/keep/file{i}.txt": f"the content of file {i}\n" for i in range(1, 6)}
WITHIN = CYCLE + 30  # a cycle, the sync, the snapshot and a loaded VM


def snapshot_with_files(service: Service) -> str:
    """Write FILES in the agent and wait for a snapshot that holds them (its take event is
    recorded once the barrier made it current). Returns its id."""
    write_in_agent(service, FILES)
    found: list[str] = []

    def taken() -> bool:
        found[:] = [
            t.snapshot_id
            for t in service.takes()
            if t.snapshot_id is not None and snapshot_holds(service, t.snapshot_id, FILES)
        ]
        return bool(found)

    wait_until(taken, WITHIN, "a snapshot that holds the files", context=service.diagnosis)
    return found[0]


def listed_ids(service: Service) -> list[str]:
    """The first column of `vigia instantaneas --todas`: what a person would copy."""
    result = run_cli(service, "instantaneas", "--todas")
    assert result.returncode == 0, (result.stdout, result.stderr)
    lines = result.stdout.strip().splitlines()
    assert lines[0].split() == ["INSTANTÁNEA", "HORA", "MOTIVO", "HACE"], lines[0]
    return [line.split()[0] for line in lines[1:]]


def log_actions(service: Service) -> list[str]:
    return [f"{e.source}/{e.action}" for e in service.events()]


# --- with a service: through the socket --------------------------------------------------------


def test_with_the_service_running_the_command_goes_through_the_socket_and_the_files_come_back(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()
    snapshot_with_files(service)

    # The demo: list, copy an id from the first column, rewind to it.
    ids = listed_ids(service)
    target = next(i for i in ids if snapshot_holds(service, i, FILES))
    assert all(Snapshot.parse(identifier) is not None for identifier in ids)
    exec_ok(service, "rm -r /workspace/work/keep")  # the agent deletes them
    assert not workspace_holds(service, FILES)
    workspace_before = service.store.workspace_id()
    process_before = service.require_process().pid

    result = run_cli(service, "rebobinar", "--si", target)

    assert result.returncode == 0, (result.stdout, result.stderr, service.diagnosis())
    assert "Vas a volver a las" in result.stdout
    assert "lo que ya salió de la máquina no vuelve" in " ".join(result.stdout.split())
    assert "socket de control" in result.stdout
    assert "No hay un servicio en marcha" not in result.stdout
    assert "El agente está en marcha otra vez." in result.stdout
    assert workspace_holds(service, FILES)
    assert service.store.workspace_id() != workspace_before
    assert service.jail.is_running()
    assert service.require_process().poll() is None
    assert service.require_process().pid == process_before  # the same service did it

    # The undo point it printed is real, and it is the state from before: the deleted one.
    undo_lines = [line for line in result.stdout.splitlines() if line.startswith("Para deshacer")]
    (undo_line,) = undo_lines
    undo = undo_line.split()[-1]
    assert Snapshot.parse(undo) is not None and undo in {s.id for s in service.snapshots()}
    assert not snapshot_holds(service, undo, FILES)

    # The service did it (not the command): the request names who asked, and nothing of the
    # command's own process is in the black box.
    (requested,) = service.events("rewind_requested", "snapshot")
    assert requested.details["requested_by"].startswith(f"cli (uid {os.geteuid()}, pid ")
    assert requested.snapshot_id == target
    (done,) = service.events("rewind_done", "snapshot")
    assert done.details["request_id"] == requested.details["request_id"]
    assert done.details["undo"] == undo and done.details["agent_started"] is True
    assert "system/cli_start" not in log_actions(service)

    # And the person can undo it, the same way.
    again = run_cli(service, "rebobinar", "--si", undo)
    assert again.returncode == 0, (again.stdout, again.stderr)
    assert not workspace_holds(service, FILES)  # back to the deleted state

    assert service.stop() == 0
    assert not (service.config.state_dir / "control.sock").exists()  # removed with the service
    report = service.box.verify()
    assert report.ok, report.problems


# --- the live socket ---------------------------------------------------------------------------


def talk(path: Path, data: bytes, *, half_close: bool = True, timeout: float = 15) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(data)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    return json.loads(raw)


def test_the_live_socket_is_private_unreachable_for_the_agent_and_refuses_what_it_should(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()
    path = service.config.state_dir / "control.sock"

    # Private, in Vigía's state folder, never in the volume, and not mounted into the agent.
    info = os.lstat(path)
    assert stat.S_ISSOCK(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid()
    assert stat.S_IMODE(os.stat(service.config.state_dir).st_mode) & 0o077 == 0
    assert not path.is_relative_to(service.store.root)  # invariant 1
    seen = service.jail.exec(["sh", "-c", f"test -e '{path}' || test -e '{path.parent}'"])
    assert seen.returncode != 0, seen
    found = service.jail.exec(
        ["sh", "-c", "find / -xdev -name 'control.sock' -not -path '/proc/*' 2>/dev/null | head"]
    )
    assert found.stdout.strip() == ""

    # Garbage, wrong commands, bad ids, extra keys and more than 4 KiB: refused, and the service
    # and the agent do not notice (no rewind was even requested).
    requests_before = len(service.events("rewind_requested", "snapshot"))
    for data in (
        b"not json\n",
        b"\xff\xfe\n",
        b"[]\n",
        b'{"cmd": "rm -rf /"}\n',
        b'{"cmd": "rewind", "snapshot_id": "latest"}\n',
        b'{"cmd": "rewind", "snapshot_id": "../../etc/passwd"}\n',
        b'{"cmd": "rewind", "snapshot_id": "20260101T000000.000000Z-periodic", "x": 1}\n',
        b"x" * 100_000,
    ):
        reply = talk(path, data)
        assert reply["ok"] is False and reply["outcome"] in ("refused", "invalid"), (data, reply)
    assert len(service.events("rewind_requested", "snapshot")) == requests_before
    assert service.jail.is_running() and service.require_process().poll() is None

    # A client that connects and says nothing is cut off after 5 s and blocks nobody (this one
    # is answered at once, by the real ask_rewind with the real SO_PEERCRED on both ends).
    silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    silent.settimeout(15)
    silent.connect(str(path))
    try:
        started = time.monotonic()
        assert ask_rewind(path, "latest", wait=0)["outcome"] == "invalid"
        assert time.monotonic() - started < 3
        raw = b""
        while chunk := silent.recv(4096):
            raw += chunk
        answer = json.loads(raw)
        assert answer["outcome"] == "refused" and "tardado" in answer["message"]
        assert 4 < time.monotonic() - started < 10  # the 5 s of the design
    finally:
        silent.close()

    # The client never follows a link to the socket.
    link = service.config.state_dir / "link.sock"
    link.symlink_to(path)
    with pytest.raises(ControlError, match="no es un socket"):
        ask_rewind(link, "20260101T000000.000000Z-periodic", wait=0)
    link.unlink()

    # The command refuses what is not a snapshot before touching anything.
    workspace_before = service.store.workspace_id()
    events_before = len(service.events())
    existing = service.snapshots()[-1]
    unknown = Snapshot(existing.taken_at.replace(year=2020), "periodic")
    garbage = run_cli(service, "rebobinar", "--si", "latest")
    assert garbage.returncode == 2 and "vigia instantaneas" in garbage.stderr
    missing = run_cli(service, "rebobinar", "--si", unknown.id)
    assert missing.returncode == 2 and "no existe" in missing.stderr
    assert "Vas a volver" not in missing.stdout
    unasked = run_cli(service, "rebobinar", existing.id)  # no --si and no terminal
    assert unasked.returncode == 2 and "--si" in unasked.stderr
    assert "Vas a volver" in unasked.stdout  # the notice is shown before it refuses to guess
    assert service.store.workspace_id() == workspace_before
    assert "snapshot/rewind_requested" not in log_actions(service)[events_before:]

    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems


# --- without a service: in the command's own process, the agent left stopped -------------------


def test_without_a_service_it_rewinds_in_its_own_process_and_leaves_the_agent_stopped(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()
    target = snapshot_with_files(service)
    assert service.stop() == 0
    assert not service.jail.is_running()
    shutil.rmtree(service.store.workspace / "agente" / "work" / "keep")  # deleted, host side
    assert not workspace_holds(service, FILES)
    workspace_before = service.store.workspace_id()
    events_before = len(service.events())
    take_lock(service.config.lock_file).close()  # nobody holds it: there is no service

    result = run_cli(service, "rebobinar", "--si", target)

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "No hay un servicio en marcha" in result.stdout
    assert "El agente queda parado" in result.stdout and "vigia vigilar" in result.stdout
    assert "socket de control" not in result.stdout
    assert workspace_holds(service, FILES)
    assert service.store.workspace_id() != workspace_before
    assert not service.jail.is_running()  # left stopped, as the design says
    undo = next(
        line.split()[-1] for line in result.stdout.splitlines() if line.startswith("Para deshacer")
    )
    assert Snapshot.parse(undo) is not None and not snapshot_holds(service, undo, FILES)
    after = [f"{e.source}/{e.action}" for e in service.events()[events_before:]]
    assert after == [
        "system/cli_start",
        "snapshot/rewind_requested",
        "snapshot/rewind_done",
        "system/cli_stop",
    ]
    (done,) = service.events("rewind_done", "snapshot")
    assert done.details["agent_started"] is False and "problems" not in done.details
    assert not service.config.pending_file.exists()
    take_lock(service.config.lock_file).close()  # and the lock was released

    # The next service boots on the rewound workspace, notes the gap and starts the agent.
    service.start()
    service.wait_ready()
    assert service.jail.is_running()
    assert workspace_holds(service, FILES)
    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems


def test_without_a_service_an_agent_left_running_by_a_killed_service_is_stopped_and_stays_so(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()
    target = snapshot_with_files(service)
    exec_ok(service, "rm -r /workspace/work/keep")
    service.kill()  # SIGKILL: the agent keeps running, the socket file stays behind
    assert service.jail.is_running()
    stale = service.config.state_dir / "control.sock"
    assert stat.S_ISSOCK(os.lstat(stale).st_mode)

    result = run_cli(service, "rebobinar", "--si", target)

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "No hay un servicio en marcha" in result.stdout  # the stale socket is no service
    assert workspace_holds(service, FILES)
    assert not service.jail.is_running()
    stops = [e for e in service.events("agent_stop") if e.details.get("reason") == "rewind"]
    assert len(stops) == 1
    assert not [e for e in service.events("agent_start") if e.details.get("reason") == "rewind"]

    # A new service replaces the stale socket and answers on it.
    service.start()
    service.wait_ready()
    assert stat.S_ISSOCK(os.lstat(stale).st_mode)
    reply = ask_rewind(stale, "latest", wait=5)
    assert reply["outcome"] == "invalid"
    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems


def test_with_the_lock_held_and_no_socket_it_waits_then_does_nothing_and_never_falls_back(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    service.start()
    service.wait_ready()
    target = snapshot_with_files(service)
    assert service.stop() == 0
    workspace_before = service.store.workspace_id()
    events_before = len(service.events())
    assert not (service.config.state_dir / "control.sock").exists()

    with take_lock(service.config.lock_file):  # "a service that is starting": lock, no socket
        started = time.monotonic()
        result = run_cli(service, "rebobinar", "--si", target)
        waited = time.monotonic() - started
        with pytest.raises(ServiceRunning):
            take_lock(service.config.lock_file)  # and the command did not keep or steal it

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 9 < waited < 40  # it retried for about 10 s
    assert "está arrancando" in result.stderr and "No se ha tocado nada" in result.stderr
    assert "No hay un servicio en marcha" not in result.stdout  # never in its own process
    assert service.store.workspace_id() == workspace_before
    assert len(service.events()) == events_before  # not a line in the black box
    assert not service.jail.is_running()


# --- a symlink where the socket should be ------------------------------------------------------


def test_a_symlink_at_the_socket_path_stops_the_service_and_the_agent_with_it(
    make_real_service: Callable[..., Service],
) -> None:
    service = make_real_service()
    decoy = service.config.state_dir / "decoy"
    decoy.write_text("not a socket")
    link = service.config.state_dir / "control.sock"
    link.symlink_to(decoy)

    service.start()
    assert service.wait_exit() == 1  # the service came up, could not open the socket, and stopped
    assert "socket de control" in service.log_text() and "no es un socket" in service.log_text()
    assert link.is_symlink() and decoy.read_text() == "not a socket"  # followed by nobody
    assert not service.jail.is_running()  # no socket, no service: the agent went down with it
    take_lock(service.config.lock_file).close()

    link.unlink()  # fixed by hand
    service.start()
    service.wait_ready()
    assert stat.S_ISSOCK(os.lstat(link).st_mode)
    assert service.stop() == 0
    report = service.box.verify()
    assert report.ok, report.problems
