"""The control socket (T04c-2): what the server serves and refuses, and what the client trusts.

The server runs for real over a Unix socket in a short temporary folder (the path of a Unix
socket is limited to about 100 bytes, and pytest's folders are longer); the Guardian is a fake
that records what it was asked, so "refused WITHOUT calling the Guardian" is something the tests
can state. ``SO_PEERCRED`` exists only on Linux, so every test plays the kernel's answer with a
fake ``peer`` (a different uid, an unreadable one), and the real call is checked on its own
(``test_the_real_peer_credentials...``, Linux only; the VM tests use it end to end).
"""

import json
import logging
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from backtide.service.control import (
    HOLD_EXIT_CODES,
    MAX_REQUEST_BYTES,
    OUTCOME_EXIT_CODES,
    ControlError,
    ControlOutcomeUnknown,
    ControlServer,
    ControlUnavailable,
    ask_decide,
    ask_holds,
    ask_resume,
    ask_rewind,
    peer_credentials,
)
from backtide.service.holds import HoldOutcome, HoldStatus
from backtide.service.pause import ResumeOutcome, ResumeStatus
from backtide.service.rewind import RewindOutcome, RewindStatus
from backtide.snapshots import Snapshot

SNAPSHOT = Snapshot(datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC), "periodic").id
UNDO = Snapshot(datetime(2026, 10, 16, 12, 5, 0, tzinfo=UTC), "pre_restore").id
ME = os.geteuid()


def me(sock: socket.socket) -> tuple[int, int, int]:
    return 4242, ME, 0


def somebody_else(sock: socket.socket) -> tuple[int, int, int]:
    return 4243, ME + 1, 0


def unreadable(sock: socket.socket) -> tuple[int, int, int]:
    raise ControlError("no SO_PEERCRED here")


class FakeGuardian:
    """Records the rewinds it is asked for. ``gate`` makes a rewind wait (a long one)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.outcome = RewindOutcome(
            RewindStatus.DONE,
            target=SNAPSHOT,
            message=f"Rebobinado a {SNAPSHOT}.",
            request_id="r1",
            undo=UNDO,
            agent_started=True,
        )
        self.error: Exception | None = None
        self.gate: threading.Event | None = None
        self.entered = threading.Event()
        self.resumes: list[str] = []
        self.resume_outcome = ResumeOutcome(
            ResumeStatus.RESUMED, "El agente sigue donde estaba.", "running"
        )
        self.decisions: list[tuple[str, str, str, str]] = []
        self.hold_status = HoldStatus.RELEASED
        self.holds: list[dict[str, Any]] = []

    def rewind(self, snapshot_id: str, *, requested_by: str) -> RewindOutcome:
        self.calls.append((snapshot_id, requested_by))
        self.entered.set()
        if self.gate is not None:
            assert self.gate.wait(10)
        if self.error is not None:
            raise self.error
        return self.outcome

    def resume(self, *, requested_by: str) -> ResumeOutcome:
        self.resumes.append(requested_by)
        if self.error is not None:
            raise self.error
        return self.resume_outcome

    def decide_hold(
        self, hold_id: str, verdict: str, *, via: str, requested_by: str
    ) -> HoldOutcome:
        self.decisions.append((hold_id, verdict, via, requested_by))
        if self.error is not None:
            raise self.error
        return HoldOutcome(self.hold_status, hold_id)

    def pending_holds(self) -> list[dict[str, Any]]:
        if self.error is not None:
            raise self.error
        return self.holds


@pytest.fixture
def folder() -> Iterator[Path]:
    """A short folder (Unix socket paths are limited), private like backtide's state."""
    path = Path(tempfile.mkdtemp(prefix="vg"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def guardian() -> FakeGuardian:
    return FakeGuardian()


@pytest.fixture
def make_server(folder: Path, guardian: FakeGuardian) -> Iterator[Callable[..., ControlServer]]:
    servers: list[ControlServer] = []

    def make(**options: Any) -> ControlServer:
        options.setdefault("peer", me)
        server = ControlServer(guardian, folder / "control.sock", **options)
        server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def talk(server: ControlServer, data: bytes, *, half_close: bool = True) -> dict[str, Any]:
    """Send ``data`` as a raw client would and return the reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(server.path))
        sock.sendall(data)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    return json.loads(raw)


def rewind_request(snapshot_id: object = SNAPSHOT, **more: object) -> bytes:
    return json.dumps({"cmd": "rewind", "snapshot_id": snapshot_id, **more}).encode() + b"\n"


# --- a rewind through the socket ---------------------------------------------------------------


def test_a_rewind_goes_to_the_guardian_and_its_outcome_comes_back(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    reply = ask_rewind(server.path, SNAPSHOT, peer=me)
    assert guardian.calls == [(SNAPSHOT, f"cli (uid {ME}, pid 4242)")]
    assert reply == {
        "ok": True,
        "outcome": "done",
        "undo": UNDO,
        "message": f"Rebobinado a {SNAPSHOT}.",
        "agent_started": True,
    }


def test_the_web_says_it_is_the_web_and_the_black_box_gets_it_with_the_kernels_ids(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    """T12b: the request may name where it came from, one of a fixed set. It is a label (any
    process of the user could claim it); the uid and pid next to it are the kernel's."""
    server = make_server()
    assert ask_rewind(server.path, SNAPSHOT, via="web", peer=me)["outcome"] == "done"
    assert talk(server, rewind_request(via="cli"))["outcome"] == "done"
    assert guardian.calls == [
        (SNAPSHOT, f"web (uid {ME}, pid 4242)"),
        (SNAPSHOT, f"cli (uid {ME}, pid 4242)"),
    ]


@pytest.mark.parametrize("via", ["email", "WEB", "web ", "", None, 7, ["web"], {"web": 1}])
def test_an_unknown_via_is_refused_without_calling_the_guardian(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, via: object
) -> None:
    reply = talk(make_server(), rewind_request(via=via))
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert guardian.calls == []


def test_the_client_refuses_to_send_an_unknown_via(folder: Path) -> None:
    with pytest.raises(ValueError):
        ask_rewind(folder / "control.sock", SNAPSHOT, via="email", wait=0, peer=me)


def test_the_cli_request_is_unchanged(folder: Path) -> None:
    """`backtide rebobinar` sends exactly what it sent before T12b (no `via`)."""
    seen: list[bytes] = []
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(folder / "control.sock"))
    listener.listen(1)

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            data = b""
            # Read up to the client's half-close, like the real server's request read and
            # drain: replying and closing first races the client's own shutdown (on macOS).
            while chunk := connection.recv(4096):
                data += chunk
            seen.append(data)
            connection.sendall(
                json.dumps(
                    {"ok": False, "outcome": "refused", "message": "x", "undo": None}
                ).encode()
                + b"\n"
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=me)
    finally:
        thread.join(5)
        listener.close()
    assert json.loads(seen[0]) == {"cmd": "rewind", "snapshot_id": SNAPSHOT}


@pytest.mark.parametrize("status", list(RewindStatus))
def test_every_outcome_status_travels_and_keeps_its_exit_code(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, status: RewindStatus
) -> None:
    guardian.outcome = RewindOutcome(status, target=SNAPSHOT, message="x", undo=None)
    reply = ask_rewind(make_server().path, SNAPSHOT, peer=me)
    assert reply["outcome"] == str(status)
    assert reply["ok"] is guardian.outcome.rewound
    assert OUTCOME_EXIT_CODES[reply["outcome"]] == guardian.outcome.exit_code


def test_the_socket_is_private_and_goes_away_with_the_server(
    make_server: Callable[..., ControlServer],
) -> None:
    server = make_server()
    info = os.lstat(server.path)
    assert stat.S_ISSOCK(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == ME
    server.close()
    assert not server.path.exists()
    server.close()  # idempotent


def test_a_stale_socket_left_by_a_dead_service_is_replaced(
    folder: Path, make_server: Callable[..., ControlServer]
) -> None:
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(folder / "control.sock"))
    stale.close()  # the file stays, nobody listens
    assert (folder / "control.sock").exists()
    server = make_server()
    assert ask_rewind(server.path, SNAPSHOT, peer=me)["outcome"] == "done"


def test_the_umask_of_the_process_is_never_touched(
    make_server: Callable[..., ControlServer],
) -> None:
    before = os.umask(0o022)
    try:
        make_server()
        assert os.umask(0o022) == 0o022
    finally:
        os.umask(before)


def test_a_rewind_in_flight_finishes_and_is_answered_before_close_returns(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    guardian.gate = threading.Event()
    replies: list[dict[str, Any]] = []
    asker = threading.Thread(
        target=lambda: replies.append(ask_rewind(server.path, SNAPSHOT, peer=me))
    )
    asker.start()
    assert guardian.entered.wait(5)
    closer = threading.Thread(target=server.close)
    closer.start()
    time.sleep(0.3)
    assert closer.is_alive()  # waiting for the rewind, not cutting it
    guardian.gate.set()
    closer.join(10)
    asker.join(10)
    assert not closer.is_alive() and not asker.is_alive()
    assert replies and replies[0]["outcome"] == "done"
    assert not server.path.exists()


def test_a_client_that_leaves_does_not_stop_the_rewind_and_the_lost_reply_is_logged(
    make_server: Callable[..., ControlServer],
    guardian: FakeGuardian,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = make_server()
    guardian.gate = threading.Event()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(server.path))
    sock.sendall(rewind_request())
    assert guardian.entered.wait(5)
    sock.close()  # Ctrl-C on the client while the service rewinds
    with caplog.at_level(logging.WARNING, logger="backtide.service.control"):
        guardian.gate.set()
        server.close()
    assert guardian.calls  # it ran to its end
    assert any("went away" in record.getMessage() for record in caplog.records)


def test_an_unexpected_exception_of_the_guardian_is_an_unknown_outcome_without_its_text(
    make_server: Callable[..., ControlServer],
    guardian: FakeGuardian,
    caplog: pytest.LogCaptureFixture,
) -> None:
    guardian.error = RuntimeError("secret internals sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
    with caplog.at_level(logging.ERROR, logger="backtide.service.control"):
        reply = ask_rewind(make_server().path, SNAPSHOT, peer=me)
    assert reply["outcome"] == "unknown" and reply["ok"] is False
    assert "sk-ant" not in json.dumps(reply)
    assert OUTCOME_EXIT_CODES[reply["outcome"]] == 3
    assert any(record.exc_info for record in caplog.records)  # nothing is swallowed


def test_the_message_of_the_reply_is_redacted(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"
    guardian.outcome = RewindOutcome(
        RewindStatus.FAILED, target=SNAPSHOT, message=f"el agente dijo {key}"
    )
    reply = ask_rewind(make_server().path, SNAPSHOT, peer=me)
    assert key not in json.dumps(reply)


# --- who may ask -------------------------------------------------------------------------------


def test_another_uid_is_refused_without_reading_or_calling_the_guardian(
    make_server: Callable[..., ControlServer],
    guardian: FakeGuardian,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = make_server(peer=somebody_else)
    with caplog.at_level(logging.WARNING, logger="backtide.service.control"):
        reply = talk(server, rewind_request())
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert guardian.calls == []
    warning = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert f"uid {ME + 1}" in warning.getMessage()  # who tried is in the log (and so the box)


def test_the_allowed_uid_can_be_chosen(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server(peer=somebody_else, allowed_uid=ME + 1)
    assert talk(server, rewind_request())["outcome"] == "done"
    assert len(guardian.calls) == 1


def test_a_peer_whose_credentials_cannot_be_read_is_refused(
    make_server: Callable[..., ControlServer],
    guardian: FakeGuardian,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = make_server(peer=unreadable)
    with caplog.at_level(logging.ERROR, logger="backtide.service.control"):
        reply = talk(server, rewind_request())
    assert reply["outcome"] == "refused"
    assert guardian.calls == []
    assert any(r.levelno == logging.ERROR for r in caplog.records)


# --- what it refuses ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "says"),
    [
        (b"not json at all\n", "JSON"),
        (b"\xff\xfe\x00\n", "JSON"),
        (b"", "JSON"),
        (b"\n", "JSON"),
        (b"[" * 4000 + b"\n", "JSON"),  # deep enough to blow the parser's recursion limit
        (b"[1, 2, 3]\n", "objeto"),
        (b'"rewind"\n', "objeto"),
        (b"null\n", "objeto"),
        (b'{"cmd": "format-the-disk"}\n', "desconocida"),
        (b'{"cmd": 7}\n', "desconocida"),
        (b"{}\n", "desconocida"),
        (b'{"cmd": "resume", "now": true}\n', "nada más"),
        (b'{"cmd": "pause"}\n', "desconocida"),
        (b'{"cmd": "rewind"}\n', "nada más"),
        (rewind_request(extra="x"), "nada más"),
        (b'{"snapshot_id": "%b"}\n' % SNAPSHOT.encode(), "desconocida"),
    ],
)
def test_garbage_is_refused_without_calling_the_guardian(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, data: bytes, says: str
) -> None:
    reply = talk(make_server(), data)
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert says in reply["message"]
    assert guardian.calls == []


@pytest.mark.parametrize(
    "snapshot_id",
    [
        "latest",
        "../../etc/passwd",
        f"{SNAPSHOT}/..",
        f"{SNAPSHOT}\n",
        SNAPSHOT.upper(),
        "",
        None,
        7,
        ["x"],
        {"id": SNAPSHOT},
    ],
)
def test_an_id_that_is_not_a_snapshot_id_is_invalid_and_never_reaches_the_guardian(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, snapshot_id: object
) -> None:
    reply = talk(make_server(), rewind_request(snapshot_id))
    assert reply["outcome"] == "invalid" and reply["ok"] is False
    assert OUTCOME_EXIT_CODES["invalid"] == 2
    assert guardian.calls == []


def test_more_than_4_kib_is_refused_with_or_without_a_newline(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    for data in (b"x" * (MAX_REQUEST_BYTES + 1), b"x" * 6000 + b"\n", b"x" * 100_000):
        reply = talk(server, data)
        assert reply["outcome"] == "refused", data[:20]
        assert "bytes" in reply["message"]
    assert guardian.calls == []


def test_the_limit_is_on_the_line_a_request_of_exactly_4_kib_is_parsed(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    padding = MAX_REQUEST_BYTES - len(rewind_request(pad="")) + 1
    line = rewind_request(pad="p" * padding)
    assert len(line.rstrip(b"\n")) == MAX_REQUEST_BYTES
    reply = talk(make_server(), line)
    assert "nada más" in reply["message"]  # parsed (and refused for its extra key), not "too big"
    assert guardian.calls == []


def test_the_bytes_after_the_newline_are_ignored(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    reply = talk(make_server(), rewind_request() + b"second request\n")
    assert reply["outcome"] == "done"
    assert len(guardian.calls) == 1


def test_a_silent_client_gets_a_timeout_and_blocks_nobody(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server(request_timeout=0.5)
    silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    silent.settimeout(5)
    silent.connect(str(server.path))  # connects and says nothing
    try:
        started = time.monotonic()
        assert talk(server, rewind_request())["outcome"] == "done"  # another client is served now
        assert time.monotonic() - started < 0.4
        raw = b""
        while chunk := silent.recv(4096):
            raw += chunk
        reply = json.loads(raw)
        assert reply["outcome"] == "refused" and "tardado" in reply["message"]
        assert time.monotonic() - started < 3
    finally:
        silent.close()
    assert len(guardian.calls) == 1  # only the good client's rewind


def test_a_client_that_drips_bytes_does_not_get_more_time(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    """The 5 s are for the whole request, not for each read."""
    server = make_server(request_timeout=0.6)
    request = rewind_request()
    started = time.monotonic()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(server.path))
        for byte in request[:-1]:  # everything but the newline, one byte every 0.1 s
            if time.monotonic() - started > 1.5:
                break
            try:
                sock.sendall(bytes([byte]))
            except OSError:
                break  # the server already answered and hung up
            time.sleep(0.1)
        raw = b""
        while chunk := sock.recv(4096):
            raw += chunk
    assert "tardado" in json.loads(raw)["message"]
    assert time.monotonic() - started < 2.5
    assert guardian.calls == []


def test_too_many_open_connections_are_turned_away_and_logged(
    make_server: Callable[..., ControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    server = make_server(max_connections=2, request_timeout=30)
    holders = []
    try:
        for _ in range(2):
            held = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            held.connect(str(server.path))
            holders.append(held)
        time.sleep(0.2)  # let both threads start
        with caplog.at_level(logging.WARNING, logger="backtide.service.control"):
            third = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            third.settimeout(5)
            third.connect(str(server.path))
            assert b"Demasiadas" in third.recv(1000)  # told so, and no thread spent
            third.close()
        assert any("too many" in record.getMessage() for record in caplog.records)
    finally:
        for held in holders:
            held.close()


# --- the path the socket lives at --------------------------------------------------------------


def test_a_symlink_at_the_socket_path_is_refused_and_left_alone(
    folder: Path, guardian: FakeGuardian
) -> None:
    decoy = folder / "decoy"
    decoy.write_text("not a socket")
    (folder / "control.sock").symlink_to(decoy)
    with pytest.raises(ControlError, match="no es un socket"):
        ControlServer(guardian, folder / "control.sock", peer=me).start()
    assert (folder / "control.sock").is_symlink()  # not removed
    assert decoy.read_text() == "not a socket"  # not bound over, not followed


def test_a_symlink_to_a_socket_is_refused_too(folder: Path, guardian: FakeGuardian) -> None:
    real = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    real.bind(str(folder / "other.sock"))
    real.listen()
    (folder / "control.sock").symlink_to(folder / "other.sock")
    try:
        with pytest.raises(ControlError, match="no es un socket"):
            ControlServer(guardian, folder / "control.sock", peer=me).start()
        assert (folder / "other.sock").exists()
    finally:
        real.close()


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_a_file_or_a_folder_at_the_socket_path_is_refused_and_left_alone(
    folder: Path, guardian: FakeGuardian, kind: str
) -> None:
    path = folder / "control.sock"
    if kind == "file":
        path.write_text("precious")
    else:
        path.mkdir()
    with pytest.raises(ControlError, match="no es un socket"):
        ControlServer(guardian, path, peer=me).start()
    assert path.exists()


def test_a_path_that_cannot_hold_a_socket_is_an_error_and_leaves_nothing(
    folder: Path, guardian: FakeGuardian
) -> None:
    long_name = folder / ("x" * 200 + ".sock")
    with pytest.raises(ControlError, match="no se puede crear"):
        ControlServer(guardian, long_name, peer=me).start()
    assert list(folder.iterdir()) == []


def test_the_server_removes_only_its_own_socket(
    folder: Path, make_server: Callable[..., ControlServer]
) -> None:
    server = make_server()
    path = server.path
    path.unlink()  # somebody replaced it...
    path.write_text("not ours")
    server.close()
    assert path.read_text() == "not ours"  # ... and it is not removed


def test_starting_twice_is_an_error(make_server: Callable[..., ControlServer]) -> None:
    server = make_server()
    with pytest.raises(ControlError, match="ya está abierto"):
        server.start()


# --- the client does not trust what it finds ---------------------------------------------------


def test_the_client_refuses_a_symlinked_socket_without_connecting(
    folder: Path, make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    link = folder / "link.sock"
    link.symlink_to(server.path)
    with pytest.raises(ControlError, match="no es un socket"):
        ask_rewind(link, SNAPSHOT, wait=0, peer=me)
    assert guardian.calls == []


def test_the_client_refuses_a_regular_file(folder: Path) -> None:
    (folder / "control.sock").write_text("")
    with pytest.raises(ControlError, match="no es un socket"):
        ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=me)


def test_the_client_refuses_a_socket_of_another_user(
    folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(folder / "control.sock"))
    listener.listen()
    monkeypatch.setattr(os, "geteuid", lambda: ME + 5)
    try:
        with pytest.raises(ControlError, match="del usuario"):
            ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=me)
    finally:
        listener.close()


def test_the_client_sends_nothing_to_a_server_that_runs_as_another_user(
    folder: Path,
) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(folder / "control.sock"))
    listener.listen()
    received: list[bytes] = []

    def accept() -> None:
        conn, _ = listener.accept()
        conn.settimeout(2)
        try:
            received.append(conn.recv(4096))
        except OSError:
            received.append(b"<error>")
        conn.close()

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        with pytest.raises(ControlError, match="no le envío nada"):
            ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=somebody_else)
        thread.join(5)
    finally:
        listener.close()
    assert received == [b""]  # the connection was closed with nothing sent


def test_the_client_sends_nothing_if_it_cannot_tell_who_answers(folder: Path) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(folder / "control.sock"))
    listener.listen()
    try:
        with pytest.raises(ControlError, match="SO_PEERCRED"):
            ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=unreadable)
    finally:
        listener.close()


# --- starting up: the client waits for the service ---------------------------------------------


class Clock:
    """A clock the retry loop can use without sleeping: ``sleep`` moves it."""

    def __init__(self, on_sleep: Callable[[int], None] | None = None) -> None:
        self.now = 0.0
        self.sleeps = 0
        self._on_sleep = on_sleep

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.sleeps += 1
        if self._on_sleep is not None:
            self._on_sleep(self.sleeps)


def test_a_missing_socket_is_retried_for_ten_seconds_and_then_unavailable(folder: Path) -> None:
    clock = Clock()
    with pytest.raises(ControlUnavailable):
        ask_rewind(
            folder / "control.sock", SNAPSHOT, peer=me, sleep=clock.sleep, monotonic=clock.monotonic
        )
    assert 9.5 <= clock.now <= 10.5


def test_a_refused_connection_is_retried_too(folder: Path) -> None:
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(folder / "control.sock"))
    stale.close()  # a file nobody listens on: ECONNREFUSED
    clock = Clock()
    with pytest.raises(ControlUnavailable):
        ask_rewind(
            folder / "control.sock", SNAPSHOT, peer=me, sleep=clock.sleep, monotonic=clock.monotonic
        )
    assert clock.sleeps >= 20


def test_the_client_gets_through_when_the_service_finishes_starting(
    folder: Path, guardian: FakeGuardian
) -> None:
    server = ControlServer(guardian, folder / "control.sock", peer=me)
    clock = Clock(on_sleep=lambda n: server.start() if n == 3 else None)
    try:
        reply = ask_rewind(
            folder / "control.sock", SNAPSHOT, peer=me, sleep=clock.sleep, monotonic=clock.monotonic
        )
    finally:
        server.close()
    assert reply["outcome"] == "done"
    assert clock.sleeps == 3


# --- what comes back is checked ----------------------------------------------------------------


def raw_server(folder: Path, answer: bytes, *, hold: float = 0.0) -> threading.Thread:
    """A listener that reads a request and answers ``answer`` (in the test's own thread)."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(folder / "control.sock"))
    listener.listen()

    def serve() -> None:
        conn, _ = listener.accept()
        conn.settimeout(5)
        # Up to the client's half-close (as the real server reads and drains): answering and
        # closing before it races the client's own shutdown, which fails on macOS.
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass
        time.sleep(hold)
        try:
            conn.sendall(answer)
        except OSError:
            pass
        conn.close()
        listener.close()

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


@pytest.mark.parametrize(
    "answer",
    [
        b"",
        b"not json",
        b"[]",
        b'{"ok": true}',
        b'{"ok": true, "outcome": "done"}',
        b'{"ok": "yes", "outcome": "done", "message": "m", "undo": null}',
        b'{"ok": true, "outcome": "exploded", "message": "m", "undo": null}',
        b'{"ok": true, "outcome": "done", "message": 5, "undo": null}',
        b'{"ok": true, "outcome": "done", "message": "m", "undo": 5}',
        b"x" * 70_000,
    ],
)
def test_a_reply_that_makes_no_sense_means_the_outcome_is_unknown(
    folder: Path, answer: bytes
) -> None:
    thread = raw_server(folder, answer)
    with pytest.raises(ControlOutcomeUnknown, match="No se sabe si"):
        ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=me)
    thread.join(5)


def test_unknown_extra_fields_in_the_reply_are_dropped(folder: Path) -> None:
    thread = raw_server(
        folder,
        b'{"ok": true, "outcome": "done", "message": "m", "undo": null, "evil": "\\u001b[2J"}\n',
    )
    reply = ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, peer=me)
    thread.join(5)
    assert set(reply) == {"ok", "outcome", "message", "undo", "agent_started"}


def test_a_service_that_never_answers_is_an_unknown_outcome_not_a_hang(folder: Path) -> None:
    thread = raw_server(folder, b"", hold=1.0)
    started = time.monotonic()
    with pytest.raises(ControlOutcomeUnknown, match="no ha contestado"):
        ask_rewind(folder / "control.sock", SNAPSHOT, wait=0, reply_timeout=0.3, peer=me)
    assert time.monotonic() - started < 1.5
    thread.join(5)


# --- the kernel's answer -----------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="SO_PEERCRED is Linux only")
def test_the_real_peer_credentials_are_this_process() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with left, right:
        assert peer_credentials(left) == (os.getpid(), ME, os.getegid())


@pytest.mark.skipif(hasattr(socket, "SO_PEERCRED"), reason="only where SO_PEERCRED is missing")
def test_without_so_peercred_the_credentials_fail_closed() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with left, right, pytest.raises(ControlError, match="SO_PEERCRED"):
        peer_credentials(left)


def test_a_connection_over_the_cap_is_told_so_not_just_cut(
    make_server: Callable[..., ControlServer],
) -> None:
    server = make_server(max_connections=1, request_timeout=30)
    holder = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    holder.connect(str(server.path))
    try:
        time.sleep(0.2)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as extra:
            extra.settimeout(5)
            extra.connect(str(server.path))
            reply = json.loads(extra.recv(4096))
        assert reply["outcome"] == "refused" and "Demasiadas" in reply["message"]
    finally:
        holder.close()


def test_if_the_serving_thread_dies_the_listener_is_closed_so_clients_fail_fast(
    folder: Path,
    guardian: FakeGuardian,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from backtide.service import control  # noqa: PLC0415

    def die(self: Any) -> None:
        raise RuntimeError("serve_forever broke")

    monkeypatch.setattr(control._Server, "service_actions", die)  # called by serve_forever
    server = ControlServer(guardian, folder / "control.sock", peer=me)
    with caplog.at_level(logging.ERROR, logger="backtide.service.control"):
        server.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    probe.connect(str(server.path))
                    probe.close()
                except OSError:
                    break  # refused: the listener is closed
                time.sleep(0.05)
            else:
                pytest.fail("the dead server still accepts connections")
        finally:
            server.close()
    assert any(r.exc_info for r in caplog.records)


# --- `backtide seguir` through the socket (T04d-2) ------------------------------------------------


def test_a_resume_goes_to_the_guardian_and_its_outcome_comes_back(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    reply = ask_resume(server.path, peer=me)
    assert guardian.resumes == [f"cli (uid {ME}, pid 4242)"]
    assert guardian.calls == []
    assert reply == {
        "ok": True,
        "outcome": "resumed",
        "message": "El agente sigue donde estaba.",
        "agent_state": "running",
    }


@pytest.mark.parametrize("status", list(ResumeStatus))
def test_every_resume_status_travels_with_ok_only_when_the_agent_may_run(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, status: ResumeStatus
) -> None:
    guardian.resume_outcome = ResumeOutcome(status, "m", "frozen")
    reply = ask_resume(make_server().path, peer=me)
    assert reply["outcome"] == str(status)
    assert reply["ok"] is (status in (ResumeStatus.RESUMED, ResumeStatus.NOT_PAUSED))
    assert OUTCOME_EXIT_CODES[str(status)] == ResumeOutcome(status, "m").exit_code


def test_another_uid_cannot_resume(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    reply = talk(make_server(peer=somebody_else), b'{"cmd": "resume"}\n')
    assert reply["outcome"] == "refused"
    assert guardian.resumes == []


def test_a_guardian_that_raises_on_resume_is_a_problem_without_its_text(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    guardian.error = RuntimeError("secret sk-ant-api03-" + "x" * 40)
    reply = ask_resume(make_server().path, peer=me)
    assert reply["outcome"] == "problem" and reply["ok"] is False
    assert "sk-ant" not in reply["message"]


def test_the_resume_message_is_redacted(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    guardian.resume_outcome = ResumeOutcome(
        ResumeStatus.STILL_RED, "token sk-ant-api03-" + "y" * 40, "frozen"
    )
    reply = ask_resume(make_server().path, peer=me)
    assert "sk-ant-api03-yyyy" not in reply["message"]


@pytest.mark.parametrize(
    "answer",
    [
        b"not json",
        b'{"ok": true, "outcome": "done", "message": "m"}',  # a rewind's outcome
        b'{"ok": "yes", "outcome": "resumed", "message": "m"}',
        b'{"ok": true, "outcome": "resumed", "message": 5}',
    ],
)
def test_a_resume_reply_that_makes_no_sense_is_unknown(folder: Path, answer: bytes) -> None:
    thread = raw_server(folder, answer)
    with pytest.raises(ControlOutcomeUnknown, match="No se sabe si"):
        ask_resume(folder / "control.sock", wait=0, peer=me)
    thread.join(5)


def test_a_resume_reply_keeps_only_what_the_cli_uses(folder: Path) -> None:
    thread = raw_server(
        folder,
        b'{"ok": true, "outcome": "resumed", "message": "m", "agent_state": "running", "x": 1}\n',
    )
    reply = ask_resume(folder / "control.sock", wait=0, peer=me)
    thread.join(5)
    assert set(reply) == {"ok", "outcome", "message", "agent_state"}


# --- held requests (T10-2): `backtide aprobar`, `rechazar` and `retenidas` -----------------------

HOLD = "h-0123456789ab"


def decide_request(**fields: object) -> bytes:
    base: dict[str, object] = {"cmd": "decide", "hold_id": HOLD, "verdict": "approve"}
    return json.dumps(base | fields).encode() + b"\n"


@pytest.mark.parametrize(
    ("status", "ok"),
    [(HoldStatus.RELEASED, True), (HoldStatus.PREAPPROVED, True), (HoldStatus.REJECTED, True),
     (HoldStatus.UNKNOWN, False), (HoldStatus.FAILED, False)],
)  # fmt: skip
def test_a_decision_reaches_the_guardian_with_who_asked(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, status: HoldStatus, ok: bool
) -> None:
    guardian.hold_status = status
    reply = ask_decide(make_server().path, HOLD, "approve", peer=me)
    assert (reply["ok"], reply["outcome"]) == (ok, str(status))
    assert reply["message"] == HoldOutcome(status, HOLD).message
    assert guardian.decisions == [(HOLD, "approve", "cli", f"cli (uid {ME}, pid 4242)")]
    assert HOLD_EXIT_CODES[reply["outcome"]] == (0 if ok else 1)


@pytest.mark.parametrize(
    ("line", "says"),
    [
        (decide_request(hold_id="h-XYZ"), "identificador"),
        (decide_request(hold_id=7), "identificador"),
        (decide_request(verdict="maybe"), "approve"),
        (decide_request(extra=1), "nada más"),
        (decide_request(via="agent"), "via"),
        (decide_request(via="telegram"), "bot"),  # only the bot, inside the service
        (json.dumps({"cmd": "decide", "hold_id": HOLD}).encode() + b"\n", "nada más"),
        (json.dumps({"cmd": "holds", "x": 1}).encode() + b"\n", "nada más"),
    ],
)
def test_a_bad_decision_is_refused_without_calling_the_guardian(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian, line: bytes, says: str
) -> None:
    reply = talk(make_server(), line)
    assert reply["outcome"] == "refused" and says in reply["message"]
    assert guardian.decisions == []


def test_another_user_cannot_decide(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    reply = talk(make_server(peer=somebody_else), decide_request())
    assert reply["outcome"] == "refused" and guardian.decisions == []


def test_a_guardian_that_raises_approves_nothing(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    guardian.error = RuntimeError("boom")
    reply = ask_decide(make_server().path, HOLD, "reject", peer=me)
    assert (reply["ok"], reply["outcome"]) == (False, "failed")


def test_the_client_refuses_a_verdict_that_is_not_one(folder: Path) -> None:
    with pytest.raises(ValueError):
        ask_decide(folder / "control.sock", HOLD, "maybe")
    with pytest.raises(ValueError):
        ask_decide(folder / "control.sock", HOLD, "approve", via="agent")


def test_the_bot_inside_the_service_decides_as_telegram(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    """T10-4: the Telegram buttons go through the same door, ``via: telegram``, which only a
    process that is the service itself may claim."""

    def inside(sock: socket.socket) -> tuple[int, int, int]:
        return os.getpid(), ME, 0

    guardian.hold_status = HoldStatus.RELEASED
    reply = ask_decide(make_server(peer=inside).path, HOLD, "approve", via="telegram", peer=me)
    assert reply["outcome"] == "released"
    assert guardian.decisions == [(HOLD, "approve", "telegram",
                                   f"telegram (uid {ME}, pid {os.getpid()})")]  # fmt: skip


def test_the_held_requests_are_listed_struck_and_checked(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    secret = "sk-ant-api03-" + "x" * 40
    guardian.holds = [
        {"hold_id": HOLD, "method": "DELETE", "path": f"/x?k={secret}", "risk": 3},
        {"hold_id": "not-an-id", "method": "GET"},
    ]
    holds = ask_holds(make_server().path, peer=me)
    assert [h["hold_id"] for h in holds] == [HOLD]
    assert secret not in json.dumps(holds)


def test_a_listing_that_fails_is_an_error(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    guardian.error = RuntimeError("boom")
    with pytest.raises(ControlError):
        ask_holds(make_server().path, peer=me)
