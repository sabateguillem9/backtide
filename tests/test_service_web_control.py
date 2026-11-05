"""T12c: the web's narrow socket. Who it serves (the web's group, by ``SO_PEERCRED``), what it
takes (a closed list, every change marked ``via: web``), what it checks itself (a rewind only to
a listed snapshot), how much (two buckets) and how the socket file is left (0660, the group).

A real server over a real Unix socket in a short folder, with a fake Guardian that records what
it was asked (tests/test_service_control.py), so "refused WITHOUT calling the Guardian" is
something a test can state. ``SO_PEERCRED`` is played by a fake ``peer``."""

import json
import logging
import os
import shutil
import socket
import stat
import tempfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide.jail.config import AGENT_GID, AGENT_UID
from backtide.jail.profile import MAX_PROMPT
from backtide.jail.proxy_config import PROXY_GID, PROXY_UID
from backtide.service.control import (
    ControlError,
    ControlServer,
    ask_decide,
    ask_rewind,
    ask_set_budget,
    ask_task_start,
    ask_trust,
)
from backtide.service.sessions import IDLE_SECONDS, Sessions
from backtide.service.settings import Applied, Outcome, SettingsOutcome
from backtide.service.spend import CapOutcome
from backtide.service.tasks import TaskOutcome, TaskStart, TaskStatus
from backtide.service.web_control import (
    CHANGES,
    COMMANDS,
    READS,
    SESSION_COMMANDS,
    SIGNED_IN_READS,
    TOUCH_CHANGES,
    Bucket,
    WebControlServer,
    ask_snapshots,
    web_group_problem,
)
from backtide.snapshots import Snapshot
from tests.test_service_control import HOLD, FakeGuardian

ME = os.geteuid()
# The web's group in these tests: ours (the server chowns its socket to it), unless that is one
# the server refuses (tests run as root): then any other, which root may chown to.
GROUP = os.getegid() if os.getegid() not in (0, AGENT_GID, PROXY_GID) else 4321
LISTED = Snapshot(datetime(2026, 10, 28, 9, 0, tzinfo=UTC), "periodic")
NEWER = Snapshot(datetime(2026, 10, 28, 9, 5, tzinfo=UTC), "periodic")
UNLISTED = Snapshot(datetime(2026, 10, 28, 9, 2, tzinfo=UTC), "periodic")
SESSION = "s" * 43  # the cookie of the person at the web (a test value)


def the_web(sock: socket.socket) -> tuple[int, int, int]:
    return 4242, ME, GROUP


def peer_as(uid: int, gid: int) -> Callable[[socket.socket], tuple[int, int, int]]:
    return lambda sock: (4243, uid, gid)


class FakeSettings:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def status(self) -> dict[str, dict[str, Any]]:
        return {"anthropic": {"set": True, "tail": "WXYZ"}}

    def set_secret(
        self, kind: str, value: str, *, chat_id: str = "", requested_by: str
    ) -> SettingsOutcome:
        self.calls.append(("set", kind, requested_by))
        return SettingsOutcome(Outcome.SAVED, "Guardada.", Applied.NOW)

    def clear_secret(self, kind: str, *, requested_by: str) -> SettingsOutcome:
        self.calls.append(("clear", kind, requested_by))
        return SettingsOutcome(Outcome.CLEARED, "Quitada.", Applied.NOW)


class FakeBudget:
    def __init__(self) -> None:
        self.caps: list[tuple[Decimal | None, Decimal | None, str]] = []
        self.accepted: list[tuple[str, str]] = []

    def status(self) -> dict[str, Any]:
        return {"day": "0.00"}

    def set_caps(
        self, daily: Decimal | None, monthly: Decimal | None, *, requested_by: str
    ) -> CapOutcome:
        self.caps.append((daily, monthly, requested_by))
        return CapOutcome(True, "saved", "Guardado.")

    def accept_prices(self, digest: str, *, requested_by: str) -> CapOutcome:
        self.accepted.append((digest, requested_by))
        return CapOutcome(True, "saved", "Precios nuevos aplicados.")


@pytest.fixture
def folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vn"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def guardian() -> FakeGuardian:
    return FakeGuardian()


@pytest.fixture
def settings() -> FakeSettings:
    return FakeSettings()


@pytest.fixture
def budget() -> FakeBudget:
    return FakeBudget()


@pytest.fixture
def make_server(
    folder: Path, guardian: FakeGuardian, settings: FakeSettings, budget: FakeBudget
) -> Iterator[Callable[..., WebControlServer]]:
    servers: list[WebControlServer] = []

    def make(**options: Any) -> WebControlServer:
        options.setdefault("peer", the_web)
        options.setdefault("group", GROUP)
        options.setdefault("snapshots", lambda: [LISTED, NEWER])
        options.setdefault("settings", settings)
        options.setdefault("budget", budget)
        options.setdefault("sessions", signed_in())
        options.setdefault("on_entry", lambda action, details: True)
        server = WebControlServer(guardian, folder / "web.sock", **options)
        server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def signed_in() -> Sessions:
    """The service's sessions with one already open: the cookie of the person at the web."""
    sessions = Sessions()
    sessions.preset(SESSION)
    return sessions


def signed(request: dict[str, Any]) -> dict[str, Any]:
    """A change as the web sends it: with the session of the person who asked (T26-3a)."""
    return {**request, "session": SESSION}


def talk(server: ControlServer, request: object) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(server.path))
        sock.sendall(json.dumps(request).encode() + b"\n")
        sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    return json.loads(raw)


def nothing_asked(guardian: FakeGuardian, settings: FakeSettings, budget: FakeBudget) -> bool:
    return not (
        guardian.calls
        or guardian.resumes
        or guardian.decisions
        or settings.calls
        or budget.caps
        or budget.accepted
    )


# -- the socket file ------------------------------------------------------------------------------


def test_the_socket_is_0660_with_the_webs_group(
    make_server: Callable[..., WebControlServer],
) -> None:
    server = make_server()
    info = os.lstat(server.path)
    assert stat.S_ISSOCK(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o660
    assert (info.st_uid, info.st_gid) == (ME, GROUP)
    server.close()
    assert not os.path.lexists(server.path)


@pytest.mark.parametrize("group", [0, AGENT_GID, PROXY_GID, True, 61101, 61150, 61201])
def test_the_group_of_root_the_agent_or_the_proxy_is_refused(folder: Path, group: int) -> None:
    with pytest.raises(ControlError):
        WebControlServer(FakeGuardian(), folder / "web.sock", group=group, snapshots=list)
    assert web_group_problem(0) and web_group_problem(AGENT_GID) and web_group_problem(PROXY_GID)
    assert web_group_problem(GROUP) is None


@pytest.mark.parametrize("group", [61100, 61101, 61150, 61200, 61201, 61299])
def test_no_gid_of_the_other_agents_can_be_the_webs_group(group: int) -> None:
    """The only thing that holds this range for a group: `refusal_for` compares with the socket's
    own group, so a socket opened for 61150 would let the agent number 50 in."""
    assert web_group_problem(group) is not None


@pytest.mark.parametrize("group", [61099, 61300])
def test_the_ids_around_the_agents_range_are_free(group: int) -> None:
    assert web_group_problem(group) is None


def test_the_control_socket_is_still_0600(folder: Path) -> None:
    server = ControlServer(FakeGuardian(), folder / "control.sock")
    server.start()
    try:
        assert stat.S_IMODE(os.lstat(server.path).st_mode) == 0o600
    finally:
        server.close()


# -- who ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [
        (ME, GROUP + 1),  # the right user in another group
        (AGENT_UID, AGENT_GID),  # the agent
        (AGENT_UID, GROUP),  # the agent, claiming the web's group
        (PROXY_UID, GROUP),  # the proxy, the same
        (61101, GROUP),  # another agent (T26-2a), claiming it too
        (61299, GROUP),  # another agent's proxy
        (ME, 61150),  # a group of that range
        (ME + 1, 0),  # root's group
    ],
)
def test_only_the_webs_group_is_served(
    make_server: Callable[..., WebControlServer],
    guardian: FakeGuardian,
    settings: FakeSettings,
    budget: FakeBudget,
    who: tuple[int, int],
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = make_server(peer=peer_as(*who))
    for request in (
        {"cmd": "rewind", "snapshot_id": LISTED.id},
        {"cmd": "decide", "hold_id": HOLD, "verdict": "approve"},
        {"cmd": "holds"},
    ):
        reply = talk(server, request)
        assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert nothing_asked(guardian, settings, budget)
    assert any("web socket: refused a connection" in r.getMessage() for r in caplog.records)


def test_unreadable_credentials_are_refused(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    def unreadable(sock: socket.socket) -> tuple[int, int, int]:
        raise ControlError("no SO_PEERCRED here")

    server = make_server(peer=unreadable)
    assert talk(server, signed({"cmd": "rewind", "snapshot_id": LISTED.id}))["outcome"] == "refused"
    assert guardian.calls == []


# -- what -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "resume"},
        {"cmd": "shell", "kind": "session", "continue": False},
        {"cmd": "shell", "kind": "task", "continue": True},
        {"cmd": "export", "dest": "/home/fuera"},
        {"cmd": "export", "dest": "/etc", "include_config": True},
        {
            "cmd": "import",
            "name": "x",
            "source": "/",
            "files": 1,
            "bytes": 1,
            "replace": True,
            "secrets_left_out": 0,
            "include_secrets": True,
        },  # fmt: skip
        {"cmd": "config", "path": "/etc/backtide/backtide.toml"},
        {"cmd": "REWIND", "snapshot_id": LISTED.id},
        {"cmd": "rewind\n"},
        {"cmd": ""},
        {"cmd": None},
        {"cmd": ["rewind"]},
        {"snapshot_id": LISTED.id},
        {},
    ],
)
def test_nothing_outside_the_list_is_served(
    make_server: Callable[..., WebControlServer],
    guardian: FakeGuardian,
    settings: FakeSettings,
    budget: FakeBudget,
    request_: dict[str, Any],
) -> None:
    reply = talk(make_server(), request_)
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert nothing_asked(guardian, settings, budget)


def test_the_list_is_closed() -> None:
    from backtide.service.web_control import PASSKEY_COMMANDS, SIGN_IN_COMMANDS

    assert COMMANDS == (
        READS | SIGNED_IN_READS | CHANGES | SESSION_COMMANDS | PASSKEY_COMMANDS | SIGN_IN_COMMANDS
    )
    assert not SIGNED_IN_READS & READS  # an answer is never a read without a session
    assert "task_stop" not in COMMANDS  # only the CLI's Ctrl-C
    assert {"passkeys", "passkey_remove"}.isdisjoint(COMMANDS)  # only root takes a key out
    assert not READS & CHANGES and not (READS | CHANGES) & SESSION_COMMANDS
    assert not (READS | CHANGES | SESSION_COMMANDS) & PASSKEY_COMMANDS
    assert "web_link" not in COMMANDS  # only root mints a way in
    assert {"resume", "shell", "import", "export"}.isdisjoint(COMMANDS)


@pytest.mark.parametrize("payload", [b"not json\n", b"[1, 2]\n", b"\xff\xfe\n", b"{" * 5000])
def test_anything_malformed_is_refused(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian, payload: bytes
) -> None:
    server = make_server()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(server.path))
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    assert json.loads(raw)["outcome"] == "refused"
    assert guardian.calls == []


@pytest.mark.parametrize("via", ["cli", "telegram", "WEB", "", None, 7])
def test_a_change_says_it_is_the_web_or_is_refused(
    make_server: Callable[..., WebControlServer],
    guardian: FakeGuardian,
    settings: FakeSettings,
    budget: FakeBudget,
    via: object,
) -> None:
    server = make_server()
    for request in (
        {"cmd": "rewind", "snapshot_id": LISTED.id, "via": via},
        {"cmd": "decide", "hold_id": HOLD, "verdict": "approve", "via": via},
        {"cmd": "set_budget", "daily_usd": "5", "via": via},
    ):
        assert talk(server, request)["outcome"] == "refused"
    assert nothing_asked(guardian, settings, budget)


@pytest.mark.parametrize("command", sorted(READS - {"snapshots"}) + ["snapshots"])
def test_a_read_takes_no_via_nor_anything_else(
    make_server: Callable[..., WebControlServer], command: str
) -> None:
    server = make_server()
    assert talk(server, {"cmd": command, "via": "web"})["outcome"] == "refused"
    assert talk(server, {"cmd": command, "path": "/etc"})["outcome"] == "refused"


# -- the changes, as the web asks them ------------------------------------------------------------


def test_a_rewind_to_a_listed_snapshot_is_recorded_as_the_web(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    reply = ask_rewind(
        server.path, LISTED.id, via="web", peer=the_web, server_uid=ME, session=SESSION
    )
    assert reply["outcome"] == "done"
    # Without `via` too: the narrow socket says it is the web whatever the client sends.
    assert talk(server, signed({"cmd": "rewind", "snapshot_id": NEWER.id}))["outcome"] == "done"
    assert guardian.calls == [
        (LISTED.id, f"web (uid {ME}, pid 4242)"),
        (NEWER.id, f"web (uid {ME}, pid 4242)"),
    ]


def test_a_forged_snapshot_id_is_refused_without_the_guardian(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    for snapshot_id in (UNLISTED.id, "../../etc", "20261028T090000Z-periodic/..", 7):
        reply = talk(server, signed({"cmd": "rewind", "snapshot_id": snapshot_id}))
        assert reply["ok"] is False and reply["outcome"] in ("invalid", "refused")
    assert (
        talk(server, signed({"cmd": "rewind", "snapshot_id": UNLISTED.id}))["outcome"] == "invalid"
    )
    assert guardian.calls == []


def test_an_unreadable_list_rewinds_nothing(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    def broken() -> list[Snapshot]:
        raise OSError("the volume is gone")

    server = make_server(snapshots=broken)
    assert talk(server, signed({"cmd": "rewind", "snapshot_id": LISTED.id}))["outcome"] == "invalid"
    assert talk(server, {"cmd": "snapshots"})["ok"] is False
    assert guardian.calls == []


def test_approving_and_rejecting_go_to_the_guardian_as_the_web(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    assert ask_decide(
        server.path, HOLD, "approve", via="web", peer=the_web, server_uid=ME, session=SESSION
    )["ok"]
    assert ask_decide(server.path, HOLD, "reject", peer=the_web, server_uid=ME, session=SESSION)[
        "ok"
    ]
    trusted = ask_trust(server.path, HOLD, peer=the_web, server_uid=ME, session=SESSION)
    assert trusted["outcome"] == "trusted"
    who = f"web (uid {ME}, pid 4242)"
    assert guardian.decisions == [
        (HOLD, "approve", "web", who),
        (HOLD, "reject", "web", who),
        (HOLD, "trust", "web", who),
    ]


@pytest.mark.parametrize("hold_id", ["h-zzzz", "../h-0", "", 7, "h-" + "0" * 200])
def test_a_forged_hold_id_is_refused_without_the_guardian(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian, hold_id: object
) -> None:
    server = make_server()
    for request in (
        {"cmd": "decide", "hold_id": hold_id, "verdict": "approve"},
        {"cmd": "trust", "hold_id": hold_id},
    ):
        assert talk(server, signed(request))["outcome"] == "refused"
    assert guardian.decisions == []


def test_an_unknown_hold_is_the_guardians_word(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    from backtide.service.holds import HoldStatus

    guardian.hold_status = HoldStatus.UNKNOWN
    reply = talk(make_server(), signed({"cmd": "decide", "hold_id": HOLD, "verdict": "approve"}))
    assert (reply["ok"], reply["outcome"]) == (False, "unknown")


def test_settings_and_caps_go_to_the_service_as_the_web(
    make_server: Callable[..., WebControlServer], settings: FakeSettings, budget: FakeBudget
) -> None:
    server = make_server()
    key = "sk-ant-api03-" + "k" * 80
    reply = talk(server, signed({"cmd": "set_secret", "kind": "anthropic", "value": key}))
    assert reply["outcome"] == "saved" and key not in json.dumps(reply)
    assert talk(server, signed({"cmd": "clear_secret", "kind": "openai"}))["outcome"] == "cleared"
    secrets = talk(server, {"cmd": "secrets"})
    assert secrets["secrets"] == {"anthropic": {"set": True, "tail": "WXYZ"}}
    capped = ask_set_budget(
        server.path,
        daily_usd="2,5",
        monthly_usd=None,
        via="web",
        peer=the_web,
        server_uid=ME,
        session=SESSION,
    )
    assert capped["outcome"] == "saved"
    assert talk(server, signed({"cmd": "set_budget", "daily_usd": "-1"}))["outcome"] == "invalid"
    assert talk(server, signed({"cmd": "accept_prices", "digest": "0123456789abcdef"}))["ok"]
    who = f"web (uid {ME}, pid 4242)"
    assert settings.calls == [("set", "anthropic", who), ("clear", "openai", who)]
    assert budget.caps == [(Decimal("2.5"), None, who)]
    assert budget.accepted == [("0123456789abcdef", who)]


def test_the_snapshot_list_comes_back_checked(make_server: Callable[..., WebControlServer]) -> None:
    server = make_server()
    assert ask_snapshots(server.path, server_uid=ME, peer=the_web) == [LISTED, NEWER]


def test_the_client_wants_the_socket_and_its_server_to_be_the_services(
    make_server: Callable[..., WebControlServer],
) -> None:
    """The web expects root's socket: a socket of another user (or a server that is not root)
    gets nothing sent."""
    server = make_server()
    with pytest.raises(ControlError):
        ask_snapshots(server.path, server_uid=ME + 1, peer=the_web, wait=0)
    with pytest.raises(ControlError):
        ask_rewind(server.path, LISTED.id, via="web", server_uid=ME + 1, peer=the_web, wait=0)
    with pytest.raises(ControlError):
        ask_snapshots(server.path, server_uid=ME, peer=peer_as(ME + 1, GROUP), wait=0)


# -- how much -------------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_a_bucket_gives_its_burst_and_then_its_rate() -> None:
    clock = Clock()
    bucket = Bucket(3, 0.5, clock=clock)
    assert [bucket.take() for _ in range(4)] == [True, True, True, False]
    clock.now += 1.9
    assert bucket.take() is False
    clock.now += 0.2
    assert bucket.take() is True
    clock.now += 1000
    assert [bucket.take() for _ in range(4)] == [True, True, True, False]


def test_too_many_requests_or_changes_are_refused_without_the_guardian(
    make_server: Callable[..., WebControlServer],
    guardian: FakeGuardian,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = Clock()
    server = make_server(
        requests=Bucket(5, 0.001, clock=clock), changes=Bucket(2, 0.001, clock=clock)
    )
    rewind = signed({"cmd": "rewind", "snapshot_id": LISTED.id})
    assert [talk(server, rewind)["outcome"] for _ in range(3)] == ["done", "done", "refused"]
    assert len(guardian.calls) == 2
    assert [talk(server, {"cmd": "holds"})["outcome"] for _ in range(3)] == [
        "listed",
        "listed",
        "refused",
    ]
    assert any("too many" in r.getMessage() for r in caplog.records)
    clock.now += 10_000
    assert talk(server, rewind)["outcome"] == "done"


def test_a_refusal_is_a_warning_the_log_bridge_records(
    make_server: Callable[..., WebControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="backtide.service.web_control")
    talk(make_server(), {"cmd": "resume"})
    [record] = [r for r in caplog.records if r.name == "backtide.service.web_control"]
    assert record.levelno == logging.WARNING and "outside its list" in record.getMessage()


# -- `backtide vigilar --grupo-web` --------------------------------------------------------------


def test_the_web_group_is_looked_up_by_name_and_checked() -> None:
    import grp

    from backtide.cli import _web_group

    assert _web_group(None) is None
    assert "no existe" in str(_web_group("no-such-group-backtide"))
    root_group = grp.getgrgid(0).gr_name
    assert "no sirve" in str(_web_group(root_group))
    mine = grp.getgrgid(os.getegid())
    if os.getegid() not in (0, AGENT_GID, PROXY_GID):
        assert _web_group(mine.gr_name) == os.getegid()


def test_vigilar_refuses_a_group_that_does_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide import cli

    monkeypatch.setattr(cli.ServiceConfig, "from_file", lambda path: object())
    monkeypatch.setattr(cli, "serve", lambda *a, **k: pytest.fail("served"))
    code = cli.main(["vigilar", "--config", str(tmp_path / "x.toml"), "--grupo-web", "no-such-g"])
    assert code == cli.EXIT_ERROR


# -- after the review of T12c ----------------------------------------------------------------------


def test_with_the_webs_user_a_member_of_the_group_is_not_enough(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    """A member of the web's group who switches to it (`sg backtide-web`) has the right gid but
    is not the web's user: refused. Root still may ask."""
    server = make_server(peer=peer_as(ME + 7, GROUP), user=ME)
    assert talk(server, {"cmd": "holds"})["outcome"] == "refused"
    server.close()
    server = make_server(peer=peer_as(ME, GROUP), user=ME)
    assert talk(server, {"cmd": "holds"})["outcome"] == "listed"
    server.close()
    server = make_server(peer=peer_as(0, GROUP), user=ME)
    assert talk(server, {"cmd": "holds"})["outcome"] == "listed"


@pytest.mark.parametrize(
    ("request_", "warned"),
    [
        (
            {"cmd": "set_secret", "kind": "telegram", "value": "1:" + "a" * 35, "chat_id": "42"},
            True,
        ),
        ({"cmd": "clear_secret", "kind": "telegram"}, True),
        ({"cmd": "trust", "hold_id": HOLD}, True),
        ({"cmd": "set_secret", "kind": "anthropic", "value": "sk-ant-" + "a" * 40}, False),
        ({"cmd": "decide", "hold_id": HOLD, "verdict": "approve"}, False),
    ],
)
def test_changes_that_outlast_the_web_are_a_warning(
    make_server: Callable[..., WebControlServer],
    caplog: pytest.LogCaptureFixture,
    request_: dict[str, Any],
    warned: bool,
) -> None:
    """Review of T12c (M1): a new Telegram or a trusted recipient outlasts whoever held the web,
    so the owner hears of it over today's alert channel (the log bridge alerts a WARNING)."""
    caplog.set_level(logging.WARNING, logger="backtide.service.web_control")
    talk(make_server(), signed(request_))
    said = [r.getMessage() for r in caplog.records if r.name == "backtide.service.web_control"]
    assert any("if it was not you" in m for m in said) is warned
    assert not any("a" * 30 in m for m in said)  # never the value


def test_the_log_says_which_socket_was_full(
    make_server: Callable[..., WebControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    server = make_server()
    assert server.label == "web socket" and ControlServer.label == "control socket"


# -- T26-3a: the service keeps the web's sessions --------------------------------------------------

CHANGE_REQUESTS = [
    {"cmd": "rewind", "snapshot_id": LISTED.id},
    {"cmd": "decide", "hold_id": HOLD, "verdict": "approve"},
    {"cmd": "trust", "hold_id": HOLD},
    {"cmd": "untrust", "trust_id": "t-0a1b2c3d"},
    {"cmd": "end_batch", "rule_id": "b-01234567"},
    {"cmd": "set_secret", "kind": "anthropic", "value": "sk-ant-api03-" + "k" * 80},
    {"cmd": "clear_secret", "kind": "openai"},
    {"cmd": "set_budget", "daily_usd": "2"},
    {"cmd": "accept_prices", "digest": "0123456789abcdef"},
    {"cmd": "task_start", "prompt": "borra todo"},
    {"cmd": "agent_create", "slug": "tercero", "profile": "claude-code", "volume_gib": 10},
    {"cmd": "agent_start", "agent": "revisor"},
    {"cmd": "agent_stop", "agent": "revisor"},
    {"cmd": "agent_pause", "agent": "revisor"},
    {"cmd": "agent_resume", "agent": "revisor"},
    {"cmd": "agent_delete", "agent": "revisor", "typed": "revisor"},
]


def test_every_change_is_in_the_list_of_those_that_need_a_session() -> None:
    assert {request["cmd"] for request in CHANGE_REQUESTS} == CHANGES


@pytest.mark.parametrize("request_", CHANGE_REQUESTS, ids=lambda r: r["cmd"])
@pytest.mark.parametrize("session", [None, "", "x" * 43, 7, ["s" * 43]])
def test_a_change_without_a_live_session_calls_nothing(
    make_server: Callable[..., WebControlServer],
    guardian: FakeGuardian,
    settings: FakeSettings,
    budget: FakeBudget,
    caplog: pytest.LogCaptureFixture,
    request_: dict[str, Any],
    session: object,
) -> None:
    caplog.set_level(logging.WARNING, logger="backtide.service.web_control")
    request = dict(request_) if session is None else {**request_, "session": session}
    reply = talk(make_server(), request)
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert "sesión" in reply["message"]
    assert nothing_asked(guardian, settings, budget)
    assert any("without a live session" in r.getMessage() for r in caplog.records)


def test_a_change_with_a_session_that_ended_calls_nothing(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    sessions = signed_in()
    server = make_server(sessions=sessions)
    assert talk(server, signed(CHANGE_REQUESTS[0]))["outcome"] == "done"
    sessions.end(SESSION)
    assert talk(server, signed(CHANGE_REQUESTS[0]))["outcome"] == "refused"
    assert len(guardian.calls) == 1


def test_without_sessions_no_change_goes_through(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    """A service built without the web's sessions fails closed."""
    server = make_server(sessions=None)
    assert talk(server, signed(CHANGE_REQUESTS[0]))["outcome"] == "refused"
    assert talk(server, {"cmd": "session_check", "session": SESSION})["outcome"] == "refused"
    assert guardian.calls == []


def test_a_link_opens_a_session_that_then_changes(
    make_server: Callable[..., WebControlServer],
    guardian: FakeGuardian,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from backtide.service.web_control import (
        ask_session_check,
        ask_session_end,
        ask_session_open,
    )

    caplog.set_level(logging.WARNING, logger="backtide.service.web_control")
    sessions = Sessions()
    server = make_server(sessions=sessions)
    ask = {"server_uid": ME, "peer": the_web}
    token = sessions.new_link()
    assert ask_session_open(server.path, "y" * 43, **ask) is None  # a guess spends nothing
    session = ask_session_open(server.path, token, **ask)
    assert session is not None and session.id != token
    assert ask_session_open(server.path, token, **ask) is None  # one use
    assert ask_session_check(server.path, session.id, **ask) == session
    reply = ask_rewind(server.path, LISTED.id, via="web", session=session.id, **ask)
    assert reply["outcome"] == "done"
    assert ask_session_end(server.path, session.id, **ask) == "ended"
    assert ask_session_check(server.path, session.id, **ask) is None
    assert ask_session_end(server.path, session.id, **ask) == "expired"
    said = [r.getMessage() for r in caplog.records if r.name == "backtide.service.web_control"]
    assert any("wrong, spent or old" in m for m in said)
    assert not any(token in m or session.id in m for m in said)  # never a secret in the log


def test_closing_every_session_needs_a_live_one(
    make_server: Callable[..., WebControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    from backtide.service.web_control import ask_session_end

    caplog.set_level(logging.INFO, logger="backtide.service.web_control")
    sessions = signed_in()
    other = sessions.open(sessions.new_link())
    assert other is not None
    server = make_server(sessions=sessions)
    ask = {"server_uid": ME, "peer": the_web}
    assert ask_session_end(server.path, "x" * 43, every=True, **ask) == "refused"
    assert len(sessions) == 2
    assert ask_session_end(server.path, SESSION, every=True, **ask) == "ended"
    assert len(sessions) == 0
    assert any("closed every session (2)" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "session_open"},
        {"cmd": "session_open", "token": "t" * 43, "session": SESSION},
        {"cmd": "session_check", "token": "t" * 43},
        {"cmd": "session_end", "session": SESSION, "via": "web"},
        {"cmd": "web_link"},  # root's alone
    ],
)
def test_a_session_command_of_another_shape_is_refused(
    make_server: Callable[..., WebControlServer], request_: dict[str, Any]
) -> None:
    sessions = signed_in()
    reply = talk(make_server(sessions=sessions), request_)
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert len(sessions) == 1


def test_opening_sessions_has_a_bucket_of_its_own(
    make_server: Callable[..., WebControlServer],
) -> None:
    clock = Clock()
    server = make_server(opens=Bucket(2, 0.001, clock=clock), checks=Bucket(3, 0.001, clock=clock))
    opens = [talk(server, {"cmd": "session_open", "token": "t" * 43}) for _ in range(3)]
    assert [r["outcome"] for r in opens] == ["refused"] * 3
    assert "Demasiadas" in opens[2]["message"]
    checks = [talk(server, {"cmd": "session_check", "session": SESSION}) for _ in range(4)]
    assert [r["outcome"] for r in checks] == ["live", "live", "live", "busy"]
    assert talk(server, {"cmd": "holds"})["outcome"] == "listed"  # the reads' bucket is apart


def test_root_mints_the_link_on_the_control_socket(
    folder: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from backtide.service.control import ask_web_link

    caplog.set_level(logging.INFO, logger="backtide.service.control")
    sessions = Sessions()
    me = lambda sock: (4242, ME, os.getegid())  # noqa: E731
    server = ControlServer(
        FakeGuardian(),
        folder / "control.sock",
        peer=me,
        sessions=sessions,
        on_entry=lambda action, details: True,
    )
    server.start()
    try:
        first = ask_web_link(server.path, peer=me)
        second = ask_web_link(server.path, peer=me)
        assert sessions.open(first) is None  # the new one killed the unspent one
        assert sessions.open(second) is not None
        assert talk(server, {"cmd": "web_link", "x": 1})["outcome"] == "refused"
        said = [r.getMessage() for r in caplog.records]
        assert any("a new one-time link for the web" in m for m in said)
        assert not any(first in m or second in m for m in said)
    finally:
        server.close()


def test_a_service_without_a_web_gives_no_link(folder: Path) -> None:
    from backtide.service.control import ask_web_link

    me = lambda sock: (4242, ME, os.getegid())  # noqa: E731
    server = ControlServer(FakeGuardian(), folder / "control.sock", peer=me)
    server.start()
    try:
        with pytest.raises(ControlError, match="no tiene web"):
            ask_web_link(server.path, peer=me)
    finally:
        server.close()


def test_a_check_may_say_it_is_not_a_use_and_nothing_else(
    make_server: Callable[..., WebControlServer],
) -> None:
    server = make_server()
    assert talk(server, {"cmd": "session_check", "session": SESSION, "use": False})["ok"]
    for use in (True, 1, "false", None):
        reply = talk(server, {"cmd": "session_check", "session": SESSION, "use": use})
        assert reply["outcome"] == "refused", use


def test_closing_every_session_has_a_bucket_of_its_own(
    make_server: Callable[..., WebControlServer],
) -> None:
    """Made-up links that empty the opening bucket never block "close them all"."""
    clock = Clock()
    server = make_server(opens=Bucket(1, 0.001, clock=clock), ends=Bucket(1, 0.001, clock=clock))
    for _ in range(3):
        talk(server, {"cmd": "session_open", "token": "t" * 43})
    assert talk(server, {"cmd": "session_end_all", "session": SESSION})["outcome"] == "ended"


def test_every_link_and_every_entry_reaches_the_hook(folder: Path) -> None:
    """One by one (review of T26-3a): the log bridge would let only one a minute by."""
    from backtide.service.control import ask_web_link
    from backtide.service.web_control import ask_session_open

    entries: list[tuple[str, dict[str, Any]]] = []
    sessions = Sessions()
    me = lambda sock: (4242, ME, os.getegid())  # noqa: E731
    control = ControlServer(
        FakeGuardian(),
        folder / "control.sock",
        peer=me,
        sessions=sessions,
        on_entry=lambda action, details: entries.append((action, details)) is None,
    )
    narrow = WebControlServer(
        FakeGuardian(),
        folder / "web.sock",
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: entries.append((action, details)) is None,
    )
    control.start()
    narrow.start()
    try:
        ask_web_link(control.path, peer=me)
        token = ask_web_link(control.path, peer=me)
        assert ask_session_open(narrow.path, "x" * 43, server_uid=ME, peer=the_web) is None
        assert ask_session_open(narrow.path, token, server_uid=ME, peer=the_web) is not None
    finally:
        control.close()
        narrow.close()
    assert entries == [
        ("web_link_given", {"uid": ME, "pid": 4242}),
        ("web_link_given", {"uid": ME, "pid": 4242}),
        ("web_session_opened", {"pid": 4242}),
    ]
    assert token not in repr(entries)


def test_sessions_without_a_place_to_record_entries_are_refused(folder: Path) -> None:
    with pytest.raises(ControlError, match="apuntar"):
        ControlServer(FakeGuardian(), folder / "control.sock", sessions=Sessions())
    with pytest.raises(ControlError, match="apuntar"):
        WebControlServer(
            FakeGuardian(), folder / "web.sock", group=GROUP, snapshots=list, sessions=Sessions()
        )


def test_an_entry_that_cannot_be_recorded_is_refused(
    make_server: Callable[..., WebControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    """Fails closed (review of T26-3a): no record, no session; the cookie never leaves."""
    from backtide.service.web_control import ask_session_open

    sessions = Sessions()
    server = make_server(sessions=sessions, on_entry=lambda action, details: False)
    token = sessions.new_link()
    assert ask_session_open(server.path, token, server_uid=ME, peer=the_web) is None
    assert len(sessions) == 0
    assert any("could not be recorded" in r.getMessage() for r in caplog.records)


def test_root_closes_every_session_on_its_own_socket(folder: Path) -> None:
    """`sudo backtide enlace --cerrar-todas` (T26-3a-2): for when the web is not to be trusted."""
    from backtide.service.control import ask_web_end_all

    entries: list[tuple[str, dict[str, Any]]] = []
    sessions = signed_in()
    sessions.open(sessions.new_link())
    unspent = sessions.new_link()
    me = lambda sock: (4242, ME, os.getegid())  # noqa: E731
    server = ControlServer(
        FakeGuardian(),
        folder / "control.sock",
        peer=me,
        sessions=sessions,
        on_entry=lambda action, details: entries.append((action, details)) is None,
    )
    server.start()
    try:
        assert ask_web_end_all(server.path, peer=me) == 2
        assert talk(server, {"cmd": "web_end_all", "x": 1})["outcome"] == "refused"
    finally:
        server.close()
    assert len(sessions) == 0 and sessions.open(unspent) is None
    assert entries == [("web_sessions_closed", {"uid": ME, "pid": 4242, "ended": 2})]


def test_the_webs_close_all_is_recorded_too(make_server: Callable[..., WebControlServer]) -> None:
    entries: list[tuple[str, dict[str, Any]]] = []
    server = make_server(on_entry=lambda action, details: entries.append((action, details)) is None)
    assert talk(server, {"cmd": "session_end_all", "session": SESSION})["outcome"] == "ended"
    assert entries == [("web_sessions_closed", {"pid": 4242, "ended": 1})]


def test_web_end_all_is_not_on_the_narrow_socket(
    make_server: Callable[..., WebControlServer],
) -> None:
    assert talk(make_server(), {"cmd": "web_end_all"})["outcome"] == "refused"


# -- T26-3b-1: the web's password --------------------------------------------------------------

WEB_PASSWORD = "correct horse battery staple"  # noqa: S105 - a test value


@pytest.fixture
def checker(tmp_path: Path) -> Any:
    from backtide.service import password

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    password.write(state, WEB_PASSWORD)
    return password.Checker(state)


def test_the_right_password_opens_a_recorded_session(
    make_server: Callable[..., WebControlServer], checker: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from backtide.service.web_control import ask_session_check, ask_session_password

    caplog.set_level(logging.DEBUG)
    entries: list[tuple[str, dict[str, Any]]] = []
    sessions = Sessions()
    server = make_server(
        sessions=sessions,
        password=checker,
        on_entry=lambda action, details: entries.append((action, details)) is None,
    )
    ask = {"server_uid": ME, "peer": the_web}
    session, why = ask_session_password(server.path, WEB_PASSWORD, **ask)
    assert why == "opened" and session is not None
    assert ask_session_check(server.path, session.id, **ask) == session
    assert entries == [("web_session_opened", {"pid": 4242, "via": "password"})]
    wrong, why = ask_session_password(server.path, WEB_PASSWORD + "!", **ask)
    assert wrong is None and why == "wrong"
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "wrong password" in logged and "horse" not in logged and session.id not in logged


def test_the_password_bucket_and_lock_are_said(
    make_server: Callable[..., WebControlServer], checker: Any
) -> None:
    from backtide.service.password import LOCK_AFTER
    from backtide.service.web_control import ask_session_password

    entries: list[str] = []
    from backtide.service.password import Checker

    clock = Clock()
    checker = Checker(checker._state_dir, clock=clock)  # noqa: SLF001 - its time, driven
    server = make_server(
        password=checker,
        on_entry=lambda a, d: entries.append(a) is None,
        passwords=Bucket(1000, 1000),  # the socket's own bucket out of the way: the Checker's
    )
    ask = {"server_uid": ME, "peer": the_web}
    whys = [ask_session_password(server.path, f"wrong one number {i}", **ask)[1] for i in range(6)]
    assert whys == ["wrong"] * 5 + ["slow_down"]
    for i in range(LOCK_AFTER):
        clock.now += 12
        ask_session_password(server.path, f"wrong one number {i}", **ask)
    clock.now += 12
    assert ask_session_password(server.path, WEB_PASSWORD, **ask) == (None, "locked")
    assert entries.count("web_password_locked") == 1


def test_without_a_password_checker_or_a_password_nothing_opens(
    make_server: Callable[..., WebControlServer], tmp_path: Path
) -> None:
    from backtide.service import password
    from backtide.service.web_control import ask_session_password

    ask = {"server_uid": ME, "peer": the_web}
    server = make_server()
    assert ask_session_password(server.path, WEB_PASSWORD, **ask) == (None, "refused")
    server.close()
    empty = tmp_path / "empty"
    empty.mkdir(mode=0o700)
    server = make_server(password=password.Checker(empty))
    assert ask_session_password(server.path, WEB_PASSWORD, **ask) == (None, "unset")


def test_root_sets_the_password_recorded_and_unquoted(
    folder: Path, checker: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from backtide.service import password
    from backtide.service.control import ask_set_password

    caplog.set_level(logging.DEBUG)
    entries: list[tuple[str, dict[str, Any]]] = []
    me = lambda sock: (4242, ME, os.getegid())  # noqa: E731
    server = ControlServer(
        FakeGuardian(),
        folder / "control.sock",
        peer=me,
        sessions=Sessions(),
        on_entry=lambda action, details: entries.append((action, details)) is None,
        password=checker,
    )
    server.start()
    try:
        assert ask_set_password(server.path, "short", peer=me)["outcome"] == "invalid"
        assert ask_set_password(server.path, "a brand new password", peer=me)["ok"] is True
        assert talk(server, {"cmd": "set_password"})["outcome"] == "refused"
    finally:
        server.close()
    line = password.read(checker._state_dir)  # noqa: SLF001
    assert line is not None and password.matches("a brand new password", line)
    assert entries == [("web_password_set", {"uid": ME, "pid": 4242, "ended": 0})]
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "brand new" not in logged and "short" not in logged


def test_the_password_is_not_on_the_narrow_socket_to_set(
    make_server: Callable[..., WebControlServer], checker: Any
) -> None:
    reply = talk(make_server(password=checker), {"cmd": "set_password", "password": "x" * 20})
    assert reply["outcome"] == "refused"


def test_a_new_password_ends_every_session(folder: Path, checker: Any) -> None:
    from backtide.service.control import ask_set_password

    sessions = Sessions()
    sessions.preset(SESSION)
    sessions.open(sessions.new_link())
    me = lambda sock: (4242, ME, os.getegid())  # noqa: E731
    server = ControlServer(FakeGuardian(), folder / "control.sock", peer=me, sessions=sessions,
                           on_entry=lambda a, d: True, password=checker)  # fmt: skip
    server.start()
    try:
        assert ask_set_password(server.path, "a brand new password", peer=me)["ok"] is True
    finally:
        server.close()
    assert len(sessions) == 0


def test_passwords_have_a_bucket_of_their_own(
    make_server: Callable[..., WebControlServer], checker: Any
) -> None:
    """A stream of passwords never empties the pages' checks (review of T26-3b-1)."""
    clock = Clock()
    server = make_server(password=checker, passwords=Bucket(2, 0.001, clock=clock),
                         checks=Bucket(5, 0.001, clock=clock))  # fmt: skip
    outcomes = [
        talk(server, {"cmd": "session_password", "password": f"not it number {i}"})["outcome"]
        for i in range(3)
    ]
    assert outcomes == ["wrong", "wrong", "refused"]
    assert talk(server, {"cmd": "session_check", "session": SESSION})["outcome"] == "live"


def test_a_password_file_that_changed_hands_lets_nobody_in(
    make_server: Callable[..., WebControlServer], checker: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from backtide.service import password

    path = password.path_of(checker._state_dir)  # noqa: SLF001
    path.chmod(0o644)
    reply = talk(
        make_server(password=checker), {"cmd": "session_password", "password": WEB_PASSWORD}
    )
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert any(
        r.levelno == logging.ERROR and "password file cannot be used" in r.getMessage()
        for r in caplog.records
    )


# -- T26-3b-2: passkeys over the narrow socket ------------------------------------------------


@pytest.fixture
def passkeys(tmp_path: Path) -> Any:
    from backtide.service.passkeys import Passkeys, origin_for

    state = tmp_path / "keys-state"
    state.mkdir(mode=0o700)
    return Passkeys(state, origins=[origin_for(8765)])


@pytest.mark.parametrize("session", [None, "x" * 43])
def test_no_passkey_without_a_live_session(
    make_server: Callable[..., WebControlServer], passkeys: Any, session: str | None
) -> None:
    server = make_server(passkeys=passkeys)
    for request in (
        {"cmd": "passkey_begin", "session": session},
        {"cmd": "passkey_list", "session": session},
        {"cmd": "passkey_finish", "session": session, "answer": "{}", "name": "x"},
    ):
        assert talk(server, request)["outcome"] == "refused"
    assert passkeys.keys() == []


def test_a_passkey_through_the_socket_is_recorded(
    make_server: Callable[..., WebControlServer], passkeys: Any
) -> None:
    from backtide.service.passkeys import origin_for
    from backtide.service.web_control import ask_passkey
    from tests.passkey_kit import SoftAuthenticator

    entries: list[tuple[str, dict[str, Any]]] = []
    server = make_server(passkeys=passkeys,
                         on_entry=lambda a, d: entries.append((a, d)) is None)  # fmt: skip
    ask = {"server_uid": ME, "peer": the_web}
    begun = ask_passkey(server.path, "passkey_begin", SESSION, **ask)
    answer = SoftAuthenticator().create(begun["options"], origin_for(8765))
    done = ask_passkey(server.path, "passkey_finish", SESSION, answer=answer, name="móvil", **ask)
    assert done["outcome"] == "added" and done["key"]["name"] == "móvil"
    listed = ask_passkey(server.path, "passkey_list", SESSION, **ask)
    assert [k["name"] for k in listed["keys"]] == ["móvil"]
    [(action, details)] = entries
    assert action == "web_passkey_added" and details["name"] == "móvil"
    assert set(details) == {"pid", "name", "tail"}


def test_a_passkey_the_box_does_not_take_is_taken_out(
    make_server: Callable[..., WebControlServer], passkeys: Any
) -> None:
    from backtide.service.passkeys import origin_for
    from backtide.service.web_control import ask_passkey
    from tests.passkey_kit import SoftAuthenticator

    server = make_server(passkeys=passkeys, on_entry=lambda a, d: False)
    ask = {"server_uid": ME, "peer": the_web}
    begun = ask_passkey(server.path, "passkey_begin", SESSION, **ask)
    answer = SoftAuthenticator().create(begun["options"], origin_for(8765))
    done = ask_passkey(server.path, "passkey_finish", SESSION, answer=answer, name="móvil", **ask)
    assert done["outcome"] == "refused" and passkeys.keys() == []


def test_a_passkey_command_of_another_shape_is_refused(
    make_server: Callable[..., WebControlServer], passkeys: Any
) -> None:
    server = make_server(passkeys=passkeys)
    for request in (
        {"cmd": "passkey_begin", "session": SESSION, "rp_id": "evil.example"},
        {"cmd": "passkey_finish", "session": SESSION, "answer": "{}"},
        {"cmd": "passkey_list"},
    ):
        assert talk(server, request)["outcome"] == "refused"


def test_a_recorded_passkey_that_cannot_be_written_is_refused(
    make_server: Callable[..., WebControlServer], passkeys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide.service.passkeys import PasskeyError, origin_for
    from backtide.service.web_control import ask_passkey
    from tests.passkey_kit import SoftAuthenticator

    def full(key: object) -> None:
        raise PasskeyError("no se puede guardar: disco lleno")

    monkeypatch.setattr(passkeys, "keep", full)
    entries: list[str] = []
    server = make_server(passkeys=passkeys, on_entry=lambda a, d: entries.append(a) is None)
    ask = {"server_uid": ME, "peer": the_web}
    begun = ask_passkey(server.path, "passkey_begin", SESSION, **ask)
    answer = SoftAuthenticator().create(begun["options"], origin_for(8765))
    done = ask_passkey(server.path, "passkey_finish", SESSION, answer=answer, name="x", **ask)
    assert done["outcome"] == "refused" and entries == ["web_passkey_added"]


# -- T26-3c: signing in with a passkey, and touching it again ----------------------------------


class Keyed:
    """A web's service with one key kept and one session open by the password."""

    def __init__(self, passkeys: Any, clock: Any = None) -> None:
        from backtide.service.passkeys import origin_for
        from tests.passkey_kit import SoftAuthenticator

        self.origin = origin_for(8765)
        self.keys = passkeys
        self.owner = SoftAuthenticator()
        self.keys.finish(
            "alta", self.owner.create(self.keys.begin("alta"), self.origin), "portátil"
        )
        self.sessions = Sessions(clock=clock) if clock is not None else Sessions()
        self.session = self.sessions.start().id
        self.entries: list[tuple[str, dict[str, Any]]] = []

    def record(self, action: str, details: dict[str, Any]) -> bool:
        self.entries.append((action, details))
        return True


class Ticks:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def keyed(passkeys: Any) -> Keyed:
    return Keyed(passkeys)


def keyed_server(
    make: Callable[..., WebControlServer], keyed: Keyed, **more: Any
) -> WebControlServer:
    return make(passkeys=keyed.keys, sessions=keyed.sessions, on_entry=keyed.record, **more)


def touched(server: WebControlServer, keyed: Keyed) -> None:
    begun = talk(server, {"cmd": "touch_begin", "session": keyed.session})
    answer = keyed.owner.get(begun["options"], keyed.origin)
    reply = talk(server, {"cmd": "touch_finish", "session": keyed.session, "answer": answer})
    assert reply["outcome"] == "touched"


def test_a_passkey_signs_in_and_it_is_recorded_first(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = keyed_server(make_server, keyed)
    begun = talk(server, {"cmd": "auth_begin"})
    answer = keyed.owner.get(begun["options"], keyed.origin)
    reply = talk(server, {"cmd": "auth_finish", "answer": answer})
    assert reply["outcome"] == "opened" and keyed.sessions.check(reply["session"]) is not None
    assert keyed.sessions.recently_touched(reply["session"])  # entering with it counts
    [(action, details)] = keyed.entries
    assert action == "web_session_opened" and details["via"] == "passkey"
    assert details["name"] == "portátil" and len(details["tail"]) == 4
    assert reply["session"] not in str(details)


def test_a_passkey_entry_the_box_does_not_take_is_refused(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = make_server(passkeys=keyed.keys, sessions=keyed.sessions, on_entry=lambda a, d: False)
    before = len(keyed.sessions)
    answer = keyed.owner.get(talk(server, {"cmd": "auth_begin"})["options"], keyed.origin)
    reply = talk(server, {"cmd": "auth_finish", "answer": answer})
    assert reply["outcome"] == "refused" and "session" not in reply
    assert len(keyed.sessions) == before


def test_a_signature_for_another_site_opens_nothing_and_warns(
    make_server: Callable[..., WebControlServer], keyed: Keyed, caplog: pytest.LogCaptureFixture
) -> None:
    server = keyed_server(make_server, keyed)
    before = len(keyed.sessions)
    answer = keyed.owner.get(talk(server, {"cmd": "auth_begin"})["options"], "https://evil.example")
    with caplog.at_level(logging.WARNING):
        reply = talk(server, {"cmd": "auth_finish", "answer": answer})
    assert reply["outcome"] == "refused" and "session" not in reply
    assert len(keyed.sessions) == before and keyed.entries == []
    assert "did not sign in" in caplog.text


def test_many_answers_are_not_even_looked_at(
    make_server: Callable[..., WebControlServer], keyed: Keyed, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide.service.passkeys import PasskeyError

    looked: list[object] = []

    def refuse(answer: object) -> None:
        looked.append(answer)
        raise PasskeyError("no")

    monkeypatch.setattr(keyed.keys, "sign_in", refuse)
    server = keyed_server(make_server, keyed, auth_answers=Bucket(3, 0))
    replies = [talk(server, {"cmd": "auth_finish", "answer": "x"})["message"] for _ in range(8)]
    assert len(looked) == 3
    assert sum("Demasiados" in message for message in replies) == 5


def test_a_stream_of_challenges_leaves_the_answers_alone(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = keyed_server(make_server, keyed, auth_begins=Bucket(1, 0))
    options = talk(server, {"cmd": "auth_begin"})["options"]
    assert "Demasiados" in talk(server, {"cmd": "auth_begin"})["message"]
    answer = keyed.owner.get(options, keyed.origin)
    assert talk(server, {"cmd": "auth_finish", "answer": answer})["outcome"] == "opened"


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "auth_begin", "rp_id": "evil.example"},
        {"cmd": "auth_begin", "session": "x"},
        {"cmd": "auth_finish"},
        {"cmd": "auth_finish", "answer": "{}", "origin": "https://evil.example"},
        {"cmd": "touch_begin"},
        {"cmd": "touch_finish", "session": "x"},
        {"cmd": "touch_status"},
    ],
)
def test_a_sign_in_of_another_shape_is_refused(
    make_server: Callable[..., WebControlServer], keyed: Keyed, request_: dict[str, Any]
) -> None:
    assert talk(keyed_server(make_server, keyed), request_)["outcome"] == "refused"


LASTING = [
    ({"cmd": "set_secret", "kind": "anthropic", "value": "sk-test", "via": "web"}, "settings"),
    ({"cmd": "clear_secret", "kind": "anthropic", "via": "web"}, "settings"),
    ({"cmd": "trust", "hold_id": "h-abc", "via": "web"}, "guardian"),
]


@pytest.mark.parametrize(("request_", "_who"), LASTING)
def test_what_lasts_asks_for_the_key_touched(
    make_server: Callable[..., WebControlServer],
    keyed: Keyed,
    settings: FakeSettings,
    guardian: FakeGuardian,
    budget: FakeBudget,
    request_: dict[str, Any],
    _who: str,
) -> None:
    server = keyed_server(make_server, keyed)
    reply = talk(server, {**request_, "session": keyed.session})
    assert reply["outcome"] == "refused" and "tocar tu llave" in reply["message"]
    assert nothing_asked(guardian, settings, budget)
    touched(server, keyed)
    reply = talk(server, {**request_, "session": keyed.session})
    assert "tocar tu llave" not in reply["message"]
    assert _who != "settings" or settings.calls


def test_a_touch_lasts_five_minutes(
    make_server: Callable[..., WebControlServer], passkeys: Any
) -> None:
    clock = Ticks()
    keyed = Keyed(passkeys, clock)
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    asked = {"cmd": "clear_secret", "kind": "anthropic", "via": "web", "session": keyed.session}
    assert "tocar tu llave" not in talk(server, asked)["message"]
    clock.now += 5 * 60
    assert "tocar tu llave" in talk(server, dict(asked))["message"]


def test_what_is_daily_does_not_ask_for_the_key(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = keyed_server(make_server, keyed)
    for request_ in (
        {"cmd": "decide", "hold_id": "h-abc", "verdict": "reject", "via": "web"},
        {"cmd": "end_batch", "rule_id": "r-1", "via": "web"},
        {"cmd": "set_budget", "daily_usd": "3", "via": "web"},
    ):
        reply = talk(server, {**request_, "session": keyed.session})
        assert "tocar tu llave" not in reply["message"]


def test_closing_every_session_asks_for_the_key_too(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = keyed_server(make_server, keyed)
    request_ = {"cmd": "session_end_all", "session": keyed.session}
    assert "tocar tu llave" in talk(server, dict(request_))["message"]
    assert keyed.sessions.check(keyed.session) is not None
    touched(server, keyed)
    assert talk(server, dict(request_))["outcome"] == "ended"
    assert keyed.sessions.check(keyed.session) is None


def test_without_keys_the_password_is_enough(
    make_server: Callable[..., WebControlServer],
    passkeys: Any,
    settings: FakeSettings,
    guardian: FakeGuardian,
    budget: FakeBudget,
) -> None:
    """D40: through the tunnel or a private network, nothing asks for a key nobody has."""
    server = make_server(passkeys=passkeys)
    asked = {"cmd": "clear_secret", "kind": "anthropic", "via": "web", "session": SESSION}
    assert "tocar tu llave" not in talk(server, asked)["message"]
    assert not nothing_asked(guardian, settings, budget)


def test_keys_that_cannot_be_read_ask_for_a_touch_that_cannot_happen(
    make_server: Callable[..., WebControlServer], keyed: Keyed, caplog: pytest.LogCaptureFixture
) -> None:
    from backtide.service.passkeys import path_of

    server = keyed_server(make_server, keyed)
    path_of(keyed.keys._state_dir).write_text("no es json")
    asked = {"cmd": "clear_secret", "kind": "anthropic", "via": "web", "session": keyed.session}
    with caplog.at_level(logging.ERROR):
        assert "tocar tu llave" in talk(server, asked)["message"]
    assert "cannot be read" in caplog.text


def test_another_key_asks_to_touch_one_of_those_there_are(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    from tests.passkey_kit import SoftAuthenticator

    server = keyed_server(make_server, keyed)
    begin = {"cmd": "passkey_begin", "session": keyed.session}
    assert "tocar tu llave" in talk(server, dict(begin))["message"]
    touched(server, keyed)
    answer = SoftAuthenticator().create(talk(server, dict(begin))["options"], keyed.origin)
    done = talk(server, {"cmd": "passkey_finish", "session": keyed.session, "answer": answer,
                         "name": "móvil"})  # fmt: skip
    assert done["outcome"] == "added" and len(keyed.keys.keys()) == 2


def test_the_first_key_is_only_right_after_entering(
    make_server: Callable[..., WebControlServer], passkeys: Any
) -> None:
    clock = Ticks()
    sessions = Sessions(clock=clock)
    session = sessions.start().id
    server = make_server(passkeys=passkeys, sessions=sessions)
    assert talk(server, {"cmd": "passkey_begin", "session": session})["outcome"] == "options"
    assert talk(server, {"cmd": "touch_status", "session": session})["add"] == "ok"
    clock.now += 5 * 60
    assert (
        "nada más entrar" in talk(server, {"cmd": "passkey_begin", "session": session})["message"]
    )
    assert talk(server, {"cmd": "touch_status", "session": session})["add"] == "again"


def test_two_sessions_racing_for_the_first_key_add_only_one(
    make_server: Callable[..., WebControlServer], passkeys: Any
) -> None:
    from backtide.service.passkeys import origin_for
    from tests.passkey_kit import SoftAuthenticator

    sessions = Sessions()
    one, other = sessions.start().id, sessions.start().id
    server = make_server(passkeys=passkeys, sessions=sessions)
    answers = {
        who: SoftAuthenticator().create(
            talk(server, {"cmd": "passkey_begin", "session": who})["options"], origin_for(8765)
        )
        for who in (one, other)
    }
    for who, outcome in ((one, "added"), (other, "refused")):
        reply = talk(server, {"cmd": "passkey_finish", "session": who, "answer": answers[who],
                              "name": "llave"})  # fmt: skip
        assert reply["outcome"] == outcome
    assert len(passkeys.keys()) == 1


def test_a_touch_is_recorded_first_and_said(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    [(action, details)] = keyed.entries
    assert action == "web_passkey_touched" and details["name"] == "portátil"
    assert set(details) == {"pid", "name", "tail"}


def test_a_touch_the_box_does_not_take_does_not_count(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = make_server(passkeys=keyed.keys, sessions=keyed.sessions, on_entry=lambda a, d: False)
    begun = talk(server, {"cmd": "touch_begin", "session": keyed.session})
    answer = keyed.owner.get(begun["options"], keyed.origin)
    reply = talk(server, {"cmd": "touch_finish", "session": keyed.session, "answer": answer})
    assert reply["outcome"] == "refused" and not keyed.sessions.recently_touched(keyed.session)


# -- T26-3d: taking a key out and naming it from the web ---------------------------------------


@pytest.fixture
def two_keyed(passkeys: Any) -> tuple[Keyed, Any]:
    """The service with two keys kept: ``owner``'s (portátil) and the one given back (móvil)."""
    from tests.passkey_kit import SoftAuthenticator

    keyed = Keyed(passkeys)
    other = SoftAuthenticator()
    keyed.keys.finish("alta2", other.create(keyed.keys.begin("alta2"), keyed.origin), "móvil")
    return keyed, other


def key_requests(key_id: str) -> list[dict[str, Any]]:
    return [{"cmd": "key_remove", "key": key_id},
            {"cmd": "key_rename", "key": key_id, "name": "otro"}]  # fmt: skip


@pytest.mark.parametrize("which", [0, 1], ids=["remove", "rename"])
def test_managing_a_key_without_a_live_session_changes_nothing(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any], which: int
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    before = keyed.keys.keys()
    request_ = key_requests(before[0].id)[which]
    for session in ("x" * 43, None, 7):
        reply = talk(server, {**request_, "session": session})
        assert reply["ok"] is False and "vuelve a entrar" in reply["message"]
    assert keyed.keys.keys() == before and keyed.entries == []


@pytest.mark.parametrize("which", [0, 1], ids=["remove", "rename"])
def test_managing_a_key_asks_for_a_key_touched_a_moment_ago(
    make_server: Callable[..., WebControlServer], passkeys: Any, which: int
) -> None:
    from tests.passkey_kit import SoftAuthenticator

    ticks = Ticks()
    keyed = Keyed(passkeys, clock=ticks)
    keyed.keys.finish("b", SoftAuthenticator().create(keyed.keys.begin("b"), keyed.origin), "móvil")
    server = keyed_server(make_server, keyed)
    before = keyed.keys.keys()
    request_ = {**key_requests(before[0].id)[which], "session": keyed.session}
    reply = talk(server, dict(request_))
    assert (reply["ok"], reply["outcome"]) == (False, "touch")
    assert "tocar tu llave" in reply["message"]
    assert keyed.keys.keys() == before and keyed.entries == []
    touched(server, keyed)
    keyed.entries.clear()
    ticks.now += 5 * 60 + 1  # the session lives on, the touch does not
    assert keyed.sessions.check(keyed.session) is not None
    assert talk(server, dict(request_))["outcome"] == "touch"
    assert keyed.keys.keys() == before and keyed.entries == []


def test_a_key_goes_from_the_web_recorded_first_and_every_session_with_it(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    keyed, _ = two_keyed
    other_session = keyed.sessions.start().id
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    keyed.entries.clear()
    going, staying = keyed.keys.keys()
    seen_when_recorded: list[int] = []

    def record(action: str, details: dict[str, Any]) -> bool:
        seen_when_recorded.append(len(keyed.keys.keys()))
        return keyed.record(action, details)

    server._on_entry = record
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, "key": going.id})
    assert (reply["ok"], reply["outcome"]) == (True, "removed")
    assert reply["ended"] == 2 and reply["name"] == going.name and reply["tail"] == going.tail
    assert keyed.keys.keys() == [staying]
    assert seen_when_recorded == [2]  # the black box heard before the file changed
    [(action, details)] = keyed.entries
    assert action == "web_passkey_removed"
    assert details == {"pid": 4242, "via": "web", "name": going.name, "tail": going.tail}
    assert keyed.sessions.check(keyed.session) is None
    assert keyed.sessions.check(other_session) is None


def test_a_removal_the_box_does_not_take_is_not_done(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    server._on_entry = lambda action, details: False
    before = keyed.keys.keys()
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, "key": before[0].id})
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert "apuntar" in reply["message"]
    assert keyed.keys.keys() == before
    assert keyed.sessions.check(keyed.session) is not None


def test_the_last_key_does_not_go_from_the_web(
    make_server: Callable[..., WebControlServer], keyed: Keyed
) -> None:
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    keyed.entries.clear()
    [only] = keyed.keys.keys()
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, "key": only.id})
    assert (reply["ok"], reply["outcome"]) == (False, "last")
    assert "sudo backtide llaves --quitar" in reply["message"]
    assert keyed.keys.keys() == [only] and keyed.entries == []
    assert keyed.sessions.check(keyed.session) is not None


def test_two_removals_at_once_leave_a_key(
    make_server: Callable[..., WebControlServer],
    two_keyed: tuple[Keyed, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Both saw two keys and were recorded: the second write is refused under the lock, and the
    ERROR says the event was not followed by the change."""
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    first, second = keyed.keys.keys()

    def the_other_goes_meanwhile(action: str, details: dict[str, Any]) -> bool:
        keyed.keys.remove(first.id)
        return True

    server._on_entry = the_other_goes_meanwhile
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, "key": second.id})
    assert (reply["ok"], reply["outcome"]) == (False, "last")
    assert keyed.keys.keys() == [second]
    assert keyed.sessions.check(keyed.session) is not None
    assert any(
        r.levelno == logging.ERROR and "recorded but" in r.getMessage() for r in caplog.records
    )


@pytest.mark.parametrize("given", ["nada", "", 7, None, ["x"]])
def test_a_key_is_named_by_its_whole_id(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any], given: object
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    keyed.entries.clear()
    before = keyed.keys.keys()
    for request_ in key_requests("x"):
        reply = talk(server, {**request_, "session": keyed.session, "key": given})
        assert (reply["ok"], reply["outcome"]) == (False, "missing")
    assert keyed.keys.keys() == before and keyed.entries == []


def test_the_end_of_an_id_is_roots_way_not_the_webs(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    before = keyed.keys.keys()
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, "key": before[0].tail})
    assert reply["outcome"] == "missing" and keyed.keys.keys() == before
    # And root's own commands are still not on the web's list.
    for request_ in ({"cmd": "passkey_remove", "key": before[0].id}, {"cmd": "passkeys"},
                     {"cmd": "passkey_rename", "key": before[0].id, "name": "x"}):  # fmt: skip
        assert "no se acepta" in talk(server, request_)["message"]
    assert keyed.keys.keys() == before


@pytest.mark.parametrize(
    "extra",
    [{}, {"name": "x"}, {"via": "sudo"}, {"uid": 0}],
    ids=["no-key", "a-name-too", "via", "uid"],
)
def test_a_removal_of_another_shape_is_refused(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any], extra: dict
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    before = keyed.keys.keys()
    with_key = {} if not extra else {"key": before[0].id}
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, **with_key, **extra})
    assert "forma esperada" in reply["message"] and keyed.keys.keys() == before


def test_a_key_is_named_from_the_web_recorded_first(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    keyed.entries.clear()
    target, other = keyed.keys.keys()
    names_when_recorded: list[str] = []

    def record(action: str, details: dict[str, Any]) -> bool:
        names_when_recorded.append(keyed.keys.keys()[0].name)
        return keyed.record(action, details)

    server._on_entry = record
    reply = talk(server, {"cmd": "key_rename", "session": keyed.session, "key": target.id,
                          "name": "viejo"})  # fmt: skip
    assert (reply["ok"], reply["outcome"]) == (True, "renamed")
    assert [k.name for k in keyed.keys.keys()] == ["viejo", other.name]
    assert names_when_recorded == [target.name]
    [(action, details)] = keyed.entries
    assert action == "web_passkey_renamed"
    assert details == {"pid": 4242, "via": "web", "name": "viejo", "was": target.name,
                       "tail": target.tail}  # fmt: skip
    assert keyed.sessions.check(keyed.session) is not None  # a name closes nothing


def test_a_name_the_box_does_not_take_is_not_changed(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    server._on_entry = lambda action, details: False
    before = keyed.keys.keys()
    reply = talk(server, {"cmd": "key_rename", "session": keyed.session, "key": before[0].id,
                          "name": "viejo"})  # fmt: skip
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert keyed.keys.keys() == before


@pytest.mark.parametrize("name", ["t.me/x", "@alguien", "", " x", "a" * 49, 7, None])
def test_a_bad_name_is_refused_and_not_recorded(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any], name: object
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    keyed.entries.clear()
    before = keyed.keys.keys()
    reply = talk(server, {"cmd": "key_rename", "session": keyed.session, "key": before[0].id,
                          "name": name})  # fmt: skip
    assert (reply["ok"], reply["outcome"]) == (False, "name")
    assert keyed.keys.keys() == before and keyed.entries == []


def test_keys_that_cannot_be_read_are_not_touched(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    from backtide.service.passkeys import path_of

    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    touched(server, keyed)
    keyed.entries.clear()
    before = keyed.keys.keys()
    path = path_of(keyed.keys._state_dir)
    path.chmod(0o644)  # not ours any more, as far as the service can tell
    reply = talk(server, {"cmd": "key_remove", "session": keyed.session, "key": before[0].id})
    assert reply["ok"] is False and keyed.entries == []
    path.chmod(0o600)
    assert keyed.keys.keys() == before


def test_the_web_sees_each_keys_whole_id_to_ask_by_it(
    make_server: Callable[..., WebControlServer], two_keyed: tuple[Keyed, Any]
) -> None:
    keyed, _ = two_keyed
    server = keyed_server(make_server, keyed)
    listed = talk(server, {"cmd": "passkey_list", "session": keyed.session})["keys"]
    assert [k["id"] for k in listed] == [k.id for k in keyed.keys.keys()]
    assert all(set(k) == {"id", "name", "tail", "added"} for k in listed)  # never a public key


# --- the tasks (T26-5a, docs/47 section 7.1) ------------------------------------------------------

TASK_ID = "c0de" * 8
SECRET_ANSWER = "la clave era sk-ant-api03-" + "A1b2C3d4" * 8


class Tasks:
    """What a Guardian does with tasks: records what reaches it."""

    def __init__(self, guardian: FakeGuardian) -> None:
        self.started: list[tuple[str, bool, int | None, str]] = []
        self.read: list[str] = []
        self.stopped: list[str] = []
        guardian.task_start = self.task_start  # type: ignore[attr-defined]
        guardian.task_status = self.task_status  # type: ignore[attr-defined]
        guardian.task_stop = self.task_stop  # type: ignore[attr-defined]

    def task_start(
        self, prompt: str, *, resume: bool = False, seconds: int | None = None, requested_by: str
    ) -> TaskStart:
        self.started.append((prompt, resume, seconds, requested_by))
        return TaskStart(TASK_ID)

    def task_status(self, task_id: str) -> TaskStatus:
        self.read.append(task_id)
        return TaskStatus(task_id, TaskOutcome.OK, "", SECRET_ANSWER, 0, 1.0)

    def task_stop(self, task_id: str) -> bool:
        self.stopped.append(task_id)
        return True


@pytest.fixture
def tasks(guardian: FakeGuardian) -> Tasks:
    return Tasks(guardian)


NO_SESSIONS = [{}, {"session": "x" * 43}, {"session": 3}, {"session": None}]


@pytest.mark.parametrize("carried", NO_SESSIONS)
def test_a_task_without_a_live_session_is_refused(
    make_server: Callable[..., WebControlServer], tasks: Tasks, carried: dict[str, Any]
) -> None:
    reply = talk(make_server(), {"cmd": "task_start", "prompt": "borra todo", **carried})
    assert reply["ok"] is False and reply["outcome"] == "refused"
    assert "sesión" in reply["message"] and tasks.started == []


@pytest.mark.parametrize("carried", NO_SESSIONS)
def test_an_answer_without_a_live_session_is_refused(
    make_server: Callable[..., WebControlServer], tasks: Tasks, carried: dict[str, Any]
) -> None:
    """The one read of this socket that takes a session: answers are not in the black box, which
    is what the web's group may read anyway."""
    reply = talk(make_server(), {"cmd": "task_status", "task": TASK_ID, **carried})
    assert reply["ok"] is False and reply["outcome"] == "refused"
    assert "answer" not in reply and "sk-ant" not in json.dumps(reply)
    assert tasks.read == []


def test_a_session_that_ended_reads_no_answer(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    server = make_server()
    assert talk(server, {"cmd": "session_end", "session": SESSION})["outcome"] == "ended"
    assert talk(server, signed({"cmd": "task_status", "task": TASK_ID}))["outcome"] == "refused"
    assert talk(server, signed({"cmd": "task_start", "prompt": "x"}))["outcome"] == "refused"
    assert tasks.read == [] and tasks.started == []


def test_a_live_session_gives_a_task_as_the_web(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    reply = talk(make_server(), signed({"cmd": "task_start", "prompt": "hola", "continue": True}))
    assert reply == {"ok": True, "outcome": "started", "message": "", "task": TASK_ID}
    ((prompt, resume, seconds, by),) = tasks.started
    assert (prompt, resume, seconds) == ("hola", True, None)
    assert by == f"web (uid {ME}, pid 4242)"


def test_the_web_cannot_say_it_is_the_cli(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    reply = talk(make_server(), signed({"cmd": "task_start", "prompt": "hola", "via": "cli"}))
    assert reply["outcome"] == "refused" and tasks.started == []


def test_a_live_session_reads_the_answer(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    reply = talk(make_server(), signed({"cmd": "task_status", "task": TASK_ID}))
    assert reply["ok"] is True and reply["outcome"] == "ok" and reply["answer"] == SECRET_ANSWER
    assert tasks.read == [TASK_ID]


def test_the_web_cannot_stop_a_task_nor_open_the_old_way(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    """Not on its list, with a session or without. Nor `shell`, whose reply names the container."""
    server = make_server()
    for request in (
        {"cmd": "task_stop", "task": TASK_ID},
        signed({"cmd": "task_stop", "task": TASK_ID}),
    ):
        reply = talk(server, request)
        assert reply["outcome"] == "refused" and "no se acepta" in reply["message"]
    request = signed({"cmd": "shell", "kind": "session", "continue": False})
    assert talk(server, request)["outcome"] == "refused"
    assert tasks.stopped == []


def test_reading_an_answer_does_not_keep_a_session_alive(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    """A chat left open asks by itself: the idle hour goes on counting (as the panel's stream)."""
    now = [0.0]
    sessions = Sessions(clock=lambda: now[0])
    sessions.preset(SESSION)
    server = make_server(sessions=sessions)
    for _ in range(2):
        now[0] += IDLE_SECONDS / 2 - 1
        assert talk(server, signed({"cmd": "task_status", "task": TASK_ID}))["ok"] is True
    now[0] += 10
    assert talk(server, signed({"cmd": "task_status", "task": TASK_ID}))["outcome"] == "refused"


def test_a_task_counts_as_using_the_session(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    now = [0.0]
    sessions = Sessions(clock=lambda: now[0])
    sessions.preset(SESSION)
    server = make_server(sessions=sessions)
    now[0] += IDLE_SECONDS - 1
    assert talk(server, signed({"cmd": "task_start", "prompt": "hola"}))["ok"] is True
    now[0] += IDLE_SECONDS - 1
    assert sessions.check(SESSION) is not None


def test_a_task_spends_the_changes_bucket_and_an_answer_does_not(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    server = make_server(changes=Bucket(1, 0.001))
    assert talk(server, signed({"cmd": "task_start", "prompt": "uno"}))["ok"] is True
    reply = talk(server, signed({"cmd": "task_start", "prompt": "dos"}))
    assert reply["outcome"] == "refused" and "Demasiados" in reply["message"]
    assert len(tasks.started) == 1
    assert talk(server, signed({"cmd": "task_status", "task": TASK_ID}))["ok"] is True


def test_an_answer_spends_the_requests_bucket(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    server = make_server(requests=Bucket(1, 0.001))
    assert talk(server, signed({"cmd": "task_status", "task": TASK_ID}))["ok"] is True
    assert talk(server, signed({"cmd": "task_status", "task": TASK_ID}))["outcome"] == "refused"


def test_a_task_does_not_ask_to_touch_the_key() -> None:
    """Docs/47, table 5.3: what the terminal does for hours does; a task, like approving, is what
    happens every day."""
    assert "task_start" not in TOUCH_CHANGES


def test_the_longest_prompt_fits_with_its_session(
    make_server: Callable[..., WebControlServer], tasks: Tasks
) -> None:
    prompt = "ñ" * MAX_PROMPT
    server = make_server()
    reply = ask_task_start(server.path, prompt, peer=the_web, server_uid=None, session=SESSION)
    assert reply["ok"] is True and tasks.started[0][0] == prompt
