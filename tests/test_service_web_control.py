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
from backtide.jail.proxy_config import PROXY_GID, PROXY_UID
from backtide.service.control import (
    ControlError,
    ControlServer,
    ask_decide,
    ask_rewind,
    ask_set_budget,
    ask_trust,
)
from backtide.service.settings import Applied, Outcome, SettingsOutcome
from backtide.service.spend import CapOutcome
from backtide.service.web_control import (
    CHANGES,
    COMMANDS,
    READS,
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
        server = WebControlServer(guardian, folder / "web.sock", **options)
        server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


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


@pytest.mark.parametrize("group", [0, AGENT_GID, PROXY_GID, True])
def test_the_group_of_root_the_agent_or_the_proxy_is_refused(folder: Path, group: int) -> None:
    with pytest.raises(ControlError):
        WebControlServer(FakeGuardian(), folder / "web.sock", group=group, snapshots=list)
    assert web_group_problem(0) and web_group_problem(AGENT_GID) and web_group_problem(PROXY_GID)
    assert web_group_problem(GROUP) is None


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
    assert talk(server, {"cmd": "rewind", "snapshot_id": LISTED.id})["outcome"] == "refused"
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
    assert COMMANDS == READS | CHANGES and not READS & CHANGES
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
    reply = ask_rewind(server.path, LISTED.id, via="web", peer=the_web, server_uid=ME)
    assert reply["outcome"] == "done"
    # Without `via` too: the narrow socket says it is the web whatever the client sends.
    assert talk(server, {"cmd": "rewind", "snapshot_id": NEWER.id})["outcome"] == "done"
    assert guardian.calls == [
        (LISTED.id, f"web (uid {ME}, pid 4242)"),
        (NEWER.id, f"web (uid {ME}, pid 4242)"),
    ]


def test_a_forged_snapshot_id_is_refused_without_the_guardian(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    for snapshot_id in (UNLISTED.id, "../../etc", "20261028T090000Z-periodic/..", 7):
        reply = talk(server, {"cmd": "rewind", "snapshot_id": snapshot_id})
        assert reply["ok"] is False and reply["outcome"] in ("invalid", "refused")
    assert talk(server, {"cmd": "rewind", "snapshot_id": UNLISTED.id})["outcome"] == "invalid"
    assert guardian.calls == []


def test_an_unreadable_list_rewinds_nothing(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    def broken() -> list[Snapshot]:
        raise OSError("the volume is gone")

    server = make_server(snapshots=broken)
    assert talk(server, {"cmd": "rewind", "snapshot_id": LISTED.id})["outcome"] == "invalid"
    assert talk(server, {"cmd": "snapshots"})["ok"] is False
    assert guardian.calls == []


def test_approving_and_rejecting_go_to_the_guardian_as_the_web(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    server = make_server()
    assert ask_decide(server.path, HOLD, "approve", via="web", peer=the_web, server_uid=ME)["ok"]
    assert ask_decide(server.path, HOLD, "reject", peer=the_web, server_uid=ME)["ok"]
    trusted = ask_trust(server.path, HOLD, peer=the_web, server_uid=ME)
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
        assert talk(server, request)["outcome"] == "refused"
    assert guardian.decisions == []


def test_an_unknown_hold_is_the_guardians_word(
    make_server: Callable[..., WebControlServer], guardian: FakeGuardian
) -> None:
    from backtide.service.holds import HoldStatus

    guardian.hold_status = HoldStatus.UNKNOWN
    reply = talk(make_server(), {"cmd": "decide", "hold_id": HOLD, "verdict": "approve"})
    assert (reply["ok"], reply["outcome"]) == (False, "unknown")


def test_settings_and_caps_go_to_the_service_as_the_web(
    make_server: Callable[..., WebControlServer], settings: FakeSettings, budget: FakeBudget
) -> None:
    server = make_server()
    key = "sk-ant-api03-" + "k" * 80
    reply = talk(server, {"cmd": "set_secret", "kind": "anthropic", "value": key})
    assert reply["outcome"] == "saved" and key not in json.dumps(reply)
    assert talk(server, {"cmd": "clear_secret", "kind": "openai"})["outcome"] == "cleared"
    secrets = talk(server, {"cmd": "secrets"})
    assert secrets["secrets"] == {"anthropic": {"set": True, "tail": "WXYZ"}}
    capped = ask_set_budget(
        server.path, daily_usd="2,5", monthly_usd=None, via="web", peer=the_web, server_uid=ME
    )
    assert capped["outcome"] == "saved"
    assert talk(server, {"cmd": "set_budget", "daily_usd": "-1"})["outcome"] == "invalid"
    assert talk(server, {"cmd": "accept_prices", "digest": "0123456789abcdef"})["ok"]
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
    rewind = {"cmd": "rewind", "snapshot_id": LISTED.id}
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
    talk(make_server(), request_)
    said = [r.getMessage() for r in caplog.records if r.name == "backtide.service.web_control"]
    assert any("if it was not you" in m for m in said) is warned
    assert not any("a" * 30 in m for m in said)  # never the value


def test_the_log_says_which_socket_was_full(
    make_server: Callable[..., WebControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    server = make_server()
    assert server.label == "web socket" and ControlServer.label == "control socket"
