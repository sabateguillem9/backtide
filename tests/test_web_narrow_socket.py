"""T12c: the installed web acts through the service's narrow socket, not as the service's user.

The pages are the same as in tests/test_web_rewind.py, test_web_decide.py and test_web_settings.py
(the Guard, the CSRF token, the one-time confirmations): what changes is who the web asks. Here a
real ``WebControlServer`` answers over a real Unix socket in a short folder, to a fake Guardian,
with ``SO_PEERCRED`` played by a fake ``peer`` that says "the web's group"."""

import os
import shutil
import socket
import tempfile
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide.service.control import ControlError
from backtide.service.web_control import WebControlServer, ask_snapshots
from backtide.snapshots import SnapshotError
from backtide.web import server as server_module
from backtide.web.approve import ControlApprover
from backtide.web.paths import WebPaths
from backtide.web.rewind import Availability, ControlRewinder, narrow_availability
from backtide.web.settings import ControlSettings, ControlSpend
from tests import test_web_decide as decide
from tests import test_web_rewind as rewind
from tests.test_service_control import FakeGuardian
from tests.test_service_web_control import GROUP, FakeBudget, FakeSettings
from tests.webkit import new_box, new_client

ME = os.geteuid()


def the_web(sock: socket.socket) -> tuple[int, int, int]:
    return 4242, ME, GROUP


@pytest.fixture
def folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vt"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def guardian() -> FakeGuardian:
    found = FakeGuardian()
    found.holds = [decide.hold()]
    return found


@pytest.fixture
def budget() -> FakeBudget:
    return FakeBudget()


@pytest.fixture
def narrow(folder: Path, guardian: FakeGuardian, budget: FakeBudget) -> Iterator[WebControlServer]:
    server = WebControlServer(
        guardian,
        folder / "web.sock",
        group=GROUP,
        snapshots=lambda: list(rewind.SNAPS),
        peer=the_web,
        settings=FakeSettings(),
        budget=budget,
    )
    server.start()
    yield server
    server.close()


def ours(**more: Any) -> dict[str, Any]:
    """What the installed web passes its clients: the narrow socket's service uid (root there;
    here, us) and our group."""
    return {"server_uid": ME, "egid": lambda: GROUP, "peer": the_web, **more}


# -- availability ---------------------------------------------------------------------------------


def test_the_narrow_socket_is_ready_only_with_our_group_and_its_owner(
    narrow: WebControlServer, folder: Path
) -> None:
    path = narrow.path
    assert narrow_availability(path, enabled=True, server_uid=ME, egid=lambda: GROUP) is (
        Availability.READY
    )
    assert narrow_availability(path, enabled=False, server_uid=ME, egid=lambda: GROUP) is (
        Availability.DISABLED
    )
    assert narrow_availability(path, enabled=True, server_uid=ME, egid=lambda: GROUP + 1) is (
        Availability.OTHER_USER
    )
    # Not the service's (root's, when installed): something odd is there.
    assert narrow_availability(path, enabled=True, server_uid=ME + 1, egid=lambda: GROUP) is (
        Availability.OFF
    )
    assert narrow_availability(
        folder / "missing.sock", enabled=True, server_uid=ME, egid=lambda: GROUP
    ) is (Availability.NO_SERVICE)
    (folder / "link.sock").symlink_to(path)
    assert narrow_availability(
        folder / "link.sock", enabled=True, server_uid=ME, egid=lambda: GROUP
    ) is (Availability.OFF)


def test_a_narrow_socket_without_the_groups_write_bit_is_other_user(
    narrow: WebControlServer,
) -> None:
    os.chmod(narrow.path, 0o600)
    assert ControlRewinder(narrow.path, enabled=True, **ours()).availability() is (
        Availability.OTHER_USER
    )


def test_each_client_reads_the_narrow_socket_with_its_own_flag(narrow: WebControlServer) -> None:
    path = narrow.path
    assert ControlRewinder(path, enabled=True, **ours()).availability() is Availability.READY
    assert ControlApprover(path, enabled=True, **ours()).availability() is Availability.READY
    assert ControlSettings(path, enabled=True, **ours()).availability() is Availability.READY
    assert ControlSpend(path, **ours()).availability() is Availability.READY
    for client in (ControlRewinder(path, **ours()), ControlApprover(path, **ours())):
        assert client.availability() is Availability.DISABLED


# -- the web's pages over the narrow socket -------------------------------------------------------


def test_the_web_rewinds_through_the_narrow_socket_as_web(
    narrow: WebControlServer, guardian: FakeGuardian, tmp_path: Path
) -> None:
    rewinder = ControlRewinder(narrow.path, enabled=True, wait=0, **ours())
    new_box(tmp_path)
    web = new_client(
        tmp_path,
        snapshots=lambda: ask_snapshots(narrow.path, server_uid=ME, peer=the_web),
        rewinder=rewinder,
        clock=lambda: rewind.NOW,
    )
    page = web.get("/instantaneas").text
    assert "rewind-go" in page
    done = rewind.post(web, rewind.form_of(rewind.confirm(web)))
    assert 'data-outcome="done"' in done.text
    assert guardian.calls == [(rewind.TARGET.id, f"web (uid {ME}, pid 4242)")]
    # A forged POST (no confirmation) asks nothing, whatever the socket would take.
    assert rewind.post(web, {"csrf": "x", "ticket": "y", "id": rewind.TARGET.id}).status_code in (
        400,
        403,
    )
    assert len(guardian.calls) == 1


def test_the_web_approves_and_rejects_through_the_narrow_socket(
    narrow: WebControlServer, guardian: FakeGuardian, tmp_path: Path
) -> None:
    approver = ControlApprover(narrow.path, enabled=True, wait=0, **ours())
    new_box(tmp_path).append("file", "create", "work/notas.md")
    web = new_client(tmp_path, approver=approver, clock=lambda: decide.NOW)
    assert "556" in decide.text_of(web.get("/panel").text)
    assert decide.post(web, decide.confirm(web, "aprobar")).status_code == 200
    assert decide.post(web, decide.confirm(web, "rechazar")).status_code == 200
    who = f"web (uid {ME}, pid 4242)"
    assert guardian.decisions == [
        (decide.HOLD, "approve", "web", who),
        (decide.HOLD, "reject", "web", who),
    ]


def test_the_settings_page_sets_a_cap_through_the_narrow_socket(
    narrow: WebControlServer, budget: FakeBudget, tmp_path: Path
) -> None:
    from tests.test_web_spend import STATUS, budget_confirm

    budget.status = lambda: dict(STATUS)  # type: ignore[method-assign]
    settings = ControlSettings(narrow.path, enabled=True, wait=0, **ours())
    new_box(tmp_path)
    web = new_client(tmp_path, settings=settings, spend=ControlSpend(narrow.path, **ours()))
    fields = budget_confirm(web)
    saved = web.post(
        "/ajustes/guardar",
        data={**fields, "diario": "3", "mensual": "40"},
        headers=decide.POST_HEADERS,
    )
    assert saved.status_code == 200, saved.text[:300]
    assert budget.caps == [(Decimal("3"), Decimal("40"), f"web (uid {ME}, pid 4242)")]


# -- run_web: what --socket-web wires --------------------------------------------------------------


def test_run_web_with_the_narrow_socket_asks_it_for_everything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def capture(**options: Any) -> object:
        seen.update(options)
        return object()

    class Quiet:
        def run(self, sockets: Any) -> None:
            return None

    monkeypatch.setattr(server_module, "create_app", capture)
    monkeypatch.setattr(server_module, "make_server", lambda app: Quiet())
    new_box(tmp_path)
    paths = WebPaths(tmp_path / "blackbox.db", tmp_path / "volume", tmp_path / "control.sock")
    web_socket = tmp_path / "web.sock"
    server_module.run_web(
        paths,
        0,
        lambda url, name: None,
        can_rewind=True,
        can_set=True,
        can_approve=True,
        web_socket=web_socket,
    )
    for name in ("rewinder", "settings", "approver", "spend"):
        client = seen[name]
        assert (client._path, client._server_uid) == (web_socket, server_module.SERVICE_UID)
    # Nobody at the socket: the snapshot list is "cannot be read", which the pages handle.
    with pytest.raises(SnapshotError):
        seen["snapshots"]()


def test_run_web_without_it_keeps_the_control_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(server_module, "create_app", lambda **o: seen.update(o) or object())
    monkeypatch.setattr(
        server_module, "make_server", lambda app: type("Q", (), {"run": lambda s, sockets: 0})()
    )
    new_box(tmp_path)
    paths = WebPaths(tmp_path / "blackbox.db", tmp_path / "volume", tmp_path / "control.sock")
    server_module.run_web(paths, 0, lambda url, name: None)
    assert (seen["rewinder"]._path, seen["rewinder"]._server_uid) == (paths.control_socket, None)


def test_the_web_never_trusts_a_narrow_socket_that_is_not_the_services(
    narrow: WebControlServer,
) -> None:
    with pytest.raises(ControlError):
        ControlRewinder(narrow.path, enabled=True, wait=0, peer=the_web, server_uid=ME + 1).rewind(
            rewind.TARGET.id
        )
