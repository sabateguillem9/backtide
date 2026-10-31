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
from backtide.service.passkeys import Passkeys, origin_for
from backtide.service.sessions import Sessions
from backtide.service.web_control import WebControlServer, ask_snapshots
from backtide.snapshots import SnapshotError
from backtide.web import server as server_module
from backtide.web.approve import ControlApprover
from backtide.web.paths import WebPaths
from backtide.web.rewind import Availability, ControlRewinder, narrow_availability
from backtide.web.security import ServiceAccess
from backtide.web.settings import ControlSettings, ControlSpend
from tests import test_web_decide as decide
from tests import test_web_rewind as rewind
from tests.test_service_control import FakeGuardian
from tests.test_service_web_control import GROUP, FakeBudget, FakeSettings
from tests.webkit import SESSION, new_box, new_client

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
        sessions=signed_in(),
        on_entry=lambda action, details: True,
    )
    server.start()
    yield server
    server.close()


def signed_in() -> Sessions:
    """The service's sessions, with the one of the test client's cookie open (T26-3a)."""
    sessions = Sessions()
    sessions.preset(SESSION)
    return sessions


def the_service(narrow: WebControlServer) -> ServiceAccess:
    """Who is signed in, asked of the service as the installed web asks it."""
    return ServiceAccess(narrow.path, server_uid=ME, wait=0, peer=the_web)


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
        access=the_service(narrow),
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
    web = new_client(
        tmp_path, approver=approver, clock=lambda: decide.NOW, access=the_service(narrow)
    )
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
    web = new_client(
        tmp_path,
        settings=settings,
        spend=ControlSpend(narrow.path, **ours()),
        access=the_service(narrow),
    )
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


def test_signing_out_when_the_service_cannot_end_it_keeps_the_cookie(
    folder: Path, guardian: FakeGuardian, budget: FakeBudget, tmp_path: Path
) -> None:
    """The real path (review of T26-3a-2): the service checks the session for the page, then
    cannot end it (its bucket is empty): "Salir" answers 503 and keeps the cookie, and the
    session is still alive in the service."""
    from backtide.service.web_control import Bucket
    from tests.test_web_rewind import POST_HEADERS

    sessions = signed_in()
    csrf = sessions.check(SESSION).csrf  # type: ignore[union-attr]
    server = WebControlServer(
        guardian,
        folder / "web2.sock",
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: True,
        checks=Bucket(1, 1e-6),  # one check (the page's), then nothing
    )
    server.start()
    try:
        new_box(tmp_path)
        web = new_client(
            tmp_path, access=ServiceAccess(server.path, server_uid=ME, wait=0, peer=the_web)
        )
        response = web.post(
            "/salir", data={"csrf": csrf}, headers=POST_HEADERS, follow_redirects=False
        )
    finally:
        server.close()
    assert response.status_code == 503 and "set-cookie" not in response.headers
    assert sessions.check(SESSION) is not None


# -- T26-3b-1: signing in with the web's password, through the service -----------------------

WEB_PASSWORD = "correct horse battery staple"  # noqa: S105 - a test value


@pytest.fixture
def signing_in(folder: Path, guardian: FakeGuardian, tmp_path: Path) -> Iterator[Any]:
    from backtide.service import password

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    password.write(state, WEB_PASSWORD)
    sessions = Sessions()
    server = WebControlServer(
        guardian,
        folder / "web3.sock",
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: True,
        password=password.Checker(state),
        passkeys=Passkeys(state, origins=[origin_for(8765)]),
    )
    server.start()
    new_box(tmp_path)
    web = new_client(
        tmp_path,
        logged_in=False,
        access=ServiceAccess(server.path, server_uid=ME, wait=0, peer=the_web),
    )
    yield web, sessions
    server.close()


def test_the_way_in_shows_the_password_form(signing_in: Any) -> None:
    web, _ = signing_in
    page = web.get("/ahora")
    assert page.status_code == 401
    assert 'action="/s/' in page.text and '/entrar"' in page.text
    assert 'type="password"' in page.text and 'autocomplete="current-password"' in page.text


def test_the_right_password_signs_in_and_the_cookie_works(signing_in: Any) -> None:
    from tests.test_web_rewind import POST_HEADERS

    web, sessions = signing_in
    entered = web.post("/entrar", data={"password": WEB_PASSWORD}, headers=POST_HEADERS)
    assert entered.status_code == 200 and "set-cookie" in entered.headers
    assert WEB_PASSWORD not in entered.text
    assert len(sessions) == 1
    assert web.get("/ahora").status_code == 200


@pytest.mark.parametrize(
    ("data", "status", "said"),
    [
        ({"password": WEB_PASSWORD + "x"}, 401, "Esa no es la contraseña"),
        ({"password": "x" * 300}, 400, "no se ha podido leer"),
        ({"pw": WEB_PASSWORD}, 400, "no se ha podido leer"),
    ],
)
def test_a_wrong_password_signs_nobody_in(
    signing_in: Any, data: dict[str, str], status: int, said: str
) -> None:
    from tests.test_web_rewind import POST_HEADERS

    web, sessions = signing_in
    refused = web.post("/entrar", data=data, headers=POST_HEADERS)
    assert refused.status_code == status and said in refused.text
    assert "set-cookie" not in refused.headers and len(sessions) == 0
    assert WEB_PASSWORD not in refused.text


def test_a_password_from_another_site_is_refused_unread(signing_in: Any) -> None:
    web, sessions = signing_in
    refused = web.post(
        "/entrar",
        data={"password": WEB_PASSWORD},
        headers={
            "origin": "http://evil.example",
            "content-type": "application/x-www-form-urlencoded",
        },
    )
    assert refused.status_code == 403 and len(sessions) == 0


def test_signing_in_where_a_session_lives_ends_it(signing_in: Any) -> None:
    from tests.test_web_rewind import POST_HEADERS

    web, sessions = signing_in
    web.post("/entrar", data={"password": WEB_PASSWORD}, headers=POST_HEADERS)
    assert len(sessions) == 1
    web.post("/entrar", data={"password": WEB_PASSWORD}, headers=POST_HEADERS)
    assert len(sessions) == 1  # the first ended when the second began


@pytest.mark.parametrize(
    "accepted",
    [
        "contraseña de montaña 9",
        "ünïcödé pässwörd ✓",
        "🌊" * 12 + "marea",
        "Ab1!xQ9#mZ2&",
        "".join(chr(0x4E00 + i) for i in range(226)),  # 678 bytes: right at the form's edge
    ],
)
def test_every_password_that_can_be_set_can_be_typed(
    signing_in: Any, tmp_path: Path, accepted: str
) -> None:
    """Review of T26-3b-1: what ``problem`` accepts goes through the web's form as it is."""
    from backtide.service import password
    from tests.test_web_rewind import POST_HEADERS

    assert password.problem(accepted) is None
    password.write(tmp_path / "state", accepted)
    web, sessions = signing_in
    entered = web.post("/entrar", data={"password": accepted}, headers=POST_HEADERS)
    assert entered.status_code == 200 and len(sessions) == 1


# -- T26-3b-2: registering a passkey, through the service ---------------------------------------


def _signed_in_to_keys(web: Any) -> tuple[Any, str]:
    import re

    from tests.test_web_rewind import POST_HEADERS

    entered = web.post("/entrar", data={"password": WEB_PASSWORD}, headers=POST_HEADERS)
    assert "/llaves?nueva=1" in entered.text  # the first entry asks for a passkey (D40)
    elsewhere = web.get("/llaves?nueva=1")  # 127.0.0.1: where a passkey cannot be made
    assert 'id="passkey-form"' not in elsewhere.text and "backtide.localhost" in elsewhere.text
    page = web.get("/llaves?nueva=1", headers={"host": "backtide.localhost:8765"})
    assert page.status_code == 200 and 'id="passkey-form"' in page.text
    csrf = re.search(r'data-csrf="([^"]+)"', page.text)
    assert csrf is not None
    return page, csrf.group(1)


def test_a_passkey_is_registered_from_the_web(signing_in: Any) -> None:
    import json

    from tests.passkey_kit import SoftAuthenticator
    from tests.test_web_rewind import POST_HEADERS

    web, _ = signing_in
    _, csrf = _signed_in_to_keys(web)
    begun = web.post("/llaves/empezar", data={"csrf": csrf}, headers=POST_HEADERS).json()
    assert begun["ok"] is True
    answer = SoftAuthenticator().create(begun["options"], "http://backtide.localhost:8765")
    finished = web.post(
        "/llaves/registrar",
        data={"csrf": csrf, "name": "portátil", "answer": answer},
        headers=POST_HEADERS,
    ).json()
    assert finished["ok"] is True and finished["key"]["name"] == "portátil"
    assert "portátil" in web.get("/llaves").text
    assert json.dumps(finished).count("public") == 0  # never a key's bytes back to the page


def test_a_passkey_cannot_be_registered_without_this_sessions_csrf(signing_in: Any) -> None:
    from tests.test_web_rewind import POST_HEADERS

    web, _ = signing_in
    _signed_in_to_keys(web)
    refused = web.post("/llaves/empezar", data={"csrf": "x" * 43}, headers=POST_HEADERS)
    assert refused.status_code == 403 and refused.json()["ok"] is False
    web.cookies.clear()
    assert (
        web.post("/llaves/empezar", data={"csrf": "x" * 43}, headers=POST_HEADERS).status_code
        == 401
    )


def test_the_web_answers_on_backtide_localhost(signing_in: Any) -> None:
    web, _ = signing_in
    page = web.get("/ahora", headers={"host": "backtide.localhost:8765"})
    assert page.status_code == 401 and 'type="password"' in page.text
