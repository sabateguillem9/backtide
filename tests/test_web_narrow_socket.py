"""T12c: the installed web acts through the service's narrow socket, not as the service's user.

The pages are the same as in tests/test_web_rewind.py, test_web_decide.py and test_web_settings.py
(the Guard, the CSRF token, the one-time confirmations): what changes is who the web asks. Here a
real ``WebControlServer`` answers over a real Unix socket in a short folder, to a fake Guardian,
with ``SO_PEERCRED`` played by a fake ``peer`` that says "the web's group"."""

import os
import re
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
from backtide.service.web_control import Bucket, WebControlServer, ask_snapshots
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
        keys=Bucket(1000, 1000),  # the flows here are longer than a person's in one breath
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


# -- T26-3c: signing in with the key, and touching it again, through the service ---------------


KEY_HOST = {"host": "backtide.localhost:8765"}
KEY_ORIGIN = "http://backtide.localhost:8765"


def key_headers() -> dict[str, str]:
    from tests.test_web_rewind import POST_HEADERS

    return {
        **POST_HEADERS,
        **KEY_HOST,
        "origin": KEY_ORIGIN,
        "content-type": "application/x-www-form-urlencoded",
    }


def registered(web: Any) -> tuple[Any, str]:
    """An owner with a key registered, signed out by the end: the key, and the session's CSRF."""
    from tests.passkey_kit import SoftAuthenticator
    from tests.test_web_rewind import POST_HEADERS

    _, csrf = _signed_in_to_keys(web)
    begun = web.post("/llaves/empezar", data={"csrf": csrf}, headers=POST_HEADERS).json()
    owner = SoftAuthenticator()
    finished = web.post(
        "/llaves/registrar",
        data={
            "csrf": csrf,
            "name": "portátil",
            "answer": owner.create(begun["options"], KEY_ORIGIN),
        },
        headers=POST_HEADERS,
    ).json()
    assert finished["ok"] is True
    return owner, csrf


def test_signing_in_with_the_key_from_the_web(signing_in: Any) -> None:
    web, sessions = signing_in
    owner, _ = registered(web)
    web.cookies.clear()
    page = web.get("/ahora", headers=KEY_HOST)
    assert page.status_code == 401 and 'id="webauthn-go"' in page.text
    assert "webauthn-get.js" in page.text
    begun = web.post("/entrar/llave/empezar", headers=key_headers()).json()
    assert begun["ok"] is True
    finished = web.post(
        "/entrar/llave/responder",
        data={"answer": owner.get(begun["options"], KEY_ORIGIN)},
        headers=key_headers(),
    )
    assert finished.status_code == 200 and finished.json()["ok"] is True
    assert "HttpOnly" in finished.headers["set-cookie"]
    assert "samesite=strict" in finished.headers["set-cookie"].lower()
    assert web.get("/ahora", headers=KEY_HOST).status_code == 200


def test_at_the_numeric_address_the_way_in_says_where_a_key_works(signing_in: Any) -> None:
    web, _ = signing_in
    page = web.get("/ahora")
    assert 'id="webauthn-go"' not in page.text and "backtide.localhost:8765" in page.text


def test_a_signature_for_another_site_gives_no_cookie(signing_in: Any) -> None:
    web, _ = signing_in
    owner, _ = registered(web)
    web.cookies.clear()
    begun = web.post("/entrar/llave/empezar", headers=key_headers()).json()
    refused = web.post(
        "/entrar/llave/responder",
        data={"answer": owner.get(begun["options"], "https://evil.example")},
        headers=key_headers(),
    )
    assert refused.status_code == 400 and refused.json()["ok"] is False
    assert "set-cookie" not in refused.headers
    assert web.get("/ahora", headers=KEY_HOST).status_code == 401


def test_another_site_cannot_ask_for_a_challenge(signing_in: Any) -> None:
    web, _ = signing_in
    registered(web)
    headers = {**key_headers(), "origin": "https://evil.example"}
    assert web.post("/entrar/llave/empezar", headers=headers).status_code == 403
    assert (
        web.post("/entrar/llave/responder", data={"answer": "{}"}, headers=headers).status_code
        == 403
    )


def test_closing_every_session_sends_you_to_touch_the_key_first(signing_in: Any) -> None:
    from tests.test_web_rewind import POST_HEADERS

    web, sessions = signing_in
    owner, csrf = registered(web)
    live = len(sessions)
    sent = web.post(
        "/ajustes/cerrar-sesiones",
        data={"csrf": csrf, "confirmo": "cerrar-todas"},
        headers=POST_HEADERS,
        follow_redirects=False,
    )
    assert sent.status_code == 303 and "/tocar?volver=ajustes" in sent.headers["location"]
    assert len(sessions) == live
    page = web.get("/tocar?volver=ajustes", headers=KEY_HOST)
    assert page.status_code == 200 and 'id="webauthn-go"' in page.text
    assert 'data-target="' in page.text and "/ajustes" in page.text
    begun = web.post("/tocar/empezar", data={"csrf": csrf}, headers=key_headers()).json()
    touched = web.post(
        "/tocar/responder",
        data={"csrf": csrf, "answer": owner.get(begun["options"], KEY_ORIGIN)},
        headers=key_headers(),
    ).json()
    assert touched["ok"] is True
    closed = web.post(
        "/ajustes/cerrar-sesiones",
        data={"csrf": csrf, "confirmo": "cerrar-todas"},
        headers=POST_HEADERS,
        follow_redirects=False,
    )
    assert closed.status_code != 303 or "/tocar" not in closed.headers["location"]
    assert len(sessions) == 0


def test_touching_the_key_needs_this_sessions_csrf(signing_in: Any) -> None:
    web, _ = signing_in
    registered(web)
    assert (
        web.post("/tocar/empezar", data={"csrf": "x" * 43}, headers=key_headers()).status_code
        == 403
    )
    web.cookies.clear()
    assert (
        web.post("/tocar/empezar", data={"csrf": "x" * 43}, headers=key_headers()).status_code
        == 401
    )


def test_the_touch_page_goes_back_only_to_our_own_pages(signing_in: Any) -> None:
    web, _ = signing_in
    registered(web)
    page = web.get("/tocar?volver=https://evil.example/", headers=KEY_HOST)
    assert re.search(r'data-target="/s/[a-z0-9]+/"', page.text)
    assert not re.search(r'(data-target|class="settings-cancel" href)="[^"]*evil', page.text)


def test_with_a_key_the_keys_page_asks_to_touch_one_before_adding(signing_in: Any) -> None:
    web, _ = signing_in
    registered(web)
    page = web.get("/llaves", headers=KEY_HOST)
    assert 'id="passkey-form"' not in page.text and "/tocar?volver=llaves" in page.text


# -- T26-3d: managing the keys from the web, with the service answering -------------------------


def touch_with(web: Any, signer: Any, csrf: str) -> None:
    begun = web.post("/tocar/empezar", data={"csrf": csrf}, headers=key_headers()).json()
    done = web.post(
        "/tocar/responder",
        data={"csrf": csrf, "answer": signer.get(begun["options"], KEY_ORIGIN)},
        headers=key_headers(),
    ).json()
    assert done["ok"] is True, done


def add_key(web: Any, csrf: str, name: str) -> Any:
    from tests.passkey_kit import SoftAuthenticator

    signer = SoftAuthenticator()
    begun = web.post("/llaves/empezar", data={"csrf": csrf}, headers=key_headers()).json()
    assert begun["ok"] is True, begun
    done = web.post(
        "/llaves/registrar",
        data={"csrf": csrf, "name": name, "answer": signer.create(begun["options"], KEY_ORIGIN)},
        headers=key_headers(),
    ).json()
    assert done["ok"] is True, done
    return signer


def sign_in_with(web: Any, signer: Any) -> Any:
    begun = web.post("/entrar/llave/empezar", headers=key_headers()).json()
    return web.post(
        "/entrar/llave/responder",
        data={"answer": signer.get(begun["options"], KEY_ORIGIN)},
        headers=key_headers(),
    )


def field(html: str, name: str) -> str:
    found = re.search(rf'name="{name}" value="([^"]*)"', html)
    assert found is not None, f"no {name} in the page"
    return found.group(1)


def key_ids(tmp_path: Path) -> dict[str, str]:
    keys = Passkeys(tmp_path / "state", origins=[origin_for(8765)])
    return {key.name: key.id for key in keys.keys()}


def test_a_lost_key_is_taken_out_from_the_web_with_the_other_one(
    signing_in: Any, tmp_path: Path
) -> None:
    """T26-3d's "terminada cuando": a key is lost (gone from the test's authenticator), the other
    signs in and takes it out, every session ends, and the lost one no longer signs in."""
    web, sessions = signing_in
    lost, csrf = registered(web)
    touch_with(web, lost, csrf)
    kept = add_key(web, csrf, "móvil")
    thief_session = sessions.start().id  # `lost` is now only the thief's: the owner has no copy
    web.cookies.clear()

    entered = sign_in_with(web, kept)
    assert entered.status_code == 200 and entered.json()["ok"] is True
    cookie = entered.headers["set-cookie"].split(";")[0]
    ids = key_ids(tmp_path)
    assert sorted(ids) == ["móvil", "portátil"]
    page = web.get("/llaves", headers=KEY_HOST)
    assert f"/llaves/quitar?llave={ids['portátil']}" in page.text
    confirm = web.get(f"/llaves/quitar?llave={ids['portátil']}", headers=KEY_HOST)
    assert confirm.status_code == 200 and "portátil" in confirm.text
    done = web.post(
        "/llaves/quitar",
        data={"csrf": field(confirm.text, "csrf"), "ticket": field(confirm.text, "ticket"),
              "llave": ids["portátil"]},
        headers=key_headers(),
    )  # fmt: skip
    assert done.status_code == 200 and "portátil" in done.text
    assert 'class="settings-yes"' in done.text
    gone = done.headers["set-cookie"].lower()  # the browser is told to forget it
    assert gone.startswith(cookie.split("=")[0].lower() + '=""') and "max-age=0" in gone
    assert list(key_ids(tmp_path)) == ["móvil"]
    assert len(sessions) == 0 and sessions.check(thief_session) is None
    web.cookies.clear()
    # The same cookie, kept by whoever had it: the service has ended its session.
    after = web.get("/llaves", headers={**KEY_HOST, "cookie": cookie})
    assert after.status_code == 401

    refused = sign_in_with(web, lost)
    assert refused.status_code == 400 and "no está registrada" in refused.json()["message"]
    assert sign_in_with(web, kept).json()["ok"] is True


def test_managing_a_key_sends_you_to_touch_one_first(signing_in: Any, tmp_path: Path) -> None:
    web, _ = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    add_key(web, csrf, "móvil")
    web.cookies.clear()
    web.post("/entrar", data={"password": WEB_PASSWORD}, headers=key_headers())
    assert web.get("/ahora", headers=KEY_HOST).status_code == 200  # a password's session: no touch
    the_id = key_ids(tmp_path)["portátil"]
    for path in ("quitar", "nombre"):
        page = web.get(f"/llaves/{path}?llave={the_id}", headers=KEY_HOST, follow_redirects=False)
        assert page.status_code == 303 and "/tocar?volver=llaves" in page.headers["location"]


def test_the_service_says_no_even_if_the_page_was_open_from_before(
    signing_in: Any, tmp_path: Path
) -> None:
    """A form left open, whose touch ran out: the POST goes to touch, and nothing changes."""
    web, _ = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    add_key(web, csrf, "móvil")
    ids = key_ids(tmp_path)
    confirm = web.get(f"/llaves/quitar?llave={ids['portátil']}", headers=KEY_HOST)
    form = {"csrf": field(confirm.text, "csrf"), "ticket": field(confirm.text, "ticket"),
            "llave": ids["portátil"]}  # fmt: skip
    web.cookies.clear()
    web.post("/entrar", data={"password": WEB_PASSWORD}, headers=key_headers())
    session_csrf = re.search(r'data-csrf="([^"]+)"', web.get("/tocar", headers=KEY_HOST).text)
    assert session_csrf is not None
    done = web.post(
        "/llaves/quitar",
        data={**form, "csrf": session_csrf.group(1)},
        headers=key_headers(),
        follow_redirects=False,
    )
    assert done.status_code == 303 and "/tocar?volver=llaves" in done.headers["location"]
    assert sorted(key_ids(tmp_path)) == ["móvil", "portátil"]


def test_removing_needs_this_sessions_csrf_and_a_ticket_for_this_key(
    signing_in: Any, tmp_path: Path
) -> None:
    web, _ = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    add_key(web, csrf, "móvil")
    ids = key_ids(tmp_path)
    confirm = web.get(f"/llaves/quitar?llave={ids['portátil']}", headers=KEY_HOST)
    ticket = field(confirm.text, "ticket")
    good = {"csrf": csrf, "ticket": ticket, "llave": ids["portátil"]}
    wrong_csrf = web.post("/llaves/quitar", data={**good, "csrf": "x" * 43}, headers=key_headers())
    assert wrong_csrf.status_code == 403
    other_key = web.post(
        "/llaves/quitar", data={**good, "llave": ids["móvil"]}, headers=key_headers()
    )  # the ticket was for the other key: spent, and nothing changes
    assert other_key.status_code == 400
    spent = web.post("/llaves/quitar", data=good, headers=key_headers())
    assert spent.status_code == 400
    assert sorted(key_ids(tmp_path)) == ["móvil", "portátil"]
    without = web.post(
        "/llaves/quitar", data={"csrf": csrf, "llave": ids["móvil"]}, headers=key_headers()
    )
    assert without.status_code == 400
    assert sorted(key_ids(tmp_path)) == ["móvil", "portátil"]


def test_removing_from_another_site_is_stopped_by_the_guard(
    signing_in: Any, tmp_path: Path
) -> None:
    web, _ = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    add_key(web, csrf, "móvil")
    ids = key_ids(tmp_path)
    confirm = web.get(f"/llaves/quitar?llave={ids['portátil']}", headers=KEY_HOST)
    form = {"csrf": csrf, "ticket": field(confirm.text, "ticket"), "llave": ids["portátil"]}
    foreign = {**key_headers(), "origin": "https://evil.example"}
    assert web.post("/llaves/quitar", data=form, headers=foreign).status_code == 403
    assert sorted(key_ids(tmp_path)) == ["móvil", "portátil"]


def test_the_last_key_offers_no_removal_and_the_service_refuses_it(
    signing_in: Any, tmp_path: Path
) -> None:
    web, sessions = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    the_id = key_ids(tmp_path)["portátil"]
    page = web.get("/llaves", headers=KEY_HOST)
    assert "/llaves/quitar" not in page.text and "sudo backtide llaves --quitar" in page.text
    confirm = web.get(f"/llaves/quitar?llave={the_id}", headers=KEY_HOST)
    assert 'name="ticket"' not in confirm.text and "sudo backtide llaves --quitar" in confirm.text
    # Whatever the page offers: the service decides. A ticket from when there were two.
    other = add_key(web, csrf, "móvil")
    ids = key_ids(tmp_path)
    confirm = web.get(f"/llaves/quitar?llave={ids['portátil']}", headers=KEY_HOST)
    form = {"csrf": csrf, "ticket": field(confirm.text, "ticket"), "llave": ids["portátil"]}
    Passkeys(tmp_path / "state", origins=[origin_for(8765)]).remove(ids["móvil"])
    done = web.post("/llaves/quitar", data=form, headers=key_headers())
    assert done.status_code == 400 and "sudo backtide llaves --quitar" in done.text
    assert list(key_ids(tmp_path)) == ["portátil"] and len(sessions) == 1
    assert other is not None


def test_a_key_gets_a_new_name_from_the_web(signing_in: Any, tmp_path: Path) -> None:
    web, sessions = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    the_id = key_ids(tmp_path)["portátil"]
    assert f"/llaves/nombre?llave={the_id}" in web.get("/llaves", headers=KEY_HOST).text
    confirm = web.get(f"/llaves/nombre?llave={the_id}", headers=KEY_HOST)
    assert confirm.status_code == 200 and 'value="portátil"' in confirm.text
    done = web.post(
        "/llaves/nombre",
        data={"csrf": csrf, "ticket": field(confirm.text, "ticket"), "llave": the_id,
              "nombre": "portátil viejo"},
        headers=key_headers(),
        follow_redirects=False,
    )  # fmt: skip
    assert done.status_code == 303 and done.headers["location"].endswith("/llaves")
    assert key_ids(tmp_path) == {"portátil viejo": the_id}
    assert len(sessions) == 1


def test_a_bad_name_comes_back_with_its_reason_and_a_new_ticket(
    signing_in: Any, tmp_path: Path
) -> None:
    web, _ = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    the_id = key_ids(tmp_path)["portátil"]
    confirm = web.get(f"/llaves/nombre?llave={the_id}", headers=KEY_HOST)
    ticket = field(confirm.text, "ticket")
    done = web.post(
        "/llaves/nombre",
        data={"csrf": csrf, "ticket": ticket, "llave": the_id, "nombre": "t.me/x"},
        headers=key_headers(),
    )
    assert done.status_code == 400 and 'aria-invalid="true"' in done.text
    assert field(done.text, "ticket") != ticket and 'id="key-name-error"' in done.text
    assert key_ids(tmp_path) == {"portátil": the_id}
    again = web.post(
        "/llaves/nombre",
        data={"csrf": csrf, "ticket": field(done.text, "ticket"), "llave": the_id,
              "nombre": " móvil "},
        headers=key_headers(),
        follow_redirects=False,
    )  # fmt: skip
    assert again.status_code == 303 and key_ids(tmp_path) == {"móvil": the_id}


def test_a_key_that_is_not_there_says_so(signing_in: Any) -> None:
    web, _ = signing_in
    owner, csrf = registered(web)
    touch_with(web, owner, csrf)
    for path in ("quitar", "nombre"):
        page = web.get(f"/llaves/{path}?llave=nada", headers=KEY_HOST)
        assert page.status_code == 404 and 'name="ticket"' not in page.text


def test_after_the_first_key_the_page_asks_for_a_second(signing_in: Any, tmp_path: Path) -> None:
    web, _ = signing_in
    owner, csrf = registered(web)
    page = web.get("/llaves?nueva=1", headers=KEY_HOST)
    assert "segunda llave" in page.text and "/tocar?volver=llaves-alta" in page.text
    touch = web.get("/tocar?volver=llaves-alta", headers=KEY_HOST)
    assert re.search(r'data-target="/s/[a-z0-9]+/llaves\?nueva=1"', touch.text)
    touch_with(web, owner, csrf)
    form = web.get("/llaves?nueva=1", headers=KEY_HOST)
    assert 'id="passkey-form"' in form.text and "Más tarde" in form.text
    add_key(web, csrf, "móvil")
    done = web.get("/llaves?nueva=1", headers=KEY_HOST)
    assert "segunda llave" not in done.text and 'id="passkey-form"' not in done.text
