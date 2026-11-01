"""T26-4a: the web behind a domain, with a made-up https origin and the real ``Guard``, app and
narrow socket. The web still listens only on loopback; what changes is what it answers to: one
``Host``, one ``Origin``, the root of the site, a ``__Host-`` cookie, no password (D40), and the
passkeys of that domain. Each refusal is checked by its reason, next to a control that gets in.

And the review of T26-3c: with a domain anyone can send made-up cookies, so they must never empty
the bucket of a session that lives, and a refusal by that cap is a 503, not a 401."""

import json
import shutil
import socket
import tempfile
import threading
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backtide.service import password
from backtide.service.control import ControlError, ControlServer, ask_web_link
from backtide.service.origin import parse_public_origin
from backtide.service.passkeys import Passkeys, origin_for, path_of
from backtide.service.runner import web_passkeys_of
from backtide.service.sessions import Session, Sessions
from backtide.service.web_control import Bucket, WebControlServer
from backtide.web.security import (
    CHECKS_AT_ONCE,
    COOKIE_NAME,
    DOMAIN_COOKIE_NAME,
    SECURITY_HEADERS,
    ServiceAccess,
    SessionsBusy,
    allowed_hosts,
)
from tests.passkey_kit import SoftAuthenticator
from tests.test_service_control import FakeGuardian
from tests.test_service_web_control import GROUP, ME, talk
from tests.webkit import PORT, PREFIX, PREFIX_PATH, SESSION, TOKEN, new_box, new_client

DOMAIN = "backtide.example.org"
ORIGIN = parse_public_origin(f"https://{DOMAIN}")
URL = ORIGIN.url
POST = {
    "origin": URL,
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "content-type": "application/x-www-form-urlencoded",
}
RIGHT_PASSWORD = "correct horse battery staple"  # noqa: S105 - a test value


def the_web(sock: socket.socket) -> tuple[int, int, int]:
    return 4242, ME, GROUP


SOCKET_FOLDERS: list[Path] = []


def socket_path() -> Path:
    """A socket's path is short, or it cannot be made: not under pytest's own folders."""
    SOCKET_FOLDERS.append(Path(tempfile.mkdtemp(prefix="vn")))
    return SOCKET_FOLDERS[-1] / "web.sock"


@pytest.fixture(autouse=True)
def _remove_socket_folders() -> Iterator[None]:
    yield
    while SOCKET_FOLDERS:
        shutil.rmtree(SOCKET_FOLDERS.pop(), ignore_errors=True)


def domain_client(tmp_path: Path, *, logged_in: bool = True, **options: Any) -> TestClient:
    """The real app behind the domain, reached as the proxy reaches it (its ``Host``)."""
    from tests.webkit import new_app

    new_box(tmp_path).append("file", "create", "secret-plans.md")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        client = TestClient(new_app(tmp_path, origin=ORIGIN, **options), base_url=URL)
    if logged_in:
        client.cookies.set(DOMAIN_COOKIE_NAME, SESSION, domain=DOMAIN, path="/")
    return client


@pytest.fixture
def domain(tmp_path: Path) -> TestClient:
    return domain_client(tmp_path)


# -- Host and Origin: that list and nothing else -------------------------------------------------


def test_the_list_behind_a_domain_is_its_host_alone() -> None:
    assert allowed_hosts(PORT, ORIGIN) == {DOMAIN}
    assert allowed_hosts(PORT, parse_public_origin(f"{URL}:8443")) == {f"{DOMAIN}:8443"}


def test_the_domain_answers_its_own_host(domain: TestClient) -> None:
    """The control: everything below is refused for its reason, not because nothing works."""
    assert domain.get("/panel").status_code == 200
    assert domain.get("/panel", headers={"host": DOMAIN.upper()}).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        f"evil.example:{PORT}",
        f"{DOMAIN}.evil.example",
        f"evil.{DOMAIN}",
        f"{DOMAIN}:8443",  # another port of the same name is another origin
        f"{DOMAIN}:443",  # not the form a browser sends
        f"127.0.0.1:{PORT}",  # a proxy that passes on any name must not make a request "local"
        f"backtide.localhost:{PORT}",
        f"[::1]:{PORT}",
        "localhost",
        "",
    ],
)
def test_a_host_of_elsewhere_is_refused(domain: TestClient, host: str) -> None:
    response = domain.get("/panel", headers={"host": host})
    assert (response.status_code, response.text) == (400, "Host not allowed")
    assert "secret-plans" not in response.text


def test_two_hosts_are_refused(tmp_path: Path) -> None:
    from backtide.web.security import Guard

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        raise AssertionError("the app was reached")

    guard = Guard(inner, port=PORT, prefix=PREFIX, origin=ORIGIN)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"host", DOMAIN.encode()), (b"host", b"evil.example")],
    }
    assert guard._refusal(scope) == (400, "Host not allowed", [])  # noqa: SLF001


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        f"http://{DOMAIN}",  # the same name without https is another origin
        f"https://{DOMAIN}:8443",
        f"https://{DOMAIN}.evil.example",
        f"http://127.0.0.1:{PORT}",
        f"http://backtide.localhost:{PORT}",
        "null",
    ],
)
def test_an_origin_of_elsewhere_changes_nothing(domain: TestClient, origin: str) -> None:
    response = domain.post(
        "/salir", data={"csrf": "x"}, headers={**POST, "origin": origin}, follow_redirects=False
    )
    assert (response.status_code, response.text) == (403, "A change needs our own Origin")
    read = domain.get("/panel", headers={"origin": origin})
    assert (read.status_code, read.text) == (403, "Origin not allowed")


def test_a_post_with_our_origin_goes_through_the_guard(domain: TestClient) -> None:
    """The control of the one above: the form is what stops this one, further in."""
    response = domain.post("/salir", data={"csrf": "x"}, headers=POST, follow_redirects=False)
    assert (response.status_code, response.text) == (403, "Formulario de otra sesión")


@pytest.mark.parametrize(
    "headers",
    [
        {"x-forwarded-host": DOMAIN, "host": "evil.example"},
        {"x-forwarded-proto": "https", "host": f"127.0.0.1:{PORT}"},
        {"forwarded": f"host={DOMAIN};proto=https", "host": "evil.example"},
    ],
)
def test_the_proxys_headers_are_not_believed(domain: TestClient, headers: dict[str, str]) -> None:
    response = domain.get("/panel", headers=headers)
    assert (response.status_code, response.text) == (400, "Host not allowed")


def test_a_forwarded_address_opens_nothing(tmp_path: Path) -> None:
    """Nothing is limited or let in by address, so there is nothing to say "I am local" to."""
    client = domain_client(tmp_path, logged_in=False)
    response = client.get("/panel", headers={"x-forwarded-for": "127.0.0.1"})
    assert response.status_code == 401


def test_every_refusal_carries_the_security_headers(domain: TestClient) -> None:
    response = domain.get("/panel", headers={"host": "evil.example"})
    for name, value in SECURITY_HEADERS:
        assert response.headers[name.decode()] == value.decode()


# -- the fixed prefix ----------------------------------------------------------------------------


def test_the_web_lives_at_the_root(domain: TestClient) -> None:
    page = domain.get("/panel")
    assert page.status_code == 200
    assert 'href="/static/web.css"' in page.text and 'href="/peticiones"' in page.text
    assert PREFIX_PATH not in page.text and "/s/" not in page.text
    assert domain.get("/static/web.css").status_code == 200
    assert domain.get(f"{PREFIX_PATH}/panel").status_code == 404  # the tunnel's prefix is no door


def test_without_a_session_nothing_is_shown_at_the_root(tmp_path: Path) -> None:
    """The prefix is no secret here: every page has to stand on the session alone."""
    client = domain_client(tmp_path, logged_in=False)
    pages = ["/", "/panel", "/ahora", "/historia", "/instantaneas", "/peticiones", "/ajustes",
             "/llaves", "/tocar", "/ahora/stream", "/panel/stream", "/ahora/preguntar?q=x",
             "/agentes/principal/ahora"]  # fmt: skip
    for page in pages:
        response = client.get(page)
        assert response.status_code == 401, page
        assert "secret-plans" not in response.text, page


def test_every_route_of_the_app_asks_for_a_session(tmp_path: Path) -> None:
    """Not a list that can fall behind: the app's own routes, each without a cookie. What may
    answer: the way in (a POST with no session yet), and the static files."""
    app = domain_client(tmp_path, logged_in=False).app
    routes = [r for r in app.inner.routes if hasattr(r, "methods")]
    assert len(routes) > 10
    client = domain_client(tmp_path, logged_in=False)
    way_in = {"/entrar/llave/empezar", "/entrar/llave/responder"}
    for route in routes:
        path = route.path.replace("{slug}", "principal")
        if "GET" in route.methods:
            assert client.get(path).status_code == 401, path
        elif path not in way_in and "POST" in route.methods:
            response = client.post(path, data={"csrf": "x"}, headers=POST, follow_redirects=False)
            assert response.status_code in (401, 405), path


# -- the cookie ----------------------------------------------------------------------------------


def test_the_cookie_is_the_secure_one(tmp_path: Path) -> None:
    client = domain_client(tmp_path, logged_in=False)
    response = client.get(f"/panel?t={TOKEN}")
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{DOMAIN_COOKIE_NAME}=")
    parts = {part.strip().lower() for part in cookie.split(";")[1:]}
    assert {"secure", "httponly", "samesite=strict", "path=/"} <= parts
    assert TOKEN not in cookie


def test_the_plain_cookie_is_no_way_in(tmp_path: Path) -> None:
    """http can set a plain cookie, and only https a ``__Host-`` one."""
    client = domain_client(tmp_path, logged_in=False)
    plain = client.get("/panel", headers={"cookie": f"{COOKIE_NAME}={SESSION}"})
    assert plain.status_code == 401
    good = client.get("/panel", headers={"cookie": f"{DOMAIN_COOKIE_NAME}={SESSION}"})
    assert good.status_code == 200


def test_signing_out_takes_the_secure_cookie_away(tmp_path: Path) -> None:
    class Inside:
        def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session:
            return Session(SESSION, "c" * 43)

        def end(self, session_id: str, *, every: bool = False) -> bool:
            return True

    domain = domain_client(tmp_path, access=Inside())
    response = domain.post("/salir", data={"csrf": "c" * 43}, headers=POST, follow_redirects=False)
    assert (response.status_code, response.headers["location"]) == (303, "/")
    cookie = response.headers["set-cookie"]
    # A browser only takes this away from a response that says Secure too.
    assert cookie.startswith(f"{DOMAIN_COOKIE_NAME}=") and "max-age=0" in cookie.lower()
    assert "secure" in cookie.lower() and "path=/" in cookie.lower()


def test_the_language_cookie_is_secure_too(domain: TestClient) -> None:
    cookie = domain.get("/panel?lang=en").headers["set-cookie"].lower()
    assert "secure" in cookie and "path=/" in cookie


# -- `/entrar`: there is no password through the domain (D40) ------------------------------------


class Installed:
    """The service as the installed web asks it, counting what it was asked."""

    passwords = True

    def __init__(self) -> None:
        self.tried: list[str] = []

    def open(self, token: str) -> Session | None:
        return Session("a-new-one", "c" * 43) if token == TOKEN else None

    def sign_in(self, password_: str) -> tuple[Session | None, str]:
        self.tried.append(password_)
        return Session("a-new-one", "c" * 43), "opened"

    def auth(self, command: str, **fields: str) -> dict[str, Any]:
        return {"ok": False, "outcome": "refused", "message": "aún no hay ninguna llave registrada"}

    def passkey(self, command: str, session_id: str, **fields: str) -> dict[str, Any]:
        return {"ok": True, "keys": []}

    def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
        return None

    def end(self, session_id: str, *, every: bool = False) -> bool | None:
        return True


def test_a_password_through_the_domain_finds_no_door(tmp_path: Path) -> None:
    access = Installed()
    client = domain_client(tmp_path, logged_in=False, access=access)
    response = client.post("/entrar", data={"password": RIGHT_PASSWORD}, headers=POST)
    assert (response.status_code, response.text) == (405, "Read-only")
    assert access.tried == []
    assert "set-cookie" not in response.headers
    assert RIGHT_PASSWORD not in response.text


def test_the_app_itself_has_no_such_path(tmp_path: Path) -> None:
    """The second wall: if the Guard let it pass, there is still nothing there."""
    app = domain_client(tmp_path, logged_in=False, access=Installed()).app
    assert "/entrar" not in {getattr(route, "path", "") for route in app.inner.routes}


def test_the_way_in_is_the_key_and_no_password_field(tmp_path: Path) -> None:
    client = domain_client(tmp_path, logged_in=False, access=Installed())
    page = client.get("/")
    assert page.status_code == 401
    assert 'type="password"' not in page.text and '/entrar"' not in page.text
    assert 'id="webauthn-go"' in page.text and "webauthn-get.js" in page.text
    assert 'data-begin="/entrar/llave/empezar"' in page.text
    assert "sudo backtide enlace" in page.text


def test_the_tunnels_way_in_stays_as_it_was(tmp_path: Path) -> None:
    """Without ``public_origin``, the password form and its POST are there."""
    new_box(tmp_path)
    access = Installed()
    client = new_client(tmp_path, logged_in=False, access=access)
    assert 'type="password"' in client.get("/").text
    client.post(
        "/entrar",
        data={"password": RIGHT_PASSWORD},
        headers={"origin": f"http://127.0.0.1:{PORT}", "sec-fetch-site": "same-origin"},
    )
    assert access.tried == [RIGHT_PASSWORD]


def test_the_link_goes_straight_to_the_first_key(tmp_path: Path) -> None:
    """The link is how the first key of a domain gets registered: no password there (D40)."""
    client = domain_client(tmp_path, logged_in=False, access=Installed())
    response = client.get(f"/panel?t={TOKEN}")
    assert response.status_code == 200 and "/llaves?nueva=1" in response.text
    assert response.headers["set-cookie"].startswith(f"{DOMAIN_COOKIE_NAME}=")


def test_a_wrong_link_says_how_to_get_another(tmp_path: Path) -> None:
    client = domain_client(tmp_path, logged_in=False, access=Installed())
    response = client.get("/panel?t=made-up")
    assert response.status_code == 401
    assert "ya no vale" in response.text or "no longer works" in response.text
    assert "sudo backtide enlace" in response.text


# -- without `public_origin`, all as today -------------------------------------------------------


def test_without_a_public_origin_everything_is_as_it_was(tmp_path: Path) -> None:
    new_box(tmp_path)
    client = new_client(tmp_path, logged_in=False)
    assert allowed_hosts(PORT) == {f"127.0.0.1:{PORT}", f"backtide.localhost:{PORT}"}
    # The random prefix, and nothing outside it.
    assert client.get(f"http://127.0.0.1:{PORT}/panel").status_code == 404
    # Its two names, and no other: the domain is not one of them.
    assert client.get("/panel").status_code == 401
    assert client.get("/panel", headers={"host": f"backtide.localhost:{PORT}"}).status_code == 401
    refused = client.get("/panel", headers={"host": DOMAIN})
    assert (refused.status_code, refused.text) == (400, "Host not allowed")
    # The plain cookie, on the prefix, with neither Secure nor the prefix of the name.
    cookie = client.get(f"/panel?t={TOKEN}").headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert f"path={PREFIX_PATH}" in cookie.lower() and "secure" not in cookie.lower()
    # An Origin of that name's own.
    post = {"origin": URL, "sec-fetch-site": "same-origin"}
    rejected = client.post("/salir", data={"csrf": "x"}, headers=post)
    assert (rejected.status_code, rejected.text) == (403, "A change needs our own Origin")


def test_a_secure_cookie_opens_nothing_on_the_tunnel(tmp_path: Path) -> None:
    new_box(tmp_path)
    client = new_client(tmp_path, logged_in=False)
    cookie = {"cookie": f"{DOMAIN_COOKIE_NAME}={SESSION}"}
    assert client.get("/panel", headers=cookie).status_code == 401


def test_the_service_without_a_public_origin_keeps_the_tunnels_keys(tmp_path: Path) -> None:
    class Config:
        state_dir = tmp_path

        def web_public_origin(self) -> None:
            return None

    keys = web_passkeys_of(Config())  # type: ignore[arg-type]
    assert not keys.on_a_domain
    assert path_of(tmp_path).name == "passkeys.json"
    owner = SoftAuthenticator()
    keys.finish("s", owner.create(keys.begin("s"), origin_for(8765)), "portátil")
    assert path_of(tmp_path).exists()


# -- the passkey of that domain ------------------------------------------------------------------


@pytest.fixture
def domain_keys(tmp_path: Path) -> Passkeys:
    class Config:
        state_dir = tmp_path

        def web_public_origin(self) -> Any:
            return ORIGIN

    state = tmp_path
    (state / "web-auth").mkdir(mode=0o700)
    return web_passkeys_of(Config())  # type: ignore[arg-type]


def test_a_key_of_the_domain_is_for_the_domain(domain_keys: Passkeys, tmp_path: Path) -> None:
    assert domain_keys.on_a_domain
    options = json.loads(domain_keys.begin("s"))
    assert options["rp"]["id"] == DOMAIN
    owner = SoftAuthenticator()
    domain_keys.finish("s", owner.create(json.dumps(options), URL, rp_id=DOMAIN), "portátil")
    # The control: that key signs in through the domain.
    answer = owner.get(domain_keys.sign_in_begin(), URL, rp_id=DOMAIN)
    assert domain_keys.sign_in(answer).name == "portátil"
    assert path_of(tmp_path, DOMAIN).exists() and not path_of(tmp_path).exists()


@pytest.mark.parametrize(
    ("at", "rp_id"),
    [
        (f"http://{DOMAIN}", DOMAIN),  # the same name without https
        (f"https://{DOMAIN}:8443", DOMAIN),  # another port
        ("https://evil.example", DOMAIN),
        (origin_for(8765), DOMAIN),  # the tunnel's own origin
        (URL, "backtide.localhost"),  # a key of the tunnel's name
        (URL, "evil.example"),
    ],
)
def test_a_signature_for_anywhere_else_does_not_enter(
    domain_keys: Passkeys, at: str, rp_id: str
) -> None:
    from backtide.service.passkeys import PasskeyError

    owner = SoftAuthenticator()
    begun = domain_keys.begin("s")
    domain_keys.finish("s", owner.create(begun, URL, rp_id=DOMAIN), "portátil")
    with pytest.raises(PasskeyError, match="firma válida"):
        domain_keys.sign_in(owner.get(domain_keys.sign_in_begin(), at, rp_id=rp_id))


def test_the_keys_of_the_tunnel_stay_out_of_the_way(tmp_path: Path) -> None:
    """Otherwise the domain would ask to touch a key no browser there can touch, for good."""
    tunnel = Passkeys(tmp_path, origins=[origin_for(8765)])
    tunnel.finish("s", SoftAuthenticator().create(tunnel.begin("s"), origin_for(8765)), "viejo")
    behind = Passkeys(tmp_path, origins=[URL], rp_id=DOMAIN)
    assert behind.keys() == []
    behind.finish("s", SoftAuthenticator().create(behind.begin("s"), URL, rp_id=DOMAIN), "nuevo")
    assert [k.name for k in behind.keys()] == ["nuevo"]
    assert [k.name for k in tunnel.keys()] == ["viejo"]  # and back, if the domain goes away


# -- what the service does behind a domain -------------------------------------------------------


@pytest.fixture
def behind(tmp_path: Path) -> Iterator[tuple[WebControlServer, Sessions]]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    sessions = Sessions()
    sessions.preset(SESSION)
    server = WebControlServer(
        FakeGuardian(),
        socket_path(),
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: True,
        passkeys=Passkeys(state, origins=[URL], rp_id=DOMAIN),
        password=None,  # what the runner gives it behind a domain
    )
    server.start()
    yield server, sessions
    server.close()


def test_the_service_takes_no_password_there_either(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    """A web taken over has the socket, not the page: the wall is at the service too."""
    server, sessions = behind
    before = len(sessions)
    reply = talk(server, {"cmd": "session_password", "password": RIGHT_PASSWORD})
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert "contraseña" in reply["message"] and len(sessions) == before


def test_the_runner_gives_the_narrow_socket_no_password_behind_a_domain() -> None:
    """Read in the wiring: the narrow socket's checker is the one this line decides."""
    import inspect

    from backtide.service import runner

    source = inspect.getsource(runner.serve)
    assert "web_checks = None if config.web_public_origin() is not None else web_password" in source
    server_call = source[source.index("WebControlServer(") :]
    assert "password=web_checks" in server_call[: server_call.index("),")]


def test_with_a_password_the_control_of_that_wall_gets_in(tmp_path: Path) -> None:
    """The same socket with a checker: it is the checker's absence that refuses above."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    password.write(state, RIGHT_PASSWORD)
    server = WebControlServer(
        FakeGuardian(),
        socket_path(),
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=Sessions(),
        on_entry=lambda action, details: True,
        password=password.Checker(state),
    )
    server.start()
    try:
        reply = talk(server, {"cmd": "session_password", "password": RIGHT_PASSWORD})
    finally:
        server.close()
    assert reply["outcome"] == "opened"


def test_behind_a_domain_what_lasts_asks_for_a_key_even_with_none_yet(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    """D40: through the domain it takes a passkey. A session of root's link has the first key
    to register; a provider's key or Telegram wait for it."""
    server, _ = behind
    change = {
        "cmd": "set_secret",
        "kind": "telegram",
        "value": "x",
        "via": "web",
        "session": SESSION,
    }
    assert "tocar tu llave" in talk(server, change)["message"]
    closing = {"cmd": "session_end_all", "session": SESSION}
    assert "tocar tu llave" in talk(server, closing)["message"]


def test_the_first_key_can_still_be_registered_with_roots_link(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    server, _ = behind
    begun = talk(server, {"cmd": "passkey_begin", "session": SESSION})
    assert begun["ok"] is True and json.loads(begun["options"])["rp"]["id"] == DOMAIN
    answer = SoftAuthenticator().create(begun["options"], URL, rp_id=DOMAIN)
    done = talk(
        server, {"cmd": "passkey_finish", "session": SESSION, "answer": answer, "name": "m"}
    )
    assert done["outcome"] == "added"


# -- root's link behind a domain: for the first key, and no more (D40, review of T26-4a) ---------


def behind_with_a_key(behind: tuple[WebControlServer, Sessions]) -> Passkeys:
    server, _ = behind
    keys = server._passkeys  # noqa: SLF001
    assert keys is not None
    keys.finish("s", SoftAuthenticator().create(keys.begin("s"), URL, rp_id=DOMAIN), "portátil")
    return keys


def test_without_keys_roots_link_opens_a_session(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    """The control of the two below: nothing else can register the first key."""
    server, sessions = behind
    reply = talk(server, {"cmd": "session_open", "token": sessions.new_link()})
    assert reply["outcome"] == "opened"


def test_with_a_key_even_a_right_link_opens_nothing(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    server, sessions = behind
    token = sessions.new_link()  # given before the key was registered
    keys = behind_with_a_key(behind)
    before = len(sessions)
    reply = talk(server, {"cmd": "session_open", "token": token})
    assert (reply["ok"], reply["outcome"]) == (False, "refused")
    assert "llaves --quitar" in reply["message"] and len(sessions) == before
    # The way back: with the key taken out, that same link, which it did not spend, works.
    assert keys.remove(keys.keys()[0].id)
    assert talk(server, {"cmd": "session_open", "token": token})["outcome"] == "opened"


def test_with_a_keys_file_that_cannot_be_read_the_link_is_closed(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    server, sessions = behind
    keys = behind_with_a_key(behind)
    path_of(keys._state_dir, DOMAIN).chmod(0o644)  # noqa: SLF001 - not ours any more
    reply = talk(server, {"cmd": "session_open", "token": sessions.new_link()})
    assert reply["outcome"] == "refused" and "llaves --quitar" in reply["message"]


def make_control(keys: Passkeys, sessions: Sessions) -> ControlServer:
    server = ControlServer(
        FakeGuardian(),
        socket_path(),
        peer=lambda sock: (4242, ME, GROUP),
        sessions=sessions,
        on_entry=lambda action, details: True,
        passkeys=keys,
    )
    server.start()
    return server


def test_root_is_given_no_link_with_a_key_and_is_told_the_way_back(
    behind: tuple[WebControlServer, Sessions],
) -> None:
    _, sessions = behind
    keys = behind_with_a_key(behind)
    control = make_control(keys, sessions)
    try:
        with pytest.raises(ControlError, match="llaves --quitar"):
            ask_web_link(control.path, peer=the_web)
        assert keys.remove(keys.keys()[0].id)
        assert ask_web_link(control.path, peer=the_web)
    finally:
        control.close()


def test_on_the_tunnel_the_link_works_with_keys_as_before(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    keys = Passkeys(state, origins=[origin_for(8765)])
    keys.finish("s", SoftAuthenticator().create(keys.begin("s"), origin_for(8765)), "portátil")
    sessions = Sessions()
    control = make_control(keys, sessions)
    try:
        token = ask_web_link(control.path, peer=the_web)
    finally:
        control.close()
    server = WebControlServer(
        FakeGuardian(),
        socket_path(),
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: True,
        passkeys=keys,
    )
    server.start()
    try:
        assert talk(server, {"cmd": "session_open", "token": token})["outcome"] == "opened"
    finally:
        server.close()


def test_the_footer_says_the_domain_and_not_this_computer(domain: TestClient) -> None:
    page = domain.get("/panel?lang=es").text
    assert f"<span>{DOMAIN}</span>" in page and "Solo en este ordenador" not in page


def test_the_tunnels_footer_stays(tmp_path: Path) -> None:
    new_box(tmp_path)
    assert "Solo en este ordenador" in new_client(tmp_path).get("/panel?lang=es").text


# -- made-up cookies: a live session never pays for them (review of T26-3c) ----------------------


def make_narrow(tmp_path: Path, **options: Any) -> tuple[WebControlServer, Sessions]:
    sessions = Sessions()
    sessions.preset(SESSION)
    server = WebControlServer(
        FakeGuardian(),
        socket_path(),
        group=GROUP,
        snapshots=list,
        peer=the_web,
        sessions=sessions,
        on_entry=lambda action, details: True,
        **options,
    )
    server.start()
    return server, sessions


def test_made_up_cookies_empty_their_own_bucket_only(tmp_path: Path) -> None:
    server, _ = make_narrow(tmp_path, made_up=Bucket(3, 1e-6), checks=Bucket(5, 1e-6))
    try:
        made_up = [talk(server, {"cmd": "session_check", "session": f"m{i}"}) for i in range(5)]
        assert [r["outcome"] for r in made_up] == ["expired", "expired", "expired", "busy", "busy"]
        # A session that lives has lost nothing, after all of that.
        live = [talk(server, {"cmd": "session_check", "session": SESSION}) for _ in range(5)]
        assert [r["outcome"] for r in live] == ["live"] * 5
        # Its own bucket is there still: past it, busy, and never "expired".
        past = talk(server, {"cmd": "session_check", "session": SESSION})
        assert past["outcome"] == "busy" and past["ok"] is False
    finally:
        server.close()


def web_on(server: WebControlServer, tmp_path: Path, **options: Any) -> TestClient:
    new_box(tmp_path)
    return new_client(
        tmp_path,
        access=ServiceAccess(server.path, server_uid=ME, wait=0, peer=the_web),
        **options,
    )


def test_a_flood_of_made_up_cookies_leaves_the_owner_inside(tmp_path: Path) -> None:
    server, _ = make_narrow(tmp_path, made_up=Bucket(2, 1e-6))
    try:
        web = web_on(server, tmp_path, logged_in=False)
        flood = [web.get("/panel", headers={"cookie": f"{COOKIE_NAME}=made-up-{i}"})
                 for i in range(4)]  # fmt: skip
        assert [r.status_code for r in flood] == [401, 401, 503, 503]
        owner = web.get("/panel", headers={"cookie": f"{COOKIE_NAME}={SESSION}"})
        assert owner.status_code == 200
    finally:
        server.close()


def test_a_refusal_by_the_cap_is_a_503_with_the_way_in(tmp_path: Path) -> None:
    server, _ = make_narrow(tmp_path, checks=Bucket(0, 1e-6))
    try:
        response = web_on(server, tmp_path).get("/panel")
    finally:
        server.close()
    assert response.status_code == 503 and response.headers["retry-after"] == "5"
    assert "set-cookie" not in response.headers
    assert "demasiadas peticiones" in response.text or "too many requests" in response.text
    assert "secret-plans" not in response.text


def test_too_many_connections_is_a_503_too_and_not_nobody(tmp_path: Path) -> None:
    """The service's own "too many connections" is one more refusal: it says nothing of a
    session, which may be alive."""
    server, _ = make_narrow(tmp_path)
    try:
        web = web_on(server, tmp_path)
        server._max_connections = 0  # noqa: SLF001
        response = web.get("/panel")
    finally:
        server.close()
    assert response.status_code == 503


def test_a_service_that_cannot_be_asked_is_nobody_as_before(tmp_path: Path) -> None:
    new_box(tmp_path)
    web = new_client(
        tmp_path,
        access=ServiceAccess(tmp_path / "no.sock", server_uid=ME, wait=0, peer=the_web),
    )
    assert web.get("/panel").status_code == 401


def test_one_cookie_past_the_cap_does_not_hide_a_live_one(tmp_path: Path) -> None:
    server, _ = make_narrow(tmp_path, made_up=Bucket(0, 1e-6))
    try:
        access = ServiceAccess(server.path, server_uid=ME, wait=0, peer=the_web)
        header = f"{COOKIE_NAME}=old-one; {COOKIE_NAME}={SESSION}"
        found = access.session_of(header)
        assert found is not None and found.id == SESSION
        with pytest.raises(SessionsBusy):
            access.session_of(f"{COOKIE_NAME}=old-one")
    finally:
        server.close()


def test_with_an_old_cookie_the_link_still_gets_in_during_a_flood(tmp_path: Path) -> None:
    server, sessions = make_narrow(tmp_path, made_up=Bucket(0, 1e-6))
    try:
        web = web_on(server, tmp_path, logged_in=False)
        token = sessions.new_link()
        old = {"cookie": f"{COOKIE_NAME}=an-old-one"}
        assert web.get("/panel", headers=old).status_code == 503
        response = web.get(f"/panel?t={token}", headers=old)
        assert response.status_code == 200 and "set-cookie" in response.headers
    finally:
        server.close()


def test_the_right_link_goes_through_a_stream_of_wrong_ones(tmp_path: Path) -> None:
    """Behind a domain anyone can send made-up links, and root's is the way back in."""
    server, sessions = make_narrow(tmp_path, opens=Bucket(2, 1e-6))
    try:
        wrong = [talk(server, {"cmd": "session_open", "token": f"t{i}"}) for i in range(4)]
        assert [r["outcome"] for r in wrong] == ["refused"] * 4
        assert "Demasiadas" in wrong[3]["message"] and "ya no vale" in wrong[0]["message"]
        right = talk(server, {"cmd": "session_open", "token": sessions.new_link()})
        assert right["outcome"] == "opened"
    finally:
        server.close()


def test_a_flood_never_takes_every_connection(tmp_path: Path) -> None:
    """Checks wait in line for a share of the connections: the rest stay for the clicks, and
    nobody meets the service's "too many connections" because of a stream of cookies."""
    server, _ = make_narrow(tmp_path)
    peak = [0]
    inside = [0]
    lock = threading.Lock()
    release = threading.Event()
    access = ServiceAccess(server.path, server_uid=ME, wait=5, peer=the_web)

    from backtide.web import security

    real = security.ask_session_check

    def counted(*args: Any, **kwargs: Any) -> Any:
        with lock:
            inside[0] += 1
            peak[0] = max(peak[0], inside[0])
            if inside[0] >= CHECKS_AT_ONCE:
                release.set()
        release.wait(5)
        try:
            return real(*args, **kwargs)
        finally:
            with lock:
                inside[0] -= 1

    security.ask_session_check = counted
    try:
        threads = [
            threading.Thread(target=access.session_of, args=(f"{COOKIE_NAME}=m{i}",))
            for i in range(CHECKS_AT_ONCE * 4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        security.ask_session_check = real
        server.close()
    assert peak[0] == CHECKS_AT_ONCE


def test_an_open_stream_ends_when_its_session_cannot_be_known(tmp_path: Path) -> None:
    class Busy(Installed):
        def __init__(self) -> None:
            super().__init__()
            self.asked = 0

        def session_of(self, cookie_header: str | None, *, use: bool = True) -> Session | None:
            self.asked += 1
            if self.asked == 1:
                return Session(SESSION, "c" * 43)
            raise SessionsBusy

    new_box(tmp_path)
    web = new_client(
        tmp_path, access=Busy(), stream_seconds=30, poll_interval=0.02, session_recheck=0.05
    )
    assert "event: session\ndata: expired" in web.get("/ahora/stream").text
