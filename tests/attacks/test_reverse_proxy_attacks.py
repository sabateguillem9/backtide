"""T26-4b (invariant 7): the web behind a real nginx, with the file a person copies, unchanged.

``deploy/reverse-proxy/backtide.nginx.conf`` runs in a container of the VM on the host's network
(``tests/reverse_proxy_kit.py``), with HTTPS from a CA made for the occasion and ``[web]
public_origin`` on the real installation, restored at the end. Each loopback address (127.0.0.0/8)
is a different visitor to nginx, so "one address" and "many" are real, and nothing leaves the VM.

The scenarios that reach the web by HTTP run here again through the proxy: `entrar-sin-llave` and
`cookies-inventadas`. What `web-en-un-dominio` checks by HTTP runs in `web-tras-el-proxy`. The other
scenarios of the web talk to its narrow socket, and no proxy stands in that way.

Like tests/attacks/test_install_attacks.py, it never runs in vigia-dev nor on the Mac
(``instalada``). In a clean VM, after `install.sh`, as root:

    sudo uv run --locked pytest -m ataques -p no:cacheprovider \\
        tests/attacks/test_reverse_proxy_attacks.py
"""

import itertools
import json
import pwd
import re
import secrets
import shutil
import socket
import ssl
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException, RemoteDisconnected
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from attack_kit import Attack, scenario
from test_install_attacks import Installed, open_installed, sh, wait
from test_web_attacks import host_addresses
from test_web_socket_attacks import (
    CHANGES_WAIT,
    CONTROL_SOCKET,
    KEYS_WAIT,
    WEB_SOCKET,
    no_way_in,
    order_form,
    probe_as,
    restart_service,
    web_says_domain,
)

from backtide.service import passkeys as pk
from backtide.service.control import ask_web_end_all, ask_web_link
from backtide.setup import layout
from backtide.web.security import DOMAIN_COOKIE_NAME
from tests import reverse_proxy_kit as kit
from tests.passkey_kit import SoftAuthenticator

pytestmark = pytest.mark.instalada

DOMAIN, DOMAIN_URL = kit.DOMAIN, kit.DOMAIN_URL
KEYS_FILE = pk.path_of(layout.STATE_DIR, DOMAIN)
OWNER = "127.0.0.3"  # the owner's address; a flood comes from others
SIGN_IN_BEGIN, SIGN_IN_ANSWER = "/entrar/llave/empezar", "/entrar/llave/responder"
BEGINS_WAIT = 31  # the sign-in's first step: 10 at once, then one every 3 s
ANSWERS_WAIT = 61  # and its answers: 10 at once, then one every 6 s
HSTS = "max-age=31536000"
CANARY = "canaria" + secrets.token_hex(8)  # a token's place in a request; found nowhere afterwards
BODY_TIMEOUT, HEAD_TIMEOUT = 10, 10  # the file's client_body_timeout and client_header_timeout


@dataclass
class Domain:
    """The web on its domain, through the proxy."""

    proxy: kit.Proxy
    context: ssl.SSLContext
    _next: Iterator[int]

    def ask(self, method: str, where: str, **options: Any) -> kit.Reply:
        options.setdefault("source", OWNER)
        return kit.ask(self.context, method, where, **options)

    def visitor(self) -> str:
        """A loopback address nobody has come from yet in this run."""
        number = next(self._next)
        return f"127.50.{number >> 8 & 255}.{number & 255}"

    def cookie(self, reply: kit.Reply) -> str:
        """The session's cookie this reply gave."""
        return reply.header("set-cookie").partition(";")[0]


def direct(where: str, *, cookie: str | None = None, method: str = "GET", body: str | None = None):  # noqa: ANN201 - a kit.Reply
    """To the web itself on loopback, as if there were no proxy or it had no caps."""
    conn = HTTPConnection("127.0.0.1", pk.WEB_PORT, timeout=20)
    headers = {"Host": DOMAIN, "Origin": DOMAIN_URL}
    if cookie is not None:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, where, body=body, headers=headers)
        return kit.read_reply(conn)
    finally:
        conn.close()


@pytest.fixture(scope="module")
def installed() -> Iterator[Installed]:
    yield from open_installed()


@pytest.fixture(scope="module")
def domain(installed: Installed) -> Iterator[Domain]:
    service_toml, web_toml = layout.CONFIG_FILE.read_bytes(), layout.WEB_CONFIG_FILE.read_bytes()
    assert b"[web]" not in service_toml + web_toml, "the installation already has a [web] table"
    assert not KEYS_FILE.exists(), "a key of the domain is left from a run that was killed"
    table = f'\n[web]\npublic_origin = "{DOMAIN_URL}"\n'.encode()
    folder = Path(tempfile.mkdtemp(prefix="backtide-proxy-", dir="/var/tmp"))  # noqa: S108 - in the VM
    try:
        proxy = kit.start(folder)
        layout.CONFIG_FILE.write_bytes(service_toml + table)
        layout.WEB_CONFIG_FILE.write_bytes(web_toml + table)
        restart_service(installed)
        sh("systemctl", "restart", layout.WEB_UNIT, timeout=120)
        assert wait(web_says_domain, 60, interval=1), "the web did not come back on its domain"
        found = Domain(proxy, kit.trusting(proxy.ca), itertools.count(1))
        assert wait(lambda: found.ask("GET", "/").status == 401, 60, interval=1), (
            "the web does not answer through the proxy"
        )
        yield found
    finally:
        kit.stop()
        KEYS_FILE.unlink(missing_ok=True)
        layout.CONFIG_FILE.write_bytes(service_toml)
        layout.WEB_CONFIG_FILE.write_bytes(web_toml)
        try:
            restart_service(installed)
        finally:  # or the web stays on the domain, and the next scenarios fail for that
            sh("systemctl", "restart", layout.WEB_UNIT, timeout=120)
        shutil.rmtree(folder, ignore_errors=True)


def clean_slate() -> None:
    """No key of the domain and nobody signed in: each scenario starts where the first one did."""
    if KEYS_FILE.exists():
        for key in json.loads(KEYS_FILE.read_text())["keys"]:
            sh(str(layout.PROGRAM), "llaves", "--quitar", key["id"])
    ask_web_end_all(CONTROL_SOCKET)


def probe_web(*requests: dict) -> list[dict]:
    """The narrow socket, as the web's own user."""
    web = pwd.getpwnam(layout.WEB_USER)
    return probe_as(web.pw_uid, web.pw_gid, "", str(WEB_SOCKET), *requests)


def no_answer(call: Callable[[], Any]) -> bool:
    """nginx closed without a word (its ``return 444``)."""
    try:
        call()
    except RemoteDisconnected:
        return True
    return False


def handshake_refused(context: ssl.SSLContext, sni: str | None) -> str:
    """Why the handshake failed, or an empty string if it went through."""
    try:
        kit.ask(context, "GET", "/", sni=sni, source=OWNER)
    except ssl.SSLError as error:
        return str(error)
    return ""


def enlace() -> str:
    """Root's own command, as root runs it: the token of the link it prints."""
    given = sh(str(layout.PROGRAM), "enlace")
    found = re.search(rf"{re.escape(DOMAIN_URL)}/\?t=([A-Za-z0-9_-]+)", given.stdout)
    assert found is not None, "`backtide enlace` printed no link on the domain"
    return found[1]


def sign_in(domain: Domain, owner: SoftAuthenticator, source: str) -> tuple[kit.Reply, kit.Reply]:
    """What the sign-in page does, through the proxy from ``source``: its two POSTs. If the first
    is refused, the second is that same reply."""
    begun = domain.ask("POST", SIGN_IN_BEGIN, origin=DOMAIN_URL, body="", source=source)
    if begun.status != 200:
        return begun, begun
    signed = owner.get(json.loads(begun.text)["options"], DOMAIN_URL, rp_id=DOMAIN)
    finished = domain.ask(
        "POST", SIGN_IN_ANSWER, origin=DOMAIN_URL, body=urlencode({"answer": signed}), source=source
    )
    return begun, finished


def key_of_the_owner(owner: SoftAuthenticator) -> None:
    """The domain's first key, from a session of root's link, by the socket: for the scenarios
    whose point is not how it got there. Its session goes too."""
    opened = probe_web(
        {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_see": True}
    )[0]
    begun = probe_web({"cmd": "passkey_begin", "session": opened["session"], "_see": True})[0]
    assert begun.get("options"), f"no options to register a key: {begun}"
    answer = owner.create(begun["options"], DOMAIN_URL, rp_id=DOMAIN)
    added = probe_web(
        {"cmd": "passkey_finish", "session": opened["session"], "answer": answer, "name": "x"}
    )[0]
    assert added.get("outcome") == "added", added
    ask_web_end_all(CONTROL_SOCKET)


def half_sent(domain: Domain, count: int) -> list[kit.SNIConnection]:
    """Connections that said a POST would bring 2000 bytes and brought five, ten from an address
    (the file lets one address hold forty)."""
    head = (
        f"POST /salir HTTP/1.1\r\nHost: {DOMAIN}\r\nOrigin: {DOMAIN_URL}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 2000\r\n\r\ncsrf="
    ).encode()
    found = []
    for number in range(count):
        if number % 10 == 0:
            source = domain.visitor()
        conn = kit.SNIConnection(domain.context, source=source, timeout=30)
        conn.connect()
        assert conn.sock is not None
        conn.sock.sendall(head)
        found.append(conn)
    return found


def owner_kept_out(domain: Domain, owner: SoftAuthenticator) -> kit.Reply | None:
    """The refusal of the bucket, if the owner gets it. Three tries, right after a flood: the bucket
    gives one back every 3 s, and one of those can land between the flood and the owner."""
    for _ in range(3):
        begun, _ = sign_in(domain, owner, domain.visitor())
        if "Demasiados intentos" in begun.text:
            return begun
    return None


def seconds_until_closed(conn: kit.SNIConnection) -> float:
    start = time.monotonic()
    assert conn.sock is not None
    conn.sock.settimeout(30)
    while conn.sock.recv(4096):  # whatever it says last; what counts is that it hangs up
        pass
    return time.monotonic() - start


@scenario("web-tras-el-proxy")
def test_through_nginx_only_its_name_gets_in_and_no_token_stays_behind(
    attack: Attack, installed: Installed, domain: Domain
) -> None:
    """The way in, from the first link to a signature, and everything the guide says the proxy
    does, each with its control, on the running file."""
    clean_slate()
    time.sleep(ANSWERS_WAIT)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    results: dict[str, Any] = {}

    # What runs is the file a person copies, byte by byte.
    shown = kit.docker("exec", kit.CONTAINER, "nginx", "-T")
    results["el archivo"] = kit.CONFIG_FILE.read_text() in shown.stdout

    # HTTPS: only with the test's CA, only by its name.
    results["sin la CA"] = handshake_refused(ssl.create_default_context(), DOMAIN)
    no_name_check = kit.trusting(domain.proxy.ca)
    no_name_check.check_hostname = False
    results["otro nombre TLS"] = handshake_refused(no_name_check, "evil.example")
    results["sin nombre TLS"] = handshake_refused(no_name_check, None)
    anon = domain.ask("GET", "/")
    results["anónimo"] = (anon.status, anon.header("strict-transport-security"),
                          anon.header("server"))  # fmt: skip

    # Port 80: to https, and what the request carried stays behind.
    plain = kit.plain_http(f"/?t={CANARY}")
    results["puerto 80"] = (plain.status, plain.header("location"))
    results["puerto 80, otro nombre"] = no_answer(lambda: kit.plain_http("/", host="evil.example"))

    # Names: nginx closes for any other, whichever part of the request says it, and the web
    # refuses what nginx lets through by its own reason.
    results["Host ajeno"] = no_answer(lambda: domain.ask("GET", "/", host="evil.example"))
    results["Host dirección"] = no_answer(lambda: domain.ask("GET", "/", host="127.0.0.1"))
    results["Host en la línea"] = no_answer(lambda: domain.ask("GET", "https://evil.example/"))
    wrong_port = domain.ask("GET", "/", host=f"{DOMAIN}:8443")
    results["otro puerto"] = (wrong_port.status, wrong_port.text, wrong_port.header(
        "strict-transport-security"))  # fmt: skip
    mixed = domain.ask("GET", f"{DOMAIN_URL}/panel", host="evil.example")
    results["línea buena, Host ajeno"] = (mixed.status, mixed.text)
    results["mayúsculas"] = domain.ask("GET", "/", host=DOMAIN.upper()).status

    # The way in, by HTTPS as a browser takes it: root's link, the first key, out, a signature.
    token = enlace()
    link = domain.ask("GET", f"/?t={token}")
    cookie_line = link.header("set-cookie")
    cookie = domain.cookie(link)
    results["enlace"] = link.status
    keys_page = domain.ask("GET", "/llaves?nueva=1", cookie=cookie)
    csrf = re.search(r'data-csrf="([^"]+)"', keys_page.text)
    assert csrf is not None, f"no form to add a key on the page ({keys_page.status})"
    begun = domain.ask("POST", "/llaves/empezar", origin=DOMAIN_URL, cookie=cookie,
                       body=f"csrf={csrf[1]}")  # fmt: skip
    assert begun.status == 200, begun.text
    owner = SoftAuthenticator()
    answer = owner.create(json.loads(begun.text)["options"], DOMAIN_URL, rp_id=DOMAIN)
    added = domain.ask(
        "POST", "/llaves/registrar", origin=DOMAIN_URL, cookie=cookie,
        body=urlencode({"csrf": csrf[1], "answer": answer, "name": "portátil"}),
    )  # fmt: skip
    results["llave"] = (added.status, KEYS_FILE.exists())
    # A change from a page of ours gets through; the same one from elsewhere, not.
    foreign = domain.ask("POST", "/salir", origin="https://evil.example", cookie=cookie,
                         body=f"csrf={csrf[1]}")  # fmt: skip
    results["Origin ajeno"] = (foreign.status, foreign.text)
    results["dentro todavía"] = domain.ask("GET", "/panel", cookie=cookie).status
    out = domain.ask("POST", "/salir", origin=DOMAIN_URL, cookie=cookie, body=f"csrf={csrf[1]}")
    results["salir"] = (out.status, domain.ask("GET", "/panel", cookie=cookie).status)
    other_site = domain.ask("POST", SIGN_IN_BEGIN, origin=DOMAIN_URL, body="")
    signed = owner.get(json.loads(other_site.text)["options"], "https://evil.example", rp_id=DOMAIN)
    results["firma de otro sitio"] = domain.ask(
        "POST", SIGN_IN_ANSWER, origin=DOMAIN_URL, body=urlencode({"answer": signed})
    ).status
    _, finished = sign_in(domain, owner, OWNER)
    inside = domain.cookie(finished)
    results["firma buena"] = (finished.status, inside.startswith(f"{DOMAIN_COOKIE_NAME}="))
    results["panel"] = domain.ask("GET", "/panel", cookie=inside).status

    # What nobody asks for reaches nothing: X-Forwarded-* changes nothing either.
    results["X-Forwarded"] = domain.ask(
        "GET", "/panel",
        more={"X-Forwarded-Host": DOMAIN, "X-Forwarded-For": "127.0.0.1",
              "X-Forwarded-Proto": "https"},
    ).status  # fmt: skip

    # The live page: it keeps coming, event by event, instead of waiting for a buffer to fill.
    live = kit.SNIConnection(domain.context, source=OWNER, timeout=30)
    start = time.monotonic()
    live.request("GET", "/panel/stream", headers={"Host": DOMAIN, "Cookie": inside})
    stream = live.getresponse()
    chunks = [stream.read1(4000) for _ in range(5)]  # the panel's card comes every 5 s
    results["directo"] = (stream.status, all(chunks), time.monotonic() - start)
    live.close()

    # Slow clients: the control, without the proxy, that the web's connections are worth holding.
    idle = [socket.create_connection(("127.0.0.1", pk.WEB_PORT), timeout=20) for _ in range(70)]
    time.sleep(1)
    results["sin proxy, 70 quietas"] = direct("/panel", cookie=inside).status
    for sock in idle:
        sock.close()
    assert wait(lambda: direct("/panel", cookie=inside).status == 200, 30, interval=1), (
        "the web did not come back after the control"
    )
    # Through the proxy, more of them than that, and the owner does not notice.
    slow = half_sent(domain, 100)
    start = time.monotonic()
    results["con 100 a medias"] = (domain.ask("GET", "/panel", cookie=inside).status,
                                   time.monotonic() - start)  # fmt: skip
    half_head = kit.SNIConnection(domain.context, source=domain.visitor(), timeout=30)
    half_head.connect()
    assert half_head.sock is not None
    half_head.sock.sendall(b"GET /panel HTTP/1.1\r\nHost: ")
    results["cuerpo a medias"] = seconds_until_closed(slow[0])
    results["cabecera a medias"] = seconds_until_closed(half_head)
    for conn in (*slow, half_head):
        conn.close()
    big = domain.ask("POST", SIGN_IN_ANSWER, origin=DOMAIN_URL, body="a" * 20000,
                     source=domain.visitor())  # fmt: skip
    results["cuerpo enorme"] = (big.status, big.header("strict-transport-security"))

    # What must never stay behind: with the web up and with it down, where an error line would
    # quote the whole request, with the query string and the Referer.
    referer = {"Referer": f"{DOMAIN_URL}/?t={CANARY}"}
    results["otra página con ?t="] = domain.ask("GET", f"/panel?t={CANARY}", more=referer).status
    sh("systemctl", "stop", layout.WEB_UNIT, timeout=120)
    try:
        down = domain.ask("GET", f"/?t={CANARY}", more=referer)
    finally:
        sh("systemctl", "start", layout.WEB_UNIT, timeout=120)
    results["web parada"] = (down.status, down.header("strict-transport-security"))
    assert wait(lambda: domain.ask("GET", "/").status == 401, 60, interval=1), (
        "the web did not come back"
    )
    logged = domain.proxy.logged()
    access = (domain.proxy.logs / kit.ACCESS_LOG).read_text()
    results["en los registros"] = [word for word in (token, CANARY, "?t=", "t=") if word in logged]
    # The control: the log is alive, and has those very requests, without their query string.
    results["registro vivo"] = [line for line in ('"GET /" 401', '"GET /" 502', '"GET /" 301',
                                                  '"GET /panel" 401',
                                                  f'"POST {SIGN_IN_ANSWER}" 200')
                                if line not in access]  # fmt: skip

    # From the jail: the proxy listens on every address of the VM, and the agent has no way there.
    targets = host_addresses(installed)  # type: ignore[arg-type] # its jail and its config
    outcome = attack.run_script(
        installed.jail, "web_desde_la_carcel", "80,443", targets.proxy, *targets.addresses
    )
    results["desde la cárcel"] = (outcome["reached"], outcome["answers"],
                                  outcome["via_proxy_through"])  # fmt: skip
    events = installed.box.events(since_seq=since)

    ok = (
        results["el archivo"]
        and "CERTIFICATE_VERIFY_FAILED" in results["sin la CA"]
        and "UNRECOGNIZED_NAME" in results["otro nombre TLS"]
        and "UNRECOGNIZED_NAME" in results["sin nombre TLS"]
        and results["anónimo"] == (401, HSTS, "nginx")
        and results["puerto 80"] == (301, f"{DOMAIN_URL}/")
        and results["puerto 80, otro nombre"]
        and results["Host ajeno"]
        and results["Host dirección"]
        and results["Host en la línea"]
        and results["otro puerto"] == (400, "Host not allowed", HSTS)
        and results["línea buena, Host ajeno"] == (400, "Host not allowed")
        and results["mayúsculas"] == 401
        and results["enlace"] == 200
        and {"secure", "httponly", "samesite=strict", "path=/"}
        <= {part.strip().lower() for part in cookie_line.split(";")[1:]}
        and cookie.startswith(f"{DOMAIN_COOKIE_NAME}=")
        and results["llave"] == (200, True)
        and results["Origin ajeno"] == (403, "A change needs our own Origin")
        and results["dentro todavía"] == 200
        and results["salir"] == (303, 401)
        and results["firma de otro sitio"] == 400
        and results["firma buena"] == (200, True)
        and results["panel"] == 200
        and results["X-Forwarded"] == 401
        and results["directo"][:2] == (200, True)
        and results["directo"][2] < 30
        and results["sin proxy, 70 quietas"] == 503
        and results["con 100 a medias"][0] == 200
        and results["con 100 a medias"][1] < 5
        and BODY_TIMEOUT - 2 < results["cuerpo a medias"] < BODY_TIMEOUT + 5
        and HEAD_TIMEOUT - 2 < results["cabecera a medias"] < HEAD_TIMEOUT + 5
        and results["cuerpo enorme"] == (413, HSTS)
        and results["otra página con ?t="] == 401
        and results["web parada"] == (502, HSTS)
        and not results["en los registros"]
        and not results["registro vivo"]
        and results["desde la cárcel"] == ([], [], [])
    )
    attack.check("stopped", ok, f"lo que se ha visto por nginx: {results}")
    ways = sorted(str(e.details.get("via")) for e in events if e.action == "web_session_opened")
    attack.check(
        "recorded",
        "passkey" in ways and "password" not in ways,
        f"en la caja negra, las entradas por el dominio: {ways}",
    )


@scenario("entrar-sin-llave-por-el-proxy")
def test_no_way_in_without_a_session_through_nginx(
    attack: Attack, installed: Installed, domain: Domain
) -> None:
    """`entrar-sin-llave`, every page and order, by https://<domain>/ through nginx."""
    clean_slate()
    time.sleep(max(CHANGES_WAIT, KEYS_WAIT))

    def fetch(method: str, where: str, cookie: str | None = None, csrf: str = "x" * 43) -> int:
        return domain.ask(
            method,
            where,
            origin=DOMAIN_URL,
            cookie=None if cookie is None else f"{DOMAIN_COOKIE_NAME}={cookie}",
            body=order_form(where, csrf) if method == "POST" else None,
        ).status

    no_way_in(attack, fetch, KEYS_FILE)


@scenario("cookies-inventadas-por-el-proxy")
def test_made_up_cookies_through_nginx_do_not_throw_the_owner_out(
    attack: Attack, installed: Installed, domain: Domain
) -> None:
    """`cookies-inventadas`' flood from many addresses, so that the proxy's caps let it through to
    the service's: the owner stays in, and the word past the cap is a 503, never a 401."""
    clean_slate()
    opened = probe_web(
        {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_see": True}
    )[0]
    own = f"{DOMAIN_COOKIE_NAME}={opened['session']}"
    stop = threading.Event()
    lock = threading.Lock()
    flood_said: list[int] = []
    busy_said: list[kit.Reply] = []
    errors: list[str] = []

    def flooding() -> None:
        while not stop.is_set():  # each address stays under the file's cap for one address
            with lock:
                source = domain.visitor()
            conn = kit.SNIConnection(domain.context, source=source)
            try:
                for _ in range(100):
                    if stop.is_set():
                        return
                    forged = f"{DOMAIN_COOKIE_NAME}={secrets.token_urlsafe(32)}"
                    conn.request("GET", "/ahora", headers={"Host": DOMAIN, "Cookie": forged})
                    found = kit.read_reply(conn)
                    flood_said.append(found.status)
                    if found.status == 503:
                        busy_said.append(found)
            except (OSError, HTTPException) as error:  # or the flood ends here, and nobody knows
                errors.append(type(error).__name__)
                return
            finally:
                conn.close()

    threads = [threading.Thread(target=flooding) for _ in range(8)]
    for thread in threads:
        thread.start()
    owner_said: list[int] = []
    try:
        for _ in range(60):
            owner_said.append(domain.ask("GET", "/ahora", cookie=own).status)
            time.sleep(0.25)
    finally:
        stop.set()
        for thread in threads:
            thread.join()
    time.sleep(8)  # the control of the 401: one made-up cookie alone, with its bucket back
    alone = domain.ask(
        "GET", "/ahora", cookie=f"{DOMAIN_COOKIE_NAME}={'m' * 43}", source=domain.visitor()
    ).status
    # The same thing from one address: this one nginx stops, and the service never sees it.
    single = domain.visitor()
    conn = kit.SNIConnection(domain.context, source=single)
    single_said = []
    for _ in range(600):
        conn.request("GET", "/ahora", headers={"Host": DOMAIN, "Cookie": f"{DOMAIN_COOKIE_NAME}=x"})
        single_said.append(kit.read_reply(conn).status)
    conn.close()
    owner_after = domain.ask("GET", "/ahora", cookie=own).status
    ask_web_end_all(CONTROL_SOCKET)
    attack.check(
        "stopped",
        not errors
        and len(flood_said) >= 100
        and set(flood_said) <= {401, 503}
        and bool(busy_said)
        and {found.header("retry-after") for found in busy_said} == {"5"}
        and all('id="webauthn-go"' in found.text for found in busy_said)
        and owner_said.count(200) >= 57
        and 401 not in owner_said
        and alone == 401
        and 429 in single_said
        and owner_after == 200,
        f"desde muchas direcciones, {len(flood_said)} cookies inventadas: "
        f"{sorted(set(flood_said))} (errores de los hilos: {errors or 'ninguno'}; Retry-After de "
        f"los 503: {sorted({found.header('retry-after') for found in busy_said})}); el dueño a la "
        f"vez, {owner_said.count(200)} de {len(owner_said)} dentro y {owner_said.count(401)} con "
        f"401; una sola, sin avalancha: {alone}. Desde una sola dirección: "
        f"{sorted(set(single_said))}, {single_said.count(429)} de {len(single_said)} se quedan en "
        f"nginx, y el dueño, después: {owner_after}",
    )


@scenario("tope-por-direccion")
def test_one_address_cannot_lock_the_owner_out(
    attack: Attack, installed: Installed, domain: Domain
) -> None:
    """What the guide warns about, and what the file's cap does about it: without the cap a `curl`
    leaves the owner out; with it, not from one address. From many it still can, as the guide
    says: then it is SSH, and the way in comes back by itself when it stops."""
    clean_slate()
    owner = SoftAuthenticator()
    key_of_the_owner(owner)
    time.sleep(BEGINS_WAIT)

    # The control: nothing stands in front of the web. The bucket empties and the owner stays out.
    uncapped = [direct(SIGN_IN_BEGIN, method="POST", body="") for _ in range(40)]
    refused_directly = [r for r in uncapped if "Demasiados intentos" in r.text]
    locked_out = owner_kept_out(domain, owner)
    time.sleep(BEGINS_WAIT)

    # One address through nginx: both POSTs, far more than the buckets hold.
    attacker = domain.visitor()
    flood = []
    for _ in range(100):
        flood.append(domain.ask("POST", SIGN_IN_BEGIN, origin=DOMAIN_URL, body="", source=attacker))
        flood.append(
            domain.ask("POST", SIGN_IN_ANSWER, origin=DOMAIN_URL, body="answer=x", source=attacker)
        )
    let_through = [r for r in flood if r.status != 429]
    capped = [r for r in flood if r.status == 429]
    _, finished = sign_in(domain, owner, domain.visitor())
    cookie = domain.cookie(finished)
    inside = domain.ask("GET", "/panel", cookie=cookie).status
    still = domain.ask("POST", SIGN_IN_BEGIN, origin=DOMAIN_URL, body="", source=attacker).status
    ask_web_end_all(CONTROL_SOCKET)
    time.sleep(BEGINS_WAIT)

    # Many addresses: the cap goes by address, so these reach the service. The documented limit.
    spread = [
        domain.ask("POST", SIGN_IN_BEGIN, origin=DOMAIN_URL, body="", source=domain.visitor())
        for _ in range(40)
    ]
    refused_spread = [r for r in spread if "Demasiados intentos" in r.text]
    out_again = owner_kept_out(domain, owner)
    # SSH is not behind any of this.
    by_ssh = sh(str(layout.PROGRAM), "llaves", check=False).returncode
    time.sleep(BEGINS_WAIT)
    _, back_in = sign_in(domain, owner, domain.visitor())
    in_again = domain.ask("GET", "/panel", cookie=domain.cookie(back_in)).status
    ask_web_end_all(CONTROL_SOCKET)
    capped_headers = {r.header("strict-transport-security") for r in capped}
    attack.check(
        "stopped",
        bool(refused_directly)
        and locked_out is not None
        and len(capped) >= 190
        and len(let_through) <= 10
        and capped_headers == {HSTS}
        and finished.status == 200
        and inside == 200
        and still == 429
        and bool(refused_spread)
        and out_again is not None
        and by_ssh == 0
        and back_in.status == 200
        and in_again == 200,
        f"sin el tope, {len(uncapped)} peticiones: {len(refused_directly)} ya rechazadas por el "
        f"cubo, y el dueño fuera ({locked_out and locked_out.text[:70]}). Por nginx, desde "
        f"una dirección, {len(flood)} peticiones: {len(capped)} se quedan en 429 (con "
        f"{capped_headers}) y {len(let_through)} llegan a la web; el dueño, desde otra, entra "
        f"({finished.status}, panel {inside}) y esa dirección sigue topada ({still}). Desde "
        f"{len(spread)} direcciones, el límite que la guía dice: {len(refused_spread)} ya "
        f"rechazadas por el cubo y el dueño fuera ({out_again and out_again.text[:70]}), "
        f"`backtide llaves` por SSH sale con {by_ssh} y, cuando paran, el dueño vuelve a entrar "
        f"({back_in.status}, panel {in_again})",
    )
