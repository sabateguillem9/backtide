"""T26-4b, on the Mac: the shape of the nginx file a person copies, and what it promises against
the numbers it depends on. That nginx really does all this is for a clean VM
(`tests/attacks/test_reverse_proxy_attacks.py`), which runs this same file."""

import http.server
import re
import ssl
import stat
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509

from backtide.service import passkeys
from backtide.service.origin import parse_public_origin
from backtide.service.web_control import (
    AUTH_ANSWERS_BURST,
    AUTH_ANSWERS_PER_SECOND,
    AUTH_BEGINS_BURST,
    AUTH_BEGINS_PER_SECOND,
)
from backtide.web.security import (
    MAX_LARGE_FORM_BYTES,
    SIGN_IN_KEY_BEGIN_PATH,
    SIGN_IN_KEY_FINISH_PATH,
)
from tests import reverse_proxy_kit as kit

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "guide" / "reverse-proxy.md"
TEXT = kit.CONFIG_FILE.read_text()
# What is in force, without its comments.
RULES = "\n".join(line.split("#", 1)[0] for line in TEXT.splitlines())


def directive(name: str, text: str = RULES) -> list[str]:
    """Every value of a directive."""
    return [v.strip() for v in re.findall(rf"^\s*{name}\s+([^;]*);", text, re.MULTILINE)]


def blocks(text: str, opening: str) -> list[str]:
    """The inside of each ``opening {`` block at any depth."""
    found = []
    for match in re.finditer(rf"^\s*{re.escape(opening)}[^{{\n]*\{{", text, re.MULTILINE):
        depth, at = 1, match.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(text[at], 0)
            at += 1
        found.append(text[match.end() : at - 1])
    return found


def site() -> str:
    """The ``server`` that is the site: the one that goes to the web."""
    [found] = [block for block in blocks(RULES, "server") if "proxy_pass" in block]
    return found


# -- nothing of the link's token stays behind ------------------------------------------------------


@pytest.mark.parametrize(
    "variable", ["$request", "$request_uri", "$args", "$query_string", "$http_referer", "$arg_"]
)
def test_no_log_carries_what_holds_the_token(variable: str) -> None:
    formats = re.findall(r"log_format\s+\w+\s+(.*?);", RULES, re.DOTALL)
    assert formats, "the file defines its log format"
    for found in formats:
        assert not re.search(re.escape(variable) + r"(?![a-z_])", found), found


def test_the_log_says_which_page_by_its_path_alone() -> None:
    assert '"$request_method $uri"' in " ".join(
        re.findall(r"log_format\s+\w+\s+(.*?);", RULES, re.S)
    )


def test_every_log_is_ours_and_no_error_line_quotes_a_request() -> None:
    """An error line of nginx carries the request line and the Referer: only crit is safe."""
    errors = directive("error_log")
    assert errors and all(found.endswith(" crit") for found in errors)
    for found in directive("access_log"):
        assert found == "off" or found.endswith(f"{kit.ACCESS_LOG} backtide")
    for block in blocks(RULES, "server"):
        assert "error_log" in block and "access_log" in block


def test_port_80_repeats_nothing_of_the_request() -> None:
    [redirect] = [b for b in blocks(RULES, "server") if "return 301" in b]
    assert directive("return", redirect) == [f"301 {kit.DOMAIN_URL}/"]


# -- what the web needs from it --------------------------------------------------------------------


def test_the_host_goes_as_the_browser_sent_it() -> None:
    """The web answers one name, its port included: $host would lose a public_origin's port."""
    assert directive("proxy_set_header") == ["Host $http_host"]


def test_it_believes_and_adds_nothing_about_the_address() -> None:
    assert "x-forwarded" not in RULES.lower()
    assert "real_ip" not in RULES


def test_it_goes_to_the_web_on_loopback() -> None:
    assert set(directive("proxy_pass", site())) == {f"http://127.0.0.1:{passkeys.WEB_PORT}"}


def test_it_only_opens_https_for_its_own_name() -> None:
    names = directive("server_name")
    assert names.count(kit.DOMAIN) == 2 and names.count("_") == 1
    [default] = [b for b in blocks(RULES, "server") if "default_server" in b]
    assert directive("ssl_reject_handshake", default) == ["on"]
    assert directive("return", default) == ["444"]
    assert parse_public_origin(kit.DOMAIN_URL).host == kit.DOMAIN


def test_the_certificate_is_where_the_test_mounts_it() -> None:
    assert directive("ssl_certificate", site()) == [f"{kit.CERT_FOLDER}/{kit.CERT_NAME}"]
    assert directive("ssl_certificate_key", site()) == [f"{kit.CERT_FOLDER}/{kit.KEY_NAME}"]


def test_hsts_is_on_every_answer_and_nothing_can_drop_it() -> None:
    """nginx forgets a server's add_header in any location that sets its own."""
    assert directive("add_header", site()) == [
        'Strict-Transport-Security "max-age=31536000" always'
    ]
    for location in blocks(site(), "location"):
        assert "add_header" not in location


# -- the caps --------------------------------------------------------------------------------------


def test_the_cap_covers_both_steps_of_signing_in() -> None:
    [path] = re.findall(r"location\s+(/entrar/llave/)\s*\{", RULES)
    assert SIGN_IN_KEY_BEGIN_PATH.startswith(path) and SIGN_IN_KEY_FINISH_PATH.startswith(path)
    [capped] = [b for b in blocks(site(), "location /entrar/llave/")]
    assert directive("limit_req", capped) == ["zone=backtide_sign_in burst=5 nodelay"]


def test_one_address_stays_under_what_the_service_gives_back() -> None:
    """Or one address could empty the buckets all by itself, which is what the cap is there for."""
    zones = dict(re.findall(r"zone=(\w+):\w+ rate=([\w/]+);", RULES))
    assert zones["backtide_sign_in"] == "6r/m"
    per_second, burst = 6 / 60, 5
    for gives_back, holds in ((AUTH_ANSWERS_PER_SECOND, AUTH_ANSWERS_BURST),
                              (AUTH_BEGINS_PER_SECOND, AUTH_BEGINS_BURST)):  # fmt: skip
        assert per_second < gives_back
        assert burst + 1 < holds
    # And it leaves room for a person: a sign-in is two requests, and three tries in a row work.
    assert burst + 1 >= 3 * 2


def test_the_caps_are_by_the_same_address_and_answer_429() -> None:
    assert re.findall(r"limit_(?:req|conn)_zone\s+(\S+)", RULES) == ["$backtide_client"] * 3
    assert directive("limit_req_status") == ["429"]
    assert directive("limit_conn_status") == ["429"]
    assert directive("limit_conn", site()) == ["backtide_conn 40"]


def backtide_client(address: str) -> str:
    """The file's ``map``, by the rule nginx follows: regexes in order, else the default."""
    [body] = blocks(RULES, "map")
    for pattern, _ in re.findall(r'"~(.*?)"\s+(\$\w+)', body):
        found = re.match(pattern.replace("(?<", "(?P<"), address)
        if found is not None:
            return found[1]
    return address


@pytest.mark.parametrize(
    ("address", "counted_as"),
    [
        ("192.0.2.7", "192.0.2.7"),
        ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2"),
        ("2001:db8:1:2::1", "2001:db8:1:2"),
        ("2001:db8:1::1", "2001:db8:1::"),
        ("2001:db8::1", "2001:db8::"),
        ("::1", "::"),
    ],
)
def test_an_ipv6_address_counts_by_its_64(address: str, counted_as: str) -> None:
    assert backtide_client(address) == counted_as


def test_the_map_counts_by_what_it_captured() -> None:
    """Or the key would be something else, and the table above says nothing about it."""
    [body] = blocks(RULES, "map")
    rules = re.findall(r'"~(.*?)"\s+(\$\w+)', body)
    assert len(rules) == 2
    for pattern, value in rules:
        assert value == "$" + re.findall(r"\(\?<(\w+)>", pattern)[0]
    assert directive("default", body) == ["$remote_addr"]


def test_a_whole_64_is_one_address() -> None:
    """A customer's /64 holds 2**64 addresses: counted one by one there would be no cap."""
    many = {backtide_client(f"2001:db8:1:2:{n:x}:{n:x}:{n:x}:{n:x}") for n in range(1, 500)}
    assert many == {"2001:db8:1:2"}
    assert backtide_client("2001:db8:1:3::1") != backtide_client("2001:db8:1:2::1")


# -- slow clients ----------------------------------------------------------------------------------


def test_slow_clients_wait_in_nginx_and_for_a_limited_time() -> None:
    assert directive("proxy_request_buffering", site()) == ["on"]
    assert directive("proxy_buffering", site()) == ["on"]
    for name in ("client_body_timeout", "send_timeout", "proxy_read_timeout"):
        assert directive(name, site()), name


def test_the_header_timeout_is_where_nginx_reads_it() -> None:
    """Measured: inside the name's ``server``, a half-sent head waits out the default 60 s,
    because nginx has not gone by the name yet."""
    assert directive("client_header_timeout") == ["10s"]
    for block in blocks(RULES, "server"):
        assert "client_header_timeout" not in block


def test_a_body_is_kept_in_memory_and_fits_the_largest_form() -> None:
    def kib(value: str) -> int:
        return int(value.removesuffix("k")) * 1024

    [limit] = directive("client_max_body_size", site())
    [memory] = directive("client_body_buffer_size", site())
    assert MAX_LARGE_FORM_BYTES < kib(limit) <= kib(memory)


def test_nothing_is_compressed_next_to_the_csrf_token() -> None:
    assert directive("gzip", site()) == ["off"]


# -- the test's own container ----------------------------------------------------------------------


def test_the_image_is_pinned_by_digest_with_its_version() -> None:
    assert re.fullmatch(r"nginx:[0-9.]+-alpine@sha256:[0-9a-f]{64}", kit.IMAGE)


def test_the_container_sees_what_it_needs_and_nothing_of_backtide(tmp_path: Path) -> None:
    argv = kit.run_argv(tmp_path / "certs", tmp_path / "logs")
    assert argv[argv.index("--network") + 1] == "host"  # the web is on the host's loopback
    assert "--read-only" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--privileged" not in argv
    mounts = [argv[i + 1] for i, word in enumerate(argv) if word == "--volume"]
    assert mounts == [
        f"{kit.CONFIG_FILE}:/etc/nginx/conf.d/default.conf:ro",
        f"{tmp_path / 'certs'}:{kit.CERT_FOLDER}:ro",
        f"{tmp_path / 'logs'}:{kit.LOG_FOLDER}",
    ]


def test_the_check_is_the_same_container_with_nginx_t(tmp_path: Path) -> None:
    run = kit.run_argv(tmp_path, tmp_path)
    check = kit.check_argv(tmp_path, tmp_path)
    assert check[-1] == "-t" and "--rm" in check
    assert "--detach" not in check and "--name" not in check
    assert kit.CONTAINER not in check
    assert kit.IMAGE in check and [w for w in run if w.startswith("/")] == [
        w for w in check if w.startswith("/")
    ]


# -- the certificates ------------------------------------------------------------------------------


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    kit.make_certificates(tmp_path)
    return tmp_path


def handshake(certs: Path, name: str) -> None:
    """Client and server in memory: no socket, no port."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certs / kit.CERT_NAME, certs / kit.KEY_NAME)
    client = kit.trusting(certs / kit.CA_NAME)
    to_server, to_client = ssl.MemoryBIO(), ssl.MemoryBIO()
    far = server.wrap_bio(to_server, to_client, server_side=True)
    near = client.wrap_bio(to_client, to_server, server_hostname=name)
    for _ in range(8):
        done = 0
        for side in (near, far):
            try:
                side.do_handshake()
                done += 1
            except ssl.SSLWantReadError:
                pass
        if done == 2:
            return
    raise AssertionError("the handshake did not finish")


def test_the_certificate_is_good_for_its_name_and_no_other(certs: Path) -> None:
    handshake(certs, kit.DOMAIN)
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(certs, "evil.example")


def test_the_ca_can_only_sign_that_name_and_its_key_is_gone(certs: Path) -> None:
    """Trusting it for a test leaves nothing that could sign anything else."""
    ca = x509.load_pem_x509_certificate((certs / kit.CA_NAME).read_bytes())
    limits = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert limits.critical
    assert [n.value for n in limits.value.permitted_subtrees] == [kit.DOMAIN]
    private = [p.name for p in certs.iterdir() if b"PRIVATE KEY" in p.read_bytes()]
    assert private == [kit.KEY_NAME]  # the certificate's: the CA's never reached the disk
    assert stat.S_IMODE((certs / kit.KEY_NAME).stat().st_mode) == 0o600


def test_the_spki_is_the_certificates_public_key(certs: Path) -> None:
    assert re.fullmatch(r"[A-Za-z0-9+/]{43}=", kit.certificate_spki(certs / kit.CERT_NAME))


# -- the client the scenarios use ------------------------------------------------------------------


class _Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = self.headers.get("Host", "").encode()
        self.send_response(200)
        self.send_header("X-Said", "yes")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def tls_server(certs: Path) -> Iterator[int]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _Echo)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs / kit.CERT_NAME, certs / kit.KEY_NAME)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()
    thread.join()


def test_ask_speaks_https_by_the_domains_name_to_this_machine(certs: Path, tls_server: int) -> None:
    reply = kit.ask(kit.trusting(certs / kit.CA_NAME), "GET", "/", port=tls_server)
    assert (reply.status, reply.text, reply.header("x-said")) == (200, kit.DOMAIN, "yes")


def test_ask_refuses_a_server_it_has_no_ca_for(certs: Path, tls_server: int) -> None:
    other = ssl.create_default_context()
    with pytest.raises(ssl.SSLCertVerificationError):
        kit.ask(other, "GET", "/", port=tls_server)


def test_the_logs_are_read_whatever_their_name(tmp_path: Path) -> None:
    (tmp_path / "a.log").write_text("uno")
    (tmp_path / "b.log").write_text("dos")
    (tmp_path / "folder").mkdir()
    assert kit.read_logs(tmp_path) == "uno\ndos"


# -- the guide -------------------------------------------------------------------------------------


def test_the_guide_points_at_the_file_and_says_what_happens_without_the_cap() -> None:
    guide = GUIDE.read_text()
    assert "deploy/reverse-proxy/backtide.nginx.conf" in guide
    for words in ("curl", "SSH", "`/entrar/llave/`", "HSTS", "public_origin"):
        assert words in guide, words


@pytest.mark.parametrize(
    "page", [ROOT / "docs" / "guide" / "README.md", ROOT / "docs" / "guide" / "configuration.md"]
)
def test_the_guide_can_be_found(page: Path) -> None:
    assert "reverse-proxy.md" in page.read_text()


def test_the_other_guides_no_longer_say_host() -> None:
    """`$host` loses the port of a public_origin that has one: the file says why."""
    assert "$host" not in (ROOT / "docs" / "guide" / "configuration.md").read_text()
