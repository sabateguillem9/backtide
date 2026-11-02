"""The real reverse proxy for the tests of T26-4b: the file a person copies, unchanged, in nginx.

``deploy/reverse-proxy/backtide.nginx.conf`` goes into a container of the official image, pinned
by digest and used only here (it is no dependency of the product), on the host's network, because
the web listens on the host's loopback and nowhere else. The certificate comes from a CA made for
the occasion, whose private key is never written: it signs one name, the file's, and is gone, so
trusting it for a test leaves nothing that could sign anything else.

Importing this touches nothing; only ``Proxy.start`` runs Docker. What needs Docker runs only in a
clean VM (``tests/attacks/test_reverse_proxy_attacks.py``, ``tests/install/proxy_lab.py``).
"""

import base64
import datetime
import hashlib
import socket
import ssl
import subprocess
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT / "deploy" / "reverse-proxy" / "backtide.nginx.conf"
# The stable line, for linux/amd64 and linux/arm64 alike (the digest is of the multi-arch index).
IMAGE = (
    "nginx:1.30.6-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949"
)
CONTAINER = "backtide-lab-nginx"
DOMAIN = "backtide.example.org"  # the name in the file; made up, and only ever reached in the VM
DOMAIN_URL = f"https://{DOMAIN}"
HTTP_PORT, HTTPS_PORT = 80, 443
# The file's paths for the certificate, its folder mounted from the test's.
CERT_FOLDER = f"/etc/letsencrypt/live/{DOMAIN}"
CERT_NAME, KEY_NAME = "fullchain.pem", "privkey.pem"
CA_NAME = "ca.pem"
LOG_FOLDER = "/var/log/nginx"
ACCESS_LOG, ERROR_LOG = "backtide.access.log", "backtide.error.log"
CERT_DAYS = 30


def make_certificates(folder: Path, name: str = DOMAIN) -> Path:
    """A throwaway CA that can only sign ``name`` (its key never leaves this function), and that
    name's certificate. The certificate's key goes to 0600 files; returns the CA's path."""
    now = datetime.datetime.now(datetime.UTC)
    start, end = now - datetime.timedelta(hours=1), now + datetime.timedelta(days=CERT_DAYS)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"backtide lab CA for {name}")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.NameConstraints(permitted_subtrees=[x509.DNSName(name)], excluded_subtrees=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    ca_path = folder / CA_NAME
    ca_path.write_bytes(ca.public_bytes(pem))
    (folder / CERT_NAME).write_bytes(certificate.public_bytes(pem) + ca.public_bytes(pem))
    key_path = folder / KEY_NAME
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return ca_path


def certificate_spki(cert_file: Path) -> str:
    """The base64 SHA-256 of the certificate's public key: what Chrome's
    ``--ignore-certificate-errors-spki-list`` wants, for the founder's test from the Mac."""
    certificate = x509.load_pem_x509_certificate(cert_file.read_bytes())
    der = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def run_argv(certs: Path, logs: Path, *, config: Path = CONFIG_FILE) -> list[str]:
    """``docker run`` for the proxy. The host's network, because the web is on its loopback;
    nothing is published and nothing of backtide is mounted but the file under test."""
    return [
        "docker", "run", "--detach", "--name", CONTAINER,
        "--network", "host",
        "--read-only",
        "--tmpfs", "/var/cache/nginx",
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",  # noqa: S108 - inside the container
        "--cap-drop", "ALL",
        "--cap-add", "NET_BIND_SERVICE",
        "--cap-add", "CHOWN",
        "--cap-add", "SETUID",
        "--cap-add", "SETGID",
        "--security-opt", "no-new-privileges",
        "--security-opt", "label=disable",  # a test's own files, not worth relabelling on Fedora
        "--volume", f"{config}:/etc/nginx/conf.d/default.conf:ro",
        "--volume", f"{certs}:{CERT_FOLDER}:ro",
        "--volume", f"{logs}:{LOG_FOLDER}",
        "--entrypoint", "nginx",
        IMAGE,
        "-g", "daemon off;",
    ]  # fmt: skip


def check_argv(certs: Path, logs: Path, *, config: Path = CONFIG_FILE) -> list[str]:
    """The same container with ``nginx -t``: is the file valid, before anything relies on it."""
    argv = run_argv(certs, logs, config=config)
    at = argv.index("--detach")
    return [*argv[:at], "--rm", *argv[at + 3 :], "-t"]


class SNIConnection(HTTPSConnection):
    """HTTPS to this machine with the domain's name in the handshake, from a chosen loopback
    address: on Linux the whole of 127.0.0.0/8 is local, so each address is a different visitor
    to nginx, and nothing leaves the VM. ``sni`` None sends no name at all."""

    def __init__(
        self,
        context: ssl.SSLContext,
        *,
        source: str = "127.0.0.1",
        sni: str | None = DOMAIN,
        port: int = HTTPS_PORT,
        timeout: float = 20,
    ) -> None:
        super().__init__("127.0.0.1", port, timeout=timeout, context=context)
        self._backtide_source = source
        self._backtide_sni = sni
        self._backtide_context = context

    def connect(self) -> None:
        sock = socket.create_connection(
            ("127.0.0.1", self.port), self.timeout, (self._backtide_source, 0)
        )
        self.sock = self._backtide_context.wrap_socket(sock, server_hostname=self._backtide_sni)


def trusting(ca_file: Path) -> ssl.SSLContext:
    """A client that believes the test's CA and nothing else, and checks the name."""
    return ssl.create_default_context(cafile=str(ca_file))


@dataclass(frozen=True)
class Reply:
    status: int
    text: str
    headers: dict[str, str]  # lower case; the last of a repeated one

    def header(self, name: str) -> str:
        return self.headers.get(name, "")


def read_reply(conn: HTTPConnection) -> Reply:
    response = conn.getresponse()
    text = response.read().decode(errors="replace")
    return Reply(response.status, text, {k.lower(): v for k, v in response.getheaders()})


def ask(
    context: ssl.SSLContext,
    method: str,
    where: str,
    *,
    host: str = DOMAIN,
    origin: str | None = None,
    cookie: str | None = None,
    body: str | None = None,
    more: dict[str, str] | None = None,
    source: str = "127.0.0.1",
    sni: str | None = DOMAIN,
    port: int = HTTPS_PORT,
) -> Reply:
    """One request through the proxy, on its own connection."""
    headers = {"Host": host, **(more or {})}
    if origin is not None:
        headers["Origin"] = origin
    if cookie is not None:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn = SNIConnection(context, source=source, sni=sni, port=port)
    try:
        conn.request(method, where, body=body, headers=headers)
        return read_reply(conn)
    finally:
        conn.close()


def plain_http(
    where: str, *, host: str = DOMAIN, source: str = "127.0.0.1", port: int = HTTP_PORT
) -> Reply:
    """Port 80, as a browser's first try."""
    conn = HTTPConnection("127.0.0.1", port, timeout=20, source_address=(source, 0))
    try:
        conn.request("GET", where, headers={"Host": host})
        return read_reply(conn)
    finally:
        conn.close()


def read_logs(folder: Path) -> str:
    """Every log nginx wrote in the folder, whatever its name."""
    return "\n".join(
        path.read_text(errors="replace") for path in sorted(folder.iterdir()) if path.is_file()
    )


def docker(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        ["docker", *argv],  # noqa: S607 - the VM's Docker
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


@dataclass(frozen=True)
class Proxy:
    """A running proxy's folders: ``certs`` holds the certificate, ``logs`` what nginx wrote."""

    certs: Path
    logs: Path

    @property
    def ca(self) -> Path:
        return self.certs / CA_NAME

    def logged(self) -> str:
        """What nginx wrote: its files and its standard output and error."""
        output = docker("logs", CONTAINER)
        return read_logs(self.logs) + output.stdout + output.stderr


def start(folder: Path) -> Proxy:
    """Certificates, ``nginx -t`` on the shipped file, and the proxy running. Raises with what
    nginx said if the file does not load; the caller removes the container (``stop``)."""
    certs, logs = folder / "certs", folder / "logs"
    certs.mkdir(mode=0o700)
    logs.mkdir(mode=0o700)
    make_certificates(certs)
    for argv in (check_argv(certs, logs), run_argv(certs, logs)):
        ran = subprocess.run(  # noqa: S603 - fixed argv
            argv, capture_output=True, text=True, check=False, timeout=300
        )
        if ran.returncode != 0:
            raise RuntimeError(f"nginx: {ran.stdout}{ran.stderr}")
    return Proxy(certs, logs)


def stop() -> None:
    """Remove the proxy, if there is one. Its image stays (`make vm-limpiar` never touches any)."""
    docker("rm", "--force", "--volumes", CONTAINER)
