"""T06-1: what the egress proxy design (docs/21) assumes, checked in the VM (P1-P9).

Each test pins one behaviour of the pinned mitmproxy image, Docker or OpenClaw that T06-2 to
T06-5 build on, or records a figure for docs/21 ("Resultados en la VM"). Behaviours the design
relies on are asserted, so an upgrade of the image, Docker or OpenClaw that changes them stops
the work. Figures go through ``report`` (shown with ``pytest -rP``, kept in the JUnit XML).

The lab (``lab``, one per module) is made of throwaway containers on two networks, both
``--internal`` with isolated gateways: nothing in it can reach the internet, the VM or the Mac
(invariant 8), even if a check fails.

    agent net:  client (the agent's role, --dns = fake-dns) . fake-dns . proxy ("vigia-proxy")
    egress net: proxy . fake-internet (every *.fake.test name is an alias of it)

- ``proxy``: the pinned mitmproxy image as uid 61001, no capabilities, read-only root, started
  from Python (proxy_fixtures/proxy_main.py), with the CA made by the VM's openssl.
- ``fake-internet``: HTTPS servers with a CA of the test's own, that say what reached them and
  count every TCP connection (proxy_fixtures/fake_internet.py).
- ``fake-dns``: a resolver that logs every query (proxy_fixtures/fake_dns.py).
- ``client``: the test's client (proxy_fixtures/client.py), which trusts only the agent CA.

P9 adds the real OpenClaw from the pinned image. Every key is a fake one made here; nothing
ever talks to a real model provider.

Containers and networks are named like conftest.py's test agents (``vigia-test-agent-<pid>-``
and ``vigia-test-net-<pid>-``), so the cleanup of a killed run's leftovers covers them too.
"""

import json
import os
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from uuid import uuid4

import pytest

from vigia.jail import IMAGE, AgentJail, AgentJailConfig
from vigia.jail import docker as jail_docker
from vigia.jail.config import docker_create_argv, openclaw_config, token_env

pytestmark = pytest.mark.integration

# mitmproxy 12.2.3 (12 May 2026), the multi-arch index; its arm64 image is ARM64_MANIFEST.
MITMPROXY_VERSION = "12.2.3"
MITMPROXY_REPO = "mitmproxy/mitmproxy"
MITMPROXY_DIGEST = "sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
MITMPROXY_IMAGE = f"{MITMPROXY_REPO}:{MITMPROXY_VERSION}@{MITMPROXY_DIGEST}"
ARM64_MANIFEST = "sha256:62d266a86ee95187217866c0e35487837498daa3aa1cdce37d256f07e198a47b"
AMD64_MANIFEST = "sha256:68afa70d7b6ac9d269b88f88534f9ffceb363b4ce31703a78702341fba82e831"

PROXY_UID = 61001
CLIENT_UID = 61000  # the agent's own ids (vigia/jail/config.py)
FAKE_UID = 61002
PROXY_ALIAS = "vigia-proxy"
PROXY_PORT = 8080
PROXY = f"{PROXY_ALIAS}:{PROXY_PORT}"
CONTAINER_PREFIX = "vigia-test-agent-"  # conftest.TEST_CONTAINER_PREFIX
NETWORK_PREFIX = "vigia-test-net-"  # conftest.TEST_NETWORK_PREFIX

FIXTURES = Path(__file__).parent / "proxy_fixtures"
SCRIPTS = ("proxy_main.py", "fake_internet.py", "fake_dns.py", "client.py")
PROXY_READY = "t06-proxy-ready"
INTERNET_READY = "t06-internet-ready"
DNS_READY = "t06-dns-ready"
FAKE_HOSTS = (
    "control.fake.test",
    "plain.fake.test",
    "p6.fake.test",
    "p6h2.fake.test",
    "p6-deny.fake.test",
    "eager.fake.test",
    "p7-sync.fake.test",
    "p7-async.fake.test",
    "p7-connect.fake.test",
    "p7-wrapped.fake.test",
    "p8.fake.test",
    "p8-sni.fake.test",
    "model.fake.test",
)
AGENT_CA_NAME = "Vigia agent CA t06-1"
INTERNET_CA_NAME = "T06 test internet CA"

PULL_TIMEOUT = 900.0
READY_TIMEOUT = 60.0
OPENSSL_TIMEOUT = 120.0


def report(record_property: Callable[[str, object], None], name: str, outcome: object) -> None:
    """Shown with ``pytest -rP``, and kept in the JUnit XML, for docs/21."""
    print(f"{name}: {outcome}")  # noqa: T201
    record_property(name, str(outcome))


# The lab


@dataclass
class Lab:
    root: Path
    agent_net: str
    egress_net: str
    fake: str
    dns: str
    proxy: str
    client: str
    dns_ip: str
    proxy_ip: str
    fake_ip: str
    figures: dict[str, str] = field(default_factory=dict)
    channel_dir: Path = field(init=False)
    t06_dir: Path = field(init=False)
    proxy_ca_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        self.channel_dir = self.root / "channel"
        self.t06_dir = self.root / "t06"
        self.proxy_ca_dir = self.root / "proxy-ca"


def unique(prefix: str) -> str:
    return f"{prefix}{os.getpid()}-{uuid4().hex[:12]}"


def docker(*args: str, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    return jail_docker.run(list(args), timeout=timeout, check=check)


def inspect(name: str) -> dict:
    return json.loads(docker("inspect", name).stdout)[0]


def ip_on(name: str, network: str) -> str:
    return inspect(name)["NetworkSettings"]["Networks"][network]["IPAddress"]


def wait_for_line(name: str, line: str, timeout: float = READY_TIMEOUT) -> float:
    """Wait until ``docker logs name`` shows ``line``; return the seconds it took."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        logs = docker("logs", name, check=False)
        if line in logs.stdout + logs.stderr:
            return time.monotonic() - start
        state = inspect(name)["State"]
        if not state["Running"]:
            raise AssertionError(
                f"{name} exited ({state['ExitCode']}) before {line!r}:\n"
                f"{jail_docker.sanitize(logs.stdout + logs.stderr)}"
            )
        time.sleep(0.25)
    raise AssertionError(f"{name} did not print {line!r} within {timeout} s")


def hardened(name: str, uid: int, *, memory: str = "256m", pids: int = 64) -> list[str]:
    """The options every lab container shares (those of the proxy in docs/21, section 1)."""
    return [
        "create",
        "--name", name,
        "--user", f"{uid}:{uid}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true",
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",  # noqa: S108 - in the container
        "--memory", memory,
        "--memory-swap", memory,
        "--pids-limit", str(pids),
        "--restart", "no",
        "--env", "HOME=/tmp",
    ]  # fmt: skip


def openssl(*args: str) -> None:
    subprocess.run(
        ["openssl", *args], check=True, capture_output=True, text=True, timeout=OPENSSL_TIMEOUT
    )


def make_ca(folder: Path, name: str, bits: int, days: int) -> tuple[Path, Path]:
    """A CA as Vigía will make it (docs/21, section 3): the VM's openssl, a fixed config."""
    config = folder / f"{bits}-ca.cnf"
    config.write_text(
        "[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n"
        f"[dn]\nCN = {name}\n"
        "[v3_ca]\nbasicConstraints = critical,CA:TRUE\n"
        "keyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n"
    )
    key, cert = folder / f"{bits}-ca.key", folder / f"{bits}-ca.pem"
    openssl(
        "req", "-x509", "-new", "-config", str(config), "-newkey", f"rsa:{bits}", "-nodes",
        "-sha256", "-days", str(days), "-keyout", str(key), "-out", str(cert),
    )  # fmt: skip
    return key, cert


def make_server_cert(folder: Path, ca_key: Path, ca_cert: Path) -> Path:
    """The fake internet's certificate, for *.fake.test, signed by the test internet CA."""
    key, csr, cert = folder / "server.key", folder / "server.csr", folder / "server.crt"
    ext = folder / "server.ext"
    ext.write_text(
        "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,"
        "keyEncipherment\nextendedKeyUsage = serverAuth\n"
        "subjectAltName = DNS:*.fake.test,DNS:fake.test\n"
    )
    openssl(
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=fake.test",
        "-keyout", str(key), "-out", str(csr),
    )  # fmt: skip
    openssl(
        "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
        "-set_serial", "2", "-days", "30", "-sha256", "-extfile", str(ext), "-out", str(cert),
    )  # fmt: skip
    pem = folder / "server.pem"
    pem.write_text(cert.read_text() + key.read_text())
    return pem


def write_mitmproxy_confdir(folder: Path, ca_key: Path, ca_cert: Path, *, dhparam: bool) -> None:
    """``mitmproxy-ca.pem`` (key, then certificate) and, if asked, ``mitmproxy-dhparam.pem``."""
    folder.mkdir()
    (folder / "mitmproxy-ca.pem").write_text(ca_key.read_text() + ca_cert.read_text())
    if dhparam:
        # A standard RFC 7919 group: instant, unlike `openssl dhparam`.
        openssl(
            "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", "group:ffdhe3072",
            "-out", str(folder / "mitmproxy-dhparam.pem"),
        )  # fmt: skip
    for path in folder.iterdir():
        path.chmod(0o444)  # production: 0440 root:61001; the test user cannot chgrp to 61001
    folder.chmod(0o555)


def require_mitmproxy_image() -> None:
    if docker("image", "inspect", MITMPROXY_IMAGE, check=False).returncode == 0:
        return
    docker("pull", "--quiet", MITMPROXY_IMAGE, timeout=PULL_TIMEOUT)


def proxy_argv(lab_root: Path, name: str, agent_net: str, egress_net: str, *, alias: str,
               confdir: Path, env: tuple[str, ...] = ()) -> list[str]:  # fmt: skip
    """docs/21, section 1: both networks in the one ``docker create`` (P4)."""
    argv = hardened(name, PROXY_UID, memory="1g", pids=128)
    argv += [
        "--network", f"name={agent_net},alias={alias}",
        "--network", egress_net,
        "--cpus", "1",
        "--ulimit", "nofile=4096",
        "--log-driver", "local",
        "--log-opt", "max-size=10m",
        "--log-opt", "max-file=3",
        # Docker's sysctl, not the VM's: a container inherits the VM's 1 (P4).
        "--sysctl", "net.ipv4.ip_forward=0",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        # Without it mitmproxy's own log (addon errors) stays in stdout's buffer (P7).
        "--env", "PYTHONUNBUFFERED=1",
        "--volume", f"{confdir}:/ca:ro,z",
        "--volume", f"{lab_root / 'channel'}:/run/vigia:ro,z",
        "--volume", f"{lab_root / 't06'}:/opt/t06:ro,z",
    ]  # fmt: skip
    for item in env:
        argv += ["--env", item]
    argv += ["--entrypoint", "python3", MITMPROXY_IMAGE, "/opt/t06/proxy_main.py"]
    return argv


def remove_all(containers: list[str], networks: list[str]) -> None:
    for name in reversed(containers):
        docker("rm", "--force", name, check=False)
    for name in reversed(networks):
        docker("network", "rm", name, check=False)


def internal_network(name: str) -> None:
    docker(
        "network", "create", "--driver", "bridge", "--internal",
        "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "--opt", "com.docker.network.bridge.gateway_mode_ipv6=isolated",
        name,
    )  # fmt: skip


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    require_mitmproxy_image()
    root = tmp_path_factory.mktemp("t06-lab")
    root.chmod(0o755)
    t06, internet, certs, channel = (
        root / "t06",
        root / "internet",
        root / "certs",
        root / "channel",
    )
    for folder in (t06, internet, certs, channel):
        folder.mkdir()
    for script in SCRIPTS:
        shutil.copyfile(FIXTURES / script, t06 / script)
    start = time.monotonic()
    agent_key, agent_cert = make_ca(certs, AGENT_CA_NAME, 3072, 1826)
    figures = {"agent CA (RSA 3072, 5 years) made in": f"{time.monotonic() - start:.2f} s"}
    internet_key, internet_cert = make_ca(certs, INTERNET_CA_NAME, 2048, 30)
    shutil.copyfile(make_server_cert(certs, internet_key, internet_cert), internet / "server.pem")
    shutil.copyfile(agent_cert, t06 / "agent-ca.pem")
    shutil.copyfile(internet_cert, t06 / "internet-ca.pem")
    write_mitmproxy_confdir(root / "proxy-ca", agent_key, agent_cert, dhparam=True)
    for folder in (t06, internet):
        for path in folder.iterdir():
            path.chmod(0o444)
        folder.chmod(0o555)
    channel.chmod(0o755)

    agent_net, egress_net = unique(NETWORK_PREFIX), unique(NETWORK_PREFIX)
    fake, dns, proxy, client = (unique(CONTAINER_PREFIX) for _ in range(4))
    containers: list[str] = []
    networks: list[str] = []
    try:
        for net in (agent_net, egress_net):
            internal_network(net)
            networks.append(net)

        argv = hardened(fake, FAKE_UID) + ["--network", egress_net]
        for host in FAKE_HOSTS:
            argv += ["--network-alias", host]
        argv += [
            "--volume", f"{t06}:/opt/t06:ro,z",
            "--volume", f"{internet}:/opt/internet:ro,z",
            "--entrypoint", "python3", MITMPROXY_IMAGE, "/opt/t06/fake_internet.py",
        ]  # fmt: skip
        docker(*argv)
        containers.append(fake)
        docker("start", fake)
        wait_for_line(fake, INTERNET_READY)

        docker(
            *hardened(dns, FAKE_UID), "--network", agent_net,
            "--volume", f"{t06}:/opt/t06:ro,z",
            "--entrypoint", "python3", MITMPROXY_IMAGE, "/opt/t06/fake_dns.py",
        )  # fmt: skip
        containers.append(dns)
        docker("start", dns)
        wait_for_line(dns, DNS_READY)
        dns_ip = ip_on(dns, agent_net)

        start = time.monotonic()
        docker(*proxy_argv(root, proxy, agent_net, egress_net, alias=PROXY_ALIAS,
                           confdir=root / "proxy-ca"))  # fmt: skip
        containers.append(proxy)
        docker("start", proxy)
        wait_for_line(proxy, PROXY_READY)
        figures["proxy: docker create to listening"] = f"{time.monotonic() - start:.2f} s"

        docker(
            *hardened(client, CLIENT_UID), "--network", agent_net,
            "--volume", f"{t06}:/opt/t06:ro,z",
            "--entrypoint", "sleep", MITMPROXY_IMAGE, "infinity",
        )  # fmt: skip
        containers.append(client)
        docker("start", client)

        yield Lab(
            root=root,
            agent_net=agent_net,
            egress_net=egress_net,
            fake=fake,
            dns=dns,
            proxy=proxy,
            client=client,
            dns_ip=dns_ip,
            proxy_ip=ip_on(proxy, agent_net),
            fake_ip=ip_on(fake, egress_net),
            figures=figures,
        )
    finally:
        remove_all(containers, networks)


def run_client(lab: Lab, *args: str, container: str | None = None, timeout: float = 60) -> dict:
    result = docker(
        "exec", container or lab.client, "python3", "/opt/t06/client.py", *args,
        timeout=timeout, check=False,
    )  # fmt: skip
    lines = result.stdout.strip().splitlines()
    assert lines, f"the client printed nothing: {jail_docker.sanitize(result.stderr)}"
    return json.loads(lines[-1])


STATS = (
    "import sys, urllib.request; "
    "sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:9000/stats', timeout=10)"
    ".read().decode())"
)


def fake_stats(lab: Lab) -> dict:
    return json.loads(docker("exec", lab.fake, "python3", "-c", STATS).stdout)


def requests_to(stats: dict, host: str) -> list[dict]:
    return [r for r in stats["requests"] if (r["host"] or "").split(":")[0] == host]


def proc_status(container: str, pid: str = "1") -> dict[str, str]:
    text = docker("exec", container, "cat", f"/proc/{pid}/status").stdout
    fields = {}
    for line in text.splitlines():
        name, _, value = line.partition(":")
        fields[name] = value.strip()
    return fields


def proxy_logs(lab: Lab) -> str:
    result = docker("logs", lab.proxy, check=False)
    return result.stdout + result.stderr


# The image


def test_the_image_is_pinned_multi_arch_and_runs_arm64(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """The digest is the multi-arch index of 12.2.3; the VM runs its arm64 image."""
    image = json.loads(docker("image", "inspect", MITMPROXY_IMAGE).stdout)[0]
    assert f"{MITMPROXY_REPO}@{MITMPROXY_DIGEST}" in image["RepoDigests"]
    assert image["Os"] == "linux"
    assert image["Architecture"] == "arm64"
    version = docker(
        "exec", lab.proxy, "python3", "-c", "import mitmproxy.version as v; print(v.VERSION)"
    ).stdout.strip()
    assert version == MITMPROXY_VERSION
    python = docker("exec", lab.proxy, "python3", "--version").stdout.strip()
    manifest = docker("manifest", "inspect", MITMPROXY_IMAGE, check=False, timeout=120)
    if manifest.returncode == 0:
        platforms = {
            (m["platform"]["architecture"], m["digest"])
            for m in json.loads(manifest.stdout)["manifests"]
            if m["platform"]["os"] == "linux"
        }
        assert ("arm64", ARM64_MANIFEST) in platforms
        assert ("amd64", AMD64_MANIFEST) in platforms
        report(record_property, "manifest", sorted(platforms))
    else:
        report(record_property, "manifest", f"not read: {manifest.stderr.strip()[:200]}")
    report(record_property, "image", f"{image['Architecture']}, {image['Size']} bytes, {python}")


# P1: the image runs as 61001, without capabilities, with a read-only root and main.py


def test_p1_proxy_runs_unprivileged_from_python(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """Our ``proxy_main.py`` (a DumpMaster, the entrypoint skipped) runs as 61001 with no
    capabilities and a read-only root, and listens."""
    config = inspect(lab.proxy)
    assert config["Config"]["User"] == f"{PROXY_UID}:{PROXY_UID}"
    assert config["Config"]["Entrypoint"] == ["python3"]
    assert config["HostConfig"]["ReadonlyRootfs"] is True
    assert config["HostConfig"]["CapDrop"] == ["ALL"]
    assert config["HostConfig"]["Privileged"] is False
    status = proc_status(lab.proxy)
    assert status["Uid"].split() == [str(PROXY_UID)] * 4
    assert status["Gid"].split() == [str(PROXY_UID)] * 4
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(status[name], 16) == 0, f"{name} = {status[name]}"
    assert status["NoNewPrivs"] == "1"
    assert "python3" in docker("exec", lab.proxy, "cat", "/proc/1/cmdline").stdout
    tmp = "/tmp"  # noqa: S108 - inside the container
    written = docker("exec", lab.proxy, "find", tmp, "-mindepth", "1").stdout.split()
    report(record_property, "files the proxy wrote in /tmp (HOME)", written or "none")
    report(record_property, "startup", lab.figures)
    for name, value in lab.figures.items():
        print(f"{name}: {value}")  # noqa: T201


def test_p1_memory_after_some_requests(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """Records only: the proxy's memory once it has served a few requests."""
    for _ in range(5):
        assert run_client(lab, "https", PROXY, "plain.fake.test", "/warm")["status"] == 200
    usage = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", lab.proxy).stdout
    report(record_property, "proxy memory", usage.strip())


# P2: our CA (RSA 3072, made by openssl), with /ca read-only


def test_p2_proxy_signs_with_our_ca(lab: Lab) -> None:
    """The client trusts only the agent CA, and the proxy's certificate for the fake host is
    issued by it: interception works with the openssl CA in a read-only /ca."""
    result = run_client(lab, "https", PROXY, "plain.fake.test", "/p2")
    assert result["ok"], result
    assert result["status"] == 200
    assert result["issuer"] == AGENT_CA_NAME
    assert result["body"]["sni"] == "plain.fake.test"  # the proxy -> fake hop verified the cert


def test_p2_dhparam_is_needed_in_a_read_only_confdir(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """With only ``mitmproxy-ca.pem`` in a read-only /ca, mitmproxy tries to write
    ``mitmproxy-dhparam.pem`` there and the proxy does not start (fails closed). So Vigía
    writes the dhparam next to the CA beforehand (RFC 7919 ffdhe3072, ``openssl genpkey``):
    the lab's proxy, which works, is made that way."""
    confdir = lab.root / "proxy-ca-only"
    certs = lab.root / "certs"
    write_mitmproxy_confdir(confdir, certs / "3072-ca.key", certs / "3072-ca.pem", dhparam=False)
    name = unique(CONTAINER_PREFIX)
    try:
        docker(*proxy_argv(lab.root, name, lab.agent_net, lab.egress_net,
                           alias="vigia-proxy-ca-only", confdir=confdir))  # fmt: skip
        docker("start", name)
        try:
            wait_for_line(name, PROXY_READY, timeout=30)
            outcome = "starts"
            result = run_client(lab, "https", "vigia-proxy-ca-only:8080", "plain.fake.test", "/")
            outcome += f"; a request through it: {result.get('status', result.get('error'))}"
        except AssertionError as error:
            outcome = f"does not start: {str(error)[-600:]}"
        report(record_property, "only mitmproxy-ca.pem in a read-only /ca", outcome)
    finally:
        docker("rm", "--force", name, check=False)
    assert outcome.startswith("does not start"), outcome
    assert "Read-only file system: '/ca/mitmproxy-dhparam.pem'" in outcome, outcome


# P3: a container_t process connects to a Unix socket of a host process, read-only mount


@dataclass
class PeerSeen:
    uid: int = -1
    gid: int = -1
    pid: int = -1
    cgroup: str = ""
    line: str = ""


def read_peer(conn: socket.socket, seen: PeerSeen) -> None:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    seen.pid, seen.uid, seen.gid = struct.unpack("3i", creds)
    seen.cgroup = Path(f"/proc/{seen.pid}/cgroup").read_text().strip()


def serve_once(path: Path, seen: PeerSeen, ready: threading.Event) -> threading.Thread:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    path.chmod(0o666)  # production: 0660 root:61001 (the test user cannot chgrp to 61001)
    server.listen(1)
    server.settimeout(30)

    def run() -> None:
        with server:
            ready.set()
            try:
                conn, _ = server.accept()
            except TimeoutError:
                return
            with conn:
                read_peer(conn, seen)
                seen.line = conn.makefile("rb").readline().decode().strip()
                conn.sendall(b"ack\n")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def connect_from(lab: Lab, container: str, sock: Path) -> tuple[dict, PeerSeen]:
    """The host listens on ``sock`` (in the channel folder); ``container`` connects to it
    through its read-only /run/vigia."""
    seen, ready = PeerSeen(), threading.Event()
    thread = serve_once(sock, seen, ready)
    try:
        assert ready.wait(10)
        result = run_client(
            lab, "unix", f"/run/vigia/{sock.name}", "hello", container=container, timeout=40
        )
        thread.join(40)
    finally:
        sock.unlink(missing_ok=True)
    return result, seen


def selinux_mode() -> str:
    enforce = Path("/sys/fs/selinux/enforce")
    return enforce.read_text().strip() if enforce.exists() else "absent"


def test_p3_selinux_refuses_container_t_a_host_socket(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """The channel as docs/21 section 5 first drew it does NOT work: with SELinux enforcing,
    the proxy (container_t) gets EACCES connecting to a socket that a host process listens
    on, although the socket is 0666 and its folder is labelled container_file_t. The control,
    the same connection from a container with ``label=disable`` on the same read-only mount,
    succeeds: the refusal is SELinux's (connectto towards the host's domain), not the
    read-only mount nor the file mode. Hence plan B (the next test)."""
    assert selinux_mode() == "1", "SELinux must be enforcing for this check to mean anything"
    security = docker("info", "--format", "{{json .SecurityOptions}}").stdout.strip()
    label = os.getxattr(lab.channel_dir, "security.selinux").decode().rstrip("\0")
    report(record_property, "selinux", f"enforcing, docker {security}, channel folder {label}")
    report(record_property, "proxy process label", inspect(lab.proxy)["ProcessLabel"])
    result, seen = connect_from(lab, lab.proxy, lab.channel_dir / "events.sock")
    report(record_property, "container_t -> host socket", result)
    assert result == {"ok": False, "error": "PermissionError: [Errno 13] Permission denied"}
    assert seen.uid == -1  # the host never saw a connection

    name = unique(CONTAINER_PREFIX)
    docker(
        *hardened(name, PROXY_UID), "--network", "none",
        "--security-opt", "label=disable",
        "--volume", f"{lab.channel_dir}:/run/vigia:ro,z",
        "--volume", f"{lab.t06_dir}:/opt/t06:ro,z",
        "--entrypoint", "sleep", MITMPROXY_IMAGE, "infinity",
    )  # fmt: skip
    try:
        docker("start", name)
        control, seen = connect_from(lab, name, lab.channel_dir / "control.sock")
        container_id = inspect(name)["Id"]
    finally:
        docker("rm", "--force", name, check=False)
    assert control == {"ok": True, "reply": "ack"}, control
    assert seen.line == "hello"
    assert (seen.uid, seen.gid) == (PROXY_UID, PROXY_UID)
    assert container_id in seen.cgroup, seen.cgroup


def test_p3_plan_b_the_host_connects_to_a_socket_of_the_proxy(
    lab: Lab, tmp_path: Path, record_property: Callable[[str, object], None]
) -> None:
    """Plan B of docs/21 section 5, with SELinux enforcing: the proxy listens on a socket in
    its own folder (mounted read-write, ``:z``) and the host connects. The host opens the
    socket with O_PATH|O_NOFOLLOW, checks it is a socket of 61001 and connects through
    /proc/self/fd/N (no symlink can redirect it). SO_PEERCRED gives 61001 and a pid whose
    cgroup names the proxy's container, which is what Vigía checks before sending anything."""
    folder = tmp_path / "proxy-channel"
    folder.mkdir()
    folder.chmod(0o777)  # production: 0700 61001 (the test user cannot chown to 61001)
    name = unique(CONTAINER_PREFIX)
    docker(
        *hardened(name, PROXY_UID), "--network", "none",
        "--volume", f"{folder}:/run/vigia:rw,z",
        "--volume", f"{lab.t06_dir}:/opt/t06:ro,z",
        "--entrypoint", "python3", MITMPROXY_IMAGE,
        "/opt/t06/client.py", "listen", "/run/vigia/events.sock",
    )  # fmt: skip
    try:
        docker("start", name)
        sock = folder / "events.sock"
        deadline = time.monotonic() + 20
        while not sock.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        fd = os.open(sock, os.O_PATH | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            assert stat.S_ISSOCK(info.st_mode)
            assert info.st_uid == PROXY_UID
            seen = PeerSeen()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(20)
                conn.connect(f"/proc/self/fd/{fd}")
                read_peer(conn, seen)
                conn.sendall(b"hello\n")
                reply = conn.makefile("rb").readline()
        finally:
            os.close(fd)
        docker("wait", name, timeout=30)
        logs = docker("logs", name).stdout.strip().splitlines()
        container_id = inspect(name)["Id"]
        label = os.getxattr(folder, "security.selinux").decode().rstrip("\0")
    finally:
        docker("rm", "--force", name, check=False)
    report(record_property, "plan B peer", f"uid {seen.uid}, cgroup {seen.cgroup}, {label}")
    assert reply == b"ack\n"
    assert json.loads(logs[-1]) == {"ok": True, "line": "hello"}
    assert (seen.uid, seen.gid) == (PROXY_UID, PROXY_UID)
    assert container_id in seen.cgroup, seen.cgroup


# P4: docker create with two --network and the alias


def test_p4_one_create_puts_the_proxy_on_both_networks(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """``--network name=<agent>,alias=vigia-proxy --network <egress>`` in one docker create:
    the proxy is on both, and the alias exists only on the agent's network. Forwarding is off
    in the proxy only because its argv says so: a container inherits the VM's
    ``ip_forward=1`` (Docker turns it on in the VM)."""
    networks = inspect(lab.proxy)["NetworkSettings"]["Networks"]
    assert set(networks) == {lab.agent_net, lab.egress_net}
    agent_side, egress_side = networks[lab.agent_net], networks[lab.egress_net]
    assert PROXY_ALIAS in (agent_side.get("Aliases") or [])
    assert PROXY_ALIAS not in (egress_side.get("Aliases") or [])
    assert PROXY_ALIAS not in (egress_side.get("DNSNames") or [])
    version = docker("version", "--format", "{{.Server.Version}}").stdout.strip()
    report(record_property, "docker", version)
    forward = docker("exec", lab.proxy, "cat", "/proc/sys/net/ipv4/ip_forward").stdout.strip()
    inherited = docker("exec", lab.client, "cat", "/proc/sys/net/ipv4/ip_forward").stdout.strip()
    report(
        record_property, "ip_forward", f"proxy {forward}, a container without --sysctl {inherited}"
    )
    assert forward == "0"
    assert inherited == "1"
    # The agent never sees the egress side: no name of it resolves, no address of it answers.
    assert not run_client(lab, "resolve", "control.fake.test")["ok"]
    probe = (
        "import socket; s = socket.socket(); s.settimeout(3)\n"
        f"try:\n    s.connect(({lab.fake_ip!r}, 443)); print('ESCAPED')\n"
        "except OSError as e: print('blocked', e)"
    )
    direct = docker("exec", lab.client, "python3", "-c", probe, check=False).stdout
    assert "blocked" in direct and "ESCAPED" not in direct, direct


# P5: the agent resolves vigia-proxy, and its DNS goes nowhere


def fake_dns_queries(lab: Lab) -> list[str]:
    logs = docker("logs", lab.dns).stdout
    return [line for line in logs.splitlines() if line.startswith("query ")]


def test_p5_the_agent_resolves_the_proxy_and_nothing_else(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """The agent as the jail makes it (no ``--dns``): Docker's embedded resolver answers
    ``vigia-proxy`` and nothing else, the egress side's names included; the proxy answers no
    DNS; and the fake resolver on the agent's network gets nothing."""
    resolv = docker("exec", lab.client, "cat", "/etc/resolv.conf").stdout
    ext = [line for line in resolv.splitlines() if "ExtServers" in line]
    report(record_property, "agent resolv.conf, external servers", ext)
    before = fake_dns_queries(lab)
    proxy = run_client(lab, "resolve", PROXY_ALIAS)
    assert proxy == {"ok": True, "addresses": [lab.proxy_ip]}, proxy
    marker = secrets.token_hex(6)
    start = time.monotonic()
    for name in (f"exfil-{marker}.example.com", f"{marker}.fake.test", marker):
        result = run_client(lab, "resolve", name)
        assert not result["ok"], result
    report(record_property, "three failed lookups took", f"{time.monotonic() - start:.2f} s")
    to_proxy = run_client(lab, "dns", lab.proxy_ip, f"proxy-{marker}.example")
    assert not to_proxy["ok"], to_proxy
    time.sleep(1)
    assert fake_dns_queries(lab) == before


def test_p5_with_a_dns_option_docker_forwards_inside_the_internal_network(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """What docs/21 expected NOT to happen: with ``--dns <fake resolver>``, the embedded
    resolver of a container that is only on internal networks DOES forward outside names to
    it, from the container's own network. Docker only refuses the host's resolvers there.
    So the agent must never get ``--dns`` (verify.py has to require HostConfig.Dns empty), and
    nothing on the agent's network may answer DNS. The direct query is the control."""
    name = unique(CONTAINER_PREFIX)
    docker(
        *hardened(name, CLIENT_UID), "--network", lab.agent_net, "--dns", lab.dns_ip,
        "--volume", f"{lab.t06_dir}:/opt/t06:ro,z",
        "--entrypoint", "sleep", MITMPROXY_IMAGE, "infinity",
    )  # fmt: skip
    marker = secrets.token_hex(6)
    try:
        docker("start", name)
        resolved = run_client(lab, "resolve", f"exfil-{marker}.example.com", container=name)
        direct = run_client(lab, "dns", lab.dns_ip, f"direct-{marker}.example", container=name)
    finally:
        docker("rm", "--force", name, check=False)
    assert not resolved["ok"]  # NXDOMAIN from the fake resolver
    assert direct == {"ok": True, "rcode": 3}, direct
    time.sleep(0.5)
    queries = fake_dns_queries(lab)
    forwarded = [q for q in queries if f"exfil-{marker}.example.com" in q]
    report(record_property, "forwarded to --dns", forwarded)
    assert forwarded, "the embedded resolver no longer forwards to --dns: read docs/21 again"
    assert any(f"direct-{marker}.example" in q for q in queries)


# P6: with lazy, no connection to the server until the request hook returns, none if it refuses


def accepts_seen_by_the_hook(result: dict) -> tuple[int, int]:
    before, after = result["body"]["headers"]["x-t06-accepts"].split(",")
    return int(before), int(after)


def test_p6_lazy_connects_only_after_the_request_hook(lab: Lab) -> None:
    """During the hook (after CONNECT and the TLS handshake with the client) the fake server
    has not accepted any new connection; the one that carries the request comes right after."""
    result = run_client(lab, "https", PROXY, "p6.fake.test", "/p6")
    assert result["ok"] and result["status"] == 200, result
    before, after = accepts_seen_by_the_hook(result)
    assert before == after
    assert result["body"]["accept"] == after + 1


def test_p6_lazy_holds_over_http2_too(lab: Lab) -> None:
    """The same when the client negotiates h2 with the proxy (ALPN without asking the server)."""
    result = run_client(lab, "h2", PROXY, "p6h2.fake.test", "/p6h2")
    assert result["ok"] and result["status"] == 200, result
    assert result["alpn"] == "h2"
    assert result["issuer"] == AGENT_CA_NAME
    before, after = accepts_seen_by_the_hook(result)
    assert before == after
    assert result["body"]["accept"] == after + 1


def test_p6_a_refused_request_never_reaches_the_server(lab: Lab) -> None:
    """A request answered by the hook (403) opens no connection to the server at all."""
    before = fake_stats(lab)
    result = run_client(lab, "https", PROXY, "p6-deny.fake.test", "/p6-deny", "POST")
    assert result["ok"] and result["status"] == 403, result
    time.sleep(0.5)
    after = fake_stats(lab)
    assert after["accepts"] == before["accepts"]
    assert requests_to(after, "p6-deny.fake.test") == []


def test_p6_control_eager_connects_before_the_hook(lab: Lab) -> None:
    """Control: with ``connection_strategy=eager`` the fake server sees the connection before
    the hook runs. So the measurement above would have caught an early connection."""
    name = unique(CONTAINER_PREFIX)
    try:
        docker(*proxy_argv(lab.root, name, lab.agent_net, lab.egress_net,
                           alias="vigia-proxy-eager", confdir=lab.proxy_ca_dir,
                           env=("T06_STRATEGY=eager",)))  # fmt: skip
        docker("start", name)
        wait_for_line(name, PROXY_READY)
        result = run_client(lab, "https", "vigia-proxy-eager:8080", "eager.fake.test", "/eager")
    finally:
        docker("rm", "--force", name, check=False)
    assert result["ok"] and result["status"] == 200, result
    before, _ = accepts_seen_by_the_hook(result)
    assert result["body"]["accept"] <= before


# P7: what mitmproxy 12.2.3 does when a hook raises


def outcome_of(lab: Lab, host: str) -> tuple[dict, list[dict]]:
    result = run_client(lab, "https", PROXY, host, f"/{host.split('.')[0]}", "POST")
    time.sleep(0.5)
    return result, requests_to(fake_stats(lab), host)


def test_p7_a_raising_request_hook_lets_the_request_through(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """mitmproxy logs the exception and carries on: the request reaches the server, sync or
    async. This is why every hook of the real addon is wrapped (docs/21, section 4)."""
    for host in ("p7-sync.fake.test", "p7-async.fake.test"):
        result, reached = outcome_of(lab, host)
        report(
            record_property,
            f"{host}: request hook raises",
            f"client {result.get('status', result.get('error'))}, reached the server "
            f"{len(reached)} time(s)",
        )
        assert result["ok"] and result["status"] == 200, result
        assert len(reached) == 1
    logs = proxy_logs(lab)
    assert "t06 sync request hook failure" in logs
    assert "t06 async request hook failure" in logs


def test_p7_a_raising_server_connect_hook(
    lab: Lab, record_property: Callable[[str, object], None]
) -> None:
    """Records what a raising server_connect does (the hook where docs/21 checks the IP)."""
    result, reached = outcome_of(lab, "p7-connect.fake.test")
    outcome = (
        f"client {result.get('status', result.get('error'))}, reached the server "
        f"{len(reached)} time(s)"
    )
    report(record_property, "server_connect raises", outcome)
    assert "t06 server_connect hook failure" in proxy_logs(lab)
    assert result["ok"] and result["status"] == 200 and len(reached) == 1, outcome


def test_p7_the_wrapper_answers_502_and_nothing_leaves(lab: Lab) -> None:
    """The wrapper of docs/21: on any error the hook answers 502 itself. Nothing reaches the
    server."""
    result, reached = outcome_of(lab, "p7-wrapped.fake.test")
    assert result["ok"] and result["status"] == 502, result
    assert reached == []


# P8: changing server.address in server_connect, keeping the SNI


@pytest.mark.parametrize("host", ["p8.fake.test", "p8-sni.fake.test"])
def test_p8_server_connect_can_pin_the_checked_ip(
    lab: Lab, host: str, record_property: Callable[[str, object], None]
) -> None:
    """The hook resolves the name, then sets ``server.address`` to (that IP, 8443). The proxy
    connects there, sends the name as SNI and in Host, and verifies the certificate against
    the name. ``p8`` leaves ``server.sni`` alone; ``p8-sni`` sets it explicitly."""
    result = run_client(lab, "https", PROXY, host, "/p8")
    report(
        record_property,
        f"{host}",
        {k: v for k, v in result.get("headers", {}).items() if k.startswith("x-t06")} or result,
    )
    assert result["ok"] and result["status"] == 200, result
    body = result["body"]
    assert body["listener"] == "8443"
    assert body["sni"] == host
    assert body["host"] == host
    assert result["headers"]["x-t06-address-set"] == f"{lab.fake_ip}:8443"
    assert result["headers"]["x-t06-sni-sent"] == host


# P9: OpenClaw reaches the fake model through the proxy, trusting the CA by NODE_EXTRA_CA_CERTS

MODEL_HOST = "model.fake.test"
FAKE_PROVIDER = "t06-fake"
FAKE_MODEL = "fake-claude"
REPLY_TEXT = "T06 PONG FROM THE FAKE MODEL"  # proxy_fixtures/fake_internet.py
AGENT_CA_DIR = "/etc/vigia-ca"
PROXY_URL = f"http://{PROXY}"
# docs/21, sections 2 and 3: what T06-2 adds to the agent's _FIXED_ENV.
PROXY_ENV = (
    ("HTTP_PROXY", PROXY_URL),
    ("HTTPS_PROXY", PROXY_URL),
    ("http_proxy", PROXY_URL),
    ("https_proxy", PROXY_URL),
    ("OPENCLAW_PROXY_URL", PROXY_URL),
    ("NO_PROXY", "localhost,127.0.0.1,::1"),
    ("no_proxy", "localhost,127.0.0.1,::1"),
    ("NODE_USE_ENV_PROXY", "1"),
    ("NODE_EXTRA_CA_CERTS", f"{AGENT_CA_DIR}/ca.pem"),
    ("SSL_CERT_FILE", f"{AGENT_CA_DIR}/ca.pem"),
    ("REQUESTS_CA_BUNDLE", f"{AGENT_CA_DIR}/ca.pem"),
    ("CURL_CA_BUNDLE", f"{AGENT_CA_DIR}/ca.pem"),
    ("GIT_SSL_CAINFO", f"{AGENT_CA_DIR}/ca.pem"),
)
OPENCLAW_TURN_TIMEOUT = 240.0


@dataclass(frozen=True)
class OpenClawFiles:
    """What both OpenClaw containers of P9 share: the jail's config (with the fake provider)
    and the agent CA's folder."""

    config: AgentJailConfig
    agent_ca: Path
    fake_key: str


@dataclass(frozen=True)
class OpenClaw:
    name: str
    fake_key: str


def openclaw_test_config(base: dict, fake_key: str) -> dict:
    """The jail's openclaw.json plus a custom Anthropic-compatible provider at the fake model,
    with the fake key as a literal ``apiKey`` (investigador-openclaw, 2026-10-17)."""
    config = json.loads(json.dumps(base))
    config["models"]["mode"] = "merge"
    config["models"]["providers"] = {
        FAKE_PROVIDER: {
            "baseUrl": f"https://{MODEL_HOST}",
            "api": "anthropic-messages",
            "apiKey": fake_key,
            "auth": "api-key",
            "models": [
                {
                    "id": FAKE_MODEL,
                    "name": "Fake Claude",
                    "input": ["text"],
                    "contextWindow": 200000,
                    "maxTokens": 8192,
                }
            ],
        }
    }
    config["agents"]["defaults"]["model"] = {"primary": f"{FAKE_PROVIDER}/{FAKE_MODEL}"}
    return config


@pytest.fixture(scope="module")
def openclaw_files(lab: Lab, tmp_path_factory: pytest.TempPathFactory) -> OpenClawFiles:
    if docker("image", "inspect", IMAGE, check=False).returncode != 0:
        docker("pull", "--quiet", IMAGE, timeout=1800)
    base = tmp_path_factory.mktemp("t06-openclaw")
    workspace, config_dir, agent_ca = base / "workspace", base / "config", base / "agent-ca"
    workspace.mkdir()
    agent_ca.mkdir()
    shutil.copyfile(lab.t06_dir / "agent-ca.pem", agent_ca / "ca.pem")
    (agent_ca / "ca.pem").chmod(0o444)
    agent_ca.chmod(0o555)
    config = AgentJailConfig(
        workspace=workspace,
        config_dir=config_dir,
        gateway_token=secrets.token_urlsafe(32),
        name=unique(CONTAINER_PREFIX),
        network=lab.agent_net,
        uid=os.getuid(),
        gid=os.getgid(),
        allow_shared_ids=True,
    )
    jail = AgentJail(config)
    jail.prepare_workspace()
    jail.write_config()
    fake_key = f"vigia-fake-anthropic-{secrets.token_hex(16)}"
    config.config_file.write_text(
        json.dumps(openclaw_test_config(openclaw_config(config), fake_key), indent=2)
    )
    return OpenClawFiles(config=config, agent_ca=agent_ca, fake_key=fake_key)


@contextmanager
def openclaw_container(files: OpenClawFiles, *, gateway: bool) -> Iterator[OpenClaw]:
    """The real OpenClaw with the jail's own argv (vigia/jail/config.py) on the lab's agent
    network, plus docs/21's variables and the agent CA in /etc/vigia-ca. With ``gateway`` it
    runs the Gateway, as the jail does; without, only ``sleep``, for embedded turns
    (``--local`` refuses to run next to a Gateway, and both at once do not fit in 2 GB)."""
    config = replace(files.config, name=unique(CONTAINER_PREFIX))
    argv = docker_create_argv(config)
    entry = argv.index("--entrypoint")
    extra = ["--volume", f"{files.agent_ca}:{AGENT_CA_DIR}:ro,z"]
    for name, value in PROXY_ENV:
        extra += ["--env", f"{name}={value}"]
    argv[entry:entry] = extra
    if not gateway:
        argv = [*argv[: argv.index(config.image) + 1], "-s", "--", "sleep", "infinity"]
    try:
        jail_docker.run(argv, env=token_env(config))
        docker("start", config.name)
        if gateway:
            AgentJail(config).wait_ready()
        yield OpenClaw(name=config.name, fake_key=files.fake_key)
    finally:
        docker("rm", "--force", config.name, check=False)


def openclaw_turn(
    claw: OpenClaw, *, local: bool, env: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """One turn of ``openclaw agent --agent main --message``. Through the Gateway (the way the
    jail runs it: the call leaves from the Gateway's process, with the container's env), or
    embedded with ``--local`` (the call leaves from this CLI process, so ``env`` can change its
    variables), on a fresh state folder in /tmp."""
    argv = ["exec", "--user", f"{os.getuid()}:{os.getgid()}"]
    if local:
        argv += ["--env", f"OPENCLAW_STATE_DIR=/tmp/t06-state-{uuid4().hex[:8]}"]
    for item in env:
        argv += ["--env", item]
    argv += [claw.name, "node", "openclaw.mjs", "agent", "--agent", "main"]
    argv += ["--local"] if local else []
    argv += ["--message", "Say the test phrase.", "--json"]
    return docker(*argv, timeout=OPENCLAW_TURN_TIMEOUT, check=False)


def model_calls(lab: Lab, since: int) -> list[dict]:
    return requests_to(fake_stats(lab), MODEL_HOST)[since:]


def assert_turn_reached_the_fake_model(
    claw: OpenClaw, result: subprocess.CompletedProcess[str], calls: list[dict]
) -> None:
    text = jail_docker.sanitize(result.stdout + result.stderr)
    assert result.returncode == 0, text
    assert REPLY_TEXT in result.stdout, text
    assert calls, "the fake model saw no request"
    for call in calls:
        assert call["method"] == "POST"
        assert call["path"] == "/v1/messages"
        assert call["sni"] == MODEL_HOST
        assert call["headers"].get("x-api-key") == claw.fake_key
        assert "authorization" not in call["headers"]


# Class scope: each container lives only while its class runs, so the two never run together.
@pytest.fixture(scope="class")
def gateway_claw(openclaw_files: OpenClawFiles) -> Iterator[OpenClaw]:
    with openclaw_container(openclaw_files, gateway=True) as claw:
        yield claw


@pytest.fixture(scope="class")
def embedded_claw(openclaw_files: OpenClawFiles) -> Iterator[OpenClaw]:
    with openclaw_container(openclaw_files, gateway=False) as claw:
        yield claw


@pytest.fixture
def claw(request: pytest.FixtureRequest) -> OpenClaw:
    """The class's own container (its ``container`` attribute names the fixture)."""
    return request.getfixturevalue(request.cls.container)


class TestP9Gateway:
    """OpenClaw as the jail runs it: the Gateway, with the container's variables."""

    container = "gateway_claw"

    def test_openclaw_reaches_the_fake_model_through_the_proxy(
        self, lab: Lab, claw: OpenClaw, record_property: Callable[[str, object], None]
    ) -> None:
        """``openclaw agent --message`` through the Gateway calls the fake Anthropic: only
        through the proxy (the agent has no other way out), trusting the proxy's certificate
        through NODE_EXTRA_CA_CERTS, with the literal fake key of openclaw.json in
        ``x-api-key``. The CLI's connection to the Gateway on loopback stays out of the proxy
        (NO_PROXY)."""
        since = len(requests_to(fake_stats(lab), MODEL_HOST))
        start = time.monotonic()
        result = openclaw_turn(claw, local=False)
        took = time.monotonic() - start
        calls = model_calls(lab, since)
        memory = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", claw.name).stdout
        report(
            record_property,
            "openclaw turn through the Gateway",
            f"{took:.1f} s, {len(calls)} model call(s), user-agent "
            f"{calls[0]['headers'].get('user-agent') if calls else None}, "
            f"container memory {memory.strip()}",
        )
        assert_turn_reached_the_fake_model(claw, result, calls)

    @pytest.mark.parametrize(
        "argv",
        [
            ["curl", "-sS", "--max-time", "20", "https://plain.fake.test/p9-curl"],
            [
                "python3",
                "-c",
                "import urllib.request as u; print(u.urlopen('https://plain.fake.test/p9-py',"
                " timeout=20).read().decode())",
            ],
        ],
        ids=["curl", "python"],
    )
    def test_commands_in_the_agent_use_the_proxy_and_the_ca(
        self, claw: OpenClaw, argv: list[str]
    ) -> None:
        """What ``exec`` would run sees the same variables: curl (lowercase https_proxy and
        CURL_CA_BUNDLE) and Python (HTTPS_PROXY and SSL_CERT_FILE) get through the proxy."""
        result = docker(
            "exec", "--user", f"{os.getuid()}:{os.getgid()}", claw.name, *argv,
            timeout=60, check=False,
        )  # fmt: skip
        assert result.returncode == 0, jail_docker.sanitize(result.stdout + result.stderr)
        body = json.loads(result.stdout)
        assert body["sni"] == "plain.fake.test"
        assert body["path"] in ("/p9-curl", "/p9-py")


class TestP9Embedded:
    """Embedded turns (``--local``), whose variables each test can change."""

    container = "embedded_claw"

    @pytest.mark.parametrize(
        "env",
        [
            (),
            ("NODE_USE_ENV_PROXY=0",),
            ("NODE_USE_ENV_PROXY=0", "OPENCLAW_PROXY_URL="),
        ],
        ids=["all-variables", "no-node-use-env-proxy", "only-https-proxy"],
    )
    def test_which_variables_openclaw_needs(
        self,
        lab: Lab,
        claw: OpenClaw,
        env: tuple[str, ...],
        record_property: Callable[[str, object], None],
    ) -> None:
        """OpenClaw does not need NODE_USE_ENV_PROXY (it installs its own undici dispatcher),
        nor OPENCLAW_PROXY_URL (HTTPS_PROXY is enough). docs/21 keeps both: the first for the
        agent's own node scripts, the second for OpenClaw's managed proxy."""
        since = len(requests_to(fake_stats(lab), MODEL_HOST))
        start = time.monotonic()
        result = openclaw_turn(claw, local=True, env=env)
        took = time.monotonic() - start
        calls = model_calls(lab, since)
        proxy_lines = [line for line in result.stderr.splitlines() if "[proxy]" in line]
        report(
            record_property,
            f"embedded turn with {env or 'all variables'}",
            f"exit {result.returncode}, {took:.1f} s, {proxy_lines}",
        )
        assert_turn_reached_the_fake_model(claw, result, calls)

    def test_control_without_proxy_variables_openclaw_has_no_way_out(
        self, lab: Lab, claw: OpenClaw, record_property: Callable[[str, object], None]
    ) -> None:
        """Control: with every proxy variable emptied the same embedded turn fails and the
        fake model sees nothing. The proxy is the only way, and what reached the model went
        through it."""
        empty = tuple(f"{name}=" for name, _ in PROXY_ENV if "PROXY" in name.upper())
        since = len(requests_to(fake_stats(lab), MODEL_HOST))
        result = openclaw_turn(claw, local=True, env=(*empty, "NODE_USE_ENV_PROXY=0"))
        calls = model_calls(lab, since)
        tail = jail_docker.sanitize((result.stdout + result.stderr)[-500:])
        report(record_property, "without proxy variables", f"exit {result.returncode}: {tail}")
        assert REPLY_TEXT not in result.stdout
        assert "is not running" not in result.stdout + result.stderr
        assert calls == []
