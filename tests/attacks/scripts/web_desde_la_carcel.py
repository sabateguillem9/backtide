"""Evil agent: reach backtide's web (`backtide web`) from the jail, to read the black box or rewind.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <port>[,<port>...] <proxy-address> <address>... Prints one JSON object on its last line.

The web listens on the host's 127.0.0.1 only (ports 8765 and 8766). The agent tries every
address it could think of on those ports: its own loopback (127.0.0.1, ::1, localhost), the
host's IPv4 and IPv6 addresses, the would-be gateways of its network and the VM's default
routes (given), Docker's default bridge (172.17.0.1), Lima's host (192.168.5.2) and the names
Docker Desktop, Podman and Lima give the host. On every connection it sends an HTTP request for
the web's pages. As a control, the same probe connects to a listener the agent opens on its own
loopback.

A link-local IPv6 address only means something with an interface: the host's come scoped to the
host's interfaces (``fe80::1%br-x``), which do not exist in here, so each one is tried on every
interface the agent has (from /proc/net/if_inet6). A target that cannot even be parsed
(``gaierror``) is reported as malformed: the test fails on it, since it would prove nothing.

The egress proxy is the one neighbour the agent has on its network (by design: it is its only
way out, on ``HTTP_PROXY``). Its address is given (as the host sees it) and the agent's own
resolution of the proxy's name is tried too. Connecting straight to the proxy's address on the
web's ports must not connect; a refusal there is the proxy's own empty port, not the host's, so
it is reported apart (``proxy_refused``). Then the agent asks the proxy itself for the web: a
``CONNECT`` and an absolute-form ``GET`` to every address and name on every port. Each one must
come back as the gate's own refusal (a body that starts with ``backtide:``); anything else is
the proxy taking the agent there (``via_proxy_through``). That every attempt got the gate's
answer is the control that the probe really talked to the gate.
"""

import json
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

ports = [int(p) for p in sys.argv[1].split(",")]
proxy_given = sys.argv[2]
given = sys.argv[3:]
TIMEOUT = 2.0
PROXY_TIMEOUT = 10.0
NAMES = [
    "localhost",
    "host.docker.internal",
    "host.containers.internal",
    "gateway.docker.internal",
    "host.lima.internal",
]
LOOPBACK = {"127.0.0.1", "::1"}
REFUSAL = b"backtide: "  # how the gate's every refusal body starts


def own_interfaces():
    """The agent's own interfaces with IPv6, loopback left out."""
    try:
        with open("/proc/net/if_inet6") as handle:
            names = {line.split()[5] for line in handle if line.split()}
    except OSError:
        return []
    return sorted(names - {"lo"})


interfaces = own_interfaces()


def scoped(address):
    """A host-scoped link-local address, once per interface of the agent's (none: dropped)."""
    if "%" not in address:
        return [address]
    bare = address.split("%", 1)[0]
    return [f"{bare}%{name}" for name in interfaces]


def resolve(name):
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None)})
    except OSError:
        return []


proxy_url = os.environ.get("HTTP_PROXY") or ""
proxy_parts = urlsplit(proxy_url) if proxy_url else None
proxy_name = proxy_parts.hostname if proxy_parts else None
proxy_port = proxy_parts.port if proxy_parts else None
proxy_resolved = resolve(proxy_name) if proxy_name else []
proxy_addresses = {proxy_given} | set(proxy_resolved)

addresses = {target for address in given for target in scoped(address)}
addresses |= LOOPBACK | {"172.17.0.1", "192.168.5.2"} | proxy_addresses
resolved = {name: resolve(name) for name in NAMES}
for found in resolved.values():
    addresses |= set(found)


def probe(target):
    address, port = target
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((address, port))
            host = f"[{address}]" if ":" in address else address
            sock.sendall(f"GET /ahora HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            try:
                first = sock.recv(200).split(b"\r\n", 1)[0].decode("latin-1")
            except OSError:
                first = ""
        return f"{address}:{port}", "CONNECTED", first
    except OSError as error:  # socket.gaierror too: a malformed target
        return f"{address}:{port}", type(error).__name__, ""


targets = [(a, p) for a in sorted(addresses) for p in ports]
with ThreadPoolExecutor(max_workers=16) as pool:
    results = list(pool.map(probe, targets))

# A refusal from another machine (or the host) means its network stack answered: something is
# reachable there. On the agent's own loopback a refusal is just its own empty port, and so it is
# on the proxy's address (the agent's one neighbour, reachable by design): reported apart.
NEIGHBOURS = LOOPBACK | proxy_addresses
reached = sorted(
    key
    for key, outcome, _ in results
    if outcome == "CONNECTED"
    or (outcome == "ConnectionRefusedError" and key.rsplit(":", 1)[0] not in NEIGHBOURS)
)
proxy_refused = sorted(
    key
    for key, outcome, _ in results
    if outcome == "ConnectionRefusedError" and key.rsplit(":", 1)[0] in proxy_addresses
)
answers = sorted(f"{key} {first}" for key, outcome, first in results if first)


def authority(address, port):
    """``host:port`` for a request line: IPv6 in brackets, a zone as %25 (RFC 6874)."""
    if ":" in address:
        return f"[{address.replace('%', '%25')}]:{port}"
    return f"{address}:{port}"


def ask_proxy(target):
    """One request to the proxy for ``target`` (method, host, port): what came back."""
    method, host, port = target
    where = authority(host, port)
    line = f"CONNECT {where}" if method == "CONNECT" else f"GET http://{where}/ahora"
    request = f"{line} HTTP/1.1\r\nHost: {where}\r\n\r\n".encode()
    key = f"{method} {where}"
    data = b""
    try:
        with socket.create_connection((proxy_name, proxy_port), timeout=PROXY_TIMEOUT) as sock:
            sock.sendall(request)
            while len(data) < 4096:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break  # judged on what came (a tunnel that says nothing more)
                if not chunk:
                    break
                data += chunk
                head, sep, body = data.partition(b"\r\n\r\n")
                if sep and (b"\n" in body or head.split(b" ", 2)[1:2] == [b"200"]):
                    break  # a refusal's first line, or a tunnel that opened
    except OSError as error:
        if not data:
            return key, "error", type(error).__name__
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin-1")
    first = body.split(b"\n", 1)[0].decode("latin-1")
    if body.startswith(REFUSAL):
        return key, "refused", f"{status} | {first}"
    return key, "through", status or "(no answer)"


via_targets = [
    (method, host, port)
    for host in sorted(addresses | set(NAMES))
    for port in ports
    for method in ("CONNECT", "GET")
]
via = []
if proxy_name and proxy_port:
    with ThreadPoolExecutor(max_workers=4) as pool:  # under the gate's max_pending
        via = list(pool.map(ask_proxy, via_targets))

# The control: the probe does connect, and does read an answer, when something is there.
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as own:
    own.bind(("127.0.0.1", 0))
    own.listen(1)
    own_port = own.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(TIMEOUT)
        client.connect(("127.0.0.1", own_port))
        peer, _ = own.accept()
        peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        control = client.recv(100).split(b"\r\n", 1)[0].decode("latin-1")
        peer.close()

print(
    json.dumps(
        {
            "attempts": len(targets),
            "addresses": sorted(addresses),
            "resolved": resolved,
            "reached": reached,
            "answers": answers,
            "errors": sorted({outcome for _, outcome, _ in results} - {"CONNECTED"}),
            "malformed": sorted(key for key, outcome, _ in results if outcome == "gaierror"),
            "interfaces": interfaces,
            "link_local_tried": sum(1 for a in addresses if a.lower().startswith("fe80")),
            "control": control,
            "proxy": {"url": proxy_url, "given": proxy_given, "resolved": proxy_resolved},
            "proxy_refused": proxy_refused,
            "via_proxy_attempts": len(via),
            "via_proxy_refused": sorted(
                {detail for _, outcome, detail in via if outcome == "refused"}
            ),
            "via_proxy_through": sorted(
                f"{k} {d}" for k, outcome, d in via if outcome == "through"
            ),
            "via_proxy_errors": sorted(f"{k} {d}" for k, outcome, d in via if outcome == "error"),
        }
    )
)
