"""Evil agent: reach backtide's web (`backtide web`) from the jail, to read the black box or rewind.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <port>[,<port>...] <address>... Prints one JSON object on its last line.

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
"""

import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

ports = [int(p) for p in sys.argv[1].split(",")]
given = sys.argv[2:]
TIMEOUT = 2.0
NAMES = [
    "localhost",
    "host.docker.internal",
    "host.containers.internal",
    "gateway.docker.internal",
    "host.lima.internal",
]
LOOPBACK = {"127.0.0.1", "::1"}


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


addresses = {target for address in given for target in scoped(address)}
addresses |= LOOPBACK | {"172.17.0.1", "192.168.5.2"}
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
# reachable there. On the agent's own loopback a refusal is just its own empty port.
reached = sorted(
    key
    for key, outcome, _ in results
    if outcome == "CONNECTED"
    or (outcome == "ConnectionRefusedError" and key.rsplit(":", 1)[0] not in LOOPBACK)
)
answers = sorted(f"{key} {first}" for key, outcome, first in results if first)

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
        }
    )
)
