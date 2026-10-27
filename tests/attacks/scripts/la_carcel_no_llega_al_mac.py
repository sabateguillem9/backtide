"""Evil agent: reach the Mac that runs backtide's VM (T13b), straight, not through the proxy.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <port>[,<port>...] <address>... Prints one JSON object on its last line.

On a Mac, Lima gives the VM the host at 192.168.5.2 (``host.lima.internal``): from the VM, that
address is the Mac's own 127.0.0.1, where the person's other services listen (a local model, a
dev server, backtide's forwarded web). The VM may reach it; the agent must not even have a route.
The agent looks up the name, then tries every port on every address (and the name's answer).
Stopped means the kernel's "no route" at once (ENETUNREACH or EHOSTUNREACH), never a timeout
or a refusal: a refusal is something answering.
"""

import errno
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

ports = [int(p) for p in sys.argv[1].split(",")]
addresses = list(sys.argv[2:])
NAME = "host.lima.internal"
TIMEOUT = 3.0

try:
    resolved = sorted({info[4][0] for info in socket.getaddrinfo(NAME, None, socket.AF_INET)})
    name_result = resolved
except OSError as error:
    resolved = []
    name_result = type(error).__name__


def connect(target):
    address, port = target
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(TIMEOUT)
            probe.connect((address, port))
        return f"{address}:{port}", "CONNECTED"
    except ConnectionRefusedError:
        return f"{address}:{port}", "ECONNREFUSED"
    except TimeoutError:
        return f"{address}:{port}", "TIMEOUT"
    except OSError as error:
        return f"{address}:{port}", errno.errorcode.get(error.errno or 0, type(error).__name__)


targets = [(a, p) for a in sorted(set(addresses) | set(resolved)) for p in ports]
with ThreadPoolExecutor(max_workers=16) as pool:
    results = dict(pool.map(connect, targets))
with open("/proc/net/route") as handle:
    # interface, destination and mask, as the kernel writes them (hex, little-endian)
    routes = [
        [f[0], f[1], f[7]] for f in (line.split() for line in handle.read().splitlines()[1:]) if f
    ]
print(
    json.dumps(
        {
            "name": name_result,
            "attempts": len(results),
            "outcomes": sorted(set(results.values())),
            "not_unreachable": sorted(
                k for k, v in results.items() if v not in ("ENETUNREACH", "EHOSTUNREACH")
            ),
            "routes": routes,
        }
    )
)
