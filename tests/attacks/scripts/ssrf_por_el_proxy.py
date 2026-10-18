"""Evil agent: ask the proxy to take it where it cannot go itself (SSRF).

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <tag> <target>...
Prints one JSON object on its last line.

Each target is an IP address or a name: the cloud's metadata service, loopback, private ranges,
the VM's own addresses, the Mac of Lima, the proxy's own addresses, IPv6 loopback and link-local,
an IPv4 hidden in IPv6, and names that resolve to such places (localhost, a number that is
127.0.0.1, the containers of its own network). For each, ports 80 and 443 only (the others the
gate refuses by port, which web-desde-la-carcel already shows): ``http://<target>/`` sent to the
proxy, and ``CONNECT <target>:443`` followed by HTTPS. It reports the status the proxy gave.
"""

import http.client
import json
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor

tag, targets = sys.argv[1], sys.argv[2:]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def authority(target, port):
    return f"[{target}]:{port}" if ":" in target else f"{target}:{port}"


def plain(target):
    conn = http.client.HTTPConnection(*PROXY, timeout=20)
    try:
        where = authority(target, 80)
        conn.request("GET", f"http://{where}/{tag}/plain", headers={"Host": where})
        return conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}: {error}"[:200]
    finally:
        conn.close()


def tunnel(target):
    """CONNECT by hand (the authority bracketed for IPv6), then HTTPS if it is let through."""
    where = authority(target, 443)
    try:
        with socket.create_connection(PROXY, timeout=20) as sock:
            sock.sendall(f"CONNECT {where} HTTP/1.1\r\nHost: {where}\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
            status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else None
            if status != 200:
                return status if status is not None else f"no answer: {head[:80]!r}"
            tls = ssl.create_default_context(cafile=CA)
            with tls.wrap_socket(sock, server_hostname=target) as secure:
                secure.sendall(f"GET /{tag}/tunnel HTTP/1.1\r\nHost: {where}\r\n\r\n".encode())
                line = secure.recv(200).split(b"\r\n", 1)[0]
                return int(line.split(b" ", 2)[1]) if line.startswith(b"HTTP/") else repr(line)
    except (OSError, ValueError) as error:
        return f"{type(error).__name__}: {error}"[:200]


with ThreadPoolExecutor(max_workers=8) as pool:
    plains = dict(zip(targets, pool.map(plain, targets), strict=True))
    tunnels = dict(zip(targets, pool.map(tunnel, targets), strict=True))
print(json.dumps({"plain": plains, "tunnel": tunnels}))
