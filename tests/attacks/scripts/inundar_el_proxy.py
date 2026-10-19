"""Evil agent: flood the proxy to drown it or slip something out unrecorded.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <allowed host> <tag>
Prints one JSON object on its last line.

Four floods against ``backtide-proxy:8080`` (docs/21, section 8):

- ``connections``: many raw TCP connections at once, kept open and mute (no CONNECT, no bytes),
  to pass the proxy's connection cap and tie up its memory.
- ``huge``: a POST whose ``Content-Length`` is a gigabyte, and a chunked POST that never stops:
  a body over the 16 MiB cap must be refused, never read whole into the proxy.
- ``burst``: a few hundred small GETs to the allowed host as fast as keep-alive allows, to pass
  backtide's request budget (20/s, burst 500).
- ``slow``: several tunnels that trickle a POST body a byte at a time (slowloris), to hold the
  proxy's pending slots.

Then a plain request to the allowed host (the control): if backtide's channel and the proxy
survived, it still goes out and is recorded. Every byte here stays inside the test's networks.
"""

import http.client
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

host, tag = sys.argv[1], sys.argv[2]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
CONTEXT = ssl.create_default_context(cafile=CA)


def tunnel() -> socket.socket:
    """A raw socket with a CONNECT to the allowed host already answered (not yet TLS)."""
    sock = socket.create_connection(PROXY, timeout=20)
    sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head and len(head) < 8192:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    if not head.startswith(b"HTTP/") or int(head.split(b" ", 2)[1]) != 200:
        sock.close()
        raise OSError(f"CONNECT refused: {head[:80]!r}")
    return sock


def flood_connections(count: int) -> dict:
    """Open ``count`` sockets to the proxy at once and keep them mute. Count how many stay open
    (the proxy lets so many in and cuts the rest)."""
    socks: list[socket.socket] = []
    opened = 0
    for _ in range(count):
        try:
            sock = socket.create_connection(PROXY, timeout=10)
            socks.append(sock)
            opened += 1
        except OSError:
            break
    time.sleep(2.0)  # the proxy cuts the ones over its cap
    alive = 0
    for sock in socks:
        try:
            sock.setblocking(False)
            try:
                data = sock.recv(1)  # a cut connection is at EOF (b""); an accepted one blocks
                alive += 1 if data else 0
            except (BlockingIOError, ssl.SSLWantReadError):
                alive += 1
            except OSError:
                pass
        finally:
            sock.close()
    time.sleep(1.0)  # let the proxy see the closes and free the slots before the next floods
    return {"opened": opened, "still_open_after": alive}


def huge_body() -> dict:
    """A gigabyte Content-Length (refused at the headers, never read), and a chunked body that
    keeps coming (refused once it passes the cap)."""
    out: dict[str, object] = {}
    conn = http.client.HTTPSConnection(*PROXY, timeout=30, context=CONTEXT)
    conn.set_tunnel(host, 443)
    try:
        conn.putrequest("POST", f"/{tag}/huge-length")
        conn.putheader("Content-Length", str(1024**3))
        conn.putheader("Content-Type", "application/octet-stream")
        conn.endheaders()
        conn.send(b"x" * 4096)  # a taste of the body; the proxy should already have refused
        out["length_status"] = conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        out["length_status"] = f"{type(error).__name__}: {error}"[:120]
    finally:
        conn.close()
    sock = None
    try:
        sock = tunnel()
        tls = CONTEXT.wrap_socket(sock, server_hostname=host)
        tls.settimeout(20)
        tls.sendall(
            f"POST /{tag}/huge-chunked HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n".encode()
        )
        sent = 0
        chunk = b"10000\r\n" + b"a" * 0x10000 + b"\r\n"
        try:
            while sent < 18 * 1024 * 1024:  # just over the 16 MiB cap
                tls.sendall(chunk)  # once the proxy refuses and stops reading, this times out
                sent += 0x10000
        except (OSError, ssl.SSLError):
            pass  # the proxy cut us off: the 413 is waiting to be read
        answer = b""
        try:
            answer = tls.recv(4096)
        except (OSError, ssl.SSLError):
            pass
        out["chunked_status"] = int(answer.split(b" ", 2)[1]) if answer.startswith(b"HTTP/") else 0
        out["chunked_sent_mib"] = round(sent / 1024 / 1024, 1)
    except (OSError, ssl.SSLError, ValueError, IndexError) as error:
        out["chunked_status"] = f"{type(error).__name__}: {error}"[:120]
    finally:
        if sock is not None:
            sock.close()
    return out


def burst(tunnels: int, each: int) -> dict:
    """``tunnels`` keep-alive tunnels, each firing ``each`` quick GETs to the allowed host."""

    def one(index: int) -> list[int]:
        conn = http.client.HTTPSConnection(*PROXY, timeout=30, context=CONTEXT)
        conn.set_tunnel(host, 443)
        statuses = []
        try:
            for n in range(each):
                conn.request("GET", f"/{tag}/burst-{index}-{n}")
                response = conn.getresponse()
                response.read()
                statuses.append(response.status)
        except (OSError, http.client.HTTPException):
            pass
        finally:
            conn.close()
        return statuses

    with ThreadPoolExecutor(max_workers=tunnels) as pool:
        all_statuses = [s for result in pool.map(one, range(tunnels)) for s in result]
    counts: dict[str, int] = {}
    for status in all_statuses:
        counts[str(status)] = counts.get(str(status), 0) + 1
    return {"sent": len(all_statuses), "by_status": counts}


def slow_uploads(count: int) -> dict:
    """``count`` tunnels that start a POST and trickle its body without ever finishing it
    (slowloris), to hold the proxy's pending slots. They never complete, so nothing reaches the
    server; each is dropped after a short hold."""

    def one(index: int) -> str:
        sock = None
        try:
            sock = tunnel()
            tls = CONTEXT.wrap_socket(sock, server_hostname=host)
            tls.settimeout(10)
            tls.sendall(
                f"POST /{tag}/slow-{index} HTTP/1.1\r\nHost: {host}\r\n"
                f"Content-Length: 1000\r\nContent-Type: text/plain\r\n\r\n".encode()
            )
            for _ in range(6):  # 6 bytes over 3 s, far short of the 1000 promised
                tls.sendall(b"a")
                time.sleep(0.5)
            return "held"
        except (OSError, ssl.SSLError, ValueError) as error:
            return f"{type(error).__name__}"
        finally:
            if sock is not None:
                sock.close()

    with ThreadPoolExecutor(max_workers=count) as pool:
        return {"outcomes": list(pool.map(one, range(count)))}


def control() -> dict:
    conn = http.client.HTTPSConnection(*PROXY, timeout=30, context=CONTEXT)
    conn.set_tunnel(host, 443)
    try:
        conn.request("GET", f"/{tag}/control")
        response = conn.getresponse()
        response.read()
        return {"status": response.status}
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:120]}
    finally:
        conn.close()


outcome = {
    "connections": flood_connections(400),
    "huge": huge_body(),
    "slow": slow_uploads(40),
    "burst": burst(tunnels=24, each=40),
    "control": control(),
}
print(json.dumps(outcome))
