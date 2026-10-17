"""The test's client for the T06-1 checks: what an agent would do, one command per call.

Runs in a throwaway container of the pinned mitmproxy image (``docker exec <c> python3
/opt/t06/client.py ...``): the standard library plus ``h2``, which mitmproxy ships. It trusts
only the CA it is given (the agent's), like the agent with SSL_CERT_FILE. Every command prints
one JSON line, with ``"ok": false`` and the error instead of a traceback.

- ``https <proxy host:port> <host> <path> [POST]``: HTTP/1.1 through the proxy's CONNECT.
- ``h2 <proxy host:port> <host> <path>``: the same over HTTP/2 (ALPN offers h2 first).
- ``unix <socket path> <line>``: send one line to a Unix socket, read one line back.
- ``listen <socket path>``: listen on a Unix socket (mode 0666: the test user connects),
  read one line from the first client, answer ``ack`` (P3's plan B).
- ``resolve <name>``: getaddrinfo, through the container's resolver.
- ``dns <server ip> <name>``: one UDP query straight to ``server ip`` (the control of P5).
"""

import json
import socket
import ssl
import struct
import sys
from http.client import HTTPSConnection

AGENT_CA = "/opt/t06/agent-ca.pem"
TIMEOUT = 20


def context(alpn: list[str]) -> ssl.SSLContext:
    tls = ssl.create_default_context(cafile=AGENT_CA)  # only this CA, no system store
    tls.set_alpn_protocols(alpn)
    return tls


def issuer_of(sock: ssl.SSLSocket) -> str:
    cert = sock.getpeercert() or {}
    names = [value for rdn in cert.get("issuer", ()) for key, value in rdn if key == "commonName"]
    return names[0] if names else ""


def https(proxy: str, host: str, path: str, method: str = "GET") -> dict:
    proxy_host, _, proxy_port = proxy.rpartition(":")
    conn = HTTPSConnection(
        proxy_host, int(proxy_port), timeout=TIMEOUT, context=context(["http/1.1"])
    )
    conn.set_tunnel(host, 443)
    body = b'{"t06": "outgoing body"}' if method == "POST" else None
    headers = {"content-type": "application/json"} if body else {}
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    issuer = issuer_of(conn.sock)  # type: ignore[arg-type]
    conn.close()
    return {
        "ok": True,
        "status": response.status,
        "headers": {name.lower(): value for name, value in response.getheaders()},
        "body": _decode(data),
        "issuer": issuer,
    }


def h2(proxy: str, host: str, path: str) -> dict:
    import h2.config  # noqa: PLC0415 - only this command needs it
    import h2.connection  # noqa: PLC0415
    import h2.events  # noqa: PLC0415

    proxy_host, _, proxy_port = proxy.rpartition(":")
    raw = socket.create_connection((proxy_host, int(proxy_port)), timeout=TIMEOUT)
    raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    reply = b""
    while b"\r\n\r\n" not in reply:
        chunk = raw.recv(4096)
        if not chunk:
            raise ConnectionError("the proxy closed the CONNECT")
        reply += chunk
    if not reply.startswith(b"HTTP/1.1 200") and not reply.startswith(b"HTTP/1.0 200"):
        return {"ok": True, "status": "connect " + reply.split(b"\r\n", 1)[0].decode()}
    sock = context(["h2", "http/1.1"]).wrap_socket(raw, server_hostname=host)
    alpn = sock.selected_alpn_protocol()
    if alpn != "h2":
        return {"ok": False, "error": f"ALPN gave {alpn!r}, not h2"}
    conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    stream = conn.get_next_available_stream_id()
    conn.send_headers(
        stream,
        [(":method", "GET"), (":path", path), (":scheme", "https"), (":authority", host)],
        end_stream=True,
    )
    sock.sendall(conn.data_to_send())
    status, headers, data, done = None, {}, b"", False
    while not done:
        chunk = sock.recv(65536)
        if not chunk:
            break
        for event in conn.receive_data(chunk):
            if isinstance(event, h2.events.ResponseReceived):
                for name, value in event.headers:
                    name = name.decode() if isinstance(name, bytes) else name
                    value = value.decode() if isinstance(value, bytes) else value
                    if name == ":status":
                        status = int(value)
                    else:
                        headers[name] = value
            elif isinstance(event, h2.events.DataReceived):
                data += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded | h2.events.StreamReset):
                done = True
        sock.sendall(conn.data_to_send())
    issuer = issuer_of(sock)
    sock.close()
    return {
        "ok": True,
        "alpn": alpn,
        "status": status,
        "headers": headers,
        "body": _decode(data),
        "issuer": issuer,
    }


def unix(path: str, line: str) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect(path)
        sock.sendall(line.encode() + b"\n")
        reply = sock.makefile("rb").readline()
    return {"ok": True, "reply": reply.decode().strip()}


def listen(path: str) -> dict:
    import os  # noqa: PLC0415 - only this command needs it

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        os.chmod(path, 0o666)  # noqa: S103 - production: 0600, backtide connects as root
        server.listen(1)
        server.settimeout(TIMEOUT)
        conn, _ = server.accept()
        with conn:
            line = conn.makefile("rb").readline().decode().strip()
            conn.sendall(b"ack\n")
    os.unlink(path)
    return {"ok": True, "line": line}


def resolve(name: str) -> dict:
    infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    return {"ok": True, "addresses": sorted({info[4][0] for info in infos})}


def dns(server: str, name: str) -> dict:
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = struct.pack("!HHHHHH", 0x7406, 0x0100, 1, 0, 0, 0) + question + b"\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(packet, (server, 53))
        reply, _ = sock.recvfrom(4096)
    return {"ok": True, "rcode": reply[3] & 0x0F}


def _decode(data: bytes) -> object:
    try:
        return json.loads(data)
    except ValueError:
        return data.decode("utf-8", "replace")


COMMANDS = {
    "https": https,
    "h2": h2,
    "unix": unix,
    "listen": listen,
    "resolve": resolve,
    "dns": dns,
}


def main() -> None:
    command, *args = sys.argv[1:]
    try:
        result = COMMANDS[command](*args)
    except Exception as error:  # noqa: BLE001 - reported to the test as data
        result = {"ok": False, "error": f"{type(error).__name__}: {error}"}
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
