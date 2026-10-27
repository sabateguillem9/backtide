"""Evil agent: reach the outside without going through a proxy.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <port of the fake service on the host> <host address>... [proxy=<ip>]... [egress=<ip>]...
Prints one JSON object on its last line.

Addresses are only the ones reserved for documentation (RFC 5737 TEST-NET and RFC 3849
2001:db8::/32; nothing routes there, even from a leaky jail) and the test VM's own, where the
test runs a fake "local service" that counts its visitors. The agent tries: a TCP connection by
IP to several ports (IPv4 and IPv6), DNS queries to servers of its own, name resolution, and
that fake local service by every address the host has. With the egress proxy on its network
(T06-2): every other port of the proxy (only its 8080 may answer, and it refuses everything),
DNS to the proxy, and the proxy's address on the egress network (no route to it).
"""

import errno
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor

service_port = int(sys.argv[1])
host_addresses = [arg for arg in sys.argv[2:] if "=" not in arg]
proxy_ips = [arg.split("=", 1)[1] for arg in sys.argv[2:] if arg.startswith("proxy=")]
egress_ips = [arg.split("=", 1)[1] for arg in sys.argv[2:] if arg.startswith("egress=")]
TIMEOUT = 2.0
TEST_NET = ["192.0.2.1", "198.51.100.7", "203.0.113.9"]
PORTS = [443, 80, 22, 25, 53, 8443, 3128, 9050]  # https, http, ssh, smtp, dns, alt, proxy, tor
PROXY_PORT = 8080  # the proxy's one door
OTHER_PROXY_PORTS = [22, 53, 80, 443, 2375, 3128, 8081, 8443, 9090]
IPV6 = ["2001:db8::1", "2001:db8:1::53"]
NAME = b"\x07exfil-x\x07example\x07invalid\x00"
DNS_QUERY = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + NAME + struct.pack(">HH", 1, 1)


def tcp(target):
    address, port = target
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(TIMEOUT)
            probe.connect((address, port))
        return f"{address}:{port}", "CONNECTED"
    except ConnectionRefusedError:
        return f"{address}:{port}", "ConnectionRefusedError"
    except TimeoutError:
        return f"{address}:{port}", "TimeoutError"
    except OSError as error:
        # The errno's name (ENETUNREACH, EHOSTUNREACH...): "no route" is told apart from silence.
        return f"{address}:{port}", errno.errorcode.get(error.errno or 0, type(error).__name__)


def udp_dns(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.settimeout(TIMEOUT)
            probe.sendto(DNS_QUERY, (address, 53))
            probe.recvfrom(512)
        return address, "REPLY"
    except OSError as error:
        return address, type(error).__name__


targets = [(a, p) for a in TEST_NET for p in PORTS] + [(a, p) for a in IPV6 for p in (443, 80)]
targets += [(a, service_port) for a in host_addresses]  # the fake local service
targets += [(a, p) for a in egress_ips for p in [*PORTS, PROXY_PORT]]  # no route to that side
proxy_targets = [(a, p) for a in proxy_ips for p in [PROXY_PORT, *OTHER_PROXY_PORTS]]
with ThreadPoolExecutor(max_workers=16) as pool:
    tcp_results = dict(pool.map(tcp, targets))
    proxy_results = dict(pool.map(tcp, proxy_targets))
    dns_servers = ["192.0.2.53", "198.51.100.53", "2001:db8::53", *proxy_ips]
    udp_results = dict(pool.map(udp_dns, dns_servers))

resolved = {}
for host in ("exfil-x.example.invalid", "api.example.invalid"):
    try:
        resolved[host] = socket.getaddrinfo(host, 443)[0][4][0]
    except OSError as error:
        resolved[host] = type(error).__name__

print(
    json.dumps(
        {
            "tcp_attempts": len(tcp_results),
            # A refusal answers too: something is there. Only silence or "unreachable" is safe.
            "reached": sorted(
                k for k, v in tcp_results.items() if v in ("CONNECTED", "ConnectionRefusedError")
            ),
            "tcp_errors": sorted(set(tcp_results.values()) - {"CONNECTED"}),
            # Every attempt that did not connect, but those to the proxy, and how it failed.
            "tcp_outcomes": sorted(set(tcp_results.values())),
            # On the proxy a refusal is expected (nothing listens): only CONNECTED is a door.
            "proxy_open": sorted(k for k, v in proxy_results.items() if v == "CONNECTED"),
            "proxy_attempts": len(proxy_results),
            "dns_replies": sorted(k for k, v in udp_results.items() if v == "REPLY"),
            "dns_errors": sorted(set(udp_results.values()) - {"REPLY"}),
            "resolved": resolved,
        }
    )
)
