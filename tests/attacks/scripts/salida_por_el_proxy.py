"""Evil agent: go out through the proxy, where it is let, and around it, where it is not.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <allowed host> <host not allowed> <fake internet's address> <tag>
Prints one JSON object on its last line.

Every host is a name of the test's fake internet (*.fake.test), on an egress network with no way
to the internet. Through the proxy (HTTPS_PROXY, the proxy's CA): a GET and a POST to the
allowed host, and a GET to the other one. Around it: the fake internet's address straight
(TCP to 443, 8443 and 9000), its names resolved by the agent itself, IPv6, and curl with the
proxy variables emptied.
"""

import http.client
import json
import socket
import ssl
import subprocess
import sys

allowed, other, fake_ip, tag = sys.argv[1:5]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def through_proxy(host, path, method="GET", body=None):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        return {"status": response.status, "body": response.read(2000).decode("latin-1")}
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
    finally:
        conn.close()


def straight(address, port):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(3)
            probe.connect((address, port))
        return "CONNECTED"
    except OSError as error:
        return type(error).__name__


def resolve(name):
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, 443)})
    except OSError as error:
        return type(error).__name__


# No proxy variables at all (the jail's /tmp is its own).
env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"}  # noqa: S108
curl = subprocess.run(
    ["curl", "-sS", "--max-time", "8", f"https://{allowed}/{tag}/curl-direct"],
    capture_output=True,
    text=True,
    env=env,
    check=False,
)
print(
    json.dumps(
        {
            "allowed_get": through_proxy(allowed, f"/{tag}/get"),
            "allowed_post": through_proxy(allowed, f"/{tag}/post", "POST", b'{"n": 1}'),
            "not_allowed": through_proxy(other, f"/{tag}/denied"),
            "straight": {str(port): straight(fake_ip, port) for port in (443, 8443, 9000, 80)},
            "ipv6": straight("2001:db8::1", 443),
            "resolved": {name: resolve(name) for name in (allowed, other)},
            "curl_without_proxy": curl.returncode,
        }
    )
)
