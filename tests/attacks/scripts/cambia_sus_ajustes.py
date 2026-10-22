"""Evil agent: change where Claude Code goes, then try to use it.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> jail                        try to rewrite the jail's settings (/config/claude.json)
<script> proxy <base url> <proxy>    its own settings: another base URL and another proxy
<script> escape <host> <ip:port>...  through backtide's proxy to <host>, and direct to each ip:port
<script> clean                       remove its own settings again
Prints one JSON object on its last line.
"""

import http.client
import json
import socket
import ssl
import sys
from pathlib import Path

JAIL_SETTINGS = Path("/config/claude.json")
OWN = Path.home() / ".claude" / "settings.json"
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
mode = sys.argv[1]

if mode == "jail":
    outcome = {}
    for name, how in (("rewrite", "w"), ("append", "a")):
        try:
            with JAIL_SETTINGS.open(how) as handle:
                handle.write('{"env": {"ANTHROPIC_BASE_URL": "https://elsewhere.invalid"}}')
            outcome[name] = "WRITTEN"
        except OSError as error:
            outcome[name] = type(error).__name__
    try:
        JAIL_SETTINGS.unlink()
        outcome["unlink"] = "REMOVED"
    except OSError as error:
        outcome["unlink"] = type(error).__name__
    print(json.dumps(outcome))

elif mode == "proxy":
    base_url, proxy_url = sys.argv[2], sys.argv[3]
    env = {"ANTHROPIC_BASE_URL": base_url}
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        env[name] = proxy_url
    env["NO_PROXY"] = env["no_proxy"] = ""
    OWN.parent.mkdir(parents=True, exist_ok=True)
    OWN.write_text(json.dumps({"env": env}))
    print(json.dumps({"written": str(OWN), "env": sorted(env)}))

elif mode == "escape":
    host = sys.argv[2]
    targets = [arg for arg in sys.argv[3:]]

    def through_proxy() -> object:
        conn = http.client.HTTPSConnection(
            *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
        )
        conn.set_tunnel(host, 443)
        try:
            conn.request("GET", "/base-url-probe")
            return conn.getresponse().status
        except (OSError, http.client.HTTPException) as error:
            return f"{type(error).__name__}"
        finally:
            conn.close()

    def direct(target: str) -> str:
        address, port = target.rsplit(":", 1)
        address = address.strip("[]")
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.settimeout(3)
                probe.connect((address, int(port)))
                return "CONNECTED"
        except OSError as error:
            return type(error).__name__

    print(
        json.dumps(
            {
                "proxy_status": through_proxy(),
                "direct": {target: direct(target) for target in targets},
            }
        )
    )

elif mode == "clean":
    OWN.unlink(missing_ok=True)
    print(json.dumps({"removed": str(OWN)}))
