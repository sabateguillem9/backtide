"""Evil agent: a destructive request held by the gate while the proxy, its channel or backtide
itself falls; and the same request again once they are back.

Runs INSIDE the jail, as the agent's user (python3 -c).
Usage: <script> <allowed host> <method> <path> <timeout>
Prints one JSON object on its last line: what the proxy answered (or the connection error) and
how long it took. The test kills, freezes or restarts things around it; a timeout shorter than
the gate's wait means a client that gives up and leaves the hold behind.
"""

import http.client
import json
import ssl
import sys
import time

host, method, path, timeout = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
start = time.monotonic()
conn = http.client.HTTPSConnection(
    "backtide-proxy",
    8080,
    timeout=timeout,
    context=ssl.create_default_context(cafile="/etc/backtide-ca/ca.pem"),
)
conn.set_tunnel(host, 443)
try:
    conn.request(method, path, headers={"Authorization": "Bearer agent-cloud-token"})
    response = conn.getresponse()
    outcome = {"status": response.status, "body": response.read(600).decode("latin-1")}
except (OSError, http.client.HTTPException) as error:
    outcome = {"status": None, "error": f"{type(error).__name__}"}
finally:
    conn.close()
outcome["seconds"] = round(time.monotonic() - start, 2)
print(json.dumps(outcome))
