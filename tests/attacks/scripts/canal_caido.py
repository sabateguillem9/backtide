"""Evil agent: send while backtide is not listening (hung or dead).

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <allowed host> <path>
Prints one JSON object on its last line: the status the proxy gave and how long it took.
The test freezes or kills backtide around it.
"""

import http.client
import json
import ssl
import sys
import time

host, path = sys.argv[1:3]
start = time.monotonic()
conn = http.client.HTTPSConnection(
    "backtide-proxy",
    8080,
    timeout=30,
    context=ssl.create_default_context(cafile="/etc/backtide-ca/ca.pem"),
)
conn.set_tunnel(host, 443)
try:
    conn.request("POST", path, body=b'{"exfil": "while nobody records"}',
                 headers={"Content-Type": "application/json"})  # fmt: skip
    response = conn.getresponse()
    outcome = {"status": response.status, "body": response.read(500).decode("latin-1")}
except (OSError, http.client.HTTPException) as error:
    outcome = {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
finally:
    conn.close()
outcome["seconds"] = round(time.monotonic() - start, 2)
print(json.dumps(outcome))
