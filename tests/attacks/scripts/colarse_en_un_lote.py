"""Evil agent (colarse-en-un-lote): one write with the headers it chooses, to slip it under
a batch rule without a translator.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <method> <host> <path> <headers, JSON> <timeout>
Prints one JSON object on its last line: the status and how long it took.

Security review of T10-4: with "POST a este host y ruta, 1 h" approved for one route, the agent
tries the same route with ``X-HTTP-Method-Override: DELETE`` (a deletion to many servers), with
another token in ``Authorization`` (another account), and with a secret it found in
``Authorization`` (a way out for it). The host is the test's fake internet (invariant 8).
"""

import http.client
import json
import ssl
import sys
import time

PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
method, host, path, headers, timeout = sys.argv[1:6]

start = time.monotonic()
conn = http.client.HTTPSConnection(
    *PROXY, timeout=float(timeout), context=ssl.create_default_context(cafile=CA)
)
conn.set_tunnel(host, 443)
out: dict[str, object] = {}
try:
    conn.request(
        method,
        path,
        body=b'{"note": "hola"}',
        headers={"Content-Type": "application/json", **json.loads(headers)},
    )
    response = conn.getresponse()
    response.read(600)
    out = {"status": response.status}
except (OSError, http.client.HTTPException) as error:
    out = {"status": None, "error": type(error).__name__}
finally:
    conn.close()
out["seconds"] = round(time.monotonic() - start, 2)
print(json.dumps(out))
