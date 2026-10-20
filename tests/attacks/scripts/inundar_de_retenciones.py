"""Evil agent: a flood of distinct writes, so that the person drowns in approvals (fatigue as an
attack) or the gate gives in.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <host> <tag> <count> <timeout>   (or <script> <host> <tag> read <timeout>)
Prints one JSON object on its last line: how many answers of each status came back, and the
bodies of the refusals (403). With ``read``, the control: one plain GET of ``/<tag>/read``.

``count`` POSTs at once (16 threads), each to its own path ``/<tag>/flood/<n>`` with its own
body, so no two share a fingerprint and every one is a new hold. Each client gives up after
``timeout`` seconds. The host is the test's fake internet (invariant 8).
"""

import http.client
import json
import ssl
import sys
import threading
import time
from collections import Counter

PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
host, tag, what, timeout = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])

statuses: Counter = Counter()
refusals: list[str] = []
lock = threading.Lock()


def one(n: int) -> None:
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=timeout, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        body = json.dumps({"order": n, "to": f"cuenta-{n}"}).encode()
        conn.request("POST", f"/{tag}/flood/{n}", body=body,
                     headers={"Content-Type": "application/json"})  # fmt: skip
        response = conn.getresponse()
        text = response.read(400).decode("latin-1")
        with lock:
            statuses[str(response.status)] += 1
            if response.status == 403:
                refusals.append(text[:200])
    except (OSError, http.client.HTTPException) as error:
        with lock:
            statuses[type(error).__name__] += 1
    finally:
        conn.close()


if what == "read":
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=timeout, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request("GET", f"/{tag}/read")
        print(json.dumps({"status": conn.getresponse().status}))
    except (OSError, http.client.HTTPException) as error:
        print(json.dumps({"status": None, "error": type(error).__name__}))
    raise SystemExit(0)

start = time.monotonic()
queue = list(range(int(what)))


def worker() -> None:
    while True:
        with lock:
            if not queue:
                return
            n = queue.pop(0)
        one(n)


threads = [threading.Thread(target=worker) for _ in range(16)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print(json.dumps({"statuses": dict(statuses), "refusals": refusals[:5],
                  "seconds": round(time.monotonic() - start, 2)}))  # fmt: skip
