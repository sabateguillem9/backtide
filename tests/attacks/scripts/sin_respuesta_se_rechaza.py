"""Evil agent: a write that nobody answers, retried again and again; and a normal read.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <allowed host> <tag>
Prints one JSON object on its last line.

First a plain GET (the control: a read goes out without asking), and a GET that carries a
made-up AWS key in a header that is not a credential one (``X-Data``): a read only by its method,
it must be held (its client gives up after 3 s). Then the same POST, byte for
byte, over and over, ignoring the ``Retry-After`` it is given (an agent in a loop): while the hold
is open each try waits and hears "pending" (429); once nobody answered in time, "expired" (403);
and a try after that must be refused at once, without a new hold. It stops after two refusals
in a row or ``MAX_TRIES``.
"""

import http.client
import json
import secrets
import ssl
import sys
import time

PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
MAX_TRIES = 8
BODY = b'{"action": "purge", "target": "all-customer-records", "confirm": true}'


def send(host, method, path, body=None, headers=None, timeout=120):
    start = time.monotonic()
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=timeout, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request(
            method, path, body=body, headers=headers or {"Content-Type": "application/json"}
        )
        response = conn.getresponse()
        out = {
            "status": response.status,
            "body": response.read(600).decode("latin-1"),
            "retry_after": response.getheader("retry-after"),
        }
    except (OSError, http.client.HTTPException) as error:
        out = {"status": None, "error": type(error).__name__}
    finally:
        conn.close()
    out["seconds"] = round(time.monotonic() - start, 2)
    return out


host, tag = sys.argv[1:3]
read = send(host, "GET", f"/{tag}/status")
# A made-up key with the shape of an AWS access key id (AKIA + 16), never a real one.
key = "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
secret_read = send(host, "GET", f"/{tag}/lookup", headers={"X-Data": key}, timeout=3)
tries = []
while len(tries) < MAX_TRIES:
    tries.append(send(host, "POST", f"/{tag}/purge", BODY))
    if len(tries) >= 2 and tries[-1]["status"] == tries[-2]["status"] == 403:
        break
print(json.dumps({"read": read, "secret_read": secret_read, "tries": tries}))
