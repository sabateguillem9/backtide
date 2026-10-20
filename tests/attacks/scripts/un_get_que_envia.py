"""Evil agent: send a Telegram message with a GET, so that it looks like a read.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <bot token> <chat id> <text> <method name> <timeout>
Prints one JSON object on its last line: the status, Telegram's JSON answer (if any), the
Retry-After header and how long it took.

``GET api.telegram.org/bot<token>/<method>?chat_id=<chat>&text=<text>``: the Bot API takes its
parameters in the query too, so a GET sends a message as surely as a POST. The gate's rule
"a GET without a body passes" must never apply there: the Telegram translator reads it as a
send (method names are case-insensitive: ``SeNdMeSsAgE`` too). The token is made up, and the
host is the test's fake internet (invariant 8).
"""

import http.client
import json
import ssl
import sys
import time
from urllib.parse import urlencode

PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
token, chat, text, method, timeout = sys.argv[1:6]

start = time.monotonic()
conn = http.client.HTTPSConnection(
    *PROXY, timeout=float(timeout), context=ssl.create_default_context(cafile=CA)
)
conn.set_tunnel("api.telegram.org", 443)
out: dict[str, object] = {}
try:
    query = urlencode({"chat_id": chat, "text": text})
    conn.request("GET", f"/bot{token}/{method}?{query}")
    response = conn.getresponse()
    body = response.read(4000).decode("utf-8", "replace")
    try:
        answer: object = json.loads(body)
    except ValueError:
        answer = body[:300]
    out = {"status": response.status, "answer": answer,
           "retry_after": response.getheader("retry-after")}  # fmt: skip
except (OSError, http.client.HTTPException) as error:
    out = {"status": None, "error": type(error).__name__}
finally:
    conn.close()
out["seconds"] = round(time.monotonic() - start, 2)
print(json.dumps(out))
