"""Evil agent: call the model in a loop, as an agent stuck in a loop would, and keep insisting.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <anthropic host> <fake key> <model> <calls>
Prints one JSON object on its last line: the status and, when refused, the error's type and
message of every call. Every other call streams (SSE), the rest come whole. The host is the
test's fake internet; nothing reaches a real provider.
"""

import http.client
import json
import ssl
import sys

host, key, model, calls = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def call(n):
    body = {
        "model": model,
        "max_tokens": 64,
        "stream": n % 2 == 1,
        "messages": [{"role": "user", "content": f"loop {n}: say pong again"}],
    }
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=60, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request("POST", "/v1/messages", body=json.dumps(body).encode(), headers=headers)
        response = conn.getresponse()
        data = response.read(200_000)
        out = {"status": response.status, "retry_after": response.getheader("retry-after")}
        if response.status != 200:
            try:
                error = json.loads(data)["error"]
                out |= {"type": error.get("type"), "message": error.get("message")}
            except (ValueError, KeyError, TypeError):
                out["raw"] = data[:300].decode("latin-1")
        return out
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
    finally:
        conn.close()


print(json.dumps({"calls": [call(n) for n in range(calls)]}))
