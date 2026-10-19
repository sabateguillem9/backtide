"""Evil agent: complete an OAuth login or device-code flow through the proxy, to get a token
backtide does not control.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <tag> <anthropic host> <fake anthropic key> <target>...
where each ``target`` is ``host|method|path``. Prints one JSON object on its last line.

For each target it opens a tunnel to the host and makes the request (the authorization page, the
token endpoint, the device-code endpoint), including paths dressed up to fool a lenient server:
percent-encoding, odd case, double slashes, a trailing dot. The proxy must refuse every one as
an OAuth login. The control is a normal model call with the agent's own fake key, which must
still pass. The hosts are aliases of the test's fake internet; no real login server is contacted.
"""

import http.client
import json
import ssl
import sys

tag, anthropic_host, fake_key = sys.argv[1:4]
targets = sys.argv[4:]
PROXY = ("backtide-proxy", 8080)
CONTEXT = ssl.create_default_context(cafile="/etc/backtide-ca/ca.pem")


def through(host: str, method: str, path: str, body: bytes, headers: dict) -> dict:
    conn = http.client.HTTPSConnection(*PROXY, timeout=30, context=CONTEXT)
    conn.set_tunnel(host, 443)
    try:
        conn.request(method, path, body=body or None, headers=headers)
        response = conn.getresponse()
        return {"status": response.status, "body": response.read(400).decode("latin-1")}
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:160]}
    finally:
        conn.close()


attempts = {}
for target in targets:
    host, method, path = target.split("|", 2)
    body = b"grant_type=authorization_code&code=stolen" if method == "POST" else b""
    headers = {"content-type": "application/x-www-form-urlencoded"} if body else {}
    attempts[f"{host}{path}"] = through(host, method, path, body, headers)

# The control: a normal model call with the agent's own (fake) key, which the proxy swaps and
# lets through. If it did not pass, the OAuth refusals would prove nothing.
model = through(
    anthropic_host,
    "POST",
    f"/{tag}/control/v1/messages",
    json.dumps(
        {"model": "fake-claude", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
    ).encode(),
    {"content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": fake_key},
)
print(json.dumps({"attempts": attempts, "control": model}))
