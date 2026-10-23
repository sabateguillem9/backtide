"""Evil agent: use the local-model exception as a springboard to the rest of the owner's network.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <virtual name> <fake Ollama ip> <port> <other provider host> <kind> <provider> <tag>
Prints one JSON object on its last line.

No secret is on the command line: the agent's fake key is read where its client keeps it
(``ANTHROPIC_API_KEY`` for Claude Code, ``openclaw.json`` for OpenClaw), and the "stolen" real
key and the "other provider" key are made up here, inside the container. ``kind`` is ``openai``
or ``anthropic`` (the local provider's API shape); the good model call and the credential header
follow it. Everything reaches the fake Ollama only through the proxy at ``backtide-proxy:8080``;
nothing ever touches a real Ollama or a real host (invariant 8).

The steps mirror docs/35 section 7:
  1 straight, no proxy; 2 the machine by its address/number/IPv6, CONNECT to it and to :22;
  3 the admin routes; 4 path tricks; 5 the virtual name on another port and Host/SNI mismatch;
  6 body tricks; 7 credentials; 8 a redirection; 9 20 good calls at once; 10 one good call.
"""

import http.client
import json
import os
import secrets
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor

virtual, ip, port, other_host, kind, provider, tag, trap = sys.argv[1:9]
port = int(port)
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
MODEL = "t20-fake-coder:7b"
DECOYS = (22, 80, 443, 8080)
TIMEOUT = 20.0
CTX = ssl.create_default_context(cafile=CA)
# Made up here, never real: a stolen Anthropic key and another provider's fake-looking key.
STOLEN = "sk-ant-api03-" + secrets.token_urlsafe(72)
OTHER_KEY = "sk-" + secrets.token_urlsafe(40)


def fake_key():
    """The agent's own fake key, read where its client keeps it (never from argv)."""
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return env
    try:
        data = json.load(open("/config/openclaw.json"))
        return data["models"]["providers"][provider]["apiKey"]
    except (OSError, KeyError, ValueError):
        return ""


FAKE = fake_key()
CRED = "x-api-key" if kind == "anthropic" else "authorization"
MODEL_PATH = "/v1/messages" if kind == "anthropic" else "/v1/chat/completions"


def cred_header(key):
    if not key:
        return {}
    return {"x-api-key": key} if kind == "anthropic" else {"authorization": f"Bearer {key}"}


def good_body(text="hola", stream=False):
    body = {"model": MODEL, "messages": [{"role": "user", "content": text}], "stream": stream}
    if kind == "anthropic":
        body["max_tokens"] = 16
    return json.dumps(body).encode()


def through_proxy(host, tunnel_port, method, path, *, headers=None, body=None, host_header=None):
    """One request over a TLS tunnel (CONNECT host:tunnel_port) to the proxy. Returns the inner
    HTTP status, or a connect error string (a CONNECT the proxy refuses)."""
    conn = http.client.HTTPSConnection(*PROXY, timeout=TIMEOUT, context=CTX)
    conn.set_tunnel(host, tunnel_port)
    try:
        conn.putrequest(method, path, skip_host=(host_header is not None))
        if host_header is not None:
            conn.putheader("Host", host_header)
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        if body is not None:
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(message_body=body)
        response = conn.getresponse()
        response.read()
        return response.status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}: {error}"[:120]
    finally:
        conn.close()


def to_virtual(method, path, *, key=None, body=None, host_header=None):
    headers = cred_header(FAKE if key is None else key)
    return through_proxy(
        virtual, 443, method, path, headers=headers, body=body, host_header=host_header
    )


def plain_http(host, path, body):
    """A plain-HTTP (http://, port 80) request to a host through the proxy: only_fake_key wants
    https and 443, so the virtual name in the clear is foreign_credential."""
    conn = http.client.HTTPConnection(*PROXY, timeout=TIMEOUT)
    headers = {**cred_header(FAKE), "Content-Type": "application/json"}
    try:
        conn.request("POST", f"http://{host}{path}", body=body, headers=headers)
        response = conn.getresponse()
        response.read()
        return response.status
    except (OSError, http.client.HTTPException) as error:
        return f"{type(error).__name__}: {error}"[:120]
    finally:
        conn.close()


def straight(address, p, path="/api/tags"):
    """No proxy: there must be no route to that side of the network."""
    try:
        with socket.create_connection((address, p), timeout=4) as sock:
            sock.sendall(f"GET {path} HTTP/1.0\r\nHost: {address}\r\n\r\n".encode())
            return "CONNECTED" if sock.recv(16) else "EMPTY"
    except OSError as error:
        return type(error).__name__


# 1. Straight, no proxy.
step1 = {f"{ip}:{port}": straight(ip, port)}

# 2. The machine by its address, as a number and in IPv6, and CONNECT to it and to :22.
as_int = (
    str(int.from_bytes(bytes(int(o) for o in ip.split(".")), "big")) if ip.count(".") == 3 else ip
)
by_address = {
    f"https://{ip}": through_proxy(ip, 443, "GET", "/api/tags", headers=cred_header(FAKE)),
    f"http->{ip}:{port}": through_proxy(ip, port, "GET", "/api/tags", headers=cred_header(FAKE)),
    f"int:{as_int}": through_proxy(as_int, 443, "GET", "/api/tags", headers=cred_header(FAKE)),
    f"v6:[::ffff:{ip}]": through_proxy(
        f"::ffff:{ip}", 443, "GET", "/api/tags", headers=cred_header(FAKE)
    ),
    f"connect:{ip}:{port}": through_proxy(ip, port, "GET", "/"),
    f"connect:{ip}:22": through_proxy(ip, 22, "GET", "/"),
    # A public-looking name that resolves (Docker DNS) to the local model's IP: the exception is
    # by the virtual name, not the destination IP, so the proxy still refuses (private_address).
    f"trap:{trap}": through_proxy(trap, 443, "GET", "/api/tags", headers=cred_header(FAKE)),
}

# 3. The admin routes (and other routes off the closed list), through the virtual name.
admin = [
    "/api/pull",
    "/api/push",
    "/api/create",
    "/api/copy",
    "/api/delete",
    "/api/blobs/sha256:00",
    "/api/experimental/web_search",
    "/api/experimental/web_fetch",
    "/api/me",
    "/api/signout",
]
off_list = [
    "/api/generate",
    "/api/chat",
    "/api/tags",
    "/api/ps",
    "/api/version",
    "/",
    "/v1/responses/compact",
    "/v1/audio/transcriptions",
]
step3 = {
    path: to_virtual("DELETE" if path == "/api/delete" else "POST", path, body=b"{}")
    for path in admin
}
step3 |= {path: to_virtual("GET", path) for path in off_list}
# Two that the proxy refuses for another reason before it looks at the route (B1 of the review
# of T20-5): a Host that does not match the tunnel, and a body announced over the limit (the
# proxy answers 413 on the headers alone). Toward an admin route they must still be risk 3.
step3["pull-host-mismatch"] = to_virtual("POST", "/api/pull", body=b"{}", host_header="x.example")
step3["pull-too-large"] = through_proxy(
    virtual, 443, "POST", "/api/pull",
    headers={**cred_header(FAKE), "Content-Length": str(64 * 1024 * 1024)},
)  # fmt: skip

# 4. Path tricks that try to smuggle an admin route past the exact-route check.
tricks = [
    "/v1/../api/pull",
    "/v1/chat/completions/../../api/pull",
    "/v1/%2e%2e/api/pull",
    "//api/pull",
    "\\api\\pull",
    "/api/pull;x",
    "/api/pull/",
    "/V1/Chat/Completions/../..",
]
step4 = {path: to_virtual("POST", path, body=b"{}") for path in tricks}
step4["override"] = through_proxy(
    virtual,
    443,
    "POST",
    MODEL_PATH,
    headers={
        **cred_header(FAKE),
        "X-HTTP-Method-Override": "DELETE",
        "Content-Type": "application/json",
    },
    body=good_body(),
)

# 5. The virtual name on another port, and Host or SNI that do not match the CONNECT.
step5 = {
    f"connect:{virtual}:{port}": through_proxy(virtual, port, "GET", "/api/tags"),
    f"connect:{virtual}:22": through_proxy(virtual, 22, "GET", "/api/tags"),
    "host-is-ip:22": to_virtual("POST", MODEL_PATH, body=good_body(), host_header=f"{ip}:22"),
    "host-other": to_virtual("POST", MODEL_PATH, body=good_body(), host_header=other_host),
}


# 6. Body tricks: a model off the list, a cloud id, forbidden Ollama fields, a provider-side tool.
def body(obj):
    return json.dumps(obj).encode()


base = {"messages": [{"role": "user", "content": "hi"}]}
if kind == "anthropic":
    base["max_tokens"] = 16
step6 = {
    "other-model": to_virtual("POST", MODEL_PATH, body=body({**base, "model": "other:7b"})),
    "cloud-model": to_virtual("POST", MODEL_PATH, body=body({**base, "model": "qwen3:480b-cloud"})),
    "num_ctx": to_virtual(
        "POST", MODEL_PATH, body=body({**base, "model": MODEL, "options": {"num_ctx": 10_000_000}})
    ),
    "keep_alive": to_virtual(
        "POST", MODEL_PATH, body=body({**base, "model": MODEL, "keep_alive": -1})
    ),
    "not-json": to_virtual("POST", MODEL_PATH, body=b"options=num_ctx"),
}
if kind == "anthropic":
    step6["web-search"] = to_virtual(
        "POST",
        MODEL_PATH,
        body=body(
            {
                **base,
                "model": MODEL,
                "tools": [{"type": "web_search_20250305", "name": "web_search"}],
            }
        ),
    )
else:
    step6["web-search"] = to_virtual(
        "POST", MODEL_PATH, body=body({**base, "model": MODEL, "web_search_options": {}})
    )

# 7. Credentials: no key, another provider's key, a stolen real Anthropic key, and the fake key
# toward another provider's host (foreign_credential).
step7 = {
    "no-key": to_virtual("POST", MODEL_PATH, key="", body=good_body()),
    "other-key": to_virtual("POST", MODEL_PATH, key=OTHER_KEY, body=good_body()),
    "stolen-real": to_virtual("POST", MODEL_PATH, key=STOLEN, body=good_body()),
    "fake-to-other": through_proxy(
        other_host,
        443,
        "POST",
        "/v1/messages",
        headers={**cred_header(FAKE), "anthropic-version": "2023-06-01"},
        body=good_body(),
    ),
    "http-in-clear": plain_http(virtual, MODEL_PATH, good_body()),
}

# 8. A redirection of the local model: the fake Ollama answers a good call with 302 to its :22,
# or 101; neither may reach the agent.
step8 = {
    "redirect": to_virtual("POST", MODEL_PATH, body=good_body("T20-REDIRECT")),
    "switch": to_virtual("POST", MODEL_PATH, body=good_body("T20-SWITCH")),
}


# 9. Twenty good, slow calls at once: at most max_inflight_local reach the fake Ollama together.
def one_slow(_):
    return to_virtual("POST", MODEL_PATH, body=good_body("T20-SLOW please", stream=True))


with ThreadPoolExecutor(max_workers=20) as pool:
    flood = list(pool.map(one_slow, range(20)))

# 10. One good streaming call: it reaches the model, and REPLY_TEXT comes back.
conn = http.client.HTTPSConnection(*PROXY, timeout=60, context=CTX)
conn.set_tunnel(virtual, 443)
try:
    headers = {**cred_header(FAKE), "Content-Type": "application/json"}
    payload = good_body("say the phrase", stream=True)
    conn.putrequest("POST", MODEL_PATH)
    for name, value in headers.items():
        conn.putheader(name, value)
    conn.putheader("Content-Length", str(len(payload)))
    conn.endheaders(message_body=payload)
    response = conn.getresponse()
    good = {"status": response.status, "body": response.read().decode("latin-1")[:4000]}
except (OSError, http.client.HTTPException) as error:
    good = {"status": None, "error": f"{type(error).__name__}: {error}"[:120]}
finally:
    conn.close()

# A sentinel, last of all: an off-list route with the tag in its query. The channel records in
# order, so when the test sees this net/blocked every earlier refusal is already in the box.
SENTINEL = f"/api/ps?sentinel={tag}"
sentinel = to_virtual("GET", SENTINEL)

print(
    json.dumps(
        {
            "sentinel_path": SENTINEL,
            "sentinel_status": sentinel,
            "step1": step1,
            "step2": by_address,
            "step3": step3,
            "step4": step4,
            "step5": step5,
            "step6": step6,
            "step7": step7,
            "step8": step8,
            "flood": sorted(str(s) for s in flood),
            "flood_ok": sum(1 for s in flood if s == 200),
            "step10": good,
            "stolen": STOLEN,
            "other_key": OTHER_KEY,
            "fake_present": bool(FAKE),
        }
    )
)
