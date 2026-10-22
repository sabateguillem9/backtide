"""Evil agent: spend without being charged, by hanging up on the model at the right moment.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <host> <fake key> <model> <cut|hangup|plain|usage_cut>

- ``cut``: a streamed call with a big ``max_tokens`` whose text all arrives; the agent closes the
  connection right after the last ``content_block_stop``, before ``message_delta`` (which carries
  the real output usage) and ``message_stop``. The provider bills what it generated.
- ``hangup``: a call whose answer is slow to start; the agent hangs up before the status line.
  The provider got the request and bills it.
- ``plain``: an ordinary call (to see whether the cap stops it).
- ``usage_cut`` (to the OpenAI-shaped provider): a streamed Chat Completions call without
  ``stream_options``, so the proxy asks for its usage (docs/33, "include_usage"); the agent
  reads its answer, waits while the usage chunk reaches the proxy, and hangs up before
  ``[DONE]``. It also says whether the usage chunk it never asked for reached it.

Prints one JSON object on its last line. The host is the test's fake internet (it pauses where
the markers ``T11-CUT-TAIL``, ``T11-NO-HEAD`` and ``T11-USAGE-CUT`` say); nothing reaches a real
provider.
"""

import http.client
import json
import socket
import ssl
import sys
import time

host, key, model, mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
MAX_TOKENS = 1000
MARK = {"cut": "T11-CUT-TAIL", "hangup": "T11-NO-HEAD", "plain": "plain",
        "usage_cut": "T11-USAGE-CUT"}[mode]  # fmt: skip
QUIET = 2.0  # seconds without a byte: the provider is pausing before [DONE]


def connect(timeout):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=timeout, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    return conn


def send(conn, stream):
    body = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "stream": stream,
        "messages": [{"role": "user", "content": f"{MARK}: write me a long story"}],
    }
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    conn.request("POST", "/v1/messages", body=json.dumps(body).encode(), headers=headers)


def hang_up(conn):
    """Close at once (RST), as a client that gives up does."""
    sock = conn.sock
    if sock is not None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        sock.close()
    conn.close()


def cut():
    conn = connect(30)
    send(conn, True)
    response = conn.getresponse()
    seen = []
    while True:
        line = response.fp.readline()
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        if text.startswith("event: "):
            seen.append(text[7:])
        if text == "" and seen and seen[-1] == "content_block_stop":
            break  # the text is all here: hang up before the usage comes
    hang_up(conn)
    return {"status": response.status, "events": seen}


def hangup():
    conn = connect(2)
    send(conn, False)
    try:
        response = conn.getresponse()
    except TimeoutError:
        hang_up(conn)
        return {"status": None, "hung_up": True}
    status = response.status
    hang_up(conn)
    return {"status": status, "hung_up": False}


def usage_cut():
    conn = connect(30)
    body = {
        "model": model,
        "max_completion_tokens": MAX_TOKENS,
        "stream": True,
        "messages": [{"role": "user", "content": f"{MARK}: write me a long story"}],
    }
    headers = {"authorization": f"Bearer {key}", "content-type": "application/json"}
    conn.request("POST", "/v1/chat/completions", body=json.dumps(body).encode(), headers=headers)
    sock = conn.sock  # http.client lets go of it once the answer says "connection: close"
    response = conn.getresponse()
    out = {"status": response.status, "finished": False, "usage_chunk_seen": False,
           "done": False}  # fmt: skip
    started = time.monotonic()
    while time.monotonic() - started < 20:
        if out["finished"]:
            sock.settimeout(QUIET)  # the usage chunk reaches the proxy meanwhile
        try:
            line = response.fp.readline()
        except TimeoutError:
            break  # quiet: the provider waits before [DONE]; hang up now
        if not line:
            break
        text = line.strip()
        if not text.startswith(b"data: "):
            continue
        data = text[6:]
        if data == b"[DONE]":
            out["done"] = True
            break
        try:
            chunk = json.loads(data)
        except ValueError:
            continue
        choices = chunk.get("choices")
        if choices == []:
            out["usage_chunk_seen"] = True
        if any(isinstance(c, dict) and c.get("finish_reason") for c in choices or []):
            out["finished"] = True
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    response.close()
    sock.close()
    conn.close()
    return out


def plain():
    conn = connect(60)
    try:
        send(conn, False)
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


try:
    result = {"cut": cut, "hangup": hangup, "plain": plain, "usage_cut": usage_cut}[mode]()
except (OSError, http.client.HTTPException) as error:
    result = {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
print(json.dumps(result))
