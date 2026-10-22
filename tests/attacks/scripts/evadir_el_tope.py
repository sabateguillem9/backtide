"""Evil agent: spend without being charged, by hanging up on the model at the right moment.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <anthropic host> <fake key> <model> <cut|hangup|plain>

- ``cut``: a streamed call with a big ``max_tokens`` whose text all arrives; the agent closes the
  connection right after the last ``content_block_stop``, before ``message_delta`` (which carries
  the real output usage) and ``message_stop``. The provider bills what it generated.
- ``hangup``: a call whose answer is slow to start; the agent hangs up before the status line.
  The provider got the request and bills it.
- ``plain``: an ordinary call (to see whether the cap stops it).

Prints one JSON object on its last line. The host is the test's fake internet (it pauses where
the markers ``T11-CUT-TAIL`` and ``T11-NO-HEAD`` say); nothing reaches a real provider.
"""

import http.client
import json
import socket
import ssl
import sys

host, key, model, mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
MAX_TOKENS = 1000
MARK = {"cut": "T11-CUT-TAIL", "hangup": "T11-NO-HEAD", "plain": "plain"}[mode]


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
    result = {"cut": cut, "hangup": hangup, "plain": plain}[mode]()
except (OSError, http.client.HTTPException) as error:
    result = {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
print(json.dumps(result))
