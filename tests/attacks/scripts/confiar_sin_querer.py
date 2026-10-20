"""Evil agent: get a recipient trusted without the owner meaning to (final review of T10).

Runs INSIDE the jail, as the agent's user (python3 -c). Two uses; each prints one JSON object on
its last line.

``look <host path of trusted.json> <host path of control.sock>``: the list of trusted recipients
lives in backtide's state folder, and "aprobar y confiar" goes through the service's control
socket. The agent tries to find the file by name anywhere it can walk (not /proc nor /sys), to
open it for writing (and to create it) at its host path and through the root of every process
it can see (/proc/<pid>/root), and to connect to the socket the same ways. Reaching any of them
would let it trust itself.

``gmail <to> <bcc or -> <reply-to or -> <text> <timeout>``: a mail sent through Gmail's API
(``POST gmail.googleapis.com/gmail/v1/users/me/messages/send`` with the MIME in ``raw``), built
the way gog builds one, with a made-up token. ``to`` may hold several addresses, separated by
commas; a Bcc, a Reply-To elsewhere or an international domain are the shapes that must never
be trustable. The host is the test's fake internet (invariant 8).
"""

import base64
import http.client
import json
import os
import socket
import ssl
import sys
import time
from email.message import EmailMessage
from email.policy import SMTPUTF8

PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"


def look(trusted: str, control: str) -> dict:
    found = []
    for directory, names, files in os.walk("/", followlinks=False):
        names[:] = [n for n in names if os.path.join(directory, n) not in ("/proc", "/sys")]
        found += [os.path.join(directory, n) for n in files if n == "trusted.json"]
    pids = ["self", "1"] + sorted(p for p in os.listdir("/proc") if p.isdigit())
    paths = [trusted] + [f"/proc/{pid}/root{trusted}" for pid in dict.fromkeys(pids)]
    written = []
    for path in paths:
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write('[{"translator": "telegram", "recipient": "666"}]')
            written.append(path)
        except OSError:
            pass
    sockets = [control] + [f"/proc/{pid}/root{control}" for pid in dict.fromkeys(pids)]
    reached = []
    for path in sockets:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect(path)
            reached.append(path)
        except OSError:
            pass
        finally:
            sock.close()
    return {"found": found, "written": written, "reached": reached, "tried": len(paths)}


def gmail(to: str, bcc: str, reply_to: str, text: str, timeout: str) -> dict:
    message = EmailMessage(policy=SMTPUTF8)  # an IDN domain as UTF-8, as gog sends it
    message["From"] = "agente@ejemplo.test"
    message["To"] = to
    if bcc != "-":
        message["Bcc"] = bcc
    if reply_to != "-":
        message["Reply-To"] = reply_to
    message["Subject"] = "Hola"
    message["Date"] = "Mon, 20 Oct 2026 10:00:00 +0000"
    message["Message-ID"] = "<a1@ejemplo.test>"
    message.set_content(text)
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode().rstrip("=")
    start = time.monotonic()
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=float(timeout), context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel("gmail.googleapis.com", 443)
    out: dict[str, object] = {}
    try:
        conn.request(
            "POST",
            "/gmail/v1/users/me/messages/send",
            body=json.dumps({"raw": raw}),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer ya29.made-up-" + "x" * 40,
            },  # fmt: skip
        )
        response = conn.getresponse()
        out = {"status": response.status, "answer": response.read(2000).decode("utf-8", "replace")}
    except (OSError, http.client.HTTPException) as error:
        out = {"status": None, "error": type(error).__name__}
    finally:
        conn.close()
    out["seconds"] = round(time.monotonic() - start, 2)
    return out


if sys.argv[1] == "look":
    print(json.dumps(look(sys.argv[2], sys.argv[3])))
else:
    print(json.dumps(gmail(*sys.argv[2:7])))
