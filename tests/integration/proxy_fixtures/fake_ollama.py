"""A fake Ollama for the VM tests of T20 (docs/35, sections 6 and 7): never a real one.

Runs inside a throwaway container on the test's egress network (``--internal``: it reaches
nothing real), as ``python3 /opt/t20/fake_ollama.py``. Standard library only, so it runs in the
pinned mitmproxy image. It has a private address the tests never grant as public: the proxy may
only reach it through a local provider's fixed address.

- 11434: plain HTTP, like Ollama. ``POST /v1/chat/completions`` answers like Ollama's copy of
  OpenAI's API (JSON, or SSE with ``"stream": true``), ``POST /v1/messages`` like its copy of
  Anthropic's (JSON, or SSE with ``"stream": true``: Claude Code streams; T20-4), ``GET
  /v1/models`` with one model. Anything else (``/api/pull``, ``/api/tags``...)
  gets ``{"fake": "ollama"}``, so a request that should never arrive is seen when it does. A
  model request with ``T20-REDIRECT`` in its body gets ``302 Location: http://<this
  container>:22/``; with ``T20-SWITCH``, ``101 Switching Protocols`` (the proxy must cut both).
- 22 and 8080: decoys. They count every TCP connection and close it: the tests check that nothing
  ever reaches them.
- 9000: control, ``GET /stats``: every request seen on 11434 (method, path, headers, body size,
  the ``model`` and the top-level fields of a JSON body, the peer's address) and the connections
  accepted per port. ``GET /api/version`` says VERSION: the service asks it from the VM, never
  through the proxy (``system/provider_local_ready``), so its peer is not the proxy's.

Prints READY_LINE once all of them listen.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

READY_LINE = "t20-ollama-ready"
REPLY_TEXT = "T20 PONG FROM THE FAKE OLLAMA"
MODEL = "t20-fake-coder:7b"
VERSION = "0.40.8"  # what it says it is
DECOYS = (22, 8080)
LOCK = threading.Lock()
REQUESTS: list[dict] = []
ACCEPTS = {"11434": 0, "22": 0, "8080": 0}


def own_address() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


class Counting(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, handler: type) -> None:
        self.label = str(port)
        super().__init__(("0.0.0.0", port), handler)  # noqa: S104 - inside the test's network

    def get_request(self):  # type: ignore[no-untyped-def]
        conn, addr = super().get_request()
        with LOCK:
            ACCEPTS[self.label] = ACCEPTS.get(self.label, 0) + 1
        return conn, addr


class Ollama(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    def _body(self) -> bytes:
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length) if length else b""

    def _note(self, body: bytes) -> None:
        try:
            request = json.loads(body) if body else None
        except ValueError:
            request = None
        fields = sorted(request) if isinstance(request, dict) else []
        model = request.get("model") if isinstance(request, dict) else None
        with LOCK:
            REQUESTS.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body_size": len(body),
                    "fields": fields,
                    "model": model if isinstance(model, str) else None,
                    "peer": self.client_address[0],
                }
            )

    def _sse(self, events: list[tuple[str | None, dict]]) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True
        for name, data in events:
            chunk = "" if name is None else f"event: {name}\n"
            self.wfile.write(f"{chunk}data: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

    def _send(self, code: int, data: bytes, kind: str = "application/json", **extra: str) -> None:
        self.send_response(code)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        for name, value in extra.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - http.server's name
        self._note(b"")
        if self.path == "/api/version":  # what the SERVICE asks, from the VM (T20-4)
            self._send(200, json.dumps({"version": VERSION}).encode())
            return
        if self.path.split("?", 1)[0] == "/v1/models":
            listing = {"object": "list", "data": [{"id": MODEL, "object": "model"}]}
            self._send(200, json.dumps(listing).encode())
            return
        self._send(200, b'{"fake": "ollama"}')

    def do_DELETE(self) -> None:  # noqa: N802
        self._note(self._body())
        self._send(200, b'{"fake": "ollama"}')

    def do_POST(self) -> None:  # noqa: N802
        body = self._body()
        self._note(body)
        path = self.path.split("?", 1)[0]
        if path not in ("/v1/chat/completions", "/v1/messages"):
            self._send(200, b'{"fake": "ollama"}')
            return
        if b"T20-REDIRECT" in body:
            self._send(302, b"", location=f"http://{own_address()}:22/")
            return
        if b"T20-SWITCH" in body:
            self.send_response(101)
            self.send_header("upgrade", "websocket")
            self.send_header("connection", "Upgrade")
            self.end_headers()
            self.close_connection = True
            return
        try:
            request = json.loads(body or b"{}")
        except ValueError:
            request = {}
        if path == "/v1/messages" and request.get("stream") is True:
            self._sse(anthropic_stream())
            return
        if path == "/v1/messages":
            answer = {
                "id": "msg_t20",
                "type": "message",
                "role": "assistant",
                "model": MODEL,
                "content": [{"type": "text", "text": REPLY_TEXT}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 6},
            }
            self._send(200, json.dumps(answer).encode())
            return
        if request.get("stream") is True:
            chunk = {
                "id": "chatcmpl-t20",
                "object": "chat.completion.chunk",
                "model": MODEL,
                "choices": [{"index": 0, "delta": {"content": REPLY_TEXT}}],
            }
            end = {
                "id": "chatcmpl-t20",
                "object": "chat.completion.chunk",
                "model": MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            data = f"data: {json.dumps(chunk)}\n\ndata: {json.dumps(end)}\n\ndata: [DONE]\n\n"
            self._send(200, data.encode(), "text/event-stream")
            return
        answer = {
            "id": "chatcmpl-t20",
            "object": "chat.completion",
            "model": MODEL,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": REPLY_TEXT},
                }
            ],
            "usage": {"prompt_tokens": 7, "completion_tokens": 8, "total_tokens": 15},
        }
        self._send(200, json.dumps(answer).encode())


def anthropic_stream() -> list[tuple[str | None, dict]]:
    """Ollama's copy of Anthropic's streamed answer: REPLY_TEXT in one text block."""
    message = {
        "id": "msg_t20", "type": "message", "role": "assistant", "model": MODEL, "content": [],
        "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 5, "output_tokens": 1},
    }  # fmt: skip
    return [
        ("message_start", {"type": "message_start", "message": message}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": REPLY_TEXT}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta",
                           "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": {"output_tokens": 6}}),
        ("message_stop", {"type": "message_stop"}),
    ]  # fmt: skip


class Control(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        with LOCK:
            data = json.dumps({"requests": REQUESTS, "accepts": ACCEPTS}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Decoy(BaseHTTPRequestHandler):
    def handle(self) -> None:  # counted on accept; nothing is ever answered
        return


def serve(server: ThreadingHTTPServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main() -> None:
    serve(Counting(11434, Ollama))
    for port in DECOYS:
        serve(Counting(port, Decoy))
    control = ThreadingHTTPServer(("127.0.0.1", 9000), Control)
    print(READY_LINE, flush=True)  # noqa: T201 - the line the test waits for
    control.serve_forever()


if __name__ == "__main__":
    main()
