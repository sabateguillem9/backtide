"""The fake internet of the T06-1 checks: HTTPS servers that say what reached them.

Runs inside a throwaway container on the test's egress network (``--internal``: it reaches
nothing real), as ``python3 /opt/t06/fake_internet.py``. Standard library only, so it runs in
the pinned mitmproxy image. Never contacted from the Mac and never with a real key.

- 443 and 8443: HTTPS with the test's own internet CA (``/opt/internet/server.pem``), HTTP/1.1
  only. Every accepted TCP connection is counted per listener *before* its TLS handshake, so
  a proxy that connects early is seen even if it never sends a request. Every request is
  answered with what arrived (listener, accept number, SNI, method, path, headers, body size),
  except the model APIs below.
- ``/v1/messages``: a fake Anthropic Messages API (JSON or SSE, ``"stream": true``).
- ``.../chat/completions``: a fake OpenAI-compatible Chat Completions API (JSON or SSE).
- ``.../responses``: a fake OpenAI Responses API (JSON or SSE).
- 9000: plain HTTP control, ``GET /stats``: accepts per listener and every request seen.

Prints READY_LINE once all three listen.
"""

import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

READY_LINE = "t06-internet-ready"
SERVER_PEM = "/opt/internet/server.pem"
REPLY_TEXT = "T06 PONG FROM THE FAKE MODEL"

LOCK = threading.Lock()
ACCEPTS = {"443": 0, "8443": 0}
REQUESTS: list[dict] = []
CURRENT = threading.local()  # the connection a handler thread is serving


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib name
        del format, args  # quiet: the test reads /stats, never these logs

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    def _serve(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        record = {
            "at": time.time(),  # the same kernel clock as the VM's: T06-4 compares it
            "listener": getattr(CURRENT, "listener", "control"),
            "accept": getattr(CURRENT, "accept", None),
            "sni": getattr(CURRENT, "sni", None),
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("host"),
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body_size": len(body),
        }
        if record["listener"] == "control":
            self._control()
            return
        with LOCK:
            REQUESTS.append(record)
        path = self.path.split("?", 1)[0]
        if path.endswith("/v1/messages"):
            self._anthropic(body)
        elif path.endswith("/chat/completions"):
            self._openai_chat(body)
        elif path.endswith("/responses"):
            self._openai_responses(body)
        else:
            self._json(200, record)

    def _control(self) -> None:
        with LOCK:
            stats = {"accepts": dict(ACCEPTS), "requests": list(REQUESTS)}
        self._json(200, stats)

    def _json(self, status: int, payload: object) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, events: list[tuple[str | None, object]]) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True
        for name, data in events:
            chunk = "" if name is None else f"event: {name}\n"
            text = data if isinstance(data, str) else json.dumps(data)
            chunk += f"data: {text}\n\n"
            self.wfile.write(chunk.encode())
            self.wfile.flush()
            time.sleep(0.01)

    def _anthropic(self, body: bytes) -> None:
        request = _json_or_empty(body)
        model = request.get("model", "fake-model")
        usage = {"input_tokens": 12, "output_tokens": 7}
        if not request.get("stream"):
            self._json(
                200,
                {
                    "id": "msg_t06",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [{"type": "text", "text": REPLY_TEXT}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": usage,
                },
            )
            return
        message = {
            "id": "msg_t06",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 1},
        }
        self._sse(
            [
                ("message_start", {"type": "message_start", "message": message}),
                (
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": ""},
                    },
                ),
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": REPLY_TEXT},
                    },
                ),
                ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                (
                    "message_delta",
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                        "usage": {"output_tokens": 7},
                    },
                ),
                ("message_stop", {"type": "message_stop"}),
            ]
        )

    def _openai_chat(self, body: bytes) -> None:
        request = _json_or_empty(body)
        model = request.get("model", "fake-model")
        created = int(time.time())
        if not request.get("stream"):
            self._json(
                200,
                {
                    "id": "chatcmpl-t06",
                    "object": "chat.completion",
                    "created": created,
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": REPLY_TEXT},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19},
                },
            )
            return

        def chunk(delta: dict, finish: str | None) -> dict:
            return {
                "id": "chatcmpl-t06",
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }

        self._sse(
            [
                (None, chunk({"role": "assistant", "content": ""}, None)),
                (None, chunk({"content": REPLY_TEXT}, None)),
                (None, chunk({}, "stop")),
                (None, "[DONE]"),
            ]
        )

    def _openai_responses(self, body: bytes) -> None:
        request = _json_or_empty(body)
        model = request.get("model", "fake-model")
        item = {
            "id": "msg_t06",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": REPLY_TEXT, "annotations": []}],
        }
        response = {
            "id": "resp_t06",
            "object": "response",
            "created_at": int(time.time()),
            "status": "completed",
            "model": model,
            "output": [item],
            "usage": {"input_tokens": 12, "output_tokens": 7, "total_tokens": 19},
        }
        if not request.get("stream"):
            self._json(200, response)
            return
        start = {**response, "status": "in_progress", "output": []}
        self._sse(
            [
                ("response.created", {"type": "response.created", "response": start}),
                (
                    "response.output_item.added",
                    {
                        "type": "response.output_item.added",
                        "output_index": 0,
                        "item": {**item, "status": "in_progress", "content": []},
                    },
                ),
                (
                    "response.output_text.delta",
                    {
                        "type": "response.output_text.delta",
                        "item_id": "msg_t06",
                        "output_index": 0,
                        "content_index": 0,
                        "delta": REPLY_TEXT,
                    },
                ),
                (
                    "response.output_item.done",
                    {"type": "response.output_item.done", "output_index": 0, "item": item},
                ),
                ("response.completed", {"type": "response.completed", "response": response}),
            ]
        )


def _json_or_empty(body: bytes) -> dict:
    try:
        value = json.loads(body or b"{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


class TLSServer(ThreadingHTTPServer):
    """One HTTPS listener. Counts each TCP accept, then does TLS in the connection's thread."""

    daemon_threads = True

    def __init__(self, port: int, context: ssl.SSLContext) -> None:
        super().__init__(("0.0.0.0", port), Handler)  # noqa: S104 - inside the fake internet
        self.listener = str(port)
        self.tls = context

    def process_request(self, request: socket.socket, client_address: object) -> None:
        with LOCK:
            ACCEPTS[self.listener] += 1
            number = ACCEPTS[self.listener]
        thread = threading.Thread(
            target=self._serve_tls, args=(request, client_address, number), daemon=True
        )
        thread.start()

    def _serve_tls(self, request: socket.socket, client_address: object, number: int) -> None:
        CURRENT.listener, CURRENT.accept, CURRENT.sni = self.listener, number, None
        try:
            request.settimeout(30)
            tls = self.tls.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError):
            request.close()
            return
        try:
            Handler(tls, client_address, self)
        except OSError:
            pass
        finally:
            tls.close()


def _remember_sni(sock: object, name: str | None, context: ssl.SSLContext) -> None:
    del sock, context
    CURRENT.sni = name


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(SERVER_PEM)
    context.set_alpn_protocols(["http/1.1"])
    context.sni_callback = _remember_sni
    servers: list[ThreadingHTTPServer] = [TLSServer(443, context), TLSServer(8443, context)]
    control = ThreadingHTTPServer(("0.0.0.0", 9000), Handler)  # noqa: S104 - see TLSServer
    control.daemon_threads = True
    servers.append(control)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(READY_LINE, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
