"""The fake internet of the T06-1 checks: HTTPS servers that say what reached them.

Runs inside a throwaway container on the test's egress network (``--internal``: it reaches
nothing real), as ``python3 /opt/t06/fake_internet.py``. Standard library only, so it runs in
the pinned mitmproxy image. Never contacted from the Mac and never with a real key.

- 443 and 8443: HTTPS with the test's own internet CA (``/opt/internet/server.pem``), HTTP/1.1
  only. Every accepted TCP connection is counted per listener *before* its TLS handshake, so
  a proxy that connects early is seen even if it never sends a request. Every request is
  answered with what arrived (listener, accept number, SNI, method, path, headers, body size),
  except the model APIs below.
- ``/v1/messages``: a fake Anthropic Messages API (JSON or SSE, ``"stream": true``). A user
  message with ``T06-EXEC:[[<command>]]`` in it is answered with a call of the ``exec`` tool
  running that command (T06-5: what does a command of the agent see?); the turn that brings
  its result back gets the usual text.
- ``.../chat/completions``: a fake OpenAI-compatible Chat Completions API (JSON or SSE).
- T06-6, a provider that echoes the key it got: a model request with ``T06-ECHO-JSON`` in it is
  answered with a JSON error that quotes the key; with ``T06-ECHO-SSE``, a stream whose text
  deltas spell the key in three pieces; with ``T06-ECHO-B64``, a stream with the key in base64;
  with ``T06-ECHO-HEADER``, an ordinary answer with the key in a response header.
  Each stream ends with the text ``END-OF-ECHO``, so a test sees where it was cut.
- ``.../responses``: a fake OpenAI Responses API (JSON or SSE).
- 9000: plain HTTP control, ``GET /stats``: accepts per listener and every request seen.

Prints READY_LINE once all three listen.
"""

import base64
import json
import re
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

READY_LINE = "t06-internet-ready"
SERVER_PEM = "/opt/internet/server.pem"
REPLY_TEXT = "T06 PONG FROM THE FAKE MODEL"
EXEC_MARK = re.compile(r"T06-EXEC:\[\[(.+?)\]\]", re.S)
ECHO_MARK = re.compile(rb"T06-ECHO-(JSON|SSE|B64|HEADER)")
ECHO_END = "END-OF-ECHO"

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
        echo = ECHO_MARK.search(body)
        if echo is not None and path.endswith(("/v1/messages", "/chat/completions")):
            self._echo(echo.group(1).decode(), anthropic=path.endswith("/v1/messages"))
        elif path.endswith("/v1/messages"):
            record["model_turn"] = _turn_summary(_json_or_empty(body))
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

    def _echo(self, mode: str, *, anthropic: bool) -> None:
        """A provider that hands back the key it received (what the gate must never let reach
        the agent): quoted in an error, spelled over three text deltas, or in base64."""
        if anthropic:
            key = self.headers.get("x-api-key") or ""
        else:
            key = (self.headers.get("authorization") or "").removeprefix("Bearer ")
        if mode == "HEADER":
            data = json.dumps({"type": "message", "content": [], "model": "fake-model"}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("x-echo-key", key)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if mode == "JSON":
            error = {"type": "authentication_error", "message": f"invalid key {key}"}
            self._json(401, {"type": "error", "error": error})
            return
        third = max(1, len(key) // 3)
        if mode == "SSE":
            pieces = ["your key: ", key[:third], key[third : 2 * third], key[2 * third :]]
        else:
            pieces = ["your key in base64: ", base64.b64encode(key.encode()).decode()]
        pieces.append(f" {ECHO_END}")
        if anthropic:
            message = {"id": "msg_echo", "type": "message", "role": "assistant",
                       "model": "fake-model", "content": []}  # fmt: skip
            events: list[tuple[str | None, object]] = [
                ("message_start", {"type": "message_start", "message": message})
            ]
            for text in pieces:
                delta = {"type": "content_block_delta", "index": 0,
                         "delta": {"type": "text_delta", "text": text}}  # fmt: skip
                events.append(("content_block_delta", delta))
            events.append(("message_stop", {"type": "message_stop"}))
        else:
            events = [
                (
                    None,
                    {
                        "object": "chat.completion.chunk",
                        "model": "fake-model",
                        "choices": [{"index": 0, "delta": {"content": text}}],
                    },
                )  # fmt: skip
                for text in pieces
            ]
            events.append((None, "[DONE]"))
        self._sse(events)

    def _anthropic(self, body: bytes) -> None:
        request = _json_or_empty(body)
        model = request.get("model", "fake-model")
        command = _exec_asked(request)
        if command is not None and request.get("stream"):
            self._anthropic_tool_use(model, command)
            return
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

    def _anthropic_tool_use(self, model: str, command: str) -> None:
        message = {
            "id": "msg_t06_tool",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 1},
        }
        block = {"type": "tool_use", "id": "toolu_t06_exec", "name": "exec", "input": {}}
        self._sse(
            [
                ("message_start", {"type": "message_start", "message": message}),
                (
                    "content_block_start",
                    {"type": "content_block_start", "index": 0, "content_block": block},
                ),
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps({"command": command}),
                        },
                    },
                ),
                ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                (
                    "message_delta",
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                        "usage": {"output_tokens": 9},
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


def _turn_summary(request: dict) -> dict:
    """What the test may want to see of a model request: the tool names it offers, the exec it
    gets asked for, and the start of the last tool result (never more than 2 KiB)."""
    tools = request.get("tools")
    names = [t.get("name") for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []
    result = None
    messages = request.get("messages")
    if isinstance(messages, list) and messages and isinstance(messages[-1], dict):
        content = messages[-1].get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    result = json.dumps(block.get("content"))[:2048]
    last_text = None
    if isinstance(messages, list) and messages and isinstance(messages[-1], dict):
        last_text = json.dumps(messages[-1].get("content"))[:300]
    return {"tools": names, "exec": _exec_asked(request), "tool_result": result, "last": last_text}


def _exec_asked(request: dict) -> str | None:
    """The command of ``T06-EXEC:[[...]]`` in the user's latest messages (those after the last
    answer of the model), unless they bring a tool's result back (that ends the exchange)."""
    messages = request.get("messages")
    if not isinstance(messages, list):
        return None
    for message in reversed(messages):
        if not isinstance(message, dict) or message.get("role") != "user":
            return None
        content = message.get("content")
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
        if not isinstance(blocks, list):
            continue
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in blocks):
            return None
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text":
                found = EXEC_MARK.search(str(b.get("text", "")))
                if found:
                    return found.group(1)
    return None


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
