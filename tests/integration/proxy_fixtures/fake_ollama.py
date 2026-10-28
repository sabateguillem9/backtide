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
  With ``T20-SLOW`` it waits SLOW_SECONDS before answering, and counts how many such calls it
  holds at once (``slow`` in ``/stats``: T20-5's flood, against ``max_inflight_local``).
  For `backtide tarea` with OpenClaw (D27): with ``T20-LATE-<tag>``, it waits LATE_SECONDS,
  then answers with a call to the agent's file-writing tool (``LATE_TOOLS``) that creates
  ``/workspace/work/tarde-<tag>``: the later effect of a turn that should have been stopped
  (once per tag; after that it answers REPLY_TEXT). With ``T20-ESC-<marker>``, its answer
  carries escape sequences (an OSC 52 with the marker, then a clear screen); with
  ``T20-ERRESC-<marker>``, it answers 400 with those in the error's message. These three look
  only at this turn's user messages: the conversation's history repeats old ones.
- 22, 80, 443 and 8080: decoys. They count every TCP connection and close it: the tests check
  that nothing ever reaches them.
- 9000: control, ``GET /stats``: every request seen on 11434 (method, path, headers, body size,
  the ``model`` and the top-level fields of a JSON body, the peer's address) and the connections
  accepted per port. ``GET /api/version`` says VERSION: the service asks it from the VM, never
  through the proxy (``system/provider_local_ready``), so its peer is not the proxy's.

Prints READY_LINE once all of them listen.
"""

import base64
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

READY_LINE = "t20-ollama-ready"
REPLY_TEXT = "T20 PONG FROM THE FAKE OLLAMA"
MODEL = "t20-fake-coder:7b"
VERSION = "0.40.8"  # what it says it is
DECOYS = (22, 80, 443, 8080)
LOCK = threading.Lock()
REQUESTS: list[dict] = []
ACCEPTS = {str(p): 0 for p in (11434, 22, 80, 443, 8080)}
SLOW_SECONDS = 4.0
LATE_SECONDS = 20.0  # longer than any turn's start, so a deadline can fall inside it
SLOW = {"now": 0, "max": 0, "seen": 0}  # T20-SLOW calls held at once, at most, and in all
LATE_RE = re.compile(r"T20-LATE-([a-z0-9]{1,32})")
ESC_RE = re.compile(r"T20-(ERR)?ESC-([a-z0-9]{1,32})")
LATE_CALLED: set[str] = set()  # each tag gets its late call once, whatever comes after
# The tools that write a file, and how each takes it, in the order it looks for them.
LATE_TOOLS = (
    ("write", lambda path: {"path": path, "content": "tarde\n"}),
    ("exec", lambda path: {"command": f"touch {path}"}),
    ("bash", lambda path: {"command": f"touch {path}"}),
)


def escapes(marker: str) -> str:
    """What an evil model answers to reach the owner's terminal: its clipboard (OSC 52 with the
    marker, base64) and a clear screen."""
    return f"\x1b]52;c;{base64.b64encode(marker.encode()).decode()}\x07\x1b[2J"


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
        tools = tool_names(request)
        messages = request.get("messages") if isinstance(request, dict) else None
        last = messages[-1] if isinstance(messages, list) and messages else None
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
                    "tools": tools,
                    "last_role": last.get("role") if isinstance(last, dict) else None,
                    "late": bool(LATE_RE.search(turn_text(request))),
                    "roles": [m.get("role") for m in messages if isinstance(m, dict)][-6:]
                    if isinstance(messages, list)
                    else [],
                    "turn": turn_text(request)[-160:],
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

    def _slowly(self, seconds: float = SLOW_SECONDS) -> None:
        with LOCK:
            SLOW["now"] += 1
            SLOW["seen"] += 1
            SLOW["max"] = max(SLOW["max"], SLOW["now"])
        try:
            time.sleep(seconds)
        finally:
            with LOCK:
                SLOW["now"] -= 1

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
        if b"T20-SLOW" in body:
            self._slowly()
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
        asked = turn_text(request)  # never the history: an old trigger fires once
        escaped = ESC_RE.search(asked)
        if escaped and escaped.group(1) and path == "/v1/chat/completions":
            message = escapes(escaped.group(2)) + " T20 MODEL ERROR"
            error = {"error": {"message": message, "type": "invalid_request_error"}}
            self._send(400, json.dumps(error).encode())
            return
        late = LATE_RE.search(asked)
        if late and path == "/v1/chat/completions" and late.group(1) not in LATE_CALLED:
            with LOCK:
                LATE_CALLED.add(late.group(1))
            self._slowly(LATE_SECONDS)
            call = late_call(request, late.group(1))
            if call is not None:
                self._tool_call(call, stream=request.get("stream") is True)
                return
        text = REPLY_TEXT
        if escaped:
            text = f"{escapes(escaped.group(2))} {REPLY_TEXT}"
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
                "choices": [{"index": 0, "delta": {"content": text}}],
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
                    "message": {"role": "assistant", "content": text},
                }
            ],
            "usage": {"prompt_tokens": 7, "completion_tokens": 8, "total_tokens": 15},
        }
        self._send(200, json.dumps(answer).encode())

    def _tool_call(self, call: dict, *, stream: bool) -> None:
        if stream:
            chunk = {
                "id": "chatcmpl-t20", "object": "chat.completion.chunk", "model": MODEL,
                "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
                    {"index": 0, **call}]}}],
            }  # fmt: skip
            end = {
                "id": "chatcmpl-t20", "object": "chat.completion.chunk", "model": MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
            }  # fmt: skip
            data = f"data: {json.dumps(chunk)}\n\ndata: {json.dumps(end)}\n\ndata: [DONE]\n\n"
            self._send(200, data.encode(), "text/event-stream")
            return
        answer = {
            "id": "chatcmpl-t20", "object": "chat.completion", "model": MODEL,
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [call]}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 8, "total_tokens": 15},
        }  # fmt: skip
        self._send(200, json.dumps(answer).encode())


def tool_names(request: object) -> list[str]:
    """The names of the tools an OpenAI-shaped request offers."""
    tools = request.get("tools") if isinstance(request, dict) else None
    names = []
    for tool in tools if isinstance(tools, list) else []:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.append(function["name"])
    return names


def turn_text(request: object) -> str:
    """The text of this turn's user messages in an OpenAI-shaped request: those after the last
    assistant message (never the history, which repeats old triggers)."""
    messages = request.get("messages") if isinstance(request, dict) else None
    texts: list[str] = []
    for message in reversed(messages if isinstance(messages, list) else []):
        if not isinstance(message, dict) or message.get("role") == "assistant":
            break
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(
                part["text"]
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            )
    return " ".join(reversed(texts))


def late_call(request: dict, tag: str) -> dict | None:
    """The call that writes ``/workspace/work/tarde-<tag>`` with the first offered LATE_TOOLS."""
    offered = tool_names(request)
    path = f"/workspace/work/tarde-{tag}"
    for name, arguments in LATE_TOOLS:
        if name in offered:
            function = {"name": name, "arguments": json.dumps(arguments(path))}
            return {"id": f"call_{tag}", "type": "function", "function": function}
    return None


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
            data = json.dumps({"requests": REQUESTS, "accepts": ACCEPTS, "slow": SLOW}).encode()
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
