"""The fake internet of the T06-1 checks: HTTPS servers that say what reached them.

Runs inside a throwaway container on the test's egress network (``--internal``: it reaches
nothing real), as ``python3 /opt/t06/fake_internet.py``. Standard library only, so it runs in
the pinned mitmproxy image. Never contacted from the Mac and never with a real key.

- 443 and 8443: HTTPS with the test's own internet CA (``/opt/internet/server.pem``), HTTP/1.1
  only. Every accepted TCP connection is counted per listener *before* its TLS handshake, so
  a proxy that connects early is seen even if it never sends a request. Every request is
  answered with what arrived (listener, accept number, SNI, method, path, headers, body size),
  except the model APIs below. GET, POST, DELETE, PUT and PATCH (T10-2's held writes).
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
- T06-7, a provider whose answers are big: a model request with ``T06-BIG`` in it gets a
  JSON answer of BIG_ANSWER bytes (with its length), sent slowly over a few seconds, so several
  are held whole in the proxy at once (its HELD_BUDGET).
- T11's security review (evadir-el-tope): a model request with ``T11-CUT-TAIL`` in it gets a
  stream that stops for CUT_PAUSE seconds after its last ``content_block_stop``, before
  ``message_delta`` and ``message_stop`` (the agent hangs up there); with ``T11-NO-HEAD``, the
  answer waits SLOW_HEAD seconds before its status line (the agent hangs up before it).
- 53 (UDP and TCP): a resolver that logs every query and answers NXDOMAIN. The VM tests make it
  the proxy's upstream DNS (``test_dns``, T06-7): any name the proxy resolves that is not a
  container on its networks lands here, so a test sees which names left (``dns-tunel``).
- T10-5, a fake Telegram Bot API for OpenClaw's own Telegram channel: on ``api.telegram.org``,
  a bot whose token starts with ``FAKE_BOT_ID:`` is answered like the real Bot API (``getMe``,
  ``getUpdates`` by long polling from what the test pushes, ``sendMessage`` with a new message,
  ``true`` for the rest). Every other token still gets "what reached it" (T10-3's tests). Each
  call is also kept in ``telegram`` (method, chat, text, when), for the test.
- 9000: plain HTTP control, ``GET /stats``: accepts per listener, every request seen and every
  DNS query (and the fake bot's calls). ``POST /tg/push`` with an update (JSON, without
  ``update_id``) hands it to the fake bot's next ``getUpdates``.

Prints READY_LINE once all of them listen.
"""

import base64
import json
import re
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

READY_LINE = "t06-internet-ready"
SERVER_PEM = "/opt/internet/server.pem"
REPLY_TEXT = "T06 PONG FROM THE FAKE MODEL"
EXEC_MARK = re.compile(r"T06-EXEC:\[\[(.+?)\]\]", re.S)
ECHO_MARK = re.compile(rb"T06-ECHO-(JSON|SSE|B64|HEADER)")
ECHO_END = "END-OF-ECHO"
BIG_MARK = b"T06-BIG"
BIG_ANSWER = 15 * 1024 * 1024  # under the proxy's body_size_limit (16 MiB)
BIG_CHUNK = 1024 * 1024
BIG_PAUSE = 0.4  # seconds between chunks: about 6 s for the whole answer
CUT_MARK = b"T11-CUT-TAIL"
CUT_PAUSE = 6.0
SLOW_MARK = b"T11-NO-HEAD"
SLOW_HEAD = 8.0
DNS_QUERIES: list[dict] = []
DNS_ERRORS = {"udp": 0, "tcp": 0}  # a resolver that fails must show it, never prove "nothing came"

LOCK = threading.Lock()
ACCEPTS = {"443": 0, "8443": 0}
REQUESTS: list[dict] = []
# T10-5: the fake Bot API of OpenClaw's Telegram channel (never Telegram: invariant 8).
TELEGRAM_HOST = "api.telegram.org"
FAKE_BOT_ID = "7100000001"
TG_PATH = re.compile(r"/bot(\d+):([^/]+)/([A-Za-z]+)$")
TG_POLL_MAX = 20.0  # seconds a getUpdates waits at most
TG_CALLS: list[dict] = []
TG_UPDATES: list[dict] = []
TG_COND = threading.Condition(LOCK)
TG_NEXT = {"update": 5000, "message": 900}
CURRENT = threading.local()  # the connection a handler thread is serving


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib name
        del format, args  # quiet: the test reads /stats, never these logs

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    # T10-2: the writes the gate holds (a DELETE "that wipes buckets and their backups").
    def do_DELETE(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib name
        self._serve()

    def _serve(self) -> None:
        body = self._read_body()
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
            if self.command == "POST" and self.path == "/tg/push":
                self._tg_push(body)
                return
            self._control()
            return
        with LOCK:
            REQUESTS.append(record)
        path = self.path.split("?", 1)[0]
        bot = TG_PATH.fullmatch(path)
        host = (record["host"] or "").split(":")[0]
        if host == TELEGRAM_HOST and bot is not None and bot.group(1) == FAKE_BOT_ID:
            self._telegram(bot.group(3), body, record)
            return
        echo = ECHO_MARK.search(body)
        if BIG_MARK in body and path.endswith("/v1/messages"):
            self._big()
        elif CUT_MARK in body and path.endswith("/v1/messages"):
            self._anthropic_cut(_json_or_empty(body).get("model", "fake-model"))
        elif SLOW_MARK in body and path.endswith("/v1/messages"):
            time.sleep(SLOW_HEAD)
            try:
                self._anthropic(body)
            except OSError:
                self.close_connection = True  # the proxy hung up meanwhile
        elif echo is not None and path.endswith(("/v1/messages", "/chat/completions")):
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

    def _read_body(self) -> bytes:
        """The whole request body, by Content-Length or chunked. A chunked body left unread would
        make the socket close with data pending, and the kernel's reset can drop the answer that
        was already on its way (T06-7: fronting-y-tuneles's honest chunked POST)."""
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            body = bytearray()
            while True:
                size = int(self.rfile.readline(1024).split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                        pass  # trailers, if any
                    return bytes(body)
                body += self.rfile.read(size)
                self.rfile.readline(1024)  # the CRLF after each chunk
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length) if length else b""

    def _control(self) -> None:
        with LOCK:
            stats = {
                "accepts": dict(ACCEPTS),
                "requests": list(REQUESTS),
                "dns": list(DNS_QUERIES),
                "dns_errors": dict(DNS_ERRORS),
                "telegram": list(TG_CALLS),
            }
        self._json(200, stats)

    # The fake Bot API (T10-5)

    def _tg_push(self, body: bytes) -> None:
        update = _json_or_empty(body)
        with TG_COND:
            update_id = TG_NEXT["update"]
            TG_NEXT["update"] += 1
            TG_UPDATES.append({"update_id": update_id, **update})
            TG_COND.notify_all()
        self._json(200, {"ok": True, "update_id": update_id})

    def _telegram(self, method: str, body: bytes, record: dict) -> None:
        params = _tg_params(self.path, self.headers.get("content-type") or "", body)
        name = method.lower()
        call = {
            "at": time.time(),
            "method": method,
            "chat_id": str(params.get("chat_id", "")),
            "text": str(params.get("text", ""))[:500],
        }
        record["tg_method"] = method
        if name == "getupdates":
            self._tg_ok(_tg_updates(params))
            return
        with LOCK:
            TG_CALLS.append(call)
        if name == "getme":
            self._tg_ok({"id": int(FAKE_BOT_ID), "is_bot": True, "first_name": "T10 fake bot",
                         "username": "t10_fake_bot", "can_join_groups": False,
                         "can_read_all_group_messages": False,
                         "supports_inline_queries": False})  # fmt: skip
        elif name in ("getmycommands",):
            self._tg_ok([])
        elif name == "getwebhookinfo":
            self._tg_ok({"url": "", "has_custom_certificate": False, "pending_update_count": 0})
        elif name == "getchat":
            self._tg_ok({"id": _tg_int(params.get("chat_id")), "type": "private"})
        elif name.startswith("send") and name != "sendchataction":
            with LOCK:
                TG_NEXT["message"] += 1
                message_id = TG_NEXT["message"]
            chat = {"id": _tg_int(params.get("chat_id")), "type": "private", "first_name": "x"}
            message = {"message_id": message_id, "date": int(time.time()), "chat": chat,
                       "from": {"id": int(FAKE_BOT_ID), "is_bot": True,
                                "first_name": "T10 fake bot"},
                       "text": str(params.get("text", ""))}  # fmt: skip
            call["message_id"] = message_id
            self._tg_ok(message)
        else:
            self._tg_ok(True)

    def _tg_ok(self, result: object) -> None:
        self._json(200, {"ok": True, "result": result})

    def _big(self) -> None:
        """A model answer of BIG_ANSWER bytes of JSON, sent slowly."""
        head = (
            b'{"type": "message", "role": "assistant", "model": "fake-model", '
            b'"content": [{"type": "text", "text": "'
        )
        tail = b'"}], "stop_reason": "end_turn"}'
        data = head + b"a" * (BIG_ANSWER - len(head) - len(tail)) + tail
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        try:
            for start in range(0, len(data), BIG_CHUNK):
                self.wfile.write(data[start : start + BIG_CHUNK])
                self.wfile.flush()
                time.sleep(BIG_PAUSE)
        except OSError:
            self.close_connection = True  # the proxy cut it (its budget): nothing more to send

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

    def _anthropic_cut(self, model: str) -> None:
        """A stream whose text is all there, then a pause before the usage that ends it."""
        message = {"id": "msg_t11", "type": "message", "role": "assistant", "model": model,
                   "content": [], "stop_reason": None, "stop_sequence": None,
                   "usage": {"input_tokens": 12, "output_tokens": 1}}  # fmt: skip
        head = [
            ("message_start", {"type": "message_start", "message": message}),
            ("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": REPLY_TEXT}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ]  # fmt: skip
        tail = [
            ("message_delta", {"type": "message_delta", "usage": {"output_tokens": 900},
                               "delta": {"stop_reason": "end_turn", "stop_sequence": None}}),
            ("message_stop", {"type": "message_stop"}),
        ]  # fmt: skip
        try:
            self._sse(head)
            time.sleep(CUT_PAUSE)
            for name, data in tail:
                self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
                self.wfile.flush()
        except OSError:
            self.close_connection = True  # the proxy hung up: nothing more to send

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


def _tg_params(path: str, content_type: str, body: bytes) -> dict:
    """The Bot API's parameters, from the query, a form or a JSON body (multipart: ignored)."""
    from urllib.parse import parse_qsl

    params: dict = dict(parse_qsl(path.partition("?")[2]))
    kind = content_type.split(";")[0].strip().lower()
    if kind == "application/json":
        params.update(_json_or_empty(body))
    elif kind == "application/x-www-form-urlencoded":
        params.update(parse_qsl(body.decode("utf-8", "replace")))
    return params


def _tg_int(value: object) -> int:
    try:
        return int(str(value))
    except ValueError:
        return 0


def _tg_updates(params: dict) -> list[dict]:
    """Long polling: the pushed updates from ``offset`` on, waiting up to ``timeout`` s."""
    offset = _tg_int(params.get("offset", 0))
    wait = min(float(_tg_int(params.get("timeout", 0))), TG_POLL_MAX)
    deadline = time.monotonic() + wait
    with TG_COND:
        while True:
            ready = [u for u in TG_UPDATES if u["update_id"] >= offset]
            left = deadline - time.monotonic()
            if ready or left <= 0:
                return ready[:100]
            TG_COND.wait(left)


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


def _question_name(packet: bytes) -> str:
    labels, offset = [], 12
    while offset < len(packet) and packet[offset] != 0 and len(labels) < 128:
        size = packet[offset]
        labels.append(packet[offset + 1 : offset + 1 + size].decode("ascii", "replace"))
        offset += 1 + size
    return ".".join(labels)


def _nxdomain(packet: bytes) -> bytes:
    if len(packet) < 12:
        return b""
    (ident,) = struct.unpack("!H", packet[:2])
    end = packet.find(b"\x00", 12)
    question = packet[12 : end + 5] if end > 0 else b""
    return struct.pack("!HHHHHH", ident, 0x8183, 1 if question else 0, 0, 0, 0) + question


def _log_query(packet: bytes, proto: str, peer: str) -> None:
    with LOCK:
        DNS_QUERIES.append(
            {"at": time.time(), "name": _question_name(packet), "proto": proto, "from": peer}
        )


def _dns_error(proto: str) -> None:
    with LOCK:
        DNS_ERRORS[proto] += 1


def _serve_dns_udp(sock: socket.socket) -> None:
    while True:
        try:
            packet, peer = sock.recvfrom(4096)
            _log_query(packet, "udp", peer[0])
            sock.sendto(_nxdomain(packet), peer)
        except Exception:  # noqa: BLE001 - counted in /stats, and the loop keeps serving
            _dns_error("udp")


def _serve_dns_tcp(sock: socket.socket) -> None:
    while True:
        try:
            conn, peer = sock.accept()
        except OSError:
            _dns_error("tcp")
            continue
        with conn:
            try:
                conn.settimeout(5)
                (size,) = struct.unpack("!H", conn.recv(2))
                packet = conn.recv(size)
                _log_query(packet, "tcp", peer[0])
                reply = _nxdomain(packet)
                conn.sendall(struct.pack("!H", len(reply)) + reply)
            except Exception:  # noqa: BLE001 - counted in /stats, and the loop keeps serving
                _dns_error("tcp")


def main() -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 53))  # noqa: S104 - inside the fake internet
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", 53))  # noqa: S104 - inside the fake internet
    tcp.listen(16)
    threading.Thread(target=_serve_dns_udp, args=(udp,), daemon=True).start()
    threading.Thread(target=_serve_dns_tcp, args=(tcp,), daemon=True).start()
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
