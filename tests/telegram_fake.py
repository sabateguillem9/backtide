"""A fake Telegram Bot API for the tests (T09): a tiny HTTP server on 127.0.0.1 (stdlib
``http.server``) that answers like the real one at ``/bot<token>/<method>``.

It never talks to Telegram. It records every call (method, parameters, when), serves
``getUpdates`` by long polling from updates the test pushes (``push_message``,
``push_callback``), and answers ``sendMessage`` with a new ``message_id``. A wrong token gets
401, as the real API does. Used by the unit tests on the Mac and by the VM tests, where the
real service points ``api_base`` at it.

    with FakeBotApi(TOKEN) as fake:
        api = BotApi(TOKEN, base=fake.base)
        fake.push_message("/pausar", chat_id=OWNER)
        fake.wait_call("sendMessage")
"""

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

TOKEN = "123456789:" + "A" * 35  # the shape of a real token; not one
OWNER = 424242424
STRANGER = 777000111


@dataclass
class Call:
    method: str
    params: dict[str, Any]
    at: float  # time.monotonic() when it arrived
    path: str = ""
    result: Any = None  # what the fake answered (a sendMessage: the message, with its id)
    wall: float = field(default_factory=time.time)  # the wall clock, to compare with events

    @property
    def message_id(self) -> int:
        assert isinstance(self.result, dict), self.result
        return self.result["message_id"]


@dataclass
class FakeBotApi:
    token: str = TOKEN
    calls: list[Call] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)
    next_update_id: int = 1000
    next_message_id: int = 1
    max_poll: float = 2.0  # a getUpdates waits at most this long, whatever it asks for
    redirect_to: str | None = None  # answer every call with a 302 to here
    fail_with: int | None = None  # answer every call with this HTTP status
    offsets: list[Any] = field(default_factory=list)  # of every getUpdates, at arrival

    def __post_init__(self) -> None:
        self._cond = threading.Condition()
        self._closed = False
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server's name
                fake._serve(self)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "FakeBotApi":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        self._server.shutdown()
        self._server.server_close()

    # What the test pushes

    def push(self, update: dict[str, Any]) -> int:
        with self._cond:
            update_id = self.next_update_id
            self.next_update_id += 1
            self.updates.append({"update_id": update_id, **update})
            self._cond.notify_all()
        return update_id

    def push_message(
        self,
        text: str,
        *,
        chat_id: int = OWNER,
        from_id: int | None = None,
        chat_type: str = "private",
        date: float | None = None,
        **extra: Any,
    ) -> int:
        sender = from_id if from_id is not None else chat_id
        message = {
            "message_id": self._new_message_id(),
            "date": int(date if date is not None else time.time()),
            "chat": {"id": chat_id, "type": chat_type},
            "from": {"id": sender, "is_bot": False, "first_name": "x"},
            "text": text,
            **extra,
        }
        return self.push({"message": message})

    def push_callback(
        self,
        data: str,
        message_id: int,
        *,
        from_id: int = OWNER,
        chat_id: int | None = None,
    ) -> int:
        chat = chat_id if chat_id is not None else from_id
        query = {
            "id": f"cq{self.next_update_id}",
            "from": {"id": from_id, "is_bot": False, "first_name": "x"},
            "message": {"message_id": message_id, "chat": {"id": chat, "type": "private"}},
            "chat_instance": "1",
            "data": data,
        }
        return self.push({"callback_query": query})

    # What the test reads

    def sent(self, method: str = "sendMessage") -> list[Call]:
        with self._cond:
            return [call for call in self.calls if call.method == method]

    def wait_call(
        self,
        method: str,
        predicate: Callable[[Call], bool] = lambda call: True,
        *,
        timeout: float = 5.0,
        after: float = float("-inf"),
    ) -> Call:
        """The first call of ``method`` (arrived after ``after``) for which ``predicate``
        holds, waiting up to ``timeout`` seconds."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for call in self.calls:
                    if call.method == method and call.at > after and predicate(call):
                        return call
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    seen = [(c.method, c.params.get("text", "")[:60]) for c in self.calls[-10:]]
                    raise AssertionError(f"no {method} in {timeout} s; last calls: {seen}")
                self._cond.wait(remaining)

    def polls(self) -> int:
        """getUpdates calls that have arrived (finished or still waiting)."""
        with self._cond:
            return len(self.offsets)

    def confirmed(self) -> int:
        """The highest offset a getUpdates has sent (every update below it is confirmed)."""
        with self._cond:
            return max((o for o in self.offsets if isinstance(o, int)), default=0)

    # Serving

    def _new_message_id(self) -> int:
        with self._cond:
            found = self.next_message_id
            self.next_message_id += 1
            return found

    def _serve(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        raw = handler.rfile.read(length) if length else b"{}"
        try:
            params = json.loads(raw.decode("utf-8"))
        except ValueError:
            params = {}
        prefix, _, method = handler.path.rpartition("/")
        call = Call(method, params, time.monotonic(), handler.path)
        if method == "getUpdates":
            with self._cond:  # at arrival: the offset confirms what came before it
                self.offsets.append(params.get("offset"))
                self._cond.notify_all()
        if (
            self.redirect_to is not None
            or self.fail_with is not None
            or prefix != f"/bot{self.token}"
        ):
            with self._cond:
                self.calls.append(call)
                self._cond.notify_all()
        if self.redirect_to is not None:
            handler.send_response(302)
            handler.send_header("Location", self.redirect_to)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        if self.fail_with is not None:
            # The description quotes the token: the client must take it out.
            failure = f"failing on purpose {self.token}"
            body = {"ok": False, "error_code": self.fail_with, "description": failure}
            self._reply(handler, self.fail_with, body)
            return
        if prefix != f"/bot{self.token}":
            self._reply(
                handler, 401, {"ok": False, "error_code": 401, "description": "Unauthorized"}
            )
            return
        call.result = self._result(method, params)
        with self._cond:  # recorded with its answer, before the client sees it
            self.calls.append(call)
            self._cond.notify_all()
        self._reply(handler, 200, {"ok": True, "result": call.result})

    def _result(self, method: str, params: dict[str, Any]) -> Any:
        if method == "getUpdates":
            offset = params.get("offset") or 0
            wait = min(float(params.get("timeout") or 0), self.max_poll)
            deadline = time.monotonic() + wait
            with self._cond:
                while True:
                    ready = [u for u in self.updates if u["update_id"] >= offset]
                    remaining = deadline - time.monotonic()
                    if ready or remaining <= 0 or self._closed:
                        return ready[:100]
                    self._cond.wait(remaining)
        if method == "sendMessage":
            return {
                "message_id": self._new_message_id(),
                "date": int(time.time()),
                "chat": {"id": params.get("chat_id"), "type": "private"},
                "text": params.get("text", ""),
            }
        return True

    @staticmethod
    def _reply(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)


def buttons(call: Call) -> list[tuple[str, str]]:
    """The (label, callback_data) of every button of a sendMessage."""
    markup = call.params.get("reply_markup") or {}
    return [
        (button["text"], button["callback_data"])
        for row in markup.get("inline_keyboard", [])
        for button in row
    ]
