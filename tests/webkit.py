"""Helpers shared by the tests of backtide.web: a black box written by the real BlackBox, and the
app on top of it, reached with Host 127.0.0.1:PORT like a browser would."""

import threading
import warnings
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from backtide.blackbox import BlackBox, Event
from backtide.web import BoxReader, create_app
from tests.conftest import FakeClock

KEY = bytes(range(32))
TOKEN = "t0ken-for-the-tests-only"  # noqa: S105 - the link's one-time token, a test value
SESSION = "sesion-secret-for-the-tests-only"  # noqa: S105 - what the cookie holds
PREFIX = "pref0123456789abcdefghijkl"  # the random segment of /s/<prefix>/
PREFIX_PATH = f"/s/{PREFIX}"
RUN_NAME = "marea-faro-nube"
PORT = 8765
ROOT = f"http://127.0.0.1:{PORT}"
BASE = f"{ROOT}{PREFIX_PATH}"
START = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
WAIT = 10.0  # what a test waits for the app's threads at most, on any machine


def new_box(tmp_path: Path, clock: FakeClock | None = None) -> BlackBox:
    return BlackBox(
        tmp_path / "blackbox.db",
        KEY,
        checkpoint_path=tmp_path / "blackbox.checkpoint",
        clock=clock if clock is not None else FakeClock(START),
    )


def new_app(tmp_path: Path, *, reader: BoxReader | None = None, **options):  # noqa: ANN201 - the guarded ASGI app
    reader = reader if reader is not None else BoxReader(tmp_path / "blackbox.db")
    options.setdefault("tz", UTC)
    options.setdefault("clock", lambda: START)
    return create_app(
        reader=reader,
        port=PORT,
        token=TOKEN,
        session=SESSION,
        prefix=PREFIX,
        run_name=RUN_NAME,
        **options,
    )


def new_client(tmp_path: Path, *, logged_in: bool = True, **options) -> TestClient:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        client = TestClient(new_app(tmp_path, **options), base_url=BASE)
    if logged_in:
        client.cookies.set("backtide_web", SESSION, domain="127.0.0.1", path=PREFIX_PATH)
    return client


class WatchedReader(BoxReader):
    """A BoxReader that tells the test what a stream has read. "An event that arrives while
    the stream is open" was a writer that slept a guess and hoped to land inside the stream's
    few tenths of a second; a slow runner started the stream late or wrote late (CI did).
    Writing once the stream has read the box, and waiting for the read that returned what was
    written, cannot miss on any machine."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._changed = threading.Condition()
        self._reads = 0
        self._newest = 0

    def events(self, **filters: Any) -> list[Event]:
        batch: list[Event] = []
        try:
            batch = super().events(**filters)
            return batch
        finally:  # a read that failed (no box yet) is a read too
            with self._changed:
                self._reads += 1
                self._newest = max([self._newest, *(event.seq for event in batch)])
                self._changed.notify_all()

    def wait_read(self, timeout: float = WAIT) -> None:
        """Until the stream has read the box once."""
        self._wait(lambda: self._reads > 0, timeout, "the stream never read the box")

    def wait_seen(self, seq: int, timeout: float = WAIT) -> None:
        """Until a read has returned the event ``seq``."""
        self._wait(lambda: self._newest >= seq, timeout, f"the stream never read event {seq}")

    def _wait(self, done: Callable[[], bool], timeout: float, why: str) -> None:
        with self._changed:
            if not self._changed.wait_for(done, timeout):
                raise AssertionError(why)


def parse_sse(body: str) -> list[dict[str, str]]:
    """The events of a text/event-stream body: {event, id, data}; a comment has ``comment``."""
    events: list[dict[str, str]] = []
    for block in body.split("\n\n"):
        if not block.strip():
            continue
        parsed: dict[str, list[str]] = {}
        for line in block.split("\n"):
            if line.startswith(":"):
                parsed.setdefault("comment", []).append(line[1:].strip())
                continue
            name, _, value = line.partition(":")
            parsed.setdefault(name, []).append(value[1:] if value.startswith(" ") else value)
        events.append({name: "\n".join(values) for name, values in parsed.items()})
    return events


class LiveServer:
    """The real thing: uvicorn on a real 127.0.0.1 socket in a thread, with the app for the
    black box in ``tmp_path``. ``with LiveServer(tmp_path) as live:`` then plain HTTP to
    ``live.base``."""

    def __init__(self, tmp_path: Path, **options) -> None:
        from backtide.web.server import bind, make_server

        self.sock = bind(0)
        self.port = self.sock.getsockname()[1]
        reader = BoxReader(tmp_path / "blackbox.db")
        options.setdefault("poll_interval", 0.05)
        self.app = create_app(
            reader=reader,
            port=self.port,
            token=TOKEN,
            session=SESSION,
            prefix=PREFIX,
            run_name=RUN_NAME,
            **options,
        )
        self.server = make_server(self.app)
        self.thread = __import__("threading").Thread(
            target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True
        )
        self.root = f"http://127.0.0.1:{self.port}"
        self.base = f"{self.root}{PREFIX_PATH}"

    def __enter__(self) -> "LiveServer":
        import time

        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("the server did not start")
            time.sleep(0.01)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(10)
        self.sock.close()
