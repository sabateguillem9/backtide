"""The web for real: uvicorn on a real 127.0.0.1 socket, a black box written by the real BlackBox
(WAL, fsync), a real HTTP client, and the event stream read as a browser would read it."""

import socket
import threading
import time
from pathlib import Path

import httpx2 as httpx
import pytest

from tests.webkit import PREFIX_PATH, SESSION, TOKEN, LiveServer, new_box
from vigia.web.server import LOOPBACK, bind


def read_until(response: httpx.Response, wanted: str, seconds: float = 10.0) -> list[str]:
    """Lines of an open event stream until one contains ``wanted``."""
    lines: list[str] = []
    deadline = time.monotonic() + seconds
    for line in response.iter_lines():
        lines.append(line)
        if wanted in line:
            return lines
        if time.monotonic() > deadline:
            break
    pytest.fail(f"never saw {wanted!r}; got {lines[-5:]}")


def test_a_real_browser_session_end_to_end(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "service_start", "")
    box.append("system", "agent_start", "")
    box.append("file", "create", "notas.md", details={"type": "file"})

    with LiveServer(tmp_path) as live, httpx.Client(base_url=live.base) as browser:
        # 1. the link with the token: a redirect without it, and a cookie
        first = browser.get(f"/?t={TOKEN}", follow_redirects=False)
        assert first.status_code == 200 and f'content="0;url={PREFIX_PATH}/"' in first.text
        page = browser.get("/", follow_redirects=True)  # the refresh; "/" sends on to "Ahora"
        assert page.status_code == 200 and "Ha creado" in page.text and "notas.md" in page.text
        assert f'sse-connect="{PREFIX_PATH}/ahora/stream?after=3"' in page.text

        # 2. the live stream: an event written NOW shows up without reloading
        stream_url = f"/ahora/stream?after={3}"
        with browser.stream("GET", stream_url) as events:
            assert events.headers["content-type"].startswith("text/event-stream")
            writer = threading.Timer(0.3, lambda: box.append("file", "delete", "notas.md", risk=2))
            writer.start()
            seen = read_until(events, "Ha borrado")
            writer.join()
        assert any(line.startswith("event: lines") for line in seen)
        assert any(line.startswith("id: 4") for line in seen)

        # 3. the other pages over the same black box
        assert "notas.md" in browser.get("/historia").text
        assert browser.get("/instantaneas").status_code == 200


def test_the_real_server_checks_the_host_and_the_token(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "secret-plans.md")
    with LiveServer(tmp_path) as live:
        raw = httpx.Client(base_url=live.base)
        assert httpx.get(f"{live.root}/ahora").status_code == 404  # outside the prefix: nothing
        assert raw.get("/ahora").status_code == 401  # no token
        assert raw.get("/ahora", headers={"host": "evil.example"}).status_code == 400
        rebound = raw.get(f"/ahora?t={TOKEN}", headers={"host": f"evil.example:{live.port}"})
        assert rebound.status_code == 400 and "set-cookie" not in rebound.headers
        assert raw.post("/ahora").status_code == 405
        assert "secret-plans" not in raw.get("/ahora").text


def test_the_socket_is_loopback_only(tmp_path: Path) -> None:
    sock = bind(0)
    try:
        host, port = sock.getsockname()
        assert host == LOOPBACK == "127.0.0.1"
        # nothing else of this machine's addresses answers on that port
        other = socket.gethostbyname(socket.gethostname()) if _has_other_address() else None
        if other and other != "127.0.0.1":
            probe = socket.socket()
            probe.settimeout(0.5)
            assert probe.connect_ex((other, port)) != 0
            probe.close()
    finally:
        sock.close()


def _has_other_address() -> bool:
    try:
        return socket.gethostbyname(socket.gethostname()) != "127.0.0.1"
    except OSError:
        return False


def test_a_port_in_use_is_an_oserror() -> None:
    first = bind(0)
    try:
        with pytest.raises(OSError):
            bind(first.getsockname()[1])
    finally:
        first.close()


def test_the_server_stops_promptly_with_a_stream_open(tmp_path: Path) -> None:
    new_box(tmp_path).append("system", "agent_start", "")
    started = time.monotonic()
    with LiveServer(tmp_path) as live, httpx.Client(base_url=live.base) as browser:
        browser.cookies.set("vigia_web", SESSION, domain="127.0.0.1", path=PREFIX_PATH)
        with browser.stream("GET", "/ahora/stream?after=1") as events:
            lines = events.iter_lines()
            next(lines)
            # Ctrl-C now: the server must not wait for this stream to end by itself
            live.server.should_exit = True
            with pytest.raises(httpx.TransportError):  # cut after the 2 s of grace, not waited for
                for _ in lines:
                    pass
    assert time.monotonic() - started < 10
