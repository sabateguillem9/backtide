"""The local preview server (scripts/serve_static.py): byte ranges, so Safari plays the film."""

import http.client
import importlib.util
import threading
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "serve_static.py"


@pytest.fixture
def served(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("serve_static", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "film.mp4").write_bytes(bytes(range(256)) * 4)
    handler = partial(module.RangeHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def get(port: int, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/film.mp4", headers=headers or {})
    reply = conn.getresponse()
    body = reply.read()
    conn.close()
    return reply.status, {k.lower(): v for k, v in reply.getheaders()}, body


def test_a_range_comes_back_partial(served: int) -> None:
    status, headers, body = get(served, {"Range": "bytes=10-19"})
    assert status == 206 and body == bytes(range(10, 20))
    assert headers["content-range"] == "bytes 10-19/1024" and headers["content-length"] == "10"


def test_open_and_suffix_ranges(served: int) -> None:
    assert get(served, {"Range": "bytes=1020-"})[2] == bytes(range(252, 256))
    assert get(served, {"Range": "bytes=-3"})[2] == bytes(range(253, 256))


def test_whole_file_and_out_of_range(served: int) -> None:
    status, headers, body = get(served)
    assert status == 200 and len(body) == 1024 and headers["accept-ranges"] == "bytes"
    assert get(served, {"Range": "bytes=5000-"})[0] == 416
