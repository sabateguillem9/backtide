"""A static file server for previewing site/ and brand/ on the Mac, with byte ranges.

Usage: python3 scripts/serve_static.py <directory> [port]

``python -m http.server`` answers every request whole (200). Safari will not play a video
served that way: it asks for byte ranges and needs 206 Partial Content back. This adds one
range per request (``bytes=a-b``, ``bytes=a-``, ``bytes=-n``), which is all a browser asks
for a <video>. Local preview only: it binds 127.0.0.1 and serves one directory.
"""

import http.server
import os
import re
import sys
from functools import partial

_RANGE = re.compile(r"bytes=(\d*)-(\d*)$")


class RangeHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, as browsers expect for media

    def send_head(self):  # type: ignore[override]
        wanted = self.headers.get("Range")
        path = self.translate_path(self.path)
        if not wanted or os.path.isdir(path) or not os.path.isfile(path):
            return super().send_head()
        match = _RANGE.match(wanted.strip())
        size = os.path.getsize(path)
        if not match or not any(match.groups()):
            return super().send_head()
        first, last = match.groups()
        if first:
            start = int(first)
            end = min(int(last), size - 1) if last else size - 1
        else:
            start, end = max(0, size - int(last)), size - 1
        if start >= size or start > end:
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{size}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        handle = open(path, "rb")  # noqa: SIM115 - closed by copyfile's caller
        handle.seek(start)
        self._left = end - start + 1
        self.send_response(206)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Length", str(self._left))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        return handle

    def copyfile(self, source, outputfile):  # type: ignore[override]
        left = getattr(self, "_left", None)
        if left is None:
            return super().copyfile(source, outputfile)
        while left > 0:
            chunk = source.read(min(64 * 1024, left))
            if not chunk:
                break
            outputfile.write(chunk)
            left -= len(chunk)
        self._left = None

    def end_headers(self) -> None:
        if not self.headers.get("Range"):
            self.send_header("Accept-Ranges", "bytes")
        super().end_headers()


def main() -> None:
    directory = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4173
    handler = partial(RangeHandler, directory=directory)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"Serving {directory} on http://127.0.0.1:{port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
