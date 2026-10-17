"""The checkpoint file: the last (seq, hash) of the black box, signed with the key.

The chain alone cannot show that the LAST events were deleted; the checkpoint can.
It lives outside the database (and never in the snapshot volume) and is rewritten
atomically after every append. In T09 it is also sent to Telegram.
"""

import errno
import fcntl
import hmac
import json
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backtide.blackbox.chain import (
    HEX64_RE,
    KEY_ID_RE,
    TS_RE,
    canonical_json,
    checkpoint_mac,
    key_id,
)
from backtide.blackbox.model import BlackBoxError

_FIELDS = {"seq", "hash", "ts", "key_id", "mac"}
# A genuine checkpoint is about 200 bytes; never read more than this.
MAX_CHECKPOINT_BYTES = 4096
# Never follow a symlink, never block on a FIFO.
_OPEN_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class Checkpoint:
    seq: int
    hash: str
    ts: str
    key_id: str


class CheckpointError(BlackBoxError):
    """The checkpoint's CONTENT is malformed or its mac is wrong: tampering. ``detail`` is
    in Spanish. A checkpoint that cannot be read at all raises plain BlackBoxError."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"checkpoint is forged or damaged: {detail}")
        self.detail = detail


def read_checkpoint(path: Path, key: bytes) -> Checkpoint | None:
    """The checkpoint at ``path``, or None if there is no file.

    Raises CheckpointError if it is malformed or was not signed with ``key``, and plain
    BlackBoxError if it cannot be read as a regular file (I/O error, symlink, FIFO...)."""
    raw = _read_regular_file(path)
    if raw is None:
        return None
    data = _parse(raw)
    _require_valid_mac(data, key)
    return Checkpoint(seq=data["seq"], hash=data["hash"], ts=data["ts"], key_id=data["key_id"])


def write_checkpoint(path: Path, key: bytes, *, seq: int, hash: str, ts: str) -> None:
    """Sign and atomically replace the checkpoint at ``path``. Raises OSError."""
    fields = {"seq": seq, "hash": hash, "ts": ts, "key_id": key_id(key)}
    payload = {**fields, "mac": checkpoint_mac(key, fields)}
    _atomic_write(path, canonical_json(payload).encode("utf-8") + b"\n")


@contextmanager
def checkpoint_lock(path: Path, timeout: float) -> Iterator[None]:
    """Hold an exclusive flock on ``<path>.lock``. flock (not lockf) also excludes other
    open files in the same process, so two BlackBox instances serialize too."""
    lock_path = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | _OPEN_FLAGS, 0o600)
    except OSError as exc:
        raise BlackBoxError(f"cannot open checkpoint lock {lock_path}: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BlackBoxError(f"checkpoint lock {lock_path} is not a regular file")
        _flock(fd, timeout)
        yield
    finally:
        os.close(fd)  # releases the flock


def _read_regular_file(path: Path) -> bytes | None:
    """Up to MAX_CHECKPOINT_BYTES of the regular file at ``path``, or None if there is none."""
    try:
        fd = os.open(path, os.O_RDONLY | _OPEN_FLAGS)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise BlackBoxError(f"checkpoint {path} is a symlink, refusing to follow it") from exc
        raise BlackBoxError(f"cannot read checkpoint {path}: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BlackBoxError(f"checkpoint {path} is not a regular file")
        raw = _read_up_to(fd, MAX_CHECKPOINT_BYTES + 1)
    except OSError as exc:
        raise BlackBoxError(f"cannot read checkpoint {path}: {exc}") from exc
    finally:
        os.close(fd)
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise CheckpointError(f"ocupa más de {MAX_CHECKPOINT_BYTES} bytes")
    return raw


def _read_up_to(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse(raw: bytes) -> dict[str, Any]:
    """The checkpoint's fields, every one in the exact format a genuine checkpoint has."""
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise CheckpointError("no es JSON válido") from exc
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise CheckpointError("no tiene los campos esperados")
    seq = data["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise CheckpointError("tiene un seq no válido")
    if not all(isinstance(data[name], str) for name in _FIELDS - {"seq"}):
        raise CheckpointError("tiene campos que no son texto")
    well_formed = (
        HEX64_RE.fullmatch(data["hash"])
        and HEX64_RE.fullmatch(data["mac"])
        and KEY_ID_RE.fullmatch(data["key_id"])
        and TS_RE.fullmatch(data["ts"])
    )
    if not well_formed:
        raise CheckpointError("tiene campos mal formados")
    return data


def _require_valid_mac(data: dict[str, Any], key: bytes) -> None:
    try:
        expected = checkpoint_mac(key, data)
    except ValueError as exc:  # e.g. a lone surrogate; _parse already rules it out
        raise CheckpointError("tiene campos mal formados") from exc
    if not hmac.compare_digest(data["mac"].encode("ascii"), expected.encode("ascii")):
        if data["key_id"] != key_id(key):
            raise CheckpointError("está firmado con otra clave o lo han cambiado")
        raise CheckpointError("tiene una firma (mac) que no coincide")
    if data["key_id"] != key_id(key):
        raise CheckpointError("tiene un key_id que no es el de esta clave")


def _atomic_write(path: Path, data: bytes) -> None:
    """Readers see the old file or the new one, never a mix; the rename is durable."""
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _flock(fd: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise BlackBoxError(f"checkpoint lock still busy after {timeout:.0f}s") from None
            time.sleep(0.005)
