"""A deleted agent on the disk: what stays, what waits and what goes (T26-6c; docs/47, section 8.5).

``backtide.service.fleet`` gives the orders; this is what they read and write.

- **The mark.** ``agents/<slug>/retired.json``, root's and 0600. With it there is no such agent
  (``agents.is_retired``): nothing of it runs and no order reaches it, whatever a file says. It is
  ``deleting`` while the order is half way, which the next try or the next start of the service
  finishes, and ``retired`` once it is done. What was the agent's file goes beside it, so that the
  agent can come back as it was (``SAVED_AGENT_FILE``).
- **The black box.** Never deleted (invariant 4). It ends with ``system/agent_deleted``, whose hash
  goes in the mark and in the installation's box: a box cut short afterwards does not match. Then
  it goes read-only, and out of WAL: a reader with no right to write in the folder, as the web's
  group, cannot open a WAL database that nobody has open (measured with SQLite 3.53). That change
  needs nobody else to have it open, so it is tried again until it works (``settle_box``).
- **The volume and its snapshots** stay in the image in the agent's folder, unmounted, for
  ``KEEP_DAYS``. Being in its folder is what makes the image go at the end: a hand-written
  ``volume_image`` elsewhere is never removed here, and that is said.
- **Emptying** removes everything but ``KEPT``: the box and its key, the number (never reused,
  decision 14), the mark, the copy of the file and what it spent (it counts until the month ends).
  The folder stays, so the slug is taken for good: two agents never share a name in the history.
- **When** (``due``): the warning comes a day before, and emptying waits a full day after the
  warning, also if the service was off on the day it should have warned. A warning that cannot be
  written does not count, so nothing goes without one.

A slug is only ever a key of what ``retired_agents`` found in the folder. Nothing here follows a
link, and what the agent could write in its folder (its config folder) is removed without following
anything in it.
"""

import json
import logging
import os
import shutil
import sqlite3
import stat
import tomllib
from collections.abc import Callable, Collection
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from backtide.jail import identity
from backtide.service.config import (
    RETIRED_MARK,
    SAVED_AGENT_FILE,
    STATE_CHECKPOINT,
    STATE_DB,
    STATE_KEY,
    ServiceConfig,
)
from backtide.service.spend import STATE_BUDGET

logger = logging.getLogger(__name__)

KEEP_DAYS = 7  # decision 19
WARN_BEFORE = timedelta(days=1)
DELETING, RETIRED = "deleting", "retired"
WARN, PURGE = "warn", "purge"
NUMBER_FILE = "number"  # in the agent's folder: its number outlives its file (decision 14)
IMAGE_NAME = "volume.img"
SETTLE_WAIT = 1.0  # seconds: the web's reader may have it open, and that is tried again later
_MAX_MARK = 16 * 1024
_MAX_AGENT_FILE = 64 * 1024
_NO_FOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC
_DATES = ("deleted_at", "purge_after", "warned_at", "purged_at")
KEPT = frozenset(
    {
        STATE_DB, f"{STATE_DB}-wal", f"{STATE_DB}-shm", f"{STATE_DB}-journal", STATE_KEY,
        STATE_CHECKPOINT, NUMBER_FILE, RETIRED_MARK, SAVED_AGENT_FILE, STATE_BUDGET,
    }
)  # fmt: skip


class TrashError(Exception):
    """A mark that cannot be used. Nothing is removed on its word."""


@dataclass(frozen=True)
class Retired:
    """What the mark says of a deleted agent."""

    slug: str
    number: int
    name: str | None
    state: str
    deleted_at: datetime
    purge_after: datetime
    requested_by: str
    final_seq: int
    final_hash: str
    warned_at: datetime | None = None
    purged_at: datetime | None = None
    box_settled: bool = False

    def listed(self) -> dict[str, Any]:
        """What the sockets say of it (no path, no secret): the web can show it as retired."""
        return {
            "slug": self.slug,
            "name": self.name,
            "state": self.state,
            "deleted_at": self.deleted_at.isoformat(),
            "purge_after": self.purge_after.isoformat(),
            "purged": self.purged_at is not None,
        }


def new_mark(
    config: ServiceConfig, *, now: datetime, requested_by: str, final_seq: int, final_hash: str
) -> Retired:
    return Retired(
        slug=config.slug,
        number=config.number,
        name=config.display_name,
        state=DELETING,
        deleted_at=now,
        purge_after=now + timedelta(days=KEEP_DAYS),
        requested_by=requested_by,
        final_seq=final_seq,
        final_hash=final_hash,
    )


def due(mark: Retired, now: datetime) -> str | None:
    """What this one needs now: ``WARN``, ``PURGE`` or nothing."""
    if mark.state != RETIRED or mark.purged_at is not None:
        return None
    if mark.warned_at is None:
        return WARN if now >= mark.purge_after - WARN_BEFORE else None
    if now >= mark.purge_after and now >= mark.warned_at + WARN_BEFORE:
        return PURGE
    return None


def read_mark(home: Path) -> Retired:
    """The mark in the folder ``home``. Raises FileNotFoundError or NotADirectoryError if there is
    none, and TrashError if it cannot be used."""
    try:
        fd = os.open(home / RETIRED_MARK, os.O_RDONLY | os.O_NONBLOCK | _NO_FOLLOW)
    except (FileNotFoundError, NotADirectoryError):
        raise
    except OSError as error:
        raise TrashError(f"{home / RETIRED_MARK}: {error.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TrashError(f"{home / RETIRED_MARK} is not a file")
        raw = os.read(fd, _MAX_MARK + 1)
    except OSError as error:
        raise TrashError(f"{home / RETIRED_MARK}: {error.strerror}") from None
    finally:
        os.close(fd)
    try:
        if len(raw) > _MAX_MARK:
            raise ValueError("too long")
        data = json.loads(raw)
        for key in _DATES:
            if data.get(key) is not None:
                data[key] = datetime.fromisoformat(data[key])
        return Retired(**data)
    except (ValueError, TypeError, AttributeError) as error:
        raise TrashError(f"{home / RETIRED_MARK} cannot be used: {type(error).__name__}") from None


def write_mark(home: Path, mark: Retired) -> None:
    """Whole or not at all, and on the disk when this returns. Raises OSError."""
    data = asdict(mark)
    for key in _DATES:
        if data[key] is not None:
            data[key] = data[key].isoformat()
    _write_whole(home / RETIRED_MARK, json.dumps(data, ensure_ascii=False, indent=1))


def _write_whole(path: Path, text: str) -> None:
    partial = path.with_name(f".{path.name}.partial")
    partial.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NO_FOLLOW
    with os.fdopen(os.open(partial, flags, 0o600), "w", encoding="utf-8") as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
    os.replace(partial, path)


def retired_agents(agents_dir: Path) -> dict[str, Retired | None]:
    """Every agent with a mark, by slug: None for a mark that cannot be used, which is said and
    never acted on. Only what is really in the folder: this is the one list a slug is looked up
    in, so a slug is never a path."""
    try:
        names = sorted(os.listdir(agents_dir))
    except (FileNotFoundError, NotADirectoryError):
        return {}
    found: dict[str, Retired | None] = {}
    for name in names:
        if not identity.SLUG.fullmatch(name) or name in identity.RESERVED_SLUGS:
            continue
        home = agents_dir / name
        try:
            mark = read_mark(home)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except TrashError as error:
            logger.error("a deleted agent's mark cannot be used: %s", error)
            found[name] = None
            continue
        if mark.slug != name:  # a folder copied by hand: it is not this one's word
            logger.error("the mark in %s says it is another agent's", home)
            found[name] = None
            continue
        found[name] = mark
    return found


def read_agent_file(path: Path) -> str | None:
    """An agent's file as it is, or None if it is not there. Raises OSError or ValueError."""
    try:
        fd = os.open(path, os.O_RDONLY | _NO_FOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as file:
        raw = file.read(_MAX_AGENT_FILE + 1)
    if len(raw) > _MAX_AGENT_FILE:
        raise ValueError(f"{path} is too long")
    return raw.decode()


def save_agent_file(home: Path, text: str) -> None:
    _write_whole(home / SAVED_AGENT_FILE, text)


def _box_paths(home: Path) -> tuple[Path, ...]:
    db = home / STATE_DB
    return (
        db, db.with_name(f"{db.name}-wal"), db.with_name(f"{db.name}-shm"), home / STATE_CHECKPOINT,
    )  # fmt: skip


def seal_box(home: Path) -> None:
    """The box of a deleted agent is read-only: whoever could read it still can, and nobody writes.
    The chain is what proves it was not touched; this is so that nothing does by mistake. Raises
    OSError."""
    _change_box_modes(home, lambda mode: mode & ~0o222)


def unseal_box(home: Path) -> None:
    """For the agent that comes back, whose box goes on. Raises OSError."""
    _change_box_modes(home, lambda mode: mode | 0o200)


def _change_box_modes(home: Path, change: Callable[[int], int]) -> None:
    for path in _box_paths(home):
        try:
            fd = os.open(path, os.O_RDONLY | _NO_FOLLOW)
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError(f"{path} is not a file")
            os.fchmod(fd, change(stat.S_IMODE(info.st_mode)))
        finally:
            os.close(fd)


def settle_box(home: Path) -> bool:
    """Everything of the box in this folder in its one file, out of WAL, so that a reader that may
    not write in the folder can open it (see the module's text). Touches no event: it only moves
    what is there. Call it unsealed. False if it cannot be now: someone has it open, which is the
    web's reader, and the next look tries again. Never raises."""
    uri = f"{(home / STATE_DB).absolute().as_uri()}?mode=rw"  # never makes one that is not there
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=SETTLE_WAIT, isolation_level=None)
    except sqlite3.Error as error:
        logger.warning("the box in %s cannot be opened: %s", home, error)
        return False
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    except sqlite3.Error as error:
        logger.info("the box in %s is not settled yet: %s", home, error)
        return False
    finally:
        connection.close()


def image_elsewhere(home: Path) -> str | None:
    """Where a hand-written ``volume_image`` outside the agent's folder is, from the copy of its
    file. Nothing here ever removes that one. Never raises: no answer is no image elsewhere."""
    try:
        text = read_agent_file(home / SAVED_AGENT_FILE)
        image = None if text is None else tomllib.loads(text).get("volume_image")
    except (OSError, ValueError):  # tomllib's error is a ValueError
        logger.warning("the copy of the file in %s cannot be read", home)
        return None
    if not isinstance(image, str):
        return None
    return None if os.path.realpath(image) == os.path.realpath(home / IMAGE_NAME) else image


def empty_folder(home: Path, keep: Collection[str] = KEPT) -> None:
    """Everything in the folder but ``keep`` goes, and nothing is followed: what an agent left in
    its config folder may be a link to anywhere. The image first: with it gone, an emptying that
    stops half way cannot be brought back as if it were whole, and what fills the disk is off it,
    whatever the agent left in the rest. Raises OSError, or RecursionError for a tree too deep."""
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | _NO_FOLLOW)
    try:
        try:
            os.unlink(IMAGE_NAME, dir_fd=fd)
        except FileNotFoundError:
            pass
        with os.scandir(fd) as entries:
            found = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in entries]
        for name, is_folder in found:
            if name in keep:
                continue
            if is_folder:
                shutil.rmtree(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)
