"""The recipients the person trusts from the web (T10-5, docs/32 section 9 and decision 9).

"Aprobar y confiar en este destinatario": the web approves a held send and, from then on, a send
or a change to that recipient passes like one to ``[gate] trusted``, without editing the TOML.
These entries live here, apart from the TOML:

- **Where**: ``<state_dir>/trusted.json``, a 0600 file of backtide's, written atomically
  (``settings.write_private``). The state folder is never mounted into the agent (invariant 1),
  so the agent can neither read nor add to this list. Nothing in it is a secret: a translator
  and a normalized recipient (an address, a chat id, a channel id), and who added it and when.
- **What may be trusted** is decided by the channel (``ProxyChannel.trust``), from the hold's
  strict fields, never from the agent's text: a send or a change with exactly one recipient
  that a translator read, never FORWARD, DELETE, ADMIN or UNKNOWN, never risk 3, and never a
  reading that is never trusted (an inline message, a URL the platform fetches, a Slack channel
  by name, a cut reading, a secret seen). Here it is only stored, normalized
  (``translate.base.normalize_trusted``), and recorded by the caller (``gate/trust_added`` and
  ``gate/trust_removed``).
- **Fails closed**: a file that cannot be read gives no trust at all (it only ever adds leave),
  is logged, and is never overwritten: adding is refused until a person looks at it.
- **Recorded before it is used** (final review of T10, finding 6): ``prepare`` makes the entry,
  the caller records ``gate/trust_added``, and only then ``commit`` saves it and the gate uses
  it; if saving fails the caller records ``gate/trust_failed`` and nothing is trusted.
- At most ``MAX_TRUSTED`` entries. Thread-safe; ``entries()`` never blocks on a write.
"""

import json
import logging
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from backtide.gate.translate.base import MAIL_TRANSLATORS, Trusted, normalize_trusted
from backtide.service.config import ConfigError, _read_file
from backtide.service.settings import SettingsError, write_private
from backtide.snapshots import utc_now

logger = logging.getLogger(__name__)

STATE_TRUST = "trusted.json"
MAX_TRUSTED = 50
MAX_FILE_BYTES = 64 * 1024
TRUST_ID_RE = re.compile(r"t-[0-9a-f]{8}", re.ASCII)
TRUSTABLE_TRANSLATORS = frozenset({"gmail", "graph_mail", "telegram", "slack", "discord"})
_BY_RE = re.compile(r"[a-z]{1,16}", re.ASCII)


class TrustError(Exception):
    """The list cannot be changed (full, unreadable, or the file cannot be written). The
    message is for the person, in Spanish, and never quotes a recipient."""


@dataclass(frozen=True)
class TrustEntry:
    trust_id: str
    translator: str
    recipient: str
    added_at: str
    by: str
    hold_id: str | None = None

    @property
    def trusted(self) -> Trusted:
        return Trusted(self.translator, self.recipient)


def _new_id() -> str:
    return f"t-{secrets.token_hex(4)}"


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class TrustStore:
    """The list, in memory and in ``folder/trusted.json`` (``folder`` None: in memory only, for
    the tests). ``load()`` reads the file once, at start."""

    def __init__(
        self,
        folder: Path | None,
        *,
        wall: Callable[[], datetime] = utc_now,
        new_id: Callable[[], str] = _new_id,
        limit: int = MAX_TRUSTED,
    ) -> None:
        self._folder = folder
        self._wall = wall
        self._new_id = new_id
        self._limit = limit
        self._lock = threading.Lock()
        self._list: list[TrustEntry] = []
        self._entries: tuple[Trusted, ...] = ()
        self._broken = False

    @property
    def path(self) -> Path | None:
        return None if self._folder is None else self._folder / STATE_TRUST

    def load(self) -> None:
        """Read the file. A missing file is an empty list; one that cannot be used gives no
        trust (logged) and is left alone: adding is refused until a person looks at it."""
        path = self.path
        if path is None:
            return
        try:
            path.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            self._fail(f"cannot look at {path}: {error.strerror}")
            return
        try:
            raw = _read_file(path, "trusted recipients file", MAX_FILE_BYTES, private=True)
            data = json.loads(raw.decode("utf-8"))
            entries = [_entry(item) for item in data]
        except (ConfigError, UnicodeDecodeError, ValueError, TypeError) as error:
            self._fail(f"{path} cannot be used ({type(error).__name__}): {error}")
            return
        if len(entries) > self._limit or len({e.trust_id for e in entries}) != len(entries):
            self._fail(f"{path} has too many or repeated entries")
            return
        with self._lock:
            self._list = entries
            self._entries = tuple(dict.fromkeys(e.trusted for e in entries))
        mail = sum(1 for e in entries if e.translator in MAIL_TRANSLATORS)
        if mail:  # final review of T10, finding 2: no owner accounts yet, so they trust nothing
            logger.warning(
                "%d trusted mail recipient(s) of the web are not used until the owner's mail "
                "accounts are configured",
                mail,
            )

    def _fail(self, why: str) -> None:
        logger.error("the trusted recipients of the web are not used: %s", why)
        with self._lock:
            self._broken = True
            self._list, self._entries = [], ()

    def entries(self) -> tuple[Trusted, ...]:
        """What the gate compares with (a tuple swapped whole: read without the lock)."""
        return self._entries

    def listing(self) -> list[dict[str, Any]]:
        """Every entry, oldest first, as plain data (the web's list)."""
        with self._lock:
            return [asdict(entry) for entry in self._list]

    def find(self, translator: str, recipient: str) -> TrustEntry | None:
        with self._lock:
            return next(
                (e for e in self._list if (e.translator, e.recipient) == (translator, recipient)),
                None,
            )

    def add(
        self, translator: str, recipient: str, *, by: str, hold_id: str | None = None
    ) -> tuple[TrustEntry, bool]:
        """``prepare`` and, for a new entry, ``commit``: one step, for what records nothing."""
        entry, new = self.prepare(translator, recipient, by=by, hold_id=hold_id)
        if new:
            self.commit(entry)
        return entry, new

    def prepare(
        self, translator: str, recipient: str, *, by: str, hold_id: str | None = None
    ) -> tuple[TrustEntry, bool]:
        """``(entry, new)``: the entry of ``recipient`` for ``translator`` that ``commit``
        would save (``new``), or the one there already. Nothing is saved nor used yet: the
        caller records ``gate/trust_added`` first, and only then commits (final review of T10,
        finding 6). TrustError if the list is full or unreadable; ValueError for a recipient
        that could never match."""
        if translator not in TRUSTABLE_TRANSLATORS:
            raise ValueError("that translator has no trusted recipients")
        normalized = normalize_trusted(translator, recipient)
        if not _BY_RE.fullmatch(by):
            raise ValueError("by is a short word")
        with self._lock:
            self._readable()
            for entry in self._list:
                if entry.trusted == normalized:
                    return entry, False
            self._room()
            trust_id = self._new_id()
            while any(e.trust_id == trust_id for e in self._list):
                trust_id = self._new_id()
            entry = TrustEntry(
                trust_id=trust_id,
                translator=normalized.translator,
                recipient=normalized.recipient,
                added_at=_iso(self._wall()),
                by=by,
                hold_id=hold_id,
            )
            return entry, True

    def commit(self, entry: TrustEntry) -> None:
        """Save ``entry`` (from ``prepare``) and only then use it. TrustError, with nothing
        changed, if the list became unreadable or full, or the file cannot be written; an
        entry for the same recipient or with the same id that is there already is left as is."""
        with self._lock:
            self._readable()
            if any(e.trusted == entry.trusted or e.trust_id == entry.trust_id for e in self._list):
                return
            self._room()
            self._save([*self._list, entry])

    def _readable(self) -> None:
        """TrustError (under the lock) when the file could not be used at start."""
        if self._broken:
            raise TrustError(
                "La lista de destinatarios de confianza no se pudo leer al arrancar: no se "
                "añade nada hasta que alguien mire trusted.json."
            )

    def _room(self) -> None:
        """TrustError (under the lock) when the list is full."""
        if len(self._list) >= self._limit:
            raise TrustError(
                f"Ya hay {self._limit} destinatarios de confianza añadidos desde la web: "
                "quita alguno antes de añadir otro."
            )

    def remove(self, trust_id: str) -> TrustEntry | None:
        """Remove ``trust_id`` and save. None if there is no such entry; TrustError if the file
        cannot be written (then it is still trusted)."""
        with self._lock:
            entry = next((e for e in self._list if e.trust_id == trust_id), None)
            if entry is None:
                return None
            self._save([e for e in self._list if e.trust_id != trust_id])
            return entry

    def _save(self, entries: list[TrustEntry]) -> None:
        """Write ``entries`` (under the lock) and only then use them."""
        if self._folder is not None:
            try:
                data = json.dumps([asdict(e) for e in entries], indent=1).encode()
                write_private(self._folder, STATE_TRUST, data, private_dir=False)
            except (SettingsError, OSError) as error:
                logger.error("cannot write the trusted recipients: %s", type(error).__name__)
                raise TrustError(
                    "No se ha podido guardar la lista de destinatarios de confianza: no ha "
                    "cambiado nada."
                ) from None
        self._list = entries
        self._entries = tuple(dict.fromkeys(e.trusted for e in entries))


def _entry(item: object) -> TrustEntry:
    """One entry of the file, checked field by field (ValueError otherwise)."""
    if not isinstance(item, dict) or set(item) - {
        "trust_id", "translator", "recipient", "added_at", "by", "hold_id",
    }:  # fmt: skip
        raise ValueError("an entry is an object with known keys")
    trust_id, translator = item.get("trust_id"), item.get("translator")
    recipient, added_at, by = item.get("recipient"), item.get("added_at"), item.get("by")
    hold_id = item.get("hold_id")
    if not isinstance(trust_id, str) or not TRUST_ID_RE.fullmatch(trust_id):
        raise ValueError("a bad trust_id")
    if not isinstance(translator, str) or translator not in TRUSTABLE_TRANSLATORS:
        raise ValueError("a bad translator")
    if not isinstance(recipient, str):
        raise ValueError("a bad recipient")
    normalized = normalize_trusted(translator, recipient)
    if normalized.recipient != recipient:
        raise ValueError("a recipient that is not normalized")
    if not isinstance(added_at, str) or len(added_at) > 40:
        raise ValueError("a bad added_at")
    if not isinstance(by, str) or not _BY_RE.fullmatch(by):
        raise ValueError("a bad by")
    if hold_id is not None and (not isinstance(hold_id, str) or len(hold_id) > 20):
        raise ValueError("a bad hold_id")
    return TrustEntry(trust_id, translator, recipient, added_at, by, hold_id)


__all__ = [
    "MAX_TRUSTED",
    "STATE_TRUST",
    "TRUST_ID_RE",
    "TrustEntry",
    "TrustError",
    "TrustStore",
]
