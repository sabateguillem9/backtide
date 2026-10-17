"""The web's way into the black box: read-only, and never an exception into a page.

``BlackBox(path, None, readonly=True)`` never writes (SQLite itself refuses) and never holds the
HMAC key: the web reads one file, ``blackbox.db``, and nothing else of backtide's state. The box
may not exist yet (backtide has not started) or may be busy for a moment; both are
``BoxUnavailable``, which a page turns into a calm sentence and the stream into "try again next
second".
"""

import threading
from pathlib import Path
from typing import Any

from backtide.blackbox import BlackBox, BlackBoxError, Event


class BoxUnavailable(Exception):  # noqa: N818 - reads better than BoxUnavailableError
    """The black box cannot be read right now."""


class BoxReader:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._box: BlackBox | None = None
        self._lock = threading.Lock()

    def events(self, **filters: Any) -> list[Event]:
        """``BlackBox.events`` (same filters) on the read-only box."""
        with self._lock:
            try:
                if self._box is None:
                    # No key: the web lists events, it can neither verify nor forge anything.
                    self._box = BlackBox(self._path, None, readonly=True)
                return self._box.events(**filters)
            except BlackBoxError as error:
                self._drop()
                raise BoxUnavailable(str(error)) from error

    def head_seq(self) -> int:
        """The seq of the last event (0 if there are none)."""
        last = self.events(newest_first=True, limit=1)
        return last[0].seq if last else 0

    def close(self) -> None:
        with self._lock:
            self._drop()

    def _drop(self) -> None:
        box, self._box = self._box, None
        if box is not None:
            box.close()
