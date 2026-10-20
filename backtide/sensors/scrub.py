"""The process sensor's list of exact secrets to strike, which can change while it runs.

The reader (``TetragonReader``) takes one function, ``scrub(text) -> text``. It used to be a
``KnownScrubber`` built once at startup, so a key the owner changes later in Settings (T12e) was
not in it: the new key could reach the black box inside a command line. ``LiveScrub`` is that
function with a list that ``replace`` swaps as a whole: the reader's thread always sees either
the old list or the new one, never half of one. It never says what it holds (not in ``repr``, not
in an error)."""

from collections.abc import Iterable

from backtide.blackbox.redact import KnownScrubber


class LiveScrub:
    """``text`` strikes the secrets given to the last ``replace`` (or to the constructor).
    ``cut_tails``: see ``KnownScrubber``. ValueError (without the value) for a secret too short
    to search for: callers pass them through ``known_secrets``, which leaves those out."""

    def __init__(self, secrets: Iterable[str] = (), *, cut_tails: bool = True) -> None:
        self._cut_tails = cut_tails
        self._count = 0
        self._current = KnownScrubber((), cut_tails=cut_tails)
        self.replace(secrets)

    def replace(self, secrets: Iterable[str]) -> None:
        """From now on, strike exactly ``secrets``: the new ones are added, the missing dropped."""
        fresh = KnownScrubber(secrets, cut_tails=self._cut_tails)  # may raise: nothing changes
        self._count = len(fresh._plain)  # noqa: SLF001 - our own sibling class
        self._current = fresh  # one assignment: the reader sees the old list or the new one

    def text(self, text: str) -> str:
        return self._current.text(text)

    def __repr__(self) -> str:
        return f"LiveScrub({self._count} secrets)"
