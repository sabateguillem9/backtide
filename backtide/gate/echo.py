"""A provider's answer, checked for the real key before it reaches the agent. Pure: no I/O.

The agent never holds the real key, but a provider that echoed it (an error that quotes the key it
got, a compromised or fake provider, a model fed the key some other way) would hand it over. So:

- a whole answer (JSON, an error, anything that is not a plain SSE stream) is held by mitmproxy
  and checked here before any byte of it goes on (``KeyScanner.found_in``);
- a streamed one (SSE) goes through ``SseGuard``: each event is held until its blank line, checked
  as it came (raw) and, once its JSON is read, by the text each of its fields builds over the
  stream (a model's text comes as many small deltas, so a key split over them is found when its
  last piece arrives). Then the event goes on. On a hit, ``KeyEcho``: the gate cuts the stream at
  once, so the event with the key, and everything after it, never reaches the agent.

The key is looked for as is, in lower and upper case, URL-encoded, with JSON escapes or HTML
entities (``scrub_known``), in hex and in base64 (standard and URL-safe, at the three alignments).
Known limit: a key split over deltas leaks the pieces sent before the last one; a key encoded
some other way (base64 with line breaks, compressed, spelled out) is not seen.

Bounded: an event over ``max_event`` bytes stops the stream (``EventTooLarge``), and the text
kept per field is a window a little longer than the longest form of a key, for at most
MAX_CHANNELS fields (the oldest are forgotten).
"""

import base64
import json
from collections.abc import Iterable
from typing import Any

from backtide.blackbox.redact import MIN_KNOWN_SECRET, KnownScrubber
from backtide.gate.sse import MAX_EVENT_BYTES, SseParser

MAX_CHANNELS = 256
# Fields of an event that say WHICH block, choice or item a delta belongs to (the same field of
# two blocks is two texts). sequence_number is left out: it changes with every event.
_PLACE_KEYS = ("index", "output_index", "content_index", "item_id")
_MAX_WALK = 100_000  # values (of any kind) walked per event (an event is 1 MiB at most)
MAX_DEPTH = 32  # deeper than this, an event's values are only read raw
MAX_PATH_PART = 64  # characters kept of each name or place in a field's path
_URLSAFE = str.maketrans("+/", "-_")


class KeyEcho(Exception):
    """The answer carries a real key: it must not reach the agent."""


class EventTooLarge(Exception):
    """An SSE event over the limit: it cannot be checked, so the stream stops."""


def key_forms(keys: Iterable[str]) -> tuple[str, ...]:
    """Every form of each key the scanner looks for literally (scrub_known adds the
    URL-encoded, JSON-escaped and HTML forms of each)."""
    forms: list[str] = []
    for key in keys:
        data = key.encode("utf-8")
        forms += [key, key.lower(), key.upper(), data.hex(), data.hex().upper()]
        for offset in range(3):
            padded = b"\0" * offset + data
            encoded = base64.b64encode(padded).decode("ascii")
            # Only the characters that depend on the key's bits alone: whatever surrounds the
            # key in the encoded text, these show as they are.
            core = encoded[-(-8 * offset // 6) : (8 * len(padded)) // 6]
            forms += [core, core.translate(_URLSAFE)]
    return tuple(dict.fromkeys(form for form in forms if len(form) >= MIN_KNOWN_SECRET))


class KeyScanner:
    """The real keys' forms, with their pattern built once (per config)."""

    def __init__(self, keys: Iterable[str]) -> None:
        self.forms = key_forms(keys)
        self._scrubber = KnownScrubber(self.forms)
        # A text that holds a whole form, however it is escaped (an HTML entity is 6 characters).
        self.window = max((len(form) for form in self.forms), default=0) * 6 + 16

    def __repr__(self) -> str:
        return f"KeyScanner({len(self.forms)} forms)"

    def found(self, text: str) -> bool:
        return bool(self.forms) and self._scrubber.text(text) != text

    def found_in(self, *parts: str | bytes | None) -> bool:
        """Whether a key shows in any part (bytes are read as Latin-1: a key is ASCII)."""
        for part in parts:
            if part is None:
                continue
            if self.found(part.decode("latin-1") if isinstance(part, bytes) else part):
                return True
        return False


class SseGuard:
    """Holds an SSE stream back until each event is whole, checks it, then lets it go."""

    def __init__(self, scanner: KeyScanner, *, max_event: int = MAX_EVENT_BYTES) -> None:
        self._scanner = scanner
        self._max = max_event
        self._held = bytearray()
        self._scanned = 0  # bytes of _held already searched for line ends
        self._line_start = 0  # where the line being read starts, in _held
        self._boundary = 0  # the end of the last blank line, in _held
        self._parser = SseParser(max_event_bytes=max_event)
        self._texts: dict[tuple[Any, ...], str] = {}
        self.window = scanner.window

    @property
    def channels(self) -> int:
        return len(self._texts)

    @property
    def held(self) -> int:
        return sum(len(text) for text in self._texts.values())

    @property
    def key_bytes(self) -> int:
        return sum(len(str(part)) for path in self._texts for part in path)

    def feed(self, chunk: bytes) -> bytes:
        """What may go to the agent now (whole events, checked). Raises KeyEcho or
        EventTooLarge: then nothing more of the stream may go on."""
        self._held += chunk
        self._find_boundary()
        if self._boundary == 0:
            if len(self._held) > self._max:
                raise EventTooLarge("an SSE event over the limit")
            return b""
        ready = bytes(self._held[: self._boundary])
        del self._held[: self._boundary]
        self._scanned -= self._boundary
        self._line_start -= self._boundary
        self._boundary = 0
        self._check(ready)
        if len(self._held) > self._max:
            raise EventTooLarge("an SSE event over the limit")
        return ready

    def finish(self) -> bytes:
        """An empty chunk: the end of the message, or an empty frame in the middle of it (both
        reach the gate the same way). A final "\\r" now ends its line; whole events go on,
        checked, and the rest stays held: an event without its blank line never goes on (an
        SSE client drops it at the end anyway)."""
        if self._held[-1:] == b"\r":
            self._find_boundary(final=True)
        return self.feed(b"")

    def _find_boundary(self, *, final: bool = False) -> None:
        held = self._held
        i = self._scanned
        end = len(held)
        while i < end:
            byte = held[i]
            if byte not in (0x0A, 0x0D):
                i += 1
                continue
            if byte == 0x0D:
                if i + 1 == end and not final:
                    break  # a "\n" may follow in the next chunk: look again then
                after = i + 2 if i + 1 < end and held[i + 1] == 0x0A else i + 1
            else:
                after = i + 1
            if i == self._line_start:  # an empty line: the end of an event
                self._boundary = after
            self._line_start = after
            i = after
        self._scanned = i

    def _check(self, data: bytes) -> None:
        if self._scanner.found_in(data):
            raise KeyEcho("a real key in the answer")
        for event in self._parser.feed(data):
            try:
                value = json.loads(event.data)
            except (ValueError, RecursionError):
                continue  # read raw above, as it came
            self._follow(value)

    def _follow(self, value: object) -> None:
        """Add each string of an event to the text its field builds over the stream. Bounded:
        at most _MAX_WALK values, MAX_DEPTH levels, MAX_PATH_PART characters per path part."""
        place: tuple[Any, ...] = ()
        if isinstance(value, dict):
            place = tuple(
                _short(value.get(key)) for key in _PLACE_KEYS
                if isinstance(value.get(key), int | str)
            )  # fmt: skip
        stack: list[tuple[tuple[Any, ...], object]] = [(place, value)]
        seen = 0
        while stack and seen < _MAX_WALK:
            path, item = stack.pop()
            seen += 1
            if isinstance(item, str):
                self._add(path, item)
            elif len(path) - len(place) >= MAX_DEPTH:
                continue  # read raw already
            elif isinstance(item, dict):
                index = item.get("index")
                here = (*path, f"#{index}") if type(index) is int else path
                for k, v in item.items():
                    if isinstance(v, dict | list | str):
                        stack.append(((*here, _short(k)), v))
            elif isinstance(item, list):
                for n, v in enumerate(item):
                    if isinstance(v, dict | list | str):
                        stack.append(((*path, n), v))
                    if len(stack) > _MAX_WALK:
                        break

    def _add(self, path: tuple[Any, ...], piece: str) -> None:
        text = self._texts.pop(path, "") + piece
        if self._scanner.found(text):
            raise KeyEcho("a real key in the answer, over several events")
        self._texts[path] = text[-self.window :]
        while len(self._texts) > MAX_CHANNELS:
            del self._texts[next(iter(self._texts))]  # the field not seen for longest


def _short(value: object) -> object:
    return value[:MAX_PATH_PART] if isinstance(value, str) else value
