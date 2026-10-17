"""A glob that cannot be made to take long. Pure: no I/O.

Rules match paths, commands and URLs that the AGENT chose, so the matcher must not have a bad
case an agent could aim at. A regular expression can (nested quantifiers backtrack for ever);
this matcher cannot: it only ever remembers the LAST ``*``, so one match takes at most
``len(text) * len(pattern)`` steps, and a pattern is cut to ``MAX_GLOB_CHARS`` characters with
at most ``MAX_STARS`` stars when the rules are loaded. That is why rules have no regex.

Syntax (everything else is itself, case counted):

- ``*``      any run of characters, also an empty one and also ``/``;
- ``?``      exactly one character;
- ``[abc]``  one of those characters; ``[a-z]`` a range; ``[!abc]`` anything but those. A ``]``
             first in the class is itself. There are no escapes: to put a control character in a
             pattern, write it in the TOML string (``"\\u001b"``).
"""

from dataclasses import dataclass

MAX_GLOB_CHARS = 200
MAX_STARS = 8
MAX_CLASS_ITEMS = 64

_STAR = "*"
_ANY = "?"


@dataclass(frozen=True)
class _Class:
    """One ``[...]``: single characters and (low, high) ranges, maybe negated."""

    items: tuple[str | tuple[str, str], ...]
    negated: bool

    def accepts(self, char: str) -> bool:
        for item in self.items:
            if isinstance(item, tuple):
                if item[0] <= char <= item[1]:
                    return not self.negated
            elif item == char:
                return not self.negated
        return self.negated


type _Token = str | _Class


class Glob:
    """A compiled pattern. ``Glob.compile`` raises ValueError (in Spanish: it reaches the
    person who wrote the rule) for a pattern that is too long, has too many stars or has a
    broken class."""

    __slots__ = ("pattern", "_tokens")

    def __init__(self, pattern: str, tokens: tuple[_Token, ...]) -> None:
        self.pattern = pattern
        self._tokens = tokens

    def __repr__(self) -> str:
        return f"Glob({self.pattern!r})"

    @classmethod
    def compile(cls, pattern: str) -> "Glob":
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("el patrón tiene que ser un texto que no esté vacío")
        if len(pattern) > MAX_GLOB_CHARS:
            raise ValueError(f"el patrón es demasiado largo (máximo {MAX_GLOB_CHARS} caracteres)")
        tokens: list[_Token] = []
        index = 0
        while index < len(pattern):
            char = pattern[index]
            if char == "[":
                parsed, index = _parse_class(pattern, index)
                tokens.append(parsed)
                continue
            if char == _STAR and tokens and tokens[-1] == _STAR:
                index += 1  # "**" is "*"
                continue
            tokens.append(char)
            index += 1
        if sum(1 for token in tokens if token == _STAR) > MAX_STARS:
            raise ValueError(f"el patrón tiene demasiados «*» (máximo {MAX_STARS})")
        return cls(pattern, tuple(tokens))

    def match(self, text: str) -> bool:
        """True if the WHOLE ``text`` matches (put a ``*`` at each end to find a part)."""
        tokens = self._tokens
        size = len(tokens)
        t = p = 0
        star = -1  # where the last "*" is in the pattern...
        resume = 0  # ...and where in the text the next try starts
        while t < len(text):
            token = tokens[p] if p < size else None
            if token == _STAR:
                star, resume = p, t
                p += 1
            elif token is not None and _one(token, text[t]):
                p += 1
                t += 1
            elif star >= 0:
                resume += 1
                p, t = star + 1, resume
            else:
                return False
        while p < size and tokens[p] == _STAR:
            p += 1
        return p == size


def _one(token: _Token, char: str) -> bool:
    if isinstance(token, _Class):
        return token.accepts(char)
    return token == _ANY or token == char


def _parse_class(pattern: str, start: int) -> tuple[_Class, int]:
    """The class that opens at ``pattern[start]``, and the index after its ``]``."""
    index = start + 1
    negated = index < len(pattern) and pattern[index] in "!^"
    if negated:
        index += 1
    items: list[str | tuple[str, str]] = []
    first = True
    while index < len(pattern):
        char = pattern[index]
        if char == "]" and not first:
            if not items:
                raise ValueError("hay un «[]» vacío en el patrón")
            return _Class(tuple(items), negated), index + 1
        first = False
        if index + 2 < len(pattern) and pattern[index + 1] == "-" and pattern[index + 2] != "]":
            low, high = char, pattern[index + 2]
            if low > high:
                raise ValueError(f"el rango {low!r}-{high!r} está al revés")
            items.append((low, high))
            index += 3
        else:
            items.append(char)
            index += 1
        if len(items) > MAX_CLASS_ITEMS:
            raise ValueError(f"un «[...]» tiene demasiados elementos (máximo {MAX_CLASS_ITEMS})")
    raise ValueError("falta el «]» que cierra un «[» del patrón")
