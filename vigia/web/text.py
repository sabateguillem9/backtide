"""Text the agent chose (file names, paths, targets) made safe to show in a page.

Jinja's autoescape already stops HTML. This stops the rest: control characters, line breaks and
the invisible bidirectional marks that make ``evil\\u202etxt.exe`` read as ``evilexe.txt`` are shown
as a visible ``U+XXXX`` marker, so what the person reads is what the file is called. Pure.
"""

import unicodedata

from markupsafe import Markup, escape

# Written as an HTML span by this module only (never by event text): ``class="esc"`` is how the
# page tells a real marker from a name that merely contains the letters "U+202E".
_MARK = '<span class="esc" title="{title}">U+{code:04X}{times}</span>'
# "Printable" by Unicode and yet blank to the eye: Hangul fillers, the empty braille cell, the
# Khmer inherent vowels, the combining grapheme joiner. A name made of them reads as a space.
_BLANK = frozenset("\u115f\u1160\u17b4\u17b5\u2800\u3164\uffa0\u034f")
_MARKS = frozenset({"Mn", "Me"})
MAX_MARKS = 3  # Vietnamese and Devanagari stack two or three; more than that is a tower


def visible(value: object, limit: int | None = None, *, keep_newlines: bool = False) -> Markup:
    """``value`` as HTML-safe markup with every character that is not plainly printable made
    visible: controls, bidi marks, letters that print as nothing, and towers of combining marks
    (more than three on one letter, or marks with no letter to sit on), which would pile up over
    the lines around them. ``limit`` cuts the text (in characters) and says so. With
    ``keep_newlines`` a line break stays one (pretty-printed JSON in a ``<pre>``)."""
    text = value if isinstance(value, str) else str(value)
    cut = limit is not None and len(text) > limit
    if cut:
        text = text[:limit]
    pieces: list[str] = []
    run: list[str] = []
    on_a_letter = False  # the last thing written is a visible, non-blank character

    def flush() -> None:
        nonlocal run
        if run:
            pieces.append(str(escape("".join(run))))
            run = []

    i, size = 0, len(text)
    while i < size:
        char = text[i]
        if unicodedata.category(char) in _MARKS:
            j = i
            while j < size and unicodedata.category(text[j]) in _MARKS:
                j += 1
            count = j - i
            if on_a_letter and count <= MAX_MARKS and not _BLANK.intersection(text[i:j]):
                run.extend(text[i:j])
            else:
                flush()
                pieces.append(_marker(char, f"×{count}"))
            i, on_a_letter = j, on_a_letter and count <= MAX_MARKS
            continue
        i += 1
        if char == " " or (keep_newlines and char == "\n"):
            run.append(char)
            on_a_letter = False
        elif char.isprintable() and char not in _BLANK:
            run.append(char)
            on_a_letter = True
        else:
            flush()
            pieces.append(_marker(char, ""))
            on_a_letter = False
    flush()
    if cut:
        pieces.append("…")
    return Markup("".join(pieces))  # noqa: S704 - every piece above is escaped or ours


def _marker(char: str, times: str) -> str:
    name = unicodedata.name(char, "") or unicodedata.category(char)
    return _MARK.format(title=escape(name.lower()), code=ord(char), times=times)


def tail(text: str, limit: int) -> str:
    """The last ``limit`` characters of ``text`` with a leading ellipsis: for paths, where the
    end (the file name) matters more than the start."""
    if len(text) <= limit:
        return text
    return "…" + text[-(limit - 1) :]
