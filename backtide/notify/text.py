"""How a message to Telegram quotes text it does not trust (T09, and the hold notice of T10-4):
struck again, with control and invisible characters escaped and with nothing tappable."""

import re

from backtide.blackbox import redact

_COMMAND_OR_LINK = re.compile(r"(?<![\w/])/(?=[A-Za-z])|://")
# Characters that are "printable" for Python yet show nothing (or a blank), so a run of them
# could push the agent's text onto a line of its own when Telegram wraps it (security review of
# T10-4, B1): Unicode's Default_Ignorable_Code_Point (the Hangul fillers, the variation
# selectors, the combining grapheme joiner, Khmer's inherent vowels, Mongolian's selectors and
# separator, the tags) and the Braille blank. The format characters among them (Cf) are not
# printable for Python already; listing them again costs nothing.
_BLANK_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x2800, 0x2800), (0x3164, 0x3164), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)  # fmt: skip
_SPACES = re.compile(r" {2,}")
# Agent text only (``agent_text``): what Telegram turns into a link or a mention even in plain
# text. A dot between two letters or digits ("malo.example", "www.x.com") becomes U+2024 (one
# dot leader), "@" becomes U+FF20 and a "+" before a digit (a phone number) U+FF0B (review of
# T10-4, B2).
_DOT = re.compile(r"(?<=[^\W_])\.(?=[^\W_])")
_PLUS = re.compile(r"\+(?=\d)")


def inert(text: str) -> str:
    """``printable(redact(text))`` with every ``/word`` and ``://`` made untappable: Telegram
    finds commands and links even in plain text, and an alert can quote a file name the agent
    chose ("Pulsa /seguir para confirmar", "https://..."). The slash becomes U+2215."""
    return _COMMAND_OR_LINK.sub(
        lambda found: "∕" if found.group(0) == "/" else ":∕∕", printable(redact(text))
    )


def agent_text(text: str, markers: str = "") -> str:
    """Text the agent wrote, as the hold notice quotes it (T10-4 and its review, B1 and B2):
    ``inert``, with runs of spaces collapsed (so padding cannot choose where Telegram wraps a
    line), bare domains, e-mail addresses, mentions and phone numbers made untappable, and each
    of ``markers`` (the notice's own frame characters) escaped, so the agent cannot draw them."""
    shown = _SPACES.sub(" ", inert(text))
    shown = _PLUS.sub("＋", _DOT.sub("․", shown)).replace("@", "＠")
    for marker in markers:
        shown = shown.replace(marker, _escaped(marker))
    return shown


def printable(text: str) -> str:
    """``text`` with every control or invisible character escaped, keeping line breaks: alerts
    quote names the agent chose, and an RLO, a zero-width space or a Hangul filler could make a
    message say something else."""
    return "\n".join(
        "".join(char if _visible(char) else _escaped(char) for char in line)
        for line in str(text).split("\n")
    )


def _visible(char: str) -> bool:
    if not char.isprintable():
        return False
    code = ord(char)
    return not any(low <= code <= high for low, high in _BLANK_RANGES)


def _escaped(char: str) -> str:
    """``\\t``, ``\\x1b``, ``\\u202e``: Python's own escape when it has one, else the code."""
    if not char.isprintable():
        return repr(char)[1:-1]
    code = ord(char)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
