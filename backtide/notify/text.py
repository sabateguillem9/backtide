"""How a message to Telegram quotes text it does not trust (T09, and the hold notice of T10-4):
struck again, with control and invisible characters escaped and with nothing tappable."""

import re

from backtide.blackbox import redact

_COMMAND_OR_LINK = re.compile(r"(?<![\w/])/(?=[A-Za-z])|://")


def inert(text: str) -> str:
    """``printable(redact(text))`` with every ``/word`` and ``://`` made untappable: Telegram
    finds commands and links even in plain text, and an alert can quote a file name the agent
    chose ("Pulsa /seguir para confirmar", "https://..."). The slash becomes U+2215."""
    return _COMMAND_OR_LINK.sub(
        lambda found: "∕" if found.group(0) == "/" else ":∕∕", printable(redact(text))
    )


def printable(text: str) -> str:
    """``text`` with every control or invisible-formatting character escaped, keeping line
    breaks: alerts quote names the agent chose, and an RLO or a zero-width space could make a
    message say something else."""
    return "\n".join(
        "".join(char if char.isprintable() else repr(char)[1:-1] for char in line)
        for line in str(text).split("\n")
    )
