"""The web's public origin (T26-4a, D40): `[web] public_origin`, when a reverse proxy on this
server brings the web to a domain of its own.

The web itself never listens on the internet: it stays on loopback, and the proxy reaches it there.
This value is what the web then answers to: the only ``Host`` and ``Origin`` it takes, and the name
its passkeys belong to. So it is strict, and checked when anything starts: ``https``, a name, and
perhaps a port. No path (for the browser, a web under another site's path is that site's same
origin: docs/47 section 5.4), no credentials, no address (a passkey cannot belong to one) and no
``localhost``. The errors never quote the value: a mistake here can hold a password.
"""

import re
from dataclasses import dataclass

SCHEME = "https://"
HTTPS_PORT = 443
MAX_NAME_CHARS = 253
_SHAPE = re.compile(r"(?P<name>[A-Za-z0-9.-]+)(?::(?P<port>[0-9]{1,5}))?", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
# How a browser reads an address: a last label that is a number, in decimal or hex.
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*", re.ASCII)


@dataclass(frozen=True)
class PublicOrigin:
    """A checked origin, in the one form a browser sends it: lower case, without ``:443``."""

    name: str  # the name alone: what a passkey belongs to (its relying party)
    port: int | None = None  # None: https's own

    @property
    def host(self) -> str:
        """The ``Host`` header."""
        return self.name if self.port is None else f"{self.name}:{self.port}"

    @property
    def url(self) -> str:
        """The ``Origin`` header, and what a passkey's answer must say it came from."""
        return SCHEME + self.host

    @property
    def link_base(self) -> str:
        """The web's address, without a way in."""
        return self.url + "/"


def parse_public_origin(value: object) -> PublicOrigin:
    """The checked origin. ValueError says what is wrong, never quoting ``value``."""
    if not isinstance(value, str):
        raise ValueError("it must be text, like https://backtide.example.org")
    if not value.startswith(SCHEME):
        raise ValueError("it must start with https:// (the web behind a domain needs https)")
    rest = value[len(SCHEME) :]
    if any(mark in rest for mark in "/?#"):
        raise ValueError(
            "no path, query or fragment: the web needs a subdomain of its own, never a path of "
            "another site"
        )
    if "@" in rest:
        raise ValueError("no credentials: only a name and perhaps a port")
    if rest.startswith("["):
        raise ValueError("a name, not an address: a passkey cannot belong to an address")
    match = _SHAPE.fullmatch(rest)
    if match is None:
        raise ValueError(
            "a name in letters, digits, - and . and perhaps a port (an international name, in its "
            "xn-- form)"
        )
    name = match["name"].lower()
    labels = name.split(".")
    if len(name) > MAX_NAME_CHARS or not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError(
            f"not a valid name: at most {MAX_NAME_CHARS} characters, parts of 1 to 63 that do not "
            "start or end with -"
        )
    if labels[-1] == "localhost" and len(labels) > 1:
        raise ValueError("not a *.localhost: that name is this machine's, for the SSH tunnel")
    if len(labels) < 2:
        raise ValueError("a name with a dot: a subdomain of a domain of yours")
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        raise ValueError("a name, not an address: a passkey cannot belong to an address")
    port = None if match["port"] is None else int(match["port"])
    if port is not None and not 0 < port <= 65535:
        raise ValueError("its port must be between 1 and 65535")
    return PublicOrigin(name, None if port == HTTPS_PORT else port)


__all__ = ["PublicOrigin", "parse_public_origin"]
