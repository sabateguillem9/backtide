"""The proxy's fixed rules: ports, public addresses, OAuth logins, the allow list and
domain fronting. Pure: no I/O, no DNS. Nothing here can be turned off from the TOML.

Design and rationale: docs/21-diseno-t06-proxy.md, section 4.
"""

import posixpath
import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from urllib.parse import unquote

ALLOWED_PORTS = frozenset({80, 443})

# Python's is_global is not enough on its own: it calls IPv4 multicast, fec0::/10, ff00::/8,
# ::a.b.c.d and 64:ff9b::/96 "global", and its tables changed between 3.12 patch releases.
# So an IPv4 address must be global AND outside these; an IPv6 one must be global unicast
# (2000::/3), outside these, and never carry an IPv4 address inside.
_IPV4_REFUSED = tuple(
    IPv4Network(net)
    for net in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, cloud metadata
        "172.16.0.0/12",
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.88.99.0/24",  # 6to4 relay anycast (deprecated)
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, and the broadcast address
    )
)
_IPV6_GLOBAL_UNICAST = IPv6Network("2000::/3")
_IPV6_REFUSED = tuple(
    IPv6Network(net)
    for net in (
        "2001::/23",  # IETF protocol assignments: Teredo (2001::/32), benchmarking, ORCHID
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4: an IPv4 address inside
        "3fff::/20",  # documentation
    )
)


def port_allowed(port: object) -> bool:
    """Only 80 and 443, as an int (never a bool, a float or a text)."""
    return type(port) is int and port in ALLOWED_PORTS


def is_public(address: object) -> bool:
    """Whether the proxy may connect to ``address``, an IP already resolved.

    Only a plain IP text (or an ``ipaddress`` object) is accepted: decimal, octal, hex and
    short forms ("2130706433", "0177.0.0.1", "127.1"), a scope id, brackets or spaces are
    refused, and so is anything that is not loopback-free, private-free global unicast.
    IPv4 addresses hidden in IPv6 (mapped, compatible, NAT64, 6to4, Teredo) are refused
    even when the IPv4 one is public: a resolver gives plain A records for those.
    """
    if isinstance(address, str):
        try:
            parsed = ip_address(address)
        except ValueError:
            return False
    elif isinstance(address, IPv4Address | IPv6Address):
        parsed = address
    else:
        return False
    if isinstance(parsed, IPv4Address):
        return parsed.is_global and not any(parsed in net for net in _IPV4_REFUSED)
    return (
        parsed.scope_id is None
        and parsed in _IPV6_GLOBAL_UNICAST
        and parsed.is_global
        and not any(parsed in net for net in _IPV6_REFUSED)
    )


def pick_address(addresses: Iterable[str]) -> str | None:
    """The address to connect to, or None when there is none or ANY of them is not public
    (a name that answers with a public and a private address is a rebinding trick).

    IPv4 is preferred: the proxy's outgoing network has no IPv6. The addon then pins the
    connection to this address and keeps the name as SNI (docs/21, section 4).
    """
    candidates = list(addresses)
    if not candidates or not all(is_public(address) for address in candidates):
        return None
    for address in candidates:
        if isinstance(ip_address(address), IPv4Address):
            return address
    return candidates[0]


# --- host names --------------------------------------------------------------------------------

_LABEL_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", re.ASCII)
_MAX_HOST_LENGTH = 253


def normalize_host(host: object, *, idna: bool = False) -> str | None:
    """The host as it is compared: lower case, without the final dot; an IP in its
    canonical form (an IPv6 one may come in brackets). None if it is not a valid host name
    or IP.

    A host from the wire (``CONNECT``, ``Host``, SNI) must already be ASCII (punycode):
    clients send it so, and IDNA 2003 would fold look-alikes into it ("ａｐｉ.example",
    "api。example", "faß.de" -> "fass.de", which IDNA 2008 reads otherwise). Only names
    that backtide's own configuration writes are converted, with ``idna=True``."""
    if not isinstance(host, str):
        return None
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        try:
            return str(IPv6Address(text[1:-1]))
        except ValueError:
            return None
    try:
        return str(ip_address(text))
    except ValueError:
        pass
    if text.endswith("."):
        text = text[:-1]
    if not text or not text.isprintable() or (not idna and not text.isascii()):
        return None
    try:
        ascii_host = text.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(ascii_host) > _MAX_HOST_LENGTH:
        return None
    if not all(_LABEL_RE.fullmatch(label) for label in ascii_host.split(".")):
        return None
    return ascii_host


def normalize_pattern(entry: str) -> str:
    """An allow-list entry, normalized: an exact name or ``*.domain`` (subdomains of a
    domain with at least two labels, never the domain itself). IPs are not accepted.
    Raises ValueError, with a message that is safe to show."""
    if not isinstance(entry, str):
        raise ValueError("an allowed host must be a text")
    text = entry.strip()
    wildcard = text.startswith("*.")
    name = normalize_host(text[2:] if wildcard else text, idna=True)
    if name is None:
        raise ValueError(f"not a valid host name: {entry!r}")
    if is_ip(name):
        raise ValueError(f"an allowed host must be a name, not an IP: {entry!r}")
    if wildcard and "." not in name:
        raise ValueError(f"a wildcard needs a domain with two labels or more: {entry!r}")
    return f"*.{name}" if wildcard else name


class AllowList:
    """The hosts the agent may reach, as backtide decides them (docs/21, section 4)."""

    def __init__(self, entries: Iterable[str]) -> None:
        normalized = dict.fromkeys(normalize_pattern(entry) for entry in entries)
        self.entries: tuple[str, ...] = tuple(normalized)
        self._exact = frozenset(entry for entry in self.entries if not entry.startswith("*."))
        self._suffixes = tuple(entry[1:] for entry in self.entries if entry.startswith("*."))

    def allows(self, host: str) -> bool:
        name = normalize_host(host)
        if name is None or is_ip(name):
            return False
        return name in self._exact or any(name.endswith(suffix) for suffix in self._suffixes)


_NUMBER_RE = re.compile(r"0[xX][0-9a-fA-F]*|0[0-7]*|[1-9][0-9]*", re.ASCII)  # glibc: "0x" is 0


def _number(part: str) -> int:
    if part[:2].lower() == "0x":
        return int(part[2:] or "0", 16)
    return int(part, 8 if part[0] == "0" else 10)


def numeric_ipv4(host: object) -> str | None:
    """The IPv4 address a host written as numbers stands for, as ``inet_aton`` (and so the
    resolver behind ``getaddrinfo``) reads it, or None: one to four parts, each decimal, octal
    (``0177``) or hex (``0x7f``), the last one filling the bytes left (``127.1``, ``0x7f.1``,
    ``2130706433``). ``ip_address`` takes none of these, so they would pass for host names."""
    if not isinstance(host, str):
        return None
    text = host.strip()
    if text.endswith("."):
        text = text[:-1]
    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or not all(_NUMBER_RE.fullmatch(part) for part in parts):
        return None
    values = [_number(part) for part in parts]
    *head, last = values
    if any(value > 255 for value in head) or last >= 256 ** (5 - len(parts)):
        return None
    number = 0
    for value in head:
        number = number << 8 | value
    number = number << 8 * (5 - len(parts)) | last
    return str(IPv4Address(number))


def is_ip(name: str) -> bool:
    """Whether ``name`` is an IP literal (as normalize_host leaves one)."""
    try:
        ip_address(name)
    except ValueError:
        return False
    return True


# --- domain fronting ---------------------------------------------------------------------------

_PORT_RE = re.compile(r"[0-9]{1,5}", re.ASCII)


def parse_host_header(value: object) -> tuple[str, int | None] | None:
    """``(host, port or None)`` from a ``Host`` header (or an HTTP/2 ``:authority``), or
    None if it does not parse. An IPv6 address must come in brackets."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        host_part, rest = text[: end + 1], text[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        port_part = rest[1:] if rest else None
    else:
        host_part, colon, port_part = text.partition(":")
        if not colon:
            port_part = None
    host = normalize_host(host_part)
    if host is None or (":" in host and not host_part.startswith("[")):
        return None
    if port_part is None:
        return host, None
    if not _PORT_RE.fullmatch(port_part) or not 0 < int(port_part) < 65536:
        return None
    return host, int(port_part)


def host_mismatch(
    connect_host: str,
    host_header: str | None,
    *,
    connect_port: int | None = None,
    sni: str | None = None,
) -> bool:
    """True unless the ``Host`` header (and the SNI, when the client sent one) names the
    same host as the connection (``CONNECT``), and the same port when the header has one.
    A missing or unparsable ``Host`` is a mismatch: refuse what cannot be compared."""
    connect = normalize_host(connect_host)
    parsed = parse_host_header(host_header)
    if connect is None or parsed is None:
        return True
    host, port = parsed
    if host != connect:
        return True
    if port is not None and connect_port is not None and port != connect_port:
        return True
    return sni is not None and normalize_host(sni) != connect


# --- OAuth logins ------------------------------------------------------------------------------

# Hosts that only serve logins: refused whatever the path. Revisable list (docs/21, section 4).
OAUTH_HOSTS = frozenset(
    {
        "auth.openai.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
        "login.microsoftonline.com",
        "login.live.com",
    }
)
# (host, path prefix) of OAuth routes on hosts that also serve other things. A prefix
# matches on whole segments, after the path is canonicalized (see _canonical_path).
OAUTH_PATHS = frozenset(
    {
        ("claude.ai", "/oauth"),
        ("claude.ai", "/api/oauth"),
        ("console.anthropic.com", "/oauth"),
        ("console.anthropic.com", "/v1/oauth"),
        ("platform.claude.com", "/oauth"),
        ("platform.claude.com", "/v1/oauth"),
        ("api.anthropic.com", "/api/oauth"),
        ("api.anthropic.com", "/v1/oauth"),
        ("github.com", "/login/oauth"),
        ("github.com", "/login/device"),
    }
)
_MAX_UNQUOTE_ROUNDS = 3


def is_oauth_login(host: str, path: str) -> bool:
    """Whether a request to ``host`` (the connection's) and ``path`` (with its query) is
    an OAuth login. A host that does not normalize counts as one: refuse on doubt."""
    name = normalize_host(host)
    if name is None:
        return True
    if name in OAUTH_HOSTS:
        return True
    canonical = _canonical_path(path)
    return any(
        name == oauth_host and (canonical == prefix or canonical.startswith(prefix + "/"))
        for oauth_host, prefix in OAUTH_PATHS
    )


def _canonical_path(path: str) -> str:
    """The path as a lenient server could read it: without query, percent-decoded (a few
    rounds, for %25xx), backslashes as slashes, ``;params`` and trailing dots or spaces of
    each segment dropped, repeated slashes and dot segments resolved, and in lower case.
    Matching on this refuses more, never less."""
    text = path
    for _ in range(_MAX_UNQUOTE_ROUNDS):
        text = text.split("?", 1)[0].split("#", 1)[0]  # again once decoded: "%3F" is a "?"
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = text.replace("\\", "/")
    segments = [_canonical_segment(segment) for segment in text.split("/")]
    # Empty segments are dropped, so there is never a leading "//" for normpath to keep.
    return posixpath.normpath("/" + "/".join(segment for segment in segments if segment)).lower()


def _canonical_segment(segment: str) -> str:
    segment = segment.split(";", 1)[0]
    return segment if segment in {".", ".."} else segment.rstrip(". \t")
