"""Where each local model provider really is (T20, docs/35 section 6.1): resolved by the service,
on the trusted side, once at the start and again at each reload of the keys. The proxy never
resolves a local provider's name: it gets a fixed IPv4 and port through the channel.

- An IPv4 written in ``local`` is taken as is (the config checked that it is private).
- A name (``host.lima.internal``, the tower's) is looked up twice in a row (IPv4 only): it must
  give exactly one address, the same both times, and that address must be private and allowed
  (``providers.local_address_ok``). Anything else is ``LocalModelError``: at the start the service
  does not start and says why; at a reload the address it had is kept (``resolve_all``).
- At a reload, a name that now resolves elsewhere (a DHCP lease, a DNS someone changed) keeps
  its old address too: the new one is only reported (``moved``), and the Egress records it
  (risk 2) and alerts. The owner confirms it by restarting the service, which resolves it anew
  (review of T20-2/3, L2): nothing on the agent's side can move where the proxy goes.
- Never the agent's own network: ``outside`` checks an address against its subnets (the Egress
  asks Docker for them before the proxy starts).

- Which Ollama answers there (T20-4, docs/35 section 6.4): the service asks ``GET
  /api/version`` (``ollama_version``), once per place, from the VM and never through the proxy,
  and says whether it is older than ``MIN_OLLAMA_VERSION``. Plain HTTP/1.0 to the fixed address
  only, on a bare socket: VERSION_TIMEOUT seconds in all (connecting, headers and body, however
  slowly they drip: review of T20-4), no redirect followed, no chunked answer, at most
  MAX_VERSION_ANSWER bytes in all, and only a version number is taken from it.

Never logs or records anything but names, addresses, ports and versions: none of them is a
secret.
"""

import json
import logging
import re
import socket
import time
from collections.abc import Callable, Iterable, Mapping
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Any

from backtide.gate.providers import local_address_ok
from backtide.service.config import Provider

logger = logging.getLogger(__name__)

OLLAMA_PORT = 11434
# The oldest Ollama backtide is happy with: 0.14.0 (January 2026) added Anthropic's API
# (``/v1/messages``, which Claude Code needs; its release notes), and it is after
# ``/v1/responses`` (0.13.3) and the fixes of CVE-2024-37032, -39720 and -39722 (0.1.x).
MIN_OLLAMA_VERSION = "0.14.0"
VERSION_TIMEOUT = 5.0  # seconds IN ALL: Ollama answers /api/version at once, with no model loaded
MAX_VERSION_ANSWER = 8192  # bytes, headers and body: Ollama's answer is about 150
_STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?", re.ASCII)
_LENGTH_RE = re.compile(rb"content-length: *([0-9]{1,6}) *", re.ASCII | re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:[-+][0-9A-Za-z.-]{1,32})?", re.ASCII)
Lookup = Callable[..., list[Any]]  # socket.getaddrinfo


class LocalModelError(Exception):
    """A local provider cannot be placed. The message names the provider and what is wrong."""


def resolve(provider: Provider, *, lookup: Lookup = socket.getaddrinfo) -> tuple[str, int]:
    """(IPv4, port) of a local provider, as described above. LocalModelError otherwise."""
    if provider.local is None:
        raise LocalModelError(f"provider {provider.name} is not local")
    target, port = provider.local
    if local_address_ok(target):
        return target, port
    first = _addresses(provider.name, target, lookup)
    second = _addresses(provider.name, target, lookup)
    if len(first) != 1 or first != second:
        raise LocalModelError(
            f"provider {provider.name}: {target} must resolve to one IPv4 address, the same "
            f"each time (it gave {sorted(first)} and then {sorted(second)})"
        )
    [address] = first
    if not local_address_ok(address):
        raise LocalModelError(
            f"provider {provider.name}: {target} resolves to {address}, which is not a private "
            "address a local model may be at (10/8, 172.16/12, 192.168/16 or 100.64/10; never "
            "loopback, link-local or public)"
        )
    return address, port


def _addresses(name: str, target: str, lookup: Lookup) -> set[str]:
    try:
        infos = lookup(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as error:
        raise LocalModelError(f"provider {name}: {target} does not resolve ({error})") from None
    return {str(info[4][0]) for info in infos}


def resolve_all(
    providers: Iterable[Provider],
    previous: Mapping[str, tuple[str, int]] | None = None,
    *,
    lookup: Lookup = socket.getaddrinfo,
) -> tuple[dict[str, tuple[str, int]], dict[str, tuple[str, int]]]:
    """(where each local provider of ``providers`` is to be reached, where the ones that moved
    are now). With ``previous`` (a reload), one that cannot be resolved now, or that resolves
    to another address, keeps the address it had (logged; a move is returned in the second
    mapping); without it (the start), or with none before, LocalModelError."""
    found: dict[str, tuple[str, int]] = {}
    moved: dict[str, tuple[str, int]] = {}
    for provider in providers:
        if provider.local is None:
            continue
        try:
            found[provider.name] = resolve(provider, lookup=lookup)
        except LocalModelError as error:
            kept = (previous or {}).get(provider.name)
            if kept is None:
                raise
            logger.error("%s: it keeps %s:%d until the next reload", error, *kept)
            found[provider.name] = kept
            continue
        kept = (previous or {}).get(provider.name)
        if kept is not None and kept != found[provider.name]:
            now = found[provider.name]
            logger.warning(
                "local provider %s now resolves to %s:%d; it keeps %s:%d until the service is "
                "restarted", provider.name, *now, *kept,
            )  # fmt: skip
            moved[provider.name] = now
            found[provider.name] = kept
        if provider.local[1] != OLLAMA_PORT:
            logger.warning(
                "local provider %s is on port %d, not Ollama's %d: check it is not a typo that "
                "points to another service", provider.name, provider.local[1], OLLAMA_PORT,
            )  # fmt: skip
    return found, moved


def outside(upstreams: Mapping[str, tuple[str, int]], subnets: Iterable[str]) -> None:
    """LocalModelError if a local provider is inside one of ``subnets`` (the agent's network:
    the agent itself, or the proxy's leg there). A subnet that cannot be read is an error; an
    IPv6 one is skipped (a local model is only ever at an IPv4)."""
    networks: list[IPv4Network] = []
    for text in subnets:
        try:
            network = ip_network(str(text), strict=False)
        except ValueError:
            raise LocalModelError(
                f"the agent's network has a subnet that cannot be read: {text}"
            ) from None
        if isinstance(network, IPv4Network):
            networks.append(network)
    for name, (address, _port) in sorted(upstreams.items()):
        if any(IPv4Address(address) in network for network in networks):
            raise LocalModelError(
                f"provider {name}: {address} is on the agent's own network: a local model is "
                "never the agent nor the proxy"
            )


def ollama_version(
    address: str,
    port: int,
    *,
    timeout: float = VERSION_TIMEOUT,
    connect: Callable[..., socket.socket] = socket.create_connection,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """The version the Ollama at ``address:port`` says it is (``GET /api/version``), checked to
    be one (``0.40.8``, ``0.14.0-rc1``). LocalModelError if it does not answer, takes more than
    ``timeout`` seconds in all ("too slow"), answers anything else than a 200 with that (a
    redirect is not followed, a chunked answer is refused) or says something else."""
    deadline = monotonic() + timeout
    where = f"{address}:{port}"
    try:
        link = connect((address, port), timeout=timeout)
    except TimeoutError:
        raise LocalModelError(f"{where} is too slow to say its version") from None
    except OSError as error:
        raise LocalModelError(f"{where} does not answer ({type(error).__name__})") from None
    try:
        link.sendall(
            f"GET /api/version HTTP/1.0\r\nHost: {where}\r\nAccept: application/json\r\n"
            "Connection: close\r\n\r\n".encode("ascii")
        )
        data = _read_bounded(link, where, deadline, monotonic)
    except TimeoutError:
        raise LocalModelError(f"{where} is too slow to say its version") from None
    except OSError as error:
        raise LocalModelError(f"{where} does not answer ({type(error).__name__})") from None
    finally:
        link.close()
    return _version_in(data, where)


def _read_bounded(
    link: socket.socket, where: str, deadline: float, monotonic: Callable[[], float]
) -> bytes:
    """The whole answer: until the server closes, or until the body its Content-Length gives
    is in. LocalModelError past the deadline or past MAX_VERSION_ANSWER bytes."""
    data = b""
    while True:
        left = deadline - monotonic()
        if left <= 0:
            raise LocalModelError(f"{where} is too slow to say its version")
        link.settimeout(left)
        chunk = link.recv(MAX_VERSION_ANSWER + 1 - len(data))
        if not chunk:
            return data
        data += chunk
        if len(data) > MAX_VERSION_ANSWER:
            raise LocalModelError(f"{where}'s answer to /api/version is too long")
        head, found, body = data.partition(b"\r\n\r\n")
        if found:
            lengths = [_LENGTH_RE.fullmatch(line) for line in head.split(b"\r\n")[1:]]
            length = next((int(m.group(1)) for m in lengths if m is not None), None)
            if length is not None and len(body) >= length:
                return data


def _version_in(data: bytes, where: str) -> str:
    head, found, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = _STATUS_RE.fullmatch(lines[0]) if found else None
    if status is None:
        raise LocalModelError(f"{where} does not say an Ollama version (not an HTTP answer)")
    if status.group(1) != b"200":
        raise LocalModelError(f"{where} answered /api/version with {status.group(1).decode()}")
    if any(line.lower().startswith(b"transfer-encoding:") for line in lines[1:]):
        raise LocalModelError(f"{where} does not say an Ollama version (a chunked answer)")
    lengths = [_LENGTH_RE.fullmatch(line) for line in lines[1:]]
    length = next((int(m.group(1)) for m in lengths if m is not None), None)
    if length is not None:
        body = body[:length]
    try:
        version = json.loads(body).get("version")
    except (ValueError, AttributeError):
        version = None
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise LocalModelError(f"{where} does not say an Ollama version")
    return version


def older_than(version: str, minimum: str = MIN_OLLAMA_VERSION) -> bool:
    """Whether ``version`` (as ``ollama_version`` checked it) is older than ``minimum``. A
    pre-release of the minimum (``0.14.0-rc1``) counts as the minimum."""
    return _numbers(version) < _numbers(minimum)


def _numbers(version: str) -> tuple[int, int, int]:
    found = _VERSION_RE.fullmatch(version)
    if found is None:
        raise ValueError(f"not a version: {version!r}")
    major, minor, patch = found.groups()
    return int(major), int(minor), int(patch)
