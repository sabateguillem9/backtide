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

Never logs or records anything but names, addresses and ports: none of them is a secret.
"""

import logging
import socket
from collections.abc import Callable, Iterable, Mapping
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Any

from backtide.gate.providers import local_address_ok
from backtide.service.config import Provider

logger = logging.getLogger(__name__)

OLLAMA_PORT = 11434
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
