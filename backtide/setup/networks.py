"""The two Docker networks' subnets, chosen so they do not clash with a VPN or the LAN (T13-3).

Docker picks a network's subnet from its default pools (172.17-31.0.0/16, 192.168.0.0/16)
and skips the ones the host routes at that moment. A VPN that comes up later with one of them,
or a LAN on 172.x, then shadows the network: the proxy's answers go down the VPN, or the LAN
becomes unreachable (docs/25, "Riesgos"). So the installer creates the agent's network and the
egress network itself, before the service first starts, each with a fixed /24 that nothing on
the host uses: no route, no address, no other Docker network. The argv is the jail's own
(``network_create_argv``) with ``--subnet`` added, so the service's checks find exactly the
network they would have made, and reuse it. ``backtide comprobar`` looks again later: a route
that came after (a VPN) and overlaps one of them is a warning that says what to do.

The pool is 172.29.0.0/16, from the top down: inside Docker's own range, where home routers and
the usual VPNs (10/8, 192.168/16, 100.64/10) are not. ``--subredes A,B`` picks others.
"""

import ipaddress
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from backtide.setup.host import Ran, Runner

IPv4Network = ipaddress.IPv4Network
POOL = ipaddress.ip_network("172.29.0.0/16")
PREFIX = 24
# Interfaces that are Docker's own: their routes are the networks themselves, not a clash.
DOCKER_DEVICES = ("docker0", "br-", "veth")
ROUTES_ARGV = ("ip", "-j", "-4", "route", "show", "table", "all")
ADDRESSES_ARGV = ("ip", "-j", "-4", "addr", "show")
DOCKER_NETWORKS_ARGV = ("docker", "network", "ls", "--quiet", "--no-trunc")


class NetworkError(Exception):
    """A subnet could not be chosen or a network could not be made (in Spanish)."""


@dataclass(frozen=True)
class Route:
    network: IPv4Network
    device: str

    @property
    def is_docker(self) -> bool:
        return self.device.startswith(DOCKER_DEVICES)

    def describe(self) -> str:
        return f"{self.network} ({self.device or '?'})"


def host_routes(run: Runner) -> list[Route]:
    """Every IPv4 route and address of the host (all tables), Docker's included."""
    found: list[Route] = []
    for entry in _json_list(run(ROUTES_ARGV)):
        dst = entry.get("dst")
        if not isinstance(dst, str) or dst == "default":
            continue
        network = _network(dst)
        if network is not None:
            found.append(Route(network, str(entry.get("dev", ""))))
    for link in _json_list(run(ADDRESSES_ARGV)):
        device = str(link.get("ifname", ""))
        for address in link.get("addr_info") or []:
            if not isinstance(address, dict):
                continue
            network = _network(f"{address.get('local')}/{address.get('prefixlen')}")
            if network is not None:
                found.append(Route(network, device))
    return found


def docker_subnets(run: Runner) -> list[IPv4Network]:
    """The IPv4 subnets of every Docker network that exists."""
    listed = run(DOCKER_NETWORKS_ARGV)
    ids = listed.stdout.split() if listed is not None and listed.returncode == 0 else []
    if not ids:
        return []
    ran = run(("docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", *ids))
    subnets = []
    for line in ran.stdout.splitlines() if ran is not None and ran.returncode == 0 else []:
        subnets += _subnets_of(line)
    return subnets


def subnet_of(name: str, run: Runner) -> IPv4Network | None | bool:
    """The subnet of Docker network ``name``: None if there is no such network, False if it
    exists without an IPv4 subnet Docker tells."""
    ran = run(("docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", name))
    if ran is None or ran.returncode != 0:
        return None
    found = _subnets_of(ran.stdout)
    return found[0] if found else False


def choose(taken: Iterable[IPv4Network], count: int) -> list[IPv4Network]:
    """``count`` /24s of POOL, from the top, that overlap nothing in ``taken``."""
    taken = list(taken)
    chosen: list[IPv4Network] = []
    for candidate in reversed(list(POOL.subnets(new_prefix=PREFIX))):
        if any(candidate.overlaps(other) for other in [*taken, *chosen]):
            continue
        chosen.append(candidate)
        if len(chosen) == count:
            return chosen
    raise NetworkError(
        f"no queda ninguna subred /{PREFIX} libre en {POOL}: elige dos con --subredes A,B"
    )


def parse_choice(text: str, count: int) -> list[IPv4Network]:
    """``--subredes 10.77.1.0/24,10.77.2.0/24``: private, IPv4, apart from each other."""
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if len(parts) != count:
        raise NetworkError(f"--subredes lleva {count} subredes separadas por comas")
    chosen = []
    for part in parts:
        try:
            network = ipaddress.ip_network(part, strict=True)
        except ValueError:
            raise NetworkError(f"{part!r} no es una subred IPv4 (como 172.29.255.0/24)") from None
        if not isinstance(network, IPv4Network) or not network.is_private:
            raise NetworkError(f"{part} no es una subred IPv4 privada")
        if network.prefixlen > 28:
            raise NetworkError(f"{part} es demasiado pequeña: como mínimo una /28")
        chosen.append(network)
    if chosen[0].overlaps(chosen[1]):
        raise NetworkError("las dos subredes se solapan")
    return chosen


def clashes(subnet: IPv4Network, routes: Sequence[Route]) -> list[Route]:
    """The host routes that are not Docker's and overlap ``subnet`` (a VPN, the LAN)."""
    return [route for route in routes if not route.is_docker and route.network.overlaps(subnet)]


def with_subnet(create_argv: Sequence[str], subnet: IPv4Network) -> list[str]:
    """The jail's ``docker network create`` argv (without ``docker``) with ``--subnet``: the
    options go before the network's name, which is its last argument."""
    argv = list(create_argv)
    if argv[:2] != ["network", "create"] or "--subnet" in argv:
        raise ValueError(f"not a plain network create argv: {argv}")
    return ["docker", *argv[:-1], "--subnet", str(subnet), argv[-1]]


def _subnets_of(text: str) -> list[IPv4Network]:
    try:
        config = json.loads(text)
    except ValueError:
        return []
    found = []
    for entry in config if isinstance(config, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("Subnet"), str):
            network = _network(entry["Subnet"])
            if network is not None:
                found.append(network)
    return found


def _network(text: str) -> IPv4Network | None:
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return network if isinstance(network, IPv4Network) else None


def _json_list(ran: Ran | None) -> list[dict]:
    if ran is None or ran.returncode != 0:
        return []
    try:
        data = json.loads(ran.stdout)
    except ValueError:
        return []
    return [entry for entry in data if isinstance(entry, dict)] if isinstance(data, list) else []
