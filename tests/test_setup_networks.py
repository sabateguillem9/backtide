"""The subnets of the two Docker networks (T13-3), against a VPN or the LAN."""

import ipaddress
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from backtide.jail.config import AgentJailConfig
from backtide.jail.config import network_create_argv as agent_argv
from backtide.setup import networks
from backtide.setup.host import Ran
from backtide.setup.networks import NetworkError

net = ipaddress.ip_network


def fake(answers: dict[tuple[str, ...], Ran]):
    def run(argv: Sequence[str]) -> Ran | None:
        return answers.get(tuple(argv))

    return run


ROUTES = [
    {"dst": "default", "gateway": "192.168.5.2", "dev": "eth0"},
    {"dst": "192.168.5.0/24", "dev": "eth0"},
    {"dst": "172.17.0.0/16", "dev": "docker0"},
    {"dst": "10.8.0.0/24", "dev": "tun0"},
    {"type": "local", "dst": "192.168.5.15", "dev": "eth0", "table": "local"},
]
ADDRESSES = [
    {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "eth0", "addr_info": [{"local": "192.168.5.15", "prefixlen": 24}]},
]


def test_host_routes_reads_routes_and_addresses() -> None:
    run = fake({
        networks.ROUTES_ARGV: Ran(0, json.dumps(ROUTES), ""),
        networks.ADDRESSES_ARGV: Ran(0, json.dumps(ADDRESSES), ""),
    })  # fmt: skip
    found = {(str(r.network), r.device) for r in networks.host_routes(run)}
    assert ("10.8.0.0/24", "tun0") in found
    assert ("192.168.5.15/32", "eth0") in found
    assert ("127.0.0.0/8", "lo") in found
    assert all(r[0] != "default" for r in found)


def test_unreadable_answers_are_no_routes() -> None:
    run = fake(
        {networks.ROUTES_ARGV: Ran(0, "not json", ""), networks.ADDRESSES_ARGV: Ran(1, "", "")}
    )
    assert networks.host_routes(run) == []
    assert networks.host_routes(fake({})) == []


def test_choose_takes_free_ones_from_the_top_of_the_pool() -> None:
    assert networks.choose([], 2) == [net("172.29.255.0/24"), net("172.29.254.0/24")]
    taken = [net("172.29.255.128/25"), net("172.29.253.0/24")]
    assert networks.choose(taken, 2) == [net("172.29.254.0/24"), net("172.29.252.0/24")]
    with pytest.raises(NetworkError, match="--subredes"):
        networks.choose([net("172.29.0.0/16")], 1)


def test_a_route_that_covers_the_whole_pool_is_seen() -> None:
    with pytest.raises(NetworkError):
        networks.choose([net("172.16.0.0/12")], 2)


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("10.77.1.0/24", "2 subredes"),
        ("10.77.1.0/24,nope", "no es una subred"),
        ("10.77.1.0/24,8.8.8.0/24", "privada"),
        ("10.77.1.0/24,10.77.1.128/25", "solapan"),
        ("10.77.1.0/24,10.77.2.0/30", "pequeña"),
        ("10.77.1.1/24,10.77.2.0/24", "no es una subred"),
        ("fd00::/64,10.77.2.0/24", "IPv4"),
    ],
)
def test_parse_choice_refuses_bad_subnets(text: str, said: str) -> None:
    with pytest.raises(NetworkError, match=said):
        networks.parse_choice(text, 2)


def test_parse_choice_keeps_the_order() -> None:
    assert networks.parse_choice(" 10.77.1.0/24 , 10.77.2.0/24 ", 2) == [
        net("10.77.1.0/24"),
        net("10.77.2.0/24"),
    ]


def test_clashes_ignore_dockers_own_devices() -> None:
    routes = [
        networks.Route(net("172.29.255.0/24"), "br-0123456789ab"),
        networks.Route(net("172.29.0.0/16"), "wg0"),
        networks.Route(net("10.0.0.0/8"), "eth0"),
    ]
    found = networks.clashes(net("172.29.255.0/24"), routes)
    assert [r.device for r in found] == ["wg0"]


def test_with_subnet_puts_it_before_the_name_of_the_jails_own_argv() -> None:
    base = agent_argv(
        AgentJailConfig(
            workspace=Path("/w"), config_dir=Path("/c"), ca_dir=Path("/ca"), gateway_token="t" * 43
        )
    )
    argv = networks.with_subnet(base, net("172.29.255.0/24"))
    assert argv[0] == "docker" and argv[1:3] == ["network", "create"]
    assert argv[-3:] == ["--subnet", "172.29.255.0/24", base[-1]]
    assert set(base) <= set(argv)
    with pytest.raises(ValueError):
        networks.with_subnet(["run", "x"], net("172.29.255.0/24"))
    with pytest.raises(ValueError):
        networks.with_subnet(argv[1:], net("172.29.255.0/24"))  # already has one


def test_subnet_of_and_docker_subnets() -> None:
    inspect = ("docker", "network", "inspect", "--format", "{{json .IPAM.Config}}")
    run = fake({
        (*inspect, "backtide-agente-net"): Ran(0, '[{"Subnet":"172.29.255.0/24"}]\n', ""),
        (*inspect, "empty"): Ran(0, "[]\n", ""),
        networks.DOCKER_NETWORKS_ARGV: Ran(0, "aaa\nbbb\n", ""),
        (*inspect, "aaa", "bbb"): Ran(
            0, '[{"Subnet":"172.17.0.0/16"}]\n[{"Subnet":"fd00::/64"}]\n', ""
        ),
    })  # fmt: skip
    assert networks.subnet_of("backtide-agente-net", run) == net("172.29.255.0/24")
    assert networks.subnet_of("empty", run) is False
    assert networks.subnet_of("missing", run) is None
    assert networks.docker_subnets(run) == [net("172.17.0.0/16")]
