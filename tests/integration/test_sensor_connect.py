"""T07-3 in the VM: the agent's connection attempts in the black box (docs/23, section 4).

The real OpenClaw in its jail has no route out (its network is internal): every attempt here
fails, and that is the point, the attempt is what is recorded (``net/connect``). The addresses
are documentation ones (192.0.2.0/24, 2001:db8::/32), so nothing could leave the VM anyway.
Loopback is not recorded, except Docker's DNS (127.0.0.11:53), which is how the agent's name
lookups look. A connect to the egress proxy waits for T06-4, which starts it from the service.
"""

import json
from collections.abc import Callable, Iterator

import pytest

from tests.integration import sensor_kit
from tests.integration.service_kit import Service

pytestmark = pytest.mark.integration

# Run inside the agent as `python3 -c`: each attempt fails fast, and it prints what it tried.
ATTEMPTS = r"""
import json, socket
tried = []
def attempt(family, kind, addr):
    try:
        s = socket.socket(family, kind)
    except OSError as e:
        tried.append([addr[0], "no-socket", e.errno]); return
    s.settimeout(2)
    try:
        s.connect(addr); tried.append([addr[0], "connected", 0])
    except OSError as e:
        tried.append([addr[0], "failed", e.errno])
    finally:
        s.close()
attempt(socket.AF_INET, socket.SOCK_STREAM, ("192.0.2.1", 24226))
attempt(socket.AF_INET6, socket.SOCK_STREAM, ("2001:db8::1", 24226))
attempt(socket.AF_INET, socket.SOCK_DGRAM, ("192.0.2.2", 5353))
attempt(socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 9))
try:
    socket.getaddrinfo("t073.example.invalid", 443)
except OSError:
    pass
print(json.dumps(tried))
"""


@pytest.fixture
def sensed(make_real_service: Callable[..., Service]) -> Iterator[Service]:
    with sensor_kit.sensed_service(make_real_service) as service:
        yield service


def test_connects_outside_loopback_are_recorded_even_when_they_fail(sensed: Service) -> None:
    service = sensed
    service.start()
    service.wait_ready()
    sensor_kit.sensor_started(service)
    agent_id = service.jail.container_id()
    assert agent_id is not None
    since = sensor_kit.head_seq(service)

    result = service.jail.exec(["python3", "-c", ATTEMPTS], timeout=60)
    assert result.returncode == 0, result.stderr
    tried = {addr: outcome for addr, outcome, _ in json.loads(result.stdout)}
    assert tried["192.0.2.1"] == "failed" and tried["127.0.0.1"] == "failed"

    expected = {"192.0.2.1:24226": ("AF_INET", "tcp"), "192.0.2.2:5353": ("AF_INET", "udp")}
    if tried["2001:db8::1"] == "failed":  # an IPv6 socket exists in the jail
        expected["[2001:db8::1]:24226"] = ("AF_INET6", "tcp")

    def connects() -> dict[str, dict[str, object]]:
        found = service.box.events(source="net", action="connect", since_seq=since)
        return {e.target: e.details for e in found}

    for target in expected:
        sensor_kit.wait_event(
            service,
            lambda e, target=target: e.source == "net" and e.target == target,
            f"net/connect {target}",
            since=since,
        )
    seen = connects()
    for target, (family, proto) in expected.items():
        details = seen[target]
        assert (details["family"], details["proto"]) == (family, proto), target
        assert details["container"] == agent_id[:12]
        assert "python" in str(details["binary"])
    assert "127.0.0.1:9" not in seen  # loopback: not recorded
    # The name lookup went to Docker's DNS, which is not treated as loopback.
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "net" and e.target == "127.0.0.11:53",
        "the DNS lookup as net/connect 127.0.0.11:53",
        since=since,
    )
