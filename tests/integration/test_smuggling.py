"""HTTP/2-to-HTTP/1.1 request smuggling (security review of T11, docs/incidentes.md 2026-10-22),
in the VM: the real service, the real proxy and the real OpenClaw jail, with the fake internet
(which only offers the ``http/1.1`` ALPN, so the proxy always speaks HTTP/1.1 upstream).

An HTTP/2 request whose body is sent in DATA frames carries no Content-Length and no
Transfer-Encoding. mitmproxy 12.2.3 forwards it to the HTTP/1.1 server without adding either; the
server reads a zero-length body and the body bytes become a second request. The gate now adds the
Content-Length of the body it read before recording the request, so the whole body reaches the
server framed and nothing is smuggled.

Here, toward the OpenAI-shaped fake provider (a model call is never held): an HTTP/2 POST to
/v1/chat/completions whose JSON body is streamed without a Content-Length. Before the fix the
provider received ``body_size`` 0 (the body stayed on the wire); after it, the whole body. The
non-provider smuggle with an arbitrary second request is in the battery (``contrabando-h2``).

Nothing here reaches a real provider and no real key exists (invariant 8).
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.integration.conftest import _new_service
from tests.integration.internet_kit import (
    ANTHROPIC,
    OPENAI,
    OPENAI_HOST,
    OPENAI_MODEL,
    FakeInternet,
    made_up_key,
    provider_toml,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import Service, wait_until

pytestmark = pytest.mark.integration

CURL_TIMEOUT = 60
URL = f"https://{OPENAI_HOST}/v1/chat/completions"


@dataclass
class Lab:
    service: Service
    internet: FakeInternet

    @property
    def fake(self) -> str:
        return self.service.config.provider_keys[OPENAI].fake


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    real = {ANTHROPIC: made_up_key("anthropic"), OPENAI: made_up_key("openai")}
    service = _new_service(
        btrfs_volume, tmp_path_factory, proxy_toml=provider_toml(), real_keys=real
    )
    internet: FakeInternet | None = None
    try:
        internet = start_fake_internet(service, tmp_path_factory.mktemp("t11-smuggle-internet"))
        service.main_args = internet.service_args()
        service.start()
        service.wait_ready()
        yield Lab(service, internet)
    finally:
        stop_with_internet(service, internet)


def h2_post_without_length(lab: Lab, body: bytes) -> dict:
    """An HTTP/2 POST whose body is streamed (chunked over the tunnel, no Content-Length) to the
    OpenAI-shaped provider. Returns the provider's record of what reached it."""
    seen_before = len(lab.internet.requests(OPENAI_HOST, "/v1/chat/completions"))
    argv = [
        "curl", "-sS", "--http2", "--max-time", "30",
        "-H", f"Authorization: Bearer {lab.fake}",
        "-H", "Content-Type: application/json",
        "-H", "Transfer-Encoding: chunked",  # over h2, curl streams with no Content-Length
        "--data-binary", body.decode("latin-1"),
        "-o", "/dev/null", "-w", "%{http_code}",
        URL,
    ]  # fmt: skip
    lab.service.jail.exec(argv, timeout=CURL_TIMEOUT)
    wait_until(
        lambda: len(lab.internet.requests(OPENAI_HOST, "/v1/chat/completions")) > seen_before,
        30,
        "the provider to receive the call",
        context=lab.service.diagnosis,
    )
    return lab.internet.requests(OPENAI_HOST, "/v1/chat/completions")[-1]


def test_an_h2_body_reaches_the_provider_whole_not_zero_length(lab: Lab) -> None:
    body = json.dumps(
        {"model": OPENAI_MODEL, "messages": [{"role": "user", "content": "say the test phrase"}]}
    ).encode()
    seen = h2_post_without_length(lab, body)
    # Before the fix this was 0: the body stayed on the connection, unseen by the server.
    assert seen["body_size"] == len(body), seen
    # And the gate recorded the call with its full body too.
    requests = [
        e for e in lab.service.events("request", "llm") if e.details.get("provider") == OPENAI
    ]
    assert requests and requests[-1].details["body"]["size"] == len(body)
