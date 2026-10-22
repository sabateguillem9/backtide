"""T20-3's done-when, in the VM (docs/35, section 9): the real service, the real proxy and the
real OpenClaw's jail, with a local provider whose model is our fake Ollama
(tests/integration/ollama_kit.py) on the egress network, at a private address the proxy may only
reach as that provider.

- A good call to ``https://<provider>.backtide.internal/v1/chat/completions`` reaches the fake
  Ollama at its fixed address, without any credential and with its own ``Host``; the black box
  has its ``llm/request {local: true, key: "none"}`` and an ``llm/response`` that cost 0.
- A call to ``/api/pull`` never reaches it (``provider_endpoint``, risk 3).
- A redirection of the local model never reaches the agent (502, ``local_redirect``), and the
  decoy port it points to sees nothing.
- The agent cannot name the fake Ollama itself: straight (no route), through the proxy by its
  address (``private_address``) or on its port (``port``).

It also answers T20-1's P3 for mitmproxy 12.2.3: a request that came through ``CONNECT
<name>:443`` can be rewritten to ``http://<IPv4>:<port>`` in the request hook. Nothing here
reaches a real Ollama, ollama.com or a real provider, and no real key exists (invariant 8).
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.integration.conftest import _new_service
from tests.integration.internet_kit import (
    ANTHROPIC,
    FakeInternet,
    leaks,
    made_up_key,
    provider_toml,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.ollama_kit import (
    MODEL,
    PLACEHOLDER,
    PORT,
    REPLY_TEXT,
    FakeOllama,
    local_provider_toml,
    point_local_provider,
    start_fake_ollama,
    with_neighbour,
)
from tests.integration.service_kit import Service, wait_until

pytestmark = pytest.mark.integration

LOCAL = "t20-ollama"
VIRTUAL = f"{LOCAL}.backtide.internal"
CURL_TIMEOUT = 60


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    ollama: FakeOllama
    real: dict[str, str]

    @property
    def fake(self) -> str:
        return self.service.config.provider_keys[LOCAL].fake


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    real = {ANTHROPIC: made_up_key("anthropic")}
    service = _new_service(
        btrfs_volume,
        tmp_path_factory,
        proxy_toml=provider_toml(openai=False) + local_provider_toml(LOCAL),
        real_keys=real,
    )
    internet: FakeInternet | None = None
    ollama: FakeOllama | None = None
    root = tmp_path_factory.mktemp("t20-3")
    try:
        internet = start_fake_internet(service, root / "internet")
        ollama = start_fake_ollama(service.config, root)
        point_local_provider(service, PLACEHOLDER, ollama.ip)
        service.main_args = with_neighbour(internet, ollama, root)
        service.start()
        service.wait_ready()
        yield Lab(service, internet, ollama, real)
    finally:
        if ollama is not None:
            ollama.remove()
        stop_with_internet(service, internet)


def curl(
    lab: Lab,
    url: str,
    *,
    body: dict | None = None,
    key: str | None = None,
    method: str | None = None,
    proxy: bool = True,
    http2: bool = False,
) -> tuple[int, str]:
    """``curl`` from inside the agent's jail: (HTTP status, body). 0 when it could not connect."""
    argv = (
        []
        if proxy
        else [
            "env",
            "-u",
            "HTTPS_PROXY",
            "-u",
            "https_proxy",
            "-u",
            "HTTP_PROXY",
            "-u",
            "http_proxy",
        ]
    )
    # --path-as-is: curl would squash "/v1/../api/pull" to "/api/pull" before sending it.
    argv += ["curl", "-sS", "--path-as-is", "--max-time", "30", "-o", "-", "-w", "\n%{http_code}"]
    if key is not None:
        argv += ["-H", f"Authorization: Bearer {key}"]
    if body is not None:
        argv += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(body)]
    if method is not None:
        argv += ["-X", method]
    if http2:  # HTTP/2 to the proxy (inside the tunnel); the proxy speaks HTTP/1.1 to Ollama
        argv += ["--http2"]
    done = lab.service.jail.exec([*argv, url], timeout=CURL_TIMEOUT)
    text, _, code = done.stdout.rpartition("\n")
    return int(code) if code.strip().isdigit() else 0, text


def chat(text: str = "say the test phrase", *, stream: bool = False) -> dict:
    return {"model": MODEL, "stream": stream, "messages": [{"role": "user", "content": text}]}


def local_events(lab: Lab, action: str, source: str = "llm") -> list:
    return [e for e in lab.service.events(action, source) if e.details.get("local") is True]


# --- the good call --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stream", "http2"), [(False, False), (True, False), (False, True)], ids=["json", "sse", "h2"]
)
def test_a_good_call_reaches_the_local_model_without_any_credential(
    lab: Lab, stream: bool, http2: bool
) -> None:
    before = len(lab.ollama.requests("/v1/chat/completions"))
    responses_before = len(local_events(lab, "response"))
    code, text = curl(
        lab,
        f"https://{VIRTUAL}/v1/chat/completions",
        body=chat(stream=stream),
        key=lab.fake,
        http2=http2,
    )
    assert code == 200, text
    assert REPLY_TEXT in text
    [seen] = lab.ollama.requests("/v1/chat/completions")[before:]
    headers = seen["headers"]
    assert headers["host"] == f"{lab.ollama.ip}:{PORT}"
    assert not {"authorization", "x-api-key", "cookie", "proxy-authorization"} & set(headers)
    assert lab.fake not in json.dumps(seen)
    assert seen["method"] == "POST"
    requests = local_events(lab, "request")
    assert requests, "no llm/request with local: true"
    details = requests[-1].details
    assert details["key"] == "none" and details["provider"] == LOCAL
    assert details["upstream"] == f"{lab.ollama.ip}:{PORT}" and details["host"] == VIRTUAL
    wait_until(
        lambda: len(local_events(lab, "response")) > responses_before,
        30,
        "the local llm/response",
        context=lab.service.diagnosis,
    )
    answer = local_events(lab, "response")[-1]
    assert answer.details["status"] == 200
    assert answer.details["cost"]["usd_micro"] == 0
    assert answer.details["cost"]["priced_by"] == "local"


def test_where_the_local_model_is_was_recorded(lab: Lab) -> None:
    [placed] = lab.service.events("provider_local", "system")
    assert placed.details == {
        "provider": LOCAL,
        "name": VIRTUAL,
        "address": lab.ollama.ip,
        "port": PORT,
    }


# --- what never reaches it ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "method", "risk"),
    [
        ("/api/pull", "POST", 3),
        ("/v1/../api/pull", "POST", 3),
        ("/api/delete", "DELETE", 3),
        ("/api/tags", "GET", 2),
        ("/api/chat", "POST", 2),
    ],
)
def test_an_ollama_route_off_the_list_never_reaches_it(
    lab: Lab, path: str, method: str, risk: int
) -> None:
    before = lab.ollama.stats()["requests"]
    blocked_before = len(lab.service.events("blocked", "net"))
    body = {"model": MODEL, "name": "evil/model", "insecure": True} if method != "GET" else None
    code, _ = curl(lab, f"https://{VIRTUAL}{path}", body=body, key=lab.fake, method=method)
    assert code == 403
    assert lab.ollama.stats()["requests"] == before
    wait_until(
        lambda: len(lab.service.events("blocked", "net")) > blocked_before,
        30,
        "the net/blocked",
        context=lab.service.diagnosis,
    )
    event = lab.service.events("blocked", "net")[-1]
    assert event.details["reason"] == "provider_endpoint" and event.details["local"] is True
    assert event.risk == risk


def test_without_its_fake_key_nothing_reaches_it(lab: Lab) -> None:
    before = lab.ollama.stats()["requests"]
    for key in (None, made_up_key("someone-else")):
        code, _ = curl(lab, f"https://{VIRTUAL}/v1/chat/completions", body=chat(), key=key)
        assert code == 403
    assert lab.ollama.stats()["requests"] == before


def redirections(lab: Lab) -> list:
    return [
        e
        for e in lab.service.events("blocked", "net")
        if e.details.get("reason") == "local_redirect"
    ]


@pytest.mark.parametrize("marker", ["T20-REDIRECT", "T20-SWITCH"], ids=["302", "101"])
def test_a_redirection_of_the_local_model_never_reaches_the_agent(lab: Lab, marker: str) -> None:
    accepts = lab.ollama.accepts()
    before = len(redirections(lab))
    code, text = curl(
        lab, f"https://{VIRTUAL}/v1/chat/completions", body=chat(marker), key=lab.fake
    )
    assert code == 502, text
    assert ":22" not in text and "Switching" not in text
    wait_until(
        lambda: len(redirections(lab)) > before,
        30,
        "the net/blocked of the redirection",
        context=lab.service.diagnosis,
    )
    event = redirections(lab)[-1]
    assert event.details["side"] == "response" and event.risk == 2
    after = lab.ollama.accepts()
    assert after["22"] == accepts["22"] == 0 and after["8080"] == accepts["8080"] == 0


def test_the_agent_cannot_name_the_local_model_itself(lab: Lab) -> None:
    before = lab.ollama.stats()
    ip = lab.ollama.ip
    # Straight, without the proxy: there is no route.
    assert curl(lab, f"http://{ip}:{PORT}/api/tags", proxy=False)[0] == 0
    # Through the proxy, by its address: a port the proxy never opens, or a private address.
    assert curl(lab, f"http://{ip}:{PORT}/api/tags")[0] in (0, 403)
    assert curl(lab, f"https://{ip}/api/tags")[0] in (0, 403)
    assert curl(lab, f"http://{ip}/api/tags")[0] in (0, 403)
    after = lab.ollama.stats()
    assert after["requests"] == before["requests"]
    assert after["accepts"]["22"] == 0 and after["accepts"]["8080"] == 0
    reasons = {e.details.get("reason") for e in lab.service.events("blocked", "net")}
    assert {"private_address", "port"} <= reasons


def test_no_key_of_the_test_is_anywhere(lab: Lab) -> None:
    assert local_events(lab, "response"), "the calls ran first"
    assert leaks(lab.service, list(lab.real.values())) == []
    report = lab.service.box.verify()
    assert report.ok, report.problems


def test_a_virtual_name_no_local_provider_has_goes_nowhere(lab: Lab) -> None:
    before = lab.ollama.stats()["requests"]
    code, _ = curl(lab, "https://other.backtide.internal/v1/chat/completions", body=chat())
    assert code in (0, 403)
    assert lab.ollama.stats()["requests"] == before
    assert not [q for q in lab.internet.dns_queries() if "backtide.internal" in q["name"]]
