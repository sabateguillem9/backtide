"""T11's leftover in the VM (docs/33, "include_usage"): the real service, the real proxy and the
real OpenClaw's jail, with the fake OpenAI-compatible provider of the fake internet
(tests/integration/internet_kit.py), which streams its usage only when it is asked to, as
OpenAI does.

- A streamed Chat Completions call without ``stream_options`` reaches the provider with
  ``{"include_usage": true}`` (over HTTP/1.1, HTTP/2 and a chunked body); the agent gets the
  answer and ``[DONE]`` but never the extra usage chunk; the black box has the call as sent
  (``include_usage: "added"``) and an ``llm/response`` priced with the provider's usage.
- The agent's own ``stream_options`` is never touched: with ``include_usage: false`` the call is
  still estimated by excess, with ``true`` the agent gets its chunk.
- A stream the agent cuts right after the usage chunk, before ``[DONE]``, costs at least what it
  cost before the rewrite (its estimate), never the little its usage says.

Nothing here reaches a real provider and no real key exists (invariant 8).
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest

from tests.integration.conftest import _new_service
from tests.integration.internet_kit import (
    ANTHROPIC,
    OPENAI,
    OPENAI_HOST,
    OPENAI_MODEL,
    REPLY_TEXT,
    FakeInternet,
    made_up_key,
    provider_toml,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import TEST_BUDGET, Service, wait_until

pytestmark = pytest.mark.integration

CURL_TIMEOUT = 60
URL = f"https://{OPENAI_HOST}/v1/chat/completions"
MAX_TOKENS = 1000
# The owner's price of the fake model, in $/MTok (= µ$ per token): its calls are priced, not
# estimated as an unknown model's.
BUDGET = TEST_BUDGET + f'[budget.prices."{OPENAI_MODEL}"]\ninput = 1\noutput = 2\n'
USAGE_CHUNK = b'"choices": []'


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
        btrfs_volume,
        tmp_path_factory,
        proxy_toml=provider_toml(),
        real_keys=real,
        budget_toml=BUDGET,
    )
    internet: FakeInternet | None = None
    try:
        internet = start_fake_internet(service, tmp_path_factory.mktemp("t11-usage-internet"))
        service.main_args = internet.service_args()
        service.start()
        service.wait_ready()
        yield Lab(service, internet)
    finally:
        stop_with_internet(service, internet)


def call(
    lab: Lab, body: dict, *, say: str = "say the test phrase", mode: str = "h1", max_time: int = 30
) -> tuple[int, bytes, dict, dict]:
    """A streamed call from inside the agent's jail with its fake key, through the proxy: (HTTP
    status, what the agent got, its llm/request and what the provider saw, its llm/response)."""
    body = body | {"messages": [{"role": "user", "content": f"{say} ({uuid4().hex[:8]})"}]}
    requests_before = len(lab.service.events("request", "llm"))
    seen_before = len(lab.internet.requests(OPENAI_HOST))
    argv = ["curl", "-sS", "-N", "--max-time", str(max_time), "-o", "-", "-w", "\n%{http_code}",
            "-H", f"Authorization: Bearer {lab.fake}", "-H", "Content-Type: application/json",
            "--data-binary", json.dumps(body)]  # fmt: skip
    if mode == "h2":
        argv.append("--http2")  # curl sends its Content-Length
    elif mode == "chunked":  # HTTP/1.1 only: HTTP/2 has no chunked framing
        argv += ["--http1.1", "-H", "Transfer-Encoding: chunked"]
    else:
        argv.append("--http1.1")  # curl would pick HTTP/2 inside the tunnel otherwise
    done = lab.service.jail.exec([*argv, URL], timeout=CURL_TIMEOUT)
    text, _, code = done.stdout.rpartition("\n")
    seen = lab.internet.requests(OPENAI_HOST)[seen_before:]
    wait_until(
        lambda: len(lab.service.events("request", "llm")) > requests_before,
        30,
        "the llm/request",
    )
    request = lab.service.events("request", "llm")[requests_before]
    flow_id = request.details["flow_id"]

    def response() -> dict | None:
        found = [e for e in lab.service.events("response", "llm")
                 if e.details.get("flow_id") == flow_id]  # fmt: skip
        return found[-1].details if found else None

    wait_until(
        response,
        30,
        "the llm/response",
        context=lambda: f"stderr: {done.stderr[-500:]}\n{lab.service.diagnosis()}",
    )
    answer = response()
    assert answer is not None
    record = {"request": request.details, "provider": seen}
    return int(code) if code.strip().isdigit() else 0, text.encode(), record, answer


def chat(**extra: object) -> dict:
    return {"model": OPENAI_MODEL, "stream": True, "max_completion_tokens": MAX_TOKENS} | extra


@pytest.mark.parametrize("mode", ["h1", "h2", "chunked"])
def test_the_proxy_asks_for_the_usage_the_agent_did_not(lab: Lab, mode: str) -> None:
    code, got, record, answer = call(lab, chat(), mode=mode)
    assert code == 200, got[-500:]
    assert REPLY_TEXT.encode() in got and b"data: [DONE]" in got, (got[-300:], record)
    assert USAGE_CHUNK not in got  # the chunk it did not ask for never reaches it
    [seen] = record["provider"]
    assert seen["stream_options"] == {"include_usage": True}
    request = record["request"]
    assert request["include_usage"] == "added"
    assert request["body"]["size"] == seen["body_size"]  # recorded as sent
    assert answer["usage"] == {"input": 12, "output": 7} and answer["complete"] is True
    assert answer["cost"] == {"usd_micro": 12 * 1 + 7 * 2, "estimated": False,
                              "unknown_model": False, "priced_by": "owner"}  # fmt: skip


@pytest.mark.parametrize("mode", ["h1", "chunked"])
def test_the_agents_own_include_usage_false_is_left_alone(lab: Lab, mode: str) -> None:
    own = {"include_usage": False}
    code, got, record, answer = call(lab, chat(stream_options=own), mode=mode)
    assert code == 200 and REPLY_TEXT.encode() in got and b"data: [DONE]" in got, json.dumps(record)
    [seen] = record["provider"]
    assert seen["stream_options"] == own
    assert "include_usage" not in record["request"]
    assert answer.get("usage_missing") is True
    assert answer["cost"]["estimated"] is True  # by excess, as before


def test_an_agent_that_asked_for_the_usage_gets_its_chunk(lab: Lab) -> None:
    code, got, record, answer = call(lab, chat(stream_options={"include_usage": True}))
    assert code == 200 and USAGE_CHUNK in got and b"data: [DONE]" in got
    assert "include_usage" not in record["request"]
    assert answer["usage"] == {"input": 12, "output": 7}


def test_a_stream_cut_after_its_usage_costs_at_least_its_old_estimate(lab: Lab) -> None:
    """The fake provider pauses after the usage chunk (T11-USAGE-CUT) and the agent hangs up:
    the usage came but the answer did not end. Before the rewrite such a call had no usage and
    was estimated (its bytes at the dearest input price, 2 µ$ for the 1 h cache write, and its
    max_tokens of output); it still costs at least that, far above the 12 + 7 its usage says."""
    _, got, record, answer = call(lab, chat(), say="T11-USAGE-CUT", max_time=3)
    assert USAGE_CHUNK not in got and b"[DONE]" not in got
    assert answer["usage"] == {"input": 12, "output": 7} and answer["complete"] is False
    size = record["request"]["body"]["size"]
    assert answer["cost"]["estimated"] is True
    assert answer["cost"]["usd_micro"] >= size * 2 + MAX_TOKENS * 2
