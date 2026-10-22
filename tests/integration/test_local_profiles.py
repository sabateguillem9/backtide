"""T20-4 in the VM (docs/35, sections 6.6 and 11): the two agent profiles, the real OpenClaw
2026.9.8 and the real Claude Code 2.1.306 from their pinned images, think with a local model
through the proxy. The model is our fake Ollama (tests/integration/ollama_kit.py) on the egress
network: never a real Ollama, ollama.com or a real provider, and no real key (invariant 8).

For each agent, one turn ends with the fake Ollama's answer and:
- every call the agent made reached the fake Ollama with the one listed model (no background or
  utility model the proxy refuses, ``model_not_listed``), and OpenClaw's never carried
  ``options`` (``injectNumCtxForOpenAICompat: false``);
- the black box has its ``llm/request {local: true}`` and nothing toward the virtual name was
  refused (``net/blocked``): what each agent asks for, measured;
- the service asked that Ollama its version from the VM (``system/provider_local_ready``).
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from backtide.service.local_models import MIN_OLLAMA_VERSION
from tests.integration.conftest import _new_service
from tests.integration.internet_kit import FakeInternet, start_fake_internet, stop_with_internet
from tests.integration.ollama_kit import (
    MODEL,
    PLACEHOLDER,
    REPLY_TEXT,
    FakeOllama,
    local_provider_toml,
    point_local_provider,
    start_fake_ollama,
    with_neighbour,
)
from tests.integration.service_kit import Service, run_cli, wait_until

pytestmark = pytest.mark.integration

LOCAL = "ollama"  # the name an owner would write; OpenClaw takes it for its own Ollama plugin
VIRTUAL = f"{LOCAL}.backtide.internal"
TURN_TIMEOUT = 360.0
# What a local provider may be asked through the proxy (docs/35, section 6.2, step 4).
MODEL_PATHS = {
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/responses",
    "/v1/models",
    "/v1/messages",
    "/v1/messages/count_tokens",
}


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    ollama: FakeOllama

    def agent_calls(self) -> list[dict]:
        """What reached the fake Ollama through the proxy (not the service's /api/version)."""
        return [r for r in self.ollama.stats()["requests"] if r["path"] != "/api/version"]

    def refused(self) -> list[dict]:
        return [
            e.details
            for e in self.service.events("blocked", "net")
            if e.details.get("local") is True or VIRTUAL in str(e.target)
        ]

    def local_requests(self) -> list[dict]:
        return [
            e.details
            for e in self.service.events("request", "llm")
            if e.details.get("local") is True
        ]


def make_lab(
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
    *,
    kind: str,
    agent_toml: str = "",
) -> Iterator[Lab]:
    service = _new_service(
        btrfs_volume,
        tmp_path_factory,
        proxy_toml=local_provider_toml(LOCAL, kind=kind),
        agent_toml=agent_toml,
        agent_memory="3g",
    )
    internet: FakeInternet | None = None
    ollama: FakeOllama | None = None
    root = tmp_path_factory.mktemp("t20-4")
    try:
        internet = start_fake_internet(service, root / "internet")
        ollama = start_fake_ollama(service.config, root)
        point_local_provider(service, PLACEHOLDER, ollama.ip)
        service.main_args = with_neighbour(internet, ollama, root)
        service.start()
        service.wait_ready()
        yield Lab(service, internet, ollama)
    finally:
        if ollama is not None:
            ollama.remove()
        stop_with_internet(service, internet)


@pytest.fixture(scope="module")
def openclaw(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    yield from make_lab(btrfs_volume, tmp_path_factory, kind="openai")


@pytest.fixture(scope="module")
def claude_code(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    agent = f'profile = "claude-code"\n[agent.model]\nprovider = "{LOCAL}"\n'
    yield from make_lab(btrfs_volume, tmp_path_factory, kind="anthropic", agent_toml=agent)


def check_calls(lab: Lab) -> list[dict]:
    """Every call reached the fake Ollama with the listed model, on a model route, and none
    was refused on the way. Returns them."""
    calls = lab.agent_calls()
    assert calls, "the agent never reached its local model"
    assert {c["path"].split("?", 1)[0] for c in calls} <= MODEL_PATHS, calls
    asked = {c["model"] for c in calls if c["method"] == "POST"}
    assert asked == {MODEL}, f"models the agent asked for: {asked}"
    assert not lab.refused(), f"refused toward the local model: {lab.refused()}"
    requests = lab.local_requests()
    assert requests and {r["model"] for r in requests} == {MODEL}
    assert {r["key"] for r in requests} == {"none"}
    return calls


def check_version_asked(lab: Lab) -> None:
    """The service asked, once, from the VM and never through the proxy. In this lab the fake
    Ollama sits on the proxy's egress network, which is internal and has no address of the VM
    (measured: the VM's connection times out, "too slow"), so the answer recorded is
    ``unanswered``; what is recorded for an answer is in tests/test_jail_local_profiles.py.
    Either way the agent works."""
    wait_until(
        lambda: (
            lab.service.events("provider_local_ready", "system")
            or lab.service.events("provider_local_unanswered", "system")
        ),
        30,
        "the service to ask the Ollama its version",
        context=lab.service.diagnosis,
    )
    ready = lab.service.events("provider_local_ready", "system")
    unanswered = lab.service.events("provider_local_unanswered", "system")
    assert len(ready) + len(unanswered) == 1, (ready, unanswered)
    if ready:
        assert ready[0].details == {
            "provider": LOCAL,
            "version": "0.40.8",
            "minimum": MIN_OLLAMA_VERSION,
            "old": False,
        }
        assert ready[0].risk == 0
    else:
        details = unanswered[0].details
        assert details["address"] == lab.ollama.ip and details["port"] == 11434
        # A connect that times out is "too slow" (5 s in all); a refused one "does not answer".
        assert "too slow" in details["why"] or "does not answer" in details["why"]
        assert unanswered[0].risk == 1
    # Never through the proxy: the agent's side never asks /api/version, and the proxy would
    # refuse it (provider_endpoint).
    assert not [c for c in lab.agent_calls() if c["path"].startswith("/api/")]


# --- OpenClaw -------------------------------------------------------------------------------------


def test_openclaw_ends_a_turn_with_the_local_model(openclaw: Lab) -> None:
    claw = json.loads(
        openclaw.service.jail.exec(["cat", "/config/openclaw.json"], check=True).stdout
    )
    assert claw["models"]["mode"] == "replace"
    entry = claw["models"]["providers"][LOCAL]
    assert entry["baseUrl"] == f"https://{VIRTUAL}/v1"
    assert entry["injectNumCtxForOpenAICompat"] is False and entry["timeoutSeconds"] == 300
    turn = ["node", "openclaw.mjs", "agent", "--agent", "main", "--message", "say the phrase"]
    done = openclaw.service.jail.exec(turn, timeout=TURN_TIMEOUT)
    assert done.returncode == 0, (done.stdout[-2000:], done.stderr[-2000:])
    assert REPLY_TEXT in done.stdout, (done.stdout[-2000:], done.stderr[-2000:])
    calls = check_calls(openclaw)
    for call in calls:
        assert "options" not in call["fields"], call  # no num_ctx: the proxy would refuse it
    responses = [
        e for e in openclaw.service.events("response", "llm") if e.details.get("local") is True
    ]
    assert responses and responses[-1].details["cost"]["usd_micro"] == 0


def test_openclaw_the_service_asked_its_version(openclaw: Lab) -> None:
    check_version_asked(openclaw)


# --- Claude Code ----------------------------------------------------------------------------------


def test_claude_code_ends_a_task_with_the_local_model(claude_code: Lab) -> None:
    env = claude_code.service.jail.exec(["env"], check=True).stdout
    assert f"ANTHROPIC_BASE_URL=https://{VIRTUAL}" in env
    assert f"ANTHROPIC_DEFAULT_HAIKU_MODEL={MODEL}" in env
    assert "ANTHROPIC_API_KEY=backtide-fake-ollama-" in env
    done = run_cli(claude_code.service, "tarea", "say the phrase", timeout=TURN_TIMEOUT)
    assert done.returncode == 0, (done.stdout[-2000:], done.stderr[-2000:])
    assert REPLY_TEXT in done.stdout, (done.stdout[-2000:], done.stderr[-2000:])
    calls = check_calls(claude_code)
    assert any(c["path"].split("?", 1)[0] == "/v1/messages" for c in calls)


def test_claude_code_the_service_asked_its_version(claude_code: Lab) -> None:
    check_version_asked(claude_code)
