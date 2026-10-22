"""T20-4 (docs/35, sections 6.6 and 11): the two agent profiles thinking with a local model, an
Ollama the proxy reaches by its virtual name ``<provider>.backtide.internal``.

- OpenClaw: a local provider never gets ``options.num_ctx`` (``injectNumCtxForOpenAICompat:
  false``), waits up to 300 s, and when it is the agent's model the catalog is only the configured
  one (``models.mode: "replace"``, decision 8: no silent paid fallback, no discovery).
- Claude Code: ``[agent.model] provider`` picks a provider of kind anthropic; its fake key goes in
  ``ANTHROPIC_API_KEY``, ``ANTHROPIC_BASE_URL`` points at its host and every model Claude Code
  would pick itself is one of its ``models``.
- The profile only says what the agent needs: the variables that come from the providers go
  through exactly the same checks as a profile's own (``AgentProfile.for_providers``).
- The service asks the Ollama its version (``system/provider_local_ready``) from the VM.
- `make probar LOCAL=<model>` writes that config (scripts/demo/probar.py).

Every key here is a fake one, made by the test.
"""

from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import Source
from backtide.gate.providers import Providers, new_fake_key
from backtide.jail.config import (
    AgentJailConfig,
    container_env,
    create_env,
    openclaw_config,
    token_env,
)
from backtide.jail.model import ModelProvider
from backtide.jail.openclaw import check_rewindable
from backtide.jail.profiles import CLAUDE_CODE, OPENCLAW
from backtide.jail.profiles.claude_code import (
    KEY_ENV,
    claude_code_profile,
    model_env,
)
from backtide.jail.profiles.openclaw import LOCAL_TIMEOUT_SECONDS, model_settings
from backtide.notify import AlertLevel
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.local_models import (
    MIN_OLLAMA_VERSION,
    LocalModelError,
    older_than,
    ollama_version,
)
from backtide.service.proxy_channel import Policy
from scripts.demo import demo, probar
from tests.test_jail_profile import CA_DIR, CONFIG_DIR, WORKSPACE, profile
from tests.test_probar_script import _event, paths  # noqa: F401 - paths is a fixture
from tests.test_service_config import layout, write_toml  # noqa: F401 - a fixture
from tests.test_service_egress import World
from tests.test_service_local import MAC, local_gate

MODEL = "qwen3-coder:30b"
SMALL = "qwen3:4b"


def local(name: str = "ollama", kind: str = "openai", *models: str) -> ModelProvider:
    return ModelProvider(
        name, kind, f"{name}.backtide.internal", new_fake_key(name), models or (MODEL,), local=True
    )


def anthropic(*models: str) -> ModelProvider:
    return ModelProvider(
        "anthropic", "anthropic", "api.anthropic.com", new_fake_key("anthropic"), models
    )


def jail(agent: Any, *providers: ModelProvider) -> AgentJailConfig:
    return AgentJailConfig(
        workspace=WORKSPACE,
        config_dir=CONFIG_DIR,
        ca_dir=CA_DIR,
        gateway_token="t" * 43 if agent.token_env else None,
        model_providers=providers,
        profile=agent,
    )


# --- the provider as the agent sees it ------------------------------------------------------------


def test_a_local_provider_is_at_its_virtual_name_and_only_it_is() -> None:
    assert local().local is True and local().host == "ollama.backtide.internal"
    with pytest.raises(ValueError, match="virtual name"):
        ModelProvider("ollama", "openai", "192.168.5.2", new_fake_key("ollama"), (MODEL,), True)
    with pytest.raises(ValueError, match="virtual name"):
        ModelProvider(
            "ollama", "openai", "other.backtide.internal", new_fake_key("ollama"), (MODEL,), True
        )
    with pytest.raises(ValueError, match="only a local provider"):
        ModelProvider("ollama", "openai", "ollama.backtide.internal", new_fake_key("ollama"))
    with pytest.raises(ValueError, match="true or false"):
        ModelProvider("o", "openai", "o.backtide.internal", new_fake_key("o"), (MODEL,), 1)  # type: ignore[arg-type]


def test_the_service_says_which_providers_are_local(layout: Path) -> None:  # noqa: F811
    config = ServiceConfig.from_file(
        write_toml(
            layout,
            "[proxy]\n"
            '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
            '[[proxy.providers]]\nname = "ollama"\nkind = "openai"\n'
            f'local = "http://host.lima.internal:11434"\nmodels = ["{MODEL}"]\n',
        )
    )
    claude, ollama = config.jail_config().model_providers
    assert (claude.local, ollama.local) == (False, True)
    assert ollama.host == "ollama.backtide.internal"  # never where it really is


# --- OpenClaw -------------------------------------------------------------------------------------


def test_openclaw_thinking_locally_sends_no_num_ctx_and_falls_back_to_nothing() -> None:
    claw = openclaw_config(jail(OPENCLAW, local()))
    check_rewindable(claw)
    models = claw["models"]
    assert models["mode"] == "replace"  # decision 8: only the configured catalog
    entry = models["providers"]["ollama"]
    assert entry == {
        "baseUrl": "https://ollama.backtide.internal/v1",
        "api": "openai-completions",
        "auth": "api-key",
        "apiKey": entry["apiKey"],
        "timeoutSeconds": LOCAL_TIMEOUT_SECONDS,
        "injectNumCtxForOpenAICompat": False,
        "models": [{"id": MODEL, "name": MODEL}],
    }
    assert entry["apiKey"].startswith("backtide-fake-ollama-")
    assert claw["agents"]["defaults"]["model"] == {"primary": f"ollama/{MODEL}"}
    assert LOCAL_TIMEOUT_SECONDS <= 300  # Node's own limit (T10-1)


def test_openclaw_keeps_merging_when_its_model_is_not_the_local_one() -> None:
    settings = model_settings((anthropic("claude-sonnet-5-5"), local()))
    assert settings["models"]["mode"] == "merge"
    assert settings["primary"] == "anthropic/claude-sonnet-5-5"
    assert settings["models"]["providers"]["ollama"]["injectNumCtxForOpenAICompat"] is False
    assert "timeoutSeconds" not in settings["models"]["providers"]["anthropic"]
    assert "injectNumCtxForOpenAICompat" not in settings["models"]["providers"]["anthropic"]


def test_a_local_provider_first_is_the_agents_model() -> None:
    settings = model_settings((local(), anthropic("claude-sonnet-5-5")))
    assert settings["models"]["mode"] == "replace"
    assert settings["primary"] == f"ollama/{MODEL}"


def test_an_anthropic_shaped_local_provider_has_no_openai_setting() -> None:
    entry = model_settings((local("ollama-claude", "anthropic"),))["models"]["providers"][
        "ollama-claude"
    ]
    assert entry["api"] == "anthropic-messages"
    assert entry["baseUrl"] == "https://ollama-claude.backtide.internal"
    assert "injectNumCtxForOpenAICompat" not in entry
    assert entry["timeoutSeconds"] == LOCAL_TIMEOUT_SECONDS


# --- Claude Code ----------------------------------------------------------------------------------


def test_claude_code_by_default_is_unchanged() -> None:
    assert claude_code_profile() is CLAUDE_CODE
    assert claude_code_profile("anthropic") is CLAUDE_CODE
    assert CLAUDE_CODE.fake_key_env == ((KEY_ENV, "anthropic"),)
    config = jail(CLAUDE_CODE, anthropic())
    assert config.profile is CLAUDE_CODE  # nothing added for Anthropic's own host
    assert "ANTHROPIC_BASE_URL" not in dict(container_env(config))


def test_claude_code_with_a_local_model_is_pointed_at_it() -> None:
    agent = claude_code_profile("ollama")
    assert agent is claude_code_profile("ollama")  # one object per provider
    assert agent.fake_key_env == ((KEY_ENV, "ollama"),)
    ollama = local("ollama", "anthropic", MODEL, SMALL)
    config = jail(agent, ollama)
    env = dict(container_env(config))
    assert env["ANTHROPIC_BASE_URL"] == "https://ollama.backtide.internal"
    for name in (
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "CLAUDE_CODE_SUBAGENT_MODEL",
    ):
        assert env[name] == MODEL
    assert env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == SMALL  # the last: small background tasks
    assert env["ANTHROPIC_SMALL_FAST_MODEL"] == SMALL
    assert token_env(config) == {KEY_ENV: ollama.fake_key}  # its own fake key, and only that
    assert create_env(config)["ANTHROPIC_BASE_URL"] == "https://ollama.backtide.internal"
    # The jail is the same: the variables are the profile's, nothing of the jail changed.
    assert env["HOME"] == "/workspace/home" and "HTTPS_PROXY" in env
    assert config.profile.name == "claude-code"


def test_one_model_does_everything() -> None:
    env = dict(model_env((local("ollama", "anthropic"),), "ollama"))
    assert set(env.values()) == {"https://ollama.backtide.internal", MODEL}


def test_claude_code_refuses_a_provider_it_cannot_speak_to() -> None:
    agent = claude_code_profile("ollama")
    with pytest.raises(ValueError, match="only speaks Anthropic"):
        jail(agent, local("ollama", "openai"))
    no_models = ModelProvider(
        "gateway", "anthropic", "gateway.example.com", new_fake_key("gateway")
    )
    with pytest.raises(ValueError, match="model ids"):
        jail(claude_code_profile("gateway"), no_models)
    wrong = ModelProvider(
        "anthropic", "anthropic", "gateway.example.com", new_fake_key("anthropic")
    )
    with pytest.raises(ValueError, match="calls that host itself"):
        jail(agent, wrong, local("ollama", "anthropic"))


PASTED_KEY = "sk-ant-api03-" + "Zq7" * 30  # what an owner might paste there by mistake


def test_a_provider_name_that_is_not_one_is_refused_without_quoting_it() -> None:
    for wrong in ("Not A Name", PASTED_KEY, "x" * 40, "-a", ""):
        with pytest.raises(ValueError, match="not a provider name") as refused:
            claude_code_profile(wrong)
        assert wrong not in str(refused.value) or not wrong
        assert PASTED_KEY[:12] not in str(refused.value)


def test_a_key_pasted_as_the_provider_never_reaches_the_message(
    layout: Path,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    text = f'[agent]\nprofile = "claude-code"\n[agent.model]\nprovider = "{PASTED_KEY}"\n'
    with pytest.raises(ConfigError) as refused:
        ServiceConfig.from_file(write_toml(layout, text + LOCAL_CLAUDE))
    assert "not a provider name" in str(refused.value)
    assert PASTED_KEY[:12] not in str(refused.value) and PASTED_KEY[:12] not in caplog.text


# --- for_providers: the same checks as any variable of a profile ----------------------------------


def test_variables_from_the_providers_follow_the_rules_of_env() -> None:
    def gives(*pairs: tuple[str, str]) -> Any:
        return profile(provider_env=lambda providers: pairs)

    for pairs, why in (
        ((("HTTPS_PROXY", "http://evil:1"),), "set by the jail"),
        ((("LD_PRELOAD", "/x.so"),), "set by the jail"),
        ((("DOCKER_HOST", "tcp://x"),), "docker CLI"),
        ((("SOME_TOKEN", "x"),), "never carry a secret"),
        ((("URL", "https://u:p4ssw0rd-long-enough@x.example"),), "looks like a secret"),
        ((("A", "x\ny"),), "one line"),
    ):
        with pytest.raises(ValueError, match=why):
            gives(*pairs).for_providers(())
    with pytest.raises(ValueError, match="tuple"):
        profile(provider_env=lambda providers: [("A", "b")]).for_providers(())


def test_variables_from_the_providers_are_added_once() -> None:
    agent = profile(env=(("A", "1"),), provider_env=lambda providers: (("B", "2"),))
    once = agent.for_providers(())
    assert once.env == (("A", "1"), ("B", "2"))
    assert once.for_providers(()) is once
    assert profile().for_providers(()) == profile()


# --- [agent.model] provider for Claude Code -------------------------------------------------------


LOCAL_CLAUDE = (
    "[proxy]\n"
    '[[proxy.providers]]\nname = "ollama"\nkind = "anthropic"\n'
    f'local = "http://host.lima.internal:11434"\nmodels = ["{MODEL}"]\n'
)


def test_claude_code_picks_its_provider_in_agent_model(layout: Path) -> None:  # noqa: F811
    text = '[agent]\nprofile = "claude-code"\n[agent.model]\nprovider = "ollama"\n' + LOCAL_CLAUDE
    config = ServiceConfig.from_file(write_toml(layout, text))
    assert config.agent_profile is claude_code_profile("ollama")
    jailed = config.jail_config()
    env = dict(container_env(jailed))
    assert env["ANTHROPIC_BASE_URL"] == "https://ollama.backtide.internal"
    assert env["ANTHROPIC_MODEL"] == MODEL
    assert token_env(jailed)[KEY_ENV] == config.provider_keys["ollama"].fake


@pytest.mark.parametrize(
    ("agent", "why"),
    [
        ('profile = "openclaw"\n[agent.model]\nprovider = "ollama"\n', "only for profile"),
        ('profile = "claude-code"\n[agent.model]\nprovider = "nobody"\n', "not one of"),
        (
            'profile = "claude-code"\n[agent.model]\nprovider = "ollama"\nkey_env = "X_KEY"\n',
            "takes only provider",
        ),
        ('profile = "claude-code"\n[agent.model]\nprovider = 3\n', "takes only provider"),
        ('profile = "claude-code"\nmodel = "ollama"\n', "takes only provider"),
        ('profile = "claude-code"\n[agent.model]\nprovider = "Bad Name"\n', "not a provider"),
        ('profile = "claude-code"\nentrypoint = ["x"]\n', "only for profile"),
    ],
)
def test_a_wrong_agent_model_is_refused(layout: Path, agent: str, why: str) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match=why):
        ServiceConfig.from_file(write_toml(layout, f"[agent]\n{agent}" + LOCAL_CLAUDE))


def test_claude_code_with_an_openai_shaped_local_provider_does_not_start(
    layout: Path,  # noqa: F811
) -> None:
    text = (
        '[agent]\nprofile = "claude-code"\n[agent.model]\nprovider = "ollama"\n'
        + LOCAL_CLAUDE.replace('kind = "anthropic"', 'kind = "openai"')
    )
    with pytest.raises(ConfigError, match="only speaks Anthropic"):
        ServiceConfig.from_file(write_toml(layout, text)).jail_config()


# --- the Ollama's version (system/provider_local_ready) -------------------------------------------


OK = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n"
VERSION_BODY = b'{"version":"0.40.8"}'


class FakeSocket:
    """The part of a socket ollama_version uses, on a fake clock: each ``recv`` hands the next
    chunk and moves the clock ``step`` seconds (a slow or dripping server)."""

    def __init__(self, *chunks: bytes, step: float = 0.0, error: Exception | None = None) -> None:
        self.chunks, self.step, self.error = list(chunks), step, error
        self.now = 0.0
        self.sent = b""
        self.connected: list[tuple[tuple[str, int], float]] = []
        self.timeouts: list[float] = []
        self.closed = False

    def connect(self, address: tuple[str, int], timeout: float) -> "FakeSocket":
        self.connected.append((address, timeout))
        return self

    def clock(self) -> float:
        return self.now

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def settimeout(self, seconds: float) -> None:
        self.timeouts.append(seconds)

    def recv(self, size: int) -> bytes:
        self.now += self.step
        if self.error is not None:
            raise self.error
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            chunk = chunk[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


def ask(fake: FakeSocket) -> str:
    return ollama_version(MAC, 11434, connect=fake.connect, monotonic=fake.clock)  # type: ignore[arg-type]


def test_the_version_is_asked_at_the_fixed_address_only() -> None:
    fake = FakeSocket(OK + VERSION_BODY)
    assert ask(fake) == "0.40.8"
    assert fake.connected == [((MAC, 11434), 5.0)]
    request = fake.sent.decode()
    assert request.startswith("GET /api/version HTTP/1.0\r\n")  # 1.0: never chunked
    assert f"Host: {MAC}:11434\r\n" in request and request.endswith("\r\n\r\n")
    assert fake.closed and all(0 < t <= 5.0 for t in fake.timeouts)


def test_an_answer_in_pieces_and_without_a_length_is_read_to_its_end() -> None:
    fake = FakeSocket(b"HTTP/1.0 200 OK\r\n", b"\r\n", b'{"version":', b'"0.14.0-rc1"}')
    assert ask(fake) == "0.14.0-rc1"


@pytest.mark.parametrize(
    ("chunks", "why"),
    [
        ((b"HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1:22/\r\n\r\n",), "with 302"),
        ((b"HTTP/1.1 200 OK\r\n\r\nnot json",), "version"),
        ((b'HTTP/1.1 200 OK\r\n\r\n{"version": "latest; rm -rf"}',), "version"),
        ((b'HTTP/1.1 200 OK\r\n\r\n{"version": 14}',), "version"),
        ((b'HTTP/1.1 200 OK\r\n\r\n["0.40.8"]',), "version"),
        (
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n14\r\n" + VERSION_BODY,),
            "version",
        ),
        ((b"SSH-2.0-OpenSSH_9.6\r\n",), "version"),  # not HTTP at all
        ((OK + VERSION_BODY + b" " * 9000,), "too long"),
        ((b"HTTP/1.1 200 OK\r\nX: " + b"a" * 9000,), "too long"),  # endless headers
    ],
)
def test_an_answer_that_is_not_a_version_is_said(chunks: tuple[bytes, ...], why: str) -> None:
    fake = FakeSocket(*chunks)
    with pytest.raises(LocalModelError, match=why):
        ask(fake)
    assert fake.closed


@pytest.mark.parametrize(
    "chunks",
    [
        (OK[:5], OK[5:10], OK[10:15], OK[15:], VERSION_BODY),  # headers dripped
        (OK, *(bytes([b]) for b in VERSION_BODY)),  # body dripped
        (b"HTTP/1.1 200 OK\r\n", *(b"X-Trailer: 1\r\n" for _ in range(200))),  # endless lines
    ],
    ids=["headers", "body", "lines"],
)
def test_a_server_that_drips_is_cut_at_the_deadline(chunks: tuple[bytes, ...]) -> None:
    """Each piece comes before the per-read timeout (4 s), but the whole answer never comes
    within 5 s: cut, never waited on for hours (review of T20-4)."""
    fake = FakeSocket(*chunks, step=4.0)
    with pytest.raises(LocalModelError, match="too slow"):
        ask(fake)
    assert fake.now <= 8.0 and fake.closed  # at most one read past the deadline


def test_no_answer_is_said_and_the_socket_is_closed() -> None:
    for error in (ConnectionRefusedError(), ConnectionResetError(), OSError("no route")):
        fake = FakeSocket(error=error)
        with pytest.raises(LocalModelError, match="does not answer"):
            ask(fake)
        assert fake.closed
    fake = FakeSocket(error=TimeoutError())
    with pytest.raises(LocalModelError, match="too slow"):
        ask(fake)

    def refused(address: tuple[str, int], timeout: float) -> Any:
        raise ConnectionRefusedError

    with pytest.raises(LocalModelError, match="does not answer"):
        ollama_version(MAC, 11434, connect=refused)


def test_the_minimum_version() -> None:
    assert MIN_OLLAMA_VERSION == "0.14.0"
    assert older_than("0.13.9") and older_than("0.1.47")
    assert not older_than("0.14.0") and not older_than("0.14.0-rc1")
    assert not older_than("0.40.8") and not older_than("1.0.0")
    with pytest.raises(ValueError):
        older_than("nonsense")


def started(tmp_path: Path, answer: Any) -> World:
    world = World(tmp_path)
    world.jail.agent_subnets = lambda: ["172.18.0.0/16"]  # type: ignore[attr-defined]
    asked: list[tuple[str, int]] = []

    def ask(address: str, port: int) -> str:
        asked.append((address, port))
        if isinstance(answer, Exception):
            raise answer
        return answer

    world.egress._ask_version = ask
    world.egress._policy = Policy(allow_hosts=(), providers=Providers([local_gate()]))
    world.egress.start(world.hooks)
    world.asked = asked  # type: ignore[attr-defined]
    return world


def test_the_ollamas_version_is_recorded_once_per_place(tmp_path: Path) -> None:
    world = started(tmp_path, "0.40.8")
    details, risk = world.only("provider_local_ready")
    assert details == {"provider": "ollama", "version": "0.40.8", "minimum": "0.14.0", "old": False}
    assert risk == 0 and not world.alerts
    world.egress.reload(Policy(allow_hosts=(), providers=Providers([local_gate()])))
    assert world.asked == [(MAC, 11434)]  # type: ignore[attr-defined]
    world.egress.reload(Policy(allow_hosts=(), providers=Providers([local_gate("192.168.5.9")])))
    assert world.asked[-1] == ("192.168.5.9", 11434)  # type: ignore[attr-defined]


def test_an_old_ollama_is_risk_2_and_alerted(tmp_path: Path) -> None:
    world = started(tmp_path, "0.12.3")
    details, risk = world.only("provider_local_ready")
    assert details["old"] is True and risk == 2
    assert [level for level, title in world.alerts if "antiguo" in title] == [AlertLevel.WARNING]


def test_an_ollama_that_does_not_answer_is_said(tmp_path: Path) -> None:
    world = started(tmp_path, LocalModelError(f"{MAC}:11434 does not answer (TimeoutError)"))
    details, risk = world.only("provider_local_unanswered")
    assert details == {
        "provider": "ollama",
        "address": MAC,
        "port": 11434,
        "why": f"{MAC}:11434 does not answer (TimeoutError)",
    }
    assert risk == 1 and "provider_local_ready" not in world.actions()


def test_a_broken_probe_never_stops_the_egress(tmp_path: Path) -> None:
    world = started(tmp_path, RuntimeError("boom"))
    assert "provider_local" in world.actions()
    assert "provider_local_ready" not in world.actions()


# --- make probar LOCAL=<model> --------------------------------------------------------------------


@pytest.mark.parametrize("agent", [probar.OPENCLAW, probar.CLAUDE_CODE])
def test_probar_with_the_owners_ollama(paths: demo.Paths, agent: str) -> None:  # noqa: F811
    paths.config.write_text(probar.render_config(paths, 1000, 1000, profile=agent, local=MODEL))
    paths.config.chmod(0o600)
    config = ServiceConfig.from_file(paths.config)
    (provider,) = config.proxy_settings().providers
    assert (provider.name, provider.local, provider.models) == (
        "ollama",
        ("host.lima.internal", 11434),
        (MODEL,),
    )
    assert provider.kind == ("anthropic" if agent == probar.CLAUDE_CODE else "openai")
    assert config.agent_profile.name == agent
    jailed = config.jail_config()
    if agent == probar.CLAUDE_CODE:
        assert dict(container_env(jailed))["ANTHROPIC_MODEL"] == MODEL
    else:
        claw = openclaw_config(jailed)
        assert claw["models"]["mode"] == "replace"
        assert claw["agents"]["defaults"]["model"] == {"primary": f"ollama/{MODEL}"}
    assert probar.is_local(paths) and probar.model_of(paths) == MODEL
    assert "key =" not in paths.config.read_text()  # no key anywhere


def test_probar_refuses_a_cloud_model_or_the_fake_internet(paths: demo.Paths) -> None:  # noqa: F811
    with pytest.raises(demo.DemoError, match="nube"):
        probar.render_config(paths, 1, 1, local="qwen3-coder:480b-cloud")
    with pytest.raises(demo.DemoError, match="FALSO"):
        probar.render_config(paths, 1, 1, local=MODEL, offline=True)
    with pytest.raises(demo.DemoError, match="forma"):
        probar.render_config(paths, 1, 1, local='x"\n[gate]')
    args = probar.build_parser().parse_args(["up", "--local", MODEL, "--perfil", "claude-code"])
    assert (args.local, args.perfil) == (MODEL, "claude-code")


def test_the_live_view_leaves_the_local_models_own_requests_to_the_llm_lines() -> None:
    call = _event(Source.NET, "request", "https://ollama.backtide.internal/v1/chat/completions")
    call.details["host"] = "ollama.backtide.internal"
    assert probar.describe(call) is None  # the llm lines say it
