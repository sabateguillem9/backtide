"""T20-2 (docs/35, sections 6.1, 6.4 and 6.5): a local model provider in the service. One test per
check of ``[[proxy.providers]] local`` (backtide/service/config.py), where backtide finds it
(local_models.py: one IPv4, twice the same, private), what the Egress records about it and checks
before the proxy starts, and its price: 0, decided by backtide's own config, never stopped by the
caps and with its own calls in flight (spend.py, proxy_channel.py). Also Ollama's cloud API, an
ordinary provider whose models the owner must price, and its key in the Settings page."""

import json
import logging
import socket
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.gate import protocol, record
from backtide.gate.providers import Provider as GateProvider
from backtide.gate.providers import Providers, Secret, new_fake_key
from backtide.gate.sse import LlmSummary
from backtide.jail.docker import JailError
from backtide.service import runner
from backtide.service.config import ConfigError, Provider, ServiceConfig
from backtide.service.local_models import LocalModelError, outside, resolve, resolve_all
from backtide.service.prices import price
from backtide.service.proxy_channel import Policy
from backtide.service.settings import check_value
from backtide.service.spend import Budget, BudgetSettings
from tests.test_service_config import layout, write_token, write_toml  # noqa: F401
from tests.test_service_egress import World
from tests.test_service_proxy_channel import Proxy, make_channel

MAC = "192.168.5.2"
KEY = b"k" * 32
LOCAL = (
    '[[proxy.providers]]\nname = "ollama"\nkind = "openai"\n'
    'local = "http://host.lima.internal:11434"\nmodels = ["qwen3-coder:30b"]\n'
)


def config_with(layout: Path, providers: str, extra: str = "") -> ServiceConfig:  # noqa: F811
    return ServiceConfig.from_file(write_toml(layout, f"{extra}[proxy]\n{providers}"))


def provider(local: str, name: str = "ollama", models: str = '["qwen3-coder:30b"]') -> str:
    return f'[[proxy.providers]]\nname = "{name}"\nkind = "openai"\nlocal = "{local}"\n' + (
        f"models = {models}\n" if models else ""
    )


# --- the configuration (6.1) ----------------------------------------------------------------------


def test_a_local_provider_is_read(layout: Path) -> None:  # noqa: F811
    config = config_with(layout, LOCAL)
    [read] = config.proxy_settings().providers
    assert read == Provider(
        "ollama",
        "openai",
        "ollama.backtide.internal",
        ("qwen3-coder:30b",),
        local=("host.lima.internal", 11434),
    )
    # The agent gets a fake key for it, as for any provider, and its virtual name.
    assert config.provider_keys["ollama"].fake.startswith("backtide-fake-ollama-")
    [model] = config.jail_config().model_providers
    assert model.host == "ollama.backtide.internal"
    # Not resolved here: the config touches no network. Built so, it has no address yet.
    [gate] = config.model_providers().items
    assert gate.local and gate.upstream is None and gate.real_key is None


def test_an_ipv4_as_written_needs_no_resolving(layout: Path) -> None:  # noqa: F811
    config = config_with(layout, provider("http://192.168.1.40:11434"))
    [gate] = config.model_providers().items
    assert gate.upstream == ("192.168.1.40", 11434)


@pytest.mark.parametrize(
    "local",
    [
        "https://host.lima.internal:11434",  # Ollama speaks no TLS
        "http://host.lima.internal",  # the port is said
        "http://host.lima.internal:11434/",  # no path
        "http://host.lima.internal:11434/v1",
        "http://user:pw@host.lima.internal:11434",
        "http://host.lima.internal:11434?x=1",
        "http://host.lima.internal:11434#x",
        "http://[::1]:11434",
        "http://[fd00::1]:11434",
        "http://host lima:11434",
        "HTTP://host.lima.internal:11434",
        "host.lima.internal:11434",
        "http://host.lima.internal:0",
        "http://host.lima.internal:70000",
    ],
)
def test_local_is_exactly_http_a_host_and_a_port(layout: Path, local: str) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match="local"):
        config_with(layout, provider(local))


@pytest.mark.parametrize(
    "local",
    [
        "http://127.0.0.1:11434",  # inside the proxy, that is the proxy itself
        "http://127.1:11434",
        "http://0x7f000001:11434",
        "http://3232236802:11434",  # 192.168.5.2 written as one number
        "http://0xc0a80502:11434",
        "http://192.168.005.002:11434",
        "http://169.254.169.254:11434",  # a cloud's metadata
        "http://0.0.0.0:11434",
        "http://8.8.8.8:11434",  # public: a public provider goes by https
        "http://224.0.0.1:11434",
        "http://255.255.255.255:11434",
        "http://localhost:11434",
        "http://ollama.localhost:11434",
    ],
)
def test_local_never_names_loopback_or_a_public_place(layout: Path, local: str) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match="local"):
        config_with(layout, provider(local))


def test_a_local_provider_has_no_host_setting(layout: Path) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match="no host setting"):
        config_with(layout, LOCAL + 'host = "ollama.lan"\n')


def test_no_other_provider_takes_a_virtual_name(layout: Path) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match="virtual name"):
        config_with(
            layout,
            '[[proxy.providers]]\nname = "x"\nkind = "openai"\nhost = "ollama.backtide.internal"\n',
        )


@pytest.mark.parametrize("models", ["", "[]", '["qwen3:480b-cloud"]', '["a", "gpt-oss:cloud"]'])
def test_a_local_provider_lists_its_models_and_none_of_the_cloud(
    layout: Path,  # noqa: F811
    models: str,
) -> None:
    with pytest.raises(ConfigError, match="local"):
        config_with(layout, provider("http://host.lima.internal:11434", models=models))


def test_at_most_four_local_providers(layout: Path) -> None:  # noqa: F811
    four = "".join(provider(f"http://10.0.0.{n}:11434", name=f"l{n}") for n in range(1, 5))
    assert len(config_with(layout, four).proxy_settings().providers) == 4
    with pytest.raises(ConfigError, match="at most 4 local"):
        config_with(layout, four + provider("http://10.0.0.9:11434", name="l9"))


def test_a_key_file_of_a_local_provider_is_never_sent_only_struck(
    layout: Path,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    keys = layout / "state" / "keys"
    keys.mkdir(mode=0o700)
    left = "sk-test-a-key-left-for-the-local-ollama-0123456789"
    write_token(keys / "ollama.key", left)
    config = config_with(layout, provider("http://192.168.5.2:11434"))
    providers, problems = config.model_providers_and_problems()
    [gate] = providers.items
    assert gate.real_key is None and not gate.waiting and problems == {}
    assert left in providers.strike_only and left in providers.known_secrets()
    with caplog.at_level(logging.WARNING):
        runner.local_upstreams(config)
    assert "never sent" in caplog.text and left not in caplog.text


def test_max_inflight_local_is_its_own_number(layout: Path) -> None:  # noqa: F811
    assert config_with(layout, "").budget_settings().max_inflight_local == 2
    config = config_with(layout, "", "[budget]\nmax_inflight_local = 5\n")
    assert config.budget_settings().max_inflight_local == 5
    for bad in ("0", "65", "true", '"2"'):
        with pytest.raises(ConfigError, match="max_inflight_local"):
            config_with(layout, "", f"[budget]\nmax_inflight_local = {bad}\n")


# --- where it is: resolved by the service, once (6.1) ---------------------------------------------


def lookup_of(*answers: list[str] | Exception) -> tuple[Any, list[tuple[Any, ...]]]:
    asked: list[tuple[Any, ...]] = []
    queue = list(answers)

    def lookup(host: str, port: object, **options: Any) -> list[Any]:
        asked.append((host, port, options.get("family")))
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(answer, Exception):
            raise answer
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in answer]

    return lookup, asked


NAMED = Provider("ollama", "openai", "ollama.backtide.internal", ("m",), local=("mac.lan", 11434))


def test_a_name_that_gives_one_private_ipv4_twice_is_taken() -> None:
    lookup, asked = lookup_of([MAC])
    assert resolve(NAMED, lookup=lookup) == (MAC, 11434)
    assert asked == [("mac.lan", None, socket.AF_INET)] * 2  # IPv4 only, asked twice


def test_an_ipv4_is_never_looked_up() -> None:
    lookup, asked = lookup_of(OSError("no DNS"))
    written = Provider("o", "openai", "o.backtide.internal", ("m",), local=("10.1.2.3", 8080))
    assert resolve(written, lookup=lookup) == ("10.1.2.3", 8080) and asked == []


@pytest.mark.parametrize(
    ("answers", "match"),
    [
        (([MAC, "192.168.5.3"],), "one IPv4"),  # two addresses
        (([],), "one IPv4"),
        (([MAC], ["192.168.5.3"]), "one IPv4"),  # it changed between the two lookups
        ((["127.0.0.1"],), "not a private"),
        ((["8.8.8.8"],), "not a private"),  # rebinding to a public address
        ((["169.254.169.254"],), "not a private"),
        ((socket.gaierror("Name or service not known"),), "does not resolve"),
    ],
)
def test_anything_else_is_refused(answers: tuple, match: str) -> None:
    lookup, _ = lookup_of(*answers)
    with pytest.raises(LocalModelError, match=match):
        resolve(NAMED, lookup=lookup)


def test_at_the_start_a_provider_that_cannot_be_placed_stops_the_service(
    layout: Path,  # noqa: F811
) -> None:
    config = config_with(layout, LOCAL)
    lookup, _ = lookup_of(socket.gaierror("nope"))
    with pytest.raises(ConfigError, match="does not resolve"):
        runner.local_upstreams(config, lookup=lookup)
    providers, problems = config.model_providers_and_problems()  # unresolved
    with pytest.raises(ConfigError, match="no address yet"):
        runner.egress_policy(config, providers, problems)


def test_at_a_reload_it_keeps_the_address_it_had(caplog: pytest.LogCaptureFixture) -> None:
    lookup, _ = lookup_of(socket.gaierror("nope"))
    with caplog.at_level(logging.ERROR):
        found, moved = resolve_all([NAMED], {"ollama": (MAC, 11434)}, lookup=lookup)
    assert found == {"ollama": (MAC, 11434)} and moved == {}
    assert "keeps 192.168.5.2:11434" in caplog.text


def test_at_a_reload_a_new_address_waits_for_the_owner(caplog: pytest.LogCaptureFixture) -> None:
    """L2 of the review: a name that resolves elsewhere at a reload (DHCP, or a DNS someone
    changed) is not used until the service restarts: the old address stays, and the new one is
    reported (``moved``) for the Egress to record and alert."""
    lookup, _ = lookup_of(["192.168.5.9"])
    with caplog.at_level(logging.WARNING):
        found, moved = resolve_all([NAMED], {"ollama": (MAC, 11434)}, lookup=lookup)
    assert found == {"ollama": (MAC, 11434)}
    assert moved == {"ollama": ("192.168.5.9", 11434)}
    assert "192.168.5.9" in caplog.text and "restart" in caplog.text
    fresh, nothing = resolve_all([NAMED], None, lookup=lookup)  # the start takes it at once
    assert fresh == {"ollama": ("192.168.5.9", 11434)} and nothing == {}


def test_the_keys_reload_keeps_the_old_address_and_says_where_it_moved(
    layout: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_with(layout, LOCAL)
    first, _ = lookup_of([MAC])
    monkeypatch.setattr(
        runner, "resolve_all", lambda p, prev=None: resolve_all(p, prev, lookup=first)
    )
    providers, problems = config.model_providers_and_problems(runner.local_upstreams(config))
    current = runner.egress_policy(config, providers, problems)

    class Reloadable:
        policy = current
        given: list[Policy] = []

        def reload(self, policy: Policy) -> bool:
            self.given.append(policy)
            return True

    later, _ = lookup_of(["192.168.5.9"])
    monkeypatch.setattr(
        runner, "resolve_all", lambda p, prev=None: resolve_all(p, prev, lookup=later)
    )
    egress = Reloadable()
    runner.key_reloader(config, egress)()
    [policy] = egress.given
    assert policy.providers.by_name("ollama").upstream == (MAC, 11434)
    assert policy.local_moved == {"ollama": ("192.168.5.9", 11434)}


def test_another_port_than_ollamas_is_said(caplog: pytest.LogCaptureFixture) -> None:
    other = Provider("o", "openai", "o.backtide.internal", ("m",), local=("10.1.2.3", 8080))
    with caplog.at_level(logging.WARNING):
        resolve_all([other])
    assert "port 8080" in caplog.text


def test_never_on_the_agents_own_network() -> None:
    outside({"ollama": (MAC, 11434)}, ["172.18.0.0/16", "fd00::/64"])
    with pytest.raises(LocalModelError, match="agent's own network"):
        outside({"ollama": ("172.18.0.3", 11434)}, ["172.18.0.0/16"])
    with pytest.raises(LocalModelError, match="cannot be read"):
        outside({"ollama": (MAC, 11434)}, ["nonsense"])


def test_build_egress_hands_the_proxy_the_resolved_address(
    layout: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_with(layout, LOCAL)
    lookup, _ = lookup_of([MAC])
    monkeypatch.setattr(
        runner, "resolve_all", lambda p, prev=None: resolve_all(p, prev, lookup=lookup)
    )
    providers, problems = config.model_providers_and_problems(runner.local_upstreams(config))
    policy = runner.egress_policy(config, providers, problems)
    [gate] = policy.providers.items
    assert gate.upstream == (MAC, 11434)
    message = protocol.config([], policy.providers, protocol.DEFAULT_LIMITS, fp_key=KEY)
    assert message["providers"][0]["upstream"] == [MAC, 11434]


# --- what the Egress records, and checks before the proxy (6.4) -----------------------------------


def local_gate(address: str = MAC) -> GateProvider:
    return GateProvider(
        "ollama",
        "openai",
        "ollama.backtide.internal",
        new_fake_key("ollama"),
        None,  # type: ignore[arg-type]
        models=("m",),
        local=True,
        upstream=(address, 11434),
    )


def test_where_it_is_is_recorded_once_and_again_when_it_moves(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.jail.agent_subnets = lambda: ["172.18.0.0/16"]  # type: ignore[attr-defined]
    world.egress._policy = Policy(allow_hosts=(), providers=Providers([local_gate()]))
    world.egress.start(world.hooks)
    details, risk = world.only("provider_local")
    assert (
        details
        == {"provider": "ollama", "name": "ollama.backtide.internal", "address": MAC, "port": 11434}
        and risk == 0
    )
    same = Policy(allow_hosts=(), providers=Providers([local_gate()]))
    world.egress.reload(same)
    assert world.actions().count("provider_local") == 1
    assert "provider_local_changed" not in world.actions()
    world.egress.reload(Policy(allow_hosts=(), providers=Providers([local_gate("192.168.5.9")])))
    details, risk = world.only("provider_local_changed")
    assert details["address"] == "192.168.5.9" and details["before"] == f"{MAC}:11434"
    assert details["applied"] is True and risk == 1


def test_a_move_a_reload_did_not_apply_is_recorded_at_risk_2_and_alerted(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.jail.agent_subnets = lambda: ["172.18.0.0/16"]  # type: ignore[attr-defined]
    world.egress._policy = Policy(allow_hosts=(), providers=Providers([local_gate()]))
    world.egress.start(world.hooks)
    moved = Policy(
        allow_hosts=(),
        providers=Providers([local_gate()]),
        local_moved={"ollama": ("192.168.5.9", 11434)},
    )
    world.egress.reload(moved)
    world.egress.reload(moved)  # the same move again: recorded once
    details, risk = world.only("provider_local_changed")
    assert details == {
        "provider": "ollama",
        "name": "ollama.backtide.internal",
        "address": "192.168.5.9",
        "port": 11434,
        "before": f"{MAC}:11434",
        "applied": False,
    }
    assert risk == 2
    assert [title for _, title in world.alerts if "ollama" in title]
    world.egress.reload(Policy(allow_hosts=(), providers=Providers([local_gate()])))
    world.egress.reload(moved)  # it moved away and back: said again
    assert world.actions().count("provider_local_changed") == 2


def test_a_reload_never_puts_a_local_provider_on_the_agents_network(tmp_path: Path) -> None:
    """L2 of the review: the subnets the Egress read at the start are checked again at each
    reload; a policy that fails is not taken."""
    world = World(tmp_path)
    world.jail.agent_subnets = lambda: ["172.18.0.0/16"]  # type: ignore[attr-defined]
    world.egress._policy = Policy(allow_hosts=(), providers=Providers([local_gate()]))
    world.egress.start(world.hooks)
    inside = Policy(allow_hosts=(), providers=Providers([local_gate("172.18.0.3")]))
    assert world.egress.reload(inside) is False
    assert world.egress.policy.providers.by_name("ollama").upstream == (MAC, 11434)
    details, risk = world.only("proxy_reconfigured")
    assert details["now"] is False and "agent's own network" in details["error"] and risk == 2


def test_the_proxy_does_not_start_with_a_local_provider_on_the_agents_network(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    world.jail.agent_subnets = lambda: ["192.168.5.0/24"]  # type: ignore[attr-defined]
    world.egress._policy = Policy(allow_hosts=(), providers=Providers([local_gate()]))
    assert world.egress.start(world.hooks) is False
    details, risk = world.only("proxy_start_failed")
    assert details["step"] == "local_provider" and risk == 2
    assert "proxy.start" not in world.log


def test_without_local_providers_the_subnets_are_not_even_asked(tmp_path: Path) -> None:
    world = World(tmp_path)

    def never() -> list[str]:
        raise JailError("not asked")

    world.jail.agent_subnets = never  # type: ignore[attr-defined]
    assert world.egress.start(world.hooks) is True


# --- the price: 0, by backtide's own reading (6.5) -----------------------------------------------


@pytest.fixture
def box(tmp_path: Path) -> BlackBox:
    with BlackBox(tmp_path / "bb.db", KEY, checkpoint_path=tmp_path / "bb.checkpoint") as opened:
        yield opened


def budget_for(tmp_path: Path, box: BlackBox, **settings: Any) -> Budget:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    options = {
        "daily_usd": Decimal("0.01"),
        "monthly_usd": Decimal("100"),
        "owner_prices": {"m": price("100", "100", "10")},
    } | settings
    budget = Budget(
        BudgetSettings(**options),
        state_dir=state,
        record=box.append,
        history=box.events,
        now=lambda: datetime(2026, 10, 22, 12, tzinfo=UTC),
    )
    budget.open()
    return budget


def both_policy() -> Policy:
    real = "sk-ant-api03-" + "LocalTestReal0Key" * 3
    providers = Providers(
        [
            GateProvider(
                "anthropic",
                "anthropic",
                "api.anthropic.com",  # type: ignore[arg-type]
                new_fake_key("anthropic"),
                Secret(real),
                models=("m",),
            ),
            local_gate(),
        ]
    )
    return Policy(allow_hosts=(), providers=providers, unknown_hosts="deny")


def llm_request(
    flow_id: str, *, host: str = "ollama.backtide.internal", provider: str = "ollama"
) -> dict[str, Any]:
    flow = {
        "flow_id": flow_id,
        "method": "POST",
        "scheme": "https",
        "host": host,
        "port": 443,
        "path": "/v1/chat/completions",
        "headers": [],
        "body": json.dumps({"model": "m", "max_tokens": 10, "messages": []}).encode(),
    }
    upstream = (MAC, 11434) if provider == "ollama" else None
    return record.llm_request_event(flow, provider, (), endpoint="chat", upstream=upstream)


def llm_response(flow_id: str, provider: str = "ollama", usage: dict | None = None) -> dict:
    summary = LlmSummary(model="m", usage=dict(usage or {}), complete=True)
    flow = {
        "flow_id": flow_id,
        "scheme": "https",
        "host": "ollama.backtide.internal",
        "port": 443,
        "path": "/v1/chat/completions",
    }
    return record.llm_response_event(
        flow,
        provider,
        {"status": 200, "size": 10, "duration_ms": 5},
        summary,
        (),
        local=provider == "ollama",
    )


def ask(channel: Any, proxy: Proxy, request_id: int, event: dict[str, Any]) -> dict[str, Any]:
    channel.handle({"type": "request", "id": request_id, "event": event})
    return proxy.receive_type("ack")


def test_a_local_call_costs_nothing_and_no_cap_stops_it(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box)
    channel, proxy = make_channel(box, budget=budget, policy=both_policy())
    for n in range(1, 8):  # the paid ones reach the cap of 0.01 $
        ack = ask(
            channel, proxy, n, llm_request(f"p{n}", host="api.anthropic.com", provider="anthropic")
        )
        if ack["verdict"] != "allow":
            break
        channel.handle(
            {
                "type": "event",
                "event": llm_response(f"p{n}", "anthropic", {"input": 50, "output": 50}),
            }
        )
    assert budget.blocked_window() == "day"
    for n in range(1, 4):  # the local model still works, and costs 0
        assert ask(channel, proxy, 100 + n, llm_request(f"l{n}"))["verdict"] == "allow"
        channel.handle({"type": "event", "event": llm_response(f"l{n}", usage=None)})
    local_costs = [
        e.details["cost"]
        for e in box.events()
        if e.action == "response" and e.details.get("provider") == "ollama"
    ]
    assert (
        local_costs
        == [{"usd_micro": 0, "estimated": False, "unknown_model": False, "priced_by": "local"}] * 3
    )
    requests = [e for e in box.events() if e.action == "request" and e.details.get("local")]
    assert len(requests) == 3 and all(e.details["key"] == "none" for e in requests)


def test_local_calls_have_their_own_places_in_flight(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(
        tmp_path, box, daily_usd=Decimal("100"), max_inflight=1, max_inflight_local=2
    )
    channel, proxy = make_channel(box, budget=budget, policy=both_policy())
    acks = [ask(channel, proxy, n, llm_request(f"l{n}"))["verdict"] for n in range(1, 4)]
    assert acks == ["allow", "allow", "deny"]
    assert budget.in_flight() == (0, 2)
    # The paid one is not left without room by the local ones.
    paid = llm_request("p1", host="api.anthropic.com", provider="anthropic")
    assert ask(channel, proxy, 10, paid)["verdict"] == "allow"
    assert budget.status()["reserved_micro"] > 0  # the paid one reserves; the local ones never
    # An error ends a local call for free (no system/budget_charged) and gives back its place.
    error = record.error_event(
        "flow", flow_id="l1", host="ollama.backtide.internal", port=443, secrets=(), upstream=True
    )
    channel.handle({"type": "event", "event": error})
    assert "budget_charged" not in [e.action for e in box.events()]
    assert ask(channel, proxy, 11, llm_request("l4"))["verdict"] == "allow"


def test_only_backtides_config_makes_a_call_local(tmp_path: Path, box: BlackBox) -> None:
    """The proxy's word is not enough: a call it says is local but goes to a paid provider's host
    is admitted, reserved and charged as that provider's."""
    budget = budget_for(tmp_path, box, daily_usd=Decimal("100"))
    channel, proxy = make_channel(box, budget=budget, policy=both_policy())
    lying = llm_request("x1", host="api.anthropic.com", provider="anthropic")
    lying["details"] |= {"local": True, "upstream": f"{MAC}:11434", "key": "none"}
    assert ask(channel, proxy, 1, lying)["verdict"] == "allow"
    assert budget.in_flight() == (1, 0)
    channel.handle(
        {"type": "event", "event": llm_response("x1", "anthropic", {"input": 10, "output": 10})}
    )
    [cost] = [e.details["cost"] for e in box.events() if e.action == "response"]
    assert cost["priced_by"] == "owner" and cost["usd_micro"] == 2000


def test_a_paid_call_answered_as_local_is_still_charged(tmp_path: Path, box: BlackBox) -> None:
    budget = budget_for(tmp_path, box, daily_usd=Decimal("100"))
    assert budget.admit("p", model="m", request_bytes=10, max_tokens=10) is None
    cost = budget.settle("anthropic", {"flow_id": "p", "model": "m"}, local=True)
    assert cost.micro > 0 and cost.priced_by == "estimate"


# --- Ollama's cloud API: priced by the owner, its key in the Settings page ------------------------

CLOUD = '[[proxy.providers]]\nname = "ollama-cloud"\nkind = "openai"\nhost = "ollama.com"\n'


def test_a_subdomain_of_ollama_com_is_ollamas_cloud_too(layout: Path) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match="missing gpt-oss:120b"):
        config_with(
            layout,
            '[[proxy.providers]]\nname = "ollama-cloud"\nkind = "openai"\n'
            'host = "api.ollama.com"\nmodels = ["gpt-oss:120b"]\n',
        )


def test_ollamas_cloud_needs_the_owners_prices(layout: Path) -> None:  # noqa: F811
    with pytest.raises(ConfigError):
        config_with(layout, CLOUD)  # no models: OpenClaw's own check says it first
    with pytest.raises(ConfigError, match="missing gpt-oss:120b"):
        config_with(layout, CLOUD + 'models = ["gpt-oss:120b"]\n')
    priced = '[budget.prices."gpt-oss:120b"]\ninput = 0.5\noutput = 2\n'
    config = config_with(layout, CLOUD + 'models = ["gpt-oss:120b"]\n', priced)
    [gate] = config.model_providers().items
    assert gate.host == "ollama.com" and gate.exact_paths and not gate.local
    assert gate.waiting  # until its key is set in the Settings page


def test_the_settings_page_takes_an_ollama_key() -> None:
    assert check_value("ollama-cloud", "0123456789abcdef0123456789abcdef.AbCdEfGh_ij-kl")
    for bad in (
        "short",
        "with a space " + "x" * 30,
        "x" * 241,
        "sk-ant-api03-" + "x" * 30,
        new_fake_key("ollama-cloud"),
        "ümlaut" + "x" * 30,
    ):
        assert not check_value("ollama-cloud", bad)


# --- decision 9: a refusal of risk 2 toward a local provider is told (T20-5) ---------------------


class Notices:
    """The channel's side of ``LocalRefusals``: what it was handed."""

    def __init__(self) -> None:
        self.noted: list[tuple[Any, str]] = []
        self.due = 0

    def note(self, event: Any, provider: str) -> None:
        self.noted.append((event, provider))

    def send_due(self) -> None:
        self.due += 1


def refused(
    reason: str, path: str, *, host: str = "ollama.backtide.internal", local: bool = True,
    method: str = "GET",
) -> dict[str, Any]:  # fmt: skip
    flow = {"flow_id": "b1", "method": method, "scheme": "https", "host": host, "port": 443,
            "path": path, "headers": []}  # fmt: skip
    return record.blocked_event(reason, flow, (), local=local)


def test_a_refusal_of_risk_2_toward_a_local_provider_is_told(box: BlackBox) -> None:
    notices = Notices()
    channel, _ = make_channel(box, policy=both_policy(), local_refusals=notices)
    for event in (
        refused("provider_endpoint", "/api/tags"),
        refused("provider_endpoint", "/api/pull", method="POST"),  # risk 3: the RiskResponder's
        # The proxy's word alone is not enough: not a local provider's host by backtide's config.
        refused("foreign_credential", "/v1/messages", host="api.anthropic.com"),
        # And backtide's config is: a Host that does not match, toward the virtual name.
        refused("host_mismatch", "/v1/chat/completions", local=False),
        refused("port", "/v1/chat/completions"),  # risk 1: no notice
    ):
        channel.handle({"type": "event", "event": event})
    told = [(e.details["reason"], e.details["path"], e.risk, name) for e, name in notices.noted]
    assert told == [
        ("provider_endpoint", "/api/tags", 2, "ollama"),
        ("host_mismatch", "/v1/chat/completions", 2, "ollama"),
    ]
    assert all(e.seq > 0 for e, _ in notices.noted)  # recorded first, then told


def test_with_the_spending_cap_the_refusals_are_told_too(tmp_path: Path, box: BlackBox) -> None:
    notices = Notices()
    budget = budget_for(tmp_path, box, daily_usd=Decimal("100"))
    channel, _ = make_channel(box, budget=budget, policy=both_policy(), local_refusals=notices)
    channel.handle(
        {"type": "event", "event": refused("provider_side_tool", "/v1/chat/completions")}
    )
    assert [e.details["reason"] for e, _ in notices.noted] == ["provider_side_tool"]


def test_the_channels_tick_sends_what_is_due(box: BlackBox) -> None:
    notices = Notices()
    channel, _ = make_channel(box, policy=both_policy(), local_refusals=notices)
    channel.tick()
    assert notices.due == 1


def test_the_egress_tells_through_the_guardians_door_and_never_loses_a_count(
    tmp_path: Path, box: BlackBox
) -> None:
    world = World(tmp_path)
    assert world.egress.start(world.hooks)
    notices = world.egress.local_refusals
    first = box.append("net", "blocked", "x", details={"reason": "provider_endpoint"}, risk=2)
    second = box.append("net", "blocked", "y", details={"reason": "provider_endpoint"}, risk=2)

    def told() -> list[str]:
        return [title for _, title in world.alerts if "modelo local" in title]

    notices.note(first, "ollama")
    notices.note(second, "ollama")
    assert len(told()) == 1  # the second waits for its 10 minutes
    world.now[0] += 600
    world.egress.check()  # the proxy's watch sends it, even with no channel ticking
    assert len(told()) == 2
    notices.note(first, "ollama")
    world.egress.stop()  # and the stop sends what is still held
    assert len(told()) == 3


@pytest.mark.parametrize(
    ("reason", "method"),
    [("host_mismatch", "POST"), ("too_large", "POST"), ("provider_endpoint", "DELETE")],
)
def test_an_admin_route_toward_a_local_provider_is_risk_3_whatever_the_reason(
    box: BlackBox, reason: str, method: str
) -> None:
    """B1 of the review of T20-5: the proxy marks ``local`` only in its provider branch, so a
    ``Host: x.example`` (host_mismatch) or a huge body (too_large) on /api/pull stayed at 2 or 1.
    backtide raises it by its own config: the host is a local provider's virtual name."""
    notices = Notices()
    channel, _ = make_channel(box, policy=both_policy(), local_refusals=notices)
    event = refused(reason, "/v1/../api/pull", local=False, method=method)
    channel.handle({"type": "event", "event": event})
    [stored] = [e for e in box.events() if e.action == "blocked"]
    assert stored.risk == 3 and stored.details["reason"] == reason
    assert notices.noted == []  # risk 3 is the RiskResponder's


def test_an_admin_path_toward_another_host_keeps_its_risk(box: BlackBox) -> None:
    channel, _ = make_channel(box, policy=both_policy())
    event = refused("host_mismatch", "/api/pull", host="api.anthropic.com", local=False)
    channel.handle({"type": "event", "event": event})
    [stored] = [e for e in box.events() if e.action == "blocked"]
    assert stored.risk == 2
