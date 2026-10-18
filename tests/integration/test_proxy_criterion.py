"""T06's done-when, in the VM (docs/21, "En la VM"): leaving without the proxy fails, and no API
key ends up in the black box.

The real service (`backtide vigilar`, tests/integration/service_main.py) watches the real
OpenClaw with two model providers in ``[proxy]``, a fake Anthropic and a fake OpenAI-compatible
one on the fake internet (tests/integration/internet_kit.py). Their "real" keys are made up by
this module and written to ``<state_dir>/keys/<name>.key`` as an installation would; backtide makes
the fake ones. A full ``openclaw agent --message`` turn against each:

- the fake provider receives the REAL key (swapped by the proxy), never the fake one;
- afterwards no spelling of a real key (as is, lower case, URL-encoded, base64) is anywhere:
  black box and its WAL and checkpoint, the service's log, the proxy's and the agent's docker
  logs and inspect, the agent's volume and its snapshots, its config and its environment;
- the black box has ``llm/request`` (``key: swapped``) and ``llm/response`` with its usage, and
  ``verify()`` is ok;
- without the proxy (straight to the fake internet's address, or with the proxy variables
  emptied) the agent reaches nothing.

And T06-1's open question: does a command OpenClaw's ``exec`` runs inherit the Gateway token?

Nothing here reaches a real provider and no real key exists (invariant 8).
"""

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from backtide.gate.providers import new_fake_key
from backtide.jail import docker as jail_docker
from backtide.jail.config import openclaw_config
from backtide.jail.openclaw import ModelProvider, check_rewindable
from tests.integration.conftest import _new_service
from tests.integration.internet_kit import (
    ANTHROPIC,
    ANTHROPIC_HOST,
    OPENAI,
    OPENAI_HOST,
    OPENAI_MODEL,
    PLAIN_HOST,
    REPLY_TEXT,
    FakeInternet,
    leaks,
    made_up_key,
    provider_toml,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import Service, wait_until
from tests.integration.test_jail import _validate_copy

pytestmark = pytest.mark.integration

TURN_TIMEOUT = 300.0
EXEC_ENV_FILE = "t06-exec-env.txt"


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    real: dict[str, str]  # provider -> the made-up real key

    @property
    def fake(self) -> dict[str, str]:
        return {name: key.fake for name, key in self.service.config.provider_keys.items()}


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    real = {ANTHROPIC: made_up_key("anthropic"), OPENAI: made_up_key("openai")}
    service = _new_service(
        btrfs_volume,
        tmp_path_factory,
        proxy_toml=f'allow_hosts = ["{PLAIN_HOST}"]\n' + provider_toml(),
        real_keys=real,
        # The Gateway takes 1.4 GiB, and a CLI turn in the same container that runs a command
        # with exec went over 2 GiB (OOM-killed in the VM): room for the turns of this test.
        agent_memory="3g",
    )
    internet: FakeInternet | None = None
    try:
        internet = start_fake_internet(service, tmp_path_factory.mktemp("t06-5-internet"))
        service.main_args = internet.service_args()
        service.start()
        service.wait_ready()
        yield Lab(service, internet, real)
    finally:
        stop_with_internet(service, internet)


def turn(lab: Lab, message: str, *, model: str | None = None) -> str:
    """One ``openclaw agent --agent main --message`` turn through the Gateway, as the agent's
    user; returns what it printed."""
    argv = ["node", "openclaw.mjs", "agent", "--agent", "main", "--message", message, "--json"]
    if model is not None:
        argv += ["--model", model]
    done = lab.service.jail.exec(argv, timeout=TURN_TIMEOUT)
    text = jail_docker.sanitize(done.stdout + done.stderr)
    if done.returncode != 0:
        name = lab.service.jail.config.name
        state = jail_docker.run(["inspect", "--format", "{{json .State}}", name], check=False)
        stats = jail_docker.run(["stats", "--no-stream", name], check=False)
        pytest.fail(
            f"the turn exited {done.returncode}: {text[-3000:]}\nstate: {state.stdout}\n"
            f"{stats.stdout}\nagent log: {lab.service.jail.log_tail()}\n"
            f"{lab.service.diagnosis()}"
        )
    assert REPLY_TEXT in done.stdout, text[-3000:]
    return done.stdout


def llm_events(lab: Lab, action: str, provider: str) -> list:
    return [e for e in lab.service.events(action, "llm") if e.details.get("provider") == provider]


# --- the fake key, end to end ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "host", "model"),
    [(ANTHROPIC, ANTHROPIC_HOST, None), (OPENAI, OPENAI_HOST, f"{OPENAI}/{OPENAI_MODEL}")],
    ids=["anthropic", "openai"],
)
def test_a_turn_reaches_the_provider_with_the_real_key(
    lab: Lab, provider: str, host: str, model: str | None
) -> None:
    before = len(lab.internet.requests(host))
    responses_before = len(llm_events(lab, "response", provider))
    turn(lab, "Say the test phrase.", model=model)
    calls = lab.internet.requests(host)[before:]
    assert calls, "the fake provider saw no request"
    for call in calls:
        assert call["method"] == "POST" and call["sni"] == host
        headers = call["headers"]
        if provider == ANTHROPIC:
            assert call["path"] == "/v1/messages"
            assert headers.get("x-api-key") == lab.real[provider]
            assert "authorization" not in headers
        else:
            assert call["path"] == "/v1/chat/completions"
            assert headers.get("authorization") == f"Bearer {lab.real[provider]}"
            assert "x-api-key" not in headers
        assert lab.fake[provider] not in json.dumps(headers)
    # Recorded: the request (before it went out, T06-4) and the answer with its usage.
    requests = llm_events(lab, "request", provider)
    assert requests and all(e.details["key"] == "swapped" for e in requests)
    wait_until(
        lambda: len(llm_events(lab, "response", provider)) > responses_before,
        30,
        "the llm/response",
        context=lambda: (
            f"errors: {[e.details for e in lab.service.events('error')][-3:]}\n"
            + lab.service.diagnosis()
        ),
    )
    answer = llm_events(lab, "response", provider)[-1]
    assert answer.details["status"] == 200
    if provider == ANTHROPIC:
        assert answer.details.get("usage"), answer.details
    else:
        # OpenAI streams its usage only if asked (stream_options.include_usage): T11 decides
        # whether the proxy asks. Until then the answer says it is missing (docs/21, section 8).
        assert answer.details.get("usage") or answer.details.get("usage_missing"), answer.details


def test_the_agent_only_ever_has_the_fake_keys(lab: Lab) -> None:
    claw = json.loads(lab.service.config.jail_config().config_file.read_text())
    providers = claw["models"]["providers"]
    assert {name: entry["apiKey"] for name, entry in providers.items()} == lab.fake
    environment = lab.service.jail.exec(["env"]).stdout
    assert not [line for line in environment.splitlines() if "KEY" in line.split("=", 1)[0]]
    for fake in lab.fake.values():
        assert fake not in environment


def test_openclaw_accepts_its_own_providers_without_a_model_list(lab: Lab) -> None:
    """In production the providers are usually OpenClaw's own (anthropic, openai), with no
    ``models`` (its catalog has them): that config must validate in the real OpenClaw too."""
    providers = (
        ModelProvider("anthropic", "anthropic", "api.anthropic.com", new_fake_key("anthropic")),
        ModelProvider("openai", "openai", "api.openai.com", new_fake_key("openai")),
    )
    config = openclaw_config(replace(lab.service.jail.config, model_providers=providers))
    check_rewindable(config)
    validated = _validate_copy(lab.service.jail, config)
    assert validated.returncode == 0, validated.stdout + validated.stderr


def test_no_real_key_is_anywhere(lab: Lab) -> None:
    """After the turns: not in the black box, the logs, the agent's volume, its snapshots, its
    config or its environment. The fake keys are struck from the black box too."""
    assert llm_events(lab, "response", ANTHROPIC), "the turns ran first"
    assert leaks(lab.service, list(lab.real.values())) == []
    in_the_box = [
        str(path)
        for path in (lab.service.config.blackbox_db, lab.service.config.blackbox_checkpoint)
        if path.exists() and any(fake.encode() in path.read_bytes() for fake in lab.fake.values())
    ]
    assert in_the_box == []
    report = lab.service.box.verify()
    assert report.ok, report.problems


def test_the_service_never_logged_a_key(lab: Lab) -> None:
    log = lab.service.log_text()
    for key in (*lab.real.values(), *lab.fake.values()):
        assert key not in log


# --- leaving without the proxy fails ---------------------------------------------------------

CONNECT = (
    "import socket, sys\n"
    "try:\n"
    "    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5).close()\n"
    "    print('connected')\n"
    "except OSError as error:\n"
    "    print(type(error).__name__)\n"
)


def test_without_the_proxy_the_agent_reaches_nothing(lab: Lab) -> None:
    accepts = lab.internet.accepts()
    for port in ("443", "8443", "9000"):
        outcome = lab.service.jail.exec(["python3", "-c", CONNECT, lab.internet.ip, port])
        assert outcome.stdout.strip() != "connected", (port, outcome.stdout)
    no_proxy = ["env", "-u", "HTTPS_PROXY", "-u", "https_proxy", "-u", "HTTP_PROXY"]
    no_proxy += ["-u", "http_proxy", "-u", "OPENCLAW_PROXY_URL"]
    curl = lab.service.jail.exec(
        [*no_proxy, "curl", "-sS", "--max-time", "10", f"https://{PLAIN_HOST}/t06-5-direct"]
    )
    assert curl.returncode != 0
    # Control: through the proxy the same call works.
    through = lab.service.jail.exec(
        ["curl", "-sS", "--max-time", "20", f"https://{PLAIN_HOST}/t06-5-proxied"]
    )
    assert through.returncode == 0, through.stderr
    assert json.loads(through.stdout)["path"] == "/t06-5-proxied"
    assert lab.internet.requests(PLAIN_HOST, "/t06-5-direct") == []
    after = lab.internet.accepts()
    assert after["8443"] == accepts["8443"]  # nothing reached it but the proxy's own call


# --- T06-1's question: what does a command of OpenClaw's exec see? ---------------------------


def test_what_a_command_of_exec_inherits(lab: Lab, record_property) -> None:
    """The fake model asks for ``exec`` of ``env`` into a file of the workspace. Recorded as a
    finding (docs/21 and the backlog), not a pass/fail on OpenClaw: whether the Gateway token is
    in it. What must hold either way: no real key and no ``*KEY*`` variable."""
    target = lab.service.jail.config.agent_dir / "work" / EXEC_ENV_FILE
    command = f"env > /workspace/work/{EXEC_ENV_FILE}"
    turn(lab, f"Run this: T06-EXEC:[[{command}]]")
    wait_until(
        target.exists,
        30,
        "the file exec writes",
        context=lambda: json.dumps(
            [r.get("model_turn") for r in lab.internet.requests(ANTHROPIC_HOST)[-3:]]
        ),
    )
    time.sleep(0.5)
    names = {line.split("=", 1)[0] for line in target.read_text().splitlines() if "=" in line}
    token = lab.service.config.gateway_token.reveal()
    inherits = token in target.read_text()
    finding = (
        f"exec inherits OPENCLAW_GATEWAY_TOKEN: {inherits} "
        f"(variables: {sorted(n for n in names if n.startswith(('OPENCLAW', 'NODE', 'HTTP')))})"
    )
    print(finding)  # noqa: T201 - for docs/21, with -rP
    record_property("exec environment", finding)
    assert not [name for name in names if "KEY" in name.upper()]
    for real in lab.real.values():
        assert real not in target.read_text()
    target.unlink()
