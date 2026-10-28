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

And D27 (the "day 3b" of docs/44): the owner talks to OpenClaw with backtide's own `tarea`
(backtide/shell_cli.py), the real CLI through the running service: a turn of its CLI through its
Gateway, recorded first as ``system/agent_shell`` with what was asked, one at a time (a second
one while the first runs is refused), and stopped at its deadline by the Gateway itself: a later
effect of the turn (a tool call the fake model sends after the deadline) never happens, even with
the CLI killed so it cannot ask for an abort. `entrar` is refused for OpenClaw (Claude Code's
only, for now).
"""

import json
import os
import signal
import subprocess
import sys
import time
import uuid
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
from tests.integration.service_kit import REPO, Service, run_cli, wait_until

pytestmark = pytest.mark.integration

LOCAL = "ollama"  # the name an owner would write; OpenClaw takes it for its own Ollama plugin
VIRTUAL = f"{LOCAL}.backtide.internal"
TURN_TIMEOUT = 360.0
LATE_SECONDS = (
    20.0  # how long the fake Ollama holds a T20-LATE call (proxy_fixtures/fake_ollama.py)
)
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


def shell_events(lab: Lab, kind: str) -> list:
    return [e for e in lab.service.events("agent_shell", "system") if e.target == kind]


def test_openclaw_answers_backtide_tarea(openclaw: Lab) -> None:
    """`backtide tarea` with OpenClaw: one turn through its Gateway, the prompt one argument
    whatever it starts with, the answer printed; recorded first. --continue is the same turn:
    there is one conversation."""
    before = len(shell_events(openclaw, "task"))
    for extra in ((), ("--continue",)):
        done = run_cli(openclaw.service, "tarea", *extra, "--", "-rf say the phrase")
        assert done.returncode == 0, (done.stdout[-2000:], done.stderr[-2000:])
        assert done.stdout.strip() == REPLY_TEXT, done.stdout[-2000:]
    events = shell_events(openclaw, "task")[before:]
    assert [e.details["continue"] for e in events] == [False, True]
    assert {(e.details["prompt"], e.details["slash"]) for e in events} == {
        ("-rf say the phrase", False)
    }
    check_calls(openclaw)
    # The prompt is the one OpenClaw got, as it was written, never split or read as an option:
    # its own record of the turn (``finalPromptText``) for the argv `tarea` builds.
    shell = openclaw.service.config.agent_profile.shell
    assert shell is not None
    argv = shell.task_argv("-rf say the phrase; $(id)", seconds=120)
    turn = openclaw.service.jail.exec(argv, timeout=TURN_TIMEOUT, max_output=8 * 1024 * 1024)
    assert turn.returncode == 0, turn.stderr[-2000:]
    assert (
        json.loads(turn.stdout)["result"]["meta"]["finalPromptText"] == "-rf say the phrase; $(id)"
    )


def start_cli(service: Service, command: str, *args: str) -> subprocess.Popen[str]:
    """The real `backtide <command>`, as run_cli runs it, but in the background."""
    return subprocess.Popen(
        [sys.executable, "-m", "tests.integration.cli_main", command, "--config",
         str(service.config_path), *args],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO), "PYTHONUNBUFFERED": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )  # fmt: skip


def last_asked(lab: Lab) -> str:
    """What the fake model saw last (roles and this turn's text), for a failure's message."""
    seen = [
        {"roles": r.get("roles"), "turn": r.get("turn")} for r in lab.ollama.stats()["requests"]
    ]
    return json.dumps(seen[-3:], ensure_ascii=False)


def late_asked(lab: Lab) -> int:
    """How many model calls carried a T20-LATE trigger in their last user message."""
    return sum(1 for r in lab.ollama.stats()["requests"] if r.get("late"))


def exists(lab: Lab, path: str) -> bool:
    return lab.service.jail.exec(["/usr/bin/test", "-e", path]).returncode == 0


def test_openclaw_tarea_goes_one_at_a_time_and_the_late_effect_happens_with_time(
    openclaw: Lab,
) -> None:
    """The positive control of the deadline test below: with time to spare, the fake model's
    late call (after LATE_SECONDS) runs and writes its file. Meanwhile, a second `tarea` is
    refused, since OpenClaw has one conversation: the check finds the task backtide started
    (``pgrep -P 0``: started by docker exec)."""
    tag = uuid.uuid4().hex[:12]
    first = start_cli(openclaw.service, "tarea", "--minutos", "1", f"T20-LATE-{tag} write it")
    try:
        wait_until(
            lambda: openclaw.ollama.slow()["now"] >= 1,
            60,
            "the late call to be held",
            context=lambda: last_asked(openclaw),
        )
        second = run_cli(openclaw.service, "tarea", "say the phrase")
        assert second.returncode == 1, (second.stdout[-2000:], second.stderr[-2000:])
        assert "una sola conversación" in second.stderr, second.stderr[-2000:]
        out, err = first.communicate(timeout=TURN_TIMEOUT)
    finally:
        if first.poll() is None:
            first.kill()
    assert first.returncode == 0, (out[-2000:], err[-2000:])
    assert exists(openclaw, f"/workspace/work/tarde-{tag}"), "the late call never ran"


def test_openclaw_tarea_is_stopped_at_its_deadline_by_the_gateway(openclaw: Lab) -> None:
    """--minutos is the turn's own deadline, and the Gateway enforces it. The fake model holds
    the call LATE_SECONDS (20 s) and then asks the agent to write ``work/tarde-<tag>``; the
    deadline is 12 s, after any turn's start. The CLI inside is killed (SIGKILL) as soon as the
    call is held, so it never asks the Gateway to abort: only the deadline can stop the turn.
    Past the slow call and a margin: no file, no later model call of that turn, and the next
    `tarea` is not refused as busy. (What the agent itself starts and detaches is not a turn:
    snapshots and the gate are for that.) Without --timeout the turn would run on in the
    Gateway and write the file."""
    tag = uuid.uuid4().hex[:12]
    late_before = late_asked(openclaw)
    task = start_cli(openclaw.service, "tarea", "--minutos", "0.2", f"T20-LATE-{tag} write it")
    try:
        wait_until(
            lambda: late_asked(openclaw) > late_before,
            60,
            "the late call to be asked",
            context=lambda: last_asked(openclaw),
        )
        held = time.monotonic()
        killed = openclaw.service.jail.exec(["/usr/bin/pkill", "-KILL", "-f", "openclaw.mjs agent"])
        assert killed.returncode == 0, "the CLI turn was not running to be killed"
        out, err = task.communicate(timeout=60)
    finally:
        if task.poll() is None:
            task.send_signal(signal.SIGKILL)
    assert task.returncode == 1, (out[-2000:], err[-2000:])
    requests = len(openclaw.local_requests())
    time.sleep(max(0.0, held + LATE_SECONDS + 8.0 - time.monotonic()))  # and a margin
    assert not exists(openclaw, f"/workspace/work/tarde-{tag}"), "the turn ran past its deadline"
    assert len(openclaw.local_requests()) == requests, "the turn asked its model again"
    assert late_asked(openclaw) == late_before + 1
    after = run_cli(openclaw.service, "tarea", "say the phrase")
    assert after.returncode == 0, (after.stdout[-2000:], after.stderr[-2000:])
    assert after.stdout.strip() == REPLY_TEXT


def test_openclaw_backtide_entrar_is_refused(openclaw: Lab) -> None:
    """No terminal session for OpenClaw in the preview: an always-on agent fed by Telegram and
    the web could write escape sequences into its terminal UI's tty. Refused before asking the
    service, pointing to `tarea`, the web and Telegram."""
    before = len(shell_events(openclaw, "session"))
    done = run_cli(openclaw.service, "entrar")
    assert done.returncode == 2, (done.stdout[-2000:], done.stderr[-2000:])
    assert "solo para Claude Code" in done.stderr and "backtide tarea" in done.stderr
    assert len(shell_events(openclaw, "session")) == before


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
