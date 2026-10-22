"""T17a-4 in the VM: Claude Code end to end inside backtide (docs/34, section 11).

Done when Claude Code runs inside backtide with recording, rewind, proxy, sensor, space cap and
Telegram. The lab is the real `backtide vigilar` (tests/integration/service_main.py) with
``[agent] profile = "claude-code"`` and the pinned image of T17a-1, the process sensor, T06's
fake internet (tests/integration/proxy_fixtures/fake_internet.py: ``api.anthropic.com`` and
``github.com`` among its names, a fake model that answers ``T17-BASH:[[...]]`` with Claude Code's
own Bash tool, and just enough of git's smart HTTP for a push to send its POST) and the bot
pointed at a fake Bot API on the VM's 127.0.0.1 (tests/telegram_fake.py). The person's side is
the real CLI (tests/integration/cli_main.py): `backtide tarea`, `entrar` (on a pseudo-terminal,
as `script` would give it), `rebobinar`, `importar` and `exportar`.

Only fake keys and made-up ones: nothing reaches Anthropic, GitHub or Telegram (invariant 8).
"""

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from backtide.jail.profiles.claude_code import CLAUDE, REWIND_NOTICE_LINES
from backtide.service.config import ServiceConfig
from backtide.snapshots import btrfs
from tests.integration import sensor_kit
from tests.integration.conftest import (
    QuotaVolume,
    _agent_names,
    _new_service,
    _remove_stale_test_agents,
)
from tests.integration.internet_kit import (
    REPLY_TEXT,
    FakeInternet,
    made_up_key,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import (
    REPO,
    Service,
    exec_in_agent,
    make_service,
    run_cli,
    snapshot_holds,
    wait_until,
)
from tests.integration.test_agent_profile_assumptions import Terminal, wait_for
from tests.telegram_fake import OWNER, TOKEN, FakeBotApi

pytestmark = pytest.mark.integration

AGENT_TOML = 'profile = "claude-code"\n'
PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
LIFE, WAIT = 40.0, 8.0  # a hold's life and wait, in seconds (5 min and 90 s in production)
TIMINGS = ("--hold-timings", f"{LIFE:g},{WAIT:g},60,60")
TASK_TIMEOUT = 300.0
NOTES = "work/notes.txt"


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    bot: FakeBotApi

    @property
    def work(self) -> Path:
        return self.service.store.workspace / "agente" / "work"

    def task(self, prompt: str, *more: str) -> Any:
        return run_cli(self.service, "tarea", *more, prompt, timeout=TASK_TIMEOUT)

    def model_turns(self) -> list[dict[str, Any]]:
        return [
            r["model_turn"]
            for r in self.internet.requests("api.anthropic.com", "/v1/messages")
            if isinstance(r.get("model_turn"), dict)
        ]


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    sensor_kit.remove_stale_sensors()
    service = _new_service(
        btrfs_volume,
        tmp_path_factory,
        agent_toml=AGENT_TOML,
        proxy_toml=PROVIDER,
        real_keys={"anthropic": made_up_key("anthropic")},
    )
    sensor = f"{sensor_kit.SENSOR_PREFIX}{os.getpid()}-{uuid4().hex[:12]}"
    with service.config_path.open("a") as config:
        config.write(f'[sensor]\nname = "{sensor}"\n')
    service.config = ServiceConfig.from_file(service.config_path)
    telegram = service.config.state_dir / "telegram.toml"
    internet: FakeInternet | None = None
    with FakeBotApi(max_poll=5.0) as bot:
        telegram.write_text(f'token = "{TOKEN}"\nchat_id = {OWNER}\napi_base = "{bot.base}"\n')
        telegram.chmod(0o600)
        try:
            internet = start_fake_internet(service, tmp_path_factory.mktemp("t17a4-internet"))
            service.main_args = ("--with-sensor", *internet.service_args(), *TIMINGS)
            service.start()
            service.wait_ready()
            sensor_kit.sensor_started(service)
            wait_until(lambda: bot.polls() >= 1, 60, "the bot to poll", context=service.diagnosis)
            yield Lab(service, internet, bot)
        finally:
            try:
                stop_with_internet(service, internet)
            finally:
                sensor_kit.remove_sensor(sensor)


def write(path: str, word: str) -> str:
    return f"T17-BASH:[[printf '%s\\n' {word} >> /workspace/{path}]] escribe {word}"


def test_claude_code_starts_in_the_jail_ready_by_its_version(lab: Lab) -> None:
    service = lab.service
    assert service.config.agent_profile.name == "claude-code"
    started = service.events("service_start")[-1]
    assert started.details["profile"] == "claude-code"
    assert "param:diagnostics" in started.details["profile_params"]
    version = service.jail.exec([CLAUDE, "--version"], check=True)
    assert version.stdout.strip() == "2.1.306 (Claude Code)"
    settings = service.jail.exec(["cat", "/config/claude.json"], check=True)
    assert json.loads(settings.stdout)["permissions"] == {"deny": ["WebSearch"]}
    env = service.jail.exec(["env"], check=True).stdout
    assert "npm_config_audit=false" in env and "ANTHROPIC_API_KEY=backtide-fake-" in env


def test_a_task_writes_is_recorded_rewound_and_resumed(lab: Lab) -> None:
    service = lab.service
    since = sensor_kit.head_seq(service)
    first = lab.task(write(NOTES, "uno"))
    assert first.returncode == 0, (first.stdout, first.stderr[-2000:])
    assert REPLY_TEXT in first.stdout
    assert (lab.work / "notes.txt").exists(), (first.stdout, lab.model_turns())
    assert (lab.work / "notes.txt").read_text() == "uno\n"

    # Recorded: who asked, Claude Code and its command (the sensor), its model calls (the proxy).
    shells = [e for e in service.events("agent_shell") if e.seq > since]
    assert [e.details["kind"] for e in shells] == ["task"]
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "exec" and "notes.txt" in str(e.details.get("argv", "")),
        "the sensor's record of the Bash command",
        since=since,
    )
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "exec" and "--output-format" in json.dumps(e.details, default=str)
        and "claude" in json.dumps(e.details, default=str),
        "the sensor's record of claude -p",
        since=since,
    )  # fmt: skip
    model = [
        e
        for e in service.box.events(since_seq=since)
        if "api.anthropic.com" in json.dumps([e.target, e.details], default=str)
    ]
    assert model, "no record of the model calls"
    snapshot = wait_until_snapshot(service, {NOTES: "uno\n"})

    second = lab.task(write(NOTES, "dos"), "--continue")
    assert second.returncode == 0, second.stderr[-2000:]
    assert (lab.work / "notes.txt").read_text() == "uno\ndos\n"

    rewound = run_cli(service, "rebobinar", "--si", snapshot)
    assert rewound.returncode == 0, (rewound.stdout, rewound.stderr)
    flat = " ".join(rewound.stdout.split())
    assert all(" ".join(line.split()) in flat for line in REWIND_NOTICE_LINES)
    assert (lab.work / "notes.txt").read_text() == "uno\n"

    before = len(lab.model_turns())
    resumed = lab.task("T17-NOTE:[[hola]] sigue", "--continue")
    assert resumed.returncode == 0, resumed.stderr[-2000:]
    markers = lab.model_turns()[before]["markers"]
    assert "hola" in markers and any(" uno >>" in m for m in markers), markers
    assert not any(" dos >>" in m for m in markers), markers  # the snapshot's conversation


def wait_until_snapshot(service: Service, files: dict[str, str]) -> str:
    found: list[str] = []

    def taken() -> bool:
        found[:] = [s.id for s in service.snapshots() if snapshot_holds(service, s.id, files)]
        return bool(found)

    wait_until(taken, 60, f"a snapshot with {files}", context=service.diagnosis)
    return found[-1]


def test_a_git_push_is_held_and_never_leaves(lab: Lab) -> None:
    service = lab.service
    since = sensor_kit.head_seq(service)
    calls = len(lab.bot.sent())
    script = (
        "cd /workspace/work && rm -rf repo && git init -q repo && cd repo && "
        "git -c user.email=t17@example.com -c user.name=t17 commit -q --allow-empty -m x && "
        "git push https://github.com/example/demo.git HEAD:main; echo push-exit=$?"
    )
    done = lab.task(f"T17-BASH:[[{script}]] haz push")
    assert done.returncode == 0, done.stderr[-2000:]
    held = [
        e
        for e in service.box.events(since_seq=since)
        if e.source == "gate" and e.action == "held" and "git-receive-pack" in json.dumps(
            [e.target, e.details], default=str
        )
    ]  # fmt: skip
    assert held, "the push was not held"
    pushes = lab.internet.requests("github.com")
    assert any("info/refs" in r["path"] for r in pushes)  # the read went out...
    assert not any(r["method"] == "POST" for r in pushes)  # ...the push never did
    wait_until(lambda: len(lab.bot.sent()) > calls, 30, "the notice on Telegram")
    notice = lab.bot.sent()[calls:]
    assert any(str(c.params.get("chat_id")) == str(OWNER) for c in notice)
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "exec" and "git" in str(e.details.get("argv", ""))
        and "push" in str(e.details.get("argv", "")),
        "the sensor's record of git push",
        since=since,
    )  # fmt: skip


DIALOGS = ("Yes,Iaccept", "Yes,Itrustthisfolder", "DoyouwanttousethisAPIkey?")


def test_entrar_opens_claude_code_on_a_terminal(lab: Lab) -> None:
    service = lab.service
    since = sensor_kit.head_seq(service)
    (service.store.workspace / "agente" / "home" / ".claude.json").unlink(missing_ok=True)
    env_argv = [
        "env", f"PYTHONPATH={REPO}", "TERM=xterm-256color", sys.executable, "-m",
        "tests.integration.cli_main", "entrar", "--config", str(service.config_path),
    ]  # fmt: skip
    term = Terminal(env_argv)
    target = lab.work / "entrar.txt"
    target.unlink(missing_ok=True)
    try:
        wait_for(lambda: "bypasspermissionson" in term.squeezed(), 90, "the prompt", term)
        screen = term.squeezed()
        assert not any(dialog in screen for dialog in DIALOGS), term.text()[-2000:]
        term.type(write("work/entrar.txt", "tres"))
        wait_for(lambda: target.exists() and target.read_text() == "tres\n", 90, "tres", term)
        term.type("/exit")
        code = term.process.wait(timeout=60)
    finally:
        term.close()
    assert code == 0, term.text()[-2000:]
    assert "Sesión de Claude Code cerrada. Estás otra vez en tu terminal." in term.text()
    seeded = json.loads((service.store.workspace / "agente" / "home" / ".claude.json").read_text())
    assert seeded["hasCompletedOnboarding"] is True
    assert seeded["projects"]["/workspace/work"]["hasTrustDialogAccepted"] is True
    fake = service.config.provider_keys["anthropic"].fake
    assert fake[-20:] in seeded["customApiKeyResponses"]["approved"]
    kinds = [e.details["kind"] for e in service.events("agent_shell") if e.seq > since]
    assert kinds == ["session"]


def test_importar_and_exportar(lab: Lab, tmp_path: Path) -> None:
    service = lab.service
    source = tmp_path / "proyecto"
    (source / "src").mkdir(parents=True)
    (source / "README.md").write_text("hola\n")
    (source / "src" / "main.py").write_text("print(1)\n")
    (source / "src" / "secreto").symlink_to("/etc/passwd")
    brought = run_cli(service, "importar", str(source))
    assert brought.returncode == 0, (brought.stdout, brought.stderr)
    assert "src/secreto" in brought.stdout
    inside = lab.work / "proyecto"
    assert (inside / "src" / "main.py").read_text() == "print(1)\n"
    assert not os.path.lexists(inside / "src" / "secreto")
    owner = exec_in_agent(service, "stat -c %u /workspace/work/proyecto/README.md").strip()
    assert owner == str(service.jail.config.uid)
    again = run_cli(service, "importar", str(source))
    assert again.returncode == 1 and "--reemplazar" in again.stderr
    replaced = run_cli(service, "importar", "--reemplazar", str(source))
    assert replaced.returncode == 0, replaced.stderr
    imports = [e for e in service.events("agent_shell") if e.details["kind"] == "import"]
    assert imports and imports[-1].details["files"] == 2

    exec_in_agent(service, "ln -sf /etc/hostname /workspace/work/link && mkfifo /workspace/work/p")
    out = tmp_path / "salida"
    taken = run_cli(service, "exportar", str(out))
    assert taken.returncode == 0, (taken.stdout, taken.stderr)
    assert (out / "proyecto" / "README.md").read_text() == "hola\n"
    assert not os.path.lexists(out / "link") and not os.path.lexists(out / "p")
    assert "1 enlaces simbólicos" in taken.stdout
    assert "Lo exportado lo escribió el agente" in taken.stdout  # A1 of the review
    event = service.events("export")[-1]
    assert event.target == str(out) and event.snapshot_id
    twice = run_cli(service, "exportar", str(out))
    assert twice.returncode == 2 and "ya existe" in twice.stderr
    inward = run_cli(service, "exportar", str(service.config.state_dir / "x"))
    assert inward.returncode == 2 and "protege" in inward.stderr


def test_exportar_git_takes_the_commits_out_as_a_bundle(lab: Lab, tmp_path: Path) -> None:
    """A1 of the review: the agent makes the bundle inside the jail and only that file leaves;
    a clone of it on this side has the commits and a config of its own."""
    service = lab.service
    exec_in_agent(
        service,
        "mkdir -p /workspace/work/conbundle && cd /workspace/work/conbundle && git init -q "
        "&& echo hola > README.md && git add README.md "
        "&& git -c user.email=a@example.invalid -c user.name=a commit -qm primero",
    )
    out = tmp_path / "conbundle.bundle"
    taken = run_cli(service, "exportar", "--git", "conbundle", str(out))
    assert taken.returncode == 0, (taken.stdout, taken.stderr)
    assert "Lo exportado lo escribió el agente" in taken.stdout
    assert out.read_bytes().startswith(b"# v")
    event = service.events("export")[-1]
    assert event.details["kind"] == "bundle" and event.details["repo"] == "conbundle"
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    clone = tmp_path / "clon"
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", str(out), str(clone)], env=env, check=True
    )
    log = subprocess.run(
        ["git", "-C", str(clone), "log", "--format=%s"], env=env, check=True,
        capture_output=True, text=True,
    )  # fmt: skip
    assert log.stdout.strip() == "primero"
    left = exec_in_agent(service, "ls -A /workspace/home/.backtide-export").split()
    assert left == []  # tidied up inside; the snapshot keeps it as the record


def test_a_task_past_its_time_is_stopped_inside(lab: Lab) -> None:
    """M4 of the review: the run goes under timeout inside the container, so a task past
    --minutos stops there, with what it launched."""
    service = lab.service
    cut = lab.task("T17-BASH:[[sleep 97531]] espera", "--minutos", "0.25")
    assert cut.returncode == 1 and "se ha cortado" in cut.stderr, (cut.stdout, cut.stderr)
    wait_until(
        lambda: exec_in_agent(service, "pgrep -f 'slee[p] 97531' || true").strip() == "",
        60,
        "the task's command to be gone",
        context=service.diagnosis,
    )


# --- the space cap ------------------------------------------------------------------------------

MIB = 1024**2
CAP = 64 * MIB


def test_the_space_cap_holds_for_claude_code(
    quota_volume: QuotaVolume, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The cap of T03b on Claude Code's workspace: a write past it fails inside the agent."""
    _remove_stale_test_agents()
    root = quota_volume.mnt / f"svc-{uuid4().hex}"
    root.mkdir(mode=0o700)
    service = make_service(
        root,
        tmp_path_factory.mktemp("t17a4-cap"),
        _agent_names(os.getpid()),
        workspace_limit=CAP,
        agent_toml=AGENT_TOML,
        proxy_toml=PROVIDER,
    )
    service.main = "tests.integration.pause_main"
    service.main_args = (str(quota_volume.mnt),)
    try:
        service.start()
        service.wait_ready()
        assert btrfs.qgroup_usage(service.store.workspace).limit == CAP
        full = service.jail.exec(
            ["dd", "if=/dev/zero", "of=/workspace/work/big", "bs=1M", "count=128"], timeout=120
        )
        assert full.returncode != 0 and "quota" in full.stderr.lower(), full.stderr
        assert service.stop() == 0
    finally:
        service.shutdown()
