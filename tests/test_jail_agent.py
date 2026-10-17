"""Unit tests for AgentJail. Docker is faked; the workspace and config folders are real.

The VM tests (tests/integration/test_jail.py) run the same code against the real image."""

import json
import os
import re
import stat
import subprocess
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from backtide.jail import agent as agent_module
from backtide.jail import docker
from backtide.jail.agent import AgentJail
from backtide.jail.config import (
    AgentJailConfig,
    docker_create_argv,
    network_create_argv,
    openclaw_config,
    token_env,
)
from backtide.jail.docker import JailError
from backtide.jail.openclaw import UnrewindableConfig

TOKEN = "u" * 43
STARTED_AT = "2026-10-06T16:44:06.49679418Z"
GOOD_NETWORK = {
    "Driver": "bridge",
    "Internal": True,
    "EnableIPv6": False,
    "Options": {
        "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
        "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
    },
}
running_as_root = pytest.mark.skipif(os.geteuid() == 0, reason="root may chown to anyone")


@dataclass(frozen=True)
class Reply:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: str | None = None  # raise JailError(error), as docker.run does on a timeout


OK = Reply()
NO_CONTAINER = Reply(stderr="Error response from daemon: No such container: x\n", returncode=1)
NO_NETWORK = Reply(stderr="Error response from daemon: network x not found\n", returncode=1)
DAEMON_DOWN = Reply(stderr="Cannot connect to the Docker daemon\n", returncode=1)
READY_LOGS = Reply(stdout="[gateway] starting...\n", stderr="x [gateway] ready\n")
HEALTHY = Reply(stdout='{"ok":true,"status":"live"}')
CONTAINER_INFO = Reply(json.dumps({"Id": "c0ffee", "Config": {}, "HostConfig": {}}))
IMAGE_ENV = Reply(json.dumps(["PATH=/usr/bin:/bin", "NODE_ENV=production"]))
OSC52 = "\x1b]52;c;ZWNobyBoYWNrZWQ=\x07"  # "write this to the clipboard", in a terminal


@dataclass(frozen=True)
class Call:
    args: list[str]
    env: dict[str, str] | None
    timeout: float
    check: bool
    max_output: int


class FakeDocker:
    """Stands in for docker.run. Replies are queued per command prefix (the leading args); the
    last reply of a queue repeats and an unknown command answers OK. Like the real one,
    ``check`` turns a non-zero exit into JailError."""

    def __init__(self) -> None:
        self.calls: list[Call] = []
        self.queues: dict[tuple[str, ...], deque[Reply]] = {}

    def reply(self, *prefix_and_replies: str | Reply) -> None:
        prefix = tuple(p for p in prefix_and_replies if isinstance(p, str))
        replies = [r for r in prefix_and_replies if isinstance(r, Reply)]
        self.queues[prefix] = deque(replies)

    def commands(self) -> list[list[str]]:
        return [call.args for call in self.calls]

    def __call__(
        self,
        args: list[str],
        *,
        timeout: float = docker.DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
        check: bool = True,
        max_output: int = docker.DEFAULT_MAX_OUTPUT,
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        self.calls.append(Call(args, env, timeout, check, max_output))
        reply = self._next(args)
        if reply.error is not None:
            raise JailError(reply.error)
        if check and reply.returncode != 0:
            raise JailError(f"docker {args[0]} failed", returncode=reply.returncode)
        return subprocess.CompletedProcess(args, reply.returncode, reply.stdout, reply.stderr)

    def _next(self, args: list[str]) -> Reply:
        for length in range(len(args), 0, -1):
            queue = self.queues.get(tuple(args[:length]))
            if queue:
                return queue.popleft() if len(queue) > 1 else queue[0]
        return OK


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake = FakeDocker()
    fake.reply("container", "inspect", "--format", "{{json .}}", CONTAINER_INFO)
    fake.reply("image", "inspect", IMAGE_ENV)
    monkeypatch.setattr(docker, "run", fake)
    return fake


@dataclass
class ContainerCheck:
    """Stands in for verify.container_problems: records its inputs, answers ``problems``."""

    problems: list[str]
    calls: list[tuple[dict, object, list[str]]]

    def __call__(
        self, config: AgentJailConfig, info: dict, *, seccomp_profile: object, image_env: list[str]
    ) -> list[str]:
        self.calls.append((info, seccomp_profile, image_env))
        return self.problems


@pytest.fixture(autouse=True)
def container_check(monkeypatch: pytest.MonkeyPatch) -> ContainerCheck:
    """verify.py has its own tests (test_jail_verify.py): here every container passes, unless
    a test says otherwise."""
    check = ContainerCheck(problems=[], calls=[])
    monkeypatch.setattr(agent_module, "container_problems", check)
    return check


@pytest.fixture
def config(tmp_path: Path) -> AgentJailConfig:
    workspace = tmp_path / "root" / "workspace"
    workspace.mkdir(parents=True)
    return AgentJailConfig(
        workspace=workspace,
        config_dir=tmp_path / "agent-config",
        gateway_token=TOKEN,
        name="agent-under-test",
        network="net-under-test",
        uid=os.getuid(),
        gid=os.getgid(),
        ready_timeout=10,
        allow_shared_ids=True,  # without root, the agent's folders can only be this user's
    )


@pytest.fixture
def jail(config: AgentJailConfig) -> AgentJail:
    return AgentJail(config)


@pytest.fixture
def ready_jail(jail: AgentJail, fake_docker: FakeDocker) -> AgentJail:
    """Workspace and config on disk, so create() and start() pass their checks."""
    jail.prepare_workspace()
    jail.write_config()
    return jail


def state(running: bool = True, exit_code: int = 0) -> Reply:
    return Reply(json.dumps({"Running": running, "ExitCode": exit_code, "StartedAt": STARTED_AT}))


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# The network


def test_ensure_network_creates_a_missing_network(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("network", "inspect", NO_NETWORK, Reply(json.dumps(GOOD_NETWORK)))
    jail.ensure_network()
    assert network_create_argv(jail.config) in fake_docker.commands()


def test_ensure_network_reuses_a_safe_network(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("network", "inspect", Reply(json.dumps(GOOD_NETWORK)))
    jail.ensure_network()
    assert [c for c in fake_docker.commands() if c[:2] == ["network", "create"]] == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"Internal": False}, "not --internal"),
        ({"Driver": "macvlan"}, "driver"),
        ({"Options": {}}, "IPv4 gateway is not isolated"),
        (
            {
                "EnableIPv6": True,
                "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            },
            "IPv6 gateway is not isolated",
        ),
    ],
)
def test_ensure_network_refuses_an_unsafe_network(
    jail: AgentJail, fake_docker: FakeDocker, change: dict[str, object], problem: str
) -> None:
    fake_docker.reply("network", "inspect", Reply(json.dumps(GOOD_NETWORK | change)))
    with pytest.raises(JailError, match=problem):
        jail.ensure_network()
    assert [c for c in fake_docker.commands() if c[:2] == ["network", "create"]] == []


def test_ensure_network_accepts_a_network_created_meanwhile(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("network", "inspect", NO_NETWORK, Reply(json.dumps(GOOD_NETWORK)))
    fake_docker.reply("network", "create", Reply(stderr="already exists", returncode=1))
    jail.ensure_network()


def test_ensure_network_raises_when_creation_fails(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("network", "inspect", NO_NETWORK)
    fake_docker.reply("network", "create", DAEMON_DOWN)
    with pytest.raises(JailError, match="network failed"):
        jail.ensure_network()


def test_ensure_network_raises_when_inspect_fails(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("network", "inspect", DAEMON_DOWN)
    with pytest.raises(JailError, match="cannot inspect network"):
        jail.ensure_network()


def test_remove_network_ignores_a_missing_network(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("network", "rm", NO_NETWORK)
    jail.remove_network()
    fake_docker.reply("network", "rm", DAEMON_DOWN)
    with pytest.raises(JailError, match="network rm"):
        jail.remove_network()


# The workspace


def test_prepare_workspace_creates_the_agents_folders(jail: AgentJail) -> None:
    jail.prepare_workspace()
    agent_dir = jail.config.agent_dir
    for path in (agent_dir, agent_dir / "home", agent_dir / "state", agent_dir / "work"):
        assert path.is_dir() and not path.is_symlink()
        assert mode(path) == 0o700
        assert path.stat().st_uid == jail.config.uid
    assert sorted(p.name for p in agent_dir.iterdir()) == ["home", "state", "work"]


def test_prepare_workspace_keeps_what_exists(jail: AgentJail) -> None:
    jail.prepare_workspace()
    note = jail.config.agent_dir / "work" / "note.txt"
    note.write_text("keep me")
    (jail.config.agent_dir / "home").chmod(0o750)
    jail.prepare_workspace()
    assert note.read_text() == "keep me"
    assert mode(jail.config.agent_dir / "home") == 0o750  # the agent's: never changed


def test_prepare_workspace_needs_the_workspace(config: AgentJailConfig) -> None:
    config.workspace.rmdir()
    with pytest.raises(JailError, match="missing"):
        AgentJail(config).prepare_workspace()


@pytest.mark.parametrize("name", ["agente", "agente/home", "agente/state", "agente/work"])
def test_prepare_workspace_never_follows_a_symlink(
    jail: AgentJail, tmp_path: Path, name: str
) -> None:
    target = tmp_path / "host-folder"
    target.mkdir(mode=0o755)
    link = jail.config.workspace / name
    link.parent.mkdir(exist_ok=True)
    link.symlink_to(target)
    with pytest.raises(JailError, match="not a directory"):
        jail.prepare_workspace()
    assert list(target.iterdir()) == []
    assert mode(target) == 0o755


def test_prepare_workspace_refuses_a_file(jail: AgentJail) -> None:
    (jail.config.workspace / "agente").write_text("not a folder")
    with pytest.raises(JailError, match="not a directory"):
        jail.prepare_workspace()


@running_as_root
def test_prepare_workspace_refuses_a_folder_of_another_uid(config: AgentJailConfig) -> None:
    (config.workspace / "agente").mkdir()
    other = AgentJail(AgentJailConfig(**(vars(config) | {"uid": os.getuid() + 1})))
    with pytest.raises(JailError, match=f"not the agent's {os.getuid() + 1}"):
        other.prepare_workspace()


@running_as_root
def test_prepare_workspace_cannot_give_folders_away_without_root(config: AgentJailConfig) -> None:
    other = AgentJail(AgentJailConfig(**(vars(config) | {"uid": os.getuid() + 1})))
    with pytest.raises(JailError, match="must run as root"):
        other.prepare_workspace()


# OpenClaw's config


def test_write_config_writes_the_config_for_the_agent_only(jail: AgentJail) -> None:
    jail.write_config()
    config_dir, config_file = jail.config.config_dir, jail.config.config_file
    assert json.loads(config_file.read_text()) == openclaw_config(jail.config)
    assert mode(config_dir) == 0o750
    assert mode(config_file) == 0o640
    assert config_file.stat().st_gid == jail.config.gid
    assert sorted(p.name for p in config_dir.iterdir()) == ["openclaw.json"]


def test_write_config_replaces_the_file(jail: AgentJail) -> None:
    jail.write_config()
    jail.config.config_file.write_text("{}")
    jail.write_config()
    assert json.loads(jail.config.config_file.read_text()) == openclaw_config(jail.config)


def test_write_config_cleans_up_an_interrupted_write(jail: AgentJail) -> None:
    jail.config.config_dir.mkdir()
    (jail.config.config_dir / ".openclaw.json.tmp").write_text("half")
    jail.write_config()
    assert sorted(p.name for p in jail.config.config_dir.iterdir()) == ["openclaw.json"]


def test_write_config_never_writes_an_unrewindable_config(
    jail: AgentJail, monkeypatch: pytest.MonkeyPatch
) -> None:
    unsafe = openclaw_config(jail.config) | {"channels": {"telegram": {"dmPolicy": "pairing"}}}
    monkeypatch.setattr(agent_module, "openclaw_config", lambda _config: unsafe)
    with pytest.raises(UnrewindableConfig, match="channels.telegram.dmPolicy"):
        jail.write_config()
    assert not jail.config.config_dir.exists()  # refused before touching the disk
    jail.config.config_dir.mkdir()  # and an old config is left as it was
    jail.config.config_file.write_text("old")
    with pytest.raises(UnrewindableConfig):
        jail.write_config()
    assert jail.config.config_file.read_text() == "old"


def test_write_config_refuses_anything_else_in_the_folder(jail: AgentJail) -> None:
    jail.config.config_dir.mkdir()
    (jail.config.config_dir / "blackbox.db").write_text("never mount me")
    with pytest.raises(JailError, match="blackbox.db"):
        jail.write_config()
    assert not jail.config.config_file.exists()


def test_write_config_refuses_a_symlinked_folder(jail: AgentJail, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    jail.config.config_dir.symlink_to(target)
    with pytest.raises(JailError, match="not a directory"):
        jail.write_config()
    assert list(target.iterdir()) == []


@running_as_root
def test_write_config_needs_the_agents_group(config: AgentJailConfig) -> None:
    foreign_gid = max(os.getgroups() + [os.getgid()]) + 1000
    other = AgentJail(AgentJailConfig(**(vars(config) | {"gid": foreign_gid})))
    with pytest.raises(JailError, match=f"group {foreign_gid}"):
        other.write_config()


# Lifecycle


def test_create_passes_the_token_through_the_environment(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    ready_jail.create()
    (call,) = [c for c in fake_docker.calls if c.args[0] == "create"]
    assert call.args == docker_create_argv(ready_jail.config)
    assert call.env == token_env(ready_jail.config)
    assert TOKEN not in " ".join(call.args)


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_need_both_mount_sources(
    jail: AgentJail, fake_docker: FakeDocker, method: str
) -> None:
    with pytest.raises(JailError, match="missing"):
        getattr(jail, method)()
    jail.prepare_workspace()
    with pytest.raises(JailError, match="missing"):
        getattr(jail, method)()
    jail.config.config_dir.mkdir(mode=0o750)
    with pytest.raises(JailError, match="run write_config"):
        getattr(jail, method)()
    assert fake_docker.calls == []


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_refuse_a_symlinked_agent_folder(
    jail: AgentJail, fake_docker: FakeDocker, tmp_path: Path, method: str
) -> None:
    jail.write_config()
    target = tmp_path / "host-folder"
    target.mkdir()
    jail.config.agent_dir.symlink_to(target)
    with pytest.raises(JailError, match="not a directory"):
        getattr(jail, method)()
    assert fake_docker.calls == []


def test_start_stop_and_remove(ready_jail: AgentJail, fake_docker: FakeDocker) -> None:
    ready_jail.start()
    ready_jail.stop()
    ready_jail.remove()
    assert fake_docker.commands() == [
        ["container", "inspect", "--format", "{{json .}}", "agent-under-test"],
        ["image", "inspect", "--format", "{{json .Config.Env}}", ready_jail.config.image],
        ["start", "agent-under-test"],
        ["stop", "--time", "30", "agent-under-test"],
        ["rm", "--force", "agent-under-test"],
    ]
    (stop,) = [call for call in fake_docker.calls if call.args[0] == "stop"]
    assert stop.timeout > ready_jail.config.stop_timeout


# start() only starts the jail it would create (finding: a container left by an older backtide)


def test_start_checks_the_container_against_the_config(
    ready_jail: AgentJail, fake_docker: FakeDocker, container_check: ContainerCheck
) -> None:
    ready_jail.start()
    ((info, seccomp_profile, image_env),) = container_check.calls
    assert info == json.loads(CONTAINER_INFO.stdout)
    assert seccomp_profile == json.loads(ready_jail.config.seccomp_profile.read_text())
    assert image_env == json.loads(IMAGE_ENV.stdout)


def test_start_refuses_a_container_that_is_not_the_jail(
    ready_jail: AgentJail, fake_docker: FakeDocker, container_check: ContainerCheck
) -> None:
    container_check.problems = ["HostConfig.Privileged is set: True"]
    with pytest.raises(JailError, match="not the jail.*Privileged.*docker rm -f agent-under-test"):
        ready_jail.start()
    assert ["start", ready_jail.config.name] not in fake_docker.commands()


def test_start_refuses_a_missing_container(ready_jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{json .}}", NO_CONTAINER)
    with pytest.raises(JailError, match="does not exist"):
        ready_jail.start()
    assert ["start", ready_jail.config.name] not in fake_docker.commands()


@pytest.mark.parametrize("output", ["", "{not json", '{"PATH": "/bin"}', "[1, 2]"])
def test_start_refuses_an_unreadable_image_environment(
    ready_jail: AgentJail, fake_docker: FakeDocker, output: str
) -> None:
    fake_docker.reply("image", "inspect", Reply(output))
    with pytest.raises(JailError, match="unexpected environment for image"):
        ready_jail.start()


def test_start_needs_the_seccomp_profile(
    config: AgentJailConfig, fake_docker: FakeDocker, tmp_path: Path
) -> None:
    jail = AgentJail(replace(config, seccomp_profile=tmp_path / "missing.json"))
    jail.prepare_workspace()
    jail.write_config()
    with pytest.raises(JailError, match="cannot read the seccomp profile"):
        jail.start()


def test_running_and_existing(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("container", "inspect", state(running=True))
    assert jail.exists() and jail.is_running()
    fake_docker.reply("container", "inspect", state(running=False))
    assert jail.exists() and not jail.is_running()
    fake_docker.reply("container", "inspect", NO_CONTAINER)
    assert not jail.exists() and not jail.is_running()
    fake_docker.reply("container", "inspect", DAEMON_DOWN)
    with pytest.raises(JailError, match="cannot inspect container"):
        jail.is_running()


def test_is_paused_reads_the_real_state_of_the_container(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    # A frozen container still has Running = true: only Paused tells the two apart.
    fake_docker.reply("container", "inspect", Reply(json.dumps({"Running": True, "Paused": True})))
    assert jail.is_running() and jail.is_paused()
    fake_docker.reply("container", "inspect", Reply(json.dumps({"Running": True, "Paused": False})))
    assert not jail.is_paused()
    fake_docker.reply("container", "inspect", state(running=False))  # no Paused key at all
    assert not jail.is_paused()
    fake_docker.reply("container", "inspect", NO_CONTAINER)
    assert not jail.is_paused()
    fake_docker.reply("container", "inspect", DAEMON_DOWN)
    with pytest.raises(JailError, match="cannot inspect container"):
        jail.is_paused()


def test_kill_sends_sigkill_without_waiting_for_a_graceful_stop(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    jail.kill()
    assert fake_docker.commands() == [["kill", jail.config.name]]
    assert not any(command[0] == "stop" for command in fake_docker.commands())


@pytest.mark.parametrize(
    "stderr",
    [
        "Error response from daemon: No such container: x",
        "Error response from daemon: Cannot kill container: x: container x is not running",
    ],
)
def test_kill_of_a_missing_or_stopped_container_is_not_an_error(
    jail: AgentJail, fake_docker: FakeDocker, stderr: str
) -> None:
    fake_docker.reply("kill", Reply(stderr=stderr + "\n", returncode=1))
    jail.kill()


def test_kill_failing_for_another_reason_raises(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("kill", DAEMON_DOWN)
    with pytest.raises(JailError, match="docker kill"):
        jail.kill()


# pause and unpause (T04d-2)


def test_pause_freezes_the_container_with_a_short_timeout(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    """Freezing takes milliseconds: a docker CLI that hangs must not hold the freeze for two
    minutes, the Guardian kills the agent instead."""
    jail.pause()
    (call,) = fake_docker.calls
    assert call.args == ["pause", jail.config.name]
    assert call.timeout <= 15


@pytest.mark.parametrize("reply", [DAEMON_DOWN, NO_CONTAINER, Reply(error="timed out")])
def test_pause_that_fails_raises(jail: AgentJail, fake_docker: FakeDocker, reply: Reply) -> None:
    """Every failure of a freeze is an error, also a missing container: the caller decides."""
    fake_docker.reply("pause", reply)
    with pytest.raises(JailError):
        jail.pause()


def test_unpause_thaws_the_container(jail: AgentJail, fake_docker: FakeDocker) -> None:
    jail.unpause()
    assert fake_docker.commands() == [["unpause", jail.config.name]]


def test_unpause_of_a_container_that_is_not_frozen_is_not_an_error(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply(
        "unpause",
        Reply(stderr="Error response from daemon: container x is not paused\n", returncode=1),
    )
    jail.unpause()


def test_unpause_failing_for_another_reason_raises(
    jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("unpause", DAEMON_DOWN)
    with pytest.raises(JailError, match="docker unpause"):
        jail.unpause()


def test_exec_runs_as_the_agent(jail: AgentJail, fake_docker: FakeDocker) -> None:
    jail.exec(["id", "-u"], check=True, timeout=5)
    (call,) = fake_docker.calls
    user = f"{os.getuid()}:{os.getgid()}"
    assert call.args == ["exec", "--user", user, jail.config.name, "id", "-u"]
    assert call.check is True and call.timeout == 5


# Waiting until ready


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    """time.monotonic reads now[0]; time.sleep advances it."""
    now = [0.0]
    monkeypatch.setattr(agent_module.time, "monotonic", lambda: now[0])

    def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(agent_module.time, "sleep", sleep)
    yield now


def test_wait_ready_needs_the_log_line_and_health(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", state())
    fake_docker.reply("logs", OK, READY_LOGS)
    fake_docker.reply("exec", Reply(returncode=7), HEALTHY)
    jail.wait_ready()
    assert ["logs", "--since", STARTED_AT, jail.config.name] in fake_docker.commands()
    health = [c for c in fake_docker.commands() if c[0] == "exec"]
    assert health[-1][-1] == "http://127.0.0.1:18789/healthz"
    assert clock[0] > 0  # it polled


def test_wait_ready_fails_when_the_agent_exits(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", state(running=False, exit_code=1))
    fake_docker.reply("logs", Reply(stdout="Gateway failed to start: lease\n"))
    with pytest.raises(JailError, match="exit code 1.*Gateway failed to start"):
        jail.wait_ready()


def test_wait_ready_fails_when_the_container_is_gone(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", NO_CONTAINER)
    with pytest.raises(JailError, match="does not exist"):
        jail.wait_ready()


def test_wait_ready_times_out(jail: AgentJail, fake_docker: FakeDocker, clock: list[float]) -> None:
    fake_docker.reply("container", "inspect", state())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", Reply(stdout='{"ok":false}'))
    with pytest.raises(JailError, match="not ready after 3 s"):
        jail.wait_ready(3)
    assert 3 <= clock[0] < 4


# quiesce


def stopping() -> tuple[Reply, ...]:
    """What `docker inspect` says around a stop: running on entry, still running (not frozen)
    right before the stop, stopped after it, and running again once started."""
    return state(), state(), state(running=False), state()


def test_quiesce_stops_then_starts_and_waits(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", *stopping())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    with ready_jail.quiesce():
        assert [c[0] for c in fake_docker.commands()] == [
            "container",
            "container",
            "stop",
            "container",
        ]
    lifecycle = [c[0] for c in fake_docker.commands() if c[0] in {"stop", "start", "exec"}]
    assert lifecycle == ["stop", "start", "exec"]


def test_quiesce_starts_the_agent_even_if_the_body_fails(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", *stopping())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    with pytest.raises(RuntimeError, match="swap failed"), ready_jail.quiesce():
        raise RuntimeError("swap failed")
    assert ["start", ready_jail.config.name] in fake_docker.commands()


def test_quiesce_leaves_a_stopped_agent_stopped(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("container", "inspect", state(running=False))
    with ready_jail.quiesce():
        pass
    assert [c[0] for c in fake_docker.commands()] == ["container"]


def test_quiesce_reports_a_failed_restart(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", *stopping())
    fake_docker.reply("start", DAEMON_DOWN)
    with pytest.raises(JailError, match="start failed"), ready_jail.quiesce():
        pass


def test_quiesce_does_not_enter_if_stop_fails(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("container", "inspect", state())
    fake_docker.reply("stop", DAEMON_DOWN)
    entered = False
    with pytest.raises(JailError, match="stop failed"), ready_jail.quiesce():
        entered = True
    assert not entered
    assert ["start", ready_jail.config.name] not in fake_docker.commands()


# quiesce when stopping fails (finding: the agent stayed down after a failed stop)


def test_quiesce_starts_the_agent_again_if_it_stopped_despite_the_error(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    """The CLI timed out, but the daemon did stop the container: restore will not run, so the
    agent goes back to how it was (running), and the error still propagates."""
    fake_docker.reply("container", "inspect", *stopping())
    fake_docker.reply("stop", Reply(error="docker stop timed out after 90 s"))
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    entered = False
    with pytest.raises(JailError, match="timed out"), ready_jail.quiesce():
        entered = True
    assert not entered
    lifecycle = [c[0] for c in fake_docker.commands() if c[0] in {"stop", "start", "exec"}]
    assert lifecycle == ["stop", "start", "exec"]  # started again and waited until ready


def test_quiesce_notes_a_failed_restart_after_a_failed_stop(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", state(), state(), state(running=False))
    fake_docker.reply("stop", Reply(error="docker stop timed out after 90 s"))
    fake_docker.reply("start", DAEMON_DOWN)
    with pytest.raises(JailError, match="stop timed out") as error, ready_jail.quiesce():
        pass
    assert any("failed stop failed too" in note for note in error.value.__notes__)


# quiesce with a frozen agent, and start_if (T04c-1)


def paused_state() -> Reply:
    return Reply(json.dumps({"Running": True, "Paused": True, "StartedAt": STARTED_AT}))


def test_quiesce_kills_a_frozen_agent_and_leaves_it_stopped(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    """`docker stop` would wake a frozen agent to run its SIGTERM handler for up to 30 s: it is
    killed, and someone froze it on purpose, so it is not started again by default."""
    fake_docker.reply("container", "inspect", paused_state(), state(running=False))
    with ready_jail.quiesce():
        assert [c[0] for c in fake_docker.commands()] == ["container", "kill", "container"]
    lifecycle = [c[0] for c in fake_docker.commands() if c[0] in {"stop", "kill", "start"}]
    assert lifecycle == ["kill"]


def test_quiesce_kills_an_agent_frozen_right_before_the_stop(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    """The space thread may freeze the agent at any moment (it never waits for agent_lock):
    the state is read again right before stopping, and a frozen agent is killed instead."""
    fake_docker.reply("container", "inspect", state(), paused_state(), state(running=False))
    with ready_jail.quiesce(start_if=lambda error: False):
        pass
    lifecycle = [c[0] for c in fake_docker.commands() if c[0] in {"stop", "kill", "start"}]
    assert lifecycle == ["kill"]


def test_quiesce_never_enters_while_the_agent_still_runs(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    """`docker stop` returned but Docker still says running: the swap must not happen under
    a running agent (it would keep the old workspace mounted)."""
    fake_docker.reply("container", "inspect", state())  # running, always
    entered = False
    with (
        pytest.raises(JailError, match="still running"),
        ready_jail.quiesce(start_if=lambda error: False),
    ):
        entered = True
    assert not entered


def test_wait_ready_fails_at_once_when_the_agent_is_frozen(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", paused_state())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    with pytest.raises(JailError, match="frozen"):
        jail.wait_ready()
    assert clock[0] == 0  # no polling: a frozen agent will not get ready
    assert not [c for c in fake_docker.commands() if c[0] == "exec"]


def test_quiesce_start_if_decides_whether_to_start_and_sees_the_error(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", *stopping())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    seen: list[BaseException | None] = []

    def refuse(error: BaseException | None) -> bool:
        seen.append(error)
        return False

    with (
        pytest.raises(RuntimeError, match="no space") as raised,
        ready_jail.quiesce(start_if=refuse),
    ):
        raise RuntimeError("no space")
    assert seen == [raised.value]
    assert ["start", ready_jail.config.name] not in fake_docker.commands()

    fake_docker.calls.clear()
    fake_docker.reply("container", "inspect", *stopping())
    with ready_jail.quiesce(start_if=lambda error: seen.append(error) or True):
        pass
    assert seen[-1] is None
    lifecycle = [c[0] for c in fake_docker.commands() if c[0] in {"stop", "start", "exec"}]
    assert lifecycle == ["stop", "start", "exec"]  # started and waited until ready


def test_quiesce_start_if_can_start_an_agent_that_was_stopped_or_frozen(
    ready_jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    """With start_if, the caller (the Guardian) decides: a rewind of an agent frozen for lack
    of space starts it again when everything is green."""
    fake_docker.reply("container", "inspect", paused_state(), state(running=False), state())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    with ready_jail.quiesce(start_if=lambda error: True):
        pass
    lifecycle = [c[0] for c in fake_docker.commands() if c[0] in {"stop", "kill", "start"}]
    assert lifecycle == ["kill", "start"]


def test_quiesce_start_if_also_decides_after_a_failed_stop(
    ready_jail: AgentJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("container", "inspect", state(), state(running=False))
    fake_docker.reply("stop", Reply(error="docker stop timed out after 90 s"))
    seen: list[BaseException | None] = []
    with (
        pytest.raises(JailError, match="timed out"),
        ready_jail.quiesce(start_if=lambda error: seen.append(error) or False),
    ):
        pass
    assert len(seen) == 1 and isinstance(seen[0], JailError)
    assert ["start", ready_jail.config.name] not in fake_docker.commands()


# The agent never shares backtide's ids (finding: the agent ran as the test user)


@pytest.mark.parametrize("method", ["create", "start"])
@pytest.mark.parametrize(
    ("ids", "shared"),
    [
        ({"uid": os.getuid()}, "uid"),
        ({"gid": os.getgid()}, "gid"),
        ({"gid": os.getgroups()[-1] if os.getgroups() else os.getgid()}, "gid"),
    ],
)
def test_create_and_start_refuse_ids_shared_with_backtide(
    config: AgentJailConfig,
    fake_docker: FakeDocker,
    method: str,
    ids: dict[str, int],
    shared: str,
) -> None:
    others = {"uid": os.getuid() + 7919, "gid": max([os.getgid(), *os.getgroups()]) + 7919}
    jail = AgentJail(replace(config, allow_shared_ids=False, **(others | ids)))
    with pytest.raises(JailError, match=f"share {shared}"):
        getattr(jail, method)()
    assert fake_docker.calls == []


def test_the_default_ids_are_the_agents_own(tmp_path: Path) -> None:
    config = AgentJailConfig(
        workspace=tmp_path / "workspace", config_dir=tmp_path / "config", gateway_token=TOKEN
    )
    assert (config.uid, config.gid) == (61000, 61000)
    assert config.allow_shared_ids is False
    assert os.getuid() != 61000  # the check above is meaningful on this machine


# The mounted config folder is checked right before the agent sees it


@pytest.mark.parametrize("method", ["create", "start"])
@pytest.mark.parametrize("stray", ["mitmproxy-ca.pem", ".env", ".openclaw.json.tmp"])
def test_create_and_start_refuse_anything_else_in_the_config_folder(
    ready_jail: AgentJail, fake_docker: FakeDocker, method: str, stray: str
) -> None:
    (ready_jail.config.config_dir / stray).write_text("never mount me")
    with pytest.raises(JailError, match=f"must hold only openclaw.json.*{re.escape(stray)}"):
        getattr(ready_jail, method)()
    assert fake_docker.calls == []


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_refuse_a_subfolder_in_the_config_folder(
    ready_jail: AgentJail, fake_docker: FakeDocker, method: str
) -> None:
    (ready_jail.config.config_dir / "keys").mkdir()
    with pytest.raises(JailError, match="must hold only openclaw.json"):
        getattr(ready_jail, method)()
    assert fake_docker.calls == []


# What comes out of the container is bounded and sanitized


def test_the_health_probe_ignores_the_agents_curlrc_and_is_bounded(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", state())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", HEALTHY)
    jail.wait_ready()
    (probe,) = [call for call in fake_docker.calls if call.args[0] == "exec"]
    curl = probe.args[probe.args.index("curl") :]
    assert curl[1] == "-q"  # first: curl reads no .curlrc from HOME (the agent's folder)
    assert curl[-1] == "http://127.0.0.1:18789/healthz"
    assert probe.max_output <= 64 * 1024
    (logs,) = [call for call in fake_docker.calls if call.args[:2] == ["logs", "--since"]]
    assert logs.max_output <= 1024 * 1024


def test_wait_ready_fails_when_the_health_probe_floods(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", state())
    fake_docker.reply("logs", READY_LOGS)
    fake_docker.reply("exec", Reply(error="docker exec ... printed more than 65536 bytes"))
    with pytest.raises(JailError, match="printed more than"):
        jail.wait_ready()


def test_exec_passes_its_output_limit(jail: AgentJail, fake_docker: FakeDocker) -> None:
    jail.exec(["cat", "/workspace/work/big"])
    jail.exec(["cat", "/workspace/work/big"], max_output=10)
    assert [call.max_output for call in fake_docker.calls] == [1024 * 1024, 10]


def test_log_tail_in_errors_is_sanitized(
    jail: AgentJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", state(running=False, exit_code=1))
    fake_docker.reply("logs", Reply(stdout=f"crashed {OSC52}\x1b[2J\x1b[1A\n"))
    with pytest.raises(JailError) as error:
        jail.wait_ready()
    message = str(error.value)
    assert "\x1b" not in message and "\x07" not in message
    assert "crashed \\x1b]52;c;" in message
    (tail,) = [call for call in fake_docker.calls if call.args[:2] == ["logs", "--tail"]]
    assert tail.max_output <= 1024 * 1024


def test_log_tail_never_raises(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("logs", Reply(error="docker logs printed more than 524288 bytes"))
    assert jail.log_tail() == "(no log tail: docker logs printed more than 524288 bytes)"


def test_log_tail_keeps_the_end_of_long_logs(jail: AgentJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("logs", Reply(stdout="old line\n" * 2000 + "the last line\n"))
    tail = jail.log_tail()
    assert tail.endswith("the last line") and len(tail) <= docker.MESSAGE_LIMIT
