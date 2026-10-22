"""T17a-3 in the VM: a ``custom`` agent profile starts with the whole jail (docs/34, sections 6,
7 and 11).

The custom agent is described in ``[agent]`` of backtide.toml alone: a pinned image, its own
entrypoint and command, a working folder, a variable, the variable that gets the fake model key,
a ready line and probe, and a line of the rewind notice. The image is OpenClaw's pinned one
(already in the VM, with ``sh``, ``python3`` and ``curl`` for the probes), but nothing of
OpenClaw runs: the agent is ``sh -c 'echo ...; exec sleep infinity'`` under the image's tini,
with no openclaw.json and no Gateway token. Around it, the same jail as for any agent: the
agent's ids, no capabilities, backtide's seccomp, the read-only root, the internal network with
the proxy as its only way out, the process sensor, the snapshots and the mount check of every
cycle (a container recreated with one more ``-v`` is killed).
"""

import json
import os
import secrets
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.gate.providers import is_fake_key
from backtide.jail import IMAGE
from backtide.jail import docker as jail_docker
from backtide.jail.config import CONTAINER_CA_FILE, PROXY_URL, create_env, docker_create_argv
from backtide.jail.mounts import agent_policy, exposure_problems
from backtide.jail.profiles.custom import UNKNOWN_AGENT_NOTICE
from backtide.jail.profiles.openclaw import TOKEN_ENV
from backtide.jail.verify import container_problems
from tests.integration import sensor_kit
from tests.integration.service_kit import (
    REWIND_WITHIN,
    Service,
    snapshot_holds,
    wait_until,
    write_in_agent,
)

pytestmark = pytest.mark.integration

READY_LINE = "t17a3-custom-agent ready"
NOTICE = "Prueba de T17a-3: un agente que backtide no conoce."
# The [agent] of a custom agent, after the container's options make_service writes.
AGENT_TOML = f"""profile = "custom"
image = "{IMAGE}"
entrypoint = ["tini", "-s", "--"]
command = ["sh", "-c", "echo {READY_LINE}; exec sleep infinity"]
workdir = "work"
env = {{ T17A3_AGENT_MODE = "custom", XDG_CONFIG_HOME = "/workspace/home/.config" }}
[agent.model]
provider = "anthropic"
key_env = "ANTHROPIC_API_KEY"
allow_params = ["diagnostics"]
[agent.ready]
log_line = "{READY_LINE}"
probe = ["python3", "-c", "import os, sys; sys.exit(0 if os.path.isdir('/workspace/work') else 1)"]
timeout = 120
[agent.rewind]
notice = ["{NOTICE}"]
"""
PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
NO_CAPABILITIES = "0" * 16
KILL_TIMEOUT = 60.0
DIRECT = r"""
import json, socket
outcome = {}
for address in ("192.0.2.1", "1.1.1.1"):
    try:
        socket.create_connection((address, 24226), timeout=3).close()
        outcome[address] = "connected"
    except OSError as error:
        outcome[address] = type(error).__name__
print(json.dumps(outcome))
"""
COPY_PROBE = r"""
import errno, json, os, sys
folder = sys.argv[1]
source = os.open(f"{folder}/a", os.O_RDWR | os.O_CREAT, 0o600)
os.write(source, b"abc")
target = os.open(f"{folder}/b", os.O_RDWR | os.O_CREAT, 0o600)
try:
    os.copy_file_range(source, target, 3, 0, 0)
    print(json.dumps("copied"))
except OSError as error:
    print(json.dumps(errno.errorcode.get(error.errno, str(error.errno))))
"""


def _custom(make_real_service: Callable[..., Service]) -> Service:
    return make_real_service(agent_toml=AGENT_TOML, proxy_toml=PROVIDER)


@pytest.fixture
def sensed_custom(make_real_service: Callable[..., Service]) -> Iterator[Service]:
    with sensor_kit.sensed_service(
        make_real_service, agent_toml=AGENT_TOML, proxy_toml=PROVIDER
    ) as service:
        yield service


def _inspect(name: str) -> dict[str, Any]:
    return json.loads(
        jail_docker.run(["container", "inspect", "--format", "{{json .}}", name]).stdout
    )


def _env(service: Service) -> dict[str, str]:
    entries = service.jail.exec(["env", "-0"], check=True).stdout.split("\0")
    return dict(entry.split("=", 1) for entry in entries if "=" in entry)


def test_a_custom_agent_runs_in_the_whole_jail(sensed_custom: Service) -> None:
    service = sensed_custom
    config = service.config
    assert config.agent_profile.name == "custom"
    assert config.gateway_token is None  # not even read: a custom agent has no Gateway
    service.start()
    service.wait_ready()
    sensor_kit.sensor_started(service)
    jail = service.jail.config
    name = jail.name

    # Started as its profile says, and ready by its line and its probe.
    assert READY_LINE in service.jail.log_tail()
    service.jail.wait_ready(timeout=30)
    info = _inspect(name)
    created, host = info["Config"], info["HostConfig"]
    assert created["Image"] == IMAGE
    assert created["Entrypoint"] == ["tini"]
    assert created["Cmd"] == ["-s", "--", "sh", "-c", f"echo {READY_LINE}; exec sleep infinity"]
    assert created["WorkingDir"] == "/workspace/work"
    # OpenClaw's image has a HEALTHCHECK of its own: it never runs in the jail.
    assert created["Healthcheck"]["Test"] == ["NONE"] and "Health" not in info["State"]

    # The jail, the same as OpenClaw's: verify.py accepts exactly it.
    assert created["User"] == f"{jail.uid}:{jail.gid}"
    assert host["CapDrop"] == ["ALL"] and not host["CapAdd"] and host["Privileged"] is False
    assert host["ReadonlyRootfs"] is True
    assert "no-new-privileges=true" in host["SecurityOpt"]
    (seccomp,) = [opt for opt in host["SecurityOpt"] if opt.startswith("seccomp=")]
    applied = json.loads(seccomp.removeprefix("seccomp="))
    assert applied == json.loads(jail.seccomp_profile.read_text())
    assert not host["PortBindings"] and host["PublishAllPorts"] is False
    assert list(info["NetworkSettings"]["Networks"]) == [jail.network]
    image_env = service.jail._image_env()  # noqa: SLF001 - what start() checked it against
    assert container_problems(jail, info, seccomp_profile=applied, image_env=image_env) == []
    assert exposure_problems(info, agent_policy(jail)) == []  # the mount check of each cycle

    # Inside: not root, no capabilities, a seccomp filter, nothing writable but its own.
    status = dict(
        line.split(":", 1)
        for line in service.jail.exec(["cat", "/proc/self/status"], check=True).stdout.splitlines()
    )
    assert "0" not in status["Uid"].split()
    for capabilities in ("CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert status[capabilities].strip() == NO_CAPABILITIES, capabilities
    assert status["NoNewPrivs"].strip() == "1" and status["Seccomp"].strip() == "2"
    probe = "/var/tmp/x"  # noqa: S108 - inside the container: world-writable in the image
    assert "Read-only file system" in service.jail.exec(["touch", probe]).stderr
    copy = service.jail.exec(["python3", "-c", COPY_PROBE, "/workspace/work"], check=True)
    assert json.loads(copy.stdout) == "EXDEV"  # backtide's seccomp: copy_file_range blocked
    assert service.jail.exec(["test", "-e", "/config/openclaw.json"]).returncode == 1
    assert service.jail.exec(["ls", "-A", "/config"], check=True).stdout == ""

    # Its variables, the jail's around them, the fake key only where it was declared.
    env = _env(service)
    fake = config.provider_keys["anthropic"].fake
    assert env["ANTHROPIC_API_KEY"] == fake and is_fake_key(fake, "anthropic")
    assert [variable for variable, value in env.items() if value == fake] == ["ANTHROPIC_API_KEY"]
    assert TOKEN_ENV not in env
    assert env["T17A3_AGENT_MODE"] == "custom"
    assert env["HOME"] == "/workspace/home" and env["HTTPS_PROXY"] == PROXY_URL
    assert env["SSL_CERT_FILE"] == str(CONTAINER_CA_FILE)
    assert (env["BASH_ENV"], env["CLAUDE_ENV_FILE"]) == ("/dev/null", "/dev/null")
    sourced = service.jail.exec(["bash", "-c", "echo ran"], check=True)
    assert sourced.stdout == "ran\n" and sourced.stderr == ""

    # The only way out is the proxy: directly, nothing; through it, recorded.
    since = sensor_kit.head_seq(service)
    direct = service.jail.exec(["python3", "-c", DIRECT], check=True, timeout=60)
    assert "connected" not in json.loads(direct.stdout).values(), direct.stdout
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "net" and e.target == "192.0.2.1:24226",
        "the sensor's net/connect of the direct attempt",
        since=since,
    )
    marker = f"t17a3-{secrets.token_hex(6)}"
    service.jail.exec(
        ["curl", "-q", "--silent", "--max-time", "20", f"http://example.com/{marker}"],
        timeout=60,
    )
    sensor_kit.wait_event(
        service,
        lambda e: (
            e.source == "net"
            and e.action != "connect"
            and marker in json.dumps([e.target, e.details], default=str)
        ),
        "the proxy's record of the request through it",
        since=since,
    )

    # The sensor sees its commands, by its container.
    service.jail.exec(["sh", "-c", f"true {marker}-exec"], check=True)
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "exec" and f"{marker}-exec" in str(e.details.get("argv", "")),
        "the agent's command in the black box",
        since=since,
    )
    agent_id = service.jail.container_id()
    assert agent_id is not None
    (by_exec,) = sensor_kit.execs_with(service, f"{marker}-exec")
    assert by_exec.details["container"] == agent_id[:12]

    # The snapshots take what it writes.
    count = len(service.snapshots())
    write_in_agent(service, {f"work/{marker}.txt": "v1\n"})
    wait_until(
        lambda: any(
            snapshot_holds(service, snap.id, {f"work/{marker}.txt": "v1\n"})
            for snap in service.snapshots()[count:]
        ),
        REWIND_WITHIN,
        "a snapshot with what the custom agent wrote",
        context=service.diagnosis,
    )

    # The rewind notice says what its profile says.
    assert config.agent_profile.rewind_notice_lines == (UNKNOWN_AGENT_NOTICE, NOTICE)
    assert service.stop() == 0
    assert not service.jail.is_running()
    report = service.box.verify()
    assert report.ok, report.problems


def test_the_mount_check_holds_for_a_custom_agent(
    make_real_service: Callable[..., Service],
) -> None:
    """montar-lo-prohibido (tests/attacks/test_mount_attacks.py) with a custom agent: a config
    folder that resolves into the state folder is refused before anything is made, and the
    container recreated with one more ``-v`` of the state is killed at the next cycle."""
    bad = _custom(make_real_service)
    state = bad.config.state_dir
    alias = state.parent / f"alias-{uuid.uuid4().hex[:8]}"
    alias.symlink_to(state.parent)
    text = bad.config_path.read_text()
    bad.config_path.write_text(
        text.replace("[agent]\n", f'[agent]\nconfig_dir = "{alias / state.name}"\n', 1)
    )
    bad.start()
    assert bad.wait_exit() == 2
    log = bad.log_text()
    assert "holds backtide's state folder" in log and "holds the black box" in log
    assert not bad.jail.exists()

    service = _custom(make_real_service)
    service.start()
    service.wait_ready()
    name = service.jail.config.name
    before = len(service.events("agent_stop"))
    jail_docker.run(["rm", "--force", name])
    argv = docker_create_argv(service.jail.config)
    argv[1:1] = ["--volume", f"{service.config.state_dir}:/mnt/caja:ro"]
    jail_docker.run(argv, env=create_env(service.jail.config))
    jail_docker.run(["start", name])
    wait_until(
        lambda: len(service.events("agent_stop")) > before and not service.jail.is_running(),
        KILL_TIMEOUT,
        "the Guardian to kill the exposed custom agent",
        context=service.diagnosis,
    )
    stops = service.events("agent_stop")[before:]
    exposed = [e for e in stops if e.details.get("reason") == "exposed"]
    assert exposed and exposed[0].risk == 3
    assert any("holds the black box" in p for p in exposed[0].details["problems"])
    time.sleep(1)
    assert not service.jail.is_running()
    assert service.stop() == 0


def test_a_custom_agent_with_an_entrypoint_and_no_command(
    make_real_service: Callable[..., Service], tmp_path: Path
) -> None:
    """Review of the profiles, L7: with ``--entrypoint`` and nothing after the image, Docker
    keeps ``Config.Cmd`` null, not []; verify.py takes both, so the agent starts and is still
    checked as the jail at every cycle. The program must run on its own, with no argument: a
    one-line script copied into OpenClaw's pinned image and committed locally (no download)."""
    script = tmp_path / "wait"
    script.write_text("#!/bin/sh\nexec sleep infinity\n")
    script.chmod(0o755)
    tag = f"backtide-test-bare-{os.getpid()}"
    source = f"{tag}-src"
    jail_docker.run(["create", "--name", source, IMAGE])  # never started
    try:
        jail_docker.run(["cp", str(script), f"{source}:/usr/local/bin/backtide-wait"])
        jail_docker.run(["commit", source, f"{tag}:latest"])
    finally:
        jail_docker.run(["rm", "--force", source])
    try:
        digest = json.loads(
            jail_docker.run(
                ["image", "inspect", "--format", "{{json .Id}}", f"{tag}:latest"]
            ).stdout
        )
        bare = (
            'profile = "custom"\n'
            f'image = "{tag}@{digest}"\n'
            'entrypoint = ["/usr/local/bin/backtide-wait"]\n'
            "[agent.ready]\n"
            "timeout = 60\n"
        )
        service = make_real_service(agent_toml=bare)
        service.start()
        service.wait_ready()
        info = _inspect(service.jail.config.name)
        assert info["Config"]["Entrypoint"] == ["/usr/local/bin/backtide-wait"]
        assert info["Config"]["Cmd"] is None  # what docker keeps: the reason for the fix
        image_env = service.jail._image_env()  # noqa: SLF001 - what start() checked it against
        seccomp = json.loads(service.jail.config.seccomp_profile.read_text())
        problems = container_problems(
            service.jail.config, info, seccomp_profile=seccomp, image_env=image_env
        )
        assert problems == []
        assert service.events("agent_start") and not service.events("agent_start_failed")
        time.sleep(service.config.cycle_interval * 2)  # a cycle or two: nothing stops it
        assert service.jail.is_running() and not service.events("agent_stop")
        assert service.stop() == 0
        service.jail.remove()
    finally:
        jail_docker.run(["image", "rm", "--force", f"{tag}:latest"], check=False)
