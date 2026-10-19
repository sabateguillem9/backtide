"""T07-3 in the VM: the process sensor in the service, with the real OpenClaw (docs/23, section 7).

T07's criterion: the agent's commands appear in the black box with their container. And T07-3's:
a fallen sensor gives ``sensor_down``, and restarting the service (cleanly or with kill -9)
neither loses nor repeats events. Also, from T07-2's review: the sensor that
``sensor_create_argv`` makes passes ``verify`` against the real daemon.

Every service here runs Tetragon for real (see tests/integration/sensor_kit.py): privileged, in
the dev VM only, stopped and removed when each test ends.
"""

import os
import secrets
import time
from collections import Counter
from collections.abc import Callable, Iterator

import pytest

from backtide.jail import IMAGE
from backtide.jail import docker as jail_docker
from backtide.jail.sensor import SensorJail
from backtide.jail.verify import sensor_container_problems
from tests.integration import sensor_kit
from tests.integration.service_kit import Service, exec_in_agent

pytestmark = pytest.mark.integration


@pytest.fixture
def sensed(make_real_service: Callable[..., Service]) -> Iterator[Service]:
    with sensor_kit.sensed_service(make_real_service) as service:
        yield service


def _started(service: Service) -> None:
    service.start()
    service.wait_ready()
    sensor_kit.sensor_started(service)


def _marker() -> str:
    return f"t073-{secrets.token_hex(6)}"


def _recorded(service: Service, text: str, *, since: int = 0) -> None:
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "exec" and text in str(e.details.get("argv", "")),
        f"an exec with {text!r} in the black box",
        since=since,
    )


def test_the_agents_commands_are_in_the_black_box_with_their_container(sensed: Service) -> None:
    service = sensed
    _started(service)
    agent_id = service.jail.container_id()
    assert agent_id is not None
    marker = _marker()

    # A command run by docker exec, with a secret in its arguments and one in its environment.
    exec_in_agent(service, f"true {marker}-exec --password hunter2{marker}")
    user = f"{service.jail.config.uid}:{service.jail.config.gid}"
    jail_docker.run([
        "exec", "--user", user, "--env", f"BACKTIDE_T073_ENV=envsecret{marker}",
        service.jail.config.name, "/bin/true", f"{marker}-env",
    ])  # fmt: skip
    # The same command in another container: not the agent's.
    other = f"backtide-test-agent-{os.getpid()}-{secrets.token_hex(6)}"  # the cleanup's scheme
    jail_docker.run([
        "run", "--rm", "--name", other, "--network", "none", "--cap-drop", "ALL",
        "--user", "1000:1000", "--entrypoint", "/bin/true", IMAGE, f"{marker}-other",
    ], timeout=120)  # fmt: skip

    _recorded(service, f"{marker}-exec")
    _recorded(service, f"{marker}-env")
    time.sleep(3)  # the other container's line, if it were the agent's, would be in by now

    (by_exec,) = sensor_kit.execs_with(service, f"{marker}-exec")
    assert by_exec.details["container"] == agent_id[:12]
    assert by_exec.details["container_name"] == service.jail.config.name
    assert by_exec.details["injected"] is True
    assert by_exec.target in ("/bin/sh", "/usr/bin/sh", "/bin/dash", "/usr/bin/dash")
    assert sensor_kit.execs_with(service, f"{marker}-other") == []
    # OpenClaw's own commands (from its tree, not injected) since it started under the sensor.
    own = [
        e
        for e in service.box.events(source="exec", action="exec")
        if e.details.get("container") == agent_id[:12] and e.details.get("injected") is False
    ]
    assert own, "none of OpenClaw's own commands were recorded"
    # No secret, no environment: not in the black box, not in Tetragon's file.
    everything = repr([(e.target, e.details) for e in service.box.events()])
    assert f"hunter2{marker}" not in everything
    assert f"envsecret{marker}" not in everything
    tetragon = sensor_kit.events_text(service)
    assert f"hunter2{marker}" not in tetragon and f"envsecret{marker}" not in tetragon
    assert "environment_variables" not in tetragon
    # The probes went through and none was recorded.
    assert not [e for e in service.box.events(source="exec") if "backtide-hb-" in str(e.details)]
    assert not [e for e in service.box.events(source="exec") if "backtide-ready-" in str(e.details)]


def test_the_real_sensor_passes_verify(sensed: Service) -> None:
    """T07-2's review: on this daemon (SELinux Enforcing) a privileged container gets
    ``label=disable`` and the image brings no Healthcheck and no VOLUME."""
    service = sensed
    _started(service)
    info = sensor_kit.sensor_inspect(service)
    assert info is not None
    config = service.config.sensor_jail_config()
    image_env = SensorJail(config)._image_env()  # noqa: SLF001
    assert sensor_container_problems(config, info, image_env=image_env) == []
    assert sorted(info["HostConfig"].get("SecurityOpt") or []) in ([], ["label=disable"])
    assert not info["Config"].get("Healthcheck")
    assert all(mount["Type"] == "bind" for mount in info["Mounts"])
    assert info["HostConfig"]["NetworkMode"] == "none"


def test_a_fallen_sensor_is_sensor_down_and_comes_back(sensed: Service) -> None:
    service = sensed
    _started(service)
    before = sensor_kit.head_seq(service)
    killed_at = time.monotonic()
    jail_docker.run(["kill", sensor_kit.sensor_name(service)])

    down = sensor_kit.wait_event(
        service,
        lambda e: e.action == "sensor_down",
        "sensor_down",
        sensor_kit.DOWN_WITHIN,
        since=before,
    )
    assert time.monotonic() - killed_at < sensor_kit.DOWN_WITHIN
    assert down.risk == 2 and down.details["reason"] in ("container_stopped", "heartbeat")
    restarted = sensor_kit.wait_event(
        service,
        lambda e: e.action == "sensor_start" and e.details.get("restart") is True,
        "the sensor to be restarted",
        sensor_kit.SENSOR_START_TIMEOUT,
        since=down.seq,
    )
    assert [e.action for e in service.box.events(since_seq=down.seq, action="sensor_restart")]
    assert service.jail.is_running()  # not required: the agent went on

    # And it sees again (the first heartbeat after the restart proves the path).
    marker = _marker()
    exec_in_agent(service, f"true {marker}-back")
    _recorded(service, f"{marker}-back", since=restarted.seq)


def test_restarting_the_service_neither_loses_nor_repeats_events(sensed: Service) -> None:
    service = sensed
    markers = {name: _marker() for name in ("a", "b", "c", "d")}

    # A clean stop: the sensor stops after the agent, the reader saves its cursor at the end.
    _started(service)
    exec_in_agent(service, f"true {markers['a']}")
    _recorded(service, markers["a"])
    assert service.stop() == 0
    assert [e.details for e in service.events("sensor_stop")] == [{"reason": "service_stop"}]
    assert sensor_kit.sensor_inspect(service) is None, "the privileged container was left"

    # Again; then a kill -9 right after a command, inside the cursor's 5 s.
    seq = sensor_kit.head_seq(service)
    service.start()
    service.wait_ready()
    sensor_kit.sensor_started(service, since=seq)
    exec_in_agent(service, f"true {markers['b']}")
    exec_in_agent(service, f"true {markers['c']}")
    _recorded(service, markers["c"], since=seq)
    service.kill()
    assert sensor_kit.sensor_inspect(service) is not None  # Tetragon goes on writing
    # A command while nobody records: Tetragon sees it, the next service must not lose it.
    exec_in_agent(service, f"true {markers['d']}")

    seq = sensor_kit.head_seq(service)
    service.start()
    service.wait_ready()
    reused = sensor_kit.sensor_started(service, since=seq)
    assert reused.details["reused"] is True
    _recorded(service, markers["d"], since=seq)
    assert service.stop() == 0

    for name, marker in markers.items():
        assert len(sensor_kit.execs_with(service, marker)) == 1, (name, marker)
    exec_ids = Counter(
        e.details.get("exec_id")
        for e in service.box.events(source="exec", action="exec")
        if e.details.get("exec_id") and not e.details.get("preexisting")
    )
    assert [key for key, count in exec_ids.items() if count > 1] == []
    report = service.box.verify()
    assert report.ok, report.problems


# --- T07-5: a parallel build under a required sensor ---------------------------------------

# A build inside the agent: tiny C files compiled two at a time by the image's own compiler
# when it has one (each `cc -c` is cc, cc1 and as: three or four execs), or else a copy of
# /bin/true named cc run with each file's own command line. Two workers, paced, so the burst
# stays under the kernel's cut (cgroup-rate: 1,000 exec and exit a second) and only the
# reader's buckets fill: what a `make -j` does to the sensor. Prints one JSON line.
BUILD = r"""
import json, os, shutil, subprocess, sys, threading, time
workdir, count, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3]
os.makedirs(workdir, exist_ok=True)
cc = shutil.which("cc") or shutil.which("gcc")
mode = "cc"
if cc is None:
    mode = "copy"
    cc = os.path.join(workdir, "cc")
    shutil.copy("/bin/true", cc)
    os.chmod(cc, 0o755)
for i in range(count):
    with open(os.path.join(workdir, f"f{i}.c"), "w") as handle:
        handle.write(f"int f{i}(void) {{ return {i}; }}\n")
failed = []
def work(part):
    for i in range(part, count, 2):
        source = os.path.join(workdir, f"f{i}.c")
        done = subprocess.run([cc, f"-DMARK_{marker.replace('-', '_')}", "-c", source, "-o",
                               source[:-2] + ".o"], capture_output=True, timeout=60)
        if done.returncode:
            failed.append(i)
        time.sleep(0.004 if mode == "copy" else 0.0)
started = time.monotonic()
workers = [threading.Thread(target=work, args=(part,)) for part in (0, 1)]
for worker in workers:
    worker.start()
for worker in workers:
    worker.join()
print(json.dumps({"mode": mode, "count": count, "failed": len(failed),
                  "seconds": round(time.monotonic() - started, 1)}))
"""


def test_a_parallel_build_does_not_stop_a_required_agent(
    make_real_service: Callable[..., Service],
) -> None:
    """T07-5: under `required = true` a normal build drained the novelty bucket, and
    novelty_lost stopped the agent. The compiler has events of its own in the window: its
    command lines that do not fit are risk 2 (novelty_lost, blind: false) and an alert, never
    a stop. Measured here with the real service, Tetragon and OpenClaw."""
    with sensor_kit.sensed_service(make_real_service, required=True) as service:
        _started(service)
        before = sensor_kit.head_seq(service)
        marker = _marker()
        count = "1500"
        done = service.jail.exec(
            ["python3", "-c", BUILD, f"/workspace/work/build-{marker}", count, marker], timeout=600
        )
        assert done.returncode == 0, (done.stdout, done.stderr)
        outcome = done.stdout.strip().splitlines()[-1]
        # The summary window (10 s) closes, then at least two heartbeats (30 s each) look.
        time.sleep(75)
        events = service.box.events(since_seq=before)
        stops = [e for e in events if e.action == "agent_stop"]
        gaps = [e for e in events if e.action == "sensor_gap"]
        kinds = Counter((str(e.details.get("kind")), e.details.get("blind"), e.risk) for e in gaps)
        seen = [
            e for e in gaps if e.details.get("kind") == "novelty_lost" and not e.details["blind"]
        ]
        recorded = len([e for e in events if e.source == "exec" and e.action == "exec"])
        folded = sum(int(e.details.get("folded", 0)) for e in events if e.action == "summary")
        summaries = [
            (e.source, e.details.get("counts"), e.details.get("top_binaries"))
            for e in events
            if e.action == "summary"
        ]
        print(
            f"RESULT build {outcome} recorded={recorded} folded={folded} gaps={dict(kinds)} "
            f"stops={[e.details for e in stops]} summaries={summaries}"
        )
        assert stops == [], [e.details for e in stops]
        assert service.jail.is_running()
        assert seen and all(e.risk == 2 for e in seen), dict(kinds)  # the burst did drain it
        assert not [e for e in gaps if e.details.get("blind") is True], dict(kinds)
