"""Unit tests for the egress proxy's container: its argv and network (proxy_config.py) and
ProxyJail (proxy.py). Docker is faked; the folders are real.

The VM tests (tests/integration/test_proxy_container.py) run the same code against the pinned
mitmproxy image."""

# ruff: noqa: S108 - the /tmp here is the tmpfs inside the proxy's container

import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from test_jail_agent import FakeDocker, Reply

from backtide.jail import docker, proxy_config
from backtide.jail import proxy as proxy_module
from backtide.jail.config import PROXY_ALIAS
from backtide.jail.docker import JailError
from backtide.jail.proxy import ProxyJail
from backtide.jail.proxy_config import (
    ProxyJailConfig,
    network_create_argv,
    proxy_create_argv,
)

CA_DIR = Path("/var/lib/backtide/proxy-ca")
CHANNEL_DIR = Path("/var/lib/backtide/proxy-channel")
STATE_FILES = ("blackbox.db", "blackbox.key", "gateway.token", "backtide.toml", "keys")
SECRET_WORDS = ("KEY", "SECRET", "PASSWORD", "TOKEN")
STARTED_AT = "2026-10-17T10:00:00.1Z"
# Options that would open a hole. None may ever appear in the proxy's argv.
FORBIDDEN_OPTIONS = {
    "-p", "--publish", "-P", "--publish-all", "--privileged", "--cap-add", "--add-host",
    "--device", "--mount", "--pid", "--ipc", "--uts", "--userns", "--cgroupns",
    "--volumes-from", "--group-add", "--dns", "--dns-option", "--dns-search", "-v",
}  # fmt: skip


@pytest.fixture
def cfg() -> ProxyJailConfig:
    return ProxyJailConfig(ca_dir=CA_DIR, channel_dir=CHANNEL_DIR)


def option_values(argv: list[str], option: str) -> list[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == option]


# The argv (proxy_config.py)


def test_create_argv_has_every_option_of_the_design(cfg: ProxyJailConfig) -> None:
    """docs/21, section 1, the table of the proxy's container, plus T06-1's plan Bs."""
    argv = proxy_create_argv(cfg)
    assert argv[0] == "create"
    expected = {
        "--name": ["backtide-egress"],
        "--user": ["61001:61001"],  # neither the agent's 61000 nor backtide's
        "--cap-drop": ["ALL"],
        "--security-opt": ["no-new-privileges=true"],  # and Docker's default seccomp
        "--network": ["name=backtide-agente-net,alias=backtide-proxy", "backtide-salida-net"],
        "--restart": ["no"],
        "--memory": ["1g"],
        "--memory-swap": ["1g"],
        "--pids-limit": ["128"],
        "--cpus": ["1"],
        "--ulimit": ["nofile=4096"],
        # T06-1 P4: it would inherit the host's 1
        "--sysctl": ["net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0"],
        "--tmpfs": [
            "/tmp:rw,nosuid,nodev,noexec,size=64m",
            # The image's VOLUME, covered: else Docker adds a writable anonymous volume
            "/home/mitmproxy/.mitmproxy:ro,nosuid,nodev,noexec,size=4k,mode=0555",
        ],
        "--log-driver": ["local"],
        "--log-opt": ["max-size=10m", "max-file=3"],
        "--entrypoint": ["python3"],  # the image's entrypoint would start as root (gosu)
    }
    for option, values in expected.items():
        assert option_values(argv, option) == values, option
    assert "--read-only" in argv
    image_at = argv.index(proxy_config.IMAGE)
    assert argv[image_at + 1 :] == ["-m", "backtide.gate.main"]  # never mitmdump -s


def test_the_image_is_the_pinned_one_of_t06_1() -> None:
    assert proxy_config.IMAGE == (
        "mitmproxy/mitmproxy:12.2.3"
        "@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
    )


def test_create_argv_mounts_only_the_ca_the_channel_and_the_code(cfg: ProxyJailConfig) -> None:
    argv = proxy_create_argv(cfg)
    assert option_values(argv, "--volume") == [
        f"{CA_DIR}:/ca:ro,z",
        f"{CHANNEL_DIR}:/run/backtide:z",  # the proxy makes its socket here (T06-1, P3)
        f"{proxy_config.PACKAGE_DIR}:/opt/backtide/backtide:ro,z",
    ]
    assert (proxy_config.PACKAGE_DIR / "gate" / "main.py").is_file()


def test_create_argv_never_opens_a_hole(cfg: ProxyJailConfig) -> None:
    argv = proxy_create_argv(cfg)
    assert FORBIDDEN_OPTIONS.isdisjoint(argv)
    text = " ".join(argv)
    for needle in ("docker.sock", "host-gateway", "unconfined", "label=disable", "--dns"):
        assert needle not in text
    for name in STATE_FILES:
        assert name not in text, name
    assert not any(arg.startswith(("--publish=", "-p=", "--network=host")) for arg in argv)


def test_create_argv_carries_no_secret(cfg: ProxyJailConfig) -> None:
    env = dict(entry.split("=", 1) for entry in option_values(proxy_create_argv(cfg), "--env"))
    assert [n for n in env if any(word in n.upper() for word in SECRET_WORDS)] == []
    assert env == {
        "PYTHONPATH": "/opt/backtide",
        "HOME": "/tmp",
        "PYTHONUNBUFFERED": "1",  # T06-1 P7: mitmproxy's errors reach docker logs
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONNOUSERSITE": "1",
        "BACKTIDE_UID": "0",  # the one uid the proxy lets connect to its channel (T06-4)
    }


def test_create_argv_follows_the_config(cfg: ProxyJailConfig) -> None:
    custom = replace(
        cfg,
        name="proxy-2",
        agent_network="agent-net-2",
        network="egress-2",
        uid=501,
        gid=20,
        memory="512m",
        pids_limit=64,
        cpus="0.5",
        nofile=1024,
        tmp_size="16m",
        stop_timeout=3,
        package_dir=Path("/opt/src/backtide"),
    )
    argv = proxy_create_argv(custom)
    assert option_values(argv, "--name") == ["proxy-2"]
    assert option_values(argv, "--network") == ["name=agent-net-2,alias=backtide-proxy", "egress-2"]
    assert option_values(argv, "--user") == ["501:20"]
    assert option_values(argv, "--memory") == option_values(argv, "--memory-swap") == ["512m"]
    assert option_values(argv, "--pids-limit") == ["64"]
    assert option_values(argv, "--cpus") == ["0.5"]
    assert option_values(argv, "--ulimit") == ["nofile=1024"]
    assert option_values(argv, "--tmpfs")[0] == "/tmp:rw,nosuid,nodev,noexec,size=16m"
    assert option_values(argv, "--stop-timeout") == ["3"]
    assert "/opt/src/backtide:/opt/backtide/backtide:ro,z" in option_values(argv, "--volume")


def test_the_ready_line_is_the_one_main_prints() -> None:
    """backtide/gate/main.py imports mitmproxy, which the Mac does not have: read its text."""
    main = (proxy_config.PACKAGE_DIR / "gate" / "main.py").read_text()
    assert f'READY_LOG_LINE = "{proxy_config.READY_LOG_LINE}"' in main


def test_main_imports_nothing_of_the_service() -> None:
    main = (proxy_config.PACKAGE_DIR / "gate" / "main.py").read_text()
    imports = re.findall(r"^(?:from|import) ([\w.]+)", main, flags=re.MULTILINE)
    assert sorted(set(imports)) == [
        "asyncio", "backtide", "backtide.gate.addon", "backtide.gate.client",
        "collections.abc", "logging", "mitmproxy", "mitmproxy.tools.dump", "os", "socket",
        "typing",
    ]  # fmt: skip
    # Only the agent's side may use it (the egress side is reachable from the host).
    assert 'AGENT_SIDE_ALIAS = "backtide-proxy"' in main
    assert '"connection_strategy": "lazy"' in main
    assert "with_dumper=False" in main
    assert "master.addons.add(gate, Ready())" in main
    assert 'int(os.environ["BACKTIDE_UID"])' in main  # no uid, no proxy


def test_the_gate_brings_only_the_standard_library_and_backtides_gate() -> None:
    """In a fresh interpreter: what the proxy's addon and channel import (mitmproxy aside,
    which they never import) is the standard library, backtide.gate and backtide.blackbox."""
    script = (
        "import sys, json\n"
        "before = set(sys.modules)\n"
        "import backtide.gate.addon, backtide.gate.client\n"
        "print(json.dumps(sorted(set(sys.modules) - before)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, check=True, cwd=proxy_config.PACKAGE_DIR.parent,
        env={"PYTHONPATH": str(proxy_config.PACKAGE_DIR.parent)},
    )  # fmt: skip
    loaded = json.loads(result.stdout)
    ours = sorted(name for name in loaded if name.split(".")[0] == "backtide")
    assert ours, result.stderr
    allowed = ("backtide.gate", "backtide.blackbox", "backtide.snapshots")
    assert [name for name in ours if name != "backtide" and not name.startswith(allowed)] == []
    for foreign in ("fastapi", "uvicorn", "jinja2", "mitmproxy", "backtide.service"):
        assert not any(name == foreign or name.startswith(foreign + ".") for name in loaded)


# The egress network


def test_the_egress_network_is_a_plain_bridge_without_ipv6(cfg: ProxyJailConfig) -> None:
    argv = network_create_argv(cfg)
    assert argv == [
        "network", "create", "--driver", "bridge", "--ipv6=false",
        "--label", "backtide.role=egress", cfg.network,
    ]  # fmt: skip


def test_the_tests_egress_network_is_internal(cfg: ProxyJailConfig) -> None:
    argv = network_create_argv(replace(cfg, internal_egress=True))
    assert "--internal" in argv
    assert "com.docker.network.bridge.gateway_mode_ipv4=isolated" in argv
    assert argv[-1] == cfg.network


# Validation


@pytest.mark.parametrize(
    "changes",
    [
        {"ca_dir": Path("relative")},
        {"channel_dir": Path("/with:colon")},
        {"package_dir": Path("/a,b")},
        {"channel_dir": CA_DIR / "channel"},  # the channel inside the CA's folder
        {"ca_dir": Path("/var/lib")},  # the CA's folder around the channel's
        {"package_dir": CA_DIR},
        {"name": "-rm"},
        {"network": "backtide-agente-net"},  # the egress network must not be the agent's
        {"network": "bridge"},  # Docker's default: any `docker run` would sit next to it
        {"network": "host"},
        {"agent_network": "none"},
        {"agent_network": "has space"},
        {"image": "mitmproxy/mitmproxy:12.2.3"},  # not pinned
        {"image": "mitmproxy/mitmproxy@sha256:abc"},
        {"uid": 0},
        {"gid": -1},
        {"uid": True},
        {"agent_uid": 0},
        {"memory": "1"},
        {"cpus": "0"},
        {"nofile": 0},
        {"pids_limit": 0},
        {"stop_timeout": 0},
        {"ready_timeout": 0},
        {"internal_egress": "yes"},
        {"allow_shared_ids": 1},
    ],
)
def test_invalid_configs_are_refused(changes: dict[str, object]) -> None:
    fields = {"ca_dir": CA_DIR, "channel_dir": CHANNEL_DIR}
    with pytest.raises(ValueError):
        ProxyJailConfig(**(fields | changes))  # type: ignore[arg-type]


def test_the_defaults_are_the_designs() -> None:
    config = ProxyJailConfig(ca_dir=CA_DIR, channel_dir=CHANNEL_DIR)
    assert (config.uid, config.gid) == (61001, 61001)
    assert (config.agent_uid, config.agent_gid) == (61000, 61000)
    assert config.internal_egress is False and config.allow_shared_ids is False


# ProxyJail (proxy.py)

GOOD_EGRESS = {
    "Driver": "bridge",
    "Internal": False,
    "EnableIPv6": False,
    "Containers": {},
    "Labels": {"backtide.role": "egress"},
}
RUNNING = Reply(json.dumps({"Running": True, "ExitCode": 0, "StartedAt": STARTED_AT}))
STOPPED = Reply(json.dumps({"Running": False, "ExitCode": 1, "StartedAt": STARTED_AT}))
NO_CONTAINER = Reply(stderr="Error response from daemon: No such container: x\n", returncode=1)
NO_NETWORK = Reply(stderr="Error response from daemon: network x not found\n", returncode=1)
CONTAINER_INFO = Reply(json.dumps({"Id": "c0ffee", "Config": {}, "HostConfig": {}}))
IMAGE_ENV = Reply(json.dumps(["PATH=/usr/bin:/bin"]))


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake = FakeDocker()
    fake.reply("container", "inspect", "--format", "{{json .}}", CONTAINER_INFO)
    fake.reply("image", "inspect", IMAGE_ENV)
    fake.reply("network", "inspect", Reply(json.dumps(GOOD_EGRESS)))
    monkeypatch.setattr(docker, "run", fake)
    return fake


@pytest.fixture(autouse=True)
def container_check(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """verify.py has its own tests: here every container passes, unless a test says otherwise."""
    problems: list[list[str]] = [[]]
    monkeypatch.setattr(
        proxy_module, "proxy_container_problems", lambda config, info, *, image_env: problems[0]
    )
    return problems


@pytest.fixture
def local_cfg(tmp_path: Path) -> ProxyJailConfig:
    """Folders as ca.py and prepare_channel leave them, owned by this user (no root here)."""
    ca_dir = tmp_path / "proxy-ca"
    ca_dir.mkdir(mode=0o750)
    for name in ("mitmproxy-ca.pem", "mitmproxy-dhparam.pem"):
        (ca_dir / name).write_text("pem")
        (ca_dir / name).chmod(0o440)
    return ProxyJailConfig(
        ca_dir=ca_dir,
        channel_dir=tmp_path / "proxy-channel",
        name="proxy-under-test",
        agent_network="agent-net-under-test",
        network="egress-under-test",
        uid=os.getuid(),
        gid=os.getgid(),
        ready_timeout=5,
        allow_shared_ids=True,  # without root, the proxy's folders can only be this user's
        channel_tmpfs=False,  # without root, nothing can be mounted
    )


@pytest.fixture
def jail(local_cfg: ProxyJailConfig) -> ProxyJail:
    return ProxyJail(local_cfg)


@pytest.fixture
def ready(jail: ProxyJail, fake_docker: FakeDocker) -> ProxyJail:
    jail.prepare_channel()
    return jail


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [0.0]
    monkeypatch.setattr(proxy_module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        proxy_module.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds)
    )
    return now


def test_ensure_network_creates_a_missing_egress_network(
    jail: ProxyJail, fake_docker: FakeDocker
) -> None:
    fake_docker.reply("network", "inspect", NO_NETWORK, Reply(json.dumps(GOOD_EGRESS)))
    jail.ensure_network()
    assert network_create_argv(jail.config) in fake_docker.commands()


def test_ensure_network_reuses_a_safe_one(jail: ProxyJail, fake_docker: FakeDocker) -> None:
    owned = GOOD_EGRESS | {"Containers": {"abc": {"Name": "proxy-under-test"}}}
    fake_docker.reply("network", "inspect", Reply(json.dumps(owned)))
    jail.ensure_network()
    assert [c for c in fake_docker.commands() if c[:2] == ["network", "create"]] == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"Internal": True}, "--internal"),
        ({"EnableIPv6": True}, "IPv6"),
        ({"Driver": "host"}, "driver"),
        ({"Containers": {"x": {"Name": "backtide-agente"}}}, "backtide-agente"),
        ({"Containers": {"x": {"Name": "someone-else"}}}, "someone-else"),
        ({"Labels": {}}, "not one backtide made"),
    ],
)
def test_ensure_network_refuses_an_unsafe_egress_network(
    jail: ProxyJail, fake_docker: FakeDocker, change: dict[str, object], problem: str
) -> None:
    """Only the proxy may be on the network with a way out (docs/21, section 2)."""
    fake_docker.reply("network", "inspect", Reply(json.dumps(GOOD_EGRESS | change)))
    with pytest.raises(JailError, match=problem):
        jail.ensure_network()
    assert [c for c in fake_docker.commands() if c[:2] == ["network", "create"]] == []


def test_the_tests_egress_network_must_be_internal_and_isolated(
    local_cfg: ProxyJailConfig, fake_docker: FakeDocker
) -> None:
    jail = ProxyJail(replace(local_cfg, internal_egress=True))
    fake_docker.reply("network", "inspect", Reply(json.dumps(GOOD_EGRESS)))
    with pytest.raises(JailError, match="not --internal"):
        jail.ensure_network()
    isolated = GOOD_EGRESS | {
        "Internal": True,
        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
    }
    fake_docker.reply("network", "inspect", Reply(json.dumps(isolated)))
    jail.ensure_network()


def test_prepare_channel_makes_the_proxys_own_folder(jail: ProxyJail) -> None:
    jail.prepare_channel()
    st = jail.config.channel_dir.stat()
    assert (st.st_uid, st.st_gid) == (jail.config.uid, jail.config.gid)
    assert st.st_mode & 0o777 == 0o700
    jail.prepare_channel()  # idempotent


def test_prepare_channel_refuses_a_symlink(jail: ProxyJail, tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    jail.config.channel_dir.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(JailError, match="not a directory"):
        jail.prepare_channel()


def test_create_runs_the_argv_and_start_checks_the_container_first(
    ready: ProxyJail, fake_docker: FakeDocker
) -> None:
    ready.create()
    ready.start()
    commands = fake_docker.commands()
    assert proxy_create_argv(ready.config) in commands
    inspect_at = commands.index(
        ["container", "inspect", "--format", "{{json .}}", ready.config.name]
    )
    assert commands.index(["start", ready.config.name]) > inspect_at


def test_start_refuses_a_container_that_is_not_the_proxy(
    ready: ProxyJail, fake_docker: FakeDocker, container_check: list[list[str]]
) -> None:
    container_check[0] = ["HostConfig.Sysctls is None, not {'net.ipv4.ip_forward': '0'}"]
    with pytest.raises(JailError, match="not the proxy this backtide expects.*Sysctls"):
        ready.start()
    assert ["start", ready.config.name] not in fake_docker.commands()


def test_start_refuses_someone_else_on_the_egress_network(
    ready: ProxyJail, fake_docker: FakeDocker
) -> None:
    crowded = GOOD_EGRESS | {"Containers": {"a": {"Name": "intruder"}}}
    fake_docker.reply("network", "inspect", Reply(json.dumps(crowded)))
    with pytest.raises(JailError, match="intruder"):
        ready.start()
    assert ["start", ready.config.name] not in fake_docker.commands()


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_need_the_ca_and_the_channel(
    jail: ProxyJail, fake_docker: FakeDocker, method: str
) -> None:
    with pytest.raises(JailError, match="proxy-channel is missing"):
        getattr(jail, method)()
    jail.prepare_channel()
    (jail.config.ca_dir / "mitmproxy-dhparam.pem").unlink()
    with pytest.raises(JailError, match="must hold exactly"):
        getattr(jail, method)()
    assert fake_docker.calls == []


@pytest.mark.parametrize("method", ["create", "start"])
@pytest.mark.parametrize("stray", ["blackbox.key", "anthropic.key", "gateway.token"])
def test_create_and_start_refuse_anything_else_in_the_ca_folder(
    ready: ProxyJail, fake_docker: FakeDocker, method: str, stray: str
) -> None:
    (ready.config.ca_dir / stray).write_text("never show the proxy")
    with pytest.raises(JailError, match=f"must hold exactly.*{stray}"):
        getattr(ready, method)()
    assert fake_docker.calls == []


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_refuse_a_symlink_in_the_ca_folder(
    ready: ProxyJail, fake_docker: FakeDocker, tmp_path: Path, method: str
) -> None:
    target = ready.config.ca_dir / "mitmproxy-dhparam.pem"
    target.unlink()
    target.symlink_to(tmp_path / "blackbox.key")
    with pytest.raises(JailError, match="not a regular file"):
        getattr(ready, method)()


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_refuse_a_package_without_the_gate(
    ready: ProxyJail, fake_docker: FakeDocker, tmp_path: Path, method: str
) -> None:
    empty = tmp_path / "not-backtide"
    empty.mkdir()
    (empty / "__init__.py").write_text("")
    jail = ProxyJail(replace(ready.config, package_dir=empty))
    with pytest.raises(JailError, match="no gate"):
        getattr(jail, method)()


@pytest.mark.parametrize("method", ["create", "start"])
@pytest.mark.parametrize(
    ("ids", "shared"),
    [
        ({"uid": "own"}, "backtide's uid"),
        ({"gid": "own"}, "backtide's gid"),
        ({"uid": 61000}, "the agent's uid"),
        ({"gid": 61000}, "the agent's gid"),
    ],
)
def test_create_and_start_refuse_shared_ids(
    ready: ProxyJail, fake_docker: FakeDocker, method: str, ids: dict, shared: str
) -> None:
    others = {"uid": os.getuid() + 7919, "gid": max([os.getgid(), *os.getgroups()]) + 7919}
    own = {"uid": os.getuid(), "gid": os.getgid()}
    chosen = {name: own[name] if value == "own" else value for name, value in ids.items()}
    jail = ProxyJail(replace(ready.config, allow_shared_ids=False, **(others | chosen)))
    with pytest.raises(JailError, match=re.escape(shared)):
        getattr(jail, method)()
    assert fake_docker.calls == []


def test_wait_ready_waits_for_the_line_of_this_start(
    ready: ProxyJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{json .State}}", RUNNING)
    fake_docker.reply("logs", Reply(stdout=""), Reply(stdout=f"{proxy_config.READY_LOG_LINE}\n"))
    ready.wait_ready()
    logs = [c for c in fake_docker.calls if c.args[0] == "logs"]
    assert logs[-1].args == ["logs", "--since", STARTED_AT, ready.config.name]
    assert all(call.max_output <= 1024 * 1024 for call in logs)


def test_wait_ready_fails_when_the_proxy_dies(
    ready: ProxyJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{json .State}}", STOPPED)
    fake_docker.reply("logs", Reply(stderr="KeyError: 'flow_detail'\x1b[2J\n"))
    with pytest.raises(JailError, match="stopped before it was ready.*flow_detail") as error:
        ready.wait_ready()
    assert "\x1b" not in str(error.value)


def test_wait_ready_gives_up_after_the_timeout(
    ready: ProxyJail, fake_docker: FakeDocker, clock: list[float]
) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{json .State}}", RUNNING)
    fake_docker.reply("logs", Reply(stdout="starting\n"))
    with pytest.raises(JailError, match="not ready after 5"):
        ready.wait_ready()


def test_lifecycle_commands(ready: ProxyJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{json .State}}", RUNNING)
    assert ready.exists() and ready.is_running()
    ready.stop()
    ready.kill()
    ready.remove()
    ready.remove_network()
    name = ready.config.name
    commands = fake_docker.commands()
    assert ["stop", "--time", "10", name] in commands
    assert ["kill", name] in commands
    assert ["rm", "--force", "--volumes", name] in commands
    assert ["network", "rm", ready.config.network] in commands


def test_a_missing_container_is_not_running(ready: ProxyJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{json .State}}", NO_CONTAINER)
    assert not ready.exists() and not ready.is_running()
    fake_docker.reply("kill", NO_CONTAINER)
    ready.kill()  # nothing to kill is not an error
    fake_docker.reply("network", "rm", NO_NETWORK)
    ready.remove_network()


def test_start_empties_the_channel_folder_without_following_links(
    ready: ProxyJail, fake_docker: FakeDocker, tmp_path: Path
) -> None:
    """What the proxy left there (a stale socket, a planted symlink) never outlives a start."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("not the proxy's")
    channel = ready.config.channel_dir
    (channel / "events.sock").write_text("stale")
    (channel / "link").symlink_to(outside)
    (channel / "sub").mkdir()
    (channel / "sub" / "x").write_text("x")
    ready.start()
    assert os.listdir(channel) == []
    assert (outside / "keep").read_text() == "not the proxy's"


@pytest.mark.parametrize("method", ["create", "start"])
def test_create_and_start_refuse_a_package_others_may_change(
    ready: ProxyJail, fake_docker: FakeDocker, tmp_path: Path, method: str
) -> None:
    """Whoever may write the gate's code controls the way out."""
    import shutil

    package = tmp_path / "pkg"
    shutil.copytree(proxy_config.PACKAGE_DIR, package, ignore=shutil.ignore_patterns("__pycache__"))
    jail = ProxyJail(replace(ready.config, package_dir=package))
    (package / "gate" / "main.py").chmod(0o666)
    with pytest.raises(JailError, match="may be changed by someone"):
        getattr(jail, method)()
    (package / "gate" / "main.py").chmod(0o644)
    (package / "gate").chmod(0o777)
    with pytest.raises(JailError, match="may be changed by someone"):
        getattr(jail, method)()


# T06-4: the test grants, the channel's tmpfs and the agent's network


def test_the_test_grants_reach_the_proxy_as_variables(cfg: ProxyJailConfig) -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    granted = replace(
        cfg, backtide_uid=501, test_public_addresses=("172.30.0.9",), test_upstream_ca=pem
    )
    env = dict(proxy_config.proxy_env(granted))
    assert env["BACKTIDE_UID"] == "501"
    assert env["BACKTIDE_TEST_PUBLIC"] == "172.30.0.9"
    assert env["BACKTIDE_TEST_UPSTREAM_CA"] == pem
    assert "BACKTIDE_TEST_PUBLIC" not in dict(proxy_config.proxy_env(cfg))
    assert pem not in repr(granted)


@pytest.mark.parametrize(
    "changes",
    [
        {"test_upstream_ca": "-----BEGIN PRIVATE KEY-----"},
        {"test_upstream_ca": "not a pem"},
        {"test_public_addresses": ("10.0.0.1/8",)},
        {"egress_neighbours": ("bad name!",)},
        {"egress_neighbours": ("backtide-egress",)},
        {"backtide_uid": -1},
        {"backtide_uid": True},
        {"channel_size": "lots"},
        {"channel_tmpfs": "yes"},
        {"test_dns": ("not an address",)},
        {"test_dns": ("10.0.0.0/8",)},
        {"test_dns": "172.30.0.9"},
    ],
)
def test_the_grants_are_checked(cfg: ProxyJailConfig, changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        replace(cfg, **changes)


def test_the_test_resolver_is_the_proxys_upstream_only_when_granted(
    cfg: ProxyJailConfig,
) -> None:
    # T06-7 (dns-tunel): the VM tests give the proxy a fake resolver as its upstream, as T06-1
    # P5 did, to see every name the proxy resolves. Never in production: no --dns at all.
    assert "--dns" not in proxy_config.proxy_create_argv(cfg)
    argv = proxy_config.proxy_create_argv(replace(cfg, test_dns=("172.30.0.9",)))
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--dns"] == ["172.30.0.9"]
    assert argv.index("--dns") < argv.index("--entrypoint")


def test_the_channel_tmpfs_is_small_private_and_inert(cfg: ProxyJailConfig) -> None:
    assert proxy_config.channel_mount_argv(cfg) == [
        "mount", "-t", "tmpfs", "-o",
        "size=1m,mode=0700,uid=61001,gid=61001,nosuid,nodev,noexec",
        "backtide-proxy-channel", str(CHANNEL_DIR),
    ]  # fmt: skip


class FakeMounts:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.mounted = False
        self.calls: list[list[str]] = []

    def mount(self, argv: list[str]) -> None:
        self.calls.append(argv)
        self.mounted = True

    def table(self) -> str:
        root = "22 1 0:21 / / rw,relatime shared:1 - btrfs /dev/vda2 rw\n"
        if not self.mounted:
            return root
        point = os.path.realpath(self.path).replace(" ", "\\040")
        return root + f"80 22 0:50 / {point} rw,nosuid shared:2 - tmpfs backtide-proxy-channel rw\n"


def test_prepare_channel_mounts_the_tmpfs_once(local_cfg: ProxyJailConfig) -> None:
    config = replace(local_cfg, channel_tmpfs=True)
    mounts = FakeMounts(config.channel_dir)
    jail = ProxyJail(config, mount=mounts.mount, mountinfo=mounts.table)
    jail.prepare_channel()
    jail.prepare_channel()
    assert mounts.calls == [proxy_config.channel_mount_argv(config)]


def test_create_and_start_refuse_a_channel_that_is_not_its_tmpfs(
    local_cfg: ProxyJailConfig, fake_docker: FakeDocker
) -> None:
    config = replace(local_cfg, channel_tmpfs=True)
    mounts = FakeMounts(config.channel_dir)
    ProxyJail(local_cfg).prepare_channel()  # the folder, without its tmpfs
    jail = ProxyJail(config, mount=mounts.mount, mountinfo=mounts.table)
    for step in (jail.create, jail.start):
        with pytest.raises(JailError, match="not the channel's tmpfs"):
            step()


def test_a_mount_that_does_not_show_up_is_an_error(local_cfg: ProxyJailConfig) -> None:
    config = replace(local_cfg, channel_tmpfs=True)
    jail = ProxyJail(config, mount=lambda argv: None, mountinfo=lambda: "")
    with pytest.raises(JailError, match="still not a tmpfs"):
        jail.prepare_channel()


def test_the_fake_internet_may_share_the_egress_network_only_by_grant(
    local_cfg: ProxyJailConfig, fake_docker: FakeDocker
) -> None:
    egress = dict(GOOD_EGRESS, Containers={"a": {"Name": "fake-internet"}})
    fake_docker.reply("network", "inspect", Reply(json.dumps(egress)))
    ProxyJail(local_cfg).prepare_channel()
    with pytest.raises(JailError, match="others are on it"):
        ProxyJail(local_cfg).start()
    ProxyJail(replace(local_cfg, egress_neighbours=("fake-internet",))).start()


def test_only_the_agent_and_the_proxy_may_be_on_the_agents_network(
    jail: ProxyJail, fake_docker: FakeDocker
) -> None:
    two = {"a": {"Name": "the-agent"}, "b": {"Name": jail.config.name}}
    fake_docker.reply("network", "inspect", Reply(json.dumps(two)))
    jail.check_agent_network("the-agent")
    fake_docker.reply("network", "inspect", Reply(json.dumps(two | {"c": {"Name": "intruder"}})))
    with pytest.raises(JailError, match="intruder"):
        jail.check_agent_network("the-agent")


def test_container_id_is_the_full_id(jail: ProxyJail, fake_docker: FakeDocker) -> None:
    fake_docker.reply("container", "inspect", "--format", "{{.Id}}", Reply("ab" * 32 + "\n"))
    assert jail.container_id() == "ab" * 32
    fake_docker.reply("container", "inspect", "--format", "{{.Id}}", Reply("../x\n"))
    with pytest.raises(JailError):
        jail.container_id()


def test_the_container_is_never_named_like_the_agent_side_alias(tmp_path: Path) -> None:
    """Docker answers a container's name on every network it is on: named like the alias, the
    proxy resolves the alias to its egress address and refuses every client of the agent."""
    with pytest.raises(ValueError, match="agent-side alias"):
        ProxyJailConfig(ca_dir=tmp_path / "ca", channel_dir=tmp_path / "ch", name=PROXY_ALIAS)
    assert ProxyJailConfig(ca_dir=tmp_path / "ca", channel_dir=tmp_path / "ch").name != PROXY_ALIAS
