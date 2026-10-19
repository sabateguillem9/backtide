"""Unit tests for backtide/jail/sensor.py and the sensor's half of backtide/jail/verify.py.

The sensor is the most privileged container of the install (docs/23, section 2): these tests
pin every option of its argv and of its Tetragon settings, and check that verify refuses any
container that differs. Docker is faked; the sensor's folders are real (tmp_path)."""

import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from backtide.jail import docker
from backtide.jail import sensor as sensor_jail
from backtide.jail.docker import JailError
from backtide.jail.sensor import (
    IMAGE,
    POLICY_FILE,
    POLICY_SHA256,
    REDACTION_RULES,
    REDACTION_TOOL_RULES,
    SensorJail,
    SensorJailConfig,
    policy_text,
    sensor_create_argv,
    sensor_settings,
    volume_binds,
)
from backtide.jail.verify import sensor_container_problems

STATE = Path("/var/lib/backtide/sensor")
CONFIG = SensorJailConfig(state_dir=STATE)
IMAGE_ENV = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
SENSOR_ID = "ab" * 32

EXPECTED_ARGV = [
    "create",
    "--name", "backtide-sensor",
    "--privileged", "--pid=host", "--cgroupns=host",
    "--network", "none",
    "--restart", "no",
    "--memory", "1g",
    "--memory-swap", "1g",
    "--cpus", "1",
    "--stop-timeout", "10",
    "--log-driver", "local",
    "--log-opt", "max-size=10m",
    "--log-opt", "max-file=3",
    "--volume", "/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro",
    "--volume", "/var/lib/backtide/sensor/events:/var/log/tetragon",
    "--volume", "/var/lib/backtide/sensor/tp.d:/etc/tetragon/tetragon.tp.d:ro",
    "--volume", "/var/lib/backtide/sensor/conf.d:/etc/tetragon/tetragon.conf.d:ro",
    "--entrypoint", "/usr/bin/tetragon",
    IMAGE,
]  # fmt: skip


# --- the image and the argv -----------------------------------------------------------------


def test_the_image_is_pinned_by_digest() -> None:
    assert IMAGE == (
        "quay.io/cilium/tetragon"
        "@sha256:afc9458ba4bc3f2795da3df6b03d88ce50e175ac3903027de8036e2046b84a02"
    )


def test_the_create_argv_is_exactly_the_design() -> None:
    assert sensor_create_argv(CONFIG) == EXPECTED_ARGV


def test_the_argv_never_opens_anything_else() -> None:
    argv = sensor_create_argv(CONFIG)
    text = " ".join(argv)
    assert "docker.sock" not in text
    for option in ("-p", "--publish", "-P", "--publish-all", "-e", "--env", "--env-file"):
        assert option not in argv
    for option in ("--cap-add", "--device", "--security-opt", "--add-host", "--mount"):
        assert option not in argv
    volumes = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--volume"]
    assert len(volumes) == 4
    sources = [volume.split(":")[0] for volume in volumes]
    assert sources[0] == "/sys/kernel/btf/vmlinux"
    assert all(source.startswith(f"{STATE}/") for source in sources[1:])
    assert not any(volume.endswith((":z", ":Z", ",z", ",Z")) for volume in volumes)  # no relabel


def test_volume_binds_are_the_four_folders() -> None:
    assert volume_binds(CONFIG) == [
        "/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro",
        "/var/lib/backtide/sensor/events:/var/log/tetragon",
        "/var/lib/backtide/sensor/tp.d:/etc/tetragon/tetragon.tp.d:ro",
        "/var/lib/backtide/sensor/conf.d:/etc/tetragon/tetragon.conf.d:ro",
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"state_dir": Path("relative/sensor")},
        {"state_dir": Path("/srv/a:b")},
        {"state_dir": Path("/srv/a,b")},
        {"btf": Path("/sys/kernel/btf/vmlinux:rw")},
        {"name": "bad name"},
        {"name": "-flag"},
        {"image": "quay.io/cilium/tetragon:v1.7.1"},
        {"memory": "lots"},
        {"cpus": "0"},
        {"stop_timeout": 0},
        {"file_max_size_mb": 0},
        {"file_max_backups": -1},
        {"cgroup_rate": "1000"},
        {"cgroup_rate": "1000,1s\nlog-level: debug"},
        {"ready_timeout": 0},
        {"file_perm": "666"},
        {"file_perm": "0600"},
    ],
)
def test_the_config_refuses_bad_values(change: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        SensorJailConfig(**{"state_dir": STATE, **change})


def test_the_folders_live_under_the_state_dir() -> None:
    assert CONFIG.events_dir == STATE / "events"
    assert CONFIG.tp_dir == STATE / "tp.d"
    assert CONFIG.conf_dir == STATE / "conf.d"
    assert CONFIG.cursor_file == STATE / "cursor.json"
    assert CONFIG.events_file == STATE / "events" / "tetragon.log"


# --- Tetragon's settings --------------------------------------------------------------------


def test_the_settings_are_the_design() -> None:
    settings = sensor_settings(CONFIG)
    assert settings == {
        "export-filename": "/var/log/tetragon/tetragon.log",
        "export-file-max-size-mb": "50",
        "export-file-max-backups": "8",
        "export-file-compress": "false",
        "export-file-perm": "600",
        "export-allowlist": settings["export-allowlist"],
        "field-filters": settings["field-filters"],
        "cgroup-rate": "1000,1s",
        "redaction-filters": settings["redaction-filters"],
        "server-address": "unix:///var/run/tetragon/tetragon.sock",
        "health-server-address": "",
        # T07 review: the loss counters, on the loopback of the sensor's own netns (none).
        "metrics-server": "127.0.0.1:2112",
        "metrics-label-filter": "namespace",
        "log-level": "warn",
    }


def test_the_environment_of_processes_is_never_turned_on() -> None:
    settings = sensor_settings(CONFIG)
    assert not any("environment" in name for name in settings)
    assert not any("environment" in value for value in settings.values())


def test_the_allowlist_has_the_container_line_and_the_throttle_line() -> None:
    """T07-1, P10: THROTTLE carries no process, so the container filter alone drops it."""
    lines = sensor_settings(CONFIG)["export-allowlist"].splitlines()
    assert [json.loads(line) for line in lines] == [
        {"container_id": ["."]},
        {"event_set": ["PROCESS_THROTTLE"]},
    ]


def test_the_field_filters_keep_what_procs_needs() -> None:
    (line,) = sensor_settings(CONFIG)["field-filters"].splitlines()
    rule = json.loads(line)
    assert rule["event_set"] == ["PROCESS_EXEC"] and rule["action"] == "INCLUDE"
    fields = set(rule["fields"].split(","))
    for needed in (
        "process.binary",
        "process.arguments",
        "process.cwd",
        "process.flags",
        "process.docker",
        "process.in_init_tree",
        "process.pid",
        "process.uid",
        "parent.pid",
        "parent.binary",
    ):
        assert needed in fields


def test_each_redaction_line_is_one_json_rule() -> None:
    lines = sensor_settings(CONFIG)["redaction-filters"].splitlines()
    assert [json.loads(line) for line in lines] == [
        {"redact": list(r)} for r in REDACTION_RULES
    ] + [{"binary_regex": [b], "redact": list(r)} for b, r in REDACTION_TOOL_RULES]


def _tetragon_redact(text: str, binary: str = "/bin/true") -> str:
    """What Tetragon does with a rule: each capture group of each match becomes *****. A rule
    with a binary_regex only applies to a binary it matches."""
    filters = [*REDACTION_RULES]
    filters += [rules for regex, rules in REDACTION_TOOL_RULES if re.search(regex, binary)]
    for rules in filters:
        for rule in rules:
            pattern = re.compile(rule)

            def strike(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
                whole, start, out = match.group(0), match.start(), []
                last = 0
                for group in range(1, pattern.groups + 1):
                    if match.start(group) < 0 or match.start(group) - start < last:
                        continue
                    out.append(whole[last : match.start(group) - start] + "*****")
                    last = match.end(group) - start
                return "".join(out) + whole[last:]

            text = pattern.sub(strike, text)
    return text


# The fake secrets of T07-1, P11, in the same command line.
P11_FAKE = {
    "bearer": "faketokenP11bearer0123456789",
    "password": "hunter2-fake-P11",
    "token_flag": "fake-token-flag-P11-0123",
    "sk": "sk-fakeP11abcdefghijklmnop0123",
    "ghp": "ghp_fakeP11abcdefghijklmnopqrstuv",
    "akia": "AKIAFAKEP11ABCDE0123",
    "url_password": "fakeurlpassP11",
    "api_key_header": "fakeapikeyheaderP11xyz",
}


def test_the_redaction_rules_strike_the_p11_secrets() -> None:
    f = P11_FAKE
    arguments = (
        f'nonce -H "Authorization: Bearer {f["bearer"]}" --password {f["password"]} '
        f"--token={f['token_flag']} {f['sk']} {f['ghp']} {f['akia']} "
        f"https://someone:{f['url_password']}@example.invalid/repo.git "
        f'-H "x-api-key: {f["api_key_header"]}"'
    )
    struck = _tetragon_redact(arguments)
    assert not [name for name, value in f.items() if value in struck]


def test_the_refined_capture_keeps_the_closing_quote() -> None:
    """T07-1, P11: ``(\\S+)`` also ate the closing quote; ``([^\\s"']+)`` does not."""
    assert _tetragon_redact('-H "Authorization: Bearer abc123"') == (
        '-H "Authorization: Bearer *****"'
    )
    assert _tetragon_redact("--password=hunter2 x") == "--password=***** x"
    # A quoted value (--password "two words") is the second barrier's: procs.safe_text.
    for rules in REDACTION_RULES[:2]:
        assert all(rule.endswith(r"""([^\s"']+)""") for rule in rules)


# --- T07-5: passwords glued to their flag, and values Tetragon wraps in quotes -----------

_G = "Qx7vR2mK9pLt4ZwB8nHc"  # noqa: S105 - a fake
_G2 = "Vb6Yc1Df5Gh0JqR2mX9k"  # noqa: S105 - a fake


@pytest.mark.parametrize(
    ("binary", "arguments", "kept"),
    [
        ("/usr/bin/mysql", f"-uroot -p{_G} shop", "shop"),
        ("/usr/bin/mariadb-dump", f'"-p{_G} {_G2}" shop', "shop"),
        ("/usr/bin/sshpass", f"-p {_G} ssh host.invalid", "ssh host.invalid"),
        ("/usr/bin/sshpass", f'-p "{_G} {_G2}" ssh host.invalid', "ssh host.invalid"),
        ("/usr/bin/redis-cli", f"-a{_G} ping", "ping"),
        ("/usr/bin/mongosh", f"-u a -p {_G} --quiet", "--quiet"),
        ("/usr/bin/lftp", f"-u alice,{_G} sftp://h.invalid", "sftp://h.invalid"),
        ("/usr/bin/smbclient", f"//h.invalid/s -U alice%{_G}", "//h.invalid/s"),
        ("/usr/bin/curl", f"-ualice:{_G} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/env", f'"DB_PASSWORD={_G} {_G2}" run', "run"),
        ("/bin/true", f'"--password=pass phrase {_G} {_G2}" x', " x"),
        ("/bin/true", f'"--token={_G} {_G2}" x', " x"),
        ("/bin/true", f"-bsessionid={_G};csrftoken={_G2} x", " x"),
        ("/bin/true", f'"-bsessionid={_G}; csrftoken={_G2}" x', " x"),
        ("/bin/sh", f'-c "mysql -uroot -p{_G} shop; ls /w"', "ls /w"),
        ("/bin/sh", f"-c \"mysql -p'{_G} {_G2}' shop && echo ok\"", "echo ok"),
        ("/bin/sh", f'-c "MYSQL_PWD={_G} mysql shop"', "mysql shop"),
        ("/bin/sh", f'-c "SSHPASS={_G} sshpass -e ssh h.invalid"', "ssh h.invalid"),
        ("/bin/sh", f'-c "sshpass -p {_G} ssh h.invalid"', "ssh h.invalid"),
        ("/bin/sh", f'-c "redis-cli -h c.invalid -a {_G} ping | cat"', "| cat"),
        ("/bin/sh", f'-c "lftp -u alice,{_G} h.invalid; echo done"', "echo done"),
        ("/bin/sh", f'-c "smbclient //h/s -U alice%{_G} -c ls"', "-c ls"),
        ("/bin/sh", f'-c "curl -ualice:{_G} https://x.invalid/"', "https://x.invalid/"),
        ("/usr/bin/openssl", f"enc -pass pass:{_G} -in f", "-in f"),
        # The review of T07-5: more tools, and values with spaces after user flags.
        ("/usr/bin/podman", f"login -u me -p {_G} registry.invalid", "registry.invalid"),
        ("/usr/bin/helm", f"registry login -u me -p {_G} r.invalid", "r.invalid"),
        ("/usr/bin/ldapsearch", f"-x -D cn=admin -w {_G} -b dc=x", "cn=admin"),
        ("/usr/bin/sqlcmd", f"-S db.invalid -U sa -P {_G} -Q x", "-Q x"),
        ("/usr/bin/ipmitool", f"-U admin -P {_G} power status", "power status"),
        ("/usr/bin/mosquitto_pub", f"-u me -P {_G} -t t", "-t t"),
        ("/usr/bin/zip", f"-P {_G} out.zip a.txt", "out.zip"),
        ("/usr/bin/7z", f"a -p{_G} out.7z", "out.7z"),
        ("/usr/bin/openssl", f"enc -aes-256-cbc -k {_G} -in f", "-in f"),
        ("/usr/bin/ssh-keygen", f"-t ed25519 -N {_G} -f key", "-f key"),
        ("/usr/bin/curl", f"-E cert.pem:{_G} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/curl", f'-u "alice:pw {_G}" https://x.invalid/', "https://x.invalid/"),
        ("/usr/bin/curl", f'"--user=alice:pw {_G}" https://x.invalid/', "https://x.invalid/"),
        ("/usr/bin/sqlplus", f"scott/{_G}@orcl @run.sql", "@run.sql"),
        ("/usr/bin/gh", f"secret set T --body {_G}", "secret set"),
        ("/usr/bin/vault", f"login {_G}", "login"),
        ("/usr/sbin/htpasswd", f"-nb alice {_G}", "alice"),
        ("/usr/bin/nmcli", f"dev wifi connect home password {_G}", "connect home"),
        ("/usr/bin/xfreerdp", f"/v:h /u:me /p:{_G}", "/u:me"),
        ("/usr/bin/aws", f"configure set aws_secret_access_key {_G}", "configure set"),
        ("/usr/bin/mysql", f"-e \"CREATE USER u IDENTIFIED BY '{_G}'\"", "CREATE USER"),
        ("/usr/bin/psql", f"-c \"ALTER USER u WITH PASSWORD '{_G}'\"", "ALTER USER"),
        ("/bin/sh", f'-c "docker login -u me -p {_G} r.invalid && docker push x"', "push x"),
        ("/bin/sh", f"-c \"curl -u 'alice:pw {_G}' https://x.invalid/\"", "x.invalid"),
        ("/bin/sh", f'-c "ldapsearch -x -w {_G} -b dc=x; ls"', "; ls"),
    ],
)
def test_the_redaction_rules_strike_glued_passwords(binary: str, arguments: str, kept: str) -> None:
    struck = _tetragon_redact(arguments, binary)
    assert _G not in struck and _G2 not in struck, struck
    assert kept in struck, struck


@pytest.mark.parametrize(
    ("binary", "arguments"),
    [
        ("/usr/bin/ssh", "-p2222 user@host.invalid"),
        ("/bin/mkdir", "-pmode /w/x"),
        ("/usr/bin/mysql", '-p "my db"'),
        ("/bin/sh", '-c "mysql shop; mkdir -pnew /w/x"'),
        ("/bin/sh", "-c 'git checkout -b x && rm -rf /w'"),
        ("/bin/sh", '-c "sort -b list; rm -rf /w"'),
        ("/usr/bin/docker", "run -p 8080:80 nginx"),
        ("/bin/sh", '-c "docker run -p 8080:80 nginx"'),
        ("/usr/bin/vault", "login -method=oidc"),
        ("/usr/bin/zip", "-r out.zip dir"),
    ],
)
def test_the_redaction_rules_leave_ordinary_flags(binary: str, arguments: str) -> None:
    assert _tetragon_redact(arguments, binary) == arguments


def test_every_rule_is_re2_shaped() -> None:
    """RE2 has no lookaround and no backreference: Tetragon would refuse to start."""
    rules = [rule for rules in REDACTION_RULES for rule in rules]
    rules += [rule for _, rules in REDACTION_TOOL_RULES for rule in rules]
    rules += [binary for binary, _ in REDACTION_TOOL_RULES]
    for rule in rules:
        assert not re.search(r"\(\?<?[=!]|\\[1-9]|\(\?P=", rule), rule
        assert re.compile(rule).groups >= (0 if rule.startswith("(?:^|/)") else 1), rule


# --- the connect policy ---------------------------------------------------------------------


def test_the_policy_lives_in_deploy_and_is_the_tested_one() -> None:
    assert POLICY_FILE == Path(__file__).resolve().parents[1] / "deploy" / "tetragon" / (
        "backtide-connect.yaml"
    )
    text = policy_text()
    assert 'name: "backtide-connect"' in text
    assert "vigia" not in text
    assert 'call: "security_socket_connect"' in text
    # T07-1, P7: argument 0 is a struct socket *, not a struct sock *.
    assert re.search(r'- index: 0\s+type: "socket"', text)
    assert re.search(r'- index: 1\s+type: "sockaddr"', text)
    assert 'values: ["AF_INET", "AF_INET6"]' in text
    assert re.search(r'operator: NotIn\s+values: \["host_ns"\]', text)
    for verb in ("Sigkill", "Override", "NotifyEnforcer"):  # only observe (decision 11)
        assert verb not in text


def test_the_policy_is_pinned_by_its_hash() -> None:
    """T07-2's review: the policy is code loaded into the kernel by a privileged container,
    so a file changed on the disk is refused instead of loaded."""
    assert hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest() == POLICY_SHA256


def test_a_changed_policy_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    changed = tmp_path / "backtide-connect.yaml"
    changed.write_text(POLICY_FILE.read_text() + "  # one more line\n")
    monkeypatch.setattr(sensor_jail, "POLICY_FILE", changed)
    with pytest.raises(JailError, match="sha256"):
        policy_text()


def test_the_events_file_is_root_only_unless_a_test_says_otherwise() -> None:
    """The VM tests run without root and must read Tetragon's file: a test-only concession,
    never in the TOML (like the agent's allow_shared_ids)."""
    assert sensor_settings(CONFIG)["export-file-perm"] == "600"
    assert sensor_settings(replace(CONFIG, file_perm="644"))["export-file-perm"] == "644"


# --- prepare: the folders and the files -----------------------------------------------------


def _jail(tmp_path: Path, **change: Any) -> SensorJail:
    btf = tmp_path / "vmlinux"
    btf.write_bytes(b"BTF")
    return SensorJail(SensorJailConfig(state_dir=tmp_path / "sensor", btf=btf, **change))


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_prepare_creates_the_folders_and_writes_the_settings(tmp_path: Path) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    config = jail.config
    assert _mode(config.state_dir) == 0o700
    assert _mode(config.events_dir) == 0o700
    assert _mode(config.tp_dir) == 0o755
    assert _mode(config.conf_dir) == 0o755
    settings = sensor_settings(config)
    assert sorted(os.listdir(config.conf_dir)) == sorted(settings)
    for name, value in settings.items():
        assert (config.conf_dir / name).read_text() == value
        assert _mode(config.conf_dir / name) == 0o644
    assert os.listdir(config.tp_dir) == ["backtide-connect.yaml"]
    assert (config.tp_dir / "backtide-connect.yaml").read_text() == policy_text()


def test_prepare_rewrites_whatever_was_left_on_disk(tmp_path: Path) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    config = jail.config
    (config.conf_dir / "enable-process-environment-variables").write_text("true")
    (config.conf_dir / "log-level").write_text("debug")
    (config.tp_dir / "kill-everything.yaml").write_text("Sigkill")
    os.chmod(config.events_dir, 0o777)  # noqa: S103 - prepare() must put it back
    jail.prepare()
    assert "enable-process-environment-variables" not in os.listdir(config.conf_dir)
    assert (config.conf_dir / "log-level").read_text() == "warn"
    assert os.listdir(config.tp_dir) == ["backtide-connect.yaml"]
    assert _mode(config.events_dir) == 0o700


def test_prepare_keeps_the_events(tmp_path: Path) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    log = jail.config.events_dir / "tetragon.log"
    log.write_text('{"x":1}\n')
    jail.prepare()
    assert log.read_text() == '{"x":1}\n'


@pytest.mark.parametrize("folder", ["events", "tp.d", "conf.d"])
def test_prepare_refuses_a_symlinked_folder(tmp_path: Path, folder: str) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    target = tmp_path / "elsewhere"
    target.mkdir()
    path = jail.config.state_dir / folder
    for entry in path.iterdir():
        entry.unlink()
    path.rmdir()
    path.symlink_to(target)
    with pytest.raises(JailError):
        jail.prepare()
    assert not any(target.iterdir())


def test_prepare_refuses_a_directory_inside_conf_d(tmp_path: Path) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    (jail.config.conf_dir / "strange").mkdir()
    with pytest.raises(JailError):
        jail.prepare()


def test_prepare_needs_the_parent_of_the_state_dir(tmp_path: Path) -> None:
    jail = SensorJail(SensorJailConfig(state_dir=tmp_path / "missing" / "sensor"))
    with pytest.raises(JailError):
        jail.prepare()


# --- the lifecycle, with a fake docker -----------------------------------------------------


class FakeDocker:
    """Answers ``docker`` calls from a table of (prefix, stdout, stderr, returncode)."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.answers: list[tuple[tuple[str, ...], str, str, int]] = []

    def answer(self, *prefix: str, stdout: str = "", stderr: str = "", code: int = 0) -> None:
        self.answers.insert(0, (prefix, stdout, stderr, code))

    def __call__(
        self, args: list[str], *, check: bool = True, **_: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        for prefix, stdout, stderr, code in self.answers:
            if tuple(args[: len(prefix)]) == prefix:
                if check and code != 0:
                    raise JailError(f"docker {args[0]} failed", returncode=code, stderr=stderr)
                return subprocess.CompletedProcess(args, code, stdout, stderr)
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake = FakeDocker()
    monkeypatch.setattr(docker, "run", fake)
    return fake


NO_SUCH = "Error response from daemon: No such container: backtide-sensor"


def _good_info(config: SensorJailConfig) -> dict[str, Any]:
    """What ``docker container inspect`` shows for a container made by sensor_create_argv
    (Docker 29; the daemon adds label=disable for privileged containers on SELinux hosts)."""
    return {
        "Id": SENSOR_ID,
        "Config": {
            "Image": config.image,
            "User": "",
            "Entrypoint": ["/usr/bin/tetragon"],
            "Cmd": None,
            "Env": list(IMAGE_ENV),
            "StopTimeout": 10,
        },
        "HostConfig": {
            "Binds": volume_binds(config),
            "CapAdd": None,
            "CapDrop": None,
            "Cgroup": "",
            "CgroupnsMode": "host",
            "DeviceCgroupRules": None,
            "DeviceRequests": None,
            "Devices": [],
            "ExtraHosts": None,
            "GroupAdd": None,
            "IpcMode": "private",
            "Links": None,
            "LogConfig": {"Type": "local", "Config": {"max-file": "3", "max-size": "10m"}},
            "Memory": 1073741824,
            "MemorySwap": 1073741824,
            "NanoCpus": 1000000000,
            "NetworkMode": "none",
            "OomKillDisable": False,
            "PidMode": "host",
            "PortBindings": {},
            "Privileged": True,
            "PublishAllPorts": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "SecurityOpt": ["label=disable"],
            "Sysctls": None,
            "Tmpfs": None,
            "UTSMode": "",
            "UsernsMode": "",
            "VolumeDriver": "",
            "VolumesFrom": None,
            "Mounts": None,
        },
        "NetworkSettings": {"Networks": {"none": {}}},
        "Mounts": [{"Type": "bind", "Source": b.split(":")[0]} for b in volume_binds(config)],
    }


def _ready_docker(fake: FakeDocker, config: SensorJailConfig, info: dict[str, Any]) -> None:
    fake.answer("container", "inspect", "--format", "{{json .}}", stdout=json.dumps(info))
    fake.answer("image", "inspect", stdout=json.dumps(IMAGE_ENV))


def test_create_runs_the_argv_after_checking_the_sources(
    tmp_path: Path, fake_docker: FakeDocker
) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    jail.create()
    assert fake_docker.calls == [sensor_create_argv(jail.config)]


def test_create_refuses_missing_sources(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    with pytest.raises(JailError):
        jail.create()  # prepare() never ran
    jail.prepare()
    jail.config.btf.unlink()
    with pytest.raises(JailError):
        jail.create()
    assert fake_docker.calls == []


def test_create_refuses_a_btf_that_is_not_a_file(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    jail.config.btf.unlink()
    jail.config.btf.mkdir()
    with pytest.raises(JailError):
        jail.create()


def test_start_checks_the_container_first(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    _ready_docker(fake_docker, jail.config, _good_info(jail.config))
    jail.start()
    assert fake_docker.calls[-1] == ["start", "backtide-sensor"]


def test_start_refuses_a_container_that_is_not_the_sensor(
    tmp_path: Path, fake_docker: FakeDocker
) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    info = _good_info(jail.config)
    info["HostConfig"]["Binds"].append("/var/run/docker.sock:/var/run/docker.sock")
    _ready_docker(fake_docker, jail.config, info)
    with pytest.raises(JailError, match="docker.sock"):
        jail.start()
    assert ["start", "backtide-sensor"] not in fake_docker.calls


def test_start_refuses_a_missing_container(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    jail.prepare()
    fake_docker.answer("container", "inspect", stderr=NO_SUCH, code=1)
    with pytest.raises(JailError, match="does not exist"):
        jail.start()


def test_state_queries(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    fake_docker.answer("container", "inspect", stderr=NO_SUCH, code=1)
    assert jail.exists() is False
    assert jail.is_running() is False
    assert jail.container_id() is None
    fake_docker.answer(
        "container", "inspect", "--format", "{{json .State}}", stdout='{"Running": true}'
    )
    fake_docker.answer("container", "inspect", "--format", "{{json .Id}}", stdout=f'"{SENSOR_ID}"')
    assert jail.exists() is True
    assert jail.is_running() is True
    assert jail.container_id() == SENSOR_ID


def test_container_id_refuses_odd_output(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    fake_docker.answer("container", "inspect", "--format", "{{json .Id}}", stdout='"abc"')
    with pytest.raises(JailError):
        jail.container_id()


def test_a_daemon_error_is_not_a_missing_container(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    fake_docker.answer("container", "inspect", stderr="Cannot connect to the Docker daemon", code=1)
    with pytest.raises(JailError):
        jail.is_running()


def test_stop_and_remove(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    jail.stop()
    jail.remove()
    assert fake_docker.calls == [
        ["stop", "--time", "10", "backtide-sensor"],
        ["rm", "--force", "--volumes", "backtide-sensor"],
    ]


# --- verify ---------------------------------------------------------------------------------


def _problems(mutate: Callable[[dict[str, Any]], None]) -> list[str]:
    info = _good_info(CONFIG)
    mutate(info)
    return sensor_container_problems(CONFIG, info, image_env=IMAGE_ENV)


def test_verify_accepts_the_sensor_it_creates() -> None:
    assert _problems(lambda info: None) == []


def test_verify_accepts_no_security_options_on_a_host_without_selinux() -> None:
    assert _problems(lambda info: info["HostConfig"].update(SecurityOpt=None)) == []


def _set(section: str, **values: Any) -> Callable[[dict[str, Any]], None]:
    return lambda info: info[section].update(values)


@pytest.mark.parametrize(
    "mutate",
    [
        _set("Config", Image="quay.io/cilium/tetragon:latest"),
        _set("Config", User="1000"),
        _set("Config", Entrypoint=["sh"]),
        _set("Config", Cmd=["-c", "cat /etc/shadow"]),
        _set("Config", Env=[*IMAGE_ENV, "TETRAGON_ENABLE_PROCESS_ENVIRONMENT_VARIABLES=true"]),
        _set("Config", StopTimeout=1),
        _set("HostConfig", Privileged=False),
        _set("HostConfig", PidMode=""),
        _set("HostConfig", CgroupnsMode="private"),
        _set("HostConfig", NetworkMode="bridge"),
        _set("HostConfig", Binds=volume_binds(CONFIG)[:3]),
        _set("HostConfig", Binds=[*volume_binds(CONFIG), "/var/lib/backtide:/backtide"]),
        _set("HostConfig", Binds=[b.replace(":ro", "") for b in volume_binds(CONFIG)]),
        _set("HostConfig", Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}]),
        _set("HostConfig", PortBindings={"6789/tcp": [{"HostPort": "6789"}]}),
        _set("HostConfig", PublishAllPorts=True),
        _set("HostConfig", CapAdd=["SYS_ADMIN"]),
        _set("HostConfig", Devices=[{"PathOnHost": "/dev/sda"}]),
        _set("HostConfig", VolumesFrom=["backtide-agente"]),
        _set("HostConfig", ExtraHosts=["x:1.2.3.4"]),
        _set("HostConfig", Tmpfs={"/x": ""}),
        _set("HostConfig", SecurityOpt=["seccomp=unconfined"]),
        _set("HostConfig", SecurityOpt=["label=disable", "apparmor=unconfined"]),
        _set("HostConfig", UTSMode="host"),
        _set("HostConfig", UsernsMode="host"),
        _set("HostConfig", IpcMode="host"),
        _set("HostConfig", RestartPolicy={"Name": "always"}),
        _set("HostConfig", Memory=0),
        _set("HostConfig", NanoCpus=0),
        _set("HostConfig", LogConfig={"Type": "json-file", "Config": {}}),
        _set("NetworkSettings", Networks={"none": {}, "backtide-agente-net": {}}),
        _set("Config", Healthcheck={"Test": ["CMD", "sh", "-c", "id"]}),
        _set("HostConfig", Runtime="runsc"),
        _set("HostConfig", CgroupParent="/elsewhere"),
        lambda info: info["Mounts"].append({"Type": "volume", "Name": "x"}),
        lambda info: info.pop("Mounts"),
    ],
)
def test_verify_refuses_every_difference(mutate: Callable[[dict[str, Any]], None]) -> None:
    assert _problems(mutate)


def test_verify_never_quotes_an_environment_value() -> None:
    problems = _problems(_set("Config", Env=[*IMAGE_ENV, "SOME_TOKEN=fake-secret-value"]))
    assert problems and "fake-secret-value" not in " ".join(problems)


def test_verify_with_a_lowered_config() -> None:
    config = replace(CONFIG, memory="512m", cpus="0.5", name="backtide-sensor-test")
    info = _good_info(config)
    info["HostConfig"].update(Memory=512 * 1024**2, MemorySwap=512 * 1024**2, NanoCpus=500_000_000)
    assert sensor_container_problems(config, info, image_env=IMAGE_ENV) == []


# --- serving: Tetragon answers and its policy is on (T07-3) ---------------------------------

TETRA = (
    "exec",
    "backtide-sensor",
    "tetra",
    "--server-address",
    "unix:///var/run/tetragon/tetragon.sock",
)


def test_serving_needs_the_status_and_the_policy(tmp_path: Path, fake_docker: FakeDocker) -> None:
    jail = _jail(tmp_path)
    fake_docker.answer(*TETRA, "status", stdout="Health Status: running\n")
    fake_docker.answer(
        *TETRA, "tracingpolicy", "list", stdout="ID NAME STATE\n1 backtide-connect enabled\n"
    )
    assert jail.serving() is True
    assert [call[:6] for call in fake_docker.calls] == [list(TETRA) + ["status"]] + [
        list(TETRA) + ["tracingpolicy"]
    ]


@pytest.mark.parametrize(
    ("status", "policies", "code"),
    [
        ("Health Status: starting", "1 backtide-connect enabled", 0),
        ("Health Status: running", "1 backtide-connect error", 0),
        ("Health Status: running", "", 0),
        ("Health Status: running", "1 backtide-connect enabled", 1),
        ("Health Status: not running", "1 backtide-connect enabled", 0),
        ("Health Status: running", "1 backtide-connect-old enabled", 0),
        ("Health Status: running", "1 backtide-connect disabled-enabled", 0),
    ],
)
def test_not_serving(
    tmp_path: Path, fake_docker: FakeDocker, status: str, policies: str, code: int
) -> None:
    jail = _jail(tmp_path)
    fake_docker.answer(*TETRA, "status", stdout=status)
    fake_docker.answer(*TETRA, "tracingpolicy", "list", stdout=policies, code=code)
    assert jail.serving() is False


def test_serving_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise JailError("docker exec timed out")

    monkeypatch.setattr(docker, "run", broken)
    assert _jail(tmp_path).serving() is False


# --- T07 review: the forms only the second barrier knew, and Tetragon's loss counters --------


REVIEW_FAKE = {
    "env": "Lp4TzW8nBc3YdF6hJs1QaE",
    "secret_env": "Gq7vR2mX9kLp4TzW8nBc",
    "user_u": "R2mX9kLp4TzW8nBc3Yd",
    "user_long": "W8nBc3YdF6hJs1QaEGq",
    "telegram": "AAHx7Kp2Lq9Zr4Mw8Nt3Vb6Yc1Df5Gh0Jq",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.Rk3Vb6Yc1Df5Gh0Jx7Kp",
    "aiza": "AIzaSyD8nBc3YdF6hJs1QaEGq7vR2mX9kLp4TzW",
    "xox": "xoxb-123456789012-Bc3YdF6hJs1QaEGq7vR2",
    "stripe": "sk_live_Bc3YdF6hJs1QaEGq7vR2",
    "ghpat": "github_pat_Bc3YdF6hJs1QaEGq7vR2mX9kLp4",
    "glpat": "glpat-Bc3YdF6hJs1QaEGq7vR2",
    "asia": "ASIAQQQQQQQQQQQQQQQQ",
    "bearer_plain": "Bc3YdF6hJs1QaEGq7vR2mX",
    "xauth": "YdF6hJs1QaEGq7vR2mX9",
    "client_secret": "hJs1QaEGq7vR2mX9kLp4",
}


def test_the_redaction_rules_strike_what_only_backtide_struck_before() -> None:
    f = REVIEW_FAKE
    arguments = " ".join(
        [
            f"API_KEY={f['env']}",
            f"MY_SECRET={f['secret_env']}",
            "-u",
            f"alice:{f['user_u']}",
            f"--user=bob:{f['user_long']}",
            f"123456789:{f['telegram']}",
            f["jwt"],
            f["aiza"],
            f["xox"],
            f["stripe"],
            f["ghpat"],
            f["glpat"],
            f["asia"],
            f'"Bearer {f["bearer_plain"]}"',
            f'"X-Auth-Token: {f["xauth"]}"',
            f"https://x.invalid/?client_secret={f['client_secret']}&keep=visible",
            "plain-word-kept",
        ]
    )
    struck = _tetragon_redact(arguments)
    assert not [name for name, value in f.items() if value in struck], struck
    assert "keep=visible" in struck and struck.endswith("plain-word-kept")
    assert struck.startswith("API_KEY=***** MY_SECRET=*****")


def test_the_new_rules_do_not_strike_ordinary_arguments() -> None:
    ordinary = "ls -la /tmp --color=auto input_tokens=5 git commit -m 'fix: 12:30 meeting'"
    assert _tetragon_redact(ordinary) == ordinary


METRICS_TEXT = """# HELP tetragon_bpf_missed_events_total Number of failed perf events
tetragon_bpf_missed_events_total{error="EAGAIN",msg_op="13"} 371099
tetragon_bpf_missed_events_total{error="EAGAIN",msg_op="5"} 10
tetragon_notify_overflowed_events_total 143854
tetragon_observer_ringbuf_errors_total 0
tetragon_observer_ringbuf_events_lost_total 0
tetragon_observer_ringbuf_events_received_total 429620
tetragon_observer_ringbuf_queue_events_lost_total 169260
tetragon_export_ratelimit_events_dropped_total 0
tetragon_events_total{binary="/usr/bin/x",type="PROCESS_EXEC"} 3
"""

METRICS_CALL = (
    "exec",
    "backtide-sensor",
    "wget",
    "-q",
    "-O",
    "-",
    "http://127.0.0.1:2112/metrics",
)


def test_the_loss_counters_are_read_from_the_metrics(
    tmp_path: Path, fake_docker: FakeDocker
) -> None:
    fake_docker.answer(*METRICS_CALL, stdout=METRICS_TEXT)
    assert _jail(tmp_path).loss_counters() == {
        "kernel": 371109,
        "notify": 143854,
        "ringbuf": 0,
        "queue": 169260,
        "export": 0,
    }
    assert fake_docker.calls == [list(METRICS_CALL)]


def test_a_missing_kernel_counter_is_zero(tmp_path: Path, fake_docker: FakeDocker) -> None:
    text = "\n".join(line for line in METRICS_TEXT.splitlines() if "bpf_missed" not in line)
    fake_docker.answer(*METRICS_CALL, stdout=text)
    assert _jail(tmp_path).loss_counters()["kernel"] == 0


@pytest.mark.parametrize(
    ("stdout", "code"),
    [
        ("", 0),
        ("tetragon_events_total 3\n", 0),
        (METRICS_TEXT, 1),
        ("tetragon_notify_overflowed_events_total NaN\n" + METRICS_TEXT, 0),
    ],
)
def test_odd_metrics_are_an_error(
    tmp_path: Path, fake_docker: FakeDocker, stdout: str, code: int
) -> None:
    fake_docker.answer(*METRICS_CALL, stdout=stdout, code=code)
    with pytest.raises(JailError):
        _jail(tmp_path).loss_counters()


def test_what_the_agent_puts_in_other_metrics_cannot_break_the_reading(
    tmp_path: Path, fake_docker: FakeDocker
) -> None:
    """Re-review M1: a binary named "x}y" in a label, or a float in any notation."""
    hostile = (
        'tetragon_events_total{binary="/tmp/x}y",type="PROCESS_EXEC"} 3\n'
        'tetragon_events_total{binary="/tmp/a b c"} 1.2e-05\n'
        "tetragon_notify_overflowed_events_total 1.2e+01\n"
    )
    fake_docker.answer(*METRICS_CALL, stdout=hostile + METRICS_TEXT)
    counters = _jail(tmp_path).loss_counters()
    assert counters["notify"] == 143854 + 12


def test_an_odd_loss_line_is_an_error_without_the_line(
    tmp_path: Path, fake_docker: FakeDocker
) -> None:
    fake_docker.answer(
        *METRICS_CALL, stdout='tetragon_notify_overflowed_events_total{x="secretX"} bad\n'
    )
    with pytest.raises(JailError) as raised:
        _jail(tmp_path).loss_counters()
    assert "secretX" not in str(raised.value)
