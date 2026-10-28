"""The self-test of an installed backtide (T13-3): what each check makes of what it reads."""

from collections.abc import Sequence

import pytest

from backtide.setup import layout, selftest, units
from backtide.setup.host import Ran
from backtide.setup.preflight import Status

STATUS = """Name:\tnode
Uid:\t61000\t61000\t61000\t61000
Gid:\t61000\t61000\t61000\t61000
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t2
"""
SELINUX_LABEL = "system_u:system_r:container_t:s0:c517,c963"


def runner(answers: dict[tuple[str, ...], Ran]):
    def run(argv: Sequence[str]) -> Ran | None:
        return answers.get(tuple(argv))

    return run


def test_the_agent_as_t13_1_saw_it_is_ok() -> None:
    check = selftest.identity(STATUS, SELINUX_LABEL, selinux=True, apparmor=False, uid=61000)
    assert check.status is Status.OK and "container_t" in check.summary
    check = selftest.identity(STATUS, "docker-default (enforce)", selinux=False, apparmor=True,
                              uid=61000)  # fmt: skip
    assert check.status is Status.OK


@pytest.mark.parametrize(
    ("status", "label", "said"),
    [
        (STATUS.replace("Uid:\t61000\t61000", "Uid:\t0\t61000"), SELINUX_LABEL, "ids"),
        (STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t00000000a80425fb"), SELINUX_LABEL,
         "capacidades"),
        (STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), SELINUX_LABEL, "NoNewPrivs"),
        # T13-1, P6: Docker without selinux-enabled runs the agent as spc_t, silently
        (STATUS, "system_u:system_r:spc_t:s0", "SELinux"),
        ("", "", "ids"),
    ],
)  # fmt: skip
def test_an_agent_that_is_not_jailed_fails(status: str, label: str, said: str) -> None:
    check = selftest.identity(status, label, selinux=True, apparmor=False, uid=61000)
    assert check.status is Status.FAIL and said in check.summary


def test_an_agent_without_its_apparmor_profile_is_a_warning() -> None:
    check = selftest.identity(STATUS, "unconfined", selinux=False, apparmor=True, uid=61000)
    assert check.status is Status.WARN


@pytest.mark.parametrize(
    ("printed", "status"),
    [
        ("ENETUNREACH ENETUNREACH", Status.OK),
        ("timeout ECONNREFUSED", Status.OK),
        ("connected ENETUNREACH", Status.FAIL),
        ("ENETUNREACH connected", Status.FAIL),
        ("", Status.FAIL),
        ("python3: not found", Status.FAIL),
    ],
)
def test_egress_never_connects(printed: str, status: Status) -> None:
    assert selftest.egress(printed).status is status


def test_the_probe_aims_at_nothing_real() -> None:
    import ipaddress

    assert ipaddress.ip_address(selftest.TEST_NET) in ipaddress.ip_network("192.0.2.0/24")
    assert "connect" in selftest._CONNECT_PROBE  # noqa: SLF001


def test_units_must_all_be_active() -> None:
    names = (units.volume_unit_name(), units.channel_unit_name(), layout.SERVICE_UNIT,
             layout.WEB_UNIT)  # fmt: skip
    answers = {("systemctl", "is-active", name): Ran(0, "active\n", "") for name in names}
    assert selftest.unit_states(runner(answers)).status is Status.OK
    answers[("systemctl", "is-active", layout.WEB_UNIT)] = Ran(3, "failed\n", "")
    check = selftest.unit_states(runner(answers))
    assert check.status is Status.FAIL and "backtide-web.service (failed)" in check.summary


def test_the_volume_must_be_btrfs_with_its_options(tmp_path) -> None:
    argv = ("findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--mountpoint", str(tmp_path))
    good = "btrfs rw,nosuid,nodev,noatime,discard=async,space_cache=v2\n"
    assert selftest.mount_options(runner({argv: Ran(0, good, "")}), tmp_path).status is Status.OK
    bad = "btrfs rw,nodev,noatime\n"
    check = selftest.mount_options(runner({argv: Ran(0, bad, "")}), tmp_path)
    assert check.status is Status.FAIL and "nosuid" in check.summary
    assert selftest.mount_options(runner({}), tmp_path).status is Status.FAIL


def test_the_security_level_against_its_threshold() -> None:
    text = (
        "  NAME  DESCRIPTION  EXPOSURE\n→ Overall exposure level for backtide.service: 3.1 OK :-)\n"
    )
    assert selftest.security_level(text) == 3.1
    assert selftest.security_level("nothing here") is None
    service = ("systemd-analyze", "security", "--no-pager", layout.SERVICE_UNIT)
    web = ("systemd-analyze", "security", "--no-pager", layout.WEB_UNIT)
    found = selftest.security(runner({
        service: Ran(0, text, ""),
        web: Ran(0, "→ Overall exposure level for backtide-web.service: 9.6 UNSAFE\n", ""),
    }))  # fmt: skip
    assert [check.status for check in found] == [Status.OK, Status.FAIL]
    assert selftest.security(runner({}))[0].status is Status.WARN


def test_the_host_address_is_never_loopback_or_dockers() -> None:
    import json

    links = [
        {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
        {"ifname": "docker0", "addr_info": [{"local": "172.17.0.1"}]},
        {"ifname": "eth0", "addr_info": [{"local": "192.168.5.15"}]},
    ]
    run = runner({("ip", "-j", "-4", "addr", "show"): Ran(0, json.dumps(links), "")})
    assert selftest.host_address(run) == "192.168.5.15"


def test_the_thresholds_are_the_measured_levels_plus_a_little() -> None:
    """docs/25, "Resultados de T13-3": 3.1 and 1.2 on systemd 255 and 259. Losing a directive
    moves the level up by more than the margin."""
    assert selftest.SECURITY_THRESHOLDS == {layout.SERVICE_UNIT: 3.2, layout.WEB_UNIT: 1.3}


def test_a_link_in_the_webs_journal_is_seen() -> None:
    """The web prints its run name to the journal, never its link (`--enlace-en`)."""
    printed = "Puesto de vigilancia listo, solo en este ordenador. Ejecución: pino-faro-brisa."
    assert not selftest.link_in_journal(printed)
    assert selftest.link_in_journal("  http://127.0.0.1:8765/s/AbCd/?t=TTTT\n")


def test_the_health_probe_is_judged_as_the_service_judges_it() -> None:
    """D27: Claude Code's probe is `claude --version`, and only the pinned version is healthy
    (the service's own reading, jail/agent.py); OpenClaw's answers by its exit code."""
    import subprocess

    from backtide.jail.profiles import CLAUDE_CODE, OPENCLAW
    from backtide.jail.profiles.claude_code import CLAUDE_CODE_VERSION

    def done(code: int, out: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, out, "")

    assert selftest.probe_answers(CLAUDE_CODE, done(0, f"{CLAUDE_CODE_VERSION} (Claude Code)\n"))
    assert not selftest.probe_answers(CLAUDE_CODE, done(0, "2.0.1 (Claude Code)\n"))
    assert not selftest.probe_answers(CLAUDE_CODE, done(1, f"{CLAUDE_CODE_VERSION} (Claude Code)"))
    assert selftest.probe_answers(OPENCLAW, done(0, '{"ok":true}'))
    assert not selftest.probe_answers(OPENCLAW, done(7, ""))
