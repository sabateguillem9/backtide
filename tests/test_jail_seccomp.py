"""Unit tests for the agent's seccomp profile: Docker's default plus the Btrfs ioctl block and
the copy_file_range block.

The VM test (tests/integration/test_jail.py) proves the kernel enforces it; these prove the
profile shipped in deploy/seccomp is exactly what the generator makes, and that its ioctl rules
never overlap, for every ioctl type."""

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from backtide.jail import config as jail_config
from backtide.jail import seccomp
from backtide.jail.seccomp import (
    ALLOW,
    BLOCKED_ERRNO,
    COPY_FILE_RANGE_ERRNO,
    ERRNO,
    SeccompProfileError,
    agent_profile,
    evaluate_ioctl,
    evaluate_syscall,
    render,
)

SECCOMP_DIR = Path(__file__).resolve().parents[1] / "deploy" / "seccomp"
DOCKER_DEFAULT = SECCOMP_DIR / "docker-default.json"
AGENT = SECCOMP_DIR / "agent.json"
REGENERATE = SECCOMP_DIR / "regenerate.sh"
LINUX_EOPNOTSUPP = 95
LINUX_EPERM = 1
LINUX_EXDEV = 18

BLOCKED = {
    "BTRFS_IOC_SUBVOL_CREATE": 0x5000940E,
    "BTRFS_IOC_SNAP_CREATE": 0x50009401,
    "BTRFS_IOC_SNAP_CREATE_V2": 0x50009417,
    "BTRFS_IOC_SUBVOL_CREATE_V2": 0x50009418,
    "BTRFS_IOC_SNAP_DESTROY": 0x5000940F,
    "BTRFS_IOC_SUBVOL_SETFLAGS": 0x4008941A,
    "FICLONE": 0x40049409,
    "FICLONERANGE": 0x4020940D,
    "FIDEDUPERANGE": 0xC0189436,
}
ALLOWED = {
    "TCGETS": 0x5401,
    "TIOCGWINSZ": 0x5413,
    "FIONREAD": 0x541B,
    "FIONBIO": 0x5421,
    "FS_IOC_GETFLAGS": 0x80086601,
    "FS_IOC_FIEMAP": 0xC020660B,
    "SIOCGIFCONF": 0x8912,
}


@pytest.fixture(scope="module")
def docker_default() -> dict:
    return json.loads(DOCKER_DEFAULT.read_text())


@pytest.fixture(scope="module")
def shipped() -> dict:
    return json.loads(AGENT.read_text())


# The shipped file


def test_shipped_profile_is_exactly_what_the_generator_makes(docker_default: dict) -> None:
    assert AGENT.read_text() == render(agent_profile(docker_default))


def test_docker_default_is_the_pinned_copy() -> None:
    script = REGENERATE.read_text()
    expected = re.search(r'^DOCKER_DEFAULT_SHA256="([0-9a-f]{64})"$', script, re.MULTILINE)
    assert expected is not None
    assert hashlib.sha256(DOCKER_DEFAULT.read_bytes()).hexdigest() == expected.group(1)


def test_config_points_at_the_shipped_profile() -> None:
    assert jail_config.SECCOMP_PROFILE == AGENT


def test_only_ioctl_and_copy_file_range_change(docker_default: dict, shipped: dict) -> None:
    original = copy.deepcopy(docker_default)
    original["syscalls"][0]["names"].remove("ioctl")
    original["syscalls"][0]["names"].remove("copy_file_range")
    assert shipped["syscalls"][: len(original["syscalls"])] == original["syscalls"]
    added = shipped["syscalls"][len(original["syscalls"]) :]
    assert added == [*seccomp.ioctl_rules(), seccomp.copy_file_range_rule()]
    assert {k: v for k, v in shipped.items() if k != "syscalls"} == {
        k: v for k, v in docker_default.items() if k != "syscalls"
    }


def test_ioctl_is_never_allowed_unconditionally(shipped: dict) -> None:
    unconditional = [r for r in shipped["syscalls"] if "ioctl" in r["names"] and not r.get("args")]
    assert unconditional == []


def test_copy_file_range_is_never_allowed(shipped: dict) -> None:
    allowing = [
        r for r in shipped["syscalls"] if "copy_file_range" in r["names"] and r["action"] == ALLOW
    ]
    assert allowing == []


# The rules


def test_copy_file_range_fails_with_linux_exdev(shipped: dict) -> None:
    """On Btrfs it makes reflinks, which the space cap does not charge (docs/16, A11). EXDEV
    is what it returns across filesystems, so cp, libuv and Node copy by reading and writing."""
    assert COPY_FILE_RANGE_ERRNO == LINUX_EXDEV
    assert evaluate_syscall(shipped, "copy_file_range") == (ERRNO, LINUX_EXDEV)


def test_other_syscalls_keep_dockers_action(docker_default: dict, shipped: dict) -> None:
    for name in ("read", "sendfile", "splice", "openat"):
        assert (
            evaluate_syscall(shipped, name)
            == evaluate_syscall(docker_default, name)
            == (
                ALLOW,
                None,
            )
        )


def test_the_naive_copy_file_range_rule_would_overlap(docker_default: dict) -> None:
    naive = copy.deepcopy(docker_default)
    naive["syscalls"].append(seccomp.copy_file_range_rule())
    with pytest.raises(SeccompProfileError, match="overlapping"):
        evaluate_syscall(naive, "copy_file_range")


def test_blocked_errno_is_linux_eopnotsupp() -> None:
    # Written out on purpose: Python's errno module gives the host's value (102 on macOS).
    assert BLOCKED_ERRNO == LINUX_EOPNOTSUPP


@pytest.mark.parametrize("name", BLOCKED)
def test_btrfs_and_clone_ioctls_are_blocked(shipped: dict, name: str) -> None:
    assert evaluate_ioctl(shipped, BLOCKED[name]) == (ERRNO, LINUX_EOPNOTSUPP)


@pytest.mark.parametrize("name", ALLOWED)
def test_other_ioctls_are_allowed(shipped: dict, name: str) -> None:
    assert evaluate_ioctl(shipped, ALLOWED[name]) == (ALLOW, None)


@pytest.mark.parametrize("type_byte", range(256))
def test_exactly_one_rule_matches_every_type(shipped: dict, type_byte: int) -> None:
    """Every ioctl type, with different directions, sizes, numbers and garbage in the upper
    32 bits (the kernel ignores them): blocked iff the type is 0x94, and never two rules."""
    expected = (ERRNO, LINUX_EOPNOTSUPP) if type_byte == 0x94 else (ALLOW, None)
    for direction in range(4):
        for size, number in ((0, 0), (8, 14), (4096, 255), (0x3FFF, 0x80)):
            request = direction << 30 | size << 16 | type_byte << 8 | number
            for high in (0, 0xFFFFFFFF << 32, 1 << 40):
                assert evaluate_ioctl(shipped, request | high) == expected, hex(request | high)


def test_the_naive_rule_would_overlap(docker_default: dict) -> None:
    """Why ioctl leaves the unconditional list: next to it, an ERRNO rule for 0x94 overlaps,
    and libseccomp then drops one of them (in the VM, the subvolume WAS created)."""
    naive = copy.deepcopy(docker_default)
    naive["syscalls"].append(seccomp.ioctl_rules()[-1])
    with pytest.raises(SeccompProfileError, match="overlapping"):
        evaluate_ioctl(naive, BLOCKED["BTRFS_IOC_SUBVOL_CREATE"])


def test_unmatched_ioctl_falls_to_the_default_action(docker_default: dict) -> None:
    without_ioctl = copy.deepcopy(docker_default)
    without_ioctl["syscalls"][0]["names"].remove("ioctl")
    assert evaluate_ioctl(without_ioctl, 0x5401) == ("SCMP_ACT_ERRNO", LINUX_EPERM)


# The generator


def test_agent_profile_does_not_change_its_input(docker_default: dict) -> None:
    before = copy.deepcopy(docker_default)
    agent_profile(docker_default)
    assert docker_default == before


def _profile_with_ioctl_rules(*rules: dict) -> dict:
    return {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [*rules]}


@pytest.mark.parametrize(
    ("profile", "message"),
    [
        ({"defaultAction": "SCMP_ACT_ERRNO"}, "no 'syscalls'"),
        (_profile_with_ioctl_rules({"names": ["read"], "action": ALLOW}), "found 0"),
        (
            _profile_with_ioctl_rules(
                {"names": ["ioctl"], "action": ALLOW}, {"names": ["ioctl"], "action": ALLOW}
            ),
            "found 2",
        ),
        (
            _profile_with_ioctl_rules(
                {"names": ["ioctl"], "action": ALLOW, "args": [{"index": 1, "value": 1}]}
            ),
            "unconditionally",
        ),
        (
            _profile_with_ioctl_rules(
                {"names": ["ioctl"], "action": ALLOW, "includes": {"caps": ["CAP_SYS_ADMIN"]}}
            ),
            "unconditionally",
        ),
        (
            _profile_with_ioctl_rules({"names": ["ioctl"], "action": "SCMP_ACT_LOG"}),
            "unconditionally",
        ),
        (
            _profile_with_ioctl_rules({"names": ["ioctl", "read"], "action": ALLOW}),
            "copy_file_range, found 0",
        ),
    ],
)
def test_agent_profile_refuses_an_unexpected_shape(profile: dict, message: str) -> None:
    with pytest.raises(SeccompProfileError, match=message):
        agent_profile(profile)


def test_render_matches_dockers_style(docker_default: dict) -> None:
    text = render(docker_default)
    assert text.endswith("}\n")
    assert '\n\t"defaultAction"' in text
    assert json.loads(text) == docker_default


def test_main_writes_the_profile(tmp_path: Path, docker_default: dict) -> None:
    output = tmp_path / "agent.json"
    assert seccomp.main([str(DOCKER_DEFAULT), str(output)]) == 0
    assert output.read_text() == render(agent_profile(docker_default))
