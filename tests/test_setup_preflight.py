"""The installer's preflight (docs/25, section 4, step 1; T13-2), against a fake host."""

import json
import struct
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from backtide.jail import sensor
from backtide.setup import layout, preflight
from backtide.setup.host import Ran
from backtide.setup.preflight import Status

GIB = 1024**3


def btf_header(hdr_len: int = 24, trailer: bytes = b"", *, magic: bytes = b"\x9f\xeb") -> bytes:
    """The start of /sys/kernel/btf/vmlinux: magic, version, flags, hdr_len, then the offsets."""
    head = magic + bytes([1, 0]) + struct.pack("<I", hdr_len) + struct.pack("<4I", 0, 8, 8, 8)
    return head + trailer + b"\0" * 64


DOCKER_INFO = {
    "ServerVersion": "29.9.2",
    "OperatingSystem": "Fedora Linux 44 (Cloud Edition)",
    "SecurityOptions": ["name=seccomp,profile=builtin", "name=selinux", "name=cgroupns"],
}


@dataclass
class FakeHost:
    euid_value: int = 0
    machine_value: str = "aarch64"
    release_value: str = "6.19.10-300.fc44.aarch64"
    files: dict[str, bytes] = field(
        default_factory=lambda: {
            "/proc/filesystems": b"nodev\tsysfs\nnodev\ttmpfs\n\text4\n\tbtrfs\n",
            "/sys/kernel/btf/vmlinux": btf_header(),
            "/sys/fs/selinux/enforce": b"1",
        }
    )
    present: set[str] = field(
        default_factory=lambda: {
            "/dev/loop-control",
            "/sys/fs/cgroup/cgroup.controllers",
            "/run/systemd/system",
        }
    )
    commands: dict[tuple[str, ...], Ran] = field(
        default_factory=lambda: {
            ("mkfs.btrfs", "--version"): Ran(0, "mkfs.btrfs, part of btrfs-progs v6.19.1\n", ""),
            ("openssl", "version"): Ran(0, "OpenSSL 3.5.4 30 Sep 2025\n", ""),
            ("docker", "--version"): Ran(0, "Docker version 29.9.2, build 1a2b3c4\n", ""),
            ("docker", "info", "--format", "{{json .}}"): Ran(0, json.dumps(DOCKER_INFO), ""),
        }
    )
    free: int | None = 100 * GIB
    taken_uids: set[int] = field(default_factory=set)
    taken_gids: set[int] = field(default_factory=set)
    synced: bool | None = True
    ran: list[tuple[str, ...]] = field(default_factory=list)

    def euid(self) -> int:
        return self.euid_value

    def machine(self) -> str:
        return self.machine_value

    def release(self) -> str:
        return self.release_value

    def read(self, path: str, limit: int = 65536) -> bytes | None:
        data = self.files.get(path)
        return None if data is None else data[:limit]

    def exists(self, path: str) -> bool:
        return path in self.present or path in self.files

    def run(self, argv: Sequence[str]) -> Ran | None:
        self.ran.append(tuple(argv))
        return self.commands.get(tuple(argv))

    def free_bytes(self, path: str) -> int | None:
        return self.free

    def uid_taken(self, uid: int) -> bool:
        return uid in self.taken_uids

    def gid_taken(self, gid: int) -> bool:
        return gid in self.taken_gids

    def clock_synced(self) -> bool | None:
        return self.synced


def checks(host: FakeHost, *, installing: bool = True) -> dict[str, preflight.Check]:
    return {check.key: check for check in preflight.run_checks(host, installing=installing)}


def test_a_good_machine_has_no_failures_and_no_warnings_but_the_kernel() -> None:
    result = checks(FakeHost(release_value="7.0.0-34-generic"))
    statuses = {key: check.status for key, check in result.items()}
    assert statuses.pop("kernel") is Status.WARN  # 7.0 < 7.1: the squota fixes are missing
    assert set(statuses.values()) == {Status.OK}, statuses
    assert set(statuses) == {
        "root",
        "arch",
        "btrfs",
        "loop",
        "cgroup",
        "systemd",
        "clock",
        "btf",
        "space",
        "ids",
        "btrfs-progs",
        "openssl",
        "docker",
        "confinement",
    }


def test_every_check_says_how_to_fix_what_is_not_ok() -> None:
    host = FakeHost(
        euid_value=1000,
        machine_value="riscv64",
        release_value="6.6.0",
        files={},
        present=set(),
        commands={},
        free=1 * GIB,
        taken_uids={61000},
        synced=False,
    )
    for check in preflight.run_checks(host, installing=True):
        if check.status is not Status.OK:
            assert check.fix, check
        assert "\n" not in check.summary


@pytest.mark.parametrize(
    ("release", "status"),
    [
        ("6.6.87-generic", Status.FAIL),
        ("6.7.0", Status.WARN),
        ("6.8.0-142-generic", Status.WARN),
        ("7.0.0-34-generic", Status.WARN),
        ("7.1.0", Status.OK),
        ("7.2.11-200.fc44.aarch64", Status.OK),
        ("10.0.1", Status.OK),
        ("not-a-version", Status.FAIL),
    ],
)
def test_kernel(release: str, status: Status) -> None:
    assert checks(FakeHost(release_value=release))["kernel"].status is status


def test_root_is_required_to_install_and_only_warned_to_check() -> None:
    assert checks(FakeHost(euid_value=1000))["root"].status is Status.FAIL
    assert checks(FakeHost(euid_value=1000), installing=False)["root"].status is Status.WARN


@pytest.mark.parametrize(("machine", "status"), [("x86_64", Status.OK), ("armv7l", Status.FAIL)])
def test_arch(machine: str, status: Status) -> None:
    assert checks(FakeHost(machine_value=machine))["arch"].status is status


def test_btrfs_loaded_or_loadable() -> None:
    host = FakeHost()
    host.files["/proc/filesystems"] = b"nodev\tsysfs\n\text4\n"
    assert checks(host)["btrfs"].status is Status.FAIL
    host.commands[("modinfo", "-F", "name", "btrfs")] = Ran(0, "btrfs\n", "")
    assert checks(host)["btrfs"].status is Status.OK
    # A name that only contains "btrfs" is not btrfs.
    host = FakeHost()
    host.files["/proc/filesystems"] = b"nodev\tsysfs\n\tnotbtrfs\n"
    assert checks(host)["btrfs"].status is Status.FAIL


@pytest.mark.parametrize(
    ("key", "path"),
    [
        ("loop", "/dev/loop-control"),
        ("cgroup", "/sys/fs/cgroup/cgroup.controllers"),
        ("systemd", "/run/systemd/system"),
    ],
)
def test_required_kernel_pieces(key: str, path: str) -> None:
    host = FakeHost()
    host.present.discard(path)
    assert checks(host)[key].status is Status.FAIL


@pytest.mark.parametrize(
    ("synced", "status"), [(True, Status.OK), (False, Status.WARN), (None, Status.WARN)]
)
def test_clock_only_warns(synced: bool | None, status: Status) -> None:
    assert checks(FakeHost(synced=synced))["clock"].status is status


# BTF and Tetragon (D24): the sensor needs to read the kernel's BTF; v1.7.1 cannot read the
# longer header of the 7.1+ kernels built with pahole 1.31 (docs/25, "Resultados en la VM").


def test_the_btf_limit_belongs_to_the_pinned_tetragon() -> None:
    # Bumping Tetragon must make someone look at TETRAGON_BTF_HEADER_LEN again (option C of D24).
    assert sensor.TETRAGON_VERSION == "v1.7.1"
    assert preflight.TETRAGON_BTF_HEADER_LEN == 24


def test_btf_of_the_usual_size_is_ok() -> None:
    assert checks(FakeHost())["btf"].status is Status.OK


def test_btf_with_a_longer_header_warns_that_the_sensor_will_not_start() -> None:
    host = FakeHost(release_value="7.2.11-200.fc44.aarch64")
    host.files["/sys/kernel/btf/vmlinux"] = btf_header(32, struct.pack("<II", 1024, 96))
    check = checks(host)["btf"]
    assert check.status is Status.WARN
    assert "v1.7.1" in check.summary and "32" in check.summary
    assert "D24" in check.fix


# The first 32 bytes of /sys/kernel/btf/vmlinux on Fedora 44 with kernel 7.2.11-200 (aarch64),
# read in a clean VM on 2026-10-25: the header the sensor fails on.
FEDORA_7_2_11_BTF = bytes.fromhex(
    "9feb0100 20000000 00000000 a8934300 f8934300 be4a3200 a8934300 50000000"
)


def test_the_real_header_of_fedora_kernel_7_2_warns() -> None:
    assert len(FEDORA_7_2_11_BTF) == 32
    assert preflight.btf_header_problem(FEDORA_7_2_11_BTF) is not None


def test_a_longer_header_of_zeros_is_still_readable() -> None:
    # cilium/ebpf only refuses a trailer that is not zero ("header contains non-zero trailer").
    host = FakeHost()
    host.files["/sys/kernel/btf/vmlinux"] = btf_header(32, b"\0" * 8)
    assert checks(host)["btf"].status is Status.OK


def test_big_endian_btf_is_read_too() -> None:
    head = b"\xeb\x9f" + bytes([1, 0]) + struct.pack(">I", 32) + struct.pack(">4I", 0, 8, 8, 8)
    host = FakeHost()
    host.files["/sys/kernel/btf/vmlinux"] = head + b"\x01" + b"\0" * 64
    assert checks(host)["btf"].status is Status.WARN
    # Read in the right order, a 24-byte header and a 32-byte one ending in zeros are fine
    # (read as little-endian, hdr_len would be huge and both would warn).
    for hdr_len in (24, 32):
        head = b"\xeb\x9f" + bytes([1, 0]) + struct.pack(">I", hdr_len)
        host.files["/sys/kernel/btf/vmlinux"] = head + struct.pack(">4I", 0, 8, 8, 8) + b"\0" * 64
        assert checks(host)["btf"].status is Status.OK, hdr_len


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(None, id="missing"),
        pytest.param(b"\x9f\xeb", id="short"),
        pytest.param(btf_header(magic=b"\0\0"), id="bad-magic"),
        pytest.param(btf_header(16), id="header-too-short"),
        pytest.param(btf_header(4096)[:100], id="header-longer-than-read"),
    ],
)
def test_btf_that_cannot_be_read_warns(data: bytes | None) -> None:
    host = FakeHost()
    if data is None:
        del host.files["/sys/kernel/btf/vmlinux"]
    else:
        host.files["/sys/kernel/btf/vmlinux"] = data
    check = checks(host)["btf"]
    assert check.status is Status.WARN
    assert "sensor" in check.summary


def test_btf_header_problem_is_pure() -> None:
    assert preflight.btf_header_problem(btf_header()) is None
    assert preflight.btf_header_problem(btf_header(32, b"\x01" + b"\0" * 7)) is not None


# Space (decision 17, D25): V/2 + 8 GiB before installing.


def test_space_before_installing() -> None:
    need = layout.VOLUME_SIZE // 2 + layout.IMAGES_ROOM
    assert need == 18 * GIB
    assert checks(FakeHost(free=need))["space"].status is Status.OK
    assert checks(FakeHost(free=need - 1))["space"].status is Status.FAIL
    assert checks(FakeHost(free=None))["space"].status is Status.WARN


def test_space_without_root_cannot_tell_an_installed_machine() -> None:
    # Without root volume.img is out of sight, so a little free space is a warning, not a fail.
    host = FakeHost(euid_value=1000, free=5 * GIB)
    assert checks(host, installing=False)["space"].status is Status.WARN
    assert checks(host, installing=True)["space"].status is Status.FAIL


def test_space_once_installed_only_warns_when_little_is_left() -> None:
    host = FakeHost(free=5 * GIB)
    host.present.add(str(layout.VOLUME_IMAGE))
    assert checks(host)["space"].status is Status.OK
    host.free = 1 * GIB
    assert checks(host)["space"].status is Status.WARN


@pytest.mark.parametrize(
    ("uids", "gids"), [({61000}, set()), (set(), {61000}), ({61001}, set()), (set(), {61001})]
)
def test_the_agent_and_proxy_ids_must_be_nobodys(uids: set[int], gids: set[int]) -> None:
    check = checks(FakeHost(taken_uids=uids, taken_gids=gids))["ids"]
    assert check.status is Status.FAIL
    assert str(next(iter(uids | gids))) in check.summary


@pytest.mark.parametrize(
    ("key", "argv"),
    [("btrfs-progs", ("mkfs.btrfs", "--version")), ("openssl", ("openssl", "version"))],
)
def test_missing_tools_are_left_to_the_installer(key: str, argv: tuple[str, ...]) -> None:
    host = FakeHost()
    del host.commands[argv]
    assert checks(host)[key].status is Status.WARN


# Docker (decision 5): Docker Engine, never Docker Desktop, Podman or rootless.


def test_no_docker_is_left_to_the_installer() -> None:
    host = FakeHost(commands={})
    check = checks(host)["docker"]
    assert check.status is Status.WARN
    assert ("docker", "info", "--format", "{{json .}}") not in host.ran


def docker_with(info: dict[str, object]) -> FakeHost:
    host = FakeHost()
    host.commands[("docker", "info", "--format", "{{json .}}")] = Ran(0, json.dumps(info), "")
    return host


def test_docker_desktop_is_refused() -> None:
    host = docker_with({**DOCKER_INFO, "OperatingSystem": "Docker Desktop"})
    assert checks(host)["docker"].status is Status.FAIL


def test_rootless_docker_is_refused() -> None:
    options = [*DOCKER_INFO["SecurityOptions"], "name=rootless"]  # type: ignore[misc]
    host = docker_with({**DOCKER_INFO, "SecurityOptions": options})
    assert checks(host)["docker"].status is Status.FAIL


def test_podman_is_refused() -> None:
    host = FakeHost()
    host.commands[("docker", "--version")] = Ran(0, "podman version 5.6.0\n", "")
    assert checks(host)["docker"].status is Status.FAIL


def test_docker_that_does_not_answer_fails() -> None:
    host = FakeHost()
    host.commands[("docker", "info", "--format", "{{json .}}")] = Ran(
        1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n"
    )
    assert checks(host)["docker"].status is Status.FAIL


def test_docker_without_root_is_only_a_warning_when_checking() -> None:
    host = FakeHost(euid_value=1000)
    host.commands[("docker", "info", "--format", "{{json .}}")] = Ran(
        1, "", "permission denied while trying to connect to the Docker daemon socket\n"
    )
    assert checks(host, installing=False)["docker"].status is Status.WARN


def test_docker_output_that_is_not_json_fails() -> None:
    host = FakeHost()
    host.commands[("docker", "info", "--format", "{{json .}}")] = Ran(0, "\x1b[31mnope", "")
    check = checks(host)["docker"]
    assert check.status is Status.FAIL
    assert "\x1b" not in check.summary


# Confinement: SELinux on Fedora (decision 16, D25), AppArmor on Ubuntu.


def test_selinux_enforcing_without_docker_using_it_warns() -> None:
    host = docker_with({**DOCKER_INFO, "SecurityOptions": ["name=seccomp,profile=builtin"]})
    check = checks(host)["confinement"]
    assert check.status is Status.WARN
    assert "live-restore" in check.fix


def test_selinux_permissive_warns() -> None:
    host = FakeHost()
    host.files["/sys/fs/selinux/enforce"] = b"0"
    assert checks(host)["confinement"].status is Status.WARN


def test_selinux_without_knowing_docker_is_not_green() -> None:
    # Before Docker is installed, or without root: Docker may well leave SELinux off (P6).
    host = FakeHost()
    del host.commands[("docker", "--version")]
    assert checks(host)["confinement"].status is Status.WARN
    host = FakeHost(euid_value=1000)
    host.commands[("docker", "info", "--format", "{{json .}}")] = Ran(
        1, "", "permission denied while trying to connect to the Docker daemon socket\n"
    )
    assert checks(host, installing=False)["confinement"].status is Status.WARN


def test_apparmor_is_green_only_when_docker_uses_it() -> None:
    host = docker_with({**DOCKER_INFO, "SecurityOptions": ["name=apparmor", "name=seccomp"]})
    del host.files["/sys/fs/selinux/enforce"]
    host.files["/sys/module/apparmor/parameters/enabled"] = b"Y\n"
    assert checks(host)["confinement"].status is Status.OK
    host.commands[("docker", "info", "--format", "{{json .}}")] = Ran(
        0, json.dumps({**DOCKER_INFO, "SecurityOptions": ["name=seccomp"]}), ""
    )
    assert checks(host)["confinement"].status is Status.WARN  # no apparmor_parser, say
    del host.commands[("docker", "--version")]
    assert checks(host)["confinement"].status is Status.WARN  # Docker not known yet
    host.files["/sys/module/apparmor/parameters/enabled"] = b"N\n"
    assert checks(host)["confinement"].status is Status.WARN


def test_failed_counts_only_failures() -> None:
    ok = preflight.Check("a", Status.OK, "bien")
    warn = preflight.Check("b", Status.WARN, "ojo", "haz algo")
    fail = preflight.Check("c", Status.FAIL, "mal", "arréglalo")
    assert not preflight.failed([ok, warn])
    assert preflight.failed([ok, fail])
