"""The systemd units the installer writes (docs/25, sections 1 and 2; T13-2)."""

import re
from pathlib import Path

import pytest

from backtide.jail.proxy_config import CHANNEL_TMPFS_SOURCE, PROXY_GID, PROXY_UID
from backtide.setup import layout, units

VOLUME_UNIT = r"var-lib-backtide\x2dagent.mount"
CHANNEL_UNIT = r"var-lib-backtide-proxy\x2dchannel.mount"


@pytest.mark.parametrize(
    ("path", "escaped"),
    [
        # What `systemd-escape -p` prints for each.
        ("/var/lib/backtide-agent", r"var-lib-backtide\x2dagent"),
        ("/var/lib/backtide/proxy-channel", r"var-lib-backtide-proxy\x2dchannel"),
        ("/", "-"),
        ("/var//lib/", "var-lib"),
        ("/.hidden", r"\x2ehidden"),  # only a dot that starts the name
        ("/a/.hidden", "a-.hidden"),
        ("/a/b.c", "a-b.c"),
        ("/x y", r"x\x20y"),
        ("/é", r"\xc3\xa9"),
        ("/a:b_c", "a:b_c"),
    ],
)
def test_escape_path_matches_systemd_escape(path: str, escaped: str) -> None:
    assert units.escape_path(Path(path)) == escaped


def test_escape_path_wants_an_absolute_path() -> None:
    with pytest.raises(ValueError):
        units.escape_path(Path("var/lib"))


@pytest.fixture(scope="module")
def rendered() -> dict[str, str]:
    return units.render_units()


def directives(text: str, section: str) -> dict[str, list[str]]:
    """The ``Key=value`` lines of one ``[Section]``, each key with all its values, read as
    systemd reads them: blanks around the key and the value do not count."""
    found: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            current = line.strip("[]")
        elif current == section and "=" in line and not line.startswith(("#", ";")):
            key, value = line.split("=", 1)
            found.setdefault(key.strip(), []).append(value.strip())
    return found


# Every directive of [Service], closed: a new one (an ExecStartPre=+..., AmbientCapabilities=,
# BindPaths=...) fails here until someone looks at it. docs/25, section 2, as measured in T13-1.
SERVICE = {
    "Type": ["simple"],
    "ExecStart": [f"{layout.PROGRAM} vigilar --config {layout.CONFIG_FILE}"],
    "Restart": ["always"],
    "RestartSec": ["5"],
    "TimeoutStopSec": ["120"],
    "KillMode": ["mixed"],
    "UMask": ["0077"],
    "CapabilityBoundingSet": [" ".join(layout.SERVICE_CAPABILITIES)],
    "NoNewPrivileges": ["yes"],
    "ProtectSystem": ["strict"],
    "ReadWritePaths": [f"{layout.STATE_DIR} {layout.VOLUME_MOUNT}"],
    "ProtectHome": ["yes"],
    "PrivateTmp": ["yes"],
    "ProtectKernelModules": ["yes"],
    "ProtectKernelTunables": ["yes"],
    "ProtectControlGroups": ["yes"],
    "RestrictAddressFamilies": ["AF_UNIX AF_INET AF_INET6"],
    "RestrictNamespaces": ["yes"],
    "LockPersonality": ["yes"],
    "MemoryDenyWriteExecute": ["yes"],
    "SystemCallFilter": ["@system-service"],
    "SystemCallArchitectures": ["native"],
}
WEB = {
    "Type": ["simple"],
    "User": [layout.WEB_USER],
    "Group": [layout.WEB_USER],
    "ExecStart": [f"{layout.PROGRAM} web --config {layout.WEB_CONFIG_FILE}"],
    "Restart": ["on-failure"],
    "RestartSec": ["5"],
    "UMask": ["0077"],
    "CapabilityBoundingSet": [""],
    "AmbientCapabilities": [""],
    "NoNewPrivileges": ["yes"],
    "ProtectSystem": ["strict"],
    "ProtectHome": ["yes"],
    "PrivateTmp": ["yes"],
    "PrivateDevices": ["yes"],
    "ProtectKernelModules": ["yes"],
    "ProtectKernelTunables": ["yes"],
    "ProtectKernelLogs": ["yes"],
    "ProtectControlGroups": ["yes"],
    "ProtectClock": ["yes"],
    "ProtectHostname": ["yes"],
    "RestrictAddressFamilies": ["AF_UNIX AF_INET AF_INET6"],
    # Only 127.0.0.1: a web taken over could read the whole black box (D25), never send it out.
    "IPAddressDeny": ["any"],
    "IPAddressAllow": ["localhost"],
    "RestrictNamespaces": ["yes"],
    "RestrictRealtime": ["yes"],
    "RestrictSUIDSGID": ["yes"],
    "LockPersonality": ["yes"],
    "MemoryDenyWriteExecute": ["yes"],
    "SystemCallFilter": ["@system-service"],
    "SystemCallArchitectures": ["native"],
}


def test_directives_reads_like_systemd() -> None:
    text = "[Service]\n  NoNewPrivileges = no \n# Bogus=1\n; Other=1\n[Install]\nX=1\n"
    assert directives(text, "Service") == {"NoNewPrivileges": ["no"]}


def test_the_four_units(rendered: dict[str, str]) -> None:
    assert set(rendered) == {"backtide.service", "backtide-web.service", VOLUME_UNIT, CHANNEL_UNIT}
    assert units.volume_unit_name() == VOLUME_UNIT
    assert units.channel_unit_name() == CHANNEL_UNIT


def test_no_placeholder_or_specifier_is_left(rendered: dict[str, str]) -> None:
    for name, text in rendered.items():
        assert not re.search(r"@[A-Z_]+@", text), name
        assert "%" not in text, name  # systemd would expand it as a specifier


def test_no_secret_reaches_a_unit(rendered: dict[str, str]) -> None:
    for name, text in rendered.items():
        lowered = text.lower()
        assert "environment" not in lowered, name
        assert "credential" not in lowered, name
        assert "/keys" not in lowered and "token" not in lowered, name


def test_the_service_directives_are_exactly_these(rendered: dict[str, str]) -> None:
    assert directives(rendered["backtide.service"], "Service") == SERVICE
    assert set(layout.SERVICE_CAPABILITIES) == {
        "CAP_SYS_ADMIN",
        "CAP_DAC_OVERRIDE",
        "CAP_CHOWN",
        "CAP_FOWNER",
    }


def test_restrict_suid_sgid_is_left_out(rendered: dict[str, str]) -> None:
    # T13-1, P5: it makes openat2 fail with ENOSYS and the file watcher falls back to slow paths.
    assert "RestrictSUIDSGID" not in rendered["backtide.service"]


def test_the_service_waits_for_docker_and_both_mounts(rendered: dict[str, str]) -> None:
    unit = directives(rendered["backtide.service"], "Unit")
    assert unit["RequiresMountsFor"] == [f"{layout.VOLUME_MOUNT} {layout.PROXY_CHANNEL_DIR}"]
    # Without its mount unit RequiresMountsFor does nothing: the service would start on the
    # empty folder underneath. These make it refuse instead.
    assert unit["AssertPathIsMountPoint"] == [
        str(layout.VOLUME_MOUNT),
        str(layout.PROXY_CHANNEL_DIR),
    ]
    assert unit["Requires"] == ["docker.service"]
    assert unit["After"] == ["docker.service network-online.target"]


def test_every_unit_starts_with_the_machine(rendered: dict[str, str]) -> None:
    # T13-1, P2: without [Install] the mount units do not come back after a reboot.
    for name, text in rendered.items():
        assert directives(text, "Install")["WantedBy"] == ["multi-user.target"], name


def test_the_volume_mount(rendered: dict[str, str]) -> None:
    mount = directives(rendered[VOLUME_UNIT], "Mount")
    assert mount["What"] == [str(layout.VOLUME_IMAGE)]
    assert mount["Where"] == [str(layout.VOLUME_MOUNT)]
    assert mount["Type"] == ["btrfs"]
    options = mount["Options"][0].split(",")
    assert {"loop", "noatime", "nosuid", "nodev"} <= set(options)
    assert "user_subvol_rm_allowed" not in options  # only the VM tests use it


def test_the_channel_tmpfs_mount(rendered: dict[str, str]) -> None:
    # T13-1, P5: mounted from inside the hardened service, Docker would not see it.
    mount = directives(rendered[CHANNEL_UNIT], "Mount")
    assert mount["What"] == [CHANNEL_TMPFS_SOURCE]
    assert mount["Where"] == [str(layout.PROXY_CHANNEL_DIR)]
    assert mount["Type"] == ["tmpfs"]
    assert mount["Options"] == [
        f"size=1m,mode=0700,uid={PROXY_UID},gid={PROXY_GID},nosuid,nodev,noexec"
    ]


def test_the_web_directives_are_exactly_these(rendered: dict[str, str]) -> None:
    web = directives(rendered["backtide-web.service"], "Service")
    assert web == WEB
    assert "ReadWritePaths" not in web  # it only reads


def test_render_refuses_a_missing_or_odd_value() -> None:
    with pytest.raises(ValueError, match="UNKNOWN"):
        units.render("ExecStart=@UNKNOWN@\n", {})
    for bad in ("a\nb", "50%", 'a"b', "a\\b", "\x1b"):
        with pytest.raises(ValueError):
            units.render("X=@V@\n", {"V": bad})
    assert units.render("X=@V@\n", {"V": "/opt/backtide"}) == "X=/opt/backtide\n"
