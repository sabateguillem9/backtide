"""The systemd units of an installed backtide, rendered from deploy/systemd/*.in.

Design: docs/25, sections 1 and 2, with what T13-1 measured. Four units:
- ``backtide.service``: root, with the capabilities of layout.SERVICE_CAPABILITIES and the
  hardening that coexists with ctypes, docker, the snapshots and the file watcher (all of
  section 2 but ``RestrictSUIDSGID``, which makes openat2 fail);
- ``backtide-web.service``: the web as ``backtide-web``, with no capability at all;
- the volume's mount and the proxy channel's tmpfs, both with ``[Install]`` so they come back
  after a reboot, and named as ``systemd-escape -p --suffix=mount`` would.

Every value comes from backtide.setup.layout; a template with an unknown ``@NAME@`` or a value
systemd would read differently (a specifier ``%``, a quote, a line break) is refused.
"""

import re
from collections.abc import Mapping
from pathlib import Path

from backtide.jail.proxy_config import (
    CHANNEL_SIZE,
    CHANNEL_TMPFS_SOURCE,
    PROXY_GID,
    PROXY_UID,
    channel_tmpfs_options,
)
from backtide.setup import layout

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "deploy" / "systemd"
_PLACEHOLDER = re.compile(r"@([A-Z_]+)@")
_SAFE_VALUE = re.compile(r"[A-Za-z0-9/._:,= -]*")
_ESCAPE_KEEP = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_.")


def escape_path(path: Path) -> str:
    """``systemd-escape -p``: the unit name of a path, without its suffix."""
    if not path.is_absolute():
        raise ValueError(f"{path} is not an absolute path")
    parts = [part for part in str(path).split("/") if part]
    if not parts:
        return "-"
    text = "/".join(parts)
    escaped = []
    for index, char in enumerate(text):
        if char == "/":
            escaped.append("-")
        elif char in _ESCAPE_KEEP and not (char == "." and index == 0):
            escaped.append(char)
        else:
            escaped.extend(f"\\x{byte:02x}" for byte in char.encode())
    return "".join(escaped)


def volume_unit_name() -> str:
    return escape_path(layout.VOLUME_MOUNT) + ".mount"


def channel_unit_name() -> str:
    return escape_path(layout.PROXY_CHANNEL_DIR) + ".mount"


def unit_values() -> dict[str, str]:
    return {
        "PROGRAM": str(layout.PROGRAM),
        "CONFIG_FILE": str(layout.CONFIG_FILE),
        "WEB_CONFIG_FILE": str(layout.WEB_CONFIG_FILE),
        "STATE_DIR": str(layout.STATE_DIR),
        "VOLUME_IMAGE": str(layout.VOLUME_IMAGE),
        "VOLUME_MOUNT": str(layout.VOLUME_MOUNT),
        "PROXY_CHANNEL_DIR": str(layout.PROXY_CHANNEL_DIR),
        "CAPABILITIES": " ".join(layout.SERVICE_CAPABILITIES),
        "WEB_USER": layout.WEB_USER,
        "WEB_LINK_FILE": str(layout.WEB_LINK_FILE),
        "WEB_RUN_DIR_NAME": layout.WEB_RUN_DIR.name,
        "SERVICE_UNIT": layout.SERVICE_UNIT,
        "CHANNEL_SOURCE": CHANNEL_TMPFS_SOURCE,
        "CHANNEL_OPTIONS": channel_tmpfs_options(CHANNEL_SIZE, PROXY_UID, PROXY_GID),
    }


def render(template: str, values: Mapping[str, str]) -> str:
    for name, value in values.items():
        if not _SAFE_VALUE.fullmatch(value):
            raise ValueError(f"{name}={value!r} cannot go into a systemd unit as it is")

    def substitute(match: re.Match[str]) -> str:
        name = match[1]
        if name not in values:
            raise ValueError(f"the template asks for @{name}@, which has no value")
        return values[name]

    return _PLACEHOLDER.sub(substitute, template)


def render_units(template_dir: Path = TEMPLATE_DIR) -> dict[str, str]:
    """Each unit's file name (in /etc/systemd/system) and its text."""
    values = unit_values()
    sources = {
        layout.SERVICE_UNIT: "backtide.service.in",
        layout.WEB_UNIT: "backtide-web.service.in",
        volume_unit_name(): "volume.mount.in",
        channel_unit_name(): "proxy-channel.mount.in",
    }
    return {
        name: render((template_dir / source).read_text(encoding="utf-8"), values)
        for name, source in sources.items()
    }
