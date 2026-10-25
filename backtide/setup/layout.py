"""Where an installed backtide lives (docs/25, "Disposición"), in one place.

Every path, name and size the installer, the preflight and the systemd units use comes from
here, so a rename touches this file and nothing else (docs/25, "Riesgos")."""

from pathlib import Path

from backtide.jail.config import AGENT_GID, AGENT_UID
from backtide.jail.proxy_config import PROXY_GID, PROXY_UID
from backtide.service.config import STATE_PROXY_CHANNEL

NAME = "backtide"
GIB = 1024**3

OPT_DIR = Path("/opt") / NAME  # releases/<version> and the `current` link
CURRENT = OPT_DIR / "current"
PROGRAM = CURRENT / ".venv" / "bin" / NAME  # what `uv sync` leaves in the release folder

CONFIG_DIR = Path("/etc") / NAME
CONFIG_FILE = CONFIG_DIR / f"{NAME}.toml"
WEB_CONFIG_FILE = CONFIG_DIR / "web.toml"  # the web's own, readable by WEB_USER (D25)

STATE_DIR = Path("/var/lib") / NAME
VOLUME_IMAGE = STATE_DIR / "volume.img"
PROXY_CHANNEL_DIR = STATE_DIR / STATE_PROXY_CHANNEL
# The volume's mount point is NOT inside STATE_DIR: the agent writes the volume, and the state
# must never be in it (ServiceConfig refuses one inside the other).
VOLUME_MOUNT = Path("/var/lib") / f"{NAME}-agent"
VOLUME_LABEL = NAME

WEB_USER = f"{NAME}-web"  # a system account: no login, no home (docs/25, section 3)
SERVICE_UNIT = f"{NAME}.service"
WEB_UNIT = f"{NAME}-web.service"

# Nobody's: the agent and the proxy run as these ids, which are never accounts (docs/13, docs/21).
RESERVED_IDS = {
    "el agente": (AGENT_UID, AGENT_GID),
    "el proxy": (PROXY_UID, PROXY_GID),
}

# Decision 4 of docs/25: a 20 GiB sparse volume, allowed to grow to 1.5 times that (T04e-1).
VOLUME_SIZE = 20 * GIB
MAX_VOLUME_SIZE = VOLUME_SIZE * 3 // 2
# Decision 17 (D25): free space before installing is V/2 + 8 GiB; the three pinned images take
# 5.5 GiB unpacked (OpenClaw 4.7, mitmproxy 0.4, Tetragon 0.35), measured in T13-1.
IMAGES_ROOM = 8 * GIB
# Once installed, less than this left for the volume and Docker to grow is worth a warning.
GROW_ROOM = 4 * GIB

# backtide.service's capabilities, measured in a clean VM (T13-1, P5; decision 14, D25):
# SYS_ADMIN for the btrfs ioctls and qgroups, DAC_OVERRIDE to empty and prepare the proxy's
# channel folder (61001, 0700), CHOWN and FOWNER for the agent's folder.
SERVICE_CAPABILITIES = ("CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER")
