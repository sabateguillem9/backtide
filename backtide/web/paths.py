"""The only paths the web needs from the configuration: the black box's database, the snapshot
volume and the service's control socket (to ask for a rewind, T12b).

``ServiceConfig.from_file`` also reads the gateway token (and the service opens the HMAC key):
secrets a viewer has no use for, and which would force it to run as root. This reads the same
TOML, with the same checks on the file (not writable by group or others, not a link, small; its
owner the web's own user or root: an installed web, as ``backtide-web``, reads root's
``/etc/backtide/web.toml``, 0640 with the group ``backtide-web``, T13-3), and takes
``state_dir`` and ``volume`` and nothing else: no token, no key, no checkpoint. Everything else
in the file is ignored, so the service's own configuration works as it is. The control socket is
only ever connected to (``backtide.web.rewind``), never opened as a file. From ``[agent]`` it
takes only the profile's lines of the rewind notice (T17a-3): no secret lives there.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path

from backtide.jail.profiles import DEFAULT_PROFILE
from backtide.service.config import (
    MAX_CONFIG_BYTES,
    STATE_DB,
    STATE_SOCKET,
    ConfigError,
    _as_path,
    _decode,
    _read_file,
    agent_profile_of,
)


@dataclass(frozen=True)
class WebPaths:
    blackbox_db: Path
    volume: Path
    control_socket: Path
    # The agent profile's lines of the rewind notice (backtide/service/notice.py).
    agent_lines: tuple[str, ...] = DEFAULT_PROFILE.rewind_notice_lines

    @classmethod
    def from_file(cls, path: Path) -> "WebPaths":
        """Raises ConfigError (its message never quotes the file)."""
        text = _decode(
            _read_file(
                Path(path), "configuration file", MAX_CONFIG_BYTES, private=False, owners=(0,)
            )
        )
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise ConfigError(f"{path} is not valid TOML: {error}") from error
        for key in ("state_dir", "volume"):
            if key not in data:
                raise ConfigError(f"the setting {key!r} is required")
        state_dir = _as_path("state_dir", data["state_dir"])
        volume = _as_path("volume", data["volume"])
        profile = agent_profile_of(data.get("agent", {}))
        return cls(
            blackbox_db=state_dir / STATE_DB,
            volume=volume,
            control_socket=state_dir / STATE_SOCKET,
            agent_lines=profile.rewind_notice_lines,
        )
