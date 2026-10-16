"""The only two paths the web needs from the configuration: the black box's database and the
snapshot volume.

``ServiceConfig.from_file`` also reads the gateway token (and the service opens the HMAC key):
secrets a viewer has no use for, and which would force it to run as root. This reads the same
TOML, with the same checks on the file (not writable by others, not a link, small), and takes
``state_dir`` and ``volume`` and nothing else: no token, no key, no checkpoint. Everything else
in the file is ignored, so the service's own configuration works as it is.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path

from vigia.service.config import (
    MAX_CONFIG_BYTES,
    STATE_DB,
    ConfigError,
    _as_path,
    _decode,
    _read_file,
)


@dataclass(frozen=True)
class WebPaths:
    blackbox_db: Path
    volume: Path

    @classmethod
    def from_file(cls, path: Path) -> "WebPaths":
        """Raises ConfigError (its message never quotes the file)."""
        text = _decode(
            _read_file(Path(path), "configuration file", MAX_CONFIG_BYTES, private=False)
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
        return cls(blackbox_db=state_dir / STATE_DB, volume=volume)
