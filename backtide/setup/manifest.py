"""What the installer made, so it can be undone exactly (docs/25, sections 3 and 5).

``/var/lib/backtide/install-manifest.json`` (root, 0600) lists every file, folder, account,
unit, network and Docker setting the installer CREATED or CHANGED, and which steps are done.
Only what it made itself is listed: a Docker that was already there, a ``daemon.json`` it did
not write, an account that existed are never in it, so the uninstaller (T13-4) never removes
them. It is rewritten whole and atomically after each step, so a cut leaves the last good one.
A second install adds nothing that is already there: the lists are sets.
"""

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION = 1
MAX_BYTES = 256 * 1024
KINDS = ("files", "dirs", "users", "groups", "units", "networks", "packages", "docker")


class ManifestError(Exception):
    """The manifest cannot be read or written (in Spanish)."""


@dataclass
class Manifest:
    created: dict[str, list[str]] = field(default_factory=lambda: {k: [] for k in KINDS})
    steps: list[str] = field(default_factory=list)  # the steps done, in order
    facts: dict[str, Any] = field(default_factory=dict)  # subnets, the release, plan B...

    def add(self, kind: str, item: str | Path) -> None:
        if kind not in KINDS:
            raise ValueError(f"unknown kind {kind!r}")
        if str(item) not in self.created[kind]:
            self.created[kind].append(str(item))

    def remove(self, kind: str, item: str | Path) -> None:
        if str(item) in self.created.get(kind, []):
            self.created[kind].remove(str(item))

    def has(self, kind: str, item: str | Path) -> bool:
        return str(item) in self.created.get(kind, [])

    def done(self, step: str) -> None:
        if step not in self.steps:
            self.steps.append(step)

    def to_json(self) -> str:
        data = {"version": VERSION, "created": self.created, "steps": self.steps}
        data["facts"] = self.facts
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "Manifest":
        try:
            data = json.loads(text)
        except ValueError as error:
            raise ManifestError(f"el manifiesto no es JSON válido: {error}") from None
        if not isinstance(data, dict) or data.get("version") != VERSION:
            raise ManifestError("el manifiesto no es de esta versión del instalador")
        created = data.get("created", {})
        manifest = cls()
        for kind in KINDS:
            items = created.get(kind, []) if isinstance(created, dict) else []
            manifest.created[kind] = [str(item) for item in items if isinstance(item, str)]
        steps = data.get("steps", [])
        manifest.steps = [str(step) for step in steps if isinstance(step, str)]
        facts = data.get("facts", {})
        manifest.facts = facts if isinstance(facts, dict) else {}
        return manifest


def load(path: Path) -> Manifest:
    """The manifest at ``path``, or an empty one if there is none yet. It must be root's 0600
    regular file: one anyone else could write would let them pick what uninstall removes."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return Manifest()
    except OSError as error:
        raise ManifestError(f"no se puede abrir {path}: {os.strerror(error.errno or 0)}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ManifestError(f"{path} no es un archivo de root")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ManifestError(f"{path} está abierto a otros ({stat.S_IMODE(info.st_mode):04o})")
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_BYTES:
        raise ManifestError(f"{path} es demasiado grande")
    return Manifest.from_json(data.decode("utf-8", errors="replace"))


def save(manifest: Manifest, path: Path) -> None:
    """Write the manifest whole, 0600, through a new file renamed over the old one."""
    temp = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(temp, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, manifest.to_json().encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, path)
    except OSError as error:
        raise ManifestError(
            f"no se puede escribir {path}: {os.strerror(error.errno or 0)}"
        ) from None
