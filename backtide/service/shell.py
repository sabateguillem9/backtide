"""What the service answers to `backtide entrar`, `backtide tarea` and `backtide exportar` (T17a-4).

Design: docs/34-diseno-t17-cualquier-agente.md, section 7 and decision 3. Only for an agent of
the ``shell`` mode (Claude Code): its container waits, and the owner runs the agent inside it.

- `entrar` and `tarea` ask the service first (``Guardian.open_shell``, over the control socket):
  the agent must be running (not paused, not being rewound), and the black box records who
  opened what (``system/agent_shell``) before the CLI runs ``docker exec``. What the agent does
  then is recorded like anything else it does: the sensor sees its commands, the proxy its
  requests, the file watcher and the snapshots its files.
- `exportar` is done by the service (``Guardian.export``): a snapshot of the workspace, and a
  copy of its work folder into the owner's new folder (backtide/service/export.py), recorded as
  ``system/export``.

The outcomes' messages are Spanish, for the owner, and never carry the agent's text.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

SHELL_KINDS = frozenset({"session", "task", "import"})  # `entrar`, `tarea`, `importar`


class ShellStatus(StrEnum):
    READY = "ready"  # recorded; the CLI may run docker exec
    NOT_SHELL = "not_shell"  # the profile is not of the shell mode
    NOT_RUNNING = "not_running"  # the agent is not running (stopped, starting, paused)
    FAILED = "failed"  # the black box could not record it: nothing is opened


@dataclass(frozen=True)
class ShellOutcome:
    status: ShellStatus
    message: str
    container: str = ""
    user: str = ""
    workdir: str = ""

    @property
    def ready(self) -> bool:
        return self.status is ShellStatus.READY


class ExportStatus(StrEnum):
    DONE = "done"
    INVALID = "invalid"  # the destination: nothing was made
    NOT_SHELL = "not_shell"
    FAILED = "failed"  # no snapshot, or the copy failed (it may be half done: the message says)


@dataclass(frozen=True)
class ExportOutcome:
    status: ExportStatus
    message: str
    destination: str = ""
    snapshot: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def done(self) -> bool:
        return self.status is ExportStatus.DONE


NOT_SHELL_MESSAGE = (
    "El agente de esta instalación no es de modo shell (perfil {profile}): `backtide entrar`, "
    "`backtide tarea` y `backtide exportar` son para agentes de programación como claude-code."
)
