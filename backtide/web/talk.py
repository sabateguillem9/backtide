"""The chat of the web (T26-5b, docs/47 sections 7.1 and 7.3): who it asks, and what a page shows.

The web never runs a task: it asks the service, on its socket, the same way `backtide tarea` does
(``ask_task_start``, with ``via="web"``), so the CLI and the web do exactly the same. Writes are
explicit: only `backtide web --tareas` gives a task or stops one (``enabled``). Without it the page
says how to turn it on and the POSTs do not exist.

What it reads:
- ``tasks``: every task of the agent, small whatever the answers measure. The stream asks this every
  second, and it has no answer in it.
- ``status``: one task's answer, cut to ``SHOWN_CHARS`` by the service, so neither a page nor this
  process ever holds 48 MiB of what an agent chose to write. Asked once per task that has ended:
  the stream keeps which ones the page has (``known_of``), and one that ended is not asked again.

The answers stay in the service's memory, and here only while a page is being drawn: nothing goes to
a file, to a log or to the black box (invariant 5): the app logs an error here by its type alone.

What the agent writes is hostile (section 7.3), and that is the templates' job: only ever
``vis(...)`` (``backtide.web.text.visible``), in a ``<pre>`` of its own, under a label that is ours.
"""

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from backtide.service.control import (
    ControlError,
    PeerCredentials,
    ask_task_list,
    ask_task_start,
    ask_task_status,
    ask_task_stop,
    peer_credentials,
)
from backtide.web.rewind import WAIT_FOR_SERVICE, Availability, availability_of
from backtide.web.security import acting_session

SHOWN_CHARS = 64 * 1024  # of an answer, on the page: at twenty of them, a page a browser can draw
RUNNING = "running"
UNKNOWN = "unknown"
_MAX_KNOWN = 64  # far more than the service keeps (MAX_KEPT + MAX_RUNNING)
_KNOWN = re.compile(r"([re])([0-9a-f]{32})", re.ASCII)
_TASK_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)


class TaskClient(Protocol):
    """What the app needs. Every call but ``availability`` raises the socket's errors
    (ControlUnavailable, ControlOutcomeUnknown, ControlError)."""

    enabled: bool

    def availability(self) -> Availability: ...

    def tasks(self, *, agent: str | None = None) -> list[dict[str, Any]]: ...

    def status(self, task_id: str, *, agent: str | None = None) -> dict[str, Any]: ...

    def start(
        self, prompt: str, *, resume: bool = False, agent: str | None = None
    ) -> dict[str, Any]: ...

    def stop(self, task_id: str, *, agent: str | None = None) -> bool: ...


class ControlTasks:
    """The real one: the socket at ``path``, the narrow one (``server_uid``) on the installed web.
    Each read carries the session of who asks, like a change: the answers are not in the box."""

    def __init__(
        self,
        path: Path,
        *,
        enabled: bool = False,
        wait: float = WAIT_FOR_SERVICE,
        peer: PeerCredentials = peer_credentials,
        euid: Callable[[], int] = os.geteuid,
        server_uid: int | None = None,
        egid: Callable[[], int] = os.getegid,
    ) -> None:
        self._path = Path(path)
        self.enabled = enabled
        self._wait = wait
        self._peer = peer
        self._euid = euid
        self._server_uid = server_uid
        self._egid = egid

    def availability(self) -> Availability:
        return availability_of(
            self._path,
            enabled=self.enabled,
            euid=self._euid,
            server_uid=self._server_uid,
            egid=self._egid,
        )

    def _ask(self) -> dict[str, Any]:
        if not self.enabled:  # the app never gets here without READY; still, never by accident
            raise ControlError("esta web no se lanzó con --tareas")
        return {
            "wait": self._wait,
            "peer": self._peer,
            "server_uid": self._server_uid,
            "session": acting_session(self._server_uid),
        }

    def tasks(self, *, agent: str | None = None) -> list[dict[str, Any]]:
        return ask_task_list(self._path, agent=agent, **self._ask())

    def status(self, task_id: str, *, agent: str | None = None) -> dict[str, Any]:
        return ask_task_status(self._path, task_id, cut=SHOWN_CHARS, agent=agent, **self._ask())

    def start(
        self, prompt: str, *, resume: bool = False, agent: str | None = None
    ) -> dict[str, Any]:
        return ask_task_start(
            self._path, prompt, resume=resume, via="web", agent=agent, **self._ask()
        )

    def stop(self, task_id: str, *, agent: str | None = None) -> bool:
        return ask_task_stop(self._path, task_id, via="web", agent=agent, **self._ask())


@dataclass(frozen=True)
class TaskView:
    """One line of the chat, as the templates use it. ``asked``, ``answer`` and ``said`` are text
    of the owner or of the agent, not escaped: a template only ever shows them with ``vis``."""

    id: str
    asked: str
    asked_at: str  # ISO, for ``<time data-ago>``
    from_cli: bool
    outcome: str
    ended: bool
    answer: str | None = None
    answer_chars: int = 0  # the whole answer's
    cut: bool = False  # the service sent only the first of them
    said: str = ""  # what the service says of how it went: it can carry the agent's text too
    seconds: float | None = None
    unread: bool = False  # it ended, and the answer could not be asked for: the stream tries again


def view_of(entry: Mapping[str, Any], status: Mapping[str, Any] | None = None) -> TaskView:
    """A line from ``tasks`` and, if it ended, its ``status`` (None: not read). The line says what
    was asked; how it went, the status, which is newer. A status that says the service no longer
    knows the task is the end too: there is nothing else to wait for."""
    outcome = entry["outcome"] if status is None else status["outcome"]
    ended_in_list = entry["outcome"] != RUNNING
    answer = None if status is None else status.get("answer")
    answer_chars = 0 if status is None else status.get("answer_chars", 0)
    return TaskView(
        id=entry["task"],
        asked=entry["asked"],
        asked_at=datetime.fromtimestamp(entry["asked_at"], UTC).isoformat(),
        from_cli=entry["via"] != "web",
        outcome=outcome,
        ended=outcome != RUNNING,
        # With a line feed for a line break: CR LF is no trick, only how some programs write.
        answer=None if answer is None else answer.replace("\r\n", "\n"),
        answer_chars=answer_chars,
        cut=answer is not None and answer_chars > len(answer),
        said="" if status is None else status.get("message", ""),
        seconds=entry.get("seconds") if status is None else status.get("seconds"),
        unread=ended_in_list and status is None,
    )


def is_task_id(text: str) -> bool:
    return _TASK_ID.fullmatch(text) is not None


def known_of(text: str) -> dict[str, bool]:
    """What a page has, as the stream's id or the page's own ``visto`` said it: task id to "it has
    its end". Anything that is not this shape counts as nothing, which only sends a line again."""
    known: dict[str, bool] = {}
    for item in text.split(",")[:_MAX_KNOWN]:
        found = _KNOWN.fullmatch(item)
        if found is not None:
            known[found.group(2)] = found.group(1) == "e"
    return known


def known_id(known: Mapping[str, bool]) -> str:
    """The other way: the stream's ``id:`` and the page's first ``visto``. The latest of the tasks
    are the ones to keep if there were ever more than the browser should send back."""
    return ",".join(f"{'e' if ended else 'r'}{task}" for task, ended in known.items())


__all__ = [
    "RUNNING",
    "SHOWN_CHARS",
    "UNKNOWN",
    "ControlTasks",
    "TaskClient",
    "TaskView",
    "is_task_id",
    "known_id",
    "known_of",
    "view_of",
]
