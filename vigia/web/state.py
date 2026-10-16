"""Is the agent watched, frozen or stopped? Told from the black box alone, by rules.

The box records every start, stop, pause and resume, so the newest of those says where the agent
stands. It cannot say that Vigía itself died without a trace (a killed process records nothing):
the page says "according to the last signal", and T12b can add the control socket's word.
"""

from dataclasses import dataclass
from datetime import datetime

from vigia.blackbox import Event, Source
from vigia.web import format as fmt
from vigia.web.reader import BoxReader

WATCHED, FROZEN, STOPPED, UNKNOWN = "watched", "frozen", "stopped", "unknown"
# The system/* actions that move the agent between states.
STATE_ACTIONS = (
    "agent_start", "agent_stop", "agent_start_failed", "agent_stop_failed", "space_pause",
    "space_resume", "service_start", "service_stop", "service_start_failed", "cli_stop",
)  # fmt: skip


@dataclass(frozen=True)
class AgentStatus:
    state: str
    since: datetime | None  # when of the signal it comes from; None if the box has none


def status_from(events: list[Event]) -> AgentStatus:
    """The state after the newest of ``events`` that moves it."""
    moving = [e for e in events if e.source is Source.SYSTEM and e.action in STATE_ACTIONS]
    if not moving:
        return AgentStatus(UNKNOWN, None)
    last = max(moving, key=lambda e: e.seq)
    since = fmt.parse_ts(last.ts)
    if last.action in {"agent_start", "space_resume"}:
        return AgentStatus(WATCHED, since)
    if last.action == "space_pause":
        return AgentStatus(FROZEN if last.details.get("frozen") is True else STOPPED, since)
    if last.action == "agent_stop_failed":
        return AgentStatus(UNKNOWN, since)  # it may still be running: do not say "stopped"
    return AgentStatus(STOPPED, since)


def read_status(reader: BoxReader) -> AgentStatus:
    newest: list[Event] = []
    for action in STATE_ACTIONS:
        newest += reader.events(source="system", action=action, newest_first=True, limit=1)
    return status_from(newest)
