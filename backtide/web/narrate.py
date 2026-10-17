"""Black-box events told as short human sentences, with bursts folded into one line.

``Narrator`` is stateful on purpose: the live stream keeps one across polls, so "Ha borrado 120
archivos" becomes "Ha borrado 382 archivos" in place while a deletion goes on, instead of a new
line every second. Everything it says is language-free (a key and parameters); ``sentence()``
puts the words in, and is the one place where text the agent chose is made visible and escaped.
"""

import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from typing import Any

from markupsafe import Markup, escape

from backtide.blackbox import Event, Source
from backtide.snapshots import Snapshot
from backtide.web import format as fmt
from backtide.web.i18n import Translator
from backtide.web.text import tail, visible

logger = logging.getLogger(__name__)

GROUP_GAP = timedelta(seconds=30)  # events this close (and alike) are one line
GROUPABLE = frozenset({"create", "modify", "delete", "move"})
PATH_CHARS = 90
_STOP_REASONS = frozenset(
    {
        "service_stop", "unsupervised", "boot_failed", "freeze_failed", "rewind",
        "rewind_no_space", "no_service",
    }
)  # fmt: skip
_FIELD = re.compile(r"\{(\w+)\}")


class Name(str):
    """Text the agent chose (a path, a target): shown in its own span, always made visible."""


@dataclass(frozen=True)
class Ref:
    """A word to look up in the language of the page (a noun, a reason). If ``key`` is not one
    of ours (it may be built from text the agent wrote), ``fallback`` is used."""

    key: str
    fallback: str = "time.unknown"


class Counts(dict[str, int]):
    """How many of each file action ("380 borrados, 2 creados")."""

    ORDER = ("create", "modify", "delete", "move")


@dataclass(frozen=True)
class Moment:
    """An instant, shown in the person's time zone."""

    at: datetime


@dataclass
class Line:
    """One sentence of the conversation. ``id`` is the seq of the first event it covers; a
    folded line keeps its id while ``last_seq`` and the count grow."""

    id: int
    last_seq: int
    ts: str
    risk: int
    key: str
    params: dict[str, Any] = field(default_factory=dict)
    mark: bool = False  # a snapshot: drawn as a mark on the line, not as a sentence
    count: int = 1
    what: str = ""  # "source/action", for the plain line shown if this one cannot be told
    first_ts: str = ""  # when the first event of a folded line happened


# -- words -------------------------------------------------------------------------------------


def sentence(t: Translator, key: str, params: Mapping[str, Any], tz: tzinfo) -> Markup:
    """``key`` in the page's language with ``params`` filled in. Anything that is text is made
    visible and escaped; a ``Name`` also gets its own span."""
    template = t.raw(key)
    pieces: list[str] = []
    last = 0
    for match in _FIELD.finditer(template):
        pieces.append(str(escape(template[last : match.start()])))
        pieces.append(str(_value(t, params.get(match.group(1), ""), tz)))
        last = match.end()
    pieces.append(str(escape(template[last:])))
    return Markup("".join(pieces))  # noqa: S704 - literal parts escaped, values via _value


def _value(t: Translator, value: Any, tz: tzinfo) -> Markup:
    if isinstance(value, Name):
        return Markup('<span class="name">{}</span>').format(visible(value))
    if isinstance(value, Ref):
        return escape(t(value.key if t.has(value.key) else value.fallback))
    if isinstance(value, Moment):
        return escape(fmt.clock(value.at, tz))
    if isinstance(value, Counts):
        return escape(counts_text(t, value))
    if isinstance(value, str):
        return visible(value)
    return escape(str(value))


def counts_text(t: Translator, counts: Mapping[str, int]) -> str:
    return ", ".join(t.plural(f"count.{a}", counts[a]) for a in Counts.ORDER if counts.get(a))


# -- one event, one line -----------------------------------------------------------------------


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _snapshot_time(event: Event) -> Moment | Ref:
    for candidate in (event.details.get("target"), event.target, event.snapshot_id):
        snapshot = Snapshot.parse(candidate) if isinstance(candidate, str) else None
        if snapshot is not None:
            return Moment(snapshot.taken_at)
    return Ref("time.unknown")


def line_for(event: Event) -> Line:
    """The line of a single event (no folding)."""
    key, params, mark = _tell(event)
    return Line(
        id=event.seq,
        last_seq=event.seq,
        ts=event.ts,
        risk=event.risk,
        key=key,
        params=params,
        mark=mark,
        what=f"{event.source.value}/{event.action}",
        first_ts=event.ts,
    )


def safe_sentence(t: Translator, line: "Line", tz: tzinfo) -> Markup:
    """``sentence`` for a line, which never raises: one event the page cannot tell must not take
    the page (or the live stream) down with it. It becomes a plain line and an ERROR in the log."""
    try:
        return sentence(t, line.key, line.params, tz)
    except Exception:
        logger.exception("cannot tell the event %s (%s)", line.id, line.what)
        source, _, action = line.what.partition("/")
        return Markup("{} · {}").format(visible(source), visible(action))  # noqa: S704


def _tell(event: Event) -> tuple[str, dict[str, Any], bool]:
    source, action = event.source, event.action
    if source is Source.FILE:
        return _tell_file(event)
    if source is Source.SYSTEM:
        return _tell_system(event)
    if source is Source.SNAPSHOT:
        return _tell_snapshot(event)
    target = Name(event.target) if event.target else None
    if source is Source.EXEC:
        return "exec.run", {"target": target or Name(action)}, False
    if source is Source.NET:
        return "net.connect", {"target": target or Name(action)}, False
    if source is Source.LLM:
        return "llm.call", {"target": target or Name(action)}, False
    if source is Source.GATE and target is not None:
        return "gate.hold", {"action": Name(action), "target": target}, False
    return _generic(event)


def _generic(event: Event) -> tuple[str, dict[str, Any], bool]:
    params: dict[str, Any] = {"source": event.source.value, "action": Name(event.action)}
    if event.target:
        params["target"] = Name(tail(event.target, PATH_CHARS))
        return "generic", params, False
    return "generic.notarget", params, False


def _tell_file(event: Event) -> tuple[str, dict[str, Any], bool]:
    action, details = event.action, event.details
    if action in GROUPABLE:
        is_dir = details.get("type") == "dir"
        key = f"file.{action}" + (".dir" if is_dir else "")
        params: dict[str, Any] = {"path": Name(tail(event.target, PATH_CHARS))}
        if action == "move":
            params["origin"] = Name(tail(_text(details.get("from")) or "?", PATH_CHARS))
        return key, params, False
    if action == "summary":
        counts = file_counts(details.get("counts"))
        return (
            "file.summary",
            {"n": sum(counts.values()), "noun": Ref("noun.items"), "parts": counts},
            False,
        )
    if action == "dropped":
        reason = _text(details.get("reason")) or ""
        ref = Ref(f"dropped.{reason}", "dropped.other")
        return "file.dropped", {"reason": ref}, False
    return _generic(event)


def file_counts(raw: object) -> Counts:
    """The ``counts`` of a ``file/summary``, keeping only what is a plain count."""
    counts = Counts()
    if isinstance(raw, dict):
        for action in Counts.ORDER:
            value = raw.get(action)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                counts[action] = value
    return counts


def _tell_system(event: Event) -> tuple[str, dict[str, Any], bool]:
    action, details = event.action, event.details
    known = {
        "service_start", "service_stop", "service_start_failed", "agent_start",
        "agent_start_failed", "agent_stop_failed", "space_resume", "space_low",
        "watcher_armed", "watcher_failed", "watcher_lost", "record_budget", "cli_stop",
        "log", "cycle_failed",
    }  # fmt: skip
    if action in known:
        return f"system.{action}", {}, False
    if action == "agent_stop":
        reason = _text(details.get("reason"))
        if reason in _STOP_REASONS:
            return "system.agent_stop", {"reason": Ref(f"stop.{reason}")}, False
        return "system.agent_stop.plain", {}, False
    if action == "space_pause":
        frozen = details.get("frozen") is True
        return f"system.space_pause.{'frozen' if frozen else 'stopped'}", {}, False
    return _generic(event)


def _tell_snapshot(event: Event) -> tuple[str, dict[str, Any], bool]:
    action = event.action
    if action == "take":
        return "snapshot.take", {}, True
    if action in {"take_failed", "prune", "busy", "recovered"}:
        return f"snapshot.{action}", {}, False
    if action in {"rewind_requested", "rewind_done", "rewind_failed"}:
        key = f"snapshot.{action}"
        if action == "rewind_done" and event.details.get("problems"):
            key += ".problems"
        return key, {"time": _snapshot_time(event)}, False
    return _generic(event)


# -- folding bursts ----------------------------------------------------------------------------


class _Group:
    """A burst of file events of one action, still open (a gap of 30 s or another kind of event
    closes it)."""

    def __init__(self, event: Event, when: datetime) -> None:
        self.action = event.action
        self.last_when = when
        self.dirs = 0
        self.files = 0
        self.sample = Name(tail(event.target, PATH_CHARS))
        self.line = Line(
            event.seq,
            event.seq,
            event.ts,
            0,
            "",
            {},
            what=f"file/{event.action}",
            first_ts=event.ts,
        )
        self.count = 0
        self.add(event, when)

    def add_summary(self, event: Event, when: datetime, spilled: int) -> None:
        """A ``file/summary`` of the same action: records the watcher folded instead of
        writing them. They were this burst too (types unknown: counted as files)."""
        self.count += spilled
        self.files += spilled
        self.last_when = when
        self._retell(event)

    def add(self, event: Event, when: datetime) -> None:
        self.count += 1
        if event.details.get("type") == "dir":
            self.dirs += 1
        else:
            self.files += 1
        self.last_when = when
        self._retell(event)

    def _retell(self, event: Event) -> None:
        line = self.line
        line.last_seq, line.ts, line.count = event.seq, event.ts, self.count
        line.risk = max(line.risk, event.risk)
        if self.count == 1:
            line_single = line_for(event)
            line.key, line.params = line_single.key, line_single.params
        else:
            noun = (
                "noun.dirs" if not self.files else ("noun.files" if not self.dirs else "noun.items")
            )
            line.key = f"file.{self.action}.many"
            line.params = {"n": self.count, "noun": Ref(noun), "path": self.sample}


class Narrator:
    """Feed it events in order; it returns the lines that are new or have changed (a folded
    line comes back, with the same ``id``, every time it grows)."""

    def __init__(self) -> None:
        self._open: _Group | None = None

    def feed(self, events: Iterable[Event]) -> list[Line]:
        changed: dict[int, Line] = {}
        for event in events:
            if event.source is Source.FILE and event.action in GROUPABLE:
                line = self._fold(event)
            elif event.source is Source.FILE and event.action == "summary":
                line = self._summary(event)
            else:
                self._open = None
                line = line_for(event)
            changed[line.id] = line
        return list(changed.values())

    def _summary(self, event: Event) -> Line:
        """A summary of nothing but the action of the open burst joins it; any other summary is
        a line of its own."""
        group = self._open
        counts = file_counts(event.details.get("counts"))
        when = fmt.parse_ts(event.ts)
        if (
            group is not None
            and set(counts) == {group.action}
            and when - group.last_when <= GROUP_GAP
        ):
            group.add_summary(event, when, counts[group.action])
            return group.line
        self._open = None
        return line_for(event)

    def _fold(self, event: Event) -> Line:
        when = fmt.parse_ts(event.ts)
        group = self._open
        if (
            group is not None
            and group.action == event.action
            and when - group.last_when <= GROUP_GAP
        ):
            group.add(event, when)
        else:
            group = self._open = _Group(event, when)
        return group.line
