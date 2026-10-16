"""The chat box of "Ahora": questions it can answer from the black box alone, by rules.

No model: a handful of patterns (a summary of the last N minutes or hours, the agent's state,
help). Anything else gets an honest "not yet": natural-language questions are T15.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo

from markupsafe import Markup, escape

from vigia.blackbox import Event, Source
from vigia.web import format as fmt
from vigia.web.i18n import Translator
from vigia.web.narrate import GROUPABLE, Counts, Line, Narrator, counts_text, file_counts, sentence
from vigia.web.reader import BoxReader
from vigia.web.state import read_status

MAX_QUESTION = 200
MAX_WINDOW = timedelta(days=30)
MAX_EVENTS = 20_000
RISKY_SHOWN = 5

_UNITS = (
    (re.compile(r"\b(\d+) ?(?:minutos?|mins?|minutes?|m)\b"), timedelta(minutes=1)),
    (re.compile(r"\b(\d+) ?(?:horas?|hrs?|hours?|h)\b"), timedelta(hours=1)),
    (re.compile(r"\b(\d+) ?(?:dias?|days?|d)\b"), timedelta(days=1)),
)
_LAST = (
    (re.compile(r"\b(?:ultim[oa]s? minutos?|last minute)\b"), timedelta(minutes=1)),
    (re.compile(r"\b(?:ultim[oa]s? horas?|last hours?)\b"), timedelta(hours=1)),
    (re.compile(r"\b(?:ultim[oa]s? dias?|last days?)\b"), timedelta(days=1)),
    (re.compile(r"\b(?:ultim[oa]s? semanas?|last weeks?|semana|week)\b"), timedelta(days=7)),
)
_TODAY = re.compile(r"\b(?:hoy|today)\b")
_HELP = re.compile(r"\b(?:ayuda|help|comandos|commands|puedes|can you)\b")
_STATE = re.compile(r"\b(?:estado|como esta|esta vigilado|status|how is|is it running)\b")
_TOPIC = re.compile(
    r"\b(?:hecho|hizo|resumen|resume|pasado|pasa|ocurrido|done|did|summary|happened|going on)\b"
)


@dataclass(frozen=True)
class Intent:
    kind: str  # "help", "state", "summary" or "unknown"
    window: timedelta | None = None  # summary: how far back
    since_midnight: bool = False  # summary: "today"


def normalize(text: str) -> str:
    folded = unicodedata.normalize("NFD", text.casefold())
    bare = "".join(c for c in folded if unicodedata.category(c) != "Mn")
    return " ".join(re.sub(r"[^a-z0-9 ]", " ", bare).split())


def parse(question: str) -> Intent:
    """What the person means, by rules. Pure."""
    text = normalize(question[:MAX_QUESTION])
    if not text or _HELP.search(text):
        return Intent("help")
    if _TODAY.search(text):
        return Intent("summary", since_midnight=True)
    window = _window(text)
    if window is not None:
        return Intent("summary", window=min(window, MAX_WINDOW))
    if _STATE.search(text):
        return Intent("state")
    if _TOPIC.search(text):
        return Intent("summary", window=timedelta(hours=1))
    return Intent("unknown")


def _window(text: str) -> timedelta | None:
    for pattern, unit in _UNITS:
        found = pattern.search(text)
        if found and int(found.group(1)) > 0:
            return unit * min(int(found.group(1)), 10_000)
    for pattern, span in _LAST:
        if pattern.search(text):
            return span
    return None


# -- the summary -------------------------------------------------------------------------------


@dataclass
class Summary:
    start: datetime
    end: datetime
    total: int = 0
    files: Counts = field(default_factory=Counts)
    dropped: int = 0
    snapshots: int = 0
    rewinds: int = 0
    starts: int = 0
    stops: int = 0
    risky: list[Line] = field(default_factory=list)
    truncated_to: int | None = None  # set when more events than we read fit the window


def summarize(events: list[Event], start: datetime, end: datetime) -> Summary:
    """Counts and the delicate moments of ``events`` (oldest first). Rules only."""
    summary = Summary(start, end, total=len(events))
    for event in events:
        source, action = event.source, event.action
        if source is Source.FILE and action in GROUPABLE:
            summary.files[action] = summary.files.get(action, 0) + 1
        elif source is Source.FILE and action == "summary":
            for name, count in file_counts(event.details.get("counts")).items():
                summary.files[name] = summary.files.get(name, 0) + count
        elif source is Source.FILE and action == "dropped":
            summary.dropped += 1
        elif source is Source.SNAPSHOT and action == "take":
            summary.snapshots += 1
        elif source is Source.SNAPSHOT and action == "rewind_done":
            summary.rewinds += 1
        elif source is Source.SYSTEM and action == "agent_start":
            summary.starts += 1
        elif source is Source.SYSTEM and action == "agent_stop":
            summary.stops += 1
    delicate = [e for e in events if e.risk >= 2]
    summary.risky = [line for line in Narrator().feed(delicate) if line.risk >= 2][-RISKY_SHOWN:]
    return summary


@dataclass(frozen=True)
class Answer:
    lines: tuple[Markup, ...]
    risky: tuple[Markup, ...] = ()


def answer(question: str, *, reader: BoxReader, now: datetime, tz: tzinfo, t: Translator) -> Answer:
    """The reply to ``question``, ready to show (every line is escaped markup)."""
    intent = parse(question)
    if intent.kind == "help":
        return Answer((escape(t("chat.help")), *map(escape, _help_items(t))))
    if intent.kind == "state":
        status = read_status(reader)
        return Answer((escape(t("chat.state", state=t(f"state.{status.state}"))),))
    if intent.kind == "unknown":
        return Answer((escape(t("chat.unknown")), escape(t("chat.help.later"))))
    if intent.since_midnight:
        start = now.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        start = now - (intent.window or timedelta(hours=1))
    newest = reader.events(since_ts=start, newest_first=True, limit=MAX_EVENTS)
    events = list(reversed(newest))
    summary = summarize(events, start, now)
    if len(newest) == MAX_EVENTS:
        summary.truncated_to = MAX_EVENTS
    return _tell_summary(t, tz, summary)


def _help_items(t: Translator) -> tuple[str, ...]:
    return (t("chat.help.summary"), t("chat.help.state"), t("chat.help.later"))


def _tell_summary(t: Translator, tz: tzinfo, summary: Summary) -> Answer:
    lines: list[Markup] = [
        escape(
            t(
                "chat.window",
                from_=fmt.clock(summary.start, tz),
                to=fmt.clock(summary.end, tz),
            )
        )
    ]
    if summary.total == 0:
        lines.append(escape(t("chat.nothing")))
        return Answer(tuple(lines))
    if summary.files:
        lines.append(escape(t("chat.files", parts=counts_text(t, summary.files))))
    else:
        lines.append(escape(t("chat.files.none")))
    if summary.snapshots:
        lines.append(escape(t.plural("chat.snapshots", summary.snapshots)))
    if summary.rewinds:
        lines.append(escape(t("chat.rewinds", n=summary.rewinds)))
    if summary.starts or summary.stops:
        lines.append(escape(t("chat.starts", starts=summary.starts, stops=summary.stops)))
    if summary.dropped:
        lines.append(escape(t("chat.dropped", n=summary.dropped)))
    if summary.truncated_to:
        lines.append(escape(t("chat.truncated", n=summary.truncated_to)))
    if summary.risky:
        lines.append(escape(t("chat.risky")))
        risky = tuple(sentence(t, line.key, line.params, tz) for line in summary.risky)
        return Answer(tuple(lines), risky)
    lines.append(escape(t("chat.calm")))
    return Answer(tuple(lines))
