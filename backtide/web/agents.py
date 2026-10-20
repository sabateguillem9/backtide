"""The agents the web shows, and what the control room says about each one. Presentation only.

Today ``backtide web`` watches one agent: the black box it reads (``BoxReader``, read-only and
without the key) and the snapshot list. That is the roster's first agent, the MAIN one: its pages
keep their old addresses (``/ahora``, ``/historia``...) and it is the only one the rewind acts on
(the service's control socket knows one agent). The demo (``scripts/web-demo``) adds more, each
with its own black box, through ``create_app(others=...)``; T17 will hand the real list over the
same way. Every agent is read the same way as the main one: a ``BoxReader``, nothing else.

The gate's held requests (T10): ``PendingRequest`` is the shape the control room draws. The real
web builds them from the service's list (``backtide web --aprobar``) or from the black box
(``backtide.web.approve``); the demo reads made-up ones from a file of its own
(``create_app(pending=...)``). Deciding goes through ``backtide.web.approve`` and its POST, only
with ``--aprobar``.

Everything an agent chose (a target, a subject line) is a ``Name`` here: the templates make it
visible and escaped, in its own isolated span (``backtide.web.narrate.sentence``).
"""

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, tzinfo
from typing import Any

from backtide.blackbox import Event, Source
from backtide.snapshots import Snapshot
from backtide.web import format as fmt
from backtide.web.narrate import Line, Name, Narrator
from backtide.web.reader import BoxReader
from backtide.web.state import FROZEN, STATE_ACTIONS, STOPPED, UNKNOWN, WATCHED, status_from
from backtide.web.tide import Tide, build_tide

MAIN_SLUG = "principal"
SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
MAX_NAME = 48
COLOURS = 6  # identity colours of the app palette (brand tokens.json, "app")
WORKING_FOR = timedelta(seconds=60)  # an agent that moved this recently is "working"
REWIND_FOR = timedelta(minutes=10)  # a rewind asked and not answered for this long is stale
FEED_LINES = 24  # lines of each agent in the control room's feed when the page loads
FEED_EVENTS = 600  # events read to tell them (a burst folds into one line)
MINI_WIDTH = 280.0  # a card's tide: half as long as the big one, as tall
RISK_CAP = 10_000  # risk-3 events counted beyond the rows read; past it the count says "≥"

# The states of the control room, most urgent first: a card shows the first that applies.
SENSOR_DOWN, WAITING, REWINDING = "sensor_down", "waiting", "rewinding"
WORKING, IDLE = "working", "idle"
STATES = (SENSOR_DOWN, WAITING, REWINDING, FROZEN, STOPPED, WORKING, IDLE, UNKNOWN)

SENSOR_ACTIONS = frozenset(
    {"sensor_start", "sensor_restart", "sensor_down", "sensor_unproven", "sensor_stop"}
)
SENSOR_IS_DOWN = frozenset({"sensor_down", "sensor_unproven"})
REWIND_ACTIONS = frozenset({"rewind_requested", "rewind_done", "rewind_failed"})

# What a held request wants to do, in plain words (i18n "req.<kind>"); anything else is "other".
KINDS = ("email", "message", "delete", "call", "pay", "post", "other")


class RosterError(ValueError):
    """The list of agents is not one the web can show (a bad or repeated slug, a long name)."""


@dataclass(frozen=True)
class AgentSource:
    """Where the web reads one agent from. ``slug`` is its address (``/agentes/<slug>/``) and
    ``name`` what the founder calls it (None: "your agent", in the page's language)."""

    slug: str
    name: str | None
    reader: BoxReader
    snapshots: Callable[[], Sequence[Snapshot]] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.slug, str) or not SLUG.fullmatch(self.slug):
            raise RosterError(f"an agent's slug must match {SLUG.pattern}, got {self.slug!r}")
        if self.name is not None and (
            not isinstance(self.name, str) or not self.name.strip() or len(self.name) > MAX_NAME
        ):
            raise RosterError(f"an agent's name is 1 to {MAX_NAME} characters")


@dataclass(frozen=True)
class Agent:
    """One agent of the roster, as the pages use it."""

    source: AgentSource
    colour: int  # 1..COLOURS: its identity colour (a-<colour> in the CSS)
    main: bool  # the one the service runs: its pages keep the old addresses, and it rewinds
    base: str  # the root of its pages

    @property
    def slug(self) -> str:
        return self.source.slug

    @property
    def name(self) -> str | None:
        return self.source.name

    @property
    def reader(self) -> BoxReader:
        return self.source.reader


class Roster:
    """The agents, in order: the main one first, then the rest. Colours follow the order, so an
    agent keeps its colour for the whole run."""

    def __init__(self, main: AgentSource, others: Iterable[AgentSource], base: str) -> None:
        sources = [main, *others]
        slugs = [s.slug for s in sources]
        if len(set(slugs)) != len(slugs):
            raise RosterError("two agents have the same slug")
        self.agents = tuple(
            Agent(
                source,
                colour=i % COLOURS + 1,
                main=i == 0,
                base=base if i == 0 else f"{base}/agentes/{source.slug}",
            )
            for i, source in enumerate(sources)
        )
        self._by_slug = {a.slug: a for a in self.agents}

    @property
    def main(self) -> Agent:
        return self.agents[0]

    def get(self, slug: str) -> Agent | None:
        return self._by_slug.get(slug)

    def __iter__(self):  # noqa: ANN204 - an iterator of Agent
        return iter(self.agents)

    def __len__(self) -> int:
        return len(self.agents)


# -- the gate's requests (T10) ------------------------------------------------------------------


@dataclass(frozen=True)
class PendingRequest:
    """Something an agent wants to do that the gate held until you say yes. ``target`` and
    ``detail`` are the agent's (shown as names); ``reason`` is the key of the gate's rule that
    held it (i18n "why.<reason>", an unknown one reads as "unknown")."""

    id: str
    agent: str
    kind: str
    target: str
    reason: str
    risk: int
    held_at: datetime
    expires_at: datetime
    detail: str = ""
    # T10-5: a hold of the real gate (``backtide.web.approve.held_request``). ``action`` and
    # ``notes`` are OUR words (backtide.gate.phrase); the rest is the agent's, cut and shown as
    # such. ``seq`` is its gate/held ("Ver"); ``waiting``, whether the agent waits connected;
    # ``batches`` and ``trustable``, what the person may make of it.
    action: str = ""
    notes: tuple[str, ...] = ()
    recipients: tuple[str, ...] = ()
    more_recipients: int = 0
    reply_to: tuple[str, ...] = ()
    subject: str = ""
    lines: str = ""
    attachments: tuple[str, ...] = ()
    request: str = ""
    seq: int | None = None
    waiting: bool = False
    batches: tuple[str, ...] = ()
    trustable: bool = False
    # Final review of T10: which API it is (``translator``, for our notes on the trust
    # confirmation) and, when it may not make a trusted recipient for a reason worth saying,
    # which one (``trust_off``: "mail", "name").
    translator: str = ""
    trust_off: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not SLUG.fullmatch(self.id):
            raise RosterError(f"a request id must match {SLUG.pattern}")
        if self.risk not in (0, 1, 2, 3):
            raise RosterError("a request's risk is 0 to 3")
        if self.expires_at <= self.held_at:
            raise RosterError("a request expires after it was held")

    @property
    def domains(self) -> tuple[str, ...]:
        """The domain of every address it names (recipients and Reply-To), each once: shown
        apart, in our words, so a long address cannot hide where it goes (finding 4)."""
        found = (
            item.rpartition("@")[2] for item in (*self.recipients, *self.reply_to) if "@" in item
        )
        return tuple(dict.fromkeys(domain for domain in found if domain))

    @property
    def what(self) -> str:
        return self.kind if self.kind in KINDS else "other"

    @property
    def target_name(self) -> Name:
        return Name(self.target[:300])

    @property
    def detail_name(self) -> Name | None:
        return Name(self.detail[:300]) if self.detail else None

    def left(self, now: datetime) -> timedelta:
        return max(self.expires_at - now, timedelta(0))

    def fraction_left(self, now: datetime) -> float:
        whole = (self.expires_at - self.held_at).total_seconds()
        return min(max(self.left(now).total_seconds() / whole, 0.0), 1.0)


def request_from(data: Mapping[str, Any]) -> PendingRequest:
    """A request from plain data (the demo's JSON). Raises RosterError on anything else."""
    try:
        held = datetime.fromisoformat(str(data["held_at"]))
        expires = datetime.fromisoformat(str(data["expires_at"]))
        risk = data.get("risk", 2)
        if held.utcoffset() is None or expires.utcoffset() is None:
            raise RosterError("request times carry their offset")
        if not isinstance(risk, int) or isinstance(risk, bool):
            raise RosterError("a request's risk is a number")
        return PendingRequest(
            id=str(data["id"]),
            agent=str(data["agent"]),
            kind=str(data.get("kind", "other")),
            target=str(data.get("target", "")),
            detail=str(data.get("detail", "")),
            reason=str(data.get("reason", "unknown")),
            risk=risk,
            held_at=held,
            expires_at=expires,
            action=str(data.get("action", ""))[:200],
            notes=tuple(str(n)[:200] for n in data.get("notes", []) if isinstance(n, str)),
            recipients=tuple(
                str(r)[:200] for r in data.get("recipients", []) if isinstance(r, str)
            )[:5],
            subject=str(data.get("subject", ""))[:200],
            lines=str(data.get("lines", ""))[:300],
            request=str(data.get("request", ""))[:600],
            trustable=data.get("trustable") is True,
            batches=tuple(b for b in data.get("batches", []) if b in ("recipient", "kind")),
            translator=str(data.get("translator", ""))[:20],
            trust_off=str(data.get("trust_off", ""))[:20],
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, RosterError):
            raise
        raise RosterError(f"not a request: {error}") from error


def countdown(left: timedelta) -> str:
    """``4:07`` for four minutes and seven seconds (``1:02:03`` past an hour)."""
    seconds = max(int(left.total_seconds()), 0)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


# -- what the box says about one agent --------------------------------------------------------

# The signals a card needs from the WHOLE box, not only from its newest rows: (source, actions).
SIGNALS: dict[str, tuple[Source, frozenset[str]]] = {
    "state": (Source.SYSTEM, frozenset(STATE_ACTIONS)),
    "sensor": (Source.SYSTEM, SENSOR_ACTIONS),
    "rewind": (Source.SNAPSHOT, REWIND_ACTIONS),
}


class Watch:
    """What one agent's whole box says beyond the newest rows a card reads: the newest state,
    sensor and rewind signals, and how many risk-3 events there were today.

    A card reads the newest ``ACTIVITY_EVENTS`` rows. An agent that floods its box (5001 file
    events) would push a ``sensor_down`` or a risk-3 action out of them, and the card would say
    "watched" and "0". So whatever the rows do not cover is asked for, by query, and kept: the
    first look queries the whole box once (like ``read_status`` does on every "Ahora"); after
    that only the events since the last look that the newest rows do not cover, which is
    nothing at all unless more than a whole read arrived in between. The box's ``source`` /
    ``action`` and ``risk`` columns have no index, so a whole-box query on every refresh would
    let a flood make the web slow; this keeps each query to what is new.

    ``update`` raises ``BoxUnavailable`` and then changes nothing. Not thread-safe: the app
    holds the agent's lock around it."""

    def __init__(self, reader: BoxReader) -> None:
        self.reader = reader
        self.upto = 0  # every event up to this seq has been looked at
        self.newest: dict[str, Event | None] = dict.fromkeys(SIGNALS)
        self.day: date | None = None
        self.risk3 = 0
        self.risk3_cut = False

    def update(self, rows: Sequence[Event], midnight: datetime) -> None:
        """``rows``: the agent's newest events, newest first. ``midnight``: when today began."""
        if not rows:
            return
        head, oldest = rows[0].seq, rows[-1].seq
        upto = self.upto if head >= self.upto else 0  # a box that went back: start again
        newest = dict(self.newest) if upto else dict.fromkeys(SIGNALS)
        gap = (upto, oldest) if oldest > upto + 1 else None  # seqs strictly between
        for name, (source, actions) in SIGNALS.items():
            found = next((e for e in rows if e.source is source and e.action in actions), None)
            if found is None and gap is not None:
                found = self._newest_between(source, actions, gap)
            if found is not None:
                newest[name] = found
        day = midnight.date()
        same_day = upto and self.day == day
        since = upto if same_day else 0
        count = self.risk3 if same_day else 0
        cut = self.risk3_cut if same_day else False
        count += sum(
            1 for e in rows if e.seq > since and e.risk >= 3 and fmt.parse_ts(e.ts) >= midnight
        )
        if oldest > since + 1:
            more = self.reader.events(
                min_risk=3,
                since_seq=since,
                before_seq=oldest,
                since_ts=midnight,
                newest_first=True,
                limit=RISK_CAP + 1,
            )
            cut = cut or len(more) > RISK_CAP
            count += min(len(more), RISK_CAP)
        self.upto, self.newest = head, newest
        self.day, self.risk3, self.risk3_cut = day, count, cut

    def _newest_between(
        self, source: Source, actions: frozenset[str], gap: tuple[int, int]
    ) -> Event | None:
        """The newest event of ``source`` with one of ``actions`` and a seq strictly between
        the two of ``gap``: one query per action, each limited to that range."""
        found: Event | None = None
        for action in sorted(actions):
            rows = self.reader.events(
                source=source,
                action=action,
                since_seq=gap[0],
                before_seq=gap[1],
                newest_first=True,
                limit=1,
            )
            if rows and (found is None or rows[0].seq > found.seq):
                found = rows[0]
        return found


@dataclass(frozen=True)
class Summary:
    """What one read of an agent's newest events says. Built by ``summarise``; cached by the app
    and combined with the requests and the clock when a card is drawn (``card``)."""

    head: int  # the seq of the newest event (0: none)
    last: Line | None  # the newest line, told (a burst folded)
    last_ts: str | None
    base_state: str  # watched / frozen / stopped / unknown, from the newest state signal
    sensor_down: bool
    rewinding_since: datetime | None
    events_today: int
    snaps_today: int
    risk3_today: int
    more: bool  # there were more events today than were read
    tide: Tide
    lines: tuple[Line, ...] = ()  # the newest lines for the control room's feed
    unreadable: bool = False
    whole: bool = True  # ``lines`` go back to the box's first event (nothing older was cut)
    risk3_cut: bool = False  # ``risk3_today`` is a floor: there may be more ("≥N")
    version: int = 0  # a new one every time the app reads the agent again (a card's key)


def summarise(
    rows: Sequence[Event],
    now: datetime,
    tz: tzinfo,
    *,
    cut: bool = False,
    watch: Watch | None = None,
    snapshots: Sequence[Snapshot] | None = None,
) -> Summary:
    """The summary of ``rows``: an agent's newest events, newest first (``cut``: there were
    more). ``watch`` keeps what the whole box says beyond them (``Watch``): the state, the
    sensor, a rewind and today's risk-3 count; it is updated here and may raise
    ``BoxUnavailable``. Without it, only the rows count."""
    newest_first = list(rows)
    midnight = now.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    today = [e for e in newest_first if fmt.parse_ts(e.ts) >= midnight]
    if watch is not None:
        watch.update(newest_first, midnight)
        state_event, sensor, rewind = (watch.newest[k] for k in ("state", "sensor", "rewind"))
        risk3, risk3_cut = watch.risk3, watch.risk3_cut
    else:
        state_event = next((e for e in newest_first if _moves_state(e)), None)
        sensor = next((e for e in newest_first if _is_sensor(e)), None)
        rewind = next(
            (e for e in newest_first if e.source is Source.SNAPSHOT and e.action in REWIND_ACTIONS),
            None,
        )
        risk3 = sum(1 for e in today if e.risk >= 3)
        risk3_cut = cut and len(today) == len(newest_first)
    status = status_from([state_event] if state_event is not None else [])
    rewinding_since = None
    if rewind is not None and rewind.action == "rewind_requested":
        asked = fmt.parse_ts(rewind.ts)
        if now - asked <= REWIND_FOR:
            rewinding_since = asked
    lines = Narrator().feed(reversed(newest_first[:FEED_EVENTS]))
    window = timedelta(hours=24)
    day = [e for e in newest_first if fmt.parse_ts(e.ts) >= now - window]
    takes = [e for e in day if e.source is Source.SNAPSHOT and e.action == "take"]
    marks = None
    if snapshots is not None:
        marks = [s for s in snapshots if s.taken_at >= now - window]
    tide = build_tide(
        list(reversed(takes)),
        now,
        [fmt.parse_ts(e.ts) for e in day],
        more=cut and len(day) == len(newest_first),
        snapshots=marks,
        width=MINI_WIDTH,
    )
    return Summary(
        head=newest_first[0].seq if newest_first else 0,
        last=lines[-1] if lines else None,
        last_ts=newest_first[0].ts if newest_first else None,
        base_state=status.state,
        sensor_down=sensor is not None and sensor.action in SENSOR_IS_DOWN,
        rewinding_since=rewinding_since,
        events_today=len(today),
        snaps_today=sum(1 for e in today if e.source is Source.SNAPSHOT and e.action == "take"),
        risk3_today=risk3,
        risk3_cut=risk3_cut,
        more=cut and len(today) == len(newest_first),
        tide=tide,
        lines=tuple(lines[-FEED_LINES:]),
        whole=not cut and len(newest_first) <= FEED_EVENTS and len(lines) <= FEED_LINES,
    )


def empty_summary(now: datetime, *, unreadable: bool = False) -> Summary:
    return Summary(
        head=0,
        last=None,
        last_ts=None,
        base_state=UNKNOWN,
        sensor_down=False,
        rewinding_since=None,
        events_today=0,
        snaps_today=0,
        risk3_today=0,
        more=False,
        tide=build_tide([], now, width=MINI_WIDTH),
        unreadable=unreadable,
    )


def _moves_state(event: Event) -> bool:
    return event.source is Source.SYSTEM and event.action in STATE_ACTIONS


def _is_sensor(event: Event) -> bool:
    return event.source is Source.SYSTEM and event.action in SENSOR_ACTIONS


def state_of(summary: Summary, pending: int, now: datetime) -> str:
    """The one state a card shows: the most urgent that applies (``STATES`` order)."""
    if summary.sensor_down and summary.base_state == WATCHED:
        return SENSOR_DOWN
    if pending:
        return WAITING
    if summary.rewinding_since is not None:
        return REWINDING
    if summary.base_state in (FROZEN, STOPPED):
        return summary.base_state
    if summary.base_state == WATCHED:
        moved = fmt.parse_ts(summary.last_ts) if summary.last_ts else None
        return WORKING if moved is not None and now - moved <= WORKING_FOR else IDLE
    return UNKNOWN


@dataclass(frozen=True)
class Card:
    """One agent's card in the control room."""

    agent: Agent
    summary: Summary
    state: str
    pending: tuple[PendingRequest, ...] = field(default=())

    @property
    def key(self) -> tuple[Any, ...]:
        """What makes two drawings of the card differ (ages tick in the browser)."""
        return (self.summary.version, self.state, tuple(p.id for p in self.pending))


def card(agent: Agent, summary: Summary, pending: Sequence[PendingRequest], now: datetime) -> Card:
    mine = tuple(p for p in pending if p.agent == agent.slug)
    return Card(agent, summary, state_of(summary, len(mine), now), mine)


def merged_feed(cards: Sequence[Card], limit: int) -> list[tuple[Agent, Line]]:
    """The newest lines of every agent, newest first, as far back as ALL of them reach: a busy
    agent's list is cut sooner, and a quiet one's older lines must not show below that cut as
    if nothing else had happened then."""
    cut = ""
    for one in cards:
        lines = one.summary.lines
        if lines and not one.summary.whole:
            cut = max(cut, started(lines[0]))
    merged = [(c.agent, line) for c in cards for line in c.summary.lines if started(line) >= cut]
    merged.sort(key=lambda pair: (started(pair[1]), pair[0].slug, pair[1].id), reverse=True)
    return merged[:limit]


def started(line: Line) -> str:
    """When a line began (a burst keeps its place in the feed as it grows)."""
    return line.first_ts or line.ts


def live_requests(
    requests: Sequence[PendingRequest], roster: Roster, now: datetime
) -> list[PendingRequest]:
    """The requests still waiting (not past their time) of agents on the roster, the one that
    runs out first at the top."""
    known = {a.slug for a in roster}
    waiting = [r for r in requests if r.agent in known and r.expires_at > now]
    return sorted(waiting, key=lambda r: (r.expires_at, r.id))
