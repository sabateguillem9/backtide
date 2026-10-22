"""The spending cap (T11): what the agent's model calls have cost today and this month, and whether
the next one may go out. Design: docs/33-diseno-t11-tope-de-gasto.md.

- **Where it is counted.** In backtide, never in the proxy: ``ProxyChannel`` asks ``admit`` before
  it lets a model call out (``llm/request``) and hands every ``llm/response`` to ``settle``, which
  prices it (``prices.cost_of``: priced from the provider's usage, or estimated by excess); the
  cost goes into the ``llm/response`` event (``details.cost``) and then ``book`` adds it here.
- **The check is before sending.** A call over the cap is refused (``spend_cap``) before it
  reaches the provider; the ones already in flight finish and are charged. Each call in flight
  reserves its estimate (``prices.estimate``: its bytes and its ``max_tokens`` at its model's
  price), and a new one is ``throttled`` while what is spent plus what is reserved reaches the
  cap: a burst passes the cap by one call at most (security review of T11, M5). There are also at
  most ``max_inflight`` calls (4 by default) at once. A call is never cut half way.
- **What backtide does not know is charged high, never low** (security review of T11): an answer
  that did not end (``complete`` not true) is charged at least its whole ``max_tokens`` of output
  (A1); a call that was let out and ends without an answer (an error, the answer stopped by the
  proxy, a new proxy, or no word of it in ``INFLIGHT_TTL``) is charged its estimate
  (``system/budget_charged``), and only one the proxy says never reached the provider
  (``upstream: false``) is freed for nothing (M1); the endpoints the providers do not bill (the
  list of models, Anthropic's token count) cost nothing but hold a place in flight (M4).
- **Windows.** A day and a month, natural, in the configured time zone (by default the
  machine's). Rolling over is decided by the clock (``now``) and only forwards: a clock that goes
  back never opens a new day with nothing spent.
- An answer with an error status (4xx, 5xx) and no usage costs nothing (the provider does not
  bill it); one with usage is priced as usual.
- **Kept across restarts** in ``<state_dir>/budget.json`` (0600, written atomically after every
  change): the totals of the current day and month, the warnings already given, the caps set
  from the web and the seq of the last cost event counted (``last_seq``). The black box stays
  append-only and is the record of every cost (``llm/response`` and ``system/budget_charged``):
  at start, what it has after ``last_seq`` is added (a file older than the black box, B1; a file
  without ``last_seq`` takes the larger of itself and the month rebuilt); if the file is missing
  or broken, the totals are rebuilt from the month's cost events (``system/budget_rebuilt``). If
  even that fails, every model call is refused (``spend_unavailable``): without a count nothing
  goes out.
- **Warnings** at 50 %, 80 % and 100 % of each window, once each per window
  (``system/budget_warning`` and ``system/budget_exceeded``), each with an alert (Telegram and the
  log; the web shows the totals). A jump past several thresholds records each and alerts once.
- **Raising the cap** (the Settings page, ``set_caps``) is recorded first
  (``settings/budget_set``); calls go through again at once if the new cap is above what was spent
  (``system/budget_unblocked``), and so at the next day or month.
- Refused calls are recorded as ``llm/blocked {reason: spend_cap}``, the first at once and then at
  most one every ``BLOCKED_EVERY`` seconds with how many: an agent that insists does not fill the
  black box.
- **A local model** (T20, docs/35 section 6.5): a call to a local provider (backtide's own config
  says the provider is local and the call went to its virtual name: ``ProxyChannel`` decides,
  never the proxy alone) costs 0 (``priced_by: "local"``), reserves nothing and is never stopped
  by the caps (it costs no money, and it is what can still work once the budget is spent). It
  has its own ``max_inflight_local`` calls in flight (2), apart from ``max_inflight``: one can
  take minutes and Ollama serves one at a time, so it must not leave the paid ones without room.
- Thread-safe: one lock for the totals, the file and what is recorded about them.
"""

import json
import logging
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, tzinfo
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from backtide.blackbox import Event, Source
from backtide.notify import Alert, AlertLevel
from backtide.service.prices import (
    DEFAULT_PRICES,
    DEFAULTS_SOURCE,
    ESTIMATE_MAX_OUTPUT,
    Cost,
    Price,
    PriceBook,
    cost_of,
    estimate,
    owner_shadowed,
    to_micro,
    usd,
)

logger = logging.getLogger(__name__)

STATE_BUDGET = "budget.json"
STATE_VERSION = 1
MAX_STATE_BYTES = 64 * 1024
# Decidido por defecto (revisable), docs/33: a cap from the first start, low enough that a loop
# costs little before someone looks, easy to raise from the web.
DEFAULT_DAILY_USD = Decimal("5")
DEFAULT_MONTHLY_USD = Decimal("50")
MAX_CAP_USD = Decimal("100000")
DEFAULT_MAX_INFLIGHT = 4
DEFAULT_MAX_INFLIGHT_LOCAL = 2  # T20, decision 7: Ollama serves one call at a time per model
MAX_INFLIGHT = 64
LOCAL = "local"  # Cost.priced_by of a local model's call
# B5: a call in flight holds its place until something closes it (its answer, an error, a
# block); this long safety TTL only catches one nobody ever says anything of, and charges it.
INFLIGHT_TTL = 2 * 3600.0
# What an answer that cannot be priced at all is charged (B2): the most output a call may be
# billed, at the dearest shipped output price.
FALLBACK_MICRO = ESTIMATE_MAX_OUTPUT * int(max(row.output for row in DEFAULT_PRICES.values()))
COST_EVENTS = (("llm", "response"), ("system", "budget_charged"))
THRESHOLDS = (50, 80, 100)
BLOCKED_EVERY = 10.0
WINDOWS = ("day", "month")
WINDOW_NAMES = {"day": "de hoy", "month": "de este mes"}
_RISK = {50: 0, 80: 1, 100: 2}
_LEVEL = {50: AlertLevel.INFO, 80: AlertLevel.WARNING, 100: AlertLevel.ERROR}

Record = Callable[..., Event | None]
Alerts = Callable[[Alert], object]
History = Callable[..., list[Event]]


class BudgetError(Exception):
    """The budget's file or the black box cannot be used. The message is for a log."""


@dataclass(frozen=True)
class BudgetSettings:
    """What ``[budget]`` says (``ServiceConfig.budget_settings``)."""

    daily_usd: Decimal = DEFAULT_DAILY_USD
    monthly_usd: Decimal = DEFAULT_MONTHLY_USD
    timezone: tzinfo | None = None  # None: the machine's local time
    timezone_name: str = "local"
    max_inflight: int = DEFAULT_MAX_INFLIGHT
    max_inflight_local: int = DEFAULT_MAX_INFLIGHT_LOCAL
    auto_prices: bool = True
    prices_url: str = ""
    owner_prices: dict[str, Price] = field(default_factory=dict)


def check_cap(value: object) -> Decimal | None:
    """A cap typed by a person: a positive number of dollars with at most two decimals, up to
    MAX_CAP_USD ("7", "7.5", "7,50"). None if it is not one."""
    if not isinstance(value, str) or not 0 < len(value.strip()) <= 12:
        return None
    text = value.strip().replace(",", ".")
    if not all(ch.isdigit() or ch == "." for ch in text) or text.count(".") > 1:
        return None
    try:
        number = Decimal(text)
    except InvalidOperation:
        return None
    if not number.is_finite() or number.as_tuple().exponent < -2:  # type: ignore[operator]
        return None
    return number if Decimal(0) < number <= MAX_CAP_USD else None


@dataclass(frozen=True)
class CapOutcome:
    """The answer to ``set_caps``. ``message`` is a fixed Spanish text."""

    ok: bool
    outcome: str  # saved | invalid | failed
    message: str


@dataclass
class _Flight:
    started: float
    request_bytes: int | None
    max_tokens: int | None
    model: str | None = None
    choices: int | None = None
    context: bool = False
    service_tier: str | None = None
    free: bool = False
    reserved: int = 0  # µ$ held against the caps while it is in flight (M5)
    local: bool = False  # T20: a local model's call: costs 0, counted apart


def local_zone(
    *, localtime: Path = Path("/etc/localtime"), env: Mapping[str, str] = os.environ
) -> tzinfo:
    """The machine's own time zone, with its changes of time (B4): ``TZ`` when it names a zone,
    else the zone ``/etc/localtime`` links to, else that file read as a zone; only if none of
    them works, today's fixed offset (warned: a day may then start an hour early or late)."""
    names = []
    tz = env.get("TZ", "").removeprefix(":")
    if tz:
        names.append(tz)
    try:
        target = str(localtime.resolve(strict=True))
    except OSError:
        target = ""
    if "zoneinfo/" in target:
        names.append(target.split("zoneinfo/", 1)[1])
    for name in names:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            continue
    try:
        with open(localtime, "rb") as data:
            return ZoneInfo.from_file(data, key="localtime")
    except (OSError, ValueError):
        pass
    logger.warning(
        "the machine's time zone has no name backtide can use: the spending's day follows "
        "today's fixed offset (set [budget] timezone to an IANA zone)"
    )
    return datetime.now().astimezone().tzinfo or UTC


class Budget:
    """The spending of the agent, its caps and its warnings. ``open()`` before use."""

    def __init__(
        self,
        settings: BudgetSettings,
        *,
        state_dir: Path,
        record: Record,
        alert: Alerts | None = None,
        history: History | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._state_dir = Path(state_dir)
        self._record = record
        self._alert = alert
        self._history = history
        self._now = now
        self._mono = monotonic
        self._tz = settings.timezone or local_zone()
        self._lock = threading.RLock()
        self.book = PriceBook(owner=dict(settings.owner_prices))
        for name, deeper in owner_shadowed(self.book).items():
            # M2: the owner's shorter id does not price these (a more specific row does).
            logger.warning(
                "[budget.prices.%s] does not apply to %s: a more specific price wins for them",
                name,
                ", ".join(deeper[:8]),
            )
        self._daily = to_micro(settings.daily_usd)
        self._monthly = to_micro(settings.monthly_usd)
        self._caps_from: str = "config"
        self._day = ""
        self._month = ""
        self._spent = {"day": 0, "month": 0}
        self._warned: dict[str, set[int]] = {"day": set(), "month": set()}
        self._estimated = 0
        self._last_seq = 0  # the seq of the last cost event counted (B1)
        self._unavailable = True  # until open() has the totals
        self._flights: dict[str, _Flight] = {}
        self._blocked = 0
        self._blocked_last = float("-inf")
        self._blocked_window = "day"
        self._unsaved_told = False
        # B3: the prices the page offers that are only used once the owner accepts them (new
        # models, or more than half below the shipped price), and who applies them.
        self.pending: dict[str, dict[str, Any]] = {}
        self._accept: Callable[[str, str], CapOutcome] | None = None

    # -- start ---------------------------------------------------------------------------

    def open(self) -> None:
        """The totals from ``budget.json``, caught up with the black box (B1), or rebuilt from it.
        Never raises: if neither works, every model call is refused until a restart (recorded,
        alerted)."""
        with self._lock:
            day, month = self._keys()
            try:
                state = self._load()
            except BudgetError as error:
                logger.error("the budget file cannot be used (%s): rebuilding it", error)
                state, why = None, "unreadable"
            else:
                why = "missing" if state is None else ""
            if state is not None:
                self._apply_state(state)
                self._roll(day, month, quiet=True)
                self._unavailable = False
                try:
                    self._catch_up("last_seq" in state)
                except Exception as error:  # the file's count stands; said
                    logger.error(
                        "cannot compare the spending with the black box: %s", type(error).__name__
                    )
                    self.tell(
                        AlertLevel.WARNING,
                        "No se ha podido comprobar el gasto",
                        "backtide sigue con lo que tenía apuntado, pero no ha podido compararlo "
                        "con la caja negra al arrancar (mira el registro).",
                        None,
                    )
                return
            try:
                self._rebuild(day, month)
            except Exception as error:  # the black box cannot be read: fail closed
                logger.error(
                    "cannot rebuild the spending from the black box: %s", type(error).__name__
                )
                self._unavailable = True
                event = self._safe_record(
                    "system",
                    "budget_unavailable",
                    "",
                    {"why": why, "error": type(error).__name__},
                    2,
                )
                self.tell(
                    AlertLevel.ERROR,
                    "No se puede contar el gasto",
                    "backtide no ha podido leer lo gastado este mes: las llamadas al modelo "
                    "se rechazan hasta que se arregle (mira el registro).",
                    event,
                )
                return
            self._unavailable = False
            self._safe_record(
                "system",
                "budget_rebuilt",
                "",
                {
                    "why": why,
                    "day_usd": usd(self._spent["day"]),
                    "month_usd": usd(self._spent["month"]),
                },
                1 if why == "unreadable" else 0,
            )
            self._save()

    def _count(self, since_seq: int | None) -> tuple[int, int, int, int]:
        """(day, month, estimated calls, last seq) of the cost events of this month in the black
        box, after ``since_seq`` (all of them with None)."""
        if self._history is None:
            raise BudgetError("no black box to read")
        now = self._now().astimezone(self._tz)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        spent_month = spent_day = estimated = 0
        last = since_seq or 0
        for source, action in COST_EVENTS:
            filters: dict[str, Any] = {"source": source, "action": action, "since_ts": month_start}
            if since_seq is not None:
                filters["since_seq"] = since_seq
            for event in self._history(**filters):
                last = max(last, event.seq)
                cost = event.details.get("cost") if isinstance(event.details, dict) else None
                micro = cost.get("usd_micro") if isinstance(cost, dict) else None
                if type(micro) is not int or micro < 0:
                    continue
                spent_month += micro
                if cost.get("estimated") is True:
                    estimated += 1
                when = _parse_ts(event.ts)
                if when is not None and when >= day_start:
                    spent_day += micro
        return spent_day, spent_month, estimated, last

    def _catch_up(self, incremental: bool) -> None:
        """B1: what the black box counted that the file does not have. With the file's
        ``last_seq``, the cost events after it are added; without it (an older file), the larger
        of the file and the month rebuilt is kept. Said (``budget_rebuilt {why: behind}``)."""
        day, month, estimated, last = self._count(self._last_seq if incremental else None)
        before = dict(self._spent)
        if incremental:
            self._spent = {"day": before["day"] + day, "month": before["month"] + month}
            self._estimated += estimated
        else:
            self._spent = {"day": max(before["day"], day), "month": max(before["month"], month)}
            self._estimated = max(self._estimated, estimated)
        self._last_seq = max(self._last_seq, last)
        if self._spent != before:
            for window in WINDOWS:  # what is crossed now is not announced: it was spent before
                self._warned[window] |= set(self._crossed(window))
            logger.warning("budget.json was behind the black box: the spending was caught up")
            self._safe_record(
                "system",
                "budget_rebuilt",
                "",
                {
                    "why": "behind",
                    "day_usd": usd(self._spent["day"]),
                    "month_usd": usd(self._spent["month"]),
                },
                1,
            )
        self._save()

    def _rebuild(self, day: str, month: str) -> None:
        spent_day, spent_month, estimated, last = self._count(None)
        self._day, self._month = day, month
        self._spent = {"day": spent_day, "month": spent_month}
        self._estimated = estimated
        self._last_seq = last
        # What was crossed before is not announced again.
        self._warned = {w: set(self._crossed(w)) for w in WINDOWS}

    # -- the gate ------------------------------------------------------------------------

    def admit(
        self,
        flow_id: object,
        *,
        model: object = None,
        request_bytes: object = None,
        max_tokens: object = None,
        choices: object = None,
        context: object = False,
        service_tier: object = None,
        free: bool = False,
        local: bool = False,
    ) -> str | None:
        """None if this model call may go out (it now holds a place in flight and, unless it is
        ``free``, reserves its estimate), else why not: ``spend_unavailable``, ``spend_cap``
        (recorded as ``llm/blocked``) or ``throttled`` (too many in flight, or what is spent and
        reserved reaches a cap: M5). ``local`` (T20): only its own ``max_inflight_local``
        counts; it reserves nothing and no cap stops it."""
        with self._lock:
            if local:
                return self._admit_local(flow_id)
            if self._unavailable:
                return "spend_unavailable"
            self._roll(*self._keys())
            self._expire()
            window = self.blocked_window()
            if window is not None:
                self._note_blocked(window, model)
                return "spend_cap"
            now = self._mono()
            paid = sum(1 for flight in self._flights.values() if not flight.local)
            if paid >= self._settings.max_inflight:
                return "throttled"
            flight = _Flight(
                now,
                request_bytes if type(request_bytes) is int else None,
                max_tokens if type(max_tokens) is int else None,
                model=model if isinstance(model, str) else None,
                choices=choices if type(choices) is int else None,
                context=context is True,
                service_tier=None if service_tier is None else str(service_tier)[:64],
                free=free is True,
            )
            if not flight.free:
                reserved = self._reserved()
                caps = {"day": self._daily, "month": self._monthly}
                if any(self._spent[w] + reserved >= caps[w] for w in WINDOWS):
                    return "throttled"  # the calls in flight may reach the cap already
                flight.reserved = self._estimate(flight)
            key = flow_id if isinstance(flow_id, str) and flow_id else f"anon-{now}"
            old = self._flights.pop(key, None)
            if old is not None:  # cannot be (flow ids are unique); never dropped uncharged
                self._charge_flight(key, old, "replaced")
            self._flights[key] = flight
            return None

    def _admit_local(self, flow_id: object) -> str | None:
        """A local model's call (T20): ``throttled`` past ``max_inflight_local`` in flight."""
        self._expire()
        now = self._mono()
        if sum(1 for f in self._flights.values() if f.local) >= self._settings.max_inflight_local:
            return "throttled"
        key = flow_id if isinstance(flow_id, str) and flow_id else f"anon-{now}"
        old = self._flights.pop(key, None)
        if old is not None:  # cannot be (flow ids are unique); never dropped uncharged
            self._charge_flight(key, old, "replaced")
        self._flights[key] = _Flight(now, None, None, local=True)
        return None

    def forget(self, flow_id: object) -> None:
        """A call that was never sent (backtide could not record it): freed, charged nothing."""
        with self._lock:
            if isinstance(flow_id, str):
                self._flights.pop(flow_id, None)

    def charge_unanswered(
        self, flow_id: object, *, why: str, cause: Event | None = None
    ) -> Cost | None:
        """A call let out that ended without an answer (an error, its answer stopped by the
        proxy): charged its estimate (M1), recorded as ``system/budget_charged``. None if no such
        call is in flight (answered already, or never let out)."""
        with self._lock:
            flight = self._flights.pop(flow_id, None) if isinstance(flow_id, str) else None
            if flight is None:
                return None
            return self._charge_flight(str(flow_id), flight, why, cause)

    def forget_all(self) -> None:
        """A new proxy: whatever the old one had in flight was let out and nobody will say what
        it cost, so each is charged its estimate (M1)."""
        with self._lock:
            flights, self._flights = self._flights, {}
            for key, flight in flights.items():
                self._charge_flight(key, flight, "proxy_restart")

    def settle(self, kind: str, details: dict[str, Any], *, local: bool = False) -> Cost:
        """The cost of one ``llm/response`` (it leaves the calls in flight and gives back its
        reservation). Not added yet: ``book`` adds it once its event is in the black box (or
        failed to be). Never raises: a price that cannot be worked out is the estimate (B2).
        ``local`` (T20, backtide's own reading of where the call went): 0."""
        with self._lock:
            flow_id = details.get("flow_id")
            flight = self._flights.pop(flow_id, None) if isinstance(flow_id, str) else None
            if local:
                if flight is not None and not flight.local:
                    # Admitted as a paid call: what it reserved is charged, never freed by a
                    # word of the proxy's (it cannot be: backtide decides both from its config).
                    return self._fallback(flight)
                return Cost(0, priced_by=LOCAL)
            if flight is not None and flight.local:
                return Cost(0, priced_by=LOCAL)  # admitted as local by backtide itself
            try:
                return self._price(kind, details, flight)
            except Exception:
                logger.exception("pricing a model answer failed: it is charged its estimate")
                return self._fallback(flight)

    def fallback_cost(self, details: Mapping[str, Any]) -> Cost:
        """What an answer is charged when even ``settle`` failed (B2). Never raises."""
        try:
            with self._lock:
                flow_id = details.get("flow_id")
                flight = self._flights.pop(flow_id, None) if isinstance(flow_id, str) else None
                return self._fallback(flight)
        except Exception:
            return Cost(FALLBACK_MICRO, estimated=True, priced_by="estimate")

    def _price(self, kind: str, details: Mapping[str, Any], flight: _Flight | None) -> Cost:
        if flight is not None and flight.free:
            return Cost(0, priced_by="free")  # M4: the provider does not bill it
        status = details.get("status")
        failed = type(status) is int and not 200 <= status < 300
        if failed and not isinstance(details.get("usage"), dict):
            # The provider refused or failed (a 4xx or 5xx, no usage): it does not bill it,
            # and estimating it would make a run of overloaded errors eat the cap.
            return Cost(0, priced_by="error")
        model = details.get("model")
        if not (isinstance(model, str) and model) and flight is not None:
            model = flight.model  # cut before the provider said it: the one asked for
        return cost_of(
            self.book,
            kind=kind,
            model=model,
            usage=details.get("usage"),
            request_bytes=None if flight is None else flight.request_bytes,
            max_tokens=None if flight is None else flight.max_tokens,
            choices=None if flight is None else flight.choices,
            context=flight is not None and flight.context,
            service_tier=None if flight is None else flight.service_tier,
            # A1: a 2xx (or no status) that did not end is billed for what it generated.
            complete=failed or details.get("complete") is True,
        )

    def _fallback(self, flight: _Flight | None) -> Cost:
        try:
            micro = (
                self._estimate(flight)
                if flight is not None
                else estimate(self.book, request_bytes=None, max_tokens=None)
            )
        except Exception:
            micro = FALLBACK_MICRO
        return Cost(micro, estimated=True, priced_by="estimate")

    def _estimate(self, flight: _Flight) -> int:
        return estimate(
            self.book,
            model=flight.model,
            request_bytes=flight.request_bytes,
            max_tokens=flight.max_tokens,
            choices=flight.choices,
            context=flight.context,
            service_tier=flight.service_tier,
        )

    def in_flight(self) -> tuple[int, int]:
        """(paid, local) calls in flight now."""
        with self._lock:
            local = sum(1 for flight in self._flights.values() if flight.local)
            return len(self._flights) - local, local

    def _reserved(self) -> int:
        return sum(flight.reserved for flight in self._flights.values())

    def _expire(self) -> None:
        """B5: a call nobody said anything of for INFLIGHT_TTL is charged its estimate."""
        now = self._mono()
        for key, flight in list(self._flights.items()):
            if now - flight.started > INFLIGHT_TTL:
                del self._flights[key]
                self._charge_flight(key, flight, "timeout")

    def _charge_flight(
        self, key: str, flight: _Flight, why: str, cause: Event | None = None
    ) -> Cost:
        """Charge a call that ended without an answer: its estimate, recorded first (the money
        counts also when that fails). A local model's call costs nothing (T20)."""
        if flight.local:
            return Cost(0, priced_by=LOCAL)
        if flight.free:
            return Cost(0, priced_by="free")
        cost = self._fallback(flight)
        unknown = self.book.lookup(flight.model) is None
        cost = Cost(cost.micro, estimated=True, unknown_model=unknown, priced_by="estimate")
        details: dict[str, Any] = {"flow_id": key[:64], "why": why, "cost": cost.details()}
        if cause is not None:
            details["seq"] = cause.seq
        event = self._safe_record("system", "budget_charged", "", details, 1)
        self.book_cost(cost, event)
        return cost

    def book_cost(self, cost: Cost, event: Event | None) -> None:
        """Add ``cost`` (whose ``llm/response`` is ``event``, None if it could not be recorded:
        the money was spent anyway) and give the warnings it crosses."""
        with self._lock:
            self._roll(*self._keys())
            for window in WINDOWS:
                self._spent[window] += cost.micro
            if cost.estimated:
                self._estimated += 1
            if event is not None:
                self._last_seq = max(self._last_seq, event.seq)
            self._save()
            for window in WINDOWS:
                self._warn(window, event)

    def blocked_window(self) -> str | None:
        """``day`` or ``month`` when that cap is reached (the month first), else None."""
        with self._lock:
            if self._spent["month"] >= self._monthly:
                return "month"
            if self._spent["day"] >= self._daily:
                return "day"
            return None

    def flush_blocked(self) -> None:
        """Record the refusals counted since the last ``llm/blocked``, if it is time (and charge
        the calls in flight past their TTL: B5)."""
        with self._lock:
            if not self._unavailable:
                self._expire()
            if self._blocked and self._mono() - self._blocked_last >= BLOCKED_EVERY:
                self._record_blocked(None)

    def _note_blocked(self, window: str, model: object) -> None:
        self._blocked += 1
        self._blocked_window = window
        if self._mono() - self._blocked_last >= BLOCKED_EVERY:
            self._record_blocked(model)

    def _record_blocked(self, model: object) -> None:
        details: dict[str, Any] = {
            "reason": "spend_cap",
            "window": self._blocked_window,
            "count": self._blocked,
        }
        if isinstance(model, str):
            details["model"] = model[:128]
        self._blocked = 0
        self._blocked_last = self._mono()
        self._safe_record("llm", "blocked", "", details, 2)

    # -- caps ----------------------------------------------------------------------------

    def set_caps(
        self, daily: Decimal | None, monthly: Decimal | None, *, requested_by: str
    ) -> CapOutcome:
        """New caps (None keeps that one). Recorded before anything changes."""
        if daily is None and monthly is None:
            return CapOutcome(
                False, "invalid", "No has puesto ningún tope: no se ha cambiado nada."
            )
        for value in (daily, monthly):
            if value is not None and not Decimal(0) < value <= MAX_CAP_USD:
                return CapOutcome(False, "invalid", CAP_SHAPE)
        with self._lock:
            new_daily = self._daily if daily is None else to_micro(daily)
            new_monthly = self._monthly if monthly is None else to_micro(monthly)
            before = self.blocked_window()
            details = {
                "daily_usd": usd(new_daily),
                "monthly_usd": usd(new_monthly),
                "daily_was_usd": usd(self._daily),
                "monthly_was_usd": usd(self._monthly),
                "requested_by": requested_by,
            }
            try:
                self._record(Source.SETTINGS, "budget_set", "budget", details=details, risk=1)
            except Exception as error:
                logger.error(
                    "a new spending cap was not recorded, so not set: %s", type(error).__name__
                )
                return CapOutcome(
                    False,
                    "failed",
                    "No se ha podido apuntar en la caja negra, así que no se ha cambiado nada.",
                )
            self._daily, self._monthly = new_daily, new_monthly
            self._caps_from = "web"
            for window in WINDOWS:  # what is below the new cap may be announced again
                self._warned[window] &= set(self._crossed(window))
            self._save()
            after = self.blocked_window()
            if before is not None and after is None:
                self._unblocked(before, "cap_raised")
        if after is not None:
            return CapOutcome(
                True,
                "saved",
                "Guardado. Lo gastado ya pasa del tope nuevo, así que "
                "las llamadas al modelo siguen bloqueadas.",
            )
        return CapOutcome(True, "saved", "Guardado. Se aplica a la siguiente llamada al modelo.")

    def _unblocked(self, window: str, why: str) -> None:
        event = self._safe_record(
            "system", "budget_unblocked", "", {"window": window, "why": why}, 0
        )
        self.tell(
            AlertLevel.INFO,
            "El agente puede volver a llamar al modelo",
            f"Lo gastado {WINDOW_NAMES[window]} ya está por debajo del tope "
            + ("(lo has subido)." if why == "cap_raised" else "(ha empezado otro periodo)."),
            event,
        )

    # -- what is shown -------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """For ``/estado``, the web's panel and Settings: totals, caps, prices' date. No secret."""
        with self._lock:
            if not self._unavailable:
                self._roll(*self._keys())
            book = self.book
            return {
                "available": not self._unavailable,
                "day": {
                    "spent_micro": self._spent["day"],
                    "cap_micro": self._daily,
                    "key": self._day,
                },
                "month": {
                    "spent_micro": self._spent["month"],
                    "cap_micro": self._monthly,
                    "key": self._month,
                },
                "blocked": None if self._unavailable else self.blocked_window(),
                "caps_from": self._caps_from,
                "estimated_calls": self._estimated,
                "inflight": len(self._flights),
                "reserved_micro": self._reserved(),
                "max_inflight": self._settings.max_inflight,
                "timezone": self._settings.timezone_name,
                "prices": {
                    "updated_on": None if book.fetched_on is None else book.fetched_on.isoformat(),
                    "source": "anthropic" if book.fetched_on is not None else DEFAULTS_SOURCE,
                    "defaults_on": book.defaults_on.isoformat(),
                    "auto": self._settings.auto_prices,
                    "owner_models": sorted(book.owner),
                    "pending": [
                        {"model": model} | entry for model, entry in sorted(self.pending.items())
                    ],
                    "pending_digest": pending_digest(self.pending),
                },
            }

    def lines(self) -> list[str]:
        """``status`` in Spanish, for ``/estado`` (Telegram)."""
        return status_lines(self.status())

    # -- prices --------------------------------------------------------------------------

    def use_fetched(self, table: dict[str, Price], on: date) -> None:
        with self._lock:
            self.book = self.book.with_fetched(table, on)

    def offer_prices(
        self, pending: Mapping[str, dict[str, Any]], accept: Callable[[str, str], CapOutcome]
    ) -> None:
        """B3: the prices waiting for the owner (``{model: {why, input, output}}``) and who
        applies them (``PriceUpdater.accept``)."""
        with self._lock:
            self.pending = {model: dict(entry) for model, entry in pending.items()}
            self._accept = accept

    def accept_prices(self, digest: object, *, requested_by: str) -> CapOutcome:
        """The owner accepts the prices waiting (the ones whose ``pending_digest`` is
        ``digest``, so what changed meanwhile is never accepted unseen)."""
        with self._lock:
            accept = self._accept
            current = pending_digest(self.pending)
        if accept is None or current is None:
            return CapOutcome(False, "invalid", "No hay precios nuevos por aceptar.")
        if not isinstance(digest, str) or digest != current:
            return CapOutcome(
                False,
                "invalid",
                "Los precios nuevos han cambiado desde que los viste: vuelve a mirarlos.",
            )
        return accept(digest, requested_by)

    # -- pieces --------------------------------------------------------------------------

    def _keys(self) -> tuple[str, str]:
        local = self._now().astimezone(self._tz)
        return local.date().isoformat(), f"{local.year:04d}-{local.month:02d}"

    def _roll(self, day: str, month: str, *, quiet: bool = False) -> None:
        """A new day or month (only forwards): its total and warnings start again."""
        before = self.blocked_window()
        changed = False
        if month > self._month:
            self._month = month
            self._spent["month"] = 0
            self._warned["month"] = set()
            changed = True
        if day > self._day:
            self._day = day
            self._spent["day"] = 0
            self._warned["day"] = set()
            changed = True
        if changed:
            self._save()
            if before is not None and self.blocked_window() is None and not quiet:
                self._unblocked(before, "new_period")

    def _crossed(self, window: str) -> list[int]:
        cap = self._daily if window == "day" else self._monthly
        spent = self._spent[window]
        return [t for t in THRESHOLDS if cap > 0 and spent * 100 >= cap * t]

    def _warn(self, window: str, cause: Event | None) -> None:
        new = [t for t in self._crossed(window) if t not in self._warned[window]]
        if not new:
            return
        cap = self._daily if window == "day" else self._monthly
        spent = self._spent[window]
        last: Event | None = None
        for threshold in new:
            self._warned[window].add(threshold)
            details = {
                "window": window,
                "pct": threshold,
                "spent_usd": usd(spent),
                "cap_usd": usd(cap),
            }
            if cause is not None:
                details["seq"] = cause.seq
            action = "budget_exceeded" if threshold == 100 else "budget_warning"
            last = self._safe_record("system", action, "", details, _RISK[threshold]) or last
        self._save()
        top = new[-1]
        spent_text, cap_text = _euroish(spent), _euroish(cap)
        if top == 100:
            until = "mañana" if window == "day" else "el mes que viene"
            title = f"Tope de gasto {WINDOW_NAMES[window]} alcanzado"
            body = (
                f"El agente ha gastado {spent_text} $ de {cap_text} $ {WINDOW_NAMES[window]}. Las "
                f"llamadas al modelo están bloqueadas hasta {until} o hasta que subas el tope en "
                "Ajustes de la web. Las que ya estaban en marcha terminan."
            )
        else:
            title = f"El agente lleva el {top} % de su tope {WINDOW_NAMES[window]}"
            body = f"Ha gastado {spent_text} $ de {cap_text} $ {WINDOW_NAMES[window]}."
        self.tell(_LEVEL[top], title, body, last)

    def tell(self, level: AlertLevel, title: str, body: str, event: Event | None) -> None:
        if self._alert is None:
            return
        try:
            self._alert(Alert(level, title, body, None if event is None else event.seq))
        except Exception:
            logger.exception("an alert about the spending could not be queued")

    def _safe_record(
        self, source: str, action: str, target: str, details: dict[str, Any], risk: int
    ) -> Event | None:
        try:
            return self._record(source, action, target, details=details, risk=risk)
        except Exception as error:
            logger.error("cannot record %s/%s: %s", source, action, type(error).__name__)
            return None

    def _load(self) -> dict[str, Any] | None:
        path = self._state_dir / STATE_BUDGET
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise BudgetError(f"cannot open {STATE_BUDGET}: {error.strerror}") from None
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise BudgetError(f"{STATE_BUDGET} is not ours and private")
            data = os.read(fd, MAX_STATE_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_STATE_BYTES:
            raise BudgetError(f"{STATE_BUDGET} is too big")
        try:
            state = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise BudgetError(f"{STATE_BUDGET} is not JSON") from None
        _check_state(state)
        return state

    def _apply_state(self, state: dict[str, Any]) -> None:
        self._day, self._month = state["day"], state["month"]
        self._spent = {"day": state["day_micro"], "month": state["month_micro"]}
        self._warned = {w: set(state["warned"][w]) for w in WINDOWS}
        self._estimated = state["estimated_calls"]
        self._last_seq = state.get("last_seq", 0)
        caps = state.get("caps")
        if caps is not None:
            self._daily, self._monthly = caps["daily_micro"], caps["monthly_micro"]
            self._caps_from = "web"

    def _save(self) -> None:
        from backtide.service.settings import SettingsError, write_private

        state: dict[str, Any] = {
            "version": STATE_VERSION,
            "day": self._day,
            "month": self._month,
            "day_micro": self._spent["day"],
            "month_micro": self._spent["month"],
            "warned": {w: sorted(self._warned[w]) for w in WINDOWS},
            "estimated_calls": self._estimated,
            "last_seq": self._last_seq,
        }
        if self._caps_from == "web":
            state["caps"] = {"daily_micro": self._daily, "monthly_micro": self._monthly}
        try:
            write_private(
                self._state_dir, STATE_BUDGET, json.dumps(state).encode(), private_dir=False
            )
            self._unsaved_told = False
        except (SettingsError, OSError) as error:
            # The totals in memory are right; a restart rebuilds them from the black box.
            logger.error("cannot save the spending to %s: %s", STATE_BUDGET, error)
            if not self._unsaved_told:
                self._unsaved_told = True
                self._safe_record(
                    "system", "budget_unsaved", "", {"error": type(error).__name__}, 1
                )


def _check_state(state: object) -> None:
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise BudgetError(f"{STATE_BUDGET} is not a budget of this version")
    allowed = {
        "version",
        "day",
        "month",
        "day_micro",
        "month_micro",
        "warned",
        "estimated_calls",
        "caps",
        "last_seq",
    }
    if not set(state) <= allowed:
        raise BudgetError(f"{STATE_BUDGET} has unknown fields")
    for name, length in (("day", 10), ("month", 7)):
        value = state.get(name)
        if not isinstance(value, str) or len(value) != length:
            raise BudgetError(f"{STATE_BUDGET}: {name} is not a date")
    for name in ("day_micro", "month_micro", "estimated_calls", "last_seq"):
        if name == "last_seq" and name not in state:
            continue
        value = state.get(name)
        if type(value) is not int or value < 0:
            raise BudgetError(f"{STATE_BUDGET}: {name} is not a count")
    warned = state.get("warned")
    if (
        not isinstance(warned, dict)
        or set(warned) != set(WINDOWS)
        or not all(isinstance(v, list) and all(t in THRESHOLDS for t in v) for v in warned.values())
    ):
        raise BudgetError(f"{STATE_BUDGET}: warned is not valid")
    caps = state.get("caps")
    if caps is not None and (
        not isinstance(caps, dict)
        or set(caps) != {"daily_micro", "monthly_micro"}
        or not all(type(v) is int and 0 < v <= to_micro(MAX_CAP_USD) for v in caps.values())
    ):
        raise BudgetError(f"{STATE_BUDGET}: caps are not valid")


def pending_digest(pending: Mapping[str, Any]) -> str | None:
    """A short fingerprint of the prices waiting (None when there are none): what the owner saw
    is what is accepted."""
    if not pending:
        return None
    import hashlib

    data = json.dumps(pending, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()[:16]


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _euroish(micro: int) -> str:
    """Dollars for a person, Spanish style: ``1,25``."""
    return usd(micro).replace(".", ",")


CAP_SHAPE = (
    "El tope tiene que ser una cantidad de dólares mayor que cero, con dos decimales como mucho "
    f"(hasta {MAX_CAP_USD}): no se ha cambiado nada."
)


def status_lines(status: dict[str, Any]) -> list[str]:
    """The spending in Spanish, a line per window and one for the prices."""
    if not status.get("available"):
        return ["Gasto: no se puede contar ahora mismo; las llamadas al modelo se rechazan."]
    lines = []
    for window, name in (("day", "hoy"), ("month", "este mes")):
        part = status[window]
        lines.append(
            f"Gasto {name}: {_euroish(part['spent_micro'])} $ de {_euroish(part['cap_micro'])} $."
        )
    blocked = status.get("blocked")
    if blocked:
        lines.append(f"Tope {WINDOW_NAMES[blocked]} alcanzado: las llamadas al modelo se rechazan.")
    prices = status["prices"]
    if prices.get("updated_on"):
        lines.append(f"Precios actualizados el {prices['updated_on']} (fuente: Anthropic).")
    else:
        lines.append(f"Precios de fábrica del {prices['defaults_on']}.")
    return lines
