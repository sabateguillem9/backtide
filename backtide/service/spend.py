"""The spending cap (T11): what the agent's model calls have cost today and this month, and whether
the next one may go out. Design: docs/33-diseno-t11-tope-de-gasto.md.

- **Where it is counted.** In backtide, never in the proxy: ``ProxyChannel`` asks ``admit`` before
  it lets a model call out (``llm/request``) and hands every ``llm/response`` to ``settle``, which
  prices it (``prices.cost_of``: priced from the provider's usage, or estimated by excess); the
  cost goes into the ``llm/response`` event (``details.cost``) and then ``book`` adds it here.
- **The check is before sending.** A call over the cap is refused (``spend_cap``) before it
  reaches the provider; the ones already in flight finish and are charged. So a burst can pass
  the cap by what the calls in flight cost: at most ``max_inflight`` calls (4 by default) at once,
  past which a new one gets ``throttled`` with a short wait. A call is never cut half way.
- **Windows.** A day and a month, natural, in the configured time zone (by default the
  machine's). Rolling over is decided by the clock (``now``) and only forwards: a clock that goes
  back never opens a new day with nothing spent.
- An answer with an error status (4xx, 5xx) and no usage costs nothing (the provider does not
  bill it); one with usage is priced as usual.
- **Kept across restarts** in ``<state_dir>/budget.json`` (0600, written atomically after every
  change): the totals of the current day and month, the warnings already given and the caps set
  from the web. The black box stays append-only and is the record of every cost; if the file is
  missing or broken, the totals are rebuilt from the ``llm/response`` events of the month
  (``system/budget_rebuilt``). If even that fails, every model call is refused
  (``spend_unavailable``): without a count nothing goes out.
- **Warnings** at 50 %, 80 % and 100 % of each window, once each per window
  (``system/budget_warning`` and ``system/budget_exceeded``), each with an alert (Telegram and the
  log; the web shows the totals). A jump past several thresholds records each and alerts once.
- **Raising the cap** (the Settings page, ``set_caps``) is recorded first
  (``settings/budget_set``); calls go through again at once if the new cap is above what was spent
  (``system/budget_unblocked``), and so at the next day or month.
- Refused calls are recorded as ``llm/blocked {reason: spend_cap}``, the first at once and then at
  most one every ``BLOCKED_EVERY`` seconds with how many: an agent that insists does not fill the
  black box.
- Thread-safe: one lock for the totals, the file and what is recorded about them.
"""

import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, tzinfo
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from backtide.blackbox import Event, Source
from backtide.notify import Alert, AlertLevel
from backtide.service.prices import (
    DEFAULTS_SOURCE,
    Cost,
    Price,
    PriceBook,
    cost_of,
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
MAX_INFLIGHT = 64
INFLIGHT_TTL = 30 * 60.0  # seconds: a call never answered stops holding its place
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
        self._tz = settings.timezone or datetime.now().astimezone().tzinfo or UTC
        self._lock = threading.RLock()
        self.book = PriceBook(owner=dict(settings.owner_prices))
        self._daily = to_micro(settings.daily_usd)
        self._monthly = to_micro(settings.monthly_usd)
        self._caps_from: str = "config"
        self._day = ""
        self._month = ""
        self._spent = {"day": 0, "month": 0}
        self._warned: dict[str, set[int]] = {"day": set(), "month": set()}
        self._estimated = 0
        self._unavailable = True  # until open() has the totals
        self._flights: dict[str, _Flight] = {}
        self._blocked = 0
        self._blocked_last = float("-inf")
        self._blocked_window = "day"
        self._unsaved_told = False

    # -- start ---------------------------------------------------------------------------

    def open(self) -> None:
        """The totals from ``budget.json``, or rebuilt from the black box. Never raises: if
        neither works, every model call is refused until a restart (recorded, alerted)."""
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

    def _rebuild(self, day: str, month: str) -> None:
        if self._history is None:
            raise BudgetError("no black box to rebuild from")
        now = self._now().astimezone(self._tz)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        spent_month = spent_day = estimated = 0
        for event in self._history(source="llm", action="response", since_ts=month_start):
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
        self._day, self._month = day, month
        self._spent = {"day": spent_day, "month": spent_month}
        self._estimated = estimated
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
    ) -> str | None:
        """None if this model call may go out (it now holds a place in flight), else why not:
        ``spend_unavailable``, ``spend_cap`` (recorded as ``llm/blocked``) or ``throttled``."""
        with self._lock:
            if self._unavailable:
                return "spend_unavailable"
            self._roll(*self._keys())
            window = self.blocked_window()
            if window is not None:
                self._note_blocked(window, model)
                return "spend_cap"
            now = self._mono()
            for key, flight in list(self._flights.items()):
                if now - flight.started > INFLIGHT_TTL:
                    del self._flights[key]
            if len(self._flights) >= self._settings.max_inflight:
                return "throttled"
            key = flow_id if isinstance(flow_id, str) and flow_id else f"anon-{now}"
            self._flights[key] = _Flight(
                now,
                request_bytes if type(request_bytes) is int else None,
                max_tokens if type(max_tokens) is int else None,
            )
            return None

    def forget(self, flow_id: object) -> None:
        """A call that ended without an answer (an error, a refusal of its answer)."""
        with self._lock:
            if isinstance(flow_id, str):
                self._flights.pop(flow_id, None)

    def forget_all(self) -> None:
        """A new proxy: whatever the old one had in flight is gone (and was never answered)."""
        with self._lock:
            self._flights.clear()

    def settle(self, kind: str, details: dict[str, Any]) -> Cost:
        """The cost of one ``llm/response`` (it leaves the calls in flight). Not added yet:
        ``book`` adds it once its event is in the black box (or failed to be)."""
        with self._lock:
            flow_id = details.get("flow_id")
            flight = self._flights.pop(flow_id, None) if isinstance(flow_id, str) else None
            status = details.get("status")
            failed = type(status) is int and not 200 <= status < 300
            if failed and not isinstance(details.get("usage"), dict):
                # The provider refused or failed (a 4xx or 5xx, no usage): it does not bill it,
                # and estimating it would make a run of overloaded errors eat the cap.
                return Cost(0, priced_by="error")
            return cost_of(
                self.book,
                kind=kind,
                model=details.get("model"),
                usage=details.get("usage"),
                request_bytes=None if flight is None else flight.request_bytes,
                max_tokens=None if flight is None else flight.max_tokens,
            )

    def book_cost(self, cost: Cost, event: Event | None) -> None:
        """Add ``cost`` (whose ``llm/response`` is ``event``, None if it could not be recorded:
        the money was spent anyway) and give the warnings it crosses."""
        with self._lock:
            self._roll(*self._keys())
            for window in WINDOWS:
                self._spent[window] += cost.micro
            if cost.estimated:
                self._estimated += 1
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
        """Record the refusals counted since the last ``llm/blocked``, if it is time."""
        with self._lock:
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
                "max_inflight": self._settings.max_inflight,
                "timezone": self._settings.timezone_name,
                "prices": {
                    "updated_on": None if book.fetched_on is None else book.fetched_on.isoformat(),
                    "source": "anthropic" if book.fetched_on is not None else DEFAULTS_SOURCE,
                    "defaults_on": book.defaults_on.isoformat(),
                    "auto": self._settings.auto_prices,
                    "owner_models": sorted(book.owner),
                },
            }

    def lines(self) -> list[str]:
        """``status`` in Spanish, for ``/estado`` (Telegram)."""
        return status_lines(self.status())

    # -- prices --------------------------------------------------------------------------

    def use_fetched(self, table: dict[str, Price], on: date) -> None:
        with self._lock:
            self.book = self.book.with_fetched(table, on)

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
    }
    if not set(state) <= allowed:
        raise BudgetError(f"{STATE_BUDGET} has unknown fields")
    for name, length in (("day", 10), ("month", 7)):
        value = state.get(name)
        if not isinstance(value, str) or len(value) != length:
            raise BudgetError(f"{STATE_BUDGET}: {name} is not a date")
    for name in ("day_micro", "month_micro", "estimated_calls"):
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
