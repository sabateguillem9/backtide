"""The spending cap of the whole installation (T26-2c; docs/47 section 6.4, decision 13).

Adding agents must not multiply what is spent unless the owner says so. So ``[budget]`` of
``backtide.toml`` (5 $ a day and 50 $ a month, D5) is the cap of the machine, and each agent may
have a lower one of its own (``backtide.service.spend.Budget``). With one agent none of this
exists: its caps are the installation's, as they always were.

- **An agent with no cap of its own** has only this one (``build_budget`` gives its ``Budget``
  ``MAX_CAP_USD``), so raising the total raises what each may spend. Its file's ``[budget]``
  (``daily_usd``, ``monthly_usd``) or a cap set for it by the owner lowers it.
- **What is counted.** Each agent's ``Budget`` is the record of its own spending (its
  ``budget.json`` and its black box), so there is no second ledger that could disagree: the total is
  their sum. Each tells this object what it has now (``report``), and an agent that has not
  started (or could not: its model calls do not go out, but what it spent this month still counts)
  is read from its ``budget.json``.
- **What backtide does not know.** An agent whose count cannot be made (a ``budget.json`` that
  cannot be used and no ``Budget`` that says otherwise, or a ``Budget`` that could not rebuild it)
  leaves the total unknown, and without a count nothing goes out (``spend_unavailable``), for every
  agent, as with one (docs/33). It is recorded and alerted once, and it ends by itself when the
  count comes back.
- **The check is one step.** ``reserve`` looks at what all of them have spent and at what this
  agent has in flight, and takes its part with one lock, so that several at once pass the cap by one
  call each at most (security review of T11, M5). What another has in flight does not count: a call
  of an agent with a huge ``max_tokens``, which a provider refuses for free, would leave the others
  with no model for nothing (review of T26-2c).
- **What it keeps.** ``<state_dir>/installation/budget.json``: the caps set by the owner (they win
  over ``[budget]``, as an agent's do) and the warnings already given, and no totals. The first
  time, with no such file, the caps are the ones the main agent had really set, which until now
  were the installation's, and that is written at once, so it happens once. ``MAX_CAP_USD`` there
  means it has none of its own, and is never taken. A file that cannot be used gives ``[budget]``,
  said.
- **What goes where.** The warnings and the changes of its caps are the installation's, so they go
  to its black box (``settings/budget_set``, recorded before anything changes, and
  ``system/budget_warning`` and ``budget_exceeded``). A call that is refused is the agent's: its
  ``llm/blocked`` says ``scope: installation``.
- Thread-safe, one lock. A ``Budget`` calls in with its own lock held and this never calls back,
  so the order is always the same. Nothing slow runs under this lock.
"""

import dataclasses
import json
import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from backtide.notify import Alert, AlertLevel
from backtide.service.prices import to_micro, usd
from backtide.service.spend import (
    _LEVEL,
    _RISK,
    CAP_SHAPE,
    MAX_CAP_USD,
    STATE_BUDGET,
    THRESHOLDS,
    UNCOUNTED,
    WINDOW_NAMES,
    WINDOWS,
    BudgetError,
    BudgetSettings,
    CapOutcome,
    Count,
    _euroish,
    local_zone,
    read_private_json,
    read_state,
)

logger = logging.getLogger(__name__)

STATE_VERSION = 1
# action, target, details, risk and source; False if it could not be recorded.
Record = Callable[..., bool]
Alerts = Callable[[Alert], object]


@dataclass
class _Totals:
    day: int = 0
    month: int = 0
    reserved: int = 0
    uncounted: tuple[str, ...] = ()


class InstallationSpend:
    """The total of the agents ``members`` (slug to the folder of its ``budget.json``)."""

    def __init__(
        self,
        settings: BudgetSettings,
        *,
        members: Mapping[str, Path],
        folder: Path,
        inherit_from: Path | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._members = dict(members)
        self._folder = Path(folder)
        self._now = now
        self._tz = settings.timezone or local_zone()
        self._lock = threading.Lock()
        self._counts: dict[str, Count] = {}
        self._record: Record = lambda *_, **__: False
        self._alert: Alerts | None = None
        self._daily = to_micro(settings.daily_usd)
        self._monthly = to_micro(settings.monthly_usd)
        self._caps_from = "config"
        self._day = ""
        self._month = ""
        self._warned: dict[str, set[int]] = {window: set() for window in WINDOWS}
        self._said_uncounted: tuple[str, ...] = ()
        self._file_was_broken = False
        self._ended_blocked: str | None = None  # a window that was blocked and ended, to be said
        self._load(inherit_from)

    def bind(self, *, record: Record, alert: Alerts) -> None:
        """Where it writes and who it tells (the installation's box and the owner). Separate
        because the alerts are born with the main agent's ``Guardian``, which needs this."""
        self._record, self._alert = record, alert
        if self._file_was_broken:
            self._file_was_broken = False
            self._record("budget_file_unusable", "", {"file": STATE_BUDGET}, risk=1)
            self._tell(
                AlertLevel.WARNING,
                "No se ha podido leer el tope de toda la instalación",
                "Se usa el de [budget] de backtide.toml hasta que lo cambies (mira el registro).",
            )

    # -- what a Budget asks -----------------------------------------------------------------

    def report(self, slug: str, count: Count) -> None:
        with self._lock:
            self._counts[slug] = count

    def blocked(self) -> str | None:
        """``month`` or ``day`` when that cap of the whole installation is reached, ``UNCOUNTED``
        when the total cannot be known, else None."""
        with self._lock:
            self._roll()
            totals = self._totals()
            window = self._window(totals)
            unblocked, self._ended_blocked = self._ended_blocked, None
        self._say_uncounted(totals.uncounted)
        self._say_unblocked(unblocked)
        if totals.uncounted:
            return UNCOUNTED
        return window

    def reserve(self, slug: str, micro: int) -> bool:
        """Take ``micro`` for a call in flight, unless what all of them have spent and what this
        one holds already reaches a cap. The agent's own next ``report`` says the same, exactly."""
        with self._lock:
            totals = self._totals()
            count = self._counts.get(slug, Count())
            if (
                totals.uncounted
                or totals.day + count.reserved >= self._daily
                or totals.month + count.reserved >= self._monthly
            ):
                return False
            self._counts[slug] = dataclasses.replace(count, reserved=count.reserved + micro)
            return True

    def booked(self) -> None:
        """A cost was added somewhere: the warnings it crosses, once each per window."""
        with self._lock:
            self._roll()
            totals = self._totals()
            told = [
                (window, threshold, spent, cap)
                for window, spent, cap in (
                    ("day", totals.day, self._daily),
                    ("month", totals.month, self._monthly),
                )
                for threshold in _crossed(spent, cap)
                if threshold not in self._warned[window]
            ]
            for window, threshold, _, _ in told:
                self._warned[window].add(threshold)
            if told:
                self._save()
        for window in WINDOWS:
            mine = [item for item in told if item[0] == window]
            if mine:
                self._warn(window, mine)

    # -- what the sockets ask ---------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """The total, its caps and each agent's part. No secret."""
        with self._lock:
            self._roll()
            totals = self._totals()
            agents = {
                slug: {"day_micro": day, "month_micro": month}
                for slug, (day, month) in self._parts().items()
            }
            return {
                "available": not totals.uncounted,
                "uncounted": list(totals.uncounted),
                "day": {"spent_micro": totals.day, "cap_micro": self._daily, "key": self._day},
                "month": {
                    "spent_micro": totals.month,
                    "cap_micro": self._monthly,
                    "key": self._month,
                },
                "blocked": None if totals.uncounted else self._window(totals),
                "caps_from": self._caps_from,
                "reserved_micro": totals.reserved,
                "agents": agents,
            }

    def set_caps(
        self, daily: Decimal | None, monthly: Decimal | None, *, requested_by: str
    ) -> CapOutcome:
        """New caps for the whole installation (None keeps that one). Recorded before anything
        changes, in the installation's box: not recorded, not changed."""
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
            before = self._window(self._totals())
            details = {
                "scope": "installation",
                "daily_usd": usd(new_daily),
                "monthly_usd": usd(new_monthly),
                "daily_was_usd": usd(self._daily),
                "monthly_was_usd": usd(self._monthly),
                "requested_by": requested_by,
            }
        if not self._record("budget_set", "budget", details, risk=1, source="settings"):
            logger.error("a new cap of the whole installation was not recorded, so not set")
            return CapOutcome(
                False,
                "failed",
                "No se ha podido apuntar en la caja de la instalación, así que no se ha cambiado "
                "nada.",
            )
        with self._lock:
            self._daily, self._monthly = new_daily, new_monthly
            self._caps_from = "web"
            totals = self._totals()
            self._warned = {
                "day": self._warned["day"] & set(_crossed(totals.day, self._daily)),
                "month": self._warned["month"] & set(_crossed(totals.month, self._monthly)),
            }
            self._save()
            after = self._window(totals)
        if before is not None and after is None:
            self._say_unblocked(before, "(lo has subido).")
        if after is not None:
            return CapOutcome(
                True,
                "saved",
                "Guardado, para toda la instalación. Lo gastado ya pasa del tope nuevo, así que "
                "las llamadas al modelo siguen bloqueadas.",
            )
        return CapOutcome(
            True,
            "saved",
            "Guardado, para toda la instalación. Se aplica a la siguiente llamada al modelo.",
        )

    # -- pieces ------------------------------------------------------------------------------

    def _keys(self) -> tuple[str, str]:
        local = self._now().astimezone(self._tz)
        return local.date().isoformat(), f"{local.year:04d}-{local.month:02d}"

    def _roll(self) -> None:
        """A new day or month, only forwards. Its warnings start again, and what was blocked by
        the one that ended is said by ``blocked``, outside the lock."""
        day, month = self._keys()
        if day <= self._day and month <= self._month:
            return
        before = self._window(self._totals())
        changed = False
        if month > self._month:
            self._month, self._warned["month"] = month, set()
            changed = True
        if day > self._day:
            self._day, self._warned["day"] = day, set()
            changed = True
        if changed:
            self._save()
        if before is not None and self._window(self._totals()) is None:
            self._ended_blocked = before

    def _count_of(self, slug: str) -> Count | None:
        """What this agent says, or what its file says if it has not started; None if unknown."""
        count = self._counts.get(slug)
        if count is not None:
            return count if count.counted else None
        try:
            state = read_state(self._members[slug])
        except BudgetError as error:
            logger.error("the spending of the agent %s cannot be read: %s", slug, error)
            return None
        if state is None:
            return Count()
        return Count(state["day"], state["month"], state["day_micro"], state["month_micro"])

    def _parts(self) -> dict[str, tuple[int, int]]:
        parts = {}
        for slug in self._members:
            count = self._count_of(slug)
            if count is not None:
                parts[slug] = (
                    count.spent_day if count.day >= self._day else 0,
                    count.spent_month if count.month >= self._month else 0,
                )
        return parts

    def _totals(self) -> _Totals:
        totals = _Totals()
        uncounted = []
        for slug in self._members:
            count = self._count_of(slug)
            if count is None:
                uncounted.append(slug)
                continue
            # Only forwards, as in a Budget: a count of yesterday is not today's spending.
            if count.day >= self._day:
                totals.day += count.spent_day
            if count.month >= self._month:
                totals.month += count.spent_month
            totals.reserved += count.reserved
        totals.uncounted = tuple(uncounted)
        return totals

    def _window(self, totals: _Totals) -> str | None:
        if totals.month >= self._monthly:
            return "month"
        if totals.day >= self._daily:
            return "day"
        return None

    def _say_uncounted(self, uncounted: tuple[str, ...]) -> None:
        with self._lock:
            if uncounted == self._said_uncounted:
                return
            self._said_uncounted = uncounted
        if not uncounted:
            return
        names = ", ".join(uncounted)
        self._record("budget_unavailable", "", {"agents": list(uncounted)}, risk=2)
        self._tell(
            AlertLevel.ERROR,
            "No se puede contar el gasto de toda la instalación",
            f"Falta lo gastado por {names}: las llamadas al modelo de todos los agentes se "
            "rechazan hasta que se pueda contar (mira su budget.json y el registro).",
        )

    def _say_unblocked(self, window: str | None, why: str = "(ha empezado otro periodo).") -> None:
        if window is None:
            return
        self._record("budget_unblocked", "", {"window": window, "scope": "installation"}, risk=0)
        self._tell(
            AlertLevel.INFO,
            "Los agentes pueden volver a llamar al modelo",
            f"Lo gastado {WINDOW_NAMES[window]} por toda la instalación ya está por debajo del "
            f"tope {why}",
        )

    def _warn(self, window: str, crossed: list[tuple[str, int, int, int]]) -> None:
        for _, threshold, spent, cap in crossed:
            action = "budget_exceeded" if threshold == 100 else "budget_warning"
            details = {
                "scope": "installation",
                "window": window,
                "pct": threshold,
                "spent_usd": usd(spent),
                "cap_usd": usd(cap),
            }
            self._record(action, "", details, risk=_RISK[threshold])
        _, top, spent, cap = crossed[-1]
        name = WINDOW_NAMES[window]
        if top == 100:
            until = "mañana" if window == "day" else "el mes que viene"
            title = f"Tope de gasto {name} de toda la instalación alcanzado"
            body = (
                f"Entre todos, los agentes han gastado {_euroish(spent)} $ de {_euroish(cap)} $ "
                f"{name}. Las llamadas al modelo de todos están bloqueadas hasta {until} o hasta "
                "que subas el tope. Las que ya estaban en marcha terminan."
            )
        else:
            title = f"Toda la instalación lleva el {top} % de su tope {name}"
            body = f"Entre todos, {_euroish(spent)} $ de {_euroish(cap)} $ {name}."
        self._tell(_LEVEL[top], title, body)

    def _tell(self, level: AlertLevel, title: str, body: str) -> None:
        if self._alert is None:
            return
        try:
            self._alert(Alert(level, title, body))
        except Exception:
            logger.exception("an alert about the installation's spending could not be queued")

    def _load(self, inherit_from: Path | None) -> None:
        self._day, self._month = self._keys()
        try:
            state = read_private_json(self._folder, STATE_BUDGET)
            _check_state(state)
        except BudgetError as error:
            # Its own caps are lost, and the ones of [budget] apply: said, like an agent's file.
            logger.error("the installation's %s cannot be used: %s", STATE_BUDGET, error)
            self._file_was_broken = True
            self._first_time(None)
            return
        if state is None:
            self._first_time(inherit_from)
            return
        caps = state.get("caps")
        if caps is not None:
            self._daily, self._monthly = caps["daily_micro"], caps["monthly_micro"]
            self._caps_from = "web"
        if state["day"] == self._day:
            self._warned["day"] = set(state["warned"]["day"])
        if state["month"] == self._month:
            self._warned["month"] = set(state["warned"]["month"])

    def _first_time(self, inherit_from: Path | None) -> None:
        """Nothing written yet: the caps the main agent had set were the installation's, and what
        was crossed before is not announced now."""
        try:
            state = None if inherit_from is None else read_state(inherit_from)
        except BudgetError:
            state = None  # the agent's own Budget says so, when it opens it
        caps = None if state is None else state.get("caps")
        top = to_micro(MAX_CAP_USD)
        if caps is not None and caps["daily_micro"] < top:  # at the top: it has none of its own
            self._daily, self._caps_from = caps["daily_micro"], "web"
        if caps is not None and caps["monthly_micro"] < top:
            self._monthly, self._caps_from = caps["monthly_micro"], "web"
        totals = self._totals()
        self._warned = {
            "day": set(_crossed(totals.day, self._daily)),
            "month": set(_crossed(totals.month, self._monthly)),
        }
        self._save()  # the first time is one: a restart does not inherit again

    def _save(self) -> None:
        from backtide.service.settings import SettingsError, write_private

        state: dict[str, Any] = {
            "version": STATE_VERSION,
            "day": self._day,
            "month": self._month,
            "warned": {window: sorted(self._warned[window]) for window in WINDOWS},
        }
        if self._caps_from == "web":
            state["caps"] = {"daily_micro": self._daily, "monthly_micro": self._monthly}
        try:
            write_private(self._folder, STATE_BUDGET, json.dumps(state).encode(), private_dir=False)
        except (SettingsError, OSError) as error:
            logger.error("cannot save the installation's %s: %s", STATE_BUDGET, error)


def _crossed(spent: int, cap: int) -> list[int]:
    return [threshold for threshold in THRESHOLDS if cap > 0 and spent * 100 >= cap * threshold]


def _check_state(state: object) -> None:
    if state is None:
        return
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise BudgetError(f"{STATE_BUDGET} is not an installation's budget of this version")
    if not set(state) <= {"version", "day", "month", "warned", "caps"}:
        raise BudgetError(f"{STATE_BUDGET} has unknown fields")
    for name, length in (("day", 10), ("month", 7)):
        value = state.get(name)
        if not isinstance(value, str) or len(value) != length:
            raise BudgetError(f"{STATE_BUDGET}: {name} is not a date")
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
