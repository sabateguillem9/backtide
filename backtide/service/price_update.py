"""The price table keeps itself up to date (T11, decided by the founder on 2026-10-21; docs/33).

backtide (the service, on the trusted side: never through the agent's proxy) reads Anthropic's
own pricing page in Markdown, ``PRICES_URL``, when it starts and then once a day:

- **Strict parser** (``parse_pricing``): the first Markdown table whose header names a model, the
  base input, the output and the cache hits (the 5 min and 1 h cache writes when it has them;
  without them, 1.25x and 2x of the input). Each price cell is exactly ``$<number> / MTok``, or two
  of them with a ``> <n>K`` threshold (a long-prompt tier such as Haiku 5.5's). A model name must
  read ``Claude <Family> <major>[.<minor>]`` and becomes its id (``Claude Opus 5.5`` ->
  ``claude-opus-5-5``). Anything else in a row makes that row unusable, never guessed.
- **Checked** (``check_prices``): the id's shape, every value between ``MIN_FETCHED`` and
  ``MAX_FETCHED`` $/MTok, and no value more than ``MAX_CHANGE`` times above or below the price in
  use today. A row that fails is ignored for that model and recorded with why.
- **Order**: the owner's ``[budget.prices]`` > the last good table fetched (kept in
  ``<state_dir>/prices.json``, 0600) > the defaults that ship with backtide (dated).
- **Recorded**: every change is ``system/prices_updated {changes: [{model, old, new}], source,
  fetched_on}`` and one alert; rows refused, ``system/prices_rejected``. A fetch or a parse that
  fails keeps the last good table, is ``system/prices_failed`` and warns at most once a day: never
  a silent fallback.
- ``[budget] auto_prices = false`` turns all this off. Only OpenAI has no official page in a form a
  program can read: its prices stay the shipped ones (or the owner's).

The fetch is plain ``urllib`` (no new dependency): HTTPS only (or ``http://127.0.0.1`` /
``localhost`` for the tests' fake page), no redirects, no proxy from the environment, 2 MiB at most,
20 s at most.
"""

import json
import logging
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from backtide.blackbox import Event
from backtide.notify import AlertLevel
from backtide.service.prices import CACHE_1H, CACHE_5M, Price, PriceError
from backtide.service.spend import Budget

logger = logging.getLogger(__name__)

PRICES_URL = "https://platform.claude.com/docs/en/about-claude/pricing.md"
SOURCE = "anthropic"
STATE_PRICES = "prices.json"
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 256 * 1024
FETCH_TIMEOUT = 20.0
EVERY = 24 * 3600.0
RETRY_EVERY = 3600.0  # after a failure, try again in an hour (the warning stays once a day)
MIN_FETCHED = Decimal("0.01")
MAX_FETCHED = Decimal("500")
MAX_CHANGE = Decimal("10")
MAX_MODELS = 64
_MODEL_ID_RE = re.compile(r"claude-(?:opus|sonnet|haiku|fable|mythos)-[0-9]{1,2}(?:-[0-9]{1,2})?")
_NAME_RE = re.compile(r"Claude (Opus|Sonnet|Haiku|Fable|Mythos) ([0-9]{1,2})(?:\.([0-9]{1,2}))?")
_PRICE_RE = re.compile(r"\$\s?([0-9]{1,4}(?:\.[0-9]{1,4})?)\s?/\s?MTok", re.IGNORECASE)
_ONE_PRICE_RE = re.compile(rf"^{_PRICE_RE.pattern}$", re.IGNORECASE)
_TIER_RE = re.compile(r">\s?([0-9]{1,4})\s?K\b", re.IGNORECASE)
_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_NOTE_RE = re.compile(r"\s*(\([^)]*\)|<sup>.*?</sup>|\^\[?[0-9]+\]?|\*+)\s*")
_FIELDS = ("input", "cache_write_5m", "cache_write_1h", "cache_read", "output")

Fetch = Callable[[str], str]


class PriceUpdateError(Exception):
    """The page could not be fetched or read. The message is short and for a log."""


@dataclass(frozen=True)
class Parsed:
    prices: dict[str, Price]
    rejected: list[dict[str, str]]  # {"model": name or id, "why": ...}


def model_id(name: str) -> str | None:
    """``Claude Opus 5.5`` -> ``claude-opus-5-5``; None for anything else."""
    text = _NOTE_RE.sub(" ", _LINK_RE.sub(r"\1", name)).strip()
    match = _NAME_RE.fullmatch(text)
    if match is None:
        return None
    family, major, minor = match.groups()
    return f"claude-{family.lower()}-{major}" + (f"-{minor}" if minor else "")


def _columns(header: list[str]) -> dict[str, int] | None:
    found: dict[str, int] = {}
    for index, raw in enumerate(header):
        cell = raw.strip().lower()
        if "batch" in cell:
            return None  # the batch table: half prices, never mixed with these
        if cell.startswith("model"):
            found.setdefault("model", index)
        elif "5m" in cell and "cache" in cell:
            found.setdefault("cache_write_5m", index)
        elif "1h" in cell and "cache" in cell:
            found.setdefault("cache_write_1h", index)
        elif "cache" in cell and ("hit" in cell or "read" in cell):
            found.setdefault("cache_read", index)
        elif "input" in cell and "cache" not in cell:
            found.setdefault("input", index)
        elif "output" in cell:
            found.setdefault("output", index)
    needed = {"model", "input", "output", "cache_read"}
    return found if needed <= set(found) else None


def _cells(line: str) -> list[str] | None:
    line = line.strip()
    if not (line.startswith("|") and line.endswith("|")) or len(line) < 2:
        return None
    return [cell.strip() for cell in line[1:-1].split("|")]


def _cell_prices(cell: str) -> tuple[Decimal, Decimal | None, int | None]:
    """(base, long or None, threshold in tokens or None). PriceError if it is not a price."""
    text = cell.replace("**", "").strip()
    one = _ONE_PRICE_RE.fullmatch(text)
    if one is not None:
        return Decimal(one.group(1)), None, None
    found = _PRICE_RE.findall(text)
    tier = _TIER_RE.findall(text)
    if len(found) == 2 and len(tier) == 1:
        return Decimal(found[0]), Decimal(found[1]), int(tier[0]) * 1000
    raise PriceError("not a price of the form $X / MTok")


def parse_pricing(text: str) -> Parsed:
    """The per-model prices of the page (see the module's text). PriceUpdateError if the page
    has no table of that shape or not one usable row."""
    if not isinstance(text, str) or not text:
        raise PriceUpdateError("empty page")
    lines = text.splitlines()
    for index, line in enumerate(lines):
        header = _cells(line)
        if header is None or index + 1 >= len(lines):
            continue
        rule = _cells(lines[index + 1])
        if rule is None or not all(set(c) <= set(":- ") and "-" in c for c in rule):
            continue
        columns = _columns(header)
        if columns is None:
            continue
        return _rows(lines[index + 2 :], columns, len(header))
    raise PriceUpdateError("no price table of the expected shape")


def _rows(lines: list[str], columns: dict[str, int], width: int) -> Parsed:
    prices: dict[str, Price] = {}
    rejected: list[dict[str, str]] = []
    for line in lines:
        cells = _cells(line)
        if cells is None:
            break  # the table ended
        if len(cells) != width:
            rejected.append({"model": cells[0][:64] if cells else "", "why": "columns"})
            continue
        name = cells[columns["model"]]
        model = model_id(name)
        if model is None:
            rejected.append({"model": name[:64], "why": "name"})
            continue
        if model in prices:
            rejected.append({"model": model, "why": "twice"})
            prices.pop(model)
            continue
        try:
            prices[model] = _row_price(cells, columns)
        except PriceError as error:
            rejected.append({"model": model, "why": str(error)[:80]})
        if len(prices) > MAX_MODELS:
            raise PriceUpdateError("too many models in the table")
    if not prices:
        raise PriceUpdateError("no usable row in the price table")
    return Parsed(prices, rejected)


def _row_price(cells: list[str], columns: dict[str, int]) -> Price:
    base: dict[str, Decimal] = {}
    long: dict[str, Decimal] = {}
    threshold: int | None = None
    for name in _FIELDS:
        if name not in columns:
            continue
        value, upper, over = _cell_prices(cells[columns[name]])
        base[name] = value
        if upper is not None:
            if threshold is not None and over != threshold:
                raise PriceError("two different long-prompt thresholds")
            threshold = over
            long[name] = upper
    for target, factor in (("cache_write_5m", CACHE_5M), ("cache_write_1h", CACHE_1H)):
        base.setdefault(target, base["input"] * factor)
    for name in _FIELDS:
        _check_range(name, base[name])
    if threshold is None:
        return Price(**base)
    upper_row = {name: long.get(name, base[name]) for name in _FIELDS}
    if "input" in long:
        for target, factor in (("cache_write_5m", CACHE_5M), ("cache_write_1h", CACHE_1H)):
            if target not in long:
                upper_row[target] = long["input"] * factor
    for name in _FIELDS:
        _check_range(name, upper_row[name])
    return Price(**base, long_over=threshold, long=Price(**upper_row))


def _check_range(name: str, value: Decimal) -> None:
    if not MIN_FETCHED <= value <= MAX_FETCHED:
        raise PriceError(f"{name} outside {MIN_FETCHED}-{MAX_FETCHED} $/MTok")


def check_prices(
    parsed: dict[str, Price], current: Callable[[str], Price | None]
) -> tuple[dict[str, Price], list[dict[str, str]]]:
    """(accepted, rejected): the id's shape, and no value more than MAX_CHANGE times away from
    ``current(model)`` (the price in use, without the owner's)."""
    accepted: dict[str, Price] = {}
    rejected: list[dict[str, str]] = []
    for model, row in parsed.items():
        if not _MODEL_ID_RE.fullmatch(model):
            rejected.append({"model": model[:64], "why": "id"})
            continue
        old = current(model)
        if old is not None and _too_far(old, row):
            rejected.append({"model": model, "why": f"changes more than {MAX_CHANGE}x"})
            continue
        accepted[model] = row
    return accepted, rejected


def _too_far(old: Price, new: Price) -> bool:
    pairs = [(getattr(old, n), getattr(new, n)) for n in _FIELDS]
    if old.long is not None and new.long is not None:
        pairs += [(getattr(old.long, n), getattr(new.long, n)) for n in _FIELDS]
    return any(b > a * MAX_CHANGE or b * MAX_CHANGE < a for a, b in pairs)


def check_url(url: object) -> str:
    """The page's address: HTTPS, or plain HTTP to this machine (the tests' fake page)."""
    if not isinstance(url, str) or len(url) > 512 or any(c.isspace() for c in url):
        raise ValueError("prices_url must be a URL")
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return url
    raise ValueError("prices_url must be https://, or http:// to 127.0.0.1 or localhost")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise urllib.error.URLError("the price page redirected: not followed")


def fetch_page(url: str) -> str:
    """The page as text. PriceUpdateError, with a short reason, if it cannot be had."""
    check_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "backtide-prices"})  # noqa: S310
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT) as answer:  # noqa: S310 - checked URL
            if answer.status != 200:
                raise PriceUpdateError(f"HTTP {answer.status}")
            data = answer.read(MAX_PAGE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise PriceUpdateError(f"HTTP {error.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise PriceUpdateError(type(error).__name__) from None
    if len(data) > MAX_PAGE_BYTES:
        raise PriceUpdateError("the page is too big")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise PriceUpdateError("the page is not UTF-8") from None


class PriceUpdater:
    """Reads the page now and every day on a thread of its own (``start``/``close``, a hook of
    the service), and hands what it accepts to ``budget``. ``run_once`` is what the thread does
    (the tests call it). Never raises out of the thread."""

    def __init__(
        self,
        budget: Budget,
        *,
        state_dir: Path,
        record: Callable[..., Event | None],
        url: str = PRICES_URL,
        fetch: Fetch = fetch_page,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        every: float = EVERY,
        retry_every: float = RETRY_EVERY,
        auto: bool = True,
    ) -> None:
        self._auto = auto
        self._budget = budget
        self._state_dir = Path(state_dir)
        self._record = record
        self._url = check_url(url)
        self._fetch = fetch
        self._now = now
        self._every = every
        self._retry = retry_every
        self._warned_on: date | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- the stored table ------------------------------------------------------------------

    def load(self) -> None:
        """The last good table of ``prices.json`` into the budget. A broken file is recorded
        and left alone (the next good fetch replaces it)."""
        try:
            table, on = read_state(self._state_dir)
        except PriceUpdateError as error:
            logger.error("the stored prices cannot be used: %s", error)
            self._safe_record("prices_failed", {"stage": "stored", "error": str(error)}, 1)
            return
        if table:
            self._budget.use_fetched(table, on)

    # -- one round -------------------------------------------------------------------------

    def run_once(self) -> bool:
        """Fetch, parse, check, store and use. True if a table was taken (changed or not)."""
        today = self._now().date()
        try:
            parsed = parse_pricing(self._fetch(self._url))
        except (PriceUpdateError, PriceError) as error:
            self._failed("fetch_or_parse", str(error), today)
            return False
        book = self._budget.book
        accepted, refused = check_prices(parsed.prices, book.current)
        rejected = parsed.rejected + refused
        if rejected:
            self._safe_record(
                "prices_rejected", {"rows": rejected[:MAX_MODELS], "source": SOURCE}, 1
            )
        if not accepted:
            self._failed("check", "no row passed the checks", today)
            return False
        merged = dict(book.fetched)
        merged.update(accepted)
        changes = [
            {
                "model": model,
                "old": None if book.current(model) is None else book.current(model).as_dict(),  # type: ignore[union-attr]
                "new": row.as_dict(),
            }
            for model, row in sorted(accepted.items())
            if book.current(model) != row
        ]
        try:
            write_state(self._state_dir, merged, today)
        except OSError as error:
            # Used anyway for this run; the warning says the next start goes back a step.
            self._failed("store", type(error).__name__, today)
        if changes:
            event = self._safe_record(
                "prices_updated",
                {
                    "changes": changes[:MAX_MODELS],
                    "source": SOURCE,
                    "url": self._url,
                    "fetched_on": today.isoformat(),
                },
                1,
            )
            names = ", ".join(change["model"] for change in changes[:6])
            more = "" if len(changes) <= 6 else f" y {len(changes) - 6} más"
            self._budget.tell(
                AlertLevel.INFO,
                "Precios de los modelos actualizados",
                f"backtide ha leído la página de precios de Anthropic: cambian {names}{more}.",
                event,
            )
        self._budget.use_fetched(merged, today)
        return True

    def _failed(self, stage: str, error: str, today: date) -> None:
        logger.warning("the price table was not updated (%s): %s", stage, error)
        event = self._safe_record("prices_failed", {"stage": stage, "error": error[:120]}, 1)
        if self._warned_on != today:
            self._warned_on = today
            self._budget.tell(
                AlertLevel.WARNING,
                "No se han podido actualizar los precios",
                "backtide sigue con la última tabla buena "
                f"({self._budget.status()['prices']['updated_on'] or 'la de fábrica'}). "
                "Lo vuelve a intentar dentro de un rato.",
                event,
            )

    def _safe_record(self, action: str, details: dict[str, Any], risk: int) -> Event | None:
        try:
            return self._record("system", action, "", details=details, risk=risk)
        except Exception as error:
            logger.error("cannot record system/%s: %s", action, type(error).__name__)
            return None

    # -- the thread ------------------------------------------------------------------------

    def start(self) -> None:
        """The stored table, then (with ``auto``) a fetch now and every day."""
        self.load()
        if not self._auto:
            return
        self._thread = threading.Thread(target=self._run, name="backtide-prices", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(FETCH_TIMEOUT + 5)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                ok = self.run_once()
            except Exception:
                logger.exception("updating the prices failed")
                ok = False
            if self._stop.wait(self._every if ok else self._retry):
                return


def write_state(folder: Path, table: dict[str, Price], on: date) -> None:
    from backtide.service.settings import SettingsError, write_private

    data = {
        "version": 1,
        "source": SOURCE,
        "fetched_on": on.isoformat(),
        "prices": {model: row.as_dict() for model, row in sorted(table.items())},
    }
    try:
        write_private(folder, STATE_PRICES, json.dumps(data).encode(), private_dir=False)
    except SettingsError as error:
        raise OSError(str(error)) from None


def read_state(folder: Path) -> tuple[dict[str, Price], date | None]:
    """The stored table and its date ({} and None if there is none). PriceUpdateError if it is
    there and cannot be used."""
    import os

    path = Path(folder) / STATE_PRICES
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {}, None
    except OSError as error:
        raise PriceUpdateError(f"cannot open {STATE_PRICES}: {error.strerror}") from None
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PriceUpdateError(f"{STATE_PRICES} is not ours and private")
        raw = os.read(fd, MAX_STATE_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_STATE_BYTES:
        raise PriceUpdateError(f"{STATE_PRICES} is too big")
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("version")
        on = date.fromisoformat(data["fetched_on"])
        prices = data["prices"]
        if not isinstance(prices, dict) or len(prices) > MAX_MODELS:
            raise ValueError("prices")
        table = {}
        for model, row in prices.items():
            if not isinstance(model, str) or not _MODEL_ID_RE.fullmatch(model):
                raise ValueError("model")
            table[model] = Price.from_dict(row)
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, RecursionError):
        raise PriceUpdateError(f"{STATE_PRICES} is not a price table") from None
    return table, on
