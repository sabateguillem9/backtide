"""What a model call costs: the price table and the arithmetic (T11). Pure: no I/O.

Design: docs/33-diseno-t11-tope-de-gasto.md (on top of docs/24, sections 1 and 2).

- **Units.** A price is in dollars per million tokens ($/MTok), kept as ``Decimal`` (never a
  ``float``). One $/MTok is exactly one micro-dollar (µ$) per token, so a call's cost is a sum of
  ``tokens × price`` in µ$, rounded UP to a whole µ$ once per call. Totals are integers.
- **Layers** (``PriceBook``): the owner's ``[budget.prices]`` win, then the last good table
  fetched from Anthropic's pricing page (``price_update.py``), then the defaults that ship here
  (``DEFAULT_PRICES``, dated ``DEFAULTS_AS_OF``). A model is looked up by its exact id, then by
  the longest id it starts with followed by ``-`` (a dated snapshot, ``claude-haiku-4-5-2025…``).
- **Fail safe.** A model no layer knows, or an answer without usage, is charged a conservative
  estimate: the request's size in bytes as input tokens (a token is 3-4 bytes, so this counts
  at least three times too many) plus its ``max_tokens`` as output (``ESTIMATE_MAX_OUTPUT`` when it
  did not say), all at the dearest input and output prices of the table. The call is marked
  ``estimated``.
- **Provider shapes.** Anthropic's ``input`` leaves the cache out (``cache_read`` and
  ``cache_write`` are apart); OpenAI's ``input`` includes its cached part, so the plain input is
  ``input - cache_read`` (``sse.LlmSummary``). An Anthropic cache write without its 5 min / 1 h
  split is charged at the 1 h price, the dearer one.
"""

from dataclasses import dataclass, field, replace
from datetime import date
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any

MTOK = Decimal(1)  # $/MTok is µ$ per token: the factor is one
# The defaults below: the Claude API reference cached on 2026-10-06 (Anthropic) and the OpenAI
# pricing page read on 2026-10-17 (docs/24, section 2). Older first: that is the table's date.
DEFAULTS_AS_OF = date(2026, 10, 6)
DEFAULTS_SOURCE = "defaults"
# Writes to Anthropic's cache: 1.25x the input for 5 min, 2x for 1 h; a read is per model.
CACHE_5M = Decimal("1.25")
CACHE_1H = Decimal("2")
CACHE_READ = Decimal("0.1")  # when an owner's price gives none
ESTIMATE_MAX_OUTPUT = 128_000  # output tokens charged when a request did not say its max_tokens
MAX_TOKENS = 10**9  # what a usage field may say (sse.py keeps 10**12; past this is nonsense)
# Sane prices: anything outside is refused (an owner's override or a fetched one).
MIN_PRICE = Decimal("0.001")
MAX_PRICE = Decimal("10000")


class PriceError(ValueError):
    """A price that cannot be used. The text names the field, never a secret (there is none)."""


@dataclass(frozen=True)
class Price:
    """One model's prices, in $/MTok. ``long_over``: past that many prompt tokens (input with
    the cache, both ways) the whole call is charged at ``long`` (Haiku 5.5's second tier)."""

    input: Decimal
    output: Decimal
    cache_write_5m: Decimal
    cache_write_1h: Decimal
    cache_read: Decimal
    long_over: int | None = None
    long: "Price | None" = None

    def __post_init__(self) -> None:
        for name in ("input", "output", "cache_write_5m", "cache_write_1h", "cache_read"):
            value = getattr(self, name)
            if not isinstance(value, Decimal) or not value.is_finite():
                raise PriceError(f"{name}: not a number")
            if not MIN_PRICE <= value <= MAX_PRICE:
                raise PriceError(f"{name}: outside {MIN_PRICE}-{MAX_PRICE} $/MTok")
        if (self.long_over is None) != (self.long is None):
            raise PriceError("a long-prompt tier needs both its threshold and its prices")
        if self.long_over is not None and (
            type(self.long_over) is not int or not 0 < self.long_over <= MAX_TOKENS
        ):
            raise PriceError("long_over: not a positive number of tokens")

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "input": str(self.input),
            "output": str(self.output),
            "cache_write_5m": str(self.cache_write_5m),
            "cache_write_1h": str(self.cache_write_1h),
            "cache_read": str(self.cache_read),
        }
        if self.long is not None:
            out["long_over"] = self.long_over
            out["long"] = self.long.as_dict()
        return out

    @classmethod
    def from_dict(cls, data: object) -> "Price":
        """The inverse of ``as_dict`` (a stored table). PriceError if it does not fit."""
        if not isinstance(data, dict):
            raise PriceError("a price is a table")
        allowed = {
            "input",
            "output",
            "cache_write_5m",
            "cache_write_1h",
            "cache_read",
            "long_over",
            "long",
        }
        if not set(data) <= allowed:
            raise PriceError("a price has unknown fields")
        try:
            values = {
                name: to_decimal(data[name])
                for name in ("input", "output", "cache_write_5m", "cache_write_1h", "cache_read")
            }
        except KeyError as missing:
            raise PriceError(f"{missing.args[0]}: missing") from None
        long = data.get("long")
        return cls(
            **values,
            long_over=data.get("long_over"),
            long=None if long is None else cls.from_dict(long),
        )


def to_decimal(value: object) -> Decimal:
    """A price from TOML or JSON: a number or a text of one, never a bool."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise PriceError("not a number")
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation:
        raise PriceError("not a number") from None
    if not number.is_finite():
        raise PriceError("not a number")
    return number


def price(
    input: str,
    output: str,
    cache_read: str,
    *,
    long_over: int | None = None,
    long: Price | None = None,
) -> Price:
    """A price whose cache writes are the usual 1.25x and 2x of its input."""
    base = Decimal(input)
    return Price(
        input=base,
        output=Decimal(output),
        cache_write_5m=base * CACHE_5M,
        cache_write_1h=base * CACHE_1H,
        cache_read=Decimal(cache_read),
        long_over=long_over,
        long=long,
    )


_OPUS_45 = price("5", "25", "0.50")
DEFAULT_PRICES: dict[str, Price] = {
    # Anthropic (Claude API reference, cached 2026-10-06; cache reads per model)
    "claude-fable-5-1": price("10", "50", "0.25"),
    "claude-mythos-5-1": price("10", "50", "0.25"),
    "claude-fable-5": price("10", "50", "1"),
    "claude-mythos-5": price("10", "50", "1"),
    "claude-opus-5-5": price("4", "20", "0.20"),
    "claude-opus-5": _OPUS_45,
    "claude-opus-4-8": _OPUS_45,
    "claude-opus-4-7": _OPUS_45,
    "claude-opus-4-6": _OPUS_45,
    "claude-opus-4-5": _OPUS_45,
    "claude-sonnet-5-5": price("2", "10", "0.20"),
    "claude-sonnet-5": price("2", "10", "0.20"),
    "claude-sonnet-4-6": price("3", "15", "0.30"),
    "claude-sonnet-4-5": price("3", "15", "0.30"),
    "claude-haiku-5-5": price(
        "0.10", "0.50", "0.01", long_over=100_000, long=price("0.50", "2.50", "0.05")
    ),
    "claude-haiku-4-5": price("1", "5", "0.10"),
    # OpenAI (pricing page read 2026-10-17, context up to 272,000; docs/24 section 2). No cache
    # writes there: those fields are never used for an OpenAI answer.
    "gpt-6-astra": price("10", "50", "1"),
    "gpt-6.1-sol": price("2", "10", "0.10"),
    "gpt-6-sol": price("2", "10", "0.20"),
    "gpt-6-luna": price("0.10", "0.50", "0.01"),
    "gpt-5.6-sol": price("4", "20", "0.40"),
    "gpt-5.6-terra": price("2", "12", "0.20"),
    "gpt-5.6-luna": price("0.20", "1.20", "0.02"),
}


@dataclass(frozen=True)
class Usage:
    """The tokens of one answer, as ``llm/response.usage`` has them (``sse.LlmSummary``)."""

    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0
    cache_write_5m: int | None = None
    cache_write_1h: int | None = None

    @classmethod
    def from_details(cls, usage: object) -> "Usage | None":
        """From an ``llm/response``'s ``usage`` (None when it is missing or broken: estimate)."""
        if not isinstance(usage, dict) or not usage:
            return None
        values: dict[str, Any] = {}
        for name in (
            "input",
            "output",
            "cache_read",
            "cache_write",
            "cache_write_5m",
            "cache_write_1h",
        ):
            value = usage.get(name)
            if value is None:
                continue
            if type(value) is not int or not 0 <= value <= MAX_TOKENS:
                return None
            values[name] = value
        if "input" not in values and "output" not in values:
            return None
        return cls(**values)


@dataclass(frozen=True)
class Cost:
    """What a call cost: ``micro`` µ$ (rounded up), whether it was ``estimated``, whether its model
    was ``unknown`` to every layer, and which layer priced it (``owner``, ``anthropic``,
    ``defaults`` or ``estimate``)."""

    micro: int
    estimated: bool = False
    unknown_model: bool = False
    priced_by: str = DEFAULTS_SOURCE

    def details(self) -> dict[str, Any]:
        return {
            "usd_micro": self.micro,
            "estimated": self.estimated,
            "unknown_model": self.unknown_model,
            "priced_by": self.priced_by,
        }


def _ceil(amount: Decimal) -> int:
    return int(amount.to_integral_value(rounding=ROUND_CEILING))


def call_cost(row: Price, usage: Usage, kind: str) -> int:
    """µ$ of one answer, rounded up. ``kind``: ``anthropic`` or ``openai`` (its shape)."""
    if kind == "openai":
        cached = min(usage.cache_read, usage.input)
        plain = usage.input - cached
        prompt = usage.input
        writes: list[tuple[int, str]] = []
    else:
        cached = usage.cache_read
        plain = usage.input
        prompt = usage.input + usage.cache_read + usage.cache_write
        if usage.cache_write_5m is not None or usage.cache_write_1h is not None:
            five = usage.cache_write_5m or 0
            hour = usage.cache_write_1h or 0
            rest = max(0, usage.cache_write - five - hour)  # never charge less than the total
            writes = [(five, "cache_write_5m"), (hour + rest, "cache_write_1h")]
        else:
            writes = [(usage.cache_write, "cache_write_1h")]
    if row.long is not None and row.long_over is not None and prompt > row.long_over:
        row = row.long
    total = (
        Decimal(plain) * row.input
        + Decimal(cached) * row.cache_read
        + Decimal(usage.output) * row.output
        + sum((Decimal(tokens) * getattr(row, name) for tokens, name in writes), Decimal(0))
    )
    return _ceil(total * MTOK)


@dataclass
class PriceBook:
    """The three layers of prices. ``fetched`` (and its date) changes when the page is read
    again; ``owner`` comes from ``[budget.prices]``. Not thread-safe by itself: ``Budget`` reads
    and replaces it under its lock."""

    owner: dict[str, Price] = field(default_factory=dict)
    fetched: dict[str, Price] = field(default_factory=dict)
    fetched_on: date | None = None
    defaults: dict[str, Price] = field(default_factory=lambda: dict(DEFAULT_PRICES))
    defaults_on: date = DEFAULTS_AS_OF

    def lookup(self, model: object) -> tuple[Price, str] | None:
        """(price, layer) for ``model``, or None if no layer knows it."""
        if not isinstance(model, str) or not model:
            return None
        for layer, table in (
            ("owner", self.owner),
            ("anthropic", self.fetched),
            (DEFAULTS_SOURCE, self.defaults),
        ):
            found = _match(table, model)
            if found is not None:
                return found, layer
        return None

    def current(self, model: str) -> Price | None:
        """What a fetched price is compared with: the table in use today without the owner's."""
        return _match(self.fetched, model) or _match(self.defaults, model)

    def dearest(self) -> tuple[Decimal, Decimal]:
        """The highest input and output prices of every layer (the estimate's prices)."""
        rows = [*self.owner.values(), *self.fetched.values(), *self.defaults.values()]
        expanded = rows + [row.long for row in rows if row.long is not None]
        return max(row.input for row in expanded), max(row.output for row in expanded)

    def with_fetched(self, table: dict[str, Price], on: date) -> "PriceBook":
        return replace(self, fetched=dict(table), fetched_on=on)


def _match(table: dict[str, Price], model: str) -> Price | None:
    if model in table:
        return table[model]
    best = None
    for name in table:
        if model.startswith(name + "-") and (best is None or len(name) > len(best)):
            best = name
    return None if best is None else table[best]


def estimate(book: PriceBook, *, request_bytes: int | None, max_tokens: int | None) -> int:
    """µ$ of a call whose usage is unknown, by excess (see the module's text)."""
    top_input, top_output = book.dearest()
    tokens_in = request_bytes if type(request_bytes) is int and request_bytes > 0 else 0
    out = max_tokens if type(max_tokens) is int and 0 < max_tokens <= MAX_TOKENS else None
    tokens_out = out if out is not None else ESTIMATE_MAX_OUTPUT
    return _ceil((Decimal(tokens_in) * top_input + Decimal(tokens_out) * top_output) * MTOK)


def cost_of(
    book: PriceBook,
    *,
    kind: str,
    model: object,
    usage: object,
    request_bytes: int | None = None,
    max_tokens: int | None = None,
) -> Cost:
    """The cost of one ``llm/response``: priced when the model is known and the usage came,
    estimated by excess otherwise (``estimated``; ``unknown_model`` when no layer knew it)."""
    found = book.lookup(model)
    tokens = Usage.from_details(usage)
    if found is None or tokens is None:
        micro = estimate(book, request_bytes=request_bytes, max_tokens=max_tokens)
        if found is not None and tokens is None and type(max_tokens) is int and max_tokens > 0:
            # The model is known: its own prices give a smaller (still excessive) estimate.
            row = found[0]
            micro = min(
                micro,
                _ceil(
                    Decimal(request_bytes or 0) * max(row.input, row.cache_write_1h)
                    + Decimal(max_tokens) * row.output
                ),
            )
        return Cost(micro, estimated=True, unknown_model=found is None, priced_by="estimate")
    row, layer = found
    return Cost(call_cost(row, tokens, kind), priced_by=layer)


def usd(micro: int) -> str:
    """µ$ as dollars with two decimals, rounded up (``1_234_567`` -> ``"1.24"``)."""
    cents = -(-micro // 10_000)
    return f"{cents // 100}.{cents % 100:02d}"


def to_micro(dollars: Decimal) -> int:
    """Dollars to µ$ (a cap): exact for up to six decimals, rounded down past them."""
    return int((dollars * 1_000_000).to_integral_value(rounding="ROUND_FLOOR"))
