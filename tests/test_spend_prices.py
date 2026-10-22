"""T11: what a model call costs (backtide/service/prices.py) and how the usage is read from the
provider's answer, streamed or not, in Anthropic's and OpenAI's shapes (backtide/gate/sse.py)."""

import json
from datetime import date
from decimal import Decimal

import pytest

from backtide.gate.sse import UsageStream, summarize_json
from backtide.service.prices import (
    DEFAULT_PRICES,
    DEFAULTS_AS_OF,
    ESTIMATE_MAX_OUTPUT,
    Price,
    PriceBook,
    PriceError,
    Usage,
    call_cost,
    cost_of,
    price,
    to_micro,
    usd,
)

TODAY = date(2026, 10, 21)


def test_anthropic_prices_of_the_day() -> None:
    """The founder's figures (Claude API reference cached 2026-10-06), per MTok."""
    expected = {
        "claude-opus-5-5": ("4", "20"),
        "claude-sonnet-5-5": ("2", "10"),
        "claude-haiku-5-5": ("0.10", "0.50"),
        "claude-haiku-4-5": ("1", "5"),
        "claude-sonnet-5": ("2", "10"),
        "claude-opus-5": ("5", "25"),
        "claude-fable-5-1": ("10", "50"),
    }
    for model, (inp, out) in expected.items():
        row = DEFAULT_PRICES[model]
        assert (row.input, row.output) == (Decimal(inp), Decimal(out)), model
        assert row.cache_write_5m == row.input * Decimal("1.25")
        assert row.cache_write_1h == row.input * 2
    haiku = DEFAULT_PRICES["claude-haiku-5-5"]
    assert haiku.long_over == 100_000 and haiku.long is not None
    assert (haiku.long.input, haiku.long.output) == (Decimal("0.50"), Decimal("2.50"))


def test_shipped_prices_are_not_too_old() -> None:
    """The table that ships must be looked at again before a release goes out with old prices
    (docs/24): the auto-update covers Anthropic, not OpenAI."""
    assert (date.today() - DEFAULTS_AS_OF).days <= 180, (
        "the shipped prices (prices.DEFAULT_PRICES) are over 180 days old: check them and move "
        "DEFAULTS_AS_OF"
    )


def test_anthropic_cost_with_cache_split() -> None:
    row = DEFAULT_PRICES["claude-opus-5-5"]
    usage = Usage(
        input=1000,
        output=500,
        cache_read=10_000,
        cache_write=3000,
        cache_write_5m=2000,
        cache_write_1h=1000,
    )
    # 1000*4 + 10000*0.2 + 500*20 + 2000*5 + 1000*8 = 4000 + 2000 + 10000 + 10000 + 8000
    assert call_cost(row, usage, "anthropic") == 34_000


def test_anthropic_cache_write_without_split_is_charged_at_one_hour() -> None:
    row = DEFAULT_PRICES["claude-sonnet-5-5"]
    usage = Usage(input=0, output=0, cache_write=1000)
    assert call_cost(row, usage, "anthropic") == 1000 * 4  # 2x of 2 $/MTok


def test_split_that_does_not_add_up_never_charges_less() -> None:
    row = DEFAULT_PRICES["claude-sonnet-5-5"]
    usage = Usage(cache_write=1000, cache_write_5m=100, cache_write_1h=0)
    assert call_cost(row, usage, "anthropic") == round(100 * 2.5) + 900 * 4


def test_openai_input_includes_the_cached_part() -> None:
    row = DEFAULT_PRICES["gpt-6-sol"]
    usage = Usage(input=1000, output=100, cache_read=400)
    # (1000-400)*2 + 400*0.2 + 100*10
    assert call_cost(row, usage, "openai") == 1200 + 80 + 1000


def test_rounding_is_up_per_call() -> None:
    row = DEFAULT_PRICES["claude-haiku-5-5"]
    assert call_cost(row, Usage(input=1, output=0), "anthropic") == 1  # 0.1 µ$ -> 1
    assert call_cost(row, Usage(input=10, output=0), "anthropic") == 1


def test_haiku_long_prompt_tier_counts_the_cache_too() -> None:
    row = DEFAULT_PRICES["claude-haiku-5-5"]
    short = Usage(input=50_000, output=1000, cache_read=50_000)
    long = Usage(input=50_000, output=1000, cache_read=50_001)
    assert call_cost(row, short, "anthropic") == 5000 + 500 + 500
    # 50000*0.50 + 50001*0.05 + 1000*2.50 = 30000.05, rounded up
    assert call_cost(row, long, "anthropic") == 30_001


def test_lookup_exact_then_longest_prefix_then_unknown() -> None:
    book = PriceBook()
    assert book.lookup("claude-opus-5-5") == (DEFAULT_PRICES["claude-opus-5-5"], "defaults")
    assert book.lookup("claude-opus-5-5-20261001")[0] == DEFAULT_PRICES["claude-opus-5-5"]
    assert book.lookup("claude-opus-5-20260601")[0] == DEFAULT_PRICES["claude-opus-5"]
    assert book.lookup("claude-opus-55") is None  # a prefix only counts up to a dash
    assert book.lookup("fake-claude") is None
    assert book.lookup(None) is None


def test_layers_owner_then_fetched_then_defaults() -> None:
    owner = price("1", "1", "0.1")
    fetched = price("3", "15", "0.3")
    book = PriceBook(owner={"claude-opus-5-5": owner}).with_fetched(
        {"claude-opus-5-5": fetched, "claude-sonnet-5-5": fetched}, TODAY
    )
    assert book.lookup("claude-opus-5-5") == (owner, "owner")
    assert book.lookup("claude-sonnet-5-5") == (fetched, "anthropic")
    assert book.lookup("claude-haiku-4-5")[1] == "defaults"
    assert book.current("claude-opus-5-5") == fetched  # what a new fetch is compared with


def test_unknown_model_is_estimated_at_the_dearest_prices() -> None:
    book = PriceBook()
    cost = cost_of(
        book,
        kind="anthropic",
        model="claude-new-9",
        usage={"input": 10, "output": 10},
        request_bytes=3000,
        max_tokens=1000,
    )
    assert cost.estimated and cost.unknown_model and cost.priced_by == "estimate"
    assert cost.micro == 3000 * 10 + 1000 * 50  # Fable's 10/50 are the dearest


def test_missing_usage_is_estimated_by_excess() -> None:
    book = PriceBook()
    cost = cost_of(
        book,
        kind="anthropic",
        model="claude-sonnet-5-5",
        usage=None,
        request_bytes=3000,
        max_tokens=1000,
    )
    assert cost.estimated and not cost.unknown_model
    real = call_cost(
        DEFAULT_PRICES["claude-sonnet-5-5"], Usage(input=1000, output=1000), "anthropic"
    )
    assert cost.micro >= real  # never below a plausible real cost
    nothing_known = cost_of(book, kind="openai", model=None, usage=None)
    assert nothing_known.micro == ESTIMATE_MAX_OUTPUT * 50


def test_broken_usage_counts_as_missing() -> None:
    for usage in ({"input": -1}, {"input": "12"}, {"input": True}, {}, [], {"cache_read": 5}):
        assert Usage.from_details(usage) is None
    cost = cost_of(PriceBook(), kind="anthropic", model="claude-opus-5-5", usage={"input": -5})
    assert cost.estimated


def test_owner_price_shapes() -> None:
    with pytest.raises(PriceError):
        price("0", "1", "0.1")
    with pytest.raises(PriceError):
        Price.from_dict({"input": "x"})
    row = DEFAULT_PRICES["claude-haiku-5-5"]
    assert Price.from_dict(json.loads(json.dumps(row.as_dict()))) == row


def test_money_formats() -> None:
    assert usd(0) == "0.00"
    assert usd(1) == "0.01"  # up
    assert usd(1_234_567) == "1.24"
    assert to_micro(Decimal("5")) == 5_000_000


# --- the usage, as the proxy reads it --------------------------------------------------------


def _sse(events: list[tuple[str, dict]]) -> bytes:
    return b"".join(
        f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events
    )


def test_anthropic_stream_keeps_the_last_cumulative_usage_and_the_cache_split() -> None:
    body = _sse(
        [
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "model": "claude-opus-5-5",
                        "usage": {
                            "input_tokens": 12,
                            "output_tokens": 1,
                            "cache_read_input_tokens": 100,
                            "cache_creation_input_tokens": 30,
                            "cache_creation": {
                                "ephemeral_5m_input_tokens": 20,
                                "ephemeral_1h_input_tokens": 10,
                            },
                        },
                    },
                },
            ),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 7},
                },
            ),
            ("message_delta", {"type": "message_delta", "usage": {"output_tokens": 9}}),
            ("message_stop", {"type": "message_stop"}),
        ]
    )
    stream = UsageStream("anthropic")
    for i in range(0, len(body), 7):  # cut at any byte
        stream.feed(body[i : i + 7])
    summary = stream.finish()
    assert summary.usage == {
        "input": 12,
        "output": 9,
        "cache_read": 100,
        "cache_write": 30,
        "cache_write_5m": 20,
        "cache_write_1h": 10,
    }


def test_anthropic_json_answer() -> None:
    body = json.dumps(
        {
            "type": "message",
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 5, "output_tokens": 6},
        }
    ).encode()
    assert summarize_json("anthropic", body).usage == {"input": 5, "output": 6}


def test_openai_stream_with_its_last_usage_chunk() -> None:
    chunks = [
        {"model": "gpt-6-sol", "choices": [{"delta": {"content": "hi"}}]},
        {
            "model": "gpt-6-sol",
            "choices": [],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 4,
                "prompt_tokens_details": {"cached_tokens": 20},
            },
        },
    ]
    body = b"".join(f"data: {json.dumps(c)}\n\n".encode() for c in chunks) + b"data: [DONE]\n\n"
    stream = UsageStream("openai")
    stream.feed(body)
    assert stream.finish().usage == {"input": 50, "output": 4, "cache_read": 20}


def test_openai_stream_without_usage_is_missing() -> None:
    body = b'data: {"model": "gpt-6-sol", "choices": [{"delta": {"content": "x"}}]}\n\n'
    stream = UsageStream("openai")
    stream.feed(body + b"data: [DONE]\n\n")
    details = stream.finish().details()
    assert details.get("usage_missing") is True
    cost = cost_of(
        PriceBook(),
        kind="openai",
        model=details["model"],
        usage=details.get("usage"),
        request_bytes=400,
        max_tokens=100,
    )
    assert cost.estimated and cost.micro > 0


def test_openai_responses_json_answer() -> None:
    body = json.dumps(
        {
            "object": "response",
            "model": "gpt-6-luna",
            "status": "completed",
            "usage": {
                "input_tokens": 7,
                "output_tokens": 3,
                "input_tokens_details": {"cached_tokens": 2},
            },
        }
    ).encode()
    assert summarize_json("openai", body).usage == {"input": 7, "output": 3, "cache_read": 2}
