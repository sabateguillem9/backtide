"""T11 (founder's decision of 2026-10-21): the price table updates itself from Anthropic's pricing
page (backtide/service/price_update.py). Never the real page: a fake one, as a string or served on
127.0.0.1 by the test."""

import http.server
import json
import os
import stat
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox
from backtide.notify import Alert, AlertLevel
from backtide.service.price_update import (
    STATE_PRICES,
    PriceUpdateError,
    PriceUpdater,
    check_prices,
    check_url,
    fetch_page,
    model_id,
    parse_pricing,
    read_state,
)
from backtide.service.prices import DEFAULT_PRICES, PriceBook, price
from backtide.service.spend import Budget, BudgetSettings

KEY = bytes(range(32))

PAGE = """# Pricing

Some words about pricing.

## Model pricing

| Model | Base Input Tokens | 5m Cache Writes | 1h Cache Writes | Cache Hits & Refreshes | Output Tokens |
|-------|-------------------|-----------------|-----------------|------------------------|---------------|
| Claude Fable 5.1 | $10 / MTok | $12.50 / MTok | $20 / MTok | $0.25 / MTok | $50 / MTok |
| Claude Opus 5.5 | $4 / MTok | $5 / MTok | $8 / MTok | $0.20 / MTok | $20 / MTok |
| Claude Sonnet 5.5 | $2 / MTok | $2.50 / MTok | $4 / MTok | $0.20 / MTok | $10 / MTok |
| Claude Haiku 5.5 | $0.10 / MTok (≤ 100K tokens); $0.50 / MTok (> 100K tokens) | $0.125 / MTok (≤ 100K); $0.625 / MTok (> 100K) | $0.20 / MTok (≤ 100K); $1 / MTok (> 100K) | $0.01 / MTok (≤ 100K); $0.05 / MTok (> 100K) | $0.50 / MTok (≤ 100K); $2.50 / MTok (> 100K) |
| [Claude Opus 4.1](/docs/deprecations) | $15 / MTok | $18.75 / MTok | $30 / MTok | $1.50 / MTok | $75 / MTok |
| Claude Haiku 3 | $0.25 / MTok | $0.30 / MTok | $0.50 / MTok | $0.03 / MTok | $1.25 / MTok |

## Batch processing

| Model | Batch input | Batch output |
|---|---|---|
| Claude Opus 5.5 | $2 / MTok | $10 / MTok |
"""  # noqa: E501


def test_model_names_become_ids() -> None:
    assert model_id("Claude Opus 5.5") == "claude-opus-5-5"
    assert model_id("Claude Sonnet 5") == "claude-sonnet-5"
    assert model_id("[Claude Opus 4.1](/docs/x)") == "claude-opus-4-1"
    assert model_id("Claude Haiku 3 (deprecated)") == "claude-haiku-3"
    for bad in (
        "Opus 5.5",
        "Claude Opus",
        "claude-opus-5-5",
        "Claude Opus 5.5.1",
        "GPT 6",
        "Claude Opus 5.5; DROP",
        "Claude  Opus 5",
    ):
        assert model_id(bad) is None, bad


def test_the_page_is_read_strictly() -> None:
    parsed = parse_pricing(PAGE)
    assert set(parsed.prices) == {
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-sonnet-5-5",
        "claude-haiku-5-5",
        "claude-opus-4-1",
        "claude-haiku-3",
    }
    assert parsed.prices["claude-opus-5-5"] == DEFAULT_PRICES["claude-opus-5-5"]
    assert parsed.prices["claude-sonnet-5-5"] == DEFAULT_PRICES["claude-sonnet-5-5"]
    haiku = parsed.prices["claude-haiku-5-5"]
    assert haiku == DEFAULT_PRICES["claude-haiku-5-5"]
    assert haiku.long_over == 100_000
    assert parsed.rejected == []


def test_rows_that_do_not_fit_are_left_out_and_said() -> None:
    page = PAGE.replace("| Claude Sonnet 5.5 | $2 / MTok", "| Claude Sonnet 5.5 | two dollars")
    page = page.replace("| Claude Haiku 3 |", "| Haiku the third |")
    page = page.replace("$75 / MTok |", "$7500 / MTok |")  # over the range
    parsed = parse_pricing(page)
    whys = {row["model"]: row["why"] for row in parsed.rejected}
    assert set(whys) == {"claude-sonnet-5-5", "Haiku the third", "claude-opus-4-1"}
    assert "claude-sonnet-5-5" not in parsed.prices


def test_a_page_without_the_table_is_an_error() -> None:
    for page in (
        "",
        "# Pricing\nnothing here",
        "| a | b |\n|---|---|\n| 1 | 2 |",
        PAGE.split("## Model pricing")[0] + PAGE.split("## Batch processing")[1],
    ):
        with pytest.raises(PriceUpdateError):
            parse_pricing(page)


def test_a_row_twice_is_not_trusted() -> None:
    page = PAGE.replace("| Claude Haiku 3 |", "| Claude Opus 5.5 |")
    parsed = parse_pricing(page)
    assert "claude-opus-5-5" not in parsed.prices
    assert {"model": "claude-opus-5-5", "why": "twice"} in parsed.rejected


def test_changes_over_ten_times_are_refused() -> None:
    book = PriceBook()
    cheap = price("0.30", "20", "0.20")  # Opus 5.5's input 4 -> 0.30: more than 10x down
    dear = price("5", "25", "0.25")
    accepted, rejected = check_prices(
        {"claude-opus-5-5": cheap, "claude-sonnet-5-5": dear, "claude-opus-6": dear}, book.current
    )
    assert set(accepted) == {"claude-sonnet-5-5", "claude-opus-6"}
    assert rejected == [{"model": "claude-opus-5-5", "why": "changes more than 10x"}]
    _, bad_id = check_prices({"gpt-6-sol": dear}, book.current)
    assert bad_id == [{"model": "gpt-6-sol", "why": "id"}]


def test_urls() -> None:
    assert check_url("https://platform.claude.com/docs/en/about-claude/pricing.md")
    assert check_url("http://127.0.0.1:8123/pricing.md")
    for bad in (
        "http://example.com/p.md",
        "file:///etc/passwd",
        "ftp://x/y",
        "https://",
        3,
        "https://a b",
    ):
        with pytest.raises(ValueError):
            check_url(bad)


# --- the updater -----------------------------------------------------------------------------


@pytest.fixture
def box(tmp_path: Path) -> Iterator[BlackBox]:
    folder = tmp_path / "box"
    folder.mkdir()
    db = BlackBox(folder / "blackbox.db", KEY)
    db.open()
    yield db
    db.close()


def setup(
    tmp_path: Path,
    box: BlackBox,
    page: str | Exception,
    alerts: list[Alert],
    owner: dict | None = None,
) -> tuple[Budget, PriceUpdater]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    budget = Budget(
        BudgetSettings(owner_prices=owner or {}),
        state_dir=state,
        record=box.append,
        alert=alerts.append,
        history=box.events,
    )
    budget.open()

    def fetch(url: str) -> str:
        if isinstance(page, Exception):
            raise page
        return page

    updater = PriceUpdater(
        budget,
        state_dir=state,
        record=box.append,
        fetch=fetch,
        url="http://127.0.0.1:1/pricing.md",
        now=lambda: datetime(2026, 10, 21, 8, tzinfo=UTC),
    )
    return budget, updater


def test_a_change_is_recorded_announced_stored_and_used(tmp_path: Path, box: BlackBox) -> None:
    alerts: list[Alert] = []
    page = PAGE.replace(
        "| Claude Opus 5.5 | $4 / MTok | $5 / MTok | $8 / MTok",
        "| Claude Opus 5.5 | $3 / MTok | $3.75 / MTok | $6 / MTok",
    )
    budget, updater = setup(tmp_path, box, page, alerts)
    assert updater.run_once()
    found, layer = budget.book.lookup("claude-opus-5-5")
    assert (found.input, layer) == (Decimal("3"), "anthropic")
    updated = [e for e in box.events() if e.action == "prices_updated"]
    assert len(updated) == 1
    changes = {c["model"]: c for c in updated[0].details["changes"]}
    assert changes["claude-opus-5-5"]["old"]["input"] == "4"
    assert changes["claude-opus-5-5"]["new"]["input"] == "3"
    assert "claude-sonnet-5-5" not in changes  # the same as before: not a change
    assert updated[0].details["fetched_on"] == "2026-10-21"
    assert [a.level for a in alerts] == [AlertLevel.INFO]
    path = tmp_path / "state" / STATE_PRICES
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    table, on = read_state(tmp_path / "state")
    assert table["claude-opus-5-5"].input == Decimal("3") and on.isoformat() == "2026-10-21"
    assert budget.status()["prices"]["updated_on"] == "2026-10-21"
    # Again, the same page: no new event, no new alert.
    assert updater.run_once()
    assert len([e for e in box.events() if e.action == "prices_updated"]) == 1
    assert len(alerts) == 1


def test_the_owner_still_wins(tmp_path: Path, box: BlackBox) -> None:
    alerts: list[Alert] = []
    budget, updater = setup(
        tmp_path, box, PAGE, alerts, owner={"claude-opus-5-5": price("1", "2", "0.1")}
    )
    assert updater.run_once()
    assert budget.book.lookup("claude-opus-5-5")[1] == "owner"


def test_failures_keep_the_last_good_table_and_warn_once_a_day(
    tmp_path: Path, box: BlackBox
) -> None:
    alerts: list[Alert] = []
    budget, updater = setup(tmp_path, box, PriceUpdateError("HTTP 503"), alerts)
    before = budget.book
    assert not updater.run_once()
    assert not updater.run_once()
    assert budget.book == before
    failed = [e for e in box.events() if e.action == "prices_failed"]
    assert len(failed) == 2 and failed[0].details["error"] == "HTTP 503"
    assert [a.level for a in alerts] == [AlertLevel.WARNING]  # once that day
    _, garbage = setup(tmp_path, box, "<html>not the page</html>", alerts)
    assert not garbage.run_once()


def test_a_stored_table_is_loaded_at_start(tmp_path: Path, box: BlackBox) -> None:
    alerts: list[Alert] = []
    _, first = setup(
        tmp_path,
        box,
        PAGE.replace("| Claude Sonnet 5.5 | $2 / MTok", "| Claude Sonnet 5.5 | $2.20 / MTok"),
        alerts,
    )
    assert first.run_once()
    budget, second = setup(tmp_path, box, PriceUpdateError("down"), alerts)
    second.load()
    assert budget.book.lookup("claude-sonnet-5-5")[0].input == Decimal("2.20")
    (tmp_path / "state" / STATE_PRICES).write_text(json.dumps({"version": 1}))
    os.chmod(tmp_path / "state" / STATE_PRICES, 0o600)
    third, loader = setup(tmp_path, box, PAGE, alerts)
    loader.load()
    assert third.book.fetched == {}
    assert [e for e in box.events() if e.action == "prices_failed"][-1].details["stage"] == "stored"


class _Page(http.server.BaseHTTPRequestHandler):
    body = PAGE.encode()

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        if self.path == "/moved":
            self.send_response(302)
            self.send_header("location", "/pricing.md")
            self.end_headers()
            return
        self.send_response(200 if self.path == "/pricing.md" else 404)
        self.send_header("content-type", "text/markdown")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: object) -> None:
        pass


def test_fetch_from_a_local_fake_page() -> None:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Page)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert "Claude Opus 5.5" in fetch_page(f"{base}/pricing.md")
        with pytest.raises(PriceUpdateError):
            fetch_page(f"{base}/missing")
        with pytest.raises(PriceUpdateError):
            fetch_page(f"{base}/moved")  # never follows a redirect
    finally:
        server.shutdown()
        server.server_close()
