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
from backtide.service.prices import DEFAULT_PRICES, price
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


def test_changes_over_ten_times_from_the_shipped_price_are_refused() -> None:
    cheap = price("0.30", "20", "0.20")  # Opus 5.5's input 4 -> 0.30: more than 10x down
    dear = price("5", "25", "0.25")
    checked = check_prices(
        {"claude-opus-5-5": cheap, "claude-sonnet-5-5": dear, "claude-opus-6": dear},
        DEFAULT_PRICES,
    )
    assert set(checked.accepted) == {"claude-sonnet-5-5"}  # a rise: applied at once
    assert checked.pending == {"claude-opus-6": (dear, "new_model")}  # B3: the owner decides
    assert checked.rejected == [{"model": "claude-opus-5-5", "why": "changes more than 10x"}]
    bad_id = check_prices({"gpt-6-sol": dear}, DEFAULT_PRICES)
    assert bad_id.rejected == [{"model": "gpt-6-sol", "why": "id"}]


def test_m2_a_short_id_is_checked_against_every_model_it_would_shadow() -> None:
    tiny = price("0.01", "0.01", "0.01")
    checked = check_prices({"claude-sonnet-4": tiny}, DEFAULT_PRICES)
    assert checked.accepted == {} and checked.pending == {}
    assert checked.rejected == [
        {"model": "claude-sonnet-4", "why": "changes more than 10x from claude-sonnet-4-5"}
    ]
    plausible = price("3", "15", "0.30")
    again = check_prices({"claude-sonnet-4": plausible}, DEFAULT_PRICES)
    assert again.pending == {"claude-sonnet-4": (plausible, "new_model")}  # never on its own


def test_b3_the_check_is_anchored_to_the_shipped_prices() -> None:
    """A forged page cannot walk a price down 10x a day: the anchor never moves, and more than
    half below it waits for the owner."""
    half = price("1.90", "20", "0.20")  # Opus 5.5's input 4 -> 1.90: past half
    checked = check_prices({"claude-opus-5-5": half}, DEFAULT_PRICES)
    assert checked.pending == {"claude-opus-5-5": (half, "drop")} and checked.accepted == {}
    down = price("3", "15", "0.15")  # within half: applied
    assert check_prices({"claude-opus-5-5": down}, DEFAULT_PRICES).accepted == {
        "claude-opus-5-5": down
    }
    walked = price("0.30", "2", "0.02")  # yesterday's 3 was taken; the anchor is still 4
    assert check_prices({"claude-opus-5-5": walked}, DEFAULT_PRICES).rejected
    no_tier = price("0.10", "0.50", "0.01")  # Haiku 5.5 without its long-prompt tier
    assert check_prices({"claude-haiku-5-5": no_tier}, DEFAULT_PRICES).pending == {
        "claude-haiku-5-5": (no_tier, "drop")
    }
    accepted = check_prices({"claude-opus-6": half}, DEFAULT_PRICES, owned={"claude-opus-6": half})
    assert accepted.accepted == {"claude-opus-6": half}  # what the owner accepted stays


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
    # Opus 4.1 and Haiku 3 are not shipped: new models wait for the owner (B3), said once.
    pending = [e for e in box.events() if e.action == "prices_pending"]
    assert [r["model"] for r in pending[0].details["rows"]] == ["claude-haiku-3", "claude-opus-4-1"]
    assert budget.book.lookup("claude-opus-4-1") is None
    assert [a.level for a in alerts] == [AlertLevel.INFO, AlertLevel.INFO]
    path = tmp_path / "state" / STATE_PRICES
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    stored = read_state(tmp_path / "state")
    assert stored.table["claude-opus-5-5"].input == Decimal("3")
    assert stored.on.isoformat() == "2026-10-21"
    assert set(stored.pending) == {"claude-haiku-3", "claude-opus-4-1"}
    assert budget.status()["prices"]["updated_on"] == "2026-10-21"
    # Again, the same page: no new event, no new alert.
    assert updater.run_once()
    assert len([e for e in box.events() if e.action == "prices_updated"]) == 1
    assert len([e for e in box.events() if e.action == "prices_pending"]) == 1
    assert len(alerts) == 2


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


def test_b3_new_prices_wait_for_the_owner_and_are_applied_on_a_yes(
    tmp_path: Path, box: BlackBox
) -> None:
    alerts: list[Alert] = []
    page = PAGE.replace(
        "| Claude Opus 5.5 | $4 / MTok | $5 / MTok | $8 / MTok",
        "| Claude Opus 5.5 | $1 / MTok | $1.25 / MTok | $2 / MTok",
    )
    budget, updater = setup(tmp_path, box, page, alerts)
    assert updater.run_once()
    assert budget.book.lookup("claude-opus-5-5")[1] == "defaults"  # a drop past half: waits
    shown = budget.status()["prices"]
    whys = {row["model"]: row["why"] for row in shown["pending"]}
    assert whys == {"claude-opus-5-5": "drop", "claude-opus-4-1": "new_model",
                    "claude-haiku-3": "new_model"}  # fmt: skip
    assert next(r for r in shown["pending"] if r["model"] == "claude-opus-5-5")["input"] == "1"
    digest = shown["pending_digest"]
    wrong = budget.accept_prices("0" * 16, requested_by="web (uid 1, pid 2)")
    assert not wrong.ok and budget.book.lookup("claude-opus-5-5")[1] == "defaults"
    done = budget.accept_prices(digest, requested_by="web (uid 1, pid 2)")
    assert done.ok, done
    assert budget.book.lookup("claude-opus-5-5")[1] == "anthropic"
    assert budget.book.fetched["claude-opus-5-5"].input == Decimal("1")
    assert budget.status()["prices"]["pending"] == []
    [accepted] = [e for e in box.events() if e.action == "prices_accepted"]
    assert accepted.source == "settings" and accepted.details["requested_by"].startswith("web")
    assert sorted(c["model"] for c in accepted.details["changes"]) == sorted(whys)
    # Kept: a restart loads them, and the same page again asks nothing.
    budget2, again = setup(tmp_path, box, page, alerts)
    again.load()
    assert budget2.book.fetched["claude-opus-5-5"].input == Decimal("1")
    told = len([e for e in box.events() if e.action == "prices_pending"])
    assert again.run_once()
    assert budget2.status()["prices"]["pending"] == []
    assert len([e for e in box.events() if e.action == "prices_pending"]) == told


def test_b3_a_stored_table_from_before_the_review_is_checked_again(
    tmp_path: Path, box: BlackBox
) -> None:
    from backtide.service.price_update import write_state

    alerts: list[Alert] = []
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    tiny = price("0.01", "0.01", "0.01")
    write_state(state, {"claude-sonnet-4": tiny, "claude-sonnet-5-5": price("2.2", "10", "0.2")},
                datetime(2026, 10, 20).date())  # fmt: skip
    budget, updater = setup(tmp_path, box, PAGE, alerts)
    updater.load()
    assert set(budget.book.fetched) == {"claude-sonnet-5-5"}
    assert [e for e in box.events() if e.action == "prices_rejected"]
