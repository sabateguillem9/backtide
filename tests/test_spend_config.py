# ruff: noqa: F811 - pytest fixtures imported from the tests they come from
"""T11: ``[budget]`` of backtide.toml (backtide/service/config.py): the caps and their safe
defaults, the time zone, the calls in flight, the price update switch and the owner's prices."""

from decimal import Decimal
from pathlib import Path

import pytest

from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.price_update import PRICES_URL
from tests.test_service_config import layout, write_toml  # noqa: F401 - the fixture


def load(layout: Path, extra: str) -> ServiceConfig:
    return ServiceConfig.from_file(write_toml(layout, extra))


def test_the_defaults_are_a_safe_cap(layout: Path) -> None:
    settings = load(layout, "").budget_settings()
    assert (settings.daily_usd, settings.monthly_usd) == (Decimal("5"), Decimal("50"))
    assert settings.max_inflight == 4 and settings.auto_prices is True
    assert settings.prices_url == PRICES_URL and settings.owner_prices == {}
    assert settings.timezone is None and settings.timezone_name == "local"


def test_everything_can_be_set(layout: Path) -> None:
    settings = load(
        layout,
        '[budget]\ndaily_usd = 2.5\nmonthly_usd = "20"\ntimezone = "Europe/Madrid"\n'
        'max_inflight = 2\nauto_prices = false\nprices_url = "http://127.0.0.1:9/p.md"\n'
        '[budget.prices."fake-claude"]\ninput = 1000\noutput = 1000\n'
        '[budget.prices."claude-opus-5-5"]\ninput = "3"\noutput = 15\ncache_read = 0.3\n',
    ).budget_settings()
    assert (settings.daily_usd, settings.monthly_usd) == (Decimal("2.5"), Decimal("20"))
    assert settings.timezone_name == "Europe/Madrid" and settings.max_inflight == 2
    assert not settings.auto_prices
    opus = settings.owner_prices["claude-opus-5-5"]
    assert (opus.input, opus.output, opus.cache_read) == (Decimal(3), Decimal(15), Decimal("0.3"))
    assert opus.cache_write_5m == Decimal("3.75")


@pytest.mark.parametrize(
    "extra",
    [
        "[budget]\ndaily_usd = 0\n",
        "[budget]\ndaily_usd = -1\n",
        "[budget]\nmonthly_usd = true\n",
        "[budget]\ndaily_usd = 1.234\n",
        '[budget]\ntimezone = "Mars/Olympus"\n',
        "[budget]\nmax_inflight = 0\n",
        '[budget]\nauto_prices = "yes"\n',
        '[budget]\nprices_url = "http://example.com/p.md"\n',
        "[budget]\nwhatever = 1\n",
        '[budget]\napi_key = "x"\n',
        '[budget.prices."m"]\ninput = 1\n',
        '[budget.prices."m"]\ninput = 0\noutput = 1\n',
        '[budget.prices."m"]\ninput = 1\noutput = 1\nbatch = 1\n',
    ],
)
def test_what_does_not_fit_is_refused(layout: Path, extra: str) -> None:
    with pytest.raises(ConfigError) as error:
        load(layout, extra)
    assert '"x"' not in str(error.value)
