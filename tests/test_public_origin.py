"""T26-4a: `[web] public_origin`, the web behind a domain. What it may be is checked when anything
starts, in one place: only https, a name and perhaps a port, and nothing else. Anything else stops
the service, and the message says why without quoting the value (it may hold a password)."""

from pathlib import Path

import pytest

from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.origin import PublicOrigin, parse_public_origin
from backtide.web.paths import WebPaths
from tests.test_service_config import layout, write_toml  # noqa: F401 - the fixture

GOOD = "https://backtide.example.org"


@pytest.mark.parametrize(
    ("given", "name", "host", "url"),
    [
        (GOOD, "backtide.example.org", "backtide.example.org", GOOD),
        ("https://BackTide.Example.ORG", "backtide.example.org", "backtide.example.org", GOOD),
        (GOOD + ":443", "backtide.example.org", "backtide.example.org", GOOD),  # as a browser says
        (GOOD + ":8443", "backtide.example.org", "backtide.example.org:8443", GOOD + ":8443"),
        ("https://xn--bcher-kva.example", "xn--bcher-kva.example", "xn--bcher-kva.example",
         "https://xn--bcher-kva.example"),
        ("https://a-b.c1.example", "a-b.c1.example", "a-b.c1.example", "https://a-b.c1.example"),
    ],
)  # fmt: skip
def test_a_good_origin_says_its_name_its_host_and_its_url(
    given: str, name: str, host: str, url: str
) -> None:
    origin = parse_public_origin(given)
    assert (origin.name, origin.host, origin.url) == (name, host, url)
    assert origin.link_base == url + "/"


@pytest.mark.parametrize(
    ("given", "why"),
    [
        ("http://backtide.example.org", "https"),
        ("ftp://backtide.example.org", "https"),
        ("backtide.example.org", "https"),
        ("//backtide.example.org", "https"),
        ("HTTPS://backtide.example.org", "https"),
        ("https://backtide.example.org/", "path"),  # a slash is a path
        ("https://dev.example.org/backtide", "path"),  # D40: never under another site's path
        ("https://backtide.example.org?x=1", "path"),
        ("https://backtide.example.org#top", "path"),
        ("https://user:secret-in-the-url@backtide.example.org", "credentials"),
        ("https://user@backtide.example.org", "credentials"),
        ("https://backtide.example.org:0", "port"),
        ("https://backtide.example.org:65536", "port"),
        ("https://backtide.example.org:", "name"),
        ("https://backtide.example.org:abc", "name"),
        ("https://backtide.example.org:123456", "name"),
        ("https://", "name"),
        ("https://backtide", "dot"),  # one label: not a site of its own
        ("https://localhost", "dot"),
        ("https://backtide.localhost", "localhost"),  # the tunnel's name, not a public one
        ("https://x.LOCALHOST", "localhost"),
        ("https://127.0.0.1", "address"),
        ("https://1.2.3.4:8443", "address"),
        ("https://0x7f.0.0.0x1", "address"),
        ("https://[::1]", "address"),
        ("https://[2001:db8::1]:8443", "address"),
        ("https://exa mple.org", "name"),
        ("https://exámple.org", "name"),  # an international name goes in its xn-- form
        ("https://backtide.example.org\n", "name"),
        ("https://backtide.example.org\r\nX-Evil: 1", "name"),
        ("https://-bad.example.org", "name"),
        ("https://bad-.example.org", "name"),
        ("https://two..dots.org", "name"),
        ("https://trailing.dot.", "name"),
        ("https://under_score.example.org", "name"),
        ("https://" + "a" * 64 + ".example.org", "name"),
        ("https://" + ".".join(["a" * 60] * 5) + ".org", "name"),  # past 253 characters
        ("", "https"),
        (" https://backtide.example.org", "https"),
        (1, "text"),
        (True, "text"),
        (["https://backtide.example.org"], "text"),
        (None, "text"),
    ],
)
def test_anything_else_is_refused_and_says_why(given: object, why: str) -> None:
    with pytest.raises(ValueError, match=why) as refused:
        parse_public_origin(given)
    # Never the value: it may hold a password, and this goes to a terminal and a journal.
    assert "secret-in-the-url" not in str(refused.value)
    assert "user" not in str(refused.value)


def test_a_name_at_the_very_limit_is_good() -> None:
    name = ".".join(["a" * 63] * 3) + "." + "b" * 61  # 253 characters
    assert len(name) == 253
    assert parse_public_origin(f"https://{name}").name == name


def test_the_service_has_no_public_origin_unless_it_is_set(layout: Path) -> None:  # noqa: F811
    assert ServiceConfig.from_file(write_toml(layout)).web_public_origin() is None
    plain = write_toml(layout, "[web]\nsession_idle_seconds = 60\n")
    assert ServiceConfig.from_file(plain).web_public_origin() is None


def test_the_service_reads_it_from_web(layout: Path) -> None:  # noqa: F811
    config = ServiceConfig.from_file(write_toml(layout, f'[web]\npublic_origin = "{GOOD}"\n'))
    assert config.web_public_origin() == PublicOrigin("backtide.example.org")


@pytest.mark.parametrize(
    "value",
    [
        '"http://backtide.example.org"',
        '"https://user:secret-in-the-url@backtide.example.org"',
        '"https://dev.example.org/backtide"',
        '""',
        "true",
        "443",
    ],
)
def test_the_service_does_not_start_with_a_bad_one(layout: Path, value: str) -> None:  # noqa: F811
    with pytest.raises(ConfigError, match=r"\[web\] public_origin") as refused:
        ServiceConfig.from_file(write_toml(layout, f"[web]\npublic_origin = {value}\n"))
    assert "secret-in-the-url" not in str(refused.value)


def test_the_web_reads_it_from_its_own_file(tmp_path: Path) -> None:
    file = tmp_path / "web.toml"
    file.write_text(f'state_dir = "/s"\nvolume = "/v"\n\n[web]\npublic_origin = "{GOOD}:8443"\n')
    origin = WebPaths.from_file(file).public_origin
    assert origin is not None and origin.url == GOOD + ":8443"


def test_the_web_has_none_unless_it_is_set(tmp_path: Path) -> None:
    file = tmp_path / "web.toml"
    file.write_text('state_dir = "/s"\nvolume = "/v"\n')
    assert WebPaths.from_file(file).public_origin is None
    # The service's own settings of [web] are not the web's business: they stay ignored.
    file.write_text('state_dir = "/s"\nvolume = "/v"\n[web]\nsession_idle_seconds = 60\n')
    assert WebPaths.from_file(file).public_origin is None


@pytest.mark.parametrize(
    "extra",
    [
        '[web]\npublic_origin = "http://backtide.example.org"\n',
        '[web]\npublic_origin = "https://user:secret-in-the-url@backtide.example.org"\n',
        "web = 1\n",
    ],
)
def test_the_web_does_not_start_with_a_bad_one(tmp_path: Path, extra: str) -> None:
    file = tmp_path / "web.toml"
    head = 'state_dir = "/s"\nvolume = "/v"\n'
    # A top-level key has to come before any table.
    file.write_text(extra + head if extra.startswith("web") else head + extra)
    with pytest.raises(ConfigError, match=r"\[web\]") as refused:
        WebPaths.from_file(file)
    assert "secret-in-the-url" not in str(refused.value)
