from ipaddress import IPv4Address, IPv6Address

import pytest

from backtide.gate import policy
from backtide.gate.policy import (
    AllowList,
    host_mismatch,
    is_oauth_login,
    is_public,
    normalize_host,
    normalize_pattern,
    numeric_ipv4,
    parse_host_header,
    pick_address,
    port_allowed,
)

# --- ports -----------------------------------------------------------------------------------


@pytest.mark.parametrize("port", [80, 443])
def test_only_80_and_443_are_allowed(port: int) -> None:
    assert port_allowed(port)


@pytest.mark.parametrize("port", [0, 22, 25, 53, 8080, 8443, 444, 65535, 65536, -443, "443", 443.0])
def test_other_ports_are_refused(port: object) -> None:
    assert not port_allowed(port)


def test_a_bool_is_not_a_port() -> None:
    assert not port_allowed(True)


# --- is_public -------------------------------------------------------------------------------

PUBLIC = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.215.14",
    "160.79.104.10",  # api.anthropic.com, at the time of writing
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2a00:1450:4001:80b::200e",
]

NOT_PUBLIC = [
    # loopback
    "127.0.0.1",
    "127.255.255.254",
    "::1",
    # "this network" and unspecified
    "0.0.0.0",  # noqa: S104
    "0.1.2.3",
    "::",
    # private (RFC 1918) and unique local
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "fc00::1",
    "fd12:3456:789a::1",
    # link-local, including the cloud metadata service
    "169.254.169.254",
    "169.254.0.1",
    "fe80::1",
    "febf::1",
    # deprecated site-local (Python calls it global)
    "fec0::1",
    # CGNAT (RFC 6598)
    "100.64.0.1",
    "100.127.255.254",
    # multicast and broadcast (Python calls IPv4 multicast global)
    "224.0.0.1",
    "239.255.255.250",
    "255.255.255.255",
    "ff02::1",
    "ff0e::1",
    # reserved, benchmarking, documentation, IETF and 6to4 relay
    "240.0.0.1",
    "198.18.0.1",
    "198.19.255.255",
    "192.0.0.8",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "192.88.99.1",
    "2001:db8::1",
    "3fff::1",
    "2001:2::1",
    "100::1",
    # IPv4 hidden in IPv6: mapped, compatible, translated, NAT64, 6to4 and Teredo
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:10.0.0.1",
    "::ffff:8.8.8.8",
    "::127.0.0.1",
    "::7f00:1",
    "::ffff:0:7f00:1",
    "64:ff9b::7f00:1",
    "64:ff9b::808:808",
    "64:ff9b:1::a00:1",
    "2002:7f00:1::",
    "2002:808:808::",
    "2001::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
]


@pytest.mark.parametrize("address", PUBLIC)
def test_public_addresses_are_public(address: str) -> None:
    assert is_public(address)
    assert is_public(IPv4Address(address) if "." in address else IPv6Address(address))


@pytest.mark.parametrize("address", NOT_PUBLIC)
def test_addresses_that_are_not_public_are_refused(address: str) -> None:
    assert not is_public(address)


@pytest.mark.parametrize(
    "address",
    [
        "2130706433",  # 127.0.0.1 as a decimal number
        "0x7f000001",
        "0177.0.0.1",  # octal
        "0x7f.0.0.1",
        "127.1",  # short form
        "127.0.0.1.",
        " 8.8.8.8",
        "8.8.8.8 ",
        "8.8.8.8\n",
        "[2606:4700::1]",
        "2606:4700::1%eth0",  # a scope id
        "fe80::1%eth0",
        "localhost",
        "",
        "api.anthropic.com",
    ],
)
def test_texts_that_are_not_a_plain_address_are_refused(address: str) -> None:
    assert not is_public(address)


@pytest.mark.parametrize("value", [2130706433, 134744072, None, True, b"8.8.8.8", ["8.8.8.8"]])
def test_values_that_are_not_an_address_are_refused(value: object) -> None:
    assert not is_public(value)


def test_pick_address_takes_an_ipv4_one_when_all_are_public() -> None:
    assert pick_address(["2606:4700::1", "1.1.1.1", "1.0.0.1"]) == "1.1.1.1"
    assert pick_address(["2606:4700::1"]) == "2606:4700::1"


@pytest.mark.parametrize(
    "addresses",
    [
        [],
        ["8.8.8.8", "127.0.0.1"],  # one bad answer spoils them all (DNS rebinding)
        ["169.254.169.254", "8.8.8.8"],
        ["8.8.8.8", "not-an-ip"],
        ["::ffff:8.8.8.8"],
    ],
)
def test_pick_address_refuses_when_any_address_is_not_public(addresses: list[str]) -> None:
    assert pick_address(addresses) is None


# --- hosts and the allow list ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "normal"),
    [
        ("api.anthropic.com", "api.anthropic.com"),
        ("API.Anthropic.COM", "api.anthropic.com"),
        ("api.anthropic.com.", "api.anthropic.com"),
        (" api.anthropic.com ", "api.anthropic.com"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("8.8.8.8", "8.8.8.8"),
        ("[2606:4700::1]", "2606:4700::1"),
        ("2606:4700:0::1", "2606:4700::1"),
        ("my_host.example", "my_host.example"),
    ],
)
def test_hosts_are_normalized(host: str, normal: str) -> None:
    assert normalize_host(host) == normal


@pytest.mark.parametrize(
    "host",
    [
        "",
        ".",
        "a..b",
        "a.b..",
        "-a.example",
        "a-.example",
        "a b.example",
        "a/b.example",
        "a:b.example",
        "user@host.example",
        "x" * 64 + ".example",
        ".".join(["a" * 60] * 5),  # over 253
        "host\x00.example",
        "host\n.example",
        "*.example.com",
        "bücher.de",  # from the wire, a host must already be punycode
        "ａｐｉ.anthropic.com",  # fullwidth letters that IDNA 2003 would fold
        "api。anthropic。com",  # ideographic full stops
        "faß.de",
        None,
        42,
    ],
)
def test_bad_hosts_do_not_normalize(host: object) -> None:
    assert normalize_host(host) is None


@pytest.mark.parametrize(
    ("entry", "normal"),
    [
        ("api.example.com", "api.example.com"),
        ("API.Example.com.", "api.example.com"),
        ("*.example.com", "*.example.com"),
        ("*.Bücher.de", "*.xn--bcher-kva.de"),
    ],
)
def test_allow_entries_are_normalized(entry: str, normal: str) -> None:
    assert normalize_pattern(entry) == normal


@pytest.mark.parametrize(
    "entry",
    ["", "*", "*.", "*.com", "**.example.com", "a.*.example.com", "*example.com", "8.8.8.8",
     "[::1]", "example.com/path", "a..b"],
)  # fmt: skip
def test_bad_allow_entries_are_refused(entry: str) -> None:
    with pytest.raises(ValueError):
        normalize_pattern(entry)


def test_the_allow_list_matches_exact_names_and_subdomains() -> None:
    allow = AllowList(["api.example.com", "*.cdn.example.net", "Bücher.de"])
    assert allow.allows("api.example.com")
    assert allow.allows("API.EXAMPLE.COM.")
    assert allow.allows("a.cdn.example.net")
    assert allow.allows("a.b.cdn.example.net")
    assert allow.allows("xn--bcher-kva.de")
    assert not allow.allows("bücher.de")  # not punycode: not from a real client
    assert not allow.allows("cdn.example.net")  # "*." is for subdomains only
    assert not allow.allows("example.com")
    assert not allow.allows("x.api.example.com")
    assert not allow.allows("api.example.com.evil.test")
    assert not allow.allows("evilapi.example.com")
    assert not allow.allows("acdn.example.net")
    assert not allow.allows("8.8.8.8")
    assert not allow.allows("")
    assert not allow.allows("a..cdn.example.net")


def test_an_empty_allow_list_allows_nothing() -> None:
    assert not AllowList([]).allows("example.com")


def test_the_allow_list_keeps_its_entries_normalized_and_unique() -> None:
    allow = AllowList(["A.example", "a.example.", "*.B.example"])
    assert allow.entries == ("a.example", "*.b.example")


# --- host_mismatch (domain fronting) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "parsed"),
    [
        ("example.com", ("example.com", None)),
        ("Example.COM:443", ("example.com", 443)),
        ("[2606:4700::1]:8443", ("2606:4700::1", 8443)),
        ("[2606:4700::1]", ("2606:4700::1", None)),
        ("example.com.", ("example.com", None)),
    ],
)
def test_host_headers_are_parsed(value: str, parsed: tuple[str, int | None]) -> None:
    assert parse_host_header(value) == parsed


@pytest.mark.parametrize(
    "value",
    ["", ":443", "example.com:", "example.com:http", "example.com:99999", "a@b.com", "a b",
     "2606:4700::1", "example.com:443:1", None],
)  # fmt: skip
def test_bad_host_headers_do_not_parse(value: object) -> None:
    assert parse_host_header(value) is None


def test_the_same_host_is_not_a_mismatch() -> None:
    assert not host_mismatch("api.example.com", "api.example.com")
    assert not host_mismatch("api.example.com", "API.example.com.:443", connect_port=443)
    assert not host_mismatch(
        "api.example.com", "api.example.com", connect_port=443, sni="api.example.com"
    )


@pytest.mark.parametrize(
    ("connect", "header", "port", "sni"),
    [
        ("allowed.example", "evil.example", None, None),  # domain fronting
        ("allowed.example", "allowed.example.evil.test", None, None),
        ("allowed.example", "allowed.example:8443", 443, None),
        ("allowed.example", "allowed.example", 443, "evil.example"),
        ("allowed.example", None, None, None),  # no Host at all
        ("allowed.example", "", None, None),
        ("allowed.example", "allowed.example:443:1", 443, None),
        ("allowed.example", "a@allowed.example", None, None),
        ("not a host", "not a host", None, None),
    ],
)
def test_a_different_host_is_a_mismatch(
    connect: str, header: str | None, port: int | None, sni: str | None
) -> None:
    assert host_mismatch(connect, header, connect_port=port, sni=sni)


# --- OAuth logins ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("auth.openai.com", "/"),
        ("auth.openai.com", "/oauth/token"),
        ("AUTH.OPENAI.COM.", "/anything?x=1"),
        ("accounts.google.com", "/o/oauth2/v2/auth"),
        ("oauth2.googleapis.com", "/token"),
        ("claude.ai", "/oauth/authorize?client_id=x"),
        ("claude.ai", "/oauth/authorize/"),
        ("claude.ai", "/OAuth/Authorize"),
        ("claude.ai", "//oauth//authorize"),
        ("claude.ai", "/%6Fauth/authorize"),
        ("claude.ai", "/%256Fauth/authorize"),
        ("claude.ai", "/x/../oauth/authorize"),
        ("claude.ai", "/./oauth/authorize"),
        ("claude.ai", "/oauth;v=1/authorize"),
        ("claude.ai", "\\oauth\\authorize"),
        ("claude.ai", "/oauth%3Fx"),
        ("claude.ai", "/oauth."),
        ("claude.ai", "/oauth%20/authorize"),
        ("claude.ai", "/OAUTH%2e/authorize"),
        ("console.anthropic.com", "/v1/oauth/token"),
        ("console.anthropic.com", "/oauth/code/callback"),
        ("platform.claude.com", "/v1/oauth/token"),
        ("api.anthropic.com", "/api/oauth/profile"),
        ("github.com", "/login/oauth/access_token"),
        ("github.com", "/login/device/code"),
        # T06-7: the other ways to the same tokens (Google's older token endpoint, Microsoft's
        # second login host, OpenRouter's PKCE flow that hands out an API key).
        ("www.googleapis.com", "/oauth2/v4/token"),
        ("www.googleapis.com", "//OAuth2/v3/token"),
        ("login.microsoft.com", "/common/oauth2/v2.0/devicecode"),
        ("login.windows.net", "/common/oauth2/token"),
        ("sts.windows.net", "/tenant/oauth2/token"),
        ("openrouter.ai", "/auth?callback_url=https://x"),
        ("openrouter.ai", "/api/v1/auth/keys"),
        ("openrouter.ai.", "/API/v1/./auth/keys"),
    ],
)
def test_oauth_logins_are_recognized(host: str, path: str) -> None:
    assert is_oauth_login(host, path)


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("api.anthropic.com", "/v1/messages"),
        ("claude.ai", "/"),
        ("claude.ai", "/oauthx/authorize"),
        ("claude.ai", "/chat/oauth"),
        ("console.anthropic.com", "/settings/keys"),
        ("github.com", "/anthropics/claude-code"),
        ("api.openai.com", "/v1/chat/completions"),
        ("example.com", "/oauth/authorize"),
        ("www.googleapis.com", "/drive/v3/files"),
        ("openrouter.ai", "/api/v1/chat/completions"),
        ("openrouter.ai", "/api/v1/authx"),
    ],
)
def test_other_requests_are_not_oauth_logins(host: str, path: str) -> None:
    assert not is_oauth_login(host, path)


def test_a_host_that_does_not_normalize_counts_as_oauth() -> None:
    # Refusing more is the safe side: the request is refused anyway by other rules.
    assert is_oauth_login("not a host", "/")


def test_config_names_may_be_unicode_and_become_punycode() -> None:
    assert normalize_host("Bücher.de", idna=True) == "xn--bcher-kva.de"
    assert normalize_host("bücher.de") is None


def test_the_oauth_lists_are_normalized() -> None:
    for host in policy.OAUTH_HOSTS:
        assert normalize_host(host) == host
    for host, prefix in policy.OAUTH_PATHS:
        assert normalize_host(host) == host
        assert prefix.startswith("/") and prefix == prefix.lower()


# --- IPv4 written as numbers (T06-6) -------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "address"),
    [
        ("127.1", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("0x7F.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("169.254.43518", "169.254.169.254"),
        ("10.1", "10.0.0.1"),
        ("0", "0.0.0.0"),  # noqa: S104 - a target, nothing binds
        ("134744072", "8.8.8.8"),
        ("127.0.0.1.", "127.0.0.1"),
        ("1.2.3.4", "1.2.3.4"),
        ("0x", "0.0.0.0"),  # noqa: S104 - a target
        ("0x.0x.0x.0x", "0.0.0.0"),  # noqa: S104 - a target
    ],
)
def test_ipv4_written_as_numbers_is_read_as_inet_aton_does(host: str, address: str) -> None:
    assert numeric_ipv4(host) == address


@pytest.mark.parametrize(
    "host",
    ["example.com", "1.2.3.4.5", "256.1.1.1", "1.2.65536", "08.1", "1..2", "", "1.2.3.4a",
     "4294967296", "::1", "a.0x7f", 7, None],
)  # fmt: skip
def test_other_hosts_are_not_numeric_ipv4(host: object) -> None:
    assert numeric_ipv4(host) is None
