"""A page on 127.0.0.1 is still a target for every other page in the browser: these tests are the
reasons the lookout post can be left open."""

import re
import urllib.request
import warnings
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backtide.web.security import CSP, make_token, token_matches
from tests.webkit import (
    BASE,
    PORT,
    PREFIX,
    PREFIX_PATH,
    ROOT,
    RUN_NAME,
    SESSION,
    TOKEN,
    new_app,
    new_box,
    new_client,
)

PAGES = [
    "/",
    "/panel",
    "/ahora",
    "/historia",
    "/instantaneas",
    "/ahora/preguntar?q=ayuda",
    "/agentes/principal/ahora",
    "/agentes/principal/historia",
]


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    new_box(tmp_path).append("file", "create", "notas.md")
    return new_client(tmp_path)


def anonymous(tmp_path: Path, base_url: str = BASE) -> TestClient:
    new_box(tmp_path).append("file", "create", "notas.md")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return TestClient(new_app(tmp_path), base_url=base_url)


# -- the Host header: DNS rebinding -----------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        f"evil.example:{PORT}",
        "127.0.0.1",  # no port
        f"127.0.0.1:{PORT + 1}",  # another port
        f"localhost:{PORT + 1}",
        f"127.0.0.1.evil.example:{PORT}",
        f"localhost.:{PORT}",
        f"[::1]:{PORT}",
        f"0.0.0.0:{PORT}",
        f"127.0.0.1:{PORT}@evil.example",
        f"evil.example:{PORT}, 127.0.0.1:{PORT}",
        "",
    ],
)
def test_a_foreign_host_header_is_refused_even_with_the_right_cookie(
    client: TestClient, host: str
) -> None:
    response = client.get("/ahora", headers={"host": host})
    assert response.status_code == 400
    assert "notas.md" not in response.text


def test_only_the_numeric_address_is_accepted(client: TestClient) -> None:
    assert client.get("/ahora", headers={"host": f"127.0.0.1:{PORT}"}).status_code == 200
    # "localhost" may also be ::1, where another program could be listening: not ours
    for name in ("localhost", "LOCALHOST", "localhost."):
        assert client.get("/ahora", headers={"host": f"{name}:{PORT}"}).status_code == 400


def test_the_host_is_checked_before_the_token_and_for_static_files(tmp_path: Path) -> None:
    rebound = anonymous(tmp_path, f"http://evil.example:{PORT}{PREFIX_PATH}")
    assert rebound.get("/ahora").status_code == 400
    assert rebound.get("/ahora?t=" + TOKEN).status_code == 400  # not even a cookie is given
    assert rebound.get("/static/web.css").status_code == 400


def test_two_host_headers_are_refused(client: TestClient) -> None:
    response = client.get(
        "/ahora", headers=[("host", f"127.0.0.1:{PORT}"), ("host", "evil.example")]
    )
    assert response.status_code == 400


# -- the access token --------------------------------------------------------------------------


@pytest.mark.parametrize("path", PAGES)
def test_without_the_token_nothing_is_shown(tmp_path: Path, path: str) -> None:
    response = anonymous(tmp_path).get(path, follow_redirects=False)
    assert response.status_code == 401
    assert "notas.md" not in response.text
    assert "Falta el enlace" in response.text or "link with the key" in response.text
    assert "set-cookie" not in response.headers


def test_the_stream_needs_the_token_too(tmp_path: Path) -> None:
    assert anonymous(tmp_path).get("/ahora/stream").status_code == 401


@pytest.mark.parametrize("wrong", ["nope", "", TOKEN + "x", TOKEN[:-1], TOKEN.upper()])
def test_a_wrong_token_in_the_link_or_cookie_is_refused(tmp_path: Path, wrong: str) -> None:
    web = anonymous(tmp_path)
    response = web.get("/ahora", params={"t": wrong}, follow_redirects=False)
    assert response.status_code == 401 and "set-cookie" not in response.headers
    web.cookies.set("backtide_web", wrong, domain="127.0.0.1", path=PREFIX_PATH)
    assert web.get("/ahora").status_code == 401


def test_the_link_token_is_not_a_session_and_is_not_accepted_as_a_cookie(tmp_path: Path) -> None:
    web = anonymous(tmp_path)
    web.cookies.set("backtide_web", TOKEN, domain="127.0.0.1", path=PREFIX_PATH)
    assert web.get("/ahora").status_code == 401


def test_the_link_answers_a_page_with_the_cookie_and_a_refresh_under_the_prefix(
    tmp_path: Path,
) -> None:
    """Not a 303: from another site the browser would not send a SameSite=Strict cookie along a
    redirect chain that began there. Our page starts the next navigation instead."""
    web = anonymous(tmp_path)
    first = web.get(f"/historia?origen=file&t={TOKEN}", follow_redirects=False)
    assert first.status_code == 200
    target = f"{PREFIX_PATH}/historia?origen=file"
    assert f'<meta http-equiv="refresh" content="0;url={target}">' in first.text
    assert f'<a href="{target}">' in first.text  # the way in, if the refresh is blocked
    assert "location" not in first.headers
    assert TOKEN not in first.text and SESSION not in first.text
    cookie = first.headers["set-cookie"]
    # the value is a session secret, not the link's token, and the cookie hangs from the prefix
    assert cookie.startswith(f"backtide_web={SESSION}") and TOKEN not in cookie
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert f"Path={PREFIX_PATH}" in cookie and "Path=/;" not in cookie
    assert "Max-Age" not in cookie and "expires" not in cookie.lower()  # a session cookie
    # no inline script is needed (the CSP forbids it), and the page is not cached
    assert not re.search(r"<script(?![^>]*\bsrc=)", first.text)
    assert first.headers["cache-control"] == "no-store"
    second = web.get("/historia?origen=file")  # the cookie is now enough
    assert second.status_code == 200
    assert TOKEN not in second.text and SESSION not in second.text


def test_the_enter_page_works_from_another_site_too(tmp_path: Path) -> None:
    web = anonymous(tmp_path)
    response = web.get(
        f"/ahora?t={TOKEN}",
        headers={"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate"},
    )
    assert response.status_code == 200 and "set-cookie" in response.headers


@pytest.mark.parametrize("lang", ["es", "en"])
def test_the_enter_page_is_in_both_languages(tmp_path: Path, lang: str) -> None:
    web = anonymous(tmp_path)
    html = web.get(f"/ahora?t={TOKEN}&lang={lang}").text
    assert ("Entrar" if lang == "es" else "Enter") in html


def test_the_link_works_once(tmp_path: Path) -> None:
    app = new_app(tmp_path)
    first = TestClient(app, base_url=BASE)
    assert first.get(f"/ahora?t={TOKEN}", follow_redirects=False).status_code == 200
    second = TestClient(app, base_url=BASE)  # another browser, the same link
    again = second.get(f"/ahora?t={TOKEN}", follow_redirects=False)
    assert again.status_code == 401 and "set-cookie" not in again.headers
    assert "ya se usó" in again.text


def test_two_requests_with_the_link_at_once_only_one_wins() -> None:
    import threading

    from backtide.web.security import Access

    access = Access(TOKEN)
    results: list[str | None] = []
    barrier = threading.Barrier(8)

    def use() -> None:
        barrier.wait()
        results.append(access.use_link(TOKEN))

    threads = [threading.Thread(target=use) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(r is not None for r in results) == 1


def test_a_used_link_in_a_browser_that_is_already_in_just_works(client: TestClient) -> None:
    response = client.get(f"/ahora?t={TOKEN}", follow_redirects=False)
    assert response.status_code == 200 and "notas.md" in response.text


@pytest.mark.parametrize("path", ["//evil.example/x", "///evil.example", "/%5Cevil.example"])
def test_a_strange_path_with_the_link_is_a_404_and_never_a_redirect_to_another_site(
    tmp_path: Path, path: str
) -> None:
    web = TestClient(new_app(tmp_path), base_url=BASE)
    response = web.get(f"{BASE}{path}?t={TOKEN}", follow_redirects=False)
    assert response.status_code == 404
    assert "location" not in response.headers and "set-cookie" not in response.headers


@pytest.mark.parametrize("path", ["/ahora/", "/historia/", "/instantaneas/", "/ahora/preguntar/"])
def test_a_trailing_slash_is_never_a_redirect_that_carries_the_token(
    tmp_path: Path, path: str
) -> None:
    web = TestClient(new_app(tmp_path), base_url=BASE)
    response = web.get(f"{BASE}{path}?t={TOKEN}", follow_redirects=False)
    assert response.status_code not in {301, 302, 303, 307, 308}
    assert "location" not in response.headers
    assert TOKEN not in response.text


def test_the_refresh_target_always_stays_under_the_prefix(tmp_path: Path) -> None:
    for url in (
        f"{BASE}/?t={TOKEN}",
        f"{BASE}/ahora?t={TOKEN}",
        f"{BASE}/historia?x=//evil&t={TOKEN}",
    ):
        web = TestClient(new_app(tmp_path), base_url=BASE)
        html = web.get(url).text
        (target,) = re.findall(r'<meta http-equiv="refresh" content="0;url=([^"]+)">', html)
        assert target.startswith(f"{PREFIX_PATH}/") and not target.startswith("//"), url
        assert "evil.example" not in target


@pytest.mark.parametrize(
    "path", ["//evil.example/x", "///evil.example", "/%5Cevil.example", "/%2F%2Fevil.example"]
)
def test_no_link_of_any_page_starts_with_two_slashes_or_a_slash_and_a_backslash(
    client: TestClient, path: str
) -> None:
    for url in (path, path + "?lang=en"):
        html = client.get(BASE + url).text
        hrefs = re.findall(r'(?:href|action|hx-get|src)="([^"]*)"', html)
        assert hrefs, "the page has links"
        for href in hrefs:
            assert not href.startswith(("//", "/" + chr(92))), (url, href)
            assert href.startswith(f"{PREFIX_PATH}/") or href.startswith("#"), (url, href)


def test_the_token_never_appears_in_a_page(client: TestClient) -> None:
    for path in PAGES + ["/static/web.js", "/static/web.css"]:
        assert TOKEN not in client.get(path).text
    assert TOKEN not in client.get("/nope").text


def test_tokens_are_long_random_and_compared_safely() -> None:
    assert make_token() != make_token()
    assert len(make_token()) >= 43  # 256 bits in base64
    assert token_matches(TOKEN, TOKEN)
    assert not token_matches(None, TOKEN) and not token_matches("", TOKEN)
    assert not token_matches("é", TOKEN)  # non-ASCII input is just a mismatch


# -- read-only, same-origin ---------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def test_only_get_is_answered(client: TestClient, method: str) -> None:
    response = client.request(method, "/ahora")
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"


def test_a_foreign_origin_is_refused(client: TestClient) -> None:
    assert client.get("/ahora", headers={"origin": "https://evil.example"}).status_code == 403
    assert client.get("/ahora", headers={"origin": "null"}).status_code == 403
    assert client.get("/ahora", headers={"origin": ROOT}).status_code == 200
    assert client.get("/ahora", headers={"origin": f"http://localhost:{PORT}"}).status_code == 403


def test_there_is_no_cors(client: TestClient) -> None:
    for headers in ({}, {"origin": "https://evil.example"}, {"origin": BASE}):
        response = client.get("/ahora", headers=headers)
        assert not [h for h in response.headers if h.lower().startswith("access-control-")]
    preflight = client.options(
        "/ahora",
        headers={"origin": "https://evil.example", "access-control-request-method": "GET"},
    )
    assert preflight.status_code in {403, 405}
    assert "access-control-allow-origin" not in preflight.headers


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_no_api_docs(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404


# -- headers -------------------------------------------------------------------------------------


def test_the_csp_has_no_inline_and_no_other_origin() -> None:
    assert "'unsafe-inline'" not in CSP and "'unsafe-eval'" not in CSP
    directives = dict(part.strip().split(" ", 1) for part in CSP.split(";"))
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert directives["style-src"] == "'self'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["base-uri"] == "'none'"
    assert directives["connect-src"] == "'self'"
    assert not re.search(r"https?:|\*|data:", CSP)


@pytest.mark.parametrize("path", [*PAGES, "/static/web.css", "/static/web.js", "/nope", "/docs"])
def test_every_response_carries_the_security_headers(client: TestClient, path: str) -> None:
    headers = client.get(path).headers
    assert headers["content-security-policy"] == CSP
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    # same-origin, not no-referrer (T12b): with no-referrer a browser sends "Origin: null" on
    # the confirmation's plain form POST, and the guard (rightly) refuses null. There are no
    # links to other sites, so nothing of ours travels anywhere else.
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cache-control"] == "no-store"
    assert headers["cross-origin-resource-policy"] == "same-origin"


def test_refusals_carry_them_too(tmp_path: Path) -> None:
    web = anonymous(tmp_path)
    for response in (
        web.get("/ahora", headers={"host": "evil.example"}),
        web.post("/ahora"),
        web.get("/ahora"),  # 401
    ):
        assert response.headers["content-security-policy"] == CSP
        assert response.headers["x-frame-options"] == "DENY"


def test_the_event_stream_carries_them_too(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "a")
    web = new_client(tmp_path, stream_seconds=0.05, poll_interval=0.01)
    response = web.get("/ahora/stream")
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["content-security-policy"] == CSP
    assert response.headers["cache-control"] == "no-store"


# -- the pages themselves obey the policy --------------------------------------------------------


@pytest.mark.parametrize("path", PAGES[1:])
def test_pages_have_no_inline_script_style_handler_or_foreign_url(
    client: TestClient, path: str
) -> None:
    html = client.get(path).text
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline script"
    assert not re.search(r"<style", html), "inline style element"
    assert not re.search(r"\sstyle\s*=", html), "style attribute"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "inline event handler"
    assert "javascript:" not in html.lower()
    assert not re.search(r"(?:src|href|action)=[\"']?(?:https?:)?//", html), "foreign address"
    assert "hx-on" not in html, "hx-on evaluates strings"
    for src in re.findall(r'<script src="([^"]+)"', html):
        assert src.startswith(f"{PREFIX_PATH}/static/")


def test_htmx_is_told_not_to_evaluate_strings_or_add_styles(client: TestClient) -> None:
    html = client.get("/ahora").text
    config = re.search(r"name=\"htmx-config\" content='([^']+)'", html)
    assert config
    for setting in (
        '"allowEval":false',
        '"includeIndicatorStyles":false',
        '"selfRequestsOnly":true',
    ):
        assert setting in config.group(1)


def test_htmx_and_the_font_are_served_by_us(client: TestClient) -> None:
    for path, kind in (
        ("/static/vendor/htmx.min.js", "javascript"),
        ("/static/vendor/htmx-sse.js", "javascript"),
        ("/static/fonts/jost-latin.woff2", "font"),
        ("/static/web.css", "css"),
    ):
        response = client.get(path)
        assert response.status_code == 200, path
        assert kind in response.headers["content-type"], path
    css = client.get("/static/web.css").text
    assert not re.search(r"url\((?!\"?fonts/)", css), "the CSS loads only our own fonts"
    assert "googleapis" not in css


def test_static_files_cannot_be_escaped(client: TestClient) -> None:
    for path in ("/static/../app.py", "/static/%2e%2e/app.py", "/static/..%2fapp.py"):
        assert client.get(path).status_code in {400, 404}


# -- the prefix: cookies ignore ports --------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/ahora", "/", "/static/web.css", "/ahora/stream", "/s", "/s/", "/s/other", f"{PREFIX_PATH}x"],
)
def test_nothing_answers_outside_the_prefix(client: TestClient, path: str) -> None:
    """A program that guesses ``/ahora`` (or another service that shares the cookie jar of
    127.0.0.1) finds a bare 404: not a page, not a login, not even our name."""
    response = client.get(ROOT + path)
    assert response.status_code == 404
    assert response.text == "Not found"
    assert "backtide" not in response.text.lower()


def test_the_prefix_is_matched_whole(client: TestClient) -> None:
    assert client.get(f"{ROOT}{PREFIX_PATH[:-1]}/ahora").status_code == 404
    assert client.get(f"{ROOT}{PREFIX_PATH}0/ahora").status_code == 404
    assert client.get(f"{ROOT}{PREFIX_PATH}", follow_redirects=False).status_code == 303  # home


def test_the_cookie_is_scoped_to_the_prefix_so_another_port_never_gets_it(
    tmp_path: Path,
) -> None:
    web = anonymous(tmp_path)
    web.get(f"/ahora?t={TOKEN}")
    jar = web.cookies.jar
    (cookie,) = [c for c in jar if c.name == "backtide_web"]
    assert cookie.path == PREFIX_PATH and cookie.value == SESSION
    # a request to the same host, another path (another service of 127.0.0.1): not sent
    elsewhere = urllib.request.Request(f"http://127.0.0.1:{PORT + 1}/")  # noqa: S310
    jar.add_cookie_header(elsewhere)
    assert "backtide_web" not in (elsewhere.get_header("Cookie") or "")
    ours = urllib.request.Request(f"{BASE}/ahora")  # noqa: S310
    jar.add_cookie_header(ours)
    assert "backtide_web" in (ours.get_header("Cookie") or "")


def test_two_runs_have_different_prefixes_tokens_and_names() -> None:
    from backtide.web.security import make_prefix, make_run_name

    assert len({make_prefix() for _ in range(20)}) == 20
    assert len(make_prefix()) >= 22  # 128 bits
    assert len({make_run_name() for _ in range(40)}) > 20
    assert re.fullmatch(r"[a-z]+(-[a-z]+){2}", make_run_name())


def test_an_app_without_arguments_picks_its_own_random_prefix_and_name(tmp_path: Path) -> None:
    from backtide.web import BoxReader, create_app

    one = create_app(reader=BoxReader(tmp_path / "x.db"), port=PORT)
    two = create_app(reader=BoxReader(tmp_path / "x.db"), port=PORT)
    assert one.base != two.base and one.base.startswith("/s/")


def test_the_run_name_is_in_every_page_header_and_not_in_the_secrets(client: TestClient) -> None:
    for path in PAGES[1:]:
        html = client.get(path).text
        assert '<span class="run"' in html and RUN_NAME in html
    assert RUN_NAME not in TOKEN + SESSION + PREFIX


# -- Sec-Fetch-*: the browser says who is asking ---------------------------------------------------


@pytest.mark.parametrize("site", ["same-site", "cross-site", "CROSS-SITE"])
@pytest.mark.parametrize("mode", ["cors", "no-cors", "same-origin", "websocket", ""])
def test_a_request_from_another_site_is_refused_unless_it_is_a_navigation(
    client: TestClient, site: str, mode: str
) -> None:
    headers = {"sec-fetch-site": site}
    if mode:
        headers["sec-fetch-mode"] = mode
    assert client.get("/ahora/stream", headers=headers).status_code == 403
    assert client.get("/ahora/preguntar?q=ayuda", headers=headers).status_code == 403


@pytest.mark.parametrize("site", ["same-site", "cross-site"])
def test_a_top_level_navigation_from_elsewhere_may_open_the_link(tmp_path: Path, site: str) -> None:
    """The founder clicks the link in a terminal, a chat or a page: that is a navigation."""
    web = TestClient(new_app(tmp_path), base_url=BASE)
    response = web.get(
        f"/ahora?t={TOKEN}",
        headers={"sec-fetch-site": site, "sec-fetch-mode": "navigate"},
        follow_redirects=False,
    )
    assert response.status_code == 200 and "set-cookie" in response.headers


@pytest.mark.parametrize("site", ["same-origin", "none"])
def test_our_own_requests_and_typed_addresses_pass(client: TestClient, site: str) -> None:
    assert (
        client.get("/ahora", headers={"sec-fetch-site": site, "sec-fetch-mode": "cors"}).status_code
        == 200
    )


# -- errors and telemetry --------------------------------------------------------------


def test_even_a_crash_carries_the_security_headers(tmp_path: Path) -> None:
    def explode():
        raise ValueError("a bug")

    app = new_app(tmp_path, snapshots=explode)
    web = TestClient(app, base_url=BASE, raise_server_exceptions=False)
    web.cookies.set("backtide_web", SESSION, domain="127.0.0.1", path=PREFIX_PATH)
    response = web.get("/instantaneas")
    assert response.status_code == 500
    assert response.headers["content-security-policy"] == CSP
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_the_guard_is_the_outermost_layer(tmp_path: Path) -> None:
    from backtide.web.security import Guard

    app = new_app(tmp_path)
    assert isinstance(app, Guard)
    assert type(app.inner).__name__ == "FastAPI"


def test_fastapi_telemetry_is_off(tmp_path: Path) -> None:
    config = new_app(tmp_path).inner._telemetry  # noqa: SLF001 - that is the point
    for setting in ("tracing", "metrics", "logs", "operation_spans", "auto_configure"):
        assert config[setting] is False, setting


def test_a_stale_cookie_of_the_same_name_does_not_lock_us_out(tmp_path: Path) -> None:
    """Cookies ignore ports: an old ``backtide_web`` (another run, another version) on 127.0.0.1 can
    be sent together with ours, in any order. Ours must be found among them."""
    web = anonymous(tmp_path)
    for header in (
        f"backtide_web=stale; backtide_web={SESSION}",
        f"backtide_web={SESSION}; backtide_web=stale",
        f"a=b; backtide_web=stale; backtide_lang=es; backtide_web={SESSION}",
        f'backtide_web="{SESSION}"',
    ):
        assert web.get("/ahora", headers={"cookie": header}).status_code == 200, header
    for header in (
        "backtide_web=stale; other=x",
        f"x_backtide_web={SESSION}",
        f"backtide_web2={SESSION}",
    ):
        assert web.get("/ahora", headers={"cookie": header}).status_code == 401, header
