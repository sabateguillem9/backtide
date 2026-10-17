"""T12b: rewinding from the web. The first thing the web can change, so most of this file is
about what must NOT rewind: a forged request, a replayed or stale confirmation, an id that is not
in the list, a second rewind while one runs, and a web that is not allowed to ask the service.

The service is a fake (``FakeRewinder``) everywhere but the end-to-end test at the bottom, which
goes through a real control socket to a fake Guardian (``SO_PEERCRED`` is played by a fake
``peer``, as in tests/test_service_control.py)."""

import html as html_lib
import os
import re
import shutil
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlServer,
    ControlUnavailable,
)
from backtide.service.notice import rewind_notice
from backtide.service.pause import ResumeOutcome
from backtide.service.rewind import RewindOutcome, RewindStatus
from backtide.snapshots import Reason, Snapshot, SnapshotError
from backtide.web.rewind import Availability, ControlRewinder, Redeemed, Tickets
from tests.webkit import PREFIX_PATH, ROOT, SESSION, TOKEN, new_box, new_client

NOW = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
SNAPS = [
    Snapshot(NOW - timedelta(minutes=30), str(Reason.PERIODIC)),
    Snapshot(NOW - timedelta(minutes=10), str(Reason.PERIODIC)),
]
TARGET = SNAPS[0]
UNDO = Snapshot(NOW + timedelta(seconds=5), str(Reason.PRE_RESTORE))
POST_HEADERS = {
    "origin": ROOT,
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
}
REWIND = "/instantaneas/rebobinar"


class FakeRewinder:
    def __init__(self, availability: Availability = Availability.READY) -> None:
        self.state = availability
        self.calls: list[str] = []
        self.reply: dict[str, Any] = {
            "ok": True,
            "outcome": "done",
            "undo": UNDO.id,
            "message": "Rebobinado.",
            "agent_started": True,
        }
        self.error: Exception | None = None
        self.gate: threading.Event | None = None
        self.entered = threading.Event()

    def availability(self) -> Availability:
        return self.state

    def rewind(self, snapshot_id: str) -> dict[str, Any]:
        self.calls.append(snapshot_id)
        self.entered.set()
        if self.gate is not None:
            assert self.gate.wait(10)
        if self.error is not None:
            raise self.error
        return self.reply


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def rewinder() -> FakeRewinder:
    return FakeRewinder()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def listed() -> list[Snapshot]:
    return list(SNAPS)


@pytest.fixture
def web(tmp_path: Path, rewinder: FakeRewinder, clock: Clock, listed: list[Snapshot]) -> TestClient:
    new_box(tmp_path).append("file", "delete", "work/notas.md", risk=1)
    return new_client(tmp_path, snapshots=lambda: listed, rewinder=rewinder, clock=clock)


def confirm(web: TestClient, snapshot_id: str = TARGET.id, **headers: str) -> str:
    response = web.get(f"{REWIND}?{urlencode({'id': snapshot_id})}", headers=headers)
    assert response.status_code == 200, response.text[:300]
    return response.text


def form_of(page: str) -> dict[str, str]:
    """The hidden fields of the confirmation form."""
    return {
        name: html_lib.unescape(value)
        for name, value in re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page)
    }


def post(web: TestClient, fields: dict[str, str], **headers: str) -> Any:
    return web.post(REWIND, data=fields, headers={**POST_HEADERS, **headers})


def text_of(page: str) -> str:
    return html_lib.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))).strip()


# -- the list ------------------------------------------------------------------------------------


def test_with_the_service_reachable_every_row_links_to_its_confirmation(web: TestClient) -> None:
    page = web.get("/instantaneas").text
    links = re.findall(r'<a class="dot-button rewind-go" href="([^"]+)"', page)
    assert [html_lib.unescape(link) for link in links] == [
        f"{PREFIX_PATH}{REWIND}?id={s.id}" for s in reversed(SNAPS)
    ]
    assert "<form" not in page, "the list itself can never rewind: only the confirmation"
    assert "muy pronto" not in page


@pytest.mark.parametrize(
    ("state", "says"),
    [
        (Availability.NO_SERVICE, "backtide vigilar"),
        (Availability.OTHER_USER, "mismo usuario que el servicio"),
        (Availability.OFF, "no está disponible"),
    ],
)
def test_without_the_service_the_buttons_are_disabled_and_say_why(
    web: TestClient, rewinder: FakeRewinder, state: Availability, says: str
) -> None:
    rewinder.state = state
    page = web.get("/instantaneas").text
    assert page.count('<button class="dot-button" type="button" disabled') == len(SNAPS)
    assert "rewind-go" not in page
    assert says in text_of(page)


def test_without_a_rewinder_the_buttons_are_disabled(tmp_path: Path) -> None:
    page = new_client(tmp_path, snapshots=lambda: SNAPS).get("/instantaneas").text
    assert "rewind-go" not in page and "no está disponible" in text_of(page)


def test_a_list_from_the_black_box_cannot_be_rewound_from(
    tmp_path: Path, rewinder: FakeRewinder
) -> None:
    def failing() -> list[Snapshot]:
        raise SnapshotError("no volume")

    page = new_client(tmp_path, snapshots=failing, rewinder=rewinder).get("/instantaneas").text
    assert "rewind-go" not in page
    assert "volumen" in text_of(page)


# -- the confirmation ----------------------------------------------------------------------------


def test_the_confirmation_shows_the_fixed_notice_and_rewinds_nothing(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    page = confirm(web)
    shown = text_of(page)
    for paragraph in rewind_notice(TARGET.taken_at, now=NOW, tz=UTC):
        assert paragraph in shown, paragraph
    assert 'lang="es"' in page, "the notice is Spanish, whatever the page's language"
    fields = form_of(page)
    assert set(fields) == {"id", "csrf", "ticket"}
    assert fields["id"] == TARGET.id
    assert re.search(
        rf'<form class="rewind-confirm" method="post" action="{PREFIX_PATH}{REWIND}"', page
    )
    assert rewinder.calls == []


def test_the_confirmation_in_english_keeps_the_notice_word_for_word(web: TestClient) -> None:
    page = confirm(web, **{"accept-language": "en"})
    assert "Rewind to" in page
    assert rewind_notice(TARGET.taken_at, now=NOW, tz=UTC)[1] in text_of(page)


def test_htmx_gets_the_confirmation_as_a_fragment(web: TestClient) -> None:
    page = confirm(web, **{"hx-request": "true"})
    assert "<html" not in page and "rewind-confirm" in page


def test_the_csrf_token_is_none_of_the_other_secrets(web: TestClient) -> None:
    fields = form_of(confirm(web))
    assert len(fields["csrf"]) >= 40 and len(fields["ticket"]) >= 40
    assert fields["csrf"] not in {SESSION, TOKEN} and fields["ticket"] not in {SESSION, TOKEN}
    assert form_of(confirm(web))["csrf"] == fields["csrf"], "one per session"
    assert form_of(confirm(web))["ticket"] != fields["ticket"], "one per confirmation"


@pytest.mark.parametrize("snapshot_id", ["", "latest", "../../etc", UNDO.id, TARGET.id + "x"])
def test_no_confirmation_for_what_is_not_in_the_list(web: TestClient, snapshot_id: str) -> None:
    page = confirm(web, snapshot_id)
    assert "rewind-confirm" not in page and "ticket" not in page
    assert "no está en la lista" in text_of(page)


@pytest.mark.parametrize("state", [Availability.NO_SERVICE, Availability.OTHER_USER])
def test_no_confirmation_when_the_service_cannot_be_asked(
    web: TestClient, rewinder: FakeRewinder, state: Availability
) -> None:
    rewinder.state = state
    page = confirm(web)
    assert "rewind-confirm" not in page and "ticket" not in page


def test_the_confirmation_needs_the_session(tmp_path: Path) -> None:
    web = new_client(tmp_path, logged_in=False, snapshots=lambda: SNAPS, rewinder=FakeRewinder())
    assert web.get(f"{REWIND}?id={TARGET.id}").status_code == 401


# -- the rewind ----------------------------------------------------------------------------------


def test_confirming_rewinds_once_and_shows_the_undo_point(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    response = post(web, form_of(confirm(web)))
    assert response.status_code == 200, response.text[:400]
    assert rewinder.calls == [TARGET.id]
    page = response.text
    assert 'data-outcome="done"' in page
    assert f'data-rewind-to="{TARGET.taken_at.isoformat()}"' in page
    assert "El agente está en marcha otra vez" in text_of(page)
    undo_link = f"{PREFIX_PATH}{REWIND}?id={UNDO.id}"
    assert html_lib.unescape(page).count(undo_link) == 1, "the way back is one click away"


def test_htmx_gets_the_result_as_a_fragment(web: TestClient) -> None:
    page = post(web, form_of(confirm(web)), **{"hx-request": "true"}).text
    assert "<html" not in page and 'data-outcome="done"' in page


def test_a_confirmation_works_once(web: TestClient, rewinder: FakeRewinder) -> None:
    fields = form_of(confirm(web))
    assert post(web, fields).status_code == 200
    again = post(web, fields)
    assert again.status_code == 400 and rewinder.calls == [TARGET.id]
    assert "ya se ha usado" in text_of(again.text), "used, not expired: it says where to look"


def test_an_unknown_or_old_confirmation_is_expired(
    web: TestClient, rewinder: FakeRewinder, clock: Clock
) -> None:
    fields = form_of(confirm(web))
    clock.now += timedelta(minutes=11)
    assert "ya no vale" in text_of(post(web, fields).text)
    assert "ya no vale" in text_of(post(web, {**fields, "ticket": "x" * 43}).text)
    assert rewinder.calls == []


def test_a_double_submit_while_the_first_runs_says_so(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    """Without JavaScript nothing disables the button: a second click sends the same ticket
    while the first rewind runs. It must not say "expired", and must rewind once."""
    rewinder.gate = threading.Event()
    fields = form_of(confirm(web))
    results: list[int] = []

    def first() -> None:
        results.append(post(web, fields).status_code)

    thread = threading.Thread(target=first)
    thread.start()
    try:
        assert rewinder.entered.wait(10)
        again = post(web, fields)
        assert again.status_code == 400
        assert "ya se ha usado" in text_of(again.text)
        other = post(web, {**fields, "ticket": "y" * 43})  # a ticket nobody issued, meanwhile
        assert other.status_code == 409 and "Ya hay un rebobinado en marcha" in text_of(other.text)
    finally:
        rewinder.gate.set()
        thread.join(10)
    assert results == [200] and rewinder.calls == [TARGET.id]


def test_two_posts_of_one_ticket_at_once_rewind_once(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    fields = form_of(confirm(web))
    start = threading.Barrier(2)
    codes: list[int] = []

    def send() -> None:
        start.wait(5)
        codes.append(post(web, fields).status_code)

    threads = [threading.Thread(target=send) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert sorted(codes) == [200, 400]
    assert rewinder.calls == [TARGET.id]


def test_a_confirmation_expires(web: TestClient, rewinder: FakeRewinder, clock: Clock) -> None:
    fields = form_of(confirm(web))
    clock.now += timedelta(minutes=11)
    assert post(web, fields).status_code == 400
    assert rewinder.calls == []


def test_a_confirmation_is_for_one_snapshot_only(web: TestClient, rewinder: FakeRewinder) -> None:
    fields = form_of(confirm(web, SNAPS[1].id))
    assert post(web, {**fields, "id": TARGET.id}).status_code == 400
    assert post(web, fields).status_code == 400, "a ticket shown with the wrong id is spent"
    assert rewinder.calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"csrf": "wrong"},
        {"csrf": ""},
        {"ticket": "wrong"},
        {"ticket": SESSION},
        {"csrf": SESSION},
        {"csrf": TOKEN},
    ],
)
def test_a_wrong_token_rewinds_nothing(
    web: TestClient, rewinder: FakeRewinder, change: dict[str, str]
) -> None:
    fields = form_of(confirm(web))
    assert post(web, {**fields, **change}).status_code in {400, 403}
    assert rewinder.calls == []


@pytest.mark.parametrize("drop", ["id", "csrf", "ticket"])
def test_a_missing_field_rewinds_nothing(
    web: TestClient, rewinder: FakeRewinder, drop: str
) -> None:
    fields = form_of(confirm(web))
    del fields[drop]
    assert post(web, fields).status_code == 400
    assert rewinder.calls == []


def test_extra_or_repeated_fields_rewind_nothing(web: TestClient, rewinder: FakeRewinder) -> None:
    fields = form_of(confirm(web))
    assert post(web, {**fields, "extra": "1"}).status_code == 400
    body = urlencode([*fields.items(), ("id", SNAPS[1].id)])
    repeated = web.post(
        REWIND,
        content=body,
        headers={**POST_HEADERS, "content-type": "application/x-www-form-urlencoded"},
    )
    assert repeated.status_code == 400
    assert rewinder.calls == []


def test_an_id_that_left_the_list_is_not_rewound(
    web: TestClient, rewinder: FakeRewinder, listed: list[Snapshot]
) -> None:
    fields = form_of(confirm(web))
    listed.remove(TARGET)  # pruned between the confirmation and the click
    response = post(web, fields)
    assert response.status_code == 400 and rewinder.calls == []


def test_an_unreadable_list_rewinds_nothing(tmp_path: Path, rewinder: FakeRewinder) -> None:
    state = {"fail": False}

    def snapshots() -> list[Snapshot]:
        if state["fail"]:
            raise SnapshotError("gone")
        return SNAPS

    web = new_client(tmp_path, snapshots=snapshots, rewinder=rewinder, clock=lambda: NOW)
    fields = form_of(confirm(web))
    state["fail"] = True
    assert post(web, fields).status_code in {400, 503}
    assert rewinder.calls == []


def test_without_the_session_cookie_nothing_rewinds(tmp_path: Path, rewinder: FakeRewinder) -> None:
    web = new_client(tmp_path, snapshots=lambda: SNAPS, rewinder=rewinder, clock=lambda: NOW)
    fields = form_of(confirm(web))
    web.cookies.clear()
    assert post(web, fields).status_code == 401
    # the link's token is no way in for a POST either
    assert web.post(f"{REWIND}?t={TOKEN}", data=fields, headers=POST_HEADERS).status_code == 401
    assert rewinder.calls == []


def test_the_service_gone_between_confirming_and_clicking_rewinds_nothing_here(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    fields = form_of(confirm(web))
    rewinder.state = Availability.NO_SERVICE
    response = post(web, fields)
    assert response.status_code == 503 and rewinder.calls == []
    assert "backtide vigilar" in text_of(response.text)


def test_nobody_at_the_socket_is_said_and_nothing_is_done_in_process(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    rewinder.error = ControlUnavailable("nadie")
    response = post(web, form_of(confirm(web)))
    assert response.status_code == 503
    assert 'data-outcome="no_service"' in response.text
    assert "backtide vigilar" in text_of(response.text)


def test_a_lost_reply_is_unknown_not_failed(web: TestClient, rewinder: FakeRewinder) -> None:
    rewinder.error = ControlOutcomeUnknown("perdida")
    page = post(web, form_of(confirm(web))).text
    assert 'data-outcome="unknown"' in page
    assert "No se sabe si se ha rebobinado" in text_of(page)


def test_a_service_that_cannot_be_trusted_gets_nothing(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    rewinder.error = ControlError("otro usuario <b>")
    page = post(web, form_of(confirm(web))).text
    assert 'data-outcome="untrusted"' in page
    assert "<b>" not in page


@pytest.mark.parametrize(
    ("outcome", "ok", "says"),
    [
        ("failed", False, "No se ha rebobinado"),
        ("problem", True, "algo ha fallado después"),
        ("unknown", False, "No se sabe si se ha rebobinado"),
        ("refused", False, "no ha aceptado"),
        ("invalid", False, "no ha aceptado"),
    ],
)
def test_every_outcome_is_said_and_the_service_message_is_escaped(
    web: TestClient, rewinder: FakeRewinder, outcome: str, ok: bool, says: str
) -> None:
    rewinder.reply = {
        "ok": ok,
        "outcome": outcome,
        "undo": UNDO.id if ok else None,
        "message": "Detalle <img src=x onerror=alert(1)>",
        "agent_started": False,
    }
    page = post(web, form_of(confirm(web))).text
    assert f'data-outcome="{outcome}"' in page
    assert says in text_of(page)
    assert "<img" not in page and "Detalle" in page
    assert ("rebobinar?id=" + UNDO.id in page) is ok


def test_an_undo_point_that_is_not_a_snapshot_id_is_not_linked(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    rewinder.reply = {**rewinder.reply, "undo": "../../x"}
    page = post(web, form_of(confirm(web))).text
    assert "../../x" not in page
    assert "No se ha podido guardar un punto para deshacer" in text_of(page)


def test_one_rewind_at_a_time(web: TestClient, rewinder: FakeRewinder) -> None:
    rewinder.gate = threading.Event()
    first_fields, second_fields = form_of(confirm(web)), form_of(confirm(web, SNAPS[1].id))
    results: list[int] = []
    first = threading.Thread(target=lambda: results.append(post(web, first_fields).status_code))
    first.start()
    try:
        assert rewinder.entered.wait(10)
        second = post(web, second_fields)
        assert second.status_code == 409
        assert "Ya hay un rebobinado en marcha" in text_of(second.text)
    finally:
        rewinder.gate.set()
        first.join(10)
    assert results == [200]
    assert rewinder.calls == [TARGET.id]
    # once it is over, the next one goes through
    assert post(web, form_of(confirm(web, SNAPS[1].id))).status_code == 200


# -- the guard in front of the POST --------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"origin": ""},  # dropped below: no Origin at all
        {"origin": "https://evil.example"},
        {"origin": "null"},
        {"origin": f"http://localhost:{ROOT.rsplit(':', 1)[1]}"},
        {"origin": f"http://127.0.0.1:{int(ROOT.rsplit(':', 1)[1]) + 1}"},  # another local program
        {"origin": f"{ROOT}, {ROOT}"},
        {"sec-fetch-site": "same-site"},
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "none"},
        {"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate"},
    ],
)
def test_a_post_that_is_not_from_our_own_page_is_refused(
    web: TestClient, rewinder: FakeRewinder, headers: dict[str, str]
) -> None:
    fields = form_of(confirm(web))
    sent = {**POST_HEADERS, **headers}
    if not sent["origin"]:
        del sent["origin"]
    response = web.post(REWIND, data=fields, headers=sent)
    assert response.status_code == 403
    assert rewinder.calls == []


def test_the_form_without_javascript_is_a_navigation_with_our_origin(
    web: TestClient, rewinder: FakeRewinder
) -> None:
    """What a browser sends for the plain form POST (no HTMX): a navigation, same-origin, and,
    with ``Referrer-Policy: same-origin``, our Origin. It rewinds; the same with Origin null
    (what no-referrer would make the browser send) does not."""
    page = web.get(f"{REWIND}?id={TARGET.id}")
    assert page.headers["referrer-policy"] == "same-origin"
    navigation = {"sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate"}
    refused = web.post(REWIND, data=form_of(page.text), headers={**navigation, "origin": "null"})
    assert refused.status_code == 403 and rewinder.calls == []
    done = web.post(REWIND, data=form_of(confirm(web)), headers={**navigation, "origin": ROOT})
    assert done.status_code == 200 and "<html" in done.text
    assert rewinder.calls == [TARGET.id]


@pytest.mark.parametrize(
    "content_type", ["text/plain", "multipart/form-data; boundary=x", "application/json", ""]
)
def test_only_a_plain_form_is_accepted(
    web: TestClient, rewinder: FakeRewinder, content_type: str
) -> None:
    body = urlencode(form_of(confirm(web)))
    response = web.post(
        REWIND, content=body, headers={**POST_HEADERS, "content-type": content_type}
    )
    assert response.status_code == 415
    assert rewinder.calls == []


def guard_status(headers: list[tuple[bytes, bytes]]) -> int:
    """The Guard alone, with a hand-built scope: what an HTTP parser might let through."""
    import asyncio

    from backtide.web.security import Guard

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 299, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    guard = Guard(inner, port=int(ROOT.rsplit(":", 1)[1]), prefix=PREFIX_PATH.removeprefix("/s/"))
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": f"{PREFIX_PATH}{REWIND}",
        "raw_path": f"{PREFIX_PATH}{REWIND}".encode(),
        "query_string": b"",
        "headers": [
            (b"host", ROOT.removeprefix("http://").encode()),
            (b"origin", ROOT.encode()),
            (b"sec-fetch-site", b"same-origin"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            *headers,
        ],
    }
    asyncio.run(guard(scope, receive, send))
    return sent[0]["status"]


def test_the_guard_lets_a_plain_small_form_through() -> None:
    assert guard_status([(b"content-length", b"5")]) == 299


@pytest.mark.parametrize(
    "headers",
    [
        [],  # no Content-Length
        [(b"transfer-encoding", b"chunked")],
        [(b"transfer-encoding", b"chunked"), (b"content-length", b"5")],
        [(b"content-length", b"+5")],
        [(b"content-length", b" 5")],
        [(b"content-length", "٥".encode())],
        [(b"content-length", b"5"), (b"content-length", b"5")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"99999999999999999999")],
        [(b"content-length", b"0x5")],
    ],
)
def test_the_guard_wants_one_plain_content_length(headers: list[tuple[bytes, bytes]]) -> None:
    assert guard_status(headers) in {411, 413}


def test_a_big_body_is_refused_before_it_is_read(web: TestClient, rewinder: FakeRewinder) -> None:
    fields = {**form_of(confirm(web)), "pad": "x" * 10_000}
    assert post(web, fields).status_code == 413
    assert rewinder.calls == []


@pytest.mark.parametrize("path", ["/instantaneas", "/ahora", "/instantaneas/rebobinar/", "/"])
def test_every_other_path_stays_get_only(web: TestClient, path: str) -> None:
    response = web.post(path, data={"id": TARGET.id}, headers=POST_HEADERS)
    assert response.status_code == 405


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_the_rewind_path_takes_no_other_method(web: TestClient, method: str) -> None:
    assert web.request(method, REWIND, headers=POST_HEADERS).status_code == 405


def test_a_post_under_another_prefix_finds_nothing(web: TestClient, rewinder: FakeRewinder) -> None:
    fields = form_of(confirm(web))
    other = TestClient(web.app, base_url=f"{ROOT}/s/another")
    other.cookies.set("backtide_web", SESSION, domain="127.0.0.1", path="/s/another")
    assert other.post(REWIND, data=fields, headers=POST_HEADERS).status_code in {404, 405}
    assert rewinder.calls == []


# -- ControlRewinder: availability and the real socket -------------------------------------------


@pytest.fixture
def folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vw"))
    path.chmod(0o700)
    yield path
    path.chmod(0o700)
    shutil.rmtree(path, ignore_errors=True)


def me(sock: object) -> tuple[int, int, int]:
    return 4242, os.geteuid(), 0


class FakeGuardian:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def rewind(self, snapshot_id: str, *, requested_by: str) -> RewindOutcome:
        self.calls.append((snapshot_id, requested_by))
        return RewindOutcome(
            RewindStatus.DONE, target=snapshot_id, message="Hecho.", undo=UNDO.id, request_id="r"
        )

    def resume(self, *, requested_by: str) -> ResumeOutcome:
        raise AssertionError("not used")


def test_without_the_flag_the_web_only_watches(folder: Path) -> None:
    """`backtide web` without --rebobinar: never asks, even as the service's user with the service
    up (writes are explicit). It does not even look at the socket."""
    guardian = FakeGuardian()
    server = ControlServer(guardian, folder / "control.sock", peer=me)
    server.start()
    try:
        assert ControlRewinder(folder / "control.sock").availability() is Availability.DISABLED
        assert (
            ControlRewinder(folder / "control.sock", enabled=False).availability()
            is Availability.DISABLED
        )
    finally:
        server.close()


def test_a_disabled_web_says_how_to_enable_it(web: TestClient, rewinder: FakeRewinder) -> None:
    rewinder.state = Availability.DISABLED
    page = web.get("/instantaneas").text
    assert "rewind-go" not in page and "--rebobinar" in text_of(page)
    assert "rewind-confirm" not in confirm(web)


def test_no_socket_in_our_folder_means_no_service(folder: Path) -> None:
    assert (
        ControlRewinder(folder / "control.sock", enabled=True).availability()
        is Availability.NO_SERVICE
    )


def test_a_folder_of_another_user_is_other_user(folder: Path) -> None:
    rewinder = ControlRewinder(folder / "control.sock", enabled=True, euid=lambda: os.geteuid() + 1)
    assert rewinder.availability() is Availability.OTHER_USER


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any folder")
def test_a_folder_we_cannot_look_into_is_other_user(folder: Path) -> None:
    inner = folder / "state"
    inner.mkdir(mode=0o700)
    inner.chmod(0)
    try:
        assert (
            ControlRewinder(inner / "control.sock", enabled=True).availability()
            is Availability.OTHER_USER
        )
    finally:
        inner.chmod(0o700)


def test_something_else_where_the_socket_should_be_is_off(folder: Path) -> None:
    (folder / "control.sock").write_text("not a socket")
    assert ControlRewinder(folder / "control.sock", enabled=True).availability() is Availability.OFF
    (folder / "control.sock").unlink()
    (folder / "control.sock").symlink_to(folder / "elsewhere.sock")
    assert ControlRewinder(folder / "control.sock", enabled=True).availability() is Availability.OFF


def test_through_the_real_socket_the_service_hears_it_is_the_web(
    folder: Path, tmp_path: Path
) -> None:
    guardian = FakeGuardian()
    server = ControlServer(guardian, folder / "control.sock", peer=me)
    server.start()
    try:
        rewinder = ControlRewinder(folder / "control.sock", enabled=True, peer=me)
        assert rewinder.availability() is Availability.READY
        assert (
            ControlRewinder(
                folder / "control.sock", enabled=True, euid=lambda: os.geteuid() + 1
            ).availability()
            is Availability.OTHER_USER
        )
        new_box(tmp_path)
        web = new_client(tmp_path, snapshots=lambda: SNAPS, rewinder=rewinder, clock=lambda: NOW)
        page = post(web, form_of(confirm(web))).text
    finally:
        server.close()
    assert 'data-outcome="done"' in page
    assert guardian.calls == [(TARGET.id, f"web (uid {os.geteuid()}, pid 4242)")]
    assert (
        ControlRewinder(folder / "control.sock", enabled=True).availability()
        is Availability.NO_SERVICE
    )


# -- tickets on their own ------------------------------------------------------------------------


def test_tickets_are_bounded_and_the_oldest_goes_first() -> None:
    tickets = Tickets(lambda: NOW, limit=3)
    issued = [tickets.issue(TARGET.id) for _ in range(5)]
    assert tickets.redeem(issued[0], TARGET.id) is Redeemed.INVALID
    assert tickets.redeem(issued[1], TARGET.id) is Redeemed.INVALID
    assert all(tickets.redeem(t, TARGET.id) is Redeemed.OK for t in issued[2:])
    assert all(tickets.redeem(t, TARGET.id) is Redeemed.SPENT for t in issued[2:])


def test_a_spent_ticket_is_forgotten_when_it_would_have_expired() -> None:
    clock = Clock()
    tickets = Tickets(clock)
    ticket = tickets.issue(TARGET.id)
    assert tickets.redeem(ticket, TARGET.id) is Redeemed.OK
    assert tickets.redeem(ticket, TARGET.id) is Redeemed.SPENT
    clock.now += timedelta(minutes=11)
    assert tickets.redeem(ticket, TARGET.id) is Redeemed.INVALID
