"""The live feed: Server-Sent Events polling the black box, opened read-only, for new events."""

import threading
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

from backtide.web.narrate import Narrator  # noqa: F401 - the stream folds with it
from tests.conftest import FakeClock
from tests.webkit import START, new_box, new_client, parse_sse


def stream(
    tmp_path: Path,
    query: str = "",
    *,
    seconds: float = 0.4,
    write: Callable[[], None] | None = None,
    delay: float = 0.1,
    headers: dict[str, str] | None = None,
    **options,
):
    """Run /ahora/stream for ``seconds`` while ``write`` appends to the box after ``delay``."""
    options.setdefault("poll_interval", 0.02)
    web = new_client(tmp_path, stream_seconds=seconds, **options)
    writer = None
    if write is not None:

        def later() -> None:
            time.sleep(delay)
            write()

        writer = threading.Thread(target=later)
        writer.start()
    response = web.get(f"/ahora/stream{query}", headers=headers)
    if writer is not None:
        writer.join()
    assert response.status_code == 200
    return parse_sse(response.text)


def of_kind(events: list[dict[str, str]], kind: str) -> list[dict[str, str]]:
    return [e for e in events if e.get("event") == kind]


def test_new_events_arrive_as_html_lines_with_their_seq_as_id(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    box.append("system", "service_stop", "")  # the page already showed these two

    def write() -> None:
        box.append("file", "create", "notas.md")
        box.append("system", "log", "something")

    events = stream(tmp_path, "?after=2", write=write)
    assert events[0] == {"retry": "2000"}
    lines = of_kind(events, "lines")
    html = "\n".join(e["data"] for e in lines)
    assert "Ha creado" in html and ">notas.md<" in html
    assert "Aviso de backtide" in html
    assert "El agente ha arrancado" not in html and "backtide se ha parado" not in html
    assert lines[-1]["id"] == "4"


def test_nothing_is_repeated_between_polls(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    events = stream(tmp_path, "?after=1", write=lambda: box.append("system", "log", "once"))
    html = "".join(e["data"] for e in of_kind(events, "lines"))
    assert html.count('id="l-2"') == 1


def test_a_deletion_burst_grows_in_place_instead_of_adding_lines(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")

    def write() -> None:
        for i in range(3):
            box.append("file", "delete", f"f{i}.txt")
        time.sleep(0.2)  # a later poll
        for i in range(3, 10):
            box.append("file", "delete", f"f{i}.txt")

    events = stream(tmp_path, "?after=1", write=write, seconds=1.0)
    lines = [e["data"] for e in of_kind(events, "lines")]
    assert len(lines) >= 2
    assert 'id="l-2"' in lines[0] and "hx-swap-oob" not in lines[0]
    assert "Ha borrado" in lines[0]
    assert 'id="l-2" hx-swap-oob="true"' in lines[-1]  # the same line, replaced
    assert "Ha borrado 10 archivos, entre ellos" in lines[-1]
    assert ">f0.txt<" in lines[-1]


def test_a_burst_the_page_ended_on_keeps_growing_after_the_stream_connects(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    for i in range(5):
        box.append("file", "delete", f"f{i}.txt")  # the page folded these into line l-1

    events = stream(tmp_path, "?after=5", write=lambda: box.append("file", "delete", "f5.txt"))
    html = "".join(e["data"] for e in of_kind(events, "lines"))
    assert 'id="l-1" hx-swap-oob="true"' in html and "Ha borrado 6 archivos" in html


def test_the_state_follows_the_agent(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")

    def write() -> None:
        box.append("system", "space_pause", "", details={"frozen": True}, risk=2)

    events = stream(tmp_path, "?after=1", write=write)
    (state,) = of_kind(events, "state")
    assert "congelado" in state["data"] and "st-frozen" in state["data"]


def test_the_tide_follows_the_snapshots(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    take = "20261016T100001.000000Z-periodic"
    events = stream(
        tmp_path,
        "?after=1",
        write=lambda: box.append("snapshot", "take", take, snapshot_id=take),
        clock=lambda: START + timedelta(minutes=1),
    )
    tides = of_kind(events, "tide")
    assert tides and 'class="tide-mark"' in tides[-1]["data"]
    assert "Instantáneas de las últimas 24 horas: 1." in tides[-1]["data"]


def test_last_event_id_wins_over_the_address_when_the_browser_reconnects(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    for i in range(6):
        box.append("system", "log", f"n{i}")
    events = stream(
        tmp_path,
        "?after=1",
        write=lambda: box.append("system", "log", "n6"),
        headers={"last-event-id": "6"},
    )
    html = "".join(e["data"] for e in of_kind(events, "lines"))
    assert html.count('class="line') == 1 and 'id="l-7"' in html


def test_a_page_that_saw_nothing_starts_near_the_end_of_a_long_box(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    for i in range(200):
        box.append("system", "log", f"n{i}")
    events = stream(tmp_path, "?after=0")
    html = "".join(e["data"] for e in of_kind(events, "lines"))
    assert html.count('class="line') == 60
    assert 'id="l-200"' in html and 'id="l-141"' in html and 'id="l-140"' not in html


def test_junk_in_after_and_last_event_id_is_zero(tmp_path: Path) -> None:
    new_box(tmp_path).append("system", "log", "x")
    web = new_client(tmp_path, stream_seconds=0.1, poll_interval=0.02)
    for query, headers in (
        ("?after=abc", {}),
        ("?after=-5", {}),
        ("", {"last-event-id": "x" * 40}),
    ):
        response = web.get(f"/ahora/stream{query}", headers=headers)
        assert response.status_code == 200


def test_an_idle_stream_sends_a_keepalive_and_ends_on_time(tmp_path: Path) -> None:
    new_box(tmp_path).append("system", "log", "x")
    started = time.monotonic()
    events = stream(tmp_path, "?after=1", seconds=0.5, keepalive=0.1)
    assert time.monotonic() - started < 3
    assert any(e.get("comment") == "keepalive" for e in events)
    assert not of_kind(events, "lines")


def test_hostile_names_in_the_stream_are_inert(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    nasty = "</div><script>alert(1)</script>‮\n\r\ndata: injected\n\nevent: x"

    def write() -> None:
        box.append("file", "create", nasty)

    events = stream(tmp_path, "?after=0&x=1", write=write, delay=0.1)
    raw = "".join(e.get("data", "") for e in events)
    assert "<script>" not in raw and "‮" not in raw
    assert "&lt;script&gt;" in raw and "U+202E" in raw and "U+000A" in raw
    # a line break in a name must not start a new SSE field
    assert not any(
        e.get("event") == "x" or e.get("data", "").startswith("injected") for e in events
    )
    assert {e["event"] for e in events if "event" in e} <= {"lines", "state", "tide"}


def test_a_box_that_appears_later_is_picked_up(tmp_path: Path) -> None:
    def write() -> None:
        new_box(tmp_path).append("system", "agent_start", "")

    events = stream(tmp_path, "?after=0", write=write, delay=0.3, seconds=1.2)
    assert any("El agente ha arrancado" in e["data"] for e in of_kind(events, "lines"))


def test_a_missing_box_does_not_break_the_stream(tmp_path: Path) -> None:
    events = stream(tmp_path, "?after=0", seconds=0.3)
    assert not of_kind(events, "lines") and not of_kind(events, "state")


def test_the_stream_never_writes_to_the_box(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("system", "agent_start", "")
    before = box.head()
    stream(tmp_path, "?after=1", seconds=0.3)
    assert box.head() == before


def test_each_event_in_a_burst_across_many_polls_ends_with_one_line(tmp_path: Path) -> None:
    box = new_box(tmp_path, FakeClock(START))

    def write() -> None:
        for _ in range(30):
            box.append("file", "modify", "same.txt")
            time.sleep(0.01)

    events = stream(tmp_path, "?after=0", write=write, delay=0.05, seconds=1.0)
    html = "".join(e["data"] for e in of_kind(events, "lines"))
    assert "Ha modificado 30 archivos, entre ellos" in html  # grown in place, up to the end
    assert html.count('id="l-1"') >= 2 and html.count('id="l-2"') == 0
