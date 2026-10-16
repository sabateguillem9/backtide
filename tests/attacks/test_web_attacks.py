"""Evil-agent scenario against whoever reads the black box (T12): the web.

The agent, inside its jail, names files so that a page showing them would run script, reorder
what the person reads, start a fake line, pile glyphs over the page or speak as Vigía. The real
service records them (the file watcher, the real OpenClaw), and the real web, reading that same
black box without its key, must show every one inert in "Ahora", in the live stream and in
"Historia".
"""

import re
import threading
import time
import warnings
from datetime import UTC

from attack_kit import Attack, scenario
from fastapi.testclient import TestClient

from tests.integration.service_kit import Service, wait_until
from tests.webkit import BASE, PREFIX_PATH, SESSION, parse_sse
from vigia.web import BoxReader, create_app

HOSTILE_DIR = "/workspace/work/hostile"
WITHIN = 30.0  # the watcher dumps every 2 s: this is generous for a loaded VM

# What must never reach a page as itself, however it is shown.
RAW = ("<img", "onerror=alert(1)>", "\u202e", "\u3164", "\u0301", "\r")


def web_for(service: Service, **options) -> TestClient:
    """The web of this service's black box: the file only, no key, as an ordinary viewer."""
    app = create_app(
        reader=BoxReader(service.config.blackbox_db),
        port=8765,
        token="t0ken-of-the-attack",  # noqa: S106 - a test value
        session=SESSION,
        prefix=PREFIX_PATH.removeprefix("/s/"),
        tz=UTC,
        **options,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        client = TestClient(app, base_url=BASE)
    client.cookies.set("vigia_web", SESSION, domain="127.0.0.1", path=PREFIX_PATH)
    return client


def inert(html: str, where: str) -> list[str]:
    """What is wrong with ``html`` (an empty list if every trick was neutralised)."""
    problems = [f"{where}: raw {item!r}" for item in RAW if item in html]
    if re.search(r"<script(?![^>]*\bsrc=)", html):  # (the page's own scripts all have a src)
        problems.append(f"{where}: an inline script element")
    # The sentence of Vigía's voice must only ever appear as a quoted name of the agent.
    # (The target and the JSON of Historia's details are labelled, not sentences: leave them out.)
    sentences = re.sub(r"<(dd|pre)[ >].*?</\1>", "", html, flags=re.S)
    voice = sentences.count("todo en orden")
    names = re.findall(
        r'<span class="name">((?:[^<]|<span class="esc"[^>]*>[^<]*</span>)*)</span>', sentences
    )
    quoted = sum(name.count("todo en orden") for name in names)
    if voice != quoted:
        problems.append(f"{where}: 'todo en orden' outside a name ({voice} vs {quoted})")
    if "U+202E" not in html:
        problems.append(f"{where}: the bidi override is not shown")
    if not re.search(r"U\+0301×\d+", html):
        problems.append(f"{where}: the tower of marks is not one marker")
    if "U+3164" not in html:
        problems.append(f"{where}: the blank letter is not shown")
    if "U+000D" not in html or "U+000A" not in html:
        problems.append(f"{where}: the line break is not shown")
    if "&lt;img src=x onerror=alert(1)&gt;" not in html:
        problems.append(f"{where}: the markup is not escaped text")
    return problems


@scenario("nombres-hostiles-en-la-web")
def test_hostile_names_are_inert_in_the_web(attack: Attack, real_service: Service) -> None:
    jail = real_service.jail
    before = real_service.box.head()
    seq_before = before[0] if before else 0

    outcome = attack.run_script(jail, "nombres_hostiles_en_la_web", HOSTILE_DIR)
    made = outcome["made"]
    attack.check(
        "stopped",
        len(made) == 8 and not outcome["errors"],
        f"the agent created all eight hostile names (nothing can forbid a name): {sorted(made)}",
    )

    # Recorded: the watcher turns them into file events of the black box.
    def recorded() -> bool:
        targets = [e.target for e in real_service.events(source="file") if e.seq > seq_before]
        return all(any(name in target for target in targets) for name in (made["voice"],))

    wait_until(
        recorded, WITHIN, "the file events of the hostile names", context=real_service.diagnosis
    )
    real_service.freeze()  # whatever else OpenClaw would write from here on is not ours
    time.sleep(3)  # the last dump of the watcher
    events = [e for e in real_service.events(source="file") if e.seq > seq_before]

    web = web_for(real_service)
    problems: list[str] = []

    now = web.get("/ahora")
    assert now.status_code == 200, now.text[:300]
    problems += inert(now.text, "Ahora")

    # The live stream: connect at the point before the attack and read what it sends.
    live = web_for(real_service, stream_seconds=1.5, poll_interval=0.05)
    body = live.get(f"/ahora/stream?after={seq_before}").text
    streamed = "".join(e.get("data", "") for e in parse_sse(body) if e.get("event") == "lines")
    problems += inert(streamed, "stream")

    # A stream open BEFORE the names appear gets them live too (the writer is the real agent).
    ahead = web_for(real_service, stream_seconds=6.0, poll_interval=0.05)
    seen: dict[str, str] = {}
    head = real_service.box.head()
    mark = head[0] if head else 0

    def read_stream() -> None:
        seen["body"] = ahead.get(f"/ahora/stream?after={mark}").text

    reader_thread = threading.Thread(target=read_stream)
    reader_thread.start()
    time.sleep(0.5)
    jail.exec(["sh", "-c", f"touch '{HOSTILE_DIR}/live-<b>x</b>‮exe'"])
    reader_thread.join(20)
    live_html = "".join(
        e.get("data", "") for e in parse_sse(seen.get("body", "")) if e.get("event") == "lines"
    )
    if "<b>" in live_html or "‮" in live_html:
        problems.append("stream (live): a name reached the page as itself")

    history = web.get("/historia?origen=file")
    assert history.status_code == 200, history.text[:300]
    problems += inert(history.text, "Historia")

    attack.check(
        "recorded",
        len(events) >= 1 and not problems,
        f"the real service recorded {len(events)} file events for the names, and the web showed "
        f"them inert in Ahora, the stream and Historia: {problems or 'nothing raw, all shown'}",
    )
