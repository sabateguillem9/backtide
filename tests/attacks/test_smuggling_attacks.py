"""Evil-agent scenario of the h2-to-h1 request smuggling the security review of T11 found
(docs/incidentes.md 2026-10-22). The lab is test_proxy_attacks.py's: the real service, the real
proxy and the real OpenClaw jail, with T06's fake internet (every server offers only the
``http/1.1`` ALPN, so the proxy always speaks HTTP/1.1 upstream).

- ``contrabando-h2``: the agent sends an HTTP/2 POST to an allowed host whose body is itself a
  raw HTTP/1.1 DELETE to ``/T-H2-SMUGGLED``. Over HTTP/2 the body has no Content-Length. The
  gate now adds it before recording, so on approval the whole body reaches the server framed as
  the POST's body; the smuggled DELETE never becomes a second request, and the server logs no
  ``/T-H2-SMUGGLED``. The cover POST is held like any write and goes out only once approved.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from attack_kit import Attack, scenario
from test_proxy_attacks import Lab, new_tag, start_lab, ts

from backtide.blackbox import Event
from tests.integration.internet_kit import PLAIN_HOST, stop_with_internet
from tests.integration.service_kit import run_cli, wait_until

# A hold that lives long enough to approve by hand (life, wait, preapproval, remember).
TIMINGS = ("--hold-timings", "60,40,60,60")
SMUGGLED_PATH = "/T-H2-SMUGGLED"


@pytest.fixture(scope="module")
def lab(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    started = start_lab(btrfs_volume, tmp_path_factory, hold_timings=TIMINGS)
    try:
        yield started
    finally:
        stop_with_internet(started.service, started.internet)


def held_at(lab: Lab, path: str, after: int) -> Event:
    found: list[Event] = []

    def look() -> bool:
        found[:] = [
            e
            for e in lab.service.events("held", "gate")
            if e.details.get("path") == path and e.seq > after
        ]
        return bool(found)

    wait_until(look, 30, f"{path} to be held", context=lab.service.diagnosis)
    return found[-1]


def arrived(lab: Lab, path: str) -> list[dict]:
    return [r for r in lab.internet.requests(PLAIN_HOST) if r["path"] == path]


@scenario("contrabando-h2")
def test_an_h2_body_cannot_smuggle_a_second_request(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    cover = f"/{tag}/comments"
    smuggled = f"DELETE {SMUGGLED_PATH} HTTP/1.1\r\nHost: {PLAIN_HOST}\r\nContent-Length: 0\r\n\r\n"
    before = lab.head()
    smuggled_before = arrived(lab, SMUGGLED_PATH)

    def send() -> dict:
        return attack.run_script(lab.agent, "contrabando_h2", PLAIN_HOST, cover, smuggled, "15")

    # Over HTTP/2 the gate answers a held write "pending" (429) at once and keeps the hold; a yes
    # becomes a one-use preapproval that the identical retry spends (addon.py, review of T10-2).
    pending = send()
    held = held_at(lab, cover, before)
    hold_id = held.details["hold_id"]
    approval = run_cli(lab.service, "aprobar", hold_id)
    out = send()  # the same request again: preapproved, it goes out

    # LOW 1: a smuggled DELETE would arrive after the cover POST; a sentinel GET to the same path
    # (a read, never held) lets us wait until the server has processed that connection before we
    # count. If the smuggle had worked, the DELETE would already be in the log by then.
    sentinel = f"{SMUGGLED_PATH}?sentinel={tag}"
    lab.agent.exec(
        ["curl", "-sS", "--http2", "--max-time", "15", "-o", "/dev/null",
         f"https://{PLAIN_HOST}{sentinel}"],
        timeout=30,
    )  # fmt: skip
    wait_until(
        lambda: any(r["path"] == sentinel for r in lab.internet.requests(PLAIN_HOST)),
        20,
        "the sentinel GET to arrive",
        context=lab.service.diagnosis,
    )

    cover_reqs = arrived(lab, cover)
    smuggled_reqs = arrived(lab, SMUGGLED_PATH)
    # The sentinel is a GET to that path; a smuggled request would be the DELETE (any non-GET).
    new_smuggled = [r for r in smuggled_reqs[len(smuggled_before) :] if r["method"] != "GET"]
    request = next((e for e in lab.tagged(tag, "request") if e.details.get("path") == cover), None)
    received = (cover_reqs[-1]["headers"] if cover_reqs else {}) or {}
    # MEDIUM: the cover body left framed with a Content-Length the gate set (not chunked), so the
    # DELETE stayed inside it. If curl had sent its own Content-Length, _frame_h2_body would not
    # run and this would still hold; that curl sends none over h2+chunked is shown in
    # tests/integration/test_smuggling.py (before the fix the server saw body_size 0).
    framed = (
        received.get("content-length") == str(len(smuggled.encode()))
        and "transfer-encoding" not in received
    )
    # The gate's own recorded request carries the Content-Length it added, and no chunked framing.
    recorded_headers = dict(request.details.get("headers") or []) if request else {}
    recorded_cl = recorded_headers.get("content-length") == str(len(smuggled.encode()))

    attack.check(
        "stopped",
        new_smuggled == []
        and out.get("http_version") == "2"
        and framed
        and cover_reqs[-1]["body_size"] == len(smuggled.encode())
        and recorded_cl,
        f"la petición HTTP/2 ({out.get('http_version')}) llevaba en su cuerpo un DELETE a "
        f"{SMUGGLED_PATH}: el servidor (solo HTTP/1.1) no recibe ninguna petición distinta de "
        f"la centinela a esa ruta ({len(new_smuggled)}); el cuerpo entero llega enmarcado como "
        f"la POST de portada con Content-Length {received.get('content-length')} (de "
        f"{len(smuggled.encode())}) y sin transfer-encoding; la puerta grabó la petición con el "
        f"Content-Length que puso ({recorded_cl}); respuesta del agente {out}",
    )
    attack.check(
        "recorded",
        request is not None
        and held.seq < request.seq
        and ts(request) < (cover_reqs[-1]["at"] if cover_reqs else float("inf")),
        f"gate/held {held.seq} ({held.details.get('reason')}) y net/request "
        f"{request and request.seq} de la portada, grabados antes de que llegara al servidor",
    )
    attack.check(
        "risk",
        held.risk == 2,
        f"la POST de portada se retiene con riesgo {held.risk}",
    )
    attack.check(
        "held",
        approval.returncode == 0 and out.get("status") == 200 and bool(cover_reqs),
        f"la escritura HTTP/2 queda 'pendiente' ({pending.get('status')}) y se retiene hasta el "
        f"sí (`backtide aprobar` -> {approval.returncode}); el reintento sale, con estado "
        f"{out.get('status')}",
    )
