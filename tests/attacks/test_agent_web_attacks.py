"""T26-6b (invariants 1, 2, 6, 7): creating, starting, stopping and deleting agents from the web.

The real `backtide web`, not root and with the web's group, on the real narrow socket, under the
real unit, with two agents to begin with. Each scenario goes on from where the last left it, as an
owner would (the key comes last, because it asks for a touch from then on):

    make ataques PERFIL=claude-code ATK_PATH=tests/attacks/test_agent_web_attacks.py

Who may ask is decided in the service: what a web taken over would send goes straight to the socket,
with `_probe`. What a person does goes through the pages, with `web`. No model answers anything
(invariant 8): the key is made up, and the one turn given stops at the lab's cut.
"""

import json
import re
import secrets
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_agent_orders_attacks import (
    SOCKET,
    START_TIMEOUT,
    _running,
    listed,
    order,
    started_at,
    whats_there,
)
from test_two_agents_attacks import TASK_SECONDS, _probe, said_in
from test_web_socket_attacks import CHANGES_WAIT
from two_agents_kit import MAIN, OTHER, STATE, THIRD, Lab, Web, form_in, open_lab, sh, wait

from backtide.jail.profiles.claude_code import CLAUDE_CODE_VERSION
from backtide.service.config import STATE_DB, STATE_SOCKET
from backtide.web.i18n import ES
from backtide.web.live import ASK_EVERY

CONTROL = str(STATE / STATE_SOCKET)
KIND = f"Claude Code {CLAUDE_CODE_VERSION}"
GOOD = {"cmd": "agent_create", "slug": THIRD.slug, "profile": "claude-code", "volume_gib": 10}
MADE_UP = "s" * 43
QUICK = 15.0  # what a POST may take, with its agent's start still going: it never waits for it
THE_LIST = ASK_EVERY + 5  # the web asks the service every few seconds: what its list says by then
PROXY_SAID = "only ports 80 and 443"  # what the agent's own proxy answers to the web's port


@pytest.fixture(scope="module")
def lab() -> Iterator[Lab]:
    found = open_lab()
    try:
        yield found
    finally:
        found.close()


@pytest.fixture(scope="module")
def web(lab: Lab) -> Iterator[Web]:
    found = Web(lab)
    try:
        found.sign_in()
        yield found
    finally:
        found.close()


def nobody() -> int:
    return int(sh("id", "-u", "nobody").stdout)


def as_the_web(lab: Lab, *requests: dict[str, Any]) -> list[dict[str, Any]]:
    """With a live session, from a link root gave: what a web taken over with a session has."""
    token = lab.helper("link", SOCKET)["token"]
    opened, *said = _probe(
        nobody(), lab.web_gid, {"cmd": "session_open", "token": token}, *requests
    )
    assert opened["ok"] is True, {key: opened.get(key) for key in ("outcome", "ok")}
    return said


def signed(request: dict[str, Any]) -> dict[str, Any]:
    return {**request, "session": "<session>", "_why": True}


def path_of(sent: Any) -> str:
    """Where a POST sent the browser, under the web's prefix: its page of how it goes."""
    assert sent.status_code == 303, sent.text[:300]
    return "/agentes/" + sent.headers["location"].split("/agentes/", 1)[1]


def ended(web: Web, sent: Any, timeout: float = START_TIMEOUT) -> str:
    """The POST answered, with the order perhaps still running: the text of the page that says how
    it ended, which is only a page of the end."""
    path = path_of(sent)
    said = [""]

    def over() -> bool:
        page = web.get(path)
        said[0] = page.text
        return page.status_code == 200 and 'data-view="running"' not in page.text

    wait(over, timeout, "the order to end", lambda: said[0][-400:])
    assert 'data-view="result"' in said[0], said[0][-400:]
    return said[0]


def order_form(web: Web, verb: str, slug: str) -> dict[str, str]:
    page = web.get(f"/agentes/orden?v={verb}&agente={slug}")
    assert page.status_code == 200, page.text[:300]
    return form_in(page.text)


def ask(web: Web, verb: str, slug: str, **more: str) -> Any:
    return web.post("/agentes/orden", {**order_form(web, verb, slug), **more})


def row(web: Web, slug: str) -> str:
    """What the list says of one agent: its <li>."""
    text = web.get("/agentes").text
    start = text.find(f'data-agent="{slug}"')
    if start < 0:  # not on the list (yet): the callers wait, and the diagnosis says what there is
        return "<no row> " + " ".join(re.findall(r'data-agent="([^"]*)"', text))
    return text[start : text.index("</li>", start)]


def list_says(web: Web, slug: str, *words: str) -> str:
    """The row once it says all this: the web asks the service every few seconds."""
    wait(
        lambda: all(word in row(web, slug) for word in words),
        THE_LIST,
        f"the list to say {words} of {slug}",
        lambda: row(web, slug),
    )
    return row(web, slug)


def paused(container: str) -> bool:
    ran = sh("docker", "inspect", "--format", "{{.State.Paused}}", container)
    return ran.stdout.strip() == "true"


# --- who may ask --------------------------------------------------------------------------------


@scenario("crear-sin-sesion")
def test_without_a_session_the_web_creates_nothing(attack: Attack, lab: Lab) -> None:
    """A web taken over, on the real socket: no session, a made-up one and one that ended. The
    control is that the same order, with a live session, gets past the session."""
    before = whats_there(lab), len(lab.installation_events())
    bare = _probe(nobody(), lab.web_gid, {**GOOD, "_why": True})
    made_up = _probe(nobody(), lab.web_gid, {**GOOD, "session": MADE_UP, "_why": True})
    token = lab.helper("link", SOCKET)["token"]
    opened, closing, closed = _probe(
        nobody(), lab.web_gid,
        {"cmd": "session_open", "token": token},
        {"cmd": "session_end", "session": "<session>"},
        signed(GOOD),
    )  # fmt: skip
    assert opened["ok"] is True and closing["outcome"] == "ended", (opened, closing)
    # A size the disk has no room for: it stops at the machine's checks, past the session.
    [control] = as_the_web(lab, signed({**GOOD, "volume_gib": 50}))
    refused = [bare[0], made_up[0], closed]
    attack.check(
        "stopped",
        all(a["outcome"] == "refused" and "sesión viva" in a["why"] for a in refused)
        and control["outcome"] == "refused"
        and "disco" in control["why"]
        and (whats_there(lab), len(lab.installation_events())) == before,
        f"sin sesión, con una inventada y con una cerrada: {refused[0]}; con una viva llega a "
        f"mirar el disco ({control['why'][:60]}…), y nada cambia ni queda en la instalación",
    )


@scenario("crear-fuera-de-lista")
def test_a_web_taken_over_chooses_nothing_off_its_lists(attack: Attack, lab: Lab) -> None:
    """With a live session, so that the session is not what refuses. What root's socket does take
    (`restart`, a name, the caps) is here too: from the web there are three fields."""
    time.sleep(CHANGES_WAIT)  # the changes' bucket, whatever came before
    before = whats_there(lab), len(lab.installation_events())
    bad = [
        {**GOOD, "profile": "custom"},
        {**GOOD, "volume_gib": 7},
        {**GOOD, "slug": "../principal"},
        {**GOOD, "image": "alpine"},
        {**GOOD, "mounts": ["/etc:/host-etc"]},
        {**GOOD, "privileged": True},
        {**GOOD, "restart": True},
        {**GOOD, "name": "Otro", "memory": "4g"},
    ]
    said = as_the_web(lab, *(signed(request) for request in bad))
    attack.check(
        "stopped",
        len(said) == len(bad)
        and all(a["outcome"] == "invalid" and a["ok"] is False for a in said)
        and (whats_there(lab), len(lab.installation_events())) == before,
        f"las {len(bad)} órdenes dan `invalid` ({said[0]}), y `docker ps`, los archivos, los "
        "volúmenes y la caja de la instalación no cambian",
    )


# --- what a person does -------------------------------------------------------------------------


@scenario("crear-desde-la-web")
def test_the_owner_creates_an_agent_from_the_web(attack: Attack, lab: Lab, web: Web) -> None:
    """The criterion of T26-6b, up to the task: the form, its one-time ticket and a page that says
    how it went. The service is not restarted and the others do not notice."""
    pid, others = lab.show("MainPID"), (started_at(MAIN.container), started_at(OTHER.container))
    time.sleep(CHANGES_WAIT)
    fields = {"slug": THIRD.slug, "perfil": "claude-code", "tamano": "10"}
    form = form_in(web.get("/agentes/nuevo").text)
    forged = web.post("/agentes/crear", {**form, **fields, "csrf": "x" * 20})
    without_session = web.post("/agentes/crear", {**form, **fields}, signed_in=False)
    custom = web.post("/agentes/crear", {**form, **fields, "perfil": "custom"})
    same_form_again = form_in(custom.text)
    untouched = not _running(THIRD.container)
    said = ended(web, web.post("/agentes/crear", {**same_form_again, **fields}))
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    in_the_list = list_says(web, THIRD.slug, KIND, ES["agents.state.running"])
    attack.check(
        "stopped",
        forged.status_code == 403
        and without_session.status_code == 401
        and custom.status_code == 400
        and untouched
        and ES["agents.out.created"] in said
        and _running(THIRD.container)
        and lab.show("MainPID") == pid
        and (started_at(MAIN.container), started_at(OTHER.container)) == others
        and KIND in in_the_list
        and KIND in web.get("/panel").text,
        f"otra sesión {forged.status_code}, sin ella {without_session.status_code}, `custom` "
        f"{custom.status_code}, y nada creado; el formulario bueno lo crea y lo arranca, sin "
        f"reiniciar el servicio ni tocar a los otros, y la lista dice {KIND}",
    )
    created = lab.installation_events("agent_create")
    attack.check(
        "recorded",
        [event["target"] for event in created] == [THIRD.slug]
        and "web (uid" in created[0]["details"]["requested_by"]
        and lab.events(THIRD)[0]["action"] == "agent_created"
        and "web (uid" in lab.events(THIRD)[0]["details"]["requested_by"],
        "system/agent_create en la caja de la instalación y agent_created en la suya, cada uno con "
        f"«{created[0]['details']['requested_by']}», los ids del kernel",
    )


@scenario("tarea-en-marcha-en-la-lista")
def test_the_list_says_a_task_is_running_while_it_runs(attack: Attack, lab: Lab, web: Web) -> None:
    """D42. A task given on root's socket, as the CLI gives it: the list knows it because the
    service runs it. Its turn stops at the lab's cut, and its end is in the agent's box."""
    assert lab.network_cut(), "invariant 8: no turn of an agent without the lab's network cut"
    in_use = ES["agents.in_use.task"]
    before = in_use in row(web, THIRD.slug)
    mark = f"T26-6B-{secrets.token_hex(6)}"
    started = lab.helper("task", CONTROL, THIRD.slug, f"{mark} di hola")
    assert started["ok"], started
    task = started["task"]
    wait(
        lambda: in_use in row(web, THIRD.slug),
        TASK_SECONDS,
        "«Tarea en marcha» in the list",
        lab.diagnosis,
    )
    on_the_panel = in_use in web.get("/panel").text
    on_the_neighbour = in_use in row(web, OTHER.slug)
    wait(
        lambda: bool(said_in(lab.events(THIRD, "agent_task_end"), task)),
        TASK_SECONDS + START_TIMEOUT,
        "the end of the task",
        lab.diagnosis,
    )
    wait(lambda: in_use not in row(web, THIRD.slug), 30, "the list to say it ended", lab.diagnosis)
    attack.check(
        "recorded",
        not before
        and on_the_panel
        and not on_the_neighbour
        and bool(said_in(lab.events(THIRD, "agent_task_end"), task)),
        "«Tarea en marcha» en la lista y en el Panel mientras corre, solo en ese agente; deja de "
        "salir al acabar, y su caja tiene agent_task_end",
    )


@scenario("parar-desde-la-web")
def test_stopping_from_the_web_does_not_hang_nor_lie(attack: Attack, lab: Lab, web: Web) -> None:
    """A start takes its time: the POST answers at once, with the page saying so, and "parado" or
    "en marcha" come only from the service, once Docker says it. Freezing too. The main agent is
    not on the list, nor on the socket."""
    main = started_at(MAIN.container)
    time.sleep(CHANGES_WAIT)
    frozen_said = ended(web, ask(web, "pausar", THIRD.slug))
    was_frozen = paused(THIRD.container)
    thawed_said = ended(web, ask(web, "seguir", THIRD.slug))
    was_thawed = not paused(THIRD.container)
    said = ended(web, ask(web, "parar", THIRD.slug))
    gone = not _running(THIRD.container)
    stopped_row = list_says(web, THIRD.slug, ES["agents.state.stopped"], "v=arrancar")
    # And it starts again from the same list, without the POST waiting for it.
    form = order_form(web, "arrancar", THIRD.slug)
    begun = time.monotonic()
    sent = web.post("/agentes/orden", form)
    took = time.monotonic() - begun
    first = web.get(path_of(sent)).text
    back = ended(web, sent)
    list_says(web, THIRD.slug, ES["agents.state.running"])
    stop_main, freeze_main = as_the_web(
        lab,
        signed({"cmd": "agent_stop", "agent": MAIN.slug}),
        signed({"cmd": "agent_pause", "agent": MAIN.slug}),
    )
    holds = {
        "frozen_said": ES["agents.out.frozen"] in frozen_said,
        "was_frozen": was_frozen,
        "resumed_said": ES["agents.out.resumed"] in thawed_said,
        "was_thawed": was_thawed,
        "stopped_said": ES["agents.out.stopped"] in said,
        "gone": gone,
        "no_stop_button": "v=parar" not in stopped_row,
        "quick": took < QUICK,
        # A start that is quick is over when the browser asks: "arrancando", or already its end.
        # The slow one, held on purpose, is `parar-no-espera-al-arranque`'s.
        "starting_page": 'data-view="running"' in first or 'data-view="result"' in first,
        "started_said": ES["agents.out.started"] in back,
        "running_again": _running(THIRD.container),
        "main_not_listed": "agente=principal" not in web.get("/agentes").text,
        "stop_main_refused": stop_main["outcome"] == "refused",
        "freeze_main_refused": freeze_main["outcome"] == "refused",
        "main_not_paused": not paused(MAIN.container),
        "main_same_start": started_at(MAIN.container) == main,
    }
    attack.check(
        "stopped",
        all(holds.values()),
        "congelar y descongelar lo hacen en Docker; «parado» sale cuando Docker lo dice, y la "
        f"lista ofrece arrancarlo; arrancar contesta en {took:.1f} s con la página de "
        f"«arrancando»; y el principal, ni en la lista ni por el socket ({stop_main}); "
        f"no se cumple: {[name for name, ok in holds.items() if not ok] or 'nada'}",
    )
    asked = lab.events(THIRD, "agent_stop_asked")
    attack.check(
        "recorded",
        bool(asked) and "web (uid" in asked[-1]["details"]["requested_by"],
        f"agent_stop_asked en su caja, de «{asked[-1]['details']['requested_by']}»",
    )


@scenario("parar-no-espera-al-arranque")
def test_a_stop_does_not_wait_behind_a_start(attack: Attack, lab: Lab, web: Web) -> None:
    """Review of T26-6a: a start held every other order for up to 240 s, so nothing could be stopped
    meanwhile. The wait is now out of the lock: what the orders check is taken by then."""
    assert order(lab, {"cmd": "agent_stop", "agent": THIRD.slug})["outcome"] == "stopped"
    said: list[dict[str, Any]] = []
    starting = threading.Thread(
        target=lambda: said.append(order(lab, {"cmd": "agent_start", "agent": THIRD.slug}))
    )
    starting.start()
    try:
        wait(
            lambda: listed(lab).get(THIRD.slug, {}).get("order") == "starting",
            60,
            "the third to be coming up",
            lab.diagnosis,
        )
        begun = time.monotonic()
        stopped = order(lab, {"cmd": "agent_stop", "agent": OTHER.slug})
        took = time.monotonic() - begun
    finally:
        starting.join(START_TIMEOUT)
    assert said and said[0]["outcome"] == "started", said
    gone = not _running(OTHER.container)
    assert order(lab, {"cmd": "agent_start", "agent": OTHER.slug})["outcome"] == "started"
    attack.check(
        "stopped",
        stopped["outcome"] == "stopped" and gone and _running(THIRD.container),
        f"con el tercero arrancando, parar al vecino no se rechaza: {stopped['outcome']} en "
        f"{took:.0f} s, y el tercero acaba en marcha",
    )


STOP_BUSY = "Ya hay una parada"  # the service's own word when a stop finds the stops' room taken
CONNECTION_CAP = "Demasiadas conexiones"  # what the socket says with every connection taken
STOP_HELD = 1.0  # seconds a real stop has been running before the second one is asked


def reply_one(reply: list[dict[str, Any]] | None) -> dict[str, Any]:
    """The one reply a probe of one request gave (its secrets never leave the probe)."""
    return reply[0] if reply else {"error": "no answer"}


@scenario("paradas-repetidas-no-quitan-el-freno")
def test_repeated_stops_never_take_the_webs_brake(attack: Attack, lab: Lab, web: Web) -> None:
    """Review of T26-6b with the chat: the stops (`agent_stop`, `task_stop`) did not count in the
    narrow socket's cap of connections and a stop holds its own while it lasts, so two starts and
    stops asked again and again could take them all, "Congelar" with them. Now each kind of stop
    has its room, and the second one finds it taken and is told so at once, spending nothing.

    In the real unit, with two real neighbours and a real session: a real `agent_stop` of one
    lasts ~10 s (Docker's). While it runs, stops asked again and again (of the other neighbour and
    of the same) are answered `busy` by the stops' room ("Ya hay una parada"): without the room
    they reach `Fleet`, which answers `refused` with another text. Meanwhile the pages answer and
    "Congelar" and "Seguir" work from the real web on the neighbour that is up (so the stops did
    not spend the changes' tokens either). After it, both stops are possible and the starts come
    out as the service's list says.

    Not covered here, and why: (a) two starts held at once, since a lab's start answers in ~1.5 s
    and `Fleet` takes a second start only after the first one's checks; (b) a stop of a task that
    lasts (a lab's `pkill` answers at once), the per-agent room of the task's stop and the chat's
    second "Parar" (409; the lab's web has no `--tareas`). All three are in
    tests/test_service_web_agent_orders.py (real sockets, held orders), and the chat's in
    tests/test_web_talk.py."""
    time.sleep(CHANGES_WAIT)
    token = lab.helper("link", SOCKET)["token"]
    [opened] = _probe(nobody(), lab.web_gid, {"cmd": "session_open", "token": token, "_see": True})
    assert opened["ok"] is True, {key: opened.get(key) for key in ("outcome", "ok")}

    def sent(*requests: dict[str, Any]) -> list[dict[str, Any]]:
        return _probe(
            nobody(),
            lab.web_gid,
            *({**one, "session": opened["session"], "_why": True} for one in requests),
        )

    def stop_of(agent: Any) -> dict[str, Any]:
        return {"cmd": "agent_stop", "agent": agent.slug}

    answers: dict[str, list[dict[str, Any]]] = {}

    def run_stop() -> None:
        answers["stop-third"] = sent(stop_of(THIRD))

    holds: dict[str, bool] = {}
    notes: dict[str, Any] = {}
    first = threading.Thread(target=run_stop, name="stop-third")
    first.start()
    try:
        time.sleep(STOP_HELD)
        repeats = [reply_one(sent(stop_of(OTHER))), reply_one(sent(stop_of(THIRD)))]
        repeats.append(reply_one(sent(stop_of(OTHER))))
        notes["repeats"] = repeats
        holds["repeated_stops_busy"] = all(
            one.get("outcome") == "busy" and STOP_BUSY in str(one.get("why", "")) for one in repeats
        )
        holds["the_stop_was_still_running"] = first.is_alive()
        holds["neighbour_untouched"] = _running(OTHER.container)
        pages = [web.get("/agentes").status_code for _ in range(3)]
        listing = reply_one(_probe(nobody(), lab.web_gid, {"cmd": "agents", "_why": True}))
        notes["listing"] = listing
        holds["pages"] = pages == [200] * 3 and listing.get("ok") is True
        frozen = ended(web, ask(web, "pausar", OTHER.slug))
        holds["frozen"] = ES["agents.out.frozen"] in frozen and paused(OTHER.container)
        thawed = ended(web, ask(web, "seguir", OTHER.slug))
        holds["thawed"] = ES["agents.out.resumed"] in thawed and not paused(OTHER.container)
    finally:
        first.join(START_TIMEOUT)
        for agent in (THIRD, OTHER):  # whatever happened, the next scenarios find them up
            if paused(agent.container):
                order(lab, {"cmd": "agent_resume", "agent": agent.slug})
    holds["first_stop_ended"] = reply_one(answers.get("stop-third")).get(
        "outcome"
    ) == "stopped" and not _running(THIRD.container)
    # The room is back: both stops are possible again, and the starts end as the list says.
    again = reply_one(sent(stop_of(OTHER)))
    holds["room_back"] = again.get("outcome") == "stopped" and not _running(OTHER.container)
    for agent in (THIRD, OTHER):
        assert order(lab, {"cmd": "agent_start", "agent": agent.slug})["outcome"] == "started"
    said = listed(lab)
    holds["starts_as_the_list_says"] = all(
        said.get(agent.slug, {}).get("watched")
        and not said.get(agent.slug, {}).get("order")
        and _running(agent.container)
        for agent in (THIRD, OTHER)
    )
    holds["no_answer_was_the_cap"] = CONNECTION_CAP not in str(notes) + str(answers)
    attack.check(
        "stopped",
        all(holds.values()),
        "con un parar de verdad en curso (unos 10 s), los pedidos de parar repetidos se rechazan "
        "al momento con la palabra de las paradas y no con la de `Fleet`; las páginas contestan y "
        "«Congelar» y «Seguir» funcionan en el vecino que está arriba; al acabar, se puede parar "
        "otra vez y los dos vecinos arrancan como dice la lista del servicio. No se cumple: "
        f"{[name for name, ok in holds.items() if not ok] or 'nada'}; {notes}",
    )


@scenario("borrar-desde-la-web")
def test_deleting_from_the_web_leaves_the_box_and_is_retired(
    attack: Attack, lab: Lab, web: Web
) -> None:
    """The name written again, in the page and in the service. It stays "retirado", with no button,
    and its box verifies whole. What the trash holds comes back only from the server's terminal:
    not even a live session gets there, and emptying, never."""
    time.sleep(CHANGES_WAIT)
    wrong_at_the_socket = as_the_web(
        lab, signed({"cmd": "agent_delete", "agent": THIRD.slug, "typed": "otro"})
    )[0]
    wrong_page = ask(web, "borrar", THIRD.slug, escrito="otro")
    no_name = web.post("/agentes/orden", order_form(web, "borrar", THIRD.slug))
    still = _running(THIRD.container)
    said = ended(web, ask(web, "borrar", THIRD.slug, escrito=THIRD.slug))
    lab.agents = [MAIN, OTHER]
    wait(lambda: not _running(THIRD.container), 60, "the third to go", lab.diagnosis)
    wait(
        lambda: f'data-retired="{THIRD.slug}"' in web.get("/agentes").text,
        THE_LIST,
        "the list to say it is retired",
        lab.diagnosis,
    )
    page = web.get("/agentes").text
    trash = as_the_web(
        lab,
        signed({"cmd": "agent_restore", "agent": THIRD.slug}),
        signed({"cmd": "agent_purge", "agent": THIRD.slug, "typed": THIRD.slug}),
    )
    box = THIRD.box / STATE_DB
    kept = sh("sudo", "-n", "test", "-f", str(box), check=False).returncode == 0
    attack.check(
        "stopped",
        wrong_at_the_socket["outcome"] == "invalid"
        and wrong_page.status_code == 400
        and no_name.status_code == 400
        and still
        and ES["agents.out.deleted"] in said
        and ES["agents.state.retired"] in page
        and f"agente={THIRD.slug}" not in page
        and f"sudo backtide agentes recuperar {THIRD.slug}" in page
        and all(a["outcome"] == "refused" and "socket de la web" in a["why"] for a in trash)
        and kept,
        f"con otro nombre, nada ({wrong_at_the_socket}); con el suyo se borra, sale «retirado» y "
        f"sin botones, y recuperar y vaciar siguen fuera de la lista: {trash[0]}",
    )
    deleted = lab.installation_events("agent_deleted")
    asked = lab.installation_events("agent_delete")
    its_box = lab.verify(THIRD)
    attack.check(
        "recorded",
        [event["target"] for event in deleted] == [THIRD.slug]
        and "web (uid" in asked[-1]["details"]["requested_by"]
        and its_box["ok"] is True
        and lab.events(THIRD)[-1]["action"] == "agent_deleted",
        f"agent_delete de «{asked[-1]['details']['requested_by']}» y agent_deleted en la caja de "
        f"la instalación; la suya verifica entera ({its_box['checked']} eventos) y termina ahí",
    )


# --- no agent gets here -------------------------------------------------------------------------


FROM_INSIDE = """
import json, os, socket, sys, urllib.error, urllib.parse, urllib.request
out = {}
form = urllib.parse.urlencode({"csrf": "x", "ticket": "x", "slug": "cuarto", "perfil": "openclaw",
                               "tamano": "10"}).encode()
proxy = os.environ["HTTP_PROXY"]
# urllib reads NO_PROXY itself and would go straight to 127.0.0.1, past the proxy: take it out.
for name in ("NO_PROXY", "no_proxy"):
    os.environ.pop(name, None)
through = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
port = int(sys.argv[1])
for ip in sys.argv[2:]:
    with socket.socket() as sock:
        sock.settimeout(3)
        direct = sock.connect_ex((ip, port))
    # Through its proxy, as it reaches everything else, without its NO_PROXY: the only way out.
    origin = "http://%s:%d" % (ip, port)
    request = urllib.request.Request(origin + "/agentes/crear", data=form,
                                     headers={"Origin": origin})
    try:
        with through.open(request, timeout=8) as answer:
            said = [answer.status, answer.read(200).decode("utf-8", "replace")]
    except urllib.error.HTTPError as error:
        said = [error.code, error.read(200).decode("utf-8", "replace")]
    except Exception as error:
        said = [0, type(error).__name__ + ": " + str(error)[:120]]
    out[ip] = {"direct": direct, "code": said[0], "said": said[1], "proxy": proxy}
print(json.dumps(out))
"""


@scenario("agente-crea-agente-por-la-web")
def test_no_agent_reaches_the_web_to_make_another(attack: Attack, lab: Lab, web: Web) -> None:
    """The real web is up, with its path to create one: from inside an agent it is not reachable,
    directly or through its proxy, at any address of the machine. Its proxy is what answers, which
    is the control that this went through it. And from the machine the same web answers that POST
    with a 401, so it was there to be reached. Only the address goes in the script's arguments: the
    web's random prefix would end up in the agent's box."""
    before = whats_there(lab), len(lab.installation_events("agent_create"))
    port = web.url.split(":")[2].split("/")[0]
    machine = [ip for ip in sh("hostname", "-I").stdout.split() if ":" not in ip]
    targets = [*machine, "127.0.0.1"]
    script = Path("/tmp") / f"por-la-web-{secrets.token_hex(4)}.py"  # noqa: S108 - in the agent
    # The neighbour was restarted by the scenario before: its proxy may not be listening yet, and a
    # refused connection to it proves nothing. Ask again until the proxy itself answers.
    deadline = time.monotonic() + 90
    while True:
        ran = lab.in_agent(
            OTHER,
            f"cat > {script} <<'FIN'\n{FROM_INSIDE}\nFIN\npython3 {script} {port} "
            f"{' '.join(targets)}; code=$?; rm -f {script}; exit $code",
            timeout=120,
        )
        assert ran.returncode == 0, ran.stderr
        found = json.loads(ran.stdout.strip().splitlines()[-1])
        if all(said["code"] != 0 for said in found.values()) or time.monotonic() > deadline:
            break
        time.sleep(3)
    control = web.post("/agentes/crear", {"csrf": "x"}, signed_in=False)
    listening = sh("ss", "-ltnH").stdout.splitlines()
    outside = [
        line
        for line in listening
        if any(f"{address}:{port} " in line for address in ("0.0.0.0", "*", "[::]"))  # noqa: S104
    ]
    here = [line for line in listening if f"127.0.0.1:{port} " in line]
    # Whatever is not its proxy saying no got somewhere: a 401, a 404, a 303.
    reached = {
        ip: said
        for ip, said in found.items()
        if said["direct"] == 0 or said["code"] != 403 or PROXY_SAID not in said["said"]
    }
    why = ""
    if reached:  # a refusal that is not the proxy's own: what the agent sees of its proxy
        seen = lab.in_agent(
            OTHER,
            "getent hosts backtide-proxy; env | grep -i proxy | sed 's/=.*@/=***@/'; "
            'python3 -c "import socket;s=socket.socket();s.settimeout(3);'
            "print('connect', s.connect_ex(('backtide-proxy', 8080)))\"",
            timeout=30,
        )
        containers = sh("docker", "ps", "--format", "{{.Names}} {{.Status}}", check=False).stdout
        why = f" [dentro: {seen.stdout.strip()!r}; contenedores: {containers.strip()!r}]"
    attack.check(
        "stopped",
        sorted(found) == sorted(targets)
        and not reached
        and control.status_code == 401
        and here
        and not outside
        and (whats_there(lab), len(lab.installation_events("agent_create"))) == before,
        f"desde dentro no llega directo a ninguna de las {len(targets)} direcciones, y su proxy "
        f"contesta 403 «{PROXY_SAID}» a todas ({reached or 'bien'}); desde la máquina, la misma "
        f"web contesta {control.status_code}, solo escucha en lo local y no se crea nada{why}",
    )


# --- the key, last: from here on it asks for a touch ----------------------------------------------


@scenario("crear-sin-llave")
def test_with_a_key_creating_and_deleting_ask_for_it_touched(attack: Attack, lab: Lab) -> None:
    """Table 5.3 of docs/47, decided in the service: a session opened with the link or the password
    has touched nothing. Stopping and freezing do not ask, which is the control that it is the key
    that refuses. Touched, it goes on to the order's own checks."""
    from backtide.service import passkeys as pk
    from tests.passkey_kit import SoftAuthenticator

    time.sleep(CHANGES_WAIT)
    fourth = {**GOOD, "slug": "cuarto"}  # `tercero` was used, and a name is not used twice
    before = whats_there(lab), len(lab.installation_events())
    owner, origin = SoftAuthenticator(), pk.origin_for(pk.WEB_PORT)
    token = lab.helper("link", SOCKET)["token"]
    uid, gid = nobody(), lab.web_gid
    opened, begun = _probe(
        uid, gid,
        {"cmd": "session_open", "token": token, "_see": True},
        {"cmd": "passkey_begin", "session": "<session>", "_see": True},
    )  # fmt: skip
    answer = owner.create(begun["options"], origin)
    session = opened["session"]
    [added] = _probe(
        uid, gid,
        {"cmd": "passkey_finish", "session": session, "answer": answer, "name": "portátil",
         "_why": True},
    )  # fmt: skip
    assert added["outcome"] == "added", added
    # A session with no touch: the one that just registered it has not touched it either.
    create, delete, freeze, thaw = _probe(
        uid, gid,
        {**fourth, "session": session, "_why": True},
        {"cmd": "agent_delete", "agent": OTHER.slug, "typed": OTHER.slug, "session": session,
         "_why": True},
        {"cmd": "agent_pause", "agent": OTHER.slug, "session": session},
        {"cmd": "agent_resume", "agent": OTHER.slug, "session": session},
    )  # fmt: skip
    still_there = _running(OTHER.container) and not paused(OTHER.container)
    [begun] = _probe(uid, gid, {"cmd": "touch_begin", "session": session, "_see": True})
    answer = owner.get(begun["options"], origin)
    [touched] = _probe(uid, gid, {"cmd": "touch_finish", "session": session, "answer": answer})
    # Touched: past the key, as far as the machine's checks, on a size that has no room here.
    [past] = _probe(uid, gid, {**fourth, "volume_gib": 50, "session": session, "_why": True})
    attack.check(
        "stopped",
        create["outcome"] == "refused"
        and "tocar tu llave" in create["why"]
        and delete["outcome"] == "refused"
        and "tocar tu llave" in delete["why"]
        and freeze["ok"] is True
        and thaw["ok"] is True
        and still_there
        and touched["outcome"] == "touched"
        and past["outcome"] == "refused"
        and "disco" in past["why"]
        and whats_there(lab) == before[0],
        f"sin tocarla, crear y borrar se rechazan ({create['why'][:50]}…), y congelar sí va, que "
        f"es el control; tocada, crear llega a mirar el disco ({past['why'][:40]}…)",
    )
