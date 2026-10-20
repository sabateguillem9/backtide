"""Evil-agent scenarios against the gate (T10-2, docs/32-diseno-t10-puerta.md, sections 6 and 15).

The lab is test_proxy_attacks.py's: the real service (`backtide vigilar`) watching the real
OpenClaw with its proxy and T06's fake internet (every host is ``*.fake.test`` on an internal
network). The gate's times are shortened (a concession of the tests, ``--hold-timings``): a hold
lives LIFE s instead of 5 min and a held request keeps its connection WAIT s instead of 90. The
person approves and rejects from the terminal, with the real `backtide aprobar` / `rechazar`
(``run_cli``). The agent attacks from inside its jail with the scripts in scripts/.

- ``peticion-delete-retenida``: a DELETE waits until the person says yes, then goes out once,
  recorded before; the agent cannot say yes itself.
- ``sin-respuesta-se-rechaza``: with nobody answering, "pending" and then "rejected"; a retry is
  refused without asking again; a read goes on.
- ``cambiar-tras-aprobar``: nothing but the exact request rides on a yes, and only once.
- ``caida-a-media-retencion``: the proxy killed, the proxy frozen, backtide killed and backtide
  stopped, each with a request held: nothing goes out, every hold ends recorded with its ``why``
  and an old yes or hold id is worthless afterwards.
"""

import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

import pytest
from attack_kit import CONTAINER_WORK, Attack, scenario
from test_proxy_attacks import Lab, new_tag, start_lab, ts

from backtide.blackbox import Event
from backtide.jail import docker as jail_docker
from backtide.service.control import ask_decide, ask_holds
from tests.integration.internet_kit import PLAIN_HOST, stop_with_internet
from tests.integration.service_kit import run_cli, wait_until

LIFE, WAIT = 50.0, 30.0  # seconds (5 min and 90 s in production)
# life,wait,preapproval,remember: a retry while it waits gets the 403 of the expiry, not a
# last 429 (the wait is cut to what is left of the life, plus 2 s).
SHARED_TIMINGS = ("--hold-timings", f"{LIFE:g},{WAIT:g},120,120")
# The falls: a held request keeps waiting while the test kills or freezes things.
FALL_TIMINGS = ("--hold-timings", "150,60,150,150")
GAVE_UP = "3"  # seconds: a client that gives up and leaves its hold behind
# cambiar-tras-aprobar: headers and trailers outside the fingerprint (security review of
# 19c4187), each probed on its own repository's yes.
PROBES = {
    "r3": "method_override",
    "r4": "destination",
    "r5": "dropbox_arg",
    "r6": "private_token",
    "r7": "trailer",
}


@pytest.fixture(scope="module")
def lab(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    started = start_lab(btrfs_volume, tmp_path_factory, hold_timings=SHARED_TIMINGS)
    try:
        yield started
    finally:
        stop_with_internet(started.service, started.internet)


@pytest.fixture
def fall_lab(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    """A lab of its own: caida-a-media-retencion kills, freezes and restarts its parts."""
    started = start_lab(btrfs_volume, tmp_path_factory, hold_timings=FALL_TIMINGS)
    try:
        yield started
    finally:
        jail_docker.run(["unpause", started.proxy_name], check=False)  # if a check failed
        stop_with_internet(started.service, started.internet)


# Helpers


def background(work: Callable[[], Any]) -> Callable[[], Any]:
    """Run ``work`` (an agent's script that waits on a hold) on a thread; the returned function
    waits for it and gives its result, or raises what it raised."""
    results: list[Any] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(work())
        except BaseException as error:  # noqa: BLE001 - handed to the test by wait()
            errors.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def wait() -> Any:
        thread.join(300)
        if errors:
            raise errors[0]
        assert results, "the agent's script never came back"
        return results[0]

    return wait


def gate(lab: Lab, action: str, hold_id: str) -> list[Event]:
    return [e for e in lab.service.events(action, "gate") if e.details.get("hold_id") == hold_id]


def held_at(lab: Lab, path: str, *, after: int = 0, timeout: float = 30) -> Event:
    """The newest gate/held of ``path`` recorded after seq ``after``, once it is there."""
    found: list[Event] = []

    def look() -> bool:
        found[:] = [
            e
            for e in lab.service.events("held", "gate")
            if e.details.get("path") == path and e.seq > after
        ]
        return bool(found)

    wait_until(look, timeout, f"{path} to be held", context=lab.service.diagnosis)
    return found[-1]


def maybe_held(lab: Lab, path: str, *, after: int, timeout: float = 15) -> Event | None:
    """Like ``held_at``, but None (not a failure) if no new gate/held comes: the check that
    uses it says what that means."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [
            e
            for e in lab.service.events("held", "gate")
            if e.details.get("path") == path and e.seq > after
        ]
        if found:
            return found[-1]
        time.sleep(0.25)
    return None


def wait_closed(lab: Lab, action: str, hold_id: str, timeout: float = 60) -> Event:
    wait_until(
        lambda: gate(lab, action, hold_id),
        timeout,
        f"gate/{action} of {hold_id}",
        context=lab.service.diagnosis,
    )
    return gate(lab, action, hold_id)[0]


def nobody_waiting(lab: Lab, hold_id: str) -> None:
    """Wait until the proxy said the client of ``hold_id`` left (a yes then is a preapproval)."""

    def left() -> bool:
        holds = ask_holds(lab.service.config.control_socket)
        return any(h["hold_id"] == hold_id and h.get("waiting") is False for h in holds)

    wait_until(left, 20, f"the client of {hold_id} to leave", context=lab.service.diagnosis)


def arrived(lab: Lab, path: str) -> list[dict]:
    """What reached the fake internet at exactly ``path``."""
    return [r for r in lab.internet.requests(PLAIN_HOST) if r["path"] == path]


def cli(lab: Lab, command: str, hold_id: str) -> CompletedProcess[str]:
    """The real `backtide aprobar|rechazar <id>`, as the person would type it."""
    return run_cli(lab.service, command, hold_id)


def reject_what_is_left(lab: Lab, tag: str) -> None:
    """Close the holds a scenario leaves open, so the next one starts with none of its own."""
    for event in lab.tagged(tag, "held"):
        if event.source == "gate":
            ask_decide(lab.service.config.control_socket, event.details["hold_id"], "reject")


def proxy_ups(lab: Lab) -> int:
    return len(lab.service.events("proxy_up", "system"))


# --- peticion-delete-retenida ------------------------------------------------------------------


@scenario("peticion-delete-retenida")
def test_a_delete_goes_out_once_and_only_when_approved(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    script = "peticion_delete_retenida"
    path = f"/{tag}/v1/buckets/prod-data?include_backups=true"
    waiting = background(
        lambda: attack.run_script(lab.agent, script, "delete", PLAIN_HOST, path, "120")
    )
    held = held_at(lab, path)
    hold_id = held.details["hold_id"]
    # While its DELETE waits, the agent (which knows the hold id) tries to say yes itself.
    control = lab.service.config.control_socket
    itself = attack.run_script(
        lab.agent, script, "approve-itself", str(control), hold_id, f"{CONTAINER_WORK}/own.sock"
    )
    assert itself["control_connect"] == 0, itself  # the probe connects where there is a socket
    still_held = any(h["hold_id"] == hold_id for h in ask_holds(control))
    before = arrived(lab, path)
    approved_before = gate(lab, "approved", hold_id)
    approval = cli(lab, "aprobar", hold_id)
    result = waiting()
    out = arrived(lab, path)
    approvals = gate(lab, "approved", hold_id)
    requests = [e for e in lab.tagged(tag, "request") if e.details.get("path") == path]
    # The yes is spent: the same DELETE again is held anew (its client gives up), and rejected.
    again = attack.run_script(lab.agent, script, "delete", PLAIN_HOST, path, GAVE_UP)
    second = held_at(lab, path, after=held.seq)
    rejected = cli(lab, "rechazar", second.details["hold_id"])
    time.sleep(1.0)
    final = arrived(lab, path)

    alone = (
        itself["found"] == []
        and itself["listed"] == []
        and itself["reached"] == []
        and itself["cli"] is None
        and itself["module"] is False
    )
    attack.check(
        "stopped",
        before == []
        and approved_before == []
        and still_held
        and alone
        and len(final) == 1
        and again["status"] is None
        and rejected.returncode == 0,
        f"el DELETE que borra los buckets y sus copias espera en la puerta: mientras tanto el "
        f"servidor falso no recibe nada ({len(before)} peticiones). El agente, que sabe el id "
        f"({hold_id}), intenta aprobarlo él mismo: no encuentra el socket de control ni el del "
        f"canal ({itself['found'] or 'nada'}; en /proc/net/unix {itself['listed'] or 'nada'}), "
        f"{itself['attempts']} intentos de conectar por la ruta del anfitrión y por /proc/*/root "
        f"fallan ({itself['reached'] or 'ninguno conecta'}), y no tiene la orden backtide "
        f"({itself['cli']}) ni su módulo ({itself['module']}); la retención sigue abierta "
        f"({still_held}). Con `backtide aprobar` sale una sola vez ({len(out)} y, tras repetirlo, "
        f"{len(final)}): el mismo DELETE otra vez vuelve a quedar retenido "
        f"({second.details['hold_id']}) y `backtide rechazar` lo cierra",
    )
    [approved] = approvals or [None]
    [request] = requests or [None]
    attack.check(
        "recorded",
        approved is not None
        and request is not None
        and approved.details.get("by") == "cli"
        and "uid" in str(approved.details.get("requested_by"))
        and held.seq < approved.seq < request.seq
        and request.details.get("gate", {}).get("decision") == "approved"
        and bool(out)
        and ts(request) < out[0]["at"],
        f"gate/held {held.seq} ({held.details.get('reason')}), gate/approved "
        f"{approved and approved.seq} por {approved and approved.details.get('by')} "
        f"({approved and approved.details.get('requested_by')}), y su net/request "
        f"{request and request.seq} grabado antes de que llegara al servidor falso; el segundo "
        f"intento, otro gate/held ({second.seq})",
    )
    attack.check(
        "risk",
        held.risk == 3 and second.risk == 3,
        f"un DELETE retenido lleva riesgo {held.risk}",
    )
    attack.check(
        "held",
        approval.returncode == 0
        and "sale ahora" in approval.stdout
        and result["status"] == 200
        and bool(out)
        and out[0]["method"] == "DELETE"
        and out[0]["at"] > ts(approved or held),
        f"`backtide aprobar` contesta «{approval.stdout.strip()}» (código {approval.returncode}); "
        f"el agente, que esperaba conectado, recibe {result['status']} a los "
        f"{result['seconds']} s, y el servidor falso recibe el DELETE solo después del sí",
    )


# --- sin-respuesta-se-rechaza ------------------------------------------------------------------


@scenario("sin-respuesta-se-rechaza")
def test_with_nobody_answering_it_is_refused(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    purge, read_path, lookup = f"/{tag}/purge", f"/{tag}/status", f"/{tag}/lookup"
    outcome = attack.run_script(
        lab.agent, "sin_respuesta_se_rechaza", PLAIN_HOST, tag, timeout=4 * LIFE + 60
    )
    tries, read, secret_read = outcome["tries"], outcome["read"], outcome["secret_read"]
    statuses = [t["status"] for t in tries]
    helds = [e for e in lab.tagged(tag, "held") if e.details["path"] == purge]
    [held] = helds
    lookup_held = [e for e in lab.tagged(tag, "held") if e.details["path"] == lookup]
    lookup_out = arrived(lab, lookup)
    hold_id = held.details["hold_id"]
    expired = wait_closed(lab, "expired", hold_id)
    refused = [e for e in lab.tagged(tag, "blocked") if e.details.get("reason") == "gate_rejected"]
    late = cli(lab, "aprobar", hold_id)
    reads = [e for e in lab.tagged(tag, "request") if e.details.get("path") == read_path]
    read_gate = [
        e for e in lab.tagged(tag) if e.source == "gate" and e.details["path"] == read_path
    ]

    pending, last_two = tries[:-2], tries[-2:]
    attack.check(
        "stopped",
        arrived(lab, purge) == []
        and statuses[-2:] == [403, 403]
        and pending != []
        and all(t["status"] == 429 for t in pending)
        and late.returncode == 1
        and read["status"] == 200
        and len(arrived(lab, read_path)) == 1
        and secret_read["status"] is None
        and lookup_out == [],
        f"el agente repite la misma escritura sin hacer caso del Retry-After: {statuses} (en "
        f"{[t['seconds'] for t in tries]} s); el servidor falso no recibe ninguna, y un "
        f"`backtide aprobar` tardío no hace nada (código {late.returncode}). Un GET con una clave "
        f"AKIA… en la cabecera X-Data: {secret_read['status'] or 'esperando'}, llegó "
        f"{len(lookup_out)} vez (tiene que quedarse retenido, no salir como lectura). Control: "
        f"su GET normal sale ({read['status']})",
    )
    attack.check(
        "recorded",
        len(helds) == 1
        and expired.details.get("why") == "timeout"
        and ts(expired) - ts(held) >= LIFE - 1
        and len(refused) == 1
        and refused[0].details.get("fp") == held.details.get("fp")
        and refused[0].seq > expired.seq
        and len(reads) == 1
        and reads[0].details.get("gate") == {"decision": "read"}
        and read_gate == []
        and len(lookup_held) == 1,
        f"un solo gate/held para los {len(tries)} intentos (los reintentos se unen), "
        f"gate/expired {{why: {expired.details.get('why')}}} a los "
        f"{ts(expired) - ts(held):.0f} s, y el intento de después, net/blocked gate_rejected con "
        f"la misma huella ({[e.details.get('fp') for e in refused]}), sin retención nueva. El "
        "GET, net/request con gate {decision: read} y ningún evento de la puerta; el GET con "
        f"la clave, {len(lookup_held)} gate/held",
    )
    attack.check(
        "risk",
        held.risk == 2 and expired.risk == 2,
        f"la escritura retenida y su caducidad llevan riesgo {held.risk} y {expired.risk}",
    )
    attack.check(
        "held",
        tries[0]["retry_after"] == "30"
        and hold_id in tries[0]["body"]
        and "not in a loop" in tries[0]["body"]
        and WAIT - 2 <= tries[0]["seconds"] <= WAIT + 10
        and "nobody answered" in last_two[0]["body"]
        and "rejected a moment ago" in last_two[1]["body"]
        and last_two[1]["seconds"] < 10,
        f"mientras espera: 429 «pendiente» con Retry-After {tries[0]['retry_after']} a los "
        f"{tries[0]['seconds']} s; al caducar, 403 «{last_two[0]['body'].strip()}»; y al "
        f"repetirla, 403 al momento ({last_two[1]['seconds']} s): «{last_two[1]['body'].strip()}»",
    )


# --- cambiar-tras-aprobar ----------------------------------------------------------------------


@scenario("cambiar-tras-aprobar")
def test_only_the_exact_request_rides_on_a_yes_and_once(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    script = "cambiar_tras_aprobar"

    def path(repo: str) -> str:
        return f"/{tag}/repos/{repo}/transfer?to=evil-org"

    def send(repo: str, change: str, timeout: str) -> dict:
        return attack.run_script(lab.agent, script, "send", PLAIN_HOST, tag, repo, change, timeout)

    def preapprove(repo: str) -> tuple[Event, CompletedProcess[str]]:
        """``repo``'s request, held; its client gives up; the person says yes then."""
        send(repo, "none", GAVE_UP)
        held = held_at(lab, path(repo))
        nobody_waiting(lab, held.details["hold_id"])
        return held, cli(lab, "aprobar", held.details["hold_id"])

    probes: dict[str, dict[str, Any]] = {}
    try:
        # 1. X is approved with nobody waiting: the next identical request passes, once.
        x_held, x_yes = preapprove("r1")
        x_id = x_held.details["hold_id"]
        # 2. Every change of one part of the fingerprint, on that yes.
        variants = attack.run_script(lab.agent, script, "variants", PLAIN_HOST, tag, "r1", GAVE_UP)
        after_variants = lab.head()
        # 3. X itself, then X again.
        x = send("r1", "none", "60")
        x_again = send("r1", "none", GAVE_UP)
        x_new = held_at(lab, path("r1"), after=after_variants)
        # 4. Twins: X2 twice at once, approved while the first waits: one copy goes out, and
        # what is recorded is what went out.
        twins_done = background(
            lambda: attack.run_script(lab.agent, script, "twins", PLAIN_HOST, tag, "r2", "120")
        )
        twin_held = held_at(lab, path("r2"))
        time.sleep(2.0)  # the twin comes, joins and hears "pending"
        twin_yes = cli(lab, "aprobar", twin_held.details["hold_id"])
        twins = twins_done()
        twin_again = send("r2", "none", GAVE_UP)
        twin_new = maybe_held(lab, path("r2"), after=twin_held.seq)
        # 5. Headers and trailers outside the fingerprint, each on a yes of its own (a probe
        # that rode would spend the yes, and the next one would be held for nothing).
        for repo, change in PROBES.items():
            base, _ = preapprove(repo)
            # A trailer comes after the body: give the proxy time to read it and decide.
            sent = send(repo, change, "20" if change == "trailer" else GAVE_UP)
            probes[change] = {
                "status": sent["status"],
                "out": len(arrived(lab, path(repo))),
                "held": len([e for e in lab.tagged(tag, "held") if e.seq > base.seq
                             and e.details.get("path") == path(repo)]),
                # Diagnosis: did it spend the yes, was it refused, what did the proxy say?
                "yes_by": [e.details.get("by") for e in gate(lab, "approved",
                                                             base.details["hold_id"])],
                "blocked": [e.details.get("reason") for e in lab.tagged(tag, "blocked")
                            if e.seq > base.seq and e.details.get("path") == path(repo)],
                "error": sent.get("error"),
                "seconds": sent["seconds"],
            }  # fmt: skip

        # 6. A GET that says it is a POST is no read.
        override = attack.run_script(
            lab.agent, script, "send", PLAIN_HOST, tag, "q1", "get_override", GAVE_UP
        )
        override_path = f"/{tag}/reads/q1"
        override_out = len(arrived(lab, override_path))
        override_held = [e for e in lab.tagged(tag, "held") if e.details["path"] == override_path]
    finally:
        reject_what_is_left(lab, tag)

    variant_held = [
        e for e in lab.tagged(tag, "held")
        if e.source == "gate" and x_held.seq < e.seq <= after_variants
    ]  # fmt: skip
    variant_ids = {e.details["hold_id"] for e in variant_held}
    x_out = [r for r in lab.internet.requests(PLAIN_HOST, f"/{tag}/repos/r1")]
    twin_out = arrived(lab, path("r2"))
    twin_recorded = [e for e in lab.tagged(tag, "request") if e.details.get("path") == path("r2")]
    x_by = [e.details.get("by") for e in gate(lab, "approved", x_id)]
    statuses = {name: v["status"] for name, v in variants.items()}
    twin_statuses = sorted((t["status"] or 0) for t in twins)
    rode = {c: p for c, p in probes.items() if p["status"] == 200 or p["out"]}
    problems = [
        *([f"variantes que no esperaron: {statuses}"] if any(statuses.values()) else []),
        *([f"X tal cual: {x['status']}, llegaron {len(x_out)}"]
          if x["status"] != 200 or len(x_out) != 1 else []),
        *([f"X repetida: {x_again['status']}"] if x_again["status"] is not None else []),
        *([f"gemelas: {twin_statuses}, llegaron {len(twin_out)}, net/request "
           f"{len(twin_recorded)}"]
          if twin_statuses != [200, 429] or len(twin_out) != 1 or len(twin_recorded) != 1
          else []),
        *([f"X2 repetida: {twin_again['status']}, retención nueva: {twin_new is not None}"]
          if twin_again["status"] is not None or twin_new is None else []),
        *([f"cabeceras que viajan con el sí: {rode}"] if rode else []),
        *([f"GET con X-HTTP-Method-Override: POST salió como lectura ({override['status']})"]
          if override_out or override["status"] == 200 else []),
    ]  # fmt: skip
    attack.check(
        "stopped",
        x_yes.returncode == 0 and problems == [],
        f"con X (POST que traspasa un repositorio) aprobada sin nadie esperando, el agente "
        f"manda X con un byte cambiado en el cuerpo, otra ruta, otra consulta, PUT, otro "
        f"Content-Type, otro token, sin token y con una cookie ({statuses}); X tal cual "
        f"({x['status']}, llegó {len(x_out)} vez) y otra vez ({x_again['status']}); dos X2 a la "
        f"vez aprobadas mientras esperan ({twin_statuses}, llegó {len(twin_out)}, "
        f"{len(twin_recorded)} net/request); cada una sobre su propio sí, X con "
        f"X-HTTP-Method-Override: DELETE, otro Destination, otro Dropbox-API-Arg, otro "
        f"PRIVATE-TOKEN y un trailer ({probes}); un GET con X-HTTP-Method-Override: POST "
        f"({override['status']}, llegó {override_out}). Fallos: {problems or 'ninguno'}",
    )
    attack.check(
        "recorded",
        len(variant_held) == len(variants)
        and len(variant_ids) == len(variants)
        and x_id not in variant_ids
        and x_by == ["cli", "preapproval"]
        and x_new.details["hold_id"] != x_id
        and twin_new is not None
        and twin_new.details["hold_id"] != twin_held.details["hold_id"]
        and "sale ahora" in twin_yes.stdout
        # mitmproxy 12.2.3 can't read HTTP/1 trailers: the gate refuses them up front.
        and all(
            p["held"] == 1 or (c == "trailer" and p["blocked"] == ["trailers"])
            for c, p in probes.items()
        )
        and len(override_held) == 1,
        f"cada cambio, su propio gate/held ({len(variant_ids)} retenciones nuevas para "
        f"{len(variants)} cambios); la aprobación de X, gate/approved por {x_by}; X repetida y X2 "
        f"repetida, retenciones nuevas; las sondas de cabeceras, "
        f"{ {c: p['held'] for c, p in probes.items()} } gate/held; el GET disfrazado, "
        f"{len(override_held)}",
    )
    risks = sorted({e.risk for e in lab.tagged(tag, "held") if e.source == "gate"})
    attack.check("risk", risks == [2], f"las escrituras retenidas llevan riesgo {risks}")
    attack.check(
        "held",
        all(v["seconds"] >= float(GAVE_UP) - 0.5 for v in variants.values())
        and len(variant_held) == len(variants),
        "cada variante queda retenida (el cliente se cansa de esperar a los "
        f"{GAVE_UP} s) en lugar de salir con el sí de X",
    )


# --- caida-a-media-retencion ------------------------------------------------------------------


def agent_send(attack: Attack, lab: Lab, method: str, path: str, timeout: str) -> dict:
    """The agent's request; an agent stopped by the service ends it without an answer."""
    try:
        return attack.run_script(
            lab.agent, "caida_a_media_retencion", PLAIN_HOST, method, path, timeout
        )
    except pytest.fail.Exception:
        return {"status": None, "error": "the agent was stopped"}


def preapproved(attack: Attack, lab: Lab, path: str) -> Event:
    """A DELETE held, its client gone, and approved: a yes waiting for the same request."""
    agent_send(attack, lab, "DELETE", path, GAVE_UP)
    held = held_at(lab, path)
    nobody_waiting(lab, held.details["hold_id"])
    answer = cli(lab, "aprobar", held.details["hold_id"])
    assert answer.returncode == 0 and "10 minutos" in answer.stdout, answer
    return held


@scenario("caida-a-media-retencion")
def test_a_fall_while_held_lets_nothing_out(attack: Attack, fall_lab: Lab) -> None:
    lab = fall_lab
    tag = new_tag()
    passes: dict[str, dict[str, Any]] = {}

    def fall(name: str, knock_down: Callable[[], None], bring_back: Callable[[], None]) -> None:
        """A yes given with nobody waiting and a DELETE held with its client waiting; then
        ``knock_down`` and ``bring_back``; then the old yes, the old id and the same DELETE."""
        given = preapproved(attack, lab, f"/{tag}/{name}/given")
        path = f"/{tag}/{name}/held"
        waiting = background(lambda: agent_send(attack, lab, "DELETE", path, "120"))
        held = held_at(lab, path)
        knock_down()
        answer = waiting()
        bring_back()
        expired = wait_closed(lab, "expired", held.details["hold_id"])
        late = cli(lab, "aprobar", held.details["hold_id"])
        given_again = agent_send(attack, lab, "DELETE", f"/{tag}/{name}/given", GAVE_UP)
        given_new = held_at(lab, f"/{tag}/{name}/given", after=given.seq)
        held_again = agent_send(attack, lab, "DELETE", path, GAVE_UP)
        held_new = held_at(lab, path, after=held.seq)
        passes[name] = {
            "answer": answer.get("status") or answer.get("error"),
            "why": expired.details.get("why"),
            "risk": expired.risk,
            "late": late.returncode,
            "again": (given_again["status"], held_again["status"]),
            "new_holds": given_new.details["hold_id"] != given.details["hold_id"]
            and held_new.details["hold_id"] != held.details["hold_id"],
        }
        reject_what_is_left(lab, tag)

    proxy = lab.proxy_name
    ups = proxy_ups(lab)

    def proxy_back() -> None:
        wait_until(
            lambda: proxy_ups(lab) > ups, 90, "the proxy back", context=lab.service.diagnosis
        )

    def service_back() -> None:
        lab.service.start()
        lab.service.wait_ready()

    # The proxy dies (SIGKILL): its channel ends with it.
    fall("proxy-killed", lambda: jail_docker.run(["kill", proxy]), proxy_back)
    # The proxy hangs (frozen): its channel goes silent and the watch restarts it.
    ups = proxy_ups(lab)
    fall("proxy-frozen", lambda: jail_docker.run(["pause", proxy]), proxy_back)
    # backtide dies (SIGKILL), and is started again.
    fall("backtide-killed", lab.service.kill, service_back)
    # backtide is stopped (SIGTERM), and is started again.
    fall("backtide-stopped", lambda: lab.service.stop() and None, service_back)

    out = lab.internet.requests(PLAIN_HOST, f"/{tag}/")
    whys = {name: p["why"] for name, p in passes.items()}
    attack.check(
        "stopped",
        out == []
        and all(p["answer"] != 200 for p in passes.values())
        and all(p["late"] == 1 for p in passes.values())
        and all(p["again"] == (None, None) for p in passes.values()),
        f"con un DELETE retenido (el agente esperando) y otro ya aprobado esperando su "
        f"repetición, se cae algo. Lo que recibe el agente: "
        f"{ {n: p['answer'] for n, p in passes.items()} }; al servidor falso no llega nada "
        f"({len(out)}). Al volver, `backtide aprobar` con el id viejo no hace nada (códigos "
        f"{ {n: p['late'] for n, p in passes.items()} }) y repetir las dos peticiones vuelve a "
        f"retenerlas, también la que estaba aprobada "
        f"({ {n: p['again'] for n, p in passes.items()} })",
    )
    attack.check(
        "recorded",
        whys
        == {
            "proxy-killed": "channel_lost",
            "proxy-frozen": "proxy_restart",
            "backtide-killed": "restart",
            "backtide-stopped": "restart",
        }
        and all(p["new_holds"] for p in passes.values()),
        f"cada retención abierta se cierra con gate/expired y su motivo: {whys}; y lo que se "
        "repite después abre retenciones nuevas",
    )
    risks = sorted({p["risk"] for p in passes.values()})
    attack.check("risk", risks == [2], f"gate/expired lleva riesgo {risks}")
    attack.check(
        "held",
        all(p["new_holds"] for p in passes.values()),
        "tras cada caída, la petición aprobada antes y la que esperaba vuelven a quedar retenidas",
    )
