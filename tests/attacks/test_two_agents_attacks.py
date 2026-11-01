"""T26-2b (invariants 1, 2, 3, 4, 7): two Claude Codes in one service, under the real unit.

An agent must never see another: not its volume, not its black box, not its network. Each scenario
has its control (what it refuses also works for who may have it), and each refusal is checked for
its reason. All of them share one lab (tests/attacks/two_agents_kit.py): the service is the real
`backtide vigilar`, as root, under a unit rendered from the template the installer uses, with real
volumes, real uids and a real Tetragon. In vigia-dev, and only with the Claude Code battery:

    make ataques PERFIL=claude-code ATK_PATH=tests/attacks/test_two_agents_attacks.py

`vecino-sin-espacio` goes last: it leaves the neighbour paused (no `seguir --agente` until T26-2c).
"""

import json
import secrets
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from attack_kit import CONTAINER_WORK, Attack, scenario
from test_web_socket_attacks import PROBE
from two_agents_kit import (
    BIN,
    CONFIG,
    ETC,
    LAB,
    MAIN,
    MAIN_CAP,
    OTHER,
    STATE,
    Agent,
    Lab,
    open_lab,
    sh,
    sudo,
    wait,
)

from backtide.jail.config import AGENT_GID, AGENT_UID, PROXY_PORT
from backtide.jail.proxy_config import PROXY_GID, PROXY_UID
from backtide.service.config import STATE_DB, STATE_INSTALLATION, STATE_KEY, STATE_WEB_SOCKET
from backtide.snapshots.space import MIB

SEEN_TIMEOUT = 60.0  # the reader reads every half second; a heartbeat may hold it a few
CLOCK_CHECKS = 50.0  # prune_interval is 20: two clock checks under the unit's filter
KILL_TIMEOUT = 60.0
SCRIPT = "pausar_por_espacio"
BATCH = 1000  # files per fill (~3 MiB): stops short of the cap, never at it
NEIGHBOUR_CAP = 64 * MIB
FILL_TO = NEIGHBOUR_CAP - 10 * MIB
OVER = 4 * MIB
LEAF = 16 * 1024


@pytest.fixture(scope="module")
def lab() -> Iterator[Lab]:
    found = open_lab()
    try:
        yield found
    finally:
        found.close()


def uid_of(container: str) -> int:
    pid = sh("docker", "inspect", "--format", "{{.State.Pid}}", container).stdout.strip()
    status = sudo("cat", f"/proc/{pid}/status").stdout
    line = next(line for line in status.splitlines() if line.startswith("Uid:"))
    return int(line.split()[1])


def said_in(events: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    return [event for event in events if text in json.dumps(event)]


def addresses(container: str) -> dict[str, str]:
    """Each network the container is on, and its address there."""
    ran = sh(
        "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container
    ).stdout  # fmt: skip
    return {name: info["IPAddress"] for name, info in json.loads(ran).items()}


def members(network: str) -> set[str]:
    ran = sh("docker", "network", "inspect", "--format", "{{json .Containers}}", network).stdout
    return {info["Name"] for info in (json.loads(ran) or {}).values()}


class InContainer:
    """What ``attack.run_script`` needs of an agent."""

    def __init__(self, lab: Lab, agent: Agent) -> None:
        self.lab, self.agent = lab, agent

    def exec(
        self, argv: list[str], *, check: bool = False, timeout: float = 60
    ) -> subprocess.CompletedProcess[str]:
        return sh("docker", "exec", self.agent.container, *argv, check=check, timeout=timeout)


# --- both at once, each with its own ----------------------------------------------------------


@scenario("dos-agentes-a-la-vez")
def test_two_agents_run_at_once_each_with_its_own(attack: Attack, lab: Lab) -> None:
    pid, restarts = lab.show("MainPID"), lab.show("NRestarts")
    ids = {
        container: uid_of(container)
        for container in (MAIN.container, MAIN.proxy, OTHER.container, OTHER.proxy)
    }
    expected_ids = {
        MAIN.container: AGENT_UID,
        MAIN.proxy: PROXY_UID,
        OTHER.container: 61101,
        OTHER.proxy: 61201,
    }
    sensors = sh(
        "docker", "ps", "--filter", "label=backtide.role=sensor", "--format", "{{.Names}}"
    ).stdout.split()  # fmt: skip

    before = {agent.slug: set(lab.snapshots(agent)) for agent in (MAIN, OTHER)}
    marks = {agent.slug: f"solo-de-{agent.slug}-{secrets.token_hex(4)}" for agent in (MAIN, OTHER)}
    for agent in (MAIN, OTHER):
        done = lab.in_agent(agent, f"echo x > {CONTAINER_WORK}/{marks[agent.slug]}")
        assert done.returncode == 0, done.stderr

    def snapshotted(agent: Agent) -> bool:
        return bool(set(lab.snapshots(agent)) - before[agent.slug])

    wait(lambda: snapshotted(MAIN) and snapshotted(OTHER), 60, "a snapshot in each", lab.diagnosis)

    def sees(agent: Agent, mark: str) -> bool:
        return lab.in_agent(agent, f"test -e {CONTAINER_WORK}/{mark}").returncode == 0

    own_files = sees(MAIN, marks["principal"]) and sees(OTHER, marks["revisor"])
    other_files = sees(MAIN, marks["revisor"]) or sees(OTHER, marks["principal"])

    # The clock check, every 20 s under the unit's filter (the incident of 2026-11-01), both agents.
    time.sleep(CLOCK_CHECKS)
    same_process = lab.show("MainPID") == pid != "0" and lab.show("NRestarts") == restarts
    bad_clock = said_in(lab.events(MAIN) + lab.events(OTHER), "cannot read the state of the clock")
    starts = lab.installation_events("service_start")
    boxes = {agent.slug: lab.verify(agent) for agent in (MAIN, OTHER)}
    started = {agent.slug: bool(lab.events(agent, "agent_start")) for agent in (MAIN, OTHER)}
    attack.check(
        "stopped",
        ids == expected_ids
        and sensors == ["backtide-sensor"]
        and own_files
        and not other_files
        and same_process
        and not bad_clock,
        f"corren los dos a la vez con sus ids ({ids}) y un solo Tetragon ({sensors}); cada uno ve "
        f"su archivo y ninguno el del otro; con la comprobación del reloj cada 20 s y 50 s "
        f"después, bajo la unidad de verdad, sigue el mismo proceso ({pid}) con {restarts} "
        "reinicios",
    )
    attack.check(
        "recorded",
        all(started.values())
        and all(box["ok"] and box["checked"] > 0 for box in boxes.values())
        and snapshotted(MAIN)
        and snapshotted(OTHER)
        and bool(starts)
        and starts[-1]["details"]["agents"] == ["principal", "revisor"],
        f"cada uno con su caja ({boxes}) y sus instantáneas, y la de la instalación dice quiénes "
        f"arrancaron ({starts[-1]['details'] if starts else 'nada'})",
    )


# --- what one runs is in its box, and never in the other's ------------------------------------


@scenario("eventos-del-vecino")
def test_what_an_agent_runs_is_never_in_its_neighbours_box(attack: Attack, lab: Lab) -> None:
    marks = {agent.slug: f"marca-{agent.slug}-{secrets.token_hex(6)}" for agent in (MAIN, OTHER)}
    for agent in (MAIN, OTHER):
        lab.in_agent(agent, f"/bin/true {marks[agent.slug]}")

    def seen(agent: Agent, mark: str) -> bool:
        return bool(said_in(lab.events(agent), mark))

    wait(
        lambda: seen(MAIN, marks["principal"]) and seen(OTHER, marks["revisor"]),
        SEEN_TIMEOUT,
        "each agent's command in its own box",
        lab.diagnosis,
    )
    # The hostile one: a command that names the neighbour's container, which is what a reader
    # uses to find its own lines. A line of A that carries B's id must still not be B's.
    main_id = sh("docker", "inspect", "--format", "{{.Id}}", MAIN.container).stdout.strip()
    forged = f"falsa-{secrets.token_hex(6)}"
    lab.in_agent(OTHER, f"/bin/true {main_id} {forged}")
    sentinel = f"fin-{secrets.token_hex(6)}"
    lab.in_agent(OTHER, f"/bin/true {sentinel}")
    lab.in_agent(MAIN, f"/bin/true {sentinel}")
    wait(
        lambda: seen(MAIN, sentinel) and seen(OTHER, sentinel),
        SEEN_TIMEOUT,
        "the sentinel in both boxes",
        lab.diagnosis,
    )
    main_events, other_events = lab.events(MAIN), lab.events(OTHER)
    crossed = (
        said_in(main_events, marks["revisor"]),
        said_in(other_events, marks["principal"]),
        said_in(main_events, forged),
    )
    attack.check(
        "stopped",
        crossed == ([], [], []),
        "la orden de cada agente no está en la caja del otro, ni una que nombra el id del "
        f"contenedor del vecino para colarse en su lectura (cruzados: {crossed})",
    )
    attack.check(
        "recorded",
        bool(said_in(other_events, forged)) and lab.verify(MAIN)["ok"] and lab.verify(OTHER)["ok"],
        "la de cada uno está en su caja (también la que nombra al vecino, en la de quien la "
        "ejecutó) y las dos cadenas verifican",
    )


# --- its network ------------------------------------------------------------------------------


CONNECT = """
import json, socket, sys
out = {}
for address in sys.argv[1:]:
    host, port = address.rsplit(":", 1)
    with socket.socket() as sock:
        sock.settimeout(3)
        out[address] = sock.connect_ex((host, int(port)))
print(json.dumps(out))
"""


@scenario("red-del-vecino")
def test_an_agent_reaches_nothing_of_its_neighbour(attack: Attack, lab: Lab) -> None:
    own_proxy = addresses(OTHER.proxy)[OTHER.network]
    theirs = addresses(MAIN.proxy)
    targets = {
        "su agente": addresses(MAIN.container)[MAIN.network],
        "su proxy en su red": theirs[MAIN.network],
        "su proxy en la de salida": theirs["backtide-salida-net"],
    }
    probe = [f"{ip}:{PROXY_PORT}" for ip in targets.values()]
    ran = lab.in_agent(
        OTHER, f"python3 -c '{CONNECT}' {own_proxy}:{PROXY_PORT} {' '.join(probe)}", timeout=60
    )
    results = json.loads(ran.stdout.strip().splitlines()[-1])
    own = results[f"{own_proxy}:{PROXY_PORT}"]
    blocked = {name: results[f"{ip}:{PROXY_PORT}"] for name, ip in targets.items()}
    alone = {
        OTHER.network: members(OTHER.network),
        MAIN.network: members(MAIN.network),
    }
    attack.check(
        "stopped",
        own == 0
        and all(code != 0 for code in blocked.values())
        and alone[OTHER.network] == {OTHER.container, OTHER.proxy}
        and alone[MAIN.network] == {MAIN.container, MAIN.proxy},
        f"llega a su proxy (control, código {own}) y a nada del vecino ({blocked}); en cada red "
        f"solo están su agente y su proxy ({alone})",
    )


# --- its volume -------------------------------------------------------------------------------


def _kill_for_showing(lab: Lab, who: Agent, shown: Path) -> dict[str, Any] | None:
    """``who``'s container made again with one more ``-v``, and the answer of the Guardian."""
    before = len(lab.events(who, "agent_stop"))
    lab.helper("recreate", str(CONFIG), who.slug, str(shown))
    wait(
        lambda: len(lab.events(who, "agent_stop")) > before and not lab.running(who),
        KILL_TIMEOUT,
        f"the Guardian to kill {who.slug}",
        lab.diagnosis,
    )
    stops = lab.events(who, "agent_stop")[before:]
    return next((e for e in stops if e["details"].get("reason") == "exposed"), None)


def _whole_again(lab: Lab, who: Agent) -> None:
    sh("docker", "rm", "--force", who.container)
    lab.restart()


@scenario("volumen-del-vecino")
def test_a_container_that_shows_the_neighbours_volume_is_killed(attack: Attack, lab: Lab) -> None:
    started = sh("docker", "inspect", "--format", "{{.State.StartedAt}}", MAIN.container).stdout
    killed = _kill_for_showing(lab, OTHER, MAIN.volume)
    # The main agent, the other one, keeps running: nothing of it was touched.
    same = (
        lab.running(MAIN)
        and sh("docker", "inspect", "--format", "{{.State.StartedAt}}", MAIN.container).stdout
        == started
    )
    _whole_again(lab, OTHER)
    back = lab.in_agent(OTHER, "true").returncode == 0
    killed_main = _kill_for_showing(lab, MAIN, OTHER.volume)
    other_goes_on = lab.running(OTHER)
    _whole_again(lab, MAIN)
    problems = killed["details"]["problems"] if killed else []
    main_problems = killed_main["details"]["problems"] if killed_main else []
    attack.check(
        "stopped",
        any("holds the volume of the agent principal" in p for p in problems)
        and any("holds the volume of the agent revisor" in p for p in main_problems)
        and same
        and other_goes_on
        and back,
        "en las dos direcciones: el contenedor recreado con un `-v` del volumen del vecino muere "
        f"en el siguiente ciclo, por eso ({problems[:1]} / {main_problems[:1]}); el otro sigue en "
        "marcha sin enterarse, y al volver a arrancar está entero",
    )
    attack.check(
        "recorded",
        killed is not None and killed_main is not None,
        "system/agent_stop {reason: exposed} en la caja de quien lo intentó",
    )
    attack.check(
        "risk",
        killed is not None and killed["risk"] == 3 and killed_main["risk"] == 3,  # type: ignore[index]
        "riesgo 3, que fija el propio servicio",
    )


# --- files that must not run ------------------------------------------------------------------


def _refused_tree(name: str) -> tuple[Path, Path]:
    """A machine of its own under the lab, with a config that reads well and no running service."""
    root = LAB / "refused" / name
    sudo("install", "-d", "-m", "0700", str(root / "state"))
    sudo("install", "-d", "-m", "0755", str(root / "etc"), str(root / "etc" / "agents"))
    sudo("install", "-d", "-m", "0755", str(root / "vols"))
    return root, root / "etc" / "backtide.toml"


def _write(path: Path, text: str) -> None:
    subprocess.run(  # noqa: S603
        ["sudo", "-n", "tee", str(path)],
        input=text,
        text=True,
        check=True,
        timeout=30,
        capture_output=True,
    )


def _config(root: Path) -> str:
    return (
        f'state_dir = "{root / "state"}"\nvolume = "{root / "vols" / "main"}"\n'
        '[agent]\nprofile = "claude-code"\n'
        '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
        "[budget]\nauto_prices = false\n"
    )


def _agent(root: Path, number: int, volume: Path) -> str:
    return f'number = {number}\nvolume = "{volume}"\n[agent]\nprofile = "claude-code"\n'


def _vigilar(config: Path, *more: str) -> subprocess.CompletedProcess[str]:
    return sudo(str(BIN / "backtide"), "vigilar", "--config", str(config), *more, check=False)


@scenario("archivo-de-agente-rechazado")
def test_an_agents_file_that_shares_or_takes_what_is_not_its_own(attack: Attack, lab: Lab) -> None:
    group = "backtide-lab-61150"
    names_before = set(sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split())
    sudo("groupadd", "-g", "61150", group)
    try:
        # A volume that is another's through a link.
        root, shared = _refused_tree("enlace")
        _write(shared, _config(root))
        sudo("mkdir", str(root / "vols" / "real"))
        sudo("ln", "-s", str(root / "vols" / "real"), str(root / "vols" / "parece-otro"))
        _write(root / "etc" / "agents" / "uno.toml", _agent(root, 1, root / "vols" / "real"))
        _write(root / "etc" / "agents" / "dos.toml", _agent(root, 2, root / "vols" / "parece-otro"))
        by_link = _vigilar(shared)

        # A volume that leads into the state through a link.
        root, into_state = _refused_tree("estado")
        _write(into_state, _config(root))
        sudo("ln", "-s", str(root / "state"), str(root / "vols" / "parece-bien"))
        _write(root / "etc" / "agents" / "uno.toml", _agent(root, 1, root / "vols" / "parece-bien"))
        by_state = _vigilar(into_state)

        # A number whose id belongs to a group of the machine.
        root, taken = _refused_tree("id")
        _write(taken, _config(root))
        _write(root / "etc" / "agents" / "uno.toml", _agent(root, 50, root / "vols" / "uno"))
        by_id = _vigilar(taken)

        # The control: the same file with a free number reads, so what refused it was the id.
        root, good = _refused_tree("bueno")
        _write(good, _config(root))
        _write(root / "etc" / "agents" / "uno.toml", _agent(root, 51, root / "vols" / "uno"))
        control = lab.helper("load", str(good))

        # A group of the agents' range is no group for the web, whatever the file says.
        by_group = _vigilar(good, "--grupo-web", group)
    finally:
        sudo("groupdel", group, check=False)
    names_after = set(sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split())
    attack.check(
        "stopped",
        by_link.returncode == 2
        and "share a folder" in by_link.stderr
        and by_state.returncode == 2
        and "is in the state" in by_state.stderr
        and by_id.returncode == 2
        and "61150" in by_id.stderr
        and "account or a group" in by_id.stderr
        and control == {"ok": True, "agents": ["principal", "uno"]}
        and by_group.returncode == 2
        and "no sirve" in by_group.stderr
        and names_after == names_before,
        "`backtide vigilar` sale con 2 y dice por qué: un volumen de otro por un enlace "
        f"({by_link.stderr.strip()[-120:]}), uno que lleva al estado "
        f"({by_state.stderr.strip()[-90:]}), un id ocupado ({by_id.stderr.strip()[-90:]}) y un "
        f"grupo de la franja para la web ({by_group.stderr.strip()[-80:]}). El mismo archivo con "
        f"un número libre se lee ({control}), y no se ha creado ningún contenedor",
    )


# --- the web's socket and the agents' ids -----------------------------------------------------


def _probe(uid: int, gid: int, *requests: dict) -> list[dict]:
    path = str(STATE / STATE_WEB_SOCKET)
    ran = sudo(
        "setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups", "--",
        "python3", "-I", "-c", PROBE, path, *(json.dumps(r) for r in requests),
        check=False, timeout=60,
    )  # fmt: skip
    lines = ran.stdout.strip().splitlines()
    return json.loads(lines[-1]) if lines else [{"error": ran.stderr.strip()[-300:]}]


@scenario("socket-web-franja-de-agentes")
def test_the_ids_of_the_agents_never_use_the_webs_socket(attack: Attack, lab: Lab) -> None:
    """Without an account named like the group, the group is all the service has: `wrong_user`
    says nothing, and what refuses the agents' ids is their range. The control is that anybody else
    with that group is answered: remove the range and this scenario fails."""
    gid = lab.web_gid
    ask = {"cmd": "holds"}
    nobody = int(sh("id", "-u", "nobody").stdout)
    control = _probe(nobody, gid, ask)
    agent = _probe(OTHER.uid, gid, ask)
    proxy = _probe(OTHER.proxy_uid, gid, ask)
    far = _probe(61299, gid, ask)
    main_agent = _probe(AGENT_UID, gid, ask)
    main_proxy = _probe(PROXY_UID, PROXY_GID, ask)
    other_group = _probe(nobody, AGENT_GID, ask)
    refused = [{"outcome": "refused", "ok": False, "n": 0}]
    inside = lab.in_agent(
        OTHER, f"[ -e {STATE / STATE_WEB_SOCKET} ] && echo visible || echo absent"
    )
    attack.check(
        "stopped",
        control[0].get("ok") is True
        and agent == refused
        and proxy == refused
        and far == refused
        and main_agent == refused
        and main_proxy in (refused, [{"errno": "EACCES"}])
        and other_group in (refused, [{"errno": "EACCES"}])
        and inside.stdout.strip() == "absent",
        f"con el grupo de la web y sin cuenta: nobody tiene respuesta (control: {control}); los "
        f"ids del agente 61101 y de su proxy 61201 se rechazan ({agent}, {proxy}), igual que 61299 "
        f"y 61000 ({far}, {main_agent}); desde dentro del agente el socket no existe "
        f"({inside.stdout.strip()})",
    )


# --- the installation's box -------------------------------------------------------------------


@scenario("caja-de-la-instalacion")
def test_a_broken_installation_box_is_told_and_never_stops_an_agent(
    attack: Attack, lab: Lab
) -> None:
    folder = STATE / STATE_INSTALLATION
    db = folder / STATE_DB
    key = folder / STATE_KEY

    def check_of() -> dict[str, str]:
        found = lab.helper("selftest", str(CONFIG))
        return next(item for item in found if item["key"] == "installation-box")

    def count() -> int:
        return lab.helper("count", str(db))["events"]

    def restart_and_journal() -> str:
        since = time.strftime("%Y-%m-%d %H:%M:%S")
        lab.restart()
        return lab.journal(since)

    def both() -> bool:
        return lab.running(MAIN) and lab.running(OTHER)

    # Whole: it says who started, and the self-test says it is whole.
    good = lab.installation_events("service_start")
    good_check = check_of()
    whole = bool(good) and good[-1]["details"]["agents"] == ["principal", "revisor"]

    # An event changed in the file.
    lab.stop()
    assert lab.helper("tamper", str(db))["changed"] == 1
    before = count()
    journal = restart_and_journal()
    tampered = (
        both()
        and "the installation's black box cannot be used" in journal
        and "does not verify" in journal
        and count() == before
    )
    tampered_check = check_of()

    # Its key gone: nothing makes a new one for a chain that exists.
    lab.stop()
    sudo("rm", "-f", str(key))
    before_key = count()
    journal = restart_and_journal()
    keyless = (
        both()
        and "the installation's black box cannot be used" in journal
        and count() == before_key
        and sudo("test", "-e", str(key), check=False).returncode != 0
    )
    keyless_check = check_of()

    # Each agent's own box was never part of it.
    agents_whole = lab.verify(MAIN)["ok"] and lab.verify(OTHER)["ok"]

    # Taken away by the owner: a new one starts.
    lab.stop()
    sudo("rm", "-rf", str(folder))
    lab.start()
    fresh = lab.installation_events("service_start")
    attack.check(
        "stopped",
        tampered and keyless and agents_whole,
        "con un evento cambiado y con la clave borrada: los dos agentes arrancan, el servicio lo "
        "dice en voz alta, la cadena no se alarga (ni se crea una clave nueva) y las cajas de los "
        f"agentes siguen íntegras ({before} y {before_key} eventos, los mismos después)",
    )
    attack.check(
        "recorded",
        whole
        and good_check["status"] == "ok"
        and tampered_check["status"] == "falla"
        and keyless_check["status"] == "falla"
        and len(fresh) == 1,
        f"la autoprueba dice «{good_check['summary']}», «{tampered_check['summary']}» y "
        f"«{keyless_check['summary']}»; y al quitar la caja, el servicio empieza una nueva",
    )


# --- its space --------------------------------------------------------------------------------


@scenario("vecino-sin-espacio")
def test_an_agent_out_of_space_stops_nobody_else(attack: Attack, lab: Lab) -> None:
    """Last: the neighbour stays paused. The fill and the delete are `pausar-por-espacio`'s, which
    explains why it does not simply write until the quota refuses."""
    main_limit = lab.usage(MAIN)["limit"]
    other = InContainer(lab, OTHER)
    small = f"{CONTAINER_WORK}/small"
    used = lab.usage(OTHER)["referenced"]
    for _ in range(100):
        if used >= FILL_TO:
            break
        filled = attack.run_script(other, SCRIPT, "fill", small, str(BATCH))
        assert not filled["errno"], filled
        time.sleep(1)
        used = lab.usage(OTHER)["referenced"]
    full_at = set(lab.snapshots(OTHER))
    # An idle Claude Code changes nothing, and a snapshot is only taken of a change.
    assert lab.in_agent(OTHER, f"echo x > {CONTAINER_WORK}/un-cambio").returncode == 0
    wait(
        lambda: bool(set(lab.snapshots(OTHER)) - full_at),
        60,
        "a snapshot of the full workspace",
        lab.diagnosis,
    )
    leaves = (NEIGHBOUR_CAP + OVER - used) // LEAF + 1
    source = (Path(__file__).parent / "scripts" / f"{SCRIPT}.py").read_text()
    assert "'" not in source
    lab.in_agent(
        OTHER, f"python3 -c '{source}' delete {small} {leaves} >/dev/null 2>&1 &", timeout=30
    )
    wait(
        lambda: bool(lab.events(OTHER, "space_pause")),
        90,
        "the neighbour's pause by space",
        lab.diagnosis,
    )
    pause = lab.events(OTHER, "space_pause")[-1]
    paused = sh(
        "docker", "inspect", "--format", "{{.State.Paused}}", OTHER.container
    ).stdout.strip()

    # The other one, meanwhile: it runs, it writes, it snapshots, and its cap is what it was.
    before = set(lab.snapshots(MAIN))
    mark = f"sigue-{secrets.token_hex(4)}"
    wrote = lab.in_agent(MAIN, f"echo x > {CONTAINER_WORK}/{mark}").returncode == 0
    wait(
        lambda: bool(set(lab.snapshots(MAIN)) - before),
        60,
        "a snapshot of the one that goes on",
        lab.diagnosis,
    )
    state = sh("docker", "inspect", "--format", "{{.State.Paused}}", MAIN.container).stdout.strip()
    main_usage = lab.usage(MAIN)
    main_pauses = lab.events(MAIN, "space_pause")
    attack.check(
        "stopped",
        paused == "true"
        and "P3" in pause["details"]["conditions"]
        and state == "false"
        and wrote
        and main_usage["limit"] == main_limit == MAIN_CAP
        and main_pauses == [],
        f"el vecino, pasado de su tope, queda congelado ({pause['details']['conditions']}); el "
        f"otro sigue en marcha, escribe y hace instantáneas, y su tope no cambia ({main_limit} y "
        f"{main_usage['limit']}); en su caja no hay ninguna pausa",
    )
    attack.check(
        "recorded",
        pause["details"]["frozen"] is True,
        "system/space_pause en la caja de quien se quedó sin espacio, y solo en la suya",
    )
    attack.check(
        "risk",
        pause["risk"] == 2,
        "riesgo 2, que fija el propio servicio",
    )


__all__ = ["ETC"]
