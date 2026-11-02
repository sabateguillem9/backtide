"""T26-2b (invariants 1, 2, 3, 4, 7): two Claude Codes in one service, under the real unit.

An agent must never see another: not its volume, not its black box, not its network. Each scenario
has its control (what it refuses also works for who may have it), and each refusal is checked for
its reason. All of them share one lab (tests/attacks/two_agents_kit.py): the service is the real
`backtide vigilar`, as root, under a unit rendered from the template the installer uses, with real
volumes, real uids and a real Tetragon. In vigia-dev, and only with the Claude Code battery:

    make ataques PERFIL=claude-code ATK_PATH=tests/attacks/test_two_agents_attacks.py

`vecino-sin-espacio` goes last: it leaves the neighbour paused, and `seguir --agente` refuses while
it is over its cap.

T26-2c (each order says which agent, and what they spend adds up): `vecino-sin-gasto`,
`gasto-de-toda-la-instalacion`, `aprobar-al-vecino`, `confiar-en-el-vecino`,
`rebobinar-al-vecino`, `agente-inventado`, `archivo-roto-no-frena` and `tarea-del-vecino`. No model
call reaches a provider (invariant 8): the key is made up, and each scenario that gives a turn or
calls a model first checks the lab's cut, and then that no model answered.
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
    SLUG,
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
from backtide.service.config import (
    STATE_DB,
    STATE_INSTALLATION,
    STATE_KEY,
    STATE_SOCKET,
    STATE_WEB_SOCKET,
)
from backtide.snapshots.space import MIB

SEEN_TIMEOUT = 60.0  # the reader reads every half second; a heartbeat may hold it a few
CLOCK_CHECKS = 50.0  # prune_interval is 20: two clock checks under the unit's filter
KILL_TIMEOUT = 60.0
HOLD_LIFE = 30.0  # [gate] hold_s in the lab's config
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
    internal = {
        name: sh("docker", "network", "inspect", "--format", "{{.Internal}}", name).stdout.strip()
        for name in alone
    }
    attack.check(
        "stopped",
        own == 0
        and all(code != 0 for code in blocked.values())
        and alone[OTHER.network] == {OTHER.container, OTHER.proxy}
        and alone[MAIN.network] == {MAIN.container, MAIN.proxy}
        and set(internal.values()) == {"true"},
        f"llega a su proxy (control, código {own}) y a nada del vecino ({blocked}); en cada red "
        f"solo están su agente y su proxy ({alone}), y las dos son internas: sin salida directa "
        f"({internal})",
    )


# --- its gate ---------------------------------------------------------------------------------


@scenario("puerta-del-vecino")
def test_what_the_neighbour_sends_waits_at_its_own_gate(attack: Attack, lab: Lab) -> None:
    """The heart of backtide, for the agent that is not the main one: a DELETE stays at its proxy's
    gate, in its box, and with nobody to say yes it is refused (invariant 6). And what the owner
    approves for the main agent releases nothing of the other. The control is that the same request
    from the main agent is held too, in the main agent's box."""
    tag = f"puerta-{secrets.token_hex(6)}"
    host = "cubos.ejemplo.test"
    script = "peticion_delete_retenida"

    def held(agent: Agent, mark: str) -> list[dict[str, Any]]:
        return said_in(lab.events(agent, "held"), mark)

    def ask(agent: Agent, mark: str) -> None:
        attack.run_script(InContainer(lab, agent), script, "delete", host, f"/{mark}/v1", "5")

    other_mark, main_mark = f"{tag}-vecino", f"{tag}-principal"
    ask(OTHER, other_mark)
    ask(MAIN, main_mark)
    wait(
        lambda: held(OTHER, other_mark) and held(MAIN, main_mark),
        SEEN_TIMEOUT,
        "each request held at its own gate",
        lab.diagnosis,
    )
    (own,), crossed = held(OTHER, other_mark), said_in(lab.events(MAIN), other_mark)
    theirs = said_in(lab.events(OTHER), main_mark)
    hold_id = own["details"]["hold_id"]
    # What the main agent's control socket can do about it: nothing, it is not its hold.
    told = lab.helper("decide", str(STATE / STATE_SOCKET), hold_id)
    wait(
        lambda: said_in(lab.events(OTHER, "expired"), hold_id),
        HOLD_LIFE + SEEN_TIMEOUT,
        "the neighbour's hold to end with nobody saying yes",
        lab.diagnosis,
    )
    released = said_in(lab.events(OTHER, "approved"), hold_id)
    attack.check(
        "stopped",
        told.get("ok") is not True and not released,
        f"el sí por el socket de control del principal no suelta lo del vecino ({told}), y nada "
        "sale aprobado",
    )
    attack.check(
        "recorded",
        crossed == [] and theirs == [],
        "gate/held en la caja de quien lo pidió y nunca en la del otro, en las dos direcciones",
    )
    attack.check(
        "held",
        bool(said_in(lab.events(OTHER, "expired"), hold_id)),
        f"la petición del vecino quedó retenida ({hold_id}) y, sin respuesta, terminó rechazada "
        "(gate/expired)",
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


# --- what each spends (T26-2c) -----------------------------------------------------------------


MODEL_HOST = "api.anthropic.com"
MODEL = "claude-sonnet-5-5"
USD = 1_000_000
TASK_SECONDS = 30  # two_agents_helper's task: the turn stops at the cut, and this ends it


def _fake_of(lab: Lab, agent: Agent) -> str:
    return lab.helper("fake", str(CONFIG), agent.slug)["fake"]


def _call_model(
    attack: Attack, lab: Lab, agent: Agent, key: str, calls: int = 2
) -> list[dict[str, Any]]:
    """The agent calls the model through its proxy. The cut is what answers, if anything does."""
    assert lab.network_cut(), "invariant 8: no model call without the lab's network cut"
    outcome = attack.run_script(
        InContainer(lab, agent), "tope_de_gasto", MODEL_HOST, key, MODEL, str(calls)
    )
    return outcome["calls"]


def _model_requests(lab: Lab, agent: Agent) -> int:
    return len([e for e in lab.events(agent, "request") if e["source"] == "llm"])


def _answers(lab: Lab, agent: Agent) -> list[dict[str, Any]]:
    return [e for e in lab.events(agent, "response") if e["source"] == "llm"]


def _stopped_at_the_cut(lab: Lab, agent: Agent, calls: list[dict[str, Any]]) -> bool:
    """It went through the spending's gate and nobody answered: an error of the proxy or none, and
    no answer of a model in its box. A 401 here would mean it reached a provider (invariant 8)."""
    return all(c["status"] is None or c["status"] >= 500 for c in calls) and not _answers(
        lab, agent
    )


def _refused_by_the_cap(calls: list[dict[str, Any]]) -> bool:
    return all(c["status"] == 429 and "tope de gasto" in str(c.get("message")) for c in calls)


def _spend(lab: Lab, *agents: Agent) -> None:
    """Each of these has spent one dollar more, written with the service stopped; it counts it when
    it starts."""
    lab.stop()
    for agent in agents:
        lab.helper("charge", str(agent.box), str(USD))
    lab.start()


def _llm_blocked(lab: Lab, agent: Agent) -> list[dict[str, Any]]:
    return [e for e in lab.events(agent, "blocked") if e["source"] == "llm"]


@scenario("vecino-sin-gasto")
def test_an_agent_out_of_money_stops_nobody_else(attack: Attack, lab: Lab) -> None:
    """A spends all that its own cap lets it, and B goes on. A's fake key, used from B, does not
    go out: it is not B's, and the spending would be counted to the wrong one. The control of the
    cap is the neighbour's call that goes through the same gate and stops at the cut."""
    try:
        _an_agent_out_of_money(attack, lab)
    finally:
        lifted = lab.cli("tope", "--agente", SLUG, "--dia", "100")
        assert lifted.returncode == 0, lifted.stderr


def _an_agent_out_of_money(attack: Attack, lab: Lab) -> None:
    cap = lab.cli("tope", "--agente", SLUG, "--dia", "1")
    assert cap.returncode == 0, cap.stderr
    _spend(lab, OTHER)
    other_key, main_key = _fake_of(lab, OTHER), _fake_of(lab, MAIN)
    assert other_key != main_key
    said = lab.cli("gasto", "--agente", SLUG)
    before_other = _model_requests(lab, OTHER)
    before_main = _model_requests(lab, MAIN)
    blocked_main = len(_llm_blocked(lab, MAIN))

    refused = _call_model(attack, lab, OTHER, other_key)
    goes_on = _call_model(attack, lab, MAIN, main_key)
    passed = _model_requests(lab, MAIN) - before_main
    wait(
        lambda: bool(_llm_blocked(lab, OTHER)),
        SEEN_TIMEOUT,
        "the neighbour's refusals in its box",
        lab.diagnosis,
    )
    (blocked, *_) = _llm_blocked(lab, OTHER)

    # B with A's key.
    foreign_before = _model_requests(lab, MAIN)
    foreign = _call_model(attack, lab, MAIN, other_key, 1)
    wait(
        lambda: bool(said_in(lab.events(MAIN, "blocked"), "foreign_credential")),
        SEEN_TIMEOUT,
        "the foreign key refused in the box of who used it",
        lab.diagnosis,
    )
    # The sensor has it in the command that ran the script, whose argument it was: not a secret.
    written = [e for e in lab.events(MAIN) if e["source"] != "exec"]
    attack.check(
        "stopped",
        _refused_by_the_cap(refused)
        and _model_requests(lab, OTHER) == before_other
        and _stopped_at_the_cut(lab, MAIN, goes_on)
        and passed == len(goes_on)
        and said.returncode == 0
        and "1,00 $ de 1,00 $" in said.stdout
        and foreign[0]["status"] == 403
        and _model_requests(lab, MAIN) == foreign_before
        and said_in(written, other_key) == [],
        f"el que agotó su tope ({said.stdout.strip()[:120]!r}) recibe {refused} y nada llega al "
        f"proveedor; el otro pasa la puerta del gasto ({passed} llm/request) y se para en el corte "
        f"({goes_on}); la clave falsa del vecino, usada desde el otro, no sale ({foreign})",
    )
    attack.check(
        "recorded",
        blocked["details"]["reason"] == "spend_cap"
        and "scope" not in blocked["details"]
        and len(_llm_blocked(lab, MAIN)) == blocked_main,
        f"llm/blocked en la caja de quien se pasó ({blocked['details']}) y ninguno en la del otro",
    )
    attack.check("risk", blocked["risk"] == 2, f"llm/blocked con riesgo {blocked['risk']}")


def _dollars(micro: int) -> str:
    return f"{micro // 10_000 / 100:.2f}"


@scenario("gasto-de-toda-la-instalacion")
def test_adding_agents_does_not_multiply_what_is_spent(attack: Attack, lab: Lab) -> None:
    """Each under its own cap, or with none, and the sum stops them all: D13. Neither alone reaches
    the cap, so a total that were not the sum would let them through. The controls: a cap a dollar
    above lets a call out, and so does raising it afterwards. The change is in the installation's
    box."""
    try:
        _adding_agents(attack, lab)
    finally:
        raised = lab.cli("tope", "--dia", "50", "--mes", "100")
        assert raised.returncode == 0, raised.stderr


def _adding_agents(attack: Attack, lab: Lab) -> None:
    control = str(STATE / STATE_SOCKET)
    keys = {agent: _fake_of(lab, agent) for agent in (MAIN, OTHER)}
    _spend(lab, MAIN, OTHER)

    def spent() -> int:
        return lab.helper("budget", control)["installation"]["day"]["spent_micro"]

    above = lab.cli("tope", "--dia", _dollars(spent() + USD))
    assert above.returncode == 0, above.stderr
    before_control = _model_requests(lab, MAIN)
    allowed = _call_model(attack, lab, MAIN, keys[MAIN], 1)
    passed_under = _model_requests(lab, MAIN) == before_control + 1

    total = spent()
    parts = lab.helper("budget", control)["installation"]["agents"]
    alone = max(part["day_micro"] for part in parts.values())
    cap = lab.cli("tope", "--dia", _dollars(total))
    assert cap.returncode == 0, cap.stderr
    assert alone < total // 10_000 * 10_000, (alone, total)  # neither alone reaches it
    changes = lab.installation_events("budget_set")
    said = lab.cli("gasto")
    before = {agent: len(_llm_blocked(lab, agent)) for agent in keys}
    requests = {agent: _model_requests(lab, agent) for agent in keys}
    refused = {agent: _call_model(attack, lab, agent, key) for agent, key in keys.items()}
    wait(
        lambda: all(len(_llm_blocked(lab, agent)) > before[agent] for agent in keys),
        SEEN_TIMEOUT,
        "each agent's refusal in its own box",
        lab.diagnosis,
    )
    new = {agent: _llm_blocked(lab, agent)[-1] for agent in keys}
    raised = lab.cli("tope", "--dia", "50", "--mes", "100")
    assert raised.returncode == 0, raised.stderr
    through = _call_model(attack, lab, MAIN, keys[MAIN], 1)
    attack.check(
        "stopped",
        all(_refused_by_the_cap(calls) for calls in refused.values())
        and _model_requests(lab, OTHER) == requests[OTHER]
        and passed_under
        and _stopped_at_the_cut(lab, MAIN, [*allowed, *through])
        and _model_requests(lab, MAIN) == requests[MAIN] + 1
        and "Total de la instalación hoy" in said.stdout,
        f"con un dólar de margen la llamada sale ({allowed}); con el tope en lo gastado entre "
        f"todos ({total} µ$, y el que más, {alone}), cada uno recibe {refused}; subido el tope, "
        f"vuelve a salir ({through}). `gasto` dice: {said.stdout[:200]!r}",
    )
    attack.check(
        "recorded",
        all(e["details"].get("scope") == "installation" for e in new.values())
        and changes[-1]["details"]["scope"] == "installation"
        and changes[-1]["details"]["requested_by"].startswith("cli (uid 0")
        and bool(lab.installation_events("budget_unblocked")),
        "llm/blocked con scope installation en la caja de cada agente, y el cambio de tope "
        f"(settings/budget_set) en la de la instalación: {changes[-1]['details']}",
    )
    attack.check("risk", {e["risk"] for e in new.values()} == {2}, "llm/blocked con riesgo 2")


# --- each order says about whom (T26-2c) ----------------------------------------------------------


def _hold(attack: Attack, lab: Lab, agent: Agent, tag: str) -> str:
    """A DELETE of this agent, held at its gate, and its id. Its client gives up; the hold stays."""
    mark = f"{tag}-{secrets.token_hex(4)}"
    attack.run_script(
        InContainer(lab, agent),
        "peticion_delete_retenida",
        "delete",
        "cubos.ejemplo.test",
        f"/{mark}/v1",
        "5",
    )
    wait(
        lambda: bool(said_in(lab.events(agent, "held"), mark)),
        SEEN_TIMEOUT,
        "the request held",
        lab.diagnosis,
    )
    (found,) = said_in(lab.events(agent, "held"), mark)
    return found["details"]["hold_id"]


@scenario("aprobar-al-vecino")
def test_the_owner_decides_on_the_neighbours_gate(attack: Attack, lab: Lab) -> None:
    """What `puerta-del-vecino` left: a neighbour's hold no longer ends rejected for lack of a way
    to answer. The field chooses whose gate, and the wrong one, or nobody, releases nothing."""
    first = _hold(attack, lab, OTHER, "aprobar")
    listed = lab.cli("retenidas")
    wrong_gate = lab.cli("aprobar", first)
    nobody = lab.cli("aprobar", first, "--agente", "nadie")
    a_path = lab.cli("aprobar", first, "--agente", "../revisor")
    released_early = said_in(lab.events(OTHER, "approved"), first)
    yes = lab.cli("aprobar", first, "--agente", SLUG)
    second = _hold(attack, lab, OTHER, "rechazar")
    no = lab.cli("rechazar", second, "--agente", SLUG)
    approved = said_in(lab.events(OTHER, "approved"), first)
    rejected = said_in(lab.events(OTHER, "rejected"), second)
    attack.check(
        "stopped",
        wrong_gate.returncode == 1
        and nobody.returncode == 2
        and a_path.returncode == 2
        and released_early == []
        and yes.returncode == 0
        and no.returncode == 0
        and bool(approved)
        and bool(rejected),
        f"sin --agente es la puerta del principal, y no suelta nada ({wrong_gate.returncode}); un "
        f"agente inventado ({nobody.returncode}) o una ruta ({a_path.returncode}) tampoco; con "
        f"--agente {SLUG}, aprobar y rechazar funcionan",
    )
    attack.check(
        "held",
        f"Agente {SLUG}:" in listed.stdout and first in listed.stdout,
        f"`retenidas` enseña lo retenido del vecino bajo su nombre: {listed.stdout[:300]!r}",
    )
    attack.check(
        "recorded",
        said_in(lab.events(MAIN), first) == []
        and said_in(lab.events(MAIN), second) == []
        and "cli (uid 0" in json.dumps(approved),
        "gate/approved y gate/rejected en la caja del vecino, con quién lo pidió, y nada en la del "
        "otro",
    )


@scenario("confiar-en-el-vecino")
def test_what_is_trusted_for_one_lets_out_nothing_of_the_other(attack: Attack, lab: Lab) -> None:
    """Section 6.5: the trusted recipients are each agent's. The owner trusts a chat for the
    neighbour, from the web's socket: the same message of the other agent is still held, and the
    list and taking it away go by the field too. The control is the neighbour's own message, which
    passes once it is trusted and is held again after."""
    control = str(STATE / STATE_SOCKET)
    nobody = int(sh("id", "-u", "nobody").stdout)
    token = f"7{secrets.randbelow(10**8):08d}:{secrets.token_urlsafe(26)}"
    chat = f"9{secrets.randbelow(10**8):08d}"
    tag = secrets.token_hex(6)

    def send(agent: Agent, mark: str) -> None:
        assert lab.network_cut(), "invariant 8: no message without the lab's network cut"
        attack.run_script(
            InContainer(lab, agent),
            "un_get_que_envia",
            token,
            chat,
            f"hola {tag}-{mark}",
            "sendMessage",
            "5",
        )

    def held_with(agent: Agent, mark: str) -> list[dict[str, Any]]:
        return said_in(lab.events(agent, "held"), f"{tag}-{mark}")

    def wait_held(agent: Agent, mark: str) -> str:
        wait(lambda: bool(held_with(agent, mark)), SEEN_TIMEOUT, f"{mark} held", lab.diagnosis)
        return held_with(agent, mark)[-1]["details"]["hold_id"]

    send(OTHER, "primero")
    first = wait_held(OTHER, "primero")
    link = lab.helper("link", control)["token"]
    trust = {"cmd": "trust", "hold_id": first, "via": "web", "session": "<session>", "_why": True}
    _, wrong_gate, right = _probe(
        nobody,
        lab.web_gid,
        {"cmd": "session_open", "token": link},
        trust,
        {**trust, "agent": SLUG},
    )
    theirs = lab.helper("trusted", control, SLUG)
    mine = lab.helper("trusted", control, "-")

    send(MAIN, "del-otro")
    other_held = wait_held(MAIN, "del-otro")
    send(OTHER, "pasa")
    passed = said_in(lab.events(OTHER, "request"), f"{tag}-pasa")
    not_held = held_with(OTHER, "pasa")

    trust_id = next(item["trust_id"] for item in theirs if chat in json.dumps(item))
    wrong_owner = lab.helper("untrust", control, "-", trust_id)
    removed = lab.helper("untrust", control, SLUG, trust_id)
    send(OTHER, "otra-vez")
    wait_held(OTHER, "otra-vez")
    lab.cli("rechazar", other_held)
    attack.check(
        "stopped",
        wrong_gate["ok"] is False
        and right["ok"] is True
        and not any(chat in json.dumps(item) for item in mine)
        and bool(passed)
        and not_held == []
        and wrong_owner["outcome"] == "unknown"
        and removed["outcome"] == "removed",
        f"confiar sin agent es la puerta del principal, que no conoce esa retención "
        f"({wrong_gate}); con su nombre sí ({right}), y la lista es la suya; quitarla por el "
        f"principal no la quita ({wrong_owner}), y por el suyo sí ({removed})",
    )
    attack.check(
        "held",
        bool(other_held),
        f"el mismo mensaje del otro agente, al mismo chat, sigue retenido ({other_held}), y el del "
        "vecino vuelve a retenerse al quitar la confianza",
    )
    attack.check(
        "recorded",
        bool(said_in(lab.events(OTHER, "trust_added"), first))
        and said_in(lab.events(MAIN, "trust_added"), first) == [],
        "gate/trust_added en la caja de ese agente, y nada en la del otro",
    )


@scenario("rebobinar-al-vecino")
def test_the_owner_rewinds_the_neighbour_and_only_it(attack: Attack, lab: Lab) -> None:
    """`rebobinar --agente`: its workspace goes back, its agent comes back, and the other is left
    as it was. A snapshot of one is nobody else's: the id says nothing to the other."""
    tag = secrets.token_hex(4)
    kept, gone, untouched = f"vuelve-{tag}", f"se-va-{tag}", f"sigue-{tag}"
    before = set(lab.snapshots(OTHER))
    assert lab.in_agent(OTHER, f"echo x > {CONTAINER_WORK}/{kept}").returncode == 0
    wait(
        lambda: bool(set(lab.snapshots(OTHER)) - before),
        SEEN_TIMEOUT,
        "a snapshot with the file",
        lab.diagnosis,
    )
    target = sorted(set(lab.snapshots(OTHER)) - before)[-1]
    script = f"rm {CONTAINER_WORK}/{kept}; echo x > {CONTAINER_WORK}/{gone}"
    assert lab.in_agent(OTHER, script).returncode == 0
    assert lab.in_agent(MAIN, f"echo x > {CONTAINER_WORK}/{untouched}").returncode == 0
    listed = lab.cli("instantaneas", "--agente", SLUG, "--todas")
    main_rewinds = len(lab.events(MAIN, "rewind_requested"))
    main_id = sh("docker", "inspect", "--format", "{{.Id}}", MAIN.container).stdout.strip()
    elsewhere = lab.cli("rebobinar", target, "--si")
    invented = lab.cli("rebobinar", target, "--si", "--agente", "nadie")
    # The one way a name becomes a file: load_agent, which these two reach unless a path is refused.
    a_path = lab.cli("rebobinar", target, "--si", "--agente", "../revisor")
    a_list = lab.cli("instantaneas", "--agente", "../revisor")
    done = lab.cli("rebobinar", target, "--si", "--agente", SLUG)
    wait(lambda: lab.running(OTHER), SEEN_TIMEOUT, "the neighbour back", lab.diagnosis)
    seen = lab.in_agent(
        OTHER, f"ls {CONTAINER_WORK}/{kept}; ls {CONTAINER_WORK}/{gone} 2>&1 || true"
    )
    main_seen = lab.in_agent(MAIN, f"ls {CONTAINER_WORK}/{untouched}")
    same_main = sh("docker", "inspect", "--format", "{{.Id}}", MAIN.container).stdout.strip()
    requested = lab.events(OTHER, "rewind_requested")[-1]
    attack.check(
        "stopped",
        elsewhere.returncode == 2
        and invented.returncode == 2
        and a_path.returncode == 2
        and "--agente" in a_path.stderr
        and a_list.returncode == 2
        and "--agente" in a_list.stderr
        and target in listed.stdout
        and main_id == same_main
        and main_seen.returncode == 0
        and len(lab.events(MAIN, "rewind_requested")) == main_rewinds,
        f"la instantánea del vecino no le dice nada al principal ({elsewhere.returncode}), ni a un "
        f"agente inventado ({invented.returncode}); el principal sigue igual",
    )
    attack.check(
        "recoverable",
        done.returncode == 0
        and f"--agente {SLUG}" in done.stdout
        and kept in seen.stdout
        and "No such file" in seen.stdout,
        f"--agente {SLUG}: su espacio vuelve a {target}, y lo posterior se va ({seen.stdout!r}); "
        f"el punto para deshacer dice de quién es ({done.stdout[-160:]!r})",
    )
    attack.check(
        "recorded",
        "cli (uid 0" in json.dumps(requested) and lab.verify(OTHER)["ok"],
        f"rewind_requested en la caja del vecino: {requested['details']}",
    )


@scenario("agente-inventado")
def test_a_session_is_good_for_all_and_says_which_each_time(attack: Attack, lab: Lab) -> None:
    """As the web: one session for every agent, a name that is nobody's refused, the narrow socket's
    own list of snapshots per agent, and no session, nothing. Each with the real hold of a real
    neighbour, which only the last order ends: its box says so, and the other's says nothing."""
    gid = lab.web_gid
    nobody = int(sh("id", "-u", "nobody").stdout)
    hold = _hold(attack, lab, OTHER, "sesion")
    main_id, other_id = lab.snapshots(MAIN)[-1], lab.snapshots(OTHER)[-1]
    token = lab.helper("link", str(STATE / STATE_SOCKET))["token"]
    reject = {"cmd": "decide", "hold_id": hold, "verdict": "reject", "_why": True}
    with_session = {**reject, "session": "<session>"}
    answers = _probe(
        nobody,
        gid,
        {**reject, "agent": SLUG},
        {"cmd": "session_open", "token": token},
        {"cmd": "agents", "_why": True},
        {**with_session, "agent": "nadie"},
        {**with_session, "agent": "../revisor"},
        {**with_session, "agent": 7},
        with_session,
        {"cmd": "rewind", "snapshot_id": main_id, "agent": SLUG, "session": "<session>"},
        {"cmd": "snapshots", "agent": SLUG},
        {"cmd": "snapshots", "agent": "nadie"},
        {**with_session, "agent": SLUG},
    )
    bare, opened, agents, invented, a_path, a_number, its_own, foreign_rewind = answers[:8]
    listing, listing_nobody, decided = answers[8:]
    rejected = said_in(lab.events(OTHER, "rejected"), hold)
    rewinds = [e for e in lab.events(OTHER, "rewind_requested") if main_id in json.dumps(e)]
    attack.check(
        "stopped",
        bare["outcome"] == "refused"
        and "sesión" in bare["why"]
        and opened["ok"] is True
        and agents["ok"] is True
        and all(
            a["outcome"] == "refused" and "agente" in a["why"] for a in (invented, a_path, a_number)
        )
        and its_own["outcome"] == "unknown"
        and foreign_rewind["outcome"] == "invalid"
        and rewinds == []
        and listing["ok"] is True
        and listing["n"] >= 1
        and listing_nobody["outcome"] == "refused"
        and decided["ok"] is True,
        f"sin sesión: {bare}; un agente inventado, una ruta y un número: {invented}, {a_path}, "
        f"{a_number}; sin agent es la puerta del principal: {its_own}; a una instantánea del "
        f"principal ({other_id} es la suya): {foreign_rewind}; con su nombre: {decided}",
    )
    attack.check(
        "recorded",
        bool(rejected)
        and "web (uid" in json.dumps(rejected)
        and said_in(lab.events(MAIN), hold) == [],
        "gate/rejected con «web» en la caja de ese agente, y nada en la del otro",
    )


@scenario("archivo-roto-no-frena")
def test_a_broken_file_stops_nothing_that_stops_or_undoes(attack: Attack, lab: Lab) -> None:
    """The owner breaks an agent's file while the service runs: rejecting, resuming and rewinding
    go on, for the others and for that very agent, whose service has what it read. What lets
    something out still reads them all, and refuses. The file goes away at the end."""
    broken = ETC / "agents" / "roto.toml"
    own = ETC / "agents" / f"{SLUG}.toml"
    held_main = _hold(attack, lab, MAIN, "roto-a")
    held_third = _hold(attack, lab, OTHER, "roto-c")
    target = lab.snapshots(OTHER)[-1]
    original = sudo("cat", str(own)).stdout
    _write(broken, "number = 9\n")  # no volume
    try:
        approve = lab.cli("aprobar", held_third, "--agente", SLUG)
        reject_main = lab.cli("rechazar", held_main)
        resume = lab.cli("seguir", "--agente", SLUG)
        listed = lab.cli("retenidas")
        rewind = lab.cli("rebobinar", target, "--si", "--agente", SLUG)
        wait(lambda: lab.running(OTHER), SEEN_TIMEOUT, "the neighbour back", lab.diagnosis)
        # And with the file of the agent itself broken: only the service can do it.
        _write(own, "number = 1\n")  # no volume
        later = _hold(attack, lab, OTHER, "roto-d")
        reject_itself = lab.cli("rechazar", later, "--agente", SLUG)
        target = lab.snapshots(OTHER)[-1]
        rewind_itself = lab.cli("rebobinar", target, "--si", "--agente", SLUG)
        wait(lambda: lab.running(OTHER), SEEN_TIMEOUT, "the neighbour back", lab.diagnosis)
    finally:
        _write(own, original)
        sudo("rm", "-f", str(broken))
    attack.check(
        "stopped",
        approve.returncode == 2
        and "roto.toml" in approve.stderr
        and not said_in(lab.events(OTHER, "approved"), held_third)
        and reject_main.returncode == 0
        and bool(said_in(lab.events(MAIN, "rejected"), held_main))
        and resume.returncode == 0
        and listed.returncode == 0
        and rewind.returncode == 0
        and reject_itself.returncode == 0
        and rewind_itself.returncode == 0,
        f"con un archivo roto, aprobar se niega ({approve.returncode}) y rechazar, seguir, "
        f"retenidas y rebobinar funcionan ({reject_main.returncode}, {resume.returncode}, "
        f"{listed.returncode}, {rewind.returncode}), también con el del propio agente "
        f"({reject_itself.returncode}, {rewind_itself.returncode}: {rewind_itself.stderr[:160]!r})",
    )
    attack.check(
        "recorded",
        "AVISO" in reject_main.stderr and "roto.toml" in reject_main.stderr,
        f"se dice qué archivo está roto: {reject_main.stderr[:200]!r}",
    )


@scenario("tarea-del-vecino")
def test_each_guardian_has_its_own_tasks(attack: Attack, lab: Lab) -> None:
    """T26-5a over T26-2b: an agent's tasks are its own. A turn of a real Claude Code, whose call
    stops at the lab's cut (invariant 8): its command runs in that container and its end is in that
    box. Only after a sentinel has reached the other's box is it fair to say that nothing did."""
    assert lab.network_cut(), "invariant 8: no turn of an agent without the lab's network cut"
    control = str(STATE / STATE_SOCKET)
    mark = f"T26-2C-{secrets.token_hex(6)}"
    started = lab.helper("task", control, SLUG, f"{mark} di hola")
    assert started["ok"], started
    task = started["task"]
    asked_there = lab.helper("task_status", control, SLUG, task)
    asked_main = lab.helper("task_status", control, "-", task)
    asked_nobody = lab.helper("task_status", control, "nadie", task)

    def ran_there() -> list[dict[str, Any]]:
        return [e for e in said_in(lab.events(OTHER), mark) if e["source"] == "exec"]

    wait(lambda: bool(ran_there()), SEEN_TIMEOUT, "the task's command in its box", lab.diagnosis)
    wait(
        lambda: bool(said_in(lab.events(OTHER, "agent_task_end"), task)),
        TASK_SECONDS + SEEN_TIMEOUT,
        "the end of the task",
        lab.diagnosis,
    )
    sentinel = f"fin-{secrets.token_hex(6)}"
    lab.in_agent(MAIN, f"/bin/true {sentinel}")
    wait(
        lambda: bool(said_in(lab.events(MAIN), sentinel)),
        SEEN_TIMEOUT,
        "the sentinel in the other's box",
        lab.diagnosis,
    )
    attack.check(
        "stopped",
        asked_there["outcome"] != "unknown"
        and asked_main["outcome"] == "unknown"
        and asked_nobody["outcome"] == "refused"
        and not _answers(lab, OTHER),
        f"la tarea solo la conoce su agente ({asked_there['outcome']}); el principal no sabe de "
        f"ella ({asked_main['outcome']}), un agente inventado se rechaza "
        f"({asked_nobody['outcome']}) y ningún modelo ha contestado a su turno",
    )
    attack.check(
        "recorded",
        said_in(lab.events(MAIN), mark) == [],
        "su orden y su final en la caja del vecino, y nada en la del otro",
    )


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
    # Past its cap it stays frozen, even if the owner says to go on: its own pause, and its own say.
    told = lab.cli("seguir", "--agente", SLUG)
    attack.check(
        "stopped",
        paused == "true"
        and "P3" in pause["details"]["conditions"]
        and state == "false"
        and wrote
        and main_usage["limit"] == main_limit == MAIN_CAP
        and lab.usage(OTHER)["limit"] == NEIGHBOUR_CAP
        and main_pauses == []
        and told.returncode == 1,
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
