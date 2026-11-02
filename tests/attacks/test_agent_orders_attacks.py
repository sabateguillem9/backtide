"""T26-6a (invariants 1, 2, 3, 6, 7): creating, starting and stopping agents, under the real unit.

Making a jail is the power of backtide, so the order has a closed shape and no agent reaches it. All
of this runs on one lab that starts with only the main agent (tests/attacks/two_agents_kit.py), so
each scenario goes on from where the last left it, as an owner would:

    make ataques PERFIL=claude-code ATK_PATH=tests/attacks/test_agent_orders_attacks.py

First the first neighbour, which restarts the service, then a third agent, which does not. No model
answers anything (invariant 8): the key is made up, and whatever calls a model first checks the
lab's cut.
"""

import errno
import ipaddress
import json
import secrets
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_two_agents_attacks import (
    MODEL,
    MODEL_HOST,
    SEEN_TIMEOUT,
    InContainer,
    _answers,
    _call_model,
    _fake_of,
    _kill_for_showing,
    _model_requests,
    _probe,
    addresses,
    members,
    said_in,
    uid_of,
)
from two_agents_kit import (
    CONFIG,
    ETC,
    MAIN,
    OTHER,
    STATE,
    THIRD,
    Agent,
    Lab,
    _write_as_root,
    open_lab,
    sh,
    sudo,
    wait,
)

from backtide.service.config import STATE_KEY, STATE_SOCKET, STATE_WEB_SOCKET

SOCKET = str(STATE / STATE_SOCKET)
SENSOR = "backtide-sensor"
CAP_MIB = 128  # the third agent's: what shows it is its own, and neither of the others'
START_TIMEOUT = 300.0
RATE = "50,1s"  # sensor-del-vecino's `cgroup_rate`: what a flood passes here, and what is left
EXEC_FLOOD = 200  # seconds: past the three unseen heartbeats (90-120 s) and the looks at the others
NOTHING_MADE = "docker", "ps", "-a", "--format", "{{.Names}}"


@pytest.fixture(scope="module")
def lab() -> Iterator[Lab]:
    found = open_lab(only_main=True)
    try:
        yield found
    finally:
        found.close()


def started_at(container: str) -> str:
    return sh("docker", "inspect", "--format", "{{.State.StartedAt}}", container).stdout.strip()


def seen_in_its_box(lab: Lab, agent: Agent) -> tuple[bool, str]:
    """What it runs reaches its box, and only then is it fair to say what did not reach another."""
    mark = f"marca-{secrets.token_hex(6)}"
    lab.in_agent(agent, f"/bin/true {mark}")
    wait(
        lambda: bool(said_in(lab.events(agent), mark)),
        SEEN_TIMEOUT,
        f"what {agent.slug} runs in its box",
        lab.diagnosis,
    )
    return True, mark


def int_of(network: Any) -> int:
    return int(network.network_address)


def _subnets_in_use() -> list[str]:
    """Those of the networks there are, of our pool: each one made takes the next one down."""
    names = sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split()
    found = []
    for name in names:
        ran = sh(
            "docker", "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
            name, check=False,
        )  # fmt: skip
        found += [subnet for subnet in ran.stdout.split() if subnet.startswith("172.29.")]
    return found


def order(lab: Lab, request: dict[str, Any]) -> dict[str, Any]:
    return lab.helper("order", SOCKET, json.dumps(request), timeout=360)


def mounted(point: Path) -> str:
    return sudo("findmnt", "-n", "-o", "FSTYPE", "--mountpoint", str(point), check=False).stdout


def listed(lab: Lab) -> dict[str, dict[str, Any]]:
    return {a["slug"]: a for a in lab.helper("agents", SOCKET)}


def whats_there(lab: Lab) -> tuple[list[str], list[str], list[str]]:
    """Containers, agents' files and what the agents' volumes folder holds: what an order made."""
    files = sudo("ls", "-A", str(ETC / "agents")).stdout.split()
    volumes = sudo("ls", "-A", str(OTHER.volume.parent)).stdout.split()
    return sorted(sh(*NOTHING_MADE).stdout.split()), files, volumes


# --- the first one -----------------------------------------------------------------------------


@scenario("primer-vecino-reinicia")
def test_the_first_neighbour_restarts_the_service_and_only_if_accepted(
    attack: Attack, lab: Lab
) -> None:
    """One agent runs none of what several need, so the first neighbour restarts the service: the
    main agent stops and starts. It has to be accepted, and without it nothing is touched."""
    before = whats_there(lab)
    main_started = started_at(MAIN.container)
    create = ("agentes", "crear", OTHER.slug, "--perfil", "claude-code", "--volumen", "10",
              "--memoria", "1g", "--nombre", "Revisor")  # fmt: skip
    asked = lab.cli(*create)
    untouched = whats_there(lab) == before and started_at(MAIN.container) == main_started
    pid = lab.show("MainPID")
    made = lab.cli(*create, "--reiniciar")
    lab.agents = [MAIN, OTHER]
    wait(lambda: lab.show("MainPID") != pid, 120, "the service to restart", lab.diagnosis)
    lab.wait_up(START_TIMEOUT)
    attack.check(
        "stopped",
        asked.returncode == 1
        and "--reiniciar" in asked.stderr
        and untouched
        and made.returncode == 0
        and started_at(MAIN.container) != main_started
        and uid_of(OTHER.container) == OTHER.uid,
        f"sin aceptarlo no se toca nada ({asked.stderr.strip()[:90]}…); aceptado, el servicio se "
        f"reinicia solo y corren los dos, el nuevo con su id ({OTHER.uid})",
    )
    created = lab.installation_events("agent_create")
    attack.check(
        "recorded",
        len(created) == 1
        and created[0]["target"] == OTHER.slug
        and "cli (uid 0" in created[0]["details"]["requested_by"]
        and lab.events(OTHER)[0]["action"] == "agent_created"
        and "cli (uid 0" in lab.events(OTHER)[0]["details"]["requested_by"],
        "system/agent_create en la caja de la instalación, con quién lo pidió, y agent_created "
        "como primer evento en la caja del agente",
    )


# --- the third, the criterion of T26-6a -----------------------------------------------------------


@scenario("crear-un-tercer-agente")
def test_a_third_agent_is_created_by_the_cli_and_the_others_go_on(attack: Attack, lab: Lab) -> None:
    pid, restarts = lab.show("MainPID"), lab.show("NRestarts")
    others_started = started_at(MAIN.container), started_at(OTHER.container)
    # The next free subnets of the pool, taken by a route of this machine, as a VPN or the LAN
    # would: the hardened service cannot ask `ip`, and it still has to see it.
    next_free = sorted((ipaddress.ip_network(subnet) for subnet in _subnets_in_use()), key=int_of)[
        0
    ]
    in_the_way = ipaddress.ip_network((int(next_free.network_address) - 256, 24))
    sudo("ip", "route", "add", str(in_the_way), "dev", "lo")
    try:
        made = lab.cli(
        "agentes", "crear", THIRD.slug, "--perfil", "claude-code", "--volumen", "10",
        "--tope-espacio", str(CAP_MIB), "--memoria", "1g", "--cpus", "1", "--nombre", "Tercero",
        )  # fmt: skip
    finally:
        sudo("ip", "route", "del", str(in_the_way), "dev", "lo")
    assert made.returncode == 0, f"{made.stdout}{made.stderr}\n{lab.diagnosis()}"
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    # On the machine: its own file system, on its own file, and a real tmpfs for its channel.
    source = sudo("findmnt", "-n", "-o", "SOURCE", "--mountpoint", str(THIRD.volume)).stdout.strip()
    device = source.removeprefix("/dev/")
    backing = sudo("cat", f"/sys/block/{device}/loop/backing_file").stdout.strip()
    subnets = [
        sh("docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}",
           name).stdout.strip()
        for name in (THIRD.network, f"backtide-{THIRD.slug}-salida")
    ]  # fmt: skip
    written = sudo("cat", str(ETC / "agents" / f"{THIRD.slug}.toml")).stdout
    usage = lab.usage(THIRD)
    seen_in_its_box(lab, THIRD)
    attack.check(
        "stopped",
        lab.show("MainPID") == pid
        and lab.show("NRestarts") == restarts
        and (started_at(MAIN.container), started_at(OTHER.container)) == others_started
        and uid_of(THIRD.container) == THIRD.uid
        and uid_of(THIRD.proxy) == THIRD.proxy_uid
        and mounted(THIRD.volume).strip() == "btrfs"
        and backing == str(THIRD.box / "volume.img")
        and mounted(THIRD.box / "proxy-channel").strip() == "tmpfs"
        and usage["limit"] == CAP_MIB * 1024**2
        and all(s.startswith("172.29.") for s in subnets)
        and str(in_the_way) not in subnets
        and members(THIRD.network) == {THIRD.container, THIRD.proxy}
        and 'profile = "claude-code"' in written
        and "image" not in written.replace("volume_image", ""),
        f"el tercero corre con sus ids ({THIRD.uid}, {THIRD.proxy_uid}), en su btrfs de {backing}, "
        f"con su tope de {CAP_MIB} MiB y sus subredes ({subnets}, sin la {in_the_way} que usa una "
        f"ruta de la máquina); el servicio es el mismo proceso "
        f"({pid}) y los otros dos no se han parado",
    )
    verified = lab.verify(THIRD)
    created = lab.installation_events("agent_create")[-1]
    attack.check(
        "recorded",
        created["target"] == THIRD.slug
        and verified["ok"]
        and lab.events(THIRD)[0]["action"] == "agent_created",
        "agent_create en la caja de la instalación y la suya propia, que verifica entera",
    )


@scenario("el-nuevo-es-protegido")
def test_the_ones_that_were_running_are_told_of_the_new_one(attack: Attack, lab: Lab) -> None:
    """The main agent and the neighbour read the installation before the third existed. A container
    of theirs that shows its volume dies the same, and for that reason."""
    killed = _kill_for_showing(lab, OTHER, THIRD.volume)
    third_goes_on = lab.running(THIRD)
    killed_main = _kill_for_showing(lab, MAIN, THIRD.volume)  # before anything restarts
    sh("docker", "rm", "--force", OTHER.container, MAIN.container)
    lab.restart()
    label = f"holds the volume of the agent {THIRD.slug}"
    problems = killed["details"]["problems"] if killed else []
    main_problems = killed_main["details"]["problems"] if killed_main else []
    theirs = [p for p in problems if label in p]
    main_theirs = [p for p in main_problems if label in p]
    attack.check(
        "stopped",
        bool(theirs) and bool(main_theirs) and third_goes_on,
        f"los que ya corrían lo saben sin reiniciarse: {theirs[:1]} y {main_theirs[:1]}",
    )
    attack.check(
        "recorded",
        killed is not None and killed_main is not None,
        "system/agent_stop {reason: exposed} en la caja de quien lo intentó",
    )
    attack.check(
        "risk",
        killed is not None
        and killed["risk"] == 3
        and killed_main is not None
        and killed_main["risk"] == 3,
        "riesgo 3, que fija el propio servicio",
    )


# --- the shape --------------------------------------------------------------------------------


GOOD = {"cmd": "agent_create", "slug": "cuarto", "profile": "claude-code", "volume_gib": 10}
BAD_ORDERS = [
    {**GOOD, "image": "alpine:latest"},
    {**GOOD, "mounts": ["/etc:/etc"]},
    {**GOOD, "privileged": True},
    {**GOOD, "volume": "/etc"},
    {**GOOD, "volume_image": "/root/imagen"},
    {**GOOD, "cap_add": ["SYS_ADMIN"]},
    {**GOOD, "profile": "custom"},
    {**GOOD, "slug": ".."},
    {**GOOD, "slug": "../salir"},
    {**GOOD, "slug": "/etc"},
    {**GOOD, "slug": "principal"},
    {**GOOD, "volume_gib": 1},
    {**GOOD, "volume_gib": 100000},
    {**GOOD, "volume_gib": True},
    {**GOOD, "workspace_mib": 1},
    {**GOOD, "memory": "100g"},
    {**GOOD, "cpus": 64},
    {**GOOD, "daily_usd": "-1"},
    {**GOOD, "name": "con\nsalto"},
    {"cmd": "agent_stop", "agent": "../principal"},
    {"cmd": "agent_start", "agent": "/etc"},
    {"cmd": "agent_stop", "agent": OTHER.slug, "force": True},
]


@scenario("orden-fuera-de-lista")
def test_an_order_outside_its_shape_touches_nothing(attack: Attack, lab: Lab) -> None:
    before = whats_there(lab), len(lab.installation_events())
    replies = [order(lab, bad) for bad in BAD_ORDERS]
    outcomes = {reply["outcome"] for reply in replies}
    cli_custom = lab.cli("agentes", "crear", "cuarto", "--perfil", "custom", "--volumen", "10")
    # The control: what has its shape does get as far as the machine's checks. A disk this size
    # has no room for it, so nothing is made here either.
    control = order(lab, {**GOOD, "volume_gib": 50, "memory": "512m", "proxy_memory": "256m"})
    after = whats_there(lab), len(lab.installation_events())
    attack.check(
        "stopped",
        outcomes == {"invalid"}
        and cli_custom.returncode == 2
        and control["outcome"] == "refused"
        and "disco" in control["message"]
        and after == before,
        f"las {len(BAD_ORDERS)} órdenes dan `invalid` y `docker ps`, los archivos y los volúmenes "
        f"no cambian ({len(before[0][0])} contenedores); la misma orden con su forma sí llega a la "
        f"comprobación: {control['message'][:70]}…; ninguna llega a la caja de la instalación",
    )


@scenario("ordenes-fuera-de-la-web")
def test_a_live_session_of_the_web_reaches_none_of_these_orders(attack: Attack, lab: Lab) -> None:
    """Against the real narrow socket, with the group of the web and a live session: without the
    session, an order added to its list of changes would be refused too. T26-6b adds them, behind
    a key just touched, and this scenario has to change with it."""
    before = whats_there(lab)
    frozen_before = sh(
        "docker", "inspect", "--format", "{{.State.Paused}}", OTHER.container
    ).stdout.strip()  # fmt: skip
    token = lab.helper("link", SOCKET)["token"]
    session = {"session": "<session>", "_why": True}
    orders = [
        {**GOOD, **session},
        {"cmd": "agent_start", "agent": OTHER.slug, **session},
        {"cmd": "agent_stop", "agent": OTHER.slug, **session},
        {"cmd": "agent_pause", "agent": OTHER.slug, **session},
        {"cmd": "agent_resume", "agent": OTHER.slug, **session},
    ]
    nobody = int(sh("id", "-u", "nobody").stdout)
    answers = _probe(
        nobody, lab.web_gid, {"cmd": "session_open", "token": token}, *orders,
        {"cmd": "holds"},
    )  # fmt: skip
    opened, *refused, control = answers
    frozen = sh(
        "docker", "inspect", "--format", "{{.State.Paused}}", OTHER.container
    ).stdout.strip()
    attack.check(
        "stopped",
        opened["ok"] is True
        and control["ok"] is True
        and len(refused) == len(orders)
        and all(a["outcome"] == "refused" and "socket de la web" in a["why"] for a in refused)
        and whats_there(lab) == before
        and frozen == frozen_before == "false"
        and lab.running(OTHER),
        f"con una sesión viva, las {len(orders)} órdenes se rechazan por no estar en su lista "
        f"({refused[0]}), y `holds`, igual que ellas, contesta: {control}",
    )


@scenario("no-cabe-en-la-maquina")
def test_what_does_not_fit_is_refused_saying_how_much(attack: Attack, lab: Lab) -> None:
    before = whats_there(lab)
    too_much = lab.cli(
        "agentes", "crear", "cuarto", "--perfil", "claude-code", "--volumen", "10",
        "--memoria", "4g", "--memoria-proxy", "1g",
    )  # fmt: skip
    attack.check(
        "stopped",
        too_much.returncode == 1
        and "memoria" in too_much.stderr
        and "faltan" in too_much.stderr
        and whats_there(lab) == before,
        f"se niega y dice cuánto falta: {too_much.stderr.strip()[:110]}…",
    )


# --- no agent gets here ------------------------------------------------------------------------


LISTENER_PORT = 18765
LISTENER = """
import socket, sys, time
with socket.socket() as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", int(sys.argv[1])))
    sock.listen()
    time.sleep(300)
"""
LOOK_AROUND = """
import json, os, socket, stat, sys
names = ("web.sock", "terminal.sock", "control.sock", "docker.sock", "backtide.lock")
mine = "/tmp/testigo-del-escenario.sock"
with socket.socket(socket.AF_UNIX) as witness:
    witness.bind(mine)
    sockets, named = [], []
    for root, folders, files in os.walk("/"):
        folders[:] = [f for f in folders if os.path.join(root, f) not in ("/proc", "/sys")]
        for name in files:
            path = os.path.join(root, name)
            try:
                if stat.S_ISSOCK(os.lstat(path).st_mode):
                    sockets.append(path)
            except OSError:
                continue
            if name in names:
                named.append(path)
os.unlink(mine)
seen = [p for p in sys.argv[1].split(",") if os.path.lexists(p)]
reach = {}
for address in sys.argv[2].split(","):
    host, port = address.rsplit(":", 1)
    with socket.socket() as sock:
        sock.settimeout(3)
        reach[address] = sock.connect_ex((host, int(port)))
print(json.dumps({"sockets": sockets, "named": named, "seen": seen, "reach": reach}))
"""


@scenario("agente-crea-agente")
def test_no_agent_reaches_the_orders_that_make_agents(attack: Attack, lab: Lab) -> None:
    """From inside the agents, also the one just created: nothing of the service's is there, no way
    to Docker, and neither its web's port nor its neighbours answer. And the way out is the proxy:
    what it tries directly fails, and its own proxy is the control."""
    forbidden = [
        SOCKET, str(STATE / STATE_WEB_SOCKET), str(STATE / "terminal.sock"), str(STATE), str(ETC),
        str(CONFIG), "/var/run/docker.sock", "/run/docker.sock", "/etc/backtide",
    ]  # fmt: skip
    results: dict[str, dict[str, Any]] = {}
    machine = sh("hostname", "-I").stdout.split()[0]  # its network has no gateway on it
    # Something that does listen on the machine, so that "does not reach" is not "nobody there".
    listener = subprocess.Popen([sys.executable, "-c", LISTENER, str(LISTENER_PORT)])  # noqa: S603
    wait(
        lambda: subprocess.run(  # noqa: S603
            [sys.executable, "-c", f"import socket; socket.create_connection(({machine!r}, "
             f"{LISTENER_PORT}), 2)"], check=False, capture_output=True,
        ).returncode == 0,
        30,
        "the listener on the machine, from the machine",
    )  # fmt: skip
    for agent in (THIRD, OTHER):
        own = addresses(agent.proxy)[agent.network]
        neighbour = MAIN if agent is OTHER else OTHER
        targets = [
            f"{own}:8080",
            f"{machine}:{LISTENER_PORT}",  # what listens on the machine
            f"{machine}:8765",  # the web's port there
            f"{machine}:2375",  # Docker's own port
            "1.1.1.1:443",  # the way out without the proxy
            *(f"{ip}:8080" for ip in addresses(neighbour.proxy).values()),
            *(f"{ip}:8765" for ip in addresses(neighbour.container).values()),
        ]
        ran = lab.in_agent(
            agent,
            f"python3 -c '{LOOK_AROUND}' {','.join(forbidden)} {','.join(targets)}",
            timeout=120,
        )
        assert ran.returncode == 0, ran.stderr
        results[agent.slug] = json.loads(ran.stdout.strip().splitlines()[-1])
        results[agent.slug]["own"] = f"{own}:8080"
    listener.send_signal(signal.SIGTERM)
    listener.wait(10)
    internal = {
        agent.slug: sh(
            "docker", "network", "inspect", "--format", "{{.Internal}}", agent.network
        ).stdout.strip()
        for agent in (THIRD, OTHER)
    }  # fmt: skip
    bad = []
    for slug, found in results.items():
        if not any("testigo" in p for p in found["sockets"]):
            bad.append(f"{slug}: the search does not find even the socket it made")
        extra = [p for p in found["sockets"] if "testigo" not in p]
        if found["named"] or found["seen"] or extra:
            bad.append(f"{slug}: {found['named']} {found['seen']} {extra}")
        reach = dict(found["reach"])
        if reach.pop(found["own"]) != 0:
            bad.append(f"{slug}: its own proxy does not answer, so this proves nothing")
        # No route at all: not a wall that happens to be there, as the lab's cut would be.
        if any(code != errno.ENETUNREACH for code in reach.values()):
            bad.append(f"{slug}: {reach}")
    mounts = sh("docker", "inspect", "--format", "{{json .Mounts}}", THIRD.container).stdout
    jail_of = "{{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}} {{.HostConfig.Privileged}}"
    capabilities = sh("docker", "inspect", "--format", jail_of, THIRD.container).stdout.strip()
    main_capabilities = sh("docker", "inspect", "--format", jail_of, MAIN.container).stdout.strip()
    attack.check(
        "stopped",
        not bad
        and set(internal.values()) == {"true"}
        and not any(name in mounts for name in ("blackbox.db", STATE_KEY, "docker.sock", "keys"))
        and capabilities == main_capabilities
        and capabilities.endswith("false"),
        f"desde dentro no hay ningún socket del servicio ni de Docker; ni lo que escucha en la "
        f"máquina, ni Docker, ni los vecinos, ni internet tienen ruta (ENETUNREACH), y su proxy sí "
        f"contesta, que es el control ({bad or 'bien'}); sus redes son internas, y su contenedor "
        f"tiene lo mismo que el principal ({capabilities})",
    )


# --- stopping and starting -----------------------------------------------------------------------


@scenario("parar-y-arrancar")
def test_one_agent_stops_and_starts_and_the_others_never_notice(attack: Attack, lab: Lab) -> None:
    others_started = started_at(MAIN.container), started_at(OTHER.container)
    pid = lab.show("MainPID")
    tag = f"parar-{secrets.token_hex(6)}"
    attack.run_script(
        InContainer(lab, THIRD), "peticion_delete_retenida", "delete", "cubos.ejemplo.test",
        f"/{tag}/v1", "5",
    )  # fmt: skip
    wait(
        lambda: bool(said_in(lab.events(THIRD, "held"), tag)),
        SEEN_TIMEOUT,
        "the request held at its gate",
        lab.diagnosis,
    )
    hold_id = said_in(lab.events(THIRD, "held"), tag)[0]["details"]["hold_id"]
    stopped = lab.cli("agentes", "parar", THIRD.slug)
    lab.agents = [MAIN, OTHER]
    gone = sh("docker", "ps", "--format", "{{.Names}}").stdout.split()
    ended = said_in(lab.events(THIRD, "expired"), hold_id)
    state = listed(lab)[THIRD.slug]
    again = lab.cli("agentes", "parar", THIRD.slug)
    main_refused = lab.cli("agentes", "parar", "principal")
    # It stays stopped across a restart of the service, and with no volume problem of its own.
    lab.restart()
    seen_in_its_box(lab, OTHER)  # by now, one that was going to start would have
    still = listed(lab)[THIRD.slug]
    after_restart = not lab.running(THIRD) and "stays stopped" in lab.journal()
    others_again = started_at(MAIN.container), started_at(OTHER.container)

    started = lab.cli("agentes", "arrancar", THIRD.slug)
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    seen_in_its_box(lab, THIRD)
    paused = lab.cli("agentes", "pausar", THIRD.slug)
    frozen = sh(
        "docker", "inspect", "--format", "{{.State.Paused}}", THIRD.container
    ).stdout.strip()
    main_frozen = sh(
        "docker", "inspect", "--format", "{{.State.Paused}}", MAIN.container
    ).stdout.strip()
    resumed = lab.cli("agentes", "seguir", THIRD.slug)
    thawed = sh(
        "docker", "inspect", "--format", "{{.State.Paused}}", THIRD.container
    ).stdout.strip()
    verified = lab.verify(THIRD)
    wrong = _wrong(
        stopped=stopped.returncode == 0,
        third_gone=THIRD.container not in gone and THIRD.proxy not in gone,
        others_there=MAIN.container in gone and OTHER.container in gone,
        listed=state["watched"] is False and state["state"] == "stopped_by_owner",
        said_already=again.returncode == 0 and "ya está parado" in again.stdout,
        main_refused=main_refused.returncode == 1,
        stays_after_restart=still["state"] == "stopped_by_owner" and after_restart,
        started=started.returncode == 0,
        frozen=paused.returncode == 0 and frozen == "true" and main_frozen == "false",
        thawed=resumed.returncode == 0 and thawed == "false",
        restart_was_one=others_again != others_started and lab.show("MainPID") != pid,
        running=lab.running(MAIN) and lab.running(OTHER),
    )
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}se para solo (su contenedor y su proxy, los otros siguen), no vuelve tras "
        "reiniciar el servicio, arranca, se congela sin tocar al principal y sigue; el principal "
        "no se para desde aquí",
    )
    attack.check(
        "recorded",
        bool(lab.installation_events("agent_stop_asked"))
        and bool(lab.installation_events("agent_start_asked"))
        and bool(lab.events(THIRD, "agent_stop_asked"))
        and verified["ok"],
        "agent_stop_asked y agent_start_asked en la caja de la instalación, con quién, y en "
        "la suya",
    )
    attack.check(
        "held",
        bool(ended) and not said_in(lab.events(THIRD, "approved"), hold_id),
        f"lo retenido ({hold_id}) termina rechazado al pararlo: nadie dijo que sí",
    )


@scenario("parado-sigue-vivo")
def test_stopped_is_what_docker_says_never_the_mark(attack: Attack, lab: Lab) -> None:
    """A container alive with the mark on: a stop that did not take, a service killed half way.
    Nobody is watching it. At the service's start it is stopped, and by asking to stop it too."""
    assert lab.cli("agentes", "parar", THIRD.slug).returncode == 0
    lab.agents = [MAIN, OTHER]
    told = len(lab.installation_events("agent_stop"))
    # By asking, with the service up.
    sh("docker", "start", THIRD.container)
    alive = lab.running(THIRD)
    asked = lab.cli("agentes", "parar", THIRD.slug)
    after_asking = lab.running(THIRD)
    # At its start, with the service down meanwhile.
    lab.stop()
    sh("docker", "start", THIRD.container)
    alive_again = lab.running(THIRD)
    lab.start()
    wait(
        lambda: not lab.running(THIRD),
        SEEN_TIMEOUT,
        "the service to stop what runs with nobody watching",
        lab.diagnosis,
    )
    recorded = lab.installation_events("agent_stop")[told:]
    assert lab.cli("agentes", "arrancar", THIRD.slug).returncode == 0
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    attack.check(
        "stopped",
        alive and alive_again and not after_asking and asked.returncode == 0,
        "con la marca puesta y el contenedor vivo, pedir que pare lo para de verdad, y al arrancar "
        "el servicio también: «parado» lo dice Docker",
    )
    attack.check(
        "recorded",
        len(recorded) == 2
        and all(e["target"] == THIRD.slug for e in recorded)
        and all(e["details"]["reason"] == "unsupervised" for e in recorded),
        "system/agent_stop {reason: unsupervised} en la caja de la instalación, cada vez",
    )
    attack.check(
        "risk",
        bool(recorded) and all(e["risk"] == 2 for e in recorded),
        "riesgo 2, que fija el propio servicio",
    )


@scenario("parar-con-una-llamada-en-vuelo")
def test_what_is_in_flight_when_it_stops_is_charged(attack: Attack, lab: Lab) -> None:
    """A model call hanging at the lab's cut (invariant 8), and the agent stopped. It never got to
    a provider, so it costs nothing (M1), and nothing of it stays in flight. What `forget_all` adds,
    a call that did get out and whose answer never comes, cannot happen behind the cut: that is
    tests/test_service_fleet.py's, and this is what a stop does with a call in the real proxy."""
    assert lab.network_cut(), "invariant 8: no model call without the lab's network cut"
    key = _fake_of(lab, THIRD)
    source = (Path(__file__).parent / "scripts" / "tope_de_gasto.py").read_text()
    before = _model_requests(lab, THIRD)
    spent = lab.helper("budget", SOCKET)["installation"]["agents"][THIRD.slug]["day_micro"]
    sh(
        "docker", "exec", "-d", THIRD.container, "python3", "-c", source, MODEL_HOST, key, MODEL,
        "1",
    )  # fmt: skip
    wait(
        lambda: _model_requests(lab, THIRD) > before,
        SEEN_TIMEOUT,
        "the call at the proxy",
        lab.diagnosis,
    )
    flying = lab.helper("budget", SOCKET, THIRD.slug)  # the control: it was in flight, reserved
    assert lab.cli("agentes", "parar", THIRD.slug).returncode == 0
    lab.agents = [MAIN, OTHER]
    stopped = lab.helper("budget", SOCKET)["installation"]["agents"][THIRD.slug]["day_micro"]
    assert lab.cli("agentes", "arrancar", THIRD.slug).returncode == 0
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    after = lab.helper("budget", SOCKET, THIRD.slug)
    attack.check(
        "stopped",
        flying["inflight"] == 1
        and flying["reserved_micro"] > 0
        and stopped == spent
        and after["inflight"] == 0
        and after["reserved_micro"] == 0
        and not _answers(lab, THIRD),
        f"en vuelo con {flying['reserved_micro']} µ$ apartados; parado, no queda nada en vuelo ni "
        f"apartado, y como no llegó a ningún proveedor no se cobra ({spent} antes y {stopped} "
        "después). Cobrar lo que sí salió, con `forget_all`, se prueba en el Mac",
    )
    attack.check(
        "recorded",
        _model_requests(lab, THIRD) > before,
        "llm/request en su caja: la llamada queda aunque se pare",
    )


@scenario("reinicio-de-la-maquina")
def test_after_a_reboot_the_service_mounts_what_is_gone(attack: Attack, lab: Lab) -> None:
    """A reboot takes the transient mounts away. Their mount units are gone with it: the same, from
    outside, with the service stopped."""
    lab.stop()
    points = [THIRD.volume, THIRD.box / "proxy-channel", OTHER.volume, OTHER.box / "proxy-channel"]
    for point in points:
        sudo("umount", str(point))
    away = [mounted(point) for point in points]
    lab.start()
    back = {str(point): mounted(point).strip() for point in points}
    seen_in_its_box(lab, THIRD)
    seen_in_its_box(lab, OTHER)
    attack.check(
        "stopped",
        not any(away)
        and all(kind in ("btrfs", "tmpfs") for kind in back.values())
        and lab.running(THIRD)
        and lab.usage(THIRD)["limit"] == CAP_MIB * 1024**2,
        f"sin nada montado, al arrancar el servicio vuelven los dos volúmenes y sus canales "
        f"({sorted(set(back.values()))}) y los agentes siguen con su tope",
    )


# --- what must not run ---------------------------------------------------------------------------


@scenario("volumen-sin-montar")
def test_a_volume_that_is_not_mounted_never_runs_on_the_machines_disk(
    attack: Attack, lab: Lab
) -> None:
    """The bug of T26-2b's review: this VM's disk is btrfs, so a plain folder would have worked,
    with no cap at all. Three ways of it not being its volume, each with what it says: with a
    tmpfs and with another file's btrfs on the folder, `volume_problem` answers, and without its
    image nothing can be mounted at all."""
    assert sudo("stat", "-f", "-c", "%T", str(THIRD.volume.parent)).stdout.strip() == "btrfs"
    image = THIRD.box / "volume.img"
    away = THIRD.box / "imagen-apartada"
    other_image = THIRD.box.parent / "otra-imagen.img"
    assert lab.cli("agentes", "parar", THIRD.slug).returncode == 0
    lab.agents = [MAIN, OTHER]
    sudo("umount", str(THIRD.volume))
    failures = len(lab.installation_events("agent_failed"))

    def refused_with() -> tuple[int, str, bool]:
        ran = lab.cli("agentes", "arrancar", THIRD.slug)
        return ran.returncode, ran.stderr, lab.running(THIRD)

    sudo("mount", "-t", "tmpfs", "tmpfs", str(THIRD.volume))
    a_tmpfs = refused_with()
    sudo("umount", str(THIRD.volume))
    sudo("truncate", "-s", "1G", str(other_image))
    sudo("mkfs.btrfs", "-q", str(other_image))
    sudo("mount", "-o", "loop", str(other_image), str(THIRD.volume))
    another_image = refused_with()
    sudo("umount", str(THIRD.volume))
    sudo("rm", "-f", str(other_image))
    sudo("mv", str(image), str(away))
    try:
        no_image = refused_with()
        left = sudo("ls", "-A", str(THIRD.volume)).stdout.split()
        failed = lab.installation_events("agent_failed")[failures:]
        goes_on = lab.running(MAIN) and lab.running(OTHER)
    finally:
        sudo("mv", str(away), str(image))
    # With its file saying no cap at all it is not even read: the whole service would not start.
    probe = ETC / "agents" / "sintope.toml"
    _write_as_root(
        probe,
        f'number = 9\nvolume = "{THIRD.volume.parent / "sintope"}"\n[agent]\n'
        'profile = "claude-code"\n',
    )
    no_cap = lab.cli("agentes", "lista")  # only reads the socket: it says, and goes on
    said = no_cap.stderr
    sudo("rm", "-f", str(probe))
    assert lab.cli("agentes", "arrancar", THIRD.slug).returncode == 0
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    attack.check(
        "stopped",
        not (
            wrong := _wrong(
                a_tmpfs=a_tmpfs[0] == 1 and "is a tmpfs" in a_tmpfs[1] and not a_tmpfs[2],
                another_image=(
                    another_image[0] == 1
                    and "not from" in another_image[1]
                    and not another_image[2]
                ),
                no_image=no_image[0] == 1 and "image" in no_image[1] and not no_image[2],
                nothing_written=left == [],
                others_go_on=goes_on,
                no_cap_said="workspace_limit" in said,
            )
        ),
        f"{wrong or ''}con un tmpfs ({a_tmpfs[1].strip()[-70:]}), con el btrfs de otro archivo "
        f"({another_image[1].strip()[-70:]}) y sin su imagen no arranca; no se ha escrito nada "
        f"({left}) y los otros siguen; y un archivo sin tope no se lee",
    )
    attack.check(
        "recorded",
        len(failed) == 3 and {e["target"] for e in failed} == {THIRD.slug},
        "system/agent_failed en la caja de la instalación, con el motivo",
    )
    attack.check(
        "risk",
        bool(failed) and failed[0]["risk"] == 2,
        "riesgo 2, que fija el propio servicio",
    )


@scenario("vecino-que-no-arranca")
def test_a_neighbour_that_cannot_start_stops_nobody_else(attack: Attack, lab: Lab) -> None:
    """Under the real unit, at a real start of the service: its channel cannot be mounted, because
    someone left a file where its folder goes. It is told, and the others run."""
    channel = THIRD.box / "proxy-channel"
    lab.stop()
    sudo("umount", str(channel))
    sudo("rmdir", str(channel))
    sudo("touch", str(channel))
    failures = len(lab.installation_events("agent_failed"))
    lab.agents = [MAIN, OTHER]
    try:
        lab.start()
        wait(
            lambda: len(lab.installation_events("agent_failed")) > failures,
            SEEN_TIMEOUT,
            "the neighbour's failure in the installation's box",
            lab.diagnosis,
        )
        failed = lab.installation_events("agent_failed")[failures:]
        state = listed(lab)[THIRD.slug]
        container = lab.running(THIRD)
        seen_in_its_box(lab, MAIN)
        seen_in_its_box(lab, OTHER)
        pid = lab.show("MainPID")
    finally:
        sudo("rm", "-f", str(channel))
    started = lab.cli("agentes", "arrancar", THIRD.slug)  # and it can be asked again
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    attack.check(
        "stopped",
        not container
        and state["watched"] is False
        and lab.show("MainPID") == pid
        and lab.running(MAIN)
        and lab.running(OTHER)
        and started.returncode == 0,
        f"el tercero no corre, el principal y el otro sí y se graban, el servicio sigue en "
        f"{pid}, y "
        "arreglado el motivo, arranca sin reiniciar nada",
    )
    attack.check(
        "recorded",
        [event["target"] for event in failed] == [THIRD.slug]
        and failed[0]["details"]["error"] != "",
        f"system/agent_failed en la caja de la instalación: {failed[0]['details']['error'][:120]}",
    )
    attack.check("risk", failed[0]["risk"] == 2, "riesgo 2, que fija el propio servicio")


# --- what is everyone's --------------------------------------------------------------------------


@scenario("clave-quitada-al-vecino")
def test_a_key_taken_away_reaches_every_proxy_at_once(attack: Attack, lab: Lab) -> None:
    """The keys are the machine's: quitting one in Settings stops it in every agent's proxy, with
    no restart. Each is refused at its proxy: the cut is not what stops it."""
    assert lab.network_cut(), "invariant 8: no model call without the lab's network cut"
    pid = lab.show("MainPID")
    keys = {agent.slug: _fake_of(lab, agent) for agent in (MAIN, OTHER, THIRD)}
    before = _call_model(attack, lab, THIRD, keys[THIRD.slug], 1)
    real = sudo("cat", str(STATE / "keys" / "anthropic.key")).stdout.strip()
    cleared = lab.helper("clear_key", SOCKET, "anthropic")
    try:
        after = {
            agent.slug: _call_model(attack, lab, agent, keys[agent.slug], 1)
            for agent in (MAIN, OTHER, THIRD)
        }
        wait(
            lambda: all(
                said_in(lab.events(agent, "blocked"), "no_key") for agent in (MAIN, OTHER, THIRD)
            ),
            SEEN_TIMEOUT,
            "each refusal in its box",
            lab.diagnosis,
        )
    finally:
        restored = lab.helper("set_key", SOCKET, "anthropic", real)
    back = _call_model(attack, lab, THIRD, keys[THIRD.slug], 1)
    statuses = {slug: [c["status"] for c in calls] for slug, calls in after.items()}
    attack.check(
        "stopped",
        cleared["ok"]
        and restored["ok"]
        and all(status == [400] for status in statuses.values())
        and before[0]["status"] != statuses[THIRD.slug][0]
        and back[0]["status"] == before[0]["status"]
        and lab.show("MainPID") == pid
        and not _answers(lab, THIRD),
        f"sin clave, los tres se rechazan en su proxy ({statuses}, antes {before[0]['status']}), "
        f"sin reiniciar nada; con ella otra vez, {back[0]['status']}. {MODEL_HOST} no contesta a "
        "nadie: el corte del laboratorio",
    )
    attack.check(
        "recorded",
        all(said_in(lab.events(agent, "blocked"), "no_key") for agent in (MAIN, OTHER, THIRD)),
        "llm/blocked {no_key} en la caja de cada uno",
    )


@scenario("sonda-del-vecino")
def test_a_probe_made_up_by_an_agent_proves_nothing_for_anyone(attack: Attack, lab: Lab) -> None:
    """The sensor proves it sees an agent with a marked ``/bin/true``. An agent that makes one up
    runs a command like any other: it is recorded as that, in its own box, and it says nothing of
    any other. Each reader keeps only the lines of its own container."""
    hex_part = secrets.token_hex(16)
    fake = f"backtide-ready-{hex_part}"
    heartbeat = f"backtide-hb-{secrets.token_hex(16)}"

    def as_commands(agent: Agent, marker: str) -> list[dict[str, Any]]:
        """The ``/bin/true`` itself, with no shell around it to carry the marker."""
        return [
            event
            for event in lab.events(agent, "exec")
            if event["target"].endswith("/true") and event["details"].get("argv") == marker
        ]

    # Without a shell: a `sh -c` would have the marker in its own command line, and it would be
    # found even if the reader took the /bin/true for a probe.
    for marker in (fake, heartbeat):
        sh("docker", "exec", THIRD.container, "/bin/true", marker)
    wait(
        lambda: as_commands(THIRD, fake) and as_commands(THIRD, heartbeat),
        SEEN_TIMEOUT,
        "the made-up probes as commands of whoever ran them",
        lab.diagnosis,
    )
    seen_in_its_box(lab, OTHER)  # each a sentinel: its reader has gone past them by now
    seen_in_its_box(lab, MAIN)
    crossed = [
        *said_in(lab.events(OTHER), fake),
        *said_in(lab.events(MAIN), fake),
        *said_in(lab.events(OTHER), heartbeat),
        *said_in(lab.events(MAIN), heartbeat),
    ]
    attack.check(
        "stopped",
        crossed == [],
        "la sonda inventada no es de nadie más: las líneas de un contenedor solo las lee su "
        "lector, y los otros dos se siguen viendo",
    )
    attack.check(
        "recorded",
        len(as_commands(THIRD, fake)) == 1 and len(as_commands(THIRD, heartbeat)) == 1,
        "el /bin/true queda grabado una vez, como una orden más, en la caja de quien lo lanzó: un "
        "marcador que nadie espera no se toma por una sonda",
    )


FLOOD = """
import os, socket, sys, time
kind, seconds = sys.argv[1], float(sys.argv[2])
for _ in range(7):
    if os.fork() == 0:
        break
until, count = time.monotonic() + seconds, 0
while time.monotonic() < until:
    if kind == "exec":
        os.waitpid(os.spawnv(os.P_NOWAIT, "/bin/true", ["/bin/true"]), 0)
    else:
        with socket.socket() as sock:
            sock.setblocking(False)
            sock.connect_ex(("127.0.0.1", 9))
    count += 1
print(count)
"""


@scenario("sensor-del-vecino")
def test_a_neighbour_that_fails_its_sensor_blinds_nobody_else(attack: Attack, lab: Lab) -> None:
    """One Tetragon for everyone. A launches commands past what the kernel lets through for its
    cgroup (`cgroup_rate`), so its own heartbeat goes unseen: its sensor is down, and that is its
    problem. Tetragon stays as it is and the others go on being seen, while the flood goes on. (Its
    process limit does not do it: `docker exec` joins the cgroup, not subject to it: measured.)
    Then a connect flood, which no limit holds: what Tetragon loses is everyone's, and everyone's
    box says so (docs/47, 6.6). Then Tetragon is killed, and it comes back for everyone. All of it
    with `required = false`, and with the limit lowered: 8 processes in this VM do not pass the 1000
    a second of a real machine, measured. What is proven holds for any number: one's throttle is
    its own, and one's failed heartbeat does not take Tetragon away."""
    config = sudo("cat", str(CONFIG)).stdout
    _write_as_root(CONFIG, f'{config}[sensor]\ncgroup_rate = "{RATE}"\n')
    lab.restart()
    try:
        _flood_and_kill_the_sensor(attack, lab)
    finally:
        _write_as_root(CONFIG, config)
        lab.restart()


def _flood_and_kill_the_sensor(attack: Attack, lab: Lab) -> None:
    tetragon = started_at(SENSOR)
    agents = (MAIN, OTHER, THIRD)

    def gaps(agent: Agent, kind: str) -> list[dict[str, Any]]:
        return [e for e in lab.events(agent, "sensor_gap") if e["details"].get("kind") == kind]

    def heartbeat_down() -> list[dict[str, Any]]:
        return [
            e for e in lab.events(THIRD, "sensor_down") if e["details"].get("reason") == "heartbeat"
        ]

    throttles = {a.slug: len(gaps(a, "throttle")) for a in agents}
    lost = {a.slug: len(gaps(a, "kernel_lost")) for a in agents}
    others_failing = len(lab.events(OTHER, "sensor_down")) + len(lab.events(MAIN, "sensor_down"))
    down_before = len(heartbeat_down())
    sh("docker", "exec", "-d", THIRD.container, "python3", "-c", FLOOD, "exec", str(EXEC_FLOOD))
    began = time.monotonic()
    wait(lambda: len(heartbeat_down()) > down_before, 170, "its heartbeats unseen", lab.diagnosis)
    seen_in_its_box(lab, OTHER)
    seen_in_its_box(lab, MAIN)
    during = time.monotonic() - began < EXEC_FLOOD  # the others were looked at under the flood
    same = started_at(SENSOR) == tetragon
    new_throttles = {a.slug: len(gaps(a, "throttle")) - throttles[a.slug] for a in agents}
    others_quiet = (
        len(lab.events(OTHER, "sensor_down")) + len(lab.events(MAIN, "sensor_down"))
    ) == others_failing
    wait(
        lambda: _seen_again(lab, THIRD),
        EXEC_FLOOD + 90,
        "its flood to end and it to be seen again",
        lab.diagnosis,
    )
    ran = lab.in_agent(THIRD, f"python3 -c '{FLOOD}' connect 25 > /tmp/f; cat /tmp/f", timeout=120)
    flood = sum(int(n) for n in ran.stdout.split())
    assert flood > 0, ran.stderr
    wait(
        lambda: all(len(gaps(a, "kernel_lost")) > lost[a.slug] for a in agents),
        100,
        "the losses told in every box: the heartbeat of each reads them",
        lab.diagnosis,
    )
    told = {a.slug: gaps(a, "kernel_lost")[-1]["details"]["count"] for a in agents}
    print(f"sensor-del-vecino: {flood} connections in 25 s, lost {told}")
    seen_in_its_box(lab, OTHER)
    seen_in_its_box(lab, MAIN)
    sh("docker", "kill", SENSOR)
    wait(
        lambda: _running(SENSOR) and started_at(SENSOR) != tetragon,
        180,
        "Tetragon to be back",
        lab.diagnosis,
    )
    for agent in agents:
        wait(
            lambda agent=agent: _seen_again(lab, agent),
            180,
            f"{agent.slug} to be seen again",
            lab.diagnosis,
        )
    attack.check(
        "stopped",
        not (
            wrong := _wrong(
                same_tetragon=same,
                others_looked_at_under_the_flood=during,
                its_throttle_alone=(
                    new_throttles[THIRD.slug] > 0
                    and new_throttles[OTHER.slug] == 0
                    and new_throttles[MAIN.slug] == 0
                ),
                others_quiet=others_quiet,
            )
        ),
        f"{wrong or ''}con `cgroup_rate` {RATE} y `required = false`: el latido de uno no se ve, "
        f"Tetragon no se toca, el límite es solo suyo ({new_throttles}) y los otros se ven; con "
        f"{flood} conexiones en 25 s, cada caja dice lo perdido ({told}); matado Tetragon, vuelve "
        "y los tres se vuelven a ver",
    )
    attack.check(
        "recorded",
        bool(heartbeat_down()) and others_quiet,
        "system/sensor_down {heartbeat} en la caja de quien falla y en las otras no, antes del "
        "`docker kill`; system/sensor_gap {kernel_lost} en las tres",
    )


def _wrong(**conditions: bool) -> list[str]:
    return [name for name, holds in conditions.items() if not holds]


def _running(container: str) -> bool:
    ran = sh("docker", "inspect", "--format", "{{.State.Running}}", container, check=False)
    return ran.stdout.strip() == "true"


def _seen_again(lab: Lab, agent: Agent) -> bool:
    mark = f"otra-vez-{secrets.token_hex(6)}"
    try:
        lab.in_agent(agent, f"/bin/true {mark}")
    except subprocess.TimeoutExpired:
        return False
    time.sleep(3)
    return bool(said_in(lab.events(agent), mark))
