"""T26-6c (invariants 1, 2, 4, 6, 7): deleting an agent, its trash and what stays, under the unit.

Each scenario goes on from where the last left it, on one lab, as an owner would:

    make ataques PERFIL=claude-code ATK_PATH=tests/attacks/test_agent_delete_attacks.py

No model answers anything and nothing leaves the VM (invariant 8). The orders are on root's socket
alone: T26-6b adds ``agent_delete`` to the web's, behind a key just touched, and
``borrar-sin-esperar`` has to change with it. Emptying never goes there.
"""

import json
import secrets
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_agent_orders_attacks import (
    CAP_MIB,
    SOCKET,
    START_TIMEOUT,
    _running,
    _wrong,
    listed,
    mounted,
    order,
    seen_in_its_box,
    started_at,
)
from test_two_agents_attacks import SEEN_TIMEOUT, InContainer, _probe, said_in, uid_of
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

from backtide.jail import identity
from backtide.service.config import RETIRED_MARK, SAVED_AGENT_FILE, STATE_DB
from backtide.setup import images

IN_THE_WAY = "backtide-lab-estorbo"
READ_AS_THE_WEB = """
import sqlite3, sys
connection = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
print(connection.execute("SELECT count(*) FROM events").fetchone()[0])
"""
kept: dict[str, Any] = {}  # what one scenario saw, for the next to compare


@pytest.fixture(scope="module")
def lab() -> Iterator[Lab]:
    found = open_lab()
    try:
        yield found
    finally:
        sh("docker", "rm", "--force", IN_THE_WAY, check=False)
        found.close()


def mark_of(agent: Agent) -> dict[str, Any]:
    return json.loads(sudo("cat", str(agent.box / RETIRED_MARK)).stdout)


def file_of(agent: Agent) -> Path:
    return ETC / "agents" / f"{agent.slug}.toml"


def there(path: Path) -> bool:
    return sudo("test", "-e", str(path), check=False).returncode == 0


def networks_of(agent: Agent) -> list[str]:
    names = sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split()
    return [n for n in names if n in (agent.network, identity.egress_network(agent.slug))]


def mode_of(path: Path) -> int:
    return stat.S_IMODE(int(sudo("stat", "-c", "%f", str(path)).stdout.strip(), 16))


def read_as_the_web(lab: Lab, agent: Agent) -> str:
    """As the web's group reads it: it may go through the folder, not write in it."""
    nobody = sh("id", "-u", "nobody").stdout.strip()
    ran = sudo(
        "setpriv", "--reuid", nobody, "--regid", str(lab.web_gid), "--clear-groups", "--",
        "python3", "-I", "-c", READ_AS_THE_WEB, str(agent.box / STATE_DB),
        check=False, timeout=60,
    )  # fmt: skip
    return ran.stdout.strip() or ran.stderr.strip()[-200:]


def delete(lab: Lab, agent: Agent) -> Any:
    return lab.cli("agentes", "borrar", agent.slug, "--confirmar", agent.slug)


@scenario("borrar-sin-esperar")
def test_deleting_keeps_the_black_box_whole_and_the_volume_in_the_trash(
    attack: Attack, lab: Lab
) -> None:
    """The criterion of T26-6c, with what is on the web's socket today: nothing of this."""
    made = lab.cli(
        "agentes", "crear", THIRD.slug, "--perfil", "claude-code", "--volumen", "10",
        "--tope-espacio", str(CAP_MIB), "--memoria", "1g", "--cpus", "1", "--nombre", "Tercero",
    )  # fmt: skip
    assert made.returncode == 0, f"{made.stdout}{made.stderr}\n{lab.diagnosis()}"
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    seen_in_its_box(lab, THIRD)
    others_started = [started_at(a.container) for a in (MAIN, OTHER)]
    work = f"marca-{secrets.token_hex(6)}"
    lab.in_agent(THIRD, f"echo {work} > /workspace/lo-que-hizo.txt")
    kept["work"] = work
    tag = f"borrar-{secrets.token_hex(6)}"
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
    kept["snapshots"] = lab.snapshots(THIRD)
    kept["text"] = sudo("cat", str(file_of(THIRD))).stdout

    # The web, with a live session, reaches none of it.
    token = lab.helper("link", SOCKET)["token"]
    session = {"session": "<session>", "_why": True}
    tried = [
        {"cmd": "agent_delete", "agent": THIRD.slug, "typed": THIRD.slug, **session},
        {"cmd": "agent_restore", "agent": THIRD.slug, **session},
        {"cmd": "agent_purge", "agent": THIRD.slug, "typed": THIRD.slug, **session},
    ]
    nobody = int(sh("id", "-u", "nobody").stdout)
    opened, *refused, control = _probe(
        nobody, lab.web_gid, {"cmd": "session_open", "token": token}, *tried, {"cmd": "holds"}
    )
    web_refused = (
        opened["ok"] is True
        and control["ok"] is True
        and len(refused) == len(tried)
        and all(a["outcome"] == "refused" and "socket de la web" in a["why"] for a in refused)
        and _running(THIRD.container)
    )

    # The name written again: anything else is nothing.
    wrong_name = order(lab, {"cmd": "agent_delete", "agent": THIRD.slug, "typed": "otro"})
    untouched = _running(THIRD.container) and there(file_of(THIRD))

    events_before = lab.events(THIRD)
    done = delete(lab, THIRD)
    lab.agents = [MAIN, OTHER]
    assert done.returncode == 0, f"{done.stdout}{done.stderr}\n{lab.diagnosis()}"
    # Before anything here opens it as root, which would make the -wal and the -shm a reader that
    # may not write in the folder needs, and this would pass with the box still in WAL.
    db = THIRD.box / STATE_DB
    out_of_wal = (
        mark_of(THIRD)["box_settled"] is True
        and not there(db.with_name(f"{STATE_DB}-wal"))
        and not there(db.with_name(f"{STATE_DB}-shm"))
    )
    web_read = read_as_the_web(lab, THIRD)

    names = sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split()
    box = lab.events(THIRD)
    closing = box[-1]
    mark = mark_of(THIRD)
    final = lab.installation_events("agent_deleted")[-1]
    asked = lab.installation_events("agent_delete")
    wrong = _wrong(
        web_refused=web_refused,
        had_snapshots=bool(kept["snapshots"]),
        wrong_name=wrong_name["outcome"] == "invalid" and untouched,
        said=done.returncode == 0 and "recuperar" in done.stdout,
        no_container=THIRD.container not in names and THIRD.proxy not in names,
        no_network=networks_of(THIRD) == [],
        unmounted=mounted(THIRD.volume) == "" and mounted(THIRD.box / "proxy-channel") == "",
        no_mount_point=not there(THIRD.volume),
        image_kept=there(THIRD.box / "volume.img"),
        file_gone=not there(file_of(THIRD)),
        copy_kept=sudo("cat", str(THIRD.box / SAVED_AGENT_FILE)).stdout == kept["text"],
        not_listed=THIRD.slug not in listed(lab),
        in_the_list="en la papelera" in lab.cli("agentes", "lista").stdout,
        others_there=_running(MAIN.container) and _running(OTHER.container),
        others_not_restarted=others_started == [started_at(a.container) for a in (MAIN, OTHER)],
    )
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}se para, sin contenedores, redes ni montajes; la imagen y la copia de su "
        "archivo se quedan; ni la web ni un nombre mal escrito llegan a nada, y los otros siguen",
    )
    attack.check(
        "recorded",
        [e["seq"] for e in box[: len(events_before)]] == [e["seq"] for e in events_before]
        and closing["action"] == "agent_deleted"
        and closing["seq"] == mark["final_seq"] == final["details"]["final_seq"]
        and mark["final_hash"] == final["details"]["final_hash"]
        and bool(asked)
        and "cli (uid 0" in asked[-1]["details"]["requested_by"]
        and asked[-1]["seq"] < final["seq"]
        and lab.verify(THIRD)["ok"]
        and not mode_of(THIRD.box / STATE_DB) & 0o222
        and out_of_wal
        and web_read == str(len(box)),
        f"su caja verifica, entera ({len(box)} eventos), y termina en agent_deleted, cuyo hash "
        "tiene también la caja de la instalación; es de solo lectura y el grupo de la web la lee "
        "sin poder escribir en su carpeta",
    )
    attack.check(
        "held",
        bool(said_in(box, hold_id))
        and not said_in(lab.events(THIRD, "approved"), hold_id)
        and [e["details"]["why"] for e in said_in(lab.events(THIRD, "expired"), hold_id)]
        == ["restart"],
        f"lo retenido ({hold_id}) termina rechazado al borrarlo: nadie dijo que sí",
    )


@scenario("recuperar-entero")
def test_a_deleted_agent_comes_back_whole(attack: Attack, lab: Lab) -> None:
    """`recuperar` brings it back stopped and `arrancar` starts it: its work, its snapshots, its
    chain, its ids and its cap, with a volume mounted again from its own image."""
    before = lab.events(THIRD)
    final = mark_of(THIRD)["final_hash"]
    back = lab.cli("agentes", "recuperar", THIRD.slug)
    assert back.returncode == 0, f"{back.stdout}{back.stderr}\n{lab.diagnosis()}"
    state = listed(lab)[THIRD.slug]
    came_back_stopped = state["state"] == "stopped_by_owner" and not _running(THIRD.container)
    file_again = sudo("cat", str(file_of(THIRD))).stdout
    nets = networks_of(THIRD)
    started = lab.cli("agentes", "arrancar", THIRD.slug)
    lab.agents = [MAIN, OTHER, THIRD]
    lab.wait_up(START_TIMEOUT)
    seen_in_its_box(lab, THIRD)
    work = lab.in_agent(THIRD, "cat /workspace/lo-que-hizo.txt").stdout.strip()
    now = lab.events(THIRD)
    place = len(before)
    wrong = _wrong(
        came_back_stopped=came_back_stopped,
        file_same=file_again == kept["text"],
        no_mark=not there(THIRD.box / RETIRED_MARK),
        networks=len(nets) == 2,
        started=started.returncode == 0,
        its_work=work == kept["work"],
        its_snapshots=set(kept["snapshots"]) <= set(lab.snapshots(THIRD)),
        its_uid=uid_of(THIRD.container) == THIRD.uid,
        its_cap=lab.usage(THIRD)["limit"] == CAP_MIB * 1024**2,
        its_volume=mounted(THIRD.volume).strip() == "btrfs",
    )
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}vuelve parado, con su archivo tal cual, y arranca: su trabajo, sus "
        "instantáneas, su id, su tope y su volumen",
    )
    attack.check(
        "recorded",
        [e["seq"] for e in now[:place]] == [e["seq"] for e in before]
        and now[place - 1]["action"] == "agent_deleted"
        and now[place]["action"] == "agent_restored"
        and lab.verify(THIRD)["ok"]
        and bool(lab.installation_events("agent_restore"))
        and lab.installation_events("agent_restored")[-1]["details"]["final_hash"] == final,
        "su cadena sigue desde el hash con el que terminó, agent_restored es el siguiente evento y "
        "verifica entera",
    )


@scenario("borrar-a-medias")
def test_a_delete_half_way_is_nobody_and_can_be_finished(attack: Attack, lab: Lab) -> None:
    """A container of someone else on its network stops the removal half way, for real. It is not
    an agent any more for a start of the service, which says so, and the order finishes it."""
    image = images.AGENTS["claude-code"].ref
    sh(
        "docker", "run", "--detach", "--name", IN_THE_WAY, "--network", THIRD.network,
        "--entrypoint", "sleep", image, "900",
    )  # fmt: skip
    half = delete(lab, THIRD)
    lab.agents = [MAIN, OTHER]
    mark = mark_of(THIRD)
    box_after = len(lab.events(THIRD))
    half_way = (
        half.returncode == 1
        and mark["state"] == "deleting"
        and there(file_of(THIRD))
        and not _running(THIRD.container)
    )
    lab.restart()
    seen_in_its_box(lab, OTHER)
    nobody_now = (
        THIRD.slug not in listed(lab)
        and not _running(THIRD.container)
        and THIRD.slug not in lab.helper("load", str(CONFIG)).get("agents", [])
    )
    told = lab.installation_events("agent_delete_unfinished")
    restore_refused = lab.cli("agentes", "recuperar", THIRD.slug).returncode == 1
    purge_refused = lab.cli(
        "agentes", "vaciar", THIRD.slug, "--confirmar", THIRD.slug
    ).returncode == 1  # fmt: skip
    image_kept = there(THIRD.box / "volume.img")
    sh("docker", "rm", "--force", IN_THE_WAY)
    done = delete(lab, THIRD)
    wrong = _wrong(
        half_way=half_way,
        nobody_now=nobody_now,
        said_at_the_start=bool(told) and told[-1]["target"] == THIRD.slug,
        restore_refused=restore_refused,
        purge_refused=purge_refused,
        image_kept=image_kept,
        finished=done.returncode == 0 and mark_of(THIRD)["state"] == "retired",
        file_gone=not there(file_of(THIRD)),
        no_network=networks_of(THIRD) == [],
        unmounted=mounted(THIRD.volume) == "",
    )
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}a medias no es de nadie: un reinicio no lo arranca y lo dice, ni se "
        "recupera ni se vacía, y la orden lo termina",
    )
    attack.check(
        "recorded",
        len(lab.events(THIRD)) == box_after
        and lab.events(THIRD)[-1]["action"] == "agent_deleted"
        and bool(lab.installation_events("agent_delete_failed"))
        and bool(lab.installation_events("agent_delete_resumed"))
        and lab.verify(THIRD)["ok"],
        "lo que falló y lo que siguió, en la caja de la instalación; la suya se cierra una vez",
    )


@scenario("nombre-borrado-no-vuelve")
def test_a_deleted_name_inherits_nothing_and_is_no_way_out(attack: Attack, lab: Lab) -> None:
    """A slug is a key of what is there, never a path, and that one stays taken: a new agent with
    it is refused, and a file written by hand for it is not read."""
    box = lab.events(THIRD)
    again = lab.cli(
        "agentes", "crear", THIRD.slug, "--perfil", "claude-code", "--volumen", "10", "--memoria",
        "1g",
    )  # fmt: skip
    path = f"{THIRD.box}/../{THIRD.slug}"
    answers = [
        order(lab, {"cmd": "agent_restore", "agent": f"../{THIRD.slug}"}),
        order(lab, {"cmd": "agent_restore", "agent": str(THIRD.box)}),
        order(lab, {"cmd": "agent_purge", "agent": path, "typed": path}),
        order(lab, {"cmd": "agent_purge", "agent": "../..", "typed": "../.."}),
        order(lab, {"cmd": "agent_delete", "agent": "/etc", "typed": "/etc"}),
        order(lab, {"cmd": "agent_purge", "agent": THIRD.slug, "typed": THIRD.slug, "to": "/etc"}),
    ]  # fmt: skip
    main_deleted = order(lab, {"cmd": "agent_delete", "agent": "principal", "typed": "principal"})
    main_purged = order(lab, {"cmd": "agent_purge", "agent": "principal", "typed": "principal"})
    pause = lab.cli("agentes", "pausar", THIRD.slug)
    start = lab.cli("agentes", "arrancar", THIRD.slug)
    # By hand, with the machine's root: it is still nobody, and it is said.
    _write_as_root(file_of(THIRD), kept["text"].replace("number = 2", "number = 77"))
    lab.restart()
    seen_in_its_box(lab, OTHER)
    told = [e for e in lab.installation_events("agent_delete_unfinished")
            if "no se usa" in e["details"]["why"]]  # fmt: skip
    file_stays = there(file_of(THIRD))
    sudo("rm", "-f", str(file_of(THIRD)))
    wrong = _wrong(
        again=again.returncode == 1 and "ya se usó" in again.stderr,
        paths=all(a["outcome"] == "invalid" for a in answers),
        main=main_deleted["outcome"] == main_purged["outcome"] == "refused"
        and _running(MAIN.container),
        no_order=pause.returncode == 1 and start.returncode == 1,
        hand_file=bool(told)
        and file_stays
        and not _running(THIRD.container)
        and THIRD.slug not in listed(lab),
        image_kept=there(THIRD.box / "volume.img"),
    )
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}el nombre no se reutiliza; una ruta es invalid sin tocar nada; el principal "
        "no se borra; ninguna orden llega a él y un archivo escrito a mano no se lee, y se dice",
    )
    attack.check(
        "recorded",
        [e["seq"] for e in lab.events(THIRD)] == [e["seq"] for e in box]
        and lab.verify(THIRD)["ok"],
        f"su caja sigue como estaba ({len(box)} eventos)",
    )


@scenario("papelera-caducada")
def test_the_trash_warns_a_day_before_and_empties_after_the_wait(attack: Attack, lab: Lab) -> None:
    """The dates in its mark put back, as a machine would see them days later: a look at the start
    of the service warns first, even long past the date, and empties only a day after the warning.
    If the VM's clock is not synchronised this fails with nothing done, as it should."""
    box = lab.events(THIRD)
    mark = mark_of(THIRD)
    past = datetime.now(UTC) - timedelta(days=30)
    mark["purge_after"] = past.isoformat()
    _write_as_root(THIRD.box / RETIRED_MARK, json.dumps(mark), "0600")
    lab.restart()
    wait(
        lambda: bool(lab.installation_events("agent_trash_warned")),
        SEEN_TIMEOUT,
        "the warning",
        lab.diagnosis,
    )
    warned = mark_of(THIRD)["warned_at"] is not None
    # Another look, long past the date and with the warning given: a day has not gone by since.
    lab.restart()
    seen_in_its_box(lab, OTHER)
    image_after_warning = there(THIRD.box / "volume.img") and not lab.installation_events(
        "agent_purge"
    )
    mark = mark_of(THIRD)
    mark["warned_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    _write_as_root(THIRD.box / RETIRED_MARK, json.dumps(mark), "0600")
    lab.restart()
    wait(
        lambda: bool(lab.installation_events("agent_purged")),
        SEEN_TIMEOUT,
        "the trash to empty itself",
        lab.diagnosis,
    )
    purge = lab.installation_events("agent_purge")[-1]
    left = sudo("ls", "-A", str(THIRD.box)).stdout.split()
    wrong = _wrong(
        warned_first=warned and image_after_warning,
        emptied=not there(THIRD.box / "volume.img") and "proxy-ca" not in left,
        box_stays=STATE_DB in left and "number" in left,
        no_restore=lab.cli("agentes", "recuperar", THIRD.slug).returncode == 1,
    )
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}avisa antes aunque ya haya pasado la fecha, y un día después se vacía; su "
        "caja y su número se quedan",
    )
    attack.check(
        "recorded",
        purge["details"]["reason"] == "expired"
        and purge["details"]["final_hash"] == mark["final_hash"]
        and [e["seq"] for e in lab.events(THIRD)] == [e["seq"] for e in box]
        and lab.verify(THIRD)["ok"],
        "agent_purge en la caja de la instalación antes de hacerlo, con su motivo y el hash final; "
        "en su caja no se escribe nada y sigue verificando",
    )


@scenario("vaciar-la-papelera")
def test_emptying_early_and_the_last_neighbour_gone(attack: Attack, lab: Lab) -> None:
    """`vaciar` from root's terminal, on the neighbour the lab mounted by hand. With it gone there
    is no other agent, and the total stays: a neighbour gone must not leave the main agent with no
    cap (review of T26-2c)."""
    assert lab.helper("order", SOCKET, json.dumps(
        {"cmd": "agent_stop", "agent": OTHER.slug}), timeout=360)["ok"]  # fmt: skip
    # A folder: a link to a file would stay untouched whatever removed it, and this could not fail.
    work = f"marca-{secrets.token_hex(6)}"
    outside = STATE / "no-se-toca"
    sudo("install", "-d", "-m", "0700", str(outside))
    _write_as_root(outside / "dentro", work, "0600")
    sudo("ln", "-s", str(outside), f"{OTHER.box}/claude-code/enlace")
    done = delete(lab, OTHER)
    lab.agents = [MAIN]
    assert done.returncode == 0, f"{done.stdout}{done.stderr}\n{lab.diagnosis()}"
    final = mark_of(OTHER)["final_hash"]
    box = lab.events(OTHER)
    no_name = lab.cli("agentes", "vaciar", OTHER.slug, "--confirmar", "otro")
    still_there = there(OTHER.box / "volume.img")
    empty = lab.cli("agentes", "vaciar", OTHER.slug, "--confirmar", OTHER.slug)
    left = sudo("ls", "-A", str(OTHER.box)).stdout.split()
    purge = lab.installation_events("agent_purge")[-1]

    # With no neighbour left, the service goes on and its total too.
    lab.restart()
    budget = lab.helper("budget", SOCKET)
    wrong = _wrong(
        wrong_name=no_name.returncode == 2 and still_there,
        emptied=empty.returncode == 0 and not there(OTHER.box / "volume.img"),
        config_gone="claude-code" not in left,
        not_followed=sudo("cat", str(outside / "dentro")).stdout.strip() == work,
        box_stays=STATE_DB in left and "number" in left,
        no_restore=lab.cli("agentes", "recuperar", OTHER.slug).returncode == 1,
        slug_taken=lab.cli(
            "agentes", "crear", OTHER.slug, "--perfil", "claude-code", "--volumen", "10",
            "--reiniciar",
        ).returncode == 1,
        main_runs=_running(MAIN.container),
        total_stays=budget["installation"]["available"] is True
        and OTHER.slug in budget["installation"]["agents"],
    )  # fmt: skip
    attack.check(
        "stopped",
        not wrong,
        f"{wrong or ''}con el nombre mal escrito no se hace; vaciar quita el volumen y su carpeta "
        "de trabajo sin seguir enlaces, y deja la caja; el principal sigue, con el total encima",
    )
    attack.check(
        "recorded",
        purge["details"]["reason"] == "owner"
        and purge["details"]["final_hash"] == final
        and "cli (uid 0" in purge["details"]["requested_by"]
        and [e["seq"] for e in lab.events(OTHER)] == [e["seq"] for e in box]
        and lab.verify(OTHER)["ok"],
        "agent_purge, antes de hacerlo y con quién; su caja verifica, sin nada añadido",
    )
