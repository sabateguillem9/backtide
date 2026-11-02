"""T26-6c: deleting an agent, its trash, bringing it back and emptying it (docs/47, section 8.5).

Real files and a real black box, a fake machine (``Machine``, from the tests of T26-6a). The real
thing, under the real unit, is tests/attacks/test_agent_delete_attacks.py.
"""

import json
import os
import sqlite3
import threading
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from backtide import cli
from backtide.blackbox import BlackBox, BlackBoxError, load_key
from backtide.notify import AlertLevel
from backtide.notify.buttons import Action, ButtonBook
from backtide.service import agent_disk, agentes, fleet, runner, trash
from backtide.service.agents import check_alone, load_agent, load_installation, load_retired
from backtide.service.config import (
    RETIRED_MARK,
    SAVED_AGENT_FILE,
    STATE_DB,
    ConfigError,
    ServiceConfig,
)
from backtide.service.control import ask_agent_order, ask_agents, ask_deleted
from backtide.service.fleet import TrashWatch
from backtide.service.roster import OrderInvalid
from backtide.service.spend import STATE_BUDGET
from backtide.service.trash import KEPT, RETIRED, TrashError, due, read_mark, retired_agents
from backtide.setup import containers
from tests.test_service_agents import Sink, add_agent, main_config, write_main
from tests.test_service_agents import home as home  # noqa: F401, PLC0414 - the fixture
from tests.test_service_control import me
from tests.test_service_fleet import GOOD, World, served
from tests.test_service_fleet import _keys_read_at_once as _keys_read_at_once  # noqa: F401, PLC0414
from tests.test_service_fleet import alone as alone  # noqa: F401, PLC0414
from tests.test_service_fleet import sock_dir as sock_dir  # noqa: F401, PLC0414
from tests.test_service_fleet import world as world  # noqa: F401, PLC0414

SLUG = "tercero"
DELETE = {"cmd": "agent_delete", "agent": SLUG, "typed": SLUG}
RESTORE = {"cmd": "agent_restore", "agent": SLUG}
PURGE = {"cmd": "agent_purge", "agent": SLUG, "typed": SLUG}
BY = "cli (uid 0, pid 7)"
CONTAINERS = tuple(containers.containers_of_agent(SLUG))
SECRET_WORK = b"lo que el agente ha hecho, en su imagen"


def created(world: World) -> ServiceConfig:  # noqa: F811
    """A real agent as the service makes one, with something in its volume and in its box."""
    reply = world.fleet.create(GOOD, "cli (uid 0, pid 1)")
    assert reply["ok"], reply
    config = world.neighbours.configs[SLUG]
    config.agent_dir.joinpath("volume.img").write_bytes(SECRET_WORK)
    with runner.open_black_box(config) as box:
        box.append("exec", "run", "/bin/true")
    world.machine.containers += list(CONTAINERS)
    return config


def deleted(world: World) -> ServiceConfig:  # noqa: F811
    config = created(world)
    reply = world.fleet.delete(DELETE, BY)
    assert reply["ok"] and reply["outcome"] == "deleted", reply
    return config


def mark_of(config: ServiceConfig) -> trash.Retired:
    return read_mark(config.agent_dir)


def box_events(config: ServiceConfig) -> list[Any]:
    with BlackBox(config.blackbox_db, None, readonly=True) as box:
        return box.events()


def verified(config: ServiceConfig) -> Any:
    key = load_key(config.blackbox_key)
    with BlackBox(
        config.blackbox_db, key, checkpoint_path=config.blackbox_checkpoint, readonly=True
    ) as box:
        return box.verify()


# --- the closed shape, and what a slug can never be -------------------------------------------


@pytest.mark.parametrize(
    "order",
    [
        {"cmd": "agent_delete"},
        {"cmd": "agent_delete", "agent": SLUG},
        {"cmd": "agent_delete", "agent": SLUG, "typed": "otro"},
        {"cmd": "agent_delete", "agent": SLUG, "typed": ""},
        {"cmd": "agent_delete", "agent": SLUG, "typed": SLUG, "force": True},
        {"cmd": "agent_delete", "agent": "../x", "typed": "../x"},
        {"cmd": "agent_delete", "agent": "/etc", "typed": "/etc"},
        {"cmd": "agent_delete", "agent": "a/b", "typed": "a/b"},
        {"cmd": "agent_delete", "agent": 7, "typed": 7},
        {"cmd": "agent_delete", "agent": ["x"], "typed": ["x"]},
    ],
)
def test_a_delete_outside_its_shape_touches_nothing(world: World, order: dict[str, Any]) -> None:  # noqa: F811
    created(world)
    with pytest.raises(OrderInvalid) as refused:
        world.fleet.delete(order, BY)
    assert "agent_delete" not in world.actions()
    assert "../x" not in str(refused.value), "what the order said is never repeated"
    assert SLUG in world.neighbours.running


@pytest.mark.parametrize(
    "order",
    [
        {"cmd": "agent_purge", "agent": SLUG},
        {"cmd": "agent_purge", "agent": SLUG, "typed": "otro"},
        {"cmd": "agent_purge", "agent": "../tercero", "typed": "../tercero"},
        {"cmd": "agent_purge", "agent": SLUG, "typed": SLUG, "path": "/etc"},
    ],
)
def test_a_purge_outside_its_shape_touches_nothing(world: World, order: dict[str, Any]) -> None:  # noqa: F811
    config = deleted(world)
    with pytest.raises(OrderInvalid):
        world.fleet.purge(order, BY)
    assert (config.agent_dir / "volume.img").exists() and "agent_purge" not in world.actions()


@pytest.mark.parametrize(
    "order",
    [
        {"cmd": "agent_restore"},
        {"cmd": "agent_restore", "agent": "/etc"},
        {"cmd": "agent_restore", "agent": 7},
        {"cmd": "agent_restore", "agent": SLUG, "restart": "sí"},
        {"cmd": "agent_restore", "agent": SLUG, "volume": "/etc"},
    ],
)
def test_a_restore_outside_its_shape_touches_nothing(world: World, order: dict[str, Any]) -> None:  # noqa: F811
    deleted(world)
    with pytest.raises(OrderInvalid):
        world.fleet.restore(order, BY)
    assert "agent_restore" not in world.actions()


def test_the_main_agent_is_never_deleted_or_emptied(world: World, alone: World) -> None:  # noqa: F811
    for each in (world, alone):
        main = {"agent": "principal", "typed": "principal"}
        for reply in (
            each.fleet.delete({"cmd": "agent_delete", **main}, BY),
            each.fleet.purge({"cmd": "agent_purge", **main}, BY),
            each.fleet.restore({"cmd": "agent_restore", "agent": "principal"}, BY),
        ):
            assert reply["outcome"] == "refused" and "principal" in reply["message"]
        assert each.recorded == [] and each.machine.ran == []
    assert not (world.main.state_dir / RETIRED_MARK).exists()


def test_one_order_at_a_time(world: World) -> None:  # noqa: F811
    created(world)
    assert world.fleet._busy.acquire(blocking=False)
    try:
        for call, order in (
            (world.fleet.delete, DELETE),
            (world.fleet.restore, RESTORE),
            (world.fleet.purge, PURGE),
        ):
            assert call(order, BY)["outcome"] == "refused"
    finally:
        world.fleet._busy.release()
    assert "agent_delete" not in world.actions()


def test_an_agent_that_is_nobodys_is_refused(world: World) -> None:  # noqa: F811
    named = {"agent": "nadie", "typed": "nadie"}
    assert world.fleet.delete({"cmd": "agent_delete", **named}, BY)["outcome"] == "refused"
    assert world.fleet.purge({"cmd": "agent_purge", **named}, BY)["outcome"] == "refused"
    assert (
        world.fleet.restore({"cmd": "agent_restore", "agent": "nadie"}, BY)["outcome"] == "refused"
    )
    assert world.recorded == []


def test_outside_the_unit_nothing_is_deleted(world: World) -> None:  # noqa: F811
    created(world)
    fleet_ = world.make(unit=lambda: False)
    assert fleet_.delete(DELETE, BY)["outcome"] == "refused"
    assert SLUG in world.neighbours.running and "agent_delete" not in world.actions()


# --- deleting -----------------------------------------------------------------------------------


def test_delete_closes_the_box_keeps_the_volume_and_leaves_nothing_running(world: World) -> None:  # noqa: F811
    config = created(world)
    text = world.agent_file().read_text()
    assert config.agent_dir.joinpath("volume.img").read_bytes() == SECRET_WORK
    before = len(box_events(config))
    reply = world.fleet.delete(DELETE, BY)
    assert reply["ok"] and reply["outcome"] == "deleted", reply

    # Stopped first, with the mark on; Docker has the last word.
    calls = world.neighbours.calls
    assert ("stop", SLUG, BY, True) in calls and ("halt", SLUG) in calls
    assert calls.index(("stop", SLUG, BY, True)) < calls.index(("halt", SLUG))

    # The black box stays, whole, with its last event and its hash in three places.
    mark = mark_of(config)
    assert mark.state == RETIRED and mark.number == config.number and mark.requested_by == BY
    assert mark.purge_after == mark.deleted_at + timedelta(days=7)
    events = box_events(config)
    assert len(events) == before + 1
    last = events[-1]
    assert (last.source, last.action, last.target) == ("system", "agent_deleted", SLUG)
    assert last.details["requested_by"] == BY and last.details["problems"] == 0
    assert (last.seq, last.hash) == (mark.final_seq, mark.final_hash)
    recorded = dict((a, d) for a, _, d in world.recorded)
    assert recorded["agent_deleted"]["final_hash"] == last.hash
    assert world.actions().index("agent_delete") < world.actions().index("agent_deleted")
    assert verified(config).ok

    # Read-only, and readable by whoever may not write in its folder.
    assert not (config.blackbox_db.stat().st_mode & 0o222)
    assert not config.blackbox_db.with_name(f"{STATE_DB}-wal").exists()

    # Nothing runs, and nothing of it is left on Docker or mounted.
    assert world.machine.containers == [] and world.machine.docker_networks == []
    assert world.machine.mounts == []
    assert not (world.volumes / SLUG).exists(), "its empty mount point goes"

    # The volume waits, untouched, and its file went beside the box.
    assert config.agent_dir.joinpath("volume.img").read_bytes() == SECRET_WORK
    assert not world.agent_file().exists()
    assert config.agent_dir.joinpath(SAVED_AGENT_FILE).read_text() == text

    # It is nobody now, for an order and for a start.
    assert not world.roster.knows(SLUG)
    assert ("forget", SLUG) in calls
    assert [a.slug for a in load_installation(main_config(world.home)).agents] == [
        "principal",
        "revisor",
    ]
    assert [item["slug"] for item in world.roster.deleted()] == [SLUG]
    assert "/" not in json.dumps([v for v in world.roster.deleted()[0].values()]), "no path"
    assert world.told.alerts[-1].level is AlertLevel.ERROR
    assert SLUG in world.told.alerts[-1].title
    # About everybody: an alert about it would carry a «Pausar» good for 24 hours.
    assert world.told.alerts[-1].installation and world.told.alerts[-1].agent is None

    # Asking again changes nothing.
    assert world.fleet.delete(DELETE, BY)["outcome"] == "already"
    assert len(box_events(config)) == before + 1


def test_a_box_that_a_reader_had_open_settles_at_a_later_look(world: World) -> None:  # noqa: F811
    config = created(world)
    reader = sqlite3.connect(f"file:{config.blackbox_db}?mode=ro", uri=True)
    reader.execute("SELECT count(*) FROM events").fetchone()
    assert world.fleet.delete(DELETE, BY)["ok"]
    assert mark_of(config).box_settled is False
    world.fleet.tend_trash()
    assert mark_of(config).box_settled is False, "still open: nothing lost, tried again"
    assert not (config.blackbox_db.stat().st_mode & 0o222), "and read-only all the same"
    reader.close()
    world.fleet.tend_trash()
    assert mark_of(config).box_settled is True
    assert not (config.blackbox_db.stat().st_mode & 0o222)
    assert read_only_events(config) == len(box_events(config))


def read_only_events(config: ServiceConfig) -> int:
    """As the web's group reads it: it may not write in the folder, nor make a -shm."""
    folder = config.agent_dir
    mode = folder.stat().st_mode & 0o777
    folder.chmod(0o500)
    try:
        with BlackBox(config.blackbox_db, None, readonly=True) as box:
            return len(box.events())
    finally:
        folder.chmod(mode)


def test_a_deleted_box_can_be_read_by_who_may_not_write_in_its_folder(world: World) -> None:  # noqa: F811
    config = deleted(world)
    assert mark_of(config).box_settled is True
    assert read_only_events(config) == len(box_events(config)) > 0


def test_not_recorded_not_deleted(world: World) -> None:  # noqa: F811
    config = created(world)
    world.record_works = False
    reply = world.fleet.delete(DELETE, BY)
    assert reply["outcome"] == "failed" and "no se ha hecho nada" in reply["message"]
    assert SLUG in world.neighbours.running and not agent_disk.is_stopped(config)
    assert world.agent_file().exists() and not (config.agent_dir / RETIRED_MARK).exists()


def test_a_stop_that_does_not_end_deletes_nothing(world: World) -> None:  # noqa: F811
    config = created(world)
    world.neighbours.stuck = True
    reply = world.fleet.delete(DELETE, BY)
    assert reply["outcome"] == "failed"
    assert not (config.agent_dir / RETIRED_MARK).exists() and world.agent_file().exists()
    assert world.machine.containers, "what may still be running is not removed under it"
    world.neighbours.stuck = False
    world.neighbours.running.discard(SLUG)
    world.neighbours.halts = False
    assert world.fleet.delete(DELETE, BY)["outcome"] == "failed", "Docker's word, not the thread's"
    assert not (config.agent_dir / RETIRED_MARK).exists()


def test_a_box_that_cannot_be_closed_deletes_nothing(world: World) -> None:  # noqa: F811
    config = created(world)

    def no_box(_: ServiceConfig) -> BlackBox:
        raise BlackBoxError("its chain does not verify")

    reply = world.make(open_box=no_box).delete(DELETE, BY)
    assert reply["outcome"] == "failed" and "caja" in reply["message"]
    assert not (config.agent_dir / RETIRED_MARK).exists() and world.agent_file().exists()
    assert world.roster.knows(SLUG) and "agent_delete_failed" in world.actions()


def test_a_tampered_box_is_not_extended_and_not_deleted(world: World) -> None:  # noqa: F811
    config = created(world)
    connection = sqlite3.connect(config.blackbox_db)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("DROP TRIGGER IF EXISTS events_no_delete")
    connection.close()
    config.blackbox_checkpoint.write_text("not a checkpoint")
    reply = world.fleet.delete(DELETE, BY)
    assert reply["outcome"] == "failed"
    assert not (config.agent_dir / RETIRED_MARK).exists() and world.agent_file().exists()


@pytest.mark.parametrize(
    ("step", "left"),
    [
        ("docker rm", "containers"),
        ("docker network rm", "docker_networks"),
        ("systemd-umount", "mounts"),
    ],
)
def test_a_step_that_fails_can_be_asked_again_and_ends_the_same(
    world: World,  # noqa: F811
    step: str,
    left: str,
) -> None:
    config = created(world)
    events = len(box_events(config))
    world.machine.fail = step
    reply = world.fleet.delete(DELETE, BY)
    assert reply["outcome"] == "failed" and "Repite" in reply["message"], reply
    assert getattr(world.machine, left), f"{left} are still there"
    # It is half way: nobody for a start, whatever its file says, and the file is still there.
    assert mark_of(config).state == trash.DELETING
    assert world.agent_file().exists()
    assert SLUG not in [a.slug for a in load_installation(main_config(world.home)).agents]
    assert world.fleet.restore(RESTORE, BY)["outcome"] == "refused"
    assert world.fleet.purge(PURGE, BY)["outcome"] == "refused"
    assert (config.agent_dir / "volume.img").exists()

    world.machine.fail = None
    world.record_works = False
    assert world.fleet.delete(DELETE, BY)["outcome"] == "failed", "not recorded, it does not go on"
    assert mark_of(config).state == trash.DELETING
    world.record_works = True
    reply = world.fleet.delete(DELETE, BY)
    assert reply["ok"] and reply["outcome"] == "deleted", reply
    assert world.actions().count("agent_delete_resumed") == 1
    assert mark_of(config).state == RETIRED and not world.agent_file().exists()
    assert not world.machine.containers and not world.machine.mounts
    assert len(box_events(config)) == events + 1, "its box ends once"


def test_the_end_of_the_box_is_in_the_installations_before_it_counts_as_over(world: World) -> None:  # noqa: F811
    """Nothing tries again after the mark says `retired`, so what goes before it is what stays."""
    config = created(world)
    real = world.record

    def refuses_the_end(action: str, *rest: Any, **options: Any) -> bool:
        return False if action == "agent_deleted" else real(action, *rest, **options)

    fleet_ = world.make()
    fleet_._record = refuses_the_end
    assert fleet_.delete(DELETE, BY)["outcome"] == "failed"
    assert mark_of(config).state == trash.DELETING
    assert world.fleet.delete(DELETE, BY)["ok"]
    assert mark_of(config).state == RETIRED
    recorded = dict((a, d) for a, _, d in world.recorded)
    assert recorded["agent_deleted"]["final_hash"] == mark_of(config).final_hash


def test_a_container_that_is_not_backtides_is_not_touched_and_stops_it(world: World) -> None:  # noqa: F811
    config = created(world)
    world.machine.not_ours.add(CONTAINERS[0])
    reply = world.fleet.delete(DELETE, BY)
    assert reply["outcome"] == "failed" and "etiqueta" in reply["message"]
    assert CONTAINERS[0] in world.machine.containers
    assert mark_of(config).state == trash.DELETING


def test_a_machine_that_died_half_way_finishes_at_the_next_start(world: World) -> None:  # noqa: F811
    config = created(world)
    world.machine.fail = "docker rm"
    assert world.fleet.delete(DELETE, BY)["outcome"] == "failed"
    world.machine.fail = None
    world.stopped_alive.clear()
    world.fleet.finish_interrupted()
    assert world.stopped_alive == [SLUG], "what may still run with nobody watching is stopped first"
    assert "agent_delete_resumed" in world.actions()
    assert mark_of(config).state == RETIRED and not world.machine.containers
    assert not world.agent_file().exists()


def test_a_start_that_cannot_finish_says_so_and_nothing_of_it_runs(world: World) -> None:  # noqa: F811
    config = created(world)
    world.machine.fail = "docker rm"
    assert world.fleet.delete(DELETE, BY)["outcome"] == "failed"
    world.told.alerts.clear()
    world.fleet.finish_interrupted()
    assert any("a medias" in alert.title for alert in world.told.alerts)
    assert mark_of(config).state == trash.DELETING
    assert SLUG not in [a.slug for a in load_installation(main_config(world.home)).agents]


def test_a_file_written_for_a_deleted_agent_is_not_read_and_is_said(world: World) -> None:  # noqa: F811
    deleted(world)
    add_agent(world.home, SLUG, number=2)
    assert SLUG not in [a.slug for a in load_installation(main_config(world.home)).agents]
    with pytest.raises(ConfigError, match="deleted"):
        load_agent(main_config(world.home), SLUG)
    world.told.alerts.clear()
    world.fleet.finish_interrupted()
    assert any("no se usa" in alert.body for alert in world.told.alerts)
    assert world.agent_file().exists(), "it is the person's: it is said, never removed"


def test_check_alone_does_not_read_the_file_of_a_deleted_agent(world: World) -> None:  # noqa: F811
    deleted(world)
    world.agent_file().write_text("no es toml [")
    check_alone(main_config(world.home), load_agent(main_config(world.home), "revisor"))


def test_a_mark_that_cannot_be_used_stops_every_order_about_it(world: World) -> None:  # noqa: F811
    config = deleted(world)
    (config.agent_dir / RETIRED_MARK).write_text("{no es json")
    with pytest.raises(TrashError):
        read_mark(config.agent_dir)
    assert retired_agents(world.main.agents_dir) == {SLUG: None}
    for call, order in (
        (world.fleet.purge, PURGE),
        (world.fleet.restore, RESTORE),
        (world.fleet.delete, DELETE),
    ):
        assert call(order, BY)["outcome"] == "failed"
    world.fleet.tend_trash()
    assert (config.agent_dir / "volume.img").exists(), "nothing goes on its word"
    assert SLUG not in [a.slug for a in load_installation(main_config(world.home)).agents]


@pytest.mark.parametrize("kind", ["folder", "fifo", "link"])
def test_a_mark_that_is_not_a_file_is_a_mark_that_cannot_be_used(
    world: World,  # noqa: F811
    kind: str,
    tmp_path: Path,
) -> None:
    """Not a reason for the service not to start, or to hang: what reads them is on its way up."""
    config = deleted(world)
    mark = config.agent_dir / RETIRED_MARK
    mark.unlink()
    if kind == "folder":
        mark.mkdir()
    elif kind == "fifo":
        os.mkfifo(mark)
    else:
        mark.symlink_to(tmp_path / "otra")
    assert retired_agents(world.main.agents_dir) == {SLUG: None}
    assert world.fleet.purge(PURGE, BY)["outcome"] == "failed"
    assert (config.agent_dir / "volume.img").exists()
    world.fleet.finish_interrupted()
    assert runner.spend_total_for(world.main, []) is not None


def test_a_mark_that_says_another_agent_is_not_believed(world: World) -> None:  # noqa: F811
    config = deleted(world)
    data = json.loads((config.agent_dir / RETIRED_MARK).read_text())
    data["slug"] = "revisor"
    (config.agent_dir / RETIRED_MARK).write_text(json.dumps(data))
    assert retired_agents(world.main.agents_dir) == {SLUG: None}


# --- a slug that was used ---------------------------------------------------------------------


def test_a_deleted_slug_is_never_created_again_and_neither_is_its_number(world: World) -> None:  # noqa: F811
    config = deleted(world)
    assert config.number == 2
    reply = world.fleet.create(GOOD, BY)
    assert reply["outcome"] == "refused" and "ya se usó" in reply["message"]
    assert (config.agent_dir / "volume.img").read_bytes() == SECRET_WORK
    world.fleet.purge(PURGE, BY)
    reply = world.fleet.create(GOOD, BY)
    assert reply["outcome"] == "refused" and "ya se usó" in reply["message"]
    assert world.fleet.create({**GOOD, "slug": "cuarto"}, BY)["ok"]
    assert world.neighbours.configs["cuarto"].number == 3


def test_a_number_written_by_hand_is_not_used_again_either(world: World) -> None:  # noqa: F811
    """Decision 14: its ids would own what it left. Only the service writes the file `number`, so
    deleting one that was written by hand has to."""
    add_agent(world.home, "quinto", number=5)
    config = load_installation(main_config(world.home)).agent("quinto")
    world.neighbours.configs["quinto"] = config
    world.roster.add("quinto", None)
    assert not (config.agent_dir / "number").exists()
    named = {"agent": "quinto", "typed": "quinto"}
    assert world.fleet.delete({"cmd": "agent_delete", **named}, BY)["ok"]
    assert (config.agent_dir / "number").read_text() == "5\n"
    assert mark_of(config).number == 5
    (config.agent_dir / "number").unlink()  # the mark says it too
    assert world.fleet.create(GOOD, BY)["ok"]
    assert world.neighbours.configs[SLUG].number == 6


def test_a_folder_left_half_made_with_a_box_is_never_wiped(world: World) -> None:  # noqa: F811
    """`creating` is the one way to reuse a folder, and a box stops even that."""
    config = deleted(world)
    (config.agent_dir / fleet.CREATING).write_text("")
    world.fleet.create(GOOD, BY)
    assert config.blackbox_db.exists() and (config.agent_dir / RETIRED_MARK).exists()


# --- bringing it back ---------------------------------------------------------------------------


def tree_of(folder: Path) -> dict[str, bytes | None]:
    found: dict[str, bytes | None] = {}
    for path in sorted(folder.rglob("*")):
        relative = str(path.relative_to(folder))
        found[relative] = path.read_bytes() if path.is_file() else None
    return found


def test_a_deleted_agent_comes_back_whole(world: World) -> None:  # noqa: F811
    config = created(world)
    text = world.agent_file().read_text()
    token = config.agent_dir / "trust.json"
    token.write_text('{"confianza": "de este agente"}')
    before = box_events(config)
    assert world.fleet.delete(DELETE, BY)["ok"]
    final = mark_of(config).final_hash
    tree = tree_of(config.agent_dir)

    reply = world.fleet.restore(RESTORE, BY)
    assert reply["ok"] and reply["outcome"] == "restored", reply

    # Everything that was its own is there, byte by byte.
    after = tree_of(config.agent_dir)
    for name in set(tree) - {RETIRED_MARK, SAVED_AGENT_FILE}:
        if not name.startswith(STATE_DB) and "checkpoint" not in name:
            assert after[name] == tree[name], name
    assert (config.agent_dir / "volume.img").read_bytes() == SECRET_WORK
    assert world.agent_file().read_text() == text
    assert not (config.agent_dir / RETIRED_MARK).exists()

    # The chain goes on from the hash it ended with: nothing before it changed.
    events = box_events(config)
    assert [e.hash for e in events[: len(before)]] == [e.hash for e in before]
    assert events[-2].hash == final and events[-2].action == "agent_deleted"
    assert events[-1].action == "agent_restored" and events[-1].prev_hash == final
    assert verified(config).ok
    assert config.blackbox_db.stat().st_mode & 0o200, "it can be written again"

    assert not (config.agent_dir / SAVED_AGENT_FILE).exists(), "the machine's is the one again"

    # The same agent, stopped, with its networks back and everyone told again.
    new = load_installation(main_config(world.home)).agent(SLUG)
    assert (new.number, new.volume) == (config.number, config.volume)
    assert agent_disk.is_stopped(new)
    assert world.roster.knows(SLUG) and world.roster.listing()[-1]["state"] == "stopped_by_owner"
    assert SLUG not in world.neighbours.running
    assert sorted(world.machine.docker_networks) == [
        f"backtide-{SLUG}-net",
        f"backtide-{SLUG}-salida",
    ]
    assert world.neighbours.configs[SLUG] == new
    assert world.roster.deleted() == []
    assert ("protect", SLUG, world.main_protected[-1]) in world.neighbours.calls
    assert world.total.count(SLUG) == 2
    assert "agent_restored" in world.actions()

    # And it starts as any stopped agent does, or it can go again.
    reply = world.fleet.start({"cmd": "agent_start", "agent": SLUG}, BY)
    assert reply["ok"] and reply["outcome"] == "started", reply
    assert world.fleet.delete(DELETE, BY)["ok"]
    assert mark_of(config).state == RETIRED
    assert world.fleet.restore(RESTORE, BY)["ok"], "and back again: nothing stays of the last time"
    assert world.machine.containers == []


def test_not_recorded_not_restored(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.record_works = False
    assert world.fleet.restore(RESTORE, BY)["outcome"] == "failed"
    assert (config.agent_dir / RETIRED_MARK).exists() and not world.agent_file().exists()
    assert not (config.blackbox_db.stat().st_mode & 0o222)


@pytest.mark.parametrize("step", ["backtide-tercero-net", "backtide-tercero-salida"])
def test_a_restore_that_fails_leaves_it_in_the_trash_as_it_was(world: World, step: str) -> None:  # noqa: F811
    config = deleted(world)
    events = len(box_events(config))
    world.machine.fail = step
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "failed" and "papelera" in reply["message"], reply
    assert world.machine.docker_networks == []
    assert (config.agent_dir / RETIRED_MARK).exists() and not world.agent_file().exists()
    assert not (config.blackbox_db.stat().st_mode & 0o222) and len(box_events(config)) == events
    assert not world.roster.knows(SLUG)
    world.machine.fail = None
    assert world.fleet.restore(RESTORE, BY)["ok"]


def test_a_box_that_refuses_the_restore_leaves_it_in_the_trash(world: World) -> None:  # noqa: F811
    config = deleted(world)

    def no_box(_: ServiceConfig) -> BlackBox:
        raise BlackBoxError("no")

    reply = world.make(open_box=no_box).restore(RESTORE, BY)
    assert reply["outcome"] == "failed"
    assert (config.agent_dir / RETIRED_MARK).exists() and not world.agent_file().exists()
    assert world.machine.docker_networks == [] and not world.roster.knows(SLUG)


def test_networks_left_by_a_restore_that_died_do_not_stop_the_next(world: World) -> None:  # noqa: F811
    deleted(world)
    left = [f"backtide-{SLUG}-net", f"backtide-{SLUG}-salida"]
    world.machine.docker_networks += left
    assert world.fleet.restore(RESTORE, BY)["ok"]
    assert sorted(world.machine.docker_networks) == left
    removed = [a for a in world.machine.ran if a[:3] == ("docker", "network", "rm")]
    assert len(removed) >= 2, "what was there went first: a create over it would fail"


def test_a_different_file_with_its_name_stops_it_and_is_left_alone(world: World) -> None:  # noqa: F811
    deleted(world)
    add_agent(world.home, SLUG, number=9)
    other = world.agent_file().read_text()
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "refused" and "distinto" in reply["message"]
    assert world.agent_file().read_text() == other


def test_the_same_file_left_by_a_restore_that_died_is_fine(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.agent_file().write_text(config.agent_dir.joinpath(SAVED_AGENT_FILE).read_text())
    assert world.fleet.restore(RESTORE, BY)["ok"]


def test_a_volume_that_is_not_there_is_said(world: World) -> None:  # noqa: F811
    config = deleted(world)
    (config.agent_dir / "volume.img").unlink()
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "refused" and "imagen" in reply["message"]
    assert (config.agent_dir / RETIRED_MARK).exists()


def test_it_may_not_come_back_to_a_full_installation_or_disk(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.free = 0
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "refused" and "disco" in reply["message"]
    world.free = 1000 * 1024**3
    assert (config.agent_dir / RETIRED_MARK).exists()


def test_it_may_not_come_back_with_what_another_took(world: World) -> None:  # noqa: F811
    config = deleted(world)
    saved = config.agent_dir / SAVED_AGENT_FILE
    saved.write_text(saved.read_text().replace(f'"{world.volumes / SLUG}"', '"/no/relativo/x"'))
    text = saved.read_text().replace('"/no/relativo/x"', f'"{world.volumes / "revisor"}"')
    saved.write_text(text)
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "refused" and "share a folder" in reply["message"]


def test_the_first_neighbour_brought_back_restarts_and_only_if_accepted(alone: World) -> None:  # noqa: F811
    # What a service with one agent finds after the only other was deleted and it restarted.
    created_with_others = World(alone.home)
    config = deleted_from_a_second_world(created_with_others)
    alone.main = created_with_others.main
    fleet_ = alone.make()
    assert not alone.roster.knows(SLUG)
    reply = fleet_.restore(RESTORE, BY)
    assert reply["outcome"] == "needs_restart" and not alone.stop.is_set()
    assert (config.agent_dir / RETIRED_MARK).exists()
    reply = fleet_.restore({**RESTORE, "restart": True}, BY)
    assert reply["ok"] and reply["outcome"] == "restarting", reply
    assert alone.stop.is_set() and alone.roster.knows(SLUG)
    assert agent_disk.is_stopped(load_installation(main_config(alone.home)).agent(SLUG))


def deleted_from_a_second_world(other: World) -> ServiceConfig:
    return deleted(other)


# --- emptying it --------------------------------------------------------------------------------


def test_empty_removes_all_but_the_box_and_follows_no_link(world: World, tmp_path: Path) -> None:  # noqa: F811
    config = deleted(world)
    home = config.agent_dir
    outside = tmp_path / "fuera"
    outside.mkdir()
    (outside / "algo").write_text("de otro")
    work = home / "claude-code"
    work.mkdir(exist_ok=True)
    (work / "enlace").symlink_to(outside)
    (home / "enlace-fuera").symlink_to(outside)
    (home / "budget.json").write_text("{}")
    events = box_events(config)

    reply = world.fleet.purge(PURGE, BY)
    assert reply["ok"] and reply["outcome"] == "purged", reply

    assert not (home / "volume.img").exists() and not work.exists()
    assert not (home / "enlace-fuera").is_symlink()
    assert (outside / "algo").read_text() == "de otro", "nothing is followed"
    assert {path.name for path in home.iterdir()} <= KEPT
    # The box is as it was: no event added, and its last one is the one the installation has.
    assert [e.hash for e in box_events(config)] == [e.hash for e in events]
    recorded = dict((a, d) for a, _, d in world.recorded)
    assert recorded["agent_purge"]["final_hash"] == events[-1].hash
    assert recorded["agent_purge"]["requested_by"] == BY
    assert recorded["agent_purge"]["reason"] == "owner"
    assert world.actions().index("agent_purge") < world.actions().index("agent_purged")
    assert verified(config).ok
    assert (home / "number").read_text() == "2\n"
    assert world.told.alerts[-1].level is AlertLevel.ERROR
    assert world.roster.deleted()[0]["purged"] is True

    assert world.fleet.purge(PURGE, BY)["outcome"] == "already"
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "refused" and "vació" in reply["message"]


def test_an_emptying_that_stops_half_way_never_comes_back_as_if_whole(
    world: World,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An agent can leave a tree too deep for ``rmtree`` in its config folder: it is said, nothing
    of the box goes, the volume is already gone, and it is not «brought back whole» without it."""
    config = deleted(world)
    home = config.agent_dir
    (home / "claude-code").mkdir(exist_ok=True)
    (home / "blackbox.db-journal").write_text("")

    def too_deep(*_: Any, **__: Any) -> None:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(trash.shutil, "rmtree", too_deep)
    world.told.alerts.clear()
    reply = world.fleet.purge(PURGE, BY)
    assert reply["outcome"] == "failed" and "agent_purge_failed" in world.actions()
    assert not (home / "volume.img").exists() and config.blackbox_db.exists()
    assert [a.level for a in world.told.alerts] == [AlertLevel.ERROR]
    assert world.fleet.purge(PURGE, BY)["outcome"] == "failed"
    assert len(world.told.alerts) == 1, "said once: the next look tries again every hour"
    reply = world.fleet.restore(RESTORE, BY)
    assert reply["outcome"] == "refused" and "imagen" in reply["message"]
    monkeypatch.undo()
    assert world.fleet.purge(PURGE, BY)["ok"]
    assert (home / "blackbox.db-journal").exists(), "a box never loses what it may still need"


def test_not_recorded_not_emptied(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.record_works = False
    assert world.fleet.purge(PURGE, BY)["outcome"] == "failed"
    assert (config.agent_dir / "volume.img").read_bytes() == SECRET_WORK


def test_something_still_mounted_empties_nothing(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.machine.mounts.append((str(config.agent_dir / "proxy-channel"), "tmpfs", "tmpfs"))
    reply = world.fleet.purge(PURGE, BY)
    assert reply["outcome"] == "failed" and "montado" in reply["message"]
    assert (config.agent_dir / "volume.img").exists() and "agent_purge" not in world.actions()


def test_an_agent_that_is_not_deleted_has_no_trash(world: World) -> None:  # noqa: F811
    config = created(world)
    reply = world.fleet.purge(PURGE, BY)
    assert reply["outcome"] == "refused" and "no está borrado" in reply["message"]
    assert (config.agent_dir / "volume.img").exists() and world.roster.knows(SLUG)
    assert world.fleet.restore(RESTORE, BY)["outcome"] == "refused"


def test_an_image_outside_its_folder_is_never_removed_and_is_said(
    world: World,  # noqa: F811
    tmp_path: Path,
) -> None:
    config = deleted(world)
    elsewhere = tmp_path / "otra.img"
    elsewhere.write_bytes(b"de otro sitio")
    saved = config.agent_dir / SAVED_AGENT_FILE
    saved.write_text(
        saved.read_text().replace(str(config.agent_dir / "volume.img"), str(elsewhere))
    )
    reply = world.fleet.purge(PURGE, BY)
    assert reply["ok"] and str(elsewhere) in reply["message"]
    assert elsewhere.read_bytes() == b"de otro sitio"


def test_what_cannot_be_removed_can_be_asked_again(
    world: World,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = deleted(world)

    def no_room(_: Path) -> None:
        raise OSError(16, "busy")

    monkeypatch.setattr(trash, "empty_folder", no_room)
    reply = world.fleet.purge(PURGE, BY)
    assert reply["outcome"] == "failed" and "agent_purge_failed" in world.actions()
    assert mark_of(config).purged_at is None
    monkeypatch.undo()
    assert world.fleet.purge(PURGE, BY)["ok"]


# --- when it goes by itself ---------------------------------------------------------------------


def _mark(world: World) -> trash.Retired:  # noqa: F811
    return trash.new_mark(
        world.main, now=world.now, requested_by=BY, final_seq=1, final_hash="a" * 64
    )


def test_what_is_due_and_when(world: World) -> None:  # noqa: F811
    mark = _mark(world)
    from dataclasses import replace  # noqa: PLC0415

    ready = replace(mark, state=RETIRED)
    start = mark.deleted_at
    assert due(mark, start + timedelta(days=30)) is None, "half deleted: nothing"
    assert due(ready, start + timedelta(days=5, hours=23)) is None
    assert due(ready, start + timedelta(days=6)) == trash.WARN
    warned = replace(ready, warned_at=start + timedelta(days=6))
    assert due(warned, start + timedelta(days=6, hours=23)) is None
    assert due(warned, start + timedelta(days=7)) == trash.PURGE
    # The service was off when it should have warned: a warning first, and a full day after it.
    late = start + timedelta(days=20)
    assert due(ready, late) == trash.WARN
    warned_late = replace(ready, warned_at=late)
    assert due(warned_late, late + timedelta(hours=23)) is None
    assert due(warned_late, late + timedelta(days=1)) == trash.PURGE
    assert due(replace(warned_late, purged_at=late), late + timedelta(days=9)) is None


def test_a_warning_a_day_before_and_empty_after_the_wait(world: World) -> None:  # noqa: F811
    config = deleted(world)
    start = world.now
    world.told.alerts.clear()

    world.now = start + timedelta(days=5)
    world.fleet.tend_trash()
    assert world.told.alerts == [] and (config.agent_dir / "volume.img").exists()

    world.now = start + timedelta(days=6)
    world.fleet.tend_trash()
    assert [a.level for a in world.told.alerts] == [AlertLevel.WARNING]
    assert "Mañana" in world.told.alerts[0].title
    assert SLUG in world.told.alerts[0].title
    assert mark_of(config).warned_at == world.now
    assert "agent_trash_warned" in world.actions()
    world.fleet.tend_trash()
    assert len(world.told.alerts) == 1, "once"
    assert (config.agent_dir / "volume.img").exists()

    world.now = start + timedelta(days=7)
    world.fleet.tend_trash()
    assert not (config.agent_dir / "volume.img").exists()
    assert config.blackbox_db.exists()
    recorded = dict((a, d) for a, _, d in world.recorded)
    assert recorded["agent_purge"]["reason"] == "expired"
    assert world.told.alerts[-1].level is AlertLevel.ERROR
    assert "vaciada" in world.told.alerts[-1].title
    assert all(alert.installation for alert in world.told.alerts)
    assert world.roster.deleted()[0]["purged"] is True


def test_a_warning_that_cannot_be_written_does_not_count(
    world: World,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = deleted(world)
    world.told.alerts.clear()
    world.now += timedelta(days=30)

    def no_disk(_: Path, __: trash.Retired) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(trash, "write_mark", no_disk)
    world.fleet.tend_trash()
    assert world.told.alerts == [] and (config.agent_dir / "volume.img").exists()
    monkeypatch.undo()
    world.fleet.tend_trash()
    assert len(world.told.alerts) == 1 and (config.agent_dir / "volume.img").exists()


def test_a_clock_that_cannot_be_trusted_empties_nothing(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.told.alerts.clear()
    world.now += timedelta(days=30)
    world.clock_good = False
    world.fleet.tend_trash()
    assert world.told.alerts == [] and (config.agent_dir / "volume.img").exists()

    def cannot_tell() -> bool:
        raise OSError(38, "adjtimex is unavailable on this system")

    world.make(clock_ok=cannot_tell).tend_trash()
    assert world.told.alerts == [] and (config.agent_dir / "volume.img").exists()


def test_a_look_that_finds_an_order_running_waits_for_the_next(world: World) -> None:  # noqa: F811
    config = deleted(world)
    world.now += timedelta(days=30)
    assert world.fleet._busy.acquire(blocking=False)
    try:
        world.fleet.tend_trash()
    finally:
        world.fleet._busy.release()
    assert mark_of(config).warned_at is None


def test_one_agent_that_fails_does_not_stop_the_others_turn(
    world: World,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = deleted(world)
    assert world.fleet.delete({"cmd": "agent_delete", "agent": "revisor", "typed": "revisor"}, BY)[
        "ok"
    ]
    other = world.main.agents_dir / "revisor"
    world.now += timedelta(days=30)
    real = trash.write_mark

    def fails_for_one(home: Path, mark: trash.Retired) -> None:
        if home == other:
            raise OSError(28, "No space left on device")
        real(home, mark)

    monkeypatch.setattr(trash, "write_mark", fails_for_one)
    world.fleet.tend_trash()
    assert mark_of(first).warned_at == world.now


def test_the_watch_looks_at_once_and_stops_when_told(world: World) -> None:  # noqa: F811
    deleted(world)
    world.now += timedelta(days=30)
    watch = TrashWatch(world.fleet, every=60.0)
    world.told.alerts.clear()
    watch.start()
    watch.close()
    assert any("Mañana" in alert.title for alert in world.told.alerts)
    assert watch._thread is not None and not watch._thread.is_alive()


# --- what it spent ------------------------------------------------------------------------------


def _with_spending(folder: Path, day: str, month: str, micro: int) -> None:
    state = {
        "version": 1,
        "day": day,
        "month": month,
        "day_micro": micro,
        "month_micro": micro,
        "warned": {"day": [], "month": []},
        "estimated_calls": 0,
    }
    (folder / STATE_BUDGET).write_text(json.dumps(state))
    (folder / STATE_BUDGET).chmod(0o600)


def test_an_installation_that_never_had_another_agent_has_no_total(home: Path) -> None:  # noqa: F811
    write_main(home, "[budget]\nauto_prices = false\n")
    main = load_installation(main_config(home)).main
    assert runner.spend_total_for(main, ()) is None


def test_deleting_the_last_neighbour_keeps_the_total_and_its_caps(world: World) -> None:  # noqa: F811
    """Review of T26-2c: the main agent's own cap of one window is ``MAX_CAP_USD`` in the other, and
    with no total above it that would be 100000 $ a day."""
    first = runner.spend_total_for(world.main, [])
    assert first is None
    found = load_installation(main_config(world.home))
    built = runner.spend_total_for(found.main, found.others)
    assert built is not None
    built.bind(record=lambda *_, **__: True, alert=lambda _: None)
    built.set_caps(None, Decimal("3"), requested_by="x")
    assert (world.main.installation_dir / STATE_BUDGET).exists()
    again = runner.spend_total_for(world.main, [])
    assert again is not None, "no neighbours left, and it still has the total"
    assert again.caps()[1] == Decimal("3")


def test_a_deleted_neighbour_keeps_the_total_even_with_its_file_gone(world: World) -> None:  # noqa: F811
    deleted(world)
    (world.main.installation_dir / STATE_BUDGET).unlink(missing_ok=True)
    assert runner.spend_total_for(world.main, []) is not None


def test_a_settle_never_makes_a_box_that_is_not_there(tmp_path: Path) -> None:
    assert trash.settle_box(tmp_path) is False
    assert list(tmp_path.iterdir()) == []


def test_an_agent_that_comes_back_is_watched_with_nothing_of_before(home: Path) -> None:  # noqa: F811
    write_main(home, "[budget]\nauto_prices = false\n")
    add_agent(home, "revisor", number=1)
    found = load_installation(main_config(home))
    neighbours = runner._Neighbours(
        found.main,
        found.others,
        notifier_for=lambda slug: None,  # type: ignore[arg-type,return-value]
        stop=threading.Event(),
        share=None,
        told=Sink(),
        run=lambda *_, **__: None,
        build=lambda *_, **__: (_ for _ in ()).throw(ValueError("no builds here")),
        prepare=lambda config: None,
    )
    config = found.others[0]
    neighbours.start_one(config)
    neighbours.wait_settled("revisor", 10)
    assert neighbours.failure_of("revisor") is not None
    book = ButtonBook()
    book.issue(Action.PAUSE, agent="revisor")
    neighbours._telegram = {"revisor": SimpleNamespace(book=book)}
    neighbours.forget("revisor")
    assert len(book) == 0, "not even the alert of its failure, which came through the main queue"
    assert neighbours.failure_of("revisor") is None
    assert neighbours.config_of("revisor") is None
    assert not neighbours.is_running("revisor")
    neighbours.join(1)


def test_what_a_deleted_agent_spent_still_counts(world: World) -> None:  # noqa: F811
    config = deleted(world)
    total = runner.build_spend_total(world.main, [])
    keys = total._keys()
    _with_spending(config.agent_dir, keys[0], keys[1], 1_000_000)
    status = total.status()
    assert SLUG in status["agents"] and status["agents"][SLUG]["month_micro"] == 1_000_000
    assert status["month"]["spent_micro"] == 1_000_000


# --- who can ask -----------------------------------------------------------------------------


def test_the_orders_go_through_roots_socket_and_the_list_says_it(
    world: World,  # noqa: F811
    sock_dir: Path,
) -> None:
    created(world)
    server = served(sock_dir, roster=world.roster, fleet=world.fleet)
    path = sock_dir / "c.sock"
    options: dict[str, Any] = {"peer": me, "wait": 0}
    try:
        reply = ask_agent_order(path, DELETE, **options)
        assert reply["ok"] and reply["outcome"] == "deleted", reply
        assert world.recorded[-1][2]["requested_by"].startswith("cli (uid")
        assert SLUG not in [a["slug"] for a in ask_agents(path, **options)]
        listed = ask_deleted(path, **options)
        assert [(a["slug"], a["state"], a["purged"]) for a in listed] == [(SLUG, RETIRED, False)]
        assert ask_agent_order(path, {**DELETE, "typed": "otro"}, **options)["outcome"] == "invalid"
        # No order reaches it now by the agent's name.
        reply = ask_agent_order(path, {"cmd": "agent_pause", "agent": SLUG}, **options)
        assert reply["ok"] is False
        assert ask_agent_order(path, RESTORE, **options)["outcome"] == "restored"
        assert ask_deleted(path, **options) == []
    finally:
        server.close()


def test_the_cli_asks_for_the_name_and_says_what_the_service_said(
    world: World,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sent: list[dict[str, Any]] = []

    def asked(_: ServiceConfig, request: dict[str, Any]) -> int:
        sent.append(request)
        return 0

    monkeypatch.setattr(cli, "agent_order", asked)
    config = str(main_config(world.home))
    base = ["agentes", "borrar", SLUG, "--config", config]
    assert cli.main([*base, "--confirmar", SLUG]) == 0
    assert sent[-1] == {"cmd": "agent_delete", "agent": SLUG, "typed": SLUG}
    # No terminal and no name: it does not guess.
    monkeypatch.setattr("sys.stdin", open(os.devnull))  # noqa: SIM115
    assert cli.main(base) == 2
    assert len(sent) == 1
    # With a terminal, what the person wrote is what goes, right or not.
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda _: "otro\n")

    class Terminal:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Terminal())
    assert cli.main(base) == 0
    assert sent[-1]["typed"] == "otro"
    assert cli.main(["agentes", "vaciar", SLUG, "--config", config, "--confirmar", SLUG]) == 0
    assert sent[-1] == {"cmd": "agent_purge", "agent": SLUG, "typed": SLUG}
    assert cli.main(["agentes", "recuperar", SLUG, "--config", config]) == 0
    assert sent[-1] == {"cmd": "agent_restore", "agent": SLUG}
    assert cli.main(["agentes", "recuperar", SLUG, "--config", config, "--reiniciar"]) == 0
    assert sent[-1] == {"cmd": "agent_restore", "agent": SLUG, "restart": True}
    with pytest.raises(SystemExit):
        cli.main(["agentes", "vaciar", "../etc", "--config", config, "--confirmar", "x"])
    capsys.readouterr()


def test_the_list_says_what_is_in_the_trash(
    world: World,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    deleted(world)
    monkeypatch.setattr(agentes, "ask_agents", lambda *_: world.roster.listing())
    monkeypatch.setattr(agentes, "ask_deleted", lambda *_: world.roster.deleted())
    assert agentes.listing(world.main) == 0
    said = capsys.readouterr().out
    assert f"{SLUG}: en la papelera hasta el 2026-11-09" in said
    assert world.fleet.purge(PURGE, BY)["ok"]
    assert agentes.listing(world.main) == 0
    assert "queda su caja negra" in capsys.readouterr().out


def test_a_copy_of_the_file_that_cannot_be_used_refuses_what_needs_it(world: World) -> None:  # noqa: F811
    config = deleted(world)
    (config.agent_dir / SAVED_AGENT_FILE).write_text("no es toml [")
    with pytest.raises(ConfigError):
        load_retired(main_config(world.home), SLUG)
    assert world.fleet.restore(RESTORE, BY)["outcome"] == "failed"
    assert (config.agent_dir / "volume.img").exists()
