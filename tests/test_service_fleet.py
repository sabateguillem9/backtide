"""T26-6a: creating, starting, stopping and freezing agents from the service (docs/47, section 8).

Real files and real checks, a fake machine: ``Machine`` answers every command and keeps what would
be mounted. The real thing, under the real unit, is tests/attacks/test_agent_orders_attacks.py.
"""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import tomllib
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from backtide import cli
from backtide.jail import AgentJail, JailError
from backtide.jail.config import Protected
from backtide.notify import AlertLevel
from backtide.service import agent_disk, agentes, fleet
from backtide.service.agent_disk import (
    AgentDiskError,
    channel_mount_argv,
    ensure_on_disk,
    is_stopped,
    mark_stopped,
    mounted_at,
    seal_root,
    volume_mount_argv,
    volume_problem,
)
from backtide.service.agents import image_of, load_agent, load_installation
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.control import ControlServer, ask_agent_order, ask_agents
from backtide.service.fleet import (
    CPUS,
    MEMORIES,
    NUMBER_FILE,
    PROFILES,
    AgentSpec,
    Fleet,
    agent_file_text,
    disk_missing,
    memory_bytes,
    memory_missing,
    parse_create,
    still_to_grow,
)
from backtide.service.roster import STOPPED_BY_OWNER, Desk, OrderInvalid, Roster
from backtide.service.runner import _Neighbours, open_black_box, open_installation_box
from backtide.service.spend import BudgetSettings
from backtide.service.spend_total import InstallationSpend
from backtide.service.web_control import COMMANDS, WebControlServer
from backtide.setup import layout
from backtide.setup.host import Ran
from backtide.setup.networks import routes_from_proc
from tests.test_service_agents import Sink, add_agent, main_config, write_main
from tests.test_service_agents import home as home  # noqa: F401, PLC0414 - the fixture
from tests.test_service_control import FakeGuardian, me
from tests.test_service_web_control import GROUP, SESSION, signed_in, talk, the_web

GOOD = {"cmd": "agent_create", "slug": "tercero", "profile": "claude-code", "volume_gib": 10}
GIB = layout.GIB


@pytest.fixture(autouse=True)
def _keys_read_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import backtide.service.config as config  # noqa: PLC0415

    monkeypatch.setattr(config, "KEY_SETTLE_S", 0.0)


# --- the closed shape -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"image": "evil:latest"},
        {"mounts": ["/etc:/etc"]},
        {"privileged": True},
        {"volume": "/etc"},
        {"volume_image": "/root/x"},
        {"cap_add": ["SYS_ADMIN"]},
        {"entrypoint": ["sh"]},
        {"number": 1},
        {"agent": "principal"},
        {"session": "x"},
        {"via": "web"},
    ],
)
def test_a_field_outside_the_list_is_invalid(extra: dict[str, Any]) -> None:
    with pytest.raises(OrderInvalid) as refused:
        parse_create({**GOOD, **extra})
    for said in map(str, extra.values()):  # what the order said is never repeated
        assert said not in str(refused.value)


@pytest.mark.parametrize(
    "change",
    [
        {"profile": "custom"},
        {"profile": ["claude-code"]},
        {"profile": None},
        {"slug": ".."},
        {"slug": "../x"},
        {"slug": "/etc"},
        {"slug": "a/b"},
        {"slug": "Mayus"},
        {"slug": "principal"},
        {"slug": "agente"},
        {"slug": "x" * 33},
        {"slug": 7},
        {"volume_gib": 1},
        {"volume_gib": 11},
        {"volume_gib": True},
        {"volume_gib": 10.0},
        {"volume_gib": "10"},
        {"workspace_mib": 63},
        {"workspace_mib": 5121},
        {"workspace_mib": True},
        {"workspace_mib": -1},
        {"memory": "100g"},
        {"memory": 1},
        {"cpus": 3},
        {"cpus": True},
        {"cpus": "2"},
        {"proxy_memory": "4g"},
        {"daily_usd": "0"},
        {"daily_usd": "-1"},
        {"daily_usd": 5},
        {"monthly_usd": "1000000"},
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 49},
        {"name": "a\nb"},
        {"name": "a‮b"},
        {"name": 7},
        {"restart": "si"},
    ],
)
def test_a_value_outside_its_list_or_range_is_invalid(change: dict[str, Any]) -> None:
    with pytest.raises(OrderInvalid):
        parse_create({**GOOD, **change})


@pytest.mark.parametrize("missing", ["slug", "profile", "volume_gib"])
def test_what_it_needs_is_required(missing: str) -> None:
    with pytest.raises(OrderInvalid):
        parse_create({k: v for k, v in GOOD.items() if k != missing})


def test_the_lists_are_the_named_profiles_and_the_cap_is_five_percent_by_default() -> None:
    assert PROFILES == ("claude-code", "openclaw")
    assert parse_create(GOOD).workspace_mib == 512
    assert parse_create({**GOOD, "volume_gib": 20}).workspace_mib == 1024
    full = parse_create(
        {**GOOD, "name": "Revisión 日本", "memory": MEMORIES[0], "cpus": CPUS[0],
         "proxy_memory": "256m", "daily_usd": "1,50", "monthly_usd": "10", "restart": True}
    )  # fmt: skip
    assert full.daily_usd == Decimal("1.50") and full.restart is True


@pytest.mark.parametrize(
    "name", ['"', "\\", 'a"\n[agent]\nprofile="custom', "Revisión 日本", "emoji \U0001f600", "a'b"]
)
def test_the_file_is_the_template_whatever_the_name_says(name: str) -> None:
    """The one free text: it goes as a string, and it never makes a key. A name with a line break
    does not even get here; this holds even if it did."""
    spec = AgentSpec(
        "tercero", "claude-code", 10, 512, name=name, memory="1g", cpus=2, proxy_memory="256m",
        daily_usd=Decimal("1.50"), monthly_usd=Decimal("10"),
    )  # fmt: skip
    data = tomllib.loads(agent_file_text(spec, 3, Path("/s/volume.img"), Path("/v/tercero")))
    assert data == {
        "number": 3,
        "name": name,
        "volume": "/v/tercero",
        "volume_image": "/s/volume.img",
        "max_volume_bytes": 15 * GIB,
        "workspace_limit": 512 * 1024**2,
        "agent": {"profile": "claude-code", "memory": "1g", "cpus": "2"},
        "proxy": {"memory": "256m"},
        "budget": {"daily_usd": 1.5, "monthly_usd": 10},
    }


# --- what fits --------------------------------------------------------------------------------


def test_memory_is_the_limits_of_what_runs_the_new_one_the_sensor_and_one_gib() -> None:
    assert memory_bytes("512m") == 512 * 1024**2 and memory_bytes("2g") == 2 * GIB
    with pytest.raises(ValueError):
        memory_bytes("mucho")
    # Decision 15: in 8 GiB, two agents with today's limits fit, and a third does not.
    assert memory_missing(8 * GIB, [3 * GIB], 3 * GIB, GIB) == 0
    assert memory_missing(8 * GIB, [3 * GIB, 3 * GIB], 3 * GIB, GIB) == 3 * GIB


def test_the_disk_counts_what_each_image_may_still_grow_to(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    with open(image, "wb") as file:
        file.truncate(GIB)
    assert still_to_grow(image, 2 * GIB) >= 2 * GIB - 4096 * 1024  # sparse: it takes nothing yet
    assert still_to_grow(tmp_path / "ninguno", GIB) == GIB
    image.write_bytes(b"x" * 1024**2)
    assert still_to_grow(image, 0) == 0  # never below nothing, without a ceiling
    assert disk_missing(100, [10, 20], 30, 10) == 0
    assert disk_missing(70, [10, 20], 30, 10) == 0
    assert disk_missing(69, [10, 20], 30, 10) == 1


# --- a machine, made up -----------------------------------------------------------------------


class Machine:
    """Every command the service would run, and what they leave mounted."""

    def __init__(self) -> None:
        self.ran: list[tuple[str, ...]] = []
        self.mounts: list[tuple[str, str, str]] = []  # point, type, source
        self.backings: dict[str, str] = {}
        self.fail: str | None = None
        self.no_image = False
        self.docker_networks: list[str] = []
        self.containers: list[str] = []  # T26-6c: what Docker has, which deleting takes away
        self.not_ours: set[str] = set()

    def _inspect(self, name: str, there: Sequence[str], role: str) -> Ran:
        if name not in there:
            return Ran(1, "", f"Error: No such object: {name}")
        labels = {} if name in self.not_ours else {"backtide.role": role}
        return Ran(0, f"{_docker_id(name)} {json.dumps(labels)}\n", "")

    def run(self, argv: Sequence[str]) -> Ran | None:
        argv = tuple(argv)
        self.ran.append(argv)
        text = " ".join(argv)
        if self.fail is not None and self.fail in text:
            return Ran(1, "", f"{self.fail} failed")
        if argv[0] == "systemd-mount":
            kind = next(a.removeprefix("--type=") for a in argv if a.startswith("--type="))
            source = "tmpfs"
            if kind == "btrfs":
                source = f"/dev/loop{len(self.backings)}"
                self.backings[source.removeprefix("/dev/")] = os.path.realpath(argv[-2])
            self.mounts.append((os.path.realpath(argv[-1]), kind, source))
        elif argv[0] == "systemd-umount":
            self.mounts = [m for m in self.mounts if m[0] != os.path.realpath(argv[-1])]
        elif argv[0] == "findmnt":
            return Ran(0, f"btrfs {layout.VOLUME_LABEL}\n", "")
        elif argv[:3] == ("stat", "-f", "-c"):
            return Ran(0, "apfs\n", "")
        elif argv[:3] == ("docker", "image", "inspect"):
            return Ran(1 if self.no_image else 0, "sha256:x\n", "")
        elif argv[:3] == ("docker", "network", "create"):
            self.docker_networks.append(argv[-1])
        elif argv[:3] == ("docker", "network", "rm"):
            found = [n for n in self.docker_networks if argv[-1] in (n, _docker_id(n))]
            self.docker_networks.remove(found[0])
        elif argv[:3] == ("docker", "network", "inspect"):
            role = "agent-network" if argv[-1].endswith("-net") else "egress"
            return self._inspect(argv[-1], self.docker_networks, role)
        elif argv[:3] == ("docker", "container", "inspect"):
            role = "proxy" if argv[-1].endswith("-egress") else "agent"
            return self._inspect(argv[-1], self.containers, role)
        elif argv[:3] == ("docker", "rm", "--force"):
            self.containers = [c for c in self.containers if _docker_id(c) != argv[-1]]
        elif argv[:2] == ("ip", "-j"):
            return Ran(0, "[]", "")
        elif argv[:3] == ("docker", "network", "ls"):
            return Ran(0, "", "")
        return Ran(0, "", "")

    def mountinfo(self) -> str:
        return "".join(
            f"36 35 0:1 / {point} rw - {kind} {source} rw\n" for point, kind, source in self.mounts
        )

    def backing(self, device: str) -> str | None:
        return self.backings.get(device)

    def commands(self, program: str) -> list[tuple[str, ...]]:
        return [argv for argv in self.ran if argv[0] == program]


def _docker_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


class FakeNeighbours:
    def __init__(self, roster: Roster | None = None, *, fails: str | None = None) -> None:
        self.calls: list[Any] = []
        self.running: set[str] = set()
        self.configs: dict[str, ServiceConfig] = {}
        self.failure: str | None = fails
        self.roster = roster
        self.stuck = False
        self.halts = True

    def add(self, config: ServiceConfig) -> None:
        self.calls.append(("add", config.slug))
        self.configs[config.slug] = config

    def start_one(self, config: ServiceConfig) -> None:
        self.calls.append(("start", config.slug))
        self.configs[config.slug] = config
        if self.failure is None:
            self.running.add(config.slug)
            if self.roster is not None:
                self.roster.publish(Desk(config.slug, FakeGuardian()))

    def wait_settled(self, slug: str, timeout: float) -> None:
        self.calls.append(("wait", slug))

    def is_running(self, slug: str) -> bool:
        return slug in self.running

    def failure_of(self, slug: str) -> str | None:
        return self.failure

    def stop_one(self, slug: str, requested_by: str = "") -> None:
        self.calls.append(("stop", slug, requested_by, is_stopped(self.configs[slug])))
        if not self.stuck:
            self.running.discard(slug)
            if self.roster is not None:
                self.roster.retire(slug)

    def config_of(self, slug: str) -> ServiceConfig | None:
        return self.configs.get(slug)

    def protect_also(self, slug: str, items: tuple[Protected, ...]) -> None:
        self.calls.append(("protect", slug, items))

    def halt(self, config: ServiceConfig) -> bool:
        self.calls.append(("halt", config.slug))
        return self.halts

    def forget(self, slug: str) -> None:
        self.calls.append(("forget", slug))
        self.configs.pop(slug, None)


class World:
    """One service with one neighbour, or with none (``alone``)."""

    def __init__(self, home: Path, *, alone: bool = False, main_extra: str = "") -> None:  # noqa: F811
        self.home = home
        write_main(home, f"[budget]\nauto_prices = false\n{main_extra}")
        (home / "etc" / "agents").mkdir(mode=0o755, exist_ok=True)
        if not alone:
            add_agent(home, "revisor", number=1)
        self.machine = Machine()
        found = load_installation(main_config(home))
        self.main = found.main
        self.stop = threading.Event()
        self.told = Sink()
        self.recorded: list[tuple[str, str, dict[str, Any]]] = []
        self.first_events: list[str] = []
        self.main_protected: list[Any] = []
        self.total: list[str] = []
        self.record_works = True
        self.roster = Roster(
            Desk("principal", FakeGuardian()), [(o.slug, o.display_name) for o in found.others]
        )
        self.neighbours = None if alone else FakeNeighbours(self.roster)
        if self.neighbours is not None:
            for other in found.others:
                self.neighbours.configs[other.slug] = other
                self.neighbours.running.add(other.slug)
        self.routes: list[Any] = []
        self.memory = 64 * GIB
        self.free = 1000 * GIB
        self.now = datetime(2026, 11, 2, 12, tzinfo=UTC)
        self.clock_good = True
        self.stopped_alive: list[str] = []
        self.fleet = self.make()

    def make(self, **options: Any) -> Fleet:
        return Fleet(
            self.main,
            main_config(self.home),
            roster=self.roster,
            neighbours=self.neighbours,
            stop=self.stop,
            told=self.told,
            record=self.record,
            first_event=lambda new, details: self.first_events.append(new.slug),
            protect_main=self.main_protected.append,
            open_box=options.pop("open_box", open_black_box),
            stop_alive=options.pop("stop_alive", self.stop_alive),
            now=lambda: self.now,
            clock_ok=options.pop("clock_ok", lambda: self.clock_good),
            add_to_total=lambda slug, folder: self.total.append(slug),
            run=self.machine.run,
            memory_total=lambda: self.memory,
            free_bytes=lambda path: self.free,
            unit=options.pop("unit", lambda: True),
            mountinfo=self.machine.mountinfo,
            backing=self.machine.backing,
            routes=options.pop("routes", lambda: self.routes),
            **options,
        )

    def stop_alive(self, config: ServiceConfig) -> bool:
        self.stopped_alive.append(config.slug)
        return False

    def record(self, action: str, target: str, details: dict[str, Any], **_: Any) -> bool:
        if not self.record_works:
            return False
        self.recorded.append((action, target, details))
        return True

    def actions(self) -> list[str]:
        return [action for action, _, _ in self.recorded]

    @property
    def volumes(self) -> Path:
        return self.home / "agent-volumes"

    def created_home(self, slug: str = "tercero") -> Path:
        return self.main.agents_dir / slug

    def agent_file(self, slug: str = "tercero") -> Path:
        return self.home / "etc" / "agents" / f"{slug}.toml"


@pytest.fixture
def world(home: Path, monkeypatch: pytest.MonkeyPatch) -> World:  # noqa: F811
    monkeypatch.setenv(agent_disk.AGENT_VOLUMES_ENV, str(home / "agent-volumes"))
    (home / "agent-volumes").mkdir(exist_ok=True)
    return World(home)


@pytest.fixture
def alone(home: Path, monkeypatch: pytest.MonkeyPatch) -> World:  # noqa: F811
    monkeypatch.setenv(agent_disk.AGENT_VOLUMES_ENV, str(home / "agent-volumes"))
    (home / "agent-volumes").mkdir(exist_ok=True)
    return World(home, alone=True)


# --- creating ---------------------------------------------------------------------------------


def test_create_leaves_a_real_agent_with_its_volume_channel_file_and_networks(world: World) -> None:
    reply = world.fleet.create(
        {**GOOD, "name": "Tercero", "memory": "1g", "cpus": 2, "proxy_memory": "256m"},
        "cli (uid 0, pid 1)",
    )
    assert reply["ok"] and reply["outcome"] == "created", reply
    home = world.created_home()
    image, volume = home / "volume.img", world.volumes / "tercero"
    # What it makes is what a start checks, and what it runs is a closed list of commands.
    assert image.stat().st_size == 10 * GIB and image.stat().st_mode & 0o777 == 0o600
    assert volume_mount_argv(image, volume) in world.machine.ran
    uid = 61200 + 2
    assert channel_mount_argv(home / "proxy-channel", uid, uid) in world.machine.ran
    assert mounted_at(volume, world.machine.mountinfo()) is not None
    assert not (home / "creating").exists()
    assert (home / NUMBER_FILE).read_text() == "2\n"
    config = load_installation(main_config(world.home)).agent("tercero")
    assert config.number == 2 and config.display_name == "Tercero"
    assert config.workspace_limit == 512 * 1024**2 and config.volume == volume
    assert config.jail_config().memory == "1g" and config.jail_config().uid == 61102
    assert config.jail_config().cpus == "2" and config.proxy_jail_config().memory == "256m"
    assert image_of(config) == image
    assert volume_problem(config, mountinfo=world.machine.mountinfo,
                          backing=world.machine.backing) is None  # fmt: skip
    # Its networks, each with its own subnet of the pool, made before anything starts.
    made = [a for a in world.machine.ran if a[:3] == ("docker", "network", "create")]
    assert {a[-1] for a in made} == {"backtide-tercero-net", "backtide-tercero-salida"}
    subnets = [a[a.index("--subnet") + 1] for a in made]
    assert len(set(subnets)) == 2 and all(s.startswith("172.29.") for s in subnets)
    # Who is told, in this order: the box first, the others' jails, the total, the list, the start.
    assert world.actions() == ["agent_create"]
    assert world.recorded[0][2]["requested_by"] == "cli (uid 0, pid 1)"
    assert world.first_events == ["tercero"]
    labels = {item.label for item in world.main_protected[0]}
    assert "the volume of the agent tercero" in labels
    assert world.total == ["tercero"]
    assert world.roster.knows("tercero")
    assert [c[0] for c in world.neighbours.calls] == ["protect", "add", "start", "wait"]
    alert = world.told.alerts[-1]
    assert alert.level is AlertLevel.ERROR and "tercero" in alert.title


def test_a_route_of_the_machine_keeps_its_subnet_out_and_blind_nothing_is_made(
    world: World,
) -> None:
    world.routes = routes_from_proc(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        "eth0 00000000 0100A8C0 0003 0 0 0 00000000 0 0 0\n"  # the default one says nothing
        "tun0 00FF1DAC 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"  # 172.29.255.0/24
        "roto XX 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
    )
    assert [str(route.network) for route in world.routes] == ["172.29.255.0/24"]
    assert world.fleet.create(GOOD, "x")["ok"]
    made = [a for a in world.machine.ran if a[:3] == ("docker", "network", "create")]
    assert "172.29.255.0/24" not in [a[a.index("--subnet") + 1] for a in made]

    def blind() -> list[Any]:
        raise OSError("no /proc")

    reply = world.make(routes=blind).create({**GOOD, "slug": "ciego"}, "x")
    assert reply["outcome"] == "failed" and not world.created_home("ciego").exists()


def test_a_second_try_of_the_same_slug_is_refused(world: World) -> None:
    assert world.fleet.create(GOOD, "x")["ok"]
    again = world.fleet.create(GOOD, "x")
    assert again["outcome"] == "refused" and "Ya hay" in again["message"]


def test_the_first_neighbour_says_it_restarts_and_only_goes_on_if_accepted(alone: World) -> None:
    reply = alone.fleet.create(GOOD, "x")
    assert reply["outcome"] == "needs_restart" and not reply["ok"]
    assert alone.machine.ran == [] and not alone.created_home().exists()
    assert not alone.stop.is_set() and alone.recorded == []
    reply = alone.fleet.create({**GOOD, "restart": True}, "x")
    assert reply["ok"] and reply["outcome"] == "restarting", reply
    assert alone.stop.is_set(), "systemd starts it all again"
    assert alone.agent_file().exists() and alone.first_events == ["tercero"]
    assert load_installation(main_config(alone.home)).others[0].slug == "tercero"
    # With its file there and no restart yet, nothing more is created.
    second = alone.fleet.create({**GOOD, "slug": "cuarto", "restart": True}, "x")
    assert second["outcome"] == "refused"


def test_outside_the_unit_nothing_is_created(world: World) -> None:
    reply = world.make(unit=lambda: False).create(GOOD, "x")
    assert reply["outcome"] == "refused" and "unidad" in reply["message"]
    assert world.machine.ran == []


def test_not_recorded_not_made(world: World) -> None:
    world.record_works = False
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "failed"
    assert not world.created_home().exists()
    assert not [a for a in world.machine.ran if a[0] != "docker"]


def test_memory_that_does_not_fit_is_refused_with_what_is_missing(world: World) -> None:
    world.memory = 8 * GIB  # principal 3, revisor 3, sensor 1, system 1: nothing left
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "refused" and "faltan 3.0 GiB" in reply["message"]
    assert not world.created_home().exists()
    fits = world.fleet.create(
        {**GOOD, "slug": "ligero", "memory": "512m", "proxy_memory": "256m"}, "x"
    )
    assert fits["outcome"] == "refused", "still does not fit: 0.75 GiB more"
    world.memory = 9 * GIB
    assert world.fleet.create({**GOOD, "slug": "ligero", "memory": "512m",
                               "proxy_memory": "256m"}, "x")["ok"]  # fmt: skip


def test_a_stopped_agent_does_not_count_for_memory(world: World) -> None:
    world.memory = 8 * GIB
    mark_stopped(load_agent(main_config(world.home), "revisor"))
    assert world.fleet.create(GOOD, "x")["ok"]


def test_a_disk_without_room_is_refused_before_anything_is_made(world: World) -> None:
    world.free = 10 * GIB  # sparse, and it would fit today: what counts is what it may grow to
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "refused" and "disco" in reply["message"]
    assert not world.created_home().exists()


def test_an_image_that_is_not_here_is_said_with_the_way_to_get_it(world: World) -> None:
    world.machine.no_image = True
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "refused" and "docker pull" in reply["message"]
    assert not world.created_home().exists()


def test_more_agents_than_the_limit_are_refused(world: World) -> None:
    for number in range(2, 8):
        add_agent(world.home, f"otro{number}", number=number)
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "refused" and "Como mucho 8" in reply["message"]


def test_a_cap_over_the_whole_installation_is_refused(world: World) -> None:
    fleet_ = world.make(whole_caps=lambda: (Decimal(5), Decimal(50)))
    reply = fleet_.create({**GOOD, "daily_usd": "6"}, "x")
    assert reply["outcome"] == "refused" and "5 $" in reply["message"]
    assert fleet_.create({**GOOD, "monthly_usd": "51"}, "x")["outcome"] == "refused"
    assert fleet_.create({**GOOD, "daily_usd": "4,50", "monthly_usd": "50"}, "x")["ok"]
    config = load_agent(main_config(world.home), "tercero")
    assert config.budget_settings().daily_usd == Decimal("4.50")
    assert config.own_caps == ("daily_usd", "monthly_usd")


def test_a_broken_file_of_another_agent_stops_a_creation(world: World) -> None:
    add_agent(world.home, "roto", "number = 9\n")
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "refused" and "a medias" in reply["message"]
    assert world.machine.ran == []


def test_one_order_at_a_time(world: World) -> None:
    world.fleet._busy.acquire()
    try:
        reply = world.fleet.create(GOOD, "x")
        assert reply["outcome"] == "refused" and "otra orden" in reply["message"]
        assert (
            world.fleet.start({"cmd": "agent_start", "agent": "revisor"}, "x")["outcome"]
            == "refused"
        )
        assert (
            world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "x")["outcome"] == "refused"
        )
    finally:
        world.fleet._busy.release()


@pytest.mark.parametrize(
    "step", ["mkfs.btrfs", "--type=btrfs", "--type=tmpfs", "backtide-tercero-net",
             "backtide-tercero-salida"],
)  # fmt: skip
def test_whatever_fails_undoes_what_it_made_and_says_so(world: World, step: str) -> None:
    world.machine.fail = step
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "failed", reply
    assert "deshecho" in reply["message"]
    assert world.actions() == ["agent_create", "agent_create_failed"]
    assert not world.created_home().exists()
    assert not world.agent_file().exists()
    assert world.machine.mounts == []
    assert world.machine.docker_networks == []
    assert not world.roster.knows("tercero") and world.first_events == []
    # And with the cause gone, it can be asked again.
    world.machine.fail = None
    assert world.fleet.create(GOOD, "x")["ok"]


def test_a_machine_that_died_half_way_leaves_a_mark_and_the_next_try_starts_clean(
    world: World,
) -> None:
    home = world.created_home()
    home.mkdir(mode=0o700, parents=True)
    (home / fleet.CREATING).write_text("")
    (home / "volume.img").write_text("half")
    (home / NUMBER_FILE).write_text("9\n")
    assert world.fleet.create(GOOD, "x")["ok"]
    assert (home / "volume.img").stat().st_size == 10 * GIB


def test_a_slug_that_was_used_is_never_used_again_and_neither_is_its_number(world: World) -> None:
    """An agent's folder stays with its black box when it goes (docs/47, 8.5)."""
    gone = world.main.agents_dir / "viejo"
    gone.mkdir(mode=0o700, parents=True)
    (gone / NUMBER_FILE).write_text("7\n")
    reply = world.fleet.create({**GOOD, "slug": "viejo"}, "x")
    assert reply["outcome"] == "refused" and "ya se usó" in reply["message"]
    assert world.fleet.create(GOOD, "x")["ok"]
    assert load_agent(main_config(world.home), "tercero").number == 8


def test_a_number_that_is_an_account_of_the_machine_is_skipped(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fleet, "id_taken", lambda number: number == 61102)
    assert world.fleet.create(GOOD, "x")["ok"]
    assert load_agent(main_config(world.home), "tercero").number == 3


def test_an_openclaw_gets_its_own_token(world: World) -> None:
    reply = world.fleet.create({**GOOD, "profile": "openclaw"}, "x")
    assert reply["ok"], reply
    token = world.created_home() / "gateway.token"
    assert token.stat().st_mode & 0o777 == 0o600 and len(token.read_text().strip()) >= 32
    config = load_agent(main_config(world.home), "tercero")
    assert config.gateway_token is not None and config.gateway_token.reveal() in token.read_text()


def test_a_new_agent_that_does_not_start_is_said(world: World) -> None:
    world.neighbours.failure = "its volume is gone"
    reply = world.fleet.create(GOOD, "x")
    assert reply["outcome"] == "failed" and "its volume is gone" in reply["message"]


# --- starting and stopping ---------------------------------------------------------------------


def test_stop_leaves_its_mark_before_it_stops_and_start_takes_it_away(world: World) -> None:
    order = {"cmd": "agent_stop", "agent": "revisor"}
    reply = world.fleet.stop(order, "cli (uid 0, pid 2)")
    assert reply["ok"] and reply["outcome"] == "stopped", reply
    assert ("stop", "revisor", "cli (uid 0, pid 2)", True) in world.neighbours.calls
    config = world.neighbours.configs["revisor"]
    assert is_stopped(config)
    assert world.actions() == ["agent_stop_asked"]
    assert world.roster.listing()[1]["state"] == STOPPED_BY_OWNER
    assert world.fleet.stop(order, "x")["outcome"] == "already"

    reply = world.fleet.start({"cmd": "agent_start", "agent": "revisor"}, "x")
    assert reply["ok"] and reply["outcome"] == "started", reply
    assert not is_stopped(config) and world.roster.listing()[1]["state"] != STOPPED_BY_OWNER
    assert (
        world.fleet.start({"cmd": "agent_start", "agent": "revisor"}, "x")["outcome"] == "already"
    )


def test_stopping_goes_ahead_when_it_cannot_be_recorded_or_marked(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stopping is the safe way: a full disk or a broken box must not keep an agent running."""
    world.record_works = False

    def no_mark(config: ServiceConfig) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(fleet, "mark_stopped", no_mark)
    reply = world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "x")
    assert reply["ok"] and reply["outcome"] == "stopped", reply
    assert "caja" in reply["message"] and "marca" in reply["message"]
    assert not world.neighbours.is_running("revisor")
    # Starting is not the safe way: not recorded, not done.
    reply = world.fleet.start({"cmd": "agent_start", "agent": "revisor"}, "x")
    assert reply["outcome"] == "failed" and not world.neighbours.is_running("revisor")


def test_stopped_is_what_docker_says_never_the_mark(world: World) -> None:
    order = {"cmd": "agent_stop", "agent": "revisor"}
    assert world.fleet.stop(order, "x")["ok"]
    assert ("halt", "revisor") in world.neighbours.calls  # also once its thread has ended
    world.neighbours.calls.clear()
    assert world.fleet.stop(order, "x")["outcome"] == "already"
    assert ("halt", "revisor") in world.neighbours.calls  # with the mark on, it asks all the same
    world.neighbours.halts = False
    reply = world.fleet.stop(order, "x")
    assert reply["outcome"] == "failed" and "sigue en marcha" in reply["message"]
    world.neighbours.running.add("revisor")
    reply = world.fleet.stop(order, "x")
    assert reply["outcome"] == "failed" and "sigue en marcha" in reply["message"]


def test_a_stop_that_does_not_end_says_so(world: World) -> None:
    world.neighbours.stuck = True
    reply = world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "x")
    assert reply["outcome"] == "failed" and not reply["ok"]


def test_the_main_agent_is_not_started_or_stopped_here(world: World, alone: World) -> None:
    for fleet_ in (world.fleet, alone.fleet):
        for call, cmd in ((fleet_.stop, "agent_stop"), (fleet_.start, "agent_start")):
            reply = call({"cmd": cmd, "agent": "principal"}, "x")
            assert reply["outcome"] == "refused" and "principal" in reply["message"]


@pytest.mark.parametrize(
    "order",
    [
        {"cmd": "agent_stop"},
        {"cmd": "agent_stop", "agent": "../x"},
        {"cmd": "agent_stop", "agent": 7},
        {"cmd": "agent_stop", "agent": "revisor", "force": True},
    ],
)
def test_an_order_about_one_has_its_shape(world: World, order: dict[str, Any]) -> None:
    with pytest.raises(OrderInvalid):
        world.fleet.stop(order, "x")
    assert world.recorded == []


def test_an_agent_that_is_nobodys_is_refused(world: World) -> None:
    for call, cmd in ((world.fleet.stop, "agent_stop"), (world.fleet.start, "agent_start")):
        reply = call({"cmd": cmd, "agent": "nadie"}, "x")
        assert reply["outcome"] == "refused" and "no existe" in reply["message"]
    assert world.recorded == []


def test_starting_checks_memory_again(world: World) -> None:
    assert world.fleet.stop({"cmd": "agent_stop", "agent": "revisor"}, "x")["ok"]
    world.memory = 6 * GIB
    reply = world.fleet.start({"cmd": "agent_start", "agent": "revisor"}, "x")
    assert reply["outcome"] == "refused" and "memoria" in reply["message"]
    assert is_stopped(world.neighbours.configs["revisor"]), "it stays as it was"


# --- what an agent has on the disk --------------------------------------------------------------


def lines(*mounts: tuple[Path | str, str, str]) -> str:
    return "".join(f"1 2 0:1 / {p} rw - {kind} {src} rw\n" for p, kind, src in mounts)


def an_agent(home: Path, extra: str = "") -> ServiceConfig:  # noqa: F811
    write_main(home, "[budget]\nauto_prices = false\n")
    add_agent(home, "revisor", number=1)
    return load_agent(main_config(home), "revisor")


def test_a_volume_that_is_not_its_images_mount_point_is_never_used(home: Path) -> None:  # noqa: F811
    config = an_agent(home)
    image = image_of(config)
    volume = os.path.realpath(config.volume)
    good = {"loop5": os.path.realpath(image)}
    check = lambda info, backs=good: volume_problem(  # noqa: E731
        config, mountinfo=lambda: info, backing=backs.get
    )
    assert "not mounted" in check("")
    assert check(lines((volume, "btrfs", "/dev/loop5"))) is None
    assert "ext4" in check(lines((volume, "ext4", "/dev/loop5")))
    # The disk of the machine, a device of someone else, or another agent's image.
    assert "not from" in check(lines((volume, "btrfs", "/dev/vda2")))
    assert "not from" in check(lines((volume, "btrfs", "/dev/loop5")), {"loop5": "/otra/imagen"})
    assert "not from" in check(lines((volume, "btrfs", "/dev/loop5")), {})
    # What counts is the one on top.
    assert "tmpfs" in check(lines((volume, "btrfs", "/dev/loop5"), (volume, "tmpfs", "x")))
    # A folder inside the volume is not the volume.
    assert "not mounted" in check(lines((f"{volume}/x", "btrfs", "/dev/loop5")))


def test_a_file_without_a_cap_is_refused(home: Path) -> None:  # noqa: F811
    write_main(home)
    folder = home / "etc" / "agents"
    folder.mkdir(mode=0o755)
    (folder / "revisor.toml").write_text(
        f'number = 1\nvolume = "{home / "v"}"\n[agent]\nprofile = "claude-code"\n'
    )
    with pytest.raises(ConfigError, match="workspace_limit"):
        load_installation(main_config(home))
    with pytest.raises(ConfigError, match="workspace_limit"):
        load_agent(main_config(home), "revisor")


def test_ensure_on_disk_mounts_what_is_not_there_and_leaves_what_is(home: Path) -> None:  # noqa: F811
    config = an_agent(home)
    machine = Machine()
    options = {"run": machine.run, "mountinfo": machine.mountinfo, "backing": machine.backing}
    with pytest.raises(AgentDiskError, match="image"):
        ensure_on_disk(config, mounting=True, **options)  # no image: never mounts a folder
    assert machine.ran == []
    image_of(config).write_bytes(b"x")
    config.volume.parent.mkdir(exist_ok=True)
    ensure_on_disk(config, mounting=True, **options)
    assert len(machine.commands("systemd-mount")) == 2
    proxy = config.proxy_jail_config()
    assert channel_mount_argv(proxy.channel_dir, proxy.uid, proxy.gid) in machine.ran
    ensure_on_disk(config, mounting=True, **options)  # after that, a start changes nothing
    assert len(machine.commands("systemd-mount")) == 2


def test_outside_a_unit_nothing_is_mounted_and_the_check_still_holds(home: Path) -> None:  # noqa: F811
    config = an_agent(home)
    machine = Machine()
    with pytest.raises(AgentDiskError, match="not mounted"):
        ensure_on_disk(
            config, mounting=False, run=machine.run, mountinfo=machine.mountinfo,
            backing=machine.backing,
        )  # fmt: skip
    assert machine.ran == []


def test_a_mount_that_fails_is_said_with_what_systemd_said(home: Path) -> None:  # noqa: F811
    config = an_agent(home)
    image_of(config).write_bytes(b"x")
    config.volume.parent.mkdir(exist_ok=True)
    machine = Machine()
    machine.fail = "systemd-mount"
    with pytest.raises(AgentDiskError, match="failed"):
        ensure_on_disk(
            config, mounting=True, run=machine.run, mountinfo=machine.mountinfo,
            backing=machine.backing,
        )  # fmt: skip


def test_only_the_root_of_a_btrfs_just_mounted_is_sealed(tmp_path: Path) -> None:
    point = tmp_path / "volumen"
    point.mkdir(mode=0o755)
    for info in ("", lines((point, "tmpfs", "x"))):
        with pytest.raises(AgentDiskError):
            seal_root(point, info)
        assert point.stat().st_mode & 0o777 == 0o755, "never the folder underneath"
    seal_root(point, lines((point, "btrfs", "/dev/loop1")))
    assert point.stat().st_mode & 0o777 == 0o700


def test_the_stopped_mark_never_follows_a_link(home: Path) -> None:  # noqa: F811
    config = an_agent(home)
    target = home / "fuera"
    (config.agent_dir / agent_disk.STOPPED_MARK).symlink_to(target)
    with pytest.raises(OSError):
        mark_stopped(config)
    assert not target.exists()


# --- each neighbour on its own -----------------------------------------------------------------


class FakeJailed:
    def __init__(self) -> None:
        self.protected: list[Any] = []
        self.orders: list[Any] = []

    def protect_also(self, items: Any) -> None:
        self.protected.append(items)

    def owner_order(self, action: str, details: dict[str, Any]) -> None:
        self.orders.append((action, details))


@pytest.fixture
def three(home: Path) -> tuple[ServiceConfig, tuple[ServiceConfig, ...]]:  # noqa: F811
    write_main(home, "[budget]\nauto_prices = false\n")
    add_agent(home, "bueno", number=1)
    add_agent(home, "otro", number=2)
    found = load_installation(main_config(home))
    return found.main, found.others


def neighbours_of(
    three_: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
    **options: Any,
) -> tuple[_Neighbours, threading.Event, dict[str, FakeJailed], dict[str, threading.Event]]:
    main, others = three_
    stop = threading.Event()
    guardians: dict[str, FakeJailed] = {}
    ended: dict[str, threading.Event] = {}

    def build(config: ServiceConfig, **_: Any) -> Any:
        guardians[config.slug] = FakeJailed()
        ended[config.slug] = threading.Event()
        return (guardians[config.slug], "alerts", "box")

    def run(guardian: Any, *_: Any, stop: threading.Event, control: Any = None, **__: Any) -> None:
        if control is not None:
            control.start()
        stop.wait(30)
        slug = next(s for s, g in guardians.items() if g is guardian)
        ended[slug].set()
        if control is not None:
            control.close()

    found = _Neighbours(
        main, others, notifier_for=lambda slug: None, stop=stop, share=None, told=Sink(),  # type: ignore[arg-type]
        build=build, run=run, prepare=options.pop("prepare", lambda config: None),
        stop_alive=options.pop("stop_alive", lambda config: False), **options,
    )  # fmt: skip
    return found, stop, guardians, ended


def test_one_stops_and_the_others_go_on_and_the_service_stop_reaches_all(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    found, stop, guardians, ended = neighbours_of(three)
    found.start()
    found.wait_settled("bueno", 10)
    found.wait_settled("otro", 10)
    for _ in range(200):
        if found.is_running("bueno") and found.is_running("otro") and "bueno" in guardians:
            break
        threading.Event().wait(0.05)
    for _ in range(200):
        if "bueno" in ended and "otro" in ended:
            break
        threading.Event().wait(0.05)
    found.stop_one("bueno", "cli (uid 0, pid 3)")
    assert ended["bueno"].is_set() and not found.is_running("bueno")
    assert guardians["bueno"].orders == [
        ("agent_stop_asked", {"requested_by": "cli (uid 0, pid 3)"})
    ]
    assert not ended["otro"].is_set() and found.is_running("otro")
    stop.set()
    found.join(10)
    assert ended["otro"].is_set()


def test_one_the_owner_stopped_is_not_started_again_at_a_restart(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    mark_stopped(three[1][0])
    found, stop, guardians, _ = neighbours_of(three)
    found.start()
    found.wait_settled("otro", 10)
    for _ in range(200):
        if "otro" in guardians:
            break
        threading.Event().wait(0.05)
    assert "bueno" not in guardians and "otro" in guardians
    assert not found.is_running("bueno")
    stop.set()
    found.join(10)


def test_one_marked_stopped_but_alive_is_stopped_at_the_start_and_told(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    mark_stopped(three[1][0])
    asked: list[str] = []

    def stop_alive(config: ServiceConfig) -> bool:
        asked.append(config.slug)
        return True

    found, stop, _, _ = neighbours_of(three, stop_alive=stop_alive)
    found.start()
    assert asked == ["bueno"], "only the one with the mark, and only Docker can say"
    with open_installation_box(three[0]) as box:
        (event,) = box.events(action="agent_stop")
    assert event.target == "bueno" and event.risk == 2
    assert event.details["reason"] == "unsupervised"
    assert any("sin vigilancia" in alert.title for alert in found._told.alerts)
    stop.set()
    found.join(10)


def test_one_that_could_not_be_stopped_is_the_worst_and_it_is_said(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    def stop_alive(config: ServiceConfig) -> bool:
        raise JailError("docker no contesta")

    found, stop, _, _ = neighbours_of(three, stop_alive=stop_alive)
    assert found.halt(three[1][0]) is False
    with open_installation_box(three[0]) as box:
        (event,) = box.events(action="agent_stop_failed")
    assert event.risk == 3 and "docker no contesta" in event.details["error"]
    assert any("sigue en marcha" in alert.title for alert in found._told.alerts)
    stop.set()


def test_nothing_alive_is_nothing_told(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    found, stop, _, _ = neighbours_of(three)
    assert found.halt(three[1][0]) is True
    assert found._told.alerts == []
    stop.set()


def test_what_a_killed_service_left_is_stopped_when_its_disk_cannot_be_prepared(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    asked: list[str] = []

    def prepare(config: ServiceConfig) -> None:
        raise AgentDiskError("its image is gone")

    def stop_alive(config: ServiceConfig) -> bool:
        asked.append(config.slug)
        return False

    found, stop, guardians, _ = neighbours_of(three, prepare=prepare, stop_alive=stop_alive)
    found.start()
    found.wait_settled("bueno", 10)
    found.wait_settled("otro", 10)
    stop.set()
    found.join(10)
    assert sorted(asked) == ["bueno", "otro"] and guardians == {}


def test_a_stop_that_cannot_be_noted_still_stops(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    found, stop, guardians, ended = neighbours_of(three)
    found.start()
    for _ in range(200):
        if "bueno" in found._guardians and "bueno" in ended:
            break
        threading.Event().wait(0.05)

    def broken(action: str, details: dict[str, Any]) -> None:
        raise RuntimeError("the box is gone")

    guardians["bueno"].owner_order = broken  # type: ignore[method-assign]
    found.stop_one("bueno", "x")
    assert ended["bueno"].is_set()
    stop.set()
    found.join(10)


def test_a_new_agent_joins_and_every_jail_up_or_still_being_built_is_told(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
    home: Path,  # noqa: F811
) -> None:
    found, stop, guardians, _ = neighbours_of(three)
    found.start()
    for _ in range(200):
        if {"bueno", "otro"} <= set(guardians) and found._guardians.keys() >= {"bueno", "otro"}:
            break
        threading.Event().wait(0.05)
    add_agent(home, "tercero", number=3)
    new = load_installation(main_config(home)).agent("tercero")
    item = Protected("the volume of the agent tercero", new.volume)
    found.protect_also("tercero", (item,))
    assert guardians["bueno"].protected == [(item,)]
    assert guardians["otro"].protected == [(item,)]
    # An agent that read the installation before it existed, and starts now, is told too...
    found.stop_one("bueno")
    found.start_one(three[1][0])
    for _ in range(200):
        if guardians["bueno"].protected == [(item,)] and found.is_running("bueno"):
            break
        threading.Event().wait(0.05)
    assert guardians["bueno"].protected == [(item,)]
    # ...and the new one is not told of itself.
    found.add(new)
    found.start_one(new)
    for _ in range(200):
        if "tercero" in guardians:
            break
        threading.Event().wait(0.05)
    threading.Event().wait(0.1)
    assert guardians["tercero"].protected == []
    stop.set()
    found.join(10)


def test_one_that_cannot_prepare_its_disk_is_told_and_the_others_go_on(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    def prepare(config: ServiceConfig) -> None:
        if config.slug == "bueno":
            raise AgentDiskError("its volume's image is not there")

    found, stop, guardians, _ = neighbours_of(three, prepare=prepare)
    found.start()
    found.wait_settled("bueno", 10)
    for _ in range(200):
        if found.failure_of("bueno"):
            break
        threading.Event().wait(0.05)
    assert "its volume's image" in found.failure_of("bueno")
    assert "bueno" not in guardians, "it is not built on a disk that is not its"
    for _ in range(200):
        if found.is_running("otro") and "otro" in guardians:
            break
        threading.Event().wait(0.05)
    assert "otro" in guardians
    stop.set()
    found.join(10)


def test_a_stopped_agents_keys_are_not_handed_any_more(
    three: tuple[ServiceConfig, tuple[ServiceConfig, ...]],
) -> None:
    main, others = three
    stop = threading.Event()
    gate = threading.Event()

    def build(config: ServiceConfig, *, on_egress: Any, **_: Any) -> Any:
        on_egress("egress")
        return (FakeJailed(), "alerts", "box")

    def run(*_: Any, stop: threading.Event, **__: Any) -> None:
        gate.set()
        stop.wait(30)

    found = _Neighbours(
        main, others[:1], notifier_for=lambda slug: None, stop=stop, share=None, told=Sink(),  # type: ignore[arg-type]
        build=build, run=run, prepare=lambda config: None, stop_alive=lambda config: False,
    )  # fmt: skip
    found.start()
    assert gate.wait(10)
    assert len(found.reloads()) == 1
    found.stop_one("bueno")
    assert found.reloads() == []
    stop.set()
    found.join(10)


# --- the sockets --------------------------------------------------------------------------------


class Recording:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, str]] = []
        self.raises: Exception | None = None

    def _call(self, name: str, request: Any, by: str) -> dict[str, Any]:
        self.calls.append((name, dict(request), by))
        if self.raises is not None:
            raise self.raises
        return {"ok": True, "outcome": "created", "message": "hecho"}

    def create(self, request: Any, by: str) -> dict[str, Any]:
        return self._call("create", request, by)

    def delete(self, request: Any, by: str) -> dict[str, Any]:
        return self._call("delete", request, by)

    def restore(self, request: Any, by: str) -> dict[str, Any]:
        return self._call("restore", request, by)

    def purge(self, request: Any, by: str) -> dict[str, Any]:
        return self._call("purge", request, by)

    def start(self, request: Any, by: str) -> dict[str, Any]:
        return self._call("start", request, by)

    def stop(self, request: Any, by: str) -> dict[str, Any]:
        return self._call("stop", request, by)


class Pausing(FakeGuardian):
    def __init__(self) -> None:
        super().__init__()
        self.paused: list[str] = []
        self.resumed: list[str] = []

    def pause_by_user(self, *, requested_by: str) -> Any:
        from backtide.service.pause import PauseOutcome, PauseStatus  # noqa: PLC0415

        self.paused.append(requested_by)
        return PauseOutcome(PauseStatus.FROZEN, "Agente congelado", "frozen")


@pytest.fixture
def sock_dir() -> Iterator[Path]:
    # tmp_path can be too long for a unix socket's name.
    folder = Path(tempfile.mkdtemp(prefix="bt", dir="/tmp"))
    os.chmod(folder, 0o700)
    yield folder
    shutil.rmtree(folder)


def served(sock_dir: Path, **options: Any) -> ControlServer:
    server = ControlServer(
        options.pop("guardian", FakeGuardian()), sock_dir / "c.sock", peer=me, **options
    )
    server.start()
    return server


def test_the_orders_reach_the_fleet_with_who_asked(sock_dir: Path) -> None:
    orders = Recording()
    server = served(sock_dir, fleet=orders)
    try:
        path = sock_dir / "c.sock"
        reply = ask_agent_order(path, dict(GOOD), peer=me, wait=0)
        assert reply == {"ok": True, "outcome": "created", "message": "hecho"}
        ask_agent_order(path, {"cmd": "agent_stop", "agent": "x"}, peer=me, wait=0)
        ask_agent_order(path, {"cmd": "agent_start", "agent": "x"}, peer=me, wait=0)
    finally:
        server.close()
    assert [name for name, _, _ in orders.calls] == ["create", "stop", "start"]
    assert orders.calls[0][2].startswith("cli (uid ")


def test_an_order_outside_its_shape_is_invalid_and_a_bug_is_said(sock_dir: Path) -> None:
    orders = Recording()
    server = served(sock_dir, fleet=orders)
    try:
        path = sock_dir / "c.sock"
        orders.raises = OrderInvalid("no")
        reply = ask_agent_order(path, dict(GOOD), peer=me, wait=0)
        assert reply["outcome"] == "invalid" and reply["message"] == "no"
        orders.raises = RuntimeError("secreto")
        reply = ask_agent_order(path, dict(GOOD), peer=me, wait=0)
        assert reply["outcome"] == "failed" and "secreto" not in reply["message"]
    finally:
        server.close()


def test_with_no_fleet_nothing_is_created(sock_dir: Path) -> None:
    server = served(sock_dir)
    try:
        reply = ask_agent_order(sock_dir / "c.sock", dict(GOOD), peer=me, wait=0)
    finally:
        server.close()
    assert reply["ok"] is False and reply["outcome"] == "refused"


@pytest.mark.parametrize(
    "command",
    [
        "agent_create", "agent_start", "agent_stop", "agent_pause", "agent_resume", "agent_delete",
        "agent_restore", "agent_purge",
    ],
)  # fmt: skip
def test_none_of_these_is_on_the_webs_list(command: str, sock_dir: Path) -> None:
    """Prepared for T26-6b, and off its list until then: not even a live session gets there."""
    assert command not in COMMANDS
    guardian = FakeGuardian()
    server = WebControlServer(
        guardian, sock_dir / "web.sock", peer=the_web, group=GROUP, snapshots=list,
        sessions=signed_in(), on_entry=lambda action, details: True,
    )  # fmt: skip
    server.start()
    try:
        reply = talk(server, {"cmd": command, "agent": "x", "slug": "x", "session": SESSION})
    finally:
        server.close()
    assert reply["ok"] is False and reply["outcome"] == "refused"
    assert "socket de la web" in reply["message"]


def test_freezing_says_which_always(sock_dir: Path) -> None:
    main, other = Pausing(), Pausing()
    roster = Roster(Desk("principal", main), [("revisor", None)])
    roster.publish(Desk("revisor", other))
    server = served(sock_dir, guardian=main, roster=roster)
    path = sock_dir / "c.sock"
    try:
        reply = ask_agent_order(path, {"cmd": "agent_pause"}, peer=me, wait=0)
        assert reply["outcome"] == "refused" and main.paused == []
        reply = ask_agent_order(path, {"cmd": "agent_pause", "agent": "revisor"}, peer=me, wait=0)
        assert reply["ok"] and reply["outcome"] == "frozen"
        assert other.paused and main.paused == []
        reply = ask_agent_order(path, {"cmd": "agent_pause", "agent": "nadie"}, peer=me, wait=0)
        assert reply["outcome"] == "refused"
        reply = ask_agent_order(
            path, {"cmd": "agent_pause", "agent": "revisor", "force": 1}, peer=me, wait=0
        )
        assert reply["outcome"] == "refused"
        reply = ask_agent_order(path, {"cmd": "agent_resume", "agent": "revisor"}, peer=me, wait=0)
        assert reply["ok"]
        assert ask_agents(path, peer=me, wait=0)[1]["slug"] == "revisor"
    finally:
        server.close()


# --- what comes with it -------------------------------------------------------------------------


def test_the_total_counts_a_new_agent_from_its_first_call(home: Path) -> None:  # noqa: F811
    spend = InstallationSpend(BudgetSettings(), members={"principal": home}, folder=home / "state")
    assert set(spend.status()["agents"]) == {"principal"}
    spend.add_member("tercero", home / "nadie")
    assert set(spend.status()["agents"]) == {"principal", "tercero"}
    assert spend.caps() == (
        Decimal(BudgetSettings().daily_usd),
        Decimal(BudgetSettings().monthly_usd),
    )


def test_a_jail_takes_the_new_agents_paths_and_refuses_its_own(home: Path) -> None:  # noqa: F811
    config = an_agent(home)
    jail = AgentJail(config.jail_config())
    before = jail.config.protected
    other = Protected("the volume of the agent otro", home / "otro")
    jail.protect_also((other,))
    assert jail.config.protected == (*before, other)
    with pytest.raises(ValueError):
        jail.protect_also((Protected("its own", config.volume / "workspace"),))


def test_the_egress_charges_what_it_had_in_flight_when_it_stops() -> None:
    from backtide.service.egress import Egress  # noqa: PLC0415

    class FakeBudget:
        def __init__(self) -> None:
            self.forgotten = 0

        def forget_all(self) -> None:
            self.forgotten += 1

    class FakeProxy:
        class config:  # noqa: N801
            name = "x"

        def is_running(self) -> bool:
            return False

        def stop(self) -> None: ...
        def remove(self) -> None: ...
        def kill(self) -> None: ...

    budget = FakeBudget()
    egress = Egress.__new__(Egress)
    assert hasattr(egress, "stop")
    egress.budget = budget
    egress._closing = threading.Event()
    egress._ticker = None
    egress._prices = None
    egress._lock = threading.RLock()
    egress._up = True
    egress._channel = None
    egress._stop_container = lambda: None  # type: ignore[method-assign]
    egress._close_channel = lambda why: None  # type: ignore[method-assign]
    egress._record = lambda *_, **__: None  # type: ignore[method-assign]
    egress.local_refusals = type("L", (), {"flush": lambda self: None})()
    egress.stop("service_stop")
    assert budget.forgotten == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["agentes", "crear", "../x", "--perfil", "claude-code", "--volumen", "10"],
        ["agentes", "crear", "tercero", "--perfil", "custom", "--volumen", "10"],
        ["agentes", "crear", "tercero", "--perfil", "claude-code", "--volumen", "7"],
        ["agentes", "crear", "tercero", "--perfil", "claude-code", "--volumen", "10",
         "--memoria", "9g"],
        ["agentes", "crear", "tercero", "--perfil", "claude-code", "--volumen", "10",
         "--imagen", "evil"],
        ["agentes", "parar", "/etc"],
        ["agentes", "borrar", "../x", "--confirmar", "../x"],
        ["agentes", "vaciar", "/etc", "--confirmar", "/etc"],
        ["agentes", "recuperar", "a/b"],
    ],
)  # fmt: skip
def test_the_cli_only_takes_what_the_service_takes(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as ended:
        cli.main(argv)
    assert ended.value.code == 2


def order_of(monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any]) -> list[dict[str, Any]]:
    asked: list[dict[str, Any]] = []

    def ask(path: Any, request: dict[str, Any]) -> dict[str, Any]:
        asked.append(request)
        return reply

    monkeypatch.setattr(agentes, "ask_agent_order", ask)
    return asked


def test_the_cli_sends_what_was_asked_and_nothing_else(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = main_config(home)
    write_main(home, "[budget]\nauto_prices = false\n")
    asked = order_of(monkeypatch, {"ok": True, "outcome": "created", "message": "hecho"})
    code = cli.main(
        ["agentes", "crear", "tercero", "--perfil", "claude-code", "--volumen", "10",
         "--config", str(config)]
    )  # fmt: skip
    assert code == 0 and "hecho" in capsys.readouterr().out
    assert asked[-1] == {
        "cmd": "agent_create", "slug": "tercero", "profile": "claude-code", "volume_gib": 10,
    }  # fmt: skip
    code = cli.main(
        ["agentes", "crear", "tercero", "--perfil", "openclaw", "--volumen", "20",
         "--tope-espacio", "100", "--nombre", "T", "--memoria", "1g", "--cpus", "2",
         "--memoria-proxy", "256m", "--dia", "1", "--mes", "2", "--reiniciar",
         "--config", str(config)]
    )  # fmt: skip
    assert code == 0
    assert asked[-1] == {
        "cmd": "agent_create", "slug": "tercero", "profile": "openclaw", "volume_gib": 20,
        "workspace_mib": 100, "name": "T", "memory": "1g", "cpus": 2, "proxy_memory": "256m",
        "daily_usd": "1", "monthly_usd": "2", "restart": True,
    }  # fmt: skip
    for name, command in (("parar", "agent_stop"), ("arrancar", "agent_start"),
                          ("pausar", "agent_pause"), ("seguir", "agent_resume")):  # fmt: skip
        assert cli.main(["agentes", name, "tercero", "--config", str(config)]) == 0
        assert asked[-1] == {"cmd": command, "agent": "tercero"}


@pytest.mark.parametrize(
    ("outcome", "code", "said"),
    [("needs_restart", 1, "--reiniciar"), ("refused", 1, "no"), ("invalid", 2, "no")],
)
def test_the_cli_says_what_the_service_refused(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: str,
    code: int,
    said: str,
) -> None:
    write_main(home, "[budget]\nauto_prices = false\n")
    order_of(monkeypatch, {"ok": False, "outcome": outcome, "message": "no \x1b[31m"})
    assert cli.main(["agentes", "parar", "x", "--config", str(main_config(home))]) == code
    err = capsys.readouterr().err
    assert said in err and "\x1b" not in err


def test_the_cli_with_no_service_says_so(
    home: Path,  # noqa: F811
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backtide.service.control import ControlUnavailable  # noqa: PLC0415

    write_main(home, "[budget]\nauto_prices = false\n")

    def nobody(*_: Any, **__: Any) -> Any:
        raise ControlUnavailable("nadie")

    monkeypatch.setattr(agentes, "ask_agent_order", nobody)
    monkeypatch.setattr(agentes, "ask_agents", nobody)
    config = str(main_config(home))
    assert cli.main(["agentes", "parar", "x", "--config", config]) == 1
    assert "vigilar" in capsys.readouterr().err
    assert cli.main(["agentes", "lista", "--config", config]) == 1


def test_the_list_says_who_was_stopped_and_who_failed(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_main(home, "[budget]\nauto_prices = false\n")
    monkeypatch.setattr(
        agentes,
        "ask_agents",
        lambda path: [
            {"slug": "principal", "name": None, "main": True, "watched": True, "state": "running"},
            {"slug": "a", "name": "Á", "main": False, "watched": False, "state": STOPPED_BY_OWNER},
            {"slug": "b", "name": None, "main": False, "watched": False, "state": None},
        ],
    )
    monkeypatch.setattr(agentes, "ask_deleted", lambda path: [])
    assert cli.main(["agentes", "lista", "--config", str(main_config(home))]) == 0
    out = capsys.readouterr().out
    assert (
        "principal: running" in out and "a («Á»): parado por ti" in out and "b: sin vigilar" in out
    )
