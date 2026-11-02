"""Creating, starting and stopping agents from the service (T26-6a; docs/47, sections 6.7 and 8).

Making a jail is the power of backtide itself, so the order has a closed shape:

- **``agent_create``** takes exactly the fields of ``CREATE_FIELDS``, each from a list or a range,
  and a field it does not know (``image``, ``mounts``, ``privileged``, a path...) is ``invalid``
  with nothing touched. No field is a path or an image: the volume and the image come from the slug
  and the profile, and the only free text is the name to show, which reaches no command. The file
  ``agents/<slug>.toml`` is written from this module's template, never from what was sent.
- **Who can ask.** Only the control socket (root's, 0600). None of these orders is on the list of
  the web's narrow socket (T26-6b adds them, behind a key just touched), and the sockets are never
  in an agent's jail (invariants 1 and 2), so no agent reaches them.
- **What it checks** before touching anything: the slug (never used: an agent's black box stays
  when it goes, and its name with it), at most ``MAX_AGENTS``, its image here, room in memory
  (decision 15) and room on disk. The limits of what runs, the new one and the sensor, with 1 GiB
  for the system; on disk, everything each image may still grow to. A sparse file takes nothing now,
  and the disk is everyone's: when it fills, P6 pauses every agent (review of T26-2b).
- **Order of the steps.** First the installation's black box (not written, not done). Then the
  volume and the channel (``agent_disk``), then the file, which is what makes it an agent, read back
  with the same checks as a start (``load_installation``), then the networks with their subnets.
  Whatever fails undoes what this order made, and a machine that died half way leaves a mark
  (``CREATING``) so that the next try with that slug starts clean.
- **The first neighbour restarts the service.** With one agent the service runs none of what
  several need (it was the design of T26-2b: with one agent nothing of it is on), and turning it on
  under a running agent would touch the budget, the sensor and the alerts. So the service stops
  and systemd starts it again: the main agent is stopped and started, and the order must say it
  accepts that (``restart``). From the second on, the running ones are told of the new one and go
  on.
- **Numbers** are never reused (decision 14): the next is one above any seen, also of agents gone,
  whose folder stays with their black box.
- ``agent_stop`` leaves a mark in the agent's folder before it stops, so a reboot does not start it
  again. What it had held is ended by its own stop (invariant 6). It goes ahead even if it cannot be
  recorded or marked: stopping is the safe way, and what could not be done is said. And "stopped" is
  Docker's word, never the mark's: a container alive with no Guardian is stopped, here and at the
  service's start, or said. The main agent is not stopped here: it runs the sockets, and stopping it
  is stopping the service.
- Each order is in the installation's box with who asked, and starts with the agent's own.
- **Deleting** (T26-6c; ``backtide.service.trash``): ``agent_delete`` says the slug twice (the
  second written by a person), and it stops the agent, closes its black box with
  ``system/agent_deleted``,
  removes its containers and networks and unmounts its volume, which waits ``trash.KEEP_DAYS`` in
  the image. Not recorded, not done; and each step can be tried again, by the same order or by the
  next start of the service (``finish_interrupted``). ``agent_restore`` brings it back as it was,
  stopped; ``agent_purge`` empties it, and so does ``tend_trash`` after the wait, with a warning a
  day before. Nothing of it is on the web's list: T26-6b adds ``agent_delete`` alone, and emptying
  stays on root's socket for good, because what cannot be undone must not hang on the process that
  faces the internet. The main agent is never deleted, and a slug that was used stays taken.
"""

import json
import logging
import os
import re
import shutil
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import BlackBox, BlackBoxError, redact
from backtide.jail import identity
from backtide.jail.config import AgentJailConfig, Protected
from backtide.jail.config import network_create_argv as agent_network_argv
from backtide.jail.identity import MAX_AGENTS, MAX_NUMBER
from backtide.jail.proxy_config import network_create_argv as egress_network_argv
from backtide.notify import Alert, AlertLevel, AlertSink
from backtide.service import trash
from backtide.service.agent_disk import (
    AGENT_VOLUMES_ENV,
    AgentDiskError,
    anything_mounted_under,
    channel_mount_argv,
    clear_stopped,
    ensure_on_disk,
    is_stopped,
    mark_stopped,
    mount,
    mounted_at,
    read_backing,
    read_mountinfo,
    seal_root,
    umount_argv,
    under_unit,
    volume_mount_argv,
)
from backtide.service.agents import (
    Installation,
    check_fits,
    id_taken,
    image_of,
    load_installation,
    load_retired,
    protected_of,
)
from backtide.service.clock import clock_synced
from backtide.service.config import (
    AGENTS_FOLDER,
    RETIRED_MARK,
    SAVED_AGENT_FILE,
    STATE_DB,
    STATE_PROXY_CHANNEL,
    STATE_TOKEN,
    ConfigError,
    ServiceConfig,
    agent_profile_of,
    ensure_state_folder,
)
from backtide.service.roster import NOBODY, OrderInvalid, Roster
from backtide.service.spend import check_cap
from backtide.service.trash import NUMBER_FILE
from backtide.setup import containers, host, images, layout, networks, volume
from backtide.setup.host import Runner
from backtide.setup.secrets import new_token

logger = logging.getLogger(__name__)

PROFILES = tuple(sorted(images.AGENTS))  # the named ones: `custom` only by hand, with sudo
VOLUME_SIZES_GIB = (10, 20, 50)
MEMORIES = ("512m", "1g", "2g", "4g")
PROXY_MEMORIES = ("256m", "512m", "1g")
CPUS = (1, 2, 4)
MIN_WORKSPACE_MIB = 64  # what a snapshot and a turn need at the very least
SYSTEM_MEMORY = layout.GIB  # decision 15
CREATE_FIELDS = frozenset(
    {
        "cmd", "slug", "profile", "name", "volume_gib", "workspace_mib", "memory", "cpus",
        "proxy_memory", "daily_usd", "monthly_usd", "restart",
    }
)  # fmt: skip
CREATED, RESTARTING, STARTED, STOPPED, ALREADY = (
    "created", "restarting", "started", "stopped", "already",
)  # fmt: skip
DELETED, RESTORED, PURGED = "deleted", "restored", "purged"
INVALID, REFUSED, FAILED, NEEDS_RESTART = "invalid", "refused", "failed", "needs_restart"
DONE = frozenset({CREATED, RESTARTING, STARTED, STOPPED, ALREADY, DELETED, RESTORED, PURGED})
OUTCOMES = DONE | {INVALID, REFUSED, FAILED, NEEDS_RESTART}
CREATING = "creating"  # in the agent's folder, while it is not one yet
START_WAIT = 240.0  # an agent's start, with its image's checks and its first snapshot
TRASH_EVERY = 3600.0  # how often the trash is looked at: its times are days
_MEMORY = re.compile(r"([0-9]+)([bkmg]?)", re.ASCII)
_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


@dataclass(frozen=True)
class AgentSpec:
    """An ``agent_create`` that has its shape. Nothing here is a path or an image."""

    slug: str
    profile: str
    volume_gib: int
    workspace_mib: int
    name: str | None = None
    memory: str | None = None
    cpus: int | None = None
    proxy_memory: str | None = None
    daily_usd: Decimal | None = None
    monthly_usd: Decimal | None = None
    restart: bool = False


def _whole(value: object) -> bool:
    return type(value) is int


def parse_create(request: Mapping[str, Any]) -> AgentSpec:
    """The ``agent_create`` of ``request``, or OrderInvalid with nothing touched."""
    if set(request) - CREATE_FIELDS:
        raise OrderInvalid(
            "Esa orden lleva campos que no se aceptan: un agente se crea con su nombre, su perfil, "
            "su volumen y sus topes, y nada más. No se ha hecho nada."
        )
    slug = request.get("slug")
    try:
        identity.check_slug(slug)
    except identity.SlugError:
        raise OrderInvalid(
            "El nombre corto de un agente va en minúsculas, cifras y guiones (hasta 32), y no "
            "puede ser uno reservado. No se ha hecho nada."
        ) from None
    profile = request.get("profile")
    if not isinstance(profile, str) or profile not in PROFILES:
        raise OrderInvalid(f"El perfil es uno de estos: {', '.join(PROFILES)}.")
    gib = request.get("volume_gib")
    if not _whole(gib) or gib not in VOLUME_SIZES_GIB:
        raise OrderInvalid(f"El volumen es uno de estos, en GiB: {_listed(VOLUME_SIZES_GIB)}.")
    mib = request.get("workspace_mib", gib * 1024 // 20)  # 5 % of the volume (docs/19)
    if not _whole(mib) or not MIN_WORKSPACE_MIB <= mib <= gib * 1024 // 2:
        raise OrderInvalid(
            f"El tope de espacio va de {MIN_WORKSPACE_MIB} MiB a la mitad del volumen."
        )
    memory = request.get("memory")
    if memory is not None and memory not in MEMORIES:
        raise OrderInvalid(f"La memoria es una de estas: {', '.join(MEMORIES)}.")
    proxy_memory = request.get("proxy_memory")
    if proxy_memory is not None and proxy_memory not in PROXY_MEMORIES:
        raise OrderInvalid(f"La memoria del proxy es una de estas: {', '.join(PROXY_MEMORIES)}.")
    cpus = request.get("cpus")
    if cpus is not None and (not _whole(cpus) or cpus not in CPUS):
        raise OrderInvalid(f"Las CPU son una de estas: {_listed(CPUS)}.")
    restart = request.get("restart", False)
    if not isinstance(restart, bool):
        raise OrderInvalid("`restart` es sí o no.")
    return AgentSpec(
        slug=slug,
        profile=profile,
        volume_gib=gib,
        workspace_mib=mib,
        name=_name_of(request.get("name")),
        memory=memory,
        cpus=cpus,
        proxy_memory=proxy_memory,
        daily_usd=_cap_of(request.get("daily_usd")),
        monthly_usd=_cap_of(request.get("monthly_usd")),
        restart=restart,
    )


def _listed(values: Sequence[int]) -> str:
    return ", ".join(str(value) for value in values)


def _name_of(name: object) -> str | None:
    """As the agent's file takes it (``agents._display_name`` checks it again when read)."""
    if name is None:
        return None
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > identity.MAX_NAME
        or not name.isprintable()
    ):
        raise OrderInvalid(
            f"El nombre va de 1 a {identity.MAX_NAME} caracteres, sin caracteres de control."
        )
    return name


def _cap_of(value: object) -> Decimal | None:
    if value is None:
        return None
    cap = check_cap(value)
    if cap is None:
        raise OrderInvalid("Un tope es una cantidad de dólares mayor que cero, como «2» o «7,50».")
    return cap


def agent_file_text(spec: AgentSpec, number: int, image: Path, mount_point: Path) -> str:
    """The agent's file: this template and the values of a checked order, never what was sent.
    The name goes as a TOML string; the rest are numbers, list values and our own paths."""
    size = spec.volume_gib * layout.GIB
    lines = [
        "# Written by backtide when the agent was created (T26-6a). Its slug and number are for "
        "good.",
        f"number = {number}",
    ]
    if spec.name is not None:
        lines.append(f"name = {json.dumps(spec.name, ensure_ascii=False)}")
    lines += [
        f"volume = {json.dumps(str(mount_point))}",
        f"volume_image = {json.dumps(str(image))}",
        f"max_volume_bytes = {size * 3 // 2}",  # as the main agent's: 1.5 times (D25)
        f"workspace_limit = {spec.workspace_mib * 1024**2}",
        "",
        "[agent]",
        f'profile = "{spec.profile}"',
    ]
    if spec.memory is not None:
        lines.append(f'memory = "{spec.memory}"')
    if spec.cpus is not None:
        lines.append(f'cpus = "{spec.cpus}"')  # Docker's, a text: as [agent] takes it
    if spec.proxy_memory is not None:
        lines += ["", "[proxy]", f'memory = "{spec.proxy_memory}"']
    if spec.daily_usd is not None or spec.monthly_usd is not None:
        lines += ["", "[budget]"]
        if spec.daily_usd is not None:
            lines.append(f"daily_usd = {spec.daily_usd}")
        if spec.monthly_usd is not None:
            lines.append(f"monthly_usd = {spec.monthly_usd}")
    return "\n".join(lines) + "\n"


def memory_bytes(limit: str) -> int:
    """Docker's ``512m``, ``2g``. Raises ValueError for anything else."""
    found = _MEMORY.fullmatch(limit.strip().lower())
    if found is None:
        raise ValueError(f"not a memory limit: {limit!r}")
    return int(found[1]) * _UNITS[found[2]]


def limits_of(config: ServiceConfig) -> int:
    """What this agent and its proxy may take of the machine's memory."""
    return memory_bytes(config.jail_config().memory) + memory_bytes(
        config.proxy_jail_config().memory
    )


def memory_missing(total: int, running: Sequence[int], new: int, sensor: int) -> int:
    """How many bytes are missing to add ``new`` (decision 15): 0 if it fits."""
    return max(0, sum(running) + new + sensor + SYSTEM_MEMORY - total)


def still_to_grow(image: Path, ceiling: int) -> int:
    """How much of the machine's disk this image may still take. Links are not followed."""
    try:
        info = os.lstat(image)
    except FileNotFoundError:
        return ceiling
    return max(0, max(ceiling, info.st_size) - info.st_blocks * 512)


def disk_missing(free: int, images_left: Sequence[int], new: int, room: int) -> int:
    """How many bytes are missing so that every image can reach its ceiling, this one too, with
    ``room`` left for Docker and the rest: 0 if it fits."""
    return max(0, sum(images_left) + new + room - free)


def read_routes(path: Path = Path("/proc/net/route")) -> list[networks.Route]:
    """The machine's routes, or OSError and no network is made: a subnet chosen blind could hide
    the LAN or a VPN (T13-3)."""
    return networks.routes_from_proc(path.read_text(encoding="ascii", errors="replace"))


def read_memory_total(path: Path = Path("/proc/meminfo")) -> int:
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    raise ValueError("no MemTotal in /proc/meminfo")


def _gib(size: int) -> str:
    return f"{size / layout.GIB:.1f} GiB"


class Neighbours(Protocol):
    """What this module needs of ``runner._Neighbours``."""

    def add(self, config: ServiceConfig) -> None: ...

    def start_one(self, config: ServiceConfig) -> None: ...

    def wait_settled(self, slug: str, timeout: float) -> None: ...

    def is_running(self, slug: str) -> bool: ...

    def failure_of(self, slug: str) -> str | None: ...

    def stop_one(self, slug: str, requested_by: str = ...) -> None: ...

    def config_of(self, slug: str) -> ServiceConfig | None: ...

    def protect_also(self, slug: str, items: tuple[Protected, ...]) -> None: ...

    def halt(self, config: ServiceConfig) -> bool: ...

    def forget(self, slug: str) -> None: ...


class Fleet:
    """The orders about which agents there are. One at a time: a second one is refused, because
    what they check (memory, numbers, subnets) is what the first is about to take."""

    def __init__(
        self,
        main: ServiceConfig,
        config_path: Path,
        *,
        roster: Roster,
        neighbours: Neighbours | None,
        stop: threading.Event,
        told: AlertSink,
        record: Callable[..., bool],
        first_event: Callable[[ServiceConfig, dict[str, Any]], None],
        protect_main: Callable[[tuple[Protected, ...]], None],
        open_box: Callable[[ServiceConfig], BlackBox],
        stop_alive: Callable[[ServiceConfig], bool],
        add_to_total: Callable[[str, Path], None] | None = None,
        whole_caps: Callable[[], tuple[Decimal, Decimal]] | None = None,
        run: Runner = host.run,
        memory_total: Callable[[], int] = read_memory_total,
        free_bytes: Callable[[Path], int] | None = None,
        unit: Callable[[], bool] = under_unit,
        start_wait: float = START_WAIT,
        mountinfo: Callable[[], str] = read_mountinfo,
        backing: Callable[[str], str | None] = read_backing,
        routes: Callable[[], list[networks.Route]] = read_routes,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        clock_ok: Callable[[], bool] = clock_synced,
    ) -> None:
        self._open_box = open_box
        self._stop_alive = stop_alive
        self._now = now
        self._clock_ok = clock_ok
        self._routes = routes
        self._mountinfo = mountinfo
        self._backing = backing
        self._main = main
        self._path = Path(config_path)
        self._roster = roster
        self._neighbours = neighbours
        self._stop = stop
        self._told = told
        self._record = record
        self._first_event = first_event
        self._protect_main = protect_main
        self._add_to_total = add_to_total
        self._whole_caps = whole_caps
        self._run = run
        self._memory_total = memory_total
        self._free_bytes = free_bytes if free_bytes is not None else _free_bytes
        self._unit = unit
        self._start_wait = start_wait
        self._busy = threading.Lock()
        self._purge_said: set[str] = set()

    @property
    def _volumes(self) -> Path:
        return Path(os.environ.get(AGENT_VOLUMES_ENV, str(layout.AGENT_VOLUMES)))

    @contextmanager
    def _one_at_a_time(self) -> Any:
        if not self._busy.acquire(blocking=False):
            raise _Refused(
                REFUSED, "Ya hay otra orden sobre los agentes en marcha: espera a que acabe."
            )
        try:
            yield
        finally:
            self._busy.release()

    # Create

    def create(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]:
        spec = parse_create(request)  # OrderInvalid: before anything looks at the machine
        try:
            with self._one_at_a_time():
                return self._create(spec, requested_by)
        except _Refused as refused:
            logger.warning("refused to create an agent: %s", refused.outcome)
            return _reply(refused.outcome, str(refused))

    def _create(self, spec: AgentSpec, requested_by: str) -> dict[str, Any]:
        installation = self._read_all()
        self._check_can_create(spec, installation)
        number = self._next_number(installation)
        details: dict[str, Any] = {
            "requested_by": requested_by,
            "profile": spec.profile,
            "number": number,
            "volume_gib": spec.volume_gib,
            "workspace_mib": spec.workspace_mib,
        }
        if not self._record("agent_create", spec.slug, details, risk=1):
            raise _Refused(
                FAILED, "No se ha podido apuntar en la caja de la instalación: no se ha hecho nada."
            )
        made: list[Callable[[], None]] = []
        try:
            new = self._make(spec, number, made)
        except Exception as error:
            logger.exception("the agent %s could not be created", spec.slug)
            for undo in reversed(made):
                _quietly(undo)
            said = str(redact(f"{type(error).__name__}: {error}"))[:300]
            self._record("agent_create_failed", spec.slug, {"error": said}, risk=2)
            return _reply(
                FAILED, f"No se ha podido crear el agente: {said}. Se ha deshecho lo hecho."
            )
        try:
            self._first_event(new, details)
        except Exception:  # its Guardian opens that box next, and says it far louder
            logger.exception("the first event of the agent %s could not be written", spec.slug)
        self._told.submit(
            Alert(
                AlertLevel.ERROR,
                f"Agente nuevo: {spec.slug}",
                f"Se ha creado el agente {spec.slug} ({spec.profile}). Si no has sido tú, páralo "
                "con `sudo backtide agentes parar`.",
                agent=spec.slug,
            )
        )
        if self._neighbours is None:
            self._roster.add(new.slug, new.display_name)
            self._stop.set()  # the control socket answers this order before it closes
            return _reply(
                RESTARTING,
                f"Agente {spec.slug} creado. El servicio se reinicia para llevar a más de un "
                "agente: el principal se para y vuelve a arrancar, y los dos arrancan a la vez.",
            )
        items = tuple(protected_of(new))
        self._protect_main(items)
        self._neighbours.protect_also(new.slug, items)
        if self._add_to_total is not None:
            self._add_to_total(new.slug, new.agent_dir)
        self._roster.add(new.slug, new.display_name)
        self._neighbours.add(new)
        return self._start_and_tell(new, CREATED, f"Agente {spec.slug} creado y en marcha.")

    def _read_all(self) -> Installation:
        try:
            return load_installation(self._path)
        except ConfigError as error:
            raise _Refused(
                REFUSED,
                "La configuración no se puede leer entera, y esto no se hace a medias: "
                f"{redact(str(error))}",
            ) from None

    def _check_can_create(self, spec: AgentSpec, installation: Installation) -> None:
        if not self._unit():
            raise _Refused(
                REFUSED,
                "Crear un agente pide el servicio instalado: fuera de su unidad no se puede montar "
                "su volumen.",
            )
        if self._neighbours is None and len(installation.agents) > 1:
            raise _Refused(REFUSED, "El servicio aún no se ha reiniciado tras crear otro agente.")
        if len(installation.agents) >= MAX_AGENTS:
            raise _Refused(REFUSED, f"Como mucho {MAX_AGENTS} agentes, contando el principal.")
        home = self._main.agents_dir / spec.slug
        if os.path.lexists(self._file_of(spec.slug)):
            raise _Refused(REFUSED, f"Ya hay un agente {spec.slug}.")
        if os.path.lexists(home) and (
            not os.path.lexists(home / CREATING) or os.path.lexists(home / RETIRED_MARK)
        ):
            raise _Refused(
                REFUSED,
                f"El nombre {spec.slug} ya se usó: su caja negra se queda, y dos agentes no "
                "comparten nombre en la historia.",
            )
        if self._neighbours is None and not spec.restart:
            raise _Refused(
                NEEDS_RESTART,
                "Es el primer agente además del principal: el servicio tiene que reiniciarse, y "
                "con él el principal, que se para y vuelve a arrancar. Lo que tenga a medias se "
                "pierde. Si te va bien, pídelo otra vez aceptándolo.",
            )
        self._check_caps(spec)
        self._check_image(spec)
        self._check_memory(
            installation,
            memory_bytes(spec.memory or _default(AgentJailConfig, "memory"))
            + memory_bytes(spec.proxy_memory or self._main.proxy_jail_config().memory),
        )
        self._check_disk(spec.volume_gib * layout.GIB * 3 // 2, installation)

    def _check_caps(self, spec: AgentSpec) -> None:
        if self._whole_caps is not None:
            day, month = self._whole_caps()
        else:
            settings = self._main.budget_settings()
            day, month = settings.daily_usd, settings.monthly_usd
        if (spec.daily_usd is not None and spec.daily_usd > day) or (
            spec.monthly_usd is not None and spec.monthly_usd > month
        ):
            raise _Refused(
                REFUSED,
                f"El tope de un agente no puede pasar del de toda la instalación ({day} $ al día "
                f"y {month} $ al mes).",
            )

    def _check_image(self, spec: AgentSpec) -> None:
        reference = images.AGENTS[spec.profile].ref
        ran = self._run(("docker", "image", "inspect", "--format", "{{.Id}}", reference))
        if ran is None or ran.returncode != 0:
            raise _Refused(
                REFUSED,
                f"La imagen de {spec.profile} no está en esta máquina, y el servicio no la baja: "
                f"`docker pull {reference}`, y vuelve a pedirlo.",
            )

    def _check_memory(self, installation: Installation, new: int, leaving: str = "") -> None:
        running = [
            limits_of(config)
            for config in installation.agents
            if config.slug != leaving and (config.is_main or not is_stopped(config))
        ]
        sensor = memory_bytes(self._main.sensor_jail_config().memory)
        missing = memory_missing(self._memory_total(), running, new, sensor)
        if missing:
            raise _Refused(
                REFUSED,
                f"No cabe en la memoria de esta máquina: faltan {_gib(missing)}. Sumo los límites "
                "de lo que está en marcha, este y el sensor, y dejo 1 GiB para el sistema. Para "
                "otro agente o crea este con menos.",
            )

    def _check_disk(self, new: int, installation: Installation) -> None:
        """``new``: what the agent about to be here may still take of the disk."""
        left = [
            still_to_grow(
                image_of(config),
                config.max_volume_bytes if config.max_volume_bytes is not None else 0,
            )
            for config in installation.agents
        ]
        missing = disk_missing(self._free_bytes(self._main.state_dir), left, new, layout.GROW_ROOM)
        if missing:
            raise _Refused(
                REFUSED,
                f"No cabe en el disco de esta máquina: faltan {_gib(missing)}. Cuento lo que cada "
                "volumen puede llegar a ocupar: un archivo disperso no ocupa hoy, pero si el disco "
                "se llena se pausan todos los agentes.",
            )

    def _next_number(self, installation: Installation) -> int:
        used = {config.number for config in installation.agents}
        try:
            names = os.listdir(self._main.agents_dir)
        except FileNotFoundError:
            names = []
        for name in names:
            used.add(_number_in(self._main.agents_dir / name / NUMBER_FILE))
        for mark in trash.retired_agents(self._main.agents_dir).values():
            if mark is not None:  # the file `number` is there, unless someone took it away
                used.add(mark.number)
        number = max(used, default=0) + 1
        while number <= MAX_NUMBER:
            if not (id_taken(identity.agent_id(number)) or id_taken(identity.proxy_id(number))):
                return number
            number += 1
        raise _Refused(REFUSED, f"Ya no quedan números de agente (hasta {MAX_NUMBER}).")

    def _file_of(self, slug: str) -> Path:
        return self._path.parent / AGENTS_FOLDER / f"{slug}.toml"

    def _make(self, spec: AgentSpec, number: int, made: list[Callable[[], None]]) -> ServiceConfig:
        """Everything on the machine. ``made`` is what to undo, last first, if a step fails."""
        home = self._main.agents_dir / spec.slug
        image = home / "volume.img"
        mount_point = self._volumes / spec.slug
        channel = home / STATE_PROXY_CHANNEL
        ensure_state_folder(self._main.agents_dir, "the agents' folder")
        if os.path.lexists(home):  # a marked leftover of a machine that died: `_check_can_create`
            self._undo_home(home, mount_point, channel)
        ensure_state_folder(home, "the agent's folder")
        made.append(lambda: self._undo_home(home, mount_point, channel))
        _write_new(home / CREATING, "")
        _write_new(home / NUMBER_FILE, f"{number}\n")
        if agent_profile_of({"profile": spec.profile}).token_env is not None:
            _write_new(home / STATE_TOKEN, f"{new_token()}\n")
        size = spec.volume_gib * layout.GIB
        nocow = volume.host_is_btrfs(home, run=self._run)
        volume.create_image(image, size, run=self._run, nocow=nocow)
        plan_b = volume.format_image(image, run=self._run)
        volume.prepare_mountpoint(mount_point)
        mount(volume_mount_argv(image, mount_point), self._run)
        if plan_b:
            ran = self._run(volume.quota_enable_argv(mount_point))
            if ran is None or ran.returncode != 0:
                raise AgentDiskError("this btrfs has no simple quotas: the cap would not hold")
        seal_root(mount_point, self._mountinfo())
        os.mkdir(channel, 0o700)
        uid = identity.proxy_id(number)
        mount(channel_mount_argv(channel, uid, uid), self._run)
        file = self._file_of(spec.slug)
        _write_whole(file, agent_file_text(spec, number, image, mount_point))
        made.append(lambda: file.unlink(missing_ok=True))
        new = load_installation(self._path).agent(spec.slug)
        self._make_networks(new, made)
        ensure_on_disk(  # the check of every start
            new, run=self._run, mounting=False, mountinfo=self._mountinfo, backing=self._backing
        )
        os.unlink(home / CREATING)
        return new

    def _make_networks(self, new: ServiceConfig, made: list[Callable[[], None]]) -> None:
        """Each with a free subnet, as the installer does for the main agent's (T13-3)."""
        wanted = [
            (new.jail_config().network, agent_network_argv(new.jail_config())),
            (new.proxy_jail_config().network, egress_network_argv(new.proxy_jail_config())),
        ]
        taken = [route.network for route in self._routes()]
        taken += networks.docker_subnets(self._run)
        chosen = networks.choose(taken, len(wanted))
        for (name, argv), subnet in zip(wanted, chosen, strict=True):
            ran = self._run(networks.with_subnet(argv, subnet))
            if ran is None or ran.returncode != 0:
                said = " ".join((ran.stderr if ran is not None else "").split())[:200]
                raise networks.NetworkError(f"cannot make the network {name}: {said}")
            made.append(lambda name=name: self._run_quietly(("docker", "network", "rm", name)))

    def _run_quietly(self, argv: tuple[str, ...]) -> None:
        ran = self._run(argv)
        if ran is None or ran.returncode != 0:
            logger.error("undoing an agent's creation, this failed: %s", " ".join(argv))

    def _undo_home(self, home: Path, mount_point: Path, channel: Path) -> None:
        """Only what this order made: it never gets here for a folder without its mark. If
        something stays mounted the folder stays too, and it is said."""
        for point in (channel, mount_point):
            if mounted_at(point, self._mountinfo()) is not None:
                self._run_quietly(umount_argv(point))
        if any(mounted_at(p, self._mountinfo()) is not None for p in (channel, mount_point)):
            logger.error("%s stays: something of it is still mounted", home)
            return
        if os.path.lexists(home / STATE_DB):
            logger.error("%s stays: it has a black box, which is never deleted", home)
            return
        shutil.rmtree(home)
        try:
            os.rmdir(mount_point)
        except OSError:
            logger.warning("the mount point %s stays", mount_point)

    # Start and stop

    def start(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]:
        slug = _agent_of(request)
        try:
            with self._one_at_a_time():
                return self._start(slug, requested_by)
        except _Refused as refused:
            logger.warning("refused to start the agent %s: %s", slug, refused.outcome)
            return _reply(refused.outcome, str(refused))

    def _start(self, slug: str, requested_by: str) -> dict[str, Any]:
        neighbours = self._others(slug)
        if neighbours.is_running(slug):
            return _reply(ALREADY, f"El agente {slug} ya está en marcha.")
        installation = self._read_all()
        try:
            config = installation.agent(slug)
        except ConfigError:
            raise _Refused(REFUSED, NOBODY) from None
        self._check_memory(installation, limits_of(config), leaving=slug)
        if not self._record("agent_start_asked", slug, {"requested_by": requested_by}, risk=1):
            raise _Refused(
                FAILED, "No se ha podido apuntar en la caja de la instalación: no se ha hecho nada."
            )
        try:
            clear_stopped(config)
        except OSError as error:
            return _reply(FAILED, f"No se ha podido quitar la marca de parado: {error.strerror}.")
        self._roster.mark_stopped(slug, stopped=False)
        return self._start_and_tell(config, STARTED, f"El agente {slug} está en marcha.")

    def _start_and_tell(self, config: ServiceConfig, done: str, text: str) -> dict[str, Any]:
        neighbours = self._others(config.slug)
        neighbours.start_one(config)
        neighbours.wait_settled(config.slug, self._start_wait)
        if self._roster.watched(config.slug):
            return _reply(done, text)
        failure = neighbours.failure_of(config.slug)
        if failure is not None:
            return _reply(FAILED, f"El agente {config.slug} no ha arrancado: {failure}")
        return _reply(
            FAILED,
            f"El agente {config.slug} aún no ha arrancado tras {int(self._start_wait)} s: mira "
            "la caja de la instalación.",
        )

    def stop(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]:
        slug = _agent_of(request)
        try:
            with self._one_at_a_time():
                return self._stop_agent(slug, requested_by)
        except _Refused as refused:
            logger.warning("refused to stop the agent %s: %s", slug, refused.outcome)
            return _reply(refused.outcome, str(refused))

    def _stop_agent(self, slug: str, requested_by: str) -> dict[str, Any]:
        neighbours = self._others(slug)
        config = neighbours.config_of(slug)
        if config is None:
            raise _Refused(REFUSED, NOBODY)
        if is_stopped(config) and not neighbours.is_running(slug):
            if not neighbours.halt(config):  # Docker's word, not the mark's
                return _reply(FAILED, f"El agente {slug} sigue en marcha y no se ha podido parar.")
            return _reply(ALREADY, f"El agente {slug} ya está parado.")
        # Stopping is the safe way: nothing that fails here gets in its way. Recording and the
        # mark come first if they can, and what could not be done is said.
        said = ""
        if not self._record("agent_stop_asked", slug, {"requested_by": requested_by}, risk=1):
            said += " No ha quedado en la caja de la instalación."
        try:
            mark_stopped(config)  # first: if the machine dies now, it stays stopped
        except OSError as error:
            logger.error("the agent %s has no stopped mark: %s", slug, error.strerror)
            said += " No se ha podido dejar la marca: volverá a arrancar con el servicio."
        self._roster.mark_stopped(slug, stopped=True)
        was_running = neighbours.is_running(slug)  # one that had already failed is simply stopped
        neighbours.stop_one(slug, requested_by)
        if neighbours.is_running(slug):
            return _reply(
                FAILED,
                f"El agente {slug} no ha terminado de pararse: mira `docker ps` y la caja negra.",
            )
        if not neighbours.halt(config):  # whatever its thread said: Docker's word
            return _reply(FAILED, f"El agente {slug} sigue en marcha y no se ha podido parar.")
        failure = neighbours.failure_of(slug)
        if was_running and failure is not None:
            return _reply(FAILED, f"Al parar al agente {slug} ha fallado algo: {failure}{said}")
        return _reply(
            STOPPED,
            f"Agente {slug} parado: lo que tenía retenido se ha rechazado. No arranca hasta "
            f"`backtide agentes arrancar {slug}`, tampoco tras reiniciar la máquina.{said}",
        )

    def _others(self, slug: str) -> Neighbours:
        """The ones this module may start or stop: not the main one, which runs the sockets."""
        if slug == identity.MAIN_SLUG:
            raise _Refused(
                REFUSED,
                "El principal lleva los sockets y el resto de los agentes: se para con "
                "`systemctl stop backtide`, o se congela con `backtide agentes pausar principal`.",
            )
        if self._neighbours is None or not self._roster.knows(slug):
            raise _Refused(REFUSED, NOBODY)
        return self._neighbours

    # Delete, bring back and empty (T26-6c)

    def delete(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]:
        slug = _typed_agent_of(request)
        try:
            with self._one_at_a_time():
                return self._delete(slug, requested_by)
        except _Refused as refused:
            logger.warning("refused to delete the agent %s: %s", slug, refused.outcome)
            return _reply(refused.outcome, str(refused))

    def _delete(self, slug: str, requested_by: str) -> dict[str, Any]:
        _not_the_main(slug)
        mark = self._mark_of(slug)
        if mark is not None and mark.state == trash.RETIRED:
            return _reply(ALREADY, f"El agente {slug} ya está borrado.")
        if not self._unit():
            raise _Refused(
                REFUSED,
                "Borrar un agente pide el servicio instalado: fuera de su unidad no se puede "
                "desmontar su volumen.",
            )
        if mark is None:
            config, mark = self._close_agent(slug, requested_by)
        else:  # a try that stopped half way, or a machine that died: it goes on from there
            config = self._resume_delete(slug, requested_by)
        self._finish_delete(config, mark)
        return _reply(
            DELETED,
            f"Agente {slug} borrado: está parado y sin contenedores ni redes. Su caja negra se "
            f"queda. Su volumen y sus instantáneas esperan hasta el {_day(mark.purge_after)}: "
            f"`sudo backtide agentes recuperar {slug}` lo devuelve entero.",
        )

    def _close_agent(self, slug: str, requested_by: str) -> tuple[ServiceConfig, trash.Retired]:
        """Up to the mark: from then on it is nobody. Whatever fails here leaves it a stopped agent,
        which can be started or asked for again, with its black box closed or not."""
        neighbours = self._others(slug)
        config = neighbours.config_of(slug)
        if config is None:
            raise _Refused(REFUSED, NOBODY)
        try:
            text = trash.read_agent_file(self._file_of(slug))
        except (OSError, ValueError):
            text = None
        if text is None:
            raise _Refused(
                REFUSED,
                f"No se puede leer el archivo del agente {slug}, y sin él no se podría recuperar: "
                "no se ha hecho nada.",
            )
        self._must_record("agent_delete", slug, {"requested_by": requested_by}, risk=2)
        try:
            mark_stopped(config)  # first: if the machine dies now, it stays stopped
        except OSError as error:
            raise _Refused(
                FAILED, f"No se ha podido dejar la marca de parado ({error.strerror}): sigue igual."
            ) from None
        self._roster.mark_stopped(slug, stopped=True)
        neighbours.stop_one(slug, requested_by)
        if neighbours.is_running(slug) or not neighbours.halt(config):
            raise _Refused(
                FAILED,
                f"El agente {slug} no ha terminado de pararse, así que no se ha borrado nada: "
                "mira `docker ps` y la caja negra, y repítelo.",
            )
        try:
            now = self._now()
            seq, final = self._last_event(config, requested_by, now)
            trash.save_agent_file(config.agent_dir, text)
            if not os.path.lexists(
                config.agent_dir / NUMBER_FILE
            ):  # one written by hand: decision 14
                _write_new(config.agent_dir / NUMBER_FILE, f"{config.number}\n")
            mark = trash.new_mark(
                config, now=now, requested_by=requested_by, final_seq=seq, final_hash=final
            )
            trash.write_mark(config.agent_dir, mark)
        except (BlackBoxError, ConfigError, OSError) as error:
            said = str(redact(f"{type(error).__name__}: {error}"))[:300]
            self._record("agent_delete_failed", slug, {"error": said}, risk=2)
            raise _Refused(
                FAILED,
                f"El agente {slug} está parado y no se ha borrado: no se ha podido cerrar su caja "
                f"negra ({said}), y sin cerrarla no se borra.",
            ) from None
        return config, mark

    def _must_record(self, action: str, slug: str, details: dict[str, Any], risk: int) -> None:
        if not self._record(action, slug, details, risk=risk):
            raise _Refused(
                FAILED, "No se ha podido apuntar en la caja de la instalación: no se ha hecho nada."
            )

    def _resume_delete(self, slug: str, requested_by: str) -> ServiceConfig:
        config = self._config_of_deleted(slug)
        self._must_record("agent_delete_resumed", slug, {"requested_by": requested_by}, risk=2)
        self._stop_what_is_left(config)
        return config

    def _last_event(
        self, config: ServiceConfig, requested_by: str, now: datetime
    ) -> tuple[int, str]:
        """The box of this agent ends here, and this says how: what the mark and the installation's
        box keep. What was already wrong with it is said in the event itself."""
        with self._open_box(config) as box:
            report = box.verify()
            event = box.append(
                "system",
                "agent_deleted",
                config.slug,
                details={
                    "requested_by": requested_by,
                    "at": now.isoformat(),
                    "checked": report.checked,
                    "problems": len(report.problems),
                },
                risk=2,
            )
        return event.seq, event.hash

    def _finish_delete(self, config: ServiceConfig, mark: trash.Retired) -> None:
        """From the mark on, in an order that can be repeated from any step. Raises _Refused."""
        slug, home = config.slug, config.agent_dir
        try:
            self._remove_from_docker(slug)
            self._unmount(config)
            mark = replace(mark, box_settled=trash.settle_box(home))
            trash.seal_box(home)
            self._file_of(slug).unlink(missing_ok=True)
            # Before the mark says it is over: nothing tries this again after it, and a second
            # try only repeats the event. This is what a box cut short is compared with.
            self._must_record("agent_deleted", slug, _end_of(mark), risk=2)
            mark = replace(mark, state=trash.RETIRED)
            trash.write_mark(home, mark)
        except (containers.DockerObjectError, AgentDiskError, OSError) as error:
            said = str(redact(f"{type(error).__name__}: {error}"))[:300]
            logger.error("the agent %s is not deleted yet: %s", slug, said)
            self._record("agent_delete_failed", slug, {"error": said}, risk=2)
            raise _Refused(
                FAILED,
                f"El agente {slug} está parado y su caja negra cerrada, pero no se ha terminado de "
                f"borrar: {said}. Repite la orden cuando esté arreglado.",
            ) from None
        self._roster.forget(slug)
        if self._neighbours is not None:
            self._neighbours.forget(slug)
        self._list_deleted()
        self._told.submit(
            Alert(
                AlertLevel.ERROR,
                f"Agente borrado: {slug}",
                f"Se ha borrado el agente {slug}. Su caja negra se queda, y su volumen espera "
                f"hasta el {_day(mark.purge_after)}. Si no has sido tú, `sudo backtide agentes "
                f"recuperar {slug}` lo devuelve.",
            )
        )

    def _remove_from_docker(self, slug: str) -> None:
        """By the slug and the label: what is not backtide's is not touched, and that stops this."""
        for kind, names in (
            ("container", containers.containers_of_agent(slug)),
            ("network", containers.networks_of_agent(slug)),
        ):
            for name, role in names.items():
                if containers.remove(kind, name, role, run=self._run) is containers.Found.NOT_OURS:
                    raise containers.DockerObjectError(
                        f"{name} no lleva la etiqueta de backtide y no se toca: quítalo o cámbialo "
                        "de nombre"
                    )

    def _unmount(self, config: ServiceConfig) -> None:
        for point in (config.proxy_jail_config().channel_dir, config.volume):
            if mounted_at(point, self._mountinfo()) is not None:
                ran = self._run(umount_argv(point))
                if ran is None or ran.returncode != 0:
                    logger.error("this failed: %s", " ".join(umount_argv(point)))
            if mounted_at(point, self._mountinfo()) is not None:
                raise AgentDiskError(f"{point} sigue montado: algo lo está usando")
        self._rmdir_mount_point(config.slug)

    def _rmdir_mount_point(self, slug: str) -> None:
        point = self._volumes / slug
        try:
            os.rmdir(point)
        except FileNotFoundError:
            pass
        except OSError as error:  # it holds nothing of anybody's that counts: said, and it goes on
            logger.warning("the mount point %s stays: %s", point, error.strerror)

    def _mark_of(self, slug: str) -> trash.Retired | None:
        """The mark of this agent, looked up in what the folder has. A slug is never a path."""
        found = trash.retired_agents(self._main.agents_dir)
        if slug in found and found[slug] is None:
            raise _Refused(
                FAILED,
                f"La marca de borrado de {slug} no se puede leer, y nada se hace por lo que diga: "
                "mira el registro del servicio.",
            )
        return found.get(slug)

    def _config_of_deleted(self, slug: str) -> ServiceConfig:
        try:
            return load_retired(self._path, slug)
        except ConfigError as error:
            raise _Refused(
                FAILED, f"La copia del archivo de {slug} no se puede usar: {redact(str(error))}"
            ) from None

    def _stop_what_is_left(self, config: ServiceConfig) -> None:
        try:
            self._stop_alive(config)
        except Exception as error:  # that it keeps running stops all of this: said by the caller
            logger.exception("the agent %s keeps running", config.slug)
            said = str(redact(f"{type(error).__name__}: {error}"))[:300]
            raise _Refused(FAILED, f"El agente {config.slug} sigue en marcha: {said}") from None

    def _list_deleted(self) -> None:
        found = trash.retired_agents(self._main.agents_dir)
        self._roster.set_deleted([mark.listed() for mark in found.values() if mark is not None])

    def restore(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]:
        slug, restart = _restore_of(request)
        try:
            with self._one_at_a_time():
                return self._restore(slug, restart, requested_by)
        except _Refused as refused:
            logger.warning("refused to bring back the agent %s: %s", slug, refused.outcome)
            return _reply(refused.outcome, str(refused))

    def _restore(self, slug: str, restart: bool, requested_by: str) -> dict[str, Any]:
        _not_the_main(slug)
        mark = self._mark_of(slug)
        if mark is None:
            raise _Refused(REFUSED, f"No hay ningún agente {slug} en la papelera.")
        if mark.state != trash.RETIRED:
            raise _Refused(
                REFUSED,
                f"El agente {slug} quedó a medio borrar: termina de borrarlo con `agentes borrar` "
                "y luego recupéralo.",
            )
        if mark.purged_at is not None:
            raise _Refused(REFUSED, f"La papelera de {slug} ya se vació: queda solo su caja negra.")
        if not self._unit():
            raise _Refused(
                REFUSED, "Recuperar un agente pide el servicio instalado: fuera no se monta nada."
            )
        if self._neighbours is None and not restart:
            raise _Refused(
                NEEDS_RESTART,
                "Sería el primer agente además del principal: el servicio tiene que reiniciarse, y "
                "con él el principal, que se para y vuelve a arrancar. Lo que tenga a medias se "
                "pierde. Si te va bien, pídelo otra vez aceptándolo.",
            )
        config, text = self._check_can_restore(slug)
        details = {"requested_by": requested_by, "final_hash": mark.final_hash}
        self._must_record("agent_restore", slug, details, risk=2)
        made: list[Callable[[], None]] = []
        try:
            new = self._bring_back(config, mark, text, requested_by, made)
        except Exception as error:
            logger.exception("the agent %s could not be brought back", slug)
            for undo in reversed(made):
                _quietly(undo)
            said = str(redact(f"{type(error).__name__}: {error}"))[:300]
            self._record("agent_restore_failed", slug, {"error": said}, risk=2)
            return _reply(
                FAILED, f"No se ha podido recuperar: {said}. Sigue en la papelera, como estaba."
            )
        self._record("agent_restored", slug, details, risk=2)
        self._list_deleted()
        self._told.submit(
            Alert(
                AlertLevel.ERROR,
                f"Agente recuperado: {slug}",
                f"El agente {slug} ha vuelto de la papelera, parado. Si no has sido tú, bórralo "
                "otra vez.",
            )
        )
        self._roster.add(new.slug, new.display_name)
        self._roster.mark_stopped(slug, stopped=True)
        if self._neighbours is None:
            self._stop.set()  # the control socket answers this order before it closes
            return _reply(
                RESTARTING,
                f"Agente {slug} recuperado, parado. El servicio se reinicia para llevar a más de "
                f"un agente. Arráncalo con `backtide agentes arrancar {slug}`.",
            )
        items = tuple(protected_of(new))
        self._protect_main(items)
        self._neighbours.protect_also(new.slug, items)
        if self._add_to_total is not None:
            self._add_to_total(new.slug, new.agent_dir)
        self._neighbours.add(new)
        return _reply(
            RESTORED,
            f"Agente {slug} recuperado entero, y parado: mira su caja negra si quieres, y "
            f"arráncalo con `backtide agentes arrancar {slug}`.",
        )

    def _check_can_restore(self, slug: str) -> tuple[ServiceConfig, str]:
        """Everything that can be said before anything is touched."""
        installation = self._read_all()
        if len(installation.agents) >= MAX_AGENTS:
            raise _Refused(REFUSED, f"Como mucho {MAX_AGENTS} agentes, contando el principal.")
        config = self._config_of_deleted(slug)
        try:
            text = trash.read_agent_file(config.agent_dir / SAVED_AGENT_FILE)
            there = trash.read_agent_file(self._file_of(slug))
        except (OSError, ValueError) as error:
            raise _Refused(REFUSED, f"No se puede leer su archivo: {error}") from None
        if text is None:
            raise _Refused(REFUSED, f"No está la copia del archivo de {slug}.")
        if there is not None and there != text:
            raise _Refused(
                REFUSED,
                f"Ya hay un archivo {self._file_of(slug)}, distinto del que tenía este agente: "
                "quítalo si no lo quieres y vuelve a pedirlo.",
            )
        image = image_of(config)
        if not os.path.isfile(image):
            raise _Refused(REFUSED, f"La imagen de su volumen no está: {image}.")
        try:
            check_fits(installation, config)
        except ConfigError as error:
            raise _Refused(REFUSED, f"No puede volver: {redact(str(error))}") from None
        ceiling = config.max_volume_bytes if config.max_volume_bytes is not None else 0
        self._check_disk(still_to_grow(image, ceiling), installation)
        return config, text

    def _bring_back(
        self,
        config: ServiceConfig,
        mark: trash.Retired,
        text: str,
        requested_by: str,
        made: list[Callable[[], None]],
    ) -> ServiceConfig:
        """The file last but for the box, and the box's event once nothing can fail: the chain goes
        on from ``final_hash``, so nothing in it needs undoing."""
        home, file = config.agent_dir, self._file_of(config.slug)
        self._remove_from_docker(config.slug)  # what a try that died left: its networks are named
        trash.unseal_box(home)
        made.append(lambda: trash.seal_box(home))
        mark_stopped(config)
        self._make_networks(config, made)
        if not os.path.lexists(file):
            _write_whole(file, text)
            made.append(lambda: file.unlink(missing_ok=True))
        os.unlink(home / RETIRED_MARK)
        made.append(lambda: trash.write_mark(home, mark))
        new = load_installation(self._path).agent(config.slug)
        with self._open_box(new) as box:
            box.append(
                "system",
                "agent_restored",
                new.slug,
                details={
                    "requested_by": requested_by,
                    "deleted_at": mark.deleted_at.isoformat(),
                },
                risk=2,
            )
        try:
            os.unlink(home / SAVED_AGENT_FILE)  # the machine's copy is the one that counts again
        except OSError as error:
            logger.warning("the copy of the file of %s stays: %s", new.slug, error.strerror)
        return new

    def purge(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]:
        slug = _typed_agent_of(request)
        try:
            with self._one_at_a_time():
                _not_the_main(slug)
                mark = self._mark_of(slug)
                if mark is None:
                    if self._roster.knows(slug):
                        raise _Refused(
                            REFUSED, f"El agente {slug} no está borrado: no hay nada que vaciar."
                        )
                    raise _Refused(REFUSED, f"No hay ningún agente {slug} en la papelera.")
                return self._empty(mark, requested_by, "owner")
        except _Refused as refused:
            logger.warning("refused to empty the trash of %s: %s", slug, refused.outcome)
            return _reply(refused.outcome, str(refused))

    def _empty(self, mark: trash.Retired, requested_by: str, reason: str) -> dict[str, Any]:
        """For good. The box, its key and the number stay, and nothing is written in the box: its
        last event is still the one the installation's box has the hash of."""
        slug, home = mark.slug, self._main.agents_dir / mark.slug
        if mark.state != trash.RETIRED:
            raise _Refused(
                REFUSED,
                f"El agente {slug} quedó a medio borrar: termina de borrarlo con `agentes borrar`.",
            )
        if mark.purged_at is not None:
            return _reply(ALREADY, f"La papelera de {slug} ya está vacía.")
        info = self._mountinfo()
        if anything_mounted_under(home, info) or anything_mounted_under(self._volumes / slug, info):
            raise _Refused(FAILED, f"Algo de {slug} sigue montado: no se ha vaciado nada.")
        details = {
            "requested_by": requested_by,
            "reason": reason,
            "final_hash": mark.final_hash,
        }
        self._must_record("agent_purge", slug, details, risk=3)
        elsewhere = trash.image_elsewhere(home)
        try:
            trash.empty_folder(home)
            trash.write_mark(home, replace(mark, purged_at=self._now()))
        except Exception as error:  # also a tree too deep, which an agent can leave behind
            said = str(redact(f"{type(error).__name__}: {error}"))[:300]
            logger.error("the trash of the agent %s is not empty yet: %s", slug, said)
            self._record("agent_purge_failed", slug, {"error": said}, risk=3)
            if slug not in self._purge_said:  # the next look tries again: once is enough
                self._purge_said.add(slug)
                self._told.submit(
                    Alert(
                        AlertLevel.ERROR,
                        f"No se ha podido vaciar la papelera de {slug}",
                        f"{said}. Se vuelve a intentar. Su caja negra sigue.",
                    )
                )
            raise _Refused(
                FAILED, f"No se ha terminado de vaciar ({said}): repítelo. Su caja negra sigue."
            ) from None
        self._rmdir_mount_point(slug)
        self._record("agent_purged", slug, details, risk=3)
        self._list_deleted()
        left = (
            ""
            if elsewhere is None
            else f" La imagen de su volumen está en {elsewhere}, fuera de su carpeta: se queda."
        )
        self._told.submit(
            Alert(
                AlertLevel.ERROR,
                f"Papelera vaciada: {slug}",
                f"El volumen y las instantáneas de {slug} ya no están. Su caja negra se queda."
                f"{left}",
            )
        )
        return _reply(
            PURGED,
            f"Vaciado: el volumen y las instantáneas de {slug} ya no están. Su caja negra se queda "
            f"y su nombre no se vuelve a usar.{left}",
        )

    def finish_interrupted(self) -> None:
        """At the service's start, before any agent: what a machine that died left half deleted
        goes on, nothing of it runs, and what makes no sense is said. Never raises."""
        for slug, mark in trash.retired_agents(self._main.agents_dir).items():
            try:
                if mark is None:
                    raise _Refused(FAILED, "su marca de borrado no se puede leer")
                if mark.state != trash.RETIRED:
                    self._finish_delete(self._resume_delete(slug, "service"), mark)
                elif os.path.lexists(self._file_of(slug)):
                    raise _Refused(
                        FAILED,
                        f"hay un archivo {self._file_of(slug)}, y no se usa: ese agente está "
                        "borrado. O lo recuperas, o lo quitas",
                    )
            except _Refused as refused:
                self._record("agent_delete_unfinished", slug, {"why": str(refused)[:300]}, risk=2)
                self._told.submit(
                    Alert(AlertLevel.ERROR, f"Agente borrado a medias: {slug}", str(refused))
                )
            except Exception:  # the service starts all the same: nothing of this agent runs
                logger.exception("what was left of the deleted agent %s", slug)
        self._list_deleted()

    def tend_trash(self) -> None:
        """A look at the trash: its boxes, its warnings and what has waited long enough. Each from
        its mark, so a restart loses nothing. If an order is running, the next look. Never raises:
        it runs on its own thread, and what fails is logged and tried again."""
        if not self._busy.acquire(blocking=False):
            return
        try:
            for mark in trash.retired_agents(self._main.agents_dir).values():
                if mark is None:
                    continue
                try:
                    self._tend_one(mark)
                except _Refused as refused:
                    logger.error("the trash of the agent %s: %s", mark.slug, refused)
                except Exception:
                    logger.exception("the trash of the agent %s", mark.slug)
            self._list_deleted()
        finally:
            self._busy.release()

    def _tend_one(self, mark: trash.Retired) -> None:
        home = self._main.agents_dir / mark.slug
        if mark.state == trash.RETIRED and not mark.box_settled:
            mark = self._settle(home, mark)
        now = self._now()
        step = trash.due(mark, now)
        if step is None:
            return
        if not self._clock_is_good():
            logger.warning("the clock cannot be trusted: nothing leaves the trash on its word")
            return
        if step == trash.WARN:
            trash.write_mark(home, replace(mark, warned_at=now))  # not written, not warned
            self._record(
                "agent_trash_warned", mark.slug, {"purge_after": mark.purge_after.isoformat()},
                risk=1,
            )  # fmt: skip
            self._told.submit(
                Alert(
                    AlertLevel.WARNING,
                    f"Mañana se vacía la papelera de {mark.slug}",
                    f"El volumen y las instantáneas de {mark.slug} se borran para siempre en un "
                    f"día. Si los quieres, `sudo backtide agentes recuperar {mark.slug}`.",
                )
            )
        else:
            self._empty(mark, "service", "expired")

    def _settle(self, home: Path, mark: trash.Retired) -> trash.Retired:
        trash.unseal_box(home)
        try:
            settled = trash.settle_box(home)
        finally:
            trash.seal_box(home)
        if settled:
            mark = replace(mark, box_settled=True)
            trash.write_mark(home, mark)
        return mark

    def _clock_is_good(self) -> bool:
        try:
            return self._clock_ok()
        except OSError as error:
            logger.warning("cannot read the state of the clock: %s", error)
            return False


class TrashWatch:
    """A ``ControlHook``: ``Fleet.tend_trash`` now and every ``every`` seconds while the service is
    up. On a thread of its own, so a slow disk never holds up a socket."""

    def __init__(self, fleet: Fleet, *, every: float = TRASH_EVERY) -> None:
        self._fleet = fleet
        self._every = every
        self._closing = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="backtide-trash", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._closing.set()
        if self._thread is not None:
            self._thread.join(5)

    def _run(self) -> None:
        while True:
            self._fleet.tend_trash()
            if self._closing.wait(self._every):
                return


class _Refused(Exception):  # noqa: N818 - a refusal is not an error here
    def __init__(self, outcome: str, message: str) -> None:
        super().__init__(message)
        self.outcome = outcome


def _agent_of(request: Mapping[str, Any]) -> str:
    """The closed shape of ``agent_start`` and ``agent_stop``: the order and whom, nothing else."""
    if set(request) != {"cmd", "agent"}:
        raise OrderInvalid("Esa orden lleva `cmd` y `agent`, y nada más.")
    return _slug_of(request["agent"])


def _typed_agent_of(request: Mapping[str, Any]) -> str:
    """The closed shape of ``agent_delete`` and ``agent_purge``: whom, and that name written again
    by a person, so that no slip and no form with the wrong agent does it (docs/47, 8.2)."""
    if set(request) != {"cmd", "agent", "typed"}:
        raise OrderInvalid("Esa orden lleva `cmd`, `agent` y `typed`, y nada más.")
    slug = _slug_of(request["agent"])
    if request["typed"] != slug:
        raise OrderInvalid("El nombre escrito no es el de ese agente: no se ha hecho nada.")
    return slug


def _restore_of(request: Mapping[str, Any]) -> tuple[str, bool]:
    """The closed shape of ``agent_restore``: whom, and whether a restart is accepted."""
    if not {"cmd", "agent"} <= set(request) <= {"cmd", "agent", "restart"}:
        raise OrderInvalid("Esa orden lleva `cmd`, `agent` y, si acaso, `restart`, y nada más.")
    restart = request.get("restart", False)
    if not isinstance(restart, bool):
        raise OrderInvalid("`restart` es sí o no.")
    return _slug_of(request["agent"]), restart


def _slug_of(slug: object) -> str:
    """A slug, or the main agent's name, so that it can be told what it cannot have. Never a path:
    it is only compared with the lists after this."""
    if slug != identity.MAIN_SLUG:
        try:
            identity.check_slug(slug)
        except identity.SlugError:
            raise OrderInvalid(NOBODY) from None
    return str(slug)


def _not_the_main(slug: str) -> None:
    if slug == identity.MAIN_SLUG:
        raise _Refused(
            REFUSED,
            "El principal no se borra: lleva los sockets y al resto de los agentes. Para quitarlo "
            "todo está la desinstalación.",
        )


def _end_of(mark: trash.Retired) -> dict[str, Any]:
    return {
        "requested_by": mark.requested_by,
        "final_seq": mark.final_seq,
        "final_hash": mark.final_hash,
        "purge_after": mark.purge_after.isoformat(),
    }


def _day(moment: datetime) -> str:
    return moment.date().isoformat()


def _reply(outcome: str, message: str) -> dict[str, Any]:
    return {"ok": outcome in DONE, "outcome": outcome, "message": str(redact(message))}


def _write_new(path: Path, text: str) -> None:
    """A new file of ours: never one that was there, never through a link."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())


def _write_whole(path: Path, text: str) -> None:
    """A new file that exists whole or not at all: a machine that dies half way must not leave
    a broken file, which stops the whole service at its next start."""
    partial = path.with_name(f".{path.name}.partial")
    partial.unlink(missing_ok=True)
    _write_new(partial, text)
    try:
        os.link(partial, path)  # never over one that is there
    finally:
        partial.unlink()


def _number_in(path: Path) -> int:
    try:
        with open(path, encoding="ascii") as file:
            return int(file.read(16).strip())
    except (OSError, ValueError):
        return 0


def _default(kind: type, name: str) -> str:
    return next(field.default for field in fields(kind) if field.name == name)


def _free_bytes(path: Path) -> int:
    stats = os.statvfs(path)
    return stats.f_bavail * stats.f_frsize


def _quietly(undo: Callable[[], None]) -> None:
    try:
        undo()
    except Exception:  # undoing never hides why it had to: logged, and the next step tried
        logger.exception("undoing an agent's creation failed")
