"""`backtide desinstalar`: undo exactly what `backtide instalar` made (T13-4; docs/25, section 5).

The install manifest (backtide.setup.manifest) says what the installer created or changed; this
removes that and nothing else. It refuses a manifest that is not root's 0600 regular file, and
never touches a path outside backtide's own folders (``/opt/backtide``, ``/etc/backtide``,
``/var/lib/backtide``, the volume's mount point) or the few exact files the installer writes
elsewhere (its units, ``/usr/local/bin/backtide``, Docker's repository and key, ``daemon.json``).
Every removal opens the path one folder at a time without following links (``O_NOFOLLOW``) and
checks with ``fstat`` that it is root's; whole folders go with the fd-based ``shutil.rmtree``,
and never while anything is mounted under them. A container or network goes only if it carries
backtide's label (backtide.setup.containers).

Two modes:
- by default it **keeps the data**: the black box and its key, the agent's volume (its work and
  its snapshots), the keys and a copy of ``backtide.toml``, all in ``/var/lib/backtide``.
  Installing again over them carries on: the same chain, the same snapshots;
- ``--borrar-datos`` removes those too, after typing the machine's name (or ``--si``).
Docker, and the packages the installer added, stay unless ``--quitar-docker`` (Docker's
packages, its repository and its key; only if no other container is left). The settings it
changed in ``daemon.json`` go back to how they were.

In order, each step recorded in the manifest as soon as it is done, so an uninstall that stops
half way (a busy mount, a network someone else is using) is run again and goes on from there:
1. ``stop``: backtide.service (which stops the agent), the agent's container, the web.
2. ``units``: disabled, stopped (the volume and the proxy channel's tmpfs unmount) and removed.
3. ``containers``, ``networks``, ``images``: only backtide's.
4. ``volume``: the mount point; with --borrar-datos, the volume's image.
5. ``docker_settings``: ``selinux-enabled`` back with one restart of Docker (``live-restore``
   still on, so other containers keep running), then ``live-restore`` with a reload.
6. ``docker``: with --quitar-docker only.
7. ``config``, ``exports``, ``program``, ``accounts``: ``/etc/backtide``, the export folder (only
   when empty: the copies are the owner's), the command, ``backtide-web``.

The other agents (T26-2b; docs/47, section 6.8) are not in the manifest: they are the files of
``/etc/backtide/agents/``, whose names say their containers and networks. They are stopped and
removed with the main one, by label like everything else, and their mounts go (``umount``: nothing
else is needed to take them away). Their black boxes and volumes are data: they stay with the rest
of the state unless ``--borrar-datos``. Without it, each agent's file is kept beside its box.
8. ``data``: with --borrar-datos, ``/var/lib/backtide``; without it, the manifest is kept with
   what is left, for the next install.
9. ``opt``: ``/opt/backtide``, the program itself, last (this program runs from it: everything
   it needs is imported above).
"""

import json
import os
import shutil
import stat
import time
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from backtide.jail import identity
from backtide.jail.docker import sanitize
from backtide.service.config import (
    AGENTS_FOLDER,
    MAX_CONFIG_BYTES,
    SAVED_AGENT_FILE,
    STATE_CHECKPOINT,
    STATE_DB,
    STATE_INSTALLATION,
    STATE_KEY,
    STATE_KEYS,
    STATE_PROXY_CHANNEL,
    ConfigError,
    ServiceConfig,
)
from backtide.setup import containers, images, layout, manifest, packages, preflight, units
from backtide.setup.containers import Found
from backtide.setup.host import Host, Ran, Runner
from backtide.setup.install import NOLOGIN, SAVED_CONFIG, Paths
from backtide.setup.manifest import Manifest

DOCKER_WAIT = 90.0
DAEMON_BACKUP = "docker-daemon.json.antes"  # the installer's copy of a daemon.json it changed
MOUNTINFO = "/proc/self/mountinfo"
MOUNTINFO_LIMIT = 4 * 1024 * 1024
DOCKER_UNITS = ("docker.service", "docker.socket", "containerd.service")
# The service's three containers, by this version's default names: for a manifest older than
# T13-4, which did not list them (G8 in the backlog: such installs are only labs so far).
DEFAULT_CONTAINERS = {"backtide-agente": "agent", "backtide-egress": "proxy",
                      "backtide-sensor": "sensor"}  # fmt: skip
DOCKER_EXTRAS = ("docker-buildx-plugin", "docker-compose-plugin", "docker-ce-rootless-extras")


_AGENT_FILE_SUFFIX = ".toml"


@dataclass(frozen=True)
class _OtherAgent:
    """An agent other than the main one, as its file says (T26-2b)."""

    slug: str
    volume: Path | None
    image: Path | None


def _path_in(settings: dict[str, object], key: str) -> Path | None:
    """An absolute, plain path of an agent's file, or None: what is not one is not looked at."""
    value = settings.get(key)
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        return None
    path = Path(value)
    return path if os.path.normpath(value) == value else None


class UninstallError(Exception):
    """The uninstall stopped: the message says what failed and how to go on (in Spanish)."""


class Prompter(Protocol):
    interactive: bool

    def say(self, text: str) -> None: ...
    def confirm(self, question: str) -> bool: ...
    def answer(self, question: str) -> str: ...


@dataclass
class Options:
    yes: bool = False  # --si
    erase_data: bool = False  # --borrar-datos
    remove_docker: bool = False  # --quitar-docker
    dry_run: bool = False


@dataclass
class Uninstaller:
    host: Host
    run: Runner
    prompter: Prompter
    options: Options = field(default_factory=Options)
    paths: Paths = field(default_factory=Paths)
    owner: tuple[int, int] = (0, 0)  # root; the Mac tests are their own user
    hostname: str = field(default_factory=lambda: os.uname().nodename)
    run_long: Runner | None = None
    sleep: Callable[[float], None] = lambda seconds: None
    clock: Callable[[], float] | None = None
    manifest: Manifest = field(default_factory=Manifest)
    _done: list[str] = field(default_factory=list)
    _left: list[str] = field(default_factory=list)
    started: bool = False  # past the question: something may have changed
    # Read once, before anything is removed: the templates live in /opt/backtide, which goes last.
    _unit_names: frozenset[str] = field(default_factory=lambda: frozenset(units.render_units()))
    _last_id: str = ""

    # -- the whole run ----------------------------------------------------------------------------

    def uninstall(self) -> bool:
        """Undo the installation. False if there was nothing to remove. Raises UninstallError."""
        say = self.prompter.say
        if not self._load():
            return False
        plan = self.plan()
        if not plan:
            say("No queda nada de backtide que quitar.")
            self._say_kept()
            self._say_left()
            return False
        say("Esto es lo que se va a quitar:")
        for line in plan:
            say(f"  - {line}")
        for line in self._kept_lines():
            say(f"  · {line}")
        if self.options.dry_run:
            say("\nCon --dry-run no se cambia nada.")
            return True
        self._confirm()
        self._nothing_mounted_where_it_deletes()
        self.started = True
        steps: list[tuple[str, Callable[[], None]]] = [
            ("Parar el agente y backtide", self.stop),
            ("Unidades de systemd", self.units),
            ("Contenedores de backtide", self.containers),
            ("Redes de Docker", self.networks),
            ("Imágenes", self.images),
            ("Volúmenes de los demás agentes", self.other_volumes),
            ("Volumen del agente", self.volume),
            ("Ajustes de Docker", self.docker_settings),
            ("Docker", self.docker),
            ("Configuración", self.config),
            ("Copias exportadas", self.exports),
            (f"Usuario {layout.WEB_USER}", self.accounts),
            ("Datos", self.data),
            # The command and the program last: until then a run that stops can be run again.
            ("Orden `backtide`", self.program),
            ("Programa", self.opt),
        ]
        for title, action in steps:
            say(f"\n== {title}")
            action()
        self.summary()
        return True

    def plan(self) -> list[str]:
        """What this run would remove, for the person; empty when nothing is left."""
        m, lines = self.manifest, []
        if m.created["units"]:
            lines.append(f"las unidades de systemd: {', '.join(m.created['units'])}")
        if m.facts.get("containers"):
            lines.append(f"los contenedores: {', '.join(m.facts['containers'])}")
        others = self._other_agents()
        if others:
            lines.append(
                f"los demás agentes: {', '.join(a.slug for a in others)} (sus contenedores, sus "
                "redes y sus montajes; sus cajas negras y sus volúmenes son datos)"
            )
        if m.created["networks"]:
            lines.append(f"las redes de Docker: {', '.join(m.created['networks'])}")
        if m.created["images"]:
            refs = m.created["images"]
            lines.append(f"las imágenes que descargó ({len(refs)}, unos "
                         f"{images.approx_total(refs)})")  # fmt: skip
        changed = m.facts.get("daemon_json") or []
        if changed:
            lines.append(
                f"lo que cambió en {self.paths.daemon_json} ({', '.join(changed)}) vuelve a como "
                "estaba: reinicia Docker una vez (tus otros contenedores siguen, con live-restore)"
            )
        if self._docker_ours() and self.options.remove_docker:
            lines.append(
                f"Docker ({', '.join(packages.DOCKER_PACKAGES)}), su repositorio y su clave"
            )
        for path in self._removable_paths():
            lines.append(str(path))
        if m.created["users"] or m.created["groups"]:
            lines.append(f"el usuario y el grupo {layout.WEB_USER}")
        if self.options.erase_data and self._exists(self.paths.state_dir):
            lines.append(
                f"LOS DATOS, PARA SIEMPRE: la caja negra y su clave, el volumen del agente (su "
                f"trabajo y sus instantáneas) y las claves ({self.paths.state_dir})"
            )
        return lines

    def summary(self) -> None:
        say = self.prompter.say
        say("\nbacktide se ha desinstalado.")
        if self.options.erase_data:
            say("  - La caja negra se ha borrado para siempre: lo que hizo el agente ya no se "
                "puede comprobar ni recuperar, ni su trabajo ni sus instantáneas.")  # fmt: skip
        else:
            self._say_kept()
        if self._docker_ours() and not self.options.remove_docker:
            say(
                "  - Docker se queda (lo instaló backtide, pero puede que ya lo uses para otras "
                "cosas), con su repositorio, para que siga recibiendo actualizaciones. Para "
                f"quitarlo: `sudo backtide desinstalar --quitar-docker` ({self._docker_what()})."
            )
        tools = self.manifest.created["packages"]
        if tools:
            say(f"  - Se quedan los paquetes que añadió ({', '.join(tools)}): otros programas "
                "pueden usarlos. Quítalos tú si no los quieres.")  # fmt: skip
        if self._say_left():
            say("Lo demás está hecho.")

    def _say_left(self) -> bool:
        if self._left:
            self.prompter.say("\nQueda sin quitar:")
            for item in self._left:
                self.prompter.say(f"  - {item}")
        return bool(self._left)

    # -- the steps --------------------------------------------------------------------------------

    def stop(self) -> None:
        """The agent first: backtide.service stops it (and the proxy and the sensor); then the
        agent's container, should it still run; then the web."""
        if layout.SERVICE_UNIT in self.manifest.created["units"]:
            self._systemctl("stop", layout.SERVICE_UNIT)
        agents = [n for n, r in self._expected_containers().items() if r == "agent"]
        for agent in agents if self._docker() else []:
            found, object_id = self._inspect("container", agent, "agent")
            if found is Found.OURS:
                self._check(("docker", "stop", "--time", "30", object_id),
                            f"no se pudo parar {agent}")  # fmt: skip
            elif found is Found.NOT_OURS:
                self._left.append(
                    f"el contenedor {agent}: no lleva la etiqueta de backtide, así que ni se para "
                    "ni se quita"
                )
        if layout.WEB_UNIT in self.manifest.created["units"]:
            self._systemctl("stop", layout.WEB_UNIT)

    def units(self) -> None:
        names = list(self.manifest.created["units"])
        if not names:
            return
        ours = self._unit_names
        # The services before the mounts they need.
        first = (layout.SERVICE_UNIT, layout.WEB_UNIT)
        for name in sorted(names, key=lambda n: (first + (n,)).index(n)):
            if name not in ours:
                self._left.append(f"la unidad {name}: no es de backtide, no se toca")
                continue
            try:
                self._systemctl("disable", "--now", name)
            except UninstallError as error:
                if not name.endswith(".mount"):
                    raise
                raise UninstallError(
                    f"no se pudo desmontar {name}: algo lo está usando (mira `fuser -vm` sobre "
                    f"su carpeta). Ciérralo y vuelve a ejecutar `sudo backtide desinstalar`. "
                    f"Detalle: {error}"
                ) from None
            self._unlink(self.paths.unit_dir / name)
            self.manifest.remove("units", name)
            self._did(f"unidad {name}")
            self._save()
        self.run(("systemctl", "daemon-reload"))
        self.run(("systemctl", "reset-failed", *[n for n in names if n in ours]))

    def containers(self) -> None:
        recorded = "containers" in self.manifest.facts
        wanted = self._expected_containers()
        if not wanted:
            return
        if not self._docker():
            self.manifest.facts.pop("containers", None)
            self._save()
            return
        for name, role in list(wanted.items()):
            found = self._remove("container", name, role)
            if found is Found.NOT_OURS:
                if not any(item.startswith(f"el contenedor {name}:") for item in self._left):
                    self._left.append(
                        f"el contenedor {name}: no lleva la etiqueta de backtide, así que no se "
                        "toca"
                    )
                continue
            if found is Found.OURS:
                self._did(f"contenedor {name}")
            del wanted[name]
        if wanted and recorded:
            self.manifest.facts["containers"] = wanted
        else:
            self.manifest.facts.pop("containers", None)
        self._save()

    def _expected_containers(self) -> dict[str, str]:
        """What the service makes: the main agent's and those of the agents in the files of
        ``agents/``, which the manifest does not know."""
        expected = self._expected_main_containers()
        for agent in self._other_agents():
            expected |= containers.containers_of_agent(agent.slug)
        return expected

    def _expected_main_containers(self) -> dict[str, str]:
        """What the manifest says the service makes; for a manifest from before it said so (an
        install older than T13-4), the names this version's service would use."""
        recorded = self.manifest.facts.get("containers")
        if isinstance(recorded, dict):
            return {str(k): str(v) for k, v in recorded.items()}
        if not self.manifest.created["units"] and not self.manifest.created["networks"]:
            return {}  # nothing of a running backtide left
        try:
            return containers.expected_containers(ServiceConfig.from_file(self.paths.config_file))
        except (ConfigError, OSError):
            return dict(DEFAULT_CONTAINERS)

    def networks(self) -> None:
        names = list(self.manifest.created["networks"])
        roles = dict(self.manifest.facts.get("network_roles") or {})
        for agent in self._other_agents():
            found = containers.networks_of_agent(agent.slug)
            names += list(found)
            roles |= found
        if not names:
            return
        docker = self._docker()
        for name in names:
            found = Found.ABSENT
            if docker:  # without Docker there is no network either
                wanted = roles.get(name) or ("agent-network", "egress")
                found, self._last_id = self._inspect("network", name, wanted)
            if found is Found.NOT_OURS:
                self._left.append(f"la red {name}: no lleva la etiqueta de backtide, no se toca")
                continue
            if found is Found.OURS:
                ran = self.run(("docker", "network", "rm", self._last_id))
                detail = sanitize((ran.stderr if ran else "").strip(), 200)
                if (ran is None or ran.returncode != 0) and "no such" not in detail.lower():
                    self._left.append(
                        f"la red {name}: {detail} (¿la usa otro contenedor?). Cuando no la use "
                        f"nadie: `docker network rm {name}`, o vuelve a desinstalar"
                    )
                    continue
                self._did(f"red {name}")
            if self.manifest.has("networks", name):
                self.manifest.remove("networks", name)
            self.manifest.facts.get("subnets", {}).pop(name, None)
            self._save()

    def images(self) -> None:
        refs = list(self.manifest.created["images"])
        if not refs:
            return
        if not self._docker():
            for ref in refs:
                self.manifest.remove("images", ref)
            self._save()
            return
        for ref in refs:
            ran = self.run(("docker", "image", "rm", ref))
            if ran is not None and ran.returncode != 0 and "no such image" in ran.stderr.lower():
                ran = self.run(("docker", "image", "rm", images.by_digest(ref)))
            if ran is None or ran.returncode != 0:
                detail = sanitize((ran.stderr if ran else "").strip(), 200)
                if "no such image" not in detail.lower():
                    self._left.append(
                        f"la imagen {images.by_digest(ref)}: {detail}. Si ya no la usa nadie: "
                        f"`docker image rm {images.by_digest(ref)}`"
                    )
                    continue
            else:
                self._did(f"imagen {images.by_digest(ref)}")
            self.manifest.remove("images", ref)
            self._save()

    def other_volumes(self) -> None:
        """What the other agents have mounted goes, and their empty mount points. Never a file: an
        agent's image is its work, and it goes with the state or not at all."""
        for agent in self._other_agents():
            for point in self._mounts_of(agent):
                if self._mounted(point):
                    ran = self.run(("umount", str(point)))
                    if ran is None or ran.returncode != 0:
                        raise UninstallError(
                            f"{point} sigue montado: algo lo está usando. Mira `findmnt {point}` y "
                            "`fuser -vm` sobre él, ciérralo y vuelve a ejecutar la desinstalación."
                        )
                    self._did(f"montaje {point}")
            if agent.image is not None:
                self._detach_loops(agent.image)
            volume = agent.volume
            if volume is not None and self._inside(volume, self.paths.agent_volumes):
                if os.path.lexists(volume) and self._rmdir(volume):
                    self._did(f"carpeta {volume}")
        folder = self.paths.agent_volumes
        if os.path.lexists(folder) and not self._listdir(folder) and self._rmdir(folder):
            self._did(f"carpeta {folder}")

    def volume(self) -> None:
        mount, image = self.paths.volume_mount, self.paths.volume_image
        if self._mounted(mount):
            raise UninstallError(
                f"{mount} sigue montado: algo lo está usando. Mira `findmnt {mount}` y "
                "`fuser -vm` sobre él, ciérralo y vuelve a ejecutar la desinstalación."
            )
        self._detach_loops(image)
        if self.options.erase_data and self.manifest.has("files", image):
            if self._unlink(image):
                self._did(f"volumen {image}")
            self.manifest.remove("files", image)
            self._save()
        if self.manifest.has("dirs", mount):
            if self._rmdir(mount):
                self._did(f"carpeta {mount}")
            self.manifest.remove("dirs", mount)
            self._save()

    def docker_settings(self) -> None:
        """What the installer changed in daemon.json, back as it was (D25, undone). Only the
        settings it set; anything the person added since is kept."""
        changed = [str(k) for k in self.manifest.facts.get("daemon_json") or []]
        if not changed:
            return
        path, backup = self.paths.daemon_json, self.paths.state_dir / DAEMON_BACKUP
        current = self._json_file(path)
        if current is None:  # no daemon.json any more: nothing to give back
            self._forget_daemon(backup)
            return
        if os.path.lexists(backup):
            original = self._json_file(backup) or {}
        elif self.manifest.has("files", path):
            original = {}  # it made the file: before, there was none
        else:
            self._left.append(f"{path}: no está la copia de antes; revisa a mano {changed}")
            self.manifest.facts.pop("daemon_json", None)
            self._save()
            return
        restored = dict(current)
        for key in changed:
            if key in original:
                restored[key] = original[key]
            else:
                restored.pop(key, None)
        goes = self.options.remove_docker and self._docker_ours() and not self._why_docker_stays()
        staying = self._docker() and not goes
        if staying and restored.get("selinux-enabled") != current.get("selinux-enabled"):
            # selinux-enabled needs a restart; live-restore still on keeps others' containers up.
            middle = dict(restored)
            middle["live-restore"] = current.get("live-restore", restored.get("live-restore"))
            self._write_daemon(path, middle)
            self._check(("systemctl", "restart", "docker.service"), "Docker no volvió a arrancar")
            self._wait_for_docker()
        if restored == {} and self.manifest.has("files", path):
            self._unlink(path)
        else:
            self._write_daemon(path, restored)
        # What is left in it is the person's own: never removed later.
        self.manifest.remove("files", path)
        if staying and restored.get("live-restore") != current.get("live-restore"):
            self._check(("systemctl", "reload", "docker.service"), "Docker no recargó su ajuste")
            self._wait_for_docker()
        self.prompter.say(f"Hecho: {', '.join(changed)} de {path}, como estaban")
        self._forget_daemon(backup)

    def docker(self) -> None:
        if not self.options.remove_docker:
            return
        if not self._docker_ours():
            self._left.append(
                "Docker: no lo instaló esta instalación de backtide (o su manifiesto ya no lo "
                "recuerda), así que --quitar-docker no lo toca"
            )
            return
        why_not = self._why_docker_stays()
        if why_not:
            self._left.append(f"Docker: {why_not}, así que no se quita (ni su repositorio)")
            return
        for unit in DOCKER_UNITS:
            self.run(("systemctl", "disable", "--now", unit))
        distro = packages.read_distro(self.host)
        if distro is None:
            raise UninstallError("no se pudo leer /etc/os-release")
        # dnf also brought Docker's own weak dependencies (buildx, compose, rootless-extras; seen
        # in Fedora 44); apt did not (--no-install-recommends). They go too, if they are there.
        names = [*packages.DOCKER_PACKAGES]
        for extra in DOCKER_EXTRAS if not distro.apt else ():
            ran = self.run(("rpm", "-q", "--quiet", extra))
            if ran is not None and ran.returncode == 0:
                names.append(extra)
        if distro.apt:
            argv: tuple[str, ...] = (*packages.APT_ENV, "apt-get", "purge", "-y", *names)
        else:
            argv = ("dnf", "-y", "remove", *names)
        self._check(argv, "no se pudo quitar Docker", long=True)
        if distro.apt:
            files = (self.paths.apt_source, self.paths.apt_keyring)
        else:
            files = (self.paths.dnf_repo, self.paths.rpm_key)
            self._forget_rpm_key()
        for path in files:
            if self.manifest.has("files", path):
                self._unlink(path)
                self.manifest.remove("files", path)
        self.manifest.created["docker"] = []
        self._did(f"Docker ({', '.join(names)}), su repositorio y su clave")
        self.prompter.say(
            "Quedan los datos de Docker (/var/lib/docker, /var/lib/containerd: imágenes y capas "
            "que no son de backtide, si las hay). Bórralos tú si no los quieres."
        )
        self._save()

    def _why_docker_stays(self) -> str | None:
        """None when --quitar-docker may remove Docker: it answers and runs no other container.
        Without an answer there is no knowing what else runs on it (review of T13-4, R2)."""
        ran = self.run(("docker", "ps", "--all", "--quiet")) if self._docker() else None
        if ran is None or ran.returncode != 0:
            return "no responde (o falta su orden) y no se sabe si tiene otros contenedores"
        others = [line for line in ran.stdout.split() if line]
        if others:
            return f"le quedan contenedores que no son de backtide ({len(others)})"
        return None

    def config(self) -> None:
        folder = self.paths.config_dir
        if not self.options.erase_data and self.manifest.has("files", self.paths.config_file):
            self._keep_config()
        if not self.options.erase_data:
            self._keep_agent_files()
        if self.options.erase_data and self.manifest.has("dirs", folder):
            if self._rmtree(folder):
                self._did(f"carpeta {folder}")
            for item in [f for f in self.manifest.created["files"] if self._inside(f, folder)]:
                self.manifest.remove("files", item)
            self.manifest.remove("dirs", folder)
            self._save()
            return
        for item in [f for f in self.manifest.created["files"] if self._inside(f, folder)]:
            if self._unlink(Path(item)):
                self._did(item)
            self.manifest.remove("files", item)
            self._save()
        if self.manifest.has("dirs", folder):
            left = self._listdir(folder)
            if left:
                self._left.append(
                    f"{folder}: tiene archivos que no puso backtide ({', '.join(left)}): son "
                    "tuyos, no se tocan"
                )
                return
            if self._rmdir(folder):
                self._did(f"carpeta {folder}")
            self.manifest.remove("dirs", folder)
            self._save()

    def program(self) -> None:
        link = self.paths.bin_link
        if not self.manifest.has("files", link):
            return
        if self._unlink(link, link_to=self.paths.program):
            self._did(str(link))
        self.manifest.remove("files", link)
        self._save()

    def accounts(self) -> None:
        users, groups = self.manifest.created["users"], self.manifest.created["groups"]
        if not users and not groups:
            return
        if not self.options.erase_data:
            self._state_to_root()  # no file of the kept data with a group nobody owns
        for name in list(users):
            if name != layout.WEB_USER:  # the only account the installer makes (G3)
                self._left.append(f"el usuario {name}: no es la cuenta de backtide, no se toca")
                continue
            entry = self._getent("passwd", name)
            if entry is not None:
                fields = entry.split(":")
                if len(fields) < 7 or fields[5] != "/nonexistent" or fields[6] not in NOLOGIN:
                    self._left.append(f"el usuario {name}: no es la cuenta que creó backtide")
                    continue
                self._check(("userdel", name), f"no se pudo quitar el usuario {name}")
                self._did(f"usuario {name}")
            self.manifest.remove("users", name)
            self._save()
        for name in list(groups):
            if name != layout.WEB_USER:
                self._left.append(f"el grupo {name}: no es el de backtide, no se toca")
                continue
            if name in self.manifest.created["users"]:  # its user was left: so is the group
                self._left.append(f"el grupo {name}: su usuario se ha quedado, y él también")
                continue
            entry = self._getent("group", name)
            if entry is not None:
                gid = entry.split(":")[2] if entry.count(":") >= 2 else ""
                holders = self._primary_members(gid)
                if holders:
                    self._left.append(
                        f"el grupo {name}: es el grupo principal de {', '.join(holders)}, así "
                        "que no se quita"
                    )
                    continue
                self._check(("groupdel", name), f"no se pudo quitar el grupo {name}")
            self.manifest.remove("groups", name)
            self._save()

    def _primary_members(self, gid: str) -> list[str]:
        """The accounts whose primary group is ``gid`` (getent passwd, every account)."""
        ran = self.run(("getent", "passwd"))
        if ran is None or ran.returncode != 0:
            raise UninstallError("getent no pudo listar las cuentas: no se quita el grupo")
        found = []
        for line in ran.stdout.splitlines():
            fields = line.split(":")
            if len(fields) >= 4 and fields[3] == gid:
                found.append(fields[0])
        return found

    def data(self) -> None:
        state = self.paths.state_dir
        if not self.options.erase_data:
            for item in list(self.manifest.created["files"]):
                if not self._inside(item, state) and not self._docker_file(item):
                    if not os.path.lexists(item):
                        self.manifest.remove("files", item)
            self.manifest.steps = []
            for fact in ("release_started", "subnets", "network_roles"):
                self.manifest.facts.pop(fact, None)
            self._save()
            return
        if self.manifest.has("dirs", state):
            if self._rmtree(state):
                self._did(f"{state}: la caja negra, su clave, el volumen y las claves")
            return  # the manifest went with it
        # A state folder that was there before the installer: only what it made goes.
        for item in list(self.manifest.created["files"]):
            if self._inside(item, state) and self._unlink(Path(item)):
                self._did(item)
        for item in reversed(self.manifest.created["dirs"]):
            if self._inside(item, state) and Path(item) != state:
                self._rmtree(Path(item))
        self._unlink(self.paths.manifest)

    def exports(self) -> None:
        """The folder of `backtide exportar`: removed when empty; what the owner exported is
        theirs, even with --borrar-datos (which erases backtide's data, not the owner's)."""
        folder = self.paths.export_dir
        if not self.manifest.has("dirs", folder):
            return
        if self._exists(folder) and self._listdir(folder):
            self._left.append(f"{folder}: tus copias exportadas, que no se tocan")
            return
        if not self._exists(folder) or self._rmdir(folder):
            self._did(f"carpeta {folder}")
        self.manifest.remove("dirs", folder)
        self._save()

    def opt(self) -> None:
        folder = self.paths.opt_dir
        if not self.manifest.has("dirs", folder):
            return
        if self._rmtree(folder):
            self._did(f"carpeta {folder}")
        self.manifest.remove("dirs", folder)
        self._save()

    # -- what is kept, said -----------------------------------------------------------------------

    def _kept_lines(self) -> list[str]:
        if self.options.erase_data:
            return []
        return [f"se conserva {self.paths.state_dir}: la caja negra, el volumen del agente y las "
                "claves (con --borrar-datos se borrarían también)"]  # fmt: skip

    def _say_kept(self) -> None:
        say, state = self.prompter.say, self.paths.state_dir
        if not self._exists(state):
            return
        say(f"  - Se conservan los datos, en {state} (solo root):")
        say(f"      la caja negra: {STATE_DB}, su clave {STATE_KEY} y {STATE_CHECKPOINT};")
        say(f"      la caja de la instalación: {STATE_INSTALLATION}/;")
        image = self.paths.volume_image
        used = self._used(image)
        size = f", ocupa {used}" if used else ""
        say(f"      el trabajo del agente y sus instantáneas: {image.name} (el volumen{size});")
        say(f"      las claves: {STATE_KEYS}/; la configuración: {SAVED_CONFIG}.")
        say("    Para volver a instalar sobre ellos, el mismo comando de instalar (`sudo sh "
            "install.sh ...`): la caja negra sigue con la misma cadena y las instantáneas siguen "
            "ahí.")  # fmt: skip
        say(f"    Para borrarlos también, para siempre: `sudo rm -rf {state}`.")

    def _docker_what(self) -> str:
        return f"{', '.join(packages.DOCKER_PACKAGES)}, su repositorio y su clave"

    # -- pieces -----------------------------------------------------------------------------------

    def _load(self) -> bool:
        state, say = self.paths.state_dir, self.prompter.say
        try:
            fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            say(f"No está {state}: no hay nada de backtide instalado que quitar.")
            self._orphan_program()
            return False
        except OSError as error:
            raise UninstallError(f"{state} no es una carpeta de verdad: {error.strerror}") from None
        try:
            info = os.fstat(fd)
        finally:
            os.close(fd)
        if info.st_uid != self.owner[0] or stat.S_IMODE(info.st_mode) & 0o022:
            raise UninstallError(f"{state} no es de root o lo pueden escribir otros: no se toca")
        if not os.path.lexists(self.paths.manifest):
            say(f"No está {self.paths.manifest}: no se sabe qué creó el instalador, así que no se "
                "quita nada.")  # fmt: skip
            return False
        try:
            self.manifest = manifest.load(self.paths.manifest)
        except manifest.ManifestError as error:
            raise UninstallError(f"no se usa el manifiesto: {error}") from None
        for kind in ("files", "dirs"):
            for item in list(self.manifest.created[kind]):
                if not self._ours(Path(item)):  # never removed, whatever the manifest says
                    self._left.append(f"{item}: está en el manifiesto pero no es una ruta de "
                                      "backtide, así que no se toca")  # fmt: skip
                    self.manifest.created[kind].remove(item)
        return True

    def _orphan_program(self) -> None:
        if os.path.lexists(self.paths.opt_dir):
            self.prompter.say(f"Queda el programa en {self.paths.opt_dir}: quítalo con "
                              f"`sudo rm -rf {self.paths.opt_dir}`.")  # fmt: skip

    def _confirm(self) -> None:
        if self.options.yes:
            return
        if not self.prompter.interactive:
            raise UninstallError(
                "hace falta tu permiso: ejecútalo en una terminal para contestar, o con --si. "
                "No se ha tocado nada."
            )
        if self.options.erase_data:
            self.prompter.say(
                "\nSe borrarán PARA SIEMPRE la caja negra, el trabajo del agente y sus "
                f"instantáneas. Si quieres una copia, para aquí y copia {self.paths.state_dir} "
                f"y {self.paths.config_dir}."
            )
            typed = self.prompter.answer(
                f"Para seguir, escribe el nombre de esta máquina ({self.hostname}): "
            )
            if typed.strip() != self.hostname:
                raise UninstallError("el nombre no coincide: no se ha tocado nada.")
            return
        if not self.prompter.confirm("\n¿Seguimos?"):
            raise UninstallError("no se ha dado permiso: no se ha tocado nada.")

    def _nothing_mounted_where_it_deletes(self) -> None:
        """Before anything changes: nothing mounted under a folder this run deletes whole, but
        the two mounts its own units take away (the volume and the proxy channel's tmpfs). A
        bind mount of the agent's volume under /opt/backtide would otherwise go with it."""
        p = self.paths
        trees = [p.opt_dir, p.config_dir]
        if self.options.erase_data:
            trees.append(p.state_dir)
        expected = {str(p.volume_mount), str(p.channel_dir)}
        expected |= {str(m) for agent in self._other_agents() for m in self._mounts_of(agent)}
        found = [m for m in self._mount_points() if m not in expected
                 and any(self._inside(m, tree) for tree in trees)]  # fmt: skip
        if found:
            raise UninstallError(
                f"hay algo montado en {', '.join(found)}: no se borra nada mientras tanto. "
                "Desmóntalo (`umount`) y vuelve a ejecutar la desinstalación. No se ha tocado nada."
            )

    def _removable_paths(self) -> list[Path]:
        """The files and folders this run removes (not the data unless --borrar-datos, not
        Docker's files unless --quitar-docker), that are still there."""
        m, found = self.manifest, []
        state = self.paths.state_dir
        for item in [*m.created["files"], *m.created["dirs"]]:
            path = Path(item)
            if self._inside(item, state):
                continue  # the data: said apart
            if self._docker_file(item) and not self.options.remove_docker:
                continue
            if path == self.paths.daemon_json:
                continue  # said apart: back as it was, not removed
            if path == self.paths.volume_mount and not os.path.lexists(path):
                continue
            if path == self.paths.export_dir and self._exists(path) and self._listdir(path):
                continue  # the owner's copies: kept, and said so after (exports)
            if self._ours(path) and os.path.lexists(path) and path not in found:
                found.append(path)
        return found

    def _docker_ours(self) -> bool:
        return self.manifest.has("docker", "docker-ce")

    def _docker_file(self, item: str | Path) -> bool:
        p = Path(item)
        return p in (self.paths.apt_keyring, self.paths.apt_source, self.paths.dnf_repo,
                     self.paths.rpm_key)  # fmt: skip

    def _docker(self) -> bool:
        ran = self.run(("docker", "--version"))
        return ran is not None and ran.returncode == 0

    def _find(self, kind: str, name: str, role: str) -> Found:
        try:
            return containers.find(kind, name, role, run=self.run)
        except containers.DockerObjectError as error:
            raise UninstallError(str(error)) from None

    def _inspect(self, kind: str, name: str, role: str | tuple[str, ...]) -> tuple[Found, str]:
        try:
            return containers.inspect(kind, name, role, run=self.run)
        except containers.DockerObjectError as error:
            raise UninstallError(str(error)) from None

    def _remove(self, kind: str, name: str, role: str) -> Found:
        try:
            return containers.remove(kind, name, role, run=self.run)
        except containers.DockerObjectError as error:
            raise UninstallError(str(error)) from None

    def _systemctl(self, *args: str) -> None:
        """A unit that is not loaded any more (a run that was cut) is no failure."""
        ran = self.run(("systemctl", *args))
        if ran is None:
            raise UninstallError("falta systemctl")
        text = f"{ran.stdout}\n{ran.stderr}".lower()
        if ran.returncode != 0 and "not loaded" not in text and "does not exist" not in text:
            detail = sanitize((ran.stderr or ran.stdout).strip(), 300)
            raise UninstallError(f"`systemctl {' '.join(args)}` falló: {detail}")

    def _check(self, argv: Sequence[str], what: str, *, long: bool = False) -> Ran:
        runner = (self.run_long or self.run) if long else self.run
        ran = runner(argv)
        if ran is None:
            raise UninstallError(f"{what}: {argv[0]} no está instalado")
        if ran.returncode != 0:
            detail = sanitize((ran.stderr or ran.stdout).strip()[-400:], 400)
            raise UninstallError(f"{what} (código {ran.returncode}): {detail}")
        return ran

    def _wait_for_docker(self) -> None:
        clock = self.clock or time.monotonic
        start = clock()
        while True:
            ran = self.run(preflight.DOCKER_INFO)
            if ran is not None and ran.returncode == 0:
                return
            if clock() - start > DOCKER_WAIT:
                raise UninstallError(
                    "Docker no responde tras reiniciarlo: `systemctl status docker`"
                )
            self.sleep(2.0)

    def _getent(self, database: str, name: str) -> str | None:
        ran = self.run(("getent", database, name))
        if ran is None:
            raise UninstallError("falta getent")
        return ran.stdout.strip() if ran.returncode == 0 and ran.stdout.strip() else None

    def _state_to_root(self) -> None:
        """The state folder is 0710 root:backtide-web and the black box 0640 (D25). Before the
        group goes, give them root's group, so no later group that gets its number reads them;
        the next install sets backtide-web's again. The other agents' folders and boxes too, the
        ones in the trash among them: the service gives those to the web's group the same way
        (T26-2d)."""
        state = self.paths.state_dir
        names = [STATE_DB, f"{STATE_DB}-wal", f"{STATE_DB}-shm"]
        paths = [state, *(state / n for n in names)]
        agents = state / AGENTS_FOLDER
        if self._is_real_dir(agents):
            paths.append(agents)
            for name in self._listdir(agents):
                if self._is_real_dir(agents / name):
                    paths += [agents / name, *(agents / name / n for n in names)]
        for path in paths:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise UninstallError(f"no se puede abrir {path}: {error.strerror}") from None
            try:
                info = os.fstat(fd)
                if info.st_uid != self.owner[0]:
                    raise UninstallError(f"{path} no es de root: revísalo a mano")
                if info.st_gid != self.owner[1]:
                    os.fchown(fd, self.owner[0], self.owner[1])
            finally:
                os.close(fd)

    @staticmethod
    def _is_real_dir(path: Path) -> bool:
        try:
            return stat.S_ISDIR(os.lstat(path).st_mode)
        except OSError:
            return False

    def _other_agents(self) -> list[_OtherAgent]:
        """The agents of ``agents/``. A file that says nothing usable still names an agent: its
        containers and networks are found by its slug, and only its mounts need the file."""
        folder = self.paths.config_dir / AGENTS_FOLDER
        found = []
        for name in self._listdir(folder):
            slug = name.removesuffix(_AGENT_FILE_SUFFIX)
            if name == slug or not identity.SLUG.fullmatch(slug) or slug in identity.RESERVED_SLUGS:
                continue
            settings = self._agent_settings(folder / name)
            found.append(
                _OtherAgent(slug, _path_in(settings, "volume"), _path_in(settings, "volume_image"))
            )
        return found

    def _agent_settings(self, path: Path) -> dict[str, object]:
        fd = self._open_file(path)
        if fd is None:
            return {}
        try:
            data = os.read(fd, MAX_CONFIG_BYTES)
        finally:
            os.close(fd)
        try:
            return tomllib.loads(data.decode())
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return {}

    def _mounts_of(self, agent: _OtherAgent) -> list[Path]:
        """Its proxy's tmpfs first: nothing of the agent is left using the volume then."""
        channel = self.paths.state_dir / AGENTS_FOLDER / agent.slug / STATE_PROXY_CHANNEL
        return [channel, *([] if agent.volume is None else [agent.volume])]

    def _keep_agent_files(self) -> None:
        """Each agent's file goes beside its black box, for whoever comes back to it. Nothing reads
        it there. The other files of the folder are the person's: they stay."""
        folder = self.paths.config_dir / AGENTS_FOLDER
        for agent in self._other_agents():
            source = folder / f"{agent.slug}{_AGENT_FILE_SUFFIX}"
            fd = self._open_file(source)
            if fd is None:
                continue
            try:
                data = os.read(fd, MAX_CONFIG_BYTES)
            finally:
                os.close(fd)
            home = self.paths.state_dir / AGENTS_FOLDER / agent.slug
            home.mkdir(mode=0o700, parents=True, exist_ok=True)
            target = home / SAVED_AGENT_FILE
            temp = target.with_name(f".{target.name}.tmp")
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
            out = os.open(temp, flags, 0o600)
            try:
                os.fchmod(out, 0o600)
                os.write(out, data)
                os.fsync(out)
            finally:
                os.close(out)
            os.replace(temp, target)
            if self._unlink(source):
                self._did(str(source))
        if os.path.lexists(folder) and not self._listdir(folder) and self._rmdir(folder):
            self._did(f"carpeta {folder}")

    def _keep_config(self) -> None:
        """Copy backtide.toml (no secret in it) to the kept state, for the next install."""
        source, target = self.paths.config_file, self.paths.state_dir / SAVED_CONFIG
        fd = self._open_file(source)
        if fd is None:
            return
        try:
            data = os.read(fd, 256 * 1024)
        finally:
            os.close(fd)
        temp = target.with_name(f".{target.name}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
        out = os.open(temp, flags, 0o600)
        try:
            os.fchmod(out, 0o600)
            os.write(out, data)
            os.fsync(out)
        finally:
            os.close(out)
        os.replace(temp, target)

    def _forget_daemon(self, backup: Path) -> None:
        if self.manifest.has("files", backup):
            self._unlink(backup)
            self.manifest.remove("files", backup)
        self.manifest.facts.pop("daemon_json", None)
        self._save()

    def _json_file(self, path: Path) -> dict[str, object] | None:
        fd = self._open_file(path)
        if fd is None:
            return None
        try:
            text = os.read(fd, 1024 * 1024).decode("utf-8", errors="replace")
        finally:
            os.close(fd)
        try:
            data = json.loads(text or "{}")
        except ValueError:
            raise UninstallError(f"{path} no es JSON válido: no se toca; arréglalo antes") from None
        if not isinstance(data, dict):
            raise UninstallError(f"{path} no es un objeto JSON: no se toca")
        return data

    def _write_daemon(self, path: Path, settings: dict[str, object]) -> None:
        """daemon.json rewritten, keeping its mode (never more open than 0644; R8)."""
        text = (json.dumps(settings, indent=2, sort_keys=True) + "\n").encode("utf-8")
        try:
            mode = stat.S_IMODE(os.lstat(path).st_mode) & 0o644
        except FileNotFoundError:
            mode = 0o644
        parent = self._open_parent(path)
        try:
            temp = f".{path.name}.backtide-tmp"
            try:
                os.unlink(temp, dir_fd=parent)
            except FileNotFoundError:
                pass
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(temp, flags, 0o600, dir_fd=parent)
            try:
                os.write(fd, text)
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temp, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            os.close(parent)

    def _forget_rpm_key(self) -> None:
        """The key the installer gave rpm (`rpm --import`), by its fingerprint."""
        if not self.manifest.has("files", self.paths.rpm_key):
            return
        _, fingerprint = packages.DOCKER_KEYS["fedora"]
        ran = self.run(("rpmkeys", "--delete", fingerprint))
        if ran is not None and ran.returncode == 0:
            return
        ran = self.run(("rpm", "-e", "--allmatches", f"gpg-pubkey-{fingerprint[-8:].lower()}"))
        if ran is None or ran.returncode != 0:
            self._left.append(
                f"la clave de Docker en rpm ({fingerprint}): quítala con "
                f"`rpmkeys --delete {fingerprint}`"
            )

    def _detach_loops(self, image: Path) -> None:
        """A loop device still on the volume's image after unmounting (systemd frees its own)."""
        ran = self.run(("losetup", "--noheadings", "--output", "NAME", "--associated", str(image)))
        if ran is None or ran.returncode != 0:
            return
        for device in ran.stdout.split():
            if device.startswith("/dev/loop"):
                self._check(("losetup", "--detach", device), f"no se pudo soltar {device}")

    def _used(self, path: Path) -> str | None:
        try:
            info = os.lstat(path)
        except OSError:
            return None
        used = info.st_blocks * 512
        return f"{used / layout.GIB:.1f} GiB" if used >= layout.GIB else f"{used // 2**20} MiB"

    def _exists(self, path: Path) -> bool:
        return os.path.lexists(path)

    def _save(self) -> None:
        if not os.path.lexists(self.paths.state_dir):
            return
        try:
            manifest.save(self.manifest, self.paths.manifest)
        except manifest.ManifestError as error:
            raise UninstallError(str(error)) from None

    def _did(self, what: str) -> None:
        self._done.append(what)
        self.prompter.say(f"Quitado: {what}")

    # -- removing safely --------------------------------------------------------------------------

    def _ours(self, path: Path) -> bool:
        """Inside one of backtide's folders, or one of the exact files the installer writes."""
        text = str(path)
        if not path.is_absolute() or os.path.normpath(text) != text:
            return False
        p = self.paths
        trees = (p.opt_dir, p.config_dir, p.state_dir, p.volume_mount, p.agent_volumes)
        exact = {p.bin_link, p.apt_keyring, p.apt_source, p.dnf_repo, p.rpm_key, p.daemon_json,
                 p.export_dir,  # the folder only, emptied by nobody but the owner
                 *(p.unit_dir / name for name in self._unit_names)}  # fmt: skip
        return path in exact or any(path == t or path.is_relative_to(t) for t in trees)

    def _inside(self, item: str | Path, folder: Path) -> bool:
        path = Path(item)
        return path == folder or path.is_relative_to(folder)

    def _refuse(self, path: Path) -> None:
        if not self._ours(path):
            raise UninstallError(f"{path} no es una ruta de backtide: no se toca")

    def _open_parent(self, path: Path) -> int:
        """The folder holding ``path``, opened from / one component at a time, never through a
        link, and root's and closed to writes by others."""
        self._refuse(path)
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in path.parent.parts[1:]:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except OSError as error:
                    raise UninstallError(
                        f"no se puede abrir {path.parent} sin seguir enlaces: {error.strerror}"
                    ) from None
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid != self.owner[0] or stat.S_IMODE(info.st_mode) & 0o022:
                raise UninstallError(f"{path.parent} no es de root o lo escriben otros: no se toca")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _open_file(self, path: Path) -> int | None:
        """``path`` for reading, a regular file of root's; None if it is not there."""
        try:
            parent = self._open_parent(path)
        except UninstallError:
            if not os.path.lexists(path):
                return None
            raise
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)  # fmt: skip
        except FileNotFoundError:
            return None
        except OSError as error:
            raise UninstallError(f"no se puede abrir {path}: {error.strerror}") from None
        finally:
            os.close(parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner[0]:
            os.close(fd)
            raise UninstallError(f"{path} no es un archivo de root: no se toca")
        return fd

    def _unlink(self, path: Path, *, link_to: Path | None = None) -> bool:
        """Remove one file (or, with ``link_to``, one link that points there). False if it was
        not there."""
        self._refuse(path)
        if not os.path.lexists(path):
            return False
        parent = self._open_parent(path)
        try:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if link_to is not None:
                if not stat.S_ISLNK(info.st_mode) or os.readlink(path.name, dir_fd=parent) != str(
                    link_to
                ):
                    self._left.append(f"{path}: no es el enlace de backtide, no se toca")
                    return False
            elif not stat.S_ISREG(info.st_mode) and not stat.S_ISSOCK(info.st_mode):
                raise UninstallError(f"{path} no es un archivo normal: no se toca")
            elif info.st_uid != self.owner[0]:
                raise UninstallError(f"{path} no es de root: no se toca")
            os.unlink(path.name, dir_fd=parent)
            return True
        finally:
            os.close(parent)

    def _rmdir(self, path: Path) -> bool:
        """An empty folder (a mount point), never with anything in it."""
        parent = self._open_parent(path)
        try:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner[0]:
                raise UninstallError(f"{path} no es una carpeta de root: no se toca")
            try:
                os.rmdir(path.name, dir_fd=parent)
            except OSError as error:
                raise UninstallError(
                    f"{path} no está vacía ({error.strerror}): no se toca; revísala a mano"
                ) from None
            return True
        finally:
            os.close(parent)

    def _rmtree(self, path: Path) -> bool:
        """A whole folder of backtide's, without following links, never while anything is
        mounted at or under it."""
        mounted = self._mounts_under(path)
        if mounted:
            raise UninstallError(
                f"hay algo montado en {', '.join(mounted)}: no se borra {path} mientras tanto"
            )
        parent = self._open_parent(path)
        try:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner[0]:
                raise UninstallError(f"{path} no es una carpeta de root: no se toca")
            try:
                shutil.rmtree(path.name, dir_fd=parent)
            except OSError as error:
                raise UninstallError(f"no se pudo borrar {path}: {error.strerror}") from None
            return True
        finally:
            os.close(parent)

    def _listdir(self, path: Path) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except FileNotFoundError:
            return []

    def _mounted(self, path: Path) -> bool:
        return str(path) in self._mount_points()

    def _mounts_under(self, path: Path) -> list[str]:
        return [m for m in self._mount_points() if self._inside(m, path)]

    def _mount_points(self) -> list[str]:
        data = self.host.read(MOUNTINFO, MOUNTINFO_LIMIT)
        if data is None:
            if self.host.exists("/proc/self"):
                raise UninstallError(f"no se puede leer {MOUNTINFO}: no se borra nada a ciegas")
            return []
        points = []
        for line in data.decode("utf-8", errors="replace").splitlines():
            fields = line.split(" ")
            if len(fields) > 4:
                points.append(_unescape(fields[4]))
        return points


def _unescape(text: str) -> str:
    """mountinfo writes a space as \\040, a tab as \\011, a newline as \\012, \\ as \\134."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and text[i + 1 : i + 4].isdigit() and len(text[i + 1 : i + 4]) == 3:
            out.append(chr(int(text[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(text[i])
            i += 1
    return "".join(out)
