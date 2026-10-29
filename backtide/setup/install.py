"""`backtide instalar`: the installation's steps, each one checked, repeatable and recorded.

Design: docs/25, sections 3 and 4, with what T13-1, T13-2 and T13-3 changed. ``install.sh`` puts
this program in ``/opt/backtide`` and runs it as root; from here on everything is Python, tested on
the Mac with a fake host (tests/test_setup_install.py) and in clean VMs (docs/25, "Resultados de
T13-3").

Every step first looks at the machine and does only what is missing, so running the installer
twice changes nothing, and an install cut half way goes on from where it stopped. What a step
creates or changes goes into the manifest (backtide.setup.manifest) as soon as the step ends.
In order:

1. ``preflight``: the checks of `backtide comprobar`; any failure stops here, before any change.
2. ``state``: ``/var/lib/backtide`` (root) and the manifest in it.
3. ``web_user``: the ``backtide-web`` system account (no login, no home).
4. ``dirs``: the state folder 0710 ``root:backtide-web`` (D25), ``keys/`` 0700, ``/etc/backtide``.
5. ``tools``: ``btrfs-progs``, ``openssl``, ``gnupg``... with the distribution's manager, with
   permission.
6. ``docker``: Docker Engine from Docker's repository if there is none, with permission. A Docker
   that is there is never touched here.
7. ``confinement``: SELinux or AppArmor again, now that Docker is there. With SELinux enforcing
   and a Docker that does not use it, with permission (D25): ``live-restore`` first (a reload,
   nothing restarts), then ``selinux-enabled`` and one restart of Docker.
8. ``images``: the three pinned images of its profile, by digest (backtide.setup.images).
9. ``volume``: the image (never one that exists), its Btrfs (never over another filesystem) and
   the mount point (backtide.setup.volume).
10. ``config``: ``backtide.toml`` (only if there is none), ``web.toml``, the Gateway's token
    (OpenClaw's), the model's key (backtide.setup.secrets), ``telegram.toml`` with
    ``--telegram`` and the black box's file, readable by the web's group.
11. ``program``: ``/usr/local/bin/backtide``.
12. ``networks``: the agent's and the egress network, each with a free subnet
    (backtide.setup.networks).
13. ``units``: the four systemd units (backtide.setup.units), ``daemon-reload``.
14. ``mounts``: the volume and the channel's tmpfs, by their units; then the volume's root goes
    to 0700. A cut between mounting and sealing is picked up: a mounted volume is sealed, never
    prepared again.
15. ``start``: ``backtide.service`` and ``backtide-web.service``, enabled and started.
16. ``selftest``: `backtide comprobar --despues-de-instalar` (backtide.setup.selftest).

Nothing of a key goes into an argument, an environment variable or a message: the key comes from
a file, stdin or the terminal without echo, and goes to a 0600 file. The Telegram bot's token
too (``--telegram``, D27); without it Telegram is left for the web's Settings page.

The agent (D27): OpenClaw by default, or Claude Code with ``--perfil claude-code``. Its profile
decides the agent's image, the ``[agent]`` and ``[proxy]`` of the first ``backtide.toml`` and
whether there is a Gateway token. A machine keeps the agent it was installed with: a run with
another ``--perfil`` stops before any change (uninstall first: the data stays, and the next
install starts that agent on it; ``_choose_profile``).
"""

import errno
import json
import os
import stat
import sys
import time
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, fields, replace
from decimal import Decimal
from pathlib import Path
from typing import BinaryIO, Protocol

from backtide.blackbox import BlackBoxError, create_key
from backtide.jail.config import network_create_argv as agent_network_argv
from backtide.jail.docker import sanitize
from backtide.jail.profiles import NAMED
from backtide.jail.proxy_config import network_create_argv as egress_network_argv
from backtide.notify.telegram_api import DEFAULT_API_BASE
from backtide.service.config import (
    STATE_CHECKPOINT,
    STATE_KEY,
    ConfigError,
    Secret,
    ServiceConfig,
)
from backtide.service.settings import TELEGRAM, check_chat_id, check_value
from backtide.service.telegram_config import STATE_TELEGRAM, TelegramSettings, load_telegram
from backtide.setup import (
    containers,
    images,
    layout,
    manifest,
    networks,
    packages,
    preflight,
    secrets,
    units,
)
from backtide.setup import volume as volume_steps
from backtide.setup.host import Host, Ran, Runner
from backtide.setup.manifest import Manifest
from backtide.setup.preflight import Check, Status

PROVIDERS = ("anthropic", "openai")
# The agents `backtide instalar --perfil` installs (D27), with the name the person reads.
OPENCLAW, CLAUDE_CODE = "openclaw", "claude-code"
PROFILES = (OPENCLAW, CLAUDE_CODE)
AGENT_NAMES = {OPENCLAW: "OpenClaw", CLAUDE_CODE: "Claude Code"}
# Where the installed web is opened and where in its Settings each thing goes (T12c).
OPEN_WEB = "`sudo backtide enlace` da el enlace de la web"
KEY_PLACE = "la web, Ajustes > Modelos"
TELEGRAM_PLACE = "la web, Ajustes > Avisos"
MAX_CONFIG_BYTES = 256 * 1024
CHAT_REFUSED = (
    "el chat de Telegram tiene que ser el número de tu chat privado con el bot (positivo, solo "
    "cifras): no se ha guardado nada de Telegram."
)
# The models OpenClaw uses with Anthropic, as `make probar` lists them: the main one and the
# "utility" one it asks small things at the start of a turn (scripts/demo/probar.py).
ANTHROPIC_MODELS = ("claude-sonnet-5-5", "claude-haiku-4-5")
AGENT_MEMORY = "3g"  # the Gateway and a CLI turn at once went over 2 GiB (scripts/demo/probar.py)
DOCKER_WAIT = 90.0  # seconds for Docker to answer after it is installed or restarted
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin")
DIR_MODE_CONFIG = 0o755
FILE_MODE_PUBLIC = 0o644
# Where `backtide desinstalar` keeps backtide.toml (with the data), for the next install.
SAVED_CONFIG = "backtide.toml.guardado"


class InstallError(Exception):
    """The installation stopped: the message says what failed and how to go on (in Spanish)."""


def agent_name(profile: str) -> str:
    return AGENT_NAMES.get(profile, f"el perfil {profile}")


def profile_of(text: str) -> str | None:
    """The ``[agent] profile`` a ``backtide.toml`` names (OpenClaw when it names none), or None
    if it is not TOML or the profile is not a plain name."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    agent = data.get("agent", {})
    profile = agent.get("profile", OPENCLAW) if isinstance(agent, dict) else OPENCLAW
    if not isinstance(profile, str) or not profile.replace("-", "").isalnum():
        return None
    return profile


def untested(distro: packages.Distro | None, machine: str) -> list[str]:
    """What this machine has that nobody has tried backtide on yet (docs/44): accepted, said."""
    notes = []
    if distro is not None and distro.supported and not distro.tested:
        notes.append(
            f"{distro.pretty} se admite pero aún no se ha probado: solo Fedora 44 y Ubuntu 24.04 "
            "lo están. Debería ir; si algo falla, avísanos."
        )
    if machine not in packages.TESTED_ARCHITECTURES:
        notes.append(
            f"la arquitectura {sanitize(machine, 40)} se admite pero aún no se ha probado: solo "
            "aarch64 (arm64) lo está. Debería ir; si algo falla, avísanos."
        )
    return notes


@dataclass(frozen=True)
class Paths:
    """Every path the installer touches. ``installed()`` is the real layout; the Mac tests put
    the same tree under a temporary folder (``under``)."""

    opt_dir: Path = layout.OPT_DIR  # install.sh's: releases/, current, uv/, python/, cache/
    program: Path = layout.PROGRAM
    bin_link: Path = layout.BIN_LINK
    config_dir: Path = layout.CONFIG_DIR
    config_file: Path = layout.CONFIG_FILE
    web_config_file: Path = layout.WEB_CONFIG_FILE
    state_dir: Path = layout.STATE_DIR
    keys_dir: Path = layout.KEYS_DIR
    gateway_token: Path = layout.GATEWAY_TOKEN
    blackbox_db: Path = layout.BLACKBOX_DB
    volume_image: Path = layout.VOLUME_IMAGE
    volume_mount: Path = layout.VOLUME_MOUNT
    export_dir: Path = layout.EXPORT_DIR
    channel_dir: Path = layout.PROXY_CHANNEL_DIR
    manifest: Path = layout.MANIFEST
    unit_dir: Path = layout.UNIT_DIR
    daemon_json: Path = layout.DOCKER_DAEMON_JSON
    apt_keyring: Path = Path("/etc/apt/keyrings/docker.asc")
    apt_source: Path = Path("/etc/apt/sources.list.d/docker.list")
    dnf_repo: Path = Path("/etc/yum.repos.d/docker-ce.repo")
    rpm_key: Path = Path("/etc/pki/rpm-gpg/backtide-docker-ce.asc")  # the verified one (R2)

    def under(self, root: Path) -> "Paths":
        return replace(
            self, **{f.name: root / str(getattr(self, f.name)).lstrip("/") for f in fields(self)}
        )


class Accounts(Protocol):
    def user_id(self, name: str) -> int | None: ...
    def group_id(self, name: str) -> int | None: ...
    def fchown(self, fd: int, uid: int, gid: int) -> None: ...


class SystemAccounts:
    def user_id(self, name: str) -> int | None:
        import pwd

        try:
            return pwd.getpwnam(name).pw_uid
        except KeyError:
            return None

    def group_id(self, name: str) -> int | None:
        import grp

        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            return None

    def fchown(self, fd: int, uid: int, gid: int) -> None:
        os.fchown(fd, uid, gid)


class Prompter(Protocol):
    interactive: bool

    def say(self, text: str) -> None: ...
    def confirm(self, question: str) -> bool: ...
    def secret(self, prompt: str) -> str: ...
    def answer(self, question: str) -> str: ...


@dataclass
class Options:
    yes: bool = False  # --si: every question answered yes
    dry_run: bool = False
    provider: str = "anthropic"
    key_file: Path | None = None
    key_stdin: bool = False
    no_key: bool = False
    daily_usd: Decimal | None = None
    monthly_usd: Decimal | None = None
    timezone: str | None = None
    subnets: str | None = None
    volume_size: int = layout.VOLUME_SIZE
    profile: str | None = None  # --perfil; None: the installed one, or OpenClaw
    telegram: bool = False  # --telegram: the bot's token (never in argv) and the owner's chat
    telegram_token_file: Path | None = None
    telegram_token_stdin: bool = False
    telegram_chat: str | None = None  # --telegram-chat: a chat id, not a secret


@dataclass(frozen=True)
class Step:
    key: str
    title: str
    action: Callable[[], None]


@dataclass
class Installer:
    host: Host
    run: Runner
    run_long: Runner
    prompter: Prompter
    options: Options = field(default_factory=Options)
    paths: Paths = field(default_factory=Paths)
    accounts: Accounts = field(default_factory=SystemAccounts)
    owner: tuple[int, int] = (0, 0)  # root; the Mac tests are their own user
    self_test: Callable[[ServiceConfig], list[Check]] | None = None
    stdin: BinaryIO | None = None
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    release: Path | None = None
    manifest: Manifest = field(default_factory=Manifest)
    profile: str = OPENCLAW  # the agent of this run (_choose_profile)
    _manifest_ready: bool = False
    _units_changed: bool = False
    _restart_service: bool = False  # the service reads something new only when it starts
    _stdin_values: dict[str, str] | None = None
    _warnings: list[str] = field(default_factory=list)

    # -- the whole run ----------------------------------------------------------------------------

    def steps(self) -> list[Step]:
        return [
            Step("preflight", "Comprobar la máquina", self.preflight),
            Step("state", f"Carpeta de estado {self.paths.state_dir}", self.state),
            Step("web_user", f"Usuario {layout.WEB_USER}", self.web_user),
            Step("dirs", "Carpetas y permisos", self.dirs),
            Step("tools", "Programas que hacen falta", self.tools),
            Step("docker", "Docker Engine", self.docker),
            Step("confinement", "SELinux o AppArmor en Docker", self.confinement),
            Step("images", "Imágenes por digest", self.images),
            Step("volume", f"Volumen del agente ({self.paths.volume_image})", self.volume),
            Step("config", "Configuración y claves", self.config),
            Step("program", f"Orden `backtide` ({self.paths.bin_link})", self.program),
            Step("networks", "Redes de Docker", self.networks),
            Step("units", "Unidades de systemd", self.units),
            Step("mounts", "Montar el volumen y el canal del proxy", self.mounts),
            Step("start", "Arrancar backtide y su web", self.start),
            Step("selftest", "Autoprueba", self.selftest),
        ]

    def install(self) -> list[str]:
        """Run every step; the warnings to repeat at the end. Raises InstallError."""
        if self.options.dry_run:
            self.dry_run()
            return []
        self.check_options()
        for step in self.steps():
            self.prompter.say(f"\n== {step.title}")
            step.action()
            if self._manifest_ready:
                self.manifest.done(step.key)
                self._save()
        self.summary()
        return list(self._warnings)

    def dry_run(self) -> None:
        checks = preflight.run_checks(self.host, installing=True)
        self.prompter.say(preflight.report(checks))
        try:
            self._choose_profile()
            self._check_telegram_options()
        except InstallError as error:
            self.prompter.say(f"\nLa instalación se pararía aquí: {error}")
            return
        self.prompter.say("\nCon --dry-run no se cambia nada. Esto es lo que haría la instalación:")
        self.prompter.say(f"  Agente: {self._agent_name()}.")
        for number, step in enumerate(self.steps(), 1):
            self.prompter.say(f"  {number:2}. {step.title}")
        nocow = self._host_is_btrfs()
        for line in volume_steps.plan(
            self.paths.volume_image, self.paths.volume_mount, self.options.volume_size, nocow=nocow
        ):
            self.prompter.say(f"      - {line.describe}")
        for image in images.pinned(self.profile):
            self.prompter.say(f"      - {image.ref} ({image.role}, {image.approx_size})")

    def summary(self) -> None:
        say = self.prompter.say
        say(f"\nbacktide está instalado y vigilando al agente ({self._agent_name()}).")
        say("  - La web, solo en este ordenador: `sudo backtide enlace` da su enlace de un uso.")
        say("    En un servidor remoto, el mismo comando dice cómo llegar con `ssh -L`.")
        if self.profile == CLAUDE_CODE:
            say('  - Claude Code: `sudo backtide tarea "..."` le da una tarea y `sudo backtide '
                'entrar` abre una sesión en tu terminal, los dos dentro de la jaula.')  # fmt: skip
        say("  - El estado: `sudo backtide comprobar --despues-de-instalar` y "
            f"`systemctl status {layout.SERVICE_UNIT}`.")  # fmt: skip
        key = self.paths.keys_dir / f"{self.options.provider}.key"
        if not os.path.lexists(key):
            say(f"  - Falta la clave del modelo: {OPEN_WEB}; ábrela y ponla en Ajustes > Modelos. "
                "O vuelve a ejecutar el instalador con --clave-archivo <ruta>.")  # fmt: skip
        if not os.path.lexists(self.paths.state_dir / STATE_TELEGRAM):
            say(f"  - Telegram (opcional): {OPEN_WEB}; ábrela y ponlo en Ajustes > Avisos. O "
                "vuelve a ejecutar el instalador con --telegram.")  # fmt: skip
        say("  - Para quitarlo: `sudo backtide desinstalar` (conserva la caja negra, el trabajo "
            "del agente y las claves; con --borrar-datos, todo).")  # fmt: skip
        if self._warnings:
            say("\nAvisos:")
            for warning in self._warnings:
                say(f"  - {warning}")

    # -- the steps --------------------------------------------------------------------------------

    def preflight(self) -> None:
        distro = packages.read_distro(self.host)
        if distro is None or not distro.supported:
            name = distro.pretty if distro else "esta distribución"
            raise InstallError(
                f"{name} no es una de las que admite backtide: Ubuntu 24.04 o 26.04, Fedora 43 "
                "o 44 (docs/25, decisión 8)."
            )
        checks = preflight.run_checks(self.host, installing=True)
        self.prompter.say(preflight.report(checks))
        if preflight.failed(checks):
            raise InstallError("la máquina no sirve todavía: arregla los fallos de arriba.")
        for note in untested(distro, self.host.machine()):
            self.prompter.say(f"Aviso: {note}")
            self._warnings.append(note)
        for check in checks:
            if check.status is Status.WARN and check.key in ("btf", "kernel", "clock", "space"):
                self._warnings.append(check.summary)

    def state(self) -> None:
        created = self._ensure_dir(self.paths.state_dir, 0o700, self.owner, keep_mode=True)
        self.manifest = manifest.load(self.paths.manifest)
        if created:
            self.manifest.add("dirs", self.paths.state_dir)
        if self.release is not None:
            self.manifest.facts["release"] = str(self.release)
        self.manifest.facts["profile"] = self.profile
        self._manifest_ready = True
        self._save()

    def web_user(self) -> None:
        uid = self.accounts.user_id(layout.WEB_USER)
        if uid is None:
            shell = next((path for path in NOLOGIN if self.host.exists(path)), NOLOGIN[0])
            self._check(
                (
                    "useradd",
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    shell,
                    layout.WEB_USER,
                ),  # fmt: skip
                f"no se pudo crear el usuario {layout.WEB_USER}",
            )
            self.manifest.add("users", layout.WEB_USER)
            self.manifest.add("groups", layout.WEB_USER)
            uid = self.accounts.user_id(layout.WEB_USER)
        gid = self.accounts.group_id(layout.WEB_USER)
        if uid is None or gid is None:
            raise InstallError(f"el usuario o el grupo {layout.WEB_USER} no existen tras crearlos")
        reserved = {0} | {i for pair in layout.RESERVED_IDS.values() for i in pair}
        if uid in reserved or gid in reserved:
            raise InstallError(
                f"{layout.WEB_USER} tiene el id {uid}:{gid}, que es de root, del agente o del "
                "proxy: cámbialo a mano antes de seguir"
            )

    def dirs(self) -> None:
        gid = self._web_gid()
        root_uid, root_gid = self.owner
        self._ensure_dir(self.paths.state_dir, layout.STATE_DIR_MODE, (root_uid, gid))
        if self._ensure_dir(self.paths.keys_dir, 0o700, self.owner):
            self.manifest.add("dirs", self.paths.keys_dir)
        if self._ensure_dir(self.paths.config_dir, DIR_MODE_CONFIG, (root_uid, root_gid)):
            self.manifest.add("dirs", self.paths.config_dir)
        if self._ensure_dir(self.paths.export_dir, 0o700, self.owner):
            self.manifest.add("dirs", self.paths.export_dir)

    def tools(self) -> None:
        missing = packages.missing_tools(self.host)
        if not missing:
            self.prompter.say("Ya están todos.")
            return
        distro = self._distro()
        names = packages.package_names(distro, missing)
        manager = "apt" if distro.apt else "dnf"
        self._ask(f"Faltan {', '.join(names)}. ¿Se instalan con {manager}?")
        for argv in packages.install_argvs(distro, names):
            self._check(argv, f"no se pudo instalar {', '.join(names)}", long=True)
        for name in names:
            self.manifest.add("packages", name)
        still = packages.missing_tools(self.host)
        if still:
            raise InstallError(f"siguen faltando {', '.join(tool.name for tool in still)}")

    def docker(self) -> None:
        if self.run(("docker", "--version")) is not None:
            if self.manifest.has("docker", "docker-ce"):  # ours, from a run that was cut
                self._check(("systemctl", "enable", "--now", "docker.service"), "Docker no arranca")
            else:
                self.prompter.say("Docker ya está instalado: no se toca su configuración.")
            self._wait_for_docker()
            return
        distro = self._distro()
        self._ask(
            "Docker no está instalado. ¿Se instala Docker Engine desde el repositorio oficial de "
            f"Docker ({', '.join(packages.DOCKER_PACKAGES)})? Su clave de firma se comprueba "
            "antes de usarla."
        )
        if distro.apt:
            self._docker_apt(distro)
        else:
            self._docker_dnf()
        self.manifest.add("docker", "docker-ce")
        self._save()
        self._check(("systemctl", "enable", "--now", "docker.service"), "Docker no arranca")
        self._wait_for_docker()

    def confinement(self) -> None:
        checks = {c.key: c for c in preflight.run_checks(self.host, installing=True)}
        docker, confined = checks["docker"], checks["confinement"]
        if docker.status is not Status.OK:
            raise InstallError(f"{docker.summary}. {docker.fix}")
        if confined.status is Status.OK:
            self.prompter.say(confined.summary)
            return
        selinux = (self.host.read("/sys/fs/selinux/enforce") or b"").strip() == b"1"
        if not selinux:
            self.prompter.say(f"Aviso: {confined.summary}. {confined.fix}")
            self._warnings.append(confined.summary)
            return
        self._docker_selinux()
        again = {c.key: c for c in preflight.run_checks(self.host, installing=True)}
        if again["confinement"].status is not Status.OK:
            raise InstallError(
                f"Docker sigue sin usar SELinux tras encenderlo: {again['confinement'].summary}"
            )
        self.prompter.say(again["confinement"].summary)

    def images(self) -> None:
        if self.profile not in images.AGENTS:
            self.prompter.say(f"El agente de la configuración (perfil {self.profile}) no lo "
                              "descarga el instalador: tiene que estar ya en Docker.")  # fmt: skip
        for image in images.pinned(self.profile):
            if images.is_present(image, run=self.run):
                self.prompter.say(f"Ya está: {image.ref}")
                continue
            self.prompter.say(f"Descargando {image.role} ({image.approx_size} en disco)...")
            try:
                images.pull(image, run=self.run, run_long=self.run_long, sleep=self.sleep)
            except images.ImageError as error:
                raise InstallError(str(error)) from None
            self.manifest.add("images", image.ref)  # ours: the uninstaller may remove it
            self._save()

    def volume(self) -> None:
        image, mount = self.paths.volume_image, self.paths.volume_mount
        try:
            if not os.path.lexists(image):
                volume_steps.create_image(
                    image, self.options.volume_size, run=self.run, nocow=self._host_is_btrfs()
                )
                self.manifest.add("files", image)
                self._save()
            filesystem = self._image_filesystem(image)
            if filesystem is None:
                plan_b = volume_steps.format_image(image, run=self.run_long)
                if plan_b:
                    self.manifest.facts["quota_enable"] = True
            elif filesystem != ("btrfs", layout.VOLUME_LABEL):
                raise InstallError(
                    f"{image} ya tiene otro sistema de archivos ({' '.join(filesystem)}): no se "
                    "toca. Si es de una instalación anterior que quieres borrar, muévelo antes."
                )
            if self._mounted_here(mount):
                self.prompter.say(f"{mount} ya está montado: es el volumen de backtide.")
            else:
                existed = os.path.lexists(mount)
                volume_steps.prepare_mountpoint(mount)
                if not existed:
                    self.manifest.add("dirs", mount)
        except volume_steps.VolumeError as error:
            raise InstallError(str(error)) from None

    def config(self) -> None:
        gid = self._web_gid()
        root_uid, root_gid = self.owner
        written = False
        saved = self.paths.state_dir / SAVED_CONFIG
        if os.path.lexists(self.paths.config_file):
            self.prompter.say(f"{self.paths.config_file} ya existe: se conserva tal cual.")
        else:
            text = self._saved_config(saved)
            if text is not None and profile_of(text) != self.profile:
                self._put_aside(saved, text)
                text = None
            if text is not None:
                self.prompter.say(f"Se recupera la configuración que guardó la desinstalación "
                                  f"({saved}).")  # fmt: skip
            self._write(self.paths.config_file, text or self.render_config(), 0o600, self.owner)
            self.manifest.add("files", self.paths.config_file)
            self._save()  # before anything below can stop the run (code review I2)
            written = True
        if written and os.path.lexists(saved):
            saved.unlink()  # back in /etc/backtide: one copy only
        self._write(self.paths.web_config_file, self.render_web_config(), layout.WEB_CONFIG_MODE,
                    (root_uid, gid))  # fmt: skip
        self.manifest.add("files", self.paths.web_config_file)
        if self._needs_gateway_token() and not os.path.lexists(self.paths.gateway_token):
            self._secret(self.paths.state_dir, self.paths.gateway_token.name, secrets.new_token(),
                         private_dir=False)  # fmt: skip
            self.manifest.add("files", self.paths.gateway_token)
        self._model_key()
        self._telegram()
        self._blackbox_for_the_web(gid)
        try:
            ServiceConfig.from_file(self.paths.config_file)
        except ConfigError as error:
            if written:  # ours from a moment ago: not left behind to be "kept as it is" next time
                self.paths.config_file.unlink(missing_ok=True)
                self.manifest.remove("files", self.paths.config_file)
                self._save()
            raise InstallError(f"la configuración no sirve: {error}") from None

    def program(self) -> None:
        link, target = self.paths.bin_link, self.paths.program
        try:
            current = os.readlink(link)
        except FileNotFoundError:
            current = None
        except OSError as error:
            if error.errno != errno.EINVAL:
                raise InstallError(f"no se puede mirar {link}: {error.strerror}") from None
            current = ""  # a file that is not a link
        if self.paths.program.is_relative_to(self.paths.opt_dir):
            self.manifest.add("dirs", self.paths.opt_dir)  # install.sh's, all of it backtide's
        if current == str(target):
            return
        if current is not None:
            note = f"{link} ya existe y no es el de backtide: no se toca. Usa {target}."
            self.prompter.say(f"Aviso: {note}")
            self._warnings.append(note)
            return
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)
        self.manifest.add("files", link)

    def networks(self) -> None:
        config = self._service_config()
        wanted = [
            ("del agente", config.jail_config().network, agent_network_argv(config.jail_config())),
            ("de salida", config.proxy_jail_config().network,
             egress_network_argv(config.proxy_jail_config())),
        ]  # fmt: skip
        routes = networks.host_routes(self.run)
        missing = [item for item in wanted if networks.subnet_of(item[1], self.run) is None]
        chosen: list[networks.IPv4Network] = []
        if missing:
            try:
                if self.options.subnets:  # A for the agent's, B for the egress one
                    given = networks.parse_choice(self.options.subnets, 2)
                    chosen = [given[wanted.index(item)] for item in missing]
                else:
                    taken = [r.network for r in routes] + networks.docker_subnets(self.run)
                    chosen = networks.choose(taken, len(missing))
            except networks.NetworkError as error:
                raise InstallError(str(error)) from None
        # The roles their labels say, for the uninstaller (removed only with them, T13-4).
        self.manifest.facts["network_roles"] = containers.expected_networks(config)
        subnets = self.manifest.facts.setdefault("subnets", {})
        for (label, name, argv), subnet in zip(missing, chosen, strict=True):
            if networks.clashes(subnet, routes):
                raise InstallError(f"la subred {subnet} choca con una ruta de esta máquina")
            self._check(networks.with_subnet(argv, subnet), f"no se pudo crear la red {name}")
            self.manifest.add("networks", name)
            subnets[name] = str(subnet)
            self.prompter.say(f"Red {label} {name}: {subnet}")
        for label, name, _ in wanted:
            subnet = networks.subnet_of(name, self.run)
            if isinstance(subnet, networks.IPv4Network):
                subnets.setdefault(name, str(subnet))
                for route in networks.clashes(subnet, routes):
                    note = (
                        f"la red {label} ({name}, {subnet}) choca con {route.describe()}: una "
                        "VPN o la LAN. Mira `backtide comprobar`."
                    )
                    self.prompter.say(f"Aviso: {note}")
                    self._warnings.append(note)

    def units(self) -> None:
        changed = False
        for name, text in units.render_units().items():
            path = self.paths.unit_dir / name
            if self._write(path, text, FILE_MODE_PUBLIC, self.owner):
                changed = True
            self.manifest.add("units", name)
        if changed:
            self._check(("systemctl", "daemon-reload"), "systemd no recargó las unidades")
        self._units_changed = changed

    def mounts(self) -> None:
        names = (units.volume_unit_name(), units.channel_unit_name())
        self._check(("systemctl", "enable", "--now", *names), "systemd no montó el volumen")
        try:
            volume_steps.seal_mounted_root(self.paths.volume_mount, run=self.run)
        except volume_steps.VolumeError as error:
            raise InstallError(str(error)) from None
        if self.manifest.facts.get("quota_enable") is True:
            self._check(volume_steps.quota_enable_argv(self.paths.volume_mount),
                        "no se pudieron encender las cuotas simples")  # fmt: skip
            self.manifest.facts["quota_enable"] = "done"

    def start(self) -> None:
        # What the service will make, for the uninstaller (removed only with these labels).
        self.manifest.facts["containers"] = containers.expected_containers(self._service_config())
        self._save()
        started = self.manifest.facts.get("release_started")
        new_release = self.release is not None and started not in (None, str(self.release))
        if new_release:
            self._fresh_containers()
        for unit in (layout.SERVICE_UNIT, layout.WEB_UNIT):
            self._check(("systemctl", "enable", unit), f"no se pudo habilitar {unit}")
            active = self.run(("systemctl", "is-active", "--quiet", unit))
            restart = self._restart_service and unit == layout.SERVICE_UNIT
            if (
                active is not None
                and active.returncode == 0
                and not self._units_changed
                and not new_release
                and not restart
            ):
                self.prompter.say(f"{unit} ya está en marcha.")
                continue
            # restart, not start: one that systemd keeps restarting (a run that was cut) starts
            # over, with its restart count back at zero for the self-test.
            self._check(
                ("systemctl", "restart", unit), f"{unit} no arranca: `journalctl -u {unit}`"
            )
        if self.release is not None:
            self.manifest.facts["release_started"] = str(self.release)

    def check_options(self) -> None:
        """What this run would refuse before any step: another agent over an install, Claude
        Code with OpenAI, --telegram without its token or chat and no terminal. install.sh runs
        it (``--solo-comprobar``) before it points /opt/backtide/current at a new release, so a
        refused run leaves the version in use as it was (review of D27, finding 1)."""
        self._choose_profile()
        self._check_telegram_options()

    def _choose_profile(self) -> None:
        """The agent of this run (D27). A machine keeps the one it was installed with: another
        ``--perfil`` stops here, before any change. After `backtide desinstalar` (the data and
        the config kept) the saved config's agent comes back, unless another one is asked for:
        then that config is put aside (``config``) and the new agent starts on the same data."""
        asked = self.options.profile
        if asked is not None and asked not in PROFILES:
            raise InstallError(f"no hay un agente {asked!r}: {' o '.join(PROFILES)}")
        installed = self._installed_profile()
        if installed is not None and asked is not None and asked != installed:
            raise InstallError(
                f"backtide ya está instalado aquí con {agent_name(installed)} "
                f"({self.paths.config_file}): no se cambia de agente sobre una instalación. Para "
                f"pasar a {agent_name(asked)}, desinstala antes (`sudo backtide desinstalar`: "
                "conserva la caja negra, el trabajo del agente y las claves) y vuelve a instalar "
                f"con --perfil {asked}. No se ha tocado nada."
            )
        saved = self._saved_config(self.paths.state_dir / SAVED_CONFIG)
        if installed is None and asked is None and saved is not None:
            installed = profile_of(saved)
        self.profile = installed or asked or OPENCLAW
        if self.profile == CLAUDE_CODE and self.options.provider != "anthropic":
            raise InstallError(
                "Claude Code solo habla con la API de Anthropic: su clave es la de anthropic "
                "(--proveedor anthropic, el de por defecto)."
            )

    def _installed_profile(self) -> str | None:
        """The ``[agent] profile`` of the ``backtide.toml`` there is (OpenClaw if it names
        none), or None without one."""
        path = self.paths.config_file
        if not os.path.lexists(path):
            return None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError as error:
            raise InstallError(f"no se puede leer {path}: {error.strerror}") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise InstallError(f"{path} no es un archivo normal: revísalo a mano")
            text = os.read(fd, MAX_CONFIG_BYTES).decode("utf-8", errors="replace")
        finally:
            os.close(fd)
        found = profile_of(text)
        if found is None:
            raise InstallError(f"la configuración no sirve: {path} no es TOML válido, o su "
                               "[agent] profile no es un nombre")  # fmt: skip
        return found

    def _put_aside(self, saved: Path, text: str) -> None:
        """The config `backtide desinstalar` kept is of another agent than the one asked for:
        kept next to it with that agent's name, never used nor deleted; a new one is written."""
        old = profile_of(text) or "otro"
        aside = saved.with_name(f"{SAVED_CONFIG}.{old}")
        number = 1
        while True:  # one put aside before is never written over (review of D27, finding 2)
            try:
                os.link(saved, aside, follow_symlinks=False)
                break
            except FileExistsError:
                number += 1
                aside = saved.with_name(f"{SAVED_CONFIG}.{old}.{number}")
            except OSError as error:
                raise InstallError(f"no se puede apartar {saved}: {error.strerror}") from None
        saved.unlink()
        self.prompter.say(
            f"La configuración que guardó la desinstalación es de {agent_name(old)}: se aparta "
            f"a {aside} y se escribe una nueva para {self._agent_name()}. La caja negra, el "
            "volumen del agente (con el trabajo y las instantáneas de antes) y las claves "
            "siguen: el agente nuevo arranca sobre ellos."
        )

    def _check_telegram_options(self) -> None:
        """With --telegram and no terminal, the token and the chat must come with the run: said
        before any change, never half way."""
        options = self.options
        if options.telegram_chat is not None and not check_chat_id(options.telegram_chat):
            raise InstallError(CHAT_REFUSED)
        if not options.telegram or self.prompter.interactive:
            return
        if options.telegram_token_file is None and not options.telegram_token_stdin:
            raise InstallError(
                "--telegram necesita el token del bot y aquí no hay terminal para pedirlo: "
                "--telegram-token-archivo <ruta> o --telegram-token-stdin (nunca en un argumento)."
            )
        if options.telegram_chat is None:
            raise InstallError("--telegram necesita tu chat y aquí no hay terminal para pedirlo: "
                               "--telegram-chat <número>.")  # fmt: skip

    def _needs_gateway_token(self) -> bool:
        """OpenClaw's Gateway token: only a profile that uses one (or one the installer does not
        know, such as ``custom``, which may) gets it."""
        profile = NAMED.get(self.profile)
        return profile is None or profile.token_env is not None

    def _agent_name(self) -> str:
        return agent_name(self.profile)

    def _saved_config(self, path: Path) -> str | None:
        """The ``backtide.toml`` `backtide desinstalar` kept in the state folder, if it is there
        and root's 0600 regular file; None otherwise (then the installer writes a new one)."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner[0]:
                return None
            if stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 64 * 1024:
                return None
            return os.read(fd, 64 * 1024).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        finally:
            os.close(fd)

    def _fresh_containers(self) -> None:
        """Another version of backtide in /opt/backtide/current: the containers the service made
        for the one before mount its code (the proxy, the gate) and backtide rightly refuses a
        container that is not exactly its own. Stop the service and remove them (they hold no
        state: the agent's lives in its volume and config folder), so it makes them again. The
        whole upgrade, with its anchor and its way back, is T13-4's `backtide actualizar`."""
        self.prompter.say("Otra versión de backtide: se rehacen sus contenedores.")
        self._check(("systemctl", "stop", layout.SERVICE_UNIT), "backtide no se paró")
        config = self._service_config()
        for name, role in containers.expected_containers(config).items():
            # Only one that carries backtide's label (T13-4): never someone's of the same name.
            try:
                found = containers.remove("container", name, role, run=self.run)
            except containers.DockerObjectError as error:
                raise InstallError(str(error)) from None
            if found is containers.Found.NOT_OURS:
                raise InstallError(
                    f"hay un contenedor {name} que no lleva la etiqueta de backtide: no se toca. "
                    "Si es tuyo, cámbiale el nombre; si es de una versión vieja de backtide, "
                    f"quítalo con `docker rm --force {name}` y vuelve a instalar."
                )

    def selftest(self) -> None:
        if self.self_test is None:
            return
        checks = self.self_test(self._service_config())
        self.prompter.say(preflight.report(checks, installed=True))
        if preflight.failed(checks):
            raise InstallError(
                "la autoprueba ha fallado: backtide está instalado pero algo no va. Repítela con "
                "`sudo backtide comprobar --despues-de-instalar`."
            )
        self._warnings += [c.summary for c in checks if c.status is Status.WARN]

    # -- pieces -----------------------------------------------------------------------------------

    def render_config(self) -> str:
        """The first ``backtide.toml``: paths, the agent, the cap, the budget and the providers.
        No secret. Claude Code (D27) picks its own models and only speaks Anthropic's API."""
        options = self.options
        lines = [
            "# backtide's configuration, written by the installer (docs/25). Never a key here:",
            f"# they live in {self.paths.keys_dir}/ (0600), set with the web's Settings page",
            "# or `backtide instalar --clave-archivo`. Change this file, then",
            f"# `systemctl restart {layout.SERVICE_UNIT}`.",
            f'state_dir = "{self.paths.state_dir}"',
            f'volume = "{self.paths.volume_mount}"',
            f"workspace_limit = {options.volume_size // 20}  # 5 % of the volume",
            "",
            "[agent]",
            "# The agent in the jail: another one needs `backtide desinstalar` first (D27).",
            f'profile = "{self.profile}"',
            f'memory = "{AGENT_MEMORY}"',
            "",
            "[budget]",
            f"daily_usd = {options.daily_usd if options.daily_usd is not None else 5}",
            f"monthly_usd = {options.monthly_usd if options.monthly_usd is not None else 50}",
        ]
        if options.timezone:
            lines.append(f"timezone = {json.dumps(options.timezone)}")  # a TOML string, escaped
        if self.profile == CLAUDE_CODE:
            lines += [
                "",
                "# Claude Code picks its own models (a main one and a small one): none listed.",
                "# Its profile lets through the field it sends with every call (diagnostics).",
                "[[proxy.providers]]",
                'name = "anthropic"',
                'kind = "anthropic"',
                "",
            ]
            return "\n".join(lines)
        lines += [
            "",
            "[proxy]",
            "# OpenClaw sends Anthropic's server-side fallback field with its newest models.",
            'allow_provider_tools = ["param:fallbacks"]',
            "",
            "[[proxy.providers]]",
            'name = "anthropic"',
            'kind = "anthropic"',
            f"models = {json.dumps(list(ANTHROPIC_MODELS))}",
            "",
            "[[proxy.providers]]",
            'name = "openai"',
            'kind = "openai"',
            "",
        ]
        return "\n".join(lines)

    def render_web_config(self) -> str:
        return (
            "# The web's configuration (backtide-web.service): only where to read. Written by the\n"
            "# installer, root's, 0640 with the group backtide-web (T13-3).\n"
            f'state_dir = "{self.paths.state_dir}"\n'
            f'volume = "{self.paths.volume_mount}"\n'
        )

    def _model_key(self) -> None:
        options, name = self.options, f"{self.options.provider}.key"
        key_path = self.paths.keys_dir / name
        value: str | None = None
        later = f"ponla después en {KEY_PLACE} ({OPEN_WEB})"
        try:
            if options.key_file is not None:
                value = secrets.from_file(options.key_file)
            elif options.key_stdin:
                value = self._from_stdin("key")
            elif options.no_key:
                self.prompter.say(f"Sin clave del modelo (--sin-clave): {later}.")
            elif os.path.lexists(key_path):
                self.prompter.say(f"Ya hay una clave de {options.provider}: se conserva.")
            elif self.prompter.interactive and not options.yes:
                value = secrets.ask(
                    f"Clave de {options.provider} (no se ve al escribirla; vacío para ponerla "
                    "después en la web): ",
                    reader=self.prompter.secret,
                )
            else:
                self.prompter.say(f"Sin clave de {options.provider}: {later}.")
        except secrets.SecretError as error:
            if "vacío" in str(error) and options.key_file is None and not options.key_stdin:
                self.prompter.say(f"Sin clave por ahora: {later}.")
                return
            raise InstallError(str(error)) from None
        if value is None:
            return
        try:
            secrets.check(options.provider, value)
            written = self._secret(self.paths.keys_dir, name, value, private_dir=True)
        except secrets.SecretError as error:
            raise InstallError(str(error)) from None
        finally:
            value = None
        self.prompter.say(f"Clave de {options.provider}: {written.value}.")
        self.manifest.add("files", key_path)

    def _telegram(self) -> None:
        """``telegram.toml`` with ``--telegram`` (D27), written as the Settings page writes it:
        the token and the owner's chat, 0600 in the state folder, and the ``api_base`` of a
        usable file already there kept (the tests' fake Bot API). Without it, nothing changes:
        a file that is there stays, and Telegram is left for the web."""
        options, path = self.options, self.paths.state_dir / STATE_TELEGRAM
        if not options.telegram:
            if os.path.lexists(path):
                self.prompter.say("Telegram ya está puesto: se conserva.")
            else:
                self.prompter.say(f"Sin Telegram (es opcional): se puede poner después en "
                                  f"{TELEGRAM_PLACE} ({OPEN_WEB}), o con --telegram.")  # fmt: skip
            return
        try:
            if options.telegram_token_file is not None:
                token = secrets.from_file(options.telegram_token_file)
            elif options.telegram_token_stdin:
                token = self._from_stdin("telegram")
            else:
                token = secrets.ask(
                    "Token del bot de Telegram, el que da BotFather (no se ve al escribirlo): ",
                    reader=self.prompter.secret,
                )
        except secrets.SecretError as error:
            raise InstallError(f"Telegram: {error}") from None
        if not check_value(TELEGRAM, token):
            length = len(token)
            del token
            raise InstallError(
                f"eso no parece un token de bot de Telegram ({length} caracteres; son "
                "<cifras>:<letras>): no se ha guardado. Cópialo otra vez de BotFather."
            )
        chat = self._telegram_chat()
        api_base = self._telegram_api_base(path)
        try:
            TelegramSettings(Secret(token), int(chat), api_base)  # the service's own reading
        except ConfigError as error:
            raise InstallError(f"Telegram: {error}") from None
        lines = [f'token = "{token}"', f"chat_id = {int(chat)}"]
        del token
        if api_base != DEFAULT_API_BASE:
            lines.append(f"api_base = {json.dumps(api_base)}")
        data = ("\n".join(lines) + "\n").encode()
        del lines
        try:
            written = secrets.write_file(self.paths.state_dir, STATE_TELEGRAM, data,
                                         private_dir=False)  # fmt: skip
        except secrets.SecretError as error:
            raise InstallError(str(error)) from None
        finally:
            del data
        if written is not secrets.Written.UNCHANGED:
            self._restart_service = True  # the bot reads telegram.toml when the service starts
        self.prompter.say(f"Telegram (el token y el chat {int(chat)}): {written.value}.")
        self.manifest.add("files", path)

    def _telegram_chat(self) -> str:
        chat = self.options.telegram_chat
        if chat is None:
            chat = self.prompter.answer(
                "El número de tu chat privado con el bot (te lo da, por ejemplo, @userinfobot): "
            ).strip()
        if not check_chat_id(chat):
            raise InstallError(CHAT_REFUSED)
        return chat

    def _telegram_api_base(self, path: Path) -> str:
        """The ``api_base`` of a usable ``telegram.toml`` already there, or the real Bot API."""
        if not os.path.lexists(path):
            return DEFAULT_API_BASE
        try:
            current = load_telegram(self.paths.state_dir)
        except (ConfigError, OSError):
            return DEFAULT_API_BASE  # unusable: replaced whole, with the real Bot API
        return current.api_base if current is not None else DEFAULT_API_BASE

    def _from_stdin(self, which: str) -> str:
        """The model's key (``key``) or the bot's token (``telegram``) from standard input. With
        both on it, the key is the first line and the token the second; read once, each value
        handed out once."""
        if self._stdin_values is None:
            options = self.options
            sources = (("key", options.key_stdin), ("telegram", options.telegram_token_stdin))
            wanted = [name for name, on in sources if on]
            stream = self.stdin or sys.stdin.buffer
            if len(wanted) == 1:
                values = [secrets.from_stream(stream)]
            else:
                values = secrets.lines_from_stream(stream, len(wanted))
            self._stdin_values = dict(zip(wanted, values, strict=True))
            del values
        return self._stdin_values.pop(which)

    def _secret(self, folder: Path, name: str, value: str, *, private_dir: bool) -> secrets.Written:
        try:
            return secrets.write(folder, name, value, private_dir=private_dir)
        except secrets.SecretError as error:
            raise InstallError(str(error)) from None

    def _blackbox_for_the_web(self, gid: int) -> None:
        """The black box's file (and SQLite's -wal and -shm, which copy its owner and mode)
        root's, 0640, group backtide-web (D25). Made empty before the service's first start, so
        SQLite creates the other two like it; never anyone else's, never through a link.

        The service refuses a black box without its key (runner.open_black_box: never a new key
        for a chain that exists), so on a first install the installer makes the key first, with
        the same function the service would use, and only then the empty file."""
        db = self.paths.blackbox_db
        key = self.paths.state_dir / STATE_KEY
        parts = [db, Path(f"{db}-wal"), Path(f"{db}-shm"), self.paths.state_dir / STATE_CHECKPOINT]
        if not os.path.lexists(key):
            found = [part for part in parts if os.path.lexists(part)]
            ours = found == [db] and self.manifest.has("files", db) and os.lstat(db).st_size == 0
            if found and not ours:
                raise InstallError(
                    f"hay una caja negra ({', '.join(p.name for p in found)}) sin su clave {key}: "
                    "no se crea una clave nueva para una cadena que ya existe. Revísalo a mano."
                )
            try:
                create_key(key)
            except BlackBoxError as error:
                raise InstallError(str(error)) from None
            self.manifest.add("files", key)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            os.close(os.open(db, flags, 0o600))
            self.manifest.add("files", db)
        except FileExistsError:
            pass
        for path in (db, Path(f"{db}-wal"), Path(f"{db}-shm")):
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise InstallError(f"no se puede abrir {path}: {error.strerror}") from None
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner[0]:
                    raise InstallError(f"{path} no es un archivo de root: revísalo a mano")
                self.accounts.fchown(fd, self.owner[0], gid)
                os.fchmod(fd, layout.BLACKBOX_DB_MODE)
            finally:
                os.close(fd)

    def _docker_apt(self, distro: packages.Distro) -> None:
        url, fingerprint = packages.docker_key(distro)
        keyring = self.paths.apt_keyring
        self._ensure_dir(keyring.parent, DIR_MODE_CONFIG, self.owner, keep_mode=True)
        self._write(keyring, self._verified_key(url, fingerprint), FILE_MODE_PUBLIC, self.owner)
        self.manifest.add("files", keyring)
        source = packages.apt_source(distro, self.host.machine(), str(keyring))
        self._write(self.paths.apt_source, source, FILE_MODE_PUBLIC, self.owner)
        self.manifest.add("files", self.paths.apt_source)
        for argv in packages.install_argvs(distro, packages.DOCKER_PACKAGES):
            self._check(argv, "no se pudo instalar Docker", long=True)

    def _docker_dnf(self) -> None:
        url, fingerprint = packages.DOCKER_KEYS["fedora"]
        key = self.paths.rpm_key
        self._ensure_dir(key.parent, DIR_MODE_CONFIG, self.owner, keep_mode=True)
        self._write(key, self._verified_key(url, fingerprint), FILE_MODE_PUBLIC, self.owner)
        self.manifest.add("files", key)
        self._check(("rpm", "--import", str(key)), "rpm no aceptó la clave de Docker")
        self._write(self.paths.dnf_repo, packages.dnf_repo(key), FILE_MODE_PUBLIC, self.owner)
        self.manifest.add("files", self.paths.dnf_repo)
        distro = self._distro()
        for argv in packages.install_argvs(distro, packages.DOCKER_PACKAGES):
            self._check(argv, "no se pudo instalar Docker", long=True)

    def _verified_key(self, url: str, fingerprint: str) -> str:
        """Docker's signing key, and nothing else (review of T13-3, R2). The download must hold
        exactly one primary key, with the published fingerprint; then that one key is exported
        by its fingerprint from a throwaway keyring, checked again, and only that text is used:
        never the downloaded file as it came. root's own keyring is not touched."""
        work = self.paths.state_dir / "docker-key.tmp"
        self._remove_tree(work)
        self._ensure_dir(work, 0o700, self.owner)
        try:
            downloaded, home = work / "downloaded.asc", work / "gnupg"
            self._ensure_dir(home, 0o700, self.owner)
            self._check(
                ("curl", "-fsSL", "--proto", "=https", "--tlsv1.2", "--max-time", "120",
                 "-o", str(downloaded), url),
                f"no se pudo descargar la clave de Docker de {url}",
                long=True,
            )  # fmt: skip
            self._only_that_key(home, downloaded, url, fingerprint)
            gpg = ("gpg", "--homedir", str(home), "--batch", "--quiet")
            self._check((*gpg, "--import", str(downloaded)), "gpg no pudo leer la clave de Docker")
            exported = self._check(
                (*gpg, "--armor", "--export-options", "export-minimal", "--export", fingerprint),
                "gpg no pudo sacar la clave de Docker",
            ).stdout
            again = work / "verified.asc"
            again.write_text(exported, encoding="utf-8")
            self._only_that_key(home, again, url, fingerprint)
            return exported
        finally:
            self.run(("gpgconf", "--homedir", str(work / "gnupg"), "--kill", "all"))
            self._remove_tree(work)

    def _only_that_key(self, home: Path, path: Path, url: str, fingerprint: str) -> None:
        ran = self._check(
            ("gpg", "--homedir", str(home), "--batch", "--show-keys", "--with-colons", str(path)),
            "gpg no pudo leer la clave de Docker",
        )
        found = packages.primary_fingerprints(ran.stdout)
        if found != [fingerprint]:
            raise InstallError(
                f"la clave descargada de {url} no es solo la de Docker (claves {found}, se "
                f"esperaba {fingerprint} y nada más): no se usa. No sigas y avisa."
            )

    def _docker_selinux(self) -> None:
        """D25: SELinux enforcing, Docker without it. With permission: live-restore with a
        reload (nothing restarts), then selinux-enabled and one restart of Docker."""
        self._ask(
            "SELinux está activo pero Docker no lo usa: el agente correría sin confinar. ¿Se "
            "enciende en Docker? Primero `live-restore` (sin reiniciar nada) y después "
            "`selinux-enabled`, que reinicia Docker un instante; con live-restore tus otros "
            "contenedores siguen en marcha."
        )
        path = self.paths.daemon_json
        settings, existed = self._daemon_settings(path)
        # A daemon.json an earlier, cut run made is ours, not the person's: no backup of it.
        existed = existed and not self.manifest.has("files", path)
        backup = self.paths.state_dir / "docker-daemon.json.antes"
        if existed and not os.path.lexists(backup):
            self._write(backup, path.read_text(encoding="utf-8"), 0o600, self.owner)
            self.manifest.add("files", backup)
            self._save()
        # Each change is recorded BEFORE it is made (code review of 2026-10-29, I1): a run cut
        # after writing but before saving took its own change for the person's setting next
        # time, and the uninstall left it. Undoing a change that was not made yet is harmless.
        changed = self.manifest.facts.setdefault("daemon_json", [])
        if not existed:
            self.manifest.add("files", path)
        if settings.get("live-restore") is not True:
            if "live-restore" not in changed:
                changed.append("live-restore")
            self._save()
            settings["live-restore"] = True
            self._write_daemon(path, settings, existed)
            self._check(("systemctl", "reload", "docker.service"), "Docker no recargó su ajuste")
            self._wait_for_docker()
        if "selinux-enabled" not in changed:
            changed.append("selinux-enabled")
        self._save()
        settings["selinux-enabled"] = True
        self._write_daemon(path, settings, existed)
        self._check(("systemctl", "restart", "docker.service"), "Docker no volvió a arrancar")
        self._wait_for_docker()

    def _daemon_settings(self, path: Path) -> tuple[dict[str, object], bool]:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return {}, False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner[0]:
            raise InstallError(f"{path} no es un archivo de root: no se toca")
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "{}")
        except ValueError:
            raise InstallError(f"{path} no es JSON válido: arréglalo antes; no se toca") from None
        if not isinstance(data, dict):
            raise InstallError(f"{path} no es un objeto JSON: no se toca")
        return data, True

    def _write_daemon(self, path: Path, settings: dict[str, object], existed: bool) -> None:
        """daemon.json with backtide's settings. One that was there keeps its mode (never more
        open than 0644; review of T13-4, R8); a new one is 0644, as Docker's own."""
        self._ensure_dir(path.parent, DIR_MODE_CONFIG, self.owner, keep_mode=True)
        text = json.dumps(settings, indent=2, sort_keys=True) + "\n"
        mode = FILE_MODE_PUBLIC
        if existed:
            mode = stat.S_IMODE(os.lstat(path).st_mode) & FILE_MODE_PUBLIC
        self._write(path, text, mode, self.owner)
        if not existed:
            self.manifest.add("files", path)

    def _wait_for_docker(self) -> None:
        start = self.clock()
        while True:
            ran = self.run(preflight.DOCKER_INFO)
            if ran is not None and ran.returncode == 0:
                return
            if self.clock() - start > DOCKER_WAIT:
                detail = sanitize((ran.stderr if ran else "").strip(), 200)
                raise InstallError(f"Docker no responde: {detail or 'no está instalado'}")
            self.sleep(2.0)

    def _image_filesystem(self, image: Path) -> tuple[str, str] | None:
        """``(type, label)`` that blkid finds in the image, or None if it holds none."""
        ran = self.run(("blkid", "-p", "-o", "export", str(image)))
        if ran is None:
            raise InstallError("falta blkid (util-linux)")
        if ran.returncode == 2:  # nothing found: a new, empty image
            return None
        if ran.returncode != 0:
            raise InstallError(f"blkid no pudo leer {image}: {sanitize(ran.stderr.strip(), 200)}")
        found = dict(line.split("=", 1) for line in ran.stdout.splitlines() if "=" in line)
        return found.get("TYPE", "?"), found.get("LABEL", "")

    def _mounted_here(self, path: Path) -> bool:
        """Is backtide's volume mounted exactly at ``path``? Then a cut install sealed or not,
        it is never prepared again (prepare_mountpoint would refuse the 0755 root mkfs left)."""
        ran = self.run(volume_steps.findmnt_argv(path))
        if ran is None or ran.returncode != 0 or not ran.stdout.strip():
            return False
        if ran.stdout.split() == ["btrfs", layout.VOLUME_LABEL]:
            return True
        raise InstallError(f"en {path} hay montado otra cosa ({ran.stdout.strip()}): no se toca")

    def _host_is_btrfs(self) -> bool:
        try:
            return volume_steps.host_is_btrfs(self.paths.volume_image.parent, run=self.run)
        except volume_steps.VolumeError:
            return False

    def _service_config(self) -> ServiceConfig:
        try:
            return ServiceConfig.from_file(self.paths.config_file)
        except ConfigError as error:
            raise InstallError(f"la configuración no sirve: {error}") from None

    def _distro(self) -> packages.Distro:
        distro = packages.read_distro(self.host)
        if distro is None:
            raise InstallError("no se pudo leer /etc/os-release")
        return distro

    def _web_gid(self) -> int:
        gid = self.accounts.group_id(layout.WEB_USER)
        if gid is None:
            raise InstallError(f"falta el grupo {layout.WEB_USER}")
        return gid

    def _ask(self, question: str) -> None:
        if self.options.yes:
            self.prompter.say(f"{question} Sí (--si).")
            return
        if not self.prompter.interactive:
            raise InstallError(
                f"hace falta tu permiso: {question} Ejecútalo en una terminal para contestar, o "
                "con --si para decir que sí a todo."
            )
        if not self.prompter.confirm(question):
            raise InstallError("no se ha dado permiso: no se sigue. No se ha tocado nada más.")

    def _check(self, argv: Sequence[str], what: str, *, long: bool = False) -> Ran:
        ran = (self.run_long if long else self.run)(argv)
        if ran is None:
            raise InstallError(f"{what}: {argv[0]} no está instalado")
        if ran.returncode != 0:
            detail = sanitize((ran.stderr or ran.stdout).strip()[-600:], 600)
            raise InstallError(
                f"{what} (`{' '.join(argv[:4])}`…, código {ran.returncode}): {detail}"
            )
        return ran

    def _ensure_dir(
        self, path: Path, mode: int, owner: tuple[int, int], *, keep_mode: bool = False
    ) -> bool:
        """Make ``path`` (or take the one there: a real folder, root's) with ``mode`` and
        ``owner``. ``keep_mode`` only checks an existing one is not open to writes by others.
        True if it was created."""
        created = False
        try:
            os.mkdir(path, 0o700)
            created = True
        except FileExistsError:
            pass
        except OSError as error:
            raise InstallError(f"no se puede crear {path}: {error.strerror}") from None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise InstallError(f"{path} no es una carpeta de verdad: {error.strerror}") from None
        try:
            info = os.fstat(fd)
            if info.st_uid != self.owner[0]:
                raise InstallError(f"{path} no es de root (dueño {info.st_uid}): revísalo a mano")
            if keep_mode and not created:
                if stat.S_IMODE(info.st_mode) & 0o022:
                    raise InstallError(f"{path} lo pueden escribir otros: revísalo a mano")
                return False
            if (info.st_uid, info.st_gid) != owner:
                self.accounts.fchown(fd, *owner)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
        return created

    def _write(self, path: Path, text: str, mode: int, owner: tuple[int, int]) -> bool:
        """Write ``text`` to ``path`` through a new file renamed into place; True if it changed.
        Never through a link; an identical file (content, mode, owner) is left alone."""
        data = text.encode("utf-8")
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            info = None
        if info is not None:
            if not stat.S_ISREG(info.st_mode):
                raise InstallError(f"{path} existe y no es un archivo normal: no se toca")
            same = (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, *owner)
            if same and path.read_bytes() == data:
                return False
        temp = path.with_name(f".{path.name}.backtide-tmp")
        try:
            temp.unlink(missing_ok=True)
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, data)
                if (os.fstat(fd).st_uid, os.fstat(fd).st_gid) != owner:
                    self.accounts.fchown(fd, *owner)
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temp, path)
        except OSError as error:
            temp.unlink(missing_ok=True)
            raise InstallError(f"no se puede escribir {path}: {error.strerror}") from None
        return True

    def _remove_tree(self, path: Path) -> None:
        import shutil

        shutil.rmtree(path, ignore_errors=True)

    def _save(self) -> None:
        try:
            manifest.save(self.manifest, self.paths.manifest)
        except manifest.ManifestError as error:
            raise InstallError(str(error)) from None
