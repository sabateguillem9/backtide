"""The backtide demo, recordable with one command each (docs/demo.md). Runs inside the Lima VM.

    python -m scripts.demo.demo up                 # volume + config + `backtide vigilar`, in front
    python -m scripts.demo.demo crear|archivos|borrar
    python -m scripts.demo.demo instantaneas
    python -m scripts.demo.demo rebobinar <id> [--si]
    python -m scripts.demo.demo parar              # stops everything, unmounts, deletes the demo

Everything lives under ``~/backtide-demo-run`` (a folder with the ``.backtide-demo`` mark that this
script writes; it never deletes one without it): a sparse Btrfs image formatted with simple quotas
(``mkfs.btrfs -O squota``, no privileges), mounted the way tests/integration/conftest.py mounts
its throwaway volumes, and backtide's state next to it. The only privileged commands are the ones
that file already uses: ``sudo -n true`` (does sudo work without a password?), ``mount``,
``chown``, ``umount`` and ``btrfs qgroup limit <bytes>|none <path>``. Every one of them is
checked here, right before it runs, against the demo's own paths.

The concession. The VM user is not root, so the agent's ids are the user's, and ``AgentJail``
refuses that unless ``allow_shared_ids`` says so; the workspace cap also needs a privileged
``qgroup limit``. A config file cannot set either (on purpose), so this entry point, like
tests/integration/service_main.py and cli_main.py, hands the real `backtide` command a jail with
``allow_shared_ids`` and a guarded ``sudo`` limit setter, then runs ``backtide.cli.main``
unchanged. Nothing of this is in ``backtide/``: in production backtide runs as root.
"""

import argparse
import contextlib
import io
import os
import platform
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import backtide.cli as cli
from backtide.blackbox import BlackBox, BlackBoxError, Event, load_key
from backtide.jail import IMAGE, AgentJail
from backtide.service.config import ServiceConfig
from backtide.service.offline import rewind_without_service
from backtide.snapshots import SnapshotError, SnapshotStore, btrfs

MIB = 1024**2
GIB = 1024**3
VM_HOSTNAME = "lima-vigia-dev"  # Lima names the guest lima-<instance>; see VM in the Makefile
MOUNT_OPTIONS = "loop,noatime,nosuid,nodev,user_subvol_rm_allowed"  # as the integration tests
IMAGE_SIZE = 2 * GIB  # sparse; above 1 GiB so mkfs never picks mixed mode
WORKSPACE_LIMIT = 192 * MIB
CYCLE_INTERVAL = 5  # seconds between two "did anything change?" checks (the real one is 120)
COMMAND_TIMEOUT = 60.0
STOP_TIMEOUT = 120.0
PULL_TIMEOUT = 1800.0  # the first pull of the pinned OpenClaw image is about 1.3 GB
CONTAINER = "backtide-demo-agent"
NETWORK = "backtide-demo-net"
PROCESS_MARK = b"scripts.demo.demo"  # what the service's /proc/<pid>/cmdline contains
PROJECT = "/workspace/work/proyecto"  # inside the agent: the folder the demo creates and deletes
SNAPSHOT_WAIT = 90.0  # a cycle, the sync and the snapshot, on a loaded VM
FEED_INTERVAL = 1.0
KEPT_FILE = "notas.md"  # the one file the agent does not delete

DEMO_FILES = {
    "informe-q3.md": "# Informe del tercer trimestre\n\nVentas: +12 %\nClientes nuevos: 38\n",
    "clientes.csv": "nombre,ciudad,plan\nAna,Valencia,pro\nLuis,Sevilla,basico\nMar,Bilbao,pro\n",
    "presupuesto.txt": "Presupuesto 2027\n  Personal   120.000\n  Nube        18.500\n",
    KEPT_FILE: "Notas de la reunión: revisar contratos antes del viernes.\n",
}
DELETED_FILES = [name for name in DEMO_FILES if name != KEPT_FILE]


class DemoError(RuntimeError):
    """Something the person must fix or know: shown as a line, without a trace."""


@dataclass(frozen=True)
class Paths:
    """Where the demo lives. Fixed: no path ever comes from the environment or the arguments."""

    base: Path

    @property
    def image(self) -> Path:
        return self.base / "volume.img"

    @property
    def mnt(self) -> Path:
        return self.base / "mnt"

    @property
    def volume(self) -> Path:
        """backtide's snapshot store, a private folder inside the btrfs (the config's
        ``volume``)."""
        return self.mnt / "backtide"

    @property
    def state(self) -> Path:
        return self.base / "state"

    @property
    def config(self) -> Path:
        return self.base / "backtide.toml"

    @property
    def mark(self) -> Path:
        """Written first: proof that this script made the folder, and the only thing that lets
        ``teardown`` delete it."""
        return self.base / ".backtide-demo"

    @property
    def before_file(self) -> Path:
        """The id of the snapshot that holds the demo files (written by ``crear``)."""
        return self.base / "antes.id"

    @property
    def after_file(self) -> Path:
        """The id of the first snapshot taken without the deleted files (``borrar``)."""
        return self.base / "despues.id"

    @property
    def pid_file(self) -> Path:
        return self.base / "service.pid"


PATHS = Paths(Path.home() / "backtide-demo-run")


# -- Mounts (the same checks as tests/integration/conftest.py) --------------------------------


@dataclass(frozen=True)
class Mount:
    mount_point: Path
    fs_type: str
    source: str


def parse_mountinfo_line(line: str) -> Mount:
    """See proc_pid_mountinfo(5). Optional fields end at the ``-`` separator, and the kernel
    writes space, tab, newline and backslash as octal escapes like ``\\040``."""
    fields = line.split(" ")
    separator = fields.index("-", 6)

    def unescape(field: str) -> str:
        out, i = [], 0
        while i < len(field):
            digits = field[i + 1 : i + 4]
            if field[i] == "\\" and len(digits) == 3 and all(d in "01234567" for d in digits):
                out.append(chr(int(digits, 8)))
                i += 4
            else:
                out.append(field[i])
                i += 1
        return "".join(out)

    return Mount(
        mount_point=Path(unescape(fields[4])),
        fs_type=fields[separator + 1],
        source=unescape(fields[separator + 2]),
    )


def mount_at(path: Path, mountinfo: str | None = None) -> Mount | None:
    text = mountinfo if mountinfo is not None else Path("/proc/self/mountinfo").read_text()
    matches = [m for m in map(parse_mountinfo_line, text.splitlines()) if m.mount_point == path]
    return matches[-1] if matches else None  # the last one is the mount on top


def loop_backing_file(source: str) -> Path | None:
    """The file behind a /dev/loopN device, or None if ``source`` is not a loop device."""
    device = Path(source)
    if device.parent != Path("/dev") or not device.name.startswith("loop"):
        return None
    backing = Path("/sys/block") / device.name / "loop" / "backing_file"
    return Path(backing.read_text().rstrip("\n"))


def is_demo_mount(paths: Paths) -> bool:
    """True if ``paths.mnt`` is exactly the btrfs loop mount of the demo's own image."""
    mount = mount_at(paths.mnt)
    return (
        mount is not None
        and mount.fs_type == "btrfs"
        and loop_backing_file(mount.source) == paths.image
    )


def require_demo_mount(paths: Paths) -> None:
    if not is_demo_mount(paths):
        raise DemoError(f"{paths.mnt} no es el volumen de la demo: no se toca (¿`make demo`?)")


# -- The privileged commands -------------------------------------------------------------------


def run(argv: list[str], *, timeout: float = COMMAND_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` and raise with its stderr if it fails. Never ignored."""
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DemoError(f"{shlex.join(argv)} no se pudo ejecutar: {error}") from error
    if result.returncode != 0:
        raise DemoError(
            f"{shlex.join(argv)} falló con código {result.returncode}: {result.stderr.strip()}"
        )
    return result


def sudo(*args: str) -> None:
    """mount, chown and umount: with the limit setter, the only privileged commands."""
    if args[0] not in {"true", "mount", "chown", "umount"}:
        raise DemoError(f"sudo {args[0]} no está permitido en la demo")
    run(["sudo", "-n", *args])


def sudo_qgroup_limit(path: Path, limit: int | None) -> None:
    """``sudo -n btrfs qgroup limit <bytes>|none <path>``, and nothing else, on a subvolume of
    the demo volume: the production argv (btrfs.qgroup_limit_args) with only the sudo prefix.
    Checked right before it runs: the demo's own loop mount, and a canonical path (no symlink
    anywhere) that is a subvolume root strictly inside it, on that same btrfs. Raises
    SnapshotError, or SnapshotNoSpace for ENOSPC/EDQUOT, like btrfs.set_qgroup_limit."""
    args = btrfs.qgroup_limit_args(path, limit)
    mnt = PATHS.mnt
    if not is_demo_mount(PATHS):
        raise SnapshotError(f"refusing sudo on {path}: {mnt} is not the demo volume")
    real = Path(os.path.realpath(path))
    if real != path:
        raise SnapshotError(f"refusing sudo on {path}: not canonical (it resolves to {real})")
    if real == mnt or not real.is_relative_to(mnt):
        raise SnapshotError(f"refusing sudo on {path}: not strictly inside the demo volume {mnt}")
    if not btrfs.is_subvolume(path):
        raise SnapshotError(f"refusing sudo on {path}: not a subvolume root")
    if btrfs.fsid(path) != btrfs.fsid(mnt):
        raise SnapshotError(f"refusing sudo on {path}: not on the btrfs mounted at {mnt}")
    argv = ["sudo", "-n", "btrfs", *args]
    command = shlex.join(argv)
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=COMMAND_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        raise SnapshotError(f"{command} timed out after {COMMAND_TIMEOUT} s") from error
    except OSError as error:
        raise SnapshotError(f"cannot run {command}: {error}", errno=error.errno) from error
    if result.returncode != 0:
        btrfs._raise_failure(command, result.returncode, result.stderr.strip())


# -- The concession: the real `backtide` command, with what a non-root VM user needs --------------


def serve_without_root(config: ServiceConfig, **options: Any) -> None:
    from backtide.service import runner

    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    runner.serve(config, jail=jail, **options)


_production_rewind = rewind_without_service


def rewind_without_root(config: ServiceConfig, snapshot_id: str, **options: Any) -> Any:
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    return _production_rewind(config, snapshot_id, jail=jail, **options)


def run_backtide(*argv: str) -> int:
    """`backtide <argv>` as it is, in this process, with the concessions installed."""
    cli.serve = serve_without_root  # type: ignore[attr-defined]
    cli.rewind_without_service = rewind_without_root  # type: ignore[attr-defined]
    btrfs.set_qgroup_limit = sudo_qgroup_limit  # type: ignore[assignment]  # looked up at call
    return cli.main(list(argv))


# -- Setting up and tearing down ----------------------------------------------------------------


def require_dev_vm_user_with_sudo() -> None:
    # Never sudo on the Mac, a Linux laptop or a CI runner.
    if sys.platform != "linux" or platform.node() != VM_HOSTNAME:
        raise DemoError(f"la demo solo corre dentro de la VM {VM_HOSTNAME}: usa `make demo`")
    if os.geteuid() == 0:
        raise DemoError("ejecútala como el usuario normal de la VM, no como root")
    try:
        sudo("true")
    except DemoError as error:
        raise DemoError(
            f"hace falta sudo sin contraseña en la VM para montar el volumen: {error}"
        ) from error


def require_agent_image() -> None:
    """Pull the pinned OpenClaw image if the VM does not have it yet (by digest)."""
    have = subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, text=True, check=False
    )
    if have.returncode != 0:
        print("Descargando la imagen de OpenClaw (la primera vez son 1,3 GB)...", flush=True)
        run(["docker", "pull", "--quiet", IMAGE], timeout=PULL_TIMEOUT)


def service_pid(paths: Paths) -> int | None:
    """The pid of a live demo service, or None. A pid file whose process is gone, or is some
    other program that reused the pid, does not count."""
    try:
        pid = int(paths.pid_file.read_text().strip())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (OSError, ValueError):
        return None
    return pid if PROCESS_MARK in cmdline else None


def remove_agent() -> None:
    """Remove the demo container, then its network: a stopped container still holds the btrfs
    in its own mount namespace, which would make the umount fail. Missing ones are fine."""
    run(["docker", "rm", "--force", CONTAINER])
    networks = run(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    if NETWORK in networks:
        run(["docker", "network", "rm", NETWORK])


def stop_service(paths: Paths) -> None:
    pid = service_pid(paths)
    if pid is None:
        return
    print(f"Parando el servicio de backtide (pid {pid}); para al agente con él...", flush=True)
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + STOP_TIMEOUT
    while service_pid(paths) is not None:
        if time.monotonic() > deadline:
            raise DemoError(f"el servicio (pid {pid}) no ha parado en {STOP_TIMEOUT:.0f} s")
        time.sleep(0.5)


def teardown(paths: Paths) -> None:
    """Stop the service, remove the agent, unmount the demo volume and delete the folder.
    Idempotent, and it only unmounts what is exactly the demo's own loop mount."""
    if paths.base.exists() and not paths.mark.is_file():
        raise DemoError(
            f"{paths.base} existe y no es de la demo (no tiene la marca {paths.mark.name}): "
            "no lo toco; bórralo a mano si es un resto tuyo"
        )
    stop_service(paths)
    remove_agent()
    if mount_at(paths.mnt) is not None:
        require_demo_mount(paths)
        sudo("umount", str(paths.mnt))
    if paths.base.exists():
        if mount_at(paths.mnt) is not None:  # never delete a folder with a volume still in it
            raise DemoError(f"{paths.mnt} sigue montado: no se borra {paths.base}")
        shutil.rmtree(paths.base)


def render_config(paths: Paths, uid: int, gid: int) -> str:
    return (
        f'state_dir = "{paths.state}"\n'
        f'volume = "{paths.volume}"\n'
        f"workspace_limit = {WORKSPACE_LIMIT}  # 192 MiB\n"
        f"cycle_interval = {CYCLE_INTERVAL}\n"
        "\n"
        "[agent]\n"
        f'name = "{CONTAINER}"\n'
        f'network = "{NETWORK}"\n'
        f"uid = {uid}\n"
        f"gid = {gid}\n"
        'memory = "2g"\n'
        'cpus = "2"\n'
    )


def create_volume(paths: Paths) -> None:
    mkfs = shutil.which("mkfs.btrfs")
    if mkfs is None:
        raise DemoError("falta mkfs.btrfs: btrfs-progs debe estar instalado en la VM")
    paths.base.mkdir(mode=0o700)
    paths.mark.write_text(
        "Created by scripts/demo/demo.py; `make demo-parar` deletes this folder.\n"
    )
    paths.mnt.mkdir(mode=0o700)
    with open(paths.image, "xb") as image:  # x: never reuse or overwrite an existing file
        image.truncate(IMAGE_SIZE)
    run([mkfs, "-q", "-L", "backtide-demo", "-O", "squota", str(paths.image)])
    sudo("mount", "-o", MOUNT_OPTIONS, str(paths.image), str(paths.mnt))
    try:
        sudo("chown", f"{os.getuid()}:{os.getgid()}", str(paths.mnt))
        require_demo_mount(paths)
        mode = btrfs.quota_mode(paths.mnt)
        if mode != "squota":
            raise DemoError(f"el volumen debería tener cuotas simples, tiene {mode!r}")
        paths.volume.mkdir(mode=0o700)
        paths.state.mkdir(mode=0o700)
        token = paths.state / "gateway.token"
        token.write_text(secrets.token_urlsafe(32) + "\n")
        token.chmod(0o600)
        paths.config.write_text(render_config(paths, os.getuid(), os.getgid()))
        paths.config.chmod(0o600)
        copy_telegram(paths)
    except BaseException:
        teardown(paths)  # leave nothing mounted behind
        raise


# The founder's own bot (docs/28): kept outside the demo folder, which `parar` deletes.
TELEGRAM_SOURCE = Path.home() / ".config" / "backtide" / "telegram.toml"


def copy_telegram(paths: Paths, source: Path = TELEGRAM_SOURCE) -> bool:
    """Copy the bot's settings into the demo's state folder, if the founder made them. The
    token is never read into a string here or printed: the bytes go from file to file. The
    source must be the user's own regular file with mode 0600, as the service will check."""
    try:
        info = source.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise DemoError(f"{source} debe ser un archivo normal y tuyo")
    if info.st_mode & 0o077:
        raise DemoError(f"{source} debe tener permisos 600 (chmod 600 {source})")
    data = source.read_bytes()
    fd = os.open(paths.state / "telegram.toml", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
    return True


def command_up(paths: Paths) -> int:
    require_dev_vm_user_with_sudo()
    if service_pid(paths) is not None:
        raise DemoError("ya hay una demo en marcha en otra terminal; `make demo-parar` la quita")
    require_agent_image()
    if paths.base.exists() or mount_at(paths.mnt) is not None:
        print("Quedaba una demo anterior: la quito para empezar de cero.", flush=True)
    teardown(paths)
    create_volume(paths)
    print(
        f"Volumen de la demo listo en {paths.mnt} (Btrfs con cuotas, tope del agente: 192 MiB).\n"
        "Arranco `backtide vigilar`: espera a ver el agente en marcha y las primeras "
        "instantáneas.\n"
        "Para parar: Ctrl-C aquí. Para limpiarlo todo: `make demo-parar`.\n",
        flush=True,
    )
    if (paths.state / "telegram.toml").exists():
        print("Telegram: los avisos irán a tu bot. Prueba /estado y /pausar.\n", flush=True)
    paths.pid_file.write_text(f"{os.getpid()}\n")
    stop = threading.Event()
    feed = threading.Thread(target=feed_black_box, args=(paths, stop), name="demo-feed")
    feed.start()
    try:
        return run_backtide("vigilar", "--config", str(paths.config))
    finally:
        stop.set()
        feed.join(10)
        paths.pid_file.unlink(missing_ok=True)


# -- What the agent does, from outside (docker exec, as the agent's user) ----------------------


def agent_exec(paths: Paths, script: str) -> str:
    require_demo_mount(paths)
    config = ServiceConfig.from_file(paths.config)
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    if not jail.is_running():
        raise DemoError("el agente no está en marcha: arranca `make demo` en otra terminal")
    result = jail.exec(["sh", "-c", script], timeout=COMMAND_TIMEOUT)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        raise DemoError(f"el agente terminó con código {result.returncode}")
    return result.stdout


def project_matches(folder: Path, *, present: bool) -> bool:
    """Whether ``folder`` (a snapshot's copy of the project) holds the demo files
    (``present``) or lacks exactly the deleted ones."""
    try:
        if present:
            return all((folder / name).read_text() == text for name, text in DEMO_FILES.items())
        return (folder / KEPT_FILE).is_file() and not any(
            (folder / name).exists() for name in DELETED_FILES
        )
    except OSError:
        return False


def wait_for_snapshot(paths: Paths, *, present: bool, newer_than: str | None = None) -> str:
    """Wait for the newest snapshot (after ``newer_than``) that holds the demo files
    (``present``) or lacks the deleted ones, and return its id. The service snapshots on its own
    every cycle; this only waits for the one that shows the change."""
    store = SnapshotStore(ServiceConfig.from_file(paths.config).volume)
    deadline = time.monotonic() + SNAPSHOT_WAIT
    while time.monotonic() < deadline:
        for snap in reversed(store.snapshots()):
            if newer_than is not None and snap.id <= newer_than:
                break  # ids sort by time
            folder = store.snapshots_dir / snap.id / "agente" / "work" / "proyecto"
            if project_matches(folder, present=present):
                return snap.id
        time.sleep(1)
    raise DemoError(f"en {SNAPSHOT_WAIT:.0f} s no apareció la instantánea: ¿sigue `make demo`?")


def command_crear(paths: Paths) -> int:
    lines = [f"mkdir -p {PROJECT}"]
    for name, text in DEMO_FILES.items():
        lines.append(f"printf '%s' {shlex.quote(text)} > {PROJECT}/{name}")
    lines.append(f"ls -l {PROJECT}")
    print("El agente crea sus archivos de trabajo:")
    agent_exec(paths, "\n".join(lines))
    print("Espero a que backtide haga una instantánea que los tenga...", flush=True)
    paths.after_file.unlink(missing_ok=True)
    snapshot_id = wait_for_snapshot(paths, present=True)
    paths.before_file.write_text(snapshot_id + "\n")
    print(f"Instantánea con los archivos: {snapshot_id}")
    return 0


def command_archivos(paths: Paths) -> int:
    print(f"Lo que ve el agente en {PROJECT}:")
    agent_exec(paths, f"ls -l {PROJECT} 2>&1 || true")
    return 0


def command_borrar(paths: Paths) -> int:
    names = " ".join(DELETED_FILES)
    print("El agente borra archivos (rm):")
    agent_exec(paths, f"cd {PROJECT} && rm -v {names} && ls -l .")
    before = saved_id(paths.before_file)
    print("Espero a que backtide haga una instantánea ya sin ellos...", flush=True)
    after = wait_for_snapshot(paths, present=False, newer_than=before)
    paths.after_file.write_text(after + "\n")
    print(f"Instantánea sin los archivos: {after}")
    if before is not None:
        print(f"Para recuperarlos: make demo-rebobinar ID={before}")
    return 0


def saved_id(path: Path) -> str | None:
    try:
        return path.read_text().strip() or None
    except OSError:
        return None


def command_instantaneas(paths: Paths) -> int:
    """`backtide instantaneas`, with a note on the lines `crear` and `borrar` found."""
    notes = {
        saved_id(paths.before_file): "  <-- con los archivos",
        saved_id(paths.after_file): "  <-- sin los archivos (ya borrados)",
    }
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = run_backtide("instantaneas", "--config", str(paths.config))
    for line in out.getvalue().splitlines():
        print(line + next((note for key, note in notes.items() if key and key in line), ""))
    return code


def command_rebobinar(paths: Paths, snapshot: str | None, *, yes: bool) -> int:
    target = snapshot or saved_id(paths.before_file)
    if target is None:
        raise DemoError(
            "di la instantánea: make demo-rebobinar ID=<id> (mira make demo-instantaneas)"
        )
    real_stdout = sys.stdout
    sys.stdout = _UndoHint(real_stdout)  # type: ignore[assignment]
    try:
        return run_backtide(
            "rebobinar", "--config", str(paths.config), target, *(["--si"] if yes else [])
        )
    finally:
        sys.stdout = real_stdout


class _UndoHint:
    """Wraps stdout so `Para deshacer: backtide rebobinar <id>` reads as the demo's own command.
    Everything else, the question included, goes through as it is."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(text.replace("backtide rebobinar ", "make demo-rebobinar ID="))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


# -- A live view of the black box, for the terminal that runs the service -----------------------


def describe(event: Event) -> str | None:
    """One line for an event worth showing in front of a camera, or None: the agent's own
    files (OpenClaw writes its database all the time) are left out, only the demo's are shown."""
    # Local time, like the table of `backtide instantaneas`.
    when = datetime.fromisoformat(event.ts).astimezone().strftime("%H:%M:%S")
    target = str(event.target)
    source = event.source.value
    if source == "file":
        if not target.startswith("work/"):
            return None
        return f"{when}  archivo     {event.action:<15} {target}"
    if source == "snapshot":
        return f"{when}  instantánea {event.action:<15} {target}"
    return f"{when}  sistema     {event.action:<15} {target}".rstrip()


def feed_black_box(paths: Paths, stop: threading.Event) -> None:
    """Print what the black box records, as it happens, until ``stop``. Read-only: it opens the
    database the way the tests do and never writes to it. A failure here only ends the view,
    never the service, and says so."""
    box: BlackBox | None = None
    last = 0
    try:
        while not stop.wait(FEED_INTERVAL):
            if box is None:
                state = paths.state
                if not (state / "blackbox.db").exists():
                    continue
                try:
                    box = BlackBox(
                        state / "blackbox.db",
                        load_key(state / "blackbox.key"),
                        checkpoint_path=state / "blackbox.checkpoint",
                        readonly=True,
                    )
                except BlackBoxError:
                    continue  # the service is still creating it
            for event in box.events():
                if event.seq > last:
                    last = event.seq
                    line = describe(event)
                    if line is not None:
                        print(line, flush=True)
    except BlackBoxError as error:
        print(f"(la vista de la caja negra se ha parado: {error})", file=sys.stderr, flush=True)
    finally:
        if box is not None:
            box.close()


# -- Entry point ---------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="demo", description="La demo de backtide (docs/demo.md).")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("up", help="prepara el volumen y arranca el servicio en primer plano")
    commands.add_parser("crear", help="el agente crea archivos de trabajo")
    commands.add_parser("archivos", help="enseña los archivos del agente")
    commands.add_parser("borrar", help="el agente borra algunos archivos")
    commands.add_parser("instantaneas", help="lista las instantáneas")
    rewind = commands.add_parser("rebobinar", help="vuelve a una instantánea")
    rewind.add_argument(
        "snapshot", metavar="instantánea", nargs="?", help="por defecto, la que dejó `crear`"
    )
    rewind.add_argument("--si", action="store_true", help="no pedir confirmación")
    commands.add_parser("parar", help="para todo, desmonta el volumen y borra la demo")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = PATHS
    try:
        match args.command:
            case "up":
                return command_up(paths)
            case "crear":
                return command_crear(paths)
            case "archivos":
                return command_archivos(paths)
            case "borrar":
                return command_borrar(paths)
            case "instantaneas":
                require_demo_mount(paths)
                return command_instantaneas(paths)
            case "rebobinar":
                require_demo_mount(paths)
                return command_rebobinar(paths, args.snapshot, yes=args.si)
            case "parar":
                require_dev_vm_user_with_sudo()
                teardown(paths)
                print("Demo parada: sin servicio, sin agente, volumen desmontado y borrado.")
                return 0
    except DemoError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    raise AssertionError(f"unhandled command {args.command!r}")  # argparse makes it unreachable


if __name__ == "__main__":
    raise SystemExit(main())
