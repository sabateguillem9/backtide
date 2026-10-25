"""Does this machine suit backtide? The checks before installing, and `backtide comprobar`.

Design: docs/25, section 4, step 1, with what T13-1 changed. Each check is one line for the
person (in Spanish) and, when it is not OK, how to fix it:
- ``FAIL`` stops the installer: backtide cannot run safely here;
- ``WARN`` lets it go on: something works less (the process sensor, the squota fixes) or the
  installer will do it itself with permission (Docker, btrfs-progs, SELinux in Docker);
- nothing here changes the machine. ``run_checks`` only reads, through a ``Host``.

The BTF check is D24 (option A of decision 13 of docs/25): Tetragon v1.7.1 cannot read the
longer BTF header of the 7.1+ kernels built with pahole 1.31, so the sensor would not start.
The agent still runs (decision 7 of docs/23); the person is told before installing.
"""

import json
import re
import struct
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from backtide.jail.docker import sanitize
from backtide.jail.sensor import TETRAGON_VERSION
from backtide.setup import layout
from backtide.setup.host import Host, Ran

MIN_KERNEL = (6, 7)  # simple quotas (docs/16)
SQUOTA_FIXES_KERNEL = (7, 1)  # the squota fixes docs/16 asks for
ARCHITECTURES = ("x86_64", "aarch64")
BTF_FILE = "/sys/kernel/btf/vmlinux"
BTF_MAGIC = 0xEB9F
BTF_READ = 512  # bytes of BTF_FILE read: the header and then some
# The BTF header cilium/ebpf in Tetragon v1.7.1 knows: magic, version, flags, hdr_len and four
# u32 offsets. A longer header must end in zeros (cilium/ebpf#2041). Look at it again when
# TETRAGON_VERSION changes: Tetragon 1.8 brings cilium/ebpf v0.22, which reads the longer one.
TETRAGON_BTF_HEADER_LEN = 24
DOCKER_INFO = ("docker", "info", "--format", "{{json .}}")
SUMMARY_LIMIT = 200
REPORT_WIDTH = 96


class Status(StrEnum):
    OK = "ok"
    WARN = "aviso"
    FAIL = "falla"


@dataclass(frozen=True)
class Check:
    key: str
    status: Status
    summary: str  # one line
    fix: str = ""  # how to fix it; empty when OK


def failed(checks: Sequence[Check]) -> bool:
    return any(check.status is Status.FAIL for check in checks)


def report(checks: Sequence[Check]) -> str:
    """The checks for a terminal: one line each, how to fix it underneath, and a verdict."""
    lines = ["¿Sirve esta máquina para backtide?", ""]
    for check in checks:
        label = f"[{check.status.value}]"
        lines.append(f"  {label:<8}{check.summary}")
        if check.fix:
            lines.extend(
                textwrap.wrap(
                    check.fix, REPORT_WIDTH, initial_indent=" " * 10, subsequent_indent=" " * 10
                )
            )
    failures = sum(check.status is Status.FAIL for check in checks)
    warnings = sum(check.status is Status.WARN for check in checks)
    counted = f"{_count(failures, 'fallo', 'fallos')} y {_count(warnings, 'aviso', 'avisos')}"
    lines.append("")
    if failures:
        lines.append(f"{counted}: backtide no puede instalarse aquí hasta arreglar los fallos.")
    elif warnings:
        lines.append(
            f"Ningún fallo y {_count(warnings, 'aviso', 'avisos')}: backtide puede "
            "instalarse; lee los avisos."
        )
    else:
        lines.append("Ningún fallo y ningún aviso: todo listo.")
    return "\n".join(lines)


def _count(number: int, one: str, many: str) -> str:
    return f"{number} {one if number == 1 else many}"


def run_checks(host: Host, *, installing: bool) -> list[Check]:
    """Every check, in the order they are shown. ``installing`` makes root a must; without it
    (`backtide comprobar`) a missing root is a warning and the space check knows backtide may
    already be installed."""
    docker, docker_info = _docker(host, installing=installing)
    return [
        _root(host, installing=installing),
        _arch(host),
        _kernel(host),
        _btrfs(host),
        _present(
            host,
            "loop",
            "/dev/loop-control",
            "Hay dispositivos de bucle (el volumen es un archivo montado como disco)",
            "No hay dispositivos de bucle: el volumen de backtide no se puede montar",
            "Carga el módulo `loop` (`modprobe loop`). Algunos servidores virtuales en "
            "contenedor (LXC, OpenVZ) no los dan: hace falta una VM o un servidor de verdad.",
        ),
        _present(
            host,
            "cgroup",
            "/sys/fs/cgroup/cgroup.controllers",
            "cgroup v2",
            "El sistema no usa cgroup v2",
            "Usa una distribución actual (Ubuntu 24.04+, Fedora 43+) o arranca con "
            "`systemd.unified_cgroup_hierarchy=1`.",
        ),
        _present(
            host,
            "systemd",
            "/run/systemd/system",
            "systemd",
            "El sistema no arranca con systemd",
            "backtide se instala como servicio de systemd: usa Ubuntu o Fedora.",
        ),
        _clock(host),
        _btf(host),
        _space(host, installing=installing),
        _ids(host),
        _tool(
            host,
            "btrfs-progs",
            ("mkfs.btrfs", "--version"),
            "Falta btrfs-progs",
            "El instalador lo instalará (`btrfs-progs` en apt y dnf).",
        ),
        _tool(
            host,
            "openssl",
            ("openssl", "version"),
            "Falta openssl (backtide hace con él la CA del proxy)",
            "El instalador lo instalará (`openssl` en apt y dnf).",
        ),
        docker,
        _confinement(host, docker_info),
    ]


def _root(host: Host, *, installing: bool) -> Check:
    if host.euid() == 0:
        return Check("root", Status.OK, "Se ejecuta como root")
    if installing:
        return Check("root", Status.FAIL, "Instalar necesita root", "Ejecútalo con `sudo`.")
    return Check(
        "root",
        Status.WARN,
        "Sin root: alguna comprobación (Docker, SELinux) puede quedarse corta",
        "Para verlo todo: `sudo backtide comprobar`.",
    )


def _arch(host: Host) -> Check:
    machine = host.machine()
    if machine in ARCHITECTURES:
        return Check("arch", Status.OK, f"Arquitectura {machine}")
    return Check(
        "arch",
        Status.FAIL,
        f"Arquitectura {_clean(machine)} no admitida",
        "backtide funciona en x86_64 y en aarch64 (arm64).",
    )


def kernel_version(release: str) -> tuple[int, int] | None:
    match = re.match(r"(\d+)\.(\d+)", release)
    return (int(match[1]), int(match[2])) if match else None


def _kernel(host: Host) -> Check:
    release = _clean(host.release())
    version = kernel_version(release)
    if version is None:
        return Check(
            "kernel",
            Status.FAIL,
            f"No se entiende la versión del kernel ({release})",
            "backtide necesita un kernel 6.7 o posterior.",
        )
    if version < MIN_KERNEL:
        return Check(
            "kernel",
            Status.FAIL,
            f"Kernel {release}: demasiado antiguo para las cuotas simples de Btrfs",
            "Hace falta un kernel 6.7 o posterior: Ubuntu 26.04, Fedora 43 o 44, o el kernel "
            "HWE de Ubuntu 24.04.",
        )
    if version < SQUOTA_FIXES_KERNEL:
        return Check(
            "kernel",
            Status.WARN,
            f"Kernel {release}: sirve, pero no trae los arreglos de las cuotas simples del 7.1",
            "Funciona: el tope de espacio del agente se probó con este kernel. No hace falta "
            "hacer nada.",
        )
    return Check("kernel", Status.OK, f"Kernel {release}")


def _btrfs(host: Host) -> Check:
    table = host.read("/proc/filesystems") or b""
    names = {
        line.split()[-1] for line in table.decode(errors="replace").splitlines() if line.split()
    }
    if "btrfs" in names:
        return Check("btrfs", Status.OK, "Btrfs disponible")
    loadable = host.run(("modinfo", "-F", "name", "btrfs"))
    if loadable is not None and loadable.returncode == 0:
        return Check("btrfs", Status.OK, "Btrfs disponible (el módulo se carga al montar)")
    return Check(
        "btrfs",
        Status.FAIL,
        "El kernel no tiene Btrfs",
        "backtide guarda las instantáneas en Btrfs. Ubuntu y Fedora lo traen; en otras "
        "distribuciones, instala el módulo del kernel.",
    )


def _present(host: Host, key: str, path: str, ok: str, fail: str, fix: str) -> Check:
    if host.exists(path):
        return Check(key, Status.OK, ok)
    return Check(key, Status.FAIL, fail, fix)


def _clock(host: Host) -> Check:
    synced = host.clock_synced()
    if synced:
        return Check("clock", Status.OK, "La hora está sincronizada")
    return Check(
        "clock",
        Status.WARN,
        "La hora no está sincronizada"
        if synced is False
        else "No se pudo saber si la hora está sincronizada",
        "backtide no borra instantáneas viejas sin una hora fiable. Activa la sincronización "
        "(`timedatectl set-ntp true`) o espera un minuto tras arrancar.",
    )


def btf_header_problem(data: bytes) -> str | None:
    """Why Tetragon TETRAGON_VERSION cannot read a BTF that starts with ``data``, or None."""
    if len(data) < TETRAGON_BTF_HEADER_LEN:
        return "la cabecera está incompleta"
    if data[:2] == BTF_MAGIC.to_bytes(2, "little"):
        order = "<"
    elif data[:2] == BTF_MAGIC.to_bytes(2, "big"):
        order = ">"
    else:
        return "no empieza como un BTF"
    (hdr_len,) = struct.unpack_from(f"{order}I", data, 4)
    if hdr_len < TETRAGON_BTF_HEADER_LEN:
        return f"su cabecera mide {hdr_len} bytes, menos de lo normal"
    if hdr_len == TETRAGON_BTF_HEADER_LEN:
        return None
    if len(data) < hdr_len or any(data[TETRAGON_BTF_HEADER_LEN:hdr_len]):
        return (
            f"su cabecera mide {hdr_len} bytes y Tetragon {TETRAGON_VERSION} solo entiende la "
            f"de {TETRAGON_BTF_HEADER_LEN}"
        )
    return None


def _btf(host: Host) -> Check:
    no_sensor = (
        "el sensor de procesos (Tetragon) no arrancará. El agente funciona, pero sus "
        "comandos no se graban"
    )
    data = host.read(BTF_FILE, BTF_READ)
    if not data:
        return Check(
            "btf",
            Status.WARN,
            f"El kernel no publica su BTF: {no_sensor}",
            "Usa un kernel con `CONFIG_DEBUG_INFO_BTF` (los de Ubuntu y Fedora lo traen).",
        )
    problem = btf_header_problem(data)
    if problem is None:
        return Check("btf", Status.OK, "BTF legible: el sensor de procesos puede arrancar")
    return Check(
        "btf",
        Status.WARN,
        f"El BTF de este kernel no se puede leer ({problem}): {no_sensor}",
        "Pasa con los kernels 7.1 y posteriores (Fedora 43 y 44 actualizadas). Se arregla con "
        "Tetragon 1.8, que backtide adoptará en cuanto salga (decisión D24). Con Ubuntu 24.04 "
        "o 26.04 el sensor funciona ya.",
    )


def _space(host: Host, *, installing: bool) -> Check:
    where = str(layout.VOLUME_IMAGE.parent.parent)  # /var/lib: the volume and Docker's images
    free = host.free_bytes(where)
    if free is None:
        return Check(
            "space",
            Status.WARN,
            f"No se pudo leer el espacio libre de {where}",
            f"Comprueba a mano (`df -h {where}`) que quedan al menos "
            f"{_gib(layout.VOLUME_SIZE // 2 + layout.IMAGES_ROOM)}.",
        )
    if host.exists(str(layout.VOLUME_IMAGE)):  # installed: room to grow is what matters
        if free >= layout.GROW_ROOM:
            return Check("space", Status.OK, f"{_gib(free)} libres en {where}")
        return Check(
            "space",
            Status.WARN,
            f"Solo quedan {_gib(free)} en {where}",
            "El volumen del agente y las imágenes de Docker crecen ahí. Libera espacio: "
            "backtide pausa al agente si se queda sin sitio.",
        )
    need = layout.VOLUME_SIZE // 2 + layout.IMAGES_ROOM
    if free >= need:
        return Check(
            "space", Status.OK, f"{_gib(free)} libres en {where} (hacen falta {_gib(need)})"
        )
    if free < need and not installing and host.euid() != 0:
        # Without root, /var/lib/backtide (0710) hides volume.img: this may be an installed
        # machine, where 18 GiB free is not what matters.
        return Check(
            "space",
            Status.WARN,
            f"Solo hay {_gib(free)} libres en {where}; para instalar hacen falta {_gib(need)}",
            "Sin root no se ve si backtide ya está instalado: `sudo backtide comprobar`.",
        )
    return Check(
        "space",
        Status.FAIL,
        f"Solo hay {_gib(free)} libres en {where}; hacen falta {_gib(need)}",
        f"El volumen del agente ({_gib(layout.VOLUME_SIZE)}, que ocupa lo que se escribe) y las "
        "imágenes (unos 5,5 GiB) viven ahí. Libera espacio o amplía el disco.",
    )


def _ids(host: Host) -> Check:
    taken = []
    for who, (uid, gid) in layout.RESERVED_IDS.items():
        if host.uid_taken(uid):
            taken.append(f"el usuario {uid} ({who})")
        if host.gid_taken(gid):
            taken.append(f"el grupo {gid} ({who})")
    if not taken:
        ids = ", ".join(str(uid) for uid, _ in layout.RESERVED_IDS.values())
        return Check("ids", Status.OK, f"Los ids {ids} están libres")
    return Check(
        "ids",
        Status.FAIL,
        f"Ya existe {' y '.join(taken)}",
        "El agente y el proxy corren con esos ids, que no deben ser de nadie: así nada de la "
        "máquina les da permisos. Cambia el id de esa cuenta o de ese grupo.",
    )


def _tool(host: Host, key: str, argv: tuple[str, ...], missing: str, fix: str) -> Check:
    ran = host.run(argv)
    if ran is None or ran.returncode != 0:
        return Check(key, Status.WARN, missing, fix)
    return Check(key, Status.OK, _first_line(ran.stdout) or key)


def _docker(host: Host, *, installing: bool) -> tuple[Check, dict[str, object] | None]:
    """Docker Engine, never Docker Desktop, Podman or rootless (docs/25, decision 5)."""
    version = host.run(("docker", "--version"))
    if version is None:
        return Check(
            "docker",
            Status.WARN,
            "Docker no está instalado",
            "El instalador lo instalará desde el repositorio oficial, si le das permiso.",
        ), None
    if "podman" in version.stdout.lower():
        return Check(
            "docker",
            Status.FAIL,
            "`docker` es Podman",
            "backtide necesita Docker Engine (`docker-ce`): Podman no da lo que usa la jaula.",
        ), None
    ran = host.run(DOCKER_INFO)
    info = _json_object(ran)
    if info is None:
        error = _first_line(ran.stderr) if ran is not None else ""
        if ran is not None and "permission denied" in error.lower() and not installing:
            return Check(
                "docker",
                Status.WARN,
                "No se pudo preguntar a Docker sin root",
                "Para comprobarlo: `sudo backtide comprobar`.",
            ), None
        return Check(
            "docker",
            Status.FAIL,
            f"Docker no responde{': ' + error if error else ''}",
            "Arráncalo (`systemctl start docker`) y vuelve a probar.",
        ), None
    system = str(info.get("OperatingSystem", ""))
    options = _security_options(info)
    if "docker desktop" in system.lower():
        return Check(
            "docker",
            Status.FAIL,
            "Esto es Docker Desktop",
            "Docker Desktop no deja cargar eBPF ni da Btrfs. Hace falta Docker Engine en un "
            "Linux (en un Mac, dentro de una VM).",
        ), info
    if "name=rootless" in options:
        return Check(
            "docker",
            Status.FAIL,
            "Docker corre sin root (rootless)",
            "backtide necesita el Docker del sistema: la jaula y el sensor de procesos no "
            "funcionan con Docker rootless.",
        ), info
    server = _clean(str(info.get("ServerVersion", "?")))
    return Check("docker", Status.OK, f"Docker Engine {server}"), info


def _confinement(host: Host, docker_info: dict[str, object] | None) -> Check:
    enforce = (host.read("/sys/fs/selinux/enforce") or b"").strip()
    unknown_fix = (
        "Si Docker aún no está instalado, el instalador lo comprobará después de instalarlo. "
        "Si ya lo está: `sudo backtide comprobar`."
    )
    if enforce == b"1":
        if docker_info is None:
            return Check(
                "confinement",
                Status.WARN,
                "SELinux activo, pero no se sabe si Docker lo usa (sin él, el agente correría sin "
                "confinar)",
                unknown_fix,
            )
        if "name=selinux" in _security_options(docker_info):
            return Check("confinement", Status.OK, "SELinux activo, y Docker lo usa")
        return Check(
            "confinement",
            Status.WARN,
            "SELinux está activo pero Docker no lo usa: el agente correría sin confinar",
            "El instalador te pedirá permiso para encenderlo en Docker: primero `live-restore` "
            "(sin reiniciar nada) y después `selinux-enabled`, que reinicia Docker un instante "
            "sin parar tus contenedores (decisión D25).",
        )
    if enforce == b"0":
        return Check(
            "confinement",
            Status.WARN,
            "SELinux está en modo permisivo: avisa, pero no confina",
            "Ponlo en modo estricto (`setenforce 1` y `SELINUX=enforcing` en /etc/selinux/config).",
        )
    apparmor = (host.read("/sys/module/apparmor/parameters/enabled") or b"").strip()
    if apparmor == b"Y":
        if docker_info is None:
            return Check(
                "confinement",
                Status.WARN,
                "AppArmor activo, pero no se sabe si Docker lo usa",
                unknown_fix,
            )
        if "name=apparmor" in _security_options(docker_info):
            return Check("confinement", Status.OK, "AppArmor activo, y Docker lo usa")
        return Check(
            "confinement",
            Status.WARN,
            "AppArmor está activo pero Docker no lo usa: el agente correría sin su perfil",
            "Instala `apparmor` (trae `apparmor_parser`) y reinicia Docker.",
        )
    return Check(
        "confinement",
        Status.WARN,
        "Ni SELinux ni AppArmor: el agente queda confinado solo por seccomp y capacidades",
        "Ubuntu trae AppArmor y Fedora SELinux, encendidos de serie: actívalos si los apagaste.",
    )


def _security_options(info: dict[str, object]) -> list[str]:
    options = info.get("SecurityOptions")
    return [str(option) for option in options] if isinstance(options, list) else []


def _json_object(ran: Ran | None) -> dict[str, object] | None:
    if ran is None or ran.returncode != 0:
        return None
    try:
        data = json.loads(ran.stdout)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _first_line(text: str) -> str:
    return _clean(text.strip().splitlines()[0] if text.strip() else "")


def _clean(text: str) -> str:
    return sanitize(text.replace("\n", " "), SUMMARY_LIMIT)


def _gib(size: int) -> str:
    return f"{size / layout.GIB:.1f} GiB".replace(".", ",")
